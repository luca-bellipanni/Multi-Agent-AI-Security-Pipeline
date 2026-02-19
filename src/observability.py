"""Agent observability — step logging + timeout for CI visibility.

Provides:
- make_step_logger(): smolagents step_callback for per-step diagnostics
- run_with_timeout(): hard thread-based timeout for agent.run() calls

The step_callback handles inter-step logging and soft timeout (checked
between steps). run_with_timeout() adds a hard timeout that works even
when a single LLM call hangs indefinitely, plus a heartbeat so CI
output never goes silent.

Used by decision_engine.py (triage + analyzer) and remediation_engine.py.
"""

import threading
import time
from typing import Any, Callable


_TOOL_DESCRIPTIONS = {
    "fetch_pr_files": "Fetching PR file list",
    "fetch_pr_diff": "Fetching PR diff",
    "run_semgrep": "Running Semgrep scan",
    "read_code": "Reading source code",
    "apply_fix": "Applying code fix",
    "final_answer": "Producing final analysis",
}


def _extract_step_description(step) -> str:
    """Extract a human-readable description from a smolagents step.

    Priority:
    1. step.model_output → parse "Thought:" line, first sentence ≤120 chars
    2. Parse code in tool_calls arguments for known tool names
    3. Fallback: "(reasoning)"
    """
    # 1. Try model_output (LLM's own words)
    model_output = getattr(step, "model_output", None)
    if model_output and isinstance(model_output, str):
        for line in model_output.split("\n"):
            stripped = line.strip()
            if stripped.lower().startswith("thought:"):
                thought = stripped[len("thought:"):].strip()
                if not thought or thought.endswith(":"):
                    continue  # skip empty or intro-only thoughts
                # Take first sentence (up to period)
                dot_idx = thought.find(".")
                if 0 < dot_idx < 120:
                    return thought[:dot_idx + 1]
                # No period — truncate at word boundary
                if len(thought) > 120:
                    cut = thought[:120].rfind(" ")
                    if cut > 40:
                        return thought[:cut] + "..."
                    return thought[:120] + "..."
                return thought

    # 2. Parse code for known tool function calls
    tool_calls = getattr(step, "tool_calls", None)
    if tool_calls:
        for tc in tool_calls:
            args = getattr(tc, "arguments", None)
            if isinstance(args, str):
                for tool_name, desc in _TOOL_DESCRIPTIONS.items():
                    if tool_name + "(" in args:
                        return desc
            # If not python_interpreter, use tool name directly
            name = getattr(tc, "name", "")
            if name and name != "python_interpreter":
                return name

    # 3. Fallback
    return "(reasoning)"


def make_step_logger(
    agent_name: str,
    max_seconds: float | None = None,
) -> Callable:
    """Create a step callback that logs per-step info and enforces timeout.

    Args:
        agent_name: Label for CI logs (e.g. "Triage", "AppSec").
        max_seconds: If set, interrupts agent after this many seconds total.

    Returns:
        Callback compatible with smolagents step_callbacks.

    CI output example::

        [Triage] Step 1/3 (1.8s) — I need to fetch the PR files... | 3.0k tok
        [AppSec] Step 2/10 (13.0s) — Running Semgrep scan | 11.9k tok
        [AppSec] TIMEOUT after 605s (limit: 600s)
    """
    start_time = time.monotonic()

    def callback(step, **kwargs):
        elapsed = time.monotonic() - start_time

        # Step info
        step_num = getattr(step, "step_number", "?")
        agent = kwargs.get("agent")
        max_steps = getattr(agent, "max_steps", "?") if agent else "?"

        # Duration
        duration = 0.0
        timing = getattr(step, "timing", None)
        if timing:
            duration = getattr(timing, "duration", 0.0) or 0.0

        # Step description (natural language from LLM or tool mapping)
        tools_str = _extract_step_description(step)

        # Token usage
        tok_str = ""
        token_usage = getattr(step, "token_usage", None)
        if token_usage:
            total = (getattr(token_usage, "input_tokens", 0) or 0) + \
                    (getattr(token_usage, "output_tokens", 0) or 0)
            if total > 0:
                tok_str = f" | {total / 1000:.1f}k tok"

        print(f"  [{agent_name}] Step {step_num}/{max_steps} "
              f"({duration:.1f}s) — {tools_str}{tok_str}")

        # Timeout check
        if max_seconds is not None and elapsed > max_seconds:
            if agent:
                agent.interrupt_switch = True
            print(f"  [{agent_name}] TIMEOUT after {elapsed:.0f}s "
                  f"(limit: {max_seconds:.0f}s)")

    return callback


def run_with_timeout(
    fn: Callable,
    args: tuple = (),
    *,
    max_seconds: float,
    agent_name: str = "Agent",
    agent: Any = None,
) -> Any:
    """Execute fn(*args) with a hard thread-based timeout and heartbeat.

    Runs ``fn(*args)`` in a daemon thread. While waiting, prints a
    heartbeat message every 30 s so CI output never goes silent.
    If the function doesn't complete within *max_seconds*, sets
    ``agent.interrupt_switch = True`` (if agent provided) and raises
    :class:`TimeoutError`.

    Args:
        fn: Callable to execute (e.g. ``run_triage`` or ``agent.run``).
        args: Positional arguments for *fn*.
        max_seconds: Hard timeout in seconds.
        agent_name: Label for heartbeat / timeout messages.
        agent: Optional smolagents agent — used to set interrupt_switch.

    Returns:
        Whatever *fn* returns.

    Raises:
        TimeoutError: If *fn* doesn't complete within *max_seconds*.
        Exception: Re-raised if *fn* raises.
    """
    result_holder: list[Any] = [None]
    error_holder: list[BaseException | None] = [None]

    def target():
        try:
            result_holder[0] = fn(*args)
        except Exception as exc:
            error_holder[0] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()

    start = time.monotonic()
    while thread.is_alive():
        remaining = max_seconds - (time.monotonic() - start)
        if remaining <= 0:
            break
        thread.join(timeout=min(30, remaining))
        if thread.is_alive():
            elapsed = time.monotonic() - start
            if elapsed < max_seconds:
                print(f"  [{agent_name}] Still running... ({elapsed:.0f}s)")

    if thread.is_alive():
        # Hard timeout — try graceful shutdown
        if agent is not None:
            agent.interrupt_switch = True
        elapsed = time.monotonic() - start
        print(
            f"  [{agent_name}] HARD TIMEOUT — "
            f"{elapsed:.0f}s elapsed (limit: {max_seconds:.0f}s)"
        )
        # Grace period: let the agent finish current step
        thread.join(timeout=10)
        raise TimeoutError(
            f"{agent_name} did not complete within {max_seconds:.0f}s"
        )

    if error_holder[0]:
        raise error_holder[0]

    return result_holder[0]
