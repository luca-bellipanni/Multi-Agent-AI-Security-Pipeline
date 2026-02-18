"""Agent observability — step logging + timeout for CI visibility.

Provides make_step_logger(), a factory that returns a smolagents
step_callback. The callback prints per-step diagnostics (duration,
tools called, token usage) and enforces an optional agent-level timeout.

Used by decision_engine.py (triage + analyzer) and remediation_engine.py.
"""

import time
from typing import Callable


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

        [Triage] Step 1/3 (4.2s) — fetch_pr_files | 1.8k tok
        [Triage] Step 2/3 (2.1s) — (reasoning) | 0.9k tok
        [Triage] TIMEOUT after 125s (limit: 120s)
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

        # Tool calls
        tool_calls = getattr(step, "tool_calls", None)
        if tool_calls:
            tools_str = ", ".join(tc.name for tc in tool_calls)
        else:
            tools_str = "(reasoning)"

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
