"""
Agentic AppSec Pipeline - Entry Point

Reads GitHub Actions environment, makes a security decision, writes outputs.

Step 1: deterministic logic only.
- shadow mode  → decision=allowed,       continue_pipeline=true
- enforce mode → decision=manual_review,  continue_pipeline=false
"""

import os
import sys


def get_mode() -> str:
    """Read the operating mode from GitHub Actions input."""
    mode = os.environ.get("INPUT_MODE", "shadow")
    if mode not in ("shadow", "enforce"):
        print(f"::warning::Unknown mode '{mode}', defaulting to 'shadow'")
        mode = "shadow"
    return mode


def decide(mode: str) -> dict:
    """Make a security decision based on the mode."""
    if mode == "shadow":
        return {
            "decision": "allowed",
            "continue_pipeline": "true",
            "reason": "Shadow mode: observing only, pipeline continues.",
        }
    else:  # enforce
        return {
            "decision": "manual_review",
            "continue_pipeline": "false",
            "reason": "Enforce mode: no security tools configured yet, requiring manual review.",
        }


def write_outputs(outputs: dict) -> None:
    """Write key=value pairs to GITHUB_OUTPUT so subsequent steps can read them."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        # Running locally, just print
        print("--- Outputs (no GITHUB_OUTPUT file) ---")
        for key, value in outputs.items():
            print(f"  {key}={value}")
        return

    with open(output_path, "a") as f:
        for key, value in outputs.items():
            f.write(f"{key}={value}\n")
            print(f"  Output: {key}={value}")


def main() -> int:
    print("=== Agentic AppSec Pipeline ===")

    mode = get_mode()
    print(f"Mode: {mode}")

    outputs = decide(mode)
    print(f"Decision: {outputs['decision']}")
    print(f"Reason: {outputs['reason']}")

    write_outputs(outputs)

    # In shadow mode, always exit 0 (don't block the pipeline)
    # In enforce mode, exit 1 if we're blocking
    if mode == "enforce" and outputs["continue_pipeline"] == "false":
        print("::warning::Pipeline blocked by Agentic AppSec (enforce mode)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
