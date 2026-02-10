"""Agentic AppSec Pipeline — entry point."""

import os
import sys

from src.github_context import GitHubContext
from src.decision_engine import DecisionEngine


def write_outputs(outputs: dict[str, str]) -> None:
    """Write key=value pairs to GITHUB_OUTPUT."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
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

    ctx = GitHubContext.from_environment()
    print(f"Mode: {ctx.mode}")

    engine = DecisionEngine()
    decision = engine.decide(ctx)
    print(f"Decision: {decision.verdict.value}")
    print(f"Reason: {decision.reason}")

    write_outputs(decision.to_outputs())

    if not decision.continue_pipeline:
        print("::warning::Pipeline blocked by Agentic AppSec")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
