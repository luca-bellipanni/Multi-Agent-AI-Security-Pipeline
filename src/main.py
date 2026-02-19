"""Agentic AppSec Pipeline — entry point."""

import os
import sys
import uuid

from src.github_context import GitHubContext
from src.decision_engine import DecisionEngine


def write_outputs(outputs: dict[str, str]) -> None:
    """Write outputs to GITHUB_OUTPUT using multiline-safe delimiters.

    Uses the heredoc-style delimiter format to prevent injection via
    newlines in AI-generated values (e.g. the 'reason' field).
    See: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#multiline-strings
    """
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        print("--- Outputs (no GITHUB_OUTPUT file) ---")
        for key, value in outputs.items():
            print(f"  {key}={value}")
        return

    with open(output_path, "a") as f:
        for key, value in outputs.items():
            delimiter = f"ghadelimiter_{uuid.uuid4().hex}"
            f.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")
            print(f"  Output: {key}={value}")


def _run_scan(ctx: GitHubContext) -> int:
    """Run the scan workflow (existing logic)."""
    engine = DecisionEngine()
    decision = engine.decide(ctx)

    # Save exception memory (auto-exceptions for next run)
    try:
        engine.save_memory()
    except OSError as e:
        print(f"::warning::Could not save exception memory: {e}")

    # PR Reporting: comment + scan-results.json
    print("::group::PR Report")
    try:
        if ctx.is_pull_request and ctx.pr_number:
            from src.pr_reporter import format_comment, post_comment
            from src.scan_results import build_scan_results, write_scan_results

            # Collect raw findings from tool results
            raw_findings = []
            for tr in decision.tool_results:
                raw_findings.extend(tr.findings)

            # Build and write scan-results.json
            sr = build_scan_results(
                decision, raw_findings,
                pr_number=ctx.pr_number, repository=ctx.repository,
            )
            sr_path = write_scan_results(sr, ctx.workspace)
            decision.scan_results_path = sr_path
            print(f"scan-results.json written to {sr_path}")

            # Post PR comment
            if ctx.token:
                body = format_comment(decision)
                post_comment(
                    ctx.token, ctx.repository, ctx.pr_number, body,
                )
            else:
                print("No GitHub token, skipping PR comment")
        else:
            print("Not a PR event, skipping PR report")
    except Exception as e:
        print(f"::warning::PR reporting failed: {e}")
    finally:
        print("::endgroup::")

    # Footer info
    if decision.scan_results_path:
        print(f"\n  📄 {decision.scan_results_path}")
    if ctx.is_pull_request and ctx.pr_number and ctx.token:
        pr_url = (f"https://github.com/{ctx.repository}"
                  f"/pull/{ctx.pr_number}")
        print(f"  🔗 {pr_url}")

    write_outputs(decision.to_outputs())

    if not decision.continue_pipeline:
        print("\n  Pipeline: stopped")
        print()
        print("━" * 60)
        return 1
    print("\n  Pipeline: continue")
    print()
    print("━" * 60)
    return 0


def _run_remediation(ctx: GitHubContext) -> int:
    """Run the remediation workflow."""
    from src.remediation_engine import RemediationEngine

    print("::group::Remediation")
    try:
        api_key = os.environ.get("INPUT_AI_API_KEY", "")
        model_id = os.environ.get("INPUT_AI_MODEL", "gpt-4o-mini")

        if not api_key:
            print("::error::Remediation requires an AI API key.")
            return 1

        engine = RemediationEngine(api_key=api_key, model_id=model_id)
        result = engine.remediate(ctx)

        print(f"Status: {result.status}")
        print(f"Fixes applied: {result.fixes_applied}")
        print(f"Fixes failed: {result.fixes_failed}")
        if result.pr_url:
            print(f"Draft PR: {result.pr_url}")
        if result.error:
            print(f"Error: {result.error}")

        write_outputs({
            "remediation_status": result.status,
            "remediation_pr_url": result.pr_url,
            "fixes_applied": str(result.fixes_applied),
            "fixes_failed": str(result.fixes_failed),
        })

        return 0 if result.status == "success" else 1

    except Exception as e:
        print(f"::error::Remediation failed: {e}")
        return 1
    finally:
        print("::endgroup::")


def main() -> int:
    print()
    print("━" * 60)
    print("  🔒 MULTI-AGENT AI SECURITY PIPELINE")
    print("━" * 60)
    print()
    print("::group::Pipeline Info")
    ctx = GitHubContext.from_environment()
    command = os.environ.get("INPUT_COMMAND", "scan")
    print(f"Mode: {ctx.mode}")
    print(f"Command: {command}")
    print("::endgroup::")

    if command == "remediate":
        return _run_remediation(ctx)
    return _run_scan(ctx)


if __name__ == "__main__":
    sys.exit(main())
