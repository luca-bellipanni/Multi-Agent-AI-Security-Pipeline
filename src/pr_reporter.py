"""PR comment reporter — posts analysis results as PR comment.

Generates a Markdown comment with the pipeline execution trace,
confirmed findings, warnings, dismissed, and excepted findings.
Uses an HTML marker for upsert (update existing or create new).

Security (LLM01): body contains AI-generated text (reason, summary).
GitHub sanitizes HTML in comments. Structured data (rule_id, path, line)
comes from the gate (gate-validated), not from agent output directly.
"""

import requests

from src.models import Decision

# HTML marker for upsert: find existing comment to update
COMMENT_MARKER = "<!-- appsec-bot-report -->"


def format_comment(decision: Decision) -> str:
    """Generate Markdown PR comment from Decision.

    Includes execution trace table, confirmed findings, dismissed,
    excepted, and safety warnings.
    """
    lines: list[str] = []

    # Header
    verdict = decision.verdict.value.upper()
    mode = decision.mode
    count = decision.findings_count
    lines.append(
        f"## Verdict: `{verdict}` | Mode: `{mode}` | "
        f"{count} finding(s)"
    )
    lines.append("")

    # Pipeline trace table
    if decision.trace:
        lines.append("### Pipeline")
        lines.append("")
        lines.append("| # | Phase | Tools | Result |")
        lines.append("|---|-------|-------|--------|")
        for i, step in enumerate(decision.trace, 1):
            tools_str = _format_tools_used(step.tools_used)
            lines.append(
                f"| {i} | {step.name} | {tools_str} | {step.summary} |"
            )
        lines.append("")

    # Confirmed findings
    if decision.confirmed_findings:
        lines.append(f"### Confirmed Findings ({len(decision.confirmed_findings)})")
        lines.append("")
        lines.append("| ID | Sev | Rule | File | Line |")
        lines.append("|----|-----|------|------|------|")
        for f in decision.confirmed_findings:
            fid = f.get("finding_id", "?")
            sev = f.get("severity", "?").upper()
            rule = f"`{f.get('rule_id', '?')}`"
            path = f"`{f.get('path', '?')}`"
            line = f.get("line", "?")
            lines.append(f"| {fid} | {sev} | {rule} | {path} | {line} |")
        lines.append("")

        # Details (collapsible)
        lines.append("<details><summary>Details</summary>")
        lines.append("")
        for f in decision.confirmed_findings:
            sev = f.get("severity", "?").upper()
            rule = f.get("rule_id", "?")
            path = f.get("path", "?")
            line = f.get("line", "?")
            lines.append(f"**[{sev}] {rule}** at `{path}:{line}`")
            reason = f.get("agent_reason", "")
            if reason:
                lines.append(f"- Analysis: {reason}")
            rec = f.get("agent_recommendation", "")
            if rec:
                lines.append(f"- Fix: {rec}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

    # Safety warnings
    if decision.safety_warnings:
        lines.append(
            f"### Safety Warnings ({len(decision.safety_warnings)})"
        )
        lines.append("")
        for w in decision.safety_warnings:
            wtype = w.get("type", "unknown")
            rule = w.get("rule_id", "?")
            sev = w.get("severity", "?").upper()
            msg = w.get("message", "")
            lines.append(f"- **{wtype}**: [{sev}] `{rule}` — {msg}")
        lines.append("")

    # Excepted findings (collapsible)
    if decision.excepted_findings:
        n = len(decision.excepted_findings)
        lines.append(
            f"<details><summary>Auto-excepted by memory ({n})</summary>"
        )
        lines.append("")
        for e in decision.excepted_findings:
            sev = e.get("severity", "?")
            rule = e.get("rule_id", "?")
            path = e.get("path", "?")
            line = e.get("line", "?")
            reason = e.get("exception_reason", "")
            lines.append(f"- [{sev}] `{rule}` at `{path}:{line}` — {reason}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Dismissed findings (collapsible)
    if decision.dismissed_findings:
        n = len(decision.dismissed_findings)
        lines.append(
            f"<details><summary>Dismissed by agent ({n})</summary>"
        )
        lines.append("")
        for d in decision.dismissed_findings:
            rule = d.get("rule_id", "?")
            reason = d.get("reason", "no reason")
            lines.append(f"- `{rule}` — {reason}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append(
        f"*Agentic AppSec Pipeline -- {mode} mode -- "
        f"{decision.timestamp}*"
    )
    lines.append(COMMENT_MARKER)

    return "\n".join(lines)


def _format_tools_used(tools_used: dict[str, int]) -> str:
    """Format tool usage dict for the trace table."""
    if not tools_used:
        return "--"
    parts = []
    for name, count in tools_used.items():
        parts.append(f"`{name}` x{count}")
    return ", ".join(parts)


def post_comment(
    token: str,
    repository: str,
    pr_number: int,
    body: str,
    timeout: int = 10,
) -> None:
    """Post or update PR comment with upsert via HTML marker.

    - GET existing comments, search for marker
    - If found: PATCH to update
    - If not found: POST to create
    - Errors logged as warnings, never block pipeline
    """
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    base_url = f"https://api.github.com/repos/{repository}"
    comments_url = f"{base_url}/issues/{pr_number}/comments"

    try:
        # Search for existing comment with marker
        existing_id = _find_existing_comment(
            comments_url, headers, timeout,
        )

        if existing_id:
            # Update existing comment
            patch_url = f"{base_url}/issues/comments/{existing_id}"
            resp = requests.patch(
                patch_url,
                headers=headers,
                json={"body": body},
                timeout=timeout,
            )
            resp.raise_for_status()
            print(f"Updated existing PR comment (id={existing_id})")
        else:
            # Create new comment
            resp = requests.post(
                comments_url,
                headers=headers,
                json={"body": body},
                timeout=timeout,
            )
            resp.raise_for_status()
            print("Created new PR comment")

    except requests.RequestException as e:
        print(f"::warning::Failed to post PR comment: {e}")


def _find_existing_comment(
    comments_url: str,
    headers: dict,
    timeout: int,
) -> int | None:
    """Find existing comment with our marker. Returns comment ID or None."""
    try:
        resp = requests.get(
            comments_url,
            headers=headers,
            params={"per_page": 100},
            timeout=timeout,
        )
        resp.raise_for_status()

        for comment in resp.json():
            if COMMENT_MARKER in comment.get("body", ""):
                return comment["id"]
    except requests.RequestException:
        pass  # If we can't find existing, we'll create new

    return None
