"""PR comment reporter — posts analysis results as PR comment.

Generates a Markdown comment with the pipeline execution trace,
confirmed findings, warnings, dismissed, and excepted findings.
Uses an HTML marker for upsert (update existing or create new).

Security (LLM01): body contains AI-generated text (reason, summary).
GitHub sanitizes HTML in comments. Structured data (rule_id, path, line)
comes from the gate (gate-validated), not from agent output directly.
"""

import hashlib
import re

import requests

from src.models import Decision

# HTML marker for upsert: find existing comment to update
COMMENT_MARKER = "<!-- appsec-bot-report -->"


def _short_rule(rule_id: str) -> str:
    """Extract short rule name from full Semgrep rule ID."""
    return rule_id.rsplit(".", 1)[-1] if "." in rule_id else rule_id


def _short_path(path: str) -> str:
    """Strip CI workspace prefix for cleaner display."""
    for prefix in ("/github/workspace/", "/tmp/workspace/"):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def _compute_finding_id(rule_id: str, path: str, line: int) -> str:
    """Compute deterministic finding ID (same as models.Finding)."""
    key = f"{rule_id}::{path}::{line}"
    return "F" + hashlib.sha256(key.encode()).hexdigest()[:6]


def _resolve_duplicate_refs(
    reason: str, id_lookup: dict[tuple[str, int], str],
) -> str:
    """Replace rule_id+line refs in reason with finding IDs.

    Example: "duplicate: same issue covered by rule python.x.y at line 16"
    → "duplicate: see F63b1ad"
    """
    # Match "rule <rule_id> at line <N>" or "rule <rule_id> at <path>:<N>"
    def _replacer(m: re.Match) -> str:
        ref_rule = m.group(1)
        ref_line = int(m.group(2))
        # Try full rule_id
        fid = id_lookup.get((ref_rule, ref_line))
        if not fid:
            # Try short rule name
            short = _short_rule(ref_rule)
            fid = id_lookup.get((short, ref_line))
        if fid:
            return f"see {fid}"
        return m.group(0)

    return re.sub(
        r'(?:same issue covered by |see )?rule\s+(\S+)\s+at\s+'
        r'(?:line\s+)?(?:\S+:)?(\d+)',
        _replacer, reason,
    )


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

    # Build finding ID lookup for cross-references
    # Maps (rule_id, line) and (short_rule, line) → finding_id
    _id_lookup: dict[tuple[str, int], str] = {}
    for f in decision.confirmed_findings:
        fid = f.get("finding_id", "")
        rule = f.get("rule_id", "")
        line = f.get("line", 0)
        if fid and rule:
            _id_lookup[(rule, line)] = fid
            _id_lookup[(_short_rule(rule), line)] = fid

    # Findings table (confirmed + safety-net, unified)
    if decision.confirmed_findings:
        lines.append(
            f"### Findings ({len(decision.confirmed_findings)})"
        )
        lines.append("")
        lines.append("| ID | Sev | Rule | File | Line | Source |")
        lines.append("|----|-----|------|------|------|--------|")
        for f in decision.confirmed_findings:
            fid = f.get("finding_id", "?")
            sev = f.get("severity", "?").upper()
            rule = f"`{_short_rule(f.get('rule_id', '?'))}`"
            path = f"`{_short_path(f.get('path', '?'))}`"
            line = f.get("line", "?")
            source = f.get("source", "confirmed")
            src_label = ("agent" if source == "confirmed"
                         else "safety-net")
            lines.append(
                f"| {fid} | {sev} | {rule} | {path} | {line} "
                f"| {src_label} |"
            )
        lines.append("")

        # Details (collapsible) — with finding ID
        lines.append("<details><summary>Details</summary>")
        lines.append("")
        for f in decision.confirmed_findings:
            fid = f.get("finding_id", "?")
            sev = f.get("severity", "?").upper()
            rule = _short_rule(f.get("rule_id", "?"))
            path = _short_path(f.get("path", "?"))
            line = f.get("line", "?")
            lines.append(
                f"**{fid}** [{sev}] `{rule}` at `{path}:{line}`"
            )
            reason = f.get("agent_reason", "")
            source = f.get("source", "confirmed")
            if not reason and source == "safety-net":
                semgrep_msg = f.get("message", "")
                if semgrep_msg:
                    reason = semgrep_msg
                else:
                    reason = ("Flagged by safety net "
                              "(agent did not confirm this finding)")
            if reason:
                lines.append(f"- Analysis: {reason}")
            rec = f.get("agent_recommendation", "")
            if rec:
                lines.append(f"- Fix: {rec}")
            lines.append("")
        lines.append("</details>")
        lines.append("")

        # Safety-net explanation (brief note under table)
        safety_count = sum(
            1 for f in decision.confirmed_findings
            if f.get("source") == "safety-net"
        )
        if safety_count:
            lines.append(
                f"> **Safety net**: {safety_count} finding(s) marked "
                f"`safety-net` are HIGH/CRITICAL issues the AI agent "
                f"missed or dismissed. Included automatically as "
                f"precaution — review required."
            )
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
            rule = _short_rule(e.get("rule_id", "?"))
            path = _short_path(e.get("path", "?"))
            line = e.get("line", "?")
            reason = e.get("exception_reason", "")
            lines.append(
                f"- [{sev}] `{rule}` at `{path}:{line}` — {reason}"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Dismissed findings (collapsible) — with finding IDs
    if decision.dismissed_findings:
        n = len(decision.dismissed_findings)
        lines.append(
            f"<details><summary>Dismissed by agent ({n})</summary>"
        )
        lines.append("")
        for d in decision.dismissed_findings:
            rule_id = d.get("rule_id", "?")
            short = _short_rule(rule_id)
            path = d.get("path", "")
            line_num = d.get("line", 0)
            reason = d.get("reason", "no reason")
            # Compute finding ID for cross-reference
            if path and line_num:
                fid = _compute_finding_id(rule_id, path, line_num)
                # Resolve duplicate references to finding IDs
                resolved = _resolve_duplicate_refs(reason, _id_lookup)
                lines.append(f"- {fid} `{short}` — {resolved}")
            else:
                lines.append(f"- `{short}` — {reason}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # Next steps (only when there are findings)
    if decision.confirmed_findings:
        lines.append("### Next steps")
        lines.append("")
        lines.append(
            "1. **Review** each finding in the table above"
        )
        lines.append(
            "2. **Dismiss** a false positive by commenting: "
            "`/dismiss F<id> <reason>`"
        )
        lines.append(
            "3. **Auto-fix** confirmed findings by commenting: "
            "`/remediate`"
        )
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
