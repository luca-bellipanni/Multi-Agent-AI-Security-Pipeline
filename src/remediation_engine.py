"""Remediation workflow orchestrator.

Triggered by `/remediate` comment on a PR. Loads scan-results.json,
parses /dismiss commands, computes final findings, runs the Remediation
Agent per-file, and creates a Draft PR with individual commits per finding.

Security:
- subprocess array form, never shell=True (command injection)
- scope lock on writes via ApplyFixTool
- fix audit log written at end (LLM05)
- Draft PR only (human-in-the-loop)
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field

import requests

from src.github_context import GitHubContext
from src.scan_results import ScanResults, load_scan_results, SCAN_RESULTS_FILE


@dataclass
class RemediationResult:
    """Result of a remediation run."""
    status: str  # "success" | "nothing_to_fix" | "error"
    pr_url: str = ""
    fixes_applied: int = 0
    fixes_failed: int = 0
    error: str = ""


def parse_remediate_command(body: str) -> bool:
    """Check if comment body is a /remediate command."""
    return body.strip().lower().startswith("/remediate")


def parse_dismiss_commands(comments: list[dict]) -> dict[str, str]:
    """Parse /dismiss commands from PR comments.

    Returns {finding_id: reason}.
    Format: /dismiss F{6hex} reason text
    """
    dismissals: dict[str, str] = {}
    for c in comments:
        body = c.get("body", "")
        match = re.match(
            r"^/dismiss\s+(F[a-f0-9]{6})\s+(.+)$",
            body.strip(),
            re.IGNORECASE,
        )
        if match:
            dismissals[match.group(1)] = match.group(2).strip()
    return dismissals


def fetch_pr_comments(
    token: str, repository: str, pr_number: int, timeout: int = 10,
) -> list[dict]:
    """Fetch PR comments from GitHub API."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{repository}/issues/{pr_number}/comments"

    try:
        resp = requests.get(
            url, headers=headers,
            params={"per_page": 100},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"::warning::Failed to fetch PR comments: {e}")
        return []


def compute_final_findings(
    scan_results: ScanResults,
    dismiss_commands: dict[str, str],
) -> list[dict]:
    """Compute final finding list for remediation.

    confirmed + (warnings not dismissed) = final list.
    """
    final = list(scan_results.confirmed)

    for w in scan_results.warnings:
        fid = w.get("finding_id", "")
        if fid and fid not in dismiss_commands:
            final.append(w)

    return final


class RemediationEngine:
    """Orchestrates the remediation workflow."""

    def __init__(
        self,
        api_key: str = "",
        model_id: str = "gpt-4o-mini",
    ):
        self._api_key = api_key
        self._model_id = model_id
        self._workspace = ""
        self._pr_files: list[str] = []
        self._all_fix_logs: list[dict] = []

    def remediate(self, ctx: GitHubContext) -> RemediationResult:
        """Main entry point for the remediation workflow."""
        self._workspace = ctx.workspace

        # 1. Load scan-results.json
        sr_path = os.path.join(ctx.workspace, SCAN_RESULTS_FILE)
        try:
            scan_results = load_scan_results(sr_path)
        except (FileNotFoundError, ValueError) as e:
            return RemediationResult(
                status="error",
                error=f"Cannot load scan results: {e}",
            )

        # 2. Fetch PR comments, parse /dismiss commands
        comments = []
        if ctx.token and ctx.repository and ctx.pr_number:
            comments = fetch_pr_comments(
                ctx.token, ctx.repository, ctx.pr_number,
            )
        dismissals = parse_dismiss_commands(comments)

        # 3. Compute final findings
        final_findings = compute_final_findings(scan_results, dismissals)
        if not final_findings:
            return RemediationResult(status="nothing_to_fix")

        # 4. Collect PR file paths for scope lock
        self._pr_files = list({
            f.get("path", "") for f in scan_results.raw_findings if f.get("path")
        })

        # 5. Create branch
        branch = f"security/fix-{ctx.pr_number}"
        try:
            self._create_branch(branch)
        except subprocess.CalledProcessError as e:
            return RemediationResult(
                status="error", error=f"Failed to create branch: {e}",
            )

        # 6. Group findings by file
        by_file = self._group_by_file(final_findings)

        # 7. Per-file remediation
        fixes_applied = 0
        fixes_failed = 0
        for file_path, file_findings in by_file.items():
            try:
                fix_log = self._fix_file(ctx, file_path, file_findings)
                applied = [e for e in fix_log if e["applied"]]
                fixes_applied += len(applied)
                if applied:
                    self._replay_commits(file_path, applied, file_findings)
            except Exception as e:
                print(f"::warning::Fix failed for {file_path}: {e}")
                fixes_failed += len(file_findings)
                self._revert_uncommitted()

        if fixes_applied == 0:
            return RemediationResult(
                status="error",
                error="No fixes could be applied",
                fixes_failed=fixes_failed,
            )

        # 8. Push + create Draft PR
        try:
            self._push_branch(branch)
            pr_url = self._create_draft_pr(ctx, branch, final_findings)
        except (subprocess.CalledProcessError, requests.RequestException) as e:
            return RemediationResult(
                status="error",
                error=f"Failed to push/create PR: {e}",
                fixes_applied=fixes_applied,
            )

        # 9. Write fix audit log
        self._write_audit_log(ctx, branch)

        return RemediationResult(
            status="success",
            pr_url=pr_url,
            fixes_applied=fixes_applied,
            fixes_failed=fixes_failed,
        )

    def _group_by_file(self, findings: list[dict]) -> dict[str, list[dict]]:
        """Group findings by file path."""
        by_file: dict[str, list[dict]] = {}
        for f in findings:
            path = f.get("path", "")
            if path:
                by_file.setdefault(path, []).append(f)
        return by_file

    def _fix_file(
        self, ctx: GitHubContext, file_path: str, findings: list[dict],
    ) -> list[dict]:
        """Run Remediation Agent for all findings in one file."""
        from src.remediation_tools import ReadCodeTool, ApplyFixTool
        from src.remediation_agent import (
            create_remediation_agent, build_remediation_task,
        )

        read_tool = ReadCodeTool(workspace_path=ctx.workspace)
        apply_tool = ApplyFixTool(
            workspace_path=ctx.workspace,
            allowed_files=self._pr_files,
        )

        agent = create_remediation_agent(
            api_key=self._api_key,
            model_id=self._model_id,
            tools=[read_tool, apply_tool],
        )
        task = build_remediation_task(file_path, findings)
        agent.run(task)

        # Side channel: read fix audit log
        self._all_fix_logs.extend(apply_tool._fix_log)
        return [e for e in apply_tool._fix_log if e["applied"]]

    def _replay_commits(
        self,
        file_path: str,
        fix_log: list[dict],
        findings: list[dict],
    ) -> None:
        """Replay fix_log entries as individual commits per finding.

        Security (command injection): subprocess array form, never shell=True.
        """
        if not fix_log:
            return

        finding_lookup = {f.get("finding_id", ""): f for f in findings}
        full_path = os.path.join(self._workspace, file_path)

        # Restore to original state
        with open(full_path, "w") as f:
            f.write(fix_log[0]["old_content"])

        # Replay each fix as individual commit
        for entry in fix_log:
            with open(full_path, "w") as f:
                f.write(entry["new_content"])

            finding = finding_lookup.get(entry["finding_id"], {})
            rule_id = finding.get("rule_id", entry["finding_id"])
            line = finding.get("line", "?")

            subprocess.run(
                ["git", "add", file_path],
                check=True, cwd=self._workspace,
            )
            msg = f"fix: {rule_id} in {file_path}:{line}"
            subprocess.run(
                ["git", "commit", "-m", msg],
                check=True, cwd=self._workspace,
            )

    def _create_branch(self, branch: str) -> None:
        subprocess.run(
            ["git", "checkout", "-b", branch],
            check=True, cwd=self._workspace,
        )

    def _revert_uncommitted(self) -> None:
        subprocess.run(
            ["git", "checkout", "."],
            cwd=self._workspace,
        )

    def _push_branch(self, branch: str) -> None:
        subprocess.run(
            ["git", "push", "origin", branch],
            check=True, cwd=self._workspace,
        )

    def _create_draft_pr(
        self,
        ctx: GitHubContext,
        branch: str,
        findings: list[dict],
    ) -> str:
        """Create a draft PR with the fixes."""
        headers = {
            "Authorization": f"token {ctx.token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Build body
        body_lines = [
            f"## Security fixes for PR #{ctx.pr_number}",
            "",
            f"Fixes {len(findings)} security finding(s):",
            "",
        ]
        for f in findings:
            fid = f.get("finding_id", "?")
            rule = f.get("rule_id", "?")
            sev = f.get("severity", "?")
            body_lines.append(f"- [{sev.upper()}] `{rule}` ({fid})")

        body_lines.extend([
            "",
            "---",
            "*Generated by Agentic AppSec Pipeline*",
        ])

        url = f"https://api.github.com/repos/{ctx.repository}/pulls"
        resp = requests.post(
            url,
            headers=headers,
            json={
                "title": f"Security fixes for PR #{ctx.pr_number}",
                "body": "\n".join(body_lines),
                "head": branch,
                "base": ctx.ref.replace("refs/heads/", "")
                    if ctx.ref.startswith("refs/heads/") else "main",
                "draft": True,
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("html_url", "")

    def _write_audit_log(self, ctx: GitHubContext, branch: str) -> None:
        """Write fix-audit-log.json to workspace."""
        log_data = {
            "version": "1.0",
            "pr_number": ctx.pr_number,
            "branch": branch,
            "fixes": self._all_fix_logs,
        }
        log_path = os.path.join(ctx.workspace, ".appsec", "fix-audit-log.json")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "w") as f:
            json.dump(log_data, f, indent=2)
            f.write("\n")
