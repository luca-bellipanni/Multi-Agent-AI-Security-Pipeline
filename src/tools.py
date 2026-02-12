"""
Tools for the Agentic AppSec Pipeline agents.

Each tool is a smolagents Tool subclass that an agent can call.
Secrets (tokens, keys) are injected via the constructor — never
exposed as LLM-visible parameters.
"""

import json as json_module
import os
import subprocess

import requests
from smolagents import Tool

from src.models import Finding, Severity


# --- Constants ---

# Maps file extensions to language categories
EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".cs": "csharp",
    ".php": "php",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".toml": "toml",
    ".ini": "config",
    ".cfg": "config",
    ".tf": "terraform",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".md": "markdown",
    ".txt": "text",
    ".lock": "lockfile",
}

# Files that indicate dependency changes (relevant for Trivy/SCA)
DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile",
    "Pipfile.lock",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}

# GitHub API file status → short letter
STATUS_SHORT = {
    "added": "A",
    "modified": "M",
    "removed": "D",
    "renamed": "R",
    "copied": "C",
    "changed": "M",
    "unchanged": "U",
}


# --- Helper functions ---

def _get_language(filename: str) -> str:
    """Determine language/category from a filename."""
    _, ext = os.path.splitext(filename)
    if ext:
        return EXTENSION_MAP.get(ext.lower(), ext.lstrip("."))
    return "unknown"


def _format_pr_files(pr_number: int, title: str, files: list[dict]) -> str:
    """Format GitHub API file list into a human-readable summary."""
    if not files:
        return f"PR #{pr_number}: {title}\nNo files changed."

    lines = [f"PR #{pr_number}: {title}", f"Files changed ({len(files)}):"]

    total_additions = 0
    total_deletions = 0
    languages: set[str] = set()
    dep_files: list[str] = []

    for f in files:
        filename = f["filename"]
        status = STATUS_SHORT.get(f.get("status", "modified"), "?")
        additions = f.get("additions", 0)
        deletions = f.get("deletions", 0)
        lang = _get_language(filename)

        total_additions += additions
        total_deletions += deletions
        languages.add(lang)

        lang_tag = f" [{lang}]" if lang != "unknown" else ""
        lines.append(f"  {status} {filename:<40s} (+{additions} -{deletions}){lang_tag}")

        basename = os.path.basename(filename)
        if basename in DEPENDENCY_FILES:
            dep_files.append(filename)

    # Language summary
    lang_counts: dict[str, int] = {}
    for f in files:
        lang = _get_language(f["filename"])
        lang_counts[lang] = lang_counts.get(lang, 0) + 1

    summary_parts = [
        f"{count} {lang} file{'s' if count > 1 else ''}"
        for lang, count in sorted(lang_counts.items())
    ]
    lines.append("")
    lines.append(
        f"Summary: {', '.join(summary_parts)}. "
        f"{total_additions} additions, {total_deletions} deletions."
    )
    lines.append(f"Languages: {', '.join(sorted(languages))}")

    if dep_files:
        lines.append(f"Dependency files changed: {', '.join(dep_files)}")

    return "\n".join(lines)


# --- Tool class ---

class FetchPRFilesTool(Tool):
    """Fetches the list of files changed in a GitHub pull request.

    Returns file names, change status, additions/deletions, and detected
    language for each file. Does NOT return file content or diffs.
    """

    name = "fetch_pr_files"
    description = (
        "Fetches metadata about files changed in a GitHub pull request. "
        "Returns file names, status (added/modified/deleted), lines changed, "
        "and detected language. Use this to decide which security tools to run."
    )
    inputs = {
        "pr_number": {
            "type": "integer",
            "description": "The pull request number to fetch files for.",
        }
    }
    output_type = "string"

    def __init__(self, github_token: str, repository: str, **kwargs):
        # Set instance attrs BEFORE super().__init__() which runs validation
        self.github_token = github_token
        self.repository = repository
        super().__init__(**kwargs)

    def forward(self, pr_number: int) -> str:
        """Fetch PR file list from GitHub API and return formatted summary."""
        if not self.github_token:
            return "Error: No GitHub token available. Cannot fetch PR files."
        if not self.repository:
            return "Error: No repository configured. Cannot fetch PR files."

        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        # Fetch PR title (best-effort)
        title = "(unknown)"
        try:
            pr_url = f"https://api.github.com/repos/{self.repository}/pulls/{pr_number}"
            pr_resp = requests.get(pr_url, headers=headers, timeout=10)
            if pr_resp.status_code == 200:
                title = pr_resp.json().get("title", "(unknown)")
        except Exception:
            pass

        # Fetch files (paginated, up to 300 files)
        all_files: list[dict] = []
        for page in range(1, 4):  # max 3 pages
            url = f"https://api.github.com/repos/{self.repository}/pulls/{pr_number}/files"
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    params={"per_page": 100, "page": page},
                    timeout=10,
                )
            except requests.RequestException as e:
                return f"Error: GitHub API request failed: {e}"

            if resp.status_code == 404:
                return f"Error: PR #{pr_number} not found in {self.repository}."
            if resp.status_code == 403:
                return "Error: GitHub API rate limit or permission denied."
            if resp.status_code != 200:
                return f"Error: GitHub API returned status {resp.status_code}."

            batch = resp.json()
            if not batch:
                break
            all_files.extend(batch)
            if len(batch) < 100:
                break

        return _format_pr_files(pr_number, title, all_files)


# --- Semgrep constants ---

# Allowed Semgrep ruleset prefixes (security: prevent path traversal)
ALLOWED_RULESET_PREFIXES = ("p/", "r/", "s/")

# Maximum number of rulesets per scan (prevent resource abuse — LLM10)
MAX_RULESETS = 10

# Default timeout for semgrep execution in seconds
SEMGREP_TIMEOUT = 300

# Semgrep severity → our Severity mapping
SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def parse_semgrep_findings(raw_json: str) -> list[Finding]:
    """Parse raw Semgrep JSON output into Finding objects."""
    try:
        data = json_module.loads(raw_json)
    except (json_module.JSONDecodeError, TypeError):
        return []

    findings = []
    for r in data.get("results", []):
        sev_str = r.get("extra", {}).get("severity", "INFO")
        severity = SEMGREP_SEVERITY_MAP.get(sev_str, Severity.LOW)

        findings.append(Finding(
            tool="semgrep",
            rule_id=r.get("check_id", "unknown"),
            path=r.get("path", "unknown"),
            line=r.get("start", {}).get("line", 0),
            severity=severity,
            message=r.get("extra", {}).get("message", ""),
        ))
    return findings


def _format_semgrep_findings(raw_json: str) -> str:
    """Format raw Semgrep JSON into human-readable output for the agent."""
    try:
        data = json_module.loads(raw_json)
    except (json_module.JSONDecodeError, TypeError):
        return "Error: Could not parse Semgrep output."

    results = data.get("results", [])
    errors = data.get("errors", [])

    if not results and not errors:
        return "Semgrep scan complete. No findings."

    lines = [f"Semgrep scan complete. {len(results)} finding(s):"]
    for r in results:
        check_id = r.get("check_id", "unknown")
        path = r.get("path", "unknown")
        line = r.get("start", {}).get("line", 0)
        severity = r.get("extra", {}).get("severity", "INFO")
        message = r.get("extra", {}).get("message", "No message")
        lines.append(f"  [{severity}] {check_id} at {path}:{line} — {message}")

    if errors:
        lines.append(f"\n{len(errors)} scan error(s) occurred.")

    return "\n".join(lines)


def _validate_rulesets(config: str) -> tuple[list[str], str | None]:
    """Validate and parse comma-separated rulesets.

    Returns (validated_list, error_message_or_None).
    Security: allowlist prevents path traversal via --config.
    """
    rulesets = [r.strip() for r in config.split(",") if r.strip()]
    if not rulesets:
        return [], "Error: No rulesets provided."
    if len(rulesets) > MAX_RULESETS:
        return [], f"Error: Too many rulesets ({len(rulesets)}). Maximum is {MAX_RULESETS}."

    for rs in rulesets:
        if not any(rs.startswith(prefix) for prefix in ALLOWED_RULESET_PREFIXES):
            return [], f"Error: Ruleset '{rs}' not allowed. Must start with p/, r/, or s/."

    return rulesets, None


class SemgrepTool(Tool):
    """Runs Semgrep SAST scanner on the workspace.

    The workspace path is injected via the constructor (never visible to
    the LLM). The config (rulesets) is the only agent-controllable input,
    validated against an allowlist to prevent path traversal.
    """

    name = "run_semgrep"
    description = (
        "Runs Semgrep static analysis on the workspace with specified rulesets. "
        "Returns findings including rule ID, severity, file path, line number, "
        "and a description of each issue found. Use Semgrep registry rulesets "
        "like p/python, p/security-audit, p/owasp-top-ten."
    )
    inputs = {
        "config": {
            "type": "string",
            "description": (
                "Comma-separated Semgrep rulesets to use, e.g. "
                "'p/python,p/owasp-top-ten'. Must be Semgrep registry "
                "rulesets (p/..., r/..., s/...)."
            ),
        }
    }
    output_type = "string"

    def __init__(self, workspace_path: str, timeout: int = SEMGREP_TIMEOUT, **kwargs):
        self.workspace_path = workspace_path
        self.timeout = timeout
        # Side channel for the gate (LLM05: raw findings independent of agent)
        self._last_raw_findings: list[Finding] = []
        self._last_config_used: list[str] = []
        self._last_error: str = ""
        super().__init__(**kwargs)

    def forward(self, config: str) -> str:
        """Run semgrep with the given rulesets, return human-readable findings.

        Side effect: populates _last_raw_findings for the gate to read
        independently of what the agent reports (LLM05: untrusted output).
        """
        # Reset side channel
        self._last_raw_findings = []
        self._last_config_used = []
        self._last_error = ""

        rulesets, val_error = _validate_rulesets(config)
        if val_error:
            self._last_error = val_error
            return val_error

        self._last_config_used = rulesets

        raw_json, error = self._execute(config)
        if error:
            self._last_error = error
            return error

        # Side channel: save raw findings before returning to the agent
        self._last_raw_findings = parse_semgrep_findings(raw_json)
        return _format_semgrep_findings(raw_json)

    def run_and_parse(self, config: str) -> tuple[str, list[Finding]]:
        """Run semgrep and return (human_readable_output, list[Finding]).

        Used by DecisionEngine for structured access to findings.
        """
        raw_json, error = self._execute(config)
        if error:
            return error, []
        human_readable = _format_semgrep_findings(raw_json)
        findings = parse_semgrep_findings(raw_json)
        return human_readable, findings

    def _execute(self, config: str) -> tuple[str, str | None]:
        """Run semgrep subprocess. Returns (raw_json_stdout, error_or_None).

        Security (code-security/command-injection):
        - Array form subprocess, NEVER shell=True
        - Rulesets validated against allowlist
        """
        rulesets, error = _validate_rulesets(config)
        if error:
            return "", error

        # Build command — array form prevents command injection
        cmd = ["semgrep", "--json", "--quiet"]
        for rs in rulesets:
            cmd.extend(["--config", rs])
        cmd.append(self.workspace_path)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            return "", "Error: Semgrep is not installed or not accessible."
        except subprocess.TimeoutExpired:
            return "", f"Error: Semgrep timed out after {self.timeout} seconds."

        if not result.stdout.strip():
            stderr_preview = result.stderr[:500] if result.stderr else "no output"
            return "", f"Error: Semgrep produced no output. stderr: {stderr_preview}"

        return result.stdout, None
