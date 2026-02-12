"""
Tools for the Agentic AppSec Pipeline agents.

Each tool is a smolagents Tool subclass that an agent can call.
Secrets (tokens, keys) are injected via the constructor — never
exposed as LLM-visible parameters.
"""

import os

import requests
from smolagents import Tool


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
