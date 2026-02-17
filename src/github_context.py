"""Parse GitHub Actions environment into a clean dataclass."""

import json
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class GitHubContext:
    token: str
    mode: str
    workspace: str
    repository: str
    event_name: str
    sha: str
    ref: str
    pr_number: Optional[int]
    is_pull_request: bool
    comment_body: str = ""
    comment_author: str = ""
    pr_author: str = ""

    @classmethod
    def from_environment(cls) -> "GitHubContext":
        token = os.environ.get("INPUT_GITHUB_TOKEN", "")
        workspace = os.environ.get("GITHUB_WORKSPACE", ".")
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        event_name = os.environ.get("GITHUB_EVENT_NAME", "")
        sha = os.environ.get("GITHUB_SHA", "")
        ref = os.environ.get("GITHUB_REF", "")

        # Validate mode
        mode = os.environ.get("INPUT_MODE", "shadow")
        if mode not in ("shadow", "enforce"):
            print(f"::warning::Unknown mode '{mode}', defaulting to 'shadow'")
            mode = "shadow"

        # Extract context from event payload
        pr_number = None
        is_pull_request = event_name == "pull_request"
        comment_body = ""
        comment_author = ""
        pr_author = ""

        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if event_path and os.path.exists(event_path):
            with open(event_path) as f:
                event = json.load(f)

            if is_pull_request:
                pr_data = event.get("pull_request", {})
                pr_number = pr_data.get("number")
                pr_author = pr_data.get("user", {}).get("login", "")

            elif event_name == "issue_comment":
                issue = event.get("issue", {})
                pr_number = issue.get("number")
                is_pull_request = "pull_request" in issue
                comment_body = event.get("comment", {}).get("body", "")
                comment_author = (
                    event.get("comment", {}).get("user", {}).get("login", "")
                )
                pr_author = issue.get("user", {}).get("login", "")

        return cls(
            token=token,
            mode=mode,
            workspace=workspace,
            repository=repository,
            event_name=event_name,
            sha=sha,
            ref=ref,
            pr_number=pr_number,
            is_pull_request=is_pull_request,
            comment_body=comment_body,
            comment_author=comment_author,
            pr_author=pr_author,
        )
