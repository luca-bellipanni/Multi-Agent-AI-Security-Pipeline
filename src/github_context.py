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

        # Extract PR number from event payload
        pr_number = None
        is_pull_request = event_name == "pull_request"
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if event_path and os.path.exists(event_path):
            with open(event_path) as f:
                event = json.load(f)
            if is_pull_request:
                pr_number = event.get("pull_request", {}).get("number")

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
        )
