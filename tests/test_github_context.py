"""Tests for GitHubContext parsing, including issue_comment events."""

import json
import os
from unittest.mock import patch

from src.github_context import GitHubContext


class TestIssueCommentEvent:
    """Test issue_comment event parsing for remediation workflow."""

    def _write_event(self, tmp_path, event_data):
        event_path = tmp_path / "event.json"
        event_path.write_text(json.dumps(event_data))
        return str(event_path)

    def test_issue_comment_pr_number(self, tmp_path):
        event = {
            "issue": {
                "number": 42,
                "pull_request": {"url": "..."},
                "user": {"login": "pr-author"},
            },
            "comment": {
                "body": "/remediate",
                "user": {"login": "commenter"},
            },
        }
        event_path = self._write_event(tmp_path, event)
        env = {
            "GITHUB_EVENT_NAME": "issue_comment",
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_WORKSPACE": str(tmp_path),
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc",
            "GITHUB_REF": "refs/heads/main",
            "INPUT_GITHUB_TOKEN": "tok",
            "INPUT_MODE": "enforce",
        }
        with patch.dict(os.environ, env, clear=True):
            ctx = GitHubContext.from_environment()

        assert ctx.pr_number == 42
        assert ctx.is_pull_request is True
        assert ctx.comment_body == "/remediate"
        assert ctx.comment_author == "commenter"
        assert ctx.pr_author == "pr-author"

    def test_issue_comment_not_pr(self, tmp_path):
        """issue_comment on a non-PR issue."""
        event = {
            "issue": {
                "number": 10,
                "user": {"login": "issue-author"},
            },
            "comment": {
                "body": "/remediate",
                "user": {"login": "commenter"},
            },
        }
        event_path = self._write_event(tmp_path, event)
        env = {
            "GITHUB_EVENT_NAME": "issue_comment",
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_WORKSPACE": str(tmp_path),
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc",
            "GITHUB_REF": "refs/heads/main",
            "INPUT_GITHUB_TOKEN": "tok",
            "INPUT_MODE": "enforce",
        }
        with patch.dict(os.environ, env, clear=True):
            ctx = GitHubContext.from_environment()

        assert ctx.pr_number == 10
        assert ctx.is_pull_request is False

    def test_pull_request_event_pr_author(self, tmp_path):
        event = {
            "pull_request": {
                "number": 42,
                "user": {"login": "author"},
            },
        }
        event_path = self._write_event(tmp_path, event)
        env = {
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_WORKSPACE": str(tmp_path),
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc",
            "GITHUB_REF": "refs/pull/42/merge",
            "INPUT_GITHUB_TOKEN": "tok",
            "INPUT_MODE": "shadow",
        }
        with patch.dict(os.environ, env, clear=True):
            ctx = GitHubContext.from_environment()

        assert ctx.pr_number == 42
        assert ctx.pr_author == "author"
        assert ctx.comment_body == ""

    def test_defaults_for_new_fields(self):
        """New fields default to empty strings."""
        ctx = GitHubContext(
            token="", mode="shadow", workspace=".", repository="",
            event_name="push", sha="", ref="", pr_number=None,
            is_pull_request=False,
        )
        assert ctx.comment_body == ""
        assert ctx.comment_author == ""
        assert ctx.pr_author == ""
