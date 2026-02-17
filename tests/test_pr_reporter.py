"""Tests for the PR comment reporter.

Tests format_comment (Markdown generation) and post_comment (GitHub API
upsert). Verifies that the reporter handles various Decision states
correctly and that API errors don't block the pipeline.
"""

from unittest.mock import patch, MagicMock

from src.models import (
    Decision, Severity, StepTrace, Verdict,
)
from src.pr_reporter import (
    COMMENT_MARKER,
    _format_tools_used,
    format_comment,
    post_comment,
)


# --- Helpers ---

def _make_decision(**overrides):
    defaults = dict(
        verdict=Verdict.MANUAL_REVIEW,
        continue_pipeline=False,
        max_severity=Severity.HIGH,
        selected_tools=["semgrep"],
        reason="Test reason",
        mode="enforce",
        findings_count=1,
        confirmed_findings=[{
            "finding_id": "Fabc123",
            "rule_id": "python.sql-injection",
            "path": "src/db.py",
            "line": 42,
            "severity": "high",
            "message": "SQL injection",
            "agent_reason": "User input in query",
            "agent_recommendation": "Use parameterized queries",
        }],
        dismissed_findings=[],
        excepted_findings=[],
        safety_warnings=[],
        trace=[
            StepTrace(
                name="Triage Agent",
                tools_used={"fetch_pr_files": 1},
                summary="Python, 3 files, auth area",
                status="success",
            ),
            StepTrace(
                name="AppSec Agent (OODA)",
                tools_used={"fetch_pr_diff": 1, "run_semgrep": 2},
                summary="5 raw -> 1 confirmed",
                status="success",
            ),
            StepTrace(
                name="Smart Gate",
                tools_used={},
                summary="MANUAL_REVIEW",
                status="success",
            ),
        ],
    )
    defaults.update(overrides)
    return Decision(**defaults)


# --- format_comment ---

class TestFormatComment:

    def test_header_includes_verdict(self):
        d = _make_decision()
        body = format_comment(d)
        assert "MANUAL_REVIEW" in body

    def test_header_includes_mode(self):
        d = _make_decision(mode="shadow")
        body = format_comment(d)
        assert "shadow" in body

    def test_header_includes_count(self):
        d = _make_decision(findings_count=3)
        body = format_comment(d)
        assert "3 finding(s)" in body

    def test_pipeline_trace_table(self):
        d = _make_decision()
        body = format_comment(d)
        assert "### Pipeline" in body
        assert "Triage Agent" in body
        assert "AppSec Agent (OODA)" in body
        assert "Smart Gate" in body
        assert "`fetch_pr_files` x1" in body
        assert "`run_semgrep` x2" in body

    def test_confirmed_findings_table(self):
        d = _make_decision()
        body = format_comment(d)
        assert "### Confirmed Findings (1)" in body
        assert "Fabc123" in body
        assert "HIGH" in body
        assert "`python.sql-injection`" in body
        assert "`src/db.py`" in body
        assert "42" in body

    def test_confirmed_details_collapsible(self):
        d = _make_decision()
        body = format_comment(d)
        assert "<details><summary>Details</summary>" in body
        assert "User input in query" in body
        assert "Use parameterized queries" in body

    def test_safety_warnings_section(self):
        d = _make_decision(safety_warnings=[{
            "type": "dismissed_high_severity",
            "rule_id": "bad.rule",
            "severity": "high",
            "message": "Agent dismissed HIGH finding",
        }])
        body = format_comment(d)
        assert "Safety Warnings (1)" in body
        assert "dismissed_high_severity" in body
        assert "`bad.rule`" in body

    def test_no_safety_warnings_no_section(self):
        d = _make_decision(safety_warnings=[])
        body = format_comment(d)
        assert "Safety Warnings" not in body

    def test_excepted_findings_collapsible(self):
        d = _make_decision(excepted_findings=[{
            "severity": "low",
            "rule_id": "noise.rule",
            "path": "test.py",
            "line": 5,
            "exception_reason": "auto-excepted from PR #40",
        }])
        body = format_comment(d)
        assert "Auto-excepted by memory (1)" in body
        assert "`noise.rule`" in body

    def test_no_excepted_no_section(self):
        d = _make_decision(excepted_findings=[])
        body = format_comment(d)
        assert "Auto-excepted" not in body

    def test_dismissed_findings_collapsible(self):
        d = _make_decision(dismissed_findings=[
            {"rule_id": "test.rule", "reason": "test file"},
            {"rule_id": "noise.rule", "reason": "false positive"},
        ])
        body = format_comment(d)
        assert "Dismissed by agent (2)" in body
        assert "`test.rule`" in body

    def test_no_dismissed_no_section(self):
        d = _make_decision(dismissed_findings=[])
        body = format_comment(d)
        assert "Dismissed by agent" not in body

    def test_footer_with_marker(self):
        d = _make_decision()
        body = format_comment(d)
        assert COMMENT_MARKER in body
        assert "Agentic AppSec Pipeline" in body

    def test_footer_includes_mode(self):
        d = _make_decision(mode="shadow")
        body = format_comment(d)
        assert "shadow mode" in body

    def test_clean_scan(self):
        """No findings, no warnings → minimal comment."""
        d = _make_decision(
            verdict=Verdict.ALLOWED,
            findings_count=0,
            confirmed_findings=[],
            safety_warnings=[],
        )
        body = format_comment(d)
        assert "ALLOWED" in body
        assert "0 finding(s)" in body
        assert "Confirmed Findings" not in body

    def test_no_trace(self):
        d = _make_decision(trace=[])
        body = format_comment(d)
        assert "### Pipeline" not in body

    def test_blocked_verdict(self):
        d = _make_decision(verdict=Verdict.BLOCKED)
        body = format_comment(d)
        assert "BLOCKED" in body


# --- _format_tools_used ---

class TestFormatToolsUsed:

    def test_empty(self):
        assert _format_tools_used({}) == "--"

    def test_single_tool(self):
        result = _format_tools_used({"run_semgrep": 2})
        assert result == "`run_semgrep` x2"

    def test_multiple_tools(self):
        result = _format_tools_used({"fetch_pr_diff": 1, "run_semgrep": 3})
        assert "`fetch_pr_diff` x1" in result
        assert "`run_semgrep` x3" in result


# --- post_comment ---

class TestPostComment:

    @patch("src.pr_reporter.requests.get")
    @patch("src.pr_reporter.requests.post")
    def test_creates_new_comment(self, mock_post, mock_get):
        """When no existing comment found, creates new one."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[]),
        )
        mock_get.return_value.raise_for_status = MagicMock()

        mock_post.return_value = MagicMock(status_code=201)
        mock_post.return_value.raise_for_status = MagicMock()

        post_comment("tok", "o/r", 42, "test body")

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs["json"]["body"] == "test body"
        assert "/issues/42/comments" in call_kwargs.args[0]

    @patch("src.pr_reporter.requests.get")
    @patch("src.pr_reporter.requests.patch")
    def test_updates_existing_comment(self, mock_patch, mock_get):
        """When existing comment with marker found, updates it."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {"id": 99, "body": f"old content {COMMENT_MARKER}"},
            ]),
        )
        mock_get.return_value.raise_for_status = MagicMock()

        mock_patch.return_value = MagicMock(status_code=200)
        mock_patch.return_value.raise_for_status = MagicMock()

        post_comment("tok", "o/r", 42, "new body")

        mock_patch.assert_called_once()
        call_kwargs = mock_patch.call_args
        assert call_kwargs.kwargs["json"]["body"] == "new body"
        assert "/issues/comments/99" in call_kwargs.args[0]

    @patch("src.pr_reporter.requests.get")
    @patch("src.pr_reporter.requests.post")
    def test_api_error_does_not_raise(self, mock_post, mock_get):
        """API errors are logged as warnings, never raise."""
        import requests as req
        mock_get.side_effect = req.RequestException("network error")

        # Should not raise
        post_comment("tok", "o/r", 42, "body")

    @patch("src.pr_reporter.requests.get")
    @patch("src.pr_reporter.requests.post")
    def test_auth_header_sent(self, mock_post, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[]),
        )
        mock_get.return_value.raise_for_status = MagicMock()

        mock_post.return_value = MagicMock(status_code=201)
        mock_post.return_value.raise_for_status = MagicMock()

        post_comment("my-secret-token", "o/r", 42, "body")

        headers = mock_post.call_args.kwargs["headers"]
        assert headers["Authorization"] == "token my-secret-token"

    @patch("src.pr_reporter.requests.get")
    @patch("src.pr_reporter.requests.post")
    def test_ignores_comments_without_marker(self, mock_post, mock_get):
        """Comments without our marker are ignored → creates new."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {"id": 1, "body": "unrelated comment"},
                {"id": 2, "body": "another comment"},
            ]),
        )
        mock_get.return_value.raise_for_status = MagicMock()

        mock_post.return_value = MagicMock(status_code=201)
        mock_post.return_value.raise_for_status = MagicMock()

        post_comment("tok", "o/r", 42, "body")

        mock_post.assert_called_once()  # created new, not updated
