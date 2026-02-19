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
    _compute_finding_id,
    _format_tools_used,
    _resolve_duplicate_refs,
    _short_path,
    _short_rule,
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


# --- _short_rule / _short_path ---

class TestShortHelpers:

    def test_short_rule_dotted(self):
        assert _short_rule("python.flask.sql-injection") == "sql-injection"

    def test_short_rule_simple(self):
        assert _short_rule("sql-injection") == "sql-injection"

    def test_short_path_github_workspace(self):
        assert _short_path("/github/workspace/app.py") == "app.py"

    def test_short_path_tmp_workspace(self):
        assert _short_path("/tmp/workspace/src/db.py") == "src/db.py"

    def test_short_path_no_prefix(self):
        assert _short_path("src/db.py") == "src/db.py"


# --- _compute_finding_id ---

class TestComputeFindingId:

    def test_matches_model(self):
        """Finding ID matches models.Finding.finding_id."""
        from src.models import Finding, Severity
        f = Finding(tool="semgrep", rule_id="r1", path="a.py",
                    line=10, severity=Severity.HIGH, message="m")
        assert _compute_finding_id("r1", "a.py", 10) == f.finding_id


# --- _resolve_duplicate_refs ---

class TestResolveDuplicateRefs:

    def test_resolves_rule_at_line(self):
        lookup = {("python.flask.tainted-sql-string", 16): "F63b1ad",
                  ("tainted-sql-string", 16): "F63b1ad"}
        reason = (
            "duplicate: same issue covered by rule "
            "python.flask.tainted-sql-string at line 16"
        )
        result = _resolve_duplicate_refs(reason, lookup)
        # Duplicate reasons are fully replaced with "dup Fxxxxxx"
        assert result == "dup F63b1ad"

    def test_no_match_keeps_original(self):
        reason = "duplicate: same issue covered by rule unknown.rule at line 99"
        result = _resolve_duplicate_refs(reason, {})
        assert result == reason

    def test_no_reference_passes_through(self):
        reason = "not_exploitable: safe in this context"
        result = _resolve_duplicate_refs(reason, {})
        assert result == reason

    def test_resolves_confirmed_as_pattern(self):
        """Resolve 'confirmed as rule at line Y' agent format."""
        lookup = {("tainted-sql-string", 16): "F63b1ad"}
        reason = (
            "duplicate: same SQL injection already confirmed as "
            "tainted-sql-string at line 16"
        )
        assert _resolve_duplicate_refs(reason, lookup) == "dup F63b1ad"

    def test_resolves_full_rule_confirmed_as(self):
        """Resolve full Semgrep rule_id in 'confirmed as' pattern."""
        lookup = {
            ("python.flask.tainted-sql-string", 16): "Fabc123",
            ("tainted-sql-string", 16): "Fabc123",
        }
        reason = (
            "duplicate: already confirmed as "
            "python.flask.tainted-sql-string at line 16"
        )
        assert _resolve_duplicate_refs(reason, lookup) == "dup Fabc123"

    def test_non_duplicate_rule_ref_uses_see(self):
        """Non-duplicate reasons use 'see Fxxxxxx' for rule refs."""
        lookup = {("tainted-sql-string", 16): "F63b1ad"}
        reason = (
            "not_exploitable: see rule tainted-sql-string at line 16"
        )
        result = _resolve_duplicate_refs(reason, lookup)
        assert "see F63b1ad" in result


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

    def test_findings_table_short_rule(self):
        """Findings table uses short rule IDs and unified format."""
        d = _make_decision()
        body = format_comment(d)
        assert "### Findings" in body
        assert "Fabc123" in body
        assert "HIGH" in body
        # Short rule (not full path)
        assert "`sql-injection`" in body
        # File:Line combined column
        assert "src/db.py:42" in body
        assert "Verdict" in body
        assert "confirmed" in body

    def test_findings_table_strips_workspace(self):
        """Workspace prefix stripped from paths."""
        d = _make_decision(confirmed_findings=[{
            "finding_id": "Fxyz",
            "rule_id": "r1",
            "path": "/github/workspace/app.py",
            "line": 10,
            "severity": "high",
            "message": "test",
            "agent_reason": "",
            "agent_recommendation": "",
        }])
        body = format_comment(d)
        assert "app.py:10" in body
        assert "/github/workspace" not in body

    def test_details_has_finding_id(self):
        """Details section includes finding IDs for cross-reference."""
        d = _make_decision()
        body = format_comment(d)
        assert "<details><summary>Details</summary>" in body
        assert "**Fabc123**" in body
        assert "User input in query" in body
        assert "Use parameterized queries" in body

    def test_details_short_rule_and_path(self):
        """Details uses short rule and path."""
        d = _make_decision(confirmed_findings=[{
            "finding_id": "Fxyz",
            "rule_id": "python.flask.tainted-sql-string",
            "path": "/github/workspace/sample_app.py",
            "line": 16,
            "severity": "high",
            "message": "test",
            "agent_reason": "SQL injection",
            "agent_recommendation": "Fix it",
        }])
        body = format_comment(d)
        assert "`tainted-sql-string`" in body
        assert "`sample_app.py:16`" in body

    def test_safety_net_note_shown(self):
        """Safety-net note shown when findings have source=safety-net."""
        d = _make_decision(confirmed_findings=[{
            "finding_id": "Fxyz",
            "rule_id": "missed.rule",
            "path": "app.py",
            "line": 10,
            "severity": "high",
            "message": "missed",
            "agent_reason": "",
            "agent_recommendation": "",
            "source": "safety-net",
        }])
        body = format_comment(d)
        assert "Safety net" in body
        assert "safety-net" in body
        assert "1 finding(s)" in body

    def test_no_safety_net_no_note(self):
        """No safety-net note when all findings are agent-confirmed."""
        d = _make_decision(safety_warnings=[])
        body = format_comment(d)
        assert "Safety net" not in body

    def test_safety_net_details_uses_semgrep_message(self):
        """Safety-net findings use Semgrep message as analysis."""
        d = _make_decision(confirmed_findings=[{
            "finding_id": "Fxyz",
            "rule_id": "missed.rule",
            "path": "app.py",
            "line": 10,
            "severity": "high",
            "message": "SQL injection detected in query",
            "agent_reason": "",
            "agent_recommendation": "",
            "source": "safety-net",
        }])
        body = format_comment(d)
        assert "SQL injection detected in query" in body

    def test_safety_net_empty_message_fallback(self):
        """Safety-net findings with no Semgrep message use generic fallback."""
        d = _make_decision(confirmed_findings=[{
            "finding_id": "Fxyz",
            "rule_id": "missed.rule",
            "path": "app.py",
            "line": 10,
            "severity": "high",
            "message": "",
            "agent_reason": "",
            "agent_recommendation": "",
            "source": "safety-net",
        }])
        body = format_comment(d)
        assert "Flagged by safety net" in body

    def test_excepted_findings_collapsible(self):
        d = _make_decision(excepted_findings=[{
            "severity": "low",
            "rule_id": "python.noise.rule",
            "path": "/github/workspace/test.py",
            "line": 5,
            "exception_reason": "auto-excepted from PR #40",
        }])
        body = format_comment(d)
        assert "Auto-excepted by memory (1)" in body
        # Short rule
        assert "`rule`" in body
        # Stripped path
        assert "`test.py" in body

    def test_no_excepted_no_section(self):
        d = _make_decision(excepted_findings=[])
        body = format_comment(d)
        assert "Auto-excepted" not in body

    def test_dismissed_in_unified_table(self):
        """Dismissed findings appear in the unified table with IDs."""
        d = _make_decision(dismissed_findings=[
            {"rule_id": "python.test.rule", "path": "a.py",
             "line": 10, "reason": "test file", "severity": "medium"},
            {"rule_id": "python.noise.rule", "path": "b.py",
             "line": 20, "reason": "false positive", "severity": "low"},
        ])
        body = format_comment(d)
        # Dismissed in unified table (not separate section)
        assert "dismissed" in body
        # Short rule names
        assert "`rule`" in body
        # Finding IDs computed
        fid1 = _compute_finding_id("python.test.rule", "a.py", 10)
        fid2 = _compute_finding_id("python.noise.rule", "b.py", 20)
        assert fid1 in body
        assert fid2 in body

    def test_dismissed_resolves_duplicate_refs(self):
        """Duplicate references in dismissed reasons resolve to finding IDs."""
        d = _make_decision(
            confirmed_findings=[{
                "finding_id": "F63b1ad",
                "rule_id": "python.flask.tainted-sql-string",
                "path": "app.py",
                "line": 16,
                "severity": "high",
                "message": "SQL injection",
                "agent_reason": "Real issue",
                "agent_recommendation": "Fix",
            }],
            dismissed_findings=[{
                "rule_id": "python.other.rule",
                "path": "app.py",
                "line": 12,
                "severity": "medium",
                "reason": (
                    "duplicate: same issue covered by rule "
                    "python.flask.tainted-sql-string at line 16"
                ),
            }],
        )
        body = format_comment(d)
        assert "dup F63b1ad" in body

    def test_dismissed_no_path_fallback(self):
        """Dismissed without path/line shows in table with ? fallbacks."""
        d = _make_decision(dismissed_findings=[
            {"rule_id": "test.rule", "reason": "test file"},
        ])
        body = format_comment(d)
        assert "dismissed" in body
        assert "`rule`" in body
        assert "test file" in body

    def test_unified_table_has_verdict_and_reason(self):
        """Unified table includes Verdict and Reason columns."""
        d = _make_decision(
            confirmed_findings=[{
                "finding_id": "Fabc123",
                "rule_id": "sqli",
                "path": "app.py",
                "line": 10,
                "severity": "high",
                "message": "SQL injection",
                "agent_reason": "Attacker controls input",
                "agent_recommendation": "Use parameterized queries",
                "source": "confirmed",
            }],
            dismissed_findings=[{
                "rule_id": "noise.rule",
                "path": "app.py",
                "line": 20,
                "severity": "low",
                "reason": "test_file: test helper uses mock",
            }],
        )
        body = format_comment(d)
        # Unified table headers
        assert "Verdict" in body
        assert "Reason" in body
        # Confirmed in table
        assert "confirmed" in body
        assert "Attacker controls input" in body
        # Dismissed in table (not separate section)
        assert "dismissed" in body
        assert "test_file: test helper uses mock" in body
        # No separate "Dismissed by agent" section
        assert "Dismissed by agent" not in body
        # Total count includes both
        assert "### Findings (2)" in body

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
        assert "### Findings" not in body

    def test_no_trace(self):
        d = _make_decision(trace=[])
        body = format_comment(d)
        assert "### Pipeline" not in body

    def test_blocked_verdict(self):
        d = _make_decision(verdict=Verdict.BLOCKED)
        body = format_comment(d)
        assert "BLOCKED" in body

    def test_next_steps_shown_with_findings(self):
        """Next steps section shown when there are findings."""
        d = _make_decision()
        body = format_comment(d)
        assert "### Next steps" in body
        assert "/dismiss F<id>" in body
        assert "/remediate" in body

    def test_next_steps_hidden_clean_scan(self):
        """No next steps section when scan is clean."""
        d = _make_decision(
            verdict=Verdict.ALLOWED,
            findings_count=0,
            confirmed_findings=[],
            safety_warnings=[],
        )
        body = format_comment(d)
        assert "### Next steps" not in body


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
