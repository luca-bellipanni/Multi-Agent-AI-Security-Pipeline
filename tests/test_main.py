"""Tests for the main entry point.

Tests write_outputs, main() flow, and PR reporting integration.
"""

import json
import os
from unittest.mock import patch, MagicMock

from src.main import write_outputs, main
from src.models import Decision, Severity, Verdict


# --- write_outputs ---

class TestWriteOutputs:

    def test_writes_to_github_output(self, tmp_path):
        output_file = tmp_path / "output.txt"
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_file)}):
            write_outputs({"decision": "allowed", "count": "0"})

        content = output_file.read_text()
        assert "decision<<" in content
        assert "allowed" in content
        assert "count<<" in content
        assert "0" in content

    def test_no_github_output_prints(self, capsys):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITHUB_OUTPUT", None)
            write_outputs({"decision": "allowed"})

        captured = capsys.readouterr()
        assert "decision=allowed" in captured.out

    def test_multiline_safe_delimiters(self, tmp_path):
        """Delimiter format prevents injection via newlines."""
        output_file = tmp_path / "output.txt"
        with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output_file)}):
            write_outputs({"reason": "line1\nline2\nline3"})

        content = output_file.read_text()
        assert "ghadelimiter_" in content


# --- main() integration ---

class TestMain:

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_shadow_returns_zero(self, mock_ctx, mock_engine_cls, mock_write):
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = False
        ctx.pr_number = None
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Shadow mode",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        assert main() == 0

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_blocked_returns_one(self, mock_ctx, mock_engine_cls, mock_write):
        ctx = MagicMock()
        ctx.mode = "enforce"
        ctx.is_pull_request = False
        ctx.pr_number = None
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.BLOCKED,
            continue_pipeline=False,
            max_severity=Severity.CRITICAL,
            selected_tools=["semgrep"],
            reason="Blocked",
            mode="enforce",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        assert main() == 1

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_pr_reporting_called_for_pr(self, mock_ctx, mock_engine_cls, mock_write):
        """When is_pull_request, PR reporting code runs."""
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = True
        ctx.pr_number = 42
        ctx.token = "fake-token"
        ctx.repository = "o/r"
        ctx.workspace = "/tmp/test-ws"
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        with patch("src.pr_reporter.format_comment") as mock_format, \
             patch("src.pr_reporter.post_comment") as mock_post, \
             patch("src.scan_results.build_scan_results") as mock_build, \
             patch("src.scan_results.write_scan_results") as mock_write_sr:
            mock_build.return_value = MagicMock()
            mock_write_sr.return_value = "/tmp/test-ws/.appsec/scan-results.json"
            mock_format.return_value = "comment body"

            assert main() == 0

            mock_format.assert_called_once()
            mock_post.assert_called_once_with(
                "fake-token", "o/r", 42, "comment body",
            )

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_pr_reporting_skipped_for_non_pr(self, mock_ctx, mock_engine_cls, mock_write):
        """When not is_pull_request, PR reporting is skipped."""
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = False
        ctx.pr_number = None
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        # Should not try to import pr_reporter
        assert main() == 0

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_pr_reporting_error_does_not_block(self, mock_ctx, mock_engine_cls, mock_write):
        """PR reporting errors don't block the pipeline."""
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = True
        ctx.pr_number = 42
        ctx.token = "fake-token"
        ctx.repository = "o/r"
        ctx.workspace = "/tmp/test-ws"
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        with patch("src.pr_reporter.format_comment", side_effect=RuntimeError("format crash")):
            # Should still return 0 (reporting error caught)
            assert main() == 0


# --- Command dispatch ---

class TestCommandDispatch:

    @patch.dict(os.environ, {"INPUT_COMMAND": "scan"})
    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_scan_command(self, mock_ctx, mock_engine_cls, mock_write):
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = False
        ctx.pr_number = None
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        assert main() == 0

    @patch.dict(os.environ, {"INPUT_COMMAND": "remediate", "INPUT_AI_API_KEY": ""})
    @patch("src.main.write_outputs")
    @patch("src.main.GitHubContext.from_environment")
    def test_remediate_command_no_api_key(self, mock_ctx, mock_write):
        """Remediate without API key returns 1."""
        ctx = MagicMock()
        ctx.mode = "enforce"
        mock_ctx.return_value = ctx

        assert main() == 1

    @patch.dict(os.environ, {"INPUT_COMMAND": "remediate", "INPUT_AI_API_KEY": "key"})
    @patch("src.main.write_outputs")
    @patch("src.main.GitHubContext.from_environment")
    def test_remediate_command_calls_engine(self, mock_ctx, mock_write):
        from src.remediation_engine import RemediationResult

        ctx = MagicMock()
        ctx.mode = "enforce"
        mock_ctx.return_value = ctx

        mock_result = RemediationResult(
            status="nothing_to_fix",
        )
        with patch("src.remediation_engine.RemediationEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine.remediate.return_value = mock_result
            mock_engine_cls.return_value = mock_engine

            result = main()
            mock_engine.remediate.assert_called_once()
            # nothing_to_fix → returns 1
            assert result == 1

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_default_command_is_scan(self, mock_ctx, mock_engine_cls, mock_write):
        """When INPUT_COMMAND not set, defaults to scan."""
        os.environ.pop("INPUT_COMMAND", None)
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = False
        ctx.pr_number = None
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        assert main() == 0


# --- B5: analysis_report NOT printed in Results ---

class TestResultsNoBloat:

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_analysis_report_not_printed(self, mock_ctx, mock_engine_cls, mock_write, capsys):
        """analysis_report should NOT be printed in the Results section."""
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = False
        ctx.pr_number = None
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
            analysis_report="## Detailed Analysis\nLots of text here",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        main()
        out = capsys.readouterr().out
        assert "Detailed Analysis" not in out
        assert "Lots of text here" not in out
        # But Decision/Findings/Reason should still be there
        assert "Decision: allowed" in out
        assert "Findings: 0" in out


# --- B6: PR link printed ---

class TestPRLink:

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_pr_link_printed(self, mock_ctx, mock_engine_cls, mock_write, capsys):
        """PR URL is printed after posting the comment."""
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = True
        ctx.pr_number = 7
        ctx.token = "fake-token"
        ctx.repository = "myorg/myrepo"
        ctx.workspace = "/tmp/ws"
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        with patch("src.pr_reporter.format_comment") as mock_format, \
             patch("src.pr_reporter.post_comment") as mock_post, \
             patch("src.scan_results.build_scan_results") as mock_build, \
             patch("src.scan_results.write_scan_results") as mock_write_sr:
            mock_build.return_value = MagicMock()
            mock_write_sr.return_value = "/tmp/ws/.appsec/scan-results.json"
            mock_format.return_value = "body"

            main()
            out = capsys.readouterr().out
            assert "https://github.com/myorg/myrepo/pull/7" in out

    @patch("src.main.write_outputs")
    @patch("src.main.DecisionEngine")
    @patch("src.main.GitHubContext.from_environment")
    def test_no_link_without_token(self, mock_ctx, mock_engine_cls, mock_write, capsys):
        """No PR link when token is missing."""
        ctx = MagicMock()
        ctx.mode = "shadow"
        ctx.is_pull_request = True
        ctx.pr_number = 7
        ctx.token = ""
        ctx.repository = "myorg/myrepo"
        ctx.workspace = "/tmp/ws"
        mock_ctx.return_value = ctx

        decision = Decision(
            verdict=Verdict.ALLOWED,
            continue_pipeline=True,
            max_severity=Severity.NONE,
            selected_tools=["semgrep"],
            reason="Clean",
            mode="shadow",
        )
        engine = MagicMock()
        engine.decide.return_value = decision
        mock_engine_cls.return_value = engine

        with patch("src.scan_results.build_scan_results") as mock_build, \
             patch("src.scan_results.write_scan_results") as mock_write_sr:
            mock_build.return_value = MagicMock()
            mock_write_sr.return_value = "/tmp/ws/.appsec/scan-results.json"

            main()
            out = capsys.readouterr().out
            assert "https://github.com" not in out
            assert "No GitHub token" in out
