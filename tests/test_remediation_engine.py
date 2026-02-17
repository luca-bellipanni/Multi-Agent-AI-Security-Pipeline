"""Tests for the remediation workflow orchestrator.

Tests command parsing, dismiss parsing, compute_final_findings,
group_by_file, git operations with mock subprocess, and the
overall orchestrator flow.
"""

import json
import os
from unittest.mock import patch, MagicMock

from src.scan_results import ScanResults, SCAN_RESULTS_VERSION
from src.remediation_engine import (
    RemediationEngine,
    RemediationResult,
    compute_final_findings,
    fetch_pr_comments,
    parse_dismiss_commands,
    parse_remediate_command,
)


# --- parse_remediate_command ---

class TestParseRemediateCommand:

    def test_basic(self):
        assert parse_remediate_command("/remediate") is True

    def test_with_whitespace(self):
        assert parse_remediate_command("  /remediate  ") is True

    def test_case_insensitive(self):
        assert parse_remediate_command("/Remediate") is True
        assert parse_remediate_command("/REMEDIATE") is True

    def test_with_args(self):
        assert parse_remediate_command("/remediate all") is True

    def test_not_remediate(self):
        assert parse_remediate_command("/dismiss F123456 reason") is False
        assert parse_remediate_command("hello") is False
        assert parse_remediate_command("") is False


# --- parse_dismiss_commands ---

class TestParseDismissCommands:

    def test_single_dismiss(self):
        comments = [{"body": "/dismiss Fa12345 false positive in test"}]
        result = parse_dismiss_commands(comments)
        assert result == {"Fa12345": "false positive in test"}

    def test_multiple_dismisses(self):
        comments = [
            {"body": "/dismiss Fa12345 false positive"},
            {"body": "/dismiss Fb67890 test file only"},
        ]
        result = parse_dismiss_commands(comments)
        assert len(result) == 2
        assert result["Fa12345"] == "false positive"
        assert result["Fb67890"] == "test file only"

    def test_case_insensitive(self):
        comments = [{"body": "/DISMISS Fa12345 reason"}]
        result = parse_dismiss_commands(comments)
        assert "Fa12345" in result

    def test_ignores_non_dismiss(self):
        comments = [
            {"body": "Great PR!"},
            {"body": "/remediate"},
            {"body": "/dismiss Fa12345 valid reason"},
        ]
        result = parse_dismiss_commands(comments)
        assert len(result) == 1

    def test_ignores_malformed(self):
        comments = [
            {"body": "/dismiss"},  # no finding_id
            {"body": "/dismiss NOTVALID reason"},  # bad format
            {"body": "/dismiss Fa12345"},  # no reason
        ]
        result = parse_dismiss_commands(comments)
        assert len(result) == 0

    def test_empty_comments(self):
        assert parse_dismiss_commands([]) == {}

    def test_missing_body(self):
        comments = [{"no_body": True}]
        result = parse_dismiss_commands(comments)
        assert result == {}


# --- compute_final_findings ---

class TestComputeFinalFindings:

    def _make_sr(self, confirmed=None, warnings=None):
        return ScanResults(
            confirmed=confirmed or [],
            warnings=warnings or [],
        )

    def test_confirmed_always_included(self):
        sr = self._make_sr(confirmed=[
            {"finding_id": "Fa12345", "rule_id": "sqli"},
        ])
        result = compute_final_findings(sr, {})
        assert len(result) == 1
        assert result[0]["finding_id"] == "Fa12345"

    def test_warning_included_if_not_dismissed(self):
        sr = self._make_sr(warnings=[
            {"finding_id": "Fb67890", "type": "dismissed_high_severity"},
        ])
        result = compute_final_findings(sr, {})
        assert len(result) == 1

    def test_warning_excluded_if_dismissed(self):
        sr = self._make_sr(warnings=[
            {"finding_id": "Fb67890", "type": "dismissed_high_severity"},
        ])
        result = compute_final_findings(sr, {"Fb67890": "actually safe"})
        assert len(result) == 0

    def test_mixed_confirmed_and_warnings(self):
        sr = self._make_sr(
            confirmed=[{"finding_id": "Fa11111", "rule_id": "a"}],
            warnings=[
                {"finding_id": "Fb22222", "type": "sev_mismatch"},
                {"finding_id": "Fc33333", "type": "dismissed_high"},
            ],
        )
        dismissals = {"Fc33333": "safe"}
        result = compute_final_findings(sr, dismissals)
        assert len(result) == 2
        ids = [f["finding_id"] for f in result]
        assert "Fa11111" in ids
        assert "Fb22222" in ids
        assert "Fc33333" not in ids

    def test_empty_scan_results(self):
        sr = self._make_sr()
        assert compute_final_findings(sr, {}) == []

    def test_warning_without_finding_id_skipped(self):
        sr = self._make_sr(warnings=[{"type": "unknown"}])
        result = compute_final_findings(sr, {})
        assert len(result) == 0


# --- RemediationEngine._group_by_file ---

class TestGroupByFile:

    def test_groups_correctly(self):
        engine = RemediationEngine()
        findings = [
            {"path": "a.py", "finding_id": "F1"},
            {"path": "b.py", "finding_id": "F2"},
            {"path": "a.py", "finding_id": "F3"},
        ]
        result = engine._group_by_file(findings)
        assert len(result) == 2
        assert len(result["a.py"]) == 2
        assert len(result["b.py"]) == 1

    def test_empty_findings(self):
        engine = RemediationEngine()
        assert engine._group_by_file([]) == {}

    def test_skips_empty_path(self):
        engine = RemediationEngine()
        findings = [{"path": "", "finding_id": "F1"}]
        assert engine._group_by_file(findings) == {}


# --- RemediationEngine.remediate (orchestrator) ---

class TestRemediationOrchestrator:

    def _make_ctx(self, **overrides):
        from src.github_context import GitHubContext
        defaults = dict(
            token="fake-token",
            mode="enforce",
            workspace="/tmp/test-ws",
            repository="owner/repo",
            event_name="issue_comment",
            sha="abc123",
            ref="refs/heads/feature-branch",
            pr_number=42,
            is_pull_request=True,
            comment_body="/remediate",
            comment_author="dev",
            pr_author="author",
        )
        defaults.update(overrides)
        return GitHubContext(**defaults)

    def _write_scan_results(self, tmp_path, confirmed=None, warnings=None, raw=None):
        """Write a valid scan-results.json."""
        sr = {
            "version": SCAN_RESULTS_VERSION,
            "pr_number": 42,
            "repository": "owner/repo",
            "confirmed": confirmed or [],
            "warnings": warnings or [],
            "dismissed": [],
            "raw_findings": raw or [],
        }
        appsec_dir = tmp_path / ".appsec"
        appsec_dir.mkdir(exist_ok=True)
        sr_path = appsec_dir / "scan-results.json"
        sr_path.write_text(json.dumps(sr))

    def test_no_scan_results_returns_error(self):
        ctx = self._make_ctx(workspace="/tmp/nonexistent")
        engine = RemediationEngine(api_key="key")
        result = engine.remediate(ctx)
        assert result.status == "error"
        assert "Cannot load" in result.error

    def test_nothing_to_fix(self, tmp_path):
        self._write_scan_results(tmp_path)
        ctx = self._make_ctx(workspace=str(tmp_path))

        with patch("src.remediation_engine.fetch_pr_comments", return_value=[]):
            engine = RemediationEngine(api_key="key")
            result = engine.remediate(ctx)

        assert result.status == "nothing_to_fix"

    def test_all_dismissed_nothing_to_fix(self, tmp_path):
        self._write_scan_results(
            tmp_path,
            warnings=[{
                "finding_id": "Fa12345",
                "type": "dismissed_high_severity",
                "path": "a.py",
            }],
        )
        ctx = self._make_ctx(workspace=str(tmp_path))

        dismiss_comments = [{"body": "/dismiss Fa12345 safe"}]
        with patch("src.remediation_engine.fetch_pr_comments", return_value=dismiss_comments):
            engine = RemediationEngine(api_key="key")
            result = engine.remediate(ctx)

        assert result.status == "nothing_to_fix"


# --- fetch_pr_comments ---

class TestFetchPrComments:

    @patch("src.remediation_engine.requests.get")
    def test_fetches_comments(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[
                {"id": 1, "body": "comment 1"},
                {"id": 2, "body": "comment 2"},
            ]),
        )
        mock_get.return_value.raise_for_status = MagicMock()

        result = fetch_pr_comments("tok", "o/r", 42)
        assert len(result) == 2

    @patch("src.remediation_engine.requests.get")
    def test_api_error_returns_empty(self, mock_get):
        import requests as req
        mock_get.side_effect = req.RequestException("network error")

        result = fetch_pr_comments("tok", "o/r", 42)
        assert result == []


# --- RemediationResult ---

class TestRemediationResult:

    def test_success(self):
        r = RemediationResult(
            status="success",
            pr_url="https://github.com/o/r/pull/99",
            fixes_applied=3,
        )
        assert r.status == "success"
        assert r.pr_url == "https://github.com/o/r/pull/99"

    def test_nothing_to_fix(self):
        r = RemediationResult(status="nothing_to_fix")
        assert r.fixes_applied == 0
        assert r.pr_url == ""

    def test_error(self):
        r = RemediationResult(status="error", error="something failed")
        assert r.error == "something failed"
