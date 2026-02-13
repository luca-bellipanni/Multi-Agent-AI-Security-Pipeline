"""Tests for the GitHub API tools and Semgrep tool."""

import json
import subprocess
from unittest.mock import patch, MagicMock

from src.models import Finding, Severity
from src.tools import (
    FetchPRFilesTool,
    FetchPRDiffTool,
    SemgrepTool,
    _get_language,
    _format_pr_files,
    _fetch_pr_files_from_api,
    _validate_rulesets,
    _format_semgrep_findings,
    parse_semgrep_findings,
    DEPENDENCY_FILES,
    ALLOWED_RULESET_PREFIXES,
    MAX_RULESETS,
    MAX_PATCH_CHARS_PER_FILE,
    MAX_TOTAL_PATCH_CHARS,
)


# --- Helpers ---

def _make_tool(token="fake-token", repository="owner/repo"):
    return FetchPRFilesTool(github_token=token, repository=repository)


def _make_gh_file(filename, status="modified", additions=10, deletions=2):
    """Create a mock GitHub API file object."""
    return {
        "sha": "abc123",
        "filename": filename,
        "status": status,
        "additions": additions,
        "deletions": deletions,
        "changes": additions + deletions,
    }


def _make_semgrep_json(findings=None):
    """Create a mock Semgrep JSON output string."""
    results = []
    for f in (findings or []):
        results.append({
            "check_id": f.get("rule_id", "test.rule"),
            "path": f.get("path", "test.py"),
            "start": {"line": f.get("line", 1), "col": 1, "offset": 0},
            "end": {"line": f.get("line", 1), "col": 10, "offset": 10},
            "extra": {
                "severity": f.get("severity", "WARNING"),
                "message": f.get("message", "Test message"),
                "metadata": {},
            },
        })
    return json.dumps({"results": results, "errors": []})


# --- Unit tests: _get_language ---

class TestGetLanguage:

    def test_python_file(self):
        assert _get_language("src/main.py") == "python"

    def test_javascript_file(self):
        assert _get_language("app/index.js") == "javascript"

    def test_typescript_tsx(self):
        assert _get_language("components/App.tsx") == "typescript"

    def test_unknown_extension(self):
        assert _get_language("data/file.xyz") == "xyz"

    def test_no_extension(self):
        assert _get_language("Makefile") == "unknown"

    def test_yaml_file(self):
        assert _get_language(".github/workflows/ci.yml") == "yaml"

    def test_case_insensitive(self):
        assert _get_language("module.PY") == "python"


# --- Unit tests: _format_pr_files ---

class TestFormatPrFiles:

    def test_empty_files(self):
        result = _format_pr_files(42, "Test PR", [])
        assert "No files changed" in result
        assert "PR #42" in result

    def test_single_python_file(self):
        files = [_make_gh_file("src/main.py", "modified", 15, 3)]
        result = _format_pr_files(42, "Fix bug", files)
        assert "PR #42: Fix bug" in result
        assert "Files changed (1)" in result
        assert "src/main.py" in result
        assert "+15" in result
        assert "-3" in result
        assert "[python]" in result

    def test_multiple_files_summary(self):
        files = [
            _make_gh_file("src/main.py", "modified", 15, 3),
            _make_gh_file("tests/test_main.py", "added", 45, 0),
            _make_gh_file("requirements.txt", "modified", 1, 0),
        ]
        result = _format_pr_files(42, "Fix login", files)
        assert "Files changed (3)" in result
        assert "61 additions, 3 deletions" in result
        assert "Dependency files changed: requirements.txt" in result

    def test_added_file_shows_A(self):
        files = [_make_gh_file("new_file.py", "added", 50, 0)]
        result = _format_pr_files(1, "Add feature", files)
        assert "A new_file.py" in result

    def test_deleted_file_shows_D(self):
        files = [_make_gh_file("old_file.py", "removed", 0, 30)]
        result = _format_pr_files(1, "Cleanup", files)
        assert "D old_file.py" in result


# --- Unit tests: DEPENDENCY_FILES ---

class TestDependencyFiles:

    def test_requirements_txt(self):
        assert "requirements.txt" in DEPENDENCY_FILES

    def test_package_json(self):
        assert "package.json" in DEPENDENCY_FILES

    def test_dockerfile(self):
        assert "Dockerfile" in DEPENDENCY_FILES

    def test_random_file_not_dependency(self):
        assert "main.py" not in DEPENDENCY_FILES


# --- Integration tests: FetchPRFilesTool ---

class TestFetchPRFilesTool:

    def test_tool_attributes(self):
        tool = _make_tool()
        assert tool.name == "fetch_pr_files"
        assert tool.output_type == "string"
        assert "pr_number" in tool.inputs

    def test_no_token_returns_error(self):
        tool = _make_tool(token="")
        result = tool.forward(pr_number=42)
        assert "Error" in result
        assert "token" in result.lower()

    def test_no_repository_returns_error(self):
        tool = _make_tool(repository="")
        result = tool.forward(pr_number=42)
        assert "Error" in result
        assert "repository" in result.lower()

    @patch("src.tools.requests.get")
    def test_successful_fetch(self, mock_get):
        pr_response = MagicMock()
        pr_response.status_code = 200
        pr_response.json.return_value = {"title": "Fix SQL injection"}

        files_response = MagicMock()
        files_response.status_code = 200
        files_response.json.return_value = [
            _make_gh_file("src/login.py", "modified", 15, 3),
            _make_gh_file("requirements.txt", "modified", 1, 0),
        ]

        mock_get.side_effect = [pr_response, files_response]

        tool = _make_tool()
        result = tool.forward(pr_number=42)

        assert "PR #42: Fix SQL injection" in result
        assert "src/login.py" in result
        assert "requirements.txt" in result
        assert "Dependency files changed" in result

    @patch("src.tools.requests.get")
    def test_pr_not_found_404(self, mock_get):
        pr_response = MagicMock()
        pr_response.status_code = 200
        pr_response.json.return_value = {"title": "Test"}

        files_response = MagicMock()
        files_response.status_code = 404

        mock_get.side_effect = [pr_response, files_response]

        tool = _make_tool()
        result = tool.forward(pr_number=999)
        assert "Error" in result
        assert "not found" in result

    @patch("src.tools.requests.get")
    def test_rate_limit_403(self, mock_get):
        pr_response = MagicMock()
        pr_response.status_code = 200
        pr_response.json.return_value = {"title": "Test"}

        files_response = MagicMock()
        files_response.status_code = 403

        mock_get.side_effect = [pr_response, files_response]

        tool = _make_tool()
        result = tool.forward(pr_number=42)
        assert "Error" in result

    @patch("src.tools.requests.get")
    def test_network_error(self, mock_get):
        import requests as req

        pr_response = MagicMock()
        pr_response.status_code = 200
        pr_response.json.return_value = {"title": "Test"}

        mock_get.side_effect = [pr_response, req.RequestException("Timeout")]

        tool = _make_tool()
        result = tool.forward(pr_number=42)
        assert "Error" in result

    @patch("src.tools.requests.get")
    def test_pagination_multiple_pages(self, mock_get):
        pr_response = MagicMock()
        pr_response.status_code = 200
        pr_response.json.return_value = {"title": "Big PR"}

        page1 = MagicMock()
        page1.status_code = 200
        page1.json.return_value = [_make_gh_file(f"file{i}.py") for i in range(100)]

        page2 = MagicMock()
        page2.status_code = 200
        page2.json.return_value = [_make_gh_file(f"extra{i}.py") for i in range(5)]

        mock_get.side_effect = [pr_response, page1, page2]

        tool = _make_tool()
        result = tool.forward(pr_number=42)
        assert "Files changed (105)" in result

    @patch("src.tools.requests.get")
    def test_auth_header_sent(self, mock_get):
        pr_response = MagicMock()
        pr_response.status_code = 200
        pr_response.json.return_value = {"title": "Test"}

        files_response = MagicMock()
        files_response.status_code = 200
        files_response.json.return_value = []

        mock_get.side_effect = [pr_response, files_response]

        tool = _make_tool(token="my-secret-token")
        tool.forward(pr_number=1)

        for call in mock_get.call_args_list:
            headers = call.kwargs.get("headers", {})
            assert headers.get("Authorization") == "token my-secret-token"


# --- Semgrep: ruleset validation ---

class TestValidateRulesets:

    def test_valid_p_prefix(self):
        rulesets, error = _validate_rulesets("p/python")
        assert rulesets == ["p/python"]
        assert error is None

    def test_valid_r_prefix(self):
        rulesets, error = _validate_rulesets("r/python.lang.security")
        assert rulesets == ["r/python.lang.security"]
        assert error is None

    def test_valid_s_prefix(self):
        rulesets, error = _validate_rulesets("s/some-ruleset")
        assert rulesets == ["s/some-ruleset"]
        assert error is None

    def test_multiple_valid(self):
        rulesets, error = _validate_rulesets("p/python,p/owasp-top-ten")
        assert rulesets == ["p/python", "p/owasp-top-ten"]
        assert error is None

    def test_empty_config_error(self):
        rulesets, error = _validate_rulesets("")
        assert rulesets == []
        assert "No rulesets" in error

    def test_too_many_rulesets(self):
        config = ",".join(f"p/rule{i}" for i in range(MAX_RULESETS + 1))
        rulesets, error = _validate_rulesets(config)
        assert rulesets == []
        assert "Too many" in error

    def test_path_traversal_blocked(self):
        rulesets, error = _validate_rulesets("/etc/passwd")
        assert rulesets == []
        assert "not allowed" in error

    def test_relative_path_blocked(self):
        rulesets, error = _validate_rulesets("../../etc/shadow")
        assert rulesets == []
        assert "not allowed" in error

    def test_flag_injection_blocked(self):
        rulesets, error = _validate_rulesets("--include /etc")
        assert rulesets == []
        assert "not allowed" in error

    def test_whitespace_trimmed(self):
        rulesets, error = _validate_rulesets("  p/python , p/java  ")
        assert rulesets == ["p/python", "p/java"]
        assert error is None


# --- Semgrep: parse findings ---

class TestParseSemgrepFindings:

    def test_empty_results(self):
        raw = json.dumps({"results": [], "errors": []})
        assert parse_semgrep_findings(raw) == []

    def test_single_finding(self):
        raw = _make_semgrep_json([{
            "rule_id": "python.exec",
            "path": "app.py",
            "line": 42,
            "severity": "ERROR",
            "message": "Use of exec()",
        }])
        findings = parse_semgrep_findings(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "semgrep"
        assert f.rule_id == "python.exec"
        assert f.path == "app.py"
        assert f.line == 42
        assert f.severity == Severity.HIGH
        assert f.message == "Use of exec()"

    def test_severity_error_maps_to_high(self):
        raw = _make_semgrep_json([{"severity": "ERROR"}])
        assert parse_semgrep_findings(raw)[0].severity == Severity.HIGH

    def test_severity_warning_maps_to_medium(self):
        raw = _make_semgrep_json([{"severity": "WARNING"}])
        assert parse_semgrep_findings(raw)[0].severity == Severity.MEDIUM

    def test_severity_info_maps_to_low(self):
        raw = _make_semgrep_json([{"severity": "INFO"}])
        assert parse_semgrep_findings(raw)[0].severity == Severity.LOW

    def test_unknown_severity_defaults_to_low(self):
        raw = _make_semgrep_json([{"severity": "UNKNOWN"}])
        assert parse_semgrep_findings(raw)[0].severity == Severity.LOW

    def test_invalid_json_returns_empty(self):
        assert parse_semgrep_findings("not json") == []

    def test_none_returns_empty(self):
        assert parse_semgrep_findings(None) == []

    def test_multiple_findings(self):
        raw = _make_semgrep_json([
            {"severity": "ERROR", "rule_id": "rule1"},
            {"severity": "WARNING", "rule_id": "rule2"},
            {"severity": "INFO", "rule_id": "rule3"},
        ])
        findings = parse_semgrep_findings(raw)
        assert len(findings) == 3


# --- Semgrep: format findings ---

class TestFormatSemgrepFindings:

    def test_no_findings(self):
        raw = json.dumps({"results": [], "errors": []})
        result = _format_semgrep_findings(raw)
        assert "No findings" in result

    def test_with_findings(self):
        raw = _make_semgrep_json([{
            "rule_id": "python.exec",
            "path": "app.py",
            "line": 10,
            "severity": "ERROR",
            "message": "exec detected",
        }])
        result = _format_semgrep_findings(raw)
        assert "1 finding" in result
        assert "[ERROR]" in result
        assert "python.exec" in result
        assert "app.py:10" in result

    def test_invalid_json(self):
        result = _format_semgrep_findings("broken")
        assert "Error" in result


# --- Semgrep: SemgrepTool ---

class TestSemgrepTool:

    def test_tool_attributes(self):
        tool = SemgrepTool(workspace_path="/tmp/test")
        assert tool.name == "run_semgrep"
        assert tool.output_type == "string"
        assert "config" in tool.inputs

    def test_workspace_not_in_inputs(self):
        """workspace_path must NOT be visible to the LLM (LLM06)."""
        tool = SemgrepTool(workspace_path="/tmp/test")
        assert "workspace" not in str(tool.inputs).lower()

    def test_workspace_stored(self):
        tool = SemgrepTool(workspace_path="/my/workspace")
        assert tool.workspace_path == "/my/workspace"

    def test_invalid_ruleset_returns_error(self):
        tool = SemgrepTool(workspace_path="/tmp")
        result = tool.forward("/etc/passwd")
        assert "Error" in result
        assert "not allowed" in result

    def test_empty_config_returns_error(self):
        tool = SemgrepTool(workspace_path="/tmp")
        result = tool.forward("")
        assert "Error" in result

    @patch("src.tools.subprocess.run", side_effect=FileNotFoundError())
    def test_semgrep_not_installed(self, mock_run):
        tool = SemgrepTool(workspace_path="/tmp")
        result = tool.forward("p/python")
        assert "Error" in result
        assert "not installed" in result

    @patch("src.tools.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=300))
    def test_semgrep_timeout(self, mock_run):
        tool = SemgrepTool(workspace_path="/tmp")
        result = tool.forward("p/python")
        assert "Error" in result
        assert "timed out" in result

    @patch("src.tools.subprocess.run")
    def test_semgrep_no_findings(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        result = tool.forward("p/python")
        assert "No findings" in result

    @patch("src.tools.subprocess.run")
    def test_semgrep_with_findings(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{
                "rule_id": "python.exec",
                "severity": "ERROR",
                "path": "app.py",
                "line": 42,
                "message": "exec usage",
            }]),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        result = tool.forward("p/python")
        assert "1 finding" in result
        assert "python.exec" in result

    @patch("src.tools.subprocess.run")
    def test_semgrep_empty_stdout(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="some error",
            returncode=2,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        result = tool.forward("p/python")
        assert "Error" in result

    @patch("src.tools.subprocess.run")
    def test_command_uses_array_not_shell(self, mock_run):
        """Security: verify subprocess is called with array, not shell=True."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/ws")
        tool.forward("p/python,p/owasp-top-ten")

        call_args = mock_run.call_args
        cmd = call_args[0][0]  # First positional arg
        assert isinstance(cmd, list)
        assert cmd[0] == "semgrep"
        assert "--json" in cmd
        assert "--config" in cmd
        assert "p/python" in cmd
        assert "p/owasp-top-ten" in cmd
        assert "/tmp/ws" in cmd
        # shell should not be True
        assert call_args.kwargs.get("shell") is not True

    @patch("src.tools.subprocess.run")
    def test_run_and_parse_returns_findings(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{
                "rule_id": "python.exec",
                "severity": "ERROR",
                "path": "app.py",
                "line": 42,
                "message": "exec usage",
            }]),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        output, findings = tool.run_and_parse("p/python")
        assert "1 finding" in output
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].rule_id == "python.exec"

    @patch("src.tools.subprocess.run")
    def test_run_and_parse_error_returns_empty(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        tool = SemgrepTool(workspace_path="/tmp/test")
        output, findings = tool.run_and_parse("p/python")
        assert "Error" in output
        assert findings == []


# --- Semgrep: side channel (LLM05) ---

class TestSemgrepSideChannel:
    """Test the side channel that provides raw findings to the gate.

    Security (LLM05 — untrusted output handling):
    The gate reads _last_raw_findings from the tool directly, independent
    of what the agent reports. This prevents the agent from silently
    dismissing findings.
    """

    def test_initial_state_empty(self):
        tool = SemgrepTool(workspace_path="/tmp/test")
        assert tool._last_raw_findings == []
        assert tool._last_config_used == []
        assert tool._last_error == ""

    @patch("src.tools.subprocess.run")
    def test_populated_after_forward(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{
                "rule_id": "python.exec",
                "severity": "ERROR",
                "path": "app.py",
                "line": 42,
                "message": "exec usage",
            }]),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        tool.forward("p/python")

        assert len(tool._last_raw_findings) == 1
        assert tool._last_raw_findings[0].rule_id == "python.exec"
        assert tool._last_raw_findings[0].severity == Severity.HIGH

    @patch("src.tools.subprocess.run")
    def test_config_used_populated(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        tool.forward("p/python,p/owasp-top-ten")

        assert tool._last_config_used == ["p/python", "p/owasp-top-ten"]
        assert tool._last_error == ""

    @patch("src.tools.subprocess.run")
    def test_reset_between_calls(self, mock_run):
        """Side channel is reset at the start of each forward() call."""
        # First call: one finding
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{
                "rule_id": "first.rule",
                "severity": "ERROR",
            }]),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        tool.forward("p/python")
        assert len(tool._last_raw_findings) == 1

        # Second call: no findings
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
            returncode=0,
        )
        tool.forward("p/java")
        assert len(tool._last_raw_findings) == 0
        assert tool._last_config_used == ["p/java"]

    def test_error_on_invalid_ruleset(self):
        tool = SemgrepTool(workspace_path="/tmp/test")
        tool.forward("/etc/passwd")

        assert tool._last_raw_findings == []
        assert tool._last_config_used == []
        assert "not allowed" in tool._last_error

    @patch("src.tools.subprocess.run", side_effect=FileNotFoundError())
    def test_error_on_semgrep_not_installed(self, mock_run):
        tool = SemgrepTool(workspace_path="/tmp/test")
        tool.forward("p/python")

        assert tool._last_raw_findings == []
        assert tool._last_config_used == ["p/python"]
        assert "not installed" in tool._last_error

    @patch("src.tools.subprocess.run")
    def test_error_on_empty_output(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="",
            stderr="some error",
            returncode=2,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        tool.forward("p/python")

        assert tool._last_raw_findings == []
        assert tool._last_error != ""

    @patch("src.tools.subprocess.run")
    def test_no_findings_no_error(self, mock_run):
        """Clean scan: no findings, no error."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")
        tool.forward("p/python")

        assert tool._last_raw_findings == []
        assert tool._last_error == ""
        assert tool._last_config_used == ["p/python"]


# --- Semgrep: cumulative side channel (OODA) ---

class TestSemgrepCumulativeSideChannel:
    """Test the cumulative side channel for multi-call OODA loop.

    When the agent calls run_semgrep multiple times (escalation scans),
    _all_raw_findings accumulates findings from ALL calls so the gate
    sees the complete picture.
    """

    def test_all_findings_initial_empty(self):
        tool = SemgrepTool(workspace_path="/tmp/test")
        assert tool._all_raw_findings == []
        assert tool._all_configs_used == []

    @patch("src.tools.subprocess.run")
    def test_all_findings_accumulate(self, mock_run):
        """Findings from multiple forward() calls accumulate."""
        tool = SemgrepTool(workspace_path="/tmp/test")

        # First call: one finding
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{
                "rule_id": "first.rule",
                "severity": "ERROR",
            }]),
            stderr="",
            returncode=0,
        )
        tool.forward("p/python")
        assert len(tool._all_raw_findings) == 1

        # Second call: another finding
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{
                "rule_id": "second.rule",
                "severity": "WARNING",
            }]),
            stderr="",
            returncode=0,
        )
        tool.forward("p/owasp-top-ten")
        assert len(tool._all_raw_findings) == 2
        assert tool._all_raw_findings[0].rule_id == "first.rule"
        assert tool._all_raw_findings[1].rule_id == "second.rule"

    @patch("src.tools.subprocess.run")
    def test_all_configs_accumulate(self, mock_run):
        """Configs from multiple forward() calls accumulate."""
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
            returncode=0,
        )
        tool = SemgrepTool(workspace_path="/tmp/test")

        tool.forward("p/python")
        tool.forward("p/owasp-top-ten")

        assert tool._all_configs_used == ["p/python", "p/owasp-top-ten"]

    @patch("src.tools.subprocess.run")
    def test_last_vs_all_independent(self, mock_run):
        """_last resets per call, _all accumulates."""
        tool = SemgrepTool(workspace_path="/tmp/test")

        # First call with finding
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{"rule_id": "a.rule", "severity": "ERROR"}]),
            stderr="",
            returncode=0,
        )
        tool.forward("p/python")

        # Second call clean
        mock_run.return_value = MagicMock(
            stdout=json.dumps({"results": [], "errors": []}),
            stderr="",
            returncode=0,
        )
        tool.forward("p/java")

        # _last shows only last call
        assert tool._last_raw_findings == []
        assert tool._last_config_used == ["p/java"]
        # _all shows everything
        assert len(tool._all_raw_findings) == 1
        assert tool._all_configs_used == ["p/python", "p/java"]

    @patch("src.tools.subprocess.run")
    def test_all_findings_on_error(self, mock_run):
        """Error on second call doesn't corrupt accumulated findings."""
        tool = SemgrepTool(workspace_path="/tmp/test")

        # First call succeeds
        mock_run.return_value = MagicMock(
            stdout=_make_semgrep_json([{"rule_id": "ok.rule", "severity": "ERROR"}]),
            stderr="",
            returncode=0,
        )
        tool.forward("p/python")
        assert len(tool._all_raw_findings) == 1

        # Second call fails
        mock_run.return_value = MagicMock(stdout="", stderr="crash", returncode=2)
        tool.forward("p/java")

        # Accumulated findings preserved
        assert len(tool._all_raw_findings) == 1
        assert tool._all_raw_findings[0].rule_id == "ok.rule"
        # Config still accumulated (we tried p/java)
        assert tool._all_configs_used == ["p/python", "p/java"]


# --- FetchPRDiffTool ---

def _make_gh_file_with_patch(
    filename, status="modified", additions=10, deletions=2, patch="",
):
    """Create a mock GitHub API file object with patch."""
    return {
        "sha": "abc123",
        "filename": filename,
        "status": status,
        "additions": additions,
        "deletions": deletions,
        "changes": additions + deletions,
        "patch": patch,
    }


class TestFetchPRDiffTool:
    """Test the diff observation tool for the OODA loop.

    Security (LLM06 — excessive agency):
    PR number is injected via constructor, never exposed to the LLM.
    File paths only filter API response, no filesystem access.
    """

    def test_tool_attributes(self):
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        assert tool.name == "fetch_pr_diff"
        assert tool.output_type == "string"
        assert "file_paths" in tool.inputs

    def test_pr_number_not_in_inputs(self):
        """PR number must NOT be LLM-visible (LLM06)."""
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        assert "pr_number" not in tool.inputs

    def test_no_token_error(self):
        tool = FetchPRDiffTool(
            github_token="", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")
        assert "Error" in result
        assert "token" in result.lower()

    def test_no_repository_error(self):
        tool = FetchPRDiffTool(
            github_token="tok", repository="", pr_number=42,
        )
        result = tool.forward("all")
        assert "Error" in result
        assert "repository" in result.lower()

    @patch("src.tools._fetch_pr_files_from_api")
    def test_all_files_returns_patches(self, mock_api):
        mock_api.return_value = (
            [
                _make_gh_file_with_patch(
                    "src/auth.py", patch="@@ -1 +1 @@\n-old\n+new",
                ),
                _make_gh_file_with_patch(
                    "src/login.py", patch="@@ -5 +5 @@\n+import os",
                ),
            ],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")

        assert "src/auth.py" in result
        assert "src/login.py" in result
        assert "-old" in result
        assert "+new" in result
        assert "+import os" in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_specific_file_returns_patch(self, mock_api):
        mock_api.return_value = (
            [
                _make_gh_file_with_patch("src/auth.py", patch="patch_a"),
                _make_gh_file_with_patch("src/login.py", patch="patch_b"),
            ],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("src/auth.py")

        assert "src/auth.py" in result
        assert "patch_a" in result
        assert "src/login.py" not in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_file_not_found_returns_message(self, mock_api):
        mock_api.return_value = (
            [_make_gh_file_with_patch("src/auth.py", patch="p")],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("nonexistent.py")
        assert "No diffs found" in result
        assert "nonexistent.py" in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_binary_file_no_patch_skipped(self, mock_api):
        """Files without a patch field (binary files) are skipped."""
        mock_api.return_value = (
            [
                _make_gh_file_with_patch("image.png", patch=""),
                _make_gh_file_with_patch("src/app.py", patch="real patch"),
            ],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")
        assert "image.png" not in result
        assert "real patch" in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_per_file_truncation(self, mock_api):
        big_patch = "x" * (MAX_PATCH_CHARS_PER_FILE + 1000)
        mock_api.return_value = (
            [_make_gh_file_with_patch("big.py", patch=big_patch)],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")
        assert "[truncated]" in result
        assert len(result) < len(big_patch)

    @patch("src.tools._fetch_pr_files_from_api")
    def test_total_truncation(self, mock_api):
        """When total output exceeds limit, remaining files are skipped."""
        # Each file has a patch close to per-file limit
        patch = "y" * (MAX_PATCH_CHARS_PER_FILE - 100)
        files = [
            _make_gh_file_with_patch(f"file{i}.py", patch=patch)
            for i in range(20)  # 20 files * ~10K = ~200K > 50K limit
        ]
        mock_api.return_value = (files, None)

        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")
        assert "remaining files truncated" in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_api_called_once_cached(self, mock_api):
        """API is called only once, subsequent calls use cache."""
        mock_api.return_value = (
            [_make_gh_file_with_patch("a.py", patch="p")],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        tool.forward("all")
        tool.forward("a.py")

        mock_api.assert_called_once()

    @patch("src.tools._fetch_pr_files_from_api")
    def test_api_404_error(self, mock_api):
        mock_api.return_value = ([], "Error: PR #99 not found in o/r.")
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=99,
        )
        result = tool.forward("all")
        assert "Error" in result
        assert "not found" in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_api_403_error(self, mock_api):
        mock_api.return_value = (
            [],
            "Error: GitHub API rate limit or permission denied.",
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")
        assert "Error" in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_all_binary_files_message(self, mock_api):
        """When all files lack patches (all binary), return clear message."""
        mock_api.return_value = (
            [_make_gh_file_with_patch("a.bin", patch="")],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")
        assert "binary" in result.lower() or "No diffs" in result

    @patch("src.tools._fetch_pr_files_from_api")
    def test_output_includes_status(self, mock_api):
        mock_api.return_value = (
            [_make_gh_file_with_patch(
                "new.py", status="added", additions=5, deletions=0,
                patch="+new code",
            )],
            None,
        )
        tool = FetchPRDiffTool(
            github_token="tok", repository="o/r", pr_number=42,
        )
        result = tool.forward("all")
        assert "added" in result
        assert "+5" in result
