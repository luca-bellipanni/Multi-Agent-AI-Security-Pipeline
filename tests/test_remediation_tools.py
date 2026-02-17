"""Tests for remediation tools: ReadCodeTool and ApplyFixTool.

Tests scope lock, path traversal prevention, AST validation,
fix audit log side channel, and error handling.
"""

import os

from src.remediation_tools import (
    ApplyFixTool,
    ReadCodeTool,
    _validate_syntax,
)


# --- ReadCodeTool ---

class TestReadCodeTool:

    def test_tool_attributes(self, tmp_path):
        tool = ReadCodeTool(workspace_path=str(tmp_path))
        assert tool.name == "read_file"
        assert tool.output_type == "string"
        assert "path" in tool.inputs

    def test_workspace_not_in_inputs(self, tmp_path):
        """workspace_path must NOT be visible to the LLM (LLM06)."""
        tool = ReadCodeTool(workspace_path=str(tmp_path))
        assert "workspace" not in str(tool.inputs).lower()

    def test_reads_file(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("print('hello')")

        tool = ReadCodeTool(workspace_path=str(tmp_path))
        result = tool.forward("src/app.py")
        assert result == "print('hello')"

    def test_file_not_found(self, tmp_path):
        tool = ReadCodeTool(workspace_path=str(tmp_path))
        result = tool.forward("nonexistent.py")
        assert "Error" in result
        assert "not found" in result

    def test_path_traversal_blocked(self, tmp_path):
        """Cannot escape workspace via ../."""
        tool = ReadCodeTool(workspace_path=str(tmp_path))
        result = tool.forward("../../etc/passwd")
        assert "Error" in result
        assert "path traversal" in result

    def test_path_traversal_via_symlink(self, tmp_path):
        """Cannot escape workspace via symlink."""
        link = tmp_path / "escape"
        link.symlink_to("/etc")
        tool = ReadCodeTool(workspace_path=str(tmp_path))
        result = tool.forward("escape/passwd")
        assert "Error" in result
        assert "path traversal" in result

    def test_reads_any_file_no_scope_lock(self, tmp_path):
        """ReadCodeTool has no scope lock — reads any file in workspace."""
        (tmp_path / "config.py").write_text("DB_URL = 'postgres://...'")
        (tmp_path / "models.py").write_text("class User: pass")

        tool = ReadCodeTool(workspace_path=str(tmp_path))
        assert "DB_URL" in tool.forward("config.py")
        assert "class User" in tool.forward("models.py")

    def test_call_count(self, tmp_path):
        (tmp_path / "a.py").write_text("a")
        tool = ReadCodeTool(workspace_path=str(tmp_path))
        assert tool._call_count == 0
        tool.forward("a.py")
        assert tool._call_count == 1
        tool.forward("a.py")
        assert tool._call_count == 2

    def test_call_count_on_error(self, tmp_path):
        tool = ReadCodeTool(workspace_path=str(tmp_path))
        tool.forward("missing.py")
        assert tool._call_count == 1


# --- ApplyFixTool ---

class TestApplyFixTool:

    def test_tool_attributes(self, tmp_path):
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["a.py"],
        )
        assert tool.name == "apply_fix"
        assert tool.output_type == "string"
        assert "path" in tool.inputs
        assert "new_content" in tool.inputs
        assert "finding_id" in tool.inputs

    def test_workspace_not_in_inputs(self, tmp_path):
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=[],
        )
        assert "workspace" not in str(tool.inputs).lower()
        assert "allowed" not in str(tool.inputs).lower()

    def test_applies_fix_successfully(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )
        result = tool.forward("app.py", "x = 2\n", "Fa12345")
        assert "successfully" in result.lower()
        assert (tmp_path / "app.py").read_text() == "x = 2\n"

    def test_scope_lock_blocks_unlisted_file(self, tmp_path):
        (tmp_path / "secret.py").write_text("original = True\n")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )
        result = tool.forward("secret.py", "hacked = True\n", "Fhack00")
        assert "Error" in result
        assert "not in the PR diff" in result
        # File unchanged
        assert (tmp_path / "secret.py").read_text() == "original = True\n"

    def test_path_traversal_blocked(self, tmp_path):
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["../../etc/passwd"],
        )
        result = tool.forward("../../etc/passwd", "hacked", "Fhack01")
        assert "Error" in result
        assert "path traversal" in result

    def test_ast_validation_python_valid(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )
        result = tool.forward("app.py", "x = 2\ny = 3\n", "Fa12345")
        assert "successfully" in result.lower()

    def test_ast_validation_python_invalid(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )
        result = tool.forward("app.py", "def broken(\n", "Fbad000")
        assert "Error" in result
        assert "syntax" in result.lower()
        # File unchanged (fix not applied)
        assert (tmp_path / "app.py").read_text() == "x = 1"

    def test_ast_validation_non_python_always_passes(self, tmp_path):
        (tmp_path / "app.js").write_text("old")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.js"],
        )
        result = tool.forward("app.js", "this is not valid python!!!", "Fjs0001")
        assert "successfully" in result.lower()

    def test_call_count(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["a.py"],
        )
        assert tool._call_count == 0
        tool.forward("a.py", "x = 2", "F000001")
        assert tool._call_count == 1
        tool.forward("a.py", "x = 3", "F000002")
        assert tool._call_count == 2


# --- Fix audit log (side channel v2) ---

class TestFixAuditLog:
    """Test the _fix_log side channel on ApplyFixTool.

    Security (LLM05): the fix log is written by the tool, not the agent.
    It records every attempt, including failed ones, for audit purposes.
    """

    def test_initial_empty(self, tmp_path):
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=[],
        )
        assert tool._fix_log == []

    def test_successful_fix_logged(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )
        tool.forward("app.py", "x = 2\n", "Fa12345")

        assert len(tool._fix_log) == 1
        entry = tool._fix_log[0]
        assert entry["finding_id"] == "Fa12345"
        assert entry["path"] == "app.py"
        assert entry["old_content"] == "x = 1\n"
        assert entry["new_content"] == "x = 2\n"
        assert entry["ast_valid"] is True
        assert entry["applied"] is True
        assert entry["error"] == ""

    def test_scope_lock_failure_logged(self, tmp_path):
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["other.py"],
        )
        tool.forward("blocked.py", "content", "Fblock0")

        assert len(tool._fix_log) == 1
        entry = tool._fix_log[0]
        assert entry["applied"] is False
        assert "not in PR diff" in entry["error"]

    def test_ast_failure_logged(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )
        tool.forward("app.py", "def broken(\n", "Fast000")

        assert len(tool._fix_log) == 1
        entry = tool._fix_log[0]
        assert entry["ast_valid"] is False
        assert entry["applied"] is False
        assert "syntax" in entry["error"].lower()

    def test_path_traversal_logged(self, tmp_path):
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=[],
        )
        tool.forward("../../etc/passwd", "hacked", "Ftrav00")

        assert len(tool._fix_log) == 1
        entry = tool._fix_log[0]
        assert entry["applied"] is False
        assert "path traversal" in entry["error"]

    def test_multiple_attempts_accumulated(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )

        # First fix: success
        tool.forward("app.py", "x = 2", "Ffix001")
        # Second fix: AST failure
        tool.forward("app.py", "def broken(\n", "Ffix002")
        # Third fix: success (fixes the broken attempt)
        tool.forward("app.py", "x = 3\ny = 4\n", "Ffix002")

        assert len(tool._fix_log) == 3
        assert tool._fix_log[0]["applied"] is True
        assert tool._fix_log[1]["applied"] is False
        assert tool._fix_log[2]["applied"] is True

    def test_fix_log_records_incremental_old_content(self, tmp_path):
        """Old content reflects the state before each fix."""
        (tmp_path / "app.py").write_text("original")
        tool = ApplyFixTool(
            workspace_path=str(tmp_path),
            allowed_files=["app.py"],
        )

        tool.forward("app.py", "after_fix_1", "Ffix001")
        tool.forward("app.py", "after_fix_2", "Ffix002")

        assert tool._fix_log[0]["old_content"] == "original"
        assert tool._fix_log[0]["new_content"] == "after_fix_1"
        assert tool._fix_log[1]["old_content"] == "after_fix_1"
        assert tool._fix_log[1]["new_content"] == "after_fix_2"


# --- _validate_syntax ---

class TestValidateSyntax:

    def test_valid_python(self):
        ok, err = _validate_syntax("app.py", "x = 1\ndef foo(): pass\n")
        assert ok is True
        assert err == ""

    def test_invalid_python(self):
        ok, err = _validate_syntax("app.py", "def broken(\n")
        assert ok is False
        assert "syntax" in err.lower()

    def test_non_python_always_valid(self):
        ok, err = _validate_syntax("app.js", "this is not valid python")
        assert ok is True

    def test_non_python_yaml(self):
        ok, err = _validate_syntax("config.yml", ": invalid yaml [ {")
        assert ok is True

    def test_empty_python_valid(self):
        ok, err = _validate_syntax("empty.py", "")
        assert ok is True
