"""Remediation tools for the Remediation Agent.

ReadCodeTool: reads any file in the workspace (no scope lock).
ApplyFixTool: writes fixes to files in the PR diff (scope lock).

Security guardrails:
- Path traversal: realpath check (never escapes workspace)
- Scope lock on writes: only files in the PR diff can be modified
- AST validation: fixes must produce syntactically valid code
- Fix audit log: side channel records every attempt (LLM05)
- Workspace injected via constructor (LLM06)
"""

import ast
import os

from smolagents import Tool


class ReadCodeTool(Tool):
    """Reads file content from the workspace.

    No scope lock: the agent can read any file in the workspace to
    understand context (config, models, imports, API usage). A real
    developer reads the whole codebase when fixing a bug.

    Security (LLM06): workspace path injected via constructor.
    Security (code-security): path traversal prevented via realpath.
    """

    name = "read_file"
    description = (
        "Reads the content of a file in the workspace. "
        "Use this to understand context before applying fixes. "
        "You can read any file in the workspace."
    )
    inputs = {
        "path": {
            "type": "string",
            "description": (
                "Relative path to the file to read, e.g. 'src/db.py'"
            ),
        },
    }
    output_type = "string"

    def __init__(self, workspace_path: str, **kwargs):
        self.workspace_path = workspace_path
        self._call_count: int = 0
        super().__init__(**kwargs)

    def forward(self, path: str) -> str:
        self._call_count += 1

        full = os.path.join(self.workspace_path, path)
        real = os.path.realpath(full)
        ws_real = os.path.realpath(self.workspace_path)

        # Path traversal guard
        if not real.startswith(ws_real + os.sep) and real != ws_real:
            return "Error: path traversal detected."

        if not os.path.isfile(real):
            return f"Error: {path} not found."

        try:
            with open(real) as f:
                return f.read()
        except OSError as e:
            return f"Error reading {path}: {e}"


class ApplyFixTool(Tool):
    """Applies a security fix to a file in the workspace.

    Scope lock: only files listed in allowed_files can be modified.
    AST validation: fixes must produce syntactically valid code.
    Fix audit log: every attempt is recorded in _fix_log (side channel).

    Security (LLM06): scope lock prevents modifying files outside PR diff.
    Security (LLM05): _fix_log is written by the tool, not the agent.
    Security (code-security): path traversal prevented via realpath.
    """

    name = "apply_fix"
    description = (
        "Applies a security fix to a file. Provide the complete new file "
        "content and the finding_id being fixed. The file must be in the "
        "PR diff. The fix must produce syntactically valid code."
    )
    inputs = {
        "path": {
            "type": "string",
            "description": "Relative path to the file to fix.",
        },
        "new_content": {
            "type": "string",
            "description": "Complete new file content after the fix.",
        },
        "finding_id": {
            "type": "string",
            "description": (
                "Finding ID being fixed (e.g. Fa3b2c1). "
                "One apply_fix call per finding."
            ),
        },
    }
    output_type = "string"

    def __init__(
        self,
        workspace_path: str,
        allowed_files: list[str],
        **kwargs,
    ):
        self.workspace_path = workspace_path
        self.allowed_files = set(allowed_files)
        self._fix_log: list[dict] = []
        self._call_count: int = 0
        super().__init__(**kwargs)

    def forward(self, path: str, new_content: str, finding_id: str) -> str:
        self._call_count += 1

        full = os.path.join(self.workspace_path, path)
        real = os.path.realpath(full)
        ws_real = os.path.realpath(self.workspace_path)

        # Path traversal guard
        if not real.startswith(ws_real + os.sep) and real != ws_real:
            self._fix_log.append({
                "finding_id": finding_id,
                "path": path,
                "old_content": "",
                "new_content": new_content,
                "ast_valid": False,
                "applied": False,
                "error": "path traversal detected",
            })
            return "Error: path traversal detected."

        # Scope lock: only files in the PR diff
        if path not in self.allowed_files:
            self._fix_log.append({
                "finding_id": finding_id,
                "path": path,
                "old_content": "",
                "new_content": new_content,
                "ast_valid": False,
                "applied": False,
                "error": "file not in PR diff",
            })
            return f"Error: {path} is not in the PR diff. Cannot modify."

        # Read old content
        old_content = ""
        if os.path.isfile(real):
            try:
                with open(real) as f:
                    old_content = f.read()
            except OSError as e:
                self._fix_log.append({
                    "finding_id": finding_id,
                    "path": path,
                    "old_content": "",
                    "new_content": new_content,
                    "ast_valid": False,
                    "applied": False,
                    "error": str(e),
                })
                return f"Error reading {path}: {e}"

        # AST validation
        ast_ok, ast_error = _validate_syntax(path, new_content)

        if not ast_ok:
            self._fix_log.append({
                "finding_id": finding_id,
                "path": path,
                "old_content": old_content,
                "new_content": new_content,
                "ast_valid": False,
                "applied": False,
                "error": ast_error,
            })
            return f"Error: fix produces invalid syntax — {ast_error}"

        # Write new content
        try:
            with open(real, "w") as f:
                f.write(new_content)
        except OSError as e:
            self._fix_log.append({
                "finding_id": finding_id,
                "path": path,
                "old_content": old_content,
                "new_content": new_content,
                "ast_valid": True,
                "applied": False,
                "error": str(e),
            })
            return f"Error writing {path}: {e}"

        self._fix_log.append({
            "finding_id": finding_id,
            "path": path,
            "old_content": old_content,
            "new_content": new_content,
            "ast_valid": True,
            "applied": True,
            "error": "",
        })
        return f"Fix applied successfully to {path} for {finding_id}."


def _validate_syntax(path: str, content: str) -> tuple[bool, str]:
    """Validate syntax of file content.

    Returns (is_valid, error_message).
    Currently supports Python (.py). Other languages return True
    (no validation available — extensible).
    """
    if path.endswith(".py"):
        try:
            ast.parse(content)
            return True, ""
        except SyntaxError as e:
            return False, f"Python syntax error: {e}"

    # No validation for other languages (extensible)
    return True, ""
