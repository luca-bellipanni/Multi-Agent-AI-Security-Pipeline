"""Tests for the GitHub API tools."""

from unittest.mock import patch, MagicMock

from src.tools import (
    FetchPRFilesTool,
    _get_language,
    _format_pr_files,
    DEPENDENCY_FILES,
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
