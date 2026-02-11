"""Tests for the triage agent response parsing."""

from src.agent import parse_triage_response, build_triage_task
from src.github_context import GitHubContext


def _make_context(**overrides) -> GitHubContext:
    defaults = dict(
        token="fake-token",
        mode="shadow",
        workspace="/tmp/workspace",
        repository="owner/repo",
        event_name="pull_request",
        sha="abc123",
        ref="refs/pull/42/merge",
        pr_number=42,
        is_pull_request=True,
    )
    defaults.update(overrides)
    return GitHubContext(**defaults)


class TestParseTriage:

    def test_valid_json(self):
        response = '{"recommended_tools": ["semgrep"], "reason": "Python code changed"}'
        result = parse_triage_response(response)
        assert result["recommended_tools"] == ["semgrep"]
        assert result["reason"] == "Python code changed"

    def test_json_with_extra_text(self):
        response = 'Here is my analysis:\n{"recommended_tools": ["gitleaks"], "reason": "Config files"}\nDone.'
        result = parse_triage_response(response)
        assert result["recommended_tools"] == ["gitleaks"]

    def test_invalid_json_returns_default(self):
        result = parse_triage_response("this is not json at all")
        assert "semgrep" in result["recommended_tools"]
        assert "gitleaks" in result["recommended_tools"]
        assert "could not be parsed" in result["reason"]

    def test_empty_response_returns_default(self):
        result = parse_triage_response("")
        assert len(result["recommended_tools"]) > 0

    def test_none_response_returns_default(self):
        result = parse_triage_response(None)
        assert len(result["recommended_tools"]) > 0

    def test_missing_tools_field_returns_default(self):
        result = parse_triage_response('{"reason": "no tools field"}')
        assert "semgrep" in result["recommended_tools"]

    def test_missing_reason_gets_placeholder(self):
        result = parse_triage_response('{"recommended_tools": ["semgrep"]}')
        assert result["recommended_tools"] == ["semgrep"]
        assert isinstance(result["reason"], str)

    def test_empty_tools_list_is_valid(self):
        result = parse_triage_response('{"recommended_tools": [], "reason": "Docs only"}')
        assert result["recommended_tools"] == []
        assert result["reason"] == "Docs only"


class TestBuildTriageTask:

    def test_includes_repository(self):
        task = build_triage_task(_make_context(repository="myorg/myrepo"))
        assert "myorg/myrepo" in task

    def test_includes_mode(self):
        task = build_triage_task(_make_context(mode="enforce"))
        assert "enforce" in task

    def test_includes_pr_number(self):
        task = build_triage_task(_make_context(pr_number=99))
        assert "99" in task

    def test_no_pr_shows_na(self):
        task = build_triage_task(_make_context(pr_number=None))
        assert "N/A" in task
