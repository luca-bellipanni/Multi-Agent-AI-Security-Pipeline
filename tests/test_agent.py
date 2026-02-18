"""Tests for the triage agent response parsing."""

import json
from unittest.mock import patch, MagicMock

from src.agent import (
    TRIAGE_SYSTEM_PROMPT,
    parse_triage_response,
    build_triage_task,
    create_triage_agent,
)
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


# ── New format: context + recommended_agents ─────────────────────────


class TestParseTriageNewFormat:

    def test_full_new_format(self):
        response = json.dumps({
            "context": {
                "languages": ["python"],
                "files_changed": 3,
                "risk_areas": ["authentication"],
                "has_dependency_changes": True,
                "has_iac_changes": False,
                "change_summary": "Auth module changes",
            },
            "recommended_agents": ["appsec"],
            "reason": "Python code with auth changes",
        })
        result = parse_triage_response(response)
        assert result["context"]["languages"] == ["python"]
        assert result["context"]["files_changed"] == 3
        assert result["context"]["risk_areas"] == ["authentication"]
        assert result["context"]["has_dependency_changes"] is True
        assert result["context"]["has_iac_changes"] is False
        assert result["context"]["change_summary"] == "Auth module changes"
        assert result["recommended_agents"] == ["appsec"]
        assert result["reason"] == "Python code with auth changes"

    def test_multiple_languages_and_risk_areas(self):
        response = json.dumps({
            "context": {
                "languages": ["python", "javascript"],
                "files_changed": 10,
                "risk_areas": ["api_handlers", "dependencies"],
                "has_dependency_changes": True,
                "has_iac_changes": True,
                "change_summary": "Full stack changes",
            },
            "recommended_agents": ["appsec"],
            "reason": "Multiple languages",
        })
        result = parse_triage_response(response)
        assert len(result["context"]["languages"]) == 2
        assert "javascript" in result["context"]["languages"]
        assert result["context"]["has_iac_changes"] is True

    def test_explicit_empty_agents_accepted(self):
        """Triage explicitly says no agents needed (e.g., docs-only PR)."""
        response = json.dumps({
            "context": {"languages": [], "change_summary": "Docs only"},
            "recommended_agents": [],
            "reason": "Only .md files changed, no code to scan",
        })
        result = parse_triage_response(response)
        assert result["recommended_agents"] == []

    def test_missing_agents_field_defaults_to_appsec(self):
        response = json.dumps({
            "context": {"languages": ["go"]},
            "reason": "test",
        })
        result = parse_triage_response(response)
        assert result["recommended_agents"] == ["appsec"]

    def test_invalid_agents_filtered(self):
        response = json.dumps({
            "context": {"languages": []},
            "recommended_agents": [123, None, "appsec"],
            "reason": "test",
        })
        result = parse_triage_response(response)
        assert result["recommended_agents"] == ["appsec"]

    def test_missing_context_fields_get_defaults(self):
        response = json.dumps({
            "context": {},
            "recommended_agents": ["appsec"],
            "reason": "minimal context",
        })
        result = parse_triage_response(response)
        assert result["context"]["languages"] == []
        assert result["context"]["files_changed"] == 0
        assert result["context"]["risk_areas"] == []
        assert result["context"]["has_dependency_changes"] is False
        assert result["context"]["has_iac_changes"] is False
        assert result["context"]["change_summary"] == ""

    def test_non_list_languages_defaults_to_empty(self):
        response = json.dumps({
            "context": {"languages": "python"},
            "recommended_agents": ["appsec"],
            "reason": "test",
        })
        result = parse_triage_response(response)
        assert result["context"]["languages"] == []

    def test_non_int_files_changed_defaults_to_zero(self):
        response = json.dumps({
            "context": {"files_changed": "many"},
            "recommended_agents": ["appsec"],
            "reason": "test",
        })
        result = parse_triage_response(response)
        assert result["context"]["files_changed"] == 0

    def test_non_string_reason_replaced(self):
        response = json.dumps({
            "context": {"languages": []},
            "recommended_agents": ["appsec"],
            "reason": 42,
        })
        result = parse_triage_response(response)
        assert result["reason"] == "No reason provided."

    def test_json_with_surrounding_text(self):
        response = (
            'Here is my analysis:\n'
            + json.dumps({
                "context": {"languages": ["python"]},
                "recommended_agents": ["appsec"],
                "reason": "test",
            })
            + '\nDone.'
        )
        result = parse_triage_response(response)
        assert result["context"]["languages"] == ["python"]

    def test_empty_agents_only_strings_filtered_defaults_to_appsec(self):
        """If all entries are non-string, and field is present, result is []."""
        response = json.dumps({
            "context": {"languages": []},
            "recommended_agents": [123, None, False],
            "reason": "test",
        })
        result = parse_triage_response(response)
        # Field present but all entries filtered → treated as explicit empty
        assert result["recommended_agents"] == []

    def test_agents_with_unknown_agent_preserved(self):
        """Unknown agent names are kept (future-proofing)."""
        response = json.dumps({
            "context": {"languages": []},
            "recommended_agents": ["sca"],
            "reason": "dependency-only change",
        })
        result = parse_triage_response(response)
        assert result["recommended_agents"] == ["sca"]


# ── Backward compatibility: old format ───────────────────────────────


class TestParseTriageBackwardCompat:

    def test_old_format_with_semgrep(self):
        response = '{"recommended_tools": [{"tool": "semgrep"}], "reason": "Python code"}'
        result = parse_triage_response(response)
        assert "appsec" in result["recommended_agents"]
        assert "context" in result
        assert result["reason"] == "Python code"

    def test_old_format_flat_strings(self):
        response = '{"recommended_tools": ["semgrep", "gitleaks"], "reason": "Full scan"}'
        result = parse_triage_response(response)
        assert "appsec" in result["recommended_agents"]
        assert isinstance(result["context"], dict)

    def test_old_format_mixed(self):
        response = json.dumps({
            "recommended_tools": [
                "gitleaks",
                {"tool": "semgrep", "config": ["p/python"]},
            ],
            "reason": "Mix",
        })
        result = parse_triage_response(response)
        assert "appsec" in result["recommended_agents"]

    def test_old_format_context_stub(self):
        response = '{"recommended_tools": ["semgrep"], "reason": "old"}'
        result = parse_triage_response(response)
        ctx = result["context"]
        assert ctx["languages"] == []
        assert "legacy" in ctx["change_summary"].lower()


# ── Error handling ───────────────────────────────────────────────────


class TestParseTriageErrors:

    def test_invalid_json_returns_default(self):
        result = parse_triage_response("this is not json at all")
        assert result["recommended_agents"] == ["appsec"]
        assert "could not be parsed" in result["reason"].lower()

    def test_empty_response_returns_default(self):
        result = parse_triage_response("")
        assert result["recommended_agents"] == ["appsec"]

    def test_none_response_returns_default(self):
        result = parse_triage_response(None)
        assert result["recommended_agents"] == ["appsec"]

    def test_no_recognized_format_returns_default(self):
        result = parse_triage_response('{"some_random_field": 123}')
        assert result["recommended_agents"] == ["appsec"]

    def test_default_has_valid_context(self):
        result = parse_triage_response("garbage")
        assert isinstance(result["context"], dict)
        assert isinstance(result["context"]["languages"], list)


# ── build_triage_task ────────────────────────────────────────────────


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

    def test_pr_number_triggers_fetch_instruction(self):
        task = build_triage_task(_make_context(pr_number=42))
        assert "Fetch the file list" in task

    def test_no_pr_number_no_fetch_instruction(self):
        task = build_triage_task(_make_context(pr_number=None))
        assert "No PR number" in task
        assert "Fetch" not in task

    def test_mentions_context(self):
        task = build_triage_task(_make_context())
        assert "context" in task.lower()


# ── create_triage_agent ──────────────────────────────────────────────


class TestCreateTriageAgent:

    @patch("src.agent.LiteLLMModel")
    @patch("src.agent.CodeAgent")
    def test_default_no_tools(self, mock_code_agent, mock_model):
        create_triage_agent("key", "model")
        call_kwargs = mock_code_agent.call_args
        assert call_kwargs.kwargs.get("tools") == []

    @patch("src.agent.LiteLLMModel")
    @patch("src.agent.CodeAgent")
    def test_tools_passed_through(self, mock_code_agent, mock_model):
        fake_tool = MagicMock()
        create_triage_agent("key", "model", tools=[fake_tool])
        call_kwargs = mock_code_agent.call_args
        assert fake_tool in call_kwargs.kwargs.get("tools")

    @patch("src.agent.LiteLLMModel")
    @patch("src.agent.CodeAgent")
    def test_max_steps_is_three(self, mock_code_agent, mock_model):
        create_triage_agent("key", "model")
        call_kwargs = mock_code_agent.call_args
        assert call_kwargs.kwargs.get("max_steps") == 3


# ── System prompt checks ─────────────────────────────────────────────


class TestTriageSystemPrompt:

    def test_prompt_warns_about_untrusted_input(self):
        assert "UNTRUSTED INPUT" in TRIAGE_SYSTEM_PROMPT

    def test_prompt_does_not_recommend_rulesets(self):
        assert "Do NOT recommend specific rulesets" in TRIAGE_SYSTEM_PROMPT

    def test_prompt_mentions_context(self):
        assert "context" in TRIAGE_SYSTEM_PROMPT.lower()

    def test_prompt_mentions_risk_areas(self):
        assert "risk_areas" in TRIAGE_SYSTEM_PROMPT

    def test_prompt_allows_empty_agents(self):
        """Prompt teaches triage that [] is valid for non-code PRs."""
        assert '"recommended_agents": []' in TRIAGE_SYSTEM_PROMPT

    def test_prompt_prefers_false_positives(self):
        """Prompt says: if in doubt, recommend appsec."""
        assert "false positives are better" in TRIAGE_SYSTEM_PROMPT.lower()
