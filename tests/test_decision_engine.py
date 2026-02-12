"""Tests for the decision engine."""

from unittest.mock import patch

from src.models import Verdict, Severity
from src.github_context import GitHubContext
from src.decision_engine import DecisionEngine


def _make_context(**overrides) -> GitHubContext:
    """Create a GitHubContext with sensible defaults."""
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


class TestShadowMode:
    """Without API key, shadow mode always allows (deterministic fallback)."""

    def test_verdict_is_allowed(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.verdict == Verdict.ALLOWED

    def test_pipeline_continues(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.continue_pipeline is True

    def test_severity_is_none(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.max_severity == Severity.NONE


class TestEnforceMode:
    """Without API key, enforce mode requires manual review (deterministic fallback)."""

    def test_verdict_is_manual_review(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.verdict == Verdict.MANUAL_REVIEW

    def test_pipeline_blocked(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.continue_pipeline is False


class TestFallbackNoApiKey:
    """Without INPUT_AI_API_KEY, the engine skips AI and uses deterministic rules."""

    @patch.dict("os.environ", {}, clear=True)
    def test_shadow_works_without_api_key(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.verdict == Verdict.ALLOWED
        assert "No AI configured" in decision.reason

    @patch.dict("os.environ", {}, clear=True)
    def test_enforce_works_without_api_key(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.verdict == Verdict.MANUAL_REVIEW
        assert "No AI configured" in decision.reason

    @patch.dict("os.environ", {}, clear=True)
    def test_no_tools_recommended_without_ai(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.selected_tools == []


class TestFallbackAiError:
    """When AI is configured but fails, the engine falls back gracefully."""

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.create_triage_agent", side_effect=RuntimeError("API down"))
    def test_shadow_fallback_on_ai_error(self, mock_agent):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.verdict == Verdict.ALLOWED

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.create_triage_agent", side_effect=RuntimeError("API down"))
    def test_enforce_fallback_on_ai_error(self, mock_agent):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.verdict == Verdict.MANUAL_REVIEW


class TestTriageIntegration:
    """When AI triage returns results, they are included in the Decision."""

    def test_triage_tools_in_decision(self):
        engine = DecisionEngine()
        triage = {"recommended_tools": ["semgrep", "gitleaks"], "reason": "Python PR"}
        decision = engine._apply_gate(_make_context(mode="shadow"), triage)
        assert decision.selected_tools == ["semgrep", "gitleaks"]

    def test_triage_reason_in_decision(self):
        engine = DecisionEngine()
        triage = {"recommended_tools": [], "reason": "Docs only, skip scanning"}
        decision = engine._apply_gate(_make_context(mode="shadow"), triage)
        assert "Docs only" in decision.reason

    def test_gate_overrides_ai_in_shadow(self):
        """Shadow mode is ALWAYS allowed, regardless of what AI says."""
        engine = DecisionEngine()
        triage = {"recommended_tools": ["semgrep"], "reason": "Suspicious code"}
        decision = engine._apply_gate(_make_context(mode="shadow"), triage)
        assert decision.verdict == Verdict.ALLOWED

    def test_gate_overrides_ai_in_enforce(self):
        """Enforce mode is ALWAYS manual_review when no tool results exist."""
        engine = DecisionEngine()
        triage = {"recommended_tools": [], "reason": "Looks safe"}
        decision = engine._apply_gate(_make_context(mode="enforce"), triage)
        assert decision.verdict == Verdict.MANUAL_REVIEW


class TestOutputFormat:

    def test_to_outputs_returns_strings(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        outputs = decision.to_outputs()
        assert outputs["decision"] == "allowed"
        assert outputs["continue_pipeline"] == "true"
        assert isinstance(outputs["reason"], str)

    def test_to_dict_has_version(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        d = decision.to_dict()
        assert d["version"] == "1.0"

    def test_to_json_is_valid(self):
        import json
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        parsed = json.loads(decision.to_json())
        assert parsed["verdict"] == "manual_review"


class TestToolInjection:
    """Verify that DecisionEngine creates and passes the PR files tool."""

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value={
        "recommended_tools": ["semgrep", "gitleaks"],
        "reason": "Python files changed",
    })
    @patch("src.agent.create_triage_agent")
    def test_tool_created_for_pr_with_token(self, mock_create, mock_run):
        """When ctx has token, repository, and pr_number, a tool is passed."""
        ctx = _make_context(token="ghp_test", repository="owner/repo", pr_number=42)
        DecisionEngine().decide(ctx)

        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args
        tools = call_kwargs.kwargs.get("tools", [])
        assert len(tools) == 1
        assert tools[0].name == "fetch_pr_files"

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value={
        "recommended_tools": ["gitleaks"],
        "reason": "Push event",
    })
    @patch("src.agent.create_triage_agent")
    def test_no_tool_without_pr_number(self, mock_create, mock_run):
        """When pr_number is None, no tool is created."""
        ctx = _make_context(token="ghp_test", pr_number=None)
        DecisionEngine().decide(ctx)

        call_kwargs = mock_create.call_args
        tools = call_kwargs.kwargs.get("tools", [])
        assert tools == []

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value={
        "recommended_tools": [],
        "reason": "No token",
    })
    @patch("src.agent.create_triage_agent")
    def test_no_tool_without_token(self, mock_create, mock_run):
        """When github token is empty, no tool is created."""
        ctx = _make_context(token="", pr_number=42)
        DecisionEngine().decide(ctx)

        call_kwargs = mock_create.call_args
        tools = call_kwargs.kwargs.get("tools", [])
        assert tools == []
