"""Tests for the decision engine."""

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

    def test_verdict_is_allowed(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.verdict == Verdict.ALLOWED

    def test_pipeline_continues(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.continue_pipeline is True

    def test_no_tools_selected(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.selected_tools == []

    def test_severity_is_none(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.max_severity == Severity.NONE


class TestEnforceMode:

    def test_verdict_is_manual_review(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.verdict == Verdict.MANUAL_REVIEW

    def test_pipeline_blocked(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.continue_pipeline is False


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
