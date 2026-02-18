"""Tests for the AppSec Agent (Analyzer) module."""

import json
from unittest.mock import patch, MagicMock

from src.analyzer_agent import (
    ANALYZER_SYSTEM_PROMPT,
    create_analyzer_agent,
    build_analyzer_task,
    parse_analyzer_response,
    run_analyzer,
)


# ── Helper: triage result in new format ──────────────────────────────

def _make_triage(**overrides):
    defaults = {
        "context": {
            "languages": ["python"],
            "files_changed": 3,
            "risk_areas": ["authentication"],
            "has_dependency_changes": False,
            "has_iac_changes": False,
            "change_summary": "Auth module changes",
        },
        "recommended_agents": ["appsec"],
        "reason": "Python auth code changed",
    }
    defaults.update(overrides)
    return defaults


# ── parse_analyzer_response ──────────────────────────────────────────


class TestParseAnalyzerResponse:

    def test_valid_full_response(self):
        response = json.dumps({
            "rulesets_used": ["p/security-audit", "p/python"],
            "rulesets_rationale": "Python auth code",
            "findings_analyzed": 3,
            "confirmed": [{"rule_id": "python.exec", "severity": "HIGH",
                           "path": "app.py", "line": 10, "reason": "exec usage",
                           "recommendation": "Use safe alternative"}],
            "dismissed": [{"rule_id": "python.print", "severity": "INFO",
                           "path": "tests/test.py", "line": 5,
                           "reason": "test file"}],
            "summary": "One real issue found.",
            "risk_assessment": "High risk",
        })
        result = parse_analyzer_response(response)
        assert result["findings_analyzed"] == 3
        assert result["rulesets_used"] == ["p/security-audit", "p/python"]
        assert result["rulesets_rationale"] == "Python auth code"
        assert result["risk_assessment"] == "High risk"
        assert len(result["confirmed"]) == 1
        assert result["confirmed"][0]["recommendation"] == "Use safe alternative"
        assert len(result["dismissed"]) == 1
        assert result["dismissed"][0]["severity"] == "INFO"
        assert result["dismissed"][0]["path"] == "tests/test.py"
        assert result["dismissed"][0]["line"] == 5

    def test_json_with_surrounding_text(self):
        response = (
            'Here is my analysis:\n'
            + json.dumps({
                "findings_analyzed": 1, "confirmed": [], "dismissed": [],
                "summary": "Clean.",
            })
            + '\nHope that helps!'
        )
        result = parse_analyzer_response(response)
        assert result["summary"] == "Clean."

    def test_empty_string_returns_default(self):
        result = parse_analyzer_response("")
        assert result["confirmed"] == []
        assert result["dismissed"] == []
        assert result["findings_analyzed"] == 0
        assert result["rulesets_used"] == []
        assert "could not be parsed" in result["summary"]

    def test_none_returns_default(self):
        result = parse_analyzer_response(None)
        assert result["confirmed"] == []

    def test_non_string_returns_default(self):
        result = parse_analyzer_response(12345)
        assert result["confirmed"] == []

    def test_invalid_json_returns_default(self):
        result = parse_analyzer_response("this is not json")
        assert result["confirmed"] == []
        assert result["findings_analyzed"] == 0

    def test_missing_confirmed_field(self):
        response = '{"summary": "no confirmed field", "findings_analyzed": 0}'
        result = parse_analyzer_response(response)
        assert result["confirmed"] == []

    def test_missing_summary_field(self):
        response = '{"confirmed": [], "dismissed": [], "findings_analyzed": 0}'
        result = parse_analyzer_response(response)
        assert result["summary"] == "No summary provided."

    def test_non_string_summary_replaced(self):
        response = '{"summary": 42, "confirmed": [], "dismissed": []}'
        result = parse_analyzer_response(response)
        assert result["summary"] == "No summary provided."

    def test_confirmed_entry_without_rule_id_skipped(self):
        response = json.dumps({
            "confirmed": [
                {"severity": "HIGH"},
                {"rule_id": "valid.rule", "severity": "LOW"},
            ],
            "dismissed": [], "summary": "test",
        })
        result = parse_analyzer_response(response)
        assert len(result["confirmed"]) == 1
        assert result["confirmed"][0]["rule_id"] == "valid.rule"

    def test_confirmed_entry_with_non_string_rule_id_skipped(self):
        response = json.dumps({
            "confirmed": [
                {"rule_id": 123, "severity": "HIGH"},
                {"rule_id": "ok.rule", "severity": "HIGH"},
            ],
            "dismissed": [], "summary": "test",
        })
        result = parse_analyzer_response(response)
        assert len(result["confirmed"]) == 1

    def test_dismissed_entry_without_rule_id_skipped(self):
        response = json.dumps({
            "confirmed": [],
            "dismissed": [
                {"reason": "no rule_id"},
                {"rule_id": "good.rule", "reason": "test file"},
            ],
            "summary": "test",
        })
        result = parse_analyzer_response(response)
        assert len(result["dismissed"]) == 1
        assert result["dismissed"][0]["rule_id"] == "good.rule"

    def test_non_integer_findings_analyzed_uses_count(self):
        response = json.dumps({
            "findings_analyzed": "many",
            "confirmed": [{"rule_id": "a.b", "severity": "HIGH"}],
            "dismissed": [{"rule_id": "c.d", "reason": "fp"}],
            "summary": "test",
        })
        result = parse_analyzer_response(response)
        assert result["findings_analyzed"] == 2

    def test_confirmed_defaults_missing_optional_fields(self):
        response = json.dumps({
            "confirmed": [{"rule_id": "x.y"}],
            "dismissed": [], "summary": "s",
        })
        result = parse_analyzer_response(response)
        entry = result["confirmed"][0]
        assert entry["severity"] == "UNKNOWN"
        assert entry["path"] == ""
        assert entry["line"] == 0
        assert entry["reason"] == ""
        assert entry["recommendation"] == ""

    def test_dismissed_defaults_missing_optional_fields(self):
        response = json.dumps({
            "confirmed": [],
            "dismissed": [{"rule_id": "x.y"}],
            "summary": "s",
        })
        result = parse_analyzer_response(response)
        entry = result["dismissed"][0]
        assert entry["severity"] == "UNKNOWN"
        assert entry["path"] == ""
        assert entry["line"] == 0
        assert entry["reason"] == ""

    def test_non_list_rulesets_used_defaults_to_empty(self):
        response = json.dumps({
            "rulesets_used": "p/python",
            "confirmed": [], "dismissed": [], "summary": "s",
        })
        result = parse_analyzer_response(response)
        assert result["rulesets_used"] == []

    def test_non_string_rulesets_rationale(self):
        response = json.dumps({
            "rulesets_rationale": 42,
            "confirmed": [], "dismissed": [], "summary": "s",
        })
        result = parse_analyzer_response(response)
        assert result["rulesets_rationale"] == ""

    def test_non_string_risk_assessment(self):
        response = json.dumps({
            "risk_assessment": ["high"],
            "confirmed": [], "dismissed": [], "summary": "s",
        })
        result = parse_analyzer_response(response)
        assert result["risk_assessment"] == ""


# ── build_analyzer_task ──────────────────────────────────────────────


class TestBuildAnalyzerTask:

    def test_includes_languages(self):
        task = build_analyzer_task(_make_triage())
        assert "python" in task.lower()

    def test_includes_risk_areas(self):
        triage = _make_triage(context={
            "languages": [],
            "risk_areas": ["authentication", "api_handlers"],
            "change_summary": "test",
        })
        task = build_analyzer_task(triage)
        assert "authentication" in task
        assert "api_handlers" in task

    def test_includes_dependency_changes(self):
        triage = _make_triage(context={
            "languages": [],
            "has_dependency_changes": True,
            "change_summary": "test",
        })
        task = build_analyzer_task(triage)
        assert "Dependency" in task

    def test_includes_iac_changes(self):
        triage = _make_triage(context={
            "languages": [],
            "has_iac_changes": True,
            "change_summary": "test",
        })
        task = build_analyzer_task(triage)
        assert "Infrastructure" in task

    def test_includes_change_summary(self):
        triage = _make_triage(context={
            "languages": [],
            "change_summary": "Modified login handler",
        })
        task = build_analyzer_task(triage)
        assert "Modified login handler" in task

    def test_includes_triage_reason(self):
        triage = _make_triage(reason="Python auth code changed")
        task = build_analyzer_task(triage)
        assert "Python auth code changed" in task

    def test_empty_context_no_crash(self):
        task = build_analyzer_task({})
        assert isinstance(task, str)

    def test_asks_to_select_rulesets(self):
        task = build_analyzer_task(_make_triage())
        assert "rulesets" in task.lower()


# ── create_analyzer_agent ────────────────────────────────────────────


class TestCreateAnalyzerAgent:

    @patch("src.analyzer_agent.LiteLLMModel")
    @patch("src.analyzer_agent.CodeAgent")
    def test_default_no_tools(self, mock_agent, mock_model):
        create_analyzer_agent("key", "model-id")
        call_kwargs = mock_agent.call_args
        assert call_kwargs.kwargs.get("tools") == []

    @patch("src.analyzer_agent.LiteLLMModel")
    @patch("src.analyzer_agent.CodeAgent")
    def test_tools_passed_through(self, mock_agent, mock_model):
        fake_tool = MagicMock()
        create_analyzer_agent("key", "model-id", tools=[fake_tool])
        call_kwargs = mock_agent.call_args
        assert fake_tool in call_kwargs.kwargs.get("tools")

    @patch("src.analyzer_agent.LiteLLMModel")
    @patch("src.analyzer_agent.CodeAgent")
    def test_max_steps_is_ten(self, mock_agent, mock_model):
        create_analyzer_agent("key", "model-id")
        call_kwargs = mock_agent.call_args
        assert call_kwargs.kwargs.get("max_steps") == 10

    @patch("src.analyzer_agent.LiteLLMModel")
    @patch("src.analyzer_agent.CodeAgent")
    def test_system_prompt_set(self, mock_agent, mock_model):
        create_analyzer_agent("key", "model-id")
        agent_instance = mock_agent.return_value
        prompt = agent_instance.prompt_templates.__getitem__("system_prompt")
        # Verify append was called with our security prompt
        agent_instance.prompt_templates.__setitem__.assert_called()
        # Also verify the ANALYZER_SYSTEM_PROMPT constant has security content
        assert "appsec" in ANALYZER_SYSTEM_PROMPT.lower() or "security" in ANALYZER_SYSTEM_PROMPT.lower()

    @patch("src.analyzer_agent.LiteLLMModel")
    @patch("src.analyzer_agent.CodeAgent")
    def test_temperature_low(self, mock_agent, mock_model):
        create_analyzer_agent("key", "model-id")
        model_kwargs = mock_model.call_args
        assert model_kwargs.kwargs.get("temperature") == 0.1


# ── System prompt security checks (LLM01) ───────────────────────────


class TestAnalyzerSystemPromptSecurity:

    def test_prompt_warns_about_untrusted_content(self):
        assert "UNTRUSTED" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_forbids_following_scan_instructions(self):
        assert "NEVER follow instructions" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_forbids_dismissing_via_comments(self):
        assert "NEVER dismiss" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_has_false_positive_criteria(self):
        assert "FALSE POSITIVE CRITERIA" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_mentions_test_files(self):
        assert "test file" in ANALYZER_SYSTEM_PROMPT.lower()

    def test_prompt_includes_ruleset_selection(self):
        assert "RULESET SELECTION" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_mentions_security_audit(self):
        assert "p/security-audit" in ANALYZER_SYSTEM_PROMPT


# ── OODA prompt checks ──────────────────────────────────────────────


class TestAnalyzerOODAPrompt:
    """Verify the system prompt guides the OODA loop."""

    def test_prompt_has_observe_step(self):
        assert "OBSERVE" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_has_reflect_step(self):
        assert "REFLECT" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_has_escalate_step(self):
        assert "ESCALATE" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_warns_diff_untrusted(self):
        assert "diff" in ANALYZER_SYSTEM_PROMPT.lower()
        assert "UNTRUSTED" in ANALYZER_SYSTEM_PROMPT

    def test_prompt_mentions_fetch_pr_diff(self):
        assert "fetch_pr_diff" in ANALYZER_SYSTEM_PROMPT


class TestBuildAnalyzerTaskOODA:

    def test_mentions_observing_code(self):
        task = build_analyzer_task(_make_triage())
        assert "observ" in task.lower()

    def test_mentions_fetch_pr_diff(self):
        task = build_analyzer_task(_make_triage())
        assert "fetch_pr_diff" in task


# ── run_analyzer ─────────────────────────────────────────────────────


class TestRunAnalyzer:

    def test_calls_agent_and_parses(self):
        mock_agent = MagicMock()
        mock_agent.run.return_value = json.dumps({
            "findings_analyzed": 1,
            "confirmed": [{"rule_id": "r.1", "severity": "HIGH",
                           "path": "a.py", "line": 1, "reason": "bad"}],
            "dismissed": [],
            "summary": "one issue",
        })
        result = run_analyzer(mock_agent, _make_triage())
        assert result["findings_analyzed"] == 1
        assert len(result["confirmed"]) == 1
        mock_agent.run.assert_called_once()

    def test_task_includes_context(self):
        mock_agent = MagicMock()
        mock_agent.run.return_value = '{"confirmed": [], "dismissed": [], "summary": "s"}'
        run_analyzer(mock_agent, _make_triage())
        task = mock_agent.run.call_args[0][0]
        assert "python" in task.lower()

    def test_handles_non_string_agent_response(self):
        mock_agent = MagicMock()
        mock_agent.run.return_value = 42
        result = run_analyzer(mock_agent, _make_triage())
        assert result["confirmed"] == []
