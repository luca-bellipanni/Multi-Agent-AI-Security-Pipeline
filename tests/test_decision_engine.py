"""Tests for the decision engine.

Tests the deterministic gate, safety net, and analysis report builder.
The gate uses RAW findings from tool side channel (LLM05), not agent claims.
"""

import json
from unittest.mock import patch, MagicMock

from src.models import Verdict, Severity, Finding, ToolResult
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


def _make_finding(severity=Severity.HIGH, **overrides):
    defaults = dict(
        tool="semgrep",
        rule_id="python.test.rule",
        path="src/app.py",
        line=10,
        severity=severity,
        message="Test finding",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_tool_result(findings=None, success=True, **overrides):
    defaults = dict(
        tool="semgrep",
        success=success,
        findings=findings or [],
    )
    defaults.update(overrides)
    return ToolResult(**defaults)


def _empty_analysis():
    return {
        "confirmed": [],
        "dismissed": [],
        "summary": "",
        "findings_analyzed": 0,
        "rulesets_used": [],
        "rulesets_rationale": "",
        "risk_assessment": "",
    }


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


# --- Shadow mode (no API key) ---

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


# --- Enforce mode (no API key) ---

class TestEnforceMode:
    """Without API key, enforce mode runs default tools (semgrep).
    Without semgrep installed, the analyzer fails → MANUAL_REVIEW."""

    def test_verdict_is_manual_review(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.verdict == Verdict.MANUAL_REVIEW

    def test_pipeline_blocked(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.continue_pipeline is False


# --- Fallback no API key ---

class TestFallbackNoApiKey:
    """Without INPUT_AI_API_KEY, the engine uses deterministic fallback."""

    @patch.dict("os.environ", {}, clear=True)
    def test_shadow_works_without_api_key(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert decision.verdict == Verdict.ALLOWED
        assert "No AI configured" in decision.reason

    @patch.dict("os.environ", {}, clear=True)
    def test_enforce_works_without_api_key(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        assert decision.verdict == Verdict.MANUAL_REVIEW

    @patch.dict("os.environ", {}, clear=True)
    def test_default_tools_recommended_without_ai(self):
        """Without AI, semgrep should be in selected_tools as default."""
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert "semgrep" in decision.selected_tools


# --- Fallback on AI error ---

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


# --- Gate with findings (direct _apply_gate tests) ---

class TestGateWithFindings:
    """Test the deterministic gate with raw findings from tool side channel."""

    def _gate(self, mode, tool_results, triage=None, analysis=None):
        engine = DecisionEngine()
        if triage is None:
            triage = _make_triage()
        if analysis is None:
            analysis = _empty_analysis()
        return engine._apply_gate(
            _make_context(mode=mode), triage, tool_results, analysis,
        )

    # -- Shadow mode always ALLOWED --

    def test_shadow_allowed_even_with_critical(self):
        tr = _make_tool_result([_make_finding(Severity.CRITICAL)])
        d = self._gate("shadow", [tr])
        assert d.verdict == Verdict.ALLOWED
        assert d.continue_pipeline is True

    def test_shadow_max_severity_set(self):
        tr = _make_tool_result([_make_finding(Severity.HIGH)])
        d = self._gate("shadow", [tr])
        assert d.max_severity == Severity.HIGH

    def test_shadow_findings_count(self):
        tr = _make_tool_result([_make_finding(), _make_finding(Severity.MEDIUM)])
        d = self._gate("shadow", [tr])
        assert d.findings_count == 2

    def test_shadow_no_findings(self):
        tr = _make_tool_result([])
        d = self._gate("shadow", [tr])
        assert d.findings_count == 0
        assert d.max_severity == Severity.NONE

    # -- Enforce mode: BLOCKED on critical --

    def test_enforce_blocked_on_critical(self):
        tr = _make_tool_result([_make_finding(Severity.CRITICAL)])
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.BLOCKED
        assert d.continue_pipeline is False

    # -- Enforce mode: MANUAL_REVIEW on high (not BLOCKED) --

    def test_enforce_manual_review_on_high(self):
        tr = _make_tool_result([_make_finding(Severity.HIGH)])
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.continue_pipeline is False

    # -- Enforce mode: MANUAL_REVIEW on medium --

    def test_enforce_manual_review_on_medium(self):
        tr = _make_tool_result([_make_finding(Severity.MEDIUM)])
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.continue_pipeline is False

    # -- Enforce mode: MANUAL_REVIEW on low (human reviews everything) --

    def test_enforce_manual_review_on_low(self):
        tr = _make_tool_result([_make_finding(Severity.LOW)])
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.continue_pipeline is False

    # -- Enforce mode: mixed severities --

    def test_enforce_blocked_on_mixed_with_critical(self):
        tr = _make_tool_result([
            _make_finding(Severity.CRITICAL),
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
        ])
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.BLOCKED

    def test_enforce_manual_review_on_mixed_high_medium(self):
        tr = _make_tool_result([
            _make_finding(Severity.HIGH),
            _make_finding(Severity.MEDIUM),
        ])
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.MANUAL_REVIEW

    # -- Enforce mode: ALLOWED on clean scan --

    def test_enforce_allowed_on_clean_scan(self):
        tr = _make_tool_result([])
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.ALLOWED
        assert d.continue_pipeline is True

    # -- Enforce mode: tool failure --

    def test_enforce_manual_review_on_tool_failure(self):
        tr = _make_tool_result([], success=False, error="semgrep crashed")
        d = self._gate("enforce", [tr])
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.continue_pipeline is False

    # -- Enforce mode: no tools ran --

    def test_enforce_manual_review_no_tools(self):
        d = self._gate("enforce", [])
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.continue_pipeline is False

    # -- Triage reason in decision --

    def test_triage_reason_in_decision(self):
        triage = _make_triage(reason="Docs only, skip scanning")
        d = self._gate("shadow", [], triage=triage)
        assert "Docs only" in d.reason

    # -- Analysis report included --

    def test_analysis_report_included(self):
        analysis = _empty_analysis()
        analysis["summary"] = "One high finding"
        analysis["rulesets_used"] = ["p/python"]
        tr = _make_tool_result([_make_finding(Severity.HIGH)])
        d = self._gate("enforce", [tr], analysis=analysis)
        assert d.analysis_report != ""
        assert "AppSec Analysis Report" in d.analysis_report

    def test_shadow_includes_analysis_report(self):
        analysis = _empty_analysis()
        analysis["summary"] = "Test summary"
        tr = _make_tool_result([_make_finding(Severity.HIGH)])
        d = self._gate("shadow", [tr], analysis=analysis)
        assert d.analysis_report != ""


# --- Safety Net (LLM05) ---

class TestSafetyNet:
    """Test _check_agent_dismissals detects manipulated agent output.

    Security (LLM05): the gate compares raw findings from the tool's side
    channel against the agent's claims. If the agent dismissed HIGH/CRITICAL
    findings, the gate flags it.
    """

    def _check(self, raw_findings, agent_analysis):
        engine = DecisionEngine()
        return engine._check_agent_dismissals(raw_findings, agent_analysis)

    def test_dismissed_critical_triggers_warning(self):
        raw = [_make_finding(Severity.CRITICAL, rule_id="critical.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "critical.rule", "reason": "safe"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 1
        assert warnings[0]["type"] == "dismissed_high_severity"
        assert warnings[0]["rule_id"] == "critical.rule"

    def test_dismissed_high_triggers_warning(self):
        raw = [_make_finding(Severity.HIGH, rule_id="high.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "high.rule", "reason": "false positive"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 1
        assert warnings[0]["type"] == "dismissed_high_severity"

    def test_dismissed_medium_no_warning(self):
        """Agent can dismiss MEDIUM findings without triggering safety net."""
        raw = [_make_finding(Severity.MEDIUM, rule_id="med.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "med.rule", "reason": "noise"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_dismissed_low_no_warning(self):
        """Agent can dismiss LOW findings without triggering safety net."""
        raw = [_make_finding(Severity.LOW, rule_id="low.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "low.rule", "reason": "noise"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_unaccounted_high_triggers_warning(self):
        """HIGH finding not mentioned by agent → warning."""
        raw = [_make_finding(Severity.HIGH, rule_id="missed.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 1
        assert warnings[0]["type"] == "unaccounted_high_severity"

    def test_confirmed_high_no_warning(self):
        """HIGH finding confirmed by agent → no warning."""
        raw = [_make_finding(Severity.HIGH, rule_id="good.rule")]
        analysis = {
            "confirmed": [{"rule_id": "good.rule", "severity": "HIGH"}],
            "dismissed": [],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_multiple_dismissed_high(self):
        raw = [
            _make_finding(Severity.HIGH, rule_id="rule.a"),
            _make_finding(Severity.CRITICAL, rule_id="rule.b"),
        ]
        analysis = {
            "confirmed": [],
            "dismissed": [
                {"rule_id": "rule.a", "reason": "fp"},
                {"rule_id": "rule.b", "reason": "fp"},
            ],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 2

    def test_invalid_dismissed_entries_ignored(self):
        """Non-dict or missing rule_id entries in dismissed are skipped."""
        raw = [_make_finding(Severity.HIGH, rule_id="real.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [
                "not a dict",
                {"no_rule_id": True},
                {"rule_id": 123},  # non-string rule_id
            ],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 1  # unaccounted_high_severity
        assert warnings[0]["type"] == "unaccounted_high_severity"

    def test_safety_warnings_in_gate_reason(self):
        """Safety warnings are appended to the gate's reason."""
        engine = DecisionEngine()
        raw = [_make_finding(Severity.HIGH, rule_id="bad.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "bad.rule", "reason": "safe"}],
        }
        tr = _make_tool_result(raw)
        d = engine._apply_gate(
            _make_context(mode="enforce"), _make_triage(), [tr], analysis,
        )
        assert "safety warning" in d.reason.lower()
        assert len(d.safety_warnings) == 1

    def test_no_safety_warnings_clean_reason(self):
        """No safety warnings → no warning text in reason."""
        engine = DecisionEngine()
        analysis = {
            "confirmed": [{"rule_id": "python.test.rule", "severity": "HIGH"}],
            "dismissed": [],
        }
        raw = [_make_finding(Severity.HIGH)]
        tr = _make_tool_result(raw)
        d = engine._apply_gate(
            _make_context(mode="enforce"), _make_triage(), [tr], analysis,
        )
        assert "safety warning" not in d.reason.lower()


# --- Gate uses RAW findings (LLM05) ---

class TestGateUsesRawFindings:
    """Verify the gate uses raw findings from tool side channel,
    not the agent's confirmed/dismissed lists."""

    def test_agent_dismisses_all_but_gate_blocks(self):
        """Agent says 'all dismissed', but raw findings have CRITICAL → BLOCKED."""
        engine = DecisionEngine()
        raw = [_make_finding(Severity.CRITICAL, rule_id="critical.vuln")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "critical.vuln", "reason": "safe"}],
            "summary": "All clean!",
            "findings_analyzed": 1,
        }
        tr = _make_tool_result(raw)
        d = engine._apply_gate(
            _make_context(mode="enforce"), _make_triage(), [tr], analysis,
        )
        assert d.verdict == Verdict.BLOCKED
        assert d.findings_count == 1

    def test_agent_confirms_all_gate_agrees(self):
        """Agent confirms findings, gate also sees them → consistent."""
        engine = DecisionEngine()
        raw = [_make_finding(Severity.HIGH, rule_id="real.vuln")]
        analysis = {
            "confirmed": [{"rule_id": "real.vuln", "severity": "HIGH"}],
            "dismissed": [],
            "summary": "One real issue",
        }
        tr = _make_tool_result(raw)
        d = engine._apply_gate(
            _make_context(mode="enforce"), _make_triage(), [tr], analysis,
        )
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.findings_count == 1
        assert len(d.safety_warnings) == 0

    def test_empty_raw_findings_allowed(self):
        """Even if agent claims findings, empty raw → ALLOWED."""
        engine = DecisionEngine()
        analysis = {
            "confirmed": [{"rule_id": "phantom", "severity": "HIGH"}],
            "dismissed": [],
        }
        tr = _make_tool_result([])
        d = engine._apply_gate(
            _make_context(mode="enforce"), _make_triage(), [tr], analysis,
        )
        assert d.verdict == Verdict.ALLOWED


# --- Analysis Report ---

class TestAnalysisReport:
    """Test the human-readable analysis report builder."""

    def _report(self, analysis, raw_findings, safety_warnings=None):
        engine = DecisionEngine()
        return engine._build_analysis_report(
            analysis, raw_findings, safety_warnings or [],
        )

    def test_includes_header(self):
        report = self._report(_empty_analysis(), [])
        assert "AppSec Analysis Report" in report

    def test_includes_rulesets(self):
        analysis = _empty_analysis()
        analysis["rulesets_used"] = ["p/python", "p/security-audit"]
        analysis["rulesets_rationale"] = "Python code"
        report = self._report(analysis, [])
        assert "p/python" in report
        assert "Python code" in report

    def test_includes_raw_findings_count(self):
        raw = [_make_finding(), _make_finding(Severity.MEDIUM)]
        report = self._report(_empty_analysis(), raw)
        assert "Raw findings from scanner: 2" in report

    def test_includes_confirmed_detail(self):
        analysis = _empty_analysis()
        analysis["confirmed"] = [
            {"rule_id": "sql.injection", "severity": "HIGH",
             "path": "app.py", "line": 42,
             "reason": "SQL injection risk",
             "recommendation": "Use parameterized queries"},
        ]
        report = self._report(analysis, [])
        assert "sql.injection" in report
        assert "SQL injection risk" in report
        assert "parameterized queries" in report

    def test_includes_dismissed_detail(self):
        analysis = _empty_analysis()
        analysis["dismissed"] = [
            {"rule_id": "test.rule", "reason": "test file"},
        ]
        report = self._report(analysis, [])
        assert "test.rule" in report
        assert "test file" in report

    def test_includes_safety_warnings(self):
        warnings = [{
            "type": "dismissed_high_severity",
            "rule_id": "bad.rule",
            "severity": "HIGH",
            "path": "app.py",
            "line": 10,
            "message": "Agent dismissed HIGH finding bad.rule",
        }]
        report = self._report(_empty_analysis(), [], warnings)
        assert "SAFETY WARNINGS" in report
        assert "bad.rule" in report

    def test_no_warnings_no_section(self):
        report = self._report(_empty_analysis(), [], [])
        assert "SAFETY WARNINGS" not in report

    def test_includes_summary(self):
        analysis = _empty_analysis()
        analysis["summary"] = "One critical vulnerability found"
        report = self._report(analysis, [])
        assert "One critical vulnerability found" in report

    def test_includes_risk_assessment(self):
        analysis = _empty_analysis()
        analysis["risk_assessment"] = "High risk due to SQL injection"
        report = self._report(analysis, [])
        assert "High risk due to SQL injection" in report


# --- Output format ---

class TestOutputFormat:

    def test_to_outputs_returns_strings(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        outputs = decision.to_outputs()
        assert outputs["decision"] == "allowed"
        assert outputs["continue_pipeline"] == "true"
        assert isinstance(outputs["reason"], str)
        assert isinstance(outputs["findings_count"], str)

    def test_to_outputs_has_safety_warnings_count(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        outputs = decision.to_outputs()
        assert "safety_warnings_count" in outputs
        assert outputs["safety_warnings_count"] == "0"

    def test_to_dict_has_version_2(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        d = decision.to_dict()
        assert d["version"] == "2.0"

    def test_to_dict_has_findings_count(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        d = decision.to_dict()
        assert "findings_count" in d

    def test_to_dict_has_analysis_report(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        d = decision.to_dict()
        assert "analysis_report" in d

    def test_to_dict_has_safety_warnings(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        d = decision.to_dict()
        assert "safety_warnings" in d
        assert isinstance(d["safety_warnings"], list)

    def test_to_json_is_valid(self):
        decision = DecisionEngine().decide(_make_context(mode="enforce"))
        parsed = json.loads(decision.to_json())
        assert parsed["verdict"] == "manual_review"


# --- Tool injection ---

class TestToolInjection:
    """Verify that DecisionEngine creates and passes the PR files tool."""

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
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
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_no_tool_without_pr_number(self, mock_create, mock_run):
        """When pr_number is None, no tool is created."""
        ctx = _make_context(token="ghp_test", pr_number=None)
        DecisionEngine().decide(ctx)

        call_kwargs = mock_create.call_args
        tools = call_kwargs.kwargs.get("tools", [])
        assert tools == []

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_no_tool_without_token(self, mock_create, mock_run):
        """When github token is empty, no tool is created."""
        ctx = _make_context(token="", pr_number=42)
        DecisionEngine().decide(ctx)

        call_kwargs = mock_create.call_args
        tools = call_kwargs.kwargs.get("tools", [])
        assert tools == []


# --- Analyzer integration ---

class TestAnalyzerIntegration:

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    @patch("src.analyzer_agent.create_analyzer_agent", side_effect=RuntimeError("LLM down"))
    def test_analyzer_failure_manual_review(
        self, mock_create_analyzer,
        mock_create_triage, mock_run_triage,
    ):
        ctx = _make_context(mode="enforce")
        decision = DecisionEngine().decide(ctx)
        assert decision.verdict == Verdict.MANUAL_REVIEW

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage(
        recommended_agents=[],
    ))
    @patch("src.agent.create_triage_agent")
    def test_analyzer_skipped_when_no_appsec(
        self, mock_create_triage, mock_run_triage,
    ):
        """When triage doesn't recommend appsec agent, analyzer is skipped."""
        ctx = _make_context(mode="enforce")
        decision = DecisionEngine().decide(ctx)
        assert decision.verdict == Verdict.MANUAL_REVIEW

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_raw_findings_reach_gate_via_side_channel(
        self, mock_create_triage, mock_run_triage,
    ):
        """Side channel findings reach the gate for verdict."""
        engine = DecisionEngine()

        raw = [_make_finding(Severity.CRITICAL, rule_id="critical.vuln")]
        tr = _make_tool_result(raw)
        engine._run_analyzer = MagicMock(
            return_value=([tr], _empty_analysis()),
        )

        ctx = _make_context(mode="enforce")
        decision = engine.decide(ctx)
        assert decision.verdict == Verdict.BLOCKED
        assert decision.findings_count == 1

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_clean_scan_allows_in_enforce(
        self, mock_create_triage, mock_run_triage,
    ):
        """Empty side channel → clean scan → ALLOWED."""
        engine = DecisionEngine()
        tr = _make_tool_result([])
        engine._run_analyzer = MagicMock(
            return_value=([tr], _empty_analysis()),
        )

        ctx = _make_context(mode="enforce")
        decision = engine.decide(ctx)
        assert decision.verdict == Verdict.ALLOWED
        assert decision.findings_count == 0

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_shadow_always_allowed_with_findings(
        self, mock_create_triage, mock_run_triage,
    ):
        """Shadow mode ALWAYS allowed, regardless of findings."""
        engine = DecisionEngine()
        raw = [_make_finding(Severity.CRITICAL, rule_id="critical.vuln")]
        tr = _make_tool_result(raw)
        engine._run_analyzer = MagicMock(
            return_value=([tr], _empty_analysis()),
        )

        ctx = _make_context(mode="shadow")
        decision = engine.decide(ctx)
        assert decision.verdict == Verdict.ALLOWED
