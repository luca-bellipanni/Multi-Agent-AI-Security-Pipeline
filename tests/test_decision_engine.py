"""Tests for the decision engine.

Tests the smart gate, safety net, and analysis report builder.
The gate uses CONFIRMED findings (validated against raw) for its verdict.
Safety net catches dismissed/unaccounted HIGH/CRITICAL findings.
Fallback to raw findings when agent hasn't analyzed (fail-secure).
"""

import json
from unittest.mock import patch, MagicMock

from src.models import Verdict, Severity, Finding, StepTrace, ToolResult
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
        assert "Shadow mode:" in decision.reason

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

    def test_shadow_reason_format(self):
        d = self._gate("shadow", [])
        assert "Shadow mode:" in d.reason

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
    """Verify the gate validates confirmed against raw findings,
    uses safety net to catch dismissed HIGH/CRITICAL, and prevents
    hallucinated findings from driving the verdict."""

    def test_agent_dismisses_critical_safety_net_blocks(self):
        """Agent dismisses CRITICAL → safety net fires → BLOCKED.

        The safety net catches the dismissal and includes the CRITICAL
        in effective_findings. CRITICAL always auto-blocks per policy,
        regardless of agent opinion.
        """
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
        assert len(d.safety_warnings) == 1

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

    def test_agent_confirms_critical_gate_blocks(self):
        """Agent confirms CRITICAL → gate BLOCKS (confirmed drives verdict)."""
        engine = DecisionEngine()
        raw = [_make_finding(Severity.CRITICAL, rule_id="crit.vuln")]
        analysis = {
            "confirmed": [{"rule_id": "crit.vuln", "severity": "CRITICAL"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        tr = _make_tool_result(raw)
        d = engine._apply_gate(
            _make_context(mode="enforce"), _make_triage(), [tr], analysis,
        )
        assert d.verdict == Verdict.BLOCKED
        assert d.findings_count == 1


# --- Smart Gate: confirmed-based verdicts ---

class TestSmartGateConfirmedBased:
    """Test the smart gate that uses agent-confirmed findings for verdicts.

    The gate validates confirmed findings against raw (anti-hallucination),
    uses raw severity (anti-manipulation), and falls back to raw when
    the agent hasn't analyzed (fail-secure).
    """

    def _gate(self, findings, analysis, mode="enforce"):
        engine = DecisionEngine()
        tr = _make_tool_result(findings)
        return engine._apply_gate(
            _make_context(mode=mode), _make_triage(), [tr], analysis,
        )

    # -- Confirmed drives verdict --

    def test_confirmed_critical_blocks(self):
        """Confirmed CRITICAL → BLOCKED."""
        raw = [_make_finding(Severity.CRITICAL, rule_id="sqli.critical")]
        analysis = {
            "confirmed": [{"rule_id": "sqli.critical", "severity": "CRITICAL"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.BLOCKED
        assert d.findings_count == 1

    def test_confirmed_high_manual_review(self):
        """Confirmed HIGH → MANUAL_REVIEW."""
        raw = [_make_finding(Severity.HIGH, rule_id="xss.rule")]
        analysis = {
            "confirmed": [{"rule_id": "xss.rule", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.findings_count == 1

    def test_confirmed_medium_manual_review(self):
        """Confirmed MEDIUM → MANUAL_REVIEW."""
        raw = [_make_finding(Severity.MEDIUM, rule_id="info.leak")]
        analysis = {
            "confirmed": [{"rule_id": "info.leak", "severity": "MEDIUM"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.MANUAL_REVIEW

    def test_no_confirmed_allows(self):
        """Agent dismissed all (none HIGH/CRIT) → ALLOWED.

        This is the key noise-filtering scenario: 10 raw findings,
        agent dismissed all as false positives in test files, gate ALLOWS.
        """
        raw = [
            _make_finding(Severity.LOW, rule_id=f"noise.{i}")
            for i in range(10)
        ]
        analysis = {
            "confirmed": [],
            "dismissed": [
                {"rule_id": f"noise.{i}", "reason": "test file"}
                for i in range(10)
            ],
            "findings_analyzed": 10,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.ALLOWED
        assert d.findings_count == 0

    # -- Noise filtering --

    def test_raw_low_dismissed_by_agent_allows(self):
        """10 raw LOW findings, agent dismisses all → ALLOWED."""
        raw = [_make_finding(Severity.LOW, rule_id=f"low.{i}") for i in range(10)]
        analysis = {
            "confirmed": [],
            "dismissed": [
                {"rule_id": f"low.{i}", "reason": "noise"} for i in range(10)
            ],
            "findings_analyzed": 10,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.ALLOWED
        assert d.findings_count == 0

    def test_mixed_raw_only_confirmed_count(self):
        """47 raw, 3 confirmed → findings_count=3, MANUAL_REVIEW."""
        raw = (
            [_make_finding(Severity.HIGH, rule_id=f"real.{i}") for i in range(3)]
            + [_make_finding(Severity.LOW, rule_id=f"noise.{i}") for i in range(44)]
        )
        analysis = {
            "confirmed": [
                {"rule_id": f"real.{i}", "severity": "HIGH"} for i in range(3)
            ],
            "dismissed": [
                {"rule_id": f"noise.{i}", "reason": "fp"} for i in range(44)
            ],
            "findings_analyzed": 47,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.findings_count == 3

    # -- Anti-hallucination --

    def test_hallucinated_confirmed_ignored(self):
        """Agent hallucinates a CRITICAL not in raw → ignored → ALLOWED."""
        raw = [_make_finding(Severity.LOW, rule_id="real.low")]
        analysis = {
            "confirmed": [{"rule_id": "phantom.critical", "severity": "CRITICAL"}],
            "dismissed": [{"rule_id": "real.low", "reason": "noise"}],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        # phantom.critical not in raw → dropped; real.low is LOW dismissed → no safety
        assert d.verdict == Verdict.ALLOWED
        assert d.findings_count == 0

    def test_severity_from_raw_not_agent(self):
        """Agent claims CRITICAL, raw says MEDIUM → verdict uses MEDIUM.

        Anti-severity-manipulation: the gate uses severity from the raw
        finding, not the agent's classification.
        """
        raw = [_make_finding(Severity.MEDIUM, rule_id="sev.test")]
        analysis = {
            "confirmed": [{"rule_id": "sev.test", "severity": "CRITICAL"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        # Confirmed rule exists in raw, but raw severity is MEDIUM → not BLOCKED
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.max_severity == Severity.MEDIUM

    # -- Fallback: agent hasn't analyzed --

    def test_empty_analysis_falls_back_to_raw(self):
        """Empty analysis + raw findings → fallback to raw → MANUAL_REVIEW."""
        raw = [_make_finding(Severity.HIGH, rule_id="raw.high")]
        d = self._gate(raw, _empty_analysis())
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.findings_count == 1

    def test_empty_analysis_critical_blocks(self):
        """Empty analysis + raw CRITICAL → fallback → BLOCKED."""
        raw = [_make_finding(Severity.CRITICAL, rule_id="raw.crit")]
        d = self._gate(raw, _empty_analysis())
        assert d.verdict == Verdict.BLOCKED

    def test_parse_failure_falls_back_to_raw(self):
        """Unparseable response (empty confirmed/dismissed) → fallback."""
        raw = [_make_finding(Severity.MEDIUM, rule_id="raw.med")]
        analysis = {
            "confirmed": [],
            "dismissed": [],
            "findings_analyzed": 0,
            "summary": "Analyzer response could not be parsed.",
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.findings_count == 1  # raw count, not confirmed

    # -- Safety net override --

    def test_safety_net_overrides_to_manual_review(self):
        """Agent dismisses HIGH → safety net fires → MANUAL_REVIEW."""
        raw = [_make_finding(Severity.HIGH, rule_id="dismissed.high")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "dismissed.high", "reason": "fp"}],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert len(d.safety_warnings) == 1

    def test_safety_net_beats_clean_confirmed(self):
        """0 confirmed + safety net fires → MANUAL_REVIEW (not ALLOWED).

        Agent confirms nothing but also dismisses a HIGH finding
        that exists in raw → safety net catches it.
        """
        raw = [
            _make_finding(Severity.HIGH, rule_id="sneaky.high"),
            _make_finding(Severity.LOW, rule_id="noise.low"),
        ]
        analysis = {
            "confirmed": [],
            "dismissed": [
                {"rule_id": "sneaky.high", "reason": "safe"},
                {"rule_id": "noise.low", "reason": "noise"},
            ],
            "findings_analyzed": 2,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert len(d.safety_warnings) == 1

    def test_no_safety_no_confirmed_allows(self):
        """No safety warnings + no confirmed → ALLOWED."""
        raw = [_make_finding(Severity.LOW, rule_id="safe.low")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "safe.low", "reason": "test file"}],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        assert d.verdict == Verdict.ALLOWED
        assert d.findings_count == 0
        assert len(d.safety_warnings) == 0

    # -- findings_count reflects effective --

    def test_findings_count_is_confirmed_count(self):
        """findings_count = len(confirmed validated against raw), not raw."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="real.1"),
            _make_finding(Severity.HIGH, rule_id="real.2"),
            _make_finding(Severity.LOW, rule_id="noise.1"),
            _make_finding(Severity.LOW, rule_id="noise.2"),
            _make_finding(Severity.LOW, rule_id="noise.3"),
        ]
        analysis = {
            "confirmed": [
                {"rule_id": "real.1", "severity": "HIGH"},
                {"rule_id": "real.2", "severity": "HIGH"},
            ],
            "dismissed": [
                {"rule_id": "noise.1", "reason": "fp"},
                {"rule_id": "noise.2", "reason": "fp"},
                {"rule_id": "noise.3", "reason": "fp"},
            ],
            "findings_analyzed": 5,
        }
        d = self._gate(raw, analysis)
        assert d.findings_count == 2  # Only the 2 confirmed

    def test_findings_count_is_raw_in_fallback(self):
        """In fallback mode (no analysis), findings_count = raw count."""
        raw = [_make_finding(Severity.MEDIUM, rule_id=f"r.{i}") for i in range(5)]
        d = self._gate(raw, _empty_analysis())
        assert d.findings_count == 5

    # -- Report includes effective findings --

    def test_report_includes_effective_count(self):
        """Analysis report shows 'Effective findings (verdict based on)'."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="real.1"),
            _make_finding(Severity.LOW, rule_id="noise.1"),
        ]
        analysis = {
            "confirmed": [{"rule_id": "real.1", "severity": "HIGH"}],
            "dismissed": [{"rule_id": "noise.1", "reason": "fp"}],
            "findings_analyzed": 2,
        }
        d = self._gate(raw, analysis)
        assert "Effective findings (verdict based on): 1" in d.analysis_report


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
        reason="Only .md files changed, no code to scan",
    ))
    @patch("src.agent.create_triage_agent")
    def test_triage_skip_produces_allowed(
        self, mock_create_triage, mock_run_triage,
    ):
        """When triage says no agents needed (docs-only), verdict is ALLOWED."""
        ctx = _make_context(mode="enforce")
        decision = DecisionEngine().decide(ctx)
        assert decision.verdict == Verdict.ALLOWED
        assert decision.continue_pipeline is True
        assert "No security-relevant files" in decision.reason

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage(
        recommended_agents=[],
    ))
    @patch("src.agent.create_triage_agent")
    def test_triage_skip_shadow_mode(
        self, mock_create_triage, mock_run_triage,
    ):
        """Triage skip in shadow mode also produces ALLOWED."""
        ctx = _make_context(mode="shadow")
        decision = DecisionEngine().decide(ctx)
        assert decision.verdict == Verdict.ALLOWED
        assert decision.continue_pipeline is True

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage(
        recommended_agents=[],
    ))
    @patch("src.agent.create_triage_agent")
    def test_triage_skip_trace_shows_skipped(
        self, mock_create_triage, mock_run_triage,
    ):
        """Trace shows status='skipped' for AppSec Agent when triage skips."""
        ctx = _make_context(mode="enforce")
        decision = DecisionEngine().decide(ctx)
        appsec_trace = next(
            t for t in decision.trace if "AppSec" in t.name
        )
        assert appsec_trace.status == "skipped"
        assert "Skipped" in appsec_trace.summary

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
            return_value=([tr], _empty_analysis(), {}),
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
            return_value=([tr], _empty_analysis(), {}),
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
            return_value=([tr], _empty_analysis(), {}),
        )

        ctx = _make_context(mode="shadow")
        decision = engine.decide(ctx)
        assert decision.verdict == Verdict.ALLOWED


# --- Cumulative findings (OODA multi-call) ---

class TestCumulativeFindings:
    """Test that the gate sees findings from ALL semgrep calls.

    When the AppSec Agent calls run_semgrep multiple times (OODA
    escalation), the cumulative side channel captures all findings.
    """

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_gate_sees_all_findings_from_multiple_scans(
        self, mock_create_triage, mock_run_triage,
    ):
        """Simulate two semgrep calls: gate sees combined findings."""
        engine = DecisionEngine()
        combined_findings = [
            _make_finding(Severity.HIGH, rule_id="scan1.rule"),
            _make_finding(Severity.MEDIUM, rule_id="scan2.rule"),
        ]
        tr = _make_tool_result(
            combined_findings,
            config_used=["p/python", "p/owasp-top-ten"],
        )
        engine._run_analyzer = MagicMock(
            return_value=([tr], _empty_analysis(), {}),
        )

        ctx = _make_context(mode="enforce")
        decision = engine.decide(ctx)
        assert decision.findings_count == 2
        assert decision.verdict == Verdict.MANUAL_REVIEW

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_all_configs_in_tool_result(
        self, mock_create_triage, mock_run_triage,
    ):
        """Config from multiple scans is accumulated in tool result."""
        engine = DecisionEngine()
        tr = _make_tool_result(
            [],
            config_used=["p/security-audit", "p/python", "p/owasp-top-ten"],
        )
        engine._run_analyzer = MagicMock(
            return_value=([tr], _empty_analysis(), {}),
        )

        ctx = _make_context(mode="enforce")
        decision = engine.decide(ctx)
        assert decision.verdict == Verdict.ALLOWED
        configs = decision.tool_results[0].config_used
        assert "p/security-audit" in configs
        assert "p/python" in configs
        assert "p/owasp-top-ten" in configs


# --- Finding ID (deterministic hash) ---

class TestFindingId:
    """Test the deterministic finding_id property on Finding."""

    def test_format(self):
        """Finding ID starts with 'F' followed by 6 hex chars."""
        f = _make_finding(rule_id="test.rule", path="a.py", line=1)
        assert f.finding_id.startswith("F")
        assert len(f.finding_id) == 7
        # Check it's hex after the F
        int(f.finding_id[1:], 16)

    def test_deterministic(self):
        """Same rule_id+path+line → same finding_id."""
        f1 = _make_finding(rule_id="sqli", path="db.py", line=42)
        f2 = _make_finding(rule_id="sqli", path="db.py", line=42)
        assert f1.finding_id == f2.finding_id

    def test_different_rule_id(self):
        f1 = _make_finding(rule_id="rule.a", path="x.py", line=1)
        f2 = _make_finding(rule_id="rule.b", path="x.py", line=1)
        assert f1.finding_id != f2.finding_id

    def test_different_path(self):
        f1 = _make_finding(rule_id="rule.a", path="a.py", line=1)
        f2 = _make_finding(rule_id="rule.a", path="b.py", line=1)
        assert f1.finding_id != f2.finding_id

    def test_different_line(self):
        f1 = _make_finding(rule_id="rule.a", path="a.py", line=1)
        f2 = _make_finding(rule_id="rule.a", path="a.py", line=2)
        assert f1.finding_id != f2.finding_id

    def test_independent_of_severity(self):
        """ID only depends on rule_id+path+line, not severity."""
        f1 = _make_finding(Severity.HIGH, rule_id="r", path="a.py", line=1)
        f2 = _make_finding(Severity.LOW, rule_id="r", path="a.py", line=1)
        assert f1.finding_id == f2.finding_id

    def test_independent_of_message(self):
        f1 = _make_finding(rule_id="r", path="a.py", line=1, message="msg1")
        f2 = _make_finding(rule_id="r", path="a.py", line=1, message="msg2")
        assert f1.finding_id == f2.finding_id


# --- StepTrace ---

class TestStepTrace:

    def test_creation(self):
        t = StepTrace(
            name="Triage Agent",
            tools_used={"fetch_pr_files": 1},
            summary="3 files, Python",
            status="success",
        )
        assert t.name == "Triage Agent"
        assert t.tools_used == {"fetch_pr_files": 1}
        assert t.summary == "3 files, Python"
        assert t.status == "success"

    def test_empty_tools(self):
        t = StepTrace(name="Gate", tools_used={}, summary="ok", status="success")
        assert t.tools_used == {}


# --- Severity mismatch detection (LLM05) ---

class TestSeverityMismatch:
    """Test _check_severity_mismatches detects agent severity downgrades.

    Security (LLM05 — anti-severity-manipulation): if the agent claims
    a finding is lower severity than the raw scanner reported, the gate
    flags it as a warning. Raw severity always wins.
    """

    def _check(self, raw_findings, agent_analysis):
        engine = DecisionEngine()
        return engine._check_severity_mismatches(raw_findings, agent_analysis)

    def test_downgrade_high_to_low(self):
        raw = [_make_finding(Severity.HIGH, rule_id="rule.a")]
        analysis = {
            "confirmed": [{"rule_id": "rule.a", "severity": "low"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 1
        assert warnings[0]["type"] == "severity_mismatch"
        assert warnings[0]["severity"] == "high"
        assert warnings[0]["agent_severity"] == "low"
        assert warnings[0]["effective_severity"] == "high"

    def test_downgrade_critical_to_medium(self):
        raw = [_make_finding(Severity.CRITICAL, rule_id="rule.b")]
        analysis = {
            "confirmed": [{"rule_id": "rule.b", "severity": "medium"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 1
        assert warnings[0]["severity"] == "critical"
        assert warnings[0]["agent_severity"] == "medium"

    def test_no_mismatch_same_severity(self):
        raw = [_make_finding(Severity.HIGH, rule_id="rule.a")]
        analysis = {
            "confirmed": [{"rule_id": "rule.a", "severity": "high"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_upgrade_no_warning(self):
        """Agent upgrades severity → no warning (conservative is fine)."""
        raw = [_make_finding(Severity.LOW, rule_id="rule.a")]
        analysis = {
            "confirmed": [{"rule_id": "rule.a", "severity": "high"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_unconfirmed_skipped(self):
        """Findings not in agent confirmed are handled elsewhere."""
        raw = [_make_finding(Severity.HIGH, rule_id="unconfirmed")]
        analysis = {"confirmed": []}
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_no_agent_severity_skipped(self):
        """If agent doesn't provide severity field, no mismatch."""
        raw = [_make_finding(Severity.HIGH, rule_id="rule.a")]
        analysis = {
            "confirmed": [{"rule_id": "rule.a"}],  # no severity
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_unknown_agent_severity_skipped(self):
        raw = [_make_finding(Severity.HIGH, rule_id="rule.a")]
        analysis = {
            "confirmed": [{"rule_id": "rule.a", "severity": "banana"}],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 0

    def test_multiple_mismatches(self):
        raw = [
            _make_finding(Severity.HIGH, rule_id="rule.a"),
            _make_finding(Severity.CRITICAL, rule_id="rule.b"),
        ]
        analysis = {
            "confirmed": [
                {"rule_id": "rule.a", "severity": "low"},
                {"rule_id": "rule.b", "severity": "medium"},
            ],
        }
        warnings = self._check(raw, analysis)
        assert len(warnings) == 2

    def test_mismatch_in_gate_triggers_manual_review(self):
        """Severity mismatch on HIGH finding triggers MANUAL_REVIEW."""
        engine = DecisionEngine()
        raw = [_make_finding(Severity.HIGH, rule_id="mismatch.rule")]
        analysis = {
            "confirmed": [{"rule_id": "mismatch.rule", "severity": "low"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        tr = _make_tool_result(raw)
        d = engine._apply_gate(
            _make_context(mode="enforce"), _make_triage(), [tr], analysis,
        )
        # Should have a severity_mismatch warning
        mismatch_warnings = [
            w for w in d.safety_warnings if w["type"] == "severity_mismatch"
        ]
        assert len(mismatch_warnings) == 1
        # The safety warning forces MANUAL_REVIEW
        assert d.verdict == Verdict.MANUAL_REVIEW


# --- Build confirmed structured ---

class TestBuildConfirmedStructured:
    """Test _build_confirmed_structured merges raw + agent context."""

    def _build(self, effective_findings, agent_analysis):
        engine = DecisionEngine()
        return engine._build_confirmed_structured(
            effective_findings, agent_analysis,
        )

    def test_basic_merge(self):
        findings = [_make_finding(Severity.HIGH, rule_id="sqli")]
        analysis = {
            "confirmed": [{
                "rule_id": "sqli",
                "severity": "HIGH",
                "reason": "real injection",
                "recommendation": "use params",
            }],
        }
        result = self._build(findings, analysis)
        assert len(result) == 1
        assert result[0]["finding_id"] == findings[0].finding_id
        assert result[0]["rule_id"] == "sqli"
        assert result[0]["severity"] == "high"  # from raw
        assert result[0]["agent_reason"] == "real injection"
        assert result[0]["agent_recommendation"] == "use params"

    def test_missing_agent_context(self):
        """If agent didn't provide context for a finding, empty strings."""
        findings = [_make_finding(Severity.MEDIUM, rule_id="orphan")]
        analysis = {"confirmed": []}
        result = self._build(findings, analysis)
        assert len(result) == 1
        assert result[0]["agent_reason"] == ""
        assert result[0]["agent_recommendation"] == ""

    def test_includes_path_and_line(self):
        findings = [_make_finding(path="db.py", line=42)]
        analysis = {"confirmed": []}
        result = self._build(findings, analysis)
        assert result[0]["path"] == "db.py"
        assert result[0]["line"] == 42

    def test_empty_findings(self):
        result = self._build([], {"confirmed": []})
        assert result == []

    def test_source_confirmed_default(self):
        """Without safety_warnings, source defaults to 'confirmed'."""
        findings = [_make_finding(Severity.HIGH, rule_id="sqli")]
        analysis = {
            "confirmed": [{"rule_id": "sqli", "severity": "HIGH"}],
        }
        result = self._build(findings, analysis)
        assert result[0]["source"] == "confirmed"

    def test_source_safety_net(self):
        """With safety_warnings, unconfirmed rule_ids get 'safety-net'."""
        engine = DecisionEngine()
        findings = [
            _make_finding(Severity.HIGH, rule_id="confirmed.r"),
            _make_finding(Severity.HIGH, rule_id="missed.r"),
        ]
        analysis = {
            "confirmed": [{"rule_id": "confirmed.r", "severity": "HIGH"}],
        }
        warnings = [{"rule_id": "missed.r", "severity": "high"}]
        result = engine._build_confirmed_structured(
            findings, analysis, warnings,
        )
        assert result[0]["source"] == "confirmed"
        assert result[1]["source"] == "safety-net"


# --- Structured findings on Decision ---

class TestDecisionStructuredFindings:
    """Test that Decision carries structured findings lists."""

    def _gate(self, findings, analysis, mode="enforce"):
        engine = DecisionEngine()
        tr = _make_tool_result(findings)
        return engine._apply_gate(
            _make_context(mode=mode), _make_triage(), [tr], analysis,
        )

    def test_confirmed_findings_populated(self):
        raw = [_make_finding(Severity.HIGH, rule_id="real.vuln")]
        analysis = {
            "confirmed": [{
                "rule_id": "real.vuln",
                "severity": "HIGH",
                "reason": "real issue",
                "recommendation": "fix it",
            }],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        assert len(d.confirmed_findings) == 1
        assert d.confirmed_findings[0]["rule_id"] == "real.vuln"
        assert d.confirmed_findings[0]["finding_id"] == raw[0].finding_id

    def test_dismissed_findings_populated(self):
        raw = [_make_finding(Severity.LOW, rule_id="noise.rule")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "noise.rule", "reason": "test file"}],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis)
        assert len(d.dismissed_findings) == 1
        assert d.dismissed_findings[0]["rule_id"] == "noise.rule"

    def test_shadow_mode_has_structured_findings(self):
        raw = [_make_finding(Severity.HIGH, rule_id="shadow.vuln")]
        analysis = {
            "confirmed": [{"rule_id": "shadow.vuln", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(raw, analysis, mode="shadow")
        assert len(d.confirmed_findings) == 1


# --- Execution trace ---

class TestExecutionTrace:
    """Test that decide() populates the trace list."""

    def test_trace_populated_on_decide(self):
        """decide() should produce trace with 3 entries."""
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        assert len(decision.trace) == 3
        names = [t.name for t in decision.trace]
        assert "Triage Agent" in names
        assert "AppSec Agent (OODA)" in names
        assert "Smart Gate" in names

    def test_trace_all_success(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        for t in decision.trace:
            assert t.status == "success"

    def test_gate_trace_has_verdict(self):
        decision = DecisionEngine().decide(_make_context(mode="shadow"))
        gate_trace = [t for t in decision.trace if t.name == "Smart Gate"][0]
        assert gate_trace.summary == "allowed"

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "fake-key", "INPUT_AI_MODEL": "gpt-4o-mini"})
    @patch("src.agent.run_triage", return_value=_make_triage())
    @patch("src.agent.create_triage_agent")
    def test_trace_with_mocked_analyzer(
        self, mock_create_triage, mock_run_triage,
    ):
        engine = DecisionEngine()
        raw = [_make_finding(Severity.HIGH, rule_id="trace.rule")]
        tr = _make_tool_result(raw)
        engine._run_analyzer = MagicMock(
            return_value=([tr], _empty_analysis(), {"run_semgrep": 2, "fetch_pr_diff": 1}),
        )

        ctx = _make_context(mode="enforce")
        decision = engine.decide(ctx)

        assert len(decision.trace) == 3
        analyzer_trace = [t for t in decision.trace if "OODA" in t.name][0]
        assert analyzer_trace.tools_used == {"run_semgrep": 2, "fetch_pr_diff": 1}
        assert "1 raw" in analyzer_trace.summary


# --- B2: Triage context summary print ---

class TestTriageContextSummary:
    """Tests for the triage context one-liner printed after AI triage."""

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.agent.run_triage")
    @patch("src.agent.create_triage_agent")
    def test_prints_context_summary(self, mock_agent, mock_run, capsys):
        mock_run.return_value = _make_triage(
            context={
                "languages": ["python", "javascript"],
                "files_changed": 5,
                "risk_areas": ["authentication", "api_handlers"],
                "has_dependency_changes": False,
                "has_iac_changes": False,
                "change_summary": "Auth changes",
            },
        )
        engine = DecisionEngine()
        engine._run_triage(_make_context())
        out = capsys.readouterr().out
        assert "5 file(s)" in out
        assert "python, javascript" in out
        assert "authentication, api_handlers" in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.agent.run_triage")
    @patch("src.agent.create_triage_agent")
    def test_empty_context_defaults(self, mock_agent, mock_run, capsys):
        mock_run.return_value = _make_triage(
            context={
                "languages": [],
                "files_changed": 0,
                "risk_areas": [],
                "has_dependency_changes": False,
                "has_iac_changes": False,
                "change_summary": "",
            },
        )
        engine = DecisionEngine()
        engine._run_triage(_make_context())
        out = capsys.readouterr().out
        assert "0 file(s)" in out
        assert "unknown" in out
        assert "none detected" in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.agent.run_triage")
    @patch("src.agent.create_triage_agent")
    def test_decision_line_printed(self, mock_agent, mock_run, capsys):
        """Triage decision line shows recommended agents."""
        mock_run.return_value = _make_triage(
            recommended_agents=["appsec"],
        )
        engine = DecisionEngine()
        engine._run_triage(_make_context())
        out = capsys.readouterr().out
        assert "decision: appsec" in out


# --- A4 + B3: Semgrep diagnostics + Agent findings table ---

class TestAnalyzerDiagnosticsPrint:
    """Tests for Semgrep diagnostics and agent findings table in _run_analyzer()."""

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_semgrep_diagnostics_basic(self, mock_agent, mock_run, capsys):
        """Prints scan count and findings count."""
        mock_run.return_value = {
            "confirmed": [],
            "dismissed": [],
            "summary": "Clean",
            "findings_analyzed": 0,
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        engine = DecisionEngine()
        triage = _make_triage()
        ctx = _make_context()

        # Need to mock the tool objects — they're created inside _run_analyzer
        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 2
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = ["p/python"]
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st

            mock_dt = MagicMock()
            mock_dt._call_count = 1
            MockDiff.return_value = mock_dt

            engine._run_analyzer(ctx, triage)
            out = capsys.readouterr().out
            assert "Semgrep: 2 scan(s), 0 finding(s)" in out
            assert "PR diff: 1 call(s)" in out
            assert "Analysis: 0 analyzed" in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_analysis_breakdown_printed(self, mock_agent, mock_run, capsys):
        """Prints agent analysis breakdown (confirmed/dismissed counts)."""
        mock_run.return_value = {
            "confirmed": [
                {"rule_id": "r1", "severity": "HIGH",
                 "reason": "SQL injection found"},
                {"rule_id": "r2", "severity": "MEDIUM",
                 "reason": "Path traversal"},
            ],
            "dismissed": [
                {"rule_id": "r3", "reason": "false positive"},
            ],
            "summary": "Found issues",
            "findings_analyzed": 5,
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        engine = DecisionEngine()
        triage = _make_triage()
        ctx = _make_context()

        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st

            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(ctx, triage)
            out = capsys.readouterr().out
            assert "Analysis: 5 analyzed" in out
            assert "2 vulnerabilities confirmed," in out
            assert "1 dismissed" in out
            # Agent reasoning (short rule, no severity labels)
            assert "Confirmed:" in out
            assert "- r1: SQL injection found" in out
            assert "- r2: Path traversal" in out
            assert "Dismissed:" in out
            assert "- r3: false positive" in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_agent_reasoning_with_reasons(self, mock_agent, mock_run, capsys):
        """Prints agent reasoning with truncated reasons."""
        long_reason = "A" * 200
        mock_run.return_value = {
            "confirmed": [
                {"rule_id": "sql-injection", "severity": "high",
                 "reason": "User input in SQL query"},
            ],
            "dismissed": [
                {"rule_id": "noise-rule",
                 "reason": long_reason},
            ],
            "summary": "Found issues",
            "findings_analyzed": 3,
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        engine = DecisionEngine()
        triage = _make_triage()
        ctx = _make_context()

        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st

            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(ctx, triage)
            out = capsys.readouterr().out
            assert "Confirmed:" in out
            assert "- sql-injection: User input in SQL query" in out
            assert "Dismissed:" in out
            assert "- noise-rule:" in out
            # Long reason truncated at word boundary
            assert "..." in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_agent_reasoning_no_dismissed(self, mock_agent, mock_run, capsys):
        """No Dismissed section when agent dismisses nothing."""
        mock_run.return_value = {
            "confirmed": [
                {"rule_id": "xss", "severity": "medium",
                 "reason": "Reflected XSS"},
            ],
            "dismissed": [],
            "summary": "Found XSS",
            "findings_analyzed": 1,
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        engine = DecisionEngine()
        triage = _make_triage()
        ctx = _make_context()

        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st

            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(ctx, triage)
            out = capsys.readouterr().out
            assert "Confirmed:" in out
            assert "- xss: Reflected XSS" in out
            assert "Dismissed:" not in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_semgrep_errors_printed(self, mock_agent, mock_run, capsys):
        """Prints Semgrep scan errors when present."""
        mock_run.return_value = {
            "confirmed": [],
            "dismissed": [],
            "summary": "Errors occurred",
            "findings_analyzed": 0,
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        engine = DecisionEngine()
        triage = _make_triage()
        ctx = _make_context()

        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = [
                {"message": "Failed to download p/python"},
                {"message": "Network timeout"},
            ]
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st

            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(ctx, triage)
            out = capsys.readouterr().out
            assert "Semgrep errors (2):" in out
            assert "Failed to download p/python" in out
            assert "Network timeout" in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_agent_findings_table_confirmed(self, mock_agent, mock_run, capsys):
        """Prints confirmed findings table."""
        mock_run.return_value = {
            "confirmed": [
                {"rule_id": "sql-injection", "severity": "HIGH",
                 "path": "app.py", "line": 12},
                {"rule_id": "xss", "severity": "MEDIUM",
                 "path": "app.py", "line": 26},
            ],
            "dismissed": [],
            "summary": "Found issues",
            "findings_analyzed": 2,
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        engine = DecisionEngine()
        triage = _make_triage()
        ctx = _make_context()

        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st

            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(ctx, triage)
            out = capsys.readouterr().out
            # Agent findings table was moved to Smart Gate (_apply_gate)
            # _run_analyzer now only shows essential diagnostics
            assert "Semgrep: 1 scan(s)" in out
            assert "WARNING: Semgrep ran but found 0 findings" in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_no_findings_table_when_empty(self, mock_agent, mock_run, capsys):
        """No findings table when both confirmed and dismissed are empty."""
        mock_run.return_value = {
            "confirmed": [],
            "dismissed": [],
            "summary": "Clean",
            "findings_analyzed": 0,
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        engine = DecisionEngine()
        triage = _make_triage()
        ctx = _make_context()

        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 0
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st

            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(ctx, triage)
            out = capsys.readouterr().out
            assert "Agent findings" not in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_configs_used_printed(self, mock_agent, mock_run, capsys):
        """When agent used configs, they appear in diagnostics."""
        mock_run.return_value = {
            "confirmed": [], "dismissed": [], "summary": "OK",
            "findings_analyzed": 0, "rulesets_used": [],
            "rulesets_rationale": "", "risk_assessment": "",
        }
        engine = DecisionEngine()
        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = ["p/security-audit", "p/python"]
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/github/workspace"
            MockSemgrep.return_value = mock_st
            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(_make_context(), _make_triage())
            out = capsys.readouterr().out
            assert "Configs: p/security-audit, p/python" in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_no_configs_shows_warning(self, mock_agent, mock_run, capsys):
        """When _all_configs_used is empty, warning printed."""
        mock_run.return_value = {
            "confirmed": [], "dismissed": [], "summary": "OK",
            "findings_analyzed": 0, "rulesets_used": [],
            "rulesets_rationale": "", "risk_assessment": "",
        }
        engine = DecisionEngine()
        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 0
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test/workspace"
            MockSemgrep.return_value = mock_st
            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(_make_context(), _make_triage())
            out = capsys.readouterr().out
            # When configs empty, no Configs line printed
            assert "Configs:" not in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_debug_diagnostics_when_zero_findings(
        self, mock_agent, mock_run, capsys,
    ):
        """Debug diagnostics shown when Semgrep ran but found 0 findings."""
        mock_run.return_value = {
            "confirmed": [], "dismissed": [], "summary": "OK",
            "findings_analyzed": 0, "rulesets_used": [],
            "rulesets_rationale": "", "risk_assessment": "",
        }
        engine = DecisionEngine()
        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = ["p/python"]
            mock_st._last_cmd = [
                "semgrep", "--json", "--quiet",
                "--config", "p/python", "/ws",
            ]
            mock_st._last_files_scanned = []
            mock_st._last_stderr = "Downloading config..."
            mock_st.workspace_path = "/ws"
            MockSemgrep.return_value = mock_st
            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(_make_context(), _make_triage())
            out = capsys.readouterr().out
            assert "WARNING: Semgrep ran but found 0 findings" in out
            assert "Command: semgrep --json" in out
            assert "Files scanned: 0" in out
            assert "Stderr: Downloading config..." in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_no_debug_when_findings_found(
        self, mock_agent, mock_run, capsys,
    ):
        """Debug diagnostics NOT shown when Semgrep found findings."""
        from src.models import Finding, Severity
        mock_run.return_value = {
            "confirmed": [], "dismissed": [], "summary": "OK",
            "findings_analyzed": 0, "rulesets_used": [],
            "rulesets_rationale": "", "risk_assessment": "",
        }
        engine = DecisionEngine()
        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = [
                Finding(
                    tool="semgrep", rule_id="xss",
                    severity=Severity.HIGH,
                    path="app.py", line=10, message="xss",
                ),
            ]
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = ["p/python"]
            mock_st._last_cmd = ["semgrep", "--json"]
            mock_st._last_files_scanned = ["app.py"]
            mock_st._last_stderr = "some stderr"
            mock_st.workspace_path = "/ws"
            MockSemgrep.return_value = mock_st
            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(_make_context(), _make_triage())
            out = capsys.readouterr().out
            assert "WARNING: Semgrep ran but found 0" not in out
            assert "Command:" not in out
            assert "Stderr:" not in out

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_workspace_listing_in_debug(
        self, mock_agent, mock_run, capsys, tmp_path,
    ):
        """Workspace listing included in debug mode (0 findings)."""
        mock_run.return_value = {
            "confirmed": [], "dismissed": [], "summary": "OK",
            "findings_analyzed": 0, "rulesets_used": [],
            "rulesets_rationale": "", "risk_assessment": "",
        }
        (tmp_path / "app.py").write_text("x")
        (tmp_path / "readme.md").write_text("y")
        engine = DecisionEngine()
        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 1
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = ["p/python"]
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = str(tmp_path)
            MockSemgrep.return_value = mock_st
            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine._run_analyzer(_make_context(), _make_triage())
            out = capsys.readouterr().out
            assert "Workspace (2 files):" in out
            assert "app.py" in out


# --- B3b: Observability — step callbacks wired ---


class TestObservabilityWiring:
    """Tests that decision_engine passes step callbacks to agents."""

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.observability.make_step_logger")
    @patch("src.agent.run_triage")
    @patch("src.agent.create_triage_agent")
    def test_triage_passes_step_callback(
        self, mock_create, mock_run, mock_logger,
    ):
        """_run_triage creates and passes step callback to triage agent."""
        mock_cb = MagicMock()
        mock_logger.return_value = mock_cb
        mock_run.return_value = _make_triage()

        with patch("src.tools.FetchPRFilesTool"):
            engine = DecisionEngine()
            engine._run_triage(_make_context())

        mock_logger.assert_called_once()
        call_args = mock_logger.call_args
        assert call_args[0][0] == "Triage"  # agent_name
        assert call_args[1]["max_seconds"] == 120

        mock_create.assert_called_once()
        create_kwargs = mock_create.call_args[1]
        assert create_kwargs["step_callbacks"] == [mock_cb]

    @patch.dict("os.environ", {"INPUT_AI_API_KEY": "k", "INPUT_AI_MODEL": "m"})
    @patch("src.observability.make_step_logger")
    @patch("src.analyzer_agent.run_analyzer")
    @patch("src.analyzer_agent.create_analyzer_agent")
    def test_analyzer_passes_step_callback(
        self, mock_create, mock_run, mock_logger, capsys,
    ):
        """_run_analyzer creates and passes step callback to analyzer agent."""
        mock_cb = MagicMock()
        mock_logger.return_value = mock_cb
        mock_run.return_value = {
            "confirmed": [], "dismissed": [], "summary": "OK",
            "findings_analyzed": 0, "rulesets_used": [],
            "rulesets_rationale": "", "risk_assessment": "",
        }

        with patch("src.tools.SemgrepTool") as MockSemgrep, \
             patch("src.tools.FetchPRDiffTool") as MockDiff:
            mock_st = MagicMock()
            mock_st._call_count = 0
            mock_st._all_raw_findings = []
            mock_st._all_scan_errors = []
            mock_st._all_configs_used = []
            mock_st._last_cmd = []
            mock_st._last_files_scanned = []
            mock_st._last_stderr = ""
            mock_st.workspace_path = "/test"
            MockSemgrep.return_value = mock_st
            mock_dt = MagicMock()
            mock_dt._call_count = 0
            MockDiff.return_value = mock_dt

            engine = DecisionEngine()
            engine._run_analyzer(_make_context(), _make_triage())

        mock_logger.assert_called_once()
        call_args = mock_logger.call_args
        assert call_args[0][0] == "AppSec"
        assert call_args[1]["max_seconds"] == 600

        mock_create.assert_called_once()
        create_kwargs = mock_create.call_args[1]
        assert create_kwargs["step_callbacks"] == [mock_cb]


# --- B4: Smart Gate always-visible summary ---

class TestSmartGateSummaryPrint:
    """Tests for the Smart Gate summary printed in _apply_gate()."""

    def _gate(self, findings, analysis, mode="enforce"):
        engine = DecisionEngine()
        tr = _make_tool_result(findings)
        return engine._apply_gate(
            _make_context(mode=mode), _make_triage(), [tr], analysis,
        )

    def test_mode_always_printed(self, capsys):
        """Mode is always printed in the gate summary."""
        self._gate([], _empty_analysis(), mode="shadow")
        out = capsys.readouterr().out
        assert "Mode: shadow" in out

    def test_no_warning_when_clean(self, capsys):
        """No warning when both scanner and agent find nothing."""
        self._gate([], _empty_analysis(), mode="shadow")
        out = capsys.readouterr().out
        assert "Warning:" not in out

    def test_hallucination_warning_printed(self, capsys):
        """Warning printed when agent confirmed but none matched scanner."""
        analysis = {
            "confirmed": [
                {"rule_id": "ghost1", "severity": "HIGH"},
                {"rule_id": "ghost2", "severity": "MEDIUM"},
            ],
            "dismissed": [],
            "findings_analyzed": 2,
            "summary": "found",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        self._gate([], analysis, mode="shadow")
        out = capsys.readouterr().out
        assert "agent confirmed 2 finding(s)" in out
        assert "none matched scanner results" in out

    def test_gate_summary_with_safety_net(self, capsys):
        """Gate summary shows confirmed + safety-net breakdown."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="r1"),
            _make_finding(Severity.HIGH, rule_id="r2"),
        ]
        analysis = {
            "confirmed": [{"rule_id": "r1", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
            "summary": "found",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        self._gate(raw, analysis, mode="enforce")
        out = capsys.readouterr().out
        assert "Gate: 2 finding(s)" in out
        assert "1 from 1 confirmed rules + 1 safety-net" in out

    def test_findings_table_printed(self, capsys):
        """Findings table printed with all raw findings and verdicts."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="sql.injection",
                          path="app.py", line=10),
            _make_finding(Severity.LOW, rule_id="style.lint",
                          path="util.py", line=5),
        ]
        analysis = {
            "confirmed": [
                {"rule_id": "sql.injection", "severity": "HIGH",
                 "reason": "SQL injection found"},
            ],
            "dismissed": [
                {"rule_id": "style.lint", "severity": "LOW",
                 "reason": "Not security-relevant"},
            ],
            "findings_analyzed": 2,
            "summary": "found",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        self._gate(raw, analysis, mode="shadow")
        out = capsys.readouterr().out
        assert "Findings table" in out
        assert "injection" in out
        assert "confirmed" in out
        assert "dismissed" in out
        assert "Summary:" in out

    def test_noise_shows_not_analyzed(self, capsys):
        """Noise findings show 'not analyzed by agent' as reason."""
        raw = [_make_finding(Severity.LOW, rule_id="noise.rule",
                             path="x.py", line=1)]
        self._gate(raw, _empty_analysis(), mode="shadow")
        out = capsys.readouterr().out
        assert "not analyzed by agent" in out

    def test_dismissed_shows_agent_reason(self, capsys):
        """Dismissed findings show agent's dismissal reason in table."""
        raw = [
            _make_finding(Severity.MEDIUM, rule_id="style.rule",
                          path="app.py", line=5),
        ]
        analysis = {
            "confirmed": [],
            "dismissed": [
                {"rule_id": "style.rule", "severity": "MEDIUM",
                 "reason": "duplicate: covered by sql-injection at same line"},
            ],
            "findings_analyzed": 1,
            "summary": "clean",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        self._gate(raw, analysis, mode="shadow")
        out = capsys.readouterr().out
        assert "duplicate: covered by sql-injection" in out
        assert "dismissed" in out

    def test_safety_net_has_default_reason(self, capsys):
        """Safety-net findings show default reason in table."""
        raw = [_make_finding(Severity.HIGH, rule_id="missed.rule",
                             path="x.py", line=1)]
        analysis = {
            "confirmed": [],
            "dismissed": [],
            "findings_analyzed": 1,
            "summary": "clean",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        self._gate(raw, analysis, mode="enforce")
        out = capsys.readouterr().out
        assert "HIGH/CRITICAL not confirmed by agent" in out

    def test_shadow_reason_has_severity_breakdown(self, capsys):
        """Shadow mode reason includes severity breakdown."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="r1"),
            _make_finding(Severity.LOW, rule_id="r2"),
        ]
        analysis = {
            "confirmed": [{"rule_id": "r1", "severity": "HIGH"},
                          {"rule_id": "r2", "severity": "LOW"}],
            "dismissed": [],
            "findings_analyzed": 2,
            "summary": "found",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        d = self._gate(raw, analysis, mode="shadow")
        assert "1 high" in d.reason
        assert "1 low" in d.reason
        assert "Shadow mode:" in d.reason

    def test_findings_count_includes_safety_net(self, capsys):
        """findings_count includes both confirmed and safety-net findings."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="r1"),
            _make_finding(Severity.HIGH, rule_id="r2"),
            _make_finding(Severity.HIGH, rule_id="r3"),
        ]
        analysis = {
            "confirmed": [{"rule_id": "r1", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
            "summary": "found",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        d = self._gate(raw, analysis, mode="shadow")
        # 1 confirmed + 2 safety-net = 3 total
        assert d.findings_count == 3

    def test_confirmed_structured_has_source_field(self, capsys):
        """confirmed_findings entries have 'source' field."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="r1"),
            _make_finding(Severity.HIGH, rule_id="r2"),
        ]
        analysis = {
            "confirmed": [{"rule_id": "r1", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
            "summary": "found",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        d = self._gate(raw, analysis, mode="shadow")
        sources = {f["source"] for f in d.confirmed_findings}
        assert "confirmed" in sources
        assert "safety-net" in sources

    def test_safety_net_critical_blocks_enforce(self, capsys):
        """Safety-net CRITICAL finding → BLOCKED in enforce mode."""
        raw = [
            _make_finding(Severity.CRITICAL, rule_id="critical.vuln"),
        ]
        # Agent analyzed but missed the CRITICAL
        analysis = {
            "confirmed": [],
            "dismissed": [],
            "findings_analyzed": 1,
            "summary": "clean",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        d = self._gate(raw, analysis, mode="enforce")
        assert d.verdict == Verdict.BLOCKED
        assert d.findings_count == 1
        assert d.confirmed_findings[0]["source"] == "safety-net"

    def test_safety_net_high_manual_review_enforce(self, capsys):
        """Safety-net HIGH finding → MANUAL_REVIEW in enforce mode."""
        raw = [
            _make_finding(Severity.HIGH, rule_id="high.vuln"),
        ]
        # Agent analyzed but missed the HIGH
        analysis = {
            "confirmed": [],
            "dismissed": [],
            "findings_analyzed": 1,
            "summary": "clean",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        d = self._gate(raw, analysis, mode="enforce")
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.findings_count == 1

    def test_gate_summary_zero_safety_net(self, capsys):
        """Gate summary shows 0 safety-net when none present."""
        raw = [_make_finding(Severity.HIGH, rule_id="r1")]
        analysis = {
            "confirmed": [{"rule_id": "r1", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
            "summary": "found",
            "rulesets_used": [],
            "rulesets_rationale": "",
            "risk_assessment": "",
        }
        self._gate(raw, analysis, mode="shadow")
        out = capsys.readouterr().out
        assert "Gate: 1 finding(s)" in out
        assert "1 from 1 confirmed rules + 0 safety-net" in out
