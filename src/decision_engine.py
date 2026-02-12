"""
Decision engine — orchestrates multi-agent pipeline + deterministic gate.

Architecture:
  1. Triage Agent (AI) → provides context about PR changes
  2. AppSec Agent (AI) → decides rulesets, runs tools, analyzes findings
  3. Gate (Python code, not hackable) → final verdict

Security (llm-security/output-handling — LLM05):
  The gate uses RAW findings from the tool's side channel for its verdict,
  NOT the agent's classifications. The agent's analysis is included in the
  report for human reviewers (the VALUE), but raw findings drive the
  verdict (the SAFETY NET).

  The safety net compares raw findings against agent claims: if the agent
  dismissed HIGH/CRITICAL findings, the gate flags this as a warning.
"""

import os

from src.models import (
    Decision, Finding, Severity, ToolResult, Verdict,
    SEVERITY_ORDER,
)
from src.github_context import GitHubContext


_EMPTY_ANALYSIS = {
    "confirmed": [],
    "dismissed": [],
    "summary": "",
    "findings_analyzed": 0,
    "rulesets_used": [],
    "rulesets_rationale": "",
    "risk_assessment": "",
}


class DecisionEngine:

    def decide(self, ctx: GitHubContext) -> Decision:
        """Main entry point: triage → analyzer → gate → Decision."""
        triage = self._run_triage(ctx)
        tool_results, agent_analysis = self._run_analyzer(ctx, triage)
        return self._apply_gate(ctx, triage, tool_results, agent_analysis)

    def _run_triage(self, ctx: GitHubContext) -> dict:
        """Run AI triage if configured, otherwise return default."""
        api_key = os.environ.get("INPUT_AI_API_KEY", "")
        model_id = os.environ.get("INPUT_AI_MODEL", "gpt-4o-mini")

        if not api_key:
            print("No AI API key configured, using deterministic fallback.")
            return {
                "context": {
                    "languages": [],
                    "files_changed": 0,
                    "risk_areas": [],
                    "has_dependency_changes": False,
                    "has_iac_changes": False,
                    "change_summary": "No AI configured, using defaults.",
                },
                "recommended_agents": ["appsec"],
                "reason": "No AI configured, running default agent.",
            }

        try:
            from src.agent import create_triage_agent, run_triage
            from src.tools import FetchPRFilesTool

            print(f"Running AI triage (model: {model_id})...")

            tools = []
            if ctx.token and ctx.repository and ctx.pr_number:
                tools.append(
                    FetchPRFilesTool(
                        github_token=ctx.token,
                        repository=ctx.repository,
                    )
                )

            agent = create_triage_agent(api_key, model_id, tools=tools)
            result = run_triage(agent, ctx)
            print(f"AI triage complete: {result['reason']}")
            return result
        except Exception as e:
            print(f"::warning::AI triage failed: {e}")
            print("Falling back to deterministic mode.")
            return {
                "context": {
                    "languages": [],
                    "files_changed": 0,
                    "risk_areas": [],
                    "has_dependency_changes": False,
                    "has_iac_changes": False,
                    "change_summary": "Triage failed, using defaults.",
                },
                "recommended_agents": ["appsec"],
                "reason": "AI error, using fallback.",
            }

    def _run_analyzer(
        self, ctx: GitHubContext, triage: dict,
    ) -> tuple[list[ToolResult], dict]:
        """Run the AppSec Agent and return (raw_tool_results, agent_analysis).

        Security (LLM05 — untrusted output handling):
        Raw findings come from the tool's side channel, NOT from the agent.
        The agent's analysis is returned separately for the gate to compare.

        Security (LLM06 — excessive agency):
        SemgrepTool has built-in guardrails (allowlist, workspace, timeout).
        """
        api_key = os.environ.get("INPUT_AI_API_KEY", "")
        model_id = os.environ.get("INPUT_AI_MODEL", "gpt-4o-mini")

        if not api_key:
            print("No AI API key — skipping analyzer.")
            return [], dict(_EMPTY_ANALYSIS)

        agents = triage.get("recommended_agents", [])
        if "appsec" not in agents:
            print("AppSec agent not recommended by triage, skipping.")
            return [], dict(_EMPTY_ANALYSIS)

        try:
            from src.analyzer_agent import create_analyzer_agent, run_analyzer
            from src.tools import SemgrepTool

            print("Running AppSec Agent...")

            # Create tool — we keep the reference for the side channel
            semgrep_tool = SemgrepTool(workspace_path=ctx.workspace)

            agent = create_analyzer_agent(
                api_key, model_id, tools=[semgrep_tool],
            )
            analysis = run_analyzer(agent, triage)
            print(f"AppSec Agent complete: {analysis.get('summary', 'N/A')}")

            # SIDE CHANNEL: read raw findings from the tool, not the agent
            raw_findings = semgrep_tool._last_raw_findings
            config_used = semgrep_tool._last_config_used
            tool_error = semgrep_tool._last_error

            tool_success = len(raw_findings) > 0 or (not tool_error)

            tool_results = [ToolResult(
                tool="semgrep",
                success=tool_success,
                findings=raw_findings,
                config_used=config_used,
                error=tool_error,
            )]

            return tool_results, analysis

        except Exception as e:
            print(f"::warning::AppSec Agent failed: {e}")
            return [ToolResult(
                tool="semgrep",
                success=False,
                findings=[],
                error=str(e),
            )], dict(_EMPTY_ANALYSIS)

    def _check_agent_dismissals(
        self,
        raw_findings: list[Finding],
        agent_analysis: dict,
    ) -> list[dict]:
        """Compare agent dismissals against raw findings.

        Returns a list of safety warnings for dismissed or unaccounted
        HIGH/CRITICAL findings.

        Security (LLM05 — untrusted output):
        The agent cannot silently dismiss dangerous findings. If it does,
        the gate flags it as a warning. LOW/MEDIUM dismissals are allowed
        (the agent can filter noise).
        """
        warnings = []

        dismissed_rule_ids = {
            d["rule_id"] for d in agent_analysis.get("dismissed", [])
            if isinstance(d, dict) and isinstance(d.get("rule_id"), str)
        }

        confirmed_rule_ids = {
            c["rule_id"] for c in agent_analysis.get("confirmed", [])
            if isinstance(c, dict) and isinstance(c.get("rule_id"), str)
        }

        for finding in raw_findings:
            if finding.severity not in (Severity.HIGH, Severity.CRITICAL):
                continue

            if finding.rule_id in dismissed_rule_ids:
                warnings.append({
                    "type": "dismissed_high_severity",
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "path": finding.path,
                    "line": finding.line,
                    "message": (
                        f"Agent dismissed {finding.severity.value} finding "
                        f"{finding.rule_id} at {finding.path}:{finding.line}. "
                        f"Safety net: this finding is included in the verdict."
                    ),
                })
            elif finding.rule_id not in confirmed_rule_ids:
                warnings.append({
                    "type": "unaccounted_high_severity",
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "path": finding.path,
                    "line": finding.line,
                    "message": (
                        f"Agent did not account for {finding.severity.value} "
                        f"finding {finding.rule_id} at "
                        f"{finding.path}:{finding.line}. "
                        f"Safety net: this finding is included in the verdict."
                    ),
                })

        return warnings

    def _build_analysis_report(
        self,
        agent_analysis: dict,
        raw_findings: list[Finding],
        safety_warnings: list[dict],
    ) -> str:
        """Build a human-readable analysis report for reviewers.

        Combines the agent's expert analysis (the VALUE) with raw data
        and safety warnings (the SAFETY NET).
        """
        lines = ["=== AppSec Analysis Report ===\n"]

        # Agent's methodology
        rulesets = agent_analysis.get("rulesets_used", [])
        if rulesets:
            lines.append(f"Rulesets used: {', '.join(rulesets)}")
            rationale = agent_analysis.get("rulesets_rationale", "")
            if rationale:
                lines.append(f"Rationale: {rationale}")
            lines.append("")

        # Raw scan stats
        lines.append(f"Raw findings from scanner: {len(raw_findings)}")
        confirmed = agent_analysis.get("confirmed", [])
        dismissed = agent_analysis.get("dismissed", [])
        lines.append(f"Agent confirmed: {len(confirmed)}")
        lines.append(f"Agent dismissed: {len(dismissed)}")
        lines.append("")

        # Safety warnings
        if safety_warnings:
            lines.append("*** SAFETY WARNINGS ***")
            for w in safety_warnings:
                lines.append(f"  [{w['severity']}] {w['message']}")
            lines.append("")

        # Confirmed findings detail
        if confirmed:
            lines.append("--- Confirmed Findings ---")
            for c in confirmed:
                lines.append(
                    f"  [{c.get('severity', '?')}] {c.get('rule_id', '?')} "
                    f"at {c.get('path', '?')}:{c.get('line', '?')}"
                )
                if c.get("reason"):
                    lines.append(f"    Analysis: {c['reason']}")
                if c.get("recommendation"):
                    lines.append(f"    Fix: {c['recommendation']}")
            lines.append("")

        # Dismissed findings detail
        if dismissed:
            lines.append("--- Dismissed Findings ---")
            for d in dismissed:
                lines.append(
                    f"  {d.get('rule_id', '?')} — {d.get('reason', 'no reason')}"
                )
            lines.append("")

        # Agent summary
        summary = agent_analysis.get("summary", "")
        if summary:
            lines.append(f"Summary: {summary}")

        risk = agent_analysis.get("risk_assessment", "")
        if risk:
            lines.append(f"Risk Assessment: {risk}")

        return "\n".join(lines)

    def _apply_gate(
        self,
        ctx: GitHubContext,
        triage: dict,
        tool_results: list[ToolResult],
        agent_analysis: dict,
    ) -> Decision:
        """Deterministic gate with safety net against agent manipulation.

        Security (LLM05 — untrusted output handling):
        - Verdict is based on RAW findings from tool side channel
        - Agent analysis is VALUE (explains, prioritizes, recommends fixes)
        - Safety net detects agent dismissal of HIGH/CRITICAL findings

        Enforce mode policy:
        - CRITICAL findings → auto-BLOCKED
        - Any findings → MANUAL_REVIEW (human decides with full report)
        - Clean scan → ALLOWED
        - Tool failure → MANUAL_REVIEW
        """
        ai_reason = triage.get("reason", "")

        # Aggregate RAW findings from all tool results
        all_findings: list[Finding] = []
        for tr in tool_results:
            all_findings.extend(tr.findings)

        # Run safety net comparison
        safety_warnings = self._check_agent_dismissals(
            all_findings, agent_analysis,
        )
        if safety_warnings:
            for w in safety_warnings:
                print(f"::warning::Safety net: {w['message']}")

        # Build analysis report for human reviewers
        analysis_report = self._build_analysis_report(
            agent_analysis, all_findings, safety_warnings,
        )

        # Determine max severity from RAW findings
        max_severity = Severity.NONE
        for f in all_findings:
            if SEVERITY_ORDER.index(f.severity) > SEVERITY_ORDER.index(max_severity):
                max_severity = f.severity

        # Count by severity
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in all_findings:
            counts[f.severity] += 1

        findings_count = len(all_findings)

        # Shadow mode: always allow, but report everything
        if ctx.mode == "shadow":
            if findings_count > 0:
                print(
                    f"[Shadow] {findings_count} finding(s), "
                    f"max severity: {max_severity.value}"
                )
            return Decision(
                verdict=Verdict.ALLOWED,
                continue_pipeline=True,
                max_severity=max_severity,
                selected_tools=["semgrep"],
                reason=(
                    f"Shadow mode: {findings_count} finding(s). "
                    f"Triage: {ai_reason}"
                ),
                mode=ctx.mode,
                findings_count=findings_count,
                tool_results=tool_results,
                analysis_report=analysis_report,
                safety_warnings=safety_warnings,
            )

        # Enforce mode — verdict based on RAW findings
        if counts.get(Severity.CRITICAL, 0) > 0:
            verdict = Verdict.BLOCKED
            continue_pipeline = False
            reason = (
                f"BLOCKED — {counts[Severity.CRITICAL]} critical finding(s). "
                f"Auto-blocked per policy."
            )
        elif findings_count > 0:
            # Any findings → human must review
            severity_parts = []
            for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
                if counts.get(sev, 0) > 0:
                    severity_parts.append(
                        f"{counts[sev]} {sev.value}"
                    )
            severity_breakdown = ", ".join(severity_parts)
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — {findings_count} finding(s) "
                f"({severity_breakdown}). Human approval required."
            )
        elif any(not tr.success for tr in tool_results):
            failed = [tr.tool for tr in tool_results if not tr.success]
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — tool(s) failed: {', '.join(failed)}. "
                f"Triage: {ai_reason}"
            )
        elif not tool_results:
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — no tool results available. "
                f"Triage: {ai_reason}"
            )
        else:
            verdict = Verdict.ALLOWED
            continue_pipeline = True
            reason = (
                f"Clean scan, no findings. Triage: {ai_reason}"
            )

        # Append safety warning note to reason
        if safety_warnings:
            reason += (
                f" [{len(safety_warnings)} safety warning(s) — see report]"
            )

        return Decision(
            verdict=verdict,
            continue_pipeline=continue_pipeline,
            max_severity=max_severity,
            selected_tools=["semgrep"],
            reason=reason,
            mode=ctx.mode,
            findings_count=findings_count,
            tool_results=tool_results,
            analysis_report=analysis_report,
            safety_warnings=safety_warnings,
        )
