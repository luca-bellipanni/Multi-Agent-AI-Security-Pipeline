"""
Decision engine — orchestrates multi-agent OODA pipeline + smart gate.

Architecture:
  1. Triage Agent (AI) → provides context about PR changes
  2. AppSec Agent (AI, OODA loop) → observes diff, decides rulesets, runs
     tools (possibly multiple times), analyzes findings in context
  3. Smart Gate (Python code, not hackable) → final verdict

Security (llm-security/output-handling — LLM05):
  The gate uses CONFIRMED findings (validated against raw side channel)
  for its verdict. The agent is the decision-maker, but always checked:

  - Anti-hallucination: confirmed rule_ids must exist in raw findings
  - Anti-severity-manipulation: severity comes from raw, not agent claims
  - Safety net: dismissed/unaccounted HIGH/CRITICAL → force MANUAL_REVIEW
  - Fail-secure: if agent analysis is empty/unparseable → fallback to raw
"""

import os

from src.models import (
    Decision, Finding, Severity, ToolResult, Verdict,
    SEVERITY_ORDER,
)
from src.github_context import GitHubContext
from src.memory import MemoryStore


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

    _memory_store: MemoryStore | None = None

    def decide(self, ctx: GitHubContext) -> Decision:
        """Main entry point: triage → analyzer → gate → Decision."""
        triage = self._run_triage(ctx)
        tool_results, agent_analysis = self._run_analyzer(ctx, triage)
        return self._apply_gate(ctx, triage, tool_results, agent_analysis)

    def save_memory(self) -> None:
        """Save exception memory to disk (called by main.py after decide)."""
        if self._memory_store is not None:
            self._memory_store.save()

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
        """Run the AppSec Agent (OODA loop) and return (raw_tool_results, agent_analysis).

        Security (LLM05 — untrusted output handling):
        Raw findings come from the tool's CUMULATIVE side channel, NOT
        from the agent. The cumulative channel captures findings from ALL
        tool calls (the agent may call run_semgrep multiple times).

        Security (LLM06 — excessive agency):
        SemgrepTool has built-in guardrails (allowlist, workspace, timeout).
        FetchPRDiffTool has PR number injected and output size limits.
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
            from src.tools import FetchPRDiffTool, SemgrepTool

            print("Running AppSec Agent (OODA loop)...")

            # Create tools — we keep semgrep_tool ref for the side channel
            semgrep_tool = SemgrepTool(workspace_path=ctx.workspace)
            tools = [semgrep_tool]

            # Observe tool: only if PR context available (LLM06)
            if ctx.token and ctx.repository and ctx.pr_number:
                diff_tool = FetchPRDiffTool(
                    github_token=ctx.token,
                    repository=ctx.repository,
                    pr_number=ctx.pr_number,
                )
                tools.append(diff_tool)

            agent = create_analyzer_agent(
                api_key, model_id, tools=tools,
            )
            analysis = run_analyzer(agent, triage)
            print(f"AppSec Agent complete: {analysis.get('summary', 'N/A')}")

            # CUMULATIVE SIDE CHANNEL: read ALL findings from ALL tool calls
            raw_findings = semgrep_tool._all_raw_findings
            config_used = semgrep_tool._all_configs_used
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

    def _agent_has_analyzed(self, agent_analysis: dict) -> bool:
        """Check if the agent produced a real analysis (not empty/failed parse).

        If False, the gate falls back to raw-based verdict (fail-secure).
        This ensures that when AI is not configured or the response is
        unparseable, the gate defaults to the conservative raw-based approach.
        """
        return (
            agent_analysis.get("findings_analyzed", 0) > 0
            or len(agent_analysis.get("confirmed", [])) > 0
            or len(agent_analysis.get("dismissed", [])) > 0
        )

    def _validate_agent_confirmed(
        self,
        raw_findings: list[Finding],
        agent_analysis: dict,
    ) -> list[Finding]:
        """Cross-reference agent confirmed against raw findings.

        Security (LLM05 — anti-hallucination):
        - Only raw findings that the agent explicitly confirmed count
        - Severity comes from the raw finding, not the agent's claim
        - If agent hallucinates a finding, it's silently dropped

        Returns raw Finding objects for confirmed rule_ids.
        """
        confirmed_rule_ids = {
            c["rule_id"] for c in agent_analysis.get("confirmed", [])
            if isinstance(c, dict) and isinstance(c.get("rule_id"), str)
        }
        return [f for f in raw_findings if f.rule_id in confirmed_rule_ids]

    def _build_analysis_report(
        self,
        agent_analysis: dict,
        raw_findings: list[Finding],
        safety_warnings: list[dict],
        effective_findings: list[Finding] | None = None,
        excepted_info: list[dict] | None = None,
    ) -> str:
        """Build a human-readable analysis report for reviewers.

        Combines the agent's expert analysis (the VALUE) with raw data,
        effective findings (what drives the verdict), and safety warnings.
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

        # Raw scan stats + effective findings
        lines.append(f"Raw findings from scanner: {len(raw_findings)}")
        confirmed = agent_analysis.get("confirmed", [])
        dismissed = agent_analysis.get("dismissed", [])
        lines.append(f"Agent confirmed: {len(confirmed)}")
        lines.append(f"Agent dismissed: {len(dismissed)}")
        if effective_findings is not None:
            lines.append(
                f"Effective findings (verdict based on): "
                f"{len(effective_findings)}"
            )
        if excepted_info:
            lines.append(f"Auto-excepted by memory: {len(excepted_info)}")
        lines.append("")

        # Auto-excepted findings detail
        if excepted_info:
            lines.append("--- Auto-Excepted Findings ---")
            for ei in excepted_info:
                lines.append(
                    f"  [{ei['severity']}] {ei['rule_id']} "
                    f"at {ei['path']}:{ei['line']}"
                    f" — {ei['exception_reason']} ({ei['exception_source']})"
                )
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
        """Smart gate: confirmed-based verdicts with safety net.

        Security (LLM05 — untrusted output handling):
        - Verdict is based on CONFIRMED findings (validated against raw)
        - Anti-hallucination: confirmed rule_ids must exist in raw
        - Anti-severity-manipulation: severity comes from raw findings
        - Safety net: dismissed/unaccounted HIGH/CRITICAL → MANUAL_REVIEW
        - Fail-secure: empty/unparseable analysis → fallback to raw

        Enforce mode policy:
        - Safety net triggered → MANUAL_REVIEW (agent dismissed HIGH/CRIT)
        - Confirmed CRITICAL → BLOCKED
        - Confirmed any → MANUAL_REVIEW (human decides with full report)
        - No confirmed → ALLOWED
        - Tool failure → MANUAL_REVIEW
        """
        ai_reason = triage.get("reason", "")

        # Aggregate RAW findings from all tool results
        raw_findings: list[Finding] = []
        for tr in tool_results:
            raw_findings.extend(tr.findings)

        # Exception memory: load, filter, auto-add
        memory_store = MemoryStore(ctx.workspace, ctx.repository)
        memory_warnings = memory_store.load()
        for w in memory_warnings:
            print(f"::warning::Memory: {w}")
        expired_count = memory_store.remove_expired()
        if expired_count:
            print(f"Memory: removed {expired_count} expired exception(s)")

        # Filter findings against exceptions
        # Security (LLM05): HIGH/CRITICAL are NEVER removed
        active_findings, excepted_info = memory_store.filter_findings(
            raw_findings,
        )
        if excepted_info:
            print(f"Memory: {len(excepted_info)} finding(s) auto-excepted")

        # Determine effective findings and safety warnings
        if self._agent_has_analyzed(agent_analysis):
            # Agent produced real analysis → use confirmed (validated vs raw)
            effective_findings = self._validate_agent_confirmed(
                active_findings, agent_analysis,
            )
            # Safety net: only meaningful when agent has analyzed
            safety_warnings = self._check_agent_dismissals(
                active_findings, agent_analysis,
            )
            if safety_warnings:
                for w in safety_warnings:
                    print(f"::warning::Safety net: {w['message']}")
        else:
            # Fail-secure: no analysis → fallback to active findings
            effective_findings = list(active_findings)
            safety_warnings = []

        # Auto-add new exceptions from agent's dismissed LOW/MEDIUM
        if self._agent_has_analyzed(agent_analysis):
            new_exc = memory_store.add_auto_exceptions(
                agent_analysis.get("dismissed", []),
                raw_findings,  # original unfiltered for anti-hallucination
                ctx.pr_number,
            )
            if new_exc:
                print(f"Memory: added {new_exc} new auto-exception(s)")

        self._memory_store = memory_store

        # Build analysis report for human reviewers
        analysis_report = self._build_analysis_report(
            agent_analysis, active_findings, safety_warnings,
            effective_findings, excepted_info,
        )

        # Max severity from EFFECTIVE findings (what drives the verdict)
        max_severity = Severity.NONE
        for f in effective_findings:
            if SEVERITY_ORDER.index(f.severity) > SEVERITY_ORDER.index(max_severity):
                max_severity = f.severity

        # Also track max raw severity for reporting
        max_raw_severity = Severity.NONE
        for f in raw_findings:
            if SEVERITY_ORDER.index(f.severity) > SEVERITY_ORDER.index(max_raw_severity):
                max_raw_severity = f.severity

        # Count effective findings by severity
        eff_counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in effective_findings:
            eff_counts[f.severity] += 1

        findings_count = len(effective_findings)

        excepted_count = len(excepted_info)

        # Shadow mode: always allow, but report everything
        if ctx.mode == "shadow":
            raw_count = len(raw_findings)
            if raw_count > 0:
                print(
                    f"[Shadow] {raw_count} raw finding(s), "
                    f"max severity: {max_raw_severity.value}"
                )
            return Decision(
                verdict=Verdict.ALLOWED,
                continue_pipeline=True,
                max_severity=max_raw_severity,
                selected_tools=["semgrep"],
                reason=(
                    f"Shadow mode: {raw_count} raw finding(s), "
                    f"{findings_count} confirmed. "
                    f"Triage: {ai_reason}"
                ),
                mode=ctx.mode,
                findings_count=findings_count,
                excepted_count=excepted_count,
                tool_results=tool_results,
                analysis_report=analysis_report,
                safety_warnings=safety_warnings,
            )

        # Enforce mode — verdict based on effective findings + safety net

        # 1. Tool failures or missing results → MANUAL_REVIEW
        if not tool_results:
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — no tool results available. "
                f"Triage: {ai_reason}"
            )
        elif any(not tr.success for tr in tool_results):
            failed = [tr.tool for tr in tool_results if not tr.success]
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — tool(s) failed: {', '.join(failed)}. "
                f"Triage: {ai_reason}"
            )
        # 2. Safety net override: agent dismissed/ignored HIGH/CRITICAL
        elif safety_warnings:
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — {len(safety_warnings)} safety warning(s): "
                f"agent dismissed or missed HIGH/CRITICAL "
                f"finding(s). Human review required."
            )
        # 3. Confirmed CRITICAL → auto-BLOCKED
        elif eff_counts.get(Severity.CRITICAL, 0) > 0:
            verdict = Verdict.BLOCKED
            continue_pipeline = False
            reason = (
                f"BLOCKED — {eff_counts[Severity.CRITICAL]} confirmed "
                f"critical finding(s). Auto-blocked per policy."
            )
        # 4. Any confirmed findings → MANUAL_REVIEW
        elif findings_count > 0:
            severity_parts = []
            for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW):
                if eff_counts.get(sev, 0) > 0:
                    severity_parts.append(
                        f"{eff_counts[sev]} {sev.value}"
                    )
            severity_breakdown = ", ".join(severity_parts)
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — {findings_count} confirmed finding(s) "
                f"({severity_breakdown}). Human approval required."
            )
        # 5. No confirmed findings, no safety warnings → ALLOWED
        else:
            verdict = Verdict.ALLOWED
            continue_pipeline = True
            reason = (
                f"Clean: {len(raw_findings)} raw finding(s) analyzed, "
                f"0 confirmed. Triage: {ai_reason}"
            )

        return Decision(
            verdict=verdict,
            continue_pipeline=continue_pipeline,
            max_severity=max_severity,
            selected_tools=["semgrep"],
            reason=reason,
            mode=ctx.mode,
            findings_count=findings_count,
            excepted_count=excepted_count,
            tool_results=tool_results,
            analysis_report=analysis_report,
            safety_warnings=safety_warnings,
        )
