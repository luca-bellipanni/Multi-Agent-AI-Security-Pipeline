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
import re

from src.models import (
    Decision, Finding, Severity, StepTrace, ToolResult, Verdict,
    SEVERITY_ORDER,
)
from src.github_context import GitHubContext
from src.memory import MemoryStore

# Suppress LiteLLM "Give Feedback" / "_turn_on_debug()" console spam.
# Only cosmetic — LLM errors still propagate as exceptions.
try:
    import litellm
    litellm.suppress_debug_info = True
except ImportError:
    pass


_EMPTY_ANALYSIS = {
    "confirmed": [],
    "dismissed": [],
    "summary": "",
    "findings_analyzed": 0,
    "rulesets_used": [],
    "rulesets_rationale": "",
    "risk_assessment": "",
}


_SEMGREP_SEV_ALIASES = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def _normalize_severity(sev: str) -> str:
    """Normalize Semgrep severity aliases to standard labels.

    LLMs sometimes copy Semgrep's native labels (ERROR, WARNING, INFO)
    instead of the standard HIGH/MEDIUM/LOW we request. This mapping
    prevents GitHub Actions from misinterpreting [ERROR] as an annotation.
    """
    upper = sev.upper() if sev else "?"
    return _SEMGREP_SEV_ALIASES.get(upper, upper)


def _truncate_reason(text: str, max_len: int = 80) -> str:
    """Truncate reason at word boundary, ending at sentence if possible."""
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    # Try to end at first sentence
    dot = text.find(".")
    if 0 < dot < max_len:
        return text[:dot + 1]
    # Truncate at word boundary
    cut = text[:max_len].rfind(" ")
    if cut > max_len // 3:
        return text[:cut] + "..."
    return text[:max_len] + "..."


def _shorten_rule_refs(reason: str) -> str:
    """Replace full Semgrep rule IDs in reason text with short names.

    Agent reasons like 'duplicate: same issue covered by rule
    python.flask.security.injection.tainted-sql-string at line 16'
    become 'duplicate: see tainted-sql-string at line 16'.
    """
    def _replacer(m: re.Match) -> str:
        full_rule = m.group(1)
        short = (full_rule.rsplit(".", 1)[-1]
                 if "." in full_rule else full_rule)
        return f"see {short}"

    return re.sub(
        r'(?:same issue covered by |see )?rule\s+([\w][\w.-]+)',
        _replacer, reason,
    )


def _resolve_dup_ids(
    reason: str,
    id_lookup: dict[tuple[str, int], str],
) -> str:
    """Replace duplicate references with finding IDs.

    If reason starts with 'duplicate:', extract rule+line and replace
    entire reason with 'dup Fxxxxxx'.
    """
    if not reason.strip().lower().startswith("duplicate"):
        return reason
    m = re.search(r'([\w][\w.-]+)\s+at\s+(?:line\s+)?(?:\S+:)?(\d+)', reason)
    if not m:
        return reason
    ref_rule = m.group(1)
    ref_line = int(m.group(2))
    short = (ref_rule.rsplit(".", 1)[-1]
             if "." in ref_rule else ref_rule)
    fid = (id_lookup.get((ref_rule, ref_line))
           or id_lookup.get((short, ref_line)))
    if fid:
        return f"dup {fid}"
    return reason


# ── UI formatting ──────────────────────────────────────────────────

_SEV_EMOJI = {
    "CRITICAL": "🔴", "HIGH": "🔴",
    "MEDIUM": "🟡", "LOW": "🟢",
}

# Column widths for box-drawing findings table
_TBL_W = (9, 12, 28, 22, 13, 40)
_TBL_HDR = ("ID", "SEV", "RULE", "FILE:LINE", "VERDICT", "REASON")


def _sev_icon(sev: str) -> str:
    """Emoji + severity for CI table."""
    upper = sev.upper() if sev else "?"
    return f"{_SEV_EMOJI.get(upper, '⚪')} {upper}"


def _box(icon: str, title: str) -> None:
    """Print box-drawing section header."""
    content = f"  {icon}  {title}"
    w = 46
    extra = sum(1 for c in content if ord(c) > 0x1F000)
    print(f"╔{'═' * w}╗")
    print(f"║{content:<{w - extra}}║")
    print(f"╚{'═' * w}╝")


def _tbl_border(left: str, mid: str, right: str) -> str:
    """Horizontal border: ┌──┬──┐ / ├──┼──┤ / └──┴──┘."""
    return left + mid.join("─" * w for w in _TBL_W) + right


def _tbl_row(vals: tuple, emoji_col: int = -1) -> str:
    """Data row with │ separators. emoji_col adjusts for wide chars."""
    parts = []
    for i, (v, w) in enumerate(zip(vals, _TBL_W)):
        cw = w - 2  # content width (padding each side)
        pw = cw - 1 if i == emoji_col else cw
        parts.append(f" {str(v):<{pw}} ")
    return "│" + "│".join(parts) + "│"


def _tbl_span_border(left: str, right: str) -> str:
    """Full-width separator spanning all columns."""
    inner = sum(_TBL_W) + len(_TBL_W) - 1
    return f"{left}{'─' * inner}{right}"


def _tbl_span_text(text: str) -> str:
    """Full-width text row spanning all columns."""
    inner = sum(_TBL_W) + len(_TBL_W) - 1
    return f"│ {text:<{inner - 2}} │"


class DecisionEngine:

    _memory_store: MemoryStore | None = None

    def decide(self, ctx: GitHubContext) -> Decision:
        """Main entry point: triage → analyzer → gate → Decision."""
        traces: list[StepTrace] = []

        print("::group::Triage Agent")
        _box("🔍", "TRIAGE AGENT")
        try:
            triage, triage_tools = self._run_triage(ctx)
            triage_summary = triage.get("context", {}).get(
                "change_summary", ""
            )
            traces.append(StepTrace(
                name="Triage Agent",
                tools_used=triage_tools,
                summary=triage_summary,
                status="success",
            ))
        except Exception:
            traces.append(StepTrace(
                name="Triage Agent", tools_used={},
                summary="failed", status="error",
            ))
            raise
        finally:
            print("::endgroup::")

        # Detect intentional skip: triage says no agents needed
        triage_skip = "appsec" not in triage.get(
            "recommended_agents", ["appsec"],
        )

        print("::group::AppSec Agent (OODA Loop)")
        _box("🛡", "APPSEC AGENT (OODA Loop)")
        try:
            if triage_skip:
                tool_results: list[ToolResult] = []
                agent_analysis = dict(_EMPTY_ANALYSIS)
                print("AppSec agent not recommended by triage, skipping.")
                traces.append(StepTrace(
                    name="AppSec Agent (OODA)",
                    tools_used={},
                    summary="Skipped (no security-relevant files)",
                    status="skipped",
                ))
            else:
                tool_results, agent_analysis, analyzer_tools = (
                    self._run_analyzer(ctx, triage)
                )
                raw_count = sum(len(tr.findings) for tr in tool_results)
                confirmed_count = len(agent_analysis.get("confirmed", []))
                traces.append(StepTrace(
                    name="AppSec Agent (OODA)",
                    tools_used=analyzer_tools,
                    summary=(f"{raw_count} raw, "
                            f"{confirmed_count} vulnerabilities confirmed"),
                    status="success",
                ))
        except Exception:
            traces.append(StepTrace(
                name="AppSec Agent (OODA)", tools_used={},
                summary="failed", status="error",
            ))
            raise
        finally:
            print("::endgroup::")

        print("::group::Smart Gate")
        try:
            decision = self._apply_gate(
                ctx, triage, tool_results, agent_analysis,
                triage_skip=triage_skip,
            )
            traces.append(StepTrace(
                name="Smart Gate",
                tools_used={},
                summary=decision.verdict.value,
                status="success",
            ))
            decision.trace = traces
        finally:
            print("::endgroup::")

        return decision

    def save_memory(self) -> None:
        """Save exception memory to disk (called by main.py after decide)."""
        if self._memory_store is not None:
            self._memory_store.save()

    def _run_triage(self, ctx: GitHubContext) -> tuple[dict, dict[str, int]]:
        """Run AI triage if configured, otherwise return default.

        Returns (triage_result, tools_used) for execution trace.
        """
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
            }, {}

        try:
            from src.agent import create_triage_agent, run_triage
            from src.tools import FetchPRFilesTool
            from src.observability import make_step_logger, run_with_timeout

            print(f"Running AI triage (model: {model_id})...")

            fetch_tool = None
            tools = []
            if ctx.token and ctx.repository and ctx.pr_number:
                fetch_tool = FetchPRFilesTool(
                    github_token=ctx.token,
                    repository=ctx.repository,
                )
                tools.append(fetch_tool)

            callback = make_step_logger("Triage", max_seconds=120)
            agent = create_triage_agent(
                api_key, model_id, tools=tools,
                step_callbacks=[callback],
            )
            result = run_with_timeout(
                run_triage, (agent, ctx),
                max_seconds=120, agent_name="Triage", agent=agent,
            )
            print(f"AI triage complete: {result['reason']}")

            # Context summary for CI readability
            triage_ctx = result.get("context", {})
            files = triage_ctx.get("files_changed", 0)
            langs = ", ".join(triage_ctx.get("languages", [])) or "unknown"
            risks = ", ".join(triage_ctx.get("risk_areas", [])) or "none detected"
            agents = ", ".join(
                result.get("recommended_agents", ["appsec"]),
            )
            parse_failed = "could not be parsed" in result.get(
                "reason", "").lower()
            if parse_failed:
                print("\n  ⚠  Triage AI: response parse failed"
                      " — running with default context")
            else:
                print(f"\n  📋 {files} file(s) | {langs}")
                print(f"  ⚠  Risk areas: {risks}")
            print(f"\n  ➜  Decision: {agents.upper()}")

            tools_used: dict[str, int] = {}
            if fetch_tool is not None and fetch_tool._call_count > 0:
                tools_used["fetch_pr_files"] = fetch_tool._call_count

            return result, tools_used
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
            }, {}

    def _run_analyzer(
        self, ctx: GitHubContext, triage: dict,
    ) -> tuple[list[ToolResult], dict, dict[str, int]]:
        """Run the AppSec Agent (OODA loop).

        Returns (raw_tool_results, agent_analysis, tools_used).

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
            return [], dict(_EMPTY_ANALYSIS), {}

        agents = triage.get("recommended_agents", [])
        if "appsec" not in agents:
            print("AppSec agent not recommended by triage, skipping.")
            return [], dict(_EMPTY_ANALYSIS), {}

        try:
            from src.analyzer_agent import create_analyzer_agent, run_analyzer
            from src.tools import (
                FetchPRDiffTool, SemgrepTool, _fetch_pr_files_from_api,
            )
            from src.observability import make_step_logger, run_with_timeout

            print("Running AppSec Agent (OODA loop)...")

            # Fetch PR file list for scoped scanning
            pr_filenames: list[str] = []
            pr_files_raw: list[dict] = []
            if ctx.token and ctx.repository and ctx.pr_number:
                pr_files_raw, api_err = _fetch_pr_files_from_api(
                    ctx.token, ctx.repository, ctx.pr_number,
                )
                if not api_err:
                    pr_filenames = [
                        f["filename"] for f in pr_files_raw
                        if f.get("status") != "removed"
                    ]
                    print(f"  PR scope: {len(pr_filenames)} file(s)")
                else:
                    print(f"  PR scope: full workspace (API: {api_err})")

            # Create tools — we keep refs for the side channel + call counting
            semgrep_tool = SemgrepTool(
                workspace_path=ctx.workspace,
                target_files=pr_filenames or None,
            )
            diff_tool = None
            tools = [semgrep_tool]

            # Observe tool: only if PR context available (LLM06)
            if ctx.token and ctx.repository and ctx.pr_number:
                diff_tool = FetchPRDiffTool(
                    github_token=ctx.token,
                    repository=ctx.repository,
                    pr_number=ctx.pr_number,
                )
                # Pre-populate cache to avoid duplicate API call
                if pr_files_raw:
                    diff_tool._files_cache = pr_files_raw
                tools.append(diff_tool)

            callback = make_step_logger("AppSec", max_seconds=600)
            agent = create_analyzer_agent(
                api_key, model_id, tools=tools,
                step_callbacks=[callback],
            )
            analysis = run_with_timeout(
                run_analyzer, (agent, triage),
                max_seconds=600, agent_name="AppSec", agent=agent,
            )
            # Condensed summary (details in findings table)
            n_confirmed = len(analysis.get("confirmed", []))
            n_dismissed = len(analysis.get("dismissed", []))
            n_raw = len(semgrep_tool._all_raw_findings)
            print(f"\n  📊 Semgrep: {n_raw} raw"
                  f" → {n_confirmed} confirmed,"
                  f" {n_dismissed} dismissed")
            if semgrep_tool._all_configs_used:
                configs = ", ".join(semgrep_tool._all_configs_used)
                print(f"     Configs: {configs}")

            if semgrep_tool._all_scan_errors:
                print(f"  Semgrep errors "
                      f"({len(semgrep_tool._all_scan_errors)}):")
                for e in semgrep_tool._all_scan_errors[:3]:
                    msg = (e.get("message", str(e))
                           if isinstance(e, dict) else str(e))
                    print(f"    - {msg[:200]}")

            # Debug diagnostics (only when Semgrep ran but found 0 findings)
            if (semgrep_tool._call_count > 0
                    and len(semgrep_tool._all_raw_findings) == 0):
                print("  WARNING: Semgrep ran but found 0 findings — "
                      "debug info:")
                if semgrep_tool._last_cmd:
                    print(f"    Command: "
                          f"{' '.join(semgrep_tool._last_cmd)}")
                if semgrep_tool._last_files_scanned:
                    print(f"    Files scanned: "
                          f"{len(semgrep_tool._last_files_scanned)}")
                else:
                    print("    Files scanned: 0 "
                          "(Semgrep scanned no files!)")
                if semgrep_tool._last_stderr:
                    stderr_preview = (
                        semgrep_tool._last_stderr.strip()[:2000]
                    )
                    print(f"    Stderr: {stderr_preview}")
                ws = semgrep_tool.workspace_path
                if os.path.isdir(ws):
                    try:
                        entries = sorted(os.listdir(ws))[:15]
                        print(f"    Workspace ({len(entries)} files): "
                              f"{', '.join(entries[:10])}")
                    except OSError:
                        pass

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

            # Collect tool call counts for trace
            tools_used: dict[str, int] = {}
            if semgrep_tool._call_count > 0:
                tools_used["run_semgrep"] = semgrep_tool._call_count
            if diff_tool is not None and diff_tool._call_count > 0:
                tools_used["fetch_pr_diff"] = diff_tool._call_count

            return tool_results, analysis, tools_used

        except Exception as e:
            print(f"::warning::AppSec Agent failed: {e}")
            return [ToolResult(
                tool="semgrep",
                success=False,
                findings=[],
                error=str(e),
            )], dict(_EMPTY_ANALYSIS), {}

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
                        f"Agent dismissed {finding.severity.value} "
                        f"finding — included by safety net"
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
                        f"{finding.severity.value} finding not confirmed "
                        f"by agent — included by safety net"
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

    def _print_findings_table(
        self,
        raw_findings: list[Finding],
        agent_analysis: dict,
        safety_warnings: list[dict],
    ) -> None:
        """Print ASCII table of all raw findings with agent verdict."""
        if not raw_findings:
            return

        confirmed_rules = {
            c["rule_id"] for c in agent_analysis.get("confirmed", [])
            if isinstance(c, dict) and isinstance(c.get("rule_id"), str)
        }
        dismissed_rules = {
            d["rule_id"] for d in agent_analysis.get("dismissed", [])
            if isinstance(d, dict) and isinstance(d.get("rule_id"), str)
        }
        safety_net_rules = {
            w["rule_id"] for w in safety_warnings
            if isinstance(w, dict) and isinstance(w.get("rule_id"), str)
        }

        # Build id_lookup for duplicate resolution (confirmed findings)
        id_lookup: dict[tuple[str, int], str] = {}
        for f in raw_findings:
            if f.rule_id in confirmed_rules:
                short = (f.rule_id.rsplit(".", 1)[-1]
                         if "." in f.rule_id else f.rule_id)
                id_lookup[(f.rule_id, f.line)] = f.finding_id
                id_lookup[(short, f.line)] = f.finding_id

        # Separate reason dicts: confirmed vs dismissed (avoid overwrite)
        confirmed_reasons: dict[str, str] = {}
        for c in agent_analysis.get("confirmed", []):
            if isinstance(c, dict) and c.get("rule_id"):
                confirmed_reasons[c["rule_id"]] = _shorten_rule_refs(
                    c.get("reason", ""),
                )
        dismissed_reasons: dict[str, str] = {}
        for d in agent_analysis.get("dismissed", []):
            if isinstance(d, dict) and d.get("rule_id"):
                dismissed_reasons[d["rule_id"]] = _shorten_rule_refs(
                    d.get("reason", ""),
                )

        # Deduplicate by rule_id+path+line for display
        seen: set[tuple[str, str, int]] = set()
        rows: list[tuple[str, str, str, str, str, str]] = []
        for f in raw_findings:
            key = (f.rule_id, f.path, f.line)
            if key in seen:
                continue
            seen.add(key)

            if f.rule_id in confirmed_rules:
                verdict = "confirmed"
            elif f.rule_id in dismissed_rules:
                if f.rule_id in safety_net_rules:
                    verdict = "safety-net"
                else:
                    verdict = "dismissed"
            elif f.rule_id in safety_net_rules:
                verdict = "safety-net"
            else:
                verdict = "noise"

            short_rule = (f.rule_id.rsplit(".", 1)[-1]
                          if "." in f.rule_id else f.rule_id)
            short_path = (f.path.rsplit("/", 1)[-1]
                          if "/" in f.path else f.path)
            # Use the right reason dict for the verdict
            if verdict == "confirmed":
                reason = confirmed_reasons.get(f.rule_id, "")
            elif verdict in ("dismissed", "safety-net"):
                reason = dismissed_reasons.get(f.rule_id, "")
            else:
                reason = ""
            # Default reasons when agent didn't provide one
            if not reason:
                if verdict == "noise":
                    msg = f.message[:60] if f.message else ""
                    reason = (f"not analyzed — {msg}"
                              if msg else "not analyzed by agent")
                elif verdict == "safety-net":
                    msg = f.message[:60] if f.message else ""
                    reason = (f"safety-net — {msg}"
                              if msg
                              else "HIGH/CRITICAL not confirmed by agent")
            # Resolve duplicate references to finding IDs
            if verdict == "dismissed":
                reason = _resolve_dup_ids(reason, id_lookup)

            rows.append((
                f.finding_id, f.severity.value.upper(), short_rule,
                f"{short_path}:{f.line}", verdict,
                _truncate_reason(reason, 38),
            ))

        # Separate regular from safety-net for visual grouping
        regular = [r for r in rows if r[4] != "safety-net"]
        safety = [r for r in rows if r[4] == "safety-net"]

        print()
        print(_tbl_border("┌", "┬", "┐"))
        print(_tbl_row(_TBL_HDR))
        print(_tbl_border("├", "┼", "┤"))
        for fid, sev, rule, loc, vrd, rsn in regular:
            print(_tbl_row(
                (fid, _sev_icon(sev), rule, loc, vrd, rsn),
                emoji_col=1,
            ))
        if safety:
            print(_tbl_span_border("├", "┤"))
            print(_tbl_span_text(
                "⚠  SAFETY NET — agent dismissed or missed "
                "HIGH/CRITICAL findings — human review required"
            ))
            print(_tbl_span_border("├", "┤"))
            for fid, sev, rule, loc, vrd, rsn in safety:
                print(_tbl_row(
                    (fid, _sev_icon(sev), rule, loc, vrd, rsn),
                    emoji_col=1,
                ))
        print(_tbl_border("└", "┴", "┘"))

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

    def _build_confirmed_structured(
        self,
        effective_findings: list[Finding],
        agent_analysis: dict,
        safety_warnings: list[dict] | None = None,
    ) -> list[dict]:
        """Build structured findings for PR report / scan-results.

        Merges raw Finding data (gate-validated) with agent analysis context
        (reason, recommendation). Severity always from raw.
        Each entry gets a "source" field: "confirmed" or "safety-net".
        """
        # Agent context by rule_id (for reason/recommendation)
        agent_by_rule: dict[str, dict] = {}
        for c in agent_analysis.get("confirmed", []):
            if isinstance(c, dict) and isinstance(c.get("rule_id"), str):
                agent_by_rule[c["rule_id"]] = c

        # Safety-net rule_ids (not confirmed by agent)
        safety_rule_ids: set[str] = set()
        if safety_warnings:
            safety_rule_ids = {
                w["rule_id"] for w in safety_warnings
                if isinstance(w, dict)
                and isinstance(w.get("rule_id"), str)
            }
        confirmed_rule_ids = set(agent_by_rule.keys())

        result = []
        for f in effective_findings:
            agent_ctx = agent_by_rule.get(f.rule_id, {})
            is_safety = (f.rule_id in safety_rule_ids
                         and f.rule_id not in confirmed_rule_ids)
            agent_reason = agent_ctx.get("reason", "")
            agent_rec = agent_ctx.get("recommendation", "")
            # Safety-net fallback: use Semgrep message when agent didn't analyze
            if is_safety and not agent_reason:
                agent_reason = f.message or ""
            if is_safety and not agent_rec:
                if f.fix:
                    agent_rec = f"Semgrep autofix: {f.fix}"
                else:
                    sev_label = f.severity.value.upper()
                    agent_rec = f.message or (
                        f"Review this finding — flagged by Semgrep "
                        f"as {sev_label}, not confirmed by AI agent"
                    )
            result.append({
                "finding_id": f.finding_id,
                "rule_id": f.rule_id,
                "path": f.path,
                "line": f.line,
                "severity": f.severity.value,
                "message": f.message,
                "fix": f.fix,
                "agent_reason": agent_reason,
                "agent_recommendation": agent_rec,
                "source": "safety-net" if is_safety else "confirmed",
            })
        return result

    def _check_severity_mismatches(
        self,
        raw_findings: list[Finding],
        agent_analysis: dict,
    ) -> list[dict]:
        """Detect when agent downgrades severity vs raw scanner data.

        Security (LLM05 — anti-severity-manipulation):
        If the agent claims a finding is lower severity than the raw scanner
        reported, this is a warning. The raw severity always wins, but the
        mismatch is flagged for human review.
        """
        warnings = []

        # Map confirmed agent claims: rule_id → agent severity string
        agent_sev_by_rule: dict[str, str] = {}
        for c in agent_analysis.get("confirmed", []):
            if isinstance(c, dict) and isinstance(c.get("rule_id"), str):
                agent_sev = c.get("severity", "")
                if isinstance(agent_sev, str) and agent_sev:
                    agent_sev_by_rule[c["rule_id"]] = agent_sev.lower()

        # Severity string → index for comparison
        sev_str_to_idx = {s.value: i for i, s in enumerate(SEVERITY_ORDER)}

        for finding in raw_findings:
            agent_sev_str = agent_sev_by_rule.get(finding.rule_id)
            if agent_sev_str is None:
                continue  # not confirmed by agent, handled elsewhere

            raw_idx = SEVERITY_ORDER.index(finding.severity)
            agent_idx = sev_str_to_idx.get(agent_sev_str, -1)

            if agent_idx == -1:
                continue  # unrecognized severity string, skip

            if agent_idx < raw_idx:
                warnings.append({
                    "type": "severity_mismatch",
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "agent_severity": agent_sev_str,
                    "effective_severity": finding.severity.value,
                    "path": finding.path,
                    "line": finding.line,
                    "message": (
                        f"Agent downgraded {finding.rule_id} from "
                        f"{finding.severity.value} to {agent_sev_str}. "
                        f"Using raw severity: {finding.severity.value}."
                    ),
                })

        return warnings

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
        *,
        triage_skip: bool = False,
    ) -> Decision:
        """Smart gate: confirmed-based verdicts with safety net.

        Security (LLM05 — untrusted output handling):
        - Verdict is based on CONFIRMED findings (validated against raw)
        - Anti-hallucination: confirmed rule_ids must exist in raw
        - Anti-severity-manipulation: severity comes from raw findings
        - Safety net: dismissed/unaccounted HIGH/CRITICAL → MANUAL_REVIEW
        - Fail-secure: empty/unparseable analysis → fallback to raw

        Enforce mode policy:
        - Triage skip (no code files) → ALLOWED
        - Safety net triggered → MANUAL_REVIEW (agent dismissed HIGH/CRIT)
        - Confirmed CRITICAL → BLOCKED
        - Confirmed any → MANUAL_REVIEW (human decides with full report)
        - No confirmed → ALLOWED
        - Tool failure → MANUAL_REVIEW
        """
        ai_reason = triage.get("reason", "")

        # Intentional skip: triage says no security-relevant files changed.
        # Only valid when there are truly no findings (safety net).
        if triage_skip:
            has_raw = any(f for tr in tool_results for f in tr.findings)
            if not has_raw:
                return Decision(
                    verdict=Verdict.ALLOWED,
                    continue_pipeline=True,
                    max_severity=Severity.NONE,
                    selected_tools=[],
                    reason=(
                        f"No security-relevant files changed. "
                        f"Triage: {ai_reason}"
                    ),
                    mode=ctx.mode,
                )
            # If raw findings exist despite skip (shouldn't happen),
            # fall through to normal processing as safety net.

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
            # Severity mismatch: agent downgraded severity
            sev_mismatches = self._check_severity_mismatches(
                active_findings, agent_analysis,
            )
            safety_warnings.extend(sev_mismatches)

            # Include safety-net findings in effective_findings
            # (they ARE part of the verdict — not just informational)
            if safety_warnings:
                safety_rule_ids = {
                    w["rule_id"] for w in safety_warnings
                    if isinstance(w, dict)
                    and isinstance(w.get("rule_id"), str)
                }
                already = {
                    (f.rule_id, f.path, f.line)
                    for f in effective_findings
                }
                for f in active_findings:
                    key = (f.rule_id, f.path, f.line)
                    if (f.rule_id in safety_rule_ids
                            and key not in already):
                        effective_findings.append(f)
                        already.add(key)

                print(
                    f"::warning::Safety net triggered: "
                    f"{len(safety_warnings)} HIGH/CRITICAL finding(s) "
                    f"not confirmed by agent"
                )
        else:
            # Fail-secure: no analysis → fallback to active findings
            effective_findings = list(active_findings)
            safety_warnings = []

        # Findings table (after validation + safety net)
        self._print_findings_table(
            active_findings, agent_analysis, safety_warnings,
        )

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
        raw_count = len(raw_findings)

        # Anti-hallucination check
        confirmed_rule_ids_gate = {
            c["rule_id"] for c in agent_analysis.get("confirmed", [])
            if isinstance(c, dict) and isinstance(c.get("rule_id"), str)
        }
        n_agent = sum(
            1 for f in effective_findings
            if f.rule_id in confirmed_rule_ids_gate
        )
        if confirmed_rule_ids_gate and n_agent == 0:
            print(
                f"  Warning: agent confirmed "
                f"{len(confirmed_rule_ids_gate)} finding(s) "
                f"but none matched scanner results"
            )

        excepted_count = len(excepted_info)

        # Build structured findings lists for PR reporting
        confirmed_structured = self._build_confirmed_structured(
            effective_findings, agent_analysis, safety_warnings,
        )
        # Dedup: remove dismissed entries that safety-net promoted to confirmed
        _confirmed_keys: set[tuple[str, int]] = set()
        for cf in confirmed_structured:
            if cf.get("source") == "safety-net":
                rid = cf.get("rule_id", "")
                ln = cf.get("line", 0)
                _confirmed_keys.add((rid, ln))
                short = (rid.rsplit(".", 1)[-1] if "." in rid
                         else rid)
                _confirmed_keys.add((short, ln))
        def _dismissed_overlaps(d: dict) -> bool:
            rid = d.get("rule_id", "")
            ln = d.get("line", 0)
            if (rid, ln) in _confirmed_keys:
                return True
            short = rid.rsplit(".", 1)[-1] if "." in rid else rid
            return (short, ln) in _confirmed_keys

        dismissed_structured = [
            d for d in agent_analysis.get("dismissed", [])
            if not _dismissed_overlaps(d)
        ]
        excepted_structured = excepted_info

        # Shadow mode: always allow, but report everything
        if ctx.mode == "shadow":
            severity_parts = []
            for sev in (Severity.CRITICAL, Severity.HIGH,
                        Severity.MEDIUM, Severity.LOW):
                count = eff_counts.get(sev, 0)
                if count > 0:
                    severity_parts.append(f"{count} {sev.value}")
            sev_str = (f" ({', '.join(severity_parts)})"
                       if severity_parts else "")
            safety_str = (
                f", {len(safety_warnings)} safety warning(s)"
                if safety_warnings else ""
            )

            # Gate verdict display (shadow)
            _box("🚦", "GATE DECISION")
            print()
            print("  ✅  ALLOWED  (shadow mode)")
            shadow_breakdown = []
            if findings_count > 0:
                shadow_breakdown.append(
                    f"{findings_count} confirmed finding(s)")
            if safety_warnings:
                shadow_breakdown.append(
                    f"{len(safety_warnings)} safety warning(s)")
            for i, line in enumerate(shadow_breakdown):
                prefix = ("└─" if i == len(shadow_breakdown) - 1
                          else "├─")
                print(f"  {prefix} {line}")

            return Decision(
                verdict=Verdict.ALLOWED,
                continue_pipeline=True,
                max_severity=max_raw_severity,
                selected_tools=["semgrep"],
                reason=(
                    f"Shadow mode: {raw_count} raw, "
                    f"{findings_count} confirmed{sev_str}"
                    f"{safety_str}."
                ),
                mode=ctx.mode,
                findings_count=findings_count,
                excepted_count=excepted_count,
                tool_results=tool_results,
                analysis_report=analysis_report,
                safety_warnings=safety_warnings,
                confirmed_findings=confirmed_structured,
                dismissed_findings=dismissed_structured,
                excepted_findings=excepted_structured,
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
        # 2. CRITICAL in effective findings → auto-BLOCKED
        #    (covers both agent-confirmed and safety-net CRITICAL)
        elif eff_counts.get(Severity.CRITICAL, 0) > 0:
            verdict = Verdict.BLOCKED
            continue_pipeline = False
            reason = (
                f"BLOCKED — {eff_counts[Severity.CRITICAL]} critical "
                f"finding(s). Auto-blocked per policy."
            )
        # 3. Safety net override: agent dismissed/ignored HIGH
        elif safety_warnings:
            verdict = Verdict.MANUAL_REVIEW
            continue_pipeline = False
            reason = (
                f"MANUAL_REVIEW — {len(safety_warnings)} safety warning(s): "
                f"agent dismissed or missed HIGH/CRITICAL "
                f"finding(s). Human review required."
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

        # ── Gate verdict display ──
        _box("🚦", "GATE DECISION")
        print()
        if verdict == Verdict.BLOCKED:
            print("  🚫  BLOCKED")
        elif verdict == Verdict.MANUAL_REVIEW:
            print("  ⛔  MANUAL REVIEW REQUIRED")
        else:
            print("  ✅  ALLOWED")
        breakdown = []
        if findings_count > 0:
            breakdown.append(f"{findings_count} confirmed finding(s)")
        if safety_warnings:
            n_missed = sum(
                1 for w in safety_warnings
                if w.get("type") == "unaccounted_high_severity"
            )
            n_dismissed_sw = sum(
                1 for w in safety_warnings
                if w.get("type") == "dismissed_high_severity"
            )
            n_sev_mm = sum(
                1 for w in safety_warnings
                if w.get("type") == "severity_mismatch"
            )
            if n_missed:
                breakdown.append(
                    f"{n_missed} safety warning(s)"
                    f" — agent missed HIGH/CRITICAL"
                )
            if n_dismissed_sw:
                breakdown.append(
                    f"{n_dismissed_sw} safety warning(s)"
                    f" — agent dismissed HIGH/CRITICAL finding(s)"
                )
            if n_sev_mm:
                breakdown.append(
                    f"{n_sev_mm} safety warning(s)"
                    f" — severity downgrade"
                )
        if excepted_count > 0:
            breakdown.append(
                f"{excepted_count} auto-excepted by memory"
            )
        for i, line in enumerate(breakdown):
            prefix = "└─" if i == len(breakdown) - 1 else "├─"
            print(f"  {prefix} {line}")

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
            confirmed_findings=confirmed_structured,
            dismissed_findings=dismissed_structured,
            excepted_findings=excepted_structured,
        )
