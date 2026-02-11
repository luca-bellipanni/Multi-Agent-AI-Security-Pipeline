"""
Decision engine — orchestrates triage AI + deterministic gate.

Architecture:
  1. Triage (AI if available, else default) → recommends tools
  2. Gate (Python code, not hackable) → final verdict

The gate rules are FIXED in code. The AI advises, the code decides.
"""

import os

from src.models import Decision, Verdict, Severity
from src.github_context import GitHubContext


class DecisionEngine:

    def decide(self, ctx: GitHubContext) -> Decision:
        """Main entry point: triage → gate → Decision."""
        triage = self._run_triage(ctx)
        return self._apply_gate(ctx, triage)

    def _run_triage(self, ctx: GitHubContext) -> dict:
        """Run AI triage if configured, otherwise return default."""
        api_key = os.environ.get("INPUT_AI_API_KEY", "")
        model_id = os.environ.get("INPUT_AI_MODEL", "gpt-4o-mini")

        if not api_key:
            print("No AI API key configured, using deterministic fallback.")
            return {"recommended_tools": [], "reason": "No AI configured."}

        try:
            from src.agent import create_triage_agent, run_triage

            print(f"Running AI triage (model: {model_id})...")
            agent = create_triage_agent(api_key, model_id)
            result = run_triage(agent, ctx)
            print(f"AI triage complete: {result['reason']}")
            return result
        except Exception as e:
            print(f"::warning::AI triage failed: {e}")
            print("Falling back to deterministic mode.")
            return {"recommended_tools": [], "reason": f"AI error, using fallback."}

    def _apply_gate(self, ctx: GitHubContext, triage: dict) -> Decision:
        """Deterministic gate — fixed rules, not hackable by prompt injection."""
        recommended = triage.get("recommended_tools", [])
        ai_reason = triage.get("reason", "")

        if ctx.mode == "shadow":
            return Decision(
                verdict=Verdict.ALLOWED,
                continue_pipeline=True,
                max_severity=Severity.NONE,
                selected_tools=recommended,
                reason=f"Shadow mode: observing only. AI triage: {ai_reason}",
                mode=ctx.mode,
            )
        else:
            return Decision(
                verdict=Verdict.MANUAL_REVIEW,
                continue_pipeline=False,
                max_severity=Severity.NONE,
                selected_tools=recommended,
                reason=f"Enforce mode: no tool results yet. AI triage: {ai_reason}",
                mode=ctx.mode,
            )
