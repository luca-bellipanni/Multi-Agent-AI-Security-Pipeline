"""
Decision engine — the "brain" of the pipeline.

Step 2: deterministic rules based on mode.
Future: AI-powered via smolagents.
"""

from src.models import Decision, Verdict, Severity
from src.github_context import GitHubContext


class DecisionEngine:

    def decide(self, ctx: GitHubContext) -> Decision:
        if ctx.mode == "shadow":
            return Decision(
                verdict=Verdict.ALLOWED,
                continue_pipeline=True,
                max_severity=Severity.NONE,
                selected_tools=[],
                reason="Shadow mode: observing only, pipeline continues.",
                mode=ctx.mode,
            )
        else:
            return Decision(
                verdict=Verdict.MANUAL_REVIEW,
                continue_pipeline=False,
                max_severity=Severity.NONE,
                selected_tools=[],
                reason="Enforce mode: no security tools configured yet, requiring manual review.",
                mode=ctx.mode,
            )
