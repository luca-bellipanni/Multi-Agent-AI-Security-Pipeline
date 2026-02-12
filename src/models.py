"""Data models for the Agentic AppSec Pipeline."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json


class Verdict(str, Enum):
    ALLOWED = "allowed"
    MANUAL_REVIEW = "manual_review"
    BLOCKED = "blocked"


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = [Severity.NONE, Severity.LOW, Severity.MEDIUM,
                  Severity.HIGH, Severity.CRITICAL]


@dataclass
class Finding:
    tool: str
    rule_id: str
    path: str
    line: int
    severity: Severity
    message: str


@dataclass
class ToolResult:
    tool: str
    success: bool
    findings: list[Finding]
    error: str = ""
    config_used: list[str] = field(default_factory=list)


@dataclass
class Decision:
    verdict: Verdict
    continue_pipeline: bool
    max_severity: Severity
    selected_tools: list[str]
    reason: str
    mode: str
    findings_count: int = 0
    tool_results: list[ToolResult] = field(default_factory=list)
    analysis_report: str = ""
    safety_warnings: list[dict] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "version": "2.0",
            "verdict": self.verdict.value,
            "continue_pipeline": self.continue_pipeline,
            "max_severity": self.max_severity.value,
            "selected_tools": self.selected_tools,
            "findings_count": self.findings_count,
            "reason": self.reason,
            "mode": self.mode,
            "analysis_report": self.analysis_report,
            "safety_warnings": self.safety_warnings,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_outputs(self) -> dict[str, str]:
        """Format for GITHUB_OUTPUT (all values must be strings)."""
        return {
            "decision": self.verdict.value,
            "continue_pipeline": str(self.continue_pipeline).lower(),
            "findings_count": str(self.findings_count),
            "reason": self.reason,
            "safety_warnings_count": str(len(self.safety_warnings)),
        }
