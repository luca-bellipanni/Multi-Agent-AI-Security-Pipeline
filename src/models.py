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


@dataclass
class Decision:
    verdict: Verdict
    continue_pipeline: bool
    max_severity: Severity
    selected_tools: list[str]
    reason: str
    mode: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "version": "1.0",
            "verdict": self.verdict.value,
            "continue_pipeline": self.continue_pipeline,
            "max_severity": self.max_severity.value,
            "selected_tools": self.selected_tools,
            "reason": self.reason,
            "mode": self.mode,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_outputs(self) -> dict[str, str]:
        """Format for GITHUB_OUTPUT (all values must be strings)."""
        return {
            "decision": self.verdict.value,
            "continue_pipeline": str(self.continue_pipeline).lower(),
            "reason": self.reason,
        }
