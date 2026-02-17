"""Exception memory — persists known false-positive patterns between runs.

Stores exception entries in `.appsec/exceptions.json` (git-tracked).
The gate loads exceptions, auto-dismisses matching LOW/MEDIUM findings,
and writes new auto-exceptions from agent-dismissed findings.

Security (llm-security/output-handling — LLM05):
  Auto-exceptions are ONLY created for LOW/MEDIUM severity.
  HIGH/CRITICAL are NEVER auto-excepted — filter_findings() hard-codes this.
  Severity cap comes from raw findings, not agent claims.
  Anti-hallucination: auto-add verifies rule_id exists in raw findings.

Security (llm-security/prompt-injection — LLM01):
  Exception reasons appear in logs/report only, NEVER in agent prompts.

Security (code-security/path-traversal):
  path_pattern validated: no '..' components, no absolute paths.
  File is only read from the workspace directory.
"""

import fnmatch
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from src.models import Finding, Severity, SEVERITY_ORDER


EXCEPTIONS_FILE = ".appsec/exceptions.json"
EXCEPTIONS_VERSION = "1.0"
AUTO_EXCEPTION_TTL_DAYS = 90


class ExceptionSource(str, Enum):
    AUTO = "auto"
    MANUAL = "manual"


@dataclass
class ExceptionEntry:
    """A known false-positive exception.

    Matches findings by rule_id (exact) + path_pattern (glob) + severity_cap.
    Auto-exceptions expire after AUTO_EXCEPTION_TTL_DAYS days.
    Manual exceptions never expire (expires_at=None).
    """

    rule_id: str
    path_pattern: str
    reason: str
    source: ExceptionSource
    severity_cap: Severity
    created_at: str
    expires_at: str | None = None
    pr_number: int | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if this exception has expired.

        Returns True if expired or if expires_at is corrupt (fail-secure).
        Returns False if expires_at is None (manual exceptions never expire).
        """
        if self.expires_at is None:
            return False
        now = now or datetime.now(timezone.utc)
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            return now >= expiry
        except (ValueError, TypeError):
            return True  # Corrupt date = expired (fail-secure)

    def matches(self, finding: Finding) -> bool:
        """Check if this exception matches a finding.

        Security (LLM05): severity_cap is enforced here at gate level.
        The exception only applies to findings at or below the cap severity.
        """
        if finding.rule_id != self.rule_id:
            return False
        if not fnmatch.fnmatch(finding.path, self.path_pattern):
            return False
        # Severity cap: exception applies only at or below cap
        finding_idx = SEVERITY_ORDER.index(finding.severity)
        cap_idx = SEVERITY_ORDER.index(self.severity_cap)
        if finding_idx > cap_idx:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "path_pattern": self.path_pattern,
            "reason": self.reason,
            "source": self.source.value,
            "severity_cap": self.severity_cap.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "pr_number": self.pr_number,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ExceptionEntry":
        """Parse from dict with strict validation.

        Raises ValueError on invalid data.
        """
        if not isinstance(data, dict):
            raise ValueError("Exception entry must be a dict")

        rule_id = data.get("rule_id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("rule_id must be a non-empty string")

        path_pattern = data.get("path_pattern")
        if not isinstance(path_pattern, str) or not path_pattern:
            raise ValueError("path_pattern must be a non-empty string")

        reason = data.get("reason", "")
        if not isinstance(reason, str):
            reason = ""

        source_val = data.get("source", "manual")
        try:
            source = ExceptionSource(source_val)
        except ValueError:
            raise ValueError(f"Invalid source: {source_val}")

        sev_val = data.get("severity_cap", "medium")
        try:
            severity_cap = Severity(sev_val)
        except ValueError:
            raise ValueError(f"Invalid severity_cap: {sev_val}")

        created_at = data.get("created_at", "")
        if not isinstance(created_at, str):
            created_at = ""

        expires_at = data.get("expires_at")
        if expires_at is not None and not isinstance(expires_at, str):
            expires_at = None

        pr_number = data.get("pr_number")
        if pr_number is not None and not isinstance(pr_number, int):
            pr_number = None

        return cls(
            rule_id=rule_id,
            path_pattern=path_pattern,
            reason=reason,
            source=source,
            severity_cap=severity_cap,
            created_at=created_at,
            expires_at=expires_at,
            pr_number=pr_number,
        )


class MemoryStore:
    """Read/write exception list from .appsec/exceptions.json.

    Security (code-security/path-traversal):
      Workspace path is validated once at construction.
      path_pattern in exceptions is validated against workspace escape.

    Security (LLM01):
      Exception reasons are logged but NEVER passed to agents as context.
    """

    def __init__(self, workspace: str, repository: str = ""):
        self._workspace = workspace
        self._repository = repository
        self._exceptions: list[ExceptionEntry] = []
        self._file_path = os.path.join(workspace, EXCEPTIONS_FILE)

    def load(self) -> list[str]:
        """Load exceptions from disk. Returns list of warnings.

        Fail-open: missing file = no exceptions (normal on first run).
        Fail-open: corrupt file = no exceptions + warning.
        """
        warnings: list[str] = []
        self._exceptions = []

        if not os.path.isfile(self._file_path):
            return warnings

        try:
            with open(self._file_path) as f:
                raw = f.read()
        except OSError as e:
            warnings.append(f"Could not read {EXCEPTIONS_FILE}: {e}")
            return warnings

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as e:
            warnings.append(f"Corrupt {EXCEPTIONS_FILE}: {e}")
            return warnings

        if not isinstance(data, dict):
            warnings.append(f"Invalid {EXCEPTIONS_FILE}: root must be object")
            return warnings

        version = data.get("version")
        if version != EXCEPTIONS_VERSION:
            warnings.append(
                f"Unsupported {EXCEPTIONS_FILE} version: {version} "
                f"(expected {EXCEPTIONS_VERSION})"
            )
            return warnings

        for i, entry_data in enumerate(data.get("exceptions", [])):
            try:
                entry = ExceptionEntry.from_dict(entry_data)
                if not self._validate_path_pattern(entry.path_pattern):
                    warnings.append(
                        f"Exception #{i}: invalid path_pattern "
                        f"'{entry.path_pattern}' (skipped)"
                    )
                    continue
                self._exceptions.append(entry)
            except (ValueError, KeyError, TypeError) as e:
                warnings.append(f"Exception #{i}: invalid entry (skipped): {e}")

        return warnings

    def save(self) -> None:
        """Write current exceptions to disk.

        Creates .appsec/ directory if it doesn't exist.
        """
        dir_path = os.path.dirname(self._file_path)
        os.makedirs(dir_path, exist_ok=True)

        data = {
            "version": EXCEPTIONS_VERSION,
            "metadata": {
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "repository": self._repository,
            },
            "exceptions": [e.to_dict() for e in self._exceptions],
        }

        with open(self._file_path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    def match_finding(self, finding: Finding) -> ExceptionEntry | None:
        """Return the first active (non-expired) exception matching a finding."""
        now = datetime.now(timezone.utc)
        for exc in self._exceptions:
            if exc.is_expired(now):
                continue
            if exc.matches(finding):
                return exc
        return None

    def filter_findings(
        self, findings: list[Finding],
    ) -> tuple[list[Finding], list[dict]]:
        """Partition findings into (remaining, excepted_info).

        Security (LLM05): HIGH/CRITICAL findings are NEVER removed,
        even if an exception matches. They always stay in remaining.

        Returns:
          remaining: findings NOT covered by active exceptions
                     (+ all HIGH/CRITICAL regardless)
          excepted_info: dicts with finding + exception details for report
        """
        remaining: list[Finding] = []
        excepted_info: list[dict] = []

        for f in findings:
            exc = self.match_finding(f)
            # Safety: HIGH/CRITICAL are never auto-excepted
            if exc and f.severity not in (Severity.HIGH, Severity.CRITICAL):
                excepted_info.append({
                    "rule_id": f.rule_id,
                    "path": f.path,
                    "line": f.line,
                    "severity": f.severity.value,
                    "exception_reason": exc.reason,
                    "exception_source": exc.source.value,
                })
            else:
                remaining.append(f)

        return remaining, excepted_info

    def add_auto_exceptions(
        self,
        dismissed: list[dict],
        raw_findings: list[Finding],
        pr_number: int | None,
    ) -> int:
        """Create auto-exceptions from agent's dismissed LOW/MEDIUM findings.

        Security (LLM05):
          - Only LOW/MEDIUM severity (from raw, not agent claims)
          - Anti-hallucination: rule_id must exist in raw findings
          - Duplicates not created (already excepted → skip)

        Returns count of new exceptions added.
        """
        # Build lookup: rule_id → Finding from raw (first occurrence)
        raw_by_rule: dict[str, Finding] = {}
        for f in raw_findings:
            if f.rule_id not in raw_by_rule:
                raw_by_rule[f.rule_id] = f

        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=AUTO_EXCEPTION_TTL_DAYS)).isoformat()
        count = 0

        for d in dismissed:
            if not isinstance(d, dict):
                continue
            rule_id = d.get("rule_id")
            if not isinstance(rule_id, str):
                continue

            # Must exist in raw findings (anti-hallucination)
            raw_finding = raw_by_rule.get(rule_id)
            if raw_finding is None:
                continue

            # Only LOW/MEDIUM (LLM05: severity cap)
            if raw_finding.severity not in (Severity.LOW, Severity.MEDIUM):
                continue

            # Already excepted?
            if self.match_finding(raw_finding) is not None:
                continue

            reason = d.get("reason", "Auto-dismissed by AppSec agent")
            if not isinstance(reason, str):
                reason = "Auto-dismissed by AppSec agent"

            entry = ExceptionEntry(
                rule_id=rule_id,
                path_pattern=raw_finding.path,
                reason=reason,
                source=ExceptionSource.AUTO,
                severity_cap=raw_finding.severity,
                created_at=now.isoformat(),
                expires_at=expires_at,
                pr_number=pr_number,
            )

            if self._validate_path_pattern(entry.path_pattern):
                self._exceptions.append(entry)
                count += 1

        return count

    def remove_expired(self) -> int:
        """Remove expired exceptions. Returns count removed."""
        now = datetime.now(timezone.utc)
        before = len(self._exceptions)
        self._exceptions = [
            e for e in self._exceptions if not e.is_expired(now)
        ]
        return before - len(self._exceptions)

    @property
    def exceptions(self) -> list[ExceptionEntry]:
        """Current exceptions (read-only copy)."""
        return list(self._exceptions)

    @staticmethod
    def _validate_path_pattern(pattern: str) -> bool:
        """Validate path_pattern doesn't escape workspace.

        Security (code-security/path-traversal):
        Reject patterns containing '..' or absolute paths.
        """
        if not pattern:
            return False
        if os.path.isabs(pattern):
            return False
        if ".." in pattern.split("/"):
            return False
        return True
