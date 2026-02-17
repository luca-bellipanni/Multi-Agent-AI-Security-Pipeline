"""Scan results artifact — structured output for cross-workflow use.

Produces scan-results.json with 4 sections:
  - confirmed: gate + agent agree (gate-validated)
  - warnings: disagreements (dismissed HIGH/CRIT, severity mismatch)
  - dismissed: noise accepted by agent
  - raw_findings: audit trail

Security (LLM05): all data is gate-validated. Severity from raw scanner,
confirmed cross-referenced against raw side channel. Agent claims are
context only (reason, recommendation), never authority.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone


SCAN_RESULTS_VERSION = "1.0"
SCAN_RESULTS_FILE = ".appsec/scan-results.json"


@dataclass
class ScanResults:
    """Structured scan results for PR reporting and remediation workflow."""
    version: str = SCAN_RESULTS_VERSION
    pr_number: int | None = None
    repository: str = ""
    timestamp: str = ""
    confirmed: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    dismissed: list[dict] = field(default_factory=list)
    raw_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "pr_number": self.pr_number,
            "repository": self.repository,
            "timestamp": self.timestamp,
            "confirmed": self.confirmed,
            "warnings": self.warnings,
            "dismissed": self.dismissed,
            "raw_findings": self.raw_findings,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def build_scan_results(
    decision,
    raw_findings: list,
    pr_number: int | None = None,
    repository: str = "",
) -> ScanResults:
    """Build ScanResults from a Decision object.

    Uses gate-validated structured data from Decision, not raw agent output.
    """
    # Raw findings as dicts for audit trail
    raw_dicts = []
    for f in raw_findings:
        raw_dicts.append({
            "finding_id": f.finding_id,
            "tool": f.tool,
            "rule_id": f.rule_id,
            "path": f.path,
            "line": f.line,
            "severity": f.severity.value,
            "message": f.message,
        })

    # Warnings: enrich safety_warnings with finding_id where possible
    warnings = []
    for w in decision.safety_warnings:
        warning_entry = dict(w)
        # Add finding_id if we can find the matching raw finding
        if "finding_id" not in warning_entry:
            for f in raw_findings:
                if (f.rule_id == w.get("rule_id")
                        and f.path == w.get("path")
                        and f.line == w.get("line")):
                    warning_entry["finding_id"] = f.finding_id
                    break
        warnings.append(warning_entry)

    return ScanResults(
        pr_number=pr_number,
        repository=repository,
        timestamp=datetime.now(timezone.utc).isoformat(),
        confirmed=decision.confirmed_findings,
        warnings=warnings,
        dismissed=decision.dismissed_findings,
        raw_findings=raw_dicts,
    )


def write_scan_results(scan_results: ScanResults, workspace: str) -> str:
    """Write scan-results.json to workspace. Returns file path."""
    file_path = os.path.join(workspace, SCAN_RESULTS_FILE)
    dir_path = os.path.dirname(file_path)
    os.makedirs(dir_path, exist_ok=True)

    with open(file_path, "w") as f:
        f.write(scan_results.to_json())
        f.write("\n")

    return file_path


def load_scan_results(path: str) -> ScanResults:
    """Load scan-results.json from disk.

    Raises FileNotFoundError or ValueError on errors.
    """
    with open(path) as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("scan-results.json root must be an object")

    version = data.get("version")
    if version != SCAN_RESULTS_VERSION:
        raise ValueError(
            f"Unsupported scan-results.json version: {version} "
            f"(expected {SCAN_RESULTS_VERSION})"
        )

    return ScanResults(
        version=version,
        pr_number=data.get("pr_number"),
        repository=data.get("repository", ""),
        timestamp=data.get("timestamp", ""),
        confirmed=data.get("confirmed", []),
        warnings=data.get("warnings", []),
        dismissed=data.get("dismissed", []),
        raw_findings=data.get("raw_findings", []),
    )
