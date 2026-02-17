"""Tests for the scan-results.json module.

Tests build_scan_results, write_scan_results, load_scan_results, and
the ScanResults dataclass. Verifies gate-validated data flows through
correctly and security properties hold (LLM05).
"""

import json
import os

from src.models import (
    Decision, Finding, Severity, ToolResult, Verdict,
)
from src.scan_results import (
    SCAN_RESULTS_FILE,
    SCAN_RESULTS_VERSION,
    ScanResults,
    build_scan_results,
    load_scan_results,
    write_scan_results,
)


# --- Helpers ---

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


def _make_decision(**overrides):
    defaults = dict(
        verdict=Verdict.MANUAL_REVIEW,
        continue_pipeline=False,
        max_severity=Severity.HIGH,
        selected_tools=["semgrep"],
        reason="Test reason",
        mode="enforce",
        findings_count=1,
        confirmed_findings=[{
            "finding_id": "Fabc123",
            "rule_id": "python.test.rule",
            "path": "src/app.py",
            "line": 10,
            "severity": "high",
            "message": "Test finding",
            "agent_reason": "Real SQL injection",
            "agent_recommendation": "Use parameterized queries",
        }],
        dismissed_findings=[{
            "rule_id": "noise.rule",
            "reason": "test file",
        }],
        safety_warnings=[],
    )
    defaults.update(overrides)
    return Decision(**defaults)


# --- ScanResults dataclass ---

class TestScanResultsDataclass:

    def test_defaults(self):
        sr = ScanResults()
        assert sr.version == SCAN_RESULTS_VERSION
        assert sr.pr_number is None
        assert sr.repository == ""
        assert sr.confirmed == []
        assert sr.warnings == []
        assert sr.dismissed == []
        assert sr.raw_findings == []

    def test_to_dict(self):
        sr = ScanResults(
            pr_number=42,
            repository="owner/repo",
            timestamp="2025-01-15T10:00:00Z",
            confirmed=[{"rule_id": "a"}],
            warnings=[{"type": "severity_mismatch"}],
            dismissed=[{"rule_id": "b"}],
            raw_findings=[{"rule_id": "c"}],
        )
        d = sr.to_dict()
        assert d["version"] == SCAN_RESULTS_VERSION
        assert d["pr_number"] == 42
        assert d["repository"] == "owner/repo"
        assert len(d["confirmed"]) == 1
        assert len(d["warnings"]) == 1
        assert len(d["dismissed"]) == 1
        assert len(d["raw_findings"]) == 1

    def test_to_json_valid(self):
        sr = ScanResults(pr_number=42, repository="o/r")
        parsed = json.loads(sr.to_json())
        assert parsed["version"] == SCAN_RESULTS_VERSION
        assert parsed["pr_number"] == 42

    def test_to_json_roundtrip(self):
        sr = ScanResults(
            pr_number=7,
            repository="test/repo",
            timestamp="2025-01-01T00:00:00Z",
            confirmed=[{"finding_id": "F123456", "rule_id": "sqli"}],
        )
        parsed = json.loads(sr.to_json())
        assert parsed["confirmed"][0]["finding_id"] == "F123456"


# --- build_scan_results ---

class TestBuildScanResults:

    def test_basic_build(self):
        decision = _make_decision()
        raw = [_make_finding(rule_id="python.test.rule")]
        sr = build_scan_results(decision, raw, pr_number=42, repository="o/r")

        assert sr.pr_number == 42
        assert sr.repository == "o/r"
        assert sr.version == SCAN_RESULTS_VERSION
        assert sr.timestamp != ""

    def test_confirmed_from_decision(self):
        decision = _make_decision()
        raw = [_make_finding()]
        sr = build_scan_results(decision, raw)

        assert len(sr.confirmed) == 1
        assert sr.confirmed[0]["rule_id"] == "python.test.rule"

    def test_dismissed_from_decision(self):
        decision = _make_decision()
        raw = [_make_finding()]
        sr = build_scan_results(decision, raw)

        assert len(sr.dismissed) == 1
        assert sr.dismissed[0]["rule_id"] == "noise.rule"

    def test_raw_findings_serialized(self):
        raw = [
            _make_finding(Severity.HIGH, rule_id="rule.a", path="a.py", line=1),
            _make_finding(Severity.LOW, rule_id="rule.b", path="b.py", line=5),
        ]
        decision = _make_decision()
        sr = build_scan_results(decision, raw)

        assert len(sr.raw_findings) == 2
        assert sr.raw_findings[0]["rule_id"] == "rule.a"
        assert sr.raw_findings[0]["severity"] == "high"
        assert sr.raw_findings[0]["finding_id"] == raw[0].finding_id
        assert sr.raw_findings[1]["rule_id"] == "rule.b"
        assert sr.raw_findings[1]["severity"] == "low"

    def test_warnings_from_safety_warnings(self):
        decision = _make_decision(
            safety_warnings=[{
                "type": "dismissed_high_severity",
                "rule_id": "bad.rule",
                "severity": "high",
                "path": "src/bad.py",
                "line": 42,
                "message": "Agent dismissed HIGH finding",
            }],
        )
        raw = [_make_finding(rule_id="bad.rule", path="src/bad.py", line=42)]
        sr = build_scan_results(decision, raw)

        assert len(sr.warnings) == 1
        assert sr.warnings[0]["type"] == "dismissed_high_severity"
        # Should have finding_id enriched from raw finding match
        assert "finding_id" in sr.warnings[0]

    def test_warnings_enriched_with_finding_id(self):
        """Warnings get finding_id by matching rule_id+path+line to raw."""
        raw_finding = _make_finding(
            rule_id="sqli.vuln", path="db.py", line=50,
        )
        decision = _make_decision(
            safety_warnings=[{
                "type": "severity_mismatch",
                "rule_id": "sqli.vuln",
                "path": "db.py",
                "line": 50,
                "message": "severity mismatch",
            }],
        )
        sr = build_scan_results(decision, [raw_finding])

        assert sr.warnings[0]["finding_id"] == raw_finding.finding_id

    def test_warnings_no_match_no_finding_id(self):
        """If warning can't match a raw finding, no finding_id added."""
        decision = _make_decision(
            safety_warnings=[{
                "type": "severity_mismatch",
                "rule_id": "orphan.rule",
                "path": "x.py",
                "line": 1,
                "message": "no match",
            }],
        )
        sr = build_scan_results(decision, [])

        assert len(sr.warnings) == 1
        assert "finding_id" not in sr.warnings[0]

    def test_empty_decision(self):
        decision = _make_decision(
            confirmed_findings=[],
            dismissed_findings=[],
            safety_warnings=[],
            findings_count=0,
        )
        sr = build_scan_results(decision, [])

        assert sr.confirmed == []
        assert sr.dismissed == []
        assert sr.warnings == []
        assert sr.raw_findings == []


# --- write_scan_results ---

class TestWriteScanResults:

    def test_writes_file(self, tmp_path):
        sr = ScanResults(pr_number=42, repository="o/r", timestamp="now")
        path = write_scan_results(sr, str(tmp_path))

        assert os.path.isfile(path)
        assert path.endswith(SCAN_RESULTS_FILE)

    def test_creates_directory(self, tmp_path):
        workspace = str(tmp_path / "deep" / "nested")
        sr = ScanResults(pr_number=1)
        path = write_scan_results(sr, workspace)

        assert os.path.isfile(path)

    def test_content_is_valid_json(self, tmp_path):
        sr = ScanResults(
            pr_number=42,
            confirmed=[{"rule_id": "test"}],
        )
        path = write_scan_results(sr, str(tmp_path))

        with open(path) as f:
            data = json.load(f)
        assert data["version"] == SCAN_RESULTS_VERSION
        assert data["pr_number"] == 42
        assert len(data["confirmed"]) == 1

    def test_file_ends_with_newline(self, tmp_path):
        sr = ScanResults()
        path = write_scan_results(sr, str(tmp_path))

        with open(path) as f:
            content = f.read()
        assert content.endswith("\n")

    def test_returns_correct_path(self, tmp_path):
        sr = ScanResults()
        path = write_scan_results(sr, str(tmp_path))

        expected = os.path.join(str(tmp_path), SCAN_RESULTS_FILE)
        assert path == expected


# --- load_scan_results ---

class TestLoadScanResults:

    def _write_json(self, tmp_path, data):
        path = tmp_path / "scan-results.json"
        path.write_text(json.dumps(data))
        return str(path)

    def test_loads_valid_file(self, tmp_path):
        data = {
            "version": SCAN_RESULTS_VERSION,
            "pr_number": 42,
            "repository": "o/r",
            "timestamp": "2025-01-15T10:00:00Z",
            "confirmed": [{"rule_id": "a"}],
            "warnings": [],
            "dismissed": [],
            "raw_findings": [{"rule_id": "b"}],
        }
        path = self._write_json(tmp_path, data)
        sr = load_scan_results(path)

        assert sr.version == SCAN_RESULTS_VERSION
        assert sr.pr_number == 42
        assert sr.repository == "o/r"
        assert len(sr.confirmed) == 1
        assert len(sr.raw_findings) == 1

    def test_missing_file_raises(self, tmp_path):
        import pytest
        with pytest.raises(FileNotFoundError):
            load_scan_results(str(tmp_path / "nonexistent.json"))

    def test_invalid_json_raises(self, tmp_path):
        import pytest
        path = tmp_path / "bad.json"
        path.write_text("not json")
        with pytest.raises(json.JSONDecodeError):
            load_scan_results(str(path))

    def test_wrong_version_raises(self, tmp_path):
        import pytest
        data = {"version": "99.0"}
        path = self._write_json(tmp_path, data)
        with pytest.raises(ValueError, match="Unsupported"):
            load_scan_results(path)

    def test_not_object_raises(self, tmp_path):
        import pytest
        path = tmp_path / "array.json"
        path.write_text("[]")
        with pytest.raises(ValueError, match="root must be an object"):
            load_scan_results(path)

    def test_missing_optional_fields_use_defaults(self, tmp_path):
        data = {"version": SCAN_RESULTS_VERSION}
        path = self._write_json(tmp_path, data)
        sr = load_scan_results(path)

        assert sr.pr_number is None
        assert sr.repository == ""
        assert sr.confirmed == []
        assert sr.warnings == []
        assert sr.dismissed == []
        assert sr.raw_findings == []


# --- Roundtrip: build → write → load ---

class TestRoundtrip:

    def test_full_roundtrip(self, tmp_path):
        raw = [
            _make_finding(Severity.HIGH, rule_id="rule.a", path="a.py", line=1),
            _make_finding(Severity.LOW, rule_id="rule.b", path="b.py", line=5),
        ]
        decision = _make_decision(
            confirmed_findings=[{
                "finding_id": raw[0].finding_id,
                "rule_id": "rule.a",
                "path": "a.py",
                "line": 1,
                "severity": "high",
                "message": "msg",
                "agent_reason": "real",
                "agent_recommendation": "fix it",
            }],
            dismissed_findings=[{"rule_id": "rule.b", "reason": "noise"}],
            safety_warnings=[],
        )

        sr = build_scan_results(decision, raw, pr_number=42, repository="o/r")
        path = write_scan_results(sr, str(tmp_path))
        loaded = load_scan_results(path)

        assert loaded.pr_number == 42
        assert loaded.repository == "o/r"
        assert len(loaded.confirmed) == 1
        assert loaded.confirmed[0]["rule_id"] == "rule.a"
        assert len(loaded.dismissed) == 1
        assert len(loaded.raw_findings) == 2
