"""Tests for the exception memory module.

Tests the MemoryStore that persists known false-positive patterns
in .appsec/exceptions.json. Covers loading, saving, matching,
auto-adding, expiration, and security (path traversal, severity cap).
"""

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.memory import (
    AUTO_EXCEPTION_TTL_DAYS,
    EXCEPTIONS_FILE,
    EXCEPTIONS_VERSION,
    ExceptionEntry,
    ExceptionSource,
    MemoryStore,
)
from src.models import Finding, Severity, Verdict, ToolResult
from src.github_context import GitHubContext
from src.decision_engine import DecisionEngine


# --- Test helpers ---

def _make_exception(**overrides) -> ExceptionEntry:
    """Create an ExceptionEntry with sensible defaults."""
    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_id="python.test.rule",
        path_pattern="src/**",
        reason="Known FP in test utils",
        source=ExceptionSource.AUTO,
        severity_cap=Severity.MEDIUM,
        created_at=now.isoformat(),
        expires_at=(now + timedelta(days=90)).isoformat(),
        pr_number=42,
    )
    defaults.update(overrides)
    return ExceptionEntry(**defaults)


def _make_finding(
    severity=Severity.HIGH, rule_id="python.test.rule", **overrides,
) -> Finding:
    """Create a Finding with sensible defaults."""
    defaults = dict(
        tool="semgrep",
        rule_id=rule_id,
        path="src/app.py",
        line=10,
        severity=severity,
        message="Test finding",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_exceptions_file(tmp_path, exceptions=None, version=EXCEPTIONS_VERSION):
    """Write a valid exceptions file to tmp_path/.appsec/exceptions.json."""
    appsec_dir = tmp_path / ".appsec"
    appsec_dir.mkdir(exist_ok=True)
    data = {
        "version": version,
        "metadata": {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "repository": "owner/repo",
        },
        "exceptions": [
            e.to_dict() if isinstance(e, ExceptionEntry) else e
            for e in (exceptions or [])
        ],
    }
    path = appsec_dir / "exceptions.json"
    path.write_text(json.dumps(data, indent=2) + "\n")
    return path


def _make_tool_result(findings=None, success=True):
    return ToolResult(
        tool="semgrep",
        success=success,
        findings=findings or [],
    )


def _make_context(mode="enforce", workspace="/tmp/test", **overrides):
    defaults = dict(
        token="test-token",
        mode=mode,
        workspace=workspace,
        repository="owner/repo",
        event_name="pull_request",
        sha="abc123",
        ref="refs/pull/42/merge",
        pr_number=42,
        is_pull_request=True,
    )
    defaults.update(overrides)
    return GitHubContext(**defaults)


def _make_triage(**overrides):
    defaults = dict(
        context={
            "languages": ["python"],
            "files_changed": 3,
            "risk_areas": ["auth"],
            "has_dependency_changes": False,
            "has_iac_changes": False,
            "change_summary": "auth changes",
        },
        recommended_agents=["appsec"],
        reason="Security-relevant changes",
    )
    defaults.update(overrides)
    return defaults


def _empty_analysis():
    return {
        "confirmed": [],
        "dismissed": [],
        "summary": "",
        "findings_analyzed": 0,
        "rulesets_used": [],
        "rulesets_rationale": "",
        "risk_assessment": "",
    }


# --- ExceptionEntry tests ---

class TestExceptionEntry:
    """Test ExceptionEntry matching, expiration, and serialization."""

    def test_matches_exact_rule_and_path(self):
        """Exact rule_id + path within glob → matches."""
        exc = _make_exception(rule_id="xss.rule", path_pattern="src/**")
        finding = _make_finding(
            Severity.LOW, rule_id="xss.rule", path="src/app.py",
        )
        assert exc.matches(finding) is True

    def test_no_match_different_rule_id(self):
        """Different rule_id → no match."""
        exc = _make_exception(rule_id="xss.rule")
        finding = _make_finding(rule_id="sqli.rule")
        assert exc.matches(finding) is False

    def test_matches_glob_pattern(self):
        """Glob pattern tests/** matches nested paths."""
        exc = _make_exception(
            rule_id="test.rule",
            path_pattern="tests/**",
            severity_cap=Severity.MEDIUM,
        )
        finding = _make_finding(
            Severity.LOW, rule_id="test.rule", path="tests/unit/test_app.py",
        )
        assert exc.matches(finding) is True

    def test_no_match_path_outside_glob(self):
        """Path outside glob pattern → no match."""
        exc = _make_exception(path_pattern="tests/**")
        finding = _make_finding(path="src/app.py")
        assert exc.matches(finding) is False

    def test_severity_cap_blocks_high(self):
        """Finding severity HIGH > cap MEDIUM → no match."""
        exc = _make_exception(severity_cap=Severity.MEDIUM)
        finding = _make_finding(Severity.HIGH)
        assert exc.matches(finding) is False

    def test_severity_cap_allows_low(self):
        """Finding severity LOW ≤ cap MEDIUM → matches."""
        exc = _make_exception(severity_cap=Severity.MEDIUM)
        finding = _make_finding(Severity.LOW)
        assert exc.matches(finding) is True

    def test_severity_cap_allows_exact(self):
        """Finding severity == cap → matches."""
        exc = _make_exception(severity_cap=Severity.MEDIUM)
        finding = _make_finding(Severity.MEDIUM)
        assert exc.matches(finding) is True

    def test_is_expired_past_date(self):
        """Expiry in the past → expired."""
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        exc = _make_exception(expires_at=past)
        assert exc.is_expired() is True

    def test_is_expired_future_date(self):
        """Expiry in the future → not expired."""
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        exc = _make_exception(expires_at=future)
        assert exc.is_expired() is False

    def test_is_expired_none_never_expires(self):
        """expires_at=None (manual) → never expires."""
        exc = _make_exception(expires_at=None)
        assert exc.is_expired() is False

    def test_is_expired_corrupt_date(self):
        """Corrupt date string → treated as expired (fail-secure)."""
        exc = _make_exception(expires_at="not-a-date")
        assert exc.is_expired() is True

    def test_to_dict_roundtrip(self):
        """to_dict → from_dict produces equivalent entry."""
        original = _make_exception(
            rule_id="roundtrip.rule",
            path_pattern="src/*.py",
            reason="Test roundtrip",
            source=ExceptionSource.MANUAL,
            severity_cap=Severity.LOW,
            pr_number=None,
            expires_at=None,
        )
        rebuilt = ExceptionEntry.from_dict(original.to_dict())
        assert rebuilt.rule_id == original.rule_id
        assert rebuilt.path_pattern == original.path_pattern
        assert rebuilt.reason == original.reason
        assert rebuilt.source == original.source
        assert rebuilt.severity_cap == original.severity_cap
        assert rebuilt.expires_at == original.expires_at
        assert rebuilt.pr_number == original.pr_number

    def test_from_dict_missing_rule_id(self):
        """Missing rule_id → ValueError."""
        with pytest.raises(ValueError, match="rule_id"):
            ExceptionEntry.from_dict({"path_pattern": "src/**"})

    def test_from_dict_missing_path_pattern(self):
        """Missing path_pattern → ValueError."""
        with pytest.raises(ValueError, match="path_pattern"):
            ExceptionEntry.from_dict({"rule_id": "test.rule"})

    def test_from_dict_invalid_source(self):
        """Invalid source value → ValueError."""
        with pytest.raises(ValueError, match="source"):
            ExceptionEntry.from_dict({
                "rule_id": "test.rule",
                "path_pattern": "src/**",
                "source": "unknown",
            })

    def test_from_dict_invalid_severity_cap(self):
        """Invalid severity_cap → ValueError."""
        with pytest.raises(ValueError, match="severity_cap"):
            ExceptionEntry.from_dict({
                "rule_id": "test.rule",
                "path_pattern": "src/**",
                "severity_cap": "super_high",
            })


# --- MemoryStore load tests ---

class TestMemoryStoreLoad:
    """Test loading exceptions from disk."""

    def test_load_valid_file(self, tmp_path):
        """Valid file with 2 exceptions → both loaded."""
        exc1 = _make_exception(rule_id="rule.1", path_pattern="src/**")
        exc2 = _make_exception(rule_id="rule.2", path_pattern="tests/**")
        _make_exceptions_file(tmp_path, [exc1, exc2])

        store = MemoryStore(str(tmp_path), "owner/repo")
        warnings = store.load()
        assert warnings == []
        assert len(store.exceptions) == 2

    def test_load_missing_file(self, tmp_path):
        """Missing file → no exceptions, no warnings (normal first run)."""
        store = MemoryStore(str(tmp_path), "owner/repo")
        warnings = store.load()
        assert warnings == []
        assert len(store.exceptions) == 0

    def test_load_corrupt_json(self, tmp_path):
        """Invalid JSON → no exceptions + warning."""
        appsec_dir = tmp_path / ".appsec"
        appsec_dir.mkdir()
        (appsec_dir / "exceptions.json").write_text("{broken json")

        store = MemoryStore(str(tmp_path))
        warnings = store.load()
        assert len(warnings) == 1
        assert "Corrupt" in warnings[0]
        assert len(store.exceptions) == 0

    def test_load_wrong_version(self, tmp_path):
        """Wrong version → no exceptions + warning."""
        _make_exceptions_file(tmp_path, [], version="99.0")

        store = MemoryStore(str(tmp_path))
        warnings = store.load()
        assert len(warnings) == 1
        assert "Unsupported" in warnings[0]
        assert len(store.exceptions) == 0

    def test_load_invalid_entry_skipped(self, tmp_path):
        """One invalid + one valid → valid loaded, warning for invalid."""
        valid = _make_exception(rule_id="valid.rule")
        invalid = {"rule_id": ""}  # empty rule_id
        _make_exceptions_file(tmp_path, [invalid, valid])

        store = MemoryStore(str(tmp_path))
        warnings = store.load()
        assert len(warnings) == 1
        assert "Exception #0" in warnings[0]
        assert len(store.exceptions) == 1
        assert store.exceptions[0].rule_id == "valid.rule"

    def test_load_not_dict_root(self, tmp_path):
        """Root is array → warning."""
        appsec_dir = tmp_path / ".appsec"
        appsec_dir.mkdir()
        (appsec_dir / "exceptions.json").write_text("[]")

        store = MemoryStore(str(tmp_path))
        warnings = store.load()
        assert len(warnings) == 1
        assert "root must be object" in warnings[0]

    def test_load_path_traversal_rejected(self, tmp_path):
        """Exception with '../' in path_pattern → skipped with warning."""
        exc = _make_exception(path_pattern="../../../etc/passwd")
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        warnings = store.load()
        assert len(warnings) == 1
        assert "invalid path_pattern" in warnings[0]
        assert len(store.exceptions) == 0

    def test_load_io_error(self, tmp_path):
        """Unreadable file → warning."""
        appsec_dir = tmp_path / ".appsec"
        appsec_dir.mkdir()
        exc_file = appsec_dir / "exceptions.json"
        exc_file.write_text("{}")
        exc_file.chmod(0o000)

        store = MemoryStore(str(tmp_path))
        warnings = store.load()

        # Restore permissions for cleanup
        exc_file.chmod(0o644)

        assert len(warnings) == 1
        assert "Could not read" in warnings[0]


# --- MemoryStore match/filter tests ---

class TestMemoryStoreMatch:
    """Test finding matching and filtering."""

    def test_match_finding_exact(self, tmp_path):
        """Exact match returns exception."""
        exc = _make_exception(
            rule_id="match.rule", path_pattern="src/app.py",
            severity_cap=Severity.MEDIUM,
        )
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        store.load()

        finding = _make_finding(Severity.LOW, rule_id="match.rule", path="src/app.py")
        result = store.match_finding(finding)
        assert result is not None
        assert result.rule_id == "match.rule"

    def test_match_finding_no_match(self, tmp_path):
        """No matching exception → None."""
        exc = _make_exception(rule_id="other.rule")
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        store.load()

        finding = _make_finding(rule_id="unrelated.rule")
        assert store.match_finding(finding) is None

    def test_match_expired_skipped(self, tmp_path):
        """Expired exception → not matched."""
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        exc = _make_exception(
            rule_id="expired.rule", path_pattern="src/**",
            severity_cap=Severity.MEDIUM, expires_at=past,
        )
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        store.load()

        finding = _make_finding(
            Severity.LOW, rule_id="expired.rule", path="src/app.py",
        )
        assert store.match_finding(finding) is None

    def test_match_severity_cap_honored(self, tmp_path):
        """Finding severity > cap → no match."""
        exc = _make_exception(
            rule_id="cap.rule", path_pattern="src/**",
            severity_cap=Severity.LOW,
        )
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        store.load()

        finding = _make_finding(
            Severity.MEDIUM, rule_id="cap.rule", path="src/app.py",
        )
        assert store.match_finding(finding) is None

    def test_filter_separates_remaining_excepted(self, tmp_path):
        """3 findings, 1 matches exception → remaining=2, excepted=1."""
        exc = _make_exception(
            rule_id="noise.rule", path_pattern="src/**",
            severity_cap=Severity.LOW,
        )
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        store.load()

        findings = [
            _make_finding(Severity.LOW, rule_id="noise.rule", path="src/a.py"),
            _make_finding(Severity.HIGH, rule_id="real.vuln", path="src/b.py"),
            _make_finding(Severity.MEDIUM, rule_id="other.rule", path="src/c.py"),
        ]
        remaining, excepted = store.filter_findings(findings)
        assert len(remaining) == 2
        assert len(excepted) == 1
        assert excepted[0]["rule_id"] == "noise.rule"

    def test_filter_never_removes_high_critical(self, tmp_path):
        """HIGH/CRITICAL findings stay in remaining even with matching exception.

        Security (LLM05): HIGH/CRITICAL are NEVER auto-excepted.
        """
        exc_high = _make_exception(
            rule_id="high.rule", path_pattern="src/**",
            severity_cap=Severity.HIGH,
            source=ExceptionSource.MANUAL,
        )
        exc_crit = _make_exception(
            rule_id="crit.rule", path_pattern="src/**",
            severity_cap=Severity.CRITICAL,
            source=ExceptionSource.MANUAL,
        )
        _make_exceptions_file(tmp_path, [exc_high, exc_crit])

        store = MemoryStore(str(tmp_path))
        store.load()

        findings = [
            _make_finding(Severity.HIGH, rule_id="high.rule", path="src/a.py"),
            _make_finding(Severity.CRITICAL, rule_id="crit.rule", path="src/b.py"),
        ]
        remaining, excepted = store.filter_findings(findings)
        assert len(remaining) == 2  # Both stay
        assert len(excepted) == 0


# --- MemoryStore auto-add tests ---

class TestMemoryStoreAutoAdd:
    """Test auto-exception creation from agent dismissals."""

    def _store(self, tmp_path):
        store = MemoryStore(str(tmp_path))
        return store

    def test_auto_add_low(self, tmp_path):
        """Dismissed LOW finding → new auto-exception created."""
        store = self._store(tmp_path)
        raw = [_make_finding(Severity.LOW, rule_id="noise.low", path="src/a.py")]
        dismissed = [{"rule_id": "noise.low", "reason": "test file"}]

        count = store.add_auto_exceptions(dismissed, raw, pr_number=42)
        assert count == 1
        assert len(store.exceptions) == 1
        assert store.exceptions[0].rule_id == "noise.low"
        assert store.exceptions[0].source == ExceptionSource.AUTO

    def test_auto_add_medium(self, tmp_path):
        """Dismissed MEDIUM finding → new auto-exception created."""
        store = self._store(tmp_path)
        raw = [_make_finding(Severity.MEDIUM, rule_id="noise.med", path="src/b.py")]
        dismissed = [{"rule_id": "noise.med", "reason": "informational"}]

        count = store.add_auto_exceptions(dismissed, raw, pr_number=42)
        assert count == 1
        assert store.exceptions[0].severity_cap == Severity.MEDIUM

    def test_auto_add_high_rejected(self, tmp_path):
        """Dismissed HIGH finding → NOT auto-excepted.

        Security (LLM05): only LOW/MEDIUM can be auto-excepted.
        """
        store = self._store(tmp_path)
        raw = [_make_finding(Severity.HIGH, rule_id="real.high")]
        dismissed = [{"rule_id": "real.high", "reason": "safe"}]

        count = store.add_auto_exceptions(dismissed, raw, pr_number=42)
        assert count == 0

    def test_auto_add_critical_rejected(self, tmp_path):
        """Dismissed CRITICAL finding → NOT auto-excepted."""
        store = self._store(tmp_path)
        raw = [_make_finding(Severity.CRITICAL, rule_id="real.crit")]
        dismissed = [{"rule_id": "real.crit", "reason": "safe"}]

        count = store.add_auto_exceptions(dismissed, raw, pr_number=42)
        assert count == 0

    def test_auto_add_hallucinated_rejected(self, tmp_path):
        """Dismissed rule not in raw findings → NOT created.

        Security (LLM05): anti-hallucination check.
        """
        store = self._store(tmp_path)
        raw = [_make_finding(Severity.LOW, rule_id="real.rule")]
        dismissed = [{"rule_id": "phantom.rule", "reason": "imagined"}]

        count = store.add_auto_exceptions(dismissed, raw, pr_number=42)
        assert count == 0

    def test_auto_add_already_excepted(self, tmp_path):
        """Already excepted finding → NOT duplicated."""
        exc = _make_exception(
            rule_id="dup.rule", path_pattern="src/app.py",
            severity_cap=Severity.LOW,
        )
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        store.load()

        raw = [_make_finding(Severity.LOW, rule_id="dup.rule", path="src/app.py")]
        dismissed = [{"rule_id": "dup.rule", "reason": "already known"}]

        count = store.add_auto_exceptions(dismissed, raw, pr_number=42)
        assert count == 0

    def test_auto_add_sets_90_day_expiry(self, tmp_path):
        """Auto-exception has expires_at ~90 days from now."""
        store = self._store(tmp_path)
        raw = [_make_finding(Severity.LOW, rule_id="ttl.rule", path="src/x.py")]
        dismissed = [{"rule_id": "ttl.rule", "reason": "test noise"}]

        store.add_auto_exceptions(dismissed, raw, pr_number=1)

        exc = store.exceptions[0]
        assert exc.expires_at is not None
        expiry = datetime.fromisoformat(exc.expires_at)
        now = datetime.now(timezone.utc)
        delta = expiry - now
        assert AUTO_EXCEPTION_TTL_DAYS - 1 <= delta.days <= AUTO_EXCEPTION_TTL_DAYS

    def test_auto_add_invalid_dismissed_entries_skipped(self, tmp_path):
        """Non-dict and missing rule_id entries are silently skipped."""
        store = self._store(tmp_path)
        raw = [_make_finding(Severity.LOW, rule_id="valid.rule", path="src/a.py")]
        dismissed = [
            "not a dict",
            {"no_rule_id": "missing"},
            {"rule_id": 123},  # not a string
            {"rule_id": "valid.rule", "reason": "ok"},
        ]

        count = store.add_auto_exceptions(dismissed, raw, pr_number=42)
        assert count == 1  # Only the last valid one


# --- MemoryStore save tests ---

class TestMemoryStoreSave:
    """Test saving exceptions to disk."""

    def test_save_creates_directory(self, tmp_path):
        """Save creates .appsec/ if missing."""
        store = MemoryStore(str(tmp_path), "owner/repo")
        store.save()

        assert (tmp_path / ".appsec").is_dir()
        assert (tmp_path / ".appsec" / "exceptions.json").is_file()

    def test_save_writes_valid_json(self, tmp_path):
        """Saved file is valid JSON with correct version."""
        store = MemoryStore(str(tmp_path), "owner/repo")
        store.save()

        data = json.loads(
            (tmp_path / ".appsec" / "exceptions.json").read_text()
        )
        assert data["version"] == EXCEPTIONS_VERSION
        assert data["metadata"]["repository"] == "owner/repo"
        assert isinstance(data["exceptions"], list)

    def test_save_roundtrip(self, tmp_path):
        """Save then load → same exceptions."""
        store = MemoryStore(str(tmp_path), "owner/repo")
        raw = [_make_finding(Severity.LOW, rule_id="rt.rule", path="src/a.py")]
        store.add_auto_exceptions(
            [{"rule_id": "rt.rule", "reason": "roundtrip"}],
            raw, pr_number=10,
        )
        store.save()

        store2 = MemoryStore(str(tmp_path), "owner/repo")
        store2.load()
        assert len(store2.exceptions) == 1
        assert store2.exceptions[0].rule_id == "rt.rule"
        assert store2.exceptions[0].pr_number == 10


# --- MemoryStore remove_expired tests ---

class TestMemoryStoreExpiration:
    """Test expired exception removal."""

    def test_remove_expired_removes_old(self, tmp_path):
        """Expired exceptions are removed."""
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        exc_old = _make_exception(rule_id="old", expires_at=past)
        exc_new = _make_exception(rule_id="new", expires_at=future)
        _make_exceptions_file(tmp_path, [exc_old, exc_new])

        store = MemoryStore(str(tmp_path))
        store.load()
        assert len(store.exceptions) == 2

        removed = store.remove_expired()
        assert removed == 1
        assert len(store.exceptions) == 1
        assert store.exceptions[0].rule_id == "new"

    def test_remove_expired_keeps_manual(self, tmp_path):
        """Manual exceptions (expires_at=None) are never removed."""
        exc = _make_exception(
            rule_id="manual", source=ExceptionSource.MANUAL,
            expires_at=None,
        )
        _make_exceptions_file(tmp_path, [exc])

        store = MemoryStore(str(tmp_path))
        store.load()

        removed = store.remove_expired()
        assert removed == 0
        assert len(store.exceptions) == 1


# --- Path traversal security ---

class TestPathTraversal:
    """Test path traversal prevention in exceptions."""

    def test_absolute_path_rejected(self):
        assert MemoryStore._validate_path_pattern("/etc/passwd") is False

    def test_dotdot_rejected(self):
        assert MemoryStore._validate_path_pattern("../../secret") is False

    def test_normal_path_accepted(self):
        assert MemoryStore._validate_path_pattern("src/app.py") is True

    def test_glob_pattern_accepted(self):
        assert MemoryStore._validate_path_pattern("tests/**") is True

    def test_empty_pattern_rejected(self):
        assert MemoryStore._validate_path_pattern("") is False

    def test_dotdot_in_middle_rejected(self):
        assert MemoryStore._validate_path_pattern("src/../etc/passwd") is False


# --- Gate integration tests ---

class TestGateWithExceptions:
    """Test exception memory integrated with the decision engine gate.

    Uses DecisionEngine._apply_gate() directly with exception files.
    """

    def _gate(self, tmp_path, findings, analysis, exceptions=None, mode="enforce"):
        if exceptions is not None:
            _make_exceptions_file(tmp_path, exceptions)

        engine = DecisionEngine()
        tr = _make_tool_result(findings)
        ctx = _make_context(mode=mode, workspace=str(tmp_path))
        return engine._apply_gate(
            ctx, _make_triage(), [tr], analysis,
        )

    def test_excepted_low_not_in_effective(self, tmp_path):
        """Excepted LOW finding → removed from effective → ALLOWED."""
        exc = _make_exception(
            rule_id="noise.rule", path_pattern="src/app.py",
            severity_cap=Severity.LOW,
        )
        raw = [_make_finding(Severity.LOW, rule_id="noise.rule", path="src/app.py")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "noise.rule", "reason": "noise"}],
            "findings_analyzed": 1,
        }
        d = self._gate(tmp_path, raw, analysis, exceptions=[exc])
        assert d.verdict == Verdict.ALLOWED
        assert d.findings_count == 0

    def test_high_never_excepted(self, tmp_path):
        """HIGH finding with matching exception → still in effective.

        Security (LLM05): HIGH/CRITICAL never auto-excepted.
        """
        exc = _make_exception(
            rule_id="high.rule", path_pattern="src/**",
            severity_cap=Severity.HIGH,
            source=ExceptionSource.MANUAL,
        )
        raw = [_make_finding(Severity.HIGH, rule_id="high.rule", path="src/app.py")]
        analysis = {
            "confirmed": [{"rule_id": "high.rule", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(tmp_path, raw, analysis, exceptions=[exc])
        assert d.verdict == Verdict.MANUAL_REVIEW

    def test_critical_never_excepted(self, tmp_path):
        """CRITICAL finding with matching exception → still BLOCKED."""
        exc = _make_exception(
            rule_id="crit.rule", path_pattern="src/**",
            severity_cap=Severity.CRITICAL,
            source=ExceptionSource.MANUAL,
        )
        raw = [_make_finding(Severity.CRITICAL, rule_id="crit.rule", path="src/app.py")]
        analysis = {
            "confirmed": [{"rule_id": "crit.rule", "severity": "CRITICAL"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(tmp_path, raw, analysis, exceptions=[exc])
        assert d.verdict == Verdict.BLOCKED

    def test_missing_file_no_effect(self, tmp_path):
        """No exceptions file → gate works normally."""
        raw = [_make_finding(Severity.HIGH, rule_id="real.vuln")]
        analysis = {
            "confirmed": [{"rule_id": "real.vuln", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        d = self._gate(tmp_path, raw, analysis, exceptions=None)
        assert d.verdict == Verdict.MANUAL_REVIEW

    def test_corrupt_file_no_effect(self, tmp_path):
        """Corrupt exceptions file → gate works normally + warning."""
        appsec_dir = tmp_path / ".appsec"
        appsec_dir.mkdir()
        (appsec_dir / "exceptions.json").write_text("{broken")

        raw = [_make_finding(Severity.HIGH, rule_id="real.vuln")]
        analysis = {
            "confirmed": [{"rule_id": "real.vuln", "severity": "HIGH"}],
            "dismissed": [],
            "findings_analyzed": 1,
        }
        engine = DecisionEngine()
        tr = _make_tool_result(raw)
        ctx = _make_context(workspace=str(tmp_path))
        d = engine._apply_gate(ctx, _make_triage(), [tr], analysis)
        assert d.verdict == Verdict.MANUAL_REVIEW

    def test_excepted_in_report(self, tmp_path):
        """Excepted findings shown in analysis report."""
        exc = _make_exception(
            rule_id="noise.rule", path_pattern="src/app.py",
            severity_cap=Severity.LOW,
        )
        raw = [_make_finding(Severity.LOW, rule_id="noise.rule", path="src/app.py")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "noise.rule", "reason": "fp"}],
            "findings_analyzed": 1,
        }
        d = self._gate(tmp_path, raw, analysis, exceptions=[exc])
        assert "Auto-Excepted" in d.analysis_report
        assert "noise.rule" in d.analysis_report

    def test_auto_exceptions_created(self, tmp_path):
        """After analysis, dismissed LOW creates new auto-exception."""
        raw = [
            _make_finding(Severity.LOW, rule_id="new.fp", path="src/a.py"),
            _make_finding(Severity.HIGH, rule_id="real.vuln", path="src/b.py"),
        ]
        analysis = {
            "confirmed": [{"rule_id": "real.vuln", "severity": "HIGH"}],
            "dismissed": [{"rule_id": "new.fp", "reason": "noise"}],
            "findings_analyzed": 2,
        }

        engine = DecisionEngine()
        tr = _make_tool_result(raw)
        ctx = _make_context(workspace=str(tmp_path))
        engine._apply_gate(ctx, _make_triage(), [tr], analysis)

        # Check memory store was populated
        assert engine._memory_store is not None
        assert len(engine._memory_store.exceptions) == 1
        assert engine._memory_store.exceptions[0].rule_id == "new.fp"

    def test_excepted_count_in_decision(self, tmp_path):
        """Decision includes excepted_count."""
        exc = _make_exception(
            rule_id="exc.rule", path_pattern="src/**",
            severity_cap=Severity.LOW,
        )
        raw = [_make_finding(Severity.LOW, rule_id="exc.rule", path="src/a.py")]
        analysis = {
            "confirmed": [],
            "dismissed": [{"rule_id": "exc.rule", "reason": "known"}],
            "findings_analyzed": 1,
        }
        d = self._gate(tmp_path, raw, analysis, exceptions=[exc])
        assert d.excepted_count == 1

    def test_fallback_mode_with_exceptions(self, tmp_path):
        """Empty analysis + exceptions → excepted findings removed from fallback."""
        exc = _make_exception(
            rule_id="noise.rule", path_pattern="src/a.py",
            severity_cap=Severity.LOW,
        )
        raw = [
            _make_finding(Severity.LOW, rule_id="noise.rule", path="src/a.py"),
            _make_finding(Severity.MEDIUM, rule_id="real.med", path="src/b.py"),
        ]
        d = self._gate(tmp_path, raw, _empty_analysis(), exceptions=[exc])
        # Fallback uses active_findings (raw - excepted)
        assert d.verdict == Verdict.MANUAL_REVIEW
        assert d.findings_count == 1  # Only the MEDIUM one
