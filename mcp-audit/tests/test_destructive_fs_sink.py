"""Tests for the destructive_fs_sink check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.destructive_fs_sink import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_bad_fixture_flags_every_intentional_case():
    findings = check(FIXTURES / "destructive_fs_bad")
    # 4 intentional bad tools: cleanup_dir, delete_file, unlink_path, purge
    assert len(findings) == 4, [f.message for f in findings]
    assert all(f.severity == Severity.MEDIUM for f in findings)
    tools = " ".join(f.message for f in findings)
    for name in ("cleanup_dir", "delete_file", "unlink_path", "purge"):
        assert name in tools, f"missing finding for {name}"


def test_guarded_fixture_flags_nothing():
    findings = check(FIXTURES / "destructive_fs_guarded")
    assert findings == [], [f.message for f in findings]


def test_safe_fixture_flags_nothing():
    findings = check(FIXTURES / "destructive_fs_safe")
    assert findings == [], [f.message for f in findings]


def test_every_finding_has_line_and_remediation():
    findings = check(FIXTURES / "destructive_fs_bad")
    for f in findings:
        assert f.line is not None and f.line > 0
        assert "realpath" in f.remediation or "resolve" in f.remediation
        assert f.check == "destructive_fs_sink"


def test_exists_check_is_not_treated_as_a_containment_guard():
    """The manim-shaped case guards only with os.path.exists(), which does
    NOT confine the path — it must still be flagged."""
    findings = check(FIXTURES / "destructive_fs_bad")
    cleanup = [f for f in findings if "cleanup_dir" in f.message]
    assert len(cleanup) == 1
