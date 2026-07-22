"""Tests for the sql_readonly_keyword_guard check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.sql_readonly_keyword_guard import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_bad_fixture_flags_both_keyword_guarded_tools():
    findings = check(FIXTURES / "sql_readonly_bad")
    # read_query (prefix allow-list) + safe_sql (keyword blocklist)
    assert len(findings) == 2, [f.message for f in findings]
    assert all(f.severity == Severity.MEDIUM for f in findings)
    tools = " ".join(f.message for f in findings)
    assert "read_query" in tools and "safe_sql" in tools


def test_good_fixture_flags_nothing():
    findings = check(FIXTURES / "sql_readonly_good")
    assert findings == [], [f.message for f in findings]


def test_message_names_the_bypass_and_fix():
    findings = check(FIXTURES / "sql_readonly_bad")
    for f in findings:
        assert f.line is not None and f.line > 0
        assert "not a security boundary" in f.message
        assert "mode=ro" in f.remediation or "query_only" in f.remediation
        assert f.check == "sql_readonly_keyword_guard"
