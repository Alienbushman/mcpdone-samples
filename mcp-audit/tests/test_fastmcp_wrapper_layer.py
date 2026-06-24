"""Tests for the fastmcp_wrapper_layer check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.fastmcp_wrapper_layer import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_good_server_has_no_findings():
    findings = check(FIXTURES / "good_server")
    assert findings == [], [f.message for f in findings]


def test_bad_server_flags_both_tools_high_severity():
    findings = check(FIXTURES / "bad_server")
    # Both fetch_url (sync) and also_bad (async) should be flagged.
    assert len(findings) == 2
    assert all(f.severity == Severity.HIGH for f in findings)
    names = {part for f in findings for part in (f.message,)}
    joined = " | ".join(names)
    assert "fetch_url" in joined
    assert "also_bad" in joined
    # The blog-post remediation link should be referenced.
    assert any("fastmcp-wrapper-layer-bug" in f.remediation for f in findings)


def test_line_numbers_point_at_the_asyncio_run_call():
    findings = check(FIXTURES / "bad_server")
    for f in findings:
        assert f.line is not None
        assert f.line > 0
