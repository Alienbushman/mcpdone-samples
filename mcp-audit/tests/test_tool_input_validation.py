"""Tests for the tool_input_validation check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.tool_input_validation import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_loose_inputs_flags_every_loose_parameter():
    findings = check(FIXTURES / "loose_inputs")
    # search:        query LOOSE_STR              -> 1
    # upload_blob:   data LOOSE_BYTES, filename LOOSE_STR -> 2
    # passthrough:   payload LOOSE_ANY             -> 1
    # bulk_update:   records LOOSE_COLLECTION      -> 1
    # configure:     options LOOSE_COLLECTION      -> 1
    # untyped:       name UNTYPED, count UNTYPED   -> 2
    # = 8 findings, all LOW severity
    assert len(findings) == 8, [f.message for f in findings]
    assert all(f.severity == Severity.LOW for f in findings)
    assert all("FastMCP" in f.message for f in findings)
    assert all("Annotated" in f.remediation for f in findings)


def test_tight_inputs_produces_no_findings():
    findings = check(FIXTURES / "tight_inputs")
    assert findings == [], [f.message for f in findings]


def test_each_finding_carries_a_line_number():
    findings = check(FIXTURES / "loose_inputs")
    for f in findings:
        assert f.line is not None and f.line > 0


def test_loose_str_message_mentions_field_constraint():
    findings = check(FIXTURES / "loose_inputs")
    strs = [f for f in findings if "annotated `str`" in f.message]
    assert len(strs) == 2  # search.query + upload_blob.filename
    assert all("constraint" in f.message for f in strs)


def test_loose_any_messages_call_it_out():
    findings = check(FIXTURES / "loose_inputs")
    anys = [f for f in findings if "annotated `Any`" in f.message]
    assert len(anys) == 1


def test_untyped_messages_distinguish_from_loose():
    findings = check(FIXTURES / "loose_inputs")
    untyped = [f for f in findings if "is unannotated" in f.message]
    assert len(untyped) == 2  # name, count from untyped()
