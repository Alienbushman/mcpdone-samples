"""Regression tests for the v0.5 list-vs-string fix.

Each pattern in command_injection_list_concat_safe/server.py is the
canonical shape the v0.4 walker false-positive'd on (BinOp(Add) of a
list literal + tainted name + list literal, in the first positional arg
of subprocess.run, with no shell=True). All of these are safe by argv
design and must NOT flag.

The companion negative-control test confirms string-concat still flags."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.command_injection import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_list_concat_with_helper_does_not_flag():
    """The 4 patterns in command_injection_list_concat_safe must produce 0
    findings. Pre-v0.5 this yielded 4 false positives matching the
    kubectl-mcp-server FP family (workflow w6imoinmf)."""
    findings = check(FIXTURES / "command_injection_list_concat_safe")
    assert findings == [], [f.message[:120] for f in findings]


def test_string_concat_still_flags():
    """Negative control: replacing the list literals with string operands
    must still produce a finding. Asserts the v0.5 fix didn't over-narrow."""
    findings = check(FIXTURES / "command_injection_bad")
    # The v0.3 bad fixture has 8 intentional cases; all of them use string
    # concat or f-string, not list concat. Count must stay at 8.
    assert len(findings) == 8
    assert all(f.severity == Severity.HIGH for f in findings)


def test_cross_function_fixture_unchanged():
    """v0.4 cross-function fixture should still produce its 3 findings
    (execute_query, echo_target, deep_query). The v0.5 list-shape check
    must not break legitimate cross-function string-concat detection."""
    findings = check(FIXTURES / "command_injection_cross_function")
    entries = {
        e for e in ("execute_query", "echo_target", "deep_query")
        if any(e in f.message for f in findings)
    }
    assert entries == {"execute_query", "echo_target", "deep_query"}
