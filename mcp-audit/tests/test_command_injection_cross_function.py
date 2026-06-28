"""Tests for v0.4 cross-function taint propagation in the command_injection check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.command_injection import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _findings():
    return check(FIXTURES / "command_injection_cross_function")


def test_single_hop_taint_via_helper_flagged():
    findings = _findings()
    # execute_query -> _run_shell -> subprocess.run(shell=True)
    # echo_target -> _shell_via_os -> os.system
    matched_entries = {
        entry
        for entry in ("execute_query", "echo_target")
        if any(entry in f.message for f in findings)
    }
    assert matched_entries == {"execute_query", "echo_target"}


def test_two_hop_taint_via_two_helpers_flagged():
    findings = _findings()
    deep = [f for f in findings if "deep_query" in f.message]
    assert len(deep) >= 1
    # Message should mention BOTH helpers in the chain
    msg = deep[0].message
    assert "_exec_with_logging" in msg
    assert "_run_shell" in msg


def test_safe_list_helper_not_flagged():
    findings = _findings()
    assert not any("safe_passthrough" in f.message for f in findings)


def test_helper_without_tainted_arg_not_flagged():
    findings = _findings()
    # system_info calls a helper that uses shell=True but the tool's `req_id`
    # parameter never flows into the helper. No finding expected.
    assert not any("system_info" in f.message for f in findings)


def test_all_findings_attributed_to_tool_entry_not_helper():
    findings = _findings()
    # The leading "tool 'X'" should always name an @mcp.tool() entry, never
    # the helper. _run_shell / _shell_via_os / _exec_with_logging are
    # helpers, not tools.
    for f in findings:
        for helper in ("_run_shell", "_shell_via_os", "_exec_with_logging", "_safe_via_list", "_exec_static_command"):
            assert not f.message.startswith(f"tool '{helper}'"), (
                f"Finding wrongly attributed to helper {helper}: {f.message[:120]}"
            )


def test_helper_chain_mentioned_in_message():
    findings = _findings()
    cross_function_findings = [
        f for f in findings if "via helper" in f.message
    ]
    # All findings here are cross-function — every one should carry the
    # "via helper" attribution string.
    assert len(cross_function_findings) == len(findings)


def test_every_finding_is_high_severity():
    findings = _findings()
    assert findings, "expected at least 3 cross-function findings"
    assert all(f.severity == Severity.HIGH for f in findings)


def test_existing_single_function_tests_unaffected():
    """v0.4 must not regress v0.3 behavior. The existing bad/good fixtures
    are still single-function; counts should be unchanged."""
    bad = check(FIXTURES / "command_injection_bad")
    good = check(FIXTURES / "command_injection_good")
    assert len(bad) == 8
    assert len(good) == 1  # the shlex.quote documented FP
