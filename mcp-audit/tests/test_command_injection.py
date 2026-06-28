"""Tests for the command_injection check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.command_injection import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def test_bad_fixture_flags_every_intentional_case():
    findings = check(FIXTURES / "command_injection_bad")
    # 8 intentional bad cases in the fixture:
    #   run_kubectl, git_log, query_db, read_log,
    #   from_import_run, via_assignment,
    #   tainted_interpolation_no_shell, via_format_method
    assert len(findings) == 8, [f.message for f in findings]
    assert all(f.severity == Severity.HIGH for f in findings)


def test_good_fixture_flags_only_the_documented_false_positive():
    findings = check(FIXTURES / "command_injection_good")
    # Only `quoted_input` should flag — it's the acknowledged FP from
    # shlex.quote not being recognized as sanitization in v0.3.
    assert len(findings) == 1, [f.message for f in findings]
    assert "quoted_input" in findings[0].message


def test_message_kinds_distinguish_os_shell_from_subprocess():
    findings = check(FIXTURES / "command_injection_bad")
    messages = " ".join(f.message for f in findings)
    # os.system + os.popen cases
    assert "os.system" in messages or "os.popen" in messages
    # subprocess shell=True cases
    assert "shell=True" in messages
    # f-string / interpolation case
    assert "f-string" in messages


def test_every_finding_has_a_line_number_and_remediation():
    findings = check(FIXTURES / "command_injection_bad")
    for f in findings:
        assert f.line is not None and f.line > 0
        assert "subprocess.run([" in f.remediation
        assert "shlex.quote" in f.remediation


def test_taint_propagates_through_local_assignments():
    """via_assignment uses `target = name; cmd = f"echo {target}"`. Both
    `target` and `cmd` should be considered tainted, and the subprocess
    call should still fire."""
    findings = check(FIXTURES / "command_injection_bad")
    via_assign = [f for f in findings if "via_assignment" in f.message]
    assert len(via_assign) == 1
