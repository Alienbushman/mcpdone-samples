"""Tests for lint_mcp_server.py.

Drives the lint as a function call (no subprocess) and asserts each check
fires on its target fixture and stays quiet on the reference good code. The
fixtures themselves are the spec — each one contains both a "bad" example
(should fire) and a "good" example (should pass).

Run:
    python -m pytest test_lint.py -v

Or without pytest:
    python test_lint.py
"""
from __future__ import annotations

from pathlib import Path

from lint_mcp_server import _CHECKS, lint_file

FIXTURES = Path(__file__).parent / "test_fixtures"


def _violations_by_check(path: Path) -> dict[str, list[str]]:
    """Group violations from one file by check_id → list of tool names."""
    out: dict[str, list[str]] = {}
    for v in lint_file(path):
        out.setdefault(v.check_id, []).append(v.tool_name)
    return out


# --- NO_ASYNCIO_RUN_INSIDE_MCP_TOOL ---


def test_buggy_server_fixture_catches_asyncio_run() -> None:
    """The original anti-pattern: sync def + asyncio.run() inside."""
    by_check = _violations_by_check(FIXTURES / "buggy_server.py")
    assert "NO_ASYNCIO_RUN_INSIDE_MCP_TOOL" in by_check
    assert "broken_tool" in by_check["NO_ASYNCIO_RUN_INSIDE_MCP_TOOL"]
    assert "fixed_tool" not in by_check.get("NO_ASYNCIO_RUN_INSIDE_MCP_TOOL", [])


# --- TOOL_DOCSTRING_LENGTH ---


def test_missing_docstring_fixture_catches_short_and_missing_docstrings() -> None:
    by_check = _violations_by_check(FIXTURES / "missing_docstring.py")
    flagged = by_check.get("TOOL_DOCSTRING_LENGTH", [])
    assert "no_docstring_at_all" in flagged
    assert "one_liner_docstring" in flagged
    assert "well_documented_tool" not in flagged


# --- TOOL_PARAMS_TYPED ---


def test_untyped_params_fixture_catches_untyped_parameters() -> None:
    by_check = _violations_by_check(FIXTURES / "untyped_params.py")
    flagged = by_check.get("TOOL_PARAMS_TYPED", [])
    assert "untyped_query" in flagged
    assert "partially_typed" in flagged
    assert "fully_typed" not in flagged


# --- TOOL_NO_BLOCKING_SLEEP ---


def test_blocking_sleep_fixture_catches_time_sleep() -> None:
    by_check = _violations_by_check(FIXTURES / "blocking_sleep.py")
    flagged = by_check.get("TOOL_NO_BLOCKING_SLEEP", [])
    assert "blocking_tool" in flagged
    assert "correct_async_sleep" not in flagged


# --- Drift guard: every check has a corresponding fixture ---


def test_every_check_has_at_least_one_fixture_that_catches_it() -> None:
    """If we add a new check to _CHECKS, this test fails until we add a
    fixture demonstrating the anti-pattern AND a test verifying the check
    fires on it. Drift prevention."""
    all_violations: dict[str, set[str]] = {}
    for fixture in FIXTURES.glob("*.py"):
        for v in lint_file(fixture):
            all_violations.setdefault(v.check_id, set()).add(v.tool_name)

    for check_id in _CHECKS:
        assert check_id in all_violations, (
            f"Check {check_id!r} has no fixture demonstrating the anti-pattern "
            f"it catches. Add a fixture in test_fixtures/ and a test above."
        )


def _run_as_script() -> int:
    """Fallback runner if pytest isn't available."""
    tests = [
        test_buggy_server_fixture_catches_asyncio_run,
        test_missing_docstring_fixture_catches_short_and_missing_docstrings,
        test_untyped_params_fixture_catches_untyped_parameters,
        test_blocking_sleep_fixture_catches_time_sleep,
        test_every_check_has_at_least_one_fixture_that_catches_it,
    ]
    failures = []
    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
        except AssertionError as e:
            failures.append((test.__name__, str(e)))
            print(f"FAIL: {test.__name__} — {e}")
    if failures:
        print(f"\n{len(failures)} of {len(tests)} test(s) failed.")
        return 1
    print(f"\nAll {len(tests)} test(s) passed.")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_run_as_script())
