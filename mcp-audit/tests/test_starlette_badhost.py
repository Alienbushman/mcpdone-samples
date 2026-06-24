"""Tests for the starlette_badhost check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.starlette_badhost import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _findings(name: str):
    return check(FIXTURES / name)


def test_good_pyproject_is_clean():
    assert _findings("good") == []


def test_pep621_old_spec_flags_medium():
    findings = _findings("bad_pep621")
    # The main deps entry + the optional-deps entry should both flag.
    paths = [str(f.path) for f in findings]
    assert any("pyproject.toml" in p for p in paths)
    assert all(f.severity == Severity.MEDIUM for f in findings)
    # Two distinct flags expected (main + optional).
    assert len(findings) >= 2
    assert all("starlette" in f.message.lower() for f in findings)


def test_poetry_caret_flags_medium():
    findings = _findings("bad_poetry")
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "poetry" in findings[0].message.lower()


def test_requirements_pinned_old_flags_medium_with_line():
    findings = _findings("bad_requirements")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.line is not None
    assert "starlette" in f.message.lower()


def test_uvlock_pinned_old_flags_high():
    findings = _findings("bad_lockfile")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "uv lockfile" in f.message.lower() or "uv" in f.message.lower()
    assert "0.36.3" in f.message


def test_uvlock_pinned_safe_is_clean():
    assert _findings("good_lockfile") == []
