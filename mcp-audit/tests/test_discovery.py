"""Tests for shared file discovery, and for the invariant it exists to hold:

    "0 findings" must never be indistinguishable from "0 files examined."

Both defects covered here were found in the field on real code, not
imagined. Each has a test that fails against the old behaviour.
"""
from __future__ import annotations

from pathlib import Path

from mcp_audit import discovery
from mcp_audit.checks.command_injection import check as command_injection_check
from mcp_audit.cli import main, scan

FIXTURES = Path(__file__).parent / "fixtures"


def _write(path: Path, text: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# defect 1: pruning matched the ABSOLUTE path
# --------------------------------------------------------------------------
# `_should_skip` tested `any(part in _SKIP_DIRS for part in path.parts)` on the
# full path, so a checkout under a directory named `dist` / `build` / `env`
# had every file skipped and the scan reported OK having read nothing.
def test_pruning_ignores_directory_names_above_the_scan_root(tmp_path):
    root = tmp_path / "dist" / "myserver"
    _write(root / "server.py", "import os\n")
    assert discovery.is_skipped(root / "server.py", root) is False
    assert discovery.count_sources(root) == 1


def test_pruning_still_applies_below_the_scan_root(tmp_path):
    root = tmp_path / "repo"
    _write(root / "server.py", "x = 1\n")
    _write(root / "node_modules" / "dep" / "index.js", "x\n")
    assert discovery.is_skipped(root / "node_modules" / "dep" / "index.js", root)
    assert discovery.count_sources(root) == 1


def test_real_check_fires_under_a_dist_ancestor(tmp_path):
    """End-to-end version of defect 1, on the fixture that exposed it.

    `command_injection_bad` reports 16 findings normally and reported 0 when
    copied under a parent directory named `dist`.
    """
    import shutil

    staged = tmp_path / "dist" / "myserver"
    staged.parent.mkdir(parents=True)
    shutil.copytree(FIXTURES / "command_injection_bad", staged)

    baseline = command_injection_check(FIXTURES / "command_injection_bad")
    under_dist = command_injection_check(staged)
    assert baseline, "fixture should produce findings at all"
    assert len(under_dist) == len(baseline)


# --------------------------------------------------------------------------
# defect 2: a published package is almost entirely build output
# --------------------------------------------------------------------------
def test_build_output_is_pruned_by_default(tmp_path):
    root = tmp_path / "repo"
    _write(root / "src" / "index.ts", "export const x = 1;\n")
    _write(root / "dist" / "index.js", "export const x = 1;\n")
    assert discovery.count_sources(root) == 1
    assert discovery.count_sources(root, include_build=True) == 2


def test_scan_falls_back_to_build_output_when_there_is_nothing_else(tmp_path):
    """An npm tarball ships `package/dist/*.js` and no sources."""
    root = tmp_path / "package"
    _write(root / "package.json", '{"name":"x","version":"1.0.0"}\n')
    _write(root / "dist" / "index.js", "export const x = 1;\n")

    assert discovery.count_sources(root) == 0
    result = scan(root)
    assert result.scanned_build_output is True
    assert result.files_examined > 0


def test_no_fallback_when_real_sources_exist(tmp_path):
    """The fallback must never add noise to a repo that has sources: it is
    reachable only from an otherwise-empty scan."""
    root = tmp_path / "repo"
    _write(root / "src" / "index.ts", "export const x = 1;\n")
    _write(root / "dist" / "index.js", "export const x = 1;\n")
    assert scan(root).scanned_build_output is False


# --------------------------------------------------------------------------
# the trap that defeated the first version of the fallback
# --------------------------------------------------------------------------
def test_count_sources_ignores_manifests(tmp_path):
    """`count_sources` must not count `package.json`.

    The first implementation triggered the fallback on `count_analyzable`,
    which includes manifests. Every published npm package carries a
    `package.json`, so a dist-only tarball never looked empty and the
    fallback it was written for never fired. Regression guard.
    """
    root = tmp_path / "package"
    _write(root / "package.json", '{"name":"x"}\n')
    _write(root / "dist" / "index.js", "export const x = 1;\n")

    assert discovery.count_sources(root) == 0
    assert discovery.count_analyzable(root) == 1  # the manifest


def test_manifest_only_repo_is_examined_not_empty(tmp_path):
    """A repo with a real pyproject.toml and no source has genuinely been
    examined by starlette_badhost, so it is not an empty scan."""
    root = tmp_path / "repo"
    _write(root / "pyproject.toml", "[project]\nname='x'\n")
    result = scan(root)
    assert result.files_examined == 1
    assert result.scanned_build_output is False


# --------------------------------------------------------------------------
# the invariant, at the CLI boundary
# --------------------------------------------------------------------------
def test_empty_scan_exits_3_and_never_says_ok(tmp_path, capsys):
    root = tmp_path / "nothing"
    root.mkdir()
    code = main([str(root)])
    captured = capsys.readouterr()
    assert code == 3
    assert "OK" not in captured.out
    assert "NOT a clean result" in captured.err


def test_allow_empty_downgrades_the_empty_scan_to_success(tmp_path):
    root = tmp_path / "nothing"
    root.mkdir()
    assert main([str(root), "--allow-empty"]) == 0


def test_clean_scan_reports_how_many_files_it_read(tmp_path, capsys):
    root = tmp_path / "repo"
    _write(root / "ok.py", "x = 1\n")
    code = main([str(root)])
    out = capsys.readouterr().out
    assert code == 0
    assert "0 findings" in out
    assert "1 file(s)" in out


def test_json_output_carries_the_examination_counters(tmp_path, capsys):
    import json

    root = tmp_path / "repo"
    _write(root / "ok.py", "x = 1\n")
    main([str(root), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_examined"] == 1
    assert payload["scanned_build_output"] is False
