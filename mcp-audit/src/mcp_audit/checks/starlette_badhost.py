"""starlette_badhost — flag dependency on Starlette < 1.0.1.

Background: BadHost (CVE-2026-48710) lets a crafted HTTP `Host` header
bypass Starlette's path-based authorization. Patched in Starlette 1.0.1.
Affects FastAPI apps, vLLM, LiteLLM, and MCP servers using HTTP/SSE
transport (stdio servers are unaffected — they have no HTTP layer).

This check scans the repo for declared or pinned Starlette versions and
reports anything that allows or pins < 1.0.1. It deliberately does not
require the repo's venv to be installed.

Sources examined (in this priority order; first signal wins per file):
  - pyproject.toml         ([project.dependencies], [tool.poetry.dependencies],
                            [tool.uv.dependencies], [project.optional-dependencies])
  - requirements*.txt      (PEP 508 lines)
  - uv.lock                ([[package]] entries with name = "starlette")
  - poetry.lock            ([[package]] entries)
  - pdm.lock               ([[package]] entries)

Severity:
  HIGH   — a lockfile pins starlette < 1.0.1 (definitely vulnerable on install).
  MEDIUM — a spec allows < 1.0.1 (potentially vulnerable depending on resolve).
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from mcp_audit.finding import Finding, Severity

CHECK_ID = "starlette_badhost"

# The cut-off. Anything strictly below this is BadHost-vulnerable.
PATCHED_VERSION = Version("1.0.1")

# A reasonable lower-bound to probe ranges with. Any released version
# strictly below PATCHED that the spec accepts is enough to flag.
PROBE_VERSIONS = [Version(v) for v in ("0.36.0", "0.40.0", "0.45.0", "1.0.0")]


def _spec_allows_vulnerable(spec_str: str) -> bool:
    """True if the PEP 440 spec admits any version < 1.0.1.

    Strategy: (a) any `==X.Y.Z` clause whose pinned version is < 1.0.1
    is immediately a hit (exact pins are common in requirements.txt);
    (b) otherwise probe a handful of known-released versions across the
    pre-1.0 range and the 1.0.0 boundary to detect open ranges that
    admit vulnerable resolves.
    """
    try:
        spec = SpecifierSet(spec_str)
    except InvalidSpecifier:
        # Unparseable spec — conservative: flag it. Better one false
        # positive than a missed CVE.
        return True

    # (a) Direct read of `==` clauses.
    for clause in spec:
        if clause.operator == "==":
            try:
                v = Version(clause.version)
            except InvalidVersion:
                continue
            if v < PATCHED_VERSION:
                return True

    # (b) Probe ranges.
    for probe in PROBE_VERSIONS:
        if probe in spec and probe < PATCHED_VERSION:
            return True
    return Version("1.0.0") in spec and Version("1.0.0") < PATCHED_VERSION


def _check_pyproject(path: Path) -> list[Finding]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []

    findings: list[Finding] = []

    # PEP 621 [project.dependencies] — list of PEP 508 strings.
    for dep in data.get("project", {}).get("dependencies", []) or []:
        finding = _check_pep508(dep, path)
        if finding:
            findings.append(finding)
    for group, deps in (data.get("project", {}).get("optional-dependencies") or {}).items():
        for dep in deps or []:
            finding = _check_pep508(dep, path, hint=f"[optional-dependencies.{group}]")
            if finding:
                findings.append(finding)

    # Poetry [tool.poetry.dependencies] — dict of name -> spec/dict.
    for name, spec in (data.get("tool", {}).get("poetry", {}).get("dependencies") or {}).items():
        if name.lower() != "starlette":
            continue
        if isinstance(spec, dict):
            spec_str = spec.get("version", "")
        else:
            spec_str = str(spec)
        # Poetry uses "^1.0.0" / "~1.0.0" caret/tilde notation; packaging's
        # SpecifierSet does not parse those. Treat conservatively.
        if not spec_str or spec_str.startswith(("^", "~")):
            findings.append(
                _make_finding(
                    path,
                    Severity.MEDIUM,
                    f"poetry spec 'starlette = {spec_str!r}' uses caret/tilde — "
                    "if its lower bound is < 1.0.1, the install may resolve a "
                    "vulnerable version.",
                    None,
                )
            )
        elif _spec_allows_vulnerable(spec_str):
            findings.append(
                _make_finding(
                    path,
                    Severity.MEDIUM,
                    f"poetry spec 'starlette = {spec_str!r}' allows versions "
                    "below 1.0.1 (BadHost-vulnerable).",
                    None,
                )
            )

    return findings


def _check_pep508(line: str, path: Path, *, hint: str | None = None) -> Finding | None:
    """If `line` is a PEP 508 starlette dep, return a Finding if its spec
    allows < 1.0.1. Otherwise None."""
    # Strip extras + environment markers for the name-vs-spec split.
    bare = line.split(";", 1)[0].strip()
    m = re.match(r"^\s*([A-Za-z0-9._\-]+)\s*(\[.*?\])?\s*(.*)$", bare)
    if not m:
        return None
    name, _extras, spec_str = m.group(1), m.group(2), m.group(3).strip()
    if name.lower() != "starlette":
        return None
    if not spec_str:
        # Bare 'starlette' with no spec — resolves to the newest, which
        # is fine today but the lockfile is the authority. Don't flag here.
        return None
    if _spec_allows_vulnerable(spec_str):
        suffix = f" (in {hint})" if hint else ""
        return _make_finding(
            path,
            Severity.MEDIUM,
            f"dependency spec 'starlette {spec_str}'{suffix} allows versions "
            "below 1.0.1 (BadHost-vulnerable).",
            None,
        )
    return None


def _check_requirements_txt(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for i, raw in enumerate(lines, start=1):
        # Drop comments and blanks.
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "--", "-e ", "-c ")):
            continue
        finding = _check_pep508(line, path)
        if finding:
            # Re-emit with the line number.
            findings.append(
                Finding(
                    check=finding.check,
                    severity=finding.severity,
                    path=finding.path,
                    message=finding.message,
                    remediation=finding.remediation,
                    line=i,
                )
            )
    return findings


def _check_lockfile(path: Path, *, ecosystem: str) -> list[Finding]:
    """uv.lock / poetry.lock / pdm.lock — all TOML with [[package]] arrays.
    Find the starlette package entry and read its `version` key."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    findings: list[Finding] = []
    for pkg in data.get("package") or []:
        if not isinstance(pkg, dict):
            continue
        if str(pkg.get("name", "")).lower() != "starlette":
            continue
        version_str = str(pkg.get("version", "")).strip()
        try:
            v = Version(version_str)
        except InvalidVersion:
            continue
        if v < PATCHED_VERSION:
            findings.append(
                _make_finding(
                    path,
                    Severity.HIGH,
                    f"{ecosystem} lockfile pins starlette=={v} — "
                    f"vulnerable to BadHost (CVE-2026-48710). Patched in 1.0.1.",
                    None,
                )
            )
    return findings


def _make_finding(
    path: Path, severity: Severity, message: str, line: int | None
) -> Finding:
    return Finding(
        check=CHECK_ID,
        severity=severity,
        path=path,
        message=message,
        remediation=(
            "Upgrade Starlette to >=1.0.1 (the BadHost patch). If FastAPI "
            "pulls Starlette transitively, pin it explicitly. Stdio-only MCP "
            "servers are not exposed by this CVE, but upgrading is still "
            "recommended."
        ),
        line=line,
    )


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    for pyproj in root.rglob("pyproject.toml"):
        if _should_skip(pyproj):
            continue
        findings.extend(_check_pyproject(pyproj))

    for req in root.rglob("requirements*.txt"):
        if _should_skip(req):
            continue
        findings.extend(_check_requirements_txt(req))

    lock_specs = [("uv.lock", "uv"), ("poetry.lock", "poetry"), ("pdm.lock", "pdm")]
    for name, eco in lock_specs:
        for lock in root.rglob(name):
            if _should_skip(lock):
                continue
            findings.extend(_check_lockfile(lock, ecosystem=eco))

    return findings


_SKIP_DIRS = {
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".git",
    "site-packages",
    ".tox",
    ".nox",
    "build",
    "dist",
    "__pycache__",
}


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)
