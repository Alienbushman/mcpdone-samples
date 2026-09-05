"""CLI entry point and orchestrator.

  mcp-audit                # scan current directory, text output
  mcp-audit /path/to/repo  # scan a specific repo
  mcp-audit --json         # JSON output for piping into other tools
  mcp-audit --check fastmcp_wrapper_layer  # one check only
  mcp-audit --list-checks  # list available checks and exit

Exit codes:
  0 — no findings.
  1 — at least one finding (any severity).
  2 — usage error or unrecoverable script failure.
  3 — nothing was examined: no analyzable file was found under the root.
      This is NOT a clean result and must never be reported as one. Pass
      --allow-empty to treat it as success (exit 0) when a repo legitimately
      holds no auditable code.

On `0 findings` vs `0 files`: a scanner that cannot tell those apart is
worse than no scanner, because it issues a clean bill of health for code it
never opened. This shipped twice. In v0.9 every check globbed `*.py`, so any
TypeScript server returned `OK — 0 findings` without a file being read. Then
the per-check skip sets were found to match components of the ABSOLUTE path,
so a checkout under any directory named `dist`, `build` or `env` was skipped
in its entirety, and a published npm package (whose code is all under
`dist/`) was discarded whole. Exit 3 and the `files examined` counter exist
so neither shape can pass silently again. See mcp_audit.discovery.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from mcp_audit import discovery

from mcp_audit.finding import Finding


def run_all_checks(
    root: Path, *, only: list[str] | None = None, include_build: bool = False
) -> list[Finding]:
    """Run every registered check (or the named subset) against `root` and
    return findings sorted by severity then path.

    `include_build` keeps `dist`/`build`/`out` in the walk. Callers should
    prefer `scan()`, which decides that for them."""
    # Imported inside the function so the package's __init__ doesn't take a
    # transitive dep on the check modules just to publish `run_all_checks`.
    from mcp_audit.checks import CHECKS

    findings: list[Finding] = []
    for name, check_fn in CHECKS.items():
        if only and name not in only:
            continue
        findings.extend(check_fn(root, include_build=include_build))

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (severity_order[f.severity.value], str(f.path), f.line or 0))
    return findings



@dataclass(frozen=True)
class ScanResult:
    """What one scan looked at, not just what it found."""

    findings: list[Finding]
    files_examined: int
    scanned_build_output: bool


def scan(root: Path, *, only: list[str] | None = None) -> ScanResult:
    """Audit `root`, deciding for the caller whether build output is the
    product or residue.

    In a repository, `dist/` is generated and scanning it double-reports
    whatever `src/` already said. In a published package it is the only code
    present: an npm tarball ships `package/dist/*.js` and no sources at all.
    Rather than making the user know which they are holding, we prune build
    output first and reconsider only when that left us with nothing to read.
    Because the fallback triggers exclusively on an otherwise-empty scan, it
    can never add noise to a repo that has real sources.
    """
    # The trigger is *sources*, not analyzable files. Every published npm
    # package ships a package.json, so counting manifests here would make a
    # dist-only tarball look non-empty and suppress the fallback that exists
    # precisely for it.
    include_build = (
        discovery.count_sources(root) == 0
        and discovery.count_sources(root, include_build=True) > 0
    )
    examined = discovery.count_analyzable(root, include_build=include_build)
    findings = run_all_checks(root, only=only, include_build=include_build)
    return ScanResult(
        findings=findings,
        files_examined=examined,
        scanned_build_output=include_build,
    )


def main(argv: list[str] | None = None) -> int:
    # Make em-dash + other non-ASCII glyphs survive Windows cmd's cp1252.
    # Python 3.7+ supports reconfigure on the standard streams.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass

    from mcp_audit.checks import CHECKS

    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description=(
            "Static security + correctness audit for MCP server repos. "
            f"Checks: {', '.join(CHECKS.keys())}."
        ),
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Repo root to scan. Defaults to the current directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as a single JSON document on stdout.",
    )
    parser.add_argument(
        "--check",
        action="append",
        default=None,
        metavar="NAME",
        help=(
            "Run only this check. May be repeated. Use --list-checks for "
            "available names."
        ),
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List available checks and exit.",
    )
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help=(
            "Exit 0 instead of 3 when no analyzable file is found. Use only "
            "where a repo legitimately holds no auditable code."
        ),
    )
    args = parser.parse_args(argv)

    if args.list_checks:
        for name in CHECKS:
            print(name)
        return 0

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"mcp-audit: path does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"mcp-audit: not a directory: {root}", file=sys.stderr)
        return 2

    if args.check:
        unknown = [c for c in args.check if c not in CHECKS]
        if unknown:
            print(f"mcp-audit: unknown check(s): {unknown}", file=sys.stderr)
            print(f"available: {list(CHECKS)}", file=sys.stderr)
            return 2

    result = scan(root, only=args.check)
    findings = result.findings
    empty = result.files_examined == 0

    if args.json:
        json.dump(
            {
                "root": str(root),
                "finding_count": len(findings),
                "files_examined": result.files_examined,
                "scanned_build_output": result.scanned_build_output,
                "findings": [f.to_dict() for f in findings],
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    elif empty:
        # stderr, and deliberately never the word "OK". This is the failure
        # mode where the tool reads nothing and the user reads that as a pass.
        print(
            f"mcp-audit: examined 0 files under {root} — nothing here to "
            f"audit. This is NOT a clean result: no Python or TypeScript "
            f"source and no dependency manifest was found. Check the path, "
            f"or pass --allow-empty if that is expected.",
            file=sys.stderr,
        )
    else:
        note = (
            " (scanned build output: no other source present)"
            if result.scanned_build_output
            else ""
        )
        if not findings:
            print(
                f"mcp-audit: OK — 0 findings across "
                f"{result.files_examined} file(s) under {root}{note}"
            )
        else:
            for f in findings:
                print(f.format_text(root=root))
                print()
            counts = _count_by_severity(findings)
            summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
            print(
                f"mcp-audit: {len(findings)} finding(s) — {summary} "
                f"across {result.files_examined} file(s){note}"
            )

    if empty:
        return 0 if args.allow_empty else 3
    return 0 if not findings else 1


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    out = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        out[f.severity.value] += 1
    return out


if __name__ == "__main__":
    sys.exit(main())
