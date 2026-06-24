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
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_audit.finding import Finding


def run_all_checks(root: Path, *, only: list[str] | None = None) -> list[Finding]:
    """Run every registered check (or the named subset) against `root` and
    return findings sorted by severity then path."""
    # Imported inside the function so the package's __init__ doesn't take a
    # transitive dep on the check modules just to publish `run_all_checks`.
    from mcp_audit.checks import CHECKS

    findings: list[Finding] = []
    for name, check_fn in CHECKS.items():
        if only and name not in only:
            continue
        findings.extend(check_fn(root))

    severity_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (severity_order[f.severity.value], str(f.path), f.line or 0))
    return findings


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
            "Currently ships BadHost (Starlette) and FastMCP wrapper-layer "
            "checks."
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

    findings = run_all_checks(root, only=args.check)

    if args.json:
        json.dump(
            {
                "root": str(root),
                "finding_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        if not findings:
            print(f"mcp-audit: OK — 0 findings under {root}")
        else:
            for f in findings:
                print(f.format_text(root=root))
                print()
            counts = _count_by_severity(findings)
            summary = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
            print(f"mcp-audit: {len(findings)} finding(s) — {summary}")

    return 0 if not findings else 1


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    out = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        out[f.severity.value] += 1
    return out


if __name__ == "__main__":
    sys.exit(main())
