"""mcp-audit — static security + correctness audit for MCP server repos.

Public surface:

    from mcp_audit import run_all_checks, Finding, Severity
    findings = run_all_checks(Path("path/to/repo"))

Check modules live under mcp_audit.checks and each exposes a single
`check(root: Path) -> list[Finding]` callable.
"""
from mcp_audit.finding import Finding, Severity
from mcp_audit.cli import run_all_checks

__all__ = ["Finding", "Severity", "run_all_checks"]
__version__ = "0.7.0"
