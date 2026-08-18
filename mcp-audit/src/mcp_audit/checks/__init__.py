"""Check registry. Each module exposes a `check(root: Path) -> list[Finding]`
plus a module-level `CHECK_ID` matching the dict key here. The CLI iterates
this dict in order; --check NAME filters to one.

Two engines live here. The `ts_`-prefixed checks read TypeScript/JavaScript
via `mcp_audit.jsparse`; everything else reads Python via `ast`. Both run on
every scan — a repo is free to contain both, and a scanner that silently
skipped one language would hand back a clean bill of health it had not
earned. That is exactly what mcp-audit did to every TypeScript MCP server
before v0.9."""
from mcp_audit.checks import (
    command_injection,
    destructive_fs_sink,
    fastmcp_wrapper_layer,
    sql_readonly_keyword_guard,
    starlette_badhost,
    tool_input_validation,
    ts_command_injection,
    ts_destructive_fs_sink,
    ts_dns_rebinding,
    ts_tool_input_validation,
)

CHECKS = {
    # Python engine.
    starlette_badhost.CHECK_ID: starlette_badhost.check,
    fastmcp_wrapper_layer.CHECK_ID: fastmcp_wrapper_layer.check,
    tool_input_validation.CHECK_ID: tool_input_validation.check,
    command_injection.CHECK_ID: command_injection.check,
    destructive_fs_sink.CHECK_ID: destructive_fs_sink.check,
    sql_readonly_keyword_guard.CHECK_ID: sql_readonly_keyword_guard.check,
    # TypeScript / JavaScript engine (v0.9).
    ts_dns_rebinding.CHECK_ID: ts_dns_rebinding.check,
    ts_command_injection.CHECK_ID: ts_command_injection.check,
    ts_destructive_fs_sink.CHECK_ID: ts_destructive_fs_sink.check,
    ts_tool_input_validation.CHECK_ID: ts_tool_input_validation.check,
}

__all__ = ["CHECKS"]
