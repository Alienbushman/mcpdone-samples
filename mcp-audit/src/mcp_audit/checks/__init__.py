"""Check registry. Each module exposes a `check(root: Path) -> list[Finding]`
plus a module-level `CHECK_ID` matching the dict key here. The CLI iterates
this dict in order; --check NAME filters to one."""
from mcp_audit.checks import fastmcp_wrapper_layer, starlette_badhost

CHECKS = {
    starlette_badhost.CHECK_ID: starlette_badhost.check,
    fastmcp_wrapper_layer.CHECK_ID: fastmcp_wrapper_layer.check,
}

__all__ = ["CHECKS"]
