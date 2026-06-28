"""Check registry. Each module exposes a `check(root: Path) -> list[Finding]`
plus a module-level `CHECK_ID` matching the dict key here. The CLI iterates
this dict in order; --check NAME filters to one."""
from mcp_audit.checks import (
    command_injection,
    fastmcp_wrapper_layer,
    starlette_badhost,
    tool_input_validation,
)

CHECKS = {
    starlette_badhost.CHECK_ID: starlette_badhost.check,
    fastmcp_wrapper_layer.CHECK_ID: fastmcp_wrapper_layer.check,
    tool_input_validation.CHECK_ID: tool_input_validation.check,
    command_injection.CHECK_ID: command_injection.check,
}

__all__ = ["CHECKS"]
