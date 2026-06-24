"""fastmcp_wrapper_layer — forbid `asyncio.run()` inside @mcp.tool() functions.

Background: the FastMCP wrapper invokes a tool inside the MCP server's
already-running event loop. A sync `@mcp.tool()` that calls
`asyncio.run(...)` to drive its async work raises at first call:

    RuntimeError: asyncio.run() cannot be called from a running event loop

The bug is invisible to unit tests that exercise the inner async functions
directly — they have no outer loop. It surfaces only on the first real
MCP protocol call.

Fix: make the tool `async def` and use `await` directly. The full story
is at https://mcpdone.com/blog/fastmcp-wrapper-layer-bug.

This check AST-scans every .py file under the repo (skipping venvs,
node_modules, build dirs). For each function decorated `@<anything>.tool()`
— FastMCP's decorator is conventionally named .tool() regardless of the
server-object identifier (`mcp`, `app`, `server`, etc.) — it walks the
body and reports any `asyncio.run(...)` call.
"""
from __future__ import annotations

import ast
from pathlib import Path

from mcp_audit.finding import Finding, Severity

CHECK_ID = "fastmcp_wrapper_layer"

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


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    """Match @<anything>.tool() or @<anything>.tool — by attribute name.

    Teams name their FastMCP instance variably (`mcp`, `server`, `app`, ...);
    the invariant across FastMCP versions is the `.tool` attribute name.
    """
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _calls_asyncio_run(func_node: ast.AST) -> ast.Call | None:
    """Return the first `asyncio.run(...)` call node in the function body,
    or None. Nested functions are deliberately walked too — a helper that
    calls asyncio.run() inside a tool body is just as broken."""
    for sub in ast.walk(func_node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "run"
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "asyncio"
        ):
            return sub
    return None


def _check_file(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError):
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
            continue
        call = _calls_asyncio_run(node)
        if call is None:
            continue

        kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        findings.append(
            Finding(
                check=CHECK_ID,
                severity=Severity.HIGH,
                path=path,
                line=call.lineno,
                message=(
                    f"tool '{node.name}' ({kind}) calls asyncio.run() inside its "
                    "body. FastMCP invokes tools inside an already-running event "
                    "loop, and asyncio.run() raises RuntimeError when nested. "
                    "This will fail at the first real MCP protocol call even if "
                    "every unit test passes."
                ),
                remediation=(
                    "Convert the tool to `async def` and replace `asyncio.run(...)` "
                    "with `await`. If the work must remain sync, factor the async "
                    "call into a separate helper and let the tool wrap it with "
                    "`await`. See https://mcpdone.com/blog/fastmcp-wrapper-layer-bug "
                    "for the full pattern."
                ),
            )
        )
    return findings


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in root.rglob("*.py"):
        if _should_skip(py):
            continue
        findings.extend(_check_file(py))
    return findings
