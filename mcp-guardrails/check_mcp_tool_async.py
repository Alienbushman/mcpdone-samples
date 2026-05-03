#!/usr/bin/env python3
"""Lint: forbid `asyncio.run()` inside any `@mcp.tool()` function.

The bug this guards against
---------------------------

When a FastMCP-decorated tool calls `asyncio.run()` to drive async work, the
runtime invokes the tool inside the MCP server's already-running event loop,
and asyncio.run() raises:

    RuntimeError: asyncio.run() cannot be called from a running event loop

Looks fine in unit tests (which have no outer loop), breaks at first real
protocol call. We shipped this exact bug on 2026-04-30 in our own
mcp-twitter — 42 unit tests passed, then died at the first MCP request.

The fix is always the same: make the tool `async def` and use `await`
directly instead of `asyncio.run()`.

When sync `@mcp.tool()` is fine
-------------------------------

Sync tools are FINE if they don't drive async work — e.g., tools that wrap
sqlite3, imaplib, or pure-CPU code. FastMCP runs sync tools in a thread
executor. So this lint specifically targets the asyncio.run() anti-pattern,
not the sync/async choice itself.

If your project's tools all do HTTP and should all be async by convention,
add a project-level test that uses inspect.iscoroutinefunction to enforce
it. (See `mcp-twitter/tests/test_server_wrappers.py` in this repo for the
pattern, if mcp-twitter is published; otherwise check `inspect`'s docs.)

Usage
-----

    # Scan all FastMCP servers under the current directory
    python check_mcp_tool_async.py

    # Scan specific files (e.g., as a pre-commit hook)
    python check_mcp_tool_async.py path/to/server.py path/to/other.py

Exit codes:
    0 — clean
    1 — at least one violation (printed to stderr with file:line)
    2 — script error (no targets found, parse failure)
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

# Directories we never recurse into. .venv et al. contain third-party MCP
# server code that isn't ours to lint (and would 100x the runtime).
_SKIP_DIRS = {
    ".venv", "venv", ".env", "env",
    "node_modules", "__pycache__", ".git",
    ".pytest_cache", ".mypy_cache", "dist", "build",
    "site-packages",
}


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    """Match @something.tool() or @something.tool — by attribute name only.

    Doesn't bind to a specific identifier (`mcp`, `server`, `app`, …) — teams
    name their FastMCP instance differently. The contract we care about is
    "decorated by a FastMCP-shaped .tool() decorator," and the attribute name
    `tool` is invariant across FastMCP versions.
    """
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _calls_asyncio_run(func_node: ast.AST) -> bool:
    for sub in ast.walk(func_node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "run"
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "asyncio"
        ):
            return True
    return False


def check_file(path: Path) -> list[str]:
    """Return a list of violation messages, one per offending function."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        return [f"{path}: parse error — {exc}"]

    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
            continue

        if _calls_asyncio_run(node):
            kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            violations.append(
                f"{path}:{node.lineno}: tool '{node.name}' ({kind}) contains "
                f"`asyncio.run(...)`. Convert to `async def` and use `await` "
                f"directly. asyncio.run() raises RuntimeError when called "
                f"from inside an already-running event loop, which is the "
                f"case under FastMCP."
            )
    return violations


def discover_targets(root: Path) -> list[Path]:
    """All `*server*.py` files under root, skipping virtualenvs and caches."""
    out: list[Path] = []
    for path in root.rglob("*server*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        out.append(path)
    return sorted(out)


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        targets = [Path(p) for p in argv[1:]]
    else:
        targets = discover_targets(Path("."))
        if not targets:
            print(
                "No `*server*.py` files found under the current directory. "
                "Pass paths explicitly: `python check_mcp_tool_async.py "
                "path/to/server.py`",
                file=sys.stderr,
            )
            return 2

    all_violations: list[str] = []
    for path in targets:
        all_violations.extend(check_file(path))

    if all_violations:
        for v in all_violations:
            print(v, file=sys.stderr)
        print(
            f"\n{len(all_violations)} violation(s) across "
            f"{len(targets)} file(s).",
            file=sys.stderr,
        )
        return 1

    print(f"OK: no violations across {len(targets)} server.py file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
