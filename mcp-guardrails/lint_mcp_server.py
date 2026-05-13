#!/usr/bin/env python3
"""Comprehensive MCP server linter.

Runs every check in this toolkit against any FastMCP-shaped `*server*.py`
file. Each check targets a specific bug class we've actually shipped (or
seen shipped) in production. Static analysis only — no network, no
dependencies beyond the Python stdlib.

Checks implemented
------------------

1. **NO_ASYNCIO_RUN_INSIDE_MCP_TOOL** — `@mcp.tool()` functions must not
   call `asyncio.run()`. FastMCP runs tools inside its own event loop;
   `asyncio.run()` raises RuntimeError when called from a running loop.
   This is the original bug that prompted the entire toolkit.

2. **TOOL_DOCSTRING_LENGTH** — `@mcp.tool()` functions must have a
   docstring of at least 3 sentences. MCP tool docstrings are the
   primary interface the *model* sees: the JSON-Schema FastMCP generates
   exposes them as the tool description. Vague or short docstrings →
   the model calls the tool with wrong args. Three sentences is a
   minimum bar; the discipline matters more than the exact threshold.

3. **TOOL_PARAMS_TYPED** — every parameter of `@mcp.tool()` functions
   must have a type annotation. Untyped parameters produce JSON-Schema
   fields with no type constraint, and the model passes whatever it
   feels like. Type hints aren't decoration — they're the model's
   contract.

4. **TOOL_NO_BLOCKING_SLEEP** — `@mcp.tool()` functions must not call
   `time.sleep()`. In a sync FastMCP tool, `time.sleep` blocks the
   server's event loop for every other request. Use `asyncio.sleep`
   inside an `async def` tool instead. (Even in sync tools running in
   a thread executor, `time.sleep` is usually a sign of "this tool is
   waiting for something it shouldn't be waiting for synchronously.")

Usage
-----

    # Lint all FastMCP server.py files under the current directory
    python lint_mcp_server.py

    # Lint specific files
    python lint_mcp_server.py path/to/server.py

    # Skip specific checks (comma-separated)
    python lint_mcp_server.py --skip TOOL_NO_BLOCKING_SLEEP

    # Output as JSON (for CI integration)
    python lint_mcp_server.py --format json

Exit codes:
    0 — clean across all checks
    1 — at least one violation
    2 — script error (no targets found, parse failure)
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# Directories never recursed into.
_SKIP_DIRS = {
    ".venv", "venv", ".env", "env",
    "node_modules", "__pycache__", ".git",
    ".pytest_cache", ".mypy_cache", "dist", "build",
    "site-packages", ".tox",
}


@dataclass
class Violation:
    """A single lint failure with enough context to fix it."""

    check_id: str
    file: str
    line: int
    tool_name: str
    message: str

    def render(self) -> str:
        return f"{self.file}:{self.line}: [{self.check_id}] tool '{self.tool_name}': {self.message}"

    def as_dict(self) -> dict:
        return {
            "check": self.check_id,
            "file": self.file,
            "line": self.line,
            "tool": self.tool_name,
            "message": self.message,
        }


# --- AST helpers shared across checks ---


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    """Match @<anything>.tool() or @<anything>.tool — attribute name only.

    Lets the lint apply regardless of whether the FastMCP instance is named
    `mcp`, `server`, `app`, or anything else; the .tool attribute is the
    invariant across FastMCP versions.
    """
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _find_mcp_tools(tree: ast.Module) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    """Every function in the module decorated with a `.tool()` decorator."""
    out: list[ast.AsyncFunctionDef | ast.FunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
            out.append(node)
    return out


# --- Checks ---


def _check_no_asyncio_run(tool: ast.AST, file: str) -> Violation | None:
    """Forbid asyncio.run(...) inside @mcp.tool() bodies."""
    for sub in ast.walk(tool):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "run"
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "asyncio"
        ):
            kind = "async def" if isinstance(tool, ast.AsyncFunctionDef) else "def"
            return Violation(
                check_id="NO_ASYNCIO_RUN_INSIDE_MCP_TOOL",
                file=file,
                line=tool.lineno,
                tool_name=tool.name,
                message=(
                    f"({kind}) contains `asyncio.run(...)`. Convert to "
                    f"`async def` and use `await` directly. asyncio.run() "
                    f"raises RuntimeError when called from inside an "
                    f"already-running event loop, which is the case under "
                    f"FastMCP."
                ),
            )
    return None


_SENTENCE_END = re.compile(r"[.!?](?:\s|$)")


def _check_docstring_length(tool: ast.AST, file: str) -> Violation | None:
    """Tool functions must have a docstring of at least 3 sentences.

    Counts sentences via `.`, `!`, `?` followed by whitespace or end-of-string.
    Imperfect but catches the most common failure modes: missing docstring,
    one-liner, or `pass`-equivalent.
    """
    doc = ast.get_docstring(tool, clean=True)
    if not doc:
        return Violation(
            check_id="TOOL_DOCSTRING_LENGTH",
            file=file,
            line=tool.lineno,
            tool_name=tool.name,
            message=(
                "missing docstring. MCP tool docstrings are the "
                "interface the model sees; the schema FastMCP generates "
                "exposes them as the tool description. Write at least "
                "3 sentences: what the tool does, when to use it, and "
                "what it returns or costs."
            ),
        )
    sentence_count = len(_SENTENCE_END.findall(doc.strip()))
    if sentence_count < 3:
        return Violation(
            check_id="TOOL_DOCSTRING_LENGTH",
            file=file,
            line=tool.lineno,
            tool_name=tool.name,
            message=(
                f"docstring has only {sentence_count} sentence(s); "
                f"minimum is 3. The docstring becomes the model's tool "
                f"description — vague docstrings → wrong calls. Document "
                f"what the tool does, when to use it, and what it returns "
                f"or costs."
            ),
        )
    return None


def _check_params_typed(tool: ast.AST, file: str) -> Violation | None:
    """Every parameter of an @mcp.tool() function must have a type annotation."""
    args = tool.args
    # Combine positional + keyword-only (skip implicit self/cls — tool
    # functions are module-level here, but defensive doesn't hurt).
    all_args = list(args.args) + list(args.kwonlyargs)
    untyped = [a.arg for a in all_args if a.annotation is None and a.arg not in {"self", "cls"}]
    if untyped:
        return Violation(
            check_id="TOOL_PARAMS_TYPED",
            file=file,
            line=tool.lineno,
            tool_name=tool.name,
            message=(
                f"parameter(s) without type annotation: {untyped}. "
                f"FastMCP generates JSON-Schema from these annotations; "
                f"untyped → unconstrained schema field → model passes "
                f"whatever it feels like. Add type hints to every "
                f"parameter."
            ),
        )
    return None


def _check_no_blocking_sleep(tool: ast.AST, file: str) -> Violation | None:
    """Forbid time.sleep(...) inside @mcp.tool() bodies."""
    for sub in ast.walk(tool):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "sleep"
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "time"
        ):
            kind = "async def" if isinstance(tool, ast.AsyncFunctionDef) else "def"
            replacement = (
                "use `await asyncio.sleep(...)` (and make the tool async if "
                "it isn't already)"
                if isinstance(tool, ast.FunctionDef)
                else "use `await asyncio.sleep(...)` instead"
            )
            return Violation(
                check_id="TOOL_NO_BLOCKING_SLEEP",
                file=file,
                line=tool.lineno,
                tool_name=tool.name,
                message=(
                    f"({kind}) contains `time.sleep(...)`. In a sync tool "
                    f"this blocks FastMCP's event loop for every other "
                    f"request; in an async tool it does the same. "
                    f"{replacement}."
                ),
            )
    return None


# --- Registry ---

_CHECKS = {
    "NO_ASYNCIO_RUN_INSIDE_MCP_TOOL": _check_no_asyncio_run,
    "TOOL_DOCSTRING_LENGTH": _check_docstring_length,
    "TOOL_PARAMS_TYPED": _check_params_typed,
    "TOOL_NO_BLOCKING_SLEEP": _check_no_blocking_sleep,
}


def lint_file(path: Path, skip: set[str] | None = None) -> list[Violation]:
    """Run every (non-skipped) check against one file."""
    skip = skip or set()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        return [Violation(
            check_id="PARSE_ERROR",
            file=str(path),
            line=0,
            tool_name="<file>",
            message=str(exc),
        )]

    violations: list[Violation] = []
    for tool in _find_mcp_tools(tree):
        for check_id, check_fn in _CHECKS.items():
            if check_id in skip:
                continue
            v = check_fn(tool, str(path))
            if v:
                violations.append(v)
    return violations


def discover_targets(root: Path) -> list[Path]:
    """All `*server*.py` files under root, skipping venvs/caches."""
    out: list[Path] = []
    for path in root.rglob("*server*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        out.append(path)
    return sorted(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Lint FastMCP server.py files for known bug classes."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Specific files to lint. If empty, recursively finds *server*.py.",
    )
    parser.add_argument(
        "--skip",
        default="",
        help="Comma-separated check IDs to skip (e.g., TOOL_NO_BLOCKING_SLEEP).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    args = parser.parse_args(argv[1:])

    skip = {s.strip() for s in args.skip.split(",") if s.strip()}
    if args.paths:
        targets = [Path(p) for p in args.paths]
    else:
        targets = discover_targets(Path("."))
        if not targets:
            print(
                "No `*server*.py` files found under the current directory. "
                "Pass paths explicitly.",
                file=sys.stderr,
            )
            return 2

    all_violations: list[Violation] = []
    for path in targets:
        all_violations.extend(lint_file(path, skip=skip))

    if args.format == "json":
        result = {
            "checks_run": sorted(set(_CHECKS) - skip),
            "files_scanned": [str(p) for p in targets],
            "violations": [v.as_dict() for v in all_violations],
            "exit_code": 1 if all_violations else 0,
        }
        print(json.dumps(result, indent=2))
        return 1 if all_violations else 0

    if all_violations:
        for v in all_violations:
            print(v.render(), file=sys.stderr)
        n_checks = len(set(_CHECKS) - skip)
        print(
            f"\n{len(all_violations)} violation(s) across "
            f"{len(targets)} file(s) ({n_checks} check(s) run).",
            file=sys.stderr,
        )
        return 1

    n_checks = len(set(_CHECKS) - skip)
    print(
        f"OK: no violations across {len(targets)} file(s) "
        f"({n_checks} check(s) run)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
