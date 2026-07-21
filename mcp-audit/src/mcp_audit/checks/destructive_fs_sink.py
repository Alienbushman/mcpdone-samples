"""destructive_fs_sink — flag tool parameters that flow into a destructive
filesystem call without a containment guard.

Background: an MCP server that manages files on disk (a scratch/temp dir, a
workspace, an output folder) often exposes a "cleanup" or "delete" tool.
When that tool takes a path as an `@mcp.tool()` parameter and hands it
straight to `shutil.rmtree` / `os.remove` / `os.unlink` / `os.rmdir` /
`Path.unlink` / `Path.rmdir`, an attacker who can influence the tool
arguments — directly, or via prompt-injection of the driving LLM — can
delete arbitrary paths the server process can reach.

Motivating real-world case (2026-07): `manim-mcp-server`'s
`cleanup_manim_temp_dir(directory)` calls `shutil.rmtree(directory)` with
no scoping — the docstring says "the Manim temporary directory" but the
implementation deletes *any* path. mcp-audit's other four checks all
missed it (it is neither a shell sink nor a dependency pin); this check
exists to catch exactly that shape.

What's flagged (MEDIUM severity):

  - `shutil.rmtree(p)`, `os.remove(p)`, `os.unlink(p)`, `os.rmdir(p)`,
    `os.removedirs(p)` (and their `from … import` bare-name forms) where
    `p` is a tool parameter (directly or after assignment through a local).
  - `p.unlink(...)` / `p.rmdir(...)` method calls where the receiver `p`
    is a tainted path (a `pathlib.Path` built from a tool parameter).

What's NOT flagged (deliberately biased toward false negatives — the
credibility bar set by the v0.3 command_injection retraction):

  - The path argument is a server-side constant / env value, not a tool
    parameter. (Deleting a fixed, server-managed dir is the intended job.)
  - The function contains a *containment guard* — any canonicalize-then-
    confine pattern (`os.path.realpath`/`abspath`/`normpath`/`commonpath`/
    `relpath`, `Path.resolve`/`.relative_to`/`.is_relative_to`/`.samefile`,
    a `.startswith(BASE)` check, or a membership test of the path against a
    server-managed allow-set). Presence of *any* such guard suppresses the
    finding for the whole function — we would rather miss a weak guard than
    cry wolf on a real one.

Taint tracking mirrors `command_injection`: single-file, propagating taint
through `Assign` / `AnnAssign` / `AugAssign` whose RHS contains a tainted
expression. Cross-file flow is out of scope.
"""
from __future__ import annotations

import ast
from pathlib import Path

from mcp_audit.finding import Finding, Severity

CHECK_ID = "destructive_fs_sink"

_SKIP_DIRS = {
    ".venv", "venv", "env", "node_modules", ".git", "site-packages",
    ".tox", ".nox", "build", "dist", "__pycache__",
}

# module.attr destructive sinks: {module_name: {attr, ...}}
_MODULE_SINKS = {
    "shutil": {"rmtree"},
    "os": {"remove", "unlink", "rmdir", "removedirs"},
}
# bare-name forms after `from shutil import rmtree` / `from os import remove`.
_BARE_SINKS = {"rmtree", "removedirs"}  # names unambiguous enough on their own
# pathlib.Path bound-method sinks: `p.unlink()`, `p.rmdir()`.
_PATH_METHOD_SINKS = {"unlink", "rmdir"}

# Containment / canonicalization indicators. If a tool function calls any of
# these, we assume it confines the path and suppress destructive findings in
# that function. Intentionally broad (false-negative bias).
_GUARD_ATTRS = {
    "realpath", "abspath", "normpath", "commonpath", "commonprefix", "relpath",
    "resolve", "relative_to", "is_relative_to", "samefile", "startswith",
}


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _classify_sink(call: ast.Call) -> str | None:
    """Return the destructive-sink kind for a call, or None.

    Kinds: 'module' (shutil.rmtree / os.remove / …), 'bare' (imported name),
    'method' (p.unlink() / p.rmdir())."""
    fn = call.func

    if isinstance(fn, ast.Attribute):
        base = fn.value
        # module.attr form: shutil.rmtree, os.remove
        if isinstance(base, ast.Name) and base.id in _MODULE_SINKS and fn.attr in _MODULE_SINKS[base.id]:
            return "module"
        # bound-method form: <expr>.unlink(), <expr>.rmdir()
        if fn.attr in _PATH_METHOD_SINKS:
            return "method"

    if isinstance(fn, ast.Name) and fn.id in _BARE_SINKS:
        return "bare"

    return None


def _contains_guard(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the function body shows any path-containment / canonicalization
    indicator, in which case we suppress destructive findings for it."""
    for node in ast.walk(func):
        if isinstance(node, ast.Attribute) and node.attr in _GUARD_ATTRS:
            return True
        # membership test: `if directory in TEMP_DIRS` / `not in allowset`
        if isinstance(node, ast.Compare):
            for op in node.ops:
                if isinstance(op, (ast.In, ast.NotIn)):
                    return True
    return False


class _FsTaintWalker(ast.NodeVisitor):
    """Walks a single @mcp.tool() function body. Tracks tainted local names
    (seeded from the tool parameters) and records destructive-sink hits whose
    path argument (or bound-method receiver) is tainted."""

    def __init__(self, function_name: str, param_names: set[str]) -> None:
        self.function_name = function_name
        self.tainted = set(param_names)
        self.findings: list[tuple[int, str]] = []  # (lineno, sink_kind)

    def _is_tainted_expr(self, node: ast.expr | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.JoinedStr):
            return any(self._is_tainted_expr(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.BinOp):
            return self._is_tainted_expr(node.left) or self._is_tainted_expr(node.right)
        if isinstance(node, ast.Subscript):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.Attribute):
            return self._is_tainted_expr(node.value)
        if isinstance(node, ast.Call):
            # Path(tainted), os.path.join(base, tainted), tainted.strip(), …
            if any(self._is_tainted_expr(a) for a in node.args):
                return True
            for kw in node.keywords:
                if self._is_tainted_expr(kw.value):
                    return True
            if isinstance(node.func, ast.Attribute):
                return self._is_tainted_expr(node.func.value)
        if isinstance(node, ast.Starred):
            return self._is_tainted_expr(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted_expr(e) for e in node.elts)
        if isinstance(node, ast.IfExp):
            return self._is_tainted_expr(node.body) or self._is_tainted_expr(node.orelse)
        return False

    def _propagate(self, targets: list[ast.expr], value: ast.expr | None) -> None:
        if value is None or not self._is_tainted_expr(value):
            return
        for tgt in targets:
            if isinstance(tgt, ast.Name):
                self.tainted.add(tgt.id)
            elif isinstance(tgt, (ast.Tuple, ast.List)):
                for sub in tgt.elts:
                    if isinstance(sub, ast.Name):
                        self.tainted.add(sub.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._propagate(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._propagate([node.target], node.value)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._propagate([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        kind = _classify_sink(node)
        if kind is not None:
            tainted = False
            if kind == "method":
                # receiver is the path: <receiver>.unlink()
                if isinstance(node.func, ast.Attribute):
                    tainted = self._is_tainted_expr(node.func.value)
            else:
                first = node.args[0] if node.args else None
                tainted = self._is_tainted_expr(first)
            if tainted:
                self.findings.append((node.lineno, kind))
        self.generic_visit(node)


def _sink_label(kind: str) -> str:
    return {
        "module": "`shutil.rmtree` / `os.remove` / `os.unlink` / `os.rmdir`",
        "bare": "an imported `rmtree` / `removedirs`",
        "method": "a `Path.unlink()` / `Path.rmdir()`",
    }.get(kind, "a destructive filesystem call")


def _build_finding(path: Path, tool_name: str, line: int, kind: str) -> Finding:
    message = (
        f"tool '{tool_name}' passes a value flowing from a tool parameter into "
        f"{_sink_label(kind)} with no path-containment guard. An attacker who "
        "influences the argument (directly, or by prompt-injecting the model "
        "that calls the tool) can delete arbitrary files or directories the "
        "server process can reach — the tool's advertised scope (a temp/work "
        "dir) is not enforced in code."
    )
    remediation = (
        "Confine the path before deleting: canonicalize with "
        "`os.path.realpath` (or `Path.resolve()`), then assert it is inside a "
        "fixed base dir "
        "(`if not real.startswith(BASE): raise ValueError`, or "
        "`Path(real).relative_to(BASE)`), and/or check it against a "
        "server-managed allow-set of paths you created. Never pass a raw tool "
        "parameter straight to a delete call. Constraining the schema "
        "(`Annotated[str, Field(pattern=...)]`) helps but is not sufficient on "
        "its own — enforce containment at the sink."
    )
    return Finding(
        check=CHECK_ID,
        severity=Severity.MEDIUM,
        path=path,
        line=line,
        message=message,
        remediation=remediation,
    )


def _check_file(path: Path) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
            continue

        all_args = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        param_names = {a.arg for a in all_args if a.arg not in ("self", "cls")}
        if not param_names:
            continue

        # A containment guard anywhere in the function suppresses findings.
        if _contains_guard(node):
            continue

        walker = _FsTaintWalker(node.name, param_names)
        walker.visit(node)
        for line, kind in walker.findings:
            findings.append(_build_finding(path, node.name, line, kind))

    return findings


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in root.rglob("*.py"):
        if _should_skip(py):
            continue
        findings.extend(_check_file(py))
    return findings
