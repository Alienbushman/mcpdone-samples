"""sql_readonly_keyword_guard — flag read-only/safe-SQL enforcement done by
inspecting the query string for keywords instead of at the connection layer.

Background: MCP servers that expose a database often advertise "read-only"
access and try to enforce it by looking at the SQL text a tool parameter
carries — allowing only queries that start with SELECT/WITH, or blocking
INSERT/UPDATE/DELETE by substring. This is not a security boundary.

Motivating real-world case (2026-07): sqlite-explorer-fastmcp's `read_query`
allowed any query whose lowercased text started with `select` or `with`. In
SQLite a `WITH ...` CTE can prefix a DELETE/UPDATE/INSERT, so
`WITH x AS (SELECT 1) DELETE FROM t -- limit` sails past the filter and
writes to a database the user believed was read-only. Casing, comments,
`ATTACH`, and stacked-statement tricks defeat keyword filters in general.

The fix is always the same: enforce read-only where the engine enforces it.
  - SQLite:   sqlite3.connect("file:db?mode=ro", uri=True)  or  PRAGMA query_only=ON
  - Postgres/MySQL: connect as a role/user with only SELECT granted, or a
    read-only transaction (SET TRANSACTION READ ONLY).

What's flagged (MEDIUM severity): an @mcp.tool() function (or a reachable
same-file helper) that BOTH
  (a) passes a value derived from a tool parameter into a SQL execution sink
      (`.execute` / `.executescript` / `.executemany` / `.exec_driver_sql`,
      or SQLAlchemy `text(...)`), AND
  (b) contains a "keyword guard": a bare SQL keyword string literal
      (select / insert / update / delete / drop / with / alter / create /
      replace / truncate / pragma / attach / ...) used as the safety check.

What's NOT flagged (false-negative bias, per the v0.3 credibility bar):
  - Connection-level read-only (mode=ro / query_only / a read-only role):
    the correct pattern — no bare-keyword guard literal is present.
  - A plain "run arbitrary SQL" tool with no read-only claim and no keyword
    guard: there is nothing to bypass, so nothing is flagged.
"""
from __future__ import annotations

import ast
from pathlib import Path

from mcp_audit.finding import Finding, Severity

CHECK_ID = "sql_readonly_keyword_guard"

_SKIP_DIRS = {
    ".venv", "venv", "env", "node_modules", ".git", "site-packages",
    ".tox", ".nox", "build", "dist", "__pycache__",
}

# SQL execution sink method names (attribute calls) + the SQLAlchemy text() ctor.
_SQL_EXEC_ATTRS = {"execute", "executescript", "executemany", "exec_driver_sql", "scalar", "scalars"}
_SQL_TEXT_FUNCS = {"text"}

# Bare SQL keyword literals that, when present as a string constant, signal a
# keyword-based guard. Matched case-insensitively against the stripped literal
# (exact word, or "verb <space> ..." head like "delete from").
_SQL_KEYWORDS = {
    "select", "insert", "update", "delete", "drop", "with", "alter",
    "create", "replace", "truncate", "pragma", "attach", "detach", "vacuum",
    "grant", "revoke", "merge", "insert into", "delete from", "update ",
    "drop table", "create table",
}


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _keyword_literal(node: ast.expr) -> bool:
    """True if node is a string constant that is (or begins with) a bare SQL
    keyword — the signature of a keyword-based read-only guard."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        v = node.value.strip().lower()
        if v in _SQL_KEYWORDS:
            return True
        # "delete from ...", "insert into ..." style heads
        head2 = " ".join(v.split()[:2])
        if head2 in _SQL_KEYWORDS:
            return True
    return False


class _Walker(ast.NodeVisitor):
    def __init__(self, param_names: set[str]) -> None:
        self.tainted = set(param_names)
        self.sink_lines: list[int] = []      # SQL exec sinks with a tainted arg
        self.guard_line: int | None = None   # first keyword-guard literal seen

    def _tainted(self, node: ast.expr | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if isinstance(node, ast.JoinedStr):
            return any(self._tainted(v) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return self._tainted(node.value)
        if isinstance(node, ast.BinOp):
            return self._tainted(node.left) or self._tainted(node.right)
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            return self._tainted(node.value)
        if isinstance(node, ast.Call):
            if any(self._tainted(a) for a in node.args):
                return True
            if isinstance(node.func, ast.Attribute):
                return self._tainted(node.func.value)  # query.strip() etc.
        return False

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._tainted(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.tainted.add(t.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and self._tainted(node.value) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
        self.generic_visit(node)

    def _is_sql_sink(self, call: ast.Call) -> bool:
        fn = call.func
        if isinstance(fn, ast.Attribute) and fn.attr in _SQL_EXEC_ATTRS:
            return True
        if isinstance(fn, ast.Name) and fn.id in _SQL_TEXT_FUNCS:
            return True
        if isinstance(fn, ast.Attribute) and fn.attr in _SQL_TEXT_FUNCS:
            return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        # keyword-guard literal anywhere (args of a call, e.g. startswith('select'),
        # or a tuple of prefixes) — capture the first line we see one.
        if self.guard_line is None:
            for sub in ast.walk(node):
                if _keyword_literal(sub):
                    self.guard_line = node.lineno
                    break
        # SQL sink with a tainted query argument
        if self._is_sql_sink(node):
            first = node.args[0] if node.args else None
            if self._tainted(first):
                self.sink_lines.append(node.lineno)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        # keyword guard via `in` / `==` comparisons: 'insert' in query.upper()
        if self.guard_line is None:
            for sub in ast.walk(node):
                if _keyword_literal(sub):
                    self.guard_line = node.lineno
                    break
        self.generic_visit(node)


def _build_finding(path: Path, tool: str, line: int) -> Finding:
    message = (
        f"tool '{tool}' enforces read-only / safe SQL by inspecting the query "
        f"string for keywords (guard near line {line}), then executes a "
        "tool-parameter query. Keyword / prefix filters are not a security "
        "boundary: a WITH-prefixed statement, a comment, casing, ATTACH, or "
        "stacked statements can slip a write past them (this is exactly the "
        "2026 sqlite-explorer read-only bypass)."
    )
    remediation = (
        "Enforce read-only where the engine does, not in the string. SQLite: "
        "sqlite3.connect('file:db?mode=ro', uri=True) or `PRAGMA query_only=ON`. "
        "Postgres/MySQL: connect as a role granted only SELECT, or open a "
        "read-only transaction (SET TRANSACTION READ ONLY). Then the query text "
        "cannot matter."
    )
    return Finding(check=CHECK_ID, severity=Severity.MEDIUM, path=path, line=line,
                   message=message, remediation=remediation)


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
        params = {a.arg for a in all_args if a.arg not in ("self", "cls")}
        if not params:
            continue
        w = _Walker(params)
        w.visit(node)
        if w.sink_lines and w.guard_line is not None:
            findings.append(_build_finding(path, node.name, w.guard_line))
    return findings


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in root.rglob("*.py"):
        if _should_skip(py):
            continue
        findings.extend(_check_file(py))
    return findings
