"""command_injection — flag tool parameters that flow into a shell sink.

Background: MCP servers that wrap a CLI (`kubectl`, `git`, `blender`,
`ffmpeg`, etc.) commonly take user-controlled strings as `@mcp.tool()`
parameters and pass them to `subprocess.*` or `os.system`. Two patterns
turn that into command injection:

  (a) `subprocess.run(..., shell=True)` — the shell parses the whole
      command string, so anything the model emits as `;rm -rf /` lands.

  (b) Building a shell-string with `f"git checkout {branch}"` or
      `"git checkout " + branch` and then handing it to `subprocess` /
      `os.system` / `os.popen`. The shell semantics apply by definition
      for `os.system`/`os.popen`; for `subprocess` they apply when
      `shell=True`.

The safe pattern is `subprocess.run(["git", "checkout", branch])` —
list-of-args, no shell, no string interpolation. This check does NOT
flag that pattern (it would be too noisy on every CLI-wrapping MCP).

What's flagged (HIGH severity):

  - `os.system(x)` / `os.popen(x)` where `x` contains a tool parameter
    (directly or after assignment through a local).
  - `subprocess.<run|Popen|call|check_call|check_output|getoutput|
    getstatusoutput>(...)` with `shell=True` AND any tool parameter
    flowing into the args.
  - The same `subprocess.*` calls with the command built as an f-string
    or string-concat from a tool parameter (regardless of `shell=`).

Taint tracking: walks the function body and propagates taint through
`Assign` / `AnnAssign` whose RHS contains a tainted expression
(Name / JoinedStr / BinOp / format-style Call). Misses cross-function
flow and aliasing through containers — known limitation, documented as
"v0.3 ships a single-function taint analyzer; cross-call taint lands in
v0.4 if there's demand."
"""
from __future__ import annotations

import ast
from pathlib import Path

from mcp_audit.finding import Finding, Severity

CHECK_ID = "command_injection"

_SKIP_DIRS = {
    ".venv", "venv", "env", "node_modules", ".git", "site-packages",
    ".tox", ".nox", "build", "dist", "__pycache__",
}

# subprocess functions that take a command argument.
_SUBPROCESS_FUNCS = {
    "run", "Popen", "call", "check_call", "check_output",
    "getoutput", "getstatusoutput",
}

# os functions that always invoke the shell.
_OS_SHELL_FUNCS = {"system", "popen"}


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _classify_call(call: ast.Call) -> str | None:
    """Return 'os_shell' for os.system/os.popen, 'subprocess' for
    subprocess.run/Popen/etc., or None for everything else."""
    fn = call.func

    # Attribute form: os.system, subprocess.run, sp.run (where sp is import alias)
    if isinstance(fn, ast.Attribute):
        attr = fn.attr
        # Walk down to the leftmost Name to identify the module-like base.
        base = fn.value
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name):
            module_id = base.id
            if module_id == "os" and attr in _OS_SHELL_FUNCS:
                return "os_shell"
            # subprocess.run / sp.run — we accept any name that looks like a
            # subprocess alias on the leftmost segment, but require the attr
            # to be in our known set.
            if attr in _SUBPROCESS_FUNCS:
                return "subprocess"

    # Bare name form: `from subprocess import run` then `run(...)`,
    # or `from os import system` then `system(...)`.
    if isinstance(fn, ast.Name):
        if fn.id in _OS_SHELL_FUNCS:
            return "os_shell"
        if fn.id in _SUBPROCESS_FUNCS:
            return "subprocess"

    return None


def _has_shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _is_string_interpolation(node: ast.expr) -> bool:
    """True if this expr is an f-string or a string-concatenation BinOp
    or a .format()/.join() call producing a string with substitutions."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # Either side is a string constant or a recursive concat
        return True
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr in {"format", "join"}:
            return True
    return False


class _TaintWalker(ast.NodeVisitor):
    """Walks a single function body. Tracks tainted local names + collects
    finding records as (lineno, message_kind, sink_kind, entry_chain).

    v0.4 adds optional cross-function recursion: when `local_functions` is
    supplied, calls to known same-file functions get expanded inline. The
    callee is walked with a tainted set derived from which callsite args
    were tainted (positional + keyword binding). A `recursion_visited` set
    prevents infinite expansion of mutual recursion. `entry_chain` records
    the call path (tool entry -> helper -> ... -> sink) so findings can be
    attributed to the @mcp.tool() entry rather than the helper file.
    """

    def __init__(
        self,
        function_name: str,
        param_names: set[str],
        *,
        local_functions: dict[str, ast.FunctionDef] | None = None,
        entry_chain: tuple[str, ...] = (),
        recursion_visited: set[tuple[str, frozenset[str]]] | None = None,
    ) -> None:
        self.function_name = function_name
        self.tainted = set(param_names)
        self.local_functions = local_functions or {}
        self.entry_chain = entry_chain or (function_name,)
        self.recursion_visited = recursion_visited if recursion_visited is not None else set()
        self.findings: list[tuple[int, str, str, tuple[str, ...]]] = []

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
            # "X".format(tainted), " ".join([tainted, ...]), etc.
            if any(self._is_tainted_expr(a) for a in node.args):
                return True
            for kw in node.keywords:
                if self._is_tainted_expr(kw.value):
                    return True
            # also propagate through bound .format()/.join() callees
            if isinstance(node.func, ast.Attribute):
                return self._is_tainted_expr(node.func.value)
        if isinstance(node, ast.Starred):
            return self._is_tainted_expr(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._is_tainted_expr(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._is_tainted_expr(v) for v in node.values if v is not None) or any(
                self._is_tainted_expr(k) for k in node.keys if k is not None
            )
        if isinstance(node, ast.IfExp):
            return self._is_tainted_expr(node.body) or self._is_tainted_expr(node.orelse)
        return False

    def _record_finding(self, lineno: int, message_kind: str, sink_kind: str) -> None:
        self.findings.append((lineno, message_kind, sink_kind, self.entry_chain))

    def _compute_callee_tainted_params(
        self, call: ast.Call, callee: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> set[str]:
        """Given a callsite + a callee definition, return the set of callee
        parameter names that become tainted (positional + keyword binding).

        Conservative: if callee has *args / **kwargs, we cannot determine the
        binding cleanly — return empty set (skip recursion). Same if the
        callsite uses a starred arg.
        """
        if callee.args.vararg or callee.args.kwarg:
            return set()
        positional_params = list(callee.args.posonlyargs) + list(callee.args.args)
        positional_names = [a.arg for a in positional_params]
        kwonly_names = {a.arg for a in callee.args.kwonlyargs}

        tainted_params: set[str] = set()
        for i, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                return set()  # can't bind cleanly
            if i >= len(positional_names):
                break
            if self._is_tainted_expr(arg):
                tainted_params.add(positional_names[i])

        for kw in call.keywords:
            if kw.arg is None:
                continue  # **kwargs spread; skip
            if kw.arg in positional_names or kw.arg in kwonly_names:
                if self._is_tainted_expr(kw.value):
                    tainted_params.add(kw.arg)
        return tainted_params

    def visit_Assign(self, node: ast.Assign) -> None:
        if self._is_tainted_expr(node.value):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    self.tainted.add(tgt.id)
                elif isinstance(tgt, (ast.Tuple, ast.List)):
                    for sub in tgt.elts:
                        if isinstance(sub, ast.Name):
                            self.tainted.add(sub.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and self._is_tainted_expr(node.value):
            if isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # name += <anything>: if RHS is tainted, target becomes tainted.
        if self._is_tainted_expr(node.value):
            if isinstance(node.target, ast.Name):
                self.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink = _classify_call(node)
        if sink is not None:
            self._maybe_record_call(node, sink)

        # Cross-function (v0.4): if the call target is a known local function
        # and at least one tainted arg is passed, walk the callee body with
        # that tainted set. Skip helpers we've already analyzed with the same
        # tainted shape (prevents infinite recursion through mutual calls).
        if self.local_functions and isinstance(node.func, ast.Name):
            callee_name = node.func.id
            callee_node = self.local_functions.get(callee_name)
            if (
                callee_node is not None
                and callee_name not in self.entry_chain  # no direct recursion
            ):
                tainted_callee_params = self._compute_callee_tainted_params(node, callee_node)
                key = (callee_name, frozenset(tainted_callee_params))
                if tainted_callee_params and key not in self.recursion_visited:
                    self.recursion_visited.add(key)
                    sub = _TaintWalker(
                        function_name=callee_name,
                        param_names=tainted_callee_params,
                        local_functions=self.local_functions,
                        entry_chain=self.entry_chain + (callee_name,),
                        recursion_visited=self.recursion_visited,
                    )
                    for child in callee_node.body:
                        sub.visit(child)
                    self.findings.extend(sub.findings)

        # always recurse — nested call might also be a sink
        self.generic_visit(node)

    def _maybe_record_call(self, call: ast.Call, sink: str) -> None:
        # Collect the args we care about. For subprocess.* the command is
        # positional[0]; for os.system/popen also positional[0]. We also
        # walk additional positional args + keyword values to catch
        # shell-injection through env-passing patterns.
        first_arg = call.args[0] if call.args else None
        tainted_first = self._is_tainted_expr(first_arg)
        interpolation = first_arg is not None and _is_string_interpolation(first_arg)

        any_tainted_arg = any(self._is_tainted_expr(a) for a in call.args)
        for kw in call.keywords:
            if self._is_tainted_expr(kw.value):
                any_tainted_arg = True
                break

        if sink == "os_shell":
            # os.system / os.popen always invoke the shell.
            if tainted_first or any_tainted_arg:
                self._record_finding(call.lineno, "os_shell", sink)
            return

        # subprocess sink: split on shell= and interpolation.
        if _has_shell_true(call) and any_tainted_arg:
            self._record_finding(call.lineno, "shell_true", sink)
            return

        # No shell=True, but the command itself is a tainted f-string /
        # concat — that's still injection-shaped if the caller ever
        # combines with shell semantics in practice (and for run-with-list
        # it just means the user passed a single big string by mistake).
        if interpolation and tainted_first:
            self._record_finding(call.lineno, "tainted_interpolation", sink)


def _build_finding(
    path: Path,
    entry_chain: tuple[str, ...],
    line: int,
    message_kind: str,
    sink_kind: str,
) -> Finding:
    # entry_chain[0] is the @mcp.tool() entry; later entries are helpers
    # the taint passed through to reach the sink. via_clause is empty for
    # the direct (v0.3) case so existing messages are unchanged.
    entry_name = entry_chain[0]
    via_helpers = entry_chain[1:]
    via_clause = (
        f" (taint flows via helper{'s' if len(via_helpers) > 1 else ''} "
        f"{' -> '.join(via_helpers)})"
        if via_helpers
        else ""
    )

    if message_kind == "os_shell":
        message = (
            f"tool '{entry_name}'{via_clause} passes a tainted value (flowing from a "
            f"tool parameter) into an `os.system` / `os.popen` call. These "
            "functions always invoke the shell, so the model can emit metacharacters "
            "(`;`, `&&`, backticks, redirects) and execute arbitrary commands."
        )
    elif message_kind == "shell_true":
        message = (
            f"tool '{entry_name}'{via_clause} calls `subprocess.*` with `shell=True` and "
            "a tainted value flowing from a tool parameter. The shell parses the "
            "whole command string, so anything the model emits as a metacharacter "
            "or chained command will execute."
        )
    elif message_kind == "tainted_interpolation":
        message = (
            f"tool '{entry_name}'{via_clause} calls `subprocess.*` with the command built "
            "as an f-string or string-concat containing a tool parameter. Even "
            "without explicit `shell=True`, this pattern is fragile (a single-string "
            "argv is parsed shell-like in many setups) and is the canonical shape "
            "of command-injection bugs in CLI-wrapping MCP servers."
        )
    else:
        message = f"tool '{entry_name}'{via_clause} passes tainted input into a shell sink."

    remediation = (
        "Pass arguments as a list and never use `shell=True`: "
        "`subprocess.run(['git', 'checkout', branch_param], check=True)`. "
        "If you genuinely need shell features, validate / quote the parameter "
        "explicitly (`shlex.quote(branch_param)`) and document why the shell "
        "is needed. Better: constrain the parameter at the schema layer with "
        "`Annotated[str, Field(pattern=r'^[a-zA-Z0-9._/-]+$')]` so injection "
        "metacharacters never reach the call at all."
    )

    return Finding(
        check=CHECK_ID,
        severity=Severity.HIGH,
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

    # v0.4: build a same-file function map so cross-function taint can recurse
    # into helpers. We use setdefault so a later same-name def doesn't shadow
    # an earlier one in a multi-def file (matches "first def wins" semantics
    # in our analysis, which avoids the edge case of decorator-replaced names).
    local_functions: dict[str, ast.FunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local_functions.setdefault(node.name, node)

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

        # Each tool entry gets its own recursion_visited set — a helper may
        # be reachable from multiple entries with different tainted shapes.
        walker = _TaintWalker(
            function_name=node.name,
            param_names=param_names,
            local_functions=local_functions,
        )
        walker.visit(node)
        for line, message_kind, sink_kind, entry_chain in walker.findings:
            findings.append(_build_finding(path, entry_chain, line, message_kind, sink_kind))

    return findings


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for py in root.rglob("*.py"):
        if _should_skip(py):
            continue
        findings.extend(_check_file(py))
    return findings
