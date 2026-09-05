"""ts_command_injection — flag TypeScript/JavaScript MCP tool parameters that
flow into a `child_process` shell sink.

Background: an MCP server that wraps a CLI (`git`, `kubectl`, `ffmpeg`, a
package manager) usually reaches for `node:child_process`. Two of those
entry points — `exec` and `execSync` — hand the entire command string to
`/bin/sh` (or `cmd.exe` on Windows), so a `;`, `&&`, a backtick, or a
`$(...)` anywhere in an interpolated tool argument starts a second command
with the server process's privileges. The remaining entry points
(`spawn`, `spawnSync`, `execFile`, `execFileSync`, `fork`) pass an argv
array to the OS verbatim and are safe — until `{ shell: true }` is added,
which discards argv separation and re-parses everything through the shell.

The safe shape — `execFile('git', ['checkout', branch])` /
`spawn('git', args, { shell: false })` — is the dominant pattern in the
real-world corpus (`mcp-server-kubernetes`'s `execFileSyncSafe`,
`git-mcp-server`'s runtime adapter) and MUST NOT fire. It is correct code
and it is what the remediation tells the author to write.

Sink resolution is import-gated, and that gate is the whole check. A bare
textual `exec(` match is catastrophic in JavaScript: `/^v(\\d+)$/.exec(tag)`
(RegExp), `wtRe.exec(xml)`, and `db.exec(\\`CREATE TABLE …\\`)`
(better-sqlite3) are all common, all harmless, and all indistinguishable
from a shell call without knowing where the callee came from. So: a call
is a sink only when its receiver resolves — via the file's own imports —
to a namespace/default import of `child_process` / `node:child_process`,
or when a bare callee is a *named* import binding from one of those
modules. No import record, no sink, ever.

What's flagged (HIGH severity):

  - `exec(x)` / `execSync(x)` (however imported) where `x` carries a value
    flowing from the tool's first parameter — directly, through a local
    assignment, or through a `${...}` hole in a template literal.
  - `spawn` / `spawnSync` / `execFile` / `execFileSync` / `fork` called
    with an options object whose `shell` is `true` or a shell path, and a
    tool-parameter value in the command or the argument list.
  - The same argv functions where the *executable* argument (argument 0)
    is a bare tool-parameter identifier, or a template literal with a
    tainted hole — the caller chooses which binary runs.

In every one of those, the tainted value must be *spliced*: a template
hole, a `+` concatenation, or the parameter passed through raw. Taint that
only rides control flow does not count (`_taint_is_spliced`).

What's NOT flagged (false-negative bias, per the v0.3 credibility bar):

  - Any call whose callee does not resolve to a `child_process` import.
    `regexp.exec`, `db.exec`, `prisma.$executeRaw`, `page.evaluate` are
    not shell sinks and never fire.
  - The argv-array-without-a-shell pattern, in any form. This is the fix
    we recommend; flagging it would make the check unusable.
  - `shell: false` stated explicitly.

  - A local that is "tainted" only because `tstools.propagate_taint` is
    name-based, when the step that produced it is one we cannot read.
    `const bin = BINARIES[which]` (a fixed allow-list table — the shape
    this check's own remediation recommends), `const bin = mgr === "yarn"
    ? "yarn" : "npm"` (a closed set of literals), and `const clean =
    branch.replace(/[^\\w.-]/g, "")` (a hand-rolled sanitiser) are all
    tainted under that rule and all correct code. `_taint_is_spliced`
    walks one hop back to the declaration and suppresses them. The cost is
    a miss whenever the command really is built by a helper call.
  - A command template in which every tainted `${}` hole is wrapped in a
    quoting call (`JSON.stringify`, `shell-quote`'s `quote`,
    `escapeShellArg`, …). This is exactly `sentry-mcp`'s
    ``exec(`open ${JSON.stringify(url)}`)`` — correct code.
  - Any handler whose body mentions an allow-list / validation / escaping
    indicator. Deliberately broad: a validation call *anywhere* in the
    handler silences shell findings for that handler. We would rather
    miss a weak guard than cry wolf on a real one.
  - Handlers registered with no input schema. Per the SDK's own dispatch,
    a schemaless tool's callback receives the *server context* as its
    first parameter, not tool arguments — so parameter 0 is not attacker
    controlled and nothing derived from it is tainted.
  - Anything outside a statically resolvable MCP tool handler: a build
    script, a version probe, a CLI entry point. Not attacker-reachable
    over the protocol.

Known limits: analysis is confined to a single file and to the body of the
handler function itself, mirroring the Python `command_injection` check.
Taint propagates through same-body `const`/`let`/`var` declarations and
reassignments (`tstools.propagate_taint`); it does not cross function or
file boundaries. The consequence is concrete and worth stating: a server
like `desktop-commander`, which genuinely ships terminal execution as a
tool, dispatches from its handler into a manager module three files away
and is therefore NOT detected here. Following that chain needs cross-file
interprocedural taint, which is precisely the analysis shape that produced
the v0.3 command_injection retraction, and it is deliberately out of scope.
Four more misses are known and accepted, all on the suppress side:
`const execAsync = promisify(exec)` (the sink is reached through a
wrapper the import table cannot follow); a same-file helper
(`function run(c) { return execSync(c) }`); `execFileSync('/bin/bash',
['-c', script])`, where the argv array is safe but the *binary is a
shell*; and any handler whose body happens to contain one of the very
broad `_GUARD_TOKENS` (`includes`, `test`, `match`, …) for an unrelated
reason — 31% of the taint-carrying handlers in the 25-repo corpus do.
Non-`child_process` runners (`execa`, zx's `$`, `shelljs`, `Bun.spawn`,
`cross-spawn`, `Deno.Command`), `eval` / `new Function` /
`vm.runInNewContext`, and taint carried through array or object properties
are likewise not detected. Nor is a *dynamic* import — `fetch-mcp`'s
`const { execSync } = await import("child_process")` binds a real sink that
the static import table cannot see, so calls through it are invisible here.
Each of these would need its own module semantics, and every one of them
widens the sink set, which is the direction that produces false positives.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.finding import Finding, Severity
from mcp_audit import jsparse, tstools

CHECK_ID = "ts_command_injection"

# File discovery lives in mcp_audit.discovery and is applied by
# `jsparse.iter_source_files`, which prunes relative to `root`. There is no
# local skip set here any more: the per-module copies matched components of
# the ABSOLUTE path, so a checkout under a directory named `dist` or `env`
# had every file silently skipped.

# The only modules whose exports are shell sinks. A call is considered at all
# only when its callee resolves to one of these through the file's imports.
_CP_MODULES = {"child_process", "node:child_process"}

# Always spawn a shell; the command string is parsed by /bin/sh or cmd.exe.
_ALWAYS_SHELL = {"exec", "execSync"}

# argv-taking functions: safe by default, shell only when the options say so.
_ARGV_FUNCS = {"spawn", "spawnSync", "execFile", "execFileSync", "fork"}

_CP_FUNCS = _ALWAYS_SHELL | _ARGV_FUNCS

# `require('child_process').exec(...)` — an inline require has no identifier
# receiver, so `CallSite.receiver` is jsparse.UNKNOWN_RECEIVER and the import
# table cannot resolve it. This exact suffix is the one shape we accept in
# its place; it is syntactically unambiguous.
_INLINE_REQUIRE_RE = re.compile(
    r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\s*\??\.\s*$"
)

# Quoting/escaping wrappers. A tainted `${}` hole wrapped in one of these is
# considered neutralised. Matched on the LAST dotted segment, so `stringify`
# covers `JSON.stringify` (and, harmlessly, `qs.stringify` — the error
# direction is a false negative).
_QUOTE_FUNCS = {
    "stringify", "quote", "shellQuote", "shellescape", "shellEscape",
    "escapeShellArg", "shlex",
}

# Intentionally broad (false-negative bias). A validation call anywhere in
# the handler suppresses shell findings for that handler — we would rather
# miss a weak guard than cry wolf on a real one. `includes` / `test` /
# `match` in particular will fire on plenty of unrelated code; that is the
# accepted cost.
_GUARD_TOKENS = {
    "includes", "indexOf", "has", "some", "every", "test", "match",
    "safeParse", "assert", "allowlist", "allowList", "whitelist",
    "ALLOWED", "ALLOWED_COMMANDS", "sanitize", "validate", "isSafe",
}

# …plus any identifier whose lowercased form contains one of these.
_GUARD_SUBSTRINGS = ("allow", "sanitiz", "validat", "escap")

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

# A plain identifier or a dotted/optional-chained path off one: `cmd`,
# `args.cmd`, `req?.params?.arguments`. Anything with a call, an index, or an
# operator in it is NOT this.
_DOTTED_RE = re.compile(
    r"[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*"
)

# `const|let|var <name> [: T] = ` — used to walk one hop back from a local to
# the expression that produced it.
def _decl_re(name: str) -> re.Pattern[str]:
    return re.compile(
        r"(?<![\w$.])(?:const|let|var)\s+" + re.escape(name)
        + r"\s*(?::[^=;\n]*)?=(?![=>])"
    )


def _assign_re(name: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*\+?=(?![=>])")


# How many declarations deep the splice test will walk before giving up and
# firing. Two is enough for `const line = `git ${args.cmd}`` and for one
# intermediate rename; beyond that the answer is "we cannot see it".
_MAX_HOPS = 2




def _cp_bindings(
    imports: list[jsparse.ImportRecord],
) -> tuple[dict[str, str], set[str]]:
    """(bare-callable local name -> the child_process export it names,
    namespace/default import local names).

    `import { exec as run } from 'child_process'` makes `run(...)` a sink
    that must be classified as `exec`, so the mapping keeps the original
    export name rather than the local one."""
    bare: dict[str, str] = {}
    namespaces: set[str] = set()
    for rec in imports:
        if rec.module not in _CP_MODULES or not rec.local or rec.is_type_only:
            continue
        if rec.imported in ("*", "default"):
            namespaces.add(rec.local)
        else:
            bare[rec.local] = rec.imported
    return bare, namespaces


def _sink_function(
    src: jsparse.Source,
    call: jsparse.CallSite,
    bare: dict[str, str],
    namespaces: set[str],
) -> str | None:
    """The child_process export this call resolves to, or None.

    None is the answer for every call whose callee cannot be traced to a
    `child_process` import — which is what keeps `/re/.exec(s)` and
    `db.exec(sql)` out of this check entirely."""
    if not call.receiver:
        name = bare.get(call.method)
        return name if name in _CP_FUNCS else None
    if call.receiver in namespaces:
        return call.method if call.method in _CP_FUNCS else None
    if call.receiver == jsparse.UNKNOWN_RECEIVER:
        if _INLINE_REQUIRE_RE.search(src.text, 0, call.name_span.start):
            return call.method if call.method in _CP_FUNCS else None
    return None


def _contains_guard(src: jsparse.Source, body: jsparse.Span) -> bool:
    """True when the handler body shows any allow-list / validation /
    escaping indicator, in which case shell findings for the whole handler
    are suppressed."""
    if jsparse.contains_token(src, body, _GUARD_TOKENS):
        return True
    for m in _IDENT_RE.finditer(src.masked, max(0, body.start),
                                min(len(src.masked), body.end)):
        low = m.group(0).lower()
        if any(sub in low for sub in _GUARD_SUBSTRINGS):
            return True
    return False


def _real_args(src: jsparse.Source, call: jsparse.CallSite) -> list[jsparse.Span]:
    """Argument spans with the trailing-comma empty span stripped (rule R1)."""
    args = list(call.args)
    while args and src.trimmed(args[-1]).is_empty():
        args.pop()
    return args


def _is_template(src: jsparse.Source, span: jsparse.Span) -> bool:
    t = src.trimmed(span)
    return not t.is_empty() and src.text[t.start] == "`"


def _template_holes(src: jsparse.Source, span: jsparse.Span) -> list[jsparse.Span]:
    """Spans of the `${ … }` interiors inside `span`, outermost only.

    The mask keeps `${` and `}` live (that is the whole reason template
    interpolation is analysable at all), so a plain scan of the masked text
    finds them without any risk of matching a `${` that lives inside a
    string or a comment."""
    holes: list[jsparse.Span] = []
    m = src.masked
    i = max(0, span.start)
    hi = min(len(m), span.end)
    while i < hi - 1:
        j = m.find("${", i, hi)
        if j < 0:
            break
        close = jsparse.match_bracket(src, j + 1)
        if close is None or close >= hi:
            break
        holes.append(jsparse.Span(j + 2, close))
        i = close + 1
    return holes


def _is_quoted(src: jsparse.Source, hole: jsparse.Span) -> bool:
    """True when the whole hole expression is a call to a quoting helper."""
    t = src.trimmed(hole)
    if t.is_empty():
        return True
    for call in jsparse.find_calls(src, _QUOTE_FUNCS, within=hole):
        if call.call_span.start <= t.start and call.call_span.end >= t.end:
            return True
    return False


def _all_tainted_holes_quoted(
    src: jsparse.Source, span: jsparse.Span, tainted: set[str]
) -> bool:
    """True when the command is a template whose every tainted hole is
    wrapped in a quoting call.

    The motivating case: `sentry-mcp`'s device-code-flow.ts:160 does
    ``exec(`open ${JSON.stringify(url)}`)``. That is correct code — the
    value cannot escape its own argument — and firing on it would burn the
    check's credibility for no security gain."""
    holes = _template_holes(src, span)
    tainted_holes = [h for h in holes if tstools.expr_is_tainted(src, h, tainted)]
    if not tainted_holes:
        return False
    return all(_is_quoted(src, h) for h in tainted_holes)


def _shell_option(src: jsparse.Source, args: list[jsparse.Span]) -> str:
    """'on' | 'off' | 'absent' — the state of the options object's `shell`
    key. 'absent' covers both "no options object" and "an options object we
    could not read", because neither is evidence that a shell is in play."""
    if not args:
        return "absent"
    obj = jsparse.parse_object(src, args[-1])
    if obj is None or not obj.ok:
        return "absent"
    entry = obj.get("shell")
    if entry is None:
        return "absent"
    value = src.trimmed(entry.value_span)
    if value.is_empty():
        return "absent"
    if src.code(value) == "true":
        return "on"
    if src.code(value) == "false":
        return "off"
    literal = jsparse.string_literal_value(src, value)
    if literal:                      # `shell: '/bin/bash'`
        return "on"
    return "absent"


def _is_bare_tainted_identifier(
    src: jsparse.Source, span: jsparse.Span, tainted: set[str]
) -> bool:
    """True only when the span is EXACTLY a tainted identifier.

    Deliberately the tightest predicate in the module: `spawn(rgPath, args)`
    and `spawn('git', args)` are the two dominant safe shapes in the corpus
    and neither may fire. Requiring a bare identifier — not a property
    access, not a call result, not a concatenation — achieves that."""
    return src.code(src.trimmed(span)).strip() in tainted


def _depth0_plus(src: jsparse.Source, span: jsparse.Span) -> bool:
    """True when `span` contains a `+` at bracket depth 0 - i.e. the
    expression concatenates. Run on the masked text, so a `+` inside a string,
    a comment, or a `${...}` hole does not count."""
    m = src.masked
    depth = 0
    for i in range(max(0, span.start), min(len(m), span.end)):
        c = m[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth = max(0, depth - 1)
        elif c == "+" and depth == 0:
            return True
    return False


def _expr_end(src: jsparse.Source, start: int, limit: int) -> int:
    """End of the expression beginning at `start`. A local ASI approximation:
    stops at a depth-0 `;` or `,`, at an unbalanced closer, and at a newline
    that is not an obvious continuation."""
    m = src.masked
    depth = 0
    i = start
    while i < limit:
        c = m[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0:
            if c in ";,":
                break
            if c == "\n":
                j = i + 1
                while j < limit and m[j] in " \t\r":
                    j += 1
                if j >= limit or m[j] not in ".?+-*/%&|^:":
                    break
                i = j
                continue
        i += 1
    return i


def _declarations(
    src: jsparse.Source, body: jsparse.Span, name: str
) -> tuple[list[jsparse.Span], set[int]]:
    """(initializer spans of every `const|let|var <name> = ...` in `body`,
    the offsets of those declarations' `=` signs)."""
    lo = max(0, body.start)
    hi = min(len(src.masked), body.end)
    inits: list[jsparse.Span] = []
    eqs: set[int] = set()
    for m in _decl_re(name).finditer(src.masked, lo, hi):
        eqs.add(m.end() - 1)
        end = _expr_end(src, m.end(), hi)
        if end > m.end():
            inits.append(jsparse.Span(m.end(), end))
    return inits, eqs


def _reassigned(
    src: jsparse.Source, body: jsparse.Span, name: str, decl_eqs: set[int]
) -> bool:
    """True when `name` is assigned anywhere in `body` outside its own
    declarations. Its value then has a source we did not read, so the
    declaration is not evidence of anything and we must not suppress on it."""
    lo = max(0, body.start)
    hi = min(len(src.masked), body.end)
    for m in _assign_re(name).finditer(src.masked, lo, hi):
        eq = src.masked.find("=", m.start(), m.end())
        if eq not in decl_eqs:
            return True
    return False


def _strip_casts(code: str) -> str:
    """`args.cmd as string` / `args.cmd!` -> `args.cmd`. The mask has already
    blanked string interiors, so an ` as ` inside a literal cannot match."""
    i = code.find(" as ")
    if i > 0:
        code = code[:i]
    return code.rstrip("!").strip()


def _taint_is_spliced(
    src: jsparse.Source,
    span: jsparse.Span,
    roots: set[str],
    tainted: set[str],
    body: jsparse.Span,
    depth: int = 0,
) -> bool:
    """True when attacker DATA - not merely attacker-influenced control flow -
    reaches this expression.

    `tstools.propagate_taint` is name-based and unconditional: any local whose
    initializer so much as *mentions* a parameter becomes tainted. That is the
    right default for a taint engine and the wrong one for a HIGH-severity
    shell finding, because

        const bin   = manager === "yarn" ? "yarn" : "npm";
        const bin   = BINARIES[which];            // a fixed allow-list table
        const clean = branch.replace(/[^\\w.-]/g, "");

    are all "tainted" under that rule and all correct code - the middle one is
    the allow-list pattern this check's own remediation recommends. Firing on
    them is the v0.3 retraction repeating itself.

    So a value counts as spliced only when the splice is visible: a template
    hole, a `+` concatenation, or the raw parameter itself. A bare local is
    followed one hop back to its declaration (at most `_MAX_HOPS`) and judged
    there; a local produced by something we cannot read - a call, a table
    lookup, a conditional over literals - is NOT spliced, because in practice
    that unreadable step is the sanitiser. False-negative bias, deliberately.

    One place we stay loud: at the call site itself (`depth == 0`) an
    expression that is neither a template, a concatenation, nor a plain path -
    `exec(buildCommand(cmd))` - still fires. We do not second-guess a call
    written directly into the sink."""
    t = src.trimmed(span)
    if t.is_empty() or not tstools.expr_is_tainted(src, t, tainted):
        return False

    if src.text[t.start] == "`":
        return any(
            _taint_is_spliced(src, h, roots, tainted, body, depth)
            for h in _template_holes(src, t)
        )

    if _depth0_plus(src, t):
        return True

    code = _strip_casts(src.code(t).strip())
    if _DOTTED_RE.fullmatch(code):
        base = code.split(".")[0].replace("?", "").strip()
        if base in roots:
            return True              # the raw parameter, or a field of it
        if code != base or depth >= _MAX_HOPS:
            return True              # cannot walk it back: stay loud
        inits, eqs = _declarations(src, body, base)
        if not inits or _reassigned(src, body, base, eqs):
            return True
        return any(
            _taint_is_spliced(src, init, roots, tainted, body, depth + 1)
            for init in inits
        )

    return depth == 0


def _classify(
    src: jsparse.Source,
    call: jsparse.CallSite,
    fn_name: str,
    roots: set[str],
    tainted: set[str],
    body: jsparse.Span,
) -> str | None:
    """The finding variant for a resolved child_process call, or None."""
    args = _real_args(src, call)
    if not args:
        return None

    if fn_name in _ALWAYS_SHELL:
        if not tstools.expr_is_tainted(src, args[0], tainted):
            return None
        # Quoted interpolation is the correct way to use a shell; suppress.
        if _all_tainted_holes_quoted(src, args[0], tainted):
            return None
        # Control-flow taint is not command injection; require a real splice.
        if not _taint_is_spliced(src, args[0], roots, tainted, body):
            return None
        return "always_shell"

    shell = _shell_option(src, args)
    if shell == "on":
        if any(tstools.expr_is_tainted(src, a, tainted) for a in args[:2]):
            return "shell_option"
        return None
    if shell == "off":
        # `shell: false` stated explicitly — argv separation holds. The
        # executable-choice variant is not evaluated here on purpose: an
        # author who wrote `shell: false` has already thought about this
        # call, and we stay quiet rather than second-guess them.
        return None

    # No shell: the only remaining danger is the caller choosing the binary.
    #
    # NOTE both tests run against `roots`, not the propagated set. The message
    # says "passes a RAW tool parameter as the executable", and that is exactly
    # what the code must mean. Under the propagated set,
    # `const bin = BINARIES[which]` and `const bin = mgr === "yarn" ? "yarn"
    # : "npm"` both fire, and both are correct code - the first one is the
    # allow-list table our own remediation asks for.
    if _is_bare_tainted_identifier(src, args[0], roots):
        return "tainted_executable"
    if _is_template(src, args[0]):
        holes = _template_holes(src, args[0])
        if any(_taint_is_spliced(src, h, roots, tainted, body) for h in holes):
            return "tainted_executable"
    return None


def _build_finding(
    path: Path, tool: str, line: int, kind: str, fn_name: str
) -> Finding:
    if kind == "always_shell":
        message = (
            f"tool '{tool}' passes a value flowing from a tool parameter into "
            "`child_process.exec` / `execSync`. Both functions hand the whole "
            "string to `/bin/sh` (or `cmd.exe`), so a `;`, `&&`, a backtick, or "
            "a `$(...)` emitted by the model — directly, or by prompt-injecting "
            "the model that calls the tool — executes as a separate command "
            "with the server process's privileges."
        )
    elif kind == "shell_option":
        message = (
            f"tool '{tool}' calls `child_process.{fn_name}` with `shell: true` "
            "and a tool-parameter value in the command or argument list. The "
            "`shell` option discards Node's argv separation and re-parses "
            "everything through the system shell, so argument arrays give no "
            "protection here — metacharacters in any element are interpreted."
        )
    else:  # tainted_executable
        message = (
            f"tool '{tool}' passes a raw tool parameter as the *executable* "
            f"argument of `child_process.{fn_name}`. Even without a shell, the "
            "caller chooses which binary runs; a path to any executable on the "
            "host, or one dropped by an earlier tool call, is launched with the "
            "server process's privileges."
        )

    remediation = (
        "Pass a fixed binary and an argument array, with no shell: "
        "`execFile('git', ['checkout', branch], cb)` or "
        "`spawn('git', ['checkout', branch], { shell: false })`. Node passes "
        "each array element to the OS verbatim, so metacharacters are inert. "
        "If a shell feature is genuinely required, quote every interpolated "
        "value (`shell-quote`'s `quote([v])`, or `JSON.stringify(v)` for a "
        "single argument) and say in a comment why the shell is needed. "
        "Constraining the parameter at the schema layer "
        "(`z.string().regex(/^[A-Za-z0-9._\\/-]+$/)`) is a good second layer "
        "but is not sufficient on its own — fix the call."
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
    src = jsparse.load(path)
    if src is None or not src.ok:
        # A degraded lex must never emit a finding.
        return []

    # Cheapest gate first: a file that never names child_process cannot hold
    # a sink, whatever else it does.
    bare, namespaces = _cp_bindings(jsparse.collect_imports(src))
    if not bare and not namespaces and "child_process" not in src.text:
        return []

    handlers = tstools.find_tool_handlers(src)
    if not handlers:
        return []

    # Bare callees may have been renamed at the import site
    # (`import { exec as run } …`), so search for those local names too.
    wanted = set(_CP_FUNCS) | {
        local for local, imported in bare.items() if imported in _CP_FUNCS
    }

    findings: list[Finding] = []
    # One finding per sink call site (mirrors the Python command_injection
    # granularity). `seen` exists only because tstools can legitimately return
    # two handlers with overlapping bodies — a wrapped low-level dispatcher —
    # and the same physical call must not be reported twice.
    seen: set[int] = set()

    for handler in handlers:
        fn = handler.fn
        if not fn.params_ok:
            continue          # hard suppress: a pattern we could not parse
        tainted = set(handler.taint_roots)
        if not tainted:
            # No schema, or a zero-parameter handler: parameter 0 is the
            # server context, not tool arguments. Nothing is attacker
            # controlled, so nothing here can be command injection.
            continue
        # A validation / allow-list guard anywhere in the handler suppresses
        # findings for that handler.
        if _contains_guard(src, fn.body_span):
            continue

        roots = tainted
        tainted = tstools.propagate_taint(src, fn.body_span, tainted)

        for call in jsparse.find_calls(src, wanted, within=fn.body_span):
            fn_name = _sink_function(src, call, bare, namespaces)
            if fn_name is None:
                continue          # not import-resolved => not a shell sink
            if call.call_span.start in seen:
                continue
            kind = _classify(src, call, fn_name, roots, tainted, fn.body_span)
            if kind is None:
                continue
            seen.add(call.call_span.start)
            # A low-level `switch (name)` dispatcher has no per-tool
            # registration, so the enclosing `case "…":` label is the only
            # name we can put in front of the reader. Prose only.
            tool = handler.display_name
            if handler.style == "lowlevel":
                label = tstools.case_label_at(src, fn.body_span,
                                              call.call_span.start)
                if label:
                    tool = label
            findings.append(
                _build_finding(src.path, tool, call.line, kind, fn_name)
            )

    return findings


def check(root: Path, *, include_build: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for path in jsparse.iter_source_files(root, include_build=include_build):
        findings.extend(_check_file(path))
    return findings
