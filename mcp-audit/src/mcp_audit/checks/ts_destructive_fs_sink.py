"""ts_destructive_fs_sink — flag TypeScript/JavaScript MCP tool parameters
that flow into a destructive Node filesystem call without a containment guard.

Background: a TypeScript MCP server that manages files on disk (a scratch
dir, a workspace, an output folder) usually exposes a "cleanup" or "delete"
tool. When that tool takes a path from its `inputSchema` and hands it
straight to `fs.rm` / `fs.rmSync` / `fs.promises.rm` / `unlink` / `rmdir`,
`fs-extra`'s `remove` / `emptyDir`, or the `rimraf` / `del` packages, an
attacker who can influence the tool arguments — directly, or by
prompt-injecting the model that calls the tool — deletes arbitrary paths the
Node process can reach. With `{ recursive: true }` that is a whole subtree.

Motivating real-world case (2026-07): the Python sibling of this check,
`destructive_fs_sink`, was written for `manim-mcp-server`'s
`cleanup_manim_temp_dir(directory)` — a docstring that says "the Manim
temporary directory" over an implementation that deletes *any* path. The
same shape is written `async ({ dir }) => fs.promises.rm(dir, { recursive:
true })` in TypeScript, and until v0.9 mcp-audit opened zero `.ts` files: it
printed "OK — 0 findings" on every TypeScript server it was pointed at. A
false clean bill of health is the worst failure mode a scanner has; this
check is half of the fix.

What's flagged (MEDIUM severity):

  - `fs.rm(p)` / `fs.rmSync(p)` / `fs.rmdir(p)` / `fs.unlink(p)` (and the
    `Sync` forms), `fs.promises.rm(p)`, `fsp.unlink(p)` — where the receiver
    resolves through an *import record* to `fs`, `node:fs`, `fs/promises`,
    or `node:fs/promises`.
  - `fse.remove(p)` / `fse.emptyDir(p)` — receiver resolving to `fs-extra`.
  - `rimraf(p)` / `rimrafSync(p)` / `del(p)` / `deleteSync(p)` — where the
    callee is an import binding from the `rimraf` or `del` package.

  …and only when `p` carries a value flowing from parameter 0 of a
  statically-resolvable MCP tool handler (`server.registerTool`,
  `server.tool`, `addTool`/`defineTool` descriptors, or a low-level
  `setRequestHandler(CallToolRequestSchema, …)` dispatch).

What's NOT flagged (false-negative bias, per the v0.3 credibility bar):

  - Any call whose callee does not resolve to an import of one of those
    modules. `cache.remove(k)`, `store.del(k)`, `map.rm(id)`, and
    `getFs().unlink(p)` are ordinary JavaScript; `rm` / `remove` / `del` /
    `unlink` are far too common as plain method names to match textually.
    No import record ⇒ not a sink, ever.
  - Any *containment guard* anywhere in the handler body: `path.resolve`,
    `realpath`, `path.relative`, `normalize`, `isAbsolute`, `startsWith`,
    a membership test (`includes` / `indexOf` / `has` / `some` / `every`),
    or any identifier whose name reads as validation / allow-listing /
    confinement. Presence of *any* such guard suppresses every destructive
    finding for that handler — we would rather miss a weak guard than cry
    wolf on a real one. `official-servers/src/filesystem/index.ts` routes
    every delete through `await validatePath(args.path)` and must stay
    silent.
  - A registration whose handler is a factory call, a member expression, a
    cross-file forward, or an identifier that does not resolve in this file;
    and any handler whose parameter list does not parse cleanly
    (`FunctionBody.params_ok` False).
  - A registration whose input schema is a *closed set*: every declared
    field is `z.enum` / `z.literal` / `z.boolean` / `z.number` / … so no
    argument can express a path at all. `fs.rm(path.join(BASE, args.which))`
    under `{ which: z.enum(["logs", "cache"]) }` is correct code.
  - A path that reaches the sink only through the RETURN VALUE of a call we
    cannot see into. `const r = await runBuild(args.src); fs.rm(r.tmpDir)`
    deletes a directory the callee chose, not the tool parameter. Path
    arithmetic and `.parse()` are exempt, so `path.join(BASE, args.dir)`
    still propagates and still fires.
  - A schemaless registration. With no `inputSchema` the SDK calls
    `handler(extra)`, so parameter 0 is the *server context*, not the tool
    arguments — treating it as attacker-controlled would fire on
    `server.tool("getConsoleLogs", "Check our browser logs", async () => …)`,
    which accepts no input at all.
  - `recursive: true` as a separate/raised severity. One severity, one
    message; splitting on the option adds a knob nobody tunes.
  - Overwrite-shaped destruction (`fs.writeFile(p, "")`, `fs.truncate`,
    `fs.rename`, `fs.cp` with `force`). The Python sibling deliberately
    omits the analogous `open(p, "w")` / `os.rename` / `shutil.move`; this
    check stays symmetric with it.
  - Any file whose lex is degraded (`Source.ok` False). A finding anchored
    to a mis-lexed offset is exactly the v0.3 defect class.

Known limits: analysis is single-file and confined to the handler body, the
same boundary the Python checks draw. Taint is textual — seeded from the
handler's parameter-0 bindings and propagated through `const`/`let`/`var`
declarations and reassignments whose initializer references a tainted name.
Cross-file interprocedural flow is deliberately out of scope: the dominant
real deletion shape in the wild (`filesystem-mcp-server`'s registration
arrow forwarding to `deleteFileLogic.ts`) puts the sink in another module,
and we will not see it. Following that chain is the analysis shape that
produced the v0.3 command_injection retraction, so the miss is accepted and
recorded rather than guessed at. Expect this check to be silent on most
real repositories; that is the designed behaviour, not a broken engine.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.finding import Finding, Severity
from mcp_audit import jsparse

CHECK_ID = "ts_destructive_fs_sink"

# File discovery lives in mcp_audit.discovery, applied by
# `jsparse.iter_source_files` and pruned relative to `root`. The local
# absolute-path skip set this module used to carry is gone; see discovery.py
# for why it was a silent-clean hazard.

# Import prefixes that prove this file is MCP server code. Without this gate,
# `registry.tool(...)` / `observer.tool(...)` in unrelated libraries would be
# read as tool registrations.
_MCP_MODULE_MARKERS = (
    "@modelcontextprotocol/", "fastmcp", "mcp-lite", "@vercel/mcp-adapter",
    "agents/mcp",
)

# Node fs delete sinks. Reached only when the receiver resolves to an import
# of one of _FS_MODULES — `fs` is a very common local variable name.
_FS_MODULES = {"fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"}
_PROMISES_MODULES = {"fs/promises", "node:fs/promises"}
_FS_SINKS = {
    "rm", "rmSync", "rmdir", "rmdirSync",
    "unlink", "unlinkSync",
    "remove", "removeSync",          # fs-extra
    "emptyDir", "emptyDirSync",      # fs-extra
}
# Standalone delete packages; bare-callable, so the import gate is the only
# thing separating them from an unrelated local function.
_PKG_SINKS = {
    "rimraf": {"rimraf", "rimrafSync", "sync", "native"},
    "del": {"del", "deleteSync", "deleteAsync"},
}
_ALL_SINK_METHODS = set(_FS_SINKS) | {n for names in _PKG_SINKS.values() for n in names}

# Containment / canonicalization indicators. If a handler body mentions any
# of these, we assume it confines the path and suppress destructive findings
# for that handler. Intentionally broad (false-negative bias) — `resolve` in
# particular also matches Promise.resolve, and we accept that.
_GUARD_TOKENS = {
    "resolve", "realpath", "realpathSync", "normalize", "relative",
    "isAbsolute", "startsWith", "includes", "indexOf", "has", "some",
    "every", "validatePath", "resolvePath", "assertPath", "checkPath",
    "safePath", "withinRoot", "isInside", "sanitize", "allowedDirectories",
}
# …plus any identifier whose lowercased form contains one of these. Catches
# `confine()`, `assertWithinWorkspace()`, `ALLOWED_ROOTS`, `sanitizePath()`.
#
# The action-verb fragments ("assert", "ensure", "verify", "guard", "resolv",
# "canonical", "normali", "restrict") were added after an adversarial pass
# found that `assertUnderRoot(args.dir)` and `resolveWorkspacePath(args.dir)`
# — two perfectly ordinary containment helpers — matched neither the exact
# token list (which has `assertPath`/`resolvePath`, not these) nor the
# original six substrings, so correct code was flagged. Widening here only
# ever SUPPRESSES, which is the direction this check is required to err in.
# NB "contain" deliberately does not match "content" (…t-a-i-n vs …t-e-n-t),
# so a handler returning `{ content: [...] }` is not self-suppressing.
_GUARD_SUBSTRINGS = (
    "validat", "sanitiz", "allow", "within", "contain", "confin",
    "assert", "ensure", "verify", "guard", "resolv", "canonical",
    "normali", "safe", "restrict", "traver", "jail", "boundar",
    "permit", "whitelist", "denylist", "blocklist",
)

# Object keys that carry a tool's input schema, by registration style.
_SCHEMA_KEYS = ("inputSchema", "parameters", "schema")
# Object keys whose value is the handler function, for descriptor styles.
_HANDLER_KEYS = ("handler", "execute", "cb", "callback", "run", "handle")

_IDENT_FULL_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_IDENT_SCAN_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_DECL_RE = re.compile(
    r"(?<![\w$])(?:const|let|var)(?![\w$])\s*"
    r"(?P<lhs>\{[^{}]*\}|[A-Za-z_$][\w$]*)"
    r"(?:\s*:[^=;\n]*)?\s*=(?!=)"
)
_ASSIGN_RE = re.compile(r"(?<![\w$])(?P<name>[A-Za-z_$][\w$]*)\s*\+?=(?![=>])")
_CASE_RE = re.compile(r"(?<![\w$])case(?![\w$])\s*")




# ==========================================================================
# MCP tool-handler surface (design §3, implemented locally per house style:
# each check module is self-contained; only the lexer is shared)
# ==========================================================================
class _Handler:
    """One statically-resolvable MCP tool handler: its function body, the
    names that parameter 0 binds (empty when the registration declares no
    input schema), and a display name for prose."""

    def __init__(self, tool_name: str, fn: jsparse.FunctionBody,
                 seeds: frozenset[str], lowlevel: bool) -> None:
        self.tool_name = tool_name
        self.fn = fn
        self.seeds = seeds
        self.lowlevel = lowlevel

    @property
    def display_name(self) -> str:
        return self.tool_name or "<anonymous>"


def _file_imports_mcp(src: jsparse.Source, imports: list[jsparse.ImportRecord]) -> bool:
    """True when the file imports an MCP SDK / framework module. Type-only
    imports count — they prove MCP context even though they bind nothing."""
    for rec in imports:
        for marker in _MCP_MODULE_MARKERS:
            if rec.module.startswith(marker) or rec.module == marker:
                return True
    return False


def _strip_trailing_empty(src: jsparse.Source, args: tuple[jsparse.Span, ...]) -> list[jsparse.Span]:
    """Rule R1: a trailing comma yields a trailing empty argument span."""
    out = list(args)
    while out and src.trimmed(out[-1]).is_empty():
        out.pop()
    return out


def _is_schema_like(src: jsparse.Source, span: jsparse.Span) -> bool:
    """Any call expression (`z.string()`, `type("string")`, `v.object({})`)
    or an `<ident>.shape`. Deliberately NOT `startswith('z.')` — arktype and
    valibot schemas appear in the fastmcp ecosystem. ToolAnnotations values
    are all primitives, so this separates the two overload slots cleanly."""
    t = src.trimmed(span)
    if t.is_empty():
        return False
    txt = src.code(t)
    if txt.endswith(")") and "(" in txt:
        return True
    return txt.endswith(".shape")


def _is_raw_shape(src: jsparse.Source, span: jsparse.Span) -> bool:
    """Port of the SDK's `isZodRawShapeCompat`. `{}` IS a raw shape — the SDK
    then calls the handler with an (empty) args object as parameter 0."""
    obj = jsparse.parse_object(src, span)
    if obj is None or not obj.ok:
        return False
    if not obj.entries:
        return True
    return any(_is_schema_like(src, e.value_span) for e in obj.entries)


def _schema_is_non_empty(src: jsparse.Source, span: jsparse.Span) -> bool:
    obj = jsparse.parse_object(src, span)
    if obj is not None:
        return bool(obj.entries)
    return not src.trimmed(span).is_empty()


# Zod types whose inhabitants form a closed set that cannot express a path:
# an enum, a literal, or a non-string primitive. `z.string()` is absent by
# design, and so is anything we cannot name — an unrecognized type is
# treated as path-admitting.
_CLOSED_SET_TYPE_RE = re.compile(
    r"[A-Za-z_$][\w$]*\s*\.\s*"
    r"(?:enum|nativeEnum|literal|boolean|number|bigint|date|never|void)\s*\("
)
_SCHEMA_OBJECT_WRAPPER_RE = re.compile(r"[A-Za-z_$][\w$]*\s*\.\s*object\s*\(")


def _schema_object(src: jsparse.Source, span: jsparse.Span) -> jsparse.ObjectLiteral | None:
    """The schema's field map: a bare `{ … }` raw shape, or the object inside
    a `z.object({ … })` wrapper. None when it is neither."""
    obj = jsparse.parse_object(src, span)
    if obj is not None:
        return obj
    t = src.trimmed(span)
    mt = _SCHEMA_OBJECT_WRAPPER_RE.match(src.code(t))
    if mt is None:
        return None
    open_paren = t.start + mt.end() - 1
    close = jsparse.match_bracket(src, open_paren)
    if close is None:
        return None
    return jsparse.parse_object(src, jsparse.Span(open_paren + 1, close))


def _schema_admits_a_path(src: jsparse.Source, span: jsparse.Span) -> bool:
    """False only when EVERY declared field is a closed-set, non-string type.

    `{ which: z.enum(["logs", "cache"]) }` cannot carry a traversal, so a
    `fs.rm(path.join(BASE, args.which))` under it is correct code and must
    stay silent — flagging it was a real false positive found by adversarial
    review. Anything unparseable, spread, shorthand, or of a type not on the
    closed-set list returns True (fire), so this can only ever suppress.
    """
    obj = _schema_object(src, span)
    if obj is None or not obj.ok or obj.has_spread or not obj.entries:
        return True
    for entry in obj.entries:
        if entry.is_spread or entry.is_shorthand or entry.is_method or not entry.key:
            return True
        value = src.code(src.trimmed(entry.value_span))
        if _CLOSED_SET_TYPE_RE.match(value) is None:
            return True
    return False


def _resolve_function(src: jsparse.Source, span: jsparse.Span,
                      bindings: dict[str, jsparse.Binding]) -> jsparse.FunctionBody | None:
    """The handler argument as a FunctionBody, following at most one
    same-file identifier hop. A factory call, a member expression, or an
    unresolvable name returns None — the registration is then suppressed
    entirely rather than analyzed on a guess."""
    fn = jsparse.function_in_span(src, span)
    if fn is not None:
        return fn
    txt = src.code(src.trimmed(span))
    if _IDENT_FULL_RE.match(txt):
        target = jsparse.resolve_span(src, txt, bindings)
        if target is not None:
            return jsparse.function_in_span(src, target)
    # S11: `{ createTask: async (args) => … }` as the handler slot.
    obj = jsparse.parse_object(src, span)
    if obj is not None and obj.ok:
        entry = obj.get("createTask")
        if entry is not None:
            return jsparse.function_in_span(src, entry.value_span)
    return None


def _seeds_for(fn: jsparse.FunctionBody, args_are_param0: bool) -> frozenset[str] | None:
    """Parameter-0 binding names, or None when the handler must be dropped.

    Rule R2, the single biggest false-positive trap in the engine: when the
    registration declares no input schema the SDK passes the *server
    context* as parameter 0, so nothing there is attacker-controlled.
    """
    if not fn.params_ok:
        return None                      # HARD suppress: pattern we cannot read
    if not args_are_param0 or fn.positional_count == 0:
        return frozenset()
    return frozenset(p.name for p in fn.param_at(0))


def _register_tool_handler(src: jsparse.Source, call: jsparse.CallSite,
                           bindings: dict[str, jsparse.Binding]) -> _Handler | None:
    """S1-S3: `server.registerTool(name, config, handler)`."""
    args = _strip_trailing_empty(src, call.args)
    if len(args) < 3:
        return None
    cfg = jsparse.parse_object(src, args[1])
    if cfg is None or not cfg.ok:
        return None                      # schema_known False -> never guess
    schema = None
    for key in _SCHEMA_KEYS:
        schema = cfg.get(key)
        if schema is not None:
            break
    args_are_param0 = (schema is not None
                       and _schema_is_non_empty(src, schema.value_span)
                       and _schema_admits_a_path(src, schema.value_span))
    fn = _resolve_function(src, args[-1], bindings)
    if fn is None:
        return None
    seeds = _seeds_for(fn, args_are_param0)
    if seeds is None:
        return None
    name = jsparse.string_literal_value(src, args[0]) or ""
    return _Handler(name, fn, seeds, lowlevel=False)


def _tool_ladder_handler(src: jsparse.Source, call: jsparse.CallSite,
                         bindings: dict[str, jsparse.Binding]) -> _Handler | None:
    """S4: the deprecated `server.tool(...)` overload ladder. Ported from the
    SDK's own dispatch rather than guessed at — `tool(name, description, cb)`
    and `tool(name, schema, cb)` are the same arity and only
    `isZodRawShapeCompat` tells them apart."""
    args = _strip_trailing_empty(src, call.args)
    if len(args) < 2:
        return None
    rest = args[1:-1]
    if rest and jsparse.string_literal_value(src, rest[0]) is not None:
        rest = rest[1:]                  # description
    schema: jsparse.Span | None = None
    if rest and _is_raw_shape(src, rest[0]):
        schema = rest[0]
    args_are_param0 = (schema is not None
                       and _schema_is_non_empty(src, schema)
                       and _schema_admits_a_path(src, schema))
    fn = _resolve_function(src, args[-1], bindings)
    if fn is None:
        return None
    seeds = _seeds_for(fn, args_are_param0)
    if seeds is None:
        return None
    name = jsparse.string_literal_value(src, args[0]) or ""
    return _Handler(name, fn, seeds, lowlevel=False)


def _descriptor_handler(src: jsparse.Source, call: jsparse.CallSite) -> _Handler | None:
    """S9/S10: `addTool({ name, parameters, execute })` /
    `defineTool({ name, inputSchema, handler })`. Keys appear in arbitrary
    order (fastmcp sorts them alphabetically, so `execute` precedes `name`)."""
    args = _strip_trailing_empty(src, call.args)
    if len(args) != 1:
        return None
    obj = jsparse.parse_object(src, args[0])
    if obj is None or not obj.ok or obj.has_spread:
        return None
    schema = None
    for key in _SCHEMA_KEYS:
        schema = obj.get(key)
        if schema is not None:
            break
    name_entry = obj.get("name")
    if name_entry is None and schema is None:
        return None                      # not a tool descriptor at all
    fn = None
    for key in _HANDLER_KEYS:
        entry = obj.get(key)
        if entry is None:
            continue
        fn = jsparse.function_in_span(src, entry.value_span)
        if fn is not None:
            break
    if fn is None:
        return None
    args_are_param0 = (schema is not None
                       and _schema_is_non_empty(src, schema.value_span)
                       and _schema_admits_a_path(src, schema.value_span))
    seeds = _seeds_for(fn, args_are_param0)
    if seeds is None:
        return None
    name = ""
    if name_entry is not None:
        name = jsparse.string_literal_value(src, name_entry.value_span) or ""
    return _Handler(name, fn, seeds, lowlevel=False)


def _lowlevel_handler(src: jsparse.Source, call: jsparse.CallSite) -> _Handler | None:
    """S5/S6: `server.setRequestHandler(CallToolRequestSchema, async (request)
    => …)`. Argument 0 must be that schema (or the literal 'tools/call') —
    that single gate drops `tools/list`, `resources/read`, subscriptions, and
    sampling handlers, none of which carry tool arguments."""
    args = _strip_trailing_empty(src, call.args)
    if len(args) < 2:
        return None
    a0 = src.code(src.trimmed(args[0]))
    lit = jsparse.string_literal_value(src, args[0])
    if a0 != "CallToolRequestSchema" and lit != "tools/call":
        return None
    region = jsparse.Span(args[1].start, args[-1].end)
    # Outermost-first, so a wrapped handler
    # (`wrapHandler('CallTool', async (request) => …)`) still resolves.
    for fb in jsparse.find_functions(src, region):
        if not fb.params_ok or fb.positional_count == 0:
            continue
        p0 = fb.param_at(0)
        if len(p0) != 1 or p0[0].is_destructured or p0[0].is_rest:
            continue
        req = p0[0].name
        pat = re.compile(rf"(?<![\w$]){re.escape(req)}\s*\??\s*\.\s*params(?![\w$])")
        if pat.search(src.code(fb.body_span)) is None:
            continue
        # Parameter 0 is the *request*, never the arguments; the request
        # itself is the taint root and `request.params.arguments` reads,
        # destructured or not, propagate from it.
        return _Handler("", fb, frozenset({req}), lowlevel=True)
    return None


def _tool_handlers(src: jsparse.Source,
                   imports: list[jsparse.ImportRecord],
                   bindings: dict[str, jsparse.Binding]) -> list[_Handler]:
    if not _file_imports_mcp(src, imports):
        return []
    found: dict[int, _Handler] = {}

    for call in jsparse.find_calls(src, {"registerTool", "tool", "addTool", "defineTool"}):
        # Gate 1: a member call. `supabase-mcp` exports a local identity
        # helper `export function tool(t) { return t; }` called bare.
        if call.method != "defineTool" and not call.receiver:
            continue
        if call.method == "registerTool":
            h = _register_tool_handler(src, call, bindings)
        elif call.method == "tool":
            h = _tool_ladder_handler(src, call, bindings)
        else:
            h = _descriptor_handler(src, call)
        if h is not None:
            found.setdefault(h.fn.body_span.start, h)

    for call in jsparse.find_calls(src, {"setRequestHandler"}):
        h = _lowlevel_handler(src, call)
        if h is not None:
            found.setdefault(h.fn.body_span.start, h)

    return [found[k] for k in sorted(found)]


def _case_label_at(src: jsparse.Source, body: jsparse.Span, offset: int) -> str:
    """The string literal of the nearest enclosing `case "<name>":` before
    `offset` in a low-level switch dispatch. Prose only."""
    best = ""
    m = src.masked
    for mt in _CASE_RE.finditer(m, body.start, min(offset, body.end)):
        j = mt.end()
        if j >= len(m) or m[j] not in "'\"":
            continue
        close = m.find(m[j], j + 1)
        if close == -1 or close - j > 200:
            continue
        best = src.text[j + 1:close]
    return best


# ==========================================================================
# taint
# ==========================================================================
def _statement_end(src: jsparse.Source, start: int, limit: int) -> int:
    """End of the initializer expression starting at `start`: the first
    `;`, `,`, or newline at bracket depth 0, or the closing bracket of the
    enclosing group. Truncating early only *loses* taint, never invents it."""
    m = src.masked
    depth = 0
    i = start
    while i < limit:
        c = m[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and c in ";,\n":
            return i
        i += 1
    return limit


def _pattern_names(text: str) -> list[str] | None:
    """Binding names of a flat `{ a, b: c, d = 1, ...rest }` pattern. None on
    anything nested or computed — we suppress rather than half-parse."""
    inner = text.strip()
    if inner.startswith("{"):
        inner = inner[1:-1] if inner.endswith("}") else inner[1:]
    names: list[str] = []
    for part in inner.split(","):
        p = part.strip()
        if not p:
            continue
        if p.startswith("..."):
            p = p[3:].strip()
        if "=" in p:
            p = p.split("=", 1)[0].strip()
        if ":" in p:
            p = p.split(":", 1)[1].strip()
        if not _IDENT_FULL_RE.match(p):
            return None
        names.append(p)
    return names


def _expr_is_tainted(src: jsparse.Source, span: jsparse.Span, tainted: frozenset[str] | set[str]) -> bool:
    """True when the expression references a tainted name as a *value*.
    `identifier_uses` excludes property position and object-literal key
    position, so `{ path: BASE }` and `config.args` do not count, while
    `args.path` — the dominant real shape — does."""
    if span.is_empty():
        return False
    for name in sorted(tainted):
        if jsparse.identifier_uses(src, span, name):
            return True
    return False


# Callees that hand the argument's own value back, so taint must survive
# them: path arithmetic, string munging, and schema validation (`.parse()`
# returns the input it validated). Everything NOT on this list is opaque —
# see `_init_is_opaque_call`.
_PASSTHROUGH_CALLS = frozenset({
    # node:path and friends
    "join", "resolve", "normalize", "relative", "basename", "dirname",
    "extname", "format", "toNamespacedPath", "normalizePath", "expandHome",
    "untildify",
    # string / primitive coercion
    "String", "toString", "trim", "trimStart", "trimEnd", "concat", "slice",
    "substring", "substr", "toLowerCase", "toUpperCase", "replace",
    "replaceAll", "padStart", "padEnd", "at", "valueOf",
    "decodeURIComponent", "encodeURIComponent", "decodeURI", "encodeURI",
    # schema validation returns the validated input unchanged
    "parse", "safeParse", "parseAsync", "safeParseAsync",
})

_SINGLE_CALL_RE = re.compile(
    r"(?:await\s+)?(?:new\s+)?"
    r"(?P<chain>[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)"
    r"(?:\s*<[^<>;{}()\n]*>)?\s*\??\.?\s*\("
)
# What may legally trail the call and still leave it the whole initializer.
_CALL_TAIL_RE = re.compile(r"\s*!?\s*(?:as\s+[^;]*)?\Z")


def _init_is_opaque_call(src: jsparse.Source, init: jsparse.Span) -> bool:
    """True when the initializer is exactly one call to a function whose body
    we cannot see, so its RETURN VALUE is not the tool parameter.

    `const result = await runBuild(args.source); await fs.rm(result.tmpDir)`
    deletes a scratch directory that `runBuild` chose — the tool parameter
    went *in*, but what came back is the callee's own value. Treating it as
    tainted flagged correct "do work in a temp dir, then clean it up" code,
    which is the single most common filesystem shape an MCP server has. Under
    this project's false-negative bias, an unknown callee launders.

    Path arithmetic and `.parse()` are exempt (`_PASSTHROUGH_CALLS`): they
    return the argument's own value, so `const p = path.join(BASE, args.dir)`
    still propagates and still fires.
    """
    t = src.trimmed(init)
    if t.is_empty():
        return False
    txt = src.code(t)
    mt = _SINGLE_CALL_RE.match(txt)
    if mt is None:
        return False
    open_paren = t.start + mt.end() - 1
    close = jsparse.match_bracket(src, open_paren)
    if close is None or close >= t.end:
        return False
    if _CALL_TAIL_RE.match(src.code(jsparse.Span(close + 1, t.end))) is None:
        return False                     # more expression follows: not a lone call
    method = _normalize_chain(mt.group("chain")).split(".")[-1]
    return method not in _PASSTHROUGH_CALLS


def _normalize_chain(raw: str) -> str:
    return re.sub(r"\s+", "", raw).replace("?.", ".")


def _propagate_taint(src: jsparse.Source, body: jsparse.Span, seeds: frozenset[str]) -> set[str]:
    """Textual taint propagation inside a handler body, mirroring the Python
    checks' Assign / AnnAssign / AugAssign propagation. Two passes over the
    declarations and reassignments in source order — no fixpoint, no
    control-flow sensitivity, and names are never *removed*."""
    tainted: set[str] = set(seeds)
    if not tainted:
        return tainted

    events: list[tuple[int, tuple[str, ...], jsparse.Span]] = []
    m = src.masked

    for mt in _DECL_RE.finditer(m, body.start, body.end):
        lhs = m[mt.start("lhs"):mt.end("lhs")]
        if lhs.startswith("{"):
            names = _pattern_names(lhs)
            if names is None:
                continue
        else:
            names = [lhs]
        init = jsparse.Span(mt.end(), _statement_end(src, mt.end(), body.end))
        events.append((mt.start(), tuple(names), init))

    for mt in _ASSIGN_RE.finditer(m, body.start, body.end):
        k = mt.start() - 1
        while k >= body.start and m[k] in " \t\r\n":
            k -= 1
        if k >= body.start and m[k] == ".":
            continue                     # `obj.x = tainted` binds no local
        init = jsparse.Span(mt.end(), _statement_end(src, mt.end(), body.end))
        events.append((mt.start(), (mt.group("name"),), init))

    if not events:
        return tainted
    events.sort(key=lambda e: e[0])
    if len(events) > 500:                # pragma: no cover - defensive bound
        events = events[:500]

    for _ in range(2):
        for _off, names, init in events:
            if _init_is_opaque_call(src, init):
                continue                 # the callee's return value, not ours
            if _expr_is_tainted(src, init, tainted):
                tainted.update(names)
    return tainted


# ==========================================================================
# sinks
# ==========================================================================
def _sink_aliases(imports: list[jsparse.ImportRecord]) -> dict[str, dict[str, str]]:
    """Import-derived sink tables. Nothing becomes a sink without appearing
    here: `re.exec`, `db.exec`, `cache.remove`, `store.del` are ordinary
    JavaScript and a textual matcher on those names is the v0.3 defect."""
    members: dict[str, str] = {}   # receiver chain -> kind
    bare: dict[str, str] = {}      # callee name    -> kind
    for rec in imports:
        if rec.is_type_only or not rec.local:
            continue
        mod = rec.module
        if mod in _FS_MODULES:
            kind = ("fs_extra" if mod == "fs-extra"
                    else "fs_promises" if mod in _PROMISES_MODULES else "fs")
            if rec.imported in ("*", "default"):
                members.setdefault(rec.local, kind)
                if kind == "fs":
                    # `import fs from "node:fs"` -> `fs.promises.rm(p)`
                    members.setdefault(rec.local + ".promises", "fs_promises")
            elif rec.imported == "promises":
                members.setdefault(rec.local, "fs_promises")
            elif rec.imported in _FS_SINKS:
                bare.setdefault(rec.local, kind)
        elif mod in _PKG_SINKS:
            names = _PKG_SINKS[mod]
            if rec.imported in ("*", "default"):
                members.setdefault(rec.local, "pkg")
                bare.setdefault(rec.local, "pkg")
            elif rec.imported in names:
                bare.setdefault(rec.local, "pkg")
    return {"members": members, "bare": bare}


def _sink_kind(call: jsparse.CallSite, aliases: dict[str, dict[str, str]]) -> str | None:
    """The destructive-sink kind for a call site, or None. Import-gated: an
    unresolved receiver (`getFs().rm(p)` yields `jsparse.UNKNOWN_RECEIVER`)
    can never match, by construction."""
    if call.receiver:
        kind = aliases["members"].get(call.receiver)
        if kind is None:
            return None
        if kind == "pkg":
            return "pkg" if call.method in _PKG_SINKS["rimraf"] | _PKG_SINKS["del"] else None
        if call.method not in _FS_SINKS:
            return None
        if kind == "fs" and call.method in ("remove", "removeSync", "emptyDir", "emptyDirSync"):
            return None                  # fs-extra-only names on a core-fs alias
        return kind
    return aliases["bare"].get(call.method)


def _contains_guard(src: jsparse.Source, body: jsparse.Span) -> bool:
    """True if the handler body shows any path-containment / canonicalization
    indicator, in which case we suppress destructive findings for it."""
    if jsparse.contains_token(src, body, _GUARD_TOKENS):
        return True
    for mt in _IDENT_SCAN_RE.finditer(src.masked, body.start, body.end):
        low = mt.group(0).lower()
        if any(frag in low for frag in _GUARD_SUBSTRINGS):
            return True
    return False


# ==========================================================================
# findings
# ==========================================================================
def _sink_label(kind: str) -> str:
    return {
        "fs": "`fs.rm` / `fs.rmSync` / `fs.unlink` / `fs.rmdir`",
        "fs_promises": "`fs.promises.rm` / `fs.promises.unlink`",
        "fs_extra": "an `fs-extra` `remove` / `emptyDir` call",
        "pkg": "a `rimraf` / `del` call",
    }.get(kind, "a destructive filesystem call")


def _build_finding(path: Path, tool: str, line: int, kind: str) -> Finding:
    message = (
        f"tool '{tool}' passes a value flowing from a tool parameter into "
        f"{_sink_label(kind)} with no path-containment guard. An attacker who "
        "influences the argument (directly, or by prompt-injecting the model "
        "that calls the tool) can delete arbitrary files or directories the "
        "Node process can reach — on `fs.rm` with `recursive: true` that is a "
        "whole subtree. The tool's advertised scope (a temp/work dir) is not "
        "enforced in code."
    )
    remediation = (
        "Confine the path before deleting: canonicalize with "
        "`await fs.promises.realpath(p)` (or `path.resolve(p)`), then assert "
        "it is inside a fixed base directory — "
        "`const rel = path.relative(BASE, real); if (rel.startsWith('..') || "
        "path.isAbsolute(rel)) throw new Error('outside root');` — and/or check "
        "it against a server-managed allow-set of directories you created. "
        "Never pass a raw tool parameter straight to a delete call. "
        "Constraining the schema (`z.string().regex(...)`) helps but is not "
        "sufficient on its own — enforce containment at the sink."
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
    src = jsparse.load(path)
    if src is None or not src.ok:
        # A degraded lex must never emit a finding — every offset after the
        # failure point is suspect. Hard contract, design §1.1 property 3.
        return []

    imports = jsparse.collect_imports(src)
    aliases = _sink_aliases(imports)
    if not aliases["members"] and not aliases["bare"]:
        return []                        # no fs/rimraf/del import: no sinks here

    bindings = jsparse.collect_bindings(src)
    findings: list[Finding] = []
    # One finding per tainted sink call site (mirrors the Python check: a
    # handler with two unguarded `rm`s yields two findings).
    for handler in _tool_handlers(src, imports, bindings):
        body = handler.fn.body_span
        if not handler.seeds:
            continue
        # A containment guard anywhere in the handler suppresses findings.
        if _contains_guard(src, body):
            continue
        tainted = _propagate_taint(src, body, handler.seeds)
        for call in jsparse.find_calls(src, _ALL_SINK_METHODS, within=body):
            kind = _sink_kind(call, aliases)
            if kind is None:
                continue
            args = _strip_trailing_empty(src, call.args)
            if not args:
                continue
            if not _expr_is_tainted(src, args[0], tainted):
                continue
            tool = handler.tool_name
            if not tool and handler.lowlevel:
                tool = _case_label_at(src, body, call.name_span.start)
            findings.append(_build_finding(src.path, tool or "<anonymous>",
                                           call.line, kind))
    return findings


def check(root: Path, *, include_build: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for path in jsparse.iter_source_files(root, include_build=include_build):
        findings.extend(_check_file(path))
    return findings
