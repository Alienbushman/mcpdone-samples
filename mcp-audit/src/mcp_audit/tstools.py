"""tstools — the MCP tool-handler surface, layered on `mcp_audit.jsparse`.

`jsparse` knows how to lex TypeScript; it knows nothing about MCP. This
module is where every ambiguity about "what is a tool handler, and which of
its parameters is attacker-controlled" is resolved, exactly once, so that
the TypeScript checks never have to guess. Each check then asks one
question — "does a tool parameter reach my sink?" — and the answer to
"which names *are* tool parameters" comes from here.

Why this module is written the way it is
----------------------------------------

The Model Context Protocol TypeScript SDK has accumulated seven overloads
of `McpServer.tool()`, a newer `registerTool(name, config, cb)`, a
low-level `Server.setRequestHandler(CallToolRequestSchema, cb)` path, and
an ecosystem of wrappers (fastmcp's `addTool({...})`, `defineTool({...})`
catalogues) that each spell "here is a tool" differently. Registration is
therefore not a syntactic pattern but a small dispatch problem, and getting
it wrong is expensive in exactly one direction: if we decide that some
random `registry.tool(...)` in an unrelated library is an MCP handler, or
that a no-input tool's server-context parameter is attacker-controlled,
every check downstream inherits the false positive. mcp-audit already
published one retraction (v0.3) for a check that fired on correct code; the
whole design of this module is a reaction to that.

So the classification runs behind three hard gates, and each of them exists
because of a specific real repository:

  Gate 0 — the file must import MCP. Without it, `registry.tool(...)`,
    `observer.tool(...)`, and every plugin framework that happens to use
    the word "tool" become MCP registrations.
  Gate 1 — `tool` / `registerTool` / `addTool` must be MEMBER calls.
    `supabase-mcp` ships `export function tool(t) { return t; }`, an
    identity helper, invoked bare as `tool({...})` a few dozen times. It is
    not a registration. We gate on "has a receiver", never on the
    receiver's *name*: the corpus contains `server.`, `context.`,
    `this.server.`, `server.server.`, `pi.`, `mcp.`, and `registry.`
    receivers, all legitimate.
  Gate 2 — the method name is matched exactly. `prompt`,
    `registerPrompt`, `resource`, and `registerResource` share the
    identical overload ladder and are never tools.

And then rule R2, which is the single biggest false-positive trap in the
engine:

    **taint_roots is EMPTY unless a schema is present.**

`browser-tools-mcp/mcp-server.ts:178` reads
`server.tool("getConsoleLogs", "Check our browser logs", async () => {...})`.
That is the three-argument overload with no schema, and the SDK's own
dispatch then calls the callback as `cb(extra)` — parameter 0 is the
`RequestHandlerExtra` (v1) / `ServerContext` (v2) object, which is server
state, not attacker input. A check that treated parameter 0 as tainted
there would fire on a tool that accepts no input at all. Parameter 1 and
later are *never* tainted, for the same reason.

Deliberate false negatives, recorded rather than hidden
-------------------------------------------------------

  - **No cross-file taint, and no cross-function taint.** Everything here
    is confined to one `Source` and, for taint, to one function body. The
    "forwarding arrow" shape (`async (args) => handlers.doThing(args)`,
    with the logic in another module) is recognised as a handler and
    analysed as one, but we do not follow the call. Interprocedural taint
    across files is precisely the analysis shape that produced the v0.3
    retraction and it is out of scope.
  - **A handler that is a factory call, a member expression, or an
    identifier that does not resolve in this file is dropped entirely.**
    Guessing at `makeHandler(deps)` would mean guessing at its parameters.
  - **A registration whose parameter list does not parse** (array
    destructuring, a nested pattern jsparse declines to flatten) is
    dropped. `FunctionBody.params_ok` False ⇒ no handler.
  - **`.parse()` / `.safeParse()` does not launder taint.**
    `Schema.parse(request.params.arguments)` validates the *shape*; every
    string value in it is still attacker-chosen.
  - **A config object we cannot read is reported as `schema_known=False`,
    never as "no schema".** An identifier config (`registerTool(name,
    CONFIG, cb)`) and a spread config (`{ ...CONFIG, title }`) are both
    undecidable, and asserting "this tool declares no input schema" about
    them would be a false claim.
  - **Registration shapes not supported at all** (each returns no
    handler): a bare, non-member `tool(...)`/`addTool(...)`; a tool table
    built as free-floating object literals in an array with no
    `defineTool(...)` call around them; `server.registerTool(...)` applied
    via `.call`/`.apply`/spread; handlers registered in a loop from an
    imported table where the callback is imported too; `tool()` overloads
    whose schema is passed as `z.object(...)` rather than a raw shape (the
    SDK's own `isZodRawShapeCompat` rejects those as well, so this matches
    runtime behaviour); and `setRequestHandler` on any schema other than
    `CallToolRequestSchema` / `'tools/call'`.

All matching runs against `Source.masked`. A `//` inside a URL, a
commented-out registration, and a `z.any()` inside a description string are
invisible to every predicate here, which is the entire point of the mask.
"""
from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path

from mcp_audit import jsparse
from mcp_audit.jsparse import Binding, FunctionBody, ObjectEntry, Source, Span

# --------------------------------------------------------------------------
# Gate 0: what counts as "this file is MCP".
#
# `@modelcontextprotocol/` covers the official SDK in all its entry points
# (server/mcp.js, server/index.js, types.js, ...). The rest are the
# third-party frameworks that appear in the corpus and that publish their own
# registration verbs. Matching is prefix/segment-exact rather than substring
# so that a package called `my-fastmcp-helpers` does not open the gate.
# --------------------------------------------------------------------------
_MCP_MODULE_PREFIXES: tuple[str, ...] = ("@modelcontextprotocol/",)
_MCP_MODULE_ROOTS: frozenset[str] = frozenset({
    "@modelcontextprotocol/sdk",   # bare, without a subpath
    "fastmcp",
    "mcp-lite",
    "@vercel/mcp-adapter",
    "agents/mcp",
})

# Gate 2. Exactly these three verbs, and only as member calls.
_REGISTER_METHODS: frozenset[str] = frozenset({"registerTool", "tool", "addTool"})

# The descriptor verb, which is normally a bare imported function and so is
# deliberately NOT subject to Gate 1.
_DEFINE_METHODS: frozenset[str] = frozenset({"defineTool"})

# S9/S10 descriptor keys. Schema keys are tried in this order, so a
# descriptor carrying both `inputSchema` and `parameters` resolves the way
# the SDK would.
_SCHEMA_KEYS: tuple[str, ...] = ("inputSchema", "parameters", "schema")
_HANDLER_KEYS: tuple[str, ...] = ("handler", "execute", "cb", "callback",
                                  "run", "handle")

# S11. `registerTool(name, config, { createTask: async (args) => ... })` —
# two occurrences corpus-wide, cheap enough to support.
_TASK_KEY = "createTask"

# S5/S6. The only two spellings of the tools/call method that this module
# will accept. `ListToolsRequestSchema`, `'tools/list'`,
# `SubscribeRequestSchema`, `'sampling/createMessage'`, and every custom
# method fall through this gate and are skipped, which is what keeps a
# tools/list catalogue from being analysed as an execution path.
_CALL_TOOL_SCHEMA = "CallToolRequestSchema"
_CALL_TOOL_METHOD = "tools/call"

_IDENT_FULL_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_WS_CHARS = " \t\r\n\v\f"

# Characters that continue an expression onto the next line. Used to bound a
# declaration's initializer without a real parser; `const out = f(x)\n  .g()`
# must not be cut at the newline.
_CONTINUATION = ".?+-*/%&|^"

_DECL_KW_RE = re.compile(r"(?<![\w$])(?:const|let|var)(?![\w$])")

# `x = expr` / `x += expr`. The `(?![=>])` tail is load-bearing: without it
# an arrow function's parameter (`x => body`) reads as an assignment to `x`,
# and `x === y` reads as an assignment too.
_ASSIGN_RE = re.compile(r"(?<![\w$.])(?P<name>[A-Za-z_$][\w$]*)\s*\+?=(?![=>])")

_CASE_RE = re.compile(r"(?<![\w$])case(?![\w$])\s*(['\"])")


# ==========================================================================
# public dataclass
# ==========================================================================
@dataclass(frozen=True)
class ToolHandler:
    """One statically-resolvable MCP tool handler.

    `taint_roots` is the answer to "which local names hold attacker-supplied
    tool arguments on entry to this body". It is frequently EMPTY, and an
    empty set is a positive statement — "nothing in this handler is
    attacker-controlled" — not a failure to analyse. Checks must treat it
    as such and stay silent rather than fall back to parameter 0.
    """

    path: Path
    tool_name: str        # literal name if statically known, else ""
    display_name: str     # tool_name or "<anonymous>"; use this in prose
    style: str            # registerTool | tool | addTool | defineTool | lowlevel
    fn: FunctionBody
    args_are_param0: bool  # rule R2: a schema is present, so param 0 is args
    schema_span: Span | None
    schema_known: bool    # False => could not determine schema presence
    taint_roots: frozenset[str]
    reg_line: int         # line of the registration call, for context


# ==========================================================================
# small span utilities
# ==========================================================================
def _real_args(src: Source, call: jsparse.CallSite) -> list[Span]:
    """Argument spans with trailing empty spans stripped (rule R1).

    `f(a, b,)` splits to three spans, the last of which is empty. Every
    "the handler is the last argument" rule below depends on that span
    being gone first.
    """
    args = list(call.args)
    while args and src.trimmed(args[-1]).is_empty():
        args.pop()
    return args


def _text_of(src: Source, span: Span) -> str:
    """Masked text of a span, trimmed. Never the raw text — a literal's
    contents must stay invisible to every predicate in this module."""
    return src.code(src.trimmed(span)).strip()


def _is_identifier(text: str) -> bool:
    return bool(text) and _IDENT_FULL_RE.match(text) is not None


def _split_commas(src: Source, start: int, end: int) -> list[Span]:
    """Comma-split [start, end) at bracket depth 0."""
    m = src.masked
    out: list[Span] = []
    depth = 0
    seg = start
    i = start
    while i < end:
        c = m[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                depth = 0
        elif c == "," and depth == 0:
            out.append(Span(seg, i))
            seg = i + 1
        i += 1
    out.append(Span(seg, end))
    return out


def _depth0_char(src: Source, start: int, end: int, target: str) -> int:
    """Offset of the first `target` at bracket depth 0 in [start, end)."""
    m = src.masked
    depth = 0
    i = start
    while i < end:
        c = m[i]
        if c == target and depth == 0:
            return i
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                depth = 0
        i += 1
    return -1


def _depth0_assign_eq(src: Source, start: int, end: int) -> int:
    """Offset of the first depth-0 `=` in [start, end) that is a genuine
    assignment (not `==`, `===`, `=>`, `<=`, `>=`, `!=`), or -1."""
    m = src.masked
    depth = 0
    i = start
    while i < end:
        c = m[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return -1
            depth -= 1
        elif depth == 0:
            if c == ";":
                return -1
            if c == "=":
                nxt = m[i + 1] if i + 1 < end else ""
                prv = m[i - 1] if i > start else ""
                if nxt not in ("=", ">") and prv not in ("=", "!", "<", ">"):
                    return i
                return -1
        i += 1
    return -1


def _expression_end(src: Source, start: int, limit: int) -> int:
    """End of the expression beginning at `start`, bounded by `limit`.

    Stops at a depth-0 `;` or `,`, at an unbalanced closing bracket, and at
    a newline that is not obviously a continuation. This is an ASI
    approximation, not a parse; the cost of getting it wrong is a taint
    edge that is one statement too short or too long, and both directions
    are contained by the guard suppressions in the checks themselves.
    """
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
                if j >= limit or m[j] not in _CONTINUATION:
                    break
                i = j
                continue
        i += 1
    return i


# ==========================================================================
# Gate 0
# ==========================================================================
def file_imports_mcp(src: Source) -> bool:
    """True when this file imports from an MCP SDK or framework.

    Type-only imports count. `import type { CallToolRequest } from
    '@modelcontextprotocol/sdk/types.js'` binds no runtime value, but it is
    conclusive proof that the file is MCP code, and a low-level dispatcher
    frequently imports nothing else from the SDK.

    This is the gate that stops `registry.tool(...)` / `observer.tool(...)`
    in unrelated libraries from being classified as tool registrations.
    A file that reaches its server object through a relative import
    (`import { server } from './server.js'`) and registers tools on it is a
    deliberate false negative: the alternative is trusting the method name
    alone, which is how a scanner ends up auditing somebody's ORM.
    """
    for rec in jsparse.collect_imports(src):
        module = rec.module
        if any(module.startswith(p) for p in _MCP_MODULE_PREFIXES):
            return True
        for root in _MCP_MODULE_ROOTS:
            if module == root or module.startswith(root + "/"):
                return True
    return False


# ==========================================================================
# schema shape recognition (S4: the SDK's own overload dispatch)
# ==========================================================================
def _is_schema_like(src: Source, span: Span,
                    bindings: Mapping[str, Binding], *, hops: int = 1) -> bool:
    """True when a value looks like a validator instance.

    Deliberately NOT `startswith('z.')`. The fastmcp corpus registers tools
    with arktype's `type("string")` and valibot's `v.object({...})`, and a
    project-local `const Name = z.string().min(1)` referenced by name is
    common everywhere. What all of them share is being a *call expression*
    or a `<ident>.shape` reference.

    What separates them from the other object that can occupy the same
    argument slot — a `ToolAnnotations` object — is that every
    ToolAnnotations value is a primitive: `readOnlyHint: true`,
    `destructiveHint: false`, `title: "Read a file"`. None of those contain
    a call.
    """
    t = src.trimmed(span)
    if t.is_empty():
        return False               # shorthand `{ cmd }`: value lives elsewhere
    code = src.code(t).strip()
    if not code:
        return False
    if "(" in code:                # z.string(), type("string"), v.object({...})
        return True
    if code.endswith(".shape"):    # `Schema.shape` — a raw shape by reference
        return True
    if hops > 0 and _is_identifier(code):
        target = jsparse.resolve_span(src, code, bindings)
        if target is not None:
            return _is_schema_like(src, target, bindings, hops=hops - 1)
    return False


def _is_raw_shape(src: Source, span: Span,
                  bindings: Mapping[str, Binding]) -> bool:
    """Port of the SDK's `isZodRawShapeCompat` (server/mcp.ts:1369-1386).

    True when the span is an object literal that is not itself a validator
    instance and either has zero keys or has at least one schema-like
    value. `{}` IS a raw shape — the SDK then hands the callback an empty
    arguments object, which still means "parameter 0 is arguments".

    A `z.object({...})` passed in this slot returns False, exactly as the
    real `isZodRawShapeCompat` does: the SDK treats it as annotations and
    the callback receives `extra` in parameter 0. Matching the runtime is
    the point — a "smarter" heuristic here would disagree with what
    actually happens on the wire.
    """
    obj = jsparse.parse_object(src, span)
    if obj is None or not obj.ok:
        return False
    if obj.has_spread:
        # `{ ...shape }` — we cannot enumerate the keys, so we cannot say.
        return False
    if not obj.entries:
        return True
    return any(_is_schema_like(src, e.value_span, bindings)
               for e in obj.entries)


# ==========================================================================
# handler resolution (rule R1)
# ==========================================================================
def _entry_function(src: Source, entry: ObjectEntry) -> FunctionBody | None:
    """The function value of an object entry, for both
    `handler: async (a) => {}` and the method shorthand
    `async handler(a) { ... }`."""
    if entry.value_span.is_empty():
        return None
    return jsparse.function_in_span(src, entry.value_span)


def _resolve_handler(src: Source, span: Span,
                     bindings: Mapping[str, Binding]) -> FunctionBody | None:
    """The handler function for a registration argument, or None.

    Accepted:
      - a function expression written inline (the overwhelming majority);
      - a bare identifier that resolves, in THIS file, to a top-level
        `const X = async (…) => …` or `function X(…) { … }`;
      - S11: an object literal with a `createTask` function value.

    Refused (the registration is then dropped entirely):
      - a factory call `makeHandler(deps)` — its parameters are wherever
        `makeHandler` is defined, quite possibly in another file;
      - a member expression `handlers.doThing`;
      - an identifier imported from another module;
      - anything whose parameters do not parse.
    """
    t = src.trimmed(span)
    if t.is_empty():
        return None

    fn = jsparse.function_in_span(src, t)
    if fn is not None:
        return fn

    obj = jsparse.parse_object(src, t)
    if obj is not None:
        if not obj.ok:
            return None
        entry = obj.get(_TASK_KEY)
        return _entry_function(src, entry) if entry is not None else None

    code = src.code(t).strip()
    if _is_identifier(code):
        target = jsparse.resolve_span(src, code, bindings)
        if target is not None:
            return jsparse.function_in_span(src, target)
    return None


def _literal_name(src: Source, span: Span,
                  bindings: Mapping[str, Binding]) -> str:
    """The tool's name when it is statically knowable, else "".

    A string literal, or a same-file const that resolves to one. A computed
    name (`tool.name` in a dispatch loop, a template with a hole) yields ""
    and the handler is reported as `<anonymous>`.
    """
    value = jsparse.string_literal_value(src, span)
    if value is not None:
        return value
    code = _text_of(src, span)
    if _is_identifier(code):
        target = jsparse.resolve_span(src, code, bindings)
        if target is not None:
            resolved = jsparse.string_literal_value(src, target)
            if resolved is not None:
                return resolved
    return ""


def _taint_roots(fn: FunctionBody, args_are_param0: bool) -> frozenset[str]:
    """Rule R2. The names that hold tool arguments on entry, or nothing.

    Empty whenever no schema is declared, because the SDK then invokes the
    callback as `cb(extra)` and parameter 0 is the server context. Never
    parameter 1 or later: that slot is `RequestHandlerExtra` (v1),
    `ServerContext` (v2), or fastmcp's `{ log, reportProgress, session }`,
    all of which are server-side state.
    """
    if not args_are_param0:
        return frozenset()
    if not fn.params_ok or fn.positional_count == 0:
        return frozenset()
    return frozenset(p.name for p in fn.param_at(0))


def _make(src: Source, *, name: str, style: str, fn: FunctionBody,
          args_are_param0: bool, schema_span: Span | None,
          schema_known: bool, reg_line: int) -> ToolHandler:
    return ToolHandler(
        path=src.path,
        tool_name=name,
        display_name=name or "<anonymous>",
        style=style,
        fn=fn,
        args_are_param0=args_are_param0,
        schema_span=schema_span,
        schema_known=schema_known,
        taint_roots=_taint_roots(fn, args_are_param0),
        reg_line=reg_line,
    )


# ==========================================================================
# S1/S2/S3 — registerTool(name, config, handler)
# ==========================================================================
def _from_register_tool(src: Source, call: jsparse.CallSite,
                        args: list[Span],
                        bindings: Mapping[str, Binding]) -> ToolHandler | None:
    if len(args) < 3:
        return None
    fn = _resolve_handler(src, args[-1], bindings)
    if fn is None or not fn.params_ok:
        return None

    schema_known = True
    schema_span: Span | None = None
    args_are_param0 = False

    config = jsparse.parse_object(src, args[1])
    if config is None or not config.ok or config.has_spread:
        # An identifier config, or a spread we cannot enumerate. Schema
        # presence is UNDECIDABLE — not absent. Saying "this tool declares
        # no input schema" about `registerTool(name, CONFIG, cb)` would be
        # a false claim about correct code.
        schema_known = False
    else:
        entry = config.get("inputSchema")
        if entry is not None:
            args_are_param0 = True
            schema_span = entry.value_span

    return _make(src, name=_literal_name(src, args[0], bindings),
                 style="registerTool", fn=fn, args_are_param0=args_are_param0,
                 schema_span=schema_span, schema_known=schema_known,
                 reg_line=call.line)


# ==========================================================================
# S4 — the deprecated tool() / addTool() overload ladder
# ==========================================================================
def _from_overload_ladder(src: Source, call: jsparse.CallSite,
                          args: list[Span],
                          bindings: Mapping[str, Binding]) -> ToolHandler | None:
    """Port of the SDK's own dispatch (server/mcp.ts:1007-1034).

    `tool(name, cb)` / `tool(name, description, cb)` /
    `tool(name, rawShape, cb)` / `tool(name, description, rawShape, cb)` /
    `tool(name, rawShape, annotations, cb)` /
    `tool(name, description, rawShape, annotations, cb)`.

    The SDK peels a leading string as the description, then tests the next
    argument with `isZodRawShapeCompat`, then treats whatever remains as
    annotations. Reproducing that ladder rather than inventing a heuristic
    is what makes `exa-mcp-server`'s
    `server.tool(name, description, agentRunInputShape, { readOnlyHint:
    true }, handler)` come out the same way the runtime sees it.
    """
    if len(args) < 2:
        return None
    fn = _resolve_handler(src, args[-1], bindings)
    if fn is None or not fn.params_ok:
        return None

    rest = args[1:-1]
    if rest and jsparse.string_literal_value(src, rest[0]) is not None:
        rest = rest[1:]                                   # description

    schema_span: Span | None = None
    if rest and _is_raw_shape(src, rest[0], bindings):
        schema_span = rest[0]                             # the raw shape
        # whatever remains in `rest` is the annotations object

    return _make(src, name=_literal_name(src, args[0], bindings),
                 style=call.method, fn=fn,
                 args_are_param0=schema_span is not None,
                 schema_span=schema_span,
                 # The ladder can never give a confident *negative*: a bare
                 # identifier in the middle slot is indistinguishable from
                 # an annotations object without resolving it, and
                 # exa-mcp-server's agent_run genuinely does declare a
                 # schema that way. Only presence is asserted, so schema
                 # presence itself stays "known" while absence is treated
                 # as unremarkable by the consumers.
                 schema_known=True, reg_line=call.line)


# ==========================================================================
# S9/S10 — descriptor objects (defineTool / fastmcp addTool / catalogues)
# ==========================================================================
def _descriptor_handler_entry(src: Source,
                              obj: jsparse.ObjectLiteral) -> ObjectEntry | None:
    for key in _HANDLER_KEYS:
        entry = obj.get(key)
        if entry is None:
            continue
        if entry.is_method or not entry.value_span.is_empty():
            return entry
    return None


def _descriptor_schema_entry(src: Source,
                             obj: jsparse.ObjectLiteral) -> ObjectEntry | None:
    for key in _SCHEMA_KEYS:
        entry = obj.get(key)
        if entry is not None and not entry.value_span.is_empty():
            return entry
    return None


def _from_descriptor(src: Source, call: jsparse.CallSite, span: Span,
                     style: str,
                     bindings: Mapping[str, Binding]) -> ToolHandler | None:
    """`addTool({ name, parameters, execute })`, `defineTool({ name,
    inputSchema, handler })`, and the catalogue-entry shape.

    Keys appear in arbitrary order — fastmcp's own sources sort them
    alphabetically, so `execute` precedes `name` — so nothing here may
    depend on position. A descriptor qualifies when it has a `name` key or
    a schema key AND a function-valued handler key; both halves are needed,
    or every options bag with a `run` callback in the file becomes a tool.
    """
    obj = jsparse.parse_object(src, span)
    if obj is None or not obj.ok:
        return None
    handler_entry = _descriptor_handler_entry(src, obj)
    if handler_entry is None:
        return None
    schema_entry = _descriptor_schema_entry(src, obj)
    name_entry = obj.get("name")
    if name_entry is None and schema_entry is None:
        return None

    fn = _entry_function(src, handler_entry)
    if fn is None or not fn.params_ok:
        return None

    name = ""
    if name_entry is not None and not name_entry.value_span.is_empty():
        name = _literal_name(src, name_entry.value_span, bindings)

    return _make(src, name=name, style=style, fn=fn,
                 args_are_param0=schema_entry is not None,
                 schema_span=schema_entry.value_span if schema_entry else None,
                 # A spread in the descriptor means an unseen key could
                 # carry the schema; presence is then undecidable.
                 schema_known=not obj.has_spread, reg_line=call.line)


# ==========================================================================
# S5/S6 — low-level setRequestHandler dispatch
# ==========================================================================
def _is_call_tool_schema(src: Source, span: Span) -> bool:
    """Gate for `setRequestHandler`'s first argument.

    Accepts the identifier `CallToolRequestSchema` (however it is
    namespaced) and the string literal `'tools/call'`. Everything else —
    `ListToolsRequestSchema`, `'tools/list'`, `SubscribeRequestSchema`,
    `'sampling/createMessage'`, custom methods — is skipped. This one gate
    keeps a tools/list catalogue, a resource subscription, and a sampling
    callback out of every TypeScript check at once.
    """
    literal = jsparse.string_literal_value(src, span)
    if literal is not None:
        return literal == _CALL_TOOL_METHOD
    code = _text_of(src, span)
    if not code:
        return False
    return code.split(".")[-1] == _CALL_TOOL_SCHEMA


def _deref_params(src: Source, body: Span, name: str) -> bool:
    """True when `<name>.params` is dereferenced inside `body`.

    The `\\s*` between segments is what tolerates `slack/index.ts:421-423`,
    which splits `request.params` across a line break. Matching the masked
    text makes that free.
    """
    if not name:
        return False
    pattern = re.compile(
        rf"(?<![\w$]){re.escape(name)}\s*\??\s*\.\s*params(?![\w$])")
    lo = max(0, body.start)
    hi = min(len(src.masked), body.end)
    return lo < hi and pattern.search(src.masked, lo, hi) is not None


def _lowlevel_function(src: Source, span: Span) -> FunctionBody | None:
    """The outermost function in `span` whose parameter 0 is dereferenced
    as `.params` in its own body.

    "Outermost" is what tolerates a wrapped handler —
    `mcp-playwright`'s `loggingMiddleware.wrapHandler('CallTool',
    wrapWithMonitoring(async (request) => …))` puts two calls between the
    registration and the real callback. `find_functions` returns outermost
    first, and the `.params` test is what identifies the one that actually
    receives the request.

    A destructured parameter 0 (`async ({ params }) => …`) is declined: the
    request object then has no name to anchor the S8 idioms to, and half an
    analysis is worse than none.
    """
    for fn in jsparse.find_functions(src, span):
        if not fn.params_ok or fn.positional_count == 0:
            continue
        bindings = fn.param_at(0)
        if len(bindings) != 1:
            continue
        p = bindings[0]
        if p.is_destructured or p.is_rest:
            continue
        if _deref_params(src, fn.body_span, p.name):
            return fn
    return None


def _lowlevel_roots(src: Source, fn: FunctionBody, req: str) -> set[str]:
    """S8. The locals that hold `<req>.params.arguments`, plus `<req>`.

    `<req>` itself is always a root, so a bare
    `request.params.arguments.path` use — 41 occurrences in the corpus —
    is covered by `expr_is_tainted` on the receiver chain without any
    per-shape matching. The explicit idioms below exist for precision, not
    coverage:

      const { name, arguments: args } = request.params;
      const { name, arguments: args = {} } = request.params;
      const args = request.params.arguments;
      const args = request.params.arguments ?? {};
      const args = request.params.arguments as ToolArgs;
      const args = request.params.arguments?.path as string;
    """
    roots = {req}
    body = fn.body_span
    q = re.escape(req)
    masked = src.masked
    lo = max(0, body.start)
    hi = min(len(masked), body.end)

    params_re = re.compile(rf"\s*{q}\s*\??\s*\.\s*params(?![\w$])")
    arguments_alias = re.compile(
        r"(?<![\w$])arguments\s*:\s*(?P<local>[A-Za-z_$][\w$]*)")
    direct = re.compile(
        rf"(?<![\w$])(?:const|let|var)(?![\w$])\s+(?P<local>[A-Za-z_$][\w$]*)"
        rf"\s*(?::[^=;\n]*)?=\s*{q}\s*\??\s*\.\s*params\s*\??\s*\.\s*arguments"
        rf"(?![\w$])")

    # `const { name, arguments: X } = <req>.params`. The interior is located
    # with match_bracket rather than a `[^{}]*` regex, because the default
    # value in `arguments: X = {}` puts braces inside the pattern.
    for m in _DECL_KW_RE.finditer(masked, lo, hi):
        p = m.end()
        while p < hi and masked[p] in _WS_CHARS:
            p += 1
        if p >= hi or masked[p] != "{":
            continue
        close = jsparse.match_bracket(src, p)
        if close is None or close >= hi:
            continue
        eq = _depth0_assign_eq(src, close + 1, hi)
        if eq == -1 or not params_re.match(masked, eq + 1, hi):
            continue
        for alias in arguments_alias.finditer(masked, p + 1, close):
            roots.add(alias.group("local"))

    for m in direct.finditer(masked, lo, hi):
        roots.add(m.group("local"))
    return roots


def _from_set_request_handler(src: Source, call: jsparse.CallSite,
                              args: list[Span]) -> ToolHandler | None:
    if len(args) < 2:
        return None
    if not _is_call_tool_schema(src, args[0]):
        return None
    fn = _lowlevel_function(src, Span(args[1].start, args[-1].end))
    if fn is None or not fn.params_ok:
        return None
    req = fn.param_at(0)[0].name
    return ToolHandler(
        path=src.path,
        tool_name="",
        display_name="<anonymous>",
        style="lowlevel",
        fn=fn,
        # Parameter 0 is the *request*, never the arguments. The arguments
        # live at `request.params.arguments` and are reached through
        # `taint_roots` instead.
        args_are_param0=False,
        schema_span=None,
        # There is no registration config on this path at all — the schemas
        # live in a separate tools/list descriptor this module does not
        # model. Consumers key on `style == "lowlevel"` and skip.
        schema_known=True,
        taint_roots=frozenset(_lowlevel_roots(src, fn, req)),
        reg_line=call.line,
    )


# ==========================================================================
# the public entry point
# ==========================================================================
def find_tool_handlers(src: Source) -> list[ToolHandler]:
    """Every statically-resolvable MCP tool handler in `src`.

    Returns [] when `src.ok` is False or when `file_imports_mcp` is False.
    Registrations whose handler is a factory call, an unresolvable
    identifier, a cross-file forward, or whose parameters do not parse are
    omitted entirely rather than reported with a degraded `fn`.

    The result is sorted by handler position and de-duplicated on it, so a
    check that iterates it produces byte-identical output run to run.
    """
    if not src.ok or not file_imports_mcp(src):
        return []

    bindings = jsparse.collect_bindings(src)
    found: list[ToolHandler] = []

    for call in jsparse.find_calls(src, _REGISTER_METHODS | _DEFINE_METHODS):
        is_define = call.method in _DEFINE_METHODS
        # Gate 1. `tool` / `registerTool` / `addTool` must be member calls.
        # supabase-mcp's `export function tool(t) { return t; }`, invoked
        # bare, is an identity helper and not a registration. `defineTool`
        # is exempt: it is normally a bare imported function.
        if not is_define and not call.receiver:
            continue

        args = _real_args(src, call)
        if not args:
            continue

        handler: ToolHandler | None = None
        if is_define:
            handler = _from_descriptor(src, call, args[0], "defineTool",
                                       bindings)
        elif len(args) == 1:
            # S9/S10: `mcp.addTool({ name, parameters, execute })`.
            # `registerTool` is excluded — it has no single-object overload,
            # and admitting one would let a random options bag become a
            # registration with `style == "registerTool"`, which is the one
            # style the input-validation check trusts for a *negative*.
            if call.method != "registerTool":
                handler = _from_descriptor(src, call, args[0], call.method,
                                           bindings)
        elif call.method == "registerTool":
            handler = _from_register_tool(src, call, args, bindings)
        else:
            handler = _from_overload_ladder(src, call, args, bindings)

        if handler is not None:
            found.append(handler)

    for call in jsparse.find_calls(src, {"setRequestHandler"}):
        handler = _from_set_request_handler(src, call, _real_args(src, call))
        if handler is not None:
            found.append(handler)

    seen: set[tuple[int, int, str]] = set()
    out: list[ToolHandler] = []
    for h in sorted(found, key=lambda x: (x.fn.span.start, x.fn.span.end,
                                          x.style, x.reg_line)):
        key = (h.fn.span.start, h.fn.span.end, h.style)
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


# ==========================================================================
# prose helper
# ==========================================================================
def case_label_at(src: Source, body: Span, offset: int) -> str:
    """The nearest enclosing `case "<name>":` label before `offset`, or "".

    A low-level `setRequestHandler(CallToolRequestSchema, …)` dispatcher has
    no per-tool registration, so the switch label is the only name a report
    can put in front of the reader. PROSE ONLY: nothing about a finding's
    existence may depend on this, because "nearest preceding label" is not
    the same as "the case this statement is in" once a `default:` or a
    nested switch is involved.
    """
    lo = max(0, body.start)
    hi = min(len(src.masked), max(lo, min(offset, body.end)))
    best = ""
    for m in _CASE_RE.finditer(src.masked, lo, hi):
        quote_at = m.start(1)
        quote = src.masked[quote_at]
        close = src.masked.find(quote, quote_at + 1)
        if close == -1 or close >= hi:
            continue
        after = close + 1
        while after < hi and src.masked[after] in _WS_CHARS:
            after += 1
        if after >= hi or src.masked[after] != ":":
            continue
        best = src.text[quote_at + 1:close]
    return best


# ==========================================================================
# taint
# ==========================================================================
def _pattern_names(src: Source, span: Span, depth: int = 3) -> set[str]:
    """Every local name a binding pattern introduces.

    `{ name, arguments: args }` -> {name, args}; `[a, b]` -> {a, b};
    `{ a, ...rest }` -> {a, rest}; `x: SomeType` -> {x}. Nested patterns
    recurse to `depth`.
    """
    t = src.trimmed(span)
    if t.is_empty() or depth < 0:
        return set()
    m = src.masked
    head = m[t.start]

    if head in "{[":
        close = jsparse.match_bracket(src, t.start)
        if close is None or close != t.end - 1:
            return set()
        out: set[str] = set()
        for part_raw in _split_commas(src, t.start + 1, close):
            part = src.trimmed(part_raw)
            if part.is_empty():
                continue
            text = m[part.start:part.end]
            if text.startswith("..."):
                part = src.trimmed(Span(part.start + 3, part.end))
                if part.is_empty():
                    continue
            eq = _depth0_assign_eq(src, part.start, part.end)
            if eq != -1:
                part = src.trimmed(Span(part.start, eq))
            if part.is_empty():
                continue
            if head == "{":
                colon = _depth0_char(src, part.start, part.end, ":")
                if colon != -1:
                    part = src.trimmed(Span(colon + 1, part.end))
            out |= _pattern_names(src, part, depth - 1)
        return out

    # A plain binding, possibly annotated: `out: string`.
    colon = _depth0_char(src, t.start, t.end, ":")
    if colon != -1:
        t = src.trimmed(Span(t.start, colon))
    name = src.code(t).strip()
    return {name} if _is_identifier(name) else set()


def propagate_taint(src: Source, body: Span, seeds: set[str]) -> set[str]:
    """Textual taint propagation inside one handler body.

    Scans `const` / `let` / `var` declarations and `x = …` / `x += …`
    reassignments in source order; whenever the initializer references an
    already-tainted name as a value, every binding the left-hand side
    introduces joins the set. This mirrors the Python checks'
    Assign / AnnAssign / AugAssign propagation.

    Two passes, no fixpoint, no control-flow sensitivity: the second pass
    picks up a simple forward reference (a `const` whose initializer only
    becomes tainted because of a later-scanned declaration) without paying
    for iteration to convergence.

    Explicitly NOT modelled, in both directions:
      - taint carried through an array element or an object property that
        is later read back (`bag.cmd = args.cmd; exec(bag.cmd)`);
      - laundering. `Schema.parse(args)` / `Schema.safeParse(args)` keeps
        the taint, because shape validation does not constrain the string
        values inside the shape;
      - anything crossing a function or file boundary. A nested callback
        that closes over a tainted name is covered only because its text
        lies inside `body`.
    """
    tainted = set(seeds)
    lo = max(0, body.start)
    hi = min(len(src.masked), body.end)
    if lo >= hi:
        return tainted

    for _ in range(2):
        for m in _DECL_KW_RE.finditer(src.masked, lo, hi):
            start = m.end()
            eq = _depth0_assign_eq(src, start, hi)
            if eq == -1:
                continue
            init_end = _expression_end(src, eq + 1, hi)
            if init_end <= eq + 1:
                continue
            if expr_is_tainted(src, Span(eq + 1, init_end), tainted):
                tainted |= _pattern_names(src, Span(start, eq))
        for m in _ASSIGN_RE.finditer(src.masked, lo, hi):
            name = m.group("name")
            if name in tainted:
                continue
            init_end = _expression_end(src, m.end(), hi)
            if init_end <= m.end():
                continue
            if expr_is_tainted(src, Span(m.end(), init_end), tainted):
                tainted.add(name)
    return tainted


def expr_is_tainted(src: Source, span: Span,
                    tainted: Collection[str]) -> bool:
    """True when the expression references a tainted name AS A VALUE.

    Delegates to `jsparse.identifier_uses`, which excludes property
    position and object-literal key position. That distinction carries the
    whole predicate: `foo.args` is not a use of a local `args`, and
    `{ path: BASE }` is not a use of a local `path`, but `args.path` *is* a
    use of `args` — and that receiver-chain shape is the dominant one in
    every real handler.
    """
    for name in sorted({n for n in tainted if n}):
        if jsparse.identifier_uses(src, span, name):
            return True
    return False
