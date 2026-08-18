"""ts_tool_input_validation — flag unconstrained input schemas on TypeScript /
JavaScript MCP tool registrations.

Background: an MCP server publishes each tool's input schema to the model as
part of `tools/list`. A field declared `z.string()` with no length, pattern, or
format rule accepts a megabyte of arbitrary prose; a field declared `z.any()`
validates nothing at all. Large free-form string fields are the substrate most
prompt-injection-via-tool-argument attacks rely on, and an unbounded string is
also the cheapest way for a model to blow a context window or a downstream API
quota. Constraining the schema closes that window without losing useful
expressiveness.

This is a LOW-severity hygiene check, not a CVE detector. Exactly like its
Python sibling `tool_input_validation`, it will produce findings on most
well-written TypeScript MCP servers — the official `@modelcontextprotocol`
example servers declare bare `z.string()` fields in several places. Read the
output as "here are the spots where input validation could be tightened," not
as "these are exploitable." The severity must not be raised.

Motivating real-world case (2026-07): the one kind here that is a genuine
correctness bug is UNDECLARED_INPUT. `server.registerTool(name, { title },
async ({ path, content }) => ...)` reads as a two-argument tool, but with no
`inputSchema` the SDK invokes the callback as `handler(extra)` — parameter 0 is
the `RequestHandlerExtra` / `ServerContext`, so `path` and `content` are both
`undefined` on every real protocol call. Unit tests that call the handler
directly pass; the server is broken in production.

What's flagged (LOW severity):

  - LOOSE_STRING — a top-level schema field whose value chain is `z.string()`
    and whose every subsequent chain step is one of the handful of methods
    that provably constrain nothing (`.describe()`, `.optional()`,
    `.nullable()`, `.nullish()`, `.default()`, `.catch()`, `.readonly()`,
    `.meta()`). Any other method in the chain suppresses the finding — see
    the `_TRANSPARENT_METHODS` comment for why this is an allowlist of
    harmless methods and not a list of constraining ones.
  - LOOSE_ANY — a top-level schema field declared `z.any()` or `z.unknown()`,
    under the same "every following step is transparent" rule.
  - ANY_PARAM — the registration declares a schema we can read, with at least
    one field, but the handler's first parameter is a single name annotated
    `any`, so the schema and the code disagree about what arrives.
  - UNDECLARED_INPUT — a `registerTool(name, config, handler)` whose config
    object carries no `inputSchema` key at all, yet the handler destructures
    names from parameter 0 that are not server-context properties.

What's NOT flagged (false-negative bias, per the v0.3 credibility bar):

  - "No input schema" on its own. An absent `inputSchema` is the *correct*
    encoding of a zero-argument tool (`server.tool("ping", "desc", async () =>
    ...)`, and `browser-tools-mcp/mcp-server.ts:178` in the wild). Only the
    contradiction — no schema, but the handler destructures real argument
    names — is reported.
  - A config we could not parse as an object literal (an identifier, a spread).
    Schema presence is then unknown and nothing is claimed about it.
  - A handler parameter typed `unknown`, and a parameter whose name starts with
    `_`. `unknown` is TypeScript's *safe* top type: the compiler refuses every
    use until the value is narrowed, so the author has not thrown the schema
    away, only chosen to narrow explicitly. `firecrawl-mcp-server` writes
    `execute: async (args: unknown, { session, log }) => { const { url,
    ...options } = args as ... }` on 26 tools deliberately and consistently;
    flagging it 26 times would bury the real LOOSE_STRING findings in the same
    repo. A leading `_` is the universal "deliberately ignored" convention.
  - ANY_PARAM when the schema is declared by reference (`inputSchema:
    tool.inputSchema`, a generic dispatch loop over a tool table, as in
    `mcp-server-neon/app/api/[transport]/route.ts:382`). There `any` is the
    only annotation the author *can* write, so the finding would be
    unactionable.
  - UNDECLARED_INPUT on the deprecated `tool()` overload ladder and on the
    object-descriptor styles. Only `registerTool` gives a confident negative:
    its config is an object literal we parsed and saw had no `inputSchema` key.
    In the positional ladder a bare identifier in the middle slot is
    indistinguishable from an annotations object — `exa-mcp-server`'s
    `server.tool("agent_run", "...", agentRunInputShape, { readOnlyHint: true
    }, handler)` DOES declare a schema, and claiming otherwise would be a
    false positive of exactly the v0.3 class.
  - `zodToJsonSchema(X)` / `z.toJSONSchema(X)` / a hand-written JSON-Schema
    object literal. Those are `tools/list` descriptors, not runtime validators,
    and they carry `maxLength` conventions this check does not model.
  - A field whose value chain we cannot classify: an unresolved identifier, an
    arktype `type(...)`, a valibot `v.object(...)`, a call to a local helper.
    That single field is skipped; its siblings are still judged.
  - A field whose chain carries ANY method outside `_TRANSPARENT_METHODS` —
    including one this file has never heard of. `z.string().array()`,
    `z.string().or(z.number())`, `z.coerce.string()` and a hypothetical future
    `z.string().someNewFormat()` are all suppressed rather than guessed at.
  - Fields nested more than one level deep (inside a `z.object(...)` that is
    itself a field value). Top-level fields only — diminishing returns, rising
    ambiguity.
  - `z.record()`, `z.array(z.any())`, `z.custom()`. Genuinely loose, but the
    fix is not a one-line schema edit, so the finding would not be actionable.
  - Low-level `setRequestHandler(CallToolRequestSchema, ...)` dispatch. There
    is no registration config on that path to inspect.
  - Description quality and output-schema looseness. Neither is statically
    decidable, and neither is attacker-controlled.

Note that `.describe()` deliberately does NOT suppress LOOSE_STRING. It
documents a field for the model; it applies no length, pattern, or format rule.

Known limits: analysis is confined to a single file and to the registration
site. A schema assembled in another module and imported by name is not
resolved, and a handler that re-validates its arguments in a helper elsewhere
is invisible — cross-file flow is out of scope for the same reason the Python
checks confine themselves to one file. All lexing goes through
`mcp_audit.jsparse`; a file whose `Source.ok` is False is skipped entirely.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.finding import Finding, Severity
from mcp_audit import jsparse, tstools

CHECK_ID = "ts_tool_input_validation"

# House skip set, duplicated per module as the other checks do. Deliberately
# free of "test" / "tests" / "fixtures" / "examples": `_should_skip` matches on
# ANY component of an ABSOLUTE path, so those words would blank out this
# check's own fixture tree (and any repo that keeps real code under them).
# jsparse.iter_source_files applies the fuller TS set relative to `root`.
_SKIP_DIRS = {
    ".venv", "venv", "env", "node_modules", ".git", "site-packages",
    ".tox", ".nox", "build", "dist", "__pycache__",
    "out", "coverage", ".next", ".nuxt", ".svelte-kit", ".turbo",
    ".vercel", ".cache", "bower_components", "vendor",
}

# Zod chain methods that provably constrain NOTHING: with them the field
# accepts exactly what it accepted without them (modulo `undefined` / `null` /
# a default). A field is reported only when EVERY method after the constructor
# is in this set; any other method — recognised or not — suppresses.
#
# This is deliberately an allowlist of harmless methods rather than a list of
# constraining ones. An earlier revision enumerated the constraints
# (`min`/`max`/`regex`/`email`/...) and treated everything else as loose, which
# fired on thirteen genuinely-constrained zod idioms in a hand-written probe:
# `.nonempty()` (zod's own alias for `.min(1)`), `.check(z.maxLength(80))`
# (the zod v4 composable-check API), the v4 case assertions `.lowercase()` /
# `.uppercase()`, the v4 IP/CIDR spellings `.ipv4()` / `.ipv6()` /
# `.cidrv4()`, and the v4 string formats `.guid()` / `.e164()` /
# `.base64url()` / `.hostname()` / `.hex()` / `.httpUrl()`. Every one of those
# produced a finding asserting "no length, pattern, or format constraint"
# about code that has one — the exact false-positive class that cost this
# project a public retraction in v0.3. Zod ships dozens of string formats and
# adds more each minor release, so any constraint list goes stale INTO false
# positives. This one goes stale into false negatives instead: a new zod
# method we have never heard of silently suppresses.
#
# `describe` / `meta` are here on purpose: they document a field for the model
# and apply no length, pattern, or format rule.
_TRANSPARENT_METHODS = {
    "describe", "meta", "register",
    "optional", "nullable", "nullish",
    "default", "prefault", "catch",
    "readonly",
}

# Zod constructors that are open-ended enough to report. Every other
# constructor (enum, nativeEnum, literal, union, discriminatedUnion, number,
# boolean, date, object, array, tuple, instanceof, coerce, ...) is treated as
# closed and is never flagged.
_LOOSE_STRING_CTORS = {"string"}
_LOOSE_ANY_CTORS = {"any", "unknown"}

# v1 RequestHandlerExtra / v2 ServerContext / fastmcp context properties. A
# handler destructuring only these from parameter 0 is correctly reading the
# server context of a no-input tool, not a broken schema.
_EXTRA_PROPS = {
    "signal", "sessionId", "requestId", "authInfo", "_meta", "requestInfo",
    "sendNotification", "sendRequest", "server", "log", "reportProgress",
    "session", "streamContent", "elicit", "sample",
}

# Handler parameter annotations that throw away whatever the schema declared.
# `unknown` is deliberately absent: it is TypeScript's *safe* top type and the
# compiler forces a narrowing at every use, so the schema and the code do not
# actually disagree. Only `any` silently disables checking.
_ANY_TYPES = {"any"}

# JSON-Schema descriptor factories. Their output is a `tools/list` descriptor,
# not a runtime validator — see suppression 2 in the module docstring.
_JSON_SCHEMA_FACTORY_RE = re.compile(
    r"^(?:[A-Za-z_$][\w$]*\s*\.\s*)?(?:zodToJsonSchema|toJSONSchema)\s*\(")

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_WS = " \t\r\n"


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _zod_roots(src: jsparse.Source) -> set[str]:
    """Identifiers that name the zod namespace in this file.

    `z` is the universal convention; we additionally accept whatever local a
    `zod` import binds. Any other root (arktype's `type`, valibot's `v`, a
    project-local schema helper) is deliberately left unclassified — see
    suppression 3."""
    roots = {"z"}
    for rec in jsparse.collect_imports(src):
        if rec.module == "zod" or rec.module.startswith("zod/"):
            if rec.local:
                roots.add(rec.local)
    return roots


def _chain(src: jsparse.Source, span: jsparse.Span) -> tuple[str, list[str]] | None:
    """Split a schema field expression into (root identifier, method chain).

    `z.string().min(1)` -> ("z", ["string", "min"]). Runs entirely on the
    MASKED text, so a `.max` inside a string literal or a comment is invisible
    and a regex literal's contents cannot be mistaken for chain syntax.

    Returns None the moment anything appears at bracket depth 0 that is not a
    `.member` step — a ternary, an `as` cast, a `||`, an operator. We do not
    model those, so we decline to classify rather than guess."""
    trimmed = src.trimmed(span)
    if trimmed.is_empty():
        return None
    text = src.code(trimmed)

    head = _IDENT_RE.match(text)
    if head is None:
        return None
    root = head.group(0)

    methods: list[str] = []
    depth = 0
    i = head.end()
    while i < len(text):
        c = text[i]
        if c in "([{":
            depth += 1
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            if depth < 0:
                return None
            i += 1
            continue
        if depth > 0:
            i += 1
            continue
        if c in _WS:
            i += 1
            continue
        if c == "?" and text.startswith("?.", i):
            i += 1  # optional chaining: fall through to the '.' below
            continue
        if c == ".":
            j = i + 1
            while j < len(text) and text[j] in _WS:
                j += 1
            seg = _IDENT_RE.match(text, j)
            if seg is None:
                return None
            methods.append(seg.group(0))
            i = seg.end()
            continue
        # Anything else at depth 0 is an expression form we do not model.
        return None
    if depth != 0:
        return None
    return root, methods


def _classify_field(src: jsparse.Source, span: jsparse.Span,
                    roots: set[str]) -> str | None:
    """Return 'LOOSE_STRING' / 'LOOSE_ANY' for an unconstrained zod field, or
    None when the field is constrained, closed, or unclassifiable."""
    parsed = _chain(src, span)
    if parsed is None:
        return None
    root, methods = parsed
    if root not in roots or not methods:
        return None
    ctor = methods[0]
    # Anything other than a provably-transparent wrapper suppresses. That
    # covers every real constraint (`.max(80)`, `.regex(...)`, `.nonempty()`,
    # `.check(...)`, `.ipv4()`), every refinement (`z.any().refine(...)` is a
    # real validator), every transform, and every zod method invented after
    # this file was written.
    if any(m not in _TRANSPARENT_METHODS for m in methods[1:]):
        return None
    if ctor in _LOOSE_ANY_CTORS:
        return "LOOSE_ANY"
    if ctor in _LOOSE_STRING_CTORS:
        return "LOOSE_STRING"
    return None


def _shape_object(src: jsparse.Source, span: jsparse.Span,
                  roots: set[str]) -> jsparse.ObjectLiteral | None:
    """The object literal carrying the schema's top-level fields.

    Accepts a zod raw shape (`{ q: z.string() }`) directly, and peels exactly
    one `z.object({...})` wrapper (the fastmcp `parameters` shape, and a common
    `inputSchema` spelling). Returns None for anything else — a bare
    identifier, a `.merge()` chain, a JSON-Schema factory call."""
    trimmed = src.trimmed(span)
    if trimmed.is_empty():
        return None

    # `zodToJsonSchema(X)` / `z.toJSONSchema(X)` emit a tools/list descriptor,
    # not a runtime validator. Refused explicitly so the suppression is legible
    # rather than an accident of the chain parser.
    if _JSON_SCHEMA_FACTORY_RE.match(src.code(trimmed)):
        return None

    obj = jsparse.parse_object(src, trimmed)
    if obj is not None:
        return obj if obj.ok else None

    parsed = _chain(src, trimmed)
    if parsed is None:
        return None
    root, methods = parsed
    if root not in roots or methods != ["object"]:
        return None

    text = src.code(trimmed)
    open_paren = text.find("(")
    if open_paren < 0:
        return None
    split = jsparse.split_args(src, trimmed.start + open_paren)
    if split is None:
        return None
    args, _close = split
    args = [a for a in args if not src.trimmed(a).is_empty()]
    if len(args) != 1:
        return None
    inner = jsparse.parse_object(src, src.trimmed(args[0]))
    if inner is None or not inner.ok:
        return None
    return inner


def _is_json_schema_descriptor(src: jsparse.Source,
                               obj: jsparse.ObjectLiteral) -> bool:
    """True for a hand-written JSON-Schema object (`{ type: "object",
    properties: {...} }`). Those are tools/list descriptors, not zod raw
    shapes, and they are suppressed wholesale — a zod shape never has a
    string-literal `type` field alongside a `properties` field."""
    if obj.get("properties") is not None:
        return True
    entry = obj.get("type")
    if entry is not None and not entry.value_span.is_empty():
        if jsparse.string_literal_value(src, src.trimmed(entry.value_span)) is not None:
            return True
    return False


def _param0_names(fn: jsparse.FunctionBody) -> tuple[str, ...] | None:
    """The property names parameter 0 destructures, or None when parameter 0
    is absent, a plain name, a rest element, or anything we cannot flatten."""
    if fn.positional_count == 0:
        return None
    bindings = fn.param_at(0)
    if not bindings:
        return None
    if any(b.is_rest for b in bindings):
        # `({ ...rest })` — we cannot enumerate what it reads. Suppress.
        return None
    if not all(b.is_destructured for b in bindings):
        return None
    return tuple(b.source_name for b in bindings)


def _param0_any_type(fn: jsparse.FunctionBody) -> bool:
    """True when parameter 0 is a single plain name annotated `any`.

    A name starting with `_` is exempt: that is the universal "deliberately
    ignored" convention, and `async (_args: unknown, extra) => ...` in
    `mcp-server-neon` is a zero-argument tool saying so explicitly."""
    if fn.positional_count == 0:
        return False
    bindings = fn.param_at(0)
    if len(bindings) != 1:
        return False
    p = bindings[0]
    if p.is_destructured or p.is_rest or p.name.startswith("_"):
        return False
    return p.type_text.strip() in _ANY_TYPES


def _build_finding(path: Path, tool: str, line: int, kind: str,
                   field: str = "", names: str = "") -> Finding:
    remediation = (
        "Constrain the field where it is declared: "
        "`z.string().min(1).max(256)` for free-form text, "
        "`z.string().regex(/^[A-Za-z0-9._-]+$/)` for identifiers, "
        "`z.enum(['a','b','c'])` for a fixed set, `z.number().int().positive()` "
        "for counts. Replace `z.any()` with the shape you actually accept. If "
        "the handler expects arguments, declare them: "
        "`server.registerTool(name, { inputSchema: { path: z.string() } }, "
        "async ({ path }) => …)` — with no `inputSchema` the SDK passes the "
        "server context as the first parameter. `.describe()` documents a "
        "field but does not constrain it. If the looseness is intentional "
        "(genuinely arbitrary prose), say so in the field's `.describe()` so "
        "reviewers know it is a deliberate choice."
    )

    if kind == "UNDECLARED_INPUT":
        # This one is a correctness bug, not a tightening opportunity, so it
        # gets remediation that leads with the actual fix instead of the
        # `z.string().min(1)` advice the LOOSE_* kinds need.
        remediation = (
            "Declare the arguments the handler reads: "
            "`server.registerTool(name, { title, description, inputSchema: { "
            "path: z.string().min(1), content: z.string().max(65536) } }, "
            "async ({ path, content }) => …)`. With no `inputSchema` the SDK "
            "invokes the callback as `handler(extra)`, so parameter 0 is the "
            "`RequestHandlerExtra` server context and every destructured "
            "argument name is `undefined`. If the tool really takes no "
            "arguments, read the context by a name that says so "
            "(`async (extra) => …`) rather than destructuring argument names "
            "out of it."
        )
        message = (
            f"tool '{tool}' destructures {names} from its handler's first "
            "parameter, but the registration passes no `inputSchema`. The SDK "
            "calls a schemaless handler as `handler(extra)` — the first "
            "parameter is the server context, not the tool arguments — so "
            "every one of those bindings is `undefined` at runtime. This will "
            "fail at the first real MCP protocol call even if every unit test "
            "passes."
        )
    else:
        detail = {
            "LOOSE_STRING": (
                f"field '{field}' is `z.string()` with no length, pattern, or "
                "format constraint"
            ),
            "LOOSE_ANY": (
                f"field '{field}' is `z.any()` / `z.unknown()`, which "
                "validates nothing"
            ),
            "ANY_PARAM": (
                "handler parameter is typed `any`, so the schema and the code "
                "disagree about what arrives"
            ),
        }[kind]
        message = (
            f"tool '{tool}' {detail}. The MCP server publishes this schema to "
            "the model as part of `tools/list`, and an unconstrained field "
            "lets the model emit oversized or unexpected payloads; large "
            "free-form string fields are the substrate most prompt-injection-"
            "via-tool-argument attacks rely on. Constraining the schema closes "
            "that window without losing useful expressiveness."
        )

    return Finding(
        check=CHECK_ID,
        severity=Severity.LOW,
        path=path,
        line=line,
        message=message,
        remediation=remediation,
    )


def _check_file(path: Path) -> list[Finding]:
    src = jsparse.load(path)
    if src is None or not src.ok:
        # A degraded lex must never emit a finding (v0.3 credibility bar).
        return []

    handlers = tstools.find_tool_handlers(src)
    if not handlers:
        return []

    roots = _zod_roots(src)
    findings: list[Finding] = []

    for h in handlers:
        # Low-level tools/call dispatch carries no registration config; its
        # schemas live in a separate tools/list descriptor we do not model.
        if h.style == "lowlevel":
            continue
        # Schema presence undecidable (config was an identifier or a spread).
        # Never guess.
        if not h.schema_known:
            continue
        fn = h.fn
        if not fn.params_ok:
            continue

        tool = h.display_name
        param_line = (src.line_of(fn.params_span.start)
                      if fn.params_span is not None else fn.line)

        if h.schema_span is None:
            # No schema key at all. That is the CORRECT encoding of a
            # zero-argument tool, so we only report the contradiction: the
            # handler destructures names that are not server-context props.
            # `registerTool` only — its config is an object literal we parsed
            # and saw had no `inputSchema` key, which is a confident negative.
            # In the positional `tool()` ladder a bare identifier in the middle
            # slot is indistinguishable from an annotations object, so "no
            # schema" cannot be asserted there (exa-mcp-server's agent_run).
            if h.style != "registerTool":
                continue
            names = _param0_names(fn)
            if names and not set(names).issubset(_EXTRA_PROPS):
                pretty = ", ".join(f"`{n}`" for n in names)
                findings.append(_build_finding(
                    path, tool, param_line, "UNDECLARED_INPUT", names=pretty))
            continue

        shape = _shape_object(src, h.schema_span, roots)
        if shape is None or not shape.ok:
            continue
        if _is_json_schema_descriptor(src, shape):
            continue

        # A handler typed `any` throws away a schema we can actually read. If
        # the schema is declared by reference, or is empty, `any` is either the
        # only possible annotation or harmless — say nothing.
        if shape.entries and _param0_any_type(fn):
            findings.append(_build_finding(path, tool, param_line, "ANY_PARAM"))

        for entry in shape.entries:
            if entry.is_spread or entry.is_method or not entry.key:
                continue
            if entry.value_span.is_empty():
                # Shorthand (`{ query }`) — the value lives elsewhere.
                continue
            kind = _classify_field(src, entry.value_span, roots)
            if kind is None:
                continue
            findings.append(_build_finding(
                path, tool, entry.line, kind, field=entry.key))

    return findings


def check(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in jsparse.iter_source_files(root):
        if _should_skip(path):
            continue
        findings.extend(_check_file(path))
    return findings
