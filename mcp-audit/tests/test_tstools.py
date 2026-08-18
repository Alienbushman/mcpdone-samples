"""Tests for mcp_audit.tstools — the MCP tool-handler surface.

The organising principle of this file is that tstools' job is to say NO.
Every check downstream inherits whatever this module decides, so a wrong
"yes" (a plugin framework's `registry.tool(...)` read as a registration, a
no-input tool's server-context parameter read as attacker input) becomes a
false positive in three checks at once. The suppression tests below are
therefore the load-bearing ones, and `test_r2_*` is the single most
important group in the file.
"""
from __future__ import annotations

from pathlib import Path

from mcp_audit import jsparse, tstools

MCP_IMPORT = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'import { z } from "zod";\n'
)


def _src(body: str, *, prelude: str = MCP_IMPORT) -> jsparse.Source:
    return jsparse.scan(prelude + body, Path("server.ts"))


def _handlers(body: str, *, prelude: str = MCP_IMPORT) -> list[tstools.ToolHandler]:
    return tstools.find_tool_handlers(_src(body, prelude=prelude))


def _one(body: str, *, prelude: str = MCP_IMPORT) -> tstools.ToolHandler:
    hs = _handlers(body, prelude=prelude)
    assert len(hs) == 1, [(h.display_name, h.style) for h in hs]
    return hs[0]


# ==========================================================================
# Gate 0 — file_imports_mcp
# ==========================================================================
def test_official_sdk_import_opens_the_gate():
    assert tstools.file_imports_mcp(_src("", prelude=MCP_IMPORT))


def test_type_only_import_counts_as_mcp_context():
    """`import type { … }` binds no runtime value, but it is conclusive
    proof the file is MCP code — a low-level dispatcher often imports
    nothing else from the SDK."""
    src = _src("", prelude=(
        'import type { CallToolRequest } from '
        '"@modelcontextprotocol/sdk/types.js";\n'))
    assert tstools.file_imports_mcp(src)


def test_framework_imports_open_the_gate():
    for module in ("fastmcp", "fastmcp/dist/x.js", "mcp-lite",
                   "@vercel/mcp-adapter", "agents/mcp",
                   "@modelcontextprotocol/sdk"):
        src = _src("", prelude=f'import {{ X }} from "{module}";\n')
        assert tstools.file_imports_mcp(src), module


def test_commonjs_require_of_the_sdk_opens_the_gate():
    src = _src("", prelude=(
        'const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");\n'))
    assert tstools.file_imports_mcp(src)


def test_unrelated_imports_keep_the_gate_shut():
    for module in ("zod", "./plugin-registry.js", "express",
                   "my-fastmcp-helpers", "fastmcp-clone"):
        src = _src("", prelude=f'import {{ X }} from "{module}";\n')
        assert not tstools.file_imports_mcp(src), module


def test_non_mcp_file_yields_no_handlers():
    """`registry.registerTool(...)` in a plugin framework is not ours.
    Without Gate 0 the method name alone would make it a registration."""
    body = (
        'registry.registerTool("search", { inputSchema: { q: z.string() } },\n'
        "  async ({ q }) => q);\n"
    )
    assert _handlers(body, prelude='import { z } from "zod";\n') == []


def test_degraded_lex_yields_no_handlers():
    """An unterminated template sets Source.ok False. Every span after the
    break point is nonsense; the hard contract is to return []."""
    src = _src(
        'server.registerTool("x", { inputSchema: { a: z.string() } },\n'
        "  async ({ a }) => { return `unterminated ${a}; });\n")
    assert not src.ok
    assert tstools.find_tool_handlers(src) == []


# ==========================================================================
# Gate 1 — member calls only
# ==========================================================================
def test_bare_local_tool_helper_is_not_a_registration():
    """supabase-mcp ships `export function tool(t) { return t; }` and calls
    it bare. Keying on the method name alone turns every one of those into
    a tool registration."""
    body = (
        "export function tool(t) { return t; }\n"
        'const listOrgs = tool({ name: "list", inputSchema: { id: z.string() },\n'
        "  execute: async ({ id }) => id });\n"
    )
    assert _handlers(body) == []


def test_bare_addTool_is_not_a_registration():
    body = (
        'addTool({ name: "grep", parameters: z.object({ p: z.string() }),\n'
        "  execute: async (args) => args.p });\n"
    )
    assert _handlers(body) == []


def test_any_receiver_name_is_accepted():
    """190 `server.`, 85 `context.`, 24 `this.server.`, 14 `server.server.`,
    plus `pi.`, `mcp.`, `registry.` were measured in the corpus. Gate 1 is
    'has a receiver', never 'the receiver is called server'."""
    for receiver in ("server", "this.server", "server.server", "mcp", "pi",
                     "context"):
        body = (
            f'{receiver}.registerTool("t", {{ inputSchema: {{ a: z.string() }} }},\n'
            "  async ({ a }) => a);\n"
        )
        assert len(_handlers(body)) == 1, receiver


# ==========================================================================
# Gate 2 — exact method names
# ==========================================================================
def test_prompt_and_resource_registrations_are_never_tools():
    """`prompt`, `registerPrompt`, `resource`, `registerResource` share the
    identical overload ladder with `tool`."""
    for method in ("prompt", "registerPrompt", "resource", "registerResource"):
        body = (
            f'server.{method}("t", {{ inputSchema: {{ a: z.string() }} }},\n'
            "  async ({ a }) => a);\n"
        )
        assert _handlers(body) == [], method


# ==========================================================================
# R2 — the taint-root trap. The most important group in this file.
# ==========================================================================
def test_r2_no_schema_means_no_taint_roots():
    """browser-tools-mcp/mcp-server.ts:178 verbatim in shape. The SDK
    dispatches a schemaless tool as `cb(extra)`, so parameter 0 is the
    server context and nothing here is attacker-controlled."""
    h = _one('server.tool("getConsoleLogs", "Check our browser logs",\n'
             "  async () => ({ content: [] }));\n")
    assert h.style == "tool"
    assert h.args_are_param0 is False
    assert h.taint_roots == frozenset()
    assert h.schema_span is None


def test_r2_no_schema_with_a_named_first_parameter_is_still_untainted():
    """The parameter is `extra`, whatever the author called it."""
    h = _one('server.tool("getLogs", "desc", async (extra) => extra);\n')
    assert h.taint_roots == frozenset()


def test_r2_registerTool_without_inputSchema_has_no_taint_roots():
    h = _one('server.registerTool("write", { title: "Write" },\n'
             "  async ({ path, content }) => path);\n")
    assert h.schema_known is True
    assert h.schema_span is None
    assert h.args_are_param0 is False
    assert h.taint_roots == frozenset()


def test_r2_parameter_1_and_later_are_never_tainted():
    """Parameter 1 is RequestHandlerExtra (v1) / ServerContext (v2) /
    fastmcp's `{ log, reportProgress, session }`. All server-side."""
    h = _one('server.registerTool("t", { inputSchema: { a: z.string() } },\n'
             "  async ({ a }, extra, third) => a);\n")
    assert h.taint_roots == frozenset({"a"})
    assert "extra" not in h.taint_roots
    assert "third" not in h.taint_roots


def test_r2_schema_present_taints_every_binding_of_parameter_0():
    h = _one('server.registerTool("t",\n'
             "  { inputSchema: { a: z.string(), b: z.string() } },\n"
             "  async ({ a, b: renamed }) => a);\n")
    assert h.taint_roots == frozenset({"a", "renamed"})


def test_r2_zero_parameter_handler_with_a_schema_has_no_roots():
    h = _one('server.registerTool("t", { inputSchema: { a: z.string() } },\n'
             "  async () => ({ content: [] }));\n")
    assert h.args_are_param0 is True
    assert h.taint_roots == frozenset()


# ==========================================================================
# S1/S2/S3 — registerTool(name, config, handler)
# ==========================================================================
def test_registerTool_reads_name_style_schema_and_line():
    src = _src('server.registerTool(\n'
               '  "search",\n'
               "  { title: \"Search\", inputSchema: { q: z.string() } },\n"
               "  async ({ q }) => q,\n"
               ");\n")
    hs = tstools.find_tool_handlers(src)
    assert len(hs) == 1
    h = hs[0]
    assert h.tool_name == "search"
    assert h.display_name == "search"
    assert h.style == "registerTool"
    assert h.schema_known is True
    assert h.schema_span is not None
    assert src.code(h.schema_span).strip() == "{ q: z.string() }"
    assert h.reg_line == 3
    assert h.path == Path("server.ts")


def test_registerTool_trailing_comma_does_not_become_the_handler():
    """Rule R1: `split_args` yields a trailing empty span for a trailing
    comma, and the handler is the last NON-EMPTY argument."""
    h = _one('server.registerTool("t", { inputSchema: { a: z.string() } },\n'
             "  async ({ a }) => a,\n"
             ");\n")
    assert h.taint_roots == frozenset({"a"})


def test_registerTool_name_resolved_through_a_const():
    h = _one('const NAME = "search";\n'
             'server.registerTool(NAME, { inputSchema: { q: z.string() } },\n'
             "  async ({ q }) => q);\n")
    assert h.tool_name == "search"


def test_computed_name_is_anonymous_not_a_guess():
    h = _one("server.registerTool(tool.name,\n"
             "  { inputSchema: { q: z.string() } }, async ({ q }) => q);\n")
    assert h.tool_name == ""
    assert h.display_name == "<anonymous>"


def test_handler_given_as_a_resolvable_identifier():
    for decl in ("const impl = async ({ a }) => a;",
                 "async function impl({ a }) { return a; }"):
        body = (decl + "\n"
                'server.registerTool("t", { inputSchema: { a: z.string() } },'
                " impl);\n")
        h = _one(body)
        assert h.taint_roots == frozenset({"a"}), decl


def test_factory_call_handler_is_suppressed_entirely():
    """`makeHandler(deps)`'s parameters live wherever makeHandler is
    defined — quite possibly in another file. Guessing is how v0.3
    happened."""
    assert _handlers(
        'server.registerTool("t", { inputSchema: { a: z.string() } },\n'
        "  makeHandler(deps));\n") == []


def test_member_expression_handler_is_suppressed_entirely():
    assert _handlers(
        'server.registerTool("t", { inputSchema: { a: z.string() } },\n'
        "  handlers.doThing);\n") == []


def test_cross_file_identifier_handler_is_suppressed_entirely():
    """`impl` is imported, so there is nothing in this file to resolve."""
    assert _handlers(
        'import { impl } from "./impl.js";\n'
        'server.registerTool("t", { inputSchema: { a: z.string() } }, impl);\n'
    ) == []


def test_unparseable_parameters_suppress_the_handler():
    """Array destructuring sets FunctionBody.params_ok False, and a
    handler whose parameters we cannot enumerate has no usable taint
    roots."""
    assert _handlers(
        'server.registerTool("t", { inputSchema: { a: z.string() } },\n'
        "  async ([a, b]) => a);\n") == []


def test_identifier_config_leaves_schema_presence_unknown():
    """`registerTool(name, CONFIG, cb)`. Saying 'this tool declares no
    input schema' about it would be a false claim about correct code."""
    h = _one('const CONFIG = { title: "T", inputSchema: { q: z.string() } };\n'
             'server.registerTool("opaque", CONFIG, async ({ q }) => q);\n')
    assert h.schema_known is False
    assert h.schema_span is None
    assert h.taint_roots == frozenset()


def test_spread_config_leaves_schema_presence_unknown():
    h = _one('const CONFIG = { inputSchema: { q: z.string() } };\n'
             'server.registerTool("spread", { ...CONFIG, title: "S" },\n'
             "  async ({ q }) => q);\n")
    assert h.schema_known is False


def test_s11_createTask_object_handler():
    """`registerTool(name, config, { createTask: async (args) => … })`.
    Two occurrences corpus-wide."""
    h = _one('server.registerTool("t", { inputSchema: { a: z.string() } },\n'
             "  { createTask: async ({ a }) => a });\n")
    assert h.taint_roots == frozenset({"a"})


def test_plain_object_handler_without_createTask_is_suppressed():
    assert _handlers(
        'server.registerTool("t", { inputSchema: { a: z.string() } },\n'
        "  { title: \"not a handler\" });\n") == []


# ==========================================================================
# S4 — the deprecated tool() overload ladder
# ==========================================================================
def test_ladder_name_and_callback_only():
    h = _one('server.tool("ping", async () => ({ content: [] }));\n')
    assert h.style == "tool"
    assert h.schema_span is None
    assert h.taint_roots == frozenset()


def test_ladder_name_raw_shape_callback():
    h = _one('server.tool("run", { cmd: z.string() }, async ({ cmd }) => cmd);\n')
    assert h.args_are_param0 is True
    assert h.taint_roots == frozenset({"cmd"})


def test_ladder_name_description_raw_shape_callback():
    h = _one('server.tool("run", "Run a command", { cmd: z.string() },\n'
             "  async ({ cmd }) => cmd);\n")
    assert h.taint_roots == frozenset({"cmd"})


def test_ladder_name_description_raw_shape_annotations_callback():
    """exa-mcp-server's agent_run shape, with an inline raw shape. The
    annotations object must not be mistaken for the schema."""
    src = _src('server.tool("agent_run", "Start a run", { query: z.string() },\n'
               "  { readOnlyHint: true, destructiveHint: false },\n"
               "  async ({ query }, extra) => query);\n")
    hs = tstools.find_tool_handlers(src)
    assert len(hs) == 1
    assert hs[0].taint_roots == frozenset({"query"})
    assert src.code(hs[0].schema_span).strip() == "{ query: z.string() }"


def test_ladder_annotations_only_is_not_a_schema():
    """`tool(name, annotations, cb)` is a real overload. Every
    ToolAnnotations value is a primitive, which is exactly what separates
    it from a raw shape."""
    h = _one('server.tool("t", { readOnlyHint: true, title: "T" },\n'
             "  async (extra) => extra);\n")
    assert h.schema_span is None
    assert h.taint_roots == frozenset()


def test_ladder_empty_object_is_a_raw_shape():
    """isZodRawShapeCompat({}) is true: the SDK then passes the callback an
    empty arguments object, so parameter 0 is still arguments."""
    h = _one('server.tool("t", "desc", {}, async (args) => args);\n')
    assert h.args_are_param0 is True
    assert h.taint_roots == frozenset({"args"})


def test_ladder_zod_object_is_not_a_raw_shape():
    """SDK parity, not cleverness: isZodRawShapeCompat rejects a ZodObject,
    the argument is treated as annotations, and the callback really does
    receive `extra` in parameter 0 at runtime."""
    h = _one('server.tool("t", "desc", z.object({ a: z.string() }),\n'
             "  async (extra) => extra);\n")
    assert h.schema_span is None
    assert h.taint_roots == frozenset()


def test_ladder_unresolvable_shape_identifier_declares_no_schema():
    """exa-mcp-server passes its raw shape by name from another module.
    We cannot see it, so we assert nothing — a deliberate false negative,
    and the input-validation check refuses to claim 'no schema' for the
    ladder because of exactly this case."""
    h = _one('import { shape } from "./shapes.js";\n'
             'server.tool("t", "desc", shape, { readOnlyHint: true },\n'
             "  async ({ q }) => q);\n")
    assert h.schema_span is None
    assert h.taint_roots == frozenset()


def test_ladder_shape_field_resolved_through_a_local_const():
    """`{ cmd: CmdSchema }` where `const CmdSchema = z.string()`. The
    schema-like test follows one binding hop, so arktype and valibot
    schemas assigned to a const also work."""
    h = _one("const CmdSchema = z.string();\n"
             'server.tool("run", "desc", { cmd: CmdSchema },\n'
             "  async ({ cmd }) => cmd);\n")
    assert h.taint_roots == frozenset({"cmd"})


def test_ladder_addTool_positional_form():
    h = _one('server.addTool("run", "desc", { cmd: z.string() },\n'
             "  async ({ cmd }) => cmd);\n")
    assert h.style == "addTool"
    assert h.taint_roots == frozenset({"cmd"})


# ==========================================================================
# S9/S10 — descriptor objects
# ==========================================================================
FASTMCP_IMPORT = 'import { FastMCP } from "fastmcp";\nimport { z } from "zod";\n'


def test_fastmcp_addTool_descriptor():
    src = _src("mcp.addTool({\n"
               '  name: "grep",\n'
               '  description: "Search files",\n'
               "  parameters: z.object({ pattern: z.string() }),\n"
               "  execute: async (args) => String(args.pattern),\n"
               "});\n", prelude=FASTMCP_IMPORT)
    hs = tstools.find_tool_handlers(src)
    assert len(hs) == 1
    h = hs[0]
    assert h.tool_name == "grep"
    assert h.style == "addTool"
    assert h.args_are_param0 is True
    assert h.taint_roots == frozenset({"args"})
    assert src.code(h.schema_span).strip().startswith("z.object(")


def test_descriptor_keys_may_appear_in_any_order():
    """fastmcp's own sources sort keys alphabetically, so `execute`
    precedes `name`. Nothing here may depend on position."""
    h = _one("mcp.addTool({\n"
             "  execute: async (args) => args.pattern,\n"
             "  parameters: z.object({ pattern: z.string() }),\n"
             '  name: "grep",\n'
             "});\n", prelude=FASTMCP_IMPORT)
    assert h.tool_name == "grep"
    assert h.taint_roots == frozenset({"args"})


def test_descriptor_method_shorthand_handler():
    h = _one("mcp.addTool({\n"
             '  name: "grep",\n'
             "  inputSchema: { pattern: z.string() },\n"
             "  async handler({ pattern }) { return pattern; },\n"
             "});\n", prelude=FASTMCP_IMPORT)
    assert h.taint_roots == frozenset({"pattern"})


def test_defineTool_is_accepted_bare():
    """Unlike `tool`, `defineTool` is normally a bare imported function, so
    Gate 1 does not apply to it."""
    h = _one('import { defineTool } from "@modelcontextprotocol/sdk/x.js";\n'
             'export const t = defineTool({\n'
             '  name: "read",\n'
             "  inputSchema: { path: z.string() },\n"
             "  handler: async ({ path }) => path,\n"
             "});\n", prelude="")
    assert h.style == "defineTool"
    assert h.tool_name == "read"
    assert h.taint_roots == frozenset({"path"})


def test_descriptor_without_a_schema_has_no_taint_roots():
    h = _one("mcp.addTool({\n"
             '  name: "ping",\n'
             "  execute: async (ctx) => \"pong\",\n"
             "});\n", prelude=FASTMCP_IMPORT)
    assert h.args_are_param0 is False
    assert h.taint_roots == frozenset()


def test_descriptor_without_a_handler_key_is_not_a_tool():
    assert _handlers('mcp.addTool({ name: "x", inputSchema: { a: z.string() } });\n',
                     prelude=FASTMCP_IMPORT) == []


def test_options_bag_without_a_name_or_schema_is_not_a_tool():
    """A `run` callback alone must not make an options object a tool."""
    assert _handlers("mcp.addTool({ retries: 3, run: async (x) => x });\n",
                     prelude=FASTMCP_IMPORT) == []


def test_registerTool_never_takes_the_single_object_form():
    """`style == 'registerTool'` is the one style the input-validation
    check trusts for a confident negative, so nothing else may claim it."""
    assert _handlers(
        'server.registerTool({ name: "x", inputSchema: { a: z.string() },\n'
        "  handler: async ({ a }) => a });\n") == []


# ==========================================================================
# S5/S6 — low-level setRequestHandler dispatch
# ==========================================================================
LOWLEVEL_IMPORT = (
    'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n'
    "import { CallToolRequestSchema, ListToolsRequestSchema }\n"
    '  from "@modelcontextprotocol/sdk/types.js";\n'
)


def _lowlevel(body: str) -> tstools.ToolHandler:
    return _one(body, prelude=LOWLEVEL_IMPORT)


def test_lowlevel_destructuring_idiom():
    h = _lowlevel(
        "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
        "  const { name, arguments: args } = request.params;\n"
        "  return run(name, args);\n"
        "});\n")
    assert h.style == "lowlevel"
    assert h.tool_name == ""
    assert h.display_name == "<anonymous>"
    assert h.args_are_param0 is False
    assert "request" in h.taint_roots
    assert "args" in h.taint_roots


def test_lowlevel_destructuring_with_a_default():
    h = _lowlevel(
        "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
        "  const { name, arguments: args = {} } = request.params;\n"
        "  return run(name, args);\n"
        "});\n")
    assert "args" in h.taint_roots


def test_lowlevel_direct_member_chain_with_coalesce_and_cast():
    for init in ("request.params.arguments",
                 "request.params.arguments ?? {}",
                 "request.params.arguments as ToolArgs",
                 "request.params.arguments as unknown as ToolArgs",
                 "request.params.arguments?.path as string"):
        h = _lowlevel(
            "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
            f"  const bag = {init};\n"
            "  return run(bag);\n"
            "});\n")
        assert "bag" in h.taint_roots, init


def test_lowlevel_member_chain_split_across_lines():
    """slack/index.ts:421-423 splits `request.params` over a newline.
    Matching the masked text with `\\s*` between segments makes it free."""
    h = _lowlevel(
        "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
        "  const { name, arguments: args } = request\n"
        "    .params;\n"
        "  return run(name, args);\n"
        "});\n")
    assert "args" in h.taint_roots


def test_lowlevel_request_itself_is_always_a_root():
    """A bare `request.params.arguments.path` use — 41 occurrences in the
    corpus — is then covered by expr_is_tainted on the receiver chain."""
    h = _lowlevel(
        "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
        "  return run(request.params.arguments.path);\n"
        "});\n")
    assert h.taint_roots == frozenset({"request"})


def test_lowlevel_string_method_name_is_accepted():
    h = _lowlevel(
        "server.setRequestHandler('tools/call', async (request) => {\n"
        "  return run(request.params.arguments);\n"
        "});\n")
    assert h.style == "lowlevel"


def test_lowlevel_namespaced_schema_identifier_is_accepted():
    h = _lowlevel(
        "server.setRequestHandler(types.CallToolRequestSchema, async (req) => {\n"
        "  return run(req.params.arguments);\n"
        "});\n")
    assert "req" in h.taint_roots


def test_lowlevel_other_schemas_are_skipped():
    """One gate handles tools/list catalogues, resource subscriptions and
    sampling callbacks at once."""
    for arg in ("ListToolsRequestSchema", "'tools/list'",
                "SubscribeRequestSchema", "'sampling/createMessage'",
                "CustomSchema"):
        body = (f"server.setRequestHandler({arg}, async (request) => {{\n"
                "  return build(request.params.arguments);\n"
                "});\n")
        assert _handlers(body, prelude=LOWLEVEL_IMPORT) == [], arg


def test_lowlevel_wrapped_handler_is_unwrapped():
    """mcp-playwright registers through two wrappers. find_functions
    returns outermost first; the `.params` dereference identifies the one
    that actually receives the request."""
    h = _lowlevel(
        "server.setRequestHandler(CallToolRequestSchema,\n"
        "  wrapHandler('CallTool', withMonitoring(async (request) => {\n"
        "    const { arguments: args } = request.params;\n"
        "    return run(args);\n"
        "  })));\n")
    assert "args" in h.taint_roots


def test_lowlevel_handler_that_never_touches_params_is_skipped():
    assert _handlers(
        "server.setRequestHandler(CallToolRequestSchema, async (request) => {\n"
        "  return { content: [] };\n"
        "});\n", prelude=LOWLEVEL_IMPORT) == []


def test_lowlevel_destructured_request_parameter_is_declined():
    """`async ({ params }) => …` leaves the request with no name to anchor
    the S8 idioms to. Documented deliberate false negative."""
    assert _handlers(
        "server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {\n"
        "  return run(params.arguments);\n"
        "});\n", prelude=LOWLEVEL_IMPORT) == []


# ==========================================================================
# case_label_at
# ==========================================================================
def test_case_label_at_finds_the_nearest_preceding_label():
    text = (
        "function f(request) {\n"
        "  switch (name) {\n"
        '    case "alpha": {\n'
        "      alpha();\n"
        "      break;\n"
        "    }\n"
        '    case "beta": {\n'
        "      beta();\n"
        "      break;\n"
        "    }\n"
        "  }\n"
        "}\n"
    )
    src = jsparse.scan(text, Path("x.ts"))
    body = jsparse.Span(0, len(text))
    assert tstools.case_label_at(src, body, text.index("alpha();")) == "alpha"
    assert tstools.case_label_at(src, body, text.index("beta();")) == "beta"
    assert tstools.case_label_at(src, body, 0) == ""


def test_case_label_at_ignores_the_word_case_inside_a_string():
    text = 'const doc = "case \\"fake\\":"; real();\n'
    src = jsparse.scan(text, Path("x.ts"))
    body = jsparse.Span(0, len(text))
    assert tstools.case_label_at(src, body, text.index("real()")) == ""


# ==========================================================================
# propagate_taint
# ==========================================================================
def _body_span(text: str) -> tuple[jsparse.Source, jsparse.Span]:
    src = jsparse.scan(text, Path("x.ts"))
    return src, jsparse.Span(0, len(text))


def test_propagate_taint_through_a_const():
    src, body = _body_span("const line = `git ${args.cmd}`;\n")
    assert "line" in tstools.propagate_taint(src, body, {"args"})


def test_propagate_taint_through_destructuring():
    src, body = _body_span("const { name, arguments: bag } = request.params;\n")
    got = tstools.propagate_taint(src, body, {"request"})
    assert {"name", "bag"} <= got


def test_propagate_taint_through_array_destructuring():
    src, body = _body_span("const [head, tail] = args.parts;\n")
    assert {"head", "tail"} <= tstools.propagate_taint(src, body, {"args"})


def test_propagate_taint_through_reassignment_and_augmented_assignment():
    src, body = _body_span("let cmd = 'ls';\ncmd = args.cmd;\ncmd += args.extra;\n")
    assert "cmd" in tstools.propagate_taint(src, body, {"args"})


def test_propagate_taint_strips_a_type_annotation_from_the_target():
    src, body = _body_span("const line: string = args.cmd;\n")
    assert "line" in tstools.propagate_taint(src, body, {"args"})


def test_propagate_taint_is_two_pass_for_a_forward_reference():
    src, body = _body_span("const second = first;\nconst first = args.cmd;\n")
    got = tstools.propagate_taint(src, body, {"args"})
    assert {"first", "second"} <= got


def test_propagate_taint_does_not_spread_to_untainted_locals():
    src, body = _body_span("const base = '/tmp';\nconst other = BASE_DIR;\n")
    assert tstools.propagate_taint(src, body, {"args"}) == {"args"}


def test_parse_does_not_launder_taint():
    """`Schema.parse(request.params.arguments)` validates the SHAPE. Every
    string value inside it is still attacker-chosen."""
    src, body = _body_span("const parsed = ForkSchema.parse(request.params.arguments);\n")
    assert "parsed" in tstools.propagate_taint(src, body, {"request"})
    src, body = _body_span("const parsed = ForkSchema.safeParse(args);\n")
    assert "parsed" in tstools.propagate_taint(src, body, {"args"})


def test_propagate_taint_ignores_strings_and_comments():
    src, body = _body_span(
        '// const evil = args.cmd;\n'
        'const doc = "const other = args.cmd";\n')
    assert tstools.propagate_taint(src, body, {"args"}) == {"args"}


def test_propagate_taint_does_not_treat_an_arrow_parameter_as_an_assignment():
    src, body = _body_span("items.map(x => args.cmd);\n")
    assert "x" not in tstools.propagate_taint(src, body, {"args"})


def test_propagate_taint_leaves_a_multi_declarator_sibling_alone():
    src, body = _body_span("const a = args.cmd, b = 'safe';\n")
    got = tstools.propagate_taint(src, body, {"args"})
    assert "a" in got and "b" not in got


# ==========================================================================
# expr_is_tainted
# ==========================================================================
def test_expr_is_tainted_on_a_property_access_of_a_tainted_root():
    src, body = _body_span("args.path\n")
    assert tstools.expr_is_tainted(src, body, {"args"})


def test_expr_is_tainted_ignores_a_matching_property_name():
    """`foo.args` is not a use of a local called `args`."""
    src, body = _body_span("foo.args\n")
    assert not tstools.expr_is_tainted(src, body, {"args"})


def test_expr_is_tainted_ignores_object_literal_key_position():
    src, body = _body_span("{ path: BASE }\n")
    assert not tstools.expr_is_tainted(src, body, {"path"})


def test_expr_is_tainted_sees_a_template_hole():
    src, body = _body_span("`git ${cmd}`\n")
    assert tstools.expr_is_tainted(src, body, {"cmd"})


def test_expr_is_tainted_does_not_see_string_contents():
    src, body = _body_span('"git cmd here"\n')
    assert not tstools.expr_is_tainted(src, body, {"cmd"})


def test_expr_is_tainted_with_no_taint_is_false():
    src, body = _body_span("args.path\n")
    assert not tstools.expr_is_tainted(src, body, set())
    assert not tstools.expr_is_tainted(src, body, {""})


# ==========================================================================
# ordering / determinism
# ==========================================================================
def test_handlers_are_returned_in_source_order_and_deduplicated():
    body = (
        'server.registerTool("a", { inputSchema: { x: z.string() } },\n'
        "  async ({ x }) => x);\n"
        'server.tool("b", "desc", { y: z.string() }, async ({ y }) => y);\n'
        "mcp.addTool({ name: \"c\", parameters: z.object({ z: z.string() }),\n"
        "  execute: async (args) => args });\n"
    )
    names = [h.display_name for h in _handlers(body)]
    assert names == ["a", "b", "c"]
    assert [h.display_name for h in _handlers(body)] == names


def test_every_handler_carries_a_positive_registration_line():
    body = (
        'server.registerTool("a", { inputSchema: { x: z.string() } },\n'
        "  async ({ x }) => x);\n"
    )
    for h in _handlers(body):
        assert h.reg_line > 0
        assert h.fn.body_span.end > h.fn.body_span.start
        assert isinstance(h.taint_roots, frozenset)
