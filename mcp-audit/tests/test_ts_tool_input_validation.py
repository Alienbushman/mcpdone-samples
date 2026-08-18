"""Tests for the ts_tool_input_validation check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.ts_tool_input_validation import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _findings(name: str):
    return check(FIXTURES / name)


# ---------------------------------------------------------------- fire cases

def test_bad_fixture_flags_every_intentional_case():
    findings = _findings("ts_tool_input_validation_bad")
    # 3 intentional cases: search/query LOOSE_STRING, blob/payload LOOSE_ANY,
    # raw ANY_PARAM.
    assert len(findings) == 3, [f.message for f in findings]
    assert all(f.severity == Severity.LOW for f in findings)
    joined = " ".join(f.message for f in findings)
    for name in ("search", "blob", "raw"):
        assert f"tool '{name}'" in joined, f"missing finding for {name}"


def test_loose_string_field_is_flagged():
    findings = [f for f in _findings("ts_tool_input_validation_bad")
                if "'query'" in f.message]
    assert len(findings) == 1, [f.message for f in findings]
    assert "z.string()" in findings[0].message
    assert "no length, pattern, or format constraint" in findings[0].message


def test_loose_any_field_is_flagged():
    findings = [f for f in _findings("ts_tool_input_validation_bad")
                if "'payload'" in f.message]
    assert len(findings) == 1, [f.message for f in findings]
    assert "validates nothing" in findings[0].message


def test_any_typed_handler_parameter_is_flagged():
    findings = [f for f in _findings("ts_tool_input_validation_bad")
                if "typed `any`" in f.message]
    assert len(findings) == 1, [f.message for f in findings]
    assert "tool 'raw'" in findings[0].message


def test_schemaless_handler_destructuring_real_fields_is_flagged():
    """No inputSchema + a handler destructuring `{ path, content }` is a real
    bug: the SDK calls handler(extra), so both bindings are undefined."""
    findings = _findings("ts_tool_input_validation_undeclared")
    assert len(findings) == 1, [f.message for f in findings]
    f = findings[0]
    assert "tool 'write'" in f.message
    assert "undefined" in f.message
    assert "`path`" in f.message and "`content`" in f.message
    assert f.severity == Severity.LOW


def test_describe_alone_does_not_suppress():
    """`.describe()` documents a field for the model; it applies no length,
    pattern, or format rule, so an unconstrained string stays unconstrained."""
    findings = _findings("ts_tool_input_validation_describe")
    assert len(findings) == 1, [f.message for f in findings]
    assert "'query'" in findings[0].message


def test_deprecated_tool_overload_raw_shape_is_read_as_a_schema():
    """tool(name, description, rawShape, cb) puts the schema in argument 2;
    fastmcp's addTool puts it under `parameters` as a z.object(...) wrapper."""
    findings = _findings("ts_tool_input_validation_variants")
    assert len(findings) == 2, [f.message for f in findings]
    joined = " ".join(f.message for f in findings)
    assert "'cmd'" in joined
    assert "'pattern'" in joined


# ------------------------------------------------------------ suppress cases

def test_constrained_fixture_flags_nothing():
    """Realistic, correct code: every string carries a bound / pattern /
    format, every other field uses a closed constructor."""
    findings = _findings("ts_tool_input_validation_good")
    assert findings == [], [f.message for f in findings]


def test_schemaless_no_arg_tool_flags_nothing():
    """An absent inputSchema is the CORRECT encoding of a zero-argument tool
    (RECON A rule R2; browser-tools-mcp/mcp-server.ts:178 is this shape). A
    handler destructuring only server-context props is equally correct."""
    findings = _findings("ts_tool_input_validation_noschema")
    assert findings == [], [f.message for f in findings]


def test_unclassifiable_schemas_flag_nothing():
    """zodToJsonSchema output, hand-written JSON Schema, arktype/valibot
    fields, an identifier config, a spread config, and low-level dispatch are
    all suppressed rather than guessed at."""
    findings = _findings("ts_tool_input_validation_unresolvable")
    assert findings == [], [f.message for f in findings]


def test_handler_typing_shapes_from_the_corpus_flag_nothing():
    """Regression pack for the three false positives found in the 2026-08
    corpus smoke run: `args: unknown` with a real schema (firecrawl, x26), an
    ignored `_args` parameter and a schema declared by reference (neon), and
    the deprecated ladder passing its raw shape by name (exa agent_run)."""
    findings = _findings("ts_tool_input_validation_handler_types")
    assert findings == [], [f.message for f in findings]


def test_unknown_typed_parameter_is_not_flagged():
    """`unknown` forces a narrowing at every use; only `any` silently
    disables checking. Documented deliberate false negative."""
    findings = [f for f in _findings("ts_tool_input_validation_handler_types")
                if "typed `any`" in f.message]
    assert findings == [], [f.message for f in findings]


def test_non_mcp_registry_calls_flag_nothing():
    """`registry.registerTool(...)` in a file with no MCP import belongs to
    some other plugin framework — its schemas are not ours to judge."""
    findings = _findings("ts_tool_input_validation_notmcp")
    assert findings == [], [f.message for f in findings]


def test_lexing_traps_flag_nothing():
    """Unconstrained schemas that live inside a comment, a string literal, a
    template literal, or a regex containing a quote and a slash. A finding
    here means the check is matching raw text instead of the mask."""
    findings = _findings("ts_tool_input_validation_lextrap")
    assert findings == [], [f.message for f in findings]


def test_shared_noise_fixture_flags_nothing():
    """Every known false-positive trap from the corpus recon, in one place.
    Any finding here is a bug in this check, not in the fixture."""
    assert (FIXTURES / "ts_noise_common").is_dir(), (
        "the shared ts_noise_common fixture is missing; without it this test "
        "passes vacuously, because check() on an absent root returns []"
    )
    findings = _findings("ts_noise_common")
    assert findings == [], [f.message for f in findings]


def test_missing_root_is_not_an_error():
    """check() must never raise — the CLI has no try/except around it."""
    assert check(FIXTURES / "no_such_directory_at_all") == []


# ------------------------------------------------------- regression: v0.9 FPs
#
# These use tmp_path rather than a fixture directory: they are regressions for
# a specific defect, and keeping the offending source inline next to the
# assertion is what makes the test readable a year from now.

_PRELUDE = (
    'import { z } from "zod";\n'
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'const server = new McpServer({ name: "t", version: "1" });\n'
)


def _write(tmp_path: Path, body: str) -> Path:
    (tmp_path / "server.ts").write_text(_PRELUDE + body, encoding="utf-8")
    return tmp_path


def _register(fields: str, tool: str = "t") -> str:
    return (
        f'server.registerTool("{tool}", {{ title: "T", inputSchema: {{\n'
        f"{fields}\n"
        "} }, async (a: { [k: string]: unknown }) => ({ content: [] }));\n"
    )


def test_constrained_zod_idioms_outside_the_v3_core_do_not_fire(tmp_path):
    """REGRESSION. An earlier revision matched an allowlist of CONSTRAINT
    methods and called everything else loose. Each line below carries a real
    length / pattern / format constraint, and each one produced a finding
    claiming "no length, pattern, or format constraint" — 13 false positives
    on correct code, the exact class that forced the v0.3 retraction.

    `.nonempty()` is zod's own alias for `.min(1)`; `.check()` is the zod v4
    composable-check API; `.lowercase()` / `.uppercase()` are v4 case
    ASSERTIONS (not the `.toLowerCase()` transform); the rest are v4 string
    formats. The fix inverted the rule: only provably-transparent wrappers
    keep a chain reportable."""
    root = _write(tmp_path, _register(
        "  ne: z.string().nonempty(),\n"
        "  chk: z.string().check(z.maxLength(80)),\n"
        "  lc: z.string().lowercase(),\n"
        "  uc: z.string().uppercase(),\n"
        "  v4: z.string().ipv4(),\n"
        "  v6: z.string().ipv6(),\n"
        "  c4: z.string().cidrv4(),\n"
        "  c6: z.string().cidrv6(),\n"
        "  g: z.string().guid(),\n"
        "  phone: z.string().e164(),\n"
        "  b64u: z.string().base64url(),\n"
        "  host: z.string().hostname(),\n"
        "  hx: z.string().hex(),\n"
        "  hurl: z.string().httpUrl(),\n"
    ))
    assert check(root) == [], [f.message for f in check(root)]


def test_unrecognised_chain_method_suppresses(tmp_path):
    """Zod adds string formats every minor release. A method this file has
    never heard of must suppress, not fire — the list is allowed to go stale
    into false NEGATIVES only."""
    root = _write(tmp_path, _register(
        "  future: z.string().someFormatInventedNextYear(),\n"
        "  arr: z.string().array(),\n"
        "  either: z.string().or(z.number()),\n"
    ))
    assert check(root) == [], [f.message for f in check(root)]


def test_transparent_wrappers_do_not_suppress(tmp_path):
    """The other half of the same rule: `.describe()`, `.optional()`,
    `.nullable()`, `.default()`, `.catch()`, `.readonly()` and `.meta()`
    document or widen a field without constraining it, so a chain built only
    from them is still an unconstrained string."""
    root = _write(tmp_path, _register(
        '  a: z.string().describe("doc"),\n'
        "  b: z.string().optional().nullable().nullish(),\n"
        '  c: z.string().default("x").readonly(),\n'
        '  d: z.string().catch("y").meta({ note: 1 }),\n'
    ))
    findings = check(root)
    assert len(findings) == 4, [f.message for f in findings]
    joined = " ".join(f.message for f in findings)
    for name in ("a", "b", "c", "d"):
        assert f"field '{name}'" in joined


def test_zod_imported_under_an_alias_is_still_zod(tmp_path):
    """`import { z as zz }` and `import * as zod` both bind the zod namespace;
    the check must follow the local name, not the letter `z`."""
    (tmp_path / "server.ts").write_text(
        'import { z as zz } from "zod";\n'
        'import * as zod from "zod";\n'
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
        'const server = new McpServer({ name: "t", version: "1" });\n'
        'server.registerTool("aliased", { title: "T", inputSchema: {\n'
        "  named: zz.string(),\n"
        "  ns: zod.string(),\n"
        "} }, async (a: { [k: string]: unknown }) => ({ content: [] }));\n",
        encoding="utf-8")
    findings = check(tmp_path)
    assert len(findings) == 2, [f.message for f in findings]


def test_bom_and_crlf_do_not_shift_the_reported_line(tmp_path):
    """A UTF-8 BOM and CRLF endings are both common in the wild. Neither may
    move the finding off the field's key line."""
    body = _PRELUDE + _register("  q: z.string(),")
    (tmp_path / "crlf.ts").write_text(body.replace("\n", "\r\n"), encoding="utf-8")
    (tmp_path / "bom.ts").write_text(body, encoding="utf-8-sig")
    findings = check(tmp_path)
    assert len(findings) == 2, [f.message for f in findings]
    for f in findings:
        text = f.path.read_text(encoding="utf-8-sig").splitlines()[f.line - 1]
        assert "q:" in text, (f.path.name, f.line, text)


def test_degraded_lex_emits_nothing(tmp_path):
    """Unbalanced braces / an unterminated template make Source.ok False. A
    file we could not lex must produce no findings at all."""
    (tmp_path / "broken.ts").write_text(
        _PRELUDE
        + "function broken() { if (true) { \n"
        + _register("  q: z.string(),"),
        encoding="utf-8")
    (tmp_path / "untermtpl.ts").write_text(
        _PRELUDE + "const t = `never closed\n" + _register("  q: z.string(),"),
        encoding="utf-8")
    assert check(tmp_path) == [], [f.message for f in check(tmp_path)]


def test_schema_key_spellings_are_not_read_as_absent(tmp_path):
    """REGRESSION guard for UNDECLARED_INPUT, the one kind that asserts a
    runtime bug. A quoted key, a shorthand key, and a by-reference schema all
    mean "a schema is present" — claiming otherwise would tell an author their
    working tool is broken."""
    (tmp_path / "server.ts").write_text(
        _PRELUDE
        + "const inputSchema = { q: z.string().min(1) };\n"
        + "const shared = { q: z.string().min(1) };\n"
        + 'server.registerTool("quoted", { title: "T", "inputSchema": '
          "{ q: z.string().min(1) } }, async ({ q }) => ({ content: [] }));\n"
        + 'server.registerTool("shorthand", { title: "T", inputSchema }, '
          "async ({ q }) => ({ content: [] }));\n"
        + 'server.registerTool("byref", { title: "T", inputSchema: shared }, '
          "async ({ q }) => ({ content: [] }));\n"
        + 'server.registerTool("spread", { ...{ title: "T" } }, '
          "async ({ q }) => ({ content: [] }));\n",
        encoding="utf-8")
    assert check(tmp_path) == [], [f.message for f in check(tmp_path)]


# ---------------------------------------------------------------- invariants

def test_every_finding_has_line_and_remediation():
    findings = (_findings("ts_tool_input_validation_bad")
                + _findings("ts_tool_input_validation_undeclared")
                + _findings("ts_tool_input_validation_variants"))
    assert findings
    for f in findings:
        assert f.line is not None and f.line > 0, f.message
        assert f.severity == Severity.LOW
        assert f.check == "ts_tool_input_validation"
        assert isinstance(f.path, Path)
        # Remediation must match the kind. UNDECLARED_INPUT is a correctness
        # bug and gets "declare the arguments"; the LOOSE_* kinds get the
        # "tighten the constraint" advice.
        if "passes no `inputSchema`" in f.message:
            assert "inputSchema" in f.remediation
            assert "undefined" in f.remediation
        else:
            assert "z.enum" in f.remediation


def test_findings_are_deterministic():
    """Output must be byte-identical run to run (no unsorted set iteration)."""
    a = [(str(f.path), f.line, f.message) for f in _findings("ts_tool_input_validation_bad")]
    b = [(str(f.path), f.line, f.message) for f in _findings("ts_tool_input_validation_bad")]
    assert a == b
