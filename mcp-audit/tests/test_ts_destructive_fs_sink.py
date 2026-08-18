"""Tests for the ts_destructive_fs_sink check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.ts_destructive_fs_sink import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------
# fire conditions
# --------------------------------------------------------------------------
def test_bad_fixture_flags_every_intentional_case():
    findings = check(FIXTURES / "ts_destructive_fs_bad")
    # 3 intentional bad tools: cleanup, deleteFile, purge
    assert len(findings) == 3, [f.message for f in findings]
    assert all(f.severity == Severity.MEDIUM for f in findings)
    tools = " ".join(f.message for f in findings)
    for name in ("cleanup", "deleteFile", "purge"):
        assert name in tools, f"missing finding for {name}"


def test_fs_promises_member_chain_is_a_sink():
    """`fs.promises.rm(dir, { recursive: true })` off a default `node:fs`
    import — the manim shape, transliterated."""
    findings = check(FIXTURES / "ts_destructive_fs_bad")
    hits = [f for f in findings if "cleanup" in f.message]
    assert len(hits) == 1, [f.message for f in findings]
    assert "fs.promises.rm" in hits[0].message


def test_property_read_off_the_args_root_is_tainted():
    """`async (args) => fsp.unlink(args.target)` — the single most common
    real shape: the handler takes the whole args object, not a pattern."""
    findings = check(FIXTURES / "ts_destructive_fs_bad")
    assert [f for f in findings if "deleteFile" in f.message]


def test_taint_propagates_through_a_local_declaration():
    """`const victim = target; await rimraf(victim);` must still flag."""
    findings = check(FIXTURES / "ts_destructive_fs_bad")
    hits = [f for f in findings if "purge" in f.message]
    assert len(hits) == 1, [f.message for f in findings]
    assert "rimraf" in hits[0].message


def test_sync_fs_extra_and_del_package_sinks_all_flag():
    findings = check(FIXTURES / "ts_destructive_fs_extra")
    # 4 intentional bad tools: wipeSync, dropDir, emptyOut, nuke
    assert len(findings) == 4, [f.message for f in findings]
    tools = " ".join(f.message for f in findings)
    for name in ("wipeSync", "dropDir", "emptyOut", "nuke"):
        assert name in tools, f"missing finding for {name}"
    labels = " ".join(f.message for f in findings)
    assert "fs-extra" in labels
    assert "rimraf` / `del" in labels


def test_lowlevel_call_tool_handler_flags_and_names_the_case():
    """A `setRequestHandler(CallToolRequestSchema, …)` dispatch: taint starts
    at the request object and reaches `toolArgs` via the destructuring of
    `request.params`. The tool name comes from the enclosing `case` label."""
    findings = check(FIXTURES / "ts_destructive_fs_lowlevel")
    assert len(findings) == 1, [f.message for f in findings]
    assert "remove_file" in findings[0].message


# --------------------------------------------------------------------------
# suppress conditions
# --------------------------------------------------------------------------
def test_guarded_fixture_flags_nothing():
    """The mitigation IS present: path.resolve + path.relative confinement,
    a realpath + startsWith check, and an allow-set membership test."""
    findings = check(FIXTURES / "ts_destructive_fs_guarded")
    assert findings == [], [f.message for f in findings]


def test_safe_fixture_flags_nothing():
    """The dangerous pattern is NOT present: every delete target is a
    module-level constant the server owns."""
    findings = check(FIXTURES / "ts_destructive_fs_safe")
    assert findings == [], [f.message for f in findings]


def test_local_variable_named_fs_is_not_a_node_fs_sink():
    """`fileSystem.rm(key)` / `cache.remove(key)` with no fs import anywhere.
    `rm`, `remove`, and `unlink` are ordinary method names; without an import
    record nothing may resolve to a sink."""
    findings = check(FIXTURES / "ts_destructive_fs_localfs")
    assert findings == [], [f.message for f in findings]


def test_no_schema_handler_param0_is_not_tainted():
    """Rule R2. With no inputSchema the SDK calls `handler(extra)`, so
    parameter 0 is the server context. Also covers a zero-parameter handler,
    an unresolvable config identifier, and a factory-call handler."""
    findings = check(FIXTURES / "ts_destructive_fs_noschema")
    assert findings == [], [f.message for f in findings]


def test_list_tools_handler_is_not_a_tool_call_handler():
    """`setRequestHandler(ListToolsRequestSchema, …)` deletes a path derived
    from `request.params.cursor`, but that request carries no tool arguments
    — the argument-0 gate must drop it. Only the CallTool case is reported."""
    findings = check(FIXTURES / "ts_destructive_fs_lowlevel")
    assert len(findings) == 1, [f.message for f in findings]
    assert "cursor" not in findings[0].message


def test_redis_del_in_a_real_tool_handler_flags_nothing():
    """Reduced from servers-archived/src/redis/src/index.ts:192,202 — the only
    sink-NAMED call inside a tool handler in the whole 25-repo corpus.

    Every stage of the check runs here: the CallTool handler resolves, `key`
    is correctly tainted, and no containment guard is present. Only the import
    gate declines, because `redisClient` comes from the `redis` package. This
    test fails the moment someone relaxes sink resolution to textual matching.
    """
    findings = check(FIXTURES / "ts_destructive_fs_redis")
    assert findings == [], [f.message for f in findings]


def test_dangerous_text_in_comments_strings_and_regexes_flags_nothing():
    """A lexing trap: `fs.promises.rm(dir)` appears in a line comment, a
    block comment, a double-quoted string, template-literal text, and a
    regex body. None of it is code."""
    findings = check(FIXTURES / "ts_destructive_fs_strings")
    assert findings == [], [f.message for f in findings]


# --------------------------------------------------------------------------
# contract
# --------------------------------------------------------------------------
def test_every_finding_has_line_and_remediation():
    findings = check(FIXTURES / "ts_destructive_fs_bad")
    assert findings
    for f in findings:
        assert f.line is not None and f.line > 0
        assert "path.relative" in f.remediation or "realpath" in f.remediation
        assert f.check == "ts_destructive_fs_sink"
        assert isinstance(f.path, Path)


def test_line_numbers_point_at_the_sink_call():
    findings = check(FIXTURES / "ts_destructive_fs_bad")
    src = (FIXTURES / "ts_destructive_fs_bad" / "server.ts").read_text(encoding="utf-8")
    lines = src.splitlines()
    for f in findings:
        text = lines[f.line - 1]
        assert any(tok in text for tok in ("rm(", "unlink(", "rimraf(")), text


def test_check_is_deterministic_and_never_raises_on_a_missing_root():
    a = check(FIXTURES / "ts_destructive_fs_bad")
    b = check(FIXTURES / "ts_destructive_fs_bad")
    assert [(str(f.path), f.line, f.message) for f in a] == \
           [(str(f.path), f.line, f.message) for f in b]
    assert check(FIXTURES / "does_not_exist_at_all") == []


def test_python_only_repo_yields_nothing():
    """Pointed at the Python fixtures the TS engine must stay silent rather
    than error — it simply finds no analyzable TS/JS files."""
    assert check(FIXTURES / "destructive_fs_bad") == []


# --------------------------------------------------------------------------
# Regressions from the adversarial review. Each `QUIET` case below is
# hand-written CORRECT code that the check flagged before the fix; each
# `FIRE` case is the neighbouring true positive that must survive it. These
# use tmp_path rather than a fixtures/ directory so the snippet under test
# sits beside the assertion that explains it.
# --------------------------------------------------------------------------
HDR = """import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import fs from "node:fs/promises";
import nodePath from "node:path";
const server = new McpServer({ name: "s", version: "1" });
const BASE = "/srv/work";
"""


def _run(tmp_path, body: str, name: str = "server.ts"):
    (tmp_path / name).write_text(HDR + body, encoding="utf-8")
    return check(tmp_path)


# ---- FP class 1: a closed-set schema cannot express a path ---------------
def test_enum_only_schema_cannot_carry_a_traversal(tmp_path):
    """`{ which: z.enum(["logs","cache"]) }` admits exactly two values, so
    `path.join(BASE, args.which)` is confined by construction. Flagging this
    asserted "an attacker can delete arbitrary files", which is false."""
    assert _run(tmp_path, '''
server.registerTool("flush", { inputSchema: { which: z.enum(["logs", "cache"]) } },
  async (args) => { await fs.rm(nodePath.join(BASE, args.which), { recursive: true }); return { content: [] }; });
''') == []


def test_number_and_boolean_only_schema_is_not_a_path_vector(tmp_path):
    assert _run(tmp_path, '''
server.registerTool("prune", { inputSchema: { keep: z.number(), force: z.boolean() } },
  async (args) => { if (args.force) await fs.rm(nodePath.join(BASE, String(args.keep)), { recursive: true }); return { content: [] }; });
''') == []


def test_closed_set_inside_a_z_object_descriptor_is_seen_through(tmp_path):
    """fastmcp descriptors wrap the shape: `parameters: z.object({ … })`."""
    (tmp_path / "server.ts").write_text('''
import { FastMCP } from "fastmcp";
import fs from "node:fs/promises";
import nodePath from "node:path";
import { z } from "zod";
const server = new FastMCP({ name: "s", version: "1" });
const BASE = "/srv/work";
server.addTool({
  name: "flush",
  parameters: z.object({ which: z.enum(["logs", "cache"]) }),
  execute: async (args) => { await fs.rm(nodePath.join(BASE, args.which), { recursive: true }); return "ok"; },
});
''', encoding="utf-8")
    assert check(tmp_path) == []


def test_one_string_field_beside_an_enum_keeps_the_tool_live(tmp_path):
    """The suppression is all-or-nothing: any field that could be a path
    re-arms the whole handler."""
    assert len(_run(tmp_path, '''
server.registerTool("flush", { inputSchema: { mode: z.enum(["a","b"]), dir: z.string() } },
  async (args) => { await fs.rm(args.dir, { recursive: true }); return { content: [] }; });
''')) == 1


def test_an_unreadable_schema_is_never_treated_as_closed(tmp_path):
    """`inputSchema: Shape` cannot be inspected; unknown must mean fire."""
    assert len(_run(tmp_path, '''
const Shape = { dir: z.string() };
server.registerTool("cleanup", { inputSchema: Shape },
  async (args) => { await fs.rm(args.dir, { recursive: true }); return { content: [] }; });
''')) == 1


# ---- FP class 2: an opaque call's return value is not the parameter ------
def test_return_value_of_an_unknown_call_is_not_the_tool_parameter(tmp_path):
    """`runBuild` chose `tmpDir`; the tool parameter went in, but what came
    back is the callee's own value. "Do work in a scratch dir, then clean it
    up" is the most common filesystem shape an MCP server has."""
    assert _run(tmp_path, '''
server.registerTool("build", { inputSchema: { source: z.string() } },
  async (args) => {
    const result = await runBuild(args.source);
    await fs.rm(result.tmpDir, { recursive: true, force: true });
    return { content: [] };
  });
''') == []


def test_opaque_call_launders_through_destructuring_and_casts(tmp_path):
    assert _run(tmp_path, '''
server.registerTool("render", { inputSchema: { scene: z.string() } },
  async (args) => {
    const { workDir } = await renderScene(args.scene) as RenderOut;
    await fs.rm(workDir, { recursive: true });
    return { content: [] };
  });
''') == []


def test_lowlevel_dispatch_result_is_not_attacker_controlled(tmp_path):
    """The low-level handler seeds taint at the whole `request`, so every
    call taking the request used to taint its result."""
    (tmp_path / "server.ts").write_text('''
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import fs from "node:fs/promises";
const server = new Server({ name: "s", version: "1" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const result = await dispatch(request.params.name, request.params.arguments);
  await fs.rm(result.scratchDir, { recursive: true, force: true });
  return result.payload;
});
''', encoding="utf-8")
    assert check(tmp_path) == []


def test_path_arithmetic_still_propagates_and_still_fires(tmp_path):
    """The counterweight: `path.join` hands the parameter's own value back,
    so the laundering rule must not swallow the dominant true positive."""
    assert len(_run(tmp_path, '''
server.registerTool("cleanup", { inputSchema: { dir: z.string() } },
  async (args) => { const target = nodePath.join(BASE, args.dir); await fs.rm(target, { recursive: true }); return { content: [] }; });
''')) == 1


def test_zod_parse_does_not_launder(tmp_path):
    """`.parse()` returns the input it validated — a type check, not a path
    check. `servers-archived/src/redis` is written exactly this way."""
    assert len(_run(tmp_path, '''
const S = z.object({ dir: z.string() });
server.registerTool("cleanup", { inputSchema: { dir: z.string() } },
  async (args) => { const p = S.parse(args); await fs.rm(p.dir, { recursive: true }); return { content: [] }; });
''')) == 1


def test_string_concatenation_still_propagates(tmp_path):
    assert len(_run(tmp_path, '''
server.registerTool("cleanup", { inputSchema: { dir: z.string() } },
  async (args) => { const p = BASE + "/" + args.dir; await fs.rm(p, { recursive: true }); return { content: [] }; });
''')) == 1


# ---- FP class 3: containment helpers the guard vocabulary missed ---------
def test_named_containment_helpers_suppress(tmp_path):
    """`assertUnderRoot` / `resolveWorkspacePath` matched neither the exact
    token list nor the original substring list, so correct code was flagged."""
    assert _run(tmp_path, '''
server.registerTool("a", { inputSchema: { dir: z.string() } },
  async (args) => { assertUnderRoot(args.dir); await fs.rm(args.dir, { recursive: true }); return { content: [] }; });
''') == []
    assert _run(tmp_path, '''
server.registerTool("b", { inputSchema: { dir: z.string() } },
  async (args) => { const p = resolveWorkspacePath(args.dir); await fs.rm(p, { recursive: true }); return { content: [] }; });
''', name="other.ts") == []


def test_returning_content_does_not_self_suppress(tmp_path):
    """A near-miss worth pinning: "content" must not match the "contain"
    guard fragment, or every handler would suppress itself."""
    assert len(_run(tmp_path, '''
server.registerTool("cleanup", { inputSchema: { dir: z.string() } },
  async (args) => { await fs.rm(args.dir, { recursive: true }); return { content: [{ type: "text", text: "ok" }] }; });
''')) == 1


# ---- robustness ---------------------------------------------------------
def test_degraded_lexes_and_odd_bytes_never_fire_and_never_raise(tmp_path):
    """Unterminated constructs set Source.ok False and must yield nothing;
    invalid UTF-8 must not raise (jsparse reads with errors="replace")."""
    sink = ('server.registerTool("cleanup", { inputSchema: { dir: z.string() } },\n'
            '  async (args) => { await fs.rm(args.dir, { recursive: true }); return { content: [] }; });\n')
    for i, blob in enumerate([
        (HDR + "/* never closed\n" + sink).encode(),
        (HDR + "const t = `oops\n" + sink).encode(),
        (HDR + sink + 'const s = "no close').encode(),
        b"",
        b"\xef\xbb\xbf",
    ]):
        d = tmp_path / f"c{i}"
        d.mkdir()
        (d / "server.ts").write_bytes(blob)
        assert check(d) == [], blob[:40]

    # invalid UTF-8 in a comment, with a genuine sink after it
    d = tmp_path / "bytes"
    d.mkdir()
    (d / "server.ts").write_bytes(HDR.encode() + b"// caf\xe9 na\xefve \xff\xfe\n" + sink.encode())
    assert len(check(d)) == 1


def test_line_numbers_are_exact_under_crlf_and_bom(tmp_path):
    body = '''
server.registerTool("cleanup", { inputSchema: { dir: z.string() } },
  async (args) => { await fs.rm(args.dir, { recursive: true }); return { content: [] }; });
'''
    crlf = tmp_path / "crlf"
    crlf.mkdir()
    (crlf / "server.ts").write_bytes((HDR + body).replace("\n", "\r\n").encode())
    bom = tmp_path / "bom"
    bom.mkdir()
    (bom / "server.ts").write_text("﻿" + HDR + body, encoding="utf-8")

    for root in (crlf, bom):
        found = check(root)
        assert len(found) == 1, root.name
        lines = (root / "server.ts").read_text(encoding="utf-8-sig").splitlines()
        assert "fs.rm(args.dir" in lines[found[0].line - 1], (root.name, found[0].line)


def test_shared_noise_fixture_flags_nothing():
    """Every known false-positive trap from the corpus recon, in one place.
    Any finding here is a bug in this check, not in the fixture."""
    assert (FIXTURES / "ts_noise_common").is_dir(), (
        "the shared ts_noise_common fixture is missing; without it this test "
        "passes vacuously, because check() on an absent root returns []"
    )
    findings = check(FIXTURES / "ts_noise_common")
    assert findings == [], [f.message for f in findings]
