"""Tests for the ts_command_injection check."""
from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.checks.ts_command_injection import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"

_PRELUDE = """\
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync, exec, spawn, execFile, execFileSync } from "node:child_process";
import { z } from "zod";
const server = new McpServer({ name: "t", version: "0.0.1" });
"""


def _findings(name: str):
    return check(FIXTURES / name)


def _inline(tmp_path: Path, body: str, *, schema: str = "cmd: z.string()",
            sig: str = "{ cmd }"):
    """Register one tool whose handler body is `body`, then run the check."""
    src = _PRELUDE + (
        'server.registerTool("t", { inputSchema: { %s } },\n'
        "  async (%s) => {\n%s\n    return { content: [] };\n  });\n"
    ) % (schema, sig, body)
    (tmp_path / "server.ts").write_text(src, encoding="utf-8")
    return check(tmp_path)


# ---------------------------------------------------------------- fire cases
def test_bad_fixture_flags_every_intentional_case():
    findings = _findings("ts_command_injection_bad")
    # 3 intentional sinks: runGit (execSync template), openPath (shell: true),
    # launch (tainted executable).
    assert len(findings) == 3, [f.message for f in findings]
    assert all(f.severity == Severity.HIGH for f in findings)
    tools = " ".join(f.message for f in findings)
    for name in ("runGit", "openPath", "launch"):
        assert name in tools, f"missing finding for {name}"


def test_always_shell_variant_names_exec_and_execsync():
    findings = [f for f in _findings("ts_command_injection_bad") if "runGit" in f.message]
    assert len(findings) == 1, [f.message for f in findings]
    assert "`child_process.exec` / `execSync`" in findings[0].message
    assert "/bin/sh" in findings[0].message


def test_shell_option_variant_names_the_function_and_the_option():
    findings = [f for f in _findings("ts_command_injection_bad") if "openPath" in f.message]
    assert len(findings) == 1, [f.message for f in findings]
    assert "`shell: true`" in findings[0].message
    assert "child_process.spawn" in findings[0].message


def test_tainted_executable_variant_says_the_caller_picks_the_binary():
    findings = [f for f in _findings("ts_command_injection_bad") if "launch" in f.message]
    assert len(findings) == 1, [f.message for f in findings]
    assert "executable" in findings[0].message
    assert "child_process.execFile" in findings[0].message


def test_renamed_import_and_inline_require_both_resolve_as_sinks():
    """`import { execSync as runSync }` and
    `require('child_process').execSync(...)` are the two import shapes a
    naive `receiver in imports` lookup gets wrong in opposite directions."""
    findings = _findings("ts_command_injection_aliased")
    assert len(findings) == 2, [f.message for f in findings]
    tools = " ".join(f.message for f in findings)
    assert "renamed" in tools and "inlineRequire" in tools


def test_lowlevel_dispatch_taints_through_a_local():
    """setRequestHandler(CallToolRequestSchema) destructures `arguments`, and
    the command string is built into a local before reaching execSync — taint
    must survive the assignment. The sibling ListTools handler is a catalogue
    and must stay silent."""
    findings = _findings("ts_command_injection_lowlevel")
    assert len(findings) == 1, [f.message for f in findings]
    assert findings[0].severity == Severity.HIGH


def test_shell_given_as_a_path_string_is_still_a_shell():
    """Node treats `{ shell: '/bin/bash' }` exactly like `{ shell: true }`."""
    findings = _findings("ts_command_injection_shellstring")
    assert len(findings) == 1, [f.message for f in findings]
    assert "runPipeline" in findings[0].message
    assert "child_process.spawnSync" in findings[0].message


# ------------------------------------------------------------ suppress cases
def test_argv_without_shell_fixture_flags_nothing():
    """The correct-code negative. `execFileSync('kubectl', ['get', resource])`
    and `spawn('git', ['checkout', branch], { shell: false })` are exactly
    what this check's remediation asks authors to write."""
    findings = _findings("ts_command_injection_safe")
    assert findings == [], [f.message for f in findings]


def test_regexp_exec_and_sqlite_exec_are_not_shell_sinks():
    """RegExp.prototype.exec (desktop-commander/src/search-manager.ts:578)
    and better-sqlite3's db.exec (typescript-sdk examples/shared/src/auth.ts)
    share a name with child_process.exec and nothing else. The import gate is
    the only thing separating them, so the fixture also imports the real
    child_process to prove the gate is doing the work."""
    findings = _findings("ts_command_injection_not_shell")
    assert findings == [], [f.message for f in findings]


def test_json_stringify_quoting_suppresses():
    """sentry-mcp/packages/mcp-server/src/auth/device-code-flow.ts:160 does
    ``exec(`open ${JSON.stringify(url)}`)``. The value cannot escape its own
    shell argument; firing here would be a false positive."""
    findings = _findings("ts_command_injection_quoted")
    assert findings == [], [f.message for f in findings]


def test_no_schema_handler_param0_is_not_tainted():
    """RECON A rule R2, and the highest-value regression test in the suite.
    `server.tool(name, description, cb)` declares no input schema, so the SDK
    calls `cb(extra)` — parameter 0 is the server context, not tool
    arguments. browser-tools-mcp/mcp-server.ts:178 is this exact shape."""
    findings = _findings("ts_command_injection_no_schema")
    assert findings == [], [f.message for f in findings]


def test_allowlist_and_sanitizer_guards_suppress():
    """A validation indicator anywhere in the handler body silences the
    handler. Deliberately broad — false-negative bias."""
    findings = _findings("ts_command_injection_guarded")
    assert findings == [], [f.message for f in findings]


def test_dangerous_text_inside_strings_and_comments_does_not_fire():
    """The lexing trap. A commented-out execSync call, a string literal
    containing a whole template-interpolated shell command, a `//` inside a
    URL string, a `/* */` inside a string, a regex containing quotes, and a
    division that follows `)` — all must be invisible."""
    findings = _findings("ts_command_injection_lex_trap")
    assert findings == [], [f.message for f in findings]


def test_unlexable_file_flags_nothing():
    """An unterminated template literal sets Source.ok = False. Every span
    after the break point is garbage, so a finding anchored to one would be
    garbage too — the hard contract is to return []."""
    findings = _findings("ts_command_injection_malformed")
    assert findings == [], [f.message for f in findings]


def test_shared_noise_fixture_flags_nothing():
    """Every known false-positive trap from the corpus recon, in one place.
    Any finding here is a bug in this check, not in the fixture."""
    assert (FIXTURES / "ts_noise_common").is_dir(), (
        "the shared ts_noise_common fixture is missing; without it this test "
        "passes vacuously, because check() on an absent root returns []"
    )
    findings = check(FIXTURES / "ts_noise_common")
    assert findings == [], [f.message for f in findings]


# ------------------------------------------ regression: control-flow taint
# `tstools.propagate_taint` is name-based: any local whose initializer merely
# MENTIONS a parameter becomes tainted. Every case below is correct code that
# fired before `_taint_is_spliced` was added, and the first one is the exact
# allow-list shape this check's own remediation recommends. This is the v0.3
# failure mode, so these are the load-bearing tests in the file.
def test_allowlist_table_lookup_is_not_a_tainted_executable(tmp_path):
    findings = _inline(tmp_path, """\
    const BINARIES: Record<string, string> = { git: "/usr/bin/git" };
    const bin = BINARIES[cmd];
    if (!bin) throw new Error("unknown");
    execFileSync(bin, ["--version"]);""")
    assert findings == [], [f.message for f in findings]


def test_binary_chosen_from_two_literals_does_not_fire(tmp_path):
    findings = _inline(tmp_path, """\
    const bin = cmd === "yarn" ? "yarn" : "npm";
    execFile(bin, ["--version"]);""")
    assert findings == [], [f.message for f in findings]


def test_command_chosen_from_two_literals_does_not_fire(tmp_path):
    findings = _inline(tmp_path, """\
    const line = cmd === "long" ? "ls -la" : "ls -1";
    execSync(line);""")
    assert findings == [], [f.message for f in findings]


def test_regex_stripped_value_does_not_fire(tmp_path):
    """A hand-rolled sanitiser is an unreadable step, and an unreadable step
    is far more often a guard than a splice."""
    findings = _inline(tmp_path, """\
    const clean = cmd.replace(/[^A-Za-z0-9._-]/g, "");
    execSync(`git show ${clean}`);""")
    assert findings == [], [f.message for f in findings]


def test_path_join_of_a_parameter_is_not_a_raw_executable(tmp_path):
    findings = _inline(tmp_path, """\
    const exe = ["/opt/tools", cmd].join("/");
    spawn(exe, []);""")
    assert findings == [], [f.message for f in findings]


# ...and the splices that must survive the narrowing.
@pytest.mark.parametrize("body", [
    "    execSync(cmd);",                                     # raw
    "    const line = `git ${cmd}`;\n    execSync(line);",    # one hop, template
    '    const line = "git " + cmd;\n    exec(line);',        # one hop, concat
    "    const a = cmd;\n    const b = `git ${a}`;\n    execSync(b);",   # two hops
    '    let line = "git status";\n    line = `git ${cmd}`;\n    execSync(line);',
    "    execSync(build(cmd));",                              # a call at the sink
    "    execFile(cmd, []);",                                 # raw executable
    "    spawn(cmd, [], { shell: true });",                   # shell: true
])
def test_real_splices_still_fire(tmp_path, body):
    findings = _inline(tmp_path, body)
    assert len(findings) == 1, [f.message for f in findings] or "no finding"
    assert findings[0].severity == Severity.HIGH


# ------------------------------------------------------------------ contract
def test_every_finding_has_line_and_remediation():
    for name in ("ts_command_injection_bad", "ts_command_injection_aliased",
                 "ts_command_injection_lowlevel"):
        findings = _findings(name)
        assert findings, name
        for f in findings:
            assert f.line is not None and f.line > 0
            assert "execFile" in f.remediation
            assert f.check == "ts_command_injection"
            assert isinstance(f.path, Path)


def test_findings_point_at_the_sink_line():
    findings = _findings("ts_command_injection_bad")
    text = (FIXTURES / "ts_command_injection_bad" / "server.ts").read_text(
        encoding="utf-8"
    ).splitlines()
    for f in findings:
        line = text[f.line - 1]
        assert any(fn in line for fn in ("execSync", "spawn", "execFile")), line


def test_check_is_deterministic():
    a = [(str(f.path), f.line, f.message) for f in _findings("ts_command_injection_bad")]
    b = [(str(f.path), f.line, f.message) for f in _findings("ts_command_injection_bad")]
    assert a == b


def test_missing_root_returns_empty():
    assert check(FIXTURES / "does_not_exist_at_all") == []
