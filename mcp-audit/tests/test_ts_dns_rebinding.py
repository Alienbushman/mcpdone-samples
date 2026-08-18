"""Tests for the ts_dns_rebinding check."""
from __future__ import annotations

from pathlib import Path

from mcp_audit.checks.ts_dns_rebinding import check
from mcp_audit.finding import Severity

FIXTURES = Path(__file__).parent / "fixtures"


def _findings(name: str):
    return check(FIXTURES / name)


# --------------------------------------------------------------------------
# fire conditions
# --------------------------------------------------------------------------
def test_bad_fixture_flags_the_construction():
    findings = _findings("ts_dns_rebinding_bad")
    assert len(findings) == 1, [f.message for f in findings]
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert "CVE-2025-66414" in f.message
    assert "same-origin" in f.message
    assert "StreamableHTTPServerTransport" in f.message


def test_enabled_but_empty_lists_is_reported_as_a_no_op():
    """`enableDnsRebindingProtection: true` with neither allowedHosts nor
    allowedOrigins: validateRequestHeaders() guards both branches with
    `length > 0`, so it falls through and passes every request."""
    findings = _findings("ts_dns_rebinding_noop")
    assert len(findings) == 1, [f.message for f in findings]
    assert "no-op" in findings[0].message
    assert findings[0].severity == Severity.HIGH


def test_sse_transport_without_an_options_argument_is_flagged():
    """`new SSEServerTransport('/messages', res)` takes options third; with
    no third argument nothing is configured and protection is off."""
    findings = _findings("ts_dns_rebinding_sse")
    assert len(findings) == 1, [f.message for f in findings]
    assert "SSEServerTransport" in findings[0].message


def test_granularity_is_one_finding_per_construction_site():
    findings = _findings("ts_dns_rebinding_two_sites")
    assert len(findings) == 2, [f.message for f in findings]
    assert {f.line for f in findings} == {14, 20}, [f.line for f in findings]


def test_cors_allowlist_is_not_treated_as_a_mitigation():
    """RECON B: after DNS rebinding the request is genuinely same-origin, so
    the browser never performs a CORS check. A CORS allow-list — even a
    tight one — mitigates nothing here."""
    findings = _findings("ts_dns_rebinding_cors")
    assert len(findings) == 1, [f.message for f in findings]


# --------------------------------------------------------------------------
# suppress conditions
# --------------------------------------------------------------------------
def test_guarded_fixture_flags_nothing():
    """The mitigation IS present: enableDnsRebindingProtection plus both
    allow-lists."""
    findings = _findings("ts_dns_rebinding_guarded")
    assert findings == [], [f.message for f in findings]


def test_authenticated_fixture_flags_nothing():
    """Realistic correct code: the transport options are exactly as loose as
    the bad fixture's, but the endpoint is behind requireBearerAuth, so it is
    not reachable by a drive-by page."""
    findings = _findings("ts_dns_rebinding_auth")
    assert findings == [], [f.message for f in findings]


def test_stdio_only_fixture_flags_nothing():
    """Realistic correct code: an ordinary stdio server. The advisory states
    verbatim that stdio is unaffected."""
    findings = _findings("ts_dns_rebinding_stdio")
    assert findings == [], [f.message for f in findings]


def test_hand_rolled_host_validation_anywhere_in_the_repo_suppresses():
    """The Host check lives in a different file from the transport. Any
    host/origin awareness at all, even partial, suppresses the check."""
    findings = _findings("ts_dns_rebinding_hostcheck")
    assert findings == [], [f.message for f in findings]


def test_spread_or_unresolvable_options_flags_nothing():
    """A library re-exporting configurability to its caller: we cannot see
    what the deployer passes, so we do not guess."""
    findings = _findings("ts_dns_rebinding_library")
    assert findings == [], [f.message for f in findings]


def test_same_named_class_without_an_mcp_import_flags_nothing():
    """A project's own `StreamableHTTPServerTransport`. Without an
    `@modelcontextprotocol/` import this is not an SDK transport."""
    findings = _findings("ts_dns_rebinding_nonmcp")
    assert findings == [], [f.message for f in findings]


def test_constructions_inside_strings_and_comments_flag_nothing():
    """Lexing trap: every `new StreamableHTTPServerTransport(...)` in this
    fixture is inside a `//` comment, a `/* */` block, a quoted string, or a
    template literal. Only the stdio transport is real code."""
    findings = _findings("ts_dns_rebinding_lexing")
    assert findings == [], [f.message for f in findings]


def test_outbound_authorization_header_is_not_inbound_authentication():
    """Regression, found in the corpus smoke run: mcp-playwright writes
    `headers['Authorization'] = \\`Bearer ${token}\\`` in an API-request tool
    and reads `customHeaders['Authorization']` next to it. Both are OUTBOUND;
    its own SSE endpoint (src/http-server.ts:103) has no authentication at
    all. Treating either as an inbound auth check suppressed a verified true
    positive."""
    findings = _findings("ts_dns_rebinding_outbound_auth")
    assert len(findings) == 1, [f.message for f in findings]
    assert findings[0].line == 26, findings[0].line


# --------------------------------------------------------------------------
# adversarial-review regressions: four false positives found by hand-writing
# correct-but-unusual code and running the check on it. Every one of these
# fired HIGH on a server that was, in fact, protected. The corpus could not
# surface them because all 25 repos that authenticate happen to do it with an
# SDK name, and no corpus repo uses Hono.
# --------------------------------------------------------------------------
def test_api_key_header_auth_suppresses():
    """`req.headers['x-api-key']` is authentication. The original regex saw
    only `authorization`, so this shape was reported as unauthenticated.
    `context7` and `firecrawl-mcp-server` both authenticate this way."""
    findings = _findings("ts_dns_rebinding_apikey")
    assert findings == [], [f.message for f in findings]


def test_hono_accessors_and_middleware_suppress():
    """Hono spells the middleware `bearerAuth` (not `requireBearerAuth`) and
    the accessor `c.req.header("Authorization")` (not `.get(...)`). Neither
    was recognised. `sentry-mcp` and `git-mcp-server` use the `.header(...)`
    spelling in the real corpus."""
    findings = _findings("ts_dns_rebinding_hono")
    assert findings == [], [f.message for f in findings]


def test_req_hostname_host_guard_suppresses():
    """The worst of the four: this repo performs exactly the mitigation the
    remediation text asks for, spelled the Express/Fastify way as
    `req.hostname`. `filesystem-mcp-server` uses this spelling."""
    findings = _findings("ts_dns_rebinding_hostname")
    assert findings == [], [f.message for f in findings]


def test_bare_hostname_identifier_does_not_suppress():
    """Counterweight to the test above. `hostname` as a bare local is a bind
    address, not a Host-header check — mcp-server-browserbase's verified true
    positive is shaped exactly like this and must keep firing."""
    findings = _findings("ts_dns_rebinding_bare_hostname")
    assert len(findings) == 1, [f.message for f in findings]
    assert findings[0].line == 29, findings[0].line


def test_noop_variant_honours_an_independent_host_guard():
    """`enableDnsRebindingProtection: true` with no allow-lists, but a real
    `hostHeaderValidation()` middleware mounted ahead of the transport. The
    variant must ignore the three self-referential option keys as repo-level
    signals without ignoring the host gate altogether — the old code emitted
    a HIGH finding whose message ("every request passes") was simply false."""
    findings = _findings("ts_dns_rebinding_noop_guarded")
    assert findings == [], [f.message for f in findings]


def test_noop_variant_still_fires_without_an_independent_guard():
    """Proves the fix above is not a blanket disarm of the variant."""
    findings = _findings("ts_dns_rebinding_noop")
    assert len(findings) == 1, [f.message for f in findings]
    assert "no-op" in findings[0].message


def test_malformed_sources_never_raise_and_never_fire():
    """A truncated template literal, an unterminated block comment, latin-1
    bytes in a .js file, an empty file and a binary blob. `Source.ok` is
    False for the degraded lexes, and a degraded lex must never emit a
    finding."""
    findings = _findings("ts_dns_rebinding_malformed")
    assert findings == [], [f.message for f in findings]


def test_missing_root_flags_nothing():
    findings = _findings("ts_dns_rebinding_does_not_exist")
    assert findings == [], [f.message for f in findings]


# --------------------------------------------------------------------------
# house invariants
# --------------------------------------------------------------------------
def test_every_finding_has_line_and_remediation():
    for name in ("ts_dns_rebinding_bad", "ts_dns_rebinding_noop",
                 "ts_dns_rebinding_sse", "ts_dns_rebinding_cors",
                 "ts_dns_rebinding_two_sites"):
        findings = _findings(name)
        assert findings, name
        for f in findings:
            assert f.line is not None and f.line > 0
            assert "enableDnsRebindingProtection" in f.remediation
            assert "allowedHosts" in f.remediation
            assert f.check == "ts_dns_rebinding"
            assert isinstance(f.path, Path)
            assert f.severity == Severity.HIGH


def test_output_is_stable_across_runs():
    a = [(str(f.path), f.line, f.message) for f in _findings("ts_dns_rebinding_two_sites")]
    b = [(str(f.path), f.line, f.message) for f in _findings("ts_dns_rebinding_two_sites")]
    assert a == b


# --------------------------------------------------------------------------
# npm-corpus regressions (2026-08). All 230 npm-distributed MCP server repos
# in the official registry were scanned with this check, and every one of the
# 37 that opens an HTTP/SSE port was then audited by hand. Recall was 57%: 4
# genuine exposures reported, 3 missed. Each miss below was confirmed
# causally, by neutralising the single suppressing token in a copy of the repo
# and re-running until the finding fired.
#
# These use tmp_path with inlined source rather than new fixture directories,
# because each one is a single-file shape and the fixture tree is already the
# largest thing in this suite.
# --------------------------------------------------------------------------
def _write(root: Path, **files: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, body in files.items():
        p = root / name.replace("__", "/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return root


# --- DEFECT 1: aliased / renamed transport imports -------------------------
_CLAWFETCH = """\
#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import type { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';

if (process.env.MODE === 'http') {
  const { randomUUID } = await import('node:crypto');
  const { StreamableHTTPServerTransport: StreamableTransport } = await import(
    '@modelcontextprotocol/sdk/server/streamableHttp.js'
  );
  const express = (await import('express')).default;
  const app = express();
  app.all('/mcp', async (req, res) => {
    const newSessionId = randomUUID();
    const server = createServer();
    const t = new StreamableTransport({ sessionIdGenerator: () => newSessionId });
    await server.connect(t);
    await t.handleRequest(req, res);
  });
  app.listen(3001, '0.0.0.0');
}
"""


def test_destructured_dynamic_import_with_rename_is_found(tmp_path):
    """clawfetch__clawfetch-mcp/src/index.ts:80, the worst miss in the audit.
    `find_constructions` matches the class name as written, so the renamed
    binding produced no construction site at all. The file WAS scanned — the
    static `import type` satisfied the MCP gate — it simply yielded nothing.
    A 0.0.0.0 bind with no auth and no host validation."""
    root = _write(tmp_path / "clawfetch", **{"src__index.ts": _CLAWFETCH})
    findings = check(root)
    assert len(findings) == 1, [f.message for f in findings]
    assert findings[0].line == 16, findings[0].line
    # reported under the SDK's name, not the author's local alias
    assert "StreamableHTTPServerTransport" in findings[0].message
    assert "StreamableTransport`" not in findings[0].message


def test_static_named_import_with_rename_is_found(tmp_path):
    root = _write(tmp_path / "renamed", **{"src__server.ts": """\
import { StreamableHTTPServerTransport as SHT } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
const t = new SHT({ sessionIdGenerator: undefined });
"""})
    assert len(check(root)) == 1


def test_destructured_require_with_rename_is_found(tmp_path):
    """`SSEServerTransport` takes its options THIRD, so the alias has to
    resolve to the canonical name before the argument index is looked up."""
    root = _write(tmp_path / "req", **{"src__server.js": """\
const { SSEServerTransport: S } = require('@modelcontextprotocol/sdk/server/sse.js');
const t = new S('/messages', res);
"""})
    findings = check(root)
    assert len(findings) == 1, [f.message for f in findings]
    assert "SSEServerTransport" in findings[0].message


def test_plain_aliasing_assignment_is_found(tmp_path):
    root = _write(tmp_path / "plain", **{"src__server.ts": """\
import * as sdk from '@modelcontextprotocol/sdk/server/streamableHttp.js';
const SHT = sdk.StreamableHTTPServerTransport;
const Alias = SHT;
const t = new Alias({ sessionIdGenerator: undefined });
"""})
    assert len(check(root)) == 1


def test_an_alias_from_a_non_mcp_module_is_not_a_transport(tmp_path):
    """The counterweight, and the reason the resolver is origin-gated: a
    same-named class renamed out of the project's OWN module is not an SDK
    transport, and the file's unrelated `@modelcontextprotocol/` import must
    not launder it into one."""
    root = _write(tmp_path / "own", **{"src__server.ts": """\
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport as T } from './vendor/transport.js';
const { SSEServerTransport: S } = await import('./vendor/sse.js');
const U = T;
const server = new McpServer({ name: 'd', version: '1.0.0' });
const a = new T({ sessionIdGenerator: undefined });
const b = new S('/messages', res);
const c = new U({ sessionIdGenerator: undefined });
"""})
    assert check(root) == [], [f.message for f in check(root)]


def test_a_transport_reached_through_a_local_helper_stays_invisible(tmp_path):
    """jagduvi1__cellarion's `loadSdk()` shape, held here as a contract on a
    documented blind spot rather than as a fix. The alias resolver refuses a
    right-hand side that is an arbitrary call: destructuring any call's
    properties into SDK classes would flag same-named classes from unrelated
    packages. (cellarion itself is correctly quiet for an independent reason
    — it mounts `requireAuth` — and it is also hidden by a second limit, that
    `collect_imports` does not model dynamic `import()`, so its constructing
    file never passes the `@modelcontextprotocol/` gate.)"""
    root = _write(tmp_path / "cellarion", **{"src__server.js": """\
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
function loadSdk() {
  return Promise.all([
    import('@modelcontextprotocol/sdk/server/streamableHttp.js'),
  ]).then(([http]) => ({ StreamableHTTPServerTransport: http.StreamableHTTPServerTransport }));
}
async function handle(req, res) {
  const { StreamableHTTPServerTransport: SHT } = await loadSdk();
  const transport = new SHT({ sessionIdGenerator: undefined });
  await transport.handleRequest(req, res);
}
"""})
    assert check(root) == [], [f.message for f in check(root)]


# --- DEFECT 2: req.headers.host read as a URL base -------------------------
_SNAPDIFF = """\
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createMcpServer } from './server.js';

export async function startHttpServer(options) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
    if (url.pathname !== '/mcp') {
      res.writeHead(404);
      res.end();
      return;
    }
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });
    const mcp = createMcpServer();
    await mcp.connect(transport);
    await transport.handleRequest(req, res);
  });
  server.listen(options.port, options.host);
}
"""


def test_host_header_as_a_url_base_is_not_a_host_guard(tmp_path):
    """corralimited__snapdiff-mcp/src/http.ts:40. `new URL(req.url ?? '/',
    `http://${req.headers.host ?? 'localhost'}`)` is a base URL for pathname
    routing; it validates precisely nothing. The old heuristic counted a bare
    READ of the Host header as evidence the author had thought about host
    validation and went quiet across the whole repository. Note that
    `url.pathname !== '/mcp'` two lines down IS a comparison — but on the
    path, not on the host, and it must not rescue the suppression."""
    root = _write(tmp_path / "snapdiff", **{"src__http.ts": _SNAPDIFF})
    findings = check(root)
    assert len(findings) == 1, [f.message for f in findings]
    assert findings[0].line == 14, findings[0].line


def test_a_host_read_that_is_actually_compared_still_suppresses(tmp_path):
    """Counterweight. Six spellings of a real hand-rolled Host check, none of
    which uses a token from `_HOST_GUARD_TOKENS`. Every one must stay quiet:
    losing these is how raising recall turns into a false positive."""
    tests = [
        'if (req.headers.host !== "localhost:3000") { res.statusCode = 403; res.end(); return; }',
        'if (!OK.has(req.headers.host ?? "")) { res.statusCode = 403; res.end(); return; }',
        'if (!/^127\\.0\\.0\\.1(:\\d+)?$/.test(req.headers.host ?? "")) { res.end(); return; }',
        'if (!isAllowedHost(req.headers.host)) { res.end(); return; }',
        'const h = req.headers.host; if (!ALLOWED.includes(h)) { res.end(); return; }',
        'const u = new URL(`http://${req.headers.host}`); '
        'if (u.hostname !== "localhost") { res.end(); return; }',
    ]
    for i, guard in enumerate(tests):
        root = _write(tmp_path / f"guarded{i}", **{"src__server.ts": f"""\
import {{ createServer }} from 'node:http';
import {{ StreamableHTTPServerTransport }} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
const server = createServer(async (req, res) => {{
  {guard}
  const transport = new StreamableHTTPServerTransport({{ sessionIdGenerator: undefined }});
  await transport.handleRequest(req, res);
}});
server.listen(3000, '127.0.0.1');
"""})
        assert check(root) == [], (guard, [f.message for f in check(root)])


# --- DEFECT 3: auth tokens in prose and generated-code templates -----------
_EXECBRO = """\
export function buildRequestScript(opts) {
  const authBlock = opts.auth === 'auto'
    ? `
    var authFrom = headers['Authorization'] ? 'explicit' : null;
    if (token && !headers['Authorization']) {
        headers['Authorization'] = 'Bearer ' + token;
    }`
    : '';
  return `(function(){
    var headers = {};${authBlock}
    var authNote = !headers['Authorization']
        ? 'This request was sent UNAUTHENTICATED - pass headers.Authorization explicitly.'
        : null;
    return fetch(url, { headers: headers });
  })()`;
}
"""

_EXECBRO_SERVER = """\
import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
const app = express();
app.post('/mcp', async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await transport.handleRequest(req, res, req.body);
});
app.listen(3000);
"""


def test_authorization_in_prose_and_generated_code_is_not_an_auth_check(tmp_path):
    """igorzheludkov__execbro/src/index.ts:189. The ENTIRE repository was
    suppressed because `Authorization` appears in src/core/appRequest.ts
    inside (a) a template literal that generates JavaScript to inject into a
    TARGET app and (b) a plain-English error message reading
    'headers.Authorization'. It took neutralising all five mentions to make
    the finding appear. None of them is an inbound check on this server."""
    root = _write(tmp_path / "execbro", **{
        "src__core__appRequest.ts": _EXECBRO,
        "src__index.ts": _EXECBRO_SERVER,
    })
    findings = check(root)
    assert len(findings) == 1, [f.message for f in findings]
    assert findings[0].path.name == "index.ts", findings[0].path


def test_a_comment_about_the_authorization_header_is_not_an_auth_check(tmp_path):
    root = _write(tmp_path / "commented", **{"src__server.ts": """\
import express from 'express';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
// TODO: read req.headers['authorization'] here and reject anonymous callers.
/* We should also honour req.headers.host one day. */
const app = express();
app.post('/mcp', async (req, res) => {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await transport.handleRequest(req, res, req.body);
});
app.listen(3000);
"""})
    findings = check(root)
    assert len(findings) == 1, [f.message for f in findings]


def test_a_real_header_read_keeps_suppressing_even_though_the_name_is_masked(tmp_path):
    """The subtlety that makes DEFECT 3 hard, held as a contract: the common
    spelling `req.headers["authorization"]` puts the header NAME inside a
    string literal, whose interior jsparse blanks. Matching on the mask would
    lose every one of these. The liveness test is applied to the accessor
    around the string, not to the string."""
    for accessor in (
        'const a = req.headers["authorization"]; if (!a) { res.end(); return; }',
        "const a = req.get('Authorization'); if (!a) { res.end(); return; }",
        'const a = c.req.header("Authorization"); if (!a) { res.end(); return; }',
        'const a = req.headers["x-api-key"]; if (!a) { res.end(); return; }',
        'const { authorization } = req.headers; if (!authorization) { res.end(); return; }',
        'const a = `presented: ${req.headers["authorization"]}`; if (!a) { res.end(); return; }',
    ):
        root = _write(tmp_path / f"auth{abs(hash(accessor))}", **{"src__server.ts": f"""\
import express from 'express';
import {{ StreamableHTTPServerTransport }} from '@modelcontextprotocol/sdk/server/streamableHttp.js';
const app = express();
app.post('/mcp', async (req, res) => {{
  {accessor}
  const transport = new StreamableHTTPServerTransport({{ sessionIdGenerator: undefined }});
  await transport.handleRequest(req, res, req.body);
}});
app.listen(3000);
"""})
        assert check(root) == [], (accessor, [f.message for f in check(root)])


def test_shared_noise_fixture_flags_nothing():
    """Every known false-positive trap from the corpus recon, in one place.
    Any finding here is a bug in this check, not in the fixture."""
    assert (FIXTURES / "ts_noise_common").is_dir(), (
        "the shared ts_noise_common fixture is missing; without it this test "
        "passes vacuously, because check() on an absent root returns []"
    )
    findings = _findings("ts_noise_common")
    assert findings == [], [f.message for f in findings]


# ==========================================================================
# SECOND ADVERSARIAL REVIEW (npm-corpus audit follow-up).
#
# The three recall fixes above were re-probed with 43 hand-written pieces of
# correct-but-unusual code. Eight of them produced a HIGH finding on code that
# is doing exactly the right thing. Three were REGRESSIONS introduced by the
# defect-2 tightening (a host read must now be *tested*, and the set of shapes
# that count as a test was too small); five were pre-existing gaps that the
# same probe battery surfaced. Each one is pinned below.
#
# Every fix widens SUPPRESSION, so none of them can create a finding. All 11
# corpus findings across the 230 repos are byte-identical before and after.
# ==========================================================================
_CTOR = """\
const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID() });
"""
_MCP_IMPORT = (
    "import { StreamableHTTPServerTransport } from "
    "'@modelcontextprotocol/sdk/server/streamableHttp.js';\n"
)


def _host_guard_is_honoured(tmp_path, slug: str, guard: str) -> list:
    root = _write(tmp_path / slug, **{"src__server.ts": _MCP_IMPORT + guard + _CTOR})
    return check(root)


def test_regression_object_map_allowlist_indexed_by_host_suppresses(tmp_path):
    """DEFECT 2 REGRESSION. Using a record as the allow-list and indexing it
    by the Host header is a real, correct guard, but `ident[` was not in the
    set of shapes that count as a test, so the whole repo was reported."""
    findings = _host_guard_is_honoured(tmp_path, "objmap", """\
const ALLOWED = { 'localhost:3000': true, '127.0.0.1:3000': true };
function handle(req, res) {
  if (!ALLOWED[req.headers.host]) { res.writeHead(403); res.end(); return; }
}
""")
    assert findings == [], [f.message for f in findings]


def test_regression_conversion_wrapper_between_read_and_test_suppresses(tmp_path):
    """DEFECT 2 REGRESSION. `RE.test(String(req.headers.host))` — the value is
    tested, but a `String(...)` sat between the test and the read, so the
    prefix scan saw `String(` and gave up."""
    findings = _host_guard_is_honoured(tmp_path, "wrapper", """\
const RE = /^127\\.0\\.0\\.1/;
function handle(req, res) {
  if (!RE.test(String(req.headers.host))) { res.writeHead(403); res.end(); return; }
}
""")
    assert findings == [], [f.message for f in findings]


def test_regression_validation_helper_named_by_suffix_suppresses(tmp_path):
    """DEFECT 2 REGRESSION. The validation-helper name list was PREFIX-only
    (`is*`, `check*`, `validate*`), so `hostAllowed(...)`, `originIsValid(...)`
    and every other `*Allowed` / `*Valid` spelling fell straight through."""
    for slug, helper in (
        ("suffix1", "hostAllowed"),
        ("suffix2", "originIsValid"),
        ("suffix3", "hostPermitted"),
        ("suffix4", "hostWhitelisted"),
    ):
        findings = _host_guard_is_honoured(tmp_path, slug, """\
function %s(h) { return h === 'localhost:3000'; }
function handle(req, res) {
  if (!%s(req.headers.host)) { res.writeHead(403); res.end(); return; }
}
""" % (helper, helper))
        assert findings == [], (helper, [f.message for f in findings])


def test_destructured_host_header_suppresses(tmp_path):
    """`const { host } = req.headers` is the one accessor shape that puts the
    header name nowhere the host regex can see it. Pre-existing gap."""
    findings = _host_guard_is_honoured(tmp_path, "hostdestr", """\
function handle(req, res) {
  const { host } = req.headers;
  if (host !== 'localhost:3000') { res.writeHead(403); res.end(); return; }
}
""")
    assert findings == [], [f.message for f in findings]


def test_every_genuine_host_guard_spelling_still_suppresses(tmp_path):
    """Counterweight for the widened prefix set: the guards that already
    worked must keep working. A failure here means the fixes above traded one
    false positive for another."""
    guards = {
        "g_neq": "function h(req,res){ if (req.headers.host !== 'localhost:3000') { res.end(); return; } }",
        "g_has": "const OK=new Set(['localhost:3000']);\nfunction h(req,res){ if (!OK.has(req.headers.host)) { res.end(); return; } }",
        "g_inc": "const H=['localhost:3000'];\nfunction h(req,res){ const host=req.headers.host ?? ''; if (!H.includes(host)) { res.end(); return; } }",
        "g_re": "const RE=/^localhost$/;\nfunction h(req,res){ if (!RE.test(req.headers.host)) { res.end(); return; } }",
        "g_sw": "function h(req,res){ if (!req.headers.host?.startsWith('localhost')) { res.end(); return; } }",
        "g_assert": "function assertAllowedHost(x){ if (x!=='localhost:3000') throw new Error('x'); }\nfunction h(req,res){ assertAllowedHost(req.headers.host); }",
        "g_hono": "app.post('/mcp',(c)=>{ const origin=c.req.header('origin'); if (origin!=='http://localhost:3000') return c.text('no',403); });",
        "g_fastify": "fastify.addHook('onRequest', async (request,reply)=>{ if (request.hostname!=='localhost:3000') reply.code(403).send(); });",
        "g_switch": "function h(req,res){ switch (req.headers.host) { case 'localhost:3000': break; default: res.end(); return; } }",
        "g_url": "function h(req,res){ const u=new URL(req.url,`http://${req.headers.host}`); if (u.hostname!=='127.0.0.1') { res.end(); return; } }",
        "g_chain": "function h(req,res){ if (req.headers.host?.toLowerCase().split(':')[0] !== 'localhost') { res.end(); return; } }",
        "g_nullish": "function h(req,res){ if (!(req.headers.origin ?? '').startsWith('http://localhost')) { res.end(); return; } }",
        "g_indexof": "const O=['http://localhost:3000'];\nfunction h(req,res){ if (O.indexOf(req.headers.origin)===-1) { res.end(); return; } }",
        "g_exphost": "app.use((req,res,next)=>{ if (req.hostname!=='localhost') return res.sendStatus(403); next(); });",
        "g_get": "app.use((req,res,next)=>{ if (req.get('host')!=='localhost:3000') return res.sendStatus(403); next(); });",
    }
    for slug, guard in guards.items():
        findings = _host_guard_is_honoured(tmp_path, slug, guard + "\n")
        assert findings == [], (slug, [f.message for f in findings])


def test_the_url_base_idiom_still_fires_after_widening_the_guard_set(tmp_path):
    """The whole point of DEFECT 2, re-pinned. The URL-base idiom reads the
    Host header and validates nothing. Widening the prefix set to accept
    `ident[` must not accidentally make a template hole count."""
    findings = _host_guard_is_honoured(tmp_path, "urlbase", """\
function handle(req, res) {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  if (url.pathname !== '/mcp') { res.writeHead(404); res.end(); return; }
}
""")
    assert len(findings) == 1, [f.message for f in findings]


def test_with_mcp_auth_middleware_suppresses(tmp_path):
    """`withMcpAuth` is better-auth's MCP wrapper. `contains_token` is word-
    bounded, so the existing `withAuth` entry did NOT cover it and a correctly
    authenticated server was reported HIGH."""
    root = _write(tmp_path / "withmcpauth", **{"src__server.ts": _MCP_IMPORT + """\
import { withMcpAuth } from 'better-auth/plugins';
const handler = withMcpAuth(auth, (req, session) => buildHandler(session));
""" + _CTOR})
    findings = check(root)
    assert findings == [], [f.message for f in findings]


def test_search_params_get_token_suppresses(tmp_path):
    """A secret in the query string defeats the rebinding attack, but the
    URLSearchParams accessor is spelled `.get('token')` and the query regex
    only knew the property and bracket forms."""
    root = _write(tmp_path / "qtoken", **{"src__server.ts": _MCP_IMPORT + """\
function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  if (url.searchParams.get('token') !== process.env.TOKEN) { res.writeHead(401); res.end(); return; }
}
""" + _CTOR})
    findings = check(root)
    assert findings == [], [f.message for f in findings]


def test_same_named_transport_from_a_non_mcp_package_is_not_a_transport(tmp_path):
    """`_MCP_IMPORT_PREFIX` gates the FILE, not the BINDING. A file that
    imports anything from the SDK and also has its own same-named class from
    an unrelated package had that unrelated class reported as an SDK
    transport."""
    root = _write(tmp_path / "othpkg", **{"src__server.ts": """\
import { StreamableHTTPServerTransport } from 'some-other-http-lib';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
const t = new StreamableHTTPServerTransport({ port: 3000 });
"""})
    findings = check(root)
    assert findings == [], [f.message for f in findings]


def test_a_locally_declared_class_of_the_same_name_is_not_a_transport(tmp_path):
    root = _write(tmp_path / "localcls", **{"src__server.ts": """\
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
class StreamableHTTPServerTransport {
  constructor(opts) { this.opts = opts; }
}
const t = new StreamableHTTPServerTransport({ sessionIdGenerator: () => '1' });
"""})
    findings = check(root)
    assert findings == [], [f.message for f in findings]


def test_shadowing_never_silences_a_real_sdk_import(tmp_path):
    """Counterweight to the two tests above: a name the SDK itself binds must
    stay a transport even when the same name is bound elsewhere too. Without
    this, `_shadowed_transport_names` would be a silent kill switch."""
    root = _write(tmp_path / "notshadowed", **{"src__server.ts": _MCP_IMPORT + _CTOR})
    findings = check(root)
    assert len(findings) == 1, [f.message for f in findings]
