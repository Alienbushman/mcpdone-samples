"""ts_dns_rebinding — flag TypeScript/JavaScript MCP servers that construct an
HTTP or SSE transport with DNS-rebinding protection left off and no
authentication anywhere in the repository.

Background: the TypeScript MCP SDK's HTTP transports
(`StreamableHTTPServerTransport`, `SSEServerTransport`, and the v2
`NodeStreamableHTTPServerTransport` / `WebStandardStreamableHTTPServerTransport`)
ship with `enableDnsRebindingProtection` defaulting to `false`. A transport
built that way accepts any `Host` and any `Origin` header. A web page the
victim visits can re-point its own hostname at 127.0.0.1 after the browser
has cached the page's origin, then call the local MCP endpoint as
same-origin, read the responses, and drive `tools/list` and `tools/call` at
the server process's own privilege. The MCP specification says servers MUST
validate the `Origin` header on HTTP transports; the SDK does not do it for
you.

Motivating real-world case (2026-07): GHSA-w48q-cv73-mx4w / CVE-2025-66414
(CVSS v4 7.6) against `@modelcontextprotocol/sdk`. Two clean instances were
re-verified in the 25-repo TypeScript corpus behind this check:
`official-servers`' `everything` server builds a Streamable HTTP transport
with `origin: "*"`, no rebinding options and a bare `app.listen(PORT)`; and
`mcp-server-browserbase/src/transport.ts` builds
`new StreamableHTTPServerTransport({ sessionIdGenerator: () => sessionId })`
with nothing else and no authentication anywhere in the repo. Neither is a
stdio server; both are meant to be run locally next to a browser.

What's flagged (HIGH severity):

  - `no_protection` — a file that imports from `@modelcontextprotocol/` and
    constructs one of the HTTP/SSE transport classes with an options object
    that configures none of `enableDnsRebindingProtection` / `allowedHosts` /
    `allowedOrigins` (or passes no options at all), in a repository where no
    authentication signal and no host/origin-validation signal was found in
    any scanned source.
  - `noop_protection` — an options object that sets
    `enableDnsRebindingProtection: true` but configures neither
    `allowedHosts` nor `allowedOrigins`. In the SDK's
    `validateRequestHeaders()` both branches are guarded by a `length > 0`
    test, so with both lists empty the function falls through and every
    request passes. This one ignores the three transport option keys as
    repo-level host/origin signals, because the token that would suppress it
    is the very thing that is broken — but it still honours every
    *independent* host guard (`hostHeaderValidation()`, `createMcpExpressApp`,
    a hand-rolled `req.headers.host` comparison). A server that arms the
    option AND mounts real middleware is protected, and saying otherwise
    would be a false positive.

What's NOT flagged (false-negative bias, per the v0.3 credibility bar):

  - stdio-only servers. No HTTP transport construction, no finding. The
    advisory states verbatim that stdio is unaffected.
  - Any authentication signal anywhere in the repository — a bearer-auth or
    basic-auth or API-key middleware, an OAuth provider, a JWT verifier, a
    read of the `Authorization` / `X-API-Key` header through any of the
    Express, Node, Hono or Fastify accessors, or a secret read out of the
    query string. Every hosted/SaaS MCP server is authenticated and is a
    non-issue. This is the single largest false-positive source and the
    suppression is repo-wide and unconditional.
  - Any host/origin-validation signal anywhere in the repository, even a
    partial or wrong one (`allowedHosts`, `hostHeaderValidation`,
    `createMcpExpressApp`, a read of `req.headers.host`, `req.hostname`, or
    `c.req.header('host')`). Author awareness of the problem is enough to
    stay quiet.
  - An options object containing a spread (`new StreamableHTTPServerTransport(
    { ...opts })`) or one we cannot resolve to a literal. That shape is a
    library re-exporting configurability to its caller, not a deployed
    server, and we cannot see what the caller passes.
  - `Source.ok is False` — a file the lexer could not walk cleanly.

Explicitly NOT treated as mitigations, because they are not: binding to
`127.0.0.1` or `localhost` (that is precisely what rebinding defeats); a CORS
allow-list (after rebinding the request is genuinely same-origin, so CORS
never runs); and an SDK version at or above 1.24.0 on its own. The advisory
lists 1.24.0 as the first patched release, but the fix it ships is the
app-builder / middleware path, not a change to this constructor default -- a
site that still constructs the transport by hand is unprotected on any version.
We do not assert anything about the 2.x line beyond that: its server package
reorganizes host validation into `@modelcontextprotocol/express`, and the
suppression signals below are what decide a 2.x repo, not a version compare.

Known limits: analysis is per-repository for the suppression signals and
per-file for the construction sites, and it never follows a value across
files. A transport constructed from an options object built in another
module is not analyzed — the site is suppressed rather than guessed at. A
file that re-exports the transport class through a local wrapper module,
so that the constructing file has no `@modelcontextprotocol/` import, is
also missed. Cross-file interprocedural flow is out of scope for the same
reason it is out of scope in the Python checks: it is the analysis shape
that produced the v0.3 command_injection retraction.

Further known limits, named by the 230-repo npm-corpus audit (2026-08) that
measured this check's recall at 57% before the three fixes below:

  - Transport classes reached through a *local helper* rather than an
    import are still invisible. `jagduvi1__cellarion` caches the SDK in a
    `loadSdk()` promise and then writes
    `const { StreamableHTTPServerTransport } = await loadSdk();`. Two
    separate things hide it, and both are deliberate: `collect_imports`
    does not model dynamic `import()`, so that file never passes the
    `@modelcontextprotocol/` gate at all; and the alias resolver below
    refuses a right-hand side that is an arbitrary call, because treating
    any call's destructured properties as SDK classes would flag same-named
    classes from unrelated packages. (That repo is correctly quiet anyway —
    it mounts `requireAuth` on the route.)
  - Authentication that is CONDITIONAL and off by default in exactly the
    local case is read as authentication. `oobe-protocol__sap-mcp`'s
    `src/transports/http.ts` throws only when `!config.apiKey &&
    !isLoopbackHost(host)`, i.e. it explicitly blesses "loopback with no
    API key", and the 401 block below it is wrapped in `if (config.apiKey)`
    so it never runs for a local start. That is precisely the "localhost is
    safe" belief the advisory refutes, and this check cannot see it: the
    repo-wide auth gate has no notion of a condition. Deciding it would
    need path-sensitivity we do not have, and guessing wrong is a false
    positive on a server that IS authenticated in its hosted mode.
  - A control that is present but UNARMED by default is read as armed.
    `elfa-ai__mcp` gates both its origin check and the transport's option
    spread on `ELFA_MCP_ALLOWED_ORIGINS`, which is unset by default, so a
    default install has neither. Same reason as above: the signals here are
    existence signals, not reachability signals.

Both of the last two are the *conservative* failure direction — they under-
report — so they stay as documented blind spots rather than heuristics.

A second adversarial pass over the same corpus (2026-08) re-probed the three
fixes above with 43 pieces of correct-but-unusual code and found eight shapes
that produced a HIGH finding on code doing the right thing. Three were
regressions from the defect-2 tightening — an object/record allow-list indexed
by the header (`ALLOWED[req.headers.host]`), a conversion wrapped around the
read (`RE.test(String(req.headers.host))`), and a validation helper named by
suffix rather than prefix (`hostAllowed(...)`) — and five were pre-existing
gaps (`withMcpAuth`, `searchParams.get('token')`, `const { host } =
req.headers`, and the two same-name-binding cases below). All eight are fixed,
all eight widen suppression only, and the 230-repo corpus output is unchanged.

That pass also narrowed what counts as a transport at all. `_MCP_IMPORT_PREFIX`
gates the FILE, not the BINDING, so a file that imported anything from the SDK
and *also* had its own `StreamableHTTPServerTransport` — from an unrelated
package, or a locally declared class — had that unrelated class reported as an
unprotected SDK transport. `_shadowed_transport_names` now disqualifies such a
name, but only on demonstrable evidence and never when the SDK binds the same
name in the same file, so no genuine construction site is lost.
"""
from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.finding import Finding, Severity
from mcp_audit import jsparse
from mcp_audit.jsparse import ObjectLiteral, Source

CHECK_ID = "ts_dns_rebinding"

_SKIP_DIRS = {
    ".venv", "venv", "env", "node_modules", ".git", "site-packages",
    ".tox", ".nox", "build", "dist", "__pycache__",
}

# SDK transport classes that speak HTTP. `StdioServerTransport` is absent on
# purpose: the advisory does not affect stdio, and a stdio-only server must
# never produce a finding here.
_TRANSPORT_CLASSES = {
    "StreamableHTTPServerTransport",
    "SSEServerTransport",
    "NodeStreamableHTTPServerTransport",
    "WebStandardStreamableHTTPServerTransport",
}

# Positional index of the transport options object in each constructor.
# `SSEServerTransport(endpoint, res, options?)` puts it third; everything
# else takes it first. A class absent from this map is not a transport.
_OPTIONS_ARG_INDEX = {
    "StreamableHTTPServerTransport": 0,
    "NodeStreamableHTTPServerTransport": 0,
    "WebStandardStreamableHTTPServerTransport": 0,
    "SSEServerTransport": 2,
}

# The only import prefix that proves this file is wiring an MCP SDK
# transport rather than a same-named class of its own.
_MCP_IMPORT_PREFIX = "@modelcontextprotocol/"

# Option keys that mean the author has thought about host/origin validation
# at this construction site.
_PROTECTION_KEYS = {"enableDnsRebindingProtection", "allowedHosts", "allowedOrigins"}
_ALLOW_LIST_KEYS = {"allowedHosts", "allowedOrigins"}

# Authentication indicators. Repo-wide: one of these anywhere in any scanned
# source suppresses the whole check. Intentionally broad (false-negative
# bias) — an authenticated endpoint is not exposed to a drive-by browser, and
# we would far rather miss an unauthenticated server than fail a stranger's
# CI on an authenticated one.
_AUTH_TOKENS = {
    "requireBearerAuth", "mcpAuthMetadataRouter", "verifyAccessToken",
    "ProxyOAuthServerProvider", "OAuthServerProvider", "expressjwt",
    "passport", "jwtVerify", "createRemoteJWKSet", "jsonwebtoken",
    "verifyToken", "authenticate", "withAuth", "requireAuth",
    "getBearerToken", "checkApiKey",
    # Adversarial-review addition (see the FP notes below). The original set
    # was tuned against the 25-repo corpus, where every authenticated server
    # happened to use an SDK name. These are the middleware names real MCP
    # servers actually use, verified present in the corpus itself:
    # `authMiddleware` / `createAuthMiddleware` (git-mcp-server,
    # mcp-server-kubernetes), `authenticateRequest` (firecrawl-mcp-server),
    # `isAuthenticated` (sentry-mcp), `basicAuth` (fastmcp). `bearerAuth` is
    # Hono's own middleware and is the single most common shape on
    # Workers-hosted MCP servers, none of which are in the corpus.
    "basicAuth", "bearerAuth", "authMiddleware", "createAuthMiddleware",
    "authenticateRequest", "checkAuth", "verifyAuth", "isAuthenticated",
    "ensureAuthenticated", "validateToken", "verifyApiKey", "requireApiKey",
    "authGuard", "clerkMiddleware", "getAuth", "NextAuth", "betterAuth",
    # Second adversarial review (npm-corpus audit follow-up). `withMcpAuth` is
    # better-auth's MCP wrapper and is the standard spelling on better-auth
    # servers; `contains_token` is word-bounded, so the existing `withAuth`
    # entry does NOT cover it and a correctly-authenticated server was being
    # reported. `mcpAuthRouter` is the SDK's own router alongside the already
    # listed `mcpAuthMetadataRouter`.
    "withMcpAuth", "mcpAuthRouter", "requireOAuth", "verifyBearerToken",
}

# Host / origin validation indicators, repo-wide, same philosophy. Includes
# the SDK >= 1.24.0 app builders, which arm host validation by default.
_HOST_GUARD_TOKENS = {
    "enableDnsRebindingProtection", "allowedHosts", "allowedOrigins",
    "hostHeaderValidation", "localhostHostValidation", "originValidation",
    "localhostOriginValidation", "validateHostHeader",
    "hostHeaderValidationResponse", "originValidationResponse",
    "createMcpExpressApp", "createMcpHonoApp", "createMcpFastifyApp",
}

# The `noop_protection` variant cannot use the full set above: three of those
# tokens ARE the transport option keys, so the very construction that proves
# the bug would suppress the finding. It uses this reduced set instead, which
# still honours every *independent* host guard — an SDK `hostHeaderValidation()`
# middleware, a `createMcpExpressApp(...)`, or a hand-rolled `req.headers.host`
# comparison (the header regex is shared and is independent by construction).
# Adversarial-review fix: the original code skipped the host gate entirely for
# this variant, so a server that set `enableDnsRebindingProtection: true` AND
# mounted `hostHeaderValidation()` was reported HIGH with a message asserting
# that "every request passes" — which is false, the middleware rejects them.
_HOST_GUARD_TOKENS_INDEPENDENT = frozenset(_HOST_GUARD_TOKENS - _PROTECTION_KEYS)

# Header *reads* that the token sets above cannot see, because the header
# name lives inside a string literal and jsparse blanks string interiors.
# These run against the RAW text, so a mention inside a comment also
# suppresses — deliberate, since a comment about the Authorization header is
# still author awareness and over-suppression is the safe direction.
#
# The trailing `(?!\s*=[^=])` matters and is not cosmetic: it rejects a
# *write*. `mcp-playwright/src/tools/api/requests.ts:53` does
# `headers['Authorization'] = \`Bearer ${token}\`` to authenticate an
# OUTBOUND request from one of its tools — that says nothing about whether
# its own SSE endpoint at `src/http-server.ts:103` is protected (it is not).
# Treating an outbound header write as inbound authentication suppressed a
# verified true positive. `==` / `===` stay matched; those are reads.
#
# The leading `(?<![\w$])` matters too: without it, IGNORECASE makes
# `customHeaders['Authorization']` match on its "Headers" suffix. That local
# is an OUTBOUND header bag a tool caller supplied, not the inbound request
# — same false suppression, different line of the same file.
#
# Adversarial-review additions:
#   * API-key headers. `req.headers['x-api-key']` is how context7 and
#     firecrawl-mcp-server authenticate; the original pattern saw only
#     `authorization` and would have flagged both as unauthenticated.
#   * `.header(...)` alongside `.get(...)`. Hono and Fastify spell the
#     accessor `c.req.header('Authorization')` — used by sentry-mcp and
#     git-mcp-server. Hono is the dominant framework for hosted MCP servers
#     and is absent from the corpus, so the corpus could not reveal this.
_AUTH_HEADER_NAMES = r"authorization|x-api-key|api-key|x-auth-token|x-access-token|x-mcp-key"
_AUTH_HEADER_RE = re.compile(
    r"(?:(?<![\w$])headers\s*\.\s*(?:authorization|apiKey)\b"
    rf"|(?<![\w$])headers\s*\[\s*['\"`](?:{_AUTH_HEADER_NAMES})['\"`]\s*\]"
    rf"|\.\s*(?:get|header)\s*\(\s*['\"`](?:{_AUTH_HEADER_NAMES})['\"`]\s*\))"
    r"(?!\s*=[^=])",
    re.IGNORECASE,
)

# `const { authorization } = req.headers` — the fourth accessor shape named by
# the corpus audit, and the only one that never puts the header name inside a
# string. It runs against the MASK, so a mention in prose or in a generated-
# code template cannot reach it and no liveness test is needed.
_AUTH_DESTRUCTURE_RE = re.compile(
    r"(?<![\w$])(?:const|let|var)\s*\{(?P<inner>[^{}]*)\}\s*=\s*"
    r"[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*?\s*\??\.\s*headers(?![\w$])"
)
_AUTH_DESTRUCTURE_NAMES = re.compile(
    r"(?<![\w$])(?:authorization|apiKey|api_key|accessToken|access_token)(?![\w$])",
    re.IGNORECASE,
)

# A secret carried in the query string is still a secret a drive-by page does
# not know, so it defeats the rebinding attack. The name list is deliberately
# tight: `req.query.sessionId` is NOT authentication, and all three flagged
# repos in the corpus use exactly that, so a looser list would have silenced
# every true positive.
#
# The `.get('token')` alternative is the URLSearchParams accessor and is how a
# `new URL(...).searchParams` read is actually spelled; without it a server
# gating on `?token=` in the query string was reported as unauthenticated. It
# stays anchored to a `query` / `searchParams` receiver for the same reason the
# name list is tight — a bare `.get('token')` on any map would suppress far too
# much.
_AUTH_QUERY_NAMES = r"key|apiKey|api_key|token|secret|auth|accessToken|access_token"
_AUTH_QUERY_RE = re.compile(
    r"(?<![\w$])(?:query|searchParams)\s*"
    r"(?:\.\s*(?:key|apiKey|api_key|token|secret|auth|accessToken)\b"
    rf"|\[\s*['\"`](?:{_AUTH_QUERY_NAMES})['\"`]\s*\]"
    rf"|\.\s*get\s*\(\s*['\"`](?:{_AUTH_QUERY_NAMES})['\"`]\s*\))"
    r"(?!\s*=[^=])",
    re.IGNORECASE,
)

# Host / origin *reads*. Additions:
#   * `<request>.hostname` — Express and Fastify both derive it from the Host
#     header, and filesystem-mcp-server uses exactly this. It is anchored to
#     request-shaped receivers because a bare `hostname` local is ubiquitous
#     (mcp-server-browserbase takes one as a function parameter, and that is
#     a true positive that must keep firing).
#   * `.header('host'|'origin')` — the Hono / Fastify accessor.
_HOST_HEADER_RE = re.compile(
    r"(?:(?<![\w$])headers\s*\.\s*(?:host|origin)\b"
    r"|(?<![\w$])headers\s*\[\s*['\"`](?:host|origin)['\"`]\s*\]"
    r"|\.\s*(?:get|header)\s*\(\s*['\"`](?:host|origin)['\"`]\s*\)"
    r"|(?<![\w$])(?:req|request|ctx|c|httpReq|rawReq|nodeReq)\s*\.\s*hostname\b)"
    r"(?!\s*=[^=])",
    re.IGNORECASE,
)

_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")

# --------------------------------------------------------------------------
# DEFECT 3 (npm-corpus audit): auth-looking tokens in prose and in generated
# code. `igorzheludkov__execbro` was suppressed repo-wide because the word
# `Authorization` appears five times in `src/core/appRequest.ts` — inside a
# template literal that GENERATES JavaScript to inject into a target app, and
# inside a plain-English error message reading "pass headers.Authorization
# explicitly". Neither is an inbound auth check on this server's own endpoint.
#
# The regexes above must keep running against RAW text and cannot simply move
# to the mask: the common real spelling `req.headers["authorization"]` puts
# the token itself inside a string literal, whose interior the mask blanks.
# The distinguishing feature is CONTEXT, not maskedness. So: match on raw
# text, then require the match's *structural anchor* — the `headers`
# identifier, or the `.` of `.get(` / `.header(` — to be live code in the
# mask. A comment, a prose string, and a code-generation template all blank
# that anchor; `req.headers["authorization"]` does not, because only the
# string's interior is blanked and the accessor around it survives.
#
# This is the one place where the check gives up suppression, so it is scoped
# as tightly as possible: nothing about which tokens count changes, only
# whether the mention is code at all.
# --------------------------------------------------------------------------
_WS_CHARS = " \t\r\n\v\f ﻿"


def _is_live_code(src: Source, offset: int) -> bool:
    """True when the character at `offset` survived masking as itself.

    False for anything the lexer blanked: comment bodies, string-literal
    interiors, and template-literal text chunks. A `${...}` hole inside a
    template IS live — it is real code — and stays True."""
    if offset < 0 or offset >= len(src.masked):
        return False
    ch = src.masked[offset]
    return ch == src.text[offset] and ch not in _WS_CHARS


def _live_matches(src: Source, pattern: re.Pattern[str]) -> list[re.Match[str]]:
    return [m for m in pattern.finditer(src.text) if _is_live_code(src, m.start())]


# --------------------------------------------------------------------------
# DEFECT 2 (npm-corpus audit): `req.headers.host` read as a URL base, counted
# as a host guard. `corralimited__snapdiff-mcp/src/http.ts:40` reads
#
#     new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
#
# which is a base URL for pathname routing. It validates nothing whatsoever,
# yet a bare READ of the Host header was taken as evidence that the author had
# thought about host validation, and it suppressed the whole repository.
#
# The fix requires the host value to be *tested*, not merely read: compared
# (`===` / `!==` / `==` / `!=`), looked up in a collection (`.has`,
# `.includes`, `.indexOf`, `.some`, ...), run through a regex (`.test`,
# `.match`), switched on, or handed to a validation-shaped helper
# (`isAllowedHost`, `validateHost`, `checkOrigin`, ...). Value-preserving
# transforms between the read and the test are skipped, so
# `req.headers.host?.toLowerCase().split(':')[0] === expected` still counts,
# and so does the overwhelmingly common two-step
#
#     const host = req.headers.host ?? '';
#     if (!ALLOWED.has(host)) { ... }
#
# via one binding hop. Interpolating the value into a template literal or
# passing it to `new URL(...)` matches none of that, which is the point.
# --------------------------------------------------------------------------

# Value-preserving steps between a header read and the test applied to it.
_NEUTRAL_STEP_RE = re.compile(
    r"\A\s*(?:"
    r"!(?!=)"
    r"|(?:\?\.|\.)\s*(?:toLowerCase|toUpperCase|trim|trimStart|trimEnd|toString"
    r"|normalize|valueOf)\s*\(\s*\)"
    r"|(?:\?\.|\.)\s*(?:split|replace|replaceAll|slice|substring|substr|at"
    r"|padStart|padEnd|concat)\s*\([^()]*\)"
    r"|(?:\?\.)?\[\s*\d+\s*\]"
    r"|\s+as\s+[A-Za-z_$][\w$]*(?:\s*\|\s*[A-Za-z_$][\w$]*)*"
    r"|(?:\?\?|\|\|)\s*(?:'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`|[A-Za-z_$][\w$.]*)"
    # A closing paren/bracket of a group opened before the read:
    # `(req.headers.origin ?? "").startsWith(...)`. Only ever widens
    # suppression, and a `}` — the template-literal hole that closes
    # `` `http://${req.headers.host}` `` — is deliberately NOT in this set.
    r"|[)\]]"
    r")"
)

# The value is the LEFT operand of a test.
_GUARD_SUFFIX_RE = re.compile(
    r"\A\s*(?:===|!==|==(?!=)|!=(?!=)"
    r"|(?:\?\.|\.)\s*(?:includes|startsWith|endsWith|indexOf|lastIndexOf|match"
    r"|matchAll|search|test|localeCompare)\s*\("
    r"|in(?![\w$])\s)"
)

# The value is the RIGHT operand of a test, or an argument to one.
#
# Second adversarial review: the first three alternatives below were too narrow
# and each one turned a correct allow-list check into a HIGH finding. All three
# additions only ever WIDEN suppression, so none of them can create a finding.
#
#   * `ALLOWED[req.headers.host]` — an object/record used as the allow-list,
#     indexed by the host. Indexing a *named* collection by the header value is
#     a lookup, and the only reason to look a Host header up in a table is to
#     decide whether it is allowed. Anchored to `ident[` so it cannot match the
#     template-literal hole (`${`) that snapdiff-mcp's URL base opens, which is
#     what defect 2 exists to keep firing.
#   * `hostAllowed(...)` / `originIsValid(...)` / `isHostWhitelisted(...)` — a
#     validation helper whose name carries the intent in the MIDDLE or at the
#     END rather than as a leading verb. The original list was prefix-only, so
#     every `*Allowed` / `*Valid` / `*Permitted` spelling fell through.
_GUARD_PREFIX_RE = re.compile(
    r"(?:"
    r"(?:===|!==|==|!=)\s*!*\s*"
    r"|\.\s*(?:includes|has|indexOf|lastIndexOf|test|exec|match|some|every|find"
    r"|findIndex|startsWith|endsWith|search)\s*\(\s*!*\s*"
    r"|(?<![\w$])(?:is|has|are|can|should|check|validate|verify|assert|ensure"
    r"|allow|require|reject|deny|match|test|guard)[A-Za-z0-9_$]*\s*\(\s*!*\s*"
    r"|(?<![\w$])[A-Za-z_$][\w$]*"
    r"(?:[Aa]llow|[Vv]alid|[Pp]ermit|[Ww]hitelist|[Tt]rusted|[Aa]ccepted)"
    r"[A-Za-z0-9_$]*\s*\(\s*!*\s*"
    r"|(?<![\w$])[A-Za-z_$][\w$]*\s*\??\[\s*"
    r"|(?<![\w$])switch\s*\(\s*"
    r")\Z"
)

# A value-preserving CONVERSION wrapped around the read, between it and the
# test: `RE.test(String(req.headers.host))`. Peeled so the prefix test sees
# `RE.test(` rather than `String(`. These three builtins are the only ones
# accepted — anything else could be a call that changes the value's meaning.
_WRAPPER_CALL_RE = re.compile(r"(?<![\w$])(?:String|Number|Boolean)\s*\(\s*\Z")

# The read sits inside the initializer of a local, whose uses are tested
# instead. Covers `const host = req.headers.host ?? ''`,
# `const host = String(req.headers.host)` and
# `const u = new URL(\`http://${req.headers.host}\`)`.
_HOST_BIND_RE = re.compile(
    r"(?<![\w$])(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=;\n]*)?="
)

# Members of such a local that still carry the Host value. `url.pathname` is
# NOT one, which is what keeps snapdiff-mcp's routing-only `new URL(req.url,
# \`http://${req.headers.host}\`)` from counting as a guard.
_HOST_DERIVED_MEMBERS = ("hostname", "host", "origin")

# `const { host } = req.headers` — the host/origin twin of
# `_AUTH_DESTRUCTURE_RE`, and the one accessor shape that puts the header name
# nowhere `_HOST_HEADER_RE` can see it. Runs against the MASK, so a mention in
# prose or in a generated-code template cannot reach it. Treated as a guard
# unconditionally rather than requiring a downstream test: destructuring the
# Host header out by name is author awareness, over-suppression is the safe
# direction, and no repo in the corpus reaches a finding through this shape.
_HOST_DESTRUCTURE_RE = re.compile(
    r"(?<![\w$])(?:const|let|var)\s*\{(?P<inner>[^{}]*)\}\s*=\s*"
    r"[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*?\s*\??\.\s*headers(?![\w$])"
)
_HOST_DESTRUCTURE_NAMES = re.compile(r"(?<![\w$])(?:host|origin)(?![\w$])", re.IGNORECASE)

_GUARD_LOOKBEHIND = 160
_GUARD_LOOKAHEAD = 200


def _chain_start(src: Source, start: int) -> int:
    """Walk back to the head of the member chain ending at `start`.

    `_HOST_HEADER_RE` anchors on `headers.host`, so a match inside
    `OK.has(req.headers.host)` begins after `req.`. The prefix test needs to
    see `OK.has(`, not `req.`, so the receiver segments are peeled first.

    The `.get(...)` / `.header(...)` alternatives match starting AT the dot,
    so step over it first — otherwise `c.req.header("origin")` peels nothing
    and Hono's accessor loses every prefix test."""
    m = src.masked
    i = start
    if i < len(m) and m[i] == ".":
        i += 1
    for _ in range(8):
        k = i - 1
        while k >= 0 and m[k] in _WS_CHARS:
            k -= 1
        if k < 0 or m[k] != ".":
            return i
        k -= 1
        if k >= 0 and m[k] == "?":       # optional chaining `a?.b`
            k -= 1
        while k >= 0 and m[k] in _WS_CHARS:
            k -= 1
        if k < 0 or not (m[k].isalnum() or m[k] in "_$"):
            return i
        j = k
        while j >= 0 and (m[j].isalnum() or m[j] in "_$"):
            j -= 1
        if _IDENT_RE.match(m[j + 1:k + 1]) is None:
            return i
        i = j + 1
    return i


def _prefix_is_a_test(m: str, head: int) -> bool:
    """True when the text immediately before `head` applies a test to it.

    Peels up to two value-preserving conversion wrappers, so
    `RE.test(String(req.headers.host))` sees `RE.test(`."""
    for _ in range(3):
        lo = max(0, head - _GUARD_LOOKBEHIND)
        window = m[lo:head]
        if _GUARD_PREFIX_RE.search(window):
            return True
        w = _WRAPPER_CALL_RE.search(window)
        if w is None:
            return False
        head = lo + w.start()
    return False


def _tested_in_place(src: Source, start: int, end: int) -> bool:
    """True when the value spanning [start, end) is compared or looked up."""
    m = src.masked
    head = _chain_start(src, start)
    if _prefix_is_a_test(m, head):
        return True
    tail = m[end:min(len(m), end + _GUARD_LOOKAHEAD)]
    for _ in range(6):
        step = _NEUTRAL_STEP_RE.match(tail)
        if step is None or step.end() == 0:
            break
        tail = tail[step.end():]
    return _GUARD_SUFFIX_RE.match(tail) is not None


def _enclosing_binding(src: Source, head: int) -> str | None:
    """Name of the `const`/`let`/`var` whose initializer contains offset
    `head`, or None. The nearest declaration wins, and a `;` between the
    declaration and the read means the statement already ended."""
    window = src.masked[max(0, head - _GUARD_LOOKBEHIND):head]
    last: re.Match[str] | None = None
    for mt in _HOST_BIND_RE.finditer(window):
        if ";" in window[mt.end():]:
            continue
        last = mt
    return None if last is None else last.group("name")


def _host_read_is_a_guard(src: Source, start: int, end: int) -> bool:
    if _tested_in_place(src, start, end):
        return True
    head = _chain_start(src, start)
    name = _enclosing_binding(src, head)
    if name is None:
        return False
    m = src.masked
    whole = jsparse.Span(0, len(m))
    for use in jsparse.identifier_uses(src, whole, name):
        if start <= use < end:
            continue
        stop = use + len(name)
        if _tested_in_place(src, use, stop):
            return True
        # `const u = new URL(`http://${req.headers.host}`)` then
        # `u.hostname !== 'localhost'`: the Host value survives into a
        # host-shaped member, so test that member instead.
        after = m[stop:stop + 24]
        mem = re.match(r"\s*\??\.\s*([A-Za-z_$][\w$]*)", after)
        if mem is not None and mem.group(1).lower() in _HOST_DERIVED_MEMBERS:
            if _tested_in_place(src, use, stop + mem.end()):
                return True
    return False

# --------------------------------------------------------------------------
# DEFECT 1 (npm-corpus audit): aliased / renamed transport bindings.
#
# `jsparse.find_constructions` matches the class name exactly as written, so a
# renamed binding was invisible. `clawfetch__clawfetch-mcp/src/index.ts:80`
# builds an unprotected Streamable HTTP transport through
#
#     const { StreamableHTTPServerTransport: StreamableTransport } =
#         await import('@modelcontextprotocol/sdk/server/streamableHttp.js');
#     const t = new StreamableTransport({ sessionIdGenerator: () => id });
#
# The file was scanned (a static `import type` from the SDK satisfied the MCP
# gate) and simply yielded no construction site. It was the worst miss in the
# audit: a 0.0.0.0 bind, no auth, no host validation.
#
# The resolver below is deliberately origin-gated. An alias counts only when
# the binding demonstrably comes from an `@modelcontextprotocol/` module —
# a named ESM import, a `require`, or a destructured dynamic `import()`. A
# same-named identifier from any other package, or from a local helper such
# as cellarion's `loadSdk()`, is NOT a transport and must never be treated as
# one; that is the whole reason `_MCP_IMPORT_PREFIX` exists.
# --------------------------------------------------------------------------

# `const { A: B, C } = await import('...')` / without `await`. Interior is
# brace-free by construction, so a nested pattern simply does not match and is
# skipped rather than mis-parsed.
_DYNAMIC_DESTRUCTURE_RE = re.compile(
    r"(?<![\w$])(?:const|let|var)\s*\{(?P<inner>[^{}]*)\}\s*=\s*"
    r"(?:await\s+)?import\s*\(\s*(?P<q>['\"])"
)

# `const SHT = StreamableHTTPServerTransport` / `= sdk.StreamableHTTPServerTransport`.
_PLAIN_ALIAS_RE = re.compile(
    r"(?<![\w$])(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=;\n]*)?=\s*"
    r"(?P<rhs>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*(?=[;\n)\]},]|\Z)"
)


def _string_at_quote(src: Source, quote_idx: int) -> str | None:
    """Raw contents of the string literal opening at `quote_idx`, or None.

    Local copy of jsparse's private helper so this module does not reach into
    another module's underscore namespace."""
    m = src.masked
    if quote_idx < 0 or quote_idx >= len(m) or m[quote_idx] not in "'\"":
        return None
    q = m[quote_idx]
    close = m.find(q, quote_idx + 1)
    if close == -1 or close - quote_idx > 512:
        return None
    body = src.text[quote_idx + 1:close]
    return None if "\n" in body else body


def _transport_aliases(src: Source) -> dict[str, str]:
    """Local names bound to an SDK HTTP transport class, alias -> class.

    Only bindings whose origin is provably an `@modelcontextprotocol/` module
    are included. Type-only imports are excluded: they bind no runtime value,
    so `new` on one cannot happen."""
    aliases: dict[str, str] = {}
    # namespace / default bindings of an MCP module, for `sdk.StreamableHTTP...`
    namespaces: set[str] = set()

    # (a) static named import with rename, and (b) destructured `require`
    #     with rename — jsparse.collect_imports already models both.
    for rec in jsparse.collect_imports(src):
        if not rec.module.startswith(_MCP_IMPORT_PREFIX):
            continue
        if rec.is_type_only or not rec.local:
            continue
        if rec.imported in _TRANSPORT_CLASSES:
            aliases[rec.local] = rec.imported
        elif rec.imported in ("*", "default"):
            namespaces.add(rec.local)

    # (c) destructured dynamic import with rename, with or without `await`.
    for mt in _DYNAMIC_DESTRUCTURE_RE.finditer(src.masked):
        module = _string_at_quote(src, mt.start("q"))
        if module is None or not module.startswith(_MCP_IMPORT_PREFIX):
            continue
        for part in mt.group("inner").split(","):
            p = part.strip()
            if not p:
                continue
            if ":" in p:
                imported, _, local = (x.strip() for x in p.partition(":"))
            else:
                imported = local = p
            if imported in _TRANSPORT_CLASSES and _IDENT_RE.match(local):
                aliases[local] = imported

    # (d) plain aliasing assignment. Two passes so `const A = SDKClass; const
    #     B = A;` resolves; a third hop is not worth the risk.
    for _ in range(2):
        grew = False
        for mt in _PLAIN_ALIAS_RE.finditer(src.masked):
            name = mt.group("name")
            if name in aliases:
                continue
            rhs = re.sub(r"\s+", "", mt.group("rhs"))
            parts = rhs.split(".")
            resolved: str | None = None
            if len(parts) == 1:
                resolved = aliases.get(parts[0])
            elif parts[-1] in _TRANSPORT_CLASSES and parts[0] in namespaces:
                resolved = parts[-1]
            if resolved is not None:
                aliases[name] = resolved
                grew = True
        if not grew:
            break

    # An alias that is just the class's own name adds nothing.
    return {k: v for k, v in aliases.items() if k != v}


def _shadowed_transport_names(src: Source) -> set[str]:
    """Transport class names this file provably binds to something that is NOT
    the MCP SDK.

    Second adversarial review. `_MCP_IMPORT_PREFIX` gates the FILE, not the
    BINDING, so a file that imports anything at all from the SDK and *also*
    has its own `StreamableHTTPServerTransport` — imported from another
    package, or declared locally — had that unrelated class reported as an
    unprotected SDK transport. Both shapes are correct code.

    Only demonstrable evidence disqualifies a name: a same-named import from a
    non-`@modelcontextprotocol/` module, or a same-named local `class` /
    `function` declaration. A name the SDK also binds is never disqualified, so
    a file that imports the real class keeps firing."""
    mcp_bound: set[str] = set()
    other_bound: set[str] = set()
    for rec in jsparse.collect_imports(src):
        if not rec.local or rec.local not in _TRANSPORT_CLASSES:
            continue
        if rec.module.startswith(_MCP_IMPORT_PREFIX):
            mcp_bound.add(rec.local)
        else:
            other_bound.add(rec.local)
    # A local declaration of the same name. Restricted to `class` / `function`
    # — a `const` of that name is how a CommonJS or dynamic-import re-binding
    # of the REAL SDK class is spelled, and disqualifying those would silence
    # genuine findings.
    for name, binding in jsparse.collect_bindings(src).items():
        if name in _TRANSPORT_CLASSES and binding.kind in ("class", "function"):
            other_bound.add(name)
    return other_bound - mcp_bound


def _should_skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _file_imports_mcp_sdk(src: Source) -> bool:
    """True if the file imports anything from `@modelcontextprotocol/`.

    Type-only imports count — they prove MCP context. Without this gate a
    project's own class called `SSEServerTransport` would be flagged as an
    SDK transport."""
    for rec in jsparse.collect_imports(src):
        if rec.module.startswith(_MCP_IMPORT_PREFIX):
            return True
    return False


def _repo_has_auth(sources: list[Source]) -> bool:
    for src in sources:
        whole = jsparse.Span(0, len(src.masked))
        # `contains_token` already runs against the mask, so a token inside a
        # comment or a string never reaches here. The two header/query regexes
        # must run against RAW text (the header name usually lives inside a
        # string literal, whose interior the mask blanks), so they carry their
        # own liveness test — see DEFECT 3 above.
        if jsparse.contains_token(src, whole, _AUTH_TOKENS):
            return True
        if _live_matches(src, _AUTH_HEADER_RE):
            return True
        if _live_matches(src, _AUTH_QUERY_RE):
            return True
        for mt in _AUTH_DESTRUCTURE_RE.finditer(src.masked):
            if _AUTH_DESTRUCTURE_NAMES.search(mt.group("inner")):
                return True
    return False


def _repo_has_host_guard(sources: list[Source], *, tokens: frozenset[str] | set[str] | None = None) -> bool:
    use = _HOST_GUARD_TOKENS if tokens is None else tokens
    for src in sources:
        whole = jsparse.Span(0, len(src.masked))
        if jsparse.contains_token(src, whole, use):
            return True
        for m in _live_matches(src, _HOST_HEADER_RE):
            # DEFECT 2: a bare read is not a guard. The value has to be
            # tested against something.
            if _host_read_is_a_guard(src, m.start(), m.end()):
                return True
        for mt in _HOST_DESTRUCTURE_RE.finditer(src.masked):
            if _HOST_DESTRUCTURE_NAMES.search(mt.group("inner")):
                return True
    return False


def _options_object(src: Source, site: jsparse.CallSite, cls: str,
                    bindings: dict[str, jsparse.Binding]) -> tuple[ObjectLiteral | None, bool]:
    """(options literal, resolvable).

    `cls` is the *canonical* SDK class name — `site.method` may be a local
    alias, and the positional index of the options argument belongs to the
    class, not to whatever the author called it.

    `resolvable` False means the argument exists but we could not see it as
    an object literal — an identifier from another module, a call, a
    conditional. Those sites are suppressed rather than guessed at."""
    index = _OPTIONS_ARG_INDEX.get(cls)
    if index is None:
        return None, False

    args = list(site.args)
    # rule R1: a trailing comma yields a trailing empty span.
    while args and src.trimmed(args[-1]).is_empty():
        args.pop()
    if index >= len(args):
        # No options argument at all: `new SSEServerTransport('/m', res)` or
        # `new StreamableHTTPServerTransport()`. Nothing is configured.
        return None, True

    span = src.trimmed(args[index])
    if span.is_empty():
        return None, True

    obj = jsparse.parse_object(src, span)
    if obj is None:
        # A bare identifier may still resolve to a same-file literal.
        name = src.code(span)
        if _IDENT_RE.match(name):
            target = jsparse.resolve_span(src, name, bindings)
            if target is not None:
                obj = jsparse.parse_object(src, target)
    if obj is None or not obj.ok:
        return None, False
    return obj, True


def _is_true_literal(src: Source, entry: jsparse.ObjectEntry) -> bool:
    return src.code(src.trimmed(entry.value_span)).strip() == "true"


def _class_label(cls: str) -> str:
    return f"`{cls}`"


def _remediation() -> str:
    return (
        "Configure the transport with both lists: "
        "`new StreamableHTTPServerTransport({ sessionIdGenerator, "
        "enableDnsRebindingProtection: true, allowedHosts: ['127.0.0.1:3000', "
        "'localhost:3000'], allowedOrigins: ['http://127.0.0.1:3000'] })`. On "
        "SDK >= 1.24.0 you can instead build the app with "
        "`createMcpExpressApp(...)` (or the Hono / Fastify equivalent), which "
        "arms host validation by default on a localhost bind, or mount "
        "`hostHeaderValidation()` ahead of the transport. Upgrading the SDK "
        "alone does not arm this: the advisory's fix is the app-builder / "
        "middleware path above, and constructing the transport directly still "
        "leaves the option defaulted to `false`. If this endpoint already sits behind "
        "authentication, put that check somewhere the scanner can see it — "
        "this check suppresses entirely when it finds one."
    )


def _build_finding(path: Path, cls: str, line: int, kind: str) -> Finding:
    if kind == "noop_protection":
        message = (
            f"{_class_label(cls)} sets `enableDnsRebindingProtection: true` but "
            "configures neither `allowedHosts` nor `allowedOrigins`, and no "
            "authentication check was found in this repository. In the SDK's "
            "`validateRequestHeaders()` both checks are guarded by a `length > 0` "
            "test, so with both lists empty the function falls through and every "
            "request passes. The protection is a complete no-op while reading as "
            "enabled — the SDK's own JSDoc says the option \"requires allowedHosts "
            "and/or allowedOrigins to be configured\"."
        )
    else:
        message = (
            f"{_class_label(cls)} is constructed here with no DNS-rebinding "
            "protection, and no authentication check was found anywhere in this "
            "repository. `enableDnsRebindingProtection` defaults to `false` on "
            "the transport constructor, so the transport accepts any `Host` and "
            "any `Origin` header (GHSA-w48q-cv73-mx4w / CVE-2025-66414, CVSS "
            "7.6 by the v4.0 vector; the advisory lists 1.24.0 as the first "
            "patched release). A page the user "
            "visits can re-point its own hostname at 127.0.0.1, call this endpoint "
            "as same-origin, and read the responses, which hands it `tools/list` "
            "and `tools/call` at the server's own local privilege. Binding to "
            "localhost does not mitigate this — the victim's browser is already on "
            "the loopback interface — and a CORS allow-list never runs, because "
            "after rebinding the request is genuinely same-origin."
        )
    return Finding(
        check=CHECK_ID,
        severity=Severity.HIGH,
        path=path,
        line=line,
        message=message,
        remediation=_remediation(),
    )


_Site = tuple[jsparse.CallSite, ObjectLiteral | None, bool, str]


def _sites(src: Source) -> list[_Site]:
    """Transport construction sites in one file, with their options object.

    Returns [] unless the file imports from the MCP SDK. One entry per
    `new <Transport>(...)`; the file that builds two transports yields two.
    The fourth tuple element is the canonical SDK class name, which differs
    from `site.method` when the binding was renamed (DEFECT 1)."""
    if not src.ok:
        return []
    if not _file_imports_mcp_sdk(src):
        return []
    aliases = _transport_aliases(src)
    shadowed = _shadowed_transport_names(src)
    wanted = (set(_TRANSPORT_CLASSES) - shadowed) | set(aliases)
    constructions = jsparse.find_constructions(src, wanted)
    if not constructions:
        return []
    bindings = jsparse.collect_bindings(src)
    out: list[_Site] = []
    for site in constructions:
        cls = aliases.get(site.method, site.method)
        if cls not in _TRANSPORT_CLASSES:
            continue
        obj, resolvable = _options_object(src, site, cls, bindings)
        out.append((site, obj, resolvable, cls))
    return out


def check(root: Path) -> list[Finding]:
    sources: list[Source] = []
    for path in jsparse.iter_source_files(root):
        if _should_skip(path):
            continue
        src = jsparse.load(path)
        # HARD contract: a file the lexer could not walk is unusable, and a
        # degraded lex must never produce a finding.
        if src is not None and src.ok:
            sources.append(src)
    if not sources:
        return []

    # Condition 2, repo-wide and unconditional: an authenticated endpoint is
    # not reachable by a drive-by page, so neither variant can fire.
    if _repo_has_auth(sources):
        return []

    per_file: list[tuple[Source, list[_Site]]] = []
    for src in sources:
        sites = _sites(src)
        if sites:
            per_file.append((src, sites))
    # Condition 1: no HTTP transport anywhere => stdio-only server => silent.
    if not per_file:
        return []

    findings: list[Finding] = []

    # The `noop_protection` variant runs FIRST and per-site, because the very
    # token that proves the bug (`enableDnsRebindingProtection`) is also a
    # repo-level host-guard signal; running the repo gate first would make
    # this variant unreachable.
    # Keyed on (file, byte offset of the `new`), not on the line: two
    # constructions can share a line and must not shadow each other.
    noop_sites: set[tuple[str, int]] = set()
    noop_allowed = not _repo_has_host_guard(
        sources, tokens=_HOST_GUARD_TOKENS_INDEPENDENT)
    for src, sites in per_file:
        for site, obj, resolvable, cls in sites:
            if obj is None or not resolvable:
                continue
            if obj.has_spread:
                continue
            entry = obj.get("enableDnsRebindingProtection")
            if entry is None or not _is_true_literal(src, entry):
                continue
            if any(obj.get(k) is not None for k in sorted(_ALLOW_LIST_KEYS)):
                continue
            # Recorded even when suppressed, so the plain variant below does
            # not re-report the same site under a different (wrong) message.
            noop_sites.add((str(src.path), site.call_span.start))
            if not noop_allowed:
                continue
            findings.append(_build_finding(src.path, cls, site.line,
                                           "noop_protection"))

    # Condition 3, repo-wide: any host/origin awareness at all, even partial
    # or wrong, suppresses the plain `no_protection` variant.
    if _repo_has_host_guard(sources):
        return findings

    for src, sites in per_file:
        for site, obj, resolvable, cls in sites:
            if not resolvable:
                # Options we cannot see as a literal — a library re-exporting
                # configurability to its caller. Not a deployed server.
                continue
            if obj is not None and obj.has_spread:
                continue
            if obj is not None and any(obj.get(k) is not None
                                       for k in sorted(_PROTECTION_KEYS)):
                continue
            if (str(src.path), site.call_span.start) in noop_sites:
                continue
            findings.append(_build_finding(src.path, cls, site.line,
                                           "no_protection"))
    return findings
