# mcp-audit

Static security + correctness audit for MCP server repos, in **Python and TypeScript/JavaScript**.

```bash
pip install mcp-audit
mcp-audit                     # scan the current directory
mcp-audit /path/to/repo       # scan a specific repo
mcp-audit --json              # machine-readable output
mcp-audit --check fastmcp_wrapper_layer  # one check only
mcp-audit --list-checks       # list available checks
```

Exit codes: **0** clean, **1** at least one finding, **2** usage error, **3** nothing examined.

### "0 findings" is not the same as "0 files"

A scanner that cannot tell those apart is worse than no scanner, because it
issues a clean bill of health for code it never opened. `mcp-audit` has
shipped that bug twice, so it now reports how many files it read and exits
**3** when that number is zero:

```
$ mcp-audit ./docs
mcp-audit: examined 0 files under ./docs - nothing here to audit. This is NOT
a clean result: no Python or TypeScript source and no dependency manifest was
found. Check the path, or pass --allow-empty if that is expected.

$ mcp-audit ./server
mcp-audit: OK - 0 findings across 34 file(s) under ./server
```

Pass `--allow-empty` to exit 0 instead, where a repo legitimately holds no
auditable code. In the GitHub Action, exit 3 fails the job *even in
report-only mode*: a green check that read nothing is the worst result the
action can produce.

Related: build directories (`dist`, `build`, `out`) are skipped as generated
residue, **unless nothing else is there**. A published npm package ships
`package/dist/*.js` and no sources at all, so pointing `mcp-audit` at an
extracted tarball scans the compiled output and says so. Because the
fallback is reachable only from an otherwise-empty scan, it can never add
noise to a repo that has real sources.

## What it checks

| Check ID                  | Severity   | What it finds                                                                                                  |
|---------------------------|------------|----------------------------------------------------------------------------------------------------------------|
| `starlette_badhost`       | HIGH / MED | Starlette < 1.0.1 in `pyproject.toml`, `requirements*.txt`, `uv.lock`, `poetry.lock`, `pdm.lock`. **BadHost** (CVE-2026-48710) lets a crafted HTTP `Host` header bypass path-based authorization. Affects any HTTP/SSE-transport MCP server. Stdio servers are unaffected. |
| `fastmcp_wrapper_layer`   | HIGH       | Sync `@mcp.tool()` functions that call `asyncio.run(...)` inside their body. FastMCP invokes tools inside an already-running event loop; `asyncio.run()` raises `RuntimeError`. Looks fine in unit tests, dies on the first real protocol call. |
| `tool_input_validation`   | LOW        | `@mcp.tool()` parameters typed as bare `str` / `bytes` / `Any` / `list[Any]` / `dict[..., Any]` or with no annotation at all. The schema FastMCP exposes to the LLM is the substrate prompt-injection-via-tool-description attacks rely on; constraining it (`Annotated[str, Field(max_length=N)]`, `Literal[...]`, Pydantic models) closes the window without losing expressiveness. Hygiene check, not a CVE — expect findings even on well-written servers. *Added in v0.2.* |
| `command_injection`       | HIGH       | `@mcp.tool()` functions where a tool parameter (or a local tainted via assignment / `.format()` / string concat) flows into `os.system`, `os.popen`, or `subprocess.*` with `shell=True` or a tainted-interpolated command string. **v0.4 added same-file cross-function taint propagation**: the analyzer now follows local helper calls (positional + keyword binding, recursion-visited guard), so `tool -> helper -> sink` flows are caught. Cross-file taint remains out of scope. The list-of-args / no-shell pattern is correctly NOT flagged. *Added in v0.3, cross-function in v0.4.* |
| `destructive_fs_sink`     | MEDIUM     | `@mcp.tool()` functions where a tool parameter flows into a destructive filesystem call — `shutil.rmtree`, `os.remove` / `os.unlink` / `os.rmdir` / `os.removedirs`, or `Path.unlink()` / `Path.rmdir()` — with no path-containment guard, letting a caller delete arbitrary paths the server can reach. Suppressed when the function canonicalizes-and-confines the path (`realpath`/`resolve` + `startswith`/`relative_to`) or checks it against a server-managed allow-set — a deliberate false-negative bias. Found the unguarded `shutil.rmtree(directory)` in `manim-mcp-server`'s `cleanup_manim_temp_dir` that the other four checks all miss. *Added in v0.7.* |
| `sql_readonly_keyword_guard` | MEDIUM  | `@mcp.tool()` functions that enforce "read-only" / safe SQL by inspecting the query **string** for keywords (allow only queries starting with `SELECT`/`WITH`, or block `INSERT`/`UPDATE`/`DELETE` by substring) and then execute a tool-parameter query. Keyword / prefix filters are not a security boundary: a `WITH`-prefixed statement, a comment, casing, or `ATTACH` slips a write past them. Fix is connection-level read-only (`mode=ro`, `PRAGMA query_only=ON`, a SELECT-only role). Recognizes the exact anti-pattern behind the 2026 `sqlite-explorer-fastmcp` read-only bypass; does **not** fire on arbitrary-SQL tools (no guard to be weak) or on connection-level read-only (the correct pattern). *Added in v0.8.* |

| `ts_dns_rebinding`        | HIGH       | **TypeScript.** `StreamableHTTPServerTransport` / `SSEServerTransport` constructed without DNS-rebinding protection, in a repo with no authentication check. `enableDnsRebindingProtection` defaults to `false` on the constructor (GHSA-w48q-cv73-mx4w / CVE-2025-66414, CVSS 7.6), so the transport accepts any `Host` and any `Origin`. A page the victim visits can re-point its own hostname at 127.0.0.1 and call the endpoint as same-origin, reaching `tools/list` and `tools/call` at local privilege. Binding to localhost does not mitigate it, and CORS never runs. Suppressed by `enableDnsRebindingProtection: true` + `allowedHosts`/`allowedOrigins`, by an independent host gate or `hostHeaderValidation()`, by any repo-wide auth check, and entirely for stdio-only servers. *Added in v0.9.* |
| `ts_command_injection`    | HIGH       | **TypeScript.** An MCP tool parameter reaching `child_process.exec`/`execSync`, or spliced into a shell command string, or landing in the executable position. The safe array-argv-without-`shell: true` pattern is correctly **not** flagged, and a value is only counted when the splice is visible (a template hole, a `+` concat, or the raw parameter) — an allow-list table lookup does not fire. *Added in v0.9.* |
| `ts_destructive_fs_sink`  | MEDIUM     | **TypeScript.** An MCP tool parameter reaching `fs.rm`/`rmSync`/`unlink`/`rmdir`/`promises.rm` or `rimraf` with no path-containment guard. Suppressed by canonicalize-and-confine (`path.resolve` + `startsWith`/`relative`), by an allow-set, by a closed-set schema (`z.enum`/`literal`/`number`) that cannot express traversal, and when the path came back from an opaque call rather than from the caller. *Added in v0.9.* |
| `ts_tool_input_validation`| LOW        | **TypeScript.** MCP tool input schemas that constrain nothing: `z.any()`, a bare `z.string()` with no length/pattern/format, a handler parameter typed `any`, or a `registerTool` whose handler destructures arguments it never declared. Recognizes constraint methods by exclusion — only provably transparent wrappers (`.describe()`, `.optional()`, `.default()`, …) count as unconstrained — so new zod formats degrade to false negatives, not false positives. Hygiene, not a vulnerability: expect findings on well-written servers. *Added in v0.9.* |

### Two engines, one scan

The six checks above the divider read Python via `ast`; the four `ts_`-prefixed checks read TypeScript/JavaScript
via a stdlib-only masking lexer (`mcp_audit.jsparse`). Both engines run on every scan — a repo may contain both, and
a scanner that silently skipped one language would hand back a clean bill of health it had not earned. Before v0.9
that is exactly what `mcp-audit` did to every TypeScript MCP server: `OK — 0 findings`, without opening a file.

There is no parser dependency and never will be one: `pip install mcpdone-audit` must not pull node, tree-sitter, or
a wasm blob. The lexer instead produces a *masked* copy of the source, byte-for-byte the same length, with comments
and string contents blanked so offsets and line numbers stay exact. Template-literal `${...}` holes stay live, since
`` exec(`git checkout ${branch}`) `` is the shape the injection check exists to find. When the lexer cannot walk a
file cleanly it marks it degraded and every check returns nothing for it — a mis-lexed file must never produce a
finding.

More checks are landing — hard-coded secrets leaked into tool output, write-API tools missing a `FORBIDDEN_NAMES`-style guardrail, path traversal in filesystem-touching servers, and SSRF via tool-controlled URLs.

## Output format

```
$ mcp-audit examples/bad/
[HIGH  ] starlette_badhost @ uv.lock
           uv lockfile pins starlette==0.36.3 — vulnerable to BadHost (CVE-2026-48710). Patched in 1.0.1.
           -> Upgrade Starlette to >=1.0.1 (the BadHost patch). If FastAPI pulls Starlette transitively, pin it explicitly. ...

[HIGH  ] fastmcp_wrapper_layer @ server.py:18
           tool 'fetch_url' (def) calls asyncio.run() inside its body. FastMCP invokes tools inside an already-running event loop, and asyncio.run() raises RuntimeError when nested. This will fail at the first real MCP protocol call even if every unit test passes.
           -> Convert the tool to `async def` and replace `asyncio.run(...)` with `await`. ...

mcp-audit: 2 finding(s) — 2 high across 11 file(s)
```

`--json` emits one object: `{"root": "...", "finding_count": N, "files_examined": N, "scanned_build_output": false, "findings": [...]}`. Each finding has `check`, `severity`, `path`, `line`, `message`, `remediation`.

`files_examined` is there so a consumer can assert the scan actually read
something rather than trusting `finding_count: 0`.

## Use in CI (GitHub Action)

Drop MCP security scanning into any repo's CI. The job fails on findings (exit 1); flip `fail-on-findings` for a report-only gate.

```yaml
# .github/workflows/mcp-audit.yml
name: mcp-audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Alienbushman/mcpdone-samples/mcp-audit@mcp-audit-v0.9
        with:
          path: .                 # dir to scan (default '.')
          # version: 0.8.0        # pin the mcpdone-audit release (default: latest)
          # package: ./mcp-audit  # any pip spec: local path, VCS ref, private mirror
          # args: --check command_injection
          # fail-on-findings: false   # report-only: annotate but keep the job green
```

The action exposes a `finding-count` output for downstream steps. It wraps the same `mcpdone-audit` PyPI package, so local runs and CI runs are identical. Prefer pinning `version:` in CI for reproducibility.

A scan that examines **0 files** fails the job (exit 3) even with
`fail-on-findings: false`, because a green check that read nothing is worse
than a red one. Pass `--allow-empty` via `args` where that is expected.

`package:` overrides `version:` and takes any pip install spec. It exists
because the action installs from PyPI by default, which means nothing can
exercise a fix that has not been released yet. This repo's own self-test
hit exactly that: three new assertions failed against the published 0.9.0
while the repo was already fixed. Same shape as the bug above, one layer
out.

You can also run it via [pre-commit](https://pre-commit.com/) or as a plain `pip install mcpdone-audit && mcp-audit` step in any pipeline.

## What this is not

- It is **not** a runtime sandbox. Static analysis only.
- It does **not** install your venv to introspect it. It reads what's declared (manifests + lockfiles + source).
- It will not detect every vulnerability — only the classes its checks know about. Treat zero findings as "no known issues from this tool," not as a clean bill.

## Background

- BadHost write-up: https://mcpdone.com/blog/badhost-mcp-servers
- FastMCP wrapper-layer bug write-up: https://mcpdone.com/blog/fastmcp-wrapper-layer-bug

## Development

```bash
git clone https://github.com/Alienbushman/mcpdone-samples
cd mcpdone-samples/mcp-audit
pip install -e ".[dev]"
pytest
python smoke_test.py
```

To add a check: drop `src/mcp_audit/checks/<name>.py` exposing a module-level `CHECK_ID` and a `check(root: Path) -> list[Finding]` callable. Register it in `src/mcp_audit/checks/__init__.py`. Add fixtures + tests under `tests/`.

## License

MIT.
