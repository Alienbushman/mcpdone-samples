# mcp-audit

Static security + correctness audit for MCP server repos.

```bash
pip install mcp-audit
mcp-audit                     # scan the current directory
mcp-audit /path/to/repo       # scan a specific repo
mcp-audit --json              # machine-readable output
mcp-audit --check fastmcp_wrapper_layer  # one check only
mcp-audit --list-checks       # list available checks
```

Exit codes: **0** clean, **1** at least one finding, **2** usage error.

## What it checks

| Check ID                  | What it finds                                                                                                  |
|---------------------------|----------------------------------------------------------------------------------------------------------------|
| `starlette_badhost`       | Starlette < 1.0.1 in `pyproject.toml`, `requirements*.txt`, `uv.lock`, `poetry.lock`, `pdm.lock`. **BadHost** (CVE-2026-48710) lets a crafted HTTP `Host` header bypass path-based authorization. Affects any HTTP/SSE-transport MCP server. Stdio servers are unaffected. |
| `fastmcp_wrapper_layer`   | Sync `@mcp.tool()` functions that call `asyncio.run(...)` inside their body. FastMCP invokes tools inside an already-running event loop; `asyncio.run()` raises `RuntimeError`. Looks fine in unit tests, dies on the first real protocol call. |

More checks are landing — loose input schemas, hard-coded secrets, write-API tools missing a `FORBIDDEN_NAMES`-style guardrail, read-only-by-default violations.

## Output format

```
$ mcp-audit examples/bad/
[HIGH  ] starlette_badhost @ uv.lock
           uv lockfile pins starlette==0.36.3 — vulnerable to BadHost (CVE-2026-48710). Patched in 1.0.1.
           -> Upgrade Starlette to >=1.0.1 (the BadHost patch). If FastAPI pulls Starlette transitively, pin it explicitly. ...

[HIGH  ] fastmcp_wrapper_layer @ server.py:18
           tool 'fetch_url' (def) calls asyncio.run() inside its body. FastMCP invokes tools inside an already-running event loop, and asyncio.run() raises RuntimeError when nested. This will fail at the first real MCP protocol call even if every unit test passes.
           -> Convert the tool to `async def` and replace `asyncio.run(...)` with `await`. ...

mcp-audit: 2 finding(s) — 2 high
```

`--json` emits one object: `{"root": "...", "finding_count": N, "findings": [...]}`. Each finding has `check`, `severity`, `path`, `line`, `message`, `remediation`.

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
