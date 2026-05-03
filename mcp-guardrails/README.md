# mcp-guardrails

Lint hooks + tests for the bug classes that bite production MCP servers.

Built because we shipped one of those bugs ourselves.

## What's here

### `check_mcp_tool_async.py`

A static-analysis lint that forbids `asyncio.run()` inside any `@mcp.tool()`-decorated function.

**Why:** When FastMCP invokes a tool, it does so inside its own already-running event loop. A sync `@mcp.tool()` that calls `asyncio.run()` to drive async work raises:

```
RuntimeError: asyncio.run() cannot be called from a running event loop
```

…on the very first protocol call. The bug is invisible to unit tests that exercise the inner functions directly (no outer loop), and surfaces only when the MCP runtime drives the tool. This is exactly how we shipped this bug in our own twitter-reader MCP on 2026-04-30 — 42 unit tests passed, then died at the first MCP call.

The fix is always the same: convert the tool to `async def` and use `await` directly.

```python
# BROKEN — looks fine in unit tests, raises under FastMCP
@mcp.tool()
def my_tool() -> dict:
    return asyncio.run(_inner_async_work())

# FIXED — async def + await
@mcp.tool()
async def my_tool() -> dict:
    return await _inner_async_work()
```

### Usage

```bash
# Scan all *server*.py files under the current directory
python check_mcp_tool_async.py

# Scan specific files (e.g., as a pre-commit hook)
python check_mcp_tool_async.py path/to/server.py

# Demo: catch the bug in the fixture
python check_mcp_tool_async.py test_fixtures/buggy_server.py
# → exit code 1, points to the sync @mcp.tool() that calls asyncio.run()
```

Exit codes: `0` clean, `1` violations found, `2` script error.

### `test_fixtures/buggy_server.py`

A minimal MCP server containing exactly the anti-pattern, for verifying the lint works. The fixture file is **NOT** runnable as a real MCP server — it's a static demonstration.

## When this matters

Sync `@mcp.tool()` is fine when the tool wraps sync code (sqlite3, imaplib, pure CPU). FastMCP runs sync tools in a thread executor without issue. The lint targets the specific anti-pattern of nesting `asyncio.run()` inside any tool, regardless of whether that tool is `def` or `async def`.

If your project's tools all do async work and should all be `async def` by convention, add a project-level test that uses `inspect.iscoroutinefunction` to enforce it. The cross-project lint here is intentionally narrow — only the bug class, not the convention.

## Wiring as a pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: check-mcp-tool-async
      name: No asyncio.run() inside @mcp.tool()
      entry: python path/to/check_mcp_tool_async.py
      language: system
      files: '.*server.*\.py$'
      pass_filenames: true
```

Or wire to CI as a separate step that fails the build:

```yaml
- name: Lint MCP wrapper layer
  run: python mcp-guardrails/check_mcp_tool_async.py
```

## Why this exists as its own thing

When we sell custom MCP servers (`$499 Build` tier at [mcpdone.com](https://mcpdone.com)), the difference between a working delivery and a broken one is often a wrapper-layer bug like this — the kind that passes every unit test you'd think to write. Our service-delivery SOP now requires this lint to pass before a customer MCP server ships. Open-sourcing it because you should run it on yours too.

## Related

- [Anthropic MCP docs](https://modelcontextprotocol.io/docs)
- [`mcp-content-opportunity/`](../mcp-content-opportunity/), [`mcp-gmail-reader/`](../mcp-gmail-reader/), [`mcp-sqlite-query/`](../mcp-sqlite-query/) — the three sample MCP servers in this repo, all linted clean

MIT licensed. Same as the rest of the repo.
