# mcp-guardrails

Lint hooks + tests for the bug classes that bite production MCP servers.

Built because we shipped one of those bugs ourselves, then realised the broader pattern.

## What's here

### `lint_mcp_server.py` — the comprehensive linter (recommended)

Runs every check in this toolkit against any FastMCP-shaped `*server*.py` file. Each check targets a specific bug class we've shipped or seen shipped in production. Static analysis only — no network, no dependencies beyond the Python stdlib.

**Four checks currently:**

| Check ID | Catches | Why |
|---|---|---|
| `NO_ASYNCIO_RUN_INSIDE_MCP_TOOL` | `@mcp.tool()` functions calling `asyncio.run()` | FastMCP runs tools inside its own event loop; nested `asyncio.run()` raises `RuntimeError` at first call. Passes unit tests, dies in production. |
| `TOOL_DOCSTRING_LENGTH` | tools with missing or <3-sentence docstrings | Docstrings are the schema the model sees. Short or absent → model calls the tool with wrong args, fails confusingly. |
| `TOOL_PARAMS_TYPED` | tools with untyped parameters | JSON-Schema generation depends on type annotations. Untyped → schema field is unconstrained → model passes whatever shape it feels like. |
| `TOOL_NO_BLOCKING_SLEEP` | `time.sleep(...)` inside any `@mcp.tool()` body | In a sync tool, `time.sleep` blocks the server's event loop for every other request. Use `await asyncio.sleep(...)` instead. |

**Usage:**

```bash
# Lint all FastMCP server.py files under the current directory
python lint_mcp_server.py

# Lint specific files (pre-commit hook style)
python lint_mcp_server.py path/to/server.py path/to/other.py

# Skip a specific check
python lint_mcp_server.py --skip TOOL_NO_BLOCKING_SLEEP

# Output as JSON (for CI integration)
python lint_mcp_server.py --format json
```

Exit codes: `0` clean, `1` violations found, `2` script error.

Run the tests on the toolkit itself:

```bash
python test_lint.py
# → 5 tests pass, each verifying a check catches its target fixture
```

### `check_mcp_tool_async.py` — legacy single-purpose version

The original lint, runs only `NO_ASYNCIO_RUN_INSIDE_MCP_TOOL`. Kept for backward compatibility with existing links and pre-commit hooks. New projects should use `lint_mcp_server.py` for the full check suite.

```bash
python check_mcp_tool_async.py [path/to/server.py]
```

### `test_fixtures/`

Each fixture file demonstrates ONE anti-pattern, alongside a "good" reference showing the correct shape side-by-side. Useful as copy-paste references AND as the test corpus for `test_lint.py`.

- `buggy_server.py` — `NO_ASYNCIO_RUN_INSIDE_MCP_TOOL`
- `missing_docstring.py` — `TOOL_DOCSTRING_LENGTH`
- `untyped_params.py` — `TOOL_PARAMS_TYPED`
- `blocking_sleep.py` — `TOOL_NO_BLOCKING_SLEEP`

Each fixture contains both a broken tool and a fixed reference tool. The lint flags exactly the broken ones and passes the fixed ones.

## When the checks fire vs. when they don't

Each check is intentionally narrow — none of them ban legitimate patterns, only specific anti-patterns:

- **`NO_ASYNCIO_RUN_INSIDE_MCP_TOOL`** fires on `asyncio.run()` inside any `@mcp.tool()` regardless of sync/async. Sync `@mcp.tool()` is FINE when it wraps sync code (sqlite3, imaplib, pure CPU); FastMCP runs sync tools in a thread executor. The bug is the *combination* of sync wrapper + nested loop.
- **`TOOL_DOCSTRING_LENGTH`** fires if docstring is missing or has <3 sentences (counted via `.`, `!`, `?` followed by whitespace). Imperfect but catches the common failures: missing docstring, one-liner, vague description. Three sentences is a minimum bar; longer is almost always better.
- **`TOOL_PARAMS_TYPED`** fires if any positional or keyword-only parameter lacks an annotation. Doesn't enforce specific types, just that there IS one.
- **`TOOL_NO_BLOCKING_SLEEP`** fires on `time.sleep(...)` calls anywhere in the tool body. There's no scenario where this is the right answer in an MCP tool — `await asyncio.sleep(...)` always wins.

## Wiring as a pre-commit hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: lint-mcp-server
      name: Lint MCP server files
      entry: python path/to/lint_mcp_server.py
      language: system
      files: '.*server.*\.py$'
      pass_filenames: true
```

Or wire to CI as a build-fail step:

```yaml
- name: Lint MCP wrapper layer
  run: python mcp-guardrails/lint_mcp_server.py
```

Both run in milliseconds. The cost-benefit is absurdly favourable.

## Why this exists as its own thing

When we sell custom MCP servers ([`$499 Build`](https://mcpdone.com#tiers) tier at mcpdone.com), the difference between a working delivery and a broken one is usually a layer-3 wrapper-layer bug — the kind that passes every unit test you'd think to write. Our service-delivery SOP now requires these checks to pass before a customer MCP server ships. Open-sourcing the toolkit because you should run it on yours too.

Three of the four checks are derived from real bugs we either shipped ourselves or saw in client codebases. The fourth (`TOOL_NO_BLOCKING_SLEEP`) is preventive — we haven't shipped it, but we've reviewed code that has, and the failure mode is silently degraded throughput.

## Related

- [The FastMCP wrapper-layer bug your unit tests won't catch](https://mcpdone.com/blog/fastmcp-wrapper-layer-bug) — the long-form story behind `NO_ASYNCIO_RUN_INSIDE_MCP_TOOL`
- [Testing FastMCP servers: the layer hierarchy your unit tests miss](https://mcpdone.com/blog/testing-fastmcp-servers) — the four-layer taxonomy and why each layer needs its own tests
- [What we learned shipping our first 4 MCP servers](https://mcpdone.com/blog/shipping-four-mcp-servers) — the broader synthesis, including most of the principles these checks encode
- [Anthropic MCP docs](https://modelcontextprotocol.io/docs)
- [`mcp-content-opportunity/`](../mcp-content-opportunity/), [`mcp-gmail-reader/`](../mcp-gmail-reader/), [`mcp-sqlite-query/`](../mcp-sqlite-query/) — the three sample MCP servers in this repo, all linted clean

MIT licensed. Same as the rest of the repo.
