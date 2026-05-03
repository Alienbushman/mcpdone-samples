# mcpdone-samples

Open-source reference samples from **[mcpdone](https://mcpdone.com)** — a consultancy that builds custom Claude Code setups (MCP servers, skills, hooks, team rollouts).

Everything in this repo is what a paying client actually receives — same code quality, same test coverage, same documentation shape.

## What's inside

### Three MCP servers — the shape of a `$499 Build` delivery

Each one is a standalone Python project, MIT-licensed, with its own README + test suite. Install with `uv sync`, run tests with `uv run pytest`.

- **[`mcp-content-opportunity/`](mcp-content-opportunity/)** — HTTP/API integration. Searches Hacker News + Reddit, ranks discussions by 5 explainable heuristics (engagement, recency, question-intensity, comment-to-score ratio, pain keywords). **22 tests.** Live smoke test verified against real APIs. 4 MCP tools.

- **[`mcp-sqlite-query/`](mcp-sqlite-query/)** — Local database. Read-only access to any SQLite file, with two independent safety layers (SQL-shape check + driver-level `mode=ro`). Enforced row cap. Injection-protected table names. **46 tests.** 4 MCP tools.

- **[`mcp-gmail-reader/`](mcp-gmail-reader/)** — Live business integration. Scope-locked Gmail — drives mcpdone's own sales inbox. Reads a single Gmail label, drafts replies to the Drafts folder. No send capability, no delete capability, anywhere in the code. **55 tests.** 6 MCP tools.

### Sample `$299 Audit` deliverable

- **[`sample-audit/self_audit.md`](sample-audit/self_audit.md)** — full 7-section audit of a real Claude Code setup (the one that produced these samples). Includes executive summary, gap analysis, security review, prioritised action list. This is exactly the template paying Audit clients receive.

- **[`sample-audit/drop-in/`](sample-audit/drop-in/)** — copy-paste configuration bundle the audit recommends. `settings.json` with allow/deny lists, `CLAUDE.md` template, `.mcp.json` wiring, pre-tool-use + post-tool-use hooks, slash commands. MIT-licensed — use it on your own repo.

- **[`sample-audit/self_audit.html`](sample-audit/self_audit.html)** — rendered HTML version of the audit report, printable to PDF via any browser.

### Production-MCP guardrails

- **[`mcp-guardrails/`](mcp-guardrails/)** — lint hooks for the bug classes that bite production MCP servers. Currently ships `check_mcp_tool_async.py`, which catches the `asyncio.run() inside @mcp.tool()` anti-pattern that broke our own twitter-reader MCP at first call (despite 42 passing unit tests). Includes a fixture file demonstrating the bug. Wire as a pre-commit hook or CI step. Our service-delivery SOP requires this lint to pass before any customer MCP server ships.

## How we ship this kind of thing

If your team wants something in the shape of these samples — custom MCP server wired to your internal tools, an audit of your current Claude Code setup, or a full team rollout — that's what we do:

| Tier | Price | Turnaround | What you get |
|---|---|---|---|
| Audit | $299 | 48 hours | PDF report + drop-in configs + skills, tailored to your stack |
| Build | $499 | 5 days | One custom MCP server with tests, docs, 30-day support |
| Team Setup | $999 | 7–10 days | Full Claude Code rollout for 5–30 engineers |

**Every tier includes a money-back guarantee if the shipped code doesn't run in a clean environment.**

First 3 clients: 40% off in exchange for a public testimonial.

**→ [mcpdone.com](https://mcpdone.com)** for details + intake form.

## Running the samples

Each sample project has its own full README with install + usage instructions. The short version:

```bash
git clone https://github.com/Alienbushman/mcpdone-samples.git
cd mcpdone-samples/mcp-content-opportunity    # or mcp-sqlite-query, mcp-gmail-reader
uv sync
uv run pytest                                  # run the tests
```

Wire any of them into Claude Code by adding an entry to `.mcp.json`:

```json
{
  "mcpServers": {
    "content-opportunity": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/mcp-content-opportunity",
        "run",
        "python",
        "-m",
        "mcp_content_opportunity.server"
      ]
    }
  }
}
```

Per-server specifics (env vars, credentials, etc.) in each project's README.

## Philosophy — why these samples look the way they do

**Build-time constraint is cheaper than runtime trust.** Each of these servers is defined as much by what it *can't* do as what it can. `mcp-sqlite-query` physically cannot write to the database. `mcp-gmail-reader` physically cannot send or delete mail. The "physically cannot" isn't a promise — it's the absence of those code paths in the repo.

When a prospect asks us "can the MCP server do X?", the answer should be "yes, and here's the test proving it" or "no, and here's why that's deliberately out of scope." Not "maybe, depending on the prompt."

If that shape of rigour is what you want for your team's integrations, **[let's talk](https://mcpdone.com)**.

## License

MIT across the board. Use the code, fork it, learn from it. A link back to [mcpdone.com](https://mcpdone.com) is appreciated but not required.

## Status / support

This repo is a portfolio + reference, not an accepted-PRs open-source project. The code is maintained in the course of running the consultancy — bug reports welcome via issues, but feature requests will be politely declined unless they match a paid engagement.
