# mcp-content-opportunity

An MCP server that turns Hacker News + Reddit into a ranked list of content opportunities on any topic — questions, pain points, discussion-heavy threads — ready to feed into a blog calendar or newsletter.

Built as a reference MCP server: clean code, real tests, no auth required, runs locally in seconds.

## What it does

Given a query like `"Claude Code"` or `"MCP server"`, it:

1. Searches Hacker News via the public Algolia API.
2. Searches Reddit via the public `.json` endpoints.
3. Scores each result on five signals — engagement, recency, question intensity, comment-to-score ratio, pain-signal keywords.
4. Returns a ranked markdown report you can drop straight into a doc.

No API keys. No OAuth. No LLM calls. Deterministic ranking.

## Tools exposed

| Tool | Purpose |
|---|---|
| `find_opportunities(query, sources?, ...)` | One-shot: search all sources, rank, return markdown |
| `search_hn(query, limit, recent_only)` | HN only; returns raw JSON |
| `search_subreddit(query, subreddit?, ...)` | Reddit only; returns raw JSON |
| `rank_opportunities(opportunities, ...)` | Rank previously-fetched results + render markdown |

## Setup

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Alienbushman/mcpdone-samples.git
cd mcpdone-samples/mcp-content-opportunity
uv sync
```

That's it.

## Using it with Claude Code

Add to your `.claude/settings.json` (or `.claude.json` in your home directory):

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

Restart Claude Code. Then in a session:

> Find me content opportunities about MCP server security. Focus on the last month.

Claude will call `find_opportunities` and give you a ranked list.

## Running it standalone

```bash
# Smoke test against live APIs
uv run python smoke_test.py

# Or import and use directly
uv run python -c "
import asyncio
from mcp_content_opportunity import search_hackernews, rank, to_markdown

async def go():
    opps = await search_hackernews('MCP', limit=10)
    print(to_markdown(rank(opps), query='MCP', limit=5))

asyncio.run(go())
"
```

## How the ranking works

Each opportunity gets a 0–100 score from five signals:

1. **Engagement** — `log(points + comments) × 10`. Log-scaled so a 5000-point thread doesn't flatten everything else.
2. **Recency** — exponential decay with a configurable half-life (default 72h).
3. **Question intensity** — regex match for `"how do"`, `"why does"`, `"?"`, etc.
4. **Comment-to-score ratio** — high ratios = unsettled, discussion-heavy topics.
5. **Pain-signal keywords** — `"stuck"`, `"can't"`, `"error"`, `"not working"`, `"help"`.

Each opportunity also carries a `reasons` list explaining its score, so you can audit the ranking.

Tweak the weights in `src/mcp_content_opportunity/ranker.py` — it's 80 lines, no ML.

## Development

```bash
# Run tests (22 tests, all offline, no network needed)
uv run pytest -v

# Run the MCP server over stdio (for debugging with MCP Inspector)
uv run python -m mcp_content_opportunity.server
```

## Project structure

```
mcp-content-opportunity/
├── src/mcp_content_opportunity/
│   ├── __init__.py         # public API
│   ├── server.py           # MCP tool definitions
│   ├── models.py           # Opportunity dataclass
│   ├── ranker.py           # scoring logic
│   ├── formatter.py        # markdown rendering
│   └── sources/
│       ├── hackernews.py   # HN Algolia adapter
│       └── reddit.py       # Reddit JSON adapter
├── tests/                  # 22 pytest tests, pure offline
├── smoke_test.py           # live end-to-end check
└── pyproject.toml
```

## Rate limits & citizenship

- HN Algolia: 10,000 req/hour/IP. Plenty.
- Reddit JSON: unofficial but widely used; we set a descriptive User-Agent and don't poll aggressively. If you hit 429s, back off.

## License

MIT.

## Author

Part of a self-directed-agent experiment. Built by Claude; maintained by a human. See the repo root for context.
