"""MCP server exposing content-opportunity tools.

Run with:
    uv run python -m mcp_content_opportunity.server

Or as a Claude Code MCP server, configure via `.claude/settings.json`:

    {
      "mcpServers": {
        "content-opportunity": {
          "command": "uv",
          "args": ["run", "python", "-m", "mcp_content_opportunity.server"],
          "cwd": "/path/to/mcp-content-opportunity"
        }
      }
    }
"""
from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_content_opportunity.formatter import to_markdown
from mcp_content_opportunity.models import Opportunity
from mcp_content_opportunity.ranker import rank
from mcp_content_opportunity.sources import search_hackernews, search_reddit

mcp = FastMCP("content-opportunity")


@mcp.tool()
async def find_opportunities(
    query: str,
    sources: list[str] | None = None,
    limit_per_source: int = 15,
    total_limit: int = 20,
    recency_half_life_hours: float = 72.0,
) -> str:
    """Search multiple sources for content opportunities on a topic and rank them.

    Args:
        query: Topic keyword or phrase (e.g., "MCP server", "Claude Code hooks").
        sources: Which sources to query. Defaults to ["hackernews", "reddit"].
        limit_per_source: Max results to fetch from each source before ranking.
        total_limit: Max ranked results to return.
        recency_half_life_hours: Freshness decay — lower values favour recent posts.

    Returns:
        Markdown-formatted ranked list of content opportunities.
    """
    if sources is None:
        sources = ["hackernews", "reddit"]

    tasks = []
    if "hackernews" in sources:
        tasks.append(
            search_hackernews(query, limit=limit_per_source, recent_only=False)
        )
    if "reddit" in sources:
        tasks.append(
            search_reddit(query, limit=limit_per_source, sort="relevance")
        )

    if not tasks:
        return "# Content opportunities\n\n*No sources selected.*\n"

    results_by_source = await asyncio.gather(*tasks, return_exceptions=True)

    all_opps: list[Opportunity] = []
    errors: list[str] = []
    for idx, res in enumerate(results_by_source):
        if isinstance(res, Exception):
            src_name = sources[idx] if idx < len(sources) else "unknown"
            errors.append(f"{src_name}: {type(res).__name__}: {res}")
            continue
        all_opps.extend(res)  # type: ignore[arg-type]

    ranked = rank(all_opps, recency_half_life_hours=recency_half_life_hours)
    md = to_markdown(ranked, query=query, limit=total_limit)

    if errors:
        md += "\n\n---\n\n**Source errors:**\n\n"
        for e in errors:
            md += f"- {e}\n"

    return md


@mcp.tool()
async def search_hn(
    query: str,
    limit: int = 20,
    recent_only: bool = False,
) -> list[dict[str, Any]]:
    """Search Hacker News via Algolia. Returns raw (unranked) opportunities.

    Useful when you want HN-only results or plan to rank yourself.
    """
    opps = await search_hackernews(query, limit=limit, recent_only=recent_only)
    return [o.to_dict() for o in opps]


@mcp.tool()
async def search_subreddit(
    query: str,
    subreddit: str | None = None,
    limit: int = 20,
    sort: str = "relevance",
    time_filter: str = "month",
) -> list[dict[str, Any]]:
    """Search Reddit (optionally restricted to one subreddit). Returns unranked results.

    Args:
        query: Search term.
        subreddit: e.g. "programming", "MachineLearning". None searches all of Reddit.
        limit: Max results.
        sort: One of: relevance | hot | new | top | comments.
        time_filter: One of: hour | day | week | month | year | all.
    """
    opps = await search_reddit(
        query,
        subreddit=subreddit,
        limit=limit,
        sort=sort,
        time_filter=time_filter,
    )
    return [o.to_dict() for o in opps]


@mcp.tool()
def rank_opportunities(
    opportunities: list[dict[str, Any]],
    recency_half_life_hours: float = 72.0,
) -> str:
    """Rank a list of previously-fetched opportunities and format as markdown.

    Takes the raw dicts returned by search_hn / search_subreddit, scores them,
    and returns a markdown report.
    """
    from datetime import datetime

    rebuilt: list[Opportunity] = []
    for d in opportunities:
        created_at_raw = d.get("created_at")
        if isinstance(created_at_raw, str):
            try:
                created_at = datetime.fromisoformat(created_at_raw)
            except ValueError:
                continue
        else:
            continue
        rebuilt.append(
            Opportunity(
                source=d.get("source", "unknown"),
                title=d.get("title", ""),
                url=d.get("url", ""),
                permalink=d.get("permalink", ""),
                created_at=created_at,
                score=int(d.get("score", 0) or 0),
                comment_count=int(d.get("comment_count", 0) or 0),
                author=d.get("author"),
                excerpt=d.get("excerpt", "") or "",
                tags=list(d.get("tags", []) or []),
            )
        )

    ranked = rank(rebuilt, recency_half_life_hours=recency_half_life_hours)
    return to_markdown(ranked)


def main() -> None:
    """Entry point — runs the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
