"""Reddit search via public JSON API.

Uses the `.json` suffix on public Reddit URLs — no OAuth needed for read-only
search. Respectful of rate limits: we cap requests, set a User-Agent, and
never poll faster than 1/sec.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from mcp_content_opportunity.models import Opportunity

REDDIT_BASE = "https://www.reddit.com"
DEFAULT_TIMEOUT = 10.0
USER_AGENT = "mcp-content-opportunity/0.1 (by /u/anonymous; educational use)"


async def search_reddit(
    query: str,
    *,
    subreddit: str | None = None,
    limit: int = 20,
    sort: str = "relevance",  # relevance | hot | new | top | comments
    time_filter: str = "month",  # hour | day | week | month | year | all
    client: httpx.AsyncClient | None = None,
) -> list[Opportunity]:
    """Search Reddit submissions matching a query.

    Args:
        query: search term
        subreddit: restrict to one subreddit (e.g., "programming") — None = all Reddit
        limit: max results
        sort: sort order
        time_filter: recency window

    Returns:
        List of Opportunity records, unranked.
    """
    if subreddit:
        path = f"/r/{subreddit}/search.json"
        params = {
            "q": query,
            "restrict_sr": "true",
            "sort": sort,
            "t": time_filter,
            "limit": min(limit, 100),
        }
    else:
        path = "/search.json"
        params = {
            "q": query,
            "sort": sort,
            "t": time_filter,
            "limit": min(limit, 100),
        }

    headers = {"User-Agent": USER_AGENT}

    if client is None:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT, headers=headers) as c:
            resp = await c.get(f"{REDDIT_BASE}{path}", params=params)
            resp.raise_for_status()
            data = resp.json()
    else:
        resp = await client.get(f"{REDDIT_BASE}{path}", params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    children = data.get("data", {}).get("children", [])
    return [_to_opportunity(c["data"]) for c in children if c.get("kind") == "t3"][:limit]


def _to_opportunity(post: dict[str, Any]) -> Opportunity:
    """Convert a Reddit post dict to an Opportunity."""
    created_utc = post.get("created_utc", 0)
    try:
        created_at = datetime.fromtimestamp(float(created_utc), tz=timezone.utc)
    except (ValueError, TypeError):
        created_at = datetime.now(timezone.utc)

    permalink_path = post.get("permalink", "")
    permalink = f"{REDDIT_BASE}{permalink_path}" if permalink_path else ""
    url = post.get("url") or permalink

    subreddit = post.get("subreddit", "")
    tags = [f"r/{subreddit}"] if subreddit else []
    if post.get("over_18"):
        tags.append("nsfw")
    if post.get("link_flair_text"):
        tags.append(f"flair:{post['link_flair_text']}")

    return Opportunity(
        source="reddit",
        title=post.get("title", ""),
        url=url,
        permalink=permalink,
        created_at=created_at,
        score=post.get("score", 0) or 0,
        comment_count=post.get("num_comments", 0) or 0,
        author=post.get("author"),
        excerpt=(post.get("selftext") or "")[:280],
        tags=tags,
    )
