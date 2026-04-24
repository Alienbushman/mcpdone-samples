"""Hacker News search via Algolia's public API.

Docs: https://hn.algolia.com/api

No auth required. Rate-limited at 10,000 requests/hour/IP, which is plenty.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from mcp_content_opportunity.models import Opportunity

ALGOLIA_BASE = "https://hn.algolia.com/api/v1"
DEFAULT_TIMEOUT = 10.0


async def search_hackernews(
    query: str,
    *,
    limit: int = 20,
    recent_only: bool = False,
    client: httpx.AsyncClient | None = None,
) -> list[Opportunity]:
    """Search Hacker News stories and comments matching a query.

    Args:
        query: search term (keyword, phrase)
        limit: max results to return
        recent_only: if True, use search_by_date endpoint (recency-weighted)
        client: optional pre-built httpx client (mostly for tests)

    Returns:
        List of Opportunity records, unranked.
    """
    endpoint = "search_by_date" if recent_only else "search"
    params = {
        "query": query,
        "tags": "story",  # skip comments, focus on top-level stories
        "hitsPerPage": min(limit, 50),
    }

    if client is None:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as c:
            resp = await c.get(f"{ALGOLIA_BASE}/{endpoint}", params=params)
            resp.raise_for_status()
            data = resp.json()
    else:
        resp = await client.get(f"{ALGOLIA_BASE}/{endpoint}", params=params)
        resp.raise_for_status()
        data = resp.json()

    return [_to_opportunity(hit) for hit in data.get("hits", [])][:limit]


def _to_opportunity(hit: dict[str, Any]) -> Opportunity:
    """Convert an Algolia HN hit to an Opportunity."""
    object_id = hit.get("objectID", "")
    url = hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}"
    created_at_iso = hit.get("created_at")
    if created_at_iso:
        # Algolia returns ISO 8601 with Z suffix
        created_at = datetime.fromisoformat(created_at_iso.replace("Z", "+00:00"))
    else:
        created_at = datetime.now(timezone.utc)

    return Opportunity(
        source="hackernews",
        title=hit.get("title") or hit.get("story_title") or "",
        url=url,
        permalink=f"https://news.ycombinator.com/item?id={object_id}",
        created_at=created_at,
        score=hit.get("points", 0) or 0,
        comment_count=hit.get("num_comments", 0) or 0,
        author=hit.get("author"),
        excerpt=(hit.get("story_text") or "")[:280],
        tags=hit.get("_tags", []) or [],
    )
