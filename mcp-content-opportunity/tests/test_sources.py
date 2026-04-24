"""Tests for source adapters — mocked HTTP, no network."""
from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from mcp_content_opportunity.sources.hackernews import search_hackernews
from mcp_content_opportunity.sources.reddit import search_reddit


# --- Hacker News ---

HN_SAMPLE = {
    "hits": [
        {
            "objectID": "12345",
            "title": "Show HN: A new MCP server",
            "url": "https://example.com/mcp",
            "author": "founder42",
            "points": 128,
            "num_comments": 45,
            "created_at": "2026-04-15T10:30:00.000Z",
            "story_text": "I built a thing.",
            "_tags": ["story", "author_founder42"],
        },
        {
            "objectID": "12346",
            "title": "Claude Code hooks don't work",
            "url": None,
            "author": "confused_dev",
            "points": 5,
            "num_comments": 22,
            "created_at": "2026-04-18T08:00:00.000Z",
            "story_text": "I can't get the pre-commit hook to fire.",
            "_tags": ["story"],
        },
    ]
}


@pytest.mark.asyncio
async def test_search_hackernews_parses_hits(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://hn.algolia.com/api/v1/search?query=mcp&tags=story&hitsPerPage=20",
        json=HN_SAMPLE,
    )

    async with httpx.AsyncClient() as client:
        opps = await search_hackernews("mcp", limit=20, client=client)

    assert len(opps) == 2
    assert opps[0].source == "hackernews"
    assert opps[0].title == "Show HN: A new MCP server"
    assert opps[0].score == 128
    assert opps[0].comment_count == 45
    assert opps[0].permalink == "https://news.ycombinator.com/item?id=12345"
    assert opps[1].url == "https://news.ycombinator.com/item?id=12346"  # falls back to HN


@pytest.mark.asyncio
async def test_search_hackernews_recent_uses_by_date(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://hn.algolia.com/api/v1/search_by_date?query=mcp&tags=story&hitsPerPage=5",
        json={"hits": []},
    )
    async with httpx.AsyncClient() as client:
        opps = await search_hackernews("mcp", limit=5, recent_only=True, client=client)
    assert opps == []


@pytest.mark.asyncio
async def test_search_hackernews_limit_caps_at_50(httpx_mock: HTTPXMock) -> None:
    # Even if caller asks for 1000, we must cap the request at 50
    httpx_mock.add_response(
        url="https://hn.algolia.com/api/v1/search?query=mcp&tags=story&hitsPerPage=50",
        json={"hits": []},
    )
    async with httpx.AsyncClient() as client:
        await search_hackernews("mcp", limit=1000, client=client)


# --- Reddit ---

REDDIT_SAMPLE = {
    "data": {
        "children": [
            {
                "kind": "t3",
                "data": {
                    "title": "Help: MCP server crashes on startup",
                    "url": "https://reddit.com/r/ClaudeAI/comments/xyz/help_mcp",
                    "permalink": "/r/ClaudeAI/comments/xyz/help_mcp/",
                    "subreddit": "ClaudeAI",
                    "author": "lostdev",
                    "score": 42,
                    "num_comments": 30,
                    "created_utc": 1_713_456_000,
                    "selftext": "Any ideas?",
                    "over_18": False,
                    "link_flair_text": "Question",
                },
            },
            {
                "kind": "t1",  # comment, not a post — should be filtered out
                "data": {"body": "this shouldn't appear"},
            },
        ]
    }
}


@pytest.mark.asyncio
async def test_search_reddit_parses_submissions(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://www.reddit.com/search.json?q=mcp&sort=relevance&t=month&limit=20",
        json=REDDIT_SAMPLE,
    )
    async with httpx.AsyncClient() as client:
        opps = await search_reddit("mcp", limit=20, client=client)

    assert len(opps) == 1  # comment was filtered out
    assert opps[0].source == "reddit"
    assert opps[0].title == "Help: MCP server crashes on startup"
    assert opps[0].score == 42
    assert "r/ClaudeAI" in opps[0].tags
    assert "flair:Question" in opps[0].tags
    assert opps[0].permalink.startswith("https://www.reddit.com/")


@pytest.mark.asyncio
async def test_search_reddit_restricts_to_subreddit(httpx_mock: HTTPXMock) -> None:
    httpx_mock.add_response(
        url="https://www.reddit.com/r/ClaudeAI/search.json?q=mcp&restrict_sr=true&sort=relevance&t=month&limit=5",
        json={"data": {"children": []}},
    )
    async with httpx.AsyncClient() as client:
        opps = await search_reddit("mcp", subreddit="ClaudeAI", limit=5, client=client)
    assert opps == []
