"""Tests for markdown formatter."""
from __future__ import annotations

from datetime import datetime, timezone

from mcp_content_opportunity.formatter import to_markdown
from mcp_content_opportunity.models import Opportunity


def _opp(title: str, score: float = 50.0) -> Opportunity:
    return Opportunity(
        source="hackernews",
        title=title,
        url="https://example.com",
        permalink="https://news.ycombinator.com/item?id=1",
        created_at=datetime(2026, 4, 15, 12, 0, 0, tzinfo=timezone.utc),
        score=10,
        comment_count=5,
        opportunity_score=score,
        reasons=["high engagement", "fresh"],
        excerpt="A short excerpt of the discussion.",
    )


def test_to_markdown_header_includes_query() -> None:
    md = to_markdown([_opp("A")], query="mcp")
    assert "# Content opportunities: mcp" in md


def test_to_markdown_empty_list_shows_no_results() -> None:
    md = to_markdown([])
    assert "*No results.*" in md


def test_to_markdown_includes_score_and_reasons() -> None:
    md = to_markdown([_opp("How to MCP", score=72.5)])
    assert "72.5" in md
    assert "high engagement" in md


def test_to_markdown_respects_limit() -> None:
    opps = [_opp(f"Title {i}") for i in range(5)]
    md = to_markdown(opps, limit=2)
    # only 2 section headers should appear
    assert md.count("## 1.") == 1
    assert md.count("## 2.") == 1
    assert "## 3." not in md


def test_to_markdown_generates_numbered_entries() -> None:
    opps = [_opp("A"), _opp("B"), _opp("C")]
    md = to_markdown(opps)
    assert "## 1. A" in md
    assert "## 2. B" in md
    assert "## 3. C" in md
