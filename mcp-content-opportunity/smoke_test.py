"""Quick end-to-end smoke test against live HN + Reddit APIs.

Writes the markdown report to smoke_test_output.md to avoid Windows console
encoding issues with non-ASCII characters scraped from Reddit titles.

Run: uv run python smoke_test.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp_content_opportunity.formatter import to_markdown
from mcp_content_opportunity.ranker import rank
from mcp_content_opportunity.sources import search_hackernews, search_reddit

OUTPUT_FILE = Path(__file__).parent / "smoke_test_output.md"


async def main() -> int:
    query = "Claude Code"
    print(f"Smoke test: searching HN + Reddit for {query!r}...")
    try:
        hn_task = search_hackernews(query, limit=10)
        reddit_task = search_reddit(query, limit=10, sort="relevance", time_filter="month")
        hn, reddit = await asyncio.gather(hn_task, reddit_task)
    except Exception as exc:
        print(f"FAIL: network or API error: {exc}", file=sys.stderr)
        return 1

    print(f"  HN hits:     {len(hn)}")
    print(f"  Reddit hits: {len(reddit)}")

    combined = hn + reddit
    if not combined:
        print("FAIL: zero results — likely an API or network issue", file=sys.stderr)
        return 2

    ranked = rank(combined)
    md = to_markdown(ranked, query=query, limit=5)
    OUTPUT_FILE.write_text(md, encoding="utf-8")

    print(f"  Ranked {len(ranked)} opportunities. Top 5 written to: {OUTPUT_FILE.name}")
    print("\nTop 5 titles (ASCII-safe):")
    for i, opp in enumerate(ranked[:5], start=1):
        safe_title = opp.title.encode("ascii", errors="replace").decode("ascii")
        print(f"  {i}. [{opp.opportunity_score:.1f}] {safe_title[:80]}")
    print("\nSmoke test OK.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
