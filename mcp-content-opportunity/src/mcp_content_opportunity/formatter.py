"""Format opportunities into human-readable markdown."""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone

from mcp_content_opportunity.models import Opportunity


def to_markdown(
    opportunities: Iterable[Opportunity],
    *,
    query: str | None = None,
    limit: int | None = None,
) -> str:
    """Render opportunities as a markdown report ready to paste into a doc."""
    opps = list(opportunities)
    if limit is not None:
        opps = opps[:limit]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    if query:
        lines.append(f"# Content opportunities: {query}")
    else:
        lines.append("# Content opportunities")
    lines.append("")
    lines.append(f"*Generated {now} — {len(opps)} ranked opportunities*")
    lines.append("")

    if not opps:
        lines.append("*No results.*")
        return "\n".join(lines) + "\n"

    for i, opp in enumerate(opps, start=1):
        lines.append(f"## {i}. {opp.title}")
        lines.append("")
        source_label = {"hackernews": "Hacker News", "reddit": "Reddit"}.get(
            opp.source, opp.source.title()
        )
        meta_parts = [
            f"**Score:** {opp.opportunity_score}",
            f"**Source:** {source_label}",
            f"**Age:** {_pretty_age(opp.age_hours)}",
            f"**Engagement:** {opp.score} pts / {opp.comment_count} comments",
        ]
        if opp.author:
            meta_parts.append(f"**Author:** {opp.author}")
        lines.append(" · ".join(meta_parts))
        lines.append("")
        if opp.reasons:
            lines.append("**Why it ranked:** " + "; ".join(opp.reasons))
            lines.append("")
        if opp.excerpt:
            excerpt = opp.excerpt.replace("\n", " ").strip()
            lines.append(f"> {excerpt}")
            lines.append("")
        lines.append(f"[Discussion]({opp.permalink})")
        if opp.url and opp.url != opp.permalink:
            lines.append(f" · [Link]({opp.url})")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _pretty_age(hours: float) -> str:
    if hours < 1:
        return f"{int(hours * 60)}m"
    if hours < 48:
        return f"{hours:.1f}h"
    days = hours / 24
    if days < 30:
        return f"{days:.1f}d"
    months = days / 30.44
    if months < 12:
        return f"{months:.1f}mo"
    return f"{days / 365.25:.1f}y"
