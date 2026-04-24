"""Data models for content opportunities."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class Opportunity:
    """A single content opportunity surfaced from a source."""

    source: str  # "hackernews", "reddit", "rss"
    title: str
    url: str
    permalink: str  # direct link to the discussion/comment thread
    created_at: datetime
    score: int  # points/upvotes/comments — raw engagement signal
    comment_count: int
    author: str | None = None
    excerpt: str = ""  # short snippet of body/first comment
    tags: list[str] = field(default_factory=list)

    # populated by the ranker
    opportunity_score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        return d

    @property
    def age_hours(self) -> float:
        now = datetime.now(timezone.utc)
        if self.created_at.tzinfo is None:
            created = self.created_at.replace(tzinfo=timezone.utc)
        else:
            created = self.created_at
        delta = now - created
        return max(delta.total_seconds() / 3600.0, 0.0)
