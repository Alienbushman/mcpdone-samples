"""Tests for Opportunity model."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mcp_content_opportunity.models import Opportunity


def _opp(**overrides) -> Opportunity:
    base = dict(
        source="hackernews",
        title="Example",
        url="https://example.com",
        permalink="https://news.ycombinator.com/item?id=1",
        created_at=datetime.now(timezone.utc),
        score=10,
        comment_count=5,
    )
    base.update(overrides)
    return Opportunity(**base)


def test_age_hours_is_zero_for_now() -> None:
    opp = _opp(created_at=datetime.now(timezone.utc))
    assert opp.age_hours < 0.01  # within a fraction of a second


def test_age_hours_handles_naive_datetime() -> None:
    # Treats naive datetimes as UTC to avoid crashes from missing tzinfo
    naive = datetime.utcnow() - timedelta(hours=5)
    opp = _opp(created_at=naive)
    assert 4.9 < opp.age_hours < 5.1


def test_to_dict_serialises_datetime() -> None:
    when = datetime(2026, 4, 15, 12, 0, 0, tzinfo=timezone.utc)
    opp = _opp(created_at=when)
    d = opp.to_dict()
    assert d["created_at"] == "2026-04-15T12:00:00+00:00"
    assert d["title"] == "Example"


def test_age_hours_never_negative() -> None:
    # Future-dated posts shouldn't produce negative ages (would break time decay)
    future = datetime.now(timezone.utc) + timedelta(hours=3)
    opp = _opp(created_at=future)
    assert opp.age_hours == 0.0
