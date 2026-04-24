"""Tests for opportunity ranking logic."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mcp_content_opportunity.models import Opportunity
from mcp_content_opportunity.ranker import rank


def _opp(
    title: str,
    *,
    score: int = 0,
    comments: int = 0,
    age_hours: float = 0.0,
    excerpt: str = "",
) -> Opportunity:
    return Opportunity(
        source="hackernews",
        title=title,
        url="https://example.com",
        permalink="https://example.com",
        created_at=datetime.now(timezone.utc) - timedelta(hours=age_hours),
        score=score,
        comment_count=comments,
        excerpt=excerpt,
    )


def test_ranker_preserves_all_items() -> None:
    opps = [_opp("A"), _opp("B"), _opp("C")]
    out = rank(opps)
    assert len(out) == 3


def test_higher_engagement_ranks_higher() -> None:
    low = _opp("Low engagement", score=1, comments=0, age_hours=1)
    high = _opp("High engagement", score=200, comments=100, age_hours=1)
    out = rank([low, high])
    assert out[0].title == "High engagement"
    assert out[0].opportunity_score > out[1].opportunity_score


def test_fresher_ranks_higher_when_engagement_equal() -> None:
    old = _opp("Old", score=50, comments=20, age_hours=240)  # 10 days
    fresh = _opp("Fresh", score=50, comments=20, age_hours=2)
    out = rank([old, fresh])
    assert out[0].title == "Fresh"


def test_question_boost_applies() -> None:
    statement = _opp("Kubernetes is great", score=10, comments=5, age_hours=24)
    question = _opp("How do I debug Kubernetes pods?", score=10, comments=5, age_hours=24)
    out = rank([statement, question])
    assert out[0].title.startswith("How")


def test_pain_keyword_boost_applies() -> None:
    normal = _opp("A guide to Docker", score=10, comments=5, age_hours=24)
    painful = _opp("Stuck with Docker — can't get it working", score=10, comments=5, age_hours=24)
    out = rank([normal, painful])
    assert out[0].title.startswith("Stuck")
    assert any("pain-signal" in r for r in out[0].reasons)


def test_comment_heavy_boost_applies() -> None:
    normal = _opp("Standard discussion", score=100, comments=20, age_hours=24)
    heavy = _opp("Contentious topic", score=20, comments=100, age_hours=24)
    out = rank([normal, heavy])
    # comment-heavy post may still score lower if base engagement is lower,
    # but the ratio bonus should appear in its reasons
    heavy_result = next(o for o in out if o.title == "Contentious topic")
    assert any("discussion-heavy" in r for r in heavy_result.reasons)


def test_reasons_accumulate() -> None:
    opp = _opp(
        "How do I fix this? I'm stuck",
        score=200,
        comments=150,
        age_hours=2,
        excerpt="Not working at all",
    )
    [ranked] = rank([opp])
    assert len(ranked.reasons) >= 3  # engagement + fresh + question + pain


def test_score_is_bounded_to_100() -> None:
    monster = _opp(
        "How do I fix the broken error? I'm stuck, not working, can't figure it out",
        score=10_000,
        comments=10_000,
        age_hours=0.1,
        excerpt="error broken failing stuck can't help",
    )
    [ranked] = rank([monster])
    assert ranked.opportunity_score <= 100.0
