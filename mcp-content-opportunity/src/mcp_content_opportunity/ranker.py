"""Rank opportunities by signals that correlate with 'underserved demand'.

The scoring model is intentionally simple — it's a heuristic we can explain in
a blog post, not an opaque ML model. Signals:

1. Engagement: log-scaled points and comments (bigger = more demand signal).
2. Recency: fresher content ranks higher (time-decay).
3. Question intensity: posts that are literally questions ("how do I...", "?").
4. Comment-to-score ratio: high ratio = discussion-heavy = unsettled topic.
5. Keyword bonuses: problem/pain words ("help", "stuck", "can't", "error").

Result: each opportunity gets a 0–100 score and a list of reasons explaining
the rank. Consumers can sort or filter however they want.
"""
from __future__ import annotations

import math
import re
from collections.abc import Iterable

from mcp_content_opportunity.models import Opportunity

QUESTION_PATTERNS = [
    re.compile(r"\?"),
    re.compile(r"\bhow (do|can|to)\b", re.IGNORECASE),
    re.compile(r"\bwhat('?s| is)\b", re.IGNORECASE),
    re.compile(r"\bwhy (does|is|do|can)\b", re.IGNORECASE),
    re.compile(r"\banyone (know|tried|using)\b", re.IGNORECASE),
]

PAIN_KEYWORDS = [
    "help",
    "stuck",
    "can't",
    "cannot",
    "error",
    "broken",
    "failing",
    "struggle",
    "struggling",
    "confused",
    "don't understand",
    "not working",
    "issue with",
    "problem with",
    "trouble",
]


def rank(
    opportunities: Iterable[Opportunity],
    *,
    recency_half_life_hours: float = 72.0,
) -> list[Opportunity]:
    """Score and sort opportunities in-place; return them sorted high→low."""
    scored = []
    for opp in opportunities:
        opp.opportunity_score, opp.reasons = _score(opp, recency_half_life_hours)
        scored.append(opp)
    scored.sort(key=lambda o: o.opportunity_score, reverse=True)
    return scored


def _score(opp: Opportunity, recency_half_life_hours: float) -> tuple[float, list[str]]:
    reasons: list[str] = []

    # Engagement: logarithmic so a post with 500 points doesn't dwarf everything
    engagement_raw = max(opp.score, 0) + max(opp.comment_count, 0)
    engagement = math.log1p(engagement_raw) * 10  # 0 → ~70 over realistic range
    if engagement_raw > 50:
        reasons.append(f"high engagement ({engagement_raw} pts+comments)")

    # Recency: exponential decay with configurable half-life
    decay = 0.5 ** (opp.age_hours / recency_half_life_hours)
    recency_score = decay * 20  # max 20 points for a brand-new post
    if opp.age_hours < 48:
        reasons.append("fresh (< 48h)")

    # Question intensity
    question_hits = sum(
        1 for p in QUESTION_PATTERNS if p.search(opp.title) or p.search(opp.excerpt)
    )
    question_score = min(question_hits * 4, 12)  # cap at 12
    if question_hits:
        reasons.append(f"reads as a question ({question_hits} indicators)")

    # Comment-to-score ratio: lots of discussion relative to upvotes = unsettled
    if opp.score > 0:
        ratio = opp.comment_count / opp.score
        if ratio > 1.0:
            ratio_score = min(ratio * 3, 10)
            reasons.append(f"discussion-heavy (C/S ratio {ratio:.2f})")
        else:
            ratio_score = 0
    else:
        ratio_score = 0

    # Pain keyword bonus
    haystack = f"{opp.title} {opp.excerpt}".lower()
    pain_hits = sum(1 for kw in PAIN_KEYWORDS if kw in haystack)
    pain_score = min(pain_hits * 3, 9)
    if pain_hits:
        reasons.append(f"pain-signal keywords ({pain_hits} hits)")

    total = engagement + recency_score + question_score + ratio_score + pain_score
    # Clamp for sanity (not a real upper bound, just a useful normalisation)
    total = min(total, 100.0)

    return round(total, 2), reasons
