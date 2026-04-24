"""Tests for read operations driven against FakeImap."""
from __future__ import annotations

import email.utils
from datetime import datetime, timedelta, timezone

from mcp_gmail_reader.reader import (
    _parse_uid_list,
    list_recent,
    read_one,
    search,
    status,
)


# --- Low-level helpers ---


def test_parse_uid_list_simple() -> None:
    assert _parse_uid_list([b"1 2 3"]) == ["1", "2", "3"]


def test_parse_uid_list_empty() -> None:
    assert _parse_uid_list([b""]) == []
    assert _parse_uid_list([]) == []


def test_parse_uid_list_none() -> None:
    assert _parse_uid_list([None]) == []


# --- list_recent ---


def test_list_recent_returns_existing_emails(fake_imap) -> None:
    results = list_recent(fake_imap, since_days=7, unread_only=False, limit=50)
    assert len(results) == 1
    assert results[0].uid == "100"


def test_list_recent_unread_only_filter(fake_imap, make_email) -> None:
    # Add a read email
    fake_imap.add_message(uid="101", raw=make_email(), unread=False)
    all_results = list_recent(fake_imap, since_days=7, unread_only=False)
    unread_results = list_recent(fake_imap, since_days=7, unread_only=True)
    assert len(all_results) == 2
    assert len(unread_results) == 1
    assert unread_results[0].uid == "100"


def test_list_recent_respects_limit(fake_imap, make_email) -> None:
    for i in range(102, 112):
        fake_imap.add_message(uid=str(i), raw=make_email(subject=f"e{i}"))
    results = list_recent(fake_imap, since_days=7, limit=3)
    assert len(results) == 3


def test_list_recent_newest_first(fake_imap, make_email) -> None:
    fake_imap.add_message(uid="200", raw=make_email(subject="second"))
    fake_imap.add_message(uid="300", raw=make_email(subject="third"))
    # FakeImap returns UIDs in insertion order; list_recent reverses → newest first
    results = list_recent(fake_imap, since_days=7)
    uids = [r.uid for r in results]
    assert uids[0] == "300"  # last added is "newest"
    assert uids[-1] == "100"


# --- read_one ---


def test_read_one_returns_full_email(fake_imap) -> None:
    full = read_one(fake_imap, "100")
    assert full is not None
    assert full.uid == "100"
    assert full.body_plain  # has some body content


def test_read_one_missing_uid_returns_none(fake_imap) -> None:
    assert read_one(fake_imap, "9999") is None


# --- search ---


def test_search_finds_by_query(fake_imap, make_email) -> None:
    fake_imap.add_message(
        uid="500",
        raw=make_email(subject="Stripe integration question", body="Stripe setup help"),
    )
    fake_imap.add_message(
        uid="501", raw=make_email(subject="Different topic", body="nothing related")
    )
    results = search(fake_imap, query="stripe", since_days=30)
    uids = [r.uid for r in results]
    assert "500" in uids
    assert "501" not in uids


def test_search_empty_query_returns_nothing_sensible(fake_imap) -> None:
    # Empty or nonsensical query — should return empty, not crash
    results = search(fake_imap, query="zzz-absolutely-not-present-xyz", since_days=30)
    assert results == []


# --- status ---


def test_status_counts(fake_imap, make_email, config) -> None:
    fake_imap.add_message(uid="101", raw=make_email(), unread=False)
    fake_imap.add_message(uid="102", raw=make_email())  # unread by default
    st = status(fake_imap, config)
    assert st.label == config.label
    assert st.total_messages == 3
    assert st.unread_messages == 2
    assert st.checked_at.tzinfo is not None


def test_status_empty_inbox(fake_imap_empty, config) -> None:
    st = status(fake_imap_empty, config)
    assert st.total_messages == 0
    assert st.unread_messages == 0
    assert st.last_received_at is None


# --- extra fixture for empty-inbox case ---


import pytest  # noqa: E402

from tests.conftest import FakeImap  # noqa: E402


@pytest.fixture
def fake_imap_empty() -> FakeImap:
    f = FakeImap()
    f.login("test.inbox@gmail.com", "abcdefghijklmnop")
    f.select('"test-inbox"')
    return f
