"""Tests for draft + label operations."""
from __future__ import annotations

import email as _email

import pytest

from mcp_gmail_reader.writer import DraftError, apply_label, draft_reply


def test_draft_reply_saves_to_drafts_folder(fake_imap, config) -> None:
    result = draft_reply(
        fake_imap, config, uid="100", body="Thanks — I'll get back to you shortly."
    )
    assert result["status"] == "drafted"
    assert result["drafts_folder"] == config.drafts_folder
    assert len(fake_imap.drafts) == 1
    appended = fake_imap.drafts[0]
    assert appended["mailbox"] == config.drafts_folder


def test_draft_reply_preserves_threading(fake_imap, config) -> None:
    draft_reply(fake_imap, config, uid="100", body="test")
    raw = fake_imap.drafts[0]["message"]
    msg = _email.message_from_bytes(raw)
    # The reply should have In-Reply-To header matching the original's Message-ID
    assert msg["In-Reply-To"]
    assert msg["References"]
    # And a Re: subject prefix (unless already present)
    assert msg["Subject"].startswith("Re: ")


def test_draft_reply_doesnt_double_prefix_re(fake_imap, config, make_email) -> None:
    raw = make_email(subject="Re: already a reply")
    fake_imap.add_message(uid="200", raw=raw)
    draft_reply(fake_imap, config, uid="200", body="noted")
    appended = fake_imap.drafts[-1]
    msg = _email.message_from_bytes(appended["message"])
    # Should not become "Re: Re: already a reply"
    assert msg["Subject"] == "Re: already a reply"


def test_draft_reply_subject_override(fake_imap, config) -> None:
    draft_reply(
        fake_imap,
        config,
        uid="100",
        body="test",
        subject_override="Custom subject line",
    )
    appended = fake_imap.drafts[-1]
    msg = _email.message_from_bytes(appended["message"])
    assert msg["Subject"] == "Custom subject line"


def test_draft_reply_addresses_original_sender(fake_imap, config, make_email) -> None:
    raw = make_email(from_addr="lead@acme.com", from_name="Potential Lead")
    fake_imap.add_message(uid="300", raw=raw)
    result = draft_reply(fake_imap, config, uid="300", body="thanks")
    assert result["to"] == "lead@acme.com"
    msg = _email.message_from_bytes(fake_imap.drafts[-1]["message"])
    assert msg["To"] == "lead@acme.com"
    assert msg["From"] == config.email


def test_draft_reply_unknown_uid_raises(fake_imap, config) -> None:
    with pytest.raises(DraftError, match="Could not fetch"):
        draft_reply(fake_imap, config, uid="9999", body="test")


def test_draft_reply_no_from_raises(fake_imap, config, make_email) -> None:
    # Build a message without a From header
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["To"] = "test@x.com"
    msg["Subject"] = "no from"
    msg.set_content("body")
    fake_imap.add_message(uid="400", raw=msg.as_bytes())
    with pytest.raises(DraftError, match="no valid From"):
        draft_reply(fake_imap, config, uid="400", body="test")


# --- apply_label ---


def test_apply_label_adds_to_existing_labels(fake_imap, config) -> None:
    result = apply_label(fake_imap, config, uid="100", label="handled")
    assert result["status"] == "labeled"
    assert "handled" in fake_imap.labels["100"]
    # Original label is retained (additive, not replacing)
    assert "test-inbox" in fake_imap.labels["100"]


def test_apply_label_rejects_gmail_reserved_folders(fake_imap, config) -> None:
    with pytest.raises(ValueError, match="reserved"):
        apply_label(fake_imap, config, uid="100", label="[Gmail]/Spam")


def test_apply_label_noop_on_scoped_label(fake_imap, config) -> None:
    # Applying the scoped label to an email already in it is a no-op
    result = apply_label(fake_imap, config, uid="100", label=config.label)
    assert result["status"] == "noop"
