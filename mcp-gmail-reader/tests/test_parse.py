"""Tests for email parsing (MIME → models)."""
from __future__ import annotations

from datetime import datetime, timezone
from email.message import EmailMessage

from mcp_gmail_reader.parse import (
    decode_header,
    parse_address,
    parse_addresses,
    parse_date,
    parse_full,
    parse_summary,
)


# --- Header decoding ---


def test_decode_header_plain() -> None:
    assert decode_header("Hello World") == "Hello World"


def test_decode_header_rfc2047_utf8() -> None:
    # "Thé" encoded as RFC 2047
    assert decode_header("=?utf-8?b?VGjDqQ==?=") == "Thé"


def test_decode_header_empty() -> None:
    assert decode_header(None) == ""
    assert decode_header("") == ""


# --- Address parsing ---


def test_parse_address_name_and_email() -> None:
    name, addr = parse_address("Sam Dev <sam@acme.com>")
    assert name == "Sam Dev"
    assert addr == "sam@acme.com"


def test_parse_address_email_only() -> None:
    name, addr = parse_address("sam@acme.com")
    assert name == ""
    assert addr == "sam@acme.com"


def test_parse_addresses_multiple() -> None:
    result = parse_addresses("a@x.com, Bob <b@y.com>, c@z.com")
    assert set(result) == {"a@x.com", "b@y.com", "c@z.com"}


def test_parse_addresses_empty() -> None:
    assert parse_addresses(None) == []
    assert parse_addresses("") == []


# --- Date parsing ---


def test_parse_date_rfc5322() -> None:
    dt = parse_date("Mon, 15 Apr 2026 14:30:00 +0000")
    assert dt.year == 2026
    assert dt.month == 4
    assert dt.day == 15
    assert dt.tzinfo is not None


def test_parse_date_malformed_falls_back_to_now() -> None:
    dt = parse_date("garbage")
    # Should be roughly 'now' — tolerance of 5 minutes
    now = datetime.now(timezone.utc)
    delta_sec = abs((dt - now).total_seconds())
    assert delta_sec < 300


# --- Full message parsing ---


def test_parse_summary_basic(make_email) -> None:
    raw = make_email(
        from_name="Acme Corp",
        from_addr="contact@acme.com",
        subject="Interested in Build tier",
        body="Hi there,\nWe want an MCP server for our Postgres replica.",
    )
    summary = parse_summary(raw, uid="42", unread=True, labels=["mcpdone-inbox"])
    assert summary.uid == "42"
    assert summary.from_name == "Acme Corp"
    assert summary.from_addr == "contact@acme.com"
    assert summary.subject == "Interested in Build tier"
    assert "MCP server" in summary.snippet
    assert summary.unread is True
    assert "mcpdone-inbox" in summary.labels


def test_parse_summary_snippet_trims_long_bodies(make_email) -> None:
    long_body = "word " * 200
    raw = make_email(body=long_body)
    s = parse_summary(raw, uid="1", unread=False)
    assert len(s.snippet) <= 250  # capped ~240 plus ellipsis
    assert s.snippet.endswith("…")


def test_parse_full_includes_headers_and_body(make_email) -> None:
    raw = make_email(
        subject="Test",
        body="The body text",
        message_id="<abc@example.com>",
        in_reply_to="<orig@example.com>",
    )
    full = parse_full(raw, uid="1")
    assert full.message_id == "<abc@example.com>"
    assert full.in_reply_to == "<orig@example.com>"
    assert "The body text" in full.body_plain
    assert "From" in full.headers  # casing preserved


def test_parse_full_extracts_cc() -> None:
    msg = EmailMessage()
    msg["From"] = "a@x.com"
    msg["To"] = "b@y.com"
    msg["Cc"] = "c@y.com, d@y.com"
    msg["Subject"] = "test"
    msg.set_content("body")
    raw = msg.as_bytes()
    full = parse_full(raw, uid="2")
    assert set(full.cc_addrs) == {"c@y.com", "d@y.com"}


def test_parse_full_handles_no_body(make_email) -> None:
    raw = make_email(body="")
    full = parse_full(raw, uid="3")
    assert full.body_plain == ""


def test_parse_full_preserves_attachments_metadata_only() -> None:
    msg = EmailMessage()
    msg["From"] = "a@x.com"
    msg["To"] = "b@y.com"
    msg["Subject"] = "with attachment"
    msg.set_content("See attached.")
    msg.add_attachment(b"fake binary", maintype="application", subtype="pdf", filename="report.pdf")
    full = parse_full(msg.as_bytes(), uid="4")
    assert len(full.attachments) == 1
    assert full.attachments[0]["filename"] == "report.pdf"
    assert full.attachments[0]["content_type"] == "application/pdf"


def test_parse_full_html_preserved(make_email) -> None:
    msg = EmailMessage()
    msg["From"] = "a@x.com"
    msg["To"] = "b@y.com"
    msg["Subject"] = "html only"
    msg.set_content("Plain fallback")
    msg.add_alternative("<p>HTML <b>body</b></p>", subtype="html")
    full = parse_full(msg.as_bytes(), uid="5")
    assert full.body_plain == "Plain fallback"
    assert full.body_html is not None
    assert "<b>body</b>" in full.body_html
