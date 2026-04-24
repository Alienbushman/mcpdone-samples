"""Email-parsing helpers — convert raw RFC 5322 bytes into our data models.

Keeps all MIME gnarliness in one place. Tools import from here; they never
see `email.message.Message` directly.
"""
from __future__ import annotations

import email
import email.header
import email.utils
from datetime import datetime, timezone
from email.message import Message
from typing import Any

from mcp_gmail_reader.models import EmailFull, EmailSummary, utc_now

_SNIPPET_CHARS = 240


def decode_header(raw: str | None) -> str:
    """Decode RFC 2047 encoded-word headers to a clean UTF-8 string."""
    if not raw:
        return ""
    parts = email.header.decode_header(raw)
    out: list[str] = []
    for chunk, enc in parts:
        if isinstance(chunk, bytes):
            try:
                out.append(chunk.decode(enc or "utf-8", errors="replace"))
            except (LookupError, TypeError):
                out.append(chunk.decode("utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out).strip()


def parse_address(raw: str | None) -> tuple[str, str]:
    """Split a 'Name <email>' header into (name, email)."""
    if not raw:
        return "", ""
    name, addr = email.utils.parseaddr(decode_header(raw))
    return name.strip(), addr.strip()


def parse_addresses(raw: str | None) -> list[str]:
    """Parse a comma-separated address list into plain email addresses."""
    if not raw:
        return []
    out = []
    for name, addr in email.utils.getaddresses([decode_header(raw)]):
        if addr:
            out.append(addr.strip())
    return out


def parse_date(raw: str | None) -> datetime:
    """Parse an RFC 5322 Date header; fall back to 'now' if malformed."""
    if not raw:
        return utc_now()
    try:
        dt = email.utils.parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_body(msg: Message) -> tuple[str, str | None, list[dict[str, str]]]:
    """Walk a MIME tree and pull out plain-text + HTML bodies + attachment metadata.

    Returns (plain_text, html_or_none, attachments_list).
    Attachments are metadata only — we don't read the bytes.
    """
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict[str, str]] = []

    for part in msg.walk():
        ctype = part.get_content_type()
        disp = (part.get("Content-Disposition") or "").lower()

        # Skip the wrapper multipart/* parts
        if part.is_multipart():
            continue

        # Attachments — metadata only
        if "attachment" in disp:
            filename = part.get_filename() or ""
            attachments.append(
                {
                    "filename": decode_header(filename),
                    "content_type": ctype,
                }
            )
            continue

        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            continue

        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, TypeError):
            text = payload.decode("utf-8", errors="replace")

        if ctype == "text/plain":
            plain_parts.append(text)
        elif ctype == "text/html":
            html_parts.append(text)

    plain = "\n".join(p.strip() for p in plain_parts if p.strip())
    html = "\n".join(h for h in html_parts if h.strip()) or None
    return plain, html, attachments


def _snippet_from(plain: str, html: str | None) -> str:
    """Produce a short preview — first _SNIPPET_CHARS of the plain body."""
    text = plain or (_html_to_text(html) if html else "")
    text = " ".join(text.split())  # collapse whitespace
    if len(text) <= _SNIPPET_CHARS:
        return text
    return text[:_SNIPPET_CHARS].rstrip() + "…"


def _html_to_text(html: str) -> str:
    """Last-resort HTML→text. Doesn't need to be pretty — it's only for snippets."""
    import re
    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    return text


def parse_summary(
    raw_bytes: bytes, *, uid: str, unread: bool, labels: list[str] | None = None
) -> EmailSummary:
    """Parse raw message bytes into an EmailSummary (list-view payload)."""
    msg = email.message_from_bytes(raw_bytes)
    from_name, from_addr = parse_address(msg.get("From"))
    subject = decode_header(msg.get("Subject"))
    received_at = parse_date(msg.get("Date"))
    plain, html, _ = _extract_body(msg)
    return EmailSummary(
        uid=uid,
        message_id=(msg.get("Message-ID") or "").strip(),
        from_addr=from_addr,
        from_name=from_name,
        subject=subject,
        received_at=received_at,
        snippet=_snippet_from(plain, html),
        unread=unread,
        labels=labels or [],
    )


def parse_full(
    raw_bytes: bytes, *, uid: str, labels: list[str] | None = None
) -> EmailFull:
    """Parse raw message bytes into a full EmailFull (read-view payload)."""
    msg = email.message_from_bytes(raw_bytes)
    from_name, from_addr = parse_address(msg.get("From"))
    plain, html, attachments = _extract_body(msg)
    return EmailFull(
        uid=uid,
        message_id=(msg.get("Message-ID") or "").strip(),
        from_addr=from_addr,
        from_name=from_name,
        to_addrs=parse_addresses(msg.get("To")),
        cc_addrs=parse_addresses(msg.get("Cc")),
        subject=decode_header(msg.get("Subject")),
        received_at=parse_date(msg.get("Date")),
        body_plain=plain,
        body_html=html,
        attachments=attachments,
        headers={k: decode_header(v) for k, v in msg.items()},
        in_reply_to=(msg.get("In-Reply-To") or "").strip() or None,
        labels=labels or [],
    )
