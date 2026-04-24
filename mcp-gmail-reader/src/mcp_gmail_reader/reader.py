"""Read-side operations — list, read, search, inbox status.

These are the building blocks behind the MCP read-tools. Each one takes
an IMAP connection (already authenticated and label-selected) and returns
typed data — no leaking of imaplib internals.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mcp_gmail_reader.client import ImapConnection, _ensure_ok
from mcp_gmail_reader.config import Config
from mcp_gmail_reader.models import EmailFull, EmailSummary, InboxStatus, utc_now
from mcp_gmail_reader.parse import parse_full, parse_summary


# --- internal helpers ---


def _imap_date(days_ago: int) -> str:
    """Gmail IMAP SINCE takes dd-Mon-yyyy (e.g., '05-Apr-2026')."""
    dt = utc_now() - timedelta(days=max(days_ago, 0))
    return dt.strftime("%d-%b-%Y")


def _parse_uid_list(raw: list[bytes]) -> list[str]:
    """IMAP returns UIDs as a single space-separated bytes blob in a list."""
    if not raw or raw[0] is None:
        return []
    blob = raw[0] if isinstance(raw[0], bytes) else b""
    return [u.decode("ascii") for u in blob.split() if u]


def _fetch_raw_message(conn: ImapConnection, uid: str) -> bytes | None:
    """Fetch raw RFC 822 bytes for a UID. Returns None if the UID vanished."""
    typ, data = conn.uid("fetch", uid, "(RFC822)")
    if typ != "OK" or not data:
        return None
    # Response shape: [(b'UID ... {size}', b'raw bytes'), b')']
    for item in data:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    return None


def _fetch_flags_and_labels(conn: ImapConnection, uid: str) -> tuple[bool, list[str]]:
    """Return (is_unread, labels_list) for a UID using Gmail's X-GM-LABELS extension."""
    typ, data = conn.uid("fetch", uid, "(FLAGS X-GM-LABELS)")
    unread = True
    labels: list[str] = []
    if typ != "OK" or not data or not data[0]:
        return unread, labels
    line = data[0]
    if isinstance(line, tuple):
        line = line[0]
    if isinstance(line, bytes):
        text = line.decode("utf-8", errors="replace")
    else:
        text = str(line)
    # FLAGS block
    flags_idx = text.find("FLAGS (")
    if flags_idx >= 0:
        end = text.find(")", flags_idx)
        flags = text[flags_idx + 7 : end]
        unread = "\\Seen" not in flags
    # X-GM-LABELS block
    lbl_idx = text.find("X-GM-LABELS (")
    if lbl_idx >= 0:
        end = text.find(")", lbl_idx)
        raw_labels = text[lbl_idx + 13 : end]
        # Labels are space-separated; quoted if they contain spaces
        tokens = _split_label_tokens(raw_labels)
        labels = [t.strip('"').replace("\\\\", "\\") for t in tokens]
    return unread, labels


def _split_label_tokens(raw: str) -> list[str]:
    """Split an X-GM-LABELS payload respecting quoted segments."""
    out: list[str] = []
    buf = ""
    in_quote = False
    for ch in raw:
        if ch == '"':
            in_quote = not in_quote
            buf += ch
            continue
        if ch == " " and not in_quote:
            if buf:
                out.append(buf)
                buf = ""
            continue
        buf += ch
    if buf:
        out.append(buf)
    return out


# --- public operations ---


def list_recent(
    conn: ImapConnection,
    *,
    since_days: int = 7,
    unread_only: bool = False,
    limit: int = 50,
) -> list[EmailSummary]:
    """List recent emails in the currently-selected mailbox (caller must
    have selected the configured label first).

    Returns newest-first. Limited to `limit` messages to keep responses bounded.
    """
    criteria: list[str] = ["SINCE", _imap_date(since_days)]
    if unread_only:
        criteria.append("UNSEEN")

    typ, raw = conn.uid("search", *criteria)
    if typ != "OK":
        return []
    uids = _parse_uid_list(raw)

    # Newest last in IMAP search results → reverse, cap at limit
    uids = list(reversed(uids))[:limit]

    summaries: list[EmailSummary] = []
    for uid in uids:
        raw_bytes = _fetch_raw_message(conn, uid)
        if raw_bytes is None:
            continue
        unread, labels = _fetch_flags_and_labels(conn, uid)
        summaries.append(parse_summary(raw_bytes, uid=uid, unread=unread, labels=labels))
    return summaries


def read_one(conn: ImapConnection, uid: str) -> EmailFull | None:
    """Read a single email by UID. Returns None if it's not in the selected mailbox."""
    raw_bytes = _fetch_raw_message(conn, uid)
    if raw_bytes is None:
        return None
    _, labels = _fetch_flags_and_labels(conn, uid)
    return parse_full(raw_bytes, uid=uid, labels=labels)


def search(
    conn: ImapConnection, *, query: str, since_days: int = 30, limit: int = 50
) -> list[EmailSummary]:
    """Full-text search using Gmail's X-GM-RAW (respects Gmail query syntax).

    Examples of useful queries:
        from:acme.com
        subject:audit
        "specific phrase"
    """
    # Gmail's X-GM-RAW lets us pass their native search syntax
    safe_query = query.replace('"', r'\"')
    criteria = ["SINCE", _imap_date(since_days), "X-GM-RAW", f'"{safe_query}"']
    typ, raw = conn.uid("search", *criteria)
    if typ != "OK":
        return []
    uids = list(reversed(_parse_uid_list(raw)))[:limit]
    summaries: list[EmailSummary] = []
    for uid in uids:
        raw_bytes = _fetch_raw_message(conn, uid)
        if raw_bytes is None:
            continue
        unread, labels = _fetch_flags_and_labels(conn, uid)
        summaries.append(parse_summary(raw_bytes, uid=uid, unread=unread, labels=labels))
    return summaries


def status(conn: ImapConnection, config: Config) -> InboxStatus:
    """Summary of the configured-label inbox — counts + last-received timestamp."""
    # Total
    typ_all, data_all = conn.uid("search", "ALL")
    all_uids = _parse_uid_list(data_all) if typ_all == "OK" else []

    # Unread
    typ_un, data_un = conn.uid("search", "UNSEEN")
    unread_uids = _parse_uid_list(data_un) if typ_un == "OK" else []

    # Last received
    last_received: datetime | None = None
    if all_uids:
        newest = all_uids[-1]
        raw_bytes = _fetch_raw_message(conn, newest)
        if raw_bytes is not None:
            from mcp_gmail_reader.parse import parse_date  # avoid cycle at module load

            import email as _email

            m = _email.message_from_bytes(raw_bytes)
            last_received = parse_date(m.get("Date"))

    return InboxStatus(
        label=config.label,
        total_messages=len(all_uids),
        unread_messages=len(unread_uids),
        last_received_at=last_received,
        checked_at=utc_now(),
    )
