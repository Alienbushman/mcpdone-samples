"""Data models for email summaries and full messages."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EmailSummary:
    """A lightweight email summary — what `list_leads` returns for each email."""

    uid: str              # IMAP UID, stable within a mailbox
    message_id: str       # RFC 5322 Message-Id header
    from_addr: str
    from_name: str
    subject: str
    received_at: datetime
    snippet: str          # first ~200 chars of the body, plain text
    unread: bool
    labels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["received_at"] = self.received_at.isoformat()
        return d


@dataclass
class EmailFull:
    """Full email payload — what `read_email` returns."""

    uid: str
    message_id: str
    from_addr: str
    from_name: str
    to_addrs: list[str]
    cc_addrs: list[str]
    subject: str
    received_at: datetime
    body_plain: str
    body_html: str | None
    attachments: list[dict[str, str]]  # [{"filename": ..., "content_type": ...}]
    headers: dict[str, str]
    in_reply_to: str | None
    labels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["received_at"] = self.received_at.isoformat()
        return d


@dataclass
class InboxStatus:
    """Snapshot of the configured inbox."""

    label: str
    total_messages: int
    unread_messages: int
    last_received_at: datetime | None
    checked_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "total_messages": self.total_messages,
            "unread_messages": self.unread_messages,
            "last_received_at": (
                self.last_received_at.isoformat() if self.last_received_at else None
            ),
            "checked_at": self.checked_at.isoformat(),
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
