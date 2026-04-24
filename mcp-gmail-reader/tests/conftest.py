"""Shared test fixtures — a fake IMAP connection that the reader/writer can
drive without touching real network.

Everything in the test suite runs offline. No `smoke_test.py` here because
an end-to-end live test needs real credentials; that's a manual check in
the README.
"""
from __future__ import annotations

import email.utils
import time
from email.message import EmailMessage
from typing import Any

import pytest

from mcp_gmail_reader.config import Config


@pytest.fixture
def config() -> Config:
    """A valid Config for tests — doesn't touch the real environment."""
    return Config(
        email="test.inbox@gmail.com",
        app_password="abcdefghijklmnop",  # 16 chars, regex-valid
        label="test-inbox",
        imap_host="imap.gmail.com",
        imap_port=993,
        drafts_folder="[Gmail]/Drafts",
    )


def _make_email(
    *,
    from_addr: str = "sender@example.com",
    from_name: str = "Alice Sender",
    subject: str = "Hello",
    body: str = "This is the body.\nSecond line.",
    message_id: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
    cc: list[str] | None = None,
    date: str | None = None,
) -> bytes:
    msg = EmailMessage()
    msg["From"] = email.utils.formataddr((from_name, from_addr))
    msg["To"] = "test.inbox@gmail.com"
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Subject"] = subject
    msg["Message-ID"] = message_id or email.utils.make_msgid(domain="example.com")
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references
    msg["Date"] = date or email.utils.formatdate(localtime=False)
    msg.set_content(body)
    return msg.as_bytes()


@pytest.fixture
def sample_email_bytes() -> bytes:
    return _make_email()


class FakeImap:
    """In-memory IMAP stand-in. Implements the `ImapConnection` protocol.

    Stores emails keyed by UID. Tracks the currently-selected mailbox, the
    flags/labels per UID, and a list of APPEND'd drafts so tests can assert
    on what was drafted.
    """

    def __init__(self) -> None:
        self.logged_in = False
        self.selected: str | None = None
        self.select_readonly: bool = False
        self.messages: dict[str, bytes] = {}  # uid -> raw RFC 822
        self.flags: dict[str, set[str]] = {}   # uid -> {'\\Seen', ...}
        self.labels: dict[str, set[str]] = {}  # uid -> {'test-inbox', ...}
        self.drafts: list[dict[str, Any]] = []  # appended drafts
        # Stores mailbox name -> set of labels that should be available
        self.existing_labels: set[str] = {"test-inbox"}

    # helpers used only by tests
    def add_message(
        self,
        *,
        uid: str,
        raw: bytes,
        unread: bool = True,
        labels: list[str] | None = None,
    ) -> None:
        self.messages[uid] = raw
        self.flags[uid] = set() if unread else {"\\Seen"}
        self.labels[uid] = set(labels or ["test-inbox"])

    # --- ImapConnection protocol ---

    def login(self, user: str, password: str) -> tuple[str, list[bytes]]:
        if not user or not password:
            return "NO", [b"invalid credentials"]
        self.logged_in = True
        return "OK", [b"logged in"]

    def logout(self) -> tuple[str, list[bytes]]:
        self.logged_in = False
        return "OK", [b"logged out"]

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list[bytes]]:
        # Gmail quotes mailbox names — strip them for comparison
        name = mailbox.strip('"')
        if name not in self.existing_labels and not name.startswith("[Gmail]"):
            return "NO", [f"mailbox {mailbox} not found".encode()]
        self.selected = name
        self.select_readonly = readonly
        return "OK", [str(len(self.messages)).encode()]

    def search(self, charset: str | None, *criteria: str) -> tuple[str, list[bytes]]:
        return self.uid("search", *criteria)

    def fetch(self, message_set: str, message_parts: str) -> tuple[str, list]:
        return self.uid("fetch", message_set, message_parts)

    def uid(self, command: str, *args: str) -> tuple[str, list]:
        command = command.upper()
        if command == "SEARCH":
            return self._uid_search(args)
        if command == "FETCH":
            return self._uid_fetch(args)
        if command == "STORE":
            return self._uid_store(args)
        return "NO", [f"unknown UID command {command}".encode()]

    def _uid_search(self, args: tuple[str, ...]) -> tuple[str, list[bytes]]:
        # Minimal search — honours UNSEEN and 'X-GM-RAW subject' for tests.
        uids = list(self.messages.keys())
        args_upper = [a.upper() for a in args]

        if "UNSEEN" in args_upper:
            uids = [u for u in uids if "\\Seen" not in self.flags.get(u, set())]

        if "X-GM-RAW" in args_upper:
            idx = args_upper.index("X-GM-RAW")
            query = args[idx + 1].strip('"').lower()
            # Super naive substring search across subject and body
            matched: list[str] = []
            for uid in uids:
                raw = self.messages[uid].decode(errors="ignore").lower()
                if query in raw:
                    matched.append(uid)
            uids = matched

        # Return as bytes blob like real IMAP
        blob = " ".join(uids).encode("ascii")
        return "OK", [blob]

    def _uid_fetch(self, args: tuple[str, ...]) -> tuple[str, list]:
        uid = args[0]
        parts = args[1].upper() if len(args) > 1 else ""
        if uid not in self.messages:
            return "OK", []

        if "RFC822" in parts:
            return "OK", [(f"{uid} (UID {uid} RFC822 {{size}})".encode(), self.messages[uid])]

        if "FLAGS" in parts or "X-GM-LABELS" in parts:
            flags = " ".join(sorted(self.flags.get(uid, set())))
            labels = " ".join(f'"{l}"' for l in sorted(self.labels.get(uid, set())))
            line = f"{uid} (FLAGS ({flags}) X-GM-LABELS ({labels}))"
            return "OK", [line.encode()]

        return "NO", [b"unknown fetch part"]

    def _uid_store(self, args: tuple[str, ...]) -> tuple[str, list[bytes]]:
        # args like ('123', '+X-GM-LABELS', '("handled")')
        if len(args) < 3:
            return "NO", [b"bad STORE args"]
        uid, op, value = args[0], args[1].upper(), args[2]
        if uid not in self.messages:
            return "NO", [f"uid {uid} not found".encode()]
        if op == "+X-GM-LABELS":
            labels = [v.strip('"') for v in value.strip("()").split() if v.strip('"')]
            self.labels[uid].update(labels)
            return "OK", [b"stored"]
        return "NO", [f"unknown store op {op}".encode()]

    def append(
        self, mailbox: str, flags: str, date_time: str, message: bytes
    ) -> tuple[str, list[bytes]]:
        name = mailbox.strip('"')
        self.drafts.append({"mailbox": name, "flags": flags, "message": message})
        return "OK", [b"appended"]

    def noop(self) -> tuple[str, list[bytes]]:
        return "OK", [b"noop"]


@pytest.fixture
def fake_imap(sample_email_bytes: bytes) -> FakeImap:
    """A FakeImap pre-populated with one email in the test-inbox label."""
    f = FakeImap()
    f.login("test.inbox@gmail.com", "abcdefghijklmnop")
    f.select('"test-inbox"')
    f.add_message(uid="100", raw=sample_email_bytes, unread=True, labels=["test-inbox"])
    return f


@pytest.fixture
def make_email():
    """Factory fixture — tests call `make_email(subject=..., ...)` to build bytes."""
    return _make_email
