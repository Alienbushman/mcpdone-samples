"""IMAP client wrapper + connection context manager.

Wraps `imaplib.IMAP4_SSL` with:
- Context-manager lifecycle (login + logout guaranteed)
- Label-scoped selection (server can only operate on the configured label)
- Clean errors — IMAP's tuple-return convention is converted to exceptions

Intentionally **does not** expose raw IMAP commands to the MCP tools. All
tool access goes through the typed helpers here, so the scope check is
centralised and can't be bypassed.
"""
from __future__ import annotations

import imaplib
from contextlib import contextmanager
from typing import Iterator, Protocol, runtime_checkable

from mcp_gmail_reader.config import Config


class ImapError(Exception):
    """Raised when an IMAP operation fails or returns NO/BAD."""


class ScopeViolation(Exception):
    """Raised when code tries to access something outside the configured label.

    This is the belt-and-braces check against the whole class of "accidentally
    read all the user's email" bugs.
    """


@runtime_checkable
class ImapConnection(Protocol):
    """The subset of imaplib.IMAP4_SSL we use — isolates us from stdlib quirks
    and makes mocking in tests trivial."""

    def login(self, user: str, password: str) -> tuple[str, list[bytes]]: ...
    def logout(self) -> tuple[str, list[bytes]]: ...
    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list[bytes]]: ...
    def search(self, charset: str | None, *criteria: str) -> tuple[str, list[bytes]]: ...
    def fetch(self, message_set: str, message_parts: str) -> tuple[str, list]: ...
    def uid(self, command: str, *args: str) -> tuple[str, list]: ...
    def append(
        self, mailbox: str, flags: str, date_time: str, message: bytes
    ) -> tuple[str, list[bytes]]: ...
    def noop(self) -> tuple[str, list[bytes]]: ...


def _ensure_ok(result: tuple[str, list], op: str) -> list:
    """Raise ImapError if an IMAP response is anything but OK."""
    status, data = result
    if status != "OK":
        # IMAP response data is a list of bytes — decode for the message
        detail = b" ".join(b for b in data if isinstance(b, bytes)).decode(errors="replace")
        raise ImapError(f"IMAP {op} failed: {status} — {detail}")
    return data


@contextmanager
def connect(config: Config) -> Iterator[ImapConnection]:
    """Open an authenticated IMAP connection. Guarantees logout on exit.

    Usage:
        with connect(config) as conn:
            select_label(conn, config.label)
            ...
    """
    conn: imaplib.IMAP4_SSL | None = None
    try:
        conn = imaplib.IMAP4_SSL(config.imap_host, config.imap_port)
        _ensure_ok(conn.login(config.email, config.app_password), "LOGIN")
        yield conn
    except imaplib.IMAP4.error as exc:  # pragma: no cover — real-network path
        raise ImapError(
            f"Could not connect to Gmail IMAP at {config.imap_host}:{config.imap_port}. "
            "Usually one of: (a) App Password is wrong or revoked, "
            "(b) 2FA isn't enabled on the account, "
            "(c) IMAP access is disabled in Gmail settings. "
            "Regenerate the App Password at https://myaccount.google.com/apppasswords "
            f"and verify the email address {config.email}."
        ) from exc
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                # Can't do much on logout failure; don't mask the original error
                pass


def select_label(conn: ImapConnection, label: str, *, readonly: bool = True) -> None:
    """Select the configured label as the active IMAP folder.

    Gmail exposes labels as IMAP folders. Selecting a label that doesn't
    exist returns NO; we convert that to a clear error message rather than
    letting the caller get a cryptic response.

    Args:
        readonly: if True, opens with EXAMINE (no state changes allowed).
                  Set False only for operations that write (e.g., applying
                  a new label — but the mailbox selection itself is still
                  scope-locked to `label`).
    """
    # Gmail label names may contain spaces or non-ASCII; quote them.
    quoted = f'"{label}"'
    status, data = conn.select(quoted, readonly=readonly)
    if status != "OK":
        detail = b" ".join(b for b in data if isinstance(b, bytes)).decode(errors="replace")
        raise ScopeViolation(
            f"Label {label!r} not found or inaccessible (IMAP response: {detail}). "
            "Either the label doesn't exist in Gmail, or its name was misspelt in "
            "GMAIL_LABEL. Create the label in Gmail settings under 'Labels' and "
            "make sure the name matches exactly (case-sensitive)."
        )


def ensure_label_scope(requested_label: str, configured_label: str) -> None:
    """Refuse any operation that targets a label other than the configured one.

    Called at the entry point of every tool that takes a label argument, to
    stop an accidentally-broader query from reaching the server.
    """
    if requested_label != configured_label:
        raise ScopeViolation(
            f"This server is scoped to label {configured_label!r}. "
            f"Refusing to operate on {requested_label!r}. "
            "If you need to access a different label, change GMAIL_LABEL in .env "
            "and restart the server."
        )
