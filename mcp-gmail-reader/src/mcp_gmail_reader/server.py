"""MCP server wiring — exposes read + draft tools over stdio.

Run as a Claude Code MCP server via `.mcp.json`:

    {
      "mcpServers": {
        "gmail-reader": {
          "command": "uv",
          "args": [
            "--directory",
            "/absolute/path/to/mcp-gmail-reader",
            "run",
            "python",
            "-m",
            "mcp_gmail_reader.server"
          ]
        }
      }
    }

All tools are scoped to the label configured in GMAIL_LABEL. Credentials
live in .env on the local machine and never leave the host.
"""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_gmail_reader.client import ScopeViolation, connect, select_label
from mcp_gmail_reader.config import Config, ConfigError, load_config
from mcp_gmail_reader.reader import list_recent, read_one, search as _search, status as _status
from mcp_gmail_reader.writer import DraftError, apply_label as _apply_label
from mcp_gmail_reader.writer import draft_reply as _draft_reply

mcp = FastMCP("gmail-reader")

# Lazy config loading — don't fail at module import; fail on first tool call
# with a clear error instead.
_CONFIG_CACHE: Config | None = None


def _cfg() -> Config:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is None:
        _CONFIG_CACHE = load_config()
    return _CONFIG_CACHE


def _error(exc: Exception, hint: str = "") -> dict[str, Any]:
    """Return a structured error dict rather than raising — gives the calling
    LLM something actionable."""
    return {
        "error": type(exc).__name__,
        "message": str(exc),
        "hint": hint,
    }


# --- Read tools -------------------------------------------------------------


@mcp.tool()
def list_leads(
    since_days: int = 7,
    unread_only: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]] | dict[str, Any]:
    """List recent emails in the configured Gmail label.

    Every email the sales inbox receives gets auto-labelled via a Gmail
    filter rule; this tool reads that labelled folder. Results are newest-
    first and capped at `limit` to keep the response bounded for the LLM.

    Args:
        since_days: Look back this many days. Default 7, cap at 60.
        unread_only: If True, return only emails that haven't been marked read.
        limit: Max results. Default 50, cap 200.

    Returns:
        List of email summaries: uid, from, subject, date, snippet, unread flag.
        Or an error dict if the IMAP connection or label selection fails.
    """
    try:
        cfg = _cfg()
        since_days = max(0, min(since_days, 60))
        limit = max(1, min(limit, 200))
        with connect(cfg) as conn:
            select_label(conn, cfg.label, readonly=True)
            results = list_recent(
                conn, since_days=since_days, unread_only=unread_only, limit=limit
            )
        return [r.to_dict() for r in results]
    except (ConfigError, ScopeViolation) as e:
        return _error(e, hint="Check .env and that GMAIL_LABEL matches a real Gmail label.")
    except Exception as e:
        return _error(e, hint="IMAP connection error. Try again or check Gmail status.")


@mcp.tool()
def read_email(uid: str) -> dict[str, Any]:
    """Read the full content of a specific email (body + headers + attachments list).

    Use the UID returned from list_leads or search_leads. Attachments are
    NOT downloaded — only their filenames and content types are returned.

    Args:
        uid: IMAP UID from list_leads or search_leads.

    Returns:
        Full email: uid, message_id, from/to/cc, subject, body_plain,
        body_html, attachments (metadata only), headers, in_reply_to.
        Or an error dict if the UID isn't in the scoped mailbox.
    """
    try:
        cfg = _cfg()
        with connect(cfg) as conn:
            select_label(conn, cfg.label, readonly=True)
            result = read_one(conn, uid)
        if result is None:
            return _error(
                ValueError(f"No email with UID {uid!r} in label {cfg.label!r}"),
                hint="UID may be stale. Re-run list_leads to get fresh UIDs.",
            )
        return result.to_dict()
    except (ConfigError, ScopeViolation) as e:
        return _error(e)


@mcp.tool()
def search_leads(
    query: str,
    since_days: int = 30,
    limit: int = 50,
) -> list[dict[str, Any]] | dict[str, Any]:
    """Search recent emails using Gmail's native query syntax.

    Useful operators:
        from:acme.com       emails from acme.com
        subject:audit       subject contains 'audit'
        "specific phrase"   exact phrase in any field
        is:unread           unread emails
        has:attachment      has attachments

    Args:
        query: Gmail search expression.
        since_days: Narrow to recent emails (default 30).
        limit: Max results (default 50, cap 200).

    Returns:
        List of matching email summaries, newest-first.
    """
    try:
        cfg = _cfg()
        since_days = max(0, min(since_days, 180))
        limit = max(1, min(limit, 200))
        with connect(cfg) as conn:
            select_label(conn, cfg.label, readonly=True)
            results = _search(conn, query=query, since_days=since_days, limit=limit)
        return [r.to_dict() for r in results]
    except (ConfigError, ScopeViolation) as e:
        return _error(e)


@mcp.tool()
def check_inbox_status() -> dict[str, Any]:
    """Get a snapshot of the inbox: counts + last-received timestamp.

    Cheap way to ask 'has anything come in?' without pulling any email bodies
    or paying for the per-message reads list_leads incurs. Use this as the
    first call in any inbox-triage workflow — if unread_messages is 0, you
    can skip further calls entirely.

    Returns:
        {
          "label": str,
          "total_messages": int,
          "unread_messages": int,
          "last_received_at": ISO timestamp or null,
          "checked_at": ISO timestamp
        }
    """
    try:
        cfg = _cfg()
        with connect(cfg) as conn:
            select_label(conn, cfg.label, readonly=True)
            result = _status(conn, cfg)
        return result.to_dict()
    except (ConfigError, ScopeViolation) as e:
        return _error(e)


# --- Write tools — drafts and labels only ----------------------------------


@mcp.tool()
def draft_reply(uid: str, body: str, subject_override: str | None = None) -> dict[str, Any]:
    """Save a draft reply to the Gmail Drafts folder. Does NOT send.

    After drafting, open Gmail's Drafts tab, review, edit if needed, and
    click Send manually. This two-step is intentional — it keeps a human
    in the loop on every outbound email.

    The draft threads correctly: it inherits the original's Message-ID as
    In-Reply-To and adds it to References, so Gmail groups it with the
    original conversation.

    Args:
        uid: IMAP UID of the email being replied to.
        body: Plain-text body of the reply. Use \\n for line breaks.
        subject_override: Override the auto-generated 'Re: ...' subject.

    Returns:
        {"status": "drafted", "uid_of_original": ..., "subject": ..., "to": ..., "note": ...}
        Or an error dict if the UID is invalid or APPEND fails.
    """
    try:
        cfg = _cfg()
        with connect(cfg) as conn:
            select_label(conn, cfg.label, readonly=True)
            return _draft_reply(
                conn, cfg, uid=uid, body=body, subject_override=subject_override
            )
    except (ConfigError, ScopeViolation, DraftError) as e:
        return _error(e)


@mcp.tool()
def apply_label(uid: str, label: str) -> dict[str, Any]:
    """Add a Gmail label to an email. Does NOT remove existing labels.

    Useful for tracking reply state: 'handled', 'waiting-on-client', 'won',
    'lost', etc. The label must already exist in Gmail — create it first
    via Gmail Settings → Labels.

    Cannot target reserved [Gmail]/... folders.

    Args:
        uid: IMAP UID.
        label: Label name (must exist in Gmail).

    Returns:
        {"status": "labeled" | "noop", "uid": ..., "label": ...}
    """
    try:
        cfg = _cfg()
        with connect(cfg) as conn:
            # Writable selection so STORE succeeds
            select_label(conn, cfg.label, readonly=False)
            return _apply_label(conn, cfg, uid=uid, label=label)
    except (ConfigError, ScopeViolation, ValueError) as e:
        return _error(e)


def main() -> None:
    """Entry point — run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
