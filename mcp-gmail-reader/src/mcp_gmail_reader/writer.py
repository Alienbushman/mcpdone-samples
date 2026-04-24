"""Write-side operations — drafts + labels only.

Explicitly does NOT expose:
    - send (drafts are reviewed and sent manually in Gmail)
    - delete (one-way-door operation; removed on purpose)
    - move (redundant with label + the scope lock)
    - expunge (same)

If a future tool needs write access that isn't "draft" or "label", it goes
through a new signed-off review. Don't add write tools casually.
"""
from __future__ import annotations

import email.utils
import imaplib
import time
from email.message import EmailMessage

from mcp_gmail_reader.client import ImapConnection, _ensure_ok
from mcp_gmail_reader.config import Config
from mcp_gmail_reader.reader import _fetch_raw_message


class DraftError(Exception):
    """Raised when a draft can't be saved."""


def draft_reply(
    conn: ImapConnection,
    config: Config,
    *,
    uid: str,
    body: str,
    subject_override: str | None = None,
) -> dict[str, str]:
    """Save a draft reply to the original email. Drafts go to Gmail's Drafts
    folder where the user reviews and sends manually.

    Args:
        uid: IMAP UID of the email being replied to.
        body: plain-text body of the reply.
        subject_override: use this subject instead of auto-prefixing 'Re:'.

    Returns:
        {"status": "drafted", "uid_of_original": ..., "subject": ..., "to": ...}

    Raises:
        DraftError: if the original can't be read or the draft can't be saved.
    """
    # Pull the original so we can thread the reply correctly
    raw_original = _fetch_raw_message(conn, uid)
    if raw_original is None:
        raise DraftError(
            f"Could not fetch email UID {uid!r} from the current mailbox. "
            "Either the UID is wrong, or the email isn't in the scoped label."
        )

    import email as _email

    original = _email.message_from_bytes(raw_original)

    orig_subject = original.get("Subject", "").strip()
    orig_message_id = (original.get("Message-ID") or "").strip()
    orig_references = (original.get("References") or "").strip()
    orig_from = original.get("From", "")
    _, orig_from_addr = email.utils.parseaddr(orig_from)
    if not orig_from_addr:
        raise DraftError(
            f"Original email UID {uid!r} has no valid From address — can't reply."
        )

    # Build subject with Re: prefix unless overridden
    if subject_override is not None:
        reply_subject = subject_override
    elif orig_subject.lower().startswith("re:"):
        reply_subject = orig_subject
    else:
        reply_subject = f"Re: {orig_subject}"

    # Build the reply — minimal but threads correctly
    msg = EmailMessage()
    msg["From"] = config.email
    msg["To"] = orig_from_addr
    msg["Subject"] = reply_subject
    if orig_message_id:
        msg["In-Reply-To"] = orig_message_id
        # Build References chain — append original's Message-ID
        if orig_references:
            msg["References"] = f"{orig_references} {orig_message_id}"
        else:
            msg["References"] = orig_message_id
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=config.email.split("@")[1])
    msg.set_content(body)

    # APPEND to Drafts folder with \Draft flag so Gmail shows it in the Drafts tab
    raw_bytes = msg.as_bytes()
    try:
        # `imaplib.Time2Internaldate` wants a float/time.struct_time
        date_time = imaplib.Time2Internaldate(time.time())
    except Exception:
        date_time = imaplib.Time2Internaldate(0)

    typ, data = conn.append(f'"{config.drafts_folder}"', r"(\Draft)", date_time, raw_bytes)
    if typ != "OK":
        detail = b" ".join(b for b in data if isinstance(b, bytes)).decode(errors="replace")
        raise DraftError(
            f"APPEND to {config.drafts_folder} failed: {detail}. "
            "Verify the drafts folder name (Gmail uses '[Gmail]/Drafts' by default — "
            "localised accounts may use a translated name, configurable via DRAFTS_FOLDER)."
        )

    return {
        "status": "drafted",
        "uid_of_original": uid,
        "subject": reply_subject,
        "to": orig_from_addr,
        "drafts_folder": config.drafts_folder,
        "note": "Draft saved. Open Gmail → Drafts to review and send.",
    }


def apply_label(
    conn: ImapConnection,
    config: Config,
    *,
    uid: str,
    label: str,
) -> dict[str, str]:
    """Add a Gmail label to an email (does not remove existing labels).

    Uses Gmail's X-GM-LABELS IMAP extension. The label must already exist
    in the user's Gmail — Gmail will refuse to create one on the fly.

    Args:
        uid: IMAP UID of the email.
        label: label to add (must exist in Gmail). Examples: 'handled',
               'waiting-on-client', 'won'. Cannot be a reserved [Gmail]/...
               folder name.

    Returns:
        {"status": "labeled", "uid": ..., "label": ...}
    """
    if label.startswith("[Gmail]"):
        raise ValueError(
            f"Label {label!r} is a reserved Gmail folder name. Use a custom label."
        )
    if label == config.label:
        # The scoped label is already applied (that's why the email is in this mailbox)
        return {
            "status": "noop",
            "uid": uid,
            "label": label,
            "note": "This email already has the scoped label; no change made.",
        }

    typ, data = conn.uid("STORE", uid, "+X-GM-LABELS", f'("{label}")')
    if typ != "OK":
        detail = b" ".join(b for b in data if isinstance(b, bytes)).decode(errors="replace")
        raise RuntimeError(
            f"STORE X-GM-LABELS failed for UID {uid!r}, label {label!r}: {detail}. "
            "Common cause: label doesn't exist in Gmail. Create it via Settings → Labels."
        )

    return {"status": "labeled", "uid": uid, "label": label}
