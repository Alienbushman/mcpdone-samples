"""Environment-driven configuration for the Gmail MCP server.

Reads credentials from environment variables, falling back to a .env file
in the project root. All config is validated at load time — if anything's
missing or malformed, the server refuses to start rather than failing
mid-request with a cryptic IMAP error.

Required env:
    GMAIL_ADDRESS       — full Gmail address (e.g., mcpdone.inbox@gmail.com)
    GMAIL_APP_PASSWORD  — 16-char App Password from Google Account settings
    GMAIL_LABEL         — Gmail label to scope access to (e.g., "mcpdone-inbox")

Optional env:
    IMAP_HOST           — default "imap.gmail.com"
    IMAP_PORT           — default 993
    DRAFTS_FOLDER       — default "[Gmail]/Drafts" (Gmail's special drafts folder)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


# Match a Gmail App Password shape (16 alphanumeric chars, spaces optional).
# Google displays them as "abcd efgh ijkl mnop" but often users strip spaces.
_APP_PASSWORD_RE = re.compile(r"^[a-zA-Z0-9]{16}$")


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    """Validated server configuration."""

    email: str
    app_password: str
    label: str
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993
    drafts_folder: str = "[Gmail]/Drafts"

    def __post_init__(self) -> None:
        if "@" not in self.email:
            raise ConfigError(
                f"GMAIL_ADDRESS {self.email!r} does not look like an email address. "
                "Expected format: something@gmail.com"
            )
        if not _APP_PASSWORD_RE.match(self.app_password.replace(" ", "")):
            raise ConfigError(
                "GMAIL_APP_PASSWORD does not look like a Gmail App Password. "
                "Expected 16 alphanumeric characters (spaces are optional and stripped). "
                "Generate one at https://myaccount.google.com/apppasswords"
            )
        if not self.label or self.label.startswith("[Gmail]"):
            raise ConfigError(
                f"GMAIL_LABEL {self.label!r} is invalid. "
                "Use a custom label you created in Gmail (e.g. 'mcpdone-inbox'), "
                "not a reserved [Gmail]/... folder."
            )
        if self.imap_port < 1 or self.imap_port > 65535:
            raise ConfigError(f"IMAP_PORT out of range: {self.imap_port}")


def _strip_password(raw: str) -> str:
    """Gmail displays App Passwords with spaces; strip them so users can
    paste either form and it just works."""
    return raw.replace(" ", "").strip()


def load_config(env_file: Path | None = None) -> Config:
    """Load config from env + optional .env file. Raises ConfigError if invalid."""
    # load_dotenv tolerates missing files; pass override=False so real env wins
    if env_file is not None:
        load_dotenv(env_file, override=False)
    else:
        # Look for .env in the project root (the MCP server's own directory
        # when running via `uv run --directory ...`)
        load_dotenv(override=False)

    required = {
        "GMAIL_ADDRESS": os.environ.get("GMAIL_ADDRESS", "").strip(),
        "GMAIL_APP_PASSWORD": os.environ.get("GMAIL_APP_PASSWORD", "").strip(),
        "GMAIL_LABEL": os.environ.get("GMAIL_LABEL", "").strip(),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise ConfigError(
            f"Missing required environment variables: {', '.join(missing)}. "
            "Copy .env.example to .env and fill in your values."
        )

    imap_port_raw = os.environ.get("IMAP_PORT", "993").strip()
    try:
        imap_port = int(imap_port_raw)
    except ValueError as exc:
        raise ConfigError(f"IMAP_PORT must be an integer, got {imap_port_raw!r}") from exc

    return Config(
        email=required["GMAIL_ADDRESS"],
        app_password=_strip_password(required["GMAIL_APP_PASSWORD"]),
        label=required["GMAIL_LABEL"],
        imap_host=os.environ.get("IMAP_HOST", "imap.gmail.com").strip(),
        imap_port=imap_port,
        drafts_folder=os.environ.get("DRAFTS_FOLDER", "[Gmail]/Drafts").strip(),
    )
