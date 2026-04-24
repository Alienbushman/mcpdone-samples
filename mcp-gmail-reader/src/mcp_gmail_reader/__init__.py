"""Gmail MCP server — read-only scope-locked access to a single label.

Public API:
    from mcp_gmail_reader import load_config, connect, select_label
    from mcp_gmail_reader.models import EmailSummary, EmailFull, InboxStatus
    from mcp_gmail_reader.reader import list_recent, read_one, search, status
    from mcp_gmail_reader.writer import draft_reply, apply_label
"""
from mcp_gmail_reader.client import ImapError, ScopeViolation, connect, select_label
from mcp_gmail_reader.config import Config, ConfigError, load_config
from mcp_gmail_reader.models import EmailFull, EmailSummary, InboxStatus

__all__ = [
    "Config",
    "ConfigError",
    "EmailFull",
    "EmailSummary",
    "ImapError",
    "InboxStatus",
    "ScopeViolation",
    "connect",
    "load_config",
    "select_label",
]

__version__ = "0.1.0"
