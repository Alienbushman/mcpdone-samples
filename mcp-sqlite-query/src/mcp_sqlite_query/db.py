"""Connection + SQL-safety helpers."""
from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class UnsafeStatementError(Exception):
    """Raised when a SQL string contains write/DDL operations."""


# Statement-starting keywords we forbid. Read-only SELECT + WITH CTE allowed.
FORBIDDEN_KEYWORDS = {
    "insert",
    "update",
    "delete",
    "drop",
    "create",
    "alter",
    "truncate",
    "replace",
    "attach",
    "detach",
    "pragma",  # pragmas can change DB state (e.g., journal_mode=WAL)
    "vacuum",
    "reindex",
    "analyze",
}

# Allowed leading keywords — SELECT and WITH (CTE) only.
ALLOWED_LEADING = {"select", "with"}


def is_safe_select(sql: str) -> bool:
    """Return True iff `sql` is a read-only SELECT (possibly with CTEs).

    Defence in depth — the connection is also opened read-only, but this
    gives us better error messages and lets us fail early.
    """
    # Strip line + block comments
    cleaned = re.sub(r"--[^\n]*", " ", sql)
    cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL)
    # Normalise whitespace
    cleaned = cleaned.strip()
    if not cleaned:
        return False

    # Reject multi-statement input (trailing ; after the first statement)
    # Allow one trailing ; as a convenience.
    without_trailing = cleaned.rstrip(";").strip()
    if ";" in without_trailing:
        return False

    # First token must be SELECT or WITH
    first_token = re.match(r"\s*(\w+)", without_trailing)
    if not first_token or first_token.group(1).lower() not in ALLOWED_LEADING:
        return False

    # No forbidden keyword as a standalone word anywhere
    # (CTEs can still reference INSERT/UPDATE as strings in literals, but as a
    # keyword they shouldn't appear in a read-only query)
    lower = without_trailing.lower()
    for kw in FORBIDDEN_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", lower):
            return False

    return True


@contextmanager
def connect_read_only(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Open a SQLite connection in read-only mode using the URI form.

    Raises FileNotFoundError if the DB doesn't exist — without this check
    SQLite would silently create an empty DB.
    """
    path = Path(db_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(
            f"SQLite database not found at {path}. "
            "Check the path (relative paths are resolved from CWD) and that the file exists."
        )
    if not path.is_file():
        raise ValueError(f"{path} exists but is not a regular file.")

    # URI form enforces read-only at the driver level
    uri = f"file:{path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
