"""Tests for the SQL-safety check and read-only connection."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mcp_sqlite_query.db import connect_read_only, is_safe_select


# --- is_safe_select ---


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "select * from users",
        "SELECT * FROM users WHERE id = ?",
        "  SELECT 1;  ",  # trailing semicolon + whitespace ok
        "WITH t AS (SELECT 1) SELECT * FROM t",
        "select\n  count(*)\nfrom users",
        "SELECT name FROM users -- inline comment\nWHERE plan = 'pro'",
        "SELECT name FROM users /* block comment */ WHERE plan = 'pro'",
    ],
)
def test_is_safe_select_accepts_read_queries(sql: str) -> None:
    assert is_safe_select(sql), f"Should accept: {sql!r}"


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO users VALUES (1, 'a')",
        "UPDATE users SET plan='pro'",
        "DELETE FROM users",
        "DROP TABLE users",
        "CREATE TABLE x (y INT)",
        "ALTER TABLE users ADD COLUMN z INT",
        "PRAGMA journal_mode=WAL",
        "ATTACH DATABASE 'evil.db' AS evil",
        "",
        "   ",
        "SELECT 1; SELECT 2",  # multi-statement
        "SELECT * FROM users; DROP TABLE users",
        "WITH x AS (INSERT INTO users VALUES (1)) SELECT * FROM x",  # write CTE
        "VACUUM",
        "REINDEX",
        "-- just a comment",
    ],
)
def test_is_safe_select_rejects_unsafe(sql: str) -> None:
    assert not is_safe_select(sql), f"Should reject: {sql!r}"


# --- connect_read_only ---


def test_connect_read_only_opens_existing_db(sample_db: Path) -> None:
    with connect_read_only(sample_db) as conn:
        result = conn.execute("SELECT COUNT(*) FROM users").fetchone()
        assert result[0] == 4


def test_connect_read_only_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.db"
    with pytest.raises(FileNotFoundError, match="SQLite database not found"):
        with connect_read_only(missing):
            pass


def test_connect_read_only_rejects_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        with connect_read_only(tmp_path):
            pass


def test_connect_read_only_blocks_writes(sample_db: Path) -> None:
    """Even if the SQL check is bypassed, the connection refuses writes."""
    with connect_read_only(sample_db) as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO users (email) VALUES ('evil@example.com')")
