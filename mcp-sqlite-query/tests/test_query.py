"""Tests for the query executor."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from mcp_sqlite_query.db import UnsafeStatementError
from mcp_sqlite_query.query import run_query


def test_run_query_returns_structured_result(sample_db: Path) -> None:
    result = run_query(sample_db, "SELECT id, email FROM users ORDER BY id")
    assert result["columns"] == ["id", "email"]
    assert result["row_count"] == 4
    assert result["truncated"] is False
    assert result["rows"][0] == [1, "alice@example.com"]


def test_run_query_respects_limit(sample_db: Path) -> None:
    result = run_query(sample_db, "SELECT * FROM users", limit=2)
    assert result["row_count"] == 2
    assert result["truncated"] is True


def test_run_query_does_not_truncate_when_under_limit(sample_db: Path) -> None:
    result = run_query(sample_db, "SELECT * FROM users", limit=100)
    assert result["row_count"] == 4
    assert result["truncated"] is False


def test_run_query_supports_parameters(sample_db: Path) -> None:
    result = run_query(
        sample_db,
        "SELECT email FROM users WHERE plan = ?",
        parameters=["pro"],
    )
    assert result["row_count"] == 2
    emails = {row[0] for row in result["rows"]}
    assert emails == {"alice@example.com", "charlie@example.com"}


def test_run_query_cte_works(sample_db: Path) -> None:
    sql = """
    WITH pro AS (SELECT id FROM users WHERE plan = 'pro')
    SELECT COUNT(*) AS n FROM pro
    """
    result = run_query(sample_db, sql)
    assert result["rows"] == [[2]]


def test_run_query_rejects_writes(sample_db: Path) -> None:
    with pytest.raises(UnsafeStatementError):
        run_query(sample_db, "INSERT INTO users (email) VALUES ('x')")


def test_run_query_rejects_multi_statement(sample_db: Path) -> None:
    with pytest.raises(UnsafeStatementError):
        run_query(sample_db, "SELECT 1; SELECT 2")


def test_run_query_rejects_negative_limit(sample_db: Path) -> None:
    with pytest.raises(ValueError, match="limit must be >= 1"):
        run_query(sample_db, "SELECT 1", limit=0)


def test_run_query_rejects_oversized_limit(sample_db: Path) -> None:
    with pytest.raises(ValueError, match="limit must be <= 10000"):
        run_query(sample_db, "SELECT 1", limit=10_001)


def test_run_query_surfaces_sql_errors_cleanly(sample_db: Path) -> None:
    with pytest.raises(sqlite3.DatabaseError, match="SQL error"):
        run_query(sample_db, "SELECT * FROM no_such_table")


def test_run_query_includes_executed_sql(sample_db: Path) -> None:
    result = run_query(sample_db, "SELECT 1 AS x")
    assert "LIMIT" in result["sql_executed"]
    assert "SELECT 1 AS x" in result["sql_executed"]
