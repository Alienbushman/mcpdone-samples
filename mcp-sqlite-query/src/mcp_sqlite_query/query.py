"""Query execution — with safety rails."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from mcp_sqlite_query.db import UnsafeStatementError, connect_read_only, is_safe_select

DEFAULT_LIMIT = 100
MAX_LIMIT = 10_000
QUERY_TIMEOUT_SECONDS = 30


def run_query(
    db_path: str | Path,
    sql: str,
    *,
    limit: int = DEFAULT_LIMIT,
    parameters: list[Any] | None = None,
) -> dict[str, Any]:
    """Run a read-only SELECT and return structured results.

    Args:
        db_path: path to the SQLite file.
        sql: SELECT or WITH ... SELECT ... — nothing else.
        limit: row cap (default 100, max 10,000). Applied via LIMIT wrap.
        parameters: positional params for `?` placeholders in the SQL.

    Returns:
        {
            "columns": [col_name, ...],
            "rows": [[val, val, ...], ...],
            "row_count": int,
            "truncated": bool,   # True if limit was hit
            "sql_executed": str, # the actual SQL we ran (with LIMIT applied)
        }

    Raises:
        UnsafeStatementError: if the SQL contains write/DDL operations.
        ValueError: on malformed limit.
        sqlite3.DatabaseError: on invalid SQL or other DB errors.
    """
    if not is_safe_select(sql):
        raise UnsafeStatementError(
            "Only single-statement SELECT (or WITH CTE followed by SELECT) queries are allowed. "
            "INSERT, UPDATE, DELETE, CREATE, DROP, PRAGMA, ATTACH, and multi-statement "
            "input are all rejected. If you need schema info, use describe_table() or "
            "schema_summary() instead."
        )

    if limit < 1:
        raise ValueError(f"limit must be >= 1, got {limit}")
    if limit > MAX_LIMIT:
        raise ValueError(
            f"limit must be <= {MAX_LIMIT}, got {limit}. "
            "Very large results slow down Claude context. Page via OFFSET if needed."
        )

    # Wrap the user's query with an outer LIMIT to enforce the cap even if they
    # forgot their own. Over-fetch by one row so we can report truncation.
    # Use a subquery so ORDER BY etc. are preserved.
    wrapped_sql = f"SELECT * FROM ({sql}) LIMIT {limit + 1}"

    params: tuple[Any, ...] = tuple(parameters or ())

    with connect_read_only(db_path) as conn:
        conn.execute(f"PRAGMA busy_timeout = {QUERY_TIMEOUT_SECONDS * 1000}")
        try:
            cursor = conn.execute(wrapped_sql, params)
            rows = cursor.fetchall()
        except sqlite3.DatabaseError as exc:
            raise sqlite3.DatabaseError(
                f"SQL error: {exc}. "
                "Check the query syntax and that all referenced tables/columns exist. "
                "Use list_tables() or describe_table() to verify."
            ) from exc

        columns = [d[0] for d in cursor.description] if cursor.description else []

    truncated = len(rows) > limit
    if truncated:
        rows = rows[:limit]

    return {
        "columns": columns,
        "rows": [list(r) for r in rows],
        "row_count": len(rows),
        "truncated": truncated,
        "sql_executed": wrapped_sql,
    }
