"""MCP server exposing SQLite read-only tools.

Run as a Claude Code MCP server:

    {
      "mcpServers": {
        "sqlite": {
          "command": "uv",
          "args": [
            "--directory",
            "/path/to/mcp-sqlite-query",
            "run",
            "python",
            "-m",
            "mcp_sqlite_query.server"
          ]
        }
      }
    }

Claude Code can then ask plain-English questions like:
    "Show me the schema of /tmp/app.db"
    "Query /tmp/app.db: how many users signed up in the last 7 days?"
"""
from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_sqlite_query.db import UnsafeStatementError
from mcp_sqlite_query.introspect import describe_table as _describe
from mcp_sqlite_query.introspect import list_tables as _list_tables
from mcp_sqlite_query.introspect import schema_summary as _schema_summary
from mcp_sqlite_query.query import run_query as _run_query

mcp = FastMCP("sqlite-query")


@mcp.tool()
def list_tables(db_path: str) -> list[dict[str, str]]:
    """List all tables and views in the SQLite database.

    Args:
        db_path: absolute or relative path to a .db / .sqlite / .sqlite3 file.

    Returns:
        List of {name, type} records. `type` is either 'table' or 'view'.
        System tables (sqlite_*) are excluded.
    """
    return _list_tables(db_path)


@mcp.tool()
def describe_table(db_path: str, table: str) -> dict[str, Any]:
    """Describe a table's columns, types, nullability, primary keys, and row count.

    Args:
        db_path: path to the SQLite file.
        table: table or view name — must be a simple identifier.

    Returns:
        {
          "table": str,
          "columns": [{"name", "type", "nullable", "pk", "default"}, ...],
          "row_count": int | null  # null for views that can't be counted
        }
    """
    return _describe(db_path, table)


@mcp.tool()
def schema_summary(db_path: str) -> dict[str, Any]:
    """Return a compact overview of the whole database schema.

    Use this as the first tool call when exploring an unfamiliar database —
    it gives you table names, column names, and row counts in one call.

    Args:
        db_path: path to the SQLite file.
    """
    return _schema_summary(db_path)


@mcp.tool()
def query(
    db_path: str,
    sql: str,
    limit: int = 100,
    parameters: list[Any] | None = None,
) -> dict[str, Any]:
    """Run a read-only SELECT query against the database.

    Only SELECT and WITH...SELECT (CTE) queries are allowed. The server
    opens the connection in read-only mode, so write operations are
    impossible even if they slip past the SQL-shape check.

    Args:
        db_path: path to the SQLite file.
        sql: a single SELECT statement (or WITH CTE followed by SELECT).
             Use ? placeholders for parameters.
        limit: row cap (default 100, max 10,000). The server wraps the
               query with an outer LIMIT so this is enforced regardless.
        parameters: positional parameters for `?` placeholders. Safer than
                    embedding values in the SQL string.

    Returns:
        {
          "columns": [col_names],
          "rows": [[val, val, ...], ...],
          "row_count": int,
          "truncated": bool,     # True if the row cap was hit
          "sql_executed": str    # the actual SQL (with LIMIT wrap) that ran
        }

    Raises:
        UnsafeStatementError: if the SQL is not a pure read-only SELECT.
        sqlite3.DatabaseError: on syntax errors or missing tables.
    """
    try:
        return _run_query(db_path, sql, limit=limit, parameters=parameters)
    except UnsafeStatementError as exc:
        # Return a structured error so Claude can reason about it
        return {
            "error": "UnsafeStatementError",
            "message": str(exc),
            "hint": "Only SELECT/WITH queries allowed. Use describe_table() for schema info.",
        }


def main() -> None:
    """Entry point — runs the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
