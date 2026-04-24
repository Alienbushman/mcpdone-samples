"""Read-only MCP server for SQLite databases.

Exposes tools that let Claude Code introspect and query a local SQLite file
safely. Write operations (INSERT/UPDATE/DELETE/DDL) are rejected both at the
SQL-validation level and by opening the connection in read-only mode.

Public API:
    from mcp_sqlite_query import connect_read_only, is_safe_select
    from mcp_sqlite_query.introspect import list_tables, describe_table
    from mcp_sqlite_query.query import run_query
"""
from mcp_sqlite_query.db import connect_read_only, is_safe_select
from mcp_sqlite_query.introspect import describe_table, list_tables, schema_summary
from mcp_sqlite_query.query import run_query

__all__ = [
    "connect_read_only",
    "describe_table",
    "is_safe_select",
    "list_tables",
    "run_query",
    "schema_summary",
]

__version__ = "0.1.0"
