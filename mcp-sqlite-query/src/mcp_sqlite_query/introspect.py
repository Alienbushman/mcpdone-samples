"""Schema introspection tools."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp_sqlite_query.db import connect_read_only


def list_tables(db_path: str | Path) -> list[dict[str, str]]:
    """List all tables and views in the database.

    Returns:
        List of {name, type} dicts where type is 'table' or 'view'.
    """
    with connect_read_only(db_path) as conn:
        rows = conn.execute(
            """
            SELECT name, type
            FROM sqlite_master
            WHERE type IN ('table', 'view')
              AND name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
    return [{"name": r["name"], "type": r["type"]} for r in rows]


def describe_table(db_path: str | Path, table: str) -> dict[str, Any]:
    """Describe the columns of a table.

    Returns:
        {"table": str, "columns": [{"name", "type", "nullable", "pk", "default"}], "row_count": int}
    """
    # Protect against injection via table name — sqlite pragma_table_info is safe,
    # but we still validate the identifier shape.
    if not table or not all(c.isalnum() or c == "_" for c in table):
        raise ValueError(
            f"Table name {table!r} is not a simple identifier. "
            "Only alphanumeric and underscore characters allowed."
        )

    with connect_read_only(db_path) as conn:
        # pragma_table_info returns cid, name, type, notnull, dflt_value, pk
        info = conn.execute(
            f"SELECT * FROM pragma_table_info({_sql_string_literal(table)})"
        ).fetchall()
        if not info:
            # Distinguish "table doesn't exist" from "table has 0 columns"
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type IN ('table','view') AND name = ?",
                (table,),
            ).fetchone()
            if not exists:
                raise ValueError(
                    f"No table or view named {table!r}. "
                    f"Use list_tables() to see what's available."
                )
        # Try to get row count for tables (views may error — catch gracefully)
        try:
            count_row = conn.execute(
                f'SELECT COUNT(*) AS c FROM "{table}"'
            ).fetchone()
            row_count: int | None = int(count_row["c"])
        except Exception:
            row_count = None

    columns = [
        {
            "name": r["name"],
            "type": r["type"] or "",
            "nullable": not bool(r["notnull"]),
            "pk": bool(r["pk"]),
            "default": r["dflt_value"],
        }
        for r in info
    ]
    return {"table": table, "columns": columns, "row_count": row_count}


def schema_summary(db_path: str | Path) -> dict[str, Any]:
    """Return a compact overview of the whole schema.

    Useful for giving Claude a first-pass understanding of a DB in one tool call.
    """
    tables = list_tables(db_path)
    summary = {"database": str(Path(db_path).expanduser().resolve()), "objects": []}
    for obj in tables:
        if obj["type"] == "view":
            summary["objects"].append({**obj, "columns": None, "row_count": None})
            continue
        try:
            described = describe_table(db_path, obj["name"])
            summary["objects"].append(
                {
                    **obj,
                    "columns": [c["name"] for c in described["columns"]],
                    "row_count": described["row_count"],
                }
            )
        except Exception as exc:  # robust to weird tables
            summary["objects"].append({**obj, "error": str(exc)})
    return summary


def _sql_string_literal(s: str) -> str:
    """Quote a string for embedding in SQL (for non-parametric contexts)."""
    return "'" + s.replace("'", "''") + "'"
