"""Tests for schema introspection."""
from __future__ import annotations

from pathlib import Path

import pytest

from mcp_sqlite_query.introspect import describe_table, list_tables, schema_summary


def test_list_tables_returns_tables_and_views(sample_db: Path) -> None:
    items = list_tables(sample_db)
    names = {i["name"]: i["type"] for i in items}
    assert names == {"users": "table", "orders": "table", "active_pro_users": "view"}


def test_list_tables_excludes_sqlite_internal(sample_db: Path) -> None:
    items = list_tables(sample_db)
    assert not any(i["name"].startswith("sqlite_") for i in items)


def test_describe_table_returns_columns_and_row_count(sample_db: Path) -> None:
    result = describe_table(sample_db, "users")
    assert result["table"] == "users"
    assert result["row_count"] == 4
    column_names = [c["name"] for c in result["columns"]]
    assert column_names == ["id", "email", "created_at", "plan"]

    id_col = next(c for c in result["columns"] if c["name"] == "id")
    assert id_col["pk"] is True
    assert id_col["nullable"] is True  # SQLite's PRAGMA says nullable unless NOT NULL explicit

    email_col = next(c for c in result["columns"] if c["name"] == "email")
    assert email_col["nullable"] is False


def test_describe_table_handles_view(sample_db: Path) -> None:
    result = describe_table(sample_db, "active_pro_users")
    # Views get column info from pragma_table_info
    column_names = [c["name"] for c in result["columns"]]
    assert column_names == ["id", "email"]
    # Views may or may not have a row count — the important bit is no crash
    assert "row_count" in result


def test_describe_table_missing_raises(sample_db: Path) -> None:
    with pytest.raises(ValueError, match="No table or view"):
        describe_table(sample_db, "nope")


def test_describe_table_rejects_injection_via_name(sample_db: Path) -> None:
    with pytest.raises(ValueError, match="simple identifier"):
        describe_table(sample_db, "users; DROP TABLE users")


def test_schema_summary_includes_all_objects(sample_db: Path) -> None:
    summary = schema_summary(sample_db)
    names = {o["name"] for o in summary["objects"]}
    assert names == {"users", "orders", "active_pro_users"}

    users = next(o for o in summary["objects"] if o["name"] == "users")
    assert users["columns"] == ["id", "email", "created_at", "plan"]
    assert users["row_count"] == 4
