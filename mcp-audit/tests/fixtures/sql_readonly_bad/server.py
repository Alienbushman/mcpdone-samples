"""Keyword-guarded read-only SQL — the bypassable anti-pattern.
Expected findings: 2 (prefix-allowlist tool + keyword-blocklist tool)."""
import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP()
DB = "data.db"


@mcp.tool()
def read_query(query: str) -> list:
    """Run a read-only query."""  # sqlite-explorer shape: prefix allow-list
    q = query.strip().lower()
    if not any(q.startswith(p) for p in ("select", "with")):
        raise ValueError("only SELECT/WITH allowed")
    conn = sqlite3.connect(DB)            # NOT mode=ro -> writes possible
    return conn.execute(query).fetchall()


@mcp.tool()
def safe_sql(sql: str) -> list:
    """Run a safe query."""  # blocklist variant: block DML keywords by substring
    upper = sql.upper()
    if "INSERT" in upper or "UPDATE" in upper or "DELETE" in upper or "DROP" in upper:
        raise ValueError("writes not allowed")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(sql)
    return cur.fetchall()
