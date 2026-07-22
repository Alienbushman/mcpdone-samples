"""Correct read-only enforcement + plain arbitrary-SQL. Neither should flag.
Expected findings: 0."""
import sqlite3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP()
DB = "data.db"


@mcp.tool()
def read_query_ro(query: str) -> list:
    """Run a read-only query — enforced at the connection (correct)."""
    conn = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)   # engine-level RO
    return conn.execute(query).fetchall()


@mcp.tool()
def run_sql(sql: str) -> list:
    """Execute arbitrary SQL — this tool's advertised contract, no read-only
    claim and no keyword guard, so there is nothing to bypass."""
    conn = sqlite3.connect(DB)
    return conn.execute(sql).fetchall()


@mcp.tool()
def get_user(user_id: int) -> list:
    """Parameterized query with no keyword guard — safe, not flagged."""
    conn = sqlite3.connect(DB)
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
