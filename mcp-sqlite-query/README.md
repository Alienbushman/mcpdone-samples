# mcp-sqlite-query

A read-only MCP server for SQLite. Gives Claude Code safe introspection + query tools against any local `.db` / `.sqlite` / `.sqlite3` file.

Zero dependencies beyond the MCP SDK (SQLite ships with Python). ~300 lines of code, 46 tests.

## What it does

Wire this server into Claude Code, then ask things like:

> "What tables are in `/tmp/app.db`?"
> "Describe the users table."
> "Query /tmp/app.db: how many users signed up in the last 7 days?"

Claude calls the right tool, you get real results.

## Tools exposed

| Tool | Purpose |
|---|---|
| `list_tables(db_path)` | All tables + views, excluding `sqlite_*` internals |
| `describe_table(db_path, table)` | Columns, types, nullability, PK, row count |
| `schema_summary(db_path)` | Compact overview of the whole schema in one call |
| `query(db_path, sql, limit=100, parameters?)` | Run a read-only SELECT |

## Safety

Two independent layers — belt and braces:

1. **SQL-shape check.** `is_safe_select()` rejects anything that isn't a single `SELECT` or `WITH ... SELECT`. Forbidden keywords (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`, `ALTER`, `TRUNCATE`, `REPLACE`, `ATTACH`, `DETACH`, `PRAGMA`, `VACUUM`, `REINDEX`, `ANALYZE`) are flagged as standalone words. Multi-statement input (`SELECT 1; SELECT 2`) is rejected.
2. **Driver-level read-only.** Connections use SQLite's URI form (`file:path?mode=ro`), which rejects writes at the database-engine level. Even if the SQL check misses something, the driver won't.

Plus:

- **Enforced row cap.** Every query is wrapped in an outer `LIMIT` so oversized results can't blow out Claude's context. Default 100, hard max 10,000.
- **Query timeout.** SQLite busy timeout set to 30 s so a bad query can't hang forever.
- **Parametrised queries supported.** `?` placeholders for values — no SQL injection via interpolation.
- **Table identifier validation.** `describe_table()` rejects non-simple identifiers (no injection via table name).

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Alienbushman/mcpdone-samples.git
cd mcpdone-samples/mcp-sqlite-query
uv sync
```

## Wiring into Claude Code

Add to `.mcp.json` at the project root (or `~/.claude/mcp.json` for user scope):

```json
{
  "mcpServers": {
    "sqlite": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/mcp-sqlite-query",
        "run",
        "python",
        "-m",
        "mcp_sqlite_query.server"
      ]
    }
  }
}
```

Restart Claude Code. Type `/mcp` — `sqlite` should show as connected.

## Example session

```
You: What's in /tmp/shop.db?

Claude: [calls schema_summary]

  Database: /tmp/shop.db
  - users (table, 1,240 rows): id, email, created_at, plan
  - orders (table, 3,817 rows): id, user_id, amount_cents, placed_at
  - active_pro_users (view)

You: What plan do our top 5 spenders have?

Claude: [calls query]
  SELECT u.email, u.plan, SUM(o.amount_cents) AS total
  FROM users u JOIN orders o ON o.user_id = u.id
  GROUP BY u.id ORDER BY total DESC LIMIT 5

  alice@example.com   pro           $1,234
  ...
```

## Running locally (without Claude Code)

```python
from mcp_sqlite_query import run_query, schema_summary

schema_summary("/tmp/shop.db")
run_query("/tmp/shop.db", "SELECT email FROM users WHERE plan = ?", parameters=["pro"])
```

## Testing

```bash
uv run pytest -v
```

46 tests. Zero network calls, fully deterministic.

## Project structure

```
mcp-sqlite-query/
├── src/mcp_sqlite_query/
│   ├── __init__.py       # public API
│   ├── db.py             # connection + SQL safety (is_safe_select, connect_read_only)
│   ├── introspect.py     # list_tables, describe_table, schema_summary
│   ├── query.py          # run_query
│   └── server.py         # MCP tool wiring
└── tests/
    ├── conftest.py       # sample DB fixture
    ├── test_db.py        # safety + connection tests
    ├── test_introspect.py
    └── test_query.py
```

## Why you'd use this

- You've got an app's SQLite file and want Claude Code to answer questions about it without writing boilerplate
- You're a data person and want Claude to run ad-hoc SELECTs against a local dataset
- You want read-only sandboxed DB access that can't accidentally mutate state
- You want a reference MCP server that demonstrates safe database tooling patterns

## Why you wouldn't use this

- You need write access (use a different server; you probably want human review for writes anyway)
- You're on Postgres / MySQL / other — this is SQLite-only. Similar shape would work; see the `__init__.py` docstring.
- You need ms-level query latency across thousands of calls — SQLite is fine but the per-call connection open has overhead. Pool if needed.

## License

MIT.

## Part of the self-directed-agent experiment

This is a reference MCP server shipped alongside `mcp-content-opportunity` as sample deliveries in a Claude Code consultancy experiment. See [../../README.md](../../README.md) for context.
