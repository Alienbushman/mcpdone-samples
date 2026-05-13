"""Fixture: an @mcp.tool() with no docstring and another with a one-liner.

Both should be flagged by TOOL_DOCSTRING_LENGTH. The well-documented tool
should NOT be flagged.

Run:
    python ../lint_mcp_server.py missing_docstring.py
"""


class _StandInMCP:
    def tool(self):
        def deco(fn):
            return fn
        return deco


mcp = _StandInMCP()


@mcp.tool()
async def no_docstring_at_all() -> dict:
    return {"ok": True}


@mcp.tool()
async def one_liner_docstring() -> dict:
    """Returns a thing."""
    return {"ok": True}


@mcp.tool()
async def well_documented_tool(query: str, limit: int = 20) -> dict:
    """Search the support index for tickets matching `query`.

    Useful when a user asks about a past issue and you want to check whether
    we've answered it before. The match is case-insensitive and matches on
    the ticket subject + first 200 chars of body.

    Returns a list of ticket summaries (id, subject, status, last_updated)
    sorted by recency. Capped at 50 results regardless of `limit` to keep
    response sizes bounded.
    """
    return {"results": [], "query": query, "limit": limit}
