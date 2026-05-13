"""Fixture: @mcp.tool() with untyped parameters.

Should be flagged by TOOL_PARAMS_TYPED. The fully-typed tool should NOT.

Run:
    python ../lint_mcp_server.py untyped_params.py
"""


class _StandInMCP:
    def tool(self):
        def deco(fn):
            return fn
        return deco


mcp = _StandInMCP()


@mcp.tool()
async def untyped_query(query, limit=20) -> dict:
    """Search the support index for tickets matching the query.

    The match is case-insensitive on subject + first 200 chars of body. Returns
    a list of ticket summaries sorted by recency. Limit is capped at 50.
    """
    return {"results": [], "query": query, "limit": limit}


@mcp.tool()
async def partially_typed(query: str, limit=20) -> dict:
    """Same as above but only `query` is typed.

    The second parameter `limit` has no type annotation, so the JSON-Schema
    field generated for it will be unconstrained. The model will pass whatever
    it feels like — string, list, dict, anything.
    """
    return {"results": [], "query": query, "limit": limit}


@mcp.tool()
async def fully_typed(query: str, limit: int = 20) -> dict:
    """Properly typed reference. Should pass the lint.

    Every parameter has a type annotation. FastMCP's JSON-Schema generation
    produces accurate constraints for the model to honour, and the model
    calls this tool with the right types.
    """
    return {"results": [], "query": query, "limit": limit}
