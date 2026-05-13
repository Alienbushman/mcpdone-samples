"""Demonstration of the bug `check_mcp_tool_async.py` catches.

DO NOT use this code. It will break under any real MCP runtime. It exists
solely as a fixture to prove the lint detects the anti-pattern.

Run:
    python ../check_mcp_tool_async.py buggy_server.py

Expected output: a violation flagged on the @mcp.tool() function below.
Exit code 1.
"""
import asyncio

from mcp.server.fastmcp import FastMCP  # noqa: F401  (illustrative import)


# Stand-in: a real FastMCP instance would be `mcp = FastMCP("name")`. For
# fixture purposes we don't actually need to construct one — the lint
# pattern-matches on the decorator shape, not on import.
class _StandInMCP:
    def tool(self):
        def deco(fn):
            return fn
        return deco


mcp = _StandInMCP()


async def _do_async_work() -> dict:
    """Some real coroutine — e.g., an HTTP call to a remote API."""
    return {"hello": "world"}


@mcp.tool()
def broken_tool() -> dict:
    """The bug: sync def calling asyncio.run() inside.

    At runtime under FastMCP, this raises RuntimeError: asyncio.run() cannot
    be called from a running event loop. Demonstrates the bug class that the
    NO_ASYNCIO_RUN_INSIDE_MCP_TOOL check catches.
    """
    return asyncio.run(_do_async_work())


@mcp.tool()
async def fixed_tool() -> dict:
    """The fix: async def + await.

    Reference implementation showing the correct shape side-by-side with the
    broken one above. Tools that do async work should always be async def
    and use await directly instead of asyncio.run().
    """
    return await _do_async_work()
