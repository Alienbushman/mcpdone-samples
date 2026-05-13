"""Fixture: @mcp.tool() that calls time.sleep() — blocks FastMCP's event loop.

Should be flagged by TOOL_NO_BLOCKING_SLEEP. The async-sleep tool should NOT.

Run:
    python ../lint_mcp_server.py blocking_sleep.py
"""
import asyncio
import time


class _StandInMCP:
    def tool(self):
        def deco(fn):
            return fn
        return deco


mcp = _StandInMCP()


@mcp.tool()
def blocking_tool() -> dict:
    """Pretends to wait for a rate-limit window by calling time.sleep().

    In a sync FastMCP tool, time.sleep blocks the entire server's event loop
    for the duration — every other tool call queued up behind it stalls. This
    demonstrates exactly what the TOOL_NO_BLOCKING_SLEEP check is supposed to
    catch in any FastMCP-shaped server.
    """
    time.sleep(1.0)
    return {"ok": True}


@mcp.tool()
async def correct_async_sleep() -> dict:
    """The correct shape — async tool, await asyncio.sleep.

    Releases the event loop while waiting, so other tool calls continue
    processing. This is what time.sleep should always be replaced with in
    any FastMCP tool.
    """
    await asyncio.sleep(1.0)
    return {"ok": True}
