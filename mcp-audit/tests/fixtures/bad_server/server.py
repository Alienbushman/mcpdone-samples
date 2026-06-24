"""A FastMCP server with the wrapper-layer bug — sync @mcp.tool() that
calls asyncio.run() inside its body. Will pass unit tests of fetch_inner()
but raise RuntimeError on the first MCP protocol call."""
import asyncio

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("bad-server")


async def fetch_inner(url: str) -> str:
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
        return r.text


@mcp.tool()
def fetch_url(url: str) -> str:
    """BAD: drives async work via asyncio.run() inside an MCP tool body.
    asyncio.run() raises RuntimeError when the outer loop is already
    running, which is the case under FastMCP."""
    return asyncio.run(fetch_inner(url))


@mcp.tool()
async def also_bad(url: str) -> str:
    """Also bad — nested asyncio.run() in an async tool."""
    return asyncio.run(fetch_inner(url))
