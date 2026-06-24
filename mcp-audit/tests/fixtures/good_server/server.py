"""A correctly-written FastMCP server. The async tools use `await`
directly; the sync tool does no async work. Both patterns are fine."""
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("good-server")


@mcp.tool()
async def fetch_url(url: str) -> str:
    """Async tool — uses await directly."""
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
        return r.text


@mcp.tool()
def add(a: int, b: int) -> int:
    """Sync tool — pure-CPU, no async work; FastMCP runs it in a thread."""
    return a + b
