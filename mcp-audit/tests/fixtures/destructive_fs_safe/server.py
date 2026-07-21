"""Safe destructive-fs cases: the delete sink does NOT operate on a
tool-parameter-derived path, or is not in an @mcp.tool() at all.

Expected findings: 0.
"""
import os
import shutil

from mcp.server.fastmcp import FastMCP

mcp = FastMCP()

BASE = os.path.join(os.path.dirname(__file__), "media")
FIXED_TMP = os.path.join(BASE, "tmp")


@mcp.tool()
def clear_cache() -> str:
    """Delete the server-managed cache. No tool parameter involved."""
    shutil.rmtree(FIXED_TMP)            # fixed, server-side path -> safe
    return "ok"


@mcp.tool()
def note(text: str) -> str:
    """A tool that takes a param but never deletes anything."""
    return text.upper()


def _internal_cleanup(directory: str) -> None:
    """Not an @mcp.tool(): not attacker-reachable via the protocol."""
    shutil.rmtree(directory)


@mcp.tool()
def echo(value: str) -> str:
    """Uses os.remove on a fixed path, ignoring the param."""
    os.remove(FIXED_TMP)                # param `value` never reaches the sink
    return value
