"""Intentional destructive-fs-sink bad cases. Each @mcp.tool() below reaches
a delete sink from a tool parameter with NO containment guard.

Expected findings: 4 (one per tool function).
"""
import os
import shutil
from pathlib import Path
from shutil import rmtree

from mcp.server.fastmcp import FastMCP

mcp = FastMCP()


@mcp.tool()
def cleanup_dir(directory: str) -> str:
    """Clean up the temp directory."""  # manim-shaped: raw param -> rmtree
    if os.path.exists(directory):       # exists() is NOT a containment guard
        shutil.rmtree(directory)
    return "ok"


@mcp.tool()
def delete_file(name: str) -> str:
    """Delete a scratch file."""
    target = name                       # taint through assignment
    os.remove(target)
    return "ok"


@mcp.tool()
def unlink_path(rel: str) -> str:
    """Remove a generated artifact."""
    p = Path(rel)                       # Path(tainted) -> tainted receiver
    p.unlink()
    return "ok"


@mcp.tool()
def purge(folder: str) -> str:
    """Purge a workspace."""
    rmtree(folder)                      # bare imported rmtree
    return "ok"
