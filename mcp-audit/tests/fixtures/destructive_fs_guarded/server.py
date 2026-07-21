"""Guarded destructive-fs cases. Each tool deletes a tool-parameter-derived
path BUT confines it first. The check must NOT flag any of these
(false-negative bias: presence of a containment guard suppresses).

Expected findings: 0.
"""
import os
import shutil
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP()

BASE = os.path.realpath("/srv/mcp/scratch")
_MANAGED: set[str] = set()


@mcp.tool()
def cleanup_confined(directory: str) -> str:
    """Realpath + startswith(BASE) containment."""
    real = os.path.realpath(directory)
    if not real.startswith(BASE):
        raise ValueError("outside scratch dir")
    shutil.rmtree(real)
    return "ok"


@mcp.tool()
def cleanup_relative_to(directory: str) -> str:
    """Path.resolve() + relative_to containment."""
    real = Path(directory).resolve()
    real.relative_to(BASE)  # raises if not contained
    shutil.rmtree(real)
    return "ok"


@mcp.tool()
def cleanup_allowset(directory: str) -> str:
    """Membership check against a server-managed allow-set."""
    if directory not in _MANAGED:
        raise ValueError("not a managed dir")
    shutil.rmtree(directory)
    return "ok"
