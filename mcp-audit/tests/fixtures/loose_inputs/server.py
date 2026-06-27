"""Intentionally loose-typed @mcp.tool() function bodies — every parameter
shape that tool_input_validation flags. Each loose parameter should yield
exactly one finding."""
from typing import Any
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("loose-server")


@mcp.tool()
def search(query: str, limit: int = 10) -> list[str]:
    """LOOSE_STR on `query` — bare str with no max_length.
    `limit` is fine (int is constrained)."""
    return []


@mcp.tool()
def upload_blob(data: bytes, filename: str) -> dict:
    """LOOSE_BYTES on `data` + LOOSE_STR on `filename`. Two findings."""
    return {}


@mcp.tool()
def passthrough(payload: Any) -> Any:
    """LOOSE_ANY on `payload`. Return type isn't checked (only params)."""
    return payload


@mcp.tool()
def bulk_update(records: list[Any]) -> int:
    """LOOSE_COLLECTION on `records` (list[Any])."""
    return len(records)


@mcp.tool()
def configure(options: dict[str, Any]) -> None:
    """LOOSE_COLLECTION on `options` (dict[str, Any])."""
    return None


@mcp.tool()
def untyped(name, count) -> None:
    """UNTYPED on both `name` and `count`. Two findings."""
    return None
