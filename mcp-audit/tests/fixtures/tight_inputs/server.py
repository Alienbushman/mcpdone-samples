"""Tight-typed @mcp.tool() function bodies — every parameter that should
NOT trip tool_input_validation. Acts as a regression suite for the
allow-list logic in the check."""
from typing import Annotated, Literal
from dataclasses import dataclass
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tight-server")


@mcp.tool()
def search(query: Annotated[str, Field(max_length=256)], limit: int = 10) -> list[str]:
    """str CONSTRAINED via Annotated[..., Field(max_length=...)]. Clean."""
    return []


@mcp.tool()
def set_mode(mode: Literal["read", "write", "admin"]) -> str:
    """Literal allow-list. Clean."""
    return mode


@dataclass
class QueryParams:
    text: str
    limit: int


@mcp.tool()
def search_struct(params: QueryParams) -> list[str]:
    """Custom dataclass — assumed to carry its own validation. Clean."""
    return []


class CreateRequest(BaseModel):
    name: Annotated[str, Field(max_length=64)]
    age: int


@mcp.tool()
def create(req: CreateRequest) -> int:
    """Pydantic model. Clean."""
    return 1


@mcp.tool()
def numeric(a: int, b: float, c: bool) -> float:
    """All primitives that are constrained by type. Clean."""
    return a + b + (1 if c else 0)


@mcp.tool()
def list_of_str(items: list[str]) -> int:
    """list[str] is not LOOSE_COLLECTION — only Any-parameterised collections trip."""
    return len(items)
