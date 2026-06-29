"""Regression fixture for the kubectl-mcp-server FP family (v0.5 fix).

Every @mcp.tool() here passes a tool parameter into a subprocess call
*as a separate argv element* via list concatenation. None of these
should produce a command_injection finding. v0.4 misfired on all of
them; v0.5's list-vs-string-shape distinction in `_is_string_interpolation`
clears them."""
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("kubectl-shape-server")


def _ctx_args(ctx: str) -> list[str]:
    if ctx and ctx.strip():
        return ["--context", ctx.strip()]
    return []


@mcp.tool()
def get_cluster_info(context: str = "") -> str:
    """Canonical kubectl-mcp-server pattern: list + helper(tainted) + list."""
    args = _ctx_args(context)
    result = subprocess.run(
        ["kubectl"] + args + ["cluster-info"], capture_output=True, text=True
    )
    return result.stdout


@mcp.tool()
def list_resources(resource: str, context: str = "") -> str:
    """Same shape but with a tainted parameter directly in a list literal."""
    args = _ctx_args(context)
    result = subprocess.run(
        ["kubectl"] + args + ["get", resource], capture_output=True
    )
    return result.stdout.decode()


@mcp.tool()
def two_taints(branch: str, message: str) -> str:
    """Two tainted parameters, both as argv elements. List concat, no shell."""
    result = subprocess.run(
        ["git", "commit", "-m", message, "--", branch], capture_output=True
    )
    return result.stdout.decode()


@mcp.tool()
def tuple_concat(arg: str) -> str:
    """Tuple concat instead of list concat. Also safe."""
    cmd = ("echo",) + (arg,)
    result = subprocess.run(list(cmd), capture_output=True)
    return result.stdout.decode()
