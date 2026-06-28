"""Safe subprocess patterns the check should NOT flag. Acts as the
regression suite for command_injection's allow-list / negative cases."""
import shlex
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("good-shell-server")


@mcp.tool()
def kubectl_args(args: list[str]) -> str:
    """Safe: list of args, no shell. Parameter IS used, but the call doesn't
    flow through any shell sink — args go to argv directly."""
    return subprocess.run(["kubectl", *args], capture_output=True).stdout.decode()


@mcp.tool()
def git_checkout(branch: str) -> str:
    """Safe: list-form, no shell. The branch goes in as a separate argv
    element so no shell metacharacters can take effect."""
    return subprocess.run(["git", "checkout", branch], check=True).args


@mcp.tool()
def static_command() -> str:
    """Safe: hardcoded command string with shell=True — not tainted by a
    parameter, so not the check's concern."""
    return subprocess.run("uname -a", shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def quoted_input(path: str) -> str:
    """Borderline-safe: shell=True but the parameter is shlex.quote()'d
    first. The check still flags this conservatively (taint reaches the
    sink) — that's an acknowledged false positive in v0.3 and an item on
    the v0.4 cleanup list. Currently this DOES produce a finding."""
    safe = shlex.quote(path)
    return subprocess.run(f"cat {safe}", shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def no_subprocess_at_all(query: str) -> int:
    """Safe: no subprocess sink in the function body."""
    return len(query)


@mcp.tool()
def list_arg_with_concat(branch: str) -> str:
    """Safe: parameter only appears as a list element, no shell, no
    interpolation into a single command string."""
    return subprocess.run(["git", "log", "--oneline", branch]).args
