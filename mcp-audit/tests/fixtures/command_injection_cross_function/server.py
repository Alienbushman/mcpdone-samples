"""Cross-function taint patterns (v0.4). Each @mcp.tool() entry reaches a
sink only by passing user-controlled input through a same-file helper.
v0.3 missed every one of these; v0.4 catches them via single-step (and
multi-step) call recursion."""
import os
import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("crossfn-server")


# --- Single-hop: tool -> helper -> sink -------------------------------------


def _run_shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def execute_query(query: str) -> str:
    """Single-hop via _run_shell; taint flows query -> cmd parameter ->
    subprocess.run(shell=True). v0.3 misses this, v0.4 catches it."""
    return _run_shell(f"sqlite3 mydb 'SELECT * FROM {query}'")


def _shell_via_os(target: str) -> None:
    os.system(f"echo {target}")


@mcp.tool()
def echo_target(name: str) -> None:
    """Single-hop via _shell_via_os to os.system sink."""
    _shell_via_os(name)


# --- Two-hop: tool -> helper -> helper -> sink ------------------------------


def _exec_with_logging(cmd: str) -> str:
    return _run_shell(cmd)  # forwards through a second helper


@mcp.tool()
def deep_query(q: str) -> str:
    """Two-hop: deep_query -> _exec_with_logging -> _run_shell -> sink."""
    return _exec_with_logging(f"select {q}")


# --- Negative case: helper uses list-form subprocess; no finding expected ---


def _safe_via_list(cmd_argv: list[str]) -> str:
    # No shell, list args — taint flows in but doesn't reach a shell sink
    return subprocess.run(cmd_argv, capture_output=True).stdout.decode()


@mcp.tool()
def safe_passthrough(arg: str) -> str:
    """Multi-hop but the helper uses safe list-form subprocess; should NOT
    flag. Verifies the cross-function recursion doesn't blindly flag
    every helper-touching tool."""
    return _safe_via_list(["echo", arg])


# --- Negative case: helper is called without tainted args; no finding -------


def _exec_static_command() -> str:
    return subprocess.run("uname -a", shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def system_info(req_id: str) -> str:
    """The helper has shell=True but req_id never flows into it. Should NOT
    flag — recursion only fires when at least one tainted arg crosses."""
    static_result = _exec_static_command()
    return f"{req_id}: {static_result}"
