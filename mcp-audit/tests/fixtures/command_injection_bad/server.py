"""Intentional command-injection patterns. Every @mcp.tool() body here
should produce at least one finding when scanned by command_injection.

Each case is annotated with the message_kind the check should emit."""
import os
import subprocess
from subprocess import run, Popen
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("bad-shell-server")


@mcp.tool()
def run_kubectl(args: str) -> str:
    """shell_true: subprocess.run with shell=True and a tainted f-string."""
    cmd = f"kubectl {args}"
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def git_log(branch: str) -> str:
    """shell_true: shell=True + concatenated tainted parameter."""
    return subprocess.run("git log " + branch, shell=True, capture_output=True).stdout.decode()


@mcp.tool()
def query_db(table: str) -> str:
    """os_shell: os.system with tainted f-string."""
    os.system(f"sqlite3 mydb.db 'SELECT * FROM {table}'")
    return "done"


@mcp.tool()
def read_log(path: str) -> str:
    """os_shell: os.popen with concat tainted argument."""
    return os.popen("cat " + path).read()


@mcp.tool()
def from_import_run(branch: str) -> str:
    """shell_true: bare imported `run` (from subprocess import run)."""
    return run(f"git checkout {branch}", shell=True).args


@mcp.tool()
def via_assignment(name: str) -> str:
    """shell_true: tainted via local-variable assignment chain."""
    target = name
    cmd = f"echo {target}"
    subprocess.run(cmd, shell=True)
    return cmd


@mcp.tool()
def tainted_interpolation_no_shell(branch: str) -> str:
    """tainted_interpolation: subprocess.run with f-string but no shell=True.
    Still flagged because a single-string argv frequently gets parsed
    shell-like depending on the platform / sys.argv interpretation."""
    return subprocess.run(f"git checkout {branch}").args


@mcp.tool()
def via_format_method(target: str) -> str:
    """shell_true: taint flows through str.format() into a tainted local,
    then into subprocess.run(..., shell=True)."""
    cmd = "rm -rf {}".format(target)
    subprocess.run(cmd, shell=True)
    return cmd
