"""Smoke test — runs the CLI against the test fixtures and checks the
expected findings come out. Lives at the project root rather than under
tests/ because it's also a usage example: it's the shortest possible
demonstration of the package end-to-end.

Usage:
    cd products/mcp-audit
    uv run python smoke_test.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
FIXTURES = ROOT / "tests" / "fixtures"


def run_cli(args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_audit.cli", *args],
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def main() -> int:
    failures: list[str] = []

    # 1. Clean fixture should exit 0 with no findings.
    code, out, err = run_cli([str(FIXTURES / "good")])
    if code != 0:
        failures.append(f"good/: expected exit 0, got {code}\nstdout: {out}\nstderr: {err}")
    if "OK" not in out:
        failures.append(f"good/: expected 'OK' in stdout, got: {out!r}")

    # 2. Bad lockfile should exit 1 with one HIGH finding.
    code, out, err = run_cli([str(FIXTURES / "bad_lockfile"), "--json"])
    if code != 1:
        failures.append(f"bad_lockfile/: expected exit 1, got {code}")
    try:
        payload = json.loads(out)
        if payload["finding_count"] != 1:
            failures.append(f"bad_lockfile/: expected 1 finding, got {payload['finding_count']}")
        elif payload["findings"][0]["severity"] != "high":
            failures.append(
                f"bad_lockfile/: expected HIGH severity, got {payload['findings'][0]['severity']}"
            )
    except (json.JSONDecodeError, KeyError) as exc:
        failures.append(f"bad_lockfile/: --json output didn't parse: {exc}\n{out}")

    # 3. Bad server (FastMCP wrapper) should exit 1 with two findings.
    code, out, err = run_cli(
        [str(FIXTURES / "bad_server"), "--json", "--check", "fastmcp_wrapper_layer"]
    )
    if code != 1:
        failures.append(f"bad_server/: expected exit 1, got {code}")
    try:
        payload = json.loads(out)
        if payload["finding_count"] != 2:
            failures.append(
                f"bad_server/: expected 2 findings, got {payload['finding_count']}"
            )
    except (json.JSONDecodeError, KeyError) as exc:
        failures.append(f"bad_server/: --json output didn't parse: {exc}\n{out}")

    # 4. --list-checks should exit 0 with all three v0.2 checks named.
    code, out, _ = run_cli(["--list-checks"])
    for check_name in ("starlette_badhost", "fastmcp_wrapper_layer", "tool_input_validation"):
        if check_name not in out:
            failures.append(f"--list-checks: missing {check_name} (got {out!r})")
    if code != 0:
        failures.append(f"--list-checks: exit code was {code}")

    # 5. Loose-inputs fixture should produce 8 LOW findings (all from the
    # tool_input_validation check).
    code, out, _ = run_cli(
        [str(FIXTURES / "loose_inputs"), "--json", "--check", "tool_input_validation"]
    )
    if code != 1:
        failures.append(f"loose_inputs/: expected exit 1, got {code}")
    try:
        payload = json.loads(out)
        if payload["finding_count"] != 8:
            failures.append(
                f"loose_inputs/: expected 8 tool_input_validation findings, "
                f"got {payload['finding_count']}"
            )
        elif any(f["severity"] != "low" for f in payload["findings"]):
            failures.append(
                "loose_inputs/: expected all LOW severity, "
                f"got {sorted({f['severity'] for f in payload['findings']})}"
            )
    except (json.JSONDecodeError, KeyError) as exc:
        failures.append(f"loose_inputs/: --json output didn't parse: {exc}\n{out}")

    # 6. Tight-inputs fixture should be clean for tool_input_validation.
    code, out, _ = run_cli(
        [str(FIXTURES / "tight_inputs"), "--check", "tool_input_validation"]
    )
    if code != 0 or "OK" not in out:
        failures.append(f"tight_inputs/: expected exit 0 + OK, got code={code}, out={out!r}")

    if failures:
        print("Smoke test FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("Smoke test OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
