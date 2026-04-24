#!/usr/bin/env python3
"""PostToolUse hook: log Bash invocations + timing to .claude/bash_log.jsonl.

Useful for spotting slow/flaky commands across sessions and building a record
of what was actually run. Does not block the tool use; always exits 0.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path(".claude") / "bash_log.jsonl"


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    if payload.get("tool_name") != "Bash":
        return 0

    tool_input = payload.get("tool_input") or {}
    tool_response = payload.get("tool_response") or {}
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "command": tool_input.get("command", ""),
        "description": tool_input.get("description", ""),
        "exit_code": tool_response.get("exit_code"),
        "duration_ms": tool_response.get("duration_ms"),
    }

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
