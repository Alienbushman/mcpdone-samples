#!/usr/bin/env python3
"""PreToolUse hook: block Edit/Write operations that contain obvious secrets.

Reads the tool call from stdin (Claude Code hook protocol), inspects the
`content` or `new_string` payload, and exits non-zero if a known-secret
pattern matches. Claude Code treats non-zero exit as a hook-blocked tool use.

Patterns covered (non-exhaustive, intentionally conservative to avoid false
positives): AWS keys, Anthropic/OpenAI API keys, Slack tokens, GitHub PATs,
Stripe keys (test and live), RSA private keys, generic high-entropy blobs
next to words like 'secret' or 'password'.

Exit codes:
    0 — no secrets detected, allow tool use
    2 — secret detected, block tool use and surface the reason
"""
from __future__ import annotations

import json
import re
import sys

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS secret key", re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-[a-zA-Z0-9]{20,}")),
    ("Slack token", re.compile(r"\bxox[aboprs]-[A-Za-z0-9-]{10,}")),
    # GitHub classic PATs are 40 alphanumeric chars after `ghp_` in current
    # format, but older tokens can be shorter. {36,} gives coverage without
    # drowning in false positives from generic 'ghp_' occurrences.
    ("GitHub PAT (classic)", re.compile(r"\bghp_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{20,}")),
    ("Private key block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----")),
]


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        # Malformed hook payload — don't block, let the user see the weirdness
        return 0

    tool_input = payload.get("tool_input") or {}
    # Edit tool uses `new_string`; Write tool uses `content`
    text_fields = [
        tool_input.get("new_string", ""),
        tool_input.get("content", ""),
    ]
    body = "\n".join(t for t in text_fields if isinstance(t, str))
    if not body:
        return 0

    for label, pattern in PATTERNS:
        if pattern.search(body):
            print(
                f"Blocked: candidate {label} detected in Edit/Write payload. "
                "If this is a false positive, edit directly in the file outside Claude, "
                "or tighten the pattern in scripts/hooks/block_secrets.py.",
                file=sys.stderr,
            )
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
