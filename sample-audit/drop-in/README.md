# Drop-in configuration package

These files implement the recommendations from [`../self_audit.md`](../self_audit.md) for the self-directed-agent repo. They mirror what a $299 Audit-tier client would receive.

## Install (copy into place, one-time)

```bash
# From the repo root:
mkdir -p .claude scripts/hooks
cp deliverables/drop-in/settings.json .claude/settings.json
cp deliverables/drop-in/CLAUDE.md ./CLAUDE.md
cp deliverables/drop-in/.mcp.json ./.mcp.json
cp deliverables/drop-in/hooks/*.py scripts/hooks/
cp -r deliverables/drop-in/commands .claude/commands
chmod +x scripts/hooks/*.py  # Unix/macOS only
```

Then restart Claude Code so it picks up the new settings.

## What's inside

| File | Lands at | Purpose |
|---|---|---|
| `settings.json` | `.claude/settings.json` | Team-wide allow/deny permissions |
| `CLAUDE.md` | `./CLAUDE.md` | Project context loaded into every session |
| `.mcp.json` | `./.mcp.json` | Wires the content-opportunity MCP server |
| `hooks/block_secrets.py` | `scripts/hooks/block_secrets.py` | Pre-tool-use: blocks Edits containing secrets |
| `hooks/log_bash.py` | `scripts/hooks/log_bash.py` | Post-tool-use: logs Bash invocations |
| `commands/test.md` | `.claude/commands/test.md` | `/test` slash command |
| `commands/smoke.md` | `.claude/commands/smoke.md` | `/smoke` slash command |

## Verifying it works

After install, run these in a fresh Claude Code session:

1. **Permissions:** `uv run pytest` should execute without a permission prompt.
2. **CLAUDE.md pickup:** ask Claude "what is this project?" — it should answer from context.
3. **MCP server:** type `/mcp` — `content-opportunity` should appear as connected.
4. **Slash commands:** type `/test` — pytest should run.
5. **Secret hook:** try editing any file to contain `sk-ant-abc123…xxx` — the edit should be blocked.
