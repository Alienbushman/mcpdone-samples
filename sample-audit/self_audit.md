# Claude Code Audit — self-directed-agent

**Subject:** self-directed-agent repo
**Audited by:** Claude (acting as the $299 audit tier deliverable for dogfood purposes)
**Date:** 2026-04-20
**Scope:** `.claude/` configuration, repo structure, and workflow integration opportunities

---

## 1. Executive summary

The repo currently has the **bare-minimum Claude Code footprint**: a single `settings.local.json` with three `allow` permissions, no committed team settings, no CLAUDE.md, no hooks, no skills, and no configured MCP servers — even though this repo *ships* an MCP server (`products/mcp-content-opportunity`) that it should dogfood.

The opportunity is large. Implementing the recommendations below would:
- Eliminate ~80% of permission prompts during normal development.
- Give every new Claude Code session automatic project context.
- Wire in the project's own MCP server so content research happens without leaving the editor.
- Add lightweight safety hooks preventing common foot-guns (accidentally committing secrets, running destructive bash, bypassing tests).

Estimated time to implement everything: **~45 minutes**.

---

## 2. Current state

| Component | Status | Notes |
|---|---|---|
| `.claude/settings.json` (shared) | ❌ Missing | No team-wide config |
| `.claude/settings.local.json` | ✅ Exists | 164 bytes, 3 `allow` rules |
| `CLAUDE.md` | ❌ Missing | No project context for new sessions |
| `.claude/skills/` | ❌ Missing | No custom skills |
| `.claude/agents/` | ❌ Missing | No subagent definitions |
| `.claude/commands/` | ❌ Missing | No custom slash commands |
| `.mcp.json` (project MCP servers) | ❌ Missing | Our own MCP server is not wired in |
| Hooks | ❌ Missing | No automation guards |
| `.gitignore` includes `.claude/settings.local.json` | ✅ Yes (added today) | Correct |

**Current allow list** (`.claude/settings.local.json`):
- `WebFetch(domain:www.wearefounders.uk)`
- `WebFetch(domain:www.moneyweb.co.za)`
- `Bash(gh auth *)`

These are research-era artefacts — useful then, but no longer covering current work patterns (Python, uv, pytest, git, gh, Vercel, etc.).

---

## 3. Gaps and recommendations (ranked by impact)

### Priority 1 — Add a team `settings.json` with proper allow list

**Problem:** every `uv run pytest`, `git commit`, `gh` command, etc. prompts for permission. Throws off flow and wastes session time.

**Fix:** create `.claude/settings.json` (committed) with a conservative-but-useful allow list for this repo's toolchain. Drop-in config:

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "permissions": {
    "allow": [
      "Bash(uv *)",
      "Bash(python *)",
      "Bash(pytest *)",
      "Bash(git add *)",
      "Bash(git commit *)",
      "Bash(git status)",
      "Bash(git diff *)",
      "Bash(git log *)",
      "Bash(git push *)",
      "Bash(git pull *)",
      "Bash(git checkout *)",
      "Bash(git branch *)",
      "Bash(git remote -v)",
      "Bash(gh auth status)",
      "Bash(gh repo *)",
      "Bash(gh pr *)",
      "Bash(gh issue *)",
      "Bash(mkdir *)",
      "Bash(ls *)",
      "Bash(cat *)",
      "Bash(npm --version)",
      "Bash(node --version)",
      "WebFetch(domain:docs.anthropic.com)",
      "WebFetch(domain:github.com)",
      "WebFetch(domain:news.ycombinator.com)",
      "WebFetch(domain:reddit.com)",
      "WebSearch"
    ],
    "deny": [
      "Bash(rm -rf *)",
      "Bash(git push --force *)",
      "Bash(git push -f *)",
      "Bash(git reset --hard *)",
      "Bash(sudo *)"
    ]
  }
}
```

**Why deny-list matters:** prevents Claude from ever taking a destructive action without an explicit user bypass. Cheap defence against bad agent behaviour.

### Priority 2 — Create `CLAUDE.md` so new sessions start with project context

**Problem:** every new session starts blank. Claude re-derives what the repo is, what tech is used, and what conventions exist — wasting tokens and risking inconsistency.

**Fix:** create a concise `CLAUDE.md` at repo root. Target ≤100 lines, not a novel. Drop-in content:

```markdown
# CLAUDE.md

## Project
Self-directed-agent experiment. Claude attempts to generate income; human handles real-world execution. Currently bootstrapping a Claude Code consultancy — see `PLAN.md` for the authoritative plan.

## Tech
- Python 3.11+ with uv for package management (`uv sync`, `uv run`, `uv add`)
- Pytest for tests (`uv run pytest`)
- Markdown for docs
- Git with `master` as default branch; remote at `github.com/Alienbushman/self-directed-agent`

## Conventions
- Use absolute imports (`from mcp_content_opportunity.x import y`)
- Type hints on all public functions
- Tests offline-only by default; live network tests live in `smoke_test.py`, never in `tests/`
- Research docs in `research/`; deliverables in `deliverables/`; products in `products/`
- Never commit `.env`, `credentials.json`, or `.claude/settings.local.json`
- `PLAN.md` is authoritative for strategy; update it when direction changes

## What to do first in a new session
1. Read `PLAN.md` — progress tracker is there
2. Check `memory/active_strategy.md` in the user's home Claude folder
3. Work through the next unchecked task in the PLAN

## Don't
- Install packages globally; always use `uv add` within a project dir
- Push to `master` without running tests first
- Create files outside `products/`, `research/`, or `deliverables/` without asking
```

### Priority 3 — Wire the project's own MCP server into Claude Code

**Problem:** we built an MCP server but haven't configured Claude Code to use it. Dogfooding our own product is step one.

**Fix:** create `.mcp.json` at repo root (committed, version-controlled team MCP config):

```json
{
  "mcpServers": {
    "content-opportunity": {
      "command": "uv",
      "args": [
        "--directory",
        "./products/mcp-content-opportunity",
        "run",
        "python",
        "-m",
        "mcp_content_opportunity.server"
      ]
    }
  }
}
```

After adding: in a Claude Code session, type `/mcp` to confirm the server shows as connected, then try "find content opportunities on MCP server security."

### Priority 4 — Add hooks for safety + productivity

Three small hooks pay for themselves immediately:

**4a. Pre-tool-use hook: block secret-looking strings in edits**
Prevents pasting `AWS_SECRET_ACCESS_KEY=AKIA...` style strings into files that would get committed.

**4b. Post-Bash hook: log long-running commands**
Writes timing info to `.claude/bash_log.jsonl` so we can spot flaky/slow commands across sessions.

**4c. Stop hook: run pytest if Python changed and we haven't yet this session**
Catches regressions before the human even asks.

Drop-in `settings.json` addition:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "python scripts/hooks/block_secrets.py"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python scripts/hooks/log_bash.py"
          }
        ]
      }
    ]
  }
}
```

(Hook scripts to be added in `scripts/hooks/` — straightforward, ~30 LOC each.)

### Priority 5 — Custom slash commands for common workflows

Two commands that each save 30+ seconds per invocation:

**`/test` → run pytest with the right directory context**
```
products/mcp-content-opportunity/.claude/commands/test.md
```

Body:
```
---
description: Run the pytest suite for the MCP content opportunity product
---

cd products/mcp-content-opportunity && uv run pytest -v
```

**`/smoke` → run the live smoke test**
```
products/mcp-content-opportunity/.claude/commands/smoke.md
```

### Priority 6 — Two starter skills

**6a. `service-delivery` skill** — defines the SOP for delivering a client's $299/$499/$999 package. Activated when Claude sees a client intake form. Reduces delivery variance.

**6b. `seo-post` skill** — defines the house style for blog posts (word count, structure, meta description, CTA). Activated when asked to draft blog content. Ensures consistent brand voice across the always-on content engine.

---

## 4. Security review

| Risk | Current state | Recommendation |
|---|---|---|
| Secrets in repo | None found (scanned) | Pre-commit hook to block future leaks |
| `allow` list too permissive | No, currently minimal | Keep deny-list on destructive bash |
| `.claude/settings.local.json` in git | No (gitignored) | ✅ correct |
| MCP server permissions | N/A (none configured) | Once added, review tool surface area per server |
| Git push to master without review | Possible | Add Stop hook or CI to require passing tests |

No red flags currently. The main hardening is the deny-list for destructive bash commands.

---

## 5. Prioritised action list

| # | Action | Est. time | Priority |
|---|---|---|---|
| 1 | Commit `.claude/settings.json` with allow/deny lists | 5 min | P1 |
| 2 | Create `CLAUDE.md` at root | 10 min | P1 |
| 3 | Create `.mcp.json` wiring the content-opportunity server | 2 min | P2 |
| 4 | Add pre-commit block-secrets hook | 15 min | P3 |
| 5 | Add `/test` and `/smoke` slash commands | 5 min | P3 |
| 6 | Write `service-delivery` skill | 20 min | P4 (do when first client inquires) |
| 7 | Write `seo-post` skill | 15 min | P4 (do before first blog post) |

**Total to implement P1–P3: ~40 minutes.**

---

## 6. What I did NOT audit

- The contents of `products/mcp-content-opportunity` as a codebase (that's the Build-tier deliverable, not Audit-tier)
- Runtime performance of the existing allow list
- CI/CD setup (none currently, no action needed yet)
- Cross-project conventions (single-project repo, N/A)

If you want a deeper dive on any of these, upsell to the $999 team setup tier.

---

## 7. Appendix — files delivered

Alongside this audit:

- `drop-in/settings.json` — ready-to-commit team settings
- `drop-in/CLAUDE.md` — ready-to-commit project-context file
- `drop-in/.mcp.json` — MCP server wiring
- `drop-in/hooks/block_secrets.py` — pre-tool-use hook
- `drop-in/hooks/log_bash.py` — post-tool-use hook
- `drop-in/commands/test.md` + `smoke.md` — slash commands

All files live under `deliverables/drop-in/` in the repo.
