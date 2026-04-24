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
- Tests offline-only by default; live network tests go in `smoke_test.py`, never in `tests/`
- Research docs in `research/`; deliverables in `deliverables/`; products in `products/`
- Never commit `.env`, `credentials.json`, or `.claude/settings.local.json`
- `PLAN.md` is authoritative for strategy; update it when direction changes

## What to do first in a new session
1. Read `PLAN.md` — progress tracker is there
2. Check `memory/active_strategy.md` in the user's home Claude folder
3. Work through the next unchecked task

## Don't
- Install packages globally; always use `uv add` within a project dir
- Push to `master` without running tests first
- Create files outside `products/`, `research/`, `deliverables/`, or `scripts/` without asking
