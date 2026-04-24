# mcp-gmail-reader

A scope-locked MCP server that lets Claude Code triage your Gmail sales inbox, draft replies, and tag threads — without ever sending or deleting anything.

Built for the real operational problem: you want AI to read incoming leads and write first-draft replies, but you don't want it to have the power to accidentally fire bad emails at customers or delete anything. This server only reads emails in a single Gmail label and only writes to the Drafts folder.

## What it does

Six MCP tools. Three read, three write (drafts and labels only — no send, no delete):

| Tool | Purpose |
|---|---|
| `list_leads(since_days, unread_only, limit)` | Recent emails in the scoped label, newest-first |
| `read_email(uid)` | Full body + headers + attachment metadata |
| `search_leads(query, since_days, limit)` | Gmail query syntax (e.g., `from:acme.com subject:audit`) |
| `check_inbox_status()` | Counts + last-received timestamp, no bodies |
| `draft_reply(uid, body, subject_override?)` | Save a draft to the Drafts folder. You review + send manually. |
| `apply_label(uid, label)` | Add a Gmail label (e.g., `handled`, `waiting-on-client`). Never removes labels. |

## Security shape

Three independent layers, designed so a bug in one doesn't unlock the others:

1. **Label-scoped IMAP selection.** Before any read, the server `SELECT`s the configured label folder. If the label doesn't exist or the selection fails, the tool returns an error — it never falls back to reading the whole inbox.
2. **No send capability.** There's literally no SMTP code. Drafts go to `[Gmail]/Drafts` via IMAP APPEND; sending requires a human clicking Send in the Gmail UI.
3. **No delete capability.** There's no `store +flags \Deleted`, no `expunge`, no `uid move`. Emails can only be *read* or have labels *added*.

Plus:

- **App Password** (not full Google account password). 16-char token, scope-limited to IMAP/SMTP for a single "app", revocable in one click from [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
- **Credentials in `.env`** — gitignored by default. Never commit.
- **Config validation at startup.** Malformed email, too-short password, reserved label names all fail fast with clear errors.

Recommended usage pattern: dedicated Gmail account for business email (not your personal Gmail). Blast radius stays contained to business email only.

## Setup

### 1. Install

```bash
git clone https://github.com/Alienbushman/mcpdone-samples.git
cd mcpdone-samples/mcp-gmail-reader
uv sync
```

### 2. Generate a Gmail App Password

1. Enable 2FA on your Gmail if not already.
2. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
3. Create a new App Password named `mcpdone` (or whatever you want).
4. Copy the 16-character code.

### 3. Set up a Gmail filter to scope the server

In Gmail → gear → **See all settings** → **Filters and Blocked Addresses** → **Create a new filter**:

- **To:** `hello@your-domain.com`
- Create filter → **Apply label** `mcpdone-inbox` (or whatever you want to scope to).

The server will only ever read emails with this label. Your personal email stays invisible to the server.

### 4. Configure

```bash
cp .env.example .env
# Edit .env — fill in GMAIL_ADDRESS, GMAIL_APP_PASSWORD, GMAIL_LABEL
```

### 5. Wire it into Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "gmail-reader": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/mcp-gmail-reader",
        "run",
        "python",
        "-m",
        "mcp_gmail_reader.server"
      ]
    }
  }
}
```

Restart Claude Code. Type `/mcp` — `gmail-reader` should show as connected.

### 6. Try it

In a Claude Code session:

> Show me this week's leads.

Claude calls `list_leads(since_days=7)` and you see the inbox.

> Read email UID 123. Draft a reply using the Audit tier template.

Claude calls `read_email(123)`, drafts a response, calls `draft_reply`. The draft appears in your Gmail Drafts tab. You review + click Send.

## Example session

```
You: What new leads came in today?

Claude: [calls list_leads(since_days=1, unread_only=True)]
  UID 547 · Acme Corp <sam@acme.com> · "Interested in custom MCP for our Postgres"
  UID 551 · Beta Inc <chris@beta.io> · "Team setup quote?"

You: Read 547 and draft a reply — they want the Build tier.

Claude: [calls read_email(547), then draft_reply(547, body="Hi Sam, thanks for..." )]
  Drafted. Open Gmail → Drafts to review + send.
  Proposed subject: Re: Interested in custom MCP for our Postgres
  Proposed to: sam@acme.com

You: [open Gmail Drafts, review, hit Send. Then:]
     Mark 547 as handled.

Claude: [calls apply_label(547, "handled")]
  Labeled UID 547 as 'handled'.
```

## Running tests

```bash
uv run pytest -v
```

55 tests. Zero network calls — all mock the IMAP protocol. Safe to run in CI.

## Project structure

```
mcp-gmail-reader/
├── src/mcp_gmail_reader/
│   ├── __init__.py       # public API
│   ├── config.py         # env loading + validation
│   ├── client.py         # IMAP connection + scope enforcement
│   ├── models.py         # EmailSummary, EmailFull, InboxStatus
│   ├── parse.py          # MIME → models
│   ├── reader.py         # list / read / search / status
│   ├── writer.py         # draft + label (no send, no delete)
│   └── server.py         # MCP tool wiring
└── tests/
    ├── conftest.py       # FakeImap fixture
    ├── test_config.py
    ├── test_client.py
    ├── test_parse.py
    ├── test_reader.py
    └── test_writer.py
```

## Rate limits & good citizenship

Gmail IMAP limits are generous but not infinite:
- Don't hammer `list_leads` in a loop — the server opens a fresh IMAP connection per tool call
- `check_inbox_status` is the cheapest read — use it for "has anything come in?" polling
- If you hit auth-throttling errors, Google may temporarily lock the App Password — wait 10 minutes or regenerate

## Extending

Want more tools? Write-capability changes should be reviewed carefully:
- **Adding a send tool:** don't. The whole point is human-in-the-loop on outbound.
- **Adding a delete tool:** don't unless there's a compelling reason. Labels + archiving cover 99% of deletion needs.
- **Reading a different label:** change `GMAIL_LABEL` in `.env` and restart. The scope lock is deliberately one-label-at-a-time.

## License

MIT.

## Part of the self-directed-agent experiment

Sample #3 in the [mcpdone](https://www.mcpdone.com) sample portfolio. See the repo root for context.
