# Documents MCP

The Documents station uses an Obsidian-backed MCP server for local runbooks, decisions, notes, and knowledge-base entries.

## Installed Pieces

- Obsidian desktop app: Flatpak app `md.obsidian.Obsidian`.
- MCP package: user-local npm package `obsidian-mcp-server`.
- Codex MCP entry: `documents`.
- Codex wrapper: `/home/god/.local/bin/overseer-documents-mcp`.
- Codex skill: `/home/god/.codex/skills/obsidian-documents-mcp/SKILL.md`.
- Local vault: `/home/god/Documents/Overseer Documents`.
- Preinstalled vault plugin: `.obsidian/plugins/obsidian-local-rest-api`.
- Local secret file: `/home/god/.local/share/overseer/secrets/obsidian-mcp.env`.

The secret file is outside the repository, mode `0600`, and must never be committed.

## Manual Completion

Open the vault once in Obsidian:

```bash
flatpak run md.obsidian.Obsidian "obsidian://open?vault=Overseer%20Documents"
```

Then in Obsidian:

1. Confirm community plugins are enabled for the vault.
2. Enable `Local REST API with MCP` if Obsidian has not enabled it from the preinstalled plugin list.
3. In Settings -> Community Plugins -> Local REST API, generate or copy the API key.
4. Enable the non-encrypted HTTP server if using `http://127.0.0.1:27123`, or use the HTTPS port at `https://127.0.0.1:27124`.
5. Put the API key into `/home/god/.local/share/overseer/secrets/obsidian-mcp.env`.

Do not paste the key into chat, commit it, or store it in `~/.codex/config.toml`.

## Default Environment

```bash
OBSIDIAN_BASE_URL=http://127.0.0.1:27123
OBSIDIAN_VERIFY_SSL=false
OBSIDIAN_ENABLE_COMMANDS=false
OBSIDIAN_READ_PATHS=
OBSIDIAN_WRITE_PATHS=Overseer/,Inbox/
OBSIDIAN_READ_ONLY=false
```

The default write scope is limited to `Overseer/` and `Inbox/` inside the vault. Broaden it only when Documents needs to manage other vault folders.

## Verification

```bash
codex mcp get documents
/home/god/.local/bin/overseer-documents-mcp
curl -H "Authorization: Bearer $(tr -d '\n' < state/api-token)" http://127.0.0.1:8766/documents/status
PYTHONPATH=src python3 -m overseer.cli documents-status
PYTHONPATH=src python3 -m overseer.cli documents-search --query Overseer
```

The wrapper should start the MCP server once `OBSIDIAN_API_KEY` is set and the Obsidian Local REST API is listening.

If it exits with `OBSIDIAN_API_KEY is empty`, fill the local secret file. If it starts but tool calls fail, confirm Obsidian is open with the prepared vault and the Local REST API plugin is enabled.

## Overseer API Surface

The operator console's Documents tab uses Overseer API routes instead of reading the Obsidian token in the browser:

- `GET /documents/status` checks plugin availability, authentication, version metadata, and the write-prefix boundary.
- `GET /documents/notes?folder=Overseer` lists notes in a vault folder.
- `GET /documents/knowledge-capture-plan?kind=crew&limit=12` previews crew-message and audit-event notes that Ezri can write.
- `POST /documents/search` searches the vault with a JSON body containing `query` and optional `context_length`.
- `POST /documents/notes` appends or replaces a markdown note under `Overseer/` or `Inbox/`.
- `POST /documents/knowledge-capture` writes selected crew-message and audit-event notes under `Overseer/Knowledge/`.

These routes still require the Overseer API bearer token when the local API is started with `--auth-token-file`.

The matching CLI commands are `documents-status`, `documents-notes`, `documents-search`, `documents-write-note`, and `capture-knowledge-events`. `documents-write-note` reads markdown from `--content-file` and still enforces the `Overseer/` or `Inbox/` write-prefix boundary.

## Knowledge Capture

Ezri can capture Overseer crew messages and audit events into stable markdown notes:

```bash
PYTHONPATH=src python3 -m overseer.cli capture-knowledge-events --store state/overseer.sqlite3 --dry-run
PYTHONPATH=src python3 -m overseer.cli capture-knowledge-events --store state/overseer.sqlite3 --kind crew --kind audit --limit 25
```

Capture uses `replace` writes to deterministic paths so repeated runs update the same notes instead of appending duplicates. Note paths are grouped by owner:

- `Overseer/Knowledge/Crew/<owner>/<message-id>.md`
- `Overseer/Knowledge/Events/<owner>/<event-id>.md`

Long IDs use a readable prefix plus a short hash suffix to avoid filename collisions. Capture never passes the Obsidian API key through command-line arguments or browser JavaScript.
