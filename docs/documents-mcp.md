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
```

The wrapper should start the MCP server once `OBSIDIAN_API_KEY` is set and the Obsidian Local REST API is listening.

If it exits with `OBSIDIAN_API_KEY is empty`, fill the local secret file. If it starts but tool calls fail, confirm Obsidian is open with the prepared vault and the Local REST API plugin is enabled.
