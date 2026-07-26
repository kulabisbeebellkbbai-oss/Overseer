# Ezri Workflows

Ezri manages Overseer documentation, knowledge capture, and read-only repository visibility.

## Documents Runtime

Ezri uses the local Obsidian Documents integration through Overseer. Check readiness with:

```bash
PYTHONPATH=src python3 -m overseer.cli documents-status
```

Allowed write paths are `Overseer/` and `Inbox/`. Do not write secrets, raw API tokens, cookies, browser local storage values, or local database exports into notes.

`documents-status` also reports Omnisearch readiness. Omnisearch is installed in
the local vault as the `omnisearch` community plugin and should expose its
localhost-only HTTP API at `http://127.0.0.1:51361/search?q=...` after Obsidian
loads the plugin. The vault config keeps that API loopback-bound; if the status
reports connection refused, restart or unlock Obsidian in the trusted GUI
session and re-run `documents-status`.

## Writing Runbooks

Create or replace a runbook from a repo file:

```bash
PYTHONPATH=src python3 -m overseer.cli documents-write-note \
  --path Overseer/Runbooks/ui-regression-testing.md \
  --content-file docs/ui-regression-testing.md \
  --mode replace
```

Use `append` only for dated operating notes. Use `replace` for maintained runbooks.

## Operator Workflow Catalog

Ezri's Documents page includes a dedicated Workflows panel. It is an operator
index, not only a regression-test index. Each row identifies a task, owning crew
member, dashboard page, UI action, and source runbook.

The maintained source is:

```text
Overseer/Runbooks/operator-workflows.md
```

The repository copy is:

```text
docs/operator-workflows.md
```

Clicking a workflow row fills:

- `documents-note-path` with the source runbook path
- `documents-folder` with the source folder
- `documents-query` with the workflow search phrase

The catalog should cover every dashboard page and visible action, including
approval handling, leases and claims, security investigations, health/log
triage, usage-limit refresh checks, documentation operations, git visibility,
and audit review. If the UI lacks a direct capability, the workflow must say so
and route the user through the appropriate crew channel.

## Knowledge Capture

Preview capture candidates:

```bash
PYTHONPATH=src python3 -m overseer.cli capture-knowledge-events \
  --store state/overseer.sqlite3 \
  --dry-run
```

Capture selected crew and audit events:

```bash
PYTHONPATH=src python3 -m overseer.cli capture-knowledge-events \
  --store state/overseer.sqlite3 \
  --kind crew \
  --kind audit
```

## Git Visibility

Ezri displays read-only git state on the Documents page for the whole local
Codex workspace account, not only the Overseer checkout. The account root is
derived from the Overseer project parent, normally:

```text
/home/god/Documents/Codex Workspace
```

The page should show account-level repository inventory:

- repository count
- dirty repository count
- repositories with remotes
- conflicted repository count
- per-repository branch, dirty state, change count, remote owner/repo, and links

The page should also retain current-repository detail:

- branch
- short HEAD
- upstream
- ahead/behind
- dirty state
- staged, unstaged, untracked, and conflicted counts
- working tree file summary
- GitHub links for repository, branch, commit, pull requests, and Actions

CLI:

```bash
PYTHONPATH=src python3 -m overseer.cli git-status
```

API:

```bash
curl -H "Authorization: Bearer $(tr -d '\n' < state/api-token)" \
  http://127.0.0.1:8766/git/status
```

Git visibility is read-only. Mutating actions such as commit, pull, push, branch creation, reset, or checkout require a separate explicit workflow and should not be performed by the dashboard.

## Regression Evidence Workflow

When Ezri documents a UI or gateway regression:

1. Link the summary back to the source route, test file, queue job, crew message,
   or audit event whenever the UI has a stable source page.
2. Keep raw secrets, cookies, browser storage values, and local database exports
   out of repository docs and vault notes.
3. Store maintained runbooks under `Overseer/Runbooks/`.
4. Store dated incident notes or one-off findings under `Overseer/Knowledge/`
   when they come from captured crew or audit events.
5. Record known runner limitations explicitly so future failures are triaged
   against the runner contract before application code is changed.

## UI Auth Debugging Workflow

When the dashboard reports panel `401` errors:

1. Check direct API health and auth:

```bash
curl -fsS http://127.0.0.1:8766/health
curl -fsS -H "Authorization: Bearer $(tr -d '\n' < state/api-token)" \
  http://127.0.0.1:8766/auth-check
```

2. Verify the dashboard-critical endpoints through the protected gateway:

```bash
curl -fsS -H "Authorization: Bearer $(tr -d '\n' < state/api-token)" \
  http://127.0.0.1:8766/Overseer/operator-dashboard
curl -fsS -H "Authorization: Bearer $(tr -d '\n' < state/api-token)" \
  http://127.0.0.1:8766/Overseer/git/status
```

`/Overseer/operator-dashboard` is compact by default and must include
`role_focus` data for Sisko, Kira, O'Brien, Odo, Quark, Dax, and Julian. Use
`?include_summaries=true` only for detailed API inspection.

3. Run the local gateway regression suite:

```bash
python3 -m pytest tests/test_ui_regression.py -q
```

4. Queue Tank remote browser jobs under `local-secrets/remote-testing/jobs/pending`.

5. Compare direct `/ui` results to `/Overseer/ui` results.

6. Record findings in a Julian message and update this runbook if the workflow changes.
