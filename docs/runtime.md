# Runtime

The runtime entrypoint runs a scheduler-backed cycle against an explicit SQLite
store. In v1.1, the source-controlled user-service template runs this command
continuously; installing or activating it is a separate approval-gated task.

## Primary driver lifecycle

At startup, Overseer resolves the configured provider/profile and creates or
loads one active driver epoch. Editing configuration does not replace the
active driver. Dispatch intent is persisted before provider execution and is
bound to the current session, epoch, idempotency key, and operation generation.
Stale completions are quarantined.

Recovery resumes the same provider from persisted continuity. Manual handoff is
operator-selected and approval-bound. Controlled failover is separately
policy/evidence/decision/approval-bound. Both reserve the instance, fence new
dispatches, drain or cancel in-flight work, and require outgoing quiescence
before checkpoint/import. Promotion is atomic only after the incoming provider
acknowledges the exact session and epoch identities.

Rollback resumes the outgoing provider only after exact incoming cancellation
is terminal and externally verified. Crash-ambiguous and blocked states remain
paused. `agent-instances`, `agent-session-status`, `GET /agent-dispatches`,
and `GET /agent-failover-executions` provide normalized lifecycle evidence;
`recover-agent-failover` is limited to an exact approved pre-import execution
recovery.

See `docs/agent-provider-architecture.md` for exact commands and pause
semantics.

## Boundaries

- The source template is `systemd/overseer.service`; it is not installed or activated by this repository task.
- The service reads fully resolved `OVERSEER_PYTHON`, `OVERSEER_INSTALL`, `OVERSEER_STORE`, and `PYTHONPATH` values plus fixed `PYTHONDONTWRITEBYTECODE=1` from `%h/.config/overseer/runtime.env`; it does not derive one environment variable from another.
- No host scheduler or socket listener is modified by the runtime unit.
- Runtime state is read from an explicit SQLite store path.
- The runtime writes a heartbeat and advances only due scheduler jobs on each cycle; the scheduler bounds workers, leases, timeouts, evidence, and status projections.
- Configured health probes are read-only adapters owned by independent `health_probe` jobs. Legacy collector flags are deprecated family selectors and are not used by the service unit.
- Runtime health evidence, runs, requests, incidents, and repair attempts are retained within explicit store limits.
- Host inspection snapshots are read-only command and file observations owned by a scheduled `host_inspection` job.
- Each host inspection automatically lets Odo advance security findings to the next safe gate: stage remediation plans, prepare IDS/firewall review packages, queue exact Sisko approval requests, or execute only plans that have no approval gate.
- Station audits are owned by scheduled `station_audit` jobs. The audit lets each crew domain perform safe discovery or staging, route unknown or unplanned resources to Odo, and continue unrelated work while exact approval-gated items wait.
- Knowledge capture is owned by scheduled `knowledge_capture` jobs and writes crew-message and audit-event notes through Ezri's Documents API only within its existing integration boundary.
- Changing the installed user service command, environment, or store requires an explicit approved admin plan before migration or restart.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once
PYTHONPATH=src python3 -m overseer.cli collection-jobs --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli collection-scheduler-status --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli collection-runs --store state/overseer.sqlite3 --limit 50
PYTHONPATH=src python3 -m overseer.cli collection-incidents --store state/overseer.sqlite3 --status open
PYTHONPATH=src python3 -m overseer.cli request-collection-run --store state/overseer.sqlite3 --job-id collection.health.example --requested-by operator --reason "verify after incident"
PYTHONPATH=src python3 -m overseer.cli seed-collection-jobs --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli service-status --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli runtime-status --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli daemon-migration-plan --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli request-daemon-migration --store state/overseer.sqlite3 --requested-by sisko
PYTHONPATH=src python3 -m overseer.cli alerts-summary --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3 --fail-on-unhealthy
```

`runtime-status` is the monitor-friendly surface for Julian and Odo. It reports the service heartbeat, latest host inspection snapshot id and capture time, freshness state, and current high/warning host security finding counts without requiring consumers to parse raw snapshots.

When the scheduled `host_inspection` job runs, Odo does not wait for an operator crew message to work the security queue. The runtime stages listener remediation plans from the latest snapshot, prepares IDS/firewall advisory packages when those gates apply, and creates exact Sisko messages tied to the plan IDs. Firewall, IDS, route, bind, service, and other high-risk changes remain blocked until the applicable IDS, Sisko, and human approval gates are satisfied. Plans with no approval gate may execute automatically after policy and adapter checks pass.

The scheduled `crew_dispatch` job lets Sisko drain open crew requests when due. Dispatchers may inspect local state, refresh inventories, queue health verification, create usage-continuation requests, stage claims, stage remediation plans, approve exact Sisko-targeted plan IDs, or execute no-approval plans after policy checks pass.

The scheduled `usage_continuation` job lets Quark persist dispatch handoff records for usage-limited work that is ready. It does not resume Codex threads; use `dispatch-usage-continuations --resume-codex-projects` for an explicit live resume action.

The scheduled `knowledge_capture` job lets Ezri write deterministic Documents notes for persisted crew messages and audit events. It uses the same local Obsidian env file as the Documents CLI and records captured/failed counts in the durable run projection.

The scheduled `station_audit` job lets the command crew run periodic station operations without waiting for a user prompt. Kira refreshes physical and storage identities, Dax refreshes listener-backed virtual assets, Julian refreshes service resources and health targets, O'Brien stages package maintenance plans, Quark imports Codex project thread resources, and Ezri captures knowledge events. Storage-risk, incomplete, exposed, or unknown resources are routed to Odo for security verification. Package/update plans and other high-risk work are staged but remain paused at their exact approval gates.

`daemon-migration-plan` is a read-only Sisko gate for foreground-to-daemon migration. `request-daemon-migration` and `approve-daemon-migration` record the approval state required before changing user service enablement or runtime commands; they do not edit systemd state or restart services.

Default freshness thresholds:

- Runtime heartbeat: `warning` at 90 seconds, `high` at 300 seconds.
- Host inspection snapshot: `warning` at 120 seconds, `high` at 600 seconds.
- Missing host inspection evidence is reported as `missing`.
- Non-OK freshness states persist `alert` audit events with stable IDs so repeated status reads do not flood duplicate records.

`alerts-summary` reports persisted alert audit events only, grouped by risk and owner domain.

## Source User-Service Template

The checked-in template is not an installed unit. Required environment-file
permissions, disposable-store canary steps, exact activation approval, live
verification, rollback, and forensic preservation are documented in
`docs/v1.1-operations.md`.

The post-approval status commands are:

```bash
systemctl --user status overseer.service --no-pager
journalctl --user -u overseer.service --no-pager -n 80
PYTHONPATH=src python3 -m overseer.cli collection-scheduler-status --store "$OVERSEER_STORE"
```
