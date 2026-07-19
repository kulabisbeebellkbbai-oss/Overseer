# Local Registry

The first usable Overseer core is an in-memory registry backed by explicit SQLite persistence when a caller provides a store path. It is intentionally not a daemon yet; it gives the project a tested coordination surface before background probes or live host actions are introduced.

## Responsibilities

- register resources
- accept resource claims from project threads
- run the shared conflict and approval decision model
- activate claims that are allowed
- queue conflicting claims
- preserve escalation decisions for approvals
- release active claims by id
- keep local state inspectable during tests and early prototypes
- restore persisted resources, claims, decisions, approvals, and audit events across CLI calls

## Boundaries

- No secrets are stored.
- No local device, service, firewall, package manager, or database state is changed.
- Durable state is written only to the explicit store path supplied by the caller.
- Audit logging is represented by stored audit events and decision records.

## CLI Inspection

```bash
PYTHONPATH=src python3 -m overseer.cli list-state --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli approvals-summary --store state/overseer.sqlite3 --status pending
```

## Immediate Growth Path

1. Add a local service API around the stored registry.
2. Add adapters for health probes, device discovery, usage-limit probes, and maintenance runners.
3. Add lease expiry and stale-claim cleanup.
4. Add foreground-to-daemon migration only after an explicit operator approval plan.
