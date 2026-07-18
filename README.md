# Overseer

Overseer is a local resource manager for coordinating shared machine services, physical assets, virtual assets, usage-limited services, maintenance, updates, and security actions across multiple Codex projects or threads.

Its purpose is to prevent conflicting work by tracking ownership, checkout state, locks, limits, health, and safe timing for resources such as the Protected Gateway, USB and serial devices, emulators, VMs, gateways, proxies, MCP services, hosted pages, update pipelines, storage arrays, and power-sensitive assets.

The first release should include a working initial slice for every major domain:

- physical asset checkout
- virtual asset checkout
- service health monitoring
- maintenance and update scheduling
- usage-limit scheduling
- security monitoring and protective actions

## Project Layout

- `src/` - application source code
- `tests/` - automated tests
- `assets/` - static or generated project assets
- `docs/` - project summary, role map, gates, and design notes

## Development Commands

- `PYTHONPATH=src python3 -m unittest discover -s tests -v` - run the current unit test suite.
- `PYTHONPATH=src python3 -m overseer.cli demo` - print a read-only demo checkout decision.
- `PYTHONPATH=src python3 -m overseer.cli demo --store state/overseer.sqlite3` - persist the demo decision to an explicit ignored local database path.
- `PYTHONPATH=src python3 -m overseer.cli seed-config --config config/overseer.json --store state/overseer.sqlite3` - seed explicit JSON config into an ignored local database path.
- `PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.local --name Local --url http://127.0.0.1:8791/health` - run a read-only health probe against an explicit URL.
- `PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.local --name Local --url http://127.0.0.1:8791/health --store state/overseer.sqlite3` - persist read-only health evidence to an explicit ignored local database path.
- `PYTHONPATH=src python3 -m overseer.cli probe-config --config config/overseer.json --store state/overseer.sqlite3` - probe configured health targets and optionally persist evidence.
- `PYTHONPATH=src python3 -m overseer.cli discover-physical --root /dev/serial/by-id` - read directory entries for physical device paths.
- `PYTHONPATH=src python3 -m overseer.cli discover-physical --root /dev/serial/by-id --store state/overseer.sqlite3` - persist discovered path identities to an explicit ignored local database path.
- `PYTHONPATH=src python3 -m overseer.cli physical-summary --store state/overseer.sqlite3` - summarize persisted physical identities, checkout readiness, power risk, and storage risk.
- `PYTHONPATH=src python3 -m overseer.cli virtual-summary --store state/overseer.sqlite3` - summarize persisted virtual assets, checkout readiness, active claims, queued claims, and reserved ports.
- `PYTHONPATH=src python3 -m overseer.cli command-summary --store state/overseer.sqlite3` - summarize command-level service, resource, claim, health, usage, asset, admin, and alert state.
- `PYTHONPATH=src python3 -m overseer.cli maintenance-summary --store state/overseer.sqlite3` - summarize maintenance targets, install/restart plans, approvals, rollback readiness, and execution status.
- `PYTHONPATH=src python3 -m overseer.cli security-summary --store state/overseer.sqlite3` - summarize security surfaces, alert audit events, host findings, and protective admin plans.
- `PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once` - run one foreground runtime tick against an explicit store.
- `PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once --probe-health-targets --health-evidence-retention-per-target 5` - run one tick, probe configured health targets, and retain bounded evidence per target.
- `PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once --inspect-host` - run one tick and capture read-only host admin evidence.
- `PYTHONPATH=src python3 -m overseer.cli service-status --store state/overseer.sqlite3` - read the stored runtime heartbeat for the local service.
- `PYTHONPATH=src python3 -m overseer.cli runtime-status --store state/overseer.sqlite3` - read runtime heartbeat plus latest host-inspection freshness, stale-state assessment, security finding counts, and persisted freshness alert IDs.
- `PYTHONPATH=src python3 -m overseer.cli alerts-summary --store state/overseer.sqlite3` - summarize persisted alert audit events without reading full state.
- `PYTHONPATH=src python3 -m overseer.cli usage-summary --store state/overseer.sqlite3` - summarize persisted usage limits, capacity state, reset timing, and confidence.
- `PYTHONPATH=src python3 -m overseer.cli inspect-host --store state/overseer.sqlite3` - capture read-only host admin evidence for running user services, listeners, storage, kernel, and OS identity.
- `PYTHONPATH=src python3 -m overseer.cli assess-host-security --store state/overseer.sqlite3` - assess the latest persisted host snapshot for non-loopback TCP listeners.
- `PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --kind user_service_restart --target overseer-api.service --reason "reload approved code"` - prepare an approval-gated admin change plan without executing it.
- `PYTHONPATH=src python3 -m overseer.cli authorizations-required --store state/overseer.sqlite3` - list stored admin change plans waiting for explicit approval.
- `PYTHONPATH=src python3 -m overseer.cli approve-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --approved-by sisko` - record approval metadata for an exact admin plan without executing it.
- `PYTHONPATH=src python3 -m overseer.cli cancel-admin-change --store state/overseer.sqlite3 --plan-id admin.block.example --canceled-by odo --reason "reserved documentation address; no observed hostile traffic"` - cancel a placeholder or superseded admin plan without deleting history.
- `PYTHONPATH=src python3 -m overseer.cli execute-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api` - execute an approved user-service restart plan and persist the execution result.
- `PYTHONPATH=src python3 -m overseer.cli admin-executions --store state/overseer.sqlite3` - list persisted admin execution results.
- `PYTHONPATH=src python3 -m overseer.cli admin-summary --store state/overseer.sqlite3` - summarize admin plans, pending approvals, execution outcomes, and admin audit events.
- `PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3` - summarize latest health evidence per configured target.
- `PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3 --fail-on-unhealthy` - return a non-zero exit when any configured target is unhealthy or missing evidence.
- `PYTHONPATH=src python3 -m overseer.cli list-state --store state/overseer.sqlite3` - inspect stored resources, health targets, health evidence, claims, approvals, and audit events.
- `PYTHONPATH=src python3 -m overseer.cli serve-api --store state/overseer.sqlite3 --host 127.0.0.1 --port 8766 --auth-token-file state/api-token` - serve the localhost-only HTTP API for state, health, and claim operations.
- `PYTHONPATH=src python3 -m overseer.cli request-claim --store state/overseer.sqlite3 --claim-id claim.gateway --resource-id gateway.protected --claim-type lease --owner-thread thread-a --owner-role dax --intent "use gateway" --requested-action "bind gateway" --risk-level low` - request a stored resource checkout and persist the decision.
- `PYTHONPATH=src python3 -m overseer.cli approve-claim --store state/overseer.sqlite3 --approval-id approval.claim.gateway --decided-by sisko` - approve a stored approval request before activation.
- `PYTHONPATH=src python3 -m overseer.cli activate-claim --store state/overseer.sqlite3 --claim-id claim.gateway --approval-id approval.claim.gateway` - mark an approved stored claim active.
- `PYTHONPATH=src python3 -m overseer.cli release-claim --store state/overseer.sqlite3 --claim-id claim.gateway` - release a stored claim.

## Continuous Integration

GitHub Actions runs the unit suite and CLI smoke test on pushes to `main` and pull requests.

## Current Status

- Approved project summary: `docs/project-summary.md`
- DS9-inspired agent role map: `docs/agents.md`
- Initial quality gates: `docs/quality-gates.md`
- Command and safety model: `docs/command-safety-model.md`
- Virtual asset checkout: `docs/virtual-asset-checkout.md`
- Service health monitoring: `docs/service-health-monitoring.md`
- Physical asset checkout: `docs/physical-asset-checkout.md`
- Maintenance and patch operations: `docs/maintenance-and-patch-operations.md`
- Security monitoring: `docs/security-monitoring.md`
- Usage-limit scheduling: `docs/usage-limit-scheduling.md`
- Local in-memory registry: `docs/local-registry.md`
- Approval and audit records: `docs/approval-and-audit.md`
- SQLite persistence contract: `docs/persistence.md`
- Coordinator service: `docs/coordinator-service.md`
- Adapter contracts and dry-run boundary: `docs/adapters-and-dry-run.md`
- Operation planner: `docs/operation-planner.md`
- Local scheduler: `docs/scheduler.md`
- JSON configuration loading: `docs/configuration.md`
- Config seeding: `docs/config-seeding.md`
- Config validation: `docs/config-validation.md`
- Live health probes: `docs/live-health-probes.md`
- Physical discovery: `docs/physical-discovery.md`
- Foreground runtime: `docs/runtime.md`

No runtime stack has been selected yet. Do not commit secrets, credentials, local databases, live service state, or personal exports.
