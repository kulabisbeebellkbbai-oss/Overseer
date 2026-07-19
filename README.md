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
- `PYTHONPATH=src python3 -m overseer.cli physical-summary --store state/overseer.sqlite3` - summarize persisted physical identities, checkout readiness, provenance, power risk, and storage risk.
- `PYTHONPATH=src python3 -m overseer.cli virtual-summary --store state/overseer.sqlite3` - summarize persisted virtual assets, checkout readiness, active claims, queued claims, and reserved ports.
- `PYTHONPATH=src python3 -m overseer.cli command-summary --store state/overseer.sqlite3` - summarize command-level service, resource, claim, health, usage, asset, admin, and alert state.
- `PYTHONPATH=src python3 -m overseer.cli operator-dashboard --store state/overseer.sqlite3` - summarize all operator domains into one role-focused attention dashboard, including admin archive candidates, restore approvals, and security review gate blockers.
- `PYTHONPATH=src python3 -m overseer.cli maintenance-summary --store state/overseer.sqlite3` - summarize maintenance targets, install/update/upgrade/restart plans, approvals, rollback readiness, and execution status.
- `PYTHONPATH=src python3 -m overseer.cli security-summary --store state/overseer.sqlite3` - summarize security surfaces, alert audit events, host findings, protective admin plans, and IDS review gates.
- `PYTHONPATH=src python3 -m overseer.cli health-efficiency --store state/overseer.sqlite3` - summarize service health status, probe types, owner routing, recovery requirements, and latest failures.
- `PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once` - run one foreground runtime tick against an explicit store.
- `PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once --probe-health-targets --health-evidence-retention-per-target 5` - run one tick, probe configured health targets, and retain bounded evidence per target.
- `PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once --inspect-host` - run one tick and capture read-only host admin evidence.
- `PYTHONPATH=src python3 -m overseer.cli service-status --store state/overseer.sqlite3` - read the stored runtime heartbeat for the local service.
- `PYTHONPATH=src python3 -m overseer.cli runtime-status --store state/overseer.sqlite3` - read runtime heartbeat plus latest host-inspection freshness, stale-state assessment, security finding counts, and persisted freshness alert IDs.
- `PYTHONPATH=src python3 -m overseer.cli persistence-security --store state/overseer.sqlite3` - inspect SQLite store file ownership and permissions without creating or changing files.
- `PYTHONPATH=src python3 -m overseer.cli alerts-summary --store state/overseer.sqlite3` - summarize persisted alert audit events without reading full state.
- `PYTHONPATH=src python3 -m overseer.cli audit-summary --store state/overseer.sqlite3 --owner odo --subject-prefix ids-review.` - summarize persisted audit events, optionally filtered by event type, owner, or subject prefix.
- `PYTHONPATH=src python3 -m overseer.cli approvals-summary --store state/overseer.sqlite3 --status pending --owner dax` - summarize stored approval requests, optionally filtered by status, owner, approval level, or subject prefix.
- `PYTHONPATH=src python3 -m overseer.cli usage-summary --store state/overseer.sqlite3` - summarize persisted usage limits, capacity state, reset timing, and confidence.
- `PYTHONPATH=src python3 -m overseer.cli record-usage-limit --store state/overseer.sqlite3 --limit-id limit.service.requests --resource-id svc.service --kind requests --capacity 100 --remaining 25 --window hourly` - record or update Quark usage-limit evidence.
- `PYTHONPATH=src python3 -m overseer.cli usage-continuation-plan --store state/overseer.sqlite3` - summarize Quark continuation requests and dispatch handoffs.
- `PYTHONPATH=src python3 -m overseer.cli dispatch-usage-continuations --store state/overseer.sqlite3` - persist dispatch handoff records for ready usage-limited work.
- `PYTHONPATH=src python3 -m overseer.cli dispatch-usage-continuations --store state/overseer.sqlite3 --resume-codex-projects` - resume ready registered Codex project threads through the local `codex-projects` tmux registry.
- `PYTHONPATH=src python3 -m overseer.cli claim-review --store state/overseer.sqlite3` - review active, queued, expired, and release-blocked claims without releasing or revoking them.
- `PYTHONPATH=src python3 -m overseer.cli inspect-host --store state/overseer.sqlite3` - capture read-only host admin evidence for running user services, listeners, storage, kernel, and OS identity.
- `PYTHONPATH=src python3 -m overseer.cli assess-host-security --store state/overseer.sqlite3` - assess the latest persisted host snapshot for non-loopback TCP listeners.
- `PYTHONPATH=src python3 -m overseer.cli host-security-findings --store state/overseer.sqlite3` - list detailed host security findings and recommendations from the latest persisted host snapshot.
- `PYTHONPATH=src python3 -m overseer.cli host-security-triage --store state/overseer.sqlite3` - group host security findings by listener with read-only mitigation paths and approval boundaries.
- `PYTHONPATH=src python3 -m overseer.cli host-security-sources --store state/overseer.sqlite3` - correlate established TCP source addresses to triaged listeners without classifying them as hostile.
- `PYTHONPATH=src python3 -m overseer.cli create-host-security-source-review --store state/overseer.sqlite3 --remote-address 8.8.8.8 --disposition suspicious --reviewed-by odo --rationale "unexpected remote source"` - record Odo's source evidence review before any block plan is staged.
- `PYTHONPATH=src python3 -m overseer.cli host-security-source-reviews --store state/overseer.sqlite3` - list persisted host security source reviews and block-plan readiness.
- `PYTHONPATH=src python3 -m overseer.cli plan-host-security-source-block --store state/overseer.sqlite3 --review-id source-review.example` - stage an approval-gated source block from an Odo-reviewed hostile source without executing firewall changes.
- `PYTHONPATH=src python3 -m overseer.cli prepare-host-security-ids-review-package --store state/overseer.sqlite3 --plan-id admin.host-security.block-source.8-8-8-8 --source-review-id source-review.example` - prepare the Intrusion Detection advisory package required before approving firewall or source-block plans.
- `PYTHONPATH=src python3 -m overseer.cli export-host-security-ids-review-prompt --store state/overseer.sqlite3 --package-id ids-review.admin.host-security.block-source.8-8-8-8` - write the advisory prompt under the store directory without running the advisor.
- `PYTHONPATH=src python3 -m overseer.cli dispatch-host-security-ids-review-package --store state/overseer.sqlite3 --package-id ids-review.admin.host-security.block-source.8-8-8-8 --dispatched-by odo` - export and dispatch the advisory package to the registered Intrusion Detection Codex thread through `codex-projects`.
- `PYTHONPATH=src python3 -m overseer.cli submit-host-security-ids-review-package --store state/overseer.sqlite3 --package-id ids-review.admin.host-security.block-source.8-8-8-8 --submitted-by odo --prompt-path state/advisories/ids-review.admin.host-security.block-source.8-8-8-8.prompt.md` - record manual advisory handoff when codex-project dispatch is unavailable.
- `PYTHONPATH=src python3 -m overseer.cli record-host-security-ids-review-result --store state/overseer.sqlite3 --package-id ids-review.admin.host-security.block-source.8-8-8-8 --status accepted --reviewed-by odo --advisory-result "approved staged package"` - record a manual advisory result required before approval.
- `PYTHONPATH=src python3 -m overseer.cli host-security-ids-review-packages --store state/overseer.sqlite3` - list prepared IDS/firewall review packages and advisory prompts.
- `PYTHONPATH=src python3 -m overseer.cli host-security-ids-review-summary --store state/overseer.sqlite3` - summarize IDS/firewall review gate counts and latest audit evidence without full advisory prompts.
- `PYTHONPATH=src python3 -m overseer.cli plan-host-security-remediation --store state/overseer.sqlite3 --listener 0.0.0.0:22` - stage an approval-gated firewall deny plan for a triaged listener without executing it.
- `PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --kind user_service_restart --target overseer-api.service --reason "reload approved code"` - prepare an approval-gated admin change plan without executing it.
- `PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.apt.update --kind apt_update --target apt --reason "refresh package metadata"` - prepare an approval-gated package index refresh plan without executing it.
- `PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.apt.upgrade.sqlite --kind apt_upgrade --target sqlite3 --package sqlite3 --reason "apply approved patch"` - prepare an approval-gated package upgrade plan without executing it.
- `PYTHONPATH=src python3 -m overseer.cli authorizations-required --store state/overseer.sqlite3` - list stored admin change plans and restore requests waiting for explicit approval.
- `PYTHONPATH=src python3 -m overseer.cli approve-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --approved-by sisko` - record approval metadata for an exact admin plan without executing it.
- `PYTHONPATH=src python3 -m overseer.cli cancel-admin-change --store state/overseer.sqlite3 --plan-id admin.block.example --canceled-by odo --reason "reserved documentation address; no observed hostile traffic"` - cancel a placeholder or superseded admin plan without deleting history.
- `PYTHONPATH=src python3 -m overseer.cli execute-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api` - execute an approved user-service restart plan and persist the execution result.
- `PYTHONPATH=src python3 -m overseer.cli admin-executions --store state/overseer.sqlite3` - list persisted admin execution results.
- `PYTHONPATH=src python3 -m overseer.cli admin-adapter-capabilities --store state/overseer.sqlite3` - list default and store-approved live admin adapter enablement status.
- `PYTHONPATH=src python3 -m overseer.cli admin-adapter-enablement-plan --kind block_ip` - prepare a read-only high-risk approval plan before enabling a disabled live admin adapter.
- `PYTHONPATH=src python3 -m overseer.cli request-admin-adapter-enablement --store state/overseer.sqlite3 --kind block_ip --requested-by sisko` - create the approval record required before a disabled live admin adapter can become effective for that store.
- `PYTHONPATH=src python3 -m overseer.cli approve-admin-adapter-enablement --store state/overseer.sqlite3 --approval-id approval.admin.adapter.enable.block_ip --approved-by sisko` - approve a requested adapter enablement gate without approving a specific host change or running commands.
- `PYTHONPATH=src python3 -m overseer.cli admin-summary --store state/overseer.sqlite3` - summarize admin plans, pending approvals, execution outcomes, archive candidates, restore approvals, and admin audit events.
- `PYTHONPATH=src python3 -m overseer.cli admin-execution-readiness --store state/overseer.sqlite3` - summarize which admin plans are ready for Overseer execution, need approval, need IDS review, or require manual execution.
- `PYTHONPATH=src python3 -m overseer.cli admin-history-review --store state/overseer.sqlite3` - identify completed or canceled admin plans that are candidates for archive handling without deleting them.
- `PYTHONPATH=src python3 -m overseer.cli admin-history-archive-plan --store state/overseer.sqlite3` - prepare a read-only archive manifest for inactive admin plans without mutating records.
- `PYTHONPATH=src python3 -m overseer.cli admin-history-archives --store state/overseer.sqlite3 --plan-id admin.restart.example` - list persisted admin history archive records, optionally filtered by plan.
- `PYTHONPATH=src python3 -m overseer.cli request-admin-history-archive --store state/overseer.sqlite3 --plan-id admin.restart.example --requested-by sisko` - create the approval request required before archiving inactive admin history.
- `PYTHONPATH=src python3 -m overseer.cli approve-admin-history-archive --store state/overseer.sqlite3 --approval-id approval.admin.archive.admin.restart.example --approved-by sisko` - approve a requested admin history archive.
- `PYTHONPATH=src python3 -m overseer.cli admin-history-restore-readiness --store state/overseer.sqlite3 --plan-id admin.restart.example` - review restore approval level, risk, and evidence before unarchiving a plan.
- `PYTHONPATH=src python3 -m overseer.cli request-admin-history-restore --store state/overseer.sqlite3 --plan-id admin.restart.example --requested-by sisko` - create the approval request required before restoring an archived plan.
- `PYTHONPATH=src python3 -m overseer.cli approve-admin-history-restore --store state/overseer.sqlite3 --approval-id approval.admin.restore.admin.restart.example --approved-by sisko` - approve a requested admin history restore before unarchiving it.
- `PYTHONPATH=src python3 -m overseer.cli archive-admin-history --store state/overseer.sqlite3 --archived-by sisko --approval-id approval.admin.archive.admin.restart.example --plan-id admin.restart.example` - mark archive-ready admin plans archived after explicit approval while preserving original records and audit evidence.
- `PYTHONPATH=src python3 -m overseer.cli unarchive-admin-history --store state/overseer.sqlite3 --plan-id admin.restart.example --restored-by sisko --approval-id approval.admin.restore.admin.restart.example` - restore one archived admin plan to active admin history after its restore approval is approved.
- `PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3` - summarize latest health evidence per configured target.
- `PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3 --fail-on-unhealthy` - return a non-zero exit when any configured target is unhealthy or missing evidence.
- `PYTHONPATH=src python3 -m overseer.cli list-state --store state/overseer.sqlite3` - inspect stored resources, health targets, health evidence, claims, approvals, and audit events.
- `PYTHONPATH=src python3 -m overseer.cli export-state-redacted --store state/overseer.sqlite3` - print a redacted state export for sharing without writing files.
- `PYTHONPATH=src python3 -m overseer.cli serve-api --store state/overseer.sqlite3 --host 127.0.0.1 --port 8766 --auth-token-file state/api-token` - serve the localhost-only HTTP API for state, health, and claim operations.
- `PYTHONPATH=src python3 -m overseer.cli request-claim --store state/overseer.sqlite3 --claim-id claim.gateway --resource-id gateway.protected --claim-type lease --owner-thread thread-a --owner-role dax --intent "use gateway" --requested-action "bind gateway" --risk-level low` - request a stored resource checkout and persist the decision.
- `PYTHONPATH=src python3 -m overseer.cli approve-claim --store state/overseer.sqlite3 --approval-id approval.claim.gateway --decided-by sisko` - approve a stored approval request before activation.
- `PYTHONPATH=src python3 -m overseer.cli activate-claim --store state/overseer.sqlite3 --claim-id claim.gateway --approval-id approval.claim.gateway` - mark an approved stored claim active.
- `PYTHONPATH=src python3 -m overseer.cli release-claim --store state/overseer.sqlite3 --claim-id claim.gateway --released-by dax --reason "work complete and gateway health verified" --evidence-id health.gateway.ok` - release a stored claim and persist release audit evidence.

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
- Foreground runtime and local API service: `docs/runtime.md`

The current runtime is a Python package with CLI entrypoints, an optional localhost-only HTTP API, SQLite persistence, and CI-backed unit coverage. Live host mutation is intentionally limited to user-service restart plans by default. Package installs, package index refreshes, package upgrades, firewall changes, and source blocks become eligible for Overseer execution only when the same store contains an approved adapter enablement request for that exact kind, and each admin change plan still requires its own approval, IDS review when applicable, execution evidence, and verification results.

Do not commit secrets, credentials, local databases, live service state, or personal exports.
