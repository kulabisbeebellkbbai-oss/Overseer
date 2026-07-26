# Local API

The Overseer API is a loopback-only HTTP surface for local Codex threads and tools that should not shell out to the CLI for every operation.

## Boundary

- The API may bind only to `127.0.0.1` or `localhost`.
- No firewall rule is created.
- No external address is exposed.
- It uses the same explicit SQLite store path as the CLI and user service.

## Run

```bash
PYTHONPATH=src python3 -m overseer.cli serve-api --store state/overseer.sqlite3 --host 127.0.0.1 --port 8766 --auth-token-file state/api-token
```

`GET /health` is always available for local service monitoring. All other endpoints require `Authorization: Bearer <token>` when `--auth-token-file` is configured.

`GET /ui` serves the local operator console. The console shell does not embed or expose the bearer token; when the API is token-protected, enter the local token in the console to load protected JSON endpoints from the browser session.

## Read Endpoints

- `GET /health`
- `GET /ui`
- `GET /service-status`
- `GET /runtime-status`
- `GET /persistence/security`
- `GET /state/redacted`
- `GET /command-summary`
- `GET /operator-dashboard`
- `GET /maintenance-summary`
- `GET /maintenance/package-status`
- `POST /maintenance/package-update-plans`
- `GET /alerts-summary`
- `GET /audit-summary`
- `GET /approvals-summary`
- `GET /security-summary`
- `GET /usage-summary`
- `GET /usage/remote-testing`
- `GET /documents/status`
- `GET /documents/notes`
- `GET /documents/knowledge-capture-plan`
- `GET /usage/continuation-plan`
- `GET /physical-summary`
- `GET /virtual-summary`
- `GET /virtual/operations`
- `POST /virtual/target-setup-requests`
- `POST /virtual/target-setup-requests/execute`
- `POST /virtual/destroy-requests`
- `POST /virtual/destroy-requests/approve`
- `POST /virtual/destroy-requests/execute`
- `GET /virtual/image-scans`
- `POST /virtual/image-scans`
- `POST /virtual/image-scans/approve`
- `POST /virtual/image-scans/execute`
- `GET /observability/metric-history`
- `GET /observability/performance-history`
- `GET /health-summary`
- `GET /health-efficiency`
- `GET /host/security`
- `GET /host/security/findings`
- `GET /host/security/triage`
- `GET /host/security/listener-review-queue`
- `GET /host/security/sources`
- `GET /host/security/source-review-queue`
- `GET /host/security/source-reviews`
- `GET /host/security/ids-review-packages`
- `GET /host/security/ids-review-summary`
- `GET /identity/rotation-requests`
- `GET /admin/authorizations-required`
- `GET /admin/adapter-capabilities`
- `GET /admin/adapter-enablement-plan`
- `GET /admin/executions`
- `GET /admin/execution-readiness`
- `GET /admin/policies`
- `GET /admin/active-policy-profile`
- `GET /admin/policy-customization-helper`
- `GET /admin/history-review`
- `GET /admin/history-archive-plan`
- `GET /admin/history-archives`
- `GET /admin/history-restore-readiness`
- `GET /admin/summary`
- `GET /runtime/daemon-migration-plan`
- `GET /state`

## Claim Endpoints

- `POST /claims/request`
- `POST /resources`
- `POST /claims/approve`
- `POST /claims/activate`
- `POST /claims/release`
- `GET /claims/review`
- `GET /claims/cleanup-plan`
- `POST /claims/cleanup-requests`
- `POST /claims/cleanup-requests/approve`
- `POST /claims/cleanup-requests/execute`
- `POST /services/discover-user`
- `POST /physical/discover`
- `POST /physical/discover-storage`
- `POST /virtual/discover-listeners`
- `POST /virtual/runtime-records`
- `POST /virtual/snapshot-requests`
- `POST /virtual/restore-requests`
- `POST /health-targets`
- `POST /health/probes/run`
- `POST /observability/metric-history/capture`
- `POST /host/inspect`
- `POST /host/security/listener-review-queue/remediation-plans`
- `POST /host/security/source-reviews`
- `POST /host/security/source-reviews/block-plans`
- `POST /identity/rotation-requests`
- `POST /host/security/ids-review-packages`
- `POST /host/security/ids-review-packages/submit`
- `POST /host/security/ids-review-packages/prompts`
- `POST /host/security/ids-review-packages/dispatch`
- `POST /host/security/ids-review-packages/results`
- `POST /host/security/remediations/plans`
- `POST /usage-limits`
- `POST /usage/remote-testing/profiles`
- `POST /usage/remote-testing/leases`
- `POST /usage/remote-testing/jobs`
- `POST /usage/remote-testing/results`
- `POST /documents/search`
- `POST /documents/notes`
- `POST /documents/knowledge-capture`
- `POST /usage/continuation-requests`
- `POST /usage/continuation-dispatches`
- `POST /admin/plans`
- `POST /admin/approve`
- `POST /admin/cancel`
- `POST /admin/execute`
- `POST /admin/adapter-enablement-requests`
- `POST /admin/adapter-enablement-requests/approve`
- `POST /admin/policy-warning-requests`
- `POST /admin/policy-warning-requests/approve`
- `POST /admin/policy-customization-helper/profile`
- `POST /admin/history-restore-requests`
- `POST /admin/history-archive-requests`
- `POST /admin/history-archive-requests/approve`
- `POST /admin/history-archive`
- `POST /admin/history-unarchive`
- `POST /runtime/daemon-migration-requests`
- `POST /runtime/daemon-migration-requests/approve`

All request bodies are JSON objects. Claim operations use the same field names as the CLI options, with underscores instead of hyphens.

`POST /resources` records or updates a managed resource. Required fields are `resource_id`, `name`, `resource_type`, `owner_domain`, and `risk_level`; optional fields are `state`, `identifiers`, `dependencies`, `exclusive_groups`, `current_claim_id`, `last_verified_at`, and `notes`. It does not inspect or mutate host state.
`POST /host/inspect` captures read-only host evidence and persists it to the API store.
Configured health probes route HTTP, HTTPS, MCP, HTML, and JSON targets through the HTTP adapter, and process targets through Julian's local read-only process adapter.
`POST /health-targets` records or updates a Julian health target for an existing resource. Required fields are `target_id`, `resource_id`, `name`, `probe_type`, and `target`; optional fields are `owner_domain`, `expected_status`, `expected_content_type`, and `latency_warn_ms`. It does not run probes or mutate host state.
`POST /health/probes/run` probes health targets already persisted in the API store and records Julian health evidence. Optional fields: `timeout_seconds`, `retention_per_target`.
`POST /health/journal-access-requests` stages a Julian read-only system-journal access operation record without reading privileged logs.
`POST /health/journal-access-requests/execute` executes only a staged journal access record that has been transitioned to `in_progress`. It runs bounded `journalctl` reads without `sudo`, writes redacted evidence under ignored `local-secrets/journal-captures`, and returns a persisted `blocked` result when approval or journal access is missing.
`POST /admin/plans` creates and persists an approval-gated admin change plan without executing it.
`POST /admin/approve` records approval metadata for a stored plan without executing it.
`POST /admin/cancel` marks a stored plan canceled without deleting history or executing it.
`POST /admin/execute` executes only a stored plan that passes the existing approval, completeness, adapter, and IDS gates, then persists the result. Unsupported, disabled, or unapproved plans return persisted `blocked` results.
`GET /admin/authorizations-required` lists admin change plans, archive requests, restore requests, adapter enablement requests, policy warning acceptance requests, claim cleanup requests, and daemon migration requests waiting for explicit approval.
`GET /admin/adapter-capabilities` lists the effective live admin adapter table for the API store, including enabled user-service restart execution and any package install, package index refresh, package upgrade, firewall, or source-block adapters with approved adapter enablement records.
`GET /admin/adapter-enablement-plan` prepares a read-only high-risk approval plan for enabling disabled live admin adapters. It supports `?kind=...` filtering and does not enable adapters or execute commands.
`POST /admin/adapter-enablement-requests` creates the approval request required before a disabled live admin adapter can become effective for that store.
`POST /admin/adapter-enablement-requests/approve` approves a requested adapter enablement gate for that store and adapter kind without approving a specific host change or running commands.
`POST /admin/policy-warning-requests` requests explicit acceptance of an active residual policy warning for one admin plan, such as the package-upgrade rollback warning. It does not execute the plan.
`POST /admin/policy-warning-requests/approve` approves a pending residual policy warning acceptance request. Approved warning acceptance changes that warning to a pass for the targeted plan only.
`POST /admin/policy-customization-helper/profile` builds a policy profile from the stable question-answer IDs returned by `GET /admin/policy-customization-helper`. It returns JSON only and does not persist or apply the profile.
`GET /admin/executions` lists persisted admin execution results, including blocked and failed attempts.
`GET /admin/execution-readiness` explains each admin plan's execution gate state, including approval, missing fields, IDS review, manual execution, and Overseer-supported execution readiness.
`GET /admin/policies` evaluates stored admin plans against approval, adapter, IDS, rollback, verification, and risk policy checks. It supports `?plan_id=...` filtering.
`GET /admin/active-policy-profile` reports the profile currently used for admin policy evaluation. It checks for `policy-profile.json` beside the configured store and falls back to the bundled best-practice profile when that file is absent.
`GET /admin/policy-customization-helper` returns Sisko's best-practice policy profile plus stable Q/A prompts for creating a custom policy profile on this or any new Overseer install.
`GET /admin/history-review` identifies completed and canceled admin plans that are candidates for archive handling. It is read-only and does not delete plans or audit evidence.
`GET /admin/history-archive-plan` prepares a read-only archive manifest for inactive admin plans. It groups each archive candidate with related execution, IDS review, and audit records, and does not mutate state.
`GET /admin/history-archives` lists persisted archive records and supports `?plan_id=...` filtering. It is read-only and does not restore or modify plans.
`GET /admin/history-restore-readiness` lists archived plans with restore risk, required approval level, archive record presence, and related evidence. It supports `?plan_id=...` filtering and is read-only.
`POST /admin/history-archive-requests` creates the approval request required before archive-ready inactive admin plans can be archived.
`POST /admin/history-archive-requests/approve` approves a pending admin history archive request.
`POST /admin/history-restore-requests` creates the approval request required before an archived plan can be restored.
`POST /admin/history-restore-requests/approve` approves a pending admin history restore request after validating that it targets an archived admin plan with a matching archive record.
`POST /admin/history-archive` marks archive-ready admin plans archived after explicit approval. It preserves the original plan, execution, IDS review, and audit records, persists an archive record, and emits an audit event.
`POST /admin/history-unarchive` restores one archived admin plan to active admin history after the restore approval is approved. It keeps the archive record and emits an audit event.
`GET /admin/summary` returns a compact operator view of admin plans, pending authorizations, execution outcomes, archive candidates, restore approvals, and recent admin audit events.
`GET /runtime/daemon-migration-plan` prepares a read-only foreground-to-daemon migration plan with approval level, command boundary, rollback, risks, and evidence requirements.
`POST /runtime/daemon-migration-requests` creates the approval request required before daemon migration changes user service enablement or runtime commands.
`POST /runtime/daemon-migration-requests/approve` approves a pending daemon migration request without changing systemd state or running commands.

`GET /command-summary` returns Sisko's compact cross-domain view of service freshness, resources, claims, health targets, usage limits, physical assets, virtual assets, admin plans, and alerts without persisting new records.
`GET /operator-dashboard` returns a unified role-focused dashboard with overall status, attention counts, admin archive candidates, security review gate blockers, and embedded command, physical, virtual, maintenance, security, usage, health, and health-efficiency summaries.
`GET /maintenance/package-status` inspects apt package update availability without installing, upgrading, refreshing indexes, removing packages, or using sudo.
`POST /maintenance/package-update-plans` inspects apt update availability and stages approval-gated package metadata refresh plus package upgrade plans for detected or selected packages. Optional fields are `packages` and `captured_at`; it does not execute package commands.
`POST /claims/release` accepts optional `released_by`, `reason`, `evidence_ids`, and `released_at` fields and emits release audit evidence.
`GET /claims/review` reports active-like, queued, expired, and release-blocked claims for operator review without releasing, revoking, or renewing them. It supports `?now=...` for deterministic review timestamps.
`GET /claims/cleanup-plan` prepares a read-only cleanup manifest for expired active-like claims, stale queued claims, blocked claims, and claims missing release evidence. It supports `?now=...` and does not release, revoke, renew, approve, or re-evaluate claims.
`POST /claims/cleanup-requests` creates the approval request required before cleanup execution may release, revoke, renew, take over, or re-evaluate a cleanup candidate.
`POST /claims/cleanup-requests/approve` approves a pending cleanup request after validating that its claim is still a cleanup candidate. It does not mutate the claim.
`POST /claims/cleanup-requests/execute` executes only an approved cleanup request after re-validating the cleanup candidate. It can mark an expired active-like claim expired, re-evaluate a stale queued claim, move a release-blocked claim to `releasing`, or revoke a blocked claim. Moving a claim to `releasing` does not free the resource.
`POST /services/discover-user` captures read-only host evidence, persists running systemd user services as Julian-owned service resources, and creates matching process health targets. It does not start, stop, restart, enable, disable, or edit services.
`POST /physical/discover` reads configured physical path roots, persists discovered serial/USB identities for Kira, and creates checkout-ready physical resources. Optional field: `roots`, either a string or list of strings. When omitted it checks `/dev/serial/by-id` and `/dev/serial/by-path`. It does not open devices, change permissions, mount storage, or write to hardware.
`POST /physical/discover-storage` reads sysfs block-device metadata and persists discovered storage identities for Kira. Optional field: `sysfs_block_root`. It does not mount, unmount, format, partition, or write to devices.
`POST /virtual/discover-listeners` reads local TCP listener evidence and persists discovered listener resources for Dax. It does not change firewall rules, routes, processes, service definitions, proxies, or network bindings.
`GET /virtual/operations` returns Dax's local virtual runtime records plus staged snapshot, restore, destroy, execution, and target setup records from ignored state.
`POST /virtual/target-setup-requests` stages approval-required Dax target setup requests for disposable real-provider targets. It writes planning records only and does not install packages, change groups, create containers, define VMs, start processes, bind ports, or write gateway configs.
`POST /virtual/target-setup-requests/execute` executes one approved Dax provider target setup with `provider`, `approved_by`, and optional `executed_by` or `executed_at`. It creates only approved disposable targets, uses no-network or loopback-only containment where applicable, writes a local manifest, and records blocked evidence when a provider dependency is missing.
`POST /virtual/runtime-records` records observed virtual runtime state for a VM, container, emulator, gateway, or proxy. It does not start, stop, snapshot, restore, destroy, or reconfigure the runtime.
`POST /virtual/lifecycle/execute` executes an approved disposable Dax runtime lifecycle action. Required fields: `resource_id` and `action` (`inspect`, `start`, or `stop`). Optional fields: `provider`, `executed_by`, and `executed_at`. It blocks non-disposable records and unsupported providers, writes a lifecycle manifest, and limits mutation to the named disposable target.
`POST /virtual/snapshot-requests` stages a Dax snapshot request with approval guardrails. Execution is separate and requires the approved disposable provider adapter selected through `/virtual/snapshot-requests/execute`.
`POST /virtual/restore-requests` stages a Dax restore request with approval guardrails. Execution is separate and requires the approved disposable provider adapter selected through `/virtual/restore-requests/execute`.
`POST /virtual/destroy-requests` stages a Dax destroy request with approval guardrails. Execution is separate and requires the approved disposable provider adapter selected through `/virtual/destroy-requests/execute`.
`GET /virtual/image-scans` returns Dax scanner adapter availability plus staged image vulnerability scan requests and summarized results from ignored local state.
`POST /virtual/image-scans` stages a Dax container image vulnerability scan request for a declared image reference. It does not pull, run, remove, or mutate containers.
`POST /virtual/image-scans/approve` approves a staged image scan request without invoking a scanner.
`POST /virtual/image-scans/execute` executes an approved read-only Trivy image scan when `trivy` is installed. It stores raw scanner JSON under ignored `local-secrets/image-scans`, surfaces only summarized findings and severity counts, and blocks cleanly when Trivy is missing.
`POST /virtual/snapshot-requests/execute` executes only an approved Dax snapshot request against `local_fixture`, `qemu_img`, `qemu_process`, stopped `libvirt`, `docker`, `podman`, `renode`, approved disposable `android_emulator`, or `gateway_proxy` provider targets and writes a manifest under ignored local state.
`POST /virtual/restore-requests/execute` executes only an approved Dax restore request against the same provider set, preserving rollback evidence where supported and blocking non-disposable or unsafe targets.
`POST /virtual/destroy-requests/execute` executes only an approved Dax destroy request against disposable `local_fixture`, `qemu_img`, `qemu_process`, `libvirt`, `docker`, `podman`, `renode`, approved disposable `android_emulator`, or `gateway_proxy` provider targets. It preserves local fixture and file-backed target evidence before removal and blocks non-disposable or unsafe targets.
`POST /storage/backup-execution-requests` stages a Kira backup execution request for an approved project-relative source path. It does not copy files until approval and execution.
`POST /storage/backup-execution-requests/approve` approves a staged backup execution request without copying files.
`POST /storage/backup-execution-requests/execute` executes only an approved backup request for safe project-local source roots, writes the backup under ignored `backups/overseer-managed`, writes a checksum manifest under ignored `local-secrets/backup-execution-manifests`, and blocks unsafe absolute, traversal, secret, VCS, dependency, cache, or missing paths.
`POST /storage/restore-execution-requests` stages a Kira restore execution request from an ignored backup path into an isolated project-relative restore target. It does not copy files until approval and execution.
`POST /storage/restore-execution-requests/approve` approves a staged restore execution request without copying files.
`POST /storage/restore-execution-requests/execute` executes only an approved restore request from `backups/` into a new `artifacts/` or `backups/` target, writes a checksum manifest under ignored `local-secrets/backup-execution-manifests`, and blocks existing targets or unsafe paths.
`POST /storage/cleanup-requests/approve` approves a staged Kira backup cleanup request without deleting files.
`POST /storage/cleanup-requests/execute` executes only an approved Kira cleanup request for project-relative `artifacts/` or `backups/` paths, writes a local cleanup manifest, and blocks unsafe absolute, traversal, missing, or unapproved targets.
`GET /maintenance-summary` returns O'Brien's compact view of maintenance targets, install/update/upgrade/restart plans, pending approvals, rollback and verification readiness, and execution results.
`POST /maintenance/package-maintenance-cycle` runs the approved O'Brien apt maintenance cycle: stage and execute package metadata refresh, inspect refreshed package updates, stage upgrades, advance Sisko-level approvals, execute plans that pass policy, and persist command, verification, rollback, audit, blocked, or failed evidence.
`GET /runtime-status` returns service heartbeat freshness and host inspection freshness in a compact monitoring payload. Freshness states are `ok`, `warning`, `high`, or `missing`. Non-OK freshness states persist stable `alert` audit events in the same store.
`GET /persistence/security` inspects SQLite store file ownership, permissions, sidecar files, and schema migration metadata without creating a missing database or changing file modes.
`GET /state` includes schema migrations, persisted resources, claims, approvals, audit events, usage limits, usage continuation requests, usage continuation dispatches, health records, runtime records, admin plans, and security review records.
`GET /state/redacted` returns a share-oriented state export with local paths, targets, errors, summaries, reasons, command text, prompt/advisory text, hostnames, listener addresses, and secret-like keys replaced by `[REDACTED]`.
`GET /alerts-summary` returns only persisted `alert` audit events, with counts by risk and owner domain for quick Odo/Julian review.
`GET /audit-summary` returns persisted audit events with optional `event_type`, `owner`, and `subject_prefix` query filters.
`GET /approvals-summary` returns stored approval requests with optional `status`, `owner`, `approval_level`, and `subject_prefix` query filters.
`GET /security-summary` returns Odo's compact view of security surfaces, alert audit events, latest host security findings, protective firewall/block plans, and IDS review gates.
`GET /host/security/findings` returns Odo's detailed host-security finding list, severity counts, evidence lines, and recommended actions from the latest persisted host snapshot.
`GET /host/security/triage` groups Odo's host-security findings by listener, bind scope, severity, evidence, and read-only mitigation path. It does not change firewall, route, IDS, or service-bind state.
`GET /host/security/listener-review-queue` reconciles current exposed-listener triage with staged Odo firewall-deny plans and reports which listeners need exposure review, have a staged plan, are approved for execution, or have a canceled plan. It is read-only.
`GET /host/security/sources` correlates established TCP remote sources to triaged listeners and reports source scope. It is evidence only; it does not declare a source hostile or change firewall, IDS, route, or service-bind state.
`GET /host/security/source-review-queue` reconciles current source correlations with persisted Odo reviews and reports which sources need review, are ready for block-plan staging, are reviewed with no action queued, or are not blockable. It is read-only.
`GET /host/security/source-reviews` lists persisted Odo source reviews, dispositions, and whether a reviewed source is eligible for a later block-plan staging step.
`POST /host/security/source-reviews` records Odo's review of a correlated source. It does not stage a block plan or change firewall policy.
`POST /host/security/source-reviews/block-plans` stages an Odo-owned, human-approval source block plan from a reviewed hostile source. It records the plan only; firewall and IDS enforcement remain blocked until separate approval and Intrusion Detection advisory review.
`GET /identity/rotation-requests` returns Odo's staged identity, SSH key, API key, service-account, user, group, and secret rotation requests from ignored local state.
`POST /identity/rotation-requests` stages an approval-bound identity or secret rotation request. It redacts local paths and does not disclose, copy, rotate, delete, replace, or modify credentials, users, groups, SSH keys, API keys, service accounts, or token files.
`GET /host/security/ids-review-packages` lists prepared Intrusion Detection advisory packages and prompts tied to security admin plans.
`GET /host/security/ids-review-summary` returns compact IDS/firewall review gate counters, package next steps, and latest Odo audit events without full prompts or advisory text.
`POST /host/security/ids-review-packages` prepares the review package required before firewall or source-block plans can be approved. It does not run the advisor or apply policy.
`POST /host/security/ids-review-packages/submit` records manual handoff metadata for an IDS/firewall review package when codex-project dispatch is unavailable.
`POST /host/security/ids-review-packages/prompts` writes the advisory prompt under the store directory and records the prompt path. It does not execute the advisor.
`POST /host/security/ids-review-packages/dispatch` writes the advisory prompt when needed, resumes the registered Intrusion Detection Codex thread through `codex-projects`, records dispatch evidence, and leaves advisory acceptance as a separate result gate.
`POST /host/security/ids-review-packages/results` records a manual advisory result. Firewall-affecting admin plans require an accepted result before approval.
`POST /host/security/listener-review-queue/remediation-plans` stages one approval-gated Odo firewall-deny plan per currently unplanned exposed TCP port in the listener review queue. It groups duplicate listeners by port and does not apply firewall rules.
`POST /host/security/remediations/plans` stages an Odo-owned, human-approval firewall deny plan for a triaged listener. It records the plan only; enforcement remains approval-bound.
`POST /host/security/firewall-executions/execute` executes approved firewall/source-block plans through Odo's firewall execution adapter. `mode=local_fixture` requires accepted IDS review, plan approval, and adapter enablement, persists normal admin execution/audit records plus an ignored local manifest, and never changes host firewall state. `mode=live` additionally detects a supported host firewall backend, validates every command against Odo's command boundary, and runs only after IDS review, exact plan approval, adapter enablement, and admin policy gates pass; it writes audit, rollback, backend, and manifest evidence for the approved mutation.
`GET /usage-summary` returns persisted usage-limit counts, available or exhausted capacity, unknown reset counts, low-confidence counts, next reset time, and per-limit detail for Quark review.
`POST /usage-limits` records or updates a Quark usage-limit observation with `limit_id`, `resource_id`, `kind`, `capacity`, `remaining`, and `window`; optional fields are `resets_at`, `observed_at`, and `confidence`.
`GET /documents/status` reports Ezri's Obsidian Local REST API readiness using the ignored local secret env file. It redacts secret material and rejects non-loopback Obsidian API URLs.
`GET /documents/notes` lists vault entries for an optional `?folder=...` query. It is read-only and uses the stored Obsidian REST token server-side.
`GET /documents/knowledge-capture-plan` returns a dry-run list of crew-message and audit-event notes Ezri can capture. Optional query parameters are repeated `kind` values of `crew` or `audit`, plus `limit`.
`POST /documents/search` searches the Obsidian vault with `query` and optional `context_length`. It does not expose the Obsidian API key to the browser.
`POST /documents/notes` writes markdown using `path`, `content`, and optional `mode` of `append` or `replace`. Writes are restricted to the approved `Overseer/` and `Inbox/` vault prefixes and do not mutate host services.
`POST /documents/knowledge-capture` writes deterministic markdown notes for selected crew messages and audit events under `Overseer/Knowledge/`. Body fields are optional `kinds`, `limit`, and `dry_run`.
The CLI equivalents are `documents-status`, `documents-notes`, `documents-search`, `documents-write-note`, and `capture-knowledge-events`; they read the same ignored Obsidian env file by default and never require the Obsidian token as a command-line argument.
`POST /codex-projects/discover-threads` imports local `codex-projects` registry rows as Quark-owned usage-limited thread resources. Optional field: `codex_projects_registry`.
`GET /usage/continuation-plan` returns persisted usage-limited continuation requests, dispatch records, and their current ready, waiting, blocked, or escalated schedule without mutating host state.
`POST /usage/continuation-requests` persists a Quark continuation request with `request_id`, `limit_id`, `resource_id`, `owner_thread`, `requested_units`, and `intent`; optional fields are `risk_level`, `earliest_start`, `deadline`, `requested_by`, and `requested_at`.
`POST /usage/continuation-dispatches` persists idempotent dispatch records for ready continuation requests; optional fields are `dispatched_by`, `dispatched_at`, `resume_codex_projects`, and `codex_projects_registry`. When `resume_codex_projects` is true, matched `owner_thread` values are resumed through the local `codex-projects` tmux registry. It does not mutate host schedulers.
`GET /usage/remote-testing` returns Quark's Tank/MSI remote testing connection profile, queue counts, active leases, pending jobs, claimed jobs, recent redacted results, and supported job types.
`POST /usage/remote-testing/profiles` records the Tank/MSI queue connection profile. Optional fields are `profile_id`, `display_name`, `worker_hint`, `base_url`, `ui_path`, `gateway_path`, `token_source`, and `recorded_by`.
`POST /usage/remote-testing/leases` creates a Quark-managed remote testing lease. Required fields are `lease_id` and `purpose`; optional fields are `project`, `requested_by`, `job_types`, `ttl_minutes`, `priority`, and `profile_id`.
`POST /usage/remote-testing/jobs` enqueues a redacted-safe remote test job for Tank/MSI. Required fields are `lease_id` and `job_type`; optional fields are `requested_by`, `project`, `params`, `base_url`, `ui_path`, `gateway_path`, `token_source`, and `mutates`. Params that look like secrets are rejected. Mutating jobs require an explicit disposable fixture.
`POST /usage/remote-testing/results` reads redacted remote testing results. Optional fields are `lease_id` and `job_id`.
`GET /physical-summary` returns persisted physical identity counts, checkout readiness, power risk, storage risk, counts by kind and source, and per-asset detail for Kira review.
`GET /virtual-summary` returns persisted virtual asset counts, checkout readiness, active claims, queued claims, reserved ports, and per-asset detail for Dax review.
`GET /virtual/evidence` returns Dax read-only provider inventory, registered runtime records, port-pool conflicts, cleanup candidates, provider-depth coverage, virtual capacity summary, image provenance review rows, and image scanner evidence. It does not mutate runtime state.
`GET /health-efficiency` returns Julian's compact service-health view of target status counts, probe-type coverage, owner routing, recovery requirements, and latest failures.
`GET /observability/metric-history` returns Julian's durable metric history snapshots from ignored local state.
`POST /observability/metric-history/capture` captures a state-only snapshot of retained health and host trend summaries. It does not probe services, inspect the host, or read privileged logs.
`GET /observability/performance-history` returns read-only regression and operator-performance timing history from local JSON artifacts. It does not run tests or mutate project state.

## Python Client

Local Python tools can use `overseer.client.OverseerApiClient` to read the token file and call the API:

```python
from overseer.client import OverseerApiClient

client = OverseerApiClient(auth_token_file="state/api-token")
runtime = client.runtime_status()
command = client.command_summary()
resource = client.record_resource("svc.example", "Example Service", "service", "julian", "low")
dashboard = client.operator_dashboard()
maintenance = client.maintenance_summary()
packages = client.package_status()
alerts = client.alerts_summary()
audit = client.audit_summary(owner="odo", subject_prefix="ids-review.")
security = client.security_summary()
usage = client.usage_summary()
continuation_plan = client.usage_continuation_plan()
physical = client.physical_summary()
storage = client.discover_storage()
virtual = client.virtual_summary()
listeners = client.discover_virtual_listeners()
efficiency = client.health_efficiency()
documents = client.documents_status()
notes = client.documents_notes("Overseer")
search = client.documents_search("Overseer", context_length=40)
target = client.record_health_target("health.overseer.api", "svc.overseer.api", "Overseer API", "json", "http://127.0.0.1:8766/health")
probed = client.run_health_probes(retention_per_target=5)
summary = client.health_summary()
snapshot = client.inspect_host()
service_discovery = client.discover_user_services()
findings = client.host_security_findings()
triage = client.host_security_triage()
sources = client.host_security_sources()
reviews = client.host_security_source_reviews()
review = client.create_host_security_source_review({"remote_address": "8.8.8.8", "disposition": "suspicious", "reviewed_by": "odo", "rationale": "unexpected remote source"})
source_block = client.plan_host_security_source_block({"review_id": "source-review.example"})
ids_package = client.prepare_host_security_ids_review_package({"plan_id": "admin.host-security.block-source.8-8-8-8", "source_review_id": "source-review.example"})
exported_prompt = client.export_host_security_ids_review_prompt({"package_id": ids_package["id"]})
submitted = client.submit_host_security_ids_review_package({"package_id": ids_package["id"], "submitted_by": "odo", "prompt_path": exported_prompt["prompt_path"]})
result = client.record_host_security_ids_review_result({"package_id": ids_package["id"], "status": "accepted", "advisory_result": "approved staged package", "reviewed_by": "odo"})
remediation = client.plan_host_security_remediation({"listener": "0.0.0.0:22"})
plan = client.plan_admin_change(
    {
        "plan_id": "admin.restart.overseer-api",
        "kind": "user_service_restart",
        "target": "overseer-api.service",
        "reason": "reload approved code",
    }
)
pending = client.authorizations_required()
approved = client.approve_admin_change({"plan_id": "admin.restart.overseer-api", "approved_by": "sisko"})
warning_request = client.request_admin_policy_warning(
    {"plan_id": "admin.apt.upgrade.sqlite", "check_id": "admin.rollback", "requested_by": "sisko"}
)
warning_approval = client.approve_admin_policy_warning(
    {"approval_id": warning_request["approval_id"], "approved_by": "sisko"}
)
execution = client.execute_admin_change({"plan_id": "admin.restart.overseer-api"})
executions = client.admin_executions()
admin = client.admin_summary()
active_policy = client.active_policy_profile()
policy_helper = client.policy_customization_helper()
policy_profile = client.build_policy_profile({"name": "lab-profile", "warnings-block": True})
canceled = client.cancel_admin_change(
    {
        "plan_id": "admin.block.example",
        "canceled_by": "odo",
        "cancellation_reason": "reserved documentation address; no observed hostile traffic",
    }
)
```

## Installed User Service

The approved local service is installed as:

```text
/home/god/.config/systemd/user/overseer-api.service
```

The installed service reads its bearer token from an ignored local file:

```text
/home/god/.local/share/overseer/project/state/api-token
```

Rollback:

```bash
systemctl --user disable --now overseer-api.service
```
