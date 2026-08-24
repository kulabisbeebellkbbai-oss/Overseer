# Overseer v1.1 Autonomous Operations Design

**Status:** Approved design, pending implementation plan and execution

**Version target:** Overseer v1.1

## Purpose

Overseer v1.1 changes Overseer from a web-UI-driven collection surface with a
coarse periodic runtime tick into a continuously running local operations
coordinator. Collection jobs run on independent schedules, publish durable
snapshots for the UI, and cannot overlap without an explicit bounded policy.
Failures create durable triage state and may invoke only explicitly configured,
idempotent, low-risk repair runbooks. Higher-risk repairs remain subject to the
existing approval, IDS, claim, and audit gates.

The release preserves all current external integrations. It does not modify
another project's source, configuration, database, service, or network policy.

## Audited Baseline

### Runtime

The installed runtime currently consists of two user services:

- `overseer.service` runs `overseer.cli run` against the primary SQLite store.
  It performs health probes, host inspection, crew dispatch, usage-continuation
  dispatch, and station audit work from one 120-second tick.
- `overseer-api.service` serves the authenticated loopback API and dashboard on
  `127.0.0.1:8766`. It depends on the runtime service but does not own its
  collection lifecycle.

The live heartbeat and host snapshot were fresh during the audit. The runtime
is therefore operational, but its all-at-once tick creates synchronized load,
long-tail blocking, and no durable per-collector backoff or circuit state.

### Test baseline

The pre-v1.1 full suite completed with 2,016 passing tests, 28 skipped tests,
and 16 failures. The observed failures fall into four existing-drift groups:

1. exact tmux command fixtures that predate safer `paste-buffer -p` behavior;
2. a live systemd manager PID fixture that is tied to an obsolete process;
3. claim lifecycle fixtures that still assign Dax-owned role approvals to
   Sisko after role-authority hardening;
4. schema migration fixtures that assume v3 ordering while the store is at
   schema v10.

These failures are a v1.1 release gate. Each must be classified with a focused
test as stale-fixture drift or an implementation defect before scheduler work
can be accepted.

## Integration Inventory and Compatibility Contract

### Local service and MCP integrations

Overseer currently models or probes these local services:

- Calculator MCP through its loopback health endpoint;
- GitHub MCP proxy through its loopback health endpoint;
- MarkItDown MCP with a non-mutating MCP initialize request;
- Skiller MCP through its loopback health endpoint;
- Codex Usage MCP and its separate metadata snapshot store;
- Documents MCP through its approved stdio launcher, Obsidian vault, and
  external secret file.

V1.1 keeps the existing resource IDs, target IDs, transport types, endpoint
contracts, owner domains, and secret boundaries. Scheduler metadata augments a
health target; it does not replace or rename it.

### Psychlo and A-Team integration

The API hosts a signed Psychlo peer bridge with its own bridge database,
project-binding configuration, credentials, usage-attribution ledger, and
policy version. Scheduled usage production and delivery are currently handled
by dedicated systemd timer/service units. Psychlo also consumes bounded A-Team
handoff evidence through configured read-only paths.

V1.1 must not duplicate the Psychlo accounting timer or change its peer
protocol. The scheduler may observe its unit and delivery freshness. It may
enqueue an approved local reconciliation job only when that job has a distinct
idempotency key and does not bypass the signed peer contract.

### Roadex and protected gateway integration

Roadex integrates through the authenticated project-human-thread relay and
human-decision surfaces. Remote access to the dashboard and API is published
through the Protected Service Gateway under the existing `/Overseer` prefix.

V1.1 keeps loopback binding as the backend authority. It does not alter the
gateway allowlist, TLS listener, routes, firewall, VPN, or Roadex source.
Dashboard verification must include the real protected-gateway base path after
an independently approved deployment.

### Codex projects and provider adapters

Overseer reads the Codex project registry, resumes registered tmux sessions,
dispatches prompts with delivery evidence, and records usage continuations.
Provider-neutral adapters represent Codex, Claude, Qwen Code, Mistral Vibe, and
Antigravity with capability-specific availability.

V1.1 preserves exact conversation, launcher, session, provider, and delivery
identities. Scheduling a continuation remains distinct from resuming or
dispatching it. Unsupported provider capabilities continue to fail closed.

### Host, maintenance, security, and asset integrations

Overseer reads or coordinates systemd services, processes, listeners, package
evidence, storage, backups, physical devices, virtual assets, containers, VMs,
emulators, gateways, proxies, claims, usage limits, maintenance plans, security
findings, IDS review packages, and admin executions.

Read-only collection may be scheduled automatically. Any action that changes a
service, package, permission, identity, device, VM, container, route, listener,
gateway, firewall, IDS policy, or external project remains behind its current
claim and approval contracts.

## Worktree and Incomplete-Work Disposition

No worktree is deleted, pruned, merged, rebased, or modified as part of v1.1
without a separate explicit integration decision.

### Retire after preservation review

The following branches contain only patches already represented on `main` and
are candidates for retirement after confirming that no active session or dirty
state depends on them:

- `fix/arcade-dispatch-delivery-proof`
- `fix/claim-approval-continuation`
- `fix/false-submitted-delivery-proof`
- `fix/process-attestation-scan-contract`
- `fix/psychlo-bridge-cli-v2`
- `fix/psychlo-decision-reconcile`
- `fix/psychlo-legacy-abandon-envelope`
- `fix/psychlo-legacy-abandonment`
- `fix/psychlo-original-thread-binding`
- `fix/psychlo-thread-aware-dispatch`
- `feature/overseer-roadex-project-thread-relay`
- `fix/successor-process-observation-collector`
- `fix/workspace-package-routing`

The following branches have no remaining commit delta from `main` and are also
retirement candidates after attachment and session review:

- `fix/claim-role-approval-handoff`
- `fix/psychlo-legacy-process-attestation`
- `feature/psychlo-percentage-meter`
- `feature/psychlo-v1-1-counterpart`
- `feature/python-hashed-venv-adapter`

### Review for integration

- `feature/obrien-package-reconciliation` has three unique commits. Review its
  immutable package-inspection evidence and workflow-fixture ownership against
  current `main`; integrate only the still-missing bounded behavior.
- `fix/quarantine-round-recovery` has two unique commits. Review its recovery
  authority and projection against current claim-continuation safety rules;
  integrate only if its approval and idempotency contracts remain valid.

### Keep separate or preserve in place

- `feature/reusable-approval-facility` contains a large, distinct DonutHole
  approval-facility body of work. Treat it as a separate project decision and
  do not merge it into the autonomous scheduler release.
- `fix/submitted-round-recovery` contains uncommitted user work. Preserve it in
  place until its owner decides whether to finish, integrate, or abandon it.

## V1.1 Architecture

### Scheduler ownership

`overseer.service` remains the sole owner of continuous collection. Its runtime
hosts a `CollectionScheduler` that uses the primary SQLite store for durable
definitions, leases, outcomes, incidents, and repair decisions.

The API never performs a collection inline. A UI or API “run now” request only
creates or coalesces a durable scheduler request. The scheduler decides when it
can execute under concurrency, cooldown, circuit, and approval rules.

### Persistent records

The store gains these logical records:

- `CollectionJob`: stable job ID, kind, owner domain, target/resource binding,
  enabled state, interval, deterministic jitter window, timeout, priority,
  concurrency key, retention limit, and repair policy.
- `CollectionJobState`: next due time, last start/completion, last outcome,
  consecutive failures, circuit state, cooldown deadline, and active lease.
- `CollectionRun`: immutable attempt identity, trigger, timestamps, outcome,
  bounded summary, evidence IDs, error category, and retry disposition.
- `CollectionRequest`: coalesced operator/API request with requester, reason,
  requested time, earliest execution, and terminal disposition.
- `TriageIncident`: stable job/resource identity, first and latest failure,
  severity, owner domain, evidence, repair state, and resolution.
- `RepairRunbook`: exact repair ID, supported failure categories, risk level,
  idempotency contract, cooldown, approval requirement, and adapter binding.
- `RepairAttempt`: immutable runbook attempt with incident, authorization,
  result evidence, and verification run.

Records use explicit schema migrations and normalized indexed columns for due
and active-state queries. Bounded JSON payloads carry compatibility metadata.
Secrets, response bodies, full logs, and external-project data are never copied
into scheduler records.

### Default job families

V1.1 migrates the current runtime flags into independent job families:

- one health-probe job per enabled `HealthTarget`;
- host inspection and host-security assessment;
- physical and storage discovery;
- virtual listener and user-service discovery;
- crew-message dispatch;
- usage-continuation dispatch;
- knowledge-event capture;
- station audit;
- maintenance, usage, documentation, and integration freshness projections
  that already have safe read-only adapters.

Existing systemd-owned Psychlo and Quark timers remain external schedules. The
Overseer scheduler observes their freshness and does not silently duplicate
their work.

### Scheduling and load bounds

The scheduler obeys these invariants:

1. At most two collection jobs execute concurrently by default.
2. Only one job with the same concurrency key executes at a time.
3. A job cannot overlap itself, including across service restart, because its
   active lease is persisted and expires conservatively.
4. Missed runs coalesce into one due run. Restart never causes catch-up bursts.
5. Deterministic jitter spreads jobs sharing the same interval.
6. Operator requests coalesce per job and observe a per-job cooldown.
7. Each adapter has a hard timeout and returns bounded evidence.
8. Consecutive failures use exponential backoff capped by job policy.
9. An open circuit permits only scheduled half-open verification attempts.
10. Retention is enforced per job without deleting durable incident, approval,
    admin-execution, or audit history.

The service loop wakes for the nearest due job or a bounded maximum idle
interval. It does not poll every integration on every wake.

### Failure triage

Every failed run receives a stable category such as timeout, unavailable,
contract mismatch, authentication, resource conflict, policy blocked, adapter
error, or internal error. Failure processing is deterministic:

1. Persist the failed run and update job state atomically.
2. Open or update one incident for the job/resource pair.
3. Route the incident to the configured owner domain.
4. Apply backoff and circuit policy before another collection attempt.
5. Select a compatible repair runbook, if one exists.
6. Execute it only when the repair boundary permits it.
7. Require a fresh verification collection before resolving the incident.

Repeated dispatch or message creation is idempotent by incident generation.
Acknowledgment alone does not count as triage completion or repair success.

### Automatic repair boundary

The approved automatic-repair boundary is:

- `triage_only` is the default for every job.
- `preapproved_low_risk` may be configured only for an exact runbook and exact
  job/resource binding.
- An automatic runbook must be local, idempotent, bounded, reversible or
  naturally self-expiring, free of secret output, and independently verifiable.
- Safe built-in runbooks may recover an expired scheduler lease, retry a
  read-only probe after backoff, rebuild a local derived projection, or prune
  bounded non-audit evidence.
- Service restarts, process termination, package changes, permission or
  identity changes, device writes, external-project edits, network changes,
  firewall/IDS changes, and gateway changes are never low-risk automatic
  repairs. They produce the existing exact admin/claim/IDS approval records.
- A repair is not successful until its verification job records healthy or
  recovered evidence for the same target and incident generation.

### API contract

Authenticated read routes expose:

- scheduler summary and load bounds;
- job definitions and current state;
- recent bounded runs;
- open and resolved incidents;
- repair eligibility and approval disposition;
- data age, next due time, backoff, and circuit state for dashboard rendering.

Authenticated mutation routes may enable, suspend, reschedule, or request a job
run only under existing control-route authorization. A run request responds
with queue/coalescing state and never waits for collection. Repair-policy and
runbook changes use admin authorization and audit records.

Existing health, runtime, operations, and dashboard routes remain compatible.
Their data comes from the same durable evidence projections.

### Dashboard contract

The dashboard becomes an operations console over persisted state:

- It shows scheduler heartbeat, active count, queue depth, oldest overdue job,
  next due job, circuit count, and incident count.
- Each integration shows observed-at time, data age, schedule, backoff/circuit
  state, and whether repair is automatic, approval-gated, or unavailable.
- “Run now” enqueues a request and immediately renders its durable status.
- Browser refresh performs bounded concurrent GET requests only. It never
  starts probes, host inspection, discovery, repair, or dispatch implicitly.
- Automatic and manual desktop, tablet, and mobile modes remain available and
  persistent. Forced modes remain usable without horizontal overflow.
- The protected-gateway prefix remains supported for every new route and asset.

## Migration and Rollout

### Source migration

1. Repair or deliberately update every baseline failing test with focused
   evidence for the intended hardened behavior.
2. Add scheduler records and migrations without altering existing payload IDs.
3. Seed default jobs from current runtime flags and health targets
   idempotently. Existing installations receive one job per current collector;
   new installations receive the same defaults through configuration seeding.
4. Run the scheduler in foreground `--once` and dry-run modes against a
   disposable store.
5. Verify API and UI behavior without activating the installed service.

### Activation boundary

Installing source or unit changes does not authorize changing the live service.
Activation requires an exact Overseer admin plan for the installed project and
service unit, explicit approval, and bounded execution. The post-activation
check must verify process identity, scheduler heartbeat, lease recovery, API
health, UI reads, protected-gateway routes, and absence of catch-up bursts.

Rollback restores the prior unit/source deployment and preserves scheduler
tables for forensic inspection. Older code must continue to ignore the new
tables safely.

## Verification and Release Gates

V1.1 is releasable only when all of these gates pass:

- the full existing suite is clean or every deliberate skip is documented;
- scheduler unit tests cover due selection, jitter, lease recovery, overlap
  exclusion, coalescing, timeout, backoff, circuit transitions, and retention;
- runtime integration tests use a fake clock and bounded adapters;
- failure tests prove one incident per generation and fresh verification before
  resolution;
- repair tests prove default triage-only behavior and exact low-risk binding;
- negative tests prove high-risk actions only stage existing approval records;
- API tests prove run requests return without inline collection;
- performance tests prove collection concurrency and UI request bounds;
- browser tests cover desktop, tablet, and mobile modes, manual mode
  persistence, no horizontal overflow, no console errors, and the real gateway
  prefix;
- restart tests prove no duplicate jobs and no catch-up burst;
- compatibility tests cover every integration listed in this specification;
- documentation describes schedules, operations, incidents, repair policy,
  deployment, rollback, and worktree disposition;
- a final security review confirms no approval, secret, gateway, or external
  project boundary regressed.

## Out of Scope

- Modifying or deploying changes to Psychlo, Roadex, the Protected Service
  Gateway, The A-Team, an MCP server, or any other project.
- Automatically restarting services or changing host/network/security state.
- Replacing systemd timers that already own authenticated Psychlo or Quark
  workflows.
- Merging or deleting historical worktrees.
- Adding a distributed scheduler, remote worker fleet, or external queue.
- Treating the browser as a scheduler or source of authoritative runtime state.

## Design Decision

The approved approach is a persistent, bounded scheduler inside
`overseer.service`, with the UI as a read-mostly projection and with automatic
repair restricted to exact preapproved low-risk runbooks. This closes the
operational coverage gap while retaining Overseer's current fail-closed safety
model and external integration contracts.
