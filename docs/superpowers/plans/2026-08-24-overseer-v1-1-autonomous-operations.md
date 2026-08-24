# Overseer v1.1 Autonomous Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Overseer v1.1 as an always-running, bounded, independently scheduled collection and triage system whose UI reads durable state and whose automatic repairs are restricted to exact preapproved low-risk runbooks.

**Architecture:** Add pure collection scheduling models and policy functions, normalized SQLite persistence, and a bounded runtime scheduler inside `overseer.service`. Existing collection adapters become independently scheduled jobs; API mutations enqueue durable requests, the dashboard renders scheduler projections, and failures create idempotent incidents plus either bounded repair attempts or existing approval-gated admin plans.

**Tech Stack:** Python 3.11+, dataclasses, SQLite, `ThreadPoolExecutor`, existing `http.server` API, embedded HTML/CSS/JavaScript dashboard, pytest, systemd user services.

## Global Constraints

- Do not modify another project's source, configuration, database, service, or network policy.
- Preserve all current resource IDs, target IDs, endpoint contracts, owner domains, peer signatures, gateway prefixes, secret boundaries, and approval behavior.
- Keep the backend bound to `127.0.0.1`; remote access remains owned by the Protected Service Gateway.
- `overseer.service` is the sole owner of continuous collection; the API never performs collection inline.
- Default global collection concurrency is two; one concurrency key can have at most one active job.
- Missed schedules coalesce into one run and never create restart catch-up bursts.
- Every adapter has a hard timeout, bounded output, durable outcome, backoff, and circuit state.
- `triage_only` is the default repair policy.
- Automatic repair is limited to exact preapproved low-risk runbooks; service, package, permission, identity, device, VM, container, network, firewall, IDS, gateway, and external-project changes remain approval-gated.
- Existing Psychlo and Quark systemd schedules remain externally owned and must not be duplicated.
- Preserve every active, dirty, or unique-commit worktree until a separate cleanup decision.
- Follow test-driven development: observe each focused failure before production changes and run the focused green check after each slice.
- Do not install or activate source or systemd changes during implementation. Live deployment requires a separate exact approved admin plan.

---

### Task 1: Restore a release-clean pre-v1.1 baseline

**Files:**
- Modify: `src/overseer/store.py` (`initialize`, `_migrate_roadex_approval_fixture_schema`)
- Modify: `src/overseer/api.py` (`_activate_bound_decision_claim`)
- Modify: `tests/test_agent_migration.py`
- Modify: `tests/test_codex_dispatch_activation.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_performance_regression.py`
- Modify: `tests/test_psychlo_decision_reconcile.py`
- Modify: `tests/test_roadex_approval_fixture.py`
- Modify: `tests/test_ui_full_regression.py`

**Interfaces:**
- Consumes: existing role-approval enforcement in `OverseerCoordinator.approve_request`; current schema version 10.
- Produces: a clean baseline preserving `paste-buffer -p`, exact role authority, complete migration history, and fail-closed Roadex claim activation.

- [ ] **Step 1: Re-run the exact failing baseline tests and preserve RED evidence**

Run:

```bash
pytest -q \
  tests/test_agent_migration.py::test_legacy_facade_submits_whitespace_prompt_with_exact_tmux_sequence \
  tests/test_codex_dispatch_activation.py::test_live_staged_spec_captures_exact_current_user_manager_identity \
  tests/test_core.py::OverseerApiTests::test_loopback_api_runs_claim_lifecycle \
  tests/test_core.py::OverseerApiClientTests::test_client_reviews_expired_claims \
  tests/test_core.py::OverseerApiClientTests::test_client_runs_claim_lifecycle \
  tests/test_core.py::HostInspectionTests::test_dispatch_ids_review_package_uses_codex_projects_adapter \
  tests/test_psychlo_decision_reconcile.py::test_api_approves_and_activates_the_exact_structurally_bound_claim_before_delivering_outcome \
  tests/test_roadex_approval_fixture.py \
  tests/test_ui_full_regression.py::FullOperatorUiRegressionTests::test_safe_disposable_workflows_execute_through_gateway_routes
```

Expected: the known command-fixture, PID-fixture, role-authority, and migration-history failures reproduce.

- [ ] **Step 2: Make migration history complete instead of relying on `MAX(version)`**

Change `_migrate_roadex_approval_fixture_schema` to test for the exact migration row before inserting it:

```python
recorded = self._connection.execute(
    "SELECT 1 FROM schema_migrations WHERE version = ?",
    (ROADEX_APPROVAL_FIXTURE_SCHEMA_VERSION,),
).fetchone()
if recorded is None:
    self._record_schema_migration(
        ROADEX_APPROVAL_FIXTURE_SCHEMA_VERSION,
        "persist non-operational Roadex approval fixtures",
    )
```

Call `_migrate_roadex_approval_fixture_schema()` before recording the current aggregate schema marker. A legacy v2 store must end with ordered history `[2, 3, 10]`, and an injected v3 recording failure must roll back the fixture DDL and history before a clean retry.

- [ ] **Step 3: Keep role approval and Roadex human approval as separate authorities**

Replace the pending branch in `_activate_bound_decision_claim` with a fail-closed requirement:

```python
if approval_status == ApprovalStatus.PENDING:
    raise ValueError(
        "bound role claim requires owner-domain approval before Roadex human decision"
    )
if approval_status != ApprovalStatus.APPROVED:
    raise ValueError("decision resource claim approval is not active")
```

Update direct claim lifecycle fixtures to approve role-owned Dax claims with
`decided_by="dax"`. Update the Psychlo decision test to prove the human decision
is rejected while the role approval is pending, then approve the exact claim as
Dax and prove the same human decision activates it without impersonating Dax.

- [ ] **Step 4: Repair stale command and live-identity fixtures**

Update exact tmux expectations to include `paste-buffer -p`. Replace the hard-coded user-manager PID assertion with:

```python
binding = _spec().bus_peer_binding
current = activation._capture_user_bus_peer_binding()
assert binding == current
assert binding["peerUid"] == os.geteuid()
assert binding["peerGid"] == os.getegid()
assert binding["ppid"] == 1
assert binding["argv"] == ["/usr/lib/systemd/systemd", "--user"]
```

- [ ] **Step 5: Run focused and full baseline verification**

Run:

```bash
pytest -q tests/test_agent_migration.py tests/test_codex_dispatch_activation.py \
  tests/test_roadex_approval_fixture.py tests/test_psychlo_decision_reconcile.py
pytest -q tests/test_core.py tests/test_performance_regression.py tests/test_ui_full_regression.py
pytest -q
```

Expected: zero failures; existing skips remain explicit.

- [ ] **Step 6: Commit the baseline repair**

```bash
git add src/overseer/store.py src/overseer/api.py \
  tests/test_agent_migration.py tests/test_codex_dispatch_activation.py \
  tests/test_core.py tests/test_performance_regression.py \
  tests/test_psychlo_decision_reconcile.py tests/test_roadex_approval_fixture.py \
  tests/test_ui_full_regression.py
git commit -m "Restore Overseer release baseline"
```

---

### Task 2: Integrate usable package evidence and record incomplete-work decisions

**Files:**
- Modify: `src/overseer/packages.py`
- Modify: `src/overseer/store.py`
- Create: `tests/test_package_reconciliation.py`
- Create: `docs/v1.1-incomplete-work-disposition.md`

**Interfaces:**
- Consumes: `PackageInspectionSnapshot`, `PackageUpdate`, `SQLiteStore`, unique commits `3a086c7a` and `119f961c` as review evidence only.
- Produces: `PackageInspectionRecord`, `PackageReconciliationEvidence`, `package_inspection_record`, immutable store methods, and the authoritative keep/integrate/retire register.

- [ ] **Step 1: Write failing immutable package-evidence tests**

Add tests that require content-addressed identity and insert-only persistence:

```python
def test_package_record_identity_changes_with_package_state() -> None:
    first = package_inspection_record(package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2")))
    second = package_inspection_record(package_snapshot("2026-08-24T12:00:00Z", bash_update("5.3")))
    assert first.id != second.id


def test_package_record_store_is_insert_only(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        record = package_inspection_record(package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2")))
        store.save_package_inspection_record(record)
        store.save_package_inspection_record(record)
        with pytest.raises(ValueError, match="immutable package inspection collision"):
            store.save_package_inspection_record(replace(record, stderr="changed"))
```

Run: `pytest -q tests/test_package_reconciliation.py`

Expected: import or attribute failures because the record types do not exist on `main`.

- [ ] **Step 2: Port the bounded package evidence, not the historical branch wholesale**

Add the dataclasses and content fingerprint from commit `3a086c7a`, adapted to current serialization:

```python
@dataclass(frozen=True)
class PackageInspectionRecord:
    id: str
    captured_at: str
    command: tuple[str, ...]
    exit_code: int
    updates: tuple[PackageUpdate, ...]
    state_fingerprint: str
    stderr: str = ""


@dataclass(frozen=True)
class PackageReconciliationEvidence:
    id: str
    snapshot_id: str
    maintenance_batch_id: str
    observed_at: str
    outcome: str
    plan_ids: tuple[str, ...] = ()
    message_ids: tuple[str, ...] = ()
```

Create `package_inspection_records` and `package_reconciliation_evidence` in schema v11. Use `INSERT`, exact-payload idempotency, and collision rejection; never use `INSERT OR REPLACE` for immutable records.

- [ ] **Step 3: Write the disposition register**

Record these exact outcomes:

- integrate the immutable package evidence from `feature/obrien-package-reconciliation`;
- keep its remaining unfinished reconciliation workflow out of v1.1 until separately specified;
- keep `fix/quarantine-round-recovery` preserved but out of v1.1 because its process-termination/reconnect behavior is high-risk, broad, and not required by autonomous collection;
- retire patch-equivalent and zero-delta worktrees only after a later live session/attachment audit;
- preserve `feature/reusable-approval-facility` as separate DonutHole work;
- preserve dirty `fix/submitted-round-recovery` in place.

Include branch names, reviewed commit IDs, decision rationale, and the separate authorization required for cleanup.

- [ ] **Step 4: Verify and commit**

Run:

```bash
pytest -q tests/test_package_reconciliation.py tests/test_core.py -k package
git diff --check
```

Then:

```bash
git add src/overseer/packages.py src/overseer/store.py \
  tests/test_package_reconciliation.py docs/v1.1-incomplete-work-disposition.md
git commit -m "Integrate immutable package inspection evidence"
```

---

### Task 3: Define collection records and pure scheduling policy

**Files:**
- Create: `src/overseer/collection_models.py`
- Create: `src/overseer/collection_policy.py`
- Create: `tests/test_collection_policy.py`
- Modify: `src/overseer/__init__.py`

**Interfaces:**
- Consumes: `OwnerDomain`, `RiskLevel`, ISO-8601 UTC timestamps.
- Produces: collection enums/dataclasses; `deterministic_jitter`, `next_success_due`, `next_failure_due`, `circuit_after_failure`, and `job_is_due`.

- [ ] **Step 1: Write failing policy tests with a fake timestamp**

Cover these exact behaviors:

```python
def test_same_job_gets_stable_jitter() -> None:
    assert deterministic_jitter("collection.health.api", 30) == deterministic_jitter("collection.health.api", 30)


def test_failure_backoff_caps_at_policy_limit() -> None:
    job = sample_job(interval_seconds=120, max_backoff_seconds=900)
    assert next_failure_delay(job, consecutive_failures=20) == 900


def test_open_circuit_allows_only_half_open_due_attempt() -> None:
    state = sample_state(circuit_state=CircuitState.OPEN, cooldown_until="2026-08-24T12:05:00+00:00")
    assert not job_is_due(state, "2026-08-24T12:04:59+00:00")
    assert job_is_due(state, "2026-08-24T12:05:00+00:00")
```

Run: `pytest -q tests/test_collection_policy.py`

Expected: module import failure.

- [ ] **Step 2: Implement the exact record vocabulary**

Define these enums:

```python
class CollectionJobKind(StrEnum):
    HEALTH_PROBE = "health_probe"
    HOST_INSPECTION = "host_inspection"
    PHYSICAL_DISCOVERY = "physical_discovery"
    VIRTUAL_DISCOVERY = "virtual_discovery"
    CREW_DISPATCH = "crew_dispatch"
    USAGE_CONTINUATION = "usage_continuation"
    KNOWLEDGE_CAPTURE = "knowledge_capture"
    STATION_AUDIT = "station_audit"
    PACKAGE_INSPECTION = "package_inspection"
    FRESHNESS_PROJECTION = "freshness_projection"


class CollectionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class RepairPolicy(StrEnum):
    TRIAGE_ONLY = "triage_only"
    PREAPPROVED_LOW_RISK = "preapproved_low_risk"
```

Define frozen dataclasses `CollectionJob`, `CollectionJobState`, `CollectionRequest`, `CollectionRun`, `TriageIncident`, `RepairRunbook`, and `RepairAttempt`. Validate positive intervals/timeouts/retention, bounded identifiers, and low-risk automatic repair in `__post_init__`.

- [ ] **Step 3: Implement deterministic policy functions**

Use SHA-256 of the stable job ID for jitter. Use capped exponential backoff:

```python
def next_failure_delay(job: CollectionJob, consecutive_failures: int) -> int:
    exponent = min(max(consecutive_failures - 1, 0), 5)
    return min(job.interval_seconds * (2 ** exponent), job.max_backoff_seconds)
```

Open the circuit when `consecutive_failures >= job.failure_threshold`; a successful half-open run closes it and clears failures.

- [ ] **Step 4: Verify and commit**

Run:

```bash
pytest -q tests/test_collection_policy.py
python3 -m compileall -q src/overseer/collection_models.py src/overseer/collection_policy.py
```

Then:

```bash
git add src/overseer/collection_models.py src/overseer/collection_policy.py \
  src/overseer/__init__.py tests/test_collection_policy.py
git commit -m "Define bounded collection scheduling policy"
```

---

### Task 4: Add normalized scheduler persistence and atomic leases

**Files:**
- Modify: `src/overseer/store.py`
- Create: `tests/test_collection_store.py`

**Interfaces:**
- Consumes: all records from `collection_models.py`.
- Produces: `save_collection_job`, `load_collection_job`, `list_collection_jobs`, `claim_due_collection_jobs`, `complete_collection_run`, `request_collection_run`, `list_collection_runs`, `list_collection_requests`, `list_triage_incidents`, `save_repair_runbook`, and `list_repair_attempts`.

- [ ] **Step 1: Write failing migration, lease, coalescing, and immutability tests**

Add tests proving:

```python
def test_claim_due_jobs_is_atomic_and_respects_limit(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        first = store.claim_due_collection_jobs(NOW, "worker-a", LEASE_END, limit=2)
        second = store.claim_due_collection_jobs(NOW, "worker-b", LEASE_END, limit=2)
    assert len(first) == 2
    assert second == ()


def test_operator_requests_coalesce_per_job(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        first = store.request_collection_run("collection.health.api", "operator", "verify")
        second = store.request_collection_run("collection.health.api", "operator", "verify again")
    assert second.id == first.id


def test_collection_run_is_insert_only(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        store.save_collection_run(sample_run())
        with pytest.raises(ValueError, match="immutable collection run collision"):
            store.save_collection_run(replace(sample_run(), summary="changed"))
```

Run: `pytest -q tests/test_collection_store.py`

Expected: missing store methods.

- [ ] **Step 2: Add schema v12 tables and due indexes**

Create normalized tables for jobs, state, requests, runs, incidents, runbooks, and attempts. Required indexes are:

```sql
CREATE INDEX idx_collection_jobs_enabled_priority
ON collection_jobs (enabled, priority);
CREATE INDEX idx_collection_job_state_due
ON collection_job_states (next_due_at, lease_expires_at);
CREATE INDEX idx_collection_runs_job_started
ON collection_runs (job_id, started_at DESC);
CREATE UNIQUE INDEX idx_collection_request_pending_job
ON collection_requests (job_id) WHERE status = 'pending';
CREATE UNIQUE INDEX idx_triage_open_generation
ON triage_incidents (job_id, generation) WHERE status = 'open';
```

Persist bounded JSON payloads alongside normalized query columns. Use explicit schema version 12 and leave older tables intact.

- [ ] **Step 3: Implement atomic lease and completion transactions**

`claim_due_collection_jobs` must use `BEGIN IMMEDIATE`, select enabled due jobs ordered by priority and next due time, skip unexpired leases, update lease owner/expiry, and return at most `limit` records. `complete_collection_run` must atomically insert the immutable run, update state, close/coalesce its request, and open/update/resolve the incident.

Expired leases return to due state with an audit-safe `expired_lease` failure category; they never count as successful work.

- [ ] **Step 4: Add bounded retention without deleting incident or audit history**

Implement `prune_collection_runs(retain_per_job)` using normalized run rows. Reject retention below one. Never prune a run referenced by an open incident or repair attempt.

- [ ] **Step 5: Verify migration and persistence**

Run:

```bash
pytest -q tests/test_collection_store.py tests/test_agent_store.py \
  tests/test_roadex_approval_fixture.py
```

Expected: all pass, including legacy-store migration and concurrent lease tests.

- [ ] **Step 6: Commit**

```bash
git add src/overseer/store.py tests/test_collection_store.py
git commit -m "Persist collection schedules and leases"
```

---

### Task 5: Build the bounded scheduler, adapters, triage, and repair planner

**Files:**
- Create: `src/overseer/collection_adapters.py`
- Create: `src/overseer/collection_scheduler.py`
- Create: `src/overseer/repair.py`
- Create: `tests/test_collection_scheduler.py`
- Create: `tests/test_collection_repair.py`
- Modify: `src/overseer/__init__.py`

**Interfaces:**
- Consumes: collection store methods; `RoutedHealthProbeAdapter`, `HostInspectionAdapter`, existing store-path dispatch callbacks, admin planning functions.
- Produces: `CollectionAdapterRegistry`, `CollectionScheduler`, `SchedulerCycle`, `RepairCoordinator`, and `scheduler_status`.

- [ ] **Step 1: Write failing bounded-execution tests**

Use a fake clock and blocking adapters to prove:

```python
def test_scheduler_never_exceeds_global_or_key_concurrency(tmp_path: Path) -> None:
    scheduler, adapter = blocking_scheduler(tmp_path, max_workers=2)
    scheduler.run_ready_once()
    assert adapter.peak_active == 2
    assert adapter.peak_by_key["mcp"] == 1


def test_restart_coalesces_missed_intervals(tmp_path: Path) -> None:
    scheduler = scheduler_with_job_last_due_days_ago(tmp_path)
    cycle = scheduler.run_ready_once()
    assert cycle.claimed == 1
    assert cycle.started == 1


def test_timeout_opens_incident_and_applies_backoff(tmp_path: Path) -> None:
    cycle = timeout_scheduler(tmp_path).run_ready_once()
    assert cycle.failed == 1
    assert open_incident(tmp_path).failure_category == "timeout"
    assert job_state(tmp_path).next_due_at > NOW
```

Run: `pytest -q tests/test_collection_scheduler.py`

Expected: module import failure.

- [ ] **Step 2: Implement adapter isolation and bounded results**

Define:

```python
@dataclass(frozen=True)
class CollectionExecution:
    outcome: CollectionOutcome
    summary: str
    evidence_ids: tuple[str, ...] = ()
    failure_category: str = ""


class CollectionAdapter(Protocol):
    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution: ...
```

Each worker opens its own `SQLiteStore` when persistence is required. Implement health-probe, host-inspection, package-inspection, and existing store-path callback adapters. Bound summaries and errors before persistence; never persist response bodies, secrets, full logs, or exception tracebacks.

- [ ] **Step 3: Implement the scheduler cycle**

Use a `ThreadPoolExecutor(max_workers=2)`. The coordinator thread claims jobs
and submits only jobs whose concurrency key is free. Every production adapter
must enforce the job deadline in its HTTP, subprocess, socket, or callback
boundary. The coordinator marks a deadline overrun as `timeout`, retains the
lease and concurrency key until the worker actually exits, and ignores a stale
completion whose lease generation no longer matches. It never starts a
replacement beside a timed-out worker. Worker exceptions map to
`internal_error`; deadline expiry opens the circuit according to policy.

Expose:

```python
@dataclass(frozen=True)
class SchedulerCycle:
    claimed: int
    started: int
    succeeded: int
    failed: int
    blocked: int
    timed_out: int
    next_due_at: str | None


class CollectionScheduler:
    def run_ready_once(self, now: str | None = None) -> SchedulerCycle: ...
    def run_forever(self, maximum_idle_seconds: float = 5.0) -> None: ...
    def shutdown(self) -> None: ...
```

- [ ] **Step 4: Write failing repair-boundary tests**

Prove:

```python
def test_triage_only_never_invokes_repair_adapter(tmp_path: Path) -> None:
    result = repair_coordinator(tmp_path).advance(open_incident(tmp_path))
    assert result.disposition == "triage_only"
    assert list_repair_attempts(tmp_path) == ()


def test_preapproved_read_only_retry_requires_exact_job_binding(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="runbook does not bind to collection job"):
        repair_coordinator(tmp_path).advance(open_incident(tmp_path), foreign_runbook())


def test_service_restart_is_staged_and_never_executed(tmp_path: Path) -> None:
    result = repair_coordinator(tmp_path).advance(systemd_incident(tmp_path), restart_runbook())
    assert result.disposition == "approval_required"
    assert result.admin_plan_id.startswith("admin.repair.")
    assert admin_executions(tmp_path) == ()
```

- [ ] **Step 5: Implement repair coordination**

Support exact runbook actions:

- `retry_read_only`: enqueue one verification request after cooldown;
- `prune_bounded_evidence`: prune only the bound job's non-audit run/evidence rows;
- `stage_user_service_restart`: create one existing admin plan per incident generation and never approve or execute it.

Reject automatic runbooks whose risk is not low, whose job/resource binding differs, whose action is unknown, or whose idempotency key has already produced a different attempt.

- [ ] **Step 6: Verify and commit**

Run:

```bash
pytest -q tests/test_collection_scheduler.py tests/test_collection_repair.py
```

Then:

```bash
git add src/overseer/collection_adapters.py src/overseer/collection_scheduler.py \
  src/overseer/repair.py src/overseer/__init__.py \
  tests/test_collection_scheduler.py tests/test_collection_repair.py
git commit -m "Add bounded autonomous collection scheduler"
```

---

### Task 6: Replace coarse runtime flags with idempotently seeded jobs

**Files:**
- Modify: `src/overseer/runtime.py`
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/config.py`
- Modify: `src/overseer/health.py`
- Modify: `config/desired-state.json`
- Create: `tests/test_collection_runtime.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: `CollectionScheduler`, existing runtime flags, `HealthTarget` records.
- Produces: `seed_default_collection_jobs`, `collection_jobs_status`, `collection_scheduler_status`, and scheduler-backed `OverseerRuntime`.

- [ ] **Step 1: Write failing seeding and runtime tests**

Require one stable probe job per health target, idempotent reseeding, no duplication of Psychlo/Quark timers, and no all-target probe call from `OverseerRuntime.tick`:

```python
def test_health_targets_seed_independent_stable_jobs(tmp_path: Path) -> None:
    seed_target(tmp_path, "health.api")
    seed_default_collection_jobs(tmp_path)
    seed_default_collection_jobs(tmp_path)
    jobs = collection_jobs(tmp_path)
    assert [job.id for job in jobs if job.kind == CollectionJobKind.HEALTH_PROBE] == ["collection.health.health.api"]


def test_runtime_tick_advances_scheduler_without_bulk_probe(tmp_path: Path) -> None:
    runtime, scheduler = runtime_with_fake_scheduler(tmp_path)
    runtime.tick()
    assert scheduler.cycles == 1
```

Run: `pytest -q tests/test_collection_runtime.py`

Expected: missing seeding and scheduler integration.

- [ ] **Step 2: Add schedule configuration with compatibility defaults**

Extend `HealthTarget` configuration parsing with optional `interval_seconds`, `jitter_seconds`, `timeout_seconds`, and `repair_policy`; absent fields keep the v1.0-compatible 120-second probe interval and triage-only policy. Add independent defaults for host inspection, discovery, dispatch, knowledge capture, and station audit.

Do not add jobs for `overseer-psychlo-usage.timer` or `overseer-quark-scheduler.timer`; add freshness-observation jobs for their units instead.

- [ ] **Step 3: Route runtime through the scheduler**

Keep the current heartbeat counters and compatibility result fields, but have `tick()` call `scheduler.run_ready_once()` rather than invoking every enabled collector. `run()` sleeps until the scheduler's next bounded wake. `--once` runs one ready cycle and exits.

Retain old flags as idempotent seeding switches for one release. Mark them deprecated in help text; they no longer mean “run this collector on every tick.”

- [ ] **Step 4: Add CLI inspection and control commands**

Add:

```text
overseer collection-jobs --store PATH
overseer collection-scheduler-status --store PATH
overseer collection-runs --store PATH [--job-id ID] [--limit N]
overseer collection-incidents --store PATH [--status open|resolved]
overseer request-collection-run --store PATH --job-id ID --requested-by ACTOR --reason TEXT
overseer seed-collection-jobs --store PATH [--config PATH]
```

All commands produce JSON. Only the request and seed commands mutate the local Overseer store; neither runs collection inline.

- [ ] **Step 5: Verify and commit**

Run:

```bash
pytest -q tests/test_collection_runtime.py tests/test_core.py -k "runtime or health_target or collection"
```

Then:

```bash
git add src/overseer/runtime.py src/overseer/cli.py src/overseer/config.py \
  src/overseer/health.py config/desired-state.json \
  tests/test_collection_runtime.py tests/test_core.py
git commit -m "Run collectors on independent schedules"
```

---

### Task 7: Expose scheduler projections without inline collection

**Files:**
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/client.py`
- Create: `tests/test_collection_api.py`
- Modify: `tests/test_performance_regression.py`

**Interfaces:**
- Consumes: CLI/status helpers from Task 6.
- Produces: authenticated scheduler GET routes and queue-only control routes, plus matching client methods.

- [ ] **Step 1: Write failing route tests**

Require protected-prefix compatibility and non-blocking requests:

```python
def test_run_request_enqueues_without_calling_adapter(api, monkeypatch) -> None:
    monkeypatch.setattr(CollectionScheduler, "run_ready_once", lambda *_: pytest.fail("inline collection"))
    result = api.post_json("/Overseer/collections/jobs/collection.health.api/run", {
        "requested_by": "operator",
        "reason": "verify after incident",
    })
    assert result["status"] in {"queued", "coalesced"}


def test_scheduler_routes_require_authentication(api) -> None:
    assert api.get_status("/Overseer/collections/status", authenticated=False) == 401
```

Run: `pytest -q tests/test_collection_api.py`

Expected: 404 responses.

- [ ] **Step 2: Add authenticated read routes**

Add GET routes:

```text
/collections/status
/collections/jobs
/collections/runs
/collections/incidents
/collections/runbooks
```

Support `job_id`, `status`, and bounded `limit` query parameters. Return data age, next due, lease, backoff, circuit, incident, and repair disposition without secrets or unbounded payloads.

- [ ] **Step 3: Add queue-only mutation routes**

Add POST routes:

```text
/collections/jobs/{job_id}/run
/collections/jobs/{job_id}/suspend
/collections/jobs/{job_id}/resume
```

Require admin-token control authorization. Validate exact payload fields. Run requests enqueue/coalesce only; suspend/resume persists policy and audit state but never interrupts an active worker unsafely.

Keep `/health/probes/run` as a deprecated compatibility route that enqueues requests for enabled health jobs and returns request IDs instead of probe evidence. Include `Deprecation: true` and a successor `Link` header.

- [ ] **Step 4: Extend performance budgets**

Add scheduler GET routes to read-route budgets and prove the run-request POST returns within the existing safe mutation budget even when a fake collection adapter blocks.

- [ ] **Step 5: Verify and commit**

Run:

```bash
pytest -q tests/test_collection_api.py tests/test_performance_regression.py \
  tests/test_api_store_binding.py
```

Then:

```bash
git add src/overseer/api.py src/overseer/client.py \
  tests/test_collection_api.py tests/test_performance_regression.py
git commit -m "Expose durable collection scheduler API"
```

---

### Task 8: Make the dashboard a bounded scheduler projection

**Files:**
- Modify: `src/overseer/ui.py`
- Modify: `tests/test_ui_regression.py`
- Modify: `tests/test_ui_full_regression.py`
- Modify: `tests/test_performance_regression.py`
- Modify: `docs/ui-regression-testing.md`

**Interfaces:**
- Consumes: `/collections/status`, `/collections/jobs`, `/collections/runs`, `/collections/incidents`, queue-only run route.
- Produces: scheduler overview, job/incident tables, queue-only Run Now control, and bounded browser refresh behavior.

- [ ] **Step 1: Write failing static and pure-JavaScript tests**

Require endpoint registration, no direct probe action, bounded refresh concurrency, and scheduler rendering:

```python
def test_dashboard_uses_scheduler_queue_instead_of_direct_probe() -> None:
    html = OPERATOR_CONSOLE_HTML
    assert 'collectionsStatus: "/collections/status"' in html
    assert 'collectionsJobs: "/collections/jobs"' in html
    assert 'postJson(`/collections/jobs/${jobId}/run`' in html
    assert 'postJson("/health/probes/run"' not in html
    assert "mapEndpointEntries(endpointEntries, 4)" in html
```

Add Node-executed tests for data-age labels, circuit badges, run-request payloads, and layout mode behavior at 700/701/1024/1025 boundaries.

Run: `pytest -q tests/test_ui_regression.py -k collection`

Expected: scheduler UI assertions fail.

- [ ] **Step 2: Add scheduler endpoints to the existing bounded refresh**

Reuse `refreshPromise` and `mapEndpointEntries(..., 4)` so focus, visibility, timer, and manual refresh cannot overlap. Keep the 30-second UI refresh as GET-only snapshot refresh. Render the last successful refresh independently from evidence observed-at times.

- [ ] **Step 3: Replace direct collection controls**

Replace “Run health probes” with per-job and filtered “Run now” queue controls. The action status must show request ID, `queued`/`coalesced`, earliest execution, and current circuit/cooldown state. Disable repeated submission while the same request remains pending.

- [ ] **Step 4: Render operations state responsively**

Add overview metrics for scheduler heartbeat, active jobs, pending requests, overdue jobs, open circuits, and incidents. Add tables for job state and incident/repair disposition. Preserve the existing automatic/manual desktop, tablet, and mobile modes, visible focus, reduced motion, 44-pixel touch targets, and no horizontal overflow in forced desktop mode.

- [ ] **Step 5: Run direct and protected-prefix UI tests**

Run:

```bash
pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py \
  tests/test_performance_regression.py
```

Use the configured Playwright MCP for browser acceptance at `390x844`, `820x1180`, and `1440x1000`. Verify automatic mode, every forced mode, reload persistence, no overflow, no console errors, Cancel non-submit behavior, and focus restoration. Use `/Overseer/ui` through the protected gateway only after separately approved deployment; before activation, use the disposable prefix-aware API harness.

- [ ] **Step 6: Commit**

```bash
git add src/overseer/ui.py tests/test_ui_regression.py \
  tests/test_ui_full_regression.py tests/test_performance_regression.py \
  docs/ui-regression-testing.md
git commit -m "Show autonomous operations in dashboard"
```

---

### Task 9: Add operational packaging, migration, and rollback documentation

**Files:**
- Create: `systemd/overseer.service`
- Modify: `README.md`
- Modify: `docs/runtime.md`
- Modify: `docs/scheduler.md`
- Modify: `docs/live-health-probes.md`
- Modify: `docs/service-health-monitoring.md`
- Modify: `docs/operator-workflows.md`
- Modify: `docs/local-api.md`
- Create: `docs/v1.1-operations.md`
- Create: `tests/test_collection_systemd.py`

**Interfaces:**
- Consumes: new CLI commands and scheduler runtime.
- Produces: source-controlled service template, operator runbook, deployment/rollback checklist, and unit-contract tests.

- [ ] **Step 1: Write a failing service-unit contract test**

Require the source unit to run the scheduler-backed command, restart on failure, bind no network listener, and avoid duplicating collector flags:

```python
def test_overseer_runtime_unit_runs_scheduler_without_bulk_flags() -> None:
    unit = Path("systemd/overseer.service").read_text()
    assert "-m overseer.cli run" in unit
    assert "--store" in unit
    assert "--probe-health-targets" not in unit
    assert "--inspect-host" not in unit
    assert "Restart=on-failure" in unit
```

Run: `pytest -q tests/test_collection_systemd.py`

Expected: missing source unit.

- [ ] **Step 2: Add a portable source unit template**

Use environment-file variables for install path, interpreter, and store rather than hard-coded live paths:

```ini
[Service]
Type=simple
EnvironmentFile=%h/.config/overseer/runtime.env
ExecStart=${OVERSEER_PYTHON} -m overseer.cli run --store ${OVERSEER_STORE}
Restart=on-failure
RestartSec=5
```

Document the exact required variables and file permissions. Do not install the unit in this task.

- [ ] **Step 3: Update operator documentation**

Document:

- scheduler job types, defaults, and status commands;
- run-request coalescing and why the API does not collect inline;
- backoff, circuit, incident, and repair states;
- low-risk automatic repair and approval-gated repair examples;
- Psychlo/Quark external timer ownership;
- source migration, disposable-store canary, exact admin activation plan,
  live verification, rollback, and forensic preservation;
- v1.1 compatibility and external-project non-mutation boundaries.

- [ ] **Step 4: Verify and commit**

Run:

```bash
pytest -q tests/test_collection_systemd.py
rg -n "collection-scheduler-status|request-collection-run|triage_only|approval_required" \
  README.md docs/v1.1-operations.md docs/runtime.md docs/scheduler.md docs/local-api.md
git diff --check
```

Then:

```bash
git add systemd/overseer.service README.md docs/runtime.md docs/scheduler.md \
  docs/live-health-probes.md docs/service-health-monitoring.md \
  docs/operator-workflows.md docs/local-api.md docs/v1.1-operations.md \
  tests/test_collection_systemd.py
git commit -m "Document Overseer v1.1 operations"
```

---

### Task 10: Run complete compatibility, load, restart, and security gates

**Files:**
- Modify only if a failing test demonstrates a v1.1 regression.
- Create: `.superpowers/sdd/overseer-v1.1-verification-report.md`
- Create: `.superpowers/sdd/overseer-v1.1-security-review.md`

**Interfaces:**
- Consumes: all prior tasks and the approved design specification.
- Produces: fresh release evidence and an explicit activation recommendation; no live activation.

- [ ] **Step 1: Run focused scheduler and migration suites**

```bash
pytest -q tests/test_collection_policy.py tests/test_collection_store.py \
  tests/test_collection_scheduler.py tests/test_collection_repair.py \
  tests/test_collection_runtime.py tests/test_collection_api.py \
  tests/test_collection_systemd.py tests/test_package_reconciliation.py \
  tests/test_roadex_approval_fixture.py
```

Expected: all pass.

- [ ] **Step 2: Run compatibility suites**

```bash
pytest -q tests/test_agent_migration.py tests/test_agent_store.py \
  tests/test_psychlo_bridge.py tests/test_psychlo_decision_reconcile.py \
  tests/test_quark_scheduler.py tests/test_core.py tests/test_api_store_binding.py
```

Expected: all pass with no external provider prompt, service mutation, or network-policy change.

- [ ] **Step 3: Run UI and performance suites**

```bash
pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py \
  tests/test_performance_regression.py
```

Expected: all pass; browser refresh is GET-only and bounded.

- [ ] **Step 4: Run the full regression package**

```bash
pytest -q
PYTHONPATH=src python3 scripts/run_full_regression.py
```

Expected: zero failures. Record exact pass/skip totals and artifact paths in the verification report.

- [ ] **Step 5: Perform final security review**

Review the complete implementation diff for:

- lease races, duplicate runs, SQLite transaction boundaries, and stale-worker completion;
- unbounded threads, requests, output, evidence, or browser refreshes;
- secret, body, log, traceback, path, or credential leakage;
- role/human/admin/IDS approval bypass;
- automatic execution of restart, package, permission, identity, device,
  virtual asset, network, firewall, gateway, or external-project actions;
- Psychlo signature/replay boundaries, Roadex authority, exact Codex delivery
  identity, and Protected Gateway prefix compatibility.

Use `gpt-daybreak-blue-latest` for delegated final security review when available, with `gpt-5.6-terra` as the explicit fallback. Record findings and resolution evidence in `.superpowers/sdd/overseer-v1.1-security-review.md`.

- [ ] **Step 6: Verify repository scope and write release recommendation**

```bash
git status --short
git diff --check 24dd06f..HEAD
git log --oneline -12
```

Confirm no other project path changed, no user dirty file was staged, and no live service/unit/configuration was modified. Write the source-ready recommendation and the separate exact activation approval requirements to `.superpowers/sdd/overseer-v1.1-verification-report.md`.

- [ ] **Step 7: Commit verification reports**

```bash
git add .superpowers/sdd/overseer-v1.1-verification-report.md \
  .superpowers/sdd/overseer-v1.1-security-review.md
git commit -m "Verify Overseer v1.1 release readiness"
```

Do not install, restart, enable, disable, or otherwise activate the live service. Present the exact admin plan for separate user approval after source-ready verification.
