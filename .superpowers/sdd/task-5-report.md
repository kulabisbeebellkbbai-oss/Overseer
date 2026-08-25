# Task 5: Bounded autonomous collection scheduler, adapters, triage, and repair

## Outcome

Implemented Task 5 in the isolated worktree:

`/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`

Code commit: `7e8353d` (`Add bounded autonomous collection scheduler`)
Base commit: `78768c0` (`Record collection lease race verification`)

No live collection, service restart, gateway/network mutation, external project
write, or activation was performed. All new tests use fake adapters, fake
clocks, temporary SQLite stores, and explicit release events for blocking
workers.

## TDD evidence

### RED

The required scheduler tests were written before the implementation and run:

```text
PYTHONPATH=src pytest -q tests/test_collection_scheduler.py
```

The suite failed during collection with the expected missing public contract:

```text
ImportError: cannot import name 'CollectionAdapterRegistry' from 'overseer'
```

The repair tests were also run before implementation:

```text
PYTHONPATH=src pytest -q tests/test_collection_repair.py
```

They failed during collection with the expected missing public contract:

```text
ImportError: cannot import name 'RepairCoordinator' from 'overseer'
```

An integration RED case then demonstrated that a pending operator request was
visible but could not be claimed while its ordinary schedule was in the
future. The claim query was corrected with an explicit pending-request opt-in;
the regression now passes without changing ordinary due-job behavior.

### GREEN

Exact Task 5 suites:

```text
PYTHONPATH=src pytest -q tests/test_collection_scheduler.py tests/test_collection_repair.py
14 passed in 1.88s
```

Task 3/4 policy and persistence regression suites, together with Task 5:

```text
PYTHONPATH=src pytest -q tests/test_collection_scheduler.py tests/test_collection_repair.py \
  tests/test_collection_store.py tests/test_collection_policy.py
73 passed in 3.53s
```

Compilation and formatting checks:

```text
PYTHONPATH=src python3 -m compileall -q src/overseer
git diff --cached --check
```

The clean post-code-commit full suite was:

```text
PYTHONPATH=src pytest -q
2116 passed, 31 skipped in 409.62s (0:06:49)
```

## Implementation

### Adapter isolation and bounded results

- Added `CollectionExecution`, `CollectionAdapter`, and exact
  `CollectionAdapterRegistry` bindings keyed by `CollectionJobKind` and
  adapter identifier. Missing, ambiguous, advertised-kind, and identifier
  mismatches fail closed.
- Added read-only health, host-inspection, package-inspection, and store-path
  callback adapters. Health uses the existing `RoutedHealthProbeAdapter`;
  host inspection reuses `HostInspectionAdapter`; package inspection reuses
  the existing immutable package record path.
- Collection summaries, failure categories, evidence identifiers, and worker
  exception results are bounded and secret-redacted. Response bodies, full
  logs, secrets, and tracebacks are not copied into collection runs.
- Package inspection now accepts the job timeout at its subprocess boundary;
  existing one-argument test callbacks remain compatible.

### Scheduler and timeout safety

- Added `CollectionScheduler`, `SchedulerCycle`, `scheduler_status`, and the
  `ThreadPoolExecutor` coordinator with a hard global maximum of two workers.
- The coordinator claims one job at a time, tracks in-memory concurrency keys,
  and never submits a second job for an occupied key. Missed intervals are
  represented by one due claim, not catch-up bursts.
- Pending operator requests are coalesced by the existing store uniqueness
  contract and can make one otherwise-future job eligible only after their
  earliest execution time. Open circuits remain limited to their scheduled
  half-open path.
- Health HTTP/MCP/process/command adapters, host subprocess inspection, apt
  inspection, and timeout-aware callbacks receive the job timeout at their
  actual supported boundary. The scheduler deadline remains defensive.
- A deadline observation writes exactly one `timed_out` run, opens/updates the
  incident, applies backoff, and retains the persisted lease and in-memory key.
  The future is not cancelled or replaced. Its eventual result is ignored by
  exact lease ID and generation; only actual worker exit releases that lease.
- Shutdown signals the loop, reaps completed workers within a bounded window,
  and waits for workers that have exited. A still-running non-cooperative
  callable is left leased rather than falsely released; tests release all
  blocking fakes before teardown, so no test worker is leaked.

### Triage and repair boundary

- Worker exceptions become bounded `internal_error` runs.
- `RepairCoordinator` enforces exact incident/runbook `job_id` and
  `resource_id`, supported failure categories, low-risk automatic policy,
  approval requirements, cooldown, and immutable incident-generation attempt
  identifiers.
- `TRIAGE_ONLY` never invokes a repair adapter.
- `retry_read_only` creates exactly one coalesced verification request after
  cooldown; `prune_bounded_evidence` prunes only the bound job's collection
  runs and preserves incident/repair references; and
  `stage_user_service_restart` creates one existing admin plan per incident
  generation without approving or executing it.
- A successful verification request updates the repair attempt with its fresh
  verification run and resolves the incident through the existing atomic
  collection completion path. Acknowledgment or plan staging alone never
  resolves an incident.

## Minimal Task 4 corrections

Task 5 required two narrow persistence extensions, covered by the new tests:

- `record_collection_timeout` and exact `release_collection_lease` preserve a
  timed-out worker's lease until the worker exits while applying failure policy
  once.
- `claim_due_collection_jobs(..., include_pending_requests=True)` allows the
  scheduler to claim an eligible coalesced request without weakening ordinary
  due selection. `list_repair_runbooks` and bound-job pruning support repair
  selection without touching audit tables.

These changes leave the Task 3 models/policy and existing Task 4 completion,
lease, immutability, migration, and retention behavior intact.

## Files changed

- `src/overseer/collection_adapters.py`
- `src/overseer/collection_scheduler.py`
- `src/overseer/repair.py`
- `src/overseer/__init__.py`
- `src/overseer/store.py` (minimal timeout/request/repair persistence seams)
- `src/overseer/packages.py` (job timeout at apt subprocess boundary)
- `tests/test_collection_scheduler.py`
- `tests/test_collection_repair.py`

## Residual concerns

- A callback that does not accept the documented three-argument form cannot
  provide its own cancellation boundary; the scheduler still treats its
  deadline as observation-only and preserves the lease if it overruns.
- The default registry intentionally contains only the implemented health,
  host, and package adapters. Other v1.1 job families require explicit exact
  registrations and fail closed until their existing read-only callback is
  supplied.
- Python cannot safely kill an already-running thread. If a production
  callable violates its adapter boundary, shutdown preserves its lease and
  does not start a replacement; operational cleanup requires that callable to
  return.

## Safety and scope review

- No `.superpowers/sdd/progress.md` was modified.
- No live service, gateway, network, firewall, IDS, USB device, external
  project, branch, original checkout, or other worktree was touched.
- The code commit is `7e8353d`; this report is the separate Task 5 report
  commit created immediately after the verified code checkpoint.
