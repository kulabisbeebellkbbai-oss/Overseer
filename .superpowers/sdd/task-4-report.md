# Task 4 report: normalized scheduler persistence and atomic leases

## Scope and commits

- Worktree: `/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`
- Base SHA: `c33de207e68e0fcdb666b8e6ba05b1b219cd04b9`
- Implementation SHA: `078aa3a0d6f06646df1c421f3a3d582ee8d278c7`
- Implementation commit: `Persist collection schedules and leases`
- Review-fix SHA: `d07ecda`
- Review-fix commit: `Fix collection persistence review findings`
- Task 5 was not modified.
- `collection_models.py` and `collection_policy.py` contracts were not changed.

## TDD evidence

### RED

Command:

```text
PYTHONPATH=src pytest -q tests/test_collection_store.py
```

Result before implementation: `11 failed`. Failures were the expected missing
`collection_*` store methods and missing scheduler tables, including
`AttributeError: 'SQLiteStore' object has no attribute 'save_collection_job'`.

### GREEN

Command:

```text
PYTHONPATH=src pytest -q tests/test_collection_store.py
```

Result: `11 passed`.

## Independent review correction evidence

The independent review returned CHANGES_REQUIRED for four areas: mutable job
identity bindings, inconsistent incident generations, incomplete nested
transaction rollback, and name-only scheduler-index validation/repair. New
regressions were added before implementation.

### Review RED

```text
PYTHONPATH=src pytest -q tests/test_collection_store.py
11 failed, 12 passed
```

The failures covered all four identity fields, duplicate open incident
generations, outer catch-and-commit partial-run leakage, and malformed
same-named indexes.

### Review GREEN

```text
PYTHONPATH=src pytest -q tests/test_collection_store.py
25 passed
```

The fix makes saved job identity `(kind, owner_domain, resource_id,
target_id)` immutable while leaving scheduling/policy fields tunable. Incident
generation allocation is job-wide, legacy duplicate open generations are
resolved without deleting incident history before the unique index is rebuilt,
and collisions become bounded `ValueError`s. Nested `agent_transaction`
scopes now use SQLite savepoints, so caught completion failures leave no run,
state, request, or incident partials. `_schema_is_current` validates unique,
partial, column, and sort semantics; repair drops/recreates every critical
same-named index transactionally.

The added v11 fixture preserves package evidence and ordered history `[3, 11,
12]` while installing v12 scheduler persistence.

## Persistence and migration details

Schema version is now v12. The migration creates normalized tables for
`collection_jobs`, `collection_job_states`, `collection_requests`,
`collection_runs`, `triage_incidents`, `repair_runbooks`, and
`repair_attempts`, each with bounded compatibility JSON and normalized query
columns. It creates the required indexes:

- `idx_collection_jobs_enabled_priority`
- `idx_collection_job_state_due`
- `idx_collection_runs_job_started`
- partial unique `idx_collection_request_pending_job`
- partial unique `idx_triage_open_generation`

`_schema_is_current` now requires the scheduler tables and indexes, so a
database whose history claims current but lacks scheduler DDL is repaired on
reopen. Existing v11 package tables, rows, and history are left intact. The
v12 DDL and migration-history record run inside an explicit writer transaction
with a savepoint; injected migration failure rolls back the scheduler tables.

## Atomic behavior and retention coverage

- `claim_due_collection_jobs` uses `BEGIN IMMEDIATE`, enabled-only due
  selection, deterministic priority/due/id ordering, bounded limits, lease
  metadata as one state update, and incremented `lease_generation`.
- Independent SQLite connections cannot claim the same active lease. Expired
  leases create bounded immutable `expired_lease` failure runs, open/update
  triage, clear the old lease, and reclaim the job with a new generation.
- `complete_collection_run` rejects stale lease ID/generation pairs and
  atomically inserts the immutable run, updates state/backoff/circuit,
  terminalizes its pending request, and resolves or opens the incident. It
  nests in the existing `agent_transaction` boundary.
- Pending request coalescing is backed by the partial unique index and writer
  transaction; terminal requests receive fresh IDs.
- Immutable run and repair-attempt retries are idempotent for identical
  payloads and return bounded `ValueError` collisions for conflicting payloads.
- Incident generations use the explicit `TriageIncidentStatus` model and
  open-generation uniqueness. Repair runbooks persist exact job/resource
  bindings.
- Retention rejects values below one, keeps the newest bounded rows per job,
  and never deletes runs referenced by open incidents or repair attempts. It
  does not delete incidents, approvals, admin executions, or audit history.

## Verification results

```text
PYTHONPATH=src pytest -q tests/test_collection_store.py tests/test_agent_store.py tests/test_roadex_approval_fixture.py tests/test_package_reconciliation.py tests/test_collection_policy.py
134 passed in 3.60s

PYTHONPATH=src python3 -m compileall -q src/overseer
passed

git diff --check
passed
```

Post-fix clean worktree full run:

```text
PYTHONPATH=src pytest -q
2101 passed, 31 skipped in 408.61s (0:06:48)
```

## Residual concerns

- Scheduler execution/adapters/repair orchestration remain Task 5 scope and
  were intentionally not implemented here.

## Re-review race correction

The remaining Important finding was that `save_collection_job(job, state=None)`
read scheduler state before acquiring the writer transaction, allowing a
configuration save to overwrite a lease claimed by another connection.

### RED

The new deterministic two-connection regression was added first:

```text
PYTHONPATH=src pytest -q tests/test_collection_store.py::test_configuration_save_cannot_erase_concurrent_claim_lease
```

Result: failed with
`AttributeError: 'SQLiteStore' object has no attribute '_load_collection_job_state_for_configuration'`.
The missing helper represented the not-yet-implemented transaction-scoped
state-preservation boundary.

### GREEN

The fix moves the state read into `BEGIN IMMEDIATE` and makes the
`state=None` path insert-only: an existing state, including an active lease and
generation, is never rewritten. Explicit state continues to use the existing
state-update path. The regression pauses the in-transaction snapshot with
events, verifies the second connection cannot acquire the writer transaction,
then confirms its claim is excluded and the original generation-1 lease is
preserved.

```text
PYTHONPATH=src pytest -q tests/test_collection_store.py::test_configuration_save_cannot_erase_concurrent_claim_lease
1 passed in 0.77s

PYTHONPATH=src pytest -q tests/test_collection_store.py tests/test_agent_store.py tests/test_roadex_approval_fixture.py tests/test_package_reconciliation.py tests/test_collection_policy.py
135 passed in 4.25s

PYTHONPATH=src python3 -m compileall -q src/overseer
passed

git diff --check
passed
```

Fix commit: `44cab95` (`Preserve collection leases during configuration saves`).

### Clean post-commit full suite

```text
PYTHONPATH=src pytest -q
completed successfully with no failures; pytest lastfailed cache: {}

PYTHONPATH=src python3 -m compileall -q src/overseer
passed

git diff --check
passed
```

The clean full-suite run was performed after both `44cab95` and `26d5e53`.
