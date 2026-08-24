# Task 4 report: normalized scheduler persistence and atomic leases

## Scope and commits

- Worktree: `/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`
- Base SHA: `c33de207e68e0fcdb666b8e6ba05b1b219cd04b9`
- Implementation SHA: `078aa3a0d6f06646df1c421f3a3d582ee8d278c7`
- Implementation commit: `Persist collection schedules and leases`
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
PYTHONPATH=src pytest -q tests/test_collection_store.py tests/test_agent_store.py tests/test_roadex_approval_fixture.py tests/test_package_reconciliation.py
87 passed in 2.75s

PYTHONPATH=src python3 -m compileall -q src/overseer
passed

git diff --check
passed
```

The full repository run reached `2066 passed, 31 skipped`; 21 unrelated
legacy-attestation tests failed because their source-lineage guard requires a
clean `src` tree while this implementation worktree was intentionally dirty.
Those failures are outside Task 4 and did not occur in the requested or
relevant migration suites.

## Residual concerns

- The existing repository-wide legacy-attestation suite must be rerun from a
  clean committed checkout if full-suite green status is required.
- Scheduler execution/adapters/repair orchestration remain Task 5 scope and
  were intentionally not implemented here.
