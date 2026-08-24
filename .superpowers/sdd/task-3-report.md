# Task 3: Collection records and pure scheduling policy

## Outcome

Implemented Task 3 completely in the isolated `overseer-v1-1-autonomous-operations`
worktree. The implementation is pure models and policy only: it adds no
persistence, threads, subprocesses, runtime scheduling loop, API endpoint, or
service activation behavior.

Code commit: `9906e1387aa86246d554903ebc6d18978d3824a4`

## TDD evidence

### RED

Command:

```text
pytest -q tests/test_collection_policy.py
```

Before implementation, test collection failed as expected because the new
public model surface did not exist:

```text
ImportError: cannot import name 'CircuitState' from 'overseer'
```

This was the expected module/import failure from the brief, rather than a
runtime or assertion failure.

### GREEN

After implementing the records, policy, tests, and package exports:

```text
pytest -q tests/test_collection_policy.py
...................                                                      [100%]
19 passed in 0.20s

python3 -m compileall -q src/overseer/collection_models.py src/overseer/collection_policy.py
# clean; no output

git diff --check
# clean; no output
```

The focused suite was also rerun after the code commit with the same 19/19
result.

A required pre-commit full-suite attempt completed with `1998 passed, 31
skipped, 64 failed`. Those failures were existing source-lineage/clean-tree
guards observing the two newly created, still-untracked Python modules while
the code commit was pending (for example, `untracked Python or executable
import artifact exists in a reviewed source root` and `attestation source tree
is dirty`). They were not failures in `tests/test_collection_policy.py`; the
focused suite passed independently. The full suite was not changed or repaired
because that is outside Task 3 scope.

## Implementation

### Models and enums

`src/overseer/collection_models.py` defines and exports internally:

- `CollectionJobKind`
- `CollectionOutcome`
- `CircuitState`
- `RepairPolicy`
- frozen `CollectionJob`
- frozen `CollectionJobState`
- frozen `CollectionRequest`
- frozen `CollectionRun`
- frozen `TriageIncident`
- frozen `RepairRunbook`
- frozen `RepairAttempt`

Validation is deterministic and fail-closed for bounded identifiers, UTC
ISO-8601 timestamps, positive intervals/timeouts/retention/cooldowns, bounded
non-negative jitter, positive backoff and failure thresholds, non-negative
failure/lease counters, bounded evidence and summaries, and required open-
circuit cooldowns. Automatic repair runbooks (`approval_required=False`) are
accepted only with `RiskLevel.LOW`.

### Policy interfaces

`src/overseer/collection_policy.py` provides:

- `deterministic_jitter(job_id, jitter_seconds)` using SHA-256 bytes and an
  inclusive `0..jitter_seconds` additive window, independent of Python hash
  seed and process state.
- `next_success_due(job, completed_at)` using interval plus stable jitter.
- `next_failure_delay(job, consecutive_failures)` using the exact capped brief
  formula.
- `next_failure_due(job, failed_at, consecutive_failures)` using the capped
  failure delay without ordinary due-time jitter churn.
- `circuit_after_failure(job, consecutive_failures)` opening at the configured
  threshold.
- `circuit_after_success(state)` as the minimal successful half-open transition
  that closes the circuit and clears consecutive failures.
- `job_is_due(state, now)`, which rejects active unexpired leases and, for an
  open circuit, consults only the scheduled cooldown/half-open point rather
  than an overdue ordinary `next_due_at`.

`src/overseer/__init__.py` re-exports only the intended collection model,
enum, and policy names. The new modules import `OwnerDomain` and `RiskLevel`
from `core.py` and do not introduce an import cycle.

## Files changed

- `src/overseer/collection_models.py` — new immutable collection records and
  validation helpers.
- `src/overseer/collection_policy.py` — new pure deterministic schedule,
  backoff, circuit, and due policy.
- `tests/test_collection_policy.py` — RED/GREEN-focused policy and validation
  coverage, 19 tests.
- `src/overseer/__init__.py` — intended public re-exports.
- `.superpowers/sdd/task-3-report.md` — this report only; no historical task
  report or progress ledger was modified.

## Self-review

- Confirmed all interfaces named by the brief are present, including
  `next_failure_delay` and the success transition.
- Confirmed model dataclasses are frozen and validation does not depend on
  wall-clock time, Python hash randomization, persistence, or live services.
- Confirmed the implementation does not add runtime workers, subprocesses,
  API routes, schema changes, or activation behavior.
- Confirmed only the specified isolated worktree was modified.

## Residual concerns

The full-suite clean-tree guard result should be refreshed by the controller
after the code commit if release-level evidence is required. Task 3's exact
focused tests, compile check, and diff check are clean; no Task 3-specific
failure remains.

## Independent review correction

The independent Task 3 review returned `CHANGES_REQUIRED`. All seven findings
were corrected in code commit `78906c2` (`Harden collection policy model
contracts`) without adding persistence, scheduler, repair execution, API, or
service behavior.

1. Added and publicly re-exported `TriageIncidentStatus` with `OPEN` and
   `RESOLVED` values. `TriageIncident.status` is distinct from the bounded
   `repair_state`, directly supporting Task 4's normalized partial index
   `WHERE status = 'open'` and later resolution.
2. Added required `job_id` and `resource_id` fields to `RepairRunbook`, with
   bounded identifier validation for exact Task 5 binding checks.
3. Made `active_lease_id`, `lease_owner`, and `lease_expires_at` an all-or-none
   group. `job_is_due` continues to suppress work while the bound lease expiry
   is strictly in the future; the regression test covers both suppression and
   the expiry boundary.
4. Restricted `circuit_after_success` to `CircuitState.HALF_OPEN`. It now
   closes the circuit, clears failures and cooldown, and records
   `CollectionOutcome.SUCCEEDED`; CLOSED and OPEN misuse are rejected.
5. `TriageIncident` now rejects `latest_failure_at` earlier than
   `first_failure_at` after normalized UTC timestamp comparison.
6. Replaced the local-only hash-seed assertion with a bounded portable
   subprocess test using two distinct `PYTHONHASHSEED` values and the same
   SHA-256 jitter call.
7. Added lifecycle, runbook-binding, partial-lease, active-lease, circuit
   transition, timestamp-order, and bounded-repair-state tests.

### Correction TDD evidence

RED command:

```text
pytest -q tests/test_collection_policy.py
```

The newly added review tests failed during collection with the expected
missing public contract:

```text
ImportError: cannot import name 'TriageIncidentStatus' from 'overseer'
```

GREEN command and result:

```text
pytest -q tests/test_collection_policy.py
.................................                                        [100%]
33 passed in 0.77s
```

The suite includes the subprocess hash-seed check and all review regression
cases. Additional verification after the code commit:

```text
python3 -m compileall -q src/overseer/collection_models.py src/overseer/collection_policy.py
# clean; no output

git diff --check
# clean; no output

pytest -q
2076 passed, 31 skipped in 433.35s (0:07:13)
```

### Compatibility preflight

Task 4's brief was checked for the normalized `triage_incidents.status`,
`lease_expires_at`, and `job_id`/`resource_id` persistence/query contracts.
Task 5's brief is present at `.superpowers/sdd/task-5-brief.md`; its exact
runbook-binding rejection requirement was checked against the new fields.
No Task 4 persistence or Task 5 scheduler/repair implementation was added.

The earlier pre-commit full-suite concern is superseded by the clean
post-commit result above. The report update is intentionally a separate
imperative report commit after code commit `78906c2`.
