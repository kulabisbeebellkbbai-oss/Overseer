# Task 7 report: durable collection scheduler API

## Outcome and commits

- Worktree: `/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`
- Implementation commit: `34ae95f` (`Expose durable collection scheduler API`)
- Report commit: written after implementation verification
- No live services, gateway, original checkout, other worktrees, network policy,
  or `.superpowers/sdd/progress.md` were modified.

## TDD evidence

### RED

The route tests were written before the API implementation and run with:

```text
PYTHONPATH=src pytest -q tests/test_collection_api.py
```

Result: `6 failed, 1 passed`. The expected failures were scheduler GET and run
routes returning `404`, control routes missing, and the existing
`/health/probes/run` route returning its old inline-probe `200` response rather
than a bounded enqueue response.

### GREEN

Focused Task 7 and performance verification:

```text
PYTHONPATH=src pytest -q tests/test_collection_api.py tests/test_performance_regression.py
12 passed in 7.18s
```

Post-commit exact Task 7 plus relevant auth/prefix/runtime/store/scheduler/
repair suites:

```text
PYTHONPATH=src pytest -q tests/test_collection_api.py tests/test_performance_regression.py \
  tests/test_api_store_binding.py tests/test_agent_api.py tests/test_ui_regression.py \
  tests/test_collection_runtime.py tests/test_collection_store.py \
  tests/test_collection_scheduler.py tests/test_collection_repair.py \
  tests/test_collection_policy.py
164 passed in 39.23s
```

Clean full regression:

```text
PYTHONPATH=src pytest -q
2148 passed, 31 skipped in 425.42s (0:07:05)
```

Additional checks passed:

```text
PYTHONPATH=src python3 -m compileall -q src/overseer
git diff --check
```

## Route matrix and acceptance evidence

| Surface | Direct route | Protected-prefix route | Contract |
|---|---|---|---|
| Scheduler status | `GET /collections/status` | `GET /Overseer/collections/status` | Authenticated, bounded scheduler/job projection |
| Jobs | `GET /collections/jobs` | `GET /Overseer/collections/jobs` | `job_id`, enabled/disabled `status`, bounded `limit` |
| Runs | `GET /collections/runs` | `GET /Overseer/collections/runs` | `job_id`, outcome `status`, bounded `limit` |
| Incidents | `GET /collections/incidents` | `GET /Overseer/collections/incidents` | `job_id`, open/resolved `status`, bounded `limit` |
| Runbooks | `GET /collections/runbooks` | `GET /Overseer/collections/runbooks` | `job_id`, bounded `limit` |
| Queue run | `POST /collections/jobs/{job_id}/run` | `POST /Overseer/collections/jobs/{job_id}/run` | Admin token, exact `{requested_by, reason}`, durable coalescing only |
| Suspend/resume | `POST /collections/jobs/{job_id}/suspend|resume` | Prefix equivalent | Admin token, exact bounded actor/reason, enabled-only policy update |
| Deprecated health control | `POST /health/probes/run` | `POST /Overseer/health/probes/run` | Admin token, enabled health jobs only, `Deprecation: true`, successor `Link` |

Authentication uses the existing bearer contract before normalized route
dispatch. Tests cover every scheduler GET both directly and under `/Overseer`,
with unauthenticated requests returning `401`; queue controls reject missing
admin authorization and extra payload fields.

The run response contains `queued` or `coalesced`, request ID, earliest
execution, circuit state/cooldown, and no submitted reason. It calls only the
durable `request_collection_run_status` helper. Suspend/resume uses the
state-preserving `save_collection_job(..., state=None)` path; an active lease
and generation remain unchanged, and a bounded local audit event is recorded.

All GET responses reuse Task 6 bounded projections or a bounded runbook
projection. API limits are capped at 500; filters are validated; responses do
not include request reasons, raw evidence payloads, secrets, credentials,
response bodies, adapter paths, or unbounded arrays.

The deprecated route queues only enabled, scheduler-seeded health jobs and
returns bounded request IDs/statuses. It never constructs or invokes a
`CollectionScheduler` or adapter. Direct and protected-prefix responses emit
the corresponding successor link (`/collections/jobs` or
`/Overseer/collections/jobs`). Existing legacy tests were updated from inline
evidence assertions to the new enqueue contract.

## Performance evidence

- Scheduler status/jobs/runs/incidents/runbooks were added to the existing
  authenticated GET budget matrix with 1.0-second budgets.
- `test_collection_run_queue_does_not_wait_for_blocking_adapter` installs a
  blocking fake adapter entry behind `CollectionScheduler.run_ready_once`; the
  queue POST does not start it and completes under the existing 1.0-second safe
  mutation budget.
- No wall-clock sleeps or fragile exact timing assertions are used; the test
  follows the existing elapsed-time budget style.

## Residual concerns

- Deprecated health requests intentionally operate on scheduler-seeded health
  jobs. If no enabled scheduler health jobs exist, the bounded response is an
  accepted request with zero queued items; job seeding remains Task 6 policy.
- No adapter execution, scheduler cycle, service restart, gateway action, or
  external side effect is performed by these API controls.
