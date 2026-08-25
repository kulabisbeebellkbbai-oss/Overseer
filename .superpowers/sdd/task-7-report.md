# Task 7 report: review corrections

## Outcome and commits

- Worktree: `/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`
- Base implementation: `34ae95f` (`Expose durable collection scheduler API`)
- Prior report: `d4ceca1` (`Document Task 7 API verification`)
- Review correction implementation: `bd4296d` (`Harden Task 7 collection controls`)
- Report commit: follows this verification
- No live services, gateway, original checkout, other worktrees, network policy,
  or `.superpowers/sdd/progress.md` were modified.

## TDD evidence

Review-focused RED tests were added first and initially reported `10 failed,
8 passed` in `tests/test_collection_api.py`. The failures covered encoded path
IDs, idempotent transition response/audit behavior, bounded legacy enqueue
metadata, ignored route filters, and generic error handling.

GREEN focused/relevant verification:

```text
PYTHONPATH=src pytest -q tests/test_collection_api.py tests/test_performance_regression.py \
  tests/test_api_store_binding.py tests/test_agent_api.py tests/test_ui_regression.py \
  tests/test_collection_runtime.py tests/test_collection_store.py tests/test_collection_scheduler.py \
  tests/test_collection_repair.py tests/test_collection_policy.py
174 passed in 44.94s
```

Additional checks:

```text
PYTHONPATH=src python3 -m compileall -q src/overseer tests/test_collection_api.py tests/test_performance_regression.py
git diff --check
```

Clean full regression after `bd4296d`:

```text
PYTHONPATH=src pytest -q
2158 passed, 31 skipped in 429.72s (0:07:09)
```

## RED/GREEN route matrix and acceptance evidence

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

Unauthenticated scheduler GETs return `401` for both route forms. Control POSTs
require the existing admin bearer token and exact `{requested_by, reason}`
fields. Malformed percent escapes, invalid UTF-8, slash-containing IDs after
strict segment decoding, and overlong IDs return bounded `400` responses.
The client quotes job IDs with `safe=''` and tests direct/prefix round trips for
Unicode and encoded slash IDs.

## Review-finding evidence

- Path IDs: the handler captures one raw segment, validates each percent escape,
  strictly decodes UTF-8 bytes, then applies the existing bounded identifier
  validator. No path confusion or 404/500 leakage occurs.
- Atomic suspend/resume: `SQLiteStore.set_collection_job_enabled` performs the
  load, no-op check, state-preserving save, and audit insert inside one
  `agent_transaction`. Deterministic occurrence IDs avoid timestamp uniqueness;
  exact retries produce no new audit, and concurrent identical controls produce
  one transition/audit. Lease, generation, circuit, cooldown, and pending
  request state remain unchanged.
- Deprecated health enqueue: one store transaction counts enabled health jobs,
  selects at most the fixed 50-job compatibility bound, and uses indexed pending
  coalescing. Responses include `total_count`, `returned_count`, `truncated`,
  and bounded request IDs/statuses only; reasons and adapter execution are absent.
- Query schemas: each GET route declares its own accepted fields. In particular,
  `/collections/status` rejects `status`, runbooks reject `status`, and unknown
  fields are `400`. The client status method no longer offers an unsupported
  status argument.
- Generic failures: collection projection/control handlers map unexpected
  exceptions to exactly `{"error":"internal_error"}` with `500`, without
  exception text; explicit 400/401/404/409 handling remains, including
  deprecation headers on legacy failures.
- Privacy: bounded Task 6 projections remain the source for GET responses and
  omit request reasons, raw evidence, secrets, credentials, response bodies,
  and paths.

## Performance evidence

- Scheduler status/jobs/runs/incidents/runbooks were added to the existing
  authenticated GET budget matrix with 1.0-second budgets.

`test_collection_run_queue_does_not_wait_for_blocking_adapter` now creates a
temporary SQLite store, registers a real `BlockingAdapter`, starts an actual
`CollectionScheduler` with one worker against a due blocking job, and waits for
the adapter to hold that worker. It then queues a different job through the API,
asserting the response completes under the existing 1-second safe mutation
budget without inline execution. Events release the adapter and join the worker
before scheduler shutdown.

The GET budget matrix populates 24 bounded jobs, runs, incidents, and runbooks
before timing scheduler projections. No fragile fixed sleeps or exact timing
claims are used; all assertions use the existing elapsed budget style.

## Residual concerns

- Deprecated health requests intentionally operate on scheduler-seeded health
  jobs. If no enabled scheduler health jobs exist, the bounded response is an
  accepted request with zero queued items; job seeding remains Task 6 policy.
- No adapter execution, scheduler cycle, service restart, gateway action, or
  external side effect is performed by these API controls.
