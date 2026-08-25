# Task 6: Scheduler-backed runtime and idempotent collection seeding

## Outcome

Implemented in the isolated worktree:

`/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`

Implementation commits:

- `14165c4` (`Run collectors on independent schedules`)
- `2052624` (`Align runtime compatibility assertion with scheduler queue`)
- `c1aa681` (`Document independent collection runtime`)
- `008f70a` (`Harden scheduler freshness and callback bounds`)

No live services, original checkout, other worktrees, gateways, firewall/network
policy, external project, or `.superpowers/sdd/progress.md` was modified.

## TDD evidence

### RED

The Task 6 tests were written first and run with:

```text
PYTHONPATH=src pytest -q tests/test_collection_runtime.py
```

The review-correction regression run failed on the expected missing contracts:

```text
5 failed, 7 passed
TypeError: runtime_collection_adapter_registry() got an unexpected keyword argument 'systemd_runner'
TypeError: seed_default_collection_jobs() got an unexpected keyword argument 'families'
KeyError: 'limit' from the unbounded crew callback binding
argparse: unrecognized arguments: --limit 1 for collection-jobs
```

These failures demonstrated that the review requirements were not present
before the correction: freshness still projected the Overseer heartbeat,
legacy flags could not select seed families, callback bounds were not
propagated, and projections were not bounded.

### GREEN

Exact Task 6 focused command after implementation and commits:

```text
PYTHONPATH=src pytest -q tests/test_collection_runtime.py tests/test_core.py -k "runtime or health_target or collection"
65 passed, 334 deselected in 26.38s
```

Relevant scheduler/store/config coverage:

```text
PYTHONPATH=src pytest -q tests/test_collection_scheduler.py tests/test_collection_repair.py tests/test_collection_store.py tests/test_collection_policy.py tests/test_psychlo_bridge_cli_usage.py tests/test_quark_scheduler.py
151 passed in 6.29s
```

Final clean full suite:

```text
PYTHONPATH=src pytest -q
2139 passed, 31 skipped in 425.91s (0:07:05)
```

Additional checks passed:

```text
PYTHONPATH=src python3 -m compileall -q src/overseer
git diff --check
```

The review-correction focused RED/GREEN sequence was completed before commit
`008f70a`; the final full suite was clean with no unrelated failure.

## Implementation

- `OverseerRuntime.tick()` now performs one heartbeat update and exactly one
  `CollectionScheduler.run_ready_once()` call. It does not invoke bulk health,
  host, dispatch, usage, knowledge, or station collectors directly.
- `run()` sleeps toward the scheduler's nearest due time, capped by a bounded
  idle interval. `once=True` executes one ready cycle and closes the scheduler.
- Startup and `seed-collection-jobs` use stable, idempotent definitions. Existing
  job state, active leases, lease generations, backoff, and circuit state are
  preserved while schedule policy is refreshed.
- Legacy runtime flags remain accepted and are marked deprecated; they are
  seeding/compatibility switches and no longer mean “run on every tick.”
- HealthTarget now supports `interval_seconds`, `jitter_seconds`,
  `timeout_seconds`, and `repair_policy`, with v1.0-compatible defaults and
  backward-compatible persisted/config parsing.
- Scheduler job status and CLI status projections expose bounded due/age,
  lease, failure/backoff, circuit, incident, and pending-request data without
  raw evidence or secret-bearing request text. Jobs, incidents, per-job
  incidents, leased IDs, requests, and runs return deterministic
  `total_count`, `returned_count`, `truncated`, and remaining metadata where
  applicable.
- Added JSON CLI commands for jobs, scheduler status, runs, incidents, queue-only
  run requests, and idempotent seeding. Read commands do not run adapters;
  request and seed commands mutate only the local store.
- Added explicit Psychlo and Quark freshness-observation jobs only. Their
  existing timer units are not seeded as work jobs. Freshness uses an injectable
  bounded `systemctl --user show` runner in tests and an actual subprocess
  timeout from `job.timeout_seconds` in production. It queries only
  `ActiveState`, `SubState`, `Result`, `LastTriggerUSecRealtime`, and
  `NextElapseUSecRealtime`, persists no raw output, and classifies unavailable,
  stale, and timeout states as bounded blocked/failed outcomes.
- All runtime callback registrations use the three-argument
  `(job, store_path, timeout_seconds)` contract. Scheduler bindings pass
  explicit limits: crew and usage one item, knowledge and station one item,
  and discovery 25 items per cycle. Manual status defaults remain compatible.
- Legacy selectors map deterministically as follows: health, host,
  crew-dispatch, usage-continuation, knowledge-capture, and station-audit;
  selected runs always include freshness observation, while no-flag startup
  seeds the complete base matrix. Existing unrelated jobs are retained.
- Added a small scheduler completion timestamp guard so a fast worker cannot
  produce a completion timestamp earlier than its coordinator-sampled start.

## Seeded job matrix and adapter ownership

| Stable job family | Job IDs | Owner | Adapter binding |
|---|---|---|---|
| Health | `collection.health.<target-id>` per enabled target | target owner | existing `health-probe` adapter |
| Host inspection/security | `collection.host.inspection`, `collection.host.security` | Odo | `host-inspection`, exact `assess_host_security_status` callback |
| Physical/storage discovery | `collection.discovery.physical`, `collection.discovery.storage` | Kira | exact physical/storage store-path callbacks |
| Virtual discovery | `collection.discovery.virtual` | Dax | exact virtual-listener store-path callback |
| Crew dispatch | `collection.dispatch.crew` | Sisko | exact crew-dispatch store-path callback |
| Usage continuation | `collection.usage.continuation` | Quark | exact usage-dispatch store-path callback |
| Knowledge capture | `collection.knowledge.capture` | Ezri | exact knowledge-capture store-path callback |
| Station audit | `collection.station.audit` | Julian | exact station-audit store-path callback |
| Package inspection | `collection.package.inspection` | O'Brien | existing bounded package adapter |
| External freshness | `collection.freshness.psychlo-usage`, `collection.freshness.quark-scheduler` | Quark | exact bounded user-systemd freshness callback |

No job ID duplicates `overseer-psychlo-usage.timer` or
`overseer-quark-scheduler.timer`, and no callback starts those units or repeats
their accounting/scheduling work.

The freshness job IDs remain distinct from the queried service/timer unit IDs:
each job queries its exact service plus paired timer using read-only
`systemctl --user show` calls. The tests assert that no `start`, `enable`, or
execution verb is issued.

## Compatibility and residual concerns

- Existing runtime result fields and heartbeat counters remain present. Their
  collector-specific values are zero for the compatibility surface because
  durable scheduler runs are now the source of truth; detailed run outcomes are
  available through collection status commands.
- Deprecated `run` flags remain accepted and are documented as idempotent
  family-seeding selectors. They no longer invoke collectors inline or mean
  “run this collector every tick.” The explicit `seed-collection-jobs` command
  also accepts repeated bounded `--family` selectors.
- Request reasons remain durable internally for audit/coalescing semantics,
  but are intentionally absent from collection job, scheduler, and request
  JSON read projections.
- The default host job uses a short bounded command deadline because unavailable
  user-systemd/firewall evidence must not hold a one-cycle foreground run.
- Full-suite runtime verification is slower than the focused suites because
  startup seeding and one-cycle scheduler execution exercise real bounded local
  read-only adapters. The final suite is clean.
- Task 7 still owns authenticated API route exposure; this task only provides
  the CLI/status helpers and queue-only local control needed by that follow-on.
