# Task 6: Scheduler-backed runtime and idempotent collection seeding

## Outcome

Implemented in the isolated worktree:

`/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`

Implementation commit: `14165c4` (`Run collectors on independent schedules`)

Compatibility-test correction: `2052624` (`Align runtime compatibility assertion with scheduler queue`)

No live services, original checkout, other worktrees, gateways, firewall/network
policy, external project, or `.superpowers/sdd/progress.md` was modified.

## TDD evidence

### RED

The Task 6 tests were written first and run with:

```text
PYTHONPATH=src pytest -q tests/test_collection_runtime.py
```

The expected collection failure was:

```text
ImportError: cannot import name 'seed_default_collection_jobs' from 'overseer.runtime'
```

This demonstrated that the requested seeding/runtime public contract was not
present before implementation.

### GREEN

Exact Task 6 focused command after implementation and commits:

```text
PYTHONPATH=src pytest -q tests/test_collection_runtime.py tests/test_core.py -k "runtime or health_target or collection"
58 passed, 334 deselected in 28.06s
```

Relevant scheduler/store/config coverage:

```text
PYTHONPATH=src pytest -q tests/test_collection_scheduler.py tests/test_collection_repair.py tests/test_collection_store.py tests/test_collection_policy.py
82 passed in 6.05s
```

Final clean full suite:

```text
PYTHONPATH=src pytest -q
2132 passed, 31 skipped in 473.54s (0:07:53)
```

Additional checks passed:

```text
PYTHONPATH=src python3 -m compileall -q src/overseer
git diff --check
```

One full-suite run exposed an unrelated load-sensitive cross-process usage
test failure (`[False, False]` instead of `[False, True]`). The exact test
passed independently, and the final complete suite passed.

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
  raw evidence or secret-bearing request text.
- Added JSON CLI commands for jobs, scheduler status, runs, incidents, queue-only
  run requests, and idempotent seeding. Read commands do not run adapters;
  request and seed commands mutate only the local store.
- Added explicit Psychlo and Quark freshness-observation jobs only. Their
  existing timer units are not seeded as work jobs.
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
| External freshness | `collection.freshness.psychlo-usage`, `collection.freshness.quark-scheduler` | Quark | persisted-evidence freshness callback only |

No job ID duplicates `overseer-psychlo-usage.timer` or
`overseer-quark-scheduler.timer`, and no callback starts those units or repeats
their accounting/scheduling work.

## Compatibility and residual concerns

- Existing runtime result fields and heartbeat counters remain present. Their
  collector-specific values are zero for the compatibility surface because
  durable scheduler runs are now the source of truth; detailed run outcomes are
  available through collection status commands.
- The default host job uses a short bounded command deadline because unavailable
  user-systemd/firewall evidence must not hold a one-cycle foreground run.
- Full-suite runtime verification is slower than the focused suites because
  startup seeding and one-cycle scheduler execution exercise real bounded local
  read-only adapters. The final suite is clean.
- Task 7 still owns authenticated API route exposure; this task only provides
  the CLI/status helpers and queue-only local control needed by that follow-on.
