# Scheduler

The v1.1 scheduler is the always-running collection coordinator owned by the
Overseer runtime service. It persists independent jobs, leases, requests,
runs, circuits, incidents, and repair decisions in the explicit SQLite store.
The API and dashboard consume these records and never execute a collector inline.

## Responsibilities

- rank due collection work under bounded priority and concurrency
- run independent health, host, discovery, dispatch, knowledge, package, firmware, freshness, Git, and storage-capacity jobs
- retain per-job next-due, jitter, timeout, lease, outcome, and data-age state
- coalesce duplicate run requests and expose earliest execution time
- apply capped backoff and circuit cooldown after failures
- create durable incidents and invoke only exact low-risk repair runbooks
- fence stale workers and release leases safely across runtime restarts
- queue usage-limited work until reset
- persist usage-limited continuation requests for later authorized consumption
- persist idempotent dispatch records for continuation requests that are ready now
- resume ready Codex project continuations when `owner_thread` matches a `codex-projects` conversation id, launcher command, launcher path, or project path
- surface quota uncertainty as an approval-bound wait state
- detect overlapping exclusive maintenance windows
- keep continuation timing explicit for project threads

## Boundaries

- The source service has no socket listener and does not install or modify a host timer/cron schedule.
- Psychlo and Quark accounting/scheduling timers remain external owners; Overseer observes their freshness.
- No arbitrary service is started automatically.
- No persisted continuation request wakes a thread by itself; resume only happens during an explicit dispatch run with codex-projects resume enabled.
- Codex project resume starts or reuses the durable tmux session that `codex-projects` would use for the same conversation.
- Capacity, Git, and firmware inspection run only as bounded scheduled jobs; dashboard GETs read their durable SQLite projections.
- The firmware callback uses a process boundary so timeout can terminate EFI traversal or a blocked projection write without retaining a scheduler worker; firmware and preflight projections commit as one SQLite transaction.
- Every scheduler worker propagates its absolute monotonic deadline into SQLite persistence. Store lock waits use only the remaining budget, and a commit that reaches the deadline rolls back instead of publishing late evidence.
- All inputs must come from already captured usage-limit, maintenance, or operator-provided state.

## Operations

Use `collection-jobs`, `collection-scheduler-status`, `collection-runs`, and
`collection-incidents` for bounded JSON projections. Use
`request-collection-run` for a queue-only request; repeated pending requests
for one job coalesce. `seed-collection-jobs` is idempotent and writes only the
Overseer store. See `docs/v1.1-operations.md` for job defaults, repair policy,
canary/migration, activation approval, rollback, and compatibility boundaries.
