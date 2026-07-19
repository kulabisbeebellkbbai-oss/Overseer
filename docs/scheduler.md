# Scheduler

The scheduler coordinates when work should continue. It does not install timers, edit cron, start daemons, or wake suspended threads. It produces local planning records and can persist dispatch handoff records for ready usage-limited work.

## Responsibilities

- rank work that can run now
- queue usage-limited work until reset
- persist usage-limited continuation requests for later authorized consumption
- persist idempotent dispatch records for continuation requests that are ready now
- surface quota uncertainty as an approval-bound wait state
- detect overlapping exclusive maintenance windows
- keep continuation timing explicit for project threads

## Boundaries

- No host scheduler is modified.
- No service is started or resumed automatically.
- No persisted continuation request wakes a thread by itself.
- Dispatch records are local handoff evidence only; an external launcher or operator must consume them.
- No live capacity probe is performed.
- All inputs must come from already captured usage-limit, maintenance, or operator-provided state.
