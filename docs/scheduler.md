# Scheduler

The scheduler coordinates when work should continue. It does not install timers, edit cron, or start arbitrary daemons. It produces local planning records, persists dispatch handoff records for ready usage-limited work, and can resume matched Codex project threads through the local `codex-projects` tmux registry.

## Responsibilities

- rank work that can run now
- queue usage-limited work until reset
- persist usage-limited continuation requests for later authorized consumption
- persist idempotent dispatch records for continuation requests that are ready now
- resume ready Codex project continuations when `owner_thread` matches a `codex-projects` conversation id, launcher command, launcher path, or project path
- surface quota uncertainty as an approval-bound wait state
- detect overlapping exclusive maintenance windows
- keep continuation timing explicit for project threads

## Boundaries

- No host scheduler is modified.
- No arbitrary service is started automatically.
- No persisted continuation request wakes a thread by itself; resume only happens during an explicit dispatch run with codex-projects resume enabled.
- Codex project resume starts or reuses the durable tmux session that `codex-projects` would use for the same conversation.
- No live capacity probe is performed.
- All inputs must come from already captured usage-limit, maintenance, or operator-provided state.
