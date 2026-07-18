# Scheduler

The scheduler coordinates when work should continue. It does not install timers, edit cron, start daemons, or wake suspended threads. It produces local planning records that future authorized services can consume.

## Responsibilities

- rank work that can run now
- queue usage-limited work until reset
- surface quota uncertainty as an approval-bound wait state
- detect overlapping exclusive maintenance windows
- keep continuation timing explicit for project threads

## Boundaries

- No host scheduler is modified.
- No service is started or resumed automatically.
- No live capacity probe is performed.
- All inputs must come from already captured usage-limit, maintenance, or operator-provided state.
