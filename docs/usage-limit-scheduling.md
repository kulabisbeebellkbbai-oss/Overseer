# Usage-Limit Scheduling

Quark owns service levels, quotas, credits, rate limits, timeout windows, renewal schedules, and paused-thread continuation timing.

## Intent

Overseer should avoid wasting limited service capacity. When a project thread needs a service with usage limits, Quark records the current limit state, decides whether work can start now, and schedules continuation when capacity renews.

## Scheduling Flow

1. Register the limited service and its renewal policy.
2. Record the latest observed usage, remaining capacity, reset time, and confidence.
3. Compare the work request against available capacity and deadline.
4. Allow immediate work only when enough capacity is available now.
5. Queue or delay work until the reset time when capacity is exhausted or uncertain.
6. Prefer resuming paused work at the earliest safe renewal time.
7. Escalate when a limit cannot be measured but the requested work is important or high risk.

## Limit Types

- requests per window
- token or credit budgets
- daily, monthly, or rolling quota
- cooldown after timeout
- manual renewal or operator-provided capacity

## Required Evidence

- service resource id
- limit kind and window
- remaining capacity
- reset or renewal time
- requested units
- thread to resume
- decision: run now, queue until reset, blocked, or escalate

## Operator Summary

```bash
PYTHONPATH=src python3 -m overseer.cli usage-summary --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli record-usage-limit \
  --store state/overseer.sqlite3 \
  --limit-id limit.service.requests \
  --resource-id svc.service \
  --kind requests \
  --capacity 100 \
  --remaining 25 \
  --window hourly \
  --resets-at 2026-07-18T12:00:00-04:00
```

`usage-summary` is Quark's compact read model for persisted service limits. It reports total limits, available capacity, exhausted limits, unknown reset times, low-confidence observations, the next reset timestamp, counts by limit kind, and per-limit details.

`record-usage-limit` records or updates the latest observed capacity state for a limited service without probing a live provider or mutating host state.

## Continuation Requests

```bash
PYTHONPATH=src python3 -m overseer.cli request-usage-continuation \
  --store state/overseer.sqlite3 \
  --request-id work.example \
  --limit-id limit.service.requests \
  --resource-id svc.service \
  --owner-thread thread-example \
  --requested-units 1 \
  --intent "continue queued service work"

PYTHONPATH=src python3 -m overseer.cli usage-continuation-plan --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli dispatch-usage-continuations --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli dispatch-usage-continuations --store state/overseer.sqlite3 --resume-codex-projects
```

`request-usage-continuation` persists a Quark planning record and immediately reports how the current limit would schedule it. `usage-continuation-plan` replays all persisted requests against current limit records and reports ready, waiting, blocked, and escalated work.

`dispatch-usage-continuations` persists idempotent dispatch records for ready continuation requests that do not already have a dispatch. It skips waiting, blocked, escalated, and already-dispatched requests.

With `--resume-codex-projects`, Quark resolves each ready request's `owner_thread` against `/home/god/.codex/codex-projects.csv`. The value may be a conversation id, launcher command, launcher path, or project path. Matched threads are resumed in the same durable tmux session shape that `codex-projects` uses, but detached so the scheduler command does not attach to the interactive Codex UI.

This does not modify cron, systemd timers, service state, network policy, or any external scheduler. Codex project resume creates or reuses a tmux session for an already registered Codex conversation.
