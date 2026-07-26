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

## Codex Thread Registry

```bash
PYTHONPATH=src python3 -m overseer.cli discover-codex-project-threads --store state/overseer.sqlite3
```

`discover-codex-project-threads` reads the local `codex-projects` CSV registry and imports each registered conversation as a Quark-owned `usage_limited_service` resource. This gives continuation requests a managed owner-thread resource before any resume action is attempted. The command does not start, resume, or stop Codex sessions.

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

## Tank/MSI Remote Testing Facility

Quark also manages the Tank/MSI remote testing queue as a leased usage facility.
The queue root is local-only at `local-secrets/remote-testing` and is excluded
from git. Jobs must contain only redacted-safe metadata: endpoint names, status
expectations, validation stages, and fixture identifiers. Raw bearer tokens,
cookies, browser storage, API keys, local database exports, screenshots, HTML,
and raw response bodies must not be queued or returned.

```bash
PYTHONPATH=src python3 -m overseer.cli remote-testing-status --project-root .
PYTHONPATH=src python3 -m overseer.cli record-remote-testing-profile --project-root .
PYTHONPATH=src python3 -m overseer.cli request-remote-testing-lease \
  --project-root . \
  --lease-id lease.overseer.tank-regression \
  --project Overseer \
  --purpose "run protected-gateway regression without human relay" \
  --job-type ping \
  --job-type overseer.full_ui_regression
PYTHONPATH=src python3 -m overseer.cli enqueue-remote-test-job \
  --project-root . \
  --lease-id lease.overseer.tank-regression \
  --job-type ping \
  --params-json '{"validation_stage":"queue-ping"}'
PYTHONPATH=src python3 -m overseer.cli collect-remote-test-results \
  --project-root . \
  --lease-id lease.overseer.tank-regression
```

The profile describes Tank on MSI, the worker hint, protected gateway path,
token source path, supported job types, and redaction rules. The default route
is `god@10.50.0.100` through the protected gateway or VPN-reachable coordination
surface. Quark and project threads must not depend on `god@192.168.68.xxx` or
the `192.168.68.xxx` LAN path because MSI may not be on HulaHut. A lease
authorizes a project batch to queue selected job types for a limited period.
Quark rejects job parameters that appear to contain secret material and rejects
mutating jobs unless the job contract includes an explicit disposable fixture.

## Final Answer Remote Testing Hook

The user-scope Codex Stop hook `overseer-quark-remote-testing-hook.py` lets
Quark coordinate final-answer testing before an implementation answer is
delivered. When a final answer describes completed UI, protected gateway,
browser, panel, route, endpoint, API, workflow, performance, or auth work and
does not already include Quark/Tank evidence, the hook uses the Quark remote
testing queue to:

- reuse or create a project lease for the current Codex project;
- enqueue `overseer.full_ui_regression`, `overseer.performance_regression`, or
  `protected_gateway.request_sequence` as appropriate;
- record a Quark crew message for traceability when the Overseer store is
  available;
- block the final response with a hook prompt so the same thread continues;
- collect redacted Tank/MSI results on the next stop check and ask the agent to
  include those results before final delivery.

The hook is intentionally conservative. It skips answers that already include
Quark remote testing evidence, local-only work, explicit skip wording, or no
completed UI/gateway/API/browser-facing change. It never queues raw secrets and
relies on the existing remote testing redaction policy for result summaries.
