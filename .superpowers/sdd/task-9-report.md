# Task 9 Report: Overseer v1.1 operations

## Outcome

Task 9 adds the source-controlled autonomous runtime unit and the v1.1
operations, migration, canary, approval, rollback, compatibility, and
non-mutation documentation. The unit runs the scheduler-backed foreground
runtime continuously from a user-owned environment file. It has no API
listener, no bulk collector flags, and no live installation side effect.

The previously present `task-9-report.md` described an unrelated provider
adapter. It was replaced with this Task 9 report; no provider or other project
files were changed.

## TDD evidence

### RED: missing source unit reproduced

```text
$ pytest -q tests/test_collection_systemd.py
FF
FileNotFoundError: .../systemd/overseer.service
2 failed
```

The contract test was added before the unit and required the scheduler command,
environment-file paths, restart policy, no socket/listener directives, and no
deprecated bulk collector flags.

### GREEN: source unit and documentation implemented

```text
$ pytest -q tests/test_collection_systemd.py tests/test_collection_runtime.py \
    tests/test_collection_api.py tests/test_performance_regression.py
.......................................                                  [100%]
39 passed in 13.70s

$ python3 -m compileall -q src tests
passed

$ git diff --check
passed
```

CLI checks passed against a disposable SQLite store. `seed-collection-jobs`
was idempotent and seeded the scheduler-owned fixed jobs; scheduler status
reported bounded global/per-key load, durable status, and no incidents. A
queue request returned `queued`, and the identical pending request returned
`coalesced` with the same request ID. No adapter was called inline and no host
mutation was performed.

The CLI help contains `collection-scheduler-status`,
`request-collection-run`, and `seed-collection-jobs`. Documentation grep found
the required status/request and `triage_only`/`approval_required` terms in the
updated operations surfaces.

## Implementation

`systemd/overseer.service`:

- reads `%h/.config/overseer/runtime.env`;
- consumes `OVERSEER_PYTHON`, `OVERSEER_INSTALL`, and `OVERSEER_STORE`;
- sets `PYTHONPATH` from the install variable;
- runs `${OVERSEER_PYTHON} -m overseer.cli run --store ${OVERSEER_STORE}`;
- uses `Restart=on-failure`, bounded restart delay, private temporary storage,
  no-new-privileges, and a restrictive umask;
- declares no socket unit, `ListenStream`, `ListenDatagram`, API command, or
  legacy collector flag.

`docs/v1.1-operations.md` documents required variable values and 0600
environment-file permissions, all seeded job kinds/defaults, bounded
coalescing and scheduler state, backoff/circuit/incident/repair behavior,
low-risk versus approval-gated repairs, Psychlo/Quark timer ownership,
disposable-store canary, exact activation/migration/live-verification/
rollback/forensic-preservation steps, and the v1.1 compatibility and
external-project non-mutation boundary. The listed runtime, scheduler,
health, service-monitoring, operator-workflow, and local-API docs now point at
the scheduler-owned behavior and deprecated compatibility route.

## Commit

Implementation commit:

```text
92be49ae40527e6fc0e2e3274ae947f0f60f2a3c Document Overseer v1.1 operations
```

## Changed files

- `systemd/overseer.service`
- `tests/test_collection_systemd.py`
- `docs/v1.1-operations.md`
- `README.md`
- `docs/runtime.md`
- `docs/scheduler.md`
- `docs/live-health-probes.md`
- `docs/service-health-monitoring.md`
- `docs/operator-workflows.md`
- `docs/local-api.md`

## Activation gate and residual risk

This task did not install, copy, enable, start, stop, restart, migrate, or
modify any live unit, store, gateway, service, or external project. The source
unit's interpreter and store expansions require validation with the exact
0600 environment file during the separately approved activation procedure.

Before activation, an administrator must approve an exact plan naming the
reviewed source tree/commit, rendered unit hash, environment-file and store
paths, migration and seed commands, disposable-canary evidence, activation
commands, heartbeat/API/scheduler/timer verification, rollback commands, and
forensic evidence preservation. Psychlo and Quark timer ownership and all
existing approval, IDS, claim, audit, secret, gateway-prefix, and external
project boundaries remain in force.
