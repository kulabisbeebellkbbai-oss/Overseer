# Task 2 report

Status: repaired after independent rejection; live guest rehearsal intentionally not run.

## First implementation

Commit `ef87688` added the initial guest harness. Its original source-level
suite passed 10 tests, but independent review found five Critical, four
Important, and one Minor issue. The first implementation was not accepted.

## Repair scope

The repair replaces optimistic controls with observed-evidence gates and adds:

- exact root/systemd/read-only-mount/network/UID/GID preflight validation;
- production-path rendered units using systemd `LoadCredential=`, the fixed
  Overseer bridge/executor sockets, and UID/GID 984 canary ownership;
- a closed three-store canary handoff and exact runtime socket metadata;
- activation-transition evidence for the socket-activated bridge and executor;
- the real production hidden-input reader driven through `pty.openpty()`;
- inspection of the real SQLite-sibling admin-authority lock created by the API;
- the real API/client, approval verifier, ticket executor, SQLite, and replay
  controls, including wrong-scope and unlisted negative controls;
- production activation-package cleanup, state sealing, and approved rollback
  replay entry points. Only absent owner-package provenance readers are
  adapted inside the disposable guest;
- aggregate stop verification for every disposable unit and UID 984 process;
- durable bounded stage tracking, exact serial output, and guest poweroff on
  every terminal result;
- an outer sandbox with individual writable unit files instead of writable
  access to `/etc/systemd/system`.

## TDD evidence

Repair RED was reproduced in a temporary archive of commit `ef87688` with the
expanded repair matrix copied in:

```text
40 failed, 10 passed in 0.39s
```

The failures covered every independently reported gap: preflight, unit
credentials/paths, handoff, observed controls, real lock, production PTY,
production cleanup/replay, fail-closed stop, stage retention, poweroff, and
the outer sandbox.

Repair GREEN:

```text
50 passed in 0.27s
```

## Checks

- `pytest -q tests/test_phase_b_guest_rehearsal.py`: 50 passed.
- Python compile check for the guest harness and test: passed.
- `systemd-analyze verify` for the outer one-shot unit: passed.
- All six rendered child service/socket units were written to a temporary
  directory and passed `systemd-analyze verify` together.
- `git diff --check`: passed.

## Safety boundary and remaining gate

No VM image was downloaded, no VM was defined or started, no host systemd unit
was changed, no activation package was imported or executed, and no live
staging, canary, cutover, or human verifier secret was used. The production
systemd/UID/socket/cleanup/replay choreography has not yet run under PID 1;
that remains the separately approved disposable-VM rehearsal gate.
