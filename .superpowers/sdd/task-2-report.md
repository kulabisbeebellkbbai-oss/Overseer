# Task 2 report

Status: implementation complete; live guest rehearsal intentionally not run.

## Changed files

- `tests/phase_b_rehearsal/guest_rehearsal.py`
- `tests/phase_b_rehearsal/guest_rehearsal.service`
- `tests/phase_b_rehearsal/README.md`
- `tests/test_phase_b_guest_rehearsal.py`
- `.superpowers/sdd/task-2-report.md`

The guest harness has an inert import boundary, fail-closed root/systemd/
mount/network/identity preflight, guest-local deterministic provisioning,
throwaway credentials and Ed25519 material, rendered socket/service units,
real source API/client invocation hooks, PTY echo restoration, bounded
cleanup/sealing/replay stages, and exact serial-result sentinels. The result
serializer accepts only `passed` or `failed`, the required boolean control set,
bounded identifiers, and bounded exception classes; it rejects secret-bearing
keys and values and revalidates framed records.

## TDD evidence

RED: `pytest -q tests/test_phase_b_guest_rehearsal.py` failed with 8 failures
because the guest module did not yet exist (`FileNotFoundError` at the import
boundary).

GREEN: the focused test passed with `10 passed`.

## Checks

- `python3` compile check for `guest_rehearsal.py`: passed.
- `pytest -q tests/test_phase_b_guest_rehearsal.py`: `10 passed`.
- `systemd-analyze verify tests/phase_b_rehearsal/guest_rehearsal.service`:
  passed.
- `git diff --check`: passed.
- Import-boundary test confirms no process is spawned during module import.

## Limitations and safety boundary

The source-level tests do not start systemd, a VM, sockets, or a network.
No VM image was downloaded, no VM was defined or run, no activation package
was imported or executed, no host service was changed, and no live staging,
canary, cutover, or verifier secret was used. The real guest API/systemd
choreography remains for the separately approved VM rehearsal phase.
