# Task 3: Fail-closed VM rehearsal orchestrator

## Outcome

Implemented the inert host-side Phase B rehearsal planner in the isolated
`fix/approval-smoke-v1-1-6` worktree. The tool only reads state during
`preflight` and only renders canonical JSON during `render-plan`; it does not
download an image, create an overlay or ISO, define/start/stop/undefine a
VM, invoke the Phase B launcher, import/execute a package, or modify/restart a
host service.

## TDD evidence

### RED

Command:

```text
pytest -q tests/test_phase_b_rehearsal_tool.py
```

Before implementation, collection failed with eight `FileNotFoundError`
failures for the absent `tools/phase_b_rehearsal.py`. This was the expected
missing-tool failure from the new source-level tests.

### GREEN

The focused suite passed after implementation:

```text
pytest -q tests/test_phase_b_rehearsal_tool.py
.........                                                                [100%]
9 passed in 0.07s
```

The tests cover the pinned image, exact VM shape, read-only source mount,
owner-only future serial log, exact Task 2 placeholders, complete future
command choreography, deterministic plan digest, no subprocess execution in
`render-plan`, and no mutating subprocess surface in injected `preflight`
probes.

## Implementation

- `tools/phase_b_rehearsal.py` — fail-closed read-only preflight, pure plan
  rendering, canonical JSON, SHA-256 plan digest, domain XML, and NoCloud
  placeholder artifact.
- `tests/test_phase_b_rehearsal_tool.py` — source-level RED/GREEN safety and
  contract tests, including the no-temp-directory assertion.
- `docs/phase-b-disposable-rehearsal.md` — operator boundary and verification
  runbook.

The exact pinned image URL and SHA-512 are embedded in the tool and plan.
Preflight rejects dirty source, a mismatched full source SHA, missing KVM,
non-session libvirt, an existing target VM, writable source shares, network
devices, missing or unverified base images, missing tools, and unsafe
temporary or serial paths. It never creates the temporary directory.

The plan digest is the explicit separate approval boundary. Image download,
KVM use, VM lifecycle, and cleanup remain outside this task and require one
exact Dax claim plus approval of that digest. Package import, host service
action, Phase B, and cutover remain excluded.

## Verification record

- Commit message: `Prepare fail-closed Phase B VM rehearsal`
- Focused tests: `pytest -q tests/test_phase_b_rehearsal_tool.py` — `9 passed in 0.07s`
- Compile check: `python3 -B -c '... compile(...)'` — clean, no output
- `git diff --check` — clean, no output
- Preflight: exit `2`, canonical rejection `{"reason":"source tree is dirty","status":"rejected"}`
- Render plan: exit `0`, plan digest
  `4aa0d5aaf98f278b710b511af64edebaedbb7f18b2f9492bbb95c8de615f129a`
- Read-only `virsh --connect qemu:///session list --all` — one pre-existing
  `overseer-dax-disposable-libvirt` in `shut off` state; no new VM appeared

## Limitations

This task provides no proof of guest execution, systemd choreography, KVM
availability, image availability, or live libvirt behavior. Those require a
later independent exact-scope approval of the rendered digest and Dax claim.
