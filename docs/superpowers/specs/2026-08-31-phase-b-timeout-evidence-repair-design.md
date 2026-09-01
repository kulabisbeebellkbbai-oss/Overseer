# Phase B Timeout and Diagnostic Evidence Repair Design

## Goal

Repair the disposable Phase B rehearsal so host boot time cannot consume the
guest service's execution budget, and retain one bounded, secret-free timeout
record after owned VM cleanup removes the raw serial artifacts.

This change is source and package preparation only. It does not authorize or
perform package import, VM lifecycle, rehearsal execution, host service
changes, Phase B, or cutover.

## Root cause

The current future launcher starts a 960-second host result timeout immediately
after `virsh start`. The guest service starts only after boot, cloud-init,
artifact verification and extraction, identity provisioning, unit install, and
`daemon-reload`; the service then has its own 15-minute systemd start timeout.
The host can therefore terminate a healthy-but-slow guest before the guest's
own deadline. After an owned shutdown and undefine, cleanup deletes the raw
serial log and status, so the terminal guest stage is unavailable for triage.

The observed QEMU log showed normal startup and a host-requested SIGTERM
shutdown, which is consistent with this deadline inversion and not a guest or
QEMU crash.

## Deadline model

Use independent sequential deadlines:

| Boundary | Budget | Starts | Purpose |
| --- | ---: | --- | --- |
| Boot/service entry | 600 seconds | after `virsh start` | bound boot, cloud-init, extraction, and unit dispatch |
| Guest watchdog | 780 seconds | at guest Python entry | emit a bounded failed result before systemd kills a stalled guest |
| Guest systemd hard stop | 900 seconds | at service entry | final guest process containment |
| Host result wait | 1020 seconds | after a fixed service-entry marker | allow the guest hard stop plus bounded serial propagation |
| Owned shutdown | 120 seconds | cleanup | bound the normal graceful VM shutdown wait |

The guest watchdog precedes the systemd hard stop by 120 seconds. The host
result wait exceeds the systemd hard stop by 120 seconds. The configured phase
deadline budget is 1740 seconds (29 minutes): 600 seconds boot, 1020 seconds
result, and 120 seconds shutdown. This is not a hard wall-clock maximum:
fail-closed libvirt ownership probes, bounded collector sealing, evidence
publication, and recovery handling add control-plane overhead outside those
three phase deadlines.

The fixed service-entry marker is timing evidence only. It cannot satisfy the
existing passing-result contract.

## Serial protocol

The guest unit emits this exact fixed line immediately before starting the
Python rehearsal:

```text
OVERSEER_PHASE_B_REHEARSAL_SERVICE_STARTED
```

Each `StageTracker.advance` emits one canonical progress line:

```text
OVERSEER_PHASE_B_REHEARSAL_PROGRESS {"schemaVersion":"overseer.phase-b-rehearsal-progress.v1","secretValuesRecorded":false,"stage":"<allowlisted-stage>"}
```

Only the existing bounded result stages are accepted. Progress contains no
command, path, argv, environment, exception text, credential, verifier, token,
or human input. The collector publishes a private readiness record before VM
definition, then enforces a phase machine: the service marker must precede
every progress or result sentinel, and it may occur only once. Marker-prefix
variants, pre-marker progress, and pre-marker result framing fail closed. The
collector stores only the last valid canonical progress record in a dedicated
mode-0600 status artifact while retaining its existing bounded raw serial log
and terminal result status. The host checks the exact collector child during
both waits and requires a bounded clean collector seal before accepting
completion. If the collector cannot be cleanly reaped within its stop budget,
cleanup returns without an unbounded wait and retains the exact artifacts and
execution lock for explicit recovery.

The passing contract remains unchanged: a run passes only after the existing
collector reaches `complete`, the owned VM is inactive and absent, the
collector still reports `complete`, and the existing streaming validator
accepts exactly one canonical passing result frame. A start marker, progress
record, late frame, failed frame, malformed record, duplicate frame, or
overflow never passes.

## Timeout evidence

On a boot or result timeout, cleanup derives one canonical record from only
bounded launcher state and the last collector-validated progress record. Raw
serial and arbitrary error text never enter it.

The exact key set is:

```text
schemaVersion
status
failure
runId
vmName
sourceCommit
serviceStarted
resultStatus
lastStage
domainAbsent
rawSerialRetained
secretValuesRecorded
```

The schema is `overseer.phase-b-rehearsal-timeout-evidence.v1`; status is
`failed`; failure is `boot-timeout` or `result-timeout`; result status is
`absent`, `complete`, or `overflow`; the optional last stage must be one of the
allowlisted guest result stages. `domainAbsent` must be true,
`rawSerialRetained` must be false, and `secretValuesRecorded` must be false
before the record receives its final name.

Evidence is written under the caller-owned mode-0700 directory
`/home/god/.local/share/overseer/phase-b-rehearsal-evidence`. The writer opens
directories without following links and reads status children relative to one
pinned temporary-directory descriptor. Before raw cleanup it creates and
fsyncs a mode-0600 hidden pending record that accurately reports
`raw-cleanup-pending` and raw retention, then returns a bounded attestation of
the root and pending-file identities plus the final-record digest. After
confirmed owned-domain absence, exact raw cleanup, and verified temporary-path
absence, publication revalidates those identities, writes and fsyncs a new
private `raw-cleanup-complete` record, atomically replaces the hidden pending
name, rechecks target-domain absence, and creates the exact final
`<run-id>.json` without overwrite. It never truncates the only recovery record
in place. A final-publication failure therefore leaves either the prior valid
pending record or the valid completed replacement instead of silently losing
both raw and sanitized diagnostics. An existing destination, root or hidden
replacement, unsafe status metadata, malformed progress, unknown domain state,
incomplete raw cleanup, or write failure fails closed.

Successful runs produce no timeout evidence. If domain ownership or state
cannot be confirmed, existing behavior remains: do not mutate the domain and
retain the exact temporary artifacts for separately approved recovery.

## Guest watchdog

The guest installs a process-local alarm only in `main`, after argument parsing
and before `_run_rehearsal`. Expiry raises a dedicated bounded exception on the
main thread; the existing error path attempts disposable-unit cleanup and emits
one failed canonical result using the tracker's last allowlisted stage. The
alarm is cancelled and the prior signal handler restored on every return path.
Import remains inert, and tests never start an alarm merely by importing the
module.

## Required verification

- Prove the old single-clock contract fails the new deadline-order tests.
- Prove the marker and progress protocols reject malformed, unbounded, and
  secret-bearing content.
- Prove a delayed boot may consume its boot budget without reducing the result
  budget.
- Prove boot timeout and result timeout are classified separately.
- Prove timeout cleanup retains only canonical sanitized evidence and removes
  raw serial artifacts after confirmed domain absence.
- Prove unknown ownership/state retains artifacts and performs no mutation.
- Prove successful and overflow result behavior remains fail closed.
- Run focused guest/tool tests, the full repository suite, ordinary review,
  and final security review before preparing a replacement package.
