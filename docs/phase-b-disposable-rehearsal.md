# Disposable Phase B rehearsal: inert host preparation

This document describes the host-side preparation implemented by Task 3. It
does not authorize or perform a rehearsal. `tools/phase_b_rehearsal.py` has
two subcommands:

```text
preflight    read-only checks only; it never creates the temporary directory
render-plan  pure canonical JSON rendering; it never runs a subprocess
```

The pinned Debian cloud image is:

```text
https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
SHA-512: 184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003
```

The rendered plan uses `qemu:///session`, VM name
`overseer-phase-b-rehearsal-<source7>`, 2048 MiB, two vCPUs, an 8 GiB qcow2
overlay, no network interface, and disabled autostart. The checkout is a
read-only 9p filesystem tagged `overseer-source`. The future serial log is
created mode `0600` below a newly created `mktemp -d` directory.

The NoCloud artifact contains the six exact empty Task 2 placeholders,
individually owned by `root:root` with mode `0644`:

```text
/etc/systemd/system/overseer-approval-smoke.service
/etc/systemd/system/overseer-api-canary.service
/etc/systemd/system/overseer-admin-executor.socket
/etc/systemd/system/overseer-admin-executor@.service
/etc/systemd/system/overseer-codex-user-bridge.socket
/etc/systemd/system/overseer-codex-user-bridge.service
```

The future command list is descriptive output only. It includes pinned
SHA-512 verification, qcow2 overlay creation, NoCloud seed creation,
transient definition and start, bounded serial wait, exact sentinel
extraction, graceful shutdown, undefine, and removal of only the exact
overlay, seed ISO, serial log, and now-empty temporary directory. It contains
no image download, package import, host-service action, Phase B launcher, or
cutover command.

## Approval boundary

The `planDigest` is SHA-256 over the canonical JSON of the inner `plan`
object. It is a separate, explicit approval boundary: an operator must
approve that exact digest after reviewing the complete rendered plan. The
future image download (if the approved image is not already present), KVM
use, VM definition/start, and temporary-artifact cleanup additionally require
one exact Dax resource claim. Approval of this source implementation or of a
different digest does not authorize those actions.

Package import, host service action, Phase B, and cutover remain explicitly
excluded. No owner-package verifier, token, key, or human secret belongs in
the guest or in the plan.

## Verification

The source-level test suite injects all preflight readers/runners and proves
that rendering cannot execute a subprocess and that preflight's default
runner exposes only read-only Git and libvirt probes. The intended checks are:

```bash
pytest -q tests/test_phase_b_rehearsal_tool.py
python3 -B -s -P tools/phase_b_rehearsal.py preflight --source-commit "$(git rev-parse HEAD)"
python3 -B -s -P tools/phase_b_rehearsal.py render-plan --source-commit "$(git rev-parse HEAD)"
virsh --connect qemu:///session list --all
```

The preflight invocation is expected to reject a dirty checkout or any other
missing precondition. A rejected preflight is evidence of fail-closed
behavior, not permission to continue. Neither command creates a VM or the
future temporary directory.
