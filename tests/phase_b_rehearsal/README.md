# Disposable Phase B guest rehearsal

`guest_rehearsal.py` is the guest-side half of the disposable Phase B
rehearsal. Importing it is inert. Its `main()` entry point first requires a
root process, systemd as PID 1, a read-only `/mnt/overseer-source` mount, no
up non-loopback interface, and the `overseer` (984) and `god` (1000)
identities. Any failed preflight stops before guest-local provisioning.

The harness uses only throwaway credentials created inside the guest. It
keeps stores, verifier documents, Ed25519 material, rendered units, runtime
sockets, evidence, and rollback state under disposable guest paths. The
source checkout is consumed from `/mnt/overseer-source`; it is never written.

The unit starts the real source API and client path over a Unix socket, the
socket-activated user bridge and root executor, and the UID-984 canary. It
also checks the hidden-input PTY boundary, allowlisted and unlisted executor
controls, quiescent stop, authority-lock creation, evidence sealing, and a
pre-cutover rollback replay. The guest has no network address.

The only serial result is framed exactly as:

```text
OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN
<one canonical JSON object>
OVERSEER_PHASE_B_REHEARSAL_RESULT_END
```

The JSON schema is `overseer.phase-b-disposable-rehearsal.v1`. Its status is
`passed` or `failed`; failures contain only an exception class and bounded
stage. Secret-bearing keys and values are rejected by the serializer.

## Source-level verification

From the repository root, the contract tests import the script by path. They
do not invoke `main()`, systemd, a VM, a socket, or a network operation:

```bash
pytest -q tests/test_phase_b_guest_rehearsal.py
```

## Guest-only installation contract

The later disposable VM orchestrator may copy this script and unit into the
guest, expose the checkout as a read-only 9p mount tagged `overseer-source`,
run `systemctl enable --now guest_rehearsal.service`, collect the serial
sentinels, and let the guest power off. Those operations are intentionally not
performed by this task or by the source-level tests.
