# Disposable Phase B guest rehearsal

`guest_rehearsal.py` is the guest-side half of the disposable Phase B
rehearsal. Importing it is inert. Its `main()` entry point first requires a
root process, systemd as PID 1, a read-only `/opt/overseer-source` mount, no
up non-loopback interface, and the `overseer` (984) and `god` (1000)
identities. Any failed preflight stops before guest-local provisioning.

The harness uses only fixed throwaway credentials created inside the guest.
The canary receives the API token, both scoped verifier documents, and the
admin-ticket private key through systemd `LoadCredential=`. The rendered
units use Overseer's production Unix paths under `/run/overseer` and
`/run/overseer-canary`. The copied canary namespace is handed to UID/GID 984
before startup; the root executor state remains under
`/var/lib/overseer-executor`. The guest consumes a tracked-only source archive
from the read-only NoCloud ISO. Cloud-init verifies its manifest, archive
digest, exact entries, modes, sizes, and per-file hashes before extracting it
to `/opt/overseer-source` and bind-remounting that tree read-only. Ignored
files, bytecode caches, secrets, `.git`, and linked-worktree pointers are not
included. Cloud-init separately supplies the already validated,
plan-digest-bound 40-character source commit in a root-owned, single-link,
mode-`0444` artifact. The outer unit makes both inputs read-only, and the guest
receives a private mode-`0400` systemd `LoadCredential=` copy. It
verifies the copy's inode, ownership, mode, link count, size, and identity
before provisioning.

The unit starts the real source API and client path over a Unix socket, the
socket-activated user bridge and root executor, and the UID-984 canary. It
observes loaded credential files, exact socket identity, and bridge/executor
activation transitions before those controls can pass. It invokes the
production hidden-input reader through a PTY, checks the real SQLite-sibling
admin-authority lock created by the API workflow, then starts a second canary
service instance, confirms its health, and makes it encounter a deterministic
missing-plan API failure before cutover. The exact bounded rejection is
recorded before cleanup. Cleanup,
evidence sealing, durable terminal state, and rollback replay delegate to
the production `overseer.activation_package` entry points. Only the absent
owner-package provenance readers are replaced by guest-local adapters; the
cleanup commands, systemd quiescence, state sealing, runner state, activation
lock, and replay implementation remain production code. The guest has no
network address.

Fail-closed cleanup inventories every bounded
`overseer-admin-executor@*.service` instance created by the `Accept=yes`
socket, stops it after the listening socket is closed, and rechecks both the
static units and accepted instances before cleanup-needed state can clear.

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

Before this outer sandbox starts, cloud-init must create these exact empty,
root-owned `0644` placeholders:

```text
/etc/systemd/system/overseer-approval-smoke.service
/etc/systemd/system/overseer-api-canary.service
/etc/systemd/system/overseer-admin-executor.socket
/etc/systemd/system/overseer-admin-executor@.service
/etc/systemd/system/overseer-codex-user-bridge.socket
/etc/systemd/system/overseer-codex-user-bridge.service
```

Cloud-init must also create
`/etc/overseer-phase-b-rehearsal/source-commit` as a root-owned, mode-`0444`
file containing the exact host-validated source SHA and one newline. It is
input data, not a writable placeholder or credential.

The sandbox grants write access to those files individually, never to the
whole systemd unit directory. The harness rejects non-empty, linked,
non-regular, incorrectly owned, or incorrectly mode-set placeholders before
filling them.

The later disposable VM orchestrator may install those placeholders, include
the deterministic source and bounded runtime archives on the NoCloud ISO, run
the outer one-shot unit, collect the serial sentinels through a bounded pipe,
and let the guest power off. It does not expose a live host checkout or runtime
filesystem. Those operations are intentionally not performed by this task or
by the source-level tests.
