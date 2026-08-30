# Overseer Phase B Disposable Rehearsal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the complete v1.1.6 Phase B choreography in a disposable systemd VM before creating, importing, approving, or executing another host activation package.

**Architecture:** Keep the sealed activation state machine and approval boundaries unchanged. Add bounded JSON progress events around the existing checkpoints, then exercise the real API, root executor, user bridge, UID 984 canary, Unix sockets, systemd credentials, shutdown, lock release, evidence sealing, cleanup, and recovery inside a network-isolated Debian 13 VM. The host-side tooling may prepare and describe the rehearsal, but this implementation phase must not download an image, define or start a VM, import a package, or touch host services.

**Tech Stack:** Python 3.13, pytest, systemd 257, libvirt `qemu:///session`, qcow2 overlays, NoCloud seed ISO, read-only 9p source mount, canonical JSON, SHA-512.

## Global Constraints

- Hold owner package digest `a71f15e25a3b0dce379544381015ee4d8d2c720a5bfae713d498f232287e18ab`; do not import, approve, execute, replace, or mutate it.
- Do not run `/home/god/.local/bin/overseer-approved-phase-b`.
- Do not modify or restart live `overseer.service`, `overseer-api.service`, system units, user units, firewall, routing, VPN, gateway, or another project.
- Do not use the existing empty `overseer-dax-disposable-libvirt` disk as evidence of a systemd rehearsal.
- Use a new transient user-session VM with no network interface and no host-writable filesystem share.
- The source checkout may be exposed to the guest only through a read-only 9p mount.
- Use only throwaway deterministic rehearsal credentials generated inside the guest; never copy owner-package verifiers, API tokens, keys, or human secrets into the VM.
- The guest must use three distinct identities: root runner, UID/GID 984 canary principal, and UID/GID 1000 bridge owner.
- The guest must not execute cutover. A rollback exercise may use only harmless disposable transient units and disposable stores inside the VM.
- Host VM download/start/destroy commands require a separate exact approval after source implementation, tests, and review.
- Every progress record must set `secretValuesRecorded` to `false` and must not contain raw argv, environment values, credentials, tokens, or human input.
- Preserve the current branch and unrelated worktrees. Do not merge, push, prune, or modify another project.

## Observed Failure Matrix

| Terminal stage | Prior repair | Missing proof |
|---|---|---|
| systemd credential read | `9db12c9` | real `LoadCredential=` under UID 984 |
| authorization timeout | `b70dc0c` | real TTY prompt before service lifetime |
| expected unlisted rejection | `6e16d3e` | real API plus socket-activated root executor |
| canary store schema | `9857f57` through `5e18e49` | real copied store opened by the systemd canary |
| post-canary evidence seal | `fb6e670` and `1975b1a` | real authority lock creation, release, and sealing |

---

### Task 1: Add bounded Phase B progress telemetry

**Files:**
- Create: `src/overseer/activation_progress.py`
- Modify: `src/overseer/activation_package.py:7711-7848,8744-9000`
- Test: `tests/test_activation_progress.py`
- Test: `tests/test_activation_package.py:5772-6130,8336-8538`

**Interfaces:**
- Produces: `emit_activation_progress(*, package_digest: str, phase: str, status: str, stage: str, command_index: int | None = None, failure: str | None = None, stream: TextIO | None = None) -> dict[str, object]`.
- Produces: `classify_phase_b_command(command: Sequence[str]) -> str`.
- Consumes: the existing bounded failure classifications and sealed command lists; it does not change runner-state schema or command execution.

- [ ] **Step 1: Write failing progress-schema tests**

Create tests that call the new emitter with a `StringIO`, parse exactly one JSON line, and require this exact key set:

```python
{
    "schemaVersion",
    "packageDigest",
    "phase",
    "status",
    "stage",
    "commandIndex",
    "failure",
    "secretValuesRecorded",
}
```

Require schema `overseer.activation-progress.v1`, a 64-character lowercase hex digest, `secretValuesRecorded is False`, and rejection of unknown phases/statuses, invalid stage names, unbounded failure text, and non-integer command indexes.

- [ ] **Step 2: Run the new tests and verify they fail because the module is absent**

Run:

```bash
pytest -q tests/test_activation_progress.py
```

Expected: import failure for `overseer.activation_progress`.

- [ ] **Step 3: Implement the bounded emitter and command classifier**

Implement the module with the exact public signatures above. Use canonical JSON (`sort_keys=True`, `separators=(",", ":")`) and write to `sys.stderr` when `stream` is omitted. The classifier must return only these stages:

```python
{
    "principal-bootstrap",
    "release-install",
    "credential-install",
    "unit-install",
    "canary-store-stage",
    "staging-verification",
    "systemd-reload",
    "runtime-directory-create",
    "human-authorization",
    "canary-socket-start",
    "canary-service-start",
    "canary-health",
    "canary-acceptance",
    "canary-stop",
    "evidence-seal",
    "cleanup",
    "unknown-sealed-command",
}
```

Do not emit the command itself.

- [ ] **Step 4: Write failing runner-order and secret-exclusion tests**

Extend the delayed-authorization and cleanup tests to capture stderr and assert the ordered subsequence:

```text
phase-started
waiting-for-human-authorization
human-authorization-complete
stage-started
stage-complete
evidence-seal-started
evidence-seal-complete
phase-complete
```

Assert neither throwaway secret appears in the output and every record has `secretValuesRecorded: false`.

- [ ] **Step 5: Instrument existing checkpoints without changing activation semantics**

Emit only after the corresponding durable state write succeeds. Emit `waiting-for-human-authorization` before opening `/dev/tty`, `human-authorization-complete` only after verifier revalidation, command stage events around `_validated_command_outcome`, and seal/cleanup events around the existing sealing and recovery calls. Never swallow an emitter error; convert it to `ActivationPackageError("activation progress could not be emitted")` before any protected service starts.

- [ ] **Step 6: Verify focused telemetry and runner tests**

Run:

```bash
pytest -q tests/test_activation_progress.py tests/test_activation_package.py -k 'phase_bounded or delayed_human or cleanup or evidence_seal or staging_command'
```

Expected: all selected tests pass and no secret appears in captured progress output.

- [ ] **Step 7: Commit telemetry**

```bash
git add src/overseer/activation_progress.py src/overseer/activation_package.py tests/test_activation_progress.py tests/test_activation_package.py
git commit -m "Add bounded Phase B progress telemetry"
```

---

### Task 2: Build the disposable guest rehearsal

**Files:**
- Create: `tests/phase_b_rehearsal/guest_rehearsal.py`
- Create: `tests/phase_b_rehearsal/guest_rehearsal.service`
- Create: `tests/phase_b_rehearsal/README.md`
- Create: `tests/test_phase_b_guest_rehearsal.py`

**Interfaces:**
- Consumes: read-only source at `/mnt/overseer-source` and the checked-out Python runtime selected by the host preflight.
- Produces: one canonical serial-console result with schema `overseer.phase-b-disposable-rehearsal.v1` and status `passed` or `failed`.
- Produces no host files and requires no network.

- [ ] **Step 1: Write failing guest-contract tests**

Import the guest module without running it and require:

```python
REHEARSAL_ROOT == Path("/var/lib/overseer-phase-b-rehearsal")
CANARY_UID == 984
BRIDGE_UID == 1000
REQUIRED_CONTROLS == frozenset({
    "systemdCredentials",
    "secureTty",
    "socketActivation",
    "unixPeerIdentity",
    "apiHealth",
    "usageBridge",
    "sessionBridge",
    "allowlistedRestart",
    "replayNoMutation",
    "unlistedRejected",
    "authorityLockCreated",
    "quiescentStop",
    "evidenceSealed",
    "cleanupStateDurable",
    "rollbackReplay",
})
```

Require its result serializer to reject secret-bearing keys and values.

- [ ] **Step 2: Implement deterministic guest provisioning**

The guest script must fail unless PID 1 is systemd, EUID is root, `/mnt/overseer-source` is a read-only mount, no non-loopback network interface is up, UID/GID 984 resolve to `overseer`, and UID/GID 1000 resolve to `god`. It must create all stores, verifiers, API tokens, Ed25519 keys, allowlists, rendered units, and runtime directories below guest-local `/etc`, `/run`, `/opt`, and `/var/lib` paths.

Use fixed throwaway strings only inside the guest process:

```python
ADMIN_SECRET = "phase-b-rehearsal-admin-secret"
ROADEX_SECRET = "phase-b-rehearsal-roadex-secret"
API_TOKEN = "phase-b-rehearsal-api-token"
```

The final result must contain only booleans and bounded identifiers, never these values.

- [ ] **Step 3: Exercise the real systemd/API path**

Install and start the rendered bridge and executor sockets, hand off the copied canary namespace to UID/GID 984, start the real rendered canary service, validate its Unix socket, and run the real `OverseerApiClient` controls. Only package provenance and installed-package verification may be replaced by test adapters; the API server, client transport, approval verifier, executor socket, SQLite store, authority lock, and systemd unit must remain real.

- [ ] **Step 4: Exercise stop, seal, cleanup, and replay**

Stop every disposable unit, require no UID 984 process remains, acquire the authority lock non-blocking, seal the state directory root-owned mode `0500` and artifacts mode `0400`, then run a second disposable instance through a controlled pre-cutover failure. Require terminal `aborted_before_cutover`, invoke sealed rollback replay, and require the replay to revalidate retained evidence without mutation.

- [ ] **Step 5: Exercise an actual PTY**

Use Python `pty.openpty()` to invoke the hidden-input reader with throwaway input, verify echo is disabled while input is entered and restored afterward, and require the authorization-complete progress record to precede any canary systemd start event.

- [ ] **Step 6: Emit one bounded result and power off**

Write the canonical result to the serial console between exact sentinels:

```text
OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN
<one JSON object>
OVERSEER_PHASE_B_REHEARSAL_RESULT_END
```

On any error, emit only the exception class and last bounded stage, stop all disposable units, and power off.

- [ ] **Step 7: Verify source-level guest tests**

Run:

```bash
pytest -q tests/test_phase_b_guest_rehearsal.py
```

Expected: contract and serializer tests pass without starting systemd or a VM.

- [ ] **Step 8: Commit the guest rehearsal**

```bash
git add tests/phase_b_rehearsal tests/test_phase_b_guest_rehearsal.py
git commit -m "Add disposable Phase B guest rehearsal"
```

---

### Task 3: Prepare the fail-closed VM orchestrator

**Files:**
- Create: `tools/phase_b_rehearsal.py`
- Create: `tests/test_phase_b_rehearsal_tool.py`
- Create: `docs/phase-b-disposable-rehearsal.md`

**Interfaces:**
- Produces inert commands and cloud-init artifacts only; no subcommand in this task may start, define, download, delete, or mutate a VM.
- Pins official image URL `https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2`.
- Pins SHA-512 `184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003`.

- [ ] **Step 1: Write failing preflight and command-plan tests**

Require `preflight` to reject a dirty tree, a source commit other than the requested full SHA, a missing KVM device, a non-user libvirt URI, an existing target VM, a writable source-share specification, any network device, or an unverified base image. Require `render-plan` to emit canonical JSON without running subprocesses.

- [ ] **Step 2: Implement inert `preflight` and `render-plan` subcommands**

The command plan must use:

```text
libvirt URI: qemu:///session
VM name: overseer-phase-b-rehearsal-<source7>
memory: 2048 MiB
vCPUs: 2
overlay capacity: 8 GiB
network: none
autostart: disabled
source mount: read-only 9p tag overseer-source
serial log: owner-only file under a fresh mktemp directory
```

It must define explicit future commands for checksum verification, qcow2 overlay creation, NoCloud ISO creation, transient VM definition/start, bounded wait, serial-result extraction, graceful shutdown, undefine, and deletion of only the exact temporary overlay/seed/log directory. This task must not execute those commands.

- [ ] **Step 3: Document the separate approval boundary**

The runbook must state that image download, VM definition/start, KVM use, and temporary-file cleanup require one exact Dax resource claim plus explicit user approval of the rendered plan digest. It must state that package import, host service action, Phase B, and cutover remain excluded.

- [ ] **Step 4: Verify host tooling remains inert**

Run:

```bash
pytest -q tests/test_phase_b_rehearsal_tool.py
python3 -B -s -P tools/phase_b_rehearsal.py preflight --source-commit "$(git rev-parse HEAD)"
python3 -B -s -P tools/phase_b_rehearsal.py render-plan --source-commit "$(git rev-parse HEAD)"
virsh --connect qemu:///session list --all
```

Expected: tests pass, the tool reports or renders only, and no new VM exists.

- [ ] **Step 5: Commit the inert host tooling**

```bash
git add tools/phase_b_rehearsal.py tests/test_phase_b_rehearsal_tool.py docs/phase-b-disposable-rehearsal.md
git commit -m "Prepare fail-closed Phase B VM rehearsal"
```

---

### Task 4: Verify and independently review the source implementation

**Files:**
- Modify only if required by review: files from Tasks 1-3
- Verify: repository tests, static unit validation, plan safety, and worktree cleanliness

- [ ] **Step 1: Run focused rehearsal tests**

```bash
pytest -q tests/test_activation_progress.py tests/test_phase_b_guest_rehearsal.py tests/test_phase_b_rehearsal_tool.py
```

- [ ] **Step 2: Run activation and systemd regression suites**

```bash
pytest -q tests/test_activation_package.py tests/test_admin_approval_acceptance.py tests/test_admin_authority.py tests/test_dedicated_principal_systemd.py
```

- [ ] **Step 3: Run the complete suite and source checks**

```bash
pytest -q
python3 -m compileall -q src tests tools
git diff --check
git status --short
```

- [ ] **Step 4: Request implementation review**

Use a fresh `gpt-5.6-terra` reviewer. Require explicit findings for progress-secret leakage, progress/checkpoint ordering, real-vs-mocked rehearsal boundaries, network isolation, host path safety, VM name/path validation, cleanup blast radius, and package/live-action exclusion.

- [ ] **Step 5: Request final security review**

Use `gpt-daybreak-blue-latest`, with `gpt-5.6-terra` only as fallback. Require explicit review of guest-root escape risk, writable mounts, libvirt scope, network absence, credential provenance, serial-output redaction, symlink/hardlink races, subprocess command construction, and exact cleanup targets.

- [ ] **Step 6: Resolve every Critical or Important finding test-first and rerun Steps 1-3**

Expected: zero unresolved Critical or Important findings and a clean worktree after reviewed commits.

---

### Task 5: Prepare, but do not execute, the privileged rehearsal approval

**Files:**
- Create at runtime only: one Overseer Dax claim and one rendered owner-readable approval package containing the exact source commit, image SHA-512, plan digest, VM name, paths, commands, stop conditions, and cleanup targets.

- [ ] **Step 1: Record the exact Dax resource claim**

Claim only the user-session libvirt VM name, KVM execution slot, base-image cache path, and bounded temporary storage. Do not request package import or service authority.

- [ ] **Step 2: Render and independently verify the command plan**

Run `render-plan` twice and require byte-identical canonical output and an identical SHA-256 plan digest.

- [ ] **Step 3: Stop for explicit approval**

Present the exact plan digest, image checksum, VM resource limits, no-network assertion, source commit, expected controls, stop conditions, and cleanup targets. Do not download, define, start, console into, stop, undefine, or delete the VM until the user approves that exact plan.

