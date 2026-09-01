# Disposable Phase B rehearsal: inert host preparation

The rehearsal tool prepares evidence and renders a separately approved future
VM run. Both `preflight` and `render-plan` are read-only. Neither subcommand
downloads an image, creates an overlay or ISO, defines or starts a VM, imports
or executes a package, invokes Phase B, or changes a host service.

The image remains pinned to:

```text
URL: https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
SHA-512: 184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003
```

## v11 timing and timeout evidence

The rendered future script uses independent, bounded phases. The boot budget
starts immediately after the owned domain is started and waits only for the
exact guest service-entry marker. The result budget starts only after that
marker has been accepted and waits only for the collector's terminal result
status.

```text
boot wait:     600 seconds
result wait:  1020 seconds
shutdown:      120 seconds
configured phase deadline budget: 1740 seconds (29 minutes)
collector readiness: 30 seconds
collector stop:      10 seconds
evidence helper:      10 seconds
guest watchdog:      780 seconds
systemd hard stop:   900 seconds
```

The 1740-second/29-minute configured phase deadline budget is derived from
600 + 1020 + 120. It is not a hard wall-clock maximum: bounded control-plane cleanup overhead
is additional. Legacy virsh and filesystem `fsync` work is
not claimed to fit inside that 29-minute budget. The guest watchdog is shorter
than the systemd hard stop, and both are before the result deadline.

The fixed marker is timing evidence only. A marker never represents a passing
rehearsal. The canonical progress record is also diagnostic evidence only and
cannot satisfy result validation. A passing run still requires the unchanged
canonical result frame, terminal `complete` status, post-shutdown collector
validation, and every existing control.

The operator-facing timeout messages identify the phase:

```text
bounded rehearsal boot wait expired
bounded rehearsal result wait expired
serial output exceeded the bounded limit during boot
serial output exceeded the bounded limit during result
```

The first two messages set the timeout failure class to `boot-timeout` or
`result-timeout`. An overflow, malformed marker/progress record, invalid
terminal status, duplicate service marker, or late overflow fails closed and
is not converted into a passing result.

When and only when the owned domain has been authoritatively confirmed absent,
a timeout run prepares one bounded canonical record under:

```text
/home/god/.local/share/overseer/phase-b-rehearsal-evidence/<run-id>.json
```

The directory is mode `0700` and the final record is mode `0600`; evidence is
bounded to 2048 bytes. Preparation reads the exact status children through one
validated temporary-directory descriptor, then writes the hidden
`.run-id.pending.json` record exclusively and durably. That pending record has
schema `overseer.phase-b-rehearsal-timeout-pending.v1`, state
`raw-cleanup-pending`, and `rawSerialRetained: true`, and binds the evidence
root device/inode, pending-file device/inode, exact temporary-directory
device/inode, complete descriptor-verified child count and inventory digest,
and final-record digest.

Preparation also returns a canonical, maximum-1024-byte launcher-memory
attestation with schema
`overseer.phase-b-rehearsal-timeout-attestation.v1`. It binds the evidence-root
and pending-file identities, the SHA-256 of the exact pending bytes, and the
temporary-directory identity and inventory digest. The launcher keeps that
value only in its running process. Exact raw removal must consume the prepared
attestation and returns a successor attestation for the completed hidden
record; final publication and bounded recovery must consume that successor.
Consequently, a same-UID process cannot replace a hidden record with a new
self-consistent object and continue the in-flight transition. If the launcher
process loses its attestation, automatic publication stops and the remaining
hidden record requires explicit manual recovery.

After all fixed artifacts are finalized and before collector launch or domain
definition, the launcher stores a
second bounded in-memory attestation of the temporary directory and stable
device/inode/type/owner/link identities of the complete fixed raw-artifact set,
including `serial.log`, collector files, disk and seed images, manifests,
archives, and domain/cloud-init inputs. Preparation requires those same
identities while it captures the complete cleanup inventory. Only the
collector-ready, service-entry, terminal-status, progress, and empty
stop-control children are stage-dependent or non-diagnostic. A required child renamed, removed, or
replaced before preparation therefore prevents any cleanup attestation or final
evidence publication.

The launcher precreates the mode-`0600` serial log before sealing this identity.
The collector opens that exact existing safe object without truncation or
replacement and must match the sealed device/inode before it publishes
readiness. A rename, decoy, or ABA swap after the seal is therefore rejected
either by the collector or by preparation and cannot leave an escaped
descriptor receiving guest output while final evidence is published.

Raw serial and temporary files are pinned and removed relative to the exact
attested temporary-directory descriptor. Every child must have the exact safe
type, owner, mode, and single-link identity; each open descriptor must report
the same metadata and inventory digest captured during preparation, and each
open descriptor must report zero links after unlink. A child renamed or
hardlinked out after preparation therefore prevents completed evidence. The
directory is removed only after its parent entry
still matches the attested device/inode, and the held directory descriptor must
then report zero links. A rename or replacement therefore fails closed and
cannot produce a final record while the original raw directory survives.
Domain absence is revalidated immediately before publication. Publication
reopens and reattests the evidence root and pending file, writes and fsyncs a
new private `raw-cleanup-complete` record with `rawSerialRetained: false`, then
atomically replaces the hidden pending name. It never truncates the only
recovery record in place. The completed staging record must byte-semantically
equal the deterministic transformation of the independently revalidated
pending record; self-consistent but altered staging fields are rejected.
Publication then uses an exclusive no-overwrite link
for the final exact record. A collision, identity change, malformed
status/progress, unsafe metadata, incomplete cleanup, or any
write/link/fsync/unlink failure fails closed while retaining either the prior
valid pending record or the valid completed hidden replacement. A completed
staging sibling is accepted only inside the same removal invocation that just
verified exact descriptor-based cleanup. A later invocation with an absent
temporary path and a still-pending hidden record always requires explicit
manual recovery; same-UID staging content is never treated as proof of prior
deletion. A changed or unknown target-domain state produces no final record.

The timeout record schema is
`overseer.phase-b-rehearsal-timeout-evidence.v1` and its exact fields are:

```text
schemaVersion,status,failure,runId,vmName,sourceCommit,serviceStarted,
resultStatus,lastStage,domainAbsent,rawSerialRetained,secretValuesRecorded
```

`status` is always `failed`; `failure` is `boot-timeout` or
`result-timeout`; `resultStatus` is `absent`, `complete`, or `overflow`; and
`lastStage` is null or an existing allowlisted guest stage. The record always
sets `domainAbsent` to true, `rawSerialRetained` to false, and
`secretValuesRecorded` to false. It never contains raw serial, QEMU output,
paths, argv, environment, exception text, credentials, tokens, verifier
values, or human input. Successful runs create no timeout-evidence directory
or record. Unknown ownership/state retains the exact raw artifacts and creates
no timeout evidence.

## Read-only preflight

Preflight fails closed unless:

- the repository is clean and its full SHA is the requested commit;
- `/dev/kvm` is a caller-accessible character device;
- `qemu:///session` reports the expected x86-64 KVM capabilities and the
  collision-resistant target VM name is absent;
- source, runtime, image, and temporary-parent paths have conservative
  absolute names, safe object types, safe permissions, and required access;
- `--owner-thread` is one canonical full conversation UUID appearing exactly
  once in the safe, caller-owned Codex projects CSV, and that row's project is
  exactly `--owner-project`; the command and launcher must encode that exact
  UUID, and the owner project must be its exact registered worktree top level
  in the same Git common directory as the rehearsed source. Repository probes
  are anchored to no-follow directory descriptors, require both supplied paths
  to be exact Git worktree top levels, bind device/inode identities for both
  roots and their common directory, securely reopen those paths after probing, and re-attest
  both identities after every pathname-based source read. Aliases,
  absent or duplicate rows, project rebinding, malformed CSV, linked path
  components, pathname replacement, group/other-writable registries, and
  canonical-equivalent UUID aliases such as uppercase or braced forms fail
  closed;
- preflight itself is descended from exactly one Codex process whose complete
  argv is `codex resume <owner-thread> --cd <owner-project>`; the executable's
  canonical `/proc` path, device/inode identity, and SHA-256 are captured from
  the stable process ancestry and added to the owner binding;
- the exact caller session runtime directory is `/run/user/<caller-uid>`, is a
  non-linked directory owned by that caller with mode `0700`, and is bound to
  every libvirt probe and the separately approved execution as
  `XDG_RUNTIME_DIR`;
- every host tool exists at its exact `/usr/bin` path as a root-owned regular,
  single-link, non-group/other-writable executable;
- the pinned image checksum and qcow2 metadata pass, and the base is a leaf
  image with no backing file;
- a deterministic source manifest covers only NUL-delimited Git-tracked,
  single-link regular files and remains within the source file/byte bounds;
- a deterministic runtime manifest covers only the `cryptography` package and
  selected `_cffi_backend` extension, excluding links, `__pycache__`, and
  bytecode, within its independent bounds; and
- `/usr/bin/python3.13 -B -s -P -S` imports the four required modules through a
  manifest-enforcing finder. Manifest and import reads pin safe root directory
  descriptors and open every relative directory and file component with
  `O_NOFOLLOW`, revalidate stable descriptor metadata, mode, size, and SHA-256,
  then compile those verified bytes directly. Native loaders copy the exact
  verified bytes
  into a sealed anonymous file, then create and execute the extension from that
  immutable descriptor, closing the path-reopen race. Module origins are
  classified by their lexical manifest path before any symlink resolution, so
  a replaced manifest path reaches the `O_NOFOLLOW` verifier and cannot escape
  to Python's original loader. The probe redirects `sys.pycache_prefix` to an
  inaccessible location, so ignored adjacent bytecode is not eligible.

Every probe uses an absolute executable and this exact minimal environment:

```text
LANG=C
LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
PYTHONDONTWRITEBYTECODE=1
PYTHONNOUSERSITE=1
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_NOSYSTEM=1
GIT_OPTIONAL_LOCKS=0
GIT_TERMINAL_PROMPT=0
XDG_RUNTIME_DIR=/run/user/<caller-uid>
```

`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PYTHONHOME`, `BASH_ENV`, and
the caller's command lookup do not enter a preflight child. Every Git command
also supplies `--no-optional-locks`, disables `core.fsmonitor`, and disables
the untracked cache so repository configuration cannot execute an fsmonitor
helper or refresh the index during the read-only probe.

## Immutable host-to-guest handoff

The v11 plan has no host filesystem share. It binds canonical source and runtime
manifests, their SHA-256 digests, deterministic stored-ZIP digests, the runtime
probe, KVM capability probe, source commit, exact owner attestation, domain XML,
cloud-init, and future script under `planDigest`. The owner attestation contains
the exact conversation ID, project, owner top-level, source worktree, common Git
directory, their device/inode identities, authoritative registry path, command,
launcher, registry and launcher device/inode identities, complete registry and
launcher digests, the exact Codex process argv plus executable path,
device/inode identity and digest, canonical row digest, and self-digest.
`render-plan` accepts that preflight output as `--owner-binding-json`, verifies
all digests, securely rereads the authoritative registry without following any
path symlink, re-probes the owner/source Git identity, and requires a
byte-equivalent reconstruction of the binding. It does not run KVM, libvirt,
VM, service, package, or activation operations.

The separately approved future script first reconstructs the exact registry,
launcher, owner-project, source-root, common-Git, commit, cleanliness, and
tracked-inventory evidence. Reconstruction includes strict CSV parsing of one
canonical UUID row, the canonical row digest, the launcher's exact complete
token vector, every owner-binding field, and a byte-equivalent binding digest.
It then walks its stable `/proc` parent chain and
requires both the exact registered tmux pane PID and exactly one intervening
Codex process with the bound executable identity, digest, and complete
`resume` argv. Borrowing or reopening that pane's TTY from another process is
insufficient because the foreign process is not descended from the pane and
owner Codex process. The script then revalidates the private caller runtime
directory before installing its lock or contacting libvirt. Running it from
another thread, launcher, terminal, or non-interactive process fails closed.
Every process PID, parent PID, start time, command line, executable path, and
executable identity is reread for stability during that invocation. The
future validator snapshots the complete chain, reads the exact session pane
set with stable tmux session, window, and pane IDs plus PID and TTY, repeats
both snapshots, and requires exact equality before authorization; ancestor
exit, PID reuse, or pane recreation therefore fails closed. PIDs are
intentionally not preserved from preparation: execution is a later,
separately approved phase, and a legitimate restart may recreate the exact
registered session while resuming the same bound conversation. Any additional
Codex executable in the execution ancestry, even with different argv or a
different installed version, fails closed.
It reruns the manifest-enforced import probe and builds both ZIP files using
`O_NOFOLLOW`, descriptor metadata checks, per-file size/hash checks, and
deterministic ZIP metadata. A changed, linked, hard-linked, added, or omitted
artifact file fails before VM definition. Ignored bytecode, `.git`, and local
secret files never enter the tracked source manifest.

`/usr/bin/genisoimage` writes these exact NoCloud ISO entries:

```text
user-data
meta-data
source.zip
runtime.zip
source-manifest.json
runtime-manifest.json
```

Cloud-init mounts `LABEL=cidata` read-only. Its extractor verifies each manifest
digest, archive digest, exact entry inventory, safe relative path, regular-file
type, mode, size, and hash before extraction. It rejects extras, links, path
traversal, and replacement. Source is extracted to `/opt/overseer-source` and
bind-remounted read-only. Runtime is extracted to the guest's local Python 3.13
site directory and independently bind-remounted read-only. The live host
checkout and runtime remain unmounted. Before systemd starts, Python 3.13 must
prove the `cryptography` and `_cffi_backend` origins are under the extracted
runtime and all Overseer origins are under the extracted source. The outer and
child units pin `/usr/bin/python3.13 -B -s -P -S` and both exact import roots,
so system site-packages, `.pth`, `sitecustomize`, and user sites are ineligible.
Every host-side embedded Python helper, including archive construction,
ownership validation, serial collection, and result validation, uses the same
`-S` isolation.

## Owned VM lifecycle

The plan derives a collision-resistant VM name, UUID, and 64-character run ID
from the full source identity and both artifact manifest digests. Domain XML
contains the UUID and a namespaced immutable run marker. It contains only:

- the exact temporary qcow2 overlay;
- the exact read-only NoCloud ISO;
- no network interface or graphics device; and
- a pipe-backed serial device.

The future script acquires an atomic per-user rehearsal lock and never removes a
stale or foreign lock. Before start, shutdown, or undefine, it requires the lock
marker and parses `virsh dumpxml` to revalidate the exact name, UUID, sole run
marker, disk types/drivers/targets, overlay, ISO, serial pipe/console, and a
strict domain and device whitelist. The validator accepts only the exact memory,
CPU, boot, feature, power, emulator, controller, input, audio, balloon, disk,
serial, and console forms rendered by the plan or deterministically added by
this libvirt/QEMU version. That normalization may add one exact
`<model name="isa-serial"/>` child below the owned serial target and may
represent the serial console as an exact `pipe` console whose source remains
the approved serial-pipe path. The rendered inactive `pty` console remains
valid, and an active generated `/dev/pts/<number>` console remains valid only
when its source exactly matches the console's duplicated `tty` attribute. It
rejects non-whitespace XML mixed content and permits no generated alias or
address below the exact pipe console. It permits only bounded generated alias
and address metadata below the other approved devices. While the domain is
active, it also permits only the exact detected qcow2 backing chain from the
overlay to the pinned leaf base image. Both active attestations are mandatory
whenever libvirt supplies a runtime domain ID.
Across inactive and active ownership attestations, the validator accepts the
rendered EFI form or only the exact state-independent libvirt canonicalization
observed immediately after definition: the two ordered disabled firmware
features `enrolled-keys` and `secure-boot`, `format='raw'` on the loader, and
`templateFormat='raw' format='raw'` on NVRAM. Mixed, reordered, enabled,
extended, or differently formatted EFI forms are rejected.
Filesystem shares,
interfaces, host devices,
channels, QEMU command-line extensions, custom kernels, security-label changes,
host CPU passthrough, disk authentication, duplicate disks, changed disk
attributes, and every other unapproved element are rejected. A missing lock,
same-name foreign domain, UUID/metadata/device mismatch, or unknown libvirt
state prevents mutation and retains artifacts for an explicitly approved
recovery. Cleanup mutates only an owned domain reported as running, in
shutdown, or shut off; paused, crashed, suspended, blocked, and every other
unexpected state are retained without shutdown or undefine.

The temporary persistent domain has autostart disabled and verified before
start. Cleanup uses graceful shutdown, confirms inactivity, undefines only the
owned domain, confirms authoritative absence, and then removes only the
enumerated files in the validated temporary directory. It never recursively
deletes and never touches the base image or source/runtime origins.

## Bounded serial evidence

The serial device writes through a FIFO pair to a dedicated collector. After
FIFO and log setup, the collector publishes one mode-`0600` `collector-ready`
status. The future script waits for that status, and checks the exact collector
child liveness during readiness, boot, and result waits, before it defines or
starts the VM.

The collector continuously drains the pipe, stores no more than 1 MiB, enforces
a 64 KiB line bound, and upgrades a previously seen completion to overflow if
later data crosses either bound. Before the exact line
`OVERSEER_PHASE_B_REHEARSAL_SERVICE_STARTED`, exact-prefix progress, result
begin/end, and marker-prefix variants are overflow. Unrelated nearby lines
remain ordinary bounded serial output. The exact marker publishes the exact
`service-started` status once; a duplicate marker fails closed. Progress and
result framing are accepted only after that marker. Lines that begin with
`OVERSEER_PHASE_B_REHEARSAL_PROGRESS` must contain one canonical JSON record
with schema `overseer.phase-b-rehearsal-progress.v1`, the exact three-field key
set, `secretValuesRecorded: false`, and an allowlisted stage. The collector
publishes only the last such canonical progress record. A fixed marker or
progress record is timing/diagnostic evidence only and is never a passing
result.

Collector death or readiness failure is distinct from a boot/result timeout and
creates no timeout evidence. Collector stop is bounded to 10 seconds and must
reap a clean child exit before a complete result is accepted. A timeout or
unclean collector exit returns without an unbounded `wait`, retains the exact
temporary artifacts and execution lock, and requires explicit recovery.
The collector is bound once by PID and `/proc` start time, while subsequent
liveness checks and TERM/KILL requests open a pidfd, revalidate that start
identity, and signal only through the pidfd. PID reuse or identity mismatch
retains artifacts and the lock without signaling the unrelated process.
Shutdown is attempted before waiting on a collector so guest chatter cannot
block owned VM cleanup.

After the owned VM is inactive, a streaming validator rereads the collector's
terminal status and requires it still be `complete`, then requires exactly one
begin/end pair framing one canonical JSON line.
It rejects over-limit output, oversized lines, duplicate or flooded sentinels,
invalid UTF-8, incomplete frames, noncanonical JSON, missing controls, failure
state, and secret markers. It never reads the complete serial file into memory.

## Guest installation contract

Cloud-init disables default users, creates exact `overseer` UID/GID 984 and
`god` UID/GID 1000 identities, verifies Python 3.13 and all required imports,
installs the guest rehearsal and outer unit from the extracted source, creates
the six exact empty root-owned child-unit placeholders, reloads systemd, and
starts only the guest-local outer one-shot. The source commit is delivered as a
root-owned mode-`0444` file and then as a private systemd credential.

## Approval boundary and exclusions

Image download, KVM use, VM definition/start, and exact temporary-file cleanup
require one exact Dax resource claim plus explicit approval of the rendered
`planDigest`. The safe launch form is the plan's `executionCommand`, which uses
`/usr/bin/env -i` and `/usr/bin/bash`.

Approval of this source, an older plan, or a different digest is not execution
authority. Package import, host service action, the Phase B launcher, Phase B,
and cutover remain excluded.

Preparing a successor lease or transition file does not submit a claim, dispatch
a continuation, release or activate any claim, or authorize VM lifecycle. Every
successor owner field must equal the exact conversation ID already bound under
the replacement plan digest.

## Source-only verification

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_phase_b_rehearsal_tool.py
python3 -B -c 'from pathlib import Path; compile(Path("tools/phase_b_rehearsal.py").read_text(), "tools/phase_b_rehearsal.py", "exec")'
git diff --check
```

The rendered future script may be sent to `bash -n` for syntax parsing only. It
must not be executed without the separate resource claim and exact-digest
approval.
