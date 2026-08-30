# Disposable Phase B rehearsal: inert host preparation

The rehearsal tool prepares evidence and renders a separately approved future
VM run. `preflight` is read-only and `render-plan` is pure. Neither subcommand
downloads an image, creates an overlay or ISO, defines or starts a VM, imports
or executes a package, invokes Phase B, or changes a host service.

The image remains pinned to:

```text
URL: https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
SHA-512: 184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003
```

## Read-only preflight

Preflight fails closed unless:

- the repository is clean and its full SHA is the requested commit;
- `/dev/kvm` is a caller-accessible character device;
- `qemu:///session` reports the expected x86-64 KVM capabilities and the
  collision-resistant target VM name is absent;
- source, runtime, image, and temporary-parent paths have conservative
  absolute names, safe object types, safe permissions, and required access;
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
  manifest-enforcing finder. Every source loader opens with `O_NOFOLLOW`,
  revalidates stable descriptor metadata, mode, size, and SHA-256, then compiles
  those verified bytes directly. Native loaders copy the exact verified bytes
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
```

`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PYTHONHOME`, `BASH_ENV`, and
the caller's command lookup do not enter a preflight child. Every Git command
also supplies `--no-optional-locks`, disables `core.fsmonitor`, and disables
the untracked cache so repository configuration cannot execute an fsmonitor
helper or refresh the index during the read-only probe.

## Immutable host-to-guest handoff

The v4 plan has no host filesystem share. It binds canonical source and runtime
manifests, their SHA-256 digests, deterministic stored-ZIP digests, the runtime
probe, KVM capability probe, source commit, domain XML, cloud-init, and future
script under `planDigest`.

The separately approved future script rechecks Git identity and cleanliness,
reruns the manifest-enforced import probe, and builds both ZIP files using
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

The serial device writes through a FIFO pair to a dedicated collector. The
collector continuously drains the pipe, stores no more than 1 MiB, enforces a
64 KiB line bound, and upgrades a previously seen completion to overflow if
later data crosses either bound. After the owned VM is inactive, a streaming
validator rereads the collector's terminal status and requires it still be
`complete`, then requires exactly one begin/end pair framing one canonical JSON line.
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

## Source-only verification

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_phase_b_rehearsal_tool.py
python3 -B -c 'from pathlib import Path; compile(Path("tools/phase_b_rehearsal.py").read_text(), "tools/phase_b_rehearsal.py", "exec")'
git diff --check
```

The rendered future script may be sent to `bash -n` for syntax parsing only. It
must not be executed without the separate resource claim and exact-digest
approval.
