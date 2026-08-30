# Disposable Phase B rehearsal: inert host preparation

Task 3 prepares data for a separately approved disposable VM rehearsal. It
does not perform the rehearsal. `preflight` runs read-only checks and
`render-plan` is a pure canonical JSON renderer. Neither subcommand downloads
an image, creates an overlay or ISO, changes a VM, imports or executes a
package, invokes Phase B, or changes a host service.

The image is pinned exactly:

```text
URL: https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
SHA-512: 184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003
```

## Read-only preflight

Preflight fails closed unless all of these conditions hold:

- the repository is clean and its full SHA is the requested source commit;
- `/dev/kvm` is a character device readable and writable by the caller;
- `qemu:///session` is the reported URI, supports an x86_64 KVM domain, and
  has no domain with the exact target name;
- source, runtime-site, base-image, and temporary-parent paths use the
  conservative absolute host-path grammar and have safe types, permissions,
  and caller access;
- a sticky `1777` `/var/tmp` is accepted as the parent for a fresh owner-only
  `mktemp -d`; non-sticky shared-writable parents are rejected;
- the base image has the pinned SHA-512 and read-only `qemu-img info
  --output=json --force-share` identifies it as qcow2;
- every future host tool is present, including Bash, `awk`, `cat`, `grep`,
  `install`, `rm`, `rmdir`, `sleep`, `python3`, and `timeout`;
- a `python3 -B -s -P` no-bytecode probe imports `cryptography`,
  `overseer.cli`, `overseer.user_bridge`, and `overseer.admin_executor` using
  the selected source and runtime-site paths; and
- the exact rendered domain inputs contain no network interface and expose
  both 9p shares read-only.

The default offline dependency source is
`/usr/lib/python3/dist-packages`. Preflight returns the complete bounded
runtime-probe record and its digest. It does not create the future temporary
directory.

## Rendered data and approval digest

`render-plan` requires the exact passed runtime-probe JSON returned by
preflight. The selected runtime-site path, complete probe record, probe
digest, source commit, pinned image, domain XML, cloud-init, and canonical
future Bash script are all covered by `planDigest`. That digest is the
separate explicit user-approval boundary.

The domain shape is fixed to `qemu:///session`,
`overseer-phase-b-rehearsal-<source7>`, 2048 MiB, two vCPUs, an 8 GiB
overlay, no network interface, and disabled autostart. It has:

- a qcow2 overlay disk;
- the NoCloud seed as a read-only CD-ROM;
- a read-only 9p source share tagged `overseer-source`;
- a read-only 9p runtime share tagged `overseer-runtime-site`; and
- a libvirt-appended serial file created mode `0600` below a fresh future
  `mktemp` directory.

The future lifecycle deliberately uses a temporary persistent definition:
the script writes concrete domain XML under the exact temporary directory,
runs `virsh define --validate`, explicitly disables and verifies autostart,
starts the domain, gracefully shuts it down if still active, confirms it is
inactive, and then undefines it. This is temporary because successful and
partial-failure paths explicitly undefine the persistent definition; it is
chosen because `virsh define` has no valid `--transient` option and the
persistent form provides enforceable autostart state.

The one rendered future Bash script is data only. It uses `set -Eeuo
pipefail`, `umask 077`, a fixed path/locale, exact immutable variables, and
EXIT/INT/TERM cleanup. Cleanup attempts only graceful shutdown, undefines
only after confirmed inactivity, and then removes only the six exact files
inside the validated temporary directory: domain XML, user-data, meta-data,
overlay, seed ISO, and serial log. It uses no recursive deletion and never
deletes the base image, source, runtime site, or another directory.

The script never redirects `virsh console` into the serial file. It polls the
libvirt-written serial log for up to 960 seconds, exceeding Task 2's
15-minute service start timeout. Success requires exactly one complete
begin/end sentinel pair framing exactly one canonical JSON line. The result
must use schema `overseer.phase-b-disposable-rehearsal.v1`, have status
`passed` and stage `phase-complete`, contain exactly all required controls set
to true, and contain no failure or secret-bearing identifiers.

## Guest installation contract

Cloud-init disables default users; creates exact `overseer` UID/GID 984 and
`god` UID/GID 1000 identities; mounts both 9p shares read-only; copies the
offline runtime into `/usr/local/lib/python3.13/dist-packages`; installs
`guest_rehearsal.py` and the outer one-shot unit; creates and revalidates the
six exact empty root-owned mode `0644` child-unit placeholders; runs
`systemctl daemon-reload`; and starts only the guest-local outer one-shot.

## Approval boundary and exclusions

Future image download, KVM use, VM definition/start, and exact temporary-file
cleanup require one exact Dax resource claim plus explicit approval of the
rendered `planDigest`. Approval of source code, an older plan, or a different
digest is not authority to execute it.

Package import, host service action, the Phase B launcher, Phase B itself,
and cutover remain excluded. No owner-package secret, token, key, verifier,
or human input is included in the rendered data.

## Source-only verification

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_phase_b_rehearsal_tool.py
python3 -B -c 'from pathlib import Path; compile(Path("tools/phase_b_rehearsal.py").read_text(), "tools/phase_b_rehearsal.py", "exec")'
git diff --check
```

The future script may be passed to `bash -n` for syntax parsing only. It must
not be executed without the separate claim and exact digest approval.
