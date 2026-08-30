# Task 3 repair: fail-closed Phase B VM rehearsal

## Outcome

Repaired the original findings from `.superpowers/sdd/task-3-review.md`, then
resolved the later cleanup/runtime/capability findings from
`.superpowers/sdd/task-3-review-final.md`, without amending `54a53bc`. The
host tool remains inert: preflight is read-only and rendering is pure. No
future command, VM/image operation, package action, service action, Phase B,
or cutover was executed.

## Repair TDD evidence

### RED

After replacing the old string-presence tests with the reviewed contracts:

```text
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_phase_b_rehearsal_tool.py
FFFFFFFFFFFFFFFFFFFFFFFFFF                                               [100%]
26 failed in 0.29s
```

The failures were the expected missing repaired interfaces and behavior:
absent runtime-site/probe inputs, old preflight signature, unparsed domain
shape, incomplete cloud-init, and absent strict future-script lifecycle and
result validation. Test collection itself was clean.

A second focused RED round caught two source-review omissions:

```text
F...................F.....                                               [100%]
2 failed, 24 passed in 0.25s
```

Those failures required `cat` in the complete future-tool inventory and
`credential` in the scoped result secret-marker check.

### GREEN

The current focused suite reached:

```text
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_phase_b_rehearsal_tool.py
..........................                                               [100%]
26 passed in 0.22s
```

## Critical findings repaired

1. Replaced invalid `define --transient` with one valid temporary persistent
   lifecycle: concrete XML file, `define --validate`, explicit autostart
   disable/verification, start, graceful shutdown, confirmed inactivity, and
   explicit undefine.
2. Added the NoCloud seed as a read-only CD-ROM and made the unquoted domain
   heredoc expand overlay, seed, and serial paths into concrete future paths.
3. Expanded cloud-init to provide exact identities, both read-only mounts,
   offline Python dependencies, guest script/unit installation, exact empty
   child placeholders, daemon reload, and guest-local outer one-shot start.
4. Replaced the command list with one strict canonical Bash script using
   EXIT/INT/TERM cleanup, a 960-second serial poll, complete-single-sentinel
   enforcement, canonical JSON/schema/control/secret validation, graceful
   lifecycle cleanup, and exact non-recursive temporary-file deletion.

## Important findings repaired

1. Safe sticky mode `1777` `/var/tmp` is accepted; unsafe shared-writable
   non-sticky parents are rejected.
2. Preflight validates KVM character-device/access state, host path grammar,
   path types and permissions, complete tooling, KVM domain capabilities,
   qcow2 JSON metadata, pinned SHA-512, and the exact no-bytecode import
   probe.
3. The enforceable persistent lifecycle disables and verifies autostart before
   start and undefines only after the domain is confirmed inactive.
4. Tests now parse XML and inspect cloud-init, lifecycle/traps, bounded result
   handling, exact cleanup, path/KVM/image/runtime/tool rejections, render
   purity, and read-only preflight probes.

The runtime-site path, complete passed import-probe record, and probe digest
are part of the plan and therefore part of the separate `planDigest` approval
boundary. Source-share and no-network evidence is derived from the rendered
domain inputs rather than caller assertions.

## Fresh-review rejection and test-first repair

The first fresh final review correctly returned `NON-COMPLIANT / CHANGES
REQUIRED`. Its Critical finding showed that a failed `virsh dominfo` query was
being treated as authoritative absence, which could permit artifact deletion
while VM state was unknown. Four Important findings required lifecycle-spec
alignment, exact offline-runtime provenance and execution-time replay,
path-filesystem capability binding, and executable cleanup failure tests.

The new RED round produced `18 failed, 14 passed`. The repaired plan schema is
now `overseer.phase-b-disposable-rehearsal-plan.v3` and:

1. derives presence only from a successful exact-name `virsh list --all
   --name` inventory;
2. retains every artifact and returns failure for unknown inventory or domain
   state;
3. deletes only after graceful stop, confirmed inactivity, successful
   undefine, and a second authoritative absence inventory;
4. records Python 3.13 patch/ABI and exact module origins, isolates the host
   import path, replays the byte-identical probe before artifact creation, and
   verifies the ABI/imports again in the guest; and
5. parses, records, digest-binds, and replays x86_64 KVM path-filesystem
   capability for the two read-only 9p shares.

## Files

- `tools/phase_b_rehearsal.py`
- `tests/test_phase_b_rehearsal_tool.py`
- `docs/phase-b-disposable-rehearsal.md`
- `docs/superpowers/plans/2026-08-30-overseer-phase-b-disposable-rehearsal.md`
- `.superpowers/sdd/task-3-report.md`

## Final verification

- Repair commits include `Repair fail-closed Phase B VM rehearsal` and
  `Validate Phase B rehearsal domain schema`; final review-repair commit:
  `Harden Phase B rehearsal approval boundary`
- Focused tests after cleanup/runtime/capability hardening: `33 passed in 0.41s`
- Cross-layer activation-package, guest, and host rehearsal tests: `296 passed
  in 24.34s`
- In-memory Python compile of tool and tests: clean, no output
- Future Bash syntax parse with `bash -n`: clean, no output; no future command
  executed
- Concrete rendered domain XML: installed `virt-xml-validate` passes after
  removing the invalid 9p driver-name attributes and invalid explicit
  `graphics type='none'` element caught during independent integration review
- `git diff --check`: clean, no output
- Actual preflight: exit `2` with canonical fail-closed dirty-tree rejection;
  it stopped before KVM, image, runtime, or libvirt probes
- All earlier v2 fixture digests are superseded. A v3 source-only render was
  used for syntax/probe verification only; no digest is approved or runnable.
  The exact approval digest remains a Task 5 output after a clean preflight.
- Read-only `virsh --connect qemu:///session list --all`: only pre-existing
  `overseer-dax-disposable-libvirt` remains shut off; no new VM appeared

## Limitations

This source repair does not prove a guest boot or live systemd choreography.
Image acquisition, KVM use, VM lifecycle, and cleanup still require one exact
Dax claim and explicit user approval of the new rendered plan digest. Package
import, host service action, Phase B, and cutover remain excluded.
