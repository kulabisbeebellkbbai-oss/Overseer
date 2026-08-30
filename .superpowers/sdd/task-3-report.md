# Task 3 repair: fail-closed Phase B VM rehearsal

## Outcome

Repaired every Critical and Important finding from
`.superpowers/sdd/task-3-review.md` without amending `54a53bc`. The host tool
remains inert: preflight is read-only and rendering is pure. No future
command, VM/image operation, package action, service action, Phase B, or
cutover was executed.

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

## Files

- `tools/phase_b_rehearsal.py`
- `tests/test_phase_b_rehearsal_tool.py`
- `docs/phase-b-disposable-rehearsal.md`
- `.superpowers/sdd/task-3-report.md`

## Final verification

- Commit message: `Repair fail-closed Phase B VM rehearsal`
- Focused tests: `26 passed in 0.21s`
- In-memory Python compile of tool and tests: clean, no output
- Future Bash syntax parse with `bash -n`: clean, no output; no future command
  executed
- `git diff --check`: clean, no output
- Actual preflight: exit `2` with canonical fail-closed dirty-tree rejection;
  it stopped before KVM, image, runtime, or libvirt probes
- Pure render fixture: exit `0`, canonical plan digest
  `29907184774c56dd55ef8e197d5e4006235d317110c2337d32e87f99aabdc3de`
  and future-script digest
  `a078a83682a31f8972c147fa9d7c772dd834eb841805725d0b80971444c1eb34`;
  this is source-only fixture evidence, not an approved runnable plan
- Read-only `virsh --connect qemu:///session list --all`: only pre-existing
  `overseer-dax-disposable-libvirt` remains shut off; no new VM appeared

## Limitations

This source repair does not prove a guest boot or live systemd choreography.
Image acquisition, KVM use, VM lifecycle, and cleanup still require one exact
Dax claim and explicit user approval of the new rendered plan digest. Package
import, host service action, Phase B, and cutover remain excluded.
