# Overseer v1.1.6 Maintenance-Window Deployment Plan

## Scope and authority

This implementation replaces the paused Phase B rehearsal and complex cutover
workflow with one separately approved, digest-bound maintenance window. This
branch may implement, test, review, and package the runner. It must not import a
package, touch a live approval or claim record, operate a VM, stop or start a
service, reboot the host, change the gateway, or execute the maintenance window.

The eventual live runner must hold Overseer's activation lock for the complete
window, consume only a root-owned maintenance approval bound to the final
package digest and maintenance-plan digest, and execute only argv sealed into
the package. Existing Phase B approvals, claim records, canary state, and
cutover state are not authority for this runner.

## Implementation tasks

- [x] Add maintenance approval, contract, and runner-state schemas with
  independent root-owned paths and exact digest bindings.
- [x] Render one maintenance contract that contains ordered stop, quiescence,
  preflight, preservation, installation, offline migration, handoff,
  acceptance, and rollback commands.
- [x] Reject shells, VM tools, claim commands, gateway mutation tools, systemctl
  power verbs, unapproved executables/actions/targets, and legacy Phase B
  runners from every maintenance command list.
- [x] Add offline snapshot and migration primitives for the main Overseer,
  Psychlo bridge, and Roadex relay SQLite stores, including WAL/SHM capture,
  integrity checks, and dedicated-principal ownership on new copies only.
- [x] Implement a checkpointed runner that rolls back immediately after any
  post-stop failure, enforces dependency-aware restart barriers, and never
  resumes from the old Phase B runner state.
- [x] Implement bounded acceptance for API health, UI data, scheduler/runtime
  freshness, Protected Gateway reachability, Psychlo, Roadex, credential
  compatibility, and single-writer process state.
- [x] Preserve the previous immutable release, raw database artifacts,
  credentials, units, and root-owned rollback bundle until acceptance passes.
- [x] Stop the complete Overseer writer inventory, preserve and resume the
  Codex Usage store unchanged, and apply the kernel lease barrier to every
  migrated store.
- [x] Add a pre-stop input/capacity/unit preflight, preservation re-verification,
  core-job freshness limits, successor/legacy unit inventory, and an
  authenticated Protected Gateway operator challenge.
- [x] Seal per-command timeouts, a 5,400-second runner deadline, and a separate
  1,800-second rollback deadline.
- [x] Document outage behavior, no-reboot policy, exact approvals, stop
  conditions, acceptance, and rollback.
- [ ] Build and verify a new owner-scoped package without importing or executing
  it. Human verifier secrets remain terminal-only.

## Test-first slices

1. Contract and approval validation fail closed on wrong digests, wrong scope,
   missing root metadata, forbidden commands, or Phase B authority.
2. Command ordering proves writers stop and quiesce before snapshots,
   installation, migration, and new-service startup.
3. Offline migration tests preserve source triplets, validate independent
   copies, and never modify legacy authority.
4. Runner tests inject failures at every boundary and require immediate sealed
   rollback after writers have stopped.
5. Replay and interrupted-state tests permit only terminal replay or the sealed
   maintenance rollback path.
6. CLI and package tests prove maintenance approval, execution, and rollback
   remain distinct from package import and legacy activation phases.

## Verification gates

- Focused maintenance tests pass.
- Existing activation-package tests pass from the clean baseline.
- Full project tests pass or every unrelated pre-existing failure is recorded.
- Package manifest and final digest verify from the owner-scoped package path.
- Independent code review finds no unresolved correctness issues.
- Final security review finds no approval bypass, command injection, TOCTOU,
  secret exposure, privilege drift, unsafe recovery, or dual-writer path.
- The final handoff stops at the next explicit approval boundary: package import.
