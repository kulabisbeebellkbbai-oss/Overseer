# Phase B Timeout and Diagnostic Evidence Repair Plan

> **For Codex:** Follow Superpowers test-driven-development,
> subagent-driven-development, requesting-code-review, and
> verification-before-completion. Keep all execution and activation boundaries
> closed.

**Goal:** Separate disposable guest boot and execution clocks, add an early
guest watchdog, preserve bounded timeout-stage evidence, and prepare a new
digest-bound rehearsal package without importing or executing it.

**Architecture:** A fixed service-entry serial marker ends a bounded boot wait
and starts an independent result wait. Allowlisted canonical progress records
identify the last guest stage. Timeout cleanup confirms owned-domain absence,
removes raw temporary evidence, and then publishes one atomic, sanitized,
caller-only record. The existing passing result validator and ownership checks
remain authoritative.

**Boundaries:** Do not run a rehearsal launcher, contact libvirt for VM
lifecycle, import a package, modify or restart host services, run Phase B, or
cut over. Preserve unrelated worktrees and user changes. A new source commit
invalidates every prior rehearsal digest and requires a separate exact approval
before any future execution.

---

### Task 1: Add guest entry, progress, and watchdog contracts

**Files:**
- Modify: `tests/phase_b_rehearsal/guest_rehearsal.py`
- Modify: `tests/phase_b_rehearsal/guest_rehearsal.service`
- Modify: `tests/test_phase_b_guest_rehearsal.py`

- [x] Add failing tests for the fixed service-entry marker, canonical bounded
  progress serializer, allowlisted stage emission, secret rejection, 780-second
  process watchdog, and 900-second systemd hard stop.
- [x] Run the focused guest tests and record the expected failures.
- [x] Implement progress emission in `StageTracker`, the service-entry marker,
  and an inert-on-import watchdog installed only by `main`.
- [x] Run the focused guest suite and require it to pass.
- [x] Commit the task after independent review approves it.

### Task 2: Split host clocks and retain sanitized timeout evidence

**Files:**
- Modify: `tools/phase_b_rehearsal.py`
- Modify: `tests/test_phase_b_rehearsal_tool.py`
- Modify: `docs/phase-b-disposable-rehearsal.md`

- [x] Add failing tests for 600-second boot, 1020-second result, and 120-second
  shutdown budgets; independent marker/result waits; collector marker/progress
  parsing; and unchanged passing-result validation.
- [x] Add failing schema, redaction, metadata, atomic-write, cleanup-order, and
  success-no-evidence tests for timeout evidence.
- [x] Run the focused tool tests and record the expected failures.
- [x] Implement the smallest fail-closed collector, wait, evidence writer, and
  cleanup changes that satisfy the tests.
- [x] Update operator documentation with the exact 29-minute configured phase
  deadline budget, phase-specific timeout messages, retained evidence
  location, and explicit statements that control-plane cleanup overhead is
  additional and a marker or progress record is never passing evidence.
- [x] Run focused tool and cross-layer suites and require them to pass.
- [x] Commit the task after independent review approves it.

### Task 3: Verify, review, and prepare the inert replacement package

- [x] Run syntax checks, `git diff --check`, focused guest/tool tests, and the
  complete repository test suite from the clean isolated worktree.
- [x] Obtain an ordinary `gpt-5.6-terra` review and fix all findings.
- [ ] Obtain a final `gpt-daybreak-blue-latest` security review and fix all
  findings; use `gpt-5.6-terra` only if Daybreak is unavailable.
- [ ] Commit the fully reviewed source and verify the worktree is clean.
- [ ] Run read-only preflight and deterministic render twice, then prepare new
  approval artifacts bound to the exact owner and source commit.
- [ ] Verify the replacement digest, file hashes, modes, owner binding, and
  non-executed/non-imported state.
- [ ] Stop and request separate digest-bound authority. Do not execute the
  launcher, import a package, alter services, run Phase B, or cut over.
