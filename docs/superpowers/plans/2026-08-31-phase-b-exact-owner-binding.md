# Phase B Exact Owner Binding Implementation Plan

> **For Codex:** Follow the Superpowers test-driven-development and verification-before-completion workflows. Keep all work preparation-only.

**Goal:** Make disposable Phase B rehearsal preparation fail closed unless its owner is one exact registered Codex conversation ID, then prepare replacement artifacts bound to the current Overseer conversation without mutating any existing Overseer records.

**Architecture:** The read-only `preflight` command validates one canonical UUID against one safe, exact row in the authoritative Codex projects CSV and emits a canonical owner-binding attestation that includes descriptor-pinned registry, launcher, source, owner, common Git, and live Codex executable identity. Read-only `render-plan` securely reconstructs those identities and includes the attestation under the plan digest. The separately approved future script requires its process ancestry to pass through both the exact registered tmux pane and exactly one Codex process with the bound executable and exact resume argv before it revalidates all bound objects, installs its lock, or contacts libvirt. Replacement rehearsal, lease, and transition files are generated as new files from the newly committed source and remain unsubmitted and unexecuted.

**Boundaries:** Registration of the current conversation is authorized. Claim submission or dispatch, claim release or activation, VM lifecycle, rehearsal execution, package import, service changes, Phase B execution, and cutover are prohibited.

---

### Task 1: Register the current conversation exactly

**Host files:** `/home/god/.codex/codex-projects.csv`, `/home/god/.local/bin/codex-overseer-01a0354f-d735-76d1-852c-f364b6e6af56`

- [x] Read the exact active row from Codex state and verify its ID, project root, and non-archived state.
- [x] Register only conversation `01a0354f-d735-76d1-852c-f364b6e6af56` through the project manager's narrow registration helper.
- [x] Verify exactly one CSV row and the generated launcher's mode and resume target.

### Task 2: Add failing exact-owner tests

**Files:** `tests/test_phase_b_rehearsal_tool.py`

- [x] Add deterministic owner-binding fixtures.
- [x] Require preflight to accept one exact registered conversation for the expected project.
- [x] Require preflight to reject aliases, absent rows, duplicate rows, project rebinding, malformed registries, and unsafe registry objects before any probe.
- [x] Require read-only rendering to reject malformed, tampered, stale, or source-rebound attestations and digest-bind an accepted exact owner.
- [x] Reproduce borrowed-TTY provenance bypass and require tmux-pane plus exact Codex-process ancestry.
- [x] Run the focused cases and observe the expected failures before implementation.

### Task 3: Implement fail-closed owner binding

**Files:** `tools/phase_b_rehearsal.py`, `docs/phase-b-disposable-rehearsal.md`

- [x] Add safe no-follow registry reading and strict CSV parsing.
- [x] Add exact UUID, unique-row, and exact-project checks to preflight before all external probes.
- [x] Emit a canonical, self-digesting owner-binding attestation.
- [x] Bind the exact Codex executable path, inode, digest, and resume argv and revalidate the process lineage at future execution.
- [x] Stabilize future authorization with two complete ancestry and tmux-pane snapshots so PID reuse or pane recreation fails closed.
- [x] Validate and include the attestation in a versioned rendered plan.
- [x] Add explicit CLI arguments for the owner thread, owner project, and rendered owner-binding JSON while pinning the registry to its authoritative path.
- [x] Document the contract and preparation-only limits.

### Task 4: Verify and review the implementation

**Files:** `tools/phase_b_rehearsal.py`, `tests/test_phase_b_rehearsal_tool.py`, `docs/phase-b-disposable-rehearsal.md`

- [x] Run focused owner-binding tests.
- [x] Run the complete rehearsal-tool tests and full repository suite.
- [x] Run syntax/compile checks and inspect the final diff.
- [x] Obtain independent ordinary review and final security review.
- [x] Commit the reviewed implementation without pushing.

### Task 5: Prepare inert replacement artifacts

**New files only:** `/home/god/.local/share/overseer/phase-b-rehearsal-approvals/<new-digest>.json`, `successor-lease-<new-digest-prefix>.json`, `successor-transition-<new-digest-prefix>.json`, `phase-b-rehearsal-<new-digest-prefix>.sh`

- [ ] Run read-only preflight against the clean reviewed commit and exact registered owner.
- [ ] Render twice from the attested inputs and require byte-identical output.
- [ ] Generate replacement rehearsal, successor-lease, transition, and future-script artifacts as new files.
- [ ] Verify every owner field equals the exact conversation ID and every artifact remains not approved, not submitted, and not executable under current authority.
- [ ] Confirm existing approved records and predecessor artifacts are unchanged.
