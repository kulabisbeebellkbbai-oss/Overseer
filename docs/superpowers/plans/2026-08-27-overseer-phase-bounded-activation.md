# Overseer Phase-Bounded Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Overseer's all-in-one activation runner with separately approved, digest-bound staging/canary and cutover phases that cannot advance across the approval boundary automatically.

**Architecture:** Keep the finalized package approval as a package-import and verification gate. Add root-owned phase approval records bound to the exact package digest and prerequisite runner state, then expose distinct staging/canary and cutover runners under the existing root execution lock. A successful canary stops every staged unit and records an awaiting-cutover state; only a later cutover approval bound to that exact state may resume activation.

**Tech Stack:** Python 3.13, argparse, root-owned JSON records, atomic filesystem writes, systemd command contracts, pytest.

## Global Constraints

- Do not execute staging, canary, cutover, service changes, user/group changes, or privileged filesystem changes during implementation or package preparation.
- Do not modify another project's source, service, gateway, firewall, VPN, route, SSH configuration, or database.
- Preserve the live v1.1.5 user services until a later explicit phase approval.
- Keep human approval secrets interactive and out of arguments, environment variables, logs, test output, and generated package metadata.
- Continue to execute only sealed argv arrays under one root-owned nonblocking activation lock.

---

### Task 1: Define package and phase approval contracts

**Files:**
- Modify: `src/overseer/activation_package.py`
- Test: `tests/test_activation_package.py`

**Interfaces:**
- Produces: `record_activation_phase_approval(package_root, *, expected_package_digest, phase)`.
- Produces: `_load_activation_phase_approval(package_root, *, phase, expected_runner_state)`.
- Produces: `_activation_phase_approval_record_path(phase)` for `staging-canary` and `cutover` only.

- [ ] **Step 1: Write failing approval tests**

Add tests proving package approval has import-only scope, staging approval requires no runner state, cutover approval requires `canary_passed_awaiting_cutover_approval`, and a cutover approval is bound to the canonical digest of that exact state.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `pytest -q tests/test_activation_package.py -k 'phase_approval or root_approval_record'`

Expected: failures because phase approval functions and import-only package scope do not exist.

- [ ] **Step 3: Implement the minimal approval primitives**

Use root-owned mode `0600` JSON documents with these exact semantic fields:

```python
{
    "schemaVersion": ACTIVATION_PHASE_APPROVAL_SCHEMA,
    "approved": True,
    "packageRoot": str(package),
    "packageDigest": digest,
    "phase": phase,
    "executionScope": f"{phase}-for-this-package-only",
    "runnerStateDigest": None_or_sha256_canonical_state,
    "runnerStateStatus": "not-started"_or_state_status,
}
```

Reject symlinks, wrong owner/group/mode, unknown phases, an existing target, package-digest drift, stale state, and cutover approval before successful canary completion.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `pytest -q tests/test_activation_package.py -k 'phase_approval or root_approval_record'`

Expected: all selected tests pass.

### Task 2: Split the activation state machine

**Files:**
- Modify: `src/overseer/activation_package.py`
- Test: `tests/test_activation_package.py`

**Interfaces:**
- Produces: `execute_approved_staging_canary(package_root)`.
- Produces: `execute_approved_cutover(package_root)`.
- Preserves: `execute_approved_rollback(package_root)` for both pre-cutover cleanup and post-cutover rollback.

- [ ] **Step 1: Write failing runner tests**

Add tests proving:

```python
staging_result["status"] == "canary_passed_awaiting_cutover_approval"
staging_calls == [("/bin/true", "staging")]
cutover_calls == [("/bin/true", "cutover")]
```

Also prove cutover fails without its phase approval, state drift invalidates a recorded cutover approval, a completed staging replay is non-mutating, and the legacy all-in-one entrypoint fails closed.

- [ ] **Step 2: Run the runner tests and verify RED**

Run: `pytest -q tests/test_activation_package.py -k 'activation_runner or interrupted_staging or cutover_failure'`

Expected: failures because the runner still advances directly into cutover.

- [ ] **Step 3: Implement the split runners**

The staging/canary runner must load the staging phase approval before writing state, execute only `stagingAndCanaryCommands`, verify the canary attestation, and finish with phase `staging-canary` and status `canary_passed_awaiting_cutover_approval`. The cutover runner must require that exact state plus a matching state-bound cutover approval before executing `cutoverCommands`. The old `execute_approved_activation` API must fail closed without writing runner state.

- [ ] **Step 4: Preserve cleanup and rollback semantics**

Treat `staging-canary` and `staging_cleanup` as pre-cutover phases. Any staging/canary failure runs the sealed cleanup sequence; any cutover failure records the first rollback command before execution and uses the existing sealed rollback sequence.

- [ ] **Step 5: Run the runner tests and verify GREEN**

Run: `pytest -q tests/test_activation_package.py -k 'activation_runner or interrupted_staging or cutover_failure'`

Expected: all selected tests pass.

### Task 3: Seal the CLI and rendered contract boundary

**Files:**
- Modify: `src/overseer/activation_package.py`
- Test: `tests/test_activation_package.py`

**Interfaces:**
- Produces CLI: `record-activation-phase-approval --phase {staging-canary,cutover}`.
- Produces CLI: `execute-approved-staging-canary`.
- Produces CLI: `execute-approved-cutover`.
- Keeps CLI: `execute-approved-activation`, but it must fail closed with migration guidance.

- [ ] **Step 1: Write failing contract and CLI tests**

Assert that the rendered contract inventories both phase approval records, forbids automatic cutover, and stops the canary service plus both staged sockets before the staging/canary command list completes.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/test_activation_package.py -k 'contract or phase_approval or activation_cli'`

Expected: failures for missing phase metadata and staged-socket shutdown.

- [ ] **Step 3: Implement contract and CLI changes**

Add `phaseApprovalRecords`, `automaticCutoverForbidden: true`, and the two separately approved runner names to `activation-contract.json`. Change the final normal staging command to stop `overseer-api-canary.service`, `overseer-admin-executor.socket`, and `overseer-codex-user-bridge.socket`.

- [ ] **Step 4: Verify GREEN**

Run: `pytest -q tests/test_activation_package.py -k 'contract or phase_approval or activation_cli'`

Expected: all selected tests pass.

### Task 4: Update the activation runbook

**Files:**
- Modify: `docs/v1.1.6-dedicated-principal-activation-plan.md`

**Interfaces:**
- Documents the package approval, staging/canary approval, awaiting-cutover state, cutover approval, and rollback boundaries.

- [ ] **Step 1: Replace the all-in-one execution instructions**

Document only these supported transitions:

```text
package approval -> staging-canary phase approval -> execute staging-canary
-> canary_passed_awaiting_cutover_approval
-> cutover phase approval -> execute cutover
```

- [ ] **Step 2: Document the manual secret checkpoint and inert wait state**

State that the operator enters verifier secrets locally during staging/canary execution, never in chat, and that all staged services/sockets are stopped before waiting for cutover approval.

- [ ] **Step 3: Document replacement preparation boundaries**

State that package generation and verification do not authorize removing the prior root package approval, importing the replacement, recording either phase approval, or executing either phase.

### Task 5: Verify, review, and prepare the replacement package

**Files:**
- Modify: only files listed above.
- Create later: owner-scoped package below `/home/god/.local/share/overseer/activation-packages/`.

- [ ] **Step 1: Run formatting/static checks and focused tests**

Run the repository's established Python checks and the complete activation-package test module.

- [ ] **Step 2: Run the full test suite**

Run: `pytest -q`

Expected: all tests pass, with only documented skips.

- [ ] **Step 3: Perform independent final security review**

Review the exact commit with `gpt-daybreak-blue-latest`, falling back only to `gpt-5.6-terra`. Require explicit findings by severity and a pass/fail release decision.

If review identifies a direct primitive bypass, lock-lifetime race, checkpoint
recovery gap, or prior-schema recovery break, add a failing regression first.
Require mutating primitives to validate the active sealed runner command inside
their public functions; inherit the runner lock into command children; recover
immediately when a post-command checkpoint fails; and keep prior schemas
readable only by the sealed rollback path. Re-run the exact-commit Daybreak
review after all findings are corrected.

The exact-commit review must also verify that persisted runner state cannot be
replayed by a caller that did not inherit the active lock, every guarded
primitive validates its complete sealed argument map, cleanup and rollback
remain effective when either their entry or completion checkpoint fails, the
legacy-store restoration primitive cannot be invoked directly, and cleanup
treats only the exact inactive `systemctl is-active` result as satisfied.
Also exercise failure of a later command-entry checkpoint, interruption during
command and recovery execution, containment under principal drift, and exact
stale-transient rejection for added lifecycle actions, drop-ins, or credential
source changes.

- [ ] **Step 4: Generate the replacement owner-scoped package**

Reuse the reviewed package workflow and immutable local inputs. Do not use `sudo`, import into `/var/lib/overseer-executor`, write a phase approval, or execute a runner.

- [ ] **Step 5: Stop at the human-verifier gate**

Provide the exact `create-human-verifiers` command for the new package. After the operator enters fresh secrets locally, finalize and verify the exact package digest, then prepare separate package-import and staging/canary approval commands for a later explicit approval.
