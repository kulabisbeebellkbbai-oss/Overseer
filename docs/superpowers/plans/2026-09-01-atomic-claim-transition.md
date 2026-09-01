# Atomic Claim Transition Implementation Plan

> **For Codex:** Use the Superpowers test-driven-development,
> subagent-driven-development, requesting-code-review, and
> verification-before-completion workflows. Keep all operational work prohibited.

**Goal:** Add a fail-closed atomic predecessor-release/successor-activation runner,
correct linked Dax ROLE-approval evidence wording, and prepare an inert replacement
transition package for rehearsal plan digest
`a36eb10433ebae40489deb538ef0abb3bf096340d4e11082b246b79fdc4b743f`.

**Architecture:** A focused transition function runs all exact record validation,
both claim mutations, resource-pointer updates, audit writes, and durable
postcondition checks inside one `SQLiteStore.agent_transaction`. A CLI command
requires every package-bound identity as an explicit argument. Linked role
approval review classification precedes generic Dax read-only classification.

**Global constraints:** Do not execute the live transition; release or activate
either live claim; dispatch a continuation; execute the launcher; perform VM
lifecycle actions; import a package; change services; execute Phase B; or cut
over. Tests may mutate temporary stores only. The replacement package must remain
inert, unimported, and unapproved for execution.

---

### Task 1: Add atomic transition tests

**Files:** `tests/test_claim_transition.py`

- [ ] Seed temporary predecessor and successor resources, claims, decisions,
      exact Dax approval, and delivered continuation.
- [ ] Require one call to atomically release the predecessor, activate the
      successor, update both resource pointers, and persist bound audit evidence.
- [ ] Simulate failure after predecessor release and prove all durable state rolls
      back to active predecessor and requested successor.
- [ ] Require failure without mutation for mismatched claim/resource/owner/group/
      lifecycle/plan-digest bindings, invalid approval, missing or undelivered
      continuation, external claim or resource-exclusive-group conflict,
      unavailable resource, empty release evidence, audit-ID collision, and
      replay.
- [ ] Cover the live claim-level topology with no group rows, exact optional
      singleton-group transitions, and partial/mismatched group rejection.
- [ ] When optional groups exist, prove the trusted Psychlo writer lock spans
      validation through the Overseer commit.
- [ ] Add a CLI routing test for the exact explicit argument contract.
- [ ] Run the focused tests and observe expected failures before implementation.

### Task 2: Implement the atomic runner

**Files:** `src/overseer/claim_transition.py`, `src/overseer/cli.py`

- [ ] Add exact validation helpers and an atomic transition status function.
- [ ] Recompute successor conflict state while excluding only the named active
      predecessor, including resource-level exclusive groups.
- [ ] Reject deterministic audit-ID collisions and require release evidence.
- [ ] Apply both claim/resource changes, optional singleton-group state changes,
      and audit events in one writer transaction.
- [ ] Acquire the trusted Psychlo writer lock first and validate lifecycle state
      whenever persisted activation groups are present.
- [ ] Reload and verify durable postconditions before commit.
- [ ] Add the `transition-claim` parser and command routing with no inferred IDs.
- [ ] Run the focused transition tests to green and refactor without changing
      behavior.

### Task 3: Correct linked Dax evidence wording

**Files:** `tests/test_core.py`, `src/overseer/cli.py`

- [ ] Extend the linked Dax ROLE-approval test to require the exact approval reason
      and bound evidence IDs.
- [ ] Add or retain a true read-only Dax inventory control assertion.
- [ ] Run the focused regression and observe the wording failure.
- [ ] Classify exact linked ROLE-approval results before the generic read-only Dax
      branch and preserve the specific dispatcher reason.
- [ ] Run focused dispatch tests to green.

### Task 4: Document and prepare the inert replacement package

**Files:** `docs/virtual-asset-checkout.md`,
`/home/god/.local/share/overseer/phase-b-rehearsal-approvals/<replacement>.json`

- [ ] Document the atomic transition command, exact preconditions, rollback
      guarantee, replay behavior, and separate execution approval gate.
- [ ] Read the live records without mutation and generate a new transition package
      with one exact future command vector.
- [ ] Bind the package to the reviewed source commit and rehearsal plan digest.
- [ ] Verify the package says not executable, not imported, release unauthorized,
      activation unauthorized, VM lifecycle unauthorized, Phase B unauthorized,
      and cutover unauthorized.
- [ ] Confirm the existing transition package and all live records are unchanged.

### Task 5: Verify and review

**Files:** all changed source, tests, docs, and the new inert artifact

- [ ] Run focused transition and Dax evidence tests.
- [ ] Run the complete repository test suite and compile checks.
- [ ] Inspect the full diff and validate the inert package canonically.
- [ ] Obtain independent ordinary review and resolve all Critical/Important issues.
- [ ] Obtain independent final security review and resolve all Critical/Important
      issues.
- [ ] Commit the verified source changes without pushing, importing, or executing
      the package.
