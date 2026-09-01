# Task 1 Report: Atomic Claim Transition Tests

## Scope

Implemented only `tests/test_claim_transition.py` in the isolated
`approval-smoke-v1-1-6` worktree. No production module, CLI parser, live store,
service, VM, launcher, package, or operational claim state was touched.

The test fixture uses temporary `SQLiteStore` databases and persists real
resources, claims, conflict decisions, an approved Dax ROLE approval, a
delivered continuation, and its delivered attempt. The successor is bound to
the approved rehearsal digest
`a36eb10433ebae40489deb538ef0abb3bf096340d4e11082b246b79fdc4b743f`.

## Coverage added

- Successful atomic predecessor release and successor activation, including
  both resource pointers and bound release/transition audit evidence.
- Rollback when successor claim persistence fails after the predecessor has
  been released within the transaction; the complete durable fixture snapshot
  must remain unchanged.
- Fail-closed, no-mutation checks for mismatched predecessor/successor claim,
  resource, owner thread, owner role, activation group, lifecycle, plan digest,
  or approval identity.
- Fail-closed, no-mutation checks for invalid approval, missing continuation,
  undelivered continuation, external conflict, and unavailable successor
  resource.
- Non-idempotent replay rejection with no mutation after the first successful
  transition.
- CLI routing that intercepts only `transition_claim_status` and verifies all
  explicit plan bindings are passed as keyword arguments and emitted as JSON.

## Verification

- `python3 -m py_compile tests/test_claim_transition.py`: passed.
- `git diff --check -- tests/test_claim_transition.py`: passed.
- `python3 -m pytest -q tests/test_claim_transition.py`: expected RED during
  Task 1. Collection stopped with:
  `ModuleNotFoundError: No module named 'overseer.claim_transition'`.
  This confirms the requested failure is due to the not-yet-created production
  module; no test body reached a live or shared resource.

## Commit

Test-only commit: `e80919c` (`Add atomic claim transition tests`).

The pre-existing tracked modification to `.superpowers/sdd/progress.md` was
left untouched and was not included in the commit. This report is the required
worktree report and is intentionally separate from the test-only commit.

## Regenerated design correction

The regenerated brief/design was reread before this correction. The fixture now
matches the live read-only shape: neither `ClaimActivationGroup` row is seeded
for the primary success case, the successor resource carries
`identifiers={"planDigest": PLAN_DIGEST}`, and the successor claim begins with
`approval_id=None`. Both base resources carry the same resource-level
exclusive group, so only the named predecessor is waived during conflict
evaluation. A separate third active resource test uses that same resource-level
group while its claim has no `exclusive_groups` and must fail closed.

The amendment adds or strengthens tests for:

- empty release evidence;
- deterministic release and transition IDs
  `audit.claim-transition.<successor_claim_id>.predecessor-released` and
  `audit.claim-transition.<successor_claim_id>.executed`, including collision
  rejection for either pre-existing ID;
- exact optional singleton predecessor ACTIVE and successor REQUESTED groups,
  atomic group state changes to RELEASED and ACTIVE, and no-mutation rejection
  for partial, non-singleton, or mismatched group topology;
- a temporary Psychlo database and writer-lock span through grouped validation
  and Overseer commit;
- approval subject, owner, level, and decided-by bindings; continuation
  identity, claim, approval, resource, owner, group, and lifecycle bindings;
  and pending or attempting continuation states; and
- CLI omission of a required argument, proving argparse rejects before the
  intercepted transition function is called.

## Amendment verification

- `python3 -m py_compile tests/test_claim_transition.py`: passed.
- `git diff --check -- tests/test_claim_transition.py`: passed.
- `python3 -m pytest -q tests/test_claim_transition.py`: expected RED during
  Task 1. Collection stops at the absent production import with
  `ModuleNotFoundError: No module named 'overseer.claim_transition'`.
- Corrected test-only follow-up commit:
  `16988f9d7027e4564a7726696052136b0456cf0b` (`Correct atomic claim transition tests`).

The prior regenerated-design commit `9566d8d`, the pre-existing
`.superpowers/sdd/progress.md` modification, and the report itself were not
included in the test-only commit.

## Reviewer findings correction

All Task 1 reviewer findings were corrected in `tests/test_claim_transition.py`:

- every successful durable-state assertion now requires the active successor's
  persisted `approval_id` to equal the exact `APPROVAL_ID`;
- the grouped Psychlo lock test now blocks `SQLiteStore._commit` only after both
  claims, both resource pointers, and both optional group states have changed,
  then proves a competing Psychlo `BEGIN IMMEDIATE` remains locked until the
  actual Overseer commit is allowed to continue;
- claim-level and resource-level external exclusive-group conflicts are
  independent tests, and the claim-level case proves the external resource has
  no resource-level exclusive group;
- both deterministic audit events must contain the predecessor claim,
  successor claim, exact approval, exact continuation, plan digest, and every
  release evidence ID; and
- durable snapshots enumerate every seeded claim and pair it with its persisted
  decision or explicit absence, covering third-party conflict and extra group
  claims in global no-mutation comparisons.

Verification after the correction:

- `python3 -m py_compile tests/test_claim_transition.py`: passed with no output.
- `git diff --check -- tests/test_claim_transition.py`: passed with no output.
- `python3 -m pytest -q tests/test_claim_transition.py`: exited 2 during
  collection with one error, solely
  `ModuleNotFoundError: No module named 'overseer.claim_transition'`; no test
  body ran.
- Test-only commit:
  `7628529d0e1239d687e61bcc0cb6a67a1d10666b` (`Fix Task 1 reviewer findings`).

## Psychlo lock review correction

The remaining Important finding was corrected by making the grouped lock test
exercise one continuous competing Psychlo writer attempt across both critical
seams:

- lifecycle validation is blocked at entry, then the competing connection
  starts `BEGIN IMMEDIATE` and is proven unable to acquire;
- validation is allowed to finish while the same competing call remains
  blocked;
- after all Overseer mutations, `SQLiteStore._commit` is blocked and the same
  competitor is proven still unable to acquire;
- the Overseer commit is allowed to complete, and the competitor may acquire
  only after the commit-completed marker is set and the Psychlo writer lock is
  released.

This rejects implementations that validate without a Psychlo writer lock and
acquire it only immediately before the Overseer commit.

Exact verification evidence:

- `python3 -m py_compile tests/test_claim_transition.py`: exit 0, no output.
- `git diff --check -- tests/test_claim_transition.py`: exit 0, no output.
- `python3 -m pytest -q tests/test_claim_transition.py`: exit 2; one collection
  error in 0.29s, solely
  `ModuleNotFoundError: No module named 'overseer.claim_transition'`; no test
  body ran.
- Test-only commit:
  `ba9772a9054df30351272e9392f3bd8cb9b94e69` (`Strengthen Psychlo transition lock test`).
