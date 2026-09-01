# Task 2 report

## RED

The required initial command was:

```text
pytest -q tests/test_claim_transition.py
```

It failed during collection with exit code 2 because `overseer.claim_transition`
did not exist:

```text
ModuleNotFoundError: No module named 'overseer.claim_transition'
```

## GREEN

Focused transition tests:

```text
pytest -q tests/test_claim_transition.py
42 passed
```

Claim-group regression tests:

```text
pytest -q tests/test_claim_activation_group.py
20 passed
```

Additional checks passed:

```text
python3 -m py_compile src/overseer/claim_transition.py src/overseer/cli.py
git diff --check
```

## Implementation and self-review

- Added the atomic claim transition runner with exact claim, resource, approval,
  continuation, conflict, audit, and postcondition validation.
- Added deterministic release and execution audit IDs and targeted collision
  detection.
- Grouped transitions probe only the exact predecessor and successor group
  rows, acquire Psychlo `BEGIN IMMEDIATE` before the Overseer writer
  transaction, validate lifecycle under that lock, and hold the lock through
  the Overseer commit. Unrelated group rows are ignored.
- Ungrouped transitions do not require Psychlo and recheck exact group absence
  inside the Overseer writer transaction, failing closed if either row appears.
- Added `transition-claim` with every reviewed binding required and routed as
  keyword arguments.
- No API/client exposure or schema migration was added.

## Files changed

- `src/overseer/claim_transition.py`
- `src/overseer/cli.py`
- `.superpowers/sdd/task-2-report.md`

The commit stages only the two source files; this report is intentionally left
outside the commit as requested.

## Critical/Important review follow-up

### RED

Focused tests were added before production changes for canonical ROLE policy,
resource-owner bindings, sole deterministic continuation, the ungrouped probe
race, and final owner/continuation postconditions:

```text
pytest -q tests/test_claim_transition.py
12 failed, 42 passed in 2.40s
```

The failures were the expected review gaps: seven cases did not reject, two
race cases observed typed loads before the final writer transaction, and three
postcondition-tamper cases did not reject.

### GREEN

```text
pytest -q tests/test_claim_transition.py
54 passed in 2.19s

pytest -q tests/test_claim_activation_group.py
20 passed in 1.04s

python3 -m py_compile src/overseer/claim_transition.py src/overseer/cli.py tests/test_claim_transition.py
git diff --check
```

All commands exited successfully.

### Implementation and self-review

- Canonical recomputation and the stored decision must now both be exact
  `ESCALATE`/`ROLE` decisions with no blocking claims; SECURITY_SURFACE,
  HIGH-risk, HUMAN/SISKO, ALLOW, BLOCK, QUEUE, and QUARANTINE authority cannot
  be substituted with an approved ROLE record.
- Both predecessor and successor resources must remain owned by the exact
  expected role before mutation and in final postcondition verification.
- The successor must have one continuation only: the deterministic delivered
  record and its exact delivered attempt. The sole-record invariant is reloaded
  and verified before commit.
- The pre-transaction group check is now a narrow raw lock-selection probe,
  explicitly not validation. It ignores unrelated groups and performs no typed
  claim/group loads. If either exact group is observed, Psychlo is locked before
  Overseer and held through commit; the ungrouped path rechecks both exact rows
  under Overseer `BEGIN IMMEDIATE` and fails closed on appearance.
- Deterministic audit collision detection remains a targeted two-ID query.
- Rollback semantics and `transition-claim` CLI parsing/keyword routing were
  unchanged.

### Files changed in review follow-up

- `tests/test_claim_transition.py`
- `src/overseer/claim_transition.py`
- `.superpowers/sdd/task-2-report.md` (appended evidence only)
