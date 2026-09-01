# Task 3: Correct linked Dax evidence wording

## Outcome

Implemented the exact linked Dax ROLE-approval review classification in both
dispatch-time automatic review and durable reconciliation. Unlinked Dax
read-only inventory reviews retain their existing wording and evidence shape.
No approval, claim, continuation, dispatcher scope, or operational state was
changed outside temporary test stores.

## TDD evidence

### RED

After extending the linked dispatch test and adding reconciliation replay
coverage, the focused run failed as expected:

```text
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_core.py -k 'role_claim_creates_and_dispatches_exact_dax_approval_handoff or reconciliation_replays_exact_dax_role_approval_review or dispatches_dax_read_only_advisory_without_resource_claim'
.FF                                                                      [100%]
```

The linked reviews still recorded the generic reason:

```text
Dax completed the bounded read-only inventory review without reserving or mutating a resource
```

The pre-fix generic branch also supplied only the dispatch audit ID in
`decision_evidence_ids`; the required claim and approval bindings were absent.
The unlinked inventory control passed during this RED run.

### GREEN

The focused tests passed:

```text
...                                                                      [100%]
3 passed, 394 deselected in 0.68s
```

The nearby role-handoff/reconciliation set also passed:

```text
.........                                                                [100%]
9 passed, 388 deselected in 0.97s
```

## Implementation

- Added exact durable message binding checks for Dax, claim, approval, resource,
  owner, canonical subject/message, and ROLE approval identity.
- Required approved ROLE state and exact action fields:
  `claim_id`, `approval_id`, `approval_status=approved`, and
  `activation_required=true`.
- Preserved the exact dispatcher reason:
  `dax approved the exact original ROLE approval <approval-id>; activation remains separate`.
- Built deduplicated decision evidence from the original request evidence,
  exact claim ID, approval ID, and dispatch audit/evidence ID.
- Required the exact durable dispatch reason during reconciliation replay before
  applying the linked classification.

## Verification

- `python3 -B -m py_compile src/overseer/cli.py tests/test_core.py` — passed.
- `git diff --check` — passed.
- Only `src/overseer/cli.py`, `tests/test_core.py`, and this report are changed;
  `.superpowers/sdd/progress.md` was left untouched.

## Commit

This report, the focused tests, and the source fix are committed together.

## High/Medium review repair

### Outcome

Repaired every reported linked-reconciliation trust-boundary finding. Dax
messages carrying either linked claim or approval identity are now linked-only:
exact validation approves them, while every invalid linked result becomes
`CORRECTION_REQUESTED` with a specific reason and dispatch-event evidence. No
linked failure can enter the generic read-only inventory approval branch.

The dispatch audit now stores one namespaced SHA-256 digest over canonical
sorted compact JSON containing only `claim_id`, `approval_id`,
`approval_status`, and `activation_required`. Listener discovery and all other
action content are excluded from the digest input and durable evidence.

### TDD evidence

Focused RED after adding the adversarial reconciliation matrix:

```text
.FFFFFF                                                                  [100%]
6 failed, 1 passed, 395 deselected in 2.21s
```

The failures showed invalid linked records being approved, generic inventory
fallthrough, ignored forged audit identity/metadata, ignored missing/wrong
action digests, ignored request-evidence tampering, and no persisted happy-path
action digest.

Focused GREEN after the minimal repair:

```text
.......                                                                  [100%]
7 passed, 395 deselected in 1.26s
```

Nearby role-handoff/reconciliation regression set:

```text
.........                                                                [100%]
9 passed, 393 deselected in 0.87s
```

### Exact validation added

- deterministic audit ID from message ID plus audit `occurred_at` status ID;
- Dax audit owner, exact message subject, `EXECUTED` event type, and matching
  message risk;
- exact linked dispatcher summary and exact persisted action digest;
- canonical handoff comparison including `request_evidence_ids`, with only
  status and review status allowed to vary during durable replay;
- exact durable claim/ROLE approval bindings and exact action fields;
- correction-required handling with the dispatch audit ID for every invalid
  linked replay.

### Verification and safety

- `python3 -B -m py_compile src/overseer/cli.py tests/test_core.py` — passed.
- `git diff --check` — passed.
- `.superpowers/sdd/progress.md` — untouched.
- No live claim, approval, continuation, service, listener, or operational
  state was read or changed; all durable mutations occurred in temporary test
  stores.
