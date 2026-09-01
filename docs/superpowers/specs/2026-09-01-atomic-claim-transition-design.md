# Atomic Claim Transition Design

## Goal

Replace the Phase B rehearsal handoff's unsafe two-command predecessor release
and successor activation sequence with one fail-closed, atomic claim transition.
Correct Dax's durable review wording so a linked ROLE approval is recorded as an
exact approval decision, not as a generic read-only inventory review.

This work prepares source and an inert replacement transition package only. It
does not release or activate a claim, dispatch a continuation, run a launcher,
change VM or service state, import a package, execute Phase B, or cut over.

## Problem

The existing transition plan tells an operator to release the active predecessor
claim and then activate the requested successor claim in separate processes. If
the second command fails after the first commits, Overseer loses the predecessor
lease without gaining the successor lease. The plan also relies on prose to bind
the live records to the exact rehearsal digest.

The linked Dax ROLE-approval dispatcher already performs the correct bounded
action, but `_automatic_crew_review` sees the word `review` and replaces the
specific dispatcher reason with generic read-only inventory wording. The stored
review therefore misdescribes the action even though the approval record itself
is correct.

## Architecture

### Atomic transition service

Add a focused claim-transition module with a public status function used by the
CLI. It opens the explicit SQLite store and enters `SQLiteStore.agent_transaction`,
which uses `BEGIN IMMEDIATE`. All records are loaded and validated only after the
writer transaction begins.

The transaction requires:

- one exact active predecessor claim whose resource points back to it;
- one distinct exact requested successor claim and unclaimed successor resource;
- the expected owner thread, owner role, activation group, lifecycle, resource,
  and rehearsal plan digest on the successor;
- one exact approved ROLE approval for the successor, decided by its owner role;
- one exact delivered approval continuation with matching owner, lifecycle,
  activation-group, resource, claim, and approval bindings;
- no unavailable successor resource and no remaining conflict after excluding
  only the named predecessor.

After validation, the service writes the predecessor as released, clears only
its resource pointer, writes the successor as active with the exact approval,
sets only its resource pointer, and writes release plus transition audit events.
It reloads all four durable records and verifies the final postconditions before
allowing the transaction to commit. Any exception, conflict, failed write, or
postcondition mismatch rolls the whole transaction back.

The runner is deliberately non-idempotent. A replay no longer has the required
active/requested preconditions and fails without mutation. This makes accidental
second execution visible instead of silently treating an ambiguous state as a
successful transition.

### CLI contract

Add `transition-claim` with explicit arguments for every identity and authority
binding. It does not infer a predecessor, successor, approval, owner, lifecycle,
activation group, resource, or plan digest. The command returns a canonical JSON
status only after the transaction commits.

### Dax evidence wording

Before the generic Dax read-only branch, detect a linked ROLE-approval result by
its exact message bindings and dispatched action fields. Preserve the dispatcher's
specific reason, include the original request evidence plus the exact claim,
approval, and dispatch audit IDs, and record Dax as the decision actor. Ordinary
Dax inventory reviews continue to use the existing read-only wording.

### Replacement package

Prepare a new JSON artifact beside the existing rehearsal approval artifacts.
It records the reviewed source commit, exact existing rehearsal plan digest,
the live predecessor/successor/approval/continuation bindings, and a single
future `transition-claim` command vector. The artifact remains non-executable,
not imported, and explicitly marks release and activation as unauthorized until
the user gives a separate digest-bound transition execution approval.

## Testing

Use test-driven development. First add failing tests for a successful atomic
transition, rollback after a simulated post-release failure, every material
identity/authority precondition, replay rejection, and CLI argument routing.
Add a regression test proving linked Dax approval wording is specific and a
control proving true read-only inventory wording is unchanged.

After focused tests pass, run the full repository suite, compile checks, package
validation, an ordinary independent review, and a final independent security
review. No live transition or operational phase is part of verification.

