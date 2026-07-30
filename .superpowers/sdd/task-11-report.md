# Task 11 Report: Policy-Controlled Failover

## Outcome

Implemented persisted, policy-controlled primary-driver failover. Evaluation is
pure when blocked and persists only an allowed, short-lived decision bound to
the outgoing epoch, operation generation, policy, checkpoint, and exact health
and risk evidence. Execution requires that decision plus explicit operator and
approval identifiers, re-evaluates under a fenced transaction, atomically
reserves the coordinator and consumes the decision, then runs the reviewed
handoff pipeline with reason `controlled_failover`.

## TDD evidence

- Initial focused run: 51 tests passed, then the exact migration-ledger
  preservation test failed because the new additive `agent_driver_v6` row had
  not yet been included in its expected ledger.
- Process deviation: the evaluator implementation was started before the full
  behavioral RED matrix was executed. This report does not misrepresent those
  subsequently added tests as pre-implementation RED evidence.
- Added matrix coverage for missing/unapproved policy, approval timing,
  slow-only observations, failure threshold, checkpoint absence/binding/age,
  unresolved high risk, non-transferability, fallback health/order,
  capability/handoff-import mismatch, changed transition/generation, blocked
  non-persistence, immutable decisions, one-shot consumption, provider
  recovery after evaluation, and exactly one replacement epoch.
- Focused GREEN after the final reservation refinement: 14 failover tests
  passed (47 unrelated manager tests deselected).

## Persistence and safety

- Additive, idempotent `agent_driver_v6` migration creates four typed JSON
  record tables without altering prior migration rows.
- Policies, health observations, active risks, and decisions validate stable
  IDs, timezone-aware timestamps, enum states, non-negative bounds,
  duplicate evidence/fallback IDs, and redacted reason categories.
- Allowed decisions are immutable. Consumption is a compare-and-set operation.
- Blocked evaluation performs no checkpoint, handoff, epoch, reservation,
  dispatch, provider, or decision-store mutation.
- Final execution compares exact evidence IDs/timestamps, epoch, provider,
  checkpoint, policy, candidate, risk IDs, and generation. Provider recovery
  or any new evidence invalidates the decision.
- Reservation and decision consumption occur in one SQLite transaction.
  Concurrent/late execution therefore cannot create more than one incoming
  epoch; the existing generation and epoch quarantine rules remain authoritative.
- The existing coordinator still drains/quiesces/checkpoints/imports/promotes
  and retains its verified-cancellation rollback behavior and idempotency
  evidence.

## API, CLI, UI, privacy, and approval

- `POST /agent-failover/evaluate` accepts only instance and optional policy ID.
- `POST /agent-failover` accepts only instance, decision ID, initiated-by, and
  approval ID; health/risk/capability/freshness claims are not request fields.
- CLI has separate `evaluate-agent-failover` and decision-based
  `failover-agent` commands.
- Driver UI evaluates first, displays exact blockers/candidate, requires the
  fresh decision to match the selected approved fallback, then requires
  confirmation and an approval ID.
- Responses contain normalized IDs, states, blockers, and timestamps only.
  Checkpoint payloads, prompts, transcripts, credentials, and provider-private
  material are not returned.

## Verification

- First full run after implementation: 745 passed, 1 skipped, 3 failed.
  The failures were two unintended global duplicate-validation regressions and
  one stale migration-count assertion; both root causes were corrected.
- Next full run: 748 passed, 1 skipped.
- Final full run after atomic reservation refinement: 748 passed, 1 skipped.
- `python3 -m compileall -q src tests`: passed.
- `git diff --check`: passed.

## Risks

- The implementation deliberately relies on persisted health observations; it
  does not probe providers during evaluation or execution.
- A consumed decision whose external import later fails remains consumed and
  follows the existing paused/reconcile/rollback workflow; it is never replayed.
- Behavioral tests were added after evaluator code began, as disclosed above.

## Independent review hardening

All seven review findings were resolved:

1. expiry is checked again under the final immediate transaction after the
   coordinator reservation is acquired and immediately before CAS consumption;
2. failover transfers the exact immutable checkpoint bound into its decision,
   reloads and verifies it after drain, and never captures a replacement;
3. persisted healthy evidence is combined with non-executing live adapter and
   executable readiness, whose privacy-safe resolved-path digest is decision
   evidence and is re-evaluated at execution;
4. failover contracts enforce enum instances, strict booleans, positive
   integers, unique ordered identifiers, a closed ordered blocker vocabulary,
   aware timestamps, and secret-safe references;
5. evaluation and execution API parsers reject every unknown request field;
6. chronology uses aware datetime instants rather than timestamp text ordering;
7. the pure evaluator rejects foreign policy, health, risk, and checkpoint
   evidence instead of filtering or recording it.

Hardening verification: 134 focused tests passed. Final full suite: 754 passed,
1 skipped. Compileall and diff-check passed.

### Final fence review

- Final CAS comparison now includes the exact readiness evidence references in
  addition to the complete immutable stored-decision equality check. A
  ready-path A to ready-path B race is rejected before reservation, consumption,
  provider import, or epoch mutation.
- After drain, failover reloads exact checkpoint A, verifies persisted equality
  and decision bindings, and applies the decision policy's checkpoint maximum
  age using the current aware clock immediately before transition/import.
  Crossing the policy window leaves the consumed decision and owned reservation
  safely fenced for reconciliation and performs no import or epoch promotion.

### Recoverable pre-import execution

The post-drain blocked state now has a durable `agent_driver_v7`
`FailoverExecution` record. It binds the decision, exact outgoing
epoch/session/provider, checkpoint, and exact operation generation/owner.
State transitions are CAS-controlled:
`reserved -> draining -> blocked_preimport -> recovering -> recovered`, or
`draining -> transition_started`.

Post-drain checkpoint rejection records `blocked_preimport` while retaining the
fence and creates no handoff, incoming epoch, or provider import. The read-only
status route and Driver UI expose that recovery is required. Explicit recovery
requires execution, operator, and approval IDs; rejects caller assertions; and
CAS-claims recovery before the sole external resume attempt. Only a normalized,
exactly bound acknowledged/running/succeeded result releases the exact fence
and atomically marks the execution recovered. Unsupported, failed, mismatched,
unauthorized, stale, or concurrent recovery remains blocked and fenced.

## Commit

`c10b231` — `Add controlled primary driver failover`.
