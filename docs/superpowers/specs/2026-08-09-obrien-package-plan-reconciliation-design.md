# O'Brien Package Plan Reconciliation Design

**Date:** 2026-08-09
**Status:** Approved design; written-spec review requested

## Problem

Overseer's station audit calls `plan_package_updates_status()` and persists a
new APT refresh/upgrade pair, but it does not queue either plan for O'Brien or
Sisko. Repeated audits therefore accumulate executable refresh plans and
approval-blocked upgrade plans without advancing them.

The generic O'Brien crew dispatcher also treats any non-storage
`related_resource_id` as a package name. That converted
`port.loopback.8798` into an APT target, allowed Sisko-level approval to be
recorded, and reached the package dry-run before failing.

## Goals

- Route every current inspection-generated APT plan through an observable,
  exact-plan crew workflow.
- Prevent resource identifiers, ports, services, and other opaque IDs from
  becoming package arguments.
- Cancel stale provenance-backed unexecuted inspection plans and report
  unverifiable legacy plans without deleting audit history.
- Advance current stalled plans through their allowed approval and execution
  gates without broad dispatch or implicit human approval.
- Make reconciliation safe and idempotent when periodic audits repeat.

## Non-Goals

- Do not install, update, or remove packages merely by running a station
  audit or reconciliation preview.
- Do not automatically archive canceled plans; the existing approved archive
  workflow remains authoritative.
- Do not cancel or rewrite completed, failed, or blocked execution history.
- Do not auto-enable an admin adapter.
- Do not change firewall, service, gateway, or system resource policy.

## Architecture

### Durable inspection evidence and provenance

Every successful package inspection used for planning is persisted as an
immutable `PackageInspectionRecord` before any plan or crew message is
created. The record contains the snapshot ID, capture time, exact inspection
command, exit code, stderr, the complete normalized update set, and its
fingerprint. Failed inspections may be persisted for diagnostics but can never
be planning inputs.

Persisted snapshot identity is content-addressed: the ID contains the capture
timestamp plus the complete-record SHA-256 digest. If an ID already exists,
the store accepts it only when every persisted field is identical; otherwise
the transaction fails. Tests that inject equal timestamps with different
results therefore cannot overwrite immutable evidence.

The store implements package inspection as an insert-only primitive rather
than a generic upsert. Before package workflow transactions are added,
execution-result persistence must also honor the existing outer
`agent_transaction()` instead of committing independently.

Normalization emits one object per package with exactly these fields:
`name`, `architecture`, `installed_version`, `candidate_version`, and
`repository`. Missing values become empty strings. Objects are sorted by
`(name, architecture)`, encoded as compact UTF-8 JSON with sorted keys, and
hashed with SHA-256. The fingerprint therefore represents the complete
successful inspection, not only the requested package subset.

Inspection-generated APT plans gain optional, backward-compatible provenance:

- `plan_origin=package_inspection`
- `source_snapshot_id`
- `source_snapshot_captured_at`
- `package_state_fingerprint`
- `maintenance_batch_id`
- `selected_package_names`

`maintenance_batch_id` is deterministically derived from the immutable source
package-state fingerprint and the SHA-256 fingerprint of the sorted, unique
selected package names. An unfiltered batch records the complete normalized
update set as its selection. A later snapshot with identical complete state and
selection reuses the active, unexecuted batch and is attached through immutable
`PackageReconciliationEvidence` rather than creating another plan pair. A
changed state or selection creates a new batch. The plan retains its original
`source_snapshot_id`; each reconciliation evidence row records the newer
snapshot ID, batch ID, observation time, outcome, and exact plan/message IDs.
Plan IDs are never parsed to decide origin, freshness, or membership.

Legacy plans without explicit `plan_origin` and persisted snapshot evidence are
ambiguous. Reconciliation reports them as `manual_review_required` and leaves
them active; it never classifies or cancels them from ID text. A later,
separately approved migration may attach provenance only when durable evidence
can prove it.

For the existing backlog, the operator surface emits an exact legacy-candidate
report containing plan IDs, typed kind/owner/target fields, and all execution
evidence. Cleanup requires a separately approved record containing the exact
plan-ID allowlist. Apply mode reloads every allowlisted plan and cancels it only
when it is still O'Brien-owned APT work, active, unarchived, and has no
execution evidence. Any mismatch fails the whole cleanup transaction. This
bounded migration never infers origin from an ID and never auto-approves,
executes, or archives a legacy plan.

### Reconciliation

A package-plan reconciler accepts one newly persisted successful inspection
record and examines only active O'Brien plans of kind `apt_update` or
`apt_upgrade` with `plan_origin=package_inspection` and a resolvable persisted
source snapshot.

It performs these operations in order:

1. Preserve any plan with completed, failed, or blocked execution evidence.
   An execution attempt is present if any execution row names the plan; the
   decision never depends on whichever row happens to load last.
2. Report ambiguous legacy plans for manual review without mutating them.
3. Cancel provenance-backed, fingerprint-mismatched plans with no execution
   evidence using a durable
   `superseded_by_package_snapshot:<snapshot-id>` reason.
4. Reuse the active, unexecuted maintenance batch whose complete fingerprint
   and selected package set match, attaching the newer snapshot as evidence
   instead of creating duplicate plans.
5. Create at most one exact crew message per current plan and workflow stage:
   - `apt_update` with no explicit approval queues O'Brien only when live
     execution is activated; otherwise it waits for activation.
   - unapproved `apt_upgrade` queues Sisko.
   - approved `apt_upgrade` queues O'Brien only when live execution is
     activated; otherwise it waits for activation.
6. Return counts, exact plan/message IDs, cancellation reasons, ambiguous
   legacy IDs, and the next
   gate. Repeating reconciliation against the same snapshot changes nothing.

Cancellation is the cleanup boundary. It prevents stale execution while
preserving the immutable plan and making it eligible for the existing,
separately approved archive lifecycle.

### Exact crew routing

O'Brien accepts package work only through `related_plan_id`:

- The plan must exist.
- Its owner must be O'Brien.
- Its kind must be `apt_update` or `apt_upgrade`.
- Its provenance and package fingerprint must still match a fresh inspection
  before execution.

The execution dispatcher performs a new read-only inspection immediately
before calling the admin executor. That inspection is persisted and compared
with the plan's complete fingerprint and selected package set. A mismatch,
missing selected package, failed inspection, canceled plan, or superseded
message closes the message with a correction result and performs no APT
mutation.

`related_resource_id` remains an opaque resource identity and is never copied
into an APT command. O'Brien messages without an exact package plan may perform
a read-only general package inspection, but they cannot stage a filtered
package plan or execute package commands.

Explicit package filters remain available only through the typed package-plan
API/CLI argument. Every requested package must appear in the same successful
fresh inspection. If any requested package is absent, the request returns no
plans, reports `missing_packages`, and performs no plan, batch, approval, crew
message, or host mutation. This all-or-nothing validation occurs before IDs are
allocated.

### Durable workflow identity and stale messages

Package workflow messages use deterministic identities derived from
`maintenance_batch_id`, exact `related_plan_id`, and stage (`sisko_approval` or
`obrien_execution`). Deduplication examines every prior message with that key,
not only open messages. A terminal message is never silently recreated for the
same plan and stage.

When reconciliation cancels or supersedes a plan, all open linked messages are
atomically closed with `correction_requested` and evidence naming the successor
snapshot. Dispatch also reloads both plan and message under the store
transaction and rejects closed, superseded, canceled, or mismatched records.
This makes delayed dispatcher work harmless.

Package dispatch does not use the current load-close-dispatch-save pattern.
Its final transition is compare-and-set under one `agent_transaction()`: reload
the exact message, validate that it is still open and unchanged, reload the
plan and snapshot, then save the decision and evidence. A stale in-memory
message can never acknowledge or reopen a message that reconciliation already
closed.

### Authoritative Sisko decision semantics

Only the package-specific Sisko dispatcher may create Sisko approval for this
workflow. It must be processing an open, non-superseded message owned by Sisko,
requested by O'Brien, whose exact `related_plan_id` resolves to a current,
provenance-backed `approval_level=sisko` APT plan in the same maintenance
batch. The trusted dispatcher actor is recorded as `sisko`; caller-supplied
`approved_by` text cannot satisfy this transition. Generic admin approval
model, CLI, and API paths must reject any `plan_origin=package_inspection`,
`approval_level=sisko` plan; this is an enforced model invariant, not merely a
reconciler convention. Approval, Sisko-message closure, and audit evidence
occur in one store transaction. When live execution is activated, the same
transaction also creates the one exact O'Brien execution message. When it is
not activated, the transaction records `waiting_execution_activation` and
creates no executable O'Brien message.

An exact Sisko crew message distinguishes approval levels:

- A complete, current `approval_level=sisko` package plan is approved by
  Sisko and, only when live execution is activated, queues one exact O'Brien
  execution message; otherwise it becomes `waiting_execution_activation`.
- A human-level plan remains `waiting_human_approval`; Sisko cannot convert it
  into Sisko approval.
- Broad IDs such as `all`, missing plans, stale plans, canceled plans, and
  non-O'Brien/non-APT plans fail closed.

Sisko dispatch records approval but does not run APT commands. O'Brien remains
the execution owner and rechecks freshness, adapter state, and policy before
advancing the exact plan.

`_advance_obrien_package_plan` no longer writes Sisko approval. For an
unapproved Sisko-level plan it can only ensure the exact Sisko message exists.
The generic admin approval function remains available to its existing explicit
operator workflows, but package reconciliation cannot call it as a substitute
for the authoritative Sisko-message transition.

### Audit and explicit reconciliation surfaces

The station audit uses the reconciler after successful package inspection.
It may persist plans, cancellations, and exact crew messages, but it never
runs package commands itself. The existing runtime dispatcher processes those
messages on later ticks, preserving visible ownership transitions.

The same reconciliation operation is exposed through a dedicated CLI command
and authenticated local API endpoint for deterministic testing and operator
recovery. It supports a non-mutating preview mode.

### Live-execution activation boundary

Source deployment does not activate automatic package execution. A new
store-backed feature activation record,
`maintenance.package_reconciliation_live_execution`, defaults to absent/off
and requires separate explicit human approval. Station audit may inspect,
persist evidence, reconcile, cancel stale provenance-backed plans, and route
Sisko decisions while activation is off, but any approved/no-approval O'Brien
plan stops at `waiting_execution_activation`; no executable O'Brien message is
opened for dispatch.

After that exact activation record is approved, reconciliation may queue the
deterministic O'Brien execution message. Adapter enablement, exact plan
approval, policy, and immediate freshness checks remain independent mandatory
gates. Preview and tests inject fake inspectors/runners and never create or
honor live activation. The legacy package-maintenance-cycle command/API must be
refactored onto this workflow or explicitly disabled; it may not bypass the
activation record by auto-enabling adapters, auto-approving Sisko plans, or
executing newly staged work.

Activation is a dedicated typed record with pending/approved/revoked state,
scope, creator, authoritative approver identity, decision time, and evidence.
Its approval endpoint derives the human identity from authenticated server
context and accepts no caller-supplied `decided_by` value. CLI and generic
claim-approval paths may create, inspect, or revoke a request but cannot mark
it approved. Source-design approval and plan-level Sisko approval do not imply
feature activation.

The activation, exact-message, and immediate-freshness requirements are
enforced centrally by `execute_admin_change_status()` (or the lower model
operation it calls) for every provenance-backed APT plan. Direct execution,
legacy maintenance-cycle, API, and CLI entrypoints therefore fail closed with
`waiting_execution_activation` or `freshness_revalidation_required`; they
cannot bypass the package workflow by calling the generic executor.

The authoritative Sisko transition is implemented as one package-specific
store operation on a single connection. It does not call wrapper functions
that open a second connection. Plan approval, source-message decision, audit
evidence, and conditional O'Brien-message insertion either all commit or all
roll back.

## Safety and Failure Handling

- Failed package inspection creates no plans, cancellations, approvals, or
  execution messages.
- A package set changing between planning and O'Brien execution closes the
  execution message, records a blocked/correction result, and requires a
  successor snapshot. Plans with prior blocked evidence are preserved for
  review and are never stale-canceled automatically.
- Reconciliation never dispatches a broad crew queue; every generated message
  names one exact plan.
- Existing adapter, rollback, verification, and policy checks remain mandatory.
- Cancellation and message creation are committed atomically after the store's
  nested commit behavior is corrected; a retry must converge without
  duplicates.
- Historical `port.loopback.8798` remains preserved as failed evidence and is
  not rewritten.

## Verification

Tests must prove:

- Station audits create exact O'Brien/Sisko messages instead of an unadvanced
  backlog.
- `port.loopback.8798` never becomes a package target or command argument.
- Any requested package absent from fresh APT results produces zero plans.
- Current matching batches are reused and messages are deduplicated.
- Stale provenance-backed plans without execution evidence are canceled with
  evidence; ambiguous legacy plans are reported and retained.
- Completed, failed, and blocked plans are never canceled by reconciliation.
- Sisko approves only exact current Sisko-level plans and queues O'Brien only
  when live execution is activated.
- Human-level plans remain waiting for human approval.
- O'Brien revalidates freshness and advances only exact approved/no-approval
  package plans.
- Terminal and superseded messages cannot be recreated or dispatched.
- Live execution remains blocked without the separate activation record.
- The legacy maintenance-cycle surface cannot bypass the exact-message flow.
- Legacy backlog cleanup requires an approved exact-ID allowlist and fails
  atomically if any candidate changed after review.
- Preview mode performs no mutations.
- Focused tests, full regression tests, type checks, and lint all pass.

## Operational Boundaries

Implementation and tests may run in parallel only across non-conflicting
files and bounded processes. No live APT execution, service restart, adapter
enablement, stale-record cleanup, or deployment is authorized by approving
this source design. Live cleanup and deployment require their normal exact
Overseer records and approval gates.
