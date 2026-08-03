# DonutHole and Reusable Approval Facility RCA Extension

## Scope

This extension incorporates the work completed after the original DonutHole
provisioning reliability analysis. It distinguishes implemented source from
procedural guidance, uncommitted project work, and still-planned facilities so
the remediation program does not rebuild working security boundaries or claim
an integration that does not yet exist.

Reviewed source identities:

- Overseer `4b29c9f932ba3f164ddaf8031dd5dfa3a4228086`;
- Roadex `31ead2cb16d0e81ad163585655d50e66b273bace`, including integrated
  approval/publication work from `634a93514d1cecffc5c65acfc4300743f38598e1`;
- DonutHole `4739ea7946ab177b7e36d8b86df524b78d329153`, with its existing
  dirty worktree inspected read-only;
- TheUnderdark `becb2ea` as the unchanged storage-side baseline.

No provisioning plan, approval, service restart, deployment, protected-host
mutation, or worktree cleanup was performed during this analysis.

## What the Later Work Actually Added

### Overseer exact approval projection

Overseer now has an authenticated, read-only
`GET /roadex/approval-status?approval_ref=...` projection. An immutable
`RoadexApprovalBinding` binds an opaque approval reference to exact project,
workspace, resource, authority class, subject, source identity, and source
evidence digest. The binding primitive provides transactional creation,
identical persistence replay is idempotent, changed replay is rejected, and a
source that existed before the binding cannot be retroactively trusted. No
production producer invokes the primitive yet.

The projection strictly decodes canonical stored payloads, recomputes the scope
digest, validates source-specific evidence and state, returns a digest-derived
`decisionVersion`, redacts malformed-source failures, and performs no mutation
on GET. The route supports direct and protected-gateway-prefixed access.

This solves the earlier problem where Roadex could be told that a record
existed without a structural and digest binding to the authoritative Overseer
source.

### Roadex durable approval continuation

Roadex now persists an approval wait bound to the exact project, workspace,
resource, managed thread, approval reference, and decision version. It polls
the Overseer projection, rejects scope mismatch or malformed results, persists
dispatch state before continuation, consumes a one-run grant, and resumes the
same managed thread with a fixed bounded prompt. UI and responsive tests cover
the visible approval-wait lifecycle.

This continuation coordinator is project-neutral at the Roadex boundary. It
can support other projects when an authoritative provider returns the same
normalized exact-scope contract.

### Overseer current-root resolution and TheUnderdark authorization boundary

Overseer already exposes an authoritative current-root resolver used by its
storage review path, while TheUnderdark verifies a root-owned immutable
authorization mapping before mutating only its service-owned registry. These
are reusable boundaries for other storage-backed projects. DonutHole's later
instructions correctly require fresh resolution, but they invoke it as a manual
caller responsibility rather than as part of authoritative bundle construction
and staging.

### Roadex app-publication request intake

Roadex also has an authenticated, durable, default-off request intake for
protected-gateway app publication. It validates a bounded contract and supports
create and exact read. It cannot approve, deploy, activate, edit the gateway,
or change firewall policy. Current records remain `submitted`, and the accepted
route shape is still restricted to `/Roadex/...`.

This is a reusable requester boundary, not a completed publication workflow.

### DonutHole follow-up work

DonutHole's committed follow-up consists of repository instructions that define
the raw eleven-field plan workflow, ordered crew evidence, two current-root
resolver checks, and the stop at independent Roadex human approval. Those
instructions improved agent behavior after repeated stale authorization and
review-order failures, but they are procedural rather than an implemented
client or tested facility consumer.

The DonutHole worktree also contains two distinct uncommitted slices:

- a larger R1 gateway, session, audit, listener-policy, test, and operations
  slice that is valuable but separate from backup provisioning; and
- a v14 review-recovery helper that directly rewrites failed review records,
  is not run by DonutHole's normal test suite, and conflicts with the current
  immutable-successor rule.

Neither slice establishes consumption of the generalized approval facility.
The unrelated R1 slice must retain its own ownership, review, and publication
boundary. The v14 helper must not become the reusable pattern.

## Extended Root-Cause Analysis

### Primary integration cause: the trustworthy halves are not connected

Roadex can consume an exact approval projection and Overseer can produce one,
but no production Overseer source-creation path calls
`stage_bound_roadex_approval`. Its only call sites are tests. Because the
security fix correctly rejects retroactive binding, an already-staged raw
DonutHole plan cannot be made projectable afterward.

The missing operation is prospective atomic publication:

```text
typed intent
  -> authoritative source construction
  -> source plus exact approval binding in one transaction
  -> immutable bundle, preflight, and review outbox
  -> human decision
  -> exact read-only status projection
  -> one durable Roadex continuation
```

Without that transaction, real Roadex waits receive a missing-binding result
even though both services contain locally tested implementation.

### Ownership cause: DonutHole is still manufacturing authority-shaped data

DonutHole's instructions tell an agent to choose plan and evidence IDs, create
crew records, construct a raw plan, and dispatch reviews. That makes the caller
responsible for fields that should be derived by Overseer from current source,
authorization, policy, and reviewer requirements. The duplicated authority
logic is why stale roots, incorrect evidence, and ordering mistakes repeatedly
crossed the approval boundary.

The durable boundary must be:

- DonutHole and Roadex submit bounded intent;
- Overseer resolves authority, builds and binds the exact source, creates the
  review outbox, and owns lifecycle state;
- TheUnderdark validates root-owned authority and mutates only its authorized
  service-owned state;
- Roadex displays the authoritative decision and resumes only the exact paused
  managed thread.

The authoritative builder must invoke the current-root resolver during preview
and again immediately before atomic stage. A changed or ambiguous result
invalidates the preview and writes neither source nor binding. DonutHole should
never copy the resolved reference into caller-controlled raw plan fields.

### Generalization cause: reusable transport, hard-coded source semantics

The Roadex continuation contract is broadly reusable, and Overseer's binding
metadata is project-neutral. Overseer's `roadex-human-decision` implementation,
however, imports and decodes `DonutHoleBackupProvisioningPlan` directly and
maps only the backup-provisioning table. New project workflows cannot safely
register a different source type without changing the central projector.

The answer is a bounded allowlisted source-projector registry, not arbitrary
JSON projection. Each source adapter must own exact decoding, initial-state
rules, evidence validation, decision mapping, and immutable evidence digest.

### Lifecycle cause: approval projection is not execution acceptance

The new projection intentionally maps approved, executed, failed, and
rolled-back DonutHole source states to an approved human decision while varying
`decisionVersion`. That is correct for the question "was this exact scope
approved?" but insufficient for "did the feature complete successfully?"

The original resumable-execution, runtime-attestation, behavior-acceptance, and
successor lifecycle work remains necessary. The lifecycle UI must compose the
existing approval projection rather than create a second approval store or
infer completion from an approved decision.

### Publication cause: requester intake has no authoritative successor

Roadex app-publication requests are durable and default-off, but they have no
bridge to an Overseer/gateway workflow, no post-submission state transitions,
and no approve/deploy/activate operation. The current `/Roadex/...` validation
also prevents the requester from serving as a general protected-app facility.

This does not weaken its safety value. It means the facility must be described
as request intake until a separate authoritative workflow owns review,
approval, deployment, activation, and rollback.

### Process cause: invariants were discovered through a corrective chain

The approval projection was hardened through successive fixes for replay,
canonical decoding, producer-state alignment, archive evidence, malformed
sources, API redaction, and retroactive binding. The final boundary is much
stronger, but the sequence shows that producer and consumer contracts were not
first captured in one executable end-to-end fixture.

Future work must begin with a shared conformance fixture and a harmless full
path before adding another producer. Focused component suites remain required,
but they cannot be the only evidence for a cross-service workflow.

## Revised Remediation Principles

1. Preserve the existing exact projection and Roadex continuation; do not
   create a competing approval table or state model.
2. Make source creation and approval binding one prospective transaction. Do
   not backfill existing unbound sources.
3. Replace raw DonutHole plan construction with bounded typed intent and an
   authoritative Overseer builder.
4. Generalize through an allowlisted typed source adapter registry with
   per-source conformance tests.
5. Keep human decision, execution, runtime attestation, and behavior acceptance
   as separate observable stages.
6. Treat app publication as default-off request intake until its independent
   owner workflow exists.
7. Keep DonutHole's R1 gateway/security slice separate from backup-facility
   readiness and retire the record-rewriting recovery pattern.
8. Require a cross-repository acceptance test that proves source creation,
   binding, decision, projection, one continuation, and exact implementation
   completion without touching protected production state.

## Revised Completion Definition

The expanded feature is complete only when:

- a real typed DonutHole intent atomically creates its authoritative source,
  exact approval binding, passing preflight, immutable bundle, and committed
  review outbox;
- Roadex registers the returned approval reference, observes the exact human
  decision, and resumes the same managed thread once;
- execution is checkpointed and terminal success still requires runtime
  attestation and behavior acceptance;
- another fixture project can implement a new allowlisted source adapter and
  pass the same conformance kit without copying DonutHole logic;
- publication requests have an explicit authoritative handoff or continue to
  report `submitted` without implying deployment;
- DonutHole no longer documents raw plan/evidence manufacturing as its normal
  workflow; and
- local source, deployed service identity, and harmless integrated acceptance
  evidence are all recorded separately.
