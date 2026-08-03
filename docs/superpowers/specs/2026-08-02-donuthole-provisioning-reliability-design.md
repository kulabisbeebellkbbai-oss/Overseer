# DonutHole Provisioning Reliability Design

> **2026-08-03 extension:** Post-design implementation added Overseer's exact
> source-bound Roadex approval projection and Roadex's durable approval
> continuation and default-off publication requester. The expanded RCA in
> [2026-08-03-donuthole-reusable-approval-facility-analysis.md](2026-08-03-donuthole-reusable-approval-facility-analysis.md)
> is authoritative for the implemented baseline and remaining integration gap.
> No production source-creation path currently creates the required binding, so
> the projection is secure but operationally inert for new raw DonutHole plans.

## Purpose

Prevent future approval-gated provisioning work from using the live protected
environment as its integration test suite. The design keeps immutable plans,
independent human approval, protected root-owned configuration, redacted
diagnostics, and fail-closed execution while moving deterministic failures ahead
of the approval boundary.

## Problem Statement

The DonutHole provisioning feature crossed Overseer workflow state, Roadex plan
production, crew review contracts, TheUnderdark storage behavior, protected root
authorization, systemd activation, and the human approval UI. Each component had
focused tests, but their production composition was not exercised before human
approval. Late failures therefore invalidated immutable evidence and required a
successor plan, fresh reviews, and another approval.

The recurring failure classes were:

- review messages dispatched before their immutable plan existed;
- incomplete or manually formatted crew-review records;
- source identities that were syntactically valid but not resolvable;
- protected authorization and service-owned mutable state being conflated;
- provisioning steps that did not converge safely on exact existing state;
- readiness checks that verified schemas but not real storage behavior;
- installed code differing from the code served by an already-running process;
- execution evidence that could not distinguish materially different runtimes;
- cross-repository tests that replaced critical production collaborators with
  fakes and missed root-relative behavior.

## Goals

- Detect deterministic contract, source, authorization, dependency, and runtime
  failures before final human approval.
- Give Roadex and DonutHole one typed interface for producing a complete,
  immutable provisioning bundle.
- Make plan publication and review dispatch ordered and race-free.
- Make privileged execution idempotent, resumable, and explicit about which
  phase changed host state.
- Require behavior-level acceptance before a plan reaches its terminal success
  state.
- Bind execution evidence to the active runtime, configuration, process, and
  acceptance results.
- Preserve independent human approval and every current fail-closed security
  boundary.

## Non-Goals

- Do not weaken plan or review immutability.
- Do not allow Roadex, DonutHole, or TheUnderdark to write root-owned authority
  mappings.
- Do not transfer approval between different plan or bundle digests.
- Do not automatically execute a DonutHole provisioning plan as part of this
  reliability project.
- Do not introduce a generic privileged command runner.
- Do not redesign unrelated Overseer workflows or storage products.

## Recommended Architecture

The work is an umbrella reliability program divided into four independently
reviewable capability plans. Capability boundaries are used instead of
repository boundaries because the defects occurred where repositories and
services interacted.

### Capability A: Contract and Acceptance Harness

Create a versioned provisioning contract fixture shared by Overseer and
TheUnderdark tests. The fixture defines canonical plan input, crew requirements,
root registration, runtime identity, MCP tool schemas, and behavior-acceptance
requests.

The harness composes the real TheUnderdark registry, read backend, paginator,
authorization verifier, production service, and Overseer adapter. It must cover
a clean installation model and an upgrade model where a service is already
active. It runs without touching protected production paths or consuming real
human approval.

The minimum acceptance path is:

- initialize the MCP session and inspect capabilities;
- retrieve the configured project;
- retrieve the authorized root;
- list the registered root using an empty relative path;
- list a nested directory;
- verify canonical pagination metadata;
- confirm that an installed runtime identity matches the planned identity;
- exercise disposable backup and restore behavior through a test-only fixture.

This capability is foundational. Later capabilities cannot claim completion
until their behavior is represented in this harness.

### Capability B: Typed Bundle and Deterministic Preflight

Introduce one authoritative bundle builder owned by Overseer. Roadex and
DonutHole submit bounded intent and parameters; they do not construct raw plan,
crew, or evidence records.

The builder resolves and validates:

- the exact source commit and reproducible runtime and capability digests;
- canonical root-registration digests and current authorization references;
- every crew owner, related plan, related resource, acceptance criterion, and
  evidence binding;
- protected paths, service identity, dependencies, ports, canonical MCP name,
  endpoint, and rollback prerequisites.

The plan, exact `RoadexApprovalBinding`, preflight, bundle, and review-message
outbox are committed atomically. Binding must be prospective: a pre-existing
unbound source is never backfilled. Dispatch reads only committed outbox
entries, so no reviewer can observe a message for a plan that does not exist.
Review results remain independent immutable records.

Preflight is read-only and produces a digest-bound report. Final human approval
is unavailable until the report passes and all terminal crew evidence matches
the exact bundle digest.

### Capability C: Resumable Execution, Runtime Attestation, and Evidence

Replace the single all-or-nothing execution flow with explicit phases:

- materialize runtime and private configuration;
- register authorized service-owned state;
- activate or migrate the service;
- attest the active runtime;
- run behavior acceptance;
- finalize evidence.

Each operation is convergent. Exact existing users, directories, files,
registrations, and service settings return a verified no-op. Conflicting state
fails with a stable redacted code before destructive mutation. Checkpoints allow
a successor execution to resume from verified state without replaying unrelated
completed work.

Activation always performs an explicit restart or controlled process
replacement after installing a changed runtime. The service health contract
exposes a safe runtime artifact digest, configuration digest, and process-start
identity. Overseer compares those fields with the approved plan before running
behavior acceptance.

Execution evidence records, for each phase and operation:

- start and completion timestamps;
- stable redacted result code;
- changed, verified-no-op, or failed disposition;
- approved runtime and active runtime identities;
- active configuration and process-start identities;
- restart evidence;
- behavior-acceptance results;
- rollback or retained checkpoint state.

A plan reaches terminal success only after active-runtime attestation and
behavior acceptance pass.

### Capability D: Human Lifecycle UI and Operations

Compose the implemented exact Roadex approval projection into the human-decision
surface; do not create a second approval table or projector. Update the surface
to represent lifecycle states
accurately: staged, awaiting reviews, ready for approval, approved, executing,
acceptance failed, rolled back, successor required, and acceptance passed.

Approval remains an independent human action. The UI must not present approval
as completion and must not present handler completion as acceptance. When a
successor is required, the UI explains which immutable input changed and why the
previous approval cannot be reused.

Operator documentation defines the bundle, preflight, review, approval,
execution, acceptance, rollback, and successor procedures. UI and API regression
tests use the same lifecycle fixtures as the backend.

## Data Flow

1. Roadex or DonutHole submits typed provisioning intent to Overseer.
2. Overseer resolves source and authorization state and builds the immutable
   bundle.
3. Overseer runs deterministic read-only preflight.
4. A passing source, exact approval binding, bundle, and review-message outbox
   are committed atomically.
5. The dispatcher releases committed messages to the required crew reviewers.
6. Overseer verifies terminal evidence against the exact bundle digest.
7. The UI enables independent human approval and Roadex observes the exact
   digest-versioned projection.
8. Roadex resumes the same paused managed thread once within the exact scope.
9. The phased executor materializes, registers, activates, and attests state.
10. The acceptance harness exercises the live candidate through its real MCP
   behavior.
11. Overseer records terminal success only when attestation and acceptance pass;
    otherwise it records a checkpointed failure or rollback with a successor
    requirement.

## Error Handling

- Validation failures return stable typed codes and perform no host mutation.
- Preflight preserves the first failing check and exposes only redacted safe
  details.
- Dispatch is idempotent and keyed by the committed outbox record.
- Exact repeated provisioning state returns verified no-op evidence.
- Conflicting existing state fails before replacement or deletion.
- Activation failures retain enough checkpoint state for safe diagnosis while
  applying the declared rollback boundary.
- Acceptance failures cannot produce terminal success, even when every
  provisioning handler returned successfully.
- Evidence or runtime identity mismatch requires a new immutable successor; it
  cannot be repaired by editing existing records.
- Repeated counterfeit or mismatched evidence continues to be denied and routed
  to the existing Odo risk-assessment workflow.

## Security Boundaries

- Root-owned authorization configuration remains immutable to service code.
- TheUnderdark mutates only its authorized service-owned registry and backup
  state.
- Privileged execution remains an exact allowlist of plan operations.
- Secrets, tokens, host paths, and private subprocess output remain redacted.
- Human approval remains bound to the exact immutable bundle digest.
- The test harness uses disposable roots and credentials and cannot activate
  production routes or services.
- Runtime attestation exposes digests and process identity, never secret
  configuration content.

## Testing Strategy

Every implementation task follows test-driven development: add a focused
failing test, observe the expected failure, implement the minimum behavior, run
focused tests, then run the capability regression suite.

Required test layers are:

- unit tests for validation, typed builders, state transitions, and idempotency;
- contract tests using versioned fixtures consumed by both repositories;
- composed in-process tests using real production collaborators;
- service-lifecycle tests for clean install, active-service upgrade, restart,
  stale-runtime detection, and rollback;
- API and UI tests for every lifecycle state and approval blocker;
- a final read-only live acceptance sequence after separately approved
  deployment.

Mocks remain appropriate for failure injection, but a mock cannot be the sole
test of a cross-repository or service-lifecycle contract.

## Delivery Decomposition and Dependencies

The post-design approval projection and Roadex continuation are implemented
baseline components. They do not complete Capability B because the authoritative
producer does not yet create a binding, and they do not complete Capability D
because approval status is only one input to the broader execution/acceptance
lifecycle. Follow the delta plan in
`docs/superpowers/plans/2026-08-03-donuthole-reusable-approval-facility-remediation.md`
before resuming the original capability sequence.

The capability plans are delivered in this order:

1. Contract and acceptance harness, which establishes the executable definition
   of correct behavior.
2. Typed bundle and deterministic preflight, which moves known failures before
   approval.
3. Resumable execution, runtime attestation, and evidence, which makes approved
   mutation convergent and verifiable.
4. Human lifecycle UI and operations, which exposes the authoritative backend
   lifecycle without inventing a parallel state model.

Each capability must produce independently testable software and a focused
commit series. Cross-repository changes use matching contract fixtures and
record the reviewed source identities used by the integration suite.

## Ownership

- Overseer owns bundle construction, preflight, review dispatch, lifecycle
  state, execution evidence, acceptance gating, and UI/API representation.
- TheUnderdark owns storage behavior, root-path handling, idempotent root
  registration, health attestation, and its side of the shared contract.
- Roadex and DonutHole consume the typed bundle interface and provide intent;
  they do not manufacture approval evidence.
- Crew reviewers continue enforcing their typed domain policies.
- Sisko remains the final independent human approval boundary.

## Completion Criteria

The reliability project is complete when:

- malformed or incomplete bundle requests fail before immutable review records
  are published;
- reviewers cannot observe a message whose plan is absent;
- nonexistent source identity fails before approval;
- exact retry and active-service upgrade scenarios pass without false conflict;
- the active process attests the approved runtime and configuration identities;
- root-relative and nested storage behavior pass through the real composed
  service;
- terminal success is impossible without behavior acceptance;
- evidence distinguishes different runtimes and executions;
- the UI accurately displays every lifecycle state and successor condition;
- all focused, cross-repository, service-lifecycle, API, and UI regressions pass;
- no test or implementation weakens protected configuration ownership or the
  independent human approval boundary.

## Approval Boundaries

Approval of this design authorizes writing implementation plans only. It does
not authorize code changes, commits beyond planning documents, service restarts,
protected-host mutations, DonutHole provisioning, or deployment. Those actions
retain their existing review and approval gates.
