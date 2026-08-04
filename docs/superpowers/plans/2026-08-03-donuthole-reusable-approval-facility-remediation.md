# DonutHole Reusable Approval Facility Delta Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` and apply
> `superpowers:test-driven-development`, `superpowers:requesting-code-review`,
> and `superpowers:verification-before-completion` at the gates below.

**Goal:** Connect the already-implemented exact Overseer approval projection to
real typed DonutHole plan creation, preserve Roadex's durable continuation, and
turn the source-specific implementation into a bounded reusable facility for
future project workflows.

**Architecture:** Extend Capability B so authoritative source, approval binding,
preflight, bundle, and review outbox are created prospectively in one Overseer
transaction. Keep the existing read-only projection and Roadex continuation as
the only approval-status path. Generalize source semantics through an
allowlisted adapter registry, add thin typed consumers, then prove the harmless
full path with a shared cross-repository conformance fixture.

**Baseline:** Overseer `4b29c9f` provides the exact projection but no production
binding caller. Roadex `31ead2c` provides durable approval continuation and
default-off publication request intake. DonutHole
`4739ea7946ab177b7e36d8b86df524b78d329153` provides manual workflow guidance
only. This plan does not recreate those working pieces.

## Constraints

- Never bind a pre-existing source retroactively.
- Never allow a project caller to provide authorization references, evidence
  digests, crew IDs, approval fields, execution fields, or source status.
- Never add an arbitrary JSON projector or caller-supplied decision mapping.
- Do not equate human approval with successful execution or acceptance.
- Do not mutate or publish DonutHole's unrelated dirty R1 gateway/security
  slice as part of this work.
- Do not use or generalize the uncommitted v14 review-record rewrite helper.
- Source commits do not authorize deployment, restart, protected-host
  mutation, publication, or DonutHole provisioning.

## Dependency Placement

This is an integration overlay, not a replacement for the original capability
plans. Freeze Task 0's approval-source fixture first. Execute Task 2 against the
implemented projection baseline. Execute Task 1 as part of Capability B Task 3
after `provisioning_bundle.py` and its typed contracts exist. Execute Tasks 3
and 4 after that single atomic-persistence slice. Execute Task 5 with Capability
D after Capability C's execution records are stable. Execute Task 6 last. Task
7 produces a separate planning artifact and does not block the backup
provisioning acceptance path.

---

### Task 0: Freeze the approval-source conformance contract

**Files:**

- Create in Overseer: `tests/fixtures/approval_source_contract_v1.json`
- Create in Overseer: `tests/test_approval_source_cross_repo_contract.py`
- Mirror in Roadex: `tests/fixtures/approval_source_contract_v1.json`
- Create in Roadex: `tests/approvalSourceContract.test.ts`
- Mirror in DonutHole: `tests/fixtures/approval_source_contract_v1.json`
- Create in DonutHole: `tests/tools/test_approval_source_contract.py`

Overseer owns the canonical fixture. Roadex and DonutHole mirror its exact
canonical bytes; neither consumer extends the fixture independently.

- [ ] Define exact safe cases for pending, approved, revision requested,
  rejected, provider failure, changed replay, exact replay, malformed payload,
  and scope mismatch.
- [ ] Define exact public field names and types. The stage locator contains
  stable binding identity and scope only; `decisionVersion` exists only in the
  status projection returned after a status read.
- [ ] Add failing canonical-equality checks in each repository before adapter or
  producer changes begin. Run Overseer with `pytest`, Roadex with
  `npm test -- tests/approvalSourceContract.test.ts`, and DonutHole with its
  explicitly documented Python test command.
- [ ] Record the fixture digest in a reviewed cross-repository SHA manifest.
- [ ] Commit and review the fixture in Overseer first, then mirror it in Roadex
  and DonutHole as separate owned commits.

---

### Task 1: Integrate atomic binding into Capability B Task 3

**Files:**

- Modify: `src/overseer/provisioning_bundle.py`
- Modify: `src/overseer/backup_provisioning.py`
- Reuse: `src/overseer/roadex_approval_status.py`
- Modify: `tests/test_provisioning_bundle.py`
- Modify: `tests/test_backup_provisioning.py`
- Modify: `tests/test_roadex_approval_status.py`

**Interfaces:**

- Consume existing `RoadexApprovalBindingDraft` and
  `stage_bound_roadex_approval()`.
- Make `stage_authoritative_bundle()` create the backup-provisioning source and
  exact binding inside the same `SQLiteStore.agent_transaction()` as bundle,
  preflight, and outbox persistence.
- Resolve current-root authority during preview and again immediately before
  the transaction. Treat changed or ambiguous resolution as a stale preview and
  persist nothing.
- Return stable `approval_ref` and `scope_digest` only from authoritative
  persisted records. `decisionVersion` comes exclusively from the exact status
  GET after a decision is projected.

- [ ] Write a failing test proving a typed intent produces source, binding,
  bundle, report, and outbox together.
- [ ] Write a failing injected-error test at each persistence boundary and
  assert no row from the transaction survives.
- [ ] Write a failing exact-replay test that reruns the outer authoritative
  build and current-root validation, then proves the inner source-persistence
  callback is not invoked after exact persisted equality is confirmed.
- [ ] Write a failing changed-replay test and assert the immutable binding and
  source remain unchanged.
- [ ] Write a failing current-root drift test and assert source, binding,
  bundle, report, and outbox remain absent.
- [ ] Implement the minimum prospective binding call in the authoritative
  staging service; do not add a second transaction.
- [ ] Run:

  ```bash
  pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_roadex_approval_status.py -k 'atomic or binding or replay or rollback'
  ```

- [ ] Request security review for transaction boundaries, no-backfill behavior,
  exact digest inputs, callback re-entry, and redaction.
- [ ] Complete and commit this work inside Capability B Task 3's single
  `Persist provisioning bundles atomically` slice. Do not create a second
  implementation task or follow-up commit for the same persistence boundary.

---

### Task 2: Introduce an allowlisted approval-source adapter registry

**Files:**

- Create: `src/overseer/approval_source_registry.py`
- Modify: `src/overseer/roadex_approval_status.py`
- Modify: `src/overseer/backup_provisioning.py`
- Create: `tests/test_approval_source_registry.py`
- Modify: `tests/test_roadex_approval_status.py`

**Interfaces:**

```python
@dataclass(frozen=True)
class ProjectedDecision:
    decision: Literal[
        "pending", "approved", "changes-requested", "rejected", "expired", "revoked"
    ]
    source_status: str
    updated_at: str


class ApprovalSourceStore(Protocol):
    def registered_source_exists(self, accessor: str, source_id: str) -> bool: ...
    def load_registered_source_payload(self, accessor: str, source_id: str) -> str: ...


@dataclass(frozen=True)
class ApprovalSourceAdapter:
    source_kind: str
    accessor: str
    decode_exact: Callable[[str], object]
    require_initial: Callable[[object], None]
    evidence_digest: Callable[[object], str]
    project_decision: Callable[[ApprovalSourceStore, object, object], ProjectedDecision]
```

`build_approval_source_registry()` returns an immutable `MappingProxyType` with
the exact built-in adapters. Each built-in adapter selects a code-owned opaque
accessor; production `SQLiteStore` maps only the real `admin-change-plan` and
`backup-provisioning-plan` accessors to exact prospective-existence and
payload-loading methods and rejects every other value. No table name, SQL,
adapter, accessor, or decision function comes from a request. The selected adapter
owns strict decoding and semantics. Use a narrow `Protocol` and `TYPE_CHECKING`
imports so the registry does not import `SQLiteStore` or create a store/projector
cycle.

Change `RoadexApprovalBindingDraft.source_kind` and
`RoadexApprovalBinding.source_kind` from a two-value `Literal` to a validated
opaque string. Draft validation, stored-binding decoding,
`_source_exists_for_draft()`, and `load_exact_bound_source()` must all resolve
the kind through the same immutable registry. Unknown kinds, duplicate kinds,
non-canonical or extra-field payloads, invalid initial states, decision values
outside the literal set above, loader/source identity mismatch, and digest
mismatch fail closed. The built-in adapters reproduce the current exact
behavior for `admin-plan` and DonutHole backup provisioning.

Core `stage_bound_roadex_approval()` and projection functions accept an
explicit immutable registry parameter defaulting to the production registry.
Authenticated API handlers never accept or override that parameter. Tests may
inject a fixture registry with an in-memory protocol implementation; this is
the only test-only extension point.

- [ ] Write failing parity tests that run every current admin and DonutHole
  projection fixture through both the legacy expectation and the registry.
- [ ] Write failing tests for unknown and duplicate kinds, non-canonical and
  extra-field payloads, invalid initial state, unsupported projected decision,
  loader/source identity mismatch, and digest mismatch.
- [ ] Extract source-specific decoding, initial-state validation, evidence
  validation, and decision mapping behind the adapter without changing the
  public projection shape.
- [ ] Add a harmless fixture-project adapter in tests only and prove it can
  prospectively stage a source plus binding, then reuse scope digest, status
  GET, and decision version without importing DonutHole types.
- [ ] Inject the fixture registry only into core stage/project functions under
  test and use an in-memory `ApprovalSourceStore`/binding-store implementation
  that owns the fixture payload. Do not add a fixture accessor, table, or branch
  to production `SQLiteStore` or the authenticated API. A future real project
  adds its reviewed code-owned accessor, persistence methods, adapter, and
  schema tests as one coherent source implementation.
- [ ] Run:

  ```bash
  pytest -q tests/test_approval_source_registry.py tests/test_roadex_approval_status.py tests/test_ui_regression.py -k 'approval_status or source_registry'
  ```

- [ ] Request security and compatibility review; specifically reject any
  proposal that accepts caller-supplied schema or decision functions.
- [ ] Commit with message `Generalize exact approval source projection`.

---

### Task 3: Make Roadex consume authoritative staging results

**Repositories and files:**

- Overseer: modify `src/overseer/api.py`, `tests/test_core.py`, and
  `tests/test_ui_regression.py`.
- Roadex: modify `src/server/approvalWorkflowMcp.ts`,
  `src/server/approvalWorkflowHost.ts`, `src/server/sessionService.ts`, and
  their matching tests.
- Roadex: preserve `src/server/approvalStatusProvider.ts`,
  `src/server/approvalCoordinator.ts`, and `src/server/approvalContinuation.ts`
  as the established continuation path unless a focused failing test requires
  a change.

**Contract:** typed staging returns a normalized exact approval locator:

```json
{
  "provider": "overseer",
  "approvalRef": "opaque",
  "projectId": "project.donuthole",
  "workspaceId": "workspace.donuthole",
  "resourceRef": "storage.donuthole",
  "authorityClass": "project-workflow",
  "scopeDigest": "sha256:..."
}
```

- [ ] Write a failing Overseer API test proving the locator is derived from the
  persisted binding and cannot be caller-overridden.
- [ ] Write a failing Roadex test that submits typed intent, registers only the
  returned approval reference, and rejects project/workspace/resource mismatch.
- [ ] Implement the thin transport adapter; do not persist a parallel lifecycle
  or decision record in Roadex.
- [ ] Prove approval polling remains read-only and a stable approved decision
  dispatches one continuation to the same managed thread.
- [ ] Prove revision, rejection, provider delay, session close, ambiguous
  dispatch, and restart recovery remain fail closed.
- [ ] Run Roadex:

  ```bash
  npm test -- tests/approvalLifecycleIntegration.test.ts tests/approvalStatusProvider.test.ts tests/approvalCoordinator.test.ts tests/approvalWorkflowMcp.test.ts
  npm run lint
  npm run build
  ```

- [ ] Run the focused Overseer API and projection suites.
- [ ] Record and review separate source commits for each repository.

---

### Task 4: Replace DonutHole's raw workflow with a typed consumer

**DonutHole files:**

- Create: `src/tools/backup_provisioning_intent.py`
- Create: `tests/tools/test_backup_provisioning_intent.py`
- Modify: `AGENTS.md`
- Modify: `docs/operations/theunderdark-backup-root-materialization-plan.md`
- Do not modify the unrelated R1 gateway/session/listener source slice.

**Consumer boundary:** DonutHole supplies only bounded request identity,
project/resource/root intent, policy revision, source commit, reason, and an
optional predecessor plan. Overseer supplies current-root authorization,
runtime and capability digests, plan digest, evidence IDs, approval reference,
crew requirements, and execution steps.

- [ ] Write failing tests proving forbidden authority-shaped fields are rejected
  before transport.
- [ ] Write a failing contract test against the versioned Overseer typed-intent
  fixture.
- [ ] Implement a thin client or reviewed CLI invocation that supports preview,
  authoritative stage, and exact status only.
- [ ] Replace the raw eleven-field and manual crew-record instructions in
  `AGENTS.md` with the typed-intent workflow and returned authoritative IDs.
- [ ] Mark the old materialization snapshot as historical/superseded; never
  replace its failed read evidence with invented current state.
- [ ] Confirm ownership of
  `src/tools/backup_provisioning_review_recovery.py`; archive or exclude it from
  executable publication because terminal review corrections require immutable
  successors rather than record rewriting.
- [ ] Run DonutHole's Python consumer tests explicitly in addition to its normal
  TypeScript suite; add the command to repository documentation so the test is
  not silently skipped.
- [ ] Request review from both the DonutHole owner and Overseer contract owner.
- [ ] Commit only the typed-consumer slice after the existing dirty work is
  isolated safely.

---

### Task 5: Complete lifecycle composition without duplicating approval state

**Files:**

- Modify: `src/overseer/roadex_approval_status.py`
- Modify: `src/overseer/backup_provisioning_lifecycle.py`
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/ui.py`
- Modify: `tests/test_backup_provisioning_lifecycle.py`
- Modify: `tests/test_ui_regression.py`
- Modify: `tests/test_ui_full_regression.py`

- [ ] Define a frozen, exact `RoadexApprovalProjection` DTO and strict public
  parser in `roadex_approval_status.py`; lifecycle snapshots consume that type,
  not `Mapping[str, object]`.
- [ ] Make lifecycle snapshots embed or reference the exact typed approval
  projection and its `decisionVersion`.
- [ ] Treat a legacy unbound source as `successor_required`. Treat a missing
  binding for a newly typed source or a malformed projection as fail-closed
  integrity failure, never pending or approved.
- [ ] Do not add a second approval table, binding, projector, or browser-owned
  readiness calculation.
- [ ] Render human decision, execution, runtime attestation, behavior
  acceptance, rollback, and successor state as separate facts.
- [ ] Assert that approved, executed, failed, and rolled-back sources may retain
  an approved human decision while only `acceptance_passed` is success.
- [ ] Assert stale predecessors never regain actions and every disabled action
  exposes an accessible authoritative reason.
- [ ] Run all Capability D backend, API, UI, responsive, and accessibility
  suites and request workflow/UI review.

---

### Task 6: Add the reusable cross-repository conformance and acceptance kit

**Files:**

- Reuse in Overseer: `tests/fixtures/approval_source_contract_v1.json`
- Extend in Overseer: `tests/test_approval_source_cross_repo_contract.py`
- Reuse in Roadex: `tests/fixtures/approval_source_contract_v1.json`
- Create in Roadex: `tests/approvalFacilityIntegration.test.ts`
- Reuse in DonutHole: `tests/fixtures/approval_source_contract_v1.json`
- Create in DonutHole: `tests/tools/test_backup_provisioning_contract.py`
- Extend Capability A's real disposable TheUnderdark MCP/storage harness.

- [ ] Re-run Task 0's byte-for-byte canonical fixture equality and fail before
  integration if any consumer drifted.
- [ ] Compose a disposable harmless path: typed DonutHole intent, atomic
  Overseer source/binding/bundle/outbox, real local crew-evidence handlers,
  approver-independence validation, the real local Overseer human-decision API
  using a disposable fixture-human identity, authenticated status read, and one
  Roadex continuation. Only the external human interaction is synthetic; the
  source transition is never produced by direct row or status rewriting.
  Extend Capability A to exercise the real TheUnderdark registry, read backend,
  production service, root-relative listing, disposable encrypted backup, and
  disposable restore behavior before runtime attestation and behavior
  acceptance can pass.
- [ ] Use simulation only for continuation dispatch and injected failure paths;
  it is never the sole evidence for terminal implementation success, storage
  behavior, runtime attestation, or acceptance.
- [ ] Prove no protected production path, live approval, privileged host
  provisioning adapter, gateway mutation, firewall action, or service restart
  is reachable from the harness. The real TheUnderdark collaborators operate
  only on disposable fixture roots.
- [ ] Add a fixture-only second project adapter and prove reuse without copying
  DonutHole's source decoder.
- [ ] Run each repository's focused and full local suite, then run canonical
  fixture equality from a clean cross-repository harness.
- [ ] Commit in owner order: canonical Overseer fixture/harness, Roadex
  consumer/integration, then DonutHole consumer. Record the reviewed SHA for
  every repository in one manifest and require clean owned-file diffs before
  updating a downstream mirror.
- [ ] Use `superpowers:requesting-code-review` for contract, security, and
  operational-boundary review.

---

### Task 7: Separate the publication-workflow plan

**Files:**

- Follow exactly:
  `docs/superpowers/plans/2026-08-03-protected-app-publication-workflow.md`
- Do not modify Roadex, Overseer, Protected Service Gateway, firewall, or IDS
  source under this backup-facility plan.

- [x] Preserve the requester's inability to approve, deploy, activate, or edit
  gateway/firewall state.
- [x] Keep status exactly `submitted` until an authoritative external workflow
  reference and read-only status projection are designed and approved.
- [x] If prefixes beyond `/Roadex/...` are required, use the separate plan's
  Protected Service Gateway prefix registry, Overseer ownership, compatibility
  tests, security/IDS review, deployment, activation, rollback, and distinct
  approvals. Roadex alone cannot authorize or assert that gateway support.
- [x] Preserve separate exact approval records for Roadex, Overseer, gateway,
  firewall/IDS, and each project application.

## Post-Implementation Operations Handoff

This is a later approval-gated sequence, not implementation authorization:

1. Publish each reviewed repository commit separately and record the remote
   reviewed SHA manifest.
2. Stage schema migration and service-deployment plans for Overseer and Roadex;
   record backups, exact artifacts, configuration, rollback targets, and
   deployed-source verification.
3. Obtain exact human approval and deploy Overseer first, verify authenticated
   health and the no-mutation status route, then separately approve and deploy
   Roadex and verify managed-thread continuation readiness.
4. Run a separately approved harmless live projection/continuation fixture and
   correlate only redacted approval reference, scope digest, decision version,
   wait, continuation, and managed-thread identities.
5. Create a fresh typed DonutHole successor. Legacy unbound plans remain
   historical and cannot be backfilled. Obtain fresh exact crew reviews and
   independent human UI approval.
6. Execute only that approved successor through the phased executor. Require
   deployed runtime attestation and real behavior acceptance before reporting
   success; otherwise retain checkpoint/rollback evidence and require another
   successor where immutable input changed.

## Completion Gate

- [ ] A production source-creation path calls the atomic binding primitive.
- [ ] No pre-existing unbound source can be approved through Roadex.
- [ ] DonutHole submits typed intent only.
- [ ] Another allowlisted fixture project passes the same adapter conformance.
- [ ] Roadex resumes the exact managed thread once and survives restart/retry.
- [ ] Approval remains distinct from execution and acceptance.
- [ ] App-publication intake never implies deployment or activation.
- [ ] Focused, full, cross-repository, and responsive suites pass.
- [ ] Reviewed source identities are recorded separately from deployed service
  identities.
- [ ] No deployment, restart, protected mutation, provisioning execution, or
  live human decision occurs under this implementation plan.
