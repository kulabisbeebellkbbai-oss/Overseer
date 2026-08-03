# DonutHole Authoritative Lifecycle UI and Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Present the authoritative DonutHole provisioning lifecycle from immutable bundle creation through reviews, independent human approval, phased execution, runtime attestation, behavior acceptance, rollback, and successor creation without inventing UI-owned state or describing approval as completion.

**Architecture:** Add a pure lifecycle projection over the authoritative Capability B bundle/preflight/review records and Capability C execution/checkpoint/attestation/acceptance records. Expose it through a read-only lifecycle API, keep the existing Roadex decision route as the exact human mutation boundary, and render the same projection in the responsive Overseer UI. Historical plans remain inspectable, while only the latest authoritative successor may expose decision actions.

The existing `GET /roadex/approval-status` projection and
`RoadexApprovalBinding` are the authoritative approval-status input. Capability
D must compose them into the broader lifecycle; it must not create another
approval table, binding, status projector, or decision-version algorithm.

**Tech Stack:** Python 3.11+, frozen dataclasses and `StrEnum`, SQLite JSON records supplied by Capabilities B and C, Overseer's authenticated local HTTP API, embedded vanilla JavaScript UI, pytest/unittest API harnesses, responsive UI fixtures, Markdown operator documentation.

## Global Constraints

- Capability D starts only after Capability B exposes immutable bundle, preflight, review-outbox, review-result, and successor-link records and Capability C exposes phase, checkpoint, runtime-attestation, restart, behavior-acceptance, rollback, and final-evidence records.
- The UI and lifecycle projection consume those authoritative records. They must not add a parallel mutable lifecycle table, browser-owned lifecycle state, or status inferred from button clicks.
- Human approval remains independent, exact-plan and exact-bundle-digest bound, and cannot transfer to a successor.
- Crew acknowledgement is not review approval. Handler completion is not runtime attestation. Runtime attestation is not behavior acceptance. Approval is not completion.
- Only `acceptance_passed` is terminal success.
- Failed attestation, failed acceptance, rollback, or changed immutable input preserves the failed plan and explains why a successor and new approval are required.
- Actionability is derived server-side. The browser never reconstructs policy from partial fields.
- Latest-plan selection uses explicit successor links and authoritative chronology, never lexicographic plan-ID ordering.
- A terminal successor suppresses stale predecessor actions but does not delete predecessor history.
- Existing `/roadex/human-decisions` and `/roadex/human-decisions/decide` clients remain compatible for one migration cycle.
- Existing `/roadex/approval-status` response fields and no-mutation behavior
  remain compatible. Lifecycle output references its `approvalRef`,
  `scopeDigest`, and `decisionVersion`.
- Protected provisioning mutation routes continue requiring the admin token. Tokens and secrets never enter lifecycle payloads, markup, logs, fixtures, or examples.
- Raw subprocess output and private configuration remain unavailable. Expose stable codes, safe summaries, timestamps, and digests only.
- Capability D does not deploy, restart Overseer, mutate protected-host state, provision DonutHole, or authorize route, firewall, storage, or service changes.
- Preserve unrelated worktree changes.

---

## File and Responsibility Map

**Create**

- `src/overseer/backup_provisioning_lifecycle.py` — pure lifecycle projection, successor-chain selection, action derivation, and redacted serialization.
- `tests/test_backup_provisioning_lifecycle.py` — fixture-driven tests for every state, blockers, supersession, and approval boundaries.
- `tests/fixtures/donuthole_provisioning_lifecycle_v1.json` — safe versioned lifecycle fixture shared by backend, API, and UI tests.

**Modify**

- `src/overseer/backup_provisioning.py` — delegate decision selection and return authoritative post-decision state without claiming acceptance.
- `src/overseer/api.py` — add lifecycle collection/detail reads while preserving protected-prefix behavior.
- `src/overseer/ui.py` — render lifecycle, history, blockers, phase evidence, successor explanation, and exact actions.
- `tests/test_backup_provisioning.py` — compatibility and approval-not-acceptance assertions.
- `tests/test_backup_provisioning_review_flow.py` — exact review and approval boundaries.
- `tests/test_ui_regression.py` — API harness and semantic UI assertions.
- `tests/test_ui_full_regression.py` — route/action, responsive, accessibility, refresh, and stale-plan regressions.
- `docs/operator-workflows.md` — bundle through successor operator runbook.
- `docs/local-api.md` — lifecycle routes, fields, authentication, and compatibility.

**Capability B/C interfaces consumed without fallback**

```python
from overseer.backup_execution import (
    BehaviorAcceptance,
    ProvisioningCheckpoint,
    ProvisioningExecutionRecord,
    RuntimeAttestation,
)
from overseer.provisioning_bundle import (
    ProvisioningBundleV1,
    ProvisioningPreflightReport,
    ProvisioningReviewOutboxEntry,
)
from overseer.roadex_approval_status import RoadexApprovalProjection


@dataclass(frozen=True)
class LifecycleSnapshot:
    bundle: ProvisioningBundleV1
    preflight: ProvisioningPreflightReport
    outbox: tuple[ProvisioningReviewOutboxEntry, ...]
    reviews_terminal_approved: bool
    approved_at: str | None
    execution: ProvisioningExecutionRecord | None
    checkpoints: tuple[ProvisioningCheckpoint, ...]
    attestation: RuntimeAttestation | None
    acceptance: BehaviorAcceptance | None
    successor_required: bool
    successor_reason: str | None
    approval_projection: RoadexApprovalProjection


@dataclass(frozen=True)
class LifecycleStateInputs:
    preflight_status: str
    reviews_terminal_approved: bool
    approved_at: str | None
    execution_status: str | None
    attestation_status: str | None
    acceptance_status: str | None
    successor_required: bool = False
```

`load_lifecycle_snapshot(store_path, plan_id)` must load these exact records through the Capability B/C store helpers. Never reconstruct missing authoritative data from legacy prose.

---

### Task 1: Define the Pure Authoritative Lifecycle Projection

**Files:**

- Create: `src/overseer/backup_provisioning_lifecycle.py`
- Create: `tests/test_backup_provisioning_lifecycle.py`
- Create: `tests/fixtures/donuthole_provisioning_lifecycle_v1.json`

- [ ] **Step 1: Write the safe fixture and failing state-matrix tests**

Create an explicit chain: v1 rolled back, v2 acceptance failed, v3 acceptance passed. Use fixed safe digests. Load records through real Capability B/C store helpers and assert:

```python
@pytest.mark.parametrize(
    ("preflight", "reviews", "approval", "execution", "attestation", "acceptance", "expected"),
    (
        ("pending", "pending", None, None, None, None, "staged"),
        ("passed", "pending", None, None, None, None, "awaiting_reviews"),
        ("passed", "approved", None, None, None, None, "ready_for_approval"),
        ("passed", "approved", "approved", "pending", None, None, "approved"),
        ("passed", "approved", "approved", "executing", None, None, "executing"),
        ("passed", "approved", "approved", "passed", "passed", "failed", "acceptance_failed"),
        ("passed", "approved", "approved", "rolled_back", None, None, "rolled_back"),
        ("passed", "approved", "approved", "failed", "mismatch", None, "successor_required"),
        ("passed", "approved", "approved", "passed", "passed", "passed", "acceptance_passed"),
    ),
)
def test_projects_authoritative_lifecycle_state(
    preflight, reviews, approval, execution, attestation, acceptance, expected
):
    inputs = LifecycleStateInputs(
        preflight_status=preflight,
        reviews_terminal_approved=reviews == "approved",
        approved_at=approval,
        execution_status=execution,
        attestation_status=attestation,
        acceptance_status=acceptance,
        successor_required=execution == "failed" and attestation == "mismatch",
    )
    assert derive_lifecycle_state(inputs).value == expected
```

Also assert acknowledgement cannot produce readiness, completed handlers cannot produce acceptance, and bundle mismatch requires a successor.

- [ ] **Step 2: Verify the missing module failure**

Run: `pytest -q tests/test_backup_provisioning_lifecycle.py`

Expected: collection fails with `ModuleNotFoundError: No module named 'overseer.backup_provisioning_lifecycle'`.

- [ ] **Step 3: Implement the enum and precedence-ordered projection**

```python
class ProvisioningLifecycleState(StrEnum):
    STAGED = "staged"
    AWAITING_REVIEWS = "awaiting_reviews"
    READY_FOR_APPROVAL = "ready_for_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    ACCEPTANCE_FAILED = "acceptance_failed"
    ROLLED_BACK = "rolled_back"
    SUCCESSOR_REQUIRED = "successor_required"
    ACCEPTANCE_PASSED = "acceptance_passed"

def derive_lifecycle_state(snapshot: LifecycleStateInputs) -> ProvisioningLifecycleState:
    if snapshot.successor_required:
        return ProvisioningLifecycleState.SUCCESSOR_REQUIRED
    if snapshot.execution_status == "rolled_back":
        return ProvisioningLifecycleState.ROLLED_BACK
    if snapshot.acceptance_status == "failed":
        return ProvisioningLifecycleState.ACCEPTANCE_FAILED
    if snapshot.acceptance_status == "passed" and snapshot.attestation_status == "passed":
        return ProvisioningLifecycleState.ACCEPTANCE_PASSED
    if snapshot.execution_status == "executing":
        return ProvisioningLifecycleState.EXECUTING
    if snapshot.approved_at:
        return ProvisioningLifecycleState.APPROVED
    if snapshot.preflight_status == "passed" and snapshot.reviews_terminal_approved:
        return ProvisioningLifecycleState.READY_FOR_APPROVAL
    if snapshot.preflight_status == "passed":
        return ProvisioningLifecycleState.AWAITING_REVIEWS
    return ProvisioningLifecycleState.STAGED
```

Return server-derived actions:

```python
available_actions = {
    "approve": state is ProvisioningLifecycleState.READY_FOR_APPROVAL,
    "deny": state is ProvisioningLifecycleState.READY_FOR_APPROVAL,
    "request_revision": state in {
        ProvisioningLifecycleState.AWAITING_REVIEWS,
        ProvisioningLifecycleState.READY_FOR_APPROVAL,
    },
}
```

The serializer includes `mutation_performed=False`, `host_mutation_performed=False`, and `redactions_applied=True`.

- [ ] **Step 4: Run focused tests**

Run: `pytest -q tests/test_backup_provisioning_lifecycle.py`

Expected: all state, blocker, redaction, and false-success tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/overseer/backup_provisioning_lifecycle.py tests/test_backup_provisioning_lifecycle.py tests/fixtures/donuthole_provisioning_lifecycle_v1.json
git commit -m "Add authoritative provisioning lifecycle projection"
```

---

### Task 2: Implement Explicit Successor Chains and Actionable Selection

**Files:**

- Modify: `src/overseer/backup_provisioning_lifecycle.py`
- Modify: `src/overseer/backup_provisioning.py`
- Modify: `tests/test_backup_provisioning_lifecycle.py`
- Modify: `tests/test_backup_provisioning.py`

- [ ] **Step 1: Write failing successor tests**

Add exact tests for terminal successor suppressing predecessor actions, retained history, changed immutable inputs, a newer staged successor after a terminal predecessor, ambiguous chains failing closed, and legacy decisions returning only the current actionable item.

- [ ] **Step 2: Verify current selection is insufficient**

Run: `pytest -q tests/test_backup_provisioning_lifecycle.py tests/test_backup_provisioning.py -k 'successor or predecessor or human_decision'`

Expected: new history and link-validation assertions fail.

- [ ] **Step 3: Implement chain validation and delegate legacy decisions**

```python
def current_chain_head(bundles):
    by_id = {item.plan_id: item for item in bundles}
    superseded = {item.supersedes_plan_id for item in bundles if item.supersedes_plan_id}
    heads = [item for item in bundles if item.plan_id not in superseded]
    if len(heads) != 1:
        raise ValueError("provisioning successor chain is ambiguous")
    seen = set()
    current = heads[0]
    while current.supersedes_plan_id:
        if current.plan_id in seen or current.supersedes_plan_id not in by_id:
            raise ValueError("provisioning successor chain is invalid")
        seen.add(current.plan_id)
        current = by_id[current.supersedes_plan_id]
    return heads[0]
```

Have `list_roadex_human_decisions` return the head only when `available_actions.approve` is true. Preserve response keys but source readiness and blockers from lifecycle projection.

- [ ] **Step 4: Run provisioning tests**

Run: `pytest -q tests/test_backup_provisioning_lifecycle.py tests/test_backup_provisioning.py tests/test_backup_provisioning_review_flow.py`

Expected: all pass, including v9/v11 and v12/v13 regressions.

- [ ] **Step 5: Commit**

```bash
git add src/overseer/backup_provisioning_lifecycle.py src/overseer/backup_provisioning.py tests/test_backup_provisioning_lifecycle.py tests/test_backup_provisioning.py
git commit -m "Project successor-safe provisioning decisions"
```

---

### Task 3: Expose Lifecycle Collection and Exact Detail APIs

**Files:**

- Modify: `src/overseer/api.py`
- Modify: `tests/test_ui_regression.py`
- Modify: `docs/local-api.md`

- [ ] **Step 1: Write failing API tests**

Test:

```text
GET /backup-provisioning/lifecycle
GET /backup-provisioning/lifecycle?plan_id=backup-provision.donuthole.v3
GET /Overseer/backup-provisioning/lifecycle
GET /roadex/human-decisions
POST /roadex/human-decisions/decide
```

Assert head-first ordering, exact filtering, unknown-plan empty result, redaction, prefix equivalence, and unauthenticated decision rejection.
Also assert that lifecycle approval fields exactly match
`/roadex/approval-status` and that neither GET mutates binding or source state.

- [ ] **Step 2: Verify route absence**

Run: `pytest -q tests/test_ui_regression.py -k 'provisioning_lifecycle or roadex_human'`

Expected: lifecycle requests return HTTP 404 while current decisions pass.

- [ ] **Step 3: Add the route**

```python
if path == "/backup-provisioning/lifecycle":
    self._handle(
        lambda: provisioning_lifecycle_status(
            store_path,
            plan_id=_query_first(query, "plan_id"),
        )
    )
    return
```

Approval responses include a fresh lifecycle item and never synthesize `acceptance_passed` from handler or HTTP completion.

- [ ] **Step 4: Document and test**

Run: `pytest -q tests/test_ui_regression.py tests/test_backup_provisioning_lifecycle.py`

Expected: API, prefix, filtering, and lifecycle tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/overseer/api.py tests/test_ui_regression.py docs/local-api.md
git commit -m "Expose authoritative provisioning lifecycle API"
```

---

### Task 4: Render Accurate Lifecycle Cards and Human Actions

**Files:**

- Modify: `src/overseer/ui.py`
- Modify: `tests/test_ui_regression.py`
- Modify: `tests/test_ui_full_regression.py`

- [ ] **Step 1: Write failing UI tests**

Assert the endpoint, all nine state labels, `Approve exact plan`, `Approval is not completion`, and absence of `Approve and complete`. Fixture tests enable approve/deny only for ready state and show reviews, phase, failure code, changed inputs, and success evidence in their correct states.

- [ ] **Step 2: Verify rendering is missing**

Run: `pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py -k 'roadex or lifecycle or responsive'`

Expected: lifecycle endpoint, copy, state cards, and gating assertions fail.

- [ ] **Step 3: Implement server-gated rendering**

```javascript
function provisioningLifecycleCard(item) {
  const actions = item.available_actions || {};
  const approveDisabled = actions.approve === true ? "" : " disabled";
  const changed = (item.successor?.changed_immutable_inputs || [])
    .map((name) => `<li>${safe(labelize(name))}</li>`).join("");
  return `<article class="panel span-12 provisioning-lifecycle ${safe(item.lifecycle_state)}"
      aria-labelledby="lifecycle-${safe(item.plan_id)}">
    <div class="toolbar"><h2 id="lifecycle-${safe(item.plan_id)}">${safe(item.title)}</h2>
      <span class="pill">${safe(labelize(item.lifecycle_state))}</span></div>
    <p><strong>Exact plan:</strong> ${safe(item.plan_id)}</p>
    <p><strong>Bundle digest:</strong> ${safe(item.bundle_digest)}</p>
    <p class="muted">Approval is not completion. Success requires runtime attestation and behavior acceptance.</p>
    ${changed ? `<section><h3>Why a successor is required</h3><ul>${changed}</ul></section>` : ""}
    <button type="button" class="action-btn" data-action="decide-roadex-human"
      data-decision="approve" data-plan-id="${safe(item.plan_id)}"
      data-plan-digest="${safe(item.plan_digest)}"${approveDisabled}>Approve exact plan</button>
  </article>`;
}
```

Render current plus collapsible history. Escape every value. Never recalculate readiness in JavaScript.

- [ ] **Step 4: Refresh authoritative state**

After decision POST, refetch lifecycle and decisions. While `approved` or `executing`, use the existing bounded refresh mechanism. Transport failure displays unknown/stale, never success.

- [ ] **Step 5: Run responsive/accessibility regressions**

Run: `pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py`

Expected: desktop/tablet/mobile, 44-pixel target, semantic disabled controls, labels, focus, routes, and actions pass.

- [ ] **Step 6: Commit**

```bash
git add src/overseer/ui.py tests/test_ui_regression.py tests/test_ui_full_regression.py
git commit -m "Render authoritative provisioning lifecycle"
```

---

### Task 5: Separate Approval Results from Acceptance and Explain Successors

**Files:**

- Modify: `src/overseer/backup_provisioning.py`
- Modify: `src/overseer/backup_provisioning_lifecycle.py`
- Modify: `src/overseer/ui.py`
- Modify: `tests/test_backup_provisioning.py`
- Modify: `tests/test_backup_provisioning_lifecycle.py`
- Modify: `tests/test_ui_regression.py`

- [ ] **Step 1: Write failing decision tests**

Assert approve returns `approved` or `executing`, never `acceptance_passed`; acceptance failure cannot emit success; changed runtime/config identity requires a successor; deny/revision never construct the privileged adapter.

- [ ] **Step 2: Observe premature completion**

Run: `pytest -q tests/test_backup_provisioning.py tests/test_backup_provisioning_lifecycle.py -k 'approval or acceptance or successor'`

Expected: current synchronous status/copy fails the new assertions.

- [ ] **Step 3: Return fresh authoritative lifecycle state**

```python
return {
    "ok": True,
    "decision": "approve",
    "plan_id": plan_id,
    "plan_digest": plan.plan_digest,
    "lifecycle": lifecycle_item(store_path, plan_id),
    "mutation_performed": True,
    "host_mutation_performed": execution_started,
}
```

Use Capability C's exact phased executor; do not return `executed` because an HTTP handler completed.

- [ ] **Step 4: Project exact successor guidance**

```python
"successor": {
    "required": True,
    "reason_code": "ACTIVE_RUNTIME_DIGEST_MISMATCH",
    "reason": "The active runtime differs from the approved immutable bundle.",
    "changed_immutable_inputs": ["runtime_digest"],
    "prior_approval_reusable": False,
    "successor_plan_id": None,
}
```

No retry control may reuse old approval.

- [ ] **Step 5: Run regressions**

Run: `pytest -q tests/test_backup_provisioning.py tests/test_backup_provisioning_lifecycle.py tests/test_ui_regression.py`

Expected: approval, non-mutation, acceptance, successor, redaction, and copy tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/overseer/backup_provisioning.py src/overseer/backup_provisioning_lifecycle.py src/overseer/ui.py tests/test_backup_provisioning.py tests/test_backup_provisioning_lifecycle.py tests/test_ui_regression.py
git commit -m "Separate provisioning approval from acceptance"
```

---

### Task 6: Publish the Complete Operator Lifecycle Runbook

**Files:**

- Modify: `docs/operator-workflows.md`
- Modify: `docs/local-api.md`
- Modify: `tests/test_ui_regression.py`

- [ ] **Step 1: Write a failing documentation-contract test**

Require: typed bundle intent, digest-bound preflight, committed review outbox, terminal crew evidence, independent approval, phased execution, runtime attestation, behavior acceptance, rollback checkpoint, successor changed inputs, and non-reusable approval.

- [ ] **Step 2: Verify missing guidance**

Run: `pytest -q tests/test_ui_regression.py -k 'operator_lifecycle_documentation'`

Expected: missing lifecycle concepts fail.

- [ ] **Step 3: Document the exact procedure**

Document this order: submit bounded intent; verify bundle/preflight; dispatch exact committed outbox IDs; confirm terminal reviews; compare exact digests and decide in Sisko; follow materialize/register/activate/attest/accept/finalize phases; treat only acceptance passed as success; preserve failed history and create a newly reviewed/approved successor.

Label deployment/restart, protected execution, route/firewall, and live acceptance as separate approval boundaries. Plan approval authorizes none of them.

- [ ] **Step 4: Run documentation/UI tests**

Run: `pytest -q tests/test_ui_regression.py -k 'documentation or roadex or lifecycle'`

Expected: documentation and UI wording pass.

- [ ] **Step 5: Commit**

```bash
git add docs/operator-workflows.md docs/local-api.md tests/test_ui_regression.py
git commit -m "Document DonutHole provisioning lifecycle operations"
```

---

### Task 7: Run Capability D and Whole-Repository Verification

**Files:**

- Verify only; fix only Capability D failures.

- [ ] **Step 1: Run the focused suite**

```bash
pytest -q tests/test_backup_provisioning_lifecycle.py tests/test_backup_provisioning.py tests/test_backup_provisioning_review_flow.py tests/test_ui_regression.py tests/test_ui_full_regression.py
```

Expected: all pass with no lifecycle-related skips.

- [ ] **Step 2: Run the full suite**

Run: `pytest -q`

Expected: all pass; enumerate existing environmental skips. New failures/skips block completion.

- [ ] **Step 3: Verify scope and secret safety**

```bash
git diff --check
git status --short
git diff --stat
```

Expected: no whitespace errors, only D files changed, unrelated files untouched, and no tokens, credentials, raw subprocess output, or private configuration in output/fixtures.

- [ ] **Step 4: Perform disposable responsive acceptance**

Use only the test harness on an ephemeral loopback port. Load each state at desktop, tablet, and mobile widths; verify keyboard traversal, focus, labels, and disabled controls. Do not use the protected production store/service.

Expected: accurate rendering, no console errors, and unchanged fixtures.

- [ ] **Step 5: Commit verification corrections only if needed**

```bash
git add src/overseer/backup_provisioning_lifecycle.py src/overseer/backup_provisioning.py src/overseer/api.py src/overseer/ui.py tests/test_backup_provisioning_lifecycle.py tests/test_backup_provisioning.py tests/test_backup_provisioning_review_flow.py tests/test_ui_regression.py tests/test_ui_full_regression.py docs/operator-workflows.md docs/local-api.md
git commit -m "Complete provisioning lifecycle regressions"
```

Do not create an empty commit.

- [ ] **Step 6: Stop at deployment approval**

Report source SHA, focused/full tests, responsive/accessibility evidence, and deployment diff. Do not restart `overseer-api.service`, deploy, execute DonutHole provisioning, or run protected-gateway acceptance without separately staged and approved actions.

---

## Final Acceptance Checklist

- [ ] Every lifecycle state comes from authoritative Capability B/C records.
- [ ] Approval identity and decision version come from the existing exact
  Roadex approval projection, with no duplicate approval store or projector.
- [ ] Only server-derived `ready_for_approval` enables approval.
- [ ] Approval, execution, attestation, and acceptance remain distinct.
- [ ] Only `acceptance_passed` is success.
- [ ] Terminal successors never resurrect predecessor actions.
- [ ] History retains exact safe digests and stable codes.
- [ ] Successor views identify changed immutable fields and non-reusable approval.
- [ ] Decision routes remain exact-field, admin-token protected, independently approved, and host-nonmutating for deny/revision.
- [ ] UI state comes from API refreshes, not optimistic local mutation.
- [ ] Desktop, tablet, mobile, keyboard, focus, labels, and disabled-state regressions pass.
- [ ] Operator/API documentation covers the lifecycle and approval boundaries.
- [ ] Focused and full tests pass.
- [ ] No deployment, restart, protected mutation, provisioning execution, or live acceptance occurred under plan-writing approval.
