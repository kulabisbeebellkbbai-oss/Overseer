# DonutHole Typed Bundle and Deterministic Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an Overseer-owned typed DonutHole provisioning interface that authoritatively rebuilds and preflights immutable plans, then atomically publishes each passing plan with its exact crew-review outbox.

**Architecture:** Roadex and DonutHole submit only bounded `ProvisioningIntentV1` data. Overseer resolves every authority-bearing field, produces a digest-bound read-only preflight report, and accepts public staging only when a repeated authoritative build matches the caller's expected preflight and bundle digests; one SQLite transaction persists the plan, report, bundle, and four pending outbox entries. A provisioning-specific dispatcher materializes crew messages only from committed outbox entries, while existing human approval and privileged execution remain separate.

**Tech Stack:** Python 3.13, frozen dataclasses, canonical JSON and SHA-256, SQLite transactions, Overseer `SQLiteStore`, `http.server` API handlers, `argparse`, pytest.

## Global Constraints

- Root-owned authorization configuration remains immutable to service code.
- Roadex and DonutHole submit bounded intent only; they cannot submit raw plan steps, digests, authorization references, protected paths, crew owners, evidence IDs, or commands.
- Public staging accepts typed intent plus expected preflight and bundle digests and rebuilds the bundle authoritatively before persistence.
- Preflight is read-only and performs no control-store or host mutation.
- The source plan, existing exact `RoadexApprovalBinding`, preflight report,
  bundle, and four review-outbox rows are committed atomically.
- Reuse `RoadexApprovalBindingDraft`, `RoadexApprovalBinding`, and
  `stage_bound_roadex_approval()` from `src/overseer/roadex_approval_status.py`.
  Never create a competing approval identity or retroactively bind a
  pre-existing source.
- Dispatch reads only committed pending outbox rows and is idempotent by outbox ID.
- Review results remain independent immutable crew records.
- Human approval remains bound to the exact immutable plan, bundle, preflight, and terminal crew evidence.
- No approval transfers to a successor plan or changed digest.
- Secrets, tokens, private paths not already in the immutable public contract, and subprocess output remain redacted.
- This capability does not restart services, provision DonutHole, execute privileged operations, modify TheUnderdark, or add a generic command runner.
- Preserve `docs/opnsense-new-nic-migration-approval-2026-08-01.md` and all unrelated worktree changes.

## File Map

- Create `src/overseer/provisioning_bundle.py`: typed intent, checks, preflight report, review outbox, bundle construction, canonical digests, authoritative rebuild, and atomic staging service.
- Modify `src/overseer/store.py`: additive schema version 3 tables and transaction-aware bundle, report, plan, and outbox persistence methods.
- Modify `src/overseer/backup_provisioning.py`: expose store-aware immutable plan persistence, preflight/bundle approval gating, and legacy staged-plan successor handling without changing legacy serialized plan digests.
- Reuse `src/overseer/roadex_approval_status.py`: prospective exact approval
  binding and scope digest; extend through the allowlisted adapter registry in
  the 2026-08-03 delta plan rather than hard-coding another projector.
- Modify `src/overseer/cli.py`: provisioning-outbox materialization and exact dispatch status functions.
- Modify `src/overseer/api.py`: authenticated preflight, authoritative stage, bundle status, and exact outbox-dispatch routes.
- Modify `src/overseer/backup_provisioning_cli.py`: `bundle-preflight`, `bundle-stage`, `bundle-status`, and `review-dispatch` commands; retain legacy list/approve/execute behavior with typed successor enforcement.
- Create `tests/test_provisioning_bundle.py`: typed validation, deterministic digest, read-only preflight, authoritative rebuild, atomicity, idempotency, and compatibility tests.
- Modify `tests/test_backup_provisioning.py`: exact bundle/preflight/crew evidence approval gates and legacy staged-plan behavior.
- Modify `tests/test_backup_provisioning_review_flow.py`: committed outbox ordering and independent review invariants.
- Modify `tests/test_core.py`: API and CLI authentication, exact payload, redaction, and no-host-mutation regressions.
- Modify `tests/test_ui_regression.py`: Roadex decision readiness remains false until the exact passing report and reviews exist.
- Modify `docs/superpowers/specs/2026-08-02-donuthole-provisioning-reliability-design.md`: append the implemented Capability B interface names and compatibility policy only after tests pass.

---

### Task 1: Typed Intent, Report, Outbox, and Bundle Contracts

**Files:**
- Create: `src/overseer/provisioning_bundle.py`
- Create: `tests/test_provisioning_bundle.py`

**Interfaces:**
- Consumes: `DonutHoleBackupProvisioningPlan` and `build_plan()` from `overseer.backup_provisioning`; `OwnerDomain` from `overseer.core`.
- Produces: `ProvisioningIntentV1`, `PreflightCheck`, `ProvisioningPreflightReport`, `ProvisioningReviewOutboxEntry`, `ProvisioningBundleV1`, `parse_provisioning_intent(payload)`, `canonical_digest(value)`, and `bundle_digest(bundle)`.

- [ ] **Step 1: Write failing exact-schema and deterministic-digest tests**

```python
def test_intent_accepts_only_bounded_exact_fields():
    payload = intent_payload()
    intent = parse_provisioning_intent(payload)
    assert intent.plan_id == "backup-provision.donuthole.v20.20260802"
    for forbidden in ("runtime_digest", "authorization_ref", "evidence_ids", "steps"):
        with pytest.raises(ValueError, match="exact typed provisioning intent"):
            parse_provisioning_intent({**payload, forbidden: "caller-controlled"})

def test_bundle_digest_is_canonical_and_excludes_mutable_outbox_state():
    first = bundle_fixture(outbox_state="pending")
    second = bundle_fixture(outbox_state="dispatched")
    assert bundle_digest(first) == bundle_digest(second)
    assert bundle_digest(first) == "sha256:" + hashlib.sha256(canonical_bundle_bytes(first)).hexdigest()
```

- [ ] **Step 2: Run the contract tests and confirm the missing module failure**

Run: `pytest -q tests/test_provisioning_bundle.py -k 'intent or bundle_digest'`

Expected: collection fails with `ModuleNotFoundError: No module named 'overseer.provisioning_bundle'`.

- [ ] **Step 3: Implement frozen types and strict parsing**

```python
INTENT_FIELDS = frozenset({"schema_version", "request_id", "plan_id", "kind", "project_id", "resource_id", "root_id", "policy_revision", "source_commit", "requested_by", "reason", "supersedes_plan_id"})

@dataclass(frozen=True)
class ProvisioningIntentV1:
    schema_version: str
    request_id: str
    plan_id: str
    kind: str
    project_id: str
    resource_id: str
    root_id: str
    policy_revision: str
    source_commit: str
    requested_by: str
    reason: str
    supersedes_plan_id: str

@dataclass(frozen=True)
class PreflightCheck:
    code: str
    status: str
    evidence_digest: str
    summary: str

@dataclass(frozen=True)
class ProvisioningPreflightReport:
    report_id: str
    plan_id: str
    resolved_inputs: Mapping[str, object]
    checks: tuple[PreflightCheck, ...]
    passed: bool
    report_digest: str

@dataclass(frozen=True)
class ProvisioningReviewOutboxEntry:
    id: str
    message_id: str
    plan_id: str
    bundle_digest: str
    role: str
    owner_domain: OwnerDomain
    related_resource_id: str
    subject: str
    message: str
    acceptance_criteria: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    state: str = "pending"

@dataclass(frozen=True)
class ProvisioningBundleV1:
    schema_version: str
    intent: ProvisioningIntentV1
    plan: DonutHoleBackupProvisioningPlan
    preflight: ProvisioningPreflightReport
    outbox: tuple[ProvisioningReviewOutboxEntry, ...]
    bundle_digest: str
    supersedes_plan_id: str | None
    changed_immutable_inputs: tuple[str, ...]

def parse_provisioning_intent(payload: Mapping[str, object]) -> ProvisioningIntentV1:
    if set(payload) != INTENT_FIELDS or payload.get("schema_version") != "1" or payload.get("kind") != "donuthole_encrypted_backup_provisioning_v1":
        raise ValueError("exact typed provisioning intent fields are required")
    values = {name: str(payload[name]).strip() for name in INTENT_FIELDS}
    required_values = {name: value for name, value in values.items() if name != "supersedes_plan_id"}
    if any(not value for value in required_values.values()) or re.fullmatch(r"[0-9a-f]{40}", values["source_commit"]) is None:
        raise ValueError("exact typed provisioning intent values are required")
    return ProvisioningIntentV1(**values)
```

- [ ] **Step 4: Run the focused contract tests**

Run: `pytest -q tests/test_provisioning_bundle.py -k 'intent or bundle_digest'`

Expected: all selected tests pass.

- [ ] **Step 5: Commit the typed contract slice**

```bash
git add src/overseer/provisioning_bundle.py tests/test_provisioning_bundle.py
git commit -m "Add typed provisioning bundle contracts"
```

### Task 2: Deterministic Read-Only Preflight and Authoritative Bundle Builder

**Files:**
- Modify: `src/overseer/provisioning_bundle.py`
- Modify: `tests/test_provisioning_bundle.py`
- Test: `tests/test_backup_cross_repo_contract.py`

**Interfaces:**
- Consumes: `runtime_digest()`, `capability_digest()`, and `EXPECTED_BACKUP_TOOL_SCHEMAS` from `overseer.backup_host_operations`; `current_root_identity()` and `resolve_current_root_authorization()` from `overseer.storage_control`.
- Produces: `PreflightDependencies`, `run_provisioning_preflight(store_path, intent, dependencies) -> ProvisioningPreflightReport`, and `build_provisioning_bundle(store_path, intent, dependencies) -> ProvisioningBundleV1`.

- [ ] **Step 1: Write failing deterministic and no-mutation preflight tests**

```python
def test_preflight_resolves_authoritative_inputs_without_mutation(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()
    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())
    assert report.passed is True
    assert [check.code for check in report.checks] == list(REQUIRED_PREFLIGHT_CODES)
    assert report.resolved_inputs["authorization_ref"] == "root-auth.current"
    assert Path(store_path).read_bytes() == before

def test_preflight_fails_closed_on_changed_source_or_authority(tmp_path):
    dependencies = deterministic_dependencies(source_head="f" * 40)
    report = run_provisioning_preflight(seeded_authority_store(tmp_path), intent_fixture(), dependencies)
    assert report.passed is False
    assert next(check for check in report.checks if check.status == "failed").code == "SOURCE_COMMIT_MISMATCH"
    assert "private" not in repr(report)
```

- [ ] **Step 2: Run tests and verify missing preflight interfaces**

Run: `pytest -q tests/test_provisioning_bundle.py -k preflight`

Expected: failures name `PreflightDependencies` and `run_provisioning_preflight` as undefined.

- [ ] **Step 3: Implement dependency injection and stable checks**

```python
REQUIRED_PREFLIGHT_CODES = (
    "INTENT_VALID", "SOURCE_COMMIT_MATCH", "RUNTIME_DIGEST_VALID",
    "CAPABILITY_DIGEST_VALID", "GPG_DIGEST_VALID", "ROOT_AUTHORIZATION_CURRENT",
    "DEPENDENCIES_AVAILABLE", "CANONICAL_BOUNDARIES_VALID", "ROLLBACK_PREREQUISITES_VALID",
)

@dataclass(frozen=True)
class PreflightDependencies:
    source_path: str
    source_head: Callable[[str], str]
    runtime_digest: Callable[[str, str], str]
    capability_digest: Callable[[str, Mapping[str, object]], str]
    file_digest: Callable[[str], str]
    executable_exists: Callable[[str], bool]

def _check(code: str, passed: bool, evidence: Mapping[str, object], summary: str) -> PreflightCheck:
    return PreflightCheck(code, "passed" if passed else "failed", canonical_digest(evidence), summary)

def run_provisioning_preflight(store_path: str, intent: ProvisioningIntentV1, dependencies: PreflightDependencies) -> ProvisioningPreflightReport:
    source_head = dependencies.source_head(dependencies.source_path)
    runtime = dependencies.runtime_digest(dependencies.source_path, intent.source_commit)
    capability = dependencies.capability_digest(intent.source_commit, EXPECTED_BACKUP_TOOL_SCHEMAS)
    gpg = dependencies.file_digest("/usr/bin/gpg")
    identity = current_root_identity("/home/god/Documents/Codex Workspace/DonutHole")
    target = canonical_root_target_digest(identity)
    authority = resolve_current_root_authorization(store_path, intent.project_id, intent.root_id, intent.policy_revision, identity, "donuthole-development", "active", 1073741824, target)
    checks = build_ordered_checks(intent, source_head, runtime, capability, gpg, authority, dependencies)
    resolved = {"source_commit": source_head, "runtime_digest": runtime, "capability_digest": capability, "gpg_sha256": gpg, "root_identity": identity, "target_digest": target, "authorization_ref": authority["authorization_ref"]}
    report_id = f"preflight.{intent.plan_id}"
    digest = canonical_digest({"report_id": report_id, "plan_id": intent.plan_id, "resolved_inputs": resolved, "checks": [asdict(item) for item in checks]})
    return ProvisioningPreflightReport(report_id, intent.plan_id, resolved, checks, all(item.status == "passed" for item in checks), digest)
```

- [ ] **Step 4: Build the immutable plan and four exact outbox entries from resolved data only**

```python
def build_provisioning_bundle(store_path: str, intent: ProvisioningIntentV1, dependencies: PreflightDependencies) -> ProvisioningBundleV1:
    report = run_provisioning_preflight(store_path, intent, dependencies)
    if not report.passed:
        raise ProvisioningBundleError("PREFLIGHT_FAILED")
    evidence_ids = {role: f"crew.{owner}.review-{intent.plan_id}" for role, owner in (("kira", "kira"), ("obrien", "obrien"), ("security", "odo_ids"), ("sisko", "sisko"))}
    registration = canonical_root_registration(intent, report.resolved_inputs)
    plan = build_plan(intent.plan_id, str(report.resolved_inputs["gpg_sha256"]), intent.source_commit, str(report.resolved_inputs["runtime_digest"]), str(report.resolved_inputs["capability_digest"]), {str(report.resolved_inputs["target_digest"]): str(report.resolved_inputs["authorization_ref"])}, (registration,), "/home/god/.local/share/overseer/project/state/api-token", "/etc/codex-development-backups/keys/overseer.token", "/etc/codex-development-backups/keys/cursor.key", evidence_ids)
    predecessor = load_provisioning_bundle(store_path, intent.supersedes_plan_id) if intent.supersedes_plan_id else None
    changed = changed_immutable_inputs(predecessor, plan, report)
    provisional = build_review_outbox(intent, plan, report, evidence_ids, bundle_digest_value="sha256:" + "0" * 64)
    digest = canonical_digest(canonical_bundle_payload(intent, plan, report, provisional, intent.supersedes_plan_id or None, changed))
    outbox = tuple(replace(item, bundle_digest=digest, evidence_ids=(plan.plan_digest, report.report_digest, digest)) for item in provisional)
    return ProvisioningBundleV1(
        "1", intent, plan, report, outbox, digest,
        intent.supersedes_plan_id or None, changed,
    )
```

`changed_immutable_inputs(previous, plan, report)` compares only immutable plan and resolved-preflight fields, returns sorted stable field names, and rejects a supplied predecessor that is absent, already superseded by another plan, or not the current authoritative chain tip.

- [ ] **Step 5: Run preflight and cross-repository contract tests**

Run: `pytest -q tests/test_provisioning_bundle.py -k 'preflight or authoritative or deterministic' tests/test_backup_cross_repo_contract.py`

Expected: all selected tests pass or the cross-repository test reports only its existing documented skip when the sibling virtual environment is unavailable.

- [ ] **Step 6: Commit the preflight slice**

```bash
git add src/overseer/provisioning_bundle.py tests/test_provisioning_bundle.py tests/test_backup_cross_repo_contract.py
git commit -m "Add deterministic provisioning preflight"
```

### Task 3: Schema Version 3 and Atomic Source, Binding, and Bundle Persistence

**Files:**
- Modify: `src/overseer/store.py`
- Modify: `src/overseer/backup_provisioning.py`
- Modify: `src/overseer/provisioning_bundle.py`
- Modify: `tests/test_provisioning_bundle.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: `ProvisioningBundleV1` from Task 1 and `SQLiteStore.agent_transaction()`.
- Produces: `SQLiteStore.save_provisioning_bundle()`, `load_provisioning_bundle(store, plan_id) -> ProvisioningBundleV1`, `save_provisioning_preflight_report()`, `save_provisioning_review_outbox()`, `load_provisioning_review_outbox_payload()`, `list_provisioning_review_outbox_payloads()`, `save_backup_provisioning_plan_payload()`, and `stage_authoritative_bundle()`; consumes the existing exact binding primitive in the same transaction.

- [ ] **Step 1: Write failing migration, rollback, and idempotency tests**

```python
def test_atomic_stage_rolls_back_source_binding_report_bundle_and_outbox_on_failure(tmp_path, monkeypatch):
    store_path = str(tmp_path / "state.sqlite3")
    bundle = bundle_fixture()
    monkeypatch.setattr(SQLiteStore, "save_provisioning_review_outbox", fail_on_second_outbox())
    with pytest.raises(RuntimeError, match="injected outbox failure"):
        stage_authoritative_bundle(store_path, bundle)
    assert persisted_bundle_rows(store_path) == {"plans": 0, "bindings": 0, "reports": 0, "bundles": 0, "outbox": 0, "crew": 0}

def test_atomic_stage_is_exactly_idempotent_and_rejects_changed_bytes(tmp_path):
    store_path = str(tmp_path / "state.sqlite3")
    first = stage_authoritative_bundle(store_path, bundle_fixture())
    second = stage_authoritative_bundle(store_path, bundle_fixture())
    assert second["mutation_performed"] is False
    with pytest.raises(ValueError, match="immutable"):
        stage_authoritative_bundle(store_path, changed_bundle_fixture())
```

- [ ] **Step 2: Run atomicity tests and confirm schema/store failures**

Run: `pytest -q tests/test_provisioning_bundle.py -k 'atomic or idempotent'`

Expected: failures report missing bundle/outbox tables or store methods.

- [ ] **Step 3: Add the additive schema migration and transaction-aware store methods**

```python
CURRENT_SCHEMA_VERSION = 3

# Inside SQLiteStore.initialize():
self._connection.executescript("""
CREATE TABLE IF NOT EXISTS provisioning_preflight_reports (
    id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, report_digest TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS provisioning_bundles (
    id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, bundle_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS provisioning_review_outbox (
    id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, owner_domain TEXT NOT NULL, state TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS provisioning_review_outbox_plan_state
    ON provisioning_review_outbox(plan_id, state);
""")

def save_provisioning_review_outbox(self, entry_id: str, plan_id: str, owner_domain: str, state: str, payload: str) -> None:
    self._connection.execute("INSERT INTO provisioning_review_outbox VALUES (?, ?, ?, ?, ?)", (entry_id, plan_id, owner_domain, state, payload))
    self._commit_agent_mutation()
```

- [ ] **Step 4: Refactor plan persistence to participate in the same transaction**

```python
def stage_authoritative_bundle(store_path: str, bundle: ProvisioningBundleV1) -> Mapping[str, object]:
    validate_bundle(bundle)
    with SQLiteStore(store_path) as store:
        serialized = dump_bundle(bundle)

        def save_source_and_bundle() -> None:
            store.save_backup_provisioning_plan_payload(bundle.plan.plan_id, dump_plan(bundle.plan))
            store.save_provisioning_preflight_report(bundle.preflight.report_id, bundle.plan.plan_id, bundle.preflight.report_digest, dump_report(bundle.preflight))
            store.save_provisioning_bundle(bundle.intent.plan_id, bundle.plan.plan_id, bundle.bundle_digest, serialized)
            for entry in bundle.outbox:
                store.save_provisioning_review_outbox(entry.id, entry.plan_id, entry.owner_domain.value, entry.state, dump_outbox(entry))

        # stage_bound_roadex_approval owns the one transaction. Its callback
        # persists source, report, bundle, and outbox before the binding row.
        # Exact binding replay does not invoke the callback.
        binding = stage_bound_roadex_approval(
            store,
            binding_draft_for_bundle(bundle),
            save_source_and_bundle,
        )
        mutation = verify_exact_persisted_bundle_set(store, bundle, binding)
    return public_bundle_status(bundle, binding=binding, mutation=mutation)
```

`stage_bundle_api()` must perform its authoritative bundle rebuild and second
current-root resolution before calling this persistence function on every
attempt, including replay. `verify_exact_persisted_bundle_set()` then proves
the persisted source, binding, report, bundle, and outbox all exist and match;
it rejects partial or changed replay without writing.

- [ ] **Step 5: Run store, migration, and provisioning tests**

Run: `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_core.py -k 'schema or migration or atomic or idempotent or provisioning'`

Expected: all selected tests pass and schema assertions report version `3`.

- [ ] **Step 6: Commit the atomic persistence slice**

```bash
git add src/overseer/store.py src/overseer/backup_provisioning.py src/overseer/provisioning_bundle.py tests/test_provisioning_bundle.py tests/test_roadex_approval_status.py tests/test_core.py
git commit -m "Persist provisioning bundles atomically"
```

### Task 4: Public Preflight and Authoritative Stage API and CLI

**Files:**
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/backup_provisioning_cli.py`
- Modify: `src/overseer/provisioning_bundle.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_provisioning_bundle.py`

**Interfaces:**
- Consumes: `parse_provisioning_intent()`, `build_provisioning_bundle()`, and `stage_authoritative_bundle()`.
- Produces: `preflight_bundle_api(store_path, payload)`, `stage_bundle_api(store_path, payload)`, `bundle_status(store_path, plan_id)`, POST `/backup-provisioning/bundles/preflight`, POST `/backup-provisioning/bundles/stage`, GET `/backup-provisioning/bundles?plan_id=backup-provision.donuthole.v20.20260802`, and matching CLI commands.

- [ ] **Step 1: Write failing API tests for exact input, digest comparison, authentication, and no host mutation**

```python
def test_public_stage_rebuilds_authoritatively_and_requires_expected_digests(api, intent_payload):
    preview = api.post_json("/backup-provisioning/bundles/preflight", {"intent": intent_payload}, authenticated=True).json()
    staged = api.post_json("/backup-provisioning/bundles/stage", {"intent": intent_payload, "expected_preflight_digest": preview["preflight_digest"], "expected_bundle_digest": preview["bundle_digest"]}, authenticated=True).json()
    assert staged["status"] == "staged"
    assert staged["mutation_performed"] is True
    assert staged["host_mutation_performed"] is False

def test_public_stage_rejects_stale_preview_without_writes(api, intent_payload):
    response = api.post_json("/backup-provisioning/bundles/stage", {"intent": intent_payload, "expected_preflight_digest": "sha256:" + "0" * 64, "expected_bundle_digest": "sha256:" + "1" * 64}, authenticated=True)
    assert response.status_code == 400
    assert response.json()["error_code"] == "AUTHORITATIVE_REBUILD_MISMATCH"
    assert api.get_json("/backup-provisioning/bundles")["items"] == []
```

- [ ] **Step 2: Run API tests and confirm routes are missing**

Run: `pytest -q tests/test_core.py tests/test_provisioning_bundle.py -k 'public_stage or bundle_api'`

Expected: requests return `404` or tests fail because API helper functions are undefined.

- [ ] **Step 3: Implement preview and authoritative rebuild helpers**

```python
def preflight_bundle_api(store_path: str, payload: Mapping[str, object]) -> Mapping[str, object]:
    if set(payload) != {"intent"} or not isinstance(payload["intent"], Mapping):
        raise ValueError("exact provisioning preflight fields are required")
    bundle = build_provisioning_bundle(store_path, parse_provisioning_intent(payload["intent"]), production_preflight_dependencies())
    return public_bundle_preview(bundle)

def stage_bundle_api(store_path: str, payload: Mapping[str, object]) -> Mapping[str, object]:
    required = {"intent", "expected_preflight_digest", "expected_bundle_digest"}
    if set(payload) != required or not isinstance(payload["intent"], Mapping):
        raise ValueError("exact authoritative bundle stage fields are required")
    bundle = build_provisioning_bundle(store_path, parse_provisioning_intent(payload["intent"]), production_preflight_dependencies())
    if bundle.preflight.report_digest != payload["expected_preflight_digest"] or bundle.bundle_digest != payload["expected_bundle_digest"]:
        raise ProvisioningBundleError("AUTHORITATIVE_REBUILD_MISMATCH")
    return stage_authoritative_bundle(store_path, bundle)
```

- [ ] **Step 4: Wire authenticated API and CLI routes without exposing raw bundle staging**

```python
if path == "/backup-provisioning/bundles/preflight":
    self._handle_json(lambda payload: preflight_bundle_api(store_path, payload))
    return
if path == "/backup-provisioning/bundles/stage":
    self._handle_json(lambda payload: stage_bundle_api(store_path, payload))
    return
```

CLI commands and arguments:

```text
bundle-preflight --intent-json /tmp/donuthole-provisioning-intent-v20.json
bundle-stage --intent-json /tmp/donuthole-provisioning-intent-v20.json --expected-preflight-digest sha256:0000000000000000000000000000000000000000000000000000000000000000 --expected-bundle-digest sha256:1111111111111111111111111111111111111111111111111111111111111111
bundle-status --plan-id backup-provision.donuthole.v20.20260802
```

- [ ] **Step 5: Run API and CLI regressions**

Run: `pytest -q tests/test_core.py tests/test_provisioning_bundle.py -k 'bundle_api or bundle_cli or public_stage or authentication or redaction'`

Expected: all selected tests pass; preview reports both mutation flags false and stage reports only control-store mutation.

- [ ] **Step 6: Commit the public interface slice**

```bash
git add src/overseer/api.py src/overseer/backup_provisioning_cli.py src/overseer/provisioning_bundle.py tests/test_core.py tests/test_provisioning_bundle.py
git commit -m "Expose authoritative provisioning bundle API"
```

### Task 5: Atomic Review Outbox Materialization and Exact Dispatch

**Files:**
- Modify: `src/overseer/provisioning_bundle.py`
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/backup_provisioning_cli.py`
- Modify: `tests/test_provisioning_bundle.py`
- Modify: `tests/test_backup_provisioning_review_flow.py`

**Interfaces:**
- Consumes: committed `ProvisioningReviewOutboxEntry` rows and existing `_dispatch_crew_message()` typed reviewers.
- Produces: `materialize_review_outbox(store_path, outbox_id)`, `dispatch_provisioning_review_outbox_status(store_path, outbox_id, dispatched_by, dispatched_at=None)`, and POST `/backup-provisioning/review-outbox/dispatch`.

- [ ] **Step 1: Write failing committed-ordering and idempotency tests**

```python
def test_outbox_materialization_requires_committed_matching_plan(tmp_path):
    store_path = seeded_bundle_store(tmp_path)
    delete_plan_row_without_committing_fixture(store_path)
    with pytest.raises(ValueError, match="committed exact plan"):
        materialize_review_outbox(store_path, "outbox.backup-provision.v20.kira")
    assert crew_ids(store_path) == ()

def test_exact_outbox_dispatch_creates_one_bound_review(tmp_path):
    store_path = seeded_bundle_store(tmp_path)
    first = dispatch_provisioning_review_outbox_status(store_path, "outbox.backup-provision.v20.kira", "sisko")
    second = dispatch_provisioning_review_outbox_status(store_path, "outbox.backup-provision.v20.kira", "sisko")
    assert first["message"]["owner_domain"] == "kira"
    assert first["message"]["request_evidence_ids"] == [PLAN_DIGEST, PREFLIGHT_DIGEST, BUNDLE_DIGEST]
    assert second["mutation_performed"] is False
    assert crew_ids(store_path) == ("crew.kira.review-backup-provision.v20",)
```

- [ ] **Step 2: Run outbox tests and confirm missing dispatcher**

Run: `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning_review_flow.py -k outbox`

Expected: failures report undefined materialization and dispatch functions.

- [ ] **Step 3: Implement atomic materialization from committed rows**

```python
def materialize_review_outbox(store_path: str, outbox_id: str) -> Mapping[str, object]:
    with SQLiteStore(store_path) as store:
        with store.agent_transaction():
            entry = load_exact_outbox(store, outbox_id)
            if entry.state not in {"pending", "materialized", "dispatched"}:
                raise ValueError("review outbox state is invalid")
            assert_committed_bundle_plan_match(store, entry)
            try:
                existing = store.load_crew_message(entry.message_id)
            except KeyError:
                existing = None
            expected = crew_message_from_outbox(entry)
            if existing is not None and existing != expected:
                raise ValueError("review message ID is immutable")
            if existing is None:
                store.save_crew_message(expected)
            store.update_provisioning_review_outbox_state(entry.id, "materialized")
    return {"ok": True, "message": crew_message_status(expected), "mutation_performed": existing is None, "host_mutation_performed": False}
```

- [ ] **Step 4: Dispatch only the exact materialized message and persist outbox completion**

```python
def dispatch_provisioning_review_outbox_status(store_path: str, outbox_id: str, dispatched_by: str, dispatched_at: str | None = None) -> Mapping[str, object]:
    materialized = materialize_review_outbox(store_path, outbox_id)
    message_id = str(materialized["message"]["id"])
    result = dispatch_crew_messages_status(store_path, message_id=message_id, dispatched_by=dispatched_by, dispatched_at=dispatched_at)
    if result["processed"] != 1 or result["items"][0]["review_status"] not in {"approved", "correction_requested", "rejected"}:
        raise ProvisioningBundleError("REVIEW_DISPATCH_NOT_TERMINAL")
    mark_outbox_dispatched(store_path, outbox_id, message_id)
    return {"ok": True, "outbox_id": outbox_id, "message": result["items"][0], "mutation_performed": True, "host_mutation_performed": False}
```

- [ ] **Step 5: Run review-flow and dispatcher tests**

Run: `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning_review_flow.py tests/test_backup_provisioning.py -k 'outbox or dispatch or terminal_evidence'`

Expected: all selected tests pass; no reviewer observes an absent plan and repeated dispatch does not create a second message.

- [ ] **Step 6: Commit the review-outbox slice**

```bash
git add src/overseer/provisioning_bundle.py src/overseer/cli.py src/overseer/api.py src/overseer/backup_provisioning_cli.py tests/test_provisioning_bundle.py tests/test_backup_provisioning_review_flow.py
git commit -m "Dispatch provisioning reviews from atomic outbox"
```

### Task 6: Approval Gate, Legacy Compatibility, and Capability Verification

**Files:**
- Modify: `src/overseer/backup_provisioning.py`
- Modify: `tests/test_backup_provisioning.py`
- Modify: `tests/test_ui_regression.py`
- Modify: `tests/test_core.py`
- Modify: `docs/superpowers/specs/2026-08-02-donuthole-provisioning-reliability-design.md`

**Interfaces:**
- Consumes: persisted exact approval binding, bundle, passing preflight report,
  dispatched outbox, and exact terminal crew evidence.
- Produces: `_require_bundle_preflight_and_reviews(store, plan)`, stable `TYPED_BUNDLE_REQUIRED`, `PREFLIGHT_NOT_CURRENT`, and `SUCCESSOR_REQUIRED` errors, plus Roadex readiness blockers.

- [ ] **Step 1: Write failing approval and compatibility tests**

```python
def test_human_approval_requires_exact_bundle_preflight_and_reviews(tmp_path):
    store_path, plan = staged_bundle_fixture(tmp_path, preflight_passed=False)
    with pytest.raises(ValueError, match="passing exact preflight"):
        approve_plan(store_path, plan.plan_id, "independent-human")
    queue = list_roadex_human_decisions(store_path)
    assert queue["items"][0]["ready"] is False
    assert "passing exact preflight" in queue["items"][0]["blockers"]

def test_legacy_terminal_plans_remain_readable_but_legacy_staged_plan_requires_successor(tmp_path):
    store_path = legacy_plan_store(tmp_path)
    assert {item["status"] for item in list_plans(store_path)["items"]} == {"rolled_back", "staged"}
    with pytest.raises(ValueError, match="typed bundle successor"):
        approve_plan(store_path, "backup-provision.legacy-staged", "independent-human")
```

- [ ] **Step 2: Run approval/UI tests and confirm the missing gate**

Run: `pytest -q tests/test_backup_provisioning.py tests/test_ui_regression.py -k 'bundle or preflight or legacy or successor'`

Expected: legacy staged approval currently succeeds or fails for the wrong reason, and Roadex readiness lacks the preflight blocker.

- [ ] **Step 3: Require exact persisted bundle, passing report, and terminal outbox reviews**

```python
def _require_bundle_preflight_and_reviews(store: SQLiteStore, plan: DonutHoleBackupProvisioningPlan) -> None:
    bundle = load_bundle_for_plan(store, plan.plan_id)
    if bundle is None:
        raise ValueError("typed bundle successor is required for legacy staged plan")
    report = load_report_for_bundle(store, bundle)
    if not report.passed or report.report_digest != bundle.preflight.report_digest:
        raise ValueError("passing exact preflight is required")
    if bundle.plan.plan_digest != plan.plan_digest or bundle.bundle_digest != recompute_bundle_digest(bundle):
        raise ValueError("exact immutable provisioning bundle is required")
    for entry in bundle.outbox:
        if entry.state != "dispatched":
            raise ValueError(f"terminal dispatched {entry.role} outbox evidence is required")
    _require_terminal_evidence(store, plan)
```

- [ ] **Step 4: Keep compatibility explicit and non-transferrable**

Compatibility policy to encode in tests and documentation:

```text
Terminal legacy plans remain listable and auditable with their original digest.
Legacy staged plans without a typed bundle cannot receive new approval and require a successor.
Legacy sources without a prospective exact approval binding cannot be
retroactively projected and require a successor.
Existing approved plans are not rewritten; deployment must explicitly decide whether to execute or supersede each one.
The raw /backup-provisioning/stage route returns TYPED_BUNDLE_REQUIRED for new requests after feature enablement.
Non-provisioning crew dispatch remains unchanged.
No legacy approval, review, report, or digest transfers to a successor.
```

- [ ] **Step 5: Run the complete Capability B regression set**

Run: `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_backup_provisioning_review_flow.py tests/test_ui_regression.py tests/test_core.py -k 'provisioning or roadex_human or bundle or preflight or outbox'`

Expected: all selected tests pass.

Run: `pytest -q tests/test_backup_cross_repo_contract.py`

Expected: all tests pass or only the existing sibling-environment skip is reported.

Run: `pytest -q`

Expected: the full Overseer suite passes with no failures.

Run: `git diff --check`

Expected: no output and exit status 0.

- [ ] **Step 6: Document implemented interfaces and approval boundaries**

Append this exact compatibility summary to the Capability B section of the design:

```markdown
Implemented interfaces: `ProvisioningIntentV1`, digest-bound preflight preview,
authoritative intent rebuild at stage time, atomic bundle and review outbox, and
exact idempotent outbox dispatch. Terminal legacy plans remain auditable;
legacy staged plans require a typed successor. Bundle staging and review
dispatch mutate only Overseer control state. Independent human approval,
service deployment, and privileged provisioning remain separate gates.
```

- [ ] **Step 7: Commit the approval and compatibility slice**

```bash
git add src/overseer/backup_provisioning.py tests/test_backup_provisioning.py tests/test_ui_regression.py tests/test_core.py docs/superpowers/specs/2026-08-02-donuthole-provisioning-reliability-design.md
git commit -m "Gate provisioning approval on typed preflight"
```

## Migration and Deployment Boundary

Implementation commits do not authorize deployment. Before restarting `overseer-api.service`, inspect the live database for staged and approved legacy plans, record the compatibility decision for each exact ID, back up the owner-only SQLite store, run the schema migration against a disposable copy, and stage a separate admin restart plan. After explicit restart approval, verify authenticated health, bundle preflight, bundle status, outbox status, and Roadex readiness without approving or executing a provisioning plan.

## Execution Handoff

Plan implementation must use either `superpowers:subagent-driven-development` with a fresh worker and review gate per task or `superpowers:executing-plans` with task checkpoints. Each task's commit is local implementation history only; pushing, service restart, migration of the live store, DonutHole provisioning, and human approval require their existing separate authorization boundaries.
