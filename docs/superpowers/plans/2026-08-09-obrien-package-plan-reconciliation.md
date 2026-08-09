# O'Brien Package Plan Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make station-audit package plans durable, deduplicated, exactly routed through Sisko and O'Brien, safe from resource-ID/package confusion, and incapable of live execution without independent activation and freshness gates.

**Architecture:** Persist content-addressed package inspection records and reconcile them into provenance-backed admin plans with stable batch identities. A package-specific transactional workflow owns Sisko approval and exact O'Brien messages; the generic executor centrally enforces activation, exact-message, and fresh-inspection requirements. Existing live maintenance-cycle behavior is disabled, while CLI/API surfaces expose preview, reconciliation, activation requests, and separately approved exact-ID legacy cleanup.

**Tech Stack:** Python 3.11+, frozen dataclasses, SQLite, stdlib SHA-256/JSON, existing Overseer CLI/API/client, pytest.

## Global Constraints

- No production code without a failing test first; record RED and GREEN command output for every task.
- Never pass `related_resource_id` into package planning or an APT command.
- Never infer package-plan origin, freshness, or batch membership from a plan ID.
- Never auto-enable an admin adapter, auto-archive history, or execute APT during tests, station audit, preview, reconciliation, or source deployment.
- Package execution activation defaults off and can be approved only from authenticated human server context, never caller-supplied identity text.
- Preserve all existing unrelated behavior and the historical `port.loopback.8798` failed evidence.
- Work only in `.worktrees/obrien-package-reconciliation`; do not modify the dirty main checkout.

---

### Task 1: Immutable package evidence and transactional persistence

**Files:**
- Modify: `src/overseer/packages.py`
- Modify: `src/overseer/store.py`
- Modify: `tests/test_agent_store.py`
- Create: `tests/test_package_reconciliation.py`
- Create: `tests/package_workflow_fixtures.py`

**Interfaces:**
- Produces: `PackageInspectionRecord`, `PackageReconciliationEvidence`, `package_state_fingerprint(snapshot)`, `package_inspection_record(snapshot)`, and immutable store save/load/list methods.
- Consumes: existing `PackageInspectionSnapshot`, `PackageUpdate`, `SQLiteStore.agent_transaction()`.

- [ ] **Step 1: Write failing evidence and transaction tests**

Create the shared fixtures used by every later test:

```python
class StaticPackageInspector:
    def __init__(self, snapshot: PackageInspectionSnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0

    def inspect(self, captured_at: str | None = None) -> PackageInspectionSnapshot:
        self.calls += 1
        return replace(self.snapshot, captured_at=captured_at or self.snapshot.captured_at)


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, step: AdminCommandStep) -> AdminCommandResult:
        self.commands.append(step.command)
        return AdminCommandResult(step.title, step.command, 0, "ok", "")


def package_snapshot(captured_at: str, *updates: PackageUpdate) -> PackageInspectionSnapshot:
    return PackageInspectionSnapshot(
        id=f"package-inspection.{captured_at}", captured_at=captured_at,
        command=("apt", "list", "--upgradable"), exit_code=0,
        updates=tuple(updates), stderr="",
    )


def initialized_store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "overseer.sqlite3")
    store.initialize()
    return store
```

The same fixture module owns every builder used below, with these exact
signatures: `blocked_execution(plan_id)`, `execution_for(plan_id, status)`,
`persisted_record(store, fingerprint)`, `seed_provenance_plan(store,
fingerprint)`, `seed_legacy_apt_plan(store)`,
`seed_package_plan_and_record(store, kind, approved)`,
`seed_open_linked_messages(store, plan_id, count)`, `close_message(store,
message_id)`, `seed_current_sisko_workflow(store, activated)`,
`load_record_for(plan)`, `seed_closed_package_message(tmp_path)`,
`seed_current_sisko_message(tmp_path)`,
`seed_human_plan_sisko_message(tmp_path)`,
`seed_obrien_backup_message(tmp_path)`, `seed_sisko_backup_message(tmp_path)`,
`seed_ready_package_plan(store, activated)`,
`seed_ready_execution_workflow(store, **fresh_state)`, and
`seed_non_package_admin_plan(store)`. Each builder uses only temporary SQLite
stores, `StaticPackageInspector`, and `RecordingRunner`; none calls live APT.

```python
def test_package_record_identity_is_content_addressed_when_timestamps_match():
    first = package_inspection_record(package_snapshot("2026-08-09T12:00:00Z", bash_update("5.2")))
    second = package_inspection_record(package_snapshot("2026-08-09T12:00:00Z", bash_update("5.3")))
    assert first.id != second.id


def test_package_record_store_is_insert_only_and_idempotent(tmp_path):
    store = initialized_store(tmp_path)
    record = package_inspection_record(package_snapshot("2026-08-09T12:00:00Z", bash_update("5.2")))
    store.save_package_inspection_record(record)
    store.save_package_inspection_record(record)
    with pytest.raises(ValueError, match="immutable package inspection collision"):
        store.save_package_inspection_record(replace(record, stderr="changed"))


def test_admin_execution_rolls_back_with_outer_agent_transaction(tmp_path):
    store = initialized_store(tmp_path)
    with pytest.raises(RuntimeError):
        with store.agent_transaction():
            store.save_admin_execution(blocked_execution("admin.test"))
            raise RuntimeError("rollback")
    assert store.list_admin_executions() == ()
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_reconciliation.py tests/test_agent_store.py -x`

Expected: FAIL because the package evidence types/store methods do not exist and `save_admin_execution()` commits inside the outer transaction.

- [ ] **Step 3: Implement canonical evidence models**

```python
@dataclass(frozen=True)
class PackageInspectionRecord:
    id: str
    captured_at: str
    command: tuple[str, ...]
    exit_code: int
    updates: tuple[PackageUpdate, ...]
    state_fingerprint: str
    stderr: str = ""

    def succeeded(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class PackageReconciliationEvidence:
    id: str
    snapshot_id: str
    maintenance_batch_id: str
    observed_at: str
    outcome: str
    plan_ids: tuple[str, ...] = ()
    message_ids: tuple[str, ...] = ()


def package_state_fingerprint(snapshot: PackageInspectionSnapshot) -> str:
    rows = [
        {
            "architecture": item.architecture or "",
            "candidate_version": item.candidate_version or "",
            "installed_version": item.installed_version or "",
            "name": item.name or "",
            "repository": item.repository or "",
        }
        for item in sorted(snapshot.updates, key=lambda value: (value.name, value.architecture))
    ]
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def package_inspection_record(snapshot: PackageInspectionSnapshot) -> PackageInspectionRecord:
    fingerprint = package_state_fingerprint(snapshot)
    record_payload = json.dumps(
        {"captured_at": snapshot.captured_at, "command": snapshot.command,
         "exit_code": snapshot.exit_code, "fingerprint": fingerprint,
         "stderr": snapshot.stderr},
        sort_keys=True, separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(record_payload).hexdigest()
    return PackageInspectionRecord(
        id=f"{snapshot.id}.{digest[:16]}", captured_at=snapshot.captured_at,
        command=snapshot.command, exit_code=snapshot.exit_code,
        updates=snapshot.updates, state_fingerprint=fingerprint, stderr=snapshot.stderr,
    )
```

- [ ] **Step 4: Add schema/store primitives and nested-commit fix**

```python
CREATE TABLE IF NOT EXISTS package_inspection_records (
    id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS package_reconciliation_evidence (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL,
    maintenance_batch_id TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_package_reconciliation_snapshot
ON package_reconciliation_evidence (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_package_reconciliation_batch
ON package_reconciliation_evidence (maintenance_batch_id);
```

```python
def save_package_inspection_record(self, record: PackageInspectionRecord) -> None:
    payload = _dump(record)
    existing = self._connection.execute(
        "SELECT payload FROM package_inspection_records WHERE id = ?", (record.id,)
    ).fetchone()
    if existing is not None:
        if str(existing["payload"]) != payload:
            raise ValueError("immutable package inspection collision")
        return
    self._connection.execute(
        "INSERT INTO package_inspection_records (id, payload) VALUES (?, ?)",
        (record.id, payload),
    )
    self._commit_agent_mutation()


def save_admin_execution(self, result: AdminExecutionResult) -> None:
    self._connection.execute(
        "INSERT OR REPLACE INTO admin_executions (id, plan_id, payload) VALUES (?, ?, ?)",
        (result.id, result.plan_id, _dump(result)),
    )
    self._commit_agent_mutation()
```

Bump `CURRENT_SCHEMA_VERSION` to `3`, preserve existing tables, and update schema-version assertions.

- [ ] **Step 5: Run tests and verify GREEN**

Run: `pytest -q tests/test_package_reconciliation.py tests/test_agent_store.py -x`

Expected: PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add src/overseer/packages.py src/overseer/store.py tests/package_workflow_fixtures.py tests/test_agent_store.py tests/test_package_reconciliation.py
git commit -m "Persist immutable package inspection evidence"
```

---

### Task 2: Provenance-backed plan reconciliation

**Files:**
- Modify: `src/overseer/admin.py`
- Create: `src/overseer/package_reconciliation.py`
- Modify: `tests/test_package_reconciliation.py`

**Interfaces:**
- Consumes: Task 1 evidence/store APIs, existing APT plan builders, crew message model.
- Produces: `reconcile_package_inspection(store, record, selected_package_names=(), preview=False, live_execution_activated=False, observed_at=None) -> dict[str, object]`.

- [ ] **Step 1: Write failing provenance, missing-package, dedupe, cancellation, and preview tests**

```python
def test_missing_requested_package_writes_nothing(store, successful_record):
    store.save_package_inspection_record(successful_record)
    result = reconcile_package_inspection(store, successful_record, ("missing",))
    assert result["plans"] == 0
    assert result["missing_packages"] == ("missing",)
    assert store.list_admin_change_plans() == ()
    assert store.list_crew_messages() == ()


def test_same_state_new_snapshot_reuses_batch_and_plans(store, two_equal_state_records):
    first, second = two_equal_state_records
    one = reconcile_package_inspection(store, first)
    two = reconcile_package_inspection(store, second)
    assert two["maintenance_batch_id"] == one["maintenance_batch_id"]
    assert two["plan_ids"] == one["plan_ids"]
    assert len(store.list_package_reconciliation_evidence()) == 2


def test_workflow_message_id_is_deterministic_by_batch_plan_and_stage():
    approval = package_workflow_message_id("batch", "plan", "sisko_approval")
    execution = package_workflow_message_id("batch", "plan", "obrien_execution")
    assert approval == package_workflow_message_id("batch", "plan", "sisko_approval")
    assert approval != execution


@pytest.mark.parametrize(
    ("kind", "approved", "activated", "owner"),
    [("apt_update", False, False, None),
     ("apt_update", False, True, "obrien"),
     ("apt_upgrade", False, False, "sisko"),
     ("apt_upgrade", False, True, "sisko"),
     ("apt_upgrade", True, False, None),
     ("apt_upgrade", True, True, "obrien")],
)
def test_reconciliation_routes_each_plan_state(store, kind, approved, activated, owner):
    plan, record = seed_package_plan_and_record(store, kind=kind, approved=approved)
    result = reconcile_package_inspection(store, record, live_execution_activated=activated)
    owners = [message.owner_domain.value for message in store.list_crew_messages()]
    assert (owner in owners) if owner else owners == []
    if not activated and (kind == "apt_update" or approved):
        assert result["next_gate"] == "waiting_execution_activation"


def test_terminal_package_message_is_not_recreated(store):
    record = persisted_record(store, fingerprint="current")
    first = reconcile_package_inspection(store, record)
    close_message(store, first["sisko_message_ids"][0])
    second = reconcile_package_inspection(store, record)
    assert second["sisko_message_ids"] == first["sisko_message_ids"]
    assert len(store.list_crew_messages()) == 1


def test_canceling_stale_plan_closes_every_open_linked_message(store):
    plan = seed_provenance_plan(store, fingerprint="old")
    linked = seed_open_linked_messages(store, plan.id, count=2)
    reconcile_package_inspection(store, persisted_record(store, fingerprint="new"))
    assert all(store.load_crew_message(item.id).status == CrewMessageStatus.CLOSED
               for item in linked)


@pytest.mark.parametrize("status", ["completed", "failed", "blocked"])
def test_reconciliation_never_cancels_plan_with_execution_evidence(store, status):
    original = seed_provenance_plan(store, fingerprint="old")
    store.save_admin_execution(execution_for(original.id, status))
    reconcile_package_inspection(store, persisted_record(store, fingerprint="new"))
    assert store.load_admin_change_plan(original.id).canceled is False


def test_changed_state_cancels_only_unattempted_provenance_plan(store):
    original = seed_provenance_plan(store, fingerprint="old")
    result = reconcile_package_inspection(store, persisted_record(store, fingerprint="new"))
    assert store.load_admin_change_plan(original.id).canceled is True
    assert result["canceled_plan_ids"] == (original.id,)


def test_legacy_plan_is_reported_and_not_changed(store):
    legacy = seed_legacy_apt_plan(store)
    result = reconcile_package_inspection(store, persisted_record(store, fingerprint="new"))
    assert result["manual_review_plan_ids"] == (legacy.id,)
    assert store.load_admin_change_plan(legacy.id) == legacy


def test_preview_returns_decision_without_writes(store):
    record = persisted_record(store, fingerprint="current")
    result = reconcile_package_inspection(store, record, preview=True)
    assert result["plans"] == 2
    assert result["mutation_performed"] is False
    assert store.list_admin_change_plans() == ()


def test_reconciliation_transaction_rolls_back_all_outputs(store, monkeypatch):
    record = persisted_record(store, fingerprint="current")
    monkeypatch.setattr(store, "save_package_reconciliation_evidence",
                        lambda value: (_ for _ in ()).throw(RuntimeError("stop")))
    with pytest.raises(RuntimeError, match="stop"):
        reconcile_package_inspection(store, record)
    assert store.list_admin_change_plans() == ()
    assert store.list_crew_messages() == ()
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_reconciliation.py -x`

Expected: FAIL because provenance fields and reconciler are absent.

- [ ] **Step 3: Add backward-compatible provenance to `AdminChangePlan`**

```python
@dataclass(frozen=True)
class AdminChangePlan:
    # existing required fields remain unchanged
    archived_at: str | None = None
    archive_record_id: str | None = None
    plan_origin: str | None = None
    source_snapshot_id: str | None = None
    source_snapshot_captured_at: str | None = None
    package_state_fingerprint: str | None = None
    maintenance_batch_id: str | None = None
    selected_package_names: tuple[str, ...] = ()
```

Add `with_package_inspection_provenance(plan, record, batch_id, selected_names)` using `dataclasses.replace`; do not change generic APT builders.

- [ ] **Step 4: Implement stable batch IDs and transactional reconciliation**

```python
PACKAGE_PLAN_ORIGIN = "package_inspection"


def package_maintenance_batch_id(state_fingerprint: str, names: Sequence[str]) -> str:
    selected = json.dumps(sorted(set(names)), separators=(",", ":")).encode()
    selection = hashlib.sha256(selected).hexdigest()
    return f"package.batch.{state_fingerprint[:16]}.{selection[:16]}"


def reconcile_package_inspection(store, record, selected_package_names=(), *,
                                 preview=False, live_execution_activated=False,
                                 observed_at=None, require_persisted=True):
    persisted = store.load_package_inspection_record(record.id) if require_persisted else record
    if persisted != record or not record.succeeded():
        return _failed_or_unpersisted_result(record)
    detected = {item.name for item in record.updates}
    selected = tuple(sorted(set(selected_package_names or detected)))
    missing = tuple(name for name in selected if name not in detected)
    if missing:
        return _missing_result(record, missing)
    decision = _build_reconciliation_decision(store, record, selected,
                                              live_execution_activated, observed_at)
    if preview:
        return decision.status(mutation_performed=False)
    with store.agent_transaction():
        _apply_reconciliation_decision(store, decision)
    return decision.status(mutation_performed=True)
```

Decision construction must inspect all execution rows by `plan_id`, retain ambiguous legacy plans, reuse active unattempted fingerprint/selection matches, cancel only provenance-backed unattempted mismatches, close every open linked message, create deterministic stage messages with `package_workflow_message_id(batch_id, plan_id, stage)`, and persist one reconciliation evidence row per snapshot/batch. Route no-approval updates and already-approved upgrades to O'Brien only when activation is on; while activation is off they report `waiting_execution_activation` and create no executable message. Preview passes `require_persisted=False`, builds the same decision from a transient canonical record, and writes no record, plan, message, evidence, or cancellation.

- [ ] **Step 5: Run focused and compatibility tests**

Run: `pytest -q tests/test_package_reconciliation.py tests/test_agent_store.py -x`

Expected: PASS.

- [ ] **Step 6: Commit Task 2**

```bash
git add src/overseer/admin.py src/overseer/package_reconciliation.py tests/test_package_reconciliation.py
git commit -m "Reconcile provenance-backed package plans"
```

---

### Task 3: Authoritative Sisko approval and live-execution activation

**Files:**
- Modify: `src/overseer/admin.py`
- Modify: `src/overseer/package_reconciliation.py`
- Modify: `src/overseer/store.py`
- Modify: `src/overseer/store.py`
- Create: `tests/test_package_workflow_authority.py`

**Interfaces:**
- Produces: `PackageExecutionActivation`, activation store methods, `package_execution_activated(store)`, and `approve_package_plan_from_sisko_message(store, message_id, decided_at)`.
- Consumes: exact provenance/batch/message fields from Task 2.

- [ ] **Step 1: Write failing generic-approval and activation tests**

```python
def test_generic_approval_rejects_inspection_sisko_apt_plan(package_upgrade_plan):
    with pytest.raises(ValueError, match="package-specific Sisko workflow"):
        approve_admin_change_plan(package_upgrade_plan, "sisko")


def test_generic_approval_preserves_non_package_behavior(non_package_plan):
    assert approve_admin_change_plan(non_package_plan, "operator").approved is True


def test_sisko_transition_requires_exact_open_sisko_message(store):
    with pytest.raises(ValueError, match="open Sisko package message"):
        approve_package_plan_from_sisko_message(store, "crew.sisko.missing", NOW)


def test_sisko_transition_is_atomic_and_activation_off_queues_no_obrien(store):
    plan, message = seed_current_sisko_workflow(store, activated=False)
    result = approve_package_plan_from_sisko_message(store, message.id, NOW)
    assert result["state"] == "waiting_execution_activation"
    assert store.load_admin_change_plan(plan.id).approved is True
    assert not [item for item in store.list_crew_messages()
                if item.owner_domain == OwnerDomain.OBRIEN]


def test_approved_activation_queues_exact_obrien_message_once(store):
    plan, message = seed_current_sisko_workflow(store, activated=True)
    first = approve_package_plan_from_sisko_message(store, message.id, NOW)
    with pytest.raises(ValueError, match="open Sisko package message"):
        approve_package_plan_from_sisko_message(store, message.id, NOW)
    reconcile_package_inspection(store, load_record_for(plan), live_execution_activated=True)
    obrien = [item for item in store.list_crew_messages()
              if item.owner_domain == OwnerDomain.OBRIEN]
    assert first["obrien_message_id"] == obrien[0].id
    assert [item.related_plan_id for item in obrien] == [plan.id]
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_workflow_authority.py -x`

Expected: FAIL because generic approval still accepts caller text and activation/Sisko transition do not exist.

- [ ] **Step 3: Add the model authority invariant**

```python
def is_inspection_originated_sisko_apt_plan(plan: AdminChangePlan) -> bool:
    return (
        plan.plan_origin == "package_inspection"
        and plan.kind in {AdminChangeKind.APT_UPDATE, AdminChangeKind.APT_UPGRADE}
        and plan.approval_level == ApprovalLevel.SISKO
    )


def approve_admin_change_plan(plan, approved_by, approved_at=None):
    if is_inspection_originated_sisko_apt_plan(plan):
        raise ValueError("inspection-originated Sisko APT plans require the package-specific Sisko workflow")
    # preserve existing validation and replacement
```

- [ ] **Step 4: Add activation model/store and atomic Sisko transition**

```python
class PackageExecutionActivationStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"


@dataclass(frozen=True)
class PackageExecutionActivation:
    id: str
    scope: str
    status: PackageExecutionActivationStatus
    requested_by: str
    requested_at: str
    approved_by: str | None = None
    approved_at: str | None = None
    revoked_by: str | None = None
    revoked_at: str | None = None
    evidence_ids: tuple[str, ...] = ()
```

Persist these in `package_execution_activations`; require scope exactly `maintenance.package_reconciliation_live_execution` and add a test proving another scope cannot activate execution. Approval functions accept a trusted server-derived identity argument and never a request-payload identity. Implement the Sisko transition over one store connection/transaction: reload the open non-superseded Sisko message, validate requester `obrien`, exact current provenance-backed plan and batch, use `replace(plan, approved=True, approved_by="sisko", approved_at=decided_at)`, close the Sisko message with audit evidence, and conditionally insert the deterministic O'Brien message only when activation is approved.

- [ ] **Step 5: Run tests and verify GREEN**

Run: `pytest -q tests/test_package_workflow_authority.py tests/test_package_reconciliation.py -x`

Expected: PASS.

- [ ] **Step 6: Commit Task 3**

```bash
git add src/overseer/admin.py src/overseer/package_reconciliation.py src/overseer/store.py tests/test_package_workflow_authority.py
git commit -m "Enforce authoritative package workflow approval"
```

---

### Task 4: Exact crew dispatch and port/resource correction

**Files:**
- Modify: `src/overseer/cli.py`
- Create: `tests/test_package_workflow_dispatch.py`

**Interfaces:**
- Consumes: Task 3 Sisko transition, Task 2 reconciliation, persisted inspection adapter conversion.
- Produces: package-specific Sisko/O'Brien dispatch that uses exact message and plan IDs.

- [ ] **Step 1: Write failing port and stale-dispatch tests**

```python
def test_obrien_port_resource_never_becomes_package_filter(tmp_path, fake_inspector):
    message = record_obrien_message(related_resource_id="port.loopback.8798")
    result = dispatch_exact(message.id, inspection_adapter=fake_inspector)
    assert result["host_mutation_performed"] is False
    assert all("port.loopback.8798" not in step.command for plan in load_plans() for step in plan.steps)


def test_obrien_package_execution_requires_related_plan_id(tmp_path, fake_inspector):
    message = record_obrien_message(related_resource_id="service.example")
    result = dispatch_exact(message.id, inspection_adapter=fake_inspector)
    assert result["status"] == "dispatched"
    assert result["host_mutation_performed"] is False
    assert load_plans() == ()


def test_closed_or_superseded_message_cannot_be_acknowledged_from_stale_copy(tmp_path):
    message = seed_closed_package_message(tmp_path)
    result = dispatch_exact(message.id)
    assert result["status"] == "blocked"
    assert load_message(message.id).status == CrewMessageStatus.CLOSED


def test_sisko_dispatch_approves_exact_current_package_plan_only(tmp_path):
    plan, message = seed_current_sisko_message(tmp_path)
    result = dispatch_exact(message.id)
    assert result["status"] == "dispatched"
    assert load_plan(plan.id).approved_by == "sisko"


def test_human_level_sisko_message_remains_waiting_human_approval(tmp_path):
    plan, message = seed_human_plan_sisko_message(tmp_path)
    result = dispatch_exact(message.id)
    assert result["status"] == "human_approval_required"
    assert load_plan(plan.id).approved is False


def test_obrien_backup_plan_keeps_existing_review_path(tmp_path):
    message = seed_obrien_backup_message(tmp_path)
    result = dispatch_exact(message.id)
    assert result["actions"][0]["kind"] == "donuthole_encrypted_backup_provisioning_v1"


def test_sisko_backup_plan_keeps_existing_review_path(tmp_path):
    message = seed_sisko_backup_message(tmp_path)
    result = dispatch_exact(message.id)
    assert result["actions"][0]["kind"] == "donuthole_encrypted_backup_provisioning_v1"
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_workflow_dispatch.py -x`

Expected: FAIL with `port.loopback.8798` appearing as the package target and generic dispatch semantics.

- [ ] **Step 3: Replace resource fallback with exact-plan routing**

```python
def _dispatch_obrien_message(store_path, message, dispatched_by, dispatched_at):
    if message.related_plan_id:
        plan = _load_optional_admin_plan(store_path, message.related_plan_id)
        if plan is not None and is_inspection_package_plan(plan):
            return _dispatch_package_obrien_message(store_path, message.id, dispatched_at)
        backup = _backup_provisioning_review_item(store_path, message.related_plan_id, reviewer="obrien")
        if backup is not None:
            return _existing_obrien_backup_result(message, backup)
    inspection = inspect_packages_status(captured_at=dispatched_at)
    return _crew_dispatch_result(
        message, "dispatched",
        "O'Brien completed read-only package inspection; exact related_plan_id is required for package work",
        [inspection],
    )
```

Do not branch on `related_resource_id`; storage and port IDs remain opaque. Apply the same typed package-plan gate in Sisko dispatch and preserve existing backup/non-package behavior. `_advance_obrien_package_plan()` may ensure a Sisko message but must never approve or execute a package plan.

- [ ] **Step 4: Add package-specific compare-and-set dispatch**

```python
def _dispatch_package_sisko_message(store_path, message_id, dispatched_at):
    store = SQLiteStore(store_path)
    try:
        result = approve_package_plan_from_sisko_message(store, message_id, dispatched_at)
        return _crew_dispatch_result_from_package_transition(result)
    finally:
        store.close()


def _dispatch_package_obrien_message(store_path, message_id, dispatched_at,
                                     inspection_adapter=None):
    store = SQLiteStore(store_path)
    try:
        message = load_open_current_package_message(store, message_id, OwnerDomain.OBRIEN)
        plan = store.load_admin_change_plan(message.related_plan_id)
    finally:
        store.close()
    return execute_admin_change_status(
        store_path, plan.id,
        package_execution_message_id=message.id,
        package_inspection_adapter=inspection_adapter or AptPackageInspectionAdapter(),
    )
```

Add a dedicated branch inside `dispatch_crew_messages_status()` before the
generic stale load → handler → acknowledgment path. When the exact message is a
typed package-workflow Sisko or O'Brien stage, call its package helper, append
the helper's already-persisted result, and `continue`; do not run generic
`_automatic_crew_review()`, replace/save the stale message, or reconcile its
review again. Both helpers reload and validate message/plan/snapshot under
`agent_transaction()` and persist the complete terminal transition themselves.
Integration tests must dispatch each stage through public
`dispatch_crew_messages_status(message_id=...)` and prove the final closed
message cannot be reopened or overwritten.

- [ ] **Step 5: Run focused and existing crew tests**

Run: `pytest -q tests/test_package_workflow_dispatch.py tests/test_core.py -k 'obrien or sisko or crew_dispatch' -x`

Expected: PASS.

- [ ] **Step 6: Commit Task 4**

```bash
git add src/overseer/cli.py tests/test_package_workflow_dispatch.py
git commit -m "Route package work through exact crew messages"
```

---

### Task 5: Central execution guard and legacy-cycle shutdown

**Files:**
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/package_reconciliation.py`
- Create: `tests/test_package_execution_guards.py`

**Interfaces:**
- Produces: central provenance-package guard in `execute_admin_change_status()` and non-mutating legacy cycle response.
- Consumes: activation state, exact O'Brien message, immutable fresh inspection evidence.

- [ ] **Step 1: Write failing direct-execution and freshness tests**

```python
def test_direct_package_execute_waits_for_activation_without_calling_runner(store, runner):
    plan = seed_ready_package_plan(store, activated=False)
    result = execute_admin_change_status(store.path, plan.id, runner=runner)
    assert result["status"] == "waiting_execution_activation"
    runner.assert_not_called()


def test_activated_package_execute_requires_exact_obrien_message(store, runner):
    plan = seed_ready_package_plan(store, activated=True)
    result = execute_admin_change_status(store.path, plan.id, runner=runner)
    assert result["status"] == "exact_package_message_required"
    runner.assert_not_called()


def test_fingerprint_mismatch_closes_message_without_calling_runner(store, runner):
    plan, message = seed_ready_execution_workflow(store, fresh_fingerprint="changed")
    result = execute_exact_package_message(store, plan, message, runner)
    assert result["status"] == "freshness_revalidation_required"
    assert store.load_crew_message(message.id).status == CrewMessageStatus.CLOSED
    runner.assert_not_called()


def test_missing_selected_package_closes_message_without_calling_runner(store, runner):
    plan, message = seed_ready_execution_workflow(store, fresh_packages=())
    result = execute_exact_package_message(store, plan, message, runner)
    assert result["status"] == "freshness_revalidation_required"
    runner.assert_not_called()


def test_matching_fresh_plan_reaches_existing_policy_and_adapter_gates(store):
    plan, message = seed_ready_execution_workflow(store, adapter_enabled=False)
    result = execute_exact_package_message(store, plan, message, recording_runner())
    assert result["status"] == AdminExecutionStatus.BLOCKED.value
    assert "adapter" in result["summary"].lower()


def test_non_provenance_admin_execution_is_unchanged(store):
    plan = seed_non_package_admin_plan(store)
    result = execute_admin_change_status(store.path, plan.id, runner=successful_runner)
    assert result["status"] == AdminExecutionStatus.COMPLETED.value


def test_legacy_maintenance_cycle_is_non_mutating(store, runner):
    before = store.list_admin_change_plans()
    result = run_obrien_package_maintenance_cycle_status(store.path, runner=runner)
    assert result["status"] == "disabled_by_package_reconciliation"
    assert result["mutation_performed"] is False
    assert store.list_admin_change_plans() == before
    runner.assert_not_called()
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_execution_guards.py -x`

Expected: FAIL because direct execution and the legacy maintenance cycle bypass the new workflow.

- [ ] **Step 3: Enforce package gates before generic policy/runner invocation**

```python
def execute_admin_change_status(store_path, plan_id, runner=None,
                                policy_profile_path=None,
                                package_execution_message_id=None,
                                package_inspection_adapter=None):
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        if plan.plan_origin == "package_inspection" and plan.kind in APT_PACKAGE_KINDS:
            gate = validate_package_execution_gate(
                store, plan, package_execution_message_id,
                package_inspection_adapter or AptPackageInspectionAdapter(),
            )
            if not gate.can_execute:
                return gate.status(store.path)
        return _execute_admin_change_with_open_store(store, plan, runner, policy_profile_path)
    finally:
        store.close()
```

The gate requires approved activation, exact open O'Brien execution message, current plan/batch, and a newly persisted successful inspection whose complete fingerprint/selected set match. Mismatch closes the message with correction evidence. No runner is called on any failed gate.

- [ ] **Step 4: Disable legacy mutation**

```python
def run_obrien_package_maintenance_cycle_status(store_path, **_ignored):
    return {
        "store": str(Path(store_path)),
        "status": "disabled_by_package_reconciliation",
        "mutation_performed": False,
        "host_mutation_performed": False,
        "next_step": "use package-plan reconciliation and exact crew messages",
    }
```

- [ ] **Step 5: Run tests and verify GREEN**

Run: `pytest -q tests/test_package_execution_guards.py tests/test_package_workflow_dispatch.py -x`

Expected: PASS.

- [ ] **Step 6: Commit Task 5**

```bash
git add src/overseer/cli.py src/overseer/package_reconciliation.py tests/test_package_execution_guards.py
git commit -m "Guard provenance package execution centrally"
```

---

### Task 6: Station audit and reconciliation CLI/API/client

**Files:**
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/client.py`
- Create: `tests/test_package_workflow_api.py`

**Interfaces:**
- Produces: `reconcile-package-plans` CLI, `POST /maintenance/package-plan-reconciliation`, client method, and station-audit reconciliation.
- Consumes: Tasks 1–5 workflow APIs.

- [ ] **Step 1: Write failing station-audit/API/CLI tests**

```python
def test_station_audit_reconciles_and_routes_exact_package_plans(store, fake_inspector):
    result = audit_station_status(store.path, package_adapter=fake_inspector)
    package_action = next(item for item in result["items"]
                          if item["owner_domain"] == "obrien")
    assert package_action["sisko_message_ids"]
    assert package_action["host_mutation_performed"] is False


def test_reconciliation_api_preview_is_non_mutating(api_client, store):
    result = api_client.post("/maintenance/package-plan-reconciliation", {"preview": True})
    assert result["mutation_performed"] is False
    assert store.list_admin_change_plans() == ()


def test_reconciliation_api_missing_package_writes_zero_plans(api_client, store):
    result = api_client.post("/maintenance/package-plan-reconciliation",
                             {"packages": ["missing"]})
    assert result["plans"] == 0
    assert store.list_admin_change_plans() == ()


def test_package_maintenance_cycle_api_is_disabled_and_non_mutating(api_client, store):
    result = api_client.post("/maintenance/package-maintenance-cycle", {})
    assert result["status"] == "disabled_by_package_reconciliation"
    assert result["host_mutation_performed"] is False
    assert store.list_admin_change_plans() == ()
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_workflow_api.py -x`

Expected: FAIL because reconciliation surfaces and station-audit wiring are absent.

- [ ] **Step 3: Wire planning and station audit through persisted reconciliation**

```python
def plan_package_updates_status(store_path, captured_at=None, packages=(), adapter=None,
                                include_index_refresh_plan=True, preview=False):
    snapshot = (adapter or AptPackageInspectionAdapter()).inspect(captured_at)
    record = package_inspection_record(snapshot)
    store = SQLiteStore(store_path)
    try:
        if not preview:
            store.save_package_inspection_record(record)
        return reconcile_package_inspection(
            store, record, packages, preview=preview,
            live_execution_activated=package_execution_activated(store),
            observed_at=record.captured_at, require_persisted=not preview,
        )
    finally:
        store.close()
```

`audit_station_status()` calls this reconciled planner. Failed inspection and missing typed packages create no plans/messages. The audit never dispatches or executes.

- [ ] **Step 4: Add reconciliation CLI/API/client**

```python
def reconcile_package_plans(self, packages=(), captured_at=None, preview=False):
    return self._post("/maintenance/package-plan-reconciliation", {
        "packages": list(packages), "captured_at": captured_at, "preview": preview,
    })
```

Add the authenticated reconciliation preview/apply route and corresponding CLI parser/handler. Preview must use the transient-record path and leave every store table unchanged.

- [ ] **Step 5: Run focused station/API tests**

Run: `pytest -q tests/test_package_workflow_api.py tests/test_core.py -k 'package or audit_station' -x`

Expected: PASS.

- [ ] **Step 6: Commit Task 6**

```bash
git add src/overseer/cli.py src/overseer/api.py src/overseer/client.py tests/test_package_workflow_api.py
git commit -m "Expose package plan reconciliation"
```

---

### Task 7: Human-authoritative activation surfaces

**Files:**
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/client.py`
- Modify: `tests/test_package_workflow_api.py`

**Interfaces:**
- Produces: activation request/inspect/revoke routes plus a human-only approve route.
- Consumes: Task 3 activation model/store authority.

- [ ] **Step 1: Write failing API authority tests**

```python
def test_activation_approval_rejects_agent_token_and_payload_identity(api_client):
    response = api_client.post_raw("/maintenance/package-execution-activation/approve",
                                   {"decided_by": "human"}, auth="agent")
    assert response.status_code == 403


def test_activation_approval_uses_authenticated_human_identity(human_api_client):
    result = human_api_client.post("/maintenance/package-execution-activation/approve", {})
    assert result["status"] == "approved"
    assert result["approved_by"] == human_api_client.identity


def test_activation_rejects_non_package_scope(human_api_client):
    response = human_api_client.post_raw(
        "/maintenance/package-execution-activation/approve", {"scope": "other"}
    )
    assert response.status_code == 400
```

Construct both API clients with the repository's existing server harness: the agent client uses the normal bearer token; the human client supplies the independent human token configured on `serve_api()` and records the server-resolved identity. Neither helper permits a payload identity to become authoritative.

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_workflow_api.py -k 'activation' -x`

Expected: FAIL because the activation routes are absent.

- [ ] **Step 3: Implement activation routes and client methods**

Create/get/revoke use normal authenticated agent context. Approve requires independent human authentication, rejects payload `decided_by`, derives the approver from server context, and passes only that trusted identity to the Task 3 transition. Generic claim/admin approval routes cannot approve activation.

- [ ] **Step 4: Run tests and commit Task 7**

Run: `pytest -q tests/test_package_workflow_api.py -k 'activation or generic_admin_approve' -x`

Expected: PASS.

```bash
git add src/overseer/api.py src/overseer/client.py tests/test_package_workflow_api.py
git commit -m "Add human-authoritative package activation"
```

---

### Task 8: Exact-ID legacy cleanup and operator documentation

**Files:**
- Modify: `src/overseer/package_reconciliation.py`
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/client.py`
- Modify: `docs/local-api.md`
- Modify: `docs/runtime.md`
- Modify: `docs/maintenance-and-patch-operations.md`
- Modify: `tests/test_package_workflow_api.py`
- Modify: `tests/test_ui_full_regression.py`

**Interfaces:**
- Produces: legacy candidate report, separately human-approved exact allowlist, atomic cleanup apply, and updated operator contracts.

- [ ] **Step 1: Write failing cleanup tests**

```python
def test_legacy_candidate_report_does_not_cancel(api_client, legacy_plan):
    result = api_client.get("/maintenance/package-legacy-cleanup-candidates")
    assert result["plan_ids"] == [legacy_plan.id]
    assert load_plan(legacy_plan.id).canceled is False


def test_legacy_cleanup_requires_approved_exact_allowlist(api_client, legacy_plan):
    response = api_client.post_raw("/maintenance/package-legacy-cleanup/apply",
                                   {"approval_id": "approval.missing"})
    assert response.status_code == 400
    assert load_plan(legacy_plan.id).canceled is False


def test_legacy_cleanup_fails_atomically_when_candidate_changed(api_client, cleanup_approval):
    mark_plan_attempted(cleanup_approval.plan_ids[0])
    response = api_client.post_raw("/maintenance/package-legacy-cleanup/apply",
                                   {"approval_id": cleanup_approval.id})
    assert response.status_code == 400
    assert all(not load_plan(plan_id).canceled for plan_id in cleanup_approval.plan_ids)


@pytest.mark.parametrize("status", ["pending", "revoked"])
def test_legacy_cleanup_rejects_nonapproved_record(api_client, cleanup_approval, status):
    set_cleanup_approval_status(cleanup_approval.id, status)
    response = api_client.post_raw("/maintenance/package-legacy-cleanup/apply",
                                   {"approval_id": cleanup_approval.id})
    assert response.status_code == 400


def test_legacy_cleanup_record_is_immutable(api_client, cleanup_approval):
    response = api_client.post_raw("/maintenance/package-legacy-cleanup/requests",
                                   {"id": cleanup_approval.id, "plan_ids": ["different"]})
    assert response.status_code == 400


def test_legacy_cleanup_approval_requires_human_token(agent_api_client, cleanup_approval):
    response = agent_api_client.post_raw(
        "/maintenance/package-legacy-cleanup/approve",
        {"approval_id": cleanup_approval.id}, auth="agent",
    )
    assert response.status_code == 403
```

- [ ] **Step 2: Run tests and verify RED**

Run: `pytest -q tests/test_package_workflow_api.py -k 'legacy_cleanup' -x`

Expected: FAIL because candidate/approval/apply surfaces are absent.

- [ ] **Step 3: Add exact-ID legacy backlog cleanup**

```python
class PackageLegacyCleanupStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REVOKED = "revoked"
    APPLIED = "applied"


@dataclass(frozen=True)
class PackageLegacyCleanupApproval:
    id: str
    plan_ids: tuple[str, ...]
    status: PackageLegacyCleanupStatus
    requested_by: str
    requested_at: str
    approved_by: str | None = None
    approved_at: str | None = None
    revoked_by: str | None = None
    revoked_at: str | None = None
    applied_at: str | None = None
    evidence_ids: tuple[str, ...] = ()
```

Add `package_legacy_cleanup_approvals (id TEXT PRIMARY KEY, payload TEXT NOT
NULL)` and immutable store save/load/list methods. Exact replay is allowed;
same-ID/different-plan-list raises an immutable collision. Request/read/revoke
use normal authenticated routes. Approval requires the independent human token,
derives `approved_by` from server context, and accepts no payload identity.
Apply reloads the approved record by ID from SQLite; it never accepts plan IDs
from the apply request. Pending, revoked, applied, altered, or missing records
fail closed.

```python
def apply_legacy_package_cleanup(store, approval_id, canceled_at):
    approval = store.load_package_legacy_cleanup_approval(approval_id)
    if approval.status != PackageLegacyCleanupStatus.APPROVED:
        raise ValueError("approved exact legacy cleanup record is required")
    with store.agent_transaction():
        plans = tuple(store.load_admin_change_plan(plan_id) for plan_id in approval.plan_ids)
        if any(not legacy_cleanup_candidate(store, plan) for plan in plans):
            raise ValueError("legacy package cleanup candidate changed after approval")
        for plan in plans:
            store.save_admin_change_plan(cancel_admin_change_plan(
                plan, "package-reconciler",
                f"approved_legacy_cleanup:{approval.id}", canceled_at,
            ))
        store.save_package_legacy_cleanup_approval(
            replace(approval, status=PackageLegacyCleanupStatus.APPLIED,
                    applied_at=canceled_at)
        )
    return exact_cleanup_status(approval, plans)
```

Candidate reports include typed owner/kind/target and every execution status. Apply requires a separately human-approved exact plan-ID allowlist, reloads every plan, and fails the entire transaction if any plan is no longer active, unarchived, O'Brien-owned APT work with zero execution rows.

- [ ] **Step 4: Update operator documentation**

Document that `related_resource_id` is opaque, reconciliation is non-executing, activation is separate and default-off, direct execution fails closed, legacy cycle is disabled, and cleanup requires an approved exact-ID allowlist. Remove wording that advertises legacy auto-enable/auto-approve/execute behavior.

- [ ] **Step 5: Run focused cleanup/docs/UI tests**

Run: `pytest -q tests/test_package_workflow_api.py tests/test_ui_full_regression.py -k 'package or legacy_cleanup' -x`

Expected: PASS.

- [ ] **Step 6: Commit Task 8**

```bash
git add src/overseer/package_reconciliation.py src/overseer/store.py src/overseer/cli.py src/overseer/api.py src/overseer/client.py docs/local-api.md docs/runtime.md docs/maintenance-and-patch-operations.md tests/test_package_workflow_api.py tests/test_ui_full_regression.py
git commit -m "Add bounded legacy package cleanup"
```

---

### Task 9: Full verification and independent security review

**Files:**
- Verify all files changed by Tasks 1–8.
- Modify only files required by validated review findings.

**Interfaces:**
- Consumes: complete feature branch.
- Produces: fresh regression/build evidence and a reviewed branch ready for integration; no deployment.

- [ ] **Step 1: Run focused feature suites**

```bash
pytest -q \
  tests/test_package_reconciliation.py \
  tests/test_package_workflow_authority.py \
  tests/test_package_workflow_dispatch.py \
  tests/test_package_execution_guards.py \
  tests/test_package_workflow_api.py
```

Expected: all selected tests PASS with zero failures.

- [ ] **Step 2: Run syntax and full regression verification**

```bash
python3 -m compileall -q src
pytest -q
PYTHONPATH=src python3 scripts/run_full_regression.py
command -v ruff || true
command -v mypy || true
git diff --check 414bd93..HEAD
```

Expected: compile exit 0; at least the 1,090-test baseline plus new tests passes; the repository full-regression script passes; diff check exits 0. Record `ruff`/`mypy` as not configured when `command -v` returns no path rather than claiming those unavailable gates passed.

- [ ] **Step 3: Verify the historical regression boundary without host mutation**

Run the dedicated fake-adapter regression proving `port.loopback.8798` appears in no plan target or command. Do not run live APT, dispatch the live crew queue, enable adapters, restart services, apply cleanup, or activate execution.

- [ ] **Step 4: Request independent spec and security review**

Provide reviewers the design `docs/superpowers/specs/2026-08-09-obrien-package-plan-reconciliation-design.md`, this plan, base SHA `414bd93`, head SHA, and generated review package. Require separate verdicts for spec compliance and code/security quality. Fix every Critical/Important issue through a new RED/GREEN test cycle and repeat review.

- [ ] **Step 5: Commit verified review fixes, if any**

```bash
git add -u
git commit -m "Harden package reconciliation workflow"
```

- [ ] **Step 6: Hand off integration and deployment separately**

Report branch SHA, exact verification results, dirty-main overlap, and any cherry-pick/merge conflicts. Do not merge into dirty `main`, deploy source, restart Overseer, approve activation, cancel live legacy plans, or execute APT without the corresponding explicit next approval.
