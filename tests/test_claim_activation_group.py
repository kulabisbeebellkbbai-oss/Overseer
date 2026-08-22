import json
import sqlite3
import threading
from pathlib import Path

import pytest

from overseer.claim_continuation import (
    ClaimActivationGroup,
    ClaimActivationGroupState,
    activate_claim_group_status,
    claim_group_status,
    register_claim_activation_group_status,
    release_claim_group_status,
)
from overseer.audit import AuditEventType
from overseer.cli import approve_claim_status, request_claim_status
from overseer.core import Claim, ClaimStatus, ClaimType, OwnerDomain, Resource, ResourceType, RiskLevel
from overseer.store import SQLiteStore
from overseer.serialization import to_jsonable
from overseer.api import _claim_group_register_args, _claim_group_release_args


def _store_with_resource(path: Path) -> None:
    store = SQLiteStore(path)
    store.save_resource(Resource(id="proxy.continuation", name="proxy", type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    store.close()


def _psychlo_round(path: Path, *, lifecycle_id: str = "arcade-lifecycle-v10", project_id: str = "arcade", plan_id: str = "arcade-plan", plan_version: str = "v10", owner_thread: str = "thread.exact-owner") -> Path:
    psychlo = path.with_name("psychlo.sqlite3")
    connection = sqlite3.connect(psychlo)
    connection.executescript("CREATE TABLE projects (id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, plan_version TEXT NOT NULL); CREATE TABLE rounds (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, state TEXT NOT NULL, request_json TEXT NOT NULL);")
    request = {"roundId": lifecycle_id, "projectId": project_id, "planId": plan_id, "planVersion": plan_version, "threadId": owner_thread}
    connection.execute("INSERT INTO projects VALUES (?, ?, ?)", (project_id, plan_id, plan_version))
    connection.execute("INSERT INTO rounds VALUES (?, ?, 'active', ?)", (lifecycle_id, project_id, json.dumps(request)))
    connection.commit()
    connection.close()
    return psychlo


def _store_with_group(path: Path, *, second_resource: str = "proxy.continuation.two") -> dict[str, object]:
    psychlo = _psychlo_round(path)
    store = SQLiteStore(path)
    for resource_id in ("proxy.continuation", second_resource):
        store.save_resource(Resource(id=resource_id, name=resource_id, type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    group = ClaimActivationGroup(
        id="group.arcade.task9", lifecycle_id="arcade-lifecycle-v10", project_id="arcade", plan_id="arcade-plan", plan_version="v10", owner_thread="thread.exact-owner", owner_role=OwnerDomain.DAX,
        claim_ids=("claim.continuation.one", "claim.continuation.two"), approval_ids=("approval.claim.continuation.one", "approval.claim.continuation.two"), resource_ids=("proxy.continuation", second_resource),
    )
    store.save_claim_activation_group(group)
    store.close()
    first = request_claim_status(path, "claim.continuation.one", "proxy.continuation", "lease", "thread.exact-owner", OwnerDomain.DAX.value, "run paired listener", "reserve first listener", RiskLevel.LOW.value, activation_group_id=group.id, lifecycle_id=group.lifecycle_id)
    second = request_claim_status(path, "claim.continuation.two", second_resource, "lease", "thread.exact-owner", OwnerDomain.DAX.value, "run paired listener", "reserve second listener", RiskLevel.LOW.value, activation_group_id=group.id, lifecycle_id=group.lifecycle_id)
    for requested in (first, second):
        approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)
    return {"group": group.id, "first": first, "second": second, "psychlo": psychlo}


def test_group_registration_is_public_and_exactly_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    args = dict(
        group_id="group.registered",
        lifecycle_id="arcade-lifecycle-v10",
        project_id="arcade",
        plan_id="arcade-plan",
        plan_version="v10",
        owner_thread="thread.exact-owner",
        owner_role=OwnerDomain.DAX.value,
        claim_ids=("claim.one", "claim.two"),
        approval_ids=("approval.claim.one", "approval.claim.two"),
        resource_ids=("proxy.one", "proxy.two"),
    )
    psychlo = _psychlo_round(path)
    first = register_claim_activation_group_status(path, **args, _psychlo_store_path=psychlo)
    second = register_claim_activation_group_status(path, **args, _psychlo_store_path=psychlo)
    assert first["group_status"] == ClaimActivationGroupState.REQUESTED.value
    assert second["idempotent"] is True
    with pytest.raises(ValueError, match="conflicts"):
        register_claim_activation_group_status(path, **{**args, "owner_thread": "thread.other"}, _psychlo_store_path=psychlo)


def test_active_round_terminating_before_activation_is_rejected_without_claim_writes(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    psychlo = _psychlo_round(path)
    args = dict(
        group_id="group.toctou", lifecycle_id="arcade-lifecycle-v10", project_id="arcade",
        plan_id="arcade-plan", plan_version="v10", owner_thread="thread.exact-owner",
        owner_role=OwnerDomain.DAX.value, claim_ids=("claim.toctou.one", "claim.toctou.two"),
        approval_ids=("approval.claim.toctou.one", "approval.claim.toctou.two"),
        resource_ids=("proxy.toctou.one", "proxy.toctou.two"),
    )
    register_claim_activation_group_status(path, **args, _psychlo_store_path=psychlo)
    store = SQLiteStore(path)
    for resource_id in args["resource_ids"]:
        store.save_resource(Resource(id=resource_id, name=resource_id, type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    store.close()
    for claim_id, resource_id in zip(args["claim_ids"], args["resource_ids"]):
        requested = request_claim_status(path, claim_id, resource_id, "lease", args["owner_thread"], args["owner_role"], "bounded pair", "reserve", RiskLevel.LOW.value, activation_group_id=args["group_id"], lifecycle_id=args["lifecycle_id"])
        approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)
    connection = sqlite3.connect(psychlo)
    connection.execute("UPDATE rounds SET state = 'blocked'")
    connection.commit()
    connection.close()

    with pytest.raises(ValueError, match="not active"):
        activate_claim_group_status(path, args["group_id"], _psychlo_store_path=psychlo)
    store = SQLiteStore(path)
    assert all(claim.status == ClaimStatus.REQUESTED for claim in store.list_claims())
    store.close()


def test_active_group_status_invalidates_after_round_termination_but_release_still_cleans_up(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    connection = sqlite3.connect(records["psychlo"])
    connection.execute("UPDATE rounds SET state = 'completed'")
    connection.commit()
    connection.close()

    status = claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    assert status["state"] == "invalid"
    assert any("lifecycle validation failed" in item for item in status["diagnostics"])
    released = release_claim_group_status(path, str(records["group"]), ("cleanup.receipt",))
    assert released["state"] == ClaimActivationGroupState.RELEASED.value


def test_activation_holds_psychlo_writer_lock_through_overseer_commit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    entered = threading.Event()
    continue_activation = threading.Event()
    activation_result: list[dict[str, object]] = []
    activation_error: list[Exception] = []
    original_validate = __import__("overseer.claim_continuation", fromlist=["_validate_psychlo_round"])._validate_psychlo_round

    def wrapped_validate(*args, **kwargs):
        result = original_validate(*args, **kwargs)
        if kwargs.get("lifecycle_id") == "arcade-lifecycle-v10" and kwargs.get("_connection") is not None:
            entered.set()
            assert continue_activation.wait(timeout=2)
        return result

    monkeypatch.setattr("overseer.claim_continuation._validate_psychlo_round", wrapped_validate)

    def activate() -> None:
        try:
            activation_result.append(activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"]))
        except Exception as error:  # pragma: no cover - surfaced below
            activation_error.append(error)

    worker = threading.Thread(target=activate)
    worker.start()
    assert entered.wait(timeout=2)
    transition = sqlite3.connect(records["psychlo"], timeout=0.05)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            transition.execute("BEGIN IMMEDIATE")
    finally:
        transition.close()
    continue_activation.set()
    worker.join(timeout=2)
    assert not activation_error
    assert activation_result[0]["state"] == ClaimActivationGroupState.ACTIVE.value


def test_role_request_rejects_unbound_claim_before_persistence(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _store_with_resource(path)
    with pytest.raises(ValueError, match="explicit lifecycle_id"):
        request_claim_status(
            path, "claim.unbound", "proxy.continuation", "lease", "thread.exact-owner",
            OwnerDomain.DAX.value, "bounded test", "reserve", RiskLevel.LOW.value,
        )
    store = SQLiteStore(path)
    assert store.list_claims() == ()
    assert store.list_approvals() == ()
    store.close()


def test_group_activation_requires_explicit_persisted_bindings_and_is_atomic(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    result = activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    assert result["group_status"] == ClaimActivationGroupState.ACTIVE.value
    store = SQLiteStore(path)
    assert all(claim.status == ClaimStatus.ACTIVE for claim in store.list_claims())
    assert all(resource.current_claim_id for resource in store.list_resources())
    group = store.load_claim_activation_group(str(records["group"]))
    assert group.state == ClaimActivationGroupState.ACTIVE
    activated = [event for event in store.list_audit_events(subject_prefix=str(records["group"])) if event.event_type == AuditEventType.EXECUTED]
    assert len(activated) == 1
    store.close()


@pytest.mark.parametrize("tamper", ["owner", "lifecycle", "approval"])
def test_group_activation_rejects_binding_tamper_without_partial_writes(tmp_path: Path, tamper: str) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    store = SQLiteStore(path)
    group = store.load_claim_activation_group(str(records["group"]))
    if tamper == "owner":
        group = ClaimActivationGroup(**{**group.__dict__, "owner_thread": "thread.other"})
    elif tamper == "lifecycle":
        claim = store.load_claim("claim.continuation.two")
        store.save_claim(Claim(**{**claim.__dict__, "lifecycle_id": "lifecycle.other"}))
    else:
        group = ClaimActivationGroup(**{**group.__dict__, "approval_ids": ("approval.other", group.approval_ids[1])})
    if tamper != "lifecycle":
        payload = json.dumps(to_jsonable(group), sort_keys=True, separators=(",", ":"))
        store._connection.execute("UPDATE claim_activation_groups SET payload = ? WHERE id = ?", (payload, group.id))
        store._connection.commit()
    store.close()
    with pytest.raises(ValueError):
        activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    store = SQLiteStore(path)
    assert all(claim.status == ClaimStatus.REQUESTED for claim in store.list_claims())
    assert all(resource.current_claim_id is None for resource in store.list_resources())
    store.close()


def test_group_activation_rejects_internal_and_external_conflicts_without_partial_writes(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path, second_resource="proxy.continuation")
    with pytest.raises(ValueError, match="resource"):
        activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    store = SQLiteStore(path)
    assert all(claim.status == ClaimStatus.REQUESTED for claim in store.list_claims())
    store.close()


def test_group_activation_retry_is_idempotent_only_for_complete_group(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    first = activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    second = activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    assert second["idempotent"] is True
    assert first["audit_event"] == second["audit_event"]
    store = SQLiteStore(path)
    activated = [event for event in store.list_audit_events(subject_prefix=str(records["group"])) if event.event_type == AuditEventType.EXECUTED]
    assert len(activated) == 1
    store.close()


def test_group_release_requires_evidence_and_releases_both_claims_atomically(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    with pytest.raises(ValueError, match="evidence"):
        release_claim_group_status(path, str(records["group"]), ())
    result = release_claim_group_status(path, str(records["group"]), ("result.receipt", "cleanup.listeners"))
    assert result["group_status"] == ClaimActivationGroupState.RELEASED.value
    assert result["release_evidence_complete"] is True
    store = SQLiteStore(path)
    assert all(claim.status == ClaimStatus.RELEASED for claim in store.list_claims())
    assert all(resource.current_claim_id is None for resource in store.list_resources())
    assert claim_group_status(path, str(records["group"]))["state"] == ClaimActivationGroupState.RELEASED.value
    store.close()


def test_group_release_returns_post_release_resources_with_null_claim_ids(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])

    result = release_claim_group_status(path, str(records["group"]), ("cleanup.receipt",))

    assert all(resource["current_claim_id"] is None for resource in result["resources"])


def test_group_validation_rejects_resource_owner_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    store = SQLiteStore(path)
    resource = store.load_resource("proxy.continuation")
    store.save_resource(Resource(**{**resource.__dict__, "owner_domain": OwnerDomain.ODO}))
    store.close()

    with pytest.raises(ValueError, match="resource owner"):
        release_claim_group_status(path, str(records["group"]), ("cleanup.receipt",))


def test_group_release_rejects_tampered_nonexclusive_claim_type(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    store = SQLiteStore(path)
    claim = store.load_claim("claim.continuation.one")
    store.save_claim(Claim(**{**claim.__dict__, "claim_type": ClaimType.OBSERVATION}))
    store.close()

    with pytest.raises(ValueError, match="exclusive claim type"):
        release_claim_group_status(path, str(records["group"]), ("cleanup.receipt",))


@pytest.mark.parametrize("state", ["blocked", "completed"])
def test_group_registration_rejects_terminal_or_blocked_psychlo_round(tmp_path: Path, state: str) -> None:
    path = tmp_path / "overseer.sqlite3"
    psychlo = _psychlo_round(path)
    connection = sqlite3.connect(psychlo)
    connection.execute("UPDATE rounds SET state = ?", (state,))
    connection.commit()
    connection.close()
    args = dict(
        group_id="group.invalid-round", lifecycle_id="arcade-lifecycle-v10", project_id="arcade",
        plan_id="arcade-plan", plan_version="v10", owner_thread="thread.exact-owner",
        owner_role=OwnerDomain.DAX.value, claim_ids=("claim.one", "claim.two"),
        approval_ids=("approval.one", "approval.two"), resource_ids=("proxy.one", "proxy.two"),
    )

    with pytest.raises(ValueError, match="not active"):
        register_claim_activation_group_status(path, **args, _psychlo_store_path=psychlo)
    store = SQLiteStore(path)
    assert store.list_claim_activation_groups() == ()
    store.close()


def test_group_release_rejects_tampered_resource_ownership_without_partial_writes(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]), _psychlo_store_path=records["psychlo"])
    store = SQLiteStore(path)
    resource = store.load_resource("proxy.continuation")
    store.save_resource(Resource(**{**resource.__dict__, "current_claim_id": "claim.external"}))
    before_claims = store.list_claims()
    before_resources = store.list_resources()
    store.close()

    with pytest.raises(ValueError, match="current claim"):
        release_claim_group_status(path, str(records["group"]), ("cleanup.receipt",))
    store = SQLiteStore(path)
    assert store.list_claims() == before_claims
    assert store.list_resources() == before_resources
    store.close()


def test_group_status_reports_pending_approval_without_activation_validation_error(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    psychlo = _psychlo_round(path, lifecycle_id="lifecycle.pending", owner_thread="thread.pending")
    store = SQLiteStore(path)
    for resource_id in ("proxy.pending.one", "proxy.pending.two"):
        store.save_resource(Resource(id=resource_id, name=resource_id, type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    group = ClaimActivationGroup(
        id="group.pending",
        lifecycle_id="lifecycle.pending",
        project_id="arcade",
        plan_id="arcade-plan",
        plan_version="v10",
        owner_thread="thread.pending",
        owner_role=OwnerDomain.DAX,
        claim_ids=("claim.pending.one", "claim.pending.two"),
        approval_ids=("approval.claim.pending.one", "approval.claim.pending.two"),
        resource_ids=("proxy.pending.one", "proxy.pending.two"),
    )
    store.save_claim_activation_group(group)
    store.close()
    for claim_id, resource_id in zip(group.claim_ids, group.resource_ids):
        request_claim_status(
            path, claim_id, resource_id, "lease", group.owner_thread, group.owner_role.value,
            "pending pair", "reserve resource", RiskLevel.LOW.value,
            activation_group_id=group.id, lifecycle_id=group.lifecycle_id,
        )

    status = claim_group_status(path, group.id, _psychlo_store_path=psychlo)

    assert status["state"] == ClaimActivationGroupState.REQUESTED.value
    assert status["ready_for_activation"] is False
    assert any("approval" in item for item in status["diagnostics"])
    assert all(item["status"] == "pending" for item in status["approvals"])


def test_group_api_payload_validation_rejects_string_iterables_and_unknown_fields() -> None:
    payload = {
        "group_id": "group.api",
        "lifecycle_id": "lifecycle.api",
        "project_id": "arcade",
        "plan_id": "arcade-plan",
        "plan_version": "v10",
        "owner_thread": "thread.api",
        "owner_role": "dax",
        "claim_ids": "claim.one",
        "approval_ids": ["approval.one"],
        "resource_ids": ["resource.one"],
    }
    with pytest.raises(ValueError, match="claim_ids must be"):
        _claim_group_register_args(payload)
    with pytest.raises(ValueError, match="unknown claim group fields"):
        _claim_group_register_args({**payload, "claim_ids": ["claim.one"], "extra": True})
    with pytest.raises(ValueError, match="evidence_ids must be"):
        _claim_group_release_args({"group_id": "group.api", "evidence_ids": "receipt.id"})
