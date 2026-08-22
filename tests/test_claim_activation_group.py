import json
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
from overseer.core import Claim, ClaimStatus, OwnerDomain, Resource, ResourceType, RiskLevel
from overseer.store import SQLiteStore
from overseer.serialization import to_jsonable
from overseer.api import _claim_group_register_args, _claim_group_release_args


def _store_with_resource(path: Path) -> None:
    store = SQLiteStore(path)
    store.save_resource(Resource(id="proxy.continuation", name="proxy", type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    store.close()


def _store_with_group(path: Path, *, second_resource: str = "proxy.continuation.two") -> dict[str, object]:
    store = SQLiteStore(path)
    for resource_id in ("proxy.continuation", second_resource):
        store.save_resource(Resource(id=resource_id, name=resource_id, type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    group = ClaimActivationGroup(
        id="group.arcade.task9", lifecycle_id="arcade-lifecycle-v10", owner_thread="thread.exact-owner", owner_role=OwnerDomain.DAX,
        claim_ids=("claim.continuation.one", "claim.continuation.two"), approval_ids=("approval.claim.continuation.one", "approval.claim.continuation.two"), resource_ids=("proxy.continuation", second_resource),
    )
    store.save_claim_activation_group(group)
    store.close()
    first = request_claim_status(path, "claim.continuation.one", "proxy.continuation", "lease", "thread.exact-owner", OwnerDomain.DAX.value, "run paired listener", "reserve first listener", RiskLevel.LOW.value, activation_group_id=group.id, lifecycle_id=group.lifecycle_id)
    second = request_claim_status(path, "claim.continuation.two", second_resource, "lease", "thread.exact-owner", OwnerDomain.DAX.value, "run paired listener", "reserve second listener", RiskLevel.LOW.value, activation_group_id=group.id, lifecycle_id=group.lifecycle_id)
    for requested in (first, second):
        approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)
    return {"group": group.id, "first": first, "second": second}


def test_group_registration_is_public_and_exactly_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    args = dict(
        group_id="group.registered",
        lifecycle_id="arcade-lifecycle-v10",
        owner_thread="thread.exact-owner",
        owner_role=OwnerDomain.DAX.value,
        claim_ids=("claim.one", "claim.two"),
        approval_ids=("approval.claim.one", "approval.claim.two"),
        resource_ids=("proxy.one", "proxy.two"),
    )
    first = register_claim_activation_group_status(path, **args)
    second = register_claim_activation_group_status(path, **args)
    assert first["group_status"] == ClaimActivationGroupState.REQUESTED.value
    assert second["idempotent"] is True
    with pytest.raises(ValueError, match="conflicts"):
        register_claim_activation_group_status(path, **{**args, "owner_thread": "thread.other"})


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
    result = activate_claim_group_status(path, str(records["group"]))
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
        activate_claim_group_status(path, str(records["group"]))
    store = SQLiteStore(path)
    assert all(claim.status == ClaimStatus.REQUESTED for claim in store.list_claims())
    assert all(resource.current_claim_id is None for resource in store.list_resources())
    store.close()


def test_group_activation_rejects_internal_and_external_conflicts_without_partial_writes(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path, second_resource="proxy.continuation")
    with pytest.raises(ValueError, match="resource"):
        activate_claim_group_status(path, str(records["group"]))
    store = SQLiteStore(path)
    assert all(claim.status == ClaimStatus.REQUESTED for claim in store.list_claims())
    store.close()


def test_group_activation_retry_is_idempotent_only_for_complete_group(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    first = activate_claim_group_status(path, str(records["group"]))
    second = activate_claim_group_status(path, str(records["group"]))
    assert second["idempotent"] is True
    assert first["audit_event"] == second["audit_event"]
    store = SQLiteStore(path)
    activated = [event for event in store.list_audit_events(subject_prefix=str(records["group"])) if event.event_type == AuditEventType.EXECUTED]
    assert len(activated) == 1
    store.close()


def test_group_release_requires_evidence_and_releases_both_claims_atomically(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]))
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


def test_group_release_rejects_tampered_resource_ownership_without_partial_writes(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    records = _store_with_group(path)
    activate_claim_group_status(path, str(records["group"]))
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
    store = SQLiteStore(path)
    for resource_id in ("proxy.pending.one", "proxy.pending.two"):
        store.save_resource(Resource(id=resource_id, name=resource_id, type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    group = ClaimActivationGroup(
        id="group.pending",
        lifecycle_id="lifecycle.pending",
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

    status = claim_group_status(path, group.id)

    assert status["state"] == ClaimActivationGroupState.REQUESTED.value
    assert status["ready_for_activation"] is False
    assert any("approval" in item for item in status["diagnostics"])
    assert all(item["status"] == "pending" for item in status["approvals"])


def test_group_api_payload_validation_rejects_string_iterables_and_unknown_fields() -> None:
    payload = {
        "group_id": "group.api",
        "lifecycle_id": "lifecycle.api",
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
