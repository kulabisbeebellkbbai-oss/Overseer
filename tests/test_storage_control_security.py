from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from overseer.audit import ApprovalStatus
from overseer.core import OwnerDomain
from overseer.crew import CrewMessage, CrewMessageStatus, CrewReviewStatus
from overseer.storage_adapter import verify_storage_root_authorization_status
from overseer.storage_control import (
    approve_authorization,
    list_authorizations,
    materialize_authorization,
    revoke_authorization,
    stage_authorization,
    stage_authorization_api,
)
from overseer.store import SQLiteStore
from tests.test_storage_adapter import claim, request


def root_payload(now: datetime, **changes) -> dict[str, object]:
    payload: dict[str, object] = {
        "authorization_ref": "root-auth",
        "action": "root.register",
        "project_id": "project-a",
        "root_id": "root-a",
        "policy_revision": "1",
        "root_identity": "sha256:" + "1" * 64,
        "alias": "safe",
        "status": "active",
        "max_bytes": 1024,
        "target_digest": "sha256:" + "2" * 64,
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
    }
    payload.update(changes)
    return payload


def verification_payload(payload: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != "expires_at"}


def approve(path, approval_id: str, now: datetime, *, decided_by: str = "human-operator", subject_id: str | None = None) -> None:
    with SQLiteStore(path) as store:
        approval = store.load_approval(approval_id)
        store.save_approval(replace(
            approval,
            status=ApprovalStatus.APPROVED,
            decided_by=decided_by,
            decided_at=now.isoformat(),
            **({"subject_id": subject_id} if subject_id is not None else {}),
        ))


def approve_supported(path, authorization_ref: str, now: datetime) -> None:
    approve_authorization(str(path), authorization_ref, "human-operator", now.isoformat())


def seed_crew(path, evidence_id: str, owner: str, now: datetime) -> None:
    with SQLiteStore(path) as store:
        store.save_crew_message(CrewMessage(
            evidence_id, OwnerDomain(owner), "storage review", "exact external evidence",
            status=CrewMessageStatus.ACKNOWLEDGED, review_status=CrewReviewStatus.APPROVED,
            decided_by=owner, decided_at=now.isoformat(),
        ))


def test_requesting_crew_owner_cannot_self_approve_materialization(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    now = datetime.now(UTC)
    seed_crew(path, "crew.kira.review", "kira", now)
    staged = stage_authorization(str(path), "root", root_payload(now), "crew.kira.review", "kira", now.isoformat())
    approve(path, staged["approval_id"], now, decided_by="kira")
    with pytest.raises(ValueError, match="approval"):
        materialize_authorization(str(path), "root-auth", now.isoformat())


@pytest.mark.parametrize(("kind", "owner"), [("root", "obrien"), ("operation", "kira")])
def test_external_evidence_owner_is_bound_to_authorization_kind(tmp_path, kind: str, owner: str) -> None:
    now = datetime.now(UTC)
    if kind == "root":
        payload = root_payload(now)
    else:
        execution = request(now)
        payload = {
            "authorization_ref": "operation-auth", "request_id": execution.request_id,
            "request_digest": execution.request_digest, "project_id": execution.project_id,
            "root_id": execution.root_id, "action": execution.action,
            "policy_revision": execution.policy_revision, "claim_id": execution.claim_id,
            "target_digest": "sha256:" + "3" * 64, "limits": {"max_bytes": 8},
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
        }
    with pytest.raises(ValueError, match="owner"):
        stage_authorization(str(tmp_path / "state.sqlite3"), kind, payload, f"crew.{owner}.review", owner, now.isoformat())


def test_materialized_root_remains_bound_to_exact_review_and_is_verifiable(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    now = datetime.now(UTC)
    payload = root_payload(now)
    seed_crew(path, "crew.kira.review", "kira", now)
    staged = stage_authorization(str(path), "root", payload, "crew.kira.review", "kira", now.isoformat())
    approve_supported(path, "root-auth", now)
    materialize_authorization(str(path), "root-auth", now.isoformat())
    verified = verify_storage_root_authorization_status(str(path), verification_payload(payload), verified_at=now.isoformat())
    assert verified["ok"] is True
    assert verified["authorization"]["approval_id"] == staged["approval_id"]


def test_expired_payload_cannot_be_materialized(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    now = datetime.now(UTC)
    seed_crew(path, "crew.kira.review", "kira", now)
    with pytest.raises(ValueError, match="expiry"):
        stage_authorization(
            str(path), "root", root_payload(now, expires_at=(now - timedelta(seconds=1)).isoformat()),
            "crew.kira.review", "kira", now.isoformat(),
        )


def test_operation_materialization_rejects_cross_project_payload(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    now = datetime.now(UTC)
    execution, active_claim = request(now), claim(now)
    seed_crew(path, "crew.obrien.review", "obrien", now)
    payload = {
        "authorization_ref": execution.authorization_ref, "request_id": execution.request_id,
        "request_digest": execution.request_digest, "project_id": "different-project",
        "root_id": execution.root_id, "action": execution.action,
        "policy_revision": execution.policy_revision, "claim_id": execution.claim_id,
        "approval_id": execution.approval_id,
        "target_digest": "sha256:" + "3" * 64, "limits": {"max_bytes": 8},
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
    }
    staged = stage_authorization(str(path), "operation", payload, "crew.obrien.review", "obrien", now.isoformat())
    with SQLiteStore(path) as store:
        store.save_storage_execution_request(execution)
        store.save_claim(active_claim)
    approve_supported(path, execution.authorization_ref, now)
    with pytest.raises(ValueError, match="does not match"):
        materialize_authorization(str(path), execution.authorization_ref, now.isoformat())


def test_revoke_invalidates_verification_and_control_api_is_redacted(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    now = datetime.now(UTC)
    payload = root_payload(now)
    seed_crew(path, "crew.kira.review", "kira", now)
    staged = stage_authorization_api(str(path), {
        "kind": "root", "payload": payload,
        "crew_evidence_id": "crew.kira.review", "crew_owner": "kira",
    })
    approve_supported(path, "root-auth", now)
    materialize_authorization(str(path), "root-auth", now.isoformat())
    seed_crew(path, "crew.obrien.revoke", "obrien", now)
    revoke_authorization(str(path), "root-auth", "human-operator", "crew.obrien.revoke", now.isoformat())
    denied = verify_storage_root_authorization_status(str(path), verification_payload(payload), verified_at=now.isoformat())
    assert denied["ok"] is False and denied["error"]["code"] == "AUTHORIZATION_INVALID"

    response = list_authorizations(str(path))
    rendered = repr(response)
    assert "root_identity" not in rendered
    assert "expires_at" not in rendered
    assert "crew.kira.review" in rendered
    assert response["host_mutation_performed"] is False
