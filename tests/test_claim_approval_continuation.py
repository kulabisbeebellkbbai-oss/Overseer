import json
from pathlib import Path

import pytest

from overseer.claim_continuation import (
    ContinuationState,
    dispatch_claim_approval_continuation_status,
)
from overseer.audit import ApprovalStatus
from overseer.cli import approve_claim_status, request_claim_status
from overseer.core import OwnerDomain, Resource, ResourceType, RiskLevel
from overseer.store import SQLiteStore


def _store_with_resource(path: Path) -> None:
    store = SQLiteStore(path)
    store.save_resource(
        Resource(
            id="proxy.continuation",
            name="Continuation proxy",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.LOW,
        )
    )
    store.close()


def _request(path: Path) -> dict[str, object]:
    return request_claim_status(
        path,
        "claim.continuation.one",
        "proxy.continuation",
        "lease",
        "thread.exact-owner",
        OwnerDomain.DAX.value,
        "run one bounded continuation",
        "send the approved continuation prompt",
        RiskLevel.LOW.value,
        activation_group_id="group.continuation",
        lifecycle_id="lifecycle.continuation",
    )


def test_role_approval_atomically_persists_one_continuation_without_activation(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _store_with_resource(path)
    requested = _request(path)

    approved = approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)

    store = SQLiteStore(path)
    continuations = store.list_claim_approval_continuations()
    claim = store.load_claim(str(requested["claim"]))
    resource = store.load_resource("proxy.continuation")
    store.close()
    assert approved["approval_status"] == "approved"
    assert len(continuations) == 1
    continuation = continuations[0]
    assert continuation.id == f"continuation.{requested['approval_id']}"
    assert continuation.claim_id == requested["claim"]
    assert continuation.approval_id == requested["approval_id"]
    assert continuation.resource_id == "proxy.continuation"
    assert continuation.owner_thread == "thread.exact-owner"
    assert continuation.owner_role == OwnerDomain.DAX
    assert continuation.state == ContinuationState.PENDING
    assert claim.status.value == "requested"
    assert resource.current_claim_id is None


def test_approval_retry_does_not_duplicate_continuation(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _store_with_resource(path)
    requested = _request(path)
    approval_id = str(requested["approval_id"])

    approve_claim_status(path, approval_id, OwnerDomain.DAX.value)
    approve_claim_status(path, approval_id, OwnerDomain.DAX.value)

    store = SQLiteStore(path)
    assert [item.id for item in store.list_claim_approval_continuations()] == [f"continuation.{approval_id}"]
    assert store.load_claim(str(requested["claim"])).status.value == "requested"
    store.close()


def test_role_approval_rolls_back_when_continuation_persistence_fails(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "overseer.sqlite3"
    _store_with_resource(path)
    requested = _request(path)

    def fail(_store, _continuation):
        raise RuntimeError("outbox unavailable")

    monkeypatch.setattr(SQLiteStore, "save_claim_approval_continuation", fail)
    with pytest.raises(RuntimeError, match="outbox unavailable"):
        approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)

    store = SQLiteStore(path)
    assert store.load_approval(str(requested["approval_id"])).status == ApprovalStatus.PENDING
    assert store.list_claim_approval_continuations() == ()
    assert not any(event.id.endswith(".approved") for event in store.list_audit_events())
    store.close()


class _Adapter:
    def __init__(self, result=None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[tuple[str, str]] = []

    def dispatch_prompt(self, owner_thread: str, prompt: str):
        self.calls.append((owner_thread, prompt))
        if self.error is not None:
            raise self.error
        return self.result

    def dispatch_prompt_exact(self, owner_thread: str, prompt: str):
        return self.dispatch_prompt(owner_thread, prompt)


def test_dispatch_requires_exact_continuation_id_and_owner_thread(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _store_with_resource(path)
    requested = _request(path)
    approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)
    adapter = _Adapter(
        type("Result", (), {"status": "prompt_dispatched", "owner_thread": "thread.exact-owner", "conversation_id": "thread.exact-owner", "reason": "delivered"})()
    )

    result = dispatch_claim_approval_continuation_status(
        path,
        f"continuation.{requested['approval_id']}",
        adapter=adapter,
        dispatched_at="2026-08-21T20:00:00+00:00",
    )

    assert result["status"] == ContinuationState.DELIVERED.value
    assert adapter.calls and adapter.calls[0][0] == "thread.exact-owner"
    store = SQLiteStore(path)
    continuation = store.load_claim_approval_continuation(f"continuation.{requested['approval_id']}")
    assert continuation.state == ContinuationState.DELIVERED
    assert continuation.attempt_id
    assert store.load_claim(str(requested["claim"])).status.value == "requested"
    store.close()


def test_dispatch_response_loss_persists_attempt_and_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _store_with_resource(path)
    requested = _request(path)
    approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)
    adapter = _Adapter(error=TimeoutError("response lost after send"))

    result = dispatch_claim_approval_continuation_status(
        path,
        f"continuation.{requested['approval_id']}",
        adapter=adapter,
        dispatched_at="2026-08-21T20:01:00+00:00",
    )

    assert result["status"] == ContinuationState.RECONCILIATION_REQUIRED.value
    store = SQLiteStore(path)
    continuation = store.load_claim_approval_continuation(f"continuation.{requested['approval_id']}")
    attempt = store.load_claim_approval_continuation_attempt(str(continuation.attempt_id))
    assert continuation.state == ContinuationState.RECONCILIATION_REQUIRED
    assert attempt.status == ContinuationState.RECONCILIATION_REQUIRED
    assert store.load_claim(str(requested["claim"])).status.value == "requested"
    store.close()


def test_tampered_continuation_is_rejected_before_send(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _store_with_resource(path)
    requested = _request(path)
    approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)
    continuation_id = f"continuation.{requested['approval_id']}"
    store = SQLiteStore(path)
    continuation = store.load_claim_approval_continuation(continuation_id)
    payload = json.loads(store._connection.execute(
        "SELECT payload FROM claim_approval_continuations WHERE id = ?",
        (continuation_id,),
    ).fetchone()["payload"])
    payload["owner_thread"] = "thread.other"
    store._connection.execute(
        "UPDATE claim_approval_continuations SET payload = ? WHERE id = ?",
        (json.dumps(payload, sort_keys=True, separators=(",", ":")), continuation_id),
    )
    store._connection.commit()
    store.close()
    adapter = _Adapter()

    with pytest.raises(ValueError, match="owner thread"):
        dispatch_claim_approval_continuation_status(path, continuation_id, adapter=adapter)
    assert adapter.calls == []
