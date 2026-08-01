from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from overseer.audit import ApprovalRequest, ApprovalStatus
from overseer.core import ApprovalLevel, Claim, ClaimStatus, ClaimType, OwnerDomain, RiskLevel
from overseer.storage_adapter import (
    REQUIRED_READINESS,
    StorageAdapterError,
    StorageAdapterRegistration,
    StorageAdapterStatus,
    StorageDispatcher,
    StorageExecutionReceipt,
    StorageExecutionRequest,
)
from overseer.store import SQLiteStore


def registration(*, ready=True, status=StorageAdapterStatus.ENABLED):
    return StorageAdapterRegistration("storage-adapter.theunderdark", "loopback-service.theunderdark", "sha256:cap", frozenset({"file.write"}), 1, status=status, approved_revision=1, readiness_checks=REQUIRED_READINESS if ready else frozenset())


def request(now: datetime):
    value = StorageExecutionRequest("req-1", "storage-adapter.theunderdark", 1, "project.donuthole", "storage.donuthole", "root", "file.write", {"relative_path": "ok.txt"}, "1", "claim-1", "approval-1", "auth-1", "idem-1", "project.donuthole", "bounded fixture", ("digest verified",), {"max_bytes": 8}, (now + timedelta(minutes=5)).isoformat())
    return value.with_digest()


def claim(now: datetime):
    return Claim("claim-1", "storage.donuthole", ClaimType.LEASE, "project.donuthole", OwnerDomain.OBRIEN, "bounded storage", "file.write", RiskLevel.HIGH, status=ClaimStatus.ACTIVE, expires_at=(now + timedelta(minutes=10)).isoformat())


def approval():
    return ApprovalRequest("approval-1", "req-1", ApprovalLevel.HUMAN, "project.donuthole", OwnerDomain.OBRIEN, "exact storage operation", status=ApprovalStatus.APPROVED)


class Client:
    def __init__(self): self.calls = 0
    def submit(self, item):
        self.calls += 1
        return StorageExecutionReceipt(item.request_id, "op-1", "accepted", item.request_digest, 1)


def test_dispatch_requires_durable_runtime_readiness():
    now = datetime.now(UTC)
    dispatcher = StorageDispatcher((registration(ready=False),), lambda _: Client())
    with pytest.raises(StorageAdapterError, match="enabled") as failure:
        dispatcher.dispatch(request(now), claim(now), approval(), now)
    assert failure.value.code == "ADAPTER_DISABLED"


def test_dispatch_binds_claim_approval_and_idempotency():
    now = datetime.now(UTC); client = Client()
    dispatcher = StorageDispatcher((registration(),), lambda _: client)
    first = dispatcher.dispatch(request(now), claim(now), approval(), now)
    second = dispatcher.dispatch(request(now), claim(now), approval(), now)
    assert first == second and first.status == "in_progress" and client.calls == 1


def test_dispatch_rejects_changed_request_digest():
    now = datetime.now(UTC); dispatcher = StorageDispatcher((registration(),), lambda _: Client())
    altered = request(now)
    altered = altered.__class__(**{**altered.__dict__, "reason": "changed"})
    with pytest.raises(StorageAdapterError) as failure:
        dispatcher.dispatch(altered, claim(now), approval(), now)
    assert failure.value.code == "REQUEST_REJECTED"


def test_storage_records_round_trip_without_activation(tmp_path):
    now = datetime.now(UTC); path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        disabled = registration(ready=False, status=StorageAdapterStatus.REGISTERED)
        store.save_storage_adapter_registration(disabled)
        store.save_storage_execution_request(request(now))
        assert store.load_storage_adapter_registration(disabled.adapter_id) == disabled
        assert store.load_storage_execution_request("req-1") == request(now)
