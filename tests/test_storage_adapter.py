from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

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
    StorageAuthorizationRecord,
    canonical_adapter_request_digest,
    verify_storage_authorization_status,
)
from overseer.store import SQLiteStore
from overseer.api import make_api_handler


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


def test_authoritative_verification_returns_exact_redacted_snapshot(tmp_path):
    now=datetime.now(UTC); store_path=tmp_path/"state.sqlite3"; execution=request(now)
    active_claim=claim(now); approved=approval()
    tool_digest=canonical_adapter_request_digest(execution)
    authorization=StorageAuthorizationRecord("auth-1",execution.request_id,execution.request_digest,execution.project_id,execution.root_id,execution.action,execution.policy_revision,active_claim.id,approved.id,tool_digest,{"max_bytes":8},now.isoformat(),(now+timedelta(minutes=5)).isoformat())
    with SQLiteStore(store_path) as store:
        store.save_storage_execution_request(execution); store.save_claim(active_claim); store.save_approval(approved); store.save_storage_authorization(authorization)
    payload={"authorization_ref":"auth-1","request_digest":tool_digest,"project_id":execution.project_id,"root_id":execution.root_id,"action":execution.action,"policy_revision":execution.policy_revision}
    result=verify_storage_authorization_status(str(store_path),payload,verified_at=now.isoformat())
    assert result["ok"] is True and result["authorization"]["target_digest"]==tool_digest
    rendered=repr(result); assert "resource_id" not in rendered and "requested_by" not in rendered and "parameters" not in rendered


def test_authoritative_verification_fails_closed_on_digest_mismatch(tmp_path):
    now=datetime.now(UTC); store_path=tmp_path/"state.sqlite3"; execution=request(now); active_claim=claim(now); approved=approval()
    authorization=StorageAuthorizationRecord("auth-1",execution.request_id,execution.request_digest,execution.project_id,execution.root_id,execution.action,execution.policy_revision,active_claim.id,approved.id,canonical_adapter_request_digest(execution),{"max_bytes":8},now.isoformat(),(now+timedelta(minutes=5)).isoformat())
    with SQLiteStore(store_path) as store:
        store.save_storage_execution_request(execution); store.save_claim(active_claim); store.save_approval(approved); store.save_storage_authorization(authorization)
    result=verify_storage_authorization_status(str(store_path),{"authorization_ref":"auth-1","request_digest":"sha256:wrong","project_id":execution.project_id,"root_id":execution.root_id,"action":execution.action,"policy_revision":execution.policy_revision},verified_at=now.isoformat())
    assert result=={"ok":False,"error":{"code":"AUTHORIZATION_MISMATCH","message":"authoritative storage verification failed"},"redactions_applied":True}


def test_storage_verification_route_requires_api_authentication(tmp_path):
    server=ThreadingHTTPServer(("127.0.0.1",0),make_api_handler(str(tmp_path/"state.sqlite3"),"test-token")); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try:
        url=f"http://127.0.0.1:{server.server_address[1]}/storage/authorizations/verify"
        body=json.dumps({}).encode()
        with pytest.raises(HTTPError) as unauthorized: urlopen(Request(url,data=body,headers={"content-type":"application/json"},method="POST"))
        assert unauthorized.value.code==401
        response=urlopen(Request(url,data=body,headers={"content-type":"application/json","authorization":"Bearer test-token"},method="POST"))
        assert response.status==200 and json.load(response)["error"]["code"]=="INVALID_ARGUMENT"
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
