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
    BACKUP_ENCRYPTION_PROFILE,
    MCPBoundedStorageAdapterClient,
    verify_storage_authorization_status,
    StorageRootAuthorizationRecord,
    verify_storage_root_authorization_status,
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


def test_root_authorization_is_exact_redacted_and_immutable(tmp_path):
    now=datetime.now(UTC); path=tmp_path/"state.sqlite3"; approval_record=ApprovalRequest("approval-root","root-auth",ApprovalLevel.HUMAN,"operator",OwnerDomain.OBRIEN,"exact root",status=ApprovalStatus.APPROVED)
    record=StorageRootAuthorizationRecord("root-auth","root.register","project","root","1","sha256:"+"1"*64,"safe-alias","active",1024,"sha256:"+"2"*64,approval_record.id,now.isoformat(),(now+timedelta(minutes=5)).isoformat())
    with SQLiteStore(path) as store: store.save_approval(approval_record); store.save_storage_root_authorization(record)
    payload={name:getattr(record,name) for name in ("authorization_ref","action","project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest")}
    result=verify_storage_root_authorization_status(str(path),payload,verified_at=now.isoformat())
    assert result["ok"] and result["authorization"]["alias"]=="safe-alias" and "host_path" not in repr(result)
    payload["max_bytes"]=2048; rejected=verify_storage_root_authorization_status(str(path),payload,verified_at=now.isoformat())
    assert rejected["error"]["code"]=="AUTHORIZATION_MISMATCH"


def backup_request(now: datetime, *, action: str = "backup.create"):
    parameters = (
        {"source_root_id": "project-source", "retention_count": 3, "encryption_profile": BACKUP_ENCRYPTION_PROFILE}
        if action == "backup.create"
        else {"artifact_id": "backup-fixture", "expected_artifact_digest": "sha256:" + "1" * 64, "expected_manifest_digest": "sha256:" + "2" * 64}
    )
    value = StorageExecutionRequest("backup-req", "storage-adapter.theunderdark", 1, "project.donuthole", "storage.donuthole", "backup-root", action, parameters, "1", "claim-1", "approval-1", "auth-1", "backup-idem", "project.donuthole", "approved encrypted backup", ("restore verified",), {"max_bytes": 1024, "max_items": 10}, (now + timedelta(minutes=5)).isoformat())
    return value.with_digest()


@pytest.mark.parametrize("action,tool", [("backup.create", "underdark_backup_create"), ("backup.verify_restore", "underdark_backup_verify_restore")])
def test_backup_actions_are_registered_and_map_to_exact_mcp_tools(action, tool):
    now = datetime.now(UTC); calls = []
    client = MCPBoundedStorageAdapterClient(lambda name, payload: calls.append((name, payload)) or {"ok": True, "contract_version": "1.0", "request_id": "backup-req", "operation_id": "op-backup", "result": {"state": "accepted"}}, 1)
    item = backup_request(now, action=action)
    receipt = client.submit(item)
    assert receipt.operation_id == "op-backup" and calls[0][0] == tool
    assert set(client.capabilities()["actions"]) >= {"backup.create", "backup.verify_restore"}


def test_read_operations_use_the_bounded_mcp_client_boundary():
    calls = []
    envelope = {"ok": True, "contract_version": "1.0", "request_id": "read", "result": {"value": "safe"}}
    client = MCPBoundedStorageAdapterClient(lambda name, payload: calls.append((name, payload)) or envelope, 1)

    assert client.project_get("project.donuthole") == envelope
    assert client.root_get("project.donuthole", "backup-root") == envelope
    assert client.directory_list("project.donuthole", "backup-root", "", "1", limit=2) == envelope
    assert [name for name, _ in calls] == [
        "underdark_project_get",
        "underdark_root_get",
        "underdark_directory_list",
    ]


def test_backup_action_rejects_extra_parameters_and_nonpositive_limits():
    now = datetime.now(UTC)
    dispatcher = StorageDispatcher((StorageAdapterRegistration("storage-adapter.theunderdark", "loopback-service.theunderdark", "sha256:cap", frozenset({"backup.create"}), 1, status=StorageAdapterStatus.ENABLED, approved_revision=1, readiness_checks=REQUIRED_READINESS),), lambda _: Client())
    item = backup_request(now)
    bad_parameters = item.__class__(**{**item.__dict__, "parameters": {**item.parameters, "command": "tar /"}}).with_digest()
    with pytest.raises(StorageAdapterError) as extra:
        dispatcher.dispatch(bad_parameters, claim(now), approval(), now)
    assert extra.value.code == "INVALID_ARGUMENT"
    bad_limits = item.__class__(**{**item.__dict__, "limits": {"max_bytes": 0, "max_items": 10}}).with_digest()
    with pytest.raises(StorageAdapterError) as limits:
        dispatcher.dispatch(bad_limits, claim(now), approval(), now)
    assert limits.value.code == "INVALID_ARGUMENT"


@pytest.mark.parametrize("field,value", [
    ("source_root_id", "source root"),
    ("source_root_id", "source\nroot"),
    ("source_root_id", "s" * 129),
])
def test_backup_create_rejects_nonopaque_source_root_ids(field, value):
    now = datetime.now(UTC); item = backup_request(now)
    changed = item.__class__(**{**item.__dict__, "parameters": {**item.parameters, field: value}}).with_digest()
    client = MCPBoundedStorageAdapterClient(lambda *_: pytest.fail("invalid request reached MCP"), 1)
    with pytest.raises(StorageAdapterError) as failure:
        client.submit(changed)
    assert failure.value.code == "INVALID_ARGUMENT"


@pytest.mark.parametrize("artifact_id", ["backup bad", "backup-evil\nvalue", "backup-" + "x" * 122])
def test_backup_verify_rejects_nonopaque_artifact_ids(artifact_id):
    now = datetime.now(UTC); item = backup_request(now, action="backup.verify_restore")
    changed = item.__class__(**{**item.__dict__, "parameters": {**item.parameters, "artifact_id": artifact_id}}).with_digest()
    client = MCPBoundedStorageAdapterClient(lambda *_: pytest.fail("invalid request reached MCP"), 1)
    with pytest.raises(StorageAdapterError) as failure:
        client.submit(changed)
    assert failure.value.code == "INVALID_ARGUMENT"


def test_authoritative_verification_binds_backup_limits():
    now = datetime.now(UTC); item = backup_request(now)
    active_claim = Claim("claim-1", "storage.donuthole", ClaimType.LEASE, "project.donuthole", OwnerDomain.OBRIEN, "bounded storage", "backup.create", RiskLevel.HIGH, status=ClaimStatus.ACTIVE, expires_at=(now + timedelta(minutes=10)).isoformat())
    approved = ApprovalRequest("approval-1", "backup-req", ApprovalLevel.HUMAN, "project.donuthole", OwnerDomain.OBRIEN, "exact backup", status=ApprovalStatus.APPROVED)
    authorization = StorageAuthorizationRecord("auth-1", item.request_id, item.request_digest, item.project_id, item.root_id, item.action, item.policy_revision, active_claim.id, approved.id, canonical_adapter_request_digest(item), {"max_bytes": 2048, "max_items": 10}, now.isoformat(), (now + timedelta(minutes=5)).isoformat())
    with pytest.raises(StorageAdapterError) as failure:
        from overseer.storage_adapter import verify_storage_authorization
        verify_storage_authorization(authorization, item, active_claim, approved, request_digest=canonical_adapter_request_digest(item), project_id=item.project_id, root_id=item.root_id, action=item.action, policy_revision=item.policy_revision, now=now)
    assert failure.value.code == "AUTHORIZATION_MISMATCH"
