from datetime import UTC,datetime,timedelta
from dataclasses import replace
import json
import sqlite3
from overseer.audit import ApprovalStatus
from overseer.storage_control import resolve_current_root_authorization, stage_authorization,list_authorizations,materialize_authorization,revoke_authorization
from overseer.storage_control import approve_authorization
from overseer.store import SQLiteStore
from tests.test_storage_adapter import request, claim
from overseer.storage_adapter import canonical_adapter_request_digest
from overseer.crew import CrewMessage,CrewMessageStatus,CrewReviewStatus
from overseer.core import OwnerDomain,RiskLevel
from tests.test_agent_api import LocalAPI
from unittest.mock import patch
from urllib.request import Request,urlopen
from urllib.error import HTTPError
import json

def root_payload(now): return {"authorization_ref":"root-auth","action":"root.register","project_id":"project","root_id":"root","policy_revision":"1","root_identity":"sha256:"+"1"*64,"alias":"safe","status":"active","max_bytes":1024,"target_digest":"sha256:"+"2"*64,"expires_at":(now+timedelta(minutes=5)).isoformat()}
def crew(path,id,owner,now):
    with SQLiteStore(path) as store: store.save_crew_message(CrewMessage(id,OwnerDomain(owner),"review","approved external review",RiskLevel.HIGH,CrewMessageStatus.ACKNOWLEDGED,review_status=CrewReviewStatus.APPROVED,decided_by=owner,decided_at=now.isoformat()))

def test_root_stage_approve_materialize_list_revoke(tmp_path):
    path=tmp_path/"state.sqlite3"; now=datetime.now(UTC); payload=root_payload(now); crew(path,"crew.kira.root-review","kira",now)
    staged=stage_authorization(str(path),"root",payload,"crew.kira.root-review","kira",now.isoformat()); assert staged["status"]=="pending"
    approve_authorization(str(path),"root-auth","human",now.isoformat())
    assert materialize_authorization(str(path),"root-auth",now.isoformat())["status"]=="approved"
    assert list_authorizations(str(path))["items"][0]["materialized"] is True
    crew(path,"crew.obrien.revoke","obrien",now); revoke_authorization(str(path),"root-auth","operator","crew.obrien.revoke",now.isoformat())
    with SQLiteStore(path) as store: assert store.load_storage_root_authorization("root-auth").revoked_at==now.isoformat()

def test_current_root_authorization_resolves_newest_exact_approved_record(tmp_path):
    path=tmp_path/"state.sqlite3"; now=datetime.now(UTC); identity="sha256:"+"1"*64; target="sha256:"+"2"*64
    crew(path,"crew.kira.current-root","kira",now)
    for index,ref in enumerate(("root-auth-old","root-auth-current")):
        approved_at=now+timedelta(seconds=index)
        payload={**root_payload(now),"authorization_ref":ref,"root_identity":identity,"target_digest":target,"expires_at":(now+timedelta(minutes=10)).isoformat()}
        stage_authorization(str(path),"root",payload,"crew.kira.current-root","kira",now.isoformat())
        approve_authorization(str(path),ref,"human",approved_at.isoformat())
        materialize_authorization(str(path),ref,approved_at.isoformat())
    result=resolve_current_root_authorization(str(path),"project","root","1",identity,"safe","active",1024,target,(now+timedelta(seconds=2)).isoformat())
    assert result["authorization_ref"]=="root-auth-current"
    assert result["host_mutation_performed"] is False

def test_current_root_authorization_rejects_identity_without_exact_approval(tmp_path):
    path=tmp_path/"state.sqlite3"; now=datetime.now(UTC); payload=root_payload(now); crew(path,"crew.kira.current-root","kira",now)
    stage_authorization(str(path),"root",payload,"crew.kira.current-root","kira",now.isoformat())
    approve_authorization(str(path),"root-auth","human",now.isoformat()); materialize_authorization(str(path),"root-auth",now.isoformat())
    try: resolve_current_root_authorization(str(path),"project","root","1","sha256:"+"9"*64,"safe","active",1024,payload["target_digest"],now.isoformat())
    except ValueError as error: assert "no current exact" in str(error)
    else: raise AssertionError("mismatched root identity resolved")

def test_current_root_authorization_api_returns_authoritative_reference(tmp_path):
    path=tmp_path/"state.sqlite3"; now=datetime.now(UTC); payload=root_payload(now); crew(path,"crew.kira.current-root","kira",now)
    stage_authorization(str(path),"root",payload,"crew.kira.current-root","kira",now.isoformat())
    approve_authorization(str(path),"root-auth","human",now.isoformat()); materialize_authorization(str(path),"root-auth",now.isoformat())
    request_payload={name:payload[name] for name in ("project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest")}
    with LocalAPI(path,auth_token="admin-token") as api:
        response=api.post_json("/storage/control/root-authorizations/current",request_payload,authenticated=True)
    assert response.status_code==200
    assert response.json()["authorization_ref"]=="root-auth"
    assert response.json()["mutation_performed"] is False

def test_stage_is_immutable_and_materialize_requires_approval(tmp_path):
    path=tmp_path/"state.sqlite3"; now=datetime.now(UTC); payload=root_payload(now); crew(path,"crew.kira.review","kira",now); stage_authorization(str(path),"root",payload,"crew.kira.review","kira",now.isoformat())
    try: materialize_authorization(str(path),"root-auth")
    except ValueError as error: assert "approval" in str(error)
    else: raise AssertionError("pending approval materialized")
    changed=dict(payload,max_bytes=2048)
    try: stage_authorization(str(path),"root",changed,"crew.kira.review","kira",now.isoformat())
    except ValueError as error: assert "immutable" in str(error)
    else: raise AssertionError("immutable stage changed")

def test_operation_materialization_requires_stored_request_claim_and_exact_digest(tmp_path):
    path=tmp_path/"state.sqlite3"; now=datetime.now(UTC); execution=request(now); active=claim(now); crew(path,"crew.obrien.operation-review","obrien",now)
    payload={"authorization_ref":execution.authorization_ref,"request_id":execution.request_id,"request_digest":execution.request_digest,"project_id":execution.project_id,"root_id":execution.root_id,"action":execution.action,"policy_revision":execution.policy_revision,"claim_id":execution.claim_id,"approval_id":execution.approval_id,"target_digest":canonical_adapter_request_digest(execution),"limits":{"max_bytes":8},"expires_at":execution.expires_at}
    staged=stage_authorization(str(path),"operation",payload,"crew.obrien.operation-review","obrien",now.isoformat())
    with SQLiteStore(path) as store:
        store.save_storage_execution_request(execution); store.save_claim(active)
    approve_authorization(str(path),execution.authorization_ref,"human",now.isoformat())
    result=materialize_authorization(str(path),execution.authorization_ref,now.isoformat()); assert result["kind"]=="operation"
    with SQLiteStore(path) as store: assert store.load_storage_authorization(execution.authorization_ref).claim_id==active.id

def test_control_post_requires_admin_token_before_handler(tmp_path):
    path=tmp_path/"state.sqlite3"
    with patch("overseer.api.validate_remote_testing_token",return_value={"authorized":True,"auth_type":"remote_testing_token","reason":"allowed"}), LocalAPI(path,auth_token="admin-token") as api:
        request_body=json.dumps({}).encode(); remote=Request(api.base_url+"/storage/control/stage",data=request_body,headers={"content-type":"application/json","authorization":"Bearer remote-token"},method="POST")
        try: urlopen(remote)
        except HTTPError as error: assert error.code==403 and json.loads(error.read())["reason"]=="admin_token_required"
        else: raise AssertionError("remote testing token reached storage control handler")
        admin=api.post_json("/storage/control/stage",{},authenticated=True)
        assert admin.status_code==400 and "exact stage fields" in repr(admin.json())

def test_legacy_store_runs_storage_authorization_schema_migration(tmp_path):
    path=tmp_path/"legacy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
        CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,description TEXT NOT NULL,applied_at TEXT NOT NULL);
        CREATE TABLE agent_schema_migrations(version TEXT PRIMARY KEY,description TEXT NOT NULL,applied_at TEXT NOT NULL);
        INSERT INTO schema_migrations VALUES(1,'bootstrap JSON payload store','2026-01-01T00:00:00+00:00');
        INSERT INTO agent_schema_migrations VALUES('agent_driver_v9','agent driver','2026-01-01T00:00:00+00:00');
        """)
    with SQLiteStore(path) as store:
        tables={row[0] for row in store._connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"storage_authorizations","storage_root_authorizations"} <= tables
