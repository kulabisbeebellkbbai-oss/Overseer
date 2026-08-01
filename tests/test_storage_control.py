from datetime import UTC,datetime,timedelta
from dataclasses import replace
import json
from overseer.audit import ApprovalStatus
from overseer.storage_control import stage_authorization,list_authorizations,materialize_authorization,revoke_authorization
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
