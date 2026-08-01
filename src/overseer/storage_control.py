"""Supported, approval-gated storage authorization lifecycle."""
from __future__ import annotations
import hashlib,json,re
from dataclasses import dataclass,replace
from datetime import UTC,datetime
from typing import Mapping
from .audit import ApprovalRequest,ApprovalStatus
from .core import ApprovalLevel,OwnerDomain,ClaimStatus,ClaimType
from .crew import CrewMessageStatus,CrewReviewStatus
from .storage_adapter import ALLOWED_ACTIONS,StorageAdapterError,StorageAuthorizationRecord,StorageExecutionRequest,StorageRootAuthorizationRecord,canonical_adapter_request_digest,validate_storage_execution_request
from .store import SQLiteStore

@dataclass(frozen=True)
class StorageAuthorizationStage:
    stage_id:str; kind:str; authorization_ref:str; approval_id:str; payload:Mapping[str,object]; payload_digest:str; crew_evidence_id:str; crew_owner:str; created_at:str

def initialize_storage_control(store:SQLiteStore)->None:
    store._connection.executescript("""CREATE TABLE IF NOT EXISTS storage_authorization_stages(id TEXT PRIMARY KEY,kind TEXT NOT NULL,authorization_ref TEXT NOT NULL UNIQUE,payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS storage_authorization_revocations(id TEXT PRIMARY KEY,kind TEXT NOT NULL,authorization_ref TEXT NOT NULL UNIQUE,revoked_by TEXT NOT NULL,revoked_at TEXT NOT NULL,evidence_id TEXT NOT NULL);"""); store._commit()

def stage_authorization(store_path:str,kind:str,payload:Mapping[str,object],crew_evidence_id:str,crew_owner:str,created_at:str|None=None)->Mapping[str,object]:
    expected_owner={"root":"kira","operation":"obrien"}.get(kind)
    if expected_owner is None or crew_owner!=expected_owner or not crew_evidence_id.startswith("crew."): raise ValueError("external crew evidence owner does not match authorization kind")
    required_root={"authorization_ref","action","project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest","expires_at"}
    required_op={"authorization_ref","request_id","request_digest","project_id","root_id","action","policy_revision","claim_id","approval_id","target_digest","limits","expires_at"}
    required=required_root if kind=="root" else required_op
    if set(payload)!=required: raise ValueError("authorization payload fields are not exact")
    _validate_payload(kind,payload,created_at)
    canonical=json.dumps(payload,sort_keys=True,separators=(",",":")); digest="sha256:"+hashlib.sha256(canonical.encode()).hexdigest(); ref=str(payload["authorization_ref"]); now=created_at or datetime.now(UTC).isoformat(); approval_id=str(payload["approval_id"]) if kind=="operation" else f"approval.storage.{kind}.{ref}"
    stage=StorageAuthorizationStage(f"stage.storage.{kind}.{ref}",kind,ref,approval_id,dict(payload),digest,crew_evidence_id,crew_owner,now)
    approval_subject=ref if kind=="root" else str(payload["request_id"])
    approval=ApprovalRequest(approval_id,approval_subject,ApprovalLevel.HUMAN,crew_owner,OwnerDomain.OBRIEN,f"Approve exact {kind} storage authorization digest {digest}",evidence_required=(crew_evidence_id,digest))
    with SQLiteStore(store_path) as store:
        initialize_storage_control(store); _require_crew(store,crew_evidence_id,crew_owner); existing=store._connection.execute("SELECT payload FROM storage_authorization_stages WHERE authorization_ref=?",(ref,)).fetchone(); dumped=json.dumps(stage.__dict__,sort_keys=True,separators=(",",":"))
        if existing and str(existing["payload"])!=dumped: raise ValueError("authorization reference is immutable")
        store._connection.execute("INSERT OR IGNORE INTO storage_authorization_stages VALUES(?,?,?,?)",(stage.stage_id,kind,ref,dumped)); store.save_approval(approval)
    return {"ok":True,"stage_id":stage.stage_id,"authorization_ref":ref,"approval_id":approval_id,"payload_digest":digest,"status":"pending","crew_evidence_id":crew_evidence_id,"mutation_performed":True,"host_mutation_performed":False}

def list_authorizations(store_path:str,kind:str|None=None)->Mapping[str,object]:
    if kind not in {None,"root","operation"}: raise ValueError("kind is invalid")
    with SQLiteStore(store_path) as store:
        initialize_storage_control(store); rows=store._connection.execute("SELECT payload FROM storage_authorization_stages"+(" WHERE kind=?" if kind else "")+" ORDER BY id",((kind,) if kind else ())).fetchall(); items=[]
        for row in rows:
            stage=json.loads(row["payload"]); approval=store.load_approval(stage["approval_id"]); revoked=store._connection.execute("SELECT revoked_at,evidence_id FROM storage_authorization_revocations WHERE authorization_ref=?",(stage["authorization_ref"],)).fetchone()
            items.append({"stage_id":stage["stage_id"],"kind":stage["kind"],"authorization_ref":stage["authorization_ref"],"payload_digest":stage["payload_digest"],"approval_id":stage["approval_id"],"approval_status":approval.status.value,"crew_evidence_id":stage["crew_evidence_id"],"materialized":_materialized(store,stage),"revoked":bool(revoked)})
    return {"ok":True,"items":items,"mutation_performed":False,"host_mutation_performed":False}

def materialize_authorization(store_path:str,authorization_ref:str,materialized_at:str|None=None)->Mapping[str,object]:
    now=materialized_at or datetime.now(UTC).isoformat()
    with SQLiteStore(store_path) as store:
        initialize_storage_control(store); row=store._connection.execute("SELECT payload FROM storage_authorization_stages WHERE authorization_ref=?",(authorization_ref,)).fetchone()
        if not row: raise ValueError("authorization stage does not exist")
        stage=json.loads(row["payload"]); approval=store.load_approval(stage["approval_id"])
        _require_crew(store,stage["crew_evidence_id"],stage["crew_owner"])
        expected_subject=stage["authorization_ref"] if stage["kind"]=="root" else stage["payload"]["request_id"]
        if approval.status!=ApprovalStatus.APPROVED or not approval.decided_by or approval.decided_by==stage["crew_owner"] or not approval.decided_at or approval.subject_id!=expected_subject or stage["crew_evidence_id"] not in approval.evidence_required or stage["payload_digest"] not in approval.evidence_required or approval.owner_domain!=OwnerDomain.OBRIEN: raise ValueError("exact human approval and crew evidence are required")
        if _time(stage["payload"]["expires_at"])<=_time(now): raise ValueError("authorization is expired")
        p=stage["payload"]
        if stage["kind"]=="root":
            record=StorageRootAuthorizationRecord(p["authorization_ref"],p["action"],p["project_id"],p["root_id"],p["policy_revision"],p["root_identity"],p["alias"],p["status"],p["max_bytes"],p["target_digest"],approval.id,approval.decided_at or now,p["expires_at"]); store.save_storage_root_authorization(record)
        else:
            request=store.load_storage_execution_request(p["request_id"]); claim=store.load_claim(p["claim_id"])
            exact=(request.request_id,request.request_digest,request.project_id,request.root_id,request.action,request.policy_revision,request.claim_id,request.approval_id,request.authorization_ref,request.expires_at,canonical_adapter_request_digest(request),dict(request.limits))
            staged=(p["request_id"],p["request_digest"],p["project_id"],p["root_id"],p["action"],p["policy_revision"],p["claim_id"],p["approval_id"],p["authorization_ref"],p["expires_at"],p["target_digest"],dict(p["limits"]))
            if exact!=staged or approval.id!=request.approval_id or claim.id!=request.claim_id or claim.resource_id!=request.resource_id or claim.owner_thread!=request.requested_by or claim.status not in {ClaimStatus.APPROVED,ClaimStatus.ACTIVE} or claim.claim_type not in {ClaimType.LEASE,ClaimType.LOCK,ClaimType.CHECKOUT,ClaimType.HOLD} or not claim.expires_at or _time(claim.expires_at)<=_time(p["expires_at"]): raise ValueError("operation project, request, claim, approval, authorization, digest, or expiry does not match")
            record=StorageAuthorizationRecord(p["authorization_ref"],p["request_id"],p["request_digest"],p["project_id"],p["root_id"],p["action"],p["policy_revision"],p["claim_id"],approval.id,p["target_digest"],p["limits"],approval.decided_at or now,p["expires_at"]); store.save_storage_authorization(record)
    return {"ok":True,"authorization_ref":authorization_ref,"kind":stage["kind"],"status":"approved","mutation_performed":True,"host_mutation_performed":False}

def revoke_authorization(store_path:str,authorization_ref:str,revoked_by:str,evidence_id:str,revoked_at:str|None=None)->Mapping[str,object]:
    if not revoked_by or not evidence_id: raise ValueError("revoker and evidence are required")
    now=revoked_at or datetime.now(UTC).isoformat()
    with SQLiteStore(store_path) as store:
        initialize_storage_control(store); row=store._connection.execute("SELECT kind FROM storage_authorization_stages WHERE authorization_ref=?",(authorization_ref,)).fetchone(); crew=store.load_crew_message(evidence_id); _require_crew(store,evidence_id,crew.owner_domain.value)
        if not row or not _materialized(store,{"kind":row["kind"],"authorization_ref":authorization_ref}): raise ValueError("materialized authorization does not exist")
        store._connection.execute("INSERT INTO storage_authorization_revocations VALUES(?,?,?,?,?,?)",(f"revoke.{authorization_ref}",row["kind"],authorization_ref,revoked_by,now,evidence_id)); store._commit()
    return {"ok":True,"authorization_ref":authorization_ref,"status":"revoked","evidence_id":evidence_id,"mutation_performed":True,"host_mutation_performed":False}

def approve_authorization(store_path:str,authorization_ref:str,approved_by:str,approved_at:str|None=None)->Mapping[str,object]:
    if not approved_by.strip(): raise ValueError("approved_by is required")
    now=approved_at or datetime.now(UTC).isoformat(); _time(now)
    with SQLiteStore(store_path) as store:
        initialize_storage_control(store); row=store._connection.execute("SELECT payload FROM storage_authorization_stages WHERE authorization_ref=?",(authorization_ref,)).fetchone()
        if not row: raise ValueError("authorization stage does not exist")
        stage=json.loads(row["payload"]); _require_crew(store,stage["crew_evidence_id"],stage["crew_owner"]); approval=store.load_approval(stage["approval_id"])
        expected_subject=stage["authorization_ref"] if stage["kind"]=="root" else stage["payload"]["request_id"]
        if approved_by==stage["crew_owner"] or approval.status!=ApprovalStatus.PENDING or approval.subject_id!=expected_subject or tuple(approval.evidence_required)!=(stage["crew_evidence_id"],stage["payload_digest"]): raise ValueError("exact independent pending storage approval is required")
        store.save_approval(replace(approval,status=ApprovalStatus.APPROVED,decided_by=approved_by,decided_at=now))
    return {"ok":True,"authorization_ref":authorization_ref,"approval_id":stage["approval_id"],"status":"approved","approved_by":approved_by,"mutation_performed":True,"host_mutation_performed":False}

def create_execution_request(store_path:str,payload:Mapping[str,object],created_at:str|None=None)->Mapping[str,object]:
    """Validate and durably store one exact approval-bound execution request."""
    required={"request_id","adapter_id","adapter_revision","project_id","resource_id","root_id","action","parameters","policy_revision","claim_id","approval_id","authorization_ref","idempotency_key","requested_by","reason","acceptance_criteria","limits","expires_at"}
    if set(payload)!=required: raise ValueError("execution request fields are not exact")
    identifiers=("request_id","adapter_id","project_id","resource_id","root_id","action","policy_revision","claim_id","approval_id","authorization_ref","idempotency_key","requested_by")
    if any(not isinstance(payload[name],str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",payload[name]) for name in identifiers): raise ValueError("execution request identifiers are invalid")
    if payload["action"] not in ALLOWED_ACTIONS or not isinstance(payload["adapter_revision"],int) or isinstance(payload["adapter_revision"],bool) or payload["adapter_revision"]<1: raise ValueError("execution request adapter or action is invalid")
    if payload["project_id"]!=payload["requested_by"] or not isinstance(payload["reason"],str) or not 1<=len(payload["reason"])<=512: raise ValueError("execution request owner or reason is invalid")
    if not isinstance(payload["parameters"],Mapping) or not isinstance(payload["limits"],Mapping) or not payload["limits"] or any(not isinstance(v,int) or isinstance(v,bool) or v<1 for v in payload["limits"].values()): raise ValueError("execution request parameters or limits are invalid")
    criteria=payload["acceptance_criteria"]
    if not isinstance(criteria,(list,tuple)) or not criteria or any(not isinstance(item,str) or not item.strip() or len(item)>256 for item in criteria): raise ValueError("execution request acceptance criteria are invalid")
    now=_time(created_at or datetime.now(UTC).isoformat()); expires=_time(payload["expires_at"])
    if expires<=now: raise ValueError("execution request is expired")
    request=StorageExecutionRequest(
        str(payload["request_id"]),str(payload["adapter_id"]),int(payload["adapter_revision"]),str(payload["project_id"]),str(payload["resource_id"]),str(payload["root_id"]),str(payload["action"]),dict(payload["parameters"]),str(payload["policy_revision"]),str(payload["claim_id"]),str(payload["approval_id"]),str(payload["authorization_ref"]),str(payload["idempotency_key"]),str(payload["requested_by"]),str(payload["reason"]),tuple(criteria),dict(payload["limits"]),str(payload["expires_at"]),created_at=now.isoformat(),
    ).with_digest()
    expected_parameters={
        "directory.create":{"relative_path","parents"},
        "file.write":{"relative_path","content","content_digest","write_mode","content_encoding","expected_prior_digest"},
        "path.copy":{"source_root_id","source_relative_path","relative_path","destination_mode"},
        "path.move":{"source_relative_path","relative_path","expected_source_digest","expected_source_type","destination_mode"},
        "path.delete":{"relative_path","expected_type","expected_digest","recursive"},
    }.get(request.action)
    if expected_parameters is not None and set(request.parameters)!=expected_parameters: raise ValueError("execution request action fields are invalid")
    for name,value in request.parameters.items():
        if name.endswith("path") and (not isinstance(value,str) or not value or value.startswith("/") or "\\" in value or any(part in {"",".",".."} for part in value.split("/"))): raise ValueError("execution request path is invalid")
    try: validate_storage_execution_request(request)
    except StorageAdapterError as error: raise ValueError("execution request action fields are invalid") from error
    with SQLiteStore(store_path) as store:
        claim=store.load_claim(request.claim_id); registration=store.load_storage_adapter_registration(request.adapter_id)
        if claim.resource_id!=request.resource_id or claim.owner_thread!=request.requested_by or claim.requested_action!=request.action or claim.status not in {ClaimStatus.APPROVED,ClaimStatus.ACTIVE} or claim.claim_type not in {ClaimType.LEASE,ClaimType.LOCK,ClaimType.CHECKOUT,ClaimType.HOLD} or not claim.expires_at or _time(claim.expires_at)<=expires: raise ValueError("execution request claim does not match or cover expiry")
        if registration.registration_revision!=request.adapter_revision or not registration.accepts(request.resource_id,request.action,now): raise ValueError("execution request adapter is not enabled for the exact action")
        store.save_storage_execution_request(request)
    return {"ok":True,"request_id":request.request_id,"request_digest":request.request_digest,"project_id":request.project_id,"root_id":request.root_id,"action":request.action,"claim_id":request.claim_id,"approval_id":request.approval_id,"authorization_ref":request.authorization_ref,"status":"stored","mutation_performed":True,"host_mutation_performed":False,"redactions_applied":True}

def _materialized(store,stage):
    table="storage_root_authorizations" if stage["kind"]=="root" else "storage_authorizations"
    return store._connection.execute(f"SELECT 1 FROM {table} WHERE id=?",(stage["authorization_ref"],)).fetchone() is not None

def stage_authorization_api(store_path:str,p:Mapping[str,object]):
    if set(p)!={"kind","payload","crew_evidence_id","crew_owner"} or not isinstance(p.get("payload"),Mapping): raise ValueError("exact stage fields are required")
    return stage_authorization(store_path,str(p["kind"]),p["payload"],str(p["crew_evidence_id"]),str(p["crew_owner"]))
def materialize_authorization_api(store_path:str,p:Mapping[str,object]):
    if set(p)!={"authorization_ref"}: raise ValueError("exact materialize fields are required")
    return materialize_authorization(store_path,str(p["authorization_ref"]))
def revoke_authorization_api(store_path:str,p:Mapping[str,object]):
    if set(p)!={"authorization_ref","revoked_by","evidence_id"}: raise ValueError("exact revoke fields are required")
    return revoke_authorization(store_path,str(p["authorization_ref"]),str(p["revoked_by"]),str(p["evidence_id"]))
def approve_authorization_api(store_path:str,p:Mapping[str,object]):
    if set(p)!={"authorization_ref","approved_by"}: raise ValueError("exact approve fields are required")
    return approve_authorization(store_path,str(p["authorization_ref"]),str(p["approved_by"]))
def create_execution_request_api(store_path:str,p:Mapping[str,object]):
    if set(p)!={"payload"} or not isinstance(p.get("payload"),Mapping): raise ValueError("exact execution request envelope is required")
    return create_execution_request(store_path,p["payload"])

def _require_crew(store,evidence_id,owner):
    message=store.load_crew_message(evidence_id)
    if message.owner_domain.value!=owner or message.status!=CrewMessageStatus.ACKNOWLEDGED or message.review_status!=CrewReviewStatus.APPROVED or message.decided_by!=owner or not message.decided_at: raise ValueError("terminal acknowledged and approved crew evidence is required")
    return message
def _validate_payload(kind,payload,now):
    for name in ("authorization_ref","project_id","root_id","policy_revision","action"):
        if not isinstance(payload.get(name),str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",payload[name]): raise ValueError(f"{name} is invalid")
    if not _digest(payload.get("target_digest")) or not isinstance(payload.get("expires_at"),str) or _time(payload["expires_at"])<=_time(now or datetime.now(UTC).isoformat()): raise ValueError("digest or expiry is invalid")
    if kind=="root":
        if payload["action"] not in {"root.register","root.transition"} or payload["status"] not in {"active","suspended","retired"} or not _digest(payload["root_identity"]) or not isinstance(payload["alias"],str) or not payload["alias"] or not isinstance(payload["max_bytes"],int) or isinstance(payload["max_bytes"],bool) or payload["max_bytes"]<1: raise ValueError("root authorization fields are invalid")
    else:
        if not _digest(payload["request_digest"]) or not isinstance(payload["limits"],Mapping) or any(not isinstance(v,int) or isinstance(v,bool) or v<0 for v in payload["limits"].values()): raise ValueError("operation authorization fields are invalid")
def _digest(value): return isinstance(value,str) and value.startswith("sha256:") and len(value)==71 and all(c in "0123456789abcdef" for c in value[7:])
def _time(value):
    parsed=datetime.fromisoformat(str(value).replace("Z","+00:00"))
    if parsed.tzinfo is None: raise ValueError("timezone is required")
    return parsed.astimezone(UTC)
