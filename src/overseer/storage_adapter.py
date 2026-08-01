"""Typed, fail-closed boundary for bounded storage adapters.

This module is deliberately activation-neutral: it defines records, validation,
and an injectable client/dispatcher but never discovers or contacts an endpoint.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Callable, Mapping, Protocol

from .audit import ApprovalRequest, ApprovalStatus
from .core import Claim, ClaimStatus, ClaimType

CONTRACT_VERSION = "1.0"
ADAPTER_KIND = "bounded_storage_v1"
ALLOWED_ACTIONS = frozenset({"directory.create", "file.write", "path.copy", "path.move", "path.delete"})
REQUIRED_READINESS = frozenset({"durable_operation_journal", "descriptor_relative_containment", "strict_tool_schemas", "transport_verified"})


class StorageAdapterStatus(StrEnum):
    REGISTERED = "registered"
    APPROVAL_PENDING = "approval_pending"
    APPROVED = "approved"
    ENABLED = "enabled"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"
    RETIRED = "retired"


class StorageResultStatus(StrEnum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class StorageAdapterRegistration:
    adapter_id: str
    endpoint_ref: str
    capability_digest: str
    allowed_actions: frozenset[str]
    registration_revision: int
    status: StorageAdapterStatus = StorageAdapterStatus.REGISTERED
    kind: str = ADAPTER_KIND
    contract_version: str = CONTRACT_VERSION
    display_name: str = "TheUnderdark"
    transport: str = "streamable_http"
    tool_prefix: str = "underdark_"
    owner_domain: str = "obrien"
    operator_owner: str = "local-operator"
    allowed_resource_prefixes: tuple[str, ...] = ("storage.",)
    approval_id: str | None = None
    approved_revision: int | None = None
    enabled_at: str | None = None
    expires_at: str | None = None
    revoked_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    readiness_checks: frozenset[str] = frozenset()

    def accepts(self, resource_id: str, action: str, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return (
            self.status == StorageAdapterStatus.ENABLED
            and self.approved_revision == self.registration_revision
            and self.contract_version == CONTRACT_VERSION
            and self.kind == ADAPTER_KIND
            and REQUIRED_READINESS <= self.readiness_checks
            and action in self.allowed_actions <= ALLOWED_ACTIONS
            and any(resource_id.startswith(prefix) for prefix in self.allowed_resource_prefixes)
            and not self.revoked_at
            and (not self.expires_at or _timestamp(self.expires_at) > current)
        )


@dataclass(frozen=True)
class StorageExecutionRequest:
    request_id: str
    adapter_id: str
    adapter_revision: int
    project_id: str
    resource_id: str
    root_id: str
    action: str
    parameters: Mapping[str, object]
    policy_revision: str
    claim_id: str
    approval_id: str
    authorization_ref: str
    idempotency_key: str
    requested_by: str
    reason: str
    acceptance_criteria: tuple[str, ...]
    limits: Mapping[str, object]
    expires_at: str
    contract_version: str = CONTRACT_VERSION
    request_digest: str = ""
    created_at: str | None = None

    def canonical_digest(self) -> str:
        data = {name: value for name, value in self.__dict__.items() if name != "request_digest"}
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), default=list).encode()
        return f"sha256:{hashlib.sha256(encoded).hexdigest()}"

    def with_digest(self) -> StorageExecutionRequest:
        return replace(self, request_digest=self.canonical_digest())


@dataclass(frozen=True)
class StorageExecutionReceipt:
    request_id: str
    operation_id: str
    state: str
    request_digest: str
    adapter_revision: int


@dataclass(frozen=True)
class StorageExecutionResult:
    request_id: str
    operation_id: str
    adapter_id: str
    adapter_revision: int
    request_digest: str
    status: StorageResultStatus
    action: str
    summary: str
    evidence_ids: tuple[str, ...]
    verification_outcome: str
    host_state_changed: bool | str
    error_code: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


@dataclass(frozen=True)
class StorageDispatchRecord:
    id: str
    adapter_id: str
    project_id: str
    idempotency_key: str
    request_digest: str
    request_id: str
    status: str
    operation_id: str | None = None
    result: StorageExecutionResult | None = None


@dataclass(frozen=True)
class StorageAuthorizationRecord:
    authorization_ref: str
    request_id: str
    request_digest: str
    project_id: str
    root_id: str
    action: str
    policy_revision: str
    claim_id: str
    approval_id: str
    target_digest: str
    limits: Mapping[str, int]
    approved_at: str
    expires_at: str
    status: str = "approved"
    revoked_at: str | None = None


@dataclass(frozen=True)
class StorageRootAuthorizationRecord:
    authorization_ref: str
    action: str
    project_id: str
    root_id: str
    policy_revision: str
    root_identity: str
    alias: str
    status: str
    max_bytes: int
    target_digest: str
    approval_id: str
    approved_at: str
    expires_at: str
    authorization_status: str = "approved"
    revoked_at: str | None = None


def verify_storage_root_authorization_status(store_path: str, payload: Mapping[str, object], *, verified_at: str | None = None) -> Mapping[str, object]:
    from .store import SQLiteStore
    required={"authorization_ref","action","project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest"}
    if set(payload)!=required or any(name!="max_bytes" and (not isinstance(payload[name],str) or not payload[name]) for name in required) or not isinstance(payload["max_bytes"],int) or isinstance(payload["max_bytes"],bool) or int(payload["max_bytes"])<1 or payload["action"] not in {"root.register","root.transition"} or payload["status"] not in {"active","suspended","retired"} or not _sha256_digest(str(payload["root_identity"])) or not _sha256_digest(str(payload["target_digest"])):
        return {"ok":False,"error":{"code":"INVALID_ARGUMENT","message":"exact root verification fields are required"},"redactions_applied":True}
    try:
        with SQLiteStore(store_path) as store:
            record=store.load_storage_root_authorization(str(payload["authorization_ref"])); approval=store.load_approval(record.approval_id)
        exact=(record.action,record.project_id,record.root_id,record.policy_revision,record.root_identity,record.alias,record.status,record.max_bytes,record.target_digest)
        supplied=tuple(payload[name] for name in ("action","project_id","root_id","policy_revision","root_identity","alias","status","max_bytes","target_digest"))
        now=_timestamp(verified_at) if verified_at else datetime.now(UTC)
        if exact!=supplied: raise StorageAdapterError("AUTHORIZATION_MISMATCH","root authorization does not match")
        if record.authorization_status!="approved" or record.revoked_at or _timestamp(record.approved_at)>now or _timestamp(record.expires_at)<=now: raise StorageAdapterError("AUTHORIZATION_INVALID","root authorization is inactive")
        if approval.id!=record.approval_id or approval.subject_id!=record.authorization_ref or approval.status!=ApprovalStatus.APPROVED: raise StorageAdapterError("AUTHORIZATION_INVALID","root approval does not match")
        return {"ok":True,"contract_version":CONTRACT_VERSION,"authorization":{"approval_id":record.approval_id,"action":record.action,"project_id":record.project_id,"root_id":record.root_id,"policy_revision":record.policy_revision,"root_identity":record.root_identity,"alias":record.alias,"status":record.status,"max_bytes":record.max_bytes,"target_digest":record.target_digest,"approved_at":record.approved_at,"expires_at":record.expires_at,"redactions_applied":True}}
    except KeyError:
        return {"ok":False,"error":{"code":"AUTHORIZATION_REQUIRED","message":"authoritative root records are unavailable"},"redactions_applied":True}
    except (StorageAdapterError,ValueError) as error:
        return {"ok":False,"error":{"code":error.code if isinstance(error,StorageAdapterError) else "AUTHORIZATION_INVALID","message":"authoritative root verification failed"},"redactions_applied":True}


def _sha256_digest(value: str) -> bool:
    return value.startswith("sha256:") and len(value) == 71 and all(character in "0123456789abcdef" for character in value[7:])


def canonical_adapter_request_digest(request: StorageExecutionRequest) -> str:
    """Digest the exact mutation payload TheUnderdark receives over MCP."""
    payload = {
        "project_id": request.project_id,
        "root_id": request.root_id,
        "request_id": request.request_id,
        "idempotency_key": request.idempotency_key,
        "authorization_ref": request.authorization_ref,
        "policy_revision": request.policy_revision,
        "reason": request.reason,
        **dict(request.parameters),
    }
    encoded = json.dumps(
        {"action": request.action, "request": payload},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def verify_storage_authorization(
    authorization: StorageAuthorizationRecord,
    request: StorageExecutionRequest,
    claim: Claim,
    approval: ApprovalRequest,
    *,
    request_digest: str,
    project_id: str,
    root_id: str,
    action: str,
    policy_revision: str,
    now: datetime | None = None,
) -> Mapping[str, object]:
    """Return a minimal TheUnderdark snapshot after exact authoritative checks."""
    current = now or datetime.now(UTC)
    exact = (authorization.request_id, authorization.target_digest, authorization.project_id, authorization.root_id, authorization.action, authorization.policy_revision)
    supplied = (request.request_id, request_digest, project_id, root_id, action, policy_revision)
    if exact != supplied or request.request_digest != authorization.request_digest or request.canonical_digest() != authorization.request_digest or canonical_adapter_request_digest(request) != request_digest:
        raise StorageAdapterError("AUTHORIZATION_MISMATCH", "storage authorization does not match the canonical request")
    if authorization.status != "approved" or authorization.revoked_at or _timestamp(authorization.expires_at) <= current:
        raise StorageAdapterError("AUTHORIZATION_INVALID", "storage authorization is inactive or expired")
    if request.project_id != project_id or request.root_id != root_id or request.action != action or request.policy_revision != policy_revision:
        raise StorageAdapterError("AUTHORIZATION_MISMATCH", "storage request fields do not match")
    if claim.id != authorization.claim_id or claim.id != request.claim_id or claim.resource_id != request.resource_id or claim.owner_thread != request.requested_by or claim.status not in {ClaimStatus.APPROVED, ClaimStatus.ACTIVE} or claim.claim_type not in {ClaimType.LEASE, ClaimType.LOCK, ClaimType.CHECKOUT, ClaimType.HOLD}:
        raise StorageAdapterError("CLAIM_INVALID", "storage claim does not match or is inactive")
    if not claim.expires_at or _timestamp(claim.expires_at) <= _timestamp(authorization.expires_at):
        raise StorageAdapterError("CLAIM_INVALID", "storage claim does not cover authorization expiry")
    if approval.id != authorization.approval_id or approval.id != request.approval_id or approval.subject_id != request.request_id or approval.status != ApprovalStatus.APPROVED:
        raise StorageAdapterError("AUTHORIZATION_INVALID", "storage approval does not match or is inactive")
    return {
        "authorization_ref": authorization.authorization_ref,
        "request_id": authorization.request_id,
        "project_id": authorization.project_id,
        "root_id": authorization.root_id,
        "action": authorization.action,
        "target_digest": authorization.target_digest,
        "policy_revision": authorization.policy_revision,
        "claim_id": authorization.claim_id,
        "approval_id": authorization.approval_id,
        "approved_at": authorization.approved_at,
        "expires_at": authorization.expires_at,
        "limits": dict(authorization.limits),
        "redactions_applied": True,
    }


def verify_storage_authorization_status(store_path: str, payload: Mapping[str, object], *, verified_at: str | None = None) -> Mapping[str, object]:
    """Authenticated API/callable boundary; returns no raw approval or claim payload."""
    from .store import SQLiteStore
    required = {"authorization_ref", "request_digest", "project_id", "root_id", "action", "policy_revision"}
    if set(payload) != required or not all(isinstance(payload[name], str) and payload[name] for name in required):
        return {"ok": False, "error": {"code": "INVALID_ARGUMENT", "message": "exact storage verification fields are required"}, "redactions_applied": True}
    try:
        with SQLiteStore(store_path) as store:
            authorization = store.load_storage_authorization(str(payload["authorization_ref"]))
            request = store.load_storage_execution_request(authorization.request_id)
            claim = store.load_claim(authorization.claim_id)
            approval = store.load_approval(authorization.approval_id)
        snapshot = verify_storage_authorization(
            authorization, request, claim, approval,
            request_digest=str(payload["request_digest"]), project_id=str(payload["project_id"]),
            root_id=str(payload["root_id"]), action=str(payload["action"]),
            policy_revision=str(payload["policy_revision"]),
            now=_timestamp(verified_at) if verified_at else None,
        )
        return {"ok": True, "contract_version": CONTRACT_VERSION, "authorization": snapshot}
    except KeyError:
        return {"ok": False, "error": {"code": "AUTHORIZATION_REQUIRED", "message": "authoritative storage records are unavailable"}, "redactions_applied": True}
    except (StorageAdapterError, ValueError) as error:
        code = error.code if isinstance(error, StorageAdapterError) else "AUTHORIZATION_INVALID"
        return {"ok": False, "error": {"code": code, "message": "authoritative storage verification failed"}, "redactions_applied": True}


class StorageAdapterError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class BoundedStorageAdapterClient(Protocol):
    def capabilities(self) -> Mapping[str, object]: ...
    def health(self) -> Mapping[str, object]: ...
    def submit(self, request: StorageExecutionRequest) -> StorageExecutionReceipt: ...
    def get_operation(self, project_id: str, operation_id: str) -> StorageExecutionResult: ...


class MCPBoundedStorageAdapterClient:
    """Strict client over an injected MCP call function; no endpoint lookup here."""
    TOOL_BY_ACTION = {
        "directory.create": "underdark_directory_create",
        "file.write": "underdark_file_write",
        "path.copy": "underdark_path_copy",
        "path.move": "underdark_path_move",
        "path.delete": "underdark_path_delete",
    }

    def __init__(self, call_tool: Callable[[str, Mapping[str, object]], Mapping[str, object]], adapter_revision: int):
        self._call_tool = call_tool
        self._revision = adapter_revision

    def capabilities(self) -> Mapping[str, object]:
        return {"contract_version": CONTRACT_VERSION, "actions": sorted(self.TOOL_BY_ACTION)}

    def health(self) -> Mapping[str, object]:
        return self._call_tool("underdark_health_get", {})

    def submit(self, request: StorageExecutionRequest) -> StorageExecutionReceipt:
        tool = self.TOOL_BY_ACTION.get(request.action)
        if not tool:
            raise StorageAdapterError("REQUEST_REJECTED", "unsupported storage action")
        payload = {**request.parameters, "project_id": request.project_id, "root_id": request.root_id, "request_id": request.request_id, "idempotency_key": request.idempotency_key, "authorization_ref": request.authorization_ref, "policy_revision": request.policy_revision, "reason": request.reason}
        response = self._call_tool(tool, payload)
        _validate_envelope(response, request)
        if response.get("ok") is not True:
            error = response.get("error") if isinstance(response.get("error"), Mapping) else {}
            raise StorageAdapterError(str(error.get("code") or "REQUEST_REJECTED"), "storage adapter rejected request")
        operation_id = response.get("operation_id")
        result = response.get("result") if isinstance(response.get("result"), Mapping) else {}
        state = str(result.get("state") or "accepted")
        if not isinstance(operation_id, str) or state not in {"accepted", "authorized", "executing", "succeeded", "failed", "indeterminate", "cancelled"}:
            raise StorageAdapterError("RESULT_INVALID", "adapter receipt is malformed")
        return StorageExecutionReceipt(request.request_id, operation_id, state, request.request_digest, self._revision)

    def get_operation(self, project_id: str, operation_id: str) -> StorageExecutionResult:
        response = self._call_tool("underdark_operation_get", {"project_id": project_id, "operation_id": operation_id})
        if response.get("ok") is not True or not isinstance(response.get("result"), Mapping):
            raise StorageAdapterError("RESULT_INVALID", "adapter operation result is malformed")
        result = response["result"]
        state = str(result.get("state"))
        status = {"accepted": StorageResultStatus.IN_PROGRESS, "authorized": StorageResultStatus.IN_PROGRESS, "executing": StorageResultStatus.IN_PROGRESS, "succeeded": StorageResultStatus.COMPLETED, "failed": StorageResultStatus.FAILED, "indeterminate": StorageResultStatus.INDETERMINATE, "cancelled": StorageResultStatus.CANCELLED}.get(state)
        evidence = response.get("evidence") if isinstance(response.get("evidence"), Mapping) else {}
        ids = evidence.get("evidence_ids")
        if status is None or not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
            raise StorageAdapterError("RESULT_INVALID", "adapter operation state or evidence is malformed")
        return StorageExecutionResult(str(response.get("request_id")), operation_id, "storage-adapter.theunderdark", self._revision, "", status, str(result.get("action") or ""), "bounded storage operation result", tuple(ids), "verified" if status == StorageResultStatus.COMPLETED else state, evidence.get("host_state_changed", "unknown"))


class StorageDispatcher:
    def __init__(self, registrations: tuple[StorageAdapterRegistration, ...], client_factory: Callable[[StorageAdapterRegistration], BoundedStorageAdapterClient]):
        self.registrations = registrations
        self.client_factory = client_factory
        self.records: dict[tuple[str, str, str], StorageDispatchRecord] = {}

    def dispatch(self, request: StorageExecutionRequest, claim: Claim, approval: ApprovalRequest, now: datetime | None = None) -> StorageDispatchRecord:
        current = now or datetime.now(UTC)
        if request.request_digest != request.canonical_digest():
            raise StorageAdapterError("REQUEST_REJECTED", "request digest mismatch")
        matches = [r for r in self.registrations if r.adapter_id == request.adapter_id and r.registration_revision == request.adapter_revision and r.accepts(request.resource_id, request.action, current)]
        if len(matches) != 1:
            raise StorageAdapterError("ADAPTER_DISABLED", "exactly one enabled matching storage adapter is required")
        if _timestamp(request.expires_at) <= current:
            raise StorageAdapterError("AUTHORIZATION_INVALID", "storage request expired")
        if claim.id != request.claim_id or claim.resource_id != request.resource_id or claim.owner_thread != request.requested_by or claim.claim_type not in {ClaimType.LEASE, ClaimType.LOCK, ClaimType.CHECKOUT, ClaimType.HOLD} or claim.status not in {ClaimStatus.APPROVED, ClaimStatus.ACTIVE}:
            raise StorageAdapterError("CLAIM_INVALID", "exclusive storage claim does not match")
        if claim.expires_at and _timestamp(claim.expires_at) <= _timestamp(request.expires_at):
            raise StorageAdapterError("CLAIM_INVALID", "claim does not cover request deadline")
        if approval.id != request.approval_id or approval.subject_id != request.request_id or approval.status != ApprovalStatus.APPROVED:
            raise StorageAdapterError("AUTHORIZATION_INVALID", "operation approval does not match")
        key = (request.adapter_id, request.project_id, request.idempotency_key)
        prior = self.records.get(key)
        if prior:
            if prior.request_digest != request.request_digest:
                raise StorageAdapterError("IDEMPOTENCY_CONFLICT", "idempotency key belongs to another request")
            return prior
        intent = StorageDispatchRecord(f"storage-dispatch.{request.request_id}", request.adapter_id, request.project_id, request.idempotency_key, request.request_digest, request.request_id, "dispatching")
        self.records[key] = intent
        try:
            receipt = self.client_factory(matches[0]).submit(request)
        except Exception as error:
            # Once submission was attempted, absence of a receipt is unknown,
            # never proof that it is safe to resubmit.
            unknown = replace(intent, status="dispatch_unknown")
            self.records[key] = unknown
            if isinstance(error, StorageAdapterError):
                raise
            raise StorageAdapterError("TIMEOUT_UNKNOWN", "storage dispatch outcome is unknown") from error
        accepted = replace(intent, status="in_progress", operation_id=receipt.operation_id)
        self.records[key] = accepted
        return accepted


def _validate_envelope(response: Mapping[str, object], request: StorageExecutionRequest) -> None:
    if response.get("contract_version") != CONTRACT_VERSION or response.get("request_id") != request.request_id:
        raise StorageAdapterError("CONTRACT_MISMATCH", "adapter response identity or contract mismatch")


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)
