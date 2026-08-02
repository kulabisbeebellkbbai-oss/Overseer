"""Roadex final-approval projection contracts and binding lifecycle."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, Mapping, Literal

from .admin import AdminChangePlan
from .serialization import to_jsonable


_OPAQUE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def validate_opaque_ref(value: str) -> None:
    if not isinstance(value, str) or not _OPAQUE_REF.fullmatch(value):
        raise ValueError("approval_ref must be an opaque identifier")


@dataclass(frozen=True)
class RoadexApprovalBindingDraft:
    approval_ref: str
    source_kind: Literal["admin-plan", "roadex-human-decision"]
    source_id: str
    project_id: str
    workspace_id: str
    resource_ref: str
    authority_class: Literal["privileged-operation", "project-workflow"]
    subject: str


@dataclass(frozen=True)
class RoadexApprovalBinding:
    approval_ref: str
    source_kind: Literal["admin-plan", "roadex-human-decision"]
    source_id: str
    project_id: str
    workspace_id: str
    resource_ref: str
    authority_class: Literal["privileged-operation", "project-workflow"]
    subject: str
    scope_digest: str
    created_at: str


def stage_bound_roadex_approval(
    store,
    draft: RoadexApprovalBindingDraft,
    save_source: Callable[[], None],
) -> RoadexApprovalBinding:
    if draft.source_kind == "admin-plan" and draft.source_id != draft.approval_ref:
        raise ValueError("admin-plan source_id must match approval_ref")
    validate_opaque_ref(draft.approval_ref)
    validate_opaque_ref(draft.source_id)
    with store.agent_transaction():
        save_source()
        source = load_source_from_draft(store, draft)
        source_digest = exact_source_evidence_digest(source)
        binding = binding_from_draft(draft, source_digest)
        binding = store.save_roadex_approval_binding(binding)
    return binding


def roadex_approval_status(
    store_path: str,
    approval_ref: str,
) -> Mapping[str, object]:
    validate_opaque_ref(approval_ref)
    from .store import SQLiteStore

    with SQLiteStore(store_path) as store:
        try:
            binding = store.load_roadex_approval_binding(approval_ref)
        except KeyError:
            raise KeyError("bound Roadex approval")
        source = load_exact_bound_source(store, binding)
        source_digest = exact_source_evidence_digest(source)
        verify_scope_digest(binding, source_digest)
        decision, source_status, updated_at = project_decision(binding, source)
        decision_version = project_decision_version(
            binding, source_status, decision, updated_at
        )
        return public_projection(binding, decision, decision_version, updated_at)


def load_exact_bound_source(store, binding: RoadexApprovalBinding):
    if binding.source_kind == "admin-plan":
        source = store.load_admin_change_plan(binding.source_id)
        if binding.source_id != binding.approval_ref:
            raise ValueError("admin-plan source_id must match approval_ref")
        return source
    if binding.source_kind == "roadex-human-decision":
        return load_roadex_human_plan(store, binding.source_id)
    raise ValueError("unsupported source_kind")


def project_decision(
    binding: RoadexApprovalBinding,
    source: object,
) -> tuple[str, str, str]:
    if binding.source_kind == "admin-plan":
        source_plan = _require_admin_plan(source)
        if source_plan.canceled:
            return (
                "rejected",
                "canceled",
                _newest_time(source_plan.approved_at, source_plan.canceled_at, binding.created_at),
            )
        if source_plan.approved:
            return (
                "approved",
                "approved",
                _newest_time(source_plan.approved_at, source_plan.canceled_at, binding.created_at),
            )
        return ("pending", "pending", binding.created_at)

    source_plan = _require_roadex_plan(source)
    status = str(source_plan["status"])
    if status == "staged":
        return (
            "pending",
            status,
            _newest_time(
                source_plan.get("proposed_at"),
                source_plan.get("approved_at"),
                source_plan.get("decided_at"),
                source_plan.get("executed_at"),
                binding.created_at,
            ),
        )
    if status == "approved" or status == "executed":
        return (
            "approved",
            status,
            _newest_time(
                source_plan.get("approved_at"),
                source_plan.get("executed_at"),
                source_plan.get("decided_at"),
                binding.created_at,
            ),
        )
    if status == "denied":
        return (
            "rejected",
            status,
            _newest_time(
                source_plan.get("decided_at"),
                source_plan.get("approved_at"),
                source_plan.get("executed_at"),
                binding.created_at,
            ),
        )
    if status == "revision_requested":
        return (
            "changes-requested",
            status,
            _newest_time(
                source_plan.get("decided_at"),
                source_plan.get("approved_at"),
                source_plan.get("executed_at"),
                binding.created_at,
            ),
        )
    raise ValueError("unsupported Roadex human decision status")


def project_decision_version(
    binding: RoadexApprovalBinding,
    source_status: str,
    decision: str,
    updated_at: str,
) -> str:
    payload = {
        "approvalRef": binding.approval_ref,
        "scopeDigest": binding.scope_digest,
        "decision": decision,
        "sourceStatus": source_status,
        "updatedAt": updated_at,
    }
    return _digest(payload)


def public_projection(
    binding: RoadexApprovalBinding,
    decision: str,
    decision_version: str,
    updated_at: str,
) -> Mapping[str, object]:
    return {
        "approvalRef": binding.approval_ref,
        "sourceKind": binding.source_kind,
        "projectId": binding.project_id,
        "workspaceId": binding.workspace_id,
        "resourceRef": binding.resource_ref,
        "authorityClass": binding.authority_class,
        "subject": binding.subject,
        "scopeDigest": binding.scope_digest,
        "decision": decision,
        "decisionVersion": decision_version,
        "updatedAt": updated_at,
    }


def load_source_from_draft(store, draft: RoadexApprovalBindingDraft):
    if draft.source_kind == "admin-plan":
        return store.load_admin_change_plan(draft.source_id)
    if draft.source_kind == "roadex-human-decision":
        return load_roadex_human_plan(store, draft.source_id)
    raise ValueError("unsupported source_kind")


def load_roadex_human_plan(store, source_id: str) -> Mapping[str, object]:
    row = store._connection.execute(
        "SELECT payload FROM backup_provisioning_plans WHERE id=?",
        (source_id,),
    ).fetchone()
    if row is None:
        raise KeyError(source_id)
    payload = json.loads(str(row["payload"]))
    if not isinstance(payload, dict):
        raise ValueError("roadex-human source is invalid")
    return payload


def binding_from_draft(
    draft: RoadexApprovalBindingDraft,
    source_digest: str,
) -> RoadexApprovalBinding:
    return RoadexApprovalBinding(
        approval_ref=draft.approval_ref,
        source_kind=draft.source_kind,
        source_id=draft.source_id,
        project_id=draft.project_id,
        workspace_id=draft.workspace_id,
        resource_ref=draft.resource_ref,
        authority_class=draft.authority_class,
        subject=draft.subject,
        scope_digest=scope_digest(draft, source_digest),
        created_at=datetime.now(UTC).isoformat(),
    )


def source_evidence_digest(source: object) -> str:
    return exact_source_evidence_digest(source)


def exact_source_evidence_digest(source: object) -> str:
    if isinstance(source, AdminChangePlan):
        return source_digest_from_admin_plan(source)
    if isinstance(source, Mapping):
        return source_digest_from_roadex_plan(source)
    return _digest(to_jsonable(source))


def verify_scope_digest(
    binding: RoadexApprovalBinding,
    source_digest: str,
) -> None:
    if binding.scope_digest != scope_digest(_draft_from_binding(binding), source_digest):
        raise ValueError("digest no longer matches source")


def source_digest_from_admin_plan(plan: AdminChangePlan) -> str:
    payload = to_jsonable(plan)
    mutable = (
        "approved",
        "approved_by",
        "approved_at",
        "canceled",
        "canceled_by",
        "canceled_at",
        "cancellation_reason",
        "archived",
        "archived_by",
        "archived_at",
        "archive_record_id",
    )
    for field in mutable:
        payload.pop(field, None)
    return _digest(payload)


def source_digest_from_roadex_plan(plan: Mapping[str, object]) -> str:
    mutable = (
        "status",
        "decision_reason",
        "decided_by",
        "decided_at",
        "approved_by",
        "approved_at",
        "executed_at",
        "evidence_digest",
        "failed_operation",
        "error_code",
        "error_detail",
    )
    payload = dict(plan)
    for field in mutable:
        payload.pop(field, None)
    return _digest(payload)


def scope_digest(
    draft: RoadexApprovalBindingDraft,
    source_digest: str,
) -> str:
    return _digest(_scope_payload(draft, source_digest))


def _scope_payload(
    draft: RoadexApprovalBindingDraft,
    source_digest: str,
) -> dict[str, object]:
    return {
        "approval_ref": draft.approval_ref,
        "source_kind": draft.source_kind,
        "source_id": draft.source_id,
        "project_id": draft.project_id,
        "workspace_id": draft.workspace_id,
        "resource_ref": draft.resource_ref,
        "authority_class": draft.authority_class,
        "subject": draft.subject,
        "sourceEvidenceDigest": source_digest,
    }


def _draft_from_binding(binding: RoadexApprovalBinding) -> RoadexApprovalBindingDraft:
    return RoadexApprovalBindingDraft(
        approval_ref=binding.approval_ref,
        source_kind=binding.source_kind,
        source_id=binding.source_id,
        project_id=binding.project_id,
        workspace_id=binding.workspace_id,
        resource_ref=binding.resource_ref,
        authority_class=binding.authority_class,
        subject=binding.subject,
    )


def _require_admin_plan(source: object) -> AdminChangePlan:
    if not isinstance(source, AdminChangePlan):
        raise ValueError("admin-plan source must be an admin change plan")
    return source


def _require_roadex_plan(source: object) -> Mapping[str, object]:
    if not isinstance(source, Mapping):
        raise ValueError("roadex-human source must be a provisioning plan")
    return source


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def _newest_time(*values: str | None) -> str:
    candidates = [value for value in values if value is not None]
    if not candidates:
        return datetime.now(UTC).isoformat()
    return max(candidates)


__all__ = [
    "RoadexApprovalBinding",
    "RoadexApprovalBindingDraft",
    "load_roadex_human_plan",
    "load_exact_bound_source",
    "stage_bound_roadex_approval",
    "source_evidence_digest",
    "roadex_approval_status",
    "project_decision",
]
