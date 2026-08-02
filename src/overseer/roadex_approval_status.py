"""Roadex final-approval projection contracts and binding lifecycle."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, Iterable, Literal, Mapping, cast

from .admin import AdminChangePlan
from .backup_provisioning import (
    DonutHoleBackupProvisioningPlan,
    PLAN_KIND,
    ProvisioningStatus,
    _load as load_roadex_plan,
    _require_terminal_evidence,
    _validate_plan,
)
from .core import OwnerDomain
from .serialization import to_jsonable


_OPAQUE_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_ROADEX_EVIDENCE_REQUESTERS = frozenset(
    {
        OwnerDomain.KIRA.value,
        OwnerDomain.OBRIEN.value,
        OwnerDomain.ODO_IDS.value,
        OwnerDomain.SISKO.value,
    }
)
_ROADEX_EVIDENCE_ROLES = ("kira", "obrien", "security", "sisko")


def validate_opaque_ref(value: str) -> None:
    if not isinstance(value, str) or not _OPAQUE_REF.fullmatch(value):
        raise ValueError("approval_ref must be an opaque identifier")


def _require_truthy_str(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_iso8601(value: object, field: str) -> str:
    text = _require_truthy_str(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include timezone information")
    return text


def _require_optional_str(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _require_truthy_str(value, field)


def _require_enum(value: object, enum_values: set[str], field: str) -> str:
    text = _require_truthy_str(value, field)
    if text not in enum_values:
        joined = ",".join(sorted(enum_values))
        raise ValueError(f"{field} must be one of: {joined}")
    return text


def _require_exact_type(value: object, expected_type: type[object], field: str) -> None:
    if not isinstance(value, expected_type):
        raise ValueError(f"{field} must be {expected_type.__name__}")


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
    _validate_approval_binding_draft(draft)
    with store.agent_transaction():
        existing = _load_existing_binding(store, draft.approval_ref)
        if existing is not None:
            source = load_source_from_draft(store, draft)
            _validate_replayed_binding(existing, draft, source)
            return existing

        save_source()
        source = load_source_from_draft(store, draft)
        _require_initial_source_state(draft.source_kind, source)
        source_digest = exact_source_evidence_digest(source)
        binding = binding_from_draft(draft, source_digest)
        return store.save_roadex_approval_binding(binding)


def roadex_approval_status(
    store_path: str,
    approval_ref: str,
) -> Mapping[str, object]:
    validate_opaque_ref(approval_ref)
    from .store import SQLiteStore

    with SQLiteStore(store_path) as store:
        binding = store.load_roadex_approval_binding(approval_ref)
        source = load_exact_bound_source(store, binding)
        _validate_source(source, binding)
        source_digest = exact_source_evidence_digest(source)
        verify_scope_digest(binding, source_digest)
        decision, source_status, updated_at = project_decision(store, binding, source)
        decision_version = project_decision_version(
            binding,
            source_status,
            decision,
            updated_at,
        )
        return public_projection(binding, decision, decision_version, updated_at)


def load_exact_bound_source(store, binding: RoadexApprovalBinding):
    try:
        if binding.source_kind == "admin-plan":
            return store.load_admin_change_plan(binding.source_id)
        if binding.source_kind == "roadex-human-decision":
            return load_roadex_human_plan(store, binding.source_id)
    except KeyError as error:
        raise ValueError("source reference is malformed") from error
    raise ValueError("unsupported source_kind")


def project_decision(
    store,
    binding: RoadexApprovalBinding,
    source: object,
) -> tuple[str, str, str]:
    if binding.source_kind == "admin-plan":
        source_plan = _require_admin_plan(source)
        _require_admin_binding_reference(binding, source_plan)
        if source_plan.archived:
            raise ValueError("admin source must not be archived")
        if source_plan.canceled:
            _require_admin_canceled_plan_evidence(source_plan)
            return (
                "rejected",
                "canceled",
                _newest_time(
                    source_plan.approved_at,
                    source_plan.canceled_at,
                    binding.created_at,
                ),
            )
        if source_plan.approved:
            _require_admin_approved_plan_evidence(source_plan)
            return (
                "approved",
                "approved",
                _newest_time(
                    source_plan.approved_at,
                    source_plan.canceled_at,
                    binding.created_at,
                ),
            )
        _require_admin_pending_plan_evidence(source_plan)
        return ("pending", "pending", binding.created_at)

    source_plan = _require_roadex_plan(source)
    status = source_plan.status
    if status != ProvisioningStatus.STAGED:
        _require_terminal_evidence(store, source_plan)

    if status == ProvisioningStatus.STAGED:
        return (
            "pending",
            status.value,
            _newest_time(
                source_plan.approved_at,
                source_plan.decided_at,
                source_plan.executed_at,
                binding.created_at,
            ),
        )
    if status == ProvisioningStatus.DENIED:
        _require_roadex_decision_plan_evidence(store, source_plan)
        return (
            "rejected",
            status.value,
            _newest_time(
                source_plan.decided_at,
                source_plan.approved_at,
                source_plan.executed_at,
                binding.created_at,
            ),
        )
    if status == ProvisioningStatus.REVISION_REQUESTED:
        _require_roadex_decision_plan_evidence(store, source_plan)
        return (
            "changes-requested",
            status.value,
            _newest_time(
                source_plan.decided_at,
                source_plan.approved_at,
                source_plan.executed_at,
                binding.created_at,
            ),
        )
    if status in {ProvisioningStatus.APPROVED, ProvisioningStatus.EXECUTED}:
        _require_roadex_approved_plan_evidence(store, source_plan)
        if status == ProvisioningStatus.EXECUTED:
            _require_roadex_execution_evidence(source_plan)
        return (
            "approved",
            status.value,
            _newest_time(
                source_plan.approved_at,
                source_plan.decided_at,
                source_plan.executed_at,
                binding.created_at,
            ),
        )
    if status in {ProvisioningStatus.FAILED, ProvisioningStatus.ROLLED_BACK}:
        _require_roadex_approved_plan_evidence(store, source_plan)
        _require_roadex_terminal_failure_evidence(source_plan)
        return (
            "approved",
            status.value,
            _newest_time(
                source_plan.approved_at,
                source_plan.executed_at,
                source_plan.decided_at,
                binding.created_at,
            ),
        )
    raise ValueError("unsupported Roadex human decision status")


def _validate_approval_binding_draft(draft: object) -> None:
    if not isinstance(draft, RoadexApprovalBindingDraft):
        raise ValueError("binding draft must be exact RoadexApprovalBindingDraft")
    _require_truthy_str(draft.approval_ref, "approval_ref")
    _require_enum(
        draft.source_kind,
        {"admin-plan", "roadex-human-decision"},
        "source_kind",
    )
    _require_truthy_str(draft.source_id, "source_id")
    _require_truthy_str(draft.project_id, "project_id")
    _require_truthy_str(draft.workspace_id, "workspace_id")
    _require_truthy_str(draft.resource_ref, "resource_ref")
    _require_enum(
        draft.authority_class,
        {"privileged-operation", "project-workflow"},
        "authority_class",
    )
    _require_truthy_str(draft.subject, "subject")
    if (
        draft.source_kind == "admin-plan"
        and draft.source_id != draft.approval_ref
    ):
        raise ValueError("admin-plan source_id must match approval_ref")


def _validate_replayed_binding(
    existing: RoadexApprovalBinding,
    draft: RoadexApprovalBindingDraft,
    source: object,
) -> None:
    expected = binding_from_draft(
        draft,
        exact_source_evidence_digest(source),
        created_at=existing.created_at,
    )
    if existing != expected:
        raise ValueError("Roadex approval binding is immutable")


def _load_existing_binding(store, approval_ref: str) -> RoadexApprovalBinding | None:
    try:
        return store.load_roadex_approval_binding(approval_ref)
    except KeyError:
        return None


def _require_initial_source_state(source_kind: str, source: object) -> None:
    if source_kind == "admin-plan":
        source_plan = _require_admin_plan(source)
        if source_plan.approved:
            raise ValueError(
                "admin binding source must be unapproved for initial projection binding"
            )
        if source_plan.canceled:
            raise ValueError(
                "admin binding source must not be canceled for initial projection binding"
            )
        return
    if source_kind == "roadex-human-decision":
        source_plan = _require_roadex_plan(source)
        if source_plan.status != ProvisioningStatus.STAGED:
            raise ValueError(
                "roadex binding source must be staged for initial projection binding"
            )
        return
    raise ValueError("unsupported source_kind")


def _require_admin_binding_reference(
    binding: RoadexApprovalBinding,
    plan: AdminChangePlan,
) -> None:
    if binding.source_id != plan.id:
        raise ValueError("admin source id must match source payload")


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


def binding_from_draft(
    draft: RoadexApprovalBindingDraft,
    source_digest: str,
    *,
    created_at: str | None = None,
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
        created_at=created_at or datetime.now(UTC).isoformat(),
    )


def load_source_from_draft(store, draft: RoadexApprovalBindingDraft):
    if draft.source_kind == "admin-plan":
        return store.load_admin_change_plan(draft.source_id)
    if draft.source_kind == "roadex-human-decision":
        return load_roadex_human_plan(store, draft.source_id)
    raise ValueError("unsupported source_kind")


def source_evidence_digest(source: object) -> str:
    return exact_source_evidence_digest(source)


def exact_source_evidence_digest(source: object) -> str:
    if isinstance(source, AdminChangePlan):
        return source_digest_from_admin_plan(source)
    if isinstance(source, DonutHoleBackupProvisioningPlan):
        return source.plan_digest
    return _digest(to_jsonable(source))


def verify_scope_digest(
    binding: RoadexApprovalBinding,
    source_digest: str,
) -> None:
    draft = _draft_from_binding(binding)
    if binding.scope_digest != scope_digest(draft, source_digest):
        raise ValueError("source evidence digest does not match binding")


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
        "approvalRef": draft.approval_ref,
        "sourceKind": draft.source_kind,
        "sourceId": draft.source_id,
        "projectId": draft.project_id,
        "workspaceId": draft.workspace_id,
        "resourceRef": draft.resource_ref,
        "authorityClass": draft.authority_class,
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


def load_roadex_human_plan(store, source_id: str) -> DonutHoleBackupProvisioningPlan:
    row = store._connection.execute(
        "SELECT payload FROM backup_provisioning_plans WHERE id=?",
        (source_id,),
    ).fetchone()
    if row is None:
        raise KeyError(source_id)
    plan = load_roadex_plan(str(row["payload"]))
    if plan.plan_id != source_id:
        raise ValueError("source id must match approval source")
    if plan.kind != PLAN_KIND:
        raise ValueError("exact kind must be preserved")
    if plan.decision_source != "Roadex":
        raise ValueError("Roadex decision source must be preserved")
    try:
        _validate_plan(plan)
    except ValueError as error:
        raise ValueError("plan digest") from error
    return plan


def _require_admin_plan(source: object) -> AdminChangePlan:
    if not isinstance(source, AdminChangePlan):
        raise ValueError("admin-plan source must be an admin change plan")
    return source


def _validate_source(source: object, binding: RoadexApprovalBinding) -> None:
    if binding.source_kind == "admin-plan":
        if source.id != binding.source_id:
            raise ValueError("admin source id must match source payload")
    elif binding.source_kind == "roadex-human-decision":
        _require_roadex_plan(source)
    else:
        raise ValueError("unsupported source_kind")


def _require_roadex_plan(source: object) -> DonutHoleBackupProvisioningPlan:
    if not isinstance(source, DonutHoleBackupProvisioningPlan):
        raise ValueError("roadex-human source must be a provisioning plan")
    if source.decision_source != "Roadex":
        raise ValueError("Roadex decision source must be preserved")
    if source.kind != PLAN_KIND:
        raise ValueError("exact kind must be preserved")
    _validate_plan(source)
    return source


def _digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


def _require_admin_pending_plan_evidence(plan: AdminChangePlan) -> None:
    if plan.archived:
        raise ValueError("admin source must not be archived")


def _require_admin_approved_plan_evidence(plan: AdminChangePlan) -> None:
    _require_truthy_str(plan.approved_by, "approved_by")
    _require_iso8601(plan.approved_at, "approved_at")


def _require_admin_canceled_plan_evidence(plan: AdminChangePlan) -> None:
    _require_truthy_str(plan.canceled_by, "canceled_by")
    _require_iso8601(plan.canceled_at, "canceled_at")
    _require_truthy_str(plan.cancellation_reason, "cancellation_reason")


def _require_roadex_decision_plan_evidence(store, plan: DonutHoleBackupProvisioningPlan) -> None:
    try:
        _require_terminal_evidence(store, plan)
    except KeyError as error:
        raise ValueError("terminal decision evidence is required") from error
    _require_truthy_str(plan.decision_reason, "decision_reason")
    _require_truthy_str(plan.decided_by, "decided_by")
    _require_iso8601(plan.decided_at, "decided_at")
    _require_roadex_approver_independent(
        store,
        str(plan.decided_by),
        plan.evidence_ids,
        "decided_by",
    )


def _require_roadex_approved_plan_evidence(store, plan: DonutHoleBackupProvisioningPlan) -> None:
    try:
        _require_terminal_evidence(store, plan)
    except KeyError as error:
        raise ValueError("terminal approved evidence is required") from error
    _require_truthy_str(plan.approved_by, "approved_by")
    _require_iso8601(plan.approved_at, "approved_at")
    _require_roadex_approver_independent(
        store,
        str(plan.approved_by),
        plan.evidence_ids,
        "approved_by",
    )


def _require_roadex_execution_evidence(plan: DonutHoleBackupProvisioningPlan) -> None:
    _require_truthy_str(plan.evidence_digest, "evidence_digest")
    _require_iso8601(plan.executed_at, "executed_at")


def _require_roadex_terminal_failure_evidence(plan: DonutHoleBackupProvisioningPlan) -> None:
    _require_roadex_execution_evidence(plan)
    _require_truthy_str(plan.failed_operation, "failed_operation")
    _require_truthy_str(plan.error_code, "error_code")


def _require_roadex_approver_independent(
    store,
    approver: str,
    evidence_ids: Mapping[str, str],
    label: str,
) -> None:
    _require_truthy_str(approver, label)
    if approver in _ROADEX_EVIDENCE_REQUESTERS:
        raise ValueError(f"{label} must be independent from required evidence")

    from .crew import CrewMessage

    reviewers: set[str] = set()
    for role in _ROADEX_EVIDENCE_ROLES:
        try:
            message_id = cast(str, evidence_ids[role])
        except KeyError as error:
            raise ValueError(f"{label} evidence {role} message is malformed") from error
        try:
            message = store.load_crew_message(message_id)
        except KeyError as error:
            raise ValueError(f"{label} evidence {role} message is malformed") from error
        if not isinstance(message, CrewMessage):
            raise ValueError(f"{label} evidence {role} message is malformed")
        reviewers.add(message.requested_by)
        if message.decided_by:
            reviewers.add(message.decided_by)
    if approver in reviewers:
        raise ValueError(f"{label} must be independent from terminal evidence")


def _newest_time(*values: str | None) -> str:
    candidates = [value for value in values if isinstance(value, str) and value]
    if not candidates:
        return datetime.now(UTC).isoformat()
    return max(candidates)


def _validate_binding_object_types(binding: RoadexApprovalBinding) -> None:
    # keep an independent local validator for store-independent unit paths and
    # explicit API assertions.
    _require_truthy_str(binding.approval_ref, "approval_ref")
    _require_enum(
        binding.source_kind,
        {"admin-plan", "roadex-human-decision"},
        "source_kind",
    )
    _require_truthy_str(binding.source_id, "source_id")
    _require_truthy_str(binding.project_id, "project_id")
    _require_truthy_str(binding.workspace_id, "workspace_id")
    _require_truthy_str(binding.resource_ref, "resource_ref")
    _require_enum(
        binding.authority_class,
        {"privileged-operation", "project-workflow"},
        "authority_class",
    )
    _require_truthy_str(binding.subject, "subject")
    _require_truthy_str(binding.scope_digest, "scope_digest")
    _require_truthy_str(binding.created_at, "created_at")


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
