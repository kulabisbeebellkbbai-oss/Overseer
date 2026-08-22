"""Durable, exact-owner continuations for approved resource claims.

Approval is deliberately separate from activation.  This module only records
the owner-thread continuation and its delivery attempt; it never changes the
claim or resource state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from .audit import AuditEvent, AuditEventType
from .core import (
    ApprovalLevel,
    Claim,
    ClaimStatus,
    ConflictOutcome,
    OwnerDomain,
    Resource,
    RiskLevel,
    ResourceState,
    decide_claim,
)


class ClaimActivationGroupState(StrEnum):
    REQUESTED = "requested"
    ACTIVE = "active"
    RELEASED = "released"


@dataclass(frozen=True)
class ClaimActivationGroup:
    """Immutable membership and authority binding for a paired claim set."""

    id: str
    lifecycle_id: str
    owner_thread: str
    owner_role: OwnerDomain
    claim_ids: tuple[str, ...]
    approval_ids: tuple[str, ...]
    resource_ids: tuple[str, ...]
    state: ClaimActivationGroupState = ClaimActivationGroupState.REQUESTED
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.lifecycle_id.strip() or not self.owner_thread.strip():
            raise ValueError("claim activation group requires identity, lifecycle, and owner thread")
        if not self.claim_ids or len(self.claim_ids) != len(self.approval_ids) or len(self.claim_ids) != len(self.resource_ids):
            raise ValueError("claim activation group claim, approval, and resource memberships must align")
        if len(set(self.claim_ids)) != len(self.claim_ids):
            raise ValueError("claim activation group claim IDs must be unique")
        if len(set(self.approval_ids)) != len(self.approval_ids):
            raise ValueError("claim activation group approval IDs must be unique")


class ContinuationState(StrEnum):
    PENDING = "pending"
    ATTEMPTING = "attempting"
    DELIVERED = "delivered"
    UNKNOWN = "unknown"
    RECONCILIATION_REQUIRED = "reconciliation_required"


@dataclass(frozen=True)
class ClaimApprovalContinuation:
    id: str
    claim_id: str
    approval_id: str
    resource_id: str
    owner_thread: str
    owner_role: OwnerDomain
    activation_group_id: str
    lifecycle_id: str
    state: ContinuationState = ContinuationState.PENDING
    attempt_id: str | None = None


@dataclass(frozen=True)
class ClaimApprovalContinuationAttempt:
    id: str
    continuation_id: str
    owner_thread: str
    state: ContinuationState
    attempted_at: str
    result_status: str | None = None
    result_reason: str | None = None

    @property
    def status(self) -> ContinuationState:
        return self.state


class PromptAdapter(Protocol):
    def dispatch_prompt(self, owner_thread: str, prompt: str) -> Any: ...


def continuation_for_claim(claim: Claim, approval_id: str) -> ClaimApprovalContinuation:
    """Build the deterministic outbox identity for one exact ROLE approval."""
    if not claim.owner_thread.strip():
        raise ValueError("claim approval continuation requires an exact owner thread")
    if not claim.activation_group_id or not claim.lifecycle_id:
        raise ValueError("claim approval continuation requires explicit lifecycle and activation group bindings")
    return ClaimApprovalContinuation(
        id=f"continuation.{approval_id}",
        claim_id=claim.id,
        approval_id=approval_id,
        resource_id=claim.resource_id,
        owner_thread=claim.owner_thread,
        owner_role=claim.owner_role,
        activation_group_id=claim.activation_group_id,
        lifecycle_id=claim.lifecycle_id,
    )


def continuation_prompt(continuation: ClaimApprovalContinuation) -> str:
    return (
        f"ROLE approval {continuation.approval_id} for claim {continuation.claim_id} "
        f"on resource {continuation.resource_id} is approved. Activation remains "
        f"a separate explicit step for lifecycle {continuation.lifecycle_id} "
        f"and activation group {continuation.activation_group_id}."
    )


def dispatch_claim_approval_continuations_status(
    store_path: str,
    continuation_id: str,
    *,
    adapter: PromptAdapter | None = None,
    dispatched_by: str = "overseer",
    dispatched_at: str | None = None,
) -> dict[str, object]:
    """Dispatch exactly one continuation by its immutable ID.

    The attempt is committed before calling the external adapter.  Any
    exception or identity mismatch therefore leaves a durable reconciliation
    state rather than claiming delivery or retrying blindly.
    """
    from .codex_projects import CodexProjectThreadAdapter
    from .store import SQLiteStore

    if not continuation_id.strip():
        raise ValueError("continuation_id is required")
    now = dispatched_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            continuation = store.load_claim_approval_continuation(continuation_id)
            claim = store.load_claim(continuation.claim_id)
            approval = store.load_approval(continuation.approval_id)
            _validate_binding(continuation, claim, approval)
            if continuation.state == ContinuationState.DELIVERED:
                return continuation_status(continuation, dispatched_by=dispatched_by)
            if continuation.state != ContinuationState.PENDING:
                raise ValueError("continuation delivery requires reconciliation before retry")

            attempt_id = f"{continuation.id}.attempt.{_status_id(now)}"
            attempt = ClaimApprovalContinuationAttempt(
                id=attempt_id,
                continuation_id=continuation.id,
                owner_thread=continuation.owner_thread,
                state=ContinuationState.ATTEMPTING,
                attempted_at=now,
            )
            attempting = replace(
                continuation,
                state=ContinuationState.ATTEMPTING,
                attempt_id=attempt.id,
            )
            store.save_claim_approval_continuation_attempt(attempt)
            store.save_claim_approval_continuation(attempting)
            store.save_audit_event(_continuation_audit(
                continuation,
                claim,
                AuditEventType.REQUESTED,
                f"exact-owner continuation dispatch attempt {attempt.id} persisted before send",
                (attempt.id, continuation.approval_id),
                now,
            ))
    finally:
        store.close()

    selected_adapter = adapter or CodexProjectThreadAdapter()
    try:
        dispatch = getattr(selected_adapter, "dispatch_prompt_exact", None)
        if dispatch is None:
            raise ValueError("continuation adapter must implement dispatch_prompt_exact")
        result = dispatch(
            continuation.owner_thread,
            continuation_prompt(continuation),
        )
        _validate_delivery_result(result, continuation.owner_thread)
    except Exception as error:
        _finish_attempt(
            store_path,
            continuation,
            attempt,
            ContinuationState.RECONCILIATION_REQUIRED,
            result_status="unknown",
            result_reason=str(error),
        )
        return continuation_status(
            replace(continuation, state=ContinuationState.RECONCILIATION_REQUIRED, attempt_id=attempt.id),
            dispatched_by=dispatched_by,
            reason=str(error),
        )

    delivered = replace(continuation, state=ContinuationState.DELIVERED, attempt_id=attempt.id)
    _finish_attempt(
        store_path,
        continuation,
        attempt,
        ContinuationState.DELIVERED,
        result_status=str(getattr(result, "status", "delivered")),
        result_reason=str(getattr(result, "reason", "delivered")),
        final=delivered,
    )
    return continuation_status(delivered, dispatched_by=dispatched_by)


def dispatch_claim_approval_continuation_status(*args: Any, **kwargs: Any) -> dict[str, object]:
    """Compatibility wrapper for the original singular API name."""
    return dispatch_claim_approval_continuations_status(*args, **kwargs)


def _validate_binding(continuation: ClaimApprovalContinuation, claim: Claim, approval: Any) -> None:
    if continuation.id != f"continuation.{approval.id}":
        raise ValueError("continuation identity is invalid")
    if continuation.claim_id != claim.id or continuation.resource_id != claim.resource_id:
        raise ValueError("continuation claim or resource binding is invalid")
    if continuation.owner_thread != claim.owner_thread:
        raise ValueError("continuation owner thread binding is invalid")
    if continuation.owner_role != claim.owner_role:
        raise ValueError("continuation owner role binding is invalid")
    if approval.id != continuation.approval_id or approval.subject_id != claim.id:
        raise ValueError("continuation approval binding is invalid")
    if approval.approval_level != ApprovalLevel.ROLE:
        raise ValueError("continuation requires an approved ROLE approval")
    if approval.owner_domain != claim.owner_role:
        raise ValueError("continuation approval owner does not match claim owner")
    if approval.status.value != "approved":
        raise ValueError("continuation approval is not approved")
    if claim.status != ClaimStatus.REQUESTED:
        raise ValueError("continuation requires the still-requested claim")


def _validate_delivery_result(result: Any, owner_thread: str) -> None:
    returned_thread = getattr(result, "owner_thread", None)
    status = getattr(result, "status", None)
    if returned_thread != owner_thread:
        raise ValueError("dispatch returned a different owner thread")
    resume_result = getattr(result, "resume_result", None)
    conversation_id = getattr(result, "conversation_id", None)
    if resume_result is not None:
        conversation_id = getattr(resume_result, "conversation_id", None)
    if conversation_id is None:
        raise ValueError("dispatch delivery proof is missing the exact conversation identity")
    if conversation_id is not None and conversation_id != owner_thread:
        raise ValueError("dispatch returned a different conversation identity")
    if status not in {"prompt_dispatched", "delivered"}:
        raise ValueError("dispatch delivery is not confirmed")


def _finish_attempt(
    store_path: str,
    continuation: ClaimApprovalContinuation,
    attempt: ClaimApprovalContinuationAttempt,
    state: ContinuationState,
    *,
    result_status: str,
    result_reason: str,
    final: ClaimApprovalContinuation | None = None,
) -> None:
    from .store import SQLiteStore

    updated_attempt = replace(
        attempt,
        state=state,
        result_status=result_status,
        result_reason=result_reason,
    )
    store = SQLiteStore(store_path)
    try:
        claim = store.load_claim(continuation.claim_id)
        with store.agent_transaction():
            store.save_claim_approval_continuation_attempt(updated_attempt)
            updated = final or replace(continuation, state=state, attempt_id=attempt.id)
            store.save_claim_approval_continuation(updated)
            store.save_audit_event(_continuation_audit(
                updated,
                claim,
                AuditEventType.EXECUTED if state == ContinuationState.DELIVERED else AuditEventType.ALERT,
                f"exact-owner continuation delivery state is {state.value}",
                (attempt.id,),
                attempt.attempted_at,
            ))
    finally:
        store.close()


def continuation_status(
    continuation: ClaimApprovalContinuation,
    *,
    dispatched_by: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return {
        "id": continuation.id,
        "claim_id": continuation.claim_id,
        "approval_id": continuation.approval_id,
        "resource_id": continuation.resource_id,
        "owner_thread": continuation.owner_thread,
        "owner_role": continuation.owner_role.value,
        "activation_group_id": continuation.activation_group_id,
        "lifecycle_id": continuation.lifecycle_id,
        "state": continuation.state.value,
        "status": continuation.state.value,
        "attempt_id": continuation.attempt_id,
        "dispatched_by": dispatched_by,
        "reason": reason,
    }


def register_claim_activation_group_status(
    store_path: str,
    group_id: str,
    lifecycle_id: str,
    owner_thread: str,
    owner_role: str,
    claim_ids: tuple[str, ...] | list[str],
    approval_ids: tuple[str, ...] | list[str],
    resource_ids: tuple[str, ...] | list[str],
) -> dict[str, object]:
    """Register an exact group before its claims are requested.

    Registration is deliberately separate from claim request and approval. It
    creates no claim, approval, listener, or resource reservation.
    """
    from .store import SQLiteStore

    group = ClaimActivationGroup(
        id=str(group_id),
        lifecycle_id=str(lifecycle_id),
        owner_thread=str(owner_thread),
        owner_role=OwnerDomain(owner_role),
        claim_ids=tuple(str(item) for item in claim_ids),
        approval_ids=tuple(str(item) for item in approval_ids),
        resource_ids=tuple(str(item) for item in resource_ids),
    )
    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            try:
                existing = store.load_claim_activation_group(group.id)
            except KeyError:
                store.save_claim_activation_group(group)
                existing = group
            else:
                immutable_fields = (
                    "id", "lifecycle_id", "owner_thread", "owner_role",
                    "claim_ids", "approval_ids", "resource_ids",
                )
                if any(getattr(existing, field) != getattr(group, field) for field in immutable_fields):
                    raise ValueError("claim activation group registration conflicts with existing identity")
            return {
                "group": existing.id,
                "group_id": existing.id,
                "group_status": existing.state.value,
                "state": existing.state.value,
                "lifecycle_id": existing.lifecycle_id,
                "owner_thread": existing.owner_thread,
                "owner_role": existing.owner_role.value,
                "claim_ids": list(existing.claim_ids),
                "approval_ids": list(existing.approval_ids),
                "resource_ids": list(existing.resource_ids),
                "idempotent": existing is not group,
            }
    finally:
        store.close()


def claim_group_status(store_path: str, group_id: str) -> dict[str, object]:
    """Return the authoritative, read-only status of one claim group."""
    from .store import SQLiteStore

    store = SQLiteStore(store_path)
    try:
        try:
            group, claims, approvals, resources = _load_group_bundle(store, group_id)
        except ValueError as error:
            group = store.load_claim_activation_group(group_id)
            return _registered_group_status(group, str(error))
        _validate_group_bindings(store, group, claims, approvals, resources, allow_released=True)
        return _claim_group_status(group, claims, resources)
    finally:
        store.close()


create_claim_activation_group_status = register_claim_activation_group_status


def activate_claim_group_status(store_path: str, group_id: str) -> dict[str, object]:
    """Atomically activate every claim in a structurally bound group."""
    from .store import SQLiteStore

    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            group, claims, approvals, resources = _load_group_bundle(store, group_id)
            _validate_group_bindings(store, group, claims, approvals, resources)
            claim_states = {claim.status for claim in claims}
            resource_claims = {resource.id: resource.current_claim_id for resource in resources}
            if group.state == ClaimActivationGroupState.ACTIVE:
                if claim_states != {ClaimStatus.ACTIVE} or any(
                    claim.status != ClaimStatus.ACTIVE or resource_claims[claim.resource_id] != claim.id
                    for claim in claims
                ):
                    raise ValueError("claim activation group has a partial active state")
                return _claim_group_status(
                    group,
                    claims,
                    resources,
                    idempotent=True,
                    audit_event=f"audit.claim-group.{group.id}.executed",
                )
            if group.state != ClaimActivationGroupState.REQUESTED:
                raise ValueError("claim activation group is not requested")
            if claim_states != {ClaimStatus.REQUESTED}:
                raise ValueError("claim activation group claims must all be requested")
            _preflight_group_conflicts(claims, resources, store.list_claims(), store.list_resources())
            activated_claims = tuple(
                replace(claim, status=ClaimStatus.ACTIVE, approval_id=approval_id)
                for claim, approval_id in zip(claims, group.approval_ids)
            )
            activated_group = replace(group, state=ClaimActivationGroupState.ACTIVE)
            for claim in activated_claims:
                store.save_claim(claim)
            for claim, resource in zip(activated_claims, resources):
                if claim.is_exclusive():
                    store.save_resource(replace(resource, current_claim_id=claim.id))
            store.save_claim_activation_group(activated_group)
            event = _group_audit_event(
                activated_group,
                claims,
                AuditEventType.EXECUTED,
                f"claim activation group {group.id} activated atomically",
                (),
            )
            store.save_audit_event(event)
            return _claim_group_status(activated_group, activated_claims, resources, audit_event=event.id)
    finally:
        store.close()


def release_claim_group_status(
    store_path: str,
    group_id: str,
    evidence_ids: tuple[str, ...] | list[str],
) -> dict[str, object]:
    """Atomically release every active claim in a group with cleanup evidence."""
    from .store import SQLiteStore

    normalized_evidence = tuple(str(item).strip() for item in evidence_ids if str(item).strip())
    if not normalized_evidence:
        raise ValueError("claim group release requires evidence")
    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            group, claims, approvals, resources = _load_group_bundle(store, group_id)
            _validate_group_bindings(store, group, claims, approvals, resources, allow_released=True)
            if group.state == ClaimActivationGroupState.RELEASED:
                if all(claim.status == ClaimStatus.RELEASED for claim in claims) and all(
                    resource.current_claim_id is None for resource in resources
                ):
                    return _claim_group_status(group, claims, resources, idempotent=True)
                raise ValueError("claim activation group has a partial released state")
            if group.state != ClaimActivationGroupState.ACTIVE or any(
                claim.status != ClaimStatus.ACTIVE for claim in claims
            ):
                raise ValueError("claim activation group must be wholly active before release")
            released_claims = tuple(replace(claim, status=ClaimStatus.RELEASED) for claim in claims)
            released_group = replace(
                group,
                state=ClaimActivationGroupState.RELEASED,
                evidence_ids=normalized_evidence,
            )
            for claim in released_claims:
                store.save_claim(claim)
            for resource in resources:
                store.save_resource(replace(resource, current_claim_id=None))
            store.save_claim_activation_group(released_group)
            event = _group_audit_event(
                released_group,
                claims,
                AuditEventType.RELEASED,
                f"claim activation group {group.id} released atomically",
                normalized_evidence,
            )
            store.save_audit_event(event)
            status = _claim_group_status(released_group, released_claims, resources, audit_event=event.id)
            status["release_evidence_complete"] = True
            return status
    finally:
        store.close()


def _load_group_bundle(store: Any, group_id: str) -> tuple[ClaimActivationGroup, tuple[Claim, ...], tuple[Any, ...], tuple[Resource, ...]]:
    if not group_id.strip():
        raise ValueError("group_id is required")
    group = store.load_claim_activation_group(group_id)
    try:
        claims = tuple(store.load_claim(claim_id) for claim_id in group.claim_ids)
        approvals = tuple(store.load_approval(approval_id) for approval_id in group.approval_ids)
        resources = tuple(store.load_resource(resource_id) for resource_id in group.resource_ids)
    except KeyError as error:
        raise ValueError(f"claim activation group references missing record: {error.args[0]}") from error
    return group, claims, approvals, resources


def _validate_group_bindings(
    store: Any,
    group: ClaimActivationGroup,
    claims: tuple[Claim, ...],
    approvals: tuple[Any, ...],
    resources: tuple[Resource, ...],
    *,
    allow_released: bool = False,
) -> None:
    if len(claims) != len(group.claim_ids) or len(approvals) != len(group.approval_ids) or len(resources) != len(group.resource_ids):
        raise ValueError("claim activation group membership is incomplete")
    for claim, approval_id, resource_id, approval in zip(claims, group.approval_ids, group.resource_ids, approvals):
        if claim.activation_group_id != group.id or claim.lifecycle_id != group.lifecycle_id:
            raise ValueError("claim activation group lifecycle binding is invalid")
        if claim.owner_thread != group.owner_thread or claim.owner_role != group.owner_role:
            raise ValueError("claim activation group owner binding is invalid")
        if claim.resource_id != resource_id:
            raise ValueError("claim activation group resource binding is invalid")
        if approval.id != approval_id or approval.subject_id != claim.id:
            raise ValueError("claim activation group approval binding is invalid")
        if approval.approval_level != ApprovalLevel.ROLE or not approval.can_execute():
            raise ValueError("claim activation group requires approved ROLE approvals")
        continuations = tuple(item for item in store.list_claim_approval_continuations() if item.claim_id == claim.id)
        if len(continuations) != 1:
            raise ValueError("claim activation group requires its exact approval continuation")
        continuation = continuations[0]
        if continuation.approval_id != approval.id or continuation.resource_id != claim.resource_id:
            raise ValueError("claim activation group requires its exact approval continuation")
        if continuation.owner_thread != group.owner_thread or continuation.owner_role != group.owner_role:
            raise ValueError("claim activation group continuation owner binding is invalid")
        if continuation.activation_group_id != group.id or continuation.lifecycle_id != group.lifecycle_id:
            raise ValueError("claim activation group continuation binding is invalid")
    if not allow_released and group.state == ClaimActivationGroupState.RELEASED:
        raise ValueError("claim activation group is released")


def _preflight_group_conflicts(
    claims: tuple[Claim, ...],
    resources: tuple[Resource, ...],
    all_claims: tuple[Claim, ...],
    all_resources: tuple[Resource, ...],
) -> None:
    resources_by_id = {resource.id: resource for resource in all_resources}
    group_ids = {claim.id for claim in claims}
    external_active = [
        claim for claim in all_claims
        if claim.id not in group_ids and claim.is_active_like()
    ]
    for claim, resource in zip(claims, resources):
        if resource.current_claim_id and resource.current_claim_id not in group_ids:
            raise ValueError(f"resource {resource.id} has an external current claim")
        decision = decide_claim(
            resource,
            claim,
            [replace(other, status=ClaimStatus.ACTIVE) for other in (*external_active, *claims) if other.id != claim.id],
            resources_by_id,
        )
        if decision.outcome in {ConflictOutcome.QUEUE, ConflictOutcome.BLOCK, ConflictOutcome.QUARANTINE}:
            raise ValueError(f"claim activation group conflict for {claim.id}: {decision.reason}")
        if resource.state in {ResourceState.RETIRED, ResourceState.QUARANTINED}:
            raise ValueError(f"claim activation group resource {resource.id} is unavailable")


def _claim_group_status(
    group: ClaimActivationGroup,
    claims: tuple[Claim, ...],
    resources: tuple[Resource, ...],
    *,
    idempotent: bool = False,
    audit_event: str | None = None,
) -> dict[str, object]:
    return {
        "group": group.id,
        "group_id": group.id,
        "group_status": group.state.value,
        "state": group.state.value,
        "lifecycle_id": group.lifecycle_id,
        "owner_thread": group.owner_thread,
        "owner_role": group.owner_role.value,
        "claim_ids": list(group.claim_ids),
        "approval_ids": list(group.approval_ids),
        "resource_ids": list(group.resource_ids),
        "claims": [{"id": claim.id, "status": claim.status.value, "resource_id": claim.resource_id} for claim in claims],
        "resources": [{"id": resource.id, "current_claim_id": resource.current_claim_id} for resource in resources],
        "evidence_ids": list(group.evidence_ids),
        "idempotent": idempotent,
        "audit_event": audit_event or f"audit.claim-group.{group.id}.{group.state.value}",
        "release_evidence_complete": bool(group.evidence_ids),
    }


def _registered_group_status(group: ClaimActivationGroup, missing_reason: str) -> dict[str, object]:
    return {
        "group": group.id,
        "group_id": group.id,
        "group_status": group.state.value,
        "state": group.state.value,
        "lifecycle_id": group.lifecycle_id,
        "owner_thread": group.owner_thread,
        "owner_role": group.owner_role.value,
        "claim_ids": list(group.claim_ids),
        "approval_ids": list(group.approval_ids),
        "resource_ids": list(group.resource_ids),
        "claims": [],
        "resources": [],
        "missing_records": missing_reason,
        "evidence_ids": list(group.evidence_ids),
        "idempotent": False,
        "audit_event": None,
        "release_evidence_complete": bool(group.evidence_ids),
    }


def _group_audit_event(
    group: ClaimActivationGroup,
    claims: tuple[Claim, ...],
    event_type: AuditEventType,
    summary: str,
    evidence_ids: tuple[str, ...],
) -> AuditEvent:
    return AuditEvent(
        id=f"audit.claim-group.{group.id}.{event_type.value}",
        event_type=event_type,
        owner_domain=group.owner_role,
        subject_id=group.id,
        summary=summary,
        risk_level=max((claim.risk_level for claim in claims), key=lambda item: (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL).index(item)),
        evidence_ids=evidence_ids,
    )


def _status_id(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace("+", "").replace(".", "")


def _continuation_audit(
    continuation: ClaimApprovalContinuation,
    claim: Claim,
    event_type: AuditEventType,
    summary: str,
    evidence_ids: tuple[str, ...],
    occurred_at: str,
) -> AuditEvent:
    return AuditEvent(
        id=f"audit.{continuation.id}.state.{event_type.value}.{_status_id(occurred_at)}",
        event_type=event_type,
        owner_domain=continuation.owner_role,
        subject_id=continuation.id,
        summary=summary,
        risk_level=claim.risk_level,
        evidence_ids=evidence_ids,
        occurred_at=occurred_at,
    )


__all__ = [
    "ClaimActivationGroup",
    "ClaimActivationGroupState",
    "ClaimApprovalContinuation",
    "ClaimApprovalContinuationAttempt",
    "ContinuationState",
    "continuation_for_claim",
    "continuation_prompt",
    "continuation_status",
    "dispatch_claim_approval_continuation_status",
    "dispatch_claim_approval_continuations_status",
    "activate_claim_group_status",
    "claim_group_status",
    "release_claim_group_status",
    "register_claim_activation_group_status",
    "create_claim_activation_group_status",
]
