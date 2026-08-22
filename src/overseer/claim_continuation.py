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
from .core import ApprovalLevel, Claim, ClaimStatus, OwnerDomain


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
    activation_group_id: str | None
    lifecycle_id: str | None
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
        f"and activation group {continuation.activation_group_id or '[not bound]'}."
    )


def dispatch_claim_approval_continuation_status(
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
        result = selected_adapter.dispatch_prompt(
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
    if conversation_id is not None and conversation_id != owner_thread:
        raise ValueError("dispatch returned a different conversation identity")
    if status not in {"prompt_dispatched", "delivered", "acknowledged"}:
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
    "ClaimApprovalContinuation",
    "ClaimApprovalContinuationAttempt",
    "ContinuationState",
    "continuation_for_claim",
    "continuation_prompt",
    "continuation_status",
    "dispatch_claim_approval_continuation_status",
]
