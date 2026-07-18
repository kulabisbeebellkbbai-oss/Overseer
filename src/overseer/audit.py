"""Approval and audit records for command decisions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import ApprovalLevel, ConflictDecision, OwnerDomain, RiskLevel


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"


class AuditEventType(StrEnum):
    REQUESTED = "requested"
    ALLOWED = "allowed"
    QUEUED = "queued"
    BLOCKED = "blocked"
    ESCALATED = "escalated"
    QUARANTINED = "quarantined"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    VERIFIED = "verified"
    RELEASED = "released"


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    subject_id: str
    approval_level: ApprovalLevel
    requester_thread: str
    owner_domain: OwnerDomain
    reason: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    evidence_required: tuple[str, ...] = ()
    decided_by: str | None = None
    decided_at: str | None = None

    def can_execute(self) -> bool:
        return self.status == ApprovalStatus.APPROVED


@dataclass(frozen=True)
class AuditEvent:
    id: str
    event_type: AuditEventType
    owner_domain: OwnerDomain
    subject_id: str
    summary: str
    risk_level: RiskLevel
    evidence_ids: tuple[str, ...] = ()
    occurred_at: str | None = None


def approval_from_decision(
    approval_id: str,
    subject_id: str,
    requester_thread: str,
    owner_domain: OwnerDomain,
    decision: ConflictDecision,
    evidence_required: tuple[str, ...] = (),
) -> ApprovalRequest | None:
    if decision.approval_level == ApprovalLevel.NONE:
        return None
    return ApprovalRequest(
        id=approval_id,
        subject_id=subject_id,
        approval_level=decision.approval_level,
        requester_thread=requester_thread,
        owner_domain=owner_domain,
        reason=decision.reason,
        evidence_required=evidence_required,
    )


def audit_event_from_decision(
    event_id: str,
    subject_id: str,
    owner_domain: OwnerDomain,
    risk_level: RiskLevel,
    decision: ConflictDecision,
    evidence_ids: tuple[str, ...] = (),
) -> AuditEvent:
    return AuditEvent(
        id=event_id,
        event_type=_event_type_for_decision(decision),
        owner_domain=owner_domain,
        subject_id=subject_id,
        summary=decision.reason,
        risk_level=risk_level,
        evidence_ids=evidence_ids,
    )


def _event_type_for_decision(decision: ConflictDecision) -> AuditEventType:
    return {
        "allow": AuditEventType.ALLOWED,
        "queue": AuditEventType.QUEUED,
        "block": AuditEventType.BLOCKED,
        "escalate": AuditEventType.ESCALATED,
        "quarantine": AuditEventType.QUARANTINED,
    }[decision.outcome.value]
