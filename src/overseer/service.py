"""Application service that coordinates registry, persistence, and audit."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .audit import ApprovalRequest, ApprovalStatus, AuditEvent, AuditEventType, approval_from_decision, audit_event_from_decision
from .claim_continuation import continuation_for_claim
from .core import ApprovalLevel, Claim, ClaimStatus, OwnerDomain, Resource, RiskLevel, required_approval
from .crew import CrewMessage, build_crew_message
from .registry import ClaimRecord, ResourceRegistry
from .store import SQLiteStore


@dataclass(frozen=True)
class CoordinationResult:
    record: ClaimRecord
    approval: ApprovalRequest | None
    audit_event: AuditEvent


@dataclass(frozen=True)
class ApprovalDecisionResult:
    approval: ApprovalRequest
    audit_event: AuditEvent


class OverseerCoordinator:
    def __init__(self, registry: ResourceRegistry | None = None, store: SQLiteStore | None = None) -> None:
        self.registry = registry or ResourceRegistry()
        self.store = store

    def register_resource(self, resource: Resource) -> Resource:
        stored = self.registry.register_resource(resource)
        if self.store is not None:
            self.store.save_resource(stored)
        return stored

    def request_claim(self, claim: Claim) -> CoordinationResult:
        resource = self.registry.get_resource(claim.resource_id)
        if required_approval(resource, claim) == ApprovalLevel.ROLE:
            if not claim.activation_group_id or not claim.lifecycle_id:
                raise ValueError(
                    "ROLE-gated claim requires explicit lifecycle_id and activation_group_id"
                )
        record = self.registry.request_claim(claim)
        approval = approval_from_decision(
            f"approval.{claim.id}",
            record.claim.id,
            record.claim.owner_thread,
            record.claim.owner_role,
            record.decision,
        )
        event = audit_event_from_decision(
            f"audit.{claim.id}.{record.decision.outcome.value}",
            record.claim.id,
            record.claim.owner_role,
            record.claim.risk_level,
            record.decision,
            record.decision.blocking_claim_ids,
        )
        self._persist_result(record, approval, event)
        return CoordinationResult(record, approval, event)

    def activate_claim(self, claim_id: str, approval_id: str | None = None) -> ClaimRecord:
        record = self.registry.activate_claim(claim_id, approval_id)
        if self.store is not None:
            self.store.save_claim(record.claim, record.decision)
            self.store.save_resource(self.registry.get_resource(record.claim.resource_id))
        return record

    def release_claim(self, claim_id: str) -> Claim:
        released = self.registry.release_claim(claim_id)
        if self.store is not None:
            self.store.save_claim(released)
            self.store.save_resource(self.registry.get_resource(released.resource_id))
        return released

    def approve_request(
        self,
        approval_id: str,
        decided_by: str,
        decided_at: str | None = None,
    ) -> ApprovalDecisionResult:
        if self.store is None:
            raise ValueError("approval decisions require a store")
        with self.store.agent_transaction():
            current = self.store.load_approval(approval_id)
            if current.status == ApprovalStatus.APPROVED:
                if current.decided_by != decided_by or current.decided_at != decided_at:
                    raise ValueError("approved decision is immutable and exact retry metadata differs")
                approved = current
            elif current.status != ApprovalStatus.PENDING:
                raise ValueError("approval decision is no longer pending")
            else:
                approved = replace(
                    current,
                    status=ApprovalStatus.APPROVED,
                    decided_by=decided_by,
                    decided_at=decided_at,
                )
            risk_level = RiskLevel.LOW
            claim = None
            try:
                claim = self.store.load_claim(approved.subject_id)
                risk_level = claim.risk_level
            except KeyError:
                if approved.approval_level == ApprovalLevel.ROLE:
                    raise ValueError("ROLE approval requires its exact claim record") from None
            approval_level = ApprovalLevel(approved.approval_level)
            event = AuditEvent(
                id=f"audit.{approval_id}.approved",
                event_type=AuditEventType.APPROVED,
                owner_domain=approved.owner_domain,
                subject_id=approved.subject_id,
                summary=f"{approval_level.value} approval granted",
                risk_level=risk_level,
                evidence_ids=(approval_id,),
            )
            self.store.save_approval(approved)
            self.store.save_audit_event(event)
            if approved.approval_level == ApprovalLevel.ROLE and approved.status == ApprovalStatus.APPROVED:
                if claim is None or claim.status != ClaimStatus.REQUESTED:
                    raise ValueError("ROLE approval requires the still-requested claim")
                continuation = continuation_for_claim(claim, approved.id)
                self.store.save_claim_approval_continuation(continuation)
                self.store.save_audit_event(
                    AuditEvent(
                        id=f"audit.{continuation.id}.created",
                        event_type=AuditEventType.REQUESTED,
                        owner_domain=continuation.owner_role,
                        subject_id=continuation.id,
                        summary="exact-owner claim approval continuation persisted; activation remains separate",
                        risk_level=claim.risk_level,
                        evidence_ids=(approved.id, claim.id),
                        occurred_at=approved.decided_at,
                    )
                )
        return ApprovalDecisionResult(approved, event)

    def _persist_result(
        self,
        record: ClaimRecord,
        approval: ApprovalRequest | None,
        event: AuditEvent,
    ) -> None:
        if self.store is None:
            return
        with self.store.agent_transaction():
            self.store.save_claim(record.claim, record.decision)
            self.store.save_resource(self.registry.get_resource(record.claim.resource_id))
            if approval is not None:
                self.store.save_approval(approval)
            self.store.save_audit_event(event)
            handoff = role_approval_handoff(record.claim, approval)
            if handoff is not None:
                self.store.save_crew_message(handoff)
                self.store.save_audit_event(
                    AuditEvent(
                        id=f"audit.{handoff.id}",
                        event_type=AuditEventType.REQUESTED,
                        owner_domain=handoff.owner_domain,
                        subject_id=handoff.id,
                        summary=f"{handoff.subject} routed to {handoff.owner_domain.value}",
                        risk_level=handoff.priority,
                        occurred_at=handoff.created_at,
                    )
                )


def role_approval_handoff(claim: Claim, approval: ApprovalRequest | None) -> CrewMessage | None:
    """Build the single deterministic owner-role message for a ROLE approval."""
    if approval is None or approval.approval_level != ApprovalLevel.ROLE:
        return None
    return build_crew_message(
        owner_domain=claim.owner_role.value,
        subject=f"Approve claim {claim.id}",
        message=(
            f"Review and approve the exact pending ROLE approval {approval.id} for claim {claim.id} "
            f"on resource {claim.resource_id}. Activation remains a separate step."
        ),
        priority=claim.risk_level.value,
        requested_by=claim.owner_thread,
        message_id=f"crew.{claim.owner_role.value}.approval.{claim.id}",
        related_resource_id=claim.resource_id,
        related_claim_id=claim.id,
        related_approval_id=approval.id,
    )


def coordinator_from_store(store: SQLiteStore) -> OverseerCoordinator:
    registry = ResourceRegistry()
    for resource in store.list_resources():
        registry.register_resource(resource)
    for claim in store.list_claims():
        try:
            decision = store.load_decision(claim.id)
        except KeyError:
            continue
        registry.restore_claim(claim, decision)
    return OverseerCoordinator(registry=registry, store=store)


def needs_operator_approval(result: CoordinationResult) -> bool:
    return result.approval is not None and result.record.claim.status == ClaimStatus.REQUESTED
