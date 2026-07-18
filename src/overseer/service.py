"""Application service that coordinates registry, persistence, and audit."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .audit import ApprovalRequest, ApprovalStatus, AuditEvent, AuditEventType, approval_from_decision, audit_event_from_decision
from .core import ApprovalLevel, Claim, ClaimStatus, Resource, RiskLevel
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
        current = self.store.load_approval(approval_id)
        approved = replace(
            current,
            status=ApprovalStatus.APPROVED,
            decided_by=decided_by,
            decided_at=decided_at,
        )
        risk_level = RiskLevel.LOW
        try:
            risk_level = self.store.load_claim(approved.subject_id).risk_level
        except KeyError:
            pass
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
        return ApprovalDecisionResult(approved, event)

    def _persist_result(
        self,
        record: ClaimRecord,
        approval: ApprovalRequest | None,
        event: AuditEvent,
    ) -> None:
        if self.store is None:
            return
        self.store.save_claim(record.claim, record.decision)
        self.store.save_resource(self.registry.get_resource(record.claim.resource_id))
        if approval is not None:
            self.store.save_approval(approval)
        self.store.save_audit_event(event)


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
