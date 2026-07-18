"""Application service that coordinates registry, persistence, and audit."""

from __future__ import annotations

from dataclasses import dataclass

from .audit import ApprovalRequest, AuditEvent, approval_from_decision, audit_event_from_decision
from .core import Claim, ClaimStatus, Resource
from .registry import ClaimRecord, ResourceRegistry
from .store import SQLiteStore


@dataclass(frozen=True)
class CoordinationResult:
    record: ClaimRecord
    approval: ApprovalRequest | None
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
        return record

    def release_claim(self, claim_id: str) -> Claim:
        released = self.registry.release_claim(claim_id)
        if self.store is not None:
            self.store.save_claim(released)
        return released

    def _persist_result(
        self,
        record: ClaimRecord,
        approval: ApprovalRequest | None,
        event: AuditEvent,
    ) -> None:
        if self.store is None:
            return
        self.store.save_claim(record.claim, record.decision)
        if approval is not None:
            self.store.save_approval(approval)
        self.store.save_audit_event(event)


def needs_operator_approval(result: CoordinationResult) -> bool:
    return result.approval is not None and result.record.claim.status == ClaimStatus.REQUESTED
