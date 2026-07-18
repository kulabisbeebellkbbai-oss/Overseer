"""In-memory resource registry for early local coordination."""

from __future__ import annotations

from dataclasses import dataclass, replace

from .core import Claim, ClaimStatus, ConflictDecision, ConflictOutcome, Resource, decide_claim


@dataclass(frozen=True)
class ClaimRecord:
    claim: Claim
    decision: ConflictDecision


class ResourceRegistry:
    """Process-local resource and claim registry.

    This is deliberately small: it exercises the command model without choosing
    durable storage or a service runtime too early.
    """

    def __init__(self) -> None:
        self._resources: dict[str, Resource] = {}
        self._claims: dict[str, Claim] = {}
        self._decisions: dict[str, ConflictDecision] = {}

    def register_resource(self, resource: Resource) -> Resource:
        if resource.id in self._resources:
            raise ValueError(f"resource already registered: {resource.id}")
        self._resources[resource.id] = resource
        return resource

    def get_resource(self, resource_id: str) -> Resource:
        return self._resources[resource_id]

    def list_resources(self) -> tuple[Resource, ...]:
        return tuple(self._resources.values())

    def restore_claim(self, claim: Claim, decision: ConflictDecision) -> ClaimRecord:
        if claim.resource_id not in self._resources:
            raise KeyError(claim.resource_id)
        self._claims[claim.id] = claim
        self._decisions[claim.id] = decision
        return ClaimRecord(claim, decision)

    def request_claim(self, claim: Claim) -> ClaimRecord:
        resource = self.get_resource(claim.resource_id)
        decision = decide_claim(resource, claim, self.active_claims(), self._resources)
        stored = self._claim_with_status(claim, decision)
        self._claims[stored.id] = stored
        self._decisions[stored.id] = decision
        if stored.status == ClaimStatus.ACTIVE and stored.is_exclusive():
            self._resources[resource.id] = replace(resource, current_claim_id=stored.id)
        return ClaimRecord(stored, decision)

    def release_claim(self, claim_id: str) -> Claim:
        claim = self._claims[claim_id]
        released = replace(claim, status=ClaimStatus.RELEASED)
        self._claims[claim_id] = released
        resource = self._resources.get(claim.resource_id)
        if resource and resource.current_claim_id == claim_id:
            self._resources[resource.id] = replace(resource, current_claim_id=None)
        return released

    def activate_claim(self, claim_id: str, approval_id: str | None = None) -> ClaimRecord:
        claim = self._claims[claim_id]
        resource = self.get_resource(claim.resource_id)
        decision = decide_claim(
            resource,
            claim,
            [active for active in self.active_claims() if active.id != claim_id],
            self._resources,
        )
        if decision.outcome == ConflictOutcome.QUEUE:
            queued = replace(claim, status=ClaimStatus.QUEUED, approval_id=approval_id or claim.approval_id)
            self._claims[claim_id] = queued
            self._decisions[claim_id] = decision
            return ClaimRecord(queued, decision)
        if decision.outcome in {ConflictOutcome.BLOCK, ConflictOutcome.QUARANTINE}:
            blocked = replace(claim, status=ClaimStatus.BLOCKED, approval_id=approval_id or claim.approval_id)
            self._claims[claim_id] = blocked
            self._decisions[claim_id] = decision
            return ClaimRecord(blocked, decision)

        active = replace(claim, status=ClaimStatus.ACTIVE, approval_id=approval_id or claim.approval_id)
        self._claims[claim_id] = active
        if active.is_exclusive():
            self._resources[resource.id] = replace(resource, current_claim_id=active.id)
        return ClaimRecord(active, decision)

    def active_claims(self) -> list[Claim]:
        return [claim for claim in self._claims.values() if claim.is_active_like()]

    def queued_claims(self) -> tuple[Claim, ...]:
        return tuple(claim for claim in self._claims.values() if claim.status == ClaimStatus.QUEUED)

    def decisions(self) -> tuple[ClaimRecord, ...]:
        return tuple(ClaimRecord(claim, self._decisions[claim_id]) for claim_id, claim in self._claims.items())

    @staticmethod
    def _claim_with_status(claim: Claim, decision: ConflictDecision) -> Claim:
        if decision.outcome == ConflictOutcome.ALLOW:
            return replace(claim, status=ClaimStatus.ACTIVE)
        if decision.outcome == ConflictOutcome.QUEUE:
            return replace(claim, status=ClaimStatus.QUEUED)
        if decision.outcome in {ConflictOutcome.BLOCK, ConflictOutcome.QUARANTINE}:
            return replace(claim, status=ClaimStatus.BLOCKED)
        return replace(claim, status=ClaimStatus.REQUESTED)
