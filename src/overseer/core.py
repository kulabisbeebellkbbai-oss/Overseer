"""Core resource, claim, and conflict decision primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping


class OwnerDomain(StrEnum):
    SISKO = "sisko"
    KIRA = "kira"
    OBRIEN = "obrien"
    ODO = "odo"
    QUARK = "quark"
    DAX = "dax"
    JULIAN = "julian"
    EZRI = "ezri"


class ResourceType(StrEnum):
    PHYSICAL_ASSET = "physical_asset"
    VIRTUAL_ASSET = "virtual_asset"
    SERVICE = "service"
    USAGE_LIMITED_SERVICE = "usage_limited_service"
    MAINTENANCE_TARGET = "maintenance_target"
    SECURITY_SURFACE = "security_surface"
    COMPOSITE = "composite"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResourceState(StrEnum):
    AVAILABLE = "available"
    CHECKED_OUT = "checked_out"
    LOCKED = "locked"
    MAINTENANCE = "maintenance"
    DEGRADED = "degraded"
    INCIDENT = "incident"
    QUARANTINED = "quarantined"
    RETIRED = "retired"


class ClaimType(StrEnum):
    CHECKOUT = "checkout"
    LOCK = "lock"
    LEASE = "lease"
    HOLD = "hold"
    QUARANTINE = "quarantine"
    OBSERVATION = "observation"


class ClaimStatus(StrEnum):
    REQUESTED = "requested"
    APPROVED = "approved"
    ACTIVE = "active"
    BLOCKED = "blocked"
    QUEUED = "queued"
    RELEASING = "releasing"
    RELEASED = "released"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ApprovalLevel(StrEnum):
    NONE = "none"
    ROLE = "role"
    SISKO = "sisko"
    HUMAN = "human"


class ConflictOutcome(StrEnum):
    ALLOW = "allow"
    QUEUE = "queue"
    BLOCK = "block"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"


EXCLUSIVE_CLAIM_TYPES = {
    ClaimType.CHECKOUT,
    ClaimType.LOCK,
    ClaimType.LEASE,
    ClaimType.HOLD,
    ClaimType.QUARANTINE,
}

HIGH_RISK_RESOURCE_TYPES = {
    ResourceType.SECURITY_SURFACE,
    ResourceType.MAINTENANCE_TARGET,
}


@dataclass(frozen=True)
class Resource:
    id: str
    name: str
    type: ResourceType
    owner_domain: OwnerDomain
    risk_level: RiskLevel
    state: ResourceState = ResourceState.AVAILABLE
    identifiers: Mapping[str, object] = field(default_factory=dict)
    dependencies: frozenset[str] = field(default_factory=frozenset)
    exclusive_groups: frozenset[str] = field(default_factory=frozenset)
    current_claim_id: str | None = None
    last_verified_at: str | None = None
    notes: str = ""

    def ports(self) -> frozenset[int]:
        values = self.identifiers.get("ports", ())
        if isinstance(values, int):
            return frozenset({values})
        if isinstance(values, (list, tuple, set, frozenset)):
            return frozenset(int(value) for value in values)
        return frozenset()


@dataclass(frozen=True)
class Claim:
    id: str
    resource_id: str
    claim_type: ClaimType
    owner_thread: str
    owner_role: OwnerDomain
    intent: str
    requested_action: str
    risk_level: RiskLevel
    status: ClaimStatus = ClaimStatus.REQUESTED
    created_at: str | None = None
    starts_at: str | None = None
    expires_at: str | None = None
    release_condition: str | None = None
    approval_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    port_reservations: frozenset[int] = field(default_factory=frozenset)
    dependency_ids: frozenset[str] = field(default_factory=frozenset)
    exclusive_groups: frozenset[str] = field(default_factory=frozenset)
    state_mutation: str = "none"

    def is_exclusive(self) -> bool:
        return self.claim_type in EXCLUSIVE_CLAIM_TYPES

    def is_active_like(self) -> bool:
        return self.status in {
            ClaimStatus.APPROVED,
            ClaimStatus.ACTIVE,
            ClaimStatus.RELEASING,
        }


@dataclass(frozen=True)
class ConflictDecision:
    outcome: ConflictOutcome
    reason: str
    approval_level: ApprovalLevel = ApprovalLevel.NONE
    blocking_claim_ids: tuple[str, ...] = ()


def decide_claim(
    resource: Resource,
    requested: Claim,
    active_claims: list[Claim],
    resources_by_id: Mapping[str, Resource] | None = None,
) -> ConflictDecision:
    """Return the command decision for a requested claim.

    The decision is conservative: unknown or degraded resource state escalates
    or blocks when a request would mutate state.
    """

    if resource.state == ResourceState.RETIRED:
        return ConflictDecision(ConflictOutcome.BLOCK, "resource is retired")

    if resource.state == ResourceState.QUARANTINED:
        return ConflictDecision(
            ConflictOutcome.QUARANTINE,
            "resource is under security quarantine",
            ApprovalLevel.HUMAN,
        )

    if requested.resource_id != resource.id:
        return ConflictDecision(ConflictOutcome.BLOCK, "claim resource_id does not match resource")

    if requested.claim_type == ClaimType.OBSERVATION and not _has_exclusive_conflict(requested, active_claims):
        return ConflictDecision(ConflictOutcome.ALLOW, "read-only observation is compatible")

    blockers = _blocking_claims(resource, requested, active_claims, resources_by_id or {})
    if blockers:
        return ConflictDecision(
            ConflictOutcome.QUEUE,
            "resource, dependency, port, or exclusive group is already claimed",
            ApprovalLevel.NONE,
            tuple(claim.id for claim in blockers),
        )

    approval = required_approval(resource, requested)
    if approval != ApprovalLevel.NONE:
        return ConflictDecision(
            ConflictOutcome.ESCALATE,
            f"{approval.value} approval required before claim can activate",
            approval,
        )

    return ConflictDecision(ConflictOutcome.ALLOW, "claim can activate")


def required_approval(resource: Resource, claim: Claim) -> ApprovalLevel:
    if claim.claim_type == ClaimType.OBSERVATION and claim.risk_level == RiskLevel.LOW:
        return ApprovalLevel.NONE

    if resource.type in HIGH_RISK_RESOURCE_TYPES:
        return ApprovalLevel.HUMAN

    if resource.risk_level == RiskLevel.CRITICAL or claim.risk_level == RiskLevel.CRITICAL:
        return ApprovalLevel.HUMAN

    if resource.risk_level == RiskLevel.HIGH or claim.risk_level == RiskLevel.HIGH:
        return ApprovalLevel.SISKO

    if claim.claim_type in {ClaimType.CHECKOUT, ClaimType.LOCK, ClaimType.LEASE, ClaimType.HOLD}:
        return ApprovalLevel.ROLE

    return ApprovalLevel.NONE


def _has_exclusive_conflict(requested: Claim, active_claims: list[Claim]) -> bool:
    return any(_claims_overlap(requested, active) and active.is_exclusive() for active in active_claims if active.is_active_like())


def _blocking_claims(
    resource: Resource,
    requested: Claim,
    active_claims: list[Claim],
    resources_by_id: Mapping[str, Resource],
) -> list[Claim]:
    blockers: list[Claim] = []
    for active in active_claims:
        if not active.is_active_like():
            continue
        if _claims_overlap(requested, active):
            blockers.append(active)
            continue
        if requested.resource_id in active.dependency_ids or active.resource_id in requested.dependency_ids:
            blockers.append(active)
            continue
        if requested.port_reservations & active.port_reservations:
            blockers.append(active)
            continue
        if requested.exclusive_groups & active.exclusive_groups:
            blockers.append(active)
            continue
        active_resource = resources_by_id.get(active.resource_id)
        if active_resource and resource.dependencies & ({active_resource.id} | active_resource.dependencies):
            blockers.append(active)
    return blockers


def _claims_overlap(left: Claim, right: Claim) -> bool:
    return left.resource_id == right.resource_id
