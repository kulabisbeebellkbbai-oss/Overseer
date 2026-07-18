"""Security signal classification and protective action gating."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import ApprovalLevel, OwnerDomain, ResourceType, RiskLevel


class SecuritySignalType(StrEnum):
    INFO = "info"
    SUSPICIOUS = "suspicious"
    INTRUSION_LIKELY = "intrusion_likely"
    CONFIRMED_INCIDENT = "confirmed_incident"
    POLICY_VIOLATION = "policy_violation"
    VULNERABILITY = "vulnerability"


class ProtectiveAction(StrEnum):
    MONITOR = "monitor"
    AUDIT = "audit"
    ISOLATE = "isolate"
    QUARANTINE = "quarantine"
    ROTATE_CREDENTIAL = "rotate_credential"
    BLOCK_TRAFFIC = "block_traffic"
    STOP_SERVICE = "stop_service"
    PATCH = "patch"
    RESTORE = "restore"
    ESCALATE = "escalate"


class SecurityStatus(StrEnum):
    OBSERVED = "observed"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    RESPONDING = "responding"
    CONTAINED = "contained"
    CLOSED = "closed"


ACTIVE_DEFENSE_ACTIONS = {
    ProtectiveAction.ISOLATE,
    ProtectiveAction.QUARANTINE,
    ProtectiveAction.ROTATE_CREDENTIAL,
    ProtectiveAction.BLOCK_TRAFFIC,
    ProtectiveAction.STOP_SERVICE,
    ProtectiveAction.PATCH,
    ProtectiveAction.RESTORE,
}


@dataclass(frozen=True)
class SecuritySignal:
    id: str
    resource_id: str
    resource_type: ResourceType
    signal_type: SecuritySignalType
    severity: RiskLevel
    confidence: float
    source: str
    indicator: str
    observed_at: str | None = None


@dataclass(frozen=True)
class SecurityResponse:
    action: ProtectiveAction
    owner_domain: OwnerDomain
    approval_level: ApprovalLevel
    active_defense: bool
    reason: str


@dataclass(frozen=True)
class SecurityIncident:
    id: str
    signal_id: str
    resource_id: str
    status: SecurityStatus
    response: SecurityResponse
    evidence_ids: tuple[str, ...] = ()
    closure_note: str = ""

    def can_close(self) -> bool:
        return self.status == SecurityStatus.CONTAINED and bool(self.evidence_ids and self.closure_note.strip())


def recommend_security_response(signal: SecuritySignal) -> SecurityResponse:
    if signal.confidence < 0 or signal.confidence > 1:
        return SecurityResponse(
            ProtectiveAction.ESCALATE,
            OwnerDomain.ODO,
            ApprovalLevel.SISKO,
            False,
            "signal confidence must be between 0 and 1",
        )

    if signal.signal_type == SecuritySignalType.INFO and signal.severity == RiskLevel.LOW:
        return SecurityResponse(
            ProtectiveAction.MONITOR,
            OwnerDomain.ODO,
            ApprovalLevel.NONE,
            False,
            "low-risk informational signal",
        )

    if signal.signal_type == SecuritySignalType.VULNERABILITY:
        return SecurityResponse(
            ProtectiveAction.PATCH,
            OwnerDomain.OBRIEN,
            _approval_for_signal(signal, ProtectiveAction.PATCH),
            True,
            "vulnerability requires maintenance remediation",
        )

    if signal.resource_type == ResourceType.SECURITY_SURFACE:
        return SecurityResponse(
            ProtectiveAction.ESCALATE,
            OwnerDomain.ODO,
            ApprovalLevel.HUMAN,
            False,
            "security-surface mutation needs explicit human approval",
        )

    if signal.signal_type in {SecuritySignalType.CONFIRMED_INCIDENT, SecuritySignalType.INTRUSION_LIKELY}:
        action = ProtectiveAction.QUARANTINE if signal.severity in {RiskLevel.HIGH, RiskLevel.CRITICAL} else ProtectiveAction.ISOLATE
        return SecurityResponse(
            action,
            _owner_for_resource_type(signal.resource_type),
            _approval_for_signal(signal, action),
            True,
            "incident response requires containment",
        )

    if signal.signal_type in {SecuritySignalType.SUSPICIOUS, SecuritySignalType.POLICY_VIOLATION}:
        return SecurityResponse(
            ProtectiveAction.AUDIT,
            OwnerDomain.ODO,
            ApprovalLevel.NONE,
            False,
            "signal requires audit before active defense",
        )

    return SecurityResponse(
        ProtectiveAction.ESCALATE,
        OwnerDomain.SISKO,
        ApprovalLevel.SISKO,
        False,
        "unclassified security signal",
    )


def _approval_for_signal(signal: SecuritySignal, action: ProtectiveAction) -> ApprovalLevel:
    if signal.severity == RiskLevel.CRITICAL:
        return ApprovalLevel.HUMAN
    if signal.severity == RiskLevel.HIGH or action in ACTIVE_DEFENSE_ACTIONS:
        return ApprovalLevel.SISKO
    return ApprovalLevel.NONE


def _owner_for_resource_type(resource_type: ResourceType) -> OwnerDomain:
    if resource_type == ResourceType.PHYSICAL_ASSET:
        return OwnerDomain.KIRA
    if resource_type == ResourceType.VIRTUAL_ASSET:
        return OwnerDomain.DAX
    if resource_type in {ResourceType.SERVICE, ResourceType.USAGE_LIMITED_SERVICE}:
        return OwnerDomain.JULIAN
    if resource_type == ResourceType.MAINTENANCE_TARGET:
        return OwnerDomain.OBRIEN
    return OwnerDomain.ODO
