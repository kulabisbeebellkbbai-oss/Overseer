"""Maintenance scheduling, rollback, and verification helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .core import ApprovalLevel, OwnerDomain, RiskLevel


class MaintenanceKind(StrEnum):
    INSTALL = "install"
    UPDATE = "update"
    PATCH = "patch"
    RESTART = "restart"
    BACKUP = "backup"
    CLEANUP = "cleanup"
    MIGRATION = "migration"
    AUDIT = "audit"
    REPAIR = "repair"


class InterruptionPolicy(StrEnum):
    NO_INTERRUPTION = "no_interruption"
    RESTART_ALLOWED = "restart_allowed"
    DOWNTIME_ALLOWED = "downtime_allowed"
    EXCLUSIVE_WINDOW_REQUIRED = "exclusive_window_required"


class MaintenanceStatus(StrEnum):
    PLANNED = "planned"
    READY = "ready"
    BLOCKED = "blocked"
    IN_PROGRESS = "in_progress"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass(frozen=True)
class MaintenanceWindow:
    id: str
    starts_at: str
    ends_at: str
    owner_domain: OwnerDomain = OwnerDomain.OBRIEN
    exclusive: bool = True
    reason: str = ""


@dataclass(frozen=True)
class MaintenancePlan:
    id: str
    resource_id: str
    kind: MaintenanceKind
    requested_state: str
    risk_level: RiskLevel
    window: MaintenanceWindow
    interruption_policy: InterruptionPolicy
    affected_resource_ids: frozenset[str] = field(default_factory=frozenset)
    dependency_ids: frozenset[str] = field(default_factory=frozenset)
    precheck_ids: tuple[str, ...] = ()
    verification_ids: tuple[str, ...] = ()
    rollback_plan: str = ""
    status: MaintenanceStatus = MaintenanceStatus.PLANNED

    def all_resource_ids(self) -> frozenset[str]:
        return frozenset({self.resource_id}) | self.affected_resource_ids | self.dependency_ids

    def requires_rollback_plan(self) -> bool:
        return self.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}

    def has_required_rollback_plan(self) -> bool:
        return not self.requires_rollback_plan() or bool(self.rollback_plan.strip())

    def required_approval(self) -> ApprovalLevel:
        if self.risk_level == RiskLevel.CRITICAL:
            return ApprovalLevel.HUMAN
        if self.risk_level == RiskLevel.HIGH:
            return ApprovalLevel.SISKO
        if self.interruption_policy == InterruptionPolicy.EXCLUSIVE_WINDOW_REQUIRED:
            return ApprovalLevel.ROLE
        return ApprovalLevel.NONE


@dataclass(frozen=True)
class MaintenanceReadiness:
    ready: bool
    status: MaintenanceStatus
    reason: str
    approval_level: ApprovalLevel = ApprovalLevel.NONE
    missing_evidence: tuple[str, ...] = ()


def assess_maintenance_readiness(plan: MaintenancePlan) -> MaintenanceReadiness:
    if not plan.window.starts_at or not plan.window.ends_at:
        return MaintenanceReadiness(False, MaintenanceStatus.BLOCKED, "maintenance window is incomplete")

    if not plan.has_required_rollback_plan():
        return MaintenanceReadiness(
            False,
            MaintenanceStatus.BLOCKED,
            "rollback plan is required for medium or higher risk maintenance",
            plan.required_approval(),
            ("rollback_plan",),
        )

    if not plan.precheck_ids:
        return MaintenanceReadiness(
            False,
            MaintenanceStatus.BLOCKED,
            "pre-change verification evidence is required",
            plan.required_approval(),
            ("precheck_ids",),
        )

    approval = plan.required_approval()
    if approval != ApprovalLevel.NONE:
        return MaintenanceReadiness(True, MaintenanceStatus.READY, "approval required before execution", approval)

    return MaintenanceReadiness(True, MaintenanceStatus.READY, "maintenance plan is ready")


def can_close_maintenance(plan: MaintenancePlan) -> MaintenanceReadiness:
    if plan.status == MaintenanceStatus.ROLLED_BACK:
        return MaintenanceReadiness(True, MaintenanceStatus.ROLLED_BACK, "rollback completed")

    if not plan.verification_ids:
        return MaintenanceReadiness(
            False,
            MaintenanceStatus.VERIFYING,
            "post-change verification evidence is required before closure",
            plan.required_approval(),
            ("verification_ids",),
        )

    return MaintenanceReadiness(True, MaintenanceStatus.COMPLETED, "maintenance verified")
