"""Policy evaluation for approval-gated Overseer actions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .admin import AdminChangeKind, AdminChangePlan, AdminExecutionCapability, missing_admin_change_fields
from .core import ApprovalLevel, OwnerDomain, RiskLevel
from .ids_review import HostSecurityIDSReviewPackage, admin_plan_requires_ids_review


class PolicyCheckStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class PolicyCheck:
    id: str
    status: PolicyCheckStatus
    owner_domain: OwnerDomain
    summary: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    subject_id: str
    subject_kind: str
    status: PolicyCheckStatus
    checks: tuple[PolicyCheck, ...]

    def can_proceed(self) -> bool:
        return self.status == PolicyCheckStatus.PASS


def evaluate_admin_change_policy(
    plan: AdminChangePlan,
    capability: AdminExecutionCapability,
    ids_review_packages: tuple[HostSecurityIDSReviewPackage, ...] = (),
) -> PolicyDecision:
    checks = (
        _plan_state_check(plan),
        _plan_completeness_check(plan),
        _approval_check(plan),
        _adapter_check(plan, capability),
        _ids_review_check(plan, ids_review_packages),
        _rollback_check(plan),
        _verification_check(plan),
        _risk_approval_check(plan),
    )
    return PolicyDecision(
        subject_id=plan.id,
        subject_kind=AdminChangeKind(plan.kind).value,
        status=_overall_status(checks),
        checks=checks,
    )


def _overall_status(checks: tuple[PolicyCheck, ...]) -> PolicyCheckStatus:
    if any(check.status == PolicyCheckStatus.BLOCK for check in checks):
        return PolicyCheckStatus.BLOCK
    if any(check.status == PolicyCheckStatus.WARN for check in checks):
        return PolicyCheckStatus.WARN
    return PolicyCheckStatus.PASS


def _plan_state_check(plan: AdminChangePlan) -> PolicyCheck:
    if plan.archived:
        return PolicyCheck(
            "admin.plan.state",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            "archived admin plans cannot execute",
            (plan.archive_record_id,) if plan.archive_record_id else (),
        )
    if plan.canceled:
        return PolicyCheck(
            "admin.plan.state",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            "canceled admin plans cannot execute",
        )
    return PolicyCheck("admin.plan.state", PolicyCheckStatus.PASS, plan.owner_domain, "admin plan is active")


def _plan_completeness_check(plan: AdminChangePlan) -> PolicyCheck:
    missing = missing_admin_change_fields(plan)
    if missing:
        return PolicyCheck(
            "admin.plan.completeness",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            f"admin plan is missing required fields: {', '.join(missing)}",
        )
    return PolicyCheck(
        "admin.plan.completeness",
        PolicyCheckStatus.PASS,
        plan.owner_domain,
        "admin plan includes commands, risks, rollback, and verification",
    )


def _approval_check(plan: AdminChangePlan) -> PolicyCheck:
    if plan.requires_explicit_approval() and not plan.approved:
        return PolicyCheck(
            "admin.plan.approval",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            f"{ApprovalLevel(plan.approval_level).value} approval is required before execution",
        )
    if plan.approved:
        return PolicyCheck(
            "admin.plan.approval",
            PolicyCheckStatus.PASS,
            plan.owner_domain,
            f"admin plan approved by {plan.approved_by or 'unknown approver'}",
        )
    return PolicyCheck("admin.plan.approval", PolicyCheckStatus.PASS, plan.owner_domain, "no explicit approval required")


def _adapter_check(plan: AdminChangePlan, capability: AdminExecutionCapability) -> PolicyCheck:
    if not capability.can_execute_live():
        return PolicyCheck(
            "admin.adapter.enabled",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            f"live adapter is {capability.status.value}: {capability.summary}",
        )
    return PolicyCheck(
        "admin.adapter.enabled",
        PolicyCheckStatus.PASS,
        plan.owner_domain,
        f"live adapter is enabled: {capability.adapter_name}",
    )


def _ids_review_check(
    plan: AdminChangePlan,
    ids_review_packages: tuple[HostSecurityIDSReviewPackage, ...],
) -> PolicyCheck:
    if not admin_plan_requires_ids_review(plan):
        return PolicyCheck("admin.ids.review", PolicyCheckStatus.PASS, OwnerDomain.ODO, "IDS review is not required")
    accepted = tuple(package for package in ids_review_packages if package.satisfies_pre_execution_review_gate())
    if not accepted:
        return PolicyCheck(
            "admin.ids.review",
            PolicyCheckStatus.BLOCK,
            OwnerDomain.ODO,
            "accepted IDS/firewall advisory is required before approval or execution",
            tuple(package.id for package in ids_review_packages),
        )
    return PolicyCheck(
        "admin.ids.review",
        PolicyCheckStatus.PASS,
        OwnerDomain.ODO,
        "accepted IDS/firewall advisory is present",
        tuple(package.id for package in accepted),
    )


def _rollback_check(plan: AdminChangePlan) -> PolicyCheck:
    if not plan.rollback_steps:
        return PolicyCheck("admin.rollback", PolicyCheckStatus.BLOCK, plan.owner_domain, "rollback steps are required")
    if AdminChangeKind(plan.kind) == AdminChangeKind.APT_UPGRADE:
        return PolicyCheck(
            "admin.rollback",
            PolicyCheckStatus.WARN,
            plan.owner_domain,
            "apt upgrades may require operator-selected rollback because package downgrades are not always available",
        )
    return PolicyCheck("admin.rollback", PolicyCheckStatus.PASS, plan.owner_domain, "rollback steps are recorded")


def _verification_check(plan: AdminChangePlan) -> PolicyCheck:
    if not plan.verification_steps:
        return PolicyCheck("admin.verification", PolicyCheckStatus.BLOCK, plan.owner_domain, "verification steps are required")
    return PolicyCheck("admin.verification", PolicyCheckStatus.PASS, OwnerDomain.JULIAN, "verification steps are recorded")


def _risk_approval_check(plan: AdminChangePlan) -> PolicyCheck:
    risk_level = RiskLevel(plan.risk_level)
    approval_level = ApprovalLevel(plan.approval_level)
    if risk_level == RiskLevel.CRITICAL and approval_level != ApprovalLevel.HUMAN:
        return PolicyCheck(
            "admin.risk.approval-level",
            PolicyCheckStatus.BLOCK,
            OwnerDomain.SISKO,
            "critical admin changes require human approval",
        )
    if risk_level == RiskLevel.HIGH and approval_level in {ApprovalLevel.NONE, ApprovalLevel.ROLE}:
        return PolicyCheck(
            "admin.risk.approval-level",
            PolicyCheckStatus.BLOCK,
            OwnerDomain.SISKO,
            "high-risk admin changes require Sisko or human approval",
        )
    return PolicyCheck(
        "admin.risk.approval-level",
        PolicyCheckStatus.PASS,
        OwnerDomain.SISKO,
        "risk level and approval level are compatible",
    )
