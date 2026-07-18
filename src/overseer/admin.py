"""Approval-plan models for administrative host changes."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace
from enum import StrEnum

from .core import ApprovalLevel, OwnerDomain, RiskLevel


class AdminChangeKind(StrEnum):
    USER_SERVICE_RESTART = "user_service_restart"
    APT_INSTALL = "apt_install"
    FIREWALL_ALLOW_TCP = "firewall_allow_tcp"
    BLOCK_IP = "block_ip"


@dataclass(frozen=True)
class AdminCommandStep:
    title: str
    command: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class AdminChangePlan:
    id: str
    kind: AdminChangeKind
    owner_domain: OwnerDomain
    risk_level: RiskLevel
    approval_level: ApprovalLevel
    target: str
    reason: str
    current_state: str
    proposed_state: str
    steps: tuple[AdminCommandStep, ...]
    rollback_steps: tuple[AdminCommandStep, ...]
    risks: tuple[str, ...]
    verification_steps: tuple[AdminCommandStep, ...]
    approved: bool = False
    approved_by: str | None = None
    approved_at: str | None = None
    canceled: bool = False
    canceled_by: str | None = None
    canceled_at: str | None = None
    cancellation_reason: str | None = None

    def requires_explicit_approval(self) -> bool:
        return not self.canceled and (self.approval_level != ApprovalLevel.NONE or self.risk_level != RiskLevel.LOW)

    def can_execute(self) -> bool:
        return not self.canceled and self.approved and not missing_admin_change_fields(self)


def plan_user_service_restart(plan_id: str, service_name: str, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.USER_SERVICE_RESTART,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.MEDIUM,
        approval_level=ApprovalLevel.SISKO,
        target=service_name,
        reason=reason,
        current_state=current_state,
        proposed_state=f"restart user service {service_name} and verify it is active",
        steps=(
            AdminCommandStep(
                "Restart user service",
                ("systemctl", "--user", "restart", service_name),
                "apply the approved service change",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Stop service after failed restart",
                ("systemctl", "--user", "stop", service_name),
                "return the service to a non-running state if restart creates harm",
            ),
        ),
        risks=("temporary service interruption", "dependent local threads may fail while the service restarts"),
        verification_steps=(
            AdminCommandStep(
                "Verify user service status",
                ("systemctl", "--user", "status", service_name, "--no-pager"),
                "confirm the service reached the expected active state",
            ),
        ),
    )


def plan_apt_install(plan_id: str, packages: tuple[str, ...], reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if not packages:
        raise ValueError("at least one package is required")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.APT_INSTALL,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=" ".join(packages),
        reason=reason,
        current_state=current_state,
        proposed_state=f"install apt packages: {' '.join(packages)}",
        steps=(
            AdminCommandStep(
                "Simulate package install",
                ("sudo", "apt-get", "install", "--dry-run", *packages),
                "preview package changes before live install",
            ),
            AdminCommandStep(
                "Install packages",
                ("sudo", "apt-get", "install", "-y", *packages),
                "apply the approved package installation",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Remove installed packages",
                ("sudo", "apt-get", "remove", "-y", *packages),
                "undo package installation if verification fails",
            ),
        ),
        risks=("sudo privilege use", "package dependency changes", "service behavior may change after install"),
        verification_steps=(
            AdminCommandStep(
                "Verify package installation",
                ("dpkg-query", "-W", *packages),
                "confirm packages are installed and queryable",
            ),
        ),
    )


def plan_firewall_allow_tcp(plan_id: str, port: int, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if port < 1 or port > 65535:
        raise ValueError("port must be between 1 and 65535")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.FIREWALL_ALLOW_TCP,
        owner_domain=OwnerDomain.ODO,
        risk_level=RiskLevel.CRITICAL,
        approval_level=ApprovalLevel.HUMAN,
        target=f"tcp/{port}",
        reason=reason,
        current_state=current_state,
        proposed_state=f"allow inbound TCP traffic on port {port}",
        steps=(
            AdminCommandStep(
                "Allow TCP port",
                ("sudo", "ufw", "allow", f"{port}/tcp"),
                "open the approved inbound service port",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Deny TCP port",
                ("sudo", "ufw", "delete", "allow", f"{port}/tcp"),
                "remove the inbound firewall exception",
            ),
        ),
        risks=("external service exposure", "increased attack surface", "incorrect rule scope may expose more than intended"),
        verification_steps=(
            AdminCommandStep(
                "Verify firewall status",
                ("sudo", "ufw", "status", "verbose"),
                "confirm the firewall rule exists only as approved",
            ),
        ),
    )


def plan_block_ip(plan_id: str, address: str, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if not address.strip():
        raise ValueError("address is required")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.BLOCK_IP,
        owner_domain=OwnerDomain.ODO,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=address,
        reason=reason,
        current_state=current_state,
        proposed_state=f"block traffic from {address}",
        steps=(
            AdminCommandStep(
                "Block source address",
                ("sudo", "ufw", "deny", "from", address),
                "apply the approved protective block",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Remove source block",
                ("sudo", "ufw", "delete", "deny", "from", address),
                "remove the protective block if it disrupts legitimate work",
            ),
        ),
        risks=("legitimate traffic may be blocked", "firewall policy changes require audit review"),
        verification_steps=(
            AdminCommandStep(
                "Verify firewall status",
                ("sudo", "ufw", "status", "verbose"),
                "confirm the source block exists only as approved",
            ),
        ),
    )


def missing_admin_change_fields(plan: AdminChangePlan) -> tuple[str, ...]:
    missing = []
    if not plan.current_state.strip():
        missing.append("current_state")
    if not plan.proposed_state.strip():
        missing.append("proposed_state")
    if not plan.reason.strip():
        missing.append("reason")
    if not plan.steps:
        missing.append("steps")
    if not plan.rollback_steps:
        missing.append("rollback_steps")
    if not plan.risks:
        missing.append("risks")
    if not plan.verification_steps:
        missing.append("verification_steps")
    return tuple(missing)


def approve_admin_change_plan(plan: AdminChangePlan, approved_by: str, approved_at: str | None = None) -> AdminChangePlan:
    if plan.canceled:
        raise ValueError("cannot approve canceled admin change plan")
    if missing_admin_change_fields(plan):
        raise ValueError("cannot approve incomplete admin change plan")
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    return replace(plan, approved=True, approved_by=approved_by, approved_at=approved_at)


def cancel_admin_change_plan(
    plan: AdminChangePlan,
    canceled_by: str,
    cancellation_reason: str,
    canceled_at: str | None = None,
) -> AdminChangePlan:
    if not canceled_by.strip():
        raise ValueError("canceled_by is required")
    if not cancellation_reason.strip():
        raise ValueError("cancellation_reason is required")
    return replace(
        plan,
        canceled=True,
        canceled_by=canceled_by,
        canceled_at=canceled_at,
        cancellation_reason=cancellation_reason,
        approved=False,
        approved_by=None,
        approved_at=None,
    )


def authorization_required_status(plan: AdminChangePlan) -> dict[str, object]:
    return {
        "id": plan.id,
        "kind": AdminChangeKind(plan.kind).value,
        "target": plan.target,
        "owner_domain": OwnerDomain(plan.owner_domain).value,
        "risk_level": RiskLevel(plan.risk_level).value,
        "approval_level": ApprovalLevel(plan.approval_level).value,
        "approved": plan.approved,
        "canceled": plan.canceled,
        "can_execute": plan.can_execute(),
        "reason": plan.reason,
        "authorization_required": plan.requires_explicit_approval() and not plan.approved,
        "next_step": _authorization_next_step(plan),
    }


def _authorization_next_step(plan: AdminChangePlan) -> str:
    if plan.canceled:
        return "canceled; no authorization or execution is required"
    if plan.approved:
        return "approved; execution still requires a live adapter and verification boundary"
    if plan.approval_level == ApprovalLevel.HUMAN:
        return "human approval required for exact command list, risks, rollback, and verification"
    if plan.approval_level == ApprovalLevel.SISKO:
        return "Sisko approval required for exact command list, risks, rollback, and verification"
    if plan.approval_level == ApprovalLevel.ROLE:
        return f"{OwnerDomain(plan.owner_domain).value} role approval required"
    return "no explicit approval required"
