"""Approval-plan models for administrative host changes."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from dataclasses import replace
from enum import StrEnum

from .audit import AuditEvent, AuditEventType
from .core import ApprovalLevel, OwnerDomain, RiskLevel


class AdminChangeKind(StrEnum):
    USER_SERVICE_RESTART = "user_service_restart"
    APT_INSTALL = "apt_install"
    APT_UPDATE = "apt_update"
    APT_UPGRADE = "apt_upgrade"
    FLATPAK_INSTALL = "flatpak_install"
    NPM_GLOBAL_INSTALL = "npm_global_install"
    FIREWALL_ALLOW_TCP = "firewall_allow_tcp"
    FIREWALL_DENY_TCP = "firewall_deny_tcp"
    BLOCK_IP = "block_ip"


class AdminExecutionStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class AdminAdapterStatus(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class AdminCommandStep:
    title: str
    command: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class AdminCommandResult:
    title: str
    command: tuple[str, ...]
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class AdminExecutionResult:
    id: str
    plan_id: str
    status: AdminExecutionStatus
    summary: str
    command_results: tuple[AdminCommandResult, ...]
    verification_results: tuple[AdminCommandResult, ...] = ()
    rollback_results: tuple[AdminCommandResult, ...] = ()


@dataclass(frozen=True)
class AdminHistoryArchiveRecord:
    id: str
    plan_id: str
    disposition: str
    archived_by: str
    archived_at: str
    summary: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AdminExecutionCapability:
    kind: AdminChangeKind
    adapter_name: str
    status: AdminAdapterStatus
    summary: str
    authorization_required_before_enable: bool
    approval_plan_required: bool
    supported_commands: tuple[tuple[str, ...], ...] = ()

    def can_execute_live(self) -> bool:
        return self.status == AdminAdapterStatus.ENABLED


AdminCommandRunner = Callable[[AdminCommandStep], AdminCommandResult]


APT_NONINTERACTIVE_ENVIRONMENT: dict[str, str] = {
    "DEBIAN_FRONTEND": "noninteractive",
    "DEBIAN_PRIORITY": "critical",
    "APT_LISTCHANGES_FRONTEND": "none",
}


UNSUPPORTED_APT_PACKAGE_PREFIXES: tuple[str, ...] = ("flatpak:", "npm:", "pip:", "pipx:", "snap:")


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
    archived: bool = False
    archived_by: str | None = None
    archived_at: str | None = None
    archive_record_id: str | None = None

    def requires_explicit_approval(self) -> bool:
        return not self.canceled and (self.approval_level != ApprovalLevel.NONE or self.risk_level != RiskLevel.LOW)

    def can_execute(self) -> bool:
        return (
            not self.archived
            and not self.canceled
            and (self.approved or not self.requires_explicit_approval())
            and not missing_admin_change_fields(self)
        )


DEFAULT_ADMIN_EXECUTION_CAPABILITIES: dict[AdminChangeKind, AdminExecutionCapability] = {
    AdminChangeKind.USER_SERVICE_RESTART: AdminExecutionCapability(
        kind=AdminChangeKind.USER_SERVICE_RESTART,
        adapter_name="user-systemd-service",
        status=AdminAdapterStatus.ENABLED,
        summary="approved user service restart execution is enabled",
        authorization_required_before_enable=False,
        approval_plan_required=False,
        supported_commands=(("systemctl", "--user", "restart"), ("systemctl", "--user", "status")),
    ),
    AdminChangeKind.APT_INSTALL: AdminExecutionCapability(
        kind=AdminChangeKind.APT_INSTALL,
        adapter_name="apt-package-install",
        status=AdminAdapterStatus.DISABLED,
        summary="live apt installs require a specific high-risk package adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(("sudo", "apt-get", "install"), ("dpkg-query", "-W")),
    ),
    AdminChangeKind.APT_UPDATE: AdminExecutionCapability(
        kind=AdminChangeKind.APT_UPDATE,
        adapter_name="apt-package-index-refresh",
        status=AdminAdapterStatus.DISABLED,
        summary="live apt package index refresh requires a specific package-maintenance adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(("sudo", "apt-get", "update"), ("sudo", "apt-get", "check")),
    ),
    AdminChangeKind.APT_UPGRADE: AdminExecutionCapability(
        kind=AdminChangeKind.APT_UPGRADE,
        adapter_name="apt-package-upgrade",
        status=AdminAdapterStatus.DISABLED,
        summary="live apt upgrades require a specific high-risk package-maintenance adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(
            ("sudo", "apt-get", "upgrade"),
            ("sudo", "apt-get", "install", "--only-upgrade"),
            ("sudo", "apt-get", "check"),
            ("apt", "list", "--upgradable"),
        ),
    ),
    AdminChangeKind.FLATPAK_INSTALL: AdminExecutionCapability(
        kind=AdminChangeKind.FLATPAK_INSTALL,
        adapter_name="flatpak-install",
        status=AdminAdapterStatus.DISABLED,
        summary="live flatpak installs require a specific package-provider adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(("flatpak", "install"), ("flatpak", "info"), ("flatpak", "uninstall")),
    ),
    AdminChangeKind.NPM_GLOBAL_INSTALL: AdminExecutionCapability(
        kind=AdminChangeKind.NPM_GLOBAL_INSTALL,
        adapter_name="npm-global-install",
        status=AdminAdapterStatus.DISABLED,
        summary="live npm global installs require a specific package-provider adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(("npm", "install", "-g"), ("npm", "list", "-g"), ("npm", "uninstall", "-g")),
    ),
    AdminChangeKind.FIREWALL_ALLOW_TCP: AdminExecutionCapability(
        kind=AdminChangeKind.FIREWALL_ALLOW_TCP,
        adapter_name="ufw-firewall-allow",
        status=AdminAdapterStatus.DISABLED,
        summary="live firewall allow rules require a specific high-risk firewall adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(("sudo", "ufw", "allow"), ("sudo", "ufw", "status")),
    ),
    AdminChangeKind.FIREWALL_DENY_TCP: AdminExecutionCapability(
        kind=AdminChangeKind.FIREWALL_DENY_TCP,
        adapter_name="host-firewall-deny",
        status=AdminAdapterStatus.DISABLED,
        summary="live firewall deny rules require a specific high-risk firewall adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(
            ("sudo", "ufw", "deny"),
            ("sudo", "ufw", "status"),
            ("sudo", "firewall-cmd", "--zone=public", "--add-rich-rule"),
            ("sudo", "firewall-cmd", "--reload"),
            ("sudo", "firewall-cmd", "--zone=public", "--list-all"),
        ),
    ),
    AdminChangeKind.BLOCK_IP: AdminExecutionCapability(
        kind=AdminChangeKind.BLOCK_IP,
        adapter_name="ufw-source-block",
        status=AdminAdapterStatus.DISABLED,
        summary="live source blocks require a specific high-risk firewall adapter approval plan before enablement",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(("sudo", "ufw", "deny", "from"), ("sudo", "ufw", "status")),
    ),
}


def admin_execution_capability_for(
    kind: AdminChangeKind,
    enabled_adapter_kinds: Iterable[AdminChangeKind | str] = (),
) -> AdminExecutionCapability:
    normalized_kind = AdminChangeKind(kind)
    enabled = {AdminChangeKind(candidate) for candidate in enabled_adapter_kinds}
    capability = DEFAULT_ADMIN_EXECUTION_CAPABILITIES.get(
        normalized_kind,
        AdminExecutionCapability(
            kind=normalized_kind,
            adapter_name="unknown",
            status=AdminAdapterStatus.UNSUPPORTED,
            summary="no live admin adapter is registered for this plan kind",
            authorization_required_before_enable=True,
            approval_plan_required=True,
        ),
    )
    if capability.status == AdminAdapterStatus.DISABLED and normalized_kind in enabled:
        return replace(
            capability,
            status=AdminAdapterStatus.ENABLED,
            summary=f"approved live {capability.adapter_name} execution is enabled",
        )
    return capability


def archive_admin_change_plan(
    plan: AdminChangePlan,
    archive_record_id: str,
    archived_by: str,
    archived_at: str,
) -> AdminChangePlan:
    if not archived_by.strip():
        raise ValueError("archived_by is required")
    if plan.archived:
        raise ValueError("admin change plan is already archived")
    return replace(
        plan,
        archived=True,
        archived_by=archived_by,
        archived_at=archived_at,
        archive_record_id=archive_record_id,
    )


def unarchive_admin_change_plan(plan: AdminChangePlan, restored_by: str) -> AdminChangePlan:
    if not restored_by.strip():
        raise ValueError("restored_by is required")
    if not plan.archived:
        raise ValueError("admin change plan is not archived")
    return replace(
        plan,
        archived=False,
        archived_by=None,
        archived_at=None,
        archive_record_id=None,
    )


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
    _validate_apt_package_identifiers(packages)
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


def plan_apt_update(plan_id: str, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.APT_UPDATE,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.LOW,
        approval_level=ApprovalLevel.NONE,
        target="apt package index",
        reason=reason,
        current_state=current_state,
        proposed_state="refresh apt package index and verify package manager consistency",
        steps=(
            AdminCommandStep(
                "Refresh package index",
                ("sudo", "apt-get", "update"),
                "refresh package metadata before planned installs or upgrades",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Verify package manager state after refresh",
                ("sudo", "apt-get", "check"),
                "package-index refresh has no direct rollback; confirm package manager consistency",
            ),
        ),
        risks=("sudo privilege use", "repository metadata changes may affect later package decisions"),
        verification_steps=(
            AdminCommandStep(
                "Verify package manager consistency",
                ("sudo", "apt-get", "check"),
                "confirm dependency metadata remains consistent after refresh",
            ),
        ),
    )


def plan_apt_upgrade(
    plan_id: str,
    packages: tuple[str, ...] = (),
    reason: str = "",
    current_state: str = "unknown",
) -> AdminChangePlan:
    package_args = packages or ()
    _validate_apt_package_identifiers(package_args)
    target = " ".join(package_args) if package_args else "all upgradeable packages"
    if package_args:
        preview_command = ("sudo", "apt-get", "install", "--only-upgrade", "--dry-run", *package_args)
        upgrade_command = ("sudo", "apt-get", "install", "--only-upgrade", "-y", *package_args)
    else:
        preview_command = ("sudo", "apt-get", "upgrade", "--dry-run")
        upgrade_command = ("sudo", "apt-get", "upgrade", "-y")
    verification_command = ("dpkg-query", "-W", *package_args) if package_args else ("sudo", "apt-get", "check")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.APT_UPGRADE,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.SISKO,
        target=target,
        reason=reason,
        current_state=current_state,
        proposed_state=f"upgrade apt packages: {target}",
        steps=(
            AdminCommandStep(
                "Simulate package upgrade",
                preview_command,
                "preview package changes before live upgrade",
            ),
            AdminCommandStep(
                "Upgrade packages",
                upgrade_command,
                "apply the approved package upgrade",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Check package manager state before rollback decision",
                ("sudo", "apt-get", "check"),
                "verify dependency state before trying rollback or the next available package version",
            ),
            AdminCommandStep(
                "Attempt package recovery",
                ("sudo", "apt-get", "-f", "install", "-y"),
                "repair interrupted package configuration before retrying the next available version",
            ),
        ),
        risks=(
            "sudo privilege use",
            "package upgrades may restart or change local services",
            "downgrade rollback may be unavailable without cached package versions",
        ),
        verification_steps=(
            AdminCommandStep(
                "Verify package upgrade",
                verification_command,
                "confirm upgraded packages or package manager state are queryable",
            ),
        ),
    )


def plan_flatpak_install(
    plan_id: str,
    app_id: str,
    reason: str,
    current_state: str = "unknown",
    remote: str = "flathub",
) -> AdminChangePlan:
    if not app_id.strip():
        raise ValueError("app_id is required")
    if not remote.strip():
        raise ValueError("remote is required")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.FLATPAK_INSTALL,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.SISKO,
        target=app_id,
        reason=reason,
        current_state=current_state,
        proposed_state=f"install Flatpak app {app_id} from {remote}",
        steps=(
            AdminCommandStep(
                "Install Flatpak app",
                ("flatpak", "install", "-y", remote, app_id),
                "apply the approved Flatpak installation",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Remove Flatpak app",
                ("flatpak", "uninstall", "-y", app_id),
                "undo Flatpak installation if verification fails",
            ),
        ),
        risks=("user application changes", "provider repository metadata may change", "application permissions may affect local files"),
        verification_steps=(
            AdminCommandStep(
                "Verify Flatpak app",
                ("flatpak", "info", app_id),
                "confirm the Flatpak app is installed and queryable",
            ),
        ),
    )


def plan_npm_global_install(
    plan_id: str,
    package: str,
    reason: str,
    current_state: str = "unknown",
) -> AdminChangePlan:
    if not package.strip():
        raise ValueError("package is required")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.NPM_GLOBAL_INSTALL,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.SISKO,
        target=package,
        reason=reason,
        current_state=current_state,
        proposed_state=f"install global npm package {package}",
        steps=(
            AdminCommandStep(
                "Install global npm package",
                ("npm", "install", "-g", package),
                "apply the approved global npm installation",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Remove global npm package",
                ("npm", "uninstall", "-g", package),
                "undo global npm installation if verification fails",
            ),
        ),
        risks=("global developer tooling changes", "provider package scripts may run", "package version drift may affect MCP behavior"),
        verification_steps=(
            AdminCommandStep(
                "Verify global npm package",
                ("npm", "list", "-g", package, "--depth=0"),
                "confirm the global npm package is installed and queryable",
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


def plan_firewall_deny_tcp(plan_id: str, port: int, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if port < 1 or port > 65535:
        raise ValueError("port must be between 1 and 65535")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.FIREWALL_DENY_TCP,
        owner_domain=OwnerDomain.ODO,
        risk_level=RiskLevel.CRITICAL,
        approval_level=ApprovalLevel.HUMAN,
        target=f"tcp/{port}",
        reason=reason,
        current_state=current_state,
        proposed_state=f"deny inbound TCP traffic on port {port}",
        steps=(
            AdminCommandStep(
                "Deny TCP port",
                ("sudo", "ufw", "deny", f"{port}/tcp"),
                "close the approved inbound service port",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Remove TCP deny rule",
                ("sudo", "ufw", "delete", "deny", f"{port}/tcp"),
                "remove the deny rule if it disrupts legitimate work",
            ),
        ),
        risks=(
            "legitimate clients may lose access",
            "firewall policy changes require audit review",
            "service may still listen until its bind configuration is changed",
        ),
        verification_steps=(
            AdminCommandStep(
                "Verify firewall status",
                ("sudo", "ufw", "status", "verbose"),
                "confirm the deny rule exists only as approved",
            ),
        ),
    )


def plan_firewalld_deny_tcp(
    plan_id: str,
    port: int,
    reason: str,
    current_state: str = "unknown",
    zone: str = "public",
) -> AdminChangePlan:
    if port < 1 or port > 65535:
        raise ValueError("port must be between 1 and 65535")
    if not zone.strip():
        raise ValueError("zone is required")
    rich_rule = (
        f'rule port port="{port}" protocol="tcp" '
        f'log prefix="overseer-deny-{port} " level="warning" limit value="5/m" reject'
    )
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.FIREWALL_DENY_TCP,
        owner_domain=OwnerDomain.ODO,
        risk_level=RiskLevel.CRITICAL,
        approval_level=ApprovalLevel.HUMAN,
        target=f"tcp/{port}",
        reason=reason,
        current_state=current_state,
        proposed_state=f"deny inbound TCP traffic on port {port} in firewalld zone {zone}",
        steps=(
            AdminCommandStep(
                "Add firewalld deny rich rule",
                ("sudo", "firewall-cmd", "--permanent", f"--zone={zone}", f"--add-rich-rule={rich_rule}"),
                "stage the approved TCP deny rule with bounded logging",
            ),
            AdminCommandStep(
                "Reload firewalld",
                ("sudo", "firewall-cmd", "--reload"),
                "apply the approved permanent firewall rule",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Remove firewalld deny rich rule",
                ("sudo", "firewall-cmd", "--permanent", f"--zone={zone}", f"--remove-rich-rule={rich_rule}"),
                "remove the deny rule if it disrupts legitimate work",
            ),
            AdminCommandStep(
                "Reload firewalld after rollback",
                ("sudo", "firewall-cmd", "--reload"),
                "apply the rollback firewall state",
            ),
        ),
        risks=(
            "legitimate clients may lose access",
            "firewall policy changes require audit review",
            "zone selection errors may affect the wrong interface set",
            "service may still listen until its bind configuration is changed",
        ),
        verification_steps=(
            AdminCommandStep(
                "Verify firewalld zone",
                ("sudo", "firewall-cmd", f"--zone={zone}", "--list-all"),
                "confirm the deny rule exists only as approved",
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


def execute_admin_change_plan(
    plan: AdminChangePlan,
    runner: AdminCommandRunner | None = None,
    enabled_adapter_kinds: Iterable[AdminChangeKind | str] = (),
) -> AdminExecutionResult:
    capability = admin_execution_capability_for(plan.kind, enabled_adapter_kinds)
    if not capability.can_execute_live():
        return AdminExecutionResult(
            id=f"admin.exec.{plan.id}.blocked",
            plan_id=plan.id,
            status=AdminExecutionStatus.BLOCKED,
            summary=f"live adapter unavailable for {AdminChangeKind(plan.kind).value}: {capability.summary}",
            command_results=(),
        )
    if not plan.can_execute():
        return AdminExecutionResult(
            id=f"admin.exec.{plan.id}.blocked",
            plan_id=plan.id,
            status=AdminExecutionStatus.BLOCKED,
            summary="admin change plan is not approved or is incomplete",
            command_results=(),
        )
    unsupported_provider = _unsupported_apt_provider_for_plan(plan)
    if unsupported_provider is not None:
        return AdminExecutionResult(
            id=f"admin.exec.{plan.id}.blocked",
            plan_id=plan.id,
            status=AdminExecutionStatus.BLOCKED,
            summary=(
                f"unsupported package provider {unsupported_provider!r} for {AdminChangeKind(plan.kind).value}; "
                "stage a provider-specific admin adapter instead of apt"
            ),
            command_results=(),
        )

    command_runner = runner or run_admin_command_step
    command_results = tuple(command_runner(step) for step in plan.steps)
    failed = next((result for result in command_results if result.exit_code != 0), None)
    if failed is not None:
        rollback_results = tuple(command_runner(step) for step in plan.rollback_steps)
        return AdminExecutionResult(
            id=f"admin.exec.{plan.id}.failed",
            plan_id=plan.id,
            status=AdminExecutionStatus.FAILED,
            summary=f"admin change failed during step: {failed.title}; rollback steps attempted",
            command_results=command_results,
            rollback_results=rollback_results,
        )

    verification_results = tuple(command_runner(step) for step in plan.verification_steps)
    verification_failed = next((result for result in verification_results if result.exit_code != 0), None)
    if verification_failed is not None:
        rollback_results = tuple(command_runner(step) for step in plan.rollback_steps)
        return AdminExecutionResult(
            id=f"admin.exec.{plan.id}.failed",
            plan_id=plan.id,
            status=AdminExecutionStatus.FAILED,
            summary=f"admin change verification failed during step: {verification_failed.title}; rollback steps attempted",
            command_results=command_results,
            verification_results=verification_results,
            rollback_results=rollback_results,
        )

    return AdminExecutionResult(
        id=f"admin.exec.{plan.id}.completed",
        plan_id=plan.id,
        status=AdminExecutionStatus.COMPLETED,
        summary="admin change completed and verified",
        command_results=command_results,
        verification_results=verification_results,
    )


def audit_event_from_admin_execution(plan: AdminChangePlan, result: AdminExecutionResult) -> AuditEvent:
    event_type = AuditEventType.EXECUTED if result.status == AdminExecutionStatus.COMPLETED else AuditEventType.BLOCKED
    return AuditEvent(
        id=f"audit.{result.id}",
        event_type=event_type,
        owner_domain=plan.owner_domain,
        subject_id=plan.id,
        summary=result.summary,
        risk_level=plan.risk_level,
        evidence_ids=(result.id,),
    )


def run_admin_command_step(step: AdminCommandStep) -> AdminCommandResult:
    environment = _admin_command_environment(step.command)
    completed = subprocess.run(
        step.command,
        check=False,
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        env=environment,
    )
    return AdminCommandResult(
        title=step.title,
        command=step.command,
        exit_code=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def _admin_command_environment(command: tuple[str, ...]) -> dict[str, str] | None:
    if _is_apt_command(command):
        return os.environ | APT_NONINTERACTIVE_ENVIRONMENT
    return None


def _is_apt_command(command: tuple[str, ...]) -> bool:
    if len(command) >= 2 and command[0] == "sudo" and command[1] == "apt-get":
        return True
    return bool(command and command[0] == "apt-get")


def _validate_apt_package_identifiers(packages: Iterable[str]) -> None:
    unsupported = _unsupported_package_provider(packages)
    if unsupported is not None:
        raise ValueError(f"unsupported package provider {unsupported!r}; use a provider-specific admin adapter")


def _unsupported_apt_provider_for_plan(plan: AdminChangePlan) -> str | None:
    if AdminChangeKind(plan.kind) not in {AdminChangeKind.APT_INSTALL, AdminChangeKind.APT_UPGRADE}:
        return None
    return _unsupported_package_provider(
        part
        for step in (*plan.steps, *plan.rollback_steps, *plan.verification_steps)
        for part in step.command
    )


def _unsupported_package_provider(parts: Iterable[str]) -> str | None:
    for part in parts:
        lowered = part.lower()
        for prefix in UNSUPPORTED_APT_PACKAGE_PREFIXES:
            if lowered.startswith(prefix):
                return prefix[:-1]
    return None


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
