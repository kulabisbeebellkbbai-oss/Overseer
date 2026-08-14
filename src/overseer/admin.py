"""Approval-plan models for administrative host changes."""

from __future__ import annotations

import os
import ipaddress
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from dataclasses import field
from dataclasses import replace
from enum import StrEnum

from .audit import AuditEvent, AuditEventType
from .core import ApprovalLevel, OwnerDomain, RiskLevel


class AdminChangeKind(StrEnum):
    # This is a durable human-authority record only.  It deliberately has no
    # execution adapter or command steps; the policy-exception bridge owns its
    # paired ApprovalRequest decision path.
    PSYCHLO_POLICY_EXCEPTION = "psychlo_policy_exception"
    PYTHON_HASHED_VENV_PROVISION = "python_hashed_venv_provision"
    USER_SERVICE_RESTART = "user_service_restart"
    APT_INSTALL = "apt_install"
    APT_UPDATE = "apt_update"
    APT_UPGRADE = "apt_upgrade"
    FIRMWARE_UPDATE = "firmware_update"
    FLATPAK_INSTALL = "flatpak_install"
    NPM_GLOBAL_INSTALL = "npm_global_install"
    DOCKER_COMPOSE_UPDATE = "docker_compose_update"
    STORAGE_MOUNT_TEST = "storage_mount_test"
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
    environment: tuple[tuple[str, str], ...] = ()


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
    residual_scan_findings: tuple[str, ...] = ()
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
    adapter_metadata: dict[str, object] = field(default_factory=dict)

    def requires_explicit_approval(self) -> bool:
        return not self.canceled and (self.approval_level != ApprovalLevel.NONE or self.risk_level != RiskLevel.LOW)

    def can_execute(self) -> bool:
        return (
            not self.archived
            and not self.canceled
            and self.kind is not AdminChangeKind.PSYCHLO_POLICY_EXCEPTION
            and (self.approved or not self.requires_explicit_approval())
            and not missing_admin_change_fields(self)
        )


DEFAULT_ADMIN_EXECUTION_CAPABILITIES: dict[AdminChangeKind, AdminExecutionCapability] = {
    AdminChangeKind.PYTHON_HASHED_VENV_PROVISION: AdminExecutionCapability(
        kind=AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,
        adapter_name="python-hashed-venv-provisioner",
        status=AdminAdapterStatus.DISABLED,
        summary="hash-pinned Python venv provisioning requires exact admin adapter enablement and human approval",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(
            ("uv", "venv", "--python"),
            ("uv", "pip", "sync", "--require-hashes", "--no-deps", "--only-binary=:all:"),
            ("python", "-m", "venv"),
            ("python", "-m", "pip", "install", "--require-hashes", "--no-deps", "--only-binary=:all:"),
        ),
    ),
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
    AdminChangeKind.FIRMWARE_UPDATE: AdminExecutionCapability(
        kind=AdminChangeKind.FIRMWARE_UPDATE,
        adapter_name="fwupd-firmware-update",
        status=AdminAdapterStatus.DISABLED,
        summary="live firmware updates require explicit adapter enablement because they mutate boot-trust state and usually require a reboot",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(
            ("fwupdmgr", "get-upgrades", "--no-reboot-check"),
            ("fwupdmgr", "update"),
            ("fwupdmgr", "get-history"),
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
    AdminChangeKind.DOCKER_COMPOSE_UPDATE: AdminExecutionCapability(
        kind=AdminChangeKind.DOCKER_COMPOSE_UPDATE,
        adapter_name="docker-compose-update",
        status=AdminAdapterStatus.DISABLED,
        summary="live Docker Compose updates require explicit adapter enablement because they can restart services and mutate volumes",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(
            ("sudo", "docker", "compose"),
            ("sudo", "docker", "run"),
            ("sudo", "docker", "image", "inspect"),
            ("trivy", "image"),
            ("curl", "-fsS"),
        ),
    ),
    AdminChangeKind.STORAGE_MOUNT_TEST: AdminExecutionCapability(
        kind=AdminChangeKind.STORAGE_MOUNT_TEST,
        adapter_name="storage-mount-test",
        status=AdminAdapterStatus.DISABLED,
        summary="live storage mount tests require explicit adapter enablement because they mount network storage and can expose backup paths",
        authorization_required_before_enable=True,
        approval_plan_required=True,
        supported_commands=(("mkdir", "-p"), ("sudo", "mount", "-t", "cifs"), ("findmnt", "--target"), ("sudo", "umount")),
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


def plan_firmware_update(
    plan_id: str,
    target: str,
    reason: str,
    current_state: str = "unknown",
    release_id: str = "",
    update_error: str = "",
) -> AdminChangePlan:
    if not target.strip():
        raise ValueError("target is required")
    fwupd_target = release_id.strip() or target.strip()
    blockers = (update_error.strip(),) if update_error.strip() else ()
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.FIRMWARE_UPDATE,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.CRITICAL,
        approval_level=ApprovalLevel.HUMAN,
        target=target.strip(),
        reason=reason,
        current_state=current_state,
        proposed_state=f"apply approved fwupd firmware update for {target.strip()}",
        steps=(
            AdminCommandStep(
                "Inspect firmware update readiness",
                ("fwupdmgr", "get-upgrades", "--no-reboot-check"),
                "confirm the target update is still available and blockers are resolved immediately before mutation",
            ),
            AdminCommandStep(
                "Apply firmware update",
                ("fwupdmgr", "update", fwupd_target),
                "apply the explicitly approved firmware update through fwupd",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Capture firmware history after failed update",
                ("fwupdmgr", "get-history"),
                "preserve vendor/fwupd history for rollback assessment because firmware rollback may be unavailable",
            ),
        ),
        risks=(
            "firmware mutation",
            "boot trust database changes",
            "reboot required",
            "vendor rollback may be unavailable",
            *blockers,
        ),
        verification_steps=(
            AdminCommandStep(
                "Verify firmware update history",
                ("fwupdmgr", "get-history"),
                "confirm fwupd records the firmware update result after reboot",
            ),
            AdminCommandStep(
                "Verify no remaining firmware upgrades",
                ("fwupdmgr", "get-upgrades", "--no-reboot-check"),
                "confirm the targeted firmware update is no longer pending or record any remaining blockers",
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


def plan_docker_compose_update(
    plan_id: str,
    compose_file: str,
    reason: str,
    current_state: str = "unknown",
    project_directory: str | None = None,
    env: tuple[str, ...] = (),
    rollback_env: tuple[str, ...] = (),
    extra_compose_files: tuple[str, ...] = (),
    scan_images: tuple[str, ...] = (),
    residual_scan_findings: tuple[str, ...] = (),
    health_url: str | None = None,
    backup_label: str | None = None,
) -> AdminChangePlan:
    if not compose_file.strip():
        raise ValueError("compose_file is required")
    compose_path = compose_file.strip()
    extra_paths = tuple(path.strip() for path in extra_compose_files if path.strip())
    project_dir = (project_directory or os.path.dirname(compose_path) or ".").strip()
    compose_files: tuple[str, ...] = (compose_path, *extra_paths)
    compose_file_args = tuple(arg for path in compose_files for arg in ("-f", path))
    compose_command = ("sudo", "docker", "compose", *compose_file_args)
    rollback_compose_command = ("sudo", "docker", "compose", "-f", compose_path)
    env_prefix = ("sudo", "env", *env) if env else ("sudo",)
    rollback_env_prefix = ("sudo", "env", *rollback_env) if rollback_env else ("sudo",)
    safe_label = (backup_label or plan_id).replace("/", "_").replace(" ", "_")
    backup_dir = f"local-secrets/admin-backups/{safe_label}"
    backup_path = f"{project_dir}/{backup_dir}"
    verification = (
        AdminCommandStep(
            "Verify Compose services",
            (*compose_command, "ps"),
            "confirm the Compose project reports service state after the update",
        ),
    )
    if health_url:
        verification = (
            *verification,
            AdminCommandStep(
                "Verify service health endpoint",
                ("curl", "-fsS", health_url),
                "confirm the updated service responds on its local health or UI endpoint",
            ),
        )
    residual_findings = tuple(finding.strip() for finding in residual_scan_findings if finding.strip())
    scan_exit_code = "0" if residual_findings else "1"
    scan_reason = (
        "record current replacement image critical/high findings after explicit residual-risk approval"
        if residual_findings
        else "block service recreation if the pulled replacement image still has critical or high vulnerabilities"
    )
    scan_steps = tuple(
        AdminCommandStep(
            f"Scan updated image {image}",
            ("trivy", "image", "--severity", "CRITICAL,HIGH", "--exit-code", scan_exit_code, image),
            scan_reason,
        )
        for image in scan_images
    )
    extra_backup_steps = tuple(
        AdminCommandStep(
            f"Backup Compose override {index}",
            ("cp", path, f"{backup_path}/compose-override-{index}.yaml"),
            "preserve the current Compose override declaration for rollback review",
        )
        for index, path in enumerate(extra_paths, start=1)
    )
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.DOCKER_COMPOSE_UPDATE,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=compose_path,
        reason=reason,
        current_state=current_state,
        proposed_state=f"update Docker Compose project at {compose_path} and verify dependent services",
        steps=(
            AdminCommandStep(
                "Create backup directory",
                ("mkdir", "-p", backup_path),
                "prepare local-only backup storage before changing Compose services",
            ),
            AdminCommandStep(
                "Backup Compose file",
                ("cp", compose_path, f"{backup_path}/docker-compose.yaml"),
                "preserve the current Compose declaration for rollback",
            ),
            *extra_backup_steps,
            AdminCommandStep(
                "Backup Postgres volume",
                (
                    "sudo",
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    "penpot_penpot_postgres_v15:/volume:ro",
                    "-v",
                    f"{backup_path}:/backup",
                    "alpine:latest",
                    "tar",
                    "czf",
                    "/backup/postgres-volume.tgz",
                    "-C",
                    "/volume",
                    ".",
                ),
                "preserve database volume data before an application or image update",
            ),
            AdminCommandStep(
                "Backup asset volume",
                (
                    "sudo",
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    "penpot_penpot_assets:/volume:ro",
                    "-v",
                    f"{backup_path}:/backup",
                    "alpine:latest",
                    "tar",
                    "czf",
                    "/backup/assets-volume.tgz",
                    "-C",
                    "/volume",
                    ".",
                ),
                "preserve application assets before the update",
            ),
            AdminCommandStep(
                "Pull Compose images",
                (*env_prefix, "docker", "compose", *compose_file_args, "pull"),
                "download the approved image versions before recreating services",
            ),
            *scan_steps,
            AdminCommandStep(
                "Recreate Compose services",
                (*env_prefix, "docker", "compose", *compose_file_args, "up", "-d"),
                "apply the approved image update to the Compose project",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Rollback Compose services",
                (*rollback_env_prefix, "docker", "compose", "-f", compose_path, "up", "-d"),
                "return the Compose project to the base Compose file if verification fails",
            ),
        ),
        risks=(
            "Docker Compose services will restart",
            "application image updates may run irreversible migrations",
            "database and asset volumes must be backed up before service recreation",
            "dependent local integrations may fail while services restart",
        ),
        verification_steps=verification,
        residual_scan_findings=residual_findings,
    )


def plan_storage_mount_test(
    plan_id: str,
    share: str,
    mount_path: str,
    credential_file: str,
    reason: str,
    current_state: str = "unknown",
    filesystem_type: str = "cifs",
) -> AdminChangePlan:
    if not share.strip():
        raise ValueError("share is required")
    if not mount_path.strip():
        raise ValueError("mount_path is required")
    if not credential_file.strip():
        raise ValueError("credential_file is required")
    if filesystem_type != "cifs":
        raise ValueError("only cifs storage mount tests are currently supported")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.STORAGE_MOUNT_TEST,
        owner_domain=OwnerDomain.KIRA,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=f"{share} -> {mount_path}",
        reason=reason,
        current_state=current_state,
        proposed_state=f"temporarily mount {share} at {mount_path}, verify access, then unmount unless follow-up approval keeps it mounted",
        steps=(
            AdminCommandStep(
                "Create local mount directory",
                ("mkdir", "-p", mount_path),
                "prepare the approved local mount point without touching the remote share",
            ),
            AdminCommandStep(
                "Mount storage share",
                ("sudo", "mount", "-t", filesystem_type, share, mount_path, "-o", f"credentials={credential_file},rw"),
                "connect the approved network storage target using the ignored credential file",
            ),
        ),
        rollback_steps=(
            AdminCommandStep(
                "Unmount storage share",
                ("sudo", "umount", mount_path),
                "disconnect the NAS share if validation fails or after the temporary test completes",
            ),
        ),
        risks=(
            "network storage credentials could be misused if local secret permissions are wrong",
            "mounting the wrong share could expose or overwrite unintended backup data",
            "a stale mount can cause backup jobs to write to local disk instead of NAS if not monitored",
            "NAS outage or DNS failure can block backup execution until remediated",
        ),
        verification_steps=(
            AdminCommandStep(
                "Verify mount target",
                ("findmnt", "--target", mount_path),
                "confirm the mounted path resolves to the approved NAS share",
            ),
        ),
    )


def plan_firewall_allow_tcp(plan_id: str, port: int, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if port < 1 or port > 65535:
        raise ValueError("port must be between 1 and 65535")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.FIREWALL_ALLOW_TCP,
        owner_domain=OwnerDomain.ODO_FIREWALL,
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
        owner_domain=OwnerDomain.ODO_FIREWALL,
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
        owner_domain=OwnerDomain.ODO_FIREWALL,
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


def plan_firewalld_source_scoped_deny_tcp(
    plan_id: str,
    port: int,
    allowed_sources: tuple[str, ...],
    reason: str,
    current_state: str = "unknown",
    zone: str = "public",
) -> AdminChangePlan:
    if port < 1 or port > 65535:
        raise ValueError("port must be between 1 and 65535")
    if not allowed_sources:
        raise ValueError("allowed_sources is required for source-scoped firewall plans")
    if not zone.strip():
        raise ValueError("zone is required")
    normalized_sources = tuple(str(ipaddress.ip_network(source, strict=False)) for source in allowed_sources)

    allow_steps: list[AdminCommandStep] = []
    rollback_steps: list[AdminCommandStep] = []
    for source in normalized_sources:
        family = "ipv6" if ipaddress.ip_network(source, strict=False).version == 6 else "ipv4"
        allow_rule = (
            f'rule family="{family}" priority="-200" source address="{source}" '
            f'port port="{port}" protocol="tcp" log prefix="overseer-allow-{port} " '
            f'level="info" limit value="5/m" accept'
        )
        allow_steps.append(
            AdminCommandStep(
                f"Allow intended source {source}",
                ("sudo", "firewall-cmd", "--permanent", f"--zone={zone}", f"--add-rich-rule={allow_rule}"),
                "preserve an intended client before applying the logged fallback reject",
            )
        )
        rollback_steps.append(
            AdminCommandStep(
                f"Remove intended source {source}",
                ("sudo", "firewall-cmd", "--permanent", f"--zone={zone}", f"--remove-rich-rule={allow_rule}"),
                "remove the source allow rule during rollback",
            )
        )

    reject_rules = (
        (
            "ipv4",
            f'rule family="ipv4" priority="-100" port port="{port}" protocol="tcp" '
            f'log prefix="overseer-deny-{port} " level="warning" limit value="5/m" reject',
        ),
        (
            "ipv6",
            f'rule family="ipv6" priority="-100" port port="{port}" protocol="tcp" '
            f'log prefix="overseer-deny6-{port} " level="warning" limit value="5/m" reject',
        ),
    )
    reject_steps = tuple(
        AdminCommandStep(
            f"Add logged {family} fallback reject",
            ("sudo", "firewall-cmd", "--permanent", f"--zone={zone}", f"--add-rich-rule={rule}"),
            "reject non-allowlisted inbound TCP traffic before broad zone service rules can accept it",
        )
        for family, rule in reject_rules
    )
    reject_rollback_steps = tuple(
        AdminCommandStep(
            f"Remove logged {family} fallback reject",
            ("sudo", "firewall-cmd", "--permanent", f"--zone={zone}", f"--remove-rich-rule={rule}"),
            "remove the fallback reject rule during rollback",
        )
        for family, rule in reversed(reject_rules)
    )
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.FIREWALL_DENY_TCP,
        owner_domain=OwnerDomain.ODO_FIREWALL,
        risk_level=RiskLevel.CRITICAL,
        approval_level=ApprovalLevel.HUMAN,
        target=f"tcp/{port}",
        reason=reason,
        current_state=current_state,
        proposed_state=(
            f"allow intended sources {', '.join(normalized_sources)} for TCP/{port} in firewalld zone {zone}; "
            "reject and log other inbound sources"
        ),
        steps=(
            *allow_steps,
            *reject_steps,
            AdminCommandStep(
                "Validate firewalld permanent configuration",
                ("sudo", "firewall-cmd", "--check-config"),
                "confirm the staged permanent configuration parses before reload",
            ),
            AdminCommandStep(
                "Reload firewalld",
                ("sudo", "firewall-cmd", "--reload"),
                "apply the approved permanent firewall rules",
            ),
        ),
        rollback_steps=(
            *reject_rollback_steps,
            *rollback_steps,
            AdminCommandStep(
                "Validate firewalld rollback configuration",
                ("sudo", "firewall-cmd", "--check-config"),
                "confirm the rollback configuration parses before reload",
            ),
            AdminCommandStep(
                "Reload firewalld after rollback",
                ("sudo", "firewall-cmd", "--reload"),
                "apply the rollback firewall state",
            ),
        ),
        risks=(
            "legitimate clients outside the allowlist may lose access",
            "firewall policy changes require audit review",
            "source attribution errors may preserve or block the wrong client",
            "service may still listen until its bind configuration is changed",
        ),
        verification_steps=(
            AdminCommandStep(
                "Verify firewalld zone",
                ("sudo", "firewall-cmd", f"--zone={zone}", "--list-all"),
                "confirm source allow rules and fallback reject exist only as approved",
            ),
            AdminCommandStep(
                "Verify active firewalld zones",
                ("sudo", "firewall-cmd", "--get-active-zones"),
                "confirm the selected zone is active on the intended interfaces",
            ),
        ),
    )


def plan_block_ip(plan_id: str, address: str, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if not address.strip():
        raise ValueError("address is required")
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.BLOCK_IP,
        owner_domain=OwnerDomain.ODO_FIREWALL,
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
    if AdminChangeKind(plan.kind) == AdminChangeKind.PYTHON_HASHED_VENV_PROVISION and not plan.adapter_metadata.get("python_venv"):
        missing.append("python_venv_manifest")
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
    if AdminChangeKind(plan.kind) == AdminChangeKind.PYTHON_HASHED_VENV_PROVISION:
        try:
            from .python_venv import validate_python_venv_plan

            validate_python_venv_plan(plan)
        except (OSError, ValueError) as exc:
            return AdminExecutionResult(
                id=f"admin.exec.{plan.id}.blocked",
                plan_id=plan.id,
                status=AdminExecutionStatus.BLOCKED,
                summary=f"python venv manifest validation blocked execution: {exc}",
                command_results=(),
            )
    command_results_list: list[AdminCommandResult] = []
    for step in plan.steps:
        result = command_runner(step)
        command_results_list.append(result)
        if result.exit_code != 0:
            rollback_results = tuple(command_runner(step) for step in plan.rollback_steps)
            return AdminExecutionResult(
                id=f"admin.exec.{plan.id}.failed",
                plan_id=plan.id,
                status=AdminExecutionStatus.FAILED,
                summary=f"admin change failed during step: {result.title}; rollback steps attempted",
                command_results=tuple(command_results_list),
                rollback_results=rollback_results,
            )
    command_results = tuple(command_results_list)

    verification_results_list: list[AdminCommandResult] = []
    for step in plan.verification_steps:
        result = command_runner(step)
        verification_results_list.append(result)
        if result.exit_code != 0:
            verification_results = tuple(verification_results_list)
            rollback_results = tuple(command_runner(step) for step in plan.rollback_steps)
            return AdminExecutionResult(
                id=f"admin.exec.{plan.id}.failed",
                plan_id=plan.id,
                status=AdminExecutionStatus.FAILED,
                summary=f"admin change verification failed during step: {result.title}; rollback steps attempted",
                command_results=command_results,
                verification_results=verification_results,
                rollback_results=rollback_results,
            )

    verification_results = tuple(verification_results_list)
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
    if step.command and step.command[0].startswith("__overseer_python_venv_"):
        try:
            from .python_venv import execute_python_venv_marker

            exit_code, stdout, stderr = execute_python_venv_marker(step.command)
        except (OSError, ValueError) as exc:
            exit_code, stdout, stderr = 1, "", str(exc)
        return AdminCommandResult(step.title, step.command, exit_code, stdout, stderr)
    environment = _admin_command_environment(step.command)
    if step.environment:
        environment = (environment or os.environ) | dict(step.environment)
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
