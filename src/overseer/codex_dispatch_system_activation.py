"""External-only two-stage migration to the root system Overseer service."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import socket
import stat
import struct
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .admin import (
    AdminChangeKind, AdminChangePlan, AdminCommandResult, AdminCommandStep,
    AdminExecutionResult, AdminExecutionStatus,
)
from .codex_dispatch_release_activation import (
    CANONICAL_CHECKOUT, DEPENDENCY_ROOT, ROOT_PYTHON, ImmutableReleaseManifest,
    ReleaseFile, _boot_id, _canonical, _capture_api_binding, _capture_manager_binding,
    _git, _root_identity, _sha256, _stable_read, build_immutable_release_manifest,
    release_drop_in_content,
)
from .core import ApprovalLevel, OwnerDomain, RiskLevel


SCHEMA = "overseer.codex-dispatch-system-activation.v1"
ROOT_HELPER_SOURCE = "src/overseer_codex_dispatch_root_helper.py"
ROOT_HELPER_PATH = Path("/usr/local/libexec/overseer-codex-dispatch-activation")
ROOT_AUTHORITY_ROOT = Path("/etc/overseer/codex-dispatch-authorities")
ROOT_ACTIVE_AUTHORITY_PATH = ROOT_AUTHORITY_ROOT / "active.json"
SYSTEM_UNIT_PATH = Path("/etc/systemd/system/overseer-api.service")
SYSTEM_ENABLE_LINK = Path("/etc/systemd/system/multi-user.target.wants/overseer-api.service")
SYSTEM_CGROUP_PROCS = Path("/sys/fs/cgroup/system.slice/overseer-api.service/cgroup.procs")
USER_UNIT = Path("/home/god/.config/systemd/user/overseer-api.service")
USER_DROPINS = Path("/home/god/.config/systemd/user/overseer-api.service.d")
PRIMARY_STORE = "/home/god/.local/share/overseer/project/state/overseer.sqlite3"
CODEX_BINARY = Path("/usr/local/bin/codex")
CODEX_SOCKET = Path("/home/god/.codex/app-server-control/app-server-control.sock")
CODEX_SETTINGS = Path("/home/god/.codex/app-server-daemon/settings.json")
PSYCHLO_SECRET_PATH = Path("/home/god/.config/psychlo/overseer-peer-secret")
_EXTERNAL = ContextVar("overseer_codex_system_activation_external", default=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _approved_authority_record(plan: AdminChangePlan, spec: "SystemActivationSpec") -> dict[str, object]:
    if (not plan.approved or plan.approved_by != "sisko" or plan.approved_at is None
            or plan.canceled or plan.archived or plan.kind is not AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION
            or plan.risk_level is not RiskLevel.HIGH or plan.approval_level is not ApprovalLevel.HUMAN
            or plan.owner_domain is not OwnerDomain.SISKO or plan.target != "system/overseer-api.service"):
        raise ValueError("exact stored HUMAN/SISKO approved plan is required for authority export")
    try:
        approved_at = datetime.fromisoformat(plan.approved_at)
    except ValueError:
        raise ValueError("stored approved_at is not canonical") from None
    if (approved_at.tzinfo is None or approved_at.utcoffset() != timezone.utc.utcoffset(approved_at)
            or approved_at.isoformat() != plan.approved_at):
        raise ValueError("stored approved_at is not canonical UTC")
    approval = {"planId": plan.id, "approvedBy": plan.approved_by, "approvedAt": plan.approved_at,
                "kind": plan.kind.value, "riskLevel": plan.risk_level.value,
                "approvalLevel": plan.approval_level.value, "ownerDomain": plan.owner_domain.value,
                "target": plan.target}
    plan_digest = spec.capability(plan.id)["planDigest"]
    unsigned = {
        "schemaVersion": "overseer.codex-dispatch-root-authority.v1",
        "planDigest": plan_digest,
        "helperGitBlob": spec.helper_blob["blob"], "helperSha256": spec.helper_blob["sha256"],
        "helperSize": spec.helper_blob["size"], "rootHelperPath": str(ROOT_HELPER_PATH),
        "rootAuthorityPath": str(ROOT_AUTHORITY_ROOT / f"{plan_digest}.json"),
        "activeAuthorityPath": str(ROOT_ACTIVE_AUTHORITY_PATH),
        "systemUnitSha256": _sha256(spec.system_unit.encode()),
        "releaseManifestDigest": spec.manifest.digest,
        "approval": approval, "approvalDigest": _digest(approval),
    }
    return {**unsigned, "authorityDigest": _digest(unsigned)}


def _helper_blob() -> dict[str, object]:
    commit = _git("rev-parse", "HEAD").strip().decode().lower()
    blob = _git("rev-parse", f"{commit}:{ROOT_HELPER_SOURCE}").strip().decode().lower()
    completed = subprocess.run(
        ("/usr/bin/git", "--no-replace-objects", "-C", str(CANONICAL_CHECKOUT), "cat-file", "blob", blob),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
             "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null"},
    )
    if completed.returncode != 0 or not completed.stdout:
        raise ValueError("reviewed root helper blob is unavailable")
    return {"sourceCommit": commit, "blob": blob, "sha256": _sha256(completed.stdout),
            "size": len(completed.stdout), "path": ROOT_HELPER_SOURCE}


def _bound_user_resource(path: Path) -> dict[str, object]:
    content, info = _stable_read(path)
    if info.st_uid != 1000 or stat.S_IMODE(info.st_mode) & 0o002:
        raise ValueError("old user service resource is unsafe")
    return {"path": str(path), "sha256": _sha256(content), "device": info.st_dev,
            "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
            "size": info.st_size}


def _old_system_unit() -> Mapping[str, object] | None:
    if not SYSTEM_UNIT_PATH.exists():
        if os.path.lexists(SYSTEM_ENABLE_LINK) or (SYSTEM_CGROUP_PROCS.exists() and SYSTEM_CGROUP_PROCS.read_text().strip()):
            raise ValueError("root system service state exists without its unit")
        return None
    content, info = _stable_read(SYSTEM_UNIT_PATH)
    if info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("preexisting root system unit is unsafe")
    enabled = os.path.lexists(SYSTEM_ENABLE_LINK)
    if enabled:
        link = SYSTEM_ENABLE_LINK.lstat()
        if (not stat.S_ISLNK(link.st_mode) or link.st_uid != 0
                or SYSTEM_ENABLE_LINK.resolve(strict=True) != SYSTEM_UNIT_PATH):
            raise ValueError("preexisting root system enablement link is unsafe")
    pids = [int(item) for item in SYSTEM_CGROUP_PROCS.read_text().split()] if SYSTEM_CGROUP_PROCS.exists() else []
    if len(pids) > 1:
        raise ValueError("preexisting root system service is not a unique process")
    active = bool(pids)
    active_process = None
    if pids:
        pid = pids[0]
        raw_stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = raw_stat[raw_stat.rfind(")") + 2:].split()
        active_process = {"bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                          "pid": pid, "startTicks": int(fields[19]),
                          "cgroup": Path(f"/proc/{pid}/cgroup").read_text().strip(),
                          "cmdlineHex": Path(f"/proc/{pid}/cmdline").read_bytes().hex()}
    return {"path": str(SYSTEM_UNIT_PATH), "sha256": _sha256(content), "device": info.st_dev,
            "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "uid": 0,
            "size": info.st_size, "enabled": enabled, "active": active,
            "activeProcess": active_process}


def _old_user_resources() -> tuple[Mapping[str, object], ...]:
    paths = [USER_UNIT]
    if USER_DROPINS.exists():
        if USER_DROPINS.is_symlink():
            raise ValueError("user service drop-in directory is unsafe")
        paths.extend(sorted(USER_DROPINS.glob("*.conf")))
    return tuple(_bound_user_resource(path) for path in paths)


def _codex_daemon_spec() -> Mapping[str, object]:
    binary = _root_identity(CODEX_BINARY)
    prior_remote: bool | None = None
    prior_settings = None
    if CODEX_SETTINGS.exists():
        content, info = _stable_read(CODEX_SETTINGS)
        if info.st_uid != 1000 or info.st_gid != 1000 or stat.S_IMODE(info.st_mode) & 0o002:
            raise ValueError("Codex daemon settings are unsafe")
        settings = json.loads(content)
        if not isinstance(settings, dict) or set(settings) != {"remoteControlEnabled"}:
            raise ValueError("Codex daemon settings contract is invalid")
        prior_remote = settings["remoteControlEnabled"]
        prior_settings = {"sha256": _sha256(content), "size": info.st_size,
                          "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid}
    prior_running = CODEX_SOCKET.exists()
    prior_evidence = None
    if prior_running:
        socket_info = CODEX_SOCKET.lstat()
        if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != 1000:
            raise ValueError("Codex daemon socket is unsafe")
        completed = subprocess.run((str(CODEX_BINARY), "app-server", "daemon", "version"),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"HOME": "/home/god", "CODEX_HOME": "/home/god/.codex",
                                        "XDG_RUNTIME_DIR": "/run/user/1000", "PATH": "/usr/local/bin:/usr/bin:/bin",
                                        "LC_ALL": "C"}, check=False)
        version = json.loads(completed.stdout)
        if (completed.returncode != 0 or completed.stderr or not isinstance(version, dict)
                or version.get("remoteControlEnabled") is not False
                or version.get("socketPath") != str(CODEX_SOCKET)):
            raise ValueError("preexisting Codex daemon contract is invalid")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            client.connect(str(CODEX_SOCKET))
            pid, uid, gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        finally:
            client.close()
        raw_stat = Path(f"/proc/{pid}/stat").read_text()
        prior_evidence = {"version": version, "peerPid": pid, "peerUid": uid, "peerGid": gid,
                          "peerStartTicks": int(raw_stat[raw_stat.rfind(")") + 2:].split()[19]),
                          "socketDevice": socket_info.st_dev, "socketInode": socket_info.st_ino,
                          "peerCmdlineHex": Path(f"/proc/{pid}/cmdline").read_bytes().hex(),
                          "peerCgroup": Path(f"/proc/{pid}/cgroup").read_text().strip()}
    return {"binary": binary, "socketPath": str(CODEX_SOCKET),
            "priorRunning": prior_running, "priorEvidence": prior_evidence,
            "priorRemoteControlEnabled": prior_remote, "priorSettings": prior_settings,
            "uid": 1000, "gid": 1000}


def _psychlo_secret_spec() -> Mapping[str, object]:
    content, info = _stable_read(PSYCHLO_SECRET_PATH)
    if (info.st_uid != 1000 or info.st_gid != 1000 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or len(content) < 32):
        raise ValueError("Psychlo peer secret is unsafe")
    return {"path": str(PSYCHLO_SECRET_PATH), "sha256": _sha256(content),
            "device": info.st_dev, "inode": info.st_ino, "mode": 0o600,
            "uid": 1000, "gid": 1000, "links": 1, "size": len(content)}


def system_unit_content(manifest: ImmutableReleaseManifest) -> str:
    root = manifest.release_root
    old_exec = release_drop_in_content(manifest).decode().splitlines()
    exec_start = next(line for line in old_exec if line.startswith("ExecStart=/usr/bin/python3"))
    return (
        "[Unit]\nDescription=Overseer immutable dispatch API\nAfter=network.target\n\n"
        "[Service]\nType=simple\nUser=god\nGroup=god\n"
        f"WorkingDirectory={root}\n"
        "Environment=OVERSEER_CODEX_APP_SERVER_DISPATCH=1\nEnvironment=PYTHONPATH=\n"
        "Environment=OVERSEER_PSYCHLO_ENDPOINT=http://127.0.0.1:8798\n"
        "Environment=OVERSEER_PSYCHLO_BRIDGE_DATABASE=/home/god/.local/share/overseer/psychlo/bridge.sqlite3\n"
        "Environment=OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE=/home/god/.config/overseer/psychlo-project-bindings.json\n"
        "Environment=OVERSEER_PSYCHLO_POLICY_VERSION=2026-08-08\n"
        "Environment=OVERSEER_PSYCHLO_PEER_SECRET_FILE=%d/psychlo-overseer-peer-secret\n"
        "LoadCredential=psychlo-overseer-peer-secret:/home/god/.config/psychlo/overseer-peer-secret\n"
        f"{exec_start}\nRestart=on-failure\nRestartSec=5\n"
        "NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n"
        "ReadWritePaths=/home/god/.local/share/overseer/project/state /home/god/.local/share/overseer/psychlo\n"
        f"ReadOnlyPaths={root} /home/god/.config/overseer /home/god/.config/psychlo\n"
        "RestrictSUIDSGID=true\nLockPersonality=true\n\n[Install]\nWantedBy=multi-user.target\n"
    )


@dataclass(frozen=True)
class SystemActivationSpec:
    manifest: ImmutableReleaseManifest
    helper_blob: Mapping[str, object]
    manager_binding: Mapping[str, object]
    old_api_binding: Mapping[str, object]
    old_user_resources: tuple[Mapping[str, object], ...]
    old_system_unit: Mapping[str, object] | None
    system_unit: str
    codex_daemon: Mapping[str, object] = field(default_factory=dict)
    psychlo_peer_secret: Mapping[str, object] = field(default_factory=dict)

    def capability(self, plan_id: str) -> dict[str, object]:
        prior_service_state = {
            "present": self.old_system_unit is not None,
            "enabled": bool(self.old_system_unit and self.old_system_unit["enabled"]),
            "active": bool(self.old_system_unit and self.old_system_unit["active"]),
        }
        unsigned = {
            "schemaVersion": SCHEMA, "manifest": self.manifest.to_json(),
            "manifestDigest": self.manifest.digest, "releaseRoot": str(self.manifest.release_root),
            "systemUnit": self.system_unit, "systemUnitSha256": _sha256(self.system_unit.encode()),
            "bootstrapHelperSha256": self.helper_blob["sha256"], "rootHelperPath": str(ROOT_HELPER_PATH),
            "bootstrapHelperGitBlob": self.helper_blob["blob"], "bootstrapHelperSize": self.helper_blob["size"],
            "rootAuthorityDirectory": str(ROOT_AUTHORITY_ROOT),
            "activeAuthorityPath": str(ROOT_ACTIVE_AUTHORITY_PATH),
            "planBinding": {"planId": plan_id,
                            "kind": AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION.value,
                            "riskLevel": RiskLevel.HIGH.value, "approvalLevel": ApprovalLevel.HUMAN.value,
                            "ownerDomain": OwnerDomain.SISKO.value,
                            "target": "system/overseer-api.service"},
            "codexDaemon": dict(self.codex_daemon),
            "psychloPeerSecret": dict(self.psychlo_peer_secret),
            "rootPythonIdentity": dict(self.manifest.root_python),
            "oldUserResources": [dict(item) for item in self.old_user_resources],
            "oldSystemUnit": dict(self.old_system_unit) if self.old_system_unit is not None else None,
            "priorSystemServiceState": prior_service_state,
            "oldApiBinding": dict(self.old_api_binding), "managerBinding": dict(self.manager_binding),
            "journalActionId": _digest({"planId": plan_id, "manifestDigest": self.manifest.digest})[:32],
            "rollback": {"mode": "external-root-helper", "restoreOnlyExactQuarantines": True,
                         "stopSystemServiceFirst": True},
            "receiptStore": PRIMARY_STORE,
        }
        return {**unsigned, "planDigest": _digest(unsigned)}

    def to_json(self) -> dict[str, object]:
        return {"schemaVersion": SCHEMA, "manifest": self.manifest.to_json(),
                "helperBlob": dict(self.helper_blob), "managerBinding": dict(self.manager_binding),
                "oldApiBinding": dict(self.old_api_binding),
                "oldUserResources": [dict(item) for item in self.old_user_resources],
                "oldSystemUnit": dict(self.old_system_unit) if self.old_system_unit is not None else None,
                "systemUnit": self.system_unit, "codexDaemon": dict(self.codex_daemon),
                "psychloPeerSecret": dict(self.psychlo_peer_secret)}

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> "SystemActivationSpec":
        keys = {"schemaVersion", "manifest", "helperBlob", "managerBinding", "oldApiBinding",
                "oldUserResources", "oldSystemUnit", "systemUnit", "codexDaemon",
                "psychloPeerSecret"}
        if not isinstance(value, Mapping) or set(value) != keys or value["schemaVersion"] != SCHEMA:
            raise ValueError("system activation spec is invalid")
        return cls(ImmutableReleaseManifest.from_json(value["manifest"]), dict(value["helperBlob"]),
                   dict(value["managerBinding"]), dict(value["oldApiBinding"]),
                   tuple(dict(item) for item in value["oldUserResources"]),
                   dict(value["oldSystemUnit"]) if isinstance(value["oldSystemUnit"], Mapping) else None,
                   str(value["systemUnit"]), dict(value["codexDaemon"]),
                   dict(value["psychloPeerSecret"]))


def build_codex_dispatch_activation_spec() -> SystemActivationSpec:
    provisional = build_immutable_release_manifest(unit_contract=b"system-unit-v1")
    unit = system_unit_content(provisional)
    return SystemActivationSpec(provisional, _helper_blob(), _capture_manager_binding(),
                                _capture_api_binding(), _old_user_resources(), _old_system_unit(), unit,
                                _codex_daemon_spec(), _psychlo_secret_spec())


def _root_helper_command(action: str, digest: str) -> tuple[str, ...]:
    return ("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-S",
            str(ROOT_HELPER_PATH), action, digest)


def plan_codex_dispatch_activation(plan_id: str, spec: SystemActivationSpec, reason: str,
                                   current_state: str = "user service") -> AdminChangePlan:
    capability = spec.capability(plan_id)
    digest = str(capability["planDigest"])
    marker = lambda action: ("__overseer_codex_dispatch_system_v1", action, plan_id, digest)
    ceremony_artifact = {
        "schemaVersion": "overseer.codex-dispatch-authority-ceremony-requirements.v1",
        "planDigest": digest, "helperGitBlob": spec.helper_blob["blob"],
        "helperSha256": spec.helper_blob["sha256"], "helperSize": spec.helper_blob["size"],
        "rootHelperPath": str(ROOT_HELPER_PATH),
        "rootAuthorityPath": str(ROOT_AUTHORITY_ROOT / f"{digest}.json"),
        "activeAuthorityPath": str(ROOT_ACTIVE_AUTHORITY_PATH),
        "instructions": [
            "after exact plan approval, export the closed authority data from the isolated external CLI",
            "an independent human-authorized root ceremony installs the reviewed helper and per-plan authority without replacement",
            "the same root ceremony atomically rotates active.json; product code never installs or rotates authority",
        ],
    }
    metadata = {"schemaVersion": SCHEMA, "spec": spec.to_json(), "capability": capability,
                "ceremonyArtifact": ceremony_artifact,
                "externalCliOnly": True, "apiExecutionAllowed": False}
    return AdminChangePlan(
        id=plan_id, kind=AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION,
        owner_domain=OwnerDomain.SISKO, risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN, target="system/overseer-api.service", reason=reason,
        current_state=current_state,
        proposed_state=f"root system service from immutable release {spec.manifest.release_root}",
        steps=(AdminCommandStep("Activate immutable root system service", marker("activate-system"),
                                "root helper resumes the exact journaled migration and attests the system service"),),
        rollback_steps=(AdminCommandStep("Externally rollback system-service migration", marker("rollback"),
                                         "root helper stops the system service before exact user-service restoration"),),
        risks=("root helper and system unit installation require explicit approval",
               "migration stops the old user API before starting the system service",
               "rollback is external and fails closed on any quarantine identity mismatch"),
        verification_steps=(AdminCommandStep("Verify root system service receipt", marker("verify"),
                                             "verify root journal, system unit, process, port exclusivity, and health"),),
        adapter_metadata=metadata,
    )


def validate_codex_dispatch_activation_plan(plan: AdminChangePlan) -> SystemActivationSpec:
    metadata = plan.adapter_metadata
    if (AdminChangeKind(plan.kind) != AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION
            or not isinstance(metadata, dict) or set(metadata) != {"schemaVersion", "spec", "capability",
                                                               "ceremonyArtifact",
                                                               "externalCliOnly", "apiExecutionAllowed"}):
        raise ValueError("system activation plan metadata is invalid")
    spec = SystemActivationSpec.from_json(metadata["spec"])
    canonical = plan_codex_dispatch_activation(plan.id, spec, plan.reason, plan.current_state)
    normalized = replace(plan, approved=False, approved_by=None, approved_at=None, canceled=False,
                         canceled_by=None, canceled_at=None, cancellation_reason=None, archived=False,
                         archived_by=None, archived_at=None, archive_record_id=None)
    if normalized != canonical:
        raise ValueError("system activation plan is not exact and canonical")
    return spec


def verify_system_activation_spec(spec: SystemActivationSpec) -> None:
    if spec.manifest != build_immutable_release_manifest(unit_contract=b"system-unit-v1"):
        raise ValueError("approved immutable release inputs changed; restage")
    if dict(spec.helper_blob) != _helper_blob():
        raise ValueError("approved root helper Git blob changed; restage")
    if spec.system_unit != system_unit_content(spec.manifest):
        raise ValueError("approved complete system unit changed; restage")
    if spec.old_user_resources != _old_user_resources():
        raise ValueError("old user service resources changed; restage")
    if spec.old_system_unit != _old_system_unit():
        raise ValueError("preexisting root system unit changed; restage")
    if dict(spec.codex_daemon) != dict(_codex_daemon_spec()):
        raise ValueError("Codex daemon binary or prior state changed; restage")
    if dict(spec.psychlo_peer_secret) != dict(_psychlo_secret_spec()):
        raise ValueError("Psychlo peer secret identity changed; restage")
    if dict(spec.manager_binding) != _capture_manager_binding():
        raise ValueError("approved user manager changed; restage")
    if dict(spec.old_api_binding) != _capture_api_binding():
        raise ValueError("approved old API process changed; restage")


def require_isolated_activation_entry() -> None:
    from .codex_dispatch_activation import require_isolated_activation_entry as legacy_gate
    legacy_gate()
    _reject_api_context()


def require_external_activation_context() -> None:
    if not _EXTERNAL.get():
        raise ValueError("Codex system activation staging/execution is external isolated CLI only")
    _reject_api_context()


def _reject_api_context() -> None:
    try:
        cgroup = Path(f"/proc/{os.getpid()}/cgroup").read_text()
        cmdline = Path(f"/proc/{os.getpid()}/cmdline").read_bytes()
    except OSError as error:
        raise ValueError("external activation process identity is unavailable") from error
    if "overseer-api.service" in cgroup or b"serve-api" in cmdline:
        raise ValueError("Codex system activation is forbidden from API/UI process context")


@contextmanager
def external_activation_cli():
    _reject_api_context()
    token = _EXTERNAL.set(True)
    try:
        yield
    finally:
        _EXTERNAL.reset(token)


def _authority_files_present(spec: SystemActivationSpec, plan_id: str) -> bool:
    digest = str(spec.capability(plan_id)["planDigest"])
    authority_path = ROOT_AUTHORITY_ROOT / f"{digest}.json"
    try:
        authority_root = ROOT_AUTHORITY_ROOT.lstat()
        helper_content, helper_info = _stable_read(ROOT_HELPER_PATH)
        info = authority_path.lstat()
        active_info = ROOT_ACTIVE_AUTHORITY_PATH.lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISDIR(authority_root.st_mode) or ROOT_AUTHORITY_ROOT.is_symlink()
            or authority_root.st_uid != 0 or authority_root.st_gid != 0
            or stat.S_IMODE(authority_root.st_mode) != 0o755):
        raise ValueError("root dispatch authority directory is unsafe")
    if (helper_info.st_uid != 0 or helper_info.st_gid != 0 or helper_info.st_nlink != 1
            or stat.S_IMODE(helper_info.st_mode) != 0o444
            or len(helper_content) != spec.helper_blob["size"]
            or _sha256(helper_content) != spec.helper_blob["sha256"]):
        raise ValueError("preexisting root dispatch helper is not the approved immutable helper")
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400):
        raise ValueError("root dispatch authority record is unsafe")
    if (not stat.S_ISREG(active_info.st_mode) or active_info.st_uid != 0 or active_info.st_gid != 0
            or active_info.st_nlink != 1 or stat.S_IMODE(active_info.st_mode) != 0o400):
        raise ValueError("root active-authority ledger is unsafe")
    return True


def _authority_ceremony_data_for_loaded_plan(plan: AdminChangePlan) -> dict[str, object]:
    require_external_activation_context()
    spec = validate_codex_dispatch_activation_plan(plan)
    record = _approved_authority_record(plan, spec)
    return {
        "schemaVersion": "overseer.codex-dispatch-authority-export.v1",
        "planId": plan.id, "planDigest": record["planDigest"],
        "rootHelper": {"path": str(ROOT_HELPER_PATH), "gitBlob": spec.helper_blob["blob"],
                       "sha256": spec.helper_blob["sha256"], "size": spec.helper_blob["size"]},
        "authorityPath": record["rootAuthorityPath"], "authorityRecord": record,
        "authorityDigest": record["authorityDigest"],
        "activeAuthorityPath": str(ROOT_ACTIVE_AUTHORITY_PATH),
        "activeAuthoritySchema": {
            "schemaVersion": "overseer.codex-dispatch-active-authority.v1",
            "requiredFields": ["schemaVersion", "generation", "planDigest", "authorityDigest",
                               "authorityPath", "supersedesPlanDigest", "recordDigest"],
        },
        "instructions": [
            "data only: no privileged action is executed by Overseer",
            "independent root ceremony installs the immutable helper and authority file with no replacement",
            "independent root ceremony advances active.json with a monotonic generation and prior active plan digest",
        ],
    }


def _run_stream(command: Sequence[str], frames: Sequence[bytes], expected: Mapping[str, object]) -> None:
    process = subprocess.Popen(tuple(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    try:
        assert process.stdin is not None
        for frame in frames:
            process.stdin.write(struct.pack(">Q", len(frame)))
            process.stdin.write(frame)
        process.stdin.close(); process.stdin = None
        stdout, stderr = process.communicate(timeout=180)
        if process.returncode != 0 or stderr or json.loads(stdout) != expected:
            raise RuntimeError("external root activation command failed its exact result contract")
    except Exception:
        if process.poll() is None:
            process.kill(); process.wait()
        raise


def _run_activation_stream(command: Sequence[str], capability: Mapping[str, object],
                           manifest: ImmutableReleaseManifest) -> None:
    opened: list[tuple[int, ReleaseFile, tuple[int, ...]]] = []
    # Renaming the pathname changes ctime but cannot redirect this held fd;
    # streamed bytes still have to match the approved full-content digest.
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                             info.st_nlink, info.st_size)
    process = None
    try:
        for item in manifest.files:
            root = CANONICAL_CHECKOUT if item.source_kind == "checkout" else DEPENDENCY_ROOT
            path = root / item.source_path
            lexical = path.lstat()
            if not stat.S_ISREG(lexical.st_mode) or path.is_symlink() or lexical.st_nlink != 1:
                raise ValueError("release source is not a regular single-link file")
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(fd)
            if identity(info) != identity(lexical) or info.st_size != item.size:
                os.close(fd)
                raise ValueError("release source changed before descriptor pinning")
            opened.append((fd, item, identity(info)))
        process = subprocess.Popen(tuple(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        assert process.stdin is not None
        raw = _canonical(capability)
        process.stdin.write(struct.pack(">Q", len(raw))); process.stdin.write(raw)
        for fd, item, before in opened:
            process.stdin.write(struct.pack(">Q", item.size))
            hasher = hashlib.sha256(); total = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                process.stdin.write(chunk); hasher.update(chunk); total += len(chunk)
            if (identity(os.fstat(fd)) != before or total != item.size
                    or hasher.hexdigest() != item.sha256):
                raise ValueError("release source changed during held-descriptor stream")
        process.stdin.close(); process.stdin = None
        stdout, stderr = process.communicate(timeout=300)
        expected = {"status": "completed", "planDigest": capability["planDigest"]}
        if process.returncode != 0 or stderr or json.loads(stdout) != expected:
            raise RuntimeError("root helper activation failed its exact result contract")
    except Exception:
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        raise
    finally:
        for fd, _, _ in opened:
            os.close(fd)


def execute_codex_dispatch_activation_marker(command: Sequence[str]) -> tuple[int, str, str]:
    try:
        if not _EXTERNAL.get():
            raise ValueError("system activation is external isolated CLI only")
        _reject_api_context()
        if len(command) != 4 or command[0] != "__overseer_codex_dispatch_system_v1":
            raise ValueError("system activation marker is malformed")
        context = _ACTIVE.get()
        if context is None or command[2] != context[1] or command[3] != context[2]:
            raise ValueError("system activation marker lacks exact plan authority")
        spec, plan_id, digest = context
        action = command[1]
        capability = spec.capability(plan_id)
        frames = [_canonical(capability)]
        if action == "activate-system":
            cmd = _root_helper_command("activate", digest)
            _run_activation_stream(cmd, capability, spec.manifest)
            return 0, f"system activation {action} completed", ""
        elif action == "rollback":
            cmd = _root_helper_command("rollback", digest)
        elif action == "verify":
            cmd = _root_helper_command("verify", digest)
        else:
            raise ValueError("system activation marker operation is unsupported")
        _run_stream(cmd, frames, {"status": "completed", "planDigest": digest})
        return 0, f"system activation {action} completed", ""
    except Exception as error:
        return 1, "", f"system activation failed: {type(error).__name__}: {error}"


_ACTIVE = ContextVar("overseer_codex_system_activation_plan", default=None)


def execute_codex_dispatch_activation_plan(plan: AdminChangePlan, *, runner: Callable[[AdminCommandStep], AdminCommandResult] | None = None,
                                           adapter_enabled: bool = False) -> AdminExecutionResult:
    if not _EXTERNAL.get():
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED,
                                    "Codex system activation is forbidden through API/UI; use the external isolated CLI", ())
    if (not adapter_enabled or not plan.approved or str(plan.approved_by).lower() != "sisko"
            or plan.approval_level is not ApprovalLevel.HUMAN or plan.owner_domain is not OwnerDomain.SISKO
            or plan.canceled or plan.archived):
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED,
                                    "exact HUMAN/SISKO approval and adapter enablement are required", ())
    try:
        spec = validate_codex_dispatch_activation_plan(plan)
        _reject_api_context()
        if not _authority_files_present(spec, plan.id):
            raise ValueError("preexisting root helper or exact per-plan authority is missing; complete the out-of-band ceremony")
        verify_system_activation_spec(spec)
    except (OSError, ValueError) as error:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, str(error), ())
    digest = str(spec.capability(plan.id)["planDigest"])
    token = _ACTIVE.set((spec, plan.id, digest))
    try:
        if runner is None:
            runner = lambda step: AdminCommandResult(step.title, step.command, *execute_codex_dispatch_activation_marker(step.command))
        results = []
        for step in plan.steps:
            result = runner(step); results.append(result)
            if result.exit_code:
                rollback = tuple(runner(item) for item in plan.rollback_steps)
                return AdminExecutionResult(f"admin.exec.{plan.id}.failed", plan.id, AdminExecutionStatus.FAILED,
                                            f"system migration failed during {step.title}; external rollback attempted",
                                            tuple(results), rollback_results=rollback)
        verification = tuple(runner(item) for item in plan.verification_steps)
        if any(item.exit_code for item in verification):
            rollback = tuple(runner(item) for item in plan.rollback_steps)
            return AdminExecutionResult(f"admin.exec.{plan.id}.failed", plan.id, AdminExecutionStatus.FAILED,
                                        "system migration verification failed; external rollback attempted",
                                        tuple(results), verification, rollback)
        return AdminExecutionResult(f"admin.exec.{plan.id}.completed", plan.id, AdminExecutionStatus.COMPLETED,
                                    "immutable root system Overseer service activated", tuple(results), verification)
    finally:
        _ACTIVE.reset(token)


__all__ = ["SystemActivationSpec",
           "build_codex_dispatch_activation_spec", "external_activation_cli",
           "execute_codex_dispatch_activation_marker", "execute_codex_dispatch_activation_plan",
           "plan_codex_dispatch_activation", "require_external_activation_context",
           "require_isolated_activation_entry",
           "system_unit_content", "validate_codex_dispatch_activation_plan", "verify_system_activation_spec"]
