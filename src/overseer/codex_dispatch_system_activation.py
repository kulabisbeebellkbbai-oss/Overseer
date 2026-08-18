"""External-only two-stage migration to the root system Overseer service."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import struct
import subprocess
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace
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
SYSTEM_UNIT_PATH = Path("/etc/systemd/system/overseer-api.service")
USER_UNIT = Path("/home/god/.config/systemd/user/overseer-api.service")
USER_DROPINS = Path("/home/god/.config/systemd/user/overseer-api.service.d")
PRIMARY_STORE = "/home/god/.local/share/overseer/project/state/overseer.sqlite3"
_EXTERNAL = ContextVar("overseer_codex_system_activation_external", default=False)

BOOTSTRAP_INSTALLER = r'''import ctypes,hashlib,json,os,stat,struct,sys
digest,target=sys.argv[1:]; assert target=="/usr/local/libexec/overseer-codex-dispatch-activation" and len(digest)==64
def exact(n):
 b=b""
 while len(b)<n:
  x=sys.stdin.buffer.read(n-len(b))
  if not x: raise RuntimeError("truncated helper stream")
  b+=x
 return b
size=struct.unpack(">Q",exact(8))[0]; data=exact(size); assert not sys.stdin.buffer.read(1) and hashlib.sha256(data).hexdigest()==digest
root=os.lstat("/usr/local"); rootid=(root.st_dev,root.st_ino,root.st_uid,root.st_gid,stat.S_IMODE(root.st_mode)); assert stat.S_ISDIR(root.st_mode) and root.st_uid==0 and root.st_gid==0 and not stat.S_IMODE(root.st_mode)&0o022
rfd=os.open("/usr/local",os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW)
try: os.mkdir("libexec",0o755,dir_fd=rfd)
except FileExistsError: pass
lfd=os.open("libexec",os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rfd); ls=os.fstat(lfd); assert ls.st_uid==0 and ls.st_gid==0 and not stat.S_IMODE(ls.st_mode)&0o022
name="overseer-codex-dispatch-activation"
try:
 fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=lfd); existing=b""
 while True:
  x=os.read(fd,1048576)
  if not x: break
  existing+=x
 s=os.fstat(fd);os.close(fd);assert existing==data and s.st_uid==0 and s.st_gid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o555
except FileNotFoundError:
 tmp="."+name+"."+digest+".new";fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o555,dir_fd=lfd);view=memoryview(data)
 while view:
  n=os.write(fd,view);assert n>0;view=view[n:]
 os.fchmod(fd,0o555);os.fsync(fd);s=os.fstat(fd);assert s.st_uid==0 and s.st_gid==0 and s.st_nlink==1
 os.close(fd);libc=ctypes.CDLL(None,use_errno=True)
 if libc.renameat2(lfd,tmp.encode(),lfd,name.encode(),1)!=0: raise OSError(ctypes.get_errno(),"helper no-replace install failed")
 os.fsync(lfd)
after=os.lstat("/usr/local");assert rootid==(after.st_dev,after.st_ino,after.st_uid,after.st_gid,stat.S_IMODE(after.st_mode))
os.close(lfd);os.close(rfd);print(json.dumps({"status":"installed","helperDigest":digest,"helperPath":target},sort_keys=True,separators=(",",":")))'''


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


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
        return None
    content, info = _stable_read(SYSTEM_UNIT_PATH)
    if info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("preexisting root system unit is unsafe")
    return {"path": str(SYSTEM_UNIT_PATH), "sha256": _sha256(content), "device": info.st_dev,
            "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode), "uid": 0,
            "size": info.st_size}


def _old_user_resources() -> tuple[Mapping[str, object], ...]:
    paths = [USER_UNIT]
    if USER_DROPINS.exists():
        if USER_DROPINS.is_symlink():
            raise ValueError("user service drop-in directory is unsafe")
        paths.extend(sorted(USER_DROPINS.glob("*.conf")))
    return tuple(_bound_user_resource(path) for path in paths)


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

    def capability(self, plan_id: str) -> dict[str, object]:
        unsigned = {
            "schemaVersion": SCHEMA, "manifest": self.manifest.to_json(),
            "manifestDigest": self.manifest.digest, "releaseRoot": str(self.manifest.release_root),
            "systemUnit": self.system_unit, "systemUnitSha256": _sha256(self.system_unit.encode()),
            "bootstrapHelperSha256": self.helper_blob["sha256"], "rootHelperPath": str(ROOT_HELPER_PATH),
            "oldUserResources": [dict(item) for item in self.old_user_resources],
            "oldSystemUnit": dict(self.old_system_unit) if self.old_system_unit is not None else None,
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
                "systemUnit": self.system_unit}

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> "SystemActivationSpec":
        keys = {"schemaVersion", "manifest", "helperBlob", "managerBinding", "oldApiBinding",
                "oldUserResources", "oldSystemUnit", "systemUnit"}
        if not isinstance(value, Mapping) or set(value) != keys or value["schemaVersion"] != SCHEMA:
            raise ValueError("system activation spec is invalid")
        return cls(ImmutableReleaseManifest.from_json(value["manifest"]), dict(value["helperBlob"]),
                   dict(value["managerBinding"]), dict(value["oldApiBinding"]),
                   tuple(dict(item) for item in value["oldUserResources"]),
                   dict(value["oldSystemUnit"]) if isinstance(value["oldSystemUnit"], Mapping) else None,
                   str(value["systemUnit"]))


def build_codex_dispatch_activation_spec() -> SystemActivationSpec:
    provisional = build_immutable_release_manifest(unit_contract=b"system-unit-v1")
    unit = system_unit_content(provisional)
    return SystemActivationSpec(provisional, _helper_blob(), _capture_manager_binding(),
                                _capture_api_binding(), _old_user_resources(), _old_system_unit(), unit)


def _bootstrap_command(spec: SystemActivationSpec) -> tuple[str, ...]:
    return ("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-S", "-c",
            BOOTSTRAP_INSTALLER, str(spec.helper_blob["sha256"]), str(ROOT_HELPER_PATH))


def plan_codex_dispatch_activation(plan_id: str, spec: SystemActivationSpec, reason: str,
                                   current_state: str = "user service") -> AdminChangePlan:
    capability = spec.capability(plan_id)
    digest = str(capability["planDigest"])
    marker = lambda action: ("__overseer_codex_dispatch_system_v1", action, plan_id, digest)
    metadata = {"schemaVersion": SCHEMA, "spec": spec.to_json(), "capability": capability,
                "bootstrapCommand": list(_bootstrap_command(spec)),
                "activateCommand": ["/usr/bin/sudo", "-n", str(ROOT_HELPER_PATH), "activate", digest],
                "rollbackCommand": ["/usr/bin/sudo", "-n", str(ROOT_HELPER_PATH), "rollback", digest],
                "externalCliOnly": True, "apiExecutionAllowed": False}
    return AdminChangePlan(
        id=plan_id, kind=AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION,
        owner_domain=OwnerDomain.SISKO, risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN, target="system/overseer-api.service", reason=reason,
        current_state=current_state,
        proposed_state=f"root system service from immutable release {spec.manifest.release_root}",
        steps=(
            AdminCommandStep("Install reviewed root activation helper", marker("bootstrap-helper"),
                             "stream the exact reviewed helper Git blob to the tiny fixed root installer"),
            AdminCommandStep("Activate immutable root system service", marker("activate-system"),
                             "root helper resumes the exact journaled migration and attests the system service"),
        ),
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
                                                               "bootstrapCommand", "activateCommand", "rollbackCommand",
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


def _helper_bytes(spec: SystemActivationSpec) -> bytes:
    binding = spec.helper_blob
    if _git("rev-parse", f"{binding['sourceCommit']}:{ROOT_HELPER_SOURCE}").strip().decode() != binding["blob"]:
        raise ValueError("reviewed helper commit/path binding changed")
    completed = subprocess.run(("/usr/bin/git", "--no-replace-objects", "-C", str(CANONICAL_CHECKOUT),
                                "cat-file", "blob", str(binding["blob"])),
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                                    "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null"})
    if (completed.returncode != 0 or len(completed.stdout) != binding["size"]
            or _sha256(completed.stdout) != binding["sha256"]):
        raise ValueError("reviewed helper blob bytes changed")
    return completed.stdout


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
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
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
        if action == "bootstrap-helper":
            helper = _helper_bytes(spec)
            _run_stream(_bootstrap_command(spec), (helper,),
                        {"status": "installed", "helperDigest": spec.helper_blob["sha256"],
                         "helperPath": str(ROOT_HELPER_PATH)})
            return 0, "reviewed root helper installed", ""
        capability = spec.capability(plan_id)
        frames = [_canonical(capability)]
        if action == "activate-system":
            cmd = ("/usr/bin/sudo", "-n", str(ROOT_HELPER_PATH), "activate", digest)
            _run_activation_stream(cmd, capability, spec.manifest)
            return 0, f"system activation {action} completed", ""
        elif action == "rollback":
            cmd = ("/usr/bin/sudo", "-n", str(ROOT_HELPER_PATH), "rollback", digest)
        elif action == "verify":
            cmd = ("/usr/bin/sudo", "-n", str(ROOT_HELPER_PATH), "verify", digest)
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
    if not adapter_enabled or not plan.approved or plan.canceled or plan.archived:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED,
                                    "exact HUMAN/SISKO approval and adapter enablement are required", ())
    try:
        spec = validate_codex_dispatch_activation_plan(plan)
        _reject_api_context()
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


__all__ = ["SystemActivationSpec", "build_codex_dispatch_activation_spec", "external_activation_cli",
           "execute_codex_dispatch_activation_marker", "execute_codex_dispatch_activation_plan",
           "plan_codex_dispatch_activation", "require_external_activation_context",
           "require_isolated_activation_entry",
           "system_unit_content", "validate_codex_dispatch_activation_plan", "verify_system_activation_spec"]
