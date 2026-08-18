"""Approval-gated activation of the reviewed structured Codex transport.

All authority is derived from this checkout and the current euid's fixed home.
No caller-provided source path, home path, digest, socket, or health endpoint is
trusted.  Marker commands are interpreted here rather than by a shell.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pwd
import shlex
import socket
import stat
import subprocess
import tempfile
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .admin import (
    AdminChangeKind,
    AdminChangePlan,
    AdminCommandResult,
    AdminCommandStep,
    AdminExecutionResult,
    AdminExecutionStatus,
)
from .core import ApprovalLevel, OwnerDomain, RiskLevel


CODEX_DISPATCH_ACTIVATION_SCHEMA = "overseer.codex-dispatch-activation.v2"
JOURNAL_SCHEMA = "overseer.codex-dispatch-activation-journal.v5"
SERVICE_NAME = "overseer-api.service"
DROP_IN_RELATIVE_PATH = ".config/systemd/user/overseer-api.service.d/10-overseer-codex-dispatch.conf"
# This path is relative to CODEX_HOME exactly once.
DAEMON_SOCKET_RELATIVE_PATH = "app-server-control/app-server-control.sock"
HEALTH_URL = "http://127.0.0.1:8766/health"
SOURCE_ROOTS = ("src/overseer",)
DROP_IN_CONTENT = b"[Service]\nEnvironment=OVERSEER_CODEX_APP_SERVER_DISPATCH=1\n"
CANONICAL_SOURCE_ROOT = Path(__file__).resolve().parents[2]
EUID_HOME = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
CODEX_HOME = EUID_HOME / ".codex"
_HEX = set("0123456789abcdef")
_JOURNAL_KEYS = {
    "schemaVersion", "planId", "specDigest", "phase", "dropInPath", "dropInDigest",
    "dropInOwnership", "daemonSocketPath", "daemonOwnership", "bootstrapOwnership",
    "remoteControlPrior", "remoteControlOwnership", "dropInDevice", "dropInInode",
    "dropInQuarantinePath", "dropInQuarantineDevice", "dropInQuarantineInode",
}
_DAEMON_VERSION_KEYS = {"cliVersion", "daemonVersion", "state", "remoteControlEnabled", "socketPath"}
_JOURNAL_PHASES = {
    "none", "intent-bootstrap", "bootstrapped", "intent-start", "started",
    "intent-drop-in", "drop-in-installed", "reloaded", "restarted",
    "rollback-pending", "rolled-back", "verified",
}
_DROP_IN_OWNERSHIP = {
    "unknown", "write-issued", "created-by-operation", "preexisting", "quarantined", "removed",
}
_DAEMON_OWNERSHIP = {"unknown", "start-issued", "started-by-operation", "preexisting", "stopped"}
_BOOTSTRAP_OWNERSHIP = {
    "unknown", "bootstrap-issued", "created-by-operation", "preexisting",
    "not-created", "residual",
}
_REMOTE_CONTROL_PRIOR = {"unknown", "absent", "disabled", "enabled"}
_REMOTE_CONTROL_OWNERSHIP = {
    "unknown", "disable-issued", "disabled-by-operation", "preexisting-disabled",
    "not-changed", "residual", "restored",
}
_BOOTSTRAP_OUTPUT_KEYS = {
    "status", "backend", "autoUpdateEnabled", "remoteControlEnabled",
    "managedCodexPath", "managedCodexVersion", "socketPath", "cliVersion",
    "appServerVersion",
}
_REMOTE_CONTROL_REQUIRED_KEYS = {"status", "remoteControlEnabled", "socketPath", "cliVersion"}
_REMOTE_CONTROL_OPTIONAL_KEYS = {"backend", "appServerVersion"}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _valid_hex(value: object, lengths: set[int]) -> bool:
    return isinstance(value, str) and len(value) in lengths and set(value.lower()) <= _HEX


def _owner_only(path: Path, label: str) -> None:
    info = path.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"{label} is not owner-controlled")


def _safe_env() -> dict[str, str]:
    # Deliberately do not inherit caller HOME/CODEX_HOME.  The euid mapping is
    # the only authority for Codex configuration and credentials.
    return {
        "HOME": str(EUID_HOME),
        "CODEX_HOME": str(CODEX_HOME),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_checked(command: Sequence[str], *, timeout: float = 30.0, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        tuple(command), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL,
        shell=False, env=_safe_env(), cwd=str(cwd) if cwd else None, timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed: {command[0]}")
    return completed.stdout.strip()


def _git(command: Sequence[str]) -> str:
    return _run_checked(("/usr/bin/git", "-C", str(CANONICAL_SOURCE_ROOT), *command))


def _reviewed_source_files() -> tuple[str, ...]:
    tracked = tuple(
        sorted(
            item for item in _git(("ls-files", "--", *SOURCE_ROOTS)).splitlines()
            if item.endswith(".py")
        )
    )
    untracked = tuple(
        sorted(
            item for item in _git(("ls-files", "--others", "--exclude-standard", "--", *SOURCE_ROOTS)).splitlines()
            if item.endswith(".py")
        )
    )
    if untracked:
        raise ValueError("untracked Python exists in a reviewed source root")
    if not tracked:
        raise ValueError("reviewed Python source inventory is empty")
    return tracked


def _module_digest(source_files: Sequence[str]) -> str:
    hasher = hashlib.sha256()
    for relative in source_files:
        path = CANONICAL_SOURCE_ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("reviewed source module is missing")
        hasher.update(relative.encode() + b"\0" + path.read_bytes())
    return hasher.hexdigest()


def _source_clean() -> None:
    _reviewed_source_files()
    status = _git(("status", "--porcelain", "--untracked-files=no", "--", *SOURCE_ROOTS, "pyproject.toml"))
    if status:
        raise ValueError("reviewed source checkout is dirty")


def _review_digest(
    source_commit: str,
    source_tree_digest: str,
    source_module_digest: str,
    source_files: Sequence[str] | None = None,
) -> str:
    reviewed_files = tuple(source_files) if source_files is not None else _reviewed_source_files()
    return _digest({
        "reviewScope": "structured-codex-dispatch",
        "reviewAuthority": "canonical-overseer-checkout",
        "sourceCommit": source_commit,
        "sourceTreeDigest": source_tree_digest,
        "sourceModuleDigest": source_module_digest,
        "sourceFiles": list(reviewed_files),
    })


@dataclass(frozen=True)
class CodexDispatchActivationSpec:
    schema_version: str
    source_commit: str
    source_tree_digest: str
    source_module_digest: str
    review_digest: str
    service_name: str = SERVICE_NAME
    drop_in_relative_path: str = DROP_IN_RELATIVE_PATH
    daemon_socket: str = DAEMON_SOCKET_RELATIVE_PATH
    health_url: str = HEALTH_URL
    source_files: tuple[str, ...] = ()

    @property
    def source_root(self) -> Path:
        return CANONICAL_SOURCE_ROOT

    def to_json(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "sourceCommit": self.source_commit,
            "sourceTreeDigest": self.source_tree_digest,
            "sourceModuleDigest": self.source_module_digest,
            "reviewDigest": self.review_digest,
            "serviceName": self.service_name,
            "dropInRelativePath": self.drop_in_relative_path,
            "daemonSocket": self.daemon_socket,
            "healthUrl": self.health_url,
            "sourceFiles": list(self.source_files),
        }

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> "CodexDispatchActivationSpec":
        expected = {
            "schemaVersion", "sourceCommit", "sourceTreeDigest", "sourceModuleDigest", "reviewDigest",
            "serviceName", "dropInRelativePath", "daemonSocket", "healthUrl", "sourceFiles",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("Codex dispatch activation spec must contain exact keys")
        if value["schemaVersion"] != CODEX_DISPATCH_ACTIVATION_SCHEMA:
            raise ValueError("unsupported Codex dispatch activation schema")
        if not _valid_hex(value["sourceCommit"], {40, 64}):
            raise ValueError("source commit is invalid")
        if not _valid_hex(value["sourceTreeDigest"], {40, 64}):
            raise ValueError("source tree digest is invalid")
        if not _valid_hex(value["sourceModuleDigest"], {64}):
            raise ValueError("source module digest is invalid")
        if not _valid_hex(value["reviewDigest"], {64}):
            raise ValueError("review digest is invalid")
        if value["serviceName"] != SERVICE_NAME or value["dropInRelativePath"] != DROP_IN_RELATIVE_PATH:
            raise ValueError("service binding is not reviewed")
        if value["daemonSocket"] != DAEMON_SOCKET_RELATIVE_PATH or value["healthUrl"] != HEALTH_URL:
            raise ValueError("Codex endpoint binding is not reviewed")
        raw_files = value["sourceFiles"]
        if (not isinstance(raw_files, list) or not raw_files
                or any(not isinstance(item, str) or not item.endswith(".py")
                       or not any(item.startswith(f"{root}/") for root in SOURCE_ROOTS)
                       for item in raw_files)
                or raw_files != sorted(set(raw_files))):
            raise ValueError("sourceFiles are not a closed reviewed Python inventory")
        reviewed_files = tuple(raw_files)
        source_commit = str(value["sourceCommit"]).lower()
        source_tree = str(value["sourceTreeDigest"]).lower()
        source_module = str(value["sourceModuleDigest"]).lower()
        if str(value["reviewDigest"]).lower() != _review_digest(source_commit, source_tree, source_module, reviewed_files):
            raise ValueError("review digest is not derived from the reviewed binding")
        return cls(
            CODEX_DISPATCH_ACTIVATION_SCHEMA,
            source_commit,
            source_tree,
            source_module,
            str(value["reviewDigest"]).lower(),
            source_files=reviewed_files,
        )


def build_codex_dispatch_activation_spec() -> CodexDispatchActivationSpec:
    """Derive the only valid activation authority from the canonical checkout."""
    if not CANONICAL_SOURCE_ROOT.is_dir() or CANONICAL_SOURCE_ROOT.is_symlink():
        raise ValueError("canonical reviewed source checkout is unavailable")
    _source_clean()
    source_files = _reviewed_source_files()
    source_commit = _git(("rev-parse", "HEAD")).lower()
    source_tree = _git(("rev-parse", "HEAD^{tree}")).lower()
    source_module = _module_digest(source_files)
    return CodexDispatchActivationSpec(
        CODEX_DISPATCH_ACTIVATION_SCHEMA,
        source_commit,
        source_tree,
        source_module,
        _review_digest(source_commit, source_tree, source_module, source_files),
        source_files=source_files,
    )


def codex_dispatch_activation_plan_digest(spec: CodexDispatchActivationSpec) -> str:
    return _digest(spec.to_json())


def _marker_context(plan_id: str, spec: CodexDispatchActivationSpec) -> tuple[str, ...]:
    return (plan_id, codex_dispatch_activation_plan_digest(spec), _canonical(spec.to_json()))


def _canonical_plan(plan_id: str, spec: CodexDispatchActivationSpec, reason: str, current_state: str) -> AdminChangePlan:
    context = _marker_context(plan_id, spec)
    marker = lambda name: (f"__overseer_codex_dispatch_{name}", *context)
    return AdminChangePlan(
        id=plan_id, kind=AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION,
        owner_domain=OwnerDomain.SISKO, risk_level=RiskLevel.HIGH, approval_level=ApprovalLevel.HUMAN,
        target=SERVICE_NAME, reason=reason, current_state=current_state,
        proposed_state="bootstrap the local non-remote Codex app-server, enable reviewed structured dispatch, and verify Overseer",
        steps=(
            AdminCommandStep("Bootstrap local Codex app-server", marker("bootstrap"), "install local daemon management without remote control"),
            AdminCommandStep("Start local Codex app-server", marker("start"), "start the local daemon only after bootstrap"),
            AdminCommandStep("Install exact owner-only service drop-in", marker("install-drop-in"), "write only the reviewed Overseer environment override"),
            AdminCommandStep("Reload user systemd", marker("daemon-reload"), "load the exact drop-in"),
            AdminCommandStep("Restart Overseer API", marker("restart-overseer"), "apply the approved service environment"),
        ),
        rollback_steps=(AdminCommandStep("Rollback exact dispatch drop-in", marker("rollback"), "remove only a drop-in owned by this exact plan and restore service state"),),
        risks=("a daemon or service restart can interrupt local project coordination", "source or drop-in identity mismatch blocks activation", "remote control remains disabled; no network listener is authorized"),
        verification_steps=(
            AdminCommandStep("Verify daemon version", marker("verify-daemon"), "confirm the local daemon state contract"),
            AdminCommandStep("Verify local proxy readiness", marker("verify-proxy"), "confirm the local Unix-socket proxy responds"),
            AdminCommandStep("Verify Overseer environment", marker("verify-environment"), "confirm the reviewed dispatch setting is present exactly once"),
            AdminCommandStep("Verify Overseer health", marker("verify-health"), "confirm the local health endpoint responds"),
            AdminCommandStep("Verify reviewed source binding", marker("verify-source"), "confirm canonical commit, tree, module, and review digests are unchanged"),
        ),
        adapter_metadata={"spec": spec.to_json(), "specDigest": codex_dispatch_activation_plan_digest(spec)},
    )


def plan_codex_dispatch_activation(plan_id: str, spec: CodexDispatchActivationSpec, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if not plan_id.strip() or not reason.strip():
        raise ValueError("plan_id and reason are required")
    if spec.source_root != CANONICAL_SOURCE_ROOT:
        raise ValueError("caller-supplied source root is not authoritative")
    return _canonical_plan(plan_id, spec, reason, current_state)


def codex_dispatch_activation_spec_from_private_file(path: str | Path) -> CodexDispatchActivationSpec:
    raise ValueError("caller-supplied Codex dispatch manifests are not authoritative; derive the canonical source internally")


def validate_codex_dispatch_activation_plan(plan: AdminChangePlan) -> CodexDispatchActivationSpec:
    if AdminChangeKind(plan.kind) != AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION:
        raise ValueError("plan is not a Codex dispatch activation plan")
    metadata = plan.adapter_metadata
    if not isinstance(metadata, dict) or set(metadata) != {"spec", "specDigest"} or not isinstance(metadata["spec"], dict):
        raise ValueError("Codex dispatch activation plan metadata is invalid")
    spec = CodexDispatchActivationSpec.from_json(metadata["spec"])
    if metadata["specDigest"] != codex_dispatch_activation_plan_digest(spec):
        raise ValueError("Codex dispatch activation plan digest is invalid")
    canonical = _canonical_plan(plan.id, spec, plan.reason, plan.current_state)
    normalized = replace(plan, approved=False, approved_by=None, approved_at=None, canceled=False, canceled_by=None, canceled_at=None, cancellation_reason=None, archived=False, archived_by=None, archived_at=None, archive_record_id=None)
    if normalized != canonical:
        raise ValueError("Codex dispatch activation plan is not canonical")
    return spec


def verify_reviewed_source_binding(spec: CodexDispatchActivationSpec) -> None:
    if spec.source_root != CANONICAL_SOURCE_ROOT:
        raise ValueError("source root is not canonical")
    _source_clean()
    if _git(("rev-parse", "HEAD")).lower() != spec.source_commit or _git(("rev-parse", "HEAD^{tree}")).lower() != spec.source_tree_digest:
        raise ValueError("reviewed source commit or tree binding changed")
    reviewed_files = _reviewed_source_files()
    if spec.source_files != reviewed_files:
        raise ValueError("reviewed source file inventory changed")
    if _module_digest(reviewed_files) != spec.source_module_digest:
        raise ValueError("reviewed source module digest changed")
    if spec.review_digest != _review_digest(
        spec.source_commit, spec.source_tree_digest, spec.source_module_digest, reviewed_files
    ):
        raise ValueError("review digest changed")


def _paths() -> tuple[Path, Path, Path, Path]:
    drop_in = EUID_HOME / DROP_IN_RELATIVE_PATH
    journal = EUID_HOME / ".local/state/overseer/codex-dispatch/activation-journal.json"
    lock = EUID_HOME / ".local/state/overseer/codex-dispatch/activation.lock"
    return drop_in, journal, lock, CODEX_HOME / DAEMON_SOCKET_RELATIVE_PATH


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _owner_only(path.parent, "activation directory")
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open(path.parent, directory_flags)
    try:
        directory_info = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.geteuid()
                or stat.S_IMODE(directory_info.st_mode) & 0o077):
            raise ValueError("activation directory descriptor is unsafe")
        fd, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temp = Path(raw)
        try:
            os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, path)
            _owner_only(path, "activation file")
            os.fsync(directory_fd)
        finally:
            temp.unlink(missing_ok=True)
    finally:
        os.close(directory_fd)


def _stable_stat(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _secure_read_stable(path: Path, label: str, *, owner_only: bool = True) -> bytes:
    """Double-read one stable, euid-owned regular file through one nofollow fd."""
    return _secure_snapshot(path, label, owner_only=owner_only)[0]


def _secure_snapshot(path: Path, label: str, *, owner_only: bool = True) -> tuple[bytes, os.stat_result]:
    """Return stable content and the exact descriptor identity for one path."""
    lexical_before = path.lstat()
    if lexical_before.st_uid != os.geteuid():
        raise ValueError(f"{label} is not euid-owned")
    if owner_only and stat.S_IMODE(lexical_before.st_mode) & 0o077:
        raise ValueError(f"{label} is not owner-only")
    if not stat.S_ISREG(lexical_before.st_mode) or lexical_before.st_nlink != 1:
        raise ValueError(f"{label} is not a private single-link regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if _stable_stat(before) != _stable_stat(lexical_before):
            raise ValueError(f"{label} changed before secure read")
        first = _read_all_fd(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        second = _read_all_fd(fd)
        after = os.fstat(fd)
        lexical_after = path.lstat()
        if (first != second or _stable_stat(after) != _stable_stat(before)
                or _stable_stat(lexical_after) != _stable_stat(before)):
            raise ValueError(f"{label} changed during stable secure read")
        return first, after
    finally:
        os.close(fd)


def _read_all_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _open_stable_at(parent_fd: int, name: str, label: str) -> tuple[int, bytes, os.stat_result]:
    """Open and double-read a private file relative to one validated directory fd."""
    lexical_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISREG(lexical_before.st_mode) or lexical_before.st_uid != os.geteuid()
            or stat.S_IMODE(lexical_before.st_mode) & 0o077 or lexical_before.st_nlink != 1):
        raise ValueError(f"{label} is not a private euid-owned single-link regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        if _stable_stat(before) != _stable_stat(lexical_before):
            raise ValueError(f"{label} changed before secure read")
        first = _read_all_fd(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        second = _read_all_fd(fd)
        after = os.fstat(fd)
        lexical_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (first != second or _stable_stat(after) != _stable_stat(before)
                or _stable_stat(lexical_after) != _stable_stat(before)):
            raise ValueError(f"{label} changed during stable secure read")
        return fd, first, after
    except Exception:
        os.close(fd)
        raise


def _secure_read_exact(path: Path, expected: bytes) -> bytes:
    data = _secure_read_stable(path, "drop-in")
    if data != expected:
        raise ValueError("drop-in content is not the reviewed override")
    return data


def _journal(plan_id: str, digest: str, phase: str = "none", **updates: object) -> dict[str, object]:
    drop_in, _, _, socket_path = _paths()
    value: dict[str, object] = {
        "schemaVersion": JOURNAL_SCHEMA, "planId": plan_id, "specDigest": digest, "phase": phase,
        "dropInPath": str(drop_in), "dropInDigest": hashlib.sha256(DROP_IN_CONTENT).hexdigest(),
        "dropInOwnership": "unknown", "daemonSocketPath": str(socket_path), "daemonOwnership": "unknown",
        "dropInDevice": None, "dropInInode": None,
        "dropInQuarantinePath": None, "dropInQuarantineDevice": None, "dropInQuarantineInode": None,
        "bootstrapOwnership": "unknown", "remoteControlPrior": "unknown",
        "remoteControlOwnership": "unknown",
    }
    value.update(updates)
    return value


def _drop_in_quarantine_path(journal: Mapping[str, object]) -> Path:
    drop_in, _, _, _ = _paths()
    plan_suffix = _digest({"planId": journal["planId"], "specDigest": journal["specDigest"]})[:16]
    return drop_in.parent / f".{drop_in.name}.rollback-{plan_suffix}"


def _rename_noreplace_at(source: str, destination: str, *, dir_fd: int) -> None:
    """Atomically rename without replacing a concurrently-created destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise RuntimeError("atomic no-replace rename is unavailable")
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(dir_fd, os.fsencode(source), dir_fd, os.fsencode(destination), 1) != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(error_number, "quarantine destination already exists", destination)
        raise OSError(error_number, os.strerror(error_number), destination)


def _load_journal(plan_id: str, digest: str) -> dict[str, object] | None:
    drop_in, path, _, socket_path = _paths()
    try:
        raw = _secure_read_stable(path, "activation journal")
    except FileNotFoundError:
        return None
    value = json.loads(raw.decode("utf-8"))
    if (not isinstance(value, dict) or set(value) != _JOURNAL_KEYS
            or value["schemaVersion"] != JOURNAL_SCHEMA or value["planId"] != plan_id
            or value["specDigest"] != digest or value["dropInPath"] != str(drop_in)
            or value["dropInDigest"] != hashlib.sha256(DROP_IN_CONTENT).hexdigest()
            or value["daemonSocketPath"] != str(socket_path)):
        raise ValueError("activation journal binding is invalid")
    if value["phase"] not in _JOURNAL_PHASES:
        raise ValueError("activation journal phase is invalid")
    if value["dropInOwnership"] not in _DROP_IN_OWNERSHIP:
        raise ValueError("activation journal drop-in ownership is invalid")
    if not ((value["dropInDevice"] is None and value["dropInInode"] is None)
            or (isinstance(value["dropInDevice"], int) and not isinstance(value["dropInDevice"], bool)
                and value["dropInDevice"] >= 0 and isinstance(value["dropInInode"], int)
                and not isinstance(value["dropInInode"], bool) and value["dropInInode"] > 0)):
        raise ValueError("activation journal drop-in identity is invalid")
    has_drop_in_identity = value["dropInDevice"] is not None
    if (value["dropInOwnership"] == "created-by-operation" and not has_drop_in_identity
            or value["dropInOwnership"] in {"unknown", "preexisting"} and has_drop_in_identity):
        raise ValueError("activation journal drop-in identity ownership is invalid")
    quarantine_values = (
        value["dropInQuarantinePath"], value["dropInQuarantineDevice"], value["dropInQuarantineInode"],
    )
    has_quarantine_identity = quarantine_values != (None, None, None)
    if has_quarantine_identity:
        expected_quarantine = str(_drop_in_quarantine_path(value))
        if (not isinstance(quarantine_values[0], str) or quarantine_values[0] != expected_quarantine
                or not isinstance(quarantine_values[1], int) or isinstance(quarantine_values[1], bool)
                or quarantine_values[1] < 0 or not isinstance(quarantine_values[2], int)
                or isinstance(quarantine_values[2], bool) or quarantine_values[2] <= 0):
            raise ValueError("activation journal quarantine identity is invalid")
    if (value["dropInOwnership"] == "quarantined" and not has_quarantine_identity
            or value["dropInOwnership"] != "quarantined" and has_quarantine_identity):
        raise ValueError("activation journal quarantine ownership is invalid")
    if value["dropInOwnership"] == "quarantined" and (
        value["dropInDevice"], value["dropInInode"]
    ) != (value["dropInQuarantineDevice"], value["dropInQuarantineInode"]):
        raise ValueError("activation journal quarantine does not bind the operation-owned inode")
    if value["daemonOwnership"] not in _DAEMON_OWNERSHIP:
        raise ValueError("activation journal daemon ownership is invalid")
    if value["bootstrapOwnership"] not in _BOOTSTRAP_OWNERSHIP:
        raise ValueError("activation journal bootstrap ownership is invalid")
    if value["remoteControlPrior"] not in _REMOTE_CONTROL_PRIOR:
        raise ValueError("activation journal remote-control prior state is invalid")
    if value["remoteControlOwnership"] not in _REMOTE_CONTROL_OWNERSHIP:
        raise ValueError("activation journal remote-control ownership is invalid")
    return value


def _write_journal(value: Mapping[str, object]) -> None:
    _, path, _, _ = _paths()
    _atomic_write(path, (_canonical(dict(value)) + "\n").encode())


@contextmanager
def _activation_lock():
    _, _, path, _ = _paths()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _owner_only(path.parent, "activation lock directory")
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        fd = os.open(path, flags)
    with os.fdopen(fd, "r+") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1:
            raise ValueError("activation lock is not a private euid-owned regular file")
        if stat.S_IMODE(before.st_mode) & 0o077:
            raise ValueError("activation lock is not owner-only")
        os.fchmod(stream.fileno(), 0o600)
        after = os.fstat(stream.fileno())
        if _stable_stat(after)[:2] != _stable_stat(before)[:2] or stat.S_IMODE(after.st_mode) != 0o600:
            raise ValueError("activation lock changed during validation")
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Codex dispatch activation is already running") from exc
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _parse_marker(command: Sequence[str]) -> tuple[str, str, CodexDispatchActivationSpec]:
    if len(command) != 4 or not command[0].startswith("__overseer_codex_dispatch_"):
        raise ValueError("Codex dispatch activation marker context is invalid")
    try:
        spec = CodexDispatchActivationSpec.from_json(json.loads(command[3]))
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Codex dispatch activation marker context is invalid") from exc
    if not command[1].strip() or command[2] != codex_dispatch_activation_plan_digest(spec):
        raise ValueError("Codex dispatch activation marker digest is invalid")
    return command[0][len("__overseer_codex_dispatch_"):], command[1], spec


def _daemon_contract(output: str) -> dict[str, object]:
    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ValueError("Codex daemon version output is not JSON") from exc
    if not isinstance(value, dict) or set(value) != _DAEMON_VERSION_KEYS:
        raise ValueError("Codex daemon version output contract is invalid")
    if value["state"] != "running" or value["remoteControlEnabled"] is not False or value["socketPath"] != str(CODEX_HOME / DAEMON_SOCKET_RELATIVE_PATH):
        raise ValueError("Codex daemon is not running with remote control disabled on the reviewed socket")
    return value


def _daemon_version() -> dict[str, object]:
    return _daemon_contract(_run_checked(("codex", "app-server", "daemon", "version")))


def _daemon_status() -> str:
    """Return only an authoritative running/not-running state.

    A failed version probe with no reviewed socket is the sole not-running
    case.  Any payload or socket that exists but is malformed is an invalid
    pre-existing daemon and must never be started or stopped by this plan.
    """
    _, _, _, socket_path = _paths()
    try:
        _daemon_version()
    except RuntimeError:
        if not socket_path.exists():
            return "not-running"
        raise ValueError("existing Codex daemon state is invalid")
    except ValueError:
        raise
    return "running-valid"


@dataclass(frozen=True)
class _BootstrapState:
    configured: bool
    updater_running: bool
    remote_control_enabled: bool | None
    daemon_status: str


def _pid_matches_updater(pid: int) -> bool:
    proc = Path("/proc") / str(pid)
    try:
        if proc.stat().st_uid != os.geteuid():
            return False
        parts = (proc / "cmdline").read_bytes().split(b"\0")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return False
    expected = str(CODEX_HOME / "packages/standalone/current/codex").encode()
    return len(parts) >= 4 and parts[0] == expected and parts[1:4] == [
        b"app-server", b"daemon", b"pid-update-loop",
    ]


def _bootstrap_state() -> _BootstrapState:
    state_dir = CODEX_HOME / "app-server-daemon"
    settings_path = state_dir / "settings.json"
    updater_path = state_dir / "app-server-updater.pid"
    remote_enabled: bool | None = None
    configured = False
    try:
        raw_settings = _secure_read_stable(settings_path, "Codex daemon settings", owner_only=False)
    except FileNotFoundError:
        pass
    else:
        settings = json.loads(raw_settings.decode("utf-8"))
        if not isinstance(settings, dict) or set(settings) != {"remoteControlEnabled"} or not isinstance(settings["remoteControlEnabled"], bool):
            raise ValueError("Codex daemon settings contract is invalid")
        configured = True
        remote_enabled = settings["remoteControlEnabled"]
    updater_running = False
    try:
        raw_pid = _secure_read_stable(updater_path, "Codex updater pid", owner_only=False)
    except FileNotFoundError:
        pass
    else:
        try:
            pid_text = raw_pid.decode("ascii").strip()
            pid = int(pid_text)
        except (UnicodeError, ValueError) as error:
            raise ValueError("Codex updater pid contract is invalid") from error
        if pid <= 1:
            raise ValueError("Codex updater pid contract is invalid")
        updater_running = _pid_matches_updater(pid)
    return _BootstrapState(configured, updater_running, remote_enabled, _daemon_status())


def _bootstrap_contract(output: str) -> dict[str, object]:
    value = json.loads(output)
    expected_managed = str(CODEX_HOME / "packages/standalone/current/codex")
    if (not isinstance(value, dict) or set(value) != _BOOTSTRAP_OUTPUT_KEYS
            or value["status"] != "bootstrapped" or value["backend"] != "pid"
            or value["autoUpdateEnabled"] is not True or value["remoteControlEnabled"] is not False
            or value["managedCodexPath"] != expected_managed
            or value["socketPath"] != str(CODEX_HOME / DAEMON_SOCKET_RELATIVE_PATH)
            or not isinstance(value["cliVersion"], str) or not value["cliVersion"]
            or not isinstance(value["appServerVersion"], str) or not value["appServerVersion"]
            or not (value["managedCodexVersion"] is None or isinstance(value["managedCodexVersion"], str))):
        raise ValueError("Codex bootstrap output contract is invalid")
    return value


def _remote_control_disabled_contract(output: str) -> dict[str, object]:
    value = json.loads(output)
    if (not isinstance(value, dict)
            or not _REMOTE_CONTROL_REQUIRED_KEYS <= set(value)
            or not set(value) <= _REMOTE_CONTROL_REQUIRED_KEYS | _REMOTE_CONTROL_OPTIONAL_KEYS
            or value["status"] not in {"disabled", "alreadyDisabled"}
            or value["remoteControlEnabled"] is not False
            or value["socketPath"] != str(CODEX_HOME / DAEMON_SOCKET_RELATIVE_PATH)
            or not isinstance(value["cliVersion"], str) or not value["cliVersion"]
            or ("backend" in value and value["backend"] not in {None, "pid"})
            or ("appServerVersion" in value and value["appServerVersion"] is not None
                and not isinstance(value["appServerVersion"], str))):
        raise ValueError("Codex remote-control output contract is invalid")
    return value


def _probe_proxy() -> None:
    _, _, _, socket_path = _paths()
    if not socket_path.exists() or socket_path.is_symlink():
        raise ValueError("Codex app-server control socket is unavailable")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(socket_path))
        client.sendall(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"overseer","version":"1"},"capabilities":{}}}\n')
        raw = client.recv(4096)
        response = json.loads(raw.decode().splitlines()[0])
        if response.get("id") != 1 or not isinstance(response.get("result"), dict):
            raise ValueError("Codex local proxy readiness contract is invalid")
    finally:
        client.close()


def _verify_environment() -> None:
    output = _run_checked(("systemctl", "--user", "show", SERVICE_NAME, "--property=Environment", "--value"))
    assignments = shlex.split(output)
    matches = [item for item in assignments if item.startswith("OVERSEER_CODEX_APP_SERVER_DISPATCH=")]
    if matches != ["OVERSEER_CODEX_APP_SERVER_DISPATCH=1"]:
        raise ValueError("Overseer service environment does not contain exactly one correct dispatch flag")


def _install_drop_in(plan_id: str, digest: str) -> str:
    drop_in, _, _, _ = _paths()
    drop_in.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _owner_only(drop_in.parent, "systemd drop-in directory")
    journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
    prior_ownership = str(journal["dropInOwnership"])
    try:
        existing, existing_info = _secure_snapshot(drop_in, "drop-in")
        if existing != DROP_IN_CONTENT:
            raise ValueError("drop-in content is not the reviewed override")
    except FileNotFoundError:
        existing = None
        existing_info = None
    if existing is not None:
        # An exact file left by a persisted write intent belongs to this
        # operation even when a retry observes it before the success phase.
        journal["dropInOwnership"] = (
            "created-by-operation"
            if prior_ownership in {"write-issued", "created-by-operation"}
            else "preexisting"
        )
        if journal["dropInOwnership"] == "created-by-operation":
            journal["dropInDevice"] = existing_info.st_dev
            journal["dropInInode"] = existing_info.st_ino
        journal["phase"] = "drop-in-installed"
        _write_journal(journal)
        return "exact owner-only service drop-in already present"
    # Record intent before the effect.  A crash after os.replace but before
    # the success phase leaves write-issued intent for rollback reconciliation.
    journal["dropInOwnership"] = "write-issued"
    journal["phase"] = "intent-drop-in"
    _write_journal(journal)
    _atomic_write(drop_in, DROP_IN_CONTENT)
    installed, installed_info = _secure_snapshot(drop_in, "drop-in")
    if installed != DROP_IN_CONTENT:
        raise ValueError("installed drop-in is not the reviewed override")
    journal["dropInOwnership"] = "created-by-operation"
    journal["dropInDevice"] = installed_info.st_dev
    journal["dropInInode"] = installed_info.st_ino
    journal["phase"] = "drop-in-installed"
    _write_journal(journal)
    return "exact owner-only service drop-in installed"


def _revalidate_journal_drop_in(plan_id: str, digest: str) -> None:
    journal = _load_journal(plan_id, digest)
    if journal is None or journal["dropInOwnership"] not in {"preexisting", "created-by-operation"}:
        raise ValueError("drop-in intent is not ready for systemd transition")
    content, info = _secure_snapshot(Path(str(journal["dropInPath"])), "drop-in")
    if content != DROP_IN_CONTENT:
        raise ValueError("drop-in content is not the reviewed override")
    if journal["dropInOwnership"] == "created-by-operation" and (
        journal["dropInDevice"], journal["dropInInode"]
    ) != (info.st_dev, info.st_ino):
        raise ValueError("operation-owned drop-in identity changed")


def _remove_operation_drop_in(journal: dict[str, object]) -> None:
    """Move the exact operation-owned inode to inert retained quarantine."""
    drop_in, _, _, _ = _paths()
    parent = drop_in.parent
    lexical_parent = parent.lstat()
    if (not stat.S_ISDIR(lexical_parent.st_mode) or lexical_parent.st_uid != os.geteuid()
            or stat.S_IMODE(lexical_parent.st_mode) & 0o077):
        raise ValueError("systemd drop-in directory is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(parent, flags)
    quarantine_path = _drop_in_quarantine_path(journal)
    quarantine = quarantine_path.name
    if quarantine.endswith(".conf"):
        raise ValueError("drop-in quarantine name is not inert to systemd")
    try:
        parent_info = os.fstat(parent_fd)
        if ((parent_info.st_dev, parent_info.st_ino) != (lexical_parent.st_dev, lexical_parent.st_ino)
                or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
                or stat.S_IMODE(parent_info.st_mode) & 0o077):
            raise ValueError("systemd drop-in directory changed before rollback")

        def exists(name: str) -> bool:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            return True

        original_exists = exists(drop_in.name)
        quarantine_exists = exists(quarantine)
        if original_exists and quarantine_exists:
            raise ValueError("drop-in rollback has conflicting original and quarantine paths")
        if not original_exists and not quarantine_exists:
            if journal["dropInOwnership"] == "quarantined":
                raise ValueError("retained drop-in quarantine is missing")
            journal["dropInOwnership"] = "removed"
            return

        if original_exists:
            fd, content, info = _open_stable_at(parent_fd, drop_in.name, "operation-owned drop-in")
            os.close(fd)
            if content != DROP_IN_CONTENT:
                raise ValueError("operation-owned drop-in content changed")
            recorded = (journal["dropInDevice"], journal["dropInInode"])
            if recorded == (None, None) and journal["dropInOwnership"] == "write-issued":
                journal["dropInDevice"] = info.st_dev
                journal["dropInInode"] = info.st_ino
                _write_journal(journal)
            elif recorded != (info.st_dev, info.st_ino):
                raise ValueError("operation-owned drop-in identity changed")
            _rename_noreplace_at(drop_in.name, quarantine, dir_fd=parent_fd)

        fd, content, info = _open_stable_at(parent_fd, quarantine, "quarantined operation drop-in")
        os.close(fd)
        if content != DROP_IN_CONTENT:
            raise ValueError("quarantined drop-in content changed")
        if (journal["dropInDevice"], journal["dropInInode"]) != (info.st_dev, info.st_ino):
            raise ValueError("quarantined drop-in identity changed")
        if exists(drop_in.name):
            raise ValueError("drop-in path was replaced during rollback")
        parent_after = os.fstat(parent_fd)
        if ((parent_after.st_dev, parent_after.st_ino) != (parent_info.st_dev, parent_info.st_ino)
                or not stat.S_ISDIR(parent_after.st_mode) or parent_after.st_uid != os.geteuid()
                or stat.S_IMODE(parent_after.st_mode) & 0o077):
            raise ValueError("systemd drop-in directory changed during rollback")
        os.fsync(parent_fd)
        if exists(drop_in.name):
            raise ValueError("active systemd drop-in path reappeared during rollback")
        retained_fd, retained_content, retained_info = _open_stable_at(
            parent_fd, quarantine, "retained inert drop-in quarantine"
        )
        os.close(retained_fd)
        if retained_content != DROP_IN_CONTENT or (retained_info.st_dev, retained_info.st_ino) != (
            info.st_dev, info.st_ino
        ):
            raise ValueError("retained drop-in quarantine changed after directory sync")
        journal["dropInOwnership"] = "quarantined"
        journal["dropInQuarantinePath"] = str(quarantine_path)
        journal["dropInQuarantineDevice"] = retained_info.st_dev
        journal["dropInQuarantineInode"] = retained_info.st_ino
    finally:
        os.close(parent_fd)


def _revalidate_retained_drop_in_quarantine(journal: Mapping[str, object]) -> None:
    drop_in, _, _, _ = _paths()
    parent = drop_in.parent
    quarantine_path = _drop_in_quarantine_path(journal)
    if journal["dropInQuarantinePath"] != str(quarantine_path) or quarantine_path.name.endswith(".conf"):
        raise ValueError("retained drop-in quarantine binding is invalid")
    lexical_parent = parent.lstat()
    if (not stat.S_ISDIR(lexical_parent.st_mode) or lexical_parent.st_uid != os.geteuid()
            or stat.S_IMODE(lexical_parent.st_mode) & 0o077):
        raise ValueError("systemd drop-in directory is unsafe")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(parent, flags)
    try:
        parent_info = os.fstat(parent_fd)
        if ((parent_info.st_dev, parent_info.st_ino) != (lexical_parent.st_dev, lexical_parent.st_ino)
                or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.geteuid()
                or stat.S_IMODE(parent_info.st_mode) & 0o077):
            raise ValueError("systemd drop-in directory changed during quarantine validation")
        try:
            os.stat(drop_in.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("active systemd drop-in path reappeared after rollback")
        fd, content, info = _open_stable_at(
            parent_fd, quarantine_path.name, "retained inert drop-in quarantine"
        )
        os.close(fd)
        expected_identity = (journal["dropInQuarantineDevice"], journal["dropInQuarantineInode"])
        if (content != DROP_IN_CONTENT or (info.st_dev, info.st_ino) != expected_identity
                or expected_identity != (journal["dropInDevice"], journal["dropInInode"])):
            raise ValueError("retained drop-in quarantine identity changed")
        try:
            os.stat(drop_in.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("active systemd drop-in path reappeared during quarantine validation")
        parent_after = os.fstat(parent_fd)
        if _stable_stat(parent_after) != _stable_stat(parent_info):
            raise ValueError("systemd drop-in directory changed during quarantine validation")
    finally:
        os.close(parent_fd)


def _rollback(plan_id: str, digest: str) -> str:
    journal = _load_journal(plan_id, digest)
    if journal is None:
        return "no activation journal owned by this plan"
    if journal["phase"] == "rolled-back":
        if journal["dropInOwnership"] == "quarantined":
            try:
                _revalidate_retained_drop_in_quarantine(journal)
            except Exception:
                journal["phase"] = "rollback-pending"
                _write_journal(journal)
                raise
            return (
                "activation already rolled back; retained inert quarantine at "
                f"{journal['dropInQuarantinePath']}"
            )
        return "activation already rolled back"
    prior_phase = str(journal["phase"])
    journal["phase"] = "rollback-pending"
    _write_journal(journal)
    if journal["dropInOwnership"] in {"write-issued", "created-by-operation", "quarantined"}:
        _remove_operation_drop_in(journal)
        _write_journal(journal)
    if prior_phase in {"rollback-pending", "drop-in-installed", "reloaded", "restarted", "verified"} and journal["dropInOwnership"] in {"removed", "preexisting", "quarantined"}:
        _run_checked(("systemctl", "--user", "daemon-reload"))
        _run_checked(("systemctl", "--user", "restart", SERVICE_NAME))
    if journal["daemonOwnership"] in {"start-issued", "started-by-operation"}:
        try:
            status = _daemon_status()
            if status == "running-valid":
                _run_checked(("codex", "app-server", "daemon", "stop"))
        except (OSError, RuntimeError, ValueError) as error:
            raise RuntimeError(f"rollback daemon stop is retryable: {error}") from error
        journal["daemonOwnership"] = "stopped"
    residual: list[str] = []
    bootstrap_state: _BootstrapState | None = None
    if journal["bootstrapOwnership"] in {"bootstrap-issued", "created-by-operation", "residual"}:
        bootstrap_state = _bootstrap_state()
        if bootstrap_state.configured or bootstrap_state.updater_running:
            journal["bootstrapOwnership"] = "residual"
            residual.append("bootstrap")
        else:
            journal["bootstrapOwnership"] = "not-created"
    if journal["remoteControlOwnership"] in {"disable-issued", "disabled-by-operation", "residual"}:
        bootstrap_state = bootstrap_state or _bootstrap_state()
        prior = journal["remoteControlPrior"]
        if bootstrap_state.remote_control_enabled is False and prior in {"enabled", "absent"}:
            journal["remoteControlOwnership"] = "residual"
            residual.append("remote-control setting")
        elif prior == "enabled" and bootstrap_state.remote_control_enabled is True:
            journal["remoteControlOwnership"] = "restored"
        else:
            journal["remoteControlOwnership"] = "not-changed"
    if residual:
        _write_journal(journal)
        raise RuntimeError(f"rollback has residual {' and '.join(residual)} state")
    journal["phase"] = "rolled-back"
    _write_journal(journal)
    if journal["dropInOwnership"] == "quarantined":
        return (
            "exact Codex dispatch activation rolled back; retained inert quarantine at "
            f"{journal['dropInQuarantinePath']}"
        )
    return "exact Codex dispatch activation rolled back"


def execute_codex_dispatch_activation_marker(command: Sequence[str]) -> tuple[int, str, str]:
    try:
        operation, plan_id, spec = _parse_marker(command)
        digest = command[2]
        if operation in {"bootstrap", "start", "install-drop-in", "daemon-reload", "restart-overseer"}:
            verify_reviewed_source_binding(spec)
        if operation == "bootstrap":
            journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
            state = _bootstrap_state()
            if (journal["bootstrapOwnership"] in {"bootstrap-issued", "created-by-operation"}
                    and state.configured and state.updater_running
                    and state.remote_control_enabled is False and state.daemon_status == "running-valid"):
                journal["bootstrapOwnership"] = "created-by-operation"
                if journal["daemonOwnership"] == "start-issued":
                    journal["daemonOwnership"] = "started-by-operation"
                journal["remoteControlOwnership"] = (
                    "preexisting-disabled"
                    if journal["remoteControlPrior"] == "disabled"
                    else "disabled-by-operation"
                )
                journal["phase"] = "bootstrapped"
                _write_journal(journal)
                return 0, "daemon bootstrap effect reconciled with remote control disabled", ""
            journal["bootstrapOwnership"] = "preexisting" if state.updater_running else "bootstrap-issued"
            journal["remoteControlPrior"] = (
                "absent" if not state.configured else "enabled" if state.remote_control_enabled else "disabled"
            )
            journal["remoteControlOwnership"] = (
                "preexisting-disabled" if state.remote_control_enabled is False else "disable-issued"
            )
            journal["daemonOwnership"] = (
                "preexisting" if state.daemon_status == "running-valid" else "start-issued"
            )
            journal["phase"] = "intent-bootstrap"
            _write_journal(journal)
            _bootstrap_contract(_run_checked(("codex", "app-server", "daemon", "bootstrap")))
            _remote_control_disabled_contract(
                _run_checked(("codex", "app-server", "daemon", "disable-remote-control"))
            )
            journal["bootstrapOwnership"] = (
                "preexisting" if state.updater_running else "created-by-operation"
            )
            journal["daemonOwnership"] = (
                "preexisting" if state.daemon_status == "running-valid" else "started-by-operation"
            )
            journal["remoteControlOwnership"] = (
                "preexisting-disabled"
                if journal["remoteControlPrior"] == "disabled"
                else "disabled-by-operation"
            )
            journal["phase"] = "bootstrapped"
            _write_journal(journal)
            return 0, "daemon bootstrapped without remote control", ""
        if operation == "start":
            journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
            prior_ownership = str(journal["daemonOwnership"])
            journal["phase"] = "intent-start"
            _write_journal(journal)
            status = _daemon_status()
            if status == "running-valid":
                # A running daemon observed after a persisted start intent is
                # the operation's daemon, not an unrelated preexisting one.
                journal["daemonOwnership"] = (
                    "started-by-operation"
                    if prior_ownership in {"start-issued", "started-by-operation"}
                    else "preexisting"
                )
            elif status == "not-running":
                journal["daemonOwnership"] = "start-issued"
                _write_journal(journal)
                _run_checked(("codex", "app-server", "daemon", "start"))
                journal["daemonOwnership"] = "started-by-operation"
            journal["phase"] = "started"
            _write_journal(journal)
            return 0, "local daemon started", ""
        if operation == "install-drop-in":
            return 0, _install_drop_in(plan_id, digest), ""
        if operation == "daemon-reload":
            _revalidate_journal_drop_in(plan_id, digest)
            _run_checked(("systemctl", "--user", "daemon-reload"))
            _revalidate_journal_drop_in(plan_id, digest)
            journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
            journal["phase"] = "reloaded"
            _write_journal(journal)
            return 0, "user systemd reloaded", ""
        if operation == "restart-overseer":
            _revalidate_journal_drop_in(plan_id, digest)
            _run_checked(("systemctl", "--user", "restart", SERVICE_NAME))
            _revalidate_journal_drop_in(plan_id, digest)
            journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
            journal["phase"] = "restarted"
            _write_journal(journal)
            return 0, "Overseer API restarted", ""
        if operation == "rollback":
            return 0, _rollback(plan_id, digest), ""
        if operation == "verify-daemon":
            _daemon_version()
            return 0, "daemon state contract verified", ""
        if operation == "verify-proxy":
            _probe_proxy()
            return 0, "local proxy readiness verified", ""
        if operation == "verify-environment":
            _verify_environment()
            return 0, "Overseer dispatch environment verified", ""
        if operation == "verify-health":
            with urllib.request.urlopen(HEALTH_URL, timeout=5) as response:
                if response.status != 200:
                    raise ValueError("Overseer health check failed")
            return 0, "Overseer health verified", ""
        if operation == "verify-source":
            verify_reviewed_source_binding(spec)
            journal = _load_journal(plan_id, digest)
            if journal is not None:
                journal["phase"] = "verified"
                _write_journal(journal)
            return 0, "reviewed source binding verified", ""
        raise ValueError("unsupported Codex dispatch activation operation")
    except Exception as error:
        return 1, "", f"activation operation failed: {error}"


def _run_audited_step(
    runner: Callable[[AdminCommandStep], AdminCommandResult],
    step: AdminCommandStep,
) -> AdminCommandResult:
    try:
        result = runner(step)
        if not isinstance(result, AdminCommandResult):
            raise TypeError("runner returned an invalid result")
        return result
    except Exception as error:
        return AdminCommandResult(
            step.title,
            step.command,
            1,
            stderr=f"{type(error).__name__}: activation operation failed",
        )


def _run_rollback_steps(
    runner: Callable[[AdminCommandStep], AdminCommandResult],
    steps: Sequence[AdminCommandStep],
) -> tuple[AdminCommandResult, ...]:
    return tuple(_run_audited_step(runner, step) for step in steps)


def execute_codex_dispatch_activation_plan(
    plan: AdminChangePlan,
    *,
    runner: Callable[[AdminCommandStep], AdminCommandResult] | None = None,
    adapter_enabled: bool = False,
) -> AdminExecutionResult:
    if not adapter_enabled:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, "exact approved adapter enablement is required", ())
    spec = validate_codex_dispatch_activation_plan(plan)
    if not plan.approved or plan.canceled or plan.archived:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, "Codex dispatch activation requires an uncanceled approved plan", ())
    verify_reviewed_source_binding(spec)
    if runner is None:
        from .admin import run_admin_command_step
        runner = run_admin_command_step
    try:
        with _activation_lock():
            command_results: list[AdminCommandResult] = []
            for step in plan.steps:
                result = _run_audited_step(runner, step)
                command_results.append(result)
                if result.exit_code != 0:
                    rollback = _run_rollback_steps(runner, plan.rollback_steps)
                    return AdminExecutionResult(f"admin.exec.{plan.id}.failed", plan.id, AdminExecutionStatus.FAILED, f"Codex dispatch activation failed during step: {result.title}; rollback attempted", tuple(command_results), rollback_results=rollback)
            verification: list[AdminCommandResult] = []
            for step in plan.verification_steps:
                result = _run_audited_step(runner, step)
                verification.append(result)
                if result.exit_code != 0:
                    rollback = _run_rollback_steps(runner, plan.rollback_steps)
                    return AdminExecutionResult(f"admin.exec.{plan.id}.failed", plan.id, AdminExecutionStatus.FAILED, f"Codex dispatch activation verification failed during step: {result.title}; rollback attempted", tuple(command_results), tuple(verification), rollback)
            return AdminExecutionResult(f"admin.exec.{plan.id}.completed", plan.id, AdminExecutionStatus.COMPLETED, "approved Codex dispatch activation completed and verified", tuple(command_results), tuple(verification))
    except RuntimeError as error:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, str(error), ())


__all__ = [
    "CANONICAL_SOURCE_ROOT", "CODEX_DISPATCH_ACTIVATION_SCHEMA", "CODEX_HOME", "CodexDispatchActivationSpec",
    "EUID_HOME", "build_codex_dispatch_activation_spec", "codex_dispatch_activation_plan_digest",
    "execute_codex_dispatch_activation_marker", "execute_codex_dispatch_activation_plan",
    "plan_codex_dispatch_activation", "validate_codex_dispatch_activation_plan", "verify_reviewed_source_binding",
]
