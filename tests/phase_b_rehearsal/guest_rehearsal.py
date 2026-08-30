"""Disposable, network-isolated Phase B rehearsal executed inside a guest.

Importing this module is deliberately inert.  All filesystem, identity,
systemd, PTY, and source-tree work is behind :func:`main` and only runs after
the guest preflight has failed closed.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pty
import pwd
import re
import stat
import subprocess
import sys
import termios
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from urllib.error import HTTPError


REHEARSAL_ROOT = Path("/var/lib/overseer-phase-b-rehearsal")
CANARY_UID = 984
BRIDGE_UID = 1000
SOURCE_ROOT = Path("/mnt/overseer-source")
GUEST_ETC = Path("/etc/overseer-phase-b-rehearsal")
GUEST_RUN = Path("/run/overseer-phase-b-rehearsal")
GUEST_OPT = Path("/opt/overseer-phase-b-rehearsal")
GUEST_SYSTEMD = Path("/etc/systemd/system")
CANARY_STATE_ROOT = Path("/var/lib/overseer-canary")
EXECUTOR_STATE_ROOT = Path("/var/lib/overseer-executor")
OVERSEER_RUNTIME = Path("/run/overseer")
CANARY_RUNTIME = Path("/run/overseer-canary")

ADMIN_SECRET = "phase-b-rehearsal-admin-secret"
ROADEX_SECRET = "phase-b-rehearsal-roadex-secret"
API_TOKEN = "phase-b-rehearsal-api-token"

RESULT_SCHEMA = "overseer.phase-b-disposable-rehearsal.v1"
RESULT_BEGIN = "OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN"
RESULT_END = "OVERSEER_PHASE_B_REHEARSAL_RESULT_END"

REQUIRED_CONTROLS = frozenset(
    {
        "systemdCredentials",
        "secureTty",
        "socketActivation",
        "unixPeerIdentity",
        "apiHealth",
        "usageBridge",
        "sessionBridge",
        "allowlistedRestart",
        "replayNoMutation",
        "unlistedRejected",
        "authorityLockCreated",
        "quiescentStop",
        "evidenceSealed",
        "cleanupStateDurable",
        "rollbackReplay",
    }
)

_RESULT_STAGES = frozenset(
    {
        "preflight",
        "provisioning",
        "authorization",
        "canary-start",
        "canary-acceptance",
        "quiescent-stop",
        "evidence-seal",
        "cleanup",
        "rollback-replay",
        "phase-complete",
    }
)
_IDENTIFIER_KEY = re.compile(r"[A-Za-z][A-Za-z0-9]{0,31}\Z")
_IDENTIFIER_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_FAILURE = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z")
_SECRET_MARKERS = re.compile(
    r"(?:secret|token|password|credential|verifier|private[_ -]?key|argv|environment|human[_ -]?input)",
    re.IGNORECASE,
)
_DISPOSABLE_UNITS = (
    "overseer-approval-smoke.service",
    "overseer-codex-user-bridge.socket",
    "overseer-codex-user-bridge.service",
    "overseer-admin-executor.socket",
    "overseer-api-canary.service",
)
_UNITS_MAY_BE_ACTIVE = False
_PREFLIGHT_PASSED = False


class PreflightError(RuntimeError):
    """Raised when the rehearsal is not running in its intended guest."""


class RehearsalError(RuntimeError):
    """Raised for a bounded disposable rehearsal failure."""


class StageTracker:
    """Retain the last bounded stage even when a nested operation raises."""

    def __init__(self) -> None:
        self.current = "preflight"

    def advance(self, stage: str) -> None:
        if stage not in _RESULT_STAGES:
            raise RehearsalError("stage is not bounded")
        self.current = stage


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _reject_secret_text(value: str, *, field: str) -> None:
    if any(secret in value for secret in (ADMIN_SECRET, ROADEX_SECRET, API_TOKEN)):
        raise ValueError(f"secret-bearing {field} is not serializable")
    if _SECRET_MARKERS.search(value):
        raise ValueError(f"secret-bearing {field} is not serializable")


def _validate_identifiers(identifiers: object) -> dict[str, str]:
    if identifiers is None:
        return {}
    if not isinstance(identifiers, Mapping):
        raise ValueError("identifiers must be a mapping")
    result: dict[str, str] = {}
    for key, value in identifiers.items():
        if not isinstance(key, str) or _IDENTIFIER_KEY.fullmatch(key) is None:
            raise ValueError("identifier key is invalid")
        _reject_secret_text(key, field="identifier key")
        if not isinstance(value, str) or _IDENTIFIER_VALUE.fullmatch(value) is None:
            raise ValueError("identifier value is invalid")
        _reject_secret_text(value, field="identifier value")
        result[key] = value
    if len(result) > 8:
        raise ValueError("identifier count is unbounded")
    return dict(sorted(result.items()))


def _validate_controls(controls: object) -> dict[str, bool]:
    if not isinstance(controls, Mapping) or set(controls) != REQUIRED_CONTROLS:
        raise ValueError("control set is invalid")
    if any(type(key) is not str for key in controls):
        raise ValueError("control key is invalid")
    if any(type(value) is not bool for value in controls.values()):
        raise ValueError("control values must be booleans")
    return {key: controls[key] for key in sorted(REQUIRED_CONTROLS)}


def serialize_result(
    *,
    status: str,
    stage: str,
    controls: Mapping[str, object],
    identifiers: Mapping[str, object] | None = None,
    failure: str | None = None,
) -> str:
    """Return one canonical, bounded, secret-free serial result line."""

    if status not in {"passed", "failed"}:
        raise ValueError("status is invalid")
    if not isinstance(stage, str) or stage not in _RESULT_STAGES:
        raise ValueError("stage is invalid")
    if failure is not None:
        if not isinstance(failure, str) or _FAILURE.fullmatch(failure) is None:
            raise ValueError("failure is invalid")
        _reject_secret_text(failure, field="failure")
    if status == "passed" and failure is not None:
        raise ValueError("passed result cannot contain failure")
    if status == "failed" and failure is None:
        raise ValueError("failed result requires failure")
    record: dict[str, object] = {
        "schemaVersion": RESULT_SCHEMA,
        "status": status,
        "stage": stage,
        "controls": _validate_controls(controls),
        "identifiers": _validate_identifiers(identifiers),
        "failure": failure,
    }
    return _canonical(record) + "\n"


def frame_serial_result(record: str) -> str:
    """Frame exactly one already-serialized result for the serial console."""

    if not isinstance(record, str) or not record.endswith("\n") or record.count("\n") != 1:
        raise ValueError("serial result must contain one JSON line")
    try:
        parsed = json.loads(record)
    except json.JSONDecodeError as error:
        raise ValueError("serial result is not JSON") from error
    if not isinstance(parsed, dict) or _canonical(parsed) + "\n" != record:
        raise ValueError("serial result is not canonical")
    if set(parsed) != {"schemaVersion", "status", "stage", "controls", "identifiers", "failure"}:
        raise ValueError("serial result schema is invalid")
    try:
        validated = serialize_result(
            status=parsed["status"],
            stage=parsed["stage"],
            controls=parsed["controls"],
            identifiers=parsed["identifiers"],
            failure=parsed["failure"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("serial result contract is invalid") from error
    if parsed["schemaVersion"] != RESULT_SCHEMA or validated != record:
        raise ValueError("serial result contract is invalid")
    return f"{RESULT_BEGIN}\n{record}{RESULT_END}\n"


def _read(path: Path, *, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PreflightError(f"could not read {label}") from error


def _mountinfo_value(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _source_mount_is_read_only(proc_root: Path, source_root: Path = SOURCE_ROOT) -> bool:
    for line in _read(proc_root / "self/mountinfo", label="mountinfo").splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) <= separator + 3 or len(fields) < 6:
            continue
        mountpoint = _mountinfo_value(fields[4])
        mount_options = set(fields[5].split(","))
        super_options = set(fields[separator + 3].split(","))
        if mountpoint == str(source_root):
            return "ro" in mount_options or "ro" in super_options
    return False


def _network_is_quiescent(sys_root: Path) -> bool:
    interfaces = sys_root / "class/net"
    try:
        names = sorted(path.name for path in interfaces.iterdir())
    except OSError as error:
        raise PreflightError("network interface inventory is unavailable") from error
    for name in names:
        if name == "lo":
            continue
        try:
            state = (interfaces / name / "operstate").read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise PreflightError("network interface state is unavailable") from error
        if state != "down":
            return False
    return True


def validate_preflight_snapshot(snapshot: Mapping[str, object]) -> None:
    """Validate a bounded snapshot so every rejection is source-testable."""

    if snapshot.get("euid") != 0:
        raise PreflightError("rehearsal requires root")
    if snapshot.get("pid1") != "systemd":
        raise PreflightError("PID 1 is not systemd")
    if (
        snapshot.get("sourceIsDirectory") is not True
        or snapshot.get("sourceIsSymlink") is not False
        or snapshot.get("sourceMountReadOnly") is not True
    ):
        raise PreflightError("source checkout is not a read-only mount")
    interfaces = snapshot.get("interfaces")
    if not isinstance(interfaces, Mapping):
        raise PreflightError("network interface inventory is unavailable")
    for name, state_value in interfaces.items():
        if not isinstance(name, str) or not isinstance(state_value, str):
            raise PreflightError("network interface inventory is unavailable")
        if name != "lo" and state_value != "down":
            raise PreflightError("a non-loopback network interface is up")
    users = snapshot.get("users")
    groups = snapshot.get("groups")
    if not isinstance(users, Mapping) or not isinstance(groups, Mapping):
        raise PreflightError("guest identity inventory is unavailable")
    for uid, expected_name in ((CANARY_UID, "overseer"), (BRIDGE_UID, "god")):
        user = users.get(uid)
        group = groups.get(uid)
        if (
            not isinstance(user, Mapping)
            or not isinstance(group, Mapping)
            or user.get("name") != expected_name
            or user.get("uid") != uid
            or user.get("gid") != uid
            or group.get("name") != expected_name
            or group.get("gid") != uid
        ):
            raise PreflightError(f"identity {uid} is not bound exactly")


def _preflight_snapshot(
    *, source_root: Path, proc_root: Path, sys_root: Path
) -> dict[str, object]:
    try:
        interfaces = {
            path.name: (path / "operstate").read_text(encoding="ascii").strip()
            for path in sorted((sys_root / "class/net").iterdir())
        }
        users: dict[int, dict[str, object]] = {}
        groups: dict[int, dict[str, object]] = {}
        for uid in (CANARY_UID, BRIDGE_UID):
            user = pwd.getpwuid(uid)
            group = grp.getgrgid(uid)
            users[uid] = {"name": user.pw_name, "uid": user.pw_uid, "gid": user.pw_gid}
            groups[uid] = {"name": group.gr_name, "gid": group.gr_gid}
    except (KeyError, OSError, UnicodeError) as error:
        raise PreflightError("guest preflight inventory is unavailable") from error
    return {
        "euid": os.geteuid(),
        "pid1": _read(proc_root / "1/comm", label="PID 1 identity").strip(),
        "sourceIsDirectory": source_root.is_dir(),
        "sourceIsSymlink": source_root.is_symlink(),
        "sourceMountReadOnly": _source_mount_is_read_only(proc_root, source_root),
        "interfaces": interfaces,
        "users": users,
        "groups": groups,
    }


def preflight(
    *,
    source_root: Path | None = None,
    proc_root: Path | None = None,
    sys_root: Path | None = None,
) -> None:
    """Fail closed unless the process is root in the intended isolated guest."""

    global _PREFLIGHT_PASSED
    source_root = SOURCE_ROOT if source_root is None else source_root
    proc_root = Path("/proc") if proc_root is None else proc_root
    sys_root = Path("/sys") if sys_root is None else sys_root
    validate_preflight_snapshot(
        _preflight_snapshot(source_root=source_root, proc_root=proc_root, sys_root=sys_root)
    )
    _PREFLIGHT_PASSED = True


def _safe_path(path: Path) -> Path:
    allowed_roots = (
        REHEARSAL_ROOT,
        GUEST_ETC,
        GUEST_RUN,
        GUEST_OPT,
        CANARY_STATE_ROOT,
        EXECUTOR_STATE_ROOT,
        OVERSEER_RUNTIME,
        CANARY_RUNTIME,
    )
    allowed_units = {
        "overseer-approval-smoke.service",
        "overseer-api-canary.service",
        "overseer-admin-executor.socket",
        "overseer-admin-executor@.service",
        "overseer-codex-user-bridge.socket",
        "overseer-codex-user-bridge.service",
    }
    if path.parent == GUEST_SYSTEMD and path.name in allowed_units:
        return path
    resolved = path.resolve()
    if not any(resolved == root.resolve() or root.resolve() in resolved.parents for root in allowed_roots):
        raise RehearsalError(f"path escaped disposable root: {path}")
    return path


def _mkdir(path: Path, mode: int) -> None:
    _safe_path(path)
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise RehearsalError(f"disposable directory is not a directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    os.chmod(path, mode)


def _write(path: Path, data: bytes, mode: int) -> None:
    _safe_path(path)
    if path.exists() or path.is_symlink():
        raise RehearsalError(f"disposable artifact already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def _write_precreated_unit(path: Path, data: bytes) -> None:
    """Fill one exact root-owned empty unit placeholder inside the sandbox."""

    _safe_path(path)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RehearsalError("guest unit placeholder is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise RehearsalError("guest unit placeholder metadata is invalid")
    flags = os.O_WRONLY | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                raise OSError("unit write did not progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _progress(paths: Mapping[str, Path], event: str) -> None:
    """Append a bounded local ordering record; never include command or input."""

    record_progress(paths["artifacts"] / "progress.jsonl", event)


def record_progress(target: Path, event: str) -> None:
    if event not in {
        "phase-started",
        "authorization-complete",
        "systemd-start",
        "canary-service-started",
        "evidence-seal-started",
        "evidence-seal-complete",
        "cleanup-complete",
    }:
        raise RehearsalError("progress event is not allowlisted")
    with target.open("ab") as stream:
        stream.write((_canonical({"event": event, "secretValuesRecorded": False}) + "\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())


def _guest_paths() -> dict[str, Path]:
    _mkdir(REHEARSAL_ROOT, 0o700)
    _mkdir(CANARY_STATE_ROOT, 0o711)
    instance = hashlib.sha256(b"overseer-phase-b-disposable-instance").hexdigest()[:32]
    state_directory = CANARY_STATE_ROOT / instance
    _mkdir(state_directory, 0o700)
    _mkdir(EXECUTOR_STATE_ROOT, 0o700)
    _mkdir(OVERSEER_RUNTIME, 0o710)
    os.chown(OVERSEER_RUNTIME, 0, CANARY_UID)
    _mkdir(CANARY_RUNTIME, 0o700)
    os.chown(CANARY_RUNTIME, CANARY_UID, CANARY_UID)
    paths = {
        "state": state_directory,
        "artifacts": REHEARSAL_ROOT / "artifacts",
        "runtime": CANARY_RUNTIME,
        "etc": GUEST_ETC,
        "opt": GUEST_OPT,
        "run": CANARY_RUNTIME,
        "executor": EXECUTOR_STATE_ROOT,
        "package": REHEARSAL_ROOT / "package",
    }
    for name, path in paths.items():
        if name == "state":
            continue
        _mkdir(path, 0o700)
    return paths


def canary_namespace_contract(state_directory: Path) -> dict[str, dict[str, int]]:
    """Return the exact ownership contract required by the real Unix paths."""

    if state_directory.parent != CANARY_STATE_ROOT or re.fullmatch(
        r"[0-9a-f]{32}", state_directory.name
    ) is None:
        raise RehearsalError("canary state directory is not instance-bound")
    return {
        "stateDirectory": {"uid": CANARY_UID, "gid": CANARY_UID, "mode": 0o700},
        "store": {"uid": CANARY_UID, "gid": CANARY_UID, "mode": 0o600},
        "runtimeParent": {"uid": 0, "gid": CANARY_UID, "mode": 0o710},
        "executorSocket": {"uid": CANARY_UID, "gid": 0, "mode": 0o600},
        "bridgeSocket": {"uid": CANARY_UID, "gid": 0, "mode": 0o600},
        "apiRuntime": {"uid": CANARY_UID, "gid": CANARY_UID, "mode": 0o700},
        "apiSocket": {"uid": CANARY_UID, "gid": CANARY_UID, "mode": 0o600},
    }


def handoff_canary_namespace(
    state_directory: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
    chown=os.chown,
    chmod=os.chmod,
) -> None:
    """Transfer one closed three-store namespace to UID/GID 984."""

    expected_names = {
        "overseer.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
    }
    try:
        state_metadata = state_directory.lstat()
        children = tuple(state_directory.iterdir())
    except OSError as error:
        raise RehearsalError("canary namespace could not be inspected") from error
    if (
        not stat.S_ISDIR(state_metadata.st_mode)
        or stat.S_IMODE(state_metadata.st_mode) != 0o700
        or state_metadata.st_uid != expected_owner_uid
        or state_metadata.st_gid != expected_owner_gid
        or {child.name for child in children} != expected_names
    ):
        raise RehearsalError("canary namespace contains unexpected state")
    for child in children:
        metadata = child.lstat()
        if (
            child.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != expected_owner_uid
            or metadata.st_gid != expected_owner_gid
            or metadata.st_nlink != 1
        ):
            raise RehearsalError("canary namespace contains unexpected artifact metadata")
    for child in sorted(children):
        chown(child, CANARY_UID, CANARY_UID)
        chmod(child, 0o600)
    chown(state_directory, CANARY_UID, CANARY_UID)
    chmod(state_directory, 0o700)


def render_guest_units(
    *, source_root: Path, python_path: Path, state_directory: Path
) -> dict[str, str]:
    """Render deterministic production-path units without touching systemd."""

    source = source_root.resolve()
    python = python_path.resolve()
    store = state_directory / "overseer.sqlite3"
    common = (
        f"WorkingDirectory={source}\n"
        f"Environment=PYTHONPATH={source / 'src'}\n"
        "Environment=PYTHONDONTWRITEBYTECODE=1\n"
        "PrivateNetwork=yes\nNoNewPrivileges=yes\nProtectSystem=strict\n"
    )
    return {
        "overseer-approval-smoke.service": (
            "[Unit]\nDescription=Disposable Phase B allowlisted smoke\n"
            "[Service]\nType=oneshot\nExecStart=/usr/bin/true\n"
        ),
        "overseer-api-canary.service": (
            "[Unit]\nDescription=Disposable Phase B canary API\n"
            "After=overseer-admin-executor.socket overseer-codex-user-bridge.socket\n"
            "Requires=overseer-admin-executor.socket overseer-codex-user-bridge.socket\n"
            "[Service]\nType=simple\nUser=984\nGroup=984\n"
            "LoadCredential=api-token:/etc/overseer-phase-b-rehearsal/api-token\n"
            "LoadCredential=admin-approval-verifier.json:/etc/overseer-phase-b-rehearsal/admin-approval-verifier.json\n"
            "LoadCredential=roadex-fixture-approval-verifier.json:/etc/overseer-phase-b-rehearsal/roadex-fixture-approval-verifier.json\n"
            "LoadCredential=admin-ticket-private-key:/etc/overseer-phase-b-rehearsal/admin-ticket-private-key\n"
            "Environment=OVERSEER_DEDICATED_PRINCIPAL=1\n"
            "Environment=OVERSEER_ADMIN_TICKET_PRIVATE_KEY=%d/admin-ticket-private-key\n"
            "Environment=OVERSEER_ADMIN_EXECUTOR_SOCKET=/run/overseer/admin-executor.sock\n"
            "Environment=OVERSEER_USER_BRIDGE_SOCKET=/run/overseer/codex-user-bridge.sock\n"
            "Environment=OVERSEER_USER_BRIDGE_SERVER_UID=1000\n"
            + common
            + f"ExecStart={python} -B -s -P -m overseer.cli serve-api "
            f"--store {store} --socket-path {CANARY_RUNTIME / 'api.sock'} "
            f"--socket-peer-uid 0 --socket-owner-uid {CANARY_UID} "
            f"--socket-owner-gid {CANARY_UID} --auth-token-file %d/api-token "
            "--admin-approval-verifier-file %d/admin-approval-verifier.json "
            "--roadex-fixture-approval-verifier-file %d/roadex-fixture-approval-verifier.json\n"
            f"ReadWritePaths={state_directory} {CANARY_RUNTIME}\n"
        ),
        "overseer-codex-user-bridge.socket": (
            "[Unit]\nDescription=Disposable Overseer user bridge socket\n"
            "[Socket]\nListenStream=/run/overseer/codex-user-bridge.sock\n"
            "SocketMode=0600\nSocketUser=984\nSocketGroup=0\n"
        ),
        "overseer-codex-user-bridge.service": (
            "[Unit]\nRequires=overseer-codex-user-bridge.socket\n"
            "[Service]\nType=simple\nUser=1000\nGroup=1000\n"
            + common
            + f"ExecStart={python} -B -s -P -m overseer.user_bridge serve "
            f"--socket-fd=3 --peer-uid={CANARY_UID}\n"
        ),
        "overseer-admin-executor.socket": (
            "[Unit]\nDescription=Disposable Overseer admin executor socket\n"
            "[Socket]\nListenStream=/run/overseer/admin-executor.sock\n"
            "SocketMode=0600\nSocketUser=984\nSocketGroup=0\nAccept=yes\n"
        ),
        "overseer-admin-executor@.service": (
            "[Unit]\nDescription=Disposable Overseer admin executor connection\n"
            "[Service]\nType=oneshot\nUser=root\nGroup=root\nStandardInput=socket\nStandardOutput=socket\n"
            + common
            + f"ExecStart={python} -B -s -P -m overseer.admin_executor serve-one "
            f"--allowlist-file {GUEST_ETC / 'allowlist.json'} "
            f"--public-key-file {GUEST_ETC / 'admin-ticket-public-key'} "
            f"--ledger {EXECUTOR_STATE_ROOT / 'executor-ledger.sqlite3'}\n"
            f"ReadWritePaths={EXECUTOR_STATE_ROOT}\n"
        ),
    }


def _provision(paths: Mapping[str, Path], *, source: Path) -> dict[str, str]:
    """Create only deterministic guest-local stores, credentials, and units."""

    config = paths["etc"]
    canary = paths["state"]
    source_path = source.resolve()
    _write(config / "api-token", (API_TOKEN + "\n").encode("ascii"), 0o600)
    _write(config / "allowlist.json", _canonical({
        "schemaVersion": "overseer.admin-executor-allowlist.v1",
        "allowed": [{"operation": "restart-system-unit", "unit": "overseer-approval-smoke.service"}],
    }).encode("ascii") + b"\n", 0o600)
    sys.path.insert(0, str(source / "src"))
    try:
        from overseer.approval_auth import create_approval_document, write_approval_document
        from overseer.store import SQLiteStore
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    except ImportError as error:
        raise RehearsalError("guest source checkout is not importable") from error
    write_approval_document(
        config / "admin-approval-verifier.json",
        create_approval_document(ADMIN_SECRET, "admin-plan-approval"),
    )
    write_approval_document(
        config / "roadex-fixture-approval-verifier.json",
        create_approval_document(ROADEX_SECRET, "roadex-fixture-approval"),
    )
    seed = hashlib.sha256(b"overseer-phase-b-disposable-rehearsal-ed25519").digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    _write(
        config / "admin-ticket-private-key",
        private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
        0o600,
    )
    _write(
        config / "admin-ticket-public-key",
        private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
        0o644,
    )

    store = SQLiteStore(canary / "overseer.sqlite3")
    try:
        store.initialize()
    finally:
        store.close()
    for name in ("psychlo-bridge.sqlite3", "roadex-relay.sqlite3"):
        _write(canary / name, b"", 0o600)
    handoff_canary_namespace(
        canary,
        expected_owner_uid=0,
        expected_owner_gid=0,
    )
    units = render_guest_units(
        source_root=source_path,
        python_path=Path(sys.executable),
        state_directory=canary,
    )
    for name, content in units.items():
        _write_precreated_unit(GUEST_SYSTEMD / name, content.encode("utf-8"))
    return {
        "sourceCommit": _source_commit(source),
        "canaryInstanceId": canary.name,
        "packageId": "disposable",
    }


def _source_commit(source: Path) -> str:
    try:
        completed = subprocess.run(
            ("/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RehearsalError("source commit could not be identified") from error
    commit = completed.stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise RehearsalError("source commit identity is invalid")
    return commit


def _systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ("/usr/bin/systemctl", "--no-pager", *arguments),
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def exercise_production_hidden_reader(progress_ledger: Path) -> bool:
    """Drive the production hidden reader through a real disposable PTY."""

    from overseer import activation_package

    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    values: list[str] = []
    errors: list[BaseException] = []

    def read_value() -> None:
        try:
            values.append(
                activation_package._read_canary_secret_from_terminal(slave, "")
            )
        except BaseException as error:
            errors.append(error)

    reader = threading.Thread(target=read_value, daemon=True)
    reader.start()
    hidden_observed = False
    deadline = time.monotonic() + 2.0
    try:
        while reader.is_alive() and time.monotonic() < deadline:
            if not termios.tcgetattr(slave)[3] & termios.ECHO:
                hidden_observed = True
                break
            time.sleep(0.005)
        if not hidden_observed:
            raise RehearsalError("production hidden reader did not disable terminal echo")
        os.write(master, b"phase-b-throwaway-input\n")
        reader.join(2.0)
        if reader.is_alive() or errors or values != ["phase-b-throwaway-input"]:
            raise RehearsalError("production hidden reader did not complete safely")
        restored = bool(termios.tcgetattr(slave)[3] & termios.ECHO)
    finally:
        os.close(master)
        os.close(slave)
    if not restored or not original[3] & termios.ECHO:
        raise RehearsalError("production hidden reader did not restore terminal echo")
    record_progress(progress_ledger, "authorization-complete")
    return True


def controls_from_evidence(
    evidence: Mapping[str, Mapping[str, object]],
) -> dict[str, bool]:
    """Convert exact observed evidence to controls; reject every missing proof."""

    if set(evidence) != REQUIRED_CONTROLS:
        raise RehearsalError("rehearsal evidence control set is incomplete")
    controls: dict[str, bool] = {}
    for control in sorted(REQUIRED_CONTROLS):
        item = evidence.get(control)
        if not isinstance(item, Mapping) or item.get("observed") is not True:
            raise RehearsalError(f"{control} was not observed")
        controls[control] = True
    return controls


def verify_systemd_runtime_evidence(
    *,
    load_credentials: set[str],
    socket_metadata: Mapping[str, Mapping[str, object]],
    accepted_before: Mapping[str, int],
    accepted_after: Mapping[str, int],
    receipt_observed: bool,
) -> dict[str, dict[str, bool]]:
    required_credentials = {
        "api-token",
        "admin-approval-verifier.json",
        "roadex-fixture-approval-verifier.json",
        "admin-ticket-private-key",
    }
    required_sockets = {
        "executor": {"uid": CANARY_UID, "gid": 0, "mode": 0o600},
        "bridge": {"uid": CANARY_UID, "gid": 0, "mode": 0o600},
        "api": {"uid": CANARY_UID, "gid": CANARY_UID, "mode": 0o600},
    }
    activated = all(
        type(accepted_before.get(name)) is int
        and type(accepted_after.get(name)) is int
        and accepted_after[name] > accepted_before[name]
        for name in ("executor", "bridge")
    )
    if (
        load_credentials != required_credentials
        or dict(socket_metadata) != required_sockets
        or not activated
        or receipt_observed is not True
    ):
        raise RehearsalError("systemd credential or socket activation evidence is incomplete")
    return {
        "systemdCredentials": {"observed": True},
        "socketActivation": {"observed": True},
    }


def inspect_authority_lock(store: Path, *, expected_uid: int) -> bool:
    """Inspect the real lock created by the API; never create a substitute."""

    from overseer.admin_authority import admin_authority_lock_path

    lock = admin_authority_lock_path(store)
    try:
        metadata = lock.lstat()
    except OSError as error:
        raise RehearsalError("real admin authority lock was not created") from error
    if (
        lock.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise RehearsalError("real admin authority lock metadata is invalid")
    return True


def run_production_cleanup_and_replay(
    activation,
    *,
    contract: Mapping[str, object],
    package_root: Path,
    package_digest: str,
    snapshot,
) -> dict[str, object]:
    """Use production cleanup and rollback entry points, then prove no replay mutation."""

    if contract.get("schemaVersion") != activation.ACTIVATION_CONTRACT_SCHEMA:
        raise RehearsalError("production activation contract schema is required")
    durable = activation._execute_resilient_cleanup(
        contract,
        package_digest=package_digest,
        originating_failure="RehearsalControlledFailure",
        require_canary_evidence=True,
    )
    if durable is not True:
        raise RehearsalError("production cleanup state is not durable")
    before = snapshot()
    result = activation.execute_approved_rollback(package_root)
    after = snapshot()
    if (
        before != after
        or result.get("status") != "aborted_before_cutover"
        or result.get("replayed") is not True
    ):
        raise RehearsalError("production rollback replay mutated retained evidence")
    return {"status": "aborted_before_cutover", "replayed": True}


def _exercise_real_api(paths: Mapping[str, Path]) -> dict[str, dict[str, bool]]:
    """Exercise the source API/client over the canary Unix socket."""

    from overseer.client import OverseerApiClient

    token = (GUEST_ETC / "api-token").read_text(encoding="ascii").strip()
    transport = {
        "base_url": "http://localhost",
        "auth_token": token,
        "unix_socket_path": str(CANARY_RUNTIME / "api.sock"),
        "expected_server_uid": CANARY_UID,
    }
    ordinary = OverseerApiClient(**transport)
    health = ordinary.health()
    usage = ordinary._get("/health/codex-usage")
    sessions = ordinary._post(
        "/agent-sessions/discover",
        {"provider_id": "codex", "instance_id": "phase-b-rehearsal"},
    )
    if health.get("ok") is not True or health.get("service") != "overseer-api":
        raise RehearsalError("API health control failed")
    if usage.get("source") != "codex.usage.snapshot.v1":
        raise RehearsalError("usage bridge control failed")
    if sessions.get("mutation_performed") is not False or sessions.get("host_mutation_performed") is not False:
        raise RehearsalError("session bridge was not read-only")

    admin = OverseerApiClient(**transport, approval_token=ADMIN_SECRET)
    wrong_scope = OverseerApiClient(**transport, approval_token=ROADEX_SECRET)
    plan_id = "admin.phase-b-rehearsal.smoke"
    ordinary.plan_admin_change({
        "plan_id": plan_id,
        "kind": "system_service_restart",
        "target": "overseer-approval-smoke.service",
        "reason": "disposable Phase B allowlisted restart control",
        "current_state": "inactive",
    })
    rejected = False
    try:
        ordinary.approve_admin_change(plan_id)
    except HTTPError as error:
        rejected = error.code == 403
    wrong_scope_rejected = False
    try:
        wrong_scope.approve_admin_change(plan_id)
    except HTTPError as error:
        wrong_scope_rejected = error.code == 403
    approved = admin.approve_admin_change(plan_id)
    executed = ordinary.execute_admin_change({"plan_id": plan_id})
    replayed = ordinary.execute_admin_change({"plan_id": plan_id})
    if not rejected or not wrong_scope_rejected or approved.get("approved") is not True:
        raise RehearsalError("independent approval token control failed")
    if executed.get("mutation_performed") is not True or replayed.get("replayed") is not True or replayed.get("mutation_performed") is not False:
        raise RehearsalError("allowlisted executor replay control failed")

    unlisted_id = "admin.phase-b-rehearsal.unlisted"
    ordinary.plan_admin_change({
        "plan_id": unlisted_id,
        "kind": "system_service_restart",
        "target": "overseer-api.service",
        "reason": "disposable unlisted-unit rejection control",
        "current_state": "inactive",
    })
    admin.approve_admin_change(unlisted_id)
    unlisted = ordinary.execute_admin_change({"plan_id": unlisted_id})
    if unlisted.get("status") != "blocked" or unlisted.get("mutation_performed") is not False:
        raise RehearsalError("unlisted unit was not rejected")
    lock_observed = inspect_authority_lock(
        paths["state"] / "overseer.sqlite3",
        expected_uid=CANARY_UID,
    )
    return {
        "apiHealth": {"observed": True},
        "usageBridge": {"observed": True},
        "sessionBridge": {"observed": True},
        "allowlistedRestart": {"observed": True},
        "replayNoMutation": {"observed": True},
        "unlistedRejected": {"observed": True},
        "unixPeerIdentity": {"observed": True},
        "authorityLockCreated": {"observed": lock_observed},
    }


def _start_disposable_units() -> None:
    global _UNITS_MAY_BE_ACTIVE
    _UNITS_MAY_BE_ACTIVE = True
    _systemctl("daemon-reload")
    _systemctl(
        "start",
        "overseer-codex-user-bridge.socket",
        "overseer-admin-executor.socket",
    )
    _systemctl("start", "overseer-api-canary.service")


def stop_disposable_units(*, systemctl=None, processes_for_uid=None) -> None:
    """Stop and verify every disposable boundary before clearing cleanup state."""

    global _UNITS_MAY_BE_ACTIVE
    systemctl = _systemctl if systemctl is None else systemctl
    processes_for_uid = _processes_for_uid if processes_for_uid is None else processes_for_uid
    failures: list[str] = []
    for unit in reversed(_DISPOSABLE_UNITS):
        try:
            result = systemctl("stop", unit, check=False)
            if int(result.returncode) != 0:
                failures.append(unit)
        except (OSError, subprocess.SubprocessError, AttributeError):
            failures.append(unit)
    for unit in _DISPOSABLE_UNITS:
        try:
            result = systemctl("is-active", "--quiet", unit, check=False)
            if int(result.returncode) != 3:
                failures.append(unit)
        except (OSError, subprocess.SubprocessError, AttributeError):
            failures.append(unit)
    if tuple(processes_for_uid(CANARY_UID)):
        failures.append("uid-984-process")
    if failures:
        raise RehearsalError("disposable cleanup did not become quiescent")
    _UNITS_MAY_BE_ACTIVE = False


def _stop_disposable_units() -> None:
    stop_disposable_units()


def _socket_metadata(path: Path) -> dict[str, int]:
    metadata = path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_nlink != 1:
        raise RehearsalError("systemd socket metadata is invalid")
    return {
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _activation_snapshot() -> dict[str, int]:
    executor = _systemctl(
        "show",
        "overseer-admin-executor.socket",
        "--property=NAccepted",
        "--value",
    ).stdout.strip()
    bridge = _systemctl(
        "show",
        "overseer-codex-user-bridge.service",
        "--property=InvocationID",
        "--value",
        check=False,
    ).stdout.strip()
    try:
        executor_count = int(executor or "0", 10)
    except ValueError as error:
        raise RehearsalError("executor socket activation counter is invalid") from error
    return {"executor": executor_count, "bridge": 1 if bridge else 0}


def _load_credential_names() -> set[str]:
    raw_pid = _systemctl(
        "show",
        "overseer-api-canary.service",
        "--property=MainPID",
        "--value",
    ).stdout.strip()
    try:
        pid = int(raw_pid, 10)
    except ValueError as error:
        raise RehearsalError("canary service credential process is unavailable") from error
    if pid <= 0:
        raise RehearsalError("canary service credential process is unavailable")
    directory = Path(f"/proc/{pid}/root/run/credentials/overseer-api-canary.service")
    try:
        children = tuple(directory.iterdir())
    except OSError as error:
        raise RehearsalError("systemd credential namespace is unavailable") from error
    names: set[str] = set()
    for child in children:
        metadata = child.lstat()
        if child.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RehearsalError("systemd credential artifact metadata is invalid")
        names.add(child.name)
    return names


def _poweroff_guest() -> None:
    """End the disposable guest after the single serial result is flushed."""

    try:
        _systemctl("poweroff", check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _processes_for_uid(uid: int) -> tuple[int, ...]:
    matches: list[int] = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            status = (process / "status").read_text(encoding="ascii")
        except (OSError, UnicodeError):
            continue
        for line in status.splitlines():
            if line.startswith("Uid:"):
                values = line.split()
                if len(values) > 1 and values[1] == str(uid):
                    matches.append(int(process.name))
                break
    return tuple(sorted(matches))


def _no_process_for_uid(uid: int) -> bool:
    return not _processes_for_uid(uid)


def _wait_for_canary_socket() -> None:
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        try:
            metadata = (CANARY_RUNTIME / "api.sock").lstat()
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        if stat.S_ISSOCK(metadata.st_mode):
            return
        raise RehearsalError("canary API runtime path is not a socket")
    raise RehearsalError("canary API socket did not become ready")


def _progress_order_is_authorized_first(ledger: Path) -> bool:
    events = [
        json.loads(line)["event"]
        for line in ledger.read_text(encoding="ascii").splitlines()
    ]
    try:
        return events.index("authorization-complete") < events.index("systemd-start")
    except ValueError:
        return False


def _activation_contract(paths: Mapping[str, Path], activation) -> dict[str, object]:
    god = pwd.getpwnam("god")
    state = paths["state"]
    cleanup = ["/usr/bin/systemctl", "stop", *_DISPOSABLE_UNITS]
    return {
        "schemaVersion": activation.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(paths["package"].resolve()),
        "account": {
            "user": "overseer",
            "uid": CANARY_UID,
            "group": "overseer",
            "gid": CANARY_UID,
        },
        "sourceStore": {"uid": god.pw_uid, "gid": god.pw_gid},
        "stagingAndCanaryCommands": [["/usr/bin/true"]],
        "cutoverCommands": [["/usr/bin/true"]],
        "rollbackCommands": [["/usr/bin/true"]],
        "canary": {
            "canaryInstanceId": state.name,
            "stateDirectory": str(state),
            "store": str(state / "overseer.sqlite3"),
            "psychloBridgeDatabase": str(state / "psychlo-bridge.sqlite3"),
            "roadexRelayDatabase": str(state / "roadex-relay.sqlite3"),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
            "failureCleanupCommands": [cleanup],
        },
    }


class _GuestActivationAdapter:
    """Delegate lifecycle work while adapting only absent package provenance."""

    def __init__(self, activation, *, digest: str, contract: Mapping[str, object]) -> None:
        self._activation = activation
        self._digest = digest
        self._contract = contract
        self.ACTIVATION_CONTRACT_SCHEMA = activation.ACTIVATION_CONTRACT_SCHEMA

    def _execute_resilient_cleanup(self, *args, **kwargs):
        with self._activation._activation_execution_lock():
            return self._activation._execute_resilient_cleanup(*args, **kwargs)

    def execute_approved_rollback(self, package_root: Path) -> dict[str, object]:
        load_original = self._activation._load_activation_approval_for_rollback
        sealed_original = self._activation._sealed_package_json
        self._activation._load_activation_approval_for_rollback = (
            lambda _package: {"packageDigest": self._digest}
        )
        self._activation._sealed_package_json = (
            lambda *_args, **_kwargs: dict(self._contract)
        )
        try:
            return self._activation.execute_approved_rollback(package_root)
        finally:
            self._activation._load_activation_approval_for_rollback = load_original
            self._activation._sealed_package_json = sealed_original


def _retained_evidence_snapshot(state_directory: Path) -> dict[str, object]:
    result: dict[str, object] = {}
    for path in (state_directory, *sorted(state_directory.rglob("*"))):
        metadata = path.lstat()
        relative = "." if path == state_directory else path.relative_to(state_directory).as_posix()
        item: dict[str, object] = {
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "size": metadata.st_size,
            "ctimeNs": metadata.st_ctime_ns,
        }
        if stat.S_ISREG(metadata.st_mode):
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        result[relative] = item
    return result


def _sealed_evidence_is_exact(paths: Mapping[str, Path], activation) -> bool:
    state = paths["state"]
    state_metadata = state.lstat()
    if (
        state_metadata.st_uid != 0
        or state_metadata.st_gid != 0
        or stat.S_IMODE(state_metadata.st_mode) != 0o500
    ):
        return False
    if any(
        child.lstat().st_uid != 0
        or child.lstat().st_gid != 0
        or stat.S_IMODE(child.lstat().st_mode) != 0o400
        for child in state.iterdir()
    ):
        return False
    try:
        runner_state = json.loads(
            activation._activation_state_path().read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        runner_state.get("status") == "aborted_before_cutover"
        and runner_state.get("phase") == "staging_cleanup"
        and runner_state.get("secretValuesRecorded") is False
    )


def _seal_progress_artifacts(paths: Mapping[str, Path]) -> None:
    artifacts = paths["artifacts"]
    for child in artifacts.iterdir():
        metadata = child.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RehearsalError("progress evidence contains an invalid artifact")
        os.chown(child, 0, 0)
        os.chmod(child, 0o400)
    os.chown(artifacts, 0, 0)
    os.chmod(artifacts, 0o500)


def _run_rehearsal(
    tracker: StageTracker,
) -> tuple[str, dict[str, bool], dict[str, str]]:
    if os.environ.get("OVERSEER_PHASE_B_GUEST") != "1":
        raise PreflightError("disposable guest marker is unavailable")
    preflight()
    paths = _guest_paths()
    _progress(paths, "phase-started")
    tracker.advance("provisioning")
    identifiers = _provision(paths, source=SOURCE_ROOT)
    evidence = {
        control: {"observed": False} for control in REQUIRED_CONTROLS
    }

    tracker.advance("authorization")
    evidence["secureTty"] = {
        "observed": exercise_production_hidden_reader(
            paths["artifacts"] / "progress.jsonl"
        )
    }
    _progress(paths, "systemd-start")
    if not _progress_order_is_authorized_first(paths["artifacts"] / "progress.jsonl"):
        raise RehearsalError("authorization progress did not precede systemd start")

    tracker.advance("canary-start")
    _start_disposable_units()
    _wait_for_canary_socket()
    _progress(paths, "canary-service-started")
    accepted_before = _activation_snapshot()

    tracker.advance("canary-acceptance")
    api_evidence = _exercise_real_api(paths)
    accepted_after = _activation_snapshot()
    runtime_evidence = verify_systemd_runtime_evidence(
        load_credentials=_load_credential_names(),
        socket_metadata={
            "executor": _socket_metadata(OVERSEER_RUNTIME / "admin-executor.sock"),
            "bridge": _socket_metadata(OVERSEER_RUNTIME / "codex-user-bridge.sock"),
            "api": _socket_metadata(CANARY_RUNTIME / "api.sock"),
        },
        accepted_before=accepted_before,
        accepted_after=accepted_after,
        receipt_observed=api_evidence["allowlistedRestart"]["observed"],
    )
    evidence.update(api_evidence)
    evidence.update(runtime_evidence)

    tracker.advance("quiescent-stop")
    stop_disposable_units()
    _start_disposable_units()
    _wait_for_canary_socket()

    tracker.advance("cleanup")
    from overseer import activation_package

    digest = hashlib.sha256(b"overseer-phase-b-disposable-package").hexdigest()
    contract = _activation_contract(paths, activation_package)
    adapter = _GuestActivationAdapter(
        activation_package,
        digest=digest,
        contract=contract,
    )
    _progress(paths, "evidence-seal-started")
    replay = run_production_cleanup_and_replay(
        adapter,
        contract=contract,
        package_root=paths["package"],
        package_digest=digest,
        snapshot=lambda: _retained_evidence_snapshot(paths["state"]),
    )
    stop_disposable_units()
    evidence["quiescentStop"] = {"observed": _no_process_for_uid(CANARY_UID)}
    evidence["cleanupStateDurable"] = {
        "observed": _sealed_evidence_is_exact(paths, activation_package)
    }
    evidence["evidenceSealed"] = dict(evidence["cleanupStateDurable"])
    evidence["rollbackReplay"] = {
        "observed": replay == {"status": "aborted_before_cutover", "replayed": True}
    }
    _progress(paths, "evidence-seal-complete")
    _progress(paths, "cleanup-complete")
    _seal_progress_artifacts(paths)
    tracker.advance("rollback-replay")
    controls = controls_from_evidence(evidence)
    return tracker.current, controls, identifiers


def _emit_failure(error: BaseException, stage: str) -> str:
    failure = type(error).__name__
    if _FAILURE.fullmatch(failure) is None:
        failure = "RehearsalError"
    controls = {control: False for control in REQUIRED_CONTROLS}
    return frame_serial_result(serialize_result(status="failed", stage=stage, failure=failure, controls=controls))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guest-only rehearsal and emit exactly one bounded result."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    tracker = StageTracker()
    disposable_guest = os.environ.get("OVERSEER_PHASE_B_GUEST") == "1"
    try:
        _stage, controls, identifiers = _run_rehearsal(tracker)
        result = frame_serial_result(
            serialize_result(status="passed", stage="phase-complete", controls=controls, identifiers=identifiers)
        )
        sys.stdout.write(result)
        sys.stdout.flush()
        if disposable_guest:
            _poweroff_guest()
        return 0
    except BaseException as error:
        if _UNITS_MAY_BE_ACTIVE:
            try:
                stop_disposable_units()
            except BaseException:
                pass
        sys.stdout.write(_emit_failure(error, tracker.current))
        sys.stdout.flush()
        if disposable_guest:
            _poweroff_guest()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
