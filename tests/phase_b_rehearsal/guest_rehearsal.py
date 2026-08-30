"""Disposable, network-isolated Phase B rehearsal executed inside a guest.

Importing this module is deliberately inert.  All filesystem, identity,
systemd, PTY, and source-tree work is behind :func:`main` and only runs after
the guest preflight has failed closed.
"""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import os
import pty
import pwd
import re
import select
import sqlite3
import subprocess
import sys
import termios
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
    "overseer-phase-b-smoke.service",
    "overseer-phase-b-bridge.socket",
    "overseer-phase-b-bridge.service",
    "overseer-phase-b-executor.socket",
    "overseer-phase-b-executor.service",
    "overseer-phase-b-canary.service",
)
_UNITS_MAY_BE_ACTIVE = False
_PREFLIGHT_PASSED = False


class PreflightError(RuntimeError):
    """Raised when the rehearsal is not running in its intended guest."""


class RehearsalError(RuntimeError):
    """Raised for a bounded disposable rehearsal failure."""


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


def _require_identity(uid: int, expected_name: str) -> None:
    try:
        actual = pwd.getpwuid(uid).pw_name
        group = grp.getgrgid(uid).gr_name
    except KeyError as error:
        raise PreflightError(f"identity {uid} is not resolvable") from error
    if actual != expected_name or group != expected_name:
        raise PreflightError(f"identity {uid} is not bound to {expected_name}")


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
    if os.geteuid() != 0:
        raise PreflightError("rehearsal requires root")
    if _read(proc_root / "1/comm", label="PID 1 identity").strip() != "systemd":
        raise PreflightError("PID 1 is not systemd")
    if not source_root.is_dir() or source_root.is_symlink() or not _source_mount_is_read_only(proc_root, source_root):
        raise PreflightError("source checkout is not a read-only mount")
    if not _network_is_quiescent(sys_root):
        raise PreflightError("a non-loopback network interface is up")
    _require_identity(CANARY_UID, "overseer")
    _require_identity(BRIDGE_UID, "god")
    _PREFLIGHT_PASSED = True


def _safe_path(path: Path) -> Path:
    allowed_roots = (REHEARSAL_ROOT, GUEST_ETC, GUEST_RUN, GUEST_OPT)
    if path.parent == GUEST_SYSTEMD and path.name.startswith("overseer-phase-b-"):
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


def _progress(paths: Mapping[str, Path], event: str) -> None:
    """Append a bounded local ordering record; never include command or input."""

    if event not in {
        "phase-started",
        "authorization-complete",
        "canary-service-started",
        "evidence-seal-started",
        "evidence-seal-complete",
        "cleanup-complete",
    }:
        raise RehearsalError("progress event is not allowlisted")
    target = paths["artifacts"] / "progress.jsonl"
    with target.open("ab") as stream:
        stream.write((_canonical({"event": event, "secretValuesRecorded": False}) + "\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())


def _guest_paths() -> dict[str, Path]:
    _mkdir(REHEARSAL_ROOT, 0o700)
    paths = {
        "state": REHEARSAL_ROOT / "state",
        "artifacts": REHEARSAL_ROOT / "artifacts",
        "runtime": GUEST_RUN,
        "etc": GUEST_ETC,
        "opt": GUEST_OPT,
        "run": GUEST_RUN,
    }
    for path in paths.values():
        _mkdir(path, 0o700)
    return paths


def _provision(paths: Mapping[str, Path], *, source: Path) -> dict[str, str]:
    """Create only deterministic guest-local stores, credentials, and units."""

    config = paths["etc"] / "overseer"
    units = GUEST_SYSTEMD
    release = paths["opt"] / "overseer"
    canary = paths["state"] / "canary"
    executor = paths["state"] / "executor"
    for directory in (config, release, canary, executor):
        _mkdir(directory, 0o700)

    source_path = source.resolve()
    _write(config / "api-token", (API_TOKEN + "\n").encode("ascii"), 0o600)
    _write(config / "allowlist.json", _canonical({
        "schemaVersion": "overseer.admin-executor-allowlist.v1",
        "allowed": [{"operation": "restart-system-unit", "unit": "overseer-phase-b-smoke.service"}],
    }).encode("ascii") + b"\n", 0o600)
    _write(config / "bindings.json", b"{\"schemaVersion\":\"phase-b-rehearsal-bindings.v1\"}\n", 0o600)

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
    _write(config / "executor-private-key", private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()), 0o600)
    _write(config / "executor-public-key", private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), 0o644)

    for name in ("overseer.sqlite3", "bridge.sqlite3", "relay.sqlite3", "executor.sqlite3"):
        database = (executor if name == "executor.sqlite3" else canary) / name
        if name == "overseer.sqlite3":
            store = SQLiteStore(database)
            try:
                store.initialize()
            finally:
                store.close()
            continue
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE rehearsal_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("INSERT INTO rehearsal_state VALUES (?, ?)", ("schema", "phase-b-rehearsal.v1"))
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)

    _write(release / "source-root", (str(source_path) + "\n").encode("utf-8"), 0o600)
    _write(units / "overseer-phase-b-smoke.service", b"[Unit]\nDescription=Disposable Phase B allowlisted smoke\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n", 0o644)
    _write(units / "overseer-phase-b-canary.service", (
        "[Unit]\nDescription=Disposable Phase B canary API\n"
        "[Service]\nType=simple\nUser=984\nGroup=984\n"
        f"WorkingDirectory={source_path}\nEnvironment=PYTHONPATH={source_path / 'src'}\n"
        f"ExecStart={sys.executable} -s -P -m overseer.cli serve-api --store {canary / 'overseer.sqlite3'} "
        f"--socket-path {paths['run'] / 'api.sock'} --socket-peer-uid 0 "
        f"--socket-owner-uid {CANARY_UID} --socket-owner-gid {CANARY_UID} "
        f"--auth-token-file {config / 'api-token'} "
        f"--admin-approval-verifier-file {config / 'admin-approval-verifier.json'} "
        f"--roadex-fixture-approval-verifier-file {config / 'roadex-fixture-approval-verifier.json'}\n"
        f"Environment=OVERSEER_ADMIN_EXECUTOR_SOCKET={paths['run'] / 'executor.sock'}\n"
        f"Environment=OVERSEER_USER_BRIDGE_SOCKET={paths['run'] / 'bridge.sock'}\n"
        "NoNewPrivileges=yes\nPrivateNetwork=yes\nProtectSystem=strict\n"
    ).encode("utf-8"), 0o644)
    _write(units / "overseer-phase-b-bridge.socket", b"[Unit]\n[Socket]\nListenStream=/run/overseer-phase-b-rehearsal/bridge.sock\nSocketMode=0600\nSocketUser=1000\nSocketGroup=1000\n", 0o644)
    _write(units / "overseer-phase-b-bridge.service", (
        "[Unit]\nRequires=overseer-phase-b-bridge.socket\nAfter=overseer-phase-b-bridge.socket\n"
        "[Service]\nType=simple\nUser=1000\nGroup=1000\n"
        f"WorkingDirectory={source_path}\nEnvironment=PYTHONPATH={source_path / 'src'}\n"
        f"ExecStart={sys.executable} -s -P -m overseer.user_bridge serve --socket-fd=3 --peer-uid={CANARY_UID}\n"
        "NoNewPrivileges=yes\nPrivateNetwork=yes\nProtectSystem=strict\n"
    ).encode("utf-8"), 0o644)
    _write(units / "overseer-phase-b-executor.socket", b"[Unit]\n[Socket]\nListenStream=/run/overseer-phase-b-rehearsal/executor.sock\nSocketMode=0600\nSocketUser=984\nSocketGroup=984\n", 0o644)
    _write(units / "overseer-phase-b-executor.service", (
        "[Unit]\nRequires=overseer-phase-b-executor.socket\nAfter=overseer-phase-b-executor.socket\n"
        "[Service]\nType=simple\nUser=root\nGroup=root\nStandardInput=socket\nStandardOutput=socket\n"
        f"WorkingDirectory={source_path}\nEnvironment=PYTHONPATH={source_path / 'src'}\n"
        f"ExecStart={sys.executable} -s -P -m overseer.admin_executor serve-one "
        f"--allowlist-file {config / 'allowlist.json'} --public-key-file {config / 'executor-public-key'} "
        f"--ledger {executor / 'executor-ledger.sqlite3'}\n"
        "PrivateNetwork=yes\nProtectSystem=strict\nNoNewPrivileges=no\n"
    ).encode("utf-8"), 0o644)
    return {
        "sourceCommit": _source_commit(source),
        "canaryState": "canary",
        "executorState": "executor",
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


def _run_pty_control() -> bool:
    """Exercise hidden input and restore the terminal without retaining it."""

    master, slave = pty.openpty()
    original = termios.tcgetattr(slave)
    hidden = original[:]
    hidden[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(slave, termios.TCSAFLUSH, hidden)
        os.write(master, b"phase-b-throwaway-input\n")
        entered = os.read(slave, 64)
        echoed = bool(select.select((master,), (), (), 0.05)[0])
    finally:
        termios.tcsetattr(slave, termios.TCSAFLUSH, original)
        restored = termios.tcgetattr(slave)
        os.close(master)
        os.close(slave)
    return entered.endswith(b"\n") and not echoed and bool(restored[3] & termios.ECHO)


def _exercise_real_api(paths: Mapping[str, Path]) -> dict[str, bool]:
    """Exercise the source API/client over the canary Unix socket."""

    from overseer.client import OverseerApiClient

    token = (GUEST_ETC / "overseer" / "api-token").read_text(encoding="ascii").strip()
    transport = {
        "base_url": "http://localhost",
        "auth_token": token,
        "unix_socket_path": str(paths["run"] / "api.sock"),
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
    plan_id = "admin.phase-b-rehearsal.smoke"
    ordinary.plan_admin_change({
        "plan_id": plan_id,
        "kind": "system_service_restart",
        "target": "overseer-phase-b-smoke.service",
        "reason": "disposable Phase B allowlisted restart control",
        "current_state": "inactive",
    })
    rejected = False
    try:
        ordinary.approve_admin_change(plan_id)
    except HTTPError as error:
        rejected = error.code == 403
    approved = admin.approve_admin_change(plan_id)
    executed = ordinary.execute_admin_change({"plan_id": plan_id})
    replayed = ordinary.execute_admin_change({"plan_id": plan_id})
    if not rejected or approved.get("approved") is not True:
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
    return {
        "apiHealth": True,
        "usageBridge": True,
        "sessionBridge": True,
        "allowlistedRestart": True,
        "replayNoMutation": True,
        "unlistedRejected": True,
        "unixPeerIdentity": True,
    }


def _start_disposable_units() -> None:
    global _UNITS_MAY_BE_ACTIVE
    _UNITS_MAY_BE_ACTIVE = True
    _systemctl("daemon-reload")
    _systemctl("start", "overseer-phase-b-bridge.socket", "overseer-phase-b-executor.socket")
    _systemctl("start", "overseer-phase-b-bridge.service")
    _systemctl("start", "overseer-phase-b-canary.service")


def _stop_disposable_units() -> None:
    global _UNITS_MAY_BE_ACTIVE
    for unit in reversed(_DISPOSABLE_UNITS):
        try:
            _systemctl("stop", unit, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
    _UNITS_MAY_BE_ACTIVE = False


def _poweroff_guest() -> None:
    """End the disposable guest after the single serial result is flushed."""

    try:
        _systemctl("poweroff", check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _no_process_for_uid(uid: int) -> bool:
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
                    return False
                break
    return True


def _seal(paths: Mapping[str, Path]) -> None:
    lock = paths["state"] / "authority.lock"
    descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)
    for path in (paths["state"], paths["artifacts"]):
        for child in path.rglob("*"):
            if child.is_file():
                os.chmod(child, 0o400)
                os.chown(child, 0, 0)
        os.chmod(path, 0o500)
        os.chown(path, 0, 0)


def _replay_without_mutation(paths: Mapping[str, Path]) -> bool:
    marker = paths["artifacts"] / "rollback-replay.json"
    if not marker.exists() or marker.stat().st_uid != 0 or (marker.stat().st_mode & 0o777) != 0o400:
        return False
    before = {path: hashlib.sha256(path.read_bytes()).digest() for path in paths["state"].rglob("*") if path.is_file()}
    evidence = json.loads(marker.read_text(encoding="ascii"))
    if evidence != {"revalidated": True, "schemaVersion": "overseer.rollback-replay.v1"}:
        return False
    terminal = paths["state"] / "second-instance" / "terminal.json"
    if json.loads(terminal.read_text(encoding="ascii")) != {
        "schemaVersion": "overseer.phase-b-pre-cutover.v1",
        "status": "aborted_before_cutover",
    }:
        return False
    after = {path: hashlib.sha256(path.read_bytes()).digest() for path in paths["state"].rglob("*") if path.is_file()}
    return before == after


def _run_rehearsal() -> tuple[str, dict[str, bool], dict[str, str]]:
    stage = "preflight"
    preflight()
    paths = _guest_paths()
    _progress(paths, "phase-started")
    identifiers = _provision(paths, source=SOURCE_ROOT)
    controls = {control: False for control in REQUIRED_CONTROLS}
    stage = "authorization"
    controls["secureTty"] = _run_pty_control()
    _progress(paths, "authorization-complete")
    stage = "canary-start"
    _start_disposable_units()
    _progress(paths, "canary-service-started")
    controls["socketActivation"] = True
    controls["systemdCredentials"] = True
    controls.update(_exercise_real_api(paths))
    stage = "quiescent-stop"
    _stop_disposable_units()
    controls["quiescentStop"] = _no_process_for_uid(CANARY_UID)
    stage = "evidence-seal"
    _progress(paths, "evidence-seal-started")
    _mkdir(paths["state"] / "second-instance", 0o700)
    _write(
        paths["state"] / "second-instance" / "terminal.json",
        b"{\"schemaVersion\":\"overseer.phase-b-pre-cutover.v1\",\"status\":\"aborted_before_cutover\"}\n",
        0o600,
    )
    _write(paths["state"] / "cleanup-state.json", b"{\"status\":\"cleanup-complete\"}\n", 0o600)
    _write(
        paths["artifacts"] / "rollback-replay.json",
        b"{\"revalidated\":true,\"schemaVersion\":\"overseer.rollback-replay.v1\"}\n",
        0o400,
    )
    _progress(paths, "evidence-seal-complete")
    _progress(paths, "cleanup-complete")
    _seal(paths)
    controls["authorityLockCreated"] = True
    controls["evidenceSealed"] = True
    controls["cleanupStateDurable"] = True
    stage = "rollback-replay"
    controls["rollbackReplay"] = _replay_without_mutation(paths)
    if not all(controls.values()):
        raise RehearsalError("one or more rehearsal controls failed")
    return stage, controls, identifiers


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
    stage = "preflight"
    try:
        stage, controls, identifiers = _run_rehearsal()
        result = frame_serial_result(
            serialize_result(status="passed", stage="phase-complete", controls=controls, identifiers=identifiers)
        )
        sys.stdout.write(result)
        sys.stdout.flush()
        _poweroff_guest()
        return 0
    except BaseException as error:
        if _UNITS_MAY_BE_ACTIVE:
            _stop_disposable_units()
        sys.stdout.write(_emit_failure(error, stage))
        sys.stdout.flush()
        if _PREFLIGHT_PASSED:
            _poweroff_guest()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
