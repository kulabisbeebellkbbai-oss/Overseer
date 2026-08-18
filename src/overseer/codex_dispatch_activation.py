"""Approval-gated activation of the reviewed structured Codex transport.

All authority is derived from this checkout and the current euid's fixed home.
No caller-provided source path, home path, digest, socket, or health endpoint is
trusted.  Marker commands are interpreted here rather than by a shell.
"""

from __future__ import annotations

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
JOURNAL_SCHEMA = "overseer.codex-dispatch-activation-journal.v1"
SERVICE_NAME = "overseer-api.service"
DROP_IN_RELATIVE_PATH = ".config/systemd/user/overseer-api.service.d/10-overseer-codex-dispatch.conf"
# This path is relative to CODEX_HOME exactly once.
DAEMON_SOCKET_RELATIVE_PATH = "app-server-control/app-server-control.sock"
HEALTH_URL = "http://127.0.0.1:8766/health"
SOURCE_FILES = (
    "src/overseer/agent_adapters/codex.py",
    "src/overseer/codex_usage.py",
    "src/overseer/psychlo_bridge.py",
)
DROP_IN_CONTENT = b"[Service]\nEnvironment=OVERSEER_CODEX_APP_SERVER_DISPATCH=1\n"
CANONICAL_SOURCE_ROOT = Path(__file__).resolve().parents[2]
EUID_HOME = Path(pwd.getpwuid(os.geteuid()).pw_dir).resolve()
CODEX_HOME = EUID_HOME / ".codex"
_HEX = set("0123456789abcdef")
_JOURNAL_KEYS = {
    "schemaVersion", "planId", "specDigest", "phase", "dropInPath", "dropInDigest",
    "dropInOwnership", "daemonSocketPath", "daemonOwnership",
}
_DAEMON_VERSION_KEYS = {"cliVersion", "daemonVersion", "state", "remoteControlEnabled", "socketPath"}


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


def _module_digest() -> str:
    hasher = hashlib.sha256()
    for relative in SOURCE_FILES:
        path = CANONICAL_SOURCE_ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("reviewed source module is missing")
        hasher.update(relative.encode() + b"\0" + path.read_bytes())
    return hasher.hexdigest()


def _source_clean() -> None:
    status = _git(("status", "--porcelain", "--untracked-files=all", "--", *SOURCE_FILES, "pyproject.toml"))
    if status:
        raise ValueError("reviewed source checkout is dirty")


def _review_digest(source_commit: str, source_tree_digest: str, source_module_digest: str) -> str:
    return _digest({
        "reviewScope": "structured-codex-dispatch",
        "reviewAuthority": "canonical-overseer-checkout",
        "sourceCommit": source_commit,
        "sourceTreeDigest": source_tree_digest,
        "sourceModuleDigest": source_module_digest,
        "sourceFiles": list(SOURCE_FILES),
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
    source_files: tuple[str, ...] = SOURCE_FILES

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
        if value["sourceFiles"] != list(SOURCE_FILES):
            raise ValueError("sourceFiles are not the reviewed module binding")
        source_commit = str(value["sourceCommit"]).lower()
        source_tree = str(value["sourceTreeDigest"]).lower()
        source_module = str(value["sourceModuleDigest"]).lower()
        if str(value["reviewDigest"]).lower() != _review_digest(source_commit, source_tree, source_module):
            raise ValueError("review digest is not derived from the reviewed binding")
        return cls(CODEX_DISPATCH_ACTIVATION_SCHEMA, source_commit, source_tree, source_module, str(value["reviewDigest"]).lower())


def build_codex_dispatch_activation_spec() -> CodexDispatchActivationSpec:
    """Derive the only valid activation authority from the canonical checkout."""
    if not CANONICAL_SOURCE_ROOT.is_dir() or CANONICAL_SOURCE_ROOT.is_symlink():
        raise ValueError("canonical reviewed source checkout is unavailable")
    _source_clean()
    source_commit = _git(("rev-parse", "HEAD")).lower()
    source_tree = _git(("rev-parse", "HEAD^{tree}")).lower()
    source_module = _module_digest()
    return CodexDispatchActivationSpec(
        CODEX_DISPATCH_ACTIVATION_SCHEMA,
        source_commit,
        source_tree,
        source_module,
        _review_digest(source_commit, source_tree, source_module),
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
    if _module_digest() != spec.source_module_digest:
        raise ValueError("reviewed source module digest changed")
    if spec.review_digest != _review_digest(spec.source_commit, spec.source_tree_digest, spec.source_module_digest):
        raise ValueError("review digest changed")


def _paths() -> tuple[Path, Path, Path, Path]:
    drop_in = EUID_HOME / DROP_IN_RELATIVE_PATH
    journal = EUID_HOME / ".local/state/overseer/codex-dispatch/activation-journal.json"
    lock = EUID_HOME / ".local/state/overseer/codex-dispatch/activation.lock"
    return drop_in, journal, lock, CODEX_HOME / DAEMON_SOCKET_RELATIVE_PATH


def _atomic_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _owner_only(path.parent, "activation directory")
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
    finally:
        temp.unlink(missing_ok=True)


def _journal(plan_id: str, digest: str, phase: str = "none", **updates: object) -> dict[str, object]:
    drop_in, _, _, socket_path = _paths()
    value: dict[str, object] = {
        "schemaVersion": JOURNAL_SCHEMA, "planId": plan_id, "specDigest": digest, "phase": phase,
        "dropInPath": str(drop_in), "dropInDigest": hashlib.sha256(DROP_IN_CONTENT).hexdigest(),
        "dropInOwnership": "unknown", "daemonSocketPath": str(socket_path), "daemonOwnership": "unknown",
    }
    value.update(updates)
    return value


def _load_journal(plan_id: str, digest: str) -> dict[str, object] | None:
    _, path, _, _ = _paths()
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if set(value) != _JOURNAL_KEYS or value["schemaVersion"] != JOURNAL_SCHEMA or value["planId"] != plan_id or value["specDigest"] != digest:
        raise ValueError("activation journal binding is invalid")
    return value


def _write_journal(value: Mapping[str, object]) -> None:
    _, path, _, _ = _paths()
    _atomic_write(path, (_canonical(dict(value)) + "\n").encode())


@contextmanager
def _activation_lock():
    _, _, path, _ = _paths()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _owner_only(path.parent, "activation lock directory")
    with path.open("a+") as stream:
        path.chmod(0o600)
        _owner_only(path, "activation lock")
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
    existing = drop_in.read_bytes() if drop_in.exists() else None
    if existing is not None and existing != DROP_IN_CONTENT:
        raise ValueError("reviewed drop-in path contains unrelated content")
    journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
    if existing is not None:
        journal["dropInOwnership"] = "preexisting"
        journal["phase"] = "drop-in-installed"
        _write_journal(journal)
        return "exact owner-only service drop-in already present"
    # Record intent before the effect.  A crash after os.replace but before
    # the success phase leaves write-issued intent for rollback reconciliation.
    journal["dropInOwnership"] = "write-issued"
    journal["phase"] = "intent-drop-in"
    _write_journal(journal)
    _atomic_write(drop_in, DROP_IN_CONTENT)
    journal["dropInOwnership"] = "created-by-operation"
    journal["phase"] = "drop-in-installed"
    _write_journal(journal)
    return "exact owner-only service drop-in installed"


def _rollback(plan_id: str, digest: str) -> str:
    journal = _load_journal(plan_id, digest)
    if journal is None:
        return "no activation journal owned by this plan"
    if journal["phase"] == "rolled-back":
        return "activation already rolled back"
    prior_phase = str(journal["phase"])
    journal["phase"] = "rollback-pending"
    _write_journal(journal)
    drop_in, _, _, _ = _paths()
    if journal["dropInOwnership"] in {"write-issued", "created-by-operation"}:
        if drop_in.exists():
            if hashlib.sha256(drop_in.read_bytes()).hexdigest() != journal["dropInDigest"]:
                raise ValueError("drop-in changed after activation; refusing unrelated removal")
            drop_in.unlink()
        journal["dropInOwnership"] = "removed"
    if prior_phase in {"rollback-pending", "drop-in-installed", "reloaded", "restarted", "verified"} and journal["dropInOwnership"] in {"removed", "preexisting"}:
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
    journal["phase"] = "rolled-back"
    _write_journal(journal)
    return "exact Codex dispatch activation rolled back"


def execute_codex_dispatch_activation_marker(command: Sequence[str]) -> tuple[int, str, str]:
    try:
        operation, plan_id, spec = _parse_marker(command)
        digest = command[2]
        if operation in {"bootstrap", "start", "install-drop-in", "daemon-reload", "restart-overseer"}:
            verify_reviewed_source_binding(spec)
        if operation == "bootstrap":
            journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
            journal["phase"] = "intent-bootstrap"
            _write_journal(journal)
            _run_checked(("codex", "app-server", "daemon", "bootstrap"))
            _run_checked(("codex", "app-server", "daemon", "disable-remote-control"))
            journal["phase"] = "bootstrapped"
            _write_journal(journal)
            return 0, "daemon bootstrapped without remote control", ""
        if operation == "start":
            journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
            journal["phase"] = "intent-start"
            _write_journal(journal)
            status = _daemon_status()
            if status == "running-valid":
                journal["daemonOwnership"] = "preexisting"
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
            _run_checked(("systemctl", "--user", "daemon-reload"))
            journal = _load_journal(plan_id, digest) or _journal(plan_id, digest)
            journal["phase"] = "reloaded"
            _write_journal(journal)
            return 0, "user systemd reloaded", ""
        if operation == "restart-overseer":
            _run_checked(("systemctl", "--user", "restart", SERVICE_NAME))
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
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        return 1, "", str(error)


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
                result = runner(step)
                command_results.append(result)
                if result.exit_code != 0:
                    rollback = tuple(runner(item) for item in plan.rollback_steps)
                    return AdminExecutionResult(f"admin.exec.{plan.id}.failed", plan.id, AdminExecutionStatus.FAILED, f"Codex dispatch activation failed during step: {result.title}; rollback attempted", tuple(command_results), rollback_results=rollback)
            verification: list[AdminCommandResult] = []
            for step in plan.verification_steps:
                result = runner(step)
                verification.append(result)
                if result.exit_code != 0:
                    rollback = tuple(runner(item) for item in plan.rollback_steps)
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
