"""Approval-gated activation of the reviewed structured Codex transport.

The plan is deliberately closed over the reviewed source identity and the
single local systemd override.  Marker commands are interpreted here rather
than by a shell; the generic admin runner therefore cannot be tricked into
running an arbitrary command from plan metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .admin import AdminChangeKind, AdminCommandResult, AdminCommandStep, AdminChangePlan, AdminExecutionResult, AdminExecutionStatus
from .core import ApprovalLevel, OwnerDomain, RiskLevel


CODEX_DISPATCH_ACTIVATION_SCHEMA = "overseer.codex-dispatch-activation.v1"
SERVICE_NAME = "overseer-api.service"
DROP_IN_RELATIVE_PATH = ".config/systemd/user/overseer-api.service.d/10-overseer-codex-dispatch.conf"
DAEMON_SOCKET_RELATIVE_PATH = ".codex/run/app-server.sock"
HEALTH_URL = "http://127.0.0.1:8766/health"
SOURCE_FILES = (
    "src/overseer/agent_adapters/codex.py",
    "src/overseer/codex_usage.py",
    "src/overseer/psychlo_bridge.py",
)
DROP_IN_CONTENT = b"[Service]\nEnvironment=OVERSEER_CODEX_APP_SERVER_DISPATCH=1\n"
_HEX40_OR_64 = set("0123456789abcdef")
_HEX64 = set("0123456789abcdef")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _valid_hex(value: object, lengths: set[int]) -> bool:
    return isinstance(value, str) and len(value) in lengths and set(value.lower()) <= _HEX64


def _owner_only(path: Path, label: str) -> None:
    info = path.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"{label} is not owner-controlled")


@dataclass(frozen=True)
class CodexDispatchActivationSpec:
    schema_version: str
    source_root: Path
    source_commit: str
    source_tree_digest: str
    source_module_digest: str
    review_digest: str
    service_name: str
    drop_in_relative_path: str
    daemon_socket: str
    health_url: str
    source_files: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "sourceRoot": str(self.source_root),
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
            "schemaVersion", "sourceRoot", "sourceCommit", "sourceTreeDigest", "sourceModuleDigest",
            "reviewDigest", "serviceName", "dropInRelativePath", "daemonSocket", "healthUrl", "sourceFiles",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("Codex dispatch activation spec must contain exact keys")
        if value["schemaVersion"] != CODEX_DISPATCH_ACTIVATION_SCHEMA:
            raise ValueError("unsupported Codex dispatch activation schema")
        root = Path(str(value["sourceRoot"])).expanduser()
        if not root.is_absolute() or not root.is_dir() or root.is_symlink():
            raise ValueError("sourceRoot must be an absolute non-symlink directory")
        if not _valid_hex(value["sourceCommit"], {40, 64}):
            raise ValueError("source commit is invalid")
        if not _valid_hex(value["sourceTreeDigest"], {40, 64}):
            raise ValueError("source tree digest is invalid")
        if not _valid_hex(value["sourceModuleDigest"], {64}):
            raise ValueError("source module digest is invalid")
        if not _valid_hex(value["reviewDigest"], {64}):
            raise ValueError("review digest is invalid")
        if value["serviceName"] != SERVICE_NAME:
            raise ValueError("serviceName must be overseer-api.service")
        if value["dropInRelativePath"] != DROP_IN_RELATIVE_PATH:
            raise ValueError("dropInRelativePath is not the reviewed override")
        if value["daemonSocket"] != DAEMON_SOCKET_RELATIVE_PATH:
            raise ValueError("daemonSocket is not the reviewed local socket")
        if value["healthUrl"] != HEALTH_URL:
            raise ValueError("healthUrl must be the local Overseer health endpoint")
        files = value["sourceFiles"]
        if not isinstance(files, list) or tuple(files) != SOURCE_FILES:
            raise ValueError("sourceFiles are not the reviewed module binding")
        return cls(
            schema_version=CODEX_DISPATCH_ACTIVATION_SCHEMA,
            source_root=root,
            source_commit=str(value["sourceCommit"]).lower(),
            source_tree_digest=str(value["sourceTreeDigest"]).lower(),
            source_module_digest=str(value["sourceModuleDigest"]).lower(),
            review_digest=str(value["reviewDigest"]).lower(),
            service_name=SERVICE_NAME,
            drop_in_relative_path=DROP_IN_RELATIVE_PATH,
            daemon_socket=DAEMON_SOCKET_RELATIVE_PATH,
            health_url=HEALTH_URL,
            source_files=SOURCE_FILES,
        )


def codex_dispatch_activation_plan_digest(spec: CodexDispatchActivationSpec) -> str:
    return _digest(spec.to_json())


def _marker_context(plan_id: str, spec: CodexDispatchActivationSpec) -> tuple[str, ...]:
    return (plan_id, codex_dispatch_activation_plan_digest(spec), _canonical(spec.to_json()))


def _canonical_plan(plan_id: str, spec: CodexDispatchActivationSpec, reason: str, current_state: str) -> AdminChangePlan:
    context = _marker_context(plan_id, spec)
    def marker(name: str) -> tuple[str, ...]:
        return (f"__overseer_codex_dispatch_{name}", *context)
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION,
        owner_domain=OwnerDomain.SISKO,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=SERVICE_NAME,
        reason=reason,
        current_state=current_state,
        proposed_state="bootstrap the local non-remote Codex app-server, enable reviewed structured dispatch, and verify Overseer",
        steps=(
            AdminCommandStep("Bootstrap local Codex app-server", marker("bootstrap"), "install local daemon management without remote control"),
            AdminCommandStep("Start local Codex app-server", marker("start"), "start the local daemon only after bootstrap"),
            AdminCommandStep("Install exact owner-only service drop-in", marker("install-drop-in"), "write only the reviewed Overseer environment override"),
            AdminCommandStep("Reload user systemd", marker("daemon-reload"), "load the exact drop-in"),
            AdminCommandStep("Restart Overseer API", marker("restart-overseer"), "apply the approved service environment"),
        ),
        rollback_steps=(
            AdminCommandStep("Rollback exact dispatch drop-in", marker("rollback"), "remove only a drop-in owned by this exact plan and restore service state"),
        ),
        risks=(
            "a daemon or service restart can interrupt local project coordination",
            "a source or drop-in identity mismatch must block rather than activate",
            "remote control remains disabled; no network listener is authorized",
        ),
        verification_steps=(
            AdminCommandStep("Verify daemon version", marker("verify-daemon"), "confirm the local daemon is running"),
            AdminCommandStep("Verify local proxy readiness", marker("verify-proxy"), "confirm the local Unix-socket proxy responds"),
            AdminCommandStep("Verify exact Overseer environment", marker("verify-environment"), "confirm only the reviewed dispatch setting is present"),
            AdminCommandStep("Verify Overseer health", marker("verify-health"), "confirm the local health endpoint responds"),
            AdminCommandStep("Verify reviewed source binding", marker("verify-source"), "confirm commit, tree, and module digests are unchanged"),
        ),
        adapter_metadata={"spec": spec.to_json(), "specDigest": codex_dispatch_activation_plan_digest(spec)},
    )


def plan_codex_dispatch_activation(plan_id: str, spec: CodexDispatchActivationSpec, reason: str, current_state: str = "unknown") -> AdminChangePlan:
    if not plan_id.strip() or not reason.strip():
        raise ValueError("plan_id and reason are required")
    return _canonical_plan(plan_id, spec, reason, current_state)


def codex_dispatch_activation_spec_from_private_file(path: str | Path) -> CodexDispatchActivationSpec:
    manifest = Path(path).expanduser()
    if not manifest.is_file() or manifest.is_symlink():
        raise ValueError("Codex dispatch activation spec file is invalid")
    _owner_only(manifest, "Codex dispatch activation spec")
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Codex dispatch activation spec file is invalid") from exc
    return CodexDispatchActivationSpec.from_json(value)


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
    normalized = replace(
        plan, approved=False, approved_by=None, approved_at=None, canceled=False, canceled_by=None,
        canceled_at=None, cancellation_reason=None, archived=False, archived_by=None, archived_at=None,
        archive_record_id=None,
    )
    if normalized != canonical:
        raise ValueError("Codex dispatch activation plan is not canonical")
    return spec


def _safe_env() -> dict[str, str]:
    allowed = {"HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "CODEX_HOME"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _run_checked(command: Sequence[str], *, timeout: float = 30.0, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        tuple(command), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL,
        shell=False, env=_safe_env(), cwd=str(cwd) if cwd else None, timeout=timeout,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed: {command[0]}")
    return completed.stdout.strip()


def _paths(spec: CodexDispatchActivationSpec, home: Path) -> tuple[Path, Path, Path]:
    drop_in = home / spec.drop_in_relative_path
    state = home / ".local/state/overseer/codex-dispatch" / "activation.json"
    socket = home / spec.daemon_socket
    return drop_in, state, socket


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
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


def _parse_marker(command: Sequence[str]) -> tuple[str, str, CodexDispatchActivationSpec]:
    if len(command) != 4 or not command[0].startswith("__overseer_codex_dispatch_"):
        raise ValueError("Codex dispatch activation marker context is invalid")
    try:
        raw_spec = json.loads(command[3])
    except json.JSONDecodeError as exc:
        raise ValueError("Codex dispatch activation marker context is invalid") from exc
    spec = CodexDispatchActivationSpec.from_json(raw_spec)
    if command[1].strip() == "" or command[2] != codex_dispatch_activation_plan_digest(spec):
        raise ValueError("Codex dispatch activation marker digest is invalid")
    return command[0][len("__overseer_codex_dispatch_"):], command[1], spec


def _install_drop_in(plan_id: str, digest: str, spec: CodexDispatchActivationSpec, home: Path) -> str:
    drop_in, state_path, _ = _paths(spec, home)
    drop_in.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _owner_only(drop_in.parent, "systemd drop-in directory")
    existing = drop_in.read_bytes() if drop_in.exists() else None
    if existing is not None and existing != DROP_IN_CONTENT:
        raise ValueError("reviewed drop-in path contains unrelated content")
    prior_state: dict[str, object] = {}
    if state_path.exists():
        prior_state = json.loads(state_path.read_text(encoding="utf-8"))
        if prior_state.get("planId") != plan_id or prior_state.get("specDigest") != digest:
            raise ValueError("activation state binding does not match this plan")
    record = {
        "schemaVersion": CODEX_DISPATCH_ACTIVATION_SCHEMA,
        "planId": plan_id,
        "specDigest": digest,
        "dropInPath": str(drop_in),
        "dropInDigest": hashlib.sha256(DROP_IN_CONTENT).hexdigest(),
        "installedByOperation": existing is None,
        "daemonStartedByOperation": bool(prior_state.get("daemonStartedByOperation", False)),
    }
    if existing is None:
        _atomic_write(drop_in, DROP_IN_CONTENT, 0o600)
    _atomic_write(state_path, (_canonical(record) + "\n").encode(), 0o600)
    return "exact owner-only service drop-in installed"


def _rollback(plan_id: str, digest: str, spec: CodexDispatchActivationSpec, home: Path) -> str:
    drop_in, state_path, _ = _paths(spec, home)
    if not state_path.exists():
        return "no activation state owned by this plan"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if set(state) != {"schemaVersion", "planId", "specDigest", "dropInPath", "dropInDigest", "installedByOperation", "daemonStartedByOperation"}:
        raise ValueError("activation state is invalid")
    if state["planId"] != plan_id or state["specDigest"] != digest or state["dropInPath"] != str(drop_in):
        raise ValueError("activation state binding does not match this plan")
    if state["installedByOperation"]:
        if not drop_in.exists() or hashlib.sha256(drop_in.read_bytes()).hexdigest() != state["dropInDigest"]:
            raise ValueError("drop-in changed after activation; refusing unrelated removal")
        drop_in.unlink()
    _run_checked(("systemctl", "--user", "daemon-reload"))
    _run_checked(("systemctl", "--user", "restart", spec.service_name))
    if state["daemonStartedByOperation"]:
        _run_checked(("codex", "app-server", "daemon", "stop"))
    state_path.unlink(missing_ok=True)
    return "exact Codex dispatch activation rolled back"


def _verify_source(spec: CodexDispatchActivationSpec) -> str:
    commit = _run_checked(("/usr/bin/git", "-C", str(spec.source_root), "rev-parse", "HEAD"))
    tree = _run_checked(("/usr/bin/git", "-C", str(spec.source_root), "rev-parse", "HEAD^{tree}"))
    if commit.lower() != spec.source_commit or tree.lower() != spec.source_tree_digest:
        raise ValueError("reviewed source commit or tree binding changed")
    module_hash = hashlib.sha256()
    for relative in spec.source_files:
        path = spec.source_root / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError("reviewed source module is missing")
        module_hash.update(relative.encode() + b"\0" + path.read_bytes())
    if module_hash.hexdigest() != spec.source_module_digest:
        raise ValueError("reviewed source module digest changed")
    return "reviewed source binding verified"


def execute_codex_dispatch_activation_marker(command: Sequence[str], *, home: Path | None = None) -> tuple[int, str, str]:
    """Execute one closed activation marker; intended for the approved adapter only."""
    try:
        operation, plan_id, spec = _parse_marker(command)
        digest = command[2]
        root = (home or Path.home()).expanduser()
        if operation == "bootstrap":
            _run_checked(("codex", "app-server", "daemon", "bootstrap"))
            _run_checked(("codex", "app-server", "daemon", "disable-remote-control"))
            return 0, "daemon bootstrap staged", ""
        if operation == "start":
            started_by_operation = False
            try:
                _run_checked(("codex", "app-server", "daemon", "version"))
            except (RuntimeError, OSError):
                _run_checked(("codex", "app-server", "daemon", "start"))
                started_by_operation = True
            if started_by_operation:
                _, state_path, _ = _paths(spec, root)
                state = {
                    "schemaVersion": CODEX_DISPATCH_ACTIVATION_SCHEMA,
                    "planId": plan_id,
                    "specDigest": digest,
                    "dropInPath": str(_paths(spec, root)[0]),
                    "dropInDigest": hashlib.sha256(DROP_IN_CONTENT).hexdigest(),
                    "installedByOperation": False,
                    "daemonStartedByOperation": True,
                }
                if state_path.exists():
                    existing_state = json.loads(state_path.read_text(encoding="utf-8"))
                    if existing_state.get("planId") != plan_id or existing_state.get("specDigest") != digest:
                        raise ValueError("activation state binding does not match this plan")
                    state.update(existing_state)
                    state["daemonStartedByOperation"] = True
                _atomic_write(state_path, (_canonical(state) + "\n").encode(), 0o600)
            return 0, "local daemon ready", ""
        if operation == "install-drop-in":
            return 0, _install_drop_in(plan_id, digest, spec, root), ""
        if operation == "daemon-reload":
            _run_checked(("systemctl", "--user", "daemon-reload"))
            return 0, "user systemd reloaded", ""
        if operation == "restart-overseer":
            _run_checked(("systemctl", "--user", "restart", spec.service_name))
            return 0, "Overseer API restarted", ""
        if operation == "rollback":
            return 0, _rollback(plan_id, digest, spec, root), ""
        if operation == "verify-daemon":
            output = _run_checked(("codex", "app-server", "daemon", "version"))
            if "remote" in output.lower() and "false" not in output.lower():
                raise ValueError("Codex daemon remote control is enabled")
            return 0, "daemon version verified", ""
        if operation == "verify-proxy":
            _run_checked(("codex", "app-server", "proxy", "--sock", str(_paths(spec, root)[2])))
            return 0, "local proxy readiness verified", ""
        if operation == "verify-environment":
            output = _run_checked(("systemctl", "--user", "show", spec.service_name, "--property=Environment", "--value"))
            if output.strip() != "OVERSEER_CODEX_APP_SERVER_DISPATCH=1":
                raise ValueError("Overseer service environment is not exact")
            return 0, "exact service environment verified", ""
        if operation == "verify-health":
            with urllib.request.urlopen(spec.health_url, timeout=5) as response:
                if response.status != 200:
                    raise ValueError("Overseer health check failed")
            return 0, "Overseer health verified", ""
        if operation == "verify-source":
            return 0, _verify_source(spec), ""
        raise ValueError("unsupported Codex dispatch activation operation")
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        return 1, "", str(error)


def execute_codex_dispatch_activation_plan(
    plan: AdminChangePlan,
    *,
    runner: Callable[[AdminCommandStep], AdminCommandResult] | None = None,
) -> AdminExecutionResult:
    """Run the approved closed marker sequence with crash-safe rollback."""
    spec = validate_codex_dispatch_activation_plan(plan)
    if not plan.approved or plan.canceled or plan.archived:
        return AdminExecutionResult(
            id=f"admin.exec.{plan.id}.blocked", plan_id=plan.id, status=AdminExecutionStatus.BLOCKED,
            summary="Codex dispatch activation requires an uncanceled approved plan", command_results=(),
        )
    if runner is None:
        from .admin import run_admin_command_step

        runner = run_admin_command_step
    command_results: list[AdminCommandResult] = []
    for step in plan.steps:
        result = runner(step)
        command_results.append(result)
        if result.exit_code != 0:
            rollback_results = tuple(runner(item) for item in plan.rollback_steps)
            return AdminExecutionResult(
                id=f"admin.exec.{plan.id}.failed", plan_id=plan.id, status=AdminExecutionStatus.FAILED,
                summary=f"Codex dispatch activation failed during step: {result.title}; rollback attempted",
                command_results=tuple(command_results), rollback_results=rollback_results,
            )
    verification_results: list[AdminCommandResult] = []
    for step in plan.verification_steps:
        result = runner(step)
        verification_results.append(result)
        if result.exit_code != 0:
            rollback_results = tuple(runner(item) for item in plan.rollback_steps)
            return AdminExecutionResult(
                id=f"admin.exec.{plan.id}.failed", plan_id=plan.id, status=AdminExecutionStatus.FAILED,
                summary=f"Codex dispatch activation verification failed during step: {result.title}; rollback attempted",
                command_results=tuple(command_results), verification_results=tuple(verification_results),
                rollback_results=rollback_results,
            )
    return AdminExecutionResult(
        id=f"admin.exec.{plan.id}.completed", plan_id=plan.id, status=AdminExecutionStatus.COMPLETED,
        summary="approved Codex dispatch activation completed and verified",
        command_results=tuple(command_results), verification_results=tuple(verification_results),
    )


__all__ = [
    "CODEX_DISPATCH_ACTIVATION_SCHEMA", "CodexDispatchActivationSpec", "codex_dispatch_activation_plan_digest",
    "codex_dispatch_activation_spec_from_private_file", "execute_codex_dispatch_activation_marker",
    "execute_codex_dispatch_activation_plan",
    "plan_codex_dispatch_activation", "validate_codex_dispatch_activation_plan",
]
