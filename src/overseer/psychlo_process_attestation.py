"""Immutable, source-only identity attestation for a legacy Psychlo process.

This module deliberately has no terminal-input, tmux-send, process-kill, or
round-projection operation.  It records an independently revalidated identity
snapshot in the canonical primary authority database only.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from dataclasses import dataclass, field
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import re
import select
import sys
from typing import Any, Mapping

from .admin import AdminChangeKind, AdminChangePlan, plan_psychlo_legacy_process_binding_attestation
from .core import ApprovalLevel, OwnerDomain, RiskLevel
from .psychlo_contracts import canonical_digest
from .psychlo_bridge import CodexProjectDispatcher, PsychloBridge
from .psychlo_store import PsychloBridgeStore
from .store import SQLiteStore, _dump as _store_dump


SCHEMA = "psychlo.legacy-process-binding-attestation.v1"
_FORBIDDEN_KEYS = {"prompt", "rawprompt", "callback", "panecapture", "capture", "argv", "commandline"}
_TMUX = "/usr/bin/tmux"
_GIT = "/usr/bin/git"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# Process attestation is an authority operation, not a configurable adapter.
# These are the only accepted live endpoints.  Tests may replace this whole
# resolver before constructing an internal runtime, but no public operation
# accepts endpoint or evidence arguments.
CANONICAL_PRIMARY_DATABASE = Path("/home/god/.local/share/overseer/project/state/overseer.sqlite3")
CANONICAL_BRIDGE_DATABASE = Path("/home/god/.local/share/overseer/psychlo/bridge.sqlite3")
CANONICAL_PROTECTED_BINDING = Path("/home/god/.config/overseer/psychlo-project-bindings.json")
CANONICAL_CODEX_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
CANONICAL_TMUX_SOCKET = Path(f"/tmp/tmux-{os.getuid()}/default")
CANONICAL_SOURCE_ROOT = Path("/home/god/.local/share/overseer/project")
CANONICAL_CODEX_RELEASES = Path("/home/god/.codex/packages/standalone/releases")


class ProcessAttestationError(ValueError):
    pass


class TrustedEvidenceCollector:
    """Removed compatibility shim for the unsafe callback collector.

    A callback supplied by a caller is not an authority.  Keeping this name
    only as a rejecting shim makes old integrations fail closed instead of
    silently accepting operator-authored process evidence.
    """

    trusted = False

    def __init__(self, *_args: Any, **_kwargs: Any):
        raise ProcessAttestationError("operator evidence collectors are not supported; use AuthoritativeProcessEvidenceCollector")


def _validate_runtime_path(path: Path, *, label: str, regular: bool = True) -> tuple[int, int]:
    """Validate a fixed runtime artifact without resolving caller-selected links."""
    if not path.is_absolute() or path.is_symlink():
        raise ProcessAttestationError(f"{label} path is not canonical")
    current = Path("/")
    for component in path.parts[1:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ProcessAttestationError(f"{label} parent is unavailable") from error
        sticky_shared = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        system_private = metadata.st_uid == 0 and metadata.st_gid == 0 and not (stat.S_IMODE(metadata.st_mode) & 0o022)
        user_private = metadata.st_uid == os.getuid() and metadata.st_gid == os.getegid() and not (stat.S_IMODE(metadata.st_mode) & 0o002)
        if not stat.S_ISDIR(metadata.st_mode) or (not sticky_shared and not system_private and not user_private):
            raise ProcessAttestationError(f"{label} parent is not a trusted private-group directory")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProcessAttestationError(f"{label} does not exist") from error
    if regular and (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1):
        raise ProcessAttestationError(f"{label} is not a unique owned regular file")
    if not regular and (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid()):
        raise ProcessAttestationError(f"{label} is not a trusted socket")
    if stat.S_IMODE(metadata.st_mode) & 0o002:
        raise ProcessAttestationError(f"{label} is world-writable")
    return metadata.st_dev, metadata.st_ino


@dataclass
class _RuntimeAuthority:
    bridge: PsychloBridge
    primary: SQLiteStore
    collector: "AuthoritativeProcessEvidenceCollector"

    def close(self) -> None:
        self.collector.release_held_identities()
        self.bridge.close()


def _open_runtime_authority(round_id: str) -> _RuntimeAuthority:
    """Open only the fixed live authority stores and derive the exact session."""
    primary_identity = _validate_runtime_path(CANONICAL_PRIMARY_DATABASE, label="primary authority database")
    bridge_identity = _validate_runtime_path(CANONICAL_BRIDGE_DATABASE, label="Psychlo bridge database")
    if primary_identity == bridge_identity:
        raise ProcessAttestationError("primary and bridge databases must be distinct inodes")
    _validate_runtime_path(CANONICAL_PROTECTED_BINDING, label="protected binding")
    _validate_runtime_path(CANONICAL_CODEX_REGISTRY, label="canonical Codex registry")
    _validate_runtime_path(CANONICAL_TMUX_SOCKET, label="tmux socket", regular=False)
    bridge_store = PsychloBridgeStore(CANONICAL_BRIDGE_DATABASE)
    primary = SQLiteStore(CANONICAL_PRIMARY_DATABASE)
    dispatcher = CodexProjectDispatcher(CANONICAL_PROTECTED_BINDING)
    bridge = PsychloBridge(
        store=bridge_store,
        dispatcher=dispatcher,
        sender=lambda *_args, **_kwargs: {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        approval_store=primary,
        recover=False,
    )
    record = bridge_store.get_round(round_id)
    if record is None:
        bridge.close()
        raise ProcessAttestationError("round is missing")
    request = record[0]
    lead_id = request.get("projectLeadId") if isinstance(request, Mapping) else None
    if not isinstance(lead_id, str) or not lead_id.strip():
        bridge.close()
        raise ProcessAttestationError("round lead identity is missing")
    try:
        process_binding = dispatcher.process_binding_provenance(lead_id)
        target = process_binding["command"]
        if not isinstance(target, str) or not target.strip():
            raise ValueError("canonical tmux target is missing")
        collector = AuthoritativeProcessEvidenceCollector(
            bridge, CANONICAL_PROTECTED_BINDING, str(CANONICAL_TMUX_SOCKET), target, CANONICAL_SOURCE_ROOT,
        )
    except Exception as error:
        bridge.close()
        raise ProcessAttestationError("canonical process runtime is unavailable") from error
    return _RuntimeAuthority(bridge, primary, collector)


def _trusted_codex_executable() -> tuple[str, int, int, str]:
    """Resolve exactly one private Codex release executable, never a wrapper."""
    root = CANONICAL_CODEX_RELEASES
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProcessAttestationError("trusted Codex release directory is unavailable")
    candidates: list[Path] = []
    for candidate in root.rglob("codex"):
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid() and metadata.st_gid == os.getegid() and stat.S_IMODE(metadata.st_mode) & 0o022 == 0 and metadata.st_nlink == 1 and os.access(candidate, os.X_OK):
            candidates.append(candidate)
    if len(candidates) != 1:
        raise ProcessAttestationError("trusted Codex release executable is not unique")
    digest, metadata = _trusted_executable_snapshot(candidates[0])
    return str(candidates[0]), metadata.st_dev, metadata.st_ino, digest


@dataclass(frozen=True)
class AuthoritativeProcessEvidenceCollector:
    """Derive one manifest exclusively from live, application-owned sources.

    The constructor accepts handles and immutable paths, not evidence.  Both
    stage and attest call :meth:`collect`; there is no injection point for a
    prebuilt bridge, process, rollout, or source claim.
    """

    bridge: Any
    registry_path: str | Path
    tmux_socket: str
    tmux_target: str
    source_root: str | Path
    _held_pidfds: list[int] = field(default_factory=list, init=False, repr=False, compare=False)
    _held_proc_fds: list[int] = field(default_factory=list, init=False, repr=False, compare=False)
    _held_socket_fd: int | None = field(default=None, init=False, repr=False, compare=False)
    _held_socket_identity: tuple[int, int] | None = field(default=None, init=False, repr=False, compare=False)

    trusted = True

    def release_held_identities(self) -> None:
        while self._held_pidfds:
            try:
                os.close(self._held_pidfds.pop())
            except OSError:
                pass
        while self._held_proc_fds:
            try:
                os.close(self._held_proc_fds.pop())
            except OSError:
                pass
        if self._held_socket_fd is not None:
            try:
                os.close(self._held_socket_fd)
            except OSError:
                pass
            object.__setattr__(self, "_held_socket_fd", None)
        object.__setattr__(self, "_held_socket_identity", None)

    def _hold_identities(self, tmux: Mapping[str, Any], child: Mapping[str, Any]) -> None:
        self.release_held_identities()
        try:
            socket_fd = os.open(self.tmux_socket, getattr(os, "O_PATH", os.O_RDONLY) | os.O_NOFOLLOW)
            socket_meta = os.fstat(socket_fd)
            object.__setattr__(self, "_held_socket_fd", socket_fd)
            object.__setattr__(self, "_held_socket_identity", (socket_meta.st_dev, socket_meta.st_ino))
        except OSError as error:
            self.release_held_identities()
            raise ProcessAttestationError("tmux socket identity cannot be held through attestation") from error
        for identity in (tmux["serverProcess"], tmux["paneProcess"], child):
            try:
                self._held_pidfds.append(os.pidfd_open(int(identity["pid"])))
                self._held_proc_fds.append(os.open(f"/proc/{int(identity['pid'])}", getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW))
            except (AttributeError, OSError) as error:
                self.release_held_identities()
                raise ProcessAttestationError("process identity cannot be held through attestation") from error

    def revalidate_held_identities(self) -> None:
        if len(self._held_pidfds) != 3 or len(self._held_proc_fds) != 3:
            raise ProcessAttestationError("held process identities are incomplete")
        if self._held_socket_fd is None or self._held_socket_identity is None:
            raise ProcessAttestationError("held tmux socket identity is incomplete")
        if (os.fstat(self._held_socket_fd).st_dev, os.fstat(self._held_socket_fd).st_ino) != self._held_socket_identity or (capture_socket_identity(self.tmux_socket)["dev"], capture_socket_identity(self.tmux_socket)["ino"]) != self._held_socket_identity:
            raise ProcessAttestationError("tmux socket identity changed")
        for proc_fd in self._held_proc_fds:
            try:
                os.fstat(proc_fd)
            except OSError as error:
                raise ProcessAttestationError("held process proc identity became invalid") from error
        for fd in self._held_pidfds:
            try:
                os.fstat(fd)
                poller = select.poll()
                poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
                if poller.poll(0):
                    raise ProcessAttestationError("held process identity exited during attestation")
            except OSError as error:
                raise ProcessAttestationError("held process identity became invalid") from error

    def __post_init__(self) -> None:
        if not hasattr(self.bridge, "store") or not isinstance(self.tmux_socket, str) or not self.tmux_socket.startswith("/") or not isinstance(self.tmux_target, str) or not self.tmux_target.strip():
            raise ProcessAttestationError("authoritative bridge and process endpoints are required")
        dispatcher = getattr(self.bridge, "dispatcher", None)
        if not callable(getattr(dispatcher, "scan_rollout", None)) or not callable(getattr(dispatcher, "binding_provenance", None)):
            raise ProcessAttestationError("authoritative rollout dispatcher is required")

    def collect(self, round_id: str, plan_id: str) -> dict[str, Any]:
        if not isinstance(round_id, str) or not round_id.strip() or not isinstance(plan_id, str) or not plan_id.strip():
            raise ProcessAttestationError("round and plan identities are required")
        record = self.bridge.store.get_round(round_id)
        if record is None:
            raise ProcessAttestationError("round is missing")
        request, receipt, capability_hash, capability, dispatch_state, result, _ = record
        if dispatch_state != "started" or result is not None:
            raise ProcessAttestationError("only one started result-less round can be attested")
        if not isinstance(capability, str) or not capability.strip():
            raise ProcessAttestationError("round capability is missing")
        delivery = self.bridge.store.round_prompt_delivery(round_id)
        binding = self.bridge.store.round_binding(round_id)
        if delivery is None or delivery.get("phase") != "submitted" or binding is None:
            raise ProcessAttestationError("round delivery must be exactly submitted with an immutable binding")
        request_digest = sha256(json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        binding_digest = sha256(json.dumps(binding, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
        if delivery.get("requestDigest") != request_digest or delivery.get("capabilityHash") != capability_hash or delivery.get("binding") != binding or delivery.get("promptDigest") is None:
            raise ProcessAttestationError("bridge and delivery identity do not match")
        bridge_state = {
            "dispatchState": dispatch_state, "resultPresent": False,
            "deliveryPhase": delivery["phase"], "recoveryPresent": self.bridge.store.round_recovery(round_id) is not None,
            "failurePresent": self.bridge.store.operational_failure_intent(round_id) is not None,
            "cancelPresent": self.bridge.store.round_cancellation(round_id) is not None,
            "requestDigest": request_digest, "capabilityHash": capability_hash,
            "bindingDigest": binding_digest, "promptDigest": delivery["promptDigest"],
        }
        if any(bridge_state[key] for key in ("recoveryPresent", "failurePresent", "cancelPresent")):
            raise ProcessAttestationError("round has a conflicting recovery, failure, or cancellation record")
        lead_id = request.get("projectLeadId")
        if not isinstance(lead_id, str) or not lead_id.strip():
            raise ProcessAttestationError("round lead identity is missing")
        registry, registry_meta = read_private_json(self.registry_path)
        row = registry.get(lead_id)
        if not isinstance(row, Mapping) or set(row) != {"conversationId"} or not isinstance(row.get("conversationId"), str) or not row["conversationId"].strip():
            raise ProcessAttestationError("exact protected binding row identity is invalid")
        canonical = getattr(self.bridge.dispatcher, "process_binding_provenance", None)
        if not callable(canonical):
            raise ProcessAttestationError("canonical project registry process identity is required")
        try:
            process_binding = canonical(lead_id)
        except Exception as error:
            raise ProcessAttestationError("canonical project registry process identity is unavailable") from error
        required_process = {"conversationId", "sessionId", "workspace", "command", "launcher", "workspaceDev", "workspaceIno", "launcherDev", "launcherIno", "launcherDigest", "registryPath"}
        if not isinstance(process_binding, Mapping) or set(process_binding) != required_process or any(not isinstance(process_binding[key], str) or not process_binding[key].strip() for key in required_process):
            raise ProcessAttestationError("canonical project registry process identity is invalid")
        if binding.get("conversationId") != row["conversationId"] or process_binding["conversationId"] != row["conversationId"] or process_binding["sessionId"] != binding.get("sessionId"):
            raise ProcessAttestationError("registry and round binding conversation identity differ")
        if Path(process_binding["workspace"]).name.casefold() != str(request.get("projectId", "")).casefold():
            raise ProcessAttestationError("canonical workspace is not bound to the round project")
        codex_executable, codex_dev, codex_ino, codex_digest = _trusted_codex_executable()
        expected_start = f"codex resume {process_binding['conversationId']} --cd {process_binding['workspace']}"
        tmux = capture_tmux_identity(self.tmux_socket, self.tmux_target, expected_start_command=expected_start)
        pane_pid = int(tmux["paneProcess"]["pid"])
        if tmux.get("paneParentPid") != int(tmux["serverProcess"]["pid"]):
            raise ProcessAttestationError("tmux pane is not directly owned by its server")
        pane_executable = os.readlink(Path(f"/proc/{pane_pid}/exe"))
        if Path(pane_executable).name not in {"bash", "sh", "dash"} and not pane_executable.endswith(".sh"):
            raise ProcessAttestationError("tmux pane is not a trusted shell or launcher script")
        child = capture_direct_codex_child(pane_pid, expected_conversation_id=process_binding["conversationId"], expected_exe_digest=codex_digest, expected_exe_path=codex_executable, expected_exe_dev=codex_dev, expected_exe_ino=codex_ino, expected_workspace=process_binding["workspace"])
        self._hold_identities(tmux, child)
        if child.get("parentPid") != pane_pid:
            raise ProcessAttestationError("Codex child is not bound to the pane process")
        prompt = self.bridge._round_prompt(request, capability)
        scanner = self.bridge.dispatcher.scan_rollout
        if scanner(lead_id, prompt) is not False:
            raise ProcessAttestationError("rollout scan is not an authoritative strict negative result")
        scan = _require_negative_rollout(self.bridge.dispatcher.binding_provenance(lead_id), binding)
        source = capture_source_identity(self.source_root)
        # Re-read the mutable sources before returning the manifest.  The
        # attestation caller performs one more full collect immediately before
        # the CAS insert, so this is not a caller-authored snapshot.
        if scanner(lead_id, prompt) is not False or _require_negative_rollout(self.bridge.dispatcher.binding_provenance(lead_id), binding) != scan:
            raise ProcessAttestationError("rollout evidence changed during collection")
        if capture_tmux_identity(self.tmux_socket, self.tmux_target, expected_start_command=expected_start) != tmux:
            raise ProcessAttestationError("tmux identity changed during collection")
        return {
            "schemaVersion": SCHEMA, "attestationId": f"attestation-{round_id}", "roundId": round_id,
            "requestDigest": request_digest,
            "startedAt": (self.bridge.store.round_timing(round_id) or {}).get("startedAt"),
            "registry": {"pathDigest": registry_meta["digest"], "rowDigest": canonical_digest(dict(process_binding)), "conversationId": process_binding["conversationId"], "sessionId": process_binding["sessionId"], "workspaceDigest": sha256(process_binding["workspace"].encode()).hexdigest(), "commandDigest": sha256(process_binding["command"].encode()).hexdigest(), "launcherDigest": process_binding["launcherDigest"], "canonicalPathDigest": capture_private_file_digest(process_binding["registryPath"])},
            "tmux": tmux, "process": {"pane": tmux["paneProcess"], "codexChild": child},
            "rollout": scan, "bridge": bridge_state,
            "approval": {"planId": plan_id, "planDigest": ""}, "source": source,
        }


def collect_process_binding_evidence(**_operator_values: Any) -> dict[str, Any]:
    """Reject the former operator-evidence API instead of silently downgrading."""
    raise ProcessAttestationError("operator evidence collection is disabled; construct AuthoritativeProcessEvidenceCollector")


def admin_plan_digest(plan: Any) -> str:
    value = asdict(plan) if is_dataclass(plan) else dict(plan)
    return canonical_digest(value)


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    value = json.loads(json.dumps(dict(manifest)))
    approval = value.get("approval")
    if isinstance(approval, dict):
        approval.pop("planDigest", None)
    return canonical_digest(value)


def plan_psychlo_legacy_process_binding(*args: Any, **kwargs: Any) -> AdminChangePlan:
    """Compatibility alias with an intentionally explicit name."""
    return plan_psychlo_legacy_process_binding_attestation(*args, **kwargs)


def _open_private(path: Path) -> tuple[int, os.stat_result, os.stat_result]:
    if not path.is_absolute() or path.is_symlink():
        raise ProcessAttestationError("attestation path must be absolute and not a symlink")
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    try:
        for component in path.parent.parts[1:]:
            child = os.open(component, flags, dir_fd=parent)
            parent_stat = os.fstat(child)
            sticky_shared = parent_stat.st_uid == 0 and bool(parent_stat.st_mode & stat.S_ISVTX)
            if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid not in {0, os.getuid()} or ((parent_stat.st_mode & 0o022) and not sticky_shared):
                os.close(child)
                raise ProcessAttestationError("attestation parent is not private")
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077:
        os.close(fd)
        raise ProcessAttestationError("attestation file is not a private regular file")
    path_stat = os.stat(path, follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (path_stat.st_dev, path_stat.st_ino, path_stat.st_size, path_stat.st_mtime_ns, path_stat.st_ctime_ns):
        os.close(fd)
        raise ProcessAttestationError("attestation file changed during open")
    return fd, before, path_stat


def read_private_json(path: str | Path, *, expected_digest: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    fd, before, _ = _open_private(Path(path))
    try:
        chunks: list[bytes] = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        content = b"".join(chunks)
        after = os.fstat(fd)
        digest = sha256(content).hexdigest()
        if before != after or expected_digest is not None and digest != expected_digest:
            raise ProcessAttestationError("attestation file changed during read")
        try:
            value = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProcessAttestationError("attestation JSON is invalid") from error
        if not isinstance(value, dict):
            raise ProcessAttestationError("attestation JSON must be an object")
        metadata = {"dev": before.st_dev, "ino": before.st_ino, "size": before.st_size, "mtime": before.st_mtime_ns, "ctime": before.st_ctime_ns, "digest": digest}
        return value, metadata
    finally:
        os.close(fd)


def capture_private_file_digest(path: str | Path) -> str:
    """Read and digest an owner-only canonical registry without following links."""
    fd, before, _ = _open_private(Path(path))
    try:
        chunks: list[bytes] = []
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
        after = os.fstat(fd)
        if before != after:
            raise ProcessAttestationError("canonical registry changed during read")
        return sha256(b"".join(chunks)).hexdigest()
    finally:
        os.close(fd)


def _atomic_private_write(path: Path, content: bytes) -> None:
    """Create/replace a private manifest without following a temp symlink."""
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(fd, content[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ProcessAttestationError("private manifest write failed") from error


def _require_negative_rollout(value: Any, binding: Mapping[str, Any]) -> dict[str, Any]:
    """Accept only the driver's exact negative scan and binding identity."""
    if not isinstance(value, Mapping) or value.get("found") is not False:
        raise ProcessAttestationError("rollout scan is not an authoritative negative result")
    required = {"found", "conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno"}
    if set(value) != required or value.get("conversationId") != binding.get("conversationId") or value.get("sessionId") != binding.get("sessionId") or value.get("rolloutPathDigest") != binding.get("rolloutPathDigest") or value.get("rolloutDev") != binding.get("rolloutDev") or value.get("rolloutIno") != binding.get("rolloutIno"):
        raise ProcessAttestationError("rollout scan binding identity is not exact")
    if not isinstance(value["rolloutPathDigest"], str) or not _HEX64.fullmatch(value["rolloutPathDigest"]):
        raise ProcessAttestationError("rollout scan digest is invalid")
    if isinstance(value["rolloutDev"], bool) or not isinstance(value["rolloutDev"], int) or value["rolloutDev"] <= 0 or isinstance(value["rolloutIno"], bool) or not isinstance(value["rolloutIno"], int) or value["rolloutIno"] <= 0:
        raise ProcessAttestationError("rollout scan file identity is invalid")
    return dict(value)


def capture_source_identity(source_root: str | Path) -> dict[str, str]:
    """Derive source lineage with an absolute, trusted read-only git binary."""
    root = Path(source_root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProcessAttestationError("source root is not a trusted directory")
    metadata = root.stat(follow_symlinks=False)
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ProcessAttestationError("source root is not private")
    executable = Path(_GIT)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "LANG": "C", "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_NOGLOBAL": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    status = subprocess.run((_GIT, "-C", str(root), "status", "--porcelain", "--untracked-files=all", "--", "src", "pyproject.toml"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    if status.returncode != 0 or status.stdout.strip():
        raise ProcessAttestationError("source runtime tree is dirty")
    module = Path(__file__).resolve()
    try:
        module.relative_to(root.resolve())
    except ValueError as error:
        raise ProcessAttestationError("loaded attestation module is outside the source root") from error
    module_meta = module.stat(follow_symlinks=False)
    if module_meta.st_uid != os.getuid() or stat.S_IMODE(module_meta.st_mode) & 0o022:
        raise ProcessAttestationError("loaded attestation module is not trusted")
    try:
        module_bytes = module.read_bytes()
    except OSError as error:
        raise ProcessAttestationError("loaded attestation module cannot be read") from error
    try:
        git_meta = executable.stat(follow_symlinks=False)
        if not stat.S_ISREG(git_meta.st_mode) or git_meta.st_uid != 0 or stat.S_IMODE(git_meta.st_mode) & 0o022:
            raise OSError("unsafe git executable")
    except OSError as error:
        raise ProcessAttestationError("git executable is not trusted") from error
    try:
        commit = subprocess.run((_GIT, "-C", str(root), "rev-parse", "--verify", "HEAD"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
        tree = subprocess.run((_GIT, "-C", str(root), "rev-parse", "--verify", "HEAD^{tree}"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    except OSError as error:
        raise ProcessAttestationError("source lineage query failed") from error
    commit_id = commit.stdout.strip()
    tree_id = tree.stdout.strip()
    if commit.returncode != 0 or tree.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit_id) or not re.fullmatch(r"[0-9a-f]{40}", tree_id):
        raise ProcessAttestationError("source lineage is not a verified commit/tree")
    dependencies: dict[str, str] = {}
    for name, loaded in sorted(sys.modules.items()):
        loaded_path = getattr(loaded, "__file__", None)
        if not isinstance(loaded_path, str) or not loaded_path.endswith((".py", ".pyc")):
            continue
        try:
            resolved = Path(loaded_path).resolve(strict=True)
            resolved.relative_to(root.resolve())
            dependency_bytes = resolved.read_bytes()
        except (OSError, ValueError):
            continue
        dependencies[name] = sha256(dependency_bytes).hexdigest()
    try:
        interpreter_path = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise ProcessAttestationError("interpreter executable is unavailable") from error
    interpreter_digest, interpreter_meta = _trusted_executable_snapshot(interpreter_path)
    return {
        "commit": commit_id, "treeDigest": tree_id, "moduleDigest": sha256(module_bytes).hexdigest(),
        "runtimeDependencies": dependencies,
        "interpreter": {"dev": interpreter_meta.st_dev, "ino": interpreter_meta.st_ino, "digest": interpreter_digest},
    }


def _validate_redacted(value: Any, *, path: str = "manifest") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).replace("_", "").lower()
            if normalized in _FORBIDDEN_KEYS:
                raise ProcessAttestationError(f"{path} contains forbidden raw evidence")
            _validate_redacted(item, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_redacted(item, path=f"{path}[{index}]")


def _manifest(value: Mapping[str, Any], round_id: str) -> dict[str, Any]:
    if set(value) != {"schemaVersion", "attestationId", "roundId", "requestDigest", "startedAt", "registry", "tmux", "process", "rollout", "bridge", "approval", "source"}:
        raise ProcessAttestationError("manifest fields are not exact")
    if value.get("schemaVersion") != SCHEMA or value.get("roundId") != round_id:
        raise ProcessAttestationError("manifest identity is invalid")
    _validate_redacted(value)
    if not isinstance(value.get("startedAt"), str) or not value["startedAt"].strip():
        raise ProcessAttestationError("round start identity is invalid")
    for key in ("requestDigest",):
        if not isinstance(value.get(key), str) or not _HEX64.fullmatch(value[key]):
            raise ProcessAttestationError("manifest digest is invalid")
    approval = value.get("approval")
    if not isinstance(approval, Mapping) or set(approval) != {"planId", "planDigest"} or not isinstance(approval["planId"], str) or not approval["planId"].strip() or not isinstance(approval["planDigest"], str) or (approval["planDigest"] and not _HEX64.fullmatch(approval["planDigest"])):
        raise ProcessAttestationError("manifest approval identity is invalid")
    bridge = value.get("bridge")
    if not isinstance(bridge, Mapping) or set(bridge) != {"dispatchState", "resultPresent", "deliveryPhase", "recoveryPresent", "failurePresent", "cancelPresent", "requestDigest", "capabilityHash", "bindingDigest", "promptDigest"}:
        raise ProcessAttestationError("bridge state evidence is invalid")
    if bridge.get("dispatchState") != "started" or bridge.get("resultPresent") is not False or bridge.get("deliveryPhase") != "submitted" or any(bridge.get(key) is not False for key in ("recoveryPresent", "failurePresent", "cancelPresent")):
        raise ProcessAttestationError("bridge is not the exact submitted result-less state")
    if any(not isinstance(bridge.get(key), str) or not _HEX64.fullmatch(bridge[key]) for key in ("requestDigest", "capabilityHash", "bindingDigest", "promptDigest")):
        raise ProcessAttestationError("bridge digest evidence is invalid")
    registry = value.get("registry")
    if not isinstance(registry, Mapping) or set(registry) != {"pathDigest", "rowDigest", "conversationId", "sessionId", "workspaceDigest", "commandDigest", "launcherDigest", "canonicalPathDigest"} or any(not isinstance(registry[key], str) or not registry[key].strip() for key in registry):
        raise ProcessAttestationError("registry identity evidence is invalid")
    if any(not _HEX64.fullmatch(str(registry[key])) for key in ("pathDigest", "rowDigest", "workspaceDigest", "commandDigest", "launcherDigest", "canonicalPathDigest")):
        raise ProcessAttestationError("registry digest evidence is invalid")
    tmux = value.get("tmux")
    if not isinstance(tmux, Mapping) or set(tmux) != {"socket", "sessionId", "windowId", "paneId", "paneCommandDigest", "paneStartCommandDigest", "serverProcess", "paneProcess", "paneParentPid", "serverEvidence"} or tmux.get("serverEvidence") != "list-sessions-and-list-panes-explicit-socket":
        raise ProcessAttestationError("tmux identity evidence is invalid")
    socket_identity = tmux.get("socket")
    if not isinstance(socket_identity, Mapping) or set(socket_identity) != {"dev", "ino", "mode", "uid", "pathDigest"} or any(not isinstance(socket_identity[key], int) or isinstance(socket_identity[key], bool) for key in ("dev", "ino", "mode", "uid")) or not _HEX64.fullmatch(str(socket_identity.get("pathDigest"))):
        raise ProcessAttestationError("tmux socket identity evidence is invalid")
    if not isinstance(tmux.get("paneCommandDigest"), str) or not _HEX64.fullmatch(tmux["paneCommandDigest"]) or not isinstance(tmux.get("paneStartCommandDigest"), str) or not _HEX64.fullmatch(tmux["paneStartCommandDigest"]) or not isinstance(tmux.get("paneParentPid"), int) or isinstance(tmux["paneParentPid"], bool) or tmux["paneParentPid"] <= 0:
        raise ProcessAttestationError("tmux command identity evidence is invalid")
    for name in ("serverProcess", "paneProcess"):
        identity = tmux.get(name)
        if not isinstance(identity, Mapping) or set(identity) != {"pid", "startTicks", "exeDigest", "argvDigest", "cgroupDigest", "pidfdSupported"}:
            raise ProcessAttestationError("tmux process identity evidence is invalid")
        if any(not isinstance(identity[key], int) or isinstance(identity[key], bool) or identity[key] <= 0 for key in ("pid", "startTicks")) or any(not isinstance(identity[key], str) or not _HEX64.fullmatch(identity[key]) for key in ("exeDigest", "argvDigest", "cgroupDigest")) or identity["pidfdSupported"] is not True:
            raise ProcessAttestationError("tmux process identity evidence is invalid")
    source = value.get("source")
    if not isinstance(source, Mapping) or set(source) != {"commit", "treeDigest", "moduleDigest", "runtimeDependencies", "interpreter"}:
        raise ProcessAttestationError("source lineage evidence is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", str(source["commit"])) or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", str(source["treeDigest"])) or not _HEX64.fullmatch(str(source["moduleDigest"])) or not isinstance(source["runtimeDependencies"], Mapping) or any(not isinstance(key, str) or not isinstance(item, str) or not _HEX64.fullmatch(item) for key, item in source["runtimeDependencies"].items()):
        raise ProcessAttestationError("source lineage evidence is invalid")
    interpreter = source["interpreter"]
    if not isinstance(interpreter, Mapping) or set(interpreter) != {"dev", "ino", "digest"} or any(not isinstance(interpreter[key], int) or isinstance(interpreter[key], bool) or interpreter[key] <= 0 for key in ("dev", "ino")) or not _HEX64.fullmatch(str(interpreter["digest"])):
        raise ProcessAttestationError("source interpreter identity is invalid")
    process = value.get("process")
    if not isinstance(process, Mapping) or set(process) != {"pane", "codexChild"} or not isinstance(process["pane"], Mapping) or not isinstance(process["codexChild"], Mapping):
        raise ProcessAttestationError("process identity evidence is incomplete")
    if process["pane"] != tmux["paneProcess"] or process["codexChild"].get("parentPid") != tmux["paneProcess"]["pid"] or tmux["paneParentPid"] != tmux["serverProcess"]["pid"] or tmux["serverProcess"]["pid"] == tmux["paneProcess"]["pid"]:
        raise ProcessAttestationError("process and tmux identity bindings are not exact")
    child = process["codexChild"]
    if set(child) != {"pid", "startTicks", "exeDigest", "argvDigest", "cgroupDigest", "pidfdSupported", "parentPid"} or child["pid"] <= 0 or child["startTicks"] <= 0 or child["pidfdSupported"] is not True or child["parentPid"] <= 0 or any(not isinstance(child[key], str) or not _HEX64.fullmatch(child[key]) for key in ("exeDigest", "argvDigest", "cgroupDigest")):
        raise ProcessAttestationError("Codex child identity evidence is invalid")
    rollout = value.get("rollout")
    if not isinstance(rollout, Mapping) or set(rollout) != {"found", "conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno"} or rollout.get("found") is not False:
        raise ProcessAttestationError("rollout negative scan evidence is required")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _immutable_plan_digest(plan: AdminChangePlan) -> str:
    value = asdict(plan)
    for key in ("approved", "approved_by", "approved_at", "canceled", "canceled_by", "canceled_at", "cancellation_reason", "archived", "archived_by", "archived_at", "archive_record_id"):
        value.pop(key, None)
    return canonical_digest(value)


def _assert_exact_plan(primary: SQLiteStore, plan_id: str, round_id: str, manifest: Mapping[str, Any], *, approved: bool) -> AdminChangePlan:
    plan = primary.load_admin_change_plan(plan_id)
    source = manifest["source"]
    expected = plan_psychlo_legacy_process_binding_attestation(
        plan_id, round_id, manifest_digest(manifest), source["commit"], source["treeDigest"], source["moduleDigest"],
    )
    if _immutable_plan_digest(plan) != _immutable_plan_digest(expected):
        raise ProcessAttestationError("authoritative plan immutable identity changed")
    if approved and (not plan.approved or plan.approved_by != "sisko" or plan.canceled or not plan.approved_at):
        raise ProcessAttestationError("exact approved Sisko plan is required")
    if not approved and plan.approved:
        raise ProcessAttestationError("staged process plan is unexpectedly approved")
    return plan


def _assert_runtime_source_integrity() -> None:
    """Ensure the loaded attestation module is the reviewed runtime source."""
    module = Path(__file__).resolve()
    root = CANONICAL_SOURCE_ROOT.resolve()
    try:
        module.relative_to(root)
    except ValueError as error:
        raise ProcessAttestationError("loaded process attestation module is outside canonical source") from error
    capture_source_identity(root)


def stage_process_attestation(*, round_id: str, plan_id: str) -> dict[str, Any]:
    """Derive and durably prepare one exact plan in the canonical primary DB."""
    if not all(isinstance(value, str) and value.strip() for value in (round_id, plan_id)):
        raise ProcessAttestationError("round and plan identities are required")
    _assert_runtime_source_integrity()
    runtime = _open_runtime_authority(round_id)
    try:
        data = runtime.collector.collect(round_id, plan_id)
        data = dict(data)
        data.setdefault("schemaVersion", SCHEMA)
        data.setdefault("attestationId", f"attestation-{round_id}")
        data.setdefault("roundId", round_id)
        data.setdefault("approval", {"planId": plan_id, "planDigest": ""})
        value = _manifest(data, round_id)
        if value["approval"]["planId"] != plan_id:
            raise ProcessAttestationError("manifest plan identity is not exact")
        digest = manifest_digest(value)
        source = value["source"]
        plan = plan_psychlo_legacy_process_binding_attestation(plan_id, round_id, digest, source["commit"], source["treeDigest"], source["moduleDigest"])
        primary = runtime.primary
        primary._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = None
            try:
                existing = primary.load_admin_change_plan(plan_id)
            except KeyError:
                primary._connection.execute("INSERT INTO admin_change_plans(id,payload) VALUES (?,?)", (plan_id, _store_dump(plan)))
            else:
                if _immutable_plan_digest(existing) != _immutable_plan_digest(plan):
                    raise ProcessAttestationError("staged authority plan identity changed")
                if existing.approved or existing.canceled:
                    raise ProcessAttestationError("staged process plan lifecycle is not mutable")
            primary.insert_prepared_process_binding_attestation(
                attestation_id=str(value["attestationId"]), round_id=round_id, plan_id=plan_id,
                manifest_digest=digest, manifest=value, inserted_at=runtime.bridge.clock(),
            )
            primary._connection.commit()
        except Exception:
            primary._connection.rollback()
            raise
        return {"staged": True, "roundId": round_id, "planId": plan_id, "manifestDigest": digest}
    except Exception as error:
        raise ProcessAttestationError("authoritative evidence collection failed") from error
    finally:
        runtime.close()


def finalize_process_attestation(*, plan_id: str) -> dict[str, Any]:
    """Compatibility command: report the exact current plan lifecycle only."""
    _validate_runtime_path(CANONICAL_PRIMARY_DATABASE, label="primary authority database")
    primary = SQLiteStore(CANONICAL_PRIMARY_DATABASE)
    try:
        plan = primary.load_admin_change_plan(plan_id)
        if plan.kind != AdminChangeKind.PSYCHLO_LEGACY_PROCESS_BINDING_ATTESTATION:
            raise ProcessAttestationError("exact process attestation plan is required")
        return {"finalized": bool(plan.approved and plan.approved_by == "sisko" and not plan.canceled), "planId": plan.id}
    finally:
        primary.close()


def capture_process_identity(pid: int) -> dict[str, Any]:
    if not isinstance(pid, int) or pid <= 0:
        raise ProcessAttestationError("PID is invalid")
    proc = Path(f"/proc/{pid}")
    pidfd: int | None = None
    try:
        if hasattr(os, "pidfd_open"):
            pidfd = os.pidfd_open(pid)
        raw_stat = _read_proc_bytes(proc / "stat").decode("utf-8")
        end_comm = raw_stat.rfind(")")
        if end_comm < 0:
            raise ValueError("process stat comm is invalid")
        stat_line = raw_stat[end_comm + 2 :].split()
        start_ticks = int(stat_line[19])
        exe_target = os.readlink(proc / "exe")
        argv_digest = sha256(_read_proc_bytes(proc / "cmdline")).hexdigest()
        cgroup_digest = sha256(_read_proc_bytes(proc / "cgroup")).hexdigest()
        final_exe_target = os.readlink(proc / "exe")
        final_stat = _read_proc_bytes(proc / "stat").decode("utf-8")
        final_end = final_stat.rfind(")")
        if final_end < 0 or int(final_stat[final_end + 2 :].split()[19]) != start_ticks or final_exe_target != exe_target:
            raise ProcessAttestationError("process identity changed during read")
        pidfd_supported = pidfd is not None
    except (OSError, ValueError, IndexError) as error:
        raise ProcessAttestationError("process identity cannot be read") from error
    finally:
        if pidfd is not None:
            os.close(pidfd)
    executable_digest, _ = _trusted_executable_snapshot(exe_target)
    return {"pid": pid, "startTicks": start_ticks, "exeDigest": executable_digest, "argvDigest": argv_digest, "cgroupDigest": cgroup_digest, "pidfdSupported": pidfd_supported}


def _trusted_executable_snapshot(path: str | Path) -> tuple[str, os.stat_result]:
    """Digest one exact executable inode without following a replacement link."""
    executable = Path(path)
    if not executable.is_absolute():
        raise ProcessAttestationError("process executable path is not absolute")
    try:
        fd = os.open(str(executable), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProcessAttestationError("process executable cannot be opened safely") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, os.getuid()} or stat.S_IMODE(before.st_mode) & 0o022:
            raise ProcessAttestationError("process executable ownership is unsafe")
        chunks: list[bytes] = []
        while chunk := os.read(fd, 1 << 20):
            chunks.append(chunk)
        after = os.fstat(fd)
        identity_before = (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if identity_before != identity_after:
            raise ProcessAttestationError("process executable changed during digest")
        return sha256(b"".join(chunks)).hexdigest(), before
    except OSError as error:
        raise ProcessAttestationError("process executable cannot be digested") from error
    finally:
        os.close(fd)


def _read_proc_bytes(path: Path) -> bytes:
    try:
        # Keep one O_PATH handle to the PID directory while opening each
        # pseudo-file.  This prevents a later PID reuse from silently
        # changing the parent directory between reads.
        parent = path.parent
        if parent.parent == Path("/proc") and parent.name.isdigit():
            parent_fd = os.open(str(parent), getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        else:
            parent_fd = None
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise ProcessAttestationError("process evidence cannot be opened safely") from error
    try:
        before = os.fstat(fd)
        data = os.read(fd, 1 << 20)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ProcessAttestationError("process evidence changed during read")
        return data
    finally:
        os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _proc_parent_pid(pid: int) -> int:
    raw = _read_proc_bytes(Path(f"/proc/{pid}/stat")).decode("utf-8")
    end_comm = raw.rfind(")")
    if end_comm < 0:
        raise ProcessAttestationError("process parent identity is invalid")
    fields = raw[end_comm + 2 :].split()
    try:
        return int(fields[1])
    except (IndexError, ValueError) as error:
        raise ProcessAttestationError("process parent identity is invalid") from error


def capture_direct_codex_child(parent_pid: int, *, expected_argv_digest: str | None = None, expected_conversation_id: str | None = None, expected_exe_digest: str | None = None, expected_exe_path: str | None = None, expected_exe_dev: int | None = None, expected_exe_ino: int | None = None, expected_workspace: str | None = None) -> dict[str, Any]:
    """Require exactly one direct child and persist only redacted identity."""
    parent_before = capture_process_identity(parent_pid)
    workspace_identity = _cwd_identity(parent_pid, expected_workspace) if expected_workspace is not None else None
    try:
        children = [int(item) for item in _read_proc_bytes(Path(f"/proc/{parent_pid}/task/{parent_pid}/children")).decode().split()]
    except (OSError, ValueError) as error:
        raise ProcessAttestationError("direct child list cannot be read") from error
    if len(children) != 1:
        raise ProcessAttestationError("exactly one direct Codex child is required")
    identity = capture_process_identity(children[0])
    if expected_argv_digest is not None and identity["argvDigest"] != expected_argv_digest:
        raise ProcessAttestationError("direct Codex child command identity changed")
    if expected_conversation_id is not None:
        raw = _read_proc_bytes(Path(f"/proc/{children[0]}/cmdline"))
        argv = raw.split(b"\0")[:-1]
        expected = [b"codex", b"resume", expected_conversation_id.encode("utf-8")]
        if expected_workspace is not None:
            expected.extend((b"--cd", expected_workspace.encode("utf-8")))
        if argv != expected:
            raise ProcessAttestationError("direct child command is not bound to the expected conversation")
    try:
        executable = os.readlink(Path(f"/proc/{children[0]}/exe"))
    except OSError as error:
        raise ProcessAttestationError("direct child executable cannot be verified") from error
    if expected_exe_path is None or executable != expected_exe_path:
        raise ProcessAttestationError("direct child is not the exact trusted executable")
    exe_stat = Path(executable).stat(follow_symlinks=False)
    if exe_stat.st_uid != os.getuid() and exe_stat.st_uid != 0 or stat.S_IMODE(exe_stat.st_mode) & 0o022:
        raise ProcessAttestationError("direct child executable ownership is unsafe")
    executable_digest, executable_meta = _trusted_executable_snapshot(executable)
    if identity["exeDigest"] != executable_digest:
        raise ProcessAttestationError("direct child executable identity changed")
    if expected_exe_digest is not None and executable_digest != expected_exe_digest:
        raise ProcessAttestationError("direct child executable identity changed")
    if expected_exe_dev is not None and expected_exe_ino is not None and (executable_meta.st_dev != expected_exe_dev or executable_meta.st_ino != expected_exe_ino):
        raise ProcessAttestationError("direct child executable file identity changed")
    if expected_workspace is not None and _cwd_identity(children[0], expected_workspace) != workspace_identity:
        raise ProcessAttestationError("direct child cwd is not the canonical workspace")
    try:
        after = [int(item) for item in _read_proc_bytes(Path(f"/proc/{parent_pid}/task/{parent_pid}/children")).decode().split()]
    except (OSError, ValueError) as error:
        raise ProcessAttestationError("direct child list cannot be revalidated") from error
    parent_after = capture_process_identity(parent_pid)
    child_after = capture_process_identity(children[0])
    if after != children or parent_after["startTicks"] != parent_before["startTicks"] or parent_after["exeDigest"] != parent_before["exeDigest"] or child_after["startTicks"] != identity["startTicks"] or child_after["exeDigest"] != identity["exeDigest"] or child_after["cgroupDigest"] != identity["cgroupDigest"]:
        raise ProcessAttestationError("direct child changed during attestation")
    identity["parentPid"] = parent_pid
    return identity


def _cwd_identity(pid: int, expected_workspace: str) -> tuple[int, int]:
    try:
        cwd = os.readlink(Path(f"/proc/{pid}/cwd"))
        metadata = Path(cwd).stat(follow_symlinks=False)
    except OSError as error:
        raise ProcessAttestationError("process workspace cannot be verified") from error
    expected = Path(expected_workspace)
    if not expected.is_absolute() or cwd != str(expected) or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ProcessAttestationError("process cwd is not the canonical workspace")
    return metadata.st_dev, metadata.st_ino


def capture_socket_identity(socket_path: str | Path) -> dict[str, Any]:
    path = Path(socket_path)
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077:
            raise OSError("unsafe tmux socket")
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ProcessAttestationError("tmux socket identity cannot be established") from error
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid):
        raise ProcessAttestationError("tmux socket changed during attestation")
    return {"dev": before.st_dev, "ino": before.st_ino, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid}


def capture_tmux_identity(socket_path: str, target: str, *, expected_command: str | None = None, expected_start_command: str | None = None) -> dict[str, Any]:
    """Capture headless-safe tmux evidence through explicit socket/list-panes."""
    if not Path(socket_path).is_absolute() or not target.strip():
        raise ProcessAttestationError("tmux socket and target are required")
    socket_identity = capture_socket_identity(socket_path)
    executable = Path(_TMUX)
    try:
        executable_stat = executable.stat(follow_symlinks=False)
        if not stat.S_ISREG(executable_stat.st_mode) or executable_stat.st_uid != 0 or executable_stat.st_mode & 0o022:
            raise OSError("unsafe tmux executable")
    except OSError as error:
        raise ProcessAttestationError("tmux executable is not trusted") from error
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
    def query() -> tuple[str, str]:
        sessions = subprocess.run((_TMUX, "-S", socket_path, "list-sessions", "-F", "#{session_id}|#{pid}"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
        result = subprocess.run((_TMUX, "-S", socket_path, "list-panes", "-a", "-F", "#{session_id}|#{window_id}|#{pane_id}|#{pane_pid}|#{pane_current_command}|#{pane_start_command}"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
        if sessions.returncode != 0 or result.returncode != 0:
            raise ProcessAttestationError("tmux identity query failed")
        return sessions.stdout, result.stdout
    sessions_stdout, panes_stdout = query()
    sessions_again, panes_again = query()
    if (sessions_stdout, panes_stdout) != (sessions_again, panes_again):
        raise ProcessAttestationError("tmux identity changed during attestation")
    if capture_socket_identity(socket_path) != socket_identity:
        raise ProcessAttestationError("tmux identity query failed")
    raw_matches = [line.split("|") for line in panes_stdout.splitlines() if len(line.split("|")) in {4, 5, 6} and (line.split("|")[0] == target or line.split("|")[2] == target)]
    if len(raw_matches) != 1 or ((expected_command is not None or expected_start_command is not None) and len(raw_matches[0]) != 6):
        raise ProcessAttestationError("tmux target identity is not unique")
    if len(raw_matches[0]) == 4:
        session_id, window_id, pane_id, pane_pid = raw_matches[0]
        pane_command = ""
        pane_start_command = ""
    else:
        session_id, window_id, pane_id, pane_pid, pane_command = raw_matches[0][:5]
        pane_start_command = raw_matches[0][5] if len(raw_matches[0]) == 6 else ""
    if expected_command is not None and pane_command != expected_command:
        raise ProcessAttestationError("tmux pane command is not bound to the registry command")
    if expected_start_command is not None and pane_start_command != expected_start_command:
        raise ProcessAttestationError("tmux pane start command is not the exact Codex resume chain")
    if (expected_command is not None or expected_start_command is not None) and not pane_start_command:
        raise ProcessAttestationError("tmux pane start command is unavailable")
    server_rows = [line.split("|") for line in sessions_stdout.splitlines() if len(line.split("|")) == 2 and line.split("|")[0] == session_id]
    if len(server_rows) != 1 or not server_rows[0][1].isdigit():
        raise ProcessAttestationError("tmux server identity is not unique")
    return {"socket": {**socket_identity, "pathDigest": sha256(socket_path.encode()).hexdigest()}, "sessionId": session_id, "windowId": window_id, "paneId": pane_id, "paneCommandDigest": sha256(pane_command.encode()).hexdigest(), "paneStartCommandDigest": sha256(pane_start_command.encode()).hexdigest(), "serverProcess": capture_process_identity(int(server_rows[0][1])), "paneProcess": capture_process_identity(int(pane_pid)), "paneParentPid": _proc_parent_pid(int(pane_pid)), "serverEvidence": "list-sessions-and-list-panes-explicit-socket"}


def _validate_bridge_round(bridge: PsychloBridgeStore, round_id: str, manifest: Mapping[str, Any]) -> None:
    """Read-fence the exact bridge state; this function performs no writes."""
    row = bridge.connection.execute("SELECT request_json,capability_hash,dispatch_state,result_json,codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
    delivery = bridge.connection.execute("SELECT request_digest,capability_hash,binding_json,phase,prompt_digest FROM round_prompt_deliveries WHERE round_id=?", (round_id,)).fetchone()
    forbidden = any(bridge.connection.execute(f"SELECT 1 FROM {table} WHERE round_id=? LIMIT 1", (round_id,)).fetchone() is not None for table in ("round_recoveries", "operational_failure_intents", "round_cancellations"))
    bridge_state = manifest.get("bridge") if isinstance(manifest, Mapping) else None
    request_digest = None
    if row is not None:
        request_digest = bridge._round_request_digest(json.loads(row[0]))
    if row is None or row[2] != "started" or row[3] is not None or not isinstance(row[4], str) or forbidden or delivery is None or delivery[0] != request_digest or delivery[1] != row[1] or delivery[2] != row[4] or delivery[3] != "submitted" or not isinstance(bridge_state, Mapping) or bridge_state.get("requestDigest") != request_digest or bridge_state.get("capabilityHash") != row[1] or bridge_state.get("bindingDigest") != sha256(row[4].encode()).hexdigest() or delivery[4] != bridge_state.get("promptDigest"):
        raise ProcessAttestationError("bridge state changed before primary publication")


def attest_process_binding(*, round_id: str, plan_id: str) -> dict[str, Any]:
    """Publish one exact completed attestation in the canonical primary DB.

    The bridge transaction is a read fence only.  The primary transaction owns
    the sole publication and is committed before the bridge read fence closes;
    replay returns that exact completed primary row.
    """
    if not all(isinstance(value, str) and value.strip() for value in (round_id, plan_id)):
        raise ProcessAttestationError("round and plan identities are required")
    _assert_runtime_source_integrity()
    runtime = _open_runtime_authority(round_id)
    bridge_connection = runtime.bridge.store.connection
    primary_connection = runtime.primary._connection
    try:
        fresh = runtime.collector.collect(round_id, plan_id)
        fresh_again = runtime.collector.collect(round_id, plan_id)
        if manifest_digest(fresh) != manifest_digest(fresh_again) or fresh != fresh_again:
            raise ProcessAttestationError("process evidence changed before publication")
        manifest = _manifest(fresh, round_id)
        digest = manifest_digest(manifest)
        bridge_connection.execute("BEGIN IMMEDIATE")
        _validate_bridge_round(runtime.bridge.store, round_id, manifest)
        primary_connection.execute("BEGIN IMMEDIATE")
        try:
            plan = _assert_exact_plan(runtime.primary, plan_id, round_id, manifest, approved=True)
            row = primary_connection.execute("SELECT attestation_id,round_id,plan_id,manifest_digest,plan_digest,state,manifest_json FROM psychlo_process_binding_attestations WHERE round_id=?", (round_id,)).fetchone()
            encoded = json.dumps(dict(manifest), sort_keys=True, separators=(",", ":"))
            if row is None:
                raise ProcessAttestationError("prepared process attestation is missing")
            if tuple(row[1:4]) != (round_id, plan_id, digest) or row[6] != encoded or row[5] not in {"prepared", "completed"}:
                raise ProcessAttestationError("prepared process attestation identity changed")
            plan_digest = admin_plan_digest(plan)
            runtime.collector.revalidate_held_identities()
            result = runtime.primary.complete_process_binding_attestation(round_id=round_id, plan_id=plan_id, manifest_digest=digest, plan_digest=plan_digest, completed_at=runtime.bridge.clock())
            primary_connection.commit()
        except Exception:
            primary_connection.rollback()
            raise
        bridge_connection.commit()
        return {"accepted": True, "roundId": round_id, "attestationId": result["attestationId"], "manifestDigest": result["manifestDigest"], "planDigest": result["planDigest"]}
    except Exception as error:
        try:
            if primary_connection.in_transaction:
                primary_connection.rollback()
        except Exception:
            pass
        try:
            if bridge_connection.in_transaction:
                bridge_connection.rollback()
        except Exception:
            pass
        raise ProcessAttestationError(str(error)) from error
    finally:
        runtime.close()
