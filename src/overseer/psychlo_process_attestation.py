"""Immutable, source-only historical observation for a legacy Psychlo process.

This module deliberately has no terminal-input, tmux-send, process-kill, or
round-projection operation.  It records an independently revalidated identity
snapshot in the canonical primary database only.  The resulting record is
historical evidence, never authorization: no consumer may use it to
recover, dispatch, send input, kill, or otherwise mutate a live process.
Any future recovery requires a separate high-risk human/Sisko plan and fresh-live
validation.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
import sqlite3
import stat
import subprocess
import re
import select
import sys
from typing import Any, Mapping

from .admin import AdminChangeKind, AdminChangePlan, plan_psychlo_legacy_process_observation as _plan_observation
from .core import ApprovalLevel, OwnerDomain, RiskLevel
from .psychlo_contracts import canonical_digest
from .psychlo_bridge import CodexProjectDispatcher, PsychloBridge
from .psychlo_store import PsychloBridgeStore
from .store import SQLiteStore, _dump as _store_dump, _load_dataclass as _store_load_dataclass
from .psychlo_legacy_binding import _private_group_is_safe


SCHEMA = "psychlo.legacy-process-observation.v1"
RECOVERY_SCHEMA = "psychlo.legacy-process-observation.v2"
_FORBIDDEN_KEYS = {"prompt", "rawprompt", "callback", "panecapture", "capture", "argv", "commandline"}
_TMUX = "/usr/bin/tmux"
_GIT = "/usr/bin/git"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PRIVATE_FILE_BYTES = 16 << 20

# Historical observation is a fixed non-authoritative operation, not a configurable adapter.
# These are the only accepted live endpoints.  Tests may replace this whole
# resolver before constructing an internal runtime, but no public operation
# accepts endpoint or evidence arguments.
CANONICAL_PRIMARY_DATABASE = Path("/home/god/Documents/Codex Workspace/Overseer/state/overseer.sqlite3")
CANONICAL_BRIDGE_DATABASE = Path("/home/god/.local/share/overseer/psychlo/bridge.sqlite3")
CANONICAL_PROTECTED_BINDING = Path("/home/god/.config/overseer/psychlo-project-bindings.json")
CANONICAL_CODEX_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
CANONICAL_TMUX_SOCKET = Path(f"/tmp/tmux-{os.getuid()}/default")
CANONICAL_SOURCE_ROOT = Path("/home/god/.local/share/overseer/project")
CANONICAL_SOURCE_REAL_ROOT = Path("/home/god/Documents/Codex Workspace/Overseer")
CANONICAL_CODEX_RELEASES = Path("/home/god/.codex/packages/standalone/releases")
CANONICAL_CODEX_MEMORY_SESSION = "/home/god/.local/bin/codex-memory-session"
CANONICAL_CODEX_MEMORY_SESSION_TRAMPOLINE = Path("/home/god/.codex/skills/private-ai-memory/scripts/codex-session-with-memory.sh")
CANONICAL_CODEX_MEMORY_SESSION_SCRIPT = Path("/home/god/Documents/Private AI Memory Storage System/scripts/codex-session-with-memory.sh")

# A connection opened through a prevalidated `/proc/self/fd/N` URI is bound to
# that exact file description.  Keep the binding private to this module so a
# caller cannot pass an unrelated cover descriptor alongside a decoy SQLite
# connection and have it accepted as authority.
_VERIFIED_CONNECTIONS: dict[int, tuple[int, int]] = {}


class ProcessAttestationError(ValueError):
    pass


def _resolve_observation_conversation(
    bridge: Any,
    request: Mapping[str, Any],
    binding: Mapping[str, Any],
    default_conversation_id: str,
) -> str:
    """Resolve the process conversation without trusting a caller or registry row.

    The protected lead binding remains authoritative for ordinary rounds.  A
    different immutable delivery conversation is admitted only when the
    bridge's completed, approved successor validator returns that exact
    conversation.  The validator owns plan, version, thread, lead, approval,
    digest, and lifecycle checks.
    """
    selected = binding.get("conversationId") if isinstance(binding, Mapping) else None
    if not isinstance(selected, str) or not selected.strip() or not isinstance(default_conversation_id, str) or not default_conversation_id.strip():
        raise ProcessAttestationError("observation conversation binding is invalid")
    if selected == default_conversation_id:
        return default_conversation_id
    validator = getattr(bridge, "_authorized_successor_conversation", None)
    if not callable(validator):
        raise ProcessAttestationError("successor observation authority is unavailable")
    try:
        authorized = validator(request)
    except Exception as error:
        raise ProcessAttestationError("approved successor authority is invalid") from error
    if authorized != selected:
        raise ProcessAttestationError("successor conversation is not authorized")
    return selected


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
    _validate_trusted_parent_chain(path, label)
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


def _validate_trusted_parent_chain(path: Path, label: str) -> None:
    current = Path("/")
    for component in path.parts[1:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ProcessAttestationError(f"{label} parent is unavailable") from error
        sticky_shared = metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
        system_private = metadata.st_uid == 0 and metadata.st_gid == 0 and not (stat.S_IMODE(metadata.st_mode) & 0o022)
        user_private = (metadata.st_uid == os.getuid() and metadata.st_gid == os.getegid()
                        and not (stat.S_IMODE(metadata.st_mode) & 0o002)
                        and (not stat.S_IMODE(metadata.st_mode) & 0o020 or _private_group_is_safe(metadata.st_gid)))
        if (stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
                or (not sticky_shared and not system_private and not user_private)):
            raise ProcessAttestationError(f"{label} parent is not a trusted private-group directory")


@dataclass
class _RuntimeAuthority:
    bridge: PsychloBridge
    primary: SQLiteStore
    collector: "AuthoritativeProcessEvidenceCollector"
    bridge_identity: tuple[int, int, int]
    primary_identity: tuple[int, int, int]
    bridge_fd: int
    primary_fd: int

    def close(self) -> None:
        self.collector.release_held_identities()
        _forget_verified_connection(self.bridge.store.connection)
        _forget_verified_connection(self.primary._connection)
        close_error: Exception | None = None
        try:
            self.bridge.store.close()
        except Exception as error:
            close_error = error
        try:
            self.primary._connection.close()
        except Exception as error:
            close_error = close_error or error
        for fd in (self.bridge_fd, self.primary_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        if close_error is not None:
            raise close_error


@dataclass
class _PrimaryObservationAuthority:
    """Primary-only handle used for historical replay and publication.

    This deliberately has no bridge, dispatcher, collector, tmux, registry,
    source, or lead fields.  A prepared historical observation can therefore
    be recorded after its live runtime has disappeared without recollecting or
    treating the old runtime as an authority.
    """

    primary: SQLiteStore
    primary_identity: tuple[int, int]
    primary_fd: int

    def close(self) -> None:
        _forget_verified_connection(self.primary._connection)
        close_error: Exception | None = None
        try:
            self.primary._connection.close()
        except Exception as error:
            close_error = error
        try:
            os.close(self.primary_fd)
        except OSError:
            pass
        if close_error is not None:
            raise close_error


def _open_runtime_authority(round_id: str) -> _RuntimeAuthority:
    """Open only the fixed live authority stores and derive the exact session."""
    primary_identity = _validate_runtime_path(CANONICAL_PRIMARY_DATABASE, label="primary authority database")
    bridge_identity = _validate_runtime_path(CANONICAL_BRIDGE_DATABASE, label="Psychlo bridge database")
    if primary_identity == bridge_identity:
        raise ProcessAttestationError("primary and bridge databases must be distinct inodes")
    _validate_runtime_path(CANONICAL_PROTECTED_BINDING, label="protected binding")
    _validate_runtime_path(CANONICAL_CODEX_REGISTRY, label="canonical Codex registry")
    _validate_runtime_path(CANONICAL_TMUX_SOCKET, label="tmux socket", regular=False)
    bridge_fd = _open_verified_database_fd(CANONICAL_BRIDGE_DATABASE, bridge_identity, "bridge")
    try:
        primary_fd = _open_verified_database_fd(CANONICAL_PRIMARY_DATABASE, primary_identity, "primary")
    except Exception:
        try:
            os.close(bridge_fd)
        except OSError:
            pass
        raise
    try:
        bridge_store = PsychloBridgeStore(CANONICAL_BRIDGE_DATABASE, verified_fd=bridge_fd)
        primary = SQLiteStore(CANONICAL_PRIMARY_DATABASE, verified_fd=primary_fd)
        _register_verified_connection(bridge_store.connection, bridge_fd)
        _register_verified_connection(primary._connection, primary_fd)
        _bind_sqlite_database(bridge_store.connection, CANONICAL_BRIDGE_DATABASE, bridge_identity, "bridge", bound_fd=bridge_fd)
        _bind_sqlite_database(primary._connection, CANONICAL_PRIMARY_DATABASE, primary_identity, "primary", bound_fd=primary_fd)
    except Exception:
        if "bridge_store" in locals():
            _forget_verified_connection(bridge_store.connection)
        if "primary" in locals():
            _forget_verified_connection(primary._connection)
        for fd in (bridge_fd, primary_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        raise
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
        _forget_verified_connection(bridge_store.connection)
        _forget_verified_connection(primary._connection)
        bridge.close()
        for fd in (bridge_fd, primary_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        raise ProcessAttestationError("round is missing")
    request = record[0]
    lead_id = request.get("projectLeadId") if isinstance(request, Mapping) else None
    if not isinstance(lead_id, str) or not lead_id.strip():
        _forget_verified_connection(bridge_store.connection)
        _forget_verified_connection(primary._connection)
        bridge.close()
        for fd in (bridge_fd, primary_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        raise ProcessAttestationError("round lead identity is missing")
    try:
        process_binding = dispatcher.process_binding_provenance(lead_id)
        target = process_binding["command"]
        if not isinstance(target, str) or not target.strip():
            raise ValueError("canonical tmux target is missing")
        collector = AuthoritativeProcessEvidenceCollector(
            bridge, CANONICAL_PROTECTED_BINDING, str(CANONICAL_TMUX_SOCKET), "", _resolve_canonical_source_root(),
        )
    except Exception as error:
        _forget_verified_connection(bridge_store.connection)
        _forget_verified_connection(primary._connection)
        bridge.close()
        for fd in (bridge_fd, primary_fd):
            try:
                os.close(fd)
            except OSError:
                pass
        raise ProcessAttestationError("canonical process runtime is unavailable") from error
    return _RuntimeAuthority(bridge, primary, collector, bridge_identity, primary_identity, bridge_fd, primary_fd)


def _open_primary_observation_authority() -> _PrimaryObservationAuthority:
    """Open the canonical primary database through one verified descriptor.

    This is the only opener used by historical replay/record/finalize paths.
    It intentionally does not inspect the bridge, project lead, dispatcher,
    tmux, registry, rollout, or source checkout.
    """
    identity = _validate_runtime_path(CANONICAL_PRIMARY_DATABASE, label="primary authority database")
    fd: int | None = None
    primary: SQLiteStore | None = None
    try:
        fd = _open_verified_database_fd(CANONICAL_PRIMARY_DATABASE, identity, "primary")
        primary = SQLiteStore(CANONICAL_PRIMARY_DATABASE, verified_fd=fd)
        _register_verified_connection(primary._connection, fd)
        _bind_sqlite_database(primary._connection, CANONICAL_PRIMARY_DATABASE, identity, "primary", bound_fd=fd)
        return _PrimaryObservationAuthority(primary, identity, fd)
    except Exception:
        if primary is not None:
            _forget_verified_connection(primary._connection)
            try:
                primary._connection.close()
            except Exception:
                pass
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _open_verified_database_fd(path: Path, expected: tuple[int, int], label: str) -> int:
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        metadata = os.fstat(fd)
    except OSError as error:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        raise ProcessAttestationError(f"{label} database cannot be opened by identity") from error
    if (metadata.st_dev, metadata.st_ino, metadata.st_nlink) != (*expected, 1) or not stat.S_ISREG(metadata.st_mode):
        os.close(fd)
        raise ProcessAttestationError(f"{label} database identity changed before open")
    return fd


def _register_verified_connection(connection: Any, fd: int) -> None:
    """Record the exact descriptor used to create one authority connection."""
    try:
        metadata = os.fstat(fd)
    except OSError as error:
        raise ProcessAttestationError("verified database connection handle is invalid") from error
    _VERIFIED_CONNECTIONS[id(connection)] = (metadata.st_dev, metadata.st_ino)


def _forget_verified_connection(connection: Any) -> None:
    _VERIFIED_CONNECTIONS.pop(id(connection), None)


def _bind_sqlite_database(connection: Any, path: Path, expected: tuple[int, int], label: str, *, bound_fd: int | None = None) -> tuple[int, int, int]:
    """Bind an opened SQLite main database to the prevalidated inode."""
    rows = connection.execute("PRAGMA database_list").fetchall()
    main = next((row for row in rows if str(row[1]) == "main"), None)
    if main is None or Path(str(main[2])).resolve() != path.resolve():
        raise ProcessAttestationError(f"{label} database handle is not canonical")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProcessAttestationError(f"{label} database disappeared") from error
    if (metadata.st_dev, metadata.st_ino) != expected or metadata.st_nlink != 1 or not stat.S_ISREG(metadata.st_mode):
        raise ProcessAttestationError(f"{label} database identity changed")
    if bound_fd is not None:
        registered = _VERIFIED_CONNECTIONS.get(id(connection))
        if registered != expected:
            raise ProcessAttestationError(f"{label} SQLite connection was not opened from the bound authority handle")
        try:
            bound = os.fstat(bound_fd)
        except OSError as error:
            raise ProcessAttestationError(f"{label} bound database handle is invalid") from error
        if (bound.st_dev, bound.st_ino, bound.st_nlink) != (*expected, 1):
            raise ProcessAttestationError(f"{label} bound database handle changed")
        return metadata.st_dev, metadata.st_ino, metadata.st_nlink
    matches: list[tuple[int, int, int]] = []
    try:
        for entry in os.scandir("/proc/self/fd"):
            try:
                fd = int(entry.name)
                fd_meta = os.fstat(fd)
            except (ValueError, OSError):
                continue
            if (fd_meta.st_dev, fd_meta.st_ino, fd_meta.st_nlink) == (expected[0], expected[1], 1):
                matches.append((fd_meta.st_dev, fd_meta.st_ino, fd_meta.st_nlink))
    except OSError as error:
        raise ProcessAttestationError(f"{label} backing handle cannot be inspected") from error
    if len(matches) != 1:
        raise ProcessAttestationError(f"{label} SQLite handle is not bound to the canonical inode")
    return metadata.st_dev, metadata.st_ino, metadata.st_nlink


def _revalidate_sqlite_database(connection: Any, path: Path, expected: tuple[int, int, int], label: str, *, bound_fd: int | None = None) -> None:
    expected_identity = _identity_with_nlink(tuple(expected))
    current = _bind_sqlite_database(connection, path, expected_identity[:2], label, bound_fd=bound_fd)
    if current != expected_identity:
        raise ProcessAttestationError(f"{label} database identity changed during commit")


def _trusted_codex_executable(pid: int | None = None) -> tuple[str, int, int, str]:
    """Bind the executable of one already-selected direct child to a release inode.

    There are normally many installed Codex releases.  Selecting one by
    directory enumeration is not an identity binding, so the caller must
    provide the PID obtained from the exact tmux pane's direct-child list.
    """
    if pid is None or not isinstance(pid, int) or pid <= 0:
        raise ProcessAttestationError("direct Codex process identity is required")
    root = CANONICAL_CODEX_RELEASES
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProcessAttestationError("trusted Codex release directory is unavailable")
    try:
        candidate = Path(os.readlink(Path(f"/proc/{pid}/exe")))
    except OSError as error:
        raise ProcessAttestationError("direct Codex executable cannot be resolved") from error
    if not candidate.is_absolute() or candidate.name != "codex":
        raise ProcessAttestationError("direct child is not a Codex release executable")
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ProcessAttestationError("direct child executable is outside trusted Codex releases") from error
    # Reject symlinked path components as well as a symlinked final file.  A
    # lexical prefix check alone would permit a release path substitution.
    current = Path("/")
    for component in candidate.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise ProcessAttestationError("direct child executable path is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise ProcessAttestationError("direct child executable path contains a symlink")
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ProcessAttestationError("direct child executable is unavailable") from error
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_gid != os.getegid() or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022 or not os.access(candidate, os.X_OK)):
        raise ProcessAttestationError("direct child executable ownership or mode is unsafe")
    digest, snapshot = _trusted_executable_snapshot(candidate)
    if (snapshot.st_dev, snapshot.st_ino) != (metadata.st_dev, metadata.st_ino):
        raise ProcessAttestationError("direct child executable changed during identity binding")
    return str(candidate), snapshot.st_dev, snapshot.st_ino, digest


def _resolve_canonical_source_root() -> Path:
    """Resolve the fixed source link and require its reviewed real checkout."""
    try:
        resolved = CANONICAL_SOURCE_ROOT.resolve(strict=True)
    except OSError as error:
        raise ProcessAttestationError("canonical source root cannot be resolved") from error
    if resolved != CANONICAL_SOURCE_REAL_ROOT or not resolved.is_dir():
        raise ProcessAttestationError("canonical source root resolves outside the reviewed checkout")
    metadata = resolved.stat(follow_symlinks=False)
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o002:
        raise ProcessAttestationError("canonical source root is not private")
    if stat.S_IMODE(metadata.st_mode) & 0o020 and not _private_group_is_safe(metadata.st_gid):
        raise ProcessAttestationError("canonical source root group is not private")
    return resolved


def _private_workspace_mode(metadata: os.stat_result) -> bool:
    bits = stat.S_IMODE(metadata.st_mode)
    return (metadata.st_uid == os.getuid() and not bits & 0o002
            and (not bits & 0o020 or _private_group_is_safe(metadata.st_gid)))


def _trusted_observation_module(path: Path, source_root: Path) -> tuple[Path, os.stat_result, bytes]:
    """Bind and read the loaded module through a private no-follow handle."""
    try:
        content, metadata = _private_group_file_content(path, "loaded observation module")
        # The descriptor read above proves what was read.  Revalidate the
        # original lexical pathname as well: a rename-to-symlink, replacement,
        # chmod, chown, or other metadata change must not turn that read into
        # a different pathname identity after the no-follow operation.
        lexical_metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(source_root.resolve())
        resolved_metadata = resolved.stat(follow_symlinks=False)
    except (OSError, ValueError) as error:
        raise ProcessAttestationError("loaded observation module is not trusted") from error
    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns,
                value.st_ctime_ns)

    if (not stat.S_ISREG(lexical_metadata.st_mode)
            or not stat.S_ISREG(resolved_metadata.st_mode)
            or identity(metadata) != identity(lexical_metadata)
            or identity(metadata) != identity(resolved_metadata)):
        raise ProcessAttestationError("loaded observation module is not trusted")
    reopened_content, reopened_metadata = _private_group_file_content(path, "loaded observation module")
    try:
        final_metadata = path.lstat()
    except OSError as error:
        raise ProcessAttestationError("loaded observation module is not trusted") from error
    if (reopened_content != content or identity(metadata) != identity(reopened_metadata)
            or identity(metadata) != identity(final_metadata)):
        raise ProcessAttestationError("loaded observation module is not trusted")
    return resolved, metadata, content


def _parse_utc_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ProcessAttestationError(f"{label} timestamp is required")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ProcessAttestationError(f"{label} timestamp is not parseable") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ProcessAttestationError(f"{label} timestamp must be UTC")
    canonical = parsed.astimezone(timezone.utc)
    if value != canonical.isoformat():
        raise ProcessAttestationError(f"{label} timestamp is not canonical UTC")
    return canonical


def _observation_clock(bridge: Any) -> str:
    clock = getattr(getattr(bridge, "store", None), "clock", None)
    if not callable(clock):
        clock = getattr(bridge, "clock", None)
    if not callable(clock):
        raise ProcessAttestationError("observation clock is unavailable")
    value = clock()
    _parse_utc_timestamp(value, "observation")
    return value


def _private_group_file_content(
    path: Path, label: str, max_bytes: int = _MAX_PRIVATE_FILE_BYTES,
) -> tuple[bytes, os.stat_result]:
    """Read a private-primary-group file through one no-follow descriptor."""
    if not path.is_absolute() or path.is_symlink():
        raise ProcessAttestationError(f"{label} path is not canonical")
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ProcessAttestationError(f"{label} cannot be opened safely") from error
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not _private_workspace_mode(before)):
            raise ProcessAttestationError(f"{label} ownership or mode is unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            remaining = max_bytes - total
            if remaining <= 0:
                if os.read(fd, 1):
                    raise ProcessAttestationError(f"{label} exceeds the bounded read size")
                break
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                    before.st_gid, before.st_nlink, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        if identity != (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                        after.st_gid, after.st_nlink, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns):
            raise ProcessAttestationError(f"{label} changed during digest")
        try:
            path_after = path.lstat()
        except OSError as error:
            raise ProcessAttestationError(f"{label} path cannot be revalidated") from error
        if (before.st_dev, before.st_ino, before.st_nlink, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns) != (path_after.st_dev,
                path_after.st_ino, path_after.st_nlink, path_after.st_size,
                path_after.st_mtime_ns, path_after.st_ctime_ns):
            raise ProcessAttestationError(f"{label} path changed during read")
        return b"".join(chunks), before
    except OSError as error:
        raise ProcessAttestationError(f"{label} cannot be read safely") from error
    finally:
        os.close(fd)


def _private_group_file_digest(path: Path, label: str) -> tuple[str, os.stat_result]:
    content, metadata = _private_group_file_content(path, label)
    return sha256(content).hexdigest(), metadata


def _canonical_link_identity(path: Path, target: Path, label: str) -> dict[str, Any]:
    if not path.is_absolute() or not path.is_symlink() or not target.is_absolute():
        raise ProcessAttestationError(f"{label} link is not canonical")
    _validate_trusted_parent_chain(path, label)
    try:
        metadata = path.lstat()
        target_text = os.readlink(path)
        resolved = path.resolve(strict=True)
        after = path.lstat()
        after_text = os.readlink(path)
    except OSError as error:
        raise ProcessAttestationError(f"{label} link cannot be read safely") from error
    if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1 or resolved != target or target_text != str(target)):
        raise ProcessAttestationError(f"{label} target or ownership is unsafe")
    if ((metadata.st_dev, metadata.st_ino, metadata.st_nlink, metadata.st_uid) !=
            (after.st_dev, after.st_ino, after.st_nlink, after.st_uid) or after_text != target_text):
        raise ProcessAttestationError(f"{label} link changed during identity capture")
    return {"path": str(path), "target": str(target), "dev": metadata.st_dev,
            "ino": metadata.st_ino, "nlink": metadata.st_nlink,
            "uid": metadata.st_uid, "digest": sha256(target_text.encode()).hexdigest()}


def _file_identity(path: Path, label: str, *, executable: bool = False) -> dict[str, Any]:
    _validate_runtime_path(path, label=label)
    digest, metadata = _private_group_file_digest(path, label)
    if executable and not os.access(path, os.X_OK):
        raise ProcessAttestationError(f"{label} is not executable")
    return {"path": str(path), "dev": metadata.st_dev, "ino": metadata.st_ino,
            "nlink": metadata.st_nlink, "uid": metadata.st_uid,
            "gid": metadata.st_gid, "mode": stat.S_IMODE(metadata.st_mode),
            "digest": digest}


def _capture_launcher_chain(pane_pid: int, process_binding: Mapping[str, str]) -> dict[str, Any]:
    """Bind launcher -> skill trampoline -> reviewed Documents wrapper."""
    launcher = Path(process_binding["launcher"])
    launcher_identity = _file_identity(launcher, "canonical launcher", executable=True)
    if launcher_identity["digest"] != process_binding["launcherDigest"]:
        raise ProcessAttestationError("canonical launcher identity changed")
    launcher_bytes, _ = _private_group_file_content(launcher, "canonical launcher")
    if CANONICAL_CODEX_MEMORY_SESSION.encode() not in launcher_bytes:
        raise ProcessAttestationError("canonical launcher does not bind the memory-session chain")
    memory_session = Path(CANONICAL_CODEX_MEMORY_SESSION)
    link_identity = _canonical_link_identity(memory_session, CANONICAL_CODEX_MEMORY_SESSION_TRAMPOLINE, "memory-session")
    trampoline_identity = _file_identity(CANONICAL_CODEX_MEMORY_SESSION_TRAMPOLINE, "memory-session trampoline", executable=True)
    wrapper_identity = _file_identity(CANONICAL_CODEX_MEMORY_SESSION_SCRIPT, "memory-session wrapper", executable=True)
    expected_root = CANONICAL_CODEX_MEMORY_SESSION_SCRIPT.parent.parent
    expected_trampoline = (
        "#!/usr/bin/env bash\nset -euo pipefail\n\n"
        f'project_root="${{MEMORY_VAULT_PROJECT:-{expected_root}}}"\n'
        'exec "${project_root}/scripts/codex-session-with-memory.sh" "$@"\n'
    ).encode()
    trampoline_bytes, _ = _private_group_file_content(CANONICAL_CODEX_MEMORY_SESSION_TRAMPOLINE, "memory-session trampoline")
    if trampoline_bytes != expected_trampoline:
        raise ProcessAttestationError("memory-session trampoline does not bind the reviewed Documents wrapper")
    raw_cmdline = _read_proc_bytes(Path(f"/proc/{pane_pid}/cmdline"))
    argv = raw_cmdline.split(b"\0")[:-1]
    expected_tail = [CANONICAL_CODEX_MEMORY_SESSION_SCRIPT.as_posix().encode(), b"resume",
                     process_binding["conversationId"].encode(), b"--cd",
                     process_binding["workspace"].encode()]
    if len(argv) != len(expected_tail) + 1 or argv[0] not in {b"bash", b"/usr/bin/bash"} or argv[1:] != expected_tail:
        raise ProcessAttestationError("tmux pane does not execute the exact reviewed memory-session wrapper")
    raw_environment = _read_proc_bytes(Path(f"/proc/{pane_pid}/environ"))
    overrides = [entry.split(b"=", 1)[1].decode(errors="strict") for entry in raw_environment.split(b"\0") if entry.startswith(b"MEMORY_VAULT_PROJECT=")]
    if overrides and overrides != [str(expected_root)]:
        raise ProcessAttestationError("memory-session environment override is unsafe")
    return {"launcher": launcher_identity, "memorySession": link_identity,
            "trampoline": trampoline_identity, "wrapper": wrapper_identity,
            "paneArgvDigest": sha256(raw_cmdline).hexdigest()}


def _validate_pane_launcher(pane_pid: int, process_binding: Mapping[str, str]) -> None:
    """Bind the pane shell and complete launcher chain, including file identity."""
    try:
        pane_executable = Path(os.readlink(Path(f"/proc/{pane_pid}/exe")))
    except OSError as error:
        raise ProcessAttestationError("tmux pane executable cannot be verified") from error
    if pane_executable not in {Path("/usr/bin/bash"), Path("/usr/bin/sh"), Path("/usr/bin/dash")}:
        raise ProcessAttestationError("tmux pane executable is not an approved shell")
    pane_digest, pane_meta = _trusted_executable_snapshot(pane_executable)
    pane_identity = capture_process_identity(pane_pid)
    if pane_identity["exeDigest"] != pane_digest or pane_meta.st_nlink != 1:
        raise ProcessAttestationError("tmux pane shell identity changed")
    _capture_launcher_chain(pane_pid, process_binding)


@dataclass(frozen=True)
class AuthoritativeProcessEvidenceCollector:
    """Derive one manifest exclusively from live, application-owned sources.

    The constructor accepts handles and immutable paths, not evidence.  Both
    stage and record call :meth:`collect`; there is no injection point for a
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
            raise ProcessAttestationError("tmux socket identity cannot be held through observation") from error
        for identity in (tmux["serverProcess"], tmux["paneProcess"], child):
            try:
                self._held_pidfds.append(os.pidfd_open(int(identity["pid"])))
                self._held_proc_fds.append(os.open(f"/proc/{int(identity['pid'])}", getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW))
            except (AttributeError, OSError) as error:
                self.release_held_identities()
                raise ProcessAttestationError("process identity cannot be held through observation") from error

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
                    raise ProcessAttestationError("held process identity exited during observation")
            except OSError as error:
                raise ProcessAttestationError("held process identity became invalid") from error

    def __post_init__(self) -> None:
        if not hasattr(self.bridge, "store") or not isinstance(self.tmux_socket, str) or not self.tmux_socket.startswith("/") or not isinstance(self.tmux_target, str):
            raise ProcessAttestationError("authoritative bridge and process endpoints are required")
        dispatcher = getattr(self.bridge, "dispatcher", None)
        if not callable(getattr(dispatcher, "scan_rollout", None)) or not callable(getattr(dispatcher, "binding_provenance", None)):
            raise ProcessAttestationError("authoritative rollout dispatcher is required")

    def collect(self, round_id: str, plan_id: str) -> dict[str, Any]:
        if not isinstance(round_id, str) or not round_id.strip() or not isinstance(plan_id, str) or not plan_id.strip():
            raise ProcessAttestationError("round and plan identities are required")
        observed_window_start = _observation_clock(self.bridge)
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
        recovery = self.bridge.store.round_recovery(round_id)
        recovery_mode = recovery is not None
        expected_phase = "unresolved" if recovery_mode else "submitted"
        if delivery is None or delivery.get("phase") != expected_phase or binding is None:
            raise ProcessAttestationError("round delivery is not an observable abandonment state with an immutable binding")
        if recovery_mode:
            evidence = recovery.get("evidence") if isinstance(recovery, Mapping) else None
            if (recovery.get("state") != "uncertain" or recovery.get("ownerId") is not None
                    or recovery.get("claimToken") is not None or recovery.get("leaseExpiresAt") is not None
                    or not isinstance(evidence, Mapping) or evidence.get("redeliveryAttempted") is not True
                    or evidence.get("phase") != "unresolved" or evidence.get("deliveryProof") not in {"unknown", "missing"}):
                raise ProcessAttestationError("round recovery is not an exact terminal uncertain recovery")
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
        if recovery_mode:
            bridge_state.update({"recoveryState": "uncertain", "recoveryDigest": canonical_digest(recovery)})
        if bridge_state["failurePresent"] or bridge_state["cancelPresent"]:
            raise ProcessAttestationError("round has a conflicting recovery, failure, or cancellation record")
        lead_id = request.get("projectLeadId")
        if not isinstance(lead_id, str) or not lead_id.strip():
            raise ProcessAttestationError("round lead identity is missing")
        registry, registry_meta = read_private_json(self.registry_path)
        row = registry.get(lead_id)
        if not isinstance(row, Mapping) or set(row) != {"conversationId"} or not isinstance(row.get("conversationId"), str) or not row["conversationId"].strip():
            raise ProcessAttestationError("exact protected binding row identity is invalid")
        process_conversation_id = _resolve_observation_conversation(self.bridge, request, binding, row["conversationId"])
        canonical = getattr(self.bridge.dispatcher, "process_binding_provenance", None)
        if not callable(canonical):
            raise ProcessAttestationError("canonical project registry process identity is required")
        try:
            # The round's immutable delivery binding is authoritative for
            # this historical observation.  The request's threadId may be a
            # stale successor/producer identity and must never select the
            # process or rollout inspected here.
            process_binding = canonical(lead_id, conversation_id=process_conversation_id)
        except Exception as error:
            raise ProcessAttestationError("canonical project registry process identity is unavailable") from error
        required_process = {"conversationId", "sessionId", "workspace", "command", "launcher", "workspaceDev", "workspaceIno", "launcherDev", "launcherIno", "launcherDigest", "registryPath"}
        if not isinstance(process_binding, Mapping) or set(process_binding) != required_process or any(not isinstance(process_binding[key], str) or not process_binding[key].strip() for key in required_process):
            raise ProcessAttestationError("canonical project registry process identity is invalid")
        if binding.get("conversationId") != process_conversation_id or process_binding["conversationId"] != process_conversation_id or process_binding["sessionId"] != binding.get("sessionId"):
            raise ProcessAttestationError("registry and round binding conversation identity differ")
        if Path(process_binding["workspace"]).name.casefold() != str(request.get("projectId", "")).casefold():
            raise ProcessAttestationError("canonical workspace is not bound to the round project")
        expected_starts = (
            f"{CANONICAL_CODEX_MEMORY_SESSION} resume {process_binding['conversationId']} --cd {shlex.quote(process_binding['workspace'])}",
            f"{CANONICAL_CODEX_MEMORY_SESSION} --cd {shlex.quote(process_binding['workspace'])}",
        )
        tmux = capture_tmux_identity(self.tmux_socket, self.tmux_target, expected_start_commands=expected_starts)
        pane_pid = int(tmux["paneProcess"]["pid"])
        if tmux.get("paneParentPid") != int(tmux["serverProcess"]["pid"]):
            raise ProcessAttestationError("tmux pane is not directly owned by its server")
        _validate_pane_launcher(pane_pid, process_binding)
        child = capture_direct_codex_child(pane_pid, expected_conversation_id=process_binding["conversationId"], expected_workspace=process_binding["workspace"])
        self._hold_identities(tmux, child)
        if child.get("parentPid") != pane_pid:
            raise ProcessAttestationError("Codex child is not bound to the pane process")
        prompt = self.bridge._round_prompt(request, capability)
        scanner = self.bridge.dispatcher.scan_rollout
        binding_loader = self.bridge.dispatcher.binding_provenance
        scan = _collect_bound_rollout_evidence(scanner, binding_loader, lead_id, prompt, binding)
        source = capture_source_identity(self.source_root)
        # Re-read the mutable sources before returning the manifest.  The
        # recording caller performs one more full collect immediately before
        # the CAS insert, so this is not a caller-authored snapshot.
        if _collect_bound_rollout_evidence(scanner, binding_loader, lead_id, prompt, binding) != scan:
            raise ProcessAttestationError("rollout evidence changed during collection")
        if capture_tmux_identity(self.tmux_socket, self.tmux_target, expected_start_commands=expected_starts) != tmux:
            raise ProcessAttestationError("tmux identity changed during collection")
        observed_window_end = _observation_clock(self.bridge)
        if _parse_utc_timestamp(observed_window_start, "observation start") > _parse_utc_timestamp(observed_window_end, "observation end"):
            raise ProcessAttestationError("observation window is not chronological")
        started_at = (self.bridge.store.round_timing(round_id) or {}).get("startedAt")
        return {
            "schemaVersion": RECOVERY_SCHEMA if recovery_mode else SCHEMA, "observationId": f"observation-{round_id}", "roundId": round_id,
            "requestDigest": request_digest,
            "startedAt": started_at,
            "historical": True, "authoritative": False, "executable": False,
            "observedWindowStart": observed_window_start, "observedWindowEnd": observed_window_end,
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


def plan_psychlo_legacy_process_observation(*args: Any, **kwargs: Any) -> AdminChangePlan:
    """Build the historical, non-authoritative observation plan."""
    return _plan_observation(*args, **kwargs)


def _open_private(path: Path) -> tuple[int, os.stat_result, os.stat_result]:
    if not path.is_absolute() or path.is_symlink():
        raise ProcessAttestationError("observation path must be absolute and not a symlink")
    flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    try:
        for component in path.parent.parts[1:]:
            child = os.open(component, flags, dir_fd=parent)
            parent_stat = os.fstat(child)
            sticky_shared = parent_stat.st_uid == 0 and bool(parent_stat.st_mode & stat.S_ISVTX)
            unsafe_group_write = (parent_stat.st_mode & 0o020) and not _private_group_is_safe(parent_stat.st_gid)
            if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid not in {0, os.getuid()} or ((parent_stat.st_mode & 0o002) and not sticky_shared) or (unsafe_group_write and not sticky_shared):
                os.close(child)
                raise ProcessAttestationError("observation parent is not private")
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077:
        os.close(fd)
        raise ProcessAttestationError("observation file is not a private regular file")
    path_stat = os.stat(path, follow_symlinks=False)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (path_stat.st_dev, path_stat.st_ino, path_stat.st_size, path_stat.st_mtime_ns, path_stat.st_ctime_ns):
        os.close(fd)
        raise ProcessAttestationError("observation file changed during open")
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
            raise ProcessAttestationError("observation file changed during read")
        try:
            value = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProcessAttestationError("observation JSON is invalid") from error
        if not isinstance(value, dict):
            raise ProcessAttestationError("observation JSON must be an object")
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
    """Accept only an exact negative scan and immutable binding identity."""
    required = {"found", "conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno"}
    if not isinstance(value, Mapping) or set(value) != required or value.get("found") is not False:
        raise ProcessAttestationError("rollout scan is not an authoritative negative result")
    if any(value.get(field) != binding.get(field) for field in ("conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno")):
        raise ProcessAttestationError("rollout scan binding identity is not exact")
    if not isinstance(value["rolloutPathDigest"], str) or not _HEX64.fullmatch(value["rolloutPathDigest"]):
        raise ProcessAttestationError("rollout scan digest is invalid")
    if isinstance(value["rolloutDev"], bool) or not isinstance(value["rolloutDev"], int) or value["rolloutDev"] <= 0 or isinstance(value["rolloutIno"], bool) or not isinstance(value["rolloutIno"], int) or value["rolloutIno"] <= 0:
        raise ProcessAttestationError("rollout scan file identity is invalid")
    return dict(value)


def _collect_bound_rollout_evidence(
    scanner: Any,
    binding_loader: Any,
    lead_id: str,
    prompt: str,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Collect one exact negative rollout result for the stored delivery.

    New Codex drivers return the complete, closed scan envelope.  A legacy
    driver may still return only ``False``; that value is admitted only after
    an independently fetched, exact binding provenance result proves the
    same immutable round binding.  Both calls are explicitly routed to the
    delivery conversation, never to ``request.threadId``.
    """
    conversation_id = binding.get("conversationId")
    if not isinstance(conversation_id, str) or not conversation_id.strip():
        raise ProcessAttestationError("rollout delivery conversation identity is missing")
    try:
        value = scanner(lead_id, prompt, conversation_id=conversation_id)
        provenance = binding_loader(lead_id, conversation_id=conversation_id)
    except Exception as error:
        raise ProcessAttestationError("authoritative rollout evidence is unavailable") from error

    if isinstance(value, bool):
        if value is not False:
            raise ProcessAttestationError("rollout scan is not an authoritative strict negative result")
        if isinstance(provenance, Mapping) and set(provenance) == {"conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno"}:
            provenance = {"found": False, **dict(provenance)}
        return _require_negative_rollout(provenance, binding)

    scan = _require_negative_rollout(value, binding)
    if isinstance(provenance, Mapping) and set(provenance) == {"conversationId", "sessionId", "rolloutPathDigest", "rolloutDev", "rolloutIno"}:
        provenance = {"found": False, **dict(provenance)}
    if _require_negative_rollout(provenance, binding) != scan:
        raise ProcessAttestationError("rollout scan and binding provenance differ")
    return scan


def capture_source_identity(source_root: str | Path) -> dict[str, str]:
    """Derive source lineage with an absolute, trusted read-only git binary."""
    root = Path(source_root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ProcessAttestationError("source root is not a trusted directory")
    metadata = root.stat(follow_symlinks=False)
    if not _private_workspace_mode(metadata):
        raise ProcessAttestationError("source root is not private")
    executable = Path(_GIT)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C", "LANG": "C", "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_NOGLOBAL": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    status = subprocess.run((_GIT, "-C", str(root), "status", "--porcelain", "--untracked-files=all", "--", "src", "pyproject.toml"), check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL, env=env)
    if status.returncode != 0 or status.stdout.strip():
        raise ProcessAttestationError("source runtime tree is dirty")
    # Validate the loaded module itself with the same private-primary-group
    # policy used for the source workspace.  In particular, a tracked module
    # may be group-readable/writable when its group is the verified sole
    # private primary group (for example, mode 0664).  Do not resolve a
    # symlink first: doing so would turn an untrusted module substitution into
    # an apparently trusted regular file.
    module, _module_meta, module_bytes = _trusted_observation_module(Path(__file__), root)
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
    if set(value) != {"schemaVersion", "observationId", "roundId", "requestDigest", "startedAt", "historical", "authoritative", "executable", "observedWindowStart", "observedWindowEnd", "registry", "tmux", "process", "rollout", "bridge", "approval", "source"}:
        raise ProcessAttestationError("manifest fields are not exact")
    schema = value.get("schemaVersion")
    if schema not in {SCHEMA, RECOVERY_SCHEMA} or value.get("roundId") != round_id:
        raise ProcessAttestationError("manifest identity is invalid")
    _validate_redacted(value)
    if not isinstance(value.get("observationId"), str) or not value["observationId"].strip() or value.get("historical") is not True or value.get("authoritative") is not False or value.get("executable") is not False:
        raise ProcessAttestationError("historical observation flags are invalid")
    started_at = _parse_utc_timestamp(value.get("startedAt"), "round start")
    observed_start = _parse_utc_timestamp(value.get("observedWindowStart"), "observation start")
    observed_end = _parse_utc_timestamp(value.get("observedWindowEnd"), "observation end")
    if started_at > observed_start or observed_start > observed_end:
        raise ProcessAttestationError("round start identity is invalid")
    for key in ("requestDigest",):
        if not isinstance(value.get(key), str) or not _HEX64.fullmatch(value[key]):
            raise ProcessAttestationError("manifest digest is invalid")
    approval = value.get("approval")
    if not isinstance(approval, Mapping) or set(approval) != {"planId", "planDigest"} or not isinstance(approval["planId"], str) or not approval["planId"].strip() or not isinstance(approval["planDigest"], str) or (approval["planDigest"] and not _HEX64.fullmatch(approval["planDigest"])):
        raise ProcessAttestationError("manifest approval identity is invalid")
    bridge = value.get("bridge")
    bridge_keys = {"dispatchState", "resultPresent", "deliveryPhase", "recoveryPresent", "failurePresent", "cancelPresent", "requestDigest", "capabilityHash", "bindingDigest", "promptDigest"}
    if schema == RECOVERY_SCHEMA:
        bridge_keys |= {"recoveryState", "recoveryDigest"}
    if not isinstance(bridge, Mapping) or set(bridge) != bridge_keys:
        raise ProcessAttestationError("bridge state evidence is invalid")
    exact_bridge_state = (
        bridge.get("dispatchState") == "started"
        and bridge.get("resultPresent") is False
        and bridge.get("failurePresent") is False
        and bridge.get("cancelPresent") is False
        and (
            (schema == SCHEMA and bridge.get("deliveryPhase") == "submitted" and bridge.get("recoveryPresent") is False)
            or (schema == RECOVERY_SCHEMA and bridge.get("deliveryPhase") == "unresolved" and bridge.get("recoveryPresent") is True and bridge.get("recoveryState") == "uncertain" and isinstance(bridge.get("recoveryDigest"), str) and _HEX64.fullmatch(bridge["recoveryDigest"]))
        )
    )
    if not exact_bridge_state:
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


def _validate_plan_lifecycle(plan: AdminChangePlan, *, approved_required: bool | None = None) -> None:
    """Require literal lifecycle booleans, never truthy coercions."""
    for field_name in ("approved", "canceled", "archived"):
        if type(getattr(plan, field_name, None)) is not bool:
            raise ProcessAttestationError(f"plan {field_name} flag is not a boolean")
    if plan.canceled is not False or plan.archived is not False:
        raise ProcessAttestationError("process observation plan lifecycle is not active")
    if any(getattr(plan, field_name, None) is not None for field_name in ("canceled_by", "canceled_at", "cancellation_reason")):
        raise ProcessAttestationError("uncanceled process plan has cancellation metadata")
    if any(getattr(plan, field_name, None) is not None for field_name in ("archived_by", "archived_at", "archive_record_id")):
        raise ProcessAttestationError("unarchived process plan has archive metadata")
    if approved_required is None:
        approved_required = plan.approved
    if approved_required is True:
        if plan.approved is not True or plan.approved_by != "sisko" or not isinstance(plan.approved_at, str) or not plan.approved_at:
            raise ProcessAttestationError("exact approved Sisko plan is required")
        _parse_utc_timestamp(plan.approved_at, "plan approval timestamp")
    elif approved_required is False:
        if plan.approved is not False or plan.approved_by is not None or plan.approved_at is not None:
            raise ProcessAttestationError("unapproved prepared process plan has approval fields")


def _assert_exact_plan(primary: SQLiteStore, plan_id: str, round_id: str, manifest: Mapping[str, Any], *, approved: bool) -> AdminChangePlan:
    plan = primary.load_admin_change_plan(plan_id)
    _assert_plan_identity(plan, plan_id, round_id, manifest)
    _validate_plan_lifecycle(plan, approved_required=approved)
    return plan


def _assert_plan_identity(plan: AdminChangePlan, plan_id: str, round_id: str, manifest: Mapping[str, Any]) -> None:
    source = manifest["source"]
    expected = plan_psychlo_legacy_process_observation(
        plan_id, round_id, manifest_digest(manifest), source["commit"], source["treeDigest"], source["moduleDigest"],
    )
    if _immutable_plan_digest(plan) != _immutable_plan_digest(expected):
        raise ProcessAttestationError("authoritative plan immutable identity changed")


def _validate_process_observation_row(
    primary: SQLiteStore,
    row: Any,
    *,
    round_id: str,
    plan_id: str,
    expected_state: str | None = None,
) -> tuple[dict[str, Any], AdminChangePlan, str, str]:
    """Validate one complete prepared/recorded row and its exact immutable plan."""
    if row is None or len(row) != 9:
        raise ProcessAttestationError("process observation row is incomplete")
    observation_id, actual_round, actual_plan, observation_digest, plan_digest, state, manifest_json, inserted_at, recorded_at = tuple(row)
    if (
        not isinstance(observation_id, str) or not observation_id.strip()
        or actual_round != round_id or actual_plan != plan_id
        or state not in {"prepared", "recorded"}
        or not isinstance(observation_digest, str) or not _HEX64.fullmatch(observation_digest)
        or not isinstance(plan_digest, str)
        or not isinstance(manifest_json, str)
        or not isinstance(inserted_at, str)
    ):
        raise ProcessAttestationError("process observation row identity is invalid")
    if expected_state is not None and state != expected_state:
        raise ProcessAttestationError("process observation state is not exact")
    inserted_time = _parse_utc_timestamp(inserted_at, "observation inserted timestamp")
    try:
        manifest_value = json.loads(manifest_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise ProcessAttestationError("process observation manifest is invalid") from error
    manifest = _manifest(manifest_value, round_id)
    encoded = json.dumps(dict(manifest), sort_keys=True, separators=(",", ":"))
    if manifest_json != encoded or manifest_digest(manifest) != observation_digest:
        raise ProcessAttestationError("process observation manifest digest is not exact")
    approval = manifest["approval"]
    if approval.get("planId") != plan_id or approval.get("planDigest") != "":
        raise ProcessAttestationError("process observation approval snapshot is not exact")
    try:
        plan = primary.load_admin_change_plan(plan_id)
    except (KeyError, TypeError, ValueError) as error:
        raise ProcessAttestationError("process observation plan is missing") from error
    _assert_plan_identity(plan, plan_id, round_id, manifest)
    _validate_plan_lifecycle(plan)
    if plan.kind != AdminChangeKind.PSYCHLO_LEGACY_PROCESS_OBSERVATION:
        raise ProcessAttestationError("process observation plan kind or lifecycle is invalid")
    observed_end = _parse_utc_timestamp(manifest["observedWindowEnd"], "observation end")
    if observed_end > inserted_time:
        raise ProcessAttestationError("observation was persisted before its collection ended")
    if state == "prepared":
        if plan_digest != "" or recorded_at is not None:
            raise ProcessAttestationError("prepared process observation recording fields are invalid")
        if plan.approved:
            _validate_plan_lifecycle(plan, approved_required=True)
            approved_time = _parse_utc_timestamp(plan.approved_at, "plan approval timestamp")
            if inserted_time > approved_time:
                raise ProcessAttestationError("plan approval precedes prepared observation persistence")
        else:
            _validate_plan_lifecycle(plan, approved_required=False)
    else:
        if not isinstance(recorded_at, str) or not recorded_at.strip():
            raise ProcessAttestationError("recorded process observation timestamp is missing")
        recorded_time = _parse_utc_timestamp(recorded_at, "recorded process observation timestamp")
        _validate_plan_lifecycle(plan, approved_required=True)
        approved_time = _parse_utc_timestamp(plan.approved_at, "plan approval timestamp")
        if inserted_time > approved_time or approved_time > recorded_time:
            raise ProcessAttestationError("process observation persistence chronology is invalid")
        if plan_digest != admin_plan_digest(plan):
            raise ProcessAttestationError("recorded process observation plan digest is not exact")
    return manifest, plan, encoded, observation_digest


def _validate_recording_envelope(
    manifest: Mapping[str, Any], plan: AdminChangePlan, inserted_at: str, recorded_at: str,
) -> None:
    """Validate the proposed record timestamp before the UPDATE/commit."""
    inserted_time = _parse_utc_timestamp(inserted_at, "observation inserted timestamp")
    observed_end = _parse_utc_timestamp(manifest["observedWindowEnd"], "observation end")
    if observed_end > inserted_time:
        raise ProcessAttestationError("observation was persisted before its collection ended")
    _validate_plan_lifecycle(plan, approved_required=True)
    approved_time = _parse_utc_timestamp(plan.approved_at, "plan approval timestamp")
    recorded_time = _parse_utc_timestamp(recorded_at, "recorded process observation timestamp")
    if inserted_time > approved_time or approved_time > recorded_time:
        raise ProcessAttestationError("recording timestamp chronology is invalid")


def _assert_runtime_source_integrity() -> None:
    """Ensure the loaded observation module is the reviewed runtime source."""
    module = Path(__file__).resolve()
    root = _resolve_canonical_source_root()
    try:
        module.relative_to(root)
    except ValueError as error:
        raise ProcessAttestationError("loaded process observation module is outside canonical source") from error
    capture_source_identity(root)


def _load_existing_process_observation(round_id: str, plan_id: str) -> dict[str, Any] | None:
    """Reconcile an exact prepared/recorded row before any live collection."""
    authority = _open_primary_observation_authority()
    try:
        try:
            row = authority.primary._connection.execute(
                "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at "
                "FROM psychlo_process_observations WHERE round_id=?",
                (round_id,),
            ).fetchone()
        except sqlite3.OperationalError as error:
            if "no such table" not in str(error):
                raise
            row = None
        if row is None:
            return None
        manifest, plan, _encoded, digest = _validate_process_observation_row(
            authority.primary, row, round_id=round_id, plan_id=plan_id,
        )
        if row[5] == "recorded":
            return {"recorded": True, "historical": True, "authoritative": False, "executable": False,
                    "roundId": round_id, "observationId": row[0], "observationDigest": row[3],
                    "planDigest": row[4], "recordedAt": row[8]}
        return {"staged": True, "replayed": True, "historical": True, "authoritative": False,
                "executable": False, "roundId": round_id, "planId": plan_id,
                "observationDigest": digest}
    finally:
        authority.close()


def stage_process_observation(*, round_id: str, plan_id: str) -> dict[str, Any]:
    """Derive and durably prepare one exact plan in the canonical primary DB."""
    if not all(isinstance(value, str) and value.strip() for value in (round_id, plan_id)):
        raise ProcessAttestationError("round and plan identities are required")
    existing = _load_existing_process_observation(round_id, plan_id)
    if existing is not None:
        return existing
    _assert_runtime_source_integrity()
    runtime = _open_runtime_authority(round_id)
    try:
        data = runtime.collector.collect(round_id, plan_id)
        data = dict(data)
        data.setdefault("schemaVersion", SCHEMA)
        data.setdefault("observationId", f"observation-{round_id}")
        data.setdefault("roundId", round_id)
        data.setdefault("approval", {"planId": plan_id, "planDigest": ""})
        value = _manifest(data, round_id)
        if value["approval"]["planId"] != plan_id:
            raise ProcessAttestationError("manifest plan identity is not exact")
        digest = manifest_digest(value)
        source = value["source"]
        plan = plan_psychlo_legacy_process_observation(plan_id, round_id, digest, source["commit"], source["treeDigest"], source["moduleDigest"])
        primary = runtime.primary
        primary._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = None
            try:
                existing = primary.load_admin_change_plan(plan_id)
            except KeyError:
                primary._connection.execute("INSERT INTO admin_change_plans(id,payload) VALUES (?,?)", (plan_id, _store_dump(plan)))
            else:
                _validate_plan_lifecycle(existing, approved_required=False)
                if _immutable_plan_digest(existing) != _immutable_plan_digest(plan):
                    raise ProcessAttestationError("staged authority plan identity changed")
            inserted_at = _observation_clock(runtime.bridge)
            _validate_plan_lifecycle(plan, approved_required=False)
            if _parse_utc_timestamp(value["observedWindowEnd"], "observation end") > _parse_utc_timestamp(inserted_at, "observation inserted timestamp"):
                raise ProcessAttestationError("observation was persisted before its collection ended")
            primary.insert_prepared_process_observation(
                observation_id=str(value["observationId"]), round_id=round_id, plan_id=plan_id,
                observation_digest=digest, manifest=value, inserted_at=inserted_at,
            )
            _revalidate_runtime_databases(runtime)
            primary._connection.commit()
            _revalidate_primary_database_after_commit(
                runtime, round_id=round_id, plan_id=plan_id, state="prepared",
                observation_digest=digest, plan_digest="", expected_plan=plan,
            )
        except Exception:
            primary._connection.rollback()
            raise
        return {"staged": True, "historical": True, "authoritative": False, "executable": False, "roundId": round_id, "planId": plan_id, "observationDigest": digest}
    except Exception as error:
        raise ProcessAttestationError(str(error)) from error
    finally:
        runtime.close()


def finalize_process_observation(*, plan_id: str) -> dict[str, Any]:
    """Report plan/observation state; approval alone never claims recording."""
    if not isinstance(plan_id, str) or not plan_id.strip():
        raise ProcessAttestationError("plan identity is required")
    authority = _open_primary_observation_authority()
    try:
        primary = authority.primary
        plan = primary.load_admin_change_plan(plan_id)
        if plan.kind != AdminChangeKind.PSYCHLO_LEGACY_PROCESS_OBSERVATION:
            raise ProcessAttestationError("exact process observation plan is required")
        _validate_plan_lifecycle(plan)
        row = primary._connection.execute(
            "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at "
            "FROM psychlo_process_observations WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is not None:
            _manifest_value, _validated_plan, _encoded, _digest = _validate_process_observation_row(
                primary, row, round_id=row[1], plan_id=plan_id,
            )
        recorded = bool(row is not None and row[5] == "recorded")
        prepared = bool(row is not None and row[5] == "prepared")
        approved = plan.approved is True and plan.approved_by == "sisko" and isinstance(plan.approved_at, str) and bool(plan.approved_at)
        if approved:
            _validate_plan_lifecycle(plan, approved_required=True)
        return {
            "historical": True,
            "authoritative": False,
            "executable": False,
            "finalized": recorded,
            "approved": approved,
            "prepared": prepared,
            "recorded": recorded,
            "status": "recorded" if recorded else "approved-prepared" if approved and prepared else "approved-awaiting-preparation" if approved else "pending-approval",
            "planId": plan.id,
            "roundId": row[1] if row is not None else None,
        }
    finally:
        authority.close()


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
    trusted_path, trusted_dev, trusted_ino, trusted_digest = _trusted_codex_executable(children[0])
    if executable != trusted_path:
        raise ProcessAttestationError("direct child is not the exact trusted executable")
    if expected_exe_path is not None and expected_exe_path != trusted_path:
        raise ProcessAttestationError("direct child executable expectation is not authoritative")
    exe_stat = Path(executable).stat(follow_symlinks=False)
    if exe_stat.st_uid != os.getuid() and exe_stat.st_uid != 0 or stat.S_IMODE(exe_stat.st_mode) & 0o022:
        raise ProcessAttestationError("direct child executable ownership is unsafe")
    executable_digest, executable_meta = _trusted_executable_snapshot(executable)
    if identity["exeDigest"] != executable_digest:
        raise ProcessAttestationError("direct child executable identity changed")
    if expected_exe_digest is not None and executable_digest != expected_exe_digest:
        raise ProcessAttestationError("direct child executable identity changed")
    if trusted_digest is not None and executable_digest != trusted_digest:
        raise ProcessAttestationError("direct child executable identity changed")
    if trusted_dev is not None and trusted_ino is not None and (executable_meta.st_dev != trusted_dev or executable_meta.st_ino != trusted_ino):
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
        raise ProcessAttestationError("direct child changed during observation")
    identity["parentPid"] = parent_pid
    return identity


def _cwd_identity(pid: int, expected_workspace: str) -> tuple[int, int]:
    try:
        cwd = os.readlink(Path(f"/proc/{pid}/cwd"))
        metadata = Path(cwd).stat(follow_symlinks=False)
    except OSError as error:
        raise ProcessAttestationError("process workspace cannot be verified") from error
    expected = Path(expected_workspace)
    if not expected.is_absolute() or cwd != str(expected) or not stat.S_ISDIR(metadata.st_mode) or not _private_workspace_mode(metadata):
        raise ProcessAttestationError("process cwd is not the canonical workspace")
    return metadata.st_dev, metadata.st_ino


def capture_socket_identity(socket_path: str | Path) -> dict[str, Any]:
    path = Path(socket_path)
    try:
        before = path.stat(follow_symlinks=False)
        socket_bits = stat.S_IMODE(before.st_mode)
        if (not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.getuid()
                or socket_bits & 0o007 or (socket_bits & 0o070 and not _private_group_is_safe(before.st_gid))):
            raise OSError("unsafe tmux socket")
        after = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ProcessAttestationError("tmux socket identity cannot be established") from error
    if (before.st_dev, before.st_ino, before.st_mode, before.st_uid) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid):
        raise ProcessAttestationError("tmux socket changed during observation")
    return {"dev": before.st_dev, "ino": before.st_ino, "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid}


def capture_tmux_identity(
    socket_path: str,
    target: str,
    *,
    expected_command: str | None = None,
    expected_start_command: str | None = None,
    expected_start_commands: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """Capture headless-safe tmux evidence through explicit socket/list-panes."""
    if expected_start_command is not None and expected_start_commands is not None:
        raise ProcessAttestationError("only one tmux start-command selector is allowed")
    accepted_start_commands = expected_start_commands or ((expected_start_command,) if expected_start_command is not None else ())
    if not Path(socket_path).is_absolute() or (not target.strip() and not accepted_start_commands):
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
        raise ProcessAttestationError("tmux identity changed during observation")
    if capture_socket_identity(socket_path) != socket_identity:
        raise ProcessAttestationError("tmux identity query failed")
    rows = [line.split("|") for line in panes_stdout.splitlines() if len(line.split("|")) in {4, 5, 6}]
    if target.strip():
        raw_matches = [row for row in rows if row[0] == target or row[2] == target]
    else:
        raw_matches = rows
    if accepted_start_commands:
        accepted_tokens = {_command_tokens(command) for command in accepted_start_commands}
        raw_matches = [row for row in raw_matches if len(row) == 6 and _command_tokens(row[5]) in accepted_tokens]
    if expected_command is not None:
        raw_matches = [row for row in raw_matches if len(row) >= 5 and row[4] == expected_command]
    if len(raw_matches) != 1 or ((expected_command is not None or accepted_start_commands) and len(raw_matches[0]) != 6):
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
    if accepted_start_commands and _command_tokens(pane_start_command) not in {_command_tokens(command) for command in accepted_start_commands}:
        raise ProcessAttestationError("tmux pane start command is not an exact Codex launch chain")
    if (expected_command is not None or accepted_start_commands) and not pane_start_command:
        raise ProcessAttestationError("tmux pane start command is unavailable")
    server_rows = [line.split("|") for line in sessions_stdout.splitlines() if len(line.split("|")) == 2 and line.split("|")[0] == session_id]
    if len(server_rows) != 1 or not server_rows[0][1].isdigit():
        raise ProcessAttestationError("tmux server identity is not unique")
    return {"socket": {**socket_identity, "pathDigest": sha256(socket_path.encode()).hexdigest()}, "sessionId": session_id, "windowId": window_id, "paneId": pane_id, "paneCommandDigest": sha256(pane_command.encode()).hexdigest(), "paneStartCommandDigest": sha256(pane_start_command.encode()).hexdigest(), "serverProcess": capture_process_identity(int(server_rows[0][1])), "paneProcess": capture_process_identity(int(pane_pid)), "paneParentPid": _proc_parent_pid(int(pane_pid)), "serverEvidence": "list-sessions-and-list-panes-explicit-socket"}


def _command_tokens(command: str) -> tuple[str, ...]:
    try:
        tokens = tuple(shlex.split(command, posix=True))
    except ValueError as error:
        raise ProcessAttestationError("tmux pane start command is not parseable") from error
    if not tokens:
        raise ProcessAttestationError("tmux pane start command is empty")
    return tokens


def _validate_bridge_round(bridge: PsychloBridgeStore, round_id: str, manifest: Mapping[str, Any]) -> None:
    """Read-fence the exact bridge state; this function performs no writes."""
    row = bridge.connection.execute("SELECT request_json,capability_hash,dispatch_state,result_json,codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
    delivery = bridge.connection.execute("SELECT request_digest,capability_hash,binding_json,phase,prompt_digest FROM round_prompt_deliveries WHERE round_id=?", (round_id,)).fetchone()
    bridge_state = manifest.get("bridge") if isinstance(manifest, Mapping) else None
    recovery = bridge.round_recovery(round_id)
    recovery_mode = isinstance(bridge_state, Mapping) and bridge_state.get("recoveryPresent") is True
    forbidden = any(bridge.connection.execute(f"SELECT 1 FROM {table} WHERE round_id=? LIMIT 1", (round_id,)).fetchone() is not None for table in ("operational_failure_intents", "round_cancellations"))
    request_digest = None
    if row is not None:
        request_digest = bridge._round_request_digest(json.loads(row[0]))
    exact_recovery = (
        recovery_mode
        and isinstance(recovery, Mapping)
        and recovery.get("state") == "uncertain"
        and canonical_digest(recovery) == bridge_state.get("recoveryDigest")
        and delivery is not None
        and delivery[3] == "unresolved"
    )
    exact_no_recovery = not recovery_mode and recovery is None and delivery is not None and delivery[3] == "submitted"
    if row is None or row[2] != "started" or row[3] is not None or not isinstance(row[4], str) or forbidden or delivery is None or not (exact_recovery or exact_no_recovery) or delivery[0] != request_digest or delivery[1] != row[1] or delivery[2] != row[4] or not isinstance(bridge_state, Mapping) or bridge_state.get("requestDigest") != request_digest or bridge_state.get("capabilityHash") != row[1] or bridge_state.get("bindingDigest") != sha256(row[4].encode()).hexdigest() or delivery[4] != bridge_state.get("promptDigest"):
        raise ProcessAttestationError("bridge state changed before primary publication")


def record_process_observation(*, round_id: str, plan_id: str) -> dict[str, Any]:
    """Record one exact historical observation in the canonical primary DB.

    The primary transaction owns the sole publication; replay returns that
    exact recorded primary row.  No live runtime, bridge, or source read is
    required once the immutable prepared snapshot exists.
    """
    if not all(isinstance(value, str) and value.strip() for value in (round_id, plan_id)):
        raise ProcessAttestationError("round and plan identities are required")
    replay = _load_recorded_observation(round_id, plan_id)
    if replay is not None:
        return replay
    authority = _open_primary_observation_authority()
    primary = authority.primary
    primary_connection = primary._connection
    try:
        primary_connection.execute("BEGIN IMMEDIATE")
        try:
            row = primary_connection.execute("SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at FROM psychlo_process_observations WHERE round_id=?", (round_id,)).fetchone()
            if row is None:
                raise ProcessAttestationError("prepared process observation is missing")
            manifest, stored_plan, _encoded, digest = _validate_process_observation_row(
                primary, row, round_id=round_id, plan_id=plan_id,
            )
            if row[5] == "recorded":
                primary_connection.rollback()
                _revalidate_primary_database_after_commit(
                    authority, round_id=round_id, plan_id=plan_id, state="recorded",
                    observation_digest=row[3], plan_digest=row[4], expected_plan=stored_plan,
                )
                return {"recorded": True, "historical": True, "authoritative": False, "executable": False,
                        "roundId": round_id, "observationId": row[0], "observationDigest": row[3],
                        "planDigest": row[4], "recordedAt": row[8]}
            if row[5] != "prepared":
                raise ProcessAttestationError("prepared process observation state is invalid")
            plan = _assert_exact_plan(primary, plan_id, round_id, manifest, approved=True)
            plan_digest = admin_plan_digest(plan)
            recorded_at = _primary_recording_clock(primary)
            _validate_recording_envelope(manifest, plan, row[7], recorded_at)
            result = primary.record_process_observation(
                round_id=round_id, plan_id=plan_id, observation_digest=digest,
                plan_digest=plan_digest, recorded_at=recorded_at,
            )
            primary_connection.commit()
            _revalidate_primary_database_after_commit(
                authority, round_id=round_id, plan_id=plan_id, state="recorded",
                observation_digest=digest, plan_digest=plan_digest, expected_plan=plan,
            )
        except Exception:
            primary_connection.rollback()
            raise
        return {"recorded": True, "historical": True, "authoritative": False, "executable": False, "roundId": round_id, "observationId": result["observationId"], "observationDigest": result["observationDigest"], "planDigest": result["planDigest"], "recordedAt": result["recordedAt"]}
    except Exception as error:
        try:
            if primary_connection.in_transaction:
                primary_connection.rollback()
        except Exception:
            pass
        raise ProcessAttestationError(str(error)) from error
    finally:
        authority.close()


def _primary_recording_clock(primary: SQLiteStore) -> str:
    """Generate the record envelope timestamp without consulting live runtime."""
    clock = getattr(primary, "clock", None)
    if callable(clock):
        return _parse_utc_timestamp(clock(), "record timestamp").isoformat()
    return datetime.now(timezone.utc).isoformat()


def _load_recorded_observation(round_id: str, plan_id: str) -> dict[str, Any] | None:
    """Return the immutable primary result before touching live process state."""
    authority: _PrimaryObservationAuthority | None = None
    try:
        authority = _open_primary_observation_authority()
    except (KeyError, ProcessAttestationError, OSError):
        return None
    try:
        primary = authority.primary
        try:
            row = primary._connection.execute(
                "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at "
                "FROM psychlo_process_observations WHERE round_id=?",
                (round_id,),
            ).fetchone()
        except sqlite3.OperationalError as error:
            if "no such table" in str(error):
                return None
            raise
        if row is None:
            return None
        _manifest_value, _plan, _encoded, _digest = _validate_process_observation_row(
            primary, row, round_id=round_id, plan_id=plan_id,
        )
        if row[5] != "recorded":
            return None
        return {"recorded": True, "historical": True, "authoritative": False, "executable": False, "roundId": row[1], "observationId": row[0], "observationDigest": row[3], "planDigest": row[4], "recordedAt": row[8]}
    finally:
        authority.close()


def _revalidate_runtime_databases(runtime: Any) -> None:
    bridge_identity = getattr(runtime, "bridge_identity", None)
    primary_identity = getattr(runtime, "primary_identity", None)
    if bridge_identity is not None:
        _revalidate_sqlite_database(runtime.bridge.store.connection, CANONICAL_BRIDGE_DATABASE, bridge_identity, "bridge", bound_fd=getattr(runtime, "bridge_fd", None))
    if primary_identity is not None:
        _revalidate_sqlite_database(runtime.primary._connection, CANONICAL_PRIMARY_DATABASE, primary_identity, "primary", bound_fd=getattr(runtime, "primary_fd", None))


def _identity_with_nlink(identity: tuple[int, ...]) -> tuple[int, int, int]:
    if len(identity) == 2:
        return identity[0], identity[1], 1
    if len(identity) == 3:
        return identity[0], identity[1], identity[2]
    raise ProcessAttestationError("database identity is incomplete")


def _revalidate_primary_database_after_commit(
    runtime: Any,
    *,
    round_id: str | None = None,
    plan_id: str | None = None,
    state: str | None = None,
    observation_digest: str | None = None,
    plan_digest: str | None = None,
    expected_plan: AdminChangePlan | None = None,
) -> None:
    """Verify canonical identity and, after publication, independent visibility.

    The visibility query uses a newly opened read-only descriptor.  It never
    runs SQLite schema initialization/checkpointing and compares the complete
    observation row plus immutable plan payload before and after the SELECT.
    """
    identity = getattr(runtime, "primary_identity", None)
    fd = getattr(runtime, "primary_fd", None)
    if identity is None or fd is None:
        return
    expected_identity = _identity_with_nlink(tuple(identity))
    _revalidate_sqlite_database(runtime.primary._connection, CANONICAL_PRIMARY_DATABASE, identity, "primary", bound_fd=fd)
    try:
        path_before = CANONICAL_PRIMARY_DATABASE.lstat()
        held = os.fstat(fd)
        path_after = CANONICAL_PRIMARY_DATABASE.lstat()
    except OSError as error:
        raise ProcessAttestationError("canonical primary path cannot be revalidated after commit") from error
    for metadata in (path_before, path_after):
        if (metadata.st_dev, metadata.st_ino, metadata.st_nlink) != expected_identity or not stat.S_ISREG(metadata.st_mode):
            raise ProcessAttestationError("canonical primary path changed after commit")
    if (held.st_dev, held.st_ino, held.st_nlink) != expected_identity:
        raise ProcessAttestationError("bound primary database handle changed after commit")
    missing_sidecars: list[str] = []
    for suffix, sidecar_identity in getattr(runtime.primary, "_sidecar_identities", {}).items():
        sidecar = Path(f"{CANONICAL_PRIMARY_DATABASE}{suffix}")
        try:
            metadata = sidecar.lstat()
        except FileNotFoundError:
            missing_sidecars.append(suffix)
            continue
        if (metadata.st_dev, metadata.st_ino, metadata.st_nlink) != (*sidecar_identity, 1) or not stat.S_ISREG(metadata.st_mode):
            raise ProcessAttestationError(f"primary database sidecar changed after commit: {suffix}")
    if round_id is not None:
        _verify_primary_visibility(
            expected_identity,
            round_id=round_id,
            plan_id=plan_id,
            state=state,
            observation_digest=observation_digest,
            plan_digest=plan_digest,
            expected_plan=expected_plan,
            missing_sidecars=tuple(missing_sidecars),
        )


def _fd_snapshot() -> dict[int, tuple[int, int, int, str]]:
    snapshot: dict[int, tuple[int, int, int, str]] = {}
    try:
        entries = list(os.scandir("/proc/self/fd"))
    except OSError as error:
        raise ProcessAttestationError("process file descriptors cannot be inspected") from error
    for entry in entries:
        try:
            descriptor = int(entry.name)
            metadata = os.fstat(descriptor)
            target = os.readlink(f"/proc/self/fd/{descriptor}")
        except (ValueError, OSError):
            continue
        snapshot[descriptor] = (metadata.st_dev, metadata.st_ino, metadata.st_nlink, target)
    return snapshot


def _open_verified_readonly_connection(
    path: Path,
    expected_identity: tuple[int, int, int],
) -> tuple[sqlite3.Connection, int, int]:
    """Open SQLite read-only and bind the connection's own newly opened FD."""
    base_fd: int | None = None
    connection: sqlite3.Connection | None = None
    connection_fd: int | None = None
    try:
        base_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        base = os.fstat(base_fd)
        expected = _identity_with_nlink(tuple(expected_identity))
        if (base.st_dev, base.st_ino, base.st_nlink) != expected or not stat.S_ISREG(base.st_mode):
            raise ProcessAttestationError("canonical primary preopened handle identity changed")
        before = _fd_snapshot()
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{base_fd}?mode=ro&cache=private", uri=True,
        )
        after = _fd_snapshot()
        new_descriptors = set(after).difference(before)
        candidates = [
            descriptor for descriptor in sorted(new_descriptors)
            if after[descriptor][:3] == expected
            and Path(after[descriptor][3].split(" (deleted)", 1)[0]).resolve() == path.resolve()
        ]
        if len(candidates) != 1:
            raise ProcessAttestationError("read-only SQLite main database handle is ambiguous")
        connection_fd = candidates[0]
        _register_verified_connection(connection, connection_fd)
        _bind_sqlite_database(connection, path, expected[:2], "primary read-only", bound_fd=connection_fd)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        bound = os.fstat(connection_fd)
        if (bound.st_dev, bound.st_ino, bound.st_nlink) != expected:
            raise ProcessAttestationError("read-only SQLite main database handle changed")
        return connection, connection_fd, base_fd
    except Exception:
        if connection is not None:
            if connection_fd is not None:
                _forget_verified_connection(connection)
            try:
                connection.close()
            except Exception:
                pass
        if base_fd is not None:
            try:
                os.close(base_fd)
            except OSError:
                pass
        raise


def _verify_primary_visibility(
    expected_identity: tuple[int, int, int],
    *,
    round_id: str,
    plan_id: str | None,
    state: str | None,
    observation_digest: str | None,
    plan_digest: str | None,
    expected_plan: AdminChangePlan | None,
    missing_sidecars: tuple[str, ...],
) -> None:
    """Read exact committed data from a fresh canonical read-only handle."""
    base_fd: int | None = None
    connection_fd: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        before = CANONICAL_PRIMARY_DATABASE.lstat()
        if (before.st_dev, before.st_ino, before.st_nlink) != expected_identity:
            raise ProcessAttestationError("canonical primary read-only handle identity changed")
        connection, connection_fd, base_fd = _open_verified_readonly_connection(CANONICAL_PRIMARY_DATABASE, expected_identity)
        _bind_sqlite_database(connection, CANONICAL_PRIMARY_DATABASE, expected_identity[:2], "primary read-only", bound_fd=connection_fd)
        if (os.fstat(base_fd).st_dev, os.fstat(base_fd).st_ino, os.fstat(base_fd).st_nlink) != expected_identity:
            raise ProcessAttestationError("canonical primary preopened handle changed during read")
        first = connection.execute(
            "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at "
            "FROM psychlo_process_observations WHERE round_id=?",
            (round_id,),
        ).fetchone()
        plan_row = connection.execute("SELECT payload FROM admin_change_plans WHERE id=?", (plan_id,)).fetchone() if plan_id else None
        second = connection.execute(
            "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at "
            "FROM psychlo_process_observations WHERE round_id=?",
            (round_id,),
        ).fetchone()
        after = CANONICAL_PRIMARY_DATABASE.lstat()
        _bind_sqlite_database(connection, CANONICAL_PRIMARY_DATABASE, expected_identity[:2], "primary read-only", bound_fd=connection_fd)
        if (os.fstat(connection_fd).st_dev, os.fstat(connection_fd).st_ino, os.fstat(connection_fd).st_nlink) != expected_identity:
            raise ProcessAttestationError("read-only SQLite main database handle changed during read")
        if (after.st_dev, after.st_ino, after.st_nlink) != expected_identity or (None if first is None else tuple(first)) != (None if second is None else tuple(second)):
            raise ProcessAttestationError("canonical primary visibility changed during read")
        if first is None or first[1] != round_id or (plan_id is not None and first[2] != plan_id) or (state is not None and first[5] != state):
            raise ProcessAttestationError("committed historical observation is not visible")
        if observation_digest is not None and first[3] != observation_digest:
            raise ProcessAttestationError("committed observation digest is not visible")
        if plan_digest is not None and first[4] != plan_digest:
            raise ProcessAttestationError("committed plan digest is not visible")
        if plan_id is not None and plan_row is None:
            raise ProcessAttestationError("committed immutable plan is not visible")
        if plan_row is None:
            raise ProcessAttestationError("committed immutable plan is not visible")
        try:
            visible_plan = _store_load_dataclass(AdminChangePlan, str(plan_row[0]))
            class _VisiblePlanStore:
                def load_admin_change_plan(self, _plan_id: str) -> AdminChangePlan:
                    return visible_plan
            _validate_process_observation_row(
                _VisiblePlanStore(), first, round_id=round_id,
                plan_id=str(first[2]), expected_state=state,
            )
        except (KeyError, TypeError, ValueError, ProcessAttestationError) as error:
            if isinstance(error, ProcessAttestationError):
                raise
            raise ProcessAttestationError("committed immutable plan is not visible") from error
        if expected_plan is not None and visible_plan != expected_plan:
            raise ProcessAttestationError("committed immutable plan is not visible")
        # WAL/SHM disappearance is safe only after the independent canonical
        # read has proven the exact main-database data is visible.
        if missing_sidecars and first is None:
            raise ProcessAttestationError("tracked primary sidecar disappeared before committed data became visible")
    except sqlite3.Error as error:
        raise ProcessAttestationError("canonical primary committed data is not readable") from error
    except OSError as error:
        raise ProcessAttestationError("canonical primary read-only visibility check failed") from error
    finally:
        if connection is not None:
            _forget_verified_connection(connection)
        if connection is not None:
            connection.close()
        if connection_fd is not None:
            try:
                os.close(connection_fd)
            except OSError:
                pass
        if base_fd is not None:
            try:
                os.close(base_fd)
            except OSError:
                pass
