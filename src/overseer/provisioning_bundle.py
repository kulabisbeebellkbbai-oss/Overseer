"""Frozen, bounded contracts for DonutHole provisioning bundles.

This module contains read-only preflight and immutable bundle construction. It
deliberately contains no persistence, dispatch, or host-operation behavior.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from enum import Enum
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from .backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS
from .backup_provisioning import (
    ADAPTER_SOURCE_PATH, GPG_PATH, SOURCE_PATH, DonutHoleBackupProvisioningPlan,
    ProvisioningStep, _validate_plan, build_plan,
)
from .backup_host_operations import capability_digest as reviewed_capability_digest
from .backup_contract import PROVISIONING_CONTRACT_VERSION
from .core import OwnerDomain
from .storage_control import current_root_identity


INTENT_FIELDS = frozenset({
    "schema_version", "request_id", "plan_id", "kind", "project_id",
    "resource_id", "root_id", "policy_revision", "source_commit",
    "requested_by", "reason", "supersedes_plan_id",
})
INTENT_SCHEMA_VERSION = "1"
INTENT_KIND = "donuthole_encrypted_backup_provisioning_v1"
_INTENT_FIELD_ORDER = (
    "schema_version", "request_id", "plan_id", "kind", "project_id",
    "resource_id", "root_id", "policy_revision", "source_commit",
    "requested_by", "reason", "supersedes_plan_id",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_CHECK_STATUSES = frozenset({"passed", "failed"})
_OUTBOX_STATES = frozenset({"pending", "materialized", "dispatched"})
_REVIEW_OWNERS = (
    ("kira", OwnerDomain.KIRA),
    ("obrien", OwnerDomain.OBRIEN),
    ("security", OwnerDomain.ODO_IDS),
    ("sisko", OwnerDomain.SISKO),
)
REQUIRED_PREFLIGHT_CODES = (
    "INTENT_VALID", "SOURCE_COMMIT_MATCH", "RUNTIME_DIGEST_VALID",
    "CAPABILITY_DIGEST_VALID", "GPG_DIGEST_VALID", "ROOT_AUTHORIZATION_CURRENT",
    "DEPENDENCIES_AVAILABLE", "CANONICAL_BOUNDARIES_VALID", "ROLLBACK_PREREQUISITES_VALID",
)
_ROOT_ALIAS = "donuthole-development"
_ROOT_STATUS = "active"
_ROOT_MAX_BYTES = 1073741824
_OVERSEER_TOKEN_SOURCE_FILE = "/home/god/.local/share/overseer/project/state/api-token"
_OVERSEER_TOKEN_FILE = "/etc/codex-development-backups/keys/overseer.token"
_CURSOR_KEY_FILE = "/etc/codex-development-backups/keys/cursor.key"


class ProvisioningBundleError(ValueError):
    """A bounded bundle cannot be built from the authoritative read snapshot."""


def _read_current_root_authorization(
    store_path: str, project_id: str, root_id: str, policy_revision: str,
    root_identity: str, alias: str, status: str, max_bytes: int, target_digest: str,
) -> Mapping[str, object]:
    """Read one current root authorization from a stable read-only snapshot."""
    database_fd, parent_fd, identity = _open_authority_snapshot(store_path)
    now = datetime.now(UTC)
    try:
        snapshot = _read_authority_snapshot(database_fd, parent_fd, identity)
        snapshot_fd, snapshot_path = tempfile.mkstemp(prefix="overseer-authority-", suffix=".sqlite3")
        try:
            _write_snapshot(snapshot_fd, snapshot)
            os.fsync(snapshot_fd)
        finally:
            os.close(snapshot_fd)
        try:
            connection = sqlite3.connect(f"file:{snapshot_path}?mode=ro&immutable=1", uri=True)
        finally:
            os.unlink(snapshot_path)
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            _require_authority_schema(connection)
            roots = _text_rows(connection, "storage_root_authorizations", ("id", "project_id", "root_id", "status", "payload"))
            approvals = {row[0]: (row[1], row[2]) for row in _text_rows(connection, "approvals", ("id", "subject_id", "payload"))}
            crew_messages = {row[0]: (row[1], row[2]) for row in _text_rows(connection, "crew_messages", ("id", "owner_domain", "payload"))}
            revocations = _validated_revocations(connection)
        finally:
            connection.close()
        if _read_authority_snapshot(database_fd, parent_fd, identity) != snapshot:
            raise ValueError("root authorization snapshot changed during read")
    except sqlite3.Error:
        raise ValueError("root authorization read is unavailable") from None
    finally:
        try:
            _verify_authority_snapshot(parent_fd, identity)
        finally:
            os.close(database_fd)
            os.close(parent_fd)
    candidates: list[tuple[Mapping[str, object], datetime]] = []
    supplied = ("root.register", project_id, root_id, policy_revision, root_identity, alias, status, max_bytes, target_digest)
    for root_row_id, root_project_id, root_root_id, root_status, root_payload in roots:
        try:
            record, approved_at, expires_at = _root_authorization_payload(root_payload)
            approval_row_id = record["approval_id"]
            approval_subject_id, approval_payload = approvals[approval_row_id]
            approval, decided_at = _approval_payload(approval_payload, record, crew_messages)
            exact = tuple(record[name] for name in ("action", "project_id", "root_id", "policy_revision", "root_identity", "alias", "status", "max_bytes", "target_digest"))
            if (
                exact == supplied and record.get("authorization_status") == "approved"
                and record["revoked_at"] is None and root_row_id not in revocations and approved_at <= now < expires_at
                and root_row_id == record["authorization_ref"] and root_project_id == record["project_id"]
                and root_root_id == record["root_id"] and root_status == record["authorization_status"]
                and approval_row_id == approval["id"] and approval_subject_id == approval["subject_id"]
                and approval["id"] == record["approval_id"]
                and approval.get("subject_id") == record.get("authorization_ref")
                and approval.get("status") == "approved"
                and approval["id"] == f"approval.storage.root.{record['authorization_ref']}"
                and decided_at == approved_at
            ):
                candidates.append((record, approved_at))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
    if not candidates:
        raise ValueError("no current exact root authorization exists")
    candidates.sort(key=lambda candidate: (candidate[1], str(candidate[0]["authorization_ref"])), reverse=True)
    if len(candidates) > 1 and candidates[0][1] == candidates[1][1]:
        raise ValueError("current root authorization is ambiguous")
    record = candidates[0][0]
    return {"ok": True, **record, "mutation_performed": False, "host_mutation_performed": False, "redactions_applied": True}


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_authority_snapshot(store_path: str) -> tuple[int, int, tuple[str, tuple[int, int, int, int, int, int], tuple[int, int, int, int, int, int]]]:
    """Open the database once, without following links, and bind its identity."""
    path = Path(store_path)
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ValueError("root authorization read is unavailable")
    parent_fd: int | None = None
    database_fd: int | None = None
    try:
        parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in path.parts[1:-1]:
            child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
        noatime = getattr(os, "O_NOATIME", 0)
        if not noatime:
            raise OSError("metadata-preserving access is unavailable")
        database_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | noatime, dir_fd=parent_fd)
        database_info = os.fstat(database_fd)
        entry_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_info = os.fstat(parent_fd)
    except OSError:
        if database_fd is not None:
            os.close(database_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        raise ValueError("root authorization read is unavailable") from None
    if (
        not stat.S_ISREG(database_info.st_mode)
        or _file_identity(database_info)[:2] != _file_identity(entry_info)[:2]
        or _authority_sidecars_present(parent_fd, path.name)
    ):
        os.close(database_fd)
        os.close(parent_fd)
        raise ValueError("root authorization read is unavailable")
    return database_fd, parent_fd, (path.name, _file_identity(database_info), _file_identity(parent_info))


def _read_authority_snapshot(database_fd: int, parent_fd: int, identity: tuple[str, tuple[int, int, int, int, int, int], tuple[int, int, int, int, int, int]]) -> bytes:
    """Copy a stable descriptor into memory without letting SQLite touch the source."""
    _verify_authority_snapshot(parent_fd, identity)
    expected_size = identity[1][3]
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        chunk = os.pread(database_fd, min(1024 * 1024, expected_size - offset), offset)
        if not chunk:
            raise ValueError("root authorization read is unavailable")
        chunks.append(chunk)
        offset += len(chunk)
    if _file_identity(os.fstat(database_fd)) != identity[1]:
        raise ValueError("root authorization read is unavailable")
    _verify_authority_snapshot(parent_fd, identity)
    return b"".join(chunks)


def _write_snapshot(snapshot_fd: int, snapshot: bytes) -> None:
    offset = 0
    while offset < len(snapshot):
        written = os.write(snapshot_fd, snapshot[offset:])
        if written <= 0:
            raise OSError("in-memory authority snapshot is unavailable")
        offset += written


def _require_authority_schema(connection: sqlite3.Connection) -> None:
    required = {
        "storage_root_authorizations": ("id", "project_id", "root_id", "status", "payload"),
        "approvals": ("id", "subject_id", "payload"),
        "crew_messages": ("id", "owner_domain", "payload"),
        "storage_authorization_revocations": ("id", "kind", "authorization_ref", "revoked_by", "revoked_at", "evidence_id"),
    }
    for table, columns in required.items():
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        if tuple(row[1] for row in rows) != columns or any(str(row[2]).upper() != "TEXT" for row in rows):
            raise ValueError("root authorization schema is unavailable")


def _text_rows(connection: sqlite3.Connection, table: str, columns: tuple[str, ...]) -> list[tuple[str, ...]]:
    query = ", ".join(columns)
    rows = connection.execute(f"SELECT {query} FROM {table}").fetchall()
    if any(len(row) != len(columns) or any(type(value) is not str for value in row) for row in rows):
        raise ValueError("root authorization row is malformed")
    return [tuple(row) for row in rows]


def _validated_revocations(connection: sqlite3.Connection) -> set[str]:
    revoked: set[str] = set()
    for row in _text_rows(connection, "storage_authorization_revocations", ("id", "kind", "authorization_ref", "revoked_by", "revoked_at", "evidence_id")):
        row_id, kind, authorization_ref, revoked_by, revoked_at, evidence_id = row
        if (
            any(not value or value != value.strip() for value in row)
            or kind not in {"root", "operation"} or row_id != f"revoke.{authorization_ref}"
            or not evidence_id.startswith("crew.")
        ):
            raise ValueError("root authorization revocation is malformed")
        _aware_utc(revoked_at, "revocation time")
        if kind == "root":
            revoked.add(authorization_ref)
    return revoked


def _verify_authority_snapshot(
    parent_fd: int, identity: tuple[str, tuple[int, int, int, int, int, int], tuple[int, int, int, int, int, int]],
) -> None:
    """Fail closed if a rename, inode swap, WAL lifecycle, or metadata race occurred."""
    name, database_identity, parent_identity = identity
    try:
        current_entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        current_parent = os.fstat(parent_fd)
    except OSError:
        raise ValueError("root authorization read is unavailable") from None
    if (
        _file_identity(current_entry) != database_identity
        or _file_identity(current_parent) != parent_identity
        or _authority_sidecars_present(parent_fd, name)
    ):
        raise ValueError("root authorization read is unavailable")


def _authority_sidecars_present(parent_fd: int, name: str) -> bool:
    for suffix in ("-wal", "-shm"):
        try:
            os.stat(name + suffix, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError:
            return True
        return True
    return False


def _aware_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be an aware timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must be an aware timestamp")
    return parsed.astimezone(UTC)


def _root_authorization_payload(value: object) -> tuple[Mapping[str, object], datetime, datetime]:
    record = _canonical_json_object(value, "root authorization payload")
    required = {
        "authorization_ref", "action", "project_id", "root_id", "policy_revision", "root_identity",
        "alias", "status", "max_bytes", "target_digest", "approval_id", "approved_at", "expires_at",
        "authorization_status", "revoked_at",
    }
    if not isinstance(record, dict) or set(record) != required:
        raise ValueError("root authorization payload is not exact")
    string_fields = required - {"max_bytes", "revoked_at"}
    if any(not isinstance(record[field], str) or not record[field] or record[field] != record[field].strip() for field in string_fields):
        raise ValueError("root authorization payload has invalid strings")
    if record["action"] != "root.register" or record["status"] != "active" or record["authorization_status"] != "approved":
        raise ValueError("root authorization payload has invalid enums")
    if not isinstance(record["max_bytes"], int) or isinstance(record["max_bytes"], bool) or record["max_bytes"] < 1:
        raise ValueError("root authorization payload has invalid maximum")
    _digest(record["root_identity"], "root authorization identity")
    _digest(record["target_digest"], "root authorization target")
    if record["revoked_at"] is not None:
        raise ValueError("root authorization payload is revoked")
    return record, _aware_utc(record["approved_at"], "root approval"), _aware_utc(record["expires_at"], "root expiry")


def _approval_payload(
    value: object, record: Mapping[str, object], crew_messages: Mapping[str, tuple[str, str]],
) -> tuple[Mapping[str, object], datetime]:
    approval = _canonical_json_object(value, "approval payload")
    required = {
        "id", "subject_id", "approval_level", "requester_thread", "owner_domain", "reason", "status",
        "evidence_required", "decided_by", "decided_at",
    }
    if not isinstance(approval, dict) or set(approval) != required:
        raise ValueError("approval payload is not exact")
    string_fields = required - {"evidence_required"}
    if any(not isinstance(approval[field], str) or not approval[field] or approval[field] != approval[field].strip() for field in string_fields):
        raise ValueError("approval payload has invalid strings")
    if approval["approval_level"] != "human" or approval["owner_domain"] != OwnerDomain.OBRIEN.value or approval["status"] != "approved":
        raise ValueError("approval payload has invalid enums")
    evidence = approval["evidence_required"]
    staged_payload = {
        key: record[key] for key in (
            "authorization_ref", "action", "project_id", "root_id", "policy_revision", "root_identity",
            "alias", "status", "max_bytes", "target_digest", "expires_at",
        )
    }
    staged_digest = canonical_digest(staged_payload)
    crew_id = evidence[0] if isinstance(evidence, list) and evidence else None
    crew_row = crew_messages.get(crew_id) if isinstance(crew_id, str) else None
    if (
        approval["requester_thread"] != "kira" or approval["decided_by"] == approval["requester_thread"]
        or approval["reason"] != f"Approve exact root storage authorization digest {staged_digest}"
        or not isinstance(evidence, list) or len(evidence) != 2
        or not isinstance(evidence[0], str) or crew_row is None
        or tuple(evidence) != (evidence[0], staged_digest)
    ):
        raise ValueError("approval payload has invalid evidence")
    crew_owner, crew_payload = crew_row
    crew = _canonical_json_object(crew_payload, "crew evidence payload")
    crew_required = {
        "id", "owner_domain", "subject", "message", "priority", "status", "requested_by", "created_at",
        "updated_at", "related_resource_id", "related_plan_id", "related_limit_id", "review_status",
        "decision_reason", "correction_request", "decision_evidence_ids", "decided_by", "decided_at",
        "supersedes_message_id", "superseded_by_message_id", "acceptance_criteria", "request_evidence_ids",
    }
    if (
        set(crew) != crew_required or crew["id"] != crew_id or crew["owner_domain"] != crew_owner
        or crew_owner != OwnerDomain.KIRA.value or crew["status"] != "acknowledged"
        or crew["review_status"] != "approved" or crew["decided_by"] != "kira"
    ):
        raise ValueError("crew evidence is not terminal")
    _aware_utc(crew["decided_at"], "crew decision")
    return approval, _aware_utc(approval["decided_at"], "approval decision")


def _canonical_json_object(value: object, label: str) -> dict[str, object]:
    """Decode only canonical TEXT JSON objects without duplicate keys."""
    if type(value) is not str:
        raise ValueError(f"{label} must be SQLite TEXT")

    def without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for key, child in pairs:
            if key in decoded:
                raise ValueError(f"{label} contains duplicate keys")
            decoded[key] = child
        return decoded

    decoded = json.loads(value, object_pairs_hook=without_duplicates)
    if not isinstance(decoded, dict) or json.dumps(decoded, sort_keys=True, separators=(",", ":")) != value:
        raise ValueError(f"{label} is not canonical JSON")
    return decoded


def _always_true() -> bool:
    return True


class _FrozenMapping(Mapping[str, object]):
    """An immutable mapping that remains compatible with dataclass snapshots."""

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, object]) -> None:
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("frozen mappings are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("frozen mappings are immutable")

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __deepcopy__(self, memo: dict[int, object]) -> dict[str, object]:
        copied = {key: copy.deepcopy(value, memo) for key, value in self._values.items()}
        memo[id(self)] = copied
        return copied


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty canonical string")
    return value


def _digest(value: object, label: str) -> str:
    value = _nonempty_string(value, label)
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def _string_tuple(value: object, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, tuple) or (nonempty and not value):
        raise ValueError(f"{label} must be an immutable tuple")
    values = tuple(_nonempty_string(item, label) for item in value)
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must not contain duplicates")
    return values


def _snapshot_string_tuple(value: object, label: str) -> tuple[str, ...]:
    """Copy a plan string sequence so caller-owned lists cannot survive."""
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{label} must be a string sequence")
    return tuple(_nonempty_string(item, label) for item in value)


def _freeze_value(value: object) -> object:
    """Copy a JSON-compatible value into an immutable canonical shape."""
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical mappings require string keys")
        return _FrozenMapping({key: _freeze_value(child) for key, child in value.items()})
    if isinstance(value, tuple):
        return tuple(_freeze_value(child) for child in value)
    if isinstance(value, list):
        return tuple(_freeze_value(child) for child in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical values must be finite")
        return value
    raise ValueError("canonical values must be JSON-compatible")


def _frozen_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    frozen = _freeze_value(value)
    assert isinstance(frozen, Mapping)
    return frozen


def _snapshot_steps(value: object, label: str) -> tuple[ProvisioningStep, ...]:
    if not isinstance(value, (tuple, list)) or any(type(step) is not ProvisioningStep for step in value):
        raise ValueError(f"{label} must be a sequence of exact provisioning steps")
    return tuple(
        ProvisioningStep(
            _nonempty_string(step.operation, f"{label} operation"),
            _frozen_mapping(step.arguments, f"{label} arguments"),
        )
        for step in value
    )


def _snapshot_plan(plan: DonutHoleBackupProvisioningPlan) -> DonutHoleBackupProvisioningPlan:
    """Detach bundle-owned values from all caller-owned mutable plan inputs."""
    if not isinstance(plan.root_registrations, (tuple, list)):
        raise ValueError("bundle plan root registrations must be a sequence")
    return replace(
        plan,
        root_authorization_refs=_frozen_mapping(plan.root_authorization_refs, "bundle plan authorization references"),
        root_registrations=tuple(
            _frozen_mapping(registration, "bundle plan root registration")
            for registration in plan.root_registrations
        ),
        evidence_ids=_frozen_mapping(plan.evidence_ids, "bundle plan evidence IDs"),
        steps=_snapshot_steps(plan.steps, "bundle plan steps"),
        rollback_steps=_snapshot_steps(plan.rollback_steps, "bundle plan rollback steps"),
        read_only_paths=_snapshot_string_tuple(plan.read_only_paths, "bundle plan read-only paths"),
        read_write_paths=_snapshot_string_tuple(plan.read_write_paths, "bundle plan read-write paths"),
    )


def _canonical_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _canonical_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical mappings require string keys")
        return {key: _canonical_value(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(child) for child in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical values must be finite")
        return value
    raise ValueError("canonical digest value is unsupported")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _canonical_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    """Return the SHA-256 digest of canonical JSON for a typed value."""
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class ProvisioningIntentV1:
    schema_version: str
    request_id: str
    plan_id: str
    kind: str
    project_id: str
    resource_id: str
    root_id: str
    policy_revision: str
    source_commit: str
    requested_by: str
    reason: str
    supersedes_plan_id: str

    def __post_init__(self) -> None:
        values = tuple(getattr(self, field) for field in _INTENT_FIELD_ORDER)
        if any(not isinstance(value, str) for value in values):
            raise ValueError("exact typed provisioning intent values are required")
        if self.schema_version != INTENT_SCHEMA_VERSION or self.kind != INTENT_KIND:
            raise ValueError("exact typed provisioning intent values are required")
        required = values[:-1]
        if any(not value or value != value.strip() for value in required) or (
            self.supersedes_plan_id and self.supersedes_plan_id != self.supersedes_plan_id.strip()
        ):
            raise ValueError("exact typed provisioning intent values are required")
        if _COMMIT.fullmatch(self.source_commit) is None:
            raise ValueError("exact typed provisioning intent values are required")


def parse_provisioning_intent(payload: Mapping[str, object]) -> ProvisioningIntentV1:
    """Decode exactly one caller-bounded provisioning intent, failing closed."""
    if not isinstance(payload, Mapping) or set(payload) != INTENT_FIELDS:
        raise ValueError("exact typed provisioning intent fields are required")
    if any(not isinstance(name, str) or not isinstance(payload[name], str) for name in INTENT_FIELDS):
        raise ValueError("exact typed provisioning intent values are required")
    try:
        return ProvisioningIntentV1(**{name: payload[name] for name in INTENT_FIELDS})
    except (TypeError, ValueError) as error:
        raise ValueError("exact typed provisioning intent values are required") from error


@dataclass(frozen=True)
class PreflightDependencies:
    """Read-only dependencies needed to resolve one deterministic preflight."""

    source_path: str
    source_head: Callable[[str], str]
    runtime_digest: Callable[[str, str], str]
    capability_digest: Callable[[str, Mapping[str, object]], str]
    file_digest: Callable[[str], str]
    executable_exists: Callable[[str], bool]
    root_path: str = SOURCE_PATH
    root_identity: Callable[[str], str] = current_root_identity
    resolve_root_authorization: Callable[..., Mapping[str, object]] = _read_current_root_authorization
    canonical_boundaries_valid: Callable[[], bool] = _always_true
    rollback_prerequisites_valid: Callable[[], bool] = _always_true
    predecessor_lookup: Callable[[str], ProvisioningBundleV1 | None] | None = None
    authoritative_chain_tip: Callable[[], str | None] | None = None


@dataclass(frozen=True)
class PreflightCheck:
    code: str
    status: str
    evidence_digest: str
    summary: str

    def __post_init__(self) -> None:
        _nonempty_string(self.code, "preflight check code")
        if self.status not in _CHECK_STATUSES:
            raise ValueError("preflight check status is unsupported")
        _digest(self.evidence_digest, "preflight check evidence digest")
        _nonempty_string(self.summary, "preflight check summary")


@dataclass(frozen=True)
class ProvisioningPreflightReport:
    report_id: str
    plan_id: str
    resolved_inputs: Mapping[str, object]
    checks: tuple[PreflightCheck, ...]
    passed: bool
    report_digest: str

    def __post_init__(self) -> None:
        _nonempty_string(self.report_id, "preflight report ID")
        _nonempty_string(self.plan_id, "preflight report plan ID")
        object.__setattr__(self, "resolved_inputs", _frozen_mapping(self.resolved_inputs, "resolved inputs"))
        if not isinstance(self.checks, tuple) or not self.checks or any(type(check) is not PreflightCheck for check in self.checks):
            raise ValueError("preflight checks must be a non-empty immutable tuple")
        if not isinstance(self.passed, bool) or self.passed != all(check.status == "passed" for check in self.checks):
            raise ValueError("preflight passed state must match checks")
        _digest(self.report_digest, "preflight report digest")


def canonical_root_target_digest(root_identity: str) -> str:
    """Return the versioned, code-owned root target binding for an identity."""
    return canonical_digest({"version": "1", "root_identity": _digest(root_identity, "root identity")})


def _check(code: str, passed: bool, evidence: Mapping[str, object], summary: str) -> PreflightCheck:
    return PreflightCheck(code, "passed" if passed else "failed", canonical_digest(evidence), summary)


def _passing_preflight_checks() -> tuple[PreflightCheck, ...]:
    """Return the exact code-generated passing preflight projection."""
    return (
        _check("INTENT_VALID", True, {"valid": True}, "The bounded intent is valid."),
        _check("SOURCE_COMMIT_MATCH", True, {"available": True, "matched": True}, "The authoritative source commit matches the bounded intent."),
        _check("RUNTIME_DIGEST_VALID", True, {"available": True, "valid": True}, "The authoritative runtime digest is valid."),
        _check("CAPABILITY_DIGEST_VALID", True, {"available": True, "valid": True}, "The authoritative capability digest is valid."),
        _check("GPG_DIGEST_VALID", True, {"available": True, "valid": True}, "The authoritative GPG digest is valid."),
        _check("ROOT_AUTHORIZATION_CURRENT", True, {"available": True, "current": True}, "The exact root authorization is current."),
        _check("DEPENDENCIES_AVAILABLE", True, {"available": True}, "Required read dependencies are available."),
        _check("CANONICAL_BOUNDARIES_VALID", True, {"available": True, "valid": True}, "Canonical boundaries are valid."),
        _check("ROLLBACK_PREREQUISITES_VALID", True, {"available": True, "valid": True}, "Rollback prerequisites are valid."),
    )


def _safe_read(callback: Callable[..., object], *arguments: object) -> tuple[object | None, bool]:
    try:
        return callback(*arguments), True
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None, False


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _valid_commit(value: object) -> bool:
    return isinstance(value, str) and _COMMIT.fullmatch(value) is not None


def _resolved_digest(value: object) -> str:
    return value if _valid_digest(value) else ""


def _resolved_commit(value: object) -> str:
    return value if _valid_commit(value) else ""


def _resolved_authorization_ref(value: object) -> str:
    return value if isinstance(value, str) and value and value == value.strip() else ""


def run_provisioning_preflight(
    store_path: str, intent: ProvisioningIntentV1, dependencies: PreflightDependencies,
) -> ProvisioningPreflightReport:
    """Resolve the fixed authority inputs without changing store or host state."""
    source_head, source_available = _safe_read(dependencies.source_head, dependencies.source_path)
    runtime, runtime_available = _safe_read(
        dependencies.runtime_digest, dependencies.source_path, intent.source_commit,
    )
    capability, capability_available = _safe_read(
        dependencies.capability_digest, intent.source_commit, EXPECTED_BACKUP_TOOL_SCHEMAS,
    )
    gpg, gpg_available = _safe_read(dependencies.file_digest, GPG_PATH)
    executable, executable_available = _safe_read(dependencies.executable_exists, GPG_PATH)
    identity, identity_available = _safe_read(dependencies.root_identity, dependencies.root_path)
    identity_value = _resolved_digest(identity)
    target = canonical_root_target_digest(identity_value) if identity_value else ""
    authority: object | None = None
    authority_available = False
    if identity_value and target:
        authority, authority_available = _safe_read(
            dependencies.resolve_root_authorization,
            store_path, intent.project_id, intent.root_id, intent.policy_revision,
            identity_value, _ROOT_ALIAS, _ROOT_STATUS, _ROOT_MAX_BYTES, target,
        )
    authorization_ref = _resolved_authorization_ref(
        authority.get("authorization_ref") if isinstance(authority, Mapping) else None
    )
    boundaries, boundaries_available = _safe_read(dependencies.canonical_boundaries_valid)
    rollback, rollback_available = _safe_read(dependencies.rollback_prerequisites_valid)

    intent_valid = type(intent) is ProvisioningIntentV1
    source_match = source_available and _valid_commit(source_head) and source_head == intent.source_commit
    runtime_valid = runtime_available and _valid_digest(runtime)
    expected_capability = reviewed_capability_digest(
        intent.source_commit, EXPECTED_BACKUP_TOOL_SCHEMAS, PROVISIONING_CONTRACT_VERSION,
    )
    capability_valid = capability_available and _valid_digest(capability) and capability == expected_capability
    gpg_valid = gpg_available and _valid_digest(gpg)
    authority_current = authority_available and bool(authorization_ref)
    dependencies_available = all((
        source_available, runtime_available, capability_available, gpg_available,
        executable_available, identity_available, authority_available,
    )) and executable is True
    boundaries_valid = (
        boundaries_available and boundaries is True and dependencies.source_path == ADAPTER_SOURCE_PATH
        and dependencies.root_path == SOURCE_PATH
    )
    rollback_valid = rollback_available and rollback is True
    checks = (
        _check("INTENT_VALID", intent_valid, {"valid": intent_valid}, "The bounded intent is valid."),
        _check("SOURCE_COMMIT_MATCH", source_match, {"available": source_available, "matched": source_match}, "The authoritative source commit matches the bounded intent."),
        _check("RUNTIME_DIGEST_VALID", runtime_valid, {"available": runtime_available, "valid": runtime_valid}, "The authoritative runtime digest is valid."),
        _check("CAPABILITY_DIGEST_VALID", capability_valid, {"available": capability_available, "valid": capability_valid}, "The authoritative capability digest is valid."),
        _check("GPG_DIGEST_VALID", gpg_valid, {"available": gpg_available, "valid": gpg_valid}, "The authoritative GPG digest is valid."),
        _check("ROOT_AUTHORIZATION_CURRENT", authority_current, {"available": authority_available, "current": authority_current}, "The exact root authorization is current."),
        _check("DEPENDENCIES_AVAILABLE", dependencies_available, {"available": dependencies_available}, "Required read dependencies are available."),
        _check("CANONICAL_BOUNDARIES_VALID", boundaries_valid, {"available": boundaries_available, "valid": boundaries_valid}, "Canonical boundaries are valid."),
        _check("ROLLBACK_PREREQUISITES_VALID", rollback_valid, {"available": rollback_available, "valid": rollback_valid}, "Rollback prerequisites are valid."),
    )
    resolved_inputs = {
        "source_commit": _resolved_commit(source_head),
        "runtime_digest": _resolved_digest(runtime),
        "capability_digest": _resolved_digest(capability),
        "gpg_sha256": _resolved_digest(gpg),
        "root_identity": identity_value,
        "target_digest": target,
        "authorization_ref": authorization_ref,
    }
    report_id = f"preflight.{intent.plan_id}"
    report_digest = canonical_digest({
        "report_id": report_id, "plan_id": intent.plan_id, "resolved_inputs": resolved_inputs,
        "checks": [asdict(item) for item in checks],
    })
    return ProvisioningPreflightReport(
        report_id, intent.plan_id, resolved_inputs, checks,
        all(item.status == "passed" for item in checks), report_digest,
    )


@dataclass(frozen=True)
class ProvisioningReviewOutboxEntry:
    id: str
    message_id: str
    plan_id: str
    bundle_digest: str
    role: str
    owner_domain: OwnerDomain
    related_resource_id: str
    subject: str
    message: str
    acceptance_criteria: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    state: str = "pending"

    def __post_init__(self) -> None:
        for label, value in (
            ("outbox ID", self.id), ("outbox message ID", self.message_id),
            ("outbox plan ID", self.plan_id), ("outbox resource ID", self.related_resource_id),
            ("outbox subject", self.subject), ("outbox message", self.message),
        ):
            _nonempty_string(value, label)
        _digest(self.bundle_digest, "outbox bundle digest")
        if not isinstance(self.owner_domain, OwnerDomain):
            raise ValueError("outbox owner domain is unsupported")
        if (self.role, self.owner_domain) not in _REVIEW_OWNERS:
            raise ValueError("outbox role and owner domain are unsupported")
        object.__setattr__(self, "acceptance_criteria", _string_tuple(self.acceptance_criteria, "outbox acceptance criteria", nonempty=True))
        evidence_ids = _string_tuple(self.evidence_ids, "outbox evidence IDs", nonempty=True)
        for evidence_id in evidence_ids:
            _digest(evidence_id, "outbox evidence ID")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        if self.state not in _OUTBOX_STATES:
            raise ValueError("outbox state is unsupported")


@dataclass(frozen=True)
class ProvisioningBundleV1:
    schema_version: str
    intent: ProvisioningIntentV1
    plan: DonutHoleBackupProvisioningPlan
    preflight: ProvisioningPreflightReport
    outbox: tuple[ProvisioningReviewOutboxEntry, ...]
    bundle_digest: str
    supersedes_plan_id: str | None
    changed_immutable_inputs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != INTENT_SCHEMA_VERSION:
            raise ValueError("bundle schema version is unsupported")
        if type(self.intent) is not ProvisioningIntentV1 or type(self.plan) is not DonutHoleBackupProvisioningPlan:
            raise ValueError("bundle requires exact typed intent and plan")
        if type(self.preflight) is not ProvisioningPreflightReport:
            raise ValueError("bundle requires an exact preflight report")
        object.__setattr__(self, "plan", _snapshot_plan(self.plan))
        if self.intent.plan_id != self.plan.plan_id:
            raise ValueError("bundle plan ID must match intent")
        if self.preflight.plan_id != self.plan.plan_id:
            raise ValueError("bundle plan ID must match preflight")
        if not isinstance(self.outbox, tuple) or any(type(entry) is not ProvisioningReviewOutboxEntry for entry in self.outbox):
            raise ValueError("bundle requires four exact ordered review outbox entries")
        if tuple((entry.role, entry.owner_domain) for entry in self.outbox) != _REVIEW_OWNERS:
            raise ValueError("bundle requires four exact ordered review outbox entries")
        if any(entry.plan_id != self.plan.plan_id for entry in self.outbox):
            raise ValueError("bundle outbox must bind the exact plan")
        _digest(self.bundle_digest, "bundle digest")
        if any(entry.bundle_digest != self.bundle_digest for entry in self.outbox):
            raise ValueError("bundle outbox digest must match bundle")
        expected_evidence = (self.plan.plan_digest, self.preflight.report_digest, self.bundle_digest)
        if any(entry.evidence_ids != expected_evidence for entry in self.outbox):
            raise ValueError("bundle outbox evidence must be exact and ordered")
        if self.supersedes_plan_id is not None:
            _nonempty_string(self.supersedes_plan_id, "bundle supersedes plan ID")
        expected_supersedes = self.intent.supersedes_plan_id or None
        if self.supersedes_plan_id != expected_supersedes:
            raise ValueError("bundle supersedes plan ID must match intent")
        object.__setattr__(self, "changed_immutable_inputs", _string_tuple(self.changed_immutable_inputs, "changed immutable inputs"))


def _canonical_root_registration(intent: ProvisioningIntentV1, resolved_inputs: Mapping[str, object]) -> Mapping[str, object]:
    return {
        "project_id": intent.project_id,
        "root_id": intent.root_id,
        "policy_revision": intent.policy_revision,
        "host_path": SOURCE_PATH,
        "alias": _ROOT_ALIAS,
        "max_bytes": _ROOT_MAX_BYTES,
        "authorization_ref": str(resolved_inputs["authorization_ref"]),
    }


def _review_outbox(
    intent: ProvisioningIntentV1,
    plan: DonutHoleBackupProvisioningPlan,
    report: ProvisioningPreflightReport,
    bundle_digest_value: str,
) -> tuple[ProvisioningReviewOutboxEntry, ...]:
    evidence_ids = (plan.plan_digest, report.report_digest, bundle_digest_value)
    return tuple(
        ProvisioningReviewOutboxEntry(
            id=f"outbox.{intent.plan_id}.{role}",
            message_id=f"crew.{owner.value}.review-{intent.plan_id}",
            plan_id=intent.plan_id,
            bundle_digest=bundle_digest_value,
            role=role,
            owner_domain=owner,
            related_resource_id=intent.resource_id,
            subject="Review exact DonutHole provisioning bundle",
            message="Review the immutable plan and preflight evidence only.",
            acceptance_criteria=("Review the exact immutable evidence.",),
            evidence_ids=evidence_ids,
        )
        for role, owner in _REVIEW_OWNERS
    )


def _immutable_inputs(
    plan: DonutHoleBackupProvisioningPlan, report: ProvisioningPreflightReport,
) -> Mapping[str, object]:
    return {
        "gpg_sha256": plan.gpg_sha256,
        "adapter_commit": plan.adapter_commit,
        "runtime_digest": plan.runtime_digest,
        "capability_digest": plan.capability_digest,
        "root_authorization_refs": plan.root_authorization_refs,
        "root_registrations": plan.root_registrations,
        "resolved_preflight": report.resolved_inputs,
    }


def changed_immutable_inputs(
    previous: ProvisioningBundleV1 | None,
    plan: DonutHoleBackupProvisioningPlan,
    report: ProvisioningPreflightReport,
) -> tuple[str, ...]:
    """Return sorted immutable differences for a supplied authoritative predecessor."""
    if previous is None:
        return ()
    previous_values = _immutable_inputs(previous.plan, previous.preflight)
    current_values = _immutable_inputs(plan, report)
    return tuple(sorted(
        field for field in current_values if _canonical_value(current_values[field]) != _canonical_value(previous_values[field])
    ))


def _authoritative_predecessor(
    intent: ProvisioningIntentV1, dependencies: PreflightDependencies,
) -> ProvisioningBundleV1 | None:
    if not intent.supersedes_plan_id:
        return None
    if dependencies.predecessor_lookup is None or dependencies.authoritative_chain_tip is None:
        raise ProvisioningBundleError("PREDECESSOR_UNAVAILABLE")
    predecessor, available = _safe_read(dependencies.predecessor_lookup, intent.supersedes_plan_id)
    if not available or type(predecessor) is not ProvisioningBundleV1:
        raise ProvisioningBundleError("PREDECESSOR_UNAVAILABLE")
    if (
        not _valid_predecessor_contract(predecessor)
        or not _valid_predecessor_chain(predecessor, dependencies, {intent.plan_id})
        or predecessor.plan.plan_id != intent.supersedes_plan_id
    ):
        raise ProvisioningBundleError("PREDECESSOR_INVALID")
    tip, tip_available = _safe_read(dependencies.authoritative_chain_tip)
    if not tip_available or tip != intent.supersedes_plan_id:
        raise ProvisioningBundleError("PREDECESSOR_NOT_CURRENT")
    return predecessor


def _valid_predecessor_contract(predecessor: ProvisioningBundleV1) -> bool:
    """Validate every immutable predecessor binding before chain comparison."""
    try:
        intent = predecessor.intent
        report = predecessor.preflight
        plan = predecessor.plan
        if parse_provisioning_intent({name: getattr(intent, name) for name in _INTENT_FIELD_ORDER}) != intent:
            return False
        if intent.plan_id != plan.plan_id or report.plan_id != plan.plan_id or report.report_id != f"preflight.{plan.plan_id}":
            return False
        _validate_plan(plan)
        if report.checks != _passing_preflight_checks():
            return False
        if not report.passed:
            return False
        expected_report = canonical_digest({
            "report_id": report.report_id, "plan_id": report.plan_id,
            "resolved_inputs": report.resolved_inputs,
            "checks": [asdict(item) for item in report.checks],
        })
        if report.report_digest != expected_report or not _valid_predecessor_cross_bindings(intent, plan, report):
            return False
        allowed_changes = tuple(sorted(_immutable_inputs(plan, report)))
        if (
            predecessor.changed_immutable_inputs != tuple(sorted(set(predecessor.changed_immutable_inputs)))
            or any(item not in allowed_changes for item in predecessor.changed_immutable_inputs)
            or (predecessor.supersedes_plan_id is None and predecessor.changed_immutable_inputs)
        ):
            return False
        expected_outbox = _review_outbox(intent, plan, report, predecessor.bundle_digest)
        expected_evidence = (plan.plan_digest, report.report_digest, predecessor.bundle_digest)
        if (
            tuple((entry.role, entry.owner_domain) for entry in predecessor.outbox) != _REVIEW_OWNERS
            or any(
                entry.state not in _OUTBOX_STATES or entry.plan_id != plan.plan_id
                or entry.bundle_digest != predecessor.bundle_digest or entry.evidence_ids != expected_evidence
                or _outbox_static_fields(entry) != _outbox_static_fields(expected)
                for entry, expected in zip(predecessor.outbox, expected_outbox, strict=True)
            )
        ):
            return False
        return bundle_digest(predecessor) == predecessor.bundle_digest
    except (TypeError, ValueError):
        return False


def _valid_predecessor_chain(
    predecessor: ProvisioningBundleV1, dependencies: PreflightDependencies, seen: set[str],
) -> bool:
    """Reconstruct a predecessor's declared chain before trusting the chain tip."""
    plan_id = predecessor.plan.plan_id
    if plan_id in seen:
        return False
    seen.add(plan_id)
    declared = predecessor.supersedes_plan_id
    if declared is None:
        return predecessor.changed_immutable_inputs == ()
    if dependencies.predecessor_lookup is None:
        return False
    prior, available = _safe_read(dependencies.predecessor_lookup, declared)
    if (
        not available or type(prior) is not ProvisioningBundleV1
        or prior.plan.plan_id != declared or not _valid_predecessor_contract(prior)
        or not _valid_predecessor_chain(prior, dependencies, seen)
    ):
        return False
    return predecessor.changed_immutable_inputs == changed_immutable_inputs(prior, predecessor.plan, predecessor.preflight)


def _valid_predecessor_cross_bindings(
    intent: ProvisioningIntentV1, plan: DonutHoleBackupProvisioningPlan, report: ProvisioningPreflightReport,
) -> bool:
    resolved = report.resolved_inputs
    required = {
        "source_commit", "runtime_digest", "capability_digest", "gpg_sha256", "root_identity",
        "target_digest", "authorization_ref",
    }
    if set(resolved) != required:
        return False
    source_commit = resolved["source_commit"]
    runtime_digest = resolved["runtime_digest"]
    capability_digest = resolved["capability_digest"]
    gpg_sha256 = resolved["gpg_sha256"]
    root_identity = resolved["root_identity"]
    target_digest = resolved["target_digest"]
    authorization_ref = resolved["authorization_ref"]
    if (
        source_commit != intent.source_commit or plan.adapter_commit != intent.source_commit
        or not _valid_digest(runtime_digest) or runtime_digest != plan.runtime_digest
        or not _valid_digest(capability_digest) or capability_digest != plan.capability_digest
        or not _valid_digest(gpg_sha256) or gpg_sha256 != plan.gpg_sha256
        or not _valid_digest(root_identity) or target_digest != canonical_root_target_digest(root_identity)
        or not isinstance(authorization_ref, str) or not authorization_ref
    ):
        return False
    expected_refs = {target_digest: authorization_ref}
    expected_registration = (_canonical_root_registration(intent, resolved),)
    expected_evidence = {role: f"crew.{owner.value}.review-{intent.plan_id}" for role, owner in _REVIEW_OWNERS}
    return (
        dict(plan.root_authorization_refs) == expected_refs
        and tuple(plan.root_registrations) == expected_registration
        and dict(plan.evidence_ids) == expected_evidence
    )


def _outbox_static_fields(entry: ProvisioningReviewOutboxEntry) -> tuple[object, ...]:
    return (
        entry.id, entry.message_id, entry.plan_id, entry.role, entry.owner_domain,
        entry.related_resource_id, entry.subject, entry.message, entry.acceptance_criteria,
    )


def build_provisioning_bundle(
    store_path: str, intent: ProvisioningIntentV1, dependencies: PreflightDependencies,
) -> ProvisioningBundleV1:
    """Build one immutable, read-only review bundle from the preflight snapshot."""
    report = run_provisioning_preflight(store_path, intent, dependencies)
    if not report.passed:
        raise ProvisioningBundleError("PREFLIGHT_FAILED")
    predecessor = _authoritative_predecessor(intent, dependencies)
    evidence_ids = {
        role: f"crew.{owner.value}.review-{intent.plan_id}"
        for role, owner in _REVIEW_OWNERS
    }
    plan = build_plan(
        intent.plan_id,
        str(report.resolved_inputs["gpg_sha256"]),
        intent.source_commit,
        str(report.resolved_inputs["runtime_digest"]),
        str(report.resolved_inputs["capability_digest"]),
        {str(report.resolved_inputs["target_digest"]): str(report.resolved_inputs["authorization_ref"])},
        (_canonical_root_registration(intent, report.resolved_inputs),),
        _OVERSEER_TOKEN_SOURCE_FILE,
        _OVERSEER_TOKEN_FILE,
        _CURSOR_KEY_FILE,
        evidence_ids,
    )
    changed = changed_immutable_inputs(predecessor, plan, report)
    placeholder_digest = "sha256:" + "0" * 64
    provisional = ProvisioningBundleV1(
        "1", intent, plan, report,
        _review_outbox(intent, plan, report, placeholder_digest),
        placeholder_digest, intent.supersedes_plan_id or None, changed,
    )
    digest = bundle_digest(provisional)
    outbox = _review_outbox(intent, plan, report, digest)
    return ProvisioningBundleV1(
        "1", intent, plan, report, outbox, digest,
        intent.supersedes_plan_id or None, changed,
    )


def canonical_bundle_payload(bundle: ProvisioningBundleV1) -> Mapping[str, object]:
    """Return immutable bundle fields, omitting mutable and derived outbox state.

    An entry's ``bundle_digest`` and matching copy in ``evidence_ids`` are
    self-referential derived values, not independent immutable inputs.
    """
    if type(bundle) is not ProvisioningBundleV1:
        raise ValueError("bundle digest requires an exact provisioning bundle")
    return {
        "schema_version": bundle.schema_version,
        "intent": bundle.intent,
        "plan": bundle.plan,
        "preflight": bundle.preflight,
        "outbox": tuple(
            {
                "id": entry.id,
                "message_id": entry.message_id,
                "plan_id": entry.plan_id,
                "role": entry.role,
                "owner_domain": entry.owner_domain,
                "related_resource_id": entry.related_resource_id,
                "subject": entry.subject,
                "message": entry.message,
                "acceptance_criteria": entry.acceptance_criteria,
                "evidence_ids": entry.evidence_ids[:2],
            }
            for entry in bundle.outbox
        ),
        "supersedes_plan_id": bundle.supersedes_plan_id,
        "changed_immutable_inputs": bundle.changed_immutable_inputs,
    }


def canonical_bundle_bytes(bundle: ProvisioningBundleV1) -> bytes:
    """Return the stable immutable bytes covered by a bundle digest."""
    return _canonical_bytes(canonical_bundle_payload(bundle))


def bundle_digest(bundle: ProvisioningBundleV1) -> str:
    """Digest all immutable bundle fields while excluding mutable outbox state."""
    return "sha256:" + hashlib.sha256(canonical_bundle_bytes(bundle)).hexdigest()


__all__ = [
    "INTENT_FIELDS", "REQUIRED_PREFLIGHT_CODES", "PreflightCheck", "PreflightDependencies",
    "ProvisioningBundleError", "ProvisioningBundleV1", "ProvisioningIntentV1",
    "ProvisioningPreflightReport", "ProvisioningReviewOutboxEntry", "build_provisioning_bundle",
    "bundle_digest", "canonical_bundle_bytes", "canonical_bundle_payload", "canonical_digest",
    "canonical_root_target_digest", "changed_immutable_inputs", "parse_provisioning_intent",
    "run_provisioning_preflight",
]
