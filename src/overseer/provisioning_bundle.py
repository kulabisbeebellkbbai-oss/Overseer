"""Frozen contracts, authoritative preview, and atomic DonutHole bundle staging.

This module performs read-only preflight and immutable bundle construction,
then persists the exact previewed records through one approval-owned
transaction. It deliberately contains no dispatch or host-operation behavior.
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
import selectors
import sqlite3
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from .backup_host_operations import (
    EXPECTED_BACKUP_TOOL_SCHEMAS,
    RUNTIME_EXCLUDED,
    capability_digest as reviewed_capability_digest,
)
from .backup_provisioning import (
    ADAPTER_SOURCE_PATH, GPG_PATH, SOURCE_PATH, DonutHoleBackupProvisioningPlan,
    ProvisioningStep, _validate_plan, build_plan, save_staged_plan_source,
)
from .backup_contract import (
    PROVISIONING_CONTRACT_VERSION,
    load_packaged_provisioning_contract,
)
from .core import OwnerDomain
from .roadex_approval_status import (
    RoadexApprovalBinding,
    RoadexApprovalBindingDraft,
    load_exact_bound_source,
    stage_bound_roadex_approval,
)
from .serialization import dataclass_from_jsonable, to_jsonable
from .store import SQLiteStore
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
_BUNDLE_WORKSPACE_ID = "workspace.donuthole"
_BUNDLE_BINDING_SUBJECT = "Review exact DonutHole provisioning bundle"
_MAX_GIT_TREE_BYTES = 8 * 1024 * 1024
_MAX_GIT_BLOB_BYTES = 64 * 1024 * 1024
_MAX_GIT_RUNTIME_BYTES = 256 * 1024 * 1024
_MAX_GIT_TREE_ENTRIES = 10_000
_MAX_GIT_PATH_BYTES = 4096
_MAX_GIT_METADATA_BYTES = 1024 * 1024
_MAX_GIT_METADATA_ENTRIES = 100_000
_MAX_GIT_OPERATION_SECONDS = 10.0
_MAX_GIT_PROCESS_COUNT = _MAX_GIT_TREE_ENTRIES * 2 + 8
_MAX_GPG_BYTES = 128 * 1024 * 1024
_MAX_GPG_READ_SECONDS = 10.0
_MAX_BUNDLE_STATUS_DATABASE_BYTES = 2 * 1024 * 1024 * 1024
_MAX_BUNDLE_STATUS_SECONDS = 60.0
_BUNDLE_STATUS_PROGRESS_OPCODES = 1000
_BUNDLE_STATUS_BUFFER_BYTES = 1024 * 1024


class ProvisioningBundleError(ValueError):
    """A bounded bundle cannot be built from the authoritative read snapshot."""


def _read_current_root_authorization(
    store_path: str, project_id: str, root_id: str, policy_revision: str,
    root_identity: str, alias: str, status: str, max_bytes: int, target_digest: str,
) -> Mapping[str, object]:
    """Read one current root authorization from a stable read-only snapshot."""
    now = datetime.now(UTC)
    database_fd, parent_fd, identity = _open_authority_snapshot(store_path)
    snapshot_fd: int | None = None
    snapshot_path: str | None = None
    connection: sqlite3.Connection | None = None
    failed = False
    roots: list[tuple[str, ...]] = []
    approvals: dict[str, tuple[str, str]] = {}
    crew_messages: dict[str, tuple[str, str]] = {}
    revocations: set[str] = set()
    try:
        snapshot = _read_authority_snapshot(database_fd, parent_fd, identity)
        snapshot_fd, snapshot_path = tempfile.mkstemp(prefix="overseer-authority-", suffix=".sqlite3")
        _write_snapshot(snapshot_fd, snapshot)
        os.fsync(snapshot_fd)
        os.close(snapshot_fd)
        snapshot_fd = None
        _verify_authority_snapshot(parent_fd, identity)
        connection = sqlite3.connect(f"file:{snapshot_path}?mode=ro&immutable=1", uri=True)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        _require_authority_schema(connection)
        roots = _text_rows(connection, "storage_root_authorizations", ("id", "project_id", "root_id", "status", "payload"))
        approvals = {row[0]: (row[1], row[2]) for row in _text_rows(connection, "approvals", ("id", "subject_id", "payload"))}
        crew_messages = {row[0]: (row[1], row[2]) for row in _text_rows(connection, "crew_messages", ("id", "owner_domain", "payload"))}
        revocations = _validated_revocations(connection)
        if _read_authority_snapshot(database_fd, parent_fd, identity) != snapshot:
            raise ValueError("root authorization read is unavailable")
    except Exception:
        failed = True
    finally:
        for cleanup in (
            (lambda: connection.close() if connection is not None else None),
            (lambda: os.close(snapshot_fd) if snapshot_fd is not None else None),
            (lambda: os.unlink(snapshot_path) if snapshot_path is not None else None),
            (lambda: _verify_authority_snapshot(parent_fd, identity)),
            (lambda: os.close(database_fd)),
            (lambda: os.close(parent_fd)),
        ):
            try:
                cleanup()
            except Exception:
                failed = True
    if failed:
        raise ValueError("root authorization read is unavailable")
    return _select_current_root_authorization(
        roots,
        approvals,
        crew_messages,
        revocations,
        project_id,
        root_id,
        policy_revision,
        root_identity,
        alias,
        status,
        max_bytes,
        target_digest,
        now,
    )


def _select_current_root_authorization(
    roots: list[tuple[str, ...]],
    approvals: Mapping[str, tuple[str, str]],
    crew_messages: Mapping[str, tuple[str, str]],
    revocations: set[str],
    project_id: str,
    root_id: str,
    policy_revision: str,
    root_identity: str,
    alias: str,
    status: str,
    max_bytes: int,
    target_digest: str,
    now: datetime,
) -> Mapping[str, object]:
    """Select one exact current root from already-validated authority rows."""
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


def _read_current_root_authorization_from_connection(
    connection: sqlite3.Connection,
    project_id: str,
    root_id: str,
    policy_revision: str,
    root_identity: str,
    alias: str,
    status: str,
    max_bytes: int,
    target_digest: str,
) -> Mapping[str, object]:
    """Resolve current root authority from a caller-locked SQLite connection."""
    _require_authority_schema(connection)
    roots = _text_rows(
        connection,
        "storage_root_authorizations",
        ("id", "project_id", "root_id", "status", "payload"),
    )
    approvals = {
        row[0]: (row[1], row[2])
        for row in _text_rows(connection, "approvals", ("id", "subject_id", "payload"))
    }
    crew_messages = {
        row[0]: (row[1], row[2])
        for row in _text_rows(connection, "crew_messages", ("id", "owner_domain", "payload"))
    }
    revocations = _validated_revocations(connection)
    return _select_current_root_authorization(
        roots,
        approvals,
        crew_messages,
        revocations,
        project_id,
        root_id,
        policy_revision,
        root_identity,
        alias,
        status,
        max_bytes,
        target_digest,
        datetime.now(UTC),
    )


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _exact_file_metadata(
    info: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_atime_ns,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _close_authority_descriptors(*descriptors: int | None) -> None:
    """Attempt every owned descriptor close so the caller can fail closed."""
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except Exception:
            continue


def _open_authority_snapshot(store_path: str) -> tuple[int, int, tuple[str, tuple[int, int, int, int, int, int], tuple[int, int, int, int, int, int]]]:
    """Open the database once, without following links, and bind its identity."""
    path = Path(store_path)
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ValueError("root authorization read is unavailable")
    parent_fd: int | None = None
    database_fd: int | None = None
    child_fd: int | None = None
    try:
        parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in path.parts[1:-1]:
            child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child_fd
            child_fd = None
        noatime = getattr(os, "O_NOATIME", 0)
        if not noatime:
            raise OSError("metadata-preserving access is unavailable")
        database_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | noatime, dir_fd=parent_fd)
        database_info = os.fstat(database_fd)
        entry_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        parent_info = os.fstat(parent_fd)
        if (
            not stat.S_ISREG(database_info.st_mode)
            or _file_identity(database_info)[:2] != _file_identity(entry_info)[:2]
            or _authority_sidecars_present(parent_fd, path.name)
        ):
            raise ValueError("root authorization read is unavailable")
    except Exception:
        _close_authority_descriptors(database_fd, child_fd, parent_fd)
        raise ValueError("root authorization read is unavailable") from None
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
        "storage_root_authorizations": (
            ("id", "project_id", "root_id", "status", "payload"),
            (),
            "CREATE TABLE storage_root_authorizations (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, root_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL)",
        ),
        "approvals": (
            ("id", "subject_id", "payload"),
            (),
            """CREATE TABLE approvals (
                id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL,
                payload TEXT NOT NULL
            )""",
        ),
        "crew_messages": (
            ("id", "owner_domain", "payload"),
            (),
            """CREATE TABLE crew_messages (
                id TEXT PRIMARY KEY,
                owner_domain TEXT NOT NULL,
                payload TEXT NOT NULL
            )""",
        ),
        "storage_authorization_revocations": (
            ("id", "kind", "authorization_ref", "revoked_by", "revoked_at", "evidence_id"),
            (("authorization_ref", 2),),
            "CREATE TABLE storage_authorization_revocations(id TEXT PRIMARY KEY,kind TEXT NOT NULL,authorization_ref TEXT NOT NULL UNIQUE,revoked_by TEXT NOT NULL,revoked_at TEXT NOT NULL,evidence_id TEXT NOT NULL)",
        ),
    }
    for table, (columns, unique_columns, canonical_sql) in required.items():
        schema_rows = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='table' AND name=? AND tbl_name=?",
            (table, table),
        ).fetchall()
        if (
            len(schema_rows) != 1
            or len(schema_rows[0]) != 1
            or type(schema_rows[0][0]) is not str
            or " ".join(schema_rows[0][0].split()) != " ".join(canonical_sql.split())
            or connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type='trigger' AND tbl_name=? COLLATE NOCASE LIMIT 1",
                (table,),
            ).fetchone() is not None
        ):
            raise ValueError("root authorization schema is unavailable")
        expected_columns = tuple(
            (position, column, "TEXT", 0 if position == 0 else 1, None, 1 if position == 0 else 0, 0)
            for position, column in enumerate(columns)
        )
        actual_columns = tuple(
            tuple(row) for row in connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
        )
        if actual_columns != expected_columns:
            raise ValueError("root authorization schema is unavailable")
        expected_indexes = [
            (1, "pk", 0, ((0, 0, "id", 0, "BINARY", 1), (1, -1, None, 0, "BINARY", 0))),
            *(
                (1, "u", 0, ((0, column_id, column, 0, "BINARY", 1), (1, -1, None, 0, "BINARY", 0)))
                for column, column_id in unique_columns
            ),
        ]
        actual_indexes = []
        for index in connection.execute(f"PRAGMA index_list({table})").fetchall():
            if len(index) != 5 or type(index[1]) is not str or not index[1]:
                raise ValueError("root authorization schema is unavailable")
            index_columns = tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT seqno,cid,name,desc,coll,key FROM pragma_index_xinfo(?) ORDER BY seqno",
                    (index[1],),
                ).fetchall()
            )
            actual_indexes.append((index[2], index[3], index[4], index_columns))
        unmatched_indexes = list(expected_indexes)
        for index in actual_indexes:
            if index not in unmatched_indexes:
                raise ValueError("root authorization schema is unavailable")
            unmatched_indexes.remove(index)
        if unmatched_indexes or connection.execute(f"PRAGMA foreign_key_list({table})").fetchall():
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
    try:
        entries = os.listdir(parent_fd)
    except OSError:
        return True
    for entry in entries:
        if entry not in {name + "-wal", name + "-shm", name + "-journal"} and not entry.startswith(name + "-mj"):
            continue
        try:
            os.stat(entry, dir_fd=parent_fd, follow_symlinks=False)
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
    expected_crew_evidence = (staged_digest, record["root_identity"], record["target_digest"])
    expected_reason = (
        f"Kira terminal approval for authorization {record['authorization_ref']} "
        f"staged authorization digest {staged_digest} root identity {record['root_identity']} "
        f"target digest {record['target_digest']}"
    )
    if (
        set(crew) != crew_required or crew["id"] != crew_id or crew["owner_domain"] != crew_owner
        or crew_owner != OwnerDomain.KIRA.value or crew["status"] != "acknowledged"
        or crew["review_status"] != "approved" or crew["decided_by"] != "kira"
        or crew["related_resource_id"] != record["root_id"]
        or crew["related_plan_id"] != record["authorization_ref"]
        or crew["decision_reason"] != expected_reason
        or not isinstance(crew["decision_evidence_ids"], list)
        or not isinstance(crew["request_evidence_ids"], list)
        or tuple(crew["decision_evidence_ids"]) != expected_crew_evidence
        or tuple(crew["request_evidence_ids"]) != expected_crew_evidence
        or len(set(crew["decision_evidence_ids"])) != len(crew["decision_evidence_ids"])
        or len(set(crew["request_evidence_ids"])) != len(crew["request_evidence_ids"])
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


def _always_root_scope_allowed(_intent: ProvisioningIntentV1) -> bool:
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
class ProvisioningPreviewDigests:
    """Exact immutable digests returned by an authoritative bundle preview."""

    plan_digest: str
    preflight_digest: str
    bundle_digest: str

    def __post_init__(self) -> None:
        _digest(self.plan_digest, "preview digest plan")
        _digest(self.preflight_digest, "preview digest preflight")
        _digest(self.bundle_digest, "preview digest bundle")


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
class _PreflightDependencies:
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
    authoritative_chain_tip: Callable[[str], str | None] | None = None
    root_scope_allowed: Callable[[ProvisioningIntentV1], bool] = _always_root_scope_allowed


def _repository_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _pinned_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int, int, int, int]:
    """Identity suitable for stable descriptors without treating atime as content."""
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _remaining_deadline(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0:
        raise ValueError("authoritative Git read is unavailable")
    return remaining


def _deadline_result(deadline: float, operation: Callable[..., object], *arguments, **keywords):
    """Run one non-owning operation inside the shared repository deadline."""
    _remaining_deadline(deadline)
    result = operation(*arguments, **keywords)
    _remaining_deadline(deadline)
    return result


def _close_owned_git_descriptors(*descriptors: int | None) -> None:
    """Close every descriptor, then preserve any ordinary or control-flow failure."""
    ordinary_error: Exception | None = None
    base_error: BaseException | None = None
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except BaseException as error:
            if isinstance(error, Exception):
                ordinary_error = ordinary_error or error
            else:
                base_error = base_error or error
    if base_error is not None:
        raise base_error
    if ordinary_error is not None:
        raise OSError("authoritative Git descriptor close failed") from ordinary_error


def _open_git_directory(
    parent_fd: int, name: str, deadline: float,
) -> tuple[int, tuple[int, int, int, int, int, int, int, int, int]]:
    descriptor: int | None = None
    try:
        _remaining_deadline(deadline)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        _remaining_deadline(deadline)
        descriptor_info = _deadline_result(deadline, os.fstat, descriptor)
        entry_info = _deadline_result(
            deadline, os.stat, name, dir_fd=parent_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(descriptor_info.st_mode)
            or _pinned_identity(descriptor_info) != _pinned_identity(entry_info)
        ):
            raise ValueError("authoritative source repository is unavailable")
        result = descriptor, _pinned_identity(descriptor_info)
        descriptor = None
        return result
    finally:
        _close_owned_git_descriptors(descriptor)


def _open_git_regular(
    parent_fd: int, name: str, deadline: float,
) -> tuple[int, tuple[int, int, int, int, int, int, int, int, int]]:
    descriptor: int | None = None
    try:
        _remaining_deadline(deadline)
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        _remaining_deadline(deadline)
        descriptor_info = _deadline_result(deadline, os.fstat, descriptor)
        entry_info = _deadline_result(
            deadline, os.stat, name, dir_fd=parent_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(descriptor_info.st_mode)
            or _pinned_identity(descriptor_info) != _pinned_identity(entry_info)
        ):
            raise ValueError("authoritative source repository is unavailable")
        result = descriptor, _pinned_identity(descriptor_info)
        descriptor = None
        return result
    finally:
        _close_owned_git_descriptors(descriptor)


def _read_pinned_descriptor(descriptor: int, maximum: int, deadline: float) -> bytes:
    info = _deadline_result(deadline, os.fstat, descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > maximum:
        raise ValueError("authoritative source repository is unavailable")
    chunks: list[bytes] = []
    offset = 0
    while offset < info.st_size:
        chunk = _deadline_result(
            deadline, os.pread, descriptor, min(64 * 1024, info.st_size - offset), offset,
        )
        if not chunk:
            raise ValueError("authoritative source repository is unavailable")
        chunks.append(chunk)
        offset += len(chunk)
    if _pinned_identity(_deadline_result(deadline, os.fstat, descriptor)) != _pinned_identity(info):
        raise ValueError("authoritative source repository is unavailable")
    _remaining_deadline(deadline)
    return b"".join(chunks)


def _snapshot_git_metadata_tree(
    root_fd: int, prefix: str, deadline: float,
) -> dict[str, tuple[int, int, int, int, int, int, int, int, int]]:
    """Pin all object/ref components, rejecting links and unsupported nodes."""
    snapshot: dict[str, tuple[int, int, int, int, int, int, int, int, int]] = {}

    def walk(directory_fd: int, directory_prefix: str) -> None:
        entries = sorted(_deadline_result(deadline, os.listdir, f"/proc/self/fd/{directory_fd}"))
        for name in entries:
            _remaining_deadline(deadline)
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise ValueError("authoritative source repository is unavailable")
            entry = _deadline_result(
                deadline, os.stat, name, dir_fd=directory_fd, follow_symlinks=False,
            )
            entry_path = f"{directory_prefix}/{name}"
            if entry_path.startswith("objects/pack/") and name.casefold().endswith(".promisor"):
                raise ValueError("authoritative source repository is unavailable")
            if stat.S_ISLNK(entry.st_mode) or not (stat.S_ISREG(entry.st_mode) or stat.S_ISDIR(entry.st_mode)):
                raise ValueError("authoritative source repository is unavailable")
            snapshot[entry_path] = _pinned_identity(entry)
            if len(snapshot) > _MAX_GIT_METADATA_ENTRIES:
                raise ValueError("authoritative source repository is unavailable")
            if stat.S_ISDIR(entry.st_mode):
                child_fd, child_identity = _open_git_directory(directory_fd, name, deadline)
                try:
                    if child_identity != snapshot[entry_path]:
                        raise ValueError("authoritative source repository is unavailable")
                    walk(child_fd, entry_path)
                finally:
                    _close_owned_git_descriptors(child_fd)
                _remaining_deadline(deadline)

    walk(root_fd, prefix)
    _remaining_deadline(deadline)
    return snapshot


def _reject_present_git_entry(parent_fd: int, name: str, deadline: float) -> None:
    try:
        _deadline_result(deadline, os.stat, name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("authoritative source repository is unavailable")


def _validate_production_git_config(raw_config: bytes, deadline: float) -> None:
    """Permit ordinary local settings, never source-selection configuration."""
    try:
        lines = raw_config.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        raise ValueError("authoritative source repository is unavailable") from None
    section = ""
    for raw_line in lines:
        _remaining_deadline(deadline)
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().split(None, 1)[0].lower()
            if section in {"include", "includeif", "extensions"}:
                raise ValueError("authoritative source repository is unavailable")
            continue
        if "=" not in line:
            raise ValueError("authoritative source repository is unavailable")
        key, value = (item.strip().lower() for item in line.split("=", 1))
        if not key or any(token in key for token in (
            "promisor", "partial", "alternate", "replace", "graft", "object", "gitdir", "worktree", "commondir",
        )):
            raise ValueError("authoritative source repository is unavailable")
        if section == "core" and key == "repositoryformatversion" and value != "0":
            raise ValueError("authoritative source repository is unavailable")
        if section == "core" and key == "bare" and value not in {"false", "0", "no"}:
            raise ValueError("authoritative source repository is unavailable")
    _remaining_deadline(deadline)


def _valid_ref_path(value: str) -> bool:
    components = value.split("/")
    return (
        len(components) >= 3
        and components[0] == "refs"
        and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", component) for component in components[1:])
    )


def _read_packed_ref(raw_packed_refs: bytes, ref_path: str, deadline: float) -> str:
    try:
        lines = raw_packed_refs.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise ValueError("authoritative source repository is unavailable") from None
    found: str | None = None
    for line in lines:
        _remaining_deadline(deadline)
        if not line or line.startswith("#") or line.startswith("^"):
            continue
        try:
            commit, candidate = line.split(" ", 1)
        except ValueError:
            raise ValueError("authoritative source repository is unavailable") from None
        if _COMMIT.fullmatch(commit) is None or not _valid_ref_path(candidate):
            raise ValueError("authoritative source repository is unavailable")
        if candidate.startswith("refs/replace/"):
            raise ValueError("authoritative source repository is unavailable")
        if candidate == ref_path:
            if found is not None:
                raise ValueError("authoritative source repository is unavailable")
            found = commit
    if found is None:
        raise ValueError("authoritative source repository is unavailable")
    _remaining_deadline(deadline)
    return found


def _validate_packed_refs(raw_packed_refs: bytes, deadline: float) -> None:
    """Reject malformed packed references and every replacement namespace entry."""
    try:
        lines = raw_packed_refs.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise ValueError("authoritative source repository is unavailable") from None
    for line in lines:
        _remaining_deadline(deadline)
        if not line or line.startswith("#") or line.startswith("^"):
            continue
        try:
            commit, ref_path = line.split(" ", 1)
        except ValueError:
            raise ValueError("authoritative source repository is unavailable") from None
        if (
            _COMMIT.fullmatch(commit) is None
            or not _valid_ref_path(ref_path)
            or ref_path.startswith("refs/replace/")
        ):
            raise ValueError("authoritative source repository is unavailable")
    _remaining_deadline(deadline)


def _open_relative_git_ref(
    refs_fd: int, ref_path: str, deadline: float,
) -> tuple[int, tuple[int, int, int, int, int, int, int, int, int], bytes]:
    _remaining_deadline(deadline)
    if not _valid_ref_path(ref_path):
        raise ValueError("authoritative source repository is unavailable")
    parent_fd = refs_fd
    intermediates: list[int] = []
    descriptor: int | None = None
    try:
        for component in ref_path.split("/")[1:-1]:
            descriptor, _identity = _open_git_directory(parent_fd, component, deadline)
            intermediates.append(descriptor)
            parent_fd = descriptor
        descriptor, identity = _open_git_regular(parent_fd, ref_path.rsplit("/", 1)[1], deadline)
        data = _read_pinned_descriptor(descriptor, 256, deadline)
        if not data.endswith(b"\n") or data.count(b"\n") != 1:
            raise ValueError("authoritative source repository is unavailable")
        commit = data[:-1].decode("ascii", "strict")
        if _COMMIT.fullmatch(commit) is None:
            raise ValueError("authoritative source repository is unavailable")
        result = descriptor, identity, data
        _remaining_deadline(deadline)
        descriptor = None
        return result
    finally:
        _close_owned_git_descriptors(*reversed(intermediates), descriptor)


def _stat_relative_git_ref(refs_fd: int, ref_path: str, deadline: float) -> os.stat_result:
    _remaining_deadline(deadline)
    if not _valid_ref_path(ref_path):
        raise ValueError("authoritative source repository is unavailable")
    parent_fd = refs_fd
    intermediates: list[int] = []
    try:
        for component in ref_path.split("/")[1:-1]:
            descriptor, _identity = _open_git_directory(parent_fd, component, deadline)
            intermediates.append(descriptor)
            parent_fd = descriptor
        return _deadline_result(
            deadline, os.stat, ref_path.rsplit("/", 1)[1],
            dir_fd=parent_fd, follow_symlinks=False,
        )
    finally:
        _close_owned_git_descriptors(*reversed(intermediates))


@dataclass
class _ProductionGitSession:
    path: str
    worktree_name: str
    parent_fd: int
    worktree_fd: int
    git_fd: int
    config_fd: int
    head_fd: int
    refs_fd: int
    objects_fd: int
    objects_info_fd: int
    objects_pack_fd: int
    info_fd: int
    packed_refs_fd: int | None
    ref_fd: int | None
    identities: dict[str, tuple[int, int, int, int, int, int, int, int, int]]
    metadata_nodes: dict[str, tuple[int, int, int, int, int, int, int, int, int]]
    config_bytes: bytes
    head_bytes: bytes
    packed_refs_bytes: bytes | None
    ref_path: str | None
    ref_bytes: bytes | None
    head_commit: str
    deadline: float
    process_count: int = 0

    def close(self) -> None:
        _close_owned_git_descriptors(
            self.ref_fd, self.packed_refs_fd, self.info_fd, self.objects_pack_fd,
            self.objects_info_fd, self.objects_fd, self.refs_fd, self.head_fd,
            self.config_fd, self.git_fd, self.worktree_fd, self.parent_fd,
        )


def _open_production_repository(path: str, deadline: float) -> _ProductionGitSession:
    """Pin one non-worktree Git repository session with no indirect object source."""
    _remaining_deadline(deadline)
    if path != ADAPTER_SOURCE_PATH:
        raise ValueError("authoritative source path is fixed")
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.name in {"", ".", ".."}:
        raise ValueError("authoritative source repository is unavailable")
    descriptors: list[int] = []
    session: _ProductionGitSession | None = None
    try:
        _remaining_deadline(deadline)
        parent_fd = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        descriptors.append(parent_fd)
        _remaining_deadline(deadline)
        for component in candidate.parts[1:-1]:
            child_fd, _identity = _open_git_directory(parent_fd, component, deadline)
            descriptors.append(child_fd)
            _close_owned_git_descriptors(parent_fd)
            descriptors.remove(parent_fd)
            parent_fd = child_fd
            _remaining_deadline(deadline)
        worktree_fd, worktree_identity = _open_git_directory(parent_fd, candidate.name, deadline)
        descriptors.append(worktree_fd)
        git_fd, git_identity = _open_git_directory(worktree_fd, ".git", deadline)
        descriptors.append(git_fd)
        config_fd, config_identity = _open_git_regular(git_fd, "config", deadline)
        descriptors.append(config_fd)
        config_bytes = _read_pinned_descriptor(config_fd, _MAX_GIT_METADATA_BYTES, deadline)
        _validate_production_git_config(config_bytes, deadline)
        head_fd, head_identity = _open_git_regular(git_fd, "HEAD", deadline)
        descriptors.append(head_fd)
        head_bytes = _read_pinned_descriptor(head_fd, 256, deadline)
        refs_fd, refs_identity = _open_git_directory(git_fd, "refs", deadline)
        descriptors.append(refs_fd)
        objects_fd, objects_identity = _open_git_directory(git_fd, "objects", deadline)
        descriptors.append(objects_fd)
        objects_info_fd, objects_info_identity = _open_git_directory(objects_fd, "info", deadline)
        descriptors.append(objects_info_fd)
        objects_pack_fd, objects_pack_identity = _open_git_directory(objects_fd, "pack", deadline)
        descriptors.append(objects_pack_fd)
        info_fd, info_identity = _open_git_directory(git_fd, "info", deadline)
        descriptors.append(info_fd)
        _reject_present_git_entry(info_fd, "grafts", deadline)
        _reject_present_git_entry(objects_info_fd, "alternates", deadline)
        _reject_present_git_entry(objects_info_fd, "http-alternates", deadline)
        _reject_present_git_entry(refs_fd, "replace", deadline)
        metadata_nodes = _snapshot_git_metadata_tree(refs_fd, "refs", deadline)
        _remaining_deadline(deadline)
        metadata_nodes.update(_snapshot_git_metadata_tree(objects_fd, "objects", deadline))
        _remaining_deadline(deadline)
        packed_refs_fd: int | None = None
        packed_refs_identity: tuple[int, int, int, int, int, int, int, int, int] | None = None
        packed_refs_bytes: bytes | None = None
        try:
            packed_refs_fd, packed_refs_identity = _open_git_regular(git_fd, "packed-refs", deadline)
            descriptors.append(packed_refs_fd)
            packed_refs_bytes = _read_pinned_descriptor(
                packed_refs_fd, _MAX_GIT_METADATA_BYTES, deadline,
            )
            _validate_packed_refs(packed_refs_bytes, deadline)
        except FileNotFoundError:
            packed_refs_fd = None
            packed_refs_identity = None
            packed_refs_bytes = None
        except ValueError as error:
            if str(error) == "authoritative source repository is unavailable":
                raise
            raise
        if not head_bytes.endswith(b"\n") or head_bytes.count(b"\n") != 1:
            raise ValueError("authoritative source repository is unavailable")
        head_value = head_bytes[:-1].decode("ascii", "strict")
        ref_path: str | None = None
        ref_fd: int | None = None
        ref_identity: tuple[int, int, int, int, int, int, int, int, int] | None = None
        ref_bytes: bytes | None = None
        if head_value.startswith("ref: "):
            ref_path = head_value[5:]
            try:
                ref_fd, ref_identity, ref_bytes = _open_relative_git_ref(
                    refs_fd, ref_path, deadline,
                )
                descriptors.append(ref_fd)
                head_commit = ref_bytes[:-1].decode("ascii", "strict")
            except FileNotFoundError:
                if packed_refs_bytes is None:
                    raise ValueError("authoritative source repository is unavailable") from None
                head_commit = _read_packed_ref(packed_refs_bytes, ref_path, deadline)
        else:
            head_commit = head_value
        if _COMMIT.fullmatch(head_commit) is None:
            raise ValueError("authoritative source repository is unavailable")
        identities = {
            "parent": _pinned_identity(_deadline_result(deadline, os.fstat, parent_fd)),
            "worktree": worktree_identity,
            "git": git_identity,
            "config": config_identity,
            "head": head_identity,
            "refs": refs_identity,
            "objects": objects_identity,
            "objects_info": objects_info_identity,
            "objects_pack": objects_pack_identity,
            "info": info_identity,
        }
        if packed_refs_identity is not None:
            identities["packed_refs"] = packed_refs_identity
        if ref_identity is not None:
            identities["ref"] = ref_identity
        session = _ProductionGitSession(
            str(candidate), candidate.name, parent_fd, worktree_fd, git_fd, config_fd,
            head_fd, refs_fd, objects_fd, objects_info_fd, objects_pack_fd, info_fd,
            packed_refs_fd, ref_fd, identities, metadata_nodes, config_bytes, head_bytes, packed_refs_bytes,
            ref_path, ref_bytes, head_commit, deadline,
        )
        _remaining_deadline(deadline)
        descriptors.clear()
        return session
    except Exception:
        try:
            _close_owned_git_descriptors(*reversed(descriptors))
        except Exception:
            pass
        raise ValueError("authoritative source repository is unavailable") from None


def _reopen_production_repository_identity(
    path: str, deadline: float,
) -> tuple[int, int, int, int, int]:
    """Retraverse every absolute worktree component without following symlinks."""
    candidate = Path(path)
    current_fd: int | None = None
    child_fd: int | None = None
    result: tuple[int, int, int, int, int] | None = None
    try:
        _remaining_deadline(deadline)
        current_fd = os.open(
            "/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        _remaining_deadline(deadline)
        for component in candidate.parts[1:]:
            child_fd, _identity = _open_git_directory(current_fd, component, deadline)
            _close_owned_git_descriptors(current_fd)
            current_fd = child_fd
            child_fd = None
            _remaining_deadline(deadline)
        result = _repository_identity(_deadline_result(deadline, os.fstat, current_fd))
    finally:
        _close_owned_git_descriptors(child_fd, current_fd)
    _remaining_deadline(deadline)
    if result is None:
        raise ValueError("authoritative source repository is unavailable")
    return result


def _verify_production_repository_identity(session: _ProductionGitSession) -> None:
    """Revalidate every pinned worktree, Git metadata, ref, and object-store node."""
    _remaining_deadline(session.deadline)
    descriptors = {
        "parent": session.parent_fd, "worktree": session.worktree_fd, "git": session.git_fd,
        "config": session.config_fd, "head": session.head_fd, "refs": session.refs_fd,
        "objects": session.objects_fd, "objects_info": session.objects_info_fd,
        "objects_pack": session.objects_pack_fd, "info": session.info_fd,
    }
    if session.packed_refs_fd is not None:
        descriptors["packed_refs"] = session.packed_refs_fd
    if session.ref_fd is not None:
        descriptors["ref"] = session.ref_fd
    for name, descriptor in descriptors.items():
        if _pinned_identity(
            _deadline_result(session.deadline, os.fstat, descriptor)
        ) != session.identities[name]:
            raise ValueError("authoritative source repository changed during read")
    checks = (
        (session.parent_fd, session.worktree_name, "worktree"),
        (session.worktree_fd, ".git", "git"),
        (session.git_fd, "config", "config"),
        (session.git_fd, "HEAD", "head"),
        (session.git_fd, "refs", "refs"),
        (session.git_fd, "objects", "objects"),
        (session.objects_fd, "info", "objects_info"),
        (session.objects_fd, "pack", "objects_pack"),
        (session.git_fd, "info", "info"),
    )
    for parent_fd, name, identity_name in checks:
        entry = _deadline_result(
            session.deadline, os.stat, name, dir_fd=parent_fd, follow_symlinks=False,
        )
        if _pinned_identity(entry) != session.identities[identity_name]:
            raise ValueError("authoritative source repository changed during read")
    if session.packed_refs_fd is not None:
        entry = _deadline_result(
            session.deadline, os.stat, "packed-refs",
            dir_fd=session.git_fd, follow_symlinks=False,
        )
        if _pinned_identity(entry) != session.identities["packed_refs"]:
            raise ValueError("authoritative source repository changed during read")
    if session.ref_fd is not None and session.ref_path is not None:
        if _pinned_identity(
            _stat_relative_git_ref(session.refs_fd, session.ref_path, session.deadline)
        ) != session.identities["ref"]:
            raise ValueError("authoritative source repository changed during read")
    if _reopen_production_repository_identity(
        session.path, session.deadline,
    ) != _repository_identity(
        _deadline_result(session.deadline, os.fstat, session.worktree_fd)
    ):
        raise ValueError("authoritative source repository changed during read")
    _reject_present_git_entry(session.info_fd, "grafts", session.deadline)
    _reject_present_git_entry(session.objects_info_fd, "alternates", session.deadline)
    _reject_present_git_entry(session.objects_info_fd, "http-alternates", session.deadline)
    _reject_present_git_entry(session.refs_fd, "replace", session.deadline)
    current_metadata_nodes = _snapshot_git_metadata_tree(
        session.refs_fd, "refs", session.deadline,
    )
    current_metadata_nodes.update(_snapshot_git_metadata_tree(
        session.objects_fd, "objects", session.deadline,
    ))
    if current_metadata_nodes != session.metadata_nodes:
        raise ValueError("authoritative source repository changed during read")
    if _read_pinned_descriptor(
        session.config_fd, _MAX_GIT_METADATA_BYTES, session.deadline,
    ) != session.config_bytes:
        raise ValueError("authoritative source repository changed during read")
    _validate_production_git_config(session.config_bytes, session.deadline)
    if _read_pinned_descriptor(session.head_fd, 256, session.deadline) != session.head_bytes:
        raise ValueError("authoritative source repository changed during read")
    if session.packed_refs_fd is not None:
        current_packed_refs = _read_pinned_descriptor(
            session.packed_refs_fd, _MAX_GIT_METADATA_BYTES, session.deadline,
        )
        if current_packed_refs != session.packed_refs_bytes:
            raise ValueError("authoritative source repository changed during read")
        _validate_packed_refs(current_packed_refs, session.deadline)
    if session.ref_fd is not None and session.ref_bytes is not None:
        if _read_pinned_descriptor(session.ref_fd, 256, session.deadline) != session.ref_bytes:
            raise ValueError("authoritative source repository changed during read")
    _remaining_deadline(session.deadline)


def _unsafe_ambient_git_environment() -> bool:
    protected = {
        "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE",
        "GIT_INDEX_FILE", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
    }
    return any(key in protected or key.startswith("GIT_CONFIG_") for key in os.environ)


def _git_stdout(session: _ProductionGitSession, arguments: tuple[str, ...], limit: int) -> bytes:
    """Read one bounded Git result under the session's single monotonic deadline."""
    if not isinstance(session, _ProductionGitSession):
        raise ValueError("authoritative Git read is unavailable")
    _remaining_deadline(session.deadline)
    if (
        not isinstance(arguments, tuple)
        or not arguments
        or any(type(argument) is not str or not argument for argument in arguments)
        or type(limit) is not int
        or limit <= 0
        or _unsafe_ambient_git_environment()
        or session.process_count >= _MAX_GIT_PROCESS_COUNT
    ):
        raise ValueError("authoritative Git read is unavailable")
    process: subprocess.Popen[bytes] | None = None
    output = b""
    failed = False
    session.process_count += 1
    try:
        _remaining_deadline(session.deadline)
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        environment.update({
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
        })
        process = subprocess.Popen(
            (
                "/usr/bin/git", "--no-replace-objects", f"--git-dir=/proc/self/fd/{session.git_fd}",
                *arguments,
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(session.git_fd,),
            env=environment,
        )
        _remaining_deadline(session.deadline)
        if process.stdout is None:
            raise ValueError("authoritative Git read is unavailable")
        chunks: list[bytes] = []
        total = 0
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if not selector.select(_remaining_deadline(session.deadline)):
                    raise ValueError("authoritative Git read is unavailable")
                _remaining_deadline(session.deadline)
                chunk = os.read(process.stdout.fileno(), min(64 * 1024, limit + 1 - total))
                _remaining_deadline(session.deadline)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise ValueError("authoritative Git read is unavailable")
        output = b"".join(chunks)
        if process.wait(timeout=_remaining_deadline(session.deadline)) != 0:
            raise ValueError("authoritative Git read is unavailable")
    except Exception:
        failed = True
    finally:
        if process is not None:
            ordinary_cleanup_error: Exception | None = None
            base_cleanup_error: BaseException | None = None

            def cleanup(operation: Callable[[], object]) -> None:
                nonlocal ordinary_cleanup_error, base_cleanup_error
                try:
                    operation()
                except BaseException as error:
                    if isinstance(error, Exception):
                        ordinary_cleanup_error = ordinary_cleanup_error or error
                    else:
                        base_cleanup_error = base_cleanup_error or error

            try:
                running = process.poll() is None
            except BaseException as error:
                running = True
                if isinstance(error, Exception):
                    ordinary_cleanup_error = error
                else:
                    base_cleanup_error = error
            if running:
                cleanup(process.terminate)
            cleanup(lambda: process.wait(timeout=1))
            if process.stdout is not None:
                cleanup(process.stdout.close)
            if base_cleanup_error is not None:
                raise base_cleanup_error
            if ordinary_cleanup_error is not None:
                failed = True
    if failed:
        raise ValueError("authoritative Git read is unavailable")
    _remaining_deadline(session.deadline)
    return output


def _git_object_id(object_type: str, content: bytes) -> str:
    return hashlib.sha1(
        object_type.encode("ascii") + b" " + str(len(content)).encode("ascii") + b"\0" + content,
    ).hexdigest()


def _read_git_object(
    session: _ProductionGitSession, object_type: str, object_id: str, limit: int,
) -> bytes:
    _remaining_deadline(session.deadline)
    if object_type not in {"commit", "tree", "blob"} or _COMMIT.fullmatch(object_id) is None:
        raise ValueError("authoritative runtime tree is malformed")
    content = _git_stdout(session, ("cat-file", object_type, object_id), limit)
    if len(content) > limit or _git_object_id(object_type, content) != object_id:
        raise ValueError("authoritative runtime tree is malformed")
    _remaining_deadline(session.deadline)
    return content


def _commit_tree_id(content: bytes, deadline: float) -> str:
    _remaining_deadline(deadline)
    header, separator, _message = content.partition(b"\n\n")
    if not separator:
        raise ValueError("authoritative runtime tree is malformed")
    tree_ids = [line[5:] for line in header.split(b"\n") if line.startswith(b"tree ")]
    if len(tree_ids) != 1:
        raise ValueError("authoritative runtime tree is malformed")
    try:
        tree_id = tree_ids[0].decode("ascii", "strict")
    except UnicodeDecodeError:
        raise ValueError("authoritative runtime tree is malformed") from None
    if _COMMIT.fullmatch(tree_id) is None:
        raise ValueError("authoritative runtime tree is malformed")
    _remaining_deadline(deadline)
    return tree_id


def _tree_entries(content: bytes, deadline: float) -> list[tuple[bytes, bytes, str]]:
    entries: list[tuple[bytes, bytes, str]] = []
    seen_names: set[bytes] = set()
    previous_sort_key: bytes | None = None
    offset = 0
    while offset < len(content):
        _remaining_deadline(deadline)
        separator = content.find(b" ", offset)
        terminator = content.find(b"\0", separator + 1)
        if separator <= offset or terminator < 0 or terminator + 21 > len(content):
            raise ValueError("authoritative runtime tree is malformed")
        mode = content[offset:separator]
        encoded_name = content[separator + 1:terminator]
        object_id = content[terminator + 1:terminator + 21].hex()
        if not encoded_name or b"/" in encoded_name:
            raise ValueError("authoritative runtime tree is malformed")
        sort_key = encoded_name + (b"/" if mode == b"40000" else b"\0")
        if (
            encoded_name in seen_names
            or (previous_sort_key is not None and previous_sort_key >= sort_key)
        ):
            raise ValueError("authoritative runtime tree is malformed")
        seen_names.add(encoded_name)
        previous_sort_key = sort_key
        entries.append((mode, encoded_name, object_id))
        offset = terminator + 21
    if offset != len(content):
        raise ValueError("authoritative runtime tree is malformed")
    _remaining_deadline(deadline)
    return entries


def _verify_live_runtime_entry(session: _ProductionGitSession, path: str, mode: int) -> None:
    _remaining_deadline(session.deadline)
    components = path.split("/")
    if not path or any(component in {"", ".", ".."} for component in components):
        raise ValueError("authoritative runtime tree is malformed")
    parent_fd = session.worktree_fd
    intermediates: list[int] = []
    descriptor: int | None = None
    try:
        for component in components[:-1]:
            descriptor, _identity = _open_git_directory(parent_fd, component, session.deadline)
            intermediates.append(descriptor)
            parent_fd = descriptor
        descriptor, _identity = _open_git_regular(parent_fd, components[-1], session.deadline)
        descriptor_info = _deadline_result(session.deadline, os.fstat, descriptor)
        entry_info = _deadline_result(
            session.deadline, os.stat, components[-1],
            dir_fd=parent_fd, follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(descriptor_info.st_mode)
            or _pinned_identity(descriptor_info) != _pinned_identity(entry_info)
            or stat.S_IMODE(descriptor_info.st_mode) != mode
        ):
            raise ValueError("authoritative runtime tree is malformed")
    finally:
        _close_owned_git_descriptors(descriptor, *reversed(intermediates))
    _remaining_deadline(session.deadline)


def _runtime_tree_records(session: _ProductionGitSession, commit: str) -> list[dict[str, object]]:
    _remaining_deadline(session.deadline)
    if _COMMIT.fullmatch(commit) is None:
        raise ValueError("authoritative runtime tree is malformed")
    tree_id = _commit_tree_id(
        _read_git_object(session, "commit", commit, _MAX_GIT_METADATA_BYTES),
        session.deadline,
    )
    files: list[dict[str, object]] = []
    seen_paths: set[str] = set()
    seen_trees: set[str] = set()
    total_blob_bytes = 0

    def walk(current_tree_id: str, prefix: str) -> None:
        nonlocal total_blob_bytes
        _remaining_deadline(session.deadline)
        if current_tree_id in seen_trees:
            raise ValueError("authoritative runtime tree is malformed")
        seen_trees.add(current_tree_id)
        tree = _read_git_object(session, "tree", current_tree_id, _MAX_GIT_TREE_BYTES)
        for raw_mode, encoded_name, object_id in _tree_entries(tree, session.deadline):
            _remaining_deadline(session.deadline)
            try:
                name = encoded_name.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise ValueError("authoritative runtime tree is malformed") from None
            path = f"{prefix}/{name}" if prefix else name
            components = path.split("/")
            if (
                len(encoded_name) > _MAX_GIT_PATH_BYTES
                or len(path.encode("utf-8")) > _MAX_GIT_PATH_BYTES
                or any(component in {"", ".", ".."} for component in components)
            ):
                raise ValueError("authoritative runtime tree is malformed")
            if any(component in RUNTIME_EXCLUDED for component in components):
                continue
            if raw_mode == b"40000":
                walk(object_id, path)
                continue
            if raw_mode not in {b"100644", b"100755"} or path in seen_paths:
                raise ValueError("authoritative runtime tree contains unsupported entries")
            seen_paths.add(path)
            if len(seen_paths) > _MAX_GIT_TREE_ENTRIES:
                raise ValueError("authoritative runtime tree is oversized")
            blob = _read_git_object(session, "blob", object_id, _MAX_GIT_BLOB_BYTES)
            total_blob_bytes += len(blob)
            if total_blob_bytes > _MAX_GIT_RUNTIME_BYTES:
                raise ValueError("authoritative runtime tree is oversized")
            files.append({
                "path": path,
                "mode": 0o644 if raw_mode == b"100644" else 0o755,
                "sha256": "sha256:" + hashlib.sha256(blob).hexdigest(),
            })

    walk(tree_id, "")
    files.sort(key=lambda item: str(item["path"]))
    for item in files:
        _verify_live_runtime_entry(session, str(item["path"]), int(item["mode"]))
        _remaining_deadline(session.deadline)
    _verify_production_repository_identity(session)
    for item in files:
        _verify_live_runtime_entry(session, str(item["path"]), int(item["mode"]))
        _remaining_deadline(session.deadline)
    _remaining_deadline(session.deadline)
    return files


def _with_production_repository(
    path: str, reader: Callable[[_ProductionGitSession], str], label: str,
) -> str:
    deadline = time.monotonic() + _MAX_GIT_OPERATION_SECONDS
    session: _ProductionGitSession | None = None
    value: str | None = None
    failed = False
    try:
        _remaining_deadline(deadline)
        session = _open_production_repository(path, deadline)
        _verify_production_repository_identity(session)
        value = reader(session)
        _verify_production_repository_identity(session)
        _remaining_deadline(deadline)
    except Exception:
        failed = True
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                failed = True
        try:
            _remaining_deadline(deadline)
        except Exception:
            failed = True
    if failed or value is None:
        raise ValueError(f"{label} is unavailable")
    return value


def _production_source_head(path: str) -> str:
    """Resolve and authenticate HEAD from the exact pinned repository session."""
    if path != ADAPTER_SOURCE_PATH:
        raise ValueError("authoritative source path is fixed")

    def reader(session: _ProductionGitSession) -> str:
        _read_git_object(session, "commit", session.head_commit, _MAX_GIT_METADATA_BYTES)
        return session.head_commit

    return _with_production_repository(path, reader, "authoritative source revision")


def _production_runtime_digest(path: str, commit: str) -> str:
    """Digest a named immutable tree only while the pinned checkout remains at it."""
    if path != ADAPTER_SOURCE_PATH or _COMMIT.fullmatch(commit) is None:
        raise ValueError("authoritative runtime tree is unavailable")

    def reader(session: _ProductionGitSession) -> str:
        if session.head_commit != commit:
            raise ValueError("authoritative runtime tree is unavailable")
        files = _runtime_tree_records(session, commit)
        _verify_production_repository_identity(session)
        if session.head_commit != commit:
            raise ValueError("authoritative runtime tree is unavailable")
        return "sha256:" + hashlib.sha256(json.dumps(
            {"version": 1, "commit": commit, "files": files},
            sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()

    try:
        return _with_production_repository(path, reader, "authoritative runtime tree")
    except Exception:
        raise ValueError("authoritative runtime tree is unavailable") from None


def _production_file_digest(path: str) -> str:
    """Digest only the reviewed GPG executable through a stable descriptor."""
    if path != GPG_PATH:
        raise ValueError("authoritative GPG path is fixed")
    noatime = getattr(os, "O_NOATIME", 0)
    if not noatime:
        raise ValueError("authoritative GPG executable is unavailable")
    descriptor: int | None = None
    digest_value: str | None = None
    failed = False
    try:
        descriptor = os.open(
            GPG_PATH,
            os.O_RDONLY | os.O_NOFOLLOW | noatime | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        entry_before = os.stat(GPG_PATH, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > _MAX_GPG_BYTES
            or _exact_file_metadata(before) != _exact_file_metadata(entry_before)
        ):
            raise ValueError("authoritative GPG executable is unavailable")
        digest = hashlib.sha256()
        offset = 0
        deadline = time.monotonic() + _MAX_GPG_READ_SECONDS
        while offset < before.st_size:
            _remaining_deadline(deadline)
            chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
            if not chunk:
                raise ValueError("authoritative GPG executable is unavailable")
            digest.update(chunk)
            offset += len(chunk)
        _remaining_deadline(deadline)
        after = os.fstat(descriptor)
        entry_after = os.stat(GPG_PATH, follow_symlinks=False)
        if (
            _exact_file_metadata(after) != _exact_file_metadata(before)
            or _exact_file_metadata(entry_after) != _exact_file_metadata(entry_before)
            or _exact_file_metadata(after) != _exact_file_metadata(entry_after)
        ):
            raise ValueError("authoritative GPG executable changed during digest")
        digest_value = "sha256:" + digest.hexdigest()
    except Exception:
        failed = True
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except Exception:
                failed = True
    if failed or digest_value is None:
        raise ValueError("authoritative GPG executable is unavailable")
    return digest_value


def _production_executable_exists(path: str) -> bool:
    if path != GPG_PATH:
        return False
    try:
        info = os.stat(GPG_PATH, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111)


def _production_canonical_boundaries_valid() -> bool:
    """Validate the code-owned host boundary constants without host mutation."""
    fixed_paths = (
        ADAPTER_SOURCE_PATH,
        SOURCE_PATH,
        GPG_PATH,
        _OVERSEER_TOKEN_SOURCE_FILE,
        _OVERSEER_TOKEN_FILE,
        _CURSOR_KEY_FILE,
    )
    return (
        ADAPTER_SOURCE_PATH == "/home/god/Documents/Codex Workspace/TheUnderdark"
        and SOURCE_PATH == "/home/god/Documents/Codex Workspace/DonutHole"
        and GPG_PATH == "/usr/bin/gpg"
        and all(Path(path).is_absolute() for path in fixed_paths)
    )


def _production_rollback_prerequisites_valid() -> bool:
    """Require the reviewed packaged rollback and acceptance scenarios."""
    contract = load_packaged_provisioning_contract()
    scenarios = contract.raw["scenarios"]
    return (
        contract.version == PROVISIONING_CONTRACT_VERSION
        and isinstance(scenarios, list)
        and tuple(item.get("name") for item in scenarios if isinstance(item, dict))
        == ("clean_install", "active_service_upgrade")
        and all(
            isinstance(item, dict)
            and item.get("expected_terminal_status") == "acceptance_passed"
            for item in scenarios
        )
    )


def _load_persisted_bundles_read_only(store_path: str) -> tuple[ProvisioningBundleV1, ...]:
    """Load exact bundles from a stable byte snapshot without touching the store."""
    try:
        database_fd, parent_fd, identity = _open_authority_snapshot(store_path)
    except Exception:
        raise ValueError("persisted provisioning chain is unavailable") from None
    snapshot_fd: int | None = None
    snapshot_path: str | None = None
    connection: sqlite3.Connection | None = None
    failed = False
    bundles: list[ProvisioningBundleV1] = []
    try:
        snapshot = _read_authority_snapshot(database_fd, parent_fd, identity)
        snapshot_fd, snapshot_path = tempfile.mkstemp(
            prefix="overseer-bundle-chain-", suffix=".sqlite3",
        )
        _write_snapshot(snapshot_fd, snapshot)
        os.fsync(snapshot_fd)
        os.close(snapshot_fd)
        snapshot_fd = None
        _verify_authority_snapshot(parent_fd, identity)
        connection = sqlite3.connect(f"file:{snapshot_path}?mode=ro&immutable=1", uri=True)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        rows = connection.execute(
            "SELECT id, plan_id, bundle_digest, payload "
            "FROM provisioning_bundles ORDER BY plan_id"
        ).fetchall()
        for row in rows:
            if len(row) != 4 or any(type(value) is not str for value in row):
                raise ValueError("persisted provisioning chain is malformed")
            bundle_id, plan_id, stored_digest, payload = row
            bundle = _decode_exact_payload(
                payload, ProvisioningBundleV1, "provisioning bundle",
            )
            _validate_staged_bundle(bundle)
            if (
                bundle_id != plan_id
                or bundle.plan.plan_id != plan_id
                or bundle.bundle_digest != stored_digest
            ):
                raise ValueError("persisted provisioning chain is inconsistent")
            bundles.append(bundle)
        if _read_authority_snapshot(database_fd, parent_fd, identity) != snapshot:
            raise ValueError("persisted provisioning chain changed during read")
    except Exception:
        failed = True
    finally:
        for cleanup in (
            (lambda: connection.close() if connection is not None else None),
            (lambda: os.close(snapshot_fd) if snapshot_fd is not None else None),
            (lambda: os.unlink(snapshot_path) if snapshot_path is not None else None),
            (lambda: _verify_authority_snapshot(parent_fd, identity)),
            (lambda: os.close(database_fd)),
            (lambda: os.close(parent_fd)),
        ):
            try:
                cleanup()
            except Exception:
                failed = True
    if failed:
        raise ValueError("persisted provisioning chain is unavailable")
    return tuple(bundles)


def _persisted_chain_tip(
    bundles: tuple[ProvisioningBundleV1, ...], predecessor_plan_id: str,
) -> str | None:
    by_id = {bundle.plan.plan_id: bundle for bundle in bundles}
    predecessor = by_id.get(predecessor_plan_id)
    if predecessor is None or len(by_id) != len(bundles):
        return None
    scope = _intent_scope(predecessor.intent)
    scoped = {
        plan_id: bundle
        for plan_id, bundle in by_id.items()
        if _intent_scope(bundle.intent) == scope
    }
    referenced: set[str] = set()
    for bundle in scoped.values():
        declared = bundle.supersedes_plan_id
        if declared is not None:
            if declared not in scoped:
                return None
            referenced.add(declared)
    tips = set(scoped) - referenced
    if len(tips) != 1:
        return None
    tip = next(iter(tips))
    visited: set[str] = set()
    cursor: str | None = tip
    while cursor is not None:
        if cursor in visited or cursor not in scoped:
            return None
        visited.add(cursor)
        cursor = scoped[cursor].supersedes_plan_id
    return tip if visited == set(scoped) else None


def _intent_scope(intent: ProvisioningIntentV1) -> tuple[str, str, str, str, str, str]:
    """Return the code-owned typed identity for one provisioning history."""
    return (
        intent.kind,
        intent.project_id,
        _BUNDLE_WORKSPACE_ID,
        intent.resource_id,
        intent.root_id,
        intent.policy_revision,
    )


def _production_root_scope_allowed(
    bundles: tuple[ProvisioningBundleV1, ...], intent: ProvisioningIntentV1,
) -> bool:
    matching = tuple(
        bundle for bundle in bundles if _intent_scope(bundle.intent) == _intent_scope(intent)
    )
    return not matching or (
        len(matching) == 1 and matching[0].plan.plan_id == intent.plan_id
    )


def production_preflight_dependencies(store_path: str) -> _PreflightDependencies:
    """Construct the sole production-owned authoritative preflight boundary."""
    bundles = _load_persisted_bundles_read_only(store_path)
    by_id = {bundle.plan.plan_id: bundle for bundle in bundles}
    return _PreflightDependencies(
        source_path=ADAPTER_SOURCE_PATH,
        source_head=_production_source_head,
        runtime_digest=_production_runtime_digest,
        capability_digest=reviewed_capability_digest,
        file_digest=_production_file_digest,
        executable_exists=_production_executable_exists,
        root_path=SOURCE_PATH,
        root_identity=current_root_identity,
        resolve_root_authorization=_read_current_root_authorization,
        canonical_boundaries_valid=_production_canonical_boundaries_valid,
        rollback_prerequisites_valid=_production_rollback_prerequisites_valid,
        predecessor_lookup=lambda plan_id: by_id.get(plan_id),
        authoritative_chain_tip=lambda plan_id: _persisted_chain_tip(bundles, plan_id),
        root_scope_allowed=lambda intent: _production_root_scope_allowed(bundles, intent),
    )


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
    except Exception:
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


def _run_provisioning_preflight_with_dependencies(
    store_path: str, intent: ProvisioningIntentV1, dependencies: _PreflightDependencies,
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


def run_provisioning_preflight(
    store_path: str, intent: ProvisioningIntentV1,
) -> ProvisioningPreflightReport:
    """Run production preflight using only server-owned authority readers."""
    return _run_provisioning_preflight_with_dependencies(
        store_path, intent, production_preflight_dependencies(store_path),
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
    intent: ProvisioningIntentV1, dependencies: _PreflightDependencies,
) -> ProvisioningBundleV1 | None:
    if not intent.supersedes_plan_id:
        allowed, available = _safe_read(dependencies.root_scope_allowed, intent)
        if not available:
            raise ProvisioningBundleError("CHAIN_SCOPE_UNAVAILABLE")
        if allowed is not True:
            raise ProvisioningBundleError("CHAIN_ROOT_EXISTS")
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
    tip, tip_available = _safe_read(
        dependencies.authoritative_chain_tip, intent.supersedes_plan_id,
    )
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
    predecessor: ProvisioningBundleV1, dependencies: _PreflightDependencies, seen: set[str],
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


def _build_provisioning_bundle_with_dependencies(
    store_path: str, intent: ProvisioningIntentV1, dependencies: _PreflightDependencies,
) -> ProvisioningBundleV1:
    """Build one immutable, read-only review bundle from the preflight snapshot."""
    report = _run_provisioning_preflight_with_dependencies(store_path, intent, dependencies)
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


def build_provisioning_bundle(
    store_path: str, intent: ProvisioningIntentV1,
) -> ProvisioningBundleV1:
    """Build a production preview using only server-owned authority readers."""
    return _build_provisioning_bundle_with_dependencies(
        store_path, intent, production_preflight_dependencies(store_path),
    )


def _validate_staged_bundle(bundle: ProvisioningBundleV1) -> None:
    """Require the full immutable builder contract before writing any row."""
    if type(bundle) is not ProvisioningBundleV1:
        raise ValueError("bundle must be an exact ProvisioningBundleV1")
    if not _valid_predecessor_contract(bundle):
        raise ValueError("bundle immutable contract is invalid")
    if bundle.bundle_digest != bundle_digest(bundle):
        raise ValueError("bundle digest does not match immutable content")


def _canonical_payload(value: object) -> str:
    return json.dumps(to_jsonable(value), sort_keys=True, separators=(",", ":"))


def _decode_exact_payload(payload: str, value_type: type[object], label: str):
    if not isinstance(payload, str):
        raise ValueError(f"{label} serialized payload is invalid")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as error:
        raise ValueError(f"{label} serialized payload is invalid") from error
    if not isinstance(data, dict) or set(data) != {field.name for field in fields(value_type)}:
        raise ValueError(f"{label} serialized payload has an invalid shape")
    try:
        decoded = dataclass_from_jsonable(value_type, data)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} serialized payload is invalid") from error
    if type(decoded) is not value_type or _canonical_payload(decoded) != payload:
        raise ValueError(f"{label} serialized payload is not exact")
    return decoded


def dump_provisioning_bundle(bundle: ProvisioningBundleV1) -> str:
    """Serialize one already-validated bundle into its exact persisted bytes."""
    _validate_staged_bundle(bundle)
    payload = _canonical_payload(bundle)
    if _decode_exact_payload(payload, ProvisioningBundleV1, "provisioning bundle") != bundle:
        raise ValueError("provisioning bundle serialized payload is not exact")
    return payload


def load_provisioning_bundle(store: SQLiteStore, plan_id: str) -> ProvisioningBundleV1:
    """Load one bundle only if its stored bytes and digest reconstruct exactly."""
    if not isinstance(store, SQLiteStore):
        raise ValueError("bundle store must be an exact SQLiteStore")
    bundle_id, stored_plan_id, stored_digest, payload = store.load_provisioning_bundle_record(plan_id)
    bundle = _decode_exact_payload(
        payload,
        ProvisioningBundleV1,
        "provisioning bundle",
    )
    _validate_staged_bundle(bundle)
    if (
        bundle_id != plan_id
        or stored_plan_id != plan_id
        or bundle.plan.plan_id != plan_id
        or bundle.bundle_digest != stored_digest
    ):
        raise ValueError("provisioning bundle digest or plan ID is inconsistent")
    return bundle


def _dump_preflight_report(report: ProvisioningPreflightReport) -> str:
    payload = _canonical_payload(report)
    if _decode_exact_payload(payload, ProvisioningPreflightReport, "preflight report") != report:
        raise ValueError("preflight report serialized payload is not exact")
    return payload


def _dump_review_outbox_entry(entry: ProvisioningReviewOutboxEntry) -> str:
    payload = _canonical_payload(entry)
    if _decode_exact_payload(payload, ProvisioningReviewOutboxEntry, "review outbox") != entry:
        raise ValueError("review outbox serialized payload is not exact")
    return payload


def _recheck_current_root_authority(
    store_path: str,
    bundle: ProvisioningBundleV1,
) -> None:
    """Reject a preview that is no longer bound to the current exact root."""
    resolved = bundle.preflight.resolved_inputs
    try:
        current = _read_current_root_authorization(
            store_path,
            bundle.intent.project_id,
            bundle.intent.root_id,
            bundle.intent.policy_revision,
            str(resolved["root_identity"]),
            _ROOT_ALIAS,
            _ROOT_STATUS,
            _ROOT_MAX_BYTES,
            str(resolved["target_digest"]),
        )
    except Exception as error:
        raise ValueError("STALE_PREVIEW") from error
    if (
        not isinstance(current, Mapping)
        or current.get("authorization_ref") != resolved.get("authorization_ref")
        or current.get("root_identity") != resolved.get("root_identity")
        or current.get("target_digest") != resolved.get("target_digest")
    ):
        raise ValueError("STALE_PREVIEW")


def _recheck_current_root_authority_locked(
    store: SQLiteStore,
    bundle: ProvisioningBundleV1,
) -> None:
    """Revalidate the exact root after the binding transaction owns the write lock."""
    resolved = bundle.preflight.resolved_inputs
    try:
        current = _read_current_root_authorization_from_connection(
            store._connection,
            bundle.intent.project_id,
            bundle.intent.root_id,
            bundle.intent.policy_revision,
            str(resolved["root_identity"]),
            _ROOT_ALIAS,
            _ROOT_STATUS,
            _ROOT_MAX_BYTES,
            str(resolved["target_digest"]),
        )
    except Exception as error:
        raise ValueError("STALE_PREVIEW") from error
    if (
        current.get("authorization_ref") != resolved.get("authorization_ref")
        or current.get("root_identity") != resolved.get("root_identity")
        or current.get("target_digest") != resolved.get("target_digest")
    ):
        raise ValueError("STALE_PREVIEW")


def _load_persisted_bundles_locked(store: SQLiteStore) -> tuple[ProvisioningBundleV1, ...]:
    rows = store._connection.execute(
        "SELECT plan_id FROM provisioning_bundles ORDER BY plan_id"
    ).fetchall()
    if any(len(row) != 1 or type(row[0]) is not str for row in rows):
        raise ProvisioningBundleError("CHAIN_SCOPE_UNAVAILABLE")
    try:
        return tuple(load_provisioning_bundle(store, row[0]) for row in rows)
    except Exception:
        raise ProvisioningBundleError("CHAIN_SCOPE_UNAVAILABLE") from None


def _recheck_provisioning_chain_locked(
    store: SQLiteStore,
    bundle: ProvisioningBundleV1,
) -> None:
    """Revalidate exact history while BEGIN IMMEDIATE excludes competing roots."""
    bundles = _load_persisted_bundles_locked(store)
    scoped = tuple(
        candidate
        for candidate in bundles
        if _intent_scope(candidate.intent) == _intent_scope(bundle.intent)
    )
    existing = next(
        (candidate for candidate in scoped if candidate.plan.plan_id == bundle.plan.plan_id),
        None,
    )
    if bundle.supersedes_plan_id is None:
        if any(candidate.plan.plan_id != bundle.plan.plan_id for candidate in scoped):
            raise ProvisioningBundleError("CHAIN_ROOT_EXISTS")
        return
    predecessor = next(
        (
            candidate
            for candidate in scoped
            if candidate.plan.plan_id == bundle.supersedes_plan_id
        ),
        None,
    )
    if predecessor is None:
        raise ProvisioningBundleError("PREDECESSOR_UNAVAILABLE")
    actual_tip = _persisted_chain_tip(bundles, predecessor.plan.plan_id)
    expected_tip = bundle.plan.plan_id if existing is not None else predecessor.plan.plan_id
    if actual_tip != expected_tip:
        raise ProvisioningBundleError("PREDECESSOR_NOT_CURRENT")


def _recheck_locked_authority_and_chain(
    store: SQLiteStore,
    bundle: ProvisioningBundleV1,
) -> None:
    _recheck_current_root_authority_locked(store, bundle)
    _recheck_provisioning_chain_locked(store, bundle)


def binding_draft_for_bundle(bundle: ProvisioningBundleV1) -> RoadexApprovalBindingDraft:
    """Derive the one code-owned prospective approval binding for a bundle."""
    _validate_staged_bundle(bundle)
    return RoadexApprovalBindingDraft(
        approval_ref=f"approval.donuthole.{bundle.plan.plan_id}",
        source_kind="roadex-human-decision",
        source_id=bundle.plan.plan_id,
        project_id=bundle.intent.project_id,
        workspace_id=_BUNDLE_WORKSPACE_ID,
        resource_ref=bundle.intent.resource_id,
        authority_class="project-workflow",
        subject=f"{_BUNDLE_BINDING_SUBJECT} {bundle.bundle_digest}",
    )


def _load_exact_preflight_report(
    store: SQLiteStore,
    bundle: ProvisioningBundleV1,
) -> ProvisioningPreflightReport:
    report_id, plan_id, report_digest, payload = store.load_provisioning_preflight_report_record(
        bundle.preflight.report_id,
    )
    report = _decode_exact_payload(
        payload,
        ProvisioningPreflightReport,
        "preflight report",
    )
    if (
        report_id != bundle.preflight.report_id
        or plan_id != bundle.plan.plan_id
        or report_digest != bundle.preflight.report_digest
        or payload != _dump_preflight_report(bundle.preflight)
    ):
        raise ValueError("provisioning bundle immutable preflight digest is inconsistent")
    return report


def _load_exact_outbox(
    store: SQLiteStore,
    bundle: ProvisioningBundleV1,
) -> tuple[ProvisioningReviewOutboxEntry, ...]:
    records = store.list_provisioning_review_outbox_records(bundle.plan.plan_id)
    entries = tuple(
        _decode_exact_payload(record[4], ProvisioningReviewOutboxEntry, "review outbox")
        for record in records
    )
    if entries != bundle.outbox or tuple(
        _dump_review_outbox_entry(entry) for entry in entries
    ) != tuple(_dump_review_outbox_entry(entry) for entry in bundle.outbox):
        raise ValueError("provisioning bundle immutable review outbox is inconsistent")
    if any(
        record[:4] != (
            entry.id,
            entry.plan_id,
            entry.owner_domain.value,
            entry.state,
        )
        for record, entry in zip(records, entries, strict=True)
    ):
        raise ValueError("provisioning bundle immutable review outbox is inconsistent")
    return entries


def verify_exact_persisted_bundle_set(
    store: SQLiteStore,
    bundle: ProvisioningBundleV1,
    binding: RoadexApprovalBinding,
) -> None:
    """Reject a missing or changed persisted member without reconstructing it."""
    try:
        _verify_exact_persisted_bundle_set(store, bundle, binding)
    except KeyError as error:
        raise ValueError("provisioning bundle immutable persisted set is incomplete") from error


def _verify_exact_persisted_bundle_set(
    store: SQLiteStore,
    bundle: ProvisioningBundleV1,
    binding: RoadexApprovalBinding,
) -> None:
    """Prove that every stage record is present and byte-for-byte exact."""
    expected_draft = binding_draft_for_bundle(bundle)
    persisted_binding = store.load_roadex_approval_binding(binding.approval_ref)
    if persisted_binding != binding:
        raise ValueError("provisioning bundle immutable binding is inconsistent")
    if (
        persisted_binding.approval_ref != expected_draft.approval_ref
        or persisted_binding.source_kind != expected_draft.source_kind
        or persisted_binding.source_id != expected_draft.source_id
        or persisted_binding.project_id != expected_draft.project_id
        or persisted_binding.workspace_id != expected_draft.workspace_id
        or persisted_binding.resource_ref != expected_draft.resource_ref
        or persisted_binding.authority_class != expected_draft.authority_class
        or persisted_binding.subject != expected_draft.subject
    ):
        raise ValueError("provisioning bundle immutable binding is inconsistent")

    source_payload = store.load_registered_source_payload(
        "backup-provisioning-plan", bundle.plan.plan_id,
    )
    expected_source_payload = _canonical_payload(bundle.plan)
    if source_payload != expected_source_payload:
        raise ValueError("provisioning bundle immutable source is inconsistent")
    source = load_exact_bound_source(store, persisted_binding)
    if _canonical_payload(source) != expected_source_payload:
        raise ValueError("provisioning bundle immutable source is inconsistent")

    _load_exact_preflight_report(store, bundle)
    persisted_bundle = load_provisioning_bundle(store, bundle.plan.plan_id)
    if dump_provisioning_bundle(persisted_bundle) != dump_provisioning_bundle(bundle):
        raise ValueError("provisioning bundle immutable payload is inconsistent")
    _load_exact_outbox(store, bundle)


def _public_bundle_status(
    bundle: ProvisioningBundleV1,
    binding: RoadexApprovalBinding,
    *,
    mutation: bool,
) -> Mapping[str, object]:
    return {
        "ok": True,
        "status": "staged",
        "plan_id": bundle.plan.plan_id,
        "plan_digest": bundle.plan.plan_digest,
        "preflight_digest": bundle.preflight.report_digest,
        "bundle_digest": bundle.bundle_digest,
        "approval_ref": binding.approval_ref,
        "scope_digest": binding.scope_digest,
        "approval_required": True,
        "redactions_applied": True,
        "mutation_performed": mutation,
        "host_mutation_performed": False,
    }


def _public_bundle_preview(bundle: ProvisioningBundleV1) -> Mapping[str, object]:
    """Project one authoritative preview without authority or host details."""
    return {
        "ok": True,
        "status": "preview",
        "request_id": bundle.intent.request_id,
        "plan_id": bundle.plan.plan_id,
        "bundle_id": bundle.intent.plan_id,
        "preflight_report_id": bundle.preflight.report_id,
        "plan_digest": bundle.plan.plan_digest,
        "preflight_digest": bundle.preflight.report_digest,
        "bundle_digest": bundle.bundle_digest,
        "approval_required": True,
        "redactions_applied": True,
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _parse_public_intent_request(
    payload: Mapping[str, object],
    required_fields: frozenset[str],
    error_code: str,
) -> ProvisioningIntentV1:
    try:
        if not isinstance(payload, Mapping) or set(payload) != required_fields:
            raise ValueError
        intent_payload = payload["intent"]
        if not isinstance(intent_payload, Mapping):
            raise ValueError
        return parse_provisioning_intent(intent_payload)
    except Exception:
        raise ProvisioningBundleError(error_code) from None


def preflight_bundle_api(
    store_path: str, payload: Mapping[str, object],
) -> Mapping[str, object]:
    """Build one redacted preview solely from a strict typed-intent mapping."""
    intent = _parse_public_intent_request(
        payload,
        frozenset({"intent"}),
        "INVALID_BUNDLE_PREFLIGHT_REQUEST",
    )
    try:
        return _public_bundle_preview(build_provisioning_bundle(store_path, intent))
    except Exception:
        raise ProvisioningBundleError("BUNDLE_PREFLIGHT_UNAVAILABLE") from None


def stage_bundle_api(
    store_path: str, payload: Mapping[str, object],
) -> Mapping[str, object]:
    """Authoritatively rebuild and stage only a caller-previewed typed intent."""
    required = frozenset({
        "intent", "expected_preflight_digest", "expected_bundle_digest",
    })
    intent = _parse_public_intent_request(
        payload,
        required,
        "INVALID_BUNDLE_STAGE_REQUEST",
    )
    expected_preflight = payload["expected_preflight_digest"]
    expected_bundle = payload["expected_bundle_digest"]
    if not _valid_digest(expected_preflight) or not _valid_digest(expected_bundle):
        raise ProvisioningBundleError("INVALID_BUNDLE_STAGE_REQUEST")
    try:
        preview = build_provisioning_bundle(store_path, intent)
        expected = ProvisioningPreviewDigests(
            preview.plan.plan_digest,
            expected_preflight,
            expected_bundle,
        )
        result = stage_authoritative_bundle(store_path, intent, expected)
    except Exception as error:
        if str(error) == "PREVIEW_MISMATCH":
            raise ProvisioningBundleError("AUTHORITATIVE_REBUILD_MISMATCH") from None
        raise ProvisioningBundleError("BUNDLE_STAGE_UNAVAILABLE") from None
    return {
        **result,
        "bundle_id": preview.intent.plan_id,
        "preflight_report_id": preview.preflight.report_id,
    }


def _bundle_status_from_store(
    store: SQLiteStore, plan_id: str,
) -> Mapping[str, object]:
    try:
        bundle_id, stored_plan_id, stored_digest, payload = (
            store.load_provisioning_bundle_record(plan_id)
        )
    except KeyError:
        raise ProvisioningBundleError("BUNDLE_NOT_FOUND") from None
    try:
        bundle = _decode_exact_payload(
            payload,
            ProvisioningBundleV1,
            "provisioning bundle",
        )
        _validate_staged_bundle(bundle)
        if (
            bundle_id != plan_id
            or stored_plan_id != plan_id
            or bundle.plan.plan_id != plan_id
            or bundle.bundle_digest != stored_digest
        ):
            raise ValueError("provisioning bundle digest or plan ID is inconsistent")
    except Exception:
        raise ProvisioningBundleError("BUNDLE_STATUS_INTEGRITY_ERROR") from None
    try:
        binding = store.load_roadex_approval_binding(
            binding_draft_for_bundle(bundle).approval_ref,
        )
        if type(binding) is not RoadexApprovalBinding:
            raise ValueError("provisioning bundle immutable binding is inconsistent")
        verify_exact_persisted_bundle_set(store, bundle, binding)
    except sqlite3.OperationalError as error:
        if (
            getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_INTERRUPT
            or "interrupted" in str(error).lower()
        ):
            raise
        raise ProvisioningBundleError("BUNDLE_STATUS_INTEGRITY_ERROR") from None
    except Exception:
        raise ProvisioningBundleError("BUNDLE_STATUS_INTEGRITY_ERROR") from None
    return {
        **_public_bundle_status(bundle, binding, mutation=False),
        "bundle_id": bundle.intent.plan_id,
        "preflight_report_id": bundle.preflight.report_id,
        "review_outbox": tuple(
            {
                "id": entry.id,
                "owner_domain": entry.owner_domain.value,
                "state": entry.state,
            }
            for entry in bundle.outbox
        ),
    }


class _BundleStatusReadOnlyStore(SQLiteStore):
    """Loader-compatible SQLiteStore view with no writable lifecycle."""

    def __init__(self, connection: sqlite3.Connection, path: str) -> None:
        self.path = Path(path)
        self._connection = connection
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._connection.close()
        self._closed = True


def _require_bundle_status_time(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise TimeoutError("bundle status deadline expired")


def _open_bundle_status_store(
    database_path: str,
    deadline: float,
) -> _BundleStatusReadOnlyStore:
    """Open one private streamed copy without writable store lifecycle."""
    _require_bundle_status_time(deadline)
    path = Path(database_path)
    before = path.stat(follow_symlinks=False)
    if not path.is_absolute() or not stat.S_ISREG(before.st_mode):
        raise ValueError("bundle status pinned database is unavailable")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro&immutable=1",
            uri=True,
            timeout=0,
        )
        _require_bundle_status_time(deadline)
        if _file_identity(path.stat(follow_symlinks=False)) != _file_identity(before):
            raise ValueError("bundle status private database changed")
        connection.row_factory = sqlite3.Row
        connection.set_progress_handler(
            lambda: 1 if time.monotonic() > deadline else 0,
            _BUNDLE_STATUS_PROGRESS_OPCODES,
        )
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=0")
        if connection.execute("PRAGMA query_only").fetchone()[0] != 1:
            raise ValueError("bundle status query-only mode is unavailable")
        if connection.execute("PRAGMA busy_timeout").fetchone()[0] != 0:
            raise ValueError("bundle status zero busy timeout is unavailable")
        _require_bundle_status_time(deadline)
        return _BundleStatusReadOnlyStore(connection, database_path)
    except BaseException:
        if connection is not None:
            connection.close()
        raise


def _close_bundle_status_store(store: _BundleStatusReadOnlyStore) -> None:
    failure: BaseException | None = None
    try:
        store._connection.set_progress_handler(None, 0)
    except BaseException as error:
        failure = error
    try:
        store.close()
    except BaseException as error:
        if failure is None:
            failure = error
    if failure is not None:
        raise failure


def _write_bundle_status_chunk(
    descriptor: int,
    chunk: bytes,
    deadline: float,
) -> None:
    offset = 0
    while offset < len(chunk):
        _require_bundle_status_time(deadline)
        written = os.write(descriptor, chunk[offset:])
        _require_bundle_status_time(deadline)
        if written <= 0:
            raise OSError("bundle status private copy is unavailable")
        offset += written


def _stream_bundle_status_database(
    database_fd: int,
    parent_fd: int,
    identity: tuple[
        str,
        tuple[int, int, int, int, int, int],
        tuple[int, int, int, int, int, int],
    ],
    deadline: float,
) -> tuple[str, str]:
    """Stream the pinned database into a private file with bounded memory."""
    _require_bundle_status_time(deadline)
    _verify_authority_snapshot(parent_fd, identity)
    expected_size = identity[1][3]
    if expected_size > _MAX_BUNDLE_STATUS_DATABASE_BYTES:
        raise ValueError("bundle status database is too large")
    snapshot_fd: int | None = None
    snapshot_path: str | None = None
    hasher = hashlib.sha256()
    try:
        snapshot_fd, snapshot_path = tempfile.mkstemp(
            prefix="overseer-bundle-status-", suffix=".sqlite3",
        )
        offset = 0
        while offset < expected_size:
            _require_bundle_status_time(deadline)
            chunk = os.pread(
                database_fd,
                min(_BUNDLE_STATUS_BUFFER_BYTES, expected_size - offset),
                offset,
            )
            _require_bundle_status_time(deadline)
            if not chunk:
                raise ValueError("bundle status database is truncated")
            hasher.update(chunk)
            _write_bundle_status_chunk(snapshot_fd, chunk, deadline)
            offset += len(chunk)
        _require_bundle_status_time(deadline)
        extra = os.pread(database_fd, 1, offset)
        _require_bundle_status_time(deadline)
        if extra:
            raise ValueError("bundle status database grew during copy")
        _require_bundle_status_time(deadline)
        os.fsync(snapshot_fd)
        _require_bundle_status_time(deadline)
        os.close(snapshot_fd)
        snapshot_fd = None
        _verify_authority_snapshot(parent_fd, identity)
        if _file_identity(os.fstat(database_fd)) != identity[1]:
            raise ValueError("bundle status database changed during copy")
        return snapshot_path, "sha256:" + hasher.hexdigest()
    except BaseException:
        if snapshot_fd is not None:
            try:
                os.close(snapshot_fd)
            except Exception:
                pass
        if snapshot_path is not None:
            try:
                os.unlink(snapshot_path)
            except Exception:
                pass
        raise


def _hash_bundle_status_database(
    database_fd: int,
    parent_fd: int,
    identity: tuple[
        str,
        tuple[int, int, int, int, int, int],
        tuple[int, int, int, int, int, int],
    ],
    deadline: float,
) -> str:
    """Incrementally re-hash the pinned source after private queries finish."""
    _verify_authority_snapshot(parent_fd, identity)
    expected_size = identity[1][3]
    hasher = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        _require_bundle_status_time(deadline)
        chunk = os.pread(
            database_fd,
            min(_BUNDLE_STATUS_BUFFER_BYTES, expected_size - offset),
            offset,
        )
        _require_bundle_status_time(deadline)
        if not chunk:
            raise ValueError("bundle status database is truncated")
        hasher.update(chunk)
        offset += len(chunk)
    _require_bundle_status_time(deadline)
    extra = os.pread(database_fd, 1, offset)
    _require_bundle_status_time(deadline)
    if extra:
        raise ValueError("bundle status database grew during verification")
    _verify_authority_snapshot(parent_fd, identity)
    if _file_identity(os.fstat(database_fd)) != identity[1]:
        raise ValueError("bundle status database changed during verification")
    return "sha256:" + hasher.hexdigest()


def bundle_status(store_path: str, plan_id: str) -> Mapping[str, object]:
    """Read and verify one exact persisted bundle set without touching its store."""
    if (
        type(plan_id) is not str
        or not plan_id
        or plan_id != plan_id.strip()
        or len(plan_id) > 512
    ):
        raise ProvisioningBundleError("INVALID_BUNDLE_STATUS_REQUEST")
    deadline = time.monotonic() + _MAX_BUNDLE_STATUS_SECONDS
    database_fd: int | None = None
    parent_fd: int | None = None
    identity = None
    database_metadata: tuple[int, ...] | None = None
    entry_metadata: tuple[int, ...] | None = None
    snapshot_path: str | None = None
    source_digest: str | None = None
    store: _BundleStatusReadOnlyStore | None = None
    result: Mapping[str, object] | None = None
    failed = False
    semantic_error: str | None = None

    try:
        _require_bundle_status_time(deadline)
        database_fd, parent_fd, identity = _open_authority_snapshot(store_path)
        _require_bundle_status_time(deadline)
        database_info = os.fstat(database_fd)
        entry_info = os.stat(identity[0], dir_fd=parent_fd, follow_symlinks=False)
        database_metadata = _exact_file_metadata(database_info)
        entry_metadata = _exact_file_metadata(entry_info)
        if (
            database_info.st_size > _MAX_BUNDLE_STATUS_DATABASE_BYTES
            or database_metadata != entry_metadata
        ):
            raise ValueError("bundle status database is unavailable")
        _verify_authority_snapshot(parent_fd, identity)
        _require_bundle_status_time(deadline)
        snapshot_path, source_digest = _stream_bundle_status_database(
            database_fd, parent_fd, identity, deadline,
        )
        _require_bundle_status_time(deadline)
        store = _open_bundle_status_store(snapshot_path, deadline)
        _require_bundle_status_time(deadline)
        try:
            result = _bundle_status_from_store(store, plan_id)
        except ProvisioningBundleError as error:
            semantic_error = str(error)
        _require_bundle_status_time(deadline)
        _close_bundle_status_store(store)
        store = None
        _require_bundle_status_time(deadline)
        if _hash_bundle_status_database(
            database_fd, parent_fd, identity, deadline,
        ) != source_digest:
            raise ValueError("bundle status database changed during read")
        _require_bundle_status_time(deadline)
        os.unlink(snapshot_path)
        snapshot_path = None
        _require_bundle_status_time(deadline)
        _verify_authority_snapshot(parent_fd, identity)
        if (
            _exact_file_metadata(os.fstat(database_fd)) != database_metadata
            or _exact_file_metadata(
                os.stat(identity[0], dir_fd=parent_fd, follow_symlinks=False)
            ) != entry_metadata
        ):
            raise ValueError("bundle status database metadata changed")
        _require_bundle_status_time(deadline)
    except Exception:
        failed = True
    finally:
        for cleanup in (
            (lambda: _close_bundle_status_store(store) if store is not None else None),
            (lambda: os.unlink(snapshot_path) if snapshot_path is not None else None),
            (
                lambda: _verify_authority_snapshot(parent_fd, identity)
                if parent_fd is not None and database_fd is not None and identity is not None else None
            ),
            (lambda: os.close(database_fd) if database_fd is not None else None),
            (lambda: os.close(parent_fd) if parent_fd is not None else None),
        ):
            try:
                cleanup()
            except Exception:
                failed = True
        if time.monotonic() > deadline:
            failed = True
    if failed:
        raise ProvisioningBundleError("BUNDLE_STATUS_UNAVAILABLE")
    if semantic_error is not None:
        raise ProvisioningBundleError(semantic_error)
    if result is None:
        raise ProvisioningBundleError("BUNDLE_STATUS_UNAVAILABLE")
    return result


def _validate_stage_inputs(
    intent: ProvisioningIntentV1,
    expected_preview: ProvisioningPreviewDigests,
) -> None:
    if type(intent) is not ProvisioningIntentV1 or set(vars(intent)) != INTENT_FIELDS:
        raise ValueError("exact typed provisioning intent is required")
    if type(expected_preview) is not ProvisioningPreviewDigests or set(vars(expected_preview)) != {
        field.name for field in fields(ProvisioningPreviewDigests)
    }:
        raise ValueError("exact expected preview digests are required")


def _stage_authoritative_bundle_with_dependencies(
    store_path: str,
    intent: ProvisioningIntentV1,
    dependencies: _PreflightDependencies,
    expected_preview: ProvisioningPreviewDigests,
) -> Mapping[str, object]:
    """Rebuild and atomically stage exactly one caller-previewed typed intent."""
    _validate_stage_inputs(intent, expected_preview)
    if type(dependencies) is not _PreflightDependencies or set(vars(dependencies)) != {
        field.name for field in fields(_PreflightDependencies)
    }:
        raise ValueError("exact typed preflight dependencies are required")
    bundle = _build_provisioning_bundle_with_dependencies(store_path, intent, dependencies)
    if (
        bundle.plan.plan_digest != expected_preview.plan_digest
        or bundle.preflight.report_digest != expected_preview.preflight_digest
        or bundle.bundle_digest != expected_preview.bundle_digest
    ):
        raise ValueError("PREVIEW_MISMATCH")
    _validate_staged_bundle(bundle)
    serialized_bundle = dump_provisioning_bundle(bundle)
    binding_draft = binding_draft_for_bundle(bundle)
    _recheck_current_root_authority(store_path, bundle)
    with SQLiteStore(store_path) as store:
        source_persisted = False

        def save_source_and_bundle() -> None:
            nonlocal source_persisted
            save_staged_plan_source(store, bundle.plan)
            store.save_provisioning_preflight_report(
                bundle.preflight.report_id,
                bundle.plan.plan_id,
                bundle.preflight.report_digest,
                _dump_preflight_report(bundle.preflight),
            )
            store.save_provisioning_bundle(
                bundle.intent.plan_id,
                bundle.plan.plan_id,
                bundle.bundle_digest,
                serialized_bundle,
            )
            for entry in bundle.outbox:
                store.save_provisioning_review_outbox(
                    entry.id,
                    entry.plan_id,
                    entry.owner_domain.value,
                    entry.state,
                    _dump_review_outbox_entry(entry),
                )
            source_persisted = True

        binding = stage_bound_roadex_approval(
            store,
            binding_draft,
            save_source_and_bundle,
            validate_locked=lambda: _recheck_locked_authority_and_chain(store, bundle),
            verify_bound=lambda candidate: verify_exact_persisted_bundle_set(
                store, bundle, candidate,
            ),
        )
    return _public_bundle_status(bundle, binding, mutation=source_persisted)


def stage_authoritative_bundle(
    store_path: str,
    intent: ProvisioningIntentV1,
    expected_preview: ProvisioningPreviewDigests,
) -> Mapping[str, object]:
    """Rebuild and atomically stage through the server-owned trust boundary."""
    _validate_stage_inputs(intent, expected_preview)
    return _stage_authoritative_bundle_with_dependencies(
        store_path,
        intent,
        production_preflight_dependencies(store_path),
        expected_preview,
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
    "INTENT_FIELDS", "REQUIRED_PREFLIGHT_CODES", "PreflightCheck",
    "ProvisioningBundleError", "ProvisioningBundleV1", "ProvisioningIntentV1",
    "ProvisioningPreviewDigests",
    "ProvisioningPreflightReport", "ProvisioningReviewOutboxEntry", "build_provisioning_bundle",
    "binding_draft_for_bundle", "dump_provisioning_bundle", "load_provisioning_bundle",
    "bundle_status", "preflight_bundle_api", "stage_authoritative_bundle", "stage_bundle_api",
    "verify_exact_persisted_bundle_set",
    "bundle_digest", "canonical_bundle_bytes", "canonical_bundle_payload", "canonical_digest",
    "canonical_root_target_digest", "changed_immutable_inputs", "parse_provisioning_intent",
    "run_provisioning_preflight",
]
