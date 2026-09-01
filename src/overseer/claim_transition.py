"""Atomic predecessor-release and successor-activation transitions."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import sqlite3
import sys
from typing import Iterable, Iterator

from .audit import ApprovalRequest, ApprovalStatus, AuditEvent, AuditEventType
from .claim_continuation import (
    ClaimActivationGroup,
    ClaimActivationGroupState,
    ClaimApprovalContinuation,
    ClaimApprovalContinuationAttempt,
    ContinuationState,
    TRUSTED_PSYCHLO_STORE,
    _validate_psychlo_round,
)
from .core import (
    ApprovalLevel,
    Claim,
    ClaimStatus,
    ConflictOutcome,
    OwnerDomain,
    Resource,
    ResourceState,
    decide_claim,
)
from .store import SQLiteStore


def _require_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    return value


CLAIM_TRANSITION_RECORD_SET_EVIDENCE_PREFIX = (
    "overseer.claim-transition-record-set-sha256.v1:"
)
RECORD_SET_EVIDENCE_PREFIX = CLAIM_TRANSITION_RECORD_SET_EVIDENCE_PREFIX
_RECORD_SET_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_RECORD_SET_TABLES = (
    "claims",
    "resources",
    "claims",
    "resources",
    "approvals",
    "claim_approval_continuations",
    "claim_approval_continuation_attempts",
)


@dataclass(frozen=True)
class _TransitionPostconditions:
    predecessor: Claim
    successor: Claim
    predecessor_resource: Resource
    successor_resource: Resource
    approval: ApprovalRequest
    continuation: ClaimApprovalContinuation
    attempt: ClaimApprovalContinuationAttempt
    predecessor_group_id: str
    predecessor_group: ClaimActivationGroup | None
    successor_group_id: str
    successor_group: ClaimActivationGroup | None
    release_audit: AuditEvent
    transition_audit: AuditEvent


def canonical_claim_transition_record_set_digest(
    record_hashes: Iterable[tuple[str, str, str]],
) -> str:
    """Return the package-safe digest for ordered record IDs and payload hashes.

    Callers provide only SQLite table names, record IDs, and SHA-256 hashes of
    the raw canonical payloads.  The payloads themselves never enter this
    return value or any transition evidence.
    """
    entries = []
    for table, record_id, payload_sha256 in record_hashes:
        if (
            not isinstance(table, str)
            or not table
            or not isinstance(record_id, str)
            or not record_id
            or not isinstance(payload_sha256, str)
            or _RECORD_SET_SHA256_RE.fullmatch(payload_sha256) is None
        ):
            raise ValueError("claim transition record-set entry is invalid")
        entries.append(
            {
                "id": record_id,
                "payloadSha256": payload_sha256,
                "table": table,
            }
        )
    if len(entries) != len(_RECORD_SET_TABLES) or tuple(
        entry["table"] for entry in entries
    ) != _RECORD_SET_TABLES:
        raise ValueError("claim transition record-set shape is invalid")
    canonical = json.dumps(
        {"records": entries, "version": 1},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def claim_transition_record_set_digest(
    store: SQLiteStore,
    *,
    predecessor_claim_id: str,
    predecessor_resource_id: str,
    successor_claim_id: str,
    successor_resource_id: str,
    approval_id: str,
    continuation_id: str,
    attempt_id: str,
) -> str:
    """Hash the exact seven raw SQLite payloads required by a transition.

    This helper is intentionally suitable for package validation: it exposes
    only the stable record IDs and one-way payload hashes, never payload text.
    """
    record_ids = (
        predecessor_claim_id,
        predecessor_resource_id,
        successor_claim_id,
        successor_resource_id,
        approval_id,
        continuation_id,
        attempt_id,
    )
    entries: list[tuple[str, str, str]] = []
    for table, record_id in zip(_RECORD_SET_TABLES, record_ids):
        row = store._connection.execute(
            f"SELECT id, payload FROM {table} WHERE id = ?",
            (record_id,),
        ).fetchone()
        if row is None or str(row["id"]) != record_id:
            raise ValueError("claim transition record set is incomplete")
        payload = row["payload"]
        if not isinstance(payload, str):
            raise ValueError("claim transition record payload is invalid")
        entries.append(
            (
                table,
                record_id,
                hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            )
        )
    return canonical_claim_transition_record_set_digest(entries)


class _PsychloConnection(sqlite3.Connection):
    """SQLite connection retaining the descriptor identity validator."""


def _descriptor_binding(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
    )


def _validate_psychlo_parent_info(
    info: os.stat_result,
    label: str,
    *,
    allow_sticky_shared: bool = False,
) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {os.geteuid(), 0}
        or (
            stat.S_IMODE(info.st_mode) & 0o022
            and not (allow_sticky_shared and stat.S_IMODE(info.st_mode) & stat.S_ISVTX)
        )
        or info.st_nlink < 2
    ):
        raise ValueError(f"{label} is not a trusted directory")


def _validate_psychlo_file_info(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_nlink != 1
    ):
        raise ValueError(f"{label} is not a trusted single-link regular file")


def _open_psychlo_parent(path: Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("trusted Psychlo lifecycle database path is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(os.sep, flags)
    try:
        _validate_psychlo_parent_info(
            os.fstat(descriptor),
            "trusted Psychlo lifecycle database parent",
            allow_sticky_shared=True,
        )
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            _validate_psychlo_parent_info(
                os.fstat(descriptor),
                "trusted Psychlo lifecycle database parent",
                allow_sticky_shared=True,
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _psychlo_revalidate(connection: sqlite3.Connection) -> None:
    validator = getattr(connection, "_overseer_revalidate", None)
    if not callable(validator):
        raise ValueError("trusted Psychlo lifecycle database identity is unavailable")
    validator()


@contextmanager
def _psychlo_writer(path: str | Path) -> Iterator[sqlite3.Connection]:
    psychlo_path = Path(path)
    if not psychlo_path.is_absolute() or not psychlo_path.name:
        raise ValueError("trusted Psychlo lifecycle database is unavailable")
    parent_fd = -1
    file_fd = -1
    file_locked = False
    connection: sqlite3.Connection | None = None
    parent_info: os.stat_result | None = None
    file_info: os.stat_result | None = None
    try:
        parent_fd = _open_psychlo_parent(psychlo_path.parent)
        parent_info = os.fstat(parent_fd)
        _validate_psychlo_parent_info(
            parent_info,
            "trusted Psychlo lifecycle database parent",
        )
        lexical_parent = os.stat(psychlo_path.parent, follow_symlinks=False)
        if _descriptor_binding(parent_info) != _descriptor_binding(lexical_parent):
            raise ValueError("trusted Psychlo lifecycle database parent was replaced")
        entry_info = os.stat(
            psychlo_path.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        _validate_psychlo_file_info(
            entry_info,
            "trusted Psychlo lifecycle database",
        )
        file_fd = os.open(
            psychlo_path.name,
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        file_info = os.fstat(file_fd)
        _validate_psychlo_file_info(
            file_info,
            "trusted Psychlo lifecycle database",
        )
        if _descriptor_binding(file_info) != _descriptor_binding(entry_info):
            raise ValueError("trusted Psychlo lifecycle database was replaced")

        def revalidate() -> None:
            assert parent_info is not None
            assert file_info is not None
            current_parent = os.fstat(parent_fd)
            lexical_parent_now = os.stat(
                psychlo_path.parent,
                follow_symlinks=False,
            )
            if (
                _descriptor_binding(current_parent) != _descriptor_binding(parent_info)
                or _descriptor_binding(lexical_parent_now) != _descriptor_binding(parent_info)
            ):
                raise ValueError("trusted Psychlo lifecycle database parent changed")
            current_entry = os.stat(
                psychlo_path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            opened_file = os.fstat(file_fd)
            _validate_psychlo_file_info(
                current_entry,
                "trusted Psychlo lifecycle database",
            )
            _validate_psychlo_file_info(
                opened_file,
                "trusted Psychlo lifecycle database",
            )
            if (
                _descriptor_binding(current_entry) != _descriptor_binding(file_info)
                or _descriptor_binding(opened_file) != _descriptor_binding(file_info)
            ):
                raise ValueError("trusted Psychlo lifecycle database changed or was replaced")

        fcntl.flock(file_fd, fcntl.LOCK_EX)
        file_locked = True
        connection = sqlite3.connect(
            f"/proc/self/fd/{file_fd}",
            timeout=10.0,
            factory=_PsychloConnection,
        )
        connection._overseer_revalidate = revalidate
        connection.execute("BEGIN IMMEDIATE")
        revalidate()
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.rollback()
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            try:
                if file_locked:
                    fcntl.flock(file_fd, fcntl.LOCK_UN)
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
                if parent_fd >= 0:
                    os.close(parent_fd)


def _raw_group_lock_required(
    store: SQLiteStore,
    predecessor_claim_id: str,
    successor_group_id: str,
) -> bool:
    """Select the lock order only; this raw probe is not record validation."""
    predecessor_group_id = None
    row = store._connection.execute(
        "SELECT payload FROM claims WHERE id = ?",
        (predecessor_claim_id,),
    ).fetchone()
    if row is not None:
        try:
            payload = json.loads(str(row["payload"]))
        except (TypeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            candidate = payload.get("activation_group_id")
            if isinstance(candidate, str) and candidate:
                predecessor_group_id = candidate

    group_ids = tuple(
        dict.fromkeys(
            group_id
            for group_id in (predecessor_group_id, successor_group_id)
            if isinstance(group_id, str) and group_id
        )
    )
    if not group_ids:
        return False
    placeholders = ", ".join("?" for _ in group_ids)
    return (
        store._connection.execute(
            f"SELECT 1 FROM claim_activation_groups WHERE id IN ({placeholders}) LIMIT 1",
            group_ids,
        ).fetchone()
        is not None
    )


@contextmanager
def _transition_transaction(
    store: SQLiteStore,
    predecessor_claim_id: str,
    successor_group_id: str,
    psychlo_store_path: str | Path,
) -> Iterator[tuple[bool, sqlite3.Connection | None]]:
    """Keep an optional Psychlo writer lock through the Overseer commit."""
    initial_grouped = _raw_group_lock_required(
        store,
        predecessor_claim_id,
        successor_group_id,
    )

    def exact_group_presence_under_writer_lock() -> tuple[bool, bool]:
        predecessor = store.load_claim(predecessor_claim_id)
        predecessor_group_id = predecessor.activation_group_id
        predecessor_present = False
        if predecessor_group_id:
            try:
                store.load_claim_activation_group(predecessor_group_id)
            except KeyError:
                pass
            else:
                predecessor_present = True
        try:
            store.load_claim_activation_group(successor_group_id)
        except KeyError:
            successor_present = False
        else:
            successor_present = True
        return predecessor_present, successor_present

    psychlo_context = None
    psychlo_entered = False
    try:
        psychlo_connection = None
        if initial_grouped:
            psychlo_context = _psychlo_writer(psychlo_store_path)
            psychlo_connection = psychlo_context.__enter__()
            psychlo_entered = True
        with store.agent_transaction():
            predecessor_present, successor_present = exact_group_presence_under_writer_lock()
            if initial_grouped:
                if not (predecessor_present and successor_present):
                    raise ValueError("claim transition requires both exact activation groups")
            elif predecessor_present or successor_present:
                raise ValueError("claim activation groups appeared during transition setup")
            yield initial_grouped, psychlo_connection
            if psychlo_connection is not None:
                _psychlo_revalidate(psychlo_connection)
    except BaseException:
        error = sys.exc_info()
        if psychlo_entered and psychlo_context is not None:
            try:
                psychlo_context.__exit__(*error)
            except BaseException:
                pass
        raise
    else:
        if psychlo_entered and psychlo_context is not None:
            try:
                psychlo_context.__exit__(None, None, None)
            except BaseException:
                pass


def _validate_group(
    group: ClaimActivationGroup,
    *,
    group_id: str,
    lifecycle_id: str,
    owner_thread: str,
    owner_role: OwnerDomain,
    claim_id: str,
    approval_id: str,
    resource_id: str,
    state: ClaimActivationGroupState,
) -> None:
    if (
        group.id != group_id
        or group.lifecycle_id != lifecycle_id
        or group.owner_thread != owner_thread
        or group.owner_role != owner_role
        or group.claim_ids != (claim_id,)
        or group.approval_ids != (approval_id,)
        or group.resource_ids != (resource_id,)
        or group.state != state
    ):
        raise ValueError("claim activation group binding is invalid")


def _validate_optional_groups(
    store: SQLiteStore,
    *,
    predecessor: Claim,
    successor: Claim,
    approval_id: str,
    expected_predecessor_resource_id: str,
    expected_predecessor_activation_group_id: str,
    expected_predecessor_lifecycle_id: str,
    expected_resource_id: str,
    expected_owner_thread: str,
    owner_role: OwnerDomain,
    expected_activation_group_id: str,
    expected_lifecycle_id: str,
    psychlo_store_path: str | Path,
    psychlo_connection: sqlite3.Connection,
) -> tuple[ClaimActivationGroup, ClaimActivationGroup]:
    if not predecessor.activation_group_id or not predecessor.approval_id:
        raise ValueError("predecessor group binding is incomplete")
    predecessor_group = store.load_claim_activation_group(expected_predecessor_activation_group_id)
    successor_group = store.load_claim_activation_group(expected_activation_group_id)
    _validate_group(
        predecessor_group,
        group_id=expected_predecessor_activation_group_id,
        lifecycle_id=expected_predecessor_lifecycle_id,
        owner_thread=expected_owner_thread,
        owner_role=owner_role,
        claim_id=predecessor.id,
        approval_id=predecessor.approval_id,
        resource_id=expected_predecessor_resource_id,
        state=ClaimActivationGroupState.ACTIVE,
    )
    _validate_group(
        successor_group,
        group_id=expected_activation_group_id,
        lifecycle_id=expected_lifecycle_id,
        owner_thread=expected_owner_thread,
        owner_role=owner_role,
        claim_id=successor.id,
        approval_id=approval_id,
        resource_id=expected_resource_id,
        state=ClaimActivationGroupState.REQUESTED,
    )
    if (
        predecessor_group.project_id,
        predecessor_group.plan_id,
        predecessor_group.plan_version,
    ) != (
        successor_group.project_id,
        successor_group.plan_id,
        successor_group.plan_version,
    ):
        raise ValueError("claim activation group plan bindings do not match")
    _validate_psychlo_round(
        psychlo_store_path,
        lifecycle_id=predecessor_group.lifecycle_id,
        project_id=predecessor_group.project_id,
        plan_id=predecessor_group.plan_id,
        plan_version=predecessor_group.plan_version,
        owner_thread=predecessor_group.owner_thread,
        _connection=psychlo_connection,
    )
    _validate_psychlo_round(
        psychlo_store_path,
        lifecycle_id=successor_group.lifecycle_id,
        project_id=successor_group.project_id,
        plan_id=successor_group.plan_id,
        plan_version=successor_group.plan_version,
        owner_thread=successor_group.owner_thread,
        _connection=psychlo_connection,
    )
    return predecessor_group, successor_group


def _validate_conflicts(
    store: SQLiteStore,
    *,
    successor: Claim,
    successor_resource: Resource,
    predecessor_claim_id: str,
) -> None:
    claims = store.list_claims()
    resources = {resource.id: resource for resource in store.list_resources()}
    active_claims = [
        claim
        for claim in claims
        if claim.id != predecessor_claim_id and claim.is_active_like()
    ]
    canonical_decision = decide_claim(
        successor_resource,
        successor,
        active_claims,
        resources,
    )
    stored_decision = store.load_decision(successor.id)
    for decision in (canonical_decision, stored_decision):
        if (
            decision.outcome != ConflictOutcome.ESCALATE
            or decision.approval_level != ApprovalLevel.ROLE
            or decision.blocking_claim_ids
        ):
            raise ValueError("successor claim does not have exact ROLE transition authority")
    for active_claim in active_claims:
        if successor.exclusive_groups & active_claim.exclusive_groups:
            raise ValueError("successor claim has an external claim exclusive-group conflict")
        active_resource = resources.get(active_claim.resource_id)
        if (
            active_resource is not None
            and successor_resource.exclusive_groups & active_resource.exclusive_groups
        ):
            raise ValueError("successor resource has an external exclusive-group conflict")


def _validate_inputs(
    store: SQLiteStore,
    *,
    predecessor_claim_id: str,
    successor_claim_id: str,
    approval_id: str,
    expected_predecessor_resource_id: str,
    expected_predecessor_activation_group_id: str,
    expected_predecessor_lifecycle_id: str,
    expected_resource_id: str,
    expected_owner_thread: str,
    expected_owner_role: str,
    expected_activation_group_id: str,
    expected_lifecycle_id: str,
    plan_digest: str,
    evidence_ids: tuple[str, ...],
) -> tuple[
    Claim,
    Claim,
    Resource,
    Resource,
    OwnerDomain,
    ApprovalStatus,
    ClaimApprovalContinuation,
    ApprovalRequest,
    ClaimApprovalContinuationAttempt,
]:
    for value, name in (
        (predecessor_claim_id, "predecessor_claim_id"),
        (successor_claim_id, "successor_claim_id"),
        (approval_id, "approval_id"),
        (expected_predecessor_resource_id, "expected_predecessor_resource_id"),
        (expected_predecessor_activation_group_id, "expected_predecessor_activation_group_id"),
        (expected_predecessor_lifecycle_id, "expected_predecessor_lifecycle_id"),
        (expected_resource_id, "expected_resource_id"),
        (expected_owner_thread, "expected_owner_thread"),
        (expected_owner_role, "expected_owner_role"),
        (expected_activation_group_id, "expected_activation_group_id"),
        (expected_lifecycle_id, "expected_lifecycle_id"),
        (plan_digest, "plan_digest"),
    ):
        _require_text(value, name)
    if predecessor_claim_id == successor_claim_id:
        raise ValueError("predecessor and successor claims must differ")
    if not evidence_ids or not all(isinstance(item, str) and item.strip() for item in evidence_ids):
        raise ValueError("release evidence is required")
    try:
        owner_role = OwnerDomain(expected_owner_role)
    except ValueError as error:
        raise ValueError("expected_owner_role is invalid") from error

    predecessor = store.load_claim(predecessor_claim_id)
    successor = store.load_claim(successor_claim_id)
    if predecessor.status != ClaimStatus.ACTIVE:
        raise ValueError("predecessor claim is not active")
    if successor.status != ClaimStatus.REQUESTED:
        raise ValueError("successor claim is not requested")
    if predecessor.resource_id == successor.resource_id:
        raise ValueError("predecessor and successor resources must differ")
    if (
        predecessor.owner_thread != expected_owner_thread
        or predecessor.owner_role != owner_role
        or predecessor.resource_id != expected_predecessor_resource_id
        or predecessor.activation_group_id != expected_predecessor_activation_group_id
        or predecessor.lifecycle_id != expected_predecessor_lifecycle_id
        or successor.owner_thread != expected_owner_thread
        or successor.owner_role != owner_role
        or successor.activation_group_id != expected_activation_group_id
        or successor.lifecycle_id != expected_lifecycle_id
    ):
        raise ValueError("claim binding is invalid")
    if successor.resource_id != expected_resource_id:
        raise ValueError("successor resource binding is invalid")

    predecessor_resource = store.load_resource(predecessor.resource_id)
    successor_resource = store.load_resource(expected_resource_id)
    if (
        predecessor_resource.owner_domain != owner_role
        or successor_resource.owner_domain != owner_role
    ):
        raise ValueError("claim resource owner binding is invalid")
    if predecessor_resource.current_claim_id != predecessor_claim_id:
        raise ValueError("predecessor resource pointer is not active")
    if successor_resource.current_claim_id is not None:
        raise ValueError("successor resource is already claimed")
    if successor_resource.state != ResourceState.AVAILABLE:
        raise ValueError("successor resource is unavailable")
    if successor_resource.identifiers.get("planDigest") != plan_digest:
        raise ValueError("successor resource plan digest does not match")

    approval = store.load_approval(approval_id)
    if (
        approval.id != approval_id
        or approval.subject_id != successor_claim_id
        or approval.requester_thread != expected_owner_thread
        or approval.owner_domain != owner_role
        or approval.approval_level != ApprovalLevel.ROLE
        or approval.status != ApprovalStatus.APPROVED
        or approval.decided_by != expected_owner_role
        or not approval.decided_at
    ):
        raise ValueError("successor approval binding is invalid")

    continuation_id = f"continuation.{approval_id}"
    successor_continuations = tuple(
        continuation
        for continuation in store.list_claim_approval_continuations()
        if continuation.claim_id == successor_claim_id
    )
    if len(successor_continuations) != 1:
        raise ValueError("successor must have exactly one approval continuation")
    continuation = successor_continuations[0]
    if (
        continuation.id != continuation_id
        or continuation.claim_id != successor_claim_id
        or continuation.approval_id != approval_id
        or continuation.resource_id != expected_resource_id
        or continuation.owner_thread != expected_owner_thread
        or continuation.owner_role != owner_role
        or continuation.activation_group_id != expected_activation_group_id
        or continuation.lifecycle_id != expected_lifecycle_id
        or continuation.state != ContinuationState.DELIVERED
        or not continuation.attempt_id
    ):
        raise ValueError("successor approval continuation binding is invalid")
    attempt = store.load_claim_approval_continuation_attempt(continuation.attempt_id)
    if (
        attempt.id != continuation.attempt_id
        or attempt.continuation_id != continuation_id
        or attempt.owner_thread != expected_owner_thread
        or attempt.state != ContinuationState.DELIVERED
        or not attempt.attempted_at
        or attempt.result_status != "prompt_dispatched"
        or not attempt.result_reason
    ):
        raise ValueError("successor approval continuation delivery is invalid")
    record_set_digest = claim_transition_record_set_digest(
        store,
        predecessor_claim_id=predecessor_claim_id,
        predecessor_resource_id=predecessor_resource.id,
        successor_claim_id=successor_claim_id,
        successor_resource_id=successor_resource.id,
        approval_id=approval_id,
        continuation_id=continuation.id,
        attempt_id=attempt.id,
    )
    record_set_evidence = tuple(
        item
        for item in evidence_ids
        if item.startswith(CLAIM_TRANSITION_RECORD_SET_EVIDENCE_PREFIX)
    )
    if len(record_set_evidence) != 1:
        raise ValueError("claim transition requires exactly one record-set evidence ID")
    evidence_digest = record_set_evidence[0][
        len(CLAIM_TRANSITION_RECORD_SET_EVIDENCE_PREFIX) :
    ]
    if _RECORD_SET_SHA256_RE.fullmatch(evidence_digest) is None:
        raise ValueError("claim transition record-set evidence ID is malformed")
    if not hmac.compare_digest(evidence_digest, record_set_digest):
        raise ValueError("claim transition record-set evidence does not match live records")
    _validate_conflicts(
        store,
        successor=successor,
        successor_resource=successor_resource,
        predecessor_claim_id=predecessor_claim_id,
    )
    return (
        predecessor,
        successor,
        predecessor_resource,
        successor_resource,
        owner_role,
        approval.status,
        continuation,
        approval,
        attempt,
    )


def _event_evidence(
    *,
    predecessor: Claim,
    successor: Claim,
    predecessor_resource: Resource,
    successor_resource: Resource,
    approval_id: str,
    continuation: ClaimApprovalContinuation,
    expected_predecessor_resource_id: str,
    expected_predecessor_activation_group_id: str,
    expected_predecessor_lifecycle_id: str,
    expected_owner_thread: str,
    expected_owner_role: str,
    expected_activation_group_id: str,
    expected_lifecycle_id: str,
    plan_digest: str,
    evidence_ids: tuple[str, ...],
    transitioned_by: str,
    transitioned_at: str,
) -> tuple[str, ...]:
    values = (
        predecessor.id,
        successor.id,
        predecessor_resource.id,
        successor_resource.id,
        approval_id,
        continuation.id,
        expected_predecessor_resource_id,
        expected_predecessor_activation_group_id,
        expected_predecessor_lifecycle_id,
        expected_owner_thread,
        expected_owner_role,
        expected_activation_group_id,
        expected_lifecycle_id,
        plan_digest,
        transitioned_by,
        transitioned_at,
        *evidence_ids,
    )
    return tuple(dict.fromkeys(values))


def _verify_transition(
    store: SQLiteStore,
    *,
    postconditions: _TransitionPostconditions,
    require_no_transaction: bool = False,
) -> None:
    if require_no_transaction and store._connection.in_transaction:
        raise ValueError("claim transition postconditions are not committed")

    predecessor = store.load_claim(postconditions.predecessor.id)
    successor = store.load_claim(postconditions.successor.id)
    predecessor_resource = store.load_resource(postconditions.predecessor_resource.id)
    successor_resource = store.load_resource(postconditions.successor_resource.id)
    if (
        predecessor != postconditions.predecessor
        or successor != postconditions.successor
        or predecessor_resource != postconditions.predecessor_resource
        or successor_resource != postconditions.successor_resource
    ):
        raise ValueError("claim transition postcondition failed")

    approval = store.load_approval(postconditions.approval.id)
    if approval != postconditions.approval:
        raise ValueError("successor approval postcondition failed")

    successor_continuations = tuple(
        continuation
        for continuation in store.list_claim_approval_continuations()
        if continuation.claim_id == postconditions.successor.id
    )
    if successor_continuations != (postconditions.continuation,):
        raise ValueError("successor continuation postcondition failed")
    if not postconditions.continuation.attempt_id:
        raise ValueError("successor continuation delivery postcondition failed")
    attempt = store.load_claim_approval_continuation_attempt(
        postconditions.continuation.attempt_id
    )
    if attempt != postconditions.attempt:
        raise ValueError("successor continuation delivery postcondition failed")

    groups = {
        group.id: group for group in store.list_claim_activation_groups()
    }
    for group_id, expected_group, failure in (
        (
            postconditions.predecessor_group_id,
            postconditions.predecessor_group,
            "predecessor group transition postcondition failed",
        ),
        (
            postconditions.successor_group_id,
            postconditions.successor_group,
            "successor group transition postcondition failed",
        ),
    ):
        if groups.get(group_id) != expected_group:
            raise ValueError(failure)

    events = {event.id: event for event in store.list_audit_events()}
    for event_id, expected_event, failure in (
        (
            postconditions.release_audit.id,
            postconditions.release_audit,
            "claim transition audit postcondition failed",
        ),
        (
            postconditions.transition_audit.id,
            postconditions.transition_audit,
            "claim transition audit postcondition failed",
        ),
    ):
        event = events.get(event_id)
        if event != expected_event:
            raise ValueError(failure)


def _recognize_committed_transition(
    store: SQLiteStore,
    postconditions: _TransitionPostconditions | None,
) -> bool:
    """Recognize only a complete transition visible outside a transaction."""
    if postconditions is None:
        return False
    try:
        _verify_transition(
            store,
            postconditions=postconditions,
            require_no_transaction=True,
        )
        store.verify_strict_path_binding()
    except (KeyError, OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return False
    return True


def transition_claim_status(
    store_path: str | Path,
    predecessor_claim_id: str,
    successor_claim_id: str,
    approval_id: str,
    expected_predecessor_resource_id: str,
    expected_predecessor_activation_group_id: str,
    expected_predecessor_lifecycle_id: str,
    expected_resource_id: str,
    expected_owner_thread: str,
    expected_owner_role: str,
    expected_activation_group_id: str,
    expected_lifecycle_id: str,
    plan_digest: str,
    transitioned_by: str,
    evidence_ids: tuple[str, ...],
    transitioned_at: str,
    *,
    _psychlo_store_path: str | Path | None = None,
) -> dict[str, object]:
    """Atomically release one active claim and activate its exact successor."""
    _require_text(transitioned_by, "transitioned_by")
    _require_text(transitioned_at, "transitioned_at")
    release_audit_id = f"audit.claim-transition.{successor_claim_id}.predecessor-released"
    transition_audit_id = f"audit.claim-transition.{successor_claim_id}.executed"
    result = {
        "status": "transitioned",
        "predecessor_claim_id": predecessor_claim_id,
        "successor_claim_id": successor_claim_id,
        "approval_id": approval_id,
        "transitioned_at": transitioned_at,
        "audit_event_ids": [release_audit_id, transition_audit_id],
    }
    store = SQLiteStore(store_path, strict_descriptor_binding=True)
    postconditions: _TransitionPostconditions | None = None
    committed = False
    try:
        psychlo_store_path = _psychlo_store_path or TRUSTED_PSYCHLO_STORE
        with _transition_transaction(
            store,
            predecessor_claim_id,
            expected_activation_group_id,
            psychlo_store_path,
        ) as (groups, psychlo_connection):
                (
                    predecessor,
                    successor,
                    predecessor_resource,
                    successor_resource,
                    owner_role,
                    _approval_status,
                    continuation,
                    approval,
                    attempt,
                ) = _validate_inputs(
                    store,
                    predecessor_claim_id=predecessor_claim_id,
                    successor_claim_id=successor_claim_id,
                    approval_id=approval_id,
                    expected_predecessor_resource_id=expected_predecessor_resource_id,
                    expected_predecessor_activation_group_id=expected_predecessor_activation_group_id,
                    expected_predecessor_lifecycle_id=expected_predecessor_lifecycle_id,
                    expected_resource_id=expected_resource_id,
                    expected_owner_thread=expected_owner_thread,
                    expected_owner_role=expected_owner_role,
                    expected_activation_group_id=expected_activation_group_id,
                    expected_lifecycle_id=expected_lifecycle_id,
                    plan_digest=plan_digest,
                    evidence_ids=evidence_ids,
                )
                if bool(groups) != (psychlo_connection is not None):
                    raise ValueError("claim activation group lock state is invalid")
                group_pair = None
                if psychlo_connection is not None:
                    group_pair = _validate_optional_groups(
                        store,
                        predecessor=predecessor,
                        successor=successor,
                        approval_id=approval_id,
                        expected_predecessor_resource_id=expected_predecessor_resource_id,
                        expected_predecessor_activation_group_id=expected_predecessor_activation_group_id,
                        expected_predecessor_lifecycle_id=expected_predecessor_lifecycle_id,
                        expected_resource_id=expected_resource_id,
                        expected_owner_thread=expected_owner_thread,
                        owner_role=owner_role,
                        expected_activation_group_id=expected_activation_group_id,
                        expected_lifecycle_id=expected_lifecycle_id,
                        psychlo_store_path=psychlo_store_path,
                        psychlo_connection=psychlo_connection,
                    )
                collision = store._connection.execute(
                    "SELECT 1 FROM audit_events WHERE id IN (?, ?) LIMIT 1",
                    (release_audit_id, transition_audit_id),
                ).fetchone()
                if collision is not None:
                    raise ValueError("deterministic claim transition audit ID already exists")

                released_predecessor = replace(predecessor, status=ClaimStatus.RELEASED)
                active_successor = replace(
                    successor,
                    status=ClaimStatus.ACTIVE,
                    approval_id=approval_id,
                )
                released_predecessor_resource = replace(predecessor_resource, current_claim_id=None)
                active_successor_resource = replace(successor_resource, current_claim_id=successor_claim_id)
                bound_evidence = _event_evidence(
                    predecessor=predecessor,
                    successor=successor,
                    predecessor_resource=predecessor_resource,
                    successor_resource=successor_resource,
                    approval_id=approval_id,
                    continuation=continuation,
                    expected_predecessor_resource_id=expected_predecessor_resource_id,
                    expected_predecessor_activation_group_id=expected_predecessor_activation_group_id,
                    expected_predecessor_lifecycle_id=expected_predecessor_lifecycle_id,
                    expected_owner_thread=expected_owner_thread,
                    expected_owner_role=expected_owner_role,
                    expected_activation_group_id=expected_activation_group_id,
                    expected_lifecycle_id=expected_lifecycle_id,
                    plan_digest=plan_digest,
                    evidence_ids=evidence_ids,
                    transitioned_by=transitioned_by,
                    transitioned_at=transitioned_at,
                )
                release_audit = AuditEvent(
                    id=release_audit_id,
                    event_type=AuditEventType.RELEASED,
                    owner_domain=owner_role,
                    subject_id=predecessor_claim_id,
                    summary=f"released predecessor for atomic claim transition by {transitioned_by}",
                    risk_level=predecessor.risk_level,
                    evidence_ids=bound_evidence,
                    occurred_at=transitioned_at,
                )
                transition_audit = AuditEvent(
                    id=transition_audit_id,
                    event_type=AuditEventType.EXECUTED,
                    owner_domain=owner_role,
                    subject_id=successor_claim_id,
                    summary=f"activated successor for atomic claim transition by {transitioned_by}",
                    risk_level=successor.risk_level,
                    evidence_ids=bound_evidence,
                    occurred_at=transitioned_at,
                )
                postconditions = _TransitionPostconditions(
                    predecessor=released_predecessor,
                    successor=active_successor,
                    predecessor_resource=released_predecessor_resource,
                    successor_resource=active_successor_resource,
                    approval=approval,
                    continuation=continuation,
                    attempt=attempt,
                    predecessor_group_id=expected_predecessor_activation_group_id,
                    predecessor_group=(
                        replace(
                            group_pair[0],
                            state=ClaimActivationGroupState.RELEASED,
                        )
                        if group_pair is not None
                        else None
                    ),
                    successor_group_id=expected_activation_group_id,
                    successor_group=(
                        replace(
                            group_pair[1],
                            state=ClaimActivationGroupState.ACTIVE,
                        )
                        if group_pair is not None
                        else None
                    ),
                    release_audit=release_audit,
                    transition_audit=transition_audit,
                )
                store.save_claim(released_predecessor, store.load_decision(predecessor_claim_id))
                store.save_resource(released_predecessor_resource)
                store.save_claim(active_successor, store.load_decision(successor_claim_id))
                store.save_resource(active_successor_resource)
                if group_pair is not None:
                    predecessor_group, successor_group = group_pair
                    store.save_claim_activation_group(
                        replace(predecessor_group, state=ClaimActivationGroupState.RELEASED)
                    )
                    store.save_claim_activation_group(
                        replace(successor_group, state=ClaimActivationGroupState.ACTIVE)
                    )
                store.save_audit_event(
                    release_audit
                )
                store.save_audit_event(
                    transition_audit
                )
                _verify_transition(
                    store,
                    postconditions=postconditions,
                )
        if postconditions is None:
            raise ValueError("claim transition postconditions are unavailable")
        _verify_transition(
            store,
            postconditions=postconditions,
            require_no_transaction=True,
        )
        store.verify_strict_path_binding()
        committed = True
        return result
    except Exception:
        if _recognize_committed_transition(store, postconditions):
            committed = True
            return result
        raise
    finally:
        try:
            store.close()
        except Exception:
            if not committed:
                raise
            store.verify_strict_path_binding()
