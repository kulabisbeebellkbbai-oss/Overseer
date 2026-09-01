"""Atomic predecessor-release and successor-activation transitions."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import sys
from typing import Iterator

from .audit import ApprovalStatus, AuditEvent, AuditEventType
from .claim_continuation import (
    ClaimActivationGroup,
    ClaimActivationGroupState,
    ClaimApprovalContinuation,
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


@contextmanager
def _psychlo_writer(path: str | Path) -> Iterator[sqlite3.Connection]:
    psychlo_path = Path(path)
    if not psychlo_path.is_file():
        raise ValueError("trusted Psychlo lifecycle database is unavailable")
    try:
        connection = sqlite3.connect(psychlo_path, timeout=10.0)
    except sqlite3.Error as error:
        raise ValueError("trusted Psychlo lifecycle database is unavailable") from error
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
    except Exception:
        connection.rollback()
        raise
    else:
        connection.rollback()
    finally:
        connection.close()


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
    except BaseException:
        error = sys.exc_info()
        if psychlo_entered and psychlo_context is not None:
            psychlo_context.__exit__(*error)
        raise
    else:
        if psychlo_entered and psychlo_context is not None:
            psychlo_context.__exit__(None, None, None)


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
) -> tuple[Claim, Claim, Resource, Resource, OwnerDomain, ApprovalStatus, ClaimApprovalContinuation]:
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
        approval.subject_id != successor_claim_id
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
        attempt.continuation_id != continuation_id
        or attempt.owner_thread != expected_owner_thread
        or attempt.state != ContinuationState.DELIVERED
    ):
        raise ValueError("successor approval continuation delivery is invalid")
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
    predecessor_claim_id: str,
    successor_claim_id: str,
    approval_id: str,
    expected_resource_id: str,
    expected_owner_role: OwnerDomain,
    expected_continuation: ClaimApprovalContinuation,
    release_group_id: str | None,
    successor_group_id: str,
    release_audit_id: str,
    transition_audit_id: str,
    evidence_ids: tuple[str, ...],
) -> None:
    predecessor = store.load_claim(predecessor_claim_id)
    successor = store.load_claim(successor_claim_id)
    predecessor_resource = store.load_resource(predecessor.resource_id)
    successor_resource = store.load_resource(expected_resource_id)
    if (
        predecessor.status != ClaimStatus.RELEASED
        or predecessor_resource.current_claim_id is not None
        or predecessor_resource.owner_domain != expected_owner_role
        or successor.status != ClaimStatus.ACTIVE
        or successor.approval_id != approval_id
        or successor_resource.current_claim_id != successor_claim_id
        or successor_resource.owner_domain != expected_owner_role
    ):
        raise ValueError("claim transition postcondition failed")
    successor_continuations = tuple(
        continuation
        for continuation in store.list_claim_approval_continuations()
        if continuation.claim_id == successor_claim_id
    )
    if successor_continuations != (expected_continuation,):
        raise ValueError("successor continuation postcondition failed")
    if not expected_continuation.attempt_id:
        raise ValueError("successor continuation delivery postcondition failed")
    attempt = store.load_claim_approval_continuation_attempt(expected_continuation.attempt_id)
    if (
        attempt.continuation_id != expected_continuation.id
        or attempt.owner_thread != expected_continuation.owner_thread
        or attempt.state != ContinuationState.DELIVERED
    ):
        raise ValueError("successor continuation delivery postcondition failed")
    if release_group_id is not None:
        if store.load_claim_activation_group(release_group_id).state != ClaimActivationGroupState.RELEASED:
            raise ValueError("predecessor group transition postcondition failed")
        if store.load_claim_activation_group(successor_group_id).state != ClaimActivationGroupState.ACTIVE:
            raise ValueError("successor group transition postcondition failed")
    events = {event.id: event for event in store.list_audit_events()}
    for event_id, event_type, subject_id in (
        (release_audit_id, AuditEventType.RELEASED, predecessor_claim_id),
        (transition_audit_id, AuditEventType.EXECUTED, successor_claim_id),
    ):
        event = events.get(event_id)
        if event is None or event.event_type != event_type or event.subject_id != subject_id:
            raise ValueError("claim transition audit postcondition failed")
        if not set(evidence_ids).issubset(event.evidence_ids):
            raise ValueError("claim transition audit evidence postcondition failed")


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
    store = SQLiteStore(store_path)
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
                    AuditEvent(
                        id=release_audit_id,
                        event_type=AuditEventType.RELEASED,
                        owner_domain=owner_role,
                        subject_id=predecessor_claim_id,
                        summary=f"released predecessor for atomic claim transition by {transitioned_by}",
                        risk_level=predecessor.risk_level,
                        evidence_ids=bound_evidence,
                        occurred_at=transitioned_at,
                    )
                )
                store.save_audit_event(
                    AuditEvent(
                        id=transition_audit_id,
                        event_type=AuditEventType.EXECUTED,
                        owner_domain=owner_role,
                        subject_id=successor_claim_id,
                        summary=f"activated successor for atomic claim transition by {transitioned_by}",
                        risk_level=successor.risk_level,
                        evidence_ids=bound_evidence,
                        occurred_at=transitioned_at,
                    )
                )
                _verify_transition(
                    store,
                    predecessor_claim_id=predecessor_claim_id,
                    successor_claim_id=successor_claim_id,
                    approval_id=approval_id,
                    expected_resource_id=expected_resource_id,
                    expected_owner_role=owner_role,
                    expected_continuation=continuation,
                    release_group_id=group_pair[0].id if group_pair is not None else None,
                    successor_group_id=expected_activation_group_id,
                    release_audit_id=release_audit_id,
                    transition_audit_id=transition_audit_id,
                    evidence_ids=bound_evidence,
                )
        return {
            "status": "transitioned",
            "predecessor_claim_id": predecessor_claim_id,
            "successor_claim_id": successor_claim_id,
            "approval_id": approval_id,
            "transitioned_at": transitioned_at,
            "audit_event_ids": [release_audit_id, transition_audit_id],
        }
    finally:
        store.close()
