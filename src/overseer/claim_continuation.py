"""Durable, exact-owner continuations for approved resource claims.

Approval is deliberately separate from activation.  This module only records
the owner-thread continuation and its delivery attempt; it never changes the
claim or resource state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
import json
from pathlib import Path
import sqlite3
from typing import Any, Protocol

from .audit import ApprovalStatus, AuditEvent, AuditEventType
from .core import (
    ApprovalLevel,
    Claim,
    EXCLUSIVE_CLAIM_TYPES,
    ClaimStatus,
    ConflictOutcome,
    OwnerDomain,
    Resource,
    RiskLevel,
    ResourceState,
    decide_claim,
)


TRUSTED_PSYCHLO_STORE = Path("/home/god/Documents/Codex Workspace/Psychlo/data/psychlo.sqlite3")


class ClaimActivationGroupState(StrEnum):
    REQUESTED = "requested"
    ACTIVE = "active"
    RELEASED = "released"


@dataclass(frozen=True)
class ClaimActivationGroup:
    """Immutable membership and authority binding for a paired claim set."""

    id: str
    lifecycle_id: str
    project_id: str
    plan_id: str
    plan_version: str
    owner_thread: str
    owner_role: OwnerDomain
    claim_ids: tuple[str, ...]
    approval_ids: tuple[str, ...]
    resource_ids: tuple[str, ...]
    state: ClaimActivationGroupState = ClaimActivationGroupState.REQUESTED
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.id, self.lifecycle_id, self.project_id, self.plan_id, self.plan_version, self.owner_thread)):
            raise ValueError("claim activation group requires identity, lifecycle, project, plan, version, and owner thread")
        if not self.claim_ids or len(self.claim_ids) != len(self.approval_ids) or len(self.claim_ids) != len(self.resource_ids):
            raise ValueError("claim activation group claim, approval, and resource memberships must align")
        if len(set(self.claim_ids)) != len(self.claim_ids):
            raise ValueError("claim activation group claim IDs must be unique")
        if len(set(self.approval_ids)) != len(self.approval_ids):
            raise ValueError("claim activation group approval IDs must be unique")


class ContinuationState(StrEnum):
    PENDING = "pending"
    ATTEMPTING = "attempting"
    DELIVERED = "delivered"
    UNKNOWN = "unknown"
    RECONCILIATION_REQUIRED = "reconciliation_required"


@dataclass(frozen=True)
class ClaimApprovalContinuation:
    id: str
    claim_id: str
    approval_id: str
    resource_id: str
    owner_thread: str
    owner_role: OwnerDomain
    activation_group_id: str
    lifecycle_id: str
    state: ContinuationState = ContinuationState.PENDING
    attempt_id: str | None = None


@dataclass(frozen=True)
class ClaimApprovalContinuationAttempt:
    id: str
    continuation_id: str
    owner_thread: str
    state: ContinuationState
    attempted_at: str
    result_status: str | None = None
    result_reason: str | None = None

    @property
    def status(self) -> ContinuationState:
        return self.state


class PromptAdapter(Protocol):
    def dispatch_prompt(self, owner_thread: str, prompt: str) -> Any: ...


def _validate_psychlo_round(
    db_path: str | Path,
    *,
    lifecycle_id: str,
    project_id: str,
    plan_id: str,
    plan_version: str,
    owner_thread: str,
    _connection: sqlite3.Connection | None = None,
) -> None:
    """Validate a claim lifecycle against the authoritative Psychlo DB.

    This is intentionally a read-only lookup.  A claim group cannot be
    persisted for an opaque, terminal, or cross-plan round.  Tests may pass a
    temporary database through the private in-process seam; production callers
    use ``TRUSTED_PSYCHLO_STORE`` through the CLI/API wrappers.
    """
    path = Path(db_path)
    if not path.is_file():
        raise ValueError("trusted Psychlo lifecycle database is unavailable")
    connection = _connection
    owns_connection = connection is None
    if connection is None:
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        except sqlite3.Error as error:
            raise ValueError("trusted Psychlo lifecycle database is unavailable") from error
    try:
        row = connection.execute(
            """
            SELECT r.id, r.project_id, r.state, r.request_json,
                   p.plan_id, p.plan_version
              FROM rounds AS r
              JOIN projects AS p ON p.id = r.project_id
             WHERE r.id = ?
            """,
            (lifecycle_id,),
        ).fetchone()
    except sqlite3.Error as error:
        raise ValueError("trusted Psychlo lifecycle database is invalid") from error
    finally:
        if owns_connection and connection is not None:
            connection.close()
    if row is None:
        raise ValueError("claim activation lifecycle does not reference an exact Psychlo round")
    round_id, stored_project_id, state, request_json, stored_plan_id, stored_plan_version = row
    if state != "active":
        raise ValueError("claim activation lifecycle round is not active")
    if (stored_project_id, stored_plan_id, stored_plan_version) != (project_id, plan_id, plan_version):
        raise ValueError("claim activation lifecycle does not match the trusted project plan")
    try:
        request = json.loads(request_json)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("claim activation lifecycle round request is invalid") from error
    if not isinstance(request, dict):
        raise ValueError("claim activation lifecycle round request is invalid")
    expected = {
        "roundId": lifecycle_id,
        "projectId": project_id,
        "planId": plan_id,
        "planVersion": plan_version,
        "threadId": owner_thread,
    }
    if any(request.get(key) != value for key, value in expected.items()):
        raise ValueError("claim activation lifecycle round request binding is invalid")


def continuation_for_claim(claim: Claim, approval_id: str) -> ClaimApprovalContinuation:
    """Build the deterministic outbox identity for one exact ROLE approval."""
    if not claim.owner_thread.strip():
        raise ValueError("claim approval continuation requires an exact owner thread")
    if not claim.activation_group_id or not claim.lifecycle_id:
        raise ValueError("claim approval continuation requires explicit lifecycle and activation group bindings")
    return ClaimApprovalContinuation(
        id=f"continuation.{approval_id}",
        claim_id=claim.id,
        approval_id=approval_id,
        resource_id=claim.resource_id,
        owner_thread=claim.owner_thread,
        owner_role=claim.owner_role,
        activation_group_id=claim.activation_group_id,
        lifecycle_id=claim.lifecycle_id,
    )


def continuation_prompt(continuation: ClaimApprovalContinuation) -> str:
    return (
        f"ROLE approval {continuation.approval_id} for claim {continuation.claim_id} "
        f"on resource {continuation.resource_id} is approved. Activation remains "
        f"a separate explicit step for lifecycle {continuation.lifecycle_id} "
        f"and activation group {continuation.activation_group_id}."
    )


def dispatch_claim_approval_continuations_status(
    store_path: str,
    continuation_id: str,
    *,
    adapter: PromptAdapter | None = None,
    dispatched_by: str = "overseer",
    dispatched_at: str | None = None,
) -> dict[str, object]:
    """Dispatch exactly one continuation by its immutable ID.

    The attempt is committed before calling the external adapter.  Any
    exception or identity mismatch therefore leaves a durable reconciliation
    state rather than claiming delivery or retrying blindly.
    """
    from .codex_projects import CodexProjectThreadAdapter
    from .store import SQLiteStore

    if not continuation_id.strip():
        raise ValueError("continuation_id is required")
    now = dispatched_at or datetime.now(UTC).replace(microsecond=0).isoformat()
    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            continuation = store.load_claim_approval_continuation(continuation_id)
            claim = store.load_claim(continuation.claim_id)
            approval = store.load_approval(continuation.approval_id)
            _validate_binding(continuation, claim, approval)
            if continuation.state == ContinuationState.DELIVERED:
                return continuation_status(continuation, dispatched_by=dispatched_by)
            if continuation.state != ContinuationState.PENDING:
                raise ValueError("continuation delivery requires reconciliation before retry")

            attempt_id = f"{continuation.id}.attempt.{_status_id(now)}"
            attempt = ClaimApprovalContinuationAttempt(
                id=attempt_id,
                continuation_id=continuation.id,
                owner_thread=continuation.owner_thread,
                state=ContinuationState.ATTEMPTING,
                attempted_at=now,
            )
            attempting = replace(
                continuation,
                state=ContinuationState.ATTEMPTING,
                attempt_id=attempt.id,
            )
            store.save_claim_approval_continuation_attempt(attempt)
            store.save_claim_approval_continuation(attempting)
            store.save_audit_event(_continuation_audit(
                continuation,
                claim,
                AuditEventType.REQUESTED,
                f"exact-owner continuation dispatch attempt {attempt.id} persisted before send",
                (attempt.id, continuation.approval_id),
                now,
            ))
    finally:
        store.close()

    selected_adapter = adapter or CodexProjectThreadAdapter()
    try:
        dispatch = getattr(selected_adapter, "dispatch_prompt_exact", None)
        if dispatch is None:
            raise ValueError("continuation adapter must implement dispatch_prompt_exact")
        result = dispatch(
            continuation.owner_thread,
            continuation_prompt(continuation),
        )
        _validate_delivery_result(result, continuation.owner_thread)
    except Exception as error:
        _finish_attempt(
            store_path,
            continuation,
            attempt,
            ContinuationState.RECONCILIATION_REQUIRED,
            result_status="unknown",
            result_reason=str(error),
        )
        return continuation_status(
            replace(continuation, state=ContinuationState.RECONCILIATION_REQUIRED, attempt_id=attempt.id),
            dispatched_by=dispatched_by,
            reason=str(error),
        )

    delivered = replace(continuation, state=ContinuationState.DELIVERED, attempt_id=attempt.id)
    _finish_attempt(
        store_path,
        continuation,
        attempt,
        ContinuationState.DELIVERED,
        result_status=str(getattr(result, "status", "delivered")),
        result_reason=str(getattr(result, "reason", "delivered")),
        final=delivered,
    )
    return continuation_status(delivered, dispatched_by=dispatched_by)


def dispatch_claim_approval_continuation_status(*args: Any, **kwargs: Any) -> dict[str, object]:
    """Compatibility wrapper for the original singular API name."""
    return dispatch_claim_approval_continuations_status(*args, **kwargs)


def _validate_binding(continuation: ClaimApprovalContinuation, claim: Claim, approval: Any) -> None:
    if continuation.id != f"continuation.{approval.id}":
        raise ValueError("continuation identity is invalid")
    if continuation.claim_id != claim.id or continuation.resource_id != claim.resource_id:
        raise ValueError("continuation claim or resource binding is invalid")
    if continuation.owner_thread != claim.owner_thread:
        raise ValueError("continuation owner thread binding is invalid")
    if continuation.owner_role != claim.owner_role:
        raise ValueError("continuation owner role binding is invalid")
    if approval.id != continuation.approval_id or approval.subject_id != claim.id:
        raise ValueError("continuation approval binding is invalid")
    if approval.approval_level != ApprovalLevel.ROLE:
        raise ValueError("continuation requires an approved ROLE approval")
    if approval.owner_domain != claim.owner_role:
        raise ValueError("continuation approval owner does not match claim owner")
    if approval.status.value != "approved":
        raise ValueError("continuation approval is not approved")
    if claim.status != ClaimStatus.REQUESTED:
        raise ValueError("continuation requires the still-requested claim")


def _validate_delivery_result(result: Any, owner_thread: str) -> None:
    returned_thread = getattr(result, "owner_thread", None)
    status = getattr(result, "status", None)
    if returned_thread != owner_thread:
        raise ValueError("dispatch returned a different owner thread")
    resume_result = getattr(result, "resume_result", None)
    conversation_id = getattr(result, "conversation_id", None)
    if resume_result is not None:
        conversation_id = getattr(resume_result, "conversation_id", None)
    if conversation_id is None:
        raise ValueError("dispatch delivery proof is missing the exact conversation identity")
    if conversation_id is not None and conversation_id != owner_thread:
        raise ValueError("dispatch returned a different conversation identity")
    if status not in {"prompt_dispatched", "delivered"}:
        raise ValueError("dispatch delivery is not confirmed")


def _finish_attempt(
    store_path: str,
    continuation: ClaimApprovalContinuation,
    attempt: ClaimApprovalContinuationAttempt,
    state: ContinuationState,
    *,
    result_status: str,
    result_reason: str,
    final: ClaimApprovalContinuation | None = None,
) -> None:
    from .store import SQLiteStore

    updated_attempt = replace(
        attempt,
        state=state,
        result_status=result_status,
        result_reason=result_reason,
    )
    store = SQLiteStore(store_path)
    try:
        claim = store.load_claim(continuation.claim_id)
        with store.agent_transaction():
            store.save_claim_approval_continuation_attempt(updated_attempt)
            updated = final or replace(continuation, state=state, attempt_id=attempt.id)
            store.save_claim_approval_continuation(updated)
            store.save_audit_event(_continuation_audit(
                updated,
                claim,
                AuditEventType.EXECUTED if state == ContinuationState.DELIVERED else AuditEventType.ALERT,
                f"exact-owner continuation delivery state is {state.value}",
                (attempt.id,),
                attempt.attempted_at,
            ))
    finally:
        store.close()


def continuation_status(
    continuation: ClaimApprovalContinuation,
    *,
    dispatched_by: str | None = None,
    reason: str | None = None,
) -> dict[str, object]:
    return {
        "id": continuation.id,
        "claim_id": continuation.claim_id,
        "approval_id": continuation.approval_id,
        "resource_id": continuation.resource_id,
        "owner_thread": continuation.owner_thread,
        "owner_role": continuation.owner_role.value,
        "activation_group_id": continuation.activation_group_id,
        "lifecycle_id": continuation.lifecycle_id,
        "state": continuation.state.value,
        "status": continuation.state.value,
        "attempt_id": continuation.attempt_id,
        "dispatched_by": dispatched_by,
        "reason": reason,
    }


def register_claim_activation_group_status(
    store_path: str,
    group_id: str,
    lifecycle_id: str,
    project_id: str,
    plan_id: str,
    plan_version: str,
    owner_thread: str,
    owner_role: str,
    claim_ids: tuple[str, ...] | list[str],
    approval_ids: tuple[str, ...] | list[str],
    resource_ids: tuple[str, ...] | list[str],
    *,
    _psychlo_store_path: str | Path | None = None,
) -> dict[str, object]:
    """Register an exact group before its claims are requested.

    Registration is deliberately separate from claim request and approval. It
    creates no claim, approval, listener, or resource reservation.
    """
    from .store import SQLiteStore

    group = ClaimActivationGroup(
        id=str(group_id),
        lifecycle_id=str(lifecycle_id),
        project_id=str(project_id),
        plan_id=str(plan_id),
        plan_version=str(plan_version),
        owner_thread=str(owner_thread),
        owner_role=OwnerDomain(owner_role),
        claim_ids=tuple(str(item) for item in claim_ids),
        approval_ids=tuple(str(item) for item in approval_ids),
        resource_ids=tuple(str(item) for item in resource_ids),
    )
    # A lifecycle identifier is only meaningful when it is an exact active
    # Psychlo round.  The private override is an in-process test seam; the
    # public CLI/API parsers do not expose it and always use the trusted path.
    # Check an existing identity first so a conflicting retry reports the
    # immutable-record conflict rather than leaking a misleading round error.
    probe = SQLiteStore(store_path)
    try:
        try:
            existing = probe.load_claim_activation_group(group.id)
        except KeyError:
            existing = None
        if existing is not None:
            immutable_fields = (
                "id", "lifecycle_id", "project_id", "plan_id", "plan_version",
                "owner_thread", "owner_role", "claim_ids", "approval_ids", "resource_ids",
            )
            if any(getattr(existing, field) != getattr(group, field) for field in immutable_fields):
                raise ValueError("claim activation group registration conflicts with existing identity")
    finally:
        probe.close()
    _validate_psychlo_round(
        _psychlo_store_path or TRUSTED_PSYCHLO_STORE,
        lifecycle_id=group.lifecycle_id,
        project_id=group.project_id,
        plan_id=group.plan_id,
        plan_version=group.plan_version,
        owner_thread=group.owner_thread,
    )
    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            try:
                existing = store.load_claim_activation_group(group.id)
            except KeyError:
                store.save_claim_activation_group(group)
                existing = group
            else:
                immutable_fields = (
                    "id", "lifecycle_id", "project_id", "plan_id", "plan_version",
                    "owner_thread", "owner_role",
                    "claim_ids", "approval_ids", "resource_ids",
                )
                if any(getattr(existing, field) != getattr(group, field) for field in immutable_fields):
                    raise ValueError("claim activation group registration conflicts with existing identity")
            return {
                "group": existing.id,
                "group_id": existing.id,
                "group_status": existing.state.value,
                "state": existing.state.value,
                "lifecycle_id": existing.lifecycle_id,
                "project_id": existing.project_id,
                "plan_id": existing.plan_id,
                "plan_version": existing.plan_version,
                "owner_thread": existing.owner_thread,
                "owner_role": existing.owner_role.value,
                "claim_ids": list(existing.claim_ids),
                "approval_ids": list(existing.approval_ids),
                "resource_ids": list(existing.resource_ids),
                "idempotent": existing is not group,
            }
    finally:
        store.close()


def claim_group_status(
    store_path: str,
    group_id: str,
    *,
    _psychlo_store_path: str | Path | None = None,
) -> dict[str, object]:
    """Return the authoritative, read-only status of one claim group."""
    from .store import SQLiteStore

    store = SQLiteStore(store_path)
    try:
        group = store.load_claim_activation_group(group_id)
        claim_by_id = {claim.id: claim for claim in store.list_claims()}
        approval_by_id = {approval.id: approval for approval in store.list_approvals()}
        resource_by_id = {resource.id: resource for resource in store.list_resources()}
        continuations = {item.claim_id: item for item in store.list_claim_approval_continuations()}
        diagnostics: list[str] = []
        lifecycle_valid = True
        if group.state != ClaimActivationGroupState.RELEASED:
            try:
                _validate_psychlo_round(
                    _psychlo_store_path or TRUSTED_PSYCHLO_STORE,
                    lifecycle_id=group.lifecycle_id,
                    project_id=group.project_id,
                    plan_id=group.plan_id,
                    plan_version=group.plan_version,
                    owner_thread=group.owner_thread,
                )
            except ValueError as error:
                lifecycle_valid = False
                diagnostics.append(f"lifecycle validation failed: {error}")
        claims: list[Claim] = []
        approvals: list[Any] = []
        resources: list[Resource] = []
        exact_bindings = True
        for claim_id, approval_id, resource_id in zip(group.claim_ids, group.approval_ids, group.resource_ids):
            claim = claim_by_id.get(claim_id)
            approval = approval_by_id.get(approval_id)
            resource = resource_by_id.get(resource_id)
            if claim is None:
                diagnostics.append(f"missing claim {claim_id}")
                exact_bindings = False
            else:
                claims.append(claim)
                if claim.activation_group_id != group.id or claim.lifecycle_id != group.lifecycle_id:
                    diagnostics.append(f"claim {claim_id} lifecycle/group binding mismatch")
                    exact_bindings = False
                if claim.owner_thread != group.owner_thread or claim.owner_role != group.owner_role:
                    diagnostics.append(f"claim {claim_id} owner binding mismatch")
                    exact_bindings = False
                if claim.resource_id != resource_id:
                    diagnostics.append(f"claim {claim_id} resource binding mismatch")
                    exact_bindings = False
            if approval is None:
                diagnostics.append(f"missing approval {approval_id}")
                exact_bindings = False
            else:
                approvals.append(approval)
                if claim is not None and approval.subject_id != claim.id:
                    diagnostics.append(f"approval {approval_id} subject mismatch")
                    exact_bindings = False
                if approval.owner_domain != group.owner_role:
                    diagnostics.append(f"approval {approval_id} owner binding mismatch")
                    exact_bindings = False
                if approval.status != ApprovalStatus.APPROVED:
                    diagnostics.append(f"approval {approval_id} is {approval.status.value}")
            if resource is None:
                diagnostics.append(f"missing resource {resource_id}")
            else:
                resources.append(resource)
                if resource.owner_domain != group.owner_role or (claim is not None and resource.owner_domain != claim.owner_role):
                    diagnostics.append(f"resource {resource_id} owner binding mismatch")
                    exact_bindings = False
            if claim is not None and claim.claim_type not in EXCLUSIVE_CLAIM_TYPES:
                diagnostics.append(f"claim {claim_id} is not an allowed exclusive claim type")
                exact_bindings = False
            continuation = continuations.get(claim_id)
            if continuation is None:
                diagnostics.append(f"missing continuation for {claim_id}")
                exact_bindings = False
            elif (
                continuation.approval_id != approval_id
                or continuation.resource_id != resource_id
                or continuation.owner_thread != group.owner_thread
                or continuation.owner_role != group.owner_role
                or continuation.activation_group_id != group.id
                or continuation.lifecycle_id != group.lifecycle_id
            ):
                diagnostics.append(f"continuation binding mismatch for {claim_id}")
                exact_bindings = False
        resource_by_group = {resource.id: resource for resource in resources}
        all_approved = len(approvals) == len(group.approval_ids) and all(
            approval.status == ApprovalStatus.APPROVED and approval.approval_level == ApprovalLevel.ROLE
            for approval in approvals
        )
        all_requested = len(claims) == len(group.claim_ids) and all(claim.status == ClaimStatus.REQUESTED for claim in claims)
        all_active = len(claims) == len(group.claim_ids) and all(
            claim.status == ClaimStatus.ACTIVE
            and (
                not claim.is_exclusive()
                or (
                    resource_by_group.get(claim.resource_id) is not None
                    and resource_by_group[claim.resource_id].current_claim_id == claim.id
                )
            )
            for claim in claims
        )
        all_released = len(claims) == len(group.claim_ids) and all(
            claim.status == ClaimStatus.RELEASED for claim in claims
        ) and len(resources) == len(group.resource_ids) and all(resource.current_claim_id is None for resource in resources)
        if group.state == ClaimActivationGroupState.ACTIVE and not (lifecycle_valid and exact_bindings and all_approved and all_active):
            diagnostics.append("stored active group is not fully active and structurally bound")
            effective_state = "invalid"
        elif group.state == ClaimActivationGroupState.REQUESTED and not lifecycle_valid:
            effective_state = "invalid"
        elif group.state == ClaimActivationGroupState.RELEASED and not (exact_bindings and all_released):
            diagnostics.append("stored released group is not fully released")
            effective_state = "invalid"
        else:
            effective_state = group.state.value
        return {
            **_claim_group_status(group, tuple(claims), tuple(resources)),
            "group_status": effective_state,
            "state": effective_state,
            "ready_for_activation": bool(group.state == ClaimActivationGroupState.REQUESTED and lifecycle_valid and exact_bindings and all_approved and all_requested and not diagnostics),
            "diagnostics": diagnostics,
            "approvals": [{"id": approval.id, "status": approval.status.value, "subject_id": approval.subject_id} for approval in approvals],
            "continuations": [{"claim_id": item.claim_id, "approval_id": item.approval_id, "state": item.state.value} for item in continuations.values() if item.claim_id in group.claim_ids],
        }
    finally:
        store.close()


create_claim_activation_group_status = register_claim_activation_group_status


def activate_claim_group_status(
    store_path: str,
    group_id: str,
    *,
    _psychlo_store_path: str | Path | None = None,
) -> dict[str, object]:
    """Atomically activate every claim in a structurally bound group."""
    return _activate_claim_group_status(store_path, group_id, _psychlo_store_path=_psychlo_store_path)


def _activate_claim_group_status(
    store_path: str,
    group_id: str,
    *,
    _psychlo_store_path: str | Path | None = None,
) -> dict[str, object]:
    """Implementation seam; production callers use the fixed Psychlo path.

    Lock order is deliberately Psychlo (writer lock) then Overseer (writer
    transaction).  This keeps a lifecycle transition from committing between
    validation and claim activation.  Release does not acquire this lock so
    cleanup remains possible after a round terminates.
    """
    from .store import SQLiteStore

    authority_path = Path(_psychlo_store_path or TRUSTED_PSYCHLO_STORE)
    try:
        psychlo = sqlite3.connect(f"file:{authority_path}?mode=rw", uri=True, timeout=5.0)
        psychlo.execute("BEGIN IMMEDIATE")
    except sqlite3.Error as error:
        raise ValueError("trusted Psychlo lifecycle database is unavailable") from error
    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            group, claims, approvals, resources = _load_group_bundle(store, group_id)
            _validate_psychlo_round(
                authority_path,
                lifecycle_id=group.lifecycle_id,
                project_id=group.project_id,
                plan_id=group.plan_id,
                plan_version=group.plan_version,
                owner_thread=group.owner_thread,
                _connection=psychlo,
            )
            _validate_group_bindings(store, group, claims, approvals, resources)
            claim_states = {claim.status for claim in claims}
            resource_claims = {resource.id: resource.current_claim_id for resource in resources}
            if group.state == ClaimActivationGroupState.ACTIVE:
                if claim_states != {ClaimStatus.ACTIVE} or any(
                    claim.status != ClaimStatus.ACTIVE or resource_claims[claim.resource_id] != claim.id
                    for claim in claims
                ):
                    raise ValueError("claim activation group has a partial active state")
                return _claim_group_status(
                    group,
                    claims,
                    resources,
                    idempotent=True,
                    audit_event=f"audit.claim-group.{group.id}.executed",
                )
            if group.state != ClaimActivationGroupState.REQUESTED:
                raise ValueError("claim activation group is not requested")
            if claim_states != {ClaimStatus.REQUESTED}:
                raise ValueError("claim activation group claims must all be requested")
            _preflight_group_conflicts(claims, resources, store.list_claims(), store.list_resources())
            activated_claims = tuple(
                replace(claim, status=ClaimStatus.ACTIVE, approval_id=approval_id)
                for claim, approval_id in zip(claims, group.approval_ids)
            )
            activated_group = replace(group, state=ClaimActivationGroupState.ACTIVE)
            for claim in activated_claims:
                store.save_claim(claim)
            for claim, resource in zip(activated_claims, resources):
                if claim.is_exclusive():
                    store.save_resource(replace(resource, current_claim_id=claim.id))
            store.save_claim_activation_group(activated_group)
            event = _group_audit_event(
                activated_group,
                claims,
                AuditEventType.EXECUTED,
                f"claim activation group {group.id} activated atomically",
                (),
            )
            store.save_audit_event(event)
            return _claim_group_status(activated_group, activated_claims, resources, audit_event=event.id)
    finally:
        store.close()
        psychlo.rollback()
        psychlo.close()


def release_claim_group_status(
    store_path: str,
    group_id: str,
    evidence_ids: tuple[str, ...] | list[str],
) -> dict[str, object]:
    """Atomically release every active claim in a group with cleanup evidence."""
    from .store import SQLiteStore

    normalized_evidence = tuple(str(item).strip() for item in evidence_ids if str(item).strip())
    if not normalized_evidence:
        raise ValueError("claim group release requires evidence")
    store = SQLiteStore(store_path)
    try:
        with store.agent_transaction():
            group, claims, approvals, resources = _load_group_bundle(store, group_id)
            _validate_group_bindings(store, group, claims, approvals, resources, allow_released=True)
            if group.state == ClaimActivationGroupState.RELEASED:
                if all(claim.status == ClaimStatus.RELEASED for claim in claims) and all(
                    resource.current_claim_id is None for resource in resources
                ):
                    return _claim_group_status(group, claims, resources, idempotent=True)
                raise ValueError("claim activation group has a partial released state")
            if group.state != ClaimActivationGroupState.ACTIVE or any(
                claim.status != ClaimStatus.ACTIVE for claim in claims
            ):
                raise ValueError("claim activation group must be wholly active before release")
            for claim, resource in zip(claims, resources):
                # Every group member is exclusive; do not let a tampered
                # claim_type bypass the exact resource ownership check.
                if resource.current_claim_id != claim.id:
                    raise ValueError(
                        f"resource {resource.id} current claim does not match paired claim {claim.id}"
                    )
            released_claims = tuple(replace(claim, status=ClaimStatus.RELEASED) for claim in claims)
            released_group = replace(
                group,
                state=ClaimActivationGroupState.RELEASED,
                evidence_ids=normalized_evidence,
            )
            for claim in released_claims:
                store.save_claim(claim)
            for resource in resources:
                store.save_resource(replace(resource, current_claim_id=None))
            store.save_claim_activation_group(released_group)
            event = _group_audit_event(
                released_group,
                claims,
                AuditEventType.RELEASED,
                f"claim activation group {group.id} released atomically",
                normalized_evidence,
            )
            store.save_audit_event(event)
            released_resources = tuple(replace(resource, current_claim_id=None) for resource in resources)
            status = _claim_group_status(released_group, released_claims, released_resources, audit_event=event.id)
            status["release_evidence_complete"] = True
            return status
    finally:
        store.close()


def _load_group_bundle(store: Any, group_id: str) -> tuple[ClaimActivationGroup, tuple[Claim, ...], tuple[Any, ...], tuple[Resource, ...]]:
    if not group_id.strip():
        raise ValueError("group_id is required")
    group = store.load_claim_activation_group(group_id)
    try:
        claims = tuple(store.load_claim(claim_id) for claim_id in group.claim_ids)
        approvals = tuple(store.load_approval(approval_id) for approval_id in group.approval_ids)
        resources = tuple(store.load_resource(resource_id) for resource_id in group.resource_ids)
    except KeyError as error:
        raise ValueError(f"claim activation group references missing record: {error.args[0]}") from error
    return group, claims, approvals, resources


def _validate_group_bindings(
    store: Any,
    group: ClaimActivationGroup,
    claims: tuple[Claim, ...],
    approvals: tuple[Any, ...],
    resources: tuple[Resource, ...],
    *,
    allow_released: bool = False,
) -> None:
    if len(claims) != len(group.claim_ids) or len(approvals) != len(group.approval_ids) or len(resources) != len(group.resource_ids):
        raise ValueError("claim activation group membership is incomplete")
    for claim, approval_id, resource_id, approval in zip(claims, group.approval_ids, group.resource_ids, approvals):
        if claim.activation_group_id != group.id or claim.lifecycle_id != group.lifecycle_id:
            raise ValueError("claim activation group lifecycle binding is invalid")
        if claim.owner_thread != group.owner_thread or claim.owner_role != group.owner_role:
            raise ValueError("claim activation group owner binding is invalid")
        if claim.resource_id != resource_id:
            raise ValueError("claim activation group resource binding is invalid")
        if claim.claim_type not in EXCLUSIVE_CLAIM_TYPES:
            raise ValueError("claim activation group requires an allowed exclusive claim type")
        resource = next((item for item in resources if item.id == resource_id), None)
        if resource is None:
            raise ValueError("claim activation group resource binding is invalid")
        if resource.owner_domain != group.owner_role or resource.owner_domain != claim.owner_role:
            raise ValueError("claim activation group resource owner binding is invalid")
        if approval.id != approval_id or approval.subject_id != claim.id:
            raise ValueError("claim activation group approval binding is invalid")
        if approval.approval_level != ApprovalLevel.ROLE or not approval.can_execute():
            raise ValueError("claim activation group requires approved ROLE approvals")
        continuations = tuple(item for item in store.list_claim_approval_continuations() if item.claim_id == claim.id)
        if len(continuations) != 1:
            raise ValueError("claim activation group requires its exact approval continuation")
        continuation = continuations[0]
        if continuation.approval_id != approval.id or continuation.resource_id != claim.resource_id:
            raise ValueError("claim activation group requires its exact approval continuation")
        if continuation.owner_thread != group.owner_thread or continuation.owner_role != group.owner_role:
            raise ValueError("claim activation group continuation owner binding is invalid")
        if continuation.activation_group_id != group.id or continuation.lifecycle_id != group.lifecycle_id:
            raise ValueError("claim activation group continuation binding is invalid")
    if not allow_released and group.state == ClaimActivationGroupState.RELEASED:
        raise ValueError("claim activation group is released")


def _preflight_group_conflicts(
    claims: tuple[Claim, ...],
    resources: tuple[Resource, ...],
    all_claims: tuple[Claim, ...],
    all_resources: tuple[Resource, ...],
) -> None:
    resources_by_id = {resource.id: resource for resource in all_resources}
    group_ids = {claim.id for claim in claims}
    external_active = [
        claim for claim in all_claims
        if claim.id not in group_ids and claim.is_active_like()
    ]
    for claim, resource in zip(claims, resources):
        if resource.current_claim_id and resource.current_claim_id not in group_ids:
            raise ValueError(f"resource {resource.id} has an external current claim")
        decision = decide_claim(
            resource,
            claim,
            [replace(other, status=ClaimStatus.ACTIVE) for other in (*external_active, *claims) if other.id != claim.id],
            resources_by_id,
        )
        if decision.outcome in {ConflictOutcome.QUEUE, ConflictOutcome.BLOCK, ConflictOutcome.QUARANTINE}:
            raise ValueError(f"claim activation group conflict for {claim.id}: {decision.reason}")
        if resource.state in {ResourceState.RETIRED, ResourceState.QUARANTINED}:
            raise ValueError(f"claim activation group resource {resource.id} is unavailable")


def _claim_group_status(
    group: ClaimActivationGroup,
    claims: tuple[Claim, ...],
    resources: tuple[Resource, ...],
    *,
    idempotent: bool = False,
    audit_event: str | None = None,
) -> dict[str, object]:
    return {
        "group": group.id,
        "group_id": group.id,
        "group_status": group.state.value,
        "state": group.state.value,
        "lifecycle_id": group.lifecycle_id,
        "project_id": group.project_id,
        "plan_id": group.plan_id,
        "plan_version": group.plan_version,
        "owner_thread": group.owner_thread,
        "owner_role": group.owner_role.value,
        "claim_ids": list(group.claim_ids),
        "approval_ids": list(group.approval_ids),
        "resource_ids": list(group.resource_ids),
        "claims": [{"id": claim.id, "status": claim.status.value, "resource_id": claim.resource_id} for claim in claims],
        "resources": [{"id": resource.id, "current_claim_id": resource.current_claim_id} for resource in resources],
        "evidence_ids": list(group.evidence_ids),
        "idempotent": idempotent,
        "audit_event": audit_event or f"audit.claim-group.{group.id}.{group.state.value}",
        "release_evidence_complete": bool(group.evidence_ids),
    }


def _registered_group_status(group: ClaimActivationGroup, missing_reason: str) -> dict[str, object]:
    return {
        "group": group.id,
        "group_id": group.id,
        "group_status": group.state.value,
        "state": group.state.value,
        "lifecycle_id": group.lifecycle_id,
        "project_id": group.project_id,
        "plan_id": group.plan_id,
        "plan_version": group.plan_version,
        "owner_thread": group.owner_thread,
        "owner_role": group.owner_role.value,
        "claim_ids": list(group.claim_ids),
        "approval_ids": list(group.approval_ids),
        "resource_ids": list(group.resource_ids),
        "claims": [],
        "resources": [],
        "missing_records": missing_reason,
        "evidence_ids": list(group.evidence_ids),
        "idempotent": False,
        "audit_event": None,
        "release_evidence_complete": bool(group.evidence_ids),
    }


def _group_audit_event(
    group: ClaimActivationGroup,
    claims: tuple[Claim, ...],
    event_type: AuditEventType,
    summary: str,
    evidence_ids: tuple[str, ...],
) -> AuditEvent:
    return AuditEvent(
        id=f"audit.claim-group.{group.id}.{event_type.value}",
        event_type=event_type,
        owner_domain=group.owner_role,
        subject_id=group.id,
        summary=summary,
        risk_level=max((claim.risk_level for claim in claims), key=lambda item: (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL).index(item)),
        evidence_ids=evidence_ids,
    )


def _status_id(value: str) -> str:
    return value.replace("-", "").replace(":", "").replace("+", "").replace(".", "")


def _continuation_audit(
    continuation: ClaimApprovalContinuation,
    claim: Claim,
    event_type: AuditEventType,
    summary: str,
    evidence_ids: tuple[str, ...],
    occurred_at: str,
) -> AuditEvent:
    return AuditEvent(
        id=f"audit.{continuation.id}.state.{event_type.value}.{_status_id(occurred_at)}",
        event_type=event_type,
        owner_domain=continuation.owner_role,
        subject_id=continuation.id,
        summary=summary,
        risk_level=claim.risk_level,
        evidence_ids=evidence_ids,
        occurred_at=occurred_at,
    )


__all__ = [
    "ClaimActivationGroup",
    "ClaimActivationGroupState",
    "ClaimApprovalContinuation",
    "ClaimApprovalContinuationAttempt",
    "ContinuationState",
    "continuation_for_claim",
    "continuation_prompt",
    "continuation_status",
    "dispatch_claim_approval_continuation_status",
    "dispatch_claim_approval_continuations_status",
    "activate_claim_group_status",
    "claim_group_status",
    "release_claim_group_status",
    "register_claim_activation_group_status",
    "create_claim_activation_group_status",
]
