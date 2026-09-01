from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import threading
from typing import Any

import pytest

from overseer import cli
import overseer.claim_transition as transition_module
from overseer.audit import ApprovalStatus, ApprovalRequest, AuditEvent, AuditEventType
from overseer.claim_continuation import (
    ClaimApprovalContinuation,
    ClaimApprovalContinuationAttempt,
    ClaimActivationGroup,
    ClaimActivationGroupState,
    ContinuationState,
)
from overseer.claim_transition import transition_claim_status
from overseer.core import (
    ApprovalLevel,
    Claim,
    ClaimStatus,
    ClaimType,
    ConflictDecision,
    ConflictOutcome,
    OwnerDomain,
    Resource,
    ResourceState,
    ResourceType,
    RiskLevel,
)
from overseer.store import SQLiteStore


PLAN_DIGEST = "a36eb10433ebae40489deb538ef0abb3bf096340d4e11082b246b79fdc4b743f"
PREDECESSOR_CLAIM_ID = "claim.phase-b.predecessor"
SUCCESSOR_CLAIM_ID = "claim.phase-b.successor"
PREDECESSOR_RESOURCE_ID = "resource.phase-b.predecessor"
SUCCESSOR_RESOURCE_ID = "resource.phase-b.successor"
PREDECESSOR_GROUP_ID = "group.phase-b.predecessor"
APPROVAL_ID = f"approval.{SUCCESSOR_CLAIM_ID}"
PREDECESSOR_APPROVAL_ID = f"approval.{PREDECESSOR_CLAIM_ID}"
CONTINUATION_ID = f"continuation.{APPROVAL_ID}"
CONTINUATION_ATTEMPT_ID = f"{CONTINUATION_ID}.attempt.2026-09-01T12-00-00-00-00"
OWNER_THREAD = "thread.phase-b.exact-owner"
OWNER_ROLE = OwnerDomain.DAX.value
ACTIVATION_GROUP_ID = "group.phase-b.successor"
LIFECYCLE_ID = "lifecycle.phase-b.rehearsal"
TRANSITIONED_AT = "2026-09-01T12:00:00+00:00"
EVIDENCE_IDS = ("evidence.phase-b.result", "evidence.phase-b.cleanup")
RELEASE_AUDIT_ID = f"audit.claim-transition.{SUCCESSOR_CLAIM_ID}.predecessor-released"
TRANSITION_AUDIT_ID = f"audit.claim-transition.{SUCCESSOR_CLAIM_ID}.executed"


def _seed_transition_store(path: Path) -> dict[str, object]:
    """Create the complete transition fixture through SQLiteStore APIs."""
    store = SQLiteStore(path)
    try:
        store.save_resource(
            Resource(
                id=PREDECESSOR_RESOURCE_ID,
                name="Phase B predecessor resource",
                type=ResourceType.VIRTUAL_ASSET,
                owner_domain=OwnerDomain.DAX,
                risk_level=RiskLevel.LOW,
                state=ResourceState.CHECKED_OUT,
                current_claim_id=PREDECESSOR_CLAIM_ID,
                exclusive_groups=frozenset({"phase-b-successor"}),
            )
        )
        store.save_resource(
            Resource(
                id=SUCCESSOR_RESOURCE_ID,
                name="Phase B successor resource",
                type=ResourceType.VIRTUAL_ASSET,
                owner_domain=OwnerDomain.DAX,
                risk_level=RiskLevel.LOW,
                state=ResourceState.AVAILABLE,
                current_claim_id=None,
                identifiers={"planDigest": PLAN_DIGEST},
                exclusive_groups=frozenset({"phase-b-successor"}),
            )
        )

        predecessor = Claim(
            id=PREDECESSOR_CLAIM_ID,
            resource_id=PREDECESSOR_RESOURCE_ID,
            claim_type=ClaimType.LEASE,
            owner_thread=OWNER_THREAD,
            owner_role=OwnerDomain.DAX,
            intent="retain the currently active disposable rehearsal lease",
            requested_action="release only after the successor transition commits",
            risk_level=RiskLevel.LOW,
            status=ClaimStatus.ACTIVE,
            activation_group_id=PREDECESSOR_GROUP_ID,
            lifecycle_id=LIFECYCLE_ID,
            approval_id=PREDECESSOR_APPROVAL_ID,
        )
        successor = Claim(
            id=SUCCESSOR_CLAIM_ID,
            resource_id=SUCCESSOR_RESOURCE_ID,
            claim_type=ClaimType.LEASE,
            owner_thread=OWNER_THREAD,
            owner_role=OwnerDomain.DAX,
            intent="take the exact approved successor rehearsal lease",
            requested_action="activate only after predecessor release is atomic",
            risk_level=RiskLevel.LOW,
            status=ClaimStatus.REQUESTED,
            approval_id=None,
            activation_group_id=ACTIVATION_GROUP_ID,
            lifecycle_id=LIFECYCLE_ID,
        )
        store.save_claim(
            predecessor,
            ConflictDecision(ConflictOutcome.ALLOW, "predecessor is the active exact lease"),
        )
        store.save_claim(
            successor,
            ConflictDecision(
                ConflictOutcome.ESCALATE,
                "dax approval required for the successor lease",
                ApprovalLevel.ROLE,
            ),
        )

        store.save_approval(
            ApprovalRequest(
                id=PREDECESSOR_APPROVAL_ID,
                subject_id=PREDECESSOR_CLAIM_ID,
                approval_level=ApprovalLevel.ROLE,
                requester_thread=OWNER_THREAD,
                owner_domain=OwnerDomain.DAX,
                reason="approve the exact Phase B predecessor lease",
                status=ApprovalStatus.APPROVED,
                evidence_required=("evidence.phase-b.predecessor",),
                decided_by=OWNER_ROLE,
                decided_at="2026-09-01T11:40:00+00:00",
            )
        )
        store.save_approval(
            ApprovalRequest(
                id=APPROVAL_ID,
                subject_id=SUCCESSOR_CLAIM_ID,
                approval_level=ApprovalLevel.ROLE,
                requester_thread=OWNER_THREAD,
                owner_domain=OwnerDomain.DAX,
                reason="approve the exact Phase B successor claim",
                status=ApprovalStatus.APPROVED,
                evidence_required=(PLAN_DIGEST,),
                decided_by=OWNER_ROLE,
                decided_at="2026-09-01T11:50:00+00:00",
            )
        )
        store.save_claim_approval_continuation_attempt(
            ClaimApprovalContinuationAttempt(
                id=CONTINUATION_ATTEMPT_ID,
                continuation_id=CONTINUATION_ID,
                owner_thread=OWNER_THREAD,
                state=ContinuationState.DELIVERED,
                attempted_at="2026-09-01T11:55:00+00:00",
                result_status="prompt_dispatched",
                result_reason="delivered to the exact owner thread",
            )
        )
        store.save_claim_approval_continuation(
            ClaimApprovalContinuation(
                id=CONTINUATION_ID,
                claim_id=SUCCESSOR_CLAIM_ID,
                approval_id=APPROVAL_ID,
                resource_id=SUCCESSOR_RESOURCE_ID,
                owner_thread=OWNER_THREAD,
                owner_role=OwnerDomain.DAX,
                activation_group_id=ACTIVATION_GROUP_ID,
                lifecycle_id=LIFECYCLE_ID,
                state=ContinuationState.DELIVERED,
                attempt_id=CONTINUATION_ATTEMPT_ID,
            )
        )
    finally:
        store.close()
    return {
        "store_path": str(path),
        "predecessor_claim_id": PREDECESSOR_CLAIM_ID,
        "successor_claim_id": SUCCESSOR_CLAIM_ID,
        "approval_id": APPROVAL_ID,
        "expected_resource_id": SUCCESSOR_RESOURCE_ID,
        "expected_owner_thread": OWNER_THREAD,
        "expected_owner_role": OWNER_ROLE,
        "expected_activation_group_id": ACTIVATION_GROUP_ID,
        "expected_lifecycle_id": LIFECYCLE_ID,
        "plan_digest": PLAN_DIGEST,
        "transitioned_by": OWNER_ROLE,
        "evidence_ids": EVIDENCE_IDS,
        "transitioned_at": TRANSITIONED_AT,
    }


def _seed_psychlo_round(path: Path) -> Path:
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE projects (id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, plan_version TEXT NOT NULL);"
        "CREATE TABLE rounds (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, state TEXT NOT NULL, request_json TEXT NOT NULL);"
    )
    request = {
        "roundId": LIFECYCLE_ID,
        "projectId": "phase-b",
        "planId": "phase-b-plan",
        "planVersion": "1",
        "threadId": OWNER_THREAD,
    }
    connection.execute("INSERT INTO projects VALUES (?, ?, ?)", ("phase-b", "phase-b-plan", "1"))
    connection.execute(
        "INSERT INTO rounds VALUES (?, ?, 'active', ?)",
        (LIFECYCLE_ID, "phase-b", json.dumps(request)),
    )
    connection.commit()
    connection.close()
    return path


def _insert_duplicate_successor_continuation(
    store: SQLiteStore,
    continuation_id: str,
) -> None:
    row = store._connection.execute(
        "SELECT payload FROM claim_approval_continuations WHERE id = ?",
        (CONTINUATION_ID,),
    ).fetchone()
    assert row is not None
    payload = json.loads(str(row["payload"]))
    payload["id"] = continuation_id
    store._connection.execute(
        """
        INSERT INTO claim_approval_continuations (id, claim_id, approval_id, payload)
        VALUES (?, ?, ?, ?)
        """,
        (
            continuation_id,
            f"index-bypass.{continuation_id}",
            f"index-bypass.{continuation_id}",
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        ),
    )
    store._commit_agent_mutation()


def _exact_optional_groups() -> tuple[ClaimActivationGroup, ClaimActivationGroup]:
    return (
        ClaimActivationGroup(
            id=PREDECESSOR_GROUP_ID,
            lifecycle_id=LIFECYCLE_ID,
            project_id="phase-b",
            plan_id="phase-b-plan",
            plan_version="1",
            owner_thread=OWNER_THREAD,
            owner_role=OwnerDomain.DAX,
            claim_ids=(PREDECESSOR_CLAIM_ID,),
            approval_ids=(PREDECESSOR_APPROVAL_ID,),
            resource_ids=(PREDECESSOR_RESOURCE_ID,),
            state=ClaimActivationGroupState.ACTIVE,
        ),
        ClaimActivationGroup(
            id=ACTIVATION_GROUP_ID,
            lifecycle_id=LIFECYCLE_ID,
            project_id="phase-b",
            plan_id="phase-b-plan",
            plan_version="1",
            owner_thread=OWNER_THREAD,
            owner_role=OwnerDomain.DAX,
            claim_ids=(SUCCESSOR_CLAIM_ID,),
            approval_ids=(APPROVAL_ID,),
            resource_ids=(SUCCESSOR_RESOURCE_ID,),
        ),
    )


def _seed_optional_groups(
    path: Path,
    *,
    present: str = "both",
    mismatch: bool = False,
    non_singleton: bool = False,
) -> None:
    """Persist exact singleton groups, or a deliberately unsafe topology."""
    store = SQLiteStore(path)
    try:
        predecessor, successor = _exact_optional_groups()
        if mismatch:
            successor = replace(
                successor,
                claim_ids=(PREDECESSOR_CLAIM_ID,),
                approval_ids=(PREDECESSOR_APPROVAL_ID,),
                resource_ids=(PREDECESSOR_RESOURCE_ID,),
            )
        if non_singleton:
            store.save_resource(
                Resource(
                    id="resource.phase-b.extra",
                    name="unexpected extra group resource",
                    type=ResourceType.VIRTUAL_ASSET,
                    owner_domain=OwnerDomain.DAX,
                    risk_level=RiskLevel.LOW,
                )
            )
            store.save_claim(
                Claim(
                    id="claim.phase-b.extra",
                    resource_id="resource.phase-b.extra",
                    claim_type=ClaimType.LEASE,
                    owner_thread=OWNER_THREAD,
                    owner_role=OwnerDomain.DAX,
                    intent="unexpected extra singleton-group member",
                    requested_action="must never be transitioned",
                    risk_level=RiskLevel.LOW,
                    status=ClaimStatus.REQUESTED,
                    activation_group_id=ACTIVATION_GROUP_ID,
                    lifecycle_id=LIFECYCLE_ID,
                )
            )
            store.save_approval(
                ApprovalRequest(
                    id="approval.claim.phase-b.extra",
                    subject_id="claim.phase-b.extra",
                    approval_level=ApprovalLevel.ROLE,
                    requester_thread=OWNER_THREAD,
                    owner_domain=OwnerDomain.DAX,
                    reason="unexpected extra group approval",
                    status=ApprovalStatus.PENDING,
                )
            )
            successor = replace(
                successor,
                claim_ids=(SUCCESSOR_CLAIM_ID, "claim.phase-b.extra"),
                approval_ids=(APPROVAL_ID, "approval.claim.phase-b.extra"),
                resource_ids=(SUCCESSOR_RESOURCE_ID, "resource.phase-b.extra"),
            )
        if present in {"both", "predecessor"}:
            store.save_claim_activation_group(predecessor)
        if present in {"both", "successor"}:
            store.save_claim_activation_group(successor)
    finally:
        store.close()


def _snapshot(path: Path) -> tuple[Any, ...]:
    store = SQLiteStore(path)
    try:
        claims = tuple(sorted(store.list_claims(), key=lambda item: item.id))
        decisions: list[tuple[str, ConflictDecision | None]] = []
        for claim in claims:
            try:
                decision = store.load_decision(claim.id)
            except KeyError:
                decision = None
            decisions.append((claim.id, decision))
        return (
            tuple(sorted(store.list_resources(), key=lambda item: item.id)),
            claims,
            tuple(sorted(store.list_approvals(), key=lambda item: item.id)),
            tuple(sorted(store.list_claim_approval_continuations(), key=lambda item: item.id)),
            tuple(sorted(store.list_claim_approval_continuation_attempts(), key=lambda item: item.id)),
            tuple(sorted(store.list_claim_activation_groups(), key=lambda item: item.id)),
            tuple(sorted(store.list_audit_events(), key=lambda item: item.id)),
            tuple(decisions),
        )
    finally:
        store.close()


def _assert_transition_state(path: Path, *, predecessor: ClaimStatus, successor: ClaimStatus, predecessor_resource: str | None, successor_resource: str | None) -> None:
    store = SQLiteStore(path)
    try:
        assert store.load_claim(PREDECESSOR_CLAIM_ID).status == predecessor
        persisted_successor = store.load_claim(SUCCESSOR_CLAIM_ID)
        assert persisted_successor.status == successor
        if successor == ClaimStatus.ACTIVE:
            assert persisted_successor.approval_id == APPROVAL_ID
        assert store.load_resource(PREDECESSOR_RESOURCE_ID).current_claim_id == predecessor_resource
        assert store.load_resource(SUCCESSOR_RESOURCE_ID).current_claim_id == successor_resource
    finally:
        store.close()


def test_transition_claim_status_atomically_releases_and_activates_with_bound_audit(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)

    result = transition_claim_status(**arguments)

    assert result["status"] == "transitioned"
    assert result["predecessor_claim_id"] == PREDECESSOR_CLAIM_ID
    assert result["successor_claim_id"] == SUCCESSOR_CLAIM_ID
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.RELEASED,
        successor=ClaimStatus.ACTIVE,
        predecessor_resource=None,
        successor_resource=SUCCESSOR_CLAIM_ID,
    )
    store = SQLiteStore(path)
    try:
        assert store.list_claim_activation_groups() == ()
        assert store.load_resource(PREDECESSOR_RESOURCE_ID).owner_domain == OwnerDomain.DAX
        assert store.load_resource(SUCCESSOR_RESOURCE_ID).owner_domain == OwnerDomain.DAX
        successor_continuations = tuple(
            continuation
            for continuation in store.list_claim_approval_continuations()
            if continuation.claim_id == SUCCESSOR_CLAIM_ID
        )
        assert len(successor_continuations) == 1
        assert successor_continuations[0].id == CONTINUATION_ID
        assert successor_continuations[0].attempt_id == CONTINUATION_ATTEMPT_ID
        events = store.list_audit_events()
        release_events = [event for event in events if event.subject_id == PREDECESSOR_CLAIM_ID and event.event_type == AuditEventType.RELEASED]
        transition_events = [event for event in events if event.subject_id == SUCCESSOR_CLAIM_ID and event.event_type == AuditEventType.EXECUTED]
        assert len(release_events) == 1
        assert len(transition_events) == 1
        assert release_events[0].id == RELEASE_AUDIT_ID
        assert transition_events[0].id == TRANSITION_AUDIT_ID
        exact_bound_evidence = {
            PREDECESSOR_CLAIM_ID,
            SUCCESSOR_CLAIM_ID,
            APPROVAL_ID,
            CONTINUATION_ID,
            PLAN_DIGEST,
            *EVIDENCE_IDS,
        }
        for event in (*release_events, *transition_events):
            assert exact_bound_evidence.issubset(event.evidence_ids)
    finally:
        store.close()


def test_transition_with_exact_optional_singleton_groups_changes_both_group_states_atomically(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    psychlo = _seed_psychlo_round(tmp_path / "psychlo.sqlite3")
    arguments = _seed_transition_store(path)
    _seed_optional_groups(path)

    result = transition_claim_status(**arguments, _psychlo_store_path=str(psychlo))

    assert result["status"] == "transitioned"
    store = SQLiteStore(path)
    try:
        assert store.load_claim_activation_group(PREDECESSOR_GROUP_ID).state == ClaimActivationGroupState.RELEASED
        assert store.load_claim_activation_group(ACTIVATION_GROUP_ID).state == ClaimActivationGroupState.ACTIVE
    finally:
        store.close()
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.RELEASED,
        successor=ClaimStatus.ACTIVE,
        predecessor_resource=None,
        successor_resource=SUCCESSOR_CLAIM_ID,
    )


@pytest.mark.parametrize(
    ("present", "mismatch", "non_singleton"),
    [
        ("predecessor", False, False),
        ("successor", False, False),
        ("both", True, False),
        ("both", False, True),
    ],
)
def test_transition_rejects_partial_or_non_exact_optional_groups_without_mutation(
    tmp_path: Path,
    present: str,
    mismatch: bool,
    non_singleton: bool,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    psychlo = _seed_psychlo_round(tmp_path / "psychlo.sqlite3")
    arguments = _seed_transition_store(path)
    _seed_optional_groups(path, present=present, mismatch=mismatch, non_singleton=non_singleton)
    before = _snapshot(path)

    with pytest.raises((KeyError, ValueError), match=""):
        transition_claim_status(**arguments, _psychlo_store_path=str(psychlo))

    assert _snapshot(path) == before
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.ACTIVE,
        successor=ClaimStatus.REQUESTED,
        predecessor_resource=PREDECESSOR_CLAIM_ID,
        successor_resource=None,
    )


def test_grouped_transition_holds_psychlo_writer_lock_through_overseer_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    psychlo = _seed_psychlo_round(tmp_path / "psychlo.sqlite3")
    arguments = _seed_transition_store(path)
    _seed_optional_groups(path)
    validation_entered = threading.Event()
    allow_validation = threading.Event()
    commit_entered = threading.Event()
    allow_commit = threading.Event()
    overseer_commit_completed = threading.Event()
    competing_writer_started = threading.Event()
    competing_writer_acquired = threading.Event()
    results: list[dict[str, object]] = []
    errors: list[Exception] = []
    competing_errors: list[Exception] = []
    acquisition_after_commit: list[bool] = []
    original_validate = transition_module._validate_psychlo_round
    original_commit = SQLiteStore._commit

    def blocked_lifecycle_validation(*args: object, **kwargs: object) -> object:
        validation_entered.set()
        assert allow_validation.wait(timeout=2)
        return original_validate(*args, **kwargs)

    def blocked_transition_commit(store: SQLiteStore) -> None:
        is_transition_commit = False
        try:
            predecessor = store.load_claim(PREDECESSOR_CLAIM_ID)
            successor = store.load_claim(SUCCESSOR_CLAIM_ID)
            predecessor_group = store.load_claim_activation_group(PREDECESSOR_GROUP_ID)
            successor_group = store.load_claim_activation_group(ACTIVATION_GROUP_ID)
        except KeyError:
            original_commit(store)
            return
        if (
            predecessor.status == ClaimStatus.RELEASED
            and successor.status == ClaimStatus.ACTIVE
            and predecessor_group.state == ClaimActivationGroupState.RELEASED
            and successor_group.state == ClaimActivationGroupState.ACTIVE
        ):
            is_transition_commit = True
            commit_entered.set()
            assert allow_commit.wait(timeout=2)
        original_commit(store)
        if is_transition_commit:
            overseer_commit_completed.set()

    monkeypatch.setattr(
        transition_module,
        "_validate_psychlo_round",
        blocked_lifecycle_validation,
    )
    monkeypatch.setattr(SQLiteStore, "_commit", blocked_transition_commit)

    def transition() -> None:
        try:
            results.append(
                transition_claim_status(
                    **arguments,
                    _psychlo_store_path=str(psychlo),
                )
            )
        except Exception as error:  # pragma: no cover - surfaced below
            errors.append(error)

    def compete_for_psychlo_writer() -> None:
        connection = sqlite3.connect(psychlo, timeout=10.0)
        competing_writer_started.set()
        try:
            connection.execute("BEGIN IMMEDIATE")
            acquisition_after_commit.append(overseer_commit_completed.is_set())
            competing_writer_acquired.set()
            connection.rollback()
        except Exception as error:  # pragma: no cover - surfaced below
            competing_errors.append(error)
        finally:
            connection.close()

    worker = threading.Thread(target=transition)
    worker.start()
    competitor = threading.Thread(target=compete_for_psychlo_writer)
    try:
        assert validation_entered.wait(timeout=2)
        competitor.start()
        assert competing_writer_started.wait(timeout=2)
        assert not competing_writer_acquired.wait(timeout=0.1)

        allow_validation.set()
        assert commit_entered.wait(timeout=2)
        assert competing_writer_acquired.is_set() is False

        allow_commit.set()
        worker.join(timeout=2)
        assert worker.is_alive() is False
        assert overseer_commit_completed.is_set()
        assert competing_writer_acquired.wait(timeout=2)
    finally:
        allow_validation.set()
        allow_commit.set()
        worker.join(timeout=2)
        if competitor.ident is not None:
            competitor.join(timeout=2)

    assert not errors
    assert not competing_errors
    assert results and results[0]["status"] == "transitioned"
    assert acquisition_after_commit == [True]


def test_transition_rolls_back_after_successor_persistence_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    before = _snapshot(path)
    original_save_claim = SQLiteStore.save_claim

    def fail_after_predecessor_release(self: SQLiteStore, claim: Claim, decision: ConflictDecision | None = None) -> None:
        if claim.id == SUCCESSOR_CLAIM_ID and claim.status == ClaimStatus.ACTIVE:
            assert self.load_claim(PREDECESSOR_CLAIM_ID).status == ClaimStatus.RELEASED
            original_save_claim(self, claim, decision)
            raise RuntimeError("simulated successor persistence failure")
        original_save_claim(self, claim, decision)

    monkeypatch.setattr(SQLiteStore, "save_claim", fail_after_predecessor_release)
    with pytest.raises(RuntimeError, match="simulated successor persistence failure"):
        transition_claim_status(**arguments)

    assert _snapshot(path) == before
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.ACTIVE,
        successor=ClaimStatus.REQUESTED,
        predecessor_resource=PREDECESSOR_CLAIM_ID,
        successor_resource=None,
    )


@pytest.mark.parametrize("policy_case", ["security surface", "high-risk claim"])
def test_transition_rejects_non_role_canonical_policy_without_mutation(
    tmp_path: Path,
    policy_case: str,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        if policy_case == "security surface":
            resource = store.load_resource(SUCCESSOR_RESOURCE_ID)
            store.save_resource(replace(resource, type=ResourceType.SECURITY_SURFACE))
        else:
            successor = store.load_claim(SUCCESSOR_CLAIM_ID)
            store.save_claim(
                replace(successor, risk_level=RiskLevel.HIGH),
                store.load_decision(SUCCESSOR_CLAIM_ID),
            )
    finally:
        store.close()
    before = _snapshot(path)

    with pytest.raises(ValueError):
        transition_claim_status(**arguments)

    assert _snapshot(path) == before


@pytest.mark.parametrize("resource_id", [PREDECESSOR_RESOURCE_ID, SUCCESSOR_RESOURCE_ID])
def test_transition_rejects_resource_owner_mismatch_without_mutation(
    tmp_path: Path,
    resource_id: str,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        resource = store.load_resource(resource_id)
        store.save_resource(replace(resource, owner_domain=OwnerDomain.ODO))
    finally:
        store.close()
    before = _snapshot(path)

    with pytest.raises(ValueError):
        transition_claim_status(**arguments)

    assert _snapshot(path) == before


def test_transition_rejects_second_successor_continuation_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        _insert_duplicate_successor_continuation(
            store,
            "continuation.duplicate-successor",
        )
    finally:
        store.close()
    before = _snapshot(path)

    with pytest.raises(ValueError):
        transition_claim_status(**arguments)

    assert _snapshot(path) == before


@pytest.mark.parametrize(
    ("outcome", "approval_level"),
    [
        (ConflictOutcome.ESCALATE, ApprovalLevel.HUMAN),
        (ConflictOutcome.ALLOW, ApprovalLevel.ROLE),
    ],
)
def test_transition_rejects_incompatible_stored_authority_decision_without_mutation(
    tmp_path: Path,
    outcome: ConflictOutcome,
    approval_level: ApprovalLevel,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        successor = store.load_claim(SUCCESSOR_CLAIM_ID)
        store.save_claim(
            successor,
            ConflictDecision(
                outcome,
                "forged stored authority decision",
                approval_level,
            ),
        )
    finally:
        store.close()
    before = _snapshot(path)

    with pytest.raises(ValueError):
        transition_claim_status(**arguments)

    assert _snapshot(path) == before


@pytest.mark.parametrize("appearing_group", ["predecessor", "successor"])
def test_ungrouped_transition_rejects_exact_group_appearing_before_writer_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    appearing_group: str,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    predecessor_group, successor_group = _exact_optional_groups()
    group = predecessor_group if appearing_group == "predecessor" else successor_group
    original_agent_transaction = SQLiteStore.agent_transaction
    original_load_claim = SQLiteStore.load_claim
    original_load_group = SQLiteStore.load_claim_activation_group
    guard_typed_loads = True
    injected = False
    raced_snapshots: list[tuple[Any, ...]] = []

    def guarded_load_claim(self: SQLiteStore, claim_id: str) -> Claim:
        if guard_typed_loads and self.path == path and not self._connection.in_transaction:
            raise AssertionError("typed claim load occurred before final writer transaction")
        return original_load_claim(self, claim_id)

    def guarded_load_group(self: SQLiteStore, group_id: str) -> ClaimActivationGroup:
        if guard_typed_loads and self.path == path and not self._connection.in_transaction:
            raise AssertionError("typed group load occurred before final writer transaction")
        return original_load_group(self, group_id)

    @contextmanager
    def raced_agent_transaction(self: SQLiteStore) -> Any:
        nonlocal guard_typed_loads, injected
        if guard_typed_loads and self.path == path and not injected:
            injected = True
            self.save_claim_activation_group(group)
            guard_typed_loads = False
            raced_snapshots.append(_snapshot(path))
            guard_typed_loads = True
        with original_agent_transaction(self):
            yield

    monkeypatch.setattr(SQLiteStore, "load_claim", guarded_load_claim)
    monkeypatch.setattr(SQLiteStore, "load_claim_activation_group", guarded_load_group)
    monkeypatch.setattr(SQLiteStore, "agent_transaction", raced_agent_transaction)
    try:
        with pytest.raises(ValueError):
            transition_claim_status(**arguments)
    finally:
        guard_typed_loads = False

    assert injected
    assert len(raced_snapshots) == 1
    assert _snapshot(path) == raced_snapshots[0]


@pytest.mark.parametrize(
    "tamper",
    ["predecessor resource owner", "successor resource owner", "second continuation"],
)
def test_transition_postconditions_reject_owner_or_continuation_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tamper: str,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    before = _snapshot(path)
    original_save_resource = SQLiteStore.save_resource
    original_save_audit_event = SQLiteStore.save_audit_event
    injected = False

    if tamper.endswith("resource owner"):
        target_resource_id = (
            PREDECESSOR_RESOURCE_ID
            if tamper.startswith("predecessor")
            else SUCCESSOR_RESOURCE_ID
        )

        def tampered_save_resource(self: SQLiteStore, resource: Resource) -> None:
            if resource.id == target_resource_id:
                resource = replace(resource, owner_domain=OwnerDomain.ODO)
            original_save_resource(self, resource)

        monkeypatch.setattr(SQLiteStore, "save_resource", tampered_save_resource)
    else:

        def tampered_save_audit_event(self: SQLiteStore, event: AuditEvent) -> None:
            nonlocal injected
            original_save_audit_event(self, event)
            if event.id == RELEASE_AUDIT_ID and not injected:
                injected = True
                _insert_duplicate_successor_continuation(
                    self,
                    "continuation.postcondition-duplicate",
                )

        monkeypatch.setattr(SQLiteStore, "save_audit_event", tampered_save_audit_event)

    with pytest.raises(ValueError):
        transition_claim_status(**arguments)

    assert _snapshot(path) == before


@pytest.mark.parametrize(
    ("case", "overrides"),
    [
        ("predecessor claim", {"predecessor_claim_id": "claim.wrong-predecessor"}),
        ("successor claim", {"successor_claim_id": "claim.wrong-successor"}),
        ("resource", {"expected_resource_id": "resource.wrong"}),
        ("owner thread", {"expected_owner_thread": "thread.wrong"}),
        ("owner role", {"expected_owner_role": OwnerDomain.ODO.value}),
        ("activation group", {"expected_activation_group_id": "group.wrong"}),
        ("lifecycle", {"expected_lifecycle_id": "lifecycle.wrong"}),
        ("plan digest", {"plan_digest": "0" * 64}),
        ("approval identity", {"approval_id": "approval.wrong"}),
        ("empty release evidence", {"evidence_ids": ()}),
    ],
)
def test_transition_rejects_material_binding_without_mutation(tmp_path: Path, case: str, overrides: dict[str, object]) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    before = _snapshot(path)

    with pytest.raises((KeyError, ValueError), match=""):
        transition_claim_status(**{**arguments, **overrides})

    assert _snapshot(path) == before
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.ACTIVE,
        successor=ClaimStatus.REQUESTED,
        predecessor_resource=PREDECESSOR_CLAIM_ID,
        successor_resource=None,
    )


@pytest.mark.parametrize(
    "invalid_case",
    [
        "approval subject",
        "approval owner",
        "approval level",
        "approval decided by",
        "approval pending",
        "missing continuation",
        "continuation identity",
        "continuation claim",
        "continuation approval",
        "continuation resource",
        "continuation owner thread",
        "continuation owner role",
        "continuation group",
        "continuation lifecycle",
        "continuation pending",
        "continuation attempting",
    ],
)
def test_transition_rejects_invalid_or_undelivered_authority_without_mutation(tmp_path: Path, invalid_case: str) -> None:
    path = tmp_path / "overseer.sqlite3"
    _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        if invalid_case.startswith("approval"):
            approval = store.load_approval(APPROVAL_ID)
            if invalid_case == "approval subject":
                approval = replace(approval, subject_id=PREDECESSOR_CLAIM_ID)
            elif invalid_case == "approval owner":
                approval = replace(approval, owner_domain=OwnerDomain.ODO)
            elif invalid_case == "approval level":
                approval = replace(approval, approval_level=ApprovalLevel.SISKO)
            elif invalid_case == "approval decided by":
                approval = replace(approval, decided_by=OwnerDomain.ODO.value)
            else:
                approval = replace(approval, status=ApprovalStatus.PENDING, decided_by=None, decided_at=None)
            store.save_approval(approval)
        elif invalid_case == "missing continuation":
            store._connection.execute("DELETE FROM claim_approval_continuations WHERE id = ?", (CONTINUATION_ID,))
            store._connection.commit()
        else:
            if invalid_case == "continuation identity":
                _overwrite_continuation_payload(store, id="continuation.wrong")
            else:
                changes = {
                    "continuation claim": {"claim_id": PREDECESSOR_CLAIM_ID},
                    "continuation approval": {"approval_id": "approval.wrong"},
                    "continuation resource": {"resource_id": PREDECESSOR_RESOURCE_ID},
                    "continuation owner thread": {"owner_thread": "thread.wrong"},
                    "continuation owner role": {"owner_role": OwnerDomain.ODO},
                    "continuation group": {"activation_group_id": "group.wrong"},
                    "continuation lifecycle": {"lifecycle_id": "lifecycle.wrong"},
                    "continuation pending": {"state": ContinuationState.PENDING},
                    "continuation attempting": {"state": ContinuationState.ATTEMPTING},
                }[invalid_case]
                _overwrite_continuation_payload(store, **changes)
    finally:
        store.close()
    before = _snapshot(path)

    with pytest.raises((KeyError, ValueError), match=""):
        transition_claim_status(**_seed_transition_arguments(path))

    assert _snapshot(path) == before
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.ACTIVE,
        successor=ClaimStatus.REQUESTED,
        predecessor_resource=PREDECESSOR_CLAIM_ID,
        successor_resource=None,
    )


def _overwrite_continuation_payload(store: SQLiteStore, **changes: object) -> None:
    row = store._connection.execute(
        "SELECT payload FROM claim_approval_continuations WHERE id = ?",
        (CONTINUATION_ID,),
    ).fetchone()
    assert row is not None
    payload = json.loads(str(row["payload"]))
    payload.update(changes)
    store._connection.execute(
        "UPDATE claim_approval_continuations SET payload = ? WHERE id = ?",
        (json.dumps(payload, sort_keys=True, separators=(",", ":")), CONTINUATION_ID),
    )
    store._connection.commit()


def _seed_transition_arguments(path: Path) -> dict[str, object]:
    return {
        "store_path": str(path),
        "predecessor_claim_id": PREDECESSOR_CLAIM_ID,
        "successor_claim_id": SUCCESSOR_CLAIM_ID,
        "approval_id": APPROVAL_ID,
        "expected_resource_id": SUCCESSOR_RESOURCE_ID,
        "expected_owner_thread": OWNER_THREAD,
        "expected_owner_role": OWNER_ROLE,
        "expected_activation_group_id": ACTIVATION_GROUP_ID,
        "expected_lifecycle_id": LIFECYCLE_ID,
        "plan_digest": PLAN_DIGEST,
        "transitioned_by": OWNER_ROLE,
        "evidence_ids": EVIDENCE_IDS,
        "transitioned_at": TRANSITIONED_AT,
    }


def _assert_transition_rejected_without_mutation(path: Path) -> None:
    before = _snapshot(path)
    with pytest.raises((KeyError, ValueError), match=""):
        transition_claim_status(**_seed_transition_arguments(path))
    assert _snapshot(path) == before
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.ACTIVE,
        successor=ClaimStatus.REQUESTED,
        predecessor_resource=PREDECESSOR_CLAIM_ID,
        successor_resource=None,
    )


def _seed_external_active_claim(
    store: SQLiteStore,
    *,
    resource_exclusive_groups: frozenset[str] = frozenset(),
    claim_exclusive_groups: frozenset[str] = frozenset(),
) -> None:
    store.save_resource(
        Resource(
            id="resource.external-conflict",
            name="external conflicting resource",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.LOW,
            state=ResourceState.CHECKED_OUT,
            current_claim_id="claim.external-conflict",
            exclusive_groups=resource_exclusive_groups,
        )
    )
    store.save_claim(
        Claim(
            id="claim.external-conflict",
            resource_id="resource.external-conflict",
            claim_type=ClaimType.LEASE,
            owner_thread="thread.external-owner",
            owner_role=OwnerDomain.DAX,
            intent="unrelated active lease conflicting with the successor",
            requested_action="hold the conflicting resource",
            risk_level=RiskLevel.LOW,
            status=ClaimStatus.ACTIVE,
            exclusive_groups=claim_exclusive_groups,
        ),
        ConflictDecision(ConflictOutcome.ALLOW, "external claim is active"),
    )


def test_transition_rejects_resource_level_external_conflict_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        _seed_external_active_claim(
            store,
            resource_exclusive_groups=frozenset({"phase-b-successor"}),
        )
    finally:
        store.close()

    _assert_transition_rejected_without_mutation(path)


def test_transition_rejects_claim_level_external_conflict_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        successor = store.load_claim(SUCCESSOR_CLAIM_ID)
        decision = store.load_decision(SUCCESSOR_CLAIM_ID)
        store.save_claim(
            replace(successor, exclusive_groups=frozenset({"claim-level-successor"})),
            decision,
        )
        _seed_external_active_claim(
            store,
            claim_exclusive_groups=frozenset({"claim-level-successor"}),
        )
        assert store.load_resource("resource.external-conflict").exclusive_groups == frozenset()
    finally:
        store.close()

    _assert_transition_rejected_without_mutation(path)


def test_transition_rejects_unavailable_successor_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        resource = store.load_resource(SUCCESSOR_RESOURCE_ID)
        store.save_resource(replace(resource, state=ResourceState.LOCKED))
    finally:
        store.close()

    _assert_transition_rejected_without_mutation(path)


@pytest.mark.parametrize(
    ("collision_id", "event_type"),
    [
        (RELEASE_AUDIT_ID, AuditEventType.RELEASED),
        (TRANSITION_AUDIT_ID, AuditEventType.EXECUTED),
    ],
)
def test_transition_rejects_deterministic_audit_id_collision_without_mutation(
    tmp_path: Path,
    collision_id: str,
    event_type: AuditEventType,
) -> None:
    path = tmp_path / "overseer.sqlite3"
    _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        store.save_audit_event(
            AuditEvent(
                id=collision_id,
                event_type=event_type,
                owner_domain=OwnerDomain.DAX,
                subject_id="pre-existing-collision",
                summary="pre-existing deterministic audit ID collision",
                risk_level=RiskLevel.LOW,
                evidence_ids=("collision",),
                occurred_at="2026-09-01T11:59:00+00:00",
            )
        )
    finally:
        store.close()
    before = _snapshot(path)

    with pytest.raises((KeyError, ValueError), match=""):
        transition_claim_status(**_seed_transition_arguments(path))

    assert _snapshot(path) == before
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.ACTIVE,
        successor=ClaimStatus.REQUESTED,
        predecessor_resource=PREDECESSOR_CLAIM_ID,
        successor_resource=None,
    )


def test_transition_replay_is_rejected_without_mutation(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    arguments = _seed_transition_store(path)
    transition_claim_status(**arguments)
    after_first_transition = _snapshot(path)

    with pytest.raises((KeyError, ValueError), match=""):
        transition_claim_status(**arguments)

    assert _snapshot(path) == after_first_transition
    _assert_transition_state(
        path,
        predecessor=ClaimStatus.RELEASED,
        successor=ClaimStatus.ACTIVE,
        predecessor_resource=None,
        successor_resource=SUCCESSOR_CLAIM_ID,
    )


def test_transition_claim_cli_routes_every_explicit_binding_as_keyword(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    expected_result = {"status": "transitioned", "successor_claim_id": SUCCESSOR_CLAIM_ID}

    def intercepted_transition_claim_status(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return expected_result

    monkeypatch.setattr(cli, "transition_claim_status", intercepted_transition_claim_status)
    assert cli.main(
        [
            "transition-claim",
            "--store",
            str(tmp_path / "temporary.sqlite3"),
            "--predecessor-claim-id",
            PREDECESSOR_CLAIM_ID,
            "--successor-claim-id",
            SUCCESSOR_CLAIM_ID,
            "--approval-id",
            APPROVAL_ID,
            "--expected-resource-id",
            SUCCESSOR_RESOURCE_ID,
            "--expected-owner-thread",
            OWNER_THREAD,
            "--expected-owner-role",
            OWNER_ROLE,
            "--expected-activation-group-id",
            ACTIVATION_GROUP_ID,
            "--expected-lifecycle-id",
            LIFECYCLE_ID,
            "--plan-digest",
            PLAN_DIGEST,
            "--transitioned-by",
            OWNER_ROLE,
            "--evidence-id",
            EVIDENCE_IDS[0],
            "--evidence-id",
            EVIDENCE_IDS[1],
            "--transitioned-at",
            TRANSITIONED_AT,
        ]
    ) == 0

    assert captured == {
        "store_path": str(tmp_path / "temporary.sqlite3"),
        "predecessor_claim_id": PREDECESSOR_CLAIM_ID,
        "successor_claim_id": SUCCESSOR_CLAIM_ID,
        "approval_id": APPROVAL_ID,
        "expected_resource_id": SUCCESSOR_RESOURCE_ID,
        "expected_owner_thread": OWNER_THREAD,
        "expected_owner_role": OWNER_ROLE,
        "expected_activation_group_id": ACTIVATION_GROUP_ID,
        "expected_lifecycle_id": LIFECYCLE_ID,
        "plan_digest": PLAN_DIGEST,
        "transitioned_by": OWNER_ROLE,
        "evidence_ids": EVIDENCE_IDS,
        "transitioned_at": TRANSITIONED_AT,
    }
    assert json.loads(capsys.readouterr().out) == expected_result


def test_transition_claim_cli_omitted_required_argument_fails_before_routing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    called = False

    def intercepted_transition_claim_status(**kwargs: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {"status": "unexpected"}

    monkeypatch.setattr(cli, "transition_claim_status", intercepted_transition_claim_status)
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "transition-claim",
                "--store",
                str(tmp_path / "temporary.sqlite3"),
                "--predecessor-claim-id",
                PREDECESSOR_CLAIM_ID,
                "--approval-id",
                APPROVAL_ID,
                "--expected-resource-id",
                SUCCESSOR_RESOURCE_ID,
                "--expected-owner-thread",
                OWNER_THREAD,
                "--expected-owner-role",
                OWNER_ROLE,
                "--expected-activation-group-id",
                ACTIVATION_GROUP_ID,
                "--expected-lifecycle-id",
                LIFECYCLE_ID,
                "--plan-digest",
                PLAN_DIGEST,
                "--transitioned-by",
                OWNER_ROLE,
                "--evidence-id",
                EVIDENCE_IDS[0],
                # --successor-claim-id is intentionally omitted.
            ]
        )

    assert error.value.code == 2
    assert called is False
