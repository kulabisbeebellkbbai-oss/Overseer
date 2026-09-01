from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

import pytest

from overseer import cli
from overseer.audit import ApprovalStatus, ApprovalRequest, AuditEventType
from overseer.claim_continuation import (
    ClaimApprovalContinuation,
    ClaimApprovalContinuationAttempt,
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
APPROVAL_ID = f"approval.{SUCCESSOR_CLAIM_ID}"
CONTINUATION_ID = f"continuation.{APPROVAL_ID}"
CONTINUATION_ATTEMPT_ID = f"{CONTINUATION_ID}.attempt.2026-09-01T12-00-00-00-00"
OWNER_THREAD = "thread.phase-b.exact-owner"
OWNER_ROLE = OwnerDomain.DAX.value
ACTIVATION_GROUP_ID = "group.phase-b.successor"
LIFECYCLE_ID = "lifecycle.phase-b.rehearsal"
TRANSITIONED_AT = "2026-09-01T12:00:00+00:00"
EVIDENCE_IDS = ("evidence.phase-b.result", "evidence.phase-b.cleanup")


def _seed_transition_store(path: Path) -> dict[str, str]:
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
            activation_group_id="group.phase-b.predecessor",
            lifecycle_id=LIFECYCLE_ID,
            exclusive_groups=frozenset({"phase-b-predecessor"}),
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
            approval_id=APPROVAL_ID,
            evidence_ids=(PLAN_DIGEST,),
            activation_group_id=ACTIVATION_GROUP_ID,
            lifecycle_id=LIFECYCLE_ID,
            exclusive_groups=frozenset({"phase-b-successor"}),
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


def _snapshot(path: Path) -> tuple[Any, ...]:
    store = SQLiteStore(path)
    try:
        return (
            tuple(sorted(store.list_resources(), key=lambda item: item.id)),
            tuple(sorted(store.list_claims(), key=lambda item: item.id)),
            tuple(sorted(store.list_approvals(), key=lambda item: item.id)),
            tuple(sorted(store.list_claim_approval_continuations(), key=lambda item: item.id)),
            tuple(sorted(store.list_claim_approval_continuation_attempts(), key=lambda item: item.id)),
            tuple(sorted(store.list_audit_events(), key=lambda item: item.id)),
            tuple(store.load_decision(claim_id) for claim_id in (PREDECESSOR_CLAIM_ID, SUCCESSOR_CLAIM_ID)),
        )
    finally:
        store.close()


def _assert_transition_state(path: Path, *, predecessor: ClaimStatus, successor: ClaimStatus, predecessor_resource: str | None, successor_resource: str | None) -> None:
    store = SQLiteStore(path)
    try:
        assert store.load_claim(PREDECESSOR_CLAIM_ID).status == predecessor
        assert store.load_claim(SUCCESSOR_CLAIM_ID).status == successor
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
        events = store.list_audit_events()
        release_events = [event for event in events if event.subject_id == PREDECESSOR_CLAIM_ID and event.event_type == AuditEventType.RELEASED]
        transition_events = [event for event in events if event.subject_id == SUCCESSOR_CLAIM_ID and event.event_type == AuditEventType.EXECUTED]
        assert len(release_events) == 1
        assert len(transition_events) == 1
        for event in (*release_events, *transition_events):
            assert set(EVIDENCE_IDS).issubset(event.evidence_ids)
            assert PLAN_DIGEST in event.evidence_ids
        assert {PREDECESSOR_CLAIM_ID, SUCCESSOR_CLAIM_ID, APPROVAL_ID, CONTINUATION_ID}.issubset(
            set(transition_events[0].evidence_ids)
        )
    finally:
        store.close()


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


@pytest.mark.parametrize("invalid_case", ["approval", "missing continuation", "undelivered continuation"])
def test_transition_rejects_invalid_or_undelivered_authority_without_mutation(tmp_path: Path, invalid_case: str) -> None:
    path = tmp_path / "overseer.sqlite3"
    _seed_transition_store(path)
    store = SQLiteStore(path)
    try:
        if invalid_case == "approval":
            approval = store.load_approval(APPROVAL_ID)
            store.save_approval(replace(approval, status=ApprovalStatus.PENDING, decided_by=None, decided_at=None))
        elif invalid_case == "missing continuation":
            store._connection.execute("DELETE FROM claim_approval_continuations WHERE id = ?", (CONTINUATION_ID,))
            store._connection.commit()
        else:
            continuation = store.load_claim_approval_continuation(CONTINUATION_ID)
            store.save_claim_approval_continuation(replace(continuation, state=ContinuationState.PENDING))
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


def test_transition_rejects_external_conflict_and_unavailable_successor_without_mutation(tmp_path: Path) -> None:
    for case in ("external conflict", "unavailable resource"):
        path = tmp_path / f"{case.replace(' ', '-')}.sqlite3"
        _seed_transition_store(path)
        store = SQLiteStore(path)
        try:
            if case == "external conflict":
                store.save_resource(
                    Resource(
                        id="resource.external-conflict",
                        name="external conflicting resource",
                        type=ResourceType.VIRTUAL_ASSET,
                        owner_domain=OwnerDomain.DAX,
                        risk_level=RiskLevel.LOW,
                        state=ResourceState.CHECKED_OUT,
                        current_claim_id="claim.external-conflict",
                    )
                )
                store.save_claim(
                    Claim(
                        id="claim.external-conflict",
                        resource_id="resource.external-conflict",
                        claim_type=ClaimType.LEASE,
                        owner_thread="thread.external-owner",
                        owner_role=OwnerDomain.DAX,
                        intent="unrelated active lease sharing the successor exclusive group",
                        requested_action="hold the conflicting resource",
                        risk_level=RiskLevel.LOW,
                        status=ClaimStatus.ACTIVE,
                        exclusive_groups=frozenset({"phase-b-successor"}),
                    ),
                    ConflictDecision(ConflictOutcome.ALLOW, "external claim is active"),
                )
            else:
                resource = store.load_resource(SUCCESSOR_RESOURCE_ID)
                store.save_resource(replace(resource, state=ResourceState.LOCKED))
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
