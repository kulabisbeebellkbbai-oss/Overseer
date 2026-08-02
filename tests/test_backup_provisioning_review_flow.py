"""Security invariants for the two-phase backup provisioning review flow."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from overseer.backup_provisioning import (
    DedicatedProvisioningAdapter,
    approve_plan,
    build_plan,
    execute_plan,
    stage_plan,
)
from overseer.core import OwnerDomain, RiskLevel
from overseer.crew import CrewMessage, CrewMessageStatus, CrewReviewStatus
from overseer.store import SQLiteStore


REVIEWERS = {
    "kira": OwnerDomain.KIRA,
    "obrien": OwnerDomain.OBRIEN,
    "security": OwnerDomain.ODO_IDS,
    "sisko": OwnerDomain.SISKO,
}


def _plan(store_path, *, plan_id="backup-provision.review-flow"):
    evidence_ids = {}
    now = datetime.now(UTC).isoformat()
    with SQLiteStore(store_path) as store:
        for role, owner in REVIEWERS.items():
            message_id = f"crew.{role}.review-flow"
            evidence_ids[role] = message_id
            store.save_crew_message(
                CrewMessage(
                    id=message_id,
                    owner_domain=owner,
                    subject="Review exact backup provisioning plan",
                    message="Review only; dispatch and acknowledgement do not approve.",
                    priority=RiskLevel.HIGH,
                    status=CrewMessageStatus.OPEN,
                    requested_by="provisioning-requester",
                    created_at=now,
                    updated_at=now,
                    related_plan_id=plan_id,
                )
            )
    registration = {
        "project_id": "project.donuthole",
        "root_id": "backup-root",
        "policy_revision": "1",
        "host_path": "/home/god/Documents/Codex Workspace/DonutHole",
        "alias": "donuthole-source",
        "max_bytes": 1073741824,
        "authorization_ref": "root-auth.donuthole",
    }
    return build_plan(
        plan_id,
        "sha256:" + "a" * 64,
        "b" * 40,
        "sha256:" + "d" * 64,
        "sha256:" + "c" * 64,
        {"sha256:" + "e" * 64: "root-auth.donuthole"},
        (registration,),
        "/run/user/1000/overseer-api-token",
        "/etc/codex-development-backups/keys/overseer.token",
        "/etc/codex-development-backups/keys/cursor.key",
        evidence_ids,
    )


def _decide(store_path, plan, role, *, review_status=CrewReviewStatus.APPROVED,
            status=CrewMessageStatus.ACKNOWLEDGED, decided_by=None):
    owner = REVIEWERS[role]
    now = datetime.now(UTC).isoformat()
    with SQLiteStore(store_path) as store:
        message = store.load_crew_message(plan.evidence_ids[role])
        store.save_crew_message(
            replace(
                message,
                status=status,
                review_status=review_status,
                decided_by=owner.value if decided_by is None else decided_by,
                decided_at=now if review_status == CrewReviewStatus.APPROVED else None,
                updated_at=now,
            )
        )


def test_stage_precedes_reviews_and_freezes_exact_plan(tmp_path):
    store_path = str(tmp_path / "state.sqlite3")
    plan = _plan(store_path)

    result = stage_plan(store_path, plan)
    assert result["status"] == "staged"

    changed = build_plan(
        plan.plan_id,
        "sha256:" + "f" * 64,
        plan.adapter_commit,
        plan.runtime_digest,
        plan.capability_digest,
        plan.root_authorization_refs,
        plan.root_registrations,
        plan.overseer_token_source_file,
        plan.overseer_token_file,
        plan.cursor_key_file,
        plan.evidence_ids,
    )
    with pytest.raises(ValueError, match="immutable"):
        stage_plan(store_path, changed)


def test_every_review_is_terminal_approved_and_bound_to_exact_staged_plan(tmp_path):
    store_path = str(tmp_path / "state.sqlite3")
    plan = _plan(store_path)
    stage_plan(store_path, plan)

    for role in REVIEWERS:
        _decide(store_path, plan, role)
    with SQLiteStore(store_path) as store:
        message = store.load_crew_message(plan.evidence_ids["security"])
        store.save_crew_message(replace(message, related_plan_id="backup-provision.other"))

    with pytest.raises(ValueError, match="security|exact|related"):
        approve_plan(store_path, plan.plan_id, "independent-human")


def test_acknowledgement_is_not_approval(tmp_path):
    store_path = str(tmp_path / "state.sqlite3")
    plan = _plan(store_path)
    stage_plan(store_path, plan)
    for role in REVIEWERS:
        _decide(store_path, plan, role)
    _decide(
        store_path,
        plan,
        "obrien",
        review_status=CrewReviewStatus.PENDING,
        status=CrewMessageStatus.ACKNOWLEDGED,
    )

    with pytest.raises(ValueError, match="obrien"):
        approve_plan(store_path, plan.plan_id, "independent-human")


def test_requester_cannot_self_approve_after_reviews(tmp_path):
    store_path = str(tmp_path / "state.sqlite3")
    plan = _plan(store_path)
    stage_plan(store_path, plan)
    for role in REVIEWERS:
        _decide(store_path, plan, role)

    with pytest.raises(ValueError, match="independent"):
        approve_plan(store_path, plan.plan_id, "provisioning-requester")


def test_execution_rechecks_terminal_reviews_before_calling_adapter(tmp_path):
    store_path = str(tmp_path / "state.sqlite3")
    plan = _plan(store_path)
    stage_plan(store_path, plan)
    for role in REVIEWERS:
        _decide(store_path, plan, role)
    approve_plan(store_path, plan.plan_id, "independent-human")
    _decide(
        store_path,
        plan,
        "kira",
        review_status=CrewReviewStatus.CORRECTION_REQUESTED,
        status=CrewMessageStatus.ACKNOWLEDGED,
    )
    called = []
    adapter = DedicatedProvisioningAdapter(
        {step.operation: lambda _args: called.append(True) or {"ok": True} for step in plan.steps}
    )

    with pytest.raises(ValueError, match="kira"):
        execute_plan(store_path, plan.plan_id, adapter)
    assert called == []
