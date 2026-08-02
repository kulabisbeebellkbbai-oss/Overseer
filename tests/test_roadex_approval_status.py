from dataclasses import replace
from datetime import UTC, datetime
import json

import pytest

from overseer.admin import approve_admin_change_plan, cancel_admin_change_plan, plan_user_service_restart
from overseer.backup_provisioning import ProvisioningStatus
from overseer.crew import CrewMessageStatus, CrewReviewStatus
from overseer.roadex_approval_status import (
    RoadexApprovalBindingDraft,
    source_evidence_digest,
    roadex_approval_status,
    stage_bound_roadex_approval,
)
from overseer.serialization import to_jsonable
from overseer.store import SQLiteStore
from tests.test_backup_provisioning import seeded


EXPECTED_ADMIN_SOURCE_DIGEST = "sha256:80fce5400b5b6ea41928cdb93766cd316c39016e7c7ffc9279b77700c1cd48d0"
EXPECTED_ADMIN_SCOPE_DIGEST = "sha256:4f2a8297cbd8be9a23fb84251d0d79b3a38190f3f165224024639128b8d8fe54"
EXPECTED_HUMAN_PLAN_DIGEST = "sha256:0d127cc1d582dac8f751948249558ede0190035ba49b764ccd2bd87b773843a9"
EXPECTED_HUMAN_SCOPE_DIGEST = "sha256:d917e202d315c06a436f795bc9c700805c6c457c3e4ab1bbddab51485e2d4d87"


def _draft_for(approval_ref: str, source_kind: str = "admin-plan", source_id: str = "") -> RoadexApprovalBindingDraft:
    return RoadexApprovalBindingDraft(
        approval_ref=approval_ref,
        source_kind=source_kind,
        source_id=source_id or approval_ref,
        project_id="project.test",
        workspace_id="workspace.test",
        resource_ref="service.test",
        authority_class="privileged-operation",
        subject="Restart test service",
    )


def _roadex_payload(plan) -> str:
    return json.dumps(to_jsonable(plan), sort_keys=True, separators=(",", ":"))


def _write_roadex_plan(store: SQLiteStore, plan) -> None:
    store._connection.execute(
        "CREATE TABLE IF NOT EXISTS backup_provisioning_plans (id TEXT PRIMARY KEY, payload TEXT NOT NULL)",
    )
    store._connection.execute(
        "INSERT OR REPLACE INTO backup_provisioning_plans (id, payload) VALUES (?, ?)",
        (plan.plan_id, _roadex_payload(plan)),
    )
    store._connection.commit()


def test_bound_source_and_scope_are_one_transaction(tmp_path):
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        binding = stage_bound_roadex_approval(
            store,
            _draft_for("admin.roadex.test"),
            lambda: store.save_admin_change_plan(
                plan_user_service_restart(
                    "admin.roadex.test",
                    "roadex-test.service",
                    "Approval projection fixture",
                )
            ),
        )
        assert store.load_roadex_approval_binding(binding.approval_ref) == binding
        assert binding.scope_digest.startswith("sha256:")


def test_scope_digest_uses_exact_contract_for_admin_source(tmp_path):
    source = plan_user_service_restart(
        "admin.roadex.test",
        "roadex-test.service",
        "Digest fixture",
    )
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        binding = stage_bound_roadex_approval(
            store,
            _draft_for("admin.roadex.test"),
            lambda: store.save_admin_change_plan(source),
        )

    assert source_evidence_digest(source) == EXPECTED_ADMIN_SOURCE_DIGEST
    assert binding.scope_digest == EXPECTED_ADMIN_SCOPE_DIGEST


def test_legacy_unbound_source_fails_closed(tmp_path):
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        store.save_admin_change_plan(
            plan_user_service_restart(
                "admin.legacy",
                "roadex-test.service",
                "Legacy approval fixture",
            )
        )
    with pytest.raises(KeyError, match="bound Roadex approval"):
        roadex_approval_status(str(path), "admin.legacy")


def test_stage_bound_roadex_approval_is_idempotent_for_identical_replay(tmp_path):
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        plan = plan_user_service_restart(
            "admin.roadex.test",
            "roadex-test.service",
            "Approval projection fixture",
        )
        draft = _draft_for("admin.roadex.test")
        callback = lambda: store.save_admin_change_plan(plan)
        first = stage_bound_roadex_approval(store, draft, callback)
        second = stage_bound_roadex_approval(store, draft, callback)

        assert first == second
        assert first.created_at == second.created_at


def test_changed_binding_field_is_immutable_and_source_is_rollback_safe(tmp_path):
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        original = plan_user_service_restart(
            "admin.roadex.test",
            "roadex-test.service",
            "Original approval fixture",
        )
        draft = _draft_for("admin.roadex.test")

        stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.save_admin_change_plan(original),
        )

        with pytest.raises(ValueError, match="immutable"):
            stage_bound_roadex_approval(
                store,
                replace(draft, subject="Different subject"),
                lambda: store.save_admin_change_plan(
                    plan_user_service_restart(
                        "admin.roadex.test",
                        "roadex-test.service",
                        "Rollback test fixture",
                    )
                ),
            )

        rebound = store.load_admin_change_plan("admin.roadex.test")
        assert rebound == original


def test_source_save_exception_rolls_back_binding(tmp_path):
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        draft = _draft_for("admin.roadex.test")

        def save_and_fail() -> None:
            store.save_admin_change_plan(
                plan_user_service_restart(
                    "admin.roadex.test",
                    "roadex-test.service",
                    "Approval projection fixture",
                )
            )
            raise ValueError("source staging failed")

        with pytest.raises(ValueError, match="source staging failed"):
            stage_bound_roadex_approval(store, draft, save_and_fail)

        with pytest.raises(KeyError, match="admin.roadex.test"):
            store.load_roadex_approval_binding(draft.approval_ref)


def test_source_evidence_fails_closed_when_binding_created_without_source_match(tmp_path):
    path = tmp_path / "state.sqlite3"
    draft = _draft_for("admin.roadex.test")
    plan = plan_user_service_restart(
        "admin.roadex.test",
        "roadex-test.service",
        "Approval projection fixture",
    )
    with SQLiteStore(path) as store:
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.save_admin_change_plan(plan),
        )
        wrong = replace(plan, id="admin.roadex.tampered")
        store._connection.execute(
            "UPDATE admin_change_plans SET payload=? WHERE id=?",
            (_roadex_payload(wrong), plan.id),
        )
        store._connection.commit()

    with pytest.raises(ValueError, match="admin source id"):
        roadex_approval_status(str(path), draft.approval_ref)


def test_roadex_human_scope_and_source_evidence_digest_use_exact_contract(tmp_path):
    path, plan = seeded(tmp_path / "backups")
    with SQLiteStore(path) as store:
        _write_roadex_plan(store, plan)
        draft = _draft_for("admin.roadex.human", source_kind="roadex-human-decision", source_id=plan.plan_id)
        binding = stage_bound_roadex_approval(
            store,
            draft,
            lambda: _write_roadex_plan(store, plan),
        )

    assert source_evidence_digest(plan) == EXPECTED_HUMAN_PLAN_DIGEST
    assert binding.scope_digest == EXPECTED_HUMAN_SCOPE_DIGEST


def test_tampered_source_evidence_fails_closed(tmp_path):
    path = tmp_path / "state.sqlite3"
    draft = _draft_for("admin.roadex.test")
    original = plan_user_service_restart(
        "admin.roadex.test",
        "roadex-test.service",
        "Approval projection fixture",
    )
    with SQLiteStore(path) as store:
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.save_admin_change_plan(original),
        )

    with SQLiteStore(path) as store:
        store.save_admin_change_plan(
            replace(
                original,
                reason="Tampered reason",
            )
        )
        with pytest.raises(ValueError, match="digest no longer matches source"):
            roadex_approval_status(str(path), draft.approval_ref)


def test_binding_created_at_is_immutable(tmp_path):
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        draft = _draft_for("admin.roadex.test")
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.save_admin_change_plan(
                plan_user_service_restart(
                    "admin.roadex.test",
                    "roadex-test.service",
                    "Approval projection fixture",
                )
            ),
        )
        original = store.load_roadex_approval_binding(draft.approval_ref)
        with pytest.raises(ValueError, match="immutable"):
            store.save_roadex_approval_binding(replace(original, created_at="2000-01-01T00:00:00"))


def test_admin_plan_projection_statuses_are_expected(tmp_path):
    with SQLiteStore(tmp_path / "admin.sqlite3") as store:
        plan = plan_user_service_restart(
            "admin.roadex.terminal",
            "roadex-test.service",
            "Terminal approval fixture",
        )
        draft = _draft_for("admin.roadex.terminal")
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.save_admin_change_plan(plan),
        )

        pending = roadex_approval_status(str(store.path), "admin.roadex.terminal")
        assert pending["decision"] == "pending"

        now = datetime.now(UTC).isoformat()
        store.save_admin_change_plan(approve_admin_change_plan(plan, "operator", now))
        approved = roadex_approval_status(str(store.path), "admin.roadex.terminal")
        assert approved["decision"] == "approved"

        rejected = cancel_admin_change_plan(
            approve_admin_change_plan(plan, "operator", now),
            "operator",
            "Denied request",
            now,
        )
        store.save_admin_change_plan(rejected)
        cancelled = roadex_approval_status(str(store.path), "admin.roadex.terminal")
        assert cancelled["decision"] == "rejected"


@pytest.mark.parametrize(
    ("status", "decision"),
    (
        (ProvisioningStatus.STAGED, "pending"),
        (ProvisioningStatus.DENIED, "rejected"),
        (ProvisioningStatus.REVISION_REQUESTED, "changes-requested"),
        (ProvisioningStatus.APPROVED, "approved"),
        (ProvisioningStatus.EXECUTED, "approved"),
        (ProvisioningStatus.FAILED, "approved"),
        (ProvisioningStatus.ROLLED_BACK, "approved"),
    ),
)
def test_roadex_human_status_projection_maps_all_statuses(tmp_path, status, decision):
    path, plan = seeded(tmp_path / "backups")
    with SQLiteStore(path) as store:
        _write_roadex_plan(store, plan)
        now = datetime.now(UTC).isoformat()

        draft = _draft_for(
            "admin.roadex.human",
            source_kind="roadex-human-decision",
            source_id=plan.plan_id,
        )
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: _write_roadex_plan(store, plan),
        )

        if status == ProvisioningStatus.STAGED:
            projected = plan
        elif status in {ProvisioningStatus.DENIED, ProvisioningStatus.REVISION_REQUESTED}:
            projected = replace(plan, status=status, decided_by="human-user", decided_at=now)
        elif status in {ProvisioningStatus.APPROVED, ProvisioningStatus.EXECUTED}:
            projected = replace(
                plan,
                status=status,
                approved_by="human-user",
                approved_at=now,
                executed_at=now if status == ProvisioningStatus.EXECUTED else None,
            )
        else:
            projected = replace(
                plan,
                status=status,
                approved_by="human-user",
                approved_at=now,
                decided_by="human-user",
                decided_at=now,
                executed_at=now,
            )

        _write_roadex_plan(store, projected)
        projection = roadex_approval_status(path, draft.approval_ref)

    assert projection["sourceKind"] == "roadex-human-decision"
    assert projection["decision"] == decision


@pytest.mark.parametrize("status", (ProvisioningStatus.FAILED, ProvisioningStatus.ROLLED_BACK))
def test_roadex_human_terminal_status_without_approved_evidence_is_rejected(tmp_path, status):
    path, plan = seeded(tmp_path / "backups")
    with SQLiteStore(path) as store:
        _write_roadex_plan(store, plan)
        draft = _draft_for(
            "admin.roadex.human",
            source_kind="roadex-human-decision",
            source_id=plan.plan_id,
        )
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: _write_roadex_plan(store, plan),
        )
        now = datetime.now(UTC).isoformat()
        for evidence_id in plan.evidence_ids.values():
            message = store.load_crew_message(evidence_id)
            store.save_crew_message(
                message.__class__(
                    **{
                        **message.__dict__,
                        "status": CrewMessageStatus.OPEN,
                        "review_status": CrewReviewStatus.PENDING,
                        "decided_by": None,
                        "decided_at": None,
                    }
                )
            )
        _write_roadex_plan(store, replace(plan, status=status, executed_at=now))

        with pytest.raises(ValueError, match="terminal approved"):
            roadex_approval_status(path, draft.approval_ref)


def test_roadex_approval_projection_is_public_and_exact(tmp_path):
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        draft = _draft_for("admin.roadex.test")
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.save_admin_change_plan(
                plan_user_service_restart(
                    "admin.roadex.test",
                    "roadex-test.service",
                    "Approval projection fixture",
                )
            ),
        )
        projection = roadex_approval_status(str(store.path), draft.approval_ref)

    assert set(projection) == {
        "approvalRef",
        "sourceKind",
        "projectId",
        "workspaceId",
        "resourceRef",
        "authorityClass",
        "subject",
        "scopeDigest",
        "decision",
        "decisionVersion",
        "updatedAt",
    }
    assert "path" not in projection
    assert "command" not in projection
    assert "reason" not in projection
    assert "credentials" not in projection
    assert "error" not in projection
    assert "body" not in projection


@pytest.mark.parametrize(
    ("mutator", "expected"),
    (
        (lambda plan: replace(plan, plan_id="backup-provision.tampered"), "source id"),
        (lambda plan: replace(plan, kind="bad-plan-kind"), "exact kind"),
        (lambda plan: replace(plan, decision_source="Manual"), "Roadex decision source"),
        (lambda plan: replace(plan, plan_digest="sha256:" + "0" * 64), "plan digest"),
    ),
)
def test_roadex_human_plan_contract_validation_rejects_bad_source_records(tmp_path, mutator, expected):
    path, source = seeded(tmp_path / "backups")
    with SQLiteStore(path) as store:
        _write_roadex_plan(store, source)
        draft = _draft_for(
            "admin.roadex.human",
            source_kind="roadex-human-decision",
            source_id=source.plan_id,
        )
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: _write_roadex_plan(store, source),
        )
        mutated = mutator(source)
        store._connection.execute(
            "INSERT OR REPLACE INTO backup_provisioning_plans (id, payload) VALUES (?, ?)",
            (source.plan_id, _roadex_payload(mutated)),
        )
        store._connection.commit()

    with pytest.raises(ValueError, match=expected):
        roadex_approval_status(path, "admin.roadex.human")
