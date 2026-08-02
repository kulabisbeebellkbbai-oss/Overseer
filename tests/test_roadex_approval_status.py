from dataclasses import replace
from datetime import UTC, datetime
import json

import pytest

from overseer.admin import approve_admin_change_plan, cancel_admin_change_plan, plan_user_service_restart
from overseer.backup_provisioning import ProvisioningStatus
from overseer.roadex_approval_status import (
    RoadexApprovalBindingDraft,
    roadex_approval_status,
    stage_bound_roadex_approval,
)
from overseer.serialization import to_jsonable
from overseer.store import SQLiteStore
from tests.test_backup_provisioning import seeded


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


def test_admin_and_roadex_human_decision_mappings_are_deterministic(tmp_path):
    with SQLiteStore(tmp_path / "admin.sqlite3") as store:
        plan = plan_user_service_restart(
            "admin.roadex.terminal",
            "roadex-test.service",
            "Terminal approval fixture",
        )
        draft = _draft_for("admin.roadex.terminal")
        stage_bound_roadex_approval(store, draft, lambda: store.save_admin_change_plan(plan))

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

    with SQLiteStore(tmp_path / "human.sqlite3") as store:
        path = str(store.path)
        store_path, plan = seeded(tmp_path / "backups")
        _write_roadex_plan(store, plan)

        draft = _draft_for("admin.roadex.human", source_kind="roadex-human-decision", source_id=plan.plan_id)
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: _write_roadex_plan(store, plan),
        )

        staged = roadex_approval_status(path, draft.approval_ref)
        assert staged["decision"] == "pending"
        assert staged["sourceKind"] == "roadex-human-decision"

        now = datetime.now(UTC).isoformat()
        denied = replace(plan, status=ProvisioningStatus.DENIED, decided_by="human-user", decided_at=now)
        _write_roadex_plan(store, denied)
        denied_projection = roadex_approval_status(path, draft.approval_ref)
        assert denied_projection["decision"] == "rejected"

        revised = replace(plan, status=ProvisioningStatus.REVISION_REQUESTED, decided_by="human-user", decided_at=now)
        _write_roadex_plan(store, revised)
        revised_projection = roadex_approval_status(path, draft.approval_ref)
        assert revised_projection["decision"] == "changes-requested"

        approved = replace(plan, status=ProvisioningStatus.APPROVED, approved_by="human-user", approved_at=now)
        _write_roadex_plan(store, approved)
        approved_projection = roadex_approval_status(path, draft.approval_ref)
        assert approved_projection["decision"] == "approved"

        executed = replace(approved, status=ProvisioningStatus.EXECUTED, executed_at=now)
        _write_roadex_plan(store, executed)
        executed_projection = roadex_approval_status(path, draft.approval_ref)
        assert executed_projection["decision"] == "approved"


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
