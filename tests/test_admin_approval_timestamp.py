from datetime import datetime

from overseer.admin import approve_admin_change_plan, plan_user_service_restart
from overseer.cli import approve_admin_change_status
from overseer.store import SQLiteStore


def test_generic_admin_approval_stamps_timezone_aware_utc_when_omitted():
    plan = plan_user_service_restart("admin.test.timestamp", "example.service", "test approval timestamp", "active")
    approved = approve_admin_change_plan(plan, "human")
    timestamp = datetime.fromisoformat(approved.approved_at)
    assert timestamp.tzinfo is not None
    assert approved.approved_at.endswith("+00:00")


def test_generic_admin_approval_preserves_explicit_timestamp():
    plan = plan_user_service_restart("admin.test.explicit-timestamp", "example.service", "test explicit timestamp", "active")
    approved = approve_admin_change_plan(plan, "human", "2026-08-16T12:34:56+00:00")
    assert approved.approved_at == "2026-08-16T12:34:56+00:00"


def test_approve_admin_change_status_ui_style_stamps_and_persists_timestamp(tmp_path):
    store_path = tmp_path / "overseer.sqlite3"
    with SQLiteStore(store_path) as store:
        store.save_admin_change_plan(plan_user_service_restart("admin.test.api-timestamp", "example.service", "test API timestamp", "active"))
    status = approve_admin_change_status(store_path, "admin.test.api-timestamp", "sisko")
    timestamp = datetime.fromisoformat(status["approved_at"])
    assert timestamp.tzinfo is not None
    with SQLiteStore(store_path) as store:
        assert store.load_admin_change_plan("admin.test.api-timestamp").approved_at == status["approved_at"]
