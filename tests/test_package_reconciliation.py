from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from overseer.packages import package_inspection_record

from .package_workflow_fixtures import bash_update, blocked_execution, initialized_store, package_snapshot


def test_package_record_identity_is_content_addressed_when_timestamps_match() -> None:
    first = package_inspection_record(
        package_snapshot("2026-08-09T12:00:00Z", bash_update("5.2"))
    )
    second = package_inspection_record(
        package_snapshot("2026-08-09T12:00:00Z", bash_update("5.3"))
    )
    assert first.id != second.id


def test_package_record_store_is_insert_only_and_idempotent(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    record = package_inspection_record(
        package_snapshot("2026-08-09T12:00:00Z", bash_update("5.2"))
    )
    store.save_package_inspection_record(record)
    store.save_package_inspection_record(record)
    with pytest.raises(ValueError, match="immutable package inspection collision"):
        store.save_package_inspection_record(replace(record, stderr="changed"))


def test_admin_execution_rolls_back_with_outer_agent_transaction(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    with pytest.raises(RuntimeError):
        with store.agent_transaction():
            store.save_admin_execution(blocked_execution("admin.test"))
            raise RuntimeError("rollback")
    assert store.list_admin_executions() == ()
