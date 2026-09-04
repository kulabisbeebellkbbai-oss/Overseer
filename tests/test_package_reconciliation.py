from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from overseer.packages import (
    PackageInspectionSnapshot,
    PackageReconciliationEvidence,
    PackageUpdate,
    package_inspection_record,
)
from overseer.store import CURRENT_SCHEMA_VERSION, SQLiteStore


def bash_update(version: str = "5.2") -> PackageUpdate:
    return PackageUpdate(
        name="bash",
        repository="stable",
        candidate_version=version,
        architecture="amd64",
        installed_version="5.1",
    )


def package_snapshot(captured_at: str, *updates: PackageUpdate) -> PackageInspectionSnapshot:
    return PackageInspectionSnapshot(
        id=f"package-inspection.{captured_at}",
        captured_at=captured_at,
        command=("apt", "list", "--upgradable"),
        exit_code=0,
        updates=tuple(updates),
    )


def reconciliation_evidence(outcome: str = "no-op") -> PackageReconciliationEvidence:
    return PackageReconciliationEvidence(
        id="package-reconciliation.evidence.1",
        snapshot_id="package-inspection.snapshot.1",
        maintenance_batch_id="maintenance.batch.1",
        observed_at="2026-08-24T12:00:00Z",
        outcome=outcome,
        plan_ids=("plan.1",),
        message_ids=("message.1",),
    )


def _concurrent_saves(
    path: Path,
    method_name: str,
    records: tuple[object, object],
) -> list[tuple[str, BaseException | None]]:
    ready = threading.Barrier(3)
    outcomes: list[tuple[str, BaseException | None]] = []
    outcomes_lock = threading.Lock()

    def worker(record: object) -> None:
        try:
            with SQLiteStore(path) as store:
                ready.wait(timeout=10)
                getattr(store, method_name)(record)
        except BaseException as exc:
            with outcomes_lock:
                outcomes.append(("error", exc))
        else:
            with outcomes_lock:
                outcomes.append(("ok", None))

    threads = [threading.Thread(target=worker, args=(record,)) for record in records]
    for thread in threads:
        thread.start()
    ready.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    return outcomes


def test_package_record_identity_changes_with_package_state() -> None:
    first = package_inspection_record(
        package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2"))
    )
    second = package_inspection_record(
        package_snapshot("2026-08-24T12:00:00Z", bash_update("5.3"))
    )

    assert first.id != second.id


def test_package_record_store_is_insert_only(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        record = package_inspection_record(
            package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2"))
        )

        store.save_package_inspection_record(record)
        store.save_package_inspection_record(record)

        with pytest.raises(ValueError, match="immutable package inspection collision"):
            store.save_package_inspection_record(replace(record, stderr="changed"))

        assert store.load_package_inspection_record(record.id) == record
        assert store.list_package_inspection_records() == (record,)


def test_package_record_exact_concurrent_retries_are_idempotent(tmp_path: Path) -> None:
    record = package_inspection_record(
        package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2"))
    )

    outcomes = _concurrent_saves(
        tmp_path / "state.sqlite3",
        "save_package_inspection_record",
        (record, record),
    )

    assert outcomes == [("ok", None), ("ok", None)]


def test_package_record_conflicting_concurrent_writes_reject_without_sqlite_error(
    tmp_path: Path,
) -> None:
    record = package_inspection_record(
        package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2"))
    )

    outcomes = _concurrent_saves(
        tmp_path / "state.sqlite3",
        "save_package_inspection_record",
        (replace(record, stderr="left"), replace(record, stderr="right")),
    )

    assert sorted(outcome[0] for outcome in outcomes) == ["error", "ok"]
    errors = [error for outcome, error in outcomes if outcome == "error"]
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)
    assert not isinstance(errors[0], sqlite3.IntegrityError)
    assert "immutable package inspection collision" in str(errors[0])


def test_package_reconciliation_evidence_is_insert_only(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        evidence = reconciliation_evidence()

        store.save_package_reconciliation_evidence(evidence)
        store.save_package_reconciliation_evidence(evidence)

        with pytest.raises(
            ValueError,
            match="immutable package reconciliation evidence collision",
        ):
            store.save_package_reconciliation_evidence(
                replace(evidence, outcome="approved")
            )

        assert store.load_package_reconciliation_evidence(evidence.id) == evidence
        assert store.list_package_reconciliation_evidence() == (evidence,)


def test_package_evidence_saves_join_outer_agent_transaction(tmp_path: Path) -> None:
    record = package_inspection_record(
        package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2"))
    )
    evidence = reconciliation_evidence()

    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        with pytest.raises(RuntimeError, match="rollback"):
            with store.agent_transaction():
                store.save_package_inspection_record(record)
                store.save_package_reconciliation_evidence(evidence)
                raise RuntimeError("rollback")

        assert store.list_package_inspection_records() == ()
        assert store.list_package_reconciliation_evidence() == ()


def test_package_evidence_exact_concurrent_retries_are_idempotent(tmp_path: Path) -> None:
    evidence = reconciliation_evidence()

    outcomes = _concurrent_saves(
        tmp_path / "state.sqlite3",
        "save_package_reconciliation_evidence",
        (evidence, evidence),
    )

    assert outcomes == [("ok", None), ("ok", None)]


def test_package_evidence_conflicting_concurrent_writes_reject_without_sqlite_error(
    tmp_path: Path,
) -> None:
    evidence = reconciliation_evidence()

    outcomes = _concurrent_saves(
        tmp_path / "state.sqlite3",
        "save_package_reconciliation_evidence",
        (replace(evidence, outcome="left"), replace(evidence, outcome="right")),
    )

    assert sorted(outcome[0] for outcome in outcomes) == ["error", "ok"]
    errors = [error for outcome, error in outcomes if outcome == "error"]
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)
    assert not isinstance(errors[0], sqlite3.IntegrityError)
    assert "immutable package reconciliation evidence collision" in str(errors[0])


@pytest.mark.parametrize(
    "missing_tables",
    [
        ("package_inspection_records",),
        ("package_reconciliation_evidence",),
        ("package_inspection_records", "package_reconciliation_evidence"),
    ],
)
def test_schema_v11_repairs_missing_package_tables_and_preserves_history_and_data(
    tmp_path: Path,
    missing_tables: tuple[str, ...],
) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        record = package_inspection_record(
            package_snapshot("2026-08-24T12:00:00Z", bash_update("5.2"))
        )
        evidence = reconciliation_evidence()
        store.save_package_inspection_record(record)
        store.save_package_reconciliation_evidence(evidence)
        store._connection.execute(
            "INSERT INTO resources(id, payload) VALUES (?, ?)",
            ("resource.preserved", '{"preserved":true}'),
        )
        store._connection.commit()
        history_before = store.list_schema_migrations()

    with sqlite3.connect(path) as connection:
        for table in missing_tables:
            connection.execute(f"DROP TABLE {table}")
        connection.commit()

    with SQLiteStore(path) as store:
        tables = {
            row[0]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "package_inspection_records",
            "package_reconciliation_evidence",
        } <= tables
        assert store._connection.execute(
            "SELECT payload FROM resources WHERE id=?", ("resource.preserved",)
        ).fetchone()[0] == '{"preserved":true}'
        assert store.list_schema_migrations() == history_before
        store.save_package_inspection_record(record)
        store.save_package_reconciliation_evidence(evidence)
        assert max(
            row.version
            for row in store.list_schema_migrations()
            if isinstance(row.version, int)
        ) == CURRENT_SCHEMA_VERSION


def test_package_evidence_migration_advances_from_schema_v10(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        store._connection.execute(
            "INSERT INTO resources(id, payload) VALUES (?, ?)",
            ("resource.preserved", '{"preserved":true}'),
        )
        store._connection.execute("DELETE FROM schema_migrations")
        store._connection.execute(
            "INSERT INTO schema_migrations(version, description, applied_at) "
            "VALUES (?, ?, ?)",
            (10, "schema v10", "2026-08-24T00:00:00Z"),
        )
        store._connection.commit()

    with SQLiteStore(path) as store:
        tables = {
            row[0]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "package_inspection_records",
            "package_reconciliation_evidence",
        } <= tables
        assert store._connection.execute(
            "SELECT payload FROM resources WHERE id=?", ("resource.preserved",)
        ).fetchone()[0] == '{"preserved":true}'
        integer_versions = [
            row.version
            for row in store.list_schema_migrations()
            if isinstance(row.version, int)
        ]
        assert integer_versions[-2:] == [10, CURRENT_SCHEMA_VERSION]
        assert CURRENT_SCHEMA_VERSION == 13
