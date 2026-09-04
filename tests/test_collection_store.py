from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from queue import Queue

import pytest

from overseer import (
    CollectionJob,
    CollectionJobKind,
    CollectionJobState,
    CollectionOutcome,
    CollectionRun,
    OwnerDomain,
    RepairAttempt,
    RepairPolicy,
    RepairRunbook,
    RiskLevel,
    SQLiteStore,
    TriageIncident,
    TriageIncidentStatus,
)
from overseer.collection_deadline import collection_deadline_scope
from overseer.store import CURRENT_SCHEMA_VERSION


NOW = "2026-08-24T12:00:00+00:00"
LEASE_END = "2026-08-24T12:05:00+00:00"


def sample_job(job_id: str = "collection.health.api", **overrides: object) -> CollectionJob:
    values: dict[str, object] = {
        "id": job_id,
        "kind": CollectionJobKind.HEALTH_PROBE,
        "owner_domain": OwnerDomain.JULIAN,
        "resource_id": "service.api",
        "target_id": "health.api",
        "interval_seconds": 120,
        "jitter_seconds": 0,
        "timeout_seconds": 15,
        "priority": 10,
        "concurrency_key": "health",
        "retention_limit": 2,
        "max_backoff_seconds": 900,
        "failure_threshold": 3,
    }
    values.update(overrides)
    return CollectionJob(**values)


def sample_state(job_id: str = "collection.health.api", **overrides: object) -> CollectionJobState:
    values: dict[str, object] = {"job_id": job_id, "next_due_at": NOW}
    values.update(overrides)
    return CollectionJobState(**values)


def sample_run(
    run_id: str = "run.collection.health.api.1",
    *,
    outcome: CollectionOutcome = CollectionOutcome.SUCCEEDED,
    request_id: str | None = None,
    **overrides: object,
) -> CollectionRun:
    values: dict[str, object] = {
        "id": run_id,
        "job_id": "collection.health.api",
        "trigger": "scheduled",
        "started_at": NOW,
        "completed_at": LEASE_END,
        "outcome": outcome,
        "summary": "bounded result",
        "evidence_ids": ("evidence.health.api",),
        "request_id": request_id,
    }
    values.update(overrides)
    return CollectionRun(**values)


def sample_incident(**overrides: object) -> TriageIncident:
    values: dict[str, object] = {
        "id": "incident.collection.health.api.1",
        "job_id": "collection.health.api",
        "resource_id": "service.api",
        "first_failure_at": NOW,
        "latest_failure_at": NOW,
        "severity": RiskLevel.MEDIUM,
        "owner_domain": OwnerDomain.JULIAN,
    }
    values.update(overrides)
    return TriageIncident(**values)


def seeded_collection_store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "state.sqlite3")
    store.save_collection_job(sample_job(), sample_state())
    store.save_collection_job(
        sample_job("collection.health.worker", priority=5, concurrency_key="worker"),
        sample_state("collection.health.worker"),
    )
    return store


def test_schema_v13_is_normalized_and_repairs_claimed_current_missing_tables(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        store._connection.execute(
            "INSERT INTO package_inspection_records(id, payload) VALUES (?, ?)",
            ("package.preserved", '{"preserved":true}'),
        )
        store._connection.commit()
        for table in (
            "collection_jobs",
            "collection_job_states",
            "collection_requests",
            "collection_runs",
            "triage_incidents",
            "repair_runbooks",
            "repair_attempts",
        ):
            store._connection.execute(f"DROP TABLE {table}")
        store._connection.commit()

    with SQLiteStore(path) as store:
        names = {
            row[0]
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert {
            "collection_jobs",
            "collection_job_states",
            "collection_requests",
            "collection_runs",
            "triage_incidents",
            "repair_runbooks",
            "repair_attempts",
            "package_inspection_records",
        } <= names
        indexes = {
            row[1]
            for row in store._connection.execute("PRAGMA index_list(collection_jobs)")
        }
        assert "idx_collection_jobs_enabled_priority" in indexes
        assert store._connection.execute(
            "SELECT payload FROM package_inspection_records WHERE id=?",
            ("package.preserved",),
        ).fetchone()[0] == '{"preserved":true}'
        assert max(
            row.version for row in store.list_schema_migrations() if isinstance(row.version, int)
        ) == CURRENT_SCHEMA_VERSION == 13


def test_current_marked_store_recreates_missing_admin_execution_claim_table(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path):
        pass
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE admin_execution_claims")
        connection.commit()

    with SQLiteStore(path) as reopened:
        table = reopened._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            ("admin_execution_claims",),
        ).fetchone()
        assert table is not None
        assert reopened._schema_is_current()


def test_collection_context_rejects_current_marked_store_missing_admin_execution_claim_table(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path):
        pass
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE admin_execution_claims")
        connection.commit()

    with collection_deadline_scope(time.monotonic() + 5.0):
        with pytest.raises(RuntimeError, match="pre-migrated SQLite store"):
            SQLiteStore(path)

    with sqlite3.connect(path) as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            ("admin_execution_claims",),
        ).fetchone()
    assert table is None


def test_collection_context_refuses_to_initialize_or_migrate_a_store(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE preserved_marker (id TEXT PRIMARY KEY)")
        connection.commit()
    finally:
        connection.close()

    with collection_deadline_scope(time.monotonic() + 5.0):
        with pytest.raises(RuntimeError, match="pre-migrated SQLite store"):
            SQLiteStore(path)

    connection = sqlite3.connect(path)
    try:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        connection.close()
    assert tables == {"preserved_marker"}
    assert journal_mode == "delete"


def test_collection_context_does_not_create_a_missing_store(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"

    with collection_deadline_scope(time.monotonic() + 5.0):
        with pytest.raises(RuntimeError, match="pre-existing SQLite store"):
            SQLiteStore(path)

    assert not path.exists()


def test_collection_context_does_not_recreate_a_store_removed_during_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path):
        pass
    original_open = os.open
    removed = False

    def racing_open(open_path, flags, mode=0o777, *, dir_fd=None):
        nonlocal removed
        if Path(open_path) == path and not removed:
            removed = True
            path.unlink()
        return original_open(open_path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)
    with collection_deadline_scope(time.monotonic() + 5.0):
        with pytest.raises(RuntimeError, match="pre-existing SQLite store"):
            SQLiteStore(path)

    assert removed is True
    assert not path.exists()


def test_collection_context_refuses_to_reconfigure_a_non_wal_store(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path):
        pass
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
    finally:
        connection.close()

    with collection_deadline_scope(time.monotonic() + 5.0):
        with pytest.raises(RuntimeError, match="preconfigured WAL SQLite store"):
            SQLiteStore(path)

    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    finally:
        connection.close()


def test_dashboard_projection_round_trip_is_bounded(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        store.save_dashboard_projection(
            "dashboard.test",
            {"captured_at": NOW, "items": [{"status": "ok"}]},
        )
        assert store.load_dashboard_projection("dashboard.test") == {
            "captured_at": NOW,
            "items": [{"status": "ok"}],
        }
        with pytest.raises(ValueError, match="bounded limit"):
            store.save_dashboard_projection("dashboard.too-large", {"value": "x" * (512 * 1024)})


def test_dashboard_projection_batch_validates_before_atomic_write(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "state.sqlite3") as store:
        with pytest.raises(ValueError, match="bounded limit"):
            store.save_dashboard_projections(
                {
                    "dashboard.valid": {"status": "ok"},
                    "dashboard.too-large": {"value": "x" * (512 * 1024)},
                }
            )
        with pytest.raises(KeyError):
            store.load_dashboard_projection("dashboard.valid")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", CollectionJobKind.HOST_INSPECTION),
        ("owner_domain", OwnerDomain.DAX),
        ("resource_id", "service.other"),
        ("target_id", "health.other"),
    ],
)
def test_collection_job_identity_binding_is_immutable(
    tmp_path: Path, field: str, value: object
) -> None:
    with seeded_collection_store(tmp_path) as store:
        job = store.load_collection_job("collection.health.api")
        with pytest.raises(ValueError, match="immutable collection job binding"):
            store.save_collection_job(replace(job, **{field: value}))

        store.save_collection_job(replace(job, priority=1, interval_seconds=300))
        assert store.load_collection_job(job.id).priority == 1
        assert store.load_collection_job(job.id).interval_seconds == 300


def test_legacy_duplicate_open_incident_generation_is_repaired_without_sqlite_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with seeded_collection_store(tmp_path) as store:
        store._connection.execute("DROP INDEX idx_triage_open_generation")
        store._connection.commit()
        first = sample_incident(id="incident.legacy.first", generation=1)
        second = sample_incident(id="incident.legacy.second", generation=1)
        store.save_collection_incident(first)
        store.save_collection_incident(second)

    with SQLiteStore(path) as store:
        incidents = store.list_triage_incidents()
        assert sorted(incident.status.value for incident in incidents) == ["open", "resolved"]
        assert store._schema_is_current()
        assert store._connection.execute(
            "SELECT COUNT(*) FROM triage_incidents WHERE job_id=? AND generation=? AND status='open'",
            ("collection.health.api", 1),
        ).fetchone()[0] == 1


def test_complete_collection_run_nested_failure_rolls_back_when_outer_catches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with seeded_collection_store(tmp_path) as store:
        claimed = store.claim_due_collection_jobs(NOW, "worker-a", LEASE_END, limit=1)[0]
        state = store.load_collection_job_state(claimed.id)
        run = sample_run(outcome=CollectionOutcome.FAILED, error_category="unavailable")

        def fail_after_run_insert(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("injected incident failure")

        monkeypatch.setattr(store, "_open_collection_incident_in_transaction", fail_after_run_insert)
        with store.agent_transaction():
            try:
                store.complete_collection_run(
                    run,
                    lease_id=state.active_lease_id,
                    lease_generation=state.lease_generation,
                )
            except RuntimeError as error:
                assert str(error) == "injected incident failure"

        assert store.list_collection_runs() == ()
        assert store.list_triage_incidents() == ()
        assert store.load_collection_job_state(claimed.id).active_lease_id == state.active_lease_id


@pytest.mark.parametrize(
    ("index_name", "table", "malformed_sql"),
    [
        (
            "idx_collection_jobs_enabled_priority",
            "collection_jobs",
            "CREATE INDEX idx_collection_jobs_enabled_priority ON collection_jobs (priority)",
        ),
        (
            "idx_collection_job_state_due",
            "collection_job_states",
            "CREATE INDEX idx_collection_job_state_due ON collection_job_states (lease_expires_at)",
        ),
        (
            "idx_collection_runs_job_started",
            "collection_runs",
            "CREATE INDEX idx_collection_runs_job_started ON collection_runs (job_id, started_at)",
        ),
        (
            "idx_collection_runs_started",
            "collection_runs",
            "CREATE INDEX idx_collection_runs_started ON collection_runs (started_at)",
        ),
        (
            "idx_collection_runs_outcome_started",
            "collection_runs",
            "CREATE INDEX idx_collection_runs_outcome_started ON collection_runs (outcome, started_at)",
        ),
        (
            "idx_collection_runs_job_outcome_started",
            "collection_runs",
            "CREATE INDEX idx_collection_runs_job_outcome_started ON collection_runs (job_id, outcome)",
        ),
        (
            "idx_collection_request_pending_job",
            "collection_requests",
            "CREATE INDEX idx_collection_request_pending_job ON collection_requests (job_id)",
        ),
        (
            "idx_triage_open_generation",
            "triage_incidents",
            "CREATE INDEX idx_triage_open_generation ON triage_incidents (job_id)",
        ),
    ],
)
def test_reopen_repairs_same_named_scheduler_index_to_canonical_semantics(
    tmp_path: Path, index_name: str, table: str, malformed_sql: str
) -> None:
    path = tmp_path / "state.sqlite3"
    with seeded_collection_store(tmp_path) as store:
        store._connection.execute(f"DROP INDEX {index_name}")
        store._connection.execute(malformed_sql)
        store._connection.commit()

    with SQLiteStore(path) as store:
        assert store._schema_is_current()
        assert store._collection_index_is_canonical(index_name)
        assert store._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone() is not None


def test_v12_run_index_upgrade_does_not_repair_unrelated_unique_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.sqlite3"
    with seeded_collection_store(tmp_path):
        pass
    with sqlite3.connect(path) as connection:
        for index_name in (
            "idx_collection_runs_job_started",
            "idx_collection_runs_started",
            "idx_collection_runs_outcome_started",
            "idx_collection_runs_job_outcome_started",
        ):
            connection.execute(f"DROP INDEX IF EXISTS {index_name}")
        connection.execute(
            "CREATE INDEX idx_collection_runs_job_started "
            "ON collection_runs (job_id, started_at DESC)"
        )
        connection.execute(
            "DELETE FROM schema_migrations WHERE version > 12"
        )
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, description, applied_at) "
            "VALUES (12, 'legacy collection index contract', ?)",
            (NOW,),
        )
        connection.commit()

    monkeypatch.setattr(
        SQLiteStore,
        "_repair_collection_index_rows_in_transaction",
        lambda *_args, **_kwargs: pytest.fail(
            "v12 run-index upgrade invoked unrelated uniqueness repair"
        ),
    )

    with SQLiteStore(path) as store:
        assert store._schema_is_current()
        assert max(
            row.version
            for row in store.list_schema_migrations()
            if isinstance(row.version, int)
        ) == CURRENT_SCHEMA_VERSION


def test_reopen_repairs_same_named_collection_index_with_wrong_collation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with seeded_collection_store(tmp_path) as store:
        store._connection.execute("DROP INDEX idx_collection_runs_started")
        store._connection.execute(
            "CREATE INDEX idx_collection_runs_started ON collection_runs "
            "(started_at COLLATE NOCASE DESC, id DESC)"
        )
        store._connection.commit()

    with SQLiteStore(path) as store:
        keyed_columns = store._connection.execute(
            "SELECT name, coll FROM pragma_index_xinfo(?) "
            "WHERE key=1 ORDER BY seqno",
            ("idx_collection_runs_started",),
        ).fetchall()

    assert [(str(row["name"]), str(row["coll"])) for row in keyed_columns] == [
        ("started_at", "BINARY"),
        ("id", "BINARY"),
    ]


def test_repaired_pending_index_remains_race_safe_for_request_coalescing(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with seeded_collection_store(tmp_path) as store:
        store._connection.execute("DROP INDEX idx_collection_request_pending_job")
        store._connection.execute(
            "CREATE INDEX idx_collection_request_pending_job ON collection_requests (job_id)"
        )
        store._connection.commit()

    with SQLiteStore(path) as store:
        assert store._collection_index_is_canonical("idx_collection_request_pending_job")
        first = store.request_collection_run("collection.health.api", "operator", "verify")
        second = store.request_collection_run("collection.health.api", "operator", "verify again")
        assert first.id == second.id
        assert len(store.list_collection_requests()) == 1


def test_repaired_incident_index_rejects_generation_collision_without_raw_sqlite_error(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with seeded_collection_store(tmp_path) as store:
        store._connection.execute("DROP INDEX idx_triage_open_generation")
        store._connection.execute(
            "CREATE INDEX idx_triage_open_generation ON triage_incidents (job_id)"
        )
        store._connection.commit()

    with SQLiteStore(path) as store:
        assert store._collection_index_is_canonical("idx_triage_open_generation")
        store.save_collection_incident(sample_incident(id="incident.first"))
        with pytest.raises(ValueError, match="generation collision"):
            store.save_collection_incident(sample_incident(id="incident.second"))


def test_v11_fixture_migrates_to_v13_preserving_package_data_and_history(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    package_payload = '{"package":"preserved-v11"}'
    with SQLiteStore(path) as store:
        store._connection.execute(
            "INSERT INTO package_inspection_records(id, payload) VALUES (?, ?)",
            ("package.v11", package_payload),
        )
        for table in (
            "collection_jobs",
            "collection_job_states",
            "collection_requests",
            "collection_runs",
            "triage_incidents",
            "repair_runbooks",
            "repair_attempts",
        ):
            store._connection.execute(f"DROP TABLE {table}")
        store._connection.execute("DELETE FROM schema_migrations WHERE version=?", (12,))
        store._connection.execute(
            "INSERT INTO schema_migrations(version, description, applied_at) VALUES (?, ?, ?)",
            (11, "schema v11 fixture", NOW),
        )
        store._connection.commit()

    with SQLiteStore(path) as store:
        integer_versions = [
            row.version for row in store.list_schema_migrations() if isinstance(row.version, int)
        ]
        assert integer_versions == [3, 11, 13]
        assert store._connection.execute(
            "SELECT payload FROM package_inspection_records WHERE id=?", ("package.v11",)
        ).fetchone()[0] == package_payload
        assert store._schema_is_current()


def test_claim_due_jobs_is_atomic_and_respects_limit(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        path = str(store.path)

    results: Queue[tuple[str, tuple[CollectionJob, ...]]] = Queue()

    def claim(worker: str) -> None:
        with SQLiteStore(path) as worker_store:
            results.put((worker, worker_store.claim_due_collection_jobs(NOW, worker, LEASE_END, limit=2)))

    threads = [threading.Thread(target=claim, args=(worker,)) for worker in ("worker-a", "worker-b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    claimed = [item for _, jobs in (results.get() for _ in threads) for item in jobs]
    assert len(claimed) == 2
    assert len({job.id for job in claimed}) == 2
    assert {job.id for job in claimed} == {
        "collection.health.api",
        "collection.health.worker",
    }

    with SQLiteStore(path) as store:
        states = [store.load_collection_job_state(job.id) for job in claimed]
        assert all(state.active_lease_id and state.lease_generation == 1 for state in states)


def test_exact_claim_compare_and_set_does_not_claim_a_different_eligible_job(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    first = sample_job("collection.shared.first", priority=100, concurrency_key="shared")
    second = sample_job("collection.shared.second", priority=90, concurrency_key="shared")
    other = sample_job("collection.other", priority=1, concurrency_key="other")
    with SQLiteStore(path) as store:
        for job in (first, second, other):
            store.save_collection_job(job, sample_state(job.id))
        assert store.claim_due_collection_jobs(
            NOW, "worker-a", LEASE_END, limit=1, job_id=first.id
        ) == (first,)
        assert store.claim_due_collection_jobs(
            NOW, "worker-b", LEASE_END, limit=1, job_id=second.id
        ) == ()
        assert store.claim_due_collection_jobs(
            NOW, "worker-b", LEASE_END, limit=1, job_id=other.id
        ) == (other,)

        assert store.load_collection_job_state(second.id).active_lease_id is None
        assert store.load_collection_job_state(other.id).active_lease_id is not None


def test_collection_key_lease_exclusion_is_durable_across_connections_and_expiry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    first = sample_job("collection.shared.first", priority=100, concurrency_key="shared")
    second = sample_job(
        "collection.shared.second", priority=90, concurrency_key="shared"
    )
    other = sample_job("collection.other", priority=1, concurrency_key="other")
    with SQLiteStore(path) as seeded:
        for job in (first, second, other):
            seeded.save_collection_job(job, sample_state(job.id))

    with SQLiteStore(path) as worker_a, SQLiteStore(path) as worker_b:
        assert worker_a.claim_due_collection_jobs(
            NOW, "worker-a", LEASE_END, limit=1, job_id=first.id
        ) == (first,)
        assert worker_b.claim_due_collection_jobs(
            NOW, "worker-b", LEASE_END, limit=1, job_id=second.id
        ) == ()
        assert worker_b.claim_due_collection_jobs(
            NOW, "worker-b", LEASE_END, limit=1, job_id=other.id
        ) == (other,)

        assert worker_b.claim_due_collection_jobs(
            "2026-08-24T12:06:00+00:00",
            "worker-b",
            "2026-08-24T12:11:00+00:00",
            limit=1,
            job_id=second.id,
        ) == (second,)


def test_concurrent_store_connections_cannot_lease_the_same_concurrency_key(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    first = sample_job("collection.shared.first", priority=100, concurrency_key="shared")
    second = sample_job(
        "collection.shared.second", priority=90, concurrency_key="shared"
    )
    other = sample_job("collection.other", priority=1, concurrency_key="other")
    with SQLiteStore(path) as seeded:
        for job in (first, second, other):
            seeded.save_collection_job(job, sample_state(job.id))

    results: Queue[tuple[str, tuple[CollectionJob, ...]]] = Queue()

    def claim(worker: str) -> None:
        with SQLiteStore(path) as store:
            results.put(
                (
                    worker,
                    store.claim_due_collection_jobs(NOW, worker, LEASE_END, limit=1),
                )
            )

    threads = [threading.Thread(target=claim, args=(worker,)) for worker in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    claimed = [job for _worker, jobs in (results.get() for _ in threads) for job in jobs]
    assert {job.id for job in claimed} == {first.id, other.id}
    assert len(claimed) == 2
    with SQLiteStore(path) as store:
        assert store.load_collection_job_state(second.id).active_lease_id is None


def test_configuration_save_cannot_erase_concurrent_claim_lease(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "state.sqlite3")
    with SQLiteStore(path) as seeded:
        seeded.save_collection_job(sample_job(), sample_state())
        assert seeded.claim_due_collection_jobs(NOW, "worker-a", LEASE_END, limit=1)

    job = sample_job()
    snapshot_ready = threading.Event()
    release_snapshot = threading.Event()
    claim_started = threading.Event()
    claim_lock_acquired = threading.Event()
    results: Queue[tuple[str, object]] = Queue()

    def reseed_configuration() -> None:
        with SQLiteStore(path) as config_store:
            original_snapshot = config_store._load_collection_job_state_for_configuration

            def coordinated_snapshot(job_id: str) -> CollectionJobState | None:
                snapshot = original_snapshot(job_id)
                snapshot_ready.set()
                if not release_snapshot.wait(timeout=5):
                    raise RuntimeError("snapshot coordination timed out")
                return snapshot

            config_store._load_collection_job_state_for_configuration = coordinated_snapshot
            try:
                config_store.save_collection_job(replace(job, priority=1))
                results.put(("save", None))
            except BaseException as error:  # pragma: no cover - surfaced below
                results.put(("save-error", error))

    def claim() -> None:
        with SQLiteStore(path) as claim_store:
            claim_started.set()
            original_claim_transaction = claim_store.agent_transaction

            @contextmanager
            def observed_claim_transaction():
                with original_claim_transaction():
                    claim_lock_acquired.set()
                    yield

            claim_store.agent_transaction = observed_claim_transaction
            try:
                claimed = claim_store.claim_due_collection_jobs(
                    NOW, "worker-b", LEASE_END, limit=1
                )
                results.put(("claim", claimed))
            except BaseException as error:  # pragma: no cover - surfaced below
                results.put(("claim-error", error))

    save_thread = threading.Thread(target=reseed_configuration)
    claim_thread: threading.Thread | None = None
    save_thread.start()
    try:
        assert snapshot_ready.wait(timeout=5)
        claim_thread = threading.Thread(target=claim)
        claim_thread.start()
        assert claim_started.wait(timeout=5)
        assert not claim_lock_acquired.wait(timeout=0.5)
    finally:
        release_snapshot.set()
        save_thread.join(timeout=5)
        if claim_thread is not None:
            claim_thread.join(timeout=5)

    assert not save_thread.is_alive()
    assert claim_thread is not None and not claim_thread.is_alive()
    outcomes = [results.get_nowait() for _ in range(2)]
    assert sorted(kind for kind, _ in outcomes) == ["claim", "save"]
    assert next(value for kind, value in outcomes if kind == "claim") == ()

    with SQLiteStore(path) as store:
        state = store.load_collection_job_state(job.id)
        assert state.active_lease_id is not None
        assert state.lease_owner == "worker-a"
        assert state.lease_expires_at == LEASE_END
        assert state.lease_generation == 1


def test_operator_requests_coalesce_per_job_across_connections(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        path = str(store.path)

    results: Queue[str] = Queue()

    def request(reason: str) -> None:
        with SQLiteStore(path) as store:
            results.put(store.request_collection_run("collection.health.api", "operator", reason).id)

    threads = [threading.Thread(target=request, args=(reason,)) for reason in ("verify", "verify again")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert {results.get(), results.get()}.__len__() == 1


def test_collection_run_is_insert_only_and_collision_is_value_error(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        run = sample_run()
        store.save_collection_run(run)
        store.save_collection_run(run)
        with pytest.raises(ValueError, match="immutable collection run collision"):
            store.save_collection_run(replace(run, summary="changed"))


def test_complete_collection_run_is_atomic_and_resolves_incident(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        request = store.request_collection_run("collection.health.api", "operator", "verify")
        claimed = store.claim_due_collection_jobs(NOW, "worker-a", LEASE_END, limit=1)[0]
        state = store.load_collection_job_state(claimed.id)
        run = sample_run(request_id=request.id)
        store.complete_collection_run(
            run,
            lease_id=state.active_lease_id,
            lease_generation=state.lease_generation,
        )

        assert store.list_collection_runs() == (run,)
        assert store.load_collection_job_state(claimed.id).active_lease_id is None
        assert store.load_collection_job_state(claimed.id).last_outcome is CollectionOutcome.SUCCEEDED
        assert store.list_collection_requests()[0].status == "completed"
        assert store.list_triage_incidents() == ()


def test_failed_completion_opens_one_incident_per_generation(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        claimed = store.claim_due_collection_jobs(NOW, "worker-a", LEASE_END, limit=1)[0]
        state = store.load_collection_job_state(claimed.id)
        failed = sample_run(
            outcome=CollectionOutcome.FAILED,
            error_category="unavailable",
            retry_disposition="backoff",
        )
        store.complete_collection_run(
            failed,
            lease_id=state.active_lease_id,
            lease_generation=state.lease_generation,
        )
        incidents = store.list_triage_incidents()
        assert len(incidents) == 1
        assert incidents[0].status is TriageIncidentStatus.OPEN
        assert incidents[0].generation == 1


def test_stale_completion_is_rejected_and_expired_lease_is_failure_evidence(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        claimed = store.claim_due_collection_jobs(NOW, "worker-a", LEASE_END, limit=1)[0]
        old_state = store.load_collection_job_state(claimed.id)
        reclaimed = store.claim_due_collection_jobs(
            "2026-08-24T12:06:00+00:00", "worker-b", "2026-08-24T12:11:00+00:00", limit=1
        )
        assert reclaimed == (claimed,)
        assert store.load_collection_job_state(claimed.id).lease_generation == 2
        assert any(run.error_category == "expired_lease" for run in store.list_collection_runs())
        with pytest.raises(ValueError, match="stale collection lease"):
            store.complete_collection_run(
                sample_run("run.stale"),
                lease_id=old_state.active_lease_id,
                lease_generation=old_state.lease_generation,
            )


def test_complete_collection_run_preserves_outer_transaction_rollback(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        claimed = store.claim_due_collection_jobs(NOW, "worker-a", LEASE_END, limit=1)[0]
        state = store.load_collection_job_state(claimed.id)
        with pytest.raises(RuntimeError, match="rollback"):
            with store.agent_transaction():
                store.complete_collection_run(
                    sample_run(),
                    lease_id=state.active_lease_id,
                    lease_generation=state.lease_generation,
                )
                raise RuntimeError("rollback")
        assert store.list_collection_runs() == ()
        assert store.load_collection_job_state(claimed.id).active_lease_id == state.active_lease_id


def test_collection_run_page_count_and_rows_share_one_read_snapshot(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with seeded_collection_store(tmp_path) as store:
        store.save_collection_run(sample_run("run.first"))

    with SQLiteStore(path) as reader, SQLiteStore(path) as writer:
        inserted = False

        def insert_between_count_and_page(statement: str) -> None:
            nonlocal inserted
            if inserted or not statement.startswith("SELECT payload FROM collection_runs"):
                return
            inserted = True
            writer.save_collection_run(sample_run("run.second"))

        reader._connection.set_trace_callback(insert_between_count_and_page)
        total, runs = reader.page_collection_runs(limit=10)

    assert inserted is True
    assert total == len(runs) == 1


def test_retention_rejects_zero_and_preserves_protected_runs(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        with pytest.raises(ValueError, match="retention"):
            store.prune_collection_runs(0)
        first = sample_run("run.old", started_at="2026-08-24T10:00:00+00:00", completed_at="2026-08-24T10:01:00+00:00")
        second = sample_run("run.middle", started_at="2026-08-24T11:00:00+00:00", completed_at="2026-08-24T11:01:00+00:00")
        newest = sample_run("run.new", started_at="2026-08-24T12:00:00+00:00", completed_at="2026-08-24T12:01:00+00:00")
        store.save_collection_run(first)
        store.save_collection_run(second)
        store.save_collection_run(newest)
        store.save_collection_run(
            sample_run("run.protected", started_at="2026-08-24T09:00:00+00:00", completed_at="2026-08-24T09:01:00+00:00")
        )
        store.save_collection_incident(sample_incident(evidence_ids=("run.protected",)))
        store.save_repair_attempt(
            RepairAttempt(
                id="attempt.protected",
                incident_id="incident.collection.health.api.1",
                runbook_id="repair.retry.api",
                attempted_at=NOW,
                verification_run_id="run.middle",
            )
        )
        pruned = store.prune_collection_runs(1)
        assert pruned == 1
        assert {run.id for run in store.list_collection_runs()} == {
            "run.new",
            "run.protected",
            "run.middle",
        }


def test_repair_runbook_persists_exact_bindings(tmp_path: Path) -> None:
    with seeded_collection_store(tmp_path) as store:
        runbook = RepairRunbook(
            id="repair.retry.api",
            job_id="collection.health.api",
            resource_id="service.api",
            failure_categories=("unavailable",),
            risk_level=RiskLevel.LOW,
            idempotency_contract="one retry",
            cooldown_seconds=60,
            approval_required=False,
            adapter_binding="local.retry_read_only",
        )
        store.save_repair_runbook(runbook)
        assert store.load_repair_runbook(runbook.id) == runbook
        with pytest.raises(ValueError, match="binding"):
            store.save_repair_runbook(replace(runbook, job_id="other.job"))


def test_collection_migration_rolls_back_tables_when_history_record_fails(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path) as store:
        store._connection.execute("DROP TABLE collection_jobs")
        store._connection.execute("DELETE FROM schema_migrations")
        store._connection.execute(
            "INSERT INTO schema_migrations(version, description, applied_at) "
            "VALUES (?, ?, ?)",
            (11, "schema v11", NOW),
        )
        store._connection.commit()

    class FailingMigrationStore(SQLiteStore):
        def _record_schema_migration(self, version: int, description: str) -> None:
            if version == 13:
                raise RuntimeError("injected v13 migration failure")
            super()._record_schema_migration(version, description)

    with pytest.raises(RuntimeError, match="v13 migration"):
        FailingMigrationStore(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='collection_jobs'"
        ).fetchone() is None
