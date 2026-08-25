from __future__ import annotations

import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from overseer import (
    CollectionAdapterRegistry,
    CollectionExecution,
    CollectionJob,
    CollectionJobKind,
    CollectionOutcome,
    CollectionScheduler,
    OwnerDomain,
    SQLiteStore,
    scheduler_status,
)

NOW = "2026-08-24T12:00:00+00:00"


def _job(job_id: str, *, key: str = "mcp", timeout: int = 2, interval: int = 60) -> CollectionJob:
    return CollectionJob(
        id=job_id,
        kind=CollectionJobKind.HEALTH_PROBE,
        owner_domain=OwnerDomain.JULIAN,
        resource_id=f"resource.{job_id}",
        target_id=f"target.{job_id}",
        interval_seconds=interval,
        timeout_seconds=timeout,
        concurrency_key=key,
    )


def _seed(path: Path, jobs: tuple[CollectionJob, ...]) -> None:
    with SQLiteStore(path) as store:
        for job in jobs:
            from overseer import CollectionJobState

            store.save_collection_job(job, CollectionJobState(job_id=job.id, next_due_at=NOW))


class _BlockingAdapter:
    def __init__(self, *, delay: float = 0.01, block: threading.Event | None = None) -> None:
        self.delay = delay
        self.block = block
        self.active = 0
        self.peak_active = 0
        self.by_key: dict[str, int] = {}
        self.peak_by_key: dict[str, int] = {}
        self.lock = threading.Lock()

    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        with self.lock:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            self.by_key[job.concurrency_key] = self.by_key.get(job.concurrency_key, 0) + 1
            self.peak_by_key[job.concurrency_key] = max(
                self.peak_by_key.get(job.concurrency_key, 0), self.by_key[job.concurrency_key]
            )
        try:
            if self.block is not None:
                self.block.wait(2)
            else:
                time.sleep(self.delay)
            return CollectionExecution(CollectionOutcome.SUCCEEDED, f"completed {job.id}")
        finally:
            with self.lock:
                self.active -= 1
                self.by_key[job.concurrency_key] -= 1


def _scheduler(path: Path, adapter: object, *, max_workers: int = 2) -> CollectionScheduler:
    registry = CollectionAdapterRegistry()
    registry.register(CollectionJobKind.HEALTH_PROBE, "fake", adapter)
    return CollectionScheduler(str(path), registry, max_workers=max_workers, clock=lambda: NOW)


def test_scheduler_never_exceeds_global_or_key_concurrency(tmp_path: Path) -> None:
    jobs = (_job("one"), _job("two"), _job("three", key="host"))
    _seed(tmp_path / "state.sqlite3", jobs)
    adapter = _BlockingAdapter(delay=0.2)
    scheduler = _scheduler(tmp_path / "state.sqlite3", adapter)
    try:
        cycle = scheduler.run_ready_once()
        assert cycle.started == 2
        assert adapter.peak_active == 2
        assert adapter.peak_by_key["mcp"] == 1
    finally:
        scheduler.shutdown()


def test_restart_coalesces_missed_intervals(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    job = _job("old", interval=60)
    _seed(path, (job,))
    with SQLiteStore(path) as store:
        old = replace(store.load_collection_job_state(job.id), next_due_at="2026-08-20T12:00:00+00:00")
        store.save_collection_job_state(old)
    adapter = _BlockingAdapter()
    scheduler = _scheduler(path, adapter)
    try:
        cycle = scheduler.run_ready_once()
        assert cycle.claimed == 1
        assert cycle.started == 1
        with SQLiteStore(path) as store:
            assert len(store.list_collection_runs()) == 1
    finally:
        scheduler.shutdown()


def test_timeout_opens_incident_and_applies_backoff(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _seed(path, (_job("slow", timeout=1),))
    release = threading.Event()
    adapter = _BlockingAdapter(block=release)
    scheduler = _scheduler(path, adapter)
    try:
        cycle = scheduler.run_ready_once()
        assert cycle.failed == 1
        assert cycle.timed_out == 1
        with SQLiteStore(path) as store:
            incident = store.list_triage_incidents()[0]
            run = store.list_collection_runs()[0]
            state = store.load_collection_job_state("slow")
            assert run.error_category == "timeout"
            assert incident.status.value == "open"
            assert state.next_due_at > NOW
            assert state.active_lease_id is not None
        release.set()
        scheduler.shutdown()
        with SQLiteStore(path) as store:
            assert len(store.list_collection_runs()) == 1
            assert store.load_collection_job_state("slow").last_outcome is CollectionOutcome.TIMED_OUT
    finally:
        release.set()
        scheduler.shutdown()


def test_registry_rejects_missing_and_mismatched_bindings() -> None:
    registry = CollectionAdapterRegistry()
    with pytest.raises(ValueError, match="missing collection adapter"):
        registry.resolve(_job("missing"))
    class HostAdapter:
        collection_job_kind = CollectionJobKind.HOST_INSPECTION

    adapter = HostAdapter()
    registry.register(CollectionJobKind.HOST_INSPECTION, "host", adapter)
    with pytest.raises(ValueError, match="adapter kind mismatch"):
        registry.register(CollectionJobKind.HEALTH_PROBE, "host", adapter)


def test_worker_exception_is_bounded_and_does_not_persist_secret_or_traceback(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _seed(path, (_job("broken"),))

    class Broken:
        def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
            raise RuntimeError("token=super-secret response body and traceback")

    scheduler = _scheduler(path, Broken())
    try:
        cycle = scheduler.run_ready_once()
        assert cycle.failed == 1
        with SQLiteStore(path) as store:
            run = store.list_collection_runs()[0]
            assert run.error_category == "internal_error"
            assert "super-secret" not in run.summary
            assert "Traceback" not in run.summary
    finally:
        scheduler.shutdown()


def test_scheduler_status_reports_bounds(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _seed(path, (_job("one"),))
    status = scheduler_status(path)
    assert status["max_workers"] == 2
    assert status["max_per_concurrency_key"] == 1
    assert status["job_count"] == 1


def test_store_path_callback_receives_job_timeout_boundary() -> None:
    seen: list[float] = []

    def callback(job: CollectionJob, store_path: str, timeout_seconds: float) -> CollectionExecution:
        seen.append(timeout_seconds)
        return CollectionExecution(CollectionOutcome.SUCCEEDED, "callback complete")

    from overseer import StorePathCallbackAdapter

    StorePathCallbackAdapter(callback).collect(_job("callback", timeout=7), "/tmp/fake-store")
    assert seen == [7]


def test_pending_request_makes_future_job_run_once_and_terminalizes_request(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    job = _job("requested")
    _seed(path, (job,))
    with SQLiteStore(path) as store:
        store.save_collection_job(
            job,
            replace(store.load_collection_job_state(job.id), next_due_at="2026-08-30T12:00:00+00:00"),
        )
        request = store.request_collection_run(job.id, "operator", "verify", requested_at=NOW)
    scheduler = _scheduler(path, _BlockingAdapter())
    try:
        cycle = scheduler.run_ready_once()
        assert cycle.started == 1
        with SQLiteStore(path) as store:
            saved = store.list_collection_requests()[0]
            assert saved.id == request.id
            assert saved.status == "completed"
    finally:
        scheduler.shutdown()
