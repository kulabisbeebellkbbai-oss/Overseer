from __future__ import annotations

import threading
import time
from dataclasses import replace
from types import SimpleNamespace
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
from overseer.collection_adapters import (
    HealthProbeCollectionAdapter,
    HostInspectionCollectionAdapter,
    PackageInspectionCollectionAdapter,
    StorePathCallbackAdapter,
)
from overseer.health import HealthEvidence, HealthStatus, HealthTarget, ProbeType
from overseer.host import HostCommandObservation, HostInspectionSnapshot
from overseer.packages import PackageInspectionSnapshot, PackageUpdate

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
    def __init__(
        self,
        *,
        delay: float = 0.01,
        block: threading.Event | None = None,
        started: threading.Event | None = None,
    ) -> None:
        self.delay = delay
        self.block = block
        self.started = started
        self.active = 0
        self.peak_active = 0
        self.by_key: dict[str, int] = {}
        self.peak_by_key: dict[str, int] = {}
        self.lock = threading.Lock()

    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        with self.lock:
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            if self.started is not None and self.active >= 2:
                self.started.set()
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


def test_health_collection_persists_no_body_or_secret_markers(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    job = _job("health-secret")
    _seed(path, (job,))
    target = HealthTarget(
        id=job.target_id or "target",
        resource_id=job.resource_id or "resource",
        name="health",
        probe_type=ProbeType.HTTP,
        target="https://example.test/health?token=HEALTH_BODY_MARKER",
    )
    with SQLiteStore(path) as store:
        store.save_health_target(target)

    class Probe:
        def probe(self, received: HealthTarget) -> HealthEvidence:
            assert received.target == target.target
            return HealthEvidence(
                id="health.evidence.secret",
                resource_id=received.resource_id,
                target=received.target,
                probe_type=received.probe_type,
                observed_status=HealthStatus.FAILED,
                owner_domain=received.owner_domain,
                observed_error="HEALTH_BODY_MARKER password=HEALTH_SECRET",
            )

    HealthProbeCollectionAdapter(lambda _timeout: Probe()).collect(job, str(path))
    with SQLiteStore(path) as store:
        evidence = store.load_health_evidence("health.evidence.secret")
        stored = repr(evidence)
        assert "HEALTH_BODY_MARKER" not in stored
        assert "HEALTH_SECRET" not in stored
        assert "example.test/health" in evidence.target


def test_host_collection_persists_projection_without_full_observations(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    job = replace(_job("host-secret", key="host"), kind=CollectionJobKind.HOST_INSPECTION)
    _seed(path, (job,))
    marker = "HOST_BODY_MARKER"
    snapshot = HostInspectionSnapshot(
        id=f"host.{marker}",
        captured_at=NOW,
        hostname=f"host-{marker}",
        os_release={"NAME": marker, "TOKEN": "HOST_SECRET"},
        observations=(
            HostCommandObservation(
                name="ss",
                command=("ss", "-ltnp"),
                exit_code=0,
                stdout=f"{marker} stdout password=HOST_SECRET",
                stderr=f"{marker} stderr",
            ),
        ),
    )
    adapter = HostInspectionCollectionAdapter(lambda _timeout: SimpleNamespace(inspect=lambda: snapshot))
    adapter.collect(job, str(path))
    with SQLiteStore(path) as store:
        saved = store.list_host_snapshots()[0]
        stored = repr(saved)
        assert marker not in stored
        assert "HOST_SECRET" not in stored
        assert saved.observation("ss").command == ("ss", "-ltnp")
        assert saved.observation("ss").exit_code == 0
        assert saved.observation("ss").stdout == ""
        assert saved.observation("ss").stderr == ""


def test_package_collection_preserves_updates_but_strips_raw_stderr(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    job = replace(_job("package-secret", key="package"), kind=CollectionJobKind.PACKAGE_INSPECTION)
    _seed(path, (job,))
    snapshot = PackageInspectionSnapshot(
        id="package.secret",
        captured_at=NOW,
        command=("apt", "list", "--upgradable"),
        exit_code=100,
        updates=(PackageUpdate("openssl", "security", "2", "amd64"),),
        stderr="PACKAGE_BODY_MARKER token=PACKAGE_SECRET",
    )
    adapter = PackageInspectionCollectionAdapter(lambda _timeout: SimpleNamespace(inspect=lambda: snapshot))
    adapter.collect(job, str(path))
    with SQLiteStore(path) as store:
        record = store.list_package_inspection_records()[0]
        assert record.updates == snapshot.updates
        assert record.state_fingerprint
        assert "PACKAGE_BODY_MARKER" not in repr(record)
        assert "PACKAGE_SECRET" not in repr(record)
        assert record.stderr == ""


def test_callback_body_marker_is_not_written_to_collection_run(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    job = _job("callback-secret")
    _seed(path, (job,))

    def callback(_job: CollectionJob, _store_path: str, _timeout: float) -> CollectionExecution:
        return CollectionExecution(
            CollectionOutcome.SUCCEEDED,
            "CALLBACK_BODY_MARKER arbitrary external payload",
            ("evidence.safe",),
        )

    scheduler = _scheduler(path, StorePathCallbackAdapter(callback))
    try:
        scheduler.run_ready_once()
        with SQLiteStore(path) as store:
            run = store.list_collection_runs()[0]
            assert "CALLBACK_BODY_MARKER" not in repr(run)
            assert run.evidence_ids == ("evidence.safe",)
    finally:
        scheduler.shutdown()


def test_concurrent_scheduler_entries_reserve_capacity_once(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    jobs = tuple(_job(f"entry-{index}", key=f"key-{index}") for index in range(4))
    _seed(path, jobs)
    adapter_started = threading.Event()
    adapter = _BlockingAdapter(block=threading.Event(), started=adapter_started)
    scheduler = _scheduler(path, adapter)
    entry = threading.Barrier(2)
    results: list[object] = []

    def invoke() -> None:
        entry.wait()
        results.append(scheduler.run_ready_once())

    callers = [threading.Thread(target=invoke), threading.Thread(target=invoke)]
    for caller in callers:
        caller.start()
    assert adapter_started.wait(2)
    assert adapter.peak_active == 2
    with SQLiteStore(path) as store:
        assert len([state for state in store.list_collection_job_states() if state.active_lease_id]) == 2
    adapter.block.set()  # type: ignore[union-attr]
    for caller in callers:
        caller.join(2)
    assert all(not caller.is_alive() for caller in callers)
    assert len(results) == 2
    scheduler.shutdown()


def test_late_completion_after_bounded_shutdown_releases_exact_timeout_lease(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    job = _job("late", timeout=1)
    _seed(path, (job,))
    release = threading.Event()
    exited = threading.Event()

    class NonCooperative:
        def collect(self, _job: CollectionJob, _store_path: str) -> CollectionExecution:
            release.wait(2)
            exited.set()
            return CollectionExecution(CollectionOutcome.SUCCEEDED, "late completion")

    scheduler = _scheduler(path, NonCooperative())
    scheduler.shutdown_timeout_seconds = 0.05
    scheduler.run_ready_once()
    with SQLiteStore(path) as store:
        before = store.load_collection_job_state(job.id)
        assert before.active_lease_id is not None
        lease_id = before.active_lease_id
        generation = before.lease_generation
    scheduler.shutdown()
    with SQLiteStore(path) as store:
        assert store.load_collection_job_state(job.id).active_lease_id == lease_id
    release.set()
    assert exited.wait(2)
    assert scheduler._completion_event.wait(2)
    with SQLiteStore(path) as store:
        after = store.load_collection_job_state(job.id)
        assert after.active_lease_id is None
        assert after.lease_generation == generation
        runs = store.list_collection_runs()
        assert len(runs) == 1
        assert runs[0].error_category == "timeout"
        assert len(store.list_triage_incidents()) == 1
