import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import overseer.store as store_module
from overseer.collection_adapters import CollectionAdapterRegistry, CollectionExecution
from overseer.collection_models import (
    CollectionJob,
    CollectionJobKind,
    CollectionJobState,
    CollectionRun,
    CollectionOutcome,
    RepairRunbook,
    TriageIncident,
    TriageIncidentStatus,
)
from overseer.collection_scheduler import CollectionScheduler
from overseer.core import OwnerDomain, RiskLevel
from overseer.store import CURRENT_SCHEMA_VERSION, SQLiteStore
from tests.test_ui_full_regression import SAFE_POST_PAYLOADS
from tests.test_ui_regression import LocalApiHarness


GET_ENDPOINT_BUDGETS = {
    "/Overseer/auth-check": 1.0,
    "/Overseer/operator-dashboard": 1.5,
    "/Overseer/operations/gap-coverage": 2.5,
    "/Overseer/runtime-status": 1.0,
    "/Overseer/admin/authorizations-required": 1.0,
    "/Overseer/admin/execution-readiness": 1.0,
    "/Overseer/admin/adapter-capabilities": 1.0,
    "/Overseer/admin/active-policy-profile": 1.0,
    "/Overseer/usage-summary": 1.0,
    "/Overseer/documents/status": 2.5,
    "/Overseer/documents/notes?folder=Overseer": 2.5,
    "/Overseer/documents/knowledge-capture-plan?limit=12": 2.5,
    "/Overseer/crew/messages": 1.0,
    "/Overseer/audit-summary": 1.0,
    "/Overseer/approvals-summary": 1.0,
    "/Overseer/claims/review": 1.0,
    "/Overseer/claims/cleanup-plan": 1.0,
    "/Overseer/physical-summary": 1.0,
    "/Overseer/virtual-summary": 1.0,
    "/Overseer/health-summary": 1.0,
    "/Overseer/security-summary": 1.0,
    "/Overseer/host/security/listener-review-queue": 2.5,
    "/Overseer/host/security/source-review-queue": 2.5,
    "/Overseer/git/status": 2.5,
    "/Overseer/collections/status": 1.0,
    "/Overseer/collections/jobs?limit=12": 1.0,
    "/Overseer/collections/runs?limit=12": 1.0,
    "/Overseer/collections/incidents?limit=12": 1.0,
    "/Overseer/collections/runbooks?limit=12": 1.0,
}

GET_ENDPOINT_ALLOWED_STATUSES = {
    "/Overseer/runtime-status": {200},
    "/Overseer/host/security/listener-review-queue": {200},
    "/Overseer/host/security/source-review-queue": {200},
}

HOST_COLLECTION_FREE_ENDPOINTS = (
    "/Overseer/operations/gap-coverage",
    "/Overseer/health/service-evidence",
    "/Overseer/maintenance/package-status",
    "/Overseer/maintenance/firmware-status",
    "/Overseer/maintenance/firmware-preflight",
    "/Overseer/maintenance/software-evidence",
    "/Overseer/storage/evidence",
    "/Overseer/storage/backup-operations",
    "/Overseer/virtual/evidence",
    "/Overseer/git/status",
)

SAFE_POST_BUDGETS = {
    "/Overseer/resources": 1.0,
    "/Overseer/claims/request": 1.0,
    "/Overseer/usage-limits": 1.0,
    "/Overseer/usage/continuation-requests": 1.0,
    "/Overseer/usage/continuation-dispatches": 1.0,
    "/Overseer/health-targets": 1.0,
    "/Overseer/health/probes/run": 1.5,
    "/Overseer/crew/messages": 1.0,
    "/Overseer/crew/dispatch": 1.0,
    "/Overseer/admin/plans": 1.0,
    "/Overseer/admin/approve": 1.0,
    "/Overseer/admin/policy-customization-helper/profile": 1.0,
}

PRODUCTION_COLLECTION_RUN_COUNT = 150_000
PRODUCTION_COLLECTION_INDEX_UPGRADE_BUDGET_SECONDS = 10.0


def _timed(call):
    start = time.perf_counter()
    result = call()
    return result, time.perf_counter() - start


def _seed_collection_projections(path: Path, count: int = 24) -> None:
    with SQLiteStore(path) as store:
        for index in range(count):
            suffix = f"{index:03d}"
            job_id = f"collection.health.performance.{suffix}"
            resource_id = f"resource.performance.{suffix}"
            job = CollectionJob(
                id=job_id,
                kind=CollectionJobKind.HEALTH_PROBE,
                owner_domain=OwnerDomain.JULIAN,
                resource_id=resource_id,
                target_id=f"health.performance.{suffix}",
                interval_seconds=120,
            )
            store.save_collection_job(
                job,
                CollectionJobState(
                    job_id=job_id,
                    next_due_at="2026-08-24T12:10:00+00:00",
                    last_completed_at="2026-08-24T11:59:00+00:00",
                    last_outcome=CollectionOutcome.SUCCEEDED,
                ),
            )
            store.save_collection_run(
                CollectionRun(
                    id=f"run.performance.{suffix}",
                    job_id=job_id,
                    trigger="scheduled",
                    started_at="2026-08-24T11:58:00+00:00",
                    completed_at="2026-08-24T11:58:01+00:00",
                    outcome=CollectionOutcome.SUCCEEDED,
                    summary="bounded performance fixture",
                    evidence_ids=(f"evidence.performance.{suffix}",),
                )
            )
            store.save_collection_incident(
                TriageIncident(
                    id=f"incident.performance.{suffix}",
                    job_id=job_id,
                    resource_id=resource_id,
                    first_failure_at="2026-08-24T11:57:00+00:00",
                    latest_failure_at="2026-08-24T11:57:01+00:00",
                    severity=RiskLevel.LOW,
                    owner_domain=OwnerDomain.JULIAN,
                    evidence_ids=(f"evidence.performance.{suffix}",),
                    status=TriageIncidentStatus.OPEN,
                )
            )
            store.save_repair_runbook(
                RepairRunbook(
                    id=f"runbook.performance.{suffix}",
                    job_id=job_id,
                    resource_id=resource_id,
                    failure_categories=("unavailable",),
                    risk_level=RiskLevel.LOW,
                    idempotency_contract="verify after bounded repair",
                    cooldown_seconds=60,
                    approval_required=False,
                    adapter_binding="performance",
                )
            )


def _seed_production_collection_history(
    path: Path, count: int = PRODUCTION_COLLECTION_RUN_COUNT
) -> None:
    _seed_collection_projections(path, count=1)
    base_id = "run.performance.000"
    with SQLiteStore(path) as store:
        base = store._connection.execute(
            "SELECT * FROM collection_runs WHERE id=?", (base_id,)
        ).fetchone()
        assert base is not None

        def rows():
            for index in range(1, count):
                run_id = f"run.performance.scale.{index:06d}"
                yield (
                    run_id,
                    base["job_id"],
                    base["trigger"],
                    base["started_at"],
                    base["completed_at"],
                    base["outcome"],
                    base["summary"],
                    base["evidence_ids"],
                    base["error_category"],
                    base["retry_disposition"],
                    base["request_id"],
                    str(base["payload"]).replace(base_id, run_id, 1),
                )

        store._connection.executemany(
            "INSERT INTO collection_runs ("
            "id, job_id, trigger, started_at, completed_at, outcome, summary, "
            "evidence_ids, error_category, retry_disposition, request_id, payload"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows(),
        )
        store._connection.commit()


class PerformanceRegressionTests(unittest.TestCase):
    def test_scheduler_dashboard_contract_stays_projection_only(self):
        from overseer.ui import OPERATOR_CONSOLE_HTML

        for endpoint in (
            'collectionsStatus: "/collections/status"',
            'collectionsJobs: "/collections/jobs"',
            'collectionsRuns: "/collections/runs"',
            'collectionsIncidents: "/collections/incidents"',
        ):
            self.assertIn(endpoint, OPERATOR_CONSOLE_HTML)
        self.assertIn("mapEndpointEntries(endpointEntries, 4)", OPERATOR_CONSOLE_HTML)
        self.assertNotIn('postJson("/health/probes/run"', OPERATOR_CONSOLE_HTML)

    def test_operator_console_html_loads_within_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                (html, content_type), elapsed = _timed(lambda: server.get_text("/Overseer/ui"))

        self.assertIn("text/html", content_type)
        self.assertIn("Overseer", html)
        self.assertLess(elapsed, 1.0)

    def test_authenticated_panel_endpoint_matrix_stays_within_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            _seed_collection_projections(store_path)
            with LocalApiHarness(store_path) as server:
                for endpoint, budget in GET_ENDPOINT_BUDGETS.items():
                    with self.subTest(endpoint=endpoint):
                        status, elapsed = _timed(lambda endpoint=endpoint: server.get_status(endpoint))
                        self.assertIn(status, GET_ENDPOINT_ALLOWED_STATUSES.get(endpoint, {200}))
                        self.assertLess(elapsed, budget)

    def test_collection_history_projection_is_bounded_at_production_scale(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            _seed_production_collection_history(store_path)
            original_load = store_module._load_dataclass
            loaded_runs: list[str] = []

            def tracked_load(record_type, payload):
                if record_type is CollectionRun:
                    loaded_runs.append(record_type.__name__)
                return original_load(record_type, payload)

            with patch("overseer.store._load_dataclass", side_effect=tracked_load):
                with LocalApiHarness(store_path) as server:
                    status, status_elapsed = _timed(
                        lambda: server.get_json("/Overseer/collections/status")
                    )
                    runs, runs_elapsed = _timed(
                        lambda: server.get_json("/Overseer/collections/runs?limit=12")
                    )

        self.assertEqual(status["run_count"], PRODUCTION_COLLECTION_RUN_COUNT)
        self.assertEqual(runs["total_count"], PRODUCTION_COLLECTION_RUN_COUNT)
        self.assertEqual(runs["returned_count"], 12)
        self.assertTrue(runs["truncated"])
        self.assertEqual(len(loaded_runs), 12)
        self.assertLess(status_elapsed, GET_ENDPOINT_BUDGETS["/Overseer/collections/status"])
        self.assertLess(runs_elapsed, GET_ENDPOINT_BUDGETS["/Overseer/collections/runs?limit=12"])

    def test_v12_run_index_upgrade_is_bounded_at_production_scale(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            _seed_production_collection_history(store_path)
            with sqlite3.connect(store_path) as connection:
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
                    "INSERT OR IGNORE INTO schema_migrations"
                    "(version, description, applied_at) VALUES "
                    "(12, 'legacy collection index contract', '2026-08-24T12:00:00+00:00')"
                )
                connection.commit()

            upgrade_started = time.perf_counter()
            with SQLiteStore(store_path) as store:
                metrics = store.collection_scheduler_metrics()
                versions = [
                    item.version
                    for item in store.list_schema_migrations()
                    if isinstance(item.version, int)
                ]
                indexes_are_current = all(
                    store._collection_index_is_canonical(index_name)
                    for index_name in (
                        "idx_collection_runs_job_started",
                        "idx_collection_runs_started",
                        "idx_collection_runs_outcome_started",
                        "idx_collection_runs_job_outcome_started",
                    )
                )
            upgrade_elapsed = time.perf_counter() - upgrade_started

        self.assertEqual(metrics["run_count"], PRODUCTION_COLLECTION_RUN_COUNT)
        self.assertEqual(versions[-1], CURRENT_SCHEMA_VERSION)
        self.assertTrue(indexes_are_current)
        self.assertLess(
            upgrade_elapsed,
            PRODUCTION_COLLECTION_INDEX_UPGRADE_BUDGET_SECONDS,
        )

    def test_authenticated_panel_gets_never_launch_host_collectors(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "state" / "overseer.sqlite3"
            store_path.parent.mkdir()
            _seed_collection_projections(store_path)
            with (
                patch("subprocess.run", side_effect=AssertionError("dashboard GET launched a host collector")),
                patch("overseer.backup_ops._host_resolution_status", side_effect=AssertionError("dashboard GET launched DNS collection")),
            ):
                with LocalApiHarness(store_path) as server:
                    statuses = {
                        endpoint: server.get_status(endpoint)
                        for endpoint in HOST_COLLECTION_FREE_ENDPOINTS
                    }

        self.assertEqual(statuses, {endpoint: 200 for endpoint in HOST_COLLECTION_FREE_ENDPOINTS})

    def test_storage_capture_post_only_queues_the_scheduled_job(self):
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "state" / "overseer.sqlite3"
            store_path.parent.mkdir()
            from overseer.runtime import seed_default_collection_jobs

            seed_default_collection_jobs(store_path)
            with patch("subprocess.run", side_effect=AssertionError("storage POST launched a host collector")):
                with LocalApiHarness(store_path) as server:
                    response = server.post_json(
                        "/Overseer/storage/growth-snapshots/capture",
                        {"requested_by": "kira"},
                    )

        self.assertEqual(response["collection_job_id"], "collection.storage.capacity")
        self.assertIn(response["status"], {"queued", "coalesced"})
        self.assertFalse(response["deprecated_inline_capture"])
        self.assertFalse((store_path.parent.parent / "state" / "storage-growth-history.json").exists())

    def test_safe_mutating_workflow_routes_stay_within_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                for endpoint, budget in SAFE_POST_BUDGETS.items():
                    payload = SAFE_POST_PAYLOADS[endpoint.removeprefix("/Overseer")]
                    with self.subTest(endpoint=endpoint):
                        response, elapsed = _timed(
                            lambda endpoint=endpoint, payload=payload: server.post_json(
                                endpoint,
                                payload,
                                approval=endpoint.endswith("/admin/approve"),
                            )
                        )
                        self.assertIsInstance(response, dict)
                        self.assertLess(elapsed, budget)

    def test_collection_run_queue_does_not_wait_for_blocking_adapter(self):
        started = threading.Event()
        release = threading.Event()

        class BlockingAdapter:
            def collect(self, job, store_path):
                started.set()
                release.wait(5)
                return CollectionExecution(
                    CollectionOutcome.SUCCEEDED, "blocking adapter released"
                )

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "overseer.sqlite3"
            blocking_job = CollectionJob(
                id="collection.health.blocking",
                kind=CollectionJobKind.HEALTH_PROBE,
                owner_domain=OwnerDomain.JULIAN,
                resource_id="resource.blocking",
                target_id="health.blocking",
            )
            queued_job = CollectionJob(
                id="collection.health.queued",
                kind=CollectionJobKind.HEALTH_PROBE,
                owner_domain=OwnerDomain.JULIAN,
                resource_id="resource.queued",
                target_id="health.queued",
            )
            with SQLiteStore(store_path) as store:
                store.save_collection_job(
                    blocking_job,
                    CollectionJobState(
                        job_id=blocking_job.id,
                        next_due_at="2026-08-24T12:00:00+00:00",
                    ),
                )
                store.save_collection_job(
                    queued_job,
                    CollectionJobState(
                        job_id=queued_job.id,
                        next_due_at="2026-08-24T12:30:00+00:00",
                    ),
                )
            registry = CollectionAdapterRegistry()
            registry.register(CollectionJobKind.HEALTH_PROBE, "blocking", BlockingAdapter())
            scheduler = CollectionScheduler(
                store_path,
                registry,
                max_workers=1,
                adapter_ids={CollectionJobKind.HEALTH_PROBE: "blocking"},
                clock=lambda: "2026-08-24T12:00:00+00:00",
            )
            cycle_thread = threading.Thread(target=scheduler.run_ready_once)
            cycle_thread.start()
            try:
                self.assertTrue(started.wait(2))
                with LocalApiHarness(store_path) as server:
                    response, elapsed = _timed(
                        lambda: server.post_json(
                            "/Overseer/collections/jobs/collection.health.queued/run",
                            {
                                "requested_by": "performance-test",
                                "reason": "bounded queue timing",
                            },
                        )
                    )
                self.assertIn(response["status"], {"queued", "coalesced"})
                self.assertLess(elapsed, 1.0)
            finally:
                release.set()
                cycle_thread.join(timeout=5)
                scheduler.shutdown()
                self.assertFalse(cycle_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
