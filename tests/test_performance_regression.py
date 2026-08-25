import tempfile
import threading
import time
import unittest
from pathlib import Path

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
from overseer.store import SQLiteStore
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
    "/Overseer/runtime-status": {200, 404},
    "/Overseer/host/security/listener-review-queue": {200, 400},
    "/Overseer/host/security/source-review-queue": {200, 400},
}

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


class PerformanceRegressionTests(unittest.TestCase):
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

    def test_safe_mutating_workflow_routes_stay_within_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            with LocalApiHarness(Path(directory) / "overseer.sqlite3") as server:
                for endpoint, budget in SAFE_POST_BUDGETS.items():
                    payload = SAFE_POST_PAYLOADS[endpoint.removeprefix("/Overseer")]
                    with self.subTest(endpoint=endpoint):
                        response, elapsed = _timed(lambda endpoint=endpoint, payload=payload: server.post_json(endpoint, payload))
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
