from __future__ import annotations

import json
from pathlib import Path

import pytest

from overseer.cli import main
from overseer.collection_models import CollectionJobKind, CollectionOutcome
from overseer.config import config_from_mapping
from overseer.core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from overseer.health import HealthTarget, ProbeType
from overseer.runtime import OverseerRuntime, seed_default_collection_jobs
from overseer.store import SQLiteStore


def _store_path(tmp_path: Path) -> Path:
    return tmp_path / "state.sqlite3"


def _seed_resource_and_target(tmp_path: Path, target_id: str = "health.api") -> Path:
    path = _store_path(tmp_path)
    with SQLiteStore(path) as store:
        store.save_resource(
            Resource(
                id="svc.api",
                name="API",
                type=ResourceType.SERVICE,
                owner_domain=OwnerDomain.JULIAN,
                risk_level=RiskLevel.LOW,
                state=ResourceState.AVAILABLE,
            )
        )
        store.save_health_target(
            HealthTarget(
                id=target_id,
                resource_id="svc.api",
                name="API health",
                probe_type=ProbeType.HTTP,
                target="http://127.0.0.1:1/health",
            )
        )
    return path


def test_health_targets_seed_independent_stable_jobs(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)

    seed_default_collection_jobs(path)
    seed_default_collection_jobs(path)

    with SQLiteStore(path) as store:
        jobs = store.list_collection_jobs()

    assert [job.id for job in jobs if job.kind == CollectionJobKind.HEALTH_PROBE] == [
        "collection.health.health.api"
    ]


def test_reseeding_updates_policy_without_erasing_active_lease(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.health.health.api")
        state = store.load_collection_job_state(job.id)
        store.save_collection_job_state(
            state.__class__(
                **{
                    **state.__dict__,
                    "active_lease_id": "lease.keep",
                    "lease_owner": "worker.keep",
                    "lease_expires_at": "2030-01-01T00:00:00+00:00",
                    "lease_generation": 4,
                }
            )
        )

    with SQLiteStore(path) as store:
        target = store.load_health_target("health.api")
        store.save_health_target(
            HealthTarget(
                **{
                    **target.__dict__,
                    "interval_seconds": 300,
                }
            )
        )
    seed_default_collection_jobs(path)

    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.health.health.api")
        state = store.load_collection_job_state(job.id)
    assert job.interval_seconds == 300
    assert state.active_lease_id == "lease.keep"
    assert state.lease_generation == 4


def test_runtime_tick_advances_scheduler_without_bulk_probe(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)

    class FakeScheduler:
        def __init__(self) -> None:
            self.cycles = 0

        def run_ready_once(self):
            self.cycles += 1
            return type("Cycle", (), {"next_due_at": None})()

    scheduler = FakeScheduler()
    with SQLiteStore(path) as store:
        runtime = OverseerRuntime(
            store,
            scheduler=scheduler,
            probe_health_targets=True,
            health_probe_adapter=pytest.fail,
        )
        tick = runtime.tick()

    assert scheduler.cycles == 1
    assert tick.health_probes == 0


def test_health_target_schedule_fields_have_compatible_defaults() -> None:
    config = config_from_mapping(
        {
            "resources": [
                {
                    "id": "svc.api",
                    "name": "API",
                    "type": "service",
                    "owner_domain": "julian",
                    "risk_level": "low",
                }
            ],
            "health_targets": [
                {
                    "id": "health.api",
                    "resource_id": "svc.api",
                    "name": "API",
                    "probe_type": "http",
                    "target": "http://127.0.0.1:1/health",
                }
            ],
        }
    )
    target = config.health_targets[0]
    assert (target.interval_seconds, target.jitter_seconds, target.timeout_seconds) == (120, 0, 30)
    assert target.repair_policy.value == "triage_only"


def test_health_target_schedule_fields_use_collection_validation() -> None:
    with pytest.raises(ValueError, match="interval must be a positive integer"):
        HealthTarget(
            id="health.invalid",
            resource_id="svc.api",
            name="invalid",
            probe_type=ProbeType.HTTP,
            target="http://127.0.0.1:1/health",
            interval_seconds=0,
        )


def test_seed_does_not_duplicate_external_timer_work(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    with SQLiteStore(path) as store:
        ids = {job.id for job in store.list_collection_jobs()}
        freshness = [job for job in store.list_collection_jobs() if job.kind == CollectionJobKind.FRESHNESS_PROJECTION]

    assert not any("psychlo-usage.timer" in job_id or "quark-scheduler.timer" in job_id for job_id in ids)
    assert {job.id for job in freshness} >= {
        "collection.freshness.psychlo-usage",
        "collection.freshness.quark-scheduler",
    }


def test_collection_cli_reads_are_json_and_request_is_queue_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    assert main(["collection-jobs", "--store", str(path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["jobs"]

    assert main(
        [
            "request-collection-run",
            "--store",
            str(path),
            "--job-id",
            "collection.health.health.api",
            "--requested-by",
            "operator",
            "--reason",
            "verify now",
        ]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] in {"queued", "coalesced"}
    assert payload["inline_execution"] is False
    with SQLiteStore(path) as store:
        assert len(store.list_collection_runs()) == 0

    assert main(["collection-scheduler-status", "--store", str(path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"
    assert payload["durable_status"] is True
