from __future__ import annotations

import json
from pathlib import Path

import pytest

from overseer.cli import main
from overseer.collection_models import CollectionJob, CollectionJobKind, CollectionOutcome, TriageIncident
from overseer.config import config_from_mapping
from overseer.core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from overseer.health import HealthTarget, ProbeType
from overseer.runtime import OverseerRuntime, runtime_collection_adapter_registry, seed_default_collection_jobs
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


def test_default_collection_seeding_fails_closed_for_external_action_families(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)

    result = seed_default_collection_jobs(path)

    unsafe_ids = {
        "collection.dispatch.crew",
        "collection.usage.continuation",
        "collection.knowledge.capture",
        "collection.station.audit",
    }
    with SQLiteStore(path) as store:
        jobs = {job.id: job for job in store.list_collection_jobs()}

    assert unsafe_ids <= jobs.keys()
    assert all(not jobs[job_id].enabled for job_id in unsafe_ids)
    assert jobs["collection.health.health.api"].enabled is True
    assert jobs["collection.freshness.psychlo-usage"].enabled is True
    assert {item["job_id"] for item in result["disabled"]} >= unsafe_ids
    assert all(
        item["reason"] == "explicit durable authorization is required"
        for item in result["disabled"]
        if item["job_id"] in unsafe_ids
    )


def test_legacy_action_flags_do_not_authorize_unsafe_jobs(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)

    class FakeScheduler:
        def shutdown(self) -> None:
            return None

    with SQLiteStore(path) as store:
        OverseerRuntime(
            store,
            dispatch_crew_messages=True,
            dispatch_usage_continuations=True,
            capture_knowledge_events=True,
            audit_station=True,
            scheduler=FakeScheduler(),
        )
        jobs = {job.id: job for job in store.list_collection_jobs()}

    assert all(
        jobs[job_id].enabled is False
        for job_id in (
            "collection.dispatch.crew",
            "collection.usage.continuation",
            "collection.knowledge.capture",
            "collection.station.audit",
        )
    )


def test_reseeding_preserves_operator_suspension_and_authorized_state(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    with SQLiteStore(path) as store:
        suspended_id = "collection.knowledge.capture"
        authorized_id = "collection.station.audit"
        store.set_collection_job_enabled(suspended_id, True)
        store.set_collection_job_enabled(suspended_id, False)
        store.set_collection_job_enabled(authorized_id, True)
        state = store.load_collection_job_state(suspended_id)
        store.save_collection_job_state(
            state.__class__(
                **{
                    **state.__dict__,
                    "active_lease_id": "lease.suspended",
                    "lease_owner": "worker.suspended",
                    "lease_expires_at": "2030-01-01T00:00:00+00:00",
                    "lease_generation": 9,
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
        suspended = store.load_collection_job(suspended_id)
        authorized = store.load_collection_job(authorized_id)
        health = store.load_collection_job("collection.health.health.api")
        state = store.load_collection_job_state(suspended_id)
    assert suspended.enabled is False
    assert authorized.enabled is True
    assert health.interval_seconds == 300
    assert state.active_lease_id == "lease.suspended"
    assert state.lease_generation == 9


def test_reseeding_disables_job_when_its_health_target_is_disabled(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    with SQLiteStore(path) as store:
        target = store.load_health_target("health.api")
        store.save_health_target(HealthTarget(**{**target.__dict__, "enabled": False}))

    seed_default_collection_jobs(path)

    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.health.health.api")
    assert job.enabled is False


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


def test_external_freshness_queries_exact_user_systemd_units_without_starting_them(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    calls: list[tuple[tuple[str, ...], float]] = []

    def runner(command: tuple[str, ...], timeout_seconds: float):
        calls.append((command, timeout_seconds))
        unit = command[-1]
        if unit.endswith(".timer"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "ActiveState=active\nSubState=waiting\nResult=success\nLastTriggerUSecRealtime=2026-08-24 12:00:00 UTC\nNextElapseUSecRealtime=2026-08-24 12:05:00 UTC\n",
                "stderr": "secret=must-not-persist",
            })()
        return type("Result", (), {
            "returncode": 0,
            "stdout": "ActiveState=inactive\nSubState=dead\nResult=success\n",
            "stderr": "",
        })()

    registry = runtime_collection_adapter_registry(systemd_runner=runner, now=lambda: "2026-08-24T12:01:00+00:00")
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.freshness.psychlo-usage")
    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))

    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert all(command[0][0:3] == ("systemctl", "--user", "show") for command in calls)
    assert {command[-1] for command, _ in calls} == {
        "overseer-psychlo-usage.timer",
        "overseer-psychlo-usage.service",
    }
    assert all("start" not in command and "enable" not in command for command, _ in calls)
    assert all(timeout == 5 for _, timeout in calls)
    assert "secret" not in repr(execution)


def test_external_freshness_unavailable_and_timeout_are_bounded(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    calls: list[tuple[tuple[str, ...], float]] = []

    def unavailable(command: tuple[str, ...], timeout_seconds: float):
        calls.append((command, timeout_seconds))
        return type("Result", (), {"returncode": 1, "stdout": "", "stderr": "private failure"})()

    registry = runtime_collection_adapter_registry(systemd_runner=unavailable)
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.freshness.quark-scheduler")
    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))
    assert execution.outcome is CollectionOutcome.BLOCKED
    assert execution.failure_category == "unavailable"
    assert len(calls) == 1

    def timed_out(command: tuple[str, ...], timeout_seconds: float):
        calls.append((command, timeout_seconds))
        raise TimeoutError("private timeout")

    registry = runtime_collection_adapter_registry(systemd_runner=timed_out)
    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))
    assert execution.outcome is CollectionOutcome.BLOCKED
    assert execution.failure_category == "timeout"
    assert calls[-1][1] == job.timeout_seconds


def test_external_freshness_marks_old_last_trigger_failed(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    def stale_runner(command: tuple[str, ...], timeout_seconds: float):
        if command[-1].endswith(".timer"):
            return type("Result", (), {
                "returncode": 0,
                "stdout": "ActiveState=active\nSubState=waiting\nResult=success\nLastTriggerUSecRealtime=2026-08-24 10:00:00 UTC\nNextElapseUSecRealtime=2026-08-24 10:05:00 UTC\n",
                "stderr": "",
            })()
        return type("Result", (), {
            "returncode": 0,
            "stdout": "ActiveState=inactive\nSubState=dead\nResult=success\n",
            "stderr": "",
        })()

    registry = runtime_collection_adapter_registry(
        systemd_runner=stale_runner,
        now=lambda: "2026-08-24T12:00:00+00:00",
    )
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.freshness.quark-scheduler")
    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))
    assert execution.outcome is CollectionOutcome.FAILED
    assert execution.failure_category == "stale"


def test_legacy_runtime_family_selector_seeds_only_selected_families_plus_freshness(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path, families=("crew_dispatch",))
    with SQLiteStore(path) as store:
        ids = {job.id for job in store.list_collection_jobs()}
    assert "collection.dispatch.crew" in ids
    assert "collection.freshness.psychlo-usage" in ids
    assert "collection.discovery.physical" not in ids
    assert "collection.knowledge.capture" not in ids


def test_scheduler_callback_passes_exact_timeout_and_one_message_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    observed: dict[str, object] = {}

    def fake_dispatch(store_path, **kwargs):
        observed.update(kwargs)
        return {"processed": 1}

    monkeypatch.setattr("overseer.cli.dispatch_crew_messages_status", fake_dispatch)
    registry = runtime_collection_adapter_registry()
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.dispatch.crew")
    registry.resolve(job, "crew-dispatch").collect(job, str(path))
    assert observed["limit"] == 1
    assert observed["timeout_seconds"] == job.timeout_seconds


def test_collection_projections_are_bounded_and_never_return_request_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    with SQLiteStore(path) as store:
        for index in range(4):
            store.request_collection_run(
                "collection.health.health.api",
                "operator",
                f"SECRET-REQUEST-REASON-{index}",
            )

    assert main(["collection-jobs", "--store", str(path), "--limit", "1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["returned_count"] == 1
    from overseer.cli import collection_jobs_status, request_collection_run_status

    projection = collection_jobs_status(path, limit=1)
    assert projection["total_count"] >= projection["returned_count"] == 1
    assert projection["truncated"] is True
    assert "SECRET-REQUEST-REASON" not in json.dumps(projection)
    request_projection = request_collection_run_status(path, "collection.health.health.api", "operator", "SECRET-REQUEST-REASON")
    assert "SECRET-REQUEST-REASON" not in json.dumps(request_projection)


def test_scheduler_projections_bound_jobs_incidents_requests_and_leases(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    with SQLiteStore(path) as store:
        for index in range(120):
            job_id = f"collection.fixture.{index:03d}"
            store.save_collection_job(
                CollectionJob(
                    id=job_id,
                    kind=CollectionJobKind.HOST_INSPECTION,
                    owner_domain=OwnerDomain.ODO,
                    resource_id=f"fixture.resource.{index:03d}",
                )
            )
            store.request_collection_run(job_id, "operator", f"SECRET-FIXTURE-REASON-{index}")
        for generation in range(3):
            store.save_collection_incident(
                TriageIncident(
                    id=f"incident.fixture.{generation}",
                    job_id="collection.fixture.000",
                    resource_id="fixture.resource.000",
                    first_failure_at="2026-08-24T12:00:00+00:00",
                    latest_failure_at="2026-08-24T12:00:00+00:00",
                    severity=RiskLevel.MEDIUM,
                    owner_domain=OwnerDomain.ODO,
                    evidence_ids=(f"evidence.fixture.{generation}",),
                    generation=generation + 1,
                )
            )
        state = store.load_collection_job_state("collection.fixture.000")
        store.save_collection_job_state(
            state.__class__(
                **{
                    **state.__dict__,
                    "active_lease_id": "lease.fixture.000",
                    "lease_owner": "worker.fixture",
                    "lease_expires_at": "2030-01-01T00:00:00+00:00",
                }
            )
        )

    from overseer.cli import collection_jobs_status, collection_scheduler_status

    jobs = collection_jobs_status(path, limit=10, incident_limit=1)
    scheduler = collection_scheduler_status(path, limit=1)
    assert jobs["total_count"] > jobs["returned_count"] == 10
    assert jobs["truncated"] is True
    fixture = next(row for row in jobs["jobs"] if row["id"] == "collection.fixture.000")
    assert fixture["incident_total_count"] == 3
    assert fixture["incident_returned_count"] == 1
    assert fixture["incident_truncated"] is True
    assert jobs["request_truncated"] is True
    assert scheduler["leased_returned_count"] == 1
    assert scheduler["leased_truncated"] is False
    assert "SECRET-FIXTURE-REASON" not in json.dumps(jobs)
    assert "SECRET-FIXTURE-REASON" not in json.dumps(scheduler)
