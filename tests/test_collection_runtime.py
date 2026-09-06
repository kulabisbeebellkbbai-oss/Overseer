from __future__ import annotations

import json
import sqlite3
import subprocess
import threading
import time
from pathlib import Path

import pytest

from overseer import runtime as runtime_module
from overseer.cli import main
from overseer.collection_models import CollectionJob, CollectionJobKind, CollectionOutcome, TriageIncident
from overseer.collection_scheduler import CollectionScheduler
from overseer.config import config_from_mapping
from overseer.core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from overseer.health import HealthTarget, ProbeType
from overseer.host import HostCommandObservation
from overseer.git import git_status_projection_status
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
    health = next(job for job in jobs if job.kind == CollectionJobKind.HEALTH_PROBE)
    host = next(job for job in jobs if job.id == "collection.host.inspection")
    assert health.concurrency_key == "health"
    assert host.concurrency_key == "collection"


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
    assert jobs["collection.host.inspection"].timeout_seconds == 5


def test_dedicated_principal_reseeding_keeps_only_fixed_bridge_collectors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    mutation_job_ids = {
        "collection.dispatch.crew",
        "collection.usage.continuation",
        "collection.knowledge.capture",
        "collection.station.audit",
    }
    bridge_job_ids = {
        "collection.freshness.psychlo-usage",
        "collection.freshness.quark-scheduler",
        "collection.git.overseer",
    }
    user_session_ids = mutation_job_ids | bridge_job_ids
    with SQLiteStore(path) as store:
        for job_id in user_session_ids:
            job = store.load_collection_job(job_id)
            store.save_collection_job(
                job.__class__(
                    **{
                        **job.__dict__,
                        "enabled": job_id
                        != "collection.freshness.psychlo-usage",
                    }
                )
            )
        store.save_collection_job(
            CollectionJob(
                id="collection.custom.user-git",
                kind=CollectionJobKind.GIT_INSPECTION,
                owner_domain=OwnerDomain.EZRI,
                resource_id="git.custom",
                enabled=True,
            )
        )

    monkeypatch.setenv("OVERSEER_DEDICATED_PRINCIPAL", "1")
    result = seed_default_collection_jobs(path)

    with SQLiteStore(path) as store:
        jobs = {job.id: job for job in store.list_collection_jobs()}
    assert all(not jobs[job_id].enabled for job_id in mutation_job_ids)
    assert all(jobs[job_id].enabled for job_id in bridge_job_ids)
    assert jobs["collection.custom.user-git"].enabled is False
    assert jobs["collection.health.health.api"].enabled is True
    disabled = {item["job_id"]: item["reason"] for item in result["disabled"]}
    assert all(
        disabled[job_id] == "user-session bridge is required in dedicated-principal mode"
        for job_id in mutation_job_ids | {"collection.custom.user-git"}
    )
    assert not bridge_job_ids & disabled.keys()


def test_dedicated_principal_filtered_seeding_disables_forged_bridge_definitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    forged = {
        "collection.freshness.psychlo-usage": CollectionJobKind.CREW_DISPATCH,
        "collection.freshness.quark-scheduler": CollectionJobKind.GIT_INSPECTION,
        "collection.git.overseer": CollectionJobKind.FRESHNESS_PROJECTION,
    }
    with sqlite3.connect(path) as connection:
        for job_id, kind in forged.items():
            row = connection.execute(
                "SELECT payload FROM collection_jobs WHERE id=?", (job_id,)
            ).fetchone()
            payload = json.loads(row[0])
            payload.update(
                {
                    "kind": kind.value,
                    "owner_domain": OwnerDomain.SISKO.value,
                    "resource_id": "forged.resource",
                    "target_id": "forged.target",
                    "enabled": True,
                }
            )
            connection.execute(
                "UPDATE collection_jobs SET kind=?, owner_domain=?, resource_id=?, target_id=?, enabled=1, payload=? WHERE id=?",
                (
                    kind.value,
                    OwnerDomain.SISKO.value,
                    "forged.resource",
                    "forged.target",
                    json.dumps(payload, separators=(",", ":")),
                    job_id,
                ),
            )
        connection.commit()

    monkeypatch.setenv("OVERSEER_DEDICATED_PRINCIPAL", "1")
    result = seed_default_collection_jobs(path, families=("crew_dispatch",))

    with SQLiteStore(path) as store:
        jobs = {job.id: job for job in store.list_collection_jobs()}
    assert all(not jobs[job_id].enabled for job_id in forged)
    disabled = {
        item["job_id"]: item["reason"]
        for item in result["disabled"]
    }
    assert all(
        disabled[job_id] == "reserved bridge binding is invalid"
        for job_id in forged
    )


def test_dedicated_principal_filtered_seeding_adds_all_fixed_bridge_jobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _seed_resource_and_target(tmp_path)
    monkeypatch.setenv("OVERSEER_DEDICATED_PRINCIPAL", "1")

    seed_default_collection_jobs(path, families=("crew_dispatch",))

    with SQLiteStore(path) as store:
        jobs = {job.id: job for job in store.list_collection_jobs()}
    assert all(
        jobs[job_id].enabled
        for job_id in (
            "collection.freshness.psychlo-usage",
            "collection.freshness.quark-scheduler",
            "collection.git.overseer",
        )
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
                "stdout": "ActiveState=active\nSubState=waiting\nResult=success\nLastTriggerUSec=Sat 2026-08-24 12:00:00 UTC\nNextElapseUSecMonotonic=6d 15h 34min 39s\n",
                "stderr": "secret=must-not-persist",
            })()
        return type("Result", (), {
            "returncode": 0,
            "stdout": "ActiveState=inactive\nSubState=dead\nResult=success\n",
            "stderr": "",
        })()

    registry = runtime_collection_adapter_registry(systemd_runner=runner, now=lambda: "2026-08-24T12:07:00+00:00")
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.freshness.psychlo-usage")
    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))

    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert all(command[0][0:3] == ("systemctl", "--user", "show") for command in calls)
    assert {command[-1] for command, _ in calls} == {
        "overseer-psychlo-usage.timer",
        "overseer-psychlo-cycle.service",
    }
    assert all("start" not in command and "enable" not in command for command, _ in calls)
    assert all(timeout == 5 for _, timeout in calls)
    assert all("LastTriggerUSec" in command[-2] for command, _ in calls)
    assert all("NextElapseUSecMonotonic" in command[-2] for command, _ in calls)
    assert "secret" not in repr(execution)


def test_external_freshness_systemd_runner_forces_utc_timestamps(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setenv("OVERSEER_PRIVATE_FIXTURE", "must-not-propagate")
    monkeypatch.setattr(runtime_module.subprocess, "run", run)

    runtime_module._systemd_runner(("systemctl", "--user", "show", "example.timer"), 5)

    assert captured["env"]["TZ"] == "UTC"
    assert "OVERSEER_PRIVATE_FIXTURE" not in captured["env"]


def test_external_freshness_uses_remaining_shared_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    remaining = iter((4.0, 1.0))
    calls: list[float] = []

    def runner(command: tuple[str, ...], timeout_seconds: float):
        calls.append(timeout_seconds)
        if command[-1].endswith(".timer"):
            stdout = "ActiveState=active\nSubState=waiting\nResult=success\nLastTriggerUSec=Sat 2026-08-24 12:00:00 UTC\nNextElapseUSecMonotonic=1min\n"
        else:
            stdout = "ActiveState=inactive\nSubState=dead\nResult=success\n"
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr(runtime_module, "require_collection_time", lambda: next(remaining))
    registry = runtime_collection_adapter_registry(systemd_runner=runner, now=lambda: "2026-08-24T12:01:00+00:00")
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.freshness.psychlo-usage")

    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))

    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert calls == [4.0, 1.0]


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


def test_external_freshness_rejects_future_last_trigger(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    def future_runner(command: tuple[str, ...], timeout_seconds: float):
        del timeout_seconds
        if command[-1].endswith(".timer"):
            stdout = "ActiveState=active\nSubState=waiting\nResult=success\nLastTriggerUSecRealtime=2026-08-24 12:05:00 UTC\nNextElapseUSecRealtime=2026-08-24 12:10:00 UTC\n"
        else:
            stdout = "ActiveState=inactive\nSubState=dead\nResult=success\n"
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    registry = runtime_collection_adapter_registry(
        systemd_runner=future_runner,
        now=lambda: "2026-08-24T12:00:00+00:00",
    )
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.freshness.quark-scheduler")
    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))
    assert execution.outcome is CollectionOutcome.FAILED
    assert execution.failure_category == "unavailable"


def test_external_freshness_fails_when_psychlo_cycle_stage_fails(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    def failed_cycle(command: tuple[str, ...], timeout_seconds: float):
        del timeout_seconds
        if command[-1].endswith(".timer"):
            stdout = "ActiveState=active\nSubState=waiting\nResult=success\nLastTriggerUSec=Sat 2026-08-24 12:00:00 UTC\nNextElapseUSecMonotonic=1min\n"
        else:
            assert command[-1] == "overseer-psychlo-cycle.service"
            stdout = "ActiveState=failed\nSubState=failed\nResult=exit-code\n"
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    registry = runtime_collection_adapter_registry(
        systemd_runner=failed_cycle,
        now=lambda: "2026-08-24T12:01:00+00:00",
    )
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.freshness.psychlo-usage")

    execution = registry.resolve(job, "freshness-projection").collect(job, str(path))

    assert execution.outcome is CollectionOutcome.FAILED
    assert execution.failure_category == "unavailable"


def test_dedicated_runtime_collects_fixed_user_session_projections_through_bridge(
    tmp_path: Path,
) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    calls: list[str] = []

    class Bridge:
        def call(self, method: str, request_id: str) -> dict[str, object]:
            assert request_id.startswith("runtime-")
            calls.append(method)
            if method == "overseer.scheduler.freshness.v1":
                projection: dict[str, object] = {
                    "state": "available",
                    "observed_at": "2026-09-06T12:00:00+00:00",
                    "services": [
                        {
                            "job_id": "collection.freshness.psychlo-usage",
                            "outcome": "succeeded",
                            "evidence_id": "freshness.psychlo-usage",
                        },
                        {
                            "job_id": "collection.freshness.quark-scheduler",
                            "outcome": "succeeded",
                            "evidence_id": "freshness.quark-scheduler",
                        },
                    ],
                }
            else:
                assert method == "overseer.git.status.v1"
                projection = {
                    "state": "available",
                    "observed_at": "2026-09-06T12:00:00+00:00",
                    "git": {
                        "repository": "overseer",
                        "branch": "feature/maintenance-window-v1-1-6",
                        "head": "a" * 40,
                        "short_head": "a" * 7,
                        "upstream": "origin/feature/maintenance-window-v1-1-6",
                        "ahead": 1,
                        "behind": 0,
                        "dirty": True,
                        "changed": 1,
                        "staged": 0,
                        "unstaged": 1,
                        "untracked": 0,
                        "conflicted": 0,
                        "remote_owner": "example",
                        "remote_repo": "overseer",
                    },
                }
            return {
                "protocol": "overseer.user-bridge.v1",
                "request_id": request_id,
                "method": method,
                "status": "ok",
                "projection": projection,
            }

    registry = runtime_collection_adapter_registry(user_bridge_client=Bridge())
    with SQLiteStore(path) as store:
        psychlo = store.load_collection_job("collection.freshness.psychlo-usage")
        git = store.load_collection_job("collection.git.overseer")

    freshness_execution = registry.resolve(
        psychlo, "freshness-projection"
    ).collect(psychlo, str(path))
    git_execution = registry.resolve(git, "git-inspection").collect(git, str(path))

    assert freshness_execution.outcome is CollectionOutcome.SUCCEEDED
    assert freshness_execution.evidence_ids == ("freshness.psychlo-usage",)
    assert git_execution.outcome is CollectionOutcome.SUCCEEDED
    assert calls == [
        "overseer.scheduler.freshness.v1",
        "overseer.git.status.v1",
    ]
    persisted = git_status_projection_status(path)
    assert persisted["projection_available"] is True
    assert persisted["repo_path"] == "Overseer"
    assert persisted["branch"] == "feature/maintenance-window-v1-1-6"
    assert persisted["dirty"] is True
    assert persisted["remote"] == {
        "name": "origin",
        "url": None,
        "web_url": "https://github.com/example/overseer",
        "owner": "example",
        "repo": "overseer",
        "default_branch_guess": "feature/maintenance-window-v1-1-6",
        "current_commit_url": "https://github.com/example/overseer/commit/" + "a" * 40,
    }


def test_dedicated_runtime_bridge_failure_is_bounded_without_direct_fallback(
    tmp_path: Path,
) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    class Bridge:
        def call(self, method: str, request_id: str) -> dict[str, object]:
            del method, request_id
            raise TimeoutError("private user-session detail")

    registry = runtime_collection_adapter_registry(
        user_bridge_client=Bridge(),
        systemd_runner=lambda *_args: pytest.fail("must not query the user manager directly"),
        git_projection_collector=lambda *_args, **_kwargs: pytest.fail(
            "must not inspect the user checkout directly"
        ),
    )
    with SQLiteStore(path) as store:
        psychlo = store.load_collection_job("collection.freshness.psychlo-usage")
        git = store.load_collection_job("collection.git.overseer")

    freshness_execution = registry.resolve(
        psychlo, "freshness-projection"
    ).collect(psychlo, str(path))
    git_execution = registry.resolve(git, "git-inspection").collect(git, str(path))

    assert freshness_execution.outcome is CollectionOutcome.BLOCKED
    assert freshness_execution.failure_category == "unavailable"
    assert git_execution.outcome is CollectionOutcome.BLOCKED
    assert git_execution.failure_category == "unavailable"


def test_dedicated_runtime_rejects_stale_bridge_projections(
    tmp_path: Path,
) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)

    class Bridge:
        def call(self, method: str, request_id: str) -> dict[str, object]:
            del request_id
            projection: dict[str, object] = {
                "state": "stale",
                "observed_at": "2026-09-06T12:00:00+00:00",
            }
            if method == "overseer.scheduler.freshness.v1":
                projection["services"] = [
                    {
                        "job_id": "collection.freshness.psychlo-usage",
                        "outcome": "succeeded",
                        "evidence_id": "freshness.psychlo-usage",
                    }
                ]
            else:
                projection["git"] = {}
            return {
                "status": "ok",
                "method": method,
                "projection": projection,
            }

    registry = runtime_collection_adapter_registry(user_bridge_client=Bridge())
    with SQLiteStore(path) as store:
        psychlo = store.load_collection_job(
            "collection.freshness.psychlo-usage"
        )
        git = store.load_collection_job("collection.git.overseer")

    freshness_execution = registry.resolve(
        psychlo,
        "freshness-projection",
    ).collect(psychlo, str(path))
    git_execution = registry.resolve(git, "git-inspection").collect(git, str(path))

    assert freshness_execution.outcome is CollectionOutcome.FAILED
    assert freshness_execution.failure_category == "stale"
    assert git_execution.outcome is CollectionOutcome.FAILED
    assert git_execution.failure_category == "stale"


def test_dedicated_runtime_unit_depends_on_the_fixed_user_bridge() -> None:
    root = Path(__file__).parents[1]
    runtime_unit = (root / "systemd/overseer-runtime-system.service").read_text()
    bridge_unit = (root / "systemd/overseer-codex-user-bridge.service").read_text()

    assert "Wants=overseer-codex-user-bridge.socket" in runtime_unit
    assert "After=local-fs.target overseer-codex-user-bridge.socket" in runtime_unit
    assert (
        "Environment=OVERSEER_USER_BRIDGE_SOCKET=/run/overseer/codex-user-bridge.sock"
        in runtime_unit
    )
    assert "Environment=OVERSEER_USER_BRIDGE_SERVER_UID=@GOD_UID@" in runtime_unit
    assert "Environment=XDG_RUNTIME_DIR=/run/user/@GOD_UID@" in bridge_unit
    assert (
        "Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/@GOD_UID@/bus"
        in bridge_unit
    )
    assert (
        'BindReadOnlyPaths="/home/god/Documents/Codex Workspace/Overseer"'
        in bridge_unit
    )


def test_virtual_discovery_runs_only_one_bounded_listener_command(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    calls: list[tuple[tuple[str, ...], float]] = []

    def runner(command, timeout_seconds):
        calls.append((tuple(command), timeout_seconds))
        return HostCommandObservation(
            name="ss",
            command=tuple(command),
            exit_code=0,
            stdout="LISTEN 0 4096 127.0.0.1:8787 0.0.0.0:*",
        )

    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.discovery.virtual")

    registry = runtime_collection_adapter_registry(virtual_listener_runner=runner)
    execution = registry.resolve(job, "virtual-discovery").collect(job, str(path))

    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert calls == [(('ss', '-ltn'), job.timeout_seconds)]
    with SQLiteStore(path) as store:
        resource = store.load_resource("listener.tcp.127-0-0-1.8787")
        assert store.load_latest_host_snapshot() is None
    assert resource.identifiers["snapshot_id"].startswith("listeners.")
    assert "process_hint" not in resource.identifiers


def test_git_status_is_an_independent_scheduled_projection(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    calls: list[tuple[str, Path, float]] = []

    def collector(store_path: str, repo_path: Path, *, timeout_seconds: float):
        calls.append((store_path, repo_path, timeout_seconds))
        return {
            "outcome": "succeeded",
            "evidence_ids": ("git.status.fixture",),
        }

    registry = runtime_collection_adapter_registry(git_projection_collector=collector)
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.git.overseer")
    execution = registry.resolve(job, "git-inspection").collect(job, str(path))

    assert job.kind is CollectionJobKind.GIT_INSPECTION
    assert job.enabled is True
    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert calls == [(str(path), Path.cwd(), job.timeout_seconds)]


def test_storage_capacity_is_an_independent_scheduled_projection(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    calls: list[tuple[str, float]] = []

    def collector(store_path: str, *, timeout_seconds: float):
        calls.append((store_path, timeout_seconds))
        return {
            "outcome": "succeeded",
            "evidence_ids": ("evidence.storage.capacity",),
        }

    registry = runtime_collection_adapter_registry(storage_projection_collector=collector)
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.storage.capacity")
    execution = registry.resolve(job, "storage-inspection").collect(job, str(path))

    assert job.kind is CollectionJobKind.STORAGE_INSPECTION
    assert job.enabled is True
    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert calls == [(str(path), job.timeout_seconds)]


def test_firmware_is_an_independent_scheduled_projection(tmp_path: Path) -> None:
    path = _seed_resource_and_target(tmp_path)
    seed_default_collection_jobs(path)
    calls: list[tuple[str, float]] = []

    def collector(store_path: str, *, timeout_seconds: float):
        calls.append((store_path, timeout_seconds))
        return {
            "outcome": "succeeded",
            "evidence_ids": ("firmware.inspection.fixture",),
        }

    registry = runtime_collection_adapter_registry(firmware_projection_collector=collector)
    with SQLiteStore(path) as store:
        job = store.load_collection_job("collection.firmware.inspection")
    execution = registry.resolve(job, "firmware-inspection").collect(job, str(path))

    assert job.kind is CollectionJobKind.FIRMWARE_INSPECTION
    assert job.enabled is True
    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert calls == [(str(path), job.timeout_seconds)]


def test_scheduled_firmware_collection_updates_both_dashboard_projections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from overseer.maintenance_projections import (
        capture_firmware_projections,
        firmware_preflight_projection,
        firmware_status_projection,
    )
    from overseer.packages import (
        EfivarEntry,
        FirmwareInspectionSnapshot,
        FirmwarePreflightSnapshot,
        FirmwareUpdate,
    )

    class FirmwareAdapter:
        def __init__(self, timeout_seconds: float) -> None:
            assert timeout_seconds == pytest.approx(11.25)

        def inspect(self, captured_at: str) -> FirmwareInspectionSnapshot:
            return FirmwareInspectionSnapshot(
                id="firmware-inspection.fixture",
                captured_at=captured_at,
                command=("fwupdmgr", "get-upgrades", "--no-reboot-check"),
                exit_code=0,
                updates=(
                    FirmwareUpdate(
                        device="UEFI dbx",
                        title="Secure Boot dbx update",
                        release_id="release.fixture",
                        urgency="high",
                        reboot_required=True,
                    ),
                ),
            )

    class PreflightAdapter:
        def __init__(self, **kwargs: object) -> None:
            assert float(kwargs["timeout_seconds"]) > 0

        def inspect(self, captured_at: str) -> FirmwarePreflightSnapshot:
            return FirmwarePreflightSnapshot(
                id="firmware-preflight.fixture",
                captured_at=captured_at,
                efivar_path="/sys/firmware/efi/efivars",
                efivar_accessible=True,
                efivars=(EfivarEntry("dump-fixture", 1024),),
            )

    monkeypatch.setattr(
        "overseer.maintenance_projections.FwupdFirmwareInspectionAdapter",
        FirmwareAdapter,
    )
    monkeypatch.setattr(
        "overseer.maintenance_projections.FirmwarePreflightAdapter",
        PreflightAdapter,
    )
    path = _store_path(tmp_path)
    result = capture_firmware_projections(
        path,
        captured_at="2026-08-25T12:00:00Z",
    )

    firmware = firmware_status_projection(path)
    preflight = firmware_preflight_projection(path)
    assert result["outcome"] == "succeeded"
    assert firmware["updates"] == 1
    assert firmware["reboot_required"] == 1
    assert firmware["items"][0]["status"] == "available"
    assert firmware["items"][0]["blocker_type"] == ""
    assert firmware["items"][0]["blocker_resolution"]
    assert firmware["items"][0]["safe_preflight"] == [
        "fwupdmgr get-upgrades --no-reboot-check"
    ]
    assert preflight["stale_dump_candidate_count"] == 1
    assert firmware["collection_mode"] == "durable_sqlite_projection"
    assert preflight["collection_mode"] == "durable_sqlite_projection"


def test_firmware_collection_does_not_persist_after_its_absolute_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from overseer.maintenance_projections import (
        FIRMWARE_STATUS_PROJECTION_ID,
        capture_firmware_projections,
    )
    from overseer.packages import FirmwareInspectionSnapshot

    class FirmwareAdapter:
        def __init__(self, timeout_seconds: float) -> None:
            self.timeout_seconds = timeout_seconds

        def inspect(self, captured_at: str) -> FirmwareInspectionSnapshot:
            return FirmwareInspectionSnapshot(
                id="firmware-inspection.deadline",
                captured_at=captured_at,
                command=("fwupdmgr", "get-upgrades", "--no-reboot-check"),
                exit_code=0,
                updates=(),
            )

    monkeypatch.setattr(
        "overseer.maintenance_projections.FwupdFirmwareInspectionAdapter",
        FirmwareAdapter,
    )
    ticks = iter((100.0, 116.0))
    path = _store_path(tmp_path)
    result = capture_firmware_projections(
        path,
        timeout_seconds=15.0,
        captured_at="2026-08-25T12:00:00Z",
        monotonic=lambda: next(ticks),
    )

    assert result["outcome"] == "failed"
    assert result["failure_category"] == "timeout"
    with SQLiteStore(path) as store:
        with pytest.raises(KeyError):
            store.load_dashboard_projection(FIRMWARE_STATUS_PROJECTION_ID)


def test_firmware_collection_database_lock_is_bounded_and_writes_no_partial_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from overseer.maintenance_projections import (
        FIRMWARE_PREFLIGHT_PROJECTION_ID,
        FIRMWARE_STATUS_PROJECTION_ID,
        capture_firmware_projections,
    )
    from overseer.packages import FirmwareInspectionSnapshot, FirmwarePreflightSnapshot

    class FirmwareAdapter:
        def __init__(self, timeout_seconds: float) -> None:
            self.timeout_seconds = timeout_seconds

        def inspect(self, captured_at: str) -> FirmwareInspectionSnapshot:
            return FirmwareInspectionSnapshot(
                id="firmware-inspection.locked",
                captured_at=captured_at,
                command=("fwupdmgr", "get-upgrades", "--no-reboot-check"),
                exit_code=0,
                updates=(),
            )

    class PreflightAdapter:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def inspect(self, captured_at: str) -> FirmwarePreflightSnapshot:
            return FirmwarePreflightSnapshot(
                id="firmware-preflight.locked",
                captured_at=captured_at,
                efivar_path="/sys/firmware/efi/efivars",
                efivar_accessible=True,
                efivars=(),
            )

    monkeypatch.setattr(
        "overseer.maintenance_projections.FwupdFirmwareInspectionAdapter",
        FirmwareAdapter,
    )
    monkeypatch.setattr(
        "overseer.maintenance_projections.FirmwarePreflightAdapter",
        PreflightAdapter,
    )
    path = _store_path(tmp_path)
    with SQLiteStore(path):
        pass
    lock = sqlite3.connect(path, timeout=0.0)
    lock.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    try:
        result = capture_firmware_projections(
            path,
            timeout_seconds=0.3,
            captured_at="2026-08-25T12:00:00Z",
        )
    finally:
        elapsed = time.monotonic() - started
        lock.rollback()
        lock.close()

    assert result["outcome"] == "failed"
    assert result["failure_category"] == "timeout"
    assert elapsed < 1.0
    with SQLiteStore(path) as store:
        with pytest.raises(KeyError):
            store.load_dashboard_projection(FIRMWARE_STATUS_PROJECTION_ID)
        with pytest.raises(KeyError):
            store.load_dashboard_projection(FIRMWARE_PREFLIGHT_PROJECTION_ID)


def test_firmware_collection_process_boundary_reports_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from overseer.maintenance_projections import capture_firmware_projections_subprocess

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr("overseer.maintenance_projections.subprocess.run", timeout)
    result = capture_firmware_projections_subprocess(
        _store_path(tmp_path),
        timeout_seconds=0.2,
    )

    assert result == {
        "outcome": "failed",
        "failure_category": "timeout",
        "evidence_ids": (),
    }


def test_firmware_preflight_timeout_reaches_scheduler_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from overseer.maintenance_projections import capture_firmware_projections
    from overseer.packages import FirmwareInspectionSnapshot, FirmwarePreflightSnapshot

    class FirmwareAdapter:
        def __init__(self, timeout_seconds: float) -> None:
            self.timeout_seconds = timeout_seconds

        def inspect(self, captured_at: str) -> FirmwareInspectionSnapshot:
            return FirmwareInspectionSnapshot(
                id="firmware-inspection.timeout-classification",
                captured_at=captured_at,
                command=("fwupdmgr", "get-upgrades", "--no-reboot-check"),
                exit_code=0,
                updates=(),
            )

    class PreflightAdapter:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def inspect(self, captured_at: str) -> FirmwarePreflightSnapshot:
            return FirmwarePreflightSnapshot(
                id="firmware-preflight.timeout-classification",
                captured_at=captured_at,
                efivar_path="/sys/firmware/efi/efivars",
                efivar_accessible=False,
                efivars=(),
                error="efivarfs inspection timed out",
            )

    monkeypatch.setattr(
        "overseer.maintenance_projections.FwupdFirmwareInspectionAdapter",
        FirmwareAdapter,
    )
    monkeypatch.setattr(
        "overseer.maintenance_projections.FirmwarePreflightAdapter",
        PreflightAdapter,
    )
    result = capture_firmware_projections(
        _store_path(tmp_path),
        captured_at="2026-08-25T12:00:00Z",
    )

    assert result["outcome"] == "failed"
    assert result["failure_category"] == "timeout"


def test_scheduled_storage_collection_updates_dashboard_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    store_path = root / "state" / "overseer.sqlite3"
    store_path.parent.mkdir(parents=True)
    seed_default_collection_jobs(store_path)
    monkeypatch.setattr(
        "overseer.storage_evidence._df_rows",
        lambda *args, **kwargs: [
            {
                "source": "disk",
                "type": "ext4",
                "size": "1000",
                "used": "400",
                "available": "600",
                "use_percent": "40%",
                "mount": "/",
                "status": "ok",
            }
        ],
    )
    monkeypatch.setattr(
        "overseer.storage_evidence._capacity_summary",
        lambda: {"mount": "/", "total_bytes": 1000, "used_bytes": 400, "free_bytes": 600, "status": "ok"},
    )
    registry = runtime_collection_adapter_registry()
    with SQLiteStore(store_path) as store:
        job = store.load_collection_job("collection.storage.capacity")
    execution = registry.resolve(job, "storage-inspection").collect(job, str(store_path))

    from overseer.storage_evidence import storage_evidence_projection_status

    projected = storage_evidence_projection_status(store_path, root)
    assert execution.outcome is CollectionOutcome.SUCCEEDED
    assert projected["growth_sample_count"] == 1
    assert projected["mounts"][0]["use_percent"] == "40%"
    assert projected["capacity_summary"]["free_bytes"] == 600


def test_timed_out_storage_collection_cannot_persist_after_its_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    store_path = root / "state" / "overseer.sqlite3"
    store_path.parent.mkdir(parents=True)
    seed_default_collection_jobs(store_path, families=("storage",))
    with SQLiteStore(store_path) as store:
        job = store.load_collection_job("collection.storage.capacity")
        state = store.load_collection_job_state(job.id)
        store.save_collection_job(
            job.__class__(**{**job.__dict__, "timeout_seconds": 1}),
            state.__class__(**{**state.__dict__, "next_due_at": "2026-08-25T12:00:00+00:00"}),
        )

    monkeypatch.setattr(
        "overseer.storage_evidence._df_rows",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        "overseer.storage_evidence._capacity_summary",
        lambda: {"mount": "/", "status": "ok"},
    )
    save_entered = threading.Event()
    allow_save = threading.Event()
    original_save = SQLiteStore.save_dashboard_projection

    def delayed_save(store, projection_id, payload):
        save_entered.set()
        assert allow_save.wait(5)
        return original_save(store, projection_id, payload)

    monkeypatch.setattr(SQLiteStore, "save_dashboard_projection", delayed_save)
    scheduler = CollectionScheduler(
        store_path,
        runtime_collection_adapter_registry(),
        max_workers=1,
        clock=lambda: "2026-08-25T12:00:00+00:00",
    )
    try:
        cycle = scheduler.run_ready_once()
        assert save_entered.is_set()
        assert cycle.timed_out == 1

        lock = sqlite3.connect(store_path, isolation_level=None, timeout=0.0)
        try:
            lock.execute("BEGIN IMMEDIATE")
            allow_save.set()
            time.sleep(0.1)
            lock.rollback()
        finally:
            lock.close()
        scheduler.shutdown()

        with SQLiteStore(store_path) as store:
            with pytest.raises(KeyError):
                store.load_dashboard_projection("dashboard.storage.capacity")
    finally:
        allow_save.set()
        scheduler.shutdown()


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
