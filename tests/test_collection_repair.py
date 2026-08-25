from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from overseer import (
    CollectionOutcome,
    CollectionRun,
    CollectionJob,
    CollectionJobKind,
    OwnerDomain,
    RepairCoordinator,
    RepairPolicy,
    RepairRunbook,
    RiskLevel,
    SQLiteStore,
    TriageIncident,
    TriageIncidentStatus,
)

NOW = "2026-08-24T12:00:00+00:00"


def _job(path: Path, *, policy: RepairPolicy = RepairPolicy.TRIAGE_ONLY, resource: str = "resource.api") -> CollectionJob:
    job = CollectionJob(
        id="collection.api",
        kind=CollectionJobKind.HEALTH_PROBE,
        owner_domain=OwnerDomain.JULIAN,
        resource_id=resource,
        repair_policy=policy,
    )
    with SQLiteStore(path) as store:
        store.save_collection_job(job)
    return job


def _incident(path: Path, *, job_id: str = "collection.api", resource: str = "resource.api") -> TriageIncident:
    incident = TriageIncident(
        id="incident.collection.api.g1",
        job_id=job_id,
        resource_id=resource,
        first_failure_at=NOW,
        latest_failure_at=NOW,
        severity=RiskLevel.MEDIUM,
        owner_domain=OwnerDomain.JULIAN,
        evidence_ids=("run.failed",),
    )
    with SQLiteStore(path) as store:
        store.save_collection_incident(incident)
    return incident


def _runbook(*, action: str, job_id: str = "collection.api", resource: str = "resource.api", approval: bool = False, risk: RiskLevel = RiskLevel.LOW) -> RepairRunbook:
    return RepairRunbook(
        id=f"runbook.{action}",
        job_id=job_id,
        resource_id=resource,
        failure_categories=("unavailable", "timeout"),
        risk_level=risk,
        idempotency_contract="one attempt per incident generation",
        cooldown_seconds=30,
        approval_required=approval,
        adapter_binding=action,
    )


def test_triage_only_never_invokes_repair_adapter(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _job(path)
    incident = _incident(path)
    calls: list[str] = []
    coordinator = RepairCoordinator(path, repair_adapters={"retry_read_only": lambda *_: calls.append("called")})
    result = coordinator.advance(incident)
    assert result.disposition == "triage_only"
    assert calls == []
    with SQLiteStore(path) as store:
        assert store.list_repair_attempts() == ()


def test_preapproved_read_only_retry_requires_exact_job_binding(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _job(path, policy=RepairPolicy.PREAPPROVED_LOW_RISK)
    incident = _incident(path)
    foreign = _runbook(action="retry_read_only", job_id="foreign.job", resource="resource.api")
    with SQLiteStore(path) as store:
        store.save_repair_runbook(foreign)
    with pytest.raises(ValueError, match="runbook does not bind to collection job"):
        RepairCoordinator(path).advance(incident, foreign)


def test_service_restart_is_staged_and_never_executed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _job(path, policy=RepairPolicy.PREAPPROVED_LOW_RISK, resource="overseer.service")
    incident = _incident(path, resource="overseer.service")
    runbook = _runbook(action="stage_user_service_restart", resource="overseer.service", approval=True)
    with SQLiteStore(path) as store:
        store.save_repair_runbook(runbook)
    result = RepairCoordinator(path).advance(incident, runbook)
    assert result.disposition == "approval_required"
    assert result.admin_plan_id.startswith("admin.repair.")
    assert RepairCoordinator(path).advance(incident, runbook).disposition == "cooldown"
    with SQLiteStore(path) as store:
        assert store.list_admin_executions() == ()
        plans = store.list_admin_change_plans()
        assert len(plans) == 1
        assert plans[0].approved is False
        assert plans[0].canceled is False


def test_automatic_runbook_rejects_unsupported_failure_category(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _job(path, policy=RepairPolicy.PREAPPROVED_LOW_RISK)
    failed = CollectionRun(
        id="run.authentication", job_id="collection.api", trigger="test", started_at=NOW,
        completed_at=NOW, outcome=CollectionOutcome.FAILED, error_category="authentication",
    )
    with SQLiteStore(path) as store:
        store.save_collection_run(failed)
    incident = replace(_incident(path), evidence_ids=(failed.id,))
    with SQLiteStore(path) as store:
        store.save_collection_incident(incident)
        store.save_repair_runbook(_runbook(action="retry_read_only"))
    with pytest.raises(ValueError, match="failure category"):
        RepairCoordinator(path, clock=lambda: NOW).advance(incident)


def test_retry_read_only_enqueues_one_verification_request_after_cooldown(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    _job(path, policy=RepairPolicy.PREAPPROVED_LOW_RISK)
    incident = _incident(path)
    runbook = _runbook(action="retry_read_only")
    with SQLiteStore(path) as store:
        store.save_repair_runbook(runbook)
    coordinator = RepairCoordinator(path, clock=lambda: NOW)
    first = coordinator.advance(incident, runbook)
    second = coordinator.advance(incident, runbook)
    assert first.disposition == "verification_queued"
    assert second.disposition == "cooldown"
    with SQLiteStore(path) as store:
        requests = store.list_collection_requests()
        assert len(requests) == 1
        assert requests[0].job_id == incident.job_id
        assert len(store.list_repair_attempts()) == 1


def test_prune_bounded_evidence_does_not_prune_other_job(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    first = _job(path)
    other = replace(first, id="collection.other", resource_id="resource.other")
    with SQLiteStore(path) as store:
        store.save_collection_job(other)
        for index in range(3):
            from overseer import CollectionRun, CollectionOutcome

            store.save_collection_run(
                CollectionRun(
                    id=f"run.{index}", job_id=first.id, trigger="test", started_at=NOW,
                    completed_at=NOW, outcome=CollectionOutcome.FAILED, summary="bounded",
                )
            )
            store.save_collection_run(
                CollectionRun(
                    id=f"other.{index}", job_id=other.id, trigger="test", started_at=NOW,
                    completed_at=NOW, outcome=CollectionOutcome.FAILED, summary="bounded",
                )
            )
    incident = _incident(path)
    runbook = _runbook(action="prune_bounded_evidence", resource="resource.api")
    with SQLiteStore(path) as store:
        store.save_collection_job(replace(first, repair_policy=RepairPolicy.PREAPPROVED_LOW_RISK))
    with SQLiteStore(path) as store:
        store.save_repair_runbook(runbook)
    result = RepairCoordinator(path, clock=lambda: NOW).advance(incident, runbook)
    assert result.disposition == "pruned"
    with SQLiteStore(path) as store:
        assert {run.job_id for run in store.list_collection_runs()} == {first.id, other.id}
        assert len([run for run in store.list_collection_runs() if run.job_id == other.id]) == 3
