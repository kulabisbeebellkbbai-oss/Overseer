"""Deterministic, approval-aware repair coordination for collection incidents."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .admin import plan_user_service_restart
from .collection_models import (
    CollectionJob,
    RepairAttempt,
    RepairPolicy,
    RepairRunbook,
    TriageIncident,
    TriageIncidentStatus,
)
from .core import RiskLevel
from .store import SQLiteStore

SUPPORTED_ACTIONS = frozenset({"retry_read_only", "prune_bounded_evidence", "stage_user_service_restart"})


@dataclass(frozen=True)
class RepairResult:
    disposition: str
    incident_id: str
    runbook_id: str | None = None
    repair_attempt_id: str | None = None
    request_id: str | None = None
    admin_plan_id: str | None = None
    evidence_ids: tuple[str, ...] = ()


def _parse(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("repair clock must return an ISO-8601 UTC timestamp")
    return parsed.astimezone(UTC)


class RepairCoordinator:
    def __init__(
        self,
        store_path: str | Path,
        *,
        repair_adapters: Mapping[str, Callable[..., object]] | None = None,
        clock: Callable[[], str] | None = None,
    ) -> None:
        self.store_path = str(store_path)
        self.repair_adapters = dict(repair_adapters or {})
        self.clock = clock or (lambda: datetime.now(UTC).isoformat())

    def _now(self) -> str:
        value = self.clock()
        _parse(value)
        return value

    @staticmethod
    def _attempt_id(incident: TriageIncident, runbook: RepairRunbook) -> str:
        digest = hashlib.sha256(f"{incident.id}:{incident.generation}:{runbook.id}".encode()).hexdigest()[:48]
        return f"repair.attempt.{digest}"

    def advance(self, incident: TriageIncident, runbook: RepairRunbook | None = None) -> RepairResult:
        if not isinstance(incident, TriageIncident):
            raise ValueError("repair advancement requires a triage incident")
        now = self._now()
        with SQLiteStore(self.store_path) as store:
            # BEGIN IMMEDIATE and every read/write below make incident state,
            # runbook selection, cooldown, and the repair side effect one
            # serialized decision. The caller's object is only a compare token.
            with store.agent_transaction():
                persisted = store.load_collection_incident(incident.id)
                if persisted != incident:
                    raise ValueError("stale triage incident")
                if persisted.status is not TriageIncidentStatus.OPEN:
                    raise ValueError("triage incident is not open")
                job = store.load_collection_job(persisted.job_id)

                if runbook is not None and runbook.job_id != persisted.job_id:
                    raise ValueError("runbook does not bind to collection job")
                if runbook is not None and runbook.resource_id != persisted.resource_id:
                    raise ValueError("runbook does not bind to incident resource")
                if runbook is None:
                    selected = next(
                        (
                            item for item in store.list_repair_runbooks()
                            if item.job_id == persisted.job_id and item.resource_id == persisted.resource_id
                        ),
                        None,
                    )
                else:
                    try:
                        selected = store.load_repair_runbook(runbook.id)
                    except KeyError as error:
                        raise ValueError("stale repair runbook") from error
                    if selected != runbook:
                        raise ValueError("stale repair runbook")

                if job.repair_policy is RepairPolicy.TRIAGE_ONLY:
                    return RepairResult("triage_only", persisted.id)
                if selected is None:
                    return RepairResult("unavailable", persisted.id)
                if selected.job_id != persisted.job_id:
                    raise ValueError("runbook does not bind to collection job")
                if selected.resource_id != persisted.resource_id:
                    raise ValueError("runbook does not bind to incident resource")
                if selected.adapter_binding not in SUPPORTED_ACTIONS:
                    raise ValueError("unsupported repair action")
                if not selected.approval_required and selected.risk_level is not RiskLevel.LOW:
                    raise ValueError("automatic repair must be low risk")
                if not selected.approval_required and job.repair_policy is not RepairPolicy.PREAPPROVED_LOW_RISK:
                    return RepairResult("triage_only", persisted.id, selected.id)

                incident_runs = {
                    item.id: item
                    for item in store.list_collection_runs()
                    if item.id in persisted.evidence_ids
                }
                failure_category = next(
                    (item.error_category for item in reversed(tuple(incident_runs.values())) if item.error_category),
                    None,
                )
                if failure_category is not None and failure_category not in selected.failure_categories:
                    raise ValueError("runbook does not support incident failure category")

                attempt_id = self._attempt_id(persisted, selected)
                attempts = [
                    item for item in store.list_repair_attempts()
                    if item.incident_id == persisted.id and item.runbook_id == selected.id
                ]
                if attempts:
                    previous = attempts[0]
                    if previous.id != attempt_id:
                        raise ValueError("repair idempotency key produced a different attempt")
                    if _parse(now) < _parse(previous.attempted_at) + timedelta(seconds=selected.cooldown_seconds):
                        return RepairResult("cooldown", persisted.id, selected.id, previous.id)
                    return RepairResult("already_attempted", persisted.id, selected.id, previous.id)

                if selected.adapter_binding != "stage_user_service_restart" and selected.approval_required:
                    return RepairResult("approval_required", persisted.id, selected.id)

                if selected.adapter_binding == "stage_user_service_restart":
                    plan_id = f"admin.repair.{persisted.id}.g{persisted.generation}"
                    plan = plan_user_service_restart(
                        plan_id,
                        persisted.resource_id,
                        f"stage exact repair plan for collection incident {persisted.id}",
                        current_state="collection incident remains open",
                    )
                    existing = next((item for item in store.list_admin_change_plans() if item.id == plan_id), None)
                    if existing is None:
                        store.save_admin_change_plan(plan)
                    elif existing != plan:
                        raise ValueError("immutable repair admin plan collision")
                    store.save_repair_attempt(
                        RepairAttempt(
                            id=attempt_id,
                            incident_id=persisted.id,
                            runbook_id=selected.id,
                            attempted_at=now,
                            authorization_id=plan_id,
                            outcome="approval_required",
                        )
                    )
                    return RepairResult("approval_required", persisted.id, selected.id, attempt_id, admin_plan_id=plan_id)

                request = None
                if selected.adapter_binding == "retry_read_only":
                    earliest = (_parse(now) + timedelta(seconds=selected.cooldown_seconds)).isoformat()
                    request = store.request_collection_run(
                        persisted.job_id,
                        "repair-coordinator",
                        f"verification for incident {persisted.id}",
                        earliest_execution_at=earliest,
                        requested_at=now,
                    )
                    outcome = "verification_queued"
                    evidence_ids = (request.id,)
                elif selected.adapter_binding == "prune_bounded_evidence":
                    store.prune_collection_runs_for_job(persisted.job_id, job.retention_limit)
                    outcome = "pruned"
                    evidence_ids = ()
                else:
                    raise ValueError("unsupported repair action")
                store.save_repair_attempt(
                    RepairAttempt(
                        id=attempt_id,
                        incident_id=persisted.id,
                        runbook_id=selected.id,
                        attempted_at=now,
                        outcome=outcome,
                        result_evidence_ids=evidence_ids,
                    )
                )
                return RepairResult(
                    outcome,
                    persisted.id,
                    selected.id,
                    attempt_id,
                    request_id=request.id if request is not None else None,
                    evidence_ids=evidence_ids,
                )
