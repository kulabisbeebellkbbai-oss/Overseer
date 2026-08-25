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

    def _runbook_for(self, incident: TriageIncident, supplied: RepairRunbook | None) -> RepairRunbook | None:
        if supplied is not None:
            return supplied
        with SQLiteStore(self.store_path) as store:
            candidates = [
                runbook for runbook in store.list_repair_runbooks()
                if runbook.job_id == incident.job_id and runbook.resource_id == incident.resource_id
            ]
        return candidates[0] if candidates else None

    def advance(self, incident: TriageIncident, runbook: RepairRunbook | None = None) -> RepairResult:
        if not isinstance(incident, TriageIncident):
            raise ValueError("repair advancement requires a triage incident")
        if incident.status is not TriageIncidentStatus.OPEN:
            return RepairResult("already_resolved", incident.id)
        with SQLiteStore(self.store_path) as store:
            job = store.load_collection_job(incident.job_id)
        if runbook is not None and runbook.job_id != incident.job_id:
            raise ValueError("runbook does not bind to collection job")
        if runbook is not None and runbook.resource_id != incident.resource_id:
            raise ValueError("runbook does not bind to incident resource")
        if job.repair_policy is RepairPolicy.TRIAGE_ONLY:
            return RepairResult("triage_only", incident.id)
        selected = self._runbook_for(incident, runbook)
        if selected is None:
            return RepairResult("unavailable", incident.id)
        if selected.job_id != incident.job_id:
            raise ValueError("runbook does not bind to collection job")
        if selected.resource_id != incident.resource_id:
            raise ValueError("runbook does not bind to incident resource")
        if selected.adapter_binding not in SUPPORTED_ACTIONS:
            raise ValueError("unsupported repair action")
        if not selected.approval_required and selected.risk_level is not RiskLevel.LOW:
            raise ValueError("automatic repair must be low risk")
        if not selected.approval_required and job.repair_policy is not RepairPolicy.PREAPPROVED_LOW_RISK:
            return RepairResult("triage_only", incident.id, selected.id)

        now = self._now()
        with SQLiteStore(self.store_path) as store:
            incident_runs = {
                run.id: run
                for run in store.list_collection_runs()
                if run.id in incident.evidence_ids
            }
        failure_category = next(
            (run.error_category for run in reversed(tuple(incident_runs.values())) if run.error_category),
            None,
        )
        if failure_category is not None and failure_category not in selected.failure_categories:
            raise ValueError("runbook does not support incident failure category")
        attempt_id = self._attempt_id(incident, selected)
        with SQLiteStore(self.store_path) as store:
            attempts = [
                attempt for attempt in store.list_repair_attempts()
                if attempt.incident_id == incident.id and attempt.runbook_id == selected.id
            ]
        if attempts:
            previous = attempts[0]
            if previous.id != attempt_id:
                raise ValueError("repair idempotency key produced a different attempt")
            if _parse(now) < _parse(previous.attempted_at) + timedelta(seconds=selected.cooldown_seconds):
                return RepairResult("cooldown", incident.id, selected.id, previous.id)
            return RepairResult("already_attempted", incident.id, selected.id, previous.id)

        if selected.adapter_binding != "stage_user_service_restart" and selected.approval_required:
            return RepairResult("approval_required", incident.id, selected.id)

        if selected.adapter_binding == "stage_user_service_restart":
            plan_id = f"admin.repair.{incident.id}.g{incident.generation}"
            plan = plan_user_service_restart(
                plan_id,
                incident.resource_id,
                f"stage exact repair plan for collection incident {incident.id}",
                current_state="collection incident remains open",
            )
            with SQLiteStore(self.store_path) as store:
                existing = next((item for item in store.list_admin_change_plans() if item.id == plan_id), None)
                if existing is None:
                    store.save_admin_change_plan(plan)
                elif existing != plan:
                    raise ValueError("immutable repair admin plan collision")
                store.save_repair_attempt(
                    RepairAttempt(
                        id=attempt_id,
                        incident_id=incident.id,
                        runbook_id=selected.id,
                        attempted_at=now,
                        authorization_id=plan_id,
                        outcome="approval_required",
                    )
                )
            return RepairResult("approval_required", incident.id, selected.id, attempt_id, admin_plan_id=plan_id)

        with SQLiteStore(self.store_path) as store:
            # A prior attempt for another generation is retained for audit, but
            # this deterministic generation key is the only one eligible here.
            request = None
            if selected.adapter_binding == "retry_read_only":
                earliest = (_parse(now) + timedelta(seconds=selected.cooldown_seconds)).isoformat()
                request = store.request_collection_run(
                    incident.job_id,
                    "repair-coordinator",
                    f"verification for incident {incident.id}",
                    earliest_execution_at=earliest,
                    requested_at=now,
                )
                outcome = "verification_queued"
                evidence_ids = (request.id,)
            elif selected.adapter_binding == "prune_bounded_evidence":
                store.prune_collection_runs_for_job(incident.job_id, job.retention_limit)
                outcome = "pruned"
                evidence_ids = ()
            else:
                raise ValueError("unsupported repair action")
            store.save_repair_attempt(
                RepairAttempt(
                    id=attempt_id,
                    incident_id=incident.id,
                    runbook_id=selected.id,
                    attempted_at=now,
                    outcome=outcome,
                    result_evidence_ids=evidence_ids,
                )
            )
        return RepairResult(
            outcome,
            incident.id,
            selected.id,
            attempt_id,
            request_id=request.id if request is not None else None,
            evidence_ids=evidence_ids,
        )
