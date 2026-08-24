"""Immutable records used by the autonomous collection scheduler."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Iterable

from .core import OwnerDomain, RiskLevel

MAX_IDENTIFIER_LENGTH = 160
MAX_SUMMARY_LENGTH = 2048
MAX_EVIDENCE_IDS = 64


class CollectionJobKind(StrEnum):
    HEALTH_PROBE = "health_probe"
    HOST_INSPECTION = "host_inspection"
    PHYSICAL_DISCOVERY = "physical_discovery"
    VIRTUAL_DISCOVERY = "virtual_discovery"
    CREW_DISPATCH = "crew_dispatch"
    USAGE_CONTINUATION = "usage_continuation"
    KNOWLEDGE_CAPTURE = "knowledge_capture"
    STATION_AUDIT = "station_audit"
    PACKAGE_INSPECTION = "package_inspection"
    FRESHNESS_PROJECTION = "freshness_projection"


class CollectionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMED_OUT = "timed_out"


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class RepairPolicy(StrEnum):
    TRIAGE_ONLY = "triage_only"
    PREAPPROVED_LOW_RISK = "preapproved_low_risk"


class TriageIncidentStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"


def _identifier(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-blank identifier")
    if len(value) > MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{label} exceeds the {MAX_IDENTIFIER_LENGTH}-character limit")


def _optional_identifier(value: object, label: str) -> None:
    if value is not None:
        _identifier(value, label)


def _positive(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")


def _non_negative(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(None):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    return parsed.astimezone(UTC)


def _timestamp(value: object, label: str) -> None:
    _parse_timestamp(value, label)


def _optional_timestamp(value: object, label: str) -> None:
    if value is not None:
        _timestamp(value, label)


def _enum(value: object, enum_type: type[StrEnum], label: str) -> StrEnum:
    try:
        return enum_type(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is invalid") from error


def _tuple_of_identifiers(values: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{label} must be a sequence of identifiers")
    result = tuple(values)
    if len(result) > MAX_EVIDENCE_IDS:
        raise ValueError(f"{label} exceeds the bounded evidence limit")
    for value in result:
        _identifier(value, label)
    return result


@dataclass(frozen=True)
class CollectionJob:
    """A stable, independently scheduled collection definition."""

    id: str
    kind: CollectionJobKind
    owner_domain: OwnerDomain
    resource_id: str | None = None
    target_id: str | None = None
    enabled: bool = True
    interval_seconds: int = 120
    jitter_seconds: int = 0
    timeout_seconds: int = 30
    priority: int = 0
    concurrency_key: str = "collection"
    retention_limit: int = 100
    repair_policy: RepairPolicy = RepairPolicy.TRIAGE_ONLY
    max_backoff_seconds: int = 3600
    failure_threshold: int = 3

    def __post_init__(self) -> None:
        _identifier(self.id, "job id")
        object.__setattr__(self, "kind", _enum(self.kind, CollectionJobKind, "job kind"))
        object.__setattr__(self, "owner_domain", _enum(self.owner_domain, OwnerDomain, "owner domain"))
        object.__setattr__(self, "repair_policy", _enum(self.repair_policy, RepairPolicy, "repair policy"))
        _optional_identifier(self.resource_id, "resource id")
        _optional_identifier(self.target_id, "target id")
        _identifier(self.concurrency_key, "concurrency key")
        if not isinstance(self.enabled, bool):
            raise ValueError("job enabled must be a boolean")
        _positive(self.interval_seconds, "interval")
        _non_negative(self.jitter_seconds, "jitter")
        _positive(self.timeout_seconds, "timeout")
        _non_negative(self.priority, "priority")
        _positive(self.retention_limit, "retention")
        _positive(self.max_backoff_seconds, "maximum backoff")
        _positive(self.failure_threshold, "failure threshold")


@dataclass(frozen=True)
class CollectionJobState:
    """Durable scheduler state that changes independently of the job definition."""

    job_id: str
    next_due_at: str
    last_started_at: str | None = None
    last_completed_at: str | None = None
    last_outcome: CollectionOutcome | None = None
    consecutive_failures: int = 0
    circuit_state: CircuitState = CircuitState.CLOSED
    cooldown_until: str | None = None
    active_lease_id: str | None = None
    lease_owner: str | None = None
    lease_expires_at: str | None = None
    lease_generation: int = 0

    def __post_init__(self) -> None:
        _identifier(self.job_id, "job id")
        _timestamp(self.next_due_at, "next due")
        _optional_timestamp(self.last_started_at, "last started")
        _optional_timestamp(self.last_completed_at, "last completed")
        if self.last_outcome is not None:
            object.__setattr__(self, "last_outcome", _enum(self.last_outcome, CollectionOutcome, "last outcome"))
        object.__setattr__(self, "circuit_state", _enum(self.circuit_state, CircuitState, "circuit state"))
        _non_negative(self.consecutive_failures, "consecutive failures")
        _optional_timestamp(self.cooldown_until, "cooldown")
        _optional_identifier(self.active_lease_id, "active lease id")
        _optional_identifier(self.lease_owner, "lease owner")
        _optional_timestamp(self.lease_expires_at, "lease expiry")
        _non_negative(self.lease_generation, "lease generation")
        lease_values = (self.active_lease_id, self.lease_owner, self.lease_expires_at)
        if any(value is not None for value in lease_values) and not all(value is not None for value in lease_values):
            raise ValueError("active lease id, owner, and expiry must be provided together")
        if self.circuit_state is CircuitState.OPEN and self.cooldown_until is None:
            raise ValueError("open circuit requires a cooldown deadline")


@dataclass(frozen=True)
class CollectionRequest:
    """An operator/API request which the scheduler may coalesce."""

    id: str
    job_id: str
    requester: str
    reason: str
    requested_at: str
    earliest_execution_at: str | None = None
    status: str = "pending"
    terminal_disposition: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.id, "request id")
        _identifier(self.job_id, "job id")
        _identifier(self.requester, "requester")
        if not isinstance(self.reason, str) or not self.reason.strip() or len(self.reason) > MAX_SUMMARY_LENGTH:
            raise ValueError("request reason must be bounded and non-blank")
        _timestamp(self.requested_at, "requested at")
        _optional_timestamp(self.earliest_execution_at, "earliest execution")
        _identifier(self.status, "request status")
        _optional_identifier(self.terminal_disposition, "terminal disposition")


@dataclass(frozen=True)
class CollectionRun:
    """Immutable bounded evidence of one collection attempt."""

    id: str
    job_id: str
    trigger: str
    started_at: str
    completed_at: str
    outcome: CollectionOutcome
    summary: str = ""
    evidence_ids: tuple[str, ...] = ()
    error_category: str = ""
    retry_disposition: str = ""
    request_id: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.id, "run id")
        _identifier(self.job_id, "job id")
        _identifier(self.trigger, "run trigger")
        _timestamp(self.started_at, "run start")
        _timestamp(self.completed_at, "run completion")
        if datetime.fromisoformat(self.completed_at.replace("Z", "+00:00")) < datetime.fromisoformat(self.started_at.replace("Z", "+00:00")):
            raise ValueError("run completion cannot precede run start")
        object.__setattr__(self, "outcome", _enum(self.outcome, CollectionOutcome, "run outcome"))
        if not isinstance(self.summary, str) or len(self.summary) > MAX_SUMMARY_LENGTH:
            raise ValueError("run summary exceeds the bounded limit")
        object.__setattr__(self, "evidence_ids", _tuple_of_identifiers(self.evidence_ids, "evidence id"))
        for value, label in ((self.error_category, "error category"), (self.retry_disposition, "retry disposition")):
            if not isinstance(value, str) or len(value) > MAX_IDENTIFIER_LENGTH:
                raise ValueError(f"{label} exceeds the bounded limit")
        _optional_identifier(self.request_id, "request id")


@dataclass(frozen=True)
class TriageIncident:
    """One durable failure generation for a job/resource pair."""

    id: str
    job_id: str
    resource_id: str
    first_failure_at: str
    latest_failure_at: str
    severity: RiskLevel
    owner_domain: OwnerDomain
    evidence_ids: tuple[str, ...] = ()
    status: TriageIncidentStatus = TriageIncidentStatus.OPEN
    repair_state: str = "pending"
    resolution: str | None = None
    generation: int = 1

    def __post_init__(self) -> None:
        for value, label in ((self.id, "incident id"), (self.job_id, "job id"), (self.resource_id, "resource id")):
            _identifier(value, label)
        first_failure = _parse_timestamp(self.first_failure_at, "first failure")
        latest_failure = _parse_timestamp(self.latest_failure_at, "latest failure")
        if latest_failure < first_failure:
            raise ValueError("latest failure cannot precede first failure")
        object.__setattr__(self, "severity", _enum(self.severity, RiskLevel, "incident severity"))
        object.__setattr__(self, "owner_domain", _enum(self.owner_domain, OwnerDomain, "owner domain"))
        object.__setattr__(self, "evidence_ids", _tuple_of_identifiers(self.evidence_ids, "evidence id"))
        object.__setattr__(self, "status", _enum(self.status, TriageIncidentStatus, "incident status"))
        _identifier(self.repair_state, "repair state")
        _optional_identifier(self.resolution, "incident resolution")
        _positive(self.generation, "incident generation")


@dataclass(frozen=True)
class RepairRunbook:
    """An exact repair binding with an explicit automatic-repair boundary."""

    id: str
    job_id: str
    resource_id: str
    failure_categories: tuple[str, ...]
    risk_level: RiskLevel
    idempotency_contract: str
    cooldown_seconds: int
    approval_required: bool
    adapter_binding: str

    def __post_init__(self) -> None:
        _identifier(self.id, "runbook id")
        _identifier(self.job_id, "runbook job id")
        _identifier(self.resource_id, "runbook resource id")
        categories = _tuple_of_identifiers(self.failure_categories, "failure category")
        object.__setattr__(self, "failure_categories", categories)
        object.__setattr__(self, "risk_level", _enum(self.risk_level, RiskLevel, "runbook risk level"))
        if not isinstance(self.idempotency_contract, str) or not self.idempotency_contract.strip() or len(self.idempotency_contract) > MAX_SUMMARY_LENGTH:
            raise ValueError("idempotency contract must be bounded and non-blank")
        _positive(self.cooldown_seconds, "repair cooldown")
        if not isinstance(self.approval_required, bool):
            raise ValueError("approval requirement must be a boolean")
        _identifier(self.adapter_binding, "adapter binding")
        if not self.approval_required and self.risk_level is not RiskLevel.LOW:
            raise ValueError("automatic repair must be low risk")


@dataclass(frozen=True)
class RepairAttempt:
    """Immutable evidence of one runbook attempt and its verification."""

    id: str
    incident_id: str
    runbook_id: str
    attempted_at: str
    authorization_id: str | None = None
    outcome: str = "pending"
    result_evidence_ids: tuple[str, ...] = ()
    verification_run_id: str | None = None

    def __post_init__(self) -> None:
        for value, label in ((self.id, "repair attempt id"), (self.incident_id, "incident id"), (self.runbook_id, "runbook id")):
            _identifier(value, label)
        _timestamp(self.attempted_at, "repair attempt")
        _optional_identifier(self.authorization_id, "authorization id")
        _identifier(self.outcome, "repair outcome")
        object.__setattr__(self, "result_evidence_ids", _tuple_of_identifiers(self.result_evidence_ids, "result evidence id"))
        _optional_identifier(self.verification_run_id, "verification run id")
