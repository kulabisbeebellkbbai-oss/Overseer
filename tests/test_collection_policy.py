from dataclasses import FrozenInstanceError, replace
import os
from pathlib import Path
import subprocess
import sys

import pytest

from overseer import (
    CircuitState,
    CollectionJob,
    CollectionJobKind,
    CollectionJobState,
    CollectionOutcome,
    OwnerDomain,
    RepairPolicy,
    RepairRunbook,
    RiskLevel,
    TriageIncident,
    TriageIncidentStatus,
    circuit_after_failure,
    circuit_after_success,
    deterministic_jitter,
    job_is_due,
    next_failure_delay,
    next_failure_due,
    next_success_due,
)

NOW = "2026-08-24T12:00:00+00:00"


def sample_job(**overrides: object) -> CollectionJob:
    values: dict[str, object] = {
        "id": "collection.health.api",
        "kind": CollectionJobKind.HEALTH_PROBE,
        "owner_domain": OwnerDomain.JULIAN,
        "resource_id": "service.api",
        "target_id": "health.api",
        "interval_seconds": 120,
        "jitter_seconds": 30,
        "timeout_seconds": 15,
        "priority": 10,
        "concurrency_key": "health",
        "retention_limit": 50,
        "max_backoff_seconds": 900,
        "failure_threshold": 3,
    }
    values.update(overrides)
    return CollectionJob(**values)


def sample_state(**overrides: object) -> CollectionJobState:
    values: dict[str, object] = {
        "job_id": "collection.health.api",
        "next_due_at": NOW,
    }
    values.update(overrides)
    return CollectionJobState(**values)


def sample_incident(**overrides: object) -> TriageIncident:
    values: dict[str, object] = {
        "id": "incident.collection.health.api",
        "job_id": "collection.health.api",
        "resource_id": "service.api",
        "first_failure_at": NOW,
        "latest_failure_at": NOW,
        "severity": RiskLevel.MEDIUM,
        "owner_domain": OwnerDomain.JULIAN,
    }
    values.update(overrides)
    return TriageIncident(**values)


def sample_runbook(**overrides: object) -> RepairRunbook:
    values: dict[str, object] = {
        "id": "repair.retry.api",
        "job_id": "collection.health.api",
        "resource_id": "service.api",
        "failure_categories": ("unavailable",),
        "risk_level": RiskLevel.LOW,
        "idempotency_contract": "one bounded read-only retry",
        "cooldown_seconds": 60,
        "approval_required": False,
        "adapter_binding": "local.retry_read_only",
    }
    values.update(overrides)
    return RepairRunbook(**values)


def test_same_job_gets_stable_jitter() -> None:
    assert deterministic_jitter("collection.health.api", 30) == deterministic_jitter("collection.health.api", 30)


def test_jitter_is_stable_across_python_hash_seeds() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    command = (
        "from overseer import deterministic_jitter; "
        "print(deterministic_jitter('collection.health.api', 30))"
    )
    outputs: list[str] = []
    for seed in ("1", "987654"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = seed
        environment["PYTHONPATH"] = str(source_root)
        result = subprocess.run(
            [sys.executable, "-c", command],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            timeout=10,
        )
        outputs.append(result.stdout.strip())
    assert outputs[0] == outputs[1]
    assert 0 <= int(outputs[0]) <= 30


def test_success_due_adds_interval_and_deterministic_jitter() -> None:
    job = sample_job(jitter_seconds=0, interval_seconds=120)
    assert next_success_due(job, NOW) == "2026-08-24T12:02:00+00:00"


def test_failure_backoff_caps_at_policy_limit() -> None:
    job = sample_job(interval_seconds=120, max_backoff_seconds=900)
    assert next_failure_delay(job, consecutive_failures=20) == 900


def test_failure_due_uses_capped_failure_delay() -> None:
    job = sample_job(interval_seconds=120, max_backoff_seconds=900, jitter_seconds=30)
    assert next_failure_due(job, NOW, consecutive_failures=4) == "2026-08-24T12:15:00+00:00"


def test_open_circuit_allows_only_half_open_due_attempt() -> None:
    state = sample_state(circuit_state=CircuitState.OPEN, cooldown_until="2026-08-24T12:05:00+00:00")
    assert not job_is_due(state, "2026-08-24T12:04:59+00:00")
    assert job_is_due(state, "2026-08-24T12:05:00+00:00")


def test_open_circuit_ignores_an_ordinary_overdue_next_due_time() -> None:
    state = sample_state(
        circuit_state=CircuitState.OPEN,
        next_due_at="2026-08-24T11:00:00+00:00",
        cooldown_until="2026-08-24T12:05:00+00:00",
    )
    assert not job_is_due(state, "2026-08-24T12:04:59+00:00")


def test_circuit_opens_at_failure_threshold_and_success_closes_half_open() -> None:
    job = sample_job(failure_threshold=3)
    assert circuit_after_failure(job, 2) is CircuitState.CLOSED
    assert circuit_after_failure(job, 3) is CircuitState.OPEN
    recovered = circuit_after_success(
        sample_state(circuit_state=CircuitState.HALF_OPEN, consecutive_failures=3, cooldown_until=NOW)
    )
    assert recovered.circuit_state is CircuitState.CLOSED
    assert recovered.consecutive_failures == 0
    assert recovered.cooldown_until is None
    assert recovered.last_outcome is CollectionOutcome.SUCCEEDED


@pytest.mark.parametrize("circuit_state", [CircuitState.CLOSED, CircuitState.OPEN])
def test_circuit_after_success_rejects_non_half_open_state(circuit_state: CircuitState) -> None:
    state = sample_state(
        circuit_state=circuit_state,
        cooldown_until=NOW if circuit_state is CircuitState.OPEN else None,
    )
    with pytest.raises(ValueError, match="half-open"):
        circuit_after_success(state)


def test_incident_lifecycle_status_is_explicit_and_separate_from_repair_state() -> None:
    incident = sample_incident()
    assert incident.status is TriageIncidentStatus.OPEN
    assert incident.repair_state == "pending"
    resolved = sample_incident(
        status=TriageIncidentStatus.RESOLVED,
        repair_state="verified",
        resolution="fresh verification recovered target",
    )
    assert resolved.status is TriageIncidentStatus.RESOLVED
    assert resolved.repair_state == "verified"


@pytest.mark.parametrize("value", ["", "x" * 161])
def test_incident_rejects_unbounded_repair_state(value: str) -> None:
    with pytest.raises(ValueError):
        sample_incident(repair_state=value)


def test_incident_rejects_failure_time_that_moves_backwards() -> None:
    with pytest.raises(ValueError, match="latest failure"):
        sample_incident(latest_failure_at="2026-08-24T11:59:59+00:00")


def test_repair_runbook_has_exact_job_and_resource_bindings() -> None:
    runbook = sample_runbook()
    assert runbook.job_id == "collection.health.api"
    assert runbook.resource_id == "service.api"
    with pytest.raises(ValueError):
        sample_runbook(job_id="")
    with pytest.raises(ValueError):
        sample_runbook(resource_id="x" * 161)


@pytest.mark.parametrize(
    "lease_overrides",
    [
        {"active_lease_id": "lease-1"},
        {"lease_owner": "worker-a"},
        {"lease_expires_at": "2026-08-24T12:05:00+00:00"},
        {"active_lease_id": "lease-1", "lease_owner": "worker-a"},
        {"active_lease_id": "lease-1", "lease_expires_at": "2026-08-24T12:05:00+00:00"},
        {"lease_owner": "worker-a", "lease_expires_at": "2026-08-24T12:05:00+00:00"},
    ],
)
def test_partial_active_lease_is_rejected(lease_overrides: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="lease"):
        sample_state(**lease_overrides)


def test_active_unexpired_lease_suppresses_due_work() -> None:
    state = sample_state(
        active_lease_id="lease-1",
        lease_owner="worker-a",
        lease_expires_at="2026-08-24T12:05:00+00:00",
    )
    assert not job_is_due(state, "2026-08-24T12:04:59+00:00")
    assert job_is_due(state, "2026-08-24T12:05:00+00:00")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", ""),
        ("id", "x" * 161),
        ("interval_seconds", 0),
        ("jitter_seconds", -1),
        ("timeout_seconds", 0),
        ("retention_limit", 0),
        ("max_backoff_seconds", 0),
        ("failure_threshold", 0),
    ],
)
def test_collection_job_rejects_invalid_bounds(field: str, value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        sample_job(**{field: value})


def test_collection_job_is_frozen() -> None:
    job = sample_job()
    with pytest.raises(FrozenInstanceError):
        job.interval_seconds = 1  # type: ignore[misc]


def test_repair_runbook_rejects_unapproved_automatic_high_risk_repair() -> None:
    with pytest.raises(ValueError, match="low risk"):
        RepairRunbook(
            id="repair.restart.api",
            job_id="collection.health.api",
            resource_id="service.api",
            failure_categories=("unavailable",),
            risk_level=RiskLevel.HIGH,
            idempotency_contract="restart once",
            cooldown_seconds=60,
            approval_required=False,
            adapter_binding="local.restart",
        )


def test_public_models_remain_immutable_after_replace() -> None:
    state = sample_state(last_outcome=CollectionOutcome.FAILED)
    assert replace(state, consecutive_failures=1).consecutive_failures == 1
    assert state.consecutive_failures == 0
