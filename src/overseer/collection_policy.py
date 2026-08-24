"""Pure, deterministic scheduling and circuit policy."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from .collection_models import CircuitState, CollectionJob, CollectionJobState, CollectionOutcome


def _utc(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    return parsed.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def deterministic_jitter(job_id: str, jitter_seconds: int) -> int:
    """Return a stable additive jitter in the inclusive ``0..window`` range."""

    if not isinstance(job_id, str) or not job_id.strip() or len(job_id) > 160:
        raise ValueError("job id must be a bounded non-blank identifier")
    if isinstance(jitter_seconds, bool) or not isinstance(jitter_seconds, int) or jitter_seconds < 0:
        raise ValueError("jitter window must be a non-negative integer")
    if jitter_seconds == 0:
        return 0
    digest = sha256(job_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % (jitter_seconds + 1)


def next_failure_delay(job: CollectionJob, consecutive_failures: int) -> int:
    """Return the exact capped exponential delay from the approved policy."""

    if isinstance(consecutive_failures, bool) or not isinstance(consecutive_failures, int) or consecutive_failures < 0:
        raise ValueError("consecutive failures must be a non-negative integer")
    exponent = min(max(consecutive_failures - 1, 0), 5)
    return min(job.interval_seconds * (2 ** exponent), job.max_backoff_seconds)


def next_success_due(job: CollectionJob, completed_at: str) -> str:
    """Schedule the next normal run from completion, including stable jitter."""

    completed = _utc(completed_at, "completion")
    delay = job.interval_seconds + deterministic_jitter(job.id, job.jitter_seconds)
    return _iso(completed + timedelta(seconds=delay))


def next_failure_due(job: CollectionJob, failed_at: str, consecutive_failures: int) -> str:
    """Schedule a failed run's retry using capped backoff, without due churn."""

    failed = _utc(failed_at, "failure")
    return _iso(failed + timedelta(seconds=next_failure_delay(job, consecutive_failures)))


def circuit_after_failure(job: CollectionJob, consecutive_failures: int) -> CircuitState:
    """Return the circuit state after recording a failure count."""

    if isinstance(consecutive_failures, bool) or not isinstance(consecutive_failures, int) or consecutive_failures < 0:
        raise ValueError("consecutive failures must be a non-negative integer")
    return CircuitState.OPEN if consecutive_failures >= job.failure_threshold else CircuitState.CLOSED


def circuit_after_success(state: CollectionJobState) -> CollectionJobState:
    """Close a circuit after a successful verification and clear its failures."""

    if state.circuit_state is not CircuitState.HALF_OPEN:
        raise ValueError("circuit success requires a half-open state")
    return replace(
        state,
        consecutive_failures=0,
        circuit_state=CircuitState.CLOSED,
        cooldown_until=None,
        last_outcome=CollectionOutcome.SUCCEEDED,
    )


def job_is_due(state: CollectionJobState, now: str) -> bool:
    """Decide due-ness, with open circuits gated exclusively by cooldown."""

    current = _utc(now, "current time")
    if state.lease_expires_at is not None and current < _utc(state.lease_expires_at, "lease expiry"):
        return False
    if state.circuit_state is CircuitState.OPEN:
        return state.cooldown_until is not None and current >= _utc(state.cooldown_until, "cooldown")
    return current >= _utc(state.next_due_at, "next due")
