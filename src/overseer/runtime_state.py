"""Runtime liveness state for local Overseer services."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum


@dataclass(frozen=True)
class RuntimeHeartbeat:
    id: str
    service_name: str
    started_at: str
    last_tick_at: str
    tick_count: int


class FreshnessStatus(StrEnum):
    OK = "ok"
    WARNING = "warning"
    HIGH = "high"
    MISSING = "missing"


@dataclass(frozen=True)
class FreshnessPolicy:
    warning_after_seconds: int
    high_after_seconds: int


@dataclass(frozen=True)
class FreshnessAssessment:
    status: FreshnessStatus
    observed_at: str | None
    age_seconds: int | None
    warning_after_seconds: int
    high_after_seconds: int
    summary: str


DEFAULT_RUNTIME_FRESHNESS_POLICY = FreshnessPolicy(warning_after_seconds=90, high_after_seconds=300)
DEFAULT_HOST_INSPECTION_FRESHNESS_POLICY = FreshnessPolicy(warning_after_seconds=120, high_after_seconds=600)


def assess_freshness(
    observed_at: str | None,
    now: str | None = None,
    policy: FreshnessPolicy = DEFAULT_RUNTIME_FRESHNESS_POLICY,
) -> FreshnessAssessment:
    if observed_at is None:
        return FreshnessAssessment(
            status=FreshnessStatus.MISSING,
            observed_at=None,
            age_seconds=None,
            warning_after_seconds=policy.warning_after_seconds,
            high_after_seconds=policy.high_after_seconds,
            summary="timestamp is missing",
        )

    age_seconds = max(0, int((_parse_datetime(now) - _parse_datetime(observed_at)).total_seconds()))
    status = FreshnessStatus.OK
    summary = "timestamp is fresh"
    if age_seconds >= policy.high_after_seconds:
        status = FreshnessStatus.HIGH
        summary = "timestamp is critically stale"
    elif age_seconds >= policy.warning_after_seconds:
        status = FreshnessStatus.WARNING
        summary = "timestamp is stale"

    return FreshnessAssessment(
        status=status,
        observed_at=observed_at,
        age_seconds=age_seconds,
        warning_after_seconds=policy.warning_after_seconds,
        high_after_seconds=policy.high_after_seconds,
        summary=summary,
    )


def _parse_datetime(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed
