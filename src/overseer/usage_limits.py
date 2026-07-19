"""Usage-limit tracking and continuation scheduling."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import ApprovalLevel, OwnerDomain, RiskLevel


class LimitKind(StrEnum):
    REQUESTS = "requests"
    TOKENS = "tokens"
    CREDITS = "credits"
    DAILY_QUOTA = "daily_quota"
    MONTHLY_QUOTA = "monthly_quota"
    COOLDOWN = "cooldown"
    MANUAL = "manual"


class LimitDecision(StrEnum):
    RUN_NOW = "run_now"
    QUEUE_UNTIL_RESET = "queue_until_reset"
    BLOCK = "block"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class UsageLimit:
    id: str
    resource_id: str
    kind: LimitKind
    capacity: int
    remaining: int
    resets_at: str | None
    window: str
    observed_at: str | None = None
    confidence: float = 1.0

    def has_capacity_for(self, requested_units: int) -> bool:
        return requested_units >= 0 and self.remaining >= requested_units

    def is_exhausted(self) -> bool:
        return self.remaining <= 0


@dataclass(frozen=True)
class LimitedWorkRequest:
    id: str
    resource_id: str
    owner_thread: str
    requested_units: int
    intent: str
    risk_level: RiskLevel = RiskLevel.LOW
    earliest_start: str | None = None
    deadline: str | None = None


@dataclass(frozen=True)
class UsageContinuationRequest:
    id: str
    limit_id: str
    resource_id: str
    owner_thread: str
    requested_units: int
    intent: str
    risk_level: RiskLevel = RiskLevel.LOW
    earliest_start: str | None = None
    deadline: str | None = None
    requested_by: str = "quark"
    requested_at: str | None = None

    def to_limited_work_request(self) -> LimitedWorkRequest:
        return LimitedWorkRequest(
            id=self.id,
            resource_id=self.resource_id,
            owner_thread=self.owner_thread,
            requested_units=self.requested_units,
            intent=self.intent,
            risk_level=self.risk_level,
            earliest_start=self.earliest_start,
            deadline=self.deadline,
        )


@dataclass(frozen=True)
class UsageContinuationDispatch:
    id: str
    request_id: str
    limit_id: str
    resource_id: str
    owner_thread: str
    status: str
    reason: str
    dispatched_by: str
    dispatched_at: str | None = None
    scheduled_for: str | None = None
    resume_status: str | None = None
    resume_reason: str | None = None
    resume_conversation_id: str | None = None
    resume_project: str | None = None
    resume_command: str | None = None
    resume_launcher: str | None = None
    resume_exit_code: int | None = None


@dataclass(frozen=True)
class UsageSchedule:
    decision: LimitDecision
    owner_domain: OwnerDomain
    reason: str
    scheduled_for: str | None = None
    approval_level: ApprovalLevel = ApprovalLevel.NONE


def schedule_limited_work(limit: UsageLimit, request: LimitedWorkRequest) -> UsageSchedule:
    if limit.resource_id != request.resource_id:
        return UsageSchedule(
            LimitDecision.BLOCK,
            OwnerDomain.QUARK,
            "request resource_id does not match usage limit",
        )

    if request.requested_units < 0:
        return UsageSchedule(
            LimitDecision.BLOCK,
            OwnerDomain.QUARK,
            "requested units cannot be negative",
        )

    if limit.confidence < 0.5:
        return UsageSchedule(
            LimitDecision.ESCALATE,
            OwnerDomain.QUARK,
            "usage limit confidence is too low to spend capacity",
            request.earliest_start,
            ApprovalLevel.SISKO if request.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} else ApprovalLevel.ROLE,
        )

    if limit.has_capacity_for(request.requested_units):
        return UsageSchedule(
            LimitDecision.RUN_NOW,
            OwnerDomain.QUARK,
            "sufficient capacity is available",
            request.earliest_start,
        )

    if limit.resets_at:
        return UsageSchedule(
            LimitDecision.QUEUE_UNTIL_RESET,
            OwnerDomain.QUARK,
            "capacity is insufficient until reset",
            limit.resets_at,
        )

    return UsageSchedule(
        LimitDecision.ESCALATE,
        OwnerDomain.QUARK,
        "capacity is insufficient and no reset time is known",
        request.earliest_start,
        ApprovalLevel.ROLE,
    )
