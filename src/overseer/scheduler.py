"""Local scheduling decisions for maintenance windows and limited work."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .maintenance import MaintenancePlan
from .usage_limits import LimitDecision, LimitedWorkRequest, UsageLimit, schedule_limited_work


class ScheduledWorkStatus(StrEnum):
    READY = "ready"
    WAITING = "waiting"
    BLOCKED = "blocked"
    ESCALATED = "escalated"


@dataclass(frozen=True)
class ScheduledWork:
    id: str
    owner_thread: str
    resource_id: str
    status: ScheduledWorkStatus
    reason: str
    scheduled_for: str | None = None
    blocking_ids: tuple[str, ...] = ()


def schedule_usage_limited_work(limit: UsageLimit, request: LimitedWorkRequest) -> ScheduledWork:
    schedule = schedule_limited_work(limit, request)
    if schedule.decision == LimitDecision.RUN_NOW:
        return ScheduledWork(request.id, request.owner_thread, request.resource_id, ScheduledWorkStatus.READY, schedule.reason)
    if schedule.decision == LimitDecision.QUEUE_UNTIL_RESET:
        return ScheduledWork(
            request.id,
            request.owner_thread,
            request.resource_id,
            ScheduledWorkStatus.WAITING,
            schedule.reason,
            schedule.scheduled_for,
        )
    if schedule.decision == LimitDecision.ESCALATE:
        return ScheduledWork(
            request.id,
            request.owner_thread,
            request.resource_id,
            ScheduledWorkStatus.ESCALATED,
            schedule.reason,
            schedule.scheduled_for,
        )
    return ScheduledWork(request.id, request.owner_thread, request.resource_id, ScheduledWorkStatus.BLOCKED, schedule.reason)


def maintenance_window_conflicts(plan: MaintenancePlan, active_plans: tuple[MaintenancePlan, ...]) -> tuple[str, ...]:
    if not plan.window.exclusive:
        return ()
    blockers: list[str] = []
    target_resources = plan.all_resource_ids()
    for active in active_plans:
        if not active.window.exclusive:
            continue
        if not target_resources & active.all_resource_ids():
            continue
        if _windows_overlap(plan.window.starts_at, plan.window.ends_at, active.window.starts_at, active.window.ends_at):
            blockers.append(active.id)
    return tuple(blockers)


def schedule_maintenance_window(plan: MaintenancePlan, active_plans: tuple[MaintenancePlan, ...]) -> ScheduledWork:
    blockers = maintenance_window_conflicts(plan, active_plans)
    if blockers:
        return ScheduledWork(
            plan.id,
            "maintenance",
            plan.resource_id,
            ScheduledWorkStatus.WAITING,
            "exclusive maintenance window overlaps active plan",
            plan.window.ends_at,
            blockers,
        )
    return ScheduledWork(
        plan.id,
        "maintenance",
        plan.resource_id,
        ScheduledWorkStatus.READY,
        "maintenance window is available",
        plan.window.starts_at,
    )


def next_ready_work(items: tuple[ScheduledWork, ...]) -> tuple[ScheduledWork, ...]:
    ready = [item for item in items if item.status == ScheduledWorkStatus.READY]
    return tuple(sorted(ready, key=lambda item: item.scheduled_for or ""))


def _windows_overlap(left_start: str, left_end: str, right_start: str, right_end: str) -> bool:
    return left_start < right_end and right_start < left_end
