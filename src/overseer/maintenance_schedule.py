"""Durable maintenance schedule records for O'Brien."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Mapping

from .core import OwnerDomain, RiskLevel


class MaintenanceScheduleStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    RETIRED = "retired"


@dataclass(frozen=True)
class MaintenanceSchedule:
    id: str
    target: str
    owner_domain: OwnerDomain = OwnerDomain.OBRIEN
    risk_level: RiskLevel = RiskLevel.MEDIUM
    recurrence: str = "weekly"
    window: str = "unscheduled"
    timezone: str = "UTC"
    blackout: str = ""
    validation: str = "run health probes and service evidence after maintenance"
    rollback: str = "use related admin plan rollback steps"
    status: MaintenanceScheduleStatus = MaintenanceScheduleStatus.ACTIVE
    notes: str = ""
    metadata: Mapping[str, object] = field(default_factory=dict)


def record_maintenance_schedule_status(
    store_path: str | Path,
    schedule_id: str,
    target: str,
    recurrence: str = "weekly",
    window: str = "unscheduled",
    timezone: str = "UTC",
    blackout: str = "",
    validation: str = "run health probes and service evidence after maintenance",
    rollback: str = "use related admin plan rollback steps",
    status: str = MaintenanceScheduleStatus.ACTIVE.value,
    owner_domain: str = OwnerDomain.OBRIEN.value,
    risk_level: str = RiskLevel.MEDIUM.value,
    notes: str = "",
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    from .store import SQLiteStore

    schedule = MaintenanceSchedule(
        id=schedule_id,
        target=target,
        owner_domain=OwnerDomain(owner_domain),
        risk_level=RiskLevel(risk_level),
        recurrence=recurrence,
        window=window,
        timezone=timezone,
        blackout=blackout,
        validation=validation,
        rollback=rollback,
        status=MaintenanceScheduleStatus(status),
        notes=notes,
        metadata=metadata or {},
    )
    store = SQLiteStore(store_path)
    try:
        store.save_maintenance_schedule(schedule)
        return {
            "store": str(store.path),
            "schedule": maintenance_schedule_item_status(schedule),
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    finally:
        store.close()


def maintenance_schedules_status(store_path: str | Path) -> dict[str, object]:
    from .store import SQLiteStore

    store = SQLiteStore(store_path)
    try:
        schedules = store.list_maintenance_schedules()
    finally:
        store.close()
    return {
        "store": str(Path(store_path)),
        "schedules": len(schedules),
        "active": sum(1 for schedule in schedules if schedule.status == MaintenanceScheduleStatus.ACTIVE),
        "items": [maintenance_schedule_item_status(schedule) for schedule in schedules],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def maintenance_schedule_item_status(schedule: MaintenanceSchedule) -> dict[str, object]:
    return {
        "id": schedule.id,
        "target": schedule.target,
        "owner_domain": schedule.owner_domain.value,
        "risk_level": schedule.risk_level.value,
        "recurrence": schedule.recurrence,
        "window": schedule.window,
        "timezone": schedule.timezone,
        "blackout": schedule.blackout,
        "validation": schedule.validation,
        "rollback": schedule.rollback,
        "status": schedule.status.value,
        "notes": schedule.notes,
        "metadata": dict(schedule.metadata),
    }
