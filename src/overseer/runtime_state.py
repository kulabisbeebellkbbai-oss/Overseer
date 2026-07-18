"""Runtime liveness state for local Overseer services."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeHeartbeat:
    id: str
    service_name: str
    started_at: str
    last_tick_at: str
    tick_count: int
