"""Foreground runtime loop for explicit Overseer stores."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime

from .runtime_state import RuntimeHeartbeat
from .store import SQLiteStore


@dataclass(frozen=True)
class RuntimeTick:
    resources: int
    usage_limits: int
    health_targets: int
    audit_events: int
    health_evidence: int
    physical_identities: int
    runtime_heartbeats: int


class OverseerRuntime:
    def __init__(self, store: SQLiteStore, service_name: str = "overseer") -> None:
        self.store = store
        self.service_name = service_name
        self.started_at = _utc_now()
        self.tick_count = 0

    def tick(self) -> RuntimeTick:
        self.tick_count += 1
        self.store.save_runtime_heartbeat(
            RuntimeHeartbeat(
                id=self.service_name,
                service_name=self.service_name,
                started_at=self.started_at,
                last_tick_at=_utc_now(),
                tick_count=self.tick_count,
            )
        )
        return RuntimeTick(
            resources=len(self.store.list_resources()),
            usage_limits=len(self.store.list_usage_limits()),
            health_targets=len(self.store.list_health_targets()),
            audit_events=len(self.store.list_audit_events()),
            health_evidence=len(self.store.list_health_evidence()),
            physical_identities=len(self.store.list_physical_identities()),
            runtime_heartbeats=len(self.store.list_runtime_heartbeats()),
        )

    def run(self, interval_seconds: float = 30.0, once: bool = False) -> RuntimeTick:
        last_tick = self.tick()
        if once:
            return last_tick
        while True:
            time.sleep(interval_seconds)
            last_tick = self.tick()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()
