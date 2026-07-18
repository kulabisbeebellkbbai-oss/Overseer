"""Foreground runtime loop for explicit Overseer stores."""

from __future__ import annotations

import time
from dataclasses import dataclass

from .store import SQLiteStore


@dataclass(frozen=True)
class RuntimeTick:
    resources: int
    usage_limits: int
    audit_events: int
    health_evidence: int
    physical_identities: int


class OverseerRuntime:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def tick(self) -> RuntimeTick:
        return RuntimeTick(
            resources=len(self.store.list_resources()),
            usage_limits=len(self.store.list_usage_limits()),
            audit_events=len(self.store.list_audit_events()),
            health_evidence=len(self.store.list_health_evidence()),
            physical_identities=len(self.store.list_physical_identities()),
        )

    def run(self, interval_seconds: float = 30.0, once: bool = False) -> RuntimeTick:
        last_tick = self.tick()
        if once:
            return last_tick
        while True:
            time.sleep(interval_seconds)
            last_tick = self.tick()
