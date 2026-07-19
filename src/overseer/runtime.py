"""Foreground runtime loop for explicit Overseer stores."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .adapters import HealthProbeAdapter
from .host import HostInspectionAdapter, assess_host_security
from .live_health import RoutedHealthProbeAdapter
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
    health_probes: int
    host_inspections: int
    host_security_high_findings: int
    host_security_warning_findings: int
    crew_messages_dispatched: int
    crew_messages_blocked: int


class OverseerRuntime:
    def __init__(
        self,
        store: SQLiteStore,
        service_name: str = "overseer",
        probe_health_targets: bool = False,
        health_probe_adapter: HealthProbeAdapter | None = None,
        health_evidence_retention_per_target: int = 5,
        inspect_host: bool = False,
        host_inspection_adapter: HostInspectionAdapter | None = None,
        dispatch_crew_messages: bool = False,
        crew_dispatcher: Callable[[str], dict[str, Any]] | None = None,
    ) -> None:
        self.store = store
        self.service_name = service_name
        self.probe_health_targets = probe_health_targets
        self.health_probe_adapter = health_probe_adapter or RoutedHealthProbeAdapter()
        self.health_evidence_retention_per_target = health_evidence_retention_per_target
        self.inspect_host = inspect_host
        self.host_inspection_adapter = host_inspection_adapter or HostInspectionAdapter()
        self.dispatch_crew_messages = dispatch_crew_messages
        self.crew_dispatcher = crew_dispatcher
        self.started_at = _utc_now()
        self.tick_count = 0

    def tick(self) -> RuntimeTick:
        self.tick_count += 1
        health_probes = self._probe_health_targets()
        host_inspections, host_high_findings, host_warning_findings = self._inspect_host()
        crew_dispatched, crew_blocked = self._dispatch_crew_messages()
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
            health_probes=health_probes,
            host_inspections=host_inspections,
            host_security_high_findings=host_high_findings,
            host_security_warning_findings=host_warning_findings,
            crew_messages_dispatched=crew_dispatched,
            crew_messages_blocked=crew_blocked,
        )

    def run(self, interval_seconds: float = 30.0, once: bool = False) -> RuntimeTick:
        last_tick = self.tick()
        if once:
            return last_tick
        while True:
            time.sleep(interval_seconds)
            last_tick = self.tick()

    def _probe_health_targets(self) -> int:
        if not self.probe_health_targets:
            return 0
        targets = self.store.list_health_targets()
        for target in targets:
            self.store.save_health_evidence(self.health_probe_adapter.probe(target))
        self.store.prune_health_evidence(self.health_evidence_retention_per_target)
        return len(targets)

    def _inspect_host(self) -> tuple[int, int, int]:
        if not self.inspect_host:
            return 0, 0, 0
        snapshot = self.host_inspection_adapter.inspect()
        self.store.save_host_snapshot(snapshot)
        findings = assess_host_security(snapshot)
        high_findings = sum(1 for finding in findings if finding.severity == "high")
        warning_findings = sum(1 for finding in findings if finding.severity == "warning")
        return 1, high_findings, warning_findings

    def _dispatch_crew_messages(self) -> tuple[int, int]:
        if not self.dispatch_crew_messages or self.crew_dispatcher is None:
            return 0, 0
        result = self.crew_dispatcher(str(self.store.path))
        return int(result.get("acknowledged", 0)), int(result.get("blocked", 0))


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()
