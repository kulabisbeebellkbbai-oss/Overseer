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
    host_security_remediation_plans_staged: int
    host_security_ids_reviews_prepared: int
    host_security_sisko_requests: int
    host_security_auto_executions: int
    crew_messages_dispatched: int
    crew_messages_blocked: int
    usage_continuations_dispatched: int
    usage_continuations_skipped: int
    knowledge_events_captured: int
    knowledge_events_failed: int
    station_audits: int
    station_audit_actions: int
    station_audit_odo_referrals: int
    station_audit_sisko_requests: int


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
        host_security_advancer: Callable[[str, str], dict[str, Any]] | None = None,
        dispatch_crew_messages: bool = False,
        crew_dispatcher: Callable[[str], dict[str, Any]] | None = None,
        dispatch_usage_continuations: bool = False,
        usage_continuation_dispatcher: Callable[[str], dict[str, Any]] | None = None,
        capture_knowledge_events: bool = False,
        knowledge_capture_dispatcher: Callable[[str], dict[str, Any]] | None = None,
        audit_station: bool = False,
        station_auditor: Callable[[str, str | None], dict[str, Any]] | None = None,
        station_audit_interval_ticks: int = 120,
    ) -> None:
        self.store = store
        self.service_name = service_name
        self.probe_health_targets = probe_health_targets
        self.health_probe_adapter = health_probe_adapter or RoutedHealthProbeAdapter()
        self.health_evidence_retention_per_target = health_evidence_retention_per_target
        self.inspect_host = inspect_host
        self.host_inspection_adapter = host_inspection_adapter or HostInspectionAdapter(collect_firewall_commands=False)
        self.host_security_advancer = host_security_advancer
        self.dispatch_crew_messages = dispatch_crew_messages
        self.crew_dispatcher = crew_dispatcher
        self.dispatch_usage_continuations = dispatch_usage_continuations
        self.usage_continuation_dispatcher = usage_continuation_dispatcher
        self.capture_knowledge_events = capture_knowledge_events
        self.knowledge_capture_dispatcher = knowledge_capture_dispatcher
        self.audit_station = audit_station
        self.station_auditor = station_auditor
        self.station_audit_interval_ticks = max(1, station_audit_interval_ticks)
        self.started_at = _utc_now()
        self.tick_count = 0

    def tick(self) -> RuntimeTick:
        self.tick_count += 1
        self._save_heartbeat()
        health_probes = self._probe_health_targets()
        (
            host_inspections,
            host_high_findings,
            host_warning_findings,
            remediation_plans_staged,
            ids_reviews_prepared,
            sisko_requests,
            auto_executions,
        ) = self._inspect_host()
        crew_dispatched, crew_blocked = self._dispatch_crew_messages()
        usage_dispatched, usage_skipped = self._dispatch_usage_continuations()
        knowledge_captured, knowledge_failed = self._capture_knowledge_events()
        station_audits, station_actions, station_odo_referrals, station_sisko_requests = self._audit_station()
        self._save_heartbeat()
        return RuntimeTick(
            resources=len(self.store.list_resources()),
            usage_limits=len(self.store.list_usage_limits()),
            health_targets=len(self.store.list_health_targets()),
            audit_events=self.store.count_audit_events(),
            health_evidence=len(self.store.list_health_evidence()),
            physical_identities=len(self.store.list_physical_identities()),
            runtime_heartbeats=len(self.store.list_runtime_heartbeats()),
            health_probes=health_probes,
            host_inspections=host_inspections,
            host_security_high_findings=host_high_findings,
            host_security_warning_findings=host_warning_findings,
            host_security_remediation_plans_staged=remediation_plans_staged,
            host_security_ids_reviews_prepared=ids_reviews_prepared,
            host_security_sisko_requests=sisko_requests,
            host_security_auto_executions=auto_executions,
            crew_messages_dispatched=crew_dispatched,
            crew_messages_blocked=crew_blocked,
            usage_continuations_dispatched=usage_dispatched,
            usage_continuations_skipped=usage_skipped,
            knowledge_events_captured=knowledge_captured,
            knowledge_events_failed=knowledge_failed,
            station_audits=station_audits,
            station_audit_actions=station_actions,
            station_audit_odo_referrals=station_odo_referrals,
            station_audit_sisko_requests=station_sisko_requests,
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

    def _inspect_host(self) -> tuple[int, int, int, int, int, int, int]:
        if not self.inspect_host:
            return 0, 0, 0, 0, 0, 0, 0
        snapshot = self.host_inspection_adapter.inspect()
        self.store.save_host_snapshot(snapshot)
        findings = assess_host_security(snapshot)
        high_findings = sum(1 for finding in findings if finding.severity == "high")
        warning_findings = sum(1 for finding in findings if finding.severity == "warning")
        if self.host_security_advancer is None:
            return 1, high_findings, warning_findings, 0, 0, 0, 0
        advancement = self.host_security_advancer(str(self.store.path), snapshot.id)
        return (
            1,
            high_findings,
            warning_findings,
            int(advancement.get("staged_count", 0)),
            int(advancement.get("ids_reviews_prepared", 0)),
            int(advancement.get("sisko_requests", 0)),
            int(advancement.get("executions", 0)),
        )

    def _dispatch_crew_messages(self) -> tuple[int, int]:
        if not self.dispatch_crew_messages or self.crew_dispatcher is None:
            return 0, 0
        result = self.crew_dispatcher(str(self.store.path))
        return int(result.get("acknowledged", 0)), int(result.get("blocked", 0))

    def _dispatch_usage_continuations(self) -> tuple[int, int]:
        if not self.dispatch_usage_continuations or self.usage_continuation_dispatcher is None:
            return 0, 0
        result = self.usage_continuation_dispatcher(str(self.store.path))
        return int(result.get("dispatched", 0)), int(result.get("skipped", 0))

    def _capture_knowledge_events(self) -> tuple[int, int]:
        if not self.capture_knowledge_events or self.knowledge_capture_dispatcher is None:
            return 0, 0
        result = self.knowledge_capture_dispatcher(str(self.store.path))
        return int(result.get("captured", 0)), int(result.get("failed", 0))

    def _audit_station(self) -> tuple[int, int, int, int]:
        if not self.audit_station or self.station_auditor is None:
            return 0, 0, 0, 0
        if self.tick_count % self.station_audit_interval_ticks != 0:
            return 0, 0, 0, 0
        snapshots = self.store.list_host_snapshots()
        latest_snapshot = sorted(snapshots, key=lambda item: item.captured_at)[-1] if snapshots else None
        result = self.station_auditor(str(self.store.path), latest_snapshot.id if latest_snapshot else None)
        return (
            1,
            int(result.get("actions", 0)),
            int(result.get("odo_referrals", 0)),
            int(result.get("sisko_requests", 0)),
        )

    def _save_heartbeat(self) -> None:
        self.store.save_runtime_heartbeat(
            RuntimeHeartbeat(
                id=self.service_name,
                service_name=self.service_name,
                started_at=self.started_at,
                last_tick_at=_utc_now(),
                tick_count=self.tick_count,
            )
        )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()
