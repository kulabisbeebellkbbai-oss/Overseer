"""Foreground runtime loop for explicit Overseer stores."""

from __future__ import annotations

import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .adapters import HealthProbeAdapter
from .collection_adapters import (
    CollectionAdapterRegistry,
    CollectionExecution,
    StorePathCallbackAdapter,
    default_collection_adapter_registry,
)
from .collection_models import CollectionJob, CollectionJobKind, CollectionOutcome
from .collection_scheduler import CollectionScheduler
from .core import OwnerDomain
from .health import HealthTarget
from .host import HostInspectionAdapter, assess_host_security
from .live_health import RoutedHealthProbeAdapter
from .runtime_state import RuntimeHeartbeat
from .store import SQLiteStore

DEFAULT_RUNTIME_MAX_IDLE_SECONDS = 30.0
DEFAULT_COLLECTION_INTERVALS = {
    CollectionJobKind.HOST_INSPECTION: 300,
    CollectionJobKind.PHYSICAL_DISCOVERY: 900,
    CollectionJobKind.VIRTUAL_DISCOVERY: 300,
    CollectionJobKind.CREW_DISPATCH: 120,
    CollectionJobKind.USAGE_CONTINUATION: 120,
    CollectionJobKind.KNOWLEDGE_CAPTURE: 300,
    CollectionJobKind.STATION_AUDIT: 600,
    CollectionJobKind.PACKAGE_INSPECTION: 1800,
    CollectionJobKind.FRESHNESS_PROJECTION: 60,
}
DEFAULT_COLLECTION_TIMEOUTS = {
    CollectionJobKind.HOST_INSPECTION: 1,
    CollectionJobKind.PHYSICAL_DISCOVERY: 5,
    CollectionJobKind.VIRTUAL_DISCOVERY: 5,
    CollectionJobKind.CREW_DISPATCH: 5,
    CollectionJobKind.USAGE_CONTINUATION: 5,
    CollectionJobKind.KNOWLEDGE_CAPTURE: 5,
    CollectionJobKind.STATION_AUDIT: 5,
    CollectionJobKind.PACKAGE_INSPECTION: 5,
    CollectionJobKind.FRESHNESS_PROJECTION: 5,
}
RUNTIME_ADAPTER_IDS = {
    CollectionJobKind.PHYSICAL_DISCOVERY: "physical-discovery",
    CollectionJobKind.VIRTUAL_DISCOVERY: "virtual-discovery",
    CollectionJobKind.CREW_DISPATCH: "crew-dispatch",
    CollectionJobKind.USAGE_CONTINUATION: "usage-continuation",
    CollectionJobKind.KNOWLEDGE_CAPTURE: "knowledge-capture",
    CollectionJobKind.STATION_AUDIT: "station-audit",
    CollectionJobKind.FRESHNESS_PROJECTION: "freshness-projection",
    CollectionJobKind.HOST_INSPECTION: "host-inspection",
    CollectionJobKind.PACKAGE_INSPECTION: "package-inspection",
}
RUNTIME_JOB_ADAPTER_IDS = {
    "collection.host.inspection": "host-inspection",
    "collection.host.security": "host-security",
    "collection.discovery.physical": "physical-discovery",
    "collection.discovery.storage": "storage-discovery",
}
SYSTEMD_FRESHNESS_PROPERTIES = (
    "ActiveState",
    "SubState",
    "Result",
    "LastTriggerUSecRealtime",
    "NextElapseUSecRealtime",
)
EXTERNAL_FRESHNESS_UNITS = {
    "overseer-psychlo-usage.service": (
        "overseer-psychlo-usage.timer",
        "overseer-psychlo-usage.service",
    ),
    "overseer-quark-scheduler.service": (
        "overseer-quark-scheduler.timer",
        "overseer-quark-scheduler.service",
    ),
}
COLLECTION_FAMILIES = frozenset(
    {"health", "host", "discovery", "crew_dispatch", "usage_continuation", "knowledge_capture", "station_audit", "package", "freshness"}
)


def _store_path(value: str | Any) -> str:
    path = Path(value)
    if path.is_dir():
        return str(path / "state.sqlite3")
    return str(path)


def _systemd_runner(command: tuple[str, ...], timeout_seconds: float) -> object:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )


def _systemd_properties(output: object) -> dict[str, str]:
    text = str(getattr(output, "stdout", ""))[:4096]
    properties: dict[str, str] = {}
    for line in text.splitlines()[:32]:
        key, separator, value = line.partition("=")
        if separator and key in SYSTEMD_FRESHNESS_PROPERTIES and len(value) <= 256:
            properties[key] = value.strip()
    return properties


def _systemd_timestamp(value: str) -> datetime | None:
    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized.split()) >= 3 and normalized.split()[0].rstrip(".").isalpha():
        normalized = " ".join(normalized.split()[1:])
    if normalized.endswith(" UTC"):
        normalized = normalized[:-4] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _freshness_projection_status(
    job: CollectionJob,
    store_path: str,
    timeout_seconds: float,
    runner: Callable[[tuple[str, ...], float], object],
    now: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Read exact user-systemd timer/service freshness without executing either unit."""
    del store_path
    unit = str(job.resource_id or "")
    units = EXTERNAL_FRESHNESS_UNITS.get(unit)
    if units is None:
        return {"outcome": CollectionOutcome.BLOCKED.value, "failure_category": "contract_mismatch"}
    observations: dict[str, dict[str, str]] = {}
    command = (
        "systemctl",
        "--user",
        "show",
        "--no-pager",
        "--no-legend",
        "--property=" + ",".join(SYSTEMD_FRESHNESS_PROPERTIES),
    )
    for queried_unit in units:
        try:
            result = runner((*command, queried_unit), timeout_seconds)
        except (TimeoutError, subprocess.TimeoutExpired):
            return {"outcome": CollectionOutcome.BLOCKED.value, "failure_category": "timeout"}
        if getattr(result, "returncode", 1) != 0:
            return {"outcome": CollectionOutcome.BLOCKED.value, "failure_category": "unavailable"}
        observations[queried_unit] = _systemd_properties(result)
    timer, service = (observations[units[0]], observations[units[1]])
    last_trigger = _systemd_timestamp(timer.get("LastTriggerUSecRealtime", ""))
    next_trigger = _systemd_timestamp(timer.get("NextElapseUSecRealtime", ""))
    current = (now or (lambda: datetime.now(UTC)))()
    if isinstance(current, str):
        current = datetime.fromisoformat(current.replace("Z", "+00:00"))
    current = current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)
    if not {
        timer.get("ActiveState"),
        timer.get("SubState"),
        timer.get("Result"),
        service.get("Result"),
    } <= {"active", "waiting", "success"} or last_trigger is None or next_trigger is None:
        return {"outcome": CollectionOutcome.FAILED.value, "failure_category": "unavailable"}
    if (current - last_trigger).total_seconds() > max(job.interval_seconds + job.timeout_seconds, 1):
        return {"outcome": CollectionOutcome.FAILED.value, "failure_category": "stale"}
    evidence_id = f"freshness.{job.id.replace('collection.freshness.', '')}"
    return {
        "outcome": CollectionOutcome.SUCCEEDED.value,
        "evidence_ids": (evidence_id,),
    }


def runtime_collection_adapter_registry(
    *,
    systemd_runner: Callable[[tuple[str, ...], float], object] | None = None,
    now: Callable[[], datetime] | None = None,
) -> CollectionAdapterRegistry:
    """Build the exact bounded callback bindings used by seeded jobs."""
    # Importing the CLI lazily avoids the CLI/runtime module cycle at import time.
    from .cli import (
        assess_host_security_status,
        audit_station_status,
        dispatch_crew_messages_status,
        dispatch_usage_continuations_status,
        discover_physical_status,
        discover_storage_status,
        discover_virtual_listeners_status,
        knowledge_capture_status,
    )

    registry = default_collection_adapter_registry()
    callbacks = {
        (CollectionJobKind.PHYSICAL_DISCOVERY, "physical-discovery"): lambda job, path, timeout: discover_physical_status(
            ("/dev/serial/by-id", "/dev/serial/by-path"), path, limit=25, timeout_seconds=timeout
        ),
        (CollectionJobKind.PHYSICAL_DISCOVERY, "storage-discovery"): lambda job, path, timeout: discover_storage_status(
            store_path=path, limit=25, timeout_seconds=timeout
        ),
        (CollectionJobKind.VIRTUAL_DISCOVERY, "virtual-discovery"): lambda job, path, timeout: discover_virtual_listeners_status(path, limit=25, timeout_seconds=timeout),
        (CollectionJobKind.CREW_DISPATCH, "crew-dispatch"): lambda job, path, timeout: dispatch_crew_messages_status(path, dispatched_by="sisko", limit=1, timeout_seconds=timeout),
        (CollectionJobKind.USAGE_CONTINUATION, "usage-continuation"): lambda job, path, timeout: dispatch_usage_continuations_status(path, dispatched_by="quark", limit=1, timeout_seconds=timeout),
        (CollectionJobKind.KNOWLEDGE_CAPTURE, "knowledge-capture"): lambda job, path, timeout: knowledge_capture_status(path, limit=1, timeout_seconds=timeout),
        (CollectionJobKind.STATION_AUDIT, "station-audit"): lambda job, path, timeout: audit_station_status(path, limit=1, timeout_seconds=timeout),
        (CollectionJobKind.FRESHNESS_PROJECTION, "freshness-projection"): lambda job, path, timeout: _freshness_projection_status(job, path, timeout, systemd_runner or _systemd_runner, now),
        (CollectionJobKind.HOST_INSPECTION, "host-security"): lambda job, path, timeout: assess_host_security_status(path, timeout_seconds=timeout),
    }
    for (kind, adapter_id), callback in callbacks.items():
        registry.register(kind, adapter_id, StorePathCallbackAdapter(callback, kind=kind))
    return registry


def _normalize_collection_families(families: object) -> frozenset[str] | None:
    if families is None:
        return None
    if isinstance(families, (str, bytes)):
        families = (families,)
    try:
        normalized = frozenset(str(item).strip().lower() for item in families)
    except TypeError as error:
        raise ValueError("collection families must be a sequence") from error
    aliases = {"crew": "crew_dispatch", "usage": "usage_continuation", "knowledge": "knowledge_capture", "station": "station_audit"}
    normalized = frozenset(aliases.get(item, item) for item in normalized)
    unknown = normalized - COLLECTION_FAMILIES
    if unknown:
        raise ValueError(f"unknown collection family: {sorted(unknown)[0]}")
    return normalized | {"freshness"}


def _default_jobs(
    targets: tuple[HealthTarget, ...],
    families: frozenset[str] | None = None,
) -> tuple[CollectionJob, ...]:
    jobs = [
        CollectionJob(
            id=f"collection.health.{target.id}",
            kind=CollectionJobKind.HEALTH_PROBE,
            owner_domain=target.owner_domain,
            resource_id=target.resource_id,
            target_id=target.id,
            interval_seconds=target.interval_seconds,
            jitter_seconds=target.jitter_seconds,
            timeout_seconds=target.timeout_seconds,
            priority=2,
            repair_policy=target.repair_policy,
        )
        for target in targets
        if target.enabled and (families is None or "health" in families)
    ]
    fixed = (
        ("collection.host.inspection", CollectionJobKind.HOST_INSPECTION, OwnerDomain.ODO, "host.local"),
        ("collection.host.security", CollectionJobKind.HOST_INSPECTION, OwnerDomain.ODO, "host-security"),
        ("collection.discovery.physical", CollectionJobKind.PHYSICAL_DISCOVERY, OwnerDomain.KIRA, "physical.discovery"),
        ("collection.discovery.storage", CollectionJobKind.PHYSICAL_DISCOVERY, OwnerDomain.KIRA, "storage.discovery"),
        ("collection.discovery.virtual", CollectionJobKind.VIRTUAL_DISCOVERY, OwnerDomain.DAX, "virtual.discovery"),
        ("collection.dispatch.crew", CollectionJobKind.CREW_DISPATCH, OwnerDomain.SISKO, "crew.dispatch"),
        ("collection.usage.continuation", CollectionJobKind.USAGE_CONTINUATION, OwnerDomain.QUARK, "usage.continuation"),
        ("collection.knowledge.capture", CollectionJobKind.KNOWLEDGE_CAPTURE, OwnerDomain.EZRI, "knowledge.capture"),
        ("collection.station.audit", CollectionJobKind.STATION_AUDIT, OwnerDomain.JULIAN, "station.audit"),
        ("collection.package.inspection", CollectionJobKind.PACKAGE_INSPECTION, OwnerDomain.OBRIEN, "package.inspection"),
        ("collection.freshness.psychlo-usage", CollectionJobKind.FRESHNESS_PROJECTION, OwnerDomain.QUARK, "overseer-psychlo-usage.service"),
        ("collection.freshness.quark-scheduler", CollectionJobKind.FRESHNESS_PROJECTION, OwnerDomain.QUARK, "overseer-quark-scheduler.service"),
    )
    family_by_kind = {
        CollectionJobKind.HOST_INSPECTION: "host",
        CollectionJobKind.PHYSICAL_DISCOVERY: "discovery",
        CollectionJobKind.VIRTUAL_DISCOVERY: "discovery",
        CollectionJobKind.CREW_DISPATCH: "crew_dispatch",
        CollectionJobKind.USAGE_CONTINUATION: "usage_continuation",
        CollectionJobKind.KNOWLEDGE_CAPTURE: "knowledge_capture",
        CollectionJobKind.STATION_AUDIT: "station_audit",
        CollectionJobKind.PACKAGE_INSPECTION: "package",
        CollectionJobKind.FRESHNESS_PROJECTION: "freshness",
    }
    jobs.extend(
        CollectionJob(
            id=job_id,
            kind=kind,
            owner_domain=owner,
            resource_id=resource_id,
            interval_seconds=DEFAULT_COLLECTION_INTERVALS[kind],
            timeout_seconds=DEFAULT_COLLECTION_TIMEOUTS[kind],
            priority=1 if kind is not CollectionJobKind.FRESHNESS_PROJECTION else 0,
        )
        for job_id, kind, owner, resource_id in fixed
        if families is None or family_by_kind[kind] in families
    )
    return tuple(jobs)


def seed_default_collection_jobs(
    store_path: str | Any,
    config_path: str | Any | None = None,
    families: object = None,
) -> dict[str, object]:
    """Idempotently seed stable definitions while preserving scheduler state."""
    path = _store_path(store_path)
    with SQLiteStore(path) as store:
        if config_path is not None:
            from .config import load_config, seed_store_from_config

            seed_store_from_config(load_config(config_path), store)
        normalized_families = _normalize_collection_families(families)
        registry = runtime_collection_adapter_registry()
        targets = store.list_health_targets()
        enabled_target_ids = {target.id for target in targets if target.enabled}
        seeded: list[str] = []
        skipped: list[dict[str, str]] = []
        for existing in store.list_collection_jobs():
            if (
                (normalized_families is None or "health" in normalized_families)
                and
                existing.kind is CollectionJobKind.HEALTH_PROBE
                and existing.target_id is not None
                and existing.target_id not in enabled_target_ids
                and existing.enabled
            ):
                store.save_collection_job(replace(existing, enabled=False))
                skipped.append(
                    {
                        "job_id": existing.id,
                        "status": "disabled",
                        "reason": "health target is disabled",
                    }
                )
        for job in _default_jobs(targets, normalized_families):
            adapter_id = (
                "health-probe"
                if job.kind is CollectionJobKind.HEALTH_PROBE
                else RUNTIME_JOB_ADAPTER_IDS.get(job.id, RUNTIME_ADAPTER_IDS.get(job.kind))
            )
            try:
                registry.resolve(job, adapter_id)
            except ValueError as error:
                skipped.append({"job_id": job.id, "status": "disabled", "reason": str(error)})
                continue
            store.save_collection_job(job)
            seeded.append(job.id)
        return {
            "store": str(store.path),
            "status": "seeded",
            "jobs": sorted(seeded),
            "job_count": len(seeded),
            "disabled": skipped,
            "mutation_performed": True,
            "host_mutation_performed": False,
            "families": sorted(normalized_families) if normalized_families is not None else None,
        }


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
        psychlo_bridge: Any | None = None,
        scheduler: Any | None = None,
        maximum_idle_seconds: float = DEFAULT_RUNTIME_MAX_IDLE_SECONDS,
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
        self.psychlo_bridge = psychlo_bridge
        legacy_families = {
            family
            for enabled, family in (
                (probe_health_targets, "health"),
                (inspect_host, "host"),
                (dispatch_crew_messages, "crew_dispatch"),
                (dispatch_usage_continuations, "usage_continuation"),
                (capture_knowledge_events, "knowledge_capture"),
                (audit_station, "station_audit"),
            )
            if enabled
        }
        seed_default_collection_jobs(store.path, families=legacy_families or None)
        self._owns_scheduler = scheduler is None
        self.scheduler = scheduler or CollectionScheduler(
            str(store.path),
            adapter_registry=runtime_collection_adapter_registry(),
            adapter_ids={**RUNTIME_ADAPTER_IDS, **RUNTIME_JOB_ADAPTER_IDS},
        )
        if maximum_idle_seconds <= 0:
            raise ValueError("maximum idle seconds must be positive")
        self.maximum_idle_seconds = min(float(maximum_idle_seconds), DEFAULT_RUNTIME_MAX_IDLE_SECONDS)
        self.started_at = _utc_now()
        self.tick_count = 0
        self.last_scheduler_cycle: Any | None = None

    def tick(self) -> RuntimeTick:
        self.tick_count += 1
        self._save_heartbeat()
        self.last_scheduler_cycle = self.scheduler.run_ready_once()
        self._save_heartbeat()
        return RuntimeTick(
            resources=len(self.store.list_resources()),
            usage_limits=len(self.store.list_usage_limits()),
            health_targets=sum(1 for target in self.store.list_health_targets() if target.enabled),
            audit_events=self.store.count_audit_events(),
            health_evidence=len(self.store.list_health_evidence()),
            physical_identities=len(self.store.list_physical_identities()),
            runtime_heartbeats=len(self.store.list_runtime_heartbeats()),
            health_probes=0,
            host_inspections=0,
            host_security_high_findings=0,
            host_security_warning_findings=0,
            host_security_remediation_plans_staged=0,
            host_security_ids_reviews_prepared=0,
            host_security_sisko_requests=0,
            host_security_auto_executions=0,
            crew_messages_dispatched=0,
            crew_messages_blocked=0,
            usage_continuations_dispatched=0,
            usage_continuations_skipped=0,
            knowledge_events_captured=0,
            knowledge_events_failed=0,
            station_audits=0,
            station_audit_actions=0,
            station_audit_odo_referrals=0,
            station_audit_sisko_requests=0,
        )

    def run(self, interval_seconds: float = 30.0, once: bool = False) -> RuntimeTick:
        if interval_seconds <= 0:
            raise ValueError("runtime interval must be positive")
        last_tick = self.tick()
        if once:
            self.close()
            return last_tick
        while True:
            idle = min(float(interval_seconds), self.maximum_idle_seconds)
            due_at = getattr(self.last_scheduler_cycle, "next_due_at", None)
            if due_at is not None:
                due_in = max(0.0, (datetime.fromisoformat(due_at) - datetime.now(UTC)).total_seconds())
                idle = min(idle, due_in) if due_in else min(idle, 0.25)
            time.sleep(max(0.0, idle))
            last_tick = self.tick()

    def close(self) -> None:
        shutdown = getattr(self.scheduler, "shutdown", None)
        if callable(shutdown):
            shutdown()

    def _probe_health_targets(self) -> int:
        if not self.probe_health_targets:
            return 0
        targets = tuple(target for target in self.store.list_health_targets() if target.enabled)
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
