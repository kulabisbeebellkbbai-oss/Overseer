"""Read-only collection adapters and their exact scheduler registry."""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from .collection_models import (
    MAX_EVIDENCE_IDS,
    MAX_IDENTIFIER_LENGTH,
    MAX_SUMMARY_LENGTH,
    CollectionJob,
    CollectionJobKind,
    CollectionOutcome,
)
from .health import HealthStatus
from .host import HostInspectionAdapter
from .live_health import RoutedHealthProbeAdapter
from .packages import AptPackageInspectionAdapter, package_inspection_record
from .store import SQLiteStore

_SECRET_RE = re.compile(
    r"(?i)(?:bearer\s+\S+|(?:token|password|secret|api[_-]?key|authorization)\s*[=:]\s*\S+)"
)


def bounded_text(value: object, *, limit: int = MAX_SUMMARY_LENGTH) -> str:
    """Return scheduler-safe text with secrets and oversized payloads removed."""
    text = str(value or "").replace("\x00", " ").strip()
    text = _SECRET_RE.sub("[redacted]", text)
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def bounded_evidence_ids(values: object) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or values is None:
        return ()
    result: list[str] = []
    for value in values:
        item = bounded_text(value, limit=MAX_IDENTIFIER_LENGTH)
        if item and item not in result:
            result.append(item)
        if len(result) >= MAX_EVIDENCE_IDS:
            break
    return tuple(result)


@dataclass(frozen=True)
class CollectionExecution:
    outcome: CollectionOutcome
    summary: str
    evidence_ids: tuple[str, ...] = ()
    failure_category: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", CollectionOutcome(self.outcome))
        object.__setattr__(self, "summary", bounded_text(self.summary))
        object.__setattr__(self, "evidence_ids", bounded_evidence_ids(self.evidence_ids))
        object.__setattr__(self, "failure_category", bounded_text(self.failure_category, limit=MAX_IDENTIFIER_LENGTH))


class CollectionAdapter(Protocol):
    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        """Perform one bounded, read-only collection."""


class CollectionAdapterRegistry:
    """Deterministic exact ``(job kind, adapter id)`` adapter bindings."""

    def __init__(self, bindings: Mapping[tuple[CollectionJobKind | str, str], CollectionAdapter] | None = None) -> None:
        self._bindings: dict[tuple[CollectionJobKind, str], CollectionAdapter] = {}
        for (kind, adapter_id), adapter in (bindings or {}).items():
            self.register(kind, adapter_id, adapter)

    def register(self, kind: CollectionJobKind | str, adapter_id: str, adapter: CollectionAdapter) -> None:
        kind = CollectionJobKind(kind)
        if not isinstance(adapter_id, str) or not adapter_id.strip() or len(adapter_id) > MAX_IDENTIFIER_LENGTH:
            raise ValueError("adapter id must be a bounded non-blank identifier")
        advertised = getattr(adapter, "collection_job_kind", None)
        if advertised is not None and CollectionJobKind(advertised) is not kind:
            raise ValueError("adapter kind mismatch")
        key = (kind, adapter_id)
        if key in self._bindings and self._bindings[key] is not adapter:
            raise ValueError("collection adapter binding collision")
        self._bindings[key] = adapter

    bind = register

    def resolve(self, job: CollectionJob, adapter_id: str | None = None) -> CollectionAdapter:
        if not isinstance(job, CollectionJob):
            raise ValueError("collection adapter resolution requires a collection job")
        matches = [
            (identifier, adapter)
            for (kind, identifier), adapter in self._bindings.items()
            if kind is job.kind and (adapter_id is None or identifier == adapter_id)
        ]
        if not matches:
            raise ValueError(f"missing collection adapter for {job.kind.value}")
        if adapter_id is None and len(matches) != 1:
            raise ValueError(f"ambiguous collection adapter for {job.kind.value}")
        identifier, adapter = matches[0]
        advertised = getattr(adapter, "collection_adapter_id", identifier)
        if advertised != identifier:
            raise ValueError("adapter identifier mismatch")
        return adapter

    adapter_for = resolve


class HealthProbeCollectionAdapter:
    collection_job_kind = CollectionJobKind.HEALTH_PROBE

    def __init__(self, probe_adapter_factory: Callable[[float], object] | None = None) -> None:
        self.probe_adapter_factory = probe_adapter_factory or (lambda timeout: RoutedHealthProbeAdapter(timeout_seconds=timeout))

    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        if not job.target_id:
            return CollectionExecution(CollectionOutcome.FAILED, "health target binding is missing", failure_category="contract_mismatch")
        with SQLiteStore(store_path) as store:
            target = store.load_health_target(job.target_id)
            evidence = self.probe_adapter_factory(job.timeout_seconds).probe(target)
            store.save_health_evidence(evidence)
        healthy = HealthStatus(evidence.observed_status) in {HealthStatus.HEALTHY, HealthStatus.RECOVERED}
        return CollectionExecution(
            CollectionOutcome.SUCCEEDED if healthy else CollectionOutcome.FAILED,
            f"health probe {HealthStatus(evidence.observed_status).value}",
            (evidence.id,),
            "" if healthy else "unavailable",
        )


class HostInspectionCollectionAdapter:
    collection_job_kind = CollectionJobKind.HOST_INSPECTION

    def __init__(self, inspection_adapter_factory: Callable[[float], HostInspectionAdapter] | None = None) -> None:
        self.inspection_adapter_factory = inspection_adapter_factory or (lambda timeout: HostInspectionAdapter(timeout_seconds=timeout))

    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        snapshot = self.inspection_adapter_factory(job.timeout_seconds).inspect()
        with SQLiteStore(store_path) as store:
            store.save_host_snapshot(snapshot)
        return CollectionExecution(CollectionOutcome.SUCCEEDED, f"host inspection captured for {bounded_text(snapshot.hostname, limit=160)}", (snapshot.id,))


class PackageInspectionCollectionAdapter:
    collection_job_kind = CollectionJobKind.PACKAGE_INSPECTION

    def __init__(self, inspection_adapter_factory: Callable[[float], AptPackageInspectionAdapter] | None = None) -> None:
        self.inspection_adapter_factory = inspection_adapter_factory or (lambda timeout: AptPackageInspectionAdapter(timeout_seconds=timeout))

    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        snapshot = self.inspection_adapter_factory(job.timeout_seconds).inspect()
        record = package_inspection_record(snapshot)
        with SQLiteStore(store_path) as store:
            store.save_package_inspection_record(record)
        succeeded = record.succeeded()
        return CollectionExecution(
            CollectionOutcome.SUCCEEDED if succeeded else CollectionOutcome.FAILED,
            f"package inspection observed {len(record.updates)} updates",
            (record.id,),
            "" if succeeded else "unavailable",
        )


class StorePathCallbackCollectionAdapter:
    """Adapter for existing read-only store-path status callbacks.

    A callback may accept ``(job, store_path, timeout_seconds)``,
    ``(job, store_path)``, or ``(store_path)``. The three-argument form is the
    production contract for callbacks that can enforce a boundary themselves.
    """

    def __init__(self, callback: Callable[..., object], *, kind: CollectionJobKind | str | None = None) -> None:
        self.callback = callback
        self.collection_job_kind = CollectionJobKind(kind) if kind is not None else None

    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        try:
            parameters = inspect.signature(self.callback).parameters
        except (TypeError, ValueError):
            result = self.callback(store_path)
        else:
            if len(parameters) >= 3:
                result = self.callback(job, store_path, job.timeout_seconds)
            elif len(parameters) == 2:
                result = self.callback(job, store_path)
            else:
                result = self.callback(store_path)
        if isinstance(result, CollectionExecution):
            return result
        if isinstance(result, Mapping):
            return CollectionExecution(
                result.get("outcome", CollectionOutcome.SUCCEEDED),
                result.get("summary", "store-path callback completed"),
                result.get("evidence_ids", ()),
                result.get("failure_category", ""),
            )
        return CollectionExecution(CollectionOutcome.SUCCEEDED, bounded_text(result) or "store-path callback completed")


# Short compatibility name used by existing store-path integration callers.
StorePathCallbackAdapter = StorePathCallbackCollectionAdapter


def default_collection_adapter_registry() -> CollectionAdapterRegistry:
    registry = CollectionAdapterRegistry()
    registry.register(CollectionJobKind.HEALTH_PROBE, "health-probe", HealthProbeCollectionAdapter())
    registry.register(CollectionJobKind.HOST_INSPECTION, "host-inspection", HostInspectionCollectionAdapter())
    registry.register(CollectionJobKind.PACKAGE_INSPECTION, "package-inspection", PackageInspectionCollectionAdapter())
    return registry
