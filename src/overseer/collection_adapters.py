"""Read-only collection adapters and their exact scheduler registry."""

from __future__ import annotations

import inspect
import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

from .collection_models import (
    MAX_EVIDENCE_IDS,
    MAX_IDENTIFIER_LENGTH,
    MAX_SUMMARY_LENGTH,
    CollectionJob,
    CollectionJobKind,
    CollectionOutcome,
)
from .health import HealthStatus
from .host import HostCommandObservation, HostInspectionAdapter, HostInspectionSnapshot
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
        if item and not re.fullmatch(r"(?:evidence|health|host|package|run|request)\.[A-Za-z0-9_.:-]+", item):
            item = _scheduler_digest(item, "evidence")
        if item and item not in result:
            result.append(item)
        if len(result) >= MAX_EVIDENCE_IDS:
            break
    return tuple(result)


def _scheduler_digest(value: object, prefix: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{prefix}.{digest}"


def _safe_target_surface(value: object) -> str:
    """Keep target identity useful while discarding query values and bodies."""
    text = bounded_text(value, limit=320)
    try:
        parsed = urlsplit(text)
    except ValueError:
        return _scheduler_digest(text, "target")
    if parsed.scheme and parsed.netloc:
        try:
            hostname = parsed.hostname or ""
            if ":" in hostname and not hostname.startswith("["):
                hostname = f"[{hostname}]"
            safe_netloc = hostname
            if parsed.port is not None:
                safe_netloc += f":{parsed.port}"
        except ValueError:
            return _scheduler_digest(text, "target")
        return urlunsplit((parsed.scheme, safe_netloc, parsed.path, "", ""))
    return _scheduler_digest(text, "target")


def _scheduler_health_evidence(evidence: object) -> object:
    """Project probe output to the fields safe for scheduler persistence."""
    return replace(
        evidence,
        target=_safe_target_surface(evidence.target),
        observed_error="health probe reported an error" if evidence.observed_error else "",
    )


_SAFE_HOST_COMMANDS = frozenset(
    {
        "hostname", "uname", "systemctl", "ss", "df", "firewall-cmd",
        "--user", "list-units", "--type=service", "--state=running", "--no-pager",
        "-tnp", "-ltnp", "-h", "--output=source,size,used,avail,pcent,target",
        "--state", "--get-active-zones", "--zone=public", "--list-all",
    }
)


def _safe_command_identity(command: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(part if part in _SAFE_HOST_COMMANDS else _scheduler_digest(part, "arg") for part in command)


def _scheduler_host_snapshot(snapshot: HostInspectionSnapshot) -> HostInspectionSnapshot:
    observations = tuple(
        HostCommandObservation(
            name=observation.name if observation.name in _SAFE_HOST_COMMANDS else _scheduler_digest(observation.name, "command"),
            command=_safe_command_identity(observation.command),
            exit_code=observation.exit_code,
            stdout="",
            stderr="",
        )
        for observation in snapshot.observations
    )
    return replace(
        snapshot,
        id=_scheduler_digest(snapshot.id, "host"),
        hostname=_scheduler_digest(snapshot.hostname, "hostname"),
        os_release={
            key if key in {"NAME", "VERSION", "ID", "VERSION_ID", "PRETTY_NAME"} else _scheduler_digest(key, "os-key"):
            _scheduler_digest(value, "os-value")
            for key, value in snapshot.os_release.items()
        },
        observations=observations,
    )


def _callback_evidence_ids(values: object) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or values is None:
        return ()
    result: list[str] = []
    for value in values:
        item = bounded_text(value, limit=MAX_IDENTIFIER_LENGTH)
        if not item:
            continue
        # Callback evidence is an identifier channel, never a payload channel.
        # Keep the established namespaced identifiers and hash everything else.
        if not re.fullmatch(r"(?:evidence|health|host|package|run|request)\.[A-Za-z0-9_.:-]+", item):
            item = _scheduler_digest(item, "evidence")
        if item not in result:
            result.append(item)
        if len(result) >= MAX_EVIDENCE_IDS:
            break
    return tuple(result)


def _callback_execution(
    outcome: CollectionOutcome,
    evidence_ids: object = (),
    failure_category: object = "",
) -> CollectionExecution:
    safe_category = bounded_text(failure_category, limit=MAX_IDENTIFIER_LENGTH)
    if safe_category not in {
        "", "timeout", "unavailable", "contract_mismatch", "authentication",
        "resource_conflict", "policy_blocked", "adapter_error", "internal_error",
    }:
        safe_category = "adapter_error"
    return CollectionExecution(
        outcome,
        f"store-path callback {CollectionOutcome(outcome).value}",
        _callback_evidence_ids(evidence_ids),
        safe_category,
    )
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
            evidence = _scheduler_health_evidence(
                self.probe_adapter_factory(job.timeout_seconds).probe(target)
            )
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
        snapshot = _scheduler_host_snapshot(self.inspection_adapter_factory(job.timeout_seconds).inspect())
        with SQLiteStore(store_path) as store:
            store.save_host_snapshot(snapshot)
        return CollectionExecution(CollectionOutcome.SUCCEEDED, f"host inspection captured for {bounded_text(snapshot.hostname, limit=160)}", (snapshot.id,))


class PackageInspectionCollectionAdapter:
    collection_job_kind = CollectionJobKind.PACKAGE_INSPECTION

    def __init__(self, inspection_adapter_factory: Callable[[float], AptPackageInspectionAdapter] | None = None) -> None:
        self.inspection_adapter_factory = inspection_adapter_factory or (lambda timeout: AptPackageInspectionAdapter(timeout_seconds=timeout))

    def collect(self, job: CollectionJob, store_path: str) -> CollectionExecution:
        snapshot = self.inspection_adapter_factory(job.timeout_seconds).inspect()
        record = package_inspection_record(replace(snapshot, stderr=""))
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
            return _callback_execution(result.outcome, result.evidence_ids, result.failure_category)
        if isinstance(result, Mapping):
            return _callback_execution(
                result.get("outcome", CollectionOutcome.SUCCEEDED),
                result.get("evidence_ids", ()),
                result.get("failure_category", ""),
            )
        return _callback_execution(CollectionOutcome.SUCCEEDED)


# Short compatibility name used by existing store-path integration callers.
StorePathCallbackAdapter = StorePathCallbackCollectionAdapter


def default_collection_adapter_registry() -> CollectionAdapterRegistry:
    registry = CollectionAdapterRegistry()
    registry.register(CollectionJobKind.HEALTH_PROBE, "health-probe", HealthProbeCollectionAdapter())
    registry.register(CollectionJobKind.HOST_INSPECTION, "host-inspection", HostInspectionCollectionAdapter())
    registry.register(CollectionJobKind.PACKAGE_INSPECTION, "package-inspection", PackageInspectionCollectionAdapter())
    return registry
