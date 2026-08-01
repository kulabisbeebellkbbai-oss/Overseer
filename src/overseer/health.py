"""Service health evidence and classification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import OwnerDomain


class ProbeType(StrEnum):
    HTTP = "http"
    HTTPS = "https"
    MCP = "mcp"
    HTML = "html"
    JSON = "json"
    PROCESS = "process"
    COMMAND = "command"
    LOG = "log"
    MANUAL = "manual"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    RECOVERED = "recovered"
    SUSPENDED = "suspended"


@dataclass(frozen=True)
class HealthTarget:
    id: str
    resource_id: str
    name: str
    probe_type: ProbeType
    target: str
    owner_domain: OwnerDomain = OwnerDomain.JULIAN
    expected_status: int | None = None
    expected_content_type: str | None = None
    latency_warn_ms: int | None = None
    enabled: bool = True
    suspension_reason: str = ""


@dataclass(frozen=True)
class ProbeResult:
    target: str
    probe_type: ProbeType
    status_code: int | None = None
    content_type: str | None = None
    body_summary: str = ""
    error: str = ""
    latency_ms: int | None = None
    captured_at: str | None = None


@dataclass(frozen=True)
class HealthEvidence:
    id: str
    resource_id: str
    target: str
    probe_type: ProbeType
    observed_status: HealthStatus
    owner_domain: OwnerDomain
    observed_error: str = ""
    recovery_required: bool = False
    captured_at: str | None = None


@dataclass(frozen=True)
class HealthTargetSummary:
    target_id: str
    resource_id: str
    name: str
    target: str
    latest_status: HealthStatus
    owner_domain: OwnerDomain
    latest_evidence_id: str | None = None
    latest_captured_at: str | None = None
    recovery_required: bool = False
    error: str = ""
    enabled: bool = True
    suspension_reason: str = ""


def summarize_health_targets(
    targets: tuple[HealthTarget, ...],
    evidence_items: tuple[HealthEvidence, ...],
) -> tuple[HealthTargetSummary, ...]:
    evidence_by_key: dict[tuple[str, str], list[HealthEvidence]] = {}
    for evidence in evidence_items:
        evidence_by_key.setdefault((evidence.resource_id, evidence.target), []).append(evidence)
    summaries: list[HealthTargetSummary] = []
    for target in targets:
        if not target.enabled:
            summaries.append(
                HealthTargetSummary(
                    target_id=target.id,
                    resource_id=target.resource_id,
                    name=target.name,
                    target=target.target,
                    latest_status=HealthStatus.SUSPENDED,
                    owner_domain=target.owner_domain,
                    recovery_required=False,
                    enabled=False,
                    suspension_reason=target.suspension_reason,
                )
            )
            continue
        latest = _latest_evidence(evidence_by_key.get((target.resource_id, target.target), []))
        if latest is None:
            summaries.append(
                HealthTargetSummary(
                    target_id=target.id,
                    resource_id=target.resource_id,
                    name=target.name,
                    target=target.target,
                    latest_status=HealthStatus.UNKNOWN,
                    owner_domain=target.owner_domain,
                    recovery_required=True,
                    error="missing health evidence",
                )
            )
            continue
        summaries.append(
            HealthTargetSummary(
                target_id=target.id,
                resource_id=target.resource_id,
                name=target.name,
                target=target.target,
                latest_status=HealthStatus(latest.observed_status),
                owner_domain=OwnerDomain(latest.owner_domain),
                latest_evidence_id=latest.id,
                latest_captured_at=latest.captured_at,
                recovery_required=latest.recovery_required,
                error=latest.observed_error,
            )
        )
    return tuple(summaries)


def classify_probe(target: HealthTarget, result: ProbeResult | None) -> HealthEvidence:
    if result is None:
        return _evidence(target, HealthStatus.UNKNOWN, "missing probe result", True)

    if result.target != target.target:
        return _evidence(target, HealthStatus.UNKNOWN, "probe target does not match health target", True, result)

    if result.error:
        return _evidence(target, HealthStatus.FAILED, result.error, True, result)

    if result.status_code is not None:
        expected = target.expected_status or 200
        if result.status_code >= 500:
            return _evidence(target, HealthStatus.FAILED, f"HTTP {result.status_code}", True, result)
        if result.status_code != expected:
            return _evidence(target, HealthStatus.DEGRADED, f"expected HTTP {expected}, got {result.status_code}", True, result)

    if target.expected_content_type and not _content_type_matches(result.content_type, target.expected_content_type):
        return _evidence(
            target,
            HealthStatus.DEGRADED,
            f"expected content type {target.expected_content_type}, got {result.content_type or 'missing'}",
            True,
            result,
        )

    if target.probe_type == ProbeType.JSON and "invalid json" in result.body_summary.lower():
        return _evidence(target, HealthStatus.FAILED, "invalid JSON response", True, result)

    if target.latency_warn_ms is not None and result.latency_ms is not None and result.latency_ms > target.latency_warn_ms:
        return _evidence(target, HealthStatus.DEGRADED, f"latency {result.latency_ms}ms exceeds {target.latency_warn_ms}ms", True, result)

    return _evidence(target, HealthStatus.HEALTHY, "", False, result)


def recovery_evidence(failed: HealthEvidence, current: HealthEvidence) -> HealthEvidence:
    if failed.resource_id != current.resource_id or failed.target != current.target:
        return current
    if failed.observed_status in {HealthStatus.FAILED, HealthStatus.DEGRADED, HealthStatus.UNKNOWN} and current.observed_status == HealthStatus.HEALTHY:
        return HealthEvidence(
            id=current.id,
            resource_id=current.resource_id,
            target=current.target,
            probe_type=current.probe_type,
            observed_status=HealthStatus.RECOVERED,
            owner_domain=current.owner_domain,
            observed_error="",
            recovery_required=False,
            captured_at=current.captured_at,
        )
    return current


def _evidence(
    target: HealthTarget,
    status: HealthStatus,
    error: str,
    recovery_required: bool,
    result: ProbeResult | None = None,
) -> HealthEvidence:
    suffix = (result.captured_at if result and result.captured_at else "current").replace(":", "").replace("-", "")
    return HealthEvidence(
        id=f"health.{target.id}.{suffix}",
        resource_id=target.resource_id,
        target=target.target,
        probe_type=target.probe_type,
        observed_status=status,
        owner_domain=_owner_for_status(target, status, error),
        observed_error=error,
        recovery_required=recovery_required,
        captured_at=result.captured_at if result else None,
    )


def _content_type_matches(actual: str | None, expected: str) -> bool:
    if not actual:
        return False
    return expected.lower() in actual.lower()


def _owner_for_status(target: HealthTarget, status: HealthStatus, error: str) -> OwnerDomain:
    lowered = error.lower()
    if "certificate" in lowered or "unauthorized" in lowered or "forbidden" in lowered:
        return OwnerDomain.ODO
    if "proxy" in lowered or "gateway" in lowered:
        return OwnerDomain.DAX
    if status in {HealthStatus.FAILED, HealthStatus.DEGRADED, HealthStatus.UNKNOWN}:
        return target.owner_domain
    return target.owner_domain


def _latest_evidence(evidence_items: list[HealthEvidence]) -> HealthEvidence | None:
    if not evidence_items:
        return None
    return max(evidence_items, key=lambda item: item.captured_at or item.id)
