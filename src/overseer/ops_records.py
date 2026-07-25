"""Durable operations records for sysops workflow tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping

from .core import OwnerDomain, RiskLevel


class OperationRecordKind(StrEnum):
    INCIDENT = "incident"
    MAINTENANCE_WINDOW = "maintenance_window"
    SERVICE_DETAIL = "service_detail"
    SECURITY_BASELINE = "security_baseline"
    NETWORK_ROUTE = "network_route"
    STORAGE_BACKUP = "storage_backup"
    PHYSICAL_LIFECYCLE = "physical_lifecycle"
    VIRTUAL_RUNTIME = "virtual_runtime"
    OBSERVABILITY_TREND = "observability_trend"
    USAGE_COST = "usage_cost"
    COMPLIANCE_DRIFT = "compliance_drift"
    DOCUMENT_FRESHNESS = "document_freshness"
    IDENTITY_ACCESS = "identity_access"


class OperationRecordStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    STAGED = "staged"
    WAITING_APPROVAL = "waiting_approval"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    CLOSED = "closed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class OperationRecord:
    id: str
    kind: OperationRecordKind
    owner_domain: OwnerDomain
    status: OperationRecordStatus
    subject: str
    summary: str
    severity: RiskLevel = RiskLevel.LOW
    resource_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    next_step: str = ""
    created_at: str | None = None
    updated_at: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)


def operation_record_status(record: OperationRecord) -> dict[str, object]:
    return {
        "id": record.id,
        "kind": record.kind.value,
        "owner_domain": record.owner_domain.value,
        "status": record.status.value,
        "subject": record.subject,
        "summary": record.summary,
        "severity": record.severity.value,
        "resource_id": record.resource_id,
        "evidence_ids": list(record.evidence_ids),
        "next_step": record.next_step,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "metadata": dict(record.metadata),
    }
