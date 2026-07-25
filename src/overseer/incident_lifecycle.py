"""Incident lifecycle and post-review evidence for Sisko."""

from __future__ import annotations

from pathlib import Path

from .audit import AuditEventType
from .health import HealthStatus, summarize_health_targets
from .ops_records import OperationRecordKind, OperationRecordStatus, operation_record_status


def incident_lifecycle_status(store_path: str | Path) -> dict[str, object]:
    from .store import SQLiteStore

    store = SQLiteStore(store_path)
    try:
        incidents = [record for record in store.list_operation_records(kind=OperationRecordKind.INCIDENT.value)]
        alerts = list(store.list_audit_events(event_type=AuditEventType.ALERT, limit=500))
        alert_count = store.count_audit_events(event_type=AuditEventType.ALERT)
        health = summarize_health_targets(store.list_health_targets(), store.list_health_evidence())
    finally:
        store.close()
    health_incidents = [
        {
            "id": summary.latest_evidence_id or summary.target_id,
            "resource_id": summary.resource_id,
            "status": summary.latest_status.value,
            "owner_domain": summary.owner_domain.value,
            "summary": summary.error or summary.name,
            "next_step": "stage recovery and link post-incident review",
        }
        for summary in health
        if summary.latest_status in {HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN}
    ]
    return {
        "store": str(Path(store_path)),
        "records": len(incidents),
        "alerts": alert_count,
        "alert_sample_limit": 500,
        "alert_sampled": alert_count > len(alerts),
        "health_incidents": len(health_incidents),
        "open": sum(1 for record in incidents if record.status != OperationRecordStatus.CLOSED),
        "waiting_approval": sum(1 for record in incidents if record.status == OperationRecordStatus.WAITING_APPROVAL),
        "items": [operation_record_status(record) for record in incidents],
        "alert_items": [
            {
                "id": event.id,
                "severity": event.risk_level.value,
                "owner_domain": event.owner_domain.value,
                "subject_id": event.subject_id,
                "summary": event.summary,
                "occurred_at": event.occurred_at,
            }
            for event in alerts
        ],
        "health_items": health_incidents,
        "post_incident_checklist": _post_incident_checklist(),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _post_incident_checklist() -> list[dict[str, object]]:
    return [
        {"step": "timeline captured", "owner": "sisko", "status": "required_before_close"},
        {"step": "affected resources linked", "owner": "sisko", "status": "required_before_close"},
        {"step": "root cause or uncertainty documented", "owner": "julian", "status": "required_before_close"},
        {"step": "security impact reviewed", "owner": "odo", "status": "required_before_close"},
        {"step": "rollback or recovery evidence linked", "owner": "obrien", "status": "required_before_close"},
        {"step": "runbook update captured", "owner": "ezri", "status": "required_before_close"},
    ]
