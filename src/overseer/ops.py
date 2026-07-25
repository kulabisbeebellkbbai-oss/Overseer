"""Read-only operations coverage summaries for gap analysis follow-through."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .admin import AdminChangeKind
from .audit import ApprovalStatus, AuditEventType
from .core import ClaimStatus, OwnerDomain, ResourceState, ResourceType, RiskLevel
from .health import HealthStatus, ProbeType, summarize_health_targets
from .ops_records import OperationRecord, OperationRecordKind, OperationRecordStatus, operation_record_status
from .store import SQLiteStore


WORKFLOW_TEMPLATES: tuple[dict[str, object], ...] = (
    {
        "id": "incident.lifecycle",
        "kind": OperationRecordKind.INCIDENT.value,
        "owner_domain": OwnerDomain.SISKO.value,
        "severity": RiskLevel.MEDIUM.value,
        "subject": "Incident lifecycle",
        "summary": "Track severity, owner, affected resources, evidence, approval point, recovery, and review.",
        "next_step": "triage, link evidence, stage remediation, and wait only if approval is required",
    },
    {
        "id": "maintenance.window",
        "kind": OperationRecordKind.MAINTENANCE_WINDOW.value,
        "owner_domain": OwnerDomain.OBRIEN.value,
        "severity": RiskLevel.MEDIUM.value,
        "subject": "Maintenance window",
        "summary": "Track schedule, blackout conflicts, rollback plan, validation checklist, and operator impact.",
        "next_step": "stage update or service plan with rollback and post-change validation",
    },
    {
        "id": "service.detail",
        "kind": OperationRecordKind.SERVICE_DETAIL.value,
        "owner_domain": OwnerDomain.JULIAN.value,
        "severity": RiskLevel.MEDIUM.value,
        "subject": "Service detail review",
        "summary": "Track service metadata, owner, health, logs, config paths, dependencies, and restart history.",
        "next_step": "collect health evidence, link logs, and stage service action if needed",
    },
    {
        "id": "security.baseline",
        "kind": OperationRecordKind.SECURITY_BASELINE.value,
        "owner_domain": OwnerDomain.ODO.value,
        "severity": RiskLevel.HIGH.value,
        "subject": "Security baseline drift",
        "summary": "Track baseline checks, listener exposure, auth changes, firewall drift, and containment evidence.",
        "next_step": "stage remediation plan and request approval only for enforcement actions",
    },
    {
        "id": "storage.backup",
        "kind": OperationRecordKind.STORAGE_BACKUP.value,
        "owner_domain": OwnerDomain.KIRA.value,
        "severity": RiskLevel.MEDIUM.value,
        "subject": "Storage backup and recovery",
        "summary": "Track mount health, capacity, backup jobs, restore points, restore tests, and cleanup candidates.",
        "next_step": "record backup job state and schedule restore verification",
    },
    {
        "id": "virtual.runtime",
        "kind": OperationRecordKind.VIRTUAL_RUNTIME.value,
        "owner_domain": OwnerDomain.DAX.value,
        "severity": RiskLevel.MEDIUM.value,
        "subject": "Virtual runtime inventory",
        "summary": "Track VM, container, emulator, gateway, proxy, tunnel, port, lease, snapshot, and cleanup state.",
        "next_step": "refresh runtime inventory and stage cleanup or snapshot work",
    },
    {
        "id": "usage.cost",
        "kind": OperationRecordKind.USAGE_COST.value,
        "owner_domain": OwnerDomain.QUARK.value,
        "severity": RiskLevel.LOW.value,
        "subject": "Usage limit cost and forecast",
        "summary": "Track quota reset policy, remaining capacity, usage history, project allocation, and cost exposure.",
        "next_step": "link quota record and schedule continuation after reset",
    },
    {
        "id": "documentation.freshness",
        "kind": OperationRecordKind.DOCUMENT_FRESHNESS.value,
        "owner_domain": OwnerDomain.EZRI.value,
        "severity": RiskLevel.LOW.value,
        "subject": "Documentation freshness",
        "summary": "Track runbook coverage, ADR index, changelog status, stale pages, and evidence links.",
        "next_step": "review required runbook coverage and update stale workflows",
    },
    {
        "id": "identity.access",
        "kind": OperationRecordKind.IDENTITY_ACCESS.value,
        "owner_domain": OwnerDomain.ODO.value,
        "severity": RiskLevel.HIGH.value,
        "subject": "Identity and secrets review",
        "summary": "Track users, groups, sudoers, SSH keys, service accounts, token custody, and rotation reminders.",
        "next_step": "review redacted access inventory and stage rotations or revocations",
    },
)


def operations_gap_coverage_status(store_path: str | Path) -> dict[str, object]:
    """Return a broad, read-only system-operations surface map.

    The payload intentionally favors status, evidence pointers, and staged next
    steps over live mutation. It gives the UI a place to display every gap class
    identified by Ezri without granting host-changing privileges.
    """

    store = SQLiteStore(store_path)
    try:
        resources = store.list_resources()
        claims = store.list_claims()
        approvals = store.list_approvals()
        audits = store.list_audit_events(limit=2000)
        admin_plans = [plan for plan in store.list_admin_change_plans() if not plan.archived]
        executions = store.list_admin_executions()
        targets = store.list_health_targets()
        evidence = store.list_health_evidence()
        health = summarize_health_targets(targets, evidence)
        physical = store.list_physical_identities()
        usage_limits = store.list_usage_limits()
        usage_requests = store.list_usage_continuation_requests()
        operation_records = store.list_operation_records()
        latest_snapshot = store.load_latest_host_snapshot()
    finally:
        store.close()

    return {
        "coverage": _coverage_rows(),
        "operation_records": _operation_record_summary(operation_records),
        "incidents": _incident_rows(audits, health, approvals),
        "risk_register": _risk_register_rows(resources, audits, health),
        "change_calendar": _change_calendar_rows(admin_plans),
        "service_details": _service_detail_rows(resources, targets, health, admin_plans, executions),
        "service_actions": _service_action_rows(resources, admin_plans),
        "log_evidence": _log_evidence_rows(targets, evidence),
        "host_resources": host_resource_status(),
        "software_inventory": software_inventory_status(),
        "security_drift": _security_drift_rows(latest_snapshot, admin_plans, audits),
        "network": network_status(latest_snapshot),
        "storage_backup": storage_backup_status(),
        "physical_lifecycle": _physical_lifecycle_rows(physical, claims),
        "virtual_runtime": _virtual_runtime_rows(resources, claims),
        "observability": _observability_rows(health, evidence),
        "usage_costs": _usage_cost_rows(usage_limits, usage_requests),
        "compliance": _compliance_rows(approvals, admin_plans, audits),
        "documentation": documentation_coverage_status(),
        "identity_access": identity_access_status(),
    }


def record_operation_status(
    store_path: str | Path,
    record_id: str,
    kind: str,
    owner_domain: str,
    status: str,
    subject: str,
    summary: str,
    severity: str = RiskLevel.LOW.value,
    resource_id: str | None = None,
    evidence_ids: Sequence[str] = (),
    next_step: str = "",
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    now = _utc_now()
    store = SQLiteStore(store_path)
    try:
        try:
            existing = store.load_operation_record(record_id)
        except KeyError:
            existing = None
        merged_metadata = dict(existing.metadata) if existing else {}
        merged_metadata.update(metadata or {})
        created_at = str(merged_metadata.get("created_at") or (existing.created_at if existing else "") or now)
        merged_metadata["created_at"] = created_at
        merged_metadata["updated_at"] = now
        transitions = list(merged_metadata.get("transitions", ()))
        if not transitions or transitions[-1].get("status") != status:
            transitions.append({"status": status, "at": now, "by": str(merged_metadata.get("updated_by") or owner_domain)})
        merged_metadata["transitions"] = transitions
        if existing and not resource_id:
            resource_id = existing.resource_id
        if existing and not evidence_ids:
            evidence_ids = existing.evidence_ids
        if existing and not next_step:
            next_step = existing.next_step
        record = OperationRecord(
            id=record_id,
            kind=OperationRecordKind(kind),
            owner_domain=OwnerDomain(owner_domain),
            status=OperationRecordStatus(status),
            subject=subject,
            summary=summary,
            severity=RiskLevel(severity),
            resource_id=resource_id,
            evidence_ids=tuple(evidence_ids),
            next_step=next_step,
            created_at=created_at,
            updated_at=now,
            metadata=merged_metadata,
        )
        store.save_operation_record(record)
        return {
            "store": str(store.path),
            "record": operation_record_status(record),
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    finally:
        store.close()


def transition_operation_record_status(
    store_path: str | Path,
    record_id: str,
    status: str,
    updated_by: str = "sisko",
    next_step: str | None = None,
    summary_note: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        existing = store.load_operation_record(record_id)
    finally:
        store.close()
    metadata = dict(existing.metadata)
    metadata["updated_by"] = updated_by
    if summary_note:
        notes = list(metadata.get("notes", ()))
        notes.append({"at": _utc_now(), "by": updated_by, "note": summary_note})
        metadata["notes"] = notes
    return record_operation_status(
        store_path,
        record_id=existing.id,
        kind=existing.kind.value,
        owner_domain=existing.owner_domain.value,
        status=status,
        subject=existing.subject,
        summary=existing.summary,
        severity=existing.severity.value,
        resource_id=existing.resource_id,
        evidence_ids=existing.evidence_ids,
        next_step=next_step if next_step is not None else existing.next_step,
        metadata=metadata,
    )


def operation_workflow_catalog_status(store_path: str | Path) -> dict[str, object]:
    records = list_operation_records_status(store_path)["items"]
    return {
        "store": str(Path(store_path)),
        "templates": [dict(template) for template in WORKFLOW_TEMPLATES],
        "records": len(records),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def stage_operation_workflow_status(
    store_path: str | Path,
    template_id: str,
    record_id: str | None = None,
    resource_id: str | None = None,
    requested_by: str = "sisko",
) -> dict[str, object]:
    template = next((item for item in WORKFLOW_TEMPLATES if item["id"] == template_id), None)
    if template is None:
        raise ValueError(f"unknown operation workflow template: {template_id}")
    metadata = {"template_id": template_id, "requested_by": requested_by}
    return record_operation_status(
        store_path,
        record_id=record_id or f"ops.{template_id}",
        kind=str(template["kind"]),
        owner_domain=str(template["owner_domain"]),
        status=OperationRecordStatus.STAGED.value,
        subject=str(template["subject"]),
        summary=str(template["summary"]),
        severity=str(template["severity"]),
        resource_id=resource_id,
        next_step=str(template["next_step"]),
        metadata=metadata,
    )


def list_operation_records_status(
    store_path: str | Path,
    kind: str | None = None,
    owner_domain: str | None = None,
    status: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        records = store.list_operation_records(kind=kind, owner_domain=owner_domain, status=status)
        return {
            "store": str(store.path),
            "records": len(records),
            "items": [operation_record_status(record) for record in records],
            "by_kind": {
                kind.value: sum(1 for record in records if record.kind == kind)
                for kind in OperationRecordKind
            },
            "by_status": {
                status.value: sum(1 for record in records if record.status == status)
                for status in OperationRecordStatus
            },
        }
    finally:
        store.close()


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def host_resource_status() -> dict[str, object]:
    memory = _parse_meminfo()
    load = _read_text("/proc/loadavg").split()
    disk = shutil.disk_usage("/")
    return {
        "load_1m": load[0] if len(load) > 0 else "",
        "load_5m": load[1] if len(load) > 1 else "",
        "load_15m": load[2] if len(load) > 2 else "",
        "memory_total_mb": _kb_to_mb(memory.get("MemTotal")),
        "memory_available_mb": _kb_to_mb(memory.get("MemAvailable")),
        "swap_total_mb": _kb_to_mb(memory.get("SwapTotal")),
        "swap_free_mb": _kb_to_mb(memory.get("SwapFree")),
        "root_total_gb": _bytes_to_gb(disk.total),
        "root_free_gb": _bytes_to_gb(disk.free),
        "processes": len([name for name in os.listdir("/proc") if name.isdigit()]) if Path("/proc").exists() else 0,
        "thermal_zones": len(list(Path("/sys/class/thermal").glob("thermal_zone*"))),
    }


def software_inventory_status() -> dict[str, object]:
    dpkg = _run_read_only(("dpkg-query", "-W", "-f=${binary:Package}\n"), timeout_seconds=1)
    apt_holds = _run_read_only(("apt-mark", "showhold"), timeout_seconds=1)
    return {
        "dpkg_available": dpkg["exit_code"] == 0,
        "dpkg_packages": _line_count(dpkg["stdout"]),
        "held_packages": _line_count(apt_holds["stdout"]) if apt_holds["exit_code"] == 0 else 0,
        "pip_available": shutil.which("pip") is not None or shutil.which("pip3") is not None,
        "pip_packages": 0,
        "npm_available": shutil.which("npm") is not None,
        "flatpak_available": shutil.which("flatpak") is not None,
        "flatpak_apps": 0,
        "inventory_scope": "apt, python pip, npm global, flatpak availability",
        "next_step": "add provider-specific provenance, CVE correlation, and release-note links",
    }


def network_status(latest_snapshot: Any | None) -> dict[str, object]:
    routes = _run_read_only(("ip", "route", "show"), timeout_seconds=1)
    addresses = _run_read_only(("ip", "-brief", "addr"), timeout_seconds=1)
    resolv = _read_text("/etc/resolv.conf")
    listeners = latest_snapshot.observation("ss").stdout if latest_snapshot else ""
    return {
        "interfaces": _line_count(addresses["stdout"]),
        "routes": _line_count(routes["stdout"]),
        "dns_servers": len([line for line in resolv.splitlines() if line.strip().startswith("nameserver")]),
        "listener_rows": _line_count(listeners),
        "gateway_routes": len([line for line in listeners.splitlines() if "LISTEN" in line]),
        "next_step": "add protected-gateway upstream inventory and request/status trend storage",
    }


def storage_backup_status() -> dict[str, object]:
    mounts = _run_read_only(("findmnt", "--json"), timeout_seconds=1)
    df = _run_read_only(("df", "-P", "-T"), timeout_seconds=1)
    backup_markers = [
        path
        for root in (Path("state"), Path("backups"), Path("local-secrets"))
        if root.exists()
        for path in root.glob("**/*")
        if "backup" in path.name.lower()
    ]
    return {
        "mount_rows": _line_count(df["stdout"]),
        "findmnt_available": mounts["exit_code"] == 0,
        "backup_markers": len(backup_markers),
        "root_usage": _root_usage_row(),
        "restore_tests": 0,
        "next_step": "add backup job registry, restore-test records, SMART health, inode trends, and cleanup recommendations",
    }


def documentation_coverage_status() -> dict[str, object]:
    docs = sorted(Path("docs").glob("*.md"))
    expected = (
        "operator-workflows.md",
        "ui-regression-testing.md",
        "sysops-task-gap-analysis.md",
        "maintenance-and-patch-operations.md",
        "security-monitoring.md",
        "service-health-monitoring.md",
    )
    present = {path.name for path in docs}
    return {
        "docs_count": len(docs),
        "expected_runbooks": len(expected),
        "present_runbooks": sum(1 for name in expected if name in present),
        "missing_runbooks": [name for name in expected if name not in present],
        "next_step": "add freshness checks, ADR index, release notes, and per-resource required-runbook matrix",
    }


def identity_access_status() -> dict[str, object]:
    passwd = _read_text("/etc/passwd")
    group = _read_text("/etc/group")
    sudoers = Path("/etc/sudoers").exists()
    ssh_keys = list(Path.home().glob(".ssh/*.pub"))
    return {
        "local_users": len([line for line in passwd.splitlines() if line and not line.startswith("#")]),
        "local_groups": len([line for line in group.splitlines() if line and not line.startswith("#")]),
        "sudoers_present": sudoers,
        "public_ssh_keys": len(ssh_keys),
        "service_accounts": len([line for line in passwd.splitlines() if "/usr/sbin/nologin" in line or "/bin/false" in line]),
        "next_step": "add redacted user/group/sudoers/authorized_keys review and credential rotation workflow",
    }


def _coverage_rows() -> list[dict[str, object]]:
    return [
        _coverage("incident lifecycle", "partial", "Overview, Audit, crew messages", "add dedicated incident board"),
        _coverage("service detail", "partial", "Health targets, service discovery, admin plans", "add service detail panel"),
        _coverage("patch compliance", "partial", "Package status and staged update plans", "add compliance aging and provenance"),
        _coverage("security baseline drift", "partial", "Host inspection, findings, source review", "add baseline and drift records"),
        _coverage("network gateway analysis", "partial", "Listeners and virtual assets", "add route/DNS/TLS/gateway inventory"),
        _coverage("storage backup recovery", "partial", "Storage discovery and resource registry", "add backup and restore registry"),
        _coverage("physical lifecycle", "partial", "Physical discovery and claims", "add identity history and maintenance records"),
        _coverage("virtual runtime", "partial", "Claims and listener discovery", "add VM/container/emulator state inventory"),
        _coverage("observability performance", "partial", "Health probes and regression tests", "add trend history and host metrics"),
        _coverage("usage cost forecasting", "partial", "Usage limits and continuations", "add cost and exhaustion forecasting"),
        _coverage("compliance drift", "partial", "Policy profile and warning approvals", "add desired-state drift matrix"),
        _coverage("documentation coverage", "partial", "Documents, workflows, git status", "add freshness and ADR/release indexes"),
        _coverage("identity secrets access", "gap", "Security routing only", "add identity and credential review panels"),
    ]


def _operation_record_summary(records: Sequence[OperationRecord]) -> dict[str, object]:
    return {
        "records": len(records),
        "open": sum(1 for record in records if record.status != OperationRecordStatus.CLOSED),
        "waiting_approval": sum(1 for record in records if record.status == OperationRecordStatus.WAITING_APPROVAL),
        "by_kind": {
            kind.value: sum(1 for record in records if record.kind == kind)
            for kind in OperationRecordKind
        },
        "by_status": {
            status.value: sum(1 for record in records if record.status == status)
            for status in OperationRecordStatus
        },
        "items": [operation_record_status(record) for record in records],
    }


def _coverage(area: str, status: str, available: str, gap: str) -> dict[str, object]:
    return {"area": area, "status": status, "available": available, "next_gap": gap}


def _incident_rows(audits: Sequence[Any], health: Sequence[Any], approvals: Sequence[Any]) -> list[dict[str, object]]:
    rows = []
    for event in audits:
        if event.event_type == AuditEventType.ALERT:
            rows.append(
                {
                    "id": event.id,
                    "severity": event.risk_level.value,
                    "owner": event.owner_domain.value,
                    "status": "observed",
                    "summary": event.summary,
                    "next_step": "triage, assign owner, and link remediation plan",
                }
            )
    for item in health:
        if item.latest_status in {HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN}:
            rows.append(
                {
                    "id": item.latest_evidence_id or item.target_id,
                    "severity": "medium",
                    "owner": item.owner_domain.value,
                    "status": "needs_recovery",
                    "summary": f"{item.name} is {item.latest_status.value}",
                    "next_step": "open Health, review evidence, and stage recovery",
                }
            )
    pending = [approval for approval in approvals if approval.status == ApprovalStatus.PENDING]
    if pending:
        rows.append(
            {
                "id": "pending.approvals",
                "severity": "medium",
                "owner": "sisko",
                "status": "approval_waiting",
                "summary": f"{len(pending)} approval records are pending",
                "next_step": "review Admin approval decisions",
            }
        )
    return rows


def _risk_register_rows(resources: Sequence[Any], audits: Sequence[Any], health: Sequence[Any]) -> list[dict[str, object]]:
    rows = [
        {
            "id": resource.id,
            "domain": resource.owner_domain.value,
            "risk": resource.risk_level.value,
            "state": resource.state.value,
            "summary": resource.name,
            "next_review": "on change or incident",
        }
        for resource in resources
        if resource.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} or resource.state != ResourceState.AVAILABLE
    ]
    rows.extend(
        {
            "id": event.id,
            "domain": event.owner_domain.value,
            "risk": event.risk_level.value,
            "state": "alert",
            "summary": event.summary,
            "next_review": "incident triage",
        }
        for event in audits
        if event.event_type == AuditEventType.ALERT
    )
    rows.extend(
        {
            "id": item.latest_evidence_id or item.target_id,
            "domain": item.owner_domain.value,
            "risk": "medium",
            "state": item.latest_status.value,
            "summary": item.error or item.name,
            "next_review": "health recovery",
        }
        for item in health
        if item.recovery_required
    )
    return rows


def _change_calendar_rows(plans: Sequence[Any]) -> list[dict[str, object]]:
    return [
        {
            "id": plan.id,
            "kind": plan.kind.value,
            "target": plan.target,
            "status": "approved" if plan.approved else "pending" if plan.requires_explicit_approval() else "ready",
            "window": plan.proposed_state if "window" in plan.proposed_state.lower() else "unscheduled",
            "rollback": "present" if plan.rollback_steps else "missing",
        }
        for plan in plans
        if not plan.canceled
    ]


def _service_detail_rows(resources: Sequence[Any], targets: Sequence[Any], health: Sequence[Any], plans: Sequence[Any], executions: Sequence[Any]) -> list[dict[str, object]]:
    health_by_resource = {item.resource_id: item for item in health}
    targets_by_resource: dict[str, int] = {}
    for target in targets:
        targets_by_resource[target.resource_id] = targets_by_resource.get(target.resource_id, 0) + 1
    return [
        {
            "resource_id": resource.id,
            "name": resource.name,
            "state": resource.state.value,
            "health": health_by_resource.get(resource.id).latest_status.value if resource.id in health_by_resource else "unknown",
            "targets": targets_by_resource.get(resource.id, 0),
            "dependencies": len(resource.dependencies),
            "admin_plans": len([plan for plan in plans if plan.target == resource.id or resource.id in plan.current_state]),
            "executions": len(executions),
        }
        for resource in resources
        if resource.type in {ResourceType.SERVICE, ResourceType.MAINTENANCE_TARGET, ResourceType.USAGE_LIMITED_SERVICE}
    ]


def _service_action_rows(resources: Sequence[Any], plans: Sequence[Any]) -> list[dict[str, object]]:
    service_resources = [resource for resource in resources if resource.type in {ResourceType.SERVICE, ResourceType.MAINTENANCE_TARGET}]
    actions = ("start", "stop", "restart", "reload", "enable", "disable")
    return [
        {
            "resource_id": resource.id,
            "action": action,
            "status": "stage_admin_plan",
            "approval": "policy",
            "existing_plans": len([plan for plan in plans if resource.id in {plan.target, plan.current_state}]),
        }
        for resource in service_resources
        for action in actions
    ]


def _log_evidence_rows(targets: Sequence[Any], evidence: Sequence[Any]) -> list[dict[str, object]]:
    latest_by_target = {(item.resource_id, item.target): item for item in sorted(evidence, key=lambda item: item.captured_at or item.id)}
    return [
        {
            "target_id": target.id,
            "resource_id": target.resource_id,
            "kind": target.probe_type.value,
            "redacted_target": _redact_path(target.target),
            "latest_evidence": latest_by_target.get((target.resource_id, target.target)).id
            if (target.resource_id, target.target) in latest_by_target
            else "",
            "status": latest_by_target.get((target.resource_id, target.target)).observed_status.value
            if (target.resource_id, target.target) in latest_by_target
            else "missing",
        }
        for target in targets
        if target.probe_type == ProbeType.LOG or "log" in target.target.lower()
    ]


def _security_drift_rows(latest_snapshot: Any | None, plans: Sequence[Any], audits: Sequence[Any]) -> list[dict[str, object]]:
    rows = [
        {"check": "host snapshot", "status": "present" if latest_snapshot else "missing", "evidence": latest_snapshot.id if latest_snapshot else "", "next_step": "inspect host security posture"},
        {"check": "firewall preview", "status": "partial" if latest_snapshot else "missing", "evidence": "host inspection observations", "next_step": "add ruleset diff and provenance"},
        {"check": "protective plans", "status": "present" if any(plan.owner_domain == OwnerDomain.ODO for plan in plans) else "missing", "evidence": "admin plans", "next_step": "stage Odo remediation plans"},
        {"check": "security alerts", "status": "present" if any(event.event_type == AuditEventType.ALERT for event in audits) else "quiet", "evidence": "audit events", "next_step": "review incidents"},
    ]
    return rows


def _physical_lifecycle_rows(identities: Sequence[Any], claims: Sequence[Any]) -> list[dict[str, object]]:
    return [
        {
            "stable_id": identity.stable_id,
            "kind": identity.kind.value,
            "checkout_ready": identity.is_complete_for_exclusive_checkout(),
            "power_risk": identity.has_power_risk(),
            "storage_risk": identity.has_storage_risk(),
            "active_claims": len([claim for claim in claims if claim.resource_id == identity.stable_id and claim.is_active_like()]),
            "next_step": "add identity history, firmware state, and maintenance log",
        }
        for identity in identities
    ]


def _virtual_runtime_rows(resources: Sequence[Any], claims: Sequence[Any]) -> list[dict[str, object]]:
    return [
        {
            "resource_id": resource.id,
            "kind": resource.identifiers.get("kind", "unknown"),
            "state": resource.state.value,
            "ports": sorted(resource.ports()),
            "active_claims": len([claim for claim in claims if claim.resource_id == resource.id and claim.is_active_like()]),
            "cleanup_candidates": len([claim for claim in claims if claim.resource_id == resource.id and claim.status in {ClaimStatus.EXPIRED, ClaimStatus.RELEASING}]),
            "next_step": "add VM/container/emulator runtime adapter and snapshot workflow",
        }
        for resource in resources
        if resource.type == ResourceType.VIRTUAL_ASSET
    ]


def _observability_rows(health: Sequence[Any], evidence: Sequence[Any]) -> list[dict[str, object]]:
    return [
        {
            "resource_id": item.resource_id,
            "status": item.latest_status.value,
            "recovery_required": item.recovery_required,
            "evidence": item.latest_evidence_id,
            "error": item.error,
            "history_records": len([record for record in evidence if record.resource_id == item.resource_id]),
        }
        for item in health
    ]


def _usage_cost_rows(limits: Sequence[Any], requests: Sequence[Any]) -> list[dict[str, object]]:
    return [
        {
            "limit_id": limit.id,
            "resource_id": limit.resource_id,
            "remaining": limit.remaining,
            "capacity": limit.capacity,
            "resets_at": limit.resets_at,
            "queued_requests": len([request for request in requests if request.limit_id == limit.id]),
            "cost_tracking": "not_configured",
            "forecast": "add exhaustion forecast from history",
        }
        for limit in limits
    ]


def _compliance_rows(approvals: Sequence[Any], plans: Sequence[Any], audits: Sequence[Any]) -> list[dict[str, object]]:
    pending = [approval for approval in approvals if approval.status == ApprovalStatus.PENDING]
    warnings = [approval for approval in approvals if "policy.warning" in approval.subject_id]
    return [
        {"area": "approval policy", "status": "attention" if pending else "ok", "evidence": len(pending), "next_step": "review pending approvals"},
        {"area": "policy warning exceptions", "status": "attention" if warnings else "ok", "evidence": len(warnings), "next_step": "review accepted-risk expiry"},
        {"area": "desired state drift", "status": "gap", "evidence": 0, "next_step": "add desired-state baselines"},
        {"area": "post-change validation", "status": "partial", "evidence": sum(1 for plan in plans if plan.verification_steps), "next_step": "link verification checklist to every execution"},
        {"area": "audit evidence", "status": "present", "evidence": len(audits), "next_step": "add compliance matrix"},
    ]


def _run_read_only(command: Sequence[str], timeout_seconds: float) -> dict[str, object]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout_seconds)
    except FileNotFoundError:
        return {"command": list(command), "exit_code": 127, "stdout": "", "stderr": "command not found"}
    except subprocess.TimeoutExpired:
        return {"command": list(command), "exit_code": 124, "stdout": "", "stderr": "command timed out"}
    return {
        "command": list(command),
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _parse_meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in _read_text("/proc/meminfo").splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        number = rest.strip().split()[0] if rest.strip() else "0"
        try:
            values[key] = int(number)
        except ValueError:
            values[key] = 0
    return values


def _root_usage_row() -> dict[str, object]:
    usage = shutil.disk_usage("/")
    return {"mount": "/", "total_gb": _bytes_to_gb(usage.total), "used_gb": _bytes_to_gb(usage.used), "free_gb": _bytes_to_gb(usage.free)}


def _line_count(text: str) -> int:
    return len([line for line in text.splitlines() if line.strip()])


def _kb_to_mb(value: int | None) -> int:
    return int((value or 0) / 1024)


def _bytes_to_gb(value: int) -> int:
    return int(value / (1024 * 1024 * 1024))


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _redact_path(value: str) -> str:
    if not value.startswith("/"):
        return value
    path = Path(value)
    return f".../{path.name}" if path.name else "local-path"
