"""Command-line entry point for local Overseer prototypes."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .admin import (
    AdminChangeKind,
    AdminChangePlan,
    AdminCommandResult,
    AdminExecutionResult,
    AdminExecutionStatus,
    approve_admin_change_plan,
    audit_event_from_admin_execution,
    authorization_required_status,
    cancel_admin_change_plan,
    execute_admin_change_plan,
    missing_admin_change_fields,
    plan_apt_install,
    plan_block_ip,
    plan_firewall_allow_tcp,
    plan_user_service_restart,
)
from .config import load_config, seed_store_from_config
from .core import ApprovalLevel, Claim, ClaimType, OwnerDomain, Resource, ResourceType, RiskLevel
from .core import ClaimStatus, ResourceState
from .audit import ApprovalStatus, AuditEvent, AuditEventType
from .health import HealthStatus, HealthTarget, ProbeType, summarize_health_targets
from .host import HostInspectionAdapter, host_security_status, host_snapshot_status
from .live_health import HttpHealthProbeAdapter
from .physical import PhysicalAssetKind, PhysicalIdentity
from .physical_discovery import PathPhysicalDiscoveryAdapter
from .registry import ResourceRegistry
from .runtime import OverseerRuntime
from .runtime_state import (
    DEFAULT_HOST_INSPECTION_FRESHNESS_POLICY,
    DEFAULT_RUNTIME_FRESHNESS_POLICY,
    FreshnessAssessment,
    FreshnessStatus,
    assess_freshness,
)
from .service import OverseerCoordinator, coordinator_from_store
from .store import SQLiteStore
from .usage_limits import LimitKind, UsageLimit


def build_demo_registry() -> ResourceRegistry:
    registry = ResourceRegistry()
    registry.register_resource(
        Resource(
            id="gateway.protected",
            name="Protected Gateway",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.HIGH,
            identifiers={"ports": [8795]},
        )
    )
    return registry


def demo_status() -> dict[str, object]:
    registry = build_demo_registry()
    record = registry.request_claim(
        Claim(
            id="claim.demo.gateway",
            resource_id="gateway.protected",
            claim_type=ClaimType.LEASE,
            owner_thread="demo-thread",
            owner_role=OwnerDomain.DAX,
            intent="demonstrate protected gateway checkout",
            requested_action="lease protected gateway",
            risk_level=RiskLevel.HIGH,
            port_reservations=frozenset({8795}),
        )
    )
    return {
        "resources": [resource.id for resource in registry.list_resources()],
        "claim": record.claim.id,
        "claim_status": record.claim.status.value,
        "decision": record.decision.outcome.value,
        "approval": record.decision.approval_level.value,
        "reason": record.decision.reason,
    }


def persisted_demo_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        coordinator = OverseerCoordinator(store=store)
        resource = coordinator.register_resource(
            Resource(
                id="gateway.protected",
                name="Protected Gateway",
                type=ResourceType.VIRTUAL_ASSET,
                owner_domain=OwnerDomain.DAX,
                risk_level=RiskLevel.HIGH,
                identifiers={"ports": [8795]},
            )
        )
        result = coordinator.request_claim(
            Claim(
                id="claim.demo.gateway",
                resource_id=resource.id,
                claim_type=ClaimType.LEASE,
                owner_thread="demo-thread",
                owner_role=OwnerDomain.DAX,
                intent="demonstrate protected gateway checkout",
                requested_action="lease protected gateway",
                risk_level=RiskLevel.HIGH,
                port_reservations=frozenset({8795}),
            )
        )
        return {
            "store": str(store.path),
            "resources": [resource.id for resource in coordinator.registry.list_resources()],
            "claim": result.record.claim.id,
            "claim_status": result.record.claim.status.value,
            "decision": result.record.decision.outcome.value,
            "approval": result.record.decision.approval_level.value,
            "approval_id": result.approval.id if result.approval else None,
            "audit_event": result.audit_event.id,
        }
    finally:
        store.close()


def seed_config_status(config_path: str | Path, store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        result = seed_store_from_config(load_config(config_path), store)
        return {
            "store": result.store_path,
            "resources": result.resource_count,
            "usage_limits": result.usage_limit_count,
            "health_targets": result.health_target_count,
        }
    finally:
        store.close()


def probe_health_status(
    resource_id: str,
    name: str,
    url: str,
    probe_type: str,
    expected_status: int | None = None,
    expected_content_type: str | None = None,
    timeout_seconds: float = 5.0,
    store_path: str | Path | None = None,
) -> dict[str, object]:
    target = HealthTarget(
        id=resource_id.replace(".", "-"),
        resource_id=resource_id,
        name=name,
        probe_type=ProbeType(probe_type),
        target=url,
        expected_status=expected_status,
        expected_content_type=expected_content_type,
    )
    evidence = HttpHealthProbeAdapter(timeout_seconds=timeout_seconds).probe(target)
    if store_path is not None:
        store = SQLiteStore(store_path)
        try:
            store.save_health_evidence(evidence)
        finally:
            store.close()
    status = {
        "id": evidence.id,
        "resource_id": evidence.resource_id,
        "target": evidence.target,
        "probe_type": evidence.probe_type.value,
        "status": evidence.observed_status.value,
        "owner_domain": evidence.owner_domain.value,
        "recovery_required": evidence.recovery_required,
        "error": evidence.observed_error,
    }
    if store_path is not None:
        status["store"] = str(Path(store_path))
    return status


def probe_config_status(
    config_path: str | Path,
    store_path: str | Path | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, object]:
    config = load_config(config_path)
    adapter = HttpHealthProbeAdapter(timeout_seconds=timeout_seconds)
    evidence_items = [adapter.probe(target) for target in config.health_targets]
    if store_path is not None:
        store = SQLiteStore(store_path)
        try:
            for evidence in evidence_items:
                store.save_health_evidence(evidence)
        finally:
            store.close()
    status = {
        "config": str(Path(config_path)),
        "targets": len(config.health_targets),
        "healthy": sum(1 for evidence in evidence_items if evidence.observed_status.value == "healthy"),
        "evidence": [
            {
                "id": evidence.id,
                "resource_id": evidence.resource_id,
                "target": evidence.target,
                "status": evidence.observed_status.value,
                "recovery_required": evidence.recovery_required,
                "error": evidence.observed_error,
            }
            for evidence in evidence_items
        ],
    }
    if store_path is not None:
        status["store"] = str(Path(store_path))
    return status


def discover_physical_status(roots: Sequence[str], store_path: str | Path | None = None) -> dict[str, object]:
    identities = PathPhysicalDiscoveryAdapter(tuple(roots)).discover()
    if store_path is not None:
        store = SQLiteStore(store_path)
        try:
            for identity in identities:
                store.save_physical_identity(identity)
        finally:
            store.close()
    status = {
        "count": len(identities),
        "assets": [
            {
                "stable_id": identity.stable_id,
                "kind": identity.kind.value,
                "observed_paths": sorted(identity.observed_paths),
                "complete_for_checkout": identity.is_complete_for_exclusive_checkout(),
            }
            for identity in identities
        ],
    }
    if store_path is not None:
        status["store"] = str(Path(store_path))
    return status


def physical_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        identities = store.list_physical_identities()
        return {
            "store": str(store.path),
            "assets": len(identities),
            "complete_for_checkout": sum(1 for identity in identities if identity.is_complete_for_exclusive_checkout()),
            "incomplete_for_checkout": sum(1 for identity in identities if not identity.is_complete_for_exclusive_checkout()),
            "power_risk": sum(1 for identity in identities if identity.has_power_risk()),
            "storage_risk": sum(1 for identity in identities if identity.has_storage_risk()),
            "assets_by_kind": {
                kind.value: sum(1 for identity in identities if identity.kind == kind)
                for kind in PhysicalAssetKind
            },
            "items": [physical_identity_status(identity) for identity in identities],
        }
    finally:
        store.close()


def physical_identity_status(identity: PhysicalIdentity) -> dict[str, object]:
    return {
        "stable_id": identity.stable_id,
        "kind": PhysicalAssetKind(identity.kind).value,
        "observed_paths": sorted(identity.observed_paths),
        "vendor_id": identity.vendor_id,
        "product_id": identity.product_id,
        "serial_number": identity.serial_number,
        "capabilities": sorted(identity.capabilities),
        "power_profile": identity.power_profile,
        "storage_profile": identity.storage_profile,
        "exclusive_groups": sorted(identity.exclusive_groups),
        "depends_on": sorted(identity.depends_on),
        "complete_for_checkout": identity.is_complete_for_exclusive_checkout(),
        "power_risk": identity.has_power_risk(),
        "storage_risk": identity.has_storage_risk(),
    }


VIRTUAL_ASSET_KINDS = (
    "emulator",
    "vm",
    "gateway",
    "proxy",
    "network_segment",
    "composite_topology",
    "unknown",
)


def virtual_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        resources = [resource for resource in store.list_resources() if resource.type == ResourceType.VIRTUAL_ASSET]
        claims = store.list_claims()
        virtual_resource_ids = {resource.id for resource in resources}
        active_claims = [
            claim
            for claim in claims
            if claim.resource_id in virtual_resource_ids and claim.is_active_like()
        ]
        queued_claims = [
            claim
            for claim in claims
            if claim.resource_id in virtual_resource_ids and claim.status == ClaimStatus.QUEUED
        ]
        return {
            "store": str(store.path),
            "assets": len(resources),
            "ready_for_checkout": sum(1 for resource in resources if virtual_resource_ready_for_checkout(resource, active_claims)),
            "checked_out_or_reserved": sum(1 for resource in resources if not virtual_resource_ready_for_checkout(resource, active_claims)),
            "active_claims": len(active_claims),
            "queued_claims": len(queued_claims),
            "reserved_ports": sorted({port for claim in active_claims for port in claim.port_reservations}),
            "assets_by_kind": {
                kind: sum(1 for resource in resources if virtual_resource_kind(resource) == kind)
                for kind in VIRTUAL_ASSET_KINDS
            },
            "assets_by_state": {
                state.value: sum(1 for resource in resources if resource.state == state)
                for state in ResourceState
            },
            "assets_by_risk": {
                risk.value: sum(1 for resource in resources if resource.risk_level == risk)
                for risk in RiskLevel
            },
            "items": [virtual_resource_status(resource, claims) for resource in resources],
        }
    finally:
        store.close()


def virtual_resource_kind(resource: Resource) -> str:
    kind = resource.identifiers.get("kind", "unknown")
    return str(kind) if str(kind) in VIRTUAL_ASSET_KINDS else "unknown"


def virtual_resource_ready_for_checkout(resource: Resource, active_claims: Sequence[Claim]) -> bool:
    if resource.state != ResourceState.AVAILABLE:
        return False
    return not any(claim.resource_id == resource.id for claim in active_claims)


def virtual_resource_status(resource: Resource, claims: Sequence[Claim]) -> dict[str, object]:
    resource_claims = [claim for claim in claims if claim.resource_id == resource.id]
    active_claims = [claim for claim in resource_claims if claim.is_active_like()]
    queued_claims = [claim for claim in resource_claims if claim.status == ClaimStatus.QUEUED]
    return {
        "id": resource.id,
        "name": resource.name,
        "kind": virtual_resource_kind(resource),
        "owner_domain": OwnerDomain(resource.owner_domain).value,
        "risk_level": RiskLevel(resource.risk_level).value,
        "state": ResourceState(resource.state).value,
        "host": resource.identifiers.get("host"),
        "ports": sorted(resource.ports()),
        "networks": _sorted_identifier_values(resource, "networks"),
        "state_path": resource.identifiers.get("state_path"),
        "process_hint": resource.identifiers.get("process_hint"),
        "config_paths": _sorted_identifier_values(resource, "config_paths"),
        "dependencies": sorted(resource.dependencies),
        "exclusive_groups": sorted(resource.exclusive_groups),
        "current_claim_id": resource.current_claim_id,
        "active_claim_ids": [claim.id for claim in active_claims],
        "queued_claim_ids": [claim.id for claim in queued_claims],
        "ready_for_checkout": virtual_resource_ready_for_checkout(resource, active_claims),
    }


def _sorted_identifier_values(resource: Resource, key: str) -> list[object]:
    values = resource.identifiers.get(key, ())
    if isinstance(values, (list, tuple, set, frozenset)):
        return sorted(values)
    if values:
        return [values]
    return []


def command_summary_status(
    store_path: str | Path,
    service_name: str = "overseer",
    now: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        resources = store.list_resources()
        claims = store.list_claims()
        approvals = store.list_approvals()
        audit_events = store.list_audit_events()
        usage_limits = store.list_usage_limits()
        physical_identities = store.list_physical_identities()
        health_summaries = summarize_health_targets(store.list_health_targets(), store.list_health_evidence())
        admin_plans = store.list_admin_change_plans()
        heartbeats = store.list_runtime_heartbeats()
        heartbeat = next((item for item in heartbeats if item.service_name == service_name), None)
        runtime_freshness = assess_freshness(
            heartbeat.last_tick_at if heartbeat else None,
            now=now,
            policy=DEFAULT_RUNTIME_FRESHNESS_POLICY,
        )
        alerts = [event for event in audit_events if event.event_type == AuditEventType.ALERT]
        pending_approvals = [approval for approval in approvals if approval.status == ApprovalStatus.PENDING]
        pending_admin_plans = [
            plan
            for plan in admin_plans
            if plan.requires_explicit_approval() and not plan.approved and not plan.canceled
        ]
        return {
            "store": str(store.path),
            "service": {
                "service_name": service_name,
                "heartbeat_present": heartbeat is not None,
                "freshness": freshness_status(runtime_freshness),
            },
            "resources": {
                "total": len(resources),
                "by_type": {
                    resource_type.value: sum(1 for resource in resources if resource.type == resource_type)
                    for resource_type in ResourceType
                },
                "by_owner": {
                    owner.value: sum(1 for resource in resources if resource.owner_domain == owner)
                    for owner in OwnerDomain
                },
                "by_state": {
                    state.value: sum(1 for resource in resources if resource.state == state)
                    for state in ResourceState
                },
                "high_or_critical_risk": sum(
                    1 for resource in resources if resource.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
                ),
            },
            "claims": {
                "total": len(claims),
                "active_like": sum(1 for claim in claims if claim.is_active_like()),
                "queued": sum(1 for claim in claims if claim.status == ClaimStatus.QUEUED),
                "blocked": sum(1 for claim in claims if claim.status == ClaimStatus.BLOCKED),
                "pending_approvals": len(pending_approvals),
            },
            "health": {
                "targets": len(health_summaries),
                "healthy": sum(1 for summary in health_summaries if summary.latest_status == HealthStatus.HEALTHY),
                "unhealthy": sum(
                    1
                    for summary in health_summaries
                    if summary.latest_status in {HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN}
                ),
            },
            "usage_limits": {
                "total": len(usage_limits),
                "available": sum(1 for limit in usage_limits if limit.remaining > 0),
                "exhausted": sum(1 for limit in usage_limits if limit.is_exhausted()),
            },
            "physical_assets": {
                "total": len(physical_identities),
                "ready_for_checkout": sum(
                    1 for identity in physical_identities if identity.is_complete_for_exclusive_checkout()
                ),
                "power_risk": sum(1 for identity in physical_identities if identity.has_power_risk()),
                "storage_risk": sum(1 for identity in physical_identities if identity.has_storage_risk()),
            },
            "virtual_assets": {
                "total": sum(1 for resource in resources if resource.type == ResourceType.VIRTUAL_ASSET),
                "active_claims": sum(
                    1
                    for claim in claims
                    if claim.is_active_like()
                    and any(
                        resource.id == claim.resource_id and resource.type == ResourceType.VIRTUAL_ASSET
                        for resource in resources
                    )
                ),
            },
            "admin": {
                "plans": len(admin_plans),
                "pending_authorizations": len(pending_admin_plans),
            },
            "alerts": {
                "total": len(alerts),
                "high_or_critical": sum(
                    1 for event in alerts if event.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
                ),
            },
        }
    finally:
        store.close()


def maintenance_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        resources = [resource for resource in store.list_resources() if resource.type == ResourceType.MAINTENANCE_TARGET]
        plans = [
            plan
            for plan in store.list_admin_change_plans()
            if plan.owner_domain == OwnerDomain.OBRIEN or plan.kind in {AdminChangeKind.USER_SERVICE_RESTART, AdminChangeKind.APT_INSTALL}
        ]
        executions = store.list_admin_executions()
        executions_by_plan = {result.plan_id: result for result in executions}
        pending = [
            plan
            for plan in plans
            if plan.requires_explicit_approval() and not plan.approved and not plan.canceled
        ]
        return {
            "store": str(store.path),
            "targets": len(resources),
            "plans": len(plans),
            "pending_authorizations": len(pending),
            "approved_plans": sum(1 for plan in plans if plan.approved),
            "canceled_plans": sum(1 for plan in plans if plan.canceled),
            "executable_plans": sum(1 for plan in plans if plan.can_execute()),
            "executions": sum(1 for plan in plans if plan.id in executions_by_plan),
            "plans_by_kind": {
                kind.value: sum(1 for plan in plans if plan.kind == kind)
                for kind in AdminChangeKind
            },
            "plans_by_risk": {
                risk.value: sum(1 for plan in plans if plan.risk_level == risk)
                for risk in RiskLevel
            },
            "execution_by_status": {
                status.value: sum(
                    1
                    for plan in plans
                    for result in (executions_by_plan.get(plan.id),)
                    if result is not None and result.status == status
                )
                for status in AdminExecutionStatus
            },
            "targets_by_state": {
                state.value: sum(1 for resource in resources if resource.state == state)
                for state in ResourceState
            },
            "items": [maintenance_plan_status(plan, executions_by_plan.get(plan.id)) for plan in plans],
        }
    finally:
        store.close()


def maintenance_plan_status(plan: AdminChangePlan, execution: AdminExecutionResult | None = None) -> dict[str, object]:
    return {
        "id": plan.id,
        "kind": AdminChangeKind(plan.kind).value,
        "target": plan.target,
        "owner_domain": OwnerDomain(plan.owner_domain).value,
        "risk_level": RiskLevel(plan.risk_level).value,
        "approval_level": ApprovalLevel(plan.approval_level).value,
        "requires_explicit_approval": plan.requires_explicit_approval(),
        "approved": plan.approved,
        "canceled": plan.canceled,
        "can_execute": plan.can_execute(),
        "missing_fields": list(missing_admin_change_fields(plan)),
        "step_count": len(plan.steps),
        "rollback_step_count": len(plan.rollback_steps),
        "verification_step_count": len(plan.verification_steps),
        "latest_execution_id": execution.id if execution else None,
        "latest_execution_status": AdminExecutionStatus(execution.status).value if execution else None,
        "reason": plan.reason,
    }


def security_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        resources = [resource for resource in store.list_resources() if resource.type == ResourceType.SECURITY_SURFACE]
        alerts = [event for event in store.list_audit_events() if event.event_type == AuditEventType.ALERT]
        snapshots = store.list_host_snapshots()
        latest_snapshot = sorted(snapshots, key=lambda item: item.captured_at)[-1] if snapshots else None
        host_security = host_security_status(latest_snapshot) if latest_snapshot else None
        plans = [
            plan
            for plan in store.list_admin_change_plans()
            if plan.owner_domain == OwnerDomain.ODO
            or plan.kind in {AdminChangeKind.BLOCK_IP, AdminChangeKind.FIREWALL_ALLOW_TCP}
        ]
        pending = [
            plan
            for plan in plans
            if plan.requires_explicit_approval() and not plan.approved and not plan.canceled
        ]
        return {
            "store": str(store.path),
            "security_surfaces": len(resources),
            "alerts": len(alerts),
            "alerts_by_risk": {
                risk.value: sum(1 for event in alerts if event.risk_level == risk)
                for risk in RiskLevel
            },
            "alerts_by_owner": {
                owner.value: sum(1 for event in alerts if event.owner_domain == owner)
                for owner in OwnerDomain
            },
            "host_security": {
                "enabled": latest_snapshot is not None,
                "latest_snapshot_id": latest_snapshot.id if latest_snapshot else None,
                "latest_captured_at": latest_snapshot.captured_at if latest_snapshot else None,
                "high_findings": host_security["high_findings"] if host_security else 0,
                "warning_findings": host_security["warning_findings"] if host_security else 0,
            },
            "protective_plans": {
                "total": len(plans),
                "pending_authorizations": len(pending),
                "approved": sum(1 for plan in plans if plan.approved),
                "canceled": sum(1 for plan in plans if plan.canceled),
                "by_kind": {
                    kind.value: sum(1 for plan in plans if plan.kind == kind)
                    for kind in AdminChangeKind
                },
                "items": [security_plan_status(plan) for plan in plans],
            },
            "surfaces": [security_surface_status(resource) for resource in resources],
            "events": [audit_event_status(event) for event in alerts],
        }
    finally:
        store.close()


def security_plan_status(plan: AdminChangePlan) -> dict[str, object]:
    return {
        "id": plan.id,
        "kind": AdminChangeKind(plan.kind).value,
        "target": plan.target,
        "risk_level": RiskLevel(plan.risk_level).value,
        "approval_level": ApprovalLevel(plan.approval_level).value,
        "requires_explicit_approval": plan.requires_explicit_approval(),
        "approved": plan.approved,
        "canceled": plan.canceled,
        "can_execute": plan.can_execute(),
        "reason": plan.reason,
    }


def security_surface_status(resource: Resource) -> dict[str, object]:
    return {
        "id": resource.id,
        "name": resource.name,
        "owner_domain": OwnerDomain(resource.owner_domain).value,
        "risk_level": RiskLevel(resource.risk_level).value,
        "state": ResourceState(resource.state).value,
        "dependencies": sorted(resource.dependencies),
        "exclusive_groups": sorted(resource.exclusive_groups),
        "current_claim_id": resource.current_claim_id,
    }


def health_efficiency_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        targets = store.list_health_targets()
        evidence = store.list_health_evidence()
        summaries = summarize_health_targets(targets, evidence)
        unhealthy_statuses = {HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN}
        latest_failures = [summary for summary in summaries if summary.latest_status in unhealthy_statuses]
        return {
            "store": str(store.path),
            "targets": len(summaries),
            "evidence_records": len(evidence),
            "healthy": sum(1 for summary in summaries if summary.latest_status == HealthStatus.HEALTHY),
            "unhealthy": len(latest_failures),
            "recovered": sum(1 for summary in summaries if summary.latest_status == HealthStatus.RECOVERED),
            "missing_evidence": sum(1 for summary in summaries if summary.latest_evidence_id is None),
            "recovery_required": sum(1 for summary in summaries if summary.recovery_required),
            "by_status": {
                status.value: sum(1 for summary in summaries if summary.latest_status == status)
                for status in HealthStatus
            },
            "by_probe_type": {
                probe_type.value: sum(1 for target in targets if target.probe_type == probe_type)
                for probe_type in ProbeType
            },
            "by_owner": {
                owner.value: sum(1 for summary in summaries if summary.owner_domain == owner)
                for owner in OwnerDomain
            },
            "errors_by_probe_type": {
                probe_type.value: sum(
                    1
                    for summary in latest_failures
                    if any(
                        target.id == summary.target_id and target.probe_type == probe_type
                        for target in targets
                    )
                )
                for probe_type in ProbeType
            },
            "latest_failures": [health_failure_status(summary) for summary in latest_failures],
        }
    finally:
        store.close()


def health_failure_status(summary) -> dict[str, object]:
    return {
        "target_id": summary.target_id,
        "resource_id": summary.resource_id,
        "name": summary.name,
        "target": summary.target,
        "status": HealthStatus(summary.latest_status).value,
        "owner_domain": OwnerDomain(summary.owner_domain).value,
        "latest_evidence_id": summary.latest_evidence_id,
        "latest_captured_at": summary.latest_captured_at,
        "recovery_required": summary.recovery_required,
        "error": summary.error,
    }


def operator_dashboard_status(store_path: str | Path, service_name: str = "overseer") -> dict[str, object]:
    command = command_summary_status(store_path, service_name)
    physical = physical_summary_status(store_path)
    virtual = virtual_summary_status(store_path)
    maintenance = maintenance_summary_status(store_path)
    security = security_summary_status(store_path)
    usage = usage_summary_status(store_path)
    health = health_summary_status(store_path)
    health_efficiency = health_efficiency_summary_status(store_path)
    attention = operator_dashboard_attention(command, physical, virtual, maintenance, security, usage, health_efficiency)
    return {
        "store": command["store"],
        "service_name": service_name,
        "overall_status": operator_dashboard_overall_status(attention),
        "attention": attention,
        "role_focus": {
            "sisko": {
                "pending_authorizations": attention["pending_authorizations"],
                "queued_claims": attention["queued_claims"],
                "blocked_claims": attention["blocked_claims"],
                "service_freshness": attention["service_freshness"],
            },
            "kira": {
                "assets": physical["assets"],
                "power_risk": attention["physical_power_risk"],
                "storage_risk": attention["physical_storage_risk"],
            },
            "obrien": {
                "plans": maintenance["plans"],
                "pending_authorizations": attention["maintenance_pending_authorizations"],
                "executable_plans": maintenance["executable_plans"],
            },
            "odo": {
                "alerts": attention["security_alerts"],
                "high_findings": attention["high_security_findings"],
                "pending_protective_authorizations": attention["security_pending_authorizations"],
            },
            "quark": {
                "limits": usage["limits"],
                "exhausted": attention["exhausted_usage_limits"],
                "next_reset_at": usage["next_reset_at"],
            },
            "dax": {
                "assets": virtual["assets"],
                "active_claims": attention["virtual_active_claims"],
                "queued_claims": attention["virtual_queued_claims"],
            },
            "julian": {
                "targets": health_efficiency["targets"],
                "unhealthy": attention["unhealthy_health_targets"],
                "recovery_required": attention["recovery_required"],
                "latest_failures": attention["latest_failures"],
            },
        },
        "summaries": {
            "command": command,
            "physical": physical,
            "virtual": virtual,
            "maintenance": maintenance,
            "security": security,
            "usage": usage,
            "health": health,
            "health_efficiency": health_efficiency,
        },
    }


def operator_dashboard_attention(
    command: dict[str, object],
    physical: dict[str, object],
    virtual: dict[str, object],
    maintenance: dict[str, object],
    security: dict[str, object],
    usage: dict[str, object],
    health_efficiency: dict[str, object],
) -> dict[str, object]:
    service = command["service"]
    claims = command["claims"]
    admin = command["admin"]
    freshness = service["freshness"]
    protective_plans = security["protective_plans"]
    host_security = security["host_security"]
    return {
        "service_freshness": freshness["status"],
        "pending_authorizations": admin["pending_authorizations"],
        "pending_claim_approvals": claims["pending_approvals"],
        "queued_claims": claims["queued"],
        "blocked_claims": claims["blocked"],
        "unhealthy_health_targets": health_efficiency["unhealthy"],
        "recovery_required": health_efficiency["recovery_required"],
        "latest_failures": len(health_efficiency["latest_failures"]),
        "exhausted_usage_limits": usage["exhausted"],
        "low_confidence_usage_limits": usage["low_confidence"],
        "physical_power_risk": physical["power_risk"],
        "physical_storage_risk": physical["storage_risk"],
        "virtual_active_claims": virtual["active_claims"],
        "virtual_queued_claims": virtual["queued_claims"],
        "maintenance_pending_authorizations": maintenance["pending_authorizations"],
        "security_alerts": security["alerts"],
        "security_pending_authorizations": protective_plans["pending_authorizations"],
        "high_security_findings": host_security["high_findings"],
        "warning_security_findings": host_security["warning_findings"],
    }


def operator_dashboard_overall_status(attention: dict[str, object]) -> str:
    high_keys = (
        "pending_authorizations",
        "blocked_claims",
        "unhealthy_health_targets",
        "recovery_required",
        "security_alerts",
        "security_pending_authorizations",
        "high_security_findings",
    )
    warning_keys = (
        "pending_claim_approvals",
        "queued_claims",
        "exhausted_usage_limits",
        "low_confidence_usage_limits",
        "physical_power_risk",
        "physical_storage_risk",
        "virtual_queued_claims",
        "maintenance_pending_authorizations",
        "warning_security_findings",
    )
    if attention["service_freshness"] in {FreshnessStatus.HIGH.value, FreshnessStatus.MISSING.value}:
        return "attention_required"
    if any(attention[key] for key in high_keys):
        return "attention_required"
    if attention["service_freshness"] == FreshnessStatus.WARNING.value:
        return "warning"
    if any(attention[key] for key in warning_keys):
        return "warning"
    return "nominal"


def run_status(
    store_path: str | Path,
    once: bool,
    interval_seconds: float = 30.0,
    probe_health_targets: bool = False,
    health_probe_timeout_seconds: float = 5.0,
    health_evidence_retention_per_target: int = 5,
    inspect_host: bool = False,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        tick = OverseerRuntime(
            store,
            probe_health_targets=probe_health_targets,
            health_probe_adapter=HttpHealthProbeAdapter(timeout_seconds=health_probe_timeout_seconds),
            health_evidence_retention_per_target=health_evidence_retention_per_target,
            inspect_host=inspect_host,
        ).run(interval_seconds=interval_seconds, once=once)
        return {
            "store": str(store.path),
            "resources": tick.resources,
            "usage_limits": tick.usage_limits,
            "health_targets": tick.health_targets,
            "audit_events": tick.audit_events,
            "health_evidence": tick.health_evidence,
            "physical_identities": tick.physical_identities,
            "runtime_heartbeats": tick.runtime_heartbeats,
            "health_probes": tick.health_probes,
            "host_inspections": tick.host_inspections,
            "host_security_high_findings": tick.host_security_high_findings,
            "host_security_warning_findings": tick.host_security_warning_findings,
        }
    finally:
        store.close()


def service_status(store_path: str | Path, service_name: str = "overseer") -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        heartbeat = store.load_runtime_heartbeat(service_name)
        return {
            "store": str(store.path),
            "service_name": heartbeat.service_name,
            "started_at": heartbeat.started_at,
            "last_tick_at": heartbeat.last_tick_at,
            "tick_count": heartbeat.tick_count,
        }
    finally:
        store.close()


def runtime_status(store_path: str | Path, service_name: str = "overseer", now: str | None = None) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        heartbeat = store.load_runtime_heartbeat(service_name)
        snapshots = store.list_host_snapshots()
        latest_snapshot = sorted(snapshots, key=lambda item: item.captured_at)[-1] if snapshots else None
        host_security = host_security_status(latest_snapshot) if latest_snapshot else None
        heartbeat_freshness = assess_freshness(
            heartbeat.last_tick_at,
            now=now,
            policy=DEFAULT_RUNTIME_FRESHNESS_POLICY,
        )
        host_freshness = assess_freshness(
            latest_snapshot.captured_at if latest_snapshot else None,
            now=now,
            policy=DEFAULT_HOST_INSPECTION_FRESHNESS_POLICY,
        )
        freshness_alerts = (
            freshness_alert_event("runtime.heartbeat", OwnerDomain.JULIAN, heartbeat_freshness),
            freshness_alert_event("host.inspection", OwnerDomain.ODO, host_freshness),
        )
        persisted_alert_ids = []
        for alert in freshness_alerts:
            if alert is None:
                continue
            store.save_audit_event(alert)
            persisted_alert_ids.append(alert.id)
        return {
            "store": str(store.path),
            "service": {
                "service_name": heartbeat.service_name,
                "started_at": heartbeat.started_at,
                "last_tick_at": heartbeat.last_tick_at,
                "tick_count": heartbeat.tick_count,
                "freshness": freshness_status(heartbeat_freshness),
            },
            "host_inspection": {
                "enabled": latest_snapshot is not None,
                "latest_snapshot_id": latest_snapshot.id if latest_snapshot else None,
                "latest_captured_at": latest_snapshot.captured_at if latest_snapshot else None,
                "hostname": latest_snapshot.hostname if latest_snapshot else None,
                "high_findings": host_security["high_findings"] if host_security else 0,
                "warning_findings": host_security["warning_findings"] if host_security else 0,
                "freshness": freshness_status(host_freshness),
            },
            "freshness_alerts": persisted_alert_ids,
        }
    finally:
        store.close()


def freshness_status(assessment: FreshnessAssessment) -> dict[str, object]:
    return {
        "status": assessment.status.value,
        "observed_at": assessment.observed_at,
        "age_seconds": assessment.age_seconds,
        "warning_after_seconds": assessment.warning_after_seconds,
        "high_after_seconds": assessment.high_after_seconds,
        "summary": assessment.summary,
    }


def freshness_alert_event(subject_id: str, owner_domain: OwnerDomain, assessment: FreshnessAssessment) -> AuditEvent | None:
    if assessment.status == FreshnessStatus.OK:
        return None
    risk_level = RiskLevel.MEDIUM if assessment.status == FreshnessStatus.WARNING else RiskLevel.HIGH
    observed = assessment.observed_at or "missing"
    return AuditEvent(
        id=f"freshness.{subject_id}.{assessment.status.value}.{_status_id(observed)}",
        event_type=AuditEventType.ALERT,
        owner_domain=owner_domain,
        subject_id=subject_id,
        summary=f"{subject_id} freshness is {assessment.status.value}: {assessment.summary}",
        risk_level=risk_level,
        evidence_ids=(observed,),
        occurred_at=observed if assessment.observed_at else None,
    )


def inspect_host_status(store_path: str | Path | None = None) -> dict[str, object]:
    snapshot = HostInspectionAdapter().inspect()
    status = host_snapshot_status(snapshot)
    if store_path is None:
        return status
    store = SQLiteStore(store_path)
    try:
        store.save_host_snapshot(snapshot)
        return {"store": str(store.path), **status}
    finally:
        store.close()


def assess_host_security_status(store_path: str | Path, snapshot_id: str | None = None) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        if snapshot_id is not None:
            snapshot = store.load_host_snapshot(snapshot_id)
        else:
            snapshots = store.list_host_snapshots()
            if not snapshots:
                raise ValueError("no host snapshots are available")
            snapshot = sorted(snapshots, key=lambda item: item.captured_at)[-1]
        return {"store": str(store.path), **host_security_status(snapshot)}
    finally:
        store.close()


def admin_change_plan_status(plan: AdminChangePlan) -> dict[str, object]:
    return {
        "id": plan.id,
        "kind": AdminChangeKind(plan.kind).value,
        "owner_domain": OwnerDomain(plan.owner_domain).value,
        "risk_level": RiskLevel(plan.risk_level).value,
        "approval_level": ApprovalLevel(plan.approval_level).value,
        "target": plan.target,
        "reason": plan.reason,
        "current_state": plan.current_state,
        "proposed_state": plan.proposed_state,
        "requires_explicit_approval": plan.requires_explicit_approval(),
        "approved": plan.approved,
        "approved_by": plan.approved_by,
        "approved_at": plan.approved_at,
        "canceled": plan.canceled,
        "canceled_by": plan.canceled_by,
        "canceled_at": plan.canceled_at,
        "cancellation_reason": plan.cancellation_reason,
        "can_execute": plan.can_execute(),
        "missing_fields": list(missing_admin_change_fields(plan)),
        "steps": [_admin_command_status(step) for step in plan.steps],
        "rollback_steps": [_admin_command_status(step) for step in plan.rollback_steps],
        "verification_steps": [_admin_command_status(step) for step in plan.verification_steps],
        "risks": list(plan.risks),
    }


def admin_execution_status(result: AdminExecutionResult) -> dict[str, object]:
    return {
        "id": result.id,
        "plan_id": result.plan_id,
        "status": AdminExecutionStatus(result.status).value,
        "summary": result.summary,
        "command_results": [_admin_command_result_status(item) for item in result.command_results],
        "verification_results": [_admin_command_result_status(item) for item in result.verification_results],
    }


def plan_admin_change_status(
    store_path: str | Path | None,
    plan_id: str,
    kind: str,
    target: str,
    reason: str,
    current_state: str,
    packages: Sequence[str] = (),
    port: int | None = None,
) -> dict[str, object]:
    plan_kind = AdminChangeKind(kind)
    if plan_kind == AdminChangeKind.USER_SERVICE_RESTART:
        plan = plan_user_service_restart(plan_id, target, reason, current_state)
    elif plan_kind == AdminChangeKind.APT_INSTALL:
        plan = plan_apt_install(plan_id, tuple(packages or (target,)), reason, current_state)
    elif plan_kind == AdminChangeKind.FIREWALL_ALLOW_TCP:
        if port is None:
            raise ValueError("port is required for firewall_allow_tcp")
        plan = plan_firewall_allow_tcp(plan_id, port, reason, current_state)
    elif plan_kind == AdminChangeKind.BLOCK_IP:
        plan = plan_block_ip(plan_id, target, reason, current_state)
    else:
        raise ValueError(f"unsupported admin change kind: {kind}")
    status = admin_change_plan_status(plan)
    if store_path is None:
        return status
    store = SQLiteStore(store_path)
    try:
        store.save_admin_change_plan(plan)
        return {"store": str(store.path), **status}
    finally:
        store.close()


def execute_admin_change_status(store_path: str | Path, plan_id: str) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        result = execute_admin_change_plan(plan)
        store.save_admin_execution(result)
        store.save_audit_event(audit_event_from_admin_execution(plan, result))
        return {"store": str(store.path), **admin_execution_status(result)}
    finally:
        store.close()


def admin_executions_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        executions = store.list_admin_executions()
        return {
            "store": str(store.path),
            "executions": [admin_execution_status(result) for result in executions],
            "execution_count": len(executions),
        }
    finally:
        store.close()


def admin_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plans = store.list_admin_change_plans()
        executions = store.list_admin_executions()
        audit_events = [
            event
            for event in store.list_audit_events()
            if event.subject_id.startswith("admin.") or event.id.startswith("audit.admin.exec.")
        ]
        pending = [
            plan
            for plan in plans
            if plan.requires_explicit_approval() and not plan.approved and not plan.canceled
        ]
        return {
            "store": str(store.path),
            "plans": len(plans),
            "pending_authorizations": len(pending),
            "approved_plans": sum(1 for plan in plans if plan.approved),
            "canceled_plans": sum(1 for plan in plans if plan.canceled),
            "executable_plans": sum(1 for plan in plans if plan.can_execute()),
            "executions": len(executions),
            "executions_by_status": {
                status.value: sum(1 for result in executions if result.status == status)
                for status in AdminExecutionStatus
            },
            "latest_audit_events": [audit_event_status(event) for event in audit_events[-5:]],
            "pending": [admin_change_plan_status(plan) for plan in pending],
        }
    finally:
        store.close()


def approve_admin_change_status(
    store_path: str | Path,
    plan_id: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        approved = approve_admin_change_plan(plan, approved_by, approved_at)
        store.save_admin_change_plan(approved)
        return {"store": str(store.path), **admin_change_plan_status(approved)}
    finally:
        store.close()


def cancel_admin_change_status(
    store_path: str | Path,
    plan_id: str,
    canceled_by: str,
    cancellation_reason: str,
    canceled_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        canceled = cancel_admin_change_plan(plan, canceled_by, cancellation_reason, canceled_at)
        store.save_admin_change_plan(canceled)
        return {"store": str(store.path), **admin_change_plan_status(canceled)}
    finally:
        store.close()


def authorizations_required_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plans = store.list_admin_change_plans()
        pending = [
            authorization_required_status(plan)
            for plan in plans
            if plan.requires_explicit_approval() and not plan.approved and not plan.canceled
        ]
        return {
            "store": str(store.path),
            "pending": pending,
            "pending_count": len(pending),
        }
    finally:
        store.close()


def _admin_command_status(step) -> dict[str, object]:
    return {
        "title": step.title,
        "command": list(step.command),
        "reason": step.reason,
    }


def _admin_command_result_status(result: AdminCommandResult) -> dict[str, object]:
    return {
        "title": result.title,
        "command": list(result.command),
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def health_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        summaries = summarize_health_targets(store.list_health_targets(), store.list_health_evidence())
        unhealthy = [
            summary
            for summary in summaries
            if summary.latest_status in {HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN}
        ]
        return {
            "store": str(store.path),
            "targets": len(summaries),
            "healthy": sum(1 for summary in summaries if summary.latest_status == HealthStatus.HEALTHY),
            "unhealthy": len(unhealthy),
            "summaries": [
                {
                    "target_id": summary.target_id,
                    "resource_id": summary.resource_id,
                    "name": summary.name,
                    "target": summary.target,
                    "status": summary.latest_status.value,
                    "owner_domain": OwnerDomain(summary.owner_domain).value,
                    "latest_evidence_id": summary.latest_evidence_id,
                    "latest_captured_at": summary.latest_captured_at,
                    "recovery_required": summary.recovery_required,
                    "error": summary.error,
                }
                for summary in summaries
            ],
        }
    finally:
        store.close()


def usage_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        limits = store.list_usage_limits()
        reset_times = sorted(limit.resets_at for limit in limits if limit.resets_at)
        return {
            "store": str(store.path),
            "limits": len(limits),
            "available": sum(1 for limit in limits if limit.remaining > 0),
            "exhausted": sum(1 for limit in limits if limit.is_exhausted()),
            "unknown_reset": sum(1 for limit in limits if not limit.resets_at),
            "low_confidence": sum(1 for limit in limits if limit.confidence < 0.5),
            "next_reset_at": reset_times[0] if reset_times else None,
            "limits_by_kind": {
                kind.value: sum(1 for limit in limits if limit.kind == kind)
                for kind in LimitKind
            },
            "items": [usage_limit_status(limit) for limit in limits],
        }
    finally:
        store.close()


def usage_limit_status(limit: UsageLimit) -> dict[str, object]:
    return {
        "id": limit.id,
        "resource_id": limit.resource_id,
        "kind": LimitKind(limit.kind).value,
        "capacity": limit.capacity,
        "remaining": limit.remaining,
        "resets_at": limit.resets_at,
        "window": limit.window,
        "observed_at": limit.observed_at,
        "confidence": limit.confidence,
        "exhausted": limit.is_exhausted(),
    }


def alerts_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        alerts = [event for event in store.list_audit_events() if event.event_type == AuditEventType.ALERT]
        return {
            "store": str(store.path),
            "alerts": len(alerts),
            "by_risk": {
                risk.value: sum(1 for event in alerts if event.risk_level == risk)
                for risk in RiskLevel
            },
            "by_owner": {
                owner.value: sum(1 for event in alerts if event.owner_domain == owner)
                for owner in OwnerDomain
            },
            "events": [audit_event_status(event) for event in alerts],
        }
    finally:
        store.close()


def audit_event_status(event: AuditEvent) -> dict[str, object]:
    return {
        "id": event.id,
        "event_type": AuditEventType(event.event_type).value,
        "subject_id": event.subject_id,
        "owner_domain": OwnerDomain(event.owner_domain).value,
        "risk_level": RiskLevel(event.risk_level).value,
        "summary": event.summary,
        "evidence_ids": list(event.evidence_ids),
        "occurred_at": event.occurred_at,
    }


def list_state_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        resources = store.list_resources()
        health_targets = store.list_health_targets()
        health_evidence = store.list_health_evidence()
        claims = store.list_claims()
        approvals = store.list_approvals()
        audit_events = store.list_audit_events()
        heartbeats = store.list_runtime_heartbeats()
        host_snapshots = store.list_host_snapshots()
        admin_change_plans = store.list_admin_change_plans()
        admin_executions = store.list_admin_executions()
        return {
            "store": str(store.path),
            "resources": [
                {
                    "id": resource.id,
                    "type": ResourceType(resource.type).value,
                    "owner_domain": OwnerDomain(resource.owner_domain).value,
                    "risk_level": RiskLevel(resource.risk_level).value,
                    "state": ResourceState(resource.state).value,
                    "current_claim_id": resource.current_claim_id,
                }
                for resource in resources
            ],
            "health_targets": [
                {
                    "id": target.id,
                    "resource_id": target.resource_id,
                    "name": target.name,
                    "probe_type": ProbeType(target.probe_type).value,
                    "target": target.target,
                    "owner_domain": OwnerDomain(target.owner_domain).value,
                }
                for target in health_targets
            ],
            "health_evidence": [
                {
                    "id": evidence.id,
                    "resource_id": evidence.resource_id,
                    "target": evidence.target,
                    "probe_type": ProbeType(evidence.probe_type).value,
                    "status": HealthStatus(evidence.observed_status).value,
                    "owner_domain": OwnerDomain(evidence.owner_domain).value,
                    "recovery_required": evidence.recovery_required,
                    "captured_at": evidence.captured_at,
                    "error": evidence.observed_error,
                }
                for evidence in health_evidence
            ],
            "claims": [
                {
                    "id": claim.id,
                    "resource_id": claim.resource_id,
                    "claim_type": ClaimType(claim.claim_type).value,
                    "owner_thread": claim.owner_thread,
                    "owner_role": OwnerDomain(claim.owner_role).value,
                    "risk_level": RiskLevel(claim.risk_level).value,
                    "status": ClaimStatus(claim.status).value,
                    "approval_id": claim.approval_id,
                }
                for claim in claims
            ],
            "approvals": [
                {
                    "id": approval.id,
                    "subject_id": approval.subject_id,
                    "approval_level": ApprovalLevel(approval.approval_level).value,
                    "status": ApprovalStatus(approval.status).value,
                    "decided_by": approval.decided_by,
                }
                for approval in approvals
            ],
            "audit_events": [
                audit_event_status(event)
                for event in audit_events
            ],
            "runtime_heartbeats": [
                {
                    "id": heartbeat.id,
                    "service_name": heartbeat.service_name,
                    "started_at": heartbeat.started_at,
                    "last_tick_at": heartbeat.last_tick_at,
                    "tick_count": heartbeat.tick_count,
                }
                for heartbeat in heartbeats
            ],
            "host_snapshots": [
                {
                    "id": snapshot.id,
                    "captured_at": snapshot.captured_at,
                    "hostname": snapshot.hostname,
                    "observation_count": len(snapshot.observations),
                }
                for snapshot in host_snapshots
            ],
            "admin_change_plans": [
                {
                    "id": plan.id,
                    "kind": AdminChangeKind(plan.kind).value,
                    "target": plan.target,
                    "risk_level": RiskLevel(plan.risk_level).value,
                    "approval_level": ApprovalLevel(plan.approval_level).value,
                    "approved": plan.approved,
                    "canceled": plan.canceled,
                    "can_execute": plan.can_execute(),
                }
                for plan in admin_change_plans
            ],
            "admin_executions": [
                {
                    "id": result.id,
                    "plan_id": result.plan_id,
                    "status": AdminExecutionStatus(result.status).value,
                    "summary": result.summary,
                }
                for result in admin_executions
            ],
        }
    finally:
        store.close()


def request_claim_status(
    store_path: str | Path,
    claim_id: str,
    resource_id: str,
    claim_type: str,
    owner_thread: str,
    owner_role: str,
    intent: str,
    requested_action: str,
    risk_level: str,
    ports: Sequence[int] = (),
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        coordinator = coordinator_from_store(store)
        result = coordinator.request_claim(
            Claim(
                id=claim_id,
                resource_id=resource_id,
                claim_type=ClaimType(claim_type),
                owner_thread=owner_thread,
                owner_role=OwnerDomain(owner_role),
                intent=intent,
                requested_action=requested_action,
                risk_level=RiskLevel(risk_level),
                port_reservations=frozenset(ports),
            )
        )
        return {
            "store": str(store.path),
            "claim": result.record.claim.id,
            "claim_status": result.record.claim.status.value,
            "decision": result.record.decision.outcome.value,
            "approval": result.record.decision.approval_level.value,
            "approval_id": result.approval.id if result.approval else None,
            "audit_event": result.audit_event.id,
            "blocking_claim_ids": list(result.record.decision.blocking_claim_ids),
            "reason": result.record.decision.reason,
        }
    finally:
        store.close()


def activate_claim_status(
    store_path: str | Path,
    claim_id: str,
    approval_id: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        decision = store.load_decision(claim_id)
        approval_level = ApprovalLevel(decision.approval_level)
        if approval_level != ApprovalLevel.NONE:
            if approval_id is None:
                raise ValueError(f"claim requires {approval_level.value} approval before activation")
            approval = store.load_approval(approval_id)
            if approval.subject_id != claim_id:
                raise ValueError("approval subject does not match claim")
            if not approval.can_execute():
                raise ValueError("approval is not approved")
        coordinator = coordinator_from_store(store)
        record = coordinator.activate_claim(claim_id, approval_id)
        return {
            "store": str(store.path),
            "claim": record.claim.id,
            "claim_status": record.claim.status.value,
            "decision": record.decision.outcome.value,
            "approval": record.decision.approval_level.value,
            "blocking_claim_ids": list(record.decision.blocking_claim_ids),
            "reason": record.decision.reason,
        }
    finally:
        store.close()


def approve_claim_status(
    store_path: str | Path,
    approval_id: str,
    decided_by: str,
    decided_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        coordinator = coordinator_from_store(store)
        result = coordinator.approve_request(approval_id, decided_by, decided_at)
        return {
            "store": str(store.path),
            "approval_id": result.approval.id,
            "subject_id": result.approval.subject_id,
            "approval_status": result.approval.status.value,
            "decided_by": result.approval.decided_by,
            "audit_event": result.audit_event.id,
        }
    finally:
        store.close()


def release_claim_status(store_path: str | Path, claim_id: str) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        coordinator = coordinator_from_store(store)
        claim = coordinator.release_claim(claim_id)
        return {
            "store": str(store.path),
            "claim": claim.id,
            "claim_status": claim.status.value,
        }
    finally:
        store.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="overseer")
    subparsers = parser.add_subparsers(dest="command", required=True)
    demo_parser = subparsers.add_parser("demo", help="print a demo checkout decision")
    demo_parser.add_argument("--store", help="explicit SQLite path for persisting the demo decision")
    seed_parser = subparsers.add_parser("seed-config", help="persist explicit JSON config into a SQLite store")
    seed_parser.add_argument("--config", required=True, help="explicit JSON config path")
    seed_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    probe_parser = subparsers.add_parser("probe-health", help="run a read-only HTTP health probe for an explicit URL")
    probe_parser.add_argument("--resource-id", required=True)
    probe_parser.add_argument("--name", required=True)
    probe_parser.add_argument("--url", required=True)
    probe_parser.add_argument("--probe-type", default=ProbeType.HTTP.value, choices=[item.value for item in ProbeType])
    probe_parser.add_argument("--expected-status", type=int)
    probe_parser.add_argument("--expected-content-type")
    probe_parser.add_argument("--timeout-seconds", type=float, default=5.0)
    probe_parser.add_argument("--store", help="explicit SQLite store path for persisting health evidence")
    probe_config_parser = subparsers.add_parser("probe-config", help="probe health targets declared in explicit JSON config")
    probe_config_parser.add_argument("--config", required=True, help="explicit JSON config path")
    probe_config_parser.add_argument("--store", help="explicit SQLite store path for persisting health evidence")
    probe_config_parser.add_argument("--timeout-seconds", type=float, default=5.0)
    discover_parser = subparsers.add_parser("discover-physical", help="read directory entries for physical device paths")
    discover_parser.add_argument("--root", action="append", required=True, help="directory root to inspect")
    discover_parser.add_argument("--store", help="explicit SQLite store path for persisting discovered path identities")
    physical_summary_parser = subparsers.add_parser("physical-summary", help="summarize persisted physical identities")
    physical_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    virtual_summary_parser = subparsers.add_parser("virtual-summary", help="summarize persisted virtual assets")
    virtual_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    command_summary_parser = subparsers.add_parser("command-summary", help="summarize command-level Overseer state")
    command_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    command_summary_parser.add_argument("--service-name", default="overseer")
    operator_dashboard_parser = subparsers.add_parser("operator-dashboard", help="summarize all Overseer operator domains")
    operator_dashboard_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    operator_dashboard_parser.add_argument("--service-name", default="overseer")
    maintenance_summary_parser = subparsers.add_parser("maintenance-summary", help="summarize maintenance and update plans")
    maintenance_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    security_summary_parser = subparsers.add_parser("security-summary", help="summarize security surfaces and alerts")
    security_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    health_efficiency_parser = subparsers.add_parser("health-efficiency", help="summarize service health efficiency")
    health_efficiency_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    run_parser = subparsers.add_parser("run", help="run Overseer foreground runtime against an explicit store")
    run_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    run_parser.add_argument("--once", action="store_true", help="run one tick and exit")
    run_parser.add_argument("--interval-seconds", type=float, default=30.0)
    run_parser.add_argument("--probe-health-targets", action="store_true", help="probe configured health targets on each tick")
    run_parser.add_argument("--health-probe-timeout-seconds", type=float, default=5.0)
    run_parser.add_argument("--health-evidence-retention-per-target", type=int, default=5)
    run_parser.add_argument("--inspect-host", action="store_true", help="capture a read-only host inspection snapshot on each tick")
    state_parser = subparsers.add_parser("list-state", help="list stored Overseer resources, claims, approvals, and audit events")
    state_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    service_parser = subparsers.add_parser("service-status", help="read stored runtime heartbeat for a local Overseer service")
    service_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    service_parser.add_argument("--service-name", default="overseer")
    runtime_status_parser = subparsers.add_parser("runtime-status", help="read runtime heartbeat and latest host inspection status")
    runtime_status_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    runtime_status_parser.add_argument("--service-name", default="overseer")
    alerts_summary_parser = subparsers.add_parser("alerts-summary", help="summarize persisted alert audit events")
    alerts_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    inspect_parser = subparsers.add_parser("inspect-host", help="capture read-only host admin evidence")
    inspect_parser.add_argument("--store", help="explicit SQLite store path for persisting the host snapshot")
    assess_host_parser = subparsers.add_parser("assess-host-security", help="assess a persisted host snapshot for exposure findings")
    assess_host_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    assess_host_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    admin_plan_parser = subparsers.add_parser("plan-admin-change", help="prepare an approval-gated admin change plan")
    admin_plan_parser.add_argument("--store", help="explicit SQLite store path for persisting the admin change plan")
    admin_plan_parser.add_argument("--plan-id", required=True)
    admin_plan_parser.add_argument("--kind", required=True, choices=[item.value for item in AdminChangeKind])
    admin_plan_parser.add_argument("--target", required=True)
    admin_plan_parser.add_argument("--reason", required=True)
    admin_plan_parser.add_argument("--current-state", default="unknown")
    admin_plan_parser.add_argument("--package", action="append", default=())
    admin_plan_parser.add_argument("--port", type=int)
    auth_required_parser = subparsers.add_parser("authorizations-required", help="list admin plans waiting for explicit approval")
    auth_required_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    approve_admin_parser = subparsers.add_parser("approve-admin-change", help="record approval metadata for an admin change plan")
    approve_admin_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    approve_admin_parser.add_argument("--plan-id", required=True)
    approve_admin_parser.add_argument("--approved-by", required=True)
    approve_admin_parser.add_argument("--approved-at")
    cancel_admin_parser = subparsers.add_parser("cancel-admin-change", help="mark an admin change plan canceled without executing it")
    cancel_admin_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    cancel_admin_parser.add_argument("--plan-id", required=True)
    cancel_admin_parser.add_argument("--canceled-by", required=True)
    cancel_admin_parser.add_argument("--reason", required=True)
    cancel_admin_parser.add_argument("--canceled-at")
    execute_admin_parser = subparsers.add_parser("execute-admin-change", help="execute an approved user-service admin change plan")
    execute_admin_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    execute_admin_parser.add_argument("--plan-id", required=True)
    admin_executions_parser = subparsers.add_parser("admin-executions", help="list persisted admin change execution results")
    admin_executions_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_summary_parser = subparsers.add_parser("admin-summary", help="summarize admin plans, execution results, and audit events")
    admin_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    api_parser = subparsers.add_parser("serve-api", help="serve the localhost Overseer HTTP API")
    api_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    api_parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"))
    api_parser.add_argument("--port", type=int, default=8766)
    api_parser.add_argument("--auth-token-file", help="local file containing the bearer token required for API access")
    health_summary_parser = subparsers.add_parser("health-summary", help="summarize latest health evidence per target")
    health_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    health_summary_parser.add_argument("--fail-on-unhealthy", action="store_true", help="exit non-zero when any target is unhealthy")
    usage_summary_parser = subparsers.add_parser("usage-summary", help="summarize persisted usage limits")
    usage_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    claim_parser = subparsers.add_parser("request-claim", help="request a stored resource checkout or observation")
    claim_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    claim_parser.add_argument("--claim-id", required=True)
    claim_parser.add_argument("--resource-id", required=True)
    claim_parser.add_argument("--claim-type", required=True, choices=[item.value for item in ClaimType])
    claim_parser.add_argument("--owner-thread", required=True)
    claim_parser.add_argument("--owner-role", required=True, choices=[item.value for item in OwnerDomain])
    claim_parser.add_argument("--intent", required=True)
    claim_parser.add_argument("--requested-action", required=True)
    claim_parser.add_argument("--risk-level", required=True, choices=[item.value for item in RiskLevel])
    claim_parser.add_argument("--port", action="append", type=int, default=(), help="port reservation for conflict checks")
    activate_parser = subparsers.add_parser("activate-claim", help="mark a stored claim active after approval")
    activate_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    activate_parser.add_argument("--claim-id", required=True)
    activate_parser.add_argument("--approval-id")
    approve_parser = subparsers.add_parser("approve-claim", help="approve a stored approval request")
    approve_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    approve_parser.add_argument("--approval-id", required=True)
    approve_parser.add_argument("--decided-by", required=True)
    approve_parser.add_argument("--decided-at")
    release_parser = subparsers.add_parser("release-claim", help="release a stored claim")
    release_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    release_parser.add_argument("--claim-id", required=True)
    args = parser.parse_args(argv)

    if args.command == "demo":
        status = persisted_demo_status(args.store) if args.store else demo_status()
        print(json.dumps(status, sort_keys=True))
        return 0

    if args.command == "seed-config":
        print(json.dumps(seed_config_status(args.config, args.store), sort_keys=True))
        return 0

    if args.command == "probe-health":
        print(
            json.dumps(
                probe_health_status(
                    args.resource_id,
                    args.name,
                    args.url,
                    args.probe_type,
                    args.expected_status,
                    args.expected_content_type,
                    args.timeout_seconds,
                    args.store,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "probe-config":
        print(json.dumps(probe_config_status(args.config, args.store, args.timeout_seconds), sort_keys=True))
        return 0

    if args.command == "discover-physical":
        print(json.dumps(discover_physical_status(args.root, args.store), sort_keys=True))
        return 0

    if args.command == "physical-summary":
        print(json.dumps(physical_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "virtual-summary":
        print(json.dumps(virtual_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "command-summary":
        print(json.dumps(command_summary_status(args.store, args.service_name), sort_keys=True))
        return 0

    if args.command == "operator-dashboard":
        print(json.dumps(operator_dashboard_status(args.store, args.service_name), sort_keys=True))
        return 0

    if args.command == "maintenance-summary":
        print(json.dumps(maintenance_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "security-summary":
        print(json.dumps(security_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "health-efficiency":
        print(json.dumps(health_efficiency_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "run":
        print(
            json.dumps(
                run_status(
                    args.store,
                    args.once,
                    args.interval_seconds,
                    args.probe_health_targets,
                    args.health_probe_timeout_seconds,
                    args.health_evidence_retention_per_target,
                    args.inspect_host,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "list-state":
        print(json.dumps(list_state_status(args.store), sort_keys=True))
        return 0

    if args.command == "service-status":
        print(json.dumps(service_status(args.store, args.service_name), sort_keys=True))
        return 0

    if args.command == "runtime-status":
        print(json.dumps(runtime_status(args.store, args.service_name), sort_keys=True))
        return 0

    if args.command == "alerts-summary":
        print(json.dumps(alerts_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "inspect-host":
        print(json.dumps(inspect_host_status(args.store), sort_keys=True))
        return 0

    if args.command == "assess-host-security":
        print(json.dumps(assess_host_security_status(args.store, args.snapshot_id), sort_keys=True))
        return 0

    if args.command == "plan-admin-change":
        print(
            json.dumps(
                plan_admin_change_status(
                    args.store,
                    args.plan_id,
                    args.kind,
                    args.target,
                    args.reason,
                    args.current_state,
                    args.package,
                    args.port,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "authorizations-required":
        print(json.dumps(authorizations_required_status(args.store), sort_keys=True))
        return 0

    if args.command == "approve-admin-change":
        print(json.dumps(approve_admin_change_status(args.store, args.plan_id, args.approved_by, args.approved_at), sort_keys=True))
        return 0

    if args.command == "cancel-admin-change":
        print(
            json.dumps(
                cancel_admin_change_status(args.store, args.plan_id, args.canceled_by, args.reason, args.canceled_at),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "execute-admin-change":
        print(json.dumps(execute_admin_change_status(args.store, args.plan_id), sort_keys=True))
        return 0

    if args.command == "admin-executions":
        print(json.dumps(admin_executions_status(args.store), sort_keys=True))
        return 0

    if args.command == "admin-summary":
        print(json.dumps(admin_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "serve-api":
        from .api import load_auth_token, run_api_server

        run_api_server(args.store, args.host, args.port, load_auth_token(args.auth_token_file))
        return 0

    if args.command == "health-summary":
        status = health_summary_status(args.store)
        print(json.dumps(status, sort_keys=True))
        return 1 if args.fail_on_unhealthy and status["unhealthy"] else 0

    if args.command == "usage-summary":
        print(json.dumps(usage_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "request-claim":
        print(
            json.dumps(
                request_claim_status(
                    args.store,
                    args.claim_id,
                    args.resource_id,
                    args.claim_type,
                    args.owner_thread,
                    args.owner_role,
                    args.intent,
                    args.requested_action,
                    args.risk_level,
                    args.port,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "activate-claim":
        print(json.dumps(activate_claim_status(args.store, args.claim_id, args.approval_id), sort_keys=True))
        return 0

    if args.command == "approve-claim":
        print(json.dumps(approve_claim_status(args.store, args.approval_id, args.decided_by, args.decided_at), sort_keys=True))
        return 0

    if args.command == "release-claim":
        print(json.dumps(release_claim_status(args.store, args.claim_id), sort_keys=True))
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


def _status_id(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.lower()).strip("-")


if __name__ == "__main__":
    raise SystemExit(main())
