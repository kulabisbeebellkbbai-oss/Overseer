"""Command-line entry point for local Overseer prototypes."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sqlite3
import stat
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from .admin import (
    AdminChangeKind,
    AdminChangePlan,
    AdminCommandResult,
    AdminExecutionResult,
    AdminExecutionStatus,
    AdminHistoryArchiveRecord,
    admin_execution_capability_for,
    archive_admin_change_plan,
    approve_admin_change_plan,
    audit_event_from_admin_execution,
    authorization_required_status,
    cancel_admin_change_plan,
    execute_admin_change_plan,
    missing_admin_change_fields,
    plan_apt_install,
    plan_apt_update,
    plan_apt_upgrade,
    plan_block_ip,
    plan_firewall_allow_tcp,
    plan_firewall_deny_tcp,
    plan_user_service_restart,
    unarchive_admin_change_plan,
)
from .config import SECRET_KEY_PARTS, load_config, seed_store_from_config
from .codex_projects import CodexProjectThreadAdapter, codex_project_thread_resources
from .core import ApprovalLevel, Claim, ClaimType, ConflictOutcome, OwnerDomain, Resource, ResourceType, RiskLevel
from .core import ClaimStatus, ResourceState
from .core import decide_claim
from .audit import ApprovalRequest, ApprovalStatus, AuditEvent, AuditEventType
from .health import HealthStatus, HealthTarget, ProbeType, summarize_health_targets
from .host import (
    HostFindingSeverity,
    HostInspectionAdapter,
    HostInspectionSnapshot,
    host_security_status,
    host_snapshot_status,
    systemd_user_service_resources,
)
from .ids_review import (
    HostSecurityIDSReviewPackage,
    IDSReviewPackageStatus,
    admin_plan_requires_ids_review,
    build_ids_review_package,
    mark_ids_review_package_submitted,
    record_ids_review_package_result,
    write_ids_review_prompt_file,
)
from .live_health import health_probe_adapter_for
from .physical import PhysicalAssetKind, PhysicalIdentity, PhysicalIdentitySource
from .physical_discovery import PathPhysicalDiscoveryAdapter, StoragePhysicalDiscoveryAdapter
from .packages import AptPackageInspectionAdapter, PackageInspectionSnapshot, PackageUpdate
from .policy import (
    PolicyCheck,
    PolicyDecision,
    PolicyProfile,
    evaluate_admin_change_policy,
    policy_customization_helper_status,
    policy_profile_from_answers_status,
    policy_profile_from_mapping,
    policy_profile_status,
)
from .policy import PolicyCheckStatus
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
from .source_review import HostSecuritySourceReview, SourceReviewDisposition
from .store import CURRENT_SCHEMA_VERSION, SQLiteStore, SchemaMigration
from .scheduler import ScheduledWorkStatus, schedule_usage_limited_work
from .usage_limits import LimitKind, UsageContinuationDispatch, UsageContinuationRequest, UsageLimit
from .virtual_discovery import ListenerVirtualDiscoveryAdapter

POLICY_PROFILE_FILENAME = "policy-profile.json"


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
            "physical_identities": result.physical_identity_count,
        }
    finally:
        store.close()


def record_resource_status(
    store_path: str | Path,
    resource_id: str,
    name: str,
    resource_type: str,
    owner_domain: str,
    risk_level: str,
    state: str = ResourceState.AVAILABLE.value,
    identifiers: dict[str, object] | None = None,
    dependencies: Sequence[str] = (),
    exclusive_groups: Sequence[str] = (),
    current_claim_id: str | None = None,
    last_verified_at: str | None = None,
    notes: str = "",
) -> dict[str, object]:
    resource = Resource(
        id=resource_id,
        name=name,
        type=ResourceType(resource_type),
        owner_domain=OwnerDomain(owner_domain),
        risk_level=RiskLevel(risk_level),
        state=ResourceState(state),
        identifiers=identifiers or {},
        dependencies=frozenset(dependencies),
        exclusive_groups=frozenset(exclusive_groups),
        current_claim_id=current_claim_id,
        last_verified_at=last_verified_at,
        notes=notes,
    )
    store = SQLiteStore(store_path)
    try:
        store.save_resource(resource)
        return {
            "store": str(store.path),
            "resource": resource_status(resource),
            "mutation_performed": True,
            "host_mutation_performed": False,
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
    evidence = health_probe_adapter_for(target, timeout_seconds=timeout_seconds).probe(target)
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
    evidence_items = [
        health_probe_adapter_for(target, timeout_seconds=timeout_seconds).probe(target)
        for target in config.health_targets
    ]
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


def probe_stored_health_status(
    store_path: str | Path,
    timeout_seconds: float = 5.0,
    health_evidence_retention_per_target: int | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        targets = store.list_health_targets()
        evidence_items = [
            health_probe_adapter_for(target, timeout_seconds=timeout_seconds).probe(target)
            for target in targets
        ]
        for evidence in evidence_items:
            store.save_health_evidence(evidence)
        if health_evidence_retention_per_target is not None:
            store.prune_health_evidence(health_evidence_retention_per_target)
        return {
            "store": str(store.path),
            "targets": len(targets),
            "healthy": sum(1 for evidence in evidence_items if evidence.observed_status == HealthStatus.HEALTHY),
            "unhealthy": sum(1 for evidence in evidence_items if evidence.observed_status != HealthStatus.HEALTHY),
            "evidence": [_health_evidence_item_status(evidence) for evidence in evidence_items],
        }
    finally:
        store.close()


def record_health_target_status(
    store_path: str | Path,
    target_id: str,
    resource_id: str,
    name: str,
    probe_type: str,
    target: str,
    owner_domain: str = OwnerDomain.JULIAN.value,
    expected_status: int | None = None,
    expected_content_type: str | None = None,
    latency_warn_ms: int | None = None,
) -> dict[str, object]:
    health_target = HealthTarget(
        id=target_id,
        resource_id=resource_id,
        name=name,
        probe_type=ProbeType(probe_type),
        target=target,
        owner_domain=OwnerDomain(owner_domain),
        expected_status=expected_status,
        expected_content_type=expected_content_type,
        latency_warn_ms=latency_warn_ms,
    )
    store = SQLiteStore(store_path)
    try:
        try:
            store.load_resource(resource_id)
        except KeyError as error:
            raise ValueError(f"unknown resource: {resource_id}") from error
        store.save_health_target(health_target)
        return {
            "store": str(store.path),
            "target_id": health_target.id,
            "resource_id": health_target.resource_id,
            "name": health_target.name,
            "probe_type": health_target.probe_type.value,
            "target": health_target.target,
            "owner_domain": health_target.owner_domain.value,
            "expected_status": health_target.expected_status,
            "expected_content_type": health_target.expected_content_type,
            "latency_warn_ms": health_target.latency_warn_ms,
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    finally:
        store.close()


def _health_evidence_item_status(evidence: HealthEvidence) -> dict[str, object]:
    return {
        "id": evidence.id,
        "resource_id": evidence.resource_id,
        "target": evidence.target,
        "probe_type": evidence.probe_type.value,
        "status": evidence.observed_status.value,
        "owner_domain": evidence.owner_domain.value,
        "recovery_required": evidence.recovery_required,
        "error": evidence.observed_error,
    }


def discover_physical_status(roots: Sequence[str], store_path: str | Path | None = None) -> dict[str, object]:
    identities = PathPhysicalDiscoveryAdapter(tuple(roots)).discover()
    return discovered_physical_identities_status(identities, store_path)


def discover_storage_status(
    sysfs_block_root: str | Path = "/sys/class/block",
    store_path: str | Path | None = None,
) -> dict[str, object]:
    identities = StoragePhysicalDiscoveryAdapter(sysfs_block_root).discover()
    return discovered_physical_identities_status(identities, store_path)


def discovered_physical_identities_status(
    identities: Sequence[PhysicalIdentity],
    store_path: str | Path | None = None,
) -> dict[str, object]:
    if store_path is not None:
        store = SQLiteStore(store_path)
        try:
            for identity in identities:
                store.save_physical_identity(identity)
        finally:
            store.close()
    status = {
        "count": len(identities),
        "assets": [physical_identity_status(identity) for identity in identities],
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
            "assets_by_source": {
                source.value: sum(1 for identity in identities if identity.source == source)
                for source in PhysicalIdentitySource
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
        "source": PhysicalIdentitySource(identity.source).value,
        "last_observed_at": identity.last_observed_at,
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


def discover_virtual_listeners_status(
    store_path: str | Path,
    adapter: ListenerVirtualDiscoveryAdapter | None = None,
    snapshot: HostInspectionSnapshot | None = None,
) -> dict[str, object]:
    resources = (adapter or ListenerVirtualDiscoveryAdapter()).discover(snapshot)
    store = SQLiteStore(store_path)
    try:
        for resource in resources:
            store.save_resource(resource)
        return {
            "store": str(store.path),
            "count": len(resources),
            "assets": [virtual_resource_status(resource, ()) for resource in resources],
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
        "protocol": resource.identifiers.get("protocol"),
        "bind_scope": resource.identifiers.get("bind_scope"),
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
        admin_plans = active_admin_change_plans(store.list_admin_change_plans())
        heartbeats = store.list_runtime_heartbeats()
        heartbeat = next((item for item in heartbeats if item.service_name == service_name), None)
        runtime_freshness = assess_freshness(
            heartbeat.last_tick_at if heartbeat else None,
            now=now,
            policy=DEFAULT_RUNTIME_FRESHNESS_POLICY,
        )
        checked_at = _parse_optional_datetime(now) or datetime.now(UTC)
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
                "expired_active_like": sum(1 for claim in claims if _claim_is_expired(claim, checked_at)),
                "missing_release_condition": sum(
                    1
                    for claim in claims
                    if claim.is_exclusive() and claim.is_active_like() and not claim.release_condition
                ),
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
            if not plan.archived
            and (
                plan.owner_domain == OwnerDomain.OBRIEN
                or plan.kind
                in {
                    AdminChangeKind.USER_SERVICE_RESTART,
                    AdminChangeKind.APT_INSTALL,
                    AdminChangeKind.APT_UPDATE,
                    AdminChangeKind.APT_UPGRADE,
                }
            )
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


def inspect_packages_status(
    captured_at: str | None = None,
    adapter: AptPackageInspectionAdapter | None = None,
) -> dict[str, object]:
    snapshot = (adapter or AptPackageInspectionAdapter()).inspect(captured_at)
    return package_inspection_snapshot_status(snapshot)


def plan_package_updates_status(
    store_path: str | Path,
    captured_at: str | None = None,
    packages: Sequence[str] = (),
    adapter: AptPackageInspectionAdapter | None = None,
) -> dict[str, object]:
    snapshot = (adapter or AptPackageInspectionAdapter()).inspect(captured_at)
    inspection = package_inspection_snapshot_status(snapshot)
    if not snapshot.succeeded():
        return {
            "store": str(store_path),
            "inspection": inspection,
            "plans": 0,
            "items": [],
            "mutation_performed": False,
            "host_mutation_performed": False,
            "next_step": "repair package inspection before staging update plans",
        }
    detected_names = tuple(update.name for update in snapshot.updates)
    requested_names = tuple(name for name in packages if name)
    selected_names = requested_names or detected_names
    missing_names = tuple(name for name in requested_names if name not in detected_names)
    if not selected_names:
        return {
            "store": str(store_path),
            "inspection": inspection,
            "plans": 0,
            "items": [],
            "missing_packages": missing_names,
            "mutation_performed": False,
            "host_mutation_performed": False,
            "next_step": "no upgradable packages detected",
        }

    suffix = _status_id(snapshot.id)
    current_state = _package_update_current_state(snapshot, selected_names)
    plans = (
        plan_apt_update(
            f"admin.apt.update.{suffix}",
            "refresh package metadata before detected package upgrades",
            current_state,
        ),
        plan_apt_upgrade(
            f"admin.apt.upgrade.{suffix}",
            selected_names,
            "apply detected package upgrades after approval",
            current_state,
        ),
    )
    store = SQLiteStore(store_path)
    try:
        for plan in plans:
            store.save_admin_change_plan(plan)
        return {
            "store": str(store.path),
            "inspection": inspection,
            "plans": len(plans),
            "items": [admin_change_plan_status(plan) for plan in plans],
            "selected_packages": selected_names,
            "missing_packages": missing_names,
            "mutation_performed": True,
            "host_mutation_performed": False,
            "next_step": "request approval for staged package update plans before execution",
        }
    finally:
        store.close()


def package_inspection_snapshot_status(snapshot: PackageInspectionSnapshot) -> dict[str, object]:
    return {
        "id": snapshot.id,
        "captured_at": snapshot.captured_at,
        "command": list(snapshot.command),
        "exit_code": snapshot.exit_code,
        "status": "ok" if snapshot.succeeded() else "failed",
        "upgradable": len(snapshot.updates),
        "stderr": snapshot.stderr,
        "items": [package_update_status(update) for update in snapshot.updates],
    }


def _package_update_current_state(snapshot: PackageInspectionSnapshot, package_names: Sequence[str]) -> str:
    updates = {update.name: update for update in snapshot.updates}
    parts = []
    for name in package_names:
        update = updates.get(name)
        if update is None:
            parts.append(f"{name}: not reported as upgradable")
            continue
        installed = update.installed_version or "unknown"
        parts.append(f"{name}: {installed} -> {update.candidate_version} ({update.repository})")
    return "; ".join(parts) or "no upgradable packages detected"


def package_update_status(update: PackageUpdate) -> dict[str, object]:
    return {
        "name": update.name,
        "repository": update.repository,
        "candidate_version": update.candidate_version,
        "architecture": update.architecture,
        "installed_version": update.installed_version,
    }


def security_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        resources = [resource for resource in store.list_resources() if resource.type == ResourceType.SECURITY_SURFACE]
        audit_events = store.list_audit_events()
        alerts = [event for event in audit_events if event.event_type == AuditEventType.ALERT]
        snapshots = store.list_host_snapshots()
        latest_snapshot = sorted(snapshots, key=lambda item: item.captured_at)[-1] if snapshots else None
        host_security = host_security_status(latest_snapshot) if latest_snapshot else None
        plans = [
            plan
            for plan in store.list_admin_change_plans()
            if not plan.archived
            and (plan.owner_domain == OwnerDomain.ODO
            or plan.kind in {AdminChangeKind.BLOCK_IP, AdminChangeKind.FIREWALL_ALLOW_TCP}
            )
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
            "ids_review": _host_security_ids_review_summary_payload(
                store.path,
                store.list_host_security_ids_review_packages(),
                audit_events,
            ),
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
    admin = admin_summary_status(store_path)
    admin_history = admin_history_review_status(store_path)
    physical = physical_summary_status(store_path)
    virtual = virtual_summary_status(store_path)
    maintenance = maintenance_summary_status(store_path)
    security = security_summary_status(store_path)
    usage = usage_summary_status(store_path)
    health = health_summary_status(store_path)
    health_efficiency = health_efficiency_summary_status(store_path)
    attention = operator_dashboard_attention(command, admin, admin_history, physical, virtual, maintenance, security, usage, health_efficiency)
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
                "admin_archive_candidates": attention["admin_archive_candidates"],
                "pending_restore_approvals": attention["pending_restore_approvals"],
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
                "ids_review_gate_blocked": attention["security_ids_review_gate_blocked"],
                "ids_review_revision_required": attention["security_ids_review_revision_required"],
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
            "admin": admin,
            "admin_history": admin_history,
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
    admin_summary: dict[str, object],
    admin_history: dict[str, object],
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
    restore_approvals = admin_summary["restore_approvals"]
    freshness = service["freshness"]
    protective_plans = security["protective_plans"]
    host_security = security["host_security"]
    ids_review = security["ids_review"]
    return {
        "service_freshness": freshness["status"],
        "pending_authorizations": admin["pending_authorizations"],
        "pending_restore_approvals": restore_approvals["pending"],
        "pending_claim_approvals": claims["pending_approvals"],
        "queued_claims": claims["queued"],
        "blocked_claims": claims["blocked"],
        "admin_archive_candidates": admin_history["archive_candidates"],
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
        "security_ids_review_gate_blocked": ids_review["gate_blocked"],
        "security_ids_review_revision_required": ids_review["revision_required"],
        "security_ids_review_submitted_without_result": ids_review["submitted_without_result"],
        "high_security_findings": host_security["high_findings"],
        "warning_security_findings": host_security["warning_findings"],
    }


def operator_dashboard_overall_status(attention: dict[str, object]) -> str:
    high_keys = (
        "pending_authorizations",
        "pending_restore_approvals",
        "blocked_claims",
        "unhealthy_health_targets",
        "recovery_required",
        "security_alerts",
        "security_pending_authorizations",
        "security_ids_review_gate_blocked",
        "security_ids_review_revision_required",
        "high_security_findings",
    )
    warning_keys = (
        "pending_claim_approvals",
        "queued_claims",
        "admin_archive_candidates",
        "exhausted_usage_limits",
        "low_confidence_usage_limits",
        "physical_power_risk",
        "physical_storage_risk",
        "virtual_queued_claims",
        "maintenance_pending_authorizations",
        "security_ids_review_submitted_without_result",
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


def persistence_security_status(store_path: str | Path) -> dict[str, object]:
    path = Path(store_path)
    items = [_persistence_file_security_item(path, "database")]
    for suffix, label in (("-wal", "write_ahead_log"), ("-shm", "shared_memory")):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            items.append(_persistence_file_security_item(sidecar, label))
    risky = [item for item in items if item["status"] == "warning"]
    missing_database = not path.exists()
    status = "missing" if missing_database else "warning" if risky else "ok"
    next_step = "create the store through an explicit operator-selected path" if missing_database else "keep store files owner-only readable and writable"
    if risky:
        next_step = "review store ownership and permissions before relying on persisted coordination state"
    return {
        "store": str(path),
        "mutation_performed": False,
        "status": status,
        "recommended_mode": "0600",
        "database_exists": path.exists(),
        "schema": _persistence_schema_status(path),
        "files_checked": len(items),
        "warning_count": len(risky),
        "items": items,
        "next_step": next_step,
    }


def _persistence_schema_status(path: Path) -> dict[str, object]:
    if not path.exists():
        return {
            "current_schema_version": CURRENT_SCHEMA_VERSION,
            "migration_ledger_present": False,
            "applied_schema_version": None,
            "migration_count": 0,
            "migrations": [],
        }
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as error:
        return {
            "current_schema_version": CURRENT_SCHEMA_VERSION,
            "migration_ledger_present": False,
            "applied_schema_version": None,
            "migration_count": 0,
            "migrations": [],
            "error": str(error),
        }
    try:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if table is None:
            return {
                "current_schema_version": CURRENT_SCHEMA_VERSION,
                "migration_ledger_present": False,
                "applied_schema_version": None,
                "migration_count": 0,
                "migrations": [],
            }
        rows = connection.execute(
            "SELECT version, description, applied_at FROM schema_migrations ORDER BY version"
        ).fetchall()
    finally:
        connection.close()
    migrations = [
        {
            "version": int(row[0]),
            "description": str(row[1]),
            "applied_at": str(row[2]),
        }
        for row in rows
    ]
    return {
        "current_schema_version": CURRENT_SCHEMA_VERSION,
        "migration_ledger_present": True,
        "applied_schema_version": migrations[-1]["version"] if migrations else None,
        "migration_count": len(migrations),
        "migrations": migrations,
    }


def _persistence_file_security_item(path: Path, label: str) -> dict[str, object]:
    current_uid = os.getuid()
    if not path.exists():
        return {
            "label": label,
            "path": str(path),
            "exists": False,
            "status": "missing",
            "mode": None,
            "octal_mode": None,
            "owner_uid": None,
            "current_uid": current_uid,
            "owner_matches_current_user": False,
            "group_or_other_permissions": False,
            "risks": ["file does not exist"],
        }
    file_stat = path.stat()
    mode = stat.S_IMODE(file_stat.st_mode)
    owner_matches = file_stat.st_uid == current_uid
    group_or_other_permissions = bool(mode & 0o077)
    risks: list[str] = []
    if not owner_matches:
        risks.append("file is not owned by the current user")
    if group_or_other_permissions:
        risks.append("group or other users have file permissions")
    return {
        "label": label,
        "path": str(path),
        "exists": True,
        "status": "warning" if risks else "ok",
        "mode": stat.filemode(file_stat.st_mode),
        "octal_mode": oct(mode),
        "owner_uid": file_stat.st_uid,
        "current_uid": current_uid,
        "owner_matches_current_user": owner_matches,
        "group_or_other_permissions": group_or_other_permissions,
        "risks": risks,
    }


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


def discover_user_services_status(
    store_path: str | Path,
    snapshot: HostInspectionSnapshot | None = None,
    adapter: HostInspectionAdapter | None = None,
) -> dict[str, object]:
    observed = snapshot or (adapter or HostInspectionAdapter()).inspect()
    resources = systemd_user_service_resources(observed)
    store = SQLiteStore(store_path)
    try:
        store.save_host_snapshot(observed)
        for resource in resources:
            store.save_resource(resource)
            unit = resource.identifiers.get("unit")
            if unit:
                store.save_health_target(
                    HealthTarget(
                        id=f"health.{resource.id.removeprefix('svc.')}",
                        resource_id=resource.id,
                        name=f"{resource.name} process",
                        probe_type=ProbeType.PROCESS,
                        target=f"systemd:user:{unit}",
                        owner_domain=OwnerDomain.JULIAN,
                    )
                )
        return {
            "store": str(store.path),
            "snapshot_id": observed.id,
            "count": len(resources),
            "health_targets": len(resources),
            "items": [discovered_service_resource_status(resource) for resource in resources],
        }
    finally:
        store.close()


def discovered_service_resource_status(resource: Resource) -> dict[str, object]:
    return {
        "id": resource.id,
        "name": resource.name,
        "type": ResourceType(resource.type).value,
        "owner_domain": OwnerDomain(resource.owner_domain).value,
        "risk_level": RiskLevel(resource.risk_level).value,
        "state": ResourceState(resource.state).value,
        "unit": resource.identifiers.get("unit"),
        "active": resource.identifiers.get("active"),
        "sub": resource.identifiers.get("sub"),
        "description": resource.identifiers.get("description"),
        "last_observed_at": resource.identifiers.get("last_observed_at"),
    }


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


def host_security_findings_status(
    store_path: str | Path,
    snapshot_id: str | None = None,
    severity: str | None = None,
) -> dict[str, object]:
    status = assess_host_security_status(store_path, snapshot_id)
    severity_filter = HostFindingSeverity(severity) if severity else None
    findings = [
        finding
        for finding in status["findings"]
        if severity_filter is None or finding["severity"] == severity_filter.value
    ]
    return {
        "store": status["store"],
        "snapshot_id": status["snapshot_id"],
        "captured_at": status["captured_at"],
        "hostname": status["hostname"],
        "severity_filter": severity_filter.value if severity_filter else None,
        "findings": findings,
        "finding_count": len(findings),
        "by_severity": {
            item.value: sum(1 for finding in status["findings"] if finding["severity"] == item.value)
            for item in HostFindingSeverity
        },
        "high_findings": status["high_findings"],
        "warning_findings": status["warning_findings"],
    }


def host_security_triage_status(store_path: str | Path, snapshot_id: str | None = None) -> dict[str, object]:
    findings_status = host_security_findings_status(store_path, snapshot_id)
    findings = findings_status["findings"]
    groups = host_security_triage_groups(findings)
    return {
        "store": findings_status["store"],
        "snapshot_id": findings_status["snapshot_id"],
        "captured_at": findings_status["captured_at"],
        "hostname": findings_status["hostname"],
        "finding_count": findings_status["finding_count"],
        "by_severity": findings_status["by_severity"],
        "listener_groups": groups,
        "group_count": len(groups),
        "approval_boundary": (
            "read-only triage only; firewall, IDS, route, service bind, or listener changes require "
            "separate explicit approval and Intrusion Detection review"
        ),
    }


def host_security_triage_groups(findings: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[str, dict[str, object]] = {}
    for finding in findings:
        listener = listener_from_finding(finding)
        key = listener["local"]
        group = grouped.setdefault(
            key,
            {
                "local": listener["local"],
                "address": listener["address"],
                "port": listener["port"],
                "bind_scope": listener["bind_scope"],
                "severity": finding["severity"],
                "finding_ids": [],
                "evidence": [],
                "recommended_actions": set(),
            },
        )
        group["finding_ids"].append(finding["id"])
        group["evidence"].append(finding["evidence"])
        group["recommended_actions"].add(finding["recommended_action"])
        if finding["severity"] == HostFindingSeverity.HIGH.value:
            group["severity"] = HostFindingSeverity.HIGH.value
    triage_groups = []
    for group in grouped.values():
        recommended_path = host_security_recommended_path(str(group["bind_scope"]), str(group["severity"]))
        triage_groups.append(
            {
                "local": group["local"],
                "address": group["address"],
                "port": group["port"],
                "bind_scope": group["bind_scope"],
                "severity": group["severity"],
                "finding_ids": sorted(group["finding_ids"]),
                "finding_count": len(group["finding_ids"]),
                "evidence": sorted(group["evidence"]),
                "recommended_actions": sorted(group["recommended_actions"]),
                "recommended_mitigation_path": recommended_path,
                "requires_approval": True,
            }
        )
    return sorted(triage_groups, key=lambda item: (item["severity"] != HostFindingSeverity.HIGH.value, item["local"]))


def host_security_listener_review_queue_status(store_path: str | Path, snapshot_id: str | None = None) -> dict[str, object]:
    triage = host_security_triage_status(store_path, snapshot_id)
    store = SQLiteStore(store_path)
    try:
        plans_by_target = {
            plan.target: plan
            for plan in store.list_admin_change_plans()
            if plan.kind == AdminChangeKind.FIREWALL_DENY_TCP and plan.owner_domain == OwnerDomain.ODO and not plan.archived
        }
    finally:
        store.close()
    items = []
    for group in triage["listener_groups"]:
        port = str(group["port"])
        plan = plans_by_target.get(f"tcp/{port}") if port.isdigit() else None
        status = _listener_review_queue_status(group, plan)
        items.append(
            {
                "listener": group["local"],
                "address": group["address"],
                "port": port,
                "bind_scope": group["bind_scope"],
                "severity": group["severity"],
                "finding_count": group["finding_count"],
                "plan_id": plan.id if plan else None,
                "plan_target": plan.target if plan else None,
                "plan_approved": plan.approved if plan else False,
                "plan_canceled": plan.canceled if plan else False,
                "queue_status": status,
                "next_step": _listener_review_queue_next_step(group, plan, status),
                "recommended_mitigation_path": group["recommended_mitigation_path"],
                "evidence": group["evidence"],
            }
        )
    return {
        "store": str(Path(store_path)),
        "snapshot_id": triage["snapshot_id"],
        "captured_at": triage["captured_at"],
        "finding_count": triage["finding_count"],
        "listener_count": triage["group_count"],
        "needs_exposure_review": sum(1 for item in items if item["queue_status"] == "needs_exposure_review"),
        "plan_staged": sum(1 for item in items if item["queue_status"] == "plan_staged"),
        "approved_for_execution": sum(1 for item in items if item["queue_status"] == "approved_for_execution"),
        "plan_canceled": sum(1 for item in items if item["queue_status"] == "plan_canceled"),
        "items": items,
        "approval_boundary": (
            "read-only listener queue only; firewall, IDS, route, service-bind, or enforcement changes require "
            "separate approval-gated remediation"
        ),
    }


def _listener_review_queue_status(group: dict[str, object], plan: AdminChangePlan | None) -> str:
    if plan is None:
        return "needs_exposure_review"
    if plan.canceled:
        return "plan_canceled"
    if plan.can_execute():
        return "approved_for_execution"
    return "plan_staged"


def _listener_review_queue_next_step(group: dict[str, object], plan: AdminChangePlan | None, status: str) -> str:
    if status == "needs_exposure_review":
        if group["bind_scope"] == "all_interfaces":
            return "stage an approval-gated exposure plan or document why all-interface binding is intentional"
        return "confirm expected clients and document service owner before changing policy"
    if status == "plan_canceled":
        return "reassess current exposure and stage a new plan only if the listener is still unwanted"
    if status == "approved_for_execution":
        return "execute the approved plan only after required IDS review and human approval gates are satisfied"
    return "complete IDS review and required approval before execution"


def listener_from_finding(finding: dict[str, object]) -> dict[str, object]:
    summary = str(finding["summary"])
    match = re.search(r" on (?P<local>\S+)$", summary)
    local = match.group("local") if match else "unknown"
    address, port = split_listener_address_port(local)
    return {
        "local": local,
        "address": address,
        "port": port,
        "bind_scope": listener_bind_scope(address),
    }


def split_listener_address_port(local: str) -> tuple[str, str]:
    if local.startswith("[") and "]:" in local:
        address, port = local.rsplit("]:", 1)
        return f"{address}]", port
    if ":" not in local:
        return local, ""
    address, port = local.rsplit(":", 1)
    return address, port


def listener_bind_scope(address: str) -> str:
    if address in {"0.0.0.0", "*", "[::]", "::"}:
        return "all_interfaces"
    if address in {"127.0.0.1", "::1", "[::1]", "localhost"}:
        return "loopback"
    if address == "unknown":
        return "unknown"
    return "non_loopback_specific"


def host_security_recommended_path(bind_scope: str, severity: str) -> str:
    if bind_scope == "all_interfaces":
        return (
            "prepare approval-gated exposure review; prefer rebinding to the intended local interface "
            "or staging source-scoped firewall and IDS rules before enforcement"
        )
    if severity == HostFindingSeverity.WARNING.value:
        return (
            "confirm expected clients and interface; document service owner, then stage allowlist and "
            "monitoring changes only if exposure is intentional"
        )
    return "capture fresh evidence and assign Odo review before any mitigation"


def plan_host_security_remediation_status(
    store_path: str | Path,
    listener: str,
    plan_id: str | None = None,
    action: str = "deny_tcp",
    reason: str | None = None,
    snapshot_id: str | None = None,
) -> dict[str, object]:
    triage = host_security_triage_status(store_path, snapshot_id)
    group = next((item for item in triage["listener_groups"] if item["local"] == listener), None)
    if group is None:
        raise ValueError(f"host security listener is not present in triage: {listener}")
    if action != "deny_tcp":
        raise ValueError("unsupported host security remediation action")
    port_value = str(group["port"])
    if not port_value.isdigit():
        raise ValueError(f"listener does not expose a numeric TCP port: {listener}")
    default_plan_id = f"admin.host-security.deny-tcp.{port_value}"
    default_reason = f"stage approval-gated firewall deny for host security listener {listener}"
    current_state = f"{group['severity']} listener {listener}; bind_scope={group['bind_scope']}; evidence={'; '.join(group['evidence'])}"
    plan = plan_firewall_deny_tcp(plan_id or default_plan_id, int(port_value), reason or default_reason, current_state)
    store = SQLiteStore(store_path)
    try:
        store.save_admin_change_plan(plan)
        return {
            "store": str(store.path),
            "remediation_action": action,
            "listener": group,
            **admin_change_plan_status(plan),
        }
    finally:
        store.close()


def plan_host_security_listener_queue_remediations_status(
    store_path: str | Path,
    snapshot_id: str | None = None,
    requested_by: str = "odo",
    plan_prefix: str = "admin.host-security.deny-tcp",
) -> dict[str, object]:
    queue = host_security_listener_review_queue_status(store_path, snapshot_id)
    candidates_by_port: dict[str, list[dict[str, object]]] = {}
    for item in queue["items"]:
        port = str(item["port"])
        if item["queue_status"] != "needs_exposure_review" or not port.isdigit():
            continue
        candidates_by_port.setdefault(port, []).append(item)
    store = SQLiteStore(store_path)
    staged = []
    skipped = []
    try:
        existing_targets = {
            plan.target
            for plan in store.list_admin_change_plans()
            if plan.kind == AdminChangeKind.FIREWALL_DENY_TCP and plan.owner_domain == OwnerDomain.ODO and not plan.archived
        }
        for port, items in sorted(candidates_by_port.items(), key=lambda entry: int(entry[0])):
            target = f"tcp/{port}"
            if target in existing_targets:
                skipped.append({"port": port, "target": target, "reason": "active Odo firewall deny plan already exists"})
                continue
            plan_id = f"{plan_prefix}.{port}"
            current_state = _listener_queue_plan_current_state(items)
            reason = f"stage approval-gated firewall deny for exposed listener queue {target}; requested_by={requested_by}"
            plan = plan_firewall_deny_tcp(plan_id, int(port), reason, current_state)
            store.save_admin_change_plan(plan)
            existing_targets.add(target)
            staged.append({"port": port, "target": target, "plan_id": plan.id, "listeners": [item["listener"] for item in items]})
        return {
            "store": str(store.path),
            "snapshot_id": queue["snapshot_id"],
            "requested_by": requested_by,
            "candidate_ports": len(candidates_by_port),
            "staged_count": len(staged),
            "skipped_count": len(skipped),
            "staged": staged,
            "skipped": skipped,
            "host_mutation_performed": False,
            "approval_boundary": (
                "plans staged only; firewall, IDS, route, service-bind, or enforcement changes require "
                "separate approval and Intrusion Detection advisory review"
            ),
        }
    finally:
        store.close()


def _listener_queue_plan_current_state(items: Sequence[dict[str, object]]) -> str:
    listeners = ", ".join(str(item["listener"]) for item in items)
    severities = ", ".join(sorted({str(item["severity"]) for item in items}))
    bind_scopes = ", ".join(sorted({str(item["bind_scope"]) for item in items}))
    evidence = "; ".join("; ".join(str(line) for line in item["evidence"]) for item in items)
    return f"listeners={listeners}; severities={severities}; bind_scopes={bind_scopes}; evidence={evidence}"


def host_security_sources_status(store_path: str | Path, snapshot_id: str | None = None) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        if snapshot_id is not None:
            snapshot = store.load_host_snapshot(snapshot_id)
        else:
            snapshots = store.list_host_snapshots()
            if not snapshots:
                raise ValueError("no host snapshots are available")
            snapshot = sorted(snapshots, key=lambda item: item.captured_at)[-1]
    finally:
        store.close()
    triage = host_security_triage_status(store_path, snapshot.id)
    connections = host_security_source_connections(snapshot, triage["listener_groups"])
    return {
        "store": str(Path(store_path)),
        "snapshot_id": snapshot.id,
        "captured_at": snapshot.captured_at,
        "hostname": snapshot.hostname,
        "connection_count": len(connections),
        "connections": connections,
        "by_source_scope": {
            scope: sum(1 for connection in connections if connection["source_scope"] == scope)
            for scope in ("loopback", "private", "documentation", "link_local", "multicast", "external", "unknown")
        },
        "correlation_boundary": (
            "read-only source correlation only; hostile classification, blocking, firewall, IDS, route, "
            "or service-bind changes require separate evidence review and approval"
        ),
    }


def host_security_source_connections(
    snapshot: HostInspectionSnapshot,
    listener_groups: Sequence[dict[str, object]],
) -> list[dict[str, object]]:
    try:
        ss_output = snapshot.observation("ss-established").stdout
    except KeyError:
        return []
    connections = []
    for index, line in enumerate(ss_output.splitlines()):
        if "ESTAB" not in line:
            continue
        local, peer = established_tcp_sockets(line)
        if not local or not peer:
            continue
        local_address, local_port = split_listener_address_port(local)
        peer_address, peer_port = split_listener_address_port(peer)
        listener = matching_listener_group(local_address, local_port, listener_groups)
        if listener is None:
            continue
        source_scope = source_address_scope(peer_address)
        connections.append(
            {
                "id": f"source.{snapshot.id}.{index}",
                "listener": listener["local"],
                "listener_severity": listener["severity"],
                "local": local,
                "local_address": local_address,
                "local_port": local_port,
                "remote": peer,
                "remote_address": peer_address,
                "remote_port": peer_port,
                "source_scope": source_scope,
                "evidence": line.strip(),
                "recommended_action": source_recommended_action(source_scope),
                "can_stage_block_plan": source_scope == "external",
                "requires_approval": True,
            }
        )
    return sorted(connections, key=lambda item: (item["listener"], item["remote_address"], item["remote_port"]))


def established_tcp_sockets(line: str) -> tuple[str, str]:
    columns = line.split()
    if len(columns) < 5:
        return "", ""
    return columns[3], columns[4]


def matching_listener_group(
    local_address: str,
    local_port: str,
    listener_groups: Sequence[dict[str, object]],
) -> dict[str, object] | None:
    for group in listener_groups:
        if str(group["port"]) != local_port:
            continue
        listener_address = str(group["address"])
        if listener_address in {"0.0.0.0", "*", "[::]", "::"} or listener_address == local_address:
            return group
    return None


def source_address_scope(address: str) -> str:
    normalized = address.strip("[]")
    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link_local"
    if parsed.is_multicast:
        return "multicast"
    if is_documentation_address(parsed):
        return "documentation"
    if parsed.is_private:
        return "private"
    if parsed.is_global:
        return "external"
    return "unknown"


def is_documentation_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    documentation_networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )
    return any(address in network for network in documentation_networks)


def source_recommended_action(source_scope: str) -> str:
    if source_scope == "external":
        return "review source evidence with Odo before staging any block plan"
    if source_scope in {"private", "link_local"}:
        return "confirm the source is an expected local client before changing policy"
    if source_scope == "loopback":
        return "treat as local process traffic and correlate with process ownership"
    if source_scope == "documentation":
        return "documentation-range address; use only as test evidence unless observed on a live interface"
    return "capture fresh source evidence before any remediation"


def host_security_source_review_status(review: HostSecuritySourceReview) -> dict[str, object]:
    return {
        "id": review.id,
        "source_connection_id": review.source_connection_id,
        "snapshot_id": review.snapshot_id,
        "listener": review.listener,
        "remote_address": review.remote_address,
        "remote_port": review.remote_port,
        "source_scope": review.source_scope,
        "evidence": review.evidence,
        "disposition": SourceReviewDisposition(review.disposition).value,
        "rationale": review.rationale,
        "reviewed_by": review.reviewed_by,
        "reviewed_at": review.reviewed_at,
        "created_at": review.created_at,
        "can_stage_block_plan": review.can_stage_block_plan(),
        "approval_boundary": (
            "source review only; block plans, firewall, IDS, route, or service-bind changes require "
            "separate approval-gated remediation"
        ),
    }


def create_host_security_source_review_status(
    store_path: str | Path,
    remote_address: str,
    listener: str | None = None,
    review_id: str | None = None,
    disposition: str = SourceReviewDisposition.NEEDS_REVIEW.value,
    rationale: str = "pending Odo review",
    reviewed_by: str | None = None,
    reviewed_at: str | None = None,
    created_at: str | None = None,
    snapshot_id: str | None = None,
) -> dict[str, object]:
    selected_disposition = SourceReviewDisposition(disposition)
    if selected_disposition != SourceReviewDisposition.NEEDS_REVIEW and not reviewed_by:
        raise ValueError("reviewed_by is required for reviewed source dispositions")
    if not rationale.strip():
        raise ValueError("rationale is required")
    sources = host_security_sources_status(store_path, snapshot_id)
    connection = next(
        (
            item
            for item in sources["connections"]
            if item["remote_address"] == remote_address and (listener is None or item["listener"] == listener)
        ),
        None,
    )
    if connection is None:
        raise ValueError(f"remote source is not present in source correlation evidence: {remote_address}")
    default_review_id = f"source-review.{sources['snapshot_id']}.{_status_id(str(connection['listener']))}.{_status_id(remote_address)}.{connection['remote_port']}"
    review = HostSecuritySourceReview(
        id=review_id or default_review_id,
        source_connection_id=str(connection["id"]),
        snapshot_id=str(sources["snapshot_id"]),
        listener=str(connection["listener"]),
        remote_address=str(connection["remote_address"]),
        remote_port=str(connection["remote_port"]),
        source_scope=str(connection["source_scope"]),
        evidence=str(connection["evidence"]),
        disposition=selected_disposition,
        rationale=rationale,
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at,
        created_at=created_at,
    )
    store = SQLiteStore(store_path)
    try:
        store.save_host_security_source_review(review)
        return {"store": str(store.path), **host_security_source_review_status(review)}
    finally:
        store.close()


def host_security_source_reviews_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        reviews = store.list_host_security_source_reviews()
        return {
            "store": str(store.path),
            "review_count": len(reviews),
            "by_disposition": {
                disposition.value: sum(1 for review in reviews if review.disposition == disposition)
                for disposition in SourceReviewDisposition
            },
            "ready_for_block_plan": sum(1 for review in reviews if review.can_stage_block_plan()),
            "reviews": [host_security_source_review_status(review) for review in reviews],
        }
    finally:
        store.close()


def host_security_source_review_queue_status(store_path: str | Path, snapshot_id: str | None = None) -> dict[str, object]:
    sources = host_security_sources_status(store_path, snapshot_id)
    reviews = host_security_source_reviews_status(store_path)
    latest_reviews = _latest_source_reviews_by_source(reviews["reviews"])
    items = []
    for connection in sources["connections"]:
        review = latest_reviews.get(_source_review_key(connection))
        disposition = str(review["disposition"]) if review else SourceReviewDisposition.NEEDS_REVIEW.value
        can_stage_block = bool(review["can_stage_block_plan"]) if review else False
        items.append(
            {
                "source_connection_id": connection["id"],
                "listener": connection["listener"],
                "remote_address": connection["remote_address"],
                "remote_port": connection["remote_port"],
                "source_scope": connection["source_scope"],
                "listener_severity": connection["listener_severity"],
                "review_id": review["id"] if review else None,
                "disposition": disposition,
                "can_stage_block_plan": can_stage_block,
                "queue_status": _source_review_queue_status(connection, review),
                "next_step": _source_review_queue_next_step(connection, review),
                "recommended_action": connection["recommended_action"],
                "evidence": connection["evidence"],
            }
        )
    return {
        "store": str(Path(store_path)),
        "snapshot_id": sources["snapshot_id"],
        "captured_at": sources["captured_at"],
        "connection_count": sources["connection_count"],
        "review_count": reviews["review_count"],
        "needs_review": sum(1 for item in items if item["queue_status"] == "needs_review"),
        "ready_for_block_plan": sum(1 for item in items if item["queue_status"] == "ready_for_block_plan"),
        "reviewed_no_action": sum(1 for item in items if item["queue_status"] == "reviewed_no_action"),
        "not_blockable": sum(1 for item in items if item["queue_status"] == "not_blockable"),
        "items": items,
        "approval_boundary": (
            "read-only queue only; hostile classification, block plans, firewall, IDS, route, or service-bind "
            "changes require separate review and approval-gated remediation"
        ),
    }


def _latest_source_reviews_by_source(reviews: Sequence[dict[str, object]]) -> dict[tuple[str, str], dict[str, object]]:
    latest: dict[tuple[str, str], dict[str, object]] = {}
    for review in reviews:
        key = _source_review_key(review)
        existing = latest.get(key)
        if existing is None or str(review.get("reviewed_at") or review.get("created_at") or review["id"]) >= str(
            existing.get("reviewed_at") or existing.get("created_at") or existing["id"]
        ):
            latest[key] = review
    return latest


def _source_review_key(item: dict[str, object]) -> tuple[str, str]:
    return str(item["listener"]), str(item["remote_address"])


def _source_review_queue_status(connection: dict[str, object], review: dict[str, object] | None) -> str:
    if review is None:
        return "needs_review"
    if bool(review["can_stage_block_plan"]):
        return "ready_for_block_plan"
    disposition = SourceReviewDisposition(str(review["disposition"]))
    if disposition in {SourceReviewDisposition.EXPECTED, SourceReviewDisposition.BENIGN, SourceReviewDisposition.SUSPICIOUS}:
        return "reviewed_no_action"
    if not bool(connection["can_stage_block_plan"]):
        return "not_blockable"
    return "needs_review"


def _source_review_queue_next_step(connection: dict[str, object], review: dict[str, object] | None) -> str:
    if review is None:
        if connection["source_scope"] == "external":
            return "record Odo source review before any block plan is staged"
        return "record Odo source review only if this source is unexpected"
    if bool(review["can_stage_block_plan"]):
        return "stage approval-gated source block plan or downgrade the review disposition"
    disposition = SourceReviewDisposition(str(review["disposition"]))
    if disposition == SourceReviewDisposition.HOSTILE:
        return "hostile review is not block-ready; confirm external scope, reviewer, and rationale"
    if disposition == SourceReviewDisposition.SUSPICIOUS:
        return "continue monitoring or escalate to hostile only with supporting evidence"
    return "no protective action queued"


def plan_host_security_source_block_status(
    store_path: str | Path,
    review_id: str,
    plan_id: str | None = None,
    action: str = "block_ip",
    reason: str | None = None,
) -> dict[str, object]:
    if action != "block_ip":
        raise ValueError("unsupported host security source remediation action")
    store = SQLiteStore(store_path)
    try:
        review = store.load_host_security_source_review(review_id)
        if not review.can_stage_block_plan():
            raise ValueError("source review is not eligible for block-plan staging")
        default_plan_id = f"admin.host-security.block-source.{_status_id(review.remote_address)}"
        default_reason = f"stage approval-gated source block from Odo review {review.id}"
        current_state = (
            f"review={review.id}; disposition={SourceReviewDisposition(review.disposition).value}; "
            f"source_scope={review.source_scope}; listener={review.listener}; evidence={review.evidence}; "
            f"rationale={review.rationale}"
        )
        plan = plan_block_ip(plan_id or default_plan_id, review.remote_address, reason or default_reason, current_state)
        store.save_admin_change_plan(plan)
        return {
            "store": str(store.path),
            "remediation_action": action,
            "source_review": host_security_source_review_status(review),
            "ids_review_required_before_execution": True,
            "approval_boundary": (
                "block plan staged only; firewall, IDS, route, service-bind, or enforcement changes require "
                "separate approval and Intrusion Detection advisory review"
            ),
            **admin_change_plan_status(plan),
        }
    finally:
        store.close()


def host_security_ids_review_package_status(package: HostSecurityIDSReviewPackage) -> dict[str, object]:
    return {
        "id": package.id,
        "plan_id": package.plan_id,
        "plan_kind": AdminChangeKind(package.plan_kind).value,
        "target": package.target,
        "requested_by": package.requested_by,
        "status": IDSReviewPackageStatus(package.status).value,
        "source_review_id": package.source_review_id,
        "created_at": package.created_at,
        "submitted_by": package.submitted_by,
        "submitted_at": package.submitted_at,
        "prompt_path": package.prompt_path,
        "reviewed_by": package.reviewed_by,
        "reviewed_at": package.reviewed_at,
        "dispatched_by": package.dispatched_by,
        "dispatched_at": package.dispatched_at,
        "dispatch_status": package.dispatch_status,
        "dispatch_reason": package.dispatch_reason,
        "dispatch_thread": package.dispatch_thread,
        "dispatch_conversation_id": package.dispatch_conversation_id,
        "dispatch_command": package.dispatch_command,
        "dispatch_exit_code": package.dispatch_exit_code,
        "advisory_project_path": package.advisory_project_path,
        "advisory_command": list(package.advisory_command),
        "interactive_thread": package.interactive_thread,
        "current_state": package.current_state,
        "intended_traffic": package.intended_traffic,
        "operational_reason": package.operational_reason,
        "sensitivity": package.sensitivity,
        "policy_gaps": package.policy_gaps,
        "firewall_rule_drafts": list(package.firewall_rule_drafts),
        "ids_rule_drafts": list(package.ids_rule_drafts),
        "logging_plan": package.logging_plan,
        "test_plan": package.test_plan,
        "rollback_plan": package.rollback_plan,
        "approval_boundary": package.approval_boundary,
        "prompt": package.prompt,
        "advisory_result": package.advisory_result,
        "satisfies_pre_execution_review_gate": package.satisfies_pre_execution_review_gate(),
    }


def prepare_host_security_ids_review_package_status(
    store_path: str | Path,
    plan_id: str,
    package_id: str | None = None,
    source_review_id: str | None = None,
    requested_by: str = "odo",
    created_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        source_review = store.load_host_security_source_review(source_review_id) if source_review_id else None
        package = build_ids_review_package(plan, source_review, package_id, requested_by, created_at)
        store.save_host_security_ids_review_package(package)
        store.save_audit_event(_ids_review_audit_event(package, "prepared", AuditEventType.REQUESTED, created_at))
        return {"store": str(store.path), **host_security_ids_review_package_status(package)}
    finally:
        store.close()


def host_security_ids_review_packages_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        packages = store.list_host_security_ids_review_packages()
        return {
            "store": str(store.path),
            "package_count": len(packages),
            "by_status": {
                status.value: sum(1 for package in packages if package.status == status)
                for status in IDSReviewPackageStatus
            },
            "packages": [host_security_ids_review_package_status(package) for package in packages],
        }
    finally:
        store.close()


def host_security_ids_review_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        return _host_security_ids_review_summary_payload(
            store.path,
            store.list_host_security_ids_review_packages(),
            store.list_audit_events(),
        )
    finally:
        store.close()


def _host_security_ids_review_summary_payload(
    store_path: Path,
    packages: Sequence[HostSecurityIDSReviewPackage],
    audit_events: Sequence[AuditEvent],
) -> dict[str, object]:
    ids_audit_events = [
        event
        for event in audit_events
        if event.id.startswith("audit.ids-review.") or event.subject_id.startswith("ids-review.")
    ]
    return {
        "store": str(store_path),
        "package_count": len(packages),
        "by_status": {
            status.value: sum(1 for package in packages if package.status == status)
            for status in IDSReviewPackageStatus
        },
        "gate_satisfied": sum(1 for package in packages if package.satisfies_pre_execution_review_gate()),
        "gate_blocked": sum(1 for package in packages if not package.satisfies_pre_execution_review_gate()),
        "prepared_without_prompt": sum(
            1
            for package in packages
            if package.status == IDSReviewPackageStatus.PREPARED and not package.prompt_path
        ),
        "prepared_with_prompt": sum(
            1
            for package in packages
            if package.status == IDSReviewPackageStatus.PREPARED and package.prompt_path
        ),
        "submitted_without_result": sum(
            1
            for package in packages
            if package.status == IDSReviewPackageStatus.SUBMITTED and not package.advisory_result
        ),
        "revision_required": sum(
            1
            for package in packages
            if package.status == IDSReviewPackageStatus.REVISION_REQUIRED
        ),
        "latest_audit_events": [audit_event_status(event) for event in ids_audit_events[:5]],
        "packages": [_host_security_ids_review_package_summary_status(package) for package in packages],
    }


def _host_security_ids_review_package_summary_status(package: HostSecurityIDSReviewPackage) -> dict[str, object]:
    return {
        "id": package.id,
        "plan_id": package.plan_id,
        "plan_kind": AdminChangeKind(package.plan_kind).value,
        "target": package.target,
        "status": IDSReviewPackageStatus(package.status).value,
        "source_review_id": package.source_review_id,
        "created_at": package.created_at,
        "submitted_by": package.submitted_by,
        "submitted_at": package.submitted_at,
        "prompt_path": package.prompt_path,
        "reviewed_by": package.reviewed_by,
        "reviewed_at": package.reviewed_at,
        "advisory_result_present": bool(package.advisory_result),
        "satisfies_pre_execution_review_gate": package.satisfies_pre_execution_review_gate(),
        "next_step": _ids_review_package_next_step(package),
    }


def _ids_review_package_next_step(package: HostSecurityIDSReviewPackage) -> str:
    status = IDSReviewPackageStatus(package.status)
    if package.satisfies_pre_execution_review_gate():
        return "IDS/firewall advisory accepted; human approval may proceed"
    if status == IDSReviewPackageStatus.REVISION_REQUIRED:
        return "revision required by Intrusion Detection; update the package or plan before approval"
    if package.dispatch_status in {"failed", "not_found"}:
        return "repair Intrusion Detection codex-project dispatch before approval"
    if status == IDSReviewPackageStatus.SUBMITTED:
        return "await Intrusion Detection advisory result before approval"
    if status == IDSReviewPackageStatus.PREPARED and package.prompt_path:
        return "submit IDS/firewall review package with exported prompt before approval"
    return "export IDS/firewall review prompt and submit package before approval"


def submit_host_security_ids_review_package_status(
    store_path: str | Path,
    package_id: str,
    submitted_by: str,
    submitted_at: str | None = None,
    prompt_path: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        package = store.load_host_security_ids_review_package(package_id)
        submitted = mark_ids_review_package_submitted(package, submitted_by, submitted_at, prompt_path)
        store.save_host_security_ids_review_package(submitted)
        store.save_audit_event(_ids_review_audit_event(submitted, "submitted", AuditEventType.REQUESTED, submitted_at))
        return {"store": str(store.path), **host_security_ids_review_package_status(submitted)}
    finally:
        store.close()


def export_host_security_ids_review_prompt_status(
    store_path: str | Path,
    package_id: str,
    output_dir: str | Path = "advisories",
    filename: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        package = store.load_host_security_ids_review_package(package_id)
        resolved_output_dir = _resolve_store_local_output_dir(store.path, output_dir)
        exported, prompt_path = write_ids_review_prompt_file(package, resolved_output_dir, filename)
        store.save_host_security_ids_review_package(exported)
        store.save_audit_event(_ids_review_audit_event(exported, "prompt-exported", AuditEventType.VERIFIED))
        return {
            "store": str(store.path),
            "exported_prompt_path": str(prompt_path),
            **host_security_ids_review_package_status(exported),
        }
    finally:
        store.close()


def dispatch_host_security_ids_review_package_status(
    store_path: str | Path,
    package_id: str,
    dispatched_by: str,
    dispatched_at: str | None = None,
    owner_thread: str | None = None,
    output_dir: str | Path = "advisories",
    filename: str | None = None,
    codex_projects_registry: str | Path | None = None,
    adapter: CodexProjectThreadAdapter | None = None,
) -> dict[str, object]:
    if not dispatched_by.strip():
        raise ValueError("dispatched_by is required")
    store = SQLiteStore(store_path)
    try:
        package = store.load_host_security_ids_review_package(package_id)
        prompt_path = Path(package.prompt_path) if package.prompt_path else None
        if prompt_path is None:
            resolved_output_dir = _resolve_store_local_output_dir(store.path, output_dir)
            package, prompt_path = write_ids_review_prompt_file(package, resolved_output_dir, filename)

        target_thread = owner_thread or package.interactive_thread
        selected_adapter = adapter
        if selected_adapter is None:
            selected_adapter = (
                CodexProjectThreadAdapter(registry_path=codex_projects_registry)
                if codex_projects_registry
                else CodexProjectThreadAdapter()
            )
        resume_result = selected_adapter.resume(target_thread)
        dispatched = replace(
            package,
            dispatched_by=dispatched_by,
            dispatched_at=dispatched_at,
            dispatch_status=resume_result.status,
            dispatch_reason=resume_result.reason,
            dispatch_thread=target_thread,
            dispatch_conversation_id=resume_result.conversation_id,
            dispatch_command=resume_result.command,
            dispatch_exit_code=resume_result.exit_code,
        )
        if resume_result.status in {"resumed", "already_running"}:
            dispatched = mark_ids_review_package_submitted(
                dispatched,
                submitted_by=dispatched_by,
                submitted_at=dispatched_at,
                prompt_path=str(prompt_path),
            )
            event_type = AuditEventType.REQUESTED
            action = "dispatched"
        else:
            event_type = AuditEventType.BLOCKED
            action = "dispatch-blocked"

        store.save_host_security_ids_review_package(dispatched)
        store.save_audit_event(_ids_review_audit_event(dispatched, action, event_type, dispatched_at))
        return {
            "store": str(store.path),
            "exported_prompt_path": str(prompt_path),
            "resume_result": {
                "owner_thread": resume_result.owner_thread,
                "status": resume_result.status,
                "reason": resume_result.reason,
                "conversation_id": resume_result.conversation_id,
                "project": resume_result.project,
                "command": resume_result.command,
                "launcher": resume_result.launcher,
                "exit_code": resume_result.exit_code,
            },
            **host_security_ids_review_package_status(dispatched),
        }
    finally:
        store.close()


def record_host_security_ids_review_result_status(
    store_path: str | Path,
    package_id: str,
    status: str,
    advisory_result: str,
    reviewed_by: str,
    reviewed_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        package = store.load_host_security_ids_review_package(package_id)
        reviewed = record_ids_review_package_result(
            package,
            IDSReviewPackageStatus(status),
            advisory_result,
            reviewed_by,
            reviewed_at,
        )
        store.save_host_security_ids_review_package(reviewed)
        event_type = (
            AuditEventType.APPROVED
            if IDSReviewPackageStatus(reviewed.status) == IDSReviewPackageStatus.ACCEPTED
            else AuditEventType.REJECTED
        )
        store.save_audit_event(_ids_review_audit_event(reviewed, IDSReviewPackageStatus(reviewed.status).value, event_type, reviewed_at))
        return {"store": str(store.path), **host_security_ids_review_package_status(reviewed)}
    finally:
        store.close()


def _ids_review_audit_event(
    package: HostSecurityIDSReviewPackage,
    action: str,
    event_type: AuditEventType,
    occurred_at: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        id=f"audit.ids-review.{package.id}.{action}",
        event_type=event_type,
        owner_domain=OwnerDomain.ODO,
        subject_id=package.id,
        summary=f"IDS/firewall review package {action} for admin plan {package.plan_id}",
        risk_level=RiskLevel.CRITICAL,
        evidence_ids=(package.plan_id,),
        occurred_at=occurred_at,
    )


def _resolve_store_local_output_dir(store_path: Path, output_dir: str | Path) -> Path:
    base_dir = store_path.parent.resolve()
    selected = Path(output_dir)
    resolved = (selected if selected.is_absolute() else base_dir / selected).resolve()
    if resolved != base_dir and base_dir not in resolved.parents:
        raise ValueError("output_dir must be within the store directory")
    return resolved


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
        "archived": plan.archived,
        "archived_by": plan.archived_by,
        "archived_at": plan.archived_at,
        "archive_record_id": plan.archive_record_id,
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


def admin_history_archive_record_status(record: AdminHistoryArchiveRecord) -> dict[str, object]:
    return {
        "id": record.id,
        "plan_id": record.plan_id,
        "disposition": record.disposition,
        "archived_by": record.archived_by,
        "archived_at": record.archived_at,
        "summary": record.summary,
        "evidence_ids": list(record.evidence_ids),
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
    elif plan_kind == AdminChangeKind.APT_UPDATE:
        plan = plan_apt_update(plan_id, reason, current_state)
    elif plan_kind == AdminChangeKind.APT_UPGRADE:
        plan = plan_apt_upgrade(plan_id, tuple(packages), reason, current_state)
    elif plan_kind == AdminChangeKind.FIREWALL_ALLOW_TCP:
        if port is None:
            raise ValueError("port is required for firewall_allow_tcp")
        plan = plan_firewall_allow_tcp(plan_id, port, reason, current_state)
    elif plan_kind == AdminChangeKind.FIREWALL_DENY_TCP:
        if port is None:
            raise ValueError("port is required for firewall_deny_tcp")
        plan = plan_firewall_deny_tcp(plan_id, port, reason, current_state)
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


def execute_admin_change_status(
    store_path: str | Path,
    plan_id: str,
    runner=None,
    policy_profile_path: str | Path | None = None,
) -> dict[str, object]:
    profile, profile_path, profile_source = load_active_policy_profile(store_path, policy_profile_path)
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        enabled_adapter_kinds = approved_admin_adapter_enablement_kinds(store)
        ids_review_packages = store.list_host_security_ids_review_packages_for_plan(plan.id)
        policy_decision = evaluate_admin_change_policy(
            plan,
            admin_execution_capability_for(AdminChangeKind(plan.kind), enabled_adapter_kinds),
            ids_review_packages,
            approved_admin_policy_warning_check_ids(store, plan.id),
            profile,
        )
        if not policy_decision.can_proceed():
            blocking = tuple(
                check
                for check in policy_decision.checks
                if check.status in {PolicyCheckStatus.BLOCK, PolicyCheckStatus.WARN}
            )
            result = AdminExecutionResult(
                id=f"admin.exec.{plan.id}.blocked",
                plan_id=plan.id,
                status=AdminExecutionStatus.BLOCKED,
                summary=f"admin policy {policy_decision.status.value}: {blocking[0].summary if blocking else 'policy gate blocked execution'}",
                command_results=(),
            )
            store.save_admin_execution(result)
            store.save_audit_event(audit_event_from_admin_execution(plan, result))
            return {
                "store": str(store.path),
                "policy_profile": profile.name,
                "policy_profile_source": profile_source,
                "policy_profile_path": str(profile_path),
                "policy": admin_policy_decision_status(policy_decision),
                **admin_execution_status(result),
            }
        result = execute_admin_change_plan(plan, runner=runner, enabled_adapter_kinds=enabled_adapter_kinds)
        store.save_admin_execution(result)
        store.save_audit_event(audit_event_from_admin_execution(plan, result))
        return {
            "store": str(store.path),
            "policy_profile": profile.name,
            "policy_profile_source": profile_source,
            "policy_profile_path": str(profile_path),
            **admin_execution_status(result),
        }
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


def admin_adapter_capabilities_status(store_path: str | Path | None = None) -> dict[str, object]:
    enabled_adapter_kinds: tuple[AdminChangeKind, ...] = ()
    if store_path is not None:
        store = SQLiteStore(store_path)
        try:
            enabled_adapter_kinds = approved_admin_adapter_enablement_kinds(store)
        finally:
            store.close()
    capabilities = [admin_execution_capability_for(kind, enabled_adapter_kinds) for kind in AdminChangeKind]
    return {
        "store": str(Path(store_path)) if store_path is not None else None,
        "capabilities": len(capabilities),
        "enabled": sum(1 for capability in capabilities if capability.status.value == "enabled"),
        "disabled": sum(1 for capability in capabilities if capability.status.value == "disabled"),
        "unsupported": sum(1 for capability in capabilities if capability.status.value == "unsupported"),
        "items": [
            {
                "kind": capability.kind.value,
                "adapter_name": capability.adapter_name,
                "status": capability.status.value,
                "summary": capability.summary,
                "authorization_required_before_enable": capability.authorization_required_before_enable,
                "approval_plan_required": capability.approval_plan_required,
                "supported_commands": [list(command) for command in capability.supported_commands],
            }
            for capability in capabilities
        ],
    }


def approved_admin_adapter_enablement_kinds(store: SQLiteStore) -> tuple[AdminChangeKind, ...]:
    approved: list[AdminChangeKind] = []
    for approval in store.list_approvals():
        if ApprovalStatus(approval.status) != ApprovalStatus.APPROVED:
            continue
        if not approval.id.startswith("approval.admin.adapter.enable."):
            continue
        approved.append(_admin_adapter_enablement_kind_from_subject(approval.subject_id))
    return tuple(sorted(set(approved), key=lambda item: item.value))


def admin_adapter_enablement_plan_status(kind: str | None = None) -> dict[str, object]:
    selected_kind = AdminChangeKind(kind) if kind else None
    capabilities = [
        admin_execution_capability_for(candidate)
        for candidate in AdminChangeKind
        if selected_kind is None or candidate == selected_kind
    ]
    plans = [_admin_adapter_enablement_plan_item_status(capability) for capability in capabilities]
    return {
        "mode": "read_only_enablement_plan",
        "mutation_performed": False,
        "filters": {"kind": kind},
        "plans": len(plans),
        "approval_required": sum(1 for plan in plans if plan["approval_required_before_enable"]),
        "already_enabled": sum(1 for plan in plans if plan["current_status"] == "enabled"),
        "items": plans,
    }


def request_admin_adapter_enablement_status(
    store_path: str | Path,
    kind: str,
    requested_by: str,
    requested_at: str | None = None,
) -> dict[str, object]:
    if not requested_by.strip():
        raise ValueError("requested_by is required")
    capability = admin_execution_capability_for(AdminChangeKind(kind))
    if capability.can_execute_live():
        raise ValueError(f"admin adapter is already enabled: {capability.kind.value}")
    if not capability.authorization_required_before_enable:
        raise ValueError(f"admin adapter does not require enablement approval: {capability.kind.value}")
    plan = _admin_adapter_enablement_plan_item_status(capability)
    approval = ApprovalRequest(
        id=f"approval.admin.adapter.enable.{capability.kind.value}",
        subject_id=f"admin.adapter.enable.{capability.kind.value}",
        approval_level=ApprovalLevel.HUMAN,
        requester_thread=requested_by,
        owner_domain=OwnerDomain.SISKO,
        reason=f"Enable live admin adapter {capability.adapter_name} for {capability.kind.value}",
        evidence_required=(f"admin.adapter.enablement-plan.{capability.kind.value}",),
    )
    event = AuditEvent(
        id=f"audit.{approval.id}.requested",
        event_type=AuditEventType.REQUESTED,
        owner_domain=OwnerDomain.SISKO,
        subject_id=approval.subject_id,
        summary=approval.reason,
        risk_level=RiskLevel.CRITICAL,
        evidence_ids=approval.evidence_required,
        occurred_at=requested_at,
    )
    store = SQLiteStore(store_path)
    try:
        store.save_approval(approval)
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "mutation_performed": True,
            "kind": capability.kind.value,
            "adapter_name": capability.adapter_name,
            "approval_id": approval.id,
            "approval_status": ApprovalStatus(approval.status).value,
            "approval_level": ApprovalLevel(approval.approval_level).value,
            "requested_by": requested_by,
            "requested_at": requested_at,
            "enablement_plan": plan,
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def approve_admin_adapter_enablement_status(
    store_path: str | Path,
    approval_id: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"admin adapter enablement approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.admin.adapter.enable."):
            raise ValueError("admin adapter enablement approval is required")
        kind = _admin_adapter_enablement_kind_from_subject(approval.subject_id)
        capability = admin_execution_capability_for(kind)
        if capability.can_execute_live():
            raise ValueError(f"admin adapter is already enabled: {capability.kind.value}")
    finally:
        store.close()

    approved = approve_claim_status(store_path, approval_id, approved_by, approved_at)
    return {
        **approved,
        "kind": capability.kind.value,
        "adapter_name": capability.adapter_name,
        "adapter_enablement_approval": True,
        "approval_level": ApprovalLevel(approval.approval_level).value,
    }


def admin_adapter_enablement_approval_status(approval: ApprovalRequest) -> dict[str, object]:
    approval_status = ApprovalStatus(approval.status)
    kind = _admin_adapter_enablement_kind_from_subject(approval.subject_id)
    capability = admin_execution_capability_for(kind)
    return {
        "id": approval.id,
        "kind": kind.value,
        "adapter_name": capability.adapter_name,
        "subject_id": approval.subject_id,
        "approval_level": ApprovalLevel(approval.approval_level).value,
        "requester_thread": approval.requester_thread,
        "owner_domain": OwnerDomain(approval.owner_domain).value,
        "reason": approval.reason,
        "status": approval_status.value,
        "evidence_required": list(approval.evidence_required),
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
        "next_step": _admin_adapter_enablement_approval_next_step(approval_status, capability),
    }


def _admin_adapter_enablement_kind_from_subject(subject_id: str) -> AdminChangeKind:
    prefix = "admin.adapter.enable."
    if not subject_id.startswith(prefix):
        raise ValueError("admin adapter enablement subject is required")
    return AdminChangeKind(subject_id[len(prefix):])


def _admin_adapter_enablement_approval_next_step(
    approval_status: ApprovalStatus,
    capability,
) -> str:
    if approval_status == ApprovalStatus.PENDING:
        return "approve-admin-adapter-enablement before enabling adapter code"
    if approval_status == ApprovalStatus.APPROVED:
        return "implementation may enable adapter only for the approved kind and command boundary"
    return "adapter enablement approval is not actionable"


def _admin_adapter_enablement_plan_item_status(capability) -> dict[str, object]:
    approval_required = capability.authorization_required_before_enable or capability.approval_plan_required
    if capability.can_execute_live():
        next_step = "adapter is already enabled; keep monitoring execution evidence and rollback readiness"
    else:
        next_step = "prepare exact high-risk approval request before enabling this live adapter"
    return {
        "kind": capability.kind.value,
        "adapter_name": capability.adapter_name,
        "current_status": capability.status.value,
        "current_state": capability.summary,
        "approval_required_before_enable": approval_required,
        "proposed_state": f"enable live Overseer execution for {capability.kind.value} using adapter {capability.adapter_name}",
        "proposed_changes": [
            {
                "target": "Overseer admin adapter capability table",
                "change": f"change {capability.kind.value} adapter status from {capability.status.value} to enabled",
                "reason": "allow Overseer to execute only approved plans of this kind through a typed adapter boundary",
            },
            {
                "target": "execution gate",
                "change": "verify approved=true, no missing fields, no cancellation/archive state, and required advisory gates before command execution",
                "reason": "preserve the existing approval and audit safety model before any host mutation",
            },
            {
                "target": "audit and verification records",
                "change": "persist command results, verification results, and rollback evidence for every execution attempt",
                "reason": "make live host changes reviewable and reversible",
            },
        ],
        "commands_in_scope": [list(command) for command in capability.supported_commands],
        "risks": _admin_adapter_enablement_risks(capability.kind),
        "rollback_plan": [
            f"disable {capability.kind.value} adapter capability",
            "stop accepting new execution requests for this adapter kind",
            "review latest admin executions and apply each plan's stored rollback steps if verification shows harm",
        ],
        "validation_required": [
            "unit tests for approval, blocked, failed, completed, and rollback-readiness paths",
            "dry-run or mock-run evidence before any live command is attempted",
            "operator-approved live smoke test against a non-critical target",
            "post-change admin execution and audit summaries showing persisted evidence",
        ],
        "next_step": next_step,
    }


def _admin_adapter_enablement_risks(kind: AdminChangeKind) -> list[str]:
    if kind in {AdminChangeKind.APT_INSTALL, AdminChangeKind.APT_UPDATE, AdminChangeKind.APT_UPGRADE}:
        return [
            "sudo package changes may alter shared host dependencies",
            "package installation or upgrade may restart or change local services",
            "rollback may not fully restore transitive package state",
        ]
    if kind in {AdminChangeKind.FIREWALL_ALLOW_TCP, AdminChangeKind.FIREWALL_DENY_TCP, AdminChangeKind.BLOCK_IP}:
        return [
            "firewall changes can break legitimate connectivity",
            "allow rules can increase attack surface",
            "deny or source-block rules can interrupt active project work",
        ]
    return ["service interruption during execution", "dependent local threads may fail while the target changes state"]


def admin_summary_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plans = store.list_admin_change_plans()
        active_plans = active_admin_change_plans(plans)
        executions = store.list_admin_executions()
        approvals = store.list_approvals()
        audit_events = [
            event
            for event in store.list_audit_events()
            if event.subject_id.startswith("admin.") or event.id.startswith("audit.admin.exec.")
        ]
        pending = [
            plan
            for plan in active_plans
            if plan.requires_explicit_approval() and not plan.approved and not plan.canceled
        ]
        history_review = _admin_history_review_payload(
            store.path,
            active_plans,
            {result.plan_id: result for result in executions},
            archived_plans=len(plans) - len(active_plans),
        )
        restore_approvals = [
            approval
            for approval in approvals
            if approval.id.startswith("approval.admin.restore.")
        ]
        archive_approvals = [
            approval
            for approval in approvals
            if approval.id.startswith("approval.admin.archive.")
        ]
        adapter_enablement_approvals = [
            approval
            for approval in approvals
            if approval.id.startswith("approval.admin.adapter.enable.")
        ]
        claim_cleanup_approvals = [
            approval
            for approval in approvals
            if approval.id.startswith("approval.claim.cleanup.")
        ]
        daemon_migration_approvals = [
            approval
            for approval in approvals
            if approval.id.startswith("approval.runtime.daemon-migration.")
        ]
        return {
            "store": str(store.path),
            "plans": len(active_plans),
            "archived_plans": len(plans) - len(active_plans),
            "pending_authorizations": len(pending)
            + sum(1 for approval in archive_approvals if approval.status == ApprovalStatus.PENDING)
            + sum(1 for approval in restore_approvals if approval.status == ApprovalStatus.PENDING)
            + sum(1 for approval in adapter_enablement_approvals if approval.status == ApprovalStatus.PENDING)
            + sum(1 for approval in claim_cleanup_approvals if approval.status == ApprovalStatus.PENDING)
            + sum(1 for approval in daemon_migration_approvals if approval.status == ApprovalStatus.PENDING),
            "approved_plans": sum(1 for plan in active_plans if plan.approved),
            "canceled_plans": sum(1 for plan in active_plans if plan.canceled),
            "executable_plans": sum(1 for plan in active_plans if plan.can_execute()),
            "executions": len(executions),
            "executions_by_status": {
                status.value: sum(1 for result in executions if result.status == status)
                for status in AdminExecutionStatus
            },
            "latest_audit_events": [audit_event_status(event) for event in audit_events[-5:]],
            "history_review": {
                "archive_candidates": history_review["archive_candidates"],
                "active_or_pending": history_review["active_or_pending"],
                "by_disposition": history_review["by_disposition"],
            },
            "archive_approvals": {
                "total": len(archive_approvals),
                "pending": sum(1 for approval in archive_approvals if approval.status == ApprovalStatus.PENDING),
                "approved": sum(1 for approval in archive_approvals if approval.status == ApprovalStatus.APPROVED),
                "by_status": {
                    status.value: sum(1 for approval in archive_approvals if approval.status == status)
                    for status in ApprovalStatus
                },
                "items": [admin_history_archive_approval_status(approval) for approval in archive_approvals],
            },
            "restore_approvals": {
                "total": len(restore_approvals),
                "pending": sum(1 for approval in restore_approvals if approval.status == ApprovalStatus.PENDING),
                "approved": sum(1 for approval in restore_approvals if approval.status == ApprovalStatus.APPROVED),
                "by_status": {
                    status.value: sum(1 for approval in restore_approvals if approval.status == status)
                    for status in ApprovalStatus
                },
                "items": [admin_history_restore_approval_status(approval) for approval in restore_approvals],
            },
            "adapter_enablement_approvals": {
                "total": len(adapter_enablement_approvals),
                "pending": sum(1 for approval in adapter_enablement_approvals if approval.status == ApprovalStatus.PENDING),
                "approved": sum(1 for approval in adapter_enablement_approvals if approval.status == ApprovalStatus.APPROVED),
                "by_status": {
                    status.value: sum(1 for approval in adapter_enablement_approvals if approval.status == status)
                    for status in ApprovalStatus
                },
                "items": [
                    admin_adapter_enablement_approval_status(approval)
                    for approval in adapter_enablement_approvals
                ],
            },
            "claim_cleanup_approvals": {
                "total": len(claim_cleanup_approvals),
                "pending": sum(1 for approval in claim_cleanup_approvals if approval.status == ApprovalStatus.PENDING),
                "approved": sum(1 for approval in claim_cleanup_approvals if approval.status == ApprovalStatus.APPROVED),
                "by_status": {
                    status.value: sum(1 for approval in claim_cleanup_approvals if approval.status == status)
                    for status in ApprovalStatus
                },
                "items": [claim_cleanup_approval_status(approval) for approval in claim_cleanup_approvals],
            },
            "daemon_migration_approvals": {
                "total": len(daemon_migration_approvals),
                "pending": sum(1 for approval in daemon_migration_approvals if approval.status == ApprovalStatus.PENDING),
                "approved": sum(1 for approval in daemon_migration_approvals if approval.status == ApprovalStatus.APPROVED),
                "by_status": {
                    status.value: sum(1 for approval in daemon_migration_approvals if approval.status == status)
                    for status in ApprovalStatus
                },
                "items": [daemon_migration_approval_status(approval) for approval in daemon_migration_approvals],
            },
            "pending": [
                authorization_required_status_with_ids_review(
                    plan,
                    store.list_host_security_ids_review_packages_for_plan(plan.id),
                )
                for plan in pending
            ],
        }
    finally:
        store.close()


def admin_history_restore_approval_status(approval: ApprovalRequest) -> dict[str, object]:
    approval_status = ApprovalStatus(approval.status)
    return {
        "id": approval.id,
        "plan_id": approval.subject_id,
        "approval_level": ApprovalLevel(approval.approval_level).value,
        "requester_thread": approval.requester_thread,
        "owner_domain": OwnerDomain(approval.owner_domain).value,
        "reason": approval.reason,
        "status": approval_status.value,
        "evidence_required": list(approval.evidence_required),
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
        "next_step": _admin_history_restore_approval_next_step(approval_status),
    }


def admin_history_archive_approval_status(approval: ApprovalRequest) -> dict[str, object]:
    approval_status = ApprovalStatus(approval.status)
    return {
        "id": approval.id,
        "archive_subject": approval.subject_id,
        "approval_level": ApprovalLevel(approval.approval_level).value,
        "requester_thread": approval.requester_thread,
        "owner_domain": OwnerDomain(approval.owner_domain).value,
        "reason": approval.reason,
        "status": approval_status.value,
        "evidence_required": list(approval.evidence_required),
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
        "next_step": _admin_history_archive_approval_next_step(approval_status),
    }


def _admin_history_archive_approval_next_step(status: ApprovalStatus) -> str:
    if status == ApprovalStatus.PENDING:
        return "approve-admin-history-archive before archive-admin-history"
    if status == ApprovalStatus.APPROVED:
        return "archive-admin-history with the approved archive approval"
    return "archive approval is not actionable"


def _admin_history_restore_approval_next_step(status: ApprovalStatus) -> str:
    if status == ApprovalStatus.PENDING:
        return "approve-admin-history-restore before unarchive-admin-history"
    if status == ApprovalStatus.APPROVED:
        return "unarchive-admin-history with the approved restore approval"
    return "restore approval is not actionable"


def daemon_migration_plan_status(store_path: str | Path, service_name: str = "overseer") -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        heartbeats = store.list_runtime_heartbeats()
        service_heartbeat = next((heartbeat for heartbeat in heartbeats if heartbeat.service_name == service_name), None)
        return {
            "store": str(store.path),
            "mode": "read_only_daemon_migration_plan",
            "mutation_performed": False,
            "service_name": service_name,
            "approval_required": True,
            "approval_level": ApprovalLevel.HUMAN.value,
            "current_runtime_evidence": {
                "heartbeat_id": service_heartbeat.id if service_heartbeat else None,
                "last_tick_at": service_heartbeat.last_tick_at if service_heartbeat else None,
                "tick_count": service_heartbeat.tick_count if service_heartbeat else 0,
            },
            "proposed_state": f"run {service_name} as a persistent local user service after explicit approval",
            "commands_in_scope": [
                ["systemctl", "--user", "enable", "--now", f"{service_name}.service"],
                ["systemctl", "--user", "status", f"{service_name}.service", "--no-pager"],
                ["journalctl", "--user", "-u", f"{service_name}.service", "-n", "80", "--no-pager"],
            ],
            "rollback_plan": [
                ["systemctl", "--user", "disable", "--now", f"{service_name}.service"],
            ],
            "required_evidence": [
                "unit file path and exact ExecStart command",
                "store path and auth-token handling if an API service is included",
                "post-start runtime heartbeat",
                "operator-facing rollback command",
            ],
            "risks": [
                "persistent service may run probes or inspections repeatedly",
                "bad ExecStart or working directory can hide failures until logs are reviewed",
                "service restart can interrupt active local coordination",
            ],
            "next_step": "request-daemon-migration before changing user service enablement or runtime command",
        }
    finally:
        store.close()


def request_daemon_migration_status(
    store_path: str | Path,
    service_name: str,
    requested_by: str,
    requested_at: str | None = None,
) -> dict[str, object]:
    if not service_name.strip():
        raise ValueError("service_name is required")
    if not requested_by.strip():
        raise ValueError("requested_by is required")
    plan = daemon_migration_plan_status(store_path, service_name)
    approval = ApprovalRequest(
        id=f"approval.runtime.daemon-migration.{service_name}",
        subject_id=f"runtime.daemon-migration.{service_name}",
        approval_level=ApprovalLevel.HUMAN,
        requester_thread=requested_by,
        owner_domain=OwnerDomain.SISKO,
        reason=f"Approve foreground-to-daemon migration for {service_name}",
        evidence_required=(f"runtime.daemon-migration-plan.{service_name}",),
    )
    event = AuditEvent(
        id=f"audit.{approval.id}.requested",
        event_type=AuditEventType.REQUESTED,
        owner_domain=OwnerDomain.SISKO,
        subject_id=approval.subject_id,
        summary=approval.reason,
        risk_level=RiskLevel.HIGH,
        evidence_ids=approval.evidence_required,
        occurred_at=requested_at,
    )
    store = SQLiteStore(store_path)
    try:
        store.save_approval(approval)
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "mutation_performed": True,
            "service_name": service_name,
            "approval_id": approval.id,
            "subject_id": approval.subject_id,
            "approval_status": ApprovalStatus(approval.status).value,
            "approval_level": ApprovalLevel(approval.approval_level).value,
            "requested_by": requested_by,
            "requested_at": requested_at,
            "daemon_migration_plan": plan,
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def approve_daemon_migration_status(
    store_path: str | Path,
    approval_id: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"daemon migration approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.runtime.daemon-migration."):
            raise ValueError("daemon migration approval is required")
        service_name = _daemon_migration_service_from_subject(approval.subject_id)
    finally:
        store.close()

    approved = approve_claim_status(store_path, approval_id, approved_by, approved_at)
    return {
        **approved,
        "service_name": service_name,
        "daemon_migration_approval": True,
        "approval_level": ApprovalLevel(approval.approval_level).value,
    }


def daemon_migration_approval_status(approval: ApprovalRequest) -> dict[str, object]:
    approval_status = ApprovalStatus(approval.status)
    return {
        "id": approval.id,
        "service_name": _daemon_migration_service_from_subject(approval.subject_id),
        "subject_id": approval.subject_id,
        "approval_level": ApprovalLevel(approval.approval_level).value,
        "requester_thread": approval.requester_thread,
        "owner_domain": OwnerDomain(approval.owner_domain).value,
        "reason": approval.reason,
        "status": approval_status.value,
        "evidence_required": list(approval.evidence_required),
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
        "next_step": _daemon_migration_approval_next_step(approval_status),
    }


def _daemon_migration_service_from_subject(subject_id: str) -> str:
    prefix = "runtime.daemon-migration."
    if not subject_id.startswith(prefix):
        raise ValueError("daemon migration approval subject is required")
    return subject_id[len(prefix):]


def _daemon_migration_approval_next_step(status: ApprovalStatus) -> str:
    if status == ApprovalStatus.PENDING:
        return "approve-daemon-migration before changing user service enablement or runtime command"
    if status == ApprovalStatus.APPROVED:
        return "operator may apply only the approved service migration plan and rollback boundary"
    return "daemon migration approval is not actionable"


def admin_execution_readiness_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plans = store.list_admin_change_plans()
        executions_by_plan = {result.plan_id: result for result in store.list_admin_executions()}
        enabled_adapter_kinds = approved_admin_adapter_enablement_kinds(store)
        packages_by_plan = {
            plan.id: store.list_host_security_ids_review_packages_for_plan(plan.id)
            for plan in plans
        }
        items = [
            admin_change_execution_readiness_status(
                plan,
                packages_by_plan[plan.id],
                executions_by_plan.get(plan.id),
                enabled_adapter_kinds,
            )
            for plan in plans
        ]
        return {
            "store": str(store.path),
            "plans": len(plans),
            "ready_for_overseer_execution": sum(1 for item in items if item["readiness_state"] == "ready_for_overseer_execution"),
            "completed": sum(1 for item in items if item["readiness_state"] == "completed"),
            "failed": sum(1 for item in items if item["readiness_state"] == "failed"),
            "manual_execution_required": sum(1 for item in items if item["readiness_state"] == "manual_execution_required"),
            "approval_required": sum(1 for item in items if item["readiness_state"] == "approval_required"),
            "ids_review_blocked": sum(1 for item in items if item["readiness_state"] == "ids_review_blocked"),
            "incomplete": sum(1 for item in items if item["readiness_state"] == "incomplete"),
            "canceled": sum(1 for item in items if item["readiness_state"] == "canceled"),
            "adapter_enabled": sum(1 for item in items if item["adapter_status"] == "enabled"),
            "adapter_disabled": sum(1 for item in items if item["adapter_status"] == "disabled"),
            "adapter_unsupported": sum(1 for item in items if item["adapter_status"] == "unsupported"),
            "by_kind": {
                kind.value: sum(1 for plan in plans if plan.kind == kind)
                for kind in AdminChangeKind
            },
            "items": items,
        }
    finally:
        store.close()


def admin_policy_status(
    store_path: str | Path,
    plan_id: str | None = None,
    policy_profile_path: str | Path | None = None,
) -> dict[str, object]:
    profile, profile_path, profile_source = load_active_policy_profile(store_path, policy_profile_path)
    store = SQLiteStore(store_path)
    try:
        enabled_adapter_kinds = approved_admin_adapter_enablement_kinds(store)
        plans = [
            plan
            for plan in store.list_admin_change_plans()
            if not plan.archived and (plan_id is None or plan.id == plan_id)
        ]
        decisions = [
            evaluate_admin_change_policy(
                plan,
                admin_execution_capability_for(AdminChangeKind(plan.kind), enabled_adapter_kinds),
                store.list_host_security_ids_review_packages_for_plan(plan.id),
                approved_admin_policy_warning_check_ids(store, plan.id),
                profile,
            )
            for plan in plans
        ]
        return {
            "store": str(store.path),
            "plan_id": plan_id,
            "policy_profile": profile.name,
            "policy_profile_source": profile_source,
            "policy_profile_path": str(profile_path),
            "plans": len(decisions),
            "pass": sum(1 for decision in decisions if decision.status.value == "pass"),
            "warn": sum(1 for decision in decisions if decision.status.value == "warn"),
            "block": sum(1 for decision in decisions if decision.status.value == "block"),
            "items": [admin_policy_decision_status(decision) for decision in decisions],
        }
    finally:
        store.close()


def admin_policy_decision_status(decision: PolicyDecision) -> dict[str, object]:
    return {
        "subject_id": decision.subject_id,
        "subject_kind": decision.subject_kind,
        "status": decision.status.value,
        "can_proceed": decision.can_proceed(),
        "warnings_block_execution": decision.warnings_block_execution,
        "checks": [admin_policy_check_status(check) for check in decision.checks],
    }


def load_policy_profile(policy_profile_path: str | Path | None = None) -> PolicyProfile:
    if policy_profile_path is None:
        return PolicyProfile()
    with Path(policy_profile_path).open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("policy profile must be a JSON object")
    profile = loaded.get("profile", loaded)
    if not isinstance(profile, dict):
        raise ValueError("policy profile must be a JSON object")
    return policy_profile_from_mapping(profile)


def active_policy_profile_path(store_path: str | Path) -> Path:
    return Path(store_path).parent / POLICY_PROFILE_FILENAME


def load_active_policy_profile(
    store_path: str | Path,
    policy_profile_path: str | Path | None = None,
) -> tuple[PolicyProfile, Path, str]:
    if policy_profile_path is not None:
        path = Path(policy_profile_path)
        return load_policy_profile(path), path, "explicit_file"
    path = active_policy_profile_path(store_path)
    if path.exists():
        return load_policy_profile(path), path, "store_sibling_file"
    return PolicyProfile(), path, "best_practice_default"


def active_policy_profile_status(
    store_path: str | Path,
    policy_profile_path: str | Path | None = None,
) -> dict[str, object]:
    profile, path, source = load_active_policy_profile(store_path, policy_profile_path)
    customized = profile.name != PolicyProfile().name
    status: dict[str, object] = {
        "store": str(Path(store_path)),
        "path": str(path),
        "source": source,
        "active": True,
        "customized": customized,
        "profile": policy_profile_status(profile),
    }
    if source == "best_practice_default":
        status["next_step"] = (
            "Run policy-customization-helper and build-policy-profile after the customization Q/A session, "
            f"then save the generated profile at {path}."
        )
    else:
        status["next_step"] = "Evaluate admin-policy-status before executing privileged plans."
    return status


def policy_customization_helper_cli_status(output_path: str | Path | None = None) -> dict[str, object]:
    status = policy_customization_helper_status()
    if output_path is not None:
        path = Path(output_path)
        path.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"output_path": str(path), **status}
    return status


def build_policy_profile_status(
    answers_path: str | Path,
    output_path: str | Path | None = None,
) -> dict[str, object]:
    with Path(answers_path).open("r", encoding="utf-8") as handle:
        answers = json.load(handle)
    if not isinstance(answers, dict):
        raise ValueError("policy answers must be a JSON object")
    status = policy_profile_from_answers_status(answers)
    if output_path is not None:
        path = Path(output_path)
        path.write_text(json.dumps(status["profile"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return {"output_path": str(path), **status}
    return status


def admin_policy_check_status(check: PolicyCheck) -> dict[str, object]:
    return {
        "id": check.id,
        "status": check.status.value,
        "owner_domain": OwnerDomain(check.owner_domain).value,
        "summary": check.summary,
        "evidence_ids": list(check.evidence_ids),
    }


def approved_admin_policy_warning_check_ids(store: SQLiteStore, plan_id: str) -> tuple[str, ...]:
    prefix = f"admin.policy.warning.{plan_id}."
    accepted: list[str] = []
    for approval in store.list_approvals():
        if ApprovalStatus(approval.status) != ApprovalStatus.APPROVED:
            continue
        if not approval.subject_id.startswith(prefix):
            continue
        accepted.append(approval.subject_id[len(prefix):])
    return tuple(sorted(set(accepted)))


def request_admin_policy_warning_status(
    store_path: str | Path,
    plan_id: str,
    check_id: str,
    requested_by: str,
    requested_at: str | None = None,
) -> dict[str, object]:
    if not requested_by.strip():
        raise ValueError("requested_by is required")
    if not check_id.strip():
        raise ValueError("check_id is required")
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        decision = evaluate_admin_change_policy(
            plan,
            admin_execution_capability_for(AdminChangeKind(plan.kind), approved_admin_adapter_enablement_kinds(store)),
            store.list_host_security_ids_review_packages_for_plan(plan.id),
            approved_admin_policy_warning_check_ids(store, plan.id),
        )
        warning_ids = {check.id for check in decision.checks if check.status == PolicyCheckStatus.WARN}
        if check_id not in warning_ids:
            raise ValueError("policy check is not an active warning for this plan")
        approval = ApprovalRequest(
            id=f"approval.admin.policy.warning.{plan_id}.{check_id}",
            subject_id=f"admin.policy.warning.{plan_id}.{check_id}",
            approval_level=ApprovalLevel.HUMAN,
            requester_thread=requested_by,
            owner_domain=OwnerDomain.SISKO,
            reason=f"Accept residual policy warning {check_id} for admin plan {plan_id}",
            evidence_required=(plan_id, check_id),
        )
        event = AuditEvent(
            id=f"audit.{approval.id}.requested",
            event_type=AuditEventType.REQUESTED,
            owner_domain=OwnerDomain.SISKO,
            subject_id=approval.subject_id,
            summary=approval.reason,
            risk_level=plan.risk_level,
            evidence_ids=approval.evidence_required,
            occurred_at=requested_at,
        )
        store.save_approval(approval)
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "approval_id": approval.id,
            "plan_id": plan_id,
            "check_id": check_id,
            "approval_status": ApprovalStatus(approval.status).value,
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def approve_admin_policy_warning_status(
    store_path: str | Path,
    approval_id: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"admin policy warning approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.admin.policy.warning."):
            raise ValueError("admin policy warning approval is required")
    finally:
        store.close()
    approved = approve_claim_status(store_path, approval_id, approved_by, approved_at)
    return {"policy_warning_approval": True, **approved}


def admin_history_review_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plans = store.list_admin_change_plans()
        active_plans = active_admin_change_plans(plans)
        return _admin_history_review_payload(
            store.path,
            active_plans,
            {result.plan_id: result for result in store.list_admin_executions()},
            archived_plans=len(plans) - len(active_plans),
        )
    finally:
        store.close()


def admin_history_archive_plan_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plans = store.list_admin_change_plans()
        active_plans = active_admin_change_plans(plans)
        executions = store.list_admin_executions()
        audit_events = store.list_audit_events()
        ids_packages = store.list_host_security_ids_review_packages()
        history = _admin_history_review_payload(
            store.path,
            active_plans,
            {result.plan_id: result for result in executions},
            archived_plans=len(plans) - len(active_plans),
        )
        plans_by_id = {plan.id: plan for plan in active_plans}
        candidate_items = [item for item in history["items"] if item["archive_candidate"]]
        return {
            "store": str(store.path),
            "mode": "read_only_plan",
            "mutation_performed": False,
            "approval_required_before_archive": True,
            "archive_candidates": history["archive_candidates"],
            "planned_bundles": len(candidate_items),
            "items": [
                admin_history_archive_plan_item_status(
                    plans_by_id[str(item["id"])],
                    item,
                    [result for result in executions if result.plan_id == item["id"]],
                    [package for package in ids_packages if package.plan_id == item["id"]],
                    [
                        event
                        for event in audit_events
                        if event.subject_id == item["id"] or item["id"] in event.evidence_ids
                    ],
                )
                for item in candidate_items
            ],
        }
    finally:
        store.close()


def admin_history_archives_status(store_path: str | Path, plan_id: str | None = None) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        records = list(store.list_admin_history_archives())
        if plan_id is not None:
            records = [record for record in records if record.plan_id == plan_id]
        return {
            "store": str(store.path),
            "mode": "read_only",
            "mutation_performed": False,
            "archive_records": len(records),
            "filters": {"plan_id": plan_id},
            "records": [admin_history_archive_record_status(record) for record in records],
        }
    finally:
        store.close()


def admin_history_restore_readiness_status(store_path: str | Path, plan_id: str | None = None) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plans = [plan for plan in store.list_admin_change_plans() if plan.archived]
        if plan_id is not None:
            plans = [plan for plan in plans if plan.id == plan_id]
        archive_records = {record.id: record for record in store.list_admin_history_archives()}
        executions = store.list_admin_executions()
        ids_packages = store.list_host_security_ids_review_packages()
        audit_events = store.list_audit_events()
        items = [
            admin_history_restore_readiness_item_status(
                plan,
                archive_records.get(plan.archive_record_id or ""),
                [result for result in executions if result.plan_id == plan.id],
                [package for package in ids_packages if package.plan_id == plan.id],
                [
                    event
                    for event in audit_events
                    if event.subject_id == plan.id
                    or plan.id in event.evidence_ids
                    or (plan.archive_record_id is not None and plan.archive_record_id in event.evidence_ids)
                ],
            )
            for plan in plans
        ]
        return {
            "store": str(store.path),
            "mode": "read_only_restore_plan",
            "mutation_performed": False,
            "archived_plans": len(items),
            "ready_for_restore_request": sum(1 for item in items if item["readiness_state"] == "ready_for_restore_request"),
            "blocked_missing_archive_record": sum(1 for item in items if item["readiness_state"] == "missing_archive_record"),
            "approval_required_before_restore": sum(1 for item in items if item["approval_required_before_restore"]),
            "filters": {"plan_id": plan_id},
            "items": items,
        }
    finally:
        store.close()


def request_admin_history_archive_status(
    store_path: str | Path,
    requested_by: str,
    requested_at: str | None = None,
    plan_id: str | None = None,
) -> dict[str, object]:
    if not requested_by.strip():
        raise ValueError("requested_by is required")
    archive_plan = admin_history_archive_plan_status(store_path)
    candidate_ids = [str(item["id"]) for item in archive_plan["items"]]
    if plan_id is not None and plan_id not in candidate_ids:
        raise ValueError(f"admin plan is not archive-ready: {plan_id}")
    if plan_id is None and not candidate_ids:
        raise ValueError("no admin plans are archive-ready")
    subject_id = f"admin.archive.{plan_id}" if plan_id else "admin.archive.all"
    approval = ApprovalRequest(
        id=f"approval.{subject_id}",
        subject_id=subject_id,
        approval_level=ApprovalLevel.SISKO,
        requester_thread=requested_by,
        owner_domain=OwnerDomain.SISKO,
        reason=f"Archive inactive admin history for {plan_id or 'all archive-ready plans'}",
        evidence_required=("admin.history.archive-plan",),
    )
    event = AuditEvent(
        id=f"audit.{approval.id}.requested",
        event_type=AuditEventType.REQUESTED,
        owner_domain=OwnerDomain.SISKO,
        subject_id=approval.subject_id,
        summary=approval.reason,
        risk_level=RiskLevel.LOW,
        evidence_ids=approval.evidence_required,
        occurred_at=requested_at,
    )
    store = SQLiteStore(store_path)
    try:
        store.save_approval(approval)
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "mutation_performed": True,
            "approval_id": approval.id,
            "subject_id": approval.subject_id,
            "approval_status": ApprovalStatus(approval.status).value,
            "approval_level": ApprovalLevel(approval.approval_level).value,
            "requested_by": requested_by,
            "requested_at": requested_at,
            "plan_id": plan_id,
            "archive_candidates": len(candidate_ids),
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def approve_admin_history_archive_status(
    store_path: str | Path,
    approval_id: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"archive approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.admin.archive."):
            raise ValueError("admin history archive approval is required")
        archive_subject = approval.subject_id
    finally:
        store.close()

    approved = approve_claim_status(store_path, approval_id, approved_by, approved_at)
    return {
        **approved,
        "archive_subject": archive_subject,
        "archive_approval": True,
        "approval_level": ApprovalLevel(approval.approval_level).value,
    }


def request_admin_history_restore_status(
    store_path: str | Path,
    plan_id: str,
    requested_by: str,
    requested_at: str | None = None,
) -> dict[str, object]:
    if not requested_by.strip():
        raise ValueError("requested_by is required")
    store = SQLiteStore(store_path)
    try:
        try:
            plan = store.load_admin_change_plan(plan_id)
        except KeyError:
            raise ValueError(f"admin plan does not exist: {plan_id}") from None
        if not plan.archived:
            raise ValueError("admin change plan is not archived")
        archive_record_id = plan.archive_record_id
        archive_record = store.load_admin_history_archive(archive_record_id) if archive_record_id else None
        if archive_record is None:
            raise ValueError("matching admin history archive record is required before restore approval")
        approval = ApprovalRequest(
            id=f"approval.admin.restore.{plan.id}",
            subject_id=plan.id,
            approval_level=_admin_history_restore_approval_level(plan),
            requester_thread=requested_by,
            owner_domain=OwnerDomain.SISKO,
            reason=f"Restore archived admin plan {plan.id} to active admin history",
            evidence_required=(archive_record.id,),
        )
        event = AuditEvent(
            id=f"audit.{approval.id}.requested",
            event_type=AuditEventType.REQUESTED,
            owner_domain=OwnerDomain.SISKO,
            subject_id=plan.id,
            summary=approval.reason,
            risk_level=_admin_history_restore_risk_level(plan),
            evidence_ids=(approval.id, archive_record.id),
            occurred_at=requested_at,
        )
        store.save_approval(approval)
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "mutation_performed": True,
            "approval_id": approval.id,
            "subject_id": approval.subject_id,
            "approval_status": ApprovalStatus(approval.status).value,
            "approval_level": ApprovalLevel(approval.approval_level).value,
            "requested_by": requested_by,
            "requested_at": requested_at,
            "archive_record_id": archive_record.id,
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def approve_admin_history_restore_status(
    store_path: str | Path,
    approval_id: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"restore approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.admin.restore."):
            raise ValueError("admin history restore approval is required")
        try:
            plan = store.load_admin_change_plan(approval.subject_id)
        except KeyError:
            raise ValueError(f"restore approval subject admin plan does not exist: {approval.subject_id}") from None
        if not plan.archived:
            raise ValueError("restore approval subject admin plan is not archived")
        archive_record_id = plan.archive_record_id
        archive_record = store.load_admin_history_archive(archive_record_id) if archive_record_id else None
        if archive_record is None:
            raise ValueError("matching admin history archive record is required before restore approval")
    finally:
        store.close()

    approved = approve_claim_status(store_path, approval_id, approved_by, approved_at)
    return {
        **approved,
        "plan_id": approval.subject_id,
        "archive_record_id": archive_record.id,
        "restore_approval": True,
        "approval_level": ApprovalLevel(approval.approval_level).value,
    }


def archive_admin_history_status(
    store_path: str | Path,
    archived_by: str,
    approval_id: str,
    archived_at: str | None = None,
    plan_id: str | None = None,
) -> dict[str, object]:
    if not archived_by.strip():
        raise ValueError("archived_by is required")
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"archive approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.admin.archive."):
            raise ValueError("admin history archive approval is required")
        if ApprovalStatus(approval.status) != ApprovalStatus.APPROVED:
            raise ValueError("admin history archive approval is not approved")
        archive_scope = _admin_history_archive_scope_from_subject(approval.subject_id)
        if archive_scope != "all" and plan_id != archive_scope:
            raise ValueError("archive approval subject does not match requested plan")
        now = archived_at or datetime.now(UTC).isoformat()
        plans = store.list_admin_change_plans()
        executions = store.list_admin_executions()
        audit_events = store.list_audit_events()
        ids_packages = store.list_host_security_ids_review_packages()
        history = _admin_history_review_payload(
            store.path,
            active_admin_change_plans(plans),
            {result.plan_id: result for result in executions},
            archived_plans=sum(1 for plan in plans if plan.archived),
        )
        candidate_items = [item for item in history["items"] if item["archive_candidate"]]
        if plan_id is not None:
            candidate_items = [item for item in candidate_items if item["id"] == plan_id]
            if not candidate_items:
                raise ValueError(f"admin plan is not archive-ready: {plan_id}")
        elif archive_scope != "all":
            candidate_items = [item for item in candidate_items if item["id"] == archive_scope]
            if not candidate_items:
                raise ValueError(f"admin plan is not archive-ready: {archive_scope}")
        plans_by_id = {plan.id: plan for plan in plans}
        records = []
        for item in candidate_items:
            plan = plans_by_id[str(item["id"])]
            related_execution_ids = tuple(result.id for result in executions if result.plan_id == plan.id)
            related_package_ids = tuple(package.id for package in ids_packages if package.plan_id == plan.id)
            related_audit_ids = tuple(
                event.id
                for event in audit_events
                if event.subject_id == plan.id or plan.id in event.evidence_ids
            )
            evidence_ids = related_execution_ids + related_package_ids + related_audit_ids
            record = AdminHistoryArchiveRecord(
                id=f"admin.archive.{plan.id}",
                plan_id=plan.id,
                disposition=str(item["disposition"]),
                archived_by=archived_by,
                archived_at=now,
                summary=f"Archived inactive admin plan {plan.id}: {item['reason']}",
                evidence_ids=evidence_ids,
            )
            archived_plan = archive_admin_change_plan(plan, record.id, archived_by, now)
            store.save_admin_history_archive(record)
            store.save_admin_change_plan(archived_plan)
            store.save_audit_event(
                AuditEvent(
                    id=f"audit.{record.id}",
                    event_type=AuditEventType.RELEASED,
                    owner_domain=OwnerDomain.SISKO,
                    subject_id=plan.id,
                    summary=record.summary,
                    risk_level=RiskLevel.LOW,
                    evidence_ids=(approval.id, record.id) + evidence_ids,
                    occurred_at=now,
                )
            )
            records.append(record)
        return {
            "store": str(store.path),
            "mutation_performed": bool(records),
            "archived": len(records),
            "archived_by": archived_by,
            "archived_at": now,
            "approval_id": approval.id,
            "records": [admin_history_archive_record_status(record) for record in records],
        }
    finally:
        store.close()


def _admin_history_archive_scope_from_subject(subject_id: str) -> str:
    prefix = "admin.archive."
    if not subject_id.startswith(prefix):
        raise ValueError("admin history archive approval subject is required")
    return subject_id[len(prefix):]


def unarchive_admin_history_status(
    store_path: str | Path,
    plan_id: str,
    restored_by: str,
    approval_id: str,
    restored_at: str | None = None,
) -> dict[str, object]:
    if not restored_by.strip():
        raise ValueError("restored_by is required")
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    store = SQLiteStore(store_path)
    try:
        now = restored_at or datetime.now(UTC).isoformat()
        try:
            plan = store.load_admin_change_plan(plan_id)
        except KeyError:
            raise ValueError(f"admin plan does not exist: {plan_id}") from None
        if not plan.archived:
            raise ValueError("admin change plan is not archived")
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"restore approval does not exist: {approval_id}") from None
        expected_approval_level = _admin_history_restore_approval_level(plan)
        if approval.subject_id != plan.id:
            raise ValueError("restore approval subject does not match admin plan")
        if approval.approval_level != expected_approval_level:
            raise ValueError("restore approval level does not match admin plan restore gate")
        if approval.status != ApprovalStatus.APPROVED:
            raise ValueError("restore approval must be approved before unarchiving")
        archive_record_id = plan.archive_record_id
        restored = unarchive_admin_change_plan(plan, restored_by)
        store.save_admin_change_plan(restored)
        evidence_ids = (approval.id,) + ((archive_record_id,) if archive_record_id else ())
        event = AuditEvent(
            id=f"audit.admin.unarchive.{plan.id}",
            event_type=AuditEventType.RELEASED,
            owner_domain=OwnerDomain.SISKO,
            subject_id=plan.id,
            summary=f"Restored archived admin plan {plan.id} to active admin history",
            risk_level=RiskLevel.LOW,
            evidence_ids=evidence_ids,
            occurred_at=now,
        )
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "mutation_performed": True,
            "restored": 1,
            "restored_by": restored_by,
            "restored_at": now,
            "approval_id": approval.id,
            "archive_record_id": archive_record_id,
            "plan": admin_change_plan_status(restored),
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def admin_history_archive_plan_item_status(
    plan: AdminChangePlan,
    review_item: dict[str, object],
    executions: Sequence[AdminExecutionResult],
    ids_packages: Sequence[HostSecurityIDSReviewPackage],
    audit_events: Sequence[AuditEvent],
) -> dict[str, object]:
    return {
        "id": plan.id,
        "archive_bundle_id": f"admin.archive.{plan.id}",
        "disposition": review_item["disposition"],
        "reason": review_item["reason"],
        "action": "export_then_mark_archived",
        "mutation_required_for_archive": True,
        "safety_gate": "explicit approval required before any archive mutation",
        "records": {
            "admin_change_plan": 1,
            "admin_executions": len(executions),
            "ids_review_packages": len(ids_packages),
            "audit_events": len(audit_events),
        },
        "plan": admin_change_plan_status(plan),
        "executions": [admin_execution_status(result) for result in executions],
        "ids_review_packages": [host_security_ids_review_package_status(package) for package in ids_packages],
        "audit_events": [audit_event_status(event) for event in audit_events],
    }


def admin_history_restore_readiness_item_status(
    plan: AdminChangePlan,
    archive_record: AdminHistoryArchiveRecord | None,
    executions: Sequence[AdminExecutionResult],
    ids_packages: Sequence[HostSecurityIDSReviewPackage],
    audit_events: Sequence[AuditEvent],
) -> dict[str, object]:
    approval_level = _admin_history_restore_approval_level(plan)
    readiness_state = "ready_for_restore_request" if archive_record is not None else "missing_archive_record"
    next_step = (
        f"request {approval_level.value} approval before restoring archived admin plan {plan.id}"
        if archive_record is not None
        else "restore is blocked until the matching archive record is present"
    )
    evidence_ids = (
        tuple(result.id for result in executions)
        + tuple(package.id for package in ids_packages)
        + tuple(event.id for event in audit_events)
    )
    return {
        "id": plan.id,
        "archive_record_id": plan.archive_record_id,
        "archive_record_present": archive_record is not None,
        "kind": AdminChangeKind(plan.kind).value,
        "target": plan.target,
        "owner_domain": OwnerDomain(plan.owner_domain).value,
        "original_risk_level": RiskLevel(plan.risk_level).value,
        "restore_risk_level": _admin_history_restore_risk_level(plan).value,
        "approval_required_before_restore": True,
        "approval_level_before_restore": approval_level.value,
        "readiness_state": readiness_state,
        "next_step": next_step,
        "archived_by": plan.archived_by,
        "archived_at": plan.archived_at,
        "archive_summary": archive_record.summary if archive_record else None,
        "evidence": {
            "archive_record": admin_history_archive_record_status(archive_record) if archive_record else None,
            "admin_execution_ids": [result.id for result in executions],
            "ids_review_package_ids": [package.id for package in ids_packages],
            "audit_event_ids": [event.id for event in audit_events],
            "all_evidence_ids": list(evidence_ids),
        },
        "plan": admin_change_plan_status(plan),
    }


def _admin_history_restore_approval_level(plan: AdminChangePlan) -> ApprovalLevel:
    if plan.approval_level == ApprovalLevel.HUMAN or plan.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        return ApprovalLevel.HUMAN
    return ApprovalLevel.SISKO


def _admin_history_restore_risk_level(plan: AdminChangePlan) -> RiskLevel:
    if plan.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        return RiskLevel.HIGH
    return RiskLevel.MEDIUM


def _admin_history_review_payload(
    store_path: Path,
    plans: Sequence[AdminChangePlan],
    executions_by_plan: dict[str, AdminExecutionResult],
    archived_plans: int = 0,
) -> dict[str, object]:
    items = [
        admin_history_review_item_status(plan, executions_by_plan.get(plan.id))
        for plan in plans
    ]
    return {
        "store": str(store_path),
        "plans": len(plans),
        "archived_plans": archived_plans,
        "archive_candidates": sum(1 for item in items if item["archive_candidate"]),
        "active_or_pending": sum(1 for item in items if item["disposition"] == "retain_active"),
        "by_disposition": {
            disposition: sum(1 for item in items if item["disposition"] == disposition)
            for disposition in (
                "archive_completed",
                "archive_canceled",
                "review_failed_execution",
                "retain_active",
            )
        },
        "items": items,
    }


def active_admin_change_plans(plans: Sequence[AdminChangePlan]) -> tuple[AdminChangePlan, ...]:
    return tuple(plan for plan in plans if not plan.archived)


def admin_history_review_item_status(
    plan: AdminChangePlan,
    latest_execution: AdminExecutionResult | None = None,
) -> dict[str, object]:
    disposition, archive_candidate, next_step = _admin_history_disposition(plan, latest_execution)
    return {
        "id": plan.id,
        "kind": AdminChangeKind(plan.kind).value,
        "target": plan.target,
        "owner_domain": OwnerDomain(plan.owner_domain).value,
        "approved": plan.approved,
        "canceled": plan.canceled,
        "can_execute_model": plan.can_execute(),
        "latest_execution_id": latest_execution.id if latest_execution else None,
        "latest_execution_status": AdminExecutionStatus(latest_execution.status).value if latest_execution else None,
        "disposition": disposition,
        "archive_candidate": archive_candidate,
        "next_step": next_step,
        "reason": plan.reason,
    }


def _admin_history_disposition(
    plan: AdminChangePlan,
    latest_execution: AdminExecutionResult | None,
) -> tuple[str, bool, str]:
    if latest_execution is not None and latest_execution.status == AdminExecutionStatus.COMPLETED:
        return "archive_completed", True, "keep audit evidence and move completed plan out of active operator views when archive support exists"
    if latest_execution is not None and latest_execution.status == AdminExecutionStatus.FAILED:
        return "review_failed_execution", False, "inspect failed execution evidence before archiving, retrying, or replacing the plan"
    if plan.canceled:
        return "archive_canceled", True, "keep cancellation evidence and move canceled plan out of active operator views when archive support exists"
    return "retain_active", False, "keep plan visible in active readiness and authorization views"


def admin_change_execution_readiness_status(
    plan: AdminChangePlan,
    ids_review_packages: Sequence[HostSecurityIDSReviewPackage] = (),
    latest_execution: AdminExecutionResult | None = None,
    enabled_adapter_kinds: Sequence[AdminChangeKind | str] = (),
) -> dict[str, object]:
    missing_fields = missing_admin_change_fields(plan)
    ids_review_required = admin_plan_requires_ids_review(plan)
    ids_review_gate_satisfied = (
        not ids_review_required
        or any(package.satisfies_pre_execution_review_gate() for package in ids_review_packages)
    )
    capability = admin_execution_capability_for(AdminChangeKind(plan.kind), enabled_adapter_kinds)
    live_execution_supported = capability.can_execute_live()
    readiness_state, next_step = _admin_execution_readiness_state(
        plan,
        missing_fields,
        ids_review_required,
        ids_review_gate_satisfied,
        live_execution_supported,
        latest_execution,
    )
    return {
        "id": plan.id,
        "kind": AdminChangeKind(plan.kind).value,
        "target": plan.target,
        "owner_domain": OwnerDomain(plan.owner_domain).value,
        "risk_level": RiskLevel(plan.risk_level).value,
        "approval_level": ApprovalLevel(plan.approval_level).value,
        "approved": plan.approved,
        "canceled": plan.canceled,
        "requires_explicit_approval": plan.requires_explicit_approval(),
        "can_execute_model": plan.can_execute(),
        "live_execution_supported": live_execution_supported,
        "adapter": {
            "name": capability.adapter_name,
            "status": capability.status.value,
            "summary": capability.summary,
            "authorization_required_before_enable": capability.authorization_required_before_enable,
            "approval_plan_required": capability.approval_plan_required,
            "supported_commands": [list(command) for command in capability.supported_commands],
        },
        "adapter_status": capability.status.value,
        "ready_for_overseer_execution": readiness_state == "ready_for_overseer_execution",
        "readiness_state": readiness_state,
        "next_step": next_step,
        "missing_fields": list(missing_fields),
        "ids_review_required_before_approval": ids_review_required,
        "ids_review_gate_satisfied": ids_review_gate_satisfied,
        "ids_review_package_count": len(ids_review_packages),
        "latest_execution_id": latest_execution.id if latest_execution else None,
        "latest_execution_status": AdminExecutionStatus(latest_execution.status).value if latest_execution else None,
        "reason": plan.reason,
    }


def _admin_execution_readiness_state(
    plan: AdminChangePlan,
    missing_fields: Sequence[str],
    ids_review_required: bool,
    ids_review_gate_satisfied: bool,
    live_execution_supported: bool,
    latest_execution: AdminExecutionResult | None,
) -> tuple[str, str]:
    if latest_execution is not None and latest_execution.status == AdminExecutionStatus.COMPLETED:
        return "completed", "plan already completed and verified"
    if latest_execution is not None and latest_execution.status == AdminExecutionStatus.FAILED:
        return "failed", "inspect failed execution evidence before retrying or replacing the plan"
    if plan.canceled:
        return "canceled", "plan is canceled; create a new admin change plan if the work is still needed"
    if missing_fields:
        return "incomplete", "complete missing plan fields before approval or execution"
    if ids_review_required and not ids_review_gate_satisfied:
        return "ids_review_blocked", "complete accepted IDS/firewall advisory review before approval or execution"
    if plan.requires_explicit_approval() and not plan.approved:
        return "approval_required", "request explicit approval before execution"
    if not live_execution_supported:
        return "manual_execution_required", "specific live adapter approval and enablement is required before Overseer execution"
    return "ready_for_overseer_execution", "execute approved plan through Overseer"


def approve_admin_change_status(
    store_path: str | Path,
    plan_id: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        plan = store.load_admin_change_plan(plan_id)
        if admin_plan_requires_ids_review(plan) and not any(
            package.satisfies_pre_execution_review_gate()
            for package in store.list_host_security_ids_review_packages_for_plan(plan.id)
        ):
            raise ValueError("IDS/firewall review package is required before approving this admin change plan")
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
        pending_restore_approvals = [
            approval
            for approval in store.list_approvals()
            if approval.id.startswith("approval.admin.restore.")
            and approval.status == ApprovalStatus.PENDING
        ]
        pending_archive_approvals = [
            approval
            for approval in store.list_approvals()
            if approval.id.startswith("approval.admin.archive.")
            and approval.status == ApprovalStatus.PENDING
        ]
        pending_adapter_enablement_approvals = [
            approval
            for approval in store.list_approvals()
            if approval.id.startswith("approval.admin.adapter.enable.")
            and approval.status == ApprovalStatus.PENDING
        ]
        pending_policy_warning_approvals = [
            approval
            for approval in store.list_approvals()
            if approval.id.startswith("approval.admin.policy.warning.")
            and approval.status == ApprovalStatus.PENDING
        ]
        pending_claim_cleanup_approvals = [
            approval
            for approval in store.list_approvals()
            if approval.id.startswith("approval.claim.cleanup.")
            and approval.status == ApprovalStatus.PENDING
        ]
        pending_daemon_migration_approvals = [
            approval
            for approval in store.list_approvals()
            if approval.id.startswith("approval.runtime.daemon-migration.")
            and approval.status == ApprovalStatus.PENDING
        ]
        pending = [
            authorization_required_status_with_ids_review(
                plan,
                store.list_host_security_ids_review_packages_for_plan(plan.id),
            )
            for plan in plans
            if plan.requires_explicit_approval() and not plan.approved and not plan.canceled
        ]
        return {
            "store": str(store.path),
            "pending": pending,
            "pending_count": len(pending)
            + len(pending_archive_approvals)
            + len(pending_restore_approvals)
            + len(pending_adapter_enablement_approvals)
            + len(pending_policy_warning_approvals)
            + len(pending_claim_cleanup_approvals)
            + len(pending_daemon_migration_approvals),
            "pending_plan_count": len(pending),
            "pending_archive_approval_count": len(pending_archive_approvals),
            "pending_restore_approval_count": len(pending_restore_approvals),
            "pending_adapter_enablement_approval_count": len(pending_adapter_enablement_approvals),
            "pending_policy_warning_approval_count": len(pending_policy_warning_approvals),
            "pending_claim_cleanup_approval_count": len(pending_claim_cleanup_approvals),
            "pending_daemon_migration_approval_count": len(pending_daemon_migration_approvals),
            "archive_approvals": [admin_history_archive_approval_status(approval) for approval in pending_archive_approvals],
            "restore_approvals": [admin_history_restore_approval_status(approval) for approval in pending_restore_approvals],
            "adapter_enablement_approvals": [
                admin_adapter_enablement_approval_status(approval)
                for approval in pending_adapter_enablement_approvals
            ],
            "policy_warning_approvals": [
                approval_request_status(approval)
                for approval in pending_policy_warning_approvals
            ],
            "claim_cleanup_approvals": [
                claim_cleanup_approval_status(approval)
                for approval in pending_claim_cleanup_approvals
            ],
            "daemon_migration_approvals": [
                daemon_migration_approval_status(approval)
                for approval in pending_daemon_migration_approvals
            ],
        }
    finally:
        store.close()


def authorization_required_status_with_ids_review(
    plan: AdminChangePlan,
    ids_review_packages: Sequence[HostSecurityIDSReviewPackage] = (),
) -> dict[str, object]:
    status = authorization_required_status(plan)
    if not admin_plan_requires_ids_review(plan):
        status["ids_review_required_before_approval"] = False
        status["ids_review_gate_satisfied"] = True
        return status

    packages = tuple(ids_review_packages)
    gate_satisfied = any(package.satisfies_pre_execution_review_gate() for package in packages)
    status["ids_review_required_before_approval"] = True
    status["ids_review_gate_satisfied"] = gate_satisfied
    status["ids_review_package_count"] = len(packages)
    status["ids_review_packages"] = [
        {
            "id": package.id,
            "status": IDSReviewPackageStatus(package.status).value,
            "prompt_path": package.prompt_path,
            "reviewed_by": package.reviewed_by,
            "reviewed_at": package.reviewed_at,
            "satisfies_pre_execution_review_gate": package.satisfies_pre_execution_review_gate(),
        }
        for package in packages
    ]
    status["ids_review_next_step"] = _ids_review_authorization_next_step(packages)
    if not gate_satisfied:
        status["authorization_required"] = False
        status["next_step"] = status["ids_review_next_step"]
    return status


def _ids_review_authorization_next_step(ids_review_packages: Sequence[HostSecurityIDSReviewPackage]) -> str:
    packages = tuple(ids_review_packages)
    if not packages:
        return "prepare IDS/firewall review package before requesting approval"
    if any(package.satisfies_pre_execution_review_gate() for package in packages):
        return "IDS/firewall advisory accepted; human approval may proceed"
    if any(package.status == IDSReviewPackageStatus.REVISION_REQUIRED for package in packages):
        return "revision required by Intrusion Detection; update the package or plan before approval"
    if any(package.dispatch_status in {"failed", "not_found"} for package in packages):
        return "repair Intrusion Detection codex-project dispatch before approval"
    if any(package.status == IDSReviewPackageStatus.SUBMITTED for package in packages):
        return "await Intrusion Detection advisory result before approval"
    if any(package.prompt_path for package in packages):
        return "submit IDS/firewall review package with exported prompt before approval"
    return "export IDS/firewall review prompt and submit package before approval"


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


def discover_codex_project_threads_status(
    store_path: str | Path,
    registry_path: str | Path = "/home/god/.codex/codex-projects.csv",
    adapter: CodexProjectThreadAdapter | None = None,
) -> dict[str, object]:
    selected_adapter = adapter or CodexProjectThreadAdapter(registry_path)
    threads = selected_adapter.list_threads()
    resources = codex_project_thread_resources(threads)
    store = SQLiteStore(store_path)
    try:
        for resource in resources:
            store.save_resource(resource)
        return {
            "store": str(store.path),
            "registry": str(selected_adapter.registry_path),
            "threads": len(threads),
            "resources": len(resources),
            "items": [codex_project_thread_status(thread, resource) for thread, resource in zip(threads, resources, strict=True)],
            "mutation_performed": bool(resources),
            "host_mutation_performed": False,
            "next_step": "review imported codex-project thread resources before scheduling continuation work",
        }
    finally:
        store.close()


def codex_project_thread_status(thread, resource: Resource | None = None) -> dict[str, object]:
    return {
        "conversation_id": thread.conversation_id,
        "label": thread.label,
        "project": thread.project,
        "command": thread.command,
        "launcher": thread.launcher,
        "resource_id": resource.id if resource else None,
    }


def record_usage_limit_status(
    store_path: str | Path,
    limit_id: str,
    resource_id: str,
    kind: str,
    capacity: int,
    remaining: int,
    window: str,
    resets_at: str | None = None,
    observed_at: str | None = None,
    confidence: float = 1.0,
) -> dict[str, object]:
    if capacity < 0:
        raise ValueError("capacity cannot be negative")
    if remaining < 0:
        raise ValueError("remaining cannot be negative")
    if remaining > capacity:
        raise ValueError("remaining cannot exceed capacity")
    if confidence < 0 or confidence > 1:
        raise ValueError("confidence must be between 0 and 1")
    store = SQLiteStore(store_path)
    try:
        usage_limit = UsageLimit(
            id=limit_id,
            resource_id=resource_id,
            kind=LimitKind(kind),
            capacity=capacity,
            remaining=remaining,
            resets_at=resets_at,
            window=window,
            observed_at=observed_at,
            confidence=confidence,
        )
        store.save_usage_limit(usage_limit)
        return {
            "store": str(store.path),
            "limit": usage_limit_status(usage_limit),
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    finally:
        store.close()


def request_usage_continuation_status(
    store_path: str | Path,
    request_id: str,
    limit_id: str,
    resource_id: str,
    owner_thread: str,
    requested_units: int,
    intent: str,
    risk_level: str = RiskLevel.LOW.value,
    earliest_start: str | None = None,
    deadline: str | None = None,
    requested_by: str = "quark",
    requested_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        limit = store.load_usage_limit(limit_id)
        if limit.resource_id != resource_id:
            raise ValueError("request resource_id does not match usage limit")
        request = UsageContinuationRequest(
            id=request_id,
            limit_id=limit_id,
            resource_id=resource_id,
            owner_thread=owner_thread,
            requested_units=requested_units,
            intent=intent,
            risk_level=RiskLevel(risk_level),
            earliest_start=earliest_start,
            deadline=deadline,
            requested_by=requested_by,
            requested_at=requested_at,
        )
        store.save_usage_continuation_request(request)
        work = schedule_usage_limited_work(limit, request.to_limited_work_request())
        return {
            "store": str(store.path),
            "request": usage_continuation_request_status(request),
            "schedule": scheduled_work_status(work),
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    finally:
        store.close()


def usage_continuation_plan_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        requests = store.list_usage_continuation_requests()
        dispatches = store.list_usage_continuation_dispatches()
        dispatched_request_ids = {dispatch.request_id for dispatch in dispatches}
        schedules = []
        missing_limit_ids: list[str] = []
        for request in requests:
            try:
                limit = store.load_usage_limit(request.limit_id)
            except KeyError:
                missing_limit_ids.append(request.limit_id)
                schedules.append(
                    {
                        "id": request.id,
                        "owner_thread": request.owner_thread,
                        "resource_id": request.resource_id,
                        "status": ScheduledWorkStatus.BLOCKED.value,
                        "reason": "usage limit record is missing",
                        "scheduled_for": None,
                        "blocking_ids": (request.limit_id,),
                    }
                )
                continue
            schedules.append(scheduled_work_status(schedule_usage_limited_work(limit, request.to_limited_work_request())))
        return {
            "store": str(store.path),
            "continuation_requests": len(requests),
            "dispatches": len(dispatches),
            "ready": sum(1 for item in schedules if item["status"] == ScheduledWorkStatus.READY.value),
            "waiting": sum(1 for item in schedules if item["status"] == ScheduledWorkStatus.WAITING.value),
            "blocked": sum(1 for item in schedules if item["status"] == ScheduledWorkStatus.BLOCKED.value),
            "escalated": sum(1 for item in schedules if item["status"] == ScheduledWorkStatus.ESCALATED.value),
            "undispatched_ready": sum(
                1
                for item in schedules
                if item["status"] == ScheduledWorkStatus.READY.value and item["id"] not in dispatched_request_ids
            ),
            "missing_limit_ids": tuple(sorted(set(missing_limit_ids))),
            "items": [usage_continuation_request_status(request) for request in requests],
            "schedules": schedules,
            "dispatch_items": [usage_continuation_dispatch_status(dispatch) for dispatch in dispatches],
            "mutation_performed": False,
            "host_mutation_performed": False,
        }
    finally:
        store.close()


def dispatch_usage_continuations_status(
    store_path: str | Path,
    dispatched_by: str = "quark",
    dispatched_at: str | None = None,
    resume_codex_projects: bool = False,
    codex_projects_registry: str | Path = "/home/god/.codex/codex-projects.csv",
    thread_adapter: CodexProjectThreadAdapter | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        now = dispatched_at or datetime.now(UTC).isoformat()
        adapter = thread_adapter
        if resume_codex_projects and adapter is None:
            adapter = CodexProjectThreadAdapter(codex_projects_registry)
        existing_dispatches = store.list_usage_continuation_dispatches()
        dispatched_request_ids = {dispatch.request_id for dispatch in existing_dispatches}
        dispatches: list[UsageContinuationDispatch] = []
        skipped: list[dict[str, object]] = []
        resume_results: list[dict[str, object]] = []
        for request in store.list_usage_continuation_requests():
            if request.id in dispatched_request_ids:
                skipped.append(
                    {
                        "id": request.id,
                        "owner_thread": request.owner_thread,
                        "resource_id": request.resource_id,
                        "status": "already_dispatched",
                        "reason": "continuation request already has a dispatch record",
                    }
                )
                continue
            try:
                limit = store.load_usage_limit(request.limit_id)
            except KeyError:
                skipped.append(
                    {
                        "id": request.id,
                        "owner_thread": request.owner_thread,
                        "resource_id": request.resource_id,
                        "status": ScheduledWorkStatus.BLOCKED.value,
                        "reason": "usage limit record is missing",
                    }
                )
                continue
            schedule = schedule_usage_limited_work(limit, request.to_limited_work_request())
            if schedule.status != ScheduledWorkStatus.READY:
                skipped.append(scheduled_work_status(schedule))
                continue
            resume_result = adapter.resume(request.owner_thread) if adapter is not None else None
            if resume_result is not None:
                resume_results.append(codex_project_resume_status(resume_result))
            dispatch = UsageContinuationDispatch(
                id=f"usage.dispatch.{_status_id(request.id)}",
                request_id=request.id,
                limit_id=request.limit_id,
                resource_id=request.resource_id,
                owner_thread=request.owner_thread,
                status="dispatched",
                reason=schedule.reason,
                dispatched_by=dispatched_by,
                dispatched_at=now,
                scheduled_for=schedule.scheduled_for,
                resume_status=resume_result.status if resume_result else None,
                resume_reason=resume_result.reason if resume_result else None,
                resume_conversation_id=resume_result.conversation_id if resume_result else None,
                resume_project=resume_result.project if resume_result else None,
                resume_command=resume_result.command if resume_result else None,
                resume_launcher=resume_result.launcher if resume_result else None,
                resume_exit_code=resume_result.exit_code if resume_result else None,
            )
            store.save_usage_continuation_dispatch(dispatch)
            dispatches.append(dispatch)
        return {
            "store": str(store.path),
            "dispatched": len(dispatches),
            "skipped": len(skipped),
            "dispatches": [usage_continuation_dispatch_status(dispatch) for dispatch in dispatches],
            "skipped_items": skipped,
            "resume_codex_projects": resume_codex_projects,
            "resume_results": resume_results,
            "mutation_performed": bool(dispatches),
            "host_mutation_performed": any(item["status"] in {"resumed", "already_running"} for item in resume_results),
            "next_step": _dispatch_usage_continuations_next_step(resume_codex_projects, resume_results),
        }
    finally:
        store.close()


def _dispatch_usage_continuations_next_step(resume_codex_projects: bool, resume_results: list[dict[str, object]]) -> str:
    if not resume_codex_projects:
        return "run with --resume-codex-projects to resume matched codex-projects threads"
    if not resume_results:
        return "no ready codex-projects threads were resumed"
    if any(item["status"] == "failed" for item in resume_results):
        return "inspect failed codex-projects resume results before retrying"
    if any(item["status"] == "not_found" for item in resume_results):
        return "register or correct owner_thread in codex-projects before retrying missing continuations"
    return "ready codex-projects continuations have been handed to tmux"


def usage_continuation_request_status(request: UsageContinuationRequest) -> dict[str, object]:
    return {
        "id": request.id,
        "limit_id": request.limit_id,
        "resource_id": request.resource_id,
        "owner_thread": request.owner_thread,
        "requested_units": request.requested_units,
        "intent": request.intent,
        "risk_level": RiskLevel(request.risk_level).value,
        "earliest_start": request.earliest_start,
        "deadline": request.deadline,
        "requested_by": request.requested_by,
        "requested_at": request.requested_at,
    }


def usage_continuation_dispatch_status(dispatch: UsageContinuationDispatch) -> dict[str, object]:
    return {
        "id": dispatch.id,
        "request_id": dispatch.request_id,
        "limit_id": dispatch.limit_id,
        "resource_id": dispatch.resource_id,
        "owner_thread": dispatch.owner_thread,
        "status": dispatch.status,
        "reason": dispatch.reason,
        "dispatched_by": dispatch.dispatched_by,
        "dispatched_at": dispatch.dispatched_at,
        "scheduled_for": dispatch.scheduled_for,
        "resume_status": dispatch.resume_status,
        "resume_reason": dispatch.resume_reason,
        "resume_conversation_id": dispatch.resume_conversation_id,
        "resume_project": dispatch.resume_project,
        "resume_command": dispatch.resume_command,
        "resume_launcher": dispatch.resume_launcher,
        "resume_exit_code": dispatch.resume_exit_code,
    }


def codex_project_resume_status(result) -> dict[str, object]:
    return {
        "owner_thread": result.owner_thread,
        "status": result.status,
        "reason": result.reason,
        "conversation_id": result.conversation_id,
        "project": result.project,
        "command": result.command,
        "launcher": result.launcher,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def scheduled_work_status(work) -> dict[str, object]:
    return {
        "id": work.id,
        "owner_thread": work.owner_thread,
        "resource_id": work.resource_id,
        "status": ScheduledWorkStatus(work.status).value,
        "reason": work.reason,
        "scheduled_for": work.scheduled_for,
        "blocking_ids": work.blocking_ids,
    }


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


def audit_summary_status(
    store_path: str | Path,
    event_type: str | None = None,
    owner: str | None = None,
    subject_prefix: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        events = list(store.list_audit_events())
        if event_type:
            selected_event_type = AuditEventType(event_type)
            events = [event for event in events if event.event_type == selected_event_type]
        if owner:
            selected_owner = OwnerDomain(owner)
            events = [event for event in events if event.owner_domain == selected_owner]
        if subject_prefix:
            events = [event for event in events if event.subject_id.startswith(subject_prefix)]
        return {
            "store": str(store.path),
            "events": [audit_event_status(event) for event in events],
            "event_count": len(events),
            "by_event_type": {
                item.value: sum(1 for event in events if event.event_type == item)
                for item in AuditEventType
            },
            "by_owner": {
                item.value: sum(1 for event in events if event.owner_domain == item)
                for item in OwnerDomain
            },
            "by_risk": {
                item.value: sum(1 for event in events if event.risk_level == item)
                for item in RiskLevel
            },
            "filters": {
                "event_type": event_type,
                "owner": owner,
                "subject_prefix": subject_prefix,
            },
        }
    finally:
        store.close()


def approvals_summary_status(
    store_path: str | Path,
    status: str | None = None,
    owner: str | None = None,
    approval_level: str | None = None,
    subject_prefix: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        approvals = list(store.list_approvals())
        if status:
            selected_status = ApprovalStatus(status)
            approvals = [approval for approval in approvals if approval.status == selected_status]
        if owner:
            selected_owner = OwnerDomain(owner)
            approvals = [approval for approval in approvals if approval.owner_domain == selected_owner]
        if approval_level:
            selected_level = ApprovalLevel(approval_level)
            approvals = [approval for approval in approvals if approval.approval_level == selected_level]
        if subject_prefix:
            approvals = [approval for approval in approvals if approval.subject_id.startswith(subject_prefix)]
        return {
            "store": str(store.path),
            "approvals": [approval_request_status(approval) for approval in approvals],
            "approval_count": len(approvals),
            "pending_count": sum(1 for approval in approvals if approval.status == ApprovalStatus.PENDING),
            "approved_count": sum(1 for approval in approvals if approval.status == ApprovalStatus.APPROVED),
            "by_status": {
                item.value: sum(1 for approval in approvals if approval.status == item)
                for item in ApprovalStatus
            },
            "by_owner": {
                item.value: sum(1 for approval in approvals if approval.owner_domain == item)
                for item in OwnerDomain
            },
            "by_approval_level": {
                item.value: sum(1 for approval in approvals if approval.approval_level == item)
                for item in ApprovalLevel
            },
            "filters": {
                "status": status,
                "owner": owner,
                "approval_level": approval_level,
                "subject_prefix": subject_prefix,
            },
        }
    finally:
        store.close()


def approval_request_status(approval: ApprovalRequest) -> dict[str, object]:
    return {
        "id": approval.id,
        "subject_id": approval.subject_id,
        "approval_level": ApprovalLevel(approval.approval_level).value,
        "requester_thread": approval.requester_thread,
        "owner_domain": OwnerDomain(approval.owner_domain).value,
        "reason": approval.reason,
        "status": ApprovalStatus(approval.status).value,
        "evidence_required": list(approval.evidence_required),
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
    }


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


def claim_review_status(store_path: str | Path, now: str | None = None) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        checked_at = _parse_optional_datetime(now) or datetime.now(UTC)
        resources = {resource.id: resource for resource in store.list_resources()}
        items = [claim_review_item_status(claim, resources.get(claim.resource_id), checked_at) for claim in store.list_claims()]
        return {
            "store": str(store.path),
            "checked_at": checked_at.isoformat(),
            "claims": len(items),
            "active_like": sum(1 for item in items if item["active_like"]),
            "queued": sum(1 for item in items if item["status"] == ClaimStatus.QUEUED.value),
            "expired_active_like": sum(1 for item in items if item["expired"] and item["active_like"]),
            "missing_release_condition": sum(1 for item in items if item["missing_release_condition"]),
            "operator_review_required": sum(1 for item in items if item["operator_review_required"]),
            "items": items,
        }
    finally:
        store.close()


def claim_cleanup_plan_status(store_path: str | Path, now: str | None = None) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        checked_at = _parse_optional_datetime(now) or datetime.now(UTC)
        resources = {resource.id: resource for resource in store.list_resources()}
        claims = store.list_claims()
        claims_by_id = {claim.id: claim for claim in claims}
        items = [
            claim_cleanup_plan_item_status(store, claim, resources.get(claim.resource_id), claims_by_id, checked_at)
            for claim in claims
        ]
        candidates = [item for item in items if item["cleanup_candidate"]]
        return {
            "store": str(store.path),
            "checked_at": checked_at.isoformat(),
            "mutation_performed": False,
            "claims": len(items),
            "cleanup_candidates": len(candidates),
            "expired_active_like": sum(1 for item in candidates if item["cleanup_action"] == "review_expired_active_claim"),
            "missing_release_condition": sum(1 for item in candidates if item["cleanup_action"] == "add_release_condition_or_evidence"),
            "stale_queued": sum(1 for item in candidates if item["cleanup_action"] == "re_evaluate_stale_queue"),
            "blocked": sum(1 for item in candidates if item["cleanup_action"] == "review_blocked_claim"),
            "approval_required": any(item["approval_required"] for item in candidates),
            "items": candidates,
        }
    finally:
        store.close()


def request_claim_cleanup_status(
    store_path: str | Path,
    claim_id: str,
    requested_by: str,
    requested_at: str | None = None,
    now: str | None = None,
) -> dict[str, object]:
    if not claim_id.strip():
        raise ValueError("claim_id is required")
    if not requested_by.strip():
        raise ValueError("requested_by is required")
    store = SQLiteStore(store_path)
    try:
        checked_at = _parse_optional_datetime(now) or datetime.now(UTC)
        item = _claim_cleanup_candidate_for_store(store, claim_id, checked_at)
        approval_level = _claim_cleanup_approval_level(item)
        subject_id = f"claim.cleanup.{claim_id}"
        approval = ApprovalRequest(
            id=f"approval.claim.cleanup.{claim_id}",
            subject_id=subject_id,
            approval_level=approval_level,
            requester_thread=requested_by,
            owner_domain=OwnerDomain.SISKO,
            reason=f"Approve cleanup action {item['cleanup_action']} for claim {claim_id}",
            evidence_required=(f"claim.cleanup-plan.{claim_id}",),
        )
        event = AuditEvent(
            id=f"audit.{approval.id}.requested",
            event_type=AuditEventType.REQUESTED,
            owner_domain=OwnerDomain.SISKO,
            subject_id=subject_id,
            summary=approval.reason,
            risk_level=_claim_cleanup_risk_level(item),
            evidence_ids=approval.evidence_required,
            occurred_at=requested_at,
        )
        store.save_approval(approval)
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "mutation_performed": True,
            "claim_id": claim_id,
            "cleanup_action": item["cleanup_action"],
            "approval_id": approval.id,
            "subject_id": approval.subject_id,
            "approval_status": ApprovalStatus(approval.status).value,
            "approval_level": ApprovalLevel(approval.approval_level).value,
            "requested_by": requested_by,
            "requested_at": requested_at,
            "checked_at": checked_at.isoformat(),
            "cleanup_plan_item": item,
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def approve_claim_cleanup_status(
    store_path: str | Path,
    approval_id: str,
    approved_by: str,
    approved_at: str | None = None,
    now: str | None = None,
) -> dict[str, object]:
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"claim cleanup approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.claim.cleanup."):
            raise ValueError("claim cleanup approval is required")
        claim_id = _claim_cleanup_claim_id_from_subject(approval.subject_id)
        checked_at = _parse_optional_datetime(now) or datetime.now(UTC)
        item = _claim_cleanup_candidate_for_store(store, claim_id, checked_at)
    finally:
        store.close()

    approved = approve_claim_status(store_path, approval_id, approved_by, approved_at)
    return {
        **approved,
        "claim_id": claim_id,
        "claim_cleanup_approval": True,
        "cleanup_action": item["cleanup_action"],
        "cleanup_plan_item": item,
    }


def execute_claim_cleanup_status(
    store_path: str | Path,
    approval_id: str,
    executed_by: str,
    executed_at: str | None = None,
    now: str | None = None,
) -> dict[str, object]:
    if not approval_id.strip():
        raise ValueError("approval_id is required")
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    store = SQLiteStore(store_path)
    try:
        try:
            approval = store.load_approval(approval_id)
        except KeyError:
            raise ValueError(f"claim cleanup approval does not exist: {approval_id}") from None
        if not approval.id.startswith("approval.claim.cleanup."):
            raise ValueError("claim cleanup approval is required")
        if not approval.can_execute():
            raise ValueError("claim cleanup approval is not approved")
        claim_id = _claim_cleanup_claim_id_from_subject(approval.subject_id)
        checked_at = _parse_optional_datetime(now) or datetime.now(UTC)
        before = _claim_cleanup_candidate_for_store(store, claim_id, checked_at)
        claim = store.load_claim(claim_id)
        resource = store.load_resource(claim.resource_id)
        if before["cleanup_action"] == "review_expired_active_claim":
            updated_claim = replace(claim, status=ClaimStatus.EXPIRED, evidence_ids=tuple((*claim.evidence_ids, approval_id)))
            updated_resource = resource
            if resource.current_claim_id == claim.id:
                updated_resource = replace(resource, state=ResourceState.AVAILABLE, current_claim_id=None)
            store.save_claim(updated_claim)
            store.save_resource(updated_resource)
            execution_action = "expired_claim_released_from_resource"
        elif before["cleanup_action"] == "re_evaluate_stale_queue":
            updated_claim, decision = _re_evaluate_stale_queued_claim(store, claim, approval_id)
            store.save_claim(updated_claim, decision)
            execution_action = f"stale_queue_re_evaluated_{decision.outcome.value}"
        elif before["cleanup_action"] == "add_release_condition_or_evidence":
            updated_claim = replace(claim, status=ClaimStatus.RELEASING, evidence_ids=tuple((*claim.evidence_ids, approval_id)))
            store.save_claim(updated_claim)
            execution_action = "release_evidence_required_claim_marked_releasing"
        elif before["cleanup_action"] == "review_blocked_claim":
            updated_claim = replace(claim, status=ClaimStatus.REVOKED, evidence_ids=tuple((*claim.evidence_ids, approval_id)))
            store.save_claim(updated_claim)
            execution_action = "blocked_claim_revoked"
        else:
            raise ValueError(f"cleanup action is not executable yet: {before['cleanup_action']}")
        event = AuditEvent(
            id=f"audit.{approval.id}.executed",
            event_type=AuditEventType.EXECUTED,
            owner_domain=OwnerDomain.SISKO,
            subject_id=approval.subject_id,
            summary=f"Executed claim cleanup action {before['cleanup_action']} for {claim_id}",
            risk_level=_claim_cleanup_risk_level(before),
            evidence_ids=(approval_id,),
            occurred_at=executed_at,
        )
        store.save_audit_event(event)
        after_claim = store.load_claim(claim_id)
        return {
            "store": str(store.path),
            "mutation_performed": True,
            "claim_id": claim_id,
            "approval_id": approval.id,
            "executed_by": executed_by,
            "executed_at": executed_at,
            "checked_at": checked_at.isoformat(),
            "cleanup_action": before["cleanup_action"],
            "execution_action": execution_action,
            "claim_status_before": ClaimStatus(claim.status).value,
            "claim_status_after": ClaimStatus(after_claim.status).value,
            "resource_id": after_claim.resource_id,
            "audit_event": audit_event_status(event),
        }
    finally:
        store.close()


def claim_cleanup_approval_status(approval: ApprovalRequest) -> dict[str, object]:
    approval_status = ApprovalStatus(approval.status)
    return {
        "id": approval.id,
        "claim_id": _claim_cleanup_claim_id_from_subject(approval.subject_id),
        "subject_id": approval.subject_id,
        "approval_level": ApprovalLevel(approval.approval_level).value,
        "requester_thread": approval.requester_thread,
        "owner_domain": OwnerDomain(approval.owner_domain).value,
        "reason": approval.reason,
        "status": approval_status.value,
        "evidence_required": list(approval.evidence_required),
        "decided_by": approval.decided_by,
        "decided_at": approval.decided_at,
        "next_step": _claim_cleanup_approval_next_step(approval_status),
    }


def _claim_cleanup_candidate_for_store(store: SQLiteStore, claim_id: str, checked_at: datetime) -> dict[str, object]:
    try:
        claim = store.load_claim(claim_id)
    except KeyError:
        raise ValueError(f"claim does not exist: {claim_id}") from None
    resources = {resource.id: resource for resource in store.list_resources()}
    claims_by_id = {item.id: item for item in store.list_claims()}
    item = claim_cleanup_plan_item_status(store, claim, resources.get(claim.resource_id), claims_by_id, checked_at)
    if not item["cleanup_candidate"]:
        raise ValueError(f"claim is not a cleanup candidate: {claim_id}")
    return item


def _claim_cleanup_approval_level(item: dict[str, object]) -> ApprovalLevel:
    if item["approval_required"]:
        return ApprovalLevel.SISKO
    if item["cleanup_action"] in {"review_blocked_claim", "re_evaluate_stale_queue"}:
        return ApprovalLevel.ROLE
    return ApprovalLevel.SISKO


def _claim_cleanup_risk_level(item: dict[str, object]) -> RiskLevel:
    if item["approval_required"]:
        return RiskLevel.HIGH
    if item["cleanup_action"] == "re_evaluate_stale_queue":
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _claim_cleanup_claim_id_from_subject(subject_id: str) -> str:
    prefix = "claim.cleanup."
    if not subject_id.startswith(prefix):
        raise ValueError("claim cleanup approval subject is required")
    return subject_id[len(prefix):]


def _claim_cleanup_approval_next_step(approval_status: ApprovalStatus) -> str:
    if approval_status == ApprovalStatus.PENDING:
        return "approve-claim-cleanup before cleanup mutation can be implemented or executed"
    if approval_status == ApprovalStatus.APPROVED:
        return "execute-claim-cleanup may proceed only for the approved claim and cleanup action"
    return "claim cleanup approval is not actionable"


def _re_evaluate_stale_queued_claim(
    store: SQLiteStore,
    claim: Claim,
    approval_id: str,
):
    resources_by_id = {resource.id: resource for resource in store.list_resources()}
    resource = resources_by_id[claim.resource_id]
    active_claims = [
        item
        for item in store.list_claims()
        if item.id != claim.id and item.is_active_like()
    ]
    decision = decide_claim(resource, claim, active_claims, resources_by_id)
    if decision.outcome == ConflictOutcome.ALLOW:
        status = ClaimStatus.APPROVED
    elif decision.outcome == ConflictOutcome.QUEUE:
        status = ClaimStatus.QUEUED
    elif decision.outcome == ConflictOutcome.ESCALATE:
        status = ClaimStatus.REQUESTED
    elif decision.outcome == ConflictOutcome.QUARANTINE:
        status = ClaimStatus.BLOCKED
    else:
        status = ClaimStatus.BLOCKED
    updated = replace(claim, status=status, approval_id=approval_id, evidence_ids=tuple((*claim.evidence_ids, approval_id)))
    return updated, decision


def claim_cleanup_plan_item_status(
    store: SQLiteStore,
    claim: Claim,
    resource: Resource | None,
    claims_by_id: dict[str, Claim],
    checked_at: datetime,
) -> dict[str, object]:
    review = claim_review_item_status(claim, resource, checked_at)
    blocking_claim_ids = _claim_blocking_claim_ids(store, claim.id)
    active_blocking_claim_ids = [
        blocking_id
        for blocking_id in blocking_claim_ids
        if blocking_id in claims_by_id and claims_by_id[blocking_id].is_active_like()
    ]
    cleanup_action = "none"
    next_step = "no cleanup action required"
    approval_required = False
    required_gate = "none"

    if review["expired"] and review["active_like"]:
        cleanup_action = "review_expired_active_claim"
        next_step = "operator must approve release, revocation, renewal, or takeover"
        approval_required = True
        required_gate = "operator_review"
    elif review["missing_release_condition"]:
        cleanup_action = "add_release_condition_or_evidence"
        next_step = "record release condition or evidence before cleanup can proceed"
        required_gate = "owner_evidence"
    elif claim.status == ClaimStatus.QUEUED and blocking_claim_ids and not active_blocking_claim_ids:
        cleanup_action = "re_evaluate_stale_queue"
        next_step = "re-run the claim decision because recorded blockers are no longer active-like"
        required_gate = "decision_review"
    elif claim.status == ClaimStatus.BLOCKED:
        cleanup_action = "review_blocked_claim"
        next_step = "operator should cancel, revise, or re-request the blocked claim"
        required_gate = "operator_review"

    return {
        **review,
        "cleanup_candidate": cleanup_action != "none",
        "cleanup_action": cleanup_action,
        "cleanup_next_step": next_step,
        "approval_required": approval_required,
        "required_gate": required_gate,
        "blocking_claim_ids": blocking_claim_ids,
        "active_blocking_claim_ids": active_blocking_claim_ids,
    }


def _claim_blocking_claim_ids(store: SQLiteStore, claim_id: str) -> list[str]:
    try:
        decision = store.load_decision(claim_id)
    except KeyError:
        return []
    return list(decision.blocking_claim_ids)


def claim_review_item_status(claim: Claim, resource: Resource | None, checked_at: datetime) -> dict[str, object]:
    expired = _claim_is_expired(claim, checked_at)
    missing_release_condition = claim.is_exclusive() and claim.is_active_like() and not claim.release_condition
    return {
        "id": claim.id,
        "resource_id": claim.resource_id,
        "resource_name": resource.name if resource else None,
        "resource_owner": OwnerDomain(resource.owner_domain).value if resource else None,
        "claim_type": ClaimType(claim.claim_type).value,
        "owner_thread": claim.owner_thread,
        "owner_role": OwnerDomain(claim.owner_role).value,
        "status": ClaimStatus(claim.status).value,
        "active_like": claim.is_active_like(),
        "exclusive": claim.is_exclusive(),
        "starts_at": claim.starts_at,
        "expires_at": claim.expires_at,
        "release_condition": claim.release_condition,
        "expired": expired,
        "missing_release_condition": missing_release_condition,
        "operator_review_required": (expired and claim.is_active_like()) or missing_release_condition,
        "next_step": _claim_review_next_step(claim, expired, missing_release_condition),
    }


def _claim_review_next_step(claim: Claim, expired: bool, missing_release_condition: bool) -> str:
    if expired and claim.is_active_like():
        return "operator review required before release, revocation, renewal, or takeover"
    if missing_release_condition:
        return "add release evidence or release condition before considering the resource available"
    if claim.status == ClaimStatus.QUEUED:
        return "wait for blocking claim release or re-evaluate after operator review"
    if claim.status == ClaimStatus.ACTIVE:
        return "monitor release condition"
    return "no operator action required"


def _claim_is_expired(claim: Claim, checked_at: datetime) -> bool:
    expires_at = _parse_optional_datetime(claim.expires_at)
    return expires_at is not None and expires_at <= checked_at


def _parse_optional_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def list_state_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        schema_migrations = store.list_schema_migrations()
        resources = store.list_resources()
        usage_limits = store.list_usage_limits()
        usage_continuation_requests = store.list_usage_continuation_requests()
        usage_continuation_dispatches = store.list_usage_continuation_dispatches()
        health_targets = store.list_health_targets()
        health_evidence = store.list_health_evidence()
        claims = store.list_claims()
        approvals = store.list_approvals()
        audit_events = store.list_audit_events()
        heartbeats = store.list_runtime_heartbeats()
        host_snapshots = store.list_host_snapshots()
        source_reviews = store.list_host_security_source_reviews()
        ids_review_packages = store.list_host_security_ids_review_packages()
        admin_change_plans = store.list_admin_change_plans()
        admin_executions = store.list_admin_executions()
        admin_history_archives = store.list_admin_history_archives()
        return {
            "store": str(store.path),
            "schema_migrations": [schema_migration_status(migration) for migration in schema_migrations],
            "resources": [resource_status(resource) for resource in resources],
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
            "usage_limits": [usage_limit_status(limit) for limit in usage_limits],
            "usage_continuation_requests": [
                usage_continuation_request_status(request)
                for request in usage_continuation_requests
            ],
            "usage_continuation_dispatches": [
                usage_continuation_dispatch_status(dispatch)
                for dispatch in usage_continuation_dispatches
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
                    "starts_at": claim.starts_at,
                    "expires_at": claim.expires_at,
                    "release_condition": claim.release_condition,
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
                    "archived": plan.archived,
                    "archive_record_id": plan.archive_record_id,
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
            "admin_history_archives": [
                admin_history_archive_record_status(record)
                for record in admin_history_archives
            ],
            "host_security_source_reviews": [host_security_source_review_status(review) for review in source_reviews],
            "host_security_ids_review_packages": [
                host_security_ids_review_package_status(package) for package in ids_review_packages
            ],
        }
    finally:
        store.close()


def resource_status(resource: Resource) -> dict[str, object]:
    return {
        "id": resource.id,
        "name": resource.name,
        "type": ResourceType(resource.type).value,
        "owner_domain": OwnerDomain(resource.owner_domain).value,
        "risk_level": RiskLevel(resource.risk_level).value,
        "state": ResourceState(resource.state).value,
        "identifiers": dict(resource.identifiers),
        "dependencies": sorted(resource.dependencies),
        "exclusive_groups": sorted(resource.exclusive_groups),
        "current_claim_id": resource.current_claim_id,
        "last_verified_at": resource.last_verified_at,
        "notes": resource.notes,
    }


def _json_object_arg(value: str, label: str) -> dict[str, object]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object")
    return parsed


def schema_migration_status(migration: SchemaMigration) -> dict[str, object]:
    return {
        "version": migration.version,
        "description": migration.description,
        "applied_at": migration.applied_at,
    }


REDACTED_EXPORT_FIELD_KEYS = (
    "advisory",
    "command",
    "error",
    "hostname",
    "listener",
    "output",
    "path",
    "prompt",
    "reason",
    "remote_address",
    "store",
    "summary",
    "target",
)
REDACTED_EXPORT_KEY_PARTS = SECRET_KEY_PARTS + REDACTED_EXPORT_FIELD_KEYS


def export_state_redacted_status(store_path: str | Path) -> dict[str, object]:
    state = list_state_status(store_path)
    redacted, redactions = _redact_export_value(state)
    if not isinstance(redacted, dict):
        raise ValueError("redacted state export must be an object")
    redacted["export"] = {
        "mode": "redacted",
        "mutation_performed": False,
        "redaction_count": len(redactions),
        "redacted_paths": redactions,
        "redaction_policy": {
            "key_parts": list(REDACTED_EXPORT_KEY_PARTS),
            "replacement": "[REDACTED]",
        },
    }
    return redacted


def _redact_export_value(value: object, path: str = "$") -> tuple[object, list[str]]:
    if isinstance(value, dict):
        output: dict[str, object] = {}
        redactions: list[str] = []
        for key, nested in value.items():
            child_path = f"{path}.{key}"
            if _export_key_requires_redaction(str(key)):
                output[str(key)] = "[REDACTED]"
                redactions.append(child_path)
                continue
            redacted, child_redactions = _redact_export_value(nested, child_path)
            output[str(key)] = redacted
            redactions.extend(child_redactions)
        return output, redactions
    if isinstance(value, list):
        output_items: list[object] = []
        redactions: list[str] = []
        for index, item in enumerate(value):
            redacted, item_redactions = _redact_export_value(item, f"{path}[{index}]")
            output_items.append(redacted)
            redactions.extend(item_redactions)
        return output_items, redactions
    return value, []


def _export_key_requires_redaction(key: str) -> bool:
    lowered = key.lower()
    if any(part in lowered for part in SECRET_KEY_PARTS):
        return True
    return any(lowered == part or lowered.endswith(f"_{part}") for part in REDACTED_EXPORT_FIELD_KEYS)


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
    starts_at: str | None = None,
    expires_at: str | None = None,
    release_condition: str | None = None,
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
                starts_at=starts_at,
                expires_at=expires_at,
                release_condition=release_condition,
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


def release_claim_status(
    store_path: str | Path,
    claim_id: str,
    released_by: str | None = None,
    reason: str | None = None,
    evidence_ids: Sequence[str] = (),
    released_at: str | None = None,
) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        coordinator = coordinator_from_store(store)
        existing = store.load_claim(claim_id)
        claim = coordinator.release_claim(claim_id)
        release_reason = reason or "claim released by operator"
        event = AuditEvent(
            id=f"audit.{claim.id}.released",
            event_type=AuditEventType.RELEASED,
            owner_domain=claim.owner_role,
            subject_id=claim.id,
            summary=release_reason,
            risk_level=existing.risk_level,
            evidence_ids=tuple(evidence_ids),
            occurred_at=released_at,
        )
        store.save_audit_event(event)
        return {
            "store": str(store.path),
            "claim": claim.id,
            "claim_status": claim.status.value,
            "released_by": released_by,
            "reason": release_reason,
            "release_evidence_complete": bool(evidence_ids),
            "audit_event": audit_event_status(event),
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
    record_resource_parser = subparsers.add_parser("record-resource", help="record or update a managed resource")
    record_resource_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    record_resource_parser.add_argument("--resource-id", required=True)
    record_resource_parser.add_argument("--name", required=True)
    record_resource_parser.add_argument("--resource-type", required=True, choices=[item.value for item in ResourceType])
    record_resource_parser.add_argument("--owner-domain", required=True, choices=[item.value for item in OwnerDomain])
    record_resource_parser.add_argument("--risk-level", required=True, choices=[item.value for item in RiskLevel])
    record_resource_parser.add_argument("--state", default=ResourceState.AVAILABLE.value, choices=[item.value for item in ResourceState])
    record_resource_parser.add_argument("--identifier-json", default="{}", help="JSON object with structured resource identifiers")
    record_resource_parser.add_argument("--dependency", action="append", default=())
    record_resource_parser.add_argument("--exclusive-group", action="append", default=())
    record_resource_parser.add_argument("--current-claim-id")
    record_resource_parser.add_argument("--last-verified-at")
    record_resource_parser.add_argument("--notes", default="")
    probe_parser = subparsers.add_parser("probe-health", help="run a read-only health probe for an explicit target")
    probe_parser.add_argument("--resource-id", required=True)
    probe_parser.add_argument("--name", required=True)
    probe_parser.add_argument("--url", required=True, help="HTTP URL or process target such as systemd:user:overseer-api.service")
    probe_parser.add_argument("--probe-type", default=ProbeType.HTTP.value, choices=[item.value for item in ProbeType])
    probe_parser.add_argument("--expected-status", type=int)
    probe_parser.add_argument("--expected-content-type")
    probe_parser.add_argument("--timeout-seconds", type=float, default=5.0)
    probe_parser.add_argument("--store", help="explicit SQLite store path for persisting health evidence")
    probe_config_parser = subparsers.add_parser("probe-config", help="probe health targets declared in explicit JSON config")
    probe_config_parser.add_argument("--config", required=True, help="explicit JSON config path")
    probe_config_parser.add_argument("--store", help="explicit SQLite store path for persisting health evidence")
    probe_config_parser.add_argument("--timeout-seconds", type=float, default=5.0)
    probe_stored_health_parser = subparsers.add_parser("probe-stored-health", help="probe health targets already persisted in a SQLite store")
    probe_stored_health_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    probe_stored_health_parser.add_argument("--timeout-seconds", type=float, default=5.0)
    probe_stored_health_parser.add_argument("--retention-per-target", type=int)
    record_health_target_parser = subparsers.add_parser("record-health-target", help="record or update a persisted health target")
    record_health_target_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    record_health_target_parser.add_argument("--target-id", required=True)
    record_health_target_parser.add_argument("--resource-id", required=True)
    record_health_target_parser.add_argument("--name", required=True)
    record_health_target_parser.add_argument("--probe-type", required=True, choices=[item.value for item in ProbeType])
    record_health_target_parser.add_argument("--target", required=True)
    record_health_target_parser.add_argument("--owner-domain", default=OwnerDomain.JULIAN.value, choices=[item.value for item in OwnerDomain])
    record_health_target_parser.add_argument("--expected-status", type=int)
    record_health_target_parser.add_argument("--expected-content-type")
    record_health_target_parser.add_argument("--latency-warn-ms", type=int)
    discover_parser = subparsers.add_parser("discover-physical", help="read directory entries for physical device paths")
    discover_parser.add_argument("--root", action="append", required=True, help="directory root to inspect")
    discover_parser.add_argument("--store", help="explicit SQLite store path for persisting discovered path identities")
    discover_storage_parser = subparsers.add_parser("discover-storage", help="read sysfs block devices as physical storage identities")
    discover_storage_parser.add_argument("--sysfs-block-root", default="/sys/class/block", help="sysfs block root to inspect")
    discover_storage_parser.add_argument("--store", help="explicit SQLite store path for persisting discovered storage identities")
    physical_summary_parser = subparsers.add_parser("physical-summary", help="summarize persisted physical identities")
    physical_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    virtual_summary_parser = subparsers.add_parser("virtual-summary", help="summarize persisted virtual assets")
    virtual_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    discover_virtual_parser = subparsers.add_parser("discover-virtual-listeners", help="discover local TCP listeners as virtual assets")
    discover_virtual_parser.add_argument("--store", required=True, help="explicit SQLite store path for persisting discovered listener resources")
    command_summary_parser = subparsers.add_parser("command-summary", help="summarize command-level Overseer state")
    command_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    command_summary_parser.add_argument("--service-name", default="overseer")
    operator_dashboard_parser = subparsers.add_parser("operator-dashboard", help="summarize all Overseer operator domains")
    operator_dashboard_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    operator_dashboard_parser.add_argument("--service-name", default="overseer")
    maintenance_summary_parser = subparsers.add_parser("maintenance-summary", help="summarize maintenance and update plans")
    maintenance_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    inspect_packages_parser = subparsers.add_parser("inspect-packages", help="read apt package update availability without changing packages")
    inspect_packages_parser.add_argument("--captured-at", help="optional deterministic capture timestamp")
    plan_package_updates_parser = subparsers.add_parser(
        "plan-package-updates",
        help="stage approval-gated apt update and upgrade plans from current package inspection",
    )
    plan_package_updates_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    plan_package_updates_parser.add_argument("--captured-at", help="optional deterministic capture timestamp")
    plan_package_updates_parser.add_argument("--package", action="append", default=(), help="limit upgrade plan to a detected package")
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
    redacted_state_parser = subparsers.add_parser("export-state-redacted", help="print a redacted state export without writing files")
    redacted_state_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    service_parser = subparsers.add_parser("service-status", help="read stored runtime heartbeat for a local Overseer service")
    service_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    service_parser.add_argument("--service-name", default="overseer")
    runtime_status_parser = subparsers.add_parser("runtime-status", help="read runtime heartbeat and latest host inspection status")
    runtime_status_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    runtime_status_parser.add_argument("--service-name", default="overseer")
    daemon_plan_parser = subparsers.add_parser("daemon-migration-plan", help="prepare a read-only foreground-to-daemon migration approval plan")
    daemon_plan_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    daemon_plan_parser.add_argument("--service-name", default="overseer")
    daemon_request_parser = subparsers.add_parser("request-daemon-migration", help="request approval before daemon migration")
    daemon_request_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    daemon_request_parser.add_argument("--service-name", default="overseer")
    daemon_request_parser.add_argument("--requested-by", required=True)
    daemon_request_parser.add_argument("--requested-at")
    daemon_approve_parser = subparsers.add_parser("approve-daemon-migration", help="approve a requested daemon migration")
    daemon_approve_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    daemon_approve_parser.add_argument("--approval-id", required=True)
    daemon_approve_parser.add_argument("--approved-by", required=True)
    daemon_approve_parser.add_argument("--approved-at")
    persistence_security_parser = subparsers.add_parser(
        "persistence-security",
        help="inspect SQLite store file ownership and permissions without changing them",
    )
    persistence_security_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    alerts_summary_parser = subparsers.add_parser("alerts-summary", help="summarize persisted alert audit events")
    alerts_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    audit_summary_parser = subparsers.add_parser("audit-summary", help="summarize persisted audit events")
    audit_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    audit_summary_parser.add_argument("--event-type", choices=[item.value for item in AuditEventType])
    audit_summary_parser.add_argument("--owner", choices=[item.value for item in OwnerDomain])
    audit_summary_parser.add_argument("--subject-prefix")
    approvals_summary_parser = subparsers.add_parser("approvals-summary", help="summarize stored approvals with optional filters")
    approvals_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    approvals_summary_parser.add_argument("--status", choices=[item.value for item in ApprovalStatus])
    approvals_summary_parser.add_argument("--owner", choices=[item.value for item in OwnerDomain])
    approvals_summary_parser.add_argument("--approval-level", choices=[item.value for item in ApprovalLevel])
    approvals_summary_parser.add_argument("--subject-prefix")
    inspect_parser = subparsers.add_parser("inspect-host", help="capture read-only host admin evidence")
    inspect_parser.add_argument("--store", help="explicit SQLite store path for persisting the host snapshot")
    discover_services_parser = subparsers.add_parser("discover-user-services", help="discover running systemd user services as Overseer service resources")
    discover_services_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    assess_host_parser = subparsers.add_parser("assess-host-security", help="assess a persisted host snapshot for exposure findings")
    assess_host_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    assess_host_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    host_findings_parser = subparsers.add_parser("host-security-findings", help="list host security findings")
    host_findings_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    host_findings_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    host_findings_parser.add_argument("--severity", choices=[item.value for item in HostFindingSeverity])
    host_triage_parser = subparsers.add_parser("host-security-triage", help="group host security findings by listener")
    host_triage_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    host_triage_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    listener_queue_parser = subparsers.add_parser("host-security-listener-review-queue", help="summarize exposed listener review and remediation-plan state")
    listener_queue_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    listener_queue_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    listener_queue_plan_parser = subparsers.add_parser(
        "plan-host-security-listener-queue-remediations",
        help="stage approval-gated firewall deny plans for unplanned listener queue ports",
    )
    listener_queue_plan_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    listener_queue_plan_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    listener_queue_plan_parser.add_argument("--requested-by", default="odo")
    listener_queue_plan_parser.add_argument("--plan-prefix", default="admin.host-security.deny-tcp")
    host_sources_parser = subparsers.add_parser("host-security-sources", help="correlate established TCP sources to host security listeners")
    host_sources_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    host_sources_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    source_queue_parser = subparsers.add_parser("host-security-source-review-queue", help="summarize current source review and block-readiness queue")
    source_queue_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    source_queue_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    source_reviews_parser = subparsers.add_parser("host-security-source-reviews", help="list host security source reviews")
    source_reviews_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    create_source_review_parser = subparsers.add_parser("create-host-security-source-review", help="record Odo review of a correlated source")
    create_source_review_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    create_source_review_parser.add_argument("--remote-address", required=True)
    create_source_review_parser.add_argument("--listener")
    create_source_review_parser.add_argument("--review-id")
    create_source_review_parser.add_argument("--disposition", default=SourceReviewDisposition.NEEDS_REVIEW.value, choices=[item.value for item in SourceReviewDisposition])
    create_source_review_parser.add_argument("--rationale", default="pending Odo review")
    create_source_review_parser.add_argument("--reviewed-by")
    create_source_review_parser.add_argument("--reviewed-at")
    create_source_review_parser.add_argument("--created-at")
    create_source_review_parser.add_argument("--snapshot-id")
    source_block_parser = subparsers.add_parser(
        "plan-host-security-source-block",
        help="stage an approval-gated source block from an Odo-reviewed hostile source",
    )
    source_block_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    source_block_parser.add_argument("--review-id", required=True)
    source_block_parser.add_argument("--plan-id")
    source_block_parser.add_argument("--action", default="block_ip")
    source_block_parser.add_argument("--reason")
    ids_reviews_parser = subparsers.add_parser("host-security-ids-review-packages", help="list prepared IDS/firewall review packages")
    ids_reviews_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    ids_review_summary_parser = subparsers.add_parser(
        "host-security-ids-review-summary",
        help="summarize IDS/firewall review package gate state without full prompts",
    )
    ids_review_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    prepare_ids_review_parser = subparsers.add_parser(
        "prepare-host-security-ids-review-package",
        help="prepare an Intrusion Detection advisory package for a staged security admin plan",
    )
    prepare_ids_review_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    prepare_ids_review_parser.add_argument("--plan-id", required=True)
    prepare_ids_review_parser.add_argument("--package-id")
    prepare_ids_review_parser.add_argument("--source-review-id")
    prepare_ids_review_parser.add_argument("--requested-by", default="odo")
    prepare_ids_review_parser.add_argument("--created-at")
    submit_ids_review_parser = subparsers.add_parser(
        "submit-host-security-ids-review-package",
        help="record that an IDS/firewall review package was handed off for advisory review",
    )
    submit_ids_review_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    submit_ids_review_parser.add_argument("--package-id", required=True)
    submit_ids_review_parser.add_argument("--submitted-by", required=True)
    submit_ids_review_parser.add_argument("--submitted-at")
    submit_ids_review_parser.add_argument("--prompt-path")
    export_ids_review_parser = subparsers.add_parser(
        "export-host-security-ids-review-prompt",
        help="write an IDS/firewall review prompt artifact without running the advisor",
    )
    export_ids_review_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    export_ids_review_parser.add_argument("--package-id", required=True)
    export_ids_review_parser.add_argument(
        "--output-dir",
        default="advisories",
        help="directory under the store directory for prompt artifacts",
    )
    export_ids_review_parser.add_argument("--filename")
    dispatch_ids_review_parser = subparsers.add_parser(
        "dispatch-host-security-ids-review-package",
        help="export and dispatch an IDS/firewall review package to the registered Intrusion Detection Codex thread",
    )
    dispatch_ids_review_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    dispatch_ids_review_parser.add_argument("--package-id", required=True)
    dispatch_ids_review_parser.add_argument("--dispatched-by", required=True)
    dispatch_ids_review_parser.add_argument("--dispatched-at")
    dispatch_ids_review_parser.add_argument("--owner-thread", help="override the package's registered Intrusion Detection thread")
    dispatch_ids_review_parser.add_argument(
        "--output-dir",
        default="advisories",
        help="directory under the store directory for prompt artifacts when no prompt has been exported",
    )
    dispatch_ids_review_parser.add_argument("--filename")
    dispatch_ids_review_parser.add_argument("--codex-projects-registry", help="override codex-projects registry path")
    record_ids_review_parser = subparsers.add_parser(
        "record-host-security-ids-review-result",
        help="record the manual Intrusion Detection advisory result for a package",
    )
    record_ids_review_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    record_ids_review_parser.add_argument("--package-id", required=True)
    record_ids_review_parser.add_argument(
        "--status",
        required=True,
        choices=[IDSReviewPackageStatus.ACCEPTED.value, IDSReviewPackageStatus.REVISION_REQUIRED.value],
    )
    record_ids_review_parser.add_argument("--advisory-result", required=True)
    record_ids_review_parser.add_argument("--reviewed-by", required=True)
    record_ids_review_parser.add_argument("--reviewed-at")
    host_remediation_parser = subparsers.add_parser(
        "plan-host-security-remediation",
        help="stage an approval-gated host security remediation plan",
    )
    host_remediation_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    host_remediation_parser.add_argument("--listener", required=True, help="triaged listener local socket, such as 0.0.0.0:22")
    host_remediation_parser.add_argument("--plan-id", help="admin plan id; defaults from the listener port")
    host_remediation_parser.add_argument("--action", default="deny_tcp", choices=("deny_tcp",))
    host_remediation_parser.add_argument("--reason")
    host_remediation_parser.add_argument("--snapshot-id", help="host snapshot id; defaults to the latest snapshot")
    admin_plan_parser = subparsers.add_parser("plan-admin-change", help="prepare an approval-gated admin change plan")
    admin_plan_parser.add_argument("--store", help="explicit SQLite store path for persisting the admin change plan")
    admin_plan_parser.add_argument("--plan-id", required=True)
    admin_plan_parser.add_argument("--kind", required=True, choices=[item.value for item in AdminChangeKind])
    admin_plan_parser.add_argument("--target", required=True)
    admin_plan_parser.add_argument("--reason", required=True)
    admin_plan_parser.add_argument("--current-state", default="unknown")
    admin_plan_parser.add_argument("--package", action="append")
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
    execute_admin_parser.add_argument("--policy-profile", help="optional JSON policy profile generated by policy-customization-helper")
    admin_executions_parser = subparsers.add_parser("admin-executions", help="list persisted admin change execution results")
    admin_executions_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_adapter_capabilities_parser = subparsers.add_parser(
        "admin-adapter-capabilities",
        help="list live admin adapter enablement status",
    )
    admin_adapter_capabilities_parser.add_argument("--store", help="optional SQLite store path for approved enablement state")
    admin_adapter_plan_parser = subparsers.add_parser(
        "admin-adapter-enablement-plan",
        help="prepare a read-only high-risk approval plan for enabling live admin adapters",
    )
    admin_adapter_plan_parser.add_argument("--kind", choices=[item.value for item in AdminChangeKind])
    admin_adapter_request_parser = subparsers.add_parser(
        "request-admin-adapter-enablement",
        help="request approval before enabling a disabled live admin adapter",
    )
    admin_adapter_request_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_adapter_request_parser.add_argument("--kind", required=True, choices=[item.value for item in AdminChangeKind])
    admin_adapter_request_parser.add_argument("--requested-by", required=True)
    admin_adapter_request_parser.add_argument("--requested-at")
    admin_adapter_approve_parser = subparsers.add_parser(
        "approve-admin-adapter-enablement",
        help="approve a requested live admin adapter enablement gate",
    )
    admin_adapter_approve_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_adapter_approve_parser.add_argument("--approval-id", required=True)
    admin_adapter_approve_parser.add_argument("--approved-by", required=True)
    admin_adapter_approve_parser.add_argument("--approved-at")
    admin_summary_parser = subparsers.add_parser("admin-summary", help="summarize admin plans, execution results, and audit events")
    admin_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_readiness_parser = subparsers.add_parser("admin-execution-readiness", help="summarize admin plan execution readiness")
    admin_readiness_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_policy_parser = subparsers.add_parser("admin-policy-status", help="evaluate stored admin plans against Overseer policy gates")
    admin_policy_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_policy_parser.add_argument("--plan-id", help="filter policy evaluation to one admin plan")
    admin_policy_parser.add_argument("--policy-profile", help="optional JSON policy profile generated by policy-customization-helper")
    active_policy_profile_parser = subparsers.add_parser("active-policy-profile", help="show the policy profile currently active for a store")
    active_policy_profile_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    active_policy_profile_parser.add_argument("--policy-profile", help="optional JSON policy profile to inspect instead of the store-local active profile")
    policy_helper_parser = subparsers.add_parser("policy-customization-helper", help="print best-practice policy defaults and reusable customization questions")
    policy_helper_parser.add_argument("--output", help="optional JSON output path for the helper payload")
    build_policy_profile_parser = subparsers.add_parser("build-policy-profile", help="build a policy profile JSON from policy customization answers")
    build_policy_profile_parser.add_argument("--answers", required=True, help="JSON object keyed by policy customization question id")
    build_policy_profile_parser.add_argument("--output", help="optional output path for the built policy profile JSON")
    admin_policy_warning_request_parser = subparsers.add_parser(
        "request-admin-policy-warning",
        help="request approval to accept a residual policy warning for one admin plan",
    )
    admin_policy_warning_request_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_policy_warning_request_parser.add_argument("--plan-id", required=True)
    admin_policy_warning_request_parser.add_argument("--check-id", required=True)
    admin_policy_warning_request_parser.add_argument("--requested-by", required=True)
    admin_policy_warning_request_parser.add_argument("--requested-at")
    admin_policy_warning_approve_parser = subparsers.add_parser(
        "approve-admin-policy-warning",
        help="approve a requested residual policy warning acceptance",
    )
    admin_policy_warning_approve_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_policy_warning_approve_parser.add_argument("--approval-id", required=True)
    admin_policy_warning_approve_parser.add_argument("--approved-by", required=True)
    admin_policy_warning_approve_parser.add_argument("--approved-at")
    admin_history_parser = subparsers.add_parser("admin-history-review", help="review inactive admin plans for archive handling")
    admin_history_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_archive_plan_parser = subparsers.add_parser("admin-history-archive-plan", help="prepare a read-only archive manifest for inactive admin plans")
    admin_archive_plan_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_archives_parser = subparsers.add_parser("admin-history-archives", help="list persisted admin history archive records")
    admin_archives_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_archives_parser.add_argument("--plan-id", help="filter archive records by admin plan id")
    admin_archive_request_parser = subparsers.add_parser("request-admin-history-archive", help="request approval before archiving inactive admin plans")
    admin_archive_request_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_archive_request_parser.add_argument("--requested-by", required=True)
    admin_archive_request_parser.add_argument("--requested-at")
    admin_archive_request_parser.add_argument("--plan-id", help="request approval for only one archive-ready admin plan")
    admin_archive_approve_parser = subparsers.add_parser("approve-admin-history-archive", help="approve a requested admin history archive")
    admin_archive_approve_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_archive_approve_parser.add_argument("--approval-id", required=True)
    admin_archive_approve_parser.add_argument("--approved-by", required=True)
    admin_archive_approve_parser.add_argument("--approved-at")
    admin_restore_readiness_parser = subparsers.add_parser("admin-history-restore-readiness", help="plan approval and evidence gates before restoring archived admin plans")
    admin_restore_readiness_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_restore_readiness_parser.add_argument("--plan-id", help="filter restore readiness by admin plan id")
    admin_restore_request_parser = subparsers.add_parser("request-admin-history-restore", help="request approval before restoring an archived admin plan")
    admin_restore_request_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_restore_request_parser.add_argument("--plan-id", required=True)
    admin_restore_request_parser.add_argument("--requested-by", required=True)
    admin_restore_request_parser.add_argument("--requested-at")
    admin_restore_approve_parser = subparsers.add_parser("approve-admin-history-restore", help="approve a requested admin history restore")
    admin_restore_approve_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    admin_restore_approve_parser.add_argument("--approval-id", required=True)
    admin_restore_approve_parser.add_argument("--approved-by", required=True)
    admin_restore_approve_parser.add_argument("--approved-at")
    archive_admin_history_parser = subparsers.add_parser("archive-admin-history", help="archive inactive admin plans after explicit approval")
    archive_admin_history_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    archive_admin_history_parser.add_argument("--archived-by", required=True)
    archive_admin_history_parser.add_argument("--approval-id", required=True)
    archive_admin_history_parser.add_argument("--archived-at")
    archive_admin_history_parser.add_argument("--plan-id", help="archive only one eligible admin plan")
    unarchive_admin_history_parser = subparsers.add_parser("unarchive-admin-history", help="restore one archived admin plan to active admin history")
    unarchive_admin_history_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    unarchive_admin_history_parser.add_argument("--plan-id", required=True)
    unarchive_admin_history_parser.add_argument("--restored-by", required=True)
    unarchive_admin_history_parser.add_argument("--approval-id", required=True)
    unarchive_admin_history_parser.add_argument("--restored-at")
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
    discover_codex_threads_parser = subparsers.add_parser(
        "discover-codex-project-threads",
        help="import local codex-projects registry rows as managed Overseer resources",
    )
    discover_codex_threads_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    discover_codex_threads_parser.add_argument(
        "--codex-projects-registry",
        default="/home/god/.codex/codex-projects.csv",
        help="codex-projects CSV registry path",
    )
    record_usage_limit_parser = subparsers.add_parser("record-usage-limit", help="record or update a usage-limit observation")
    record_usage_limit_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    record_usage_limit_parser.add_argument("--limit-id", required=True)
    record_usage_limit_parser.add_argument("--resource-id", required=True)
    record_usage_limit_parser.add_argument("--kind", required=True, choices=[item.value for item in LimitKind])
    record_usage_limit_parser.add_argument("--capacity", required=True, type=int)
    record_usage_limit_parser.add_argument("--remaining", required=True, type=int)
    record_usage_limit_parser.add_argument("--window", required=True)
    record_usage_limit_parser.add_argument("--resets-at")
    record_usage_limit_parser.add_argument("--observed-at")
    record_usage_limit_parser.add_argument("--confidence", type=float, default=1.0)
    usage_continuation_plan_parser = subparsers.add_parser(
        "usage-continuation-plan",
        help="summarize persisted usage-limited continuation requests",
    )
    usage_continuation_plan_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    dispatch_usage_continuations_parser = subparsers.add_parser(
        "dispatch-usage-continuations",
        help="persist dispatch records for ready usage-limited continuation requests",
    )
    dispatch_usage_continuations_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    dispatch_usage_continuations_parser.add_argument("--dispatched-by", default="quark")
    dispatch_usage_continuations_parser.add_argument("--dispatched-at")
    dispatch_usage_continuations_parser.add_argument(
        "--resume-codex-projects",
        action="store_true",
        help="resume matched owner_thread values through the local codex-projects tmux registry",
    )
    dispatch_usage_continuations_parser.add_argument(
        "--codex-projects-registry",
        default="/home/god/.codex/codex-projects.csv",
        help="codex-projects CSV registry path",
    )
    request_usage_continuation_parser = subparsers.add_parser(
        "request-usage-continuation",
        help="persist a usage-limited continuation request without waking work",
    )
    request_usage_continuation_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    request_usage_continuation_parser.add_argument("--request-id", required=True)
    request_usage_continuation_parser.add_argument("--limit-id", required=True)
    request_usage_continuation_parser.add_argument("--resource-id", required=True)
    request_usage_continuation_parser.add_argument("--owner-thread", required=True)
    request_usage_continuation_parser.add_argument("--requested-units", required=True, type=int)
    request_usage_continuation_parser.add_argument("--intent", required=True)
    request_usage_continuation_parser.add_argument("--risk-level", default=RiskLevel.LOW.value, choices=[item.value for item in RiskLevel])
    request_usage_continuation_parser.add_argument("--earliest-start")
    request_usage_continuation_parser.add_argument("--deadline")
    request_usage_continuation_parser.add_argument("--requested-by", default="quark")
    request_usage_continuation_parser.add_argument("--requested-at")
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
    claim_parser.add_argument("--starts-at")
    claim_parser.add_argument("--expires-at")
    claim_parser.add_argument("--release-condition")
    claim_review_parser = subparsers.add_parser("claim-review", help="review active, queued, expired, and release-blocked claims")
    claim_review_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    claim_review_parser.add_argument("--now", help="override review timestamp for deterministic checks")
    claim_cleanup_plan_parser = subparsers.add_parser(
        "claim-cleanup-plan",
        help="prepare a read-only cleanup plan for expired, stale, blocked, or release-blocked claims",
    )
    claim_cleanup_plan_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    claim_cleanup_plan_parser.add_argument("--now", help="override review timestamp for deterministic checks")
    request_claim_cleanup_parser = subparsers.add_parser("request-claim-cleanup", help="request approval for a claim cleanup candidate")
    request_claim_cleanup_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    request_claim_cleanup_parser.add_argument("--claim-id", required=True)
    request_claim_cleanup_parser.add_argument("--requested-by", required=True)
    request_claim_cleanup_parser.add_argument("--requested-at")
    request_claim_cleanup_parser.add_argument("--now", help="override cleanup review timestamp for deterministic checks")
    approve_claim_cleanup_parser = subparsers.add_parser("approve-claim-cleanup", help="approve a pending claim cleanup request")
    approve_claim_cleanup_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    approve_claim_cleanup_parser.add_argument("--approval-id", required=True)
    approve_claim_cleanup_parser.add_argument("--approved-by", required=True)
    approve_claim_cleanup_parser.add_argument("--approved-at")
    approve_claim_cleanup_parser.add_argument("--now", help="override cleanup review timestamp for deterministic checks")
    execute_claim_cleanup_parser = subparsers.add_parser("execute-claim-cleanup", help="execute an approved claim cleanup action")
    execute_claim_cleanup_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    execute_claim_cleanup_parser.add_argument("--approval-id", required=True)
    execute_claim_cleanup_parser.add_argument("--executed-by", required=True)
    execute_claim_cleanup_parser.add_argument("--executed-at")
    execute_claim_cleanup_parser.add_argument("--now", help="override cleanup review timestamp for deterministic checks")
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
    release_parser.add_argument("--released-by")
    release_parser.add_argument("--reason")
    release_parser.add_argument("--evidence-id", action="append", default=())
    release_parser.add_argument("--released-at")
    args = parser.parse_args(argv)

    if args.command == "demo":
        status = persisted_demo_status(args.store) if args.store else demo_status()
        print(json.dumps(status, sort_keys=True))
        return 0

    if args.command == "seed-config":
        print(json.dumps(seed_config_status(args.config, args.store), sort_keys=True))
        return 0

    if args.command == "record-resource":
        print(
            json.dumps(
                record_resource_status(
                    args.store,
                    args.resource_id,
                    args.name,
                    args.resource_type,
                    args.owner_domain,
                    args.risk_level,
                    args.state,
                    _json_object_arg(args.identifier_json, "identifier-json"),
                    tuple(args.dependency),
                    tuple(args.exclusive_group),
                    args.current_claim_id,
                    args.last_verified_at,
                    args.notes,
                ),
                sort_keys=True,
            )
        )
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

    if args.command == "probe-stored-health":
        print(json.dumps(probe_stored_health_status(args.store, args.timeout_seconds, args.retention_per_target), sort_keys=True))
        return 0

    if args.command == "record-health-target":
        print(
            json.dumps(
                record_health_target_status(
                    args.store,
                    args.target_id,
                    args.resource_id,
                    args.name,
                    args.probe_type,
                    args.target,
                    args.owner_domain,
                    args.expected_status,
                    args.expected_content_type,
                    args.latency_warn_ms,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "discover-physical":
        print(json.dumps(discover_physical_status(args.root, args.store), sort_keys=True))
        return 0

    if args.command == "discover-storage":
        print(json.dumps(discover_storage_status(args.sysfs_block_root, args.store), sort_keys=True))
        return 0

    if args.command == "physical-summary":
        print(json.dumps(physical_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "virtual-summary":
        print(json.dumps(virtual_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "discover-virtual-listeners":
        print(json.dumps(discover_virtual_listeners_status(args.store), sort_keys=True))
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

    if args.command == "inspect-packages":
        print(json.dumps(inspect_packages_status(args.captured_at), sort_keys=True))
        return 0

    if args.command == "plan-package-updates":
        print(json.dumps(plan_package_updates_status(args.store, args.captured_at, tuple(args.package)), sort_keys=True))
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

    if args.command == "export-state-redacted":
        print(json.dumps(export_state_redacted_status(args.store), sort_keys=True))
        return 0

    if args.command == "service-status":
        print(json.dumps(service_status(args.store, args.service_name), sort_keys=True))
        return 0

    if args.command == "runtime-status":
        print(json.dumps(runtime_status(args.store, args.service_name), sort_keys=True))
        return 0

    if args.command == "daemon-migration-plan":
        print(json.dumps(daemon_migration_plan_status(args.store, args.service_name), sort_keys=True))
        return 0

    if args.command == "request-daemon-migration":
        print(json.dumps(request_daemon_migration_status(args.store, args.service_name, args.requested_by, args.requested_at), sort_keys=True))
        return 0

    if args.command == "approve-daemon-migration":
        print(json.dumps(approve_daemon_migration_status(args.store, args.approval_id, args.approved_by, args.approved_at), sort_keys=True))
        return 0

    if args.command == "persistence-security":
        print(json.dumps(persistence_security_status(args.store), sort_keys=True))
        return 0

    if args.command == "alerts-summary":
        print(json.dumps(alerts_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "audit-summary":
        print(json.dumps(audit_summary_status(args.store, args.event_type, args.owner, args.subject_prefix), sort_keys=True))
        return 0

    if args.command == "approvals-summary":
        print(json.dumps(approvals_summary_status(args.store, args.status, args.owner, args.approval_level, args.subject_prefix), sort_keys=True))
        return 0

    if args.command == "inspect-host":
        print(json.dumps(inspect_host_status(args.store), sort_keys=True))
        return 0

    if args.command == "discover-user-services":
        print(json.dumps(discover_user_services_status(args.store), sort_keys=True))
        return 0

    if args.command == "assess-host-security":
        print(json.dumps(assess_host_security_status(args.store, args.snapshot_id), sort_keys=True))
        return 0

    if args.command == "host-security-findings":
        print(json.dumps(host_security_findings_status(args.store, args.snapshot_id, args.severity), sort_keys=True))
        return 0

    if args.command == "host-security-triage":
        print(json.dumps(host_security_triage_status(args.store, args.snapshot_id), sort_keys=True))
        return 0

    if args.command == "host-security-listener-review-queue":
        print(json.dumps(host_security_listener_review_queue_status(args.store, args.snapshot_id), sort_keys=True))
        return 0

    if args.command == "plan-host-security-listener-queue-remediations":
        print(
            json.dumps(
                plan_host_security_listener_queue_remediations_status(
                    args.store,
                    args.snapshot_id,
                    args.requested_by,
                    args.plan_prefix,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "host-security-sources":
        print(json.dumps(host_security_sources_status(args.store, args.snapshot_id), sort_keys=True))
        return 0

    if args.command == "host-security-source-review-queue":
        print(json.dumps(host_security_source_review_queue_status(args.store, args.snapshot_id), sort_keys=True))
        return 0

    if args.command == "host-security-source-reviews":
        print(json.dumps(host_security_source_reviews_status(args.store), sort_keys=True))
        return 0

    if args.command == "create-host-security-source-review":
        print(
            json.dumps(
                create_host_security_source_review_status(
                    args.store,
                    args.remote_address,
                    args.listener,
                    args.review_id,
                    args.disposition,
                    args.rationale,
                    args.reviewed_by,
                    args.reviewed_at,
                    args.created_at,
                    args.snapshot_id,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "plan-host-security-source-block":
        print(
            json.dumps(
                plan_host_security_source_block_status(
                    args.store,
                    args.review_id,
                    args.plan_id,
                    args.action,
                    args.reason,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "host-security-ids-review-packages":
        print(json.dumps(host_security_ids_review_packages_status(args.store), sort_keys=True))
        return 0

    if args.command == "host-security-ids-review-summary":
        print(json.dumps(host_security_ids_review_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "prepare-host-security-ids-review-package":
        print(
            json.dumps(
                prepare_host_security_ids_review_package_status(
                    args.store,
                    args.plan_id,
                    args.package_id,
                    args.source_review_id,
                    args.requested_by,
                    args.created_at,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "submit-host-security-ids-review-package":
        print(
            json.dumps(
                submit_host_security_ids_review_package_status(
                    args.store,
                    args.package_id,
                    args.submitted_by,
                    args.submitted_at,
                    args.prompt_path,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "export-host-security-ids-review-prompt":
        print(
            json.dumps(
                export_host_security_ids_review_prompt_status(
                    args.store,
                    args.package_id,
                    args.output_dir,
                    args.filename,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "dispatch-host-security-ids-review-package":
        print(
            json.dumps(
                dispatch_host_security_ids_review_package_status(
                    args.store,
                    args.package_id,
                    args.dispatched_by,
                    args.dispatched_at,
                    args.owner_thread,
                    args.output_dir,
                    args.filename,
                    args.codex_projects_registry,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "record-host-security-ids-review-result":
        print(
            json.dumps(
                record_host_security_ids_review_result_status(
                    args.store,
                    args.package_id,
                    args.status,
                    args.advisory_result,
                    args.reviewed_by,
                    args.reviewed_at,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "plan-host-security-remediation":
        print(
            json.dumps(
                plan_host_security_remediation_status(
                    args.store,
                    args.listener,
                    args.plan_id,
                    args.action,
                    args.reason,
                    args.snapshot_id,
                ),
                sort_keys=True,
            )
        )
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
                    args.package or (),
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
        print(json.dumps(execute_admin_change_status(args.store, args.plan_id, policy_profile_path=args.policy_profile), sort_keys=True))
        return 0

    if args.command == "admin-executions":
        print(json.dumps(admin_executions_status(args.store), sort_keys=True))
        return 0

    if args.command == "admin-adapter-capabilities":
        print(json.dumps(admin_adapter_capabilities_status(args.store), sort_keys=True))
        return 0

    if args.command == "admin-adapter-enablement-plan":
        print(json.dumps(admin_adapter_enablement_plan_status(args.kind), sort_keys=True))
        return 0

    if args.command == "request-admin-adapter-enablement":
        print(json.dumps(request_admin_adapter_enablement_status(args.store, args.kind, args.requested_by, args.requested_at), sort_keys=True))
        return 0

    if args.command == "approve-admin-adapter-enablement":
        print(json.dumps(approve_admin_adapter_enablement_status(args.store, args.approval_id, args.approved_by, args.approved_at), sort_keys=True))
        return 0

    if args.command == "admin-summary":
        print(json.dumps(admin_summary_status(args.store), sort_keys=True))
        return 0

    if args.command == "admin-execution-readiness":
        print(json.dumps(admin_execution_readiness_status(args.store), sort_keys=True))
        return 0

    if args.command == "admin-policy-status":
        print(json.dumps(admin_policy_status(args.store, args.plan_id, args.policy_profile), sort_keys=True))
        return 0

    if args.command == "active-policy-profile":
        print(json.dumps(active_policy_profile_status(args.store, args.policy_profile), sort_keys=True))
        return 0

    if args.command == "policy-customization-helper":
        print(json.dumps(policy_customization_helper_cli_status(args.output), sort_keys=True))
        return 0

    if args.command == "build-policy-profile":
        print(json.dumps(build_policy_profile_status(args.answers, args.output), sort_keys=True))
        return 0

    if args.command == "request-admin-policy-warning":
        print(
            json.dumps(
                request_admin_policy_warning_status(
                    args.store,
                    args.plan_id,
                    args.check_id,
                    args.requested_by,
                    args.requested_at,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "approve-admin-policy-warning":
        print(
            json.dumps(
                approve_admin_policy_warning_status(
                    args.store,
                    args.approval_id,
                    args.approved_by,
                    args.approved_at,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "admin-history-review":
        print(json.dumps(admin_history_review_status(args.store), sort_keys=True))
        return 0

    if args.command == "admin-history-archive-plan":
        print(json.dumps(admin_history_archive_plan_status(args.store), sort_keys=True))
        return 0

    if args.command == "admin-history-archives":
        print(json.dumps(admin_history_archives_status(args.store, args.plan_id), sort_keys=True))
        return 0

    if args.command == "request-admin-history-archive":
        print(json.dumps(request_admin_history_archive_status(args.store, args.requested_by, args.requested_at, args.plan_id), sort_keys=True))
        return 0

    if args.command == "approve-admin-history-archive":
        print(json.dumps(approve_admin_history_archive_status(args.store, args.approval_id, args.approved_by, args.approved_at), sort_keys=True))
        return 0

    if args.command == "admin-history-restore-readiness":
        print(json.dumps(admin_history_restore_readiness_status(args.store, args.plan_id), sort_keys=True))
        return 0

    if args.command == "request-admin-history-restore":
        print(json.dumps(request_admin_history_restore_status(args.store, args.plan_id, args.requested_by, args.requested_at), sort_keys=True))
        return 0

    if args.command == "approve-admin-history-restore":
        print(json.dumps(approve_admin_history_restore_status(args.store, args.approval_id, args.approved_by, args.approved_at), sort_keys=True))
        return 0

    if args.command == "archive-admin-history":
        print(json.dumps(archive_admin_history_status(args.store, args.archived_by, args.approval_id, args.archived_at, args.plan_id), sort_keys=True))
        return 0

    if args.command == "unarchive-admin-history":
        print(json.dumps(unarchive_admin_history_status(args.store, args.plan_id, args.restored_by, args.approval_id, args.restored_at), sort_keys=True))
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

    if args.command == "discover-codex-project-threads":
        print(json.dumps(discover_codex_project_threads_status(args.store, args.codex_projects_registry), sort_keys=True))
        return 0

    if args.command == "record-usage-limit":
        print(
            json.dumps(
                record_usage_limit_status(
                    args.store,
                    args.limit_id,
                    args.resource_id,
                    args.kind,
                    args.capacity,
                    args.remaining,
                    args.window,
                    args.resets_at,
                    args.observed_at,
                    args.confidence,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "usage-continuation-plan":
        print(json.dumps(usage_continuation_plan_status(args.store), sort_keys=True))
        return 0

    if args.command == "dispatch-usage-continuations":
        print(
            json.dumps(
                dispatch_usage_continuations_status(
                    args.store,
                    args.dispatched_by,
                    args.dispatched_at,
                    args.resume_codex_projects,
                    args.codex_projects_registry,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "request-usage-continuation":
        print(
            json.dumps(
                request_usage_continuation_status(
                    args.store,
                    args.request_id,
                    args.limit_id,
                    args.resource_id,
                    args.owner_thread,
                    args.requested_units,
                    args.intent,
                    args.risk_level,
                    args.earliest_start,
                    args.deadline,
                    args.requested_by,
                    args.requested_at,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "claim-review":
        print(json.dumps(claim_review_status(args.store, args.now), sort_keys=True))
        return 0

    if args.command == "claim-cleanup-plan":
        print(json.dumps(claim_cleanup_plan_status(args.store, args.now), sort_keys=True))
        return 0

    if args.command == "request-claim-cleanup":
        print(
            json.dumps(
                request_claim_cleanup_status(
                    args.store,
                    args.claim_id,
                    args.requested_by,
                    args.requested_at,
                    args.now,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "approve-claim-cleanup":
        print(
            json.dumps(
                approve_claim_cleanup_status(
                    args.store,
                    args.approval_id,
                    args.approved_by,
                    args.approved_at,
                    args.now,
                ),
                sort_keys=True,
            )
        )
        return 0

    if args.command == "execute-claim-cleanup":
        print(
            json.dumps(
                execute_claim_cleanup_status(
                    args.store,
                    args.approval_id,
                    args.executed_by,
                    args.executed_at,
                    args.now,
                ),
                sort_keys=True,
            )
        )
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
                    args.starts_at,
                    args.expires_at,
                    args.release_condition,
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
        print(
            json.dumps(
                release_claim_status(
                    args.store,
                    args.claim_id,
                    args.released_by,
                    args.reason,
                    args.evidence_id,
                    args.released_at,
                ),
                sort_keys=True,
            )
        )
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


def _status_id(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.lower()).strip("-")


if __name__ == "__main__":
    raise SystemExit(main())
