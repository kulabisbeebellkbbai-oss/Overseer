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
from .audit import ApprovalStatus, AuditEventType
from .health import HealthStatus, HealthTarget, ProbeType, summarize_health_targets
from .host import HostInspectionAdapter, host_security_status, host_snapshot_status
from .live_health import HttpHealthProbeAdapter
from .physical_discovery import PathPhysicalDiscoveryAdapter
from .registry import ResourceRegistry
from .runtime import OverseerRuntime
from .service import OverseerCoordinator, coordinator_from_store
from .store import SQLiteStore


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


def runtime_status(store_path: str | Path, service_name: str = "overseer") -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        heartbeat = store.load_runtime_heartbeat(service_name)
        snapshots = store.list_host_snapshots()
        latest_snapshot = sorted(snapshots, key=lambda item: item.captured_at)[-1] if snapshots else None
        host_security = host_security_status(latest_snapshot) if latest_snapshot else None
        return {
            "store": str(store.path),
            "service": {
                "service_name": heartbeat.service_name,
                "started_at": heartbeat.started_at,
                "last_tick_at": heartbeat.last_tick_at,
                "tick_count": heartbeat.tick_count,
            },
            "host_inspection": {
                "enabled": latest_snapshot is not None,
                "latest_snapshot_id": latest_snapshot.id if latest_snapshot else None,
                "latest_captured_at": latest_snapshot.captured_at if latest_snapshot else None,
                "hostname": latest_snapshot.hostname if latest_snapshot else None,
                "high_findings": host_security["high_findings"] if host_security else 0,
                "warning_findings": host_security["warning_findings"] if host_security else 0,
            },
        }
    finally:
        store.close()


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
        return {"store": str(store.path), **admin_execution_status(result)}
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
                {
                    "id": event.id,
                    "event_type": AuditEventType(event.event_type).value,
                    "subject_id": event.subject_id,
                    "owner_domain": OwnerDomain(event.owner_domain).value,
                    "risk_level": RiskLevel(event.risk_level).value,
                    "summary": event.summary,
                }
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
    api_parser = subparsers.add_parser("serve-api", help="serve the localhost Overseer HTTP API")
    api_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    api_parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "localhost"))
    api_parser.add_argument("--port", type=int, default=8766)
    api_parser.add_argument("--auth-token-file", help="local file containing the bearer token required for API access")
    health_summary_parser = subparsers.add_parser("health-summary", help="summarize latest health evidence per target")
    health_summary_parser.add_argument("--store", required=True, help="explicit SQLite store path")
    health_summary_parser.add_argument("--fail-on-unhealthy", action="store_true", help="exit non-zero when any target is unhealthy")
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

    if args.command == "serve-api":
        from .api import load_auth_token, run_api_server

        run_api_server(args.store, args.host, args.port, load_auth_token(args.auth_token_file))
        return 0

    if args.command == "health-summary":
        status = health_summary_status(args.store)
        print(json.dumps(status, sort_keys=True))
        return 1 if args.fail_on_unhealthy and status["unhealthy"] else 0

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


if __name__ == "__main__":
    raise SystemExit(main())
