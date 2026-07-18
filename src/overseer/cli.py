"""Command-line entry point for local Overseer prototypes."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .config import load_config, seed_store_from_config
from .core import Claim, ClaimType, OwnerDomain, Resource, ResourceType, RiskLevel
from .health import HealthTarget, ProbeType
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


def run_status(store_path: str | Path, once: bool, interval_seconds: float = 30.0) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        tick = OverseerRuntime(store).run(interval_seconds=interval_seconds, once=once)
        return {
            "store": str(store.path),
            "resources": tick.resources,
            "usage_limits": tick.usage_limits,
            "health_targets": tick.health_targets,
            "audit_events": tick.audit_events,
            "health_evidence": tick.health_evidence,
            "physical_identities": tick.physical_identities,
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
        print(json.dumps(run_status(args.store, args.once, args.interval_seconds), sort_keys=True))
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

    if args.command == "release-claim":
        print(json.dumps(release_claim_status(args.store, args.claim_id), sort_keys=True))
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
