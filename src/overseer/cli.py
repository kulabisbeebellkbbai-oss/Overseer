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
from .registry import ResourceRegistry
from .service import OverseerCoordinator
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
                ),
                sort_keys=True,
            )
        )
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
