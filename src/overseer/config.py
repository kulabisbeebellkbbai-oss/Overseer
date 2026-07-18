"""JSON configuration loading for explicit operator-provided state."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from .store import SQLiteStore
from .usage_limits import LimitKind, UsageLimit


@dataclass(frozen=True)
class OverseerConfig:
    resources: tuple[Resource, ...] = ()
    usage_limits: tuple[UsageLimit, ...] = ()


@dataclass(frozen=True)
class ConfigSeedResult:
    resource_count: int
    usage_limit_count: int
    store_path: str


def load_config(path: str | Path) -> OverseerConfig:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("configuration root must be an object")
    return config_from_mapping(data)


def config_from_mapping(data: dict[str, Any]) -> OverseerConfig:
    resources = tuple(_resource_from_mapping(item) for item in data.get("resources", ()))
    usage_limits = tuple(_usage_limit_from_mapping(item) for item in data.get("usage_limits", ()))
    return OverseerConfig(resources, usage_limits)


def seed_store_from_config(config: OverseerConfig, store: SQLiteStore) -> ConfigSeedResult:
    for resource in config.resources:
        store.save_resource(resource)
    for usage_limit in config.usage_limits:
        store.save_usage_limit(usage_limit)
    return ConfigSeedResult(len(config.resources), len(config.usage_limits), str(store.path))


def _resource_from_mapping(data: dict[str, Any]) -> Resource:
    return Resource(
        id=str(data["id"]),
        name=str(data["name"]),
        type=ResourceType(data["type"]),
        owner_domain=OwnerDomain(data["owner_domain"]),
        risk_level=RiskLevel(data["risk_level"]),
        state=ResourceState(data.get("state", ResourceState.AVAILABLE.value)),
        identifiers=dict(data.get("identifiers", {})),
        dependencies=frozenset(data.get("dependencies", ())),
        exclusive_groups=frozenset(data.get("exclusive_groups", ())),
        current_claim_id=data.get("current_claim_id"),
        last_verified_at=data.get("last_verified_at"),
        notes=str(data.get("notes", "")),
    )


def _usage_limit_from_mapping(data: dict[str, Any]) -> UsageLimit:
    return UsageLimit(
        id=str(data["id"]),
        resource_id=str(data["resource_id"]),
        kind=LimitKind(data["kind"]),
        capacity=int(data["capacity"]),
        remaining=int(data["remaining"]),
        resets_at=data.get("resets_at"),
        window=str(data["window"]),
        observed_at=data.get("observed_at"),
        confidence=float(data.get("confidence", 1.0)),
    )
