"""JSON configuration loading for explicit operator-provided state."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from .store import SQLiteStore
from .usage_limits import LimitKind, UsageLimit

SECRET_KEY_PARTS = ("token", "secret", "password", "credential", "api_key", "private_key")


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
    _reject_secret_like_keys(data)
    resources = tuple(_resource_from_mapping(item) for item in data.get("resources", ()))
    usage_limits = tuple(_usage_limit_from_mapping(item) for item in data.get("usage_limits", ()))
    config = OverseerConfig(resources, usage_limits)
    validate_config(config)
    return config


def seed_store_from_config(config: OverseerConfig, store: SQLiteStore) -> ConfigSeedResult:
    validate_config(config)
    for resource in config.resources:
        store.save_resource(resource)
    for usage_limit in config.usage_limits:
        store.save_usage_limit(usage_limit)
    return ConfigSeedResult(len(config.resources), len(config.usage_limits), str(store.path))


def validate_config(config: OverseerConfig) -> None:
    resource_ids = [resource.id for resource in config.resources]
    usage_limit_ids = [usage_limit.id for usage_limit in config.usage_limits]
    _reject_duplicates(resource_ids, "resource")
    _reject_duplicates(usage_limit_ids, "usage limit")
    resource_id_set = set(resource_ids)
    for usage_limit in config.usage_limits:
        if usage_limit.resource_id not in resource_id_set:
            raise ValueError(f"usage limit references unknown resource: {usage_limit.resource_id}")
        if usage_limit.capacity < 0 or usage_limit.remaining < 0:
            raise ValueError("usage limit capacity and remaining must be non-negative")
        if usage_limit.remaining > usage_limit.capacity:
            raise ValueError("usage limit remaining cannot exceed capacity")


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


def _reject_duplicates(values: list[str], label: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {label} id: {value}")
        seen.add(value)


def _reject_secret_like_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in SECRET_KEY_PARTS):
                raise ValueError(f"secret-like config key is not allowed: {key}")
            _reject_secret_like_keys(nested)
    elif isinstance(value, list):
        for item in value:
            _reject_secret_like_keys(item)
