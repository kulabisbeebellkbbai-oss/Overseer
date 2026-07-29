"""Validated provider configuration for Overseer's primary AI driver."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, NoReturn

from .agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentHandoffPackage,
    AgentInstanceProfile,
    AgentProvider,
    AgentSession,
    AgentTransport,
    CredentialReference,
    PrimaryDriver,
)


_ALLOWED_EXECUTABLES = frozenset({"codex", "claude", "qwen", "vibe"})
_ALLOWED_ADAPTERS = frozenset(
    {"codex", "claude", "qwen_code", "mistral_vibe", "antigravity"}
)
_SECRET_KEY_PATTERN = re.compile(
    r"(?:secret|password|api[_-]?key|token|credential|authorization|auth)", re.IGNORECASE
)
_EXECUTABLE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_CAPABILITY_NAMES = frozenset(field.name for field in fields(AgentCapabilities))
_PROVIDER_FIELDS = frozenset({"id", "adapter", "transport", "executable", "capabilities"})
_INSTANCE_FIELDS = frozenset(
    {
        "id",
        "primary_provider_id",
        "workspace",
        "fallback_provider_ids",
        "credential_references",
    }
)


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid provider registry configuration: {path}") from error
    if not isinstance(value, dict):
        raise ValueError("provider registry configuration must be an object")
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object")
    return value


def _require_list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _secret_reference(value: object) -> CredentialReference:
    if not isinstance(value, str):
        raise ValueError("configuration accepts only secret reference locators")
    try:
        return CredentialReference(id=value)
    except ValueError as error:
        raise ValueError("configuration accepts only secret reference locators") from error


def _reject_inline_secrets(value: object, key: str | None = None) -> None:
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            if not isinstance(child_key, str):
                raise ValueError("configuration keys must be strings")
            if child_key == "credential_references":
                references = _require_mapping(child_value, child_key)
                for reference in references.values():
                    _secret_reference(reference)
                continue
            if _SECRET_KEY_PATTERN.search(child_key):
                if not child_key.lower().endswith("_secret_ref"):
                    raise ValueError("configuration accepts only secret reference locators")
                _secret_reference(child_value)
                continue
            _reject_inline_secrets(child_value, child_key)
    elif isinstance(value, list):
        for item in value:
            _reject_inline_secrets(item, key)


def _records_by_id(value: object, label: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for record in _require_list(value, label):
        mapping = dict(_require_mapping(record, f"{label} record"))
        record_id = mapping.get("id")
        if not isinstance(record_id, str) or not record_id:
            raise ValueError(f"{label} record id must be non-empty")
        if record_id in records:
            raise ValueError(f"duplicate {label} id: {record_id}")
        records[record_id] = mapping
    return records


def _merge_mapping(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key == "id" and value != base.get("id"):
            raise ValueError("local override cannot change a record id")
        if isinstance(value, Mapping) and isinstance(merged.get(key), Mapping):
            merged[key] = _merge_mapping(dict(merged[key]), value)
        else:
            merged[key] = value
    return merged


def _merge_local_overrides(
    committed: dict[str, Any], local: dict[str, Any] | None
) -> dict[str, Any]:
    if local is None:
        return committed
    allowed = {"schema_version", "providers", "instances"}
    unknown = set(local) - allowed
    if unknown:
        raise ValueError(f"local override contains unknown sections: {sorted(unknown)}")
    merged = dict(committed)
    for section in ("providers", "instances"):
        if section not in local:
            continue
        overrides = _require_mapping(local[section], f"local {section}")
        records = _records_by_id(committed.get(section, []), section)
        for record_id, override in overrides.items():
            if record_id not in records:
                raise ValueError(f"local override references unknown {section} id: {record_id}")
            records[record_id] = _merge_mapping(
                records[record_id], _require_mapping(override, f"local {section} override")
            )
        merged[section] = list(records.values())
    if "schema_version" in local and local["schema_version"] != committed.get(
        "schema_version", 1
    ):
        raise ValueError("local override cannot change schema_version")
    return merged


def _capabilities(value: object) -> AgentCapabilities:
    mapping = _require_mapping(value, "capabilities")
    unknown = set(mapping) - _CAPABILITY_NAMES
    if unknown:
        raise ValueError(f"unknown capabilities: {sorted(unknown)}")
    if any(not isinstance(enabled, bool) for enabled in mapping.values()):
        raise ValueError("capabilities must be boolean")
    return AgentCapabilities(**dict(mapping))


def _validate_fields(record: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = {
        key
        for key in record
        if key not in allowed and not key.lower().endswith("_secret_ref")
    }
    if unknown:
        raise ValueError(f"unknown {label} fields: {sorted(unknown)}")


def _provider_from_record(record: Mapping[str, Any]) -> AgentProvider:
    _validate_fields(record, _PROVIDER_FIELDS, "provider")
    provider_id = record.get("id")
    adapter = record.get("adapter")
    executable = record.get("executable")
    if not isinstance(provider_id, str) or not provider_id:
        raise ValueError("provider id must be non-empty")
    if not isinstance(adapter, str) or adapter not in _ALLOWED_ADAPTERS:
        raise ValueError("provider adapter is not supported")
    try:
        transport = AgentTransport(record.get("transport"))
    except (TypeError, ValueError) as error:
        raise ValueError("provider transport is not supported") from error
    if transport is AgentTransport.GATEWAY:
        if executable is not None:
            raise ValueError("gateway provider executable must be null")
        executable_allowlist: tuple[str, ...] = ()
    else:
        if not isinstance(executable, str) or not _EXECUTABLE_NAME_PATTERN.fullmatch(executable):
            raise ValueError("executable name must be a single command name")
        if executable not in _ALLOWED_EXECUTABLES:
            raise ValueError("executable is not allowlisted")
        executable_allowlist = (executable,)
    return AgentProvider(
        id=provider_id,
        adapter_id=adapter,
        capabilities=_capabilities(record.get("capabilities", {})),
        transports=(transport,),
        executable_allowlist=executable_allowlist,
    )


def _profile_from_record(
    record: Mapping[str, Any], providers: Mapping[str, AgentProvider]
) -> AgentInstanceProfile:
    _validate_fields(record, _INSTANCE_FIELDS, "instance")
    instance_id = record.get("id")
    primary_provider_id = record.get("primary_provider_id")
    workspace = record.get("workspace")
    fallback_ids = record.get("fallback_provider_ids", [])
    if not isinstance(instance_id, str) or not instance_id:
        raise ValueError("instance id must be non-empty")
    if not isinstance(primary_provider_id, str) or primary_provider_id not in providers:
        raise ValueError("instance primary provider must be configured")
    if not isinstance(workspace, str) or not workspace:
        raise ValueError("instance workspace must be non-empty")
    if not isinstance(fallback_ids, list) or any(
        not isinstance(provider_id, str) or provider_id not in providers
        for provider_id in fallback_ids
    ):
        raise ValueError("fallback providers must be configured provider ids")
    references = dict(_require_mapping(record.get("credential_references", {}), "credential_references"))
    for key, value in record.items():
        if key.lower().endswith("_secret_ref"):
            references[key] = value
    return AgentInstanceProfile(
        id=instance_id,
        primary_provider_id=primary_provider_id,
        transport=providers[primary_provider_id].transports[0],
        workspace=workspace,
        primary_adapter_id=providers[primary_provider_id].adapter_id,
        declared_capabilities=providers[primary_provider_id].capabilities,
        credential_references={key: _secret_reference(value) for key, value in references.items()},
        approved_fallback_provider_ids=tuple(fallback_ids),
    )


def _validate_fallbacks(profiles: Mapping[str, AgentInstanceProfile]) -> None:
    graph: dict[str, set[str]] = {}
    for profile in profiles.values():
        graph.setdefault(profile.primary_provider_id, set()).update(
            profile.approved_fallback_provider_ids
        )
    active: set[str] = set()
    visited: set[str] = set()

    def visit(provider_id: str) -> None:
        if provider_id in active:
            raise ValueError("fallback cycle is not allowed")
        if provider_id in visited:
            return
        active.add(provider_id)
        for fallback_id in graph.get(provider_id, set()):
            visit(fallback_id)
        active.remove(provider_id)
        visited.add(provider_id)

    for provider_id in graph:
        visit(provider_id)


@dataclass(frozen=True)
class _ConfiguredDriver:
    """A configuration-only driver until a provider-specific adapter is installed."""

    provider: AgentProvider

    def _unavailable(self) -> NoReturn:
        raise RuntimeError(f"no adapter implementation is installed for {self.provider.adapter_id}")

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]:
        self._unavailable()

    def resolve(self, reference: str) -> AgentSession | None:
        self._unavailable()

    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult:
        self._unavailable()

    def resume(self, session: AgentSession) -> AgentDispatchResult:
        self._unavailable()

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult:
        self._unavailable()

    def inspect(self, session: AgentSession) -> AgentDispatchResult:
        self._unavailable()

    def checkpoint(self, session: AgentSession) -> AgentCheckpoint:
        self._unavailable()

    def cancel(self, session: AgentSession) -> AgentDispatchResult:
        self._unavailable()

    def import_handoff(
        self, profile: AgentInstanceProfile, package: AgentHandoffPackage
    ) -> AgentDispatchResult:
        self._unavailable()


@dataclass(frozen=True)
class AgentRegistry:
    """Immutable validated provider and instance configuration."""

    providers: Mapping[str, AgentProvider]
    _profiles: Mapping[str, AgentInstanceProfile]
    _drivers: Mapping[str, PrimaryDriver]

    @classmethod
    def load(
        cls, committed_path: str | Path, local_path: str | Path | None = None
    ) -> AgentRegistry:
        committed = _read_json_object(Path(committed_path))
        local = _read_json_object(Path(local_path)) if local_path is not None else None
        _reject_inline_secrets(committed)
        if local is not None:
            _reject_inline_secrets(local)
        configuration = _merge_local_overrides(committed, local)
        if configuration.get("schema_version", 1) != 1:
            raise ValueError("unsupported provider registry schema_version")
        provider_records = _records_by_id(configuration.get("providers", []), "providers")
        providers = {
            provider_id: _provider_from_record(record)
            for provider_id, record in provider_records.items()
        }
        profile_records = _records_by_id(configuration.get("instances", []), "instances")
        profiles = {
            instance_id: _profile_from_record(record, providers)
            for instance_id, record in profile_records.items()
        }
        _validate_fallbacks(profiles)
        drivers = {
            instance_id: _ConfiguredDriver(providers[profile.primary_provider_id])
            for instance_id, profile in profiles.items()
        }
        return cls(
            providers=MappingProxyType(providers),
            _profiles=MappingProxyType(profiles),
            _drivers=MappingProxyType(drivers),
        )

    def profile(self, instance_id: str) -> AgentInstanceProfile:
        try:
            return self._profiles[instance_id]
        except KeyError as error:
            raise KeyError(f"unknown agent instance: {instance_id}") from error

    def driver(self, instance_id: str) -> PrimaryDriver:
        try:
            return self._drivers[instance_id]
        except KeyError as error:
            raise KeyError(f"unknown agent instance: {instance_id}") from error
