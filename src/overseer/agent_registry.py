"""Validated provider configuration for Overseer's primary AI driver."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable

from .agent_contracts import (
    AgentCapabilities,
    AgentInstanceProfile,
    AgentProvider,
    AgentTransport,
    CredentialReference,
    PrimaryDriver,
)


AgentAdapterFactory = Callable[[AgentProvider, AgentInstanceProfile], PrimaryDriver]


class AgentAdapterUnavailableError(RuntimeError):
    """Raised when a selected provider has no ready, registered adapter."""


_ALLOWED_EXECUTABLES = frozenset({"codex", "claude", "qwen", "vibe"})
_ALLOWED_ADAPTERS = frozenset(
    {"codex", "claude", "qwen_code", "mistral_vibe", "antigravity"}
)
_ADAPTER_COMBINATIONS = {
    "codex": (AgentTransport.INTERACTIVE_CLI, "codex"),
    "claude": (AgentTransport.NONINTERACTIVE_CLI, "claude"),
    "qwen_code": (AgentTransport.INTERACTIVE_CLI, "qwen"),
    "mistral_vibe": (AgentTransport.INTERACTIVE_CLI, "vibe"),
    "antigravity": (AgentTransport.GATEWAY, None),
}
_SECRET_KEY_PATTERN = re.compile(
    r"(?:secret|password|(?:api|private|access)[_-]?key|token|credential|authorization|auth|cookie|bearer)",
    re.IGNORECASE,
)
_EXECUTABLE_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_CAPABILITY_NAMES = frozenset(field.name for field in fields(AgentCapabilities))
_PROVIDER_FIELDS = frozenset(
    {
        "id",
        "adapter",
        "transport",
        "executable",
        "executable_path",
        "capabilities",
        "required_secret_references",
    }
)
_INSTANCE_FIELDS = frozenset(
    {
        "id",
        "primary_provider_id",
        "workspace",
        "fallback_provider_ids",
        "credential_references",
        "required_capabilities",
        "model_profile_id",
    }
)
_LOCAL_PROVIDER_FIELDS = frozenset({"executable_path"})
_LOCAL_INSTANCE_FIELDS = frozenset(
    {"workspace", "model_profile_id", "credential_references"}
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
            if child_key == "required_secret_references":
                for reference_name in _require_list(child_value, child_key):
                    if not isinstance(reference_name, str) or not reference_name:
                        raise ValueError("required secret references must be non-empty names")
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


def _validate_local_override_fields(section: str, override: Mapping[str, Any]) -> None:
    allowed = _LOCAL_PROVIDER_FIELDS if section == "providers" else _LOCAL_INSTANCE_FIELDS
    disallowed = {
        key
        for key in override
        if key not in allowed and not key.lower().endswith("_secret_ref")
    }
    if disallowed:
        raise ValueError(
            f"local override cannot change committed {section} fields: {sorted(disallowed)}"
        )


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
            _validate_local_override_fields(
                section, _require_mapping(override, f"local {section} override")
            )
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


def _validate_fields(
    record: Mapping[str, Any], allowed: frozenset[str], label: str, *, allow_secret_refs: bool
) -> None:
    unknown = {
        key
        for key in record
        if key not in allowed and not (allow_secret_refs and key.lower().endswith("_secret_ref"))
    }
    if unknown:
        raise ValueError(f"unknown {label} fields: {sorted(unknown)}")


def _provider_from_record(record: Mapping[str, Any]) -> AgentProvider:
    _validate_fields(record, _PROVIDER_FIELDS, "provider", allow_secret_refs=False)
    provider_id = record.get("id")
    adapter = record.get("adapter")
    executable = record.get("executable")
    executable_path = record.get("executable_path")
    if not isinstance(provider_id, str) or not provider_id:
        raise ValueError("provider id must be non-empty")
    if not isinstance(adapter, str) or adapter not in _ALLOWED_ADAPTERS:
        raise ValueError("provider adapter is not supported")
    try:
        transport = AgentTransport(record.get("transport"))
    except (TypeError, ValueError) as error:
        raise ValueError("provider transport is not supported") from error
    if transport is not AgentTransport.GATEWAY:
        if not isinstance(executable, str) or not _EXECUTABLE_NAME_PATTERN.fullmatch(executable):
            raise ValueError("executable name must be a single command name")
        if executable not in _ALLOWED_EXECUTABLES:
            raise ValueError("executable is not allowlisted")
    if _ADAPTER_COMBINATIONS[adapter] != (transport, executable):
        raise ValueError("provider adapter, transport, and executable combination is invalid")
    if transport is AgentTransport.GATEWAY:
        if executable is not None or executable_path is not None:
            raise ValueError("gateway provider executable must be null")
        executable_allowlist: tuple[str, ...] = ()
    else:
        if executable_path is None:
            executable_allowlist = (executable,)
        else:
            if not isinstance(executable_path, str) or not Path(executable_path).is_absolute():
                raise ValueError("local executable_path must be an absolute path")
            canonical_path = Path(executable_path).resolve()
            if canonical_path.name != executable:
                raise ValueError("local executable_path basename must match the provider executable")
            executable_allowlist = (str(canonical_path),)
    return AgentProvider(
        id=provider_id,
        adapter_id=adapter,
        capabilities=_capabilities(record.get("capabilities", {})),
        transports=(transport,),
        executable_allowlist=executable_allowlist,
        required_secret_references=tuple(
            _require_list(record.get("required_secret_references", []), "required_secret_references")
        ),
    )


def _profile_from_record(
    record: Mapping[str, Any], providers: Mapping[str, AgentProvider]
) -> AgentInstanceProfile:
    _validate_fields(record, _INSTANCE_FIELDS, "instance", allow_secret_refs=True)
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
    if len(set(fallback_ids)) != len(fallback_ids):
        raise ValueError("fallback provider ids must be unique and ordered")
    required_capabilities = (
        _capabilities(record["required_capabilities"])
        if "required_capabilities" in record
        else AgentCapabilities(handoff_import=True)
        if fallback_ids
        else AgentCapabilities()
    )
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
        model_profile_id=record.get("model_profile_id"),
        declared_capabilities=providers[primary_provider_id].capabilities,
        required_capabilities=required_capabilities,
        credential_references={key: _secret_reference(value) for key, value in references.items()},
        approved_fallback_provider_ids=tuple(fallback_ids),
    )


def _validate_fallbacks(
    profiles: Mapping[str, AgentInstanceProfile], providers: Mapping[str, AgentProvider]
) -> None:
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
    for profile in profiles.values():
        for fallback_id in profile.approved_fallback_provider_ids:
            if not providers[fallback_id].capabilities.supports(profile.required_capabilities):
                raise ValueError("fallback provider lacks required capabilities")


def _validate_required_secret_references(
    profiles: Mapping[str, AgentInstanceProfile], providers: Mapping[str, AgentProvider]
) -> None:
    for profile in profiles.values():
        selected_provider_ids = (
            profile.primary_provider_id,
            *profile.approved_fallback_provider_ids,
        )
        required = tuple(
            reference_name
            for provider_id in selected_provider_ids
            for reference_name in providers[provider_id].required_secret_references
        )
        missing = [name for name in required if name not in profile.credential_references]
        if missing:
            raise ValueError(f"profile is missing required credential reference: {missing[0]}")


def _validate_top_level_sections(configuration: Mapping[str, Any], source: str) -> None:
    unknown = set(configuration) - {"schema_version", "providers", "instances"}
    if unknown:
        raise ValueError(f"{source} configuration contains unknown sections: {sorted(unknown)}")


def _validate_committed_machine_local_fields(configuration: Mapping[str, Any]) -> None:
    for provider in _require_list(configuration.get("providers", []), "providers"):
        if "executable_path" in _require_mapping(provider, "provider record"):
            raise ValueError("committed configuration cannot set machine-local executable_path")


@dataclass(frozen=True)
class AgentRegistry:
    """Immutable validated provider and instance configuration."""

    providers: Mapping[str, AgentProvider]
    _profiles: Mapping[str, AgentInstanceProfile]
    _adapter_factories: Mapping[str, AgentAdapterFactory]

    @classmethod
    def load(
        cls,
        committed_path: str | Path,
        local_path: str | Path | None = None,
        *,
        adapter_factories: Mapping[str, AgentAdapterFactory] | None = None,
    ) -> AgentRegistry:
        committed = _read_json_object(Path(committed_path))
        local = _read_json_object(Path(local_path)) if local_path is not None else None
        _validate_top_level_sections(committed, "committed")
        _validate_committed_machine_local_fields(committed)
        _reject_inline_secrets(committed)
        if local is not None:
            _validate_top_level_sections(local, "local override")
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
        _validate_required_secret_references(profiles, providers)
        _validate_fallbacks(profiles, providers)
        from .agent_adapters import ADAPTER_FACTORIES

        factories = dict(ADAPTER_FACTORIES)
        factories.update(adapter_factories or {})
        if any(not isinstance(adapter_id, str) or not callable(factory) for adapter_id, factory in factories.items()):
            raise TypeError("adapter_factories must map adapter ids to callables")
        return cls(
            providers=MappingProxyType(providers),
            _profiles=MappingProxyType(profiles),
            _adapter_factories=MappingProxyType(factories),
        )

    def profile(self, instance_id: str) -> AgentInstanceProfile:
        try:
            return self._profiles[instance_id]
        except KeyError as error:
            raise KeyError(f"unknown agent instance: {instance_id}") from error

    @property
    def profiles(self) -> Mapping[str, AgentInstanceProfile]:
        return self._profiles

    def adapter_factory_available(self, adapter_id: str) -> bool:
        return adapter_id in self._adapter_factories

    def driver(self, instance_id: str) -> PrimaryDriver:
        profile = self.profile(instance_id)
        return self._driver_for(profile)

    def profile_for_provider(
        self,
        instance_id: str,
        provider_id: str,
    ) -> AgentInstanceProfile:
        profile = self.profile(instance_id)
        allowed_provider_ids = {
            profile.primary_provider_id,
            *profile.approved_fallback_provider_ids,
        }
        if provider_id not in allowed_provider_ids:
            raise ValueError(
                f"provider {provider_id} is not approved for instance {instance_id}"
            )
        provider = self.providers[provider_id]
        alternate_provider_ids = (
            profile.primary_provider_id,
            *profile.approved_fallback_provider_ids,
        )
        return replace(
            profile,
            primary_provider_id=provider.id,
            transport=provider.transports[0],
            primary_adapter_id=provider.adapter_id,
            external_session_id=None,
            declared_capabilities=provider.capabilities,
            approved_fallback_provider_ids=tuple(
                alternate_id
                for alternate_id in alternate_provider_ids
                if alternate_id != provider_id
            ),
        )

    def driver_for_provider(
        self,
        provider_id: str,
        *,
        instance_id: str | None = None,
    ) -> PrimaryDriver:
        if instance_id is None:
            candidates = tuple(
                profile.id
                for profile in self._profiles.values()
                if provider_id
                in {
                    profile.primary_provider_id,
                    *profile.approved_fallback_provider_ids,
                }
            )
            if len(candidates) != 1:
                raise ValueError(
                    "instance_id is required unless the provider selects one instance"
                )
            instance_id = candidates[0]
        return self._driver_for(self.profile_for_provider(instance_id, provider_id))

    def _driver_for(self, profile: AgentInstanceProfile) -> PrimaryDriver:
        provider = self.providers[profile.primary_provider_id]
        factory = self._adapter_factories.get(provider.adapter_id)
        if factory is None:
            raise AgentAdapterUnavailableError(
                f"no registered adapter factory for {provider.adapter_id}"
            )
        try:
            driver = factory(provider, profile)
        except Exception as error:
            raise AgentAdapterUnavailableError(
                f"adapter factory for {provider.adapter_id} is not ready"
            ) from error
        if not isinstance(driver, PrimaryDriver):
            raise AgentAdapterUnavailableError(
                f"adapter factory for {provider.adapter_id} returned an invalid driver"
            )
        if not isinstance(driver.provider, AgentProvider) or driver.provider != provider:
            raise AgentAdapterUnavailableError(
                f"adapter factory for {provider.adapter_id} returned mismatched provider claims"
            )
        return driver
