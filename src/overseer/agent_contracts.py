"""Provider-neutral contracts for Overseer's primary AI driver."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import re
from types import MappingProxyType
from typing import Mapping, Protocol, runtime_checkable


class AgentTransport(StrEnum):
    INTERACTIVE_CLI = "interactive_cli"
    NONINTERACTIVE_CLI = "noninteractive_cli"
    API = "api"
    GATEWAY = "gateway"


class AgentOperationState(StrEnum):
    QUEUED = "queued"
    ACKNOWLEDGED = "acknowledged"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


class AgentErrorCategory(StrEnum):
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    CONFIGURATION_ERROR = "configuration_error"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    SESSION_NOT_FOUND = "session_not_found"
    AUTHENTICATION_REQUIRED = "authentication_required"
    DISPATCH_REJECTED = "dispatch_rejected"
    DISPATCH_TIMEOUT = "dispatch_timeout"
    PROVIDER_PROTOCOL_ERROR = "provider_protocol_error"
    POLICY_BLOCKED = "policy_blocked"
    HANDOFF_INCOMPATIBLE = "handoff_incompatible"
    CHECKPOINT_STALE = "checkpoint_stale"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


def _require_identifier(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a stable non-empty identifier")


def _validate_optional_identifier(value: str | None, label: str) -> None:
    if value is not None:
        _require_identifier(value, label)


def _freeze_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    frozen: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key.strip():
            raise TypeError("record mapping keys must be non-empty strings")
        frozen[key] = _freeze_value(item)
    return MappingProxyType(frozen)


def _freeze_value(value: object) -> object:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, (tuple, list)):
        return tuple(_freeze_value(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("record mappings support only scalar, sequence, and mapping values")


def _validate_identifier_collection(values: tuple[str, ...], label: str) -> None:
    for value in values:
        _require_identifier(value, label)


@dataclass(frozen=True)
class AgentCapabilities:
    """Technical provider support; authorization stays with Overseer policy."""

    session_discovery: bool = False
    session_resume: bool = False
    interactive_dispatch: bool = False
    noninteractive_dispatch: bool = False
    structured_events: bool = False
    checkpoints: bool = False
    cancellation: bool = False
    delegated_workers: bool = False
    usage_observation: bool = False
    handoff_import: bool = False

    def supports(self, required: AgentCapabilities) -> bool:
        return all(
            not required_value or available_value
            for available_value, required_value in zip(
                self._values(), required._values(), strict=True
            )
        )

    def _values(self) -> tuple[bool, ...]:
        return (
            self.session_discovery,
            self.session_resume,
            self.interactive_dispatch,
            self.noninteractive_dispatch,
            self.structured_events,
            self.checkpoints,
            self.cancellation,
            self.delegated_workers,
            self.usage_observation,
            self.handoff_import,
        )


@dataclass(frozen=True)
class CredentialReference:
    """A credential locator, never credential material."""

    id: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not re.fullmatch(
            r"secret://[A-Za-z0-9][A-Za-z0-9._/-]*", self.id
        ):
            raise ValueError("credential reference must use a secret:// identifier")


def _freeze_credential_references(
    value: Mapping[str, CredentialReference],
) -> Mapping[str, CredentialReference]:
    frozen: dict[str, CredentialReference] = {}
    for key, reference in value.items():
        _require_identifier(key, "credential reference name")
        if not isinstance(reference, CredentialReference):
            raise TypeError("credential reference values must be CredentialReference")
        frozen[key] = reference
    return MappingProxyType(frozen)


@dataclass(frozen=True)
class AgentProvider:
    id: str
    adapter_id: str
    capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    transports: tuple[AgentTransport, ...] = ()
    display_name: str | None = None
    executable_allowlist: tuple[str, ...] = ()
    required_secret_references: tuple[str, ...] = ()
    profile_ids: tuple[str, ...] = ()
    health_source_id: str | None = None
    usage_limit_source_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "transports", tuple(self.transports))
        object.__setattr__(self, "executable_allowlist", tuple(self.executable_allowlist))
        object.__setattr__(self, "required_secret_references", tuple(self.required_secret_references))
        object.__setattr__(self, "profile_ids", tuple(self.profile_ids))
        _require_identifier(self.id, "provider id")
        _require_identifier(self.adapter_id, "adapter id")
        _validate_identifier_collection(self.executable_allowlist, "executable")
        _validate_identifier_collection(
            self.required_secret_references, "required secret reference"
        )
        _validate_identifier_collection(self.profile_ids, "profile id")
        _validate_optional_identifier(self.health_source_id, "health source id")
        _validate_optional_identifier(self.usage_limit_source_id, "usage limit source id")


@dataclass(frozen=True)
class AgentInstanceProfile:
    id: str
    primary_provider_id: str
    transport: AgentTransport
    workspace: str
    primary_adapter_id: str | None = None
    model_profile_id: str | None = None
    external_session_id: str | None = None
    declared_capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    required_capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    detected_capabilities: AgentCapabilities | None = None
    credential_references: Mapping[str, CredentialReference] = field(default_factory=dict)
    permission_policy_ref: str | None = None
    execution_policy_ref: str | None = None
    provider_health_source_id: str | None = None
    usage_limit_source_id: str | None = None
    approved_fallback_provider_ids: tuple[str, ...] = ()
    controlled_failover_policy_ref: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "approved_fallback_provider_ids",
            tuple(self.approved_fallback_provider_ids),
        )
        _require_identifier(self.id, "instance id")
        _require_identifier(self.primary_provider_id, "primary provider id")
        if not isinstance(self.workspace, str) or not self.workspace.strip():
            raise ValueError("workspace must be non-empty")
        _validate_optional_identifier(self.primary_adapter_id, "primary adapter id")
        _validate_optional_identifier(self.model_profile_id, "model profile id")
        _validate_optional_identifier(self.external_session_id, "external session id")
        _validate_optional_identifier(self.permission_policy_ref, "permission policy reference")
        _validate_optional_identifier(self.execution_policy_ref, "execution policy reference")
        _validate_optional_identifier(self.provider_health_source_id, "provider health source id")
        _validate_optional_identifier(self.usage_limit_source_id, "usage limit source id")
        _validate_optional_identifier(
            self.controlled_failover_policy_ref, "controlled failover policy reference"
        )
        _validate_identifier_collection(
            self.approved_fallback_provider_ids, "fallback provider id"
        )
        if self.primary_provider_id in self.approved_fallback_provider_ids:
            raise ValueError("primary provider cannot be its own fallback")
        object.__setattr__(
            self,
            "credential_references",
            _freeze_credential_references(self.credential_references),
        )


@dataclass(frozen=True)
class AgentSession:
    id: str
    provider_id: str
    external_session_id: str | None
    workspace: str
    transport: AgentTransport
    capabilities: AgentCapabilities
    instance_id: str | None = None
    model_profile_id: str | None = None
    legacy_references: Mapping[str, object] = field(default_factory=dict)
    discovered_at: str | None = None
    last_observed_at: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.id, "session id")
        _require_identifier(self.provider_id, "provider id")
        _validate_optional_identifier(self.external_session_id, "external session id")
        if not isinstance(self.workspace, str) or not self.workspace.strip():
            raise ValueError("workspace must be non-empty")
        _validate_optional_identifier(self.instance_id, "instance id")
        _validate_optional_identifier(self.model_profile_id, "model profile id")
        object.__setattr__(self, "legacy_references", _freeze_mapping(self.legacy_references))


@dataclass(frozen=True)
class DriverEpoch:
    id: str
    instance_id: str
    session_id: str
    provider_id: str
    ordinal: int
    state: AgentOperationState
    opened_at: str | None = None
    closed_at: str | None = None
    reason: str | None = None
    replacement_epoch_id: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.id, "driver epoch id")
        _require_identifier(self.instance_id, "instance id")
        _require_identifier(self.session_id, "session id")
        _require_identifier(self.provider_id, "provider id")
        if not isinstance(self.ordinal, int) or isinstance(self.ordinal, bool) or self.ordinal < 1:
            raise ValueError("driver epoch ordinal must be a positive integer")
        _validate_optional_identifier(self.replacement_epoch_id, "replacement epoch id")


@dataclass(frozen=True)
class AgentDispatchRequest:
    id: str
    instance_id: str
    session_id: str
    driver_epoch_id: str
    idempotency_key: str
    prompt: str
    requested_at: str | None = None
    requested_by: str | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_identifier(self.id, "dispatch id")
        _require_identifier(self.instance_id, "instance id")
        _require_identifier(self.session_id, "session id")
        _require_identifier(self.driver_epoch_id, "driver epoch id")
        _require_identifier(self.idempotency_key, "idempotency key")
        if not isinstance(self.prompt, str) or not self.prompt.strip():
            raise ValueError("prompt must be non-empty")
        _validate_optional_identifier(self.requested_by, "requested by")
        object.__setattr__(self, "evidence", _freeze_mapping(self.evidence))


@dataclass(frozen=True)
class AgentDispatchResult:
    id: str
    request_id: str
    instance_id: str
    session_id: str
    driver_epoch_id: str
    provider_id: str
    state: AgentOperationState
    error_category: AgentErrorCategory | None = None
    error_message: str | None = None
    provider_reference: str | None = None
    external_session_id: str | None = None
    acknowledged_at: str | None = None
    completed_at: str | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_identifier(self.id, "dispatch result id")
        _require_identifier(self.request_id, "dispatch request id")
        _require_identifier(self.instance_id, "instance id")
        _require_identifier(self.session_id, "session id")
        _require_identifier(self.driver_epoch_id, "driver epoch id")
        _require_identifier(self.provider_id, "provider id")
        _validate_optional_identifier(self.provider_reference, "provider reference")
        _validate_optional_identifier(self.external_session_id, "external session id")
        object.__setattr__(self, "evidence", _freeze_mapping(self.evidence))

    @classmethod
    def unsupported(
        cls, request: AgentDispatchRequest, provider_id: str, capability: str
    ) -> AgentDispatchResult:
        _require_identifier(provider_id, "provider id")
        _require_identifier(capability, "capability")
        return cls(
            id=f"{request.id}.unsupported",
            request_id=request.id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            driver_epoch_id=request.driver_epoch_id,
            provider_id=provider_id,
            state=AgentOperationState.FAILED,
            error_category=AgentErrorCategory.UNSUPPORTED_CAPABILITY,
            error_message=f"unsupported capability: {capability}",
            evidence={"unsupported_capability": capability},
        )


@dataclass(frozen=True)
class AgentCheckpoint:
    id: str
    instance_id: str
    session_id: str
    driver_epoch_id: str
    evidence: Mapping[str, object] = field(default_factory=dict)
    created_at: str | None = None
    expires_at: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.id, "checkpoint id")
        _require_identifier(self.instance_id, "instance id")
        _require_identifier(self.session_id, "session id")
        _require_identifier(self.driver_epoch_id, "driver epoch id")
        object.__setattr__(self, "evidence", _freeze_mapping(self.evidence))


@dataclass(frozen=True)
class AgentHandoffPackage:
    id: str
    instance_id: str
    outgoing_epoch_id: str
    incoming_provider_id: str
    objective: str
    checkpoint_id: str | None = None
    required_capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    evidence: Mapping[str, object] = field(default_factory=dict)
    created_at: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.id, "handoff id")
        _require_identifier(self.instance_id, "instance id")
        _require_identifier(self.outgoing_epoch_id, "outgoing epoch id")
        _require_identifier(self.incoming_provider_id, "incoming provider id")
        if not isinstance(self.objective, str) or not self.objective.strip():
            raise ValueError("handoff objective must be non-empty")
        _validate_optional_identifier(self.checkpoint_id, "checkpoint id")
        object.__setattr__(self, "evidence", _freeze_mapping(self.evidence))


@runtime_checkable
class PrimaryDriver(Protocol):
    provider: AgentProvider

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]: ...

    def resolve(self, reference: str) -> AgentSession | None: ...

    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult: ...

    def resume(self, session: AgentSession) -> AgentDispatchResult: ...

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult: ...

    def inspect(self, session: AgentSession) -> AgentDispatchResult: ...

    def checkpoint(self, session: AgentSession) -> AgentCheckpoint: ...

    def cancel(self, session: AgentSession) -> AgentDispatchResult: ...

    def import_handoff(
        self, profile: AgentInstanceProfile, package: AgentHandoffPackage
    ) -> AgentDispatchResult: ...
