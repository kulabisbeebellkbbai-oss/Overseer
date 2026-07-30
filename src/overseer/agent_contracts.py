"""Provider-neutral contracts for Overseer's primary AI driver."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
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


class AgentTransitionState(StrEnum):
    IMPORTING = "importing"
    IMPORT_ACKNOWLEDGED = "import_acknowledged"
    RECONCILING = "reconciling"
    FAILED = "failed"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"


class AgentOperationFenceState(StrEnum):
    OPEN = "open"
    FENCED = "fenced"


class ProviderHealthState(StrEnum):
    HEALTHY = "healthy"
    TRANSPORT_FAILURE = "transport_failure"
    FAILED = "failed"
    SLOW = "slow"


class ActiveAgentRiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FailoverExecutionState(StrEnum):
    RESERVED = "reserved"
    DRAINING = "draining"
    BLOCKED_PREIMPORT = "blocked_preimport"
    RECOVERING = "recovering"
    RECOVERED = "recovered"
    TRANSITION_STARTED = "transition_started"


RECOVERABLE_FAILOVER_EXECUTION_STATES = frozenset(
    {
        FailoverExecutionState.RESERVED,
        FailoverExecutionState.DRAINING,
        FailoverExecutionState.BLOCKED_PREIMPORT,
        FailoverExecutionState.RECOVERING,
    }
)

FAILOVER_RECOVERY_BLOCKERS = {
    FailoverExecutionState.RESERVED: "reserved_before_drain",
    FailoverExecutionState.DRAINING: "drain_state_requires_inspection",
    FailoverExecutionState.BLOCKED_PREIMPORT: "preimport_recovery_required",
    FailoverExecutionState.RECOVERING: "recovery_attempt_requires_reconciliation",
}


class AgentRecoveryAttemptState(StrEnum):
    PENDING = "pending"
    EXTERNAL_STARTED = "external_started"
    RESULT_RECORDED = "result_recorded"
    FINALIZED = "finalized"
    BLOCKED = "blocked"


FAILOVER_BLOCKER_VOCABULARY = (
    "failover policy missing or not approved",
    "policy approval does not predate failure sequence",
    "slow response is not a failover trigger",
    "failure threshold not reached",
    "checkpoint missing, stale, expired, or incorrectly bound",
    "unresolved high-risk action",
    "non-transferable active operation or checkpoint state",
    "no healthy approved fallback",
    "fallback capability mismatch or missing handoff_import",
    "transition, reservation, or epoch already changed",
)


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


def _require_safe_identifier(value: str, label: str) -> None:
    _require_identifier(value, label)
    if re.search(
        r"(?:bearer\s+|password\s*[:=]|secret\s*[:=]|\bsk-[A-Za-z0-9])",
        value,
        re.I,
    ):
        raise ValueError(f"{label} cannot contain secret-like material")


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


def _validate_unique_identifier_collection(
    values: tuple[str, ...], label: str
) -> None:
    _validate_identifier_collection(values, label)
    if len(set(values)) != len(values):
        raise ValueError(f"{label} values must be unique")


def _require_timestamp(value: str, label: str) -> datetime:
    _require_identifier(value, label)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed


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
        _validate_unique_identifier_collection(
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
class AgentInstanceTransition:
    instance_id: str
    handoff_id: str
    outgoing_epoch_id: str
    incoming_epoch_id: str
    state: AgentTransitionState
    updated_at: str
    reason: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.instance_id, "instance id")
        _require_identifier(self.handoff_id, "handoff id")
        _require_identifier(self.outgoing_epoch_id, "outgoing epoch id")
        _require_identifier(self.incoming_epoch_id, "incoming epoch id")
        _require_identifier(self.updated_at, "transition timestamp")


@dataclass(frozen=True)
class AgentOperationReservation:
    instance_id: str
    generation: int
    state: AgentOperationFenceState
    owner_token: str | None
    updated_at: str

    def __post_init__(self) -> None:
        _require_identifier(self.instance_id, "instance id")
        if (
            not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < 1
        ):
            raise ValueError("operation generation must be a positive integer")
        _validate_optional_identifier(self.owner_token, "operation owner token")
        _require_identifier(self.updated_at, "operation timestamp")


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
class FailoverPolicy:
    id: str
    instance_id: str
    approved: bool
    approval_ref: str | None
    approved_at: str | None
    failure_threshold: int
    checkpoint_max_age_seconds: int
    approved_fallback_provider_ids: tuple[str, ...]
    decision_lifetime_seconds: int

    def __post_init__(self) -> None:
        _require_safe_identifier(self.id, "failover policy id")
        _require_safe_identifier(self.instance_id, "instance id")
        _validate_optional_identifier(self.approval_ref, "approval reference")
        if type(self.approved) is not bool:
            raise TypeError("approved must be a boolean")
        if self.approved:
            if self.approval_ref is None or self.approved_at is None:
                raise ValueError("approved failover policy requires approval evidence")
        if self.approved_at is not None:
            _require_timestamp(self.approved_at, "policy approval timestamp")
        for value, label in (
            (self.failure_threshold, "failure threshold"),
            (self.checkpoint_max_age_seconds, "checkpoint maximum age"),
            (self.decision_lifetime_seconds, "decision lifetime"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{label} must be a positive integer")
        object.__setattr__(
            self,
            "approved_fallback_provider_ids",
            tuple(self.approved_fallback_provider_ids),
        )
        _validate_unique_identifier_collection(
            self.approved_fallback_provider_ids, "fallback provider id"
        )


@dataclass(frozen=True)
class ProviderHealthObservation:
    id: str
    instance_id: str
    provider_id: str
    state: ProviderHealthState
    observed_at: str
    reason_category: str

    def __post_init__(self) -> None:
        _require_safe_identifier(self.id, "health evidence id")
        _require_safe_identifier(self.instance_id, "instance id")
        _require_safe_identifier(self.provider_id, "provider id")
        if not isinstance(self.state, ProviderHealthState):
            raise TypeError("health state must be ProviderHealthState")
        _require_timestamp(self.observed_at, "health observation timestamp")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", self.reason_category):
            raise ValueError("health reason must be a redacted category")


@dataclass(frozen=True)
class ActiveAgentRisk:
    id: str
    instance_id: str
    risk_level: ActiveAgentRiskLevel
    resolved: bool
    transferable: bool
    evidence_ref: str

    def __post_init__(self) -> None:
        _require_safe_identifier(self.id, "active risk id")
        _require_safe_identifier(self.instance_id, "instance id")
        _require_safe_identifier(self.evidence_ref, "risk evidence reference")
        if not isinstance(self.risk_level, ActiveAgentRiskLevel):
            raise TypeError("risk level must be ActiveAgentRiskLevel")
        if type(self.resolved) is not bool or type(self.transferable) is not bool:
            raise TypeError("risk resolved and transferable must be booleans")


@dataclass(frozen=True)
class FailoverDecision:
    id: str
    instance_id: str
    outgoing_epoch_id: str
    outgoing_provider_id: str
    operation_generation: int
    policy_id: str | None
    incoming_provider_id: str | None
    allowed: bool
    blockers: tuple[str, ...]
    health_evidence_ids: tuple[str, ...]
    risk_evidence_ids: tuple[str, ...]
    evidence_timestamps: tuple[str, ...]
    readiness_evidence_refs: tuple[str, ...]
    checkpoint_id: str | None
    evaluated_at: str
    expires_at: str
    consumed_at: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.id, "failover decision id"),
            (self.instance_id, "instance id"),
            (self.outgoing_epoch_id, "outgoing epoch id"),
            (self.outgoing_provider_id, "outgoing provider id"),
        ):
            _require_safe_identifier(value, label)
        _validate_optional_identifier(self.policy_id, "failover policy id")
        _validate_optional_identifier(self.incoming_provider_id, "incoming provider id")
        _validate_optional_identifier(self.checkpoint_id, "checkpoint id")
        if (
            not isinstance(self.operation_generation, int)
            or isinstance(self.operation_generation, bool)
            or self.operation_generation < 1
        ):
            raise ValueError("operation generation must be positive")
        object.__setattr__(self, "blockers", tuple(self.blockers))
        object.__setattr__(self, "health_evidence_ids", tuple(self.health_evidence_ids))
        object.__setattr__(self, "risk_evidence_ids", tuple(self.risk_evidence_ids))
        object.__setattr__(self, "evidence_timestamps", tuple(self.evidence_timestamps))
        object.__setattr__(
            self, "readiness_evidence_refs", tuple(self.readiness_evidence_refs)
        )
        _validate_unique_identifier_collection(
            self.health_evidence_ids, "health evidence id"
        )
        _validate_unique_identifier_collection(
            self.risk_evidence_ids, "risk evidence id"
        )
        for timestamp in self.evidence_timestamps:
            _require_timestamp(timestamp, "failover evidence timestamp")
        _validate_unique_identifier_collection(
            self.readiness_evidence_refs, "readiness evidence reference"
        )
        for value in (
            *self.health_evidence_ids,
            *self.risk_evidence_ids,
            *self.readiness_evidence_refs,
        ):
            _require_safe_identifier(value, "failover evidence reference")
        if type(self.allowed) is not bool:
            raise TypeError("allowed must be a boolean")
        if len(set(self.blockers)) != len(self.blockers):
            raise ValueError("failover blockers must be unique")
        if any(item not in FAILOVER_BLOCKER_VOCABULARY for item in self.blockers):
            raise ValueError("failover blocker is not recognized")
        expected_order = tuple(
            item for item in FAILOVER_BLOCKER_VOCABULARY if item in self.blockers
        )
        if self.blockers != expected_order:
            raise ValueError("failover blockers must use deterministic order")
        evaluated = _require_timestamp(self.evaluated_at, "decision evaluation timestamp")
        expires = _require_timestamp(self.expires_at, "decision expiry timestamp")
        if expires <= evaluated:
            raise ValueError("decision expiry must follow evaluation")
        if self.consumed_at is not None:
            _require_timestamp(self.consumed_at, "decision consumed timestamp")
        if self.allowed != (not self.blockers):
            raise ValueError("allowed decision must have no blockers")
        if self.allowed and (
            self.policy_id is None
            or self.incoming_provider_id is None
            or self.checkpoint_id is None
        ):
            raise ValueError("allowed decision requires policy, checkpoint, and fallback")


@dataclass(frozen=True)
class FailoverExecution:
    id: str
    decision_id: str
    instance_id: str
    outgoing_epoch_id: str
    outgoing_session_id: str
    outgoing_provider_id: str
    checkpoint_id: str
    operation_generation: int
    operation_owner_ref: str
    state: FailoverExecutionState
    created_at: str
    updated_at: str
    reason: str | None = None
    resume_result_ref: str | None = None

    def __post_init__(self) -> None:
        for value, label in (
            (self.id, "failover execution id"),
            (self.decision_id, "failover decision id"),
            (self.instance_id, "instance id"),
            (self.outgoing_epoch_id, "outgoing epoch id"),
            (self.outgoing_session_id, "outgoing session id"),
            (self.outgoing_provider_id, "outgoing provider id"),
            (self.checkpoint_id, "checkpoint id"),
            (self.operation_owner_ref, "operation owner reference"),
        ):
            _require_safe_identifier(value, label)
        if (
            not isinstance(self.operation_generation, int)
            or isinstance(self.operation_generation, bool)
            or self.operation_generation < 1
        ):
            raise ValueError("operation generation must be positive")
        if not isinstance(self.state, FailoverExecutionState):
            raise TypeError("failover execution state is invalid")
        _require_timestamp(self.created_at, "execution creation timestamp")
        _require_timestamp(self.updated_at, "execution update timestamp")
        _validate_optional_identifier(self.resume_result_ref, "resume result reference")
        if self.reason is not None and not re.fullmatch(
            r"[a-z][a-z0-9_.-]{0,63}", self.reason
        ):
            raise ValueError("execution reason must be a redacted category")


@dataclass(frozen=True)
class AgentRecoveryAttempt:
    id: str
    idempotency_key: str
    execution_id: str
    decision_id: str
    instance_id: str
    outgoing_epoch_id: str
    provider_id: str
    internal_session_id: str
    external_session_id: str | None
    operation_generation: int
    operation_owner_ref: str
    state: AgentRecoveryAttemptState
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.id, "recovery attempt id"),
            (self.idempotency_key, "recovery idempotency key"),
            (self.execution_id, "failover execution id"),
            (self.decision_id, "failover decision id"),
            (self.instance_id, "instance id"),
            (self.outgoing_epoch_id, "outgoing epoch id"),
            (self.provider_id, "provider id"),
            (self.internal_session_id, "internal session id"),
            (self.operation_owner_ref, "operation owner reference"),
        ):
            _require_safe_identifier(value, label)
        if not isinstance(self.state, AgentRecoveryAttemptState):
            raise TypeError("recovery attempt state is invalid")
        _validate_optional_identifier(self.external_session_id, "external session id")
        if (
            not isinstance(self.operation_generation, int)
            or isinstance(self.operation_generation, bool)
            or self.operation_generation < 1
        ):
            raise ValueError("operation generation must be positive")
        _require_timestamp(self.created_at, "attempt creation timestamp")
        _require_timestamp(self.updated_at, "attempt update timestamp")


@dataclass(frozen=True)
class AgentRecoveryOutcome:
    id: str
    attempt_id: str
    raw_result_id: str
    request_id: str
    provenance_ref: str
    state: AgentOperationState
    recorded_at: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.id, "recovery outcome id"),
            (self.attempt_id, "recovery attempt id"),
            (self.raw_result_id, "raw result id"),
            (self.request_id, "request id"),
            (self.provenance_ref, "result provenance reference"),
        ):
            _require_safe_identifier(value, label)
        if self.state not in _ACKNOWLEDGED_RECOVERY_STATES:
            raise ValueError("recovery outcome state is not resumable")
        _require_timestamp(self.recorded_at, "outcome timestamp")


@dataclass(frozen=True)
class AgentRecoveryRequest:
    id: str
    idempotency_key: str
    attempt_id: str
    execution_id: str
    instance_id: str
    driver_epoch_id: str
    provider_id: str
    internal_session_id: str
    external_session_id: str | None
    requested_at: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.id, "recovery request id"),
            (self.idempotency_key, "recovery idempotency key"),
            (self.attempt_id, "recovery attempt id"),
            (self.execution_id, "failover execution id"),
            (self.instance_id, "instance id"),
            (self.driver_epoch_id, "driver epoch id"),
            (self.provider_id, "provider id"),
            (self.internal_session_id, "internal session id"),
        ):
            _require_safe_identifier(value, label)
        _validate_optional_identifier(self.external_session_id, "external session id")
        _require_timestamp(self.requested_at, "recovery request timestamp")


_ACKNOWLEDGED_RECOVERY_STATES = {
    AgentOperationState.ACKNOWLEDGED,
    AgentOperationState.RUNNING,
    AgentOperationState.SUCCEEDED,
}


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

    def recover(
        self, request: AgentRecoveryRequest, session: AgentSession
    ) -> AgentDispatchResult: ...

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult: ...

    def inspect(self, session: AgentSession) -> AgentDispatchResult: ...

    def checkpoint(self, session: AgentSession) -> AgentCheckpoint: ...

    def cancel(self, session: AgentSession) -> AgentDispatchResult: ...

    def import_handoff(
        self, profile: AgentInstanceProfile, package: AgentHandoffPackage
    ) -> AgentDispatchResult: ...
