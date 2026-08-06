"""Typed, immutable and hash-chained backup execution contracts."""

from __future__ import annotations

from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import json
import math
import re
import errno
import socket
from pathlib import Path
import uuid
from typing import Any, Literal, Mapping, TYPE_CHECKING

if TYPE_CHECKING:
    from .store import SQLiteStore

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00\Z")
_SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_SUCCESS = "ACCEPTANCE_PASSED"
_DOMAIN_ARGS = "overseer.backup-provisioning.arguments.v1"
_DOMAIN_STEP = "overseer.backup-provisioning.step.v1"
_DOMAIN_HEADER = "overseer.backup-provisioning.execution-header.v1"
_DOMAIN_CHECKPOINT = "overseer.backup-provisioning.checkpoint.v1"
_DOMAIN_CHECKPOINT_V3 = "overseer.backup-provisioning.checkpoint.v3"


class ExecutionPhase(StrEnum):
    MATERIALIZE = "materialize"
    REGISTER = "register"
    ACTIVATE = "activate"
    ATTEST = "attest"
    ACCEPT = "accept"
    FINALIZE = "finalize"


class StepDisposition(StrEnum):
    CHANGED = "changed"
    VERIFIED_NOOP = "verified_noop"
    FAILED = "failed"


class CheckpointEvent(StrEnum):
    STEP_STARTED = "step_started"
    STEP_COMPLETED = "step_completed"
    STEP_FAILED = "step_failed"
    ROLLBACK_STARTED = "rollback_started"
    ROLLBACK_COMPLETED = "rollback_completed"
    ROLLBACK_FAILED = "rollback_failed"
    EXECUTION_ABORTED = "execution_aborted"
    EXECUTION_FINALIZED = "execution_finalized"


class _AuthorityRecordError(ValueError):
    """A persisted authority record is missing or cannot be decoded."""


class _AuthorityMismatchError(ValueError):
    """The exact persisted authority no longer matches the execution header."""


class _ExactApprovalSourceError(ValueError):
    """The exact approval source is missing or cannot be decoded."""


class _ExecutionContentionError(ValueError):
    """A verified concurrent execution owns the next durable transition."""


class _RollbackOwnerSocketCollision(OSError):
    """An owner socket namespace is already occupied; claim context decides its meaning."""


def _string(value: object, label: str, *, identifier: bool = False) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty string")
    if identifier and _ID.fullmatch(value) is None:
        raise ValueError(f"{label} is not a safe identifier")
    return value


def _digest(value: object, label: str) -> str:
    value = _string(value, label)
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def _timestamp(value: object, label: str) -> str:
    value = _string(value, label)
    if _UTC.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical +00:00 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a canonical +00:00 timestamp") from error
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} must be UTC")
    return value


def _canonical_timestamp(value: object, label: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be UTC")
    parsed = parsed.astimezone(UTC)
    return parsed.isoformat(timespec="microseconds" if parsed.microsecond else "seconds")


def _ordinal(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _code(value: object, label: str) -> str:
    value = _string(value, label)
    if _SAFE_CODE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable safe code")
    return value


def _strict_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a bool")
    return value


def _tuple(value: object, label: str, *, nonempty: bool = False) -> tuple[Any, ...]:
    if type(value) is not tuple or (nonempty and not value):
        raise ValueError(f"{label} must be an immutable tuple")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _hash(domain: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + _canonical(value)).encode()).hexdigest()


def _exact(value: Any, cls: type[Any], label: str) -> None:
    if type(value) is not cls:
        raise ValueError(f"{label} has the wrong exact type")


def _json_value(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if type(value) is tuple:
        return [_json_value(item) for item in value]
    if type(value) is dict:
        if any(not isinstance(key, str) for key in value):
            raise ValueError("execution evidence mapping keys must be strings")
        return {key: _json_value(item) for key, item in sorted(value.items())}
    if hasattr(value, "__dataclass_fields__"):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("execution payload contains an unsupported or non-finite value")


@dataclass(frozen=True)
class ExecutionOperationIdentity:
    operation: str
    arguments_digest: str
    step_digest: str

    def __post_init__(self) -> None:
        _string(self.operation, "operation", identifier=True)
        _digest(self.arguments_digest, "arguments_digest")
        _digest(self.step_digest, "step_digest")


@dataclass(frozen=True)
class ExecutionStepIdentity:
    plan_step_ordinal: int
    forward: ExecutionOperationIdentity
    rollback: ExecutionOperationIdentity | None = None

    def __post_init__(self) -> None:
        _ordinal(self.plan_step_ordinal, "plan_step_ordinal")
        _exact(self.forward, ExecutionOperationIdentity, "forward")
        self.forward.__post_init__()
        if self.rollback is not None:
            _exact(self.rollback, ExecutionOperationIdentity, "rollback")
            self.rollback.__post_init__()

    @property
    def rollback_operation(self) -> ExecutionOperationIdentity | None:
        return self.rollback


@dataclass(frozen=True)
class ExecutionPhaseSpec:
    phase_ordinal: int
    phase: ExecutionPhase
    steps: tuple[ExecutionStepIdentity, ...]

    def __post_init__(self) -> None:
        _ordinal(self.phase_ordinal, "phase_ordinal")
        if type(self.phase) is not ExecutionPhase:
            raise ValueError("phase must be an ExecutionPhase")
        _tuple(self.steps, "steps", nonempty=True)
        if any(type(step) is not ExecutionStepIdentity for step in self.steps):
            raise ValueError("steps must contain exact ExecutionStepIdentity values")
        for step in self.steps:
            step.__post_init__()
        ordinals = tuple(step.plan_step_ordinal for step in self.steps)
        if ordinals != tuple(sorted(ordinals)) or len(set(ordinals)) != len(ordinals):
            raise ValueError("phase steps must be ordered and unique")


@dataclass(frozen=True)
class ProvisioningExecutionHeader:
    schema_version: Literal["2"]
    execution_id: str
    plan_id: str
    plan_digest: str
    bundle_id: str
    bundle_digest: str
    approval_ref: str
    approval_scope_digest: str
    approved_by: str
    approved_at: str
    acceptance_contract_version: str
    acceptance_contract_digest: str
    approved_runtime_digest: str
    approved_config_digest: str
    created_at: str
    phases: tuple[ExecutionPhaseSpec, ...]
    header_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != "2":
            raise ValueError("schema_version must be '2'")
        for name in ("execution_id", "plan_id", "bundle_id", "approval_ref", "approved_by"):
            _string(getattr(self, name), name, identifier=True)
        for name in ("plan_digest", "bundle_digest", "approval_scope_digest", "acceptance_contract_digest", "approved_runtime_digest", "approved_config_digest", "header_digest"):
            _digest(getattr(self, name), name)
        _timestamp(self.approved_at, "approved_at")
        _timestamp(self.created_at, "created_at")
        if datetime.fromisoformat(self.created_at) < datetime.fromisoformat(self.approved_at):
            raise ValueError("created_at must be at or after approved_at")
        _string(self.acceptance_contract_version, "acceptance_contract_version", identifier=True)
        _tuple(self.phases, "phases", nonempty=True)
        if any(type(phase) is not ExecutionPhaseSpec for phase in self.phases):
            raise ValueError("phases must contain exact ExecutionPhaseSpec values")
        for phase in self.phases:
            phase.__post_init__()
        if tuple(p.phase_ordinal for p in self.phases) != tuple(range(len(self.phases))) or tuple(p.phase for p in self.phases) != tuple(ExecutionPhase):
            raise ValueError("phases must use canonical phase order")
        all_steps = [step for phase in self.phases for step in phase.steps]
        if len({step.plan_step_ordinal for step in all_steps}) != len(all_steps):
            raise ValueError("plan step ordinals must be globally unique")
        if self.execution_id != "execution." + self.plan_digest.removeprefix("sha256:"):
            raise ValueError("execution_id must be derived from plan_digest")
        _validate_operation_bindings(self)
        if self.header_digest != _hash(_DOMAIN_HEADER, _header_values(self)):
            raise ValueError("header_digest does not match header")


@dataclass(frozen=True)
class RuntimeAttestation:
    approved_runtime_digest: str
    active_runtime_digest: str
    approved_config_digest: str
    active_config_digest: str
    process_start_id: str

    def __post_init__(self) -> None:
        for name in ("approved_runtime_digest", "active_runtime_digest", "approved_config_digest", "active_config_digest"):
            _digest(getattr(self, name), name)
        _string(self.process_start_id, "process_start_id", identifier=True)


@dataclass(frozen=True)
class BehaviorAcceptance:
    contract_version: str
    acceptance_contract_digest: str
    passed: bool
    safe_code: str
    results_digest: str

    def __post_init__(self) -> None:
        _string(self.contract_version, "contract_version", identifier=True)
        _digest(self.acceptance_contract_digest, "acceptance_contract_digest")
        _strict_bool(self.passed, "passed")
        _code(self.safe_code, "safe_code")
        _digest(self.results_digest, "results_digest")
        if self.passed and self.safe_code != _SUCCESS:
            raise ValueError("passed acceptance requires ACCEPTANCE_PASSED")
        if not self.passed and self.safe_code == _SUCCESS:
            raise ValueError("failed acceptance cannot use ACCEPTANCE_PASSED")


@dataclass(frozen=True)
class ProvisioningStepEvidence:
    disposition: StepDisposition
    safe_code: str
    result_digest: str
    redactions_applied: bool
    evidence: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.disposition) is not StepDisposition:
            raise ValueError("disposition must be a StepDisposition")
        _code(self.safe_code, "safe_code")
        _digest(self.result_digest, "result_digest")
        if not _strict_bool(self.redactions_applied, "redactions_applied"):
            raise ValueError("persisted evidence must have redactions_applied=True")
        if not isinstance(self.evidence, Mapping):
            raise ValueError("persisted adapter evidence must be a mapping")
        clean: dict[str, object] = {}
        for key, value in self.evidence.items():
            if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
                raise ValueError("persisted adapter evidence key is invalid")
            if any(term in key.lower() for term in ("stdout", "stderr", "secret", "token", "password", "private", "path", "content", "raw")):
                raise ValueError("persisted adapter evidence key is unsafe")
            if isinstance(value, bool) or (type(value) is int and 0 <= value <= 1_000_000_000) or (isinstance(value, str) and (re.fullmatch(r"sha256:[0-9a-f]{64}", value) or (re.fullmatch(r"(?:0|[1-9][0-9]*)", value) and int(value) <= (1 << 64) - 1))):
                clean[key] = value
            else:
                raise ValueError("persisted adapter evidence value is invalid")
        object.__setattr__(self, "evidence", clean)


@dataclass(frozen=True)
class ProvisioningCheckpoint:
    schema_version: Literal["2", "3"]
    checkpoint_id: str
    execution_id: str
    checkpoint_ordinal: int
    previous_digest: str
    phase: ExecutionPhase
    phase_ordinal: int
    plan_step_ordinal: int
    step_digest: str
    event: CheckpointEvent
    observed_at: str
    step_evidence: ProvisioningStepEvidence | None
    runtime_attestation: RuntimeAttestation | None
    behavior_acceptance: BehaviorAcceptance | None
    checkpoint_digest: str

    def __post_init__(self) -> None:
        if self.schema_version not in {"2", "3"}:
            raise ValueError("schema_version must be '2' or '3'")
        _string(self.checkpoint_id, "checkpoint_id", identifier=True)
        _string(self.execution_id, "execution_id", identifier=True)
        _ordinal(self.checkpoint_ordinal, "checkpoint_ordinal")
        _digest(self.previous_digest, "previous_digest")
        if type(self.phase) is not ExecutionPhase or type(self.event) is not CheckpointEvent:
            raise ValueError("checkpoint enum has the wrong exact type")
        _ordinal(self.phase_ordinal, "phase_ordinal")
        _ordinal(self.plan_step_ordinal, "plan_step_ordinal")
        _digest(self.step_digest, "step_digest")
        _timestamp(self.observed_at, "observed_at")
        for name, value, cls in (("step_evidence", self.step_evidence, ProvisioningStepEvidence), ("runtime_attestation", self.runtime_attestation, RuntimeAttestation), ("behavior_acceptance", self.behavior_acceptance, BehaviorAcceptance)):
            if value is not None:
                _exact(value, cls, name)
                value.__post_init__()
        _digest(self.checkpoint_digest, "checkpoint_digest")
        if self.checkpoint_digest != _hash(_checkpoint_domain(self.schema_version), _checkpoint_values(self)):
            raise ValueError("checkpoint_digest does not match checkpoint")


@dataclass(frozen=True)
class ProvisioningExecutionView:
    execution_id: str
    plan_id: str
    current_phase: ExecutionPhase | None
    status: str
    failure_code: str | None
    rollback_status: str
    runtime_attestation: RuntimeAttestation | None
    behavior_acceptance: BehaviorAcceptance | None
    tail_evidence: ProvisioningStepEvidence | None
    evidence_digest: str | None
    terminal_success: bool


def _validate_args(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str or not key:
                raise ValueError("step argument keys must be non-empty strings")
            _validate_args(child)
    elif type(value) in (list, tuple):
        for child in value:
            _validate_args(child)
    elif value is not None and type(value) not in (str, int, bool, float):
        raise ValueError("step arguments contain an unsupported value")
    elif type(value) is float and not math.isfinite(value):
        raise ValueError("step arguments contain a non-finite float")


def _canonical_value(value: Any) -> Any:
    _validate_args(value)
    if isinstance(value, Mapping):
        return {key: _canonical_value(child) for key, child in value.items()}
    if type(value) in (list, tuple):
        return [_canonical_value(child) for child in value]
    return value


def canonical_arguments_digest(arguments: Any) -> str:
    return _hash(_DOMAIN_ARGS, _canonical_value(arguments))


def _step_digest_from_identity(plan_digest: str, direction: str, ordinal: int, operation: str, arguments_digest: str) -> str:
    return _hash(_DOMAIN_STEP, {"plan_digest": plan_digest, "direction": direction, "plan_step_ordinal": ordinal, "operation": operation, "arguments_digest": arguments_digest})


def _validate_operation_bindings(header: ProvisioningExecutionHeader) -> None:
    for phase in header.phases:
        for step in phase.steps:
            for direction, identity in (("forward", step.forward), ("rollback", step.rollback)):
                if identity is not None and identity.step_digest != _step_digest_from_identity(header.plan_digest, direction, step.plan_step_ordinal, identity.operation, identity.arguments_digest):
                    raise ValueError(f"{direction} operation identity has a mismatching digest")


def canonical_step_digest(plan_digest: str, direction: str, plan_step_ordinal: int, operation: str, arguments: Any) -> str:
    _digest(plan_digest, "plan_digest")
    if direction not in {"forward", "rollback"}:
        raise ValueError("direction must be forward or rollback")
    _ordinal(plan_step_ordinal, "plan_step_ordinal")
    _string(operation, "operation", identifier=True)
    args_digest = canonical_arguments_digest(arguments)
    return _step_digest_from_identity(plan_digest, direction, plan_step_ordinal, operation, args_digest)


def _header_values(header: ProvisioningExecutionHeader) -> dict[str, Any]:
    return {field.name: _json_value(getattr(header, field.name)) for field in fields(header) if field.name != "header_digest"}


def _checkpoint_values(checkpoint: ProvisioningCheckpoint) -> dict[str, Any]:
    values = {field.name: _json_value(getattr(checkpoint, field.name)) for field in fields(checkpoint) if field.name != "checkpoint_digest"}
    if checkpoint.schema_version == "2":
        # Historical v2 omitted the evidence member from empty step evidence.
        # Preserve that exact serialized hash contract forever.
        evidence = values.get("step_evidence")
        if isinstance(evidence, dict) and evidence.get("evidence") == {}:
            evidence.pop("evidence", None)
    return values


def _checkpoint_domain(schema_version: str) -> str:
    if schema_version == "2":
        return _DOMAIN_CHECKPOINT
    if schema_version == "3":
        return _DOMAIN_CHECKPOINT_V3
    raise ValueError("unsupported checkpoint schema version")


def execution_header_digest(header: ProvisioningExecutionHeader) -> str:
    _exact(header, ProvisioningExecutionHeader, "header")
    _validate_header_fields(header)
    return _hash(_DOMAIN_HEADER, _header_values(header))


def provisioning_checkpoint_digest(checkpoint: ProvisioningCheckpoint) -> str:
    _exact(checkpoint, ProvisioningCheckpoint, "checkpoint")
    _validate_checkpoint_fields(checkpoint)
    return _hash(_checkpoint_domain(checkpoint.schema_version), _checkpoint_values(checkpoint))


def _validate_header_fields(header: ProvisioningExecutionHeader) -> None:
    # Re-run nested validation so object.__setattr__ mutation cannot cross a boundary.
    ProvisioningExecutionHeader.__post_init__(header)
    _validate_operation_bindings(header)


def _validate_checkpoint_fields(checkpoint: ProvisioningCheckpoint) -> None:
    ProvisioningCheckpoint.__post_init__(checkpoint)


def build_execution_header(*, schema_version: Literal["2"] = "2", execution_id: str, plan_id: str, plan_digest: str, bundle_id: str, bundle_digest: str, approval_ref: str, approval_scope_digest: str, approved_by: str, approved_at: str, acceptance_contract_version: str, acceptance_contract_digest: str, created_at: str, phases: tuple[ExecutionPhaseSpec, ...], approved_runtime_digest: str, approved_config_digest: str) -> ProvisioningExecutionHeader:
    approved_at = _canonical_timestamp(approved_at, "approved_at")
    created_at = _canonical_timestamp(created_at, "created_at")
    _digest(approved_runtime_digest, "approved_runtime_digest")
    _digest(approved_config_digest, "approved_config_digest")
    values = (schema_version, execution_id, plan_id, plan_digest, bundle_id, bundle_digest, approval_ref, approval_scope_digest, approved_by, approved_at, acceptance_contract_version, acceptance_contract_digest, approved_runtime_digest, approved_config_digest, created_at, phases)
    digest = _hash(_DOMAIN_HEADER, {field.name: _json_value(value) for field, value in zip(fields(ProvisioningExecutionHeader)[:-1], values)})
    return ProvisioningExecutionHeader(*values, digest)


def build_checkpoint(*, schema_version: Literal["2", "3"] = "3", checkpoint_id: str, execution_id: str, checkpoint_ordinal: int, previous_digest: str, phase: ExecutionPhase, phase_ordinal: int, plan_step_ordinal: int, step_digest: str, event: CheckpointEvent, observed_at: str, step_evidence: ProvisioningStepEvidence | None = None, runtime_attestation: RuntimeAttestation | None = None, behavior_acceptance: BehaviorAcceptance | None = None) -> ProvisioningCheckpoint:
    observed_at = _canonical_timestamp(observed_at, "observed_at")
    values = (schema_version, checkpoint_id, execution_id, checkpoint_ordinal, previous_digest, phase, phase_ordinal, plan_step_ordinal, step_digest, event, observed_at, step_evidence, runtime_attestation, behavior_acceptance)
    hash_values = {field.name: _json_value(value) for field, value in zip(fields(ProvisioningCheckpoint)[:-1], values)}
    if schema_version == "2" and isinstance(hash_values.get("step_evidence"), dict) and hash_values["step_evidence"].get("evidence") == {}:
        hash_values["step_evidence"].pop("evidence", None)
    digest = _hash(_checkpoint_domain(schema_version), hash_values)
    return ProvisioningCheckpoint(*values, digest)


def canonical_json(value: Any) -> str:
    return _canonical(_json_value(value))


def header_payload(header: ProvisioningExecutionHeader) -> str:
    _validate_header_fields(header)
    return canonical_json(header)


def checkpoint_payload(checkpoint: ProvisioningCheckpoint) -> str:
    _validate_checkpoint_fields(checkpoint)
    values = _checkpoint_values(checkpoint)
    values["checkpoint_digest"] = checkpoint.checkpoint_digest
    return _canonical(values)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value}")


def _decode_dataclass(cls: type[Any], value: dict[str, Any]) -> Any:
    if type(value) is not dict:
        raise ValueError("payload has missing or extra fields")
    expected_fields = {field.name for field in fields(cls)}
    if set(value) != expected_fields:
        raise ValueError("payload has missing or extra fields")
    try:
        if cls is ExecutionOperationIdentity:
            return ExecutionOperationIdentity(value["operation"], value["arguments_digest"], value["step_digest"])
        if cls is ExecutionStepIdentity:
            rollback = value["rollback"]
            return ExecutionStepIdentity(value["plan_step_ordinal"], _decode_dataclass(ExecutionOperationIdentity, value["forward"]), None if rollback is None else _decode_dataclass(ExecutionOperationIdentity, rollback))
        if cls is ExecutionPhaseSpec:
            return ExecutionPhaseSpec(value["phase_ordinal"], ExecutionPhase(value["phase"]), tuple(_decode_dataclass(ExecutionStepIdentity, item) for item in value["steps"]))
        if cls is ProvisioningExecutionHeader:
            return ProvisioningExecutionHeader(value["schema_version"], value["execution_id"], value["plan_id"], value["plan_digest"], value["bundle_id"], value["bundle_digest"], value["approval_ref"], value["approval_scope_digest"], value["approved_by"], value["approved_at"], value["acceptance_contract_version"], value["acceptance_contract_digest"], value["approved_runtime_digest"], value["approved_config_digest"], value["created_at"], tuple(_decode_dataclass(ExecutionPhaseSpec, item) for item in value["phases"]), value["header_digest"])
        if cls is RuntimeAttestation:
            return RuntimeAttestation(**value)
        if cls is BehaviorAcceptance:
            return BehaviorAcceptance(**value)
        if cls is ProvisioningStepEvidence:
            return ProvisioningStepEvidence(StepDisposition(value["disposition"]), value["safe_code"], value["result_digest"], value["redactions_applied"], value.get("evidence", {}))
        if cls is ProvisioningCheckpoint:
            step_evidence = value["step_evidence"]
            if step_evidence is not None and value["schema_version"] == "2" and set(step_evidence) == {"disposition", "safe_code", "result_digest", "redactions_applied"}:
                step_evidence = {**step_evidence, "evidence": {}}
            return ProvisioningCheckpoint(value["schema_version"], value["checkpoint_id"], value["execution_id"], value["checkpoint_ordinal"], value["previous_digest"], ExecutionPhase(value["phase"]), value["phase_ordinal"], value["plan_step_ordinal"], value["step_digest"], CheckpointEvent(value["event"]), value["observed_at"], None if step_evidence is None else _decode_dataclass(ProvisioningStepEvidence, step_evidence), None if value["runtime_attestation"] is None else _decode_dataclass(RuntimeAttestation, value["runtime_attestation"]), None if value["behavior_acceptance"] is None else _decode_dataclass(BehaviorAcceptance, value["behavior_acceptance"]), value["checkpoint_digest"])
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        raise ValueError("payload contains an invalid typed value") from error
    raise ValueError("unsupported execution payload type")


def _decode(cls: type[Any], payload: str) -> Any:
    if type(payload) is not str:
        raise ValueError("payload must be a string")
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError, TypeError) as error:
        raise ValueError("payload must be canonical JSON") from error
    if type(value) is not dict or _canonical(value) != payload:
        raise ValueError("payload must be canonical JSON")
    return _decode_dataclass(cls, value)


def header_from_payload(payload: str) -> ProvisioningExecutionHeader:
    return _decode(ProvisioningExecutionHeader, payload)


def checkpoint_from_payload(payload: str) -> ProvisioningCheckpoint:
    return _decode(ProvisioningCheckpoint, payload)


def _bound_step(header: ProvisioningExecutionHeader, checkpoint: ProvisioningCheckpoint) -> tuple[ExecutionStepIdentity, bool]:
    for phase in header.phases:
        if phase.phase is checkpoint.phase and phase.phase_ordinal == checkpoint.phase_ordinal:
            for step in phase.steps:
                if step.plan_step_ordinal == checkpoint.plan_step_ordinal:
                    if checkpoint.step_digest == step.forward.step_digest:
                        return step, False
                    if step.rollback is not None and checkpoint.step_digest == step.rollback.step_digest:
                        return step, True
    raise ValueError("checkpoint is not a member of the execution manifest")


def verify_backup_execution_chain(header: ProvisioningExecutionHeader, checkpoints: tuple[ProvisioningCheckpoint, ...]) -> str | None:
    _exact(header, ProvisioningExecutionHeader, "header")
    _validate_header_fields(header)
    if type(checkpoints) is not tuple or any(type(c) is not ProvisioningCheckpoint for c in checkpoints):
        raise ValueError("checkpoints must be an immutable tuple of exact DTOs")
    previous = header.header_digest
    ordered = [(phase.phase, phase.phase_ordinal, step) for phase in header.phases for step in phase.steps]
    next_forward = 0
    started: tuple[ExecutionStepIdentity, ExecutionPhase, bool] | None = None
    completed: list[tuple[ExecutionStepIdentity, ExecutionPhase, StepDisposition]] = []
    failure_seen = False
    rollback_started: tuple[ExecutionStepIdentity, ExecutionPhase] | None = None
    rollback_remaining: list[tuple[ExecutionStepIdentity, ExecutionPhase]] = []
    attestation: RuntimeAttestation | None = None
    acceptance: BehaviorAcceptance | None = None
    finalized = False
    last_observed = header.created_at
    for ordinal, checkpoint in enumerate(checkpoints):
        _validate_checkpoint_fields(checkpoint)
        if checkpoint.checkpoint_ordinal != ordinal or checkpoint.execution_id != header.execution_id or checkpoint.previous_digest != previous:
            raise ValueError("checkpoint ordinal, execution binding, or digest chain is invalid")
        if checkpoint.observed_at < last_observed:
            raise ValueError("checkpoint timestamps must be nondecreasing")
        last_observed = checkpoint.observed_at
        step, is_rollback = _bound_step(header, checkpoint)
        if checkpoint.phase_ordinal != list(ExecutionPhase).index(checkpoint.phase) or finalized:
            raise ValueError("checkpoint phase or finalization state is invalid")
        event = checkpoint.event
        evidence, runtime, behavior = checkpoint.step_evidence, checkpoint.runtime_attestation, checkpoint.behavior_acceptance
        if is_rollback:
            if event not in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED):
                raise ValueError("rollback identity used by a non-rollback event")
        elif event in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED):
            raise ValueError("rollback event lacks approved rollback identity")
        if event is CheckpointEvent.STEP_STARTED:
            if any(x is not None for x in (evidence, runtime, behavior)) or started or failure_seen or is_rollback or next_forward >= len(ordered) or step is not ordered[next_forward][2] or checkpoint.phase is not ordered[next_forward][0]:
                raise ValueError("STEP_STARTED has invalid state")
            started = (step, checkpoint.phase, False)
        elif event in (CheckpointEvent.STEP_COMPLETED, CheckpointEvent.STEP_FAILED):
            if is_rollback or started is None or started[0] is not step or started[1] is not checkpoint.phase or evidence is None:
                raise ValueError("step outcome does not match its start")
            if event is CheckpointEvent.STEP_COMPLETED:
                if evidence.disposition not in (StepDisposition.CHANGED, StepDisposition.VERIFIED_NOOP) or (runtime is not None and checkpoint.phase is not ExecutionPhase.ATTEST) or (behavior is not None and checkpoint.phase is not ExecutionPhase.ACCEPT):
                    raise ValueError("successful step has invalid evidence")
                if checkpoint.phase is ExecutionPhase.ATTEST:
                    if runtime is None or runtime.approved_runtime_digest != header.approved_runtime_digest or runtime.approved_config_digest != header.approved_config_digest or runtime.active_runtime_digest != runtime.approved_runtime_digest or runtime.active_config_digest != runtime.approved_config_digest:
                        raise ValueError("ATTEST completion lacks bound active identities")
                    attestation = runtime
                if checkpoint.phase is ExecutionPhase.ACCEPT:
                    if behavior is None or behavior.acceptance_contract_digest != header.acceptance_contract_digest or behavior.contract_version != header.acceptance_contract_version or not behavior.passed or behavior.safe_code != _SUCCESS:
                        raise ValueError("ACCEPT completion lacks bound passing contract acceptance")
                    acceptance = behavior
                completed.append((step, checkpoint.phase, evidence.disposition)); next_forward += 1
            else:
                if evidence.disposition is not StepDisposition.FAILED or (runtime is not None and checkpoint.phase is not ExecutionPhase.ATTEST) or (behavior is not None and checkpoint.phase is not ExecutionPhase.ACCEPT):
                    raise ValueError("failed step has invalid typed evidence")
                if runtime is not None and (runtime.approved_runtime_digest != header.approved_runtime_digest or runtime.approved_config_digest != header.approved_config_digest):
                    raise ValueError("failed ATTEST detail is not bound to approved identities")
                if behavior is not None and (behavior.acceptance_contract_digest != header.acceptance_contract_digest or behavior.contract_version != header.acceptance_contract_version or behavior.passed):
                    raise ValueError("failed ACCEPT detail is not bound to the acceptance contract")
                failure_seen = True
                rollback_remaining = [(s, p) for s, p, disposition in reversed(completed) if disposition is StepDisposition.CHANGED and s.rollback is not None]
            started = None
        elif event in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED):
            if not failure_seen or not rollback_remaining or rollback_remaining[0] != (step, checkpoint.phase):
                raise ValueError("rollback is not reverse order over approved completed steps")
            if event is CheckpointEvent.ROLLBACK_STARTED:
                if rollback_started or any(x is not None for x in (evidence, runtime, behavior)):
                    raise ValueError("rollback start has invalid state")
                rollback_started = (step, checkpoint.phase)
            else:
                if rollback_started != (step, checkpoint.phase) or evidence is None or runtime is not None or behavior is not None:
                    raise ValueError("rollback outcome does not match its start")
                if event is CheckpointEvent.ROLLBACK_COMPLETED and evidence.disposition not in (StepDisposition.CHANGED, StepDisposition.VERIFIED_NOOP):
                    raise ValueError("rollback completion has invalid disposition")
                if event is CheckpointEvent.ROLLBACK_FAILED and evidence.disposition is not StepDisposition.FAILED:
                    raise ValueError("rollback failure has invalid disposition")
                if event is CheckpointEvent.ROLLBACK_FAILED:
                    failure_seen = True
                rollback_started = None; rollback_remaining.pop(0)
        elif event is CheckpointEvent.EXECUTION_ABORTED:
            expected_abort_digest = _result_digest(step.forward.operation, False, "FORWARD_AUTHORITY_LOST")
            if is_rollback or any(x is not None for x in (runtime, behavior)) or started or failure_seen or rollback_started or evidence is None or evidence.disposition is not StepDisposition.FAILED or evidence.safe_code != "FORWARD_AUTHORITY_LOST" or evidence.result_digest != expected_abort_digest or next_forward >= len(ordered) or step is not ordered[next_forward][2] or checkpoint.phase is not ordered[next_forward][0]:
                raise ValueError("execution abort has invalid state")
            failure_seen = True
            rollback_remaining = [(s, p) for s, p, disposition in reversed(completed) if disposition is StepDisposition.CHANGED and s.rollback is not None]
        elif event is CheckpointEvent.EXECUTION_FINALIZED:
            if any(x is not None for x in (evidence, runtime, behavior)) or checkpoint.phase is not ExecutionPhase.FINALIZE or step is not header.phases[-1].steps[-1] or started or failure_seen or rollback_remaining or next_forward != len(ordered) or attestation is None or acceptance is None or not acceptance.passed:
                raise ValueError("execution finalization is not justified")
            finalized = True
        else:
            raise ValueError("unsupported checkpoint event")
        previous = checkpoint.checkpoint_digest
    return previous if checkpoints else None


def derive_backup_execution_view(header: ProvisioningExecutionHeader, checkpoints: tuple[ProvisioningCheckpoint, ...]) -> ProvisioningExecutionView:
    tail = verify_backup_execution_chain(header, checkpoints)
    attestation = next((c.runtime_attestation for c in reversed(checkpoints) if c.runtime_attestation), None)
    acceptance = next((c.behavior_acceptance for c in reversed(checkpoints) if c.behavior_acceptance), None)
    tail_evidence = next((c.step_evidence for c in reversed(checkpoints) if c.step_evidence), None)
    failure = next((c.step_evidence.safe_code for c in reversed(checkpoints) if c.event in (CheckpointEvent.STEP_FAILED, CheckpointEvent.ROLLBACK_FAILED, CheckpointEvent.EXECUTION_ABORTED) and c.step_evidence), None)
    rollback_events = [c.event for c in checkpoints if c.event in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED)]
    required_rollbacks = len({
        _bound_step(header, checkpoint)[0].plan_step_ordinal
        for checkpoint in checkpoints
        if checkpoint.event is CheckpointEvent.STEP_COMPLETED
        and checkpoint.step_evidence is not None
        and checkpoint.step_evidence.disposition is StepDisposition.CHANGED
        and _bound_step(header, checkpoint)[0].rollback is not None
    })
    completed_rollbacks = sum(1 for event in rollback_events if event is CheckpointEvent.ROLLBACK_COMPLETED)
    rollback = "failed" if CheckpointEvent.ROLLBACK_FAILED in rollback_events else "completed" if required_rollbacks and completed_rollbacks == required_rollbacks else "in_progress" if rollback_events else "not_started"
    finalized = bool(checkpoints and checkpoints[-1].event is CheckpointEvent.EXECUTION_FINALIZED)
    terminal = finalized and acceptance is not None and acceptance.passed and failure is None
    status = "succeeded" if terminal else "failed" if failure or (acceptance is not None and not acceptance.passed) else "finalized" if finalized else "in_progress" if checkpoints else "not_started"
    return ProvisioningExecutionView(header.execution_id, header.plan_id, checkpoints[-1].phase if checkpoints else None, status, failure or (acceptance.safe_code if acceptance and not acceptance.passed else None), rollback, attestation, acceptance, tail_evidence, tail, terminal)


_ROLLBACK_FOR = {
    "start_enable_system_service": "stop_disable_system_service",
    "install_systemd_unit": "remove_systemd_unit",
    "stop_disable_system_service": None,
    "stop_disable_user_service": "restore_enable_user_service",
    "install_private_config": "remove_private_config",
    "ensure_read_only_acl": "remove_read_only_acl",
    "generate_cursor_key": "remove_cursor_key_if_unreferenced",
    "install_overseer_api_token": "remove_overseer_api_token",
    "generate_secret_file": "remove_secret_file_if_no_backups",
    "ensure_system_user": "remove_system_user_if_unused",
    "ensure_directory": "remove_directory_if_empty",
    "install_runtime": "remove_runtime_if_unreferenced",
}

_ROLLBACK_CLAIM_LEASE = timedelta(seconds=30)


def _rollback_owner_scope_keys(store: SQLiteStore, execution_id: str) -> tuple[str, ...]:
    canonical_path = str(Path(store.path).resolve())
    device, inode = store._database_identity
    return tuple(sorted({
        f"path:{canonical_path}:{execution_id}",
        f"inode:{device}:{inode}:{execution_id}",
    }))


def _rollback_owner_socket_addresses(store: SQLiteStore, execution_id: str) -> tuple[bytes, ...]:
    return tuple(
        b"\0overseer.rollback-owner." + hashlib.sha256(scope_key.encode()).hexdigest().encode()
        for scope_key in _rollback_owner_scope_keys(store, execution_id)
    )


class _RollbackOwnerLock:
    """Hold an OS lock for the duration of one rollback adapter call.

    The durable claim remains recoverable after process death because the OS
    releases this lock, while a live owner cannot be taken over merely because
    its initial lease elapsed.
    """

    def __init__(self, socket_handles: list[socket.socket]) -> None:
        self._sockets = socket_handles

    @classmethod
    def acquire(cls, store: SQLiteStore, execution_id: str) -> _RollbackOwnerLock:
        socket_handles: list[socket.socket] = []
        try:
            for address in _rollback_owner_socket_addresses(store, execution_id):
                socket_handle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    socket_handle.bind(address)
                except OSError as error:
                    socket_handle.close()
                    if error.errno == errno.EADDRINUSE:
                        raise _RollbackOwnerSocketCollision(str(error), errno.EADDRINUSE) from error
                    raise
                socket_handles.append(socket_handle)
        except BaseException:
            for socket_handle in socket_handles:
                socket_handle.close()
            raise
        return cls(socket_handles)

    def release(self) -> None:
        sockets, self._sockets = self._sockets, []
        for socket_handle in sockets:
            socket_handle.close()

    def __enter__(self) -> _RollbackOwnerLock:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()


def _rollback_claim_clock() -> str:
    """Return trusted wall-clock time for rollback lease state only."""
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _execution_time(value: object | None) -> str:
    if value is None:
        return datetime.now(UTC).isoformat(timespec="microseconds")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("execution time must be UTC")
        value = value.astimezone(UTC).isoformat()
    return _canonical_timestamp(value, "execution time")


def _result_digest(operation: str, result: object, safe_code: str) -> str:
    if isinstance(result, Mapping) and result.get("ok") is True:
        return canonical_arguments_digest({
            "operation": result.get("operation"),
            "disposition": result.get("disposition"),
            "safe_code": result.get("safe_code"),
            "evidence": result.get("evidence"),
            "redactions_applied": result.get("redactions_applied"),
        })
    return canonical_arguments_digest({"operation": operation, "outcome": safe_code})

_ADAPTER_RESULT_CONTRACT = {
    "verify_published_adapter_source": ({"verified_noop"}, {"SOURCE_ALREADY_PUBLISHED"}, {"source_commit_verified"}),
    "install_runtime": ({"changed", "verified_noop"}, {"RUNTIME_INSTALLED", "RUNTIME_ALREADY_CURRENT"}, {"runtime_digest", "metadata_verified", "dev", "ino", "uid", "gid", "mode"}),
    "verify_endpoint_migration_ready": ({"verified_noop"}, {"ENDPOINT_READY"}, set()),
    "ensure_system_user": ({"changed", "verified_noop"}, {"SYSTEM_USER_CREATED", "SYSTEM_USER_ALREADY_CURRENT"}, {"metadata_verified"}),
    "ensure_directory": ({"changed", "verified_noop"}, {"DIRECTORY_CREATED", "DIRECTORY_ALREADY_CURRENT"}, {"metadata_verified", "dev", "ino", "uid", "gid", "mode"}),
    "generate_secret_file": ({"changed", "verified_noop"}, {"SECRET_CREATED", "SECRET_ALREADY_PRESENT"}, {"size_bytes", "metadata_verified", "identity_digest"}),
    "generate_cursor_key": ({"changed", "verified_noop"}, {"SECRET_CREATED", "SECRET_ALREADY_PRESENT"}, {"size_bytes", "metadata_verified", "identity_digest"}),
    "install_overseer_api_token": ({"changed", "verified_noop"}, {"TOKEN_INSTALLED", "TOKEN_ALREADY_PRESENT"}, {"identity_digest", "metadata_verified"}),
    "ensure_read_only_acl": ({"changed", "verified_noop"}, {"ACL_APPLIED"}, {"acl_verified", "acl_present_before"}),
    "install_private_config": ({"changed", "verified_noop"}, {"CONFIG_INSTALLED", "CONFIG_ALREADY_CURRENT"}, {"config_digest", "metadata_verified"}),
    "register_authorized_roots": ({"changed", "verified_noop"}, {"ROOTS_REGISTERED", "ROOTS_ALREADY_REGISTERED"}, {"roots_added", "roots_verified"}),
    "start_enable_system_service": ({"changed"}, {"SYSTEM_SERVICE_RESTARTED"}, {"active_enter_timestamp_monotonic"}),
    "stop_disable_user_service": ({"changed", "verified_noop"}, {"USER_SERVICE_DISABLED"}, {"previously_enabled", "previously_active", "service_verified"}),
    "stop_disable_system_service": ({"changed", "verified_noop"}, {"SYSTEM_SERVICE_DISABLED"}, {"service_verified"}),
    "restore_enable_user_service": ({"changed", "verified_noop"}, {"USER_SERVICE_ENABLED", "USER_SERVICE_NOT_RESTORED"}, {"service_verified"}),
    "install_systemd_unit": ({"changed", "verified_noop"}, {"SYSTEMD_UNIT_INSTALLED", "SYSTEMD_UNIT_ALREADY_CURRENT"}, {"unit_digest", "identity_digest", "metadata_verified"}),
    "verify_mcp_service": ({"verified_noop"}, {"MCP_SCHEMA_VERIFIED"}, set()),
    "verify_codex_url": ({"verified_noop"}, {"CODEX_MCP_URL_VERIFIED"}, set()),
    "verify_gpg_identity": ({"verified_noop"}, {"GPG_IDENTITY_VERIFIED"}, {"identity_digest"}),
    "verify_backup_policy": ({"verified_noop"}, {"BACKUP_POLICY_VERIFIED"}, set()),
    "remove_private_config": ({"changed", "verified_noop"}, {"CONFIG_REMOVED", "CONFIG_ALREADY_ABSENT"}, {"metadata_verified"}),
    "remove_overseer_api_token": ({"changed", "verified_noop"}, {"TOKEN_REMOVED", "TOKEN_ALREADY_ABSENT"}, {"metadata_verified"}),
    "remove_cursor_key_if_unreferenced": ({"changed", "verified_noop"}, {"CURSOR_KEY_REMOVED", "CURSOR_KEY_ALREADY_ABSENT"}, {"metadata_verified"}),
    "remove_secret_file_if_no_backups": ({"changed", "verified_noop"}, {"SECRET_REMOVED", "SECRET_ALREADY_ABSENT", "SECRET_RETAINED_WITH_BACKUPS"}, {"metadata_verified"}),
    "remove_systemd_unit": ({"changed", "verified_noop"}, {"SYSTEMD_UNIT_REMOVED", "SYSTEMD_UNIT_ALREADY_ABSENT"}, {"metadata_verified"}),
    "remove_read_only_acl": ({"changed", "verified_noop"}, {"ACL_REMOVED"}, {"acl_verified"}),
    "remove_directory_if_empty": ({"changed", "verified_noop"}, {"DIRECTORY_REMOVED", "DIRECTORY_ALREADY_ABSENT"}, set()),
    "remove_system_user_if_unused": ({"changed", "verified_noop"}, {"SYSTEM_USER_REMOVED", "SYSTEM_USER_ALREADY_ABSENT", "SYSTEM_USER_RETAINED_WITH_STATE"}, set()),
    "remove_runtime_if_unreferenced": ({"changed", "verified_noop"}, {"RUNTIME_REMOVED", "RUNTIME_ALREADY_ABSENT"}, {"runtime_digest", "metadata_verified"}),
}

_ADAPTER_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

# Disposition and safe code are one contract, not two independent allowlists.
_ADAPTER_RESULT_PAIRS = {
    "verify_published_adapter_source": {"verified_noop": {"SOURCE_ALREADY_PUBLISHED"}},
    "install_runtime": {"changed": {"RUNTIME_INSTALLED"}, "verified_noop": {"RUNTIME_ALREADY_CURRENT"}},
    "verify_endpoint_migration_ready": {"verified_noop": {"ENDPOINT_READY"}},
    "ensure_system_user": {"changed": {"SYSTEM_USER_CREATED"}, "verified_noop": {"SYSTEM_USER_ALREADY_CURRENT"}},
    "ensure_directory": {"changed": {"DIRECTORY_CREATED"}, "verified_noop": {"DIRECTORY_ALREADY_CURRENT"}},
    "generate_secret_file": {"changed": {"SECRET_CREATED"}, "verified_noop": {"SECRET_ALREADY_PRESENT"}},
    "generate_cursor_key": {"changed": {"SECRET_CREATED"}, "verified_noop": {"SECRET_ALREADY_PRESENT"}},
    "install_overseer_api_token": {"changed": {"TOKEN_INSTALLED"}, "verified_noop": {"TOKEN_ALREADY_PRESENT"}},
    "ensure_read_only_acl": {"changed": {"ACL_APPLIED"}, "verified_noop": {"ACL_APPLIED"}},
    "install_private_config": {"changed": {"CONFIG_INSTALLED"}, "verified_noop": {"CONFIG_ALREADY_CURRENT"}},
    "register_authorized_roots": {"changed": {"ROOTS_REGISTERED"}, "verified_noop": {"ROOTS_ALREADY_REGISTERED"}},
    "start_enable_system_service": {"changed": {"SYSTEM_SERVICE_RESTARTED"}},
    "stop_disable_user_service": {"changed": {"USER_SERVICE_DISABLED"}, "verified_noop": {"USER_SERVICE_DISABLED"}},
    "stop_disable_system_service": {"changed": {"SYSTEM_SERVICE_DISABLED"}, "verified_noop": {"SYSTEM_SERVICE_DISABLED"}},
    "restore_enable_user_service": {"changed": {"USER_SERVICE_ENABLED"}, "verified_noop": {"USER_SERVICE_NOT_RESTORED"}},
    "install_systemd_unit": {"changed": {"SYSTEMD_UNIT_INSTALLED"}, "verified_noop": {"SYSTEMD_UNIT_ALREADY_CURRENT"}},
    "verify_mcp_service": {"verified_noop": {"MCP_SCHEMA_VERIFIED"}},
    "verify_codex_url": {"verified_noop": {"CODEX_MCP_URL_VERIFIED"}},
    "verify_gpg_identity": {"verified_noop": {"GPG_IDENTITY_VERIFIED"}},
    "verify_backup_policy": {"verified_noop": {"BACKUP_POLICY_VERIFIED"}},
    "remove_private_config": {"changed": {"CONFIG_REMOVED"}, "verified_noop": {"CONFIG_ALREADY_ABSENT"}},
    "remove_overseer_api_token": {"changed": {"TOKEN_REMOVED"}, "verified_noop": {"TOKEN_ALREADY_ABSENT"}},
    "remove_cursor_key_if_unreferenced": {"changed": {"CURSOR_KEY_REMOVED"}, "verified_noop": {"CURSOR_KEY_ALREADY_ABSENT"}},
    "remove_secret_file_if_no_backups": {"changed": {"SECRET_REMOVED"}, "verified_noop": {"SECRET_ALREADY_ABSENT", "SECRET_RETAINED_WITH_BACKUPS"}},
    "remove_systemd_unit": {"changed": {"SYSTEMD_UNIT_REMOVED"}, "verified_noop": {"SYSTEMD_UNIT_ALREADY_ABSENT"}},
    "remove_read_only_acl": {"changed": {"ACL_REMOVED"}, "verified_noop": {"ACL_REMOVED"}},
    "remove_directory_if_empty": {"changed": {"DIRECTORY_REMOVED"}, "verified_noop": {"DIRECTORY_ALREADY_ABSENT"}},
    "remove_system_user_if_unused": {"changed": {"SYSTEM_USER_REMOVED"}, "verified_noop": {"SYSTEM_USER_ALREADY_ABSENT", "SYSTEM_USER_RETAINED_WITH_STATE"}},
    "remove_runtime_if_unreferenced": {"changed": {"RUNTIME_REMOVED"}, "verified_noop": {"RUNTIME_ALREADY_ABSENT"}},
}


def _validate_adapter_evidence(evidence: Mapping[str, object]) -> None:
    """Apply the same bounded evidence vocabulary at the persistence boundary."""
    for key, value in evidence.items():
        if key in {"dev", "ino", "uid", "gid", "mode"}:
            if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None or int(value) > (1 << 64) - 1:
                raise ValueError("adapter evidence identity is invalid")
            if key == "mode" and int(value) > 0o7777:
                raise ValueError("adapter evidence mode is invalid")
            continue
        if key in {"config_digest", "identity_digest", "runtime_digest", "unit_digest"}:
            if not isinstance(value, str) or _ADAPTER_DIGEST.fullmatch(value) is None:
                raise ValueError("adapter evidence digest is invalid")
        elif key in {"metadata_verified", "acl_verified", "previously_enabled", "previously_active", "service_verified", "source_commit_verified", "acl_present_before"}:
            if type(value) is not bool:
                raise ValueError("adapter evidence boolean is invalid")
        elif key in {"roots_added", "roots_verified", "size_bytes"}:
            if type(value) is not int or not 0 <= value <= 1_000_000_000:
                raise ValueError("adapter evidence count is invalid")
        elif key in {"active_enter_timestamp_monotonic", "dev", "ino", "uid", "gid", "mode"}:
            if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]{0,38}", value) is None:
                raise ValueError("adapter evidence timestamp is invalid")
        else:
            raise ValueError("adapter evidence key is not allowlisted")


def _normalize_result(operation: str, result: object) -> ProvisioningStepEvidence:
    if not isinstance(result, Mapping) or set(result) != {"ok", "operation", "disposition", "safe_code", "evidence", "redactions_applied"}:
        raise ValueError("adapter result must be the exact safe DTO")
    if result["operation"] != operation or result["redactions_applied"] is not True:
        raise ValueError("adapter result is not bound to the approved operation")
    if result["ok"] is not True:
        raise ValueError("concrete host adapter must not return ok=false")
    if result["disposition"] not in {"changed", "verified_noop"}:
        raise ValueError("adapter result has an invalid disposition")
    disposition = StepDisposition(result["disposition"])
    contract = _ADAPTER_RESULT_CONTRACT.get(operation)
    if contract is None:
        raise ValueError("adapter operation contract is not allowlisted")
    pairs = _ADAPTER_RESULT_PAIRS.get(operation)
    if pairs is None or result["disposition"] not in pairs or result["safe_code"] not in pairs[result["disposition"]]:
        raise ValueError("adapter result does not match the operation contract")
    evidence = result["evidence"]
    if not isinstance(evidence, Mapping) or not set(evidence).issubset(contract[2]):
        raise ValueError("adapter evidence does not match the operation contract")
    required = {
        ("install_runtime", "changed"): {"runtime_digest", "metadata_verified", "dev", "ino", "uid", "gid", "mode"},
        ("ensure_directory", "changed"): {"metadata_verified", "dev", "ino", "uid", "gid", "mode"},
    }.get((operation, result["disposition"]), set())
    if not required.issubset(evidence):
        raise ValueError("adapter evidence is missing required identity fields")
    _validate_adapter_evidence(evidence)
    code = "STEP_COMPLETED" if disposition is StepDisposition.CHANGED else "STEP_VERIFIED_NOOP"
    return ProvisioningStepEvidence(disposition, code, _result_digest(operation, result, code), True, evidence)


def _runtime(value: object) -> RuntimeAttestation:
    if type(value) is RuntimeAttestation:
        return value
    if isinstance(value, Mapping) and set(value) == {"approved_runtime_digest", "active_runtime_digest", "approved_config_digest", "active_config_digest", "process_start_id"}:
        return RuntimeAttestation(**value)  # type: ignore[arg-type]
    raise ValueError("typed runtime attestation is required")


def _acceptance(value: object) -> BehaviorAcceptance:
    if type(value) is BehaviorAcceptance:
        return replace(value, safe_code="ACCEPTANCE_PASSED" if value.passed else "ACCEPTANCE_FAILED")
    if isinstance(value, Mapping) and set(value) == {"contract_version", "acceptance_contract_digest", "passed", "safe_code", "results_digest"}:
        value = dict(value)
        value["safe_code"] = "ACCEPTANCE_PASSED" if value["passed"] is True else "ACCEPTANCE_FAILED"
        return BehaviorAcceptance(**value)  # type: ignore[arg-type]
    raise ValueError("typed behavior acceptance is required")


def _load_authoritative_bundle(store: SQLiteStore, plan_id: str, *, terminal: bool = False):
    from . import provisioning_bundle
    from .roadex_approval_status import RoadexApprovalBinding, load_exact_bound_source, project_decision
    try:
        bundle = provisioning_bundle.load_provisioning_bundle(store, plan_id)
    except (KeyError, ValueError) as error:
        raise _AuthorityRecordError("AUTHORITATIVE_RECORD_INVALID") from error
    if type(bundle) is not provisioning_bundle.ProvisioningBundleV1 or not bundle.preflight.passed:
        raise _AuthorityMismatchError("exact passing typed provisioning bundle is required")
    try:
        provisioning_bundle._recheck_locked_authority_and_chain(store, bundle)
    except (KeyError, ValueError) as error:
        raise _AuthorityRecordError("AUTHORITATIVE_RECORD_INVALID") from error
    try:
        binding = store.load_roadex_approval_binding(provisioning_bundle.binding_draft_for_bundle(bundle).approval_ref)
    except (KeyError, ValueError) as error:
        raise _AuthorityRecordError("AUTHORITATIVE_RECORD_INVALID") from error
    if type(binding) is not RoadexApprovalBinding:
        raise _AuthorityRecordError("AUTHORITATIVE_RECORD_INVALID")
    try:
        provisioning_bundle._load_exact_preflight_report(store, bundle)
        provisioning_bundle._load_exact_outbox(store, bundle)
        provisioning_bundle.verify_exact_completed_review_outbox_set(store, bundle)
    except (KeyError, ValueError) as error:
        raise _AuthorityRecordError("AUTHORITATIVE_RECORD_INVALID") from error
    try:
        source = load_exact_bound_source(store, binding)
        projected = project_decision(store, binding, source)
    except (KeyError, ValueError) as error:
        # The approval source is the independent authorization record.  Its
        # loss is fail-closed and must not become cleanup-eligible authority
        # loss merely because the execution has a mutable prefix.
        raise _ExactApprovalSourceError("EXACT_APPROVAL_SOURCE_INVALID") from error
    expected_projection_time = source.executed_at if source.status.value == "executed" else source.approved_at
    if projected.decision != "approved" or projected.source_status != source.status.value or projected.updated_at != expected_projection_time:
        raise _AuthorityMismatchError("current authoritative approval projection is not approved")
    draft = provisioning_bundle.binding_draft_for_bundle(bundle)
    if any(getattr(binding, field) != getattr(draft, field) for field in ("approval_ref", "source_kind", "source_id", "project_id", "workspace_id", "resource_ref", "authority_class", "subject")):
        raise _AuthorityMismatchError("approval binding identity does not match the exact bundle")
    allowed = {"approved", "executed"} if terminal else {"approved"}
    if source.plan_id != plan_id or source.status.value not in allowed or not source.approved_by or not source.approved_at:
        raise _AuthorityMismatchError("authoritative approved Roadex decision is required")
    if source.plan_digest != bundle.plan.plan_digest:
        raise _AuthorityMismatchError("approved plan digest does not match typed bundle")
    if source.provisioning_contract_version != bundle.plan.provisioning_contract_version or source.runtime_artifact_identity != bundle.plan.runtime_artifact_identity or source.config_digest != bundle.plan.config_digest:
        raise _AuthorityMismatchError("approved projection does not match the exact bundle")
    return bundle, binding, source


def _manifest(plan) -> tuple[ExecutionPhaseSpec, ...]:
    from .backup_provisioning import ProvisioningStep
    expected_operations = (
        "verify_published_adapter_source", "install_runtime", "verify_endpoint_migration_ready",
        "ensure_system_user", "ensure_directory", "ensure_directory", "ensure_directory", "ensure_directory",
        "generate_secret_file", "install_overseer_api_token", "generate_cursor_key", "ensure_read_only_acl",
        "install_private_config", "register_authorized_roots", "stop_disable_user_service", "install_systemd_unit",
        "start_enable_system_service", "verify_mcp_service", "verify_codex_url", "verify_gpg_identity", "verify_backup_policy",
    )
    if tuple(step.operation for step in plan.steps) != expected_operations:
        raise ValueError("approved plan has an altered phase layout")
    if any(type(step) is not ProvisioningStep for step in plan.steps):
        raise ValueError("approved plan contains an invalid step")
    phase_for = lambda ordinal: ExecutionPhase.MATERIALIZE if ordinal <= 12 else ExecutionPhase.REGISTER if ordinal == 13 else ExecutionPhase.ACTIVATE
    grouped: dict[ExecutionPhase, list[ExecutionStepIdentity]] = {phase: [] for phase in ExecutionPhase}
    for ordinal, step in enumerate(plan.steps):
        forward = ExecutionOperationIdentity(step.operation, canonical_arguments_digest(step.arguments), canonical_step_digest(plan.plan_digest, "forward", ordinal, step.operation, step.arguments))
        rollback_operation = _ROLLBACK_FOR.get(step.operation)
        rollback_step = None
        if rollback_operation:
            def same_target(candidate: ProvisioningStep) -> bool:
                keys = ("path", "name", "unit", "principal", "scope")
                return candidate.operation == rollback_operation and all(
                    key not in step.arguments or candidate.arguments.get(key) == step.arguments.get(key) for key in keys
                )
            candidates = [candidate for candidate in plan.rollback_steps if same_target(candidate)]
            if len(candidates) != 1:
                raise ValueError(f"missing exact rollback for {step.operation} ordinal {ordinal}")
            rollback_step = candidates[0]
        reverse = None if rollback_step is None else ExecutionOperationIdentity(rollback_step.operation, canonical_arguments_digest(rollback_step.arguments), canonical_step_digest(plan.plan_digest, "rollback", ordinal, rollback_step.operation, rollback_step.arguments))
        grouped[phase_for(ordinal)].append(ExecutionStepIdentity(ordinal, forward, reverse))
    synthetic = len(plan.steps)
    for phase, operation in ((ExecutionPhase.ATTEST, "verify_runtime_attestation"), (ExecutionPhase.ACCEPT, "run_behavior_acceptance"), (ExecutionPhase.FINALIZE, "finalize_execution")):
        args = {"plan_id": plan.plan_id, "phase": phase.value}
        grouped[phase].append(ExecutionStepIdentity(synthetic, ExecutionOperationIdentity(operation, canonical_arguments_digest(args), canonical_step_digest(plan.plan_digest, "forward", synthetic, operation, args))))
        synthetic += 1
    if any(not grouped[phase] for phase in ExecutionPhase):
        raise ValueError("approved plan does not cover every execution phase")
    return tuple(ExecutionPhaseSpec(index, phase, tuple(grouped[phase])) for index, phase in enumerate(ExecutionPhase))


def _make_header(bundle, binding, source, created_at: str) -> ProvisioningExecutionHeader:
    plan = bundle.plan
    return build_execution_header(execution_id="execution." + plan.plan_digest.removeprefix("sha256:"), plan_id=plan.plan_id, plan_digest=plan.plan_digest, bundle_id=bundle.intent.plan_id, bundle_digest=bundle.bundle_digest, approval_ref=binding.approval_ref, approval_scope_digest=binding.scope_digest, approved_by=source.approved_by, approved_at=source.approved_at, acceptance_contract_version=plan.provisioning_contract_version, acceptance_contract_digest=plan.capability_digest, created_at=source.approved_at, phases=_manifest(plan), approved_runtime_digest=plan.runtime_artifact_identity, approved_config_digest=plan.config_digest)


def _append(store: SQLiteStore, header: ProvisioningExecutionHeader, ordinal: int, identity: ExecutionStepIdentity, event: CheckpointEvent, when: str, *, evidence=None, runtime=None, acceptance=None, rollback: bool = False) -> None:
    chain = store.load_backup_execution_checkpoints(header.execution_id)
    previous = header.header_digest if not chain else chain[-1].checkpoint_digest
    phase = next(phase for phase in header.phases if identity in phase.steps)
    bound = identity.rollback if rollback else identity.forward
    if bound is None:
        raise ValueError("rollback is not approved for this operation")
    checkpoint = build_checkpoint(checkpoint_id=f"{header.execution_id}.checkpoint.{ordinal}.{uuid.uuid4().hex}", execution_id=header.execution_id, checkpoint_ordinal=ordinal, previous_digest=previous, phase=phase.phase, phase_ordinal=phase.phase_ordinal, plan_step_ordinal=identity.plan_step_ordinal, step_digest=bound.step_digest, event=event, observed_at=when, step_evidence=evidence, runtime_attestation=runtime, behavior_acceptance=acceptance)
    store.append_backup_execution_checkpoint(checkpoint)
    tracker = getattr(store, "_backup_execution_invocation_checkpoint_ids", None)
    if tracker is not None:
        tracker.add(checkpoint.checkpoint_id)


def _claim_forward(store, header: ProvisioningExecutionHeader, identity: ExecutionStepIdentity, when: str) -> bool:
    """Revalidate authority and claim one exact operation in one transaction."""
    with store.agent_transaction():
        chain = store.load_backup_execution_checkpoints(header.execution_id)
        verify_backup_execution_chain(header, chain)
        expected_steps = [step for phase in header.phases for step in phase.steps]
        try:
            requested_index = expected_steps.index(identity)
        except ValueError as error:
            raise ValueError("execution claim is not the next exact operation") from error

        def validate_frontier() -> list[int]:
            completed = [item.plan_step_ordinal for item in chain if item.event is CheckpointEvent.STEP_COMPLETED]
            if completed != [step.plan_step_ordinal for step in expected_steps[:len(completed)]]:
                raise ValueError("execution completed prefix is not exact")
            return completed

        def contend(message: str = "EXECUTION_IN_PROGRESS") -> None:
            raise _ExecutionContentionError(message)

        try:
            terminal = bool(chain and chain[-1].event is CheckpointEvent.EXECUTION_FINALIZED)
            bundle, binding, source = _load_authoritative_bundle(store, header.plan_id, terminal=terminal)
            if _make_header(bundle, binding, source, header.created_at) != header:
                raise _AuthorityMismatchError("stored execution header does not match current authority")
        except (_AuthorityRecordError, _AuthorityMismatchError) as authority_error:
            if _bound_source_is_executed(store, header.plan_id):
                raise ValueError("executed approval is not bound to a terminal execution")
            _verify_immutable_cleanup_identity(store, header, chain)
            completed = validate_frontier()
            if chain and chain[-1].event in (CheckpointEvent.STEP_STARTED, CheckpointEvent.ROLLBACK_STARTED):
                raise ValueError("EXECUTION_IN_PROGRESS")
            if len(completed) >= len(expected_steps) or chain[-1].event is not CheckpointEvent.STEP_COMPLETED:
                raise authority_error
            frontier_index = len(completed)
            if requested_index > frontier_index:
                raise authority_error
            frontier_identity = expected_steps[frontier_index]
            evidence = ProvisioningStepEvidence(StepDisposition.FAILED, "FORWARD_AUTHORITY_LOST", _result_digest(frontier_identity.forward.operation, False, "FORWARD_AUTHORITY_LOST"), True)
            _append(store, header, len(chain), frontier_identity, CheckpointEvent.EXECUTION_ABORTED, when, evidence=evidence)
            return False
        completed = validate_frontier()
        if len(completed) >= len(expected_steps) or requested_index < len(completed):
            contend()
        if chain and chain[-1].event in (CheckpointEvent.STEP_STARTED, CheckpointEvent.ROLLBACK_STARTED):
            contend()
        if requested_index > len(completed) or expected_steps[len(completed)] != identity:
            raise ValueError("execution claim is not the next exact operation")
        _append(store, header, len(chain), identity, CheckpointEvent.STEP_STARTED, when)
        return True


def _verify_immutable_cleanup_identity(store, header: ProvisioningExecutionHeader, chain: tuple[ProvisioningCheckpoint, ...]) -> None:
    from . import provisioning_bundle
    bundle = provisioning_bundle.load_provisioning_bundle(store, header.plan_id)
    if type(bundle) is not provisioning_bundle.ProvisioningBundleV1 or not bundle.preflight.passed:
        raise ValueError("EXECUTION_IMMUTABLE_IDENTITY_INVALID")
    if bundle.intent.plan_id != header.bundle_id or bundle.bundle_digest != header.bundle_digest or bundle.plan.plan_id != header.plan_id or bundle.plan.plan_digest != header.plan_digest or _manifest(bundle.plan) != header.phases:
        raise ValueError("EXECUTION_IMMUTABLE_IDENTITY_INVALID")
    draft = provisioning_bundle.binding_draft_for_bundle(bundle)
    if draft.source_kind != "roadex-human-decision" or draft.source_id != header.plan_id:
        raise ValueError("EXECUTION_IMMUTABLE_IDENTITY_INVALID")
    from .roadex_approval_status import load_roadex_human_plan
    try:
        source = load_roadex_human_plan(store, draft.source_id)
    except (KeyError, ValueError) as error:
        raise ValueError("EXECUTION_IMMUTABLE_IDENTITY_INVALID") from error
    if (
        source.status.value != "approved"
        or source.plan_id != header.plan_id
        or source.plan_digest != header.plan_digest
        or source.provisioning_contract_version != header.acceptance_contract_version
        or source.runtime_artifact_identity != header.approved_runtime_digest
        or source.config_digest != header.approved_config_digest
        or source.approved_by != header.approved_by
        or source.approved_at != header.approved_at
    ):
        raise ValueError("EXECUTION_IMMUTABLE_IDENTITY_INVALID")
    verify_backup_execution_chain(header, chain)


def _derive_rollback_frontier(header: ProvisioningExecutionHeader, checkpoints: tuple[ProvisioningCheckpoint, ...]) -> tuple[ExecutionStepIdentity, ...]:
    """Purely derive exact pending rollback identities from a verified chain."""
    verify_backup_execution_chain(header, checkpoints)
    identities = {step.plan_step_ordinal: step for phase in header.phases for step in phase.steps}
    changed: list[ExecutionStepIdentity] = []
    for checkpoint in checkpoints:
        if checkpoint.event is not CheckpointEvent.STEP_COMPLETED or checkpoint.step_evidence is None:
            continue
        if checkpoint.step_evidence.disposition is not StepDisposition.CHANGED:
            continue
        identity = identities.get(checkpoint.plan_step_ordinal)
        if identity is None or identity.forward.step_digest != checkpoint.step_digest:
            raise ValueError("changed forward checkpoint identity is invalid")
        changed.append(identity)
    completed_or_failed = {
        (item.plan_step_ordinal, item.step_digest)
        for item in checkpoints
        if item.event in (CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED)
    }
    return tuple(
        identity for identity in reversed(changed)
        if identity.rollback is not None
        and (identity.plan_step_ordinal, identity.rollback.step_digest) not in completed_or_failed
    )


def _bound_source_is_executed(store, plan_id: str) -> bool:
    from . import provisioning_bundle
    from .roadex_approval_status import load_roadex_human_plan

    # Inspect the exact source selected by the immutable bundle identity.  Do
    # not make a malformed approval binding look like a non-executed source:
    # the source itself is the independent safety check for abort decisions.
    bundle = provisioning_bundle.load_provisioning_bundle(store, plan_id)
    draft = provisioning_bundle.binding_draft_for_bundle(bundle)
    if draft.source_kind != "roadex-human-decision" or draft.source_id != plan_id:
        raise ValueError("expected approval source identity is invalid")
    source = load_roadex_human_plan(store, draft.source_id)
    return getattr(getattr(source, "status", None), "value", None) == "executed"


def _abort_paused_forward_on_authority_loss(store, header: ProvisioningExecutionHeader, when: str) -> bool:
    """Durably stop a paused mutable prefix when forward authority has drifted."""
    with store.agent_transaction():
        chain = store.load_backup_execution_checkpoints(header.execution_id)
        verify_backup_execution_chain(header, chain)
        try:
            bundle, binding, source = _load_authoritative_bundle(store, header.plan_id)
            if _make_header(bundle, binding, source, header.created_at) != header:
                raise _AuthorityMismatchError("stored execution header does not match current authority")
        except (_AuthorityRecordError, _AuthorityMismatchError) as authority_error:
            if _bound_source_is_executed(store, header.plan_id):
                raise ValueError("executed approval is not bound to a terminal execution") from authority_error
            _verify_immutable_cleanup_identity(store, header, chain)
            expected_steps = [step for phase in header.phases for step in phase.steps]
            completed = [item for item in chain if item.event is CheckpointEvent.STEP_COMPLETED]
            if [item.plan_step_ordinal for item in completed] != [step.plan_step_ordinal for step in expected_steps[:len(completed)]]:
                raise authority_error
            next_index = len(completed)
            if next_index >= len(expected_steps):
                raise authority_error
            next_identity = expected_steps[next_index]
            if not any(
                item.step_evidence is not None
                and item.step_evidence.disposition is StepDisposition.CHANGED
                and expected_steps[item.plan_step_ordinal].rollback is not None
                for item in completed
            ) or (chain and chain[-1].event is not CheckpointEvent.STEP_COMPLETED):
                raise authority_error
            evidence = ProvisioningStepEvidence(StepDisposition.FAILED, "FORWARD_AUTHORITY_LOST", _result_digest(next_identity.forward.operation, False, "FORWARD_AUTHORITY_LOST"), True)
            _append(store, header, len(chain), next_identity, CheckpointEvent.EXECUTION_ABORTED, when, evidence=evidence)
            return True
        return False


def _view(store: SQLiteStore, execution_id: str) -> ProvisioningExecutionView:
    header = store.load_backup_execution_header(execution_id)
    return derive_backup_execution_view(header, store.load_backup_execution_checkpoints(execution_id))


@dataclass(frozen=True)
class _InvocationResult:
    view: ProvisioningExecutionView
    entry_checkpoints: tuple[ProvisioningCheckpoint, ...]
    entry_plan: object
    exit_checkpoints: tuple[ProvisioningCheckpoint, ...]
    exit_plan: object
    invocation_checkpoints: tuple[ProvisioningCheckpoint, ...]
    mutation_performed: bool


def _load_execution_snapshot(store: SQLiteStore, header: ProvisioningExecutionHeader, *, after_checkpoints=None):
    """Load the invocation's execution chain and plan from one SQLite snapshot."""
    from .backup_provisioning import _load

    store._connection.execute("BEGIN")
    try:
        rows = store._connection.execute(
            "SELECT * FROM backup_provisioning_execution_checkpoints "
            "WHERE execution_id=? ORDER BY checkpoint_ordinal",
            (header.execution_id,),
        ).fetchall()
        checkpoints = tuple(store._decode_backup_checkpoint_row(row) for row in rows)
        verify_backup_execution_chain(header, checkpoints)
        if after_checkpoints is not None:
            after_checkpoints()
        row = store._connection.execute(
            "SELECT payload FROM backup_provisioning_plans WHERE id=?", (header.plan_id,)
        ).fetchone()
        if row is None:
            raise KeyError(header.plan_id)
        plan = _load(str(row["payload"]))
    except BaseException:
        store._connection.rollback()
        raise
    else:
        store._connection.commit()
    return checkpoints, plan


def _drive(store_path: str, header: ProvisioningExecutionHeader, adapter, acceptance_runner, when: str, *, genesis_claimed: bool = False, initial_mutation: bool = False) -> _InvocationResult:
    from .store import SQLiteStore
    owner_id = uuid.uuid4().hex
    with SQLiteStore(store_path) as store:
        store._backup_execution_invocation_checkpoint_ids = set()
        chain, plan = _load_execution_snapshot(store, header)
        initial_changes = store._connection.total_changes
        if not chain:
            raise ValueError("execution has no atomic genesis")
        entry_checkpoints = chain
        entry_plan = plan

        def finish() -> _InvocationResult:
            exit_checkpoints, exit_plan = _load_execution_snapshot(store, header)
            invocation_checkpoints = tuple(
                item for item in exit_checkpoints
                if item.checkpoint_id in store._backup_execution_invocation_checkpoint_ids
            )
            return _InvocationResult(
                derive_backup_execution_view(header, exit_checkpoints),
                entry_checkpoints,
                entry_plan,
                exit_checkpoints,
                exit_plan,
                invocation_checkpoints,
                initial_mutation or genesis_claimed or store._connection.total_changes > initial_changes,
            )

        def rollback_or_finish(ordinal: int) -> _InvocationResult | None:
            try:
                _rollback(store, header, when, ordinal, adapter, owner_id)
            except _ExecutionContentionError:
                if not store._backup_execution_invocation_checkpoint_ids:
                    raise
                return finish()
            return None

        if any(item.event in (CheckpointEvent.STEP_FAILED, CheckpointEvent.EXECUTION_ABORTED) for item in chain):
            if chain[-1].event is CheckpointEvent.STEP_STARTED:
                raise _ExecutionContentionError("EXECUTION_IN_PROGRESS")
            rollback_result = rollback_or_finish(len(chain))
            if rollback_result is not None:
                return rollback_result
            return finish()
        if chain[-1].event is CheckpointEvent.EXECUTION_FINALIZED:
            _reconcile_executed(store, header)
            return finish()
        if chain[-1].event is CheckpointEvent.STEP_COMPLETED and chain[-1].phase is ExecutionPhase.FINALIZE:
            identity = header.phases[-1].steps[-1]
            _append(store, header, len(chain), identity, CheckpointEvent.EXECUTION_FINALIZED, when)
            _reconcile_executed(store, header)
            return finish()
        completed = {item.plan_step_ordinal for item in chain if item.event is CheckpointEvent.STEP_COMPLETED}
        ordinal = len(chain)
        pending_claim = chain[-1].event is CheckpointEvent.STEP_STARTED
        if pending_claim and not genesis_claimed:
            raise _ExecutionContentionError("EXECUTION_IN_PROGRESS")
        for phase in header.phases:
            for identity in phase.steps:
                if identity.plan_step_ordinal in completed:
                    continue
                # Runner readiness is checked before the durable claim, so a paused
                # execution retains a resumable prefix and cannot strand ATTEST/ACCEPT.
                if identity.forward.operation == "verify_runtime_attestation" and (acceptance_runner is None or not callable(getattr(acceptance_runner, "attest", None))):
                    return finish()
                if identity.forward.operation == "run_behavior_acceptance" and (acceptance_runner is None or not callable(getattr(acceptance_runner, "accept", None))):
                    return finish()
                if pending_claim:
                    pending_claim = False
                else:
                    try:
                        claimed = _claim_forward(store, header, identity, when)
                    except _ExecutionContentionError:
                        # This invocation may have completed changed work before
                        # another caller claimed the next operation. Preserve its
                        # own checkpoints and mutation accounting; only a caller
                        # with no writes is a pure EXECUTION_IN_PROGRESS loser.
                        if not store._backup_execution_invocation_checkpoint_ids:
                            raise
                        return finish()
                    if not claimed:
                        rollback_result = rollback_or_finish(len(store.load_backup_execution_checkpoints(header.execution_id)))
                        if rollback_result is not None:
                            return rollback_result
                        return finish()
                    ordinal += 1
                operation = identity.forward.operation
                try:
                    runtime = acceptance = None
                    if operation == "verify_runtime_attestation":
                        runtime = _runtime(acceptance_runner.attest(header))
                        if runtime.approved_runtime_digest != header.approved_runtime_digest or runtime.approved_config_digest != header.approved_config_digest or runtime.active_runtime_digest != header.approved_runtime_digest or runtime.active_config_digest != header.approved_config_digest:
                            raise ValueError("runtime attestation identity mismatch")
                        evidence = ProvisioningStepEvidence(StepDisposition.CHANGED, "ATTESTATION_VERIFIED", _result_digest(operation, True, "ATTESTATION_VERIFIED"), True)
                        _append(store, header, ordinal, identity, CheckpointEvent.STEP_COMPLETED, when, evidence=evidence, runtime=runtime); ordinal += 1
                    elif operation == "run_behavior_acceptance":
                        attestation = next((item.runtime_attestation for item in reversed(store.load_backup_execution_checkpoints(header.execution_id)) if item.runtime_attestation), None)
                        if attestation is None:
                            raise ValueError("runtime attestation is required")
                        acceptance = _acceptance(acceptance_runner.accept(header, attestation))
                        if acceptance.contract_version != header.acceptance_contract_version or acceptance.acceptance_contract_digest != header.acceptance_contract_digest:
                            raise ValueError("acceptance identity mismatch")
                        evidence = ProvisioningStepEvidence(StepDisposition.CHANGED if acceptance.passed else StepDisposition.FAILED, acceptance.safe_code, acceptance.results_digest, True)
                        event = CheckpointEvent.STEP_COMPLETED if acceptance.passed else CheckpointEvent.STEP_FAILED
                        _append(store, header, ordinal, identity, event, when, evidence=evidence, acceptance=acceptance); ordinal += 1
                        if not acceptance.passed:
                            rollback_result = rollback_or_finish(ordinal)
                            if rollback_result is not None:
                                return rollback_result
                            return finish()
                    elif operation == "finalize_execution":
                        evidence = ProvisioningStepEvidence(StepDisposition.CHANGED, "FINALIZATION_VERIFIED", _result_digest(operation, True, "FINALIZATION_VERIFIED"), True)
                        _append(store, header, ordinal, identity, CheckpointEvent.STEP_COMPLETED, when, evidence=evidence); ordinal += 1
                        _append(store, header, ordinal, identity, CheckpointEvent.EXECUTION_FINALIZED, when); ordinal += 1
                        _reconcile_executed(store, header)
                        return finish()
                    else:
                        step = plan.steps[identity.plan_step_ordinal]
                        if canonical_arguments_digest(step.arguments) != identity.forward.arguments_digest:
                            raise ValueError("approved step arguments have drifted")
                        result = adapter.execute(step)
                        evidence = _normalize_result(operation, result)
                        if evidence.disposition is StepDisposition.FAILED:
                            _append(store, header, ordinal, identity, CheckpointEvent.STEP_FAILED, when, evidence=evidence); ordinal += 1
                            rollback_result = rollback_or_finish(ordinal)
                            if rollback_result is not None:
                                return rollback_result
                            return finish()
                        _append(store, header, ordinal, identity, CheckpointEvent.STEP_COMPLETED, when, evidence=evidence); ordinal += 1
                except Exception as error:
                    code = "OPERATION_FAILED"
                    evidence = ProvisioningStepEvidence(StepDisposition.FAILED, code, _result_digest(operation, False, code), True)
                    _append(store, header, ordinal, identity, CheckpointEvent.STEP_FAILED, when, evidence=evidence); ordinal += 1
                    rollback_result = rollback_or_finish(ordinal)
                    if rollback_result is not None:
                        return rollback_result
                    return finish()
        return finish()


def _rollback(store, header: ProvisioningExecutionHeader, when: str, ordinal: int, adapter, owner_id: str) -> None:
    from .backup_provisioning import _stored
    plan = _stored(store, header.plan_id)
    while True:
        checkpoints = store.load_backup_execution_checkpoints(header.execution_id)
        frontier = _derive_rollback_frontier(header, checkpoints)
        if not frontier:
            return
        requested = frontier[0]
        rollback_step = next((step for step in plan.rollback_steps
            if requested.rollback is not None
            and step.operation == requested.rollback.operation
            and canonical_arguments_digest(step.arguments) == requested.rollback.arguments_digest
            and canonical_step_digest(plan.plan_digest, "rollback", requested.plan_step_ordinal, step.operation, step.arguments) == requested.rollback.step_digest), None)
        if rollback_step is None:
            raise ValueError("approved rollback identity is not present in the exact plan")
        claim_epoch, owner_lock = _claim_rollback(store, header, requested, when, owner_id)
        try:
            try:
                prior = next((item.step_evidence for item in checkpoints if item.event is CheckpointEvent.STEP_COMPLETED and item.plan_step_ordinal == requested.plan_step_ordinal and item.step_digest == requested.forward.step_digest), None)
                setter = getattr(adapter, "set_rollback_prestate", None)
                if callable(setter): setter(requested.plan_step_ordinal, prior)
                result = adapter.execute(rollback_step)
                evidence = _normalize_result(rollback_step.operation, result)
                event = CheckpointEvent.ROLLBACK_FAILED if evidence.disposition is StepDisposition.FAILED else CheckpointEvent.ROLLBACK_COMPLETED
            except Exception:
                code = "ROLLBACK_FAILED"
                evidence = ProvisioningStepEvidence(StepDisposition.FAILED, code, _result_digest(rollback_step.operation, False, code), True)
                event = CheckpointEvent.ROLLBACK_FAILED
            deferred_error = None
            with store.agent_transaction():
                current = store.load_backup_execution_checkpoints(header.execution_id)
                verify_backup_execution_chain(header, current)
                if not current or current[-1].event is not CheckpointEvent.ROLLBACK_STARTED:
                    raise ValueError("owned rollback claim is missing")
                claim = _load_rollback_claim(store, header.execution_id)
                if (
                    claim is None
                    or claim["plan_step_ordinal"] != requested.plan_step_ordinal
                    or claim["step_digest"] != requested.rollback.step_digest
                    or claim["owner_id"] != owner_id
                    or claim["claim_epoch"] != claim_epoch
                ):
                    raise ValueError("owned rollback claim owner changed")
                claimed = next(step for phase in header.phases for step in phase.steps if step.plan_step_ordinal == current[-1].plan_step_ordinal)
                if claimed != requested or current[-1].step_digest != requested.rollback.step_digest:
                    raise ValueError("owned rollback claim identity changed")
                try:
                    _append(store, header, len(current), requested, event, when, evidence=evidence, rollback=True)
                except BaseException as error:
                    completed = store.load_backup_execution_checkpoints(header.execution_id)
                    if not completed or completed[-1].event is not event or completed[-1].plan_step_ordinal != requested.plan_step_ordinal or completed[-1].step_digest != requested.rollback.step_digest:
                        raise
                    _release_rollback_claim_locked(store, header, requested, owner_id, claim_epoch)
                    deferred_error = error
                else:
                    _release_rollback_claim_locked(store, header, requested, owner_id, claim_epoch)
            if deferred_error is not None:
                raise deferred_error
        finally:
            owner_lock.release()


def _rollback_claim_expired(lease_expires_at: str, when: str) -> bool:
    return datetime.fromisoformat(lease_expires_at) <= datetime.fromisoformat(when)


def _load_rollback_claim(store, execution_id: str):
    row = store._connection.execute(
        "SELECT execution_id, plan_step_ordinal, step_digest, owner_id, claimed_at, lease_expires_at, claim_epoch "
        "FROM backup_provisioning_execution_rollback_claims WHERE execution_id=?",
        (execution_id,),
    ).fetchone()
    if row is None:
        return None
    if (
        str(row["execution_id"]) != execution_id
        or type(row["plan_step_ordinal"]) is not int
        or row["plan_step_ordinal"] < 0
        or type(row["step_digest"]) is not str
        or type(row["owner_id"]) is not str
        or not row["owner_id"]
        or type(row["claimed_at"]) is not str
        or type(row["lease_expires_at"]) is not str
        or type(row["claim_epoch"]) is not int
        or row["claim_epoch"] < 1
    ):
        raise ValueError("rollback claim metadata is invalid")
    _digest(str(row["step_digest"]), "rollback claim step_digest")
    _timestamp(str(row["claimed_at"]), "rollback claim claimed_at")
    _timestamp(str(row["lease_expires_at"]), "rollback claim lease_expires_at")
    if datetime.fromisoformat(str(row["lease_expires_at"])) <= datetime.fromisoformat(str(row["claimed_at"])):
        raise ValueError("rollback claim lease is invalid")
    return row


def _release_rollback_claim_locked(store, header: ProvisioningExecutionHeader, requested: ExecutionStepIdentity, owner_id: str, claim_epoch: int) -> None:
    claim = _load_rollback_claim(store, header.execution_id)
    if claim is None:
        raise ValueError("rollback claim is missing before release")
    if claim["plan_step_ordinal"] != requested.plan_step_ordinal or claim["step_digest"] != requested.rollback.step_digest:
        raise ValueError("rollback claim completion identity is invalid")
    if claim["owner_id"] != owner_id or claim["claim_epoch"] != claim_epoch:
        raise ValueError("rollback claim owner changed before release")
    deleted = store._connection.execute(
        "DELETE FROM backup_provisioning_execution_rollback_claims WHERE execution_id=? AND plan_step_ordinal=? AND step_digest=? AND owner_id=? AND claim_epoch=?",
        (header.execution_id, requested.plan_step_ordinal, requested.rollback.step_digest, owner_id, claim_epoch),
    )
    if deleted.rowcount != 1:
        raise ValueError("rollback claim release rowcount is invalid")
    if _load_rollback_claim(store, header.execution_id) is not None:
        raise ValueError("rollback claim remains after release")


def _claim_rollback(store, header: ProvisioningExecutionHeader, requested: ExecutionStepIdentity, when: str, owner_id: str) -> tuple[int, _RollbackOwnerLock]:
    owner_lock_holder: list[_RollbackOwnerLock | None] = [None]
    try:
        return _claim_rollback_transaction(store, header, requested, when, owner_id, owner_lock_holder)
    except BaseException:
        if owner_lock_holder[0] is not None:
            owner_lock_holder[0].release()
        raise


def _claim_rollback_transaction(store, header: ProvisioningExecutionHeader, requested: ExecutionStepIdentity, when: str, owner_id: str, owner_lock_holder: list[_RollbackOwnerLock | None]) -> tuple[int, _RollbackOwnerLock]:
    """Atomically claim one exact rollback operation on the verified frontier."""
    if requested.rollback is None:
        raise ValueError("rollback is not approved for this operation")
    deferred_error = None
    owner_lock = None
    with store.agent_transaction():
        claim_now = _rollback_claim_clock()
        claim_expires = (datetime.fromisoformat(claim_now) + _ROLLBACK_CLAIM_LEASE).isoformat()
        chain = store.load_backup_execution_checkpoints(header.execution_id)
        verify_backup_execution_chain(header, chain)
        _verify_immutable_cleanup_identity(store, header, chain)
        frontier = _derive_rollback_frontier(header, chain)
        done = {(item.plan_step_ordinal, item.step_digest) for item in chain
                if item.event in (CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED)}
        claim = _load_rollback_claim(store, header.execution_id)
        if chain and chain[-1].event is CheckpointEvent.ROLLBACK_STARTED:
            if chain[-1].plan_step_ordinal != requested.plan_step_ordinal or chain[-1].step_digest != requested.rollback.step_digest:
                if claim is None or claim["plan_step_ordinal"] != chain[-1].plan_step_ordinal or claim["step_digest"] != chain[-1].step_digest:
                    raise ValueError("rollback frontier has an impossible active identity")
                if (requested.plan_step_ordinal, requested.rollback.step_digest) in done:
                    raise _ExecutionContentionError("EXECUTION_IN_PROGRESS")
                raise ValueError("rollback frontier has an impossible active identity")
            if claim is None or claim["plan_step_ordinal"] != requested.plan_step_ordinal or claim["step_digest"] != requested.rollback.step_digest:
                raise ValueError("active rollback claim metadata is missing or mismatched")
            try:
                owner_lock = _RollbackOwnerLock.acquire(store, header.execution_id)
            except _RollbackOwnerSocketCollision as error:
                raise _ExecutionContentionError("EXECUTION_IN_PROGRESS") from error
            owner_lock_holder[0] = owner_lock
            if not _rollback_claim_expired(str(claim["lease_expires_at"]), claim_now):
                raise _ExecutionContentionError("EXECUTION_IN_PROGRESS")
            updated = store._connection.execute(
                "UPDATE backup_provisioning_execution_rollback_claims "
                "SET owner_id=?, claimed_at=?, lease_expires_at=?, claim_epoch=claim_epoch+1 "
                "WHERE execution_id=? AND plan_step_ordinal=? AND step_digest=? AND owner_id=? AND lease_expires_at=? AND claim_epoch=?",
                (owner_id, claim_now, claim_expires, header.execution_id, requested.plan_step_ordinal, requested.rollback.step_digest, claim["owner_id"], claim["lease_expires_at"], claim["claim_epoch"]),
            )
            if updated.rowcount != 1:
                raise ValueError("rollback claim takeover rowcount is invalid")
            acquired_epoch = int(claim["claim_epoch"]) + 1
            persisted = _load_rollback_claim(store, header.execution_id)
            if (
                persisted is None
                or persisted["execution_id"] != header.execution_id
                or persisted["plan_step_ordinal"] != requested.plan_step_ordinal
                or persisted["step_digest"] != requested.rollback.step_digest
                or persisted["owner_id"] != owner_id
                or persisted["claimed_at"] != claim_now
                or persisted["lease_expires_at"] != claim_expires
                or persisted["claim_epoch"] != acquired_epoch
            ):
                raise ValueError("rollback claim takeover read-back mismatch")
            return acquired_epoch, owner_lock
        if claim is not None:
            claim_completed = any(
                item.event in (CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED)
                and item.plan_step_ordinal == claim["plan_step_ordinal"]
                and item.step_digest == claim["step_digest"]
                for item in chain
            )
            if claim_completed:
                store._connection.execute("DELETE FROM backup_provisioning_execution_rollback_claims WHERE execution_id=?", (header.execution_id,))
            else:
                raise ValueError("rollback claim metadata is not bound to the verified chain")
        if not frontier or frontier[0] != requested:
            if (requested.plan_step_ordinal, requested.rollback.step_digest) in done:
                raise _ExecutionContentionError("EXECUTION_IN_PROGRESS")
            raise ValueError("requested rollback is outside the verified frontier")
        try:
            owner_lock = _RollbackOwnerLock.acquire(store, header.execution_id)
        except _RollbackOwnerSocketCollision as error:
            raise ValueError("rollback owner socket collision without an exact active claim") from error
        owner_lock_holder[0] = owner_lock
        inserted = store._connection.execute(
            "INSERT INTO backup_provisioning_execution_rollback_claims "
            "(execution_id, plan_step_ordinal, step_digest, owner_id, claimed_at, lease_expires_at, claim_epoch) VALUES (?, ?, ?, ?, ?, ?, 1)",
            (header.execution_id, requested.plan_step_ordinal, requested.rollback.step_digest, owner_id, claim_now, claim_expires),
        )
        if inserted.rowcount != 1:
            raise ValueError("rollback claim insert rowcount is invalid")
        persisted = _load_rollback_claim(store, header.execution_id)
        if (
            persisted is None
            or persisted["execution_id"] != header.execution_id
            or persisted["plan_step_ordinal"] != requested.plan_step_ordinal
            or persisted["step_digest"] != requested.rollback.step_digest
            or persisted["owner_id"] != owner_id
            or persisted["claimed_at"] != claim_now
            or persisted["lease_expires_at"] != claim_expires
            or persisted["claim_epoch"] != 1
        ):
            raise ValueError("rollback claim insert read-back mismatch")
        try:
            _append(store, header, len(chain), requested, CheckpointEvent.ROLLBACK_STARTED, when, rollback=True)
        except BaseException as error:
            current = store.load_backup_execution_checkpoints(header.execution_id)
            if not current or current[-1].event is not CheckpointEvent.ROLLBACK_STARTED or current[-1].plan_step_ordinal != requested.plan_step_ordinal or current[-1].step_digest != requested.rollback.step_digest:
                raise
            # _append may have durably inserted the immutable row before an
            # injected crash is raised by a test/instrumentation wrapper.
            # Commit the exact claim metadata with it, then preserve the crash.
            deferred_error = error
    if deferred_error is not None:
        raise deferred_error
    return 1, owner_lock


def _reconcile_executed(store, header: ProvisioningExecutionHeader) -> None:
    from .backup_provisioning import ProvisioningStatus, _dump, _stored
    with store.agent_transaction():
        checkpoints = store.load_backup_execution_checkpoints(header.execution_id)
        verify_backup_execution_chain(header, checkpoints)
        if not checkpoints or checkpoints[-1].event is not CheckpointEvent.EXECUTION_FINALIZED:
            raise ValueError("execution finalization is not complete")
        terminal = checkpoints[-1]
        evidence_digest = terminal.checkpoint_digest
        executed_at = terminal.observed_at
        current = _stored(store, header.plan_id)
        if current.status is ProvisioningStatus.EXECUTED and current.evidence_digest == evidence_digest:
            if current.executed_at == executed_at:
                return
            store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(replace(current, executed_at=executed_at)), header.plan_id))
            return
        if current.status is ProvisioningStatus.EXECUTED:
            raise ValueError("executed plan evidence is not bound to this execution chain")
        if current.status not in (ProvisioningStatus.APPROVED, ProvisioningStatus.EXECUTED):
            raise ValueError("only an approved plan can be finalized")
        store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(replace(current, status=ProvisioningStatus.EXECUTED, executed_at=executed_at, evidence_digest=evidence_digest)), header.plan_id))


def _chain_requires_cleanup(chain: tuple[ProvisioningCheckpoint, ...]) -> bool:
    return any(item.event in (CheckpointEvent.STEP_FAILED, CheckpointEvent.EXECUTION_ABORTED, CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED) for item in chain)


def _start_execution_with_invocation(store_path: str, plan_id: str, adapter, acceptance_runner, now=None) -> _InvocationResult:
    when = _execution_time(now)
    from .store import SQLiteStore
    initial_mutation = False
    with SQLiteStore(store_path) as store:
        try:
            header = store.load_backup_execution_header_for_plan(plan_id)
        except KeyError:
            with store.agent_transaction():
                bundle, binding, source = _load_authoritative_bundle(store, plan_id)
                header = _make_header(bundle, binding, source, when)
                first = header.phases[0].steps[0]
                genesis = build_checkpoint(checkpoint_id=f"{header.execution_id}.checkpoint.0.{uuid.uuid4().hex}", execution_id=header.execution_id, checkpoint_ordinal=0, previous_digest=header.header_digest, phase=ExecutionPhase.MATERIALIZE, phase_ordinal=0, plan_step_ordinal=first.plan_step_ordinal, step_digest=first.forward.step_digest, event=CheckpointEvent.STEP_STARTED, observed_at=when)
                store.save_backup_execution(header, genesis)
            genesis_claimed = True
            initial_mutation = True
        else:
            chain = store.load_backup_execution_checkpoints(header.execution_id)
            verify_backup_execution_chain(header, chain)
            source = None
            if _chain_requires_cleanup(chain):
                _verify_immutable_cleanup_identity(store, header, chain)
            else:
                try:
                    bundle, binding, source = _load_authoritative_bundle(store, plan_id, terminal=bool(chain and chain[-1].event is CheckpointEvent.EXECUTION_FINALIZED))
                    expected = _make_header(bundle, binding, source, header.created_at)
                    if expected != header:
                        raise _AuthorityMismatchError("stored execution header does not match current authority")
                except (_AuthorityRecordError, _AuthorityMismatchError) as authority_error:
                    if not _abort_paused_forward_on_authority_loss(store, header, when):
                        raise authority_error
                    initial_mutation = True
                    source = None
            if chain and chain[-1].event is CheckpointEvent.STEP_STARTED:
                raise _ExecutionContentionError("EXECUTION_IN_PROGRESS")
            if source is not None and not _chain_requires_cleanup(chain) and source.status.value == "executed" and (not chain or chain[-1].event is not CheckpointEvent.EXECUTION_FINALIZED):
                raise ValueError("executed approval is not bound to a terminal execution")
            genesis_claimed = False
    return _drive(store_path, header, adapter, acceptance_runner, when, genesis_claimed=genesis_claimed, initial_mutation=initial_mutation)


def start_execution(store_path: str, plan_id: str, adapter, acceptance_runner, now=None) -> ProvisioningExecutionView:
    return _start_execution_with_invocation(store_path, plan_id, adapter, acceptance_runner, now=now).view


def _continue_execution_with_invocation(store_path: str, execution_id: str, adapter, acceptance_runner, now=None) -> _InvocationResult:
    when = _execution_time(now)
    from .store import SQLiteStore
    initial_mutation = False
    with SQLiteStore(store_path) as store:
        header = store.load_backup_execution_header(execution_id)
        chain = store.load_backup_execution_checkpoints(execution_id)
        verify_backup_execution_chain(header, chain)
        if _chain_requires_cleanup(chain):
            _verify_immutable_cleanup_identity(store, header, chain)
        else:
            try:
                bundle, binding, source = _load_authoritative_bundle(store, header.plan_id, terminal=bool(chain and chain[-1].event is CheckpointEvent.EXECUTION_FINALIZED))
                if _make_header(bundle, binding, source, header.created_at) != header:
                    raise _AuthorityMismatchError("checkpoint header identity or manifest has drifted")
            except (_AuthorityRecordError, _AuthorityMismatchError) as authority_error:
                if not _abort_paused_forward_on_authority_loss(store, header, when):
                    raise authority_error
                initial_mutation = True
                source = None
            if source is not None and source.status.value == "executed" and (not chain or chain[-1].event is not CheckpointEvent.EXECUTION_FINALIZED):
                raise ValueError("executed approval is not bound to a terminal execution")
    return _drive(store_path, header, adapter, acceptance_runner, when, initial_mutation=initial_mutation)


def continue_execution(store_path: str, execution_id: str, adapter, acceptance_runner, now=None) -> ProvisioningExecutionView:
    return _continue_execution_with_invocation(store_path, execution_id, adapter, acceptance_runner, now=now).view


__all__ = ["BehaviorAcceptance", "CheckpointEvent", "ExecutionOperationIdentity", "ExecutionPhase", "ExecutionPhaseSpec", "ExecutionStepIdentity", "ProvisioningCheckpoint", "ProvisioningExecutionHeader", "ProvisioningExecutionView", "ProvisioningStepEvidence", "RuntimeAttestation", "StepDisposition", "build_checkpoint", "build_execution_header", "canonical_arguments_digest", "canonical_json", "canonical_step_digest", "checkpoint_from_payload", "checkpoint_payload", "continue_execution", "derive_backup_execution_view", "execution_header_digest", "header_from_payload", "header_payload", "provisioning_checkpoint_digest", "start_execution", "verify_backup_execution_chain"]
