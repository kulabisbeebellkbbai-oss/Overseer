"""Immutable, hash-chained backup-provisioning execution contracts.

This module is deliberately limited to typed contracts, canonical digests, and
derivation of a verified execution view.  It does not invoke adapters or host
operations.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import json
import math
import re
from typing import Any, Literal


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00\Z")
_SAFE_CODE = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_SUCCESS = "ACCEPTANCE_PASSED"
_DOMAIN_STEP = "overseer.backup-provisioning.step.v1"
_DOMAIN_HEADER = "overseer.backup-provisioning.execution-header.v1"
_DOMAIN_CHECKPOINT = "overseer.backup-provisioning.checkpoint.v1"


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
    EXECUTION_FINALIZED = "execution_finalized"


def _string(value: object, label: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
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
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from error
    if parsed.tzinfo != UTC:
        raise ValueError(f"{label} must be UTC")
    return value


def _canonical_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    parsed = parsed.astimezone(UTC)
    return parsed.isoformat(timespec="microseconds" if parsed.microsecond else "seconds")


def _ordinal(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _code(value: object, label: str) -> str:
    value = _string(value, label)
    if _SAFE_CODE.fullmatch(value) is None:
        raise ValueError(f"{label} must be a stable safe code")
    return value


def _strict_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a bool")
    return value


def _tuple(value: object, label: str, *, nonempty: bool = False) -> tuple[Any, ...]:
    if not isinstance(value, tuple) or (nonempty and not value):
        raise ValueError(f"{label} must be an immutable tuple")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _hash(domain: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + _canonical(value)).encode()).hexdigest()


def _json_value(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, frozenset):
        raise ValueError("mutable or unordered values are not permitted")
    if isinstance(value, dict):
        raise ValueError("arbitrary mappings are not permitted in execution evidence")
    if hasattr(value, "__dataclass_fields__"):
        return {field.name: _json_value(getattr(value, field.name)) for field in fields(value)}
    if value is None or type(value) is str or type(value) is bool or type(value) is int:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("execution payload contains an unsupported or non-finite value")


@dataclass(frozen=True)
class ExecutionStepIdentity:
    plan_step_ordinal: int
    operation: str
    step_digest: str

    def __post_init__(self) -> None:
        _ordinal(self.plan_step_ordinal, "plan_step_ordinal")
        _string(self.operation, "operation", identifier=True)
        _digest(self.step_digest, "step_digest")


@dataclass(frozen=True)
class ExecutionPhaseSpec:
    phase_ordinal: int
    phase: ExecutionPhase
    steps: tuple[ExecutionStepIdentity, ...]

    def __post_init__(self) -> None:
        _ordinal(self.phase_ordinal, "phase_ordinal")
        if not isinstance(self.phase, ExecutionPhase):
            raise ValueError("phase must be an ExecutionPhase")
        _tuple(self.steps, "steps", nonempty=True)
        if any(not isinstance(step, ExecutionStepIdentity) for step in self.steps):
            raise ValueError("steps must contain ExecutionStepIdentity values")
        if tuple(step.plan_step_ordinal for step in self.steps) != tuple(sorted(step.plan_step_ordinal for step in self.steps)):
            raise ValueError("phase steps must be ordered by ordinal")
        if len({step.plan_step_ordinal for step in self.steps}) != len(self.steps):
            raise ValueError("phase step ordinals must be unique")
        if len({step.step_digest for step in self.steps}) != len(self.steps):
            raise ValueError("phase step digests must be unique")


@dataclass(frozen=True)
class ProvisioningExecutionHeader:
    schema_version: Literal["1"]
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
    created_at: str
    phases: tuple[ExecutionPhaseSpec, ...]
    header_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise ValueError("schema_version must be '1'")
        for name in ("execution_id", "plan_id", "bundle_id", "approval_ref", "approved_by"):
            _string(getattr(self, name), name, identifier=True)
        for name in ("plan_digest", "bundle_digest", "approval_scope_digest", "acceptance_contract_digest", "header_digest"):
            _digest(getattr(self, name), name)
        _timestamp(self.approved_at, "approved_at")
        _timestamp(self.created_at, "created_at")
        _string(self.acceptance_contract_version, "acceptance_contract_version", identifier=True)
        _tuple(self.phases, "phases", nonempty=True)
        if any(not isinstance(phase, ExecutionPhaseSpec) for phase in self.phases):
            raise ValueError("phases must contain ExecutionPhaseSpec values")
        if tuple(phase.phase_ordinal for phase in self.phases) != tuple(range(len(self.phases))):
            raise ValueError("phases must use canonical phase ordinals")
        if tuple(phase.phase for phase in self.phases) != tuple(ExecutionPhase):
            raise ValueError("phases must use canonical phase order")
        all_steps = [step for phase in self.phases for step in phase.steps]
        if len({step.plan_step_ordinal for step in all_steps}) != len(all_steps):
            raise ValueError("plan step ordinals must be globally unique")
        if self.execution_id != "execution." + self.plan_digest.removeprefix("sha256:"):
            raise ValueError("execution_id must be derived from plan_digest")
        expected = execution_header_digest(self)
        if self.header_digest != expected:
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
    passed: bool
    safe_code: str
    results_digest: str

    def __post_init__(self) -> None:
        _string(self.contract_version, "contract_version", identifier=True)
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

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, StepDisposition):
            raise ValueError("disposition must be a StepDisposition")
        _code(self.safe_code, "safe_code")
        _digest(self.result_digest, "result_digest")
        _strict_bool(self.redactions_applied, "redactions_applied")
        if not self.redactions_applied:
            raise ValueError("persisted evidence must have redactions_applied=True")


@dataclass(frozen=True)
class ProvisioningCheckpoint:
    schema_version: Literal["1"]
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
        if self.schema_version != "1":
            raise ValueError("schema_version must be '1'")
        _string(self.checkpoint_id, "checkpoint_id", identifier=True)
        _string(self.execution_id, "execution_id", identifier=True)
        _ordinal(self.checkpoint_ordinal, "checkpoint_ordinal")
        _digest(self.previous_digest, "previous_digest")
        if not isinstance(self.phase, ExecutionPhase):
            raise ValueError("phase must be an ExecutionPhase")
        _ordinal(self.phase_ordinal, "phase_ordinal")
        _ordinal(self.plan_step_ordinal, "plan_step_ordinal")
        _digest(self.step_digest, "step_digest")
        if not isinstance(self.event, CheckpointEvent):
            raise ValueError("event must be a CheckpointEvent")
        _timestamp(self.observed_at, "observed_at")
        for name, value, cls in (("step_evidence", self.step_evidence, ProvisioningStepEvidence), ("runtime_attestation", self.runtime_attestation, RuntimeAttestation), ("behavior_acceptance", self.behavior_acceptance, BehaviorAcceptance)):
            if value is not None and not isinstance(value, cls):
                raise ValueError(f"{name} has the wrong type")
        _digest(self.checkpoint_digest, "checkpoint_digest")
        if self.checkpoint_digest != provisioning_checkpoint_digest(self):
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


def canonical_step_digest(plan_digest: str, direction: str, plan_step_ordinal: int, operation: str, arguments: Any) -> str:
    """Digest a step without allowing runtime timestamps or evidence into it."""
    _digest(plan_digest, "plan_digest")
    if direction not in {"forward", "rollback"}:
        raise ValueError("direction must be forward or rollback")
    _ordinal(plan_step_ordinal, "plan_step_ordinal")
    _string(operation, "operation", identifier=True)
    try:
        normalized = _canonical_value(arguments)
        _canonical(normalized)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("arguments must be strict canonical JSON data") from error
    return _hash(_DOMAIN_STEP, {"plan_digest": plan_digest, "direction": direction, "plan_step_ordinal": plan_step_ordinal, "operation": operation, "arguments": normalized})


def _validate_canonical_arguments(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if type(key) is not str or not key:
                raise ValueError("step argument keys must be non-empty strings")
            _validate_canonical_arguments(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_canonical_arguments(child)
    elif value is not None and type(value) not in (str, int, float, bool):
        raise ValueError("step arguments contain an unsupported value")
    elif type(value) is float and not math.isfinite(value):
        raise ValueError("step arguments contain a non-finite float")


def _canonical_value(value: Any) -> Any:
    if isinstance(value, dict):
        _validate_canonical_arguments(value)
        return {key: _canonical_value(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(child) for child in value]
    if value is None or type(value) in (str, int, bool):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("unsupported canonical value")


def build_execution_header(
    *, schema_version: Literal["1"] = "1", execution_id: str, plan_id: str,
    plan_digest: str, bundle_id: str, bundle_digest: str, approval_ref: str,
    approval_scope_digest: str, approved_by: str, approved_at: str,
    acceptance_contract_version: str, acceptance_contract_digest: str,
    created_at: str, phases: tuple[ExecutionPhaseSpec, ...],
) -> ProvisioningExecutionHeader:
    """Construct a header after calculating its immutable digest."""
    approved_at = _canonical_timestamp(approved_at, "approved_at")
    created_at = _canonical_timestamp(created_at, "created_at")
    draft = object.__new__(ProvisioningExecutionHeader)
    for name, value in locals().items():
        if name != "schema_version":
            object.__setattr__(draft, name, value)
    object.__setattr__(draft, "schema_version", schema_version)
    object.__setattr__(draft, "header_digest", "")
    return ProvisioningExecutionHeader(
        schema_version, execution_id, plan_id, plan_digest, bundle_id, bundle_digest,
        approval_ref, approval_scope_digest, approved_by, approved_at,
        acceptance_contract_version, acceptance_contract_digest, created_at, phases,
        execution_header_digest(draft),
    )


def build_checkpoint(
    *, schema_version: Literal["1"] = "1", checkpoint_id: str, execution_id: str,
    checkpoint_ordinal: int, previous_digest: str, phase: ExecutionPhase,
    phase_ordinal: int, plan_step_ordinal: int, step_digest: str,
    event: CheckpointEvent, observed_at: str,
    step_evidence: ProvisioningStepEvidence | None = None,
    runtime_attestation: RuntimeAttestation | None = None,
    behavior_acceptance: BehaviorAcceptance | None = None,
) -> ProvisioningCheckpoint:
    observed_at = _canonical_timestamp(observed_at, "observed_at")
    draft = object.__new__(ProvisioningCheckpoint)
    values = locals().copy()
    values.pop("schema_version")
    values.pop("draft", None)
    for name, value in values.items():
        object.__setattr__(draft, name, value)
    object.__setattr__(draft, "schema_version", schema_version)
    object.__setattr__(draft, "checkpoint_digest", "")
    return ProvisioningCheckpoint(
        schema_version, checkpoint_id, execution_id, checkpoint_ordinal, previous_digest,
        phase, phase_ordinal, plan_step_ordinal, step_digest, event, observed_at,
        step_evidence, runtime_attestation, behavior_acceptance,
        provisioning_checkpoint_digest(draft),
    )


def _without(value: Any, field_name: str) -> dict[str, Any]:
    data = _json_value(value)
    data.pop(field_name)
    return data


def execution_header_digest(header: ProvisioningExecutionHeader) -> str:
    return _hash(_DOMAIN_HEADER, _without(header, "header_digest"))


def provisioning_checkpoint_digest(checkpoint: ProvisioningCheckpoint) -> str:
    return _hash(_DOMAIN_CHECKPOINT, _without(checkpoint, "checkpoint_digest"))


def canonical_json(value: Any) -> str:
    return _canonical(_json_value(value))


def header_payload(header: ProvisioningExecutionHeader) -> str:
    return canonical_json(header)


def checkpoint_payload(checkpoint: ProvisioningCheckpoint) -> str:
    return canonical_json(checkpoint)


def _decode(cls: type[Any], payload: str) -> Any:
    if not isinstance(payload, str):
        raise ValueError("payload must be a string")
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError, TypeError) as error:
        raise ValueError("payload must be canonical JSON") from error
    if not isinstance(value, dict) or _canonical(value) != payload:
        raise ValueError("payload must be canonical JSON")
    expected = {field.name for field in fields(cls)}
    if set(value) != expected:
        raise ValueError("payload has missing or extra fields")
    return _decode_dataclass(cls, value)


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
    try:
        if cls is ExecutionStepIdentity:
            return ExecutionStepIdentity(value["plan_step_ordinal"], value["operation"], value["step_digest"])
        if cls is ExecutionPhaseSpec:
            if type(value["steps"]) is not list:
                raise ValueError("steps must be an array")
            return ExecutionPhaseSpec(value["phase_ordinal"], ExecutionPhase(value["phase"]), tuple(_decode_dataclass(ExecutionStepIdentity, item) for item in value["steps"]))
        if cls is ProvisioningExecutionHeader:
            if type(value["phases"]) is not list:
                raise ValueError("phases must be an array")
            return ProvisioningExecutionHeader(value["schema_version"], value["execution_id"], value["plan_id"], value["plan_digest"], value["bundle_id"], value["bundle_digest"], value["approval_ref"], value["approval_scope_digest"], value["approved_by"], value["approved_at"], value["acceptance_contract_version"], value["acceptance_contract_digest"], value["created_at"], tuple(_decode_dataclass(ExecutionPhaseSpec, item) for item in value["phases"]), value["header_digest"])
        if cls is RuntimeAttestation:
            return RuntimeAttestation(**value)
        if cls is BehaviorAcceptance:
            return BehaviorAcceptance(**value)
        if cls is ProvisioningStepEvidence:
            return ProvisioningStepEvidence(StepDisposition(value["disposition"]), value["safe_code"], value["result_digest"], value["redactions_applied"])
        if cls is ProvisioningCheckpoint:
            return ProvisioningCheckpoint(value["schema_version"], value["checkpoint_id"], value["execution_id"], value["checkpoint_ordinal"], value["previous_digest"], ExecutionPhase(value["phase"]), value["phase_ordinal"], value["plan_step_ordinal"], value["step_digest"], CheckpointEvent(value["event"]), value["observed_at"], _optional(ProvisioningStepEvidence, value["step_evidence"]), _optional(RuntimeAttestation, value["runtime_attestation"]), _optional(BehaviorAcceptance, value["behavior_acceptance"]), value["checkpoint_digest"])
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        raise ValueError("payload contains an invalid typed value") from error
    raise ValueError("unsupported execution payload type")


def _optional(cls: type[Any], value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("optional value must be an object or null")
    return _decode_dataclass(cls, value)


def header_from_payload(payload: str) -> ProvisioningExecutionHeader:
    return _decode(ProvisioningExecutionHeader, payload)


def checkpoint_from_payload(payload: str) -> ProvisioningCheckpoint:
    return _decode(ProvisioningCheckpoint, payload)


def verify_backup_execution_chain(header: ProvisioningExecutionHeader, checkpoints: tuple[ProvisioningCheckpoint, ...]) -> str | None:
    if not isinstance(checkpoints, tuple):
        raise ValueError("checkpoints must be an immutable tuple")
    manifest = {(phase.phase_ordinal, step.plan_step_ordinal, step.step_digest): (phase.phase, step) for phase in header.phases for step in phase.steps}
    ordered = [(phase.phase, phase.phase_ordinal, step) for phase in header.phases for step in phase.steps]
    previous = header.header_digest
    next_forward = 0
    started: tuple[ExecutionStepIdentity, ExecutionPhase] | None = None
    completed: list[tuple[ExecutionStepIdentity, ExecutionPhase]] = []
    failure_seen = False
    rollback_next = -1
    rollback_started: tuple[ExecutionStepIdentity, ExecutionPhase] | None = None
    attestation: RuntimeAttestation | None = None
    acceptance: BehaviorAcceptance | None = None
    finalized = False
    for ordinal, checkpoint in enumerate(checkpoints):
        if checkpoint.checkpoint_ordinal != ordinal or checkpoint.execution_id != header.execution_id:
            raise ValueError("checkpoint ordinal or execution binding is invalid")
        if checkpoint.previous_digest != previous:
            raise ValueError("checkpoint digest chain is broken")
        identity = (checkpoint.phase_ordinal, checkpoint.plan_step_ordinal, checkpoint.step_digest)
        entry = manifest.get(identity)
        if entry is None or entry[0] is not checkpoint.phase:
            raise ValueError("checkpoint is not a member of the execution manifest")
        if checkpoint.phase_ordinal != list(ExecutionPhase).index(checkpoint.phase):
            raise ValueError("checkpoint phase ordinal is invalid")
        if finalized:
            raise ValueError("checkpoint follows execution finalization")
        event = checkpoint.event
        has_optional = (checkpoint.step_evidence, checkpoint.runtime_attestation, checkpoint.behavior_acceptance)
        if event is CheckpointEvent.STEP_STARTED:
            if any(value is not None for value in has_optional) or started is not None or failure_seen:
                raise ValueError("STEP_STARTED has invalid state or evidence")
            if next_forward >= len(ordered) or entry[1] is not ordered[next_forward][2] or checkpoint.phase is not ordered[next_forward][0]:
                raise ValueError("forward steps must start once in manifest order")
            started = (entry[1], checkpoint.phase)
        elif event in (CheckpointEvent.STEP_COMPLETED, CheckpointEvent.STEP_FAILED):
            if started is None or started[0] is not entry[1] or started[1] is not checkpoint.phase or checkpoint.step_evidence is None:
                raise ValueError("step outcome does not match its start")
            if checkpoint.runtime_attestation is not None and checkpoint.phase is not ExecutionPhase.ATTEST:
                raise ValueError("runtime attestation is only valid for ATTEST completion")
            if checkpoint.behavior_acceptance is not None and checkpoint.phase is not ExecutionPhase.ACCEPT:
                raise ValueError("behavior acceptance is only valid for ACCEPT completion")
            evidence = checkpoint.step_evidence
            if event is CheckpointEvent.STEP_COMPLETED:
                if evidence.disposition not in (StepDisposition.CHANGED, StepDisposition.VERIFIED_NOOP):
                    raise ValueError("successful step completion has an invalid disposition")
                if checkpoint.phase is ExecutionPhase.ATTEST:
                    if checkpoint.runtime_attestation is None or checkpoint.runtime_attestation.approved_runtime_digest != checkpoint.runtime_attestation.active_runtime_digest or checkpoint.runtime_attestation.approved_config_digest != checkpoint.runtime_attestation.active_config_digest:
                        raise ValueError("ATTEST completion lacks an exact runtime attestation")
                    attestation = checkpoint.runtime_attestation
                elif checkpoint.runtime_attestation is not None:
                    raise ValueError("runtime attestation is only valid for ATTEST completion")
                if checkpoint.phase is ExecutionPhase.ACCEPT:
                    if checkpoint.behavior_acceptance is None or checkpoint.behavior_acceptance.contract_version != header.acceptance_contract_version or not checkpoint.behavior_acceptance.passed or checkpoint.behavior_acceptance.safe_code != _SUCCESS:
                        raise ValueError("ACCEPT completion lacks passing contract acceptance")
                    acceptance = checkpoint.behavior_acceptance
                elif checkpoint.behavior_acceptance is not None:
                    raise ValueError("behavior acceptance is only valid for ACCEPT completion")
                completed.append((entry[1], checkpoint.phase))
                next_forward += 1
            else:
                if evidence.disposition is not StepDisposition.FAILED or checkpoint.runtime_attestation is not None or checkpoint.behavior_acceptance is not None:
                    raise ValueError("failed step has invalid evidence")
                failure_seen = True
                rollback_next = len(completed) - 1
            started = None
        elif event in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED):
            if not failure_seen or rollback_next < 0 or entry[1] is not completed[rollback_next][0] or checkpoint.phase is not completed[rollback_next][1]:
                raise ValueError("rollback is not the reverse of completed steps")
            if event is CheckpointEvent.ROLLBACK_STARTED:
                if rollback_started is not None or any(value is not None for value in has_optional):
                    raise ValueError("rollback start has invalid state or evidence")
                rollback_started = (entry[1], checkpoint.phase)
            else:
                if rollback_started is None or rollback_started != (entry[1], checkpoint.phase) or checkpoint.step_evidence is None:
                    raise ValueError("rollback outcome does not match its start")
                if checkpoint.runtime_attestation is not None or checkpoint.behavior_acceptance is not None:
                    raise ValueError("rollback cannot carry attestation or acceptance")
                if event is CheckpointEvent.ROLLBACK_COMPLETED:
                    if checkpoint.step_evidence.disposition not in (StepDisposition.CHANGED, StepDisposition.VERIFIED_NOOP):
                        raise ValueError("rollback completion has an invalid disposition")
                elif checkpoint.step_evidence.disposition is not StepDisposition.FAILED:
                    raise ValueError("rollback failure has an invalid disposition")
                rollback_started = None
                rollback_next -= 1
        elif event is CheckpointEvent.EXECUTION_FINALIZED:
            if any(value is not None for value in has_optional) or checkpoint.phase is not ExecutionPhase.FINALIZE or not entry[1] is header.phases[-1].steps[-1] or started is not None or failure_seen or rollback_next >= 0 or next_forward != len(ordered) or attestation is None or acceptance is None or not acceptance.passed:
                raise ValueError("execution finalization is not justified")
            finalized = True
        else:
            raise ValueError("unsupported checkpoint event")
        previous = checkpoint.checkpoint_digest
    return previous if checkpoints else None


def derive_backup_execution_view(header: ProvisioningExecutionHeader, checkpoints: tuple[ProvisioningCheckpoint, ...]) -> ProvisioningExecutionView:
    tail = verify_backup_execution_chain(header, checkpoints)
    current_phase = checkpoints[-1].phase if checkpoints else None
    failure = next((c.step_evidence.safe_code for c in reversed(checkpoints) if c.event in (CheckpointEvent.STEP_FAILED, CheckpointEvent.ROLLBACK_FAILED) and c.step_evidence), None)
    rollback = "failed" if any(c.event == CheckpointEvent.ROLLBACK_FAILED for c in checkpoints) else "completed" if any(c.event == CheckpointEvent.ROLLBACK_COMPLETED for c in checkpoints) else "started" if any(c.event == CheckpointEvent.ROLLBACK_STARTED for c in checkpoints) else "not_started"
    attestation = next((c.runtime_attestation for c in reversed(checkpoints) if c.runtime_attestation), None)
    acceptance = next((c.behavior_acceptance for c in reversed(checkpoints) if c.behavior_acceptance), None)
    tail_evidence = next((c.step_evidence for c in reversed(checkpoints) if c.step_evidence), None)
    finalized = bool(checkpoints and checkpoints[-1].event == CheckpointEvent.EXECUTION_FINALIZED and checkpoints[-1].phase is ExecutionPhase.FINALIZE)
    terminal = finalized and acceptance is not None and acceptance.passed and failure is None
    status = "succeeded" if terminal else "failed" if failure or (acceptance is not None and not acceptance.passed) else "finalized" if finalized else "in_progress" if checkpoints else "not_started"
    return ProvisioningExecutionView(header.execution_id, header.plan_id, current_phase, status, failure or (acceptance.safe_code if acceptance and not acceptance.passed else None), rollback, attestation, acceptance, tail_evidence, tail, terminal)


__all__ = [
    "BehaviorAcceptance", "CheckpointEvent", "ExecutionPhase", "ExecutionPhaseSpec",
    "ExecutionStepIdentity", "ProvisioningCheckpoint", "ProvisioningExecutionHeader",
    "ProvisioningExecutionView", "ProvisioningStepEvidence", "RuntimeAttestation",
    "StepDisposition", "build_checkpoint", "build_execution_header", "canonical_json",
    "canonical_step_digest", "checkpoint_from_payload", "checkpoint_payload",
    "derive_backup_execution_view", "execution_header_digest", "header_from_payload",
    "header_payload", "provisioning_checkpoint_digest", "verify_backup_execution_chain",
]
