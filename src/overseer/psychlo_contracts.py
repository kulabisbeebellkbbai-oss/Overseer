"""Strict, data-minimised wire contracts for the Psychlo/Overseer bridge.

The bridge intentionally keeps these contracts independent from the normal
Overseer round records.  Every payload is closed, bounded, and digestable so
that retries can compare immutable identity without retaining prompts or
application data.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import math
import re
import struct
from typing import Any, Mapping


class ContractError(ValueError):
    """Raised when a signed Psychlo payload is not an approved contract."""


ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_RE = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
MAX_ARRAY = 64
MAX_TEXT = 6_000
TELEMETRY_SCHEMA = "psychlo.telemetry.v1"
LEARNING_SCHEMA = "psychlo.learning.v1"
REGISTRY_SCHEMA = "psychlo.registry-candidate.v1"
ADOPTION_SCHEMA = "psychlo.adoption-evidence.v1"
EXTERNAL_SCHEMA = "psychlo.external-round.v1"
EXTERNAL_BINDING_SCHEMA = "psychlo.external-round-binding.v1"
TELEMETRY_KINDS = {"baseline", "completed-turn", "durable-checkpoint", "bounded-long-turn", "terminal"}
ATTRIBUTIONS = {"isolated", "shared", "censored", "unknown"}
LEARNING_DESTINATIONS = {"skiller", "private-memory"}
EVIDENCE_KINDS = {"registry", "repository", "artifact", "application", "team", "ownership", "plan", "lead", "checkpoint", "security"}
REASONS = {"registry", "canonical-repository", "repository-missing", "deployable-artifact", "artifact-missing", "application-purpose", "application-purpose-missing", "team-baseline", "active-plan", "plan-missing", "lead", "lead-missing", "checkpoint", "checkpoint-missing", "ownership", "license", "ownership-missing", "license-missing", "unsafe-files", "unsafe-modes", "symlinks", "secrets", "personal-exports", "oversized-data", "dirty-repository", "contradictory-history"}


def _canonical(value: Any) -> str:
    if isinstance(value, Mapping):
        return "{" + ",".join(json.dumps(str(k), separators=(",", ":")) + ":" + _canonical(value[k]) for k in sorted(value)) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def canonical_digest(value: Mapping[str, Any]) -> str:
    """Return SHA-256 over canonical content, ignoring a top-level digest."""
    content = {key: item for key, item in value.items() if key != "digest"}
    return hashlib.sha256(_canonical(content).encode("utf-8")).hexdigest()


def cross_project_work_request_id(link_id: str, version: str, project_id: str) -> str:
    """Match Psychlo's JSON.stringify field order for work request identity."""
    selected = {"linkId": link_id, "version": version, "projectId": project_id}
    return "cross-project-work:" + hashlib.sha256(json.dumps(selected, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def cross_project_work_request_digest(payload: Mapping[str, Any]) -> str:
    """Match Psychlo 3d178b6's selected-field work request digest exactly."""
    selected = {
        "coordinationBindingId": payload.get("coordinationBindingId"),
        "linkId": payload.get("linkId"),
        "version": payload.get("version"),
        "projectId": payload.get("projectId"),
        "leadId": payload.get("leadId"),
        "requestId": payload.get("id"),
        "requiredRequestIds": payload.get("requiredRequestIds"),
        "supervisorLeadId": payload.get("supervisorLeadId"),
        "scope": payload.get("scope"),
        "evidenceIds": payload.get("evidenceIds"),
        "expectedResultDigest": payload.get("expectedResultDigest"),
    }
    return hashlib.sha256(json.dumps(selected, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def learning_observation_digest(value: Mapping[str, Any]) -> str:
    def normalize(item: Any) -> Any:
        if isinstance(item, bool) or isinstance(item, str):
            return item
        if isinstance(item, (int, float)):
            numeric = float(item)
            if not math.isfinite(numeric):
                raise ValueError("learning observation numeric value is not finite")
            if numeric == 0:
                bits = 0
            else:
                bits = struct.unpack(">Q", struct.pack(">d", numeric))[0]
            return {"$f64": f"{bits:016x}"}
        if isinstance(item, Mapping):
            return {key: normalize(item[key]) for key in sorted(item, key=lambda key: str(key).encode("ascii"))}
        raise ValueError("learning observation digest value is invalid")

    content = normalize({"id": value["id"], "featureProfile": value["featureProfile"], "outcome": value["outcome"]})
    return hashlib.sha256(json.dumps(content, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def learning_observation_legacy_selected_digest(value: Mapping[str, Any]) -> str:
    """Digest used by the pre-60abc40 selected-field wire contract."""
    content = {"id": value["id"], "featureProfile": dict(sorted(value["featureProfile"].items())), "outcome": dict(sorted(value["outcome"].items()))}
    return hashlib.sha256(_canonical(content).encode("utf-8")).hexdigest()


def _object(value: Any, *, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{name} must be an object")
    return dict(value)


def _keys(value: Mapping[str, Any], allowed: set[str], *, name: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ContractError(f"{name} contains unknown fields")


def _id(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise ContractError(f"{name} is invalid")
    return value


def _text(value: Any, *, name: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ContractError(f"{name} is invalid")
    return value


def _digest(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractError(f"{name} is invalid")
    return value


def _timestamp(value: Any, *, name: str = "occurredAt") -> str:
    if not isinstance(value, str):
        raise ContractError(f"{name} is invalid")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractError(f"{name} is invalid") from error
    return value


def _array(value: Any, *, name: str, item: str = "id") -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_ARRAY:
        raise ContractError(f"{name} is invalid")
    return [_id(item_value, name=f"{name} item") if item == "id" else _text(item_value, name=f"{name} item") for item_value in value]


def _common(value: Mapping[str, Any], *, schema: str, required: set[str], name: str, allowed: set[str] | None = None) -> None:
    if not required.issubset(value):
        raise ContractError(f"{name} is missing required fields")
    _keys(value, allowed or required, name=name)
    if value.get("sourceId") != "overseer":
        raise ContractError(f"{name} source is invalid")
    _id(value.get("correlationId"), name="correlationId")
    _id(value.get("idempotencyKey"), name="idempotencyKey")
    _timestamp(value.get("occurredAt"))
    if value.get("schemaVersion") != schema:
        raise ContractError(f"{name} schema version is invalid")


def parse_telemetry_checkpoint(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, name="telemetry checkpoint")
    required = {"checkpointId", "projectId", "planId", "roundId", "threadId", "model", "featureClass", "sampleKind", "cumulative", "activeMs", "waitingMs", "sourceId", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion"}
    optional = {"providerSnapshotId", "providerCapturedAt", "attribution"}
    _common(value, schema=TELEMETRY_SCHEMA, required=required, allowed=required | optional, name="telemetry checkpoint")
    for field in ("checkpointId", "projectId", "planId", "roundId", "threadId", "model", "featureClass"):
        _id(value[field], name=field)
    if value["sampleKind"] not in TELEMETRY_KINDS:
        raise ContractError("sampleKind is invalid")
    counters = _object(value["cumulative"], name="cumulative")
    _keys(counters, {"cachedInput", "uncachedInput", "output", "reasoning", "total"}, name="cumulative")
    if any(not isinstance(counters[key], int) or isinstance(counters[key], bool) or counters[key] < 0 for key in counters):
        raise ContractError("cumulative counters are invalid")
    if sum(counters[key] for key in ("cachedInput", "uncachedInput", "output", "reasoning")) != counters["total"]:
        raise ContractError("cumulative total is invalid")
    for field in ("activeMs", "waitingMs"):
        if not isinstance(value[field], int) or isinstance(value[field], bool) or value[field] < 0:
            raise ContractError(f"{field} is invalid")
    if "providerSnapshotId" in value:
        _id(value["providerSnapshotId"], name="providerSnapshotId")
    if "providerCapturedAt" in value:
        _timestamp(value["providerCapturedAt"], name="providerCapturedAt")
    if "attribution" in value and value["attribution"] not in ATTRIBUTIONS:
        raise ContractError("attribution is invalid")
    return value


def parse_learning_observation(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, name="learning observation")
    required = {"id", "featureProfile", "outcome", "sourceId", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion"}
    _common(value, schema=LEARNING_SCHEMA, required=required, name="learning observation")
    if not isinstance(value["id"], str) or not re.fullmatch(r"observation-(?:[0-9]+|[a-f0-9]{32})", value["id"]):
        raise ContractError("learning observation id is invalid")
    profile = _object(value["featureProfile"], name="featureProfile")
    outcome = _object(value["outcome"], name="outcome")
    allowed_profile = {"taskClass", "projectClass", "dependencyClass", "expectedComponents", "buildGate", "testGate", "browserGate", "securityGate", "deploymentGate", "model", "executionPattern", "similarityClass", "attribution", "sampleKind"}
    allowed_outcome = {"usage", "actualUsage", "remainingUsage", "activeMs", "waitingMs", "status", "observedAt", "policyVersion", "censored"}
    _keys(profile, allowed_profile, name="featureProfile")
    _keys(outcome, allowed_outcome, name="outcome")
    if "taskClass" in profile and (not isinstance(profile["taskClass"], str) or profile["taskClass"] not in {"typescript-feature", "javascript-feature", "python-feature", "rust-feature", "go-feature", "java-feature", "kotlin-feature", "swift-feature", "cpp-feature", "csharp-feature", "round-result", "unknown"}):
        raise ContractError("taskClass is invalid")
    if "model" in profile and (not isinstance(profile["model"], str) or profile["model"] not in {"gpt-5", "gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol"}):
        raise ContractError("model is invalid")
    if "expectedComponents" in profile and (not isinstance(profile["expectedComponents"], int) or isinstance(profile["expectedComponents"], bool) or profile["expectedComponents"] < 0 or profile["expectedComponents"] > 100):
        raise ContractError("expectedComponents is invalid")
    enum_values = {"attribution": ATTRIBUTIONS, "sampleKind": TELEMETRY_KINDS}
    identifier_values = {"projectClass": {"frontend", "backend", "fullstack", "library", "service", "cli", "unknown"}, "dependencyClass": {"none", "direct", "transitive", "unknown"}, "executionPattern": {"single-round", "multi-round", "bounded", "unknown"}, "similarityClass": {"exact", "near", "none", "unknown"}}
    for key, values in enum_values.items():
        if key in profile and (not isinstance(profile[key], str) or profile[key] not in values):
            raise ContractError(f"{key} is invalid")
    for key, values in identifier_values.items():
        if key in profile and (not isinstance(profile[key], str) or profile[key] not in values):
            raise ContractError(f"{key} is invalid")
    for key in {"buildGate", "testGate", "browserGate", "securityGate", "deploymentGate"}:
        if key in profile and not isinstance(profile[key], bool):
            raise ContractError(f"{key} is invalid")
    if "status" in outcome and outcome["status"] not in {"completed", "blocked"}:
        raise ContractError("status is invalid")
    if "observedAt" in outcome:
        _timestamp(outcome["observedAt"], name="observedAt")
    for key in {"usage", "actualUsage", "remainingUsage"}:
        try:
            finite = math.isfinite(float(outcome[key])) if key in outcome else True
        except (OverflowError, TypeError, ValueError):
            finite = False
        if key in outcome and (not isinstance(outcome[key], (int, float)) or isinstance(outcome[key], bool) or not finite or outcome[key] < 0):
            raise ContractError(f"{key} is invalid")
    for key in {"activeMs", "waitingMs"}:
        if key in outcome and (not isinstance(outcome[key], int) or isinstance(outcome[key], bool) or outcome[key] < 0):
            raise ContractError(f"{key} is invalid")
    if "policyVersion" in outcome and outcome["policyVersion"] != "psychlo-estimate-v1":
        raise ContractError("policyVersion is invalid")
    if "censored" in outcome and outcome["censored"] not in {"true", "false"}:
        raise ContractError("censored is invalid")
    return value


def parse_learning_advisory(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, name="learning advisory")
    _keys(value, {"source", "version", "digest", "confidence", "evidenceLineage", "featureClass", "expectedUsage", "signatureValid", "compatible", "observedAt"}, name="learning advisory")
    if value.get("source") not in {"skiller", "private-memory"} or value.get("version") != "psychlo-estimate-v1" or value.get("signatureValid") is not True:
        raise ContractError("learning advisory identity is invalid")
    _digest(value.get("digest"), name="advisory digest")
    if not isinstance(value.get("confidence"), (int, float)) or isinstance(value.get("confidence"), bool) or not 0 <= value["confidence"] <= 1:
        raise ContractError("advisory confidence is invalid")
    lineage = value.get("evidenceLineage")
    if not isinstance(lineage, list) or not lineage or len(lineage) > MAX_ARRAY or any(not isinstance(item, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", item) for item in lineage):
        raise ContractError("advisory evidence lineage is invalid")
    if value.get("featureClass") not in {"typescript-feature", "javascript-feature", "python-feature", "rust-feature", "go-feature", "java-feature", "kotlin-feature", "swift-feature", "cpp-feature", "csharp-feature", "round-result", "unknown"}:
        raise ContractError("advisory feature class is invalid")
    if not isinstance(value.get("expectedUsage"), (int, float)) or isinstance(value["expectedUsage"], bool) or value["expectedUsage"] < 0:
        raise ContractError("advisory expected usage is invalid")
    _timestamp(value.get("observedAt"), name="observedAt")
    if "compatible" in value and not isinstance(value["compatible"], bool):
        raise ContractError("advisory compatibility is invalid")
    return value


def parse_registry_candidate(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, name="registry candidate")
    required = {"candidateId", "targetProjectId", "registryId", "registryDigest", "evidenceIds", "evidenceDigests", "evidenceKinds", "canonical", "sourceId", "messageId", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion"}
    _common(value, schema=REGISTRY_SCHEMA, required=required, name="registry candidate")
    for field in ("candidateId", "targetProjectId", "registryId", "messageId"):
        _id(value[field], name=field)
    _digest(value["registryDigest"], name="registryDigest")
    ids = _array(value["evidenceIds"], name="evidenceIds")
    digests = value["evidenceDigests"]
    kinds = value["evidenceKinds"]
    if not ids or not isinstance(digests, list) or not isinstance(kinds, list) or len(ids) != len(digests) or len(ids) != len(kinds) or len(ids) > MAX_ARRAY:
        raise ContractError("registry evidence arrays are invalid")
    for item in digests:
        _digest(item, name="evidence digest")
    if any(item not in EVIDENCE_KINDS for item in kinds) or value["canonical"] is not True:
        raise ContractError("registry candidate evidence is invalid")
    return value


def parse_adoption_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, name="adoption evidence")
    required = {"candidateId", "registry", "evidence", "sourceId", "messageId", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion"}
    _common(value, schema=ADOPTION_SCHEMA, required=required, name="adoption evidence")
    _id(value["candidateId"], name="candidateId")
    registry = _object(value["registry"], name="registry")
    _keys(registry, {"registryId", "registryDigest", "evidenceIds", "canonical"}, name="registry")
    _id(registry.get("registryId"), name="registryId")
    _digest(registry.get("registryDigest"), name="registryDigest")
    if registry.get("canonical") is not True:
        raise ContractError("registry is not canonical")
    refs = value["evidence"]
    if not isinstance(refs, list) or not refs or len(refs) > MAX_ARRAY:
        raise ContractError("adoption evidence references are invalid")
    for ref in refs:
        item = _object(ref, name="evidence reference")
        _keys(item, {"reason", "kind", "evidenceId", "digest"}, name="evidence reference")
        if item.get("reason") not in REASONS or item.get("kind") not in EVIDENCE_KINDS:
            raise ContractError("evidence reference is invalid")
        _id(item.get("evidenceId"), name="evidenceId")
        _digest(item.get("digest"), name="evidence digest")
    return value


def parse_external_round(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, name="external round")
    required = {"reconciliationId", "externalExecutionId", "projectId", "aTeamId", "planId", "planVersion", "projectLeadId", "threadId", "repository", "startingCheckpoint", "terminalCheckpoint", "terminalStatus", "deliveredScope", "remainingWork", "blockers", "evidenceIds", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion", "digest"}
    optional = {"explicitGate"}
    _keys(value, required | optional, name="external round")
    for field in ("reconciliationId", "externalExecutionId", "projectId", "aTeamId", "planId", "planVersion", "projectLeadId", "threadId", "startingCheckpoint", "terminalCheckpoint", "correlationId", "idempotencyKey"):
        _id(value.get(field), name=field)
    repo = _object(value.get("repository"), name="repository")
    _keys(repo, {"pathIdentity", "beforeHead", "afterHead", "dirtyDigest"}, name="repository")
    _text(repo.get("pathIdentity"), name="pathIdentity", maximum=2_048)
    if not GIT_RE.fullmatch(str(repo.get("beforeHead"))) or not GIT_RE.fullmatch(str(repo.get("afterHead"))):
        raise ContractError("repository heads are invalid")
    _digest(repo.get("dirtyDigest"), name="dirtyDigest")
    if value.get("terminalStatus") not in {"completed", "blocked"} or value["terminalStatus"] == "blocked" and not value["blockers"]:
        raise ContractError("terminal status is invalid")
    _text(value.get("deliveredScope"), name="deliveredScope")
    _text(value.get("remainingWork"), name="remainingWork")
    _array(value.get("blockers"), name="blockers", item="text")
    if value.get("explicitGate") is not None:
        _text(value["explicitGate"], name="explicitGate")
        if value["terminalStatus"] != "blocked":
            raise ContractError("explicit gate requires blocked result")
    _array(value.get("evidenceIds"), name="evidenceIds")
    _timestamp(value.get("occurredAt"))
    if value.get("schemaVersion") != EXTERNAL_SCHEMA or canonical_digest(value) != value.get("digest"):
        raise ContractError("external round digest or schema is invalid")
    return value


def _strict_protocol(value: Any, *, required: set[str], name: str, schema: str | None = None, allowed: set[str] | None = None) -> dict[str, Any]:
    result = _object(value, name=name)
    _keys(result, allowed or required, name=name)
    if schema is not None and result.get("schemaVersion") != schema:
        raise ContractError(f"{name} schema version is invalid")
    for field in ("correlationId", "idempotencyKey", "occurredAt"):
        if field in required:
            _id(result.get(field), name=field) if field != "occurredAt" else _timestamp(result.get(field))
    return result


def parse_external_round_binding(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {"authorizationId", "externalExecutionId", "reconciliationId", "projectId", "aTeamId", "planId", "planVersion", "projectLeadId", "threadId", "repository", "startingCheckpoint", "terminalCheckpoint", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion", "digest"}
    value = _strict_protocol(payload, required=required, name="external round binding", schema=EXTERNAL_BINDING_SCHEMA)
    for field in required - {"repository", "occurredAt", "schemaVersion", "digest"}:
        _id(value[field], name=field)
    _digest(value["digest"], name="digest")
    repository = _object(value["repository"], name="repository")
    _keys(repository, {"pathIdentity", "beforeHead", "afterHead", "dirtyDigest"}, name="repository")
    _text(repository["pathIdentity"], name="pathIdentity", maximum=2048)
    for field in ("beforeHead", "afterHead"):
        if not isinstance(repository[field], str) or not GIT_RE.fullmatch(repository[field]): raise ContractError(f"{field} is invalid")
    _digest(repository["dirtyDigest"], name="dirtyDigest")
    if canonical_digest({key: value[key] for key in value if key != "digest"}) != value["digest"]:
        raise ContractError("external round binding digest mismatch")
    return value


def parse_ingress_conflict_reconciliation(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {"sourceId", "scope", "ingressSourceId", "ingressIdempotencyKey", "correlationId", "idempotencyKey", "occurredAt", "provenanceId", "status", "ingressType"}
    value = _strict_protocol(payload, required=required, allowed=required | {"projectId"}, name="ingress conflict reconciliation")
    if value["sourceId"] != "overseer" or value["scope"] not in {"project", "global"} or value["status"] != "resolved": raise ContractError("ingress reconciliation identity is invalid")
    if value["scope"] == "project":
        if "projectId" not in value: raise ContractError("projectId is required")
        _id(value.get("projectId"), name="projectId")
    elif "projectId" in value: raise ContractError("global reconciliation must not bind a project")
    for field in ("ingressSourceId", "ingressIdempotencyKey", "provenanceId", "ingressType"): _id(value[field], name=field)
    if value["ingressType"] not in {"plan.admitted", "plan.changed", "project.decommissioned", "project.takeover-imported", "project.scheduling-input-recorded", "overseer.usage-snapshot", "handoff.receipt-recorded", "external-round-binding-authorized", "external-round-reconciled", "cross-project.team-binding-authorized", "coordinator.concurrency-canary-authorized", "coordinator.concurrency-ceiling-authorized"}: raise ContractError("ingress type is invalid")
    return value


def parse_concurrency_canary_result(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact Psychlo-derived successful canary result contract."""
    value = _object(payload, name="concurrency canary result")
    required = {"resultId", "authorizationId", "targetCeiling", "expectedRevision", "executions", "concurrencyObserved", "occurredAt", "digest"}
    _keys(value, required, name="concurrency canary result")
    for field in ("resultId", "authorizationId"):
        _id(value.get(field), name=field)
    if value.get("resultId") != f"canary-result:{value.get('authorizationId')}" or value.get("targetCeiling") != 2 or value.get("concurrencyObserved") is not True:
        raise ContractError("canary result identity is invalid")
    if not isinstance(value.get("expectedRevision"), int) or isinstance(value["expectedRevision"], bool) or value["expectedRevision"] < 0:
        raise ContractError("canary result revision is invalid")
    _timestamp(value.get("occurredAt"), name="occurredAt")
    _digest(value.get("digest"), name="digest")
    executions = value.get("executions")
    if not isinstance(executions, list) or len(executions) != 2:
        raise ContractError("canary result executions are invalid")
    for execution in executions:
        item = _object(execution, name="canary execution")
        _keys(item, {"executionId", "started", "completed"}, name="canary execution")
        _id(item.get("executionId"), name="executionId")
        started = _object(item.get("started"), name="canary execution start")
        completed = _object(item.get("completed"), name="canary execution completion")
        start_required = {"executionId", "authorizationId", "projectId", "planId", "planVersion", "roundId", "leadId", "startedAt", "digest"}
        completion_required = {"executionId", "authorizationId", "projectId", "planId", "planVersion", "roundId", "leadId", "settledAt", "terminalStatus", "resultDigest", "evidenceId", "evidenceDigest", "digest"}
        _keys(started, start_required, name="canary execution start")
        _keys(completed, completion_required, name="canary execution completion")
        for field in ("executionId", "authorizationId", "projectId", "planId", "planVersion", "roundId", "leadId"):
            _id(started.get(field), name=field)
            _id(completed.get(field), name=field)
        if started["executionId"] != item["executionId"] or completed["executionId"] != item["executionId"] or started["roundId"] != completed["roundId"]:
            raise ContractError("canary execution binding is invalid")
        if started["authorizationId"] != value["authorizationId"] or completed["authorizationId"] != value["authorizationId"] or started["projectId"] == completed["projectId"] and False:
            raise ContractError("canary execution authorization is invalid")
        _timestamp(started["startedAt"], name="startedAt"); _timestamp(completed["settledAt"], name="settledAt")
        if completed["terminalStatus"] != "completed":
            raise ContractError("canary execution was not successful")
        for field in ("resultDigest", "evidenceDigest", "digest"):
            _digest(completed[field], name=field)
        _id(completed["evidenceId"], name="evidenceId"); _digest(started["digest"], name="digest")
        start_base = {key: started[key] for key in ("executionId", "authorizationId", "projectId", "planId", "planVersion", "roundId", "leadId", "startedAt")}
        completed_base = {key: completed[key] for key in ("executionId", "authorizationId", "projectId", "planId", "planVersion", "roundId", "leadId", "settledAt", "terminalStatus", "resultDigest", "evidenceId", "evidenceDigest")}
        if hashlib.sha256(json.dumps(start_base, separators=(",", ":")).encode()).hexdigest() != started["digest"] or hashlib.sha256(json.dumps(completed_base, separators=(",", ":")).encode()).hexdigest() != completed["digest"]:
            raise ContractError("canary execution digest mismatch")
    first, second = executions
    if first["executionId"] == second["executionId"] or first["started"]["projectId"] == second["started"]["projectId"]:
        raise ContractError("canary executions must be distinct projects")
    first_start = datetime.fromisoformat(first["started"]["startedAt"].replace("Z", "+00:00"))
    second_start = datetime.fromisoformat(second["started"]["startedAt"].replace("Z", "+00:00"))
    first_end = datetime.fromisoformat(first["completed"]["settledAt"].replace("Z", "+00:00"))
    second_end = datetime.fromisoformat(second["completed"]["settledAt"].replace("Z", "+00:00"))
    occurred = datetime.fromisoformat(value["occurredAt"].replace("Z", "+00:00"))
    if not (first_start < second_end and second_start < first_end) or first_end > occurred or second_end > occurred:
        raise ContractError("canary executions do not prove overlap")
    result_base = {key: value[key] for key in ("resultId", "authorizationId", "targetCeiling", "expectedRevision", "executions", "concurrencyObserved", "occurredAt")}
    if hashlib.sha256(json.dumps(result_base, separators=(",", ":")).encode()).hexdigest() != value["digest"]:
        raise ContractError("canary result digest mismatch")
    return value


def parse_concurrency_ceiling_authorization(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {"authorizationId", "ceiling", "expectedRevision", "revision", "canaryResultId", "projectId", "planId", "workflowId", "decisionVersion", "decisionId", "question", "correlationId", "idempotencyKey", "occurredAt", "digest"}
    value = _strict_protocol(payload, required=required, name="concurrency ceiling authorization")
    for field in required - {"ceiling", "expectedRevision", "revision", "occurredAt", "digest", "question"}:
        _id(value.get(field), name=field)
    _text(value["question"], name="question")
    for field in ("ceiling", "expectedRevision", "revision"):
        if not isinstance(value.get(field), int) or isinstance(value[field], bool) or value[field] < 0:
            raise ContractError(f"{field} is invalid")
    if value["ceiling"] < 1 or value["revision"] != value["expectedRevision"] + 1:
        raise ContractError("concurrency ceiling revision is invalid")
    _timestamp(value["occurredAt"]); _digest(value["digest"], name="digest")
    if value["decisionId"] != f"roadex:concurrency:{value['authorizationId']}" or value["question"] != f"Approve the exact global concurrency operation {value['digest']}":
        raise ContractError("concurrency ceiling decision binding is invalid")
    base = {key: value[key] for key in ("authorizationId", "ceiling", "expectedRevision", "revision", "canaryResultId", "projectId", "planId", "workflowId", "decisionVersion", "correlationId", "idempotencyKey", "occurredAt")}
    if hashlib.sha256(json.dumps(base, separators=(",", ":")).encode()).hexdigest() != value["digest"]:
        raise ContractError("concurrency ceiling digest mismatch")
    return value


def parse_cross_project_team_binding(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {"bindingId", "coordinationTeamId", "supervisorMemberId", "supervisorLeadId", "approvalId", "approvalProvenanceId", "approvedAt", "correlationId", "idempotencyKey", "occurredAt", "digest"}
    value = _strict_protocol(payload, required=required, name="cross-project team binding")
    for field in required - {"approvedAt", "occurredAt", "digest"}: _id(value[field], name=field)
    _timestamp(value["approvedAt"], name="approvedAt"); _digest(value["digest"], name="digest")
    if datetime.fromisoformat(value["approvedAt"].replace("Z", "+00:00")) > datetime.fromisoformat(value["occurredAt"].replace("Z", "+00:00")): raise ContractError("team binding approval is postdated")
    ordered = {key: value[key] for key in ("bindingId", "coordinationTeamId", "supervisorMemberId", "supervisorLeadId", "approvalId", "approvalProvenanceId", "approvedAt", "correlationId", "idempotencyKey", "occurredAt")}
    if hashlib.sha256(json.dumps(ordered, separators=(",", ":")).encode()).hexdigest() != value["digest"]: raise ContractError("team binding digest mismatch")
    return value


def parse_cross_project_work(payload: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
    required = {"operation", "input", "bindingId", "coordinationTeamId", "supervisorMemberId", "supervisorLeadId", "correlationId", "idempotencyKey", "occurredAt", "digest"}
    value = _strict_protocol(payload, required=required, name=f"cross-project {kind}")
    if value["operation"] not in {"work-request", "propose", "approve", "validate", "retire", "reuse", "participant-result", "supervisor-review"}: raise ContractError("cross-project operation is invalid")
    for field in ("bindingId", "coordinationTeamId", "supervisorMemberId", "supervisorLeadId"): _id(value[field], name=field)
    if not isinstance(value["input"], Mapping) or isinstance(value["input"], list): raise ContractError("cross-project input is invalid")
    _digest(value["digest"], name="digest")
    return value


def parse_cross_project_supervisor_review(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {"projectId", "leadId", "supervisorLeadId", "decision", "evidenceId", "linkId", "version", "reviewId", "resultId", "participantResults", "coordinationTeamId", "supervisorMemberId", "accepted", "evidence", "digest", "correlationId", "idempotencyKey", "occurredAt"}
    value = _strict_protocol(payload, required=required, name="cross-project supervisor review")
    if not required.issubset(value): raise ContractError("cross-project supervisor review is missing required fields")
    for field in ("projectId", "leadId", "supervisorLeadId", "linkId", "version", "reviewId", "resultId", "coordinationTeamId", "supervisorMemberId", "correlationId", "idempotencyKey", "evidenceId"):
        _id(value[field], name=field)
    if value["decision"] not in {"accepted", "rejected"} or value["decision"] != ("accepted" if value["accepted"] else "rejected"):
        raise ContractError("supervisor review decision is invalid")
    if not isinstance(value["accepted"], bool):
        raise ContractError("supervisor review acceptance is invalid")
    if not isinstance(value["participantResults"], list) or not value["participantResults"]:
        raise ContractError("supervisor review participants are required")
    for participant in value["participantResults"]:
        item = _object(participant, name="supervisor participant result")
        _keys(item, {"resultId", "digest"}, name="supervisor participant result")
        _id(item["resultId"], name="participant resultId"); _digest(item["digest"], name="participant digest")
    if not isinstance(value["evidence"], list) or not value["evidence"] or any(not isinstance(item, str) or not item.strip() for item in value["evidence"]):
        raise ContractError("supervisor review evidence is required")
    _timestamp(value["occurredAt"]); _digest(value["digest"], name="digest")
    base = {key: value[key] for key in ("projectId", "leadId", "supervisorLeadId", "decision", "evidenceId", "linkId", "version", "reviewId", "resultId", "participantResults", "coordinationTeamId", "supervisorMemberId", "accepted", "evidence", "correlationId", "idempotencyKey", "occurredAt")}
    if canonical_digest(base) != value["digest"]:
        raise ContractError("supervisor review digest mismatch")
    return value


def parse_canary_authorization(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {"authorizationId", "targetTemporaryCeiling", "expectedGlobalCeiling", "expectedRevision", "projects", "workflowId", "decisionVersion", "decisionId", "question", "deadline", "correlationId", "idempotencyKey", "occurredAt", "digest"}
    value = _strict_protocol(payload, required=required, name="concurrency canary authorization")
    if value["targetTemporaryCeiling"] != 2 or value["expectedGlobalCeiling"] != 1 or not isinstance(value["expectedRevision"], int) or isinstance(value["expectedRevision"], bool) or value["expectedRevision"] < 0: raise ContractError("canary authorization ceiling is invalid")
    if not isinstance(value["projects"], list) or len(value["projects"]) != 2: raise ContractError("canary requires two projects")
    for project in value["projects"]:
        item = _object(project, name="canary project"); _keys(item, {"projectId", "planId", "planVersion", "leadId"}, name="canary project")
        for field in item: _id(item[field], name=field)
    if value["projects"][0]["projectId"] == value["projects"][1]["projectId"]: raise ContractError("canary projects must differ")
    _id(value["authorizationId"], name="authorizationId"); _id(value["workflowId"], name="workflowId"); _id(value["decisionVersion"], name="decisionVersion"); _id(value["decisionId"], name="decisionId"); _text(value["question"], name="question"); _timestamp(value["deadline"], name="deadline"); _digest(value["digest"], name="digest")
    if value["decisionId"] != f"roadex:concurrency-canary:{value['authorizationId']}" or value["question"] != f"Approve the exact live concurrency canary {value['digest']}" or datetime.fromisoformat(value["deadline"].replace("Z", "+00:00")) <= datetime.fromisoformat(value["occurredAt"].replace("Z", "+00:00")): raise ContractError("canary authorization binding is invalid")
    base = {key: value[key] for key in ("authorizationId", "targetTemporaryCeiling", "expectedGlobalCeiling", "expectedRevision", "projects", "workflowId", "decisionVersion", "deadline", "correlationId", "idempotencyKey", "occurredAt")}
    if hashlib.sha256(json.dumps(base, separators=(",", ":")).encode()).hexdigest() != value["digest"]: raise ContractError("canary authorization digest mismatch")
    return value
