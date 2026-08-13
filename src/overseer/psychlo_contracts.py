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
HANDOFF_VERSIONS = {"a-team.psychlo.handoff.v1", "a-team.psychlo.handoff.v2"}
HANDOFF_RECEIPT_VERSION = "a-team.psychlo.receipt.v1"
TELEMETRY_KINDS = {"baseline", "completed-turn", "durable-checkpoint", "bounded-long-turn", "terminal"}
ATTRIBUTIONS = {"isolated", "shared", "censored", "unknown"}
LEARNING_DESTINATIONS = {"skiller", "private-memory"}
EVIDENCE_KINDS = {"registry", "repository", "artifact", "application", "team", "ownership", "plan", "lead", "checkpoint", "security"}
REASONS = {"registry", "canonical-repository", "repository-missing", "deployable-artifact", "artifact-missing", "application-purpose", "application-purpose-missing", "team-baseline", "active-plan", "plan-missing", "lead", "lead-missing", "checkpoint", "checkpoint-missing", "ownership", "license", "ownership-missing", "license-missing", "unsafe-files", "unsafe-modes", "symlinks", "secrets", "personal-exports", "oversized-data", "dirty-repository", "contradictory-history"}
APPLICATION_PURPOSES = {"service", "application", "library", "cli", "web"}
LICENSE_KINDS = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "GPL-3.0", "proprietary"}
SECURITY_REASONS = {"unsafe-files", "unsafe-modes", "symlinks", "secrets", "personal-exports", "oversized-data"}
POLICY_EXCEPTION_REQUEST_SCHEMA = "psychlo.policy-exception-request.v1"
POLICY_EXCEPTION_OUTCOME_SCHEMA = "psychlo.policy-exception-outcome.v1"
POLICY_EXCEPTION_AUTHORIZATION_SCHEMA = "psychlo.policy-exception-authorization.v1"
POLICY_EXCEPTION_RULES = {
    "reset-daily-at-provider-reset", "count-other-development", "enforce-provider-quota",
    "enforce-safety-reserve", "respect-blackouts", "carry-unused-daily-allowance",
    "pause-after-failures", "require-manual-resume", "enforce-project-share",
}
USAGE_SNAPSHOT_V11_SCHEMA = "psychlo.usage-snapshot.v1.1"
USAGE_ENVELOPE_V11_SCHEMA = "psychlo.usage-envelope.v1.1"


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


def _policy_exception_f64_tag(value: Any, *, name: str) -> dict[str, str]:
    """Return the exact cross-language digest representation for one number."""
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise ContractError(f"{name} must be a finite binary64 number") from error
    if not math.isfinite(number):
        raise ContractError(f"{name} must be a finite binary64 number")
    bits = 0 if number == 0 else struct.unpack(">Q", struct.pack(">d", number))[0]
    return {"$f64": f"{bits:016x}"}


def _policy_exception_digest(value: Mapping[str, Any]) -> str:
    """Digest an exception while tagging only its requestedValue number."""
    content = {key: item for key, item in value.items() if key != "digest"}
    requested = content.get("requestedValue")
    if "requestedValue" in content and not isinstance(requested, bool):
        if not isinstance(requested, (int, float)):
            raise ContractError("policy exception requested value must be boolean or finite number")
        content["requestedValue"] = _policy_exception_f64_tag(requested, name="policy exception requested value")
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


def parse_project_registration(payload: Mapping[str, Any]) -> dict[str, Any]:
    registration = _object(payload, name="project registration")
    if set(registration) != {"envelope", "receipt"}:
        raise ContractError("project registration fields are invalid")
    envelope = _object(registration["envelope"], name="handoff envelope")
    version = envelope.get("contractVersion")
    base = {"contractVersion", "source", "aTeamId", "approval", "project", "projectLead", "plan", "correlationId", "idempotencyKey", "occurredAt", "digest"}
    if version not in HANDOFF_VERSIONS or set(envelope) != (base | ({"lifecycle"} if version.endswith(".v2") else set())) or envelope.get("source") != "a-team":
        raise ContractError("handoff envelope contract is invalid")
    _id(envelope.get("aTeamId"), name="aTeamId"); _id(envelope.get("correlationId"), name="correlationId"); _id(envelope.get("idempotencyKey"), name="idempotencyKey")
    _offset_timestamp(envelope.get("occurredAt"), name="occurredAt")
    approval = _object(envelope.get("approval"), name="handoff approval")
    if set(approval) != {"status", "approvedAt"} or approval.get("status") != "approved": raise ContractError("handoff approval is invalid")
    _offset_timestamp(approval.get("approvedAt"), name="approvedAt")
    project = _object(envelope.get("project"), name="handoff project")
    if set(project) != {"id", "planId", "planVersion", "provenancePath"}: raise ContractError("handoff project is invalid")
    for field in ("id", "planId", "planVersion"): _id(project.get(field), name=field)
    path = project.get("provenancePath")
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path or path != path.strip() or len(path) > 2_048: raise ContractError("handoff provenance path is invalid")
    lead = _object(envelope.get("projectLead"), name="handoff lead")
    if set(lead) != {"id"}: raise ContractError("handoff lead is invalid")
    _id(lead.get("id"), name="projectLead.id")
    plan = _object(envelope.get("plan"), name="handoff plan")
    if set(plan) != {"title", "summary", "goals", "constraints", "deliverables", "tasks"}: raise ContractError("handoff plan is invalid")
    _text(plan.get("title"), name="plan title", maximum=160); _text(plan.get("summary"), name="plan summary")
    for field in ("goals", "constraints", "deliverables"):
        values = plan.get(field)
        if not isinstance(values, list) or len(values) > 32: raise ContractError(f"plan {field} is invalid")
        for item in values: _text(item, name=f"plan {field} item")
    tasks = plan.get("tasks")
    if not isinstance(tasks, list) or not 0 < len(tasks) <= 128: raise ContractError("handoff tasks are invalid")
    task_ids: set[str] = set(); dependencies: dict[str, list[str]] = {}
    for raw in tasks:
        task = _object(raw, name="handoff task")
        if set(task) != {"id", "ownerMemberId", "title", "description", "dependencyIds", "acceptanceCriteria"}: raise ContractError("handoff task is invalid")
        task_id = _id(task.get("id"), name="task id")
        if task_id in task_ids: raise ContractError("handoff task ID is duplicated")
        task_ids.add(task_id); _id(task.get("ownerMemberId"), name="task owner"); _text(task.get("title"), name="task title", maximum=160); _text(task.get("description"), name="task description")
        dependencies[task_id] = _bounded_id_array(task.get("dependencyIds"), name="task dependencies", maximum=32)
        criteria = task.get("acceptanceCriteria")
        if not isinstance(criteria, list) or len(criteria) > 32: raise ContractError("task acceptance criteria are invalid")
        for item in criteria: _text(item, name="task acceptance criterion")
    _validate_task_graph(task_ids, dependencies)
    if version.endswith(".v2"): _parse_handoff_lifecycle(envelope.get("lifecycle"), project, lead["id"])
    _digest(envelope.get("digest"), name="handoff digest")
    if canonical_digest(envelope) != envelope["digest"]: raise ContractError("handoff envelope digest does not match canonical content")
    receipt = _object(registration["receipt"], name="handoff receipt")
    receipt_keys = {"contractVersion", "handoffContractVersion", "source", "status", "receiptId", "aTeamId", "project", "correlationId", "idempotencyKey", "envelopeDigest", "receivedAt"}
    if set(receipt) != receipt_keys or receipt.get("contractVersion") != HANDOFF_RECEIPT_VERSION or receipt.get("handoffContractVersion") != version or receipt.get("source") != "psychlo" or receipt.get("status") != "admitted": raise ContractError("handoff receipt contract is invalid")
    for field in ("receiptId", "aTeamId", "correlationId", "idempotencyKey"): _id(receipt.get(field), name=f"receipt {field}")
    _digest(receipt.get("envelopeDigest"), name="receipt envelopeDigest"); _offset_timestamp(receipt.get("receivedAt"), name="receivedAt")
    receipt_project = _object(receipt.get("project"), name="receipt project")
    if set(receipt_project) != {"id", "planId", "planVersion"}: raise ContractError("receipt project is invalid")
    for field in ("id", "planId", "planVersion"): _id(receipt_project.get(field), name=f"receipt project {field}")
    if receipt["aTeamId"] != envelope["aTeamId"] or receipt_project != {key: project[key] for key in ("id", "planId", "planVersion")} or receipt["correlationId"] != envelope["correlationId"] or receipt["idempotencyKey"] != envelope["idempotencyKey"] or receipt["envelopeDigest"] != envelope["digest"]: raise ContractError("handoff receipt does not bind envelope")
    return registration


def _offset_timestamp(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", value) is None: raise ContractError(f"{name} is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None: raise ContractError(f"{name} is invalid")
    return value


def _bounded_id_array(value: Any, *, name: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum: raise ContractError(f"{name} is invalid")
    return [_id(item, name=f"{name} item") for item in value]


def _validate_task_graph(task_ids: set[str], dependencies: Mapping[str, list[str]]) -> None:
    for task_id, items in dependencies.items():
        if any(item not in task_ids or item == task_id for item in items): raise ContractError("handoff task dependency is invalid")
    state: dict[str, str] = {}
    def visit(task_id: str) -> None:
        if state.get(task_id) == "visiting": raise ContractError("handoff task dependency is cyclic")
        if state.get(task_id) == "visited": return
        state[task_id] = "visiting"
        for item in dependencies[task_id]: visit(item)
        state[task_id] = "visited"
    for task_id in task_ids: visit(task_id)


def _parse_handoff_lifecycle(raw: Any, project: Mapping[str, Any], lead_id: str) -> None:
    value = _object(raw, name="handoff lifecycle"); kind = value.get("kind")
    if kind == "change":
        if set(value) != {"kind", "supersedesPlanId", "supersedesVersion"}: raise ContractError("handoff lifecycle is invalid")
        _id(value.get("supersedesPlanId"), name="supersedesPlanId"); _id(value.get("supersedesVersion"), name="supersedesVersion")
        if value["supersedesPlanId"] == project["planId"] and value["supersedesVersion"] == project["planVersion"]: raise ContractError("handoff plan change is unchanged")
    elif kind == "decommission":
        if set(value) != {"kind", "deploymentAvailability"} or value.get("deploymentAvailability") not in {"available", "unavailable"}: raise ContractError("handoff lifecycle is invalid")
    elif kind == "takeover":
        if set(value) != {"kind", "repositoryPath", "repositoryHead", "dirtyStateDigest", "currentStateEvidence"} or not isinstance(value.get("repositoryPath"), str) or not value["repositoryPath"].startswith("/") or "\0" in value["repositoryPath"] or value["repositoryPath"] != value["repositoryPath"].strip() or len(value["repositoryPath"]) > 2_048 or GIT_RE.fullmatch(str(value.get("repositoryHead"))) is None: raise ContractError("handoff lifecycle is invalid")
        _digest(value.get("dirtyStateDigest"), name="dirtyStateDigest"); evidence = _bounded_id_array(value.get("currentStateEvidence"), name="currentStateEvidence", maximum=32)
        if not evidence: raise ContractError("handoff lifecycle is invalid")
    elif kind in {"reconstruction", "onboarding", "cleanup"}:
        keys = {"kind", "assessmentId", "assessmentDigest", "classification", "teamId", "projectLeadId", "artifactActions"}
        expected = {"reconstruction": "recover-active", "onboarding": "adopt-baseline", "cleanup": "cleanup-required"}
        if set(value) != keys or value.get("classification") != expected[kind] or value.get("projectLeadId") != lead_id:
            raise ContractError("handoff lifecycle is invalid")
        for field in ("assessmentId", "teamId", "projectLeadId"): _id(value.get(field), name=field)
        _digest(value.get("assessmentDigest"), name="assessmentDigest")
        actions = value.get("artifactActions")
        if not isinstance(actions, list) or len(actions) > 64: raise ContractError("artifact actions are invalid")
        for raw_action in actions:
            action = _object(raw_action, name="artifact action")
            if set(action) != {"artifactId", "artifactDigest", "action"} or action.get("action") not in {"restore", "replace"}: raise ContractError("artifact action is invalid")
            _id(action.get("artifactId"), name="artifactId"); _digest(action.get("artifactDigest"), name="artifactDigest")
    else: raise ContractError("handoff lifecycle is invalid")


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
    required = {"candidateId", "assessmentId", "registry", "evidence", "sourceId", "messageId", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion"}
    fact_names = {"repository", "artifact", "application", "team", "ownership", "plan", "lead", "checkpoint", "security", "contradictions"}
    nested = value.get("evidence")
    if isinstance(nested, Mapping):
        outer_required = {"candidateId", "assessmentId", "evidence", "sourceId", "messageId", "correlationId", "idempotencyKey", "occurredAt", "schemaVersion"}
        _common(value, schema=ADOPTION_SCHEMA, required=outer_required, allowed=outer_required, name="adoption evidence")
        inner = _object(nested, name="adoption classification evidence")
        _keys(inner, {"candidateId", "registry", "repository", "artifact", "application", "team", "ownership", "plan", "lead", "checkpoint", "security", "contradictions", "evidence"}, name="adoption classification evidence")
        if inner.get("candidateId") != value.get("candidateId"):
            raise ContractError("adoption candidate identity conflict")
        value = {**value, **inner}
    _common(value, schema=ADOPTION_SCHEMA, required=required, allowed=required | fact_names, name="adoption evidence")
    _id(value["candidateId"], name="candidateId")
    _id(value["assessmentId"], name="assessmentId")
    registry = _object(value["registry"], name="registry")
    _keys(registry, {"registryId", "registryDigest", "evidenceIds", "canonical"}, name="registry")
    _id(registry.get("registryId"), name="registryId")
    _digest(registry.get("registryDigest"), name="registryDigest")
    if registry.get("canonical") is not True:
        raise ContractError("registry is not canonical")
    registry_ids = _array(registry.get("evidenceIds"), name="registry evidenceIds")
    if not registry_ids:
        raise ContractError("registry evidenceIds are invalid")
    refs = value["evidence"]
    if not isinstance(refs, list) or not refs or len(refs) > MAX_ARRAY:
        raise ContractError("adoption evidence references are invalid")
    for ref in refs:
        _adoption_reference(ref)
    for field, required_fields, optional_fields, kind, expected_reason in (
        ("repository", {"present", "canonical", "clean", "status"}, {"digest", "evidenceRef"}, "repository", "canonical-repository"),
        ("artifact", {"present", "deployable"}, {"digest", "evidenceRef"}, "artifact", "deployable-artifact"),
        ("application", {"present", "provenanceTrusted"}, {"purpose", "evidenceRef"}, "application", "application-purpose"),
        ("team", {"present", "authoritative", "provenanceTrusted"}, {"teamId", "leadId", "evidenceRef"}, "team", "team-baseline"),
        ("ownership", {"trusted", "provenanceTrusted"}, {"license", "evidenceRef", "licenseEvidenceRef"}, "ownership", "ownership"),
        ("plan", {"present", "status"}, {"planId", "planVersion", "evidenceRef"}, "plan", "active-plan"),
        ("lead", {"resolved", "authoritative"}, {"leadId", "teamId", "evidenceRef"}, "lead", "lead"),
        ("checkpoint", {"present", "state"}, {"checkpointId", "threadId", "evidenceRef"}, "checkpoint", "checkpoint"),
    ):
        fact = value.get(field)
        if fact is None:
            continue
        _adoption_fact(fact, required_fields, optional_fields, kind, expected_reason)
    repository = value.get("repository")
    if repository is not None and repository.get("status") not in {"known", "unknown"}:
        raise ContractError("repository status is invalid")
    plan = value.get("plan")
    if plan is not None and plan.get("status") not in {"approved", "in-progress", "none"}:
        raise ContractError("plan status is invalid")
    checkpoint = value.get("checkpoint")
    if checkpoint is not None and checkpoint.get("state") not in {"pending", "uncertain", "none"}:
        raise ContractError("checkpoint state is invalid")
    application = value.get("application")
    if application is not None and "purpose" in application and application["purpose"] not in APPLICATION_PURPOSES:
        raise ContractError("application purpose is invalid")
    ownership = value.get("ownership")
    if ownership is not None and "license" in ownership and ownership["license"] not in LICENSE_KINDS:
        raise ContractError("ownership license is invalid")
    security = value.get("security")
    if security is not None:
        security_value = _object(security, name="security")
        _keys(security_value, {"reasons", "evidence"}, name="security")
        reasons = security_value.get("reasons")
        security_refs = security_value.get("evidence")
        if not isinstance(reasons, list) or len(reasons) > MAX_ARRAY or not isinstance(security_refs, list) or len(security_refs) != len(reasons) or any(reason not in SECURITY_REASONS for reason in reasons):
            raise ContractError("security evidence is invalid")
        for reason, ref in zip(reasons, security_refs):
            _adoption_reference(ref, expected_kind="security", expected_reason=reason)
    contradictions = value.get("contradictions")
    if contradictions is not None and (not isinstance(contradictions, list) or len(contradictions) > MAX_ARRAY or any(reason not in {"dirty-repository", "contradictory-history"} for reason in contradictions)):
        raise ContractError("adoption contradictions are invalid")
    return value


def _adoption_reference(value: Any, *, expected_kind: str | None = None, expected_reason: str | None = None) -> dict[str, Any]:
    item = _object(value, name="evidence reference")
    _keys(item, {"reason", "kind", "evidenceId", "digest"}, name="evidence reference")
    if item.get("reason") not in REASONS or item.get("kind") not in EVIDENCE_KINDS or _adoption_expected_kind(str(item.get("reason"))) != item.get("kind"):
        raise ContractError("evidence reference is invalid")
    if expected_kind is not None and item["kind"] != expected_kind:
        raise ContractError("evidence reference kind is invalid")
    if expected_reason is not None and item["reason"] != expected_reason:
        raise ContractError("evidence reference reason is invalid")
    _id(item.get("evidenceId"), name="evidenceId")
    _digest(item.get("digest"), name="evidence digest")
    return item


def _adoption_expected_kind(reason: str) -> str:
    if reason == "registry": return "registry"
    if reason in {"canonical-repository", "repository-missing", "dirty-repository", "contradictory-history"}: return "repository"
    if reason in {"deployable-artifact", "artifact-missing"}: return "artifact"
    if reason in {"application-purpose", "application-purpose-missing"}: return "application"
    if reason == "team-baseline": return "team"
    if reason in {"active-plan", "plan-missing"}: return "plan"
    if reason in {"lead", "lead-missing"}: return "lead"
    if reason in {"checkpoint", "checkpoint-missing"}: return "checkpoint"
    if reason in SECURITY_REASONS: return "security"
    return "ownership"


def _adoption_fact(value: Any, required: set[str], optional: set[str], kind: str, expected_reason: str) -> None:
    fact = _object(value, name=f"{kind} evidence")
    _keys(fact, required | optional, name=f"{kind} evidence")
    for field in required:
        if field in {"present", "canonical", "clean", "deployable", "provenanceTrusted", "authoritative", "trusted", "resolved"}:
            if not isinstance(fact.get(field), bool):
                raise ContractError(f"{kind} evidence is invalid")
        elif not isinstance(fact.get(field), str) or not fact[field]:
            raise ContractError(f"{kind} evidence is invalid")
    for field in optional - {"evidenceRef", "licenseEvidenceRef"}:
        if field in fact:
            if field == "digest":
                _digest(fact[field], name=f"{kind} digest")
            else:
                _id(fact[field], name=f"{kind} {field}")
    if "evidenceRef" in fact:
        _adoption_reference(fact["evidenceRef"], expected_kind=kind, expected_reason=expected_reason)
    if "licenseEvidenceRef" in fact:
        _adoption_reference(fact["licenseEvidenceRef"], expected_kind="ownership", expected_reason="license")
    if kind == "ownership" and "license" in fact and "licenseEvidenceRef" not in fact:
        raise ContractError("ownership license evidence is missing")


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


def _finite_nonnegative(value: Any, *, name: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value < 0:
        raise ContractError(f"{name} is invalid")
    return value


def _policy_exception_requested_value(value: Any, *, name: str) -> None:
    if isinstance(value, bool):
        return
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ContractError(f"{name} must be boolean or finite number")
    try:
        finite = math.isfinite(float(value))
    except (OverflowError, TypeError, ValueError):
        finite = False
    if not finite:
        raise ContractError(f"{name} must be boolean or finite number")


def _policy_revision(value: Any, *, expected_revision: int) -> dict[str, Any]:
    proposed = _object(value, name="proposedPolicy")
    fields = {"schemaVersion", "id", "revision", "dailyQuotaPercent", "safetyReservePercent", "projectShares", "failurePauseThreshold", "rules", "operatingEnvelope", "actorId", "correlationId", "idempotencyKey", "occurredAt", "digest"}
    _keys(proposed, fields, name="proposedPolicy")
    if proposed.get("schemaVersion") != "psychlo.policy.v1": raise ContractError("proposed policy schema is invalid")
    _id(proposed.get("id"), name="proposed policy id")
    revision = proposed.get("revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision != expected_revision + 1: raise ContractError("proposed policy revision is invalid")
    for field in ("dailyQuotaPercent", "safetyReservePercent"):
        value_number = proposed.get(field)
        if isinstance(value_number, bool) or not isinstance(value_number, (int, float)):
            raise ContractError(f"proposed policy {field} is invalid")
        try: valid = math.isfinite(float(value_number)) and 0 <= value_number <= 100
        except (OverflowError, TypeError, ValueError): valid = False
        if not valid: raise ContractError(f"proposed policy {field} is invalid")
    shares = _object(proposed.get("projectShares"), name="projectShares")
    total = 0.0
    for project_id, share in shares.items():
        _id(project_id, name="project share project id")
        if isinstance(share, bool) or not isinstance(share, (int, float)):
            raise ContractError("proposed policy project share is invalid")
        try: valid = math.isfinite(float(share)) and 0 <= share <= 100
        except (OverflowError, TypeError, ValueError): valid = False
        if not valid: raise ContractError("proposed policy project share is invalid")
        total += float(share)
    if total > 100: raise ContractError("proposed policy project shares exceed 100 percent")
    threshold = proposed.get("failurePauseThreshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool) or not 0 < threshold <= 100: raise ContractError("proposed policy failure threshold is invalid")
    rules = _object(proposed.get("rules"), name="policy rules")
    _keys(rules, POLICY_EXCEPTION_RULES, name="policy rules")
    if any(not isinstance(enabled, bool) for enabled in rules.values()): raise ContractError("proposed policy rules are invalid")
    envelope = _object(proposed.get("operatingEnvelope"), name="operatingEnvelope")
    _keys(envelope, {"maxDailyQuotaPercent", "minSafetyReservePercent"}, name="operatingEnvelope")
    for field in ("maxDailyQuotaPercent", "minSafetyReservePercent"):
        value_number = envelope.get(field)
        if isinstance(value_number, bool) or not isinstance(value_number, (int, float)):
            raise ContractError(f"operating envelope {field} is invalid")
        try: valid = math.isfinite(float(value_number)) and 0 <= value_number <= 100
        except (OverflowError, TypeError, ValueError): valid = False
        if not valid: raise ContractError(f"operating envelope {field} is invalid")
    if proposed["dailyQuotaPercent"] > envelope["maxDailyQuotaPercent"] or proposed["safetyReservePercent"] < envelope["minSafetyReservePercent"]:
        raise ContractError("proposed policy violates operating envelope")
    _id(proposed.get("actorId"), name="proposed policy actorId")
    _id(proposed.get("correlationId"), name="proposed policy correlationId")
    _id(proposed.get("idempotencyKey"), name="proposed policy idempotencyKey")
    _timestamp(proposed.get("occurredAt"))
    _digest(proposed.get("digest"), name="proposed policy digest")
    if canonical_digest(proposed) != proposed["digest"]: raise ContractError("proposed policy digest mismatch")
    return proposed


def _policy_exception_form(value: Mapping[str, Any], *, policy_revision: int, name: str) -> None:
    has_requested = "requestedValue" in value
    has_base = "basePolicyDigest" in value
    has_proposed = "proposedPolicy" in value
    if has_requested:
        if has_base or has_proposed: raise ContractError(f"{name} scalar form cannot include proposed policy fields")
        _policy_exception_requested_value(value["requestedValue"], name="policy exception requested value")
        return
    if has_base or has_proposed:
        if not has_base or not has_proposed: raise ContractError(f"{name} proposed-policy form requires basePolicyDigest and proposedPolicy")
        _digest(value["basePolicyDigest"], name="basePolicyDigest")
        _policy_revision(value["proposedPolicy"], expected_revision=policy_revision)
        return
    raise ContractError(f"{name} requires exactly one exception form")


def _policy_exception_common(value: Mapping[str, Any], *, name: str, schema: str, rule_key: str) -> dict[str, Any]:
    required = {"schemaVersion", "id", rule_key, "policyRevision", "actorId", "reason", "activatedAt", "expiresAt", "correlationId", "idempotencyKey", "occurredAt", "scopeDigest", "decisionVersion", "digest"}
    optional = {"requestedValue", "basePolicyDigest", "proposedPolicy"}
    result = _strict_protocol(value, required=required, allowed=required | optional, name=name, schema=schema)
    _id(result["id"], name="exception id")
    _id(result[rule_key], name=rule_key)
    if result[rule_key] not in POLICY_EXCEPTION_RULES:
        raise ContractError("policy exception rule is invalid")
    if not isinstance(result["policyRevision"], int) or isinstance(result["policyRevision"], bool) or result["policyRevision"] < 0:
        raise ContractError("policy exception revision is invalid")
    _id(result["actorId"], name="actorId"); _text(result["reason"], name="reason", maximum=512)
    _digest(result["scopeDigest"], name="scopeDigest"); _id(result["decisionVersion"], name="decisionVersion")
    _timestamp(result["activatedAt"], name="activatedAt"); _timestamp(result["expiresAt"], name="expiresAt")
    if datetime.fromisoformat(result["expiresAt"].replace("Z", "+00:00")) <= datetime.fromisoformat(result["activatedAt"].replace("Z", "+00:00")):
        raise ContractError("policy exception expiry is invalid")
    _policy_exception_form(result, policy_revision=result["policyRevision"], name=name)
    _digest(result["digest"], name="digest")
    if _policy_exception_digest(result) != result["digest"]:
        raise ContractError(f"{name} digest mismatch")
    return result


def parse_policy_exception_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    return _policy_exception_common(payload, name="policy exception request", schema=POLICY_EXCEPTION_REQUEST_SCHEMA, rule_key="requestedRuleId")


def policy_exception_request_digest(payload: Mapping[str, Any]) -> str:
    return _policy_exception_digest(payload)


def policy_exception_outcome_digest(payload: Mapping[str, Any]) -> str:
    fields = {"status", "exceptionId", "policyRevision", "ruleId", "requestDigest", "decisionId", "decisionDigest", "scopeDigest", "decisionVersion"}
    result = {key: payload[key] for key in fields if key in payload}
    for key in ("requestedValue", "basePolicyDigest", "proposedPolicy", "reason"):
        if key in payload and payload[key] is not None: result[key] = payload[key]
    return _policy_exception_digest(result)


def parse_policy_exception_outcome(payload: Mapping[str, Any]) -> dict[str, Any]:
    value = _object(payload, name="policy exception outcome")
    required = {"schemaVersion", "sourceId", "status", "exceptionId", "policyRevision", "ruleId", "requestDigest", "decisionId", "decisionDigest", "actorId", "correlationId", "idempotencyKey", "occurredAt", "scopeDigest", "decisionVersion", "outcomeDigest"}
    _keys(value, required | {"requestedValue", "basePolicyDigest", "proposedPolicy", "reason"}, name="policy exception outcome")
    if value.get("schemaVersion") != POLICY_EXCEPTION_OUTCOME_SCHEMA or value.get("sourceId") != "overseer" or value.get("status") not in {"approved", "rejected"}: raise ContractError("policy exception outcome authority is invalid")
    _id(value.get("exceptionId"), name="exceptionId"); _id(value.get("ruleId"), name="ruleId")
    if value["ruleId"] not in POLICY_EXCEPTION_RULES or not isinstance(value["policyRevision"], int) or isinstance(value["policyRevision"], bool) or value["policyRevision"] < 0: raise ContractError("policy exception outcome binding is invalid")
    for field in ("requestDigest", "decisionDigest", "outcomeDigest"): _digest(value.get(field), name=field)
    _digest(value["scopeDigest"], name="scopeDigest"); _id(value["decisionVersion"], name="decisionVersion")
    _policy_exception_form(value, policy_revision=value["policyRevision"], name="policy exception outcome")
    for field in ("decisionId", "actorId", "correlationId", "idempotencyKey"): _id(value.get(field), name=field)
    _timestamp(value.get("occurredAt"))
    if value["status"] == "approved" and "reason" in value: raise ContractError("approved policy exception outcome forbids reason")
    if value["status"] == "rejected": _text(value.get("reason"), name="rejected policy exception reason", maximum=512)
    if policy_exception_outcome_digest(value) != value["outcomeDigest"]: raise ContractError("policy exception outcome digest mismatch")
    return value


def parse_usage_snapshot_v11(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the frozen, signed/enveloped v1.1 provider snapshot shape."""
    envelope = _object(payload, name="usage snapshot envelope")
    required = {"schemaVersion", "correlationId", "idempotencyKey", "occurredAt", "snapshot", "digest"}
    _keys(envelope, required, name="usage snapshot envelope")
    if envelope["schemaVersion"] != USAGE_ENVELOPE_V11_SCHEMA: raise ContractError("usage snapshot envelope schema is invalid")
    _id(envelope["correlationId"], name="correlationId"); _id(envelope["idempotencyKey"], name="idempotencyKey"); _timestamp(envelope["occurredAt"]); _digest(envelope["digest"], name="digest")
    snapshot = _object(envelope["snapshot"], name="usage snapshot")
    fields = {"schemaVersion", "id", "sourceId", "capturedAt", "policyVersion", "providerResetAt", "scopeDigest", "decisionVersion", "unusedPriorDayWeeklyCapacity", "weeklyQuota", "weeklyRemainingCapacity", "dailyConsumed", "otherDevelopmentConsumed", "digest"}
    _keys(snapshot, fields, name="usage snapshot")
    if snapshot["schemaVersion"] != USAGE_SNAPSHOT_V11_SCHEMA or snapshot["sourceId"] != "overseer": raise ContractError("usage snapshot authority is invalid")
    for field in ("id", "policyVersion", "decisionVersion"): _id(snapshot[field], name=field)
    _timestamp(snapshot["capturedAt"]); _timestamp(snapshot["providerResetAt"]); _digest(snapshot["scopeDigest"], name="scopeDigest"); _digest(snapshot["digest"], name="snapshot digest")
    for field in ("unusedPriorDayWeeklyCapacity", "weeklyQuota", "weeklyRemainingCapacity", "dailyConsumed", "otherDevelopmentConsumed"):
        if isinstance(snapshot[field], bool) or not isinstance(snapshot[field], int) or snapshot[field] < 0: raise ContractError(f"{field} must be nonnegative integer quota ticks")
    if snapshot["weeklyRemainingCapacity"] > snapshot["weeklyQuota"] or snapshot["dailyConsumed"] + snapshot["otherDevelopmentConsumed"] != snapshot["weeklyQuota"] - snapshot["weeklyRemainingCapacity"]: raise ContractError("usage snapshot conservation is invalid")
    if canonical_digest({key: value for key, value in snapshot.items() if key != "digest"}) != snapshot["digest"]: raise ContractError("usage snapshot digest mismatch")
    if canonical_digest({key: value for key, value in envelope.items() if key != "digest"}) != envelope["digest"]: raise ContractError("usage snapshot envelope digest mismatch")
    return envelope


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
