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
import re
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
    if not isinstance(value["id"], str) or not value["id"].startswith("observation-"):
        raise ContractError("learning observation id is invalid")
    profile = _object(value["featureProfile"], name="featureProfile")
    outcome = _object(value["outcome"], name="outcome")
    allowed_profile = {"taskClass", "projectClass", "dependencyClass", "expectedComponents", "buildGate", "testGate", "browserGate", "securityGate", "deploymentGate", "model", "executionPattern", "similarityClass", "attribution", "sampleKind"}
    allowed_outcome = {"usage", "actualUsage", "remainingUsage", "activeMs", "waitingMs", "status", "observedAt", "policyVersion", "censored"}
    _keys(profile, allowed_profile, name="featureProfile")
    _keys(outcome, allowed_outcome, name="outcome")
    if "taskClass" in profile and profile["taskClass"] not in {"frontend", "backend", "fullstack", "library", "service", "cli", "unknown"}:
        raise ContractError("taskClass is invalid")
    if "model" in profile:
        _id(profile["model"], name="model")
    if "expectedComponents" in profile and (not isinstance(profile["expectedComponents"], int) or profile["expectedComponents"] < 0 or profile["expectedComponents"] > 100):
        raise ContractError("expectedComponents is invalid")
    if "status" in outcome and outcome["status"] not in {"completed", "blocked"}:
        raise ContractError("status is invalid")
    if "observedAt" in outcome:
        _timestamp(outcome["observedAt"], name="observedAt")
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
