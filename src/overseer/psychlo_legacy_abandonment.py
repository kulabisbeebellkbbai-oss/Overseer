"""Approval-bound abandonment of one ambiguous submitted legacy round.

This module is intentionally separate from recovery and process observation.
It can only terminalize a round after a recorded, non-authoritative historical
observation and an exact approved Sisko plan have been revalidated.  It never
uses a terminal input path, dispatches a prompt, kills a process, or changes a
Codex binding.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, UTC
import hashlib
import json
import re
from typing import Any, Mapping

from .admin import AdminChangeKind, AdminChangePlan, plan_psychlo_legacy_abandonment
from .core import ApprovalLevel, OwnerDomain, RiskLevel
from .psychlo_contracts import canonical_digest
from .psychlo_process_attestation import SCHEMA as PROCESS_OBSERVATION_SCHEMA, RECOVERY_SCHEMA as PROCESS_RECOVERY_OBSERVATION_SCHEMA, _validate_process_observation_row, admin_plan_digest


SCHEMA = "psychlo.legacy-round-abandon.v1"
ENVELOPE_SCHEMA = "overseer.psychlo.legacy-round-abandon-envelope.v1"
ENVELOPE_SCHEMA_V2 = "overseer.psychlo.legacy-round-abandon-envelope.v2"
REASON = "ambiguous-submitted-delivery"
STATUS = "legacy-abandoned-uncertain"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")


class LegacyAbandonmentError(ValueError):
    """Raised when exact historical/authority bindings cannot be proven."""


def _id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise LegacyAbandonmentError(f"{name} is invalid")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise LegacyAbandonmentError(f"{name} is invalid")
    return value


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise LegacyAbandonmentError("abandonment timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise LegacyAbandonmentError("abandonment timestamp requires an offset")
    return value


def _immutable_plan_digest(plan: AdminChangePlan) -> str:
    value = asdict(plan)
    for key in ("approved", "approved_by", "approved_at", "canceled", "canceled_by", "canceled_at", "cancellation_reason", "archived", "archived_by", "archived_at", "archive_record_id"):
        value.pop(key, None)
    return canonical_digest(value)


def _require_approved_sisko_plan(plan: AdminChangePlan, kind: AdminChangeKind, target: str) -> None:
    if (
        plan.kind != kind or plan.target != target or plan.owner_domain != OwnerDomain.SISKO
        or plan.risk_level != RiskLevel.HIGH or plan.approval_level != ApprovalLevel.HUMAN
        or plan.approved is not True or plan.approved_by != "sisko"
        or plan.canceled is not False or plan.archived is not False
        or any(getattr(plan, name) is not None for name in ("canceled_by", "canceled_at", "cancellation_reason", "archived_by", "archived_at", "archive_record_id"))
    ):
        raise LegacyAbandonmentError("exact approved Sisko plan is required")
    if not isinstance(plan.approved_at, str):
        raise LegacyAbandonmentError("approved Sisko plan timestamp is missing")
    try:
        approved = datetime.fromisoformat(plan.approved_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise LegacyAbandonmentError("approved Sisko plan timestamp is invalid") from error
    if approved.tzinfo is None or approved.utcoffset() != UTC.utcoffset(approved):
        raise LegacyAbandonmentError("approved Sisko plan timestamp is not UTC")


def _delivery_digest(delivery: Mapping[str, Any], phase: str = "submitted") -> str:
    selected = {
        "requestDigest": delivery.get("requestDigest"),
        "capabilityHash": delivery.get("capabilityHash"),
        "binding": delivery.get("binding"),
        "submittedPhase": phase,
        "promptDigest": delivery.get("promptDigest"),
    }
    return canonical_digest(selected)


def _now(bridge: Any) -> str:
    value = bridge.clock()
    return _timestamp(str(value))


def _primary(bridge: Any) -> Any:
    primary = getattr(bridge, "approval_store", None)
    if primary is None:
        raise LegacyAbandonmentError("primary approval store is required")
    return primary


def _strict_source_observation(primary: Any, round_id: str, observation_plan_id: str) -> tuple[dict[str, Any], AdminChangePlan, dict[str, Any]]:
    row = primary._connection.execute(
        "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at FROM psychlo_process_observations WHERE round_id=?",
        (round_id,),
    ).fetchone()
    if row is None or row[2] != observation_plan_id or row[5] != "recorded":
        raise LegacyAbandonmentError("exact recorded historical observation is required")
    try:
        manifest, source_plan, _encoded, _manifest_digest = _validate_process_observation_row(
            primary, row, round_id=round_id, plan_id=observation_plan_id,
        )
    except Exception as error:
        raise LegacyAbandonmentError("recorded historical observation is invalid") from error
    if (
        manifest.get("schemaVersion") not in {PROCESS_OBSERVATION_SCHEMA, PROCESS_RECOVERY_OBSERVATION_SCHEMA}
        or manifest.get("historical") is not True
        or manifest.get("authoritative") is not False
        or manifest.get("executable") is not False
        or row[4] != admin_plan_digest(source_plan)
    ):
        raise LegacyAbandonmentError("recorded observation authority is not exact")
    _require_approved_sisko_plan(source_plan, AdminChangeKind.PSYCHLO_LEGACY_PROCESS_OBSERVATION, round_id)
    return ({
        "observationId": row[0], "roundId": row[1], "planId": row[2],
        "observationDigest": row[3], "planDigest": row[4], "manifest": manifest,
        "insertedAt": row[7], "recordedAt": row[8],
    }, source_plan, manifest)


def _snapshot(bridge: Any, primary: Any, round_id: str, observation_plan_id: str, successor: Mapping[str, str], *, allow_existing_abandonment: bool = False, allow_fence: bool = False, delivery_conversation_id: str | None = None) -> tuple[dict[str, Any], AdminChangePlan]:
    observation, source_plan, manifest = _strict_source_observation(primary, round_id, observation_plan_id)
    observation_digest = _digest(observation.get("observationDigest"), "observation digest")
    observation_plan_digest = _digest(observation.get("planDigest"), "observation plan digest")
    record = bridge.store.get_round(round_id)
    if record is None:
        raise LegacyAbandonmentError("round is missing")
    request, _receipt, capability_hash, _capability, state, result, forwarded = record
    if state != "started" or result is not None or forwarded:
        raise LegacyAbandonmentError("round is not an uncertain started round")
    request_digest = bridge.store._round_request_digest(request)
    _digest(request_digest, "request digest")
    _digest(capability_hash, "capability hash")
    recovery = bridge.store.round_recovery(round_id)
    recovery_authority = None
    if recovery is not None:
        evidence = recovery.get("evidence") if isinstance(recovery, Mapping) else None
        if recovery.get("state") == "uncertain":
            if (recovery.get("ownerId") is not None or recovery.get("claimToken") is not None
                    or recovery.get("leaseExpiresAt") is not None or not isinstance(evidence, Mapping)
                    or evidence.get("redeliveryAttempted") is not True or evidence.get("phase") != "unresolved"
                    or evidence.get("deliveryProof") not in {"unknown", "missing"}):
                raise LegacyAbandonmentError("round recovery is not an exact terminal uncertain recovery")
            recovery_authority = {"state": "uncertain", "recoveryDigest": canonical_digest(recovery), "evidenceDigest": canonical_digest(evidence)}
        elif allow_fence and recovery.get("state") == "abandonment-fenced" and isinstance(evidence, Mapping):
            if not all(isinstance(evidence.get(key), str) and _DIGEST_RE.fullmatch(evidence[key]) for key in ("priorRecoveryDigest", "priorEvidenceDigest")):
                raise LegacyAbandonmentError("abandonment-fenced recovery authority is invalid")
            recovery_authority = {"state": "uncertain", "recoveryDigest": evidence["priorRecoveryDigest"], "evidenceDigest": evidence["priorEvidenceDigest"]}
        else:
            raise LegacyAbandonmentError("round recovery conflicts with abandonment")
    delivery = bridge.store.round_prompt_delivery(round_id)
    ambiguous_delivery_phases = {"submit-intent", "composer-pending", "submitted"}
    effective_delivery_phase = delivery.get("phase") if delivery is not None else None
    if effective_delivery_phase == "abandonment-fence" and allow_fence:
        provisional_action_id = f"legacy-abandonment:{round_id}:{successor.get('successorPlanId', '')}"
        fenced_intent = bridge.store.legacy_abandonment(provisional_action_id)
        frozen_delivery = fenced_intent.get("payload", {}).get("delivery", {}) if isinstance(fenced_intent, Mapping) else {}
        effective_delivery_phase = frozen_delivery.get("phase")
    expected_delivery_phases = ambiguous_delivery_phases | {"unresolved"}
    if delivery is None or effective_delivery_phase not in expected_delivery_phases:
        raise LegacyAbandonmentError("ambiguous prompt delivery or terminal uncertain prompt delivery is required")
    if recovery_authority is None and effective_delivery_phase not in ambiguous_delivery_phases:
        raise LegacyAbandonmentError("ambiguous prompt delivery is required")
    if recovery_authority is not None and effective_delivery_phase != "unresolved":
        raise LegacyAbandonmentError("uncertain recovery requires unresolved prompt delivery")
    if delivery.get("requestDigest") != request_digest or delivery.get("capabilityHash") != capability_hash:
        raise LegacyAbandonmentError("prompt delivery binding is not exact")
    binding = bridge.store.round_binding(round_id)
    if binding is None or binding != delivery.get("binding"):
        raise LegacyAbandonmentError("round execution binding is not exact")
    prompt_digest = _digest(delivery.get("promptDigest"), "prompt digest")
    delivery_digest = _delivery_digest(delivery, str(effective_delivery_phase))
    _digest(delivery_digest, "delivery digest")
    bridge_evidence = manifest.get("bridge")
    expected_binding_digest = hashlib.sha256(json.dumps(binding, separators=(",", ":")).encode()).hexdigest()
    if not isinstance(bridge_evidence, Mapping):
        raise LegacyAbandonmentError("historical bridge evidence is stale")
    observation_recovery_exact = (
        recovery_authority is None
        and bridge_evidence.get("recoveryPresent") is False
        and bridge_evidence.get("deliveryPhase") == effective_delivery_phase
    ) or (
        recovery_authority is not None
        and bridge_evidence.get("recoveryPresent") is True
        and bridge_evidence.get("recoveryState") == "uncertain"
        and bridge_evidence.get("recoveryDigest") == recovery_authority["recoveryDigest"]
        and bridge_evidence.get("deliveryPhase") == "unresolved"
    )
    if bridge_evidence.get("dispatchState") != "started" or bridge_evidence.get("resultPresent") is not False or not observation_recovery_exact or bridge_evidence.get("failurePresent") is not False or bridge_evidence.get("cancelPresent") is not False or bridge_evidence.get("requestDigest") != request_digest or bridge_evidence.get("capabilityHash") != capability_hash or bridge_evidence.get("bindingDigest") != expected_binding_digest or bridge_evidence.get("promptDigest") != prompt_digest:
        raise LegacyAbandonmentError("historical bridge evidence is stale")
    forbidden_tables = ("operational_failure_intents", "round_cancellations")
    if any(bridge.store.connection.execute(f"SELECT 1 FROM {table} WHERE round_id=? LIMIT 1", (round_id,)).fetchone() is not None for table in forbidden_tables):
        raise LegacyAbandonmentError("round already has a recovery, failure, cancellation, or abandonment intent")
    existing_abandonment = bridge.store.legacy_abandonment(f"legacy-abandonment:{round_id}:{successor.get('successorPlanId', '')}")
    if existing_abandonment is not None and not allow_existing_abandonment:
        raise LegacyAbandonmentError("round already has an abandonment intent")
    original_plan_id = _id(request.get("planId"), "original plan id")
    original_plan_version = _id(request.get("planVersion"), "original plan version")
    original_conversation_id = _id(binding.get("conversationId"), "original conversation id")
    requested_thread_id = _id(request.get("threadId"), "original thread id") if "threadId" in request else None
    if delivery_conversation_id is None:
        if requested_thread_id is not None and requested_thread_id != original_conversation_id:
            raise LegacyAbandonmentError("original thread id does not match immutable binding")
        original_thread_id = requested_thread_id or original_conversation_id
    else:
        delivery_conversation_id = _id(delivery_conversation_id, "delivery conversation id")
        if requested_thread_id is None:
            raise LegacyAbandonmentError("historical misbinding requires a stored request thread id")
        if requested_thread_id == original_conversation_id:
            raise LegacyAbandonmentError("historical misbinding requires a request thread distinct from binding")
        if delivery_conversation_id != original_conversation_id:
            raise LegacyAbandonmentError("delivery conversation does not match immutable binding")
        delivery_binding = delivery.get("binding")
        if not isinstance(delivery_binding, Mapping) or delivery_binding.get("conversationId") != delivery_conversation_id:
            raise LegacyAbandonmentError("delivery conversation does not match immutable delivery binding")
        original_thread_id = requested_thread_id
    for name in ("successorPlanId", "successorPlanVersion", "successorConversationId", "successorThreadId"):
        _id(successor.get(name), name)
    if (successor["successorPlanId"] == original_plan_id
            or successor["successorPlanVersion"] == original_plan_version
            or successor["successorConversationId"] == original_conversation_id
            or successor["successorThreadId"] == original_thread_id):
        raise LegacyAbandonmentError("successor plan identity must be distinct")
    action_id = f"legacy-abandonment:{round_id}:{successor['successorPlanId']}"
    action = {
        "schemaVersion": SCHEMA, "actionId": action_id, "roundId": round_id,
        "projectId": _id(request.get("projectId"), "project id"), "requestDigest": request_digest,
        "capabilityHash": capability_hash, "observationId": _id(observation.get("observationId"), "observation id"),
        "observationDigest": observation_digest, "observationPlanDigest": observation_plan_digest,
        "delivery": {"phase": effective_delivery_phase, "promptDigest": prompt_digest, "deliveryDigest": delivery_digest, "bindingDigest": expected_binding_digest},
        "originalPlan": {"planId": original_plan_id, "planVersion": original_plan_version, "conversationId": original_conversation_id, "threadId": original_thread_id},
        "successorPlan": dict(successor), "observationPlanId": observation_plan_id, "reason": REASON,
    }
    if recovery_authority is not None:
        action["recovery"] = recovery_authority
    if delivery_conversation_id is not None:
        action.update({
            "requestedThreadId": requested_thread_id,
            "deliveryConversationId": delivery_conversation_id,
        })
    wire_body = {"schemaVersion": SCHEMA, "actionId": action_id, "roundId": round_id, "projectId": action["projectId"], "requestDigest": request_digest, "planId": original_plan_id, "planVersion": original_plan_version, "observationId": action["observationId"], "observationDigest": observation_digest, "successorPlanId": successor["successorPlanId"], "successorPlanVersion": successor["successorPlanVersion"], "successorConversationId": successor["successorConversationId"], "successorThreadId": successor["successorThreadId"], "reason": REASON, "occurredAt": _now(bridge)}
    action_digest = canonical_digest(wire_body)
    action["actionDigest"] = action_digest
    wire = {**wire_body, "actionDigest": action_digest}
    action["wire"] = wire
    return action, source_plan


def stage_legacy_abandonment(*, bridge: Any, plan_id: str, observation_plan_id: str, round_id: str, successor_plan_id: str, successor_plan_version: str, successor_conversation_id: str, successor_thread_id: str, delivery_conversation_id: str | None = None) -> dict[str, Any]:
    """Stage one non-executable authority plan and bridge outbox intent."""
    primary = _primary(bridge)
    successor = {"successorPlanId": successor_plan_id, "successorPlanVersion": successor_plan_version, "successorConversationId": successor_conversation_id, "successorThreadId": successor_thread_id}
    action_id = f"legacy-abandonment:{round_id}:{successor_plan_id}"
    existing_intent = bridge.store.legacy_abandonment(action_id)
    action, _source_plan = _snapshot(
        bridge, primary, round_id, observation_plan_id, successor,
        allow_existing_abandonment=existing_intent is not None,
        allow_fence=bool(existing_intent and existing_intent["state"] == "peer-pending"),
        delivery_conversation_id=delivery_conversation_id,
    )
    metadata = action
    plan_kwargs = {
        "delivery_phase": action["delivery"]["phase"],
        "recovery_digest": action.get("recovery", {}).get("recoveryDigest"),
        "recovery_evidence_digest": action.get("recovery", {}).get("evidenceDigest"),
    }
    if "requestedThreadId" in action or "deliveryConversationId" in action:
        plan_kwargs.update({
            "requested_thread_id": action.get("requestedThreadId"),
            "delivery_conversation_id": action.get("deliveryConversationId"),
            "binding_digest": action["delivery"]["bindingDigest"],
            "prompt_digest": action["delivery"]["promptDigest"],
            "project_id": action["projectId"],
        })
    plan = plan_psychlo_legacy_abandonment(
        plan_id, round_id, action["observationId"], action["observationDigest"], action["observationPlanDigest"], action["requestDigest"], action["capabilityHash"], action["delivery"]["deliveryDigest"], action["originalPlan"]["planId"], action["originalPlan"]["planVersion"], action["originalPlan"]["conversationId"], action["originalPlan"]["threadId"], successor_plan_id, successor_plan_version, successor_conversation_id, successor_thread_id, **plan_kwargs,
    )
    metadata["planId"] = plan_id
    metadata["planDigest"] = _immutable_plan_digest(plan)
    if existing_intent is not None:
        frozen = existing_intent["payload"]
        existing_plan = primary.load_admin_change_plan(plan_id) if _plan_exists(primary, plan_id) else None
        if (
            frozen.get("planId") != plan_id
            or frozen.get("planDigest") != metadata["planDigest"]
            or existing_intent["actionDigest"] != frozen.get("actionDigest")
            or _action_core(frozen) != _action_core(metadata)
            or _validate_wire(frozen.get("wire"), frozen).get("actionDigest") != existing_intent["actionDigest"]
            or existing_plan is None
            or _immutable_plan_digest(existing_plan) != _immutable_plan_digest(plan)
        ):
            raise LegacyAbandonmentError("legacy abandonment action identity conflict")
        return {"staged": True, "historical": True, "authoritative": False, "executable": False, "actionId": action_id, "actionDigest": existing_intent["actionDigest"], "planId": plan_id, "roundId": round_id, "state": existing_intent["state"], "replayed": True}
    if _plan_exists(primary, plan_id):
        existing_plan = primary.load_admin_change_plan(plan_id)
        if _immutable_plan_digest(existing_plan) != _immutable_plan_digest(plan):
            raise LegacyAbandonmentError("abandonment plan identity conflict")
    else:
        primary.save_admin_change_plan(plan)
    intent = bridge.store.stage_legacy_abandonment(action_id, round_id, metadata["actionDigest"], metadata, now=_now(bridge))
    return {"staged": True, "historical": True, "authoritative": False, "executable": False, "actionId": action_id, "actionDigest": metadata["actionDigest"], "planId": plan_id, "roundId": round_id, "state": intent["state"]}


def _plan_exists(primary: Any, plan_id: str) -> bool:
    try:
        primary.load_admin_change_plan(plan_id)
    except KeyError:
        return False
    return True


def _expected_plan(action: Mapping[str, Any], plan_id: str) -> AdminChangePlan:
    plan_kwargs = {
        "delivery_phase": action["delivery"]["phase"],
        "recovery_digest": action.get("recovery", {}).get("recoveryDigest"),
        "recovery_evidence_digest": action.get("recovery", {}).get("evidenceDigest"),
    }
    if "requestedThreadId" in action or "deliveryConversationId" in action:
        plan_kwargs.update({
            "requested_thread_id": action.get("requestedThreadId"),
            "delivery_conversation_id": action.get("deliveryConversationId"),
            "binding_digest": action["delivery"]["bindingDigest"],
            "prompt_digest": action["delivery"]["promptDigest"],
            "project_id": action["projectId"],
        })
    return plan_psychlo_legacy_abandonment(plan_id, action["roundId"], action["observationId"], action["observationDigest"], action["observationPlanDigest"], action["requestDigest"], action["capabilityHash"], action["delivery"]["deliveryDigest"], action["originalPlan"]["planId"], action["originalPlan"]["planVersion"], action["originalPlan"]["conversationId"], action["originalPlan"]["threadId"], action["successorPlan"]["successorPlanId"], action["successorPlan"]["successorPlanVersion"], action["successorPlan"]["successorConversationId"], action["successorPlan"]["successorThreadId"], **plan_kwargs)


def _action_core(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"actionDigest", "wire", "planDigest", "planId"}}


_WIRE_KEYS = frozenset({"schemaVersion", "actionId", "actionDigest", "roundId", "projectId", "requestDigest", "planId", "planVersion", "observationId", "observationDigest", "successorPlanId", "successorPlanVersion", "successorConversationId", "successorThreadId", "reason", "occurredAt"})
_RESPONSE_KEYS = frozenset({"accepted", "actionId", "actionDigest", "roundId", "requestDigest", "status"})
_SENDER_RESPONSE_KEYS = _RESPONSE_KEYS | {"status_code"}
_ABANDONMENT_HTTP_STATUS = 202


def _validate_wire(wire: Any, action: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(wire, Mapping) or set(wire) != _WIRE_KEYS:
        raise LegacyAbandonmentError("legacy abandonment wire schema is not exact")
    unsigned = {key: value for key, value in wire.items() if key != "actionDigest"}
    if (
        wire.get("schemaVersion") != SCHEMA
        or wire.get("reason") != REASON
        or wire.get("actionDigest") != canonical_digest(unsigned)
        or wire.get("actionDigest") != action.get("actionDigest")
        or wire.get("actionId") != action.get("actionId")
        or wire.get("roundId") != action.get("roundId")
        or wire.get("projectId") != action.get("projectId")
        or wire.get("requestDigest") != action.get("requestDigest")
        or wire.get("planId") != action.get("originalPlan", {}).get("planId")
        or wire.get("planVersion") != action.get("originalPlan", {}).get("planVersion")
        or wire.get("observationId") != action.get("observationId")
        or wire.get("observationDigest") != action.get("observationDigest")
        or wire.get("successorPlanId") != action.get("successorPlan", {}).get("successorPlanId")
        or wire.get("successorPlanVersion") != action.get("successorPlan", {}).get("successorPlanVersion")
        or wire.get("successorConversationId") != action.get("successorPlan", {}).get("successorConversationId")
        or wire.get("successorThreadId") != action.get("successorPlan", {}).get("successorThreadId")
    ):
        raise LegacyAbandonmentError("legacy abandonment wire binding changed")
    _timestamp(str(wire.get("occurredAt")))
    return dict(wire)


def _transport_envelope(
    action: Mapping[str, Any],
    current_action: Mapping[str, Any],
    approved_plan: AdminChangePlan,
    wire: Mapping[str, Any],
) -> dict[str, Any]:
    original_conversation_id = _id(
        action.get("originalPlan", {}).get("conversationId"),
        "original conversation id",
    )
    current_conversation_id = _id(
        current_action.get("originalPlan", {}).get("conversationId"),
        "current original conversation id",
    )
    metadata = approved_plan.adapter_metadata.get("legacy_abandonment") if isinstance(approved_plan.adapter_metadata, Mapping) else None
    approved_conversation_id = _id(
        metadata.get("originalConversationId") if isinstance(metadata, Mapping) else None,
        "approved original conversation id",
    )
    if original_conversation_id != current_conversation_id or original_conversation_id != approved_conversation_id:
        raise LegacyAbandonmentError("transport original conversation identity changed")
    has_v2_fields = "requestedThreadId" in action or "deliveryConversationId" in action
    if has_v2_fields:
        if not {"requestedThreadId", "deliveryConversationId"}.issubset(action):
            raise LegacyAbandonmentError("historical misbinding envelope identities are incomplete")
        requested_thread_id = _id(action.get("requestedThreadId"), "requested thread id")
        delivery_conversation_id = _id(action.get("deliveryConversationId"), "delivery conversation id")
        current_requested_thread_id = _id(current_action.get("requestedThreadId"), "current requested thread id")
        current_delivery_conversation_id = _id(current_action.get("deliveryConversationId"), "current delivery conversation id")
        approved_requested_thread_id = _id(metadata.get("requestedThreadId") if isinstance(metadata, Mapping) else None, "approved requested thread id")
        approved_delivery_conversation_id = _id(metadata.get("deliveryConversationId") if isinstance(metadata, Mapping) else None, "approved delivery conversation id")
        if (
            requested_thread_id == delivery_conversation_id
            or requested_thread_id != current_requested_thread_id
            or delivery_conversation_id != current_delivery_conversation_id
            or delivery_conversation_id != original_conversation_id
            or requested_thread_id != approved_requested_thread_id
            or delivery_conversation_id != approved_delivery_conversation_id
        ):
            raise LegacyAbandonmentError("historical misbinding envelope identity changed")
        return {
            "schemaVersion": ENVELOPE_SCHEMA_V2,
            "action": dict(wire),
            "requestedThreadId": requested_thread_id,
            "deliveryConversationId": delivery_conversation_id,
        }
    return {
        "schemaVersion": ENVELOPE_SCHEMA,
        "action": dict(wire),
        "originalConversationId": original_conversation_id,
    }


def finalize_legacy_abandonment(*, bridge: Any, plan_id: str) -> dict[str, Any]:
    primary = _primary(bridge)
    plan = primary.load_admin_change_plan(plan_id)
    if plan.kind != AdminChangeKind.PSYCHLO_LEGACY_ABANDONMENT:
        raise LegacyAbandonmentError("exact legacy abandonment plan is required")
    metadata = plan.adapter_metadata.get("legacy_abandonment") if isinstance(plan.adapter_metadata, Mapping) else None
    successor_id = metadata.get("successorPlanId") if isinstance(metadata, Mapping) else plan_id
    action_id = next((key for key in (f"legacy-abandonment:{plan.target}:{successor_id}",) if bridge.store.legacy_abandonment(key)), None)
    if action_id is None:
        return {"planId": plan_id, "approved": bool(plan.approved), "status": "approved-awaiting-intent" if plan.approved else "pending-approval", "completed": False}
    intent = bridge.store.legacy_abandonment(action_id)
    return {"planId": plan_id, "actionId": action_id, "approved": plan.approved is True and plan.approved_by == "sisko", "status": "completed" if intent and intent["state"] == "completed" else intent["state"] if intent else "missing", "completed": bool(intent and intent["state"] == "completed"), "receipt": intent.get("receipt") if intent else None}


def _validate_response(response: Mapping[str, Any], wire: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(response, Mapping) or set(response) != _SENDER_RESPONSE_KEYS or response.get("status_code") != _ABANDONMENT_HTTP_STATUS:
        raise LegacyAbandonmentError("Psychlo rejected legacy abandonment")
    body = {key: value for key, value in response.items() if key != "status_code"}
    if set(body) != _RESPONSE_KEYS or body.get("accepted") is not True or body.get("actionId") != wire["actionId"] or body.get("actionDigest") != wire["actionDigest"] or body.get("roundId") != wire["roundId"] or body.get("requestDigest") != wire["requestDigest"] or body.get("status") not in {STATUS, "already-abandoned"}:
        raise LegacyAbandonmentError("Psychlo rejected legacy abandonment")
    return body


def execute_legacy_abandonment(*, bridge: Any, plan_id: str) -> dict[str, Any]:
    """Send one exact signed peer action; retries are idempotent."""
    primary = _primary(bridge)
    plan = primary.load_admin_change_plan(plan_id)
    metadata = plan.adapter_metadata.get("legacy_abandonment") if isinstance(plan.adapter_metadata, Mapping) else None
    successor_id = metadata.get("successorPlanId") if isinstance(metadata, Mapping) else None
    if not isinstance(successor_id, str):
        raise LegacyAbandonmentError("abandonment successor identity is missing")
    action_id = f"legacy-abandonment:{plan.target}:{successor_id}"
    intent = bridge.store.legacy_abandonment(action_id)
    if intent is None:
        raise LegacyAbandonmentError("legacy abandonment intent is missing")
    try:
        _require_approved_sisko_plan(plan, AdminChangeKind.PSYCHLO_LEGACY_ABANDONMENT, plan.target)
    except LegacyAbandonmentError:
        # A crash may have occurred after the reversible bridge reservation but
        # before the primary execution claim.  With no primary claim, no peer
        # send can have begun, so a canceled/replaced authority releases it.
        if intent["state"] == "peer-pending" and primary.psychlo_legacy_abandonment_execution_claim(plan_id) is None:
            bridge.store.release_unsent_legacy_abandonment_reservation(
                action_id, intent["actionDigest"], now=_now(bridge),
            )
        raise
    action = intent["payload"]
    expected = _expected_plan(action, plan_id)
    plan_digest = _immutable_plan_digest(plan)
    wire = _validate_wire(action.get("wire"), action)
    if plan_digest != _immutable_plan_digest(expected) or action.get("planDigest") != plan_digest or intent["actionDigest"] != wire["actionDigest"]:
        raise LegacyAbandonmentError("approved abandonment plan or action identity changed")
    if intent["state"] == "completed":
        try:
            primary.claim_psychlo_legacy_abandonment_execution(
                plan_id, action_id, intent["actionDigest"], plan_digest, claimed_at=_now(bridge),
            )
        except ValueError as error:
            raise LegacyAbandonmentError("exact approved Sisko plan execution claim failed") from error
        primary.complete_psychlo_legacy_abandonment_execution(
            plan_id, action_id, intent["actionDigest"], completed_at=_now(bridge),
        )
        return {"accepted": True, "replay": True, "status": STATUS, "receipt": intent["receipt"], "actionId": action_id}
    current_action, _ = _snapshot(bridge, primary, plan.target, action["observationPlanId"], action["successorPlan"], allow_existing_abandonment=True, allow_fence=intent["state"] == "peer-pending", delivery_conversation_id=action.get("deliveryConversationId"))
    if _action_core(current_action) != _action_core(action):
        raise LegacyAbandonmentError("current bridge or observation identity differs from staged action")
    envelope = _transport_envelope(action, current_action, plan, wire)
    bridge.store.claim_legacy_abandonment(action_id, intent["actionDigest"], now=_now(bridge))
    try:
        primary.claim_psychlo_legacy_abandonment_execution(
            plan_id, action_id, intent["actionDigest"], plan_digest, claimed_at=_now(bridge),
        )
    except ValueError as error:
        # The peer sender is strictly below this point.  Release only when the
        # primary store proves that no irreversible execution claim exists.
        if primary.psychlo_legacy_abandonment_execution_claim(plan_id) is None:
            bridge.store.release_unsent_legacy_abandonment_reservation(
                action_id, intent["actionDigest"], now=_now(bridge),
            )
        raise LegacyAbandonmentError("exact approved Sisko plan execution claim failed") from error
    try:
        raw_response = bridge.sender("round-legacy-abandon", action_id, envelope)
    except Exception:
        # A transport/process failure is recoverable: leave the outbox in
        # peer-pending so the exact action can be replayed later.
        raise
    # Any invalid, malformed, or truncated response is an ambiguous transport
    # outcome: Psychlo may already have committed.  Preserve peer-pending and
    # replay the exact action until an authenticated success/already receipt is
    # observed.  The current peer contract has no provably pre-commit semantic
    # rejection, so no response can terminalize this intent as rejected.
    response = _validate_response(raw_response, wire)
    receipt = {**response, "status": STATUS, "actionId": action_id, "actionDigest": action["actionDigest"], "roundId": action["roundId"], "requestDigest": action["requestDigest"]}
    completed = bridge.store.complete_legacy_abandonment(action_id, intent["actionDigest"], receipt, now=_now(bridge))
    primary.complete_psychlo_legacy_abandonment_execution(
        plan_id, action_id, intent["actionDigest"], completed_at=_now(bridge),
    )
    return {"accepted": True, "replay": False, "status": STATUS, "receipt": completed["receipt"], "actionId": action_id}
