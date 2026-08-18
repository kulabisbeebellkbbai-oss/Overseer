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
from .psychlo_process_attestation import SCHEMA as PROCESS_OBSERVATION_SCHEMA, _validate_process_observation_row, admin_plan_digest


SCHEMA = "psychlo.legacy-round-abandon.v1"
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


def _delivery_digest(delivery: Mapping[str, Any]) -> str:
    selected = {
        "requestDigest": delivery.get("requestDigest"),
        "capabilityHash": delivery.get("capabilityHash"),
        "binding": delivery.get("binding"),
        "submittedPhase": "submitted",
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
        manifest.get("schemaVersion") != PROCESS_OBSERVATION_SCHEMA
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


def _snapshot(bridge: Any, primary: Any, round_id: str, observation_plan_id: str, successor: Mapping[str, str], *, allow_existing_abandonment: bool = False, allow_fence: bool = False) -> tuple[dict[str, Any], AdminChangePlan]:
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
    delivery = bridge.store.round_prompt_delivery(round_id)
    if delivery is None or delivery.get("phase") not in ({"submitted", "abandonment-fence"} if allow_fence else {"submitted"}):
        raise LegacyAbandonmentError("submitted prompt delivery is required")
    if delivery.get("requestDigest") != request_digest or delivery.get("capabilityHash") != capability_hash:
        raise LegacyAbandonmentError("prompt delivery binding is not exact")
    binding = bridge.store.round_binding(round_id)
    if binding is None or binding != delivery.get("binding"):
        raise LegacyAbandonmentError("round execution binding is not exact")
    prompt_digest = _digest(delivery.get("promptDigest"), "prompt digest")
    delivery_digest = _delivery_digest(delivery)
    _digest(delivery_digest, "delivery digest")
    bridge_evidence = manifest.get("bridge")
    expected_binding_digest = hashlib.sha256(json.dumps(binding, separators=(",", ":")).encode()).hexdigest()
    if not isinstance(bridge_evidence, Mapping) or bridge_evidence.get("dispatchState") != "started" or bridge_evidence.get("resultPresent") is not False or bridge_evidence.get("deliveryPhase") != "submitted" or bridge_evidence.get("recoveryPresent") is not False or bridge_evidence.get("failurePresent") is not False or bridge_evidence.get("cancelPresent") is not False or bridge_evidence.get("requestDigest") != request_digest or bridge_evidence.get("capabilityHash") != capability_hash or bridge_evidence.get("bindingDigest") != expected_binding_digest or bridge_evidence.get("promptDigest") != prompt_digest:
        raise LegacyAbandonmentError("historical bridge evidence is stale")
    forbidden_tables = ("round_recoveries", "operational_failure_intents", "round_cancellations")
    if any(bridge.store.connection.execute(f"SELECT 1 FROM {table} WHERE round_id=? LIMIT 1", (round_id,)).fetchone() is not None for table in forbidden_tables):
        raise LegacyAbandonmentError("round already has a recovery, failure, cancellation, or abandonment intent")
    existing_abandonment = bridge.store.legacy_abandonment(f"legacy-abandonment:{round_id}:{successor.get('successorPlanId', '')}")
    if existing_abandonment is not None and not allow_existing_abandonment:
        raise LegacyAbandonmentError("round already has an abandonment intent")
    original_plan_id = _id(request.get("planId"), "original plan id")
    original_plan_version = _id(request.get("planVersion"), "original plan version")
    for name in ("successorPlanId", "successorPlanVersion", "successorConversationId", "successorThreadId"):
        _id(successor.get(name), name)
    if successor["successorPlanId"] == original_plan_id or successor["successorPlanVersion"] == original_plan_version:
        raise LegacyAbandonmentError("successor plan identity must be distinct")
    action_id = f"legacy-abandonment:{round_id}:{successor['successorPlanId']}"
    action = {
        "schemaVersion": SCHEMA, "actionId": action_id, "roundId": round_id,
        "projectId": _id(request.get("projectId"), "project id"), "requestDigest": request_digest,
        "capabilityHash": capability_hash, "observationId": _id(observation.get("observationId"), "observation id"),
        "observationDigest": observation_digest, "observationPlanDigest": observation_plan_digest,
        "delivery": {"phase": "submitted", "promptDigest": prompt_digest, "deliveryDigest": delivery_digest, "bindingDigest": expected_binding_digest},
        "originalPlan": {"planId": original_plan_id, "planVersion": original_plan_version},
        "successorPlan": dict(successor), "observationPlanId": observation_plan_id, "reason": REASON,
    }
    action_digest = canonical_digest(action)
    action["actionDigest"] = action_digest
    wire = {"schemaVersion": SCHEMA, "actionId": action_id, "actionDigest": action_digest, "roundId": round_id, "projectId": action["projectId"], "requestDigest": request_digest, "planId": original_plan_id, "planVersion": original_plan_version, "observationId": action["observationId"], "observationDigest": observation_digest, "reason": REASON, "occurredAt": _now(bridge)}
    action["wire"] = wire
    return action, source_plan


def stage_legacy_abandonment(*, bridge: Any, plan_id: str, observation_plan_id: str, round_id: str, successor_plan_id: str, successor_plan_version: str, successor_conversation_id: str, successor_thread_id: str) -> dict[str, Any]:
    """Stage one non-executable authority plan and bridge outbox intent."""
    primary = _primary(bridge)
    successor = {"successorPlanId": successor_plan_id, "successorPlanVersion": successor_plan_version, "successorConversationId": successor_conversation_id, "successorThreadId": successor_thread_id}
    action, _source_plan = _snapshot(bridge, primary, round_id, observation_plan_id, successor)
    action_id = f"legacy-abandonment:{round_id}:{successor_plan_id}"
    existing_intent = bridge.store.legacy_abandonment(action_id)
    if existing_intent is not None:
        if existing_intent["payload"].get("planId") != plan_id:
            raise LegacyAbandonmentError("legacy abandonment action identity conflict")
        return {"staged": True, "historical": True, "authoritative": False, "executable": False, "actionId": action_id, "actionDigest": existing_intent["actionDigest"], "planId": plan_id, "roundId": round_id, "state": existing_intent["state"], "replayed": True}
    metadata = action
    plan = plan_psychlo_legacy_abandonment(
        plan_id, round_id, action["observationId"], action["observationDigest"], action["observationPlanDigest"], action["requestDigest"], action["capabilityHash"], action["delivery"]["deliveryDigest"], action["originalPlan"]["planId"], action["originalPlan"]["planVersion"], successor_plan_id, successor_plan_version, successor_conversation_id, successor_thread_id,
    )
    metadata["planId"] = plan_id
    metadata["planDigest"] = _immutable_plan_digest(plan)
    metadata["actionDigest"] = canonical_digest({key: value for key, value in metadata.items() if key not in {"actionDigest", "wire", "planDigest"}} | {"planDigest": metadata["planDigest"]})
    # Rebuild the signed wire after the final action digest is fixed.
    metadata["wire"] = {**metadata["wire"], "actionDigest": metadata["actionDigest"]}
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
    return plan_psychlo_legacy_abandonment(plan_id, action["roundId"], action["observationId"], action["observationDigest"], action["observationPlanDigest"], action["requestDigest"], action["capabilityHash"], action["delivery"]["deliveryDigest"], action["originalPlan"]["planId"], action["originalPlan"]["planVersion"], action["successorPlan"]["successorPlanId"], action["successorPlan"]["successorPlanVersion"], action["successorPlan"]["successorConversationId"], action["successorPlan"]["successorThreadId"])


def _action_core(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"actionDigest", "wire", "planDigest", "planId"}}


def _action_digest_content(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in {"actionDigest", "wire", "planDigest"}}


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
    if not isinstance(response, Mapping) or response.get("accepted") is not True or response.get("actionId") != wire["actionId"] or response.get("actionDigest") != wire["actionDigest"] or response.get("roundId") != wire["roundId"] or response.get("requestDigest") != wire["requestDigest"] or response.get("status") not in {STATUS, "already-abandoned"}:
        raise LegacyAbandonmentError("Psychlo rejected legacy abandonment")
    return dict(response)


def execute_legacy_abandonment(*, bridge: Any, plan_id: str) -> dict[str, Any]:
    """Send one exact signed peer action; retries are idempotent."""
    primary = _primary(bridge)
    plan = primary.load_admin_change_plan(plan_id)
    _require_approved_sisko_plan(plan, AdminChangeKind.PSYCHLO_LEGACY_ABANDONMENT, plan.target)
    metadata = plan.adapter_metadata.get("legacy_abandonment") if isinstance(plan.adapter_metadata, Mapping) else None
    successor_id = metadata.get("successorPlanId") if isinstance(metadata, Mapping) else None
    if not isinstance(successor_id, str):
        raise LegacyAbandonmentError("abandonment successor identity is missing")
    action_id = f"legacy-abandonment:{plan.target}:{successor_id}"
    intent = bridge.store.legacy_abandonment(action_id)
    if intent is None:
        raise LegacyAbandonmentError("legacy abandonment intent is missing")
    action = intent["payload"]
    expected = _expected_plan(action, plan_id)
    if _immutable_plan_digest(plan) != _immutable_plan_digest(expected) or intent["actionDigest"] != canonical_digest(_action_digest_content(action) | {"planDigest": action.get("planDigest")}):
        raise LegacyAbandonmentError("approved abandonment plan or action identity changed")
    if intent["state"] == "completed":
        return {"accepted": True, "replay": True, "status": STATUS, "receipt": intent["receipt"], "actionId": action_id}
    current_action, _ = _snapshot(bridge, primary, plan.target, action["observationPlanId"], action["successorPlan"], allow_existing_abandonment=True, allow_fence=intent["state"] == "peer-pending")
    if _action_core(current_action) != _action_core(action):
        raise LegacyAbandonmentError("current bridge or observation identity differs from staged action")
    claimed = bridge.store.claim_legacy_abandonment(action_id, intent["actionDigest"], now=_now(bridge))
    try:
        raw_response = bridge.sender("round-legacy-abandon", action_id, action["wire"])
    except Exception:
        # A transport/process failure is recoverable: leave the outbox in
        # peer-pending so the exact action can be replayed later.
        raise
    try:
        response = _validate_response(raw_response, action["wire"])
    except Exception as error:
        bridge.store.reject_legacy_abandonment(action_id, intent["actionDigest"], str(error), now=_now(bridge))
        raise
    receipt = {**response, "status": STATUS, "actionId": action_id, "actionDigest": action["actionDigest"], "roundId": action["roundId"], "requestDigest": action["requestDigest"]}
    completed = bridge.store.complete_legacy_abandonment(action_id, intent["actionDigest"], receipt, now=_now(bridge))
    return {"accepted": True, "replay": False, "status": STATUS, "receipt": completed["receipt"], "actionId": action_id}
