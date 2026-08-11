"""Private, single-stream protocol bridge between Psychlo and Overseer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import inspect
import json
from pathlib import Path
import os
import secrets
import sqlite3
import stat
from typing import Any, Callable, Mapping
from urllib.request import Request, urlopen

from .psychlo_contracts import (
    ContractError,
    canonical_digest,
    learning_observation_digest,
    parse_adoption_evidence,
    parse_external_round,
    parse_learning_observation,
    parse_learning_advisory,
    parse_registry_candidate,
    parse_telemetry_checkpoint,
)


MAX_BODY_BYTES = 256 * 1024
PEER_VERSION = b"psychlo-overseer-v1\0"


def _canonical(direction: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return PEER_VERSION + direction.encode() + b"\0" + timestamp.encode() + b"\0" + nonce.encode() + b"\0" + body


def sign_peer_message(secret: bytes, direction: str, kind: str, message_id: str, timestamp: str, nonce: str, body: bytes, *, authority: str = "127.0.0.1:8766") -> dict[str, str]:
    signature = hmac.new(secret, _canonical(direction, timestamp, nonce, body), hashlib.sha256).hexdigest()
    return {
        "host": authority,
        "content-type": "application/json",
        "content-length": str(len(body)),
        "x-psychlo-peer-kind": kind,
        "x-psychlo-peer-message-id": message_id,
        "x-psychlo-peer-timestamp": timestamp,
        "x-psychlo-peer-nonce": nonce,
        "x-psychlo-peer-signature": signature,
    }


class _LegacyPsychloBridgeStore:
    def __init__(self, filename: str | Path):
        self.filename = Path(filename)
        self.filename.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self.filename.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("Psychlo bridge directory must be private")
        if self.filename.exists() or self.filename.is_symlink():
            metadata = self.filename.stat(follow_symlinks=False)
            if self.filename.is_symlink() or not self.filename.is_file() or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ValueError("Psychlo bridge database must be private")
        self.connection = sqlite3.connect(self.filename, check_same_thread=False, isolation_level=None)
        self.filename.chmod(0o600)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=1000")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS peer_nonces(nonce TEXT PRIMARY KEY, message_id TEXT NOT NULL, claimed_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rounds(round_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, capability_hash TEXT NOT NULL UNIQUE, capability_token TEXT NOT NULL, dispatch_state TEXT NOT NULL, result_json TEXT, result_forwarded INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS decisions(decision_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT, reason TEXT);
            CREATE TABLE IF NOT EXISTS projects(project_id TEXT PRIMARY KEY, registration_json TEXT NOT NULL, scheduling_json TEXT NOT NULL);
        """)

    def claim_nonce(self, nonce: str, message_id: str, claimed_at: str) -> bool:
        cursor = self.connection.execute("INSERT OR IGNORE INTO peer_nonces VALUES (?,?,?)", (nonce, message_id, claimed_at))
        return cursor.rowcount == 1

    def get_round(self, round_id: str):
        row = self.connection.execute("SELECT request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded FROM rounds WHERE round_id=?", (round_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), row[2], row[3], row[4], json.loads(row[5]) if row[5] else None, bool(row[6]))

    def active_round(self) -> str | None:
        row = self.connection.execute("SELECT round_id FROM rounds WHERE result_json IS NULL LIMIT 1").fetchone()
        return None if row is None else str(row[0])

    def record_round(self, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str) -> None:
        self.connection.execute("INSERT INTO rounds VALUES (?,?,?,?,?,'pending',NULL,0)", (request["roundId"], _dump(request), _dump(receipt), _token_hash(capability), capability))

    def mark_dispatch_started(self, round_id: str) -> None:
        self.connection.execute("UPDATE rounds SET dispatch_state='started' WHERE round_id=? AND dispatch_state='pending'", (round_id,))

    def mark_dispatched(self, round_id: str, receipt: Mapping[str, Any]) -> None:
        self.connection.execute("UPDATE rounds SET dispatch_state='dispatched',receipt_json=? WHERE round_id=?", (_dump(receipt), round_id))

    def round_for_capability(self, capability: str):
        row = self.connection.execute("SELECT request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded FROM rounds WHERE capability_hash=?", (_token_hash(capability),)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), row[2], row[3], row[4], json.loads(row[5]) if row[5] else None, bool(row[6]))

    def record_result(self, round_id: str, result: Mapping[str, Any]) -> None:
        self.connection.execute("UPDATE rounds SET result_json=? WHERE round_id=? AND result_json IS NULL", (_dump(result), round_id))

    def mark_forwarded(self, round_id: str) -> None:
        self.connection.execute("UPDATE rounds SET result_forwarded=1 WHERE round_id=?", (round_id,))

    def record_decision(self, request: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
        self.connection.execute("INSERT OR IGNORE INTO decisions VALUES (?,?,?,'staged',NULL,NULL,NULL)", (request["decisionId"], _dump(request), _dump(receipt)))

    def decision(self, decision_id: str) -> tuple[dict[str, Any], dict[str, Any], str] | None:
        row = self.connection.execute("SELECT request_json,receipt_json,status FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), str(row[2]))

    def list_staged_decisions(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT request_json,receipt_json,status FROM decisions WHERE status='staged' ORDER BY rowid").fetchall()
        return [{"request": json.loads(row[0]), "receipt": json.loads(row[1]), "status": row[2]} for row in rows]

    def decide(self, decision_id: str, status: str, decided_by: str, decided_at: str, reason: str) -> None:
        cursor = self.connection.execute("UPDATE decisions SET status=?,decided_by=?,decided_at=?,reason=? WHERE decision_id=? AND status='staged'", (status, decided_by, decided_at, reason, decision_id))
        if cursor.rowcount != 1:
            raise ValueError("an exact staged Psychlo decision is required")

    def project(self, project_id: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
        row = self.connection.execute("SELECT registration_json,scheduling_json FROM projects WHERE project_id=?", (project_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]))

    def record_project(self, project_id: str, registration: Mapping[str, Any], scheduling: Mapping[str, Any]) -> None:
        self.connection.execute("INSERT INTO projects VALUES (?,?,?)", (project_id, _dump(registration), _dump(scheduling)))


# Keep the historical import stable while the 1.0 bridge uses the expanded
# isolated projection store.  The new store retains all legacy round/decision
# methods, so existing callers do not cross the external-execution boundary.
from .psychlo_store import PsychloBridgeStore


def verify_peer_request(secret: bytes, store: PsychloBridgeStore, expected_kind: str, body: bytes, headers: Mapping[str, str], *, now: str | None = None) -> dict[str, Any]:
    if len(secret) < 32 or len(secret) > 4096 or not body or len(body) > MAX_BODY_BYTES:
        raise ValueError("invalid_request")
    required = ("host", "content-type", "content-length", "x-psychlo-peer-kind", "x-psychlo-peer-message-id", "x-psychlo-peer-timestamp", "x-psychlo-peer-nonce", "x-psychlo-peer-signature")
    if any(not isinstance(headers.get(name), str) or "," in headers[name] for name in required):
        raise ValueError("invalid_headers")
    if headers["host"] != "127.0.0.1:8766" or headers["content-type"] != "application/json" or headers["x-psychlo-peer-kind"] != expected_kind or headers["content-length"] != str(len(body)):
        raise ValueError("invalid_headers")
    timestamp = _time(headers["x-psychlo-peer-timestamp"])
    current = _time(now or datetime.now(UTC).isoformat())
    if abs((current - timestamp).total_seconds()) > 300:
        raise ValueError("invalid_timestamp")
    nonce = headers["x-psychlo-peer-nonce"]
    signature = headers["x-psychlo-peer-signature"]
    if len(nonce) < 16 or len(nonce) > 160 or len(signature) != 64:
        raise ValueError("invalid_signature")
    expected = hmac.new(secret, _canonical("psychlo-to-overseer", headers["x-psychlo-peer-timestamp"], nonce, body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("invalid_signature")
    try:
        message = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_message") from error
    if not isinstance(message, dict) or set(message) != {"kind", "messageId", "occurredAt", "payload"} or message["kind"] != expected_kind or message["messageId"] != headers["x-psychlo-peer-message-id"]:
        raise ValueError("invalid_message")
    if not store.claim_nonce(nonce, message["messageId"], current.isoformat()):
        raise ValueError("replay")
    return message


def derive_usage_snapshot(history: list[dict[str, Any]], *, policy_version: str, now: str | None = None) -> dict[str, Any]:
    if not history:
        raise ValueError("Codex usage history is required")
    newest = history[0]
    newest_at = _time(str(newest["observed_at"]))
    newest_window = _weekly_window(newest)
    target = newest_at - timedelta(days=1)
    candidates = [item for item in history[1:] if _weekly_window(item).get("resets_at") == newest_window.get("resets_at") and _time(str(item["observed_at"])) <= target]
    if not candidates: raise ValueError("same-reset prior-day usage history is required")
    prior = min(candidates, key=lambda item: abs((_time(str(item["observed_at"])) - target).total_seconds()))
    prior_used = float(_weekly_window(prior).get("used_percent") or 0)
    current_used = float(newest_window.get("used_percent") or 0)
    # Provider rolling usage is authoritative.  Lead-reported round costs are
    # an audit signal only and must not be subtracted from that delta.
    prior_day_used = max(0.0, current_used - prior_used)
    unused = max(0.0, 100.0 / 7.0 - prior_day_used)
    captured = str(newest["observed_at"])
    snapshot_id = "codex-usage-" + hashlib.sha256((captured + str(newest_window.get("resets_at"))).encode()).hexdigest()[:24]
    return {
        "correlationId": f"psychlo:{snapshot_id}", "idempotencyKey": snapshot_id, "occurredAt": captured,
        "snapshot": {"id": snapshot_id, "sourceId": "overseer", "capturedAt": captured, "policyVersion": policy_version, "unusedPriorDayWeeklyCapacity": unused, "weeklyRemainingCapacity": float(newest_window.get("remaining_percent") or 0)},
    }


class PsychloBridge:
    def __init__(self, *, store: PsychloBridgeStore, dispatcher: Callable[[str, str], str], sender: Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]], callback_origin: str, clock: Callable[[], str] | None = None, token_factory: Callable[[], str] | None = None):
        self.store, self.dispatcher, self.sender = store, dispatcher, sender
        self.peer_secret = getattr(sender, "secret", None)
        self.callback_origin = callback_origin.rstrip("/")
        self.clock = clock or (lambda: datetime.now(UTC).isoformat())
        self.token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._recover_decision_intents()

    def request_round(self, request: Mapping[str, Any]) -> dict[str, Any]:
        _require_round(request)
        if any(item["request"].get("projectId") == request["projectId"] for item in self.store.list_staged_decisions()) or self.store.external_gate_pending(str(request["projectId"])) or self.store.external_gate_blocked(str(request["projectId"])):
            raise ValueError("decision_pending")
        existing = self.store.get_round(str(request["roundId"]))
        if existing:
            if existing[0] != dict(request): raise ValueError("round identity conflict")
            if existing[4] != "dispatched": return self._dispatch_reserved(existing[0], existing[3], existing[1])
            return {"accepted": True, "receipt": existing[1]}
        if self.store.active_round() is not None: raise ValueError("single_stream_busy")
        capability = self.token_factory()
        receipt = {**request, "sourceId": request["projectLeadId"], "provenanceId": f"overseer-dispatch:{request['roundId']}", "status": "accepted"}
        self.store.record_round(request, receipt, capability)
        return self._dispatch_reserved(dict(request), capability, receipt)

    def register_project(self, registration: Mapping[str, Any]) -> dict[str, Any]:
        envelope = registration.get("envelope")
        receipt = registration.get("receipt")
        if not isinstance(envelope, dict) or not isinstance(receipt, dict): raise ValueError("project registration is invalid")
        project = envelope.get("project"); lead = envelope.get("projectLead"); plan = envelope.get("plan")
        if not isinstance(project, dict) or not isinstance(lead, dict) or not isinstance(plan, dict): raise ValueError("project registration is invalid")
        project_id = _required_string(project, "id"); project_lead_id = _required_string(lead, "id"); receipt_id = _required_string(receipt, "receiptId")
        existing = self.store.project(project_id)
        if existing:
            if existing[0] != dict(registration): raise ValueError("project registration conflict")
            return {"accepted": True}
        tasks = plan.get("tasks")
        constraints = plan.get("constraints", [])
        if not isinstance(tasks, list) or not tasks or len(tasks) > 128 or not isinstance(constraints, list): raise ValueError("project registration is invalid")
        scheduling = {
            "projectId": project_id, "projectLeadId": project_lead_id, "state": "managed",
            "remainingEffort": "trivial" if len(tasks) == 1 else "standard",
            "hasSecurityImpact": any("security" in str(item).lower() for item in constraints),
            "hasDependencyImpact": any(isinstance(item, dict) and bool(item.get("dependencyIds")) for item in tasks),
            "gateDistance": len(tasks), "expectedUsageCost": max(1, min(10, (len(tasks) + 1) // 2)),
            "correlationId": f"psychlo-scheduling:{receipt_id}", "idempotencyKey": f"psychlo-scheduling:{receipt_id}", "occurredAt": self.clock(),
        }
        response = self.sender("scheduling-input", scheduling["idempotencyKey"], scheduling)
        if response.get("accepted") is not True: raise ValueError("Psychlo rejected project scheduling")
        self.store.record_project(project_id, registration, scheduling)
        return {"accepted": True}

    def reconcile_round(self, request: Mapping[str, Any]) -> dict[str, Any]:
        existing = self.store.get_round(str(request.get("roundId", "")))
        if existing and existing[0] == dict(request):
            if existing[4] != "dispatched": return self._dispatch_reserved(existing[0], existing[3], existing[1])
            return {"accepted": True, "receipt": existing[1]}
        return {"accepted": True, "receipt": {**request, "sourceId": request.get("projectLeadId"), "provenanceId": f"overseer-unknown:{request.get('roundId')}", "status": "unknown"}}

    def receive_round_result(self, capability: str, result: Mapping[str, Any]) -> dict[str, Any]:
        record = self.store.round_for_capability(capability)
        if record is None: raise ValueError("unknown round capability")
        request, _, _, _, _, stored_result, forwarded = record
        _require_bound_result(request, result)
        if stored_result is not None and stored_result != dict(result): raise ValueError("round result conflict")
        if stored_result is None: self.store.record_result(str(request["roundId"]), result)
        if not forwarded:
            response = dict(self.sender("round-result", str(result["provenanceId"]), result))
            if response.get("accepted") is not True: raise ValueError("Psychlo rejected round result")
            self.store.mark_forwarded(str(request["roundId"]))
        return {"accepted": True}

    def _dispatch_reserved(self, request: Mapping[str, Any], capability: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
        self.store.mark_dispatch_started(str(request["roundId"]))
        provider_reference = self.dispatcher(str(request["projectLeadId"]), self._round_prompt(request, capability))
        delivered = {**receipt, "provenanceId": str(provider_reference)}
        self.store.mark_dispatched(str(request["roundId"]), delivered)
        return {"accepted": True, "receipt": delivered}

    def stage_decision(self, request: Mapping[str, Any]) -> dict[str, Any]:
        decision_id = _required_string(request, "decisionId")
        if decision_id.startswith("roadex:external:"):
            receipt = {**request, "sourceId": "overseer", "provenanceId": f"roadex:{decision_id}", "status": "staged"}
            return self.store.stage_external_decision(request, receipt)
        existing = self.store.decision(decision_id)
        if existing:
            if existing[0] != dict(request): raise ValueError("decision identity conflict")
            return {"accepted": True, "receipt": existing[1]}
        receipt = {**request, "sourceId": "overseer", "provenanceId": f"roadex:{decision_id}", "status": "staged"}
        self.store.record_decision(request, receipt)
        return {"accepted": True, "receipt": receipt}

    def list_decisions(self) -> list[dict[str, Any]]:
        items = []
        for record in self.store.list_staged_decisions():
            request = record["request"]
            digest = hashlib.sha256(_dump(request).encode()).hexdigest()
            items.append({"id": f"roadex-human-decision.{request['decisionId']}", "source": "Roadex", "owner": "Sisko", "human_approval_required": True, "plan_id": request["decisionId"], "plan_digest": digest, "kind": "psychlo-project-gate", "title": f"Psychlo decision for {request['projectId']}", "decision": request["question"], "explanation": "Approval resumes only this exact blocked Psychlo project gate.", "impact": ["Return the exact decision outcome to Psychlo.", "Allow the globally single-stream coordinator to continue only if approved."], "risks": ["Approval may authorize the project action described in the question."], "rollback": ["Deny or request revision before work resumes."], "status": "staged", "ready": True, "blockers": []})
        return items

    def decide(self, decision_id: str, decision: str, decided_by: str, reason: str) -> dict[str, Any]:
        if decision not in {"approve", "deny", "request_revision"} or not decided_by.strip(): raise ValueError("exact human decision is required")
        record = self.store.decision(decision_id)
        status = {"approve": "approved", "deny": "rejected", "request_revision": "rejected"}[decision]
        now = self.clock()
        if decision_id.startswith("roadex:external:"):
            if record is None:
                raise ValueError("an exact staged Psychlo decision is required")
            if record[2] != "staged" and record[2] != status:
                raise ValueError("external decision conflict")
            return self._decide_external(record[0], status, decided_by, now, reason)
        if record is None or record[2] != "staged": raise ValueError("an exact staged Psychlo decision is required")
        request = record[0]
        outcome = {**request, "sourceId": "overseer", "provenanceId": f"roadex-outcome:{decision_id}:{status}", "status": status}
        response = self.sender("decision-outcome", str(request["decisionId"]), outcome)
        if response.get("accepted") is not True: raise ValueError("Psychlo rejected decision outcome")
        self.store.decide(decision_id, status, decided_by, now, reason)
        return {"ok": True, "decision": decision, "action_status": status, "mutation_performed": True, "host_mutation_performed": False}

    def _decide_external(self, request: Mapping[str, Any], status: str, decided_by: str, decided_at: str, reason: str) -> dict[str, Any]:
        reconciliation_id = str(request["decisionId"]).removeprefix("roadex:external:")
        external = self.store.external_execution(reconciliation_id)
        if external is None or external.get("gateDecisionId") != request["decisionId"]:
            raise ValueError("external decision identity conflict")
        envelope = external["payload"]
        workflow_id = external.get("gateWorkflowId")
        if not isinstance(workflow_id, str) or not workflow_id.strip():
            raise ValueError("external decision workflow conflict")
        expected = self._external_decision_request(envelope, workflow_id)
        if dict(request) != expected:
            raise ValueError("external decision identity conflict")
        prior_decision = self.store.decision(str(request["decisionId"]))
        prior_external = external["receipt"].get("decisionStatus")
        if prior_decision and prior_decision[2] == status and prior_external == status:
            return {"ok": True, "decision": "approve" if status == "approved" else "deny", "action_status": status, "mutation_performed": True, "host_mutation_performed": False}
        if prior_decision and prior_decision[2] != "staged":
            raise ValueError("external decision conflict")
        if prior_external in {"approved", "rejected", "expired"} and prior_external != status:
            raise ValueError("external decision conflict")
        outcome = {**request, "sourceId": "overseer", "provenanceId": f"roadex-outcome:{request['decisionId']}:{status}", "status": status}
        self.store.record_decision_intent(request, outcome, decided_by, decided_at, reason)
        self._deliver_decision_intent(str(request["decisionId"]))
        return {"ok": True, "decision": "approve" if status == "approved" else "deny", "action_status": status, "mutation_performed": True, "host_mutation_performed": False}

    def _deliver_decision_intent(self, decision_id: str) -> None:
        intent = self.store.decision_intent(decision_id)
        if intent is None or intent["status"] == "settled":
            return
        response = self.sender("decision-outcome", decision_id, intent["outcome"])
        if response.get("accepted") is not True:
            raise ValueError("Psychlo rejected decision outcome")
        reconciliation_id = decision_id.removeprefix("roadex:external:")
        status = str(intent["outcome"]["status"])
        self.store.settle_external_decision(decision_id, status, intent["decidedBy"], intent["decidedAt"], intent["reason"], reconciliation_id)

    def _recover_decision_intents(self) -> None:
        for decision_id in self.store.pending_decision_intents():
            try:
                self._deliver_decision_intent(decision_id)
            except Exception:
                continue

    def _round_prompt(self, request: Mapping[str, Any], capability: str) -> str:
        callback = f"{self.callback_origin}/psychlo/round-results/{capability}"
        return "\n".join((
            "You are the approved A-Team project lead and authority for this project.",
            "Invoke Superpowers with the approved project plan, your team context, dependencies, and acceptance criteria.",
            "Coordinate the actual development through the assigned project team. Keep coordination autonomous except at explicit gates.",
            "Perform exactly one conservative bounded work round described by this immutable request:",
            json.dumps(dict(request), sort_keys=True),
            "When the round reaches a terminal completed, blocked, or explicit-gate state, POST one JSON RoundResult to this one-use loopback callback:",
            callback,
            "The result must echo every request field and include sourceId, provenanceId, status, actualUsageCost, deliveredScope, remainingEstimate, blockers, questions, reachedExplicitGates, and occurredAt.",
        ))

    def emit_usage(self, history: list[dict[str, Any]], policy_version: str) -> Mapping[str, Any]:
        if not history: raise ValueError("Codex usage history is required")
        payload = derive_usage_snapshot(history, policy_version=policy_version)
        return self.sender("usage-snapshot", str(payload["idempotencyKey"]), payload)

    def status(self) -> dict[str, Any]:
        return {"configured": True, "projections": self.store.projection_counts(), "activeRound": self.store.active_round(), "pendingDecisions": len(self.store.list_staged_decisions())}

    # ---- Psychlo 1.0 immutable bridge projections ---------------------
    def record_telemetry_checkpoint(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Persist one hybrid token sample with monotonic/provider-bound counters."""
        payload = {**payload, "schemaVersion": payload.get("schemaVersion", "psychlo.telemetry.v1")}
        try:
            checkpoint = parse_telemetry_checkpoint(payload)
        except ContractError as error:
            raise ValueError(str(error)) from error
        identity = {key: value for key, value in checkpoint.items() if key != "delta"}
        digest = canonical_digest(identity)
        existing = self.store.telemetry_checkpoint(checkpoint["checkpointId"])
        if existing is not None:
            if self.store.telemetry_digest(checkpoint["checkpointId"]) == digest:
                return {"inserted": False, "replay": True, "checkpoint": existing}
            if existing != checkpoint:
                raise ValueError("telemetry checkpoint conflict")
            return {"inserted": False, "replay": True, "checkpoint": existing}
        stream = self.store.telemetry_stream(checkpoint["roundId"])
        prior = stream[-1] if stream else None
        if prior is None and checkpoint["sampleKind"] != "baseline":
            raise ValueError("telemetry baseline is required")
        if prior is not None and (prior["sampleKind"] == "terminal" or checkpoint["sampleKind"] == "baseline"):
            raise ValueError("telemetry stream is terminal or baseline already exists")
        if prior is not None:
            previous = prior["cumulative"]
            current = checkpoint["cumulative"]
            if any(current[key] < previous[key] for key in previous):
                raise ValueError("telemetry cumulative counters must be monotonic")
            if prior.get("providerSnapshotId") != checkpoint.get("providerSnapshotId"):
                raise ValueError("telemetry provider snapshot binding changed")
            checkpoint = {**checkpoint, "delta": {key: current[key] - previous[key] for key in previous}}
        else:
            checkpoint = {**checkpoint, "delta": {key: 0 for key in checkpoint["cumulative"]}}
        inserted = self.store.record_telemetry(checkpoint, digest)
        return {"inserted": inserted, "replay": not inserted, "checkpoint": checkpoint}

    receive_telemetry_checkpoint = record_telemetry_checkpoint

    # Boundary-neutral aliases used by round drivers for baseline, turn,
    # durable-checkpoint, bounded-long-turn, and terminal samples.
    sample_token_checkpoint = record_telemetry_checkpoint
    record_token_sample = record_telemetry_checkpoint

    def record_learning_observation(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        payload = {**payload, "sourceId": payload.get("sourceId", "overseer"), "messageId": payload.get("messageId", payload.get("id", "")), "correlationId": payload.get("correlationId", f"learning:{payload.get('id', '')}"), "idempotencyKey": payload.get("idempotencyKey", f"learning:observation:{payload.get('id', '')}"), "occurredAt": payload.get("occurredAt", self.clock()), "schemaVersion": payload.get("schemaVersion", "psychlo.learning.v1")}
        supplied_digest = payload.pop("digest", None)
        payload.pop("state", None)
        payload.pop("messageId", None)
        try:
            observation = parse_learning_observation(payload)
        except ContractError as error:
            raise ValueError(str(error)) from error
        if supplied_digest is not None:
            expected_digest = learning_observation_digest(observation)
            if supplied_digest != expected_digest:
                raise ValueError("learning observation digest mismatch")
        digest = canonical_digest(observation)
        inserted = self.store.record_learning(observation, digest)
        return {"inserted": inserted, "replay": not inserted, "observation": self.store.learning_observation(observation["id"])}

    receive_learning_observation = record_learning_observation

    def deliver_learning_pending(self, adapters: Mapping[str, Callable[[Mapping[str, Any]], Any]], *, limit: int = 100) -> dict[str, int]:
        """Deliver sanitized observations; adapter errors are durable and isolated."""
        delivered = failed = 0
        for destination in ("skiller", "private-memory"):
            adapter = adapters.get(destination)
            if adapter is None:
                continue
            for observation in self.store.pending_learning(destination, limit):
                try:
                    result = adapter(observation)
                    if inspect.isawaitable(result):
                        import asyncio
                        try:
                            asyncio.get_running_loop()
                        except RuntimeError:
                            asyncio.run(result)
                        else:
                            raise RuntimeError("async adapter requires an async delivery boundary")
                    self.store.transition_learning(observation["id"], destination, "delivered")
                    delivered += 1
                except Exception:
                    self.store.transition_learning(observation["id"], destination, "failed", "adapter-failed")
                    failed += 1
        return {"delivered": delivered, "failed": failed}

    def pull_learning(self, destination: str, adapters: Mapping[str, Callable[[Mapping[str, Any]], Any]], *, limit: int = 100) -> dict[str, int]:
        """Pull bounded observations, deliver them, and ack only successful deliveries."""
        if destination not in {"skiller", "private-memory"}:
            raise ValueError("learning destination is invalid")
        bounded = max(1, min(100, int(limit)))
        response = self.sender("learning-pull", f"learning-pull:{destination}:{self.clock()}", {"destination": destination, "limit": bounded})
        observations = response.get("observations", [])
        if not isinstance(observations, list) or len(observations) > bounded:
            raise ValueError("learning pull response is invalid")
        adapter = adapters.get(destination)
        if adapter is None:
            return {"delivered": 0, "failed": len(observations)}
        delivered = failed = 0
        for raw in observations:
            record = None
            try:
                if not isinstance(raw, Mapping):
                    raise ValueError("learning observation is invalid")
                record = self.record_learning_observation(raw)["observation"]
                result = adapter(record)
                if inspect.isawaitable(result):
                    import asyncio
                    asyncio.run(result)
                ack = self.sender("learning-ack", f"learning-ack:{destination}:{record['id']}:{record['digest']}", {"destination": destination, "id": record["id"], "digest": record["digest"]})
                if ack.get("accepted") is not True:
                    raise ValueError("learning acknowledgment rejected")
                self.store.transition_learning(record["id"], destination, "delivered")
                delivered += 1
            except Exception:
                if record is not None:
                    self.store.transition_learning(record["id"], destination, "failed", "adapter-failed")
                failed += 1
        return {"delivered": delivered, "failed": failed}

    def receive_learning_advisory(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        prior = payload.get("prior", payload)
        try:
            advisory = parse_learning_advisory(prior)
        except ContractError as error:
            raise ValueError(str(error)) from error
        digest = advisory["digest"]
        existing = self.store.learning_advisory(digest)
        if existing is not None and existing != advisory:
            raise ValueError("learning advisory conflict")
        if existing is None:
            self.store.record_learning_advisory(advisory)
        return {"prior": self.store.learning_advisory(digest), "replay": existing is not None}

    def receive_learning_pull(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        destination = payload.get("destination")
        limit = payload.get("limit", 100)
        if destination not in {"skiller", "private-memory"} or not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("learning pull is invalid")
        return {"observations": self.store.pending_learning(destination, min(100, limit))}

    def receive_learning_ack(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        destination, observation_id, digest = payload.get("destination"), payload.get("id"), payload.get("digest")
        if destination not in {"skiller", "private-memory"} or not isinstance(observation_id, str) or not isinstance(digest, str):
            raise ValueError("learning acknowledgment is invalid")
        record = self.store.learning_observation(observation_id)
        if record is None or record["digest"] != digest:
            raise ValueError("learning acknowledgment digest mismatch")
        return {"observation": self.store.transition_learning(observation_id, destination, "delivered")}

    def register_candidate(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        payload = {**payload, "sourceId": payload.get("sourceId", "overseer"), "messageId": payload.get("messageId", payload.get("candidateId", "")), "correlationId": payload.get("correlationId", f"registry:{payload.get('candidateId', '')}"), "idempotencyKey": payload.get("idempotencyKey", f"registry:{payload.get('candidateId', '')}"), "occurredAt": payload.get("occurredAt", self.clock()), "schemaVersion": payload.get("schemaVersion", "psychlo.registry-candidate.v1")}
        try:
            candidate = parse_registry_candidate(payload)
        except ContractError as error:
            raise ValueError(str(error)) from error
        inserted = self.store.record_registry(candidate, canonical_digest(candidate))
        return {"inserted": inserted, "replay": not inserted, "candidate": self.store.registry_candidate(candidate["candidateId"])}

    receive_registry_candidate = register_candidate

    def record_adoption_evidence(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        payload = {**payload, "sourceId": payload.get("sourceId", "overseer"), "messageId": payload.get("messageId", payload.get("assessmentId", "")), "correlationId": payload.get("correlationId", f"adoption:{payload.get('assessmentId', '')}"), "idempotencyKey": payload.get("idempotencyKey", f"adoption:{payload.get('assessmentId', '')}"), "occurredAt": payload.get("occurredAt", self.clock()), "schemaVersion": payload.get("schemaVersion", "psychlo.adoption-evidence.v1")}
        try:
            evidence = parse_adoption_evidence(payload)
        except ContractError as error:
            raise ValueError(str(error)) from error
        candidate = self.store.registry_candidate(evidence["candidateId"])
        if candidate is None or candidate["registryId"] != evidence["registry"]["registryId"] or candidate["registryDigest"] != evidence["registry"]["registryDigest"]:
            raise ValueError("adoption evidence is not bound to a canonical registry candidate")
        registered = {item: (evidence_digest, evidence_kind) for item, evidence_digest, evidence_kind in zip(candidate["evidenceIds"], candidate["evidenceDigests"], candidate["evidenceKinds"])}
        for reference in evidence["evidence"]:
            if registered.get(reference["evidenceId"]) != (reference["digest"], reference["kind"]):
                raise ValueError("adoption evidence registry reference conflict")
        assessment_id = evidence["messageId"]
        inserted = self.store.record_adoption(assessment_id, evidence["candidateId"], evidence, canonical_digest(evidence))
        return {"inserted": inserted, "replay": not inserted, "evidence": self.store.adoption_evidence(assessment_id)}

    receive_adoption_evidence = record_adoption_evidence

    def discover_adoption_evidence(self, candidate_id: str, reader: Callable[[str], Mapping[str, Any]], *, limit: int = 64) -> dict[str, Any]:
        """Perform bounded registry-only discovery; the reader receives no write API."""
        if not isinstance(candidate_id, str) or not candidate_id or limit < 1:
            raise ValueError("bounded adoption discovery is invalid")
        result = reader(candidate_id)
        if not isinstance(result, Mapping):
            raise ValueError("adoption discovery result is invalid")
        evidence = dict(result)
        records = evidence.get("evidence", [])
        if not isinstance(records, list) or len(records) > min(64, limit):
            raise ValueError("adoption discovery is oversized")
        return evidence

    def receive_external_round(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            envelope = parse_external_round(payload)
        except ContractError as error:
            raise ValueError(str(error)) from error
        digest = envelope["digest"]
        existing = self.store.external_execution(envelope["reconciliationId"])
        if existing is not None:
            if existing["digest"] != digest or existing["payload"] != envelope:
                raise ValueError("external round identity conflict")
            if not existing["forwarded"]:
                self._forward_external(envelope["reconciliationId"], envelope)
            if existing.get("gateDecisionId"):
                self._ensure_external_decision(envelope, existing["gateDecisionId"])
            return self.store.external_execution(envelope["reconciliationId"])["receipt"]
        decision_id = f"roadex:external:{envelope['reconciliationId']}" if envelope.get("explicitGate") else None
        receipt = {"receiptId": f"external-receipt:{envelope['reconciliationId']}", "reconciliationId": envelope["reconciliationId"], "idempotencyKey": envelope["idempotencyKey"], "envelopeDigest": digest, "receivedAt": self.clock(), "status": "reconciled", **({"decisionId": decision_id, "decisionStatus": "pending"} if decision_id else {})}
        self.store.record_external(envelope, digest, receipt, decision_id)
        self._forward_external(envelope["reconciliationId"], envelope)
        if decision_id:
            self._ensure_external_decision(envelope, decision_id)
        return self.store.external_execution(envelope["reconciliationId"])["receipt"]

    reconcile_external_round = receive_external_round

    def _external_decision_request(self, envelope: Mapping[str, Any], workflow_id: str) -> dict[str, Any]:
        return {"decisionId": f"roadex:external:{envelope['reconciliationId']}", "projectId": envelope["projectId"], "planId": envelope["planId"], "workflowId": workflow_id, "decisionVersion": envelope["planVersion"], "correlationId": envelope["correlationId"], "idempotencyKey": f"roadex:external:{envelope['idempotencyKey']}", "question": envelope["explicitGate"], "resultProvenanceId": envelope["digest"]}

    def _ensure_external_decision(self, envelope: Mapping[str, Any], decision_id: str) -> None:
        if f"roadex:external:{envelope['reconciliationId']}" != decision_id:
            raise ValueError("external decision identity conflict")
        existing = self.store.decision(decision_id)
        if existing is None:
            return
        workflow_id = existing[0].get("workflowId")
        if not isinstance(workflow_id, str) or not workflow_id.strip():
            raise ValueError("external decision workflow conflict")
        expected = self._external_decision_request(envelope, workflow_id)
        if existing[0] != expected:
            raise ValueError("external decision identity conflict")
        self.store.link_external_gate(envelope["reconciliationId"], decision_id, workflow_id)

    def receive_external_decision_outcome(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        decision_id = payload.get("decisionId")
        status = payload.get("status")
        if not isinstance(decision_id, str) or not decision_id.startswith("roadex:external:") or status not in {"approved", "rejected", "expired"}:
            raise ValueError("external decision outcome is invalid")
        reconciliation_id = decision_id.removeprefix("roadex:external:")
        record = self.store.external_execution(reconciliation_id)
        if record is None or record.get("gateDecisionId") != decision_id:
            raise ValueError("external decision outcome identity conflict")
        envelope = record["payload"]
        decision_record = self.store.decision(decision_id)
        if decision_record is None:
            raise ValueError("an exact staged Psychlo decision is required")
        workflow_id = decision_record[0].get("workflowId")
        if not isinstance(workflow_id, str) or not workflow_id.strip() or record.get("gateWorkflowId") != workflow_id:
            raise ValueError("external decision workflow conflict")
        expected = {
            "projectId": envelope["projectId"],
            "planId": envelope["planId"],
            "workflowId": workflow_id,
            "decisionVersion": envelope["planVersion"],
            "correlationId": envelope["correlationId"],
            "idempotencyKey": f"roadex:external:{envelope['idempotencyKey']}",
            "question": envelope["explicitGate"],
            "resultProvenanceId": envelope["digest"],
        }
        allowed = {"decisionId", "status", "sourceId", "provenanceId", *expected}
        if set(payload) - allowed or any(field in payload and payload[field] != value for field, value in expected.items()):
            raise ValueError("external decision outcome identity conflict")
        if "sourceId" in payload and payload["sourceId"] != "overseer":
            raise ValueError("external decision outcome identity conflict")
        if "provenanceId" in payload and (not isinstance(payload["provenanceId"], str) or not payload["provenanceId"].strip()):
            raise ValueError("external decision outcome is invalid")
        prior_status = record["receipt"].get("decisionStatus")
        if prior_status in {"approved", "rejected", "expired"} and prior_status != status:
            raise ValueError("external decision outcome conflict")
        self._ensure_external_decision(record["payload"], decision_id)
        if status == "approved":
            result = self._decide_external(self.store.decision(decision_id)[0], status, str(payload.get("sourceId", "psychlo")), self.clock(), "external decision outcome")
        else:
            result = self._decide_external(self.store.decision(decision_id)[0], status, str(payload.get("sourceId", "psychlo")), self.clock(), "external decision outcome")
        receipt = self.store.external_execution(reconciliation_id)["receipt"]
        return {"accepted": True, "receipt": receipt, "continuation": "fresh-round-required" if status == "approved" else "blocked", **result}

    def _forward_external(self, reconciliation_id: str, envelope: Mapping[str, Any]) -> None:
        try:
            response = self.sender("external-round", reconciliation_id, envelope)
            if response.get("accepted") is not True:
                raise ValueError("Psychlo rejected external round")
        except Exception as error:
            record = self.store.external_execution(reconciliation_id)
            receipt = dict(record["receipt"]) if record else {}
            receipt["status"] = "forward-pending"
            self.store.connection.execute("UPDATE external_executions SET status='forward-pending',receipt_json=? WHERE reconciliation_id=?", (_dump(receipt), reconciliation_id))
            return
        receipt = response.get("receipt")
        record = self.store.external_execution(reconciliation_id)
        if isinstance(receipt, Mapping):
            expected = record["receipt"].get("decisionId") if record else None
            if expected and receipt.get("decisionId") not in {None, expected}:
                raise ValueError("external decision identity conflict")
            merged = {**(record["receipt"] if record else {}), **dict(receipt)}
            self.store.update_external_receipt(reconciliation_id, merged, status=str(merged.get("status", "reconciled")))
        self.store.mark_external_forwarded(reconciliation_id)


class PsychloPeerSender:
    def __init__(self, endpoint: str, secret: bytes, *, clock: Callable[[], str] | None = None, timeout: float = 5.0):
        if endpoint != "http://127.0.0.1:8798":
            raise ValueError("Psychlo endpoint must be the exact approved loopback origin")
        self.endpoint, self.secret, self.clock, self.timeout = endpoint, secret, clock or (lambda: datetime.now(UTC).isoformat()), timeout

    def __call__(self, kind: str, message_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        timestamp = self.clock()
        nonce = secrets.token_urlsafe(24)
        body = json.dumps({"kind": kind, "messageId": message_id, "occurredAt": timestamp, "payload": dict(payload)}, separators=(",", ":")).encode()
        headers = sign_peer_message(self.secret, "overseer-to-psychlo", kind, message_id, timestamp, nonce, body, authority="127.0.0.1:8798")
        request = Request(f"{self.endpoint}/internal/overseer/{kind}", data=body, headers=headers, method="POST")
        with urlopen(request, timeout=self.timeout) as response:
            if response.status not in {202, 409} or response.headers.get_content_type() != "application/json":
                raise ValueError("Psychlo peer rejected the request")
            data = response.read(MAX_BODY_BYTES + 1)
        if len(data) > MAX_BODY_BYTES: raise ValueError("Psychlo peer response is too large")
        parsed = json.loads(data)
        if not isinstance(parsed, dict): raise ValueError("Psychlo peer response is invalid")
        return parsed


class CodexProjectDispatcher:
    """Dispatch one prompt to the explicitly bound existing Codex conversation."""

    def __init__(self, bindings_file: str | Path):
        bindings = json.loads(_read_private_file(Path(bindings_file)).decode("utf-8"))
        if not isinstance(bindings, dict): raise ValueError("Psychlo project bindings must be an object")
        self.bindings = bindings

    def __call__(self, project_lead_id: str, prompt: str) -> str:
        binding = self.bindings.get(project_lead_id)
        if not isinstance(binding, dict) or not isinstance(binding.get("conversationId"), str):
            raise ValueError("project lead has no approved Codex conversation binding")
        from .agent_adapters.codex import CodexDriver
        driver = CodexDriver.from_legacy_registry()
        session = next((item for item in driver.discover() if item.external_session_id == binding["conversationId"] or item.id == binding["conversationId"]), None)
        if session is None: raise ValueError("bound project lead conversation is unavailable")
        result = driver.dispatch_legacy(session, prompt)
        if result.state.value not in {"acknowledged", "running", "succeeded"}:
            raise ValueError("project lead dispatch was not acknowledged")
        return result.id


def create_bridge_from_environment(environment: Mapping[str, str] | None = None) -> PsychloBridge:
    selected = environment or os.environ
    secret = _read_secret(Path(selected["OVERSEER_PSYCHLO_PEER_SECRET_FILE"]))
    store = PsychloBridgeStore(selected["OVERSEER_PSYCHLO_BRIDGE_DATABASE"])
    dispatcher = CodexProjectDispatcher(selected["OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE"])
    sender = PsychloPeerSender(selected.get("OVERSEER_PSYCHLO_ENDPOINT", "http://127.0.0.1:8798"), secret)
    return PsychloBridge(store=store, dispatcher=dispatcher, sender=sender, callback_origin="http://127.0.0.1:8766")


def _weekly_window(snapshot: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not snapshot: raise ValueError("weekly usage window is required")
    windows = [window for limit in snapshot.get("rate_limits", []) for window in limit.get("windows", []) if isinstance(window, dict)]
    if not windows: raise ValueError("weekly usage window is required")
    return max(windows, key=lambda item: float(item.get("window_minutes", item.get("duration_minutes", 0)) or 0))


def _require_round(request: Mapping[str, Any]) -> None:
    for name in ("roundId", "projectId", "projectLeadId", "planId", "planVersion", "correlationId", "idempotencyKey", "snapshotId", "policyVersion"):
        _required_string(request, name)
    if request.get("scope") != "one bounded round" or request.get("selectionReason") != "priority-selected": raise ValueError("invalid round request")


def _require_bound_result(request: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    for key, value in request.items():
        if result.get(key) != value: raise ValueError("round result does not bind to request")
    if result.get("sourceId") != request["projectLeadId"] or result.get("status") not in {"completed", "blocked"}: raise ValueError("round result is invalid")
    _required_string(result, "provenanceId")


def _required_string(value: Mapping[str, Any], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not item.strip(): raise ValueError(f"{name} is required")
    return item


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None: raise ValueError("timestamp requires an offset")
    return parsed.astimezone(UTC)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _dump(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))


def _read_secret(path: Path) -> bytes:
    try:
        value = _read_private_file(path, maximum_bytes=4096)
    except (OSError, ValueError):
        raise ValueError("Psychlo peer secret is unavailable") from None
    if len(value) < 32 or len(value) > 4096 or any(byte < 0x20 or byte == 0x7F for byte in value):
        raise ValueError("Psychlo peer secret is unavailable")
    return value


def _read_private_file(path: Path, *, maximum_bytes: int = MAX_BODY_BYTES) -> bytes:
    if not path.is_absolute(): raise ValueError("private file path must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077 or metadata.st_size > maximum_bytes:
            raise ValueError("private file is unsafe")
        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk: break
            chunks.append(chunk); remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > maximum_bytes: raise ValueError("private file is too large")
        return value
    finally:
        os.close(descriptor)
