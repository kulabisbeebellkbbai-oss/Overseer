"""Private, single-stream protocol bridge between Psychlo and Overseer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import inspect
import json
import math
from pathlib import Path
import os
import re
import secrets
import sqlite3
import stat
import threading
from typing import Any, Callable, Mapping
from urllib.request import Request, urlopen

from .psychlo_contracts import (
    ContractError,
    canonical_digest,
    cross_project_work_request_digest,
    cross_project_work_request_id,
    learning_observation_digest,
    parse_adoption_evidence,
    parse_external_round,
    parse_external_round_binding,
    parse_ingress_conflict_reconciliation,
    parse_cross_project_team_binding,
    parse_cross_project_work,
    parse_cross_project_supervisor_review,
    parse_canary_authorization,
    parse_concurrency_canary_result,
    parse_concurrency_ceiling_authorization,
    parse_learning_observation,
    parse_learning_advisory,
    parse_registry_candidate,
    parse_telemetry_checkpoint,
)
from .psychlo_contracts import SHA256_RE
from .audit import ApprovalRequest, ApprovalStatus
from .core import ApprovalLevel
from .admin import AdminChangePlan
from .store import SQLiteStore


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


def verify_peer_request(secret: bytes, store: PsychloBridgeStore, expected_kind: str, body: bytes, headers: Mapping[str, str], *, now: str | None = None, expected_authority: str) -> dict[str, Any]:
    if len(secret) < 32 or len(secret) > 4096 or not body or len(body) > MAX_BODY_BYTES:
        raise ValueError("invalid_request")
    host, separator, port = expected_authority.partition(":")
    if host != "127.0.0.1" or separator != ":" or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("invalid_authority")
    required = ("host", "content-type", "content-length", "x-psychlo-peer-kind", "x-psychlo-peer-message-id", "x-psychlo-peer-timestamp", "x-psychlo-peer-nonce", "x-psychlo-peer-signature")
    if any(not isinstance(headers.get(name), str) or "," in headers[name] for name in required):
        raise ValueError("invalid_headers")
    if headers["host"] != expected_authority or headers["content-type"] != "application/json" or headers["x-psychlo-peer-kind"] != expected_kind or headers["content-length"] != str(len(body)):
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
    def __init__(self, *, store: PsychloBridgeStore, dispatcher: Callable[..., str], sender: Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]], callback_origin: str, clock: Callable[[], str] | None = None, token_factory: Callable[[], str] | None = None, require_external_binding: bool = False, approval_loader: Callable[[str], Any] | None = None, approval_store: SQLiteStore | None = None, approval_owner_domain: str = "sisko", supervisor_dispatcher: Callable[..., str] | None = None, project_result_collector: Callable[[str, Mapping[str, Any]], Mapping[str, Any] | None] | None = None, supervisor_result_collector: Callable[[str, Mapping[str, Any]], Mapping[str, Any] | None] | None = None, coordination_owner_id: str | None = None, coordination_lease_seconds: int = 30):
        self.store, self.dispatcher, self.sender = store, dispatcher, sender
        self.peer_secret = getattr(sender, "secret", None)
        self.callback_origin = callback_origin.rstrip("/")
        self.require_external_binding = require_external_binding
        self.clock = clock or (lambda: datetime.now(UTC).isoformat())
        self.token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        # Administrative authority is deliberately separate from the Psychlo
        # projection store.  The latter must never be an approval authority.
        self.approval_loader = approval_loader
        self.approval_store = approval_store
        self.approval_owner_domain = approval_owner_domain
        self.supervisor_dispatcher = supervisor_dispatcher
        self.project_result_collector = project_result_collector
        self.supervisor_result_collector = supervisor_result_collector
        self.coordination_owner_id = coordination_owner_id or f"{os.getpid()}:{secrets.token_hex(12)}"
        self.coordination_lease_seconds = max(5, min(300, int(coordination_lease_seconds)))
        self._coordination_tick_lock = threading.Lock()
        self._recover_decision_intents()
        self.recover_protocol_records()

    def tick(self, *, limit: int = 32) -> dict[str, int | bool]:
        """Run one bounded, non-overlapping coordination polling pass."""
        if not self._coordination_tick_lock.acquire(blocking=False):
            return {"busy": True, "processed": 0, "failed": 0}
        processed = failed = 0
        try:
            records = self.store.pending_protocol("coordination-work-request", limit=max(1, min(32, limit)))
            for record in records:
                if not self._coordination_retry_due(record):
                    continue
                try:
                    self._drive_coordination_request(str(record["id"]))
                    processed += 1
                except Exception as error:
                    self.store.transition_protocol("coordination-work-request", str(record["id"]), "forward-pending", "poll-failed")
                    failed += 1
            return {"busy": False, "processed": processed, "failed": failed}
        finally:
            self._coordination_tick_lock.release()

    def _coordination_retry_due(self, record: Mapping[str, Any]) -> bool:
        attempts = int(record.get("attempts", 0) or 0)
        if attempts <= 0:
            return True
        try:
            updated = datetime.fromisoformat(str(record["updatedAt"]).replace("Z", "+00:00"))
            now = datetime.fromisoformat(self.clock().replace("Z", "+00:00"))
            return (now - updated).total_seconds() >= min(60, 2 ** min(attempts, 6))
        except (KeyError, TypeError, ValueError):
            return False

    def request_round(self, request: Mapping[str, Any]) -> dict[str, Any]:
        _require_round(request)
        if any(item["request"].get("projectId") == request["projectId"] for item in self.store.list_staged_decisions()) or self.store.external_gate_pending(str(request["projectId"])) or self.store.external_gate_blocked(str(request["projectId"])):
            raise ValueError("decision_pending")
        existing = self.store.get_round(str(request["roundId"]))
        if existing:
            if existing[0] != dict(request): raise ValueError("round identity conflict")
            if existing[4] != "dispatched": return self._dispatch_reserved(existing[0], existing[3], existing[1])
            return {"accepted": True, "receipt": existing[1]}
        capability = self.token_factory()
        receipt = {**request, "sourceId": request["projectLeadId"], "provenanceId": f"overseer-dispatch:{request['roundId']}", "status": "accepted"}
        if self._durable_ceiling_available():
            self.store.record_durable_ceiling_round(request, receipt, capability, self.clock())
        else:
            canary = self._canary_authorization_for_request(request)
            if canary is not None:
                self.store.record_canary_round(request, receipt, capability, canary["authorizationId"], canary["expectedRevision"], self.clock())
            else:
                self.store.record_single_stream_round(request, receipt, capability)
        return self._dispatch_reserved(dict(request), capability, receipt)

    def _canary_authorization_for_request(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        """Select only an exact, currently approved canary authorization.

        This is merely a candidate lookup.  ``record_canary_round`` repeats
        every check while holding SQLite's write lock, so concurrent callers
        cannot rely on this process-local view to obtain a second slot.
        """
        now = _time(self.clock())
        for record in self.store.list_protocol("concurrency-canary-authorization"):
            if record is None or record.get("state") != "delivered":
                continue
            value = record.get("payload")
            if not isinstance(value, dict):
                raise ValueError("concurrency canary authorization is invalid")
            try:
                value = parse_canary_authorization(value)
            except ContractError as error:
                raise ValueError("concurrency canary authorization is invalid") from error
            if value["digest"] != record.get("digest"):
                raise ValueError("concurrency canary authorization digest conflict")
            try:
                deadline = _time(str(value["deadline"]))
            except (KeyError, TypeError, ValueError):
                continue
            if deadline <= now or not isinstance(value.get("projects"), list) or len(value["projects"]) != 2:
                continue
            if not any(isinstance(project, dict) and project.get("projectId") == request.get("projectId") and project.get("planId") == request.get("planId") and project.get("planVersion") == request.get("planVersion") and project.get("leadId") == request.get("projectLeadId") for project in value["projects"]):
                continue
            decision = self.store.decision(str(value.get("decisionId", "")))
            if decision is None or decision[2] != "approved":
                continue
            return value
        return None

    def _durable_ceiling_available(self) -> bool:
        """Return a hint only; the store repeats the check under its lock."""
        changes = self.store.list_protocol("concurrency-ceiling-change")
        for change in reversed([item for item in changes if item is not None]):
            if change.get("state") not in {"delivered", "settled"}:
                continue
            change_payload = change.get("payload")
            if not isinstance(change_payload, dict) or set(change_payload) != {"authorizationId", "correlationId", "idempotencyKey", "occurredAt"} or canonical_digest(change_payload) != change.get("digest"):
                raise ValueError("concurrency ceiling change is invalid")
            authorization_id = change_payload.get("authorizationId")
            authorization = self.store.protocol_record("concurrency-ceiling-authorization", str(authorization_id)) if authorization_id else None
            if authorization and authorization.get("state") in {"delivered", "settled"}:
                try:
                    value = parse_concurrency_ceiling_authorization(authorization["payload"])
                except ContractError as error:
                    raise ValueError("concurrency ceiling authorization is invalid") from error
                if value["digest"] != authorization.get("digest"):
                    raise ValueError("concurrency ceiling authorization digest conflict")
                if value["ceiling"] == 2:
                    return True
        return False

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
        if stored_result is None: self.store.record_result(str(request["roundId"]), result, self.clock())
        if not forwarded:
            response = dict(self.sender("round-result", str(result["provenanceId"]), result))
            if response.get("accepted") is not True: raise ValueError("Psychlo rejected round result")
            self.store.mark_forwarded(str(request["roundId"]))
        return {"accepted": True}

    def _dispatch_reserved(self, request: Mapping[str, Any], capability: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
        self.store.mark_dispatch_started(str(request["roundId"]), self.clock())
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
        digest = learning_observation_digest(observation)
        if supplied_digest is not None and supplied_digest != digest:
            raise ValueError("learning observation digest mismatch")
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
        stored = self.store.registry_candidate(candidate["candidateId"])
        if stored is None:
            raise ValueError("registry candidate was not persisted")
        protocol = self._persist_adoption_peer("registry-candidate", candidate["candidateId"], _registry_wire_payload(stored))
        return {"inserted": inserted, "replay": not inserted, "candidate": stored, "receipt": protocol["record"].get("receipt")}

    receive_registry_candidate = register_candidate
    produce_registry_candidate = register_candidate

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
        # A registry candidate is always delivered before its assessment.  If
        # this bridge was restarted after the registry row was recorded but
        # before its outbox record was created, recover that producer seam
        # here rather than letting Psychlo see an unbound assessment.
        registry_record = self.store.protocol_record("registry-candidate", evidence["candidateId"])
        if registry_record is None or registry_record.get("state") not in {"delivered", "settled"}:
            registry_wire = _registry_wire_payload(candidate)
            self._persist_adoption_peer("registry-candidate", evidence["candidateId"], registry_wire)
        assessment_id = evidence["assessmentId"]
        inserted = self.store.record_adoption(assessment_id, evidence["candidateId"], evidence, canonical_digest(evidence))
        protocol = self._persist_adoption_peer("adoption-evidence", assessment_id, _adoption_wire_payload(evidence))
        return {"inserted": inserted, "replay": not inserted, "evidence": self.store.adoption_evidence(assessment_id), "receipt": protocol["record"].get("receipt")}

    receive_adoption_evidence = record_adoption_evidence
    produce_adoption_evidence = record_adoption_evidence

    def produce_adoption(self, candidate: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
        """Persist and deliver the registry binding before its assessment."""
        self.register_candidate(candidate)
        return self.record_adoption_evidence(evidence)

    def _persist_adoption_peer(self, kind: str, record_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        digest = canonical_digest(payload)
        record, inserted = self.store.record_protocol(kind, record_id, str(payload.get("idempotencyKey", record_id)), digest, payload)
        if record["state"] in {"delivered", "settled"}:
            return {"inserted": inserted, "replay": not inserted, "record": record}
        try:
            response = self.sender(kind, record_id, payload)
            _validate_adoption_peer_response(kind, payload, response)
            record = self.store.transition_protocol(kind, record_id, "delivered", receipt=dict(response))
        except Exception as error:
            self.store.transition_protocol(kind, record_id, "forward-pending", "forward-failed")
            raise ValueError("forward-pending") from error
        return {"inserted": inserted, "replay": not inserted, "record": record}

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
        binding = self.store.protocol_record("external-round-binding", envelope["reconciliationId"])
        if binding is None and self.require_external_binding:
            raise ValueError("external round binding authorization is required")
        if binding is not None:
            bound = binding["payload"]
            if bound.get("externalExecutionId") != envelope["externalExecutionId"] or bound.get("projectId") != envelope["projectId"] or bound.get("aTeamId") != envelope["aTeamId"] or bound.get("planId") != envelope["planId"] or bound.get("planVersion") != envelope["planVersion"] or bound.get("projectLeadId") != envelope["projectLeadId"] or bound.get("threadId") != envelope["threadId"] or bound.get("repository") != envelope["repository"] or bound.get("startingCheckpoint") != envelope["startingCheckpoint"] or bound.get("terminalCheckpoint") != envelope["terminalCheckpoint"]:
                raise ValueError("external round binding conflict")
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

    # ---- Psychlo final peer projections -------------------------------
    def _revalidate_concurrency_protocol_record(self, record: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """Fail closed on stale/corrupt concurrency records before forwarding."""
        kind = record.get("kind")
        if kind not in {"concurrency-canary-authorization", "concurrency-ceiling-authorization", "concurrency-ceiling-change"}:
            return None
        payload = record.get("payload")
        if not isinstance(payload, dict):
            raise ValueError(f"{kind} payload is invalid")
        try:
            if kind == "concurrency-canary-authorization":
                value = parse_canary_authorization(payload)
                if value["digest"] != record.get("digest"):
                    raise ValueError("concurrency canary authorization digest conflict")
                return value
            if kind == "concurrency-ceiling-authorization":
                value = parse_concurrency_ceiling_authorization(payload)
                if value["digest"] != record.get("digest"):
                    raise ValueError("concurrency ceiling authorization digest conflict")
                canary_record = self.store.protocol_record("concurrency-canary-result", str(value["canaryResultId"]))
                canary = self._revalidate_canary_result_record(canary_record)
                if canary["resultId"] != value["canaryResultId"] or canary["targetCeiling"] != value["ceiling"] or canary["expectedRevision"] != value["expectedRevision"]:
                    raise ValueError("successful canary evidence does not bind to ceiling")
                return value
            if set(payload) != {"authorizationId", "correlationId", "idempotencyKey", "occurredAt"} or any(not isinstance(payload.get(field), str) or not payload[field].strip() for field in payload):
                raise ValueError("concurrency ceiling change is invalid")
            if canonical_digest(payload) != record.get("digest"):
                raise ValueError("concurrency ceiling change digest conflict")
            ceiling_record = self.store.protocol_record("concurrency-ceiling-authorization", str(payload["authorizationId"]))
            if ceiling_record is None or ceiling_record.get("state") not in {"delivered", "settled"}:
                raise ValueError("concurrency ceiling authorization is unavailable")
            ceiling = self._revalidate_concurrency_protocol_record(ceiling_record)
            decision = self.store.decision(str(ceiling["decisionId"]))
            if decision is None or decision[2] != "approved":
                raise ValueError("concurrency ceiling authorization is not approved")
            expected_decision = {"decisionId": ceiling["decisionId"], "projectId": ceiling["projectId"], "planId": ceiling["planId"], "workflowId": ceiling["workflowId"], "decisionVersion": ceiling["decisionVersion"], "question": ceiling["question"], "resultProvenanceId": ceiling["digest"]}
            if any(decision[0].get(field) != expected for field, expected in expected_decision.items()):
                raise ValueError("concurrency ceiling decision binding is invalid")
            return payload
        except ContractError as error:
            raise ValueError(f"{kind} payload is invalid") from error

    def _revalidate_canary_result_record(self, record: Mapping[str, Any] | None) -> dict[str, Any]:
        if record is None or record.get("state") != "delivered" or not isinstance(record.get("payload"), dict):
            raise ValueError("successful delivered canary evidence is required")
        try:
            value = parse_concurrency_canary_result(record["payload"])
        except ContractError as error:
            raise ValueError("successful delivered canary evidence is invalid") from error
        if value["digest"] != record.get("digest"):
            raise ValueError("concurrency canary result digest conflict")
        authorization = self.store.protocol_record("concurrency-canary-authorization", value["authorizationId"])
        if authorization is None or authorization.get("state") not in {"delivered", "settled"} or not isinstance(authorization.get("payload"), dict):
            raise ValueError("canary authorization is unavailable")
        try:
            auth = parse_canary_authorization(authorization["payload"])
        except ContractError as error:
            raise ValueError("canary authorization is invalid") from error
        if auth["digest"] != authorization.get("digest"):
            raise ValueError("canary authorization digest conflict")
        identities = {(item["projectId"], item["planId"], item["planVersion"], item["leadId"]) for item in auth["projects"]}
        observed = {(item["started"]["projectId"], item["started"]["planId"], item["started"]["planVersion"], item["started"]["leadId"]) for item in value["executions"]}
        if value["targetCeiling"] != auth["targetTemporaryCeiling"] or value["expectedRevision"] != auth["expectedRevision"] or observed != identities:
            raise ValueError("successful canary evidence does not bind to authorization")
        self.store._verify_canary_execution_rounds(value)
        return value

    def _persist_protocol(self, kind: str, record_id: str, payload: Mapping[str, Any], *, forward: bool = True) -> dict[str, Any]:
        digest = str(payload.get("digest") or canonical_digest(payload))
        synthetic = {"kind": kind, "id": record_id, "digest": digest, "payload": dict(payload), "state": "queued"}
        self._revalidate_concurrency_protocol_record(synthetic)
        record, inserted = self.store.record_protocol(kind, record_id, str(payload.get("idempotencyKey", record_id)), digest, payload)
        try:
            self._revalidate_concurrency_protocol_record(record)
        except Exception:
            if record.get("state") not in {"delivered", "settled", "forward-pending"}:
                self.store.transition_protocol(kind, record_id, "forward-pending", "protocol-integrity-failed")
            raise
        if inserted and forward:
            try:
                response = self.sender(kind, record_id, payload)
                if response.get("accepted") is not True: raise ValueError("Psychlo rejected protocol record")
                record = self.store.transition_protocol(kind, record_id, "delivered")
            except Exception as error:
                self.store.transition_protocol(kind, record_id, "forward-pending", "forward-failed")
                raise ValueError("forward-pending") from error
        elif not inserted and record["state"] not in {"delivered", "settled"} and forward:
            try:
                response = self.sender(kind, record_id, payload)
                if response.get("accepted") is not True: raise ValueError("Psychlo rejected protocol record")
                record = self.store.transition_protocol(kind, record_id, "delivered")
            except Exception as error:
                self.store.transition_protocol(kind, record_id, "forward-pending", "forward-failed")
                raise ValueError("forward-pending") from error
        return {"inserted": inserted, "replay": not inserted, "record": record}

    def authorize_external_round_binding(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try: authorization = parse_external_round_binding(payload)
        except ContractError as error: raise ValueError(str(error)) from error
        external = self.store.external_execution(authorization["reconciliationId"])
        if external is not None:
            envelope = external["payload"]
            for field in ("externalExecutionId", "projectId", "aTeamId", "planId", "planVersion", "projectLeadId", "threadId", "startingCheckpoint", "terminalCheckpoint"):
                if authorization[field] != envelope[field]: raise ValueError("external round binding conflict")
            if authorization["repository"] != envelope["repository"]: raise ValueError("external round binding conflict")
        return self._persist_protocol("external-round-binding", authorization["reconciliationId"], authorization)

    receive_external_round_binding = authorize_external_round_binding

    def _approved_admin_record(self, approval_id: str, payload: Mapping[str, Any], action: str) -> dict[str, Any]:
        if not isinstance(approval_id, str) or not approval_id.strip() or isinstance(approval_id, Mapping):
            raise ValueError("persisted approval record ID is required")
        if self.approval_loader is None and self.approval_store is None:
            raise ValueError("authoritative approval store is unavailable")
        early_snapshot = self.store.approval_snapshot(approval_id)
        if early_snapshot is not None:
            record = early_snapshot["payload"].get("record")
            aliases = {"external-round-binding": {"external-round-binding", "external-work"}, "ingress-conflict-reconciliation": {"ingress-conflict-reconciliation", "conflict-reconciliation"}, "cross-project-team-binding": {"cross-project-team-binding"}, "concurrency-canary-authorization": {"concurrency-canary-authorization", "concurrency-canary"}, "concurrency-ceiling-authorization": {"concurrency-ceiling-authorization", "concurrency-ceiling"}}
            target_field = {"external-round-binding": "reconciliationId", "ingress-conflict-reconciliation": "ingressIdempotencyKey", "cross-project-team-binding": "bindingId", "concurrency-canary-authorization": "authorizationId", "concurrency-ceiling-authorization": "authorizationId"}[action]
            if not isinstance(record, Mapping) or record.get("id") != approval_id or record.get("action") not in aliases[action] or record.get("ownerDomain") != self.approval_owner_domain:
                raise ValueError("approval authority snapshot is invalid")
            if payload.get(target_field) != record.get("target") or canonical_digest(dict(payload)) != record.get("payloadDigest"):
                raise ValueError("approval authority snapshot does not match operation")
            return dict(record)
        try:
            loaded = self.approval_loader(approval_id) if self.approval_loader is not None else self._load_primary_approval(approval_id)
        except (KeyError, LookupError, OSError, ValueError) as error:
            raise ValueError("approved administrative provenance is missing") from error
        if isinstance(loaded, tuple) and len(loaded) == 2:
            approval, subject = loaded
        else:
            approval, subject = loaded, None
        snapshot = self.store.approval_snapshot(approval_id)
        if snapshot is not None:
            record = snapshot["payload"].get("record")
            aliases = {"external-round-binding": {"external-round-binding", "external-work"}, "ingress-conflict-reconciliation": {"ingress-conflict-reconciliation", "conflict-reconciliation"}, "cross-project-team-binding": {"cross-project-team-binding"}, "concurrency-canary-authorization": {"concurrency-canary-authorization", "concurrency-canary"}, "concurrency-ceiling-authorization": {"concurrency-ceiling-authorization", "concurrency-ceiling"}}
            if not isinstance(record, Mapping) or record.get("id") != approval_id or record.get("action") not in aliases[action] or record.get("ownerDomain") != self.approval_owner_domain:
                raise ValueError("approval authority snapshot is invalid")
            target_field = {"external-round-binding": "reconciliationId", "ingress-conflict-reconciliation": "ingressIdempotencyKey", "cross-project-team-binding": "bindingId", "concurrency-canary-authorization": "authorizationId", "concurrency-ceiling-authorization": "authorizationId"}[action]
            if payload.get(target_field) != record.get("target") or canonical_digest(dict(payload)) != record.get("payloadDigest"):
                raise ValueError("approval authority snapshot does not match operation")
            return dict(record)
        if not isinstance(approval, ApprovalRequest) or approval.id != approval_id:
            raise ValueError("approval record identity conflict")
        if approval.status != ApprovalStatus.APPROVED or approval.approval_level != ApprovalLevel.HUMAN:
            raise ValueError("approved administrative provenance is required")
        if not isinstance(approval.decided_by, str) or not approval.decided_by.strip() or approval.decided_by.lower() in {"sisko", "overseer", "system"}:
            raise ValueError("independent human approval is required")
        if approval.decided_at:
            try:
                if datetime.fromisoformat(str(approval.decided_at).replace("Z", "+00:00")) > datetime.fromisoformat(self.clock().replace("Z", "+00:00")):
                    raise ValueError("approval is postdated")
            except ValueError as error:
                if str(error) == "approval is postdated":
                    raise
                raise ValueError("approval timestamp is invalid") from error
        if subject is None and self.approval_store is not None:
            subject = self._load_primary_subject(self.approval_store, approval.subject_id)
        if not isinstance(subject, AdminChangePlan):
            raise ValueError("immutable administrative subject is required")
        if subject.id != approval.subject_id or not subject.approved or subject.canceled or subject.archived:
            raise ValueError("approved administrative subject is invalid")
        metadata = self._subject_metadata(subject)
        declared_owner = metadata.get("owner", metadata.get("ownerDomain", subject.owner_domain.value))
        if declared_owner != approval.owner_domain.value or declared_owner != subject.owner_domain.value or declared_owner != self.approval_owner_domain:
            raise ValueError("approval owner does not match immutable subject")
        record_action = metadata.get("action", metadata.get("kind", subject.kind.value))
        aliases = {"external-round-binding": {"external-round-binding", "external-work"}, "ingress-conflict-reconciliation": {"ingress-conflict-reconciliation", "conflict-reconciliation"}, "cross-project-team-binding": {"cross-project-team-binding"}, "concurrency-canary-authorization": {"concurrency-canary-authorization", "concurrency-canary"}, "concurrency-ceiling-authorization": {"concurrency-ceiling-authorization", "concurrency-ceiling"}}
        if record_action not in aliases[action]:
            raise ValueError("approval action does not match operation")
        target_field = {"external-round-binding": "reconciliationId", "ingress-conflict-reconciliation": "ingressIdempotencyKey", "cross-project-team-binding": "bindingId", "concurrency-canary-authorization": "authorizationId", "concurrency-ceiling-authorization": "authorizationId"}[action]
        target = metadata.get("target", subject.target)
        if not isinstance(target, str) or payload.get(target_field) != target:
            raise ValueError("approval target does not match operation")
        expected_digest = metadata.get("payloadDigest", metadata.get("payload_digest"))
        expected_payload = metadata.get("payload")
        if expected_payload is not None and expected_payload != dict(payload):
            raise ValueError("approval payload does not match immutable subject")
        if not isinstance(expected_digest, str) or expected_digest != canonical_digest(dict(payload)):
            raise ValueError("approval payload digest does not match operation")
        evidence = metadata.get("evidence", subject.risks)
        if not isinstance(evidence, (list, tuple)) or not evidence or not all(isinstance(item, str) and item.strip() for item in evidence):
            raise ValueError("approval evidence is required")
        if tuple(approval.evidence_required) and not set(approval.evidence_required).issubset(set(evidence) | {expected_digest}):
            raise ValueError("approval evidence does not match operation")
        record = {"id": approval.id, "subjectId": approval.subject_id, "ownerDomain": approval.owner_domain.value, "decidedBy": approval.decided_by, "decidedAt": approval.decided_at, "action": record_action, "target": target, "payloadDigest": expected_digest, "evidence": list(evidence)}
        self.store.save_approval_snapshot(approval_id, {"record": record, "approval": {"id": approval.id, "subjectId": approval.subject_id, "status": approval.status.value, "approvalLevel": approval.approval_level.value, "ownerDomain": approval.owner_domain.value, "decidedBy": approval.decided_by, "decidedAt": approval.decided_at, "evidenceRequired": list(approval.evidence_required)}, "subject": {"id": subject.id, "kind": subject.kind.value, "target": subject.target, "ownerDomain": subject.owner_domain.value, "approved": subject.approved, "canceled": subject.canceled, "archived": subject.archived}}, canonical_digest(record))
        return record

    def _load_primary_approval(self, approval_id: str):
        if self.approval_store is None:
            raise KeyError(approval_id)
        approval = self.approval_store.load_approval(approval_id)
        return approval, self._load_primary_subject(self.approval_store, approval.subject_id)

    @staticmethod
    def _load_primary_subject(store: SQLiteStore, subject_id: str) -> AdminChangePlan:
        return store.load_admin_change_plan(subject_id)

    @staticmethod
    def _subject_metadata(plan: AdminChangePlan) -> dict[str, Any]:
        try:
            decoded = json.loads(plan.proposed_state)
        except (TypeError, json.JSONDecodeError):
            decoded = {}
        if not isinstance(decoded, dict):
            decoded = {}
        metadata = decoded.get("psychloAuthorization", decoded)
        if not isinstance(metadata, dict):
            metadata = {}
        return dict(metadata)

    def initiate_external_round_binding(self, approval_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._approved_admin_record(approval_id, payload, "external-round-binding")
        value = dict(payload)
        value.setdefault("correlationId", f"external-binding:{value.get('reconciliationId', '')}")
        value.setdefault("idempotencyKey", f"external-binding:{value.get('reconciliationId', '')}")
        value.setdefault("occurredAt", self.clock())
        value.setdefault("schemaVersion", "psychlo.external-round-binding.v1")
        value["digest"] = canonical_digest({key: item for key, item in value.items() if key != "digest"})
        return self.authorize_external_round_binding(value)

    def initiate_ingress_conflict_reconciliation(self, approval_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        approval = self._approved_admin_record(approval_id, payload, "ingress-conflict-reconciliation")
        value = dict(payload); value.setdefault("sourceId", "overseer"); value.setdefault("status", "resolved"); value.setdefault("provenanceId", str(approval.get("id", approval_id))); value.setdefault("correlationId", f"reconcile:{value.get('idempotencyKey', '')}"); value.setdefault("occurredAt", self.clock())
        return self.reconcile_ingress_conflict(value)

    def initiate_cross_project_team_binding(self, approval_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        approval = self._approved_admin_record(approval_id, payload, "cross-project-team-binding")
        value = dict(payload); value.setdefault("approvalProvenanceId", str(approval.get("id", approval_id))); value.setdefault("correlationId", f"team-binding:{value.get('bindingId', '')}"); value.setdefault("idempotencyKey", f"team-binding:{value.get('bindingId', '')}"); value.setdefault("occurredAt", self.clock())
        ordered = {key: value[key] for key in ("bindingId", "coordinationTeamId", "supervisorMemberId", "supervisorLeadId", "approvalId", "approvalProvenanceId", "approvedAt", "correlationId", "idempotencyKey", "occurredAt")}; value["digest"] = hashlib.sha256(json.dumps(ordered, separators=(",", ":")).encode()).hexdigest()
        return self.authorize_cross_project_team_binding(value)

    def initiate_concurrency_canary_authorization(self, approval_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._approved_admin_record(approval_id, payload, "concurrency-canary-authorization")
        value = dict(payload)
        if value.get("targetTemporaryCeiling") != 2 or value.get("expectedGlobalCeiling") != 1 or not isinstance(value.get("projects"), list) or len(value["projects"]) != 2 or value["projects"][0].get("projectId") == value["projects"][1].get("projectId"): raise ValueError("exact two-project canary is required")
        for field in ("authorizationId", "expectedRevision", "projects", "workflowId", "decisionVersion", "deadline", "correlationId", "idempotencyKey", "occurredAt"):
            if field not in value: raise ValueError("canary authorization input is incomplete")
        base = {key: value[key] for key in ("authorizationId", "targetTemporaryCeiling", "expectedGlobalCeiling", "expectedRevision", "projects", "workflowId", "decisionVersion", "deadline", "correlationId", "idempotencyKey", "occurredAt")}
        value["digest"] = hashlib.sha256(json.dumps(base, separators=(",", ":")).encode()).hexdigest()
        value["decisionId"] = f"roadex:concurrency-canary:{value['authorizationId']}"
        value["question"] = f"Approve the exact live concurrency canary {value['digest']}"
        return self.authorize_concurrency_canary(value)

    def initiate_concurrency_ceiling_authorization(self, approval_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._approved_admin_record(approval_id, payload, "concurrency-ceiling-authorization")
        value = dict(payload)
        canary_id = value.get("canaryResultId")
        canary_record = self.store.protocol_record("concurrency-canary-result", canary_id) if isinstance(canary_id, str) else None
        if canary_record is None or canary_record["state"] != "delivered":
            raise ValueError("successful delivered canary evidence is required")
        try:
            canary = parse_concurrency_canary_result(canary_record["payload"])
        except ContractError as error:
            raise ValueError("successful delivered canary evidence is invalid") from error
        required = ("authorizationId", "ceiling", "expectedRevision", "revision", "canaryResultId", "projectId", "planId", "workflowId", "decisionVersion", "correlationId", "idempotencyKey", "occurredAt")
        if any(field not in value for field in required): raise ValueError("ceiling authorization input is incomplete")
        if canary["resultId"] != value["canaryResultId"] or canary["targetCeiling"] != value["ceiling"] or canary["expectedRevision"] != value["expectedRevision"]:
            raise ValueError("successful canary evidence does not bind to ceiling")
        base = {key: value[key] for key in required}; value["digest"] = hashlib.sha256(json.dumps(base, separators=(",", ":")).encode()).hexdigest(); value["decisionId"] = f"roadex:concurrency:{value['authorizationId']}"; value["question"] = f"Approve the exact global concurrency operation {value['digest']}"
        return self.authorize_concurrency_ceiling(value)

    def initiate_authorized(self, kind: str, request: Mapping[str, Any]) -> dict[str, Any]:
        """Route authenticated API input containing only an approval ID and operation input."""
        value = dict(request)
        if set(value) != {"approval_id", "input"} or not isinstance(value["approval_id"], str) or not isinstance(value["input"], Mapping):
            raise ValueError("approval_id and operation input are required")
        methods = {
            "external-round-binding": self.initiate_external_round_binding,
            "ingress-conflict-reconciliation": self.initiate_ingress_conflict_reconciliation,
            "cross-project-team-binding": self.initiate_cross_project_team_binding,
            "concurrency-canary-authorization": self.initiate_concurrency_canary_authorization,
            "concurrency-ceiling-authorization": self.initiate_concurrency_ceiling_authorization,
        }
        method = methods.get(kind)
        if method is None:
            raise ValueError("unsupported authorized operation")
        return method(value["approval_id"], dict(value["input"]))

    def reconcile_ingress_conflict(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try: value = parse_ingress_conflict_reconciliation(payload)
        except ContractError as error: raise ValueError(str(error)) from error
        return self._persist_protocol("ingress-conflict-reconciliation", value["idempotencyKey"], value)

    receive_ingress_conflict_reconciliation = reconcile_ingress_conflict

    def authorize_cross_project_team_binding(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try: value = parse_cross_project_team_binding(payload)
        except ContractError as error: raise ValueError(str(error)) from error
        return self._persist_protocol("cross-project-team-binding", value["bindingId"], value)

    receive_cross_project_team_binding = authorize_cross_project_team_binding

    def coordinate_cross_project(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(payload)
        if set(value) != {"operation", "input"} or value["operation"] not in {"work-request", "propose", "approve", "validate", "retire", "reuse"} or not isinstance(value["input"], Mapping): raise ValueError("cross-project command is invalid")
        inner = dict(value["input"])
        key = inner.get("idempotencyKey")
        if not isinstance(key, str) or not key.strip(): raise ValueError("cross-project command idempotency is required")
        return self._persist_protocol("cross-project-command", key, value)

    def receive_coordination_work_request(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Persist a bounded request and drive it through the authoritative lead store."""
        value = dict(payload)
        required = {"schemaVersion", "id", "linkId", "version", "projectId", "leadId", "coordinationBindingId", "requiredRequestIds", "supervisorLeadId", "scope", "evidenceIds", "expectedResultDigest", "requestDigest"}
        if set(value) != required or value.get("schemaVersion") != "psychlo.event.v1" or any(not isinstance(value.get(field), str) or not value[field].strip() for field in required - {"evidenceIds", "requiredRequestIds"}): raise ValueError("coordination work request is invalid")
        if any(len(value[field]) > 256 for field in ("id", "linkId", "version", "projectId", "leadId", "coordinationBindingId", "supervisorLeadId")) or len(value["scope"]) > 2_000 or any(not re.fullmatch(r"[a-f0-9]{64}", value[field]) for field in ("expectedResultDigest", "requestDigest")): raise ValueError("coordination work request is invalid")
        if not isinstance(value["evidenceIds"], list) or not 0 < len(value["evidenceIds"] ) <= 32 or any(not isinstance(item, str) or not item.strip() or len(item) > 256 for item in value["evidenceIds"]): raise ValueError("coordination work evidence is invalid")
        request_ids = value["requiredRequestIds"]
        if not isinstance(request_ids, list) or not 1 < len(request_ids) <= 64 or len(set(request_ids)) != len(request_ids) or any(not isinstance(item, str) or not item.startswith("cross-project-work:") or len(item) > 256 for item in request_ids): raise ValueError("coordination request set is invalid")
        expected_id = cross_project_work_request_id(value["linkId"], value["version"], value["projectId"])
        if value["id"] != expected_id or value["id"] not in request_ids or value["coordinationBindingId"] == value["linkId"]: raise ValueError("coordination binding identity is invalid")
        if value["requestDigest"] != cross_project_work_request_digest(value): raise ValueError("coordination request digest is invalid")
        project = self.store.project(value["projectId"])
        if project is None or project[0].get("projectLead", {}).get("id", project[0].get("projectLeadId")) != value["leadId"]: raise ValueError("coordination work lead is not registered")
        binding = self.store.protocol_record("cross-project-team-binding", value["coordinationBindingId"])
        if binding is None or binding["state"] != "delivered" or binding["payload"].get("bindingId") != value["coordinationBindingId"] or not binding["payload"].get("coordinationTeamId") or not binding["payload"].get("supervisorMemberId") or binding["payload"].get("supervisorLeadId") != value["supervisorLeadId"]: raise ValueError("approved coordination team binding is required")
        for existing in self.store.list_protocol("coordination-work-request"):
            candidate = existing["payload"]
            if candidate.get("linkId") == value["linkId"] and candidate.get("version") == value["version"] and (candidate.get("coordinationBindingId") != value["coordinationBindingId"] or candidate.get("requiredRequestIds") != request_ids or candidate.get("supervisorLeadId") != value["supervisorLeadId"]):
                raise ValueError("coordination request set conflict")
        self._persist_protocol("coordination-work-request", value["id"], value, forward=False)
        try:
            self._drive_coordination_request(value["id"])
        except ValueError as error:
            if str(error) != "dispatch-pending": raise
        receipt = {"requestId": value["id"], "projectId": value["projectId"], "leadId": value["leadId"], "status": "accepted", "provenanceId": f"overseer:{value['id']}"}
        return {"accepted": True, "receipt": receipt}

    def _drive_coordination_request(self, request_id: str) -> dict[str, Any]:
        request_record = self.store.protocol_record("coordination-work-request", request_id)
        if request_record is None:
            raise ValueError("coordination work request is missing")
        value = request_record["payload"]
        review = self._collect_supervisor_review(request_id)
        if review is not None:
            return {"accepted": True, "requestId": request_id, "status": "settled", "reviewId": review["reviewId"]}
        existing_result = self._collect_project_result(value)
        if existing_result is not None:
            self._persist_participant_result(value, existing_result)
            return {"accepted": True, "requestId": request_id, "status": "review-pending" if self.store.coordination_review(request_id) else "pending", "dispatchId": self.store.coordination_dispatch(request_id)["dispatchId"]}
        dispatch = self.store.coordination_dispatch(value["id"])
        if dispatch is None:
            try:
                prepare = getattr(self.dispatcher, "prepare", None)
                if not callable(prepare): raise ValueError("durable lead dispatcher preparation is unavailable")
                dispatch_id = str(prepare(value["leadId"], value["scope"], value["id"]))
                if not dispatch_id.strip(): raise ValueError("lead dispatch identity is missing")
            except Exception as error:
                self.store.transition_protocol("coordination-work-request", value["id"], "forward-pending", "dispatch-failed")
                raise ValueError("dispatch-pending") from error
            created = self.store.create_coordination_dispatch_intent(value["id"], dispatch_id, {"request": value, "leadId": value["leadId"], "scope": value["scope"], "idempotencyKey": value["id"]}, owner_id=self.coordination_owner_id, idempotency_key=value["id"])
            dispatch = created["intent"]
            if not created["winner"]:
                return {"accepted": True, "requestId": value["id"], "dispatchId": dispatch["dispatchId"], "status": "pending"}
            try:
                raw_dispatch = self.dispatcher(value["leadId"], value["scope"], value["id"])
                sent_dispatch_id = str(raw_dispatch.get("dispatchId")) if isinstance(raw_dispatch, Mapping) else str(raw_dispatch)
                if sent_dispatch_id != dispatch_id: raise ValueError("lead dispatch identity conflict")
                dispatch = self.store.transition_coordination_dispatch(value["id"], "pending")
            except Exception as error:
                self.store.transition_protocol("coordination-work-request", value["id"], "forward-pending", "dispatch-uncertain")
                raise ValueError("dispatch-pending") from error
        result = self._collect_project_result(value)
        if result is not None:
            self._persist_participant_result(value, result)
            return {"accepted": True, "requestId": request_id, "status": "review-pending" if self.store.coordination_review(request_id) else "pending", "dispatchId": dispatch["dispatchId"]}
        return {"accepted": True, "requestId": value["id"], "dispatchId": dispatch["dispatchId"], "status": "pending"}

    def _collect_supervisor_review(self, request_id: str) -> dict[str, Any] | None:
        request = self.store.protocol_record("coordination-work-request", request_id)
        if request is None:
            raise ValueError("coordination work request is missing")
        group_id = str(request["payload"]["requiredRequestIds"][0])
        review = self.store.coordination_review(group_id)
        if review is None or self.supervisor_result_collector is None:
            return None
        result = self.supervisor_result_collector(str(review["reviewId"]), dict(review["payload"]))
        if result is None:
            return None
        value = dict(result)
        required = {"accepted", "evidence", "occurredAt"}
        if set(value) != required or not isinstance(value["accepted"], bool) or not isinstance(value["evidence"], list) or not value["evidence"] or any(not isinstance(item, str) or not item.strip() for item in value["evidence"]):
            raise ValueError("authoritative supervisor result is invalid")
        context = review["payload"]
        base = {"projectId": context["projectId"], "leadId": context["leadId"], "supervisorLeadId": context["supervisorLeadId"], "decision": "accepted" if value["accepted"] else "rejected", "evidenceId": value["evidence"][0], "linkId": context["linkId"], "version": context["version"], "reviewId": review["reviewId"], "resultId": context["resultId"], "participantResults": context["participantResults"], "coordinationTeamId": context["coordinationTeamId"], "supervisorMemberId": context["supervisorMemberId"], "accepted": value["accepted"], "evidence": value["evidence"], "correlationId": f"cross-project:{context['linkId']}:{context['version']}", "idempotencyKey": f"supervisor:{review['reviewId']}", "occurredAt": value["occurredAt"]}
        final = {**base, "digest": canonical_digest(base)}
        try:
            parse_cross_project_supervisor_review(final)
        except ContractError as error:
            raise ValueError(str(error)) from error
        persisted = self._persist_protocol("cross-project-supervisor-review", str(review["reviewId"]), final)
        if persisted["record"]["state"] == "delivered":
            self.store.transition_coordination_review(group_id, "delivered")
            for required_id in context["requiredRequestIds"]:
                self.store.transition_protocol("coordination-work-request", str(required_id), "settled")
        return self.store.coordination_review(group_id)

    def _collect_project_result(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        dispatch = self.store.coordination_dispatch(str(request["id"]))
        if dispatch is None or self.project_result_collector is None:
            return None
        result = self.project_result_collector(str(dispatch["dispatchId"]), dict(request))
        if result is None:
            return None
        value = dict(result)
        required = {"linkId", "version", "projectId", "leadId", "requestId", "dispatchId", "resultId", "scope", "status", "evidenceId", "digest", "correlationId", "idempotencyKey", "occurredAt"}
        if set(value) != required or value.get("status") != "completed" or any(not isinstance(value.get(field), str) or not value[field].strip() for field in required):
            raise ValueError("authoritative participant result is invalid")
        if value["requestId"] != request["id"] or value["dispatchId"] != dispatch["dispatchId"]:
            raise ValueError("participant result dispatch binding is invalid")
        if any(value[field] != request[field] for field in ("linkId", "version", "projectId", "leadId", "scope")) or value["digest"] != request["expectedResultDigest"]:
            raise ValueError("participant result request binding is invalid")
        return value

    def _persist_participant_result(self, request: Mapping[str, Any], value: Mapping[str, Any]) -> None:
        stored = self._persist_protocol("cross-project-participant-result", value["resultId"], value)
        if stored["record"]["state"] != "delivered":
            return
        self.store.transition_coordination_dispatch(str(request["id"]), "delivered")
        self._maybe_dispatch_supervisor(str(request["id"]))

    def _binding_for_request(self, request: Mapping[str, Any]) -> dict[str, Any]:
        binding = self.store.protocol_record("cross-project-team-binding", str(request["coordinationBindingId"]))
        if binding is None or binding["state"] != "delivered":
            raise ValueError("approved coordination team binding is required")
        return binding["payload"]

    def _maybe_dispatch_supervisor(self, request_id: str) -> dict[str, Any] | None:
        request_record = self.store.protocol_record("coordination-work-request", request_id)
        if request_record is None:
            return None
        request = request_record["payload"]
        binding = self._binding_for_request(request)
        required_ids = request["requiredRequestIds"]
        request_map = {item["id"]: item for item in self.store.list_protocol("coordination-work-request") if item["id"] in required_ids}
        if set(request_map) != set(required_ids): return None
        requests = [request_map[item] for item in required_ids]
        if any(item["payload"].get("coordinationBindingId") != request["coordinationBindingId"] or item["payload"].get("linkId") != request["linkId"] or item["payload"].get("version") != request["version"] or item["payload"].get("requiredRequestIds") != required_ids or item["payload"].get("supervisorLeadId") != request["supervisorLeadId"] for item in requests):
            raise ValueError("coordination request set conflict")
        participants = []
        for item in requests:
            result = next((candidate for candidate in self.store.list_protocol("cross-project-participant-result") if candidate["payload"].get("requestId") == item["id"] and candidate["state"] == "delivered"), None)
            if result is None:
                return None
            participants.append({"resultId": result["payload"]["resultId"], "digest": result["digest"]})
        group_id = str(required_ids[0])
        review = self.store.coordination_review(group_id)
        if review is not None:
            return review
        if self.supervisor_dispatcher is None:
            return None
        idempotency_key = f"cross-project-supervisor:{request['coordinationBindingId']}:{request['linkId']}:{request['version']}"
        anchor = requests[0]["payload"]
        context = {"coordinationBindingId": request["coordinationBindingId"], "linkId": request["linkId"], "version": request["version"], "projectId": anchor["projectId"], "leadId": anchor["leadId"], "supervisorLeadId": request["supervisorLeadId"], "coordinationTeamId": binding["coordinationTeamId"], "supervisorMemberId": binding["supervisorMemberId"], "participantResults": participants, "resultId": participants[0]["resultId"], "requiredRequestIds": required_ids, "requestId": anchor["id"]}
        try:
            prepare = getattr(self.supervisor_dispatcher, "prepare", None)
            if not callable(prepare): raise ValueError("durable supervisor dispatcher preparation is unavailable")
            review_id = str(prepare(str(request["supervisorLeadId"]), context, idempotency_key))
            if not review_id.strip(): raise ValueError("supervisor review dispatch is missing")
        except Exception:
            raise
        created = self.store.create_coordination_review_intent(group_id, review_id, context, owner_id=self.coordination_owner_id, idempotency_key=idempotency_key)
        review = created["intent"]
        if not created["winner"]:
            return review
        try:
            sent_review_id = str(self.supervisor_dispatcher(str(request["supervisorLeadId"]), context, idempotency_key))
            if sent_review_id != review_id: raise ValueError("supervisor review dispatch identity conflict")
            review = self.store.transition_coordination_review(group_id, "pending")
            return review
        except Exception:
            return review

    def _forward_protocol_record(self, record: Mapping[str, Any]) -> None:
        try:
            response = self.sender(str(record["kind"]), str(record["id"]), record["payload"])
            if response.get("accepted") is not True: raise ValueError("Psychlo rejected protocol record")
        except Exception as error:
            self.store.transition_protocol(str(record["kind"]), str(record["id"]), "forward-pending", "forward-failed")
            raise ValueError("forward-pending") from error
        self.store.transition_protocol(str(record["kind"]), str(record["id"]), "delivered")

    receive_cross_project_command = coordinate_cross_project

    def receive_cross_project_participant_result(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        raise ValueError("direct participant result callbacks are not accepted; use the authoritative result collector")

    def receive_cross_project_supervisor_review(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        raise ValueError("direct supervisor callbacks are not accepted; use the authoritative result collector")

    def authorize_concurrency_canary(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try: value = parse_canary_authorization(payload)
        except ContractError as error: raise ValueError(str(error)) from error
        return self._persist_protocol("concurrency-canary-authorization", value["authorizationId"], value)

    receive_concurrency_canary_authorization = authorize_concurrency_canary

    def authorize_concurrency_ceiling(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try: value = parse_concurrency_ceiling_authorization(payload)
        except ContractError as error: raise ValueError(str(error)) from error
        synthetic = {"kind": "concurrency-ceiling-authorization", "id": value["authorizationId"], "digest": value["digest"], "payload": value, "state": "queued"}
        self._revalidate_concurrency_protocol_record(synthetic)
        return self._persist_protocol("concurrency-ceiling-authorization", value["authorizationId"], value)

    receive_concurrency_ceiling_authorization = authorize_concurrency_ceiling

    def receive_concurrency_canary_result(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            value = parse_concurrency_canary_result(payload)
        except ContractError as error:
            raise ValueError(str(error)) from error
        existing_result = self.store.protocol_record("concurrency-canary-result", value["resultId"])
        if existing_result is not None:
            if existing_result["payload"] != value or existing_result.get("digest") != value["digest"]:
                raise ValueError("concurrency canary result conflict")
            return {"accepted": True, "receipt": {"resultId": value["resultId"], "digest": value["digest"], "status": "accepted", "provenanceId": f"overseer:{value['resultId']}"}}
        authorization = self.store.protocol_record("concurrency-canary-authorization", value["authorizationId"])
        if authorization is None or authorization["state"] != "delivered":
            raise ValueError("canary authorization is unavailable")
        if not isinstance(authorization.get("payload"), dict) or authorization.get("digest") != authorization["payload"].get("digest"):
            raise ValueError("canary authorization digest conflict")
        try:
            auth = parse_canary_authorization(authorization["payload"])
        except ContractError as error:
            raise ValueError("canary authorization is invalid") from error
        decision = self.store.decision(str(auth["decisionId"]))
        expected_identities = {(item["projectId"], item["planId"], item["planVersion"], item["leadId"]) for item in auth["projects"]}
        actual_identities = {(item["started"]["projectId"], item["started"]["planId"], item["started"]["planVersion"], item["started"]["leadId"]) for item in value["executions"]}
        if auth["targetTemporaryCeiling"] != value["targetCeiling"] or auth["expectedRevision"] != value["expectedRevision"] or actual_identities != expected_identities or decision is None or decision[2] != "approved":
            raise ValueError("canary result requires its exact approved authorization")
        local_intervals = []
        for execution in value["executions"]:
            round_record = self.store.get_round(str(execution["started"]["roundId"]))
            if round_record is None:
                raise ValueError("canary result round is unavailable")
            timing = self.store.round_timing(str(execution["started"]["roundId"]))
            if timing is None or timing.get("authorizationId") != value["authorizationId"] or not timing.get("startedAt") or not timing.get("completedAt"):
                raise ValueError("canary result timing or authorization conflict")
            try:
                local_started = _time(str(timing["startedAt"]))
                local_completed = _time(str(timing["completedAt"]))
            except (TypeError, ValueError) as error:
                raise ValueError("canary result timing or authorization conflict") from error
            if local_completed < local_started:
                raise ValueError("canary result timing or authorization conflict")
            local_intervals.append((local_started, local_completed))
            request, _, _, _, _, stored_result, _ = round_record
            expected = execution["started"]
            if request.get("roundId") != expected.get("roundId") or any(request.get(key) != expected.get(source) for key, source in (("projectId", "projectId"), ("planId", "planId"), ("planVersion", "planVersion"), ("projectLeadId", "leadId"))):
                raise ValueError("canary result round identity conflict")
            if stored_result is None or stored_result.get("status") != "completed":
                raise ValueError("canary result round is not completed")
            completed = execution["completed"]
            result_digest = _round_result_digest(stored_result)
            evidence_digest = canonical_digest({"provenanceId": stored_result.get("provenanceId"), "resultDigest": result_digest})
            if completed.get("evidenceId") != stored_result.get("provenanceId") or completed.get("resultDigest") != result_digest or completed.get("evidenceDigest") != evidence_digest:
                raise ValueError("canary result evidence does not bind to stored round result")
        if len(local_intervals) != 2 or not (local_intervals[0][0] < local_intervals[1][1] and local_intervals[1][0] < local_intervals[0][1]):
            raise ValueError("canary result timing does not show trusted overlap")
        record, inserted = self.store.record_protocol("concurrency-canary-result", value["resultId"], value["resultId"], value["digest"], value, state="delivered")
        if record["state"] != "delivered":
            record = self.store.transition_protocol("concurrency-canary-result", value["resultId"], "delivered")
        if inserted or record["state"] == "delivered":
            self.store.transition_protocol("concurrency-canary-authorization", value["authorizationId"], "settled")
        receipt = {"resultId": value["resultId"], "digest": value["digest"], "status": "accepted", "provenanceId": f"overseer:{value['resultId']}"}
        return {"accepted": True, "receipt": receipt}

    def change_concurrency_ceiling(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(payload)
        record, inserted = self.store.record_concurrency_ceiling_change(value)
        try:
            self._revalidate_concurrency_protocol_record(record)
        except Exception:
            if record.get("state") not in {"delivered", "settled", "forward-pending"}:
                self.store.transition_protocol("concurrency-ceiling-change", record["id"], "forward-pending", "protocol-integrity-failed")
            raise
        if record["state"] not in {"delivered", "settled"}:
            try:
                response = self.sender("concurrency-ceiling-change", record["id"], record["payload"])
                if response.get("accepted") is not True:
                    raise ValueError("Psychlo rejected concurrency ceiling change")
                record = self.store.transition_protocol("concurrency-ceiling-change", record["id"], "delivered")
            except Exception as error:
                self.store.transition_protocol("concurrency-ceiling-change", record["id"], "forward-pending", "forward-failed")
                raise ValueError("forward-pending") from error
        return {"inserted": inserted, "replay": not inserted, "record": record}

    receive_concurrency_ceiling_change = change_concurrency_ceiling

    def recover_protocol_records(self) -> dict[str, int]:
        recovered = failed = 0
        for kind in ("registry-candidate", "adoption-evidence", "external-round-binding", "ingress-conflict-reconciliation", "cross-project-team-binding", "cross-project-command", "coordination-work-request", "cross-project-participant-result", "cross-project-supervisor-review", "concurrency-canary-authorization", "concurrency-ceiling-authorization", "concurrency-ceiling-change"):
            for record in self.store.pending_protocol(kind):
                try:
                    if record["attempts"] >= 3:
                        continue
                    if kind == "coordination-work-request":
                        self._drive_coordination_request(record["id"])
                        recovered += 1
                        continue
                    if kind == "cross-project-supervisor-review":
                        self._forward_protocol_record(record)
                        review = self.store.coordination_review_for_review_id(str(record["id"]))
                        if review is None: raise ValueError("coordination review is missing")
                        self.store.transition_coordination_review(str(review["requestId"]), "delivered")
                        for request_id in review["payload"]["requiredRequestIds"]:
                            self.store.transition_protocol("coordination-work-request", str(request_id), "settled")
                        recovered += 1
                        continue
                    if kind in {"registry-candidate", "adoption-evidence"}:
                        self._forward_adoption_record(record)
                        recovered += 1
                        continue
                    if kind in {"concurrency-canary-authorization", "concurrency-ceiling-authorization", "concurrency-ceiling-change"}:
                        self._revalidate_concurrency_protocol_record(record)
                    response = self.sender(kind, record["id"], record["payload"])
                    if response.get("accepted") is not True: raise ValueError("rejected")
                    self.store.transition_protocol(kind, record["id"], "delivered")
                    recovered += 1
                except Exception:
                    self.store.transition_protocol(kind, record["id"], "forward-pending", "forward-failed")
                    failed += 1
        return {"recovered": recovered, "failed": failed}

    def _forward_adoption_record(self, record: Mapping[str, Any]) -> None:
        kind = str(record["kind"])
        payload = record.get("payload")
        if not isinstance(payload, Mapping):
            raise ValueError("adoption payload is invalid")
        if kind == "registry-candidate":
            candidate = parse_registry_candidate({**dict(payload), "sourceId": "overseer", "messageId": str(payload.get("candidateId", record["id"])), "schemaVersion": "psychlo.registry-candidate.v1"})
            wire = _registry_wire_payload(candidate)
        elif kind == "adoption-evidence":
            evidence = parse_adoption_evidence({**dict(payload), "sourceId": "overseer", "messageId": str(payload.get("assessmentId", record["id"])), "schemaVersion": "psychlo.adoption-evidence.v1"})
            wire = _adoption_wire_payload(evidence)
        else:
            raise ValueError("unsupported adoption record")
        if canonical_digest(wire) != record.get("digest"):
            raise ValueError("adoption protocol digest conflict")
        response = self.sender(kind, str(record["id"]), wire)
        _validate_adoption_peer_response(kind, wire, response)
        self.store.transition_protocol(kind, str(record["id"]), "delivered", receipt=dict(response))

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

    def __call__(self, project_lead_id: str, prompt: str, idempotency_key: str | None = None) -> str:
        driver, session = self._resolve(project_lead_id)
        result = driver.dispatch_legacy(session, prompt, idempotency_key=idempotency_key)
        if result.state.value not in {"acknowledged", "running", "succeeded"}:
            raise ValueError("project lead dispatch was not acknowledged")
        return result.id

    def prepare(self, project_lead_id: str, prompt: str, idempotency_key: str | None = None) -> str:
        """Resolve the exact stable result identity without dispatching a prompt."""
        driver, session = self._resolve(project_lead_id)
        request = driver.prepare_legacy_dispatch(session, prompt, idempotency_key=idempotency_key)
        return f"result.{request.id}"

    def _resolve(self, project_lead_id: str):
        binding = self.bindings.get(project_lead_id)
        if not isinstance(binding, dict) or not isinstance(binding.get("conversationId"), str):
            raise ValueError("project lead has no approved Codex conversation binding")
        from .agent_adapters.codex import CodexDriver
        driver = CodexDriver.from_legacy_registry()
        session = next((item for item in driver.discover() if item.external_session_id == binding["conversationId"] or item.id == binding["conversationId"]), None)
        if session is None: raise ValueError("bound project lead conversation is unavailable")
        return driver, session


class AuthoritativeAgentResultCollector:
    """Read terminal project-lead results from Overseer's agent result store.

    Dispatch acknowledgements are intentionally not terminal results.  The
    lead must publish the bounded protocol result in the agent dispatch
    evidence before this adapter returns it to the bridge.
    """

    def __init__(self, store_path: str | Path, evidence_key: str = "participant_result"):
        self.store_path = str(store_path)
        self.evidence_key = evidence_key

    def __call__(self, dispatch_id: str, context: Mapping[str, Any]) -> Mapping[str, Any] | None:
        try:
            with SQLiteStore(self.store_path) as store:
                result = store.load_agent_dispatch_result(dispatch_id)
        except (KeyError, OSError, ValueError):
            return None
        if getattr(result.state, "value", result.state) not in {"succeeded", "failed", "blocked"}:
            return None
        evidence = result.evidence.get(self.evidence_key) if isinstance(result.evidence, Mapping) else None
        if not isinstance(evidence, Mapping):
            raise ValueError("authoritative dispatch result evidence is missing")
        value = dict(evidence)
        if value.get("dispatchId") != dispatch_id:
            raise ValueError("authoritative dispatch result identity conflict")
        return value


def create_bridge_from_environment(environment: Mapping[str, str] | None = None) -> PsychloBridge:
    selected = environment or os.environ
    secret = _read_secret(Path(selected["OVERSEER_PSYCHLO_PEER_SECRET_FILE"]))
    store = PsychloBridgeStore(selected["OVERSEER_PSYCHLO_BRIDGE_DATABASE"])
    dispatcher = CodexProjectDispatcher(selected["OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE"])
    sender = PsychloPeerSender(selected.get("OVERSEER_PSYCHLO_ENDPOINT", "http://127.0.0.1:8798"), secret)
    primary_store_path = selected.get("OVERSEER_STORE_DATABASE", selected.get("OVERSEER_STORE_PATH", selected["OVERSEER_PSYCHLO_BRIDGE_DATABASE"]))
    return PsychloBridge(
        store=store,
        dispatcher=dispatcher,
        sender=sender,
        callback_origin="http://127.0.0.1:8766",
        approval_store=SQLiteStore(primary_store_path),
        approval_owner_domain=selected.get("OVERSEER_PSYCHLO_APPROVAL_OWNER_DOMAIN", "sisko"),
        supervisor_dispatcher=dispatcher,
        project_result_collector=AuthoritativeAgentResultCollector(primary_store_path, "participant_result"),
        supervisor_result_collector=AuthoritativeAgentResultCollector(primary_store_path, "supervisor_result"),
        require_external_binding=True,
    )


def _weekly_window(snapshot: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not snapshot: raise ValueError("weekly usage window is required")
    windows = [window for limit in snapshot.get("rate_limits", []) for window in limit.get("windows", []) if isinstance(window, dict)]
    if not windows: raise ValueError("weekly usage window is required")
    return max(windows, key=lambda item: float(item.get("window_minutes", item.get("duration_minutes", 0)) or 0))


def _registry_wire_payload(candidate: Mapping[str, Any]) -> dict[str, Any]:
    allowed = ("candidateId", "projectId", "targetProjectId", "registryId", "registryDigest", "evidenceIds", "evidenceDigests", "evidenceKinds", "canonical", "correlationId", "idempotencyKey", "occurredAt")
    return {key: candidate[key] for key in allowed if key in candidate}


def _adoption_wire_payload(evidence: Mapping[str, Any]) -> dict[str, Any]:
    inner_allowed = ("candidateId", "registry", "repository", "artifact", "application", "team", "ownership", "plan", "lead", "checkpoint", "security", "contradictions", "evidence")
    inner = {key: evidence[key] for key in inner_allowed if key in evidence}
    allowed = ("candidateId", "assessmentId", "correlationId", "idempotencyKey", "occurredAt")
    return {**{key: evidence[key] for key in allowed if key in evidence}, "evidence": inner}


def _validate_adoption_peer_response(kind: str, payload: Mapping[str, Any], response: Mapping[str, Any]) -> None:
    if not isinstance(response, Mapping) or response.get("accepted") is not True:
        raise ValueError("Psychlo rejected adoption evidence")
    if kind == "registry-candidate":
        registration = response.get("registration")
        if registration is not None:
            if not isinstance(registration, Mapping):
                raise ValueError("registry receipt is invalid")
            allowed = {"candidateId", "projectId", "targetProjectId", "registryId", "registryDigest", "evidenceIds", "evidenceDigests", "evidenceKinds", "canonical", "sourceId", "messageId", "correlationId", "idempotencyKey", "occurredAt", "sourceEventSequence"}
            if set(registration) - allowed or registration.get("candidateId") != payload.get("candidateId") or registration.get("sourceId") != "overseer":
                raise ValueError("registry receipt identity conflict")
            if any(key.endswith("Path") or "secret" in key.lower() or "token" in key.lower() for key in registration):
                raise ValueError("registry receipt contains sensitive fields")
            if "sourceEventSequence" in registration and (not isinstance(registration["sourceEventSequence"], int) or isinstance(registration["sourceEventSequence"], bool) or registration["sourceEventSequence"] < 1):
                raise ValueError("registry receipt sequence is invalid")
            registration_for_parse = {key: value for key, value in registration.items() if key != "sourceEventSequence"}
            registration_for_parse["schemaVersion"] = "psychlo.registry-candidate.v1"
            try:
                parse_registry_candidate(registration_for_parse)
            except ContractError as error:
                raise ValueError("registry receipt is invalid") from error
        return
    required = {"accepted", "assessmentId", "candidateId", "classification", "confidence", "evidence", "missingArtifacts", "contradictions", "recommendedWorkflow", "evidenceDigest"}
    optional = {"repositoryDigest"}
    if set(response) - required - optional or not required.issubset(response):
        raise ValueError("adoption receipt is invalid")
    if response.get("assessmentId") != payload.get("assessmentId") or response.get("candidateId") != payload.get("candidateId"):
        raise ValueError("adoption receipt identity conflict")
    submitted_evidence = payload.get("evidence", {}).get("evidence") if isinstance(payload.get("evidence"), Mapping) else None
    if response.get("evidence") != submitted_evidence:
        raise ValueError("adoption receipt evidence conflict")
    if response.get("classification") not in {"recover-active", "adopt-baseline", "cleanup-required", "insufficient-evidence"} or response.get("confidence") not in {"low", "medium", "high"} or response.get("recommendedWorkflow") not in {"reconstruction", "onboarding", "cleanup", "reject"}:
        raise ValueError("adoption receipt classification is invalid")
    allowed_reasons = {"repository-missing", "artifact-missing", "application-purpose-missing", "plan-missing", "lead-missing", "checkpoint-missing", "dirty-repository", "contradictory-history", "ownership-missing", "license-missing", "unsafe-files", "unsafe-modes", "symlinks", "secrets", "personal-exports", "oversized-data"}
    if not isinstance(response.get("missingArtifacts"), list) or not isinstance(response.get("contradictions"), list) or len(response["missingArtifacts"]) > 64 or len(response["contradictions"]) > 64 or any(item not in allowed_reasons for item in response["missingArtifacts"] + response["contradictions"]):
        raise ValueError("adoption receipt classification is invalid")
    if "repositoryDigest" in response and (not isinstance(response["repositoryDigest"], str) or not SHA256_RE.fullmatch(response["repositoryDigest"])):
        raise ValueError("adoption receipt repository digest is invalid")
    if not isinstance(response.get("evidenceDigest"), str) or not SHA256_RE.fullmatch(response["evidenceDigest"]):
        raise ValueError("adoption receipt digest is invalid")


def _require_round(request: Mapping[str, Any]) -> None:
    if not isinstance(request, Mapping):
        raise ValueError("invalid round request")
    required = {"roundId", "projectId", "projectLeadId", "planId", "planVersion", "correlationId", "idempotencyKey", "snapshotId", "policyVersion", "expectedUsageCost", "scope"}
    optional = {"threadId", "model", "featureClass", "selectionReason", "priorityRationale"}
    if set(request) - required - optional or any(name not in request for name in required):
        raise ValueError("invalid round request")
    for name in required - {"expectedUsageCost", "scope"}:
        _required_string(request, name)
    expected_usage = request.get("expectedUsageCost")
    if isinstance(expected_usage, bool) or not isinstance(expected_usage, (int, float)) or not math.isfinite(expected_usage) or expected_usage < 0:
        raise ValueError("invalid round request")
    if request.get("scope") != "one bounded round":
        raise ValueError("invalid round request")
    if request.get("selectionReason", "priority-selected") != "priority-selected":
        raise ValueError("invalid round request")
    if request.get("priorityRationale", "legacy-unknown") not in {"sole-eligible-project", "trivial-effort", "security-impact", "dependency-impact", "manual-priority", "gate-proximity", "project-id", "legacy-unknown"}:
        raise ValueError("invalid round request")
    models = {"gpt-5", "gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol"}
    feature_classes = {"typescript-feature", "javascript-feature", "python-feature", "rust-feature", "go-feature", "java-feature", "kotlin-feature", "swift-feature", "cpp-feature", "csharp-feature", "round-result", "unknown"}
    for name, choices in (("model", models), ("featureClass", feature_classes)):
        if name in request and (not isinstance(request[name], str) or not request[name].strip() or request[name] not in choices):
            raise ValueError("invalid round request")
    if "threadId" in request:
        _required_string(request, "threadId")
        if len(request["threadId"]) > 200:
            raise ValueError("invalid round request")


def _require_bound_result(request: Mapping[str, Any], result: Mapping[str, Any]) -> None:
    for key, value in request.items():
        if result.get(key) != value: raise ValueError("round result does not bind to request")
    if result.get("sourceId") != request["projectLeadId"] or result.get("status") not in {"completed", "blocked"}: raise ValueError("round result is invalid")
    _required_string(result, "provenanceId")


def _round_result_digest(result: Mapping[str, Any]) -> str:
    """Reproduce Psychlo's JSON.stringify order for a parsed RoundResult."""
    fields = ("roundId", "projectId", "projectLeadId", "planId", "planVersion", "threadId", "model", "featureClass", "correlationId", "idempotencyKey", "snapshotId", "policyVersion", "expectedUsageCost", "scope", "selectionReason", "priorityRationale", "sourceId", "provenanceId", "status", "actualUsageCost", "deliveredScope", "remainingEstimate", "blockers", "questions", "reachedExplicitGates", "occurredAt")
    return hashlib.sha256(json.dumps({key: result[key] for key in fields if key in result}, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


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
