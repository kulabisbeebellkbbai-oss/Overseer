"""Private, single-stream protocol bridge between Psychlo and Overseer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from pathlib import Path
import os
import secrets
import sqlite3
from typing import Any, Callable, Mapping
from urllib.request import Request, urlopen


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


class PsychloBridgeStore:
    def __init__(self, filename: str | Path):
        self.filename = Path(filename)
        self.filename.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.filename.parent.chmod(0o700)
        self.connection = sqlite3.connect(self.filename, check_same_thread=False, isolation_level=None)
        self.filename.chmod(0o600)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=1000")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS peer_nonces(nonce TEXT PRIMARY KEY, message_id TEXT NOT NULL, claimed_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rounds(round_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, capability_hash TEXT NOT NULL UNIQUE, result_json TEXT, result_forwarded INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS decisions(decision_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT, reason TEXT);
        """)

    def claim_nonce(self, nonce: str, message_id: str, claimed_at: str) -> bool:
        cursor = self.connection.execute("INSERT OR IGNORE INTO peer_nonces VALUES (?,?,?)", (nonce, message_id, claimed_at))
        return cursor.rowcount == 1

    def get_round(self, round_id: str) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any] | None, bool] | None:
        row = self.connection.execute("SELECT request_json,receipt_json,capability_hash,result_json,result_forwarded FROM rounds WHERE round_id=?", (round_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), row[2], json.loads(row[3]) if row[3] else None, bool(row[4]))

    def active_round(self) -> str | None:
        row = self.connection.execute("SELECT round_id FROM rounds WHERE result_json IS NULL LIMIT 1").fetchone()
        return None if row is None else str(row[0])

    def record_round(self, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str) -> None:
        self.connection.execute("INSERT INTO rounds VALUES (?,?,?,?,NULL,0)", (request["roundId"], _dump(request), _dump(receipt), _token_hash(capability)))

    def round_for_capability(self, capability: str) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any] | None, bool] | None:
        row = self.connection.execute("SELECT request_json,receipt_json,capability_hash,result_json,result_forwarded FROM rounds WHERE capability_hash=?", (_token_hash(capability),)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), row[2], json.loads(row[3]) if row[3] else None, bool(row[4]))

    def record_result(self, round_id: str, result: Mapping[str, Any]) -> None:
        self.connection.execute("UPDATE rounds SET result_json=? WHERE round_id=? AND result_json IS NULL", (_dump(result), round_id))

    def mark_forwarded(self, round_id: str) -> None:
        self.connection.execute("UPDATE rounds SET result_forwarded=1 WHERE round_id=?", (round_id,))

    def attributed_usage_between(self, start: datetime, end: datetime) -> float:
        total = 0.0
        for (payload,) in self.connection.execute("SELECT result_json FROM rounds WHERE result_json IS NOT NULL"):
            result = json.loads(payload)
            occurred_at = _time(str(result["occurredAt"]))
            if start <= occurred_at <= end:
                total += float(result.get("actualUsageCost", 0))
        return total

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


def derive_usage_snapshot(history: list[dict[str, Any]], *, policy_version: str, psychlo_attributed_usage: float = 0, now: str | None = None) -> dict[str, Any]:
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
    prior_day_used = max(0.0, current_used - prior_used - max(0.0, psychlo_attributed_usage))
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

    def request_round(self, request: Mapping[str, Any]) -> dict[str, Any]:
        _require_round(request)
        existing = self.store.get_round(str(request["roundId"]))
        if existing:
            if existing[0] != dict(request): raise ValueError("round identity conflict")
            return {"accepted": True, "receipt": existing[1]}
        if self.store.active_round() is not None: raise ValueError("single_stream_busy")
        capability = self.token_factory()
        receipt = {**request, "sourceId": request["projectLeadId"], "provenanceId": f"overseer-dispatch:{request['roundId']}", "status": "accepted"}
        prompt = self._round_prompt(request, capability)
        provider_reference = self.dispatcher(str(request["projectLeadId"]), prompt)
        receipt["provenanceId"] = str(provider_reference)
        self.store.record_round(request, receipt, capability)
        return {"accepted": True, "receipt": receipt}

    def reconcile_round(self, request: Mapping[str, Any]) -> dict[str, Any]:
        existing = self.store.get_round(str(request.get("roundId", "")))
        if existing and existing[0] == dict(request): return {"accepted": True, "receipt": existing[1]}
        return {"accepted": True, "receipt": {**request, "sourceId": request.get("projectLeadId"), "provenanceId": f"overseer-unknown:{request.get('roundId')}", "status": "unknown"}}

    def receive_round_result(self, capability: str, result: Mapping[str, Any]) -> dict[str, Any]:
        record = self.store.round_for_capability(capability)
        if record is None: raise ValueError("unknown round capability")
        request, _, _, stored_result, forwarded = record
        _require_bound_result(request, result)
        if stored_result is not None and stored_result != dict(result): raise ValueError("round result conflict")
        if stored_result is None: self.store.record_result(str(request["roundId"]), result)
        if not forwarded:
            response = dict(self.sender("round-result", str(result["provenanceId"]), result))
            if response.get("accepted") is not True: raise ValueError("Psychlo rejected round result")
            self.store.mark_forwarded(str(request["roundId"]))
        return {"accepted": True}

    def stage_decision(self, request: Mapping[str, Any]) -> dict[str, Any]:
        decision_id = _required_string(request, "decisionId")
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
        if record is None or record[2] != "staged": raise ValueError("an exact staged Psychlo decision is required")
        status = {"approve": "approved", "deny": "rejected", "request_revision": "rejected"}[decision]
        now = self.clock()
        request = record[0]
        outcome = {**request, "sourceId": "overseer", "provenanceId": f"roadex-outcome:{decision_id}:{status}", "status": status}
        response = self.sender("decision-outcome", str(request["decisionId"]), outcome)
        if response.get("accepted") is not True: raise ValueError("Psychlo rejected decision outcome")
        self.store.decide(decision_id, status, decided_by, now, reason)
        return {"ok": True, "decision": decision, "action_status": status, "mutation_performed": True, "host_mutation_performed": False}

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
        end = _time(str(history[0]["observed_at"]))
        payload = derive_usage_snapshot(
            history,
            policy_version=policy_version,
            psychlo_attributed_usage=self.store.attributed_usage_between(end - timedelta(days=1), end),
        )
        return self.sender("usage-snapshot", str(payload["idempotencyKey"]), payload)


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
        bindings = json.loads(Path(bindings_file).read_text(encoding="utf-8"))
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
    if not path.is_absolute() or path.is_symlink(): raise ValueError("Psychlo peer secret is unavailable")
    metadata = path.stat()
    if not path.is_file() or metadata.st_mode & 0o077 or metadata.st_uid != os.getuid() or metadata.st_size > 4096:
        raise ValueError("Psychlo peer secret is unavailable")
    value = path.read_bytes()
    if len(value) < 32 or len(value) > 4096 or any(byte < 0x20 or byte == 0x7F for byte in value):
        raise ValueError("Psychlo peer secret is unavailable")
    return value
