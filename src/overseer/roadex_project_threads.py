"""Dedicated authenticated Roadex project-human-thread relay.

The relay has no relationship to approval/decision records.  Its wire format,
secret domain, nonce ledger, SQLite tables, receipts, and forwarding queue are
all intentionally independent from ``psychlo_bridge``'s execution protocol.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
from typing import Any, Callable, Mapping
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_BODY_BYTES = 256 * 1024
ROADEx_THREAD_ENDPOINT_PATH = "/api/roadex/project-human-thread-relay"
ROADEx_THREAD_AUTHORITY = "127.0.0.1:8766"
REQUEST_SCHEMA = "roadex.overseer.project-human-thread-relay.v1"
RECEIPT_SCHEMA = "overseer.roadex.project-human-thread-relay-receipt.v1"
REQUEST_DOMAIN = "roadex.overseer.project-human-thread-relay.request.v1"
RECEIPT_DOMAIN = "overseer.roadex.project-human-thread-relay.receipt.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$")
_FORBIDDEN = {"approval", "approvalId", "decision", "decisionId", "plan", "planId", "execute", "execution", "cancel", "cancelId", "deploy", "deployment", "authorization", "authorizationId"}

_BINDING_SCHEMA = "roadex.project-human-thread-binding.v1"
_MESSAGE_SCHEMA = "roadex.project-human-thread-message.v1"
_RESPONSE_SCHEMA = "roadex.project-human-thread-response.v1"
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class ProjectThreadContractError(ValueError):
    pass


def stable_json(value: Any) -> str:
    if isinstance(value, Mapping):
        return "{" + ",".join(json.dumps(str(k), ensure_ascii=False, separators=(",", ":")) + ":" + stable_json(value[k]) for k in sorted(value)) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(stable_json(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def relay_sha256(value: str | bytes) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else value.encode("utf-8")).hexdigest()


def _digest(value: Mapping[str, Any]) -> str:
    return relay_sha256(stable_json(value))


def _id(value: Any, name: str) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ProjectThreadContractError(f"{name} is invalid")


def _timestamp(value: Any, name: str) -> None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise ProjectThreadContractError(f"{name} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ProjectThreadContractError(f"{name} is invalid") from None
    if parsed.tzinfo is None:
        raise ProjectThreadContractError(f"{name} is invalid")


def _strict(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProjectThreadContractError(f"{name} fields are invalid")
    return value


def _reject_control_fields(value: Mapping[str, Any]) -> None:
    for key, child in value.items():
        if key in _FORBIDDEN:
            raise ProjectThreadContractError("project thread record contains approval control fields")
        if isinstance(child, Mapping):
            _reject_control_fields(child)
        elif isinstance(child, list):
            for item in child:
                if isinstance(item, Mapping):
                    _reject_control_fields(item)


def parse_project_human_thread_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    keys = {"schemaVersion", "bindingId", "projectId", "root", "purpose", "conversationId", "generation", "status", "predecessorGeneration", "creationMode", "provenanceDigest", "createdAt", "updatedAt", "retiredAt", "recordDigest"}
    item = _strict(value, keys, "binding"); _reject_control_fields(item)
    if item["schemaVersion"] != _BINDING_SCHEMA:
        raise ProjectThreadContractError("binding schema is invalid")
    _id(item["bindingId"], "bindingId"); project_id = item["projectId"]; _id(project_id, "projectId")
    generation = item["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0 or item["bindingId"] != f"project-human-thread:{project_id}:{generation}":
        raise ProjectThreadContractError("binding identity is invalid")
    root = _strict(item["root"], {"canonicalPath", "dev", "ino"}, "root")
    if not isinstance(root["canonicalPath"], str) or not root["canonicalPath"].startswith("/") or root["canonicalPath"] != root["canonicalPath"].strip() or len(root["canonicalPath"]) > 4096:
        raise ProjectThreadContractError("root canonicalPath is invalid")
    if not isinstance(root["dev"], str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", root["dev"]):
        raise ProjectThreadContractError("root dev is invalid")
    if not isinstance(root["ino"], str) or not re.fullmatch(r"[1-9][0-9]{0,19}", root["ino"]):
        raise ProjectThreadContractError("root ino is invalid")
    if item["purpose"] != "human-interaction" or not isinstance(item["conversationId"], str) or not _UUID.fullmatch(item["conversationId"]):
        raise ProjectThreadContractError("binding purpose or conversation is invalid")
    if item["status"] not in {"active", "unavailable", "replacement-pending", "retired"}:
        raise ProjectThreadContractError("binding status is invalid")
    predecessor = item["predecessorGeneration"]
    if generation == 1 and predecessor is not None or generation > 1 and predecessor != generation - 1:
        raise ProjectThreadContractError("binding lineage is invalid")
    if item["creationMode"] not in {"created", "adopted"}:
        raise ProjectThreadContractError("binding creation mode is invalid")
    for key in ("provenanceDigest", "recordDigest"):
        if not isinstance(item[key], str) or not _DIGEST.fullmatch(item[key]):
            raise ProjectThreadContractError(f"binding {key} is invalid")
    _timestamp(item["createdAt"], "createdAt"); _timestamp(item["updatedAt"], "updatedAt")
    if item["retiredAt"] is not None: _timestamp(item["retiredAt"], "retiredAt")
    if (item["status"] == "retired") != (item["retiredAt"] is not None):
        raise ProjectThreadContractError("binding retirement is invalid")
    if datetime.fromisoformat(item["updatedAt"].replace("Z", "+00:00")) < datetime.fromisoformat(item["createdAt"].replace("Z", "+00:00")):
        raise ProjectThreadContractError("binding timestamps are invalid")
    if item["retiredAt"] is not None and datetime.fromisoformat(item["retiredAt"].replace("Z", "+00:00")) < datetime.fromisoformat(item["createdAt"].replace("Z", "+00:00")):
        raise ProjectThreadContractError("binding retirement timestamp is invalid")
    if _digest({key: value for key, value in item.items() if key != "recordDigest"}) != item["recordDigest"]:
        raise ProjectThreadContractError("binding digest is invalid")
    return dict(item)


def parse_project_human_thread_message(value: Mapping[str, Any]) -> dict[str, Any]:
    keys = {"schemaVersion", "messageId", "projectId", "conversationId", "generation", "kind", "content", "choices", "contentDigest", "correlationId", "idempotencyKey", "occurredAt", "messageDigest"}
    item = _strict(value, keys, "message"); _reject_control_fields(item)
    if item["schemaVersion"] != _MESSAGE_SCHEMA: raise ProjectThreadContractError("message schema is invalid")
    for key in ("messageId", "projectId", "correlationId", "idempotencyKey"): _id(item[key], key)
    if not isinstance(item["conversationId"], str) or not _UUID.fullmatch(item["conversationId"]): raise ProjectThreadContractError("message conversation is invalid")
    if isinstance(item["generation"], bool) or not isinstance(item["generation"], int) or item["generation"] <= 0: raise ProjectThreadContractError("message generation is invalid")
    if item["kind"] not in {"question", "bounded-choice", "clarification", "informational-notice"}: raise ProjectThreadContractError("message kind is invalid")
    if not isinstance(item["content"], str) or not 1 <= len(item["content"]) <= 6000 or item["content"] != item["content"].strip(): raise ProjectThreadContractError("message content is invalid")
    choices = item["choices"]
    if not isinstance(choices, list) or len(choices) > 20 or any(not isinstance(choice, str) or not 1 <= len(choice) <= 160 or choice != choice.strip() for choice in choices) or len(set(choices)) != len(choices) or ((item["kind"] == "bounded-choice") != bool(choices)): raise ProjectThreadContractError("message choices are invalid")
    for key in ("contentDigest", "messageDigest"):
        if not isinstance(item[key], str) or not _DIGEST.fullmatch(item[key]): raise ProjectThreadContractError(f"message {key} is invalid")
    if relay_sha256(item["content"]) != item["contentDigest"] or _digest({key: value for key, value in item.items() if key != "messageDigest"}) != item["messageDigest"]: raise ProjectThreadContractError("message digest is invalid")
    _timestamp(item["occurredAt"], "occurredAt")
    return dict(item)


def parse_project_human_thread_response(value: Mapping[str, Any]) -> dict[str, Any]:
    keys = {"schemaVersion", "responseId", "messageId", "projectId", "conversationId", "generation", "content", "contentDigest", "correlationId", "idempotencyKey", "occurredAt", "responseDigest"}
    item = _strict(value, keys, "response"); _reject_control_fields(item)
    if item["schemaVersion"] != _RESPONSE_SCHEMA: raise ProjectThreadContractError("response schema is invalid")
    for key in ("responseId", "messageId", "projectId", "correlationId", "idempotencyKey"): _id(item[key], key)
    if not isinstance(item["conversationId"], str) or not _UUID.fullmatch(item["conversationId"]): raise ProjectThreadContractError("response conversation is invalid")
    if isinstance(item["generation"], bool) or not isinstance(item["generation"], int) or item["generation"] <= 0: raise ProjectThreadContractError("response generation is invalid")
    if not isinstance(item["content"], str) or not 1 <= len(item["content"]) <= 6000 or item["content"] != item["content"].strip(): raise ProjectThreadContractError("response content is invalid")
    for key in ("contentDigest", "responseDigest"):
        if not isinstance(item[key], str) or not _DIGEST.fullmatch(item[key]): raise ProjectThreadContractError(f"response {key} is invalid")
    if relay_sha256(item["content"]) != item["contentDigest"] or _digest({key: value for key, value in item.items() if key != "responseDigest"}) != item["responseDigest"]: raise ProjectThreadContractError("response digest is invalid")
    _timestamp(item["occurredAt"], "occurredAt")
    return dict(item)


def _hmac(secret: bytes, domain: str, *parts: str) -> str:
    return hmac.new(secret, "\n".join((domain, *parts)).encode("utf-8"), hashlib.sha256).hexdigest()


def _require_secret(secret: bytes, label: str) -> None:
    if not isinstance(secret, bytes) or not 32 <= len(secret) <= 256 or any(byte < 0x20 or byte > 0x7E for byte in secret):
        raise ValueError(f"{label} is invalid")


def request_headers(secret: bytes, body: bytes, timestamp: str, nonce: str) -> dict[str, str]:
    return {"content-type": "application/json", "content-length": str(len(body)), "x-roadex-relay-timestamp": timestamp, "x-roadex-relay-nonce": nonce, "x-roadex-relay-signature": _hmac(secret, REQUEST_DOMAIN, timestamp, nonce, relay_sha256(body))}


@dataclass(frozen=True)
class RelayResponse:
    status: int
    body: bytes
    headers: dict[str, str]


class RoadexProjectThreadStore:
    """Dedicated durable relay state; no shared approval tables."""

    def __init__(self, filename: str | Path):
        self.filename = Path(filename)
        self.filename.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self.filename.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077: raise ValueError("Roadex relay directory must be private")
        if self.filename.exists() or self.filename.is_symlink():
            metadata = self.filename.stat(follow_symlinks=False)
            if self.filename.is_symlink() or not self.filename.is_file() or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077: raise ValueError("Roadex relay database must be private")
        self.connection = sqlite3.connect(self.filename, check_same_thread=False, isolation_level=None, timeout=30.0)
        self.filename.chmod(0o600); self.connection.execute("PRAGMA journal_mode=WAL"); self.connection.execute("PRAGMA synchronous=FULL"); self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.executescript("""
        CREATE TABLE IF NOT EXISTS roadex_project_thread_relay_nonces(nonce TEXT PRIMARY KEY,message_id TEXT NOT NULL,request_digest TEXT NOT NULL,claimed_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS roadex_project_thread_relay_inbox(record_id TEXT PRIMARY KEY,record_type TEXT NOT NULL,record_digest TEXT NOT NULL UNIQUE,project_id TEXT NOT NULL,record_json TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS roadex_project_thread_relay_outbox(record_id TEXT PRIMARY KEY,record_type TEXT NOT NULL,record_digest TEXT NOT NULL UNIQUE,project_id TEXT NOT NULL,record_json TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT,updated_at TEXT NOT NULL,receipt_json TEXT);
        CREATE TABLE IF NOT EXISTS roadex_project_thread_relay_receipts(record_id TEXT PRIMARY KEY,request_digest TEXT NOT NULL UNIQUE,request_nonce TEXT NOT NULL UNIQUE,receipt_nonce TEXT NOT NULL UNIQUE,body BLOB NOT NULL,occurred_at TEXT NOT NULL,signature TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS roadex_project_thread_question_outbox(record_id TEXT PRIMARY KEY,record_type TEXT NOT NULL,record_digest TEXT NOT NULL,body BLOB NOT NULL,request_nonce TEXT NOT NULL UNIQUE,request_timestamp TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,claimed_at TEXT);
        CREATE TABLE IF NOT EXISTS roadex_project_thread_question_receipts(record_id TEXT PRIMARY KEY,request_nonce TEXT NOT NULL UNIQUE,receipt_nonce TEXT NOT NULL UNIQUE,body BLOB NOT NULL,receipt_digest TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS roadex_project_thread_question_nonces(nonce TEXT PRIMARY KEY,message_id TEXT NOT NULL,claimed_at TEXT NOT NULL);
        """)
        self._lock = threading.RLock()
        try:
            self.connection.execute("ALTER TABLE roadex_project_thread_question_outbox ADD COLUMN claimed_at TEXT")
        except sqlite3.OperationalError:
            pass

    def close(self) -> None: self.connection.close()

    def nonce(self, nonce: str) -> tuple[str, str] | None:
        with self._lock:
            row = self.connection.execute("SELECT message_id,request_digest FROM roadex_project_thread_relay_nonces WHERE nonce=?", (nonce,)).fetchone()
        return None if row is None else (str(row[0]), str(row[1]))

    def receipt(self, record_id: str) -> RelayResponse | None:
        with self._lock:
            row = self.connection.execute("SELECT record_id,request_digest,request_nonce,receipt_nonce,body,occurred_at,signature FROM roadex_project_thread_relay_receipts WHERE record_id=?", (record_id,)).fetchone()
        if row is None: return None
        return RelayResponse(202, bytes(row[4]), {"x-overseer-relay-timestamp": str(row[5]), "x-overseer-relay-signature": str(row[6]), "content-type": "application/json"})

    def insert(self, *, record_id: str, record_type: str, record_digest: str, project_id: str, record: Mapping[str, Any], request_digest: str, request_nonce: str, receipt_nonce: str, receipt_body: bytes, occurred_at: str, signature: str) -> None:
        encoded = stable_json(record)
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute("INSERT INTO roadex_project_thread_relay_nonces VALUES (?,?,?,?)", (request_nonce, record_id, request_digest, occurred_at))
                self.connection.execute("INSERT INTO roadex_project_thread_relay_inbox VALUES (?,?,?,?,?,'accepted',0,?)", (record_id, record_type, record_digest, project_id, encoded, occurred_at))
                self.connection.execute("INSERT INTO roadex_project_thread_relay_outbox(record_id,record_type,record_digest,project_id,record_json,state,attempts,last_error,updated_at,receipt_json) VALUES (?,?,?,?,?,'pending',0,NULL,?,NULL)", (record_id, record_type, record_digest, project_id, encoded, occurred_at))
                self.connection.execute("INSERT INTO roadex_project_thread_relay_receipts VALUES (?,?,?,?,?,?,?)", (record_id, request_digest, request_nonce, receipt_nonce, receipt_body, occurred_at, signature))
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK"); raise

    def current_binding(self, project_id: str) -> dict[str, Any] | None:
        with self._lock:
            rows = self.connection.execute("SELECT record_json FROM roadex_project_thread_relay_inbox WHERE record_type='binding' AND project_id=? ORDER BY rowid DESC", (project_id,)).fetchall()
        if not rows:
            return None
        item = json.loads(rows[0][0])
        return item if item.get("status") == "active" else None

    def existing(self, record_id: str) -> tuple[str, str] | None:
        with self._lock:
            row = self.connection.execute("SELECT record_type,record_digest FROM roadex_project_thread_relay_inbox WHERE record_id=?", (record_id,)).fetchone()
        return None if row is None else (str(row[0]), str(row[1]))

    def pending(self, limit: int = 32) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute("SELECT record_id,record_type,record_digest,project_id,record_json,attempts FROM roadex_project_thread_relay_outbox WHERE state='pending' ORDER BY rowid LIMIT ?", (max(1, min(128, int(limit))),)).fetchall()
        return [{"recordId": row[0], "recordType": row[1], "recordDigest": row[2], "projectId": row[3], "record": json.loads(row[4]), "attempts": row[5]} for row in rows]

    def mark_delivered(self, record_id: str, receipt: Mapping[str, Any]) -> None:
        with self._lock:
            self.connection.execute("UPDATE roadex_project_thread_relay_outbox SET state='delivered',receipt_json=?,updated_at=?,last_error=NULL WHERE record_id=? AND state='pending'", (stable_json(receipt), datetime.now(UTC).isoformat(), record_id))

    def mark_failed(self, record_id: str, error: str) -> None:
        with self._lock:
            self.connection.execute("UPDATE roadex_project_thread_relay_outbox SET attempts=attempts+1,last_error=?,updated_at=? WHERE record_id=? AND state='pending'", (str(error)[:1000], datetime.now(UTC).isoformat(), record_id))

    def state(self, record_id: str) -> str | None:
        with self._lock:
            row = self.connection.execute("SELECT state FROM roadex_project_thread_relay_outbox WHERE record_id=?", (record_id,)).fetchone()
        return None if row is None else str(row[0])


def _parse_record(record_type: str, record: Mapping[str, Any]) -> dict[str, Any]:
    if record_type == "binding": return parse_project_human_thread_binding(record)
    if record_type == "message": return parse_project_human_thread_message(record)
    if record_type == "response": return parse_project_human_thread_response(record)
    raise ProjectThreadContractError("unsupported project-thread record type")


class RoadexProjectThreadRelay:
    def __init__(self, *, store: RoadexProjectThreadStore, secret: bytes, clock: Callable[[], str] | None = None, forwarder: Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]] | None = None, question_sender: "RoadexQuestionSender | None" = None):
        _require_secret(secret, "Roadex relay secret")
        self.store, self.secret, self.clock, self.forwarder, self.question_sender = store, secret, clock or (lambda: datetime.now(UTC).isoformat()), forwarder, question_sender
        self._lock = threading.RLock()

    def request_scoped(self) -> "RoadexProjectThreadRelay":
        """Give a threaded HTTP worker its own SQLite handle."""
        scoped_store = RoadexProjectThreadStore(self.store.filename)
        scoped_sender = None
        if self.question_sender is not None:
            scoped_sender = RoadexQuestionSender(store=scoped_store, secret=self.question_sender.secret, endpoint=self.question_sender.endpoint, clock=self.question_sender.clock, send=self.question_sender._send)
        return RoadexProjectThreadRelay(
            store=scoped_store,
            secret=self.secret,
            clock=self.clock,
            forwarder=self.forwarder,
            question_sender=scoped_sender,
        )

    def close(self) -> None:
        self.store.close()

    def claim_question_nonce(self, nonce: str, message_id: str, claimed_at: str) -> bool:
        with self.store._lock:
            self.store.connection.execute("INSERT OR IGNORE INTO roadex_project_thread_question_nonces VALUES (?,?,?)", (nonce, message_id, claimed_at))
            row = self.store.connection.execute("SELECT message_id FROM roadex_project_thread_question_nonces WHERE nonce=?", (nonce,)).fetchone()
            return row is not None and row[0] == message_id

    def receive_psychlo_question(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if self.question_sender is None:
            raise ValueError("project_thread_question_sender_not_configured")
        parsed = parse_project_human_thread_message(payload)
        queued = self.question_sender.enqueue(parsed)
        persistence_id = f"overseer-roadex-project-thread-question:{relay_sha256(parsed['messageId'])[:48]}"
        return {"schemaVersion": PSYCHLO_QUESTION_RECEIPT_SCHEMA, "accepted": True, "messageId": parsed["messageId"], "messageDigest": parsed["messageDigest"], "persistenceId": persistence_id, "state": queued["state"]}

    def _verify(self, body: bytes, headers: Mapping[str, str]) -> tuple[str, str, str]:
        # Roadex's fetch transport supplies content-type and the three signed
        # relay headers; HTTP may add content-length/host, but they are not
        # part of the cross-process signature contract.
        required = ("content-type", "x-roadex-relay-timestamp", "x-roadex-relay-nonce", "x-roadex-relay-signature")
        if not isinstance(body, bytes) or not body or len(body) > MAX_BODY_BYTES or any(not isinstance(headers.get(key), str) or "," in headers[key] for key in required): raise ValueError("invalid_request")
        if headers["content-type"] != "application/json" or ("content-length" in headers and headers["content-length"] != str(len(body))) or not _NONCE.fullmatch(headers["x-roadex-relay-nonce"]): raise ValueError("invalid_headers")
        _timestamp(headers["x-roadex-relay-timestamp"], "relay timestamp")
        signature = headers["x-roadex-relay-signature"]
        if not _DIGEST.fullmatch(signature) or not hmac.compare_digest(signature, _hmac(self.secret, REQUEST_DOMAIN, headers["x-roadex-relay-timestamp"], headers["x-roadex-relay-nonce"], relay_sha256(body))): raise ValueError("invalid_signature")
        try: envelope = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error: raise ValueError("invalid_message") from error
        if not isinstance(envelope, dict) or set(envelope) != {"schemaVersion", "recordType", "recordId", "recordDigest", "record"} or envelope["schemaVersion"] != REQUEST_SCHEMA: raise ValueError("invalid_message")
        record_type, record_id, record_digest, record = envelope["recordType"], envelope["recordId"], envelope["recordDigest"], envelope["record"]
        # Roadex sends lifecycle bindings and human responses into this
        # receiver.  Questions/messages originate in Psychlo and use the
        # separate question egress below; accepting them here would collapse
        # the two directions and re-open the approval-route confusion.
        if record_type not in {"binding", "response"} or not isinstance(record, dict): raise ValueError("unsupported_project_thread_record")
        _id(record_id, "recordId")
        try: parsed = _parse_record(record_type, record)
        except ProjectThreadContractError as error: raise ValueError(str(error)) from error
        actual_digest = parsed.get("recordDigest", parsed.get("messageDigest", parsed.get("responseDigest")))
        if record_digest != actual_digest: raise ValueError("project thread record digest is invalid")
        inner_id = parsed.get("bindingId", parsed.get("messageId", parsed.get("responseId")))
        _id(inner_id, "inner record identity")
        project_id = parsed["projectId"]
        if record_type == "message":
            binding = self.store.current_binding(project_id)
            if binding is None or binding["conversationId"] != parsed["conversationId"] or binding["generation"] != parsed["generation"]: raise ValueError("project thread binding is not current")
        return record_type, record_id, project_id

    def receive(self, body: bytes, headers: Mapping[str, str]) -> RelayResponse:
        record_type, record_id, project_id = self._verify(body, headers)
        request_digest = relay_sha256(body); request_nonce = headers["x-roadex-relay-nonce"]
        existing_nonce = self.store.nonce(request_nonce)
        if existing_nonce is not None:
            if existing_nonce != (record_id, request_digest): raise ValueError("nonce_reuse")
            exact = self.store.receipt(record_id)
            if exact is None: raise ValueError("replay_receipt_missing")
            return exact
        envelope = json.loads(body.decode("utf-8")); record = envelope["record"]
        receipt = {"schemaVersion": RECEIPT_SCHEMA, "accepted": True, "recordType": record_type, "recordId": record_id, "recordDigest": envelope["recordDigest"], "requestNonce": request_nonce, "receiptNonce": f"receipt-{secrets.token_urlsafe(18)}", "occurredAt": self.clock()}
        receipt_body = stable_json(receipt).encode("utf-8"); response_timestamp = receipt["occurredAt"]
        response_signature = _hmac(self.secret, RECEIPT_DOMAIN, response_timestamp, request_nonce, relay_sha256(receipt_body))
        response = RelayResponse(202, receipt_body, {"content-type": "application/json", "x-overseer-relay-timestamp": response_timestamp, "x-overseer-relay-signature": response_signature})
        try: self.store.insert(record_id=record_id, record_type=record_type, record_digest=envelope["recordDigest"], project_id=project_id, record=record, request_digest=request_digest, request_nonce=request_nonce, receipt_nonce=receipt["receiptNonce"], receipt_body=receipt_body, occurred_at=response_timestamp, signature=response_signature)
        except sqlite3.DatabaseError:
            # A concurrent request with the exact same nonce/body may have
            # committed while this worker was validating.  Only that exact
            # replay is safe to return; a new nonce is an identity conflict.
            if self.store.nonce(request_nonce) == (record_id, request_digest):
                exact = self.store.receipt(record_id)
                if exact is not None:
                    return exact
            raise ValueError("project thread record conflict") from None
        return response

    def forward_pending(self, *, limit: int = 32) -> dict[str, int]:
        if self.forwarder is None: return {"delivered": 0, "failed": 0}
        delivered = failed = 0
        for row in self.store.pending(limit):
            try:
                result = self.forwarder(row["recordType"], row["recordId"], row["record"])
                if not isinstance(result, Mapping): raise ValueError("Psychlo rejected project-thread record")
                receipt = dict(result)
                if set(receipt) != {"schemaVersion", "accepted", "recordType", "recordId", "recordDigest", "state"} or receipt.get("schemaVersion") != PSYCHLO_RELAY_RECEIPT_SCHEMA or receipt.get("accepted") is not True or receipt.get("state") not in {"inserted", "replayed"} or receipt.get("recordType") != row["recordType"] or receipt.get("recordId") != row["recordId"] or receipt.get("recordDigest") != row["recordDigest"]: raise ValueError("Psychlo project-thread receipt binding is invalid")
                self.store.mark_delivered(row["recordId"], receipt); delivered += 1
            except Exception as error:
                self.store.mark_failed(row["recordId"], str(error)); failed += 1
        return {"delivered": delivered, "failed": failed}

    def tick(self, *, limit: int = 32) -> dict[str, int]:
        result = self.forward_pending(limit=limit)
        if self.question_sender is not None:
            question_result = self.question_sender.retry_pending(limit=limit)
            result["questionDelivered"] = question_result["delivered"]
            result["questionFailed"] = question_result["failed"]
        return result


QUESTION_ENDPOINT_PATH = "/api/internal/overseer/project-human-thread/questions"
QUESTION_REQUEST_SCHEMA = "overseer.project-human-thread-question.v1"
QUESTION_RECEIPT_SCHEMA = "roadex.overseer.project-human-thread.question-receipt.v1"
QUESTION_REQUEST_DOMAIN = "overseer.roadex.project-human-thread.question.v1"
QUESTION_RECEIPT_DOMAIN = "roadex.overseer.project-human-thread.question-receipt.v1"
QUESTION_AUTHORITY = "127.0.0.1:8780"
PSYCHLO_QUESTION_RECEIPT_SCHEMA = "overseer.psychlo.project-human-thread-question-receipt.v1"
PSYCHLO_RELAY_RECEIPT_SCHEMA = "psychlo.overseer.project-human-thread-relay-receipt.v1"


def question_request_headers(secret: bytes, body: bytes, timestamp: str, nonce: str) -> dict[str, str]:
    return {"content-type": "application/json", "content-length": str(len(body)), "x-overseer-question-timestamp": timestamp, "x-overseer-question-nonce": nonce, "x-overseer-question-signature": _hmac(secret, QUESTION_REQUEST_DOMAIN, timestamp, nonce, relay_sha256(body))}


def _question_receipt_signature(secret: bytes, timestamp: str, request_nonce: str, body: bytes) -> str:
    return _hmac(secret, QUESTION_RECEIPT_DOMAIN, timestamp, request_nonce, relay_sha256(body))


class RoadexQuestionSender:
    """Durable Psychlo-question egress to Roadex on a separate endpoint."""

    def __init__(self, *, store: RoadexProjectThreadStore, secret: bytes, endpoint: str = "http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock: Callable[[], str] | None = None, send: Callable[[bytes, Mapping[str, str]], Mapping[str, Any]] | None = None, claim_timeout_seconds: int = 60):
        _require_secret(secret, "Roadex question secret")
        if endpoint != "http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH: raise ValueError("Roadex question endpoint is invalid")
        self.store, self.secret, self.endpoint = store, secret, endpoint
        self.clock, self._send, self.claim_timeout_seconds = clock or (lambda: datetime.now(UTC).isoformat()), send or self._http_send, max(1, int(claim_timeout_seconds))
        self._lock = threading.RLock()

    def request_scoped(self) -> "RoadexQuestionSender":
        return RoadexQuestionSender(store=RoadexProjectThreadStore(self.store.filename), secret=self.secret, endpoint=self.endpoint, clock=self.clock, send=self._send, claim_timeout_seconds=self.claim_timeout_seconds)

    def close(self) -> None: self.store.close()

    def _http_send(self, body: bytes, headers: Mapping[str, str]) -> Mapping[str, Any]:
        request = Request(self.endpoint, data=body, headers=dict(headers), method="POST")
        class _RejectRedirects(HTTPRedirectHandler):
            def redirect_request(self, request, file_pointer, code, message, headers, new_url):
                raise ValueError("Roadex question redirects are forbidden")
        with build_opener(ProxyHandler({}), _RejectRedirects()).open(request, timeout=10.0) as response:
            return {"status": response.status, "body": response.read(MAX_BODY_BYTES + 1), "headers": dict(response.headers.items())}

    def enqueue(self, record: Mapping[str, Any], delivery_id: str | None = None) -> dict[str, Any]:
        parsed = parse_project_human_thread_message(record)
        record_id = delivery_id or parsed["messageId"]
        _id(record_id, "question recordId")
        digest = parsed["messageDigest"]
        body = stable_json({"schemaVersion": QUESTION_REQUEST_SCHEMA, "message": parsed}).encode()
        timestamp = self.clock(); nonce = f"question-{secrets.token_urlsafe(18)}"
        _timestamp(timestamp, "question timestamp")
        with self.store._lock:
            existing = self.store.connection.execute("SELECT record_type,record_digest,body,request_nonce,request_timestamp,state,attempts FROM roadex_project_thread_question_outbox WHERE record_id=?", (record_id,)).fetchone()
            if existing is not None:
                if tuple(existing[:3]) != ("message", digest, body): raise ValueError("project-thread question conflict")
                return {"recordId": record_id, "recordDigest": digest, "state": existing[5], "attempts": existing[6], "requestNonce": existing[3], "requestTimestamp": existing[4]}
            self.store.connection.execute("""CREATE TABLE IF NOT EXISTS roadex_project_thread_question_outbox(record_id TEXT PRIMARY KEY,record_type TEXT NOT NULL,record_digest TEXT NOT NULL,body BLOB NOT NULL,request_nonce TEXT NOT NULL UNIQUE,request_timestamp TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,claimed_at TEXT)""")
            self.store.connection.execute("INSERT INTO roadex_project_thread_question_outbox(record_id,record_type,record_digest,body,request_nonce,request_timestamp,state,attempts,claimed_at) VALUES (?,?,?,?,?,?,'pending',0,NULL)", (record_id, "message", digest, body, nonce, timestamp))
        return {"recordId": record_id, "recordDigest": digest, "state": "pending", "attempts": 0, "requestNonce": nonce, "requestTimestamp": timestamp}

    def _rows(self, limit: int) -> list[dict[str, Any]]:
        with self.store._lock:
            self.store.connection.execute("""CREATE TABLE IF NOT EXISTS roadex_project_thread_question_outbox(record_id TEXT PRIMARY KEY,record_type TEXT NOT NULL,record_digest TEXT NOT NULL,body BLOB NOT NULL,request_nonce TEXT NOT NULL UNIQUE,request_timestamp TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,claimed_at TEXT)""")
            try:
                now = datetime.fromisoformat(self.clock().replace("Z", "+00:00"))
                stale_before = (now - timedelta(seconds=self.claim_timeout_seconds)).isoformat()
            except (AttributeError, TypeError, ValueError):
                # An invalid clock cannot safely classify an in-flight claim;
                # pending work remains retryable and sending work is left for
                # the next valid tick.
                stale_before = None
            query = "SELECT record_id,record_type,record_digest,body,request_nonce,request_timestamp,state,attempts FROM roadex_project_thread_question_outbox WHERE state='pending'"
            parameters: tuple[Any, ...] = ()
            if stale_before is not None:
                query += " OR (state='sending' AND claimed_at IS NOT NULL AND julianday(claimed_at) < julianday(?))"
                parameters = (stale_before,)
            query += " ORDER BY rowid LIMIT ?"
            rows = self.store.connection.execute(query, (*parameters, max(1, min(128, int(limit))))).fetchall()
        return [{"recordId": row[0], "recordType": row[1], "recordDigest": row[2], "body": bytes(row[3]), "requestNonce": row[4], "requestTimestamp": row[5], "state": row[6], "attempts": row[7]} for row in rows]

    def _claim(self, record_id: str) -> dict[str, Any]:
        with self.store._lock:
            self.store.connection.execute("BEGIN IMMEDIATE")
            try:
                self.store.connection.execute("""CREATE TABLE IF NOT EXISTS roadex_project_thread_question_outbox(record_id TEXT PRIMARY KEY,record_type TEXT NOT NULL,record_digest TEXT NOT NULL,body BLOB NOT NULL,request_nonce TEXT NOT NULL UNIQUE,request_timestamp TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,claimed_at TEXT)""")
                row = self.store.connection.execute("SELECT record_id,record_type,record_digest,body,request_nonce,request_timestamp,state,attempts FROM roadex_project_thread_question_outbox WHERE record_id=?", (record_id,)).fetchone()
                if row is None: raise ValueError("project-thread question is missing")
                if row[6] == "delivered":
                    self.store.connection.execute("COMMIT")
                    return {"recordId": row[0], "recordType": row[1], "recordDigest": row[2], "body": bytes(row[3]), "requestNonce": row[4], "requestTimestamp": row[5], "state": row[6], "attempts": row[7]}
                current_state = row[6]
                if current_state == "sending":
                    claimed = self.store.connection.execute("SELECT claimed_at FROM roadex_project_thread_question_outbox WHERE record_id=?", (record_id,)).fetchone()[0]
                    try:
                        stale = (datetime.fromisoformat(self.clock().replace("Z", "+00:00")) - datetime.fromisoformat(str(claimed).replace("Z", "+00:00"))).total_seconds() > self.claim_timeout_seconds
                    except (TypeError, ValueError):
                        stale = False
                    if not stale: raise ValueError("project-thread question is already claimed")
                    self.store.connection.execute("UPDATE roadex_project_thread_question_outbox SET state='pending',claimed_at=NULL WHERE record_id=?", (record_id,))
                    current_state = "pending"
                if current_state != "pending": raise ValueError("project-thread question is already claimed")
                claimed_at = self.clock()
                self.store.connection.execute("UPDATE roadex_project_thread_question_outbox SET state='sending',attempts=attempts+1,claimed_at=? WHERE record_id=? AND state='pending'", (claimed_at, record_id))
                self.store.connection.execute("COMMIT")
                return {"recordId": row[0], "recordType": row[1], "recordDigest": row[2], "body": bytes(row[3]), "requestNonce": row[4], "requestTimestamp": row[5], "state": "sending", "attempts": row[7] + 1}
            except Exception:
                self.store.connection.execute("ROLLBACK")
                raise

    def _reset(self, record_id: str, error: str) -> None:
        with self.store._lock:
            self.store.connection.execute("UPDATE roadex_project_thread_question_outbox SET state='pending' WHERE record_id=? AND state='sending'", (record_id,))

    def deliver(self, record_id: str) -> dict[str, Any]:
        row = self._claim(record_id)
        if row["state"] == "delivered": return row
        try:
            headers = question_request_headers(self.secret, row["body"], row["requestTimestamp"], row["requestNonce"])
            if self._send is None:
                raise ValueError("Roadex question HTTP sender is not configured")
            response = self._send(row["body"], headers)
            status = int(response.get("status", 0)); response_body = response.get("body", b"")
            response_body = response_body.encode() if isinstance(response_body, str) else bytes(response_body)
            response_headers = {str(k).lower(): str(v) for k, v in dict(response.get("headers", {})).items()}
            if status != 202 or stable_json(json.loads(response_body.decode())) != response_body.decode(): raise ValueError("project-thread question receipt is invalid")
            receipt = json.loads(response_body.decode())
            expected = {"schemaVersion": QUESTION_RECEIPT_SCHEMA, "accepted": True, "messageId": row["recordId"], "messageDigest": row["recordDigest"], "requestNonce": row["requestNonce"], "receiptNonce": receipt.get("receiptNonce"), "occurredAt": receipt.get("occurredAt")}
            if receipt != expected or not isinstance(receipt.get("receiptNonce"), str) or not _NONCE.fullmatch(receipt["receiptNonce"]): raise ValueError("project-thread question receipt binding is invalid")
            _timestamp(receipt["occurredAt"], "question receipt timestamp")
            if response_headers.get("x-roadex-question-timestamp") != receipt["occurredAt"] or not hmac.compare_digest(response_headers.get("x-roadex-question-signature", ""), _question_receipt_signature(self.secret, receipt["occurredAt"], row["requestNonce"], response_body)): raise ValueError("project-thread question receipt signature is invalid")
            with self.store._lock:
                self.store.connection.execute("BEGIN IMMEDIATE")
                try:
                    self.store.connection.execute("INSERT INTO roadex_project_thread_question_receipts VALUES (?,?,?,?,?)", (row["recordId"], row["requestNonce"], receipt["receiptNonce"], response_body, relay_sha256(response_body)))
                    self.store.connection.execute("UPDATE roadex_project_thread_question_outbox SET state='delivered',claimed_at=NULL WHERE record_id=? AND state='sending'", (record_id,))
                    self.store.connection.execute("COMMIT")
                except Exception:
                    self.store.connection.execute("ROLLBACK")
                    raise
            return {**row, "state": "delivered", "receipt": receipt}
        except Exception:
            self._reset(record_id, "delivery failed")
            raise

    def retry_pending(self, *, limit: int = 32) -> dict[str, int]:
        delivered = failed = 0
        for row in self._rows(limit):
            try: self.deliver(row["recordId"]); delivered += 1
            except Exception: failed += 1
        return {"delivered": delivered, "failed": failed}


def create_project_thread_question_sender(*, store: RoadexProjectThreadStore, secret: bytes, endpoint: str, clock: Callable[[], str] | None = None) -> RoadexQuestionSender:
    """Build the outgoing sender with a fixed, loopback-only endpoint."""
    return RoadexQuestionSender(store=store, secret=secret, endpoint=endpoint, clock=clock)


__all__ = ["ROADEx_THREAD_AUTHORITY", "ROADEx_THREAD_ENDPOINT_PATH", "REQUEST_SCHEMA", "RECEIPT_SCHEMA", "REQUEST_DOMAIN", "RECEIPT_DOMAIN", "QUESTION_ENDPOINT_PATH", "QUESTION_REQUEST_SCHEMA", "QUESTION_RECEIPT_SCHEMA", "QUESTION_REQUEST_DOMAIN", "QUESTION_RECEIPT_DOMAIN", "PSYCHLO_QUESTION_RECEIPT_SCHEMA", "PSYCHLO_RELAY_RECEIPT_SCHEMA", "RoadexProjectThreadRelay", "RoadexProjectThreadStore", "RoadexQuestionSender", "RelayResponse", "ProjectThreadContractError", "parse_project_human_thread_binding", "parse_project_human_thread_message", "parse_project_human_thread_response", "request_headers", "question_request_headers", "relay_sha256", "stable_json"]
