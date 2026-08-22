"""Dedicated authenticated Roadex project-human-thread relay.

The relay has no relationship to approval/decision records.  Its wire format,
secret domain, nonce ledger, SQLite tables, receipts, and forwarding queue are
all intentionally independent from ``psychlo_bridge``'s execution protocol.
"""

from __future__ import annotations

from datetime import UTC, datetime
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

MAX_BODY_BYTES = 256 * 1024
ROADEx_THREAD_ENDPOINT_PATH = "/api/roadex/project-human-thread-relay"
ROADEx_THREAD_AUTHORITY = "127.0.0.1:8773"
REQUEST_SCHEMA = "roadex.overseer.project-human-thread-relay.v1"
RECEIPT_SCHEMA = "overseer.roadex.project-human-thread-relay-receipt.v1"
REQUEST_DOMAIN = "roadex.overseer.project-human-thread-relay.request.v1"
RECEIPT_DOMAIN = "overseer.roadex.project-human-thread-relay.receipt.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_NONCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
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
    if not isinstance(value, str) or value != value.strip() or not value:
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
        """)
        self._lock = threading.RLock()

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
    def __init__(self, *, store: RoadexProjectThreadStore, secret: bytes, clock: Callable[[], str] | None = None, forwarder: Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]] | None = None):
        if not isinstance(secret, bytes) or len(secret) < 32: raise ValueError("Roadex relay secret is invalid")
        self.store, self.secret, self.clock, self.forwarder = store, secret, clock or (lambda: datetime.now(UTC).isoformat()), forwarder
        self._lock = threading.RLock()

    def request_scoped(self) -> "RoadexProjectThreadRelay":
        """Give a threaded HTTP worker its own SQLite handle."""
        return RoadexProjectThreadRelay(
            store=RoadexProjectThreadStore(self.store.filename),
            secret=self.secret,
            clock=self.clock,
            forwarder=self.forwarder,
        )

    def close(self) -> None:
        self.store.close()

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
        if record_type not in {"binding", "message", "response"} or not isinstance(record, dict): raise ValueError("invalid_project_thread_record")
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
                if not isinstance(result, Mapping) or result.get("accepted") is not True or not isinstance(result.get("receipt"), Mapping): raise ValueError("Psychlo rejected project-thread record")
                receipt = dict(result["receipt"])
                if receipt.get("recordType") != row["recordType"] or receipt.get("recordId") != row["recordId"] or receipt.get("recordDigest") != row["recordDigest"]: raise ValueError("Psychlo project-thread receipt binding is invalid")
                self.store.mark_delivered(row["recordId"], receipt); delivered += 1
            except Exception as error:
                self.store.mark_failed(row["recordId"], str(error)); failed += 1
        return {"delivered": delivered, "failed": failed}

    def tick(self, *, limit: int = 32) -> dict[str, int]:
        return self.forward_pending(limit=limit)


__all__ = ["ROADEx_THREAD_AUTHORITY", "ROADEx_THREAD_ENDPOINT_PATH", "REQUEST_SCHEMA", "RECEIPT_SCHEMA", "REQUEST_DOMAIN", "RECEIPT_DOMAIN", "RoadexProjectThreadRelay", "RoadexProjectThreadStore", "RelayResponse", "ProjectThreadContractError", "parse_project_human_thread_binding", "parse_project_human_thread_message", "parse_project_human_thread_response", "request_headers", "relay_sha256", "stable_json"]
