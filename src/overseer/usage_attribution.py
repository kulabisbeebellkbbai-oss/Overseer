"""Fail-closed Psychlo usage attribution and durable snapshot delivery."""

from __future__ import annotations

import json
import sqlite3
import base64
import os
import stat
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .psychlo_contracts import canonical_digest, parse_usage_snapshot_v11


class UsageAttributionError(ValueError):
    """Raised when usage ownership cannot be established exactly."""


def _time(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise UsageAttributionError(f"{name} timestamp is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise UsageAttributionError(f"{name} timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise UsageAttributionError(f"{name} timestamp requires an offset")
    return parsed


def _id(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200 or any(ord(ch) < 33 or ord(ch) > 126 for ch in value):
        raise UsageAttributionError(f"{name} identity is invalid")
    return value


def _ticks(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise UsageAttributionError(f"{name} must be nonnegative integer quota ticks")
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _verify_seal(value: Mapping[str, Any], name: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    payload = dict(value)
    digest = payload.pop("digest", None)
    signature = payload.pop("signature", None)
    if not isinstance(digest, str) or len(digest) != 64 or canonical_digest(payload) != digest:
        raise UsageAttributionError(f"{name} digest is invalid")
    if not isinstance(signature, str): raise UsageAttributionError(f"{name} signature is invalid")
    try: public_key.verify(base64.b64decode(signature, validate=True), _canonical_bytes(payload))
    except (InvalidSignature, ValueError) as error: raise UsageAttributionError(f"{name} signature is invalid") from error
    return {**payload, "signature": signature, "digest": digest}


class UsageAttributionLedger:
    """Append-only authority observations, execution receipts, and intents."""

    _SCHEMA = 2

    def __init__(self, path: Path | str, *, approved_authority_id: str, approved_authority_binding_id: str, approved_authority_binding_digest: str, approved_account_id: str, approved_authority_public_key: bytes, receipt_identity_validator: Callable[[Mapping[str, Any]], None]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = self.path.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise UsageAttributionError("usage attribution directory must be private")
        if self.path.exists() or self.path.is_symlink():
            metadata = self.path.stat(follow_symlinks=False)
            if self.path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise UsageAttributionError("usage attribution database must be private")
        self.approved_authority_id = _id(approved_authority_id, "approved authority")
        self.approved_authority_binding_id = _id(approved_authority_binding_id, "approved authority binding")
        if not isinstance(approved_authority_binding_digest, str) or len(approved_authority_binding_digest) != 64 or any(ch not in "0123456789abcdef" for ch in approved_authority_binding_digest): raise UsageAttributionError("approved authority binding digest is invalid")
        self.approved_authority_binding_digest = approved_authority_binding_digest
        self.approved_account_id = _id(approved_account_id, "approved account")
        if not callable(receipt_identity_validator): raise UsageAttributionError("managed receipt identity validator is required")
        self.receipt_identity_validator = receipt_identity_validator
        if not isinstance(approved_authority_public_key, bytes) or len(approved_authority_public_key) != 32: raise UsageAttributionError("approved authority public key is invalid")
        self.approved_authority_public_key = Ed25519PublicKey.from_public_bytes(approved_authority_public_key)
        self.connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.path.chmod(0o600)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self._initialize()

    def _initialize(self) -> None:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            existing = self.connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usage_attribution_meta'").fetchone()
            if existing:
                row = self.connection.execute("SELECT value FROM usage_attribution_meta WHERE key='schema_version'").fetchone()
                if row is None or str(row[0]) != str(self._SCHEMA):
                    raise UsageAttributionError("usage attribution migration rejects unknown or corrupt legacy schema")
            else:
                self.connection.execute("CREATE TABLE usage_attribution_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
                self.connection.execute("INSERT INTO usage_attribution_meta VALUES ('schema_version',?)", (str(self._SCHEMA),))
            self.connection.execute("CREATE TABLE IF NOT EXISTS usage_observations(observation_id TEXT PRIMARY KEY,digest TEXT NOT NULL UNIQUE,payload_json TEXT NOT NULL,inserted_at TEXT NOT NULL)")
            self.connection.execute("CREATE TABLE IF NOT EXISTS usage_execution_receipts(receipt_id TEXT PRIMARY KEY,result_id TEXT NOT NULL UNIQUE,digest TEXT NOT NULL UNIQUE,payload_json TEXT NOT NULL,inserted_at TEXT NOT NULL)")
            self.connection.execute("CREATE TABLE IF NOT EXISTS usage_snapshot_intents(idempotency_key TEXT PRIMARY KEY,observation_id TEXT NOT NULL UNIQUE,payload_json TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,inserted_at TEXT NOT NULL,updated_at TEXT NOT NULL)")
            self._validate_all_locked()
            self.connection.execute("UPDATE usage_snapshot_intents SET state='pending' WHERE state='sending'")
            self.connection.execute("COMMIT")
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise

    def _validate_all_locked(self) -> None:
        for row in self.connection.execute("SELECT payload_json,digest FROM usage_observations"):
            try: value = json.loads(row[0])
            except json.JSONDecodeError as error: raise UsageAttributionError("corrupt observation ledger") from error
            try: _verify_seal(value, "observation", self.approved_authority_public_key)
            except UsageAttributionError as error: raise UsageAttributionError("corrupt observation ledger") from error
            if value.get("digest") != row[1]:
                raise UsageAttributionError("corrupt observation ledger")
        for row in self.connection.execute("SELECT payload_json,digest FROM usage_execution_receipts"):
            try: value = json.loads(row[0])
            except json.JSONDecodeError as error: raise UsageAttributionError("corrupt receipt ledger") from error
            try: _verify_seal(value, "receipt", self.approved_authority_public_key)
            except UsageAttributionError as error: raise UsageAttributionError("corrupt receipt ledger") from error
            if value.get("digest") != row[1]:
                raise UsageAttributionError("corrupt receipt ledger")
        for row in self.connection.execute("SELECT payload_json,digest,state FROM usage_snapshot_intents"):
            try: value = json.loads(row[0])
            except json.JSONDecodeError as error: raise UsageAttributionError("corrupt snapshot intent") from error
            if canonical_digest(value) != row[1] or row[2] not in {"pending", "sending", "delivered", "rejected"}:
                raise UsageAttributionError("corrupt snapshot intent")
            try: parse_usage_snapshot_v11(value)
            except Exception as error: raise UsageAttributionError("corrupt snapshot intent") from error

    @staticmethod
    def _encoded(value: Mapping[str, Any]) -> str:
        return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def record_provider_observation(self, supplied: Mapping[str, Any]) -> dict[str, Any]:
        value = _verify_seal(supplied, "observation", self.approved_authority_public_key)
        required = {"observationId","authorityId","authorityBindingId","authorityBindingDigest","measurementScope","accountId","providerId","limitId","usageUnit","providerResetAt","intervalStart","intervalEnd","totalConsumed","weeklyQuota","weeklyRemainingCapacity","unusedPriorDayWeeklyCapacity","decisionVersion","correlationId","idempotencyKey","occurredAt","signature","digest"}
        if set(value) != required: raise UsageAttributionError("observation authority shape is invalid")
        if value["authorityId"] != self.approved_authority_id or value["accountId"] != self.approved_account_id or value["authorityBindingId"] != self.approved_authority_binding_id or value["authorityBindingDigest"] != self.approved_authority_binding_digest:
            raise UsageAttributionError("observation authority binding is invalid")
        if value["measurementScope"] != "exclusive-metered-intervals":
            raise UsageAttributionError("observation measurement authority is not exclusive")
        if value["usageUnit"] != "quota_points": raise UsageAttributionError("observation unit is invalid")
        for field in ("observationId","authorityBindingId","providerId","limitId","decisionVersion","correlationId","idempotencyKey"): _id(value[field], field)
        if not isinstance(value["authorityBindingDigest"], str) or len(value["authorityBindingDigest"]) != 64: raise UsageAttributionError("observation authority binding digest is invalid")
        start, end, occurred, reset = (_time(value[k], k) for k in ("intervalStart","intervalEnd","occurredAt","providerResetAt"))
        if reset != start or start >= end or occurred != end: raise UsageAttributionError("observation measurement interval is invalid")
        total = _ticks(value["totalConsumed"], "total consumed")
        quota = _ticks(value["weeklyQuota"], "weekly quota")
        remaining = _ticks(value["weeklyRemainingCapacity"], "weekly remaining")
        _ticks(value["unusedPriorDayWeeklyCapacity"], "unused prior day")
        if remaining > quota or quota - remaining != total: raise UsageAttributionError("observation conservation is invalid")
        return self._insert_immutable("usage_observations", "observation_id", value["observationId"], value)

    def record_execution_receipt(self, supplied: Mapping[str, Any]) -> dict[str, Any]:
        value = _verify_seal(supplied, "receipt", self.approved_authority_public_key)
        required = {"receiptId","observationId","authorityId","authorityBindingId","authorityBindingDigest","measurementScope","accountId","providerId","limitId","usageUnit","providerResetAt","projectId","planId","planVersion","aTeamId","projectLeadId","roundId","dispatchId","resultId","startedAt","settledAt","consumed","correlationId","idempotencyKey","occurredAt","signature","digest"}
        if set(value) != required: raise UsageAttributionError("receipt identity shape is invalid")
        for field in required - {"consumed","digest","signature","startedAt","settledAt","occurredAt","providerResetAt","authorityBindingDigest"}: _id(value[field], field)
        if value["accountId"] != self.approved_account_id: raise UsageAttributionError("receipt account binding is invalid")
        if value["authorityId"] != self.approved_authority_id or value["authorityBindingId"] != self.approved_authority_binding_id or value["authorityBindingDigest"] != self.approved_authority_binding_digest or value["measurementScope"] != "exclusive-metered-intervals": raise UsageAttributionError("receipt authority binding is invalid")
        if value["usageUnit"] != "quota_points": raise UsageAttributionError("receipt unit is invalid")
        observation = self._observation_for_scope(value)
        if value["authorityBindingDigest"] != observation["authorityBindingDigest"]: raise UsageAttributionError("receipt binding identity is invalid")
        self.receipt_identity_validator(value)
        start, end, occurred = (_time(value[k], k) for k in ("startedAt","settledAt","occurredAt"))
        if start >= end or occurred != end or start < _time(observation["intervalStart"], "interval start") or end > _time(observation["intervalEnd"], "interval end"): raise UsageAttributionError("receipt measurement interval is invalid")
        consumed = _ticks(value["consumed"], "receipt consumed")
        prior = self.connection.execute("SELECT payload_json FROM usage_execution_receipts WHERE json_extract(payload_json,'$.observationId')=? ORDER BY inserted_at,receipt_id", (value["observationId"],)).fetchall()
        total = consumed
        for row in prior:
            item = json.loads(row[0]); total += int(item["consumed"])
            if start < _time(item["settledAt"], "settledAt") and end > _time(item["startedAt"], "startedAt"): raise UsageAttributionError("receipt intervals overlap")
        if total > int(observation["totalConsumed"]): raise UsageAttributionError("negative residual usage is forbidden")
        return self._insert_immutable("usage_execution_receipts", "receipt_id", value["receiptId"], value, extra=("result_id", value["resultId"]))

    def _observation_for_scope(self, value: Mapping[str, Any]) -> dict[str, Any]:
        row = self.connection.execute("SELECT payload_json FROM usage_observations WHERE observation_id=?", (value["observationId"],)).fetchone()
        if row is not None:
            item = json.loads(row[0])
            if all(item[k] == value[k] for k in ("authorityId","authorityBindingId","accountId","providerId","limitId","usageUnit","providerResetAt","measurementScope")): return item
        raise UsageAttributionError("receipt account or reset scope is invalid")

    def _insert_immutable(self, table: str, key_name: str, key: str, value: Mapping[str, Any], *, extra: tuple[str,str] | None = None) -> dict[str, Any]:
        encoded = self._encoded(value); digest = str(value["digest"]); now = str(value.get("occurredAt"))
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(f"SELECT payload_json FROM {table} WHERE {key_name}=?", (key,)).fetchone()
            if row:
                existing = json.loads(row[0])
                if existing != dict(value): raise UsageAttributionError(f"{table} immutable conflict")
                self.connection.execute("COMMIT"); return existing
            if extra:
                self.connection.execute(f"INSERT INTO {table}({key_name},{extra[0]},digest,payload_json,inserted_at) VALUES (?,?,?,?,?)", (key,extra[1],digest,encoded,now))
            else:
                self.connection.execute(f"INSERT INTO {table}({key_name},digest,payload_json,inserted_at) VALUES (?,?,?,?)", (key,digest,encoded,now))
            self.connection.execute("COMMIT"); return dict(value)
        except Exception:
            if self.connection.in_transaction: self.connection.execute("ROLLBACK")
            raise

    def observation(self, observation_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT payload_json FROM usage_observations WHERE observation_id=?", (observation_id,)).fetchone()
        if row is None: raise UsageAttributionError("observation is missing")
        return json.loads(row[0])

    def receipts_for_observation(self, observation: Mapping[str, Any]) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload_json FROM usage_execution_receipts ORDER BY inserted_at,receipt_id").fetchall()
        return [json.loads(row[0]) for row in rows if json.loads(row[0])["observationId"] == observation["observationId"]]

    def delivery_intent(self, key: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT observation_id,payload_json,digest,state FROM usage_snapshot_intents WHERE idempotency_key=?", (key,)).fetchone()
        return None if row is None else {"observationId":row[0],"payload":json.loads(row[1]),"digest":row[2],"state":row[3]}

    def delivery_intent_for_observation(self, observation_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT idempotency_key FROM usage_snapshot_intents WHERE observation_id=?", (observation_id,)).fetchone()
        return None if row is None else self.delivery_intent(str(row[0]))

    def prepare_intent(self, observation_id: str, payload: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        key = str(payload["idempotencyKey"]); encoded=self._encoded(payload); digest=canonical_digest(payload); now=str(payload["occurredAt"])
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row=self.connection.execute("SELECT payload_json,state FROM usage_snapshot_intents WHERE observation_id=?",(observation_id,)).fetchone()
            if row:
                existing=json.loads(row[0])
                if existing != dict(payload): raise UsageAttributionError("snapshot intent immutable conflict")
                self.connection.execute("COMMIT"); return existing, False
            self.connection.execute("INSERT INTO usage_snapshot_intents VALUES (?,?,?,?,?,?,?)",(key,observation_id,encoded,digest,"pending",now,now))
            self.connection.execute("COMMIT"); return dict(payload), True
        except Exception:
            if self.connection.in_transaction:self.connection.execute("ROLLBACK")
            raise

    def mark_delivered(self, key: str) -> None:
        self.connection.execute("UPDATE usage_snapshot_intents SET state='delivered',updated_at=inserted_at WHERE idempotency_key=?",(key,))

    def mark_pending(self, key: str) -> None:
        self.connection.execute("UPDATE usage_snapshot_intents SET state='pending',updated_at=inserted_at WHERE idempotency_key=? AND state='sending'",(key,))

    def mark_rejected(self, key: str) -> None:
        self.connection.execute("UPDATE usage_snapshot_intents SET state='rejected',updated_at=inserted_at WHERE idempotency_key=? AND state='sending'",(key,))

    def claim_pending(self, key: str) -> bool:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            changed = self.connection.execute("UPDATE usage_snapshot_intents SET state='sending' WHERE idempotency_key=? AND state='pending'", (key,)).rowcount == 1
            self.connection.execute("COMMIT")
            return changed
        except Exception:
            if self.connection.in_transaction: self.connection.execute("ROLLBACK")
            raise


class UsageSnapshotProducer:
    def __init__(self, ledger: UsageAttributionLedger, *, sender: Callable[[str,str,dict[str,Any]], Mapping[str,Any]], after_send: Callable[[], None] | None = None):
        self.ledger=ledger; self.sender=sender; self.after_send=after_send

    def emit(self, observation_id: str, *, policy_version: str) -> dict[str, Any]:
        observation=self.ledger.observation(observation_id)
        receipts=self.ledger.receipts_for_observation(observation)
        managed=sum(int(item["consumed"]) for item in receipts)
        total=int(observation["totalConsumed"]); residual=total-managed
        if residual < 0: raise UsageAttributionError("negative residual usage")
        snapshot_id="usage-attribution-"+canonical_digest({"observationId":observation_id,"policyVersion":policy_version})[:24]
        scope=canonical_digest({"observation":observation["digest"],"receipts":[item["digest"] for item in receipts]})
        snapshot={"schemaVersion":"psychlo.usage-snapshot.v1.1","id":snapshot_id,"sourceId":"overseer","capturedAt":observation["occurredAt"],"policyVersion":policy_version,"providerResetAt":observation["providerResetAt"],"scopeDigest":scope,"decisionVersion":observation["decisionVersion"],"unusedPriorDayWeeklyCapacity":int(observation["unusedPriorDayWeeklyCapacity"]),"weeklyQuota":int(observation["weeklyQuota"]),"weeklyRemainingCapacity":int(observation["weeklyRemainingCapacity"]),"dailyConsumed":managed,"otherDevelopmentConsumed":max(0,residual)}
        snapshot["digest"]=canonical_digest(snapshot)
        envelope={"schemaVersion":"psychlo.usage-envelope.v1.1","correlationId":f"psychlo:{snapshot_id}","idempotencyKey":snapshot_id,"occurredAt":observation["occurredAt"],"snapshot":snapshot}
        envelope["digest"]=canonical_digest(envelope)
        parse_usage_snapshot_v11(envelope)
        payload,winner=self.ledger.prepare_intent(observation_id,envelope)
        intent=self.ledger.delivery_intent(str(payload["idempotencyKey"]))
        key=str(payload["idempotencyKey"])
        if intent and intent["state"]=="delivered": return {"payload":payload,"replay":True}
        if winner:
            claimed=self.ledger.claim_pending(key)
        else:
            claimed=self.ledger.claim_pending(key)
        if not claimed: return {"payload":payload,"replay":True}
        try:
            response=self.sender("usage-snapshot",key,payload)
        except BaseException:
            self.ledger.mark_pending(key)
            raise
        if self.after_send is not None: self.after_send()
        if response.get("accepted") is not True:
            self.ledger.mark_rejected(key)
            raise UsageAttributionError("peer rejected usage snapshot")
        self.ledger.mark_delivered(key)
        return {"payload":payload,"replay":False}


def managed_receipt_validator(store: Any) -> Callable[[Mapping[str, Any]], None]:
    """Bind authority receipts to Overseer's exact registered, settled round."""
    def validate(value: Mapping[str, Any]) -> None:
        project = store.project(str(value["projectId"]))
        round_record = store.get_round(str(value["roundId"]))
        timing = store.round_timing(str(value["roundId"]))
        if project is None or round_record is None or timing is None:
            raise UsageAttributionError("receipt does not bind to a managed settled round")
        registration, scheduling = project
        envelope = registration.get("envelope", {})
        request, dispatch, _, _, dispatch_state, result, _ = round_record
        expected = {
            "projectId": envelope.get("project", {}).get("id"),
            "planId": envelope.get("project", {}).get("planId"),
            "planVersion": envelope.get("project", {}).get("planVersion"),
            "aTeamId": envelope.get("aTeamId"),
            "projectLeadId": envelope.get("projectLead", {}).get("id"),
        }
        if any(value.get(key) != item for key, item in expected.items()) or scheduling.get("state") != "managed":
            raise UsageAttributionError("receipt does not bind to a managed project identity")
        if result is None or dispatch_state != "dispatched" or result.get("status") not in {"completed", "blocked"}:
            raise UsageAttributionError("receipt does not bind to a managed settled round")
        bindings = {
            "projectId": request.get("projectId"), "planId": request.get("planId"),
            "planVersion": request.get("planVersion"), "projectLeadId": request.get("projectLeadId"),
            "dispatchId": dispatch.get("provenanceId"), "resultId": result.get("provenanceId"),
            "correlationId": result.get("correlationId"), "idempotencyKey": result.get("idempotencyKey"),
            "startedAt": timing.get("startedAt"), "settledAt": timing.get("completedAt"),
        }
        if any(value.get(key) != item for key, item in bindings.items()):
            raise UsageAttributionError("receipt dispatch or result identity is invalid")
    return validate
