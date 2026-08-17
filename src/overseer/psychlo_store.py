"""Private SQLite projections for the Psychlo bridge.

External executions, telemetry, learning, and adoption evidence deliberately
have independent tables.  In particular, an external execution can never
become a normal ``rounds`` row by projection or recovery.
"""

from __future__ import annotations

import json
import hashlib
import math
from pathlib import Path
import os
import secrets
import sqlite3
import stat
from datetime import UTC, datetime
from typing import Any, Callable, Mapping

from .psychlo_contracts import canonical_digest, learning_observation_digest, learning_observation_legacy_selected_digest, parse_canary_authorization, parse_concurrency_canary_result, parse_concurrency_ceiling_authorization, parse_learning_observation, parse_policy_exception_receiver_receipt, policy_exception_request_digest, ContractError


def _round_result_digest(result: Mapping[str, Any]) -> str:
    fields = ("roundId", "projectId", "projectLeadId", "planId", "planVersion", "threadId", "model", "featureClass", "correlationId", "idempotencyKey", "snapshotId", "policyVersion", "expectedUsageCost", "scope", "selectionReason", "priorityRationale", "sourceId", "provenanceId", "status", "actualUsageCost", "deliveredScope", "remainingEstimate", "blockers", "questions", "reachedExplicitGates", "occurredAt")
    import hashlib
    return hashlib.sha256(json.dumps({key: result[key] for key in fields if key in result}, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _dump(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))


def _dump_wire(value: Mapping[str, Any]) -> str:
    """Retain authenticated contract insertion order for cross-language digests."""
    return json.dumps(dict(value), ensure_ascii=False, separators=(",", ":"))


def _requested_values_equal(left: Any, right: Any) -> bool:
    """Compare the optional scalar without collapsing booleans into numbers."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        # Request validation has already rejected non-finite values.  Python's
        # numeric comparison intentionally preserves the contract's existing
        # f64 canonicalization, where -0 and +0 share the zero bit pattern.
        return float(left) == float(right)
    return left == right


class PsychloBridgeStore:
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
        self.connection = sqlite3.connect(self.filename, check_same_thread=False, isolation_level=None, timeout=30.0)
        self.filename.chmod(0o600)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS peer_nonces(nonce TEXT PRIMARY KEY, message_id TEXT NOT NULL, claimed_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rounds(round_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, capability_hash TEXT NOT NULL UNIQUE, capability_token TEXT NOT NULL, dispatch_state TEXT NOT NULL, result_json TEXT, result_forwarded INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS round_recoveries(round_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, capability_hash TEXT NOT NULL, idempotency_key TEXT NOT NULL, owner_id TEXT, claim_token TEXT, lease_expires_at TEXT, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, evidence_json TEXT, binding_json TEXT, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS round_prompt_deliveries(round_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL UNIQUE, capability_hash TEXT NOT NULL UNIQUE, binding_json TEXT NOT NULL, phase TEXT NOT NULL, prompt_digest TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS operational_failure_intents(round_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL, capability_hash TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL UNIQUE, state TEXT NOT NULL, owner_id TEXT, claim_token TEXT, lease_expires_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, outcome_json TEXT, last_error TEXT, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS round_binding_attestations(round_id TEXT PRIMARY KEY, manifest_digest TEXT NOT NULL UNIQUE, attestation_json TEXT NOT NULL, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS round_cancellations(cancellation_id TEXT PRIMARY KEY, round_id TEXT NOT NULL UNIQUE, request_digest TEXT NOT NULL UNIQUE, attestation_json TEXT NOT NULL, receipt_json TEXT NOT NULL, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS decisions(decision_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT, reason TEXT);
            CREATE TABLE IF NOT EXISTS decision_intents(decision_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, outcome_json TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT NOT NULL, decided_at TEXT NOT NULL, reason TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS projects(project_id TEXT PRIMARY KEY, registration_json TEXT NOT NULL, scheduling_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS telemetry_checkpoints(checkpoint_id TEXT PRIMARY KEY, round_id TEXT NOT NULL, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS learning_observations(observation_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, state TEXT NOT NULL, attempts_skiller INTEGER NOT NULL DEFAULT 0, attempts_memory INTEGER NOT NULL DEFAULT 0, last_error_skiller TEXT, last_error_memory TEXT, delivery_skiller TEXT NOT NULL DEFAULT 'pending', delivery_memory TEXT NOT NULL DEFAULT 'pending', updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS learning_advisories(digest TEXT PRIMARY KEY, payload_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS registry_candidates(candidate_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS adoption_evidence(assessment_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS external_executions(reconciliation_id TEXT PRIMARY KEY, external_execution_id TEXT NOT NULL UNIQUE, idempotency_key TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL, status TEXT NOT NULL, forwarded INTEGER NOT NULL DEFAULT 0, gate_decision_id TEXT, gate_workflow_id TEXT, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS protocol_records(kind TEXT NOT NULL, record_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, receipt_json TEXT, PRIMARY KEY(kind, record_id), UNIQUE(kind, idempotency_key));
            CREATE TABLE IF NOT EXISTS approval_authority_snapshots(approval_id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS coordination_dispatches(request_id TEXT PRIMARY KEY, dispatch_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, owner_id TEXT, idempotency_key TEXT);
            CREATE TABLE IF NOT EXISTS coordination_reviews(request_id TEXT PRIMARY KEY, review_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, owner_id TEXT, idempotency_key TEXT);
            CREATE TABLE IF NOT EXISTS coordination_terminals(request_id TEXT PRIMARY KEY, result_id TEXT NOT NULL UNIQUE, digest TEXT NOT NULL, payload_json TEXT NOT NULL, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS coordination_operation_claims(kind TEXT NOT NULL, operation_id TEXT NOT NULL, owner_id TEXT, lease_expires_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, idempotency_key TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(kind, operation_id), UNIQUE(kind, idempotency_key));
            CREATE TABLE IF NOT EXISTS policy_exception_requests(request_id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, state TEXT NOT NULL, outcome_json TEXT, consumed_at TEXT, updated_at TEXT NOT NULL, receiver_receipt_json TEXT);
            CREATE TABLE IF NOT EXISTS psychlo_usage_accounting(snapshot_id TEXT PRIMARY KEY, reset_at TEXT NOT NULL, payload_json TEXT NOT NULL, inserted_at TEXT NOT NULL);
        """)
        for column in ("delivery_skiller", "delivery_memory"):
            try:
                self.connection.execute(f"ALTER TABLE learning_observations ADD COLUMN {column} TEXT NOT NULL DEFAULT 'pending'")
            except sqlite3.OperationalError:
                pass
        try:
            self.connection.execute("ALTER TABLE external_executions ADD COLUMN gate_workflow_id TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            self.connection.execute("ALTER TABLE protocol_records ADD COLUMN receipt_json TEXT")
        except sqlite3.OperationalError:
            pass
        for column, definition in (("idempotency_key", "TEXT"), ("approval_id", "TEXT")):
            try:
                self.connection.execute(f"ALTER TABLE policy_exception_requests ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        try:
            self.connection.execute("ALTER TABLE policy_exception_requests ADD COLUMN receiver_message_id TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            self.connection.execute("ALTER TABLE policy_exception_requests ADD COLUMN receiver_receipt_json TEXT")
        except sqlite3.OperationalError:
            pass
        self.connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS policy_exception_idempotency_unique ON policy_exception_requests(idempotency_key) WHERE idempotency_key IS NOT NULL")
        self.connection.execute("CREATE INDEX IF NOT EXISTS policy_exception_reset_index ON psychlo_usage_accounting(reset_at, inserted_at)")
        self._migrate_protocol_digest_uniqueness()
        self._backfill_coordination_terminals()
        for table in ("coordination_dispatches", "coordination_reviews"):
            for column in ("owner_id", "idempotency_key"):
                try:
                    self.connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT")
                except sqlite3.OperationalError:
                    pass
            self.connection.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {table}_idempotency ON {table}(idempotency_key) WHERE idempotency_key IS NOT NULL")
        for column, definition in (("canary_authorization_id", "TEXT"), ("started_at", "TEXT"), ("completed_at", "TEXT")):
            try:
                self.connection.execute(f"ALTER TABLE rounds ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        for column, definition in (("claim_token", "TEXT"), ("binding_json", "TEXT")):
            try:
                self.connection.execute(f"ALTER TABLE round_recoveries ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        try:
            self.connection.execute("ALTER TABLE rounds ADD COLUMN codex_binding_json TEXT")
        except sqlite3.OperationalError:
            pass

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "PsychloBridgeStore":
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    def _migrate_protocol_digest_uniqueness(self) -> None:
        schema = self.connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='protocol_records'").fetchone()
        normalized_schema = "" if schema is None else "".join(str(schema[0]).lower().split())
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if "unique(kind,digest)" in normalized_schema:
                self.connection.execute("ALTER TABLE protocol_records RENAME TO protocol_records_legacy_digest_unique")
                self.connection.execute("CREATE TABLE protocol_records(kind TEXT NOT NULL, record_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, receipt_json TEXT, PRIMARY KEY(kind, record_id), UNIQUE(kind, idempotency_key))")
                self.connection.execute("INSERT INTO protocol_records SELECT kind,record_id,idempotency_key,digest,payload_json,state,attempts,last_error,updated_at,receipt_json FROM protocol_records_legacy_digest_unique")
                self.connection.execute("DROP TABLE protocol_records_legacy_digest_unique")
            self._create_protocol_digest_index()
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def _create_protocol_digest_index(self) -> None:
        self.connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS protocol_kind_digest_unique ON protocol_records(kind,digest) WHERE kind != 'cross-project-participant-result'")
        row = self.connection.execute("SELECT tbl_name,sql FROM sqlite_master WHERE type='index' AND name='protocol_kind_digest_unique'").fetchone()
        normalized = "" if row is None else "".join(str(row[1]).lower().split())
        expected = "createuniqueindexprotocol_kind_digest_uniqueonprotocol_records(kind,digest)wherekind!='cross-project-participant-result'"
        if row is None or row[0] != "protocol_records" or normalized != expected:
            raise ValueError("protocol digest index binding is invalid")

    def _backfill_coordination_terminals(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            rows = self.connection.execute("SELECT record_id,digest,payload_json,updated_at FROM protocol_records WHERE kind='cross-project-participant-result'").fetchall()
            for result_id, digest, encoded, inserted_at in rows:
                payload = json.loads(encoded)
                request_id = payload.get("requestId")
                if not isinstance(request_id, str) or not request_id.strip() or payload.get("resultId") != result_id or payload.get("digest") != digest:
                    continue
                existing = self.connection.execute("SELECT result_id,digest,payload_json FROM coordination_terminals WHERE request_id=?", (request_id,)).fetchone()
                if existing is not None and existing != (result_id, digest, encoded):
                    raise ValueError("participant result terminal conflict")
                self.connection.execute("INSERT OR IGNORE INTO coordination_terminals VALUES (?,?,?,?,?)", (request_id, result_id, digest, encoded, inserted_at))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def save_approval_snapshot(self, approval_id: str, payload: Mapping[str, Any], digest: str) -> dict[str, Any]:
        if not isinstance(approval_id, str) or not approval_id.strip() or not isinstance(digest, str) or not digest.strip():
            raise ValueError("approval snapshot identity is required")
        encoded = _dump(payload)
        existing = self.approval_snapshot(approval_id)
        if existing is not None:
            if existing["digest"] != digest or existing["payload"] != dict(payload):
                raise ValueError("approval authority snapshot is immutable")
            return existing
        self.connection.execute("INSERT INTO approval_authority_snapshots VALUES (?,?,?,?)", (approval_id, digest, encoded, self._now()))
        return self.approval_snapshot(approval_id)

    def approval_snapshot(self, approval_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT digest,payload_json,created_at FROM approval_authority_snapshots WHERE approval_id=?", (approval_id,)).fetchone()
        if row is None: return None
        return {"approvalId": approval_id, "digest": row[0], "payload": json.loads(row[1]), "createdAt": row[2]}

    def record_policy_exception_request(self, request: Mapping[str, Any], digest: str | None = None, *, receiver_message_id: str | None = None, receiver_receipt: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], bool]:
        value = dict(request); request_id = value.get("id")
        if not isinstance(request_id, str) or not request_id.strip(): raise ValueError("policy exception request identity is required")
        selected_digest = str(digest or value.get("digest") or policy_exception_request_digest(value))
        if selected_digest != policy_exception_request_digest(value): raise ValueError("policy exception request digest mismatch")
        idempotency_key = value.get("idempotencyKey")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip(): raise ValueError("policy exception idempotency key is required")
        encoded = _dump_wire(value)
        parsed_receipt = parse_policy_exception_receiver_receipt(receiver_receipt) if receiver_receipt is not None else None
        if parsed_receipt is not None:
            self._validate_policy_exception_receiver_receipt_binding(request_id, value, parsed_receipt)
            if parsed_receipt["outcome"] != "inserted":
                raise ValueError("initial policy exception receiver receipt must be inserted")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self.connection.execute("SELECT request_id,digest,payload_json FROM policy_exception_requests WHERE idempotency_key=? OR request_id=?", (idempotency_key, request_id)).fetchone()
            if existing is not None:
                if existing[1] != selected_digest or json.loads(existing[2]) != value: raise ValueError("policy exception idempotency conflict")
                self.connection.execute("COMMIT")
                return self.policy_exception_request(str(existing[0])), False
            self.connection.execute("INSERT INTO policy_exception_requests(request_id,digest,payload_json,state,outcome_json,consumed_at,updated_at,idempotency_key,approval_id,receiver_message_id,receiver_receipt_json) VALUES (?,?,?,'pending',NULL,NULL,?,?,NULL,?,?)", (request_id, selected_digest, encoded, self._now(), idempotency_key, receiver_message_id, _dump_wire(parsed_receipt) if parsed_receipt is not None else None))
            self.connection.execute("COMMIT")
        except sqlite3.IntegrityError as error:
            self.connection.execute("ROLLBACK")
            raise ValueError("policy exception request conflict") from error
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        return self.policy_exception_request(request_id), True

    @staticmethod
    def _validate_policy_exception_receiver_receipt_binding(request_id: str, payload: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
        if receipt["exceptionId"] != request_id or receipt["requestDigest"] != payload.get("digest") or receipt["policyRevision"] != payload.get("policyRevision") or receipt["ruleId"] != payload.get("requestedRuleId") or receipt["scopeDigest"] != payload.get("scopeDigest") or receipt["decisionVersion"] != payload.get("decisionVersion") or receipt["correlationId"] != payload.get("correlationId") or receipt["idempotencyKey"] != payload.get("idempotencyKey") or ("requestedValue" in receipt) != ("requestedValue" in payload) or not _requested_values_equal(receipt.get("requestedValue"), payload.get("requestedValue")):
            raise ValueError("policy exception receiver receipt does not bind to the exact request")

    def policy_exception_request(self, request_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT digest,payload_json,state,outcome_json,consumed_at,updated_at,idempotency_key,approval_id,receiver_message_id,receiver_receipt_json FROM policy_exception_requests WHERE request_id=?", (request_id,)).fetchone()
        if row is None: return None
        return {"requestId": request_id, "digest": row[0], "payload": json.loads(row[1]), "state": row[2], "outcome": json.loads(row[3]) if row[3] else None, "consumedAt": row[4], "updatedAt": row[5], "idempotencyKey": row[6], "approvalId": row[7], "receiverMessageId": row[8], "receiverReceipt": json.loads(row[9]) if row[9] else None}

    def record_policy_exception_receiver_receipt(self, request_id: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Persist the first accepted receiver receipt without changing it on replay."""
        parsed = parse_policy_exception_receiver_receipt(receipt)
        encoded = _dump_wire(parsed)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT payload_json,receiver_receipt_json FROM policy_exception_requests WHERE request_id=?", (request_id,)).fetchone()
            if row is None:
                raise ValueError("policy exception request is missing")
            payload = json.loads(row[0])
            self._validate_policy_exception_receiver_receipt_binding(request_id, payload, parsed)
            if row[1] is not None:
                existing = json.loads(row[1])
                if existing != parsed:
                    raise ValueError("policy exception receiver receipt is immutable")
                self.connection.execute("COMMIT")
                return existing
            self.connection.execute("UPDATE policy_exception_requests SET receiver_receipt_json=? WHERE request_id=?", (encoded, request_id))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        return parsed

    def consume_policy_exception_request(self, request_id: str, outcome: Mapping[str, Any], *, now: str, approval_id: str | None = None) -> dict[str, Any]:
        encoded = _dump_wire(outcome)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT state,outcome_json FROM policy_exception_requests WHERE request_id=?", (request_id,)).fetchone()
            if row is None: raise ValueError("policy exception request is missing")
            if row[0] in {"approved", "rejected", "expired", "delivered", "forward-pending"}:
                if row[1] == encoded: return self.policy_exception_request(request_id)
                raise ValueError("policy exception authority is one-use and already consumed")
            self.connection.execute("UPDATE policy_exception_requests SET state='forward-pending',outcome_json=?,consumed_at=?,updated_at=?,approval_id=COALESCE(?,approval_id) WHERE request_id=? AND state='pending'", (encoded, now, now, approval_id, request_id))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        result = self.policy_exception_request(request_id)
        if result is None: raise ValueError("policy exception request is missing")
        return result

    def transition_policy_exception_request(self, request_id: str, state: str, *, now: str | None = None) -> dict[str, Any]:
        if state not in {"pending", "forward-pending", "delivered", "approved", "rejected", "expired", "recovery-invalid"}: raise ValueError("policy exception state is invalid")
        self.connection.execute("UPDATE policy_exception_requests SET state=?,updated_at=? WHERE request_id=?", (state, now or self._now(), request_id))
        result = self.policy_exception_request(request_id)
        if result is None: raise ValueError("policy exception request is missing")
        return result

    def pending_policy_exception_requests(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT request_id FROM policy_exception_requests WHERE state IN ('pending','forward-pending') ORDER BY updated_at,request_id").fetchall()
        return [self.policy_exception_request(str(row[0])) for row in rows]

    def record_usage_accounting(self, snapshot_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(payload)
        if value.get("snapshotId") != snapshot_id or value.get("resetAt") is None: raise ValueError("usage accounting identity is required")
        for field in ("weeklyQuota", "weeklyRemainingCapacity", "dailyConsumed", "otherDevelopmentConsumed"):
            item = value.get(field)
            if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(float(item)) or item < 0: raise ValueError("usage accounting values must be finite and nonnegative")
        encoded = _dump_wire(value)
        existing = self.usage_accounting(snapshot_id)
        if existing is not None:
            if existing["payload"] != value: raise ValueError("usage accounting record is immutable")
            return existing
        self.connection.execute("INSERT INTO psychlo_usage_accounting(snapshot_id,reset_at,payload_json,inserted_at) VALUES (?,?,?,?)", (snapshot_id, str(value["resetAt"]), encoded, self._now()))
        return self.usage_accounting(snapshot_id)

    def usage_accounting(self, snapshot_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT reset_at,payload_json,inserted_at FROM psychlo_usage_accounting WHERE snapshot_id=?", (snapshot_id,)).fetchone()
        if row is None: return None
        return {"snapshotId": snapshot_id, "resetAt": row[0], "payload": json.loads(row[1]), "insertedAt": row[2]}

    def latest_usage_accounting(self, reset_at: str | None = None) -> dict[str, Any] | None:
        rows = self.connection.execute("SELECT snapshot_id,reset_at FROM psychlo_usage_accounting ORDER BY inserted_at DESC,snapshot_id DESC").fetchall()
        if reset_at is not None:
            try: expected = datetime.fromisoformat(str(reset_at).replace("Z", "+00:00"))
            except ValueError: expected = None
            rows = [row for row in rows if (datetime.fromisoformat(str(row[1]).replace("Z", "+00:00")) == expected if expected is not None else row[1] == reset_at)]
        return None if not rows else self.usage_accounting(str(rows[0][0]))

    # Public names used by the provider snapshot producer and test fixtures.
    record_usage_snapshot = record_usage_accounting
    save_usage_record = record_usage_accounting
    latest_usage_snapshot = latest_usage_accounting

    def claim_coordination_operation(self, kind: str, operation_id: str, owner_id: str, lease_expires_at: str, idempotency_key: str, *, now: str) -> bool:
        if kind not in {"lead-dispatch", "supervisor-dispatch"} or not all(isinstance(item, str) and item.strip() for item in (operation_id, owner_id, lease_expires_at, idempotency_key, now)):
            raise ValueError("coordination operation claim is invalid")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT owner_id,lease_expires_at,state,idempotency_key FROM coordination_operation_claims WHERE kind=? AND operation_id=?", (kind, operation_id)).fetchone()
            if row is None:
                self.connection.execute("INSERT INTO coordination_operation_claims VALUES (?,?,?,?,1,?,'claimed',?)", (kind, operation_id, owner_id, lease_expires_at, idempotency_key, now))
                acquired = True
            elif row[3] != idempotency_key:
                raise ValueError("coordination operation idempotency conflict")
            elif row[2] == "completed" or (row[2] == "claimed" and row[1] is not None and datetime.fromisoformat(str(row[1]).replace("Z", "+00:00")) > datetime.fromisoformat(now.replace("Z", "+00:00"))):
                acquired = False
            else:
                self.connection.execute("UPDATE coordination_operation_claims SET owner_id=?,lease_expires_at=?,attempts=attempts+1,state='claimed',updated_at=? WHERE kind=? AND operation_id=?", (owner_id, lease_expires_at, now, kind, operation_id))
                acquired = True
            self.connection.execute("COMMIT")
            return acquired
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def complete_coordination_operation(self, kind: str, operation_id: str, owner_id: str, *, now: str) -> None:
        cursor = self.connection.execute("UPDATE coordination_operation_claims SET state='completed',lease_expires_at=NULL,updated_at=? WHERE kind=? AND operation_id=? AND owner_id=? AND state='claimed'", (now, kind, operation_id, owner_id))
        if cursor.rowcount != 1:
            row = self.connection.execute("SELECT state FROM coordination_operation_claims WHERE kind=? AND operation_id=?", (kind, operation_id)).fetchone()
            if row is None or row[0] != "completed": raise ValueError("coordination operation claim is unavailable")

    def release_coordination_operation(self, kind: str, operation_id: str, owner_id: str, *, now: str) -> None:
        self.connection.execute("UPDATE coordination_operation_claims SET owner_id=NULL,lease_expires_at=NULL,state='pending',updated_at=? WHERE kind=? AND operation_id=? AND owner_id=? AND state='claimed'", (now, kind, operation_id, owner_id))

    def coordination_operation_claim(self, kind: str, operation_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT owner_id,lease_expires_at,attempts,idempotency_key,state,updated_at FROM coordination_operation_claims WHERE kind=? AND operation_id=?", (kind, operation_id)).fetchone()
        if row is None: return None
        return {"kind": kind, "operationId": operation_id, "ownerId": row[0], "leaseExpiresAt": row[1], "attempts": row[2], "idempotencyKey": row[3], "state": row[4], "updatedAt": row[5]}

    def save_coordination_dispatch(self, request_id: str, dispatch_id: str, payload: Mapping[str, Any], *, state: str = "pending") -> dict[str, Any]:
        if not request_id or not dispatch_id:
            raise ValueError("coordination dispatch identity is required")
        if state not in {"uncertain", "pending"}:
            raise ValueError("coordination dispatch state is invalid")
        value = dict(payload)
        existing = self.coordination_dispatch(request_id)
        if existing is not None:
            if existing["dispatchId"] != dispatch_id or existing["payload"] != value:
                raise ValueError("coordination dispatch conflict")
            return existing
        self.connection.execute("INSERT INTO coordination_dispatches(request_id,dispatch_id,payload_json,state,updated_at) VALUES (?,?,?,?,?)", (request_id, dispatch_id, _dump(value), state, self._now()))
        return self.coordination_dispatch(request_id)

    def create_coordination_dispatch_intent(self, request_id: str, dispatch_id: str, payload: Mapping[str, Any], *, owner_id: str, idempotency_key: str) -> dict[str, Any]:
        return self._create_coordination_intent("dispatch", request_id, dispatch_id, payload, owner_id, idempotency_key)

    def coordination_dispatch(self, request_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT dispatch_id,payload_json,state,updated_at,owner_id,idempotency_key FROM coordination_dispatches WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return None
        return {"requestId": request_id, "dispatchId": row[0], "payload": json.loads(row[1]), "state": row[2], "updatedAt": row[3], "ownerId": row[4], "idempotencyKey": row[5]}

    def save_coordination_review(self, request_id: str, review_id: str, payload: Mapping[str, Any], *, state: str = "pending") -> dict[str, Any]:
        if state not in {"uncertain", "pending"}:
            raise ValueError("coordination review state is invalid")
        value = dict(payload)
        existing = self.coordination_review(request_id)
        if existing is not None:
            if existing["reviewId"] != review_id or existing["payload"] != value:
                raise ValueError("coordination review conflict")
            return existing
        self.connection.execute("INSERT INTO coordination_reviews(request_id,review_id,payload_json,state,updated_at) VALUES (?,?,?,?,?)", (request_id, review_id, _dump(value), state, self._now()))
        return self.coordination_review(request_id)

    def create_coordination_review_intent(self, request_id: str, review_id: str, payload: Mapping[str, Any], *, owner_id: str, idempotency_key: str) -> dict[str, Any]:
        return self._create_coordination_intent("review", request_id, review_id, payload, owner_id, idempotency_key)

    def _create_coordination_intent(self, kind: str, operation_id: str, external_id: str, payload: Mapping[str, Any], owner_id: str, idempotency_key: str) -> dict[str, Any]:
        if kind not in {"dispatch", "review"} or not all(isinstance(item, str) and item.strip() for item in (operation_id, external_id, owner_id, idempotency_key)):
            raise ValueError("coordination intent identity is invalid")
        table = "coordination_dispatches" if kind == "dispatch" else "coordination_reviews"
        id_column = "dispatch_id" if kind == "dispatch" else "review_id"
        encoded = _dump(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute(f"SELECT {id_column},payload_json,owner_id,idempotency_key FROM {table} WHERE request_id=?", (operation_id,)).fetchone()
            inserted = row is None
            if inserted:
                self.connection.execute(f"INSERT INTO {table}(request_id,{id_column},payload_json,state,updated_at,owner_id,idempotency_key) VALUES (?,?,?,'uncertain',?,?,?)", (operation_id, external_id, encoded, self._now(), owner_id, idempotency_key))
            elif row[0] != external_id or row[1] != encoded or row[3] != idempotency_key:
                raise ValueError("coordination intent conflict")
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        intent = self.coordination_dispatch(operation_id) if kind == "dispatch" else self.coordination_review(operation_id)
        return {"inserted": inserted, "winner": inserted, "intent": intent}

    def coordination_review(self, request_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT review_id,payload_json,state,updated_at,owner_id,idempotency_key FROM coordination_reviews WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return None
        return {"requestId": request_id, "reviewId": row[0], "payload": json.loads(row[1]), "state": row[2], "updatedAt": row[3], "ownerId": row[4], "idempotencyKey": row[5]}

    def coordination_review_for_review_id(self, review_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT request_id FROM coordination_reviews WHERE review_id=?", (review_id,)).fetchone()
        return None if row is None else self.coordination_review(str(row[0]))

    def transition_coordination_dispatch(self, request_id: str, state: str) -> dict[str, Any]:
        self.connection.execute("UPDATE coordination_dispatches SET state=?,updated_at=? WHERE request_id=?", (state, self._now(), request_id))
        result = self.coordination_dispatch(request_id)
        if result is None:
            raise ValueError("coordination dispatch is missing")
        return result

    def transition_coordination_review(self, request_id: str, state: str) -> dict[str, Any]:
        self.connection.execute("UPDATE coordination_reviews SET state=?,updated_at=? WHERE request_id=?", (state, self._now(), request_id))
        result = self.coordination_review(request_id)
        if result is None:
            raise ValueError("coordination review is missing")
        return result

    def claim_nonce(self, nonce: str, message_id: str, claimed_at: str) -> bool:
        cursor = self.connection.execute("INSERT OR IGNORE INTO peer_nonces VALUES (?,?,?)", (nonce, message_id, claimed_at))
        return cursor.rowcount == 1

    def get_round(self, round_id: str):
        row = self.connection.execute("SELECT request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded FROM rounds WHERE round_id=?", (round_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), row[2], row[3], row[4], json.loads(row[5]) if row[5] else None, bool(row[6]))

    def active_round(self) -> str | None:
        row = self.connection.execute("SELECT round_id FROM rounds WHERE result_json IS NULL AND dispatch_state NOT IN ('failed','cancelled-before-start') LIMIT 1").fetchone()
        return None if row is None else str(row[0])

    def active_rounds(self) -> list[dict[str, Any]]:
        """Return the immutable request identity for every unfinished round."""
        rows = self.connection.execute("SELECT request_json FROM rounds WHERE result_json IS NULL AND dispatch_state NOT IN ('failed','cancelled-before-start') ORDER BY rowid").fetchall()
        return [json.loads(row[0]) for row in rows]

    def record_canary_round(self, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str, authorization_id: str, expected_revision: int, now: str) -> None:
        """Atomically reserve one of the two authorized canary streams.

        The authorization and Roadex outcome are read inside the same
        ``BEGIN IMMEDIATE`` transaction as the active-round check.  This is
        intentionally a store operation: a caller cannot turn an assertion
        about authorization into a second stream or win a cross-process race.
        """
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            auth_row = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-canary-authorization' AND record_id=?", (authorization_id,)).fetchone()
            if auth_row is None or auth_row[1] != "delivered":
                raise ValueError("concurrency canary authorization is unavailable")
            try:
                authorization = parse_canary_authorization(json.loads(auth_row[0]))
            except (ContractError, TypeError, ValueError) as error:
                raise ValueError("concurrency canary authorization is invalid") from error
            if authorization["digest"] != auth_row[2]:
                raise ValueError("concurrency canary authorization digest conflict")
            if authorization.get("expectedRevision") != expected_revision:
                raise ValueError("concurrency canary authorization revision conflict")
            try:
                deadline = datetime.fromisoformat(str(authorization["deadline"]).replace("Z", "+00:00"))
                observed = datetime.fromisoformat(str(now).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("concurrency canary authorization timestamp is invalid") from error
            if deadline <= observed:
                raise ValueError("concurrency canary authorization expired")
            decision_id = authorization.get("decisionId")
            decision_row = self.connection.execute("SELECT status FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
            if decision_row is None or decision_row[0] != "approved":
                raise ValueError("concurrency canary authorization is not approved")
            projects = authorization.get("projects")
            if not isinstance(projects, list) or len(projects) != 2:
                raise ValueError("concurrency canary authorization project binding is invalid")
            bound = next((item for item in projects if isinstance(item, dict) and item.get("projectId") == request.get("projectId")), None)
            if bound is None or any(request.get(field) != bound.get(source) for field, source in (("projectId", "projectId"), ("planId", "planId"), ("planVersion", "planVersion"), ("projectLeadId", "leadId"))):
                raise ValueError("concurrency canary round identity is not authorized")
            rows = self.connection.execute("SELECT request_json FROM rounds WHERE result_json IS NULL AND dispatch_state NOT IN ('failed','cancelled-before-start') ORDER BY rowid").fetchall()
            active = [json.loads(row[0]) for row in rows]
            if len(active) >= 2:
                raise ValueError("single_stream_busy")
            allowed = {(item.get("projectId"), item.get("planId"), item.get("planVersion"), item.get("leadId")) for item in projects if isinstance(item, dict)}
            for item in active:
                identity = (item.get("projectId"), item.get("planId"), item.get("planVersion"), item.get("projectLeadId"))
                if identity not in allowed or item.get("projectId") == request.get("projectId"):
                    raise ValueError("single_stream_busy")
            self.connection.execute("INSERT INTO rounds(round_id,request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded,canary_authorization_id) VALUES (?,?,?,?,?,'pending',NULL,0,?)", (request["roundId"], _dump_wire(request), _dump_wire(receipt), _token_hash(capability), capability, authorization_id))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def _verify_canary_execution_rounds(self, canary: Mapping[str, Any]) -> None:
        intervals = []
        for execution in canary["executions"]:
            started = execution["started"]
            row = self.connection.execute("SELECT request_json,result_json FROM rounds WHERE round_id=?", (started["roundId"],)).fetchone()
            if row is None:
                raise ValueError("canary result round is unavailable")
            timing = self.connection.execute("SELECT canary_authorization_id,started_at,completed_at FROM rounds WHERE round_id=?", (started["roundId"],)).fetchone()
            if timing is None or timing[0] != canary["authorizationId"] or not timing[1] or not timing[2]:
                raise ValueError("canary result timing or authorization conflict")
            try:
                local_started = datetime.fromisoformat(str(timing[1]).replace("Z", "+00:00"))
                local_completed = datetime.fromisoformat(str(timing[2]).replace("Z", "+00:00"))
            except (TypeError, ValueError) as error:
                raise ValueError("canary result timing or authorization conflict") from error
            if local_started.tzinfo is None or local_completed.tzinfo is None or local_completed < local_started:
                raise ValueError("canary result timing or authorization conflict")
            intervals.append((local_started, local_completed))
            request = json.loads(row[0]); stored_result = json.loads(row[1]) if row[1] else None
            if request.get("roundId") != started["roundId"] or any(request.get(key) != started.get(source) for key, source in (("projectId", "projectId"), ("planId", "planId"), ("planVersion", "planVersion"), ("projectLeadId", "leadId"))):
                raise ValueError("canary result round identity conflict")
            if not isinstance(stored_result, dict) or stored_result.get("status") != "completed":
                raise ValueError("canary result round is not completed")
            completed = execution["completed"]
            result_digest = _round_result_digest(stored_result)
            evidence_digest = canonical_digest({"provenanceId": stored_result.get("provenanceId"), "resultDigest": result_digest})
            if completed.get("evidenceId") != stored_result.get("provenanceId") or completed.get("resultDigest") != result_digest or completed.get("evidenceDigest") != evidence_digest:
                raise ValueError("canary result evidence does not bind to stored round result")
        if len(intervals) != 2 or not (intervals[0][0] < intervals[1][1] and intervals[1][0] < intervals[0][1]):
            raise ValueError("canary result timing does not show trusted overlap")

    def record_durable_ceiling_round(self, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str, now: str) -> None:
        """Reserve an eligible round under the persisted global ceiling.

        The change record and its exact authorization are re-read under the
        same write lock as the unresolved-round count.  This keeps a restart
        or two bridge processes from observing a stale ceiling or admitting a
        third stream.
        """
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            change = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-ceiling-change' AND state IN ('delivered','settled') ORDER BY updated_at DESC, rowid DESC LIMIT 1").fetchone()
            if change is None:
                raise ValueError("concurrency ceiling is unavailable")
            change_payload = json.loads(change[0])
            if canonical_digest(change_payload) != change[2]:
                raise ValueError("concurrency ceiling change digest conflict")
            authorization_id = change_payload.get("authorizationId")
            if set(change_payload) != {"authorizationId", "correlationId", "idempotencyKey", "occurredAt"} or not isinstance(authorization_id, str) or not authorization_id.strip():
                raise ValueError("concurrency ceiling change binding is invalid")
            auth = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-ceiling-authorization' AND record_id=?", (authorization_id,)).fetchone()
            if auth is None or auth[1] not in {"delivered", "settled"}:
                raise ValueError("concurrency ceiling authorization is unavailable")
            try:
                authorization = parse_concurrency_ceiling_authorization(json.loads(auth[0]))
            except (ContractError, TypeError, ValueError) as error:
                raise ValueError("concurrency ceiling authorization is invalid") from error
            if authorization["digest"] != auth[2]:
                raise ValueError("concurrency ceiling authorization digest conflict")
            if authorization.get("ceiling") != 2 or authorization.get("revision") != authorization.get("expectedRevision", -1) + 1:
                raise ValueError("concurrency ceiling is invalid")
            canary_row = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-canary-result' AND record_id=?", (authorization.get("canaryResultId"),)).fetchone()
            if canary_row is None or canary_row[1] != "delivered":
                raise ValueError("successful delivered canary evidence is required")
            try:
                canary = parse_concurrency_canary_result(json.loads(canary_row[0]))
            except (ContractError, TypeError, ValueError) as error:
                raise ValueError("successful canary evidence is invalid") from error
            if canary["digest"] != canary_row[2]:
                raise ValueError("concurrency canary result digest conflict")
            canary_authorization = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-canary-authorization' AND record_id=?", (canary.get("authorizationId"),)).fetchone()
            try:
                parsed_canary_authorization = parse_canary_authorization(json.loads(canary_authorization[0])) if canary_authorization else None
            except (ContractError, TypeError, ValueError) as error:
                raise ValueError("canary authorization is invalid") from error
            if canary_authorization and parsed_canary_authorization["digest"] != canary_authorization[2]:
                raise ValueError("canary authorization digest conflict")
            expected_projects = parsed_canary_authorization and parsed_canary_authorization.get("projects")
            observed_projects = [{"projectId": item.get("started", {}).get("projectId"), "planId": item.get("started", {}).get("planId"), "planVersion": item.get("started", {}).get("planVersion"), "leadId": item.get("started", {}).get("leadId")} for item in canary.get("executions", [])] if isinstance(canary.get("executions"), list) else []
            if canary_authorization is None or canary_authorization[1] not in {"delivered", "settled"} or canary.get("resultId") != authorization.get("canaryResultId") or canary.get("targetCeiling") != authorization.get("ceiling") or canary.get("expectedRevision") != authorization.get("expectedRevision") or canary.get("concurrencyObserved") is not True or len(observed_projects) != 2 or sorted(observed_projects, key=lambda item: item["projectId"]) != sorted(expected_projects or [], key=lambda item: item.get("projectId")):
                raise ValueError("successful canary evidence does not bind to ceiling authorization")
            self._verify_canary_execution_rounds(canary)
            decision_row = self.connection.execute("SELECT request_json,status FROM decisions WHERE decision_id=?", (authorization.get("decisionId"),)).fetchone()
            if decision_row is None or decision_row[1] != "approved":
                raise ValueError("concurrency ceiling authorization is not approved")
            decision = json.loads(decision_row[0])
            expected_decision = {"decisionId": authorization.get("decisionId"), "projectId": authorization.get("projectId"), "planId": authorization.get("planId"), "workflowId": authorization.get("workflowId"), "decisionVersion": authorization.get("decisionVersion"), "question": authorization.get("question"), "resultProvenanceId": authorization.get("digest")}
            if any(decision.get(field) != value for field, value in expected_decision.items()):
                raise ValueError("concurrency ceiling decision binding is invalid")
            active = [json.loads(row[0]) for row in self.connection.execute("SELECT request_json FROM rounds WHERE result_json IS NULL AND dispatch_state NOT IN ('failed','cancelled-before-start') ORDER BY rowid").fetchall()]
            if len(active) >= 2 or any(item.get("projectId") == request.get("projectId") for item in active):
                raise ValueError("single_stream_busy")
            self.connection.execute("INSERT INTO rounds(round_id,request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded) VALUES (?,?,?,?,?,'pending',NULL,0)", (request["roundId"], _dump_wire(request), _dump_wire(receipt), _token_hash(capability), capability))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def record_concurrency_ceiling_change(self, payload: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        """Validate and durably queue one exact, approved ceiling change."""
        if set(payload) != {"authorizationId", "correlationId", "idempotencyKey", "occurredAt"}:
            raise ValueError("concurrency ceiling change is invalid")
        authorization_id = payload.get("authorizationId")
        if any(not isinstance(payload.get(field), str) or not payload[field].strip() for field in payload):
            raise ValueError("concurrency ceiling change is invalid")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            auth_row = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-ceiling-authorization' AND record_id=?", (authorization_id,)).fetchone()
            if auth_row is None or auth_row[1] not in {"delivered", "settled"}:
                raise ValueError("concurrency ceiling authorization is unavailable")
            try:
                authorization = parse_concurrency_ceiling_authorization(json.loads(auth_row[0]))
            except (ContractError, TypeError, ValueError) as error:
                raise ValueError("concurrency ceiling authorization is invalid") from error
            if authorization["digest"] != auth_row[2]:
                raise ValueError("concurrency ceiling authorization digest conflict")
            canary_row = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-canary-result' AND record_id=?", (authorization["canaryResultId"],)).fetchone()
            if canary_row is None or canary_row[1] != "delivered":
                raise ValueError("successful delivered canary evidence is required")
            try:
                canary = parse_concurrency_canary_result(json.loads(canary_row[0]))
            except (ContractError, TypeError, ValueError) as error:
                raise ValueError("successful canary evidence is invalid") from error
            if canary["digest"] != canary_row[2]:
                raise ValueError("concurrency canary result digest conflict")
            canary_auth_row = self.connection.execute("SELECT payload_json,state,digest FROM protocol_records WHERE kind='concurrency-canary-authorization' AND record_id=?", (canary["authorizationId"],)).fetchone()
            if canary_auth_row is None or canary_auth_row[1] not in {"delivered", "settled"}:
                raise ValueError("canary authorization is unavailable")
            try:
                canary_authorization = parse_canary_authorization(json.loads(canary_auth_row[0]))
            except (ContractError, TypeError, ValueError) as error:
                raise ValueError("canary authorization is invalid") from error
            if canary_authorization["digest"] != canary_auth_row[2]:
                raise ValueError("canary authorization digest conflict")
            expected_projects = {(item["projectId"], item["planId"], item["planVersion"], item["leadId"]) for item in canary_authorization["projects"]}
            observed_projects = {(item["started"]["projectId"], item["started"]["planId"], item["started"]["planVersion"], item["started"]["leadId"]) for item in canary["executions"]}
            if canary["resultId"] != authorization["canaryResultId"] or canary["targetCeiling"] != authorization["ceiling"] or canary["expectedRevision"] != authorization["expectedRevision"] or observed_projects != expected_projects:
                raise ValueError("successful canary evidence does not bind to ceiling")
            self._verify_canary_execution_rounds(canary)
            decision_row = self.connection.execute("SELECT request_json,status FROM decisions WHERE decision_id=?", (authorization["decisionId"],)).fetchone()
            if decision_row is None or decision_row[1] != "approved":
                raise ValueError("concurrency ceiling authorization is not approved")
            decision = json.loads(decision_row[0])
            for field in ("decisionId", "projectId", "planId", "workflowId", "decisionVersion", "question"):
                if decision.get(field) != authorization[field]:
                    raise ValueError("concurrency ceiling decision binding is invalid")
            if decision.get("resultProvenanceId") != authorization["digest"] or decision.get("idempotencyKey") not in {authorization["idempotencyKey"], f"decision:{authorization['idempotencyKey']}"}:
                raise ValueError("concurrency ceiling decision binding is invalid")
            digest = canonical_digest(payload)
            existing = self.protocol_record("concurrency-ceiling-change", authorization_id)
            if existing is not None:
                if existing["digest"] != digest or existing["payload"] != dict(payload):
                    raise ValueError("concurrency ceiling change conflict")
                self.connection.execute("COMMIT")
                return existing, False
            by_key = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind='concurrency-ceiling-change' AND idempotency_key=?", (payload["idempotencyKey"],)).fetchone()
            if by_key is not None and by_key[0] != authorization_id:
                raise ValueError("concurrency ceiling change idempotency conflict")
            self.connection.execute("INSERT INTO protocol_records(kind,record_id,idempotency_key,digest,payload_json,state,updated_at) VALUES (?,?,?,?,?,?,?)", ("concurrency-ceiling-change", authorization_id, payload["idempotencyKey"], digest, _dump_wire(payload), "queued", self._now()))
            record = self.protocol_record("concurrency-ceiling-change", authorization_id)
            self.connection.execute("COMMIT")
            return record, True
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def record_single_stream_round(self, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str) -> None:
        """Atomically preserve the default global ceiling of one."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if self.connection.execute("SELECT 1 FROM rounds WHERE result_json IS NULL AND dispatch_state NOT IN ('failed','cancelled-before-start') LIMIT 1").fetchone() is not None:
                raise ValueError("single_stream_busy")
            self.connection.execute("INSERT INTO rounds(round_id,request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded) VALUES (?,?,?,?,?,'pending',NULL,0)", (request["roundId"], _dump_wire(request), _dump_wire(receipt), _token_hash(capability), capability))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def record_round(self, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str) -> None:
        self.connection.execute("INSERT INTO rounds(round_id,request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded) VALUES (?,?,?,?,?,'pending',NULL,0)", (request["roundId"], _dump_wire(request), _dump_wire(receipt), _token_hash(capability), capability))

    def start_round_dispatch(self, round_id: str, request: Mapping[str, Any], capability: str, started_at: str, *, binding: Mapping[str, Any] | None = None, prompt_digest: str | None = None) -> bool:
        """CAS pending round ownership and seed its prompt ledger atomically."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT request_json,capability_hash,capability_token,dispatch_state,result_json,codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
            if row is None or json.loads(row[0]) != dict(request) or row[1] != _token_hash(capability) or row[2] != capability:
                raise ValueError("round dispatch binding is invalid")
            if row[3] != "pending" or row[4] is not None:
                self.connection.execute("COMMIT")
                return False
            encoded_binding = _dump_wire(binding) if binding is not None else None
            if row[5] is not None and row[5] != encoded_binding:
                raise ValueError("round execution binding is immutable")
            self.connection.execute("UPDATE rounds SET dispatch_state='started',started_at=COALESCE(started_at,?),codex_binding_json=COALESCE(codex_binding_json,?) WHERE round_id=? AND dispatch_state='pending' AND result_json IS NULL", (started_at, encoded_binding, round_id))
            if binding is not None and prompt_digest is not None:
                if not isinstance(prompt_digest, str) or len(prompt_digest) != 64:
                    raise ValueError("round prompt digest is invalid")
                self.connection.execute("INSERT INTO round_prompt_deliveries(round_id,request_digest,capability_hash,binding_json,phase,prompt_digest,updated_at) VALUES (?,?,?,?,?,?,?)", (round_id, self._round_request_digest(request), _token_hash(capability), encoded_binding, "prepared", prompt_digest, started_at))
            self.connection.execute("COMMIT")
            return True
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def mark_dispatch_started(self, round_id: str, started_at: str) -> None:
        self.connection.execute("UPDATE rounds SET dispatch_state='started',started_at=COALESCE(started_at,?) WHERE round_id=? AND dispatch_state='pending'", (started_at, round_id))

    def bind_round_execution(self, round_id: str, binding: Mapping[str, Any]) -> dict[str, Any]:
        encoded = _dump_wire(binding)
        existing = self.connection.execute("SELECT codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
        if existing is None:
            raise ValueError("round is missing")
        if existing[0] is not None and existing[0] != encoded:
            raise ValueError("round execution binding is immutable")
        if existing[0] is None:
            self.connection.execute("UPDATE rounds SET codex_binding_json=? WHERE round_id=? AND dispatch_state='pending'", (encoded, round_id))
        return dict(binding)

    def round_binding(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
        return None if row is None or row[0] is None else json.loads(row[0])

    def mark_dispatched(self, round_id: str, receipt: Mapping[str, Any]) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT dispatch_state,result_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
            if row is None or row[0] != "started" or row[1] is not None:
                raise ValueError("round dispatch state changed")
            delivery = self.connection.execute("SELECT phase FROM round_prompt_deliveries WHERE round_id=?", (round_id,)).fetchone()
            if delivery is not None and delivery[0] != "confirmed":
                raise ValueError("round prompt delivery is not confirmed")
            updated = self.connection.execute("UPDATE rounds SET dispatch_state='dispatched',receipt_json=? WHERE round_id=? AND dispatch_state='started' AND result_json IS NULL", (_dump_wire(receipt), round_id))
            if updated.rowcount != 1:
                raise ValueError("round dispatch state changed")
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def round_cancellation(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT cancellation_id,request_digest,attestation_json,receipt_json,inserted_at FROM round_cancellations WHERE round_id=?", (round_id,)).fetchone()
        if row is None:
            return None
        return {"cancellationId": row[0], "roundId": round_id, "requestDigest": row[1], "attestation": json.loads(row[2]), "receipt": json.loads(row[3]), "insertedAt": row[4]}

    def cancel_round_before_start(self, cancellation_id: str, request: Mapping[str, Any], request_digest: str, *, now: str) -> dict[str, Any]:
        if not isinstance(cancellation_id, str) or not cancellation_id.strip() or len(cancellation_id) > 256 or not isinstance(request_digest, str) or request_digest != canonical_digest(request):
            raise ValueError("round cancellation request binding is invalid")
        round_id = str(request.get("roundId", ""))
        attestation = {"cancellationId": cancellation_id, "request": dict(request), "requestDigest": request_digest}
        encoded_attestation = _dump_wire(attestation)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self.connection.execute(
                "SELECT cancellation_id,round_id,request_digest,attestation_json,receipt_json FROM round_cancellations WHERE cancellation_id=? OR round_id=?",
                (cancellation_id, round_id),
            ).fetchone()
            if existing is not None:
                round_state = self.connection.execute("SELECT dispatch_state,started_at,codex_binding_json,result_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
                if existing[:4] != (cancellation_id, round_id, request_digest, encoded_attestation) or round_state != ("cancelled-before-start", None, None, None):
                    raise ValueError("round cancellation conflict")
                self.connection.execute("COMMIT")
                return {"accepted": True, "inserted": False, "receipt": json.loads(existing[4])}
            row = self.connection.execute(
                "SELECT request_json,dispatch_state,result_json,started_at,codex_binding_json FROM rounds WHERE round_id=?",
                (round_id,),
            ).fetchone()
            recovery = self.connection.execute("SELECT 1 FROM round_recoveries WHERE round_id=?", (round_id,)).fetchone()
            failure = self.connection.execute("SELECT 1 FROM operational_failure_intents WHERE round_id=?", (round_id,)).fetchone()
            if row is None or json.loads(row[0]) != dict(request) or canonical_digest(json.loads(row[0])) != request_digest or row[1] != "pending" or row[2] is not None or row[3] is not None or row[4] is not None or recovery is not None or failure is not None:
                raise ValueError("round is not provably pending before start")
            before = {"dispatchState": "pending", "startedAt": None, "codexBinding": None, "result": None, "recovery": False, "operationalFailure": False}
            unsigned = {"schemaVersion": "psychlo.round-cancel-before-start.v1", "kind": "round-cancel-before-start", "status": "cancelled", "roundId": round_id, "projectId": str(request["projectId"]), "requestDigest": request_digest, "before": before, "cancelledAt": now}
            receipt = {**unsigned, "digest": canonical_digest(unsigned)}
            updated = self.connection.execute(
                "UPDATE rounds SET dispatch_state='cancelled-before-start' WHERE round_id=? AND request_json=? AND dispatch_state='pending' AND result_json IS NULL AND started_at IS NULL AND codex_binding_json IS NULL AND NOT EXISTS (SELECT 1 FROM round_recoveries WHERE round_id=?) AND NOT EXISTS (SELECT 1 FROM operational_failure_intents WHERE round_id=?)",
                (round_id, row[0], round_id, round_id),
            )
            if updated.rowcount != 1:
                raise ValueError("round changed before cancellation")
            self.connection.execute(
                "INSERT INTO round_cancellations(cancellation_id,round_id,request_digest,attestation_json,receipt_json,inserted_at) VALUES (?,?,?,?,?,?)",
                (cancellation_id, round_id, request_digest, encoded_attestation, _dump_wire(receipt), now),
            )
            self.connection.execute("COMMIT")
            return {"accepted": True, "inserted": True, "receipt": receipt}
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def round_binding_attestation(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT manifest_digest,attestation_json,inserted_at FROM round_binding_attestations WHERE round_id=?", (round_id,)).fetchone()
        if row is None:
            return None
        return {"roundId": round_id, "manifestDigest": row[0], "attestation": json.loads(row[1]), "insertedAt": row[2]}

    def migrate_legacy_round_binding(self, round_id: str, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str, binding: Mapping[str, Any], attestation: Mapping[str, Any], *, now: str) -> dict[str, Any]:
        encoded_binding = _dump_wire(binding)
        encoded_attestation = _dump_wire(attestation)
        manifest_digest = str(attestation.get("manifestDigest", ""))
        if not manifest_digest:
            raise ValueError("legacy binding attestation digest is required")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
            if row is None or row[0] != _dump_wire(request) or row[1] != _dump_wire(receipt) or row[2] != _token_hash(capability) or row[3] != capability or row[4] != "started" or row[5] is not None or row[6] is not None:
                raise ValueError("legacy binding round changed before attestation")
            if self.connection.execute("SELECT 1 FROM round_recoveries WHERE round_id=?", (round_id,)).fetchone() is not None:
                raise ValueError("legacy binding recovery record already exists")
            if self.connection.execute("SELECT 1 FROM operational_failure_intents WHERE round_id=?", (round_id,)).fetchone() is not None:
                raise ValueError("legacy binding operational failure intent already exists")
            if self.connection.execute("SELECT 1 FROM round_binding_attestations WHERE round_id=? OR manifest_digest=?", (round_id, manifest_digest)).fetchone() is not None:
                raise ValueError("legacy binding attestation already exists")
            update = self.connection.execute("UPDATE rounds SET codex_binding_json=? WHERE round_id=? AND request_json=? AND receipt_json=? AND capability_hash=? AND capability_token=? AND dispatch_state='started' AND result_json IS NULL AND codex_binding_json IS NULL AND NOT EXISTS (SELECT 1 FROM round_recoveries WHERE round_id=?) AND NOT EXISTS (SELECT 1 FROM operational_failure_intents WHERE round_id=?)", (encoded_binding, round_id, _dump_wire(request), _dump_wire(receipt), _token_hash(capability), capability, round_id, round_id))
            if update.rowcount != 1:
                raise ValueError("legacy binding round changed before attestation")
            self.connection.execute("INSERT INTO round_binding_attestations(round_id,manifest_digest,attestation_json,inserted_at) VALUES (?,?,?,?)", (round_id, manifest_digest, encoded_attestation, now))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        record = self.round_binding_attestation(round_id)
        if record is None:
            raise ValueError("legacy binding attestation is missing")
        return {"accepted": True, "roundId": round_id, "binding": dict(binding), "attestation": record}

    def operational_failure_intent(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT request_digest,capability_hash,idempotency_key,payload_json,payload_digest,state,owner_id,claim_token,lease_expires_at,attempts,outcome_json,last_error,updated_at FROM operational_failure_intents WHERE round_id=?", (round_id,)).fetchone()
        if row is None:
            return None
        return {"roundId": round_id, "requestDigest": row[0], "capabilityHash": row[1], "idempotencyKey": row[2], "payload": json.loads(row[3]), "payloadDigest": row[4], "state": row[5], "ownerId": row[6], "claimToken": row[7], "leaseExpiresAt": row[8], "attempts": row[9], "outcome": json.loads(row[10]) if row[10] else None, "lastError": row[11], "updatedAt": row[12]}

    def create_operational_failure_intent(self, round_id: str, request: Mapping[str, Any], capability: str, payload: Mapping[str, Any], *, now: str) -> tuple[dict[str, Any], bool]:
        request_digest = self._round_request_digest(request)
        capability_hash = _token_hash(capability)
        payload_digest = hashlib.sha256(_dump_wire(payload).encode("utf-8")).hexdigest()
        encoded = _dump_wire(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT request_json,capability_hash,capability_token,dispatch_state,result_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
            if row is None or json.loads(row[0]) != dict(request) or row[1] != capability_hash or row[2] != capability or row[3] != "started" or row[4] is not None:
                raise ValueError("operational failure round binding is invalid")
            existing = self.connection.execute("SELECT request_digest,capability_hash,idempotency_key,payload_digest,payload_json FROM operational_failure_intents WHERE round_id=?", (round_id,)).fetchone()
            if existing is not None:
                if existing[:4] != (request_digest, capability_hash, str(request["idempotencyKey"]), payload_digest) or existing[4] != encoded:
                    raise ValueError("operational failure intent conflict")
                inserted = False
            else:
                conflict = self.connection.execute("SELECT round_id FROM operational_failure_intents WHERE idempotency_key=? OR payload_digest=?", (str(request["idempotencyKey"]), payload_digest)).fetchone()
                if conflict is not None and conflict[0] != round_id:
                    raise ValueError("operational failure idempotency conflict")
                self.connection.execute("INSERT INTO operational_failure_intents(round_id,request_digest,capability_hash,idempotency_key,payload_json,payload_digest,state,updated_at) VALUES (?,?,?,?,?,?, 'queued',?)", (round_id, request_digest, capability_hash, str(request["idempotencyKey"]), encoded, payload_digest, now))
                inserted = True
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        record = self.operational_failure_intent(round_id)
        if record is None:
            raise ValueError("operational failure intent is missing")
        return record, inserted

    def claim_operational_failure(self, round_id: str, request: Mapping[str, Any], capability: str, *, owner_id: str, lease_expires_at: str, now: str) -> dict[str, Any] | None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            round_row = self.connection.execute("SELECT request_json,capability_hash,capability_token,dispatch_state,result_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()
            intent = self.connection.execute("SELECT request_digest,capability_hash,idempotency_key,state,owner_id,claim_token,lease_expires_at FROM operational_failure_intents WHERE round_id=?", (round_id,)).fetchone()
            if round_row is None or intent is None or json.loads(round_row[0]) != dict(request) or round_row[1] != _token_hash(capability) or round_row[2] != capability or round_row[3] != "started" or round_row[4] is not None or intent[0] != self._round_request_digest(request) or intent[1] != _token_hash(capability) or intent[2] != str(request["idempotencyKey"]):
                raise ValueError("operational failure claim binding is invalid")
            if intent[3] == "accepted":
                self.connection.execute("COMMIT")
                return None
            if intent[4] and intent[5] and intent[6]:
                try:
                    if datetime.fromisoformat(str(intent[6]).replace("Z", "+00:00")) > datetime.fromisoformat(now.replace("Z", "+00:00")):
                        self.connection.execute("COMMIT")
                        return None
                except ValueError:
                    raise ValueError("operational failure lease is invalid")
            token = secrets.token_urlsafe(32)
            self.connection.execute("UPDATE operational_failure_intents SET state='claimed',owner_id=?,claim_token=?,lease_expires_at=?,attempts=attempts+1,updated_at=? WHERE round_id=? AND state != 'accepted'", (owner_id, token, lease_expires_at, now, round_id))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        return self.operational_failure_intent(round_id)

    def finish_operational_failure(self, round_id: str, owner_id: str, claim_token: str, *, accepted: bool, outcome: Mapping[str, Any] | None = None, error: str | None = None, now: str) -> dict[str, Any]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT state FROM operational_failure_intents WHERE round_id=? AND owner_id=? AND claim_token=?", (round_id, owner_id, claim_token)).fetchone()
            if row is None:
                existing = self.operational_failure_intent(round_id)
                if accepted and existing is not None and existing["state"] == "accepted":
                    self.connection.execute("COMMIT")
                    return existing
                raise ValueError("operational failure claim is unavailable")
            if accepted:
                updated = self.connection.execute("UPDATE operational_failure_intents SET state='accepted',owner_id=NULL,claim_token=NULL,lease_expires_at=NULL,outcome_json=?,last_error=NULL,updated_at=? WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (_dump_wire(outcome or {}), now, round_id, owner_id, claim_token))
                if updated.rowcount != 1:
                    raise ValueError("operational failure claim is unavailable")
                round_update = self.connection.execute("UPDATE rounds SET dispatch_state='failed' WHERE round_id=? AND dispatch_state='started' AND result_json IS NULL", (round_id,))
                if round_update.rowcount != 1:
                    raise ValueError("operational failure round state changed")
            else:
                updated = self.connection.execute("UPDATE operational_failure_intents SET state='forward-pending',owner_id=NULL,claim_token=NULL,lease_expires_at=NULL,outcome_json=?,last_error=?,updated_at=? WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (_dump_wire(outcome or {}), error, now, round_id, owner_id, claim_token))
                if updated.rowcount != 1:
                    raise ValueError("operational failure claim is unavailable")
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        record = self.operational_failure_intent(round_id)
        if record is None:
            raise ValueError("operational failure intent is missing")
        return record

    @staticmethod
    def _round_request_digest(request: Mapping[str, Any]) -> str:
        return hashlib.sha256(_dump_wire(request).encode("utf-8")).hexdigest()

    def round_recovery(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT request_digest,capability_hash,idempotency_key,owner_id,claim_token,lease_expires_at,state,attempts,evidence_json,binding_json,updated_at FROM round_recoveries WHERE round_id=?", (round_id,)).fetchone()
        if row is None:
            return None
        return {"roundId": round_id, "requestDigest": row[0], "capabilityHash": row[1], "idempotencyKey": row[2], "ownerId": row[3], "claimToken": row[4], "leaseExpiresAt": row[5], "state": row[6], "attempts": row[7], "evidence": json.loads(row[8]) if row[8] else None, "binding": json.loads(row[9]) if row[9] else None, "updatedAt": row[10]}

    def round_prompt_delivery(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT request_digest,capability_hash,binding_json,phase,prompt_digest,updated_at FROM round_prompt_deliveries WHERE round_id=?", (round_id,)).fetchone()
        if row is None:
            return None
        return {"roundId": round_id, "requestDigest": row[0], "capabilityHash": row[1], "binding": json.loads(row[2]), "phase": row[3], "promptDigest": row[4], "updatedAt": row[5]}

    def record_round_prompt_delivery_phase(self, round_id: str, request: Mapping[str, Any], capability: str, binding: Mapping[str, Any], prompt_digest: str, phase: str, *, now: str, expected_phase: str | None = None) -> dict[str, Any]:
        phases = ("prepared", "paste-intent", "pasted", "submit-intent", "submitted", "confirmed", "unresolved")
        if phase not in phases or not isinstance(prompt_digest, str) or len(prompt_digest) != 64:
            raise ValueError("round prompt delivery phase is invalid")
        request_digest = self._round_request_digest(request)
        capability_hash = _token_hash(capability)
        encoded_binding = _dump_wire(binding)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT request_digest,capability_hash,binding_json,phase,prompt_digest FROM round_prompt_deliveries WHERE round_id=?", (round_id,)).fetchone()
            if row is None:
                self.connection.execute("INSERT INTO round_prompt_deliveries(round_id,request_digest,capability_hash,binding_json,phase,prompt_digest,updated_at) VALUES (?,?,?,?,?,?,?)", (round_id, request_digest, capability_hash, encoded_binding, phase, prompt_digest, now))
            else:
                if (row[0], row[1], row[2], row[4]) != (request_digest, capability_hash, encoded_binding, prompt_digest):
                    raise ValueError("round prompt delivery binding conflict")
                if expected_phase is not None and row[3] != expected_phase:
                    raise ValueError("round prompt delivery predecessor changed")
                if phases.index(phase) < phases.index(str(row[3])):
                    raise ValueError("round prompt delivery phase regressed")
                self.connection.execute("UPDATE round_prompt_deliveries SET phase=?,updated_at=? WHERE round_id=?", (phase, now, round_id))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        result = self.round_prompt_delivery(round_id)
        if result is None:
            raise ValueError("round prompt delivery record is missing")
        return result

    def claim_round_recovery(self, round_id: str, request: Mapping[str, Any], capability: str, *, owner_id: str, lease_expires_at: str, now: str) -> bool:
        if not all(isinstance(value, str) and value.strip() for value in (round_id, capability, owner_id, lease_expires_at, now)):
            raise ValueError("round recovery claim identity is invalid")
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT request_json,capability_hash,capability_token,dispatch_state FROM rounds WHERE round_id=?", (round_id,)).fetchone()
            if row is None or json.loads(row[0]) != dict(request) or row[1] != _token_hash(capability) or row[2] != capability:
                raise ValueError("round recovery request or capability binding is invalid")
            if row[3] != "started":
                raise ValueError("only a started round can be recovered")
            request_digest = self._round_request_digest(request)
            idempotency_key = str(request.get("idempotencyKey", ""))
            existing = self.connection.execute("SELECT request_digest,capability_hash,idempotency_key,owner_id,claim_token,lease_expires_at,state FROM round_recoveries WHERE round_id=?", (round_id,)).fetchone()
            if existing is None:
                self.connection.execute("INSERT INTO round_recoveries(round_id,request_digest,capability_hash,idempotency_key,owner_id,claim_token,lease_expires_at,state,attempts,updated_at) VALUES (?,?,?,?,?,?,?, ?,1,?)", (round_id, request_digest, row[1], idempotency_key, owner_id, secrets.token_urlsafe(32), lease_expires_at, "claimed", now))
                acquired = True
            else:
                if existing[:3] != (request_digest, row[1], idempotency_key):
                    raise ValueError("round recovery binding conflict")
                if existing[6] == "completed":
                    acquired = False
                elif existing[3] and existing[5] and datetime.fromisoformat(str(existing[5]).replace("Z", "+00:00")) > datetime.fromisoformat(now.replace("Z", "+00:00")):
                    acquired = False
                else:
                    self.connection.execute("UPDATE round_recoveries SET owner_id=?,claim_token=?,lease_expires_at=?,state='claimed',attempts=attempts+1,updated_at=? WHERE round_id=?", (owner_id, secrets.token_urlsafe(32), lease_expires_at, now, round_id))
                    acquired = True
            self.connection.execute("COMMIT")
            return acquired
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def record_round_recovery_attempt(self, round_id: str, owner_id: str, claim_token: str, evidence: Mapping[str, Any], *, now: str) -> dict[str, Any]:
        encoded = _dump_wire(evidence)
        cursor = self.connection.execute("UPDATE round_recoveries SET state='uncertain',owner_id=NULL,claim_token=NULL,lease_expires_at=NULL,evidence_json=?,updated_at=? WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (encoded, now, round_id, owner_id, claim_token))
        if cursor.rowcount != 1:
            raise ValueError("round recovery claim is unavailable")
        result = self.round_recovery(round_id)
        if result is None:
            raise ValueError("round recovery record is missing")
        return result

    def mark_round_recovery_attempted(self, round_id: str, owner_id: str, claim_token: str, evidence: Mapping[str, Any], *, now: str) -> dict[str, Any]:
        encoded = _dump_wire(evidence)
        cursor = self.connection.execute("UPDATE round_recoveries SET evidence_json=?,updated_at=? WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (encoded, now, round_id, owner_id, claim_token))
        if cursor.rowcount != 1:
            raise ValueError("round recovery claim is unavailable")
        result = self.round_recovery(round_id)
        if result is None:
            raise ValueError("round recovery record is missing")
        return result

    def bind_round_recovery(self, round_id: str, owner_id: str, claim_token: str, binding: Mapping[str, Any]) -> dict[str, Any]:
        encoded = _dump_wire(binding)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT binding_json FROM round_recoveries WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (round_id, owner_id, claim_token)).fetchone()
            if row is None:
                raise ValueError("round recovery claim is unavailable")
            if row[0] is not None and row[0] != encoded:
                raise ValueError("round recovery rollout identity changed")
            if row[0] is None:
                self.connection.execute("UPDATE round_recoveries SET binding_json=?,updated_at=? WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (encoded, self._now(), round_id, owner_id, claim_token))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        result = self.round_recovery(round_id)
        if result is None:
            raise ValueError("round recovery record is missing")
        return result

    def complete_round_recovery(self, round_id: str, owner_id: str, claim_token: str, evidence: Mapping[str, Any], *, now: str) -> dict[str, Any]:
        encoded = _dump_wire(evidence)
        cursor = self.connection.execute("UPDATE round_recoveries SET state='completed',owner_id=NULL,claim_token=NULL,lease_expires_at=NULL,evidence_json=?,updated_at=? WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (encoded, now, round_id, owner_id, claim_token))
        if cursor.rowcount != 1:
            existing = self.round_recovery(round_id)
            if existing is None or existing["state"] != "completed":
                raise ValueError("round recovery claim is unavailable")
        result = self.round_recovery(round_id)
        if result is None:
            raise ValueError("round recovery record is missing")
        return result

    def complete_round_recovery_dispatch(self, round_id: str, owner_id: str, claim_token: str, receipt: Mapping[str, Any], evidence: Mapping[str, Any], *, now: str) -> dict[str, Any]:
        """Atomically commit the guarded dispatch and its recovery evidence."""
        encoded_receipt = _dump_wire(receipt)
        encoded_evidence = _dump_wire(evidence)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            recovery = self.connection.execute("SELECT lease_expires_at FROM round_recoveries WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (round_id, owner_id, claim_token)).fetchone()
            if recovery is None or not recovery[0] or datetime.fromisoformat(str(recovery[0]).replace("Z", "+00:00")) <= datetime.fromisoformat(now.replace("Z", "+00:00")):
                raise ValueError("round recovery claim is unavailable")
            round_update = self.connection.execute("UPDATE rounds SET dispatch_state='dispatched',receipt_json=? WHERE round_id=? AND dispatch_state='started' AND result_json IS NULL", (encoded_receipt, round_id))
            if round_update.rowcount != 1:
                raise ValueError("started round state changed")
            delivery = self.connection.execute("SELECT phase FROM round_prompt_deliveries WHERE round_id=?", (round_id,)).fetchone()
            if delivery is not None and delivery[0] != "confirmed":
                raise ValueError("round prompt delivery is not confirmed")
            recovery_update = self.connection.execute("UPDATE round_recoveries SET state='completed',owner_id=NULL,claim_token=NULL,lease_expires_at=NULL,evidence_json=?,updated_at=? WHERE round_id=? AND owner_id=? AND claim_token=? AND state='claimed'", (encoded_evidence, now, round_id, owner_id, claim_token))
            if recovery_update.rowcount != 1:
                raise ValueError("round recovery claim is unavailable")
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        result = self.round_recovery(round_id)
        if result is None:
            raise ValueError("round recovery record is missing")
        return result

    def round_for_capability(self, capability: str):
        row = self.connection.execute("SELECT request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded FROM rounds WHERE capability_hash=?", (_token_hash(capability),)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), row[2], row[3], row[4], json.loads(row[5]) if row[5] else None, bool(row[6]))

    def record_result(self, round_id: str, result: Mapping[str, Any], completed_at: str | None = None) -> None:
        self.connection.execute("UPDATE rounds SET result_json=?,completed_at=COALESCE(completed_at,?) WHERE round_id=? AND result_json IS NULL", (_dump_wire(result), completed_at or result.get("occurredAt"), round_id))

    def round_timing(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT canary_authorization_id,started_at,completed_at FROM rounds WHERE round_id=?", (round_id,)).fetchone()
        if row is None:
            return None
        return {"authorizationId": row[0], "startedAt": row[1], "completedAt": row[2]}

    def mark_forwarded(self, round_id: str) -> None:
        self.connection.execute("UPDATE rounds SET result_forwarded=1 WHERE round_id=?", (round_id,))

    def record_decision(self, request: Mapping[str, Any], receipt: Mapping[str, Any]) -> None:
        self.connection.execute("INSERT OR IGNORE INTO decisions VALUES (?,?,?,'staged',NULL,NULL,NULL)", (request["decisionId"], _dump(request), _dump(receipt)))

    def stage_external_decision(self, request: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
        decision_id = str(request.get("decisionId", ""))
        reconciliation_id = decision_id.removeprefix("roadex:external:")
        workflow_id = request.get("workflowId")
        required = {
            "decisionId": decision_id,
            "projectId": request.get("projectId"),
            "planId": request.get("planId"),
            "decisionVersion": request.get("decisionVersion"),
            "correlationId": request.get("correlationId"),
            "idempotencyKey": request.get("idempotencyKey"),
            "question": request.get("question"),
            "resultProvenanceId": request.get("resultProvenanceId"),
        }
        if not isinstance(workflow_id, str) or not workflow_id.strip() or any(not isinstance(value, str) or not value for value in required.values()):
            raise ValueError("external decision identity conflict")
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            external = self.external_execution(reconciliation_id)
            if external is None or external.get("gateDecisionId") != decision_id:
                raise ValueError("external decision identity conflict")
            envelope = external["payload"]
            expected = {
                "decisionId": decision_id,
                "projectId": envelope["projectId"],
                "planId": envelope["planId"],
                "decisionVersion": envelope["planVersion"],
                "correlationId": envelope["correlationId"],
                "idempotencyKey": f"roadex:external:{envelope['idempotencyKey']}",
                "question": envelope["explicitGate"],
                "resultProvenanceId": envelope["digest"],
            }
            if set(request) != set(expected) | {"workflowId"}:
                raise ValueError("external decision identity conflict")
            if any(request.get(field) != value for field, value in expected.items()):
                raise ValueError("external decision identity conflict")
            if external.get("gateWorkflowId") not in {None, workflow_id}:
                raise ValueError("external decision workflow conflict")
            existing = self.decision(decision_id)
            if existing is not None:
                if existing[0] != dict(request):
                    raise ValueError("external decision identity conflict")
                self.connection.execute("UPDATE external_executions SET gate_workflow_id=? WHERE reconciliation_id=?", (workflow_id, reconciliation_id))
                return {"accepted": True, "receipt": existing[1]}
            self.connection.execute("INSERT INTO decisions VALUES (?,?,?,'staged',NULL,NULL,NULL)", (decision_id, _dump(request), _dump(receipt)))
            self.connection.execute("UPDATE external_executions SET gate_workflow_id=? WHERE reconciliation_id=?", (workflow_id, reconciliation_id))
        return {"accepted": True, "receipt": dict(receipt)}

    def decision(self, decision_id: str):
        row = self.connection.execute("SELECT request_json,receipt_json,status FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]), str(row[2]))

    def list_staged_decisions(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT request_json,receipt_json,status FROM decisions WHERE status='staged' ORDER BY rowid").fetchall()
        return [{"request": json.loads(row[0]), "receipt": json.loads(row[1]), "status": row[2]} for row in rows]

    def decide(self, decision_id: str, status: str, decided_by: str, decided_at: str, reason: str) -> None:
        cursor = self.connection.execute("UPDATE decisions SET status=?,decided_by=?,decided_at=?,reason=? WHERE decision_id=? AND status='staged'", (status, decided_by, decided_at, reason, decision_id))
        if cursor.rowcount != 1:
            raise ValueError("an exact staged Psychlo decision is required")

    def decision_intent(self, decision_id: str):
        row = self.connection.execute("SELECT request_json,outcome_json,status,decided_by,decided_at,reason FROM decision_intents WHERE decision_id=?", (decision_id,)).fetchone()
        if row is None:
            return None
        return {"request": json.loads(row[0]), "outcome": json.loads(row[1]), "status": row[2], "decidedBy": row[3], "decidedAt": row[4], "reason": row[5]}

    def pending_decision_intents(self) -> list[str]:
        return [str(row[0]) for row in self.connection.execute("SELECT decision_id FROM decision_intents WHERE status='pending' ORDER BY updated_at, decision_id").fetchall()]

    def record_decision_intent(self, request: Mapping[str, Any], outcome: Mapping[str, Any], decided_by: str, decided_at: str, reason: str) -> dict[str, Any]:
        decision_id = str(request["decisionId"])
        existing = self.decision_intent(decision_id)
        if existing is not None:
            if existing["request"] != dict(request) or existing["outcome"] != dict(outcome) or existing["decidedBy"] != decided_by or existing["reason"] != reason:
                raise ValueError("external decision conflict")
            return existing
        self.connection.execute("INSERT INTO decision_intents VALUES (?,?,?,?,?,?,?,?)", (decision_id, _dump(request), _dump(outcome), "pending", decided_by, decided_at, reason, self._now()))
        return self.decision_intent(decision_id)

    def settle_external_decision(self, decision_id: str, status: str, decided_by: str, decided_at: str, reason: str, reconciliation_id: str) -> dict[str, Any]:
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            decision_row = self.connection.execute("SELECT status FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
            if decision_row is None:
                raise ValueError("an exact staged Psychlo decision is required")
            if decision_row[0] not in {"staged", status}:
                raise ValueError("external decision conflict")
            external = self.external_execution(reconciliation_id)
            if external is None or external.get("gateDecisionId") != decision_id:
                raise ValueError("external decision identity conflict")
            request_row = self.connection.execute("SELECT request_json FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
            if external.get("gateWorkflowId") is None or request_row is None or json.loads(request_row[0]).get("workflowId") != external["gateWorkflowId"]:
                raise ValueError("external decision workflow conflict")
            prior = external["receipt"].get("decisionStatus")
            if prior not in {None, "pending", "stage-pending", status}:
                raise ValueError("external decision conflict")
            receipt = {**external["receipt"], "decisionId": decision_id, "decisionStatus": status, "status": status}
            self.connection.execute("UPDATE decisions SET status=?,decided_by=?,decided_at=?,reason=? WHERE decision_id=? AND status='staged'", (status, decided_by, decided_at, reason, decision_id))
            self.connection.execute("UPDATE external_executions SET receipt_json=?,status=? WHERE reconciliation_id=?", (_dump(receipt), status, reconciliation_id))
            self.connection.execute("UPDATE decision_intents SET status='settled',updated_at=? WHERE decision_id=?", (self._now(), decision_id))
        return {"decision": self.decision(decision_id), "external": self.external_execution(reconciliation_id)}

    def project(self, project_id: str):
        row = self.connection.execute("SELECT registration_json,scheduling_json FROM projects WHERE project_id=?", (project_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]))

    def record_project(self, project_id: str, registration: Mapping[str, Any], scheduling: Mapping[str, Any]) -> None:
        self.connection.execute("INSERT INTO projects VALUES (?,?,?)", (project_id, _dump(registration), _dump(scheduling)))

    def replace_project(
        self,
        project_id: str,
        expected_registration: Mapping[str, Any],
        registration: Mapping[str, Any],
        scheduling: Mapping[str, Any],
        deliver: Callable[[], None],
    ) -> bool:
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT registration_json FROM projects WHERE project_id=?",
                (project_id,),
            ).fetchone()
            if row is None:
                raise ValueError("project registration conflict")
            current = json.loads(row[0])
            if current == dict(registration):
                return False
            if current != dict(expected_registration):
                raise ValueError("project registration conflict")
            deliver()
            updated = self.connection.execute(
                "UPDATE projects SET registration_json=?,scheduling_json=? WHERE project_id=? AND registration_json=?",
                (_dump(registration), _dump(scheduling), project_id, _dump(expected_registration)),
            )
            if updated.rowcount != 1:
                raise ValueError("project registration conflict")
            return True

    def telemetry_checkpoint(self, checkpoint_id: str):
        row = self.connection.execute("SELECT payload_json FROM telemetry_checkpoints WHERE checkpoint_id=?", (checkpoint_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def telemetry_digest(self, checkpoint_id: str) -> str | None:
        row = self.connection.execute("SELECT digest FROM telemetry_checkpoints WHERE checkpoint_id=?", (checkpoint_id,)).fetchone()
        return None if row is None else str(row[0])

    def telemetry_stream(self, round_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload_json FROM telemetry_checkpoints WHERE round_id=? ORDER BY rowid", (round_id,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def record_telemetry(self, checkpoint: Mapping[str, Any], digest: str) -> bool:
        try:
            self.connection.execute("INSERT INTO telemetry_checkpoints VALUES (?,?,?,?,?)", (checkpoint["checkpointId"], checkpoint["roundId"], _dump(checkpoint), digest, self._now()))
            return True
        except sqlite3.IntegrityError:
            existing = self.telemetry_checkpoint(str(checkpoint["checkpointId"]))
            if existing == dict(checkpoint) or self.telemetry_digest(str(checkpoint["checkpointId"])) == digest:
                return False
            raise ValueError("telemetry checkpoint conflict")

    def _quarantine_learning(self, observation_id: str, error: str) -> None:
        with self.connection:
            self.connection.execute("UPDATE learning_observations SET state='corrupt',delivery_skiller='corrupt',delivery_memory='corrupt',last_error_skiller=?,last_error_memory=?,updated_at=? WHERE observation_id=?", (error, error, self._now(), observation_id))

    def learning_observation(self, observation_id: str):
        row = self.connection.execute("SELECT payload_json,digest,state,attempts_skiller,attempts_memory,last_error_skiller,last_error_memory,delivery_skiller,delivery_memory FROM learning_observations WHERE observation_id=?", (observation_id,)).fetchone()
        if row is None:
            return None
        if row[2] == "corrupt" or row[7] == "corrupt" or row[8] == "corrupt":
            return None
        try:
            payload = json.loads(row[0])
            observation = parse_learning_observation(payload)
            if observation["id"] != observation_id:
                raise ValueError("learning observation identity conflict")
            wire_digest = learning_observation_digest(observation)
            legacy_selected_digest = learning_observation_legacy_selected_digest(observation)
            legacy_digest = canonical_digest(observation)
            if row[1] not in {wire_digest, legacy_selected_digest, legacy_digest}:
                raise ValueError("learning observation digest conflict")
        except (ContractError, TypeError, ValueError, json.JSONDecodeError):
            self._quarantine_learning(observation_id, "learning-observation-integrity-failed")
            return None
        payload.update({"digest": row[1], "state": row[2], "attempts": {"skiller": row[3], "private-memory": row[4]}, "deliveries": {"skiller": row[7], "private-memory": row[8]}, "lastError": {key: value for key, value in (("skiller", row[5]), ("private-memory", row[6])) if value}})
        return payload

    def record_learning(self, observation: Mapping[str, Any], digest: str) -> bool:
        try:
            self.connection.execute("INSERT INTO learning_observations(observation_id,payload_json,digest,state,updated_at) VALUES (?,?,?,'queued',?)", (observation["id"], _dump(observation), digest, self._now()))
            return True
        except sqlite3.IntegrityError:
            existing = self.learning_observation(str(observation["id"]))
            if existing and existing["digest"] == digest and {key: value for key, value in existing.items() if key not in {"digest", "state", "attempts", "lastError", "deliveries"}} == dict(observation):
                return False
            raise ValueError("learning observation conflict")

    def pending_learning(self, destination: str, limit: int = 100) -> list[dict[str, Any]]:
        column = "attempts_skiller" if destination == "skiller" else "attempts_memory"
        delivery = "delivery_skiller" if destination == "skiller" else "delivery_memory"
        rows = self.connection.execute(f"SELECT observation_id FROM learning_observations WHERE {delivery} NOT IN ('delivered','corrupt') ORDER BY rowid LIMIT ?", (max(1, min(100, int(limit))),)).fetchall()
        return [observation for row in rows if (observation := self.learning_observation(row[0])) is not None]

    def transition_learning(self, observation_id: str, destination: str, state: str, error: str | None = None) -> dict[str, Any]:
        column = "attempts_skiller" if destination == "skiller" else "attempts_memory"
        error_column = "last_error_skiller" if destination == "skiller" else "last_error_memory"
        delivery_column = "delivery_skiller" if destination == "skiller" else "delivery_memory"
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute(f"UPDATE learning_observations SET {column}={column}+1,{error_column}=?,{delivery_column}=?,state=CASE WHEN delivery_skiller='delivered' AND delivery_memory='delivered' THEN 'delivered' ELSE ? END,updated_at=? WHERE observation_id=?", (error, state, state, self._now(), observation_id))
        result = self.learning_observation(observation_id)
        if result is None:
            raise ValueError("learning observation was not found")
        return result

    def learning_advisory(self, digest: str):
        row = self.connection.execute("SELECT payload_json FROM learning_advisories WHERE digest=?", (digest,)).fetchone()
        return None if row is None else json.loads(row[0])

    def record_learning_advisory(self, advisory: Mapping[str, Any]) -> None:
        self.connection.execute("INSERT OR IGNORE INTO learning_advisories VALUES (?,?)", (advisory["digest"], _dump(advisory)))

    def registry_candidate(self, candidate_id: str):
        row = self.connection.execute("SELECT payload_json FROM registry_candidates WHERE candidate_id=?", (candidate_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def record_registry(self, candidate: Mapping[str, Any], digest: str) -> bool:
        try:
            self.connection.execute("INSERT INTO registry_candidates VALUES (?,?,?,?)", (candidate["candidateId"], _dump(candidate), digest, self._now()))
            return True
        except sqlite3.IntegrityError:
            existing = self.registry_candidate(str(candidate["candidateId"]))
            if existing == dict(candidate):
                return False
            raise ValueError("registry candidate conflict")

    def adoption_evidence(self, assessment_id: str):
        row = self.connection.execute("SELECT payload_json FROM adoption_evidence WHERE assessment_id=?", (assessment_id,)).fetchone()
        return None if row is None else json.loads(row[0])

    def record_adoption(self, assessment_id: str, candidate_id: str, evidence: Mapping[str, Any], digest: str) -> bool:
        try:
            self.connection.execute("INSERT INTO adoption_evidence VALUES (?,?,?,?,?)", (assessment_id, candidate_id, _dump(evidence), digest, self._now()))
            return True
        except sqlite3.IntegrityError:
            existing = self.adoption_evidence(assessment_id)
            if existing == dict(evidence):
                return False
            raise ValueError("adoption evidence conflict")

    def external_execution(self, reconciliation_id: str):
        row = self.connection.execute("SELECT payload_json,digest,receipt_json,status,forwarded,gate_decision_id,gate_workflow_id FROM external_executions WHERE reconciliation_id=?", (reconciliation_id,)).fetchone()
        if row is None:
            return None
        return {"payload": json.loads(row[0]), "digest": row[1], "receipt": json.loads(row[2]), "status": row[3], "forwarded": bool(row[4]), "gateDecisionId": row[5], "gateWorkflowId": row[6]}

    def record_external(self, payload: Mapping[str, Any], digest: str, receipt: Mapping[str, Any], gate_decision_id: str | None) -> bool:
        try:
            self.connection.execute("INSERT INTO external_executions(reconciliation_id,external_execution_id,idempotency_key,payload_json,digest,receipt_json,status,forwarded,gate_decision_id,gate_workflow_id,inserted_at) VALUES (?,?,?,?,?,?,'reconciled',0,?,NULL,?)", (payload["reconciliationId"], payload["externalExecutionId"], payload["idempotencyKey"], _dump(payload), digest, _dump(receipt), gate_decision_id, self._now()))
            return True
        except sqlite3.IntegrityError:
            existing = self.external_execution(str(payload["reconciliationId"]))
            if existing and existing["digest"] == digest and existing["payload"] == dict(payload):
                return False
            raise ValueError("external round conflict")

    def link_external_gate(self, reconciliation_id: str, decision_id: str, workflow_id: str) -> None:
        record = self.external_execution(reconciliation_id)
        if record is None or record.get("gateDecisionId") != decision_id:
            raise ValueError("external decision identity conflict")
        if not isinstance(workflow_id, str) or not workflow_id.strip():
            raise ValueError("external decision workflow is invalid")
        if record.get("gateWorkflowId") not in {None, workflow_id}:
            raise ValueError("external decision workflow conflict")
        self.connection.execute("UPDATE external_executions SET gate_workflow_id=? WHERE reconciliation_id=?", (workflow_id, reconciliation_id))

    def mark_external_forwarded(self, reconciliation_id: str, status: str = "reconciled") -> None:
        record = self.external_execution(reconciliation_id)
        receipt = dict(record["receipt"])
        receipt["status"] = status
        self.connection.execute("UPDATE external_executions SET forwarded=1,status=?,receipt_json=? WHERE reconciliation_id=?", (status, _dump(receipt), reconciliation_id))

    def update_external_receipt(self, reconciliation_id: str, receipt: Mapping[str, Any], *, status: str | None = None) -> None:
        self.connection.execute("UPDATE external_executions SET receipt_json=?,status=? WHERE reconciliation_id=?", (_dump(receipt), status or str(receipt.get("status", "reconciled")), reconciliation_id))

    def external_gate_pending(self, project_id: str) -> bool:
        rows = self.connection.execute("SELECT payload_json,receipt_json FROM external_executions WHERE status NOT IN ('approved','rejected','expired')").fetchall()
        for payload_json, receipt_json in rows:
            payload = json.loads(payload_json); receipt = json.loads(receipt_json)
            if payload.get("projectId") == project_id and payload.get("explicitGate") and receipt.get("decisionStatus") not in {"approved", "rejected", "expired"}:
                return True
        return False

    def external_gate_blocked(self, project_id: str) -> bool:
        rows = self.connection.execute("SELECT payload_json,receipt_json FROM external_executions WHERE status IN ('rejected','expired')").fetchall()
        for payload_json, receipt_json in rows:
            payload = json.loads(payload_json); receipt = json.loads(receipt_json)
            if payload.get("projectId") == project_id and payload.get("explicitGate") and receipt.get("decisionStatus") in {"rejected", "expired"}:
                return True
        return False

    def projection_counts(self) -> dict[str, int]:
        return {name: int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for name, table in (("telemetry", "telemetry_checkpoints"), ("learning", "learning_observations"), ("registry", "registry_candidates"), ("adoption", "adoption_evidence"), ("external", "external_executions"))}

    def protocol_record(self, kind: str, record_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT idempotency_key,digest,payload_json,state,attempts,last_error,updated_at,receipt_json FROM protocol_records WHERE kind=? AND record_id=?", (kind, record_id)).fetchone()
        if row is None: return None
        return {"kind": kind, "id": record_id, "idempotencyKey": row[0], "digest": row[1], "payload": json.loads(row[2]), "state": row[3], "attempts": row[4], "lastError": row[5], "updatedAt": row[6], "receipt": json.loads(row[7]) if row[7] else None}

    def list_protocol(self, kind: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind=? ORDER BY updated_at,record_id LIMIT ?", (kind, max(1, min(1000, int(limit))))).fetchall()
        return [self.protocol_record(kind, str(row[0])) for row in rows]

    def protocol_records_for_ids(self, kind: str, record_ids: list[str]) -> dict[str, dict[str, Any]]:
        ids = list(dict.fromkeys(record_ids))
        if not ids:
            return {}
        if len(ids) > 64 or any(not isinstance(item, str) or not item.strip() for item in ids):
            raise ValueError("protocol record scope is invalid")
        placeholders = ",".join("?" for _ in ids)
        rows = self.connection.execute(f"SELECT record_id FROM protocol_records WHERE kind=? AND record_id IN ({placeholders})", (kind, *ids)).fetchall()
        return {str(row[0]): self.protocol_record(kind, str(row[0])) for row in rows}

    def coordination_requests_for_link(self, link_id: str, version: str) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind='coordination-work-request' AND json_extract(payload_json,'$.linkId')=? AND json_extract(payload_json,'$.version')=? ORDER BY record_id", (link_id, version)).fetchall()
        return [self.protocol_record("coordination-work-request", str(row[0])) for row in rows]

    def coordination_participant_terminal(self, request_id: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT result_id,digest,payload_json FROM coordination_terminals WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            return None
        record = self.protocol_record("cross-project-participant-result", str(row[0]))
        if record is None or record["digest"] != row[1] or record["payload"] != json.loads(row[2]) or record["payload"].get("requestId") != request_id:
            raise ValueError("participant result terminal record is invalid")
        return record

    def record_protocol(self, kind: str, record_id: str, idempotency_key: str, digest: str, payload: Mapping[str, Any], *, state: str = "queued") -> tuple[dict[str, Any], bool]:
        existing = self.protocol_record(kind, record_id)
        if existing is not None:
            if existing["digest"] != digest or existing["payload"] != dict(payload): raise ValueError(f"{kind} conflict")
            return existing, False
        by_key = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind=? AND idempotency_key=?", (kind, idempotency_key)).fetchone()
        if by_key is not None and by_key[0] != record_id: raise ValueError(f"{kind} idempotency conflict")
        try:
            self.connection.execute("INSERT INTO protocol_records(kind,record_id,idempotency_key,digest,payload_json,state,updated_at,receipt_json) VALUES (?,?,?,?,?,?,?,NULL)", (kind, record_id, idempotency_key, digest, _dump_wire(payload), state, self._now()))
        except sqlite3.IntegrityError as error:
            winner = self.protocol_record(kind, record_id)
            if winner is not None and winner["digest"] == digest and winner["payload"] == dict(payload):
                return winner, False
            raise ValueError(f"{kind} conflict") from error
        return self.protocol_record(kind, record_id), True

    def record_coordination_participant_terminal(self, request_id: str, result_id: str, idempotency_key: str, digest: str, payload: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
        """Atomically admit the one immutable terminal result for a work request."""
        if payload.get("requestId") != request_id or payload.get("resultId") != result_id:
            raise ValueError("participant result terminal binding is invalid")
        encoded = _dump_wire(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            terminal = self.connection.execute("SELECT result_id,digest,payload_json FROM coordination_terminals WHERE request_id=?", (request_id,)).fetchone()
            if terminal is not None:
                if terminal != (result_id, digest, encoded):
                    raise ValueError("participant result terminal conflict")
                inserted = False
            else:
                conflict = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind='cross-project-participant-result' AND (record_id=? OR idempotency_key=?)", (result_id, idempotency_key)).fetchone()
                if conflict is not None:
                    raise ValueError("participant result terminal conflict")
                self.connection.execute("INSERT INTO protocol_records(kind,record_id,idempotency_key,digest,payload_json,state,updated_at,receipt_json) VALUES ('cross-project-participant-result',?,?,?,?, 'queued',?,NULL)", (result_id, idempotency_key, digest, encoded, self._now()))
                self.connection.execute("INSERT INTO coordination_terminals VALUES (?,?,?,?,?)", (request_id, result_id, digest, encoded, self._now()))
                inserted = True
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        record = self.protocol_record("cross-project-participant-result", result_id)
        if record is None:
            raise ValueError("participant result terminal record is missing")
        return record, inserted

    def transition_protocol(self, kind: str, record_id: str, state: str, error: str | None = None, receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
        with self.connection:
            if receipt is None:
                self.connection.execute("UPDATE protocol_records SET state=?,attempts=attempts+1,last_error=?,updated_at=? WHERE kind=? AND record_id=?", (state, error, self._now(), kind, record_id))
            else:
                self.connection.execute("UPDATE protocol_records SET state=?,attempts=attempts+1,last_error=?,updated_at=?,receipt_json=? WHERE kind=? AND record_id=?", (state, error, self._now(), _dump_wire(receipt), kind, record_id))
        result = self.protocol_record(kind, record_id)
        if result is None: raise ValueError("protocol record is missing")
        return result

    def pending_protocol(self, kind: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind=? AND state NOT IN ('delivered','settled','rejected') ORDER BY updated_at,record_id LIMIT ?", (kind, max(1, min(100, int(limit))))).fetchall()
        return [self.protocol_record(kind, row[0]) for row in rows]


def _token_hash(token: str) -> str:
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
