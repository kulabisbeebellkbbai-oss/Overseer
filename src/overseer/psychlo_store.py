"""Private SQLite projections for the Psychlo bridge.

External executions, telemetry, learning, and adoption evidence deliberately
have independent tables.  In particular, an external execution can never
become a normal ``rounds`` row by projection or recovery.
"""

from __future__ import annotations

import json
from pathlib import Path
import os
import sqlite3
import stat
from datetime import UTC, datetime
from typing import Any, Mapping


def _dump(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))


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
            CREATE TABLE IF NOT EXISTS decisions(decision_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at TEXT, reason TEXT);
            CREATE TABLE IF NOT EXISTS projects(project_id TEXT PRIMARY KEY, registration_json TEXT NOT NULL, scheduling_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS telemetry_checkpoints(checkpoint_id TEXT PRIMARY KEY, round_id TEXT NOT NULL, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS learning_observations(observation_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, state TEXT NOT NULL, attempts_skiller INTEGER NOT NULL DEFAULT 0, attempts_memory INTEGER NOT NULL DEFAULT 0, last_error_skiller TEXT, last_error_memory TEXT, delivery_skiller TEXT NOT NULL DEFAULT 'pending', delivery_memory TEXT NOT NULL DEFAULT 'pending', updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS learning_advisories(digest TEXT PRIMARY KEY, payload_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS registry_candidates(candidate_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS adoption_evidence(assessment_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS external_executions(reconciliation_id TEXT PRIMARY KEY, external_execution_id TEXT NOT NULL UNIQUE, idempotency_key TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL, status TEXT NOT NULL, forwarded INTEGER NOT NULL DEFAULT 0, gate_decision_id TEXT, inserted_at TEXT NOT NULL);
        """)
        for column in ("delivery_skiller", "delivery_memory"):
            try:
                self.connection.execute(f"ALTER TABLE learning_observations ADD COLUMN {column} TEXT NOT NULL DEFAULT 'pending'")
            except sqlite3.OperationalError:
                pass

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

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

    def project(self, project_id: str):
        row = self.connection.execute("SELECT registration_json,scheduling_json FROM projects WHERE project_id=?", (project_id,)).fetchone()
        return None if row is None else (json.loads(row[0]), json.loads(row[1]))

    def record_project(self, project_id: str, registration: Mapping[str, Any], scheduling: Mapping[str, Any]) -> None:
        self.connection.execute("INSERT INTO projects VALUES (?,?,?)", (project_id, _dump(registration), _dump(scheduling)))

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

    def learning_observation(self, observation_id: str):
        row = self.connection.execute("SELECT payload_json,digest,state,attempts_skiller,attempts_memory,last_error_skiller,last_error_memory,delivery_skiller,delivery_memory FROM learning_observations WHERE observation_id=?", (observation_id,)).fetchone()
        if row is None:
            return None
        payload = json.loads(row[0]); payload.update({"digest": row[1], "state": row[2], "attempts": {"skiller": row[3], "private-memory": row[4]}, "deliveries": {"skiller": row[7], "private-memory": row[8]}, "lastError": {key: value for key, value in (("skiller", row[5]), ("private-memory", row[6])) if value}})
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
        rows = self.connection.execute(f"SELECT observation_id FROM learning_observations WHERE {delivery} != 'delivered' ORDER BY rowid LIMIT ?", (max(1, min(100, int(limit))),)).fetchall()
        return [self.learning_observation(row[0]) for row in rows]

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
        row = self.connection.execute("SELECT payload_json,digest,receipt_json,status,forwarded,gate_decision_id FROM external_executions WHERE reconciliation_id=?", (reconciliation_id,)).fetchone()
        if row is None:
            return None
        return {"payload": json.loads(row[0]), "digest": row[1], "receipt": json.loads(row[2]), "status": row[3], "forwarded": bool(row[4]), "gateDecisionId": row[5]}

    def record_external(self, payload: Mapping[str, Any], digest: str, receipt: Mapping[str, Any], gate_decision_id: str | None) -> bool:
        try:
            self.connection.execute("INSERT INTO external_executions VALUES (?,?,?,?,?,?,'reconciled',0,?,?)", (payload["reconciliationId"], payload["externalExecutionId"], payload["idempotencyKey"], _dump(payload), digest, _dump(receipt), gate_decision_id, self._now()))
            return True
        except sqlite3.IntegrityError:
            existing = self.external_execution(str(payload["reconciliationId"]))
            if existing and existing["digest"] == digest and existing["payload"] == dict(payload):
                return False
            raise ValueError("external round conflict")

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

    def projection_counts(self) -> dict[str, int]:
        return {name: int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]) for name, table in (("telemetry", "telemetry_checkpoints"), ("learning", "learning_observations"), ("registry", "registry_candidates"), ("adoption", "adoption_evidence"), ("external", "external_executions"))}


def _token_hash(token: str) -> str:
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
