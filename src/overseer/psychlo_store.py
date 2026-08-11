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

from .psychlo_contracts import canonical_digest, learning_observation_digest, learning_observation_legacy_selected_digest, parse_canary_authorization, parse_concurrency_canary_result, parse_concurrency_ceiling_authorization, parse_learning_observation, ContractError


def _round_result_digest(result: Mapping[str, Any]) -> str:
    fields = ("roundId", "projectId", "projectLeadId", "planId", "planVersion", "threadId", "model", "featureClass", "correlationId", "idempotencyKey", "snapshotId", "policyVersion", "expectedUsageCost", "scope", "selectionReason", "priorityRationale", "sourceId", "provenanceId", "status", "actualUsageCost", "deliveredScope", "remainingEstimate", "blockers", "questions", "reachedExplicitGates", "occurredAt")
    import hashlib
    return hashlib.sha256(json.dumps({key: result[key] for key in fields if key in result}, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


def _dump(value: Mapping[str, Any]) -> str:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"))


def _dump_wire(value: Mapping[str, Any]) -> str:
    """Retain authenticated contract insertion order for cross-language digests."""
    return json.dumps(dict(value), ensure_ascii=False, separators=(",", ":"))


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
            CREATE TABLE IF NOT EXISTS decision_intents(decision_id TEXT PRIMARY KEY, request_json TEXT NOT NULL, outcome_json TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT NOT NULL, decided_at TEXT NOT NULL, reason TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS projects(project_id TEXT PRIMARY KEY, registration_json TEXT NOT NULL, scheduling_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS telemetry_checkpoints(checkpoint_id TEXT PRIMARY KEY, round_id TEXT NOT NULL, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS learning_observations(observation_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, state TEXT NOT NULL, attempts_skiller INTEGER NOT NULL DEFAULT 0, attempts_memory INTEGER NOT NULL DEFAULT 0, last_error_skiller TEXT, last_error_memory TEXT, delivery_skiller TEXT NOT NULL DEFAULT 'pending', delivery_memory TEXT NOT NULL DEFAULT 'pending', updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS learning_advisories(digest TEXT PRIMARY KEY, payload_json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS registry_candidates(candidate_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS adoption_evidence(assessment_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS external_executions(reconciliation_id TEXT PRIMARY KEY, external_execution_id TEXT NOT NULL UNIQUE, idempotency_key TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, digest TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL, status TEXT NOT NULL, forwarded INTEGER NOT NULL DEFAULT 0, gate_decision_id TEXT, gate_workflow_id TEXT, inserted_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS protocol_records(kind TEXT NOT NULL, record_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT, updated_at TEXT NOT NULL, PRIMARY KEY(kind, record_id), UNIQUE(kind, idempotency_key), UNIQUE(kind, digest));
            CREATE TABLE IF NOT EXISTS approval_authority_snapshots(approval_id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS coordination_dispatches(request_id TEXT PRIMARY KEY, dispatch_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, owner_id TEXT, idempotency_key TEXT);
            CREATE TABLE IF NOT EXISTS coordination_reviews(request_id TEXT PRIMARY KEY, review_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, owner_id TEXT, idempotency_key TEXT);
            CREATE TABLE IF NOT EXISTS coordination_operation_claims(kind TEXT NOT NULL, operation_id TEXT NOT NULL, owner_id TEXT, lease_expires_at TEXT, attempts INTEGER NOT NULL DEFAULT 0, idempotency_key TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(kind, operation_id), UNIQUE(kind, idempotency_key));
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

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

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
        row = self.connection.execute("SELECT round_id FROM rounds WHERE result_json IS NULL LIMIT 1").fetchone()
        return None if row is None else str(row[0])

    def active_rounds(self) -> list[dict[str, Any]]:
        """Return the immutable request identity for every unfinished round."""
        rows = self.connection.execute("SELECT request_json FROM rounds WHERE result_json IS NULL ORDER BY rowid").fetchall()
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
            rows = self.connection.execute("SELECT request_json FROM rounds WHERE result_json IS NULL ORDER BY rowid").fetchall()
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
            active = [json.loads(row[0]) for row in self.connection.execute("SELECT request_json FROM rounds WHERE result_json IS NULL ORDER BY rowid").fetchall()]
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
            if self.connection.execute("SELECT 1 FROM rounds WHERE result_json IS NULL LIMIT 1").fetchone() is not None:
                raise ValueError("single_stream_busy")
            self.connection.execute("INSERT INTO rounds(round_id,request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded) VALUES (?,?,?,?,?,'pending',NULL,0)", (request["roundId"], _dump_wire(request), _dump_wire(receipt), _token_hash(capability), capability))
            self.connection.execute("COMMIT")
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def record_round(self, request: Mapping[str, Any], receipt: Mapping[str, Any], capability: str) -> None:
        self.connection.execute("INSERT INTO rounds(round_id,request_json,receipt_json,capability_hash,capability_token,dispatch_state,result_json,result_forwarded) VALUES (?,?,?,?,?,'pending',NULL,0)", (request["roundId"], _dump_wire(request), _dump_wire(receipt), _token_hash(capability), capability))

    def mark_dispatch_started(self, round_id: str, started_at: str) -> None:
        self.connection.execute("UPDATE rounds SET dispatch_state='started',started_at=COALESCE(started_at,?) WHERE round_id=? AND dispatch_state='pending'", (started_at, round_id))

    def mark_dispatched(self, round_id: str, receipt: Mapping[str, Any]) -> None:
        self.connection.execute("UPDATE rounds SET dispatch_state='dispatched',receipt_json=? WHERE round_id=?", (_dump_wire(receipt), round_id))

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
        row = self.connection.execute("SELECT idempotency_key,digest,payload_json,state,attempts,last_error,updated_at FROM protocol_records WHERE kind=? AND record_id=?", (kind, record_id)).fetchone()
        if row is None: return None
        return {"kind": kind, "id": record_id, "idempotencyKey": row[0], "digest": row[1], "payload": json.loads(row[2]), "state": row[3], "attempts": row[4], "lastError": row[5], "updatedAt": row[6]}

    def list_protocol(self, kind: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind=? ORDER BY updated_at,record_id LIMIT ?", (kind, max(1, min(1000, int(limit))))).fetchall()
        return [self.protocol_record(kind, str(row[0])) for row in rows]

    def record_protocol(self, kind: str, record_id: str, idempotency_key: str, digest: str, payload: Mapping[str, Any], *, state: str = "queued") -> tuple[dict[str, Any], bool]:
        existing = self.protocol_record(kind, record_id)
        if existing is not None:
            if existing["digest"] != digest or existing["payload"] != dict(payload): raise ValueError(f"{kind} conflict")
            return existing, False
        by_key = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind=? AND idempotency_key=?", (kind, idempotency_key)).fetchone()
        if by_key is not None and by_key[0] != record_id: raise ValueError(f"{kind} idempotency conflict")
        try:
            self.connection.execute("INSERT INTO protocol_records(kind,record_id,idempotency_key,digest,payload_json,state,updated_at) VALUES (?,?,?,?,?,?,?)", (kind, record_id, idempotency_key, digest, _dump_wire(payload), state, self._now()))
        except sqlite3.IntegrityError as error:
            winner = self.protocol_record(kind, record_id)
            if winner is not None and winner["digest"] == digest and winner["payload"] == dict(payload):
                return winner, False
            raise ValueError(f"{kind} conflict") from error
        return self.protocol_record(kind, record_id), True

    def transition_protocol(self, kind: str, record_id: str, state: str, error: str | None = None) -> dict[str, Any]:
        with self.connection:
            self.connection.execute("UPDATE protocol_records SET state=?,attempts=attempts+1,last_error=?,updated_at=? WHERE kind=? AND record_id=?", (state, error, self._now(), kind, record_id))
        result = self.protocol_record(kind, record_id)
        if result is None: raise ValueError("protocol record is missing")
        return result

    def pending_protocol(self, kind: str, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT record_id FROM protocol_records WHERE kind=? AND state NOT IN ('delivered','settled','rejected') ORDER BY updated_at,record_id LIMIT ?", (kind, max(1, min(100, int(limit))))).fetchall()
        return [self.protocol_record(kind, row[0]) for row in rows]


def _token_hash(token: str) -> str:
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
