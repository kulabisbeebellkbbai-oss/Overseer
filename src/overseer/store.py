"""SQLite persistence for local Overseer state."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .audit import ApprovalRequest, AuditEvent
from .core import Claim, ConflictDecision, Resource
from .health import HealthEvidence, HealthTarget
from .physical import PhysicalIdentity
from .serialization import dataclass_from_jsonable, to_jsonable
from .usage_limits import UsageLimit


class SQLiteStore:
    """Small JSON-payload SQLite store for early durable state."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._connection = sqlite3.connect(self.path)
        self._connection.row_factory = sqlite3.Row
        self.initialize()

    def close(self) -> None:
        self._connection.close()

    def initialize(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS resources (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS claims (
                id TEXT PRIMARY KEY,
                resource_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS decisions (
                claim_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS usage_limits (
                id TEXT PRIMARY KEY,
                resource_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS health_evidence (
                id TEXT PRIMARY KEY,
                resource_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS physical_identities (
                stable_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS health_targets (
                id TEXT PRIMARY KEY,
                resource_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """
        )
        self._connection.commit()

    def save_resource(self, resource: Resource) -> None:
        self._upsert("resources", resource.id, _dump(resource))

    def load_resource(self, resource_id: str) -> Resource:
        return _load_dataclass(Resource, self._get_payload("resources", resource_id))

    def list_resources(self) -> tuple[Resource, ...]:
        return tuple(_load_dataclass(Resource, payload) for payload in self._list_payloads("resources"))

    def save_usage_limit(self, usage_limit: UsageLimit) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO usage_limits (id, resource_id, payload) VALUES (?, ?, ?)",
            (usage_limit.id, usage_limit.resource_id, _dump(usage_limit)),
        )
        self._connection.commit()

    def load_usage_limit(self, usage_limit_id: str) -> UsageLimit:
        return _load_dataclass(UsageLimit, self._get_payload("usage_limits", usage_limit_id))

    def list_usage_limits(self) -> tuple[UsageLimit, ...]:
        return tuple(_load_dataclass(UsageLimit, payload) for payload in self._list_payloads("usage_limits"))

    def save_health_evidence(self, evidence: HealthEvidence) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO health_evidence (id, resource_id, payload) VALUES (?, ?, ?)",
            (evidence.id, evidence.resource_id, _dump(evidence)),
        )
        self._connection.commit()

    def load_health_evidence(self, evidence_id: str) -> HealthEvidence:
        return _load_dataclass(HealthEvidence, self._get_payload("health_evidence", evidence_id))

    def list_health_evidence(self) -> tuple[HealthEvidence, ...]:
        return tuple(_load_dataclass(HealthEvidence, payload) for payload in self._list_payloads("health_evidence"))

    def save_health_target(self, target: HealthTarget) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO health_targets (id, resource_id, payload) VALUES (?, ?, ?)",
            (target.id, target.resource_id, _dump(target)),
        )
        self._connection.commit()

    def load_health_target(self, target_id: str) -> HealthTarget:
        return _load_dataclass(HealthTarget, self._get_payload("health_targets", target_id))

    def list_health_targets(self) -> tuple[HealthTarget, ...]:
        return tuple(_load_dataclass(HealthTarget, payload) for payload in self._list_payloads("health_targets"))

    def save_physical_identity(self, identity: PhysicalIdentity) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO physical_identities (stable_id, payload) VALUES (?, ?)",
            (identity.stable_id, _dump(identity)),
        )
        self._connection.commit()

    def load_physical_identity(self, stable_id: str) -> PhysicalIdentity:
        row = self._connection.execute(
            "SELECT payload FROM physical_identities WHERE stable_id = ?",
            (stable_id,),
        ).fetchone()
        if row is None:
            raise KeyError(stable_id)
        return _load_dataclass(PhysicalIdentity, str(row["payload"]))

    def list_physical_identities(self) -> tuple[PhysicalIdentity, ...]:
        rows = self._connection.execute("SELECT payload FROM physical_identities ORDER BY stable_id").fetchall()
        return tuple(_load_dataclass(PhysicalIdentity, str(row["payload"])) for row in rows)

    def save_claim(self, claim: Claim, decision: ConflictDecision | None = None) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO claims (id, resource_id, payload) VALUES (?, ?, ?)",
            (claim.id, claim.resource_id, _dump(claim)),
        )
        if decision is not None:
            self._connection.execute(
                "INSERT OR REPLACE INTO decisions (claim_id, payload) VALUES (?, ?)",
                (claim.id, _dump(decision)),
            )
        self._connection.commit()

    def load_claim(self, claim_id: str) -> Claim:
        return _load_dataclass(Claim, self._get_payload("claims", claim_id))

    def list_claims(self) -> tuple[Claim, ...]:
        return tuple(_load_dataclass(Claim, payload) for payload in self._list_payloads("claims"))

    def load_decision(self, claim_id: str) -> ConflictDecision:
        row = self._connection.execute("SELECT payload FROM decisions WHERE claim_id = ?", (claim_id,)).fetchone()
        if row is None:
            raise KeyError(claim_id)
        return _load_dataclass(ConflictDecision, str(row["payload"]))

    def save_approval(self, approval: ApprovalRequest) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO approvals (id, subject_id, payload) VALUES (?, ?, ?)",
            (approval.id, approval.subject_id, _dump(approval)),
        )
        self._connection.commit()

    def load_approval(self, approval_id: str) -> ApprovalRequest:
        return _load_dataclass(ApprovalRequest, self._get_payload("approvals", approval_id))

    def save_audit_event(self, event: AuditEvent) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO audit_events (id, subject_id, payload) VALUES (?, ?, ?)",
            (event.id, event.subject_id, _dump(event)),
        )
        self._connection.commit()

    def list_audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(_load_dataclass(AuditEvent, payload) for payload in self._list_payloads("audit_events"))

    def _upsert(self, table: str, row_id: str, payload: str) -> None:
        self._connection.execute(f"INSERT OR REPLACE INTO {table} (id, payload) VALUES (?, ?)", (row_id, payload))
        self._connection.commit()

    def _get_payload(self, table: str, row_id: str) -> str:
        row = self._connection.execute(f"SELECT payload FROM {table} WHERE id = ?", (row_id,)).fetchone()
        if row is None:
            raise KeyError(row_id)
        return str(row["payload"])

    def _list_payloads(self, table: str) -> Iterable[str]:
        rows = self._connection.execute(f"SELECT payload FROM {table} ORDER BY id").fetchall()
        return (str(row["payload"]) for row in rows)


def _dump(value: Any) -> str:
    return json.dumps(to_jsonable(value), sort_keys=True, separators=(",", ":"))


def _load_dataclass(cls: type[Any], payload: str) -> Any:
    return dataclass_from_jsonable(cls, json.loads(payload))
