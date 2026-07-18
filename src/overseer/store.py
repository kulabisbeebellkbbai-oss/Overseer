"""SQLite persistence for local Overseer state."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .admin import AdminChangePlan, AdminExecutionResult
from .audit import ApprovalRequest, AuditEvent
from .core import Claim, ConflictDecision, Resource
from .health import HealthEvidence, HealthTarget
from .host import HostInspectionSnapshot
from .ids_review import HostSecurityIDSReviewPackage
from .physical import PhysicalIdentity
from .runtime_state import RuntimeHeartbeat
from .serialization import dataclass_from_jsonable, to_jsonable
from .source_review import HostSecuritySourceReview
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
            CREATE TABLE IF NOT EXISTS runtime_heartbeats (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS host_snapshots (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_change_plans (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_executions (
                id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS host_security_source_reviews (
                id TEXT PRIMARY KEY,
                remote_address TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS host_security_ids_review_packages (
                id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
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

    def delete_health_evidence(self, evidence_id: str) -> None:
        self._connection.execute("DELETE FROM health_evidence WHERE id = ?", (evidence_id,))
        self._connection.commit()

    def prune_health_evidence(self, retain_per_target: int) -> int:
        if retain_per_target < 1:
            raise ValueError("retain_per_target must be positive")
        grouped: dict[tuple[str, str], list[HealthEvidence]] = {}
        for evidence in self.list_health_evidence():
            grouped.setdefault((evidence.resource_id, evidence.target), []).append(evidence)
        deleted = 0
        for evidence_items in grouped.values():
            ordered = sorted(evidence_items, key=lambda item: item.captured_at or item.id, reverse=True)
            for stale in ordered[retain_per_target:]:
                self._connection.execute("DELETE FROM health_evidence WHERE id = ?", (stale.id,))
                deleted += 1
        self._connection.commit()
        return deleted

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

    def list_approvals(self) -> tuple[ApprovalRequest, ...]:
        return tuple(_load_dataclass(ApprovalRequest, payload) for payload in self._list_payloads("approvals"))

    def save_runtime_heartbeat(self, heartbeat: RuntimeHeartbeat) -> None:
        self._upsert("runtime_heartbeats", heartbeat.id, _dump(heartbeat))

    def load_runtime_heartbeat(self, heartbeat_id: str) -> RuntimeHeartbeat:
        return _load_dataclass(RuntimeHeartbeat, self._get_payload("runtime_heartbeats", heartbeat_id))

    def list_runtime_heartbeats(self) -> tuple[RuntimeHeartbeat, ...]:
        return tuple(_load_dataclass(RuntimeHeartbeat, payload) for payload in self._list_payloads("runtime_heartbeats"))

    def save_host_snapshot(self, snapshot: HostInspectionSnapshot) -> None:
        self._upsert("host_snapshots", snapshot.id, _dump(snapshot))

    def load_host_snapshot(self, snapshot_id: str) -> HostInspectionSnapshot:
        return _load_dataclass(HostInspectionSnapshot, self._get_payload("host_snapshots", snapshot_id))

    def list_host_snapshots(self) -> tuple[HostInspectionSnapshot, ...]:
        return tuple(_load_dataclass(HostInspectionSnapshot, payload) for payload in self._list_payloads("host_snapshots"))

    def save_admin_change_plan(self, plan: AdminChangePlan) -> None:
        self._upsert("admin_change_plans", plan.id, _dump(plan))

    def load_admin_change_plan(self, plan_id: str) -> AdminChangePlan:
        return _load_dataclass(AdminChangePlan, self._get_payload("admin_change_plans", plan_id))

    def list_admin_change_plans(self) -> tuple[AdminChangePlan, ...]:
        return tuple(_load_dataclass(AdminChangePlan, payload) for payload in self._list_payloads("admin_change_plans"))

    def save_admin_execution(self, result: AdminExecutionResult) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO admin_executions (id, plan_id, payload) VALUES (?, ?, ?)",
            (result.id, result.plan_id, _dump(result)),
        )
        self._connection.commit()

    def load_admin_execution(self, result_id: str) -> AdminExecutionResult:
        return _load_dataclass(AdminExecutionResult, self._get_payload("admin_executions", result_id))

    def list_admin_executions(self) -> tuple[AdminExecutionResult, ...]:
        return tuple(_load_dataclass(AdminExecutionResult, payload) for payload in self._list_payloads("admin_executions"))

    def save_host_security_source_review(self, review: HostSecuritySourceReview) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO host_security_source_reviews (id, remote_address, payload) VALUES (?, ?, ?)",
            (review.id, review.remote_address, _dump(review)),
        )
        self._connection.commit()

    def load_host_security_source_review(self, review_id: str) -> HostSecuritySourceReview:
        return _load_dataclass(HostSecuritySourceReview, self._get_payload("host_security_source_reviews", review_id))

    def list_host_security_source_reviews(self) -> tuple[HostSecuritySourceReview, ...]:
        return tuple(_load_dataclass(HostSecuritySourceReview, payload) for payload in self._list_payloads("host_security_source_reviews"))

    def save_host_security_ids_review_package(self, package: HostSecurityIDSReviewPackage) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO host_security_ids_review_packages (id, plan_id, payload) VALUES (?, ?, ?)",
            (package.id, package.plan_id, _dump(package)),
        )
        self._connection.commit()

    def load_host_security_ids_review_package(self, package_id: str) -> HostSecurityIDSReviewPackage:
        return _load_dataclass(HostSecurityIDSReviewPackage, self._get_payload("host_security_ids_review_packages", package_id))

    def list_host_security_ids_review_packages(self) -> tuple[HostSecurityIDSReviewPackage, ...]:
        return tuple(_load_dataclass(HostSecurityIDSReviewPackage, payload) for payload in self._list_payloads("host_security_ids_review_packages"))

    def list_host_security_ids_review_packages_for_plan(self, plan_id: str) -> tuple[HostSecurityIDSReviewPackage, ...]:
        rows = self._connection.execute(
            "SELECT payload FROM host_security_ids_review_packages WHERE plan_id = ? ORDER BY id",
            (plan_id,),
        ).fetchall()
        return tuple(_load_dataclass(HostSecurityIDSReviewPackage, str(row["payload"])) for row in rows)

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
