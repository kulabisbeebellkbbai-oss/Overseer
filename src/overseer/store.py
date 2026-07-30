"""SQLite persistence for local Overseer state."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .admin import AdminChangePlan, AdminExecutionResult, AdminHistoryArchiveRecord
from .agent_contracts import (
    AgentCheckpoint,
    ActiveAgentRisk,
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentHandoffPackage,
    AgentInstanceTransition,
    AgentInstanceProfile,
    AgentOperationFenceState,
    AgentOperationReservation,
    AgentOperationState,
    AgentProvider,
    AgentSession,
    AgentTransitionState,
    DriverEpoch,
    FailoverDecision,
    FailoverExecution,
    FailoverExecutionState,
    FailoverPolicy,
    ProviderHealthObservation,
)
from .audit import ApprovalRequest, AuditEvent, AuditEventType
from .core import Claim, ConflictDecision, OwnerDomain, Resource, RiskLevel
from .crew import CrewMessage
from .health import HealthEvidence, HealthTarget
from .host import HostInspectionSnapshot
from .ids_review import HostSecurityIDSReviewPackage
from .key_broker import KeyBrokerTokenGrant, KeyBrokerTokenRequest, KeyProviderRecord
from .maintenance_schedule import MaintenanceSchedule
from .ops_records import OperationRecord
from .physical import PhysicalIdentity
from .runtime_state import RuntimeHeartbeat
from .serialization import dataclass_from_jsonable, to_jsonable
from .source_review import HostSecuritySourceReview
from .usage_limits import UsageContinuationDispatch, UsageContinuationRequest, UsageLimit


CURRENT_SCHEMA_VERSION = 1
AGENT_DRIVER_SCHEMA_VERSION = "agent_driver_v1"
AGENT_DRIVER_SCHEMA_V2 = "agent_driver_v2"
AGENT_DRIVER_SCHEMA_V3 = "agent_driver_v3"
AGENT_DRIVER_SCHEMA_V4 = "agent_driver_v4"
AGENT_DRIVER_SCHEMA_V5 = "agent_driver_v5"
AGENT_DRIVER_SCHEMA_V6 = "agent_driver_v6"
AGENT_DRIVER_SCHEMA_V7 = "agent_driver_v7"
_AGENT_TRANSITION_SUCCESSORS = {
    AgentTransitionState.IMPORTING: {
        AgentTransitionState.IMPORT_ACKNOWLEDGED,
        AgentTransitionState.RECONCILING,
        AgentTransitionState.FAILED,
        AgentTransitionState.ROLLED_BACK,
    },
    AgentTransitionState.IMPORT_ACKNOWLEDGED: {
        AgentTransitionState.COMPLETED,
        AgentTransitionState.FAILED,
        AgentTransitionState.ROLLED_BACK,
    },
    AgentTransitionState.RECONCILING: {
        AgentTransitionState.IMPORT_ACKNOWLEDGED,
        AgentTransitionState.RECONCILING,
        AgentTransitionState.FAILED,
        AgentTransitionState.ROLLED_BACK,
    },
    AgentTransitionState.FAILED: {
        AgentTransitionState.RECONCILING,
        AgentTransitionState.ROLLED_BACK,
    },
    AgentTransitionState.COMPLETED: set(),
    AgentTransitionState.ROLLED_BACK: set(),
}
_REDACTED_AGENT_TRANSCRIPT = "[redacted agent transcript]"
_REDACTED_DISPATCH_PROMPT = "[redacted dispatch prompt]"
_AGENT_CREDENTIAL_KEYS = frozenset(
    {
        "credential",
        "credentials",
        "secret",
        "client_secret",
        "client_secret_value",
        "password",
        "authorization",
        "cookie",
        "private_key",
        "access_key",
        "api_key",
        "bearer",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
    }
)
_AGENT_TRANSCRIPT_KEYS = frozenset(
    {
        "transcript",
        "conversation",
        "history",
        "raw_message",
        "raw_messages",
        "raw_output",
        "raw_outputs",
        "provider_output",
        "message",
        "messages",
        "output",
        "outputs",
        "prompt",
        "body",
        "content",
    }
)
_AGENT_DYNAMIC_EVIDENCE_KEYS = frozenset({"evidence", "legacy_references"})
_AGENT_SAFE_EVIDENCE_KEYS = frozenset(
    {
        "status",
        "state",
        "reason",
        "available",
        "healthy",
        "provider",
        "model",
        "version",
        "capability",
        "reference",
        "hash",
        "duration",
        "duration_ms",
        "exit_code",
    }
)
_AGENT_SECRET_VALUE_RE = re.compile(
    r"(?:\bbearer\s+\S+|\bsk-[A-Za-z0-9_-]{8,}|-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----|(?:^|[;,\s])(?:session|auth|access)?_?token=\S+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SchemaMigration:
    version: int | str
    description: str
    applied_at: str


@dataclass(frozen=True)
class AgentActivationReservation:
    instance_id: str
    reservation_id: str
    owner_id: str
    generation: int
    state: str
    started_at: str
    lease_expires_at: str
    epoch_id: str | None
    reason: str | None


class SQLiteStore:
    """Small JSON-payload SQLite store for early durable state."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path, timeout=30.0)
        self._connection.row_factory = sqlite3.Row
        self._agent_transaction_depth = 0
        self._configure_connection()
        self.initialize()

    def _configure_connection(self) -> None:
        self._connection.execute("PRAGMA busy_timeout = 30000")
        try:
            self._connection.execute("PRAGMA journal_mode = WAL")
        except sqlite3.OperationalError:
            pass

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def initialize(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
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
            CREATE TABLE IF NOT EXISTS usage_continuation_requests (
                id TEXT PRIMARY KEY,
                limit_id TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS usage_continuation_dispatches (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
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
            CREATE TABLE IF NOT EXISTS admin_history_archives (
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
            CREATE TABLE IF NOT EXISTS crew_messages (
                id TEXT PRIMARY KEY,
                owner_domain TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operation_records (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                owner_domain TEXT NOT NULL,
                status TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS maintenance_schedules (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS key_providers (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS key_broker_token_requests (
                id TEXT PRIMARY KEY,
                provider_id TEXT NOT NULL,
                status TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS key_broker_token_grants (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                status TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            """
        )
        with self._connection:
            self._record_schema_migration(CURRENT_SCHEMA_VERSION, "bootstrap JSON payload store")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_schema_migrations (
                    version TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_providers (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_instance_profiles (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_sessions (
                    id TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_driver_epochs (
                    id TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    UNIQUE(instance_id, ordinal)
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_dispatches (
                    id TEXT PRIMARY KEY,
                    instance_id TEXT NOT NULL,
                    driver_epoch_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    UNIQUE(instance_id, idempotency_key)
                )
                """
            )
            self._migrate_agent_dispatch_scope()
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_dispatch_results (
                    id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    driver_epoch_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_checkpoints (
                    id TEXT PRIMARY KEY,
                    driver_epoch_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_handoffs (
                    id TEXT PRIMARY KEY,
                    outgoing_epoch_id TEXT NOT NULL,
                    incoming_provider_id TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_activation_reservations (
                    instance_id TEXT PRIMARY KEY,
                    reservation_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL DEFAULT 'legacy',
                    generation INTEGER NOT NULL DEFAULT 1,
                    state TEXT NOT NULL,
                    started_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00',
                    lease_expires_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00',
                    epoch_id TEXT,
                    reason TEXT
                )
                """
            )
            self._migrate_agent_activation_leases()
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_instance_transitions (
                    instance_id TEXT PRIMARY KEY,
                    handoff_id TEXT NOT NULL,
                    outgoing_epoch_id TEXT NOT NULL,
                    incoming_epoch_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_operation_reservations (
                    instance_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    owner_token TEXT,
                    payload TEXT NOT NULL
                )
                """
            )
            for table in (
                "agent_failover_policies",
                "agent_provider_health_observations",
                "agent_active_risks",
                "agent_failover_decisions",
                "agent_failover_executions",
            ):
                self._connection.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} "
                    "(id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
                )
            self._connection.execute(
                "DROP TRIGGER IF EXISTS agent_dispatch_transition_fence"
            )
            self._connection.execute(
                """
                CREATE TRIGGER agent_dispatch_transition_fence
                BEFORE INSERT ON agent_dispatches
                WHEN EXISTS (
                    SELECT 1
                    FROM agent_instance_transitions
                    WHERE instance_id = NEW.instance_id
                      AND state IN (
                          'importing',
                          'import_acknowledged',
                          'reconciling',
                          'failed'
                      )
                    UNION ALL
                    SELECT 1
                    FROM agent_operation_reservations
                    WHERE instance_id = NEW.instance_id
                      AND (
                          state != 'open'
                          OR json_type(
                              NEW.payload,
                              '$.evidence.operation_generation'
                          ) != 'integer'
                          OR generation != CAST(
                              json_extract(
                                  NEW.payload,
                                  '$.evidence.operation_generation'
                              ) AS INTEGER
                          )
                      )
                )
                BEGIN
                    SELECT RAISE(ABORT, 'agent transition active');
                END
                """
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_VERSION,
                "persist provider-neutral agent driver lifecycle records",
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V2,
                "scope dispatch idempotency and persist distinct result attempts",
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V3,
                "persist atomic agent activation reservations",
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V4,
                "fence agent transitions and lease activation ownership",
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V5,
                "coordinate generation-bound agent operations",
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V6,
                "persist generation-bound controlled failover evidence",
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V7,
                "persist recoverable pre-import failover execution state",
            )

    def _migrate_agent_activation_leases(self) -> None:
        columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(agent_activation_reservations)"
            ).fetchall()
        }
        additions = (
            ("owner_id", "TEXT NOT NULL DEFAULT 'legacy'"),
            ("generation", "INTEGER NOT NULL DEFAULT 1"),
            (
                "started_at",
                "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'",
            ),
            (
                "lease_expires_at",
                "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'",
            ),
        )
        for name, declaration in additions:
            if name not in columns:
                self._connection.execute(
                    f"ALTER TABLE agent_activation_reservations "
                    f"ADD COLUMN {name} {declaration}"
                )

    def _migrate_agent_dispatch_scope(self) -> None:
        columns = {
            str(row["name"])
            for row in self._connection.execute(
                "PRAGMA table_info(agent_dispatches)"
            ).fetchall()
        }
        if "instance_id" in columns:
            return
        rows = self._connection.execute(
            "SELECT id, driver_epoch_id, idempotency_key, state, payload "
            "FROM agent_dispatches"
        ).fetchall()
        self._connection.execute(
            "ALTER TABLE agent_dispatches RENAME TO agent_dispatches_legacy_v1"
        )
        self._connection.execute(
            """
            CREATE TABLE agent_dispatches (
                id TEXT PRIMARY KEY,
                instance_id TEXT NOT NULL,
                driver_epoch_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                state TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(instance_id, idempotency_key)
            )
            """
        )
        for row in rows:
            instance_id = json.loads(str(row["payload"])).get("instance_id")
            if not isinstance(instance_id, str) or not instance_id:
                raise ValueError("legacy agent dispatch lacks instance identity")
            self._connection.execute(
                "INSERT INTO agent_dispatches VALUES (?, ?, ?, ?, ?, ?)",
                (
                    row["id"],
                    instance_id,
                    row["driver_epoch_id"],
                    row["idempotency_key"],
                    row["state"],
                    row["payload"],
                ),
            )
        self._connection.execute("DROP TABLE agent_dispatches_legacy_v1")

    @contextmanager
    def agent_transaction(self) -> Iterable[None]:
        outermost = self._agent_transaction_depth == 0
        if outermost:
            self._connection.execute("BEGIN IMMEDIATE")
        self._agent_transaction_depth += 1
        try:
            yield
        except Exception:
            self._agent_transaction_depth -= 1
            if outermost:
                self._connection.rollback()
            raise
        else:
            self._agent_transaction_depth -= 1
            if outermost:
                self._connection.commit()

    def _commit_agent_mutation(self) -> None:
        if self._agent_transaction_depth == 0:
            self._connection.commit()

    def _record_schema_migration(self, version: int, description: str) -> None:
        self._connection.execute(
            """
            INSERT OR IGNORE INTO schema_migrations (version, description, applied_at)
            VALUES (?, ?, ?)
            """,
            (version, description, datetime.now(UTC).isoformat()),
        )

    def _record_agent_schema_migration(self, version: str, description: str) -> None:
        self._connection.execute(
            """
            INSERT OR IGNORE INTO agent_schema_migrations (version, description, applied_at)
            VALUES (?, ?, ?)
            """,
            (version, description, datetime.now(UTC).isoformat()),
        )

    def list_schema_migrations(self) -> tuple[SchemaMigration, ...]:
        numeric_rows = self._connection.execute(
            "SELECT version, description, applied_at FROM schema_migrations ORDER BY version"
        ).fetchall()
        named_rows = self._connection.execute(
            "SELECT version, description, applied_at FROM agent_schema_migrations ORDER BY version"
        ).fetchall()
        return tuple(
            SchemaMigration(
                version=int(row["version"]),
                description=str(row["description"]),
                applied_at=str(row["applied_at"]),
            )
            for row in numeric_rows
        ) + tuple(
            SchemaMigration(
                version=str(row["version"]),
                description=str(row["description"]),
                applied_at=str(row["applied_at"]),
            )
            for row in named_rows
        )

    def save_agent_provider(self, provider: AgentProvider) -> None:
        self._save_agent_record(
            "agent_providers",
            provider,
            AgentProvider,
            tuple(AgentProvider.__dataclass_fields__),
            {},
        )

    def load_agent_provider(self, provider_id: str) -> AgentProvider:
        return _load_dataclass(AgentProvider, self._get_payload("agent_providers", provider_id))

    def list_agent_providers(self) -> tuple[AgentProvider, ...]:
        return tuple(
            _load_dataclass(AgentProvider, payload)
            for payload in self._list_payloads("agent_providers")
        )

    def save_agent_instance_profile(self, profile: AgentInstanceProfile) -> None:
        self._save_agent_record(
            "agent_instance_profiles",
            profile,
            AgentInstanceProfile,
            (
                "id",
                "primary_provider_id",
                "transport",
                "workspace",
                "primary_adapter_id",
                "model_profile_id",
                "external_session_id",
                "declared_capabilities",
                "required_capabilities",
                "credential_references",
                "permission_policy_ref",
                "execution_policy_ref",
                "provider_health_source_id",
                "usage_limit_source_id",
                "approved_fallback_provider_ids",
                "controlled_failover_policy_ref",
            ),
            {},
        )

    def load_agent_instance_profile(self, instance_id: str) -> AgentInstanceProfile:
        return _load_dataclass(
            AgentInstanceProfile,
            self._get_payload("agent_instance_profiles", instance_id),
        )

    def list_agent_instance_profiles(self) -> tuple[AgentInstanceProfile, ...]:
        return tuple(
            _load_dataclass(AgentInstanceProfile, payload)
            for payload in self._list_payloads("agent_instance_profiles")
        )

    def save_agent_session(self, session: AgentSession) -> None:
        try:
            existing = self.load_agent_session(session.id)
        except KeyError:
            existing = None
        if (
            existing is not None
            and existing.external_session_id is not None
            and session.external_session_id != existing.external_session_id
        ):
            raise ValueError(
                "agent_sessions immutable identity field external_session_id cannot change"
            )
        self._save_agent_record(
            "agent_sessions",
            session,
            AgentSession,
            (
                "id",
                "provider_id",
                "workspace",
                "transport",
                "instance_id",
                "model_profile_id",
                "discovered_at",
            ),
            {"provider_id": session.provider_id},
        )

    def reserve_agent_activation(
        self,
        instance_id: str,
        reservation_id: str,
        *,
        owner_id: str,
        started_at: str,
        lease_expires_at: str,
        allow_blocked_retry: bool,
        observed_at: str,
    ) -> bool:
        cursor = self._connection.execute(
            """
            INSERT INTO agent_activation_reservations
                (
                    instance_id, reservation_id, owner_id, generation, state,
                    started_at, lease_expires_at, epoch_id, reason
                )
            VALUES (?, ?, ?, 1, 'starting', ?, ?, NULL, NULL)
            ON CONFLICT(instance_id) DO UPDATE SET
                reservation_id = excluded.reservation_id,
                owner_id = excluded.owner_id,
                generation = agent_activation_reservations.generation + 1,
                state = 'starting',
                started_at = excluded.started_at,
                lease_expires_at = excluded.lease_expires_at,
                epoch_id = NULL,
                reason = NULL
            WHERE (
                agent_activation_reservations.state = 'blocked' AND ? = 1
            ) OR (
                agent_activation_reservations.state = 'starting'
                AND julianday(agent_activation_reservations.lease_expires_at)
                    <= julianday(?)
            )
            """,
            (
                instance_id,
                reservation_id,
                owner_id,
                started_at,
                lease_expires_at,
                int(allow_blocked_retry),
                observed_at,
            ),
        )
        self._connection.commit()
        return cursor.rowcount == 1

    def load_agent_activation(
        self,
        instance_id: str,
    ) -> AgentActivationReservation:
        row = self._connection.execute(
            "SELECT instance_id, reservation_id, owner_id, generation, state, "
            "started_at, lease_expires_at, epoch_id, reason "
            "FROM agent_activation_reservations WHERE instance_id = ?",
            (instance_id,),
        ).fetchone()
        if row is None:
            raise KeyError(instance_id)
        return AgentActivationReservation(
            instance_id=str(row["instance_id"]),
            reservation_id=str(row["reservation_id"]),
            owner_id=str(row["owner_id"]),
            generation=int(row["generation"]),
            state=str(row["state"]),
            started_at=str(row["started_at"]),
            lease_expires_at=str(row["lease_expires_at"]),
            epoch_id=str(row["epoch_id"]) if row["epoch_id"] is not None else None,
            reason=str(row["reason"]) if row["reason"] is not None else None,
        )

    def finish_agent_activation(
        self,
        instance_id: str,
        reservation_id: str,
        owner_id: str,
        generation: int,
        state: str,
        *,
        epoch_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        cursor = self._connection.execute(
            """
            UPDATE agent_activation_reservations
            SET state = ?, epoch_id = ?, reason = ?
            WHERE instance_id = ? AND reservation_id = ? AND owner_id = ?
                AND generation = ? AND state = 'starting'
            """,
            (
                state,
                epoch_id,
                reason,
                instance_id,
                reservation_id,
                owner_id,
                generation,
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("activation reservation ownership changed")
        self._commit_agent_mutation()

    def ensure_agent_operation(
        self,
        instance_id: str,
        *,
        updated_at: str,
    ) -> AgentOperationReservation:
        operation = AgentOperationReservation(
            instance_id=instance_id,
            generation=1,
            state=AgentOperationFenceState.OPEN,
            owner_token=None,
            updated_at=updated_at,
        )
        payload = json.dumps(
            to_jsonable(operation),
            separators=(",", ":"),
            sort_keys=True,
        )
        self._connection.execute(
            """
            INSERT OR IGNORE INTO agent_operation_reservations
                (instance_id, generation, state, owner_token, payload)
            VALUES (?, 1, 'open', NULL, ?)
            """,
            (instance_id, payload),
        )
        self._commit_agent_mutation()
        return self.load_agent_operation(instance_id)

    def load_agent_operation(self, instance_id: str) -> AgentOperationReservation:
        row = self._connection.execute(
            "SELECT payload FROM agent_operation_reservations WHERE instance_id = ?",
            (instance_id,),
        ).fetchone()
        if row is None:
            raise KeyError(instance_id)
        return _load_dataclass(AgentOperationReservation, str(row["payload"]))

    def save_agent_operation(
        self,
        operation: AgentOperationReservation,
        *,
        expected_generation: int,
        expected_state: AgentOperationFenceState,
        expected_owner_token: str | None,
    ) -> None:
        payload = json.dumps(
            to_jsonable(operation),
            separators=(",", ":"),
            sort_keys=True,
        )
        cursor = self._connection.execute(
            """
            UPDATE agent_operation_reservations
            SET generation = ?, state = ?, owner_token = ?, payload = ?
            WHERE instance_id = ? AND generation = ? AND state = ?
              AND owner_token IS ?
            """,
            (
                operation.generation,
                operation.state.value,
                operation.owner_token,
                payload,
                operation.instance_id,
                expected_generation,
                expected_state.value,
                expected_owner_token,
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("agent operation reservation changed concurrently")
        self._commit_agent_mutation()

    def begin_agent_transition(self, transition: AgentInstanceTransition) -> bool:
        if transition.state is not AgentTransitionState.IMPORTING:
            raise ValueError("new agent transition must begin in importing state")
        payload = json.dumps(
            to_jsonable(transition),
            separators=(",", ":"),
            sort_keys=True,
        )
        cursor = self._connection.execute(
            """
            INSERT INTO agent_instance_transitions
                (
                    instance_id, handoff_id, outgoing_epoch_id,
                    incoming_epoch_id, state, payload
                )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(instance_id) DO UPDATE SET
                handoff_id = excluded.handoff_id,
                outgoing_epoch_id = excluded.outgoing_epoch_id,
                incoming_epoch_id = excluded.incoming_epoch_id,
                state = excluded.state,
                payload = excluded.payload
            WHERE agent_instance_transitions.state IN ('completed', 'rolled_back')
            """,
            (
                transition.instance_id,
                transition.handoff_id,
                transition.outgoing_epoch_id,
                transition.incoming_epoch_id,
                transition.state.value,
                payload,
            ),
        )
        self._commit_agent_mutation()
        return cursor.rowcount == 1

    def save_agent_transition(self, transition: AgentInstanceTransition) -> None:
        current = self.load_agent_transition(transition.instance_id)
        if (
            current.handoff_id != transition.handoff_id
            or current.outgoing_epoch_id != transition.outgoing_epoch_id
            or current.incoming_epoch_id != transition.incoming_epoch_id
        ):
            raise ValueError("agent transition identity cannot change")
        if transition.state not in _AGENT_TRANSITION_SUCCESSORS[current.state]:
            raise ValueError(
                f"invalid agent transition {current.state.value} "
                f"to {transition.state.value}"
            )
        payload = json.dumps(
            to_jsonable(transition),
            separators=(",", ":"),
            sort_keys=True,
        )
        cursor = self._connection.execute(
            """
            UPDATE agent_instance_transitions
            SET state = ?, payload = ?
            WHERE instance_id = ? AND handoff_id = ? AND state = ?
            """,
            (
                transition.state.value,
                payload,
                transition.instance_id,
                transition.handoff_id,
                current.state.value,
            ),
        )
        if cursor.rowcount != 1:
            raise ValueError("agent transition state changed concurrently")
        self._commit_agent_mutation()

    def load_agent_transition(self, instance_id: str) -> AgentInstanceTransition:
        row = self._connection.execute(
            "SELECT payload FROM agent_instance_transitions WHERE instance_id = ?",
            (instance_id,),
        ).fetchone()
        if row is None:
            raise KeyError(instance_id)
        return _load_dataclass(AgentInstanceTransition, str(row["payload"]))

    def list_agent_transitions(self) -> tuple[AgentInstanceTransition, ...]:
        rows = self._connection.execute(
            "SELECT payload FROM agent_instance_transitions ORDER BY instance_id"
        ).fetchall()
        return tuple(
            _load_dataclass(AgentInstanceTransition, str(row["payload"]))
            for row in rows
        )

    def load_agent_session(self, session_id: str) -> AgentSession:
        return _load_dataclass(AgentSession, self._get_payload("agent_sessions", session_id))

    def list_agent_sessions(self) -> tuple[AgentSession, ...]:
        return tuple(
            _load_dataclass(AgentSession, payload) for payload in self._list_payloads("agent_sessions")
        )

    def save_driver_epoch(self, epoch: DriverEpoch) -> None:
        self._reject_agent_secondary_collision(
            "agent_driver_epochs",
            {"instance_id": epoch.instance_id, "ordinal": epoch.ordinal},
            epoch.id,
            "driver epoch instance_id and ordinal",
        )
        self._save_agent_record(
            "agent_driver_epochs",
            epoch,
            DriverEpoch,
            ("id", "instance_id", "session_id", "provider_id", "ordinal", "opened_at"),
            {
                "instance_id": epoch.instance_id,
                "ordinal": epoch.ordinal,
                "state": epoch.state.value,
            },
        )

    def load_driver_epoch(self, epoch_id: str) -> DriverEpoch:
        return _load_dataclass(DriverEpoch, self._get_payload("agent_driver_epochs", epoch_id))

    def list_driver_epochs(self) -> tuple[DriverEpoch, ...]:
        return tuple(
            _load_dataclass(DriverEpoch, payload)
            for payload in self._list_payloads("agent_driver_epochs")
        )

    def save_agent_dispatch(self, dispatch: AgentDispatchRequest) -> None:
        self._reject_agent_secondary_collision(
            "agent_dispatches",
            {
                "instance_id": dispatch.instance_id,
                "idempotency_key": dispatch.idempotency_key,
            },
            dispatch.id,
            "dispatch idempotency key",
        )
        self._save_agent_record(
            "agent_dispatches",
            dispatch,
            AgentDispatchRequest,
            (
                "id",
                "instance_id",
                "session_id",
                "driver_epoch_id",
                "idempotency_key",
                "requested_at",
                "requested_by",
            ),
            {
                "instance_id": dispatch.instance_id,
                "driver_epoch_id": dispatch.driver_epoch_id,
                "idempotency_key": dispatch.idempotency_key,
                "state": AgentOperationState.QUEUED.value,
            },
        )

    def load_agent_dispatch(self, dispatch_id: str) -> AgentDispatchRequest:
        return _load_dataclass(
            AgentDispatchRequest,
            self._get_payload("agent_dispatches", dispatch_id),
        )

    def list_agent_dispatches(self) -> tuple[AgentDispatchRequest, ...]:
        return tuple(
            _load_dataclass(AgentDispatchRequest, payload)
            for payload in self._list_payloads("agent_dispatches")
        )

    def load_agent_dispatch_by_idempotency(
        self,
        instance_id: str,
        idempotency_key: str,
    ) -> AgentDispatchRequest:
        row = self._connection.execute(
            "SELECT payload FROM agent_dispatches "
            "WHERE instance_id = ? AND idempotency_key = ?",
            (instance_id, idempotency_key),
        ).fetchone()
        if row is None:
            raise KeyError((instance_id, idempotency_key))
        return _load_dataclass(AgentDispatchRequest, str(row["payload"]))

    def save_agent_dispatch_result(self, result: AgentDispatchResult) -> None:
        self._save_agent_record(
            "agent_dispatch_results",
            result,
            AgentDispatchResult,
            tuple(AgentDispatchResult.__dataclass_fields__),
            {
                "request_id": result.request_id,
                "driver_epoch_id": result.driver_epoch_id,
                "state": result.state.value,
            },
        )

    def load_agent_dispatch_result(self, result_id: str) -> AgentDispatchResult:
        return _load_dataclass(
            AgentDispatchResult,
            self._get_payload("agent_dispatch_results", result_id),
        )

    def list_agent_dispatch_results(self) -> tuple[AgentDispatchResult, ...]:
        return tuple(
            _load_dataclass(AgentDispatchResult, payload)
            for payload in self._list_payloads("agent_dispatch_results")
        )

    def save_agent_checkpoint(self, checkpoint: AgentCheckpoint) -> None:
        self._save_agent_record(
            "agent_checkpoints",
            checkpoint,
            AgentCheckpoint,
            ("id", "instance_id", "session_id", "driver_epoch_id", "created_at", "expires_at"),
            {"driver_epoch_id": checkpoint.driver_epoch_id},
        )

    def load_agent_checkpoint(self, checkpoint_id: str) -> AgentCheckpoint:
        return _load_dataclass(
            AgentCheckpoint,
            self._get_payload("agent_checkpoints", checkpoint_id),
        )

    def list_agent_checkpoints(self) -> tuple[AgentCheckpoint, ...]:
        return tuple(
            _load_dataclass(AgentCheckpoint, payload)
            for payload in self._list_payloads("agent_checkpoints")
        )

    def save_agent_handoff(self, handoff: AgentHandoffPackage) -> None:
        self._save_agent_record(
            "agent_handoffs",
            handoff,
            AgentHandoffPackage,
            (
                "id",
                "instance_id",
                "outgoing_epoch_id",
                "incoming_provider_id",
                "objective",
                "checkpoint_id",
                "required_capabilities",
                "created_at",
            ),
            {
                "outgoing_epoch_id": handoff.outgoing_epoch_id,
                "incoming_provider_id": handoff.incoming_provider_id,
            },
        )

    def load_agent_handoff(self, handoff_id: str) -> AgentHandoffPackage:
        return _load_dataclass(
            AgentHandoffPackage,
            self._get_payload("agent_handoffs", handoff_id),
        )

    def list_agent_handoffs(self) -> tuple[AgentHandoffPackage, ...]:
        return tuple(
            _load_dataclass(AgentHandoffPackage, payload)
            for payload in self._list_payloads("agent_handoffs")
        )

    def save_failover_policy(self, policy: FailoverPolicy) -> None:
        self._save_agent_record(
            "agent_failover_policies", policy, FailoverPolicy,
            tuple(FailoverPolicy.__dataclass_fields__), {},
        )

    def load_failover_policy(self, policy_id: str) -> FailoverPolicy:
        return _load_dataclass(
            FailoverPolicy, self._get_payload("agent_failover_policies", policy_id)
        )

    def save_provider_health_observation(
        self, observation: ProviderHealthObservation
    ) -> None:
        self._save_agent_record(
            "agent_provider_health_observations",
            observation,
            ProviderHealthObservation,
            tuple(ProviderHealthObservation.__dataclass_fields__),
            {},
        )

    def list_provider_health_observations(
        self, instance_id: str
    ) -> tuple[ProviderHealthObservation, ...]:
        return tuple(
            item
            for item in (
                _load_dataclass(ProviderHealthObservation, payload)
                for payload in self._list_payloads("agent_provider_health_observations")
            )
            if item.instance_id == instance_id
        )

    def save_active_agent_risk(self, risk: ActiveAgentRisk) -> None:
        self._save_agent_record(
            "agent_active_risks", risk, ActiveAgentRisk,
            tuple(ActiveAgentRisk.__dataclass_fields__), {},
        )

    def list_active_agent_risks(self, instance_id: str) -> tuple[ActiveAgentRisk, ...]:
        return tuple(
            item
            for item in (
                _load_dataclass(ActiveAgentRisk, payload)
                for payload in self._list_payloads("agent_active_risks")
            )
            if item.instance_id == instance_id
        )

    def save_failover_decision(self, decision: FailoverDecision) -> None:
        self._save_agent_record(
            "agent_failover_decisions",
            decision,
            FailoverDecision,
            tuple(FailoverDecision.__dataclass_fields__),
            {},
        )

    def load_failover_decision(self, decision_id: str) -> FailoverDecision:
        return _load_dataclass(
            FailoverDecision, self._get_payload("agent_failover_decisions", decision_id)
        )

    def consume_failover_decision(
        self, decision_id: str, *, expected_generation: int, consumed_at: str
    ) -> FailoverDecision:
        current = self.load_failover_decision(decision_id)
        if current.consumed_at is not None:
            raise ValueError("failover decision is already consumed")
        if current.operation_generation != expected_generation:
            raise ValueError("failover decision generation changed")
        updated = dataclass_from_jsonable(
            FailoverDecision,
            {**to_jsonable(current), "consumed_at": consumed_at},
        )
        cursor = self._connection.execute(
            "UPDATE agent_failover_decisions SET payload = ? "
            "WHERE id = ? AND json_extract(payload, '$.consumed_at') IS NULL",
            (_dump_agent_record(updated), decision_id),
        )
        if cursor.rowcount != 1:
            raise ValueError("failover decision is already consumed")
        self._commit_agent_mutation()
        return updated

    def save_failover_execution(self, execution: FailoverExecution) -> None:
        self._save_agent_record(
            "agent_failover_executions",
            execution,
            FailoverExecution,
            (
                "id", "decision_id", "instance_id", "outgoing_epoch_id",
                "outgoing_session_id", "outgoing_provider_id", "checkpoint_id",
                "operation_generation", "operation_owner_ref", "created_at",
            ),
            {},
        )

    def load_failover_execution(self, execution_id: str) -> FailoverExecution:
        return _load_dataclass(
            FailoverExecution,
            self._get_payload("agent_failover_executions", execution_id),
        )

    def list_failover_executions(self) -> tuple[FailoverExecution, ...]:
        return tuple(
            _load_dataclass(FailoverExecution, payload)
            for payload in self._list_payloads("agent_failover_executions")
        )

    def transition_failover_execution(
        self,
        execution_id: str,
        *,
        expected_state: FailoverExecutionState,
        state: FailoverExecutionState,
        updated_at: str,
        reason: str | None = None,
        resume_result_ref: str | None = None,
    ) -> FailoverExecution:
        current = self.load_failover_execution(execution_id)
        if current.state is not expected_state:
            raise ValueError("failover execution state changed")
        allowed = {
            FailoverExecutionState.RESERVED: {FailoverExecutionState.DRAINING},
            FailoverExecutionState.DRAINING: {
                FailoverExecutionState.BLOCKED_PREIMPORT,
                FailoverExecutionState.TRANSITION_STARTED,
            },
            FailoverExecutionState.BLOCKED_PREIMPORT: {
                FailoverExecutionState.RECOVERING,
            },
            FailoverExecutionState.RECOVERING: {
                FailoverExecutionState.BLOCKED_PREIMPORT,
                FailoverExecutionState.RECOVERED,
            },
        }
        if state not in allowed.get(expected_state, set()):
            raise ValueError("invalid failover execution transition")
        updated = dataclass_from_jsonable(
            FailoverExecution,
            {
                **to_jsonable(current),
                "state": state.value,
                "updated_at": updated_at,
                "reason": reason,
                "resume_result_ref": resume_result_ref,
            },
        )
        cursor = self._connection.execute(
            "UPDATE agent_failover_executions SET payload = ? "
            "WHERE id = ? AND json_extract(payload, '$.state') = ?",
            (_dump_agent_record(updated), execution_id, expected_state.value),
        )
        if cursor.rowcount != 1:
            raise ValueError("failover execution state changed")
        self._commit_agent_mutation()
        return updated

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

    def save_usage_continuation_request(self, request: UsageContinuationRequest) -> None:
        self._connection.execute(
            """
            INSERT OR REPLACE INTO usage_continuation_requests (id, limit_id, resource_id, payload)
            VALUES (?, ?, ?, ?)
            """,
            (request.id, request.limit_id, request.resource_id, _dump(request)),
        )
        self._connection.commit()

    def load_usage_continuation_request(self, request_id: str) -> UsageContinuationRequest:
        return _load_dataclass(UsageContinuationRequest, self._get_payload("usage_continuation_requests", request_id))

    def list_usage_continuation_requests(self) -> tuple[UsageContinuationRequest, ...]:
        return tuple(
            _load_dataclass(UsageContinuationRequest, payload)
            for payload in self._list_payloads("usage_continuation_requests")
        )

    def save_usage_continuation_dispatch(self, dispatch: UsageContinuationDispatch) -> None:
        self._connection.execute(
            """
            INSERT OR REPLACE INTO usage_continuation_dispatches (id, request_id, payload)
            VALUES (?, ?, ?)
            """,
            (dispatch.id, dispatch.request_id, _dump(dispatch)),
        )
        self._connection.commit()

    def load_usage_continuation_dispatch(self, dispatch_id: str) -> UsageContinuationDispatch:
        return _load_dataclass(
            UsageContinuationDispatch,
            self._get_payload("usage_continuation_dispatches", dispatch_id),
        )

    def list_usage_continuation_dispatches(self) -> tuple[UsageContinuationDispatch, ...]:
        return tuple(
            _load_dataclass(UsageContinuationDispatch, payload)
            for payload in self._list_payloads("usage_continuation_dispatches")
        )

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

    def list_host_snapshots(self, *, limit: int | None = None) -> tuple[HostInspectionSnapshot, ...]:
        sql = "SELECT payload FROM host_snapshots ORDER BY id"
        params: tuple[object, ...] = ()
        if limit is not None:
            sql = "SELECT payload FROM host_snapshots ORDER BY id DESC LIMIT ?"
            params = (max(0, int(limit)),)
        rows = self._connection.execute(sql, params).fetchall()
        return tuple(_load_dataclass(HostInspectionSnapshot, str(row["payload"])) for row in rows)

    def count_host_snapshots(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) AS count FROM host_snapshots").fetchone()
        return int(row["count"] if row is not None else 0)

    def load_latest_host_snapshot(self) -> HostInspectionSnapshot | None:
        row = self._connection.execute("SELECT payload FROM host_snapshots ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return _load_dataclass(HostInspectionSnapshot, str(row["payload"]))

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

    def save_admin_history_archive(self, archive: AdminHistoryArchiveRecord) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO admin_history_archives (id, plan_id, payload) VALUES (?, ?, ?)",
            (archive.id, archive.plan_id, _dump(archive)),
        )
        self._connection.commit()

    def load_admin_history_archive(self, archive_id: str) -> AdminHistoryArchiveRecord:
        return _load_dataclass(AdminHistoryArchiveRecord, self._get_payload("admin_history_archives", archive_id))

    def list_admin_history_archives(self) -> tuple[AdminHistoryArchiveRecord, ...]:
        return tuple(_load_dataclass(AdminHistoryArchiveRecord, payload) for payload in self._list_payloads("admin_history_archives"))

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

    def save_crew_message(self, message: CrewMessage) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO crew_messages (id, owner_domain, payload) VALUES (?, ?, ?)",
            (message.id, message.owner_domain.value, _dump(message)),
        )
        self._connection.commit()

    def load_crew_message(self, message_id: str) -> CrewMessage:
        return _load_dataclass(CrewMessage, self._get_payload("crew_messages", message_id))

    def list_crew_messages(self) -> tuple[CrewMessage, ...]:
        return tuple(_load_dataclass(CrewMessage, payload) for payload in self._list_payloads("crew_messages"))

    def save_operation_record(self, record: OperationRecord) -> None:
        self._connection.execute(
            """
            INSERT OR REPLACE INTO operation_records (id, kind, owner_domain, status, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (record.id, record.kind.value, record.owner_domain.value, record.status.value, _dump(record)),
        )
        self._connection.commit()

    def load_operation_record(self, record_id: str) -> OperationRecord:
        return _load_dataclass(OperationRecord, self._get_payload("operation_records", record_id))

    def list_operation_records(
        self,
        kind: str | None = None,
        owner_domain: OwnerDomain | str | None = None,
        status: str | None = None,
    ) -> tuple[OperationRecord, ...]:
        clauses: list[str] = []
        params: list[str] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if owner_domain:
            clauses.append("owner_domain = ?")
            params.append(owner_domain)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._connection.execute(
            f"SELECT payload FROM operation_records{where} ORDER BY id",
            tuple(params),
        ).fetchall()
        return tuple(_load_dataclass(OperationRecord, str(row["payload"])) for row in rows)

    def save_maintenance_schedule(self, schedule: MaintenanceSchedule) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO maintenance_schedules (id, target, payload) VALUES (?, ?, ?)",
            (schedule.id, schedule.target, _dump(schedule)),
        )
        self._connection.commit()

    def load_maintenance_schedule(self, schedule_id: str) -> MaintenanceSchedule:
        return _load_dataclass(MaintenanceSchedule, self._get_payload("maintenance_schedules", schedule_id))

    def list_maintenance_schedules(self) -> tuple[MaintenanceSchedule, ...]:
        return tuple(_load_dataclass(MaintenanceSchedule, payload) for payload in self._list_payloads("maintenance_schedules"))

    def save_key_provider(self, provider: KeyProviderRecord) -> None:
        self._upsert("key_providers", provider.id, _dump(provider))

    def load_key_provider(self, provider_id: str) -> KeyProviderRecord:
        return _load_dataclass(KeyProviderRecord, self._get_payload("key_providers", provider_id))

    def list_key_providers(self) -> tuple[KeyProviderRecord, ...]:
        return tuple(_load_dataclass(KeyProviderRecord, payload) for payload in self._list_payloads("key_providers"))

    def save_key_broker_token_request(self, request: KeyBrokerTokenRequest) -> None:
        self._connection.execute(
            """
            INSERT OR REPLACE INTO key_broker_token_requests (id, provider_id, status, payload)
            VALUES (?, ?, ?, ?)
            """,
            (request.id, request.provider_id, request.status.value, _dump(request)),
        )
        self._connection.commit()

    def load_key_broker_token_request(self, request_id: str) -> KeyBrokerTokenRequest:
        return _load_dataclass(KeyBrokerTokenRequest, self._get_payload("key_broker_token_requests", request_id))

    def list_key_broker_token_requests(self) -> tuple[KeyBrokerTokenRequest, ...]:
        return tuple(
            _load_dataclass(KeyBrokerTokenRequest, payload)
            for payload in self._list_payloads("key_broker_token_requests")
        )

    def save_key_broker_token_grant(self, grant: KeyBrokerTokenGrant) -> None:
        self._connection.execute(
            """
            INSERT OR REPLACE INTO key_broker_token_grants (id, request_id, provider_id, status, payload)
            VALUES (?, ?, ?, ?, ?)
            """,
            (grant.id, grant.request_id, grant.provider_id, grant.status.value, _dump(grant)),
        )
        self._connection.commit()

    def load_key_broker_token_grant(self, grant_id: str) -> KeyBrokerTokenGrant:
        return _load_dataclass(KeyBrokerTokenGrant, self._get_payload("key_broker_token_grants", grant_id))

    def list_key_broker_token_grants(self) -> tuple[KeyBrokerTokenGrant, ...]:
        return tuple(
            _load_dataclass(KeyBrokerTokenGrant, payload)
            for payload in self._list_payloads("key_broker_token_grants")
        )

    def save_audit_event(self, event: AuditEvent) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO audit_events (id, subject_id, payload) VALUES (?, ?, ?)",
            (event.id, event.subject_id, _dump(event)),
        )
        self._commit_agent_mutation()

    def list_audit_events(
        self,
        *,
        subject_prefix: str | None = None,
        event_type: AuditEventType | str | None = None,
        owner_domain: OwnerDomain | str | None = None,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        clauses: list[str] = []
        params: list[object] = []
        if subject_prefix:
            clauses.append("subject_id LIKE ?")
            params.append(f"{subject_prefix}%")
        if event_type:
            clauses.append("payload LIKE ?")
            params.append(f'%"event_type":"{AuditEventType(event_type).value}"%')
        if owner_domain:
            owner_value = OwnerDomain(owner_domain).value
            clauses.append("payload LIKE ?")
            params.append(f'%"owner_domain":"{owner_value}"%')
        sql = "SELECT payload FROM audit_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(max(0, int(limit)))
        rows = self._connection.execute(sql, tuple(params)).fetchall()
        return tuple(_load_dataclass(AuditEvent, str(row["payload"])) for row in rows)

    def count_audit_events(
        self,
        *,
        subject_prefix: str | None = None,
        event_type: AuditEventType | str | None = None,
        owner_domain: OwnerDomain | str | None = None,
        risk_level: RiskLevel | str | None = None,
    ) -> int:
        clauses: list[str] = []
        params: list[object] = []
        if subject_prefix:
            clauses.append("subject_id LIKE ?")
            params.append(f"{subject_prefix}%")
        if event_type:
            clauses.append("payload LIKE ?")
            params.append(f'%"event_type":"{AuditEventType(event_type).value}"%')
        if owner_domain:
            owner_value = OwnerDomain(owner_domain).value
            clauses.append("payload LIKE ?")
            params.append(f'%"owner_domain":"{owner_value}"%')
        if risk_level:
            risk_value = RiskLevel(risk_level).value
            clauses.append("payload LIKE ?")
            params.append(f'%"risk_level":"{risk_value}"%')
        sql = "SELECT COUNT(*) AS count FROM audit_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        row = self._connection.execute(sql, tuple(params)).fetchone()
        return int(row["count"] if row is not None else 0)

    def _upsert(self, table: str, row_id: str, payload: str) -> None:
        self._connection.execute(f"INSERT OR REPLACE INTO {table} (id, payload) VALUES (?, ?)", (row_id, payload))
        self._commit_agent_mutation()

    def _save_agent_record(
        self,
        table: str,
        record: Any,
        record_type: type[Any],
        immutable_fields: tuple[str, ...],
        indexed_values: dict[str, object],
    ) -> None:
        payload = _dump_agent_record(record)
        sanitized_record = _load_dataclass(record_type, payload)
        row = self._connection.execute(
            f"SELECT payload FROM {table} WHERE id = ?", (sanitized_record.id,)
        ).fetchone()
        if row is not None:
            existing_record = _load_dataclass(record_type, str(row["payload"]))
            if any(
                getattr(existing_record, field) != getattr(sanitized_record, field)
                for field in immutable_fields
            ):
                raise ValueError(f"{table} immutable identity cannot change")
            assignments = ", ".join([*(f"{column} = ?" for column in indexed_values), "payload = ?"])
            self._connection.execute(
                f"UPDATE {table} SET {assignments} WHERE id = ?",
                (*indexed_values.values(), payload, sanitized_record.id),
            )
        else:
            columns = ("id", *indexed_values, "payload")
            placeholders = ", ".join("?" for _ in columns)
            self._connection.execute(
                f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
                (sanitized_record.id, *indexed_values.values(), payload),
            )
        self._commit_agent_mutation()

    def _reject_agent_secondary_collision(
        self,
        table: str,
        values: dict[str, object],
        record_id: str,
        label: str,
    ) -> None:
        where = " AND ".join(f"{column} = ?" for column in values)
        row = self._connection.execute(
            f"SELECT id FROM {table} WHERE {where}", tuple(values.values())
        ).fetchone()
        if row is not None and str(row["id"]) != record_id:
            raise ValueError(f"{label} already belongs to {row['id']}")

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


def _dump_agent_record(value: Any) -> str:
    return json.dumps(
        _sanitize_agent_json(to_jsonable(value)), sort_keys=True, separators=(",", ":")
    )


def _sanitize_agent_json(
    value: Any,
    *,
    key: str | None = None,
    dynamic_evidence: bool = False,
) -> Any:
    normalized_key = _normalize_agent_key(key) if key is not None else None
    if normalized_key == "prompt":
        return _REDACTED_DISPATCH_PROMPT
    if normalized_key in _AGENT_TRANSCRIPT_KEYS:
        return _REDACTED_AGENT_TRANSCRIPT
    if normalized_key in _AGENT_CREDENTIAL_KEYS:
        raise ValueError("agent records cannot persist credential material")
    if isinstance(value, dict):
        child_dynamic_evidence = dynamic_evidence or normalized_key in _AGENT_DYNAMIC_EVIDENCE_KEYS
        return {
            str(item_key): _sanitize_agent_json(
                item,
                key=str(item_key),
                dynamic_evidence=child_dynamic_evidence,
            )
            for item_key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_agent_json(item, key=key, dynamic_evidence=dynamic_evidence)
            for item in value
        ]
    if isinstance(value, str) and _AGENT_SECRET_VALUE_RE.search(value):
        raise ValueError("agent records cannot persist credential material")
    if isinstance(value, str) and dynamic_evidence and not _is_safe_evidence_key(normalized_key):
        return "[redacted agent evidence]"
    return value


def _normalize_agent_key(key: str) -> str:
    with_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    with_boundaries = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", with_boundaries)
    return re.sub(r"[^a-z0-9]+", "_", with_boundaries.lower()).strip("_")


def _is_safe_evidence_key(normalized_key: str | None) -> bool:
    if normalized_key is None:
        return False
    return (
        normalized_key in _AGENT_SAFE_EVIDENCE_KEYS
        or normalized_key.endswith(("_id", "_ref", "_hash", "_at", "_count", "_tokens", "_units"))
        or normalized_key.startswith("supports_")
        or normalized_key.endswith(("_available", "_healthy", "_enabled", "_supported"))
    )


def _load_dataclass(cls: type[Any], payload: str) -> Any:
    return dataclass_from_jsonable(cls, json.loads(payload))


# The provider-neutral driver design uses this descriptive name.  Retain
# SQLiteStore as the established public API for existing callers.
OverseerStore = SQLiteStore
