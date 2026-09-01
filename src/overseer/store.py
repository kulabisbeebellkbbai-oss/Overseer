"""SQLite persistence for local Overseer state."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .admin import (
    AdminChangePlan,
    AdminExecutionClaim,
    AdminExecutionClaimState,
    AdminExecutionResult,
    AdminHistoryArchiveRecord,
)
from .admin_authority import admin_authority_lock
from .agent_contracts import (
    AgentCheckpoint,
    AgentRecoveryAttempt,
    AgentRecoveryAttemptState,
    AgentRecoveryOutcome,
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
from .audit import ApprovalRequest, ApprovalStatus, AuditEvent, AuditEventType
from .claim_continuation import (
    ClaimActivationGroup,
    ClaimActivationGroupState,
    ClaimApprovalContinuation,
    ClaimApprovalContinuationAttempt,
)
from .collection_models import (
    CircuitState,
    CollectionJob,
    CollectionJobState,
    CollectionOutcome,
    CollectionRequest,
    CollectionRun,
    RepairAttempt,
    RepairRunbook,
    TriageIncident,
    TriageIncidentStatus,
)
from .collection_deadline import current_collection_deadline, require_collection_time
from .collection_policy import circuit_after_failure, next_failure_due, next_success_due
from .core import ApprovalLevel, Claim, ConflictDecision, OwnerDomain, Resource, RiskLevel
from .crew import CrewMessage
from .health import HealthEvidence, HealthTarget
from .host import HostInspectionSnapshot
from .ids_review import HostSecurityIDSReviewPackage
from .key_broker import KeyBrokerTokenGrant, KeyBrokerTokenRequest, KeyProviderRecord
from .maintenance_schedule import MaintenanceSchedule
from .ops_records import OperationRecord
from .packages import PackageInspectionRecord, PackageReconciliationEvidence
from .physical import PhysicalIdentity
from .runtime_state import RuntimeHeartbeat
from .serialization import dataclass_from_jsonable, to_jsonable
from .source_review import HostSecuritySourceReview
from .storage_adapter import StorageAdapterRegistration, StorageAuthorizationRecord, StorageRootAuthorizationRecord, StorageDispatchRecord, StorageExecutionRequest, StorageExecutionResult
from .usage_limits import UsageContinuationDispatch, UsageContinuationRequest, UsageLimit


CURRENT_SCHEMA_VERSION = 12
_SCHEMA_CURRENT_REQUIRED_TABLES = frozenset(
    {
        "schema_migrations",
        "agent_schema_migrations",
        "roadex_approval_fixtures",
        "psychlo_legacy_abandonment_execution_claims",
        "claim_approval_continuations",
        "claim_activation_groups",
        "claim_approval_continuation_attempts",
        "audit_event_normalization_state",
        "package_inspection_records",
        "package_reconciliation_evidence",
        "collection_jobs",
        "collection_job_states",
        "collection_requests",
        "collection_runs",
        "triage_incidents",
        "repair_runbooks",
        "repair_attempts",
        "dashboard_projections",
        "admin_change_plans",
        "admin_executions",
        "admin_execution_claims",
        "admin_history_archives",
    }
)
MAX_COLLECTION_PAYLOAD_LENGTH = 65536
MAX_DASHBOARD_PROJECTION_PAYLOAD_LENGTH = 512 * 1024
_COLLECTION_INDEX_SPECS = {
    "idx_collection_jobs_enabled_priority": {
        "table": "collection_jobs",
        "unique": 0,
        "partial": 0,
        "columns": (("enabled", 0), ("priority", 0)),
        "sql": "CREATE INDEX idx_collection_jobs_enabled_priority ON collection_jobs (enabled, priority)",
    },
    "idx_collection_job_state_due": {
        "table": "collection_job_states",
        "unique": 0,
        "partial": 0,
        "columns": (("next_due_at", 0), ("lease_expires_at", 0)),
        "sql": "CREATE INDEX idx_collection_job_state_due ON collection_job_states (next_due_at, lease_expires_at)",
    },
    "idx_collection_runs_job_started": {
        "table": "collection_runs",
        "unique": 0,
        "partial": 0,
        "columns": (("job_id", 0), ("started_at", 1)),
        "sql": "CREATE INDEX idx_collection_runs_job_started ON collection_runs (job_id, started_at DESC)",
    },
    "idx_collection_request_pending_job": {
        "table": "collection_requests",
        "unique": 1,
        "partial": 1,
        "columns": (("job_id", 0),),
        "sql": "CREATE UNIQUE INDEX idx_collection_request_pending_job ON collection_requests (job_id) WHERE status = 'pending'",
    },
    "idx_triage_open_generation": {
        "table": "triage_incidents",
        "unique": 1,
        "partial": 1,
        "columns": (("job_id", 0), ("generation", 0)),
        "sql": "CREATE UNIQUE INDEX idx_triage_open_generation ON triage_incidents (job_id, generation) WHERE status = 'open'",
    },
    "idx_host_snapshots_captured_at": {
        "table": "host_snapshots",
        "unique": 0,
        "partial": 0,
        "columns": (),
        "expression": True,
        "sql": (
            "CREATE INDEX idx_host_snapshots_captured_at ON host_snapshots "
            "(julianday(json_extract(payload, '$.captured_at')) DESC, id DESC)"
        ),
    },
}
_AUDIT_EVENT_INSERT_TRIGGER = "audit_events_validate_normalized_insert"
_AUDIT_EVENT_UPDATE_TRIGGER = "audit_events_validate_normalized_update"
_AUDIT_EVENT_PAYLOAD_PREDICATE = """
CASE WHEN json_valid(NEW.payload) THEN (
    json_type(NEW.payload) = 'object'
    AND (SELECT COUNT(*) FROM json_each(NEW.payload)) = 8
    AND (SELECT COUNT(DISTINCT key) FROM json_each(NEW.payload)) = 8
    AND NOT EXISTS (
        SELECT 1 FROM json_each(NEW.payload)
        WHERE key NOT IN (
            'id','event_type','owner_domain','subject_id','summary',
            'risk_level','evidence_ids','occurred_at'
        )
    )
    AND json_type(NEW.payload, '$.id') = 'text'
    AND json_type(NEW.payload, '$.event_type') = 'text'
    AND json_type(NEW.payload, '$.owner_domain') = 'text'
    AND json_type(NEW.payload, '$.subject_id') = 'text'
    AND json_type(NEW.payload, '$.summary') = 'text'
    AND json_type(NEW.payload, '$.risk_level') = 'text'
    AND json_type(NEW.payload, '$.evidence_ids') = 'array'
    AND NOT EXISTS (
        SELECT 1 FROM json_each(json_extract(NEW.payload, '$.evidence_ids'))
        WHERE type <> 'text'
    )
    AND json_type(NEW.payload, '$.occurred_at') IN ('text','null')
    AND json_extract(NEW.payload, '$.event_type') IN (
        'requested','alert','allowed','queued','blocked','escalated',
        'quarantined','approved','rejected','executed','verified','released'
    )
    AND json_extract(NEW.payload, '$.owner_domain') IN (
        'sisko','kira','obrien','odo','odo_ids','odo_firewall','quark','dax',
        'julian','ezri'
    )
    AND json_extract(NEW.payload, '$.risk_level') IN (
        'low','medium','high','critical'
    )
) ELSE 0 END
"""
_AUDIT_EVENT_VALID_PREDICATE = f"""
CASE WHEN COALESCE(({_AUDIT_EVENT_PAYLOAD_PREDICATE}), 0) = 1 THEN
    NEW.event_type = json_extract(NEW.payload, '$.event_type')
ELSE 0 END
"""
_AUDIT_EVENT_INSERT_TRIGGER_SQL = f"""
CREATE TRIGGER {_AUDIT_EVENT_INSERT_TRIGGER}
BEFORE INSERT ON audit_events
WHEN COALESCE(({_AUDIT_EVENT_VALID_PREDICATE}), 0) = 0
BEGIN SELECT RAISE(ABORT, 'invalid normalized audit event'); END
"""
_AUDIT_EVENT_UPDATE_TRIGGER_SQL = f"""
CREATE TRIGGER {_AUDIT_EVENT_UPDATE_TRIGGER}
BEFORE UPDATE OF payload, event_type ON audit_events
WHEN COALESCE((
    ({_AUDIT_EVENT_VALID_PREDICATE})
    OR (
        NEW.event_type IS NULL
        AND COALESCE(({_AUDIT_EVENT_PAYLOAD_PREDICATE}), 0) = 0
    )
), 0) = 0
BEGIN SELECT RAISE(ABORT, 'invalid normalized audit event'); END
"""
ROADEX_APPROVAL_FIXTURE_SCHEMA_VERSION = 3
AGENT_DRIVER_SCHEMA_VERSION = "agent_driver_v1"
AGENT_DRIVER_SCHEMA_V2 = "agent_driver_v2"
AGENT_DRIVER_SCHEMA_V3 = "agent_driver_v3"
AGENT_DRIVER_SCHEMA_V4 = "agent_driver_v4"
AGENT_DRIVER_SCHEMA_V5 = "agent_driver_v5"
AGENT_DRIVER_SCHEMA_V6 = "agent_driver_v6"
AGENT_DRIVER_SCHEMA_V7 = "agent_driver_v7"
AGENT_DRIVER_SCHEMA_V8 = "agent_driver_v8"
AGENT_DRIVER_SCHEMA_V9 = "agent_driver_v9"
_OBSERVATION_TABLE_NAME = "psychlo_process_observations"
_OBSERVATION_NO_DELETE_TRIGGER = "psychlo_process_observations_no_delete"
_OBSERVATION_IMMUTABLE_TRIGGER = "psychlo_process_observations_immutable"
_OBSERVATION_TABLE_SQL = (
    "create table psychlo_process_observations ( observation_id text primary key, "
    "round_id text not null unique, plan_id text not null, "
    "observation_digest text not null unique, plan_digest text not null default '', "
    "state text not null check(state in ('prepared','recorded')), "
    "manifest_json text not null, inserted_at text not null, recorded_at text )"
)
_OBSERVATION_NO_DELETE_TRIGGER_SQL = (
    "create trigger psychlo_process_observations_no_delete before delete on "
    "psychlo_process_observations begin select raise(abort, 'process observations are append-only'); end"
)
_OBSERVATION_IMMUTABLE_TRIGGER_SQL = (
    "create trigger psychlo_process_observations_immutable before update on "
    "psychlo_process_observations when new.observation_id <> old.observation_id "
    "or new.round_id <> old.round_id or new.plan_id <> old.plan_id "
    "or new.observation_digest <> old.observation_digest "
    "or new.manifest_json <> old.manifest_json or new.inserted_at <> old.inserted_at "
    "or old.state = 'recorded' or old.state <> 'prepared' or old.plan_digest <> '' "
    "or old.recorded_at is not null or new.state <> 'recorded' "
    "or new.plan_digest = '' or new.recorded_at is null begin select raise(abort, "
    "'historical process observation identity is immutable'); end"
)
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
_STRICT_DATABASE_PIN_LOCK = threading.Lock()
_STRICT_DATABASE_PINS: list[int] = []
_STRICT_DATABASE_PIN_LIMIT = 256


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
    """Small JSON-payload SQLite store with owner-only database artifacts.

    The database and SQLite-created sidecars are restricted to mode ``0600``.
    The containing directory's existing permissions are never broadened or
    otherwise changed.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        verified_fd: int | None = None,
        timeout_seconds: float = 30.0,
        strict_descriptor_binding: bool = False,
    ) -> None:
        if isinstance(timeout_seconds, bool) or float(timeout_seconds) <= 0:
            raise ValueError("SQLite timeout must be positive")
        if not isinstance(strict_descriptor_binding, bool):
            raise TypeError("strict_descriptor_binding must be a boolean")
        if strict_descriptor_binding and verified_fd is not None:
            raise ValueError(
                "strict descriptor binding rejects caller-owned verified_fd"
            )
        self._collection_deadline = current_collection_deadline()
        if strict_descriptor_binding and self._collection_deadline is not None:
            raise RuntimeError(
                "strict descriptor binding is unavailable during collection"
            )
        remaining = require_collection_time(self._collection_deadline)
        self._sqlite_timeout_seconds = (
            min(float(timeout_seconds), remaining)
            if remaining is not None
            else float(timeout_seconds)
        )
        self.path = Path(path)
        owned_verified_fd: int | None = None
        if strict_descriptor_binding:
            if threading.active_count() != 1:
                raise RuntimeError(
                    "strict descriptor binding requires a single-threaded process"
                )
            try:
                status = self.path.lstat()
            except FileNotFoundError as error:
                raise ValueError(
                    "strict descriptor binding requires a pre-existing SQLite store"
                ) from error
            self._validate_artifact_status(self.path, status)
            self._database_identity = (status.st_dev, status.st_ino)
        elif self._collection_deadline is not None and verified_fd is None:
            flags = os.O_RDWR | os.O_NONBLOCK
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            try:
                owned_verified_fd = os.open(self.path, flags)
            except FileNotFoundError as error:
                raise RuntimeError(
                    "collection persistence requires a pre-existing SQLite store"
                ) from error
            verified_fd = owned_verified_fd
        if not strict_descriptor_binding and verified_fd is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._database_identity = self._prepare_database_file()
        elif not strict_descriptor_binding:
            try:
                status = os.fstat(verified_fd)
                self._validate_artifact_status(self.path, status)
                self._database_identity = (status.st_dev, status.st_ino)
            except BaseException:
                if owned_verified_fd is not None:
                    os.close(owned_verified_fd)
                    owned_verified_fd = None
                raise
        self._sidecar_identities: dict[str, tuple[int, int]] = {}
        self._compromised_sidecars: set[str] = set()
        connection = None
        try:
            if strict_descriptor_binding:
                existing_descriptors = self._database_descriptors()
                if existing_descriptors:
                    raise ValueError(
                        "strict descriptor binding rejects a pre-existing SQLite descriptor"
                    )
                strict_pin = self._acquire_strict_database_pin()
                pinned_descriptors = self._database_descriptors()
                if pinned_descriptors != frozenset({strict_pin}):
                    raise ValueError(
                        f"SQLite descriptor pin identity cannot be verified: {self.path}"
                    )
                connection = sqlite3.connect(
                    f"file:/proc/self/fd/{strict_pin}?mode=rw",
                    uri=True,
                    timeout=self._sqlite_timeout_seconds,
                )
                self._verify_strict_connection_binding(
                    connection,
                    strict_pin,
                    pinned_descriptors,
                )
            elif verified_fd is None:
                connection = sqlite3.connect(
                    self.path,
                    timeout=self._sqlite_timeout_seconds,
                )
            else:
                connection = sqlite3.connect(
                    f"file:/proc/self/fd/{verified_fd}?mode=rw",
                    uri=True,
                    timeout=self._sqlite_timeout_seconds,
                )
            self._connection = connection
        except BaseException:
            if connection is not None:
                connection.close()
            raise
        finally:
            if owned_verified_fd is not None:
                os.close(owned_verified_fd)
        try:
            self._harden_database_files()
        except Exception:
            self._connection.close()
            raise
        self._connection.row_factory = sqlite3.Row
        self._agent_transaction_depth = 0
        try:
            if self._collection_deadline is None:
                self._configure_connection()
                self._initialize_with_lock_retry()
            else:
                if not self._schema_is_current():
                    raise RuntimeError(
                        "collection persistence requires a pre-migrated SQLite store"
                    )
                self._configure_connection(allow_journal_mode_change=False)
            self._harden_database_files()
        except BaseException:
            self._connection.close()
            raise

    def _prepare_database_file(self) -> tuple[int, int]:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except FileExistsError:
            status = self.path.lstat()
            self._validate_artifact_status(self.path, status)
            identity = (status.st_dev, status.st_ino)
            os.chmod(self.path, 0o600, follow_symlinks=False)
            hardened_status = self.path.lstat()
            if (hardened_status.st_dev, hardened_status.st_ino) != identity:
                raise ValueError(f"SQLite artifact identity changed: {self.path}")
            return identity
        else:
            try:
                status = os.fstat(descriptor)
                self._validate_artifact_status(self.path, status)
                os.fchmod(descriptor, 0o600)
                return status.st_dev, status.st_ino
            finally:
                os.close(descriptor)

    @staticmethod
    def _validate_artifact_status(path: Path, status: os.stat_result) -> None:
        if not stat.S_ISREG(status.st_mode):
            raise ValueError(
                f"SQLite artifact must be an owned regular file: {path}"
            )
        if hasattr(os, "geteuid") and status.st_uid != os.geteuid():
            raise PermissionError(
                f"SQLite artifact is not owned by this process: {path}"
            )
        if status.st_nlink != 1:
            raise ValueError(
                f"SQLite artifact must have exactly one link: {path}"
            )

    def _acquire_strict_database_pin(self) -> int:
        """Retain one bounded process-lifetime pin for a one-shot transition."""
        if not hasattr(os, "O_PATH"):
            raise RuntimeError("SQLite descriptor verification requires O_PATH")
        with _STRICT_DATABASE_PIN_LOCK:
            if len(_STRICT_DATABASE_PINS) >= _STRICT_DATABASE_PIN_LIMIT:
                raise RuntimeError("strict SQLite descriptor pin limit reached")
            flags = os.O_PATH
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            descriptor = os.open(self.path, flags)
            # Once opened, a strict pin is never closed by application code.
            # Retaining even a failed pin avoids releasing same-process POSIX
            # locks through an unmanaged descriptor. The bounded registry and
            # one-shot process contract cap this fail-closed retention.
            _STRICT_DATABASE_PINS.append(descriptor)
            try:
                status = os.fstat(descriptor)
                self._validate_artifact_status(self.path, status)
                if (status.st_dev, status.st_ino) != self._database_identity:
                    raise ValueError(
                        f"SQLite artifact identity changed: {self.path}"
                    )
            except BaseException:
                raise
            return descriptor

    def _database_descriptors(self) -> frozenset[int]:
        """Return only process descriptors bound to the prepared inode."""
        try:
            names = os.listdir("/proc/self/fd")
        except OSError as error:
            raise RuntimeError(
                "SQLite connection identity cannot be verified"
            ) from error
        descriptors: set[int] = set()
        for name in names:
            try:
                descriptor = int(name)
                status = os.fstat(descriptor)
            except (OSError, ValueError):
                continue
            if (
                stat.S_ISREG(status.st_mode)
                and (status.st_dev, status.st_ino) == self._database_identity
            ):
                descriptors.add(descriptor)
        return frozenset(descriptors)

    def _verify_strict_connection_binding(
        self,
        connection: sqlite3.Connection,
        strict_pin: int,
        pinned_descriptors: frozenset[int],
    ) -> None:
        database_descriptors = self._database_descriptors()
        connection_descriptors = database_descriptors - pinned_descriptors
        if pinned_descriptors != frozenset({strict_pin}) or len(connection_descriptors) != 1:
            raise ValueError(
                f"SQLite connection identity does not match artifact: {self.path}"
            )
        path_status = self.path.lstat()
        self._validate_artifact_status(self.path, path_status)
        if (path_status.st_dev, path_status.st_ino) != self._database_identity:
            raise ValueError(f"SQLite artifact identity changed: {self.path}")
        try:
            connection.execute("PRAGMA schema_version").fetchone()
        except sqlite3.Error as error:
            raise ValueError(
                f"SQLite connection identity cannot be verified: {self.path}"
            ) from error

    def _harden_database_files(
        self, *, database_missing_ok: bool = False
    ) -> bool:
        try:
            database_status = self.path.lstat()
        except FileNotFoundError:
            if not database_missing_ok:
                raise
            return False
        self._validate_artifact_status(self.path, database_status)
        if (database_status.st_dev, database_status.st_ino) != self._database_identity:
            raise ValueError(f"SQLite artifact identity changed: {self.path}")
        os.chmod(self.path, 0o600, follow_symlinks=False)
        hardened_status = self.path.lstat()
        if (hardened_status.st_dev, hardened_status.st_ino) != self._database_identity:
            raise ValueError(f"SQLite artifact identity changed: {self.path}")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{self.path}{suffix}")
            try:
                identity = self._inspect_sidecar_and_harden(sidecar, suffix)
            except (ValueError, PermissionError):
                self._compromised_sidecars.add(suffix)
                raise
            if identity is not None:
                self._sidecar_identities[suffix] = identity
        return True

    def _inspect_sidecar_and_harden(
        self, sidecar: Path, suffix: str
    ) -> tuple[int, int] | None:
        """Validate a sidecar without opening an auxiliary descriptor.

        POSIX record locks are process-scoped: closing *any* descriptor for a
        file can release locks acquired through another SQLite connection in
        the process. Use no-follow path operations plus identity rechecks so
        nested stores cannot disturb each other's locks.
        """

        expected = self._sidecar_identities.get(suffix)
        try:
            path_status = sidecar.lstat()
        except FileNotFoundError:
            return None
        self._validate_artifact_status(sidecar, path_status)
        path_identity = (path_status.st_dev, path_status.st_ino)
        if expected == path_identity and stat.S_IMODE(path_status.st_mode) == 0o600:
            return path_identity

        try:
            status = sidecar.lstat()
        except FileNotFoundError:
            # A checkpoint may remove a sidecar between the initial
            # inspection and this identity re-check.
            return None
        self._validate_artifact_status(sidecar, status)
        identity = (status.st_dev, status.st_ino)
        if expected is not None and identity != expected:
            if stat.S_IMODE(status.st_mode) != 0o600:
                raise ValueError(f"SQLite artifact identity changed: {sidecar}")
        try:
            os.chmod(sidecar, 0o600, follow_symlinks=False)
            hardened_status = sidecar.lstat()
        except FileNotFoundError:
            # WAL and rollback-journal files may disappear between inspection
            # and hardening when another legitimate connection checkpoints.
            return None
        if (hardened_status.st_dev, hardened_status.st_ino) != identity:
            raise ValueError(f"SQLite artifact identity changed: {sidecar}")
        return identity

    def _stash_compromised_sidecars(self) -> list[tuple[Path, Path]]:
        stashed: list[tuple[Path, Path]] = []
        for suffix in sorted(self._compromised_sidecars):
            sidecar = Path(f"{self.path}{suffix}")
            try:
                sidecar.lstat()
            except FileNotFoundError:
                continue
            quarantine = sidecar.with_name(
                f".{sidecar.name}.untrusted.{secrets.token_hex(16)}"
            )
            os.replace(sidecar, quarantine)
            stashed.append((sidecar, quarantine))
        return stashed

    def _configure_connection(self, *, allow_journal_mode_change: bool = True) -> None:
        busy_timeout_ms = max(1, int(self._sqlite_timeout_seconds * 1000))
        self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        try:
            # Overseer has a long-lived coordinator and API plus short-lived
            # CLI writers. WAL keeps readers from blocking the coordinator's
            # writes, while the busy timeout serializes competing writers.
            # FULL synchronous durability is intentional for coordination
            # state: a completed commit must survive an OS crash or power loss.
            journal_mode = self._connection.execute("PRAGMA journal_mode").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                if not allow_journal_mode_change:
                    raise RuntimeError(
                        "collection persistence requires a preconfigured WAL SQLite store"
                    )
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        except sqlite3.OperationalError:
            if not allow_journal_mode_change:
                raise
            pass
        self._harden_database_files()

    def _initialize_with_lock_retry(self) -> None:
        """Run idempotent schema setup despite transient WAL lock recovery.

        SQLite can return ``SQLITE_PROTOCOL`` (reported by Python as
        ``locking protocol``) when several fresh processes race to recover or
        initialize the same WAL. Unlike ``SQLITE_BUSY``, busy_timeout does not
        retry that result for us.
        """

        if self._observation_schema_status() == "invalid":
            raise sqlite3.DatabaseError("psychlo process observation schema is incompatible")
        if self._schema_is_current():
            return
        for attempt in range(10):
            try:
                if self._observation_schema_status() == "invalid":
                    raise sqlite3.DatabaseError("psychlo process observation schema is incompatible")
                if self._schema_is_current():
                    return
                self.initialize()
                if self._observation_schema_status() != "exact":
                    raise sqlite3.DatabaseError("psychlo process observation schema is incomplete")
                return
            except sqlite3.OperationalError as error:
                self._connection.rollback()
                if "locking protocol" not in str(error).lower() or attempt == 9:
                    raise
                time.sleep(0.05 * (attempt + 1))

    @staticmethod
    def _normalize_schema_sql(sql: str | None) -> str:
        return " ".join((sql or "").strip().lower().split())

    def _observation_schema_status(self) -> str:
        """Classify the additive observation schema before any initialization."""
        objects = {
            str(row[1]): (str(row[0]), row[2])
            for row in self._connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name IN (?, ?, ?)"
                , (_OBSERVATION_TABLE_NAME, _OBSERVATION_NO_DELETE_TRIGGER,
                   _OBSERVATION_IMMUTABLE_TRIGGER)
            ).fetchall()
        }
        table = objects.get(_OBSERVATION_TABLE_NAME)
        if table is None:
            if any(name in objects for name in (
                    _OBSERVATION_NO_DELETE_TRIGGER, _OBSERVATION_IMMUTABLE_TRIGGER)):
                return "invalid"
            return "absent"
        if table[0] != "table":
            return "invalid"
        columns = [
            (str(row[1]), str(row[2]), int(row[3]), row[4], int(row[5]))
            for row in self._connection.execute(
                "PRAGMA table_info(psychlo_process_observations)"
            ).fetchall()
        ]
        expected_columns = [
            ("observation_id", "TEXT", 0, None, 1),
            ("round_id", "TEXT", 1, None, 0),
            ("plan_id", "TEXT", 1, None, 0),
            ("observation_digest", "TEXT", 1, None, 0),
            ("plan_digest", "TEXT", 1, "''", 0),
            ("state", "TEXT", 1, None, 0),
            ("manifest_json", "TEXT", 1, None, 0),
            ("inserted_at", "TEXT", 1, None, 0),
            ("recorded_at", "TEXT", 0, None, 0),
        ]
        if columns != expected_columns or self._normalize_schema_sql(table[1]) != _OBSERVATION_TABLE_SQL:
            return "invalid"
        expected_unique_indexes = {
            ("pk", ("observation_id",)),
            ("u", ("round_id",)),
            ("u", ("observation_digest",)),
        }
        unique_indexes: set[tuple[str, tuple[str, ...]]] = set()
        for index in self._connection.execute(
                "PRAGMA index_list(psychlo_process_observations)").fetchall():
            if int(index[2]) != 1:
                # Additional non-unique indexes are allowed; they cannot
                # change the identity/uniqueness contract.
                continue
            origin = str(index[3])
            partial = int(index[4])
            index_columns = self._connection.execute(
                "SELECT name, seqno, cid FROM pragma_index_info(?)", (str(index[1]),)
            ).fetchall()
            names = tuple(str(row[0]) for row in index_columns)
            if len(index_columns) != 1 or int(index_columns[0][1]) != 0:
                return "invalid"
            xinfo = [tuple(row) for row in self._connection.execute(
                "SELECT seqno, cid, name, desc, coll, key FROM pragma_index_xinfo(?)",
                (str(index[1]),)
            ).fetchall()]
            cid = int(index_columns[0][2])
            if xinfo != [(0, cid, names[0], 0, "BINARY", 1),
                         (1, -1, None, 0, "BINARY", 0)]:
                return "invalid"
            unique_indexes.add((origin, names))
            if partial != 0:
                return "invalid"
        if unique_indexes != expected_unique_indexes:
            return "invalid"
        for name, expected_sql in (
            (_OBSERVATION_NO_DELETE_TRIGGER, _OBSERVATION_NO_DELETE_TRIGGER_SQL),
            (_OBSERVATION_IMMUTABLE_TRIGGER, _OBSERVATION_IMMUTABLE_TRIGGER_SQL),
        ):
            trigger = objects.get(name)
            if trigger is None:
                continue
            if trigger[0] != "trigger" or self._normalize_schema_sql(trigger[1]) != expected_sql:
                return "invalid"
        if all(name in objects for name in (
                _OBSERVATION_NO_DELETE_TRIGGER, _OBSERVATION_IMMUTABLE_TRIGGER)):
            return "exact"
        return "missing_triggers"

    def _collection_index_is_canonical(self, index_name: str) -> bool:
        spec = _COLLECTION_INDEX_SPECS.get(index_name)
        if spec is None:
            return False
        row = self._connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
            (index_name,),
        ).fetchone()
        if row is None:
            return False
        index_rows = self._connection.execute(
            f"PRAGMA index_list({spec['table']})"
        ).fetchall()
        index_row = next(
            (item for item in index_rows if str(item[1]) == index_name), None
        )
        if index_row is None:
            return False
        if int(index_row[2]) != int(spec["unique"]) or int(index_row[4]) != int(spec["partial"]):
            return False
        if spec.get("expression"):
            return self._normalize_schema_sql(str(row["sql"])) == self._normalize_schema_sql(
                str(spec["sql"])
            )
        columns = self._connection.execute(
            "SELECT name, seqno FROM pragma_index_info(?) ORDER BY seqno",
            (index_name,),
        ).fetchall()
        if tuple((str(item[0]), int(item[1])) for item in columns) != tuple(
            (name, sequence) for sequence, (name, _descending) in enumerate(spec["columns"])
        ):
            return False
        sort_columns = self._connection.execute(
            "SELECT name, desc, key FROM pragma_index_xinfo(?) "
            "WHERE key=1 ORDER BY seqno",
            (index_name,),
        ).fetchall()
        if tuple((str(item[0]), int(item[1])) for item in sort_columns) != tuple(
            (name, descending) for name, descending in spec["columns"]
        ):
            return False
        if int(spec["partial"]):
            return self._normalize_schema_sql(str(row["sql"])) == self._normalize_schema_sql(
                str(spec["sql"])
            )
        return True

    def _schema_is_current(self) -> bool:
        if self._observation_schema_status() != "exact":
            return False
        required_tables = tuple(sorted(_SCHEMA_CURRENT_REQUIRED_TABLES))
        placeholders = ", ".join("?" for _ in required_tables)
        tables = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                f"AND name IN ({placeholders})",
                required_tables,
            ).fetchall()
        }
        if tables != _SCHEMA_CURRENT_REQUIRED_TABLES:
            return False
        if not all(
            self._collection_index_is_canonical(index_name)
            for index_name in _COLLECTION_INDEX_SPECS
        ):
            return False
        schema_current = self._connection.execute(
            "SELECT MAX(version) AS version FROM schema_migrations"
        ).fetchone()
        agent_current = self._connection.execute(
            "SELECT 1 FROM agent_schema_migrations WHERE version = ?",
            (AGENT_DRIVER_SCHEMA_V9,),
        ).fetchone()
        audit_index = self._connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
            ("idx_audit_events_event_type_v4",),
        ).fetchone()
        obsolete_audit_index = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
            ("idx_audit_events_event_type_v3",),
        ).fetchone()
        audit_triggers = {
            str(row["name"]): str(row["sql"])
            for row in self._connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger' "
                "AND name IN (?, ?)",
                (_AUDIT_EVENT_INSERT_TRIGGER, _AUDIT_EVENT_UPDATE_TRIGGER),
            ).fetchall()
        }
        audit_columns = {
            str(row[1]): (str(row[2]).upper(), int(row[3]), row[4], int(row[5]))
            for row in self._connection.execute("PRAGMA table_info(audit_events)").fetchall()
        }
        expected_audit_index_sql = """
            CREATE INDEX idx_audit_events_event_type_v4
            ON audit_events (event_type)
        """
        audit_normalization = self._connection.execute(
            "SELECT generation, state FROM audit_event_normalization_state "
            "WHERE id=1"
        ).fetchone()
        return (
            schema_current is not None
            and schema_current["version"] is not None
            and int(schema_current["version"]) >= CURRENT_SCHEMA_VERSION
            and agent_current is not None
            and audit_columns.get("event_type") == ("TEXT", 0, None, 0)
            and audit_normalization is not None
            and int(audit_normalization["generation"]) == CURRENT_SCHEMA_VERSION
            and str(audit_normalization["state"]) == "complete"
            and audit_index is not None
            and obsolete_audit_index is None
            and self._normalize_schema_sql(str(audit_index["sql"]))
            == self._normalize_schema_sql(expected_audit_index_sql)
            and self._normalize_schema_sql(
                audit_triggers.get(_AUDIT_EVENT_INSERT_TRIGGER)
            )
            == self._normalize_schema_sql(_AUDIT_EVENT_INSERT_TRIGGER_SQL)
            and self._normalize_schema_sql(
                audit_triggers.get(_AUDIT_EVENT_UPDATE_TRIGGER)
            )
            == self._normalize_schema_sql(_AUDIT_EVENT_UPDATE_TRIGGER_SQL)
        )

    def close(self) -> None:
        failure: Exception | None = None
        stashed: list[tuple[Path, Path]] = []
        try:
            try:
                self._harden_database_files(database_missing_ok=True)
            except (ValueError, PermissionError) as error:
                failure = error
                stashed = self._stash_compromised_sidecars()
        finally:
            self._connection.close()
            for sidecar, quarantine in stashed:
                if quarantine.exists():
                    os.replace(quarantine, sidecar)
        if failure is None:
            try:
                self._harden_database_files(database_missing_ok=True)
            except (ValueError, PermissionError) as error:
                failure = error
        if failure is not None:
            raise failure

    def _commit(self) -> None:
        require_collection_time(self._collection_deadline)
        self._harden_database_files()
        require_collection_time(self._collection_deadline)
        self._connection.commit()
        self._harden_database_files()

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def _migrate_audit_event_schema(self) -> None:
        # Install/repair the normalized schema under a short exclusive writer
        # transaction. Historical payload parsing happens in bounded batches
        # below so concurrent store users are not locked out for the full
        # backfill.
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            columns = {
                str(row[1]): (str(row[2]).upper(), int(row[3]), row[4], int(row[5]))
                for row in self._connection.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            event_type_column = columns.get("event_type")
            if event_type_column is None:
                self._connection.execute(
                    "ALTER TABLE audit_events ADD COLUMN event_type TEXT"
                )
            elif event_type_column != ("TEXT", 0, None, 0):
                raise sqlite3.DatabaseError(
                    "audit event_type column schema is incompatible"
                )
            self._connection.execute(
                "INSERT INTO audit_event_normalization_state "
                "(id, generation, state) VALUES (1, ?, 'backfilling') "
                "ON CONFLICT(id) DO UPDATE SET generation=excluded.generation, "
                "state=excluded.state",
                (CURRENT_SCHEMA_VERSION,),
            )

            # Schema v8 briefly used an application-defined expression index.
            # Remove it so standard SQLite integrity tooling remains usable.
            self._connection.execute(
                "DROP INDEX IF EXISTS idx_audit_events_event_type_v3"
            )
            existing = self._connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
                ("idx_audit_events_event_type_v4",),
            ).fetchone()
            expected = self._normalize_schema_sql(
                "CREATE INDEX idx_audit_events_event_type_v4 "
                "ON audit_events (event_type)"
            )
            if existing is not None and self._normalize_schema_sql(
                str(existing["sql"])
            ) != expected:
                self._connection.execute("DROP INDEX idx_audit_events_event_type_v4")
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_event_type_v4 "
                "ON audit_events (event_type)"
            )
            for trigger_name, trigger_sql in (
                (_AUDIT_EVENT_INSERT_TRIGGER, _AUDIT_EVENT_INSERT_TRIGGER_SQL),
                (_AUDIT_EVENT_UPDATE_TRIGGER, _AUDIT_EVENT_UPDATE_TRIGGER_SQL),
            ):
                self._connection.execute(f"DROP TRIGGER IF EXISTS {trigger_name}")
                self._connection.execute(trigger_sql)
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

        last_rowid = 0
        while True:
            rows = self._connection.execute(
                "SELECT rowid AS audit_rowid, id, payload, event_type "
                "FROM audit_events WHERE rowid > ? ORDER BY rowid LIMIT 1000",
                (last_rowid,),
            ).fetchall()
            if not rows:
                break
            updates: list[tuple[str | None, str, str, str | None]] = []
            for row in rows:
                payload = str(row["payload"])
                expected_type = _validated_audit_event_type(payload)
                if row["event_type"] != expected_type:
                    updates.append(
                        (expected_type, str(row["id"]), payload, row["event_type"])
                    )
            if updates:
                self._connection.execute("BEGIN IMMEDIATE")
                try:
                    self._connection.executemany(
                        "UPDATE audit_events SET event_type=? "
                        "WHERE id=? AND payload=? AND event_type IS ?",
                        updates,
                    )
                    self._connection.commit()
                except Exception:
                    self._connection.rollback()
                    raise
            last_rowid = int(rows[-1]["audit_rowid"])

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "UPDATE audit_event_normalization_state SET state='complete' "
                "WHERE id=1 AND generation=?",
                (CURRENT_SCHEMA_VERSION,),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def _repair_collection_index_rows_in_transaction(self) -> None:
        for index_name in _COLLECTION_INDEX_SPECS:
            self._connection.execute(f"DROP INDEX IF EXISTS {index_name}")

        pending_jobs: set[str] = set()
        pending_rows = self._connection.execute(
            "SELECT payload FROM collection_requests WHERE status='pending' "
            "ORDER BY job_id ASC, id ASC"
        ).fetchall()
        for row in pending_rows:
            request = _load_dataclass(CollectionRequest, str(row["payload"]))
            if request.job_id not in pending_jobs:
                pending_jobs.add(request.job_id)
                continue
            self._update_collection_request_in_transaction(
                replace(
                    request,
                    status="coalesced",
                    terminal_disposition="coalesced",
                )
            )

        open_generations: set[tuple[str, int]] = set()
        incident_rows = self._connection.execute(
            "SELECT payload FROM triage_incidents WHERE status='open' "
            "ORDER BY job_id ASC, generation ASC, id ASC"
        ).fetchall()
        for row in incident_rows:
            incident = _load_dataclass(TriageIncident, str(row["payload"]))
            key = (incident.job_id, incident.generation)
            if key not in open_generations:
                open_generations.add(key)
                continue
            self._upsert_collection_incident_in_transaction(
                replace(
                    incident,
                    status=TriageIncidentStatus.RESOLVED,
                    repair_state="coalesced",
                    resolution="legacy duplicate incident generation coalesced",
                )
            )

    def _migrate_collection_schema(self) -> None:
        """Install the v12 normalized scheduler schema as one rollback unit."""

        savepoint = "collection_schema_v12"
        self._connection.execute(f"SAVEPOINT {savepoint}")
        try:
            schema_sql = f"""
                CREATE TABLE IF NOT EXISTS collection_jobs (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    owner_domain TEXT NOT NULL,
                    resource_id TEXT,
                    target_id TEXT,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
                    interval_seconds INTEGER NOT NULL,
                    jitter_seconds INTEGER NOT NULL,
                    timeout_seconds INTEGER NOT NULL,
                    priority INTEGER NOT NULL,
                    concurrency_key TEXT NOT NULL,
                    retention_limit INTEGER NOT NULL,
                    repair_policy TEXT NOT NULL,
                    max_backoff_seconds INTEGER NOT NULL,
                    failure_threshold INTEGER NOT NULL,
                    payload TEXT NOT NULL CHECK(length(payload) <= {MAX_COLLECTION_PAYLOAD_LENGTH})
                );
                CREATE TABLE IF NOT EXISTS collection_job_states (
                    job_id TEXT PRIMARY KEY,
                    next_due_at TEXT NOT NULL,
                    last_started_at TEXT,
                    last_completed_at TEXT,
                    last_outcome TEXT,
                    consecutive_failures INTEGER NOT NULL,
                    circuit_state TEXT NOT NULL,
                    cooldown_until TEXT,
                    active_lease_id TEXT,
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    lease_generation INTEGER NOT NULL,
                    payload TEXT NOT NULL CHECK(length(payload) <= {MAX_COLLECTION_PAYLOAD_LENGTH})
                );
                CREATE TABLE IF NOT EXISTS collection_requests (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    requester TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    requested_at TEXT NOT NULL,
                    earliest_execution_at TEXT,
                    status TEXT NOT NULL,
                    terminal_disposition TEXT,
                    payload TEXT NOT NULL CHECK(length(payload) <= {MAX_COLLECTION_PAYLOAD_LENGTH})
                );
                CREATE TABLE IF NOT EXISTS collection_runs (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    trigger TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    evidence_ids TEXT NOT NULL,
                    error_category TEXT NOT NULL,
                    retry_disposition TEXT NOT NULL,
                    request_id TEXT,
                    payload TEXT NOT NULL CHECK(length(payload) <= {MAX_COLLECTION_PAYLOAD_LENGTH})
                );
                CREATE TABLE IF NOT EXISTS triage_incidents (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    first_failure_at TEXT NOT NULL,
                    latest_failure_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    owner_domain TEXT NOT NULL,
                    evidence_ids TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('open', 'resolved')),
                    repair_state TEXT NOT NULL,
                    resolution TEXT,
                    generation INTEGER NOT NULL,
                    payload TEXT NOT NULL CHECK(length(payload) <= {MAX_COLLECTION_PAYLOAD_LENGTH})
                );
                CREATE TABLE IF NOT EXISTS repair_runbooks (
                    id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    failure_categories TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    idempotency_contract TEXT NOT NULL,
                    cooldown_seconds INTEGER NOT NULL,
                    approval_required INTEGER NOT NULL CHECK(approval_required IN (0, 1)),
                    adapter_binding TEXT NOT NULL,
                    payload TEXT NOT NULL CHECK(length(payload) <= {MAX_COLLECTION_PAYLOAD_LENGTH})
                );
                CREATE TABLE IF NOT EXISTS repair_attempts (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    runbook_id TEXT NOT NULL,
                    attempted_at TEXT NOT NULL,
                    authorization_id TEXT,
                    outcome TEXT NOT NULL,
                    result_evidence_ids TEXT NOT NULL,
                    verification_run_id TEXT,
                    payload TEXT NOT NULL CHECK(length(payload) <= {MAX_COLLECTION_PAYLOAD_LENGTH})
                );
                """
            for statement in schema_sql.split(";"):
                if statement.strip():
                    self._connection.execute(statement)
            self._repair_collection_index_rows_in_transaction()
            for index_name, spec in _COLLECTION_INDEX_SPECS.items():
                self._connection.execute(str(spec["sql"]))
        except Exception:
            self._connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        else:
            self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")

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
            CREATE TABLE IF NOT EXISTS claim_approval_continuations (
                id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL,
                approval_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS claim_activation_groups (
                id TEXT PRIMARY KEY,
                lifecycle_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS claim_approval_continuation_attempts (
                id TEXT PRIMARY KEY,
                continuation_id TEXT NOT NULL,
                attempted_at TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                event_type TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_event_normalization_state (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                generation INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('backfilling','complete'))
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
            CREATE TABLE IF NOT EXISTS admin_execution_claims (
                id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_history_archives (
                id TEXT PRIMARY KEY,
                plan_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS package_inspection_records (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS package_reconciliation_evidence (
                id TEXT PRIMARY KEY,
                snapshot_id TEXT NOT NULL,
                maintenance_batch_id TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_package_reconciliation_snapshot
            ON package_reconciliation_evidence (snapshot_id);
            CREATE INDEX IF NOT EXISTS idx_package_reconciliation_batch
            ON package_reconciliation_evidence (maintenance_batch_id);
            CREATE TABLE IF NOT EXISTS psychlo_legacy_abandonment_execution_claims (
                plan_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL UNIQUE,
                action_digest TEXT NOT NULL UNIQUE,
                plan_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('claimed','completed')),
                claimed_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS psychlo_process_observations (
                observation_id TEXT PRIMARY KEY,
                round_id TEXT NOT NULL UNIQUE,
                plan_id TEXT NOT NULL,
                observation_digest TEXT NOT NULL UNIQUE,
                plan_digest TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL CHECK(state IN ('prepared','recorded')),
                manifest_json TEXT NOT NULL,
                inserted_at TEXT NOT NULL,
                recorded_at TEXT
            );
            CREATE TRIGGER IF NOT EXISTS psychlo_process_observations_no_delete
            BEFORE DELETE ON psychlo_process_observations
            BEGIN SELECT RAISE(ABORT, 'process observations are append-only'); END;
            CREATE TRIGGER IF NOT EXISTS psychlo_process_observations_immutable
            BEFORE UPDATE ON psychlo_process_observations
            WHEN NEW.observation_id <> OLD.observation_id
              OR NEW.round_id <> OLD.round_id
              OR NEW.plan_id <> OLD.plan_id
              OR NEW.observation_digest <> OLD.observation_digest
              OR NEW.manifest_json <> OLD.manifest_json
              OR NEW.inserted_at <> OLD.inserted_at
              OR OLD.state = 'recorded'
              OR OLD.state <> 'prepared'
              OR OLD.plan_digest <> ''
              OR OLD.recorded_at IS NOT NULL
              OR NEW.state <> 'recorded'
              OR NEW.plan_digest = ''
              OR NEW.recorded_at IS NULL
            BEGIN SELECT RAISE(ABORT, 'historical process observation identity is immutable'); END;
            CREATE TABLE IF NOT EXISTS roadex_approval_bindings (
                approval_ref TEXT PRIMARY KEY,
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
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
            CREATE TABLE IF NOT EXISTS dashboard_projections (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL CHECK(length(payload) <= 524288)
            );
            CREATE TABLE IF NOT EXISTS storage_adapter_registrations (id TEXT PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS storage_execution_requests (id TEXT PRIMARY KEY, adapter_id TEXT NOT NULL, project_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, payload TEXT NOT NULL, UNIQUE(adapter_id, project_id, idempotency_key));
            CREATE TABLE IF NOT EXISTS storage_dispatch_records (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS storage_execution_results (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS storage_authorizations (id TEXT PRIMARY KEY, request_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS storage_root_authorizations (id TEXT PRIMARY KEY, project_id TEXT NOT NULL, root_id TEXT NOT NULL, status TEXT NOT NULL, payload TEXT NOT NULL);
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
            CREATE INDEX IF NOT EXISTS idx_roadex_approval_bindings_source_kind ON roadex_approval_bindings (source_kind);
            CREATE INDEX IF NOT EXISTS idx_roadex_approval_bindings_source_id ON roadex_approval_bindings (source_id);
            """
        )
        self._migrate_audit_event_schema()
        self._connection.execute("BEGIN IMMEDIATE")
        with self._connection:
            has_schema_history = self._connection.execute(
                "SELECT 1 FROM schema_migrations LIMIT 1"
            ).fetchone() is not None
            self._migrate_roadex_approval_fixture_schema()
            self._migrate_collection_schema()
            if not has_schema_history:
                self._record_schema_migration(
                    CURRENT_SCHEMA_VERSION,
                    "bootstrap JSON payload store",
                )
            else:
                current_version = self._connection.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                ).fetchone()[0]
                if current_version is None or int(current_version) < CURRENT_SCHEMA_VERSION:
                    self._record_schema_migration(
                        CURRENT_SCHEMA_VERSION,
                        "persist normalized collection schedules, leases, and triage",
                    )
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
                CREATE TABLE IF NOT EXISTS agent_private_metadata (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                )
                """
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO agent_private_metadata(key, value) VALUES (?, ?)",
                ("handoff_hmac_sha256_v1", secrets.token_bytes(32)),
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
                "agent_recovery_attempts",
                "agent_recovery_outcomes",
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
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V8,
                "persist crash-safe provider recovery attempts and outcomes",
            )
            self._record_agent_schema_migration(
                AGENT_DRIVER_SCHEMA_V9,
                "attest new handoffs; legacy unsigned packages remain fail-safe invalid",
            )

    def _migrate_roadex_approval_fixture_schema(self) -> None:
        """Install the non-operational Roadex fixture table across schema versions."""
        savepoint = "roadex_approval_fixture_schema"
        self._connection.execute(f"SAVEPOINT {savepoint}")
        try:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS roadex_approval_fixtures (
                    id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                )
                """
            )
            recorded = self._connection.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?",
                (ROADEX_APPROVAL_FIXTURE_SCHEMA_VERSION,),
            ).fetchone()
            if recorded is None:
                self._record_schema_migration(
                    ROADEX_APPROVAL_FIXTURE_SCHEMA_VERSION,
                    "persist non-operational Roadex approval fixtures",
                )
        except Exception:
            self._connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        else:
            self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")

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
        savepoint = f"agent_transaction_{self._agent_transaction_depth}"
        require_collection_time(self._collection_deadline)
        if outermost:
            self._connection.execute("BEGIN IMMEDIATE")
        else:
            self._connection.execute(f"SAVEPOINT {savepoint}")
        self._agent_transaction_depth += 1
        try:
            yield
        except Exception:
            self._agent_transaction_depth -= 1
            if outermost:
                self._connection.rollback()
            else:
                self._connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise
        else:
            self._agent_transaction_depth -= 1
            if outermost:
                self._commit()
            else:
                self._connection.execute(f"RELEASE SAVEPOINT {savepoint}")

    def _commit_agent_mutation(self) -> None:
        if self._agent_transaction_depth == 0:
            self._commit()

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
        self._commit()
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

    def sign_and_save_agent_handoff(
        self, handoff: AgentHandoffPackage
    ) -> AgentHandoffPackage:
        from dataclasses import replace
        from .agent_handoff import canonical_handoff_bytes

        with self.agent_transaction():
            versioned = replace(
                handoff, attestation_version="hmac-sha256-v1", signature=None
            )
            signature = hmac.new(
                self._handoff_attestation_key(),
                canonical_handoff_bytes(versioned),
                hashlib.sha256,
            ).hexdigest()
            signed = replace(versioned, signature=signature)
            self.save_agent_handoff(signed)
        return signed

    def verify_agent_handoff_attestation(
        self, handoff: AgentHandoffPackage
    ) -> bool:
        from .agent_handoff import canonical_handoff_bytes

        if (
            handoff.attestation_version != "hmac-sha256-v1"
            or handoff.signature is None
        ):
            return False
        try:
            persisted = self.load_agent_handoff(handoff.id)
        except KeyError:
            return False
        if persisted != handoff:
            return False
        expected = hmac.new(
            self._handoff_attestation_key(),
            canonical_handoff_bytes(handoff),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, handoff.signature)

    def _handoff_attestation_key(self) -> bytes:
        row = self._connection.execute(
            "SELECT value FROM agent_private_metadata WHERE key = ?",
            ("handoff_hmac_sha256_v1",),
        ).fetchone()
        if row is None:
            raise RuntimeError("handoff attestation key is unavailable")
        return bytes(row["value"])

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
            FailoverExecutionState.RESERVED: {
                FailoverExecutionState.DRAINING,
                FailoverExecutionState.RECOVERED,
            },
            FailoverExecutionState.DRAINING: {
                FailoverExecutionState.BLOCKED_PREIMPORT,
                FailoverExecutionState.TRANSITION_STARTED,
                FailoverExecutionState.RECOVERED,
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

    def save_agent_recovery_attempt(self, attempt: AgentRecoveryAttempt) -> None:
        self._save_agent_record(
            "agent_recovery_attempts", attempt, AgentRecoveryAttempt,
            (
                "id", "idempotency_key", "execution_id", "decision_id",
                "instance_id", "outgoing_epoch_id", "provider_id",
                "internal_session_id", "external_session_id",
                "operation_generation", "operation_owner_ref", "created_at",
            ),
            {},
        )

    def claim_failover_recovery(
        self, execution_id: str, attempt: AgentRecoveryAttempt, *, updated_at: str
    ) -> FailoverExecution:
        with self.agent_transaction():
            if self.recovery_attempt_for_execution(execution_id) is not None:
                raise ValueError("recovery attempt already exists")
            execution = self.transition_failover_execution(
                execution_id,
                expected_state=FailoverExecutionState.BLOCKED_PREIMPORT,
                state=FailoverExecutionState.RECOVERING,
                updated_at=updated_at,
            )
            self.save_agent_recovery_attempt(attempt)
            return execution

    def load_agent_recovery_attempt(self, attempt_id: str) -> AgentRecoveryAttempt:
        return _load_dataclass(
            AgentRecoveryAttempt,
            self._get_payload("agent_recovery_attempts", attempt_id),
        )

    def recovery_attempt_for_execution(
        self, execution_id: str
    ) -> AgentRecoveryAttempt | None:
        matches = tuple(
            item for item in (
                _load_dataclass(AgentRecoveryAttempt, payload)
                for payload in self._list_payloads("agent_recovery_attempts")
            ) if item.execution_id == execution_id
        )
        if len(matches) > 1:
            raise ValueError("multiple recovery attempts for one execution")
        return matches[0] if matches else None

    def transition_agent_recovery_attempt(
        self,
        attempt_id: str,
        *,
        expected_state: AgentRecoveryAttemptState,
        state: AgentRecoveryAttemptState,
        updated_at: str,
    ) -> AgentRecoveryAttempt:
        current = self.load_agent_recovery_attempt(attempt_id)
        if current.state is not expected_state:
            raise ValueError("recovery attempt state changed")
        updated = dataclass_from_jsonable(
            AgentRecoveryAttempt,
            {**to_jsonable(current), "state": state.value, "updated_at": updated_at},
        )
        cursor = self._connection.execute(
            "UPDATE agent_recovery_attempts SET payload = ? WHERE id = ? "
            "AND json_extract(payload, '$.state') = ?",
            (_dump_agent_record(updated), attempt_id, expected_state.value),
        )
        if cursor.rowcount != 1:
            raise ValueError("recovery attempt state changed")
        self._commit_agent_mutation()
        return updated

    def save_agent_recovery_outcome(self, outcome: AgentRecoveryOutcome) -> None:
        existing = self._connection.execute(
            "SELECT payload FROM agent_recovery_outcomes WHERE id = ?",
            (outcome.id,),
        ).fetchone()
        if existing is not None and _load_dataclass(
            AgentRecoveryOutcome, str(existing["payload"])
        ) != outcome:
            raise ValueError("recovery outcome is immutable")
        self._save_agent_record(
            "agent_recovery_outcomes", outcome, AgentRecoveryOutcome,
            tuple(AgentRecoveryOutcome.__dataclass_fields__), {},
        )

    def record_agent_recovery_result_bundle(
        self,
        result: AgentDispatchResult,
        outcome: AgentRecoveryOutcome,
        *,
        attempt_id: str,
        updated_at: str,
    ) -> None:
        with self.agent_transaction():
            try:
                existing = self.load_agent_dispatch_result(result.id)
            except KeyError:
                pass
            else:
                raise ValueError(
                    "forged preexisting recovery result"
                    if existing != result
                    else "recovery result already exists without owned outcome"
                )
            if self.recovery_outcome_for_attempt(attempt_id) is not None:
                raise ValueError("recovery outcome already exists")
            self.save_agent_dispatch_result(result)
            self.save_agent_recovery_outcome(outcome)
            self.transition_agent_recovery_attempt(
                attempt_id,
                expected_state=AgentRecoveryAttemptState.EXTERNAL_STARTED,
                state=AgentRecoveryAttemptState.RESULT_RECORDED,
                updated_at=updated_at,
            )

    def recovery_outcome_for_attempt(
        self, attempt_id: str
    ) -> AgentRecoveryOutcome | None:
        matches = tuple(
            item for item in (
                _load_dataclass(AgentRecoveryOutcome, payload)
                for payload in self._list_payloads("agent_recovery_outcomes")
            ) if item.attempt_id == attempt_id
        )
        if len(matches) > 1:
            raise ValueError("multiple recovery outcomes for one attempt")
        return matches[0] if matches else None

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
        self._commit()

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
        self._commit()

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
        self._commit()

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
        self._commit()

    def save_dashboard_projection(
        self,
        projection_id: str,
        payload: dict[str, object],
    ) -> None:
        self.save_dashboard_projections({projection_id: payload})

    def save_dashboard_projections(
        self,
        projections: dict[str, dict[str, object]],
    ) -> None:
        if not isinstance(projections, dict) or not projections:
            raise ValueError("dashboard projections must be a non-empty object")
        encoded: list[tuple[str, str]] = []
        for projection_id, payload in projections.items():
            if not isinstance(projection_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", projection_id):
                raise ValueError("dashboard projection id is invalid")
            if not isinstance(payload, dict):
                raise ValueError("dashboard projection payload must be an object")
            document = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            if len(document.encode("utf-8")) > MAX_DASHBOARD_PROJECTION_PAYLOAD_LENGTH:
                raise ValueError("dashboard projection payload exceeds the bounded limit")
            encoded.append((projection_id, document))
        with self.agent_transaction():
            self._connection.executemany(
                "INSERT OR REPLACE INTO dashboard_projections (id, payload) VALUES (?, ?)",
                encoded,
            )

    def load_dashboard_projection(self, projection_id: str) -> dict[str, object]:
        payload = json.loads(self._get_payload("dashboard_projections", projection_id))
        if not isinstance(payload, dict):
            raise ValueError("dashboard projection payload is invalid")
        return payload

    def load_health_evidence(self, evidence_id: str) -> HealthEvidence:
        return _load_dataclass(HealthEvidence, self._get_payload("health_evidence", evidence_id))

    def list_health_evidence(self) -> tuple[HealthEvidence, ...]:
        return tuple(_load_dataclass(HealthEvidence, payload) for payload in self._list_payloads("health_evidence"))

    def delete_health_evidence(self, evidence_id: str) -> None:
        self._connection.execute("DELETE FROM health_evidence WHERE id = ?", (evidence_id,))
        self._commit()

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
        self._commit()
        return deleted

    def save_health_target(self, target: HealthTarget) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO health_targets (id, resource_id, payload) VALUES (?, ?, ?)",
            (target.id, target.resource_id, _dump(target)),
        )
        self._commit()

    def load_health_target(self, target_id: str) -> HealthTarget:
        return _load_dataclass(HealthTarget, self._get_payload("health_targets", target_id))

    def list_health_targets(self) -> tuple[HealthTarget, ...]:
        return tuple(_load_dataclass(HealthTarget, payload) for payload in self._list_payloads("health_targets"))

    def save_physical_identity(self, identity: PhysicalIdentity) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO physical_identities (stable_id, payload) VALUES (?, ?)",
            (identity.stable_id, _dump(identity)),
        )
        self._commit()

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
        self._commit_agent_mutation()

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
        self._commit_agent_mutation()

    def load_approval(self, approval_id: str) -> ApprovalRequest:
        return _load_dataclass(ApprovalRequest, self._get_payload("approvals", approval_id))

    def list_approvals(self) -> tuple[ApprovalRequest, ...]:
        return tuple(_load_dataclass(ApprovalRequest, payload) for payload in self._list_payloads("approvals"))

    def save_claim_approval_continuation(self, continuation: ClaimApprovalContinuation) -> None:
        existing_row = self._connection.execute(
            "SELECT payload FROM claim_approval_continuations WHERE id = ?",
            (continuation.id,),
        ).fetchone()
        if existing_row is not None:
            existing = _load_dataclass(
                ClaimApprovalContinuation,
                str(existing_row["payload"]),
            )
            immutable_fields = (
                "id",
                "claim_id",
                "approval_id",
                "resource_id",
                "owner_thread",
                "owner_role",
                "activation_group_id",
                "lifecycle_id",
            )
            if any(getattr(existing, field) != getattr(continuation, field) for field in immutable_fields):
                raise ValueError("claim approval continuation identity is immutable")
        self._connection.execute(
            """
            INSERT OR REPLACE INTO claim_approval_continuations
                (id, claim_id, approval_id, payload)
            VALUES (?, ?, ?, ?)
            """,
            (
                continuation.id,
                continuation.claim_id,
                continuation.approval_id,
                _dump(continuation),
            ),
        )
        self._commit_agent_mutation()

    def save_claim_activation_group(self, group: ClaimActivationGroup) -> None:
        existing_row = self._connection.execute(
            "SELECT payload FROM claim_activation_groups WHERE id = ?",
            (group.id,),
        ).fetchone()
        if existing_row is not None:
            existing = _load_dataclass(ClaimActivationGroup, str(existing_row["payload"]))
            immutable_fields = (
                "id",
                "lifecycle_id",
                "owner_thread",
                "owner_role",
                "claim_ids",
                "approval_ids",
                "resource_ids",
            )
            if any(getattr(existing, field) != getattr(group, field) for field in immutable_fields):
                raise ValueError("claim activation group identity is immutable")
            if existing.state == ClaimActivationGroupState.RELEASED and group.state != existing.state:
                raise ValueError("released claim activation group cannot be reopened")
        self._connection.execute(
            "INSERT OR REPLACE INTO claim_activation_groups (id, lifecycle_id, payload) VALUES (?, ?, ?)",
            (group.id, group.lifecycle_id, _dump(group)),
        )
        self._commit_agent_mutation()

    def load_claim_activation_group(self, group_id: str) -> ClaimActivationGroup:
        return _load_dataclass(ClaimActivationGroup, self._get_payload("claim_activation_groups", group_id))

    def list_claim_activation_groups(self) -> tuple[ClaimActivationGroup, ...]:
        return tuple(
            _load_dataclass(ClaimActivationGroup, payload)
            for payload in self._list_payloads("claim_activation_groups")
        )

    def load_claim_approval_continuation(self, continuation_id: str) -> ClaimApprovalContinuation:
        return _load_dataclass(
            ClaimApprovalContinuation,
            self._get_payload("claim_approval_continuations", continuation_id),
        )

    def list_claim_approval_continuations(self) -> tuple[ClaimApprovalContinuation, ...]:
        return tuple(
            _load_dataclass(ClaimApprovalContinuation, payload)
            for payload in self._list_payloads("claim_approval_continuations")
        )

    def save_claim_approval_continuation_attempt(
        self,
        attempt: ClaimApprovalContinuationAttempt,
    ) -> None:
        self._connection.execute(
            """
            INSERT OR REPLACE INTO claim_approval_continuation_attempts
                (id, continuation_id, attempted_at, payload)
            VALUES (?, ?, ?, ?)
            """,
            (attempt.id, attempt.continuation_id, attempt.attempted_at, _dump(attempt)),
        )
        self._commit_agent_mutation()

    def load_claim_approval_continuation_attempt(
        self,
        attempt_id: str,
    ) -> ClaimApprovalContinuationAttempt:
        return _load_dataclass(
            ClaimApprovalContinuationAttempt,
            self._get_payload("claim_approval_continuation_attempts", attempt_id),
        )

    def list_claim_approval_continuation_attempts(
        self,
        continuation_id: str | None = None,
    ) -> tuple[ClaimApprovalContinuationAttempt, ...]:
        if continuation_id is None:
            payloads = self._list_payloads("claim_approval_continuation_attempts")
        else:
            rows = self._connection.execute(
                "SELECT payload FROM claim_approval_continuation_attempts "
                "WHERE continuation_id = ? ORDER BY id",
                (continuation_id,),
            ).fetchall()
            payloads = tuple(str(row["payload"]) for row in rows)
        return tuple(
            _load_dataclass(ClaimApprovalContinuationAttempt, payload)
            for payload in payloads
        )

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
        sql = (
            "SELECT payload FROM host_snapshots "
            "ORDER BY julianday(json_extract(payload, '$.captured_at')) ASC, id ASC"
        )
        params: tuple[object, ...] = ()
        if limit is not None:
            sql = (
                "SELECT payload FROM host_snapshots "
                "ORDER BY julianday(json_extract(payload, '$.captured_at')) DESC, id DESC LIMIT ?"
            )
            params = (max(0, int(limit)),)
        rows = self._connection.execute(sql, params).fetchall()
        return tuple(_load_dataclass(HostInspectionSnapshot, str(row["payload"])) for row in rows)

    def count_host_snapshots(self) -> int:
        row = self._connection.execute("SELECT COUNT(*) AS count FROM host_snapshots").fetchone()
        return int(row["count"] if row is not None else 0)

    def load_latest_host_snapshot(self) -> HostInspectionSnapshot | None:
        row = self._connection.execute(
            "SELECT payload FROM host_snapshots "
            "ORDER BY julianday(json_extract(payload, '$.captured_at')) DESC, id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        return _load_dataclass(HostInspectionSnapshot, str(row["payload"]))

    def save_admin_change_plan(self, plan: AdminChangePlan) -> None:
        with admin_authority_lock(self.path), self.agent_transaction():
            active_claim = self._connection.execute(
                "SELECT payload FROM admin_execution_claims WHERE plan_id=? AND state=?",
                (plan.id, AdminExecutionClaimState.CLAIMED.value),
            ).fetchone()
            if active_claim is not None:
                raise ValueError("admin execution is claimed; authority mutation is prohibited")
            claimed = self._connection.execute(
                "SELECT 1 FROM psychlo_legacy_abandonment_execution_claims WHERE plan_id=?",
                (plan.id,),
            ).fetchone()
            if claimed is not None:
                current = self._connection.execute(
                    "SELECT payload FROM admin_change_plans WHERE id=?", (plan.id,)
                ).fetchone()
                if current is None or str(current["payload"]) != _dump(plan):
                    raise ValueError("legacy abandonment execution claim prohibits authority mutation")
            self._connection.execute(
                "INSERT OR REPLACE INTO admin_change_plans (id, payload) VALUES (?, ?)",
                (plan.id, _dump(plan)),
            )

    def claim_psychlo_legacy_abandonment_execution(
        self,
        plan_id: str,
        action_id: str,
        action_digest: str,
        plan_digest: str,
        *,
        claimed_at: str,
    ) -> dict[str, Any]:
        """Fence approval cancellation before any peer abandonment send."""
        from .admin import AdminChangeKind
        from .psychlo_legacy_abandonment import _immutable_plan_digest

        with self.agent_transaction():
            row = self._connection.execute(
                "SELECT payload FROM admin_change_plans WHERE id=?", (plan_id,)
            ).fetchone()
            if row is None:
                raise ValueError("legacy abandonment authority plan is missing")
            plan = _load_dataclass(AdminChangePlan, str(row["payload"]))
            metadata = plan.adapter_metadata.get("legacy_abandonment") if isinstance(plan.adapter_metadata, dict) else None
            successor_id = metadata.get("successorPlanId") if isinstance(metadata, dict) else None
            try:
                approved_at = datetime.fromisoformat(str(plan.approved_at).replace("Z", "+00:00"))
            except ValueError:
                approved_at = None
            if (
                plan.kind != AdminChangeKind.PSYCHLO_LEGACY_ABANDONMENT
                or plan.owner_domain != OwnerDomain.SISKO
                or plan.risk_level != RiskLevel.HIGH
                or plan.approval_level != ApprovalLevel.HUMAN
                or plan.approved is not True
                or plan.approved_by != "sisko"
                or approved_at is None
                or approved_at.tzinfo is None
                or approved_at.utcoffset() != UTC.utcoffset(approved_at)
                or plan.canceled
                or plan.archived
                or any(getattr(plan, field) is not None for field in (
                    "canceled_by", "canceled_at", "cancellation_reason", "archived_by",
                    "archived_at", "archive_record_id",
                ))
                or action_id != f"legacy-abandonment:{plan.target}:{successor_id}"
                or _immutable_plan_digest(plan) != plan_digest
            ):
                raise ValueError("exact active approved Sisko abandonment authority is required")
            existing = self._connection.execute(
                "SELECT * FROM psychlo_legacy_abandonment_execution_claims WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
            if existing is None:
                self._connection.execute(
                    "INSERT INTO psychlo_legacy_abandonment_execution_claims(plan_id,action_id,action_digest,plan_digest,state,claimed_at) VALUES (?,?,?,?,?,?)",
                    (plan_id, action_id, action_digest, plan_digest, "claimed", claimed_at),
                )
            elif (
                existing["action_id"] != action_id
                or existing["action_digest"] != action_digest
                or existing["plan_digest"] != plan_digest
            ):
                raise ValueError("legacy abandonment execution claim identity conflict")
            current = self._connection.execute(
                "SELECT * FROM psychlo_legacy_abandonment_execution_claims WHERE plan_id=?", (plan_id,)
            ).fetchone()
            return dict(current)

    def complete_psychlo_legacy_abandonment_execution(
        self,
        plan_id: str,
        action_id: str,
        action_digest: str,
        *,
        completed_at: str,
    ) -> dict[str, Any]:
        with self.agent_transaction():
            cursor = self._connection.execute(
                "UPDATE psychlo_legacy_abandonment_execution_claims SET state='completed',completed_at=COALESCE(completed_at,?) "
                "WHERE plan_id=? AND action_id=? AND action_digest=? AND state IN ('claimed','completed')",
                (completed_at, plan_id, action_id, action_digest),
            )
            if cursor.rowcount != 1:
                raise ValueError("legacy abandonment execution claim is missing or changed")
            row = self._connection.execute(
                "SELECT * FROM psychlo_legacy_abandonment_execution_claims WHERE plan_id=?", (plan_id,)
            ).fetchone()
            return dict(row)

    def psychlo_legacy_abandonment_execution_claim(self, plan_id: str) -> dict[str, Any] | None:
        row = self._connection.execute(
            "SELECT * FROM psychlo_legacy_abandonment_execution_claims WHERE plan_id=?", (plan_id,)
        ).fetchone()
        return None if row is None else dict(row)

    def stage_psychlo_policy_exception_authority(
        self,
        request: dict[str, Any],
        *,
        created_at: str,
    ) -> dict[str, Any]:
        """Atomically stage the non-executable policy-exception authority.

        The Psychlo bridge projection is intentionally not an approval store.
        This method is the single primary-store write boundary for the three
        records Roadex displays: the frozen admin plan, its HUMAN
        ``ApprovalRequest``, and the immutable source binding.  A partially
        written set is rejected rather than repaired, so restart recovery can
        only observe a complete authority or a durable failure.
        """
        from .admin import AdminChangeKind, AdminCommandStep
        from .core import ApprovalLevel, OwnerDomain, RiskLevel
        from .roadex_approval_status import (
            RoadexApprovalBindingDraft,
            binding_from_draft,
            exact_source_evidence_digest,
        )
        from .psychlo_contracts import canonical_digest

        request_id = request.get("id")
        request_digest = request.get("digest")
        if not isinstance(request_id, str) or not request_id.strip():
            raise ValueError("policy exception request identity is required")
        if not isinstance(request_digest, str) or not request_digest.strip():
            raise ValueError("policy exception request digest is required")
        plan_id = f"admin.psychlo.policy-exception.{request_id}"
        approval_id = f"approval.psychlo.policy-exception.{request_id}"
        encoded_metadata = {
            "psychloAuthorization": {
                "action": "psychlo-policy-exception",
                "authorityWorkflow": "dedicated-human-policy-exception",
                "target": request_id,
                "approvalId": approval_id,
                "payload": dict(request),
                "payloadDigest": request_digest,
                "decisionId": f"roadex:psychlo-policy-exception:{request_id}",
                "decisionDigest": canonical_digest({
                    "approvalId": approval_id,
                    "subjectId": plan_id,
                    "requestDigest": request_digest,
                }),
                "scopeDigest": request.get("scopeDigest"),
                "decisionVersion": request.get("decisionVersion"),
                "evidence": [request_digest],
            }
        }
        proposed_state = json.dumps(encoded_metadata, sort_keys=True, separators=(",", ":"))
        # No command is ever emitted for this record.  The descriptive step
        # makes the plan legible while ``AdminChangePlan.can_execute`` has an
        # explicit kind guard as a second fail-closed boundary.
        plan = AdminChangePlan(
            id=plan_id,
            kind=AdminChangeKind.PSYCHLO_POLICY_EXCEPTION,
            owner_domain=OwnerDomain.SISKO,
            risk_level=RiskLevel.MEDIUM,
            approval_level=ApprovalLevel.HUMAN,
            target=request_id,
            reason=str(request.get("reason") or "Psychlo policy exception requires independent human decision"),
            current_state="pending signed Psychlo request",
            proposed_state=proposed_state,
            steps=(AdminCommandStep("Record human decision only", ("__overseer_policy_exception_decision__",), "This marker is not an executable host command"),),
            rollback_steps=(),
            risks=("policy safety rules may be relaxed if independently approved", "the request expires at its signed deadline"),
            verification_steps=(),
        )
        approval = ApprovalRequest(
            id=approval_id,
            subject_id=plan_id,
            approval_level=ApprovalLevel.HUMAN,
            requester_thread=f"psychlo:{request.get('actorId', 'unknown')}",
            owner_domain=OwnerDomain.SISKO,
            reason=plan.reason,
            status=ApprovalStatus.PENDING,
            evidence_required=(request_digest,),
        )
        draft = RoadexApprovalBindingDraft(
            approval_ref=plan_id,
            source_kind="admin-plan",
            source_id=plan_id,
            project_id=f"psychlo:{request_id}",
            workspace_id="psychlo",
            resource_ref=f"policy-exception:{request_id}",
            authority_class="privileged-operation",
            subject=f"Psychlo policy exception {request_id}",
        )

        with admin_authority_lock(self.path), self.agent_transaction():
            existing_plan = None
            existing_approval = None
            existing_binding = None
            try:
                existing_plan = self.load_admin_change_plan(plan_id)
            except KeyError:
                pass
            try:
                existing_approval = self.load_approval(approval_id)
            except KeyError:
                pass
            try:
                existing_binding = self.load_roadex_approval_binding(plan_id)
            except KeyError:
                pass
            if any(item is not None for item in (existing_plan, existing_approval, existing_binding)):
                if not (existing_plan == plan and existing_approval == approval):
                    raise ValueError("policy exception authority staging conflict")
                expected_binding = binding_from_draft(
                    draft,
                    exact_source_evidence_digest(existing_plan),
                    created_at=existing_binding.created_at if existing_binding is not None else created_at,
                )
                if existing_binding != expected_binding:
                    raise ValueError("policy exception Roadex binding conflict")
                return {
                    "inserted": False,
                    "planId": plan_id,
                    "approvalId": approval_id,
                    "binding": existing_binding,
                }
            self.save_admin_change_plan(plan)
            self.save_approval(approval)
            binding = binding_from_draft(draft, exact_source_evidence_digest(plan), created_at=created_at)
            self.save_roadex_approval_binding(binding)
            return {"inserted": True, "planId": plan_id, "approvalId": approval_id, "binding": binding}

    def decide_psychlo_policy_exception_authority(
        self,
        request_id: str,
        decision: str,
        decided_by: str,
        reason: str,
        *,
        decided_at: str,
    ) -> dict[str, Any]:
        """Atomically decide the dedicated plan and its HUMAN approval."""
        if decision not in {"approved", "rejected", "expired"}:
            raise ValueError("policy exception decision is invalid")
        normalized_decided_by = decided_by.strip() if isinstance(decided_by, str) else ""
        automated_expiry = decision == "expired" and normalized_decided_by == "overseer-expiry"
        if not normalized_decided_by or (not automated_expiry and normalized_decided_by.lower() in {"sisko", "overseer", "system"}):
            raise ValueError("independent human policy exception decision is required")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("policy exception decision reason is required")
        try:
            decision_time = datetime.fromisoformat(decided_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise ValueError("policy exception decided_at is invalid") from error
        if decision_time.tzinfo is None:
            raise ValueError("policy exception decided_at is invalid")
        plan_id = f"admin.psychlo.policy-exception.{request_id}"
        approval_id = f"approval.psychlo.policy-exception.{request_id}"
        with admin_authority_lock(self.path), self.agent_transaction():
            plan = self.load_admin_change_plan(plan_id)
            approval = self.load_approval(approval_id)
            if plan.kind.value != "psychlo_policy_exception" or plan.target != request_id or approval.subject_id != plan_id or approval.approval_level is not ApprovalLevel.HUMAN:
                raise ValueError("policy exception authority identity is invalid")
            metadata = json.loads(plan.proposed_state).get("psychloAuthorization", {})
            signed_request = metadata.get("payload") if isinstance(metadata, dict) else None
            if not isinstance(signed_request, dict) or signed_request.get("id") != request_id or signed_request.get("digest") != metadata.get("payloadDigest"):
                raise ValueError("policy exception authority request binding is invalid")
            try:
                expires_at = datetime.fromisoformat(str(signed_request["expiresAt"]).replace("Z", "+00:00"))
            except (KeyError, ValueError) as error:
                raise ValueError("policy exception authority expiry is invalid") from error
            if expires_at.tzinfo is None:
                raise ValueError("policy exception authority expiry is invalid")

            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS psychlo_policy_exception_decisions (request_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
            existing_row = self._connection.execute(
                "SELECT payload FROM psychlo_policy_exception_decisions WHERE request_id=?", (request_id,)
            ).fetchone()
            submitted = {
                "requestId": request_id,
                "decision": decision,
                "decidedBy": normalized_decided_by,
                "reason": reason,
                "decidedAt": decided_at,
            }
            if existing_row is not None:
                existing = json.loads(str(existing_row["payload"]))
                if any(existing.get(key) != value for key, value in submitted.items()):
                    raise ValueError("policy exception authority decision conflict")
                expiration = self.psychlo_policy_exception_authority_expiration(request_id)
                if expiration is not None:
                    if not (
                        expiration.get("originalDecision") == existing.get("status")
                        and plan.canceled and not plan.approved
                        and approval.status is ApprovalStatus.EXPIRED
                    ):
                        raise ValueError("policy exception authority expiration state mismatch")
                    return {"status": "expired", "planId": plan_id, "approvalId": approval_id, "replay": True}
                status = existing.get("status")
                state_valid = (
                    status == "approved" and plan.approved and not plan.canceled and approval.status is ApprovalStatus.APPROVED
                ) or (
                    status in {"rejected", "expired"} and plan.canceled and not plan.approved
                    and approval.status is (ApprovalStatus.REJECTED if status == "rejected" else ApprovalStatus.EXPIRED)
                )
                if not state_valid:
                    raise ValueError("policy exception authority decision state mismatch")
                return {"status": status, "planId": plan_id, "approvalId": approval_id, "replay": True}

            status = "expired" if decision_time >= expires_at else decision
            record = {**submitted, "status": status}
            self._connection.execute(
                "INSERT INTO psychlo_policy_exception_decisions(request_id,payload) VALUES (?,?)",
                (request_id, _dump(record)),
            )
            if status == "approved":
                if plan.canceled or plan.approved or approval.status is not ApprovalStatus.PENDING:
                    raise ValueError("policy exception authority decision conflict")
                updated_plan = replace(plan, approved=True, approved_by=normalized_decided_by, approved_at=decided_at)
                updated_approval = replace(approval, status=ApprovalStatus.APPROVED, decided_by=normalized_decided_by, decided_at=decided_at)
            else:
                terminal_status = ApprovalStatus.REJECTED if status == "rejected" else ApprovalStatus.EXPIRED
                if plan.approved or approval.status is not ApprovalStatus.PENDING:
                    raise ValueError("policy exception authority decision conflict")
                cancellation_reason = reason if status == decision else "signed policy exception request expired before decision"
                updated_plan = replace(plan, canceled=True, canceled_by=normalized_decided_by, canceled_at=decided_at, cancellation_reason=cancellation_reason)
                updated_approval = replace(approval, status=terminal_status, decided_by=normalized_decided_by, decided_at=decided_at)
            self.save_admin_change_plan(updated_plan)
            self.save_approval(updated_approval)
            return {"status": status, "planId": plan_id, "approvalId": approval_id, "replay": False}

    def psychlo_policy_exception_decision(self, request_id: str) -> dict[str, Any] | None:
        table = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='psychlo_policy_exception_decisions'"
        ).fetchone()
        if table is None:
            return None
        row = self._connection.execute(
            "SELECT payload FROM psychlo_policy_exception_decisions WHERE request_id=?", (request_id,)
        ).fetchone()
        return None if row is None else json.loads(str(row["payload"]))

    def expire_undelivered_psychlo_policy_exception_authority(
        self,
        request_id: str,
        *,
        expired_at: str,
    ) -> dict[str, Any]:
        """Supersede an approved authority whose signed outcome was not delivered.

        The original canonical human decision remains immutable in
        ``psychlo_policy_exception_decisions``.  A separate expiration record
        binds the lifecycle supersession while this transaction cancels the
        plan and expires its paired ApprovalRequest together.
        """
        try:
            current_time = datetime.fromisoformat(expired_at.replace("Z", "+00:00"))
        except (AttributeError, ValueError) as error:
            raise ValueError("policy exception expiration time is invalid") from error
        if current_time.tzinfo is None:
            raise ValueError("policy exception expiration time is invalid")
        plan_id = f"admin.psychlo.policy-exception.{request_id}"
        approval_id = f"approval.psychlo.policy-exception.{request_id}"
        with admin_authority_lock(self.path), self.agent_transaction():
            plan = self.load_admin_change_plan(plan_id)
            approval = self.load_approval(approval_id)
            decision = self.psychlo_policy_exception_decision(request_id)
            if (
                plan.kind.value != "psychlo_policy_exception"
                or plan.target != request_id
                or approval.subject_id != plan_id
                or approval.approval_level is not ApprovalLevel.HUMAN
                or decision is None
                or decision.get("status") != "approved"
            ):
                raise ValueError("undelivered policy exception authority identity is invalid")
            metadata = json.loads(plan.proposed_state).get("psychloAuthorization", {})
            signed_request = metadata.get("payload") if isinstance(metadata, dict) else None
            if not isinstance(signed_request, dict) or signed_request.get("id") != request_id or signed_request.get("digest") != metadata.get("payloadDigest"):
                raise ValueError("undelivered policy exception authority request binding is invalid")
            try:
                expires_at = datetime.fromisoformat(str(signed_request["expiresAt"]).replace("Z", "+00:00"))
            except (KeyError, ValueError) as error:
                raise ValueError("policy exception authority expiry is invalid") from error
            if expires_at.tzinfo is None or current_time < expires_at:
                raise ValueError("policy exception authority has not expired")
            self._connection.execute(
                "CREATE TABLE IF NOT EXISTS psychlo_policy_exception_authority_expirations (request_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
            existing = self.psychlo_policy_exception_authority_expiration(request_id)
            if existing is not None:
                if not (plan.canceled and not plan.approved and approval.status is ApprovalStatus.EXPIRED):
                    raise ValueError("policy exception authority expiration state mismatch")
                return {**existing, "replay": True}
            if not (plan.approved and not plan.canceled and approval.status is ApprovalStatus.APPROVED):
                raise ValueError("only an approved undelivered policy exception authority can expire")
            expiration = {
                "requestId": request_id,
                "approvalId": approval_id,
                "planId": plan_id,
                "originalDecision": "approved",
                "originalDecisionAt": decision.get("decidedAt"),
                "expiredAt": expired_at,
                "reason": "signed policy exception request expired before approved outcome delivery",
            }
            self._connection.execute(
                "INSERT INTO psychlo_policy_exception_authority_expirations(request_id,payload) VALUES (?,?)",
                (request_id, _dump(expiration)),
            )
            self.save_admin_change_plan(replace(
                plan,
                approved=False,
                approved_by=None,
                approved_at=None,
                canceled=True,
                canceled_by="overseer-expiry",
                canceled_at=expired_at,
                cancellation_reason=expiration["reason"],
            ))
            self.save_approval(replace(
                approval,
                status=ApprovalStatus.EXPIRED,
                decided_by="overseer-expiry",
                decided_at=expired_at,
            ))
            return {**expiration, "replay": False}

    def psychlo_policy_exception_authority_expiration(self, request_id: str) -> dict[str, Any] | None:
        table = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='psychlo_policy_exception_authority_expirations'"
        ).fetchone()
        if table is None:
            return None
        row = self._connection.execute(
            "SELECT payload FROM psychlo_policy_exception_authority_expirations WHERE request_id=?", (request_id,)
        ).fetchone()
        return None if row is None else json.loads(str(row["payload"]))

    def load_admin_change_plan(self, plan_id: str) -> AdminChangePlan:
        return _load_dataclass(AdminChangePlan, self._get_payload("admin_change_plans", plan_id))

    def process_observation(self, round_id: str) -> dict[str, Any] | None:
        """Return only a recorded historical, non-authoritative observation."""
        row = self._connection.execute(
            "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,manifest_json,inserted_at,recorded_at "
            "FROM psychlo_process_observations WHERE round_id=? AND state='recorded'",
            (round_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "observationId": row[0], "roundId": row[1], "planId": row[2],
            "observationDigest": row[3], "planDigest": row[4],
            "manifest": json.loads(row[5]), "insertedAt": row[6],
            "recordedAt": row[7],
        }

    def insert_prepared_process_observation(
        self, *, observation_id: str, round_id: str, plan_id: str,
        observation_digest: str, manifest: Mapping[str, Any], inserted_at: str,
    ) -> dict[str, Any]:
        encoded = json.dumps(dict(manifest), sort_keys=True, separators=(",", ":"))
        row = self._connection.execute(
            "SELECT observation_id,round_id,plan_id,observation_digest,manifest_json,state "
            "FROM psychlo_process_observations WHERE round_id=? OR observation_id=? OR observation_digest=?",
            (round_id, observation_id, observation_digest),
        ).fetchone()
        if row is not None:
            if tuple(row[:5]) != (observation_id, round_id, plan_id, observation_digest, encoded) or row[5] not in {"prepared", "recorded"}:
                raise ValueError("historical process observation replay identity changed")
            return {"observationId": row[0], "roundId": row[1], "planId": row[2], "observationDigest": row[3], "state": row[5]}
        self._connection.execute(
            "INSERT INTO psychlo_process_observations(observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at) VALUES (?,?,?,?,?,?,?,?)",
            (observation_id, round_id, plan_id, observation_digest, "", "prepared", encoded, inserted_at),
        )
        return {"observationId": observation_id, "roundId": round_id, "planId": plan_id, "observationDigest": observation_digest, "state": "prepared"}

    def record_process_observation(self, *, round_id: str, plan_id: str, observation_digest: str, plan_digest: str, recorded_at: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at "
            "FROM psychlo_process_observations WHERE round_id=?",
            (round_id,),
        ).fetchone()
        if row is None or tuple(row[1:4]) != (round_id, plan_id, observation_digest) or row[5] not in {"prepared", "recorded"}:
            raise ValueError("prepared process observation is missing or changed")
        if row[5] == "recorded":
            if row[4] != plan_digest:
                raise ValueError("recorded process observation replay identity changed")
            return {"observationId": row[0], "roundId": row[1], "planId": row[2], "observationDigest": row[3], "planDigest": row[4], "recordedAt": row[8], "state": row[5]}
        self._connection.execute(
            "UPDATE psychlo_process_observations SET plan_digest=?,state='recorded',recorded_at=? WHERE round_id=? AND state='prepared' AND observation_digest=? AND plan_id=?",
            (plan_digest, recorded_at, round_id, observation_digest, plan_id),
        )
        if self._connection.execute("SELECT changes()").fetchone()[0] != 1:
            raise ValueError("process observation changed before recording")
        return {"observationId": row[0], "roundId": row[1], "planId": row[2], "observationDigest": row[3], "planDigest": plan_digest, "recordedAt": recorded_at, "state": "recorded"}

    def _ensure_roadex_approval_bindings(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS roadex_approval_bindings (
                approval_ref TEXT PRIMARY KEY,
                source_kind TEXT NOT NULL,
                source_id TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_roadex_approval_bindings_source_kind ON roadex_approval_bindings (source_kind)"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_roadex_approval_bindings_source_id ON roadex_approval_bindings (source_id)"
        )

    def _roadex_binding_fingerprint(self, payload: str) -> str:
        data = json.loads(payload)
        if not isinstance(data, dict):
            raise ValueError("Roadex approval binding payload must be a JSON object")
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        )

    def save_roadex_approval_binding(self, binding) -> None:
        from .roadex_approval_status import RoadexApprovalBinding
        from .roadex_approval_status import _validate_binding_object_types

        if not isinstance(binding, RoadexApprovalBinding):
            raise ValueError("Roadex approval binding must be exact RoadexApprovalBinding")
        _validate_binding_object_types(binding)

        self._ensure_roadex_approval_bindings()
        payload = _dump(binding)
        existing = self._connection.execute(
            "SELECT payload FROM roadex_approval_bindings WHERE approval_ref=?",
            (binding.approval_ref,),
        ).fetchone()
        if existing is not None:
            if str(existing["payload"]) != self._roadex_binding_fingerprint(payload):
                raise ValueError("Roadex approval binding is immutable")
            self._commit_agent_mutation()
            return _load_dataclass(RoadexApprovalBinding, str(existing["payload"]))
        self._connection.execute(
            "INSERT INTO roadex_approval_bindings (approval_ref, source_kind, source_id, payload) VALUES (?, ?, ?, ?)",
            (binding.approval_ref, binding.source_kind, binding.source_id, payload),
        )
        self._commit_agent_mutation()
        return _load_dataclass(RoadexApprovalBinding, payload)

    def load_roadex_approval_binding(self, approval_ref: str) -> object:
        from .roadex_approval_status import RoadexApprovalBinding
        from .roadex_approval_status import _decode_roadex_binding_payload

        existing_schema = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='roadex_approval_bindings'"
        ).fetchone()
        if not existing_schema:
            raise KeyError(approval_ref)
        row = self._connection.execute(
            "SELECT source_kind, source_id, payload FROM roadex_approval_bindings WHERE approval_ref=?",
            (approval_ref,),
        ).fetchone()
        if row is None:
            raise KeyError(approval_ref)
        binding = _decode_roadex_binding_payload(str(row["payload"]))
        if str(row["source_id"]) != binding.source_id:
            raise ValueError("roadex approval binding source_id is inconsistent")
        if str(row["source_kind"]) != binding.source_kind:
            raise ValueError("roadex approval binding source_kind is inconsistent")
        if binding.approval_ref != approval_ref:
            raise ValueError("roadex approval binding approval_ref is inconsistent")
        if not isinstance(binding, RoadexApprovalBinding):
            raise ValueError("roadex approval binding is malformed")
        return binding

    def save_roadex_approval_fixture(self, fixture) -> None:
        from .roadex_approval_fixture import RoadexApprovalFixture

        if not isinstance(fixture, RoadexApprovalFixture):
            raise ValueError("Roadex approval fixture must be exact RoadexApprovalFixture")
        if (
            fixture.status != "pending"
            or fixture.approved_at is not None
            or fixture.approved_by is not None
        ):
            raise ValueError("new Roadex approval fixture must be pending")
        self._connection.execute(
            "INSERT INTO roadex_approval_fixtures (id, payload) VALUES (?, ?)",
            (fixture.id, _dump(fixture)),
        )
        self._commit_agent_mutation()

    def approve_roadex_approval_fixture(self, fixture) -> None:
        from .roadex_approval_fixture import RoadexApprovalFixture

        if not isinstance(fixture, RoadexApprovalFixture):
            raise ValueError("Roadex approval fixture must be exact RoadexApprovalFixture")
        if (
            fixture.status != "approved"
            or not fixture.approved_at
            or not fixture.approved_by
        ):
            raise ValueError("Roadex approval fixture must have exact approval evidence")
        existing = self.load_roadex_approval_fixture(fixture.id)
        if existing.status != "pending":
            if existing == fixture:
                return
            raise ValueError("Roadex approval fixture decision is immutable")
        if existing.created_at != fixture.created_at:
            raise ValueError("Roadex approval fixture immutable evidence changed")
        self._connection.execute(
            "UPDATE roadex_approval_fixtures SET payload=? WHERE id=?",
            (_dump(fixture), fixture.id),
        )
        self._commit_agent_mutation()

    def load_roadex_approval_fixture(self, fixture_id: str):
        from .roadex_approval_fixture import RoadexApprovalFixture

        return _load_dataclass(
            RoadexApprovalFixture,
            self._get_payload("roadex_approval_fixtures", fixture_id),
        )

    def list_roadex_approval_fixtures(self) -> tuple[object, ...]:
        from .roadex_approval_fixture import RoadexApprovalFixture

        return tuple(
            _load_dataclass(RoadexApprovalFixture, payload)
            for payload in self._list_payloads("roadex_approval_fixtures")
        )

    def list_admin_change_plans(self) -> tuple[AdminChangePlan, ...]:
        return tuple(_load_dataclass(AdminChangePlan, payload) for payload in self._list_payloads("admin_change_plans"))

    # Collection persistence is normalized for scheduler queries and keeps a
    # bounded compatibility payload for lossless model round-trips.
    def _load_collection_job_state_for_configuration(
        self, job_id: str
    ) -> CollectionJobState | None:
        existing = self._connection.execute(
            "SELECT payload FROM collection_job_states WHERE job_id=?", (job_id,)
        ).fetchone()
        if existing is None:
            return None
        return _load_dataclass(CollectionJobState, str(existing["payload"]))

    def save_collection_job(
        self, job: CollectionJob, state: CollectionJobState | None = None
    ) -> None:
        if not isinstance(job, CollectionJob):
            raise ValueError("collection job must be a CollectionJob")
        if state is not None and state.job_id != job.id:
            raise ValueError("collection job state belongs to a different job")
        job_payload = _bounded_collection_dump(job)
        state_payload = _bounded_collection_dump(state) if state is not None else None
        with self.agent_transaction():
            existing_job = self._connection.execute(
                "SELECT payload FROM collection_jobs WHERE id=?", (job.id,)
            ).fetchone()
            if existing_job is not None:
                current_job = _load_dataclass(CollectionJob, str(existing_job["payload"]))
                current_binding = (
                    current_job.kind,
                    current_job.owner_domain,
                    current_job.resource_id,
                    current_job.target_id,
                )
                requested_binding = (
                    job.kind,
                    job.owner_domain,
                    job.resource_id,
                    job.target_id,
                )
                if current_binding != requested_binding:
                    raise ValueError("immutable collection job binding")
            self._connection.execute(
                """
                INSERT INTO collection_jobs (
                    id, kind, owner_domain, resource_id, target_id, enabled,
                    interval_seconds, jitter_seconds, timeout_seconds, priority,
                    concurrency_key, retention_limit, repair_policy,
                    max_backoff_seconds, failure_threshold, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    kind=excluded.kind, owner_domain=excluded.owner_domain,
                    resource_id=excluded.resource_id, target_id=excluded.target_id,
                    enabled=excluded.enabled, interval_seconds=excluded.interval_seconds,
                    jitter_seconds=excluded.jitter_seconds, timeout_seconds=excluded.timeout_seconds,
                    priority=excluded.priority, concurrency_key=excluded.concurrency_key,
                    retention_limit=excluded.retention_limit, repair_policy=excluded.repair_policy,
                    max_backoff_seconds=excluded.max_backoff_seconds,
                    failure_threshold=excluded.failure_threshold, payload=excluded.payload
                """,
                (
                    job.id,
                    job.kind.value,
                    job.owner_domain.value,
                    job.resource_id,
                    job.target_id,
                    int(job.enabled),
                    job.interval_seconds,
                    job.jitter_seconds,
                    job.timeout_seconds,
                    job.priority,
                    job.concurrency_key,
                    job.retention_limit,
                    job.repair_policy.value,
                    job.max_backoff_seconds,
                    job.failure_threshold,
                    job_payload,
                ),
            )
            if state is None:
                # The writer transaction must own this read.  Configuration-only
                # saves never rewrite an existing scheduler state, because it may
                # have been claimed by another connection while this call began.
                state = self._load_collection_job_state_for_configuration(job.id)
                if state is None:
                    state = CollectionJobState(
                        job_id=job.id,
                        next_due_at=datetime.now(UTC).isoformat(),
                    )
                    self._save_collection_job_state_in_transaction(
                        state, _bounded_collection_dump(state)
                    )
            else:
                self._save_collection_job_state_in_transaction(state, state_payload)

    def save_collection_job_state(self, state: CollectionJobState) -> None:
        if not isinstance(state, CollectionJobState):
            raise ValueError("collection job state must be a CollectionJobState")
        if self._connection.execute(
            "SELECT 1 FROM collection_jobs WHERE id=?", (state.job_id,)
        ).fetchone() is None:
            raise KeyError(state.job_id)
        with self.agent_transaction():
            self._save_collection_job_state_in_transaction(
                state, _bounded_collection_dump(state)
            )

    def set_collection_job_enabled(
        self, job_id: str, enabled: bool
    ) -> tuple[CollectionJob, CollectionJobState, bool, str | None]:
        """Atomically apply an idempotent enabled-policy transition and audit it."""
        if not isinstance(enabled, bool):
            raise ValueError("collection enabled policy must be a boolean")
        with self.agent_transaction():
            job = self.load_collection_job(job_id)
            state = self.load_collection_job_state(job_id)
            from_enabled = int(not enabled)
            to_enabled = int(enabled)
            summary = f"collection_job_enabled_policy_{from_enabled}_to_{to_enabled}"
            if job.enabled is enabled:
                existing_audit = self._connection.execute(
                    "SELECT id FROM audit_events WHERE subject_id=? AND payload LIKE ? "
                    "ORDER BY rowid DESC LIMIT 1",
                    (job.id, f'%"summary":"{summary}"%'),
                ).fetchone()
                return job, state, False, str(existing_audit["id"]) if existing_audit else None
            updated = replace(job, enabled=enabled)
            self.save_collection_job(updated)
            occurrence = int(
                self._connection.execute(
                    "SELECT COUNT(*) AS count FROM audit_events "
                    "WHERE subject_id=? AND payload LIKE ?",
                    (job.id, f'%"summary":"{summary}"%'),
                ).fetchone()["count"]
            )
            transition = f"{job.id}:{from_enabled}:{to_enabled}:{occurrence}"
            audit_id = "audit.collection.policy." + hashlib.sha256(
                transition.encode("utf-8")
            ).hexdigest()[:40]
            self.save_audit_event(
                AuditEvent(
                    id=audit_id,
                    event_type=AuditEventType.EXECUTED,
                    owner_domain=job.owner_domain,
                    subject_id=job.id,
                    summary=summary,
                    risk_level=RiskLevel.LOW,
                )
            )
            return updated, state, True, audit_id

    def load_collection_job(self, job_id: str) -> CollectionJob:
        return _load_dataclass(CollectionJob, self._get_payload("collection_jobs", job_id))

    def list_collection_jobs(self) -> tuple[CollectionJob, ...]:
        return tuple(
            _load_dataclass(CollectionJob, payload)
            for payload in self._list_payloads("collection_jobs")
        )

    def load_collection_job_state(self, job_id: str) -> CollectionJobState:
        return _load_dataclass(
            CollectionJobState, self._get_collection_payload("collection_job_states", job_id)
        )

    def list_collection_job_states(self) -> tuple[CollectionJobState, ...]:
        return tuple(
            _load_dataclass(CollectionJobState, payload)
            for payload in self._list_collection_payloads("collection_job_states")
        )

    def claim_due_collection_jobs(
        self,
        now: str,
        worker: str,
        lease_expires_at: str,
        *,
        limit: int = 2,
        include_pending_requests: bool = False,
        job_id: str | None = None,
    ) -> tuple[CollectionJob, ...]:
        _collection_datetime(now, "current time")
        _collection_datetime(lease_expires_at, "lease expiry")
        if not isinstance(worker, str) or not worker.strip() or len(worker) > 160:
            raise ValueError("lease owner must be a bounded non-blank identifier")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("lease limit must be a non-negative integer")
        if job_id is not None and (
            not isinstance(job_id, str) or not job_id.strip() or len(job_id) > 240
        ):
            raise ValueError("collection job id must be a bounded non-blank identifier")
        if limit == 0:
            return ()

        claimed: list[CollectionJob] = []
        with self.agent_transaction():
            # Select and claim one row per iteration.  The transaction is
            # BEGIN IMMEDIATE, so each subsequent selection observes leases
            # written by this call as well as leases written by other store
            # connections.  This prevents a limit-sized batch from leasing
            # two jobs that share a concurrency key.
            while len(claimed) < limit:
                row = self._connection.execute(
                    """
                    SELECT j.payload AS job_payload, s.payload AS state_payload
                    FROM collection_jobs AS j
                    JOIN collection_job_states AS s ON s.job_id=j.id
                    WHERE j.enabled=1
                      AND (? IS NULL OR j.id = ?)
                      AND (
                          s.active_lease_id IS NULL
                          OR (
                              s.lease_expires_at IS NOT NULL
                              AND julianday(s.lease_expires_at) <= julianday(?)
                          )
                      )
                      AND (
                          s.circuit_state <> 'open'
                          OR (s.cooldown_until IS NOT NULL AND julianday(s.cooldown_until) <= julianday(?))
                      )
                      AND (
                          julianday(s.next_due_at) <= julianday(?)
                          OR (
                              ? = 1 AND EXISTS (
                                  SELECT 1 FROM collection_requests AS r
                                  WHERE r.job_id = j.id AND r.status = 'pending'
                                    AND (r.earliest_execution_at IS NULL
                                         OR julianday(r.earliest_execution_at) <= julianday(?))
                              )
                          )
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM collection_jobs AS occupied_job
                          JOIN collection_job_states AS occupied_state
                            ON occupied_state.job_id = occupied_job.id
                          WHERE occupied_job.concurrency_key = j.concurrency_key
                            AND occupied_state.job_id <> j.id
                            AND occupied_state.active_lease_id IS NOT NULL
                            AND (
                                occupied_state.lease_expires_at IS NULL
                                OR julianday(occupied_state.lease_expires_at) > julianday(?)
                            )
                      )
                    ORDER BY j.priority DESC, julianday(s.next_due_at) ASC, j.id ASC
                    LIMIT 1
                    """,
                    (
                        job_id,
                        job_id,
                        now,
                        now,
                        now,
                        int(include_pending_requests),
                        now,
                        now,
                    ),
                ).fetchone()
                if row is None:
                    break
                job = _load_dataclass(CollectionJob, str(row["job_payload"]))
                state = _load_dataclass(CollectionJobState, str(row["state_payload"]))
                if state.active_lease_id is not None and state.lease_expires_at is not None:
                    self._recover_expired_collection_lease_in_transaction(job, state, now)
                    state = self.load_collection_job_state(job.id)
                generation = state.lease_generation + 1
                lease_id = (
                    "lease.collection."
                    + hashlib.sha256(
                        f"{job.id}:{worker}:{now}:{generation}:{secrets.token_hex(12)}".encode()
                    ).hexdigest()
                )
                claimed_state = replace(
                    state,
                    last_started_at=now,
                    active_lease_id=lease_id,
                    lease_owner=worker,
                    lease_expires_at=lease_expires_at,
                    lease_generation=generation,
                )
                self._save_collection_job_state_in_transaction(
                    claimed_state, _bounded_collection_dump(claimed_state)
                )
                claimed.append(job)
        return tuple(claimed)

    def save_collection_run(self, run: CollectionRun) -> None:
        if not isinstance(run, CollectionRun):
            raise ValueError("collection run must be a CollectionRun")
        with self.agent_transaction():
            self._insert_collection_run_in_transaction(run)

    def complete_collection_run(
        self,
        run: CollectionRun,
        lease_id: str | None = None,
        lease_generation: int | None = None,
    ) -> None:
        if not isinstance(run, CollectionRun):
            raise ValueError("collection run must be a CollectionRun")
        if lease_id is None or lease_generation is None:
            raise ValueError("collection completion requires lease id and generation")
        if isinstance(lease_generation, bool) or not isinstance(lease_generation, int):
            raise ValueError("lease generation must be an integer")
        with self.agent_transaction():
            state = self.load_collection_job_state(run.job_id)
            existing = self._connection.execute(
                "SELECT payload FROM collection_runs WHERE id=?", (run.id,)
            ).fetchone()
            if existing is not None:
                if str(existing["payload"]) == _bounded_collection_dump(run):
                    return
                raise ValueError("immutable collection run collision")
            if (
                state.active_lease_id != lease_id
                or state.lease_generation != lease_generation
                or state.lease_owner is None
            ):
                raise ValueError("stale collection lease")
            job = self.load_collection_job(run.job_id)
            self._insert_collection_run_in_transaction(run)
            if run.outcome is CollectionOutcome.SUCCEEDED:
                failures = 0
                circuit_state = CircuitState.CLOSED
                cooldown_until = None
                next_due_at = next_success_due(job, run.completed_at)
                self._resolve_collection_incident_in_transaction(job, run)
            else:
                failures = state.consecutive_failures + 1
                circuit_state = circuit_after_failure(job, failures)
                next_due_at = next_failure_due(job, run.completed_at, failures)
                cooldown_until = next_due_at if circuit_state is CircuitState.OPEN else None
                self._open_collection_incident_in_transaction(job, run)
            updated_state = replace(
                state,
                next_due_at=next_due_at,
                last_completed_at=run.completed_at,
                last_outcome=run.outcome,
                consecutive_failures=failures,
                circuit_state=circuit_state,
                cooldown_until=cooldown_until,
                active_lease_id=None,
                lease_owner=None,
                lease_expires_at=None,
            )
            self._save_collection_job_state_in_transaction(
                updated_state, _bounded_collection_dump(updated_state)
            )
            if run.request_id is not None:
                request = self._connection.execute(
                    "SELECT payload FROM collection_requests WHERE id=?", (run.request_id,)
                ).fetchone()
                if request is not None:
                    current_request = _load_dataclass(CollectionRequest, str(request["payload"]))
                    if current_request.status == "pending":
                        disposition = run.outcome.value
                        terminal = replace(
                            current_request,
                            status="completed" if run.outcome is CollectionOutcome.SUCCEEDED else "failed",
                            terminal_disposition=disposition,
                        )
                        self._update_collection_request_in_transaction(terminal)

    def record_collection_timeout(
        self,
        run: CollectionRun,
        lease_id: str,
        lease_generation: int,
    ) -> None:
        """Record a scheduler-observed timeout without releasing its worker lease.

        A Python future cannot be cancelled safely once its callable is running.
        This narrow companion to ``complete_collection_run`` keeps the exact
        lease occupied until the worker exits, while still applying the normal
        failure, incident, and backoff policy exactly once.
        """
        if run.outcome is not CollectionOutcome.TIMED_OUT:
            raise ValueError("timeout recording requires a timed-out collection run")
        if not isinstance(lease_generation, int) or isinstance(lease_generation, bool):
            raise ValueError("lease generation must be an integer")
        with self.agent_transaction():
            state = self.load_collection_job_state(run.job_id)
            if state.active_lease_id != lease_id or state.lease_generation != lease_generation:
                raise ValueError("stale collection lease")
            existing = self._connection.execute(
                "SELECT payload FROM collection_runs WHERE id=?", (run.id,)
            ).fetchone()
            if existing is not None:
                if str(existing["payload"]) != _bounded_collection_dump(run):
                    raise ValueError("immutable collection run collision")
                return
            job = self.load_collection_job(run.job_id)
            self._insert_collection_run_in_transaction(run)
            failures = state.consecutive_failures + 1
            circuit_state = circuit_after_failure(job, failures)
            next_due_at = next_failure_due(job, run.completed_at, failures)
            cooldown_until = next_due_at if circuit_state is CircuitState.OPEN else None
            self._open_collection_incident_in_transaction(job, run)
            retained = replace(
                state,
                next_due_at=next_due_at,
                last_completed_at=run.completed_at,
                last_outcome=run.outcome,
                consecutive_failures=failures,
                circuit_state=circuit_state,
                cooldown_until=cooldown_until,
            )
            self._save_collection_job_state_in_transaction(
                retained, _bounded_collection_dump(retained)
            )
            if run.request_id is not None:
                request = self._connection.execute(
                    "SELECT payload FROM collection_requests WHERE id=?", (run.request_id,)
                ).fetchone()
                if request is not None:
                    current_request = _load_dataclass(CollectionRequest, str(request["payload"]))
                    if current_request.status == "pending":
                        self._update_collection_request_in_transaction(
                            replace(
                                current_request,
                                status="failed",
                                terminal_disposition=CollectionOutcome.TIMED_OUT.value,
                            )
                        )

    def release_collection_lease(
        self, job_id: str, lease_id: str, lease_generation: int
    ) -> bool:
        """Release only the exact worker lease that has actually exited."""
        if not isinstance(lease_generation, int) or isinstance(lease_generation, bool):
            raise ValueError("lease generation must be an integer")
        with self.agent_transaction():
            state = self.load_collection_job_state(job_id)
            if state.active_lease_id != lease_id or state.lease_generation != lease_generation:
                return False
            self._save_collection_job_state_in_transaction(
                replace(
                    state,
                    active_lease_id=None,
                    lease_owner=None,
                    lease_expires_at=None,
                ),
                _bounded_collection_dump(
                    replace(
                        state,
                        active_lease_id=None,
                        lease_owner=None,
                        lease_expires_at=None,
                    )
                ),
            )
            return True

    def _request_collection_run_in_transaction(
        self,
        job_id: str,
        requester: str,
        reason: str,
        requested_at: str,
        earliest_execution_at: str | None = None,
    ) -> tuple[CollectionRequest, str]:
        if self._connection.execute(
            "SELECT 1 FROM collection_jobs WHERE id=?", (job_id,)
        ).fetchone() is None:
            raise KeyError(job_id)
        pending = self._connection.execute(
            "SELECT payload FROM collection_requests WHERE job_id=? AND status='pending'",
            (job_id,),
        ).fetchone()
        if pending is not None:
            return _load_dataclass(CollectionRequest, str(pending["payload"])), "coalesced"
        probe = CollectionRequest(
            id="request.placeholder",
            job_id=job_id,
            requester=requester,
            reason=reason,
            requested_at=requested_at,
            earliest_execution_at=earliest_execution_at,
        )
        request_id = "request.collection." + hashlib.sha256(
            f"{job_id}:{requested_at}:{requester}:{reason}:{secrets.token_hex(12)}".encode()
        ).hexdigest()[:40]
        request = replace(probe, id=request_id)
        try:
            self._insert_collection_request_in_transaction(request)
        except sqlite3.IntegrityError as error:
            pending = self._connection.execute(
                "SELECT payload FROM collection_requests WHERE job_id=? AND status='pending'",
                (job_id,),
            ).fetchone()
            if pending is not None:
                return _load_dataclass(CollectionRequest, str(pending["payload"])), "coalesced"
            raise ValueError("collection request collision") from error
        return request, "queued"

    def request_collection_run(
        self,
        job_id: str,
        requester: str,
        reason: str,
        earliest_execution_at: str | None = None,
        requested_at: str | None = None,
    ) -> CollectionRequest:
        request, _status = self.request_collection_run_with_status(
            job_id,
            requester,
            reason,
            earliest_execution_at,
            requested_at,
        )
        return request

    def request_collection_run_with_status(
        self,
        job_id: str,
        requester: str,
        reason: str,
        earliest_execution_at: str | None = None,
        requested_at: str | None = None,
    ) -> tuple[CollectionRequest, str]:
        if earliest_execution_at is not None:
            _collection_datetime(earliest_execution_at, "earliest execution")
        requested_at = requested_at or datetime.now(UTC).isoformat()
        _collection_datetime(requested_at, "requested at")
        with self.agent_transaction():
            request, status = self._request_collection_run_in_transaction(
                job_id,
                requester,
                reason,
                requested_at,
                earliest_execution_at,
            )
        return request, status

    def request_enabled_collection_runs(
        self,
        kind: str,
        requester: str,
        reason: str,
        limit: int,
    ) -> tuple[int, tuple[tuple[CollectionRequest, str], ...]]:
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError("collection job kind is required")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("collection request limit must be between 1 and 100")
        requested_at = datetime.now(UTC).isoformat()
        with self.agent_transaction():
            total = int(
                self._connection.execute(
                    "SELECT COUNT(*) AS count FROM collection_jobs "
                    "WHERE enabled=1 AND kind=?",
                    (kind,),
                ).fetchone()["count"]
            )
            rows = self._connection.execute(
                "SELECT id FROM collection_jobs WHERE enabled=1 AND kind=? "
                "ORDER BY id LIMIT ?",
                (kind, limit),
            ).fetchall()
            requests = tuple(
                self._request_collection_run_in_transaction(
                    str(row["id"]), requester, reason, requested_at
                )
                for row in rows
            )
        return total, requests

    def list_collection_runs(self) -> tuple[CollectionRun, ...]:
        return tuple(
            _load_dataclass(CollectionRun, payload)
            for payload in self._list_collection_payloads("collection_runs")
        )

    def list_collection_requests(self) -> tuple[CollectionRequest, ...]:
        return tuple(
            _load_dataclass(CollectionRequest, payload)
            for payload in self._list_collection_payloads("collection_requests")
        )

    def list_triage_incidents(self) -> tuple[TriageIncident, ...]:
        return tuple(
            _load_dataclass(TriageIncident, payload)
            for payload in self._list_collection_payloads("triage_incidents")
        )

    def load_collection_incident(self, incident_id: str) -> TriageIncident:
        return _load_dataclass(
            TriageIncident,
            self._get_collection_payload("triage_incidents", incident_id),
        )

    def save_collection_incident(self, incident: TriageIncident) -> None:
        if not isinstance(incident, TriageIncident):
            raise ValueError("triage incident must be a TriageIncident")
        with self.agent_transaction():
            self._upsert_collection_incident_in_transaction(incident)

    def save_repair_runbook(self, runbook: RepairRunbook) -> None:
        if not isinstance(runbook, RepairRunbook):
            raise ValueError("repair runbook must be a RepairRunbook")
        payload = _bounded_collection_dump(runbook)
        with self.agent_transaction():
            existing = self._connection.execute(
                "SELECT payload FROM repair_runbooks WHERE id=?", (runbook.id,)
            ).fetchone()
            if existing is not None:
                current = _load_dataclass(RepairRunbook, str(existing["payload"]))
                if (current.job_id, current.resource_id) != (runbook.job_id, runbook.resource_id):
                    raise ValueError("repair runbook binding cannot change")
                self._connection.execute(
                    "UPDATE repair_runbooks SET failure_categories=?, risk_level=?, "
                    "idempotency_contract=?, cooldown_seconds=?, approval_required=?, "
                    "adapter_binding=?, payload=? WHERE id=?",
                    (
                        json.dumps(list(runbook.failure_categories), separators=(",", ":")),
                        runbook.risk_level.value,
                        runbook.idempotency_contract,
                        runbook.cooldown_seconds,
                        int(runbook.approval_required),
                        runbook.adapter_binding,
                        payload,
                        runbook.id,
                    ),
                )
            else:
                self._connection.execute(
                    "INSERT INTO repair_runbooks (id, job_id, resource_id, failure_categories, "
                    "risk_level, idempotency_contract, cooldown_seconds, approval_required, "
                    "adapter_binding, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        runbook.id,
                        runbook.job_id,
                        runbook.resource_id,
                        json.dumps(list(runbook.failure_categories), separators=(",", ":")),
                        runbook.risk_level.value,
                        runbook.idempotency_contract,
                        runbook.cooldown_seconds,
                        int(runbook.approval_required),
                        runbook.adapter_binding,
                        payload,
                    ),
                )

    def load_repair_runbook(self, runbook_id: str) -> RepairRunbook:
        return _load_dataclass(
            RepairRunbook, self._get_collection_payload("repair_runbooks", runbook_id)
        )

    def list_repair_runbooks(self) -> tuple[RepairRunbook, ...]:
        return tuple(
            _load_dataclass(RepairRunbook, payload)
            for payload in self._list_collection_payloads("repair_runbooks")
        )

    def save_repair_attempt(self, attempt: RepairAttempt) -> None:
        if not isinstance(attempt, RepairAttempt):
            raise ValueError("repair attempt must be a RepairAttempt")
        payload = _bounded_collection_dump(attempt)
        with self.agent_transaction():
            existing = self._connection.execute(
                "SELECT payload FROM repair_attempts WHERE id=?", (attempt.id,)
            ).fetchone()
            if existing is not None:
                if str(existing["payload"]) == payload:
                    return
                raise ValueError("immutable repair attempt collision")
            try:
                self._connection.execute(
                    "INSERT INTO repair_attempts (id, incident_id, runbook_id, attempted_at, "
                    "authorization_id, outcome, result_evidence_ids, verification_run_id, payload) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        attempt.id,
                        attempt.incident_id,
                        attempt.runbook_id,
                        attempt.attempted_at,
                        attempt.authorization_id,
                        attempt.outcome,
                        json.dumps(list(attempt.result_evidence_ids), separators=(",", ":")),
                        attempt.verification_run_id,
                        payload,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("immutable repair attempt collision") from error

    def list_repair_attempts(self) -> tuple[RepairAttempt, ...]:
        return tuple(
            _load_dataclass(RepairAttempt, payload)
            for payload in self._list_collection_payloads("repair_attempts")
        )

    def prune_collection_runs(self, retain_per_job: int) -> int:
        if isinstance(retain_per_job, bool) or not isinstance(retain_per_job, int) or retain_per_job < 1:
            raise ValueError("retention must be at least one")
        deleted = 0
        with self.agent_transaction():
            protected: set[str] = set()
            for payload in self._list_collection_payloads("triage_incidents"):
                incident = _load_dataclass(TriageIncident, payload)
                if incident.status is TriageIncidentStatus.OPEN:
                    protected.update(incident.evidence_ids)
            protected.update(
                attempt.verification_run_id
                for attempt in self.list_repair_attempts()
                if attempt.verification_run_id is not None
            )
            rows = self._connection.execute(
                "SELECT id, job_id, started_at FROM collection_runs "
                "ORDER BY job_id ASC, julianday(started_at) DESC, id DESC"
            ).fetchall()
            by_job: dict[str, list[sqlite3.Row]] = {}
            for row in rows:
                by_job.setdefault(str(row["job_id"]), []).append(row)
            for job_rows in by_job.values():
                for row in job_rows[retain_per_job:]:
                    if str(row["id"]) in protected:
                        continue
                    self._connection.execute(
                        "DELETE FROM collection_runs WHERE id=?", (str(row["id"]),)
                    )
                    deleted += 1
        return deleted

    def prune_collection_runs_for_job(self, job_id: str, retain_per_job: int) -> int:
        """Prune only one job's bounded collection evidence, never audit rows."""
        if not isinstance(job_id, str) or not job_id.strip():
            raise ValueError("job id must be a non-blank identifier")
        if isinstance(retain_per_job, bool) or not isinstance(retain_per_job, int) or retain_per_job < 1:
            raise ValueError("retention must be at least one")
        deleted = 0
        with self.agent_transaction():
            protected: set[str] = set()
            for payload in self._list_collection_payloads("triage_incidents"):
                incident = _load_dataclass(TriageIncident, payload)
                if incident.job_id == job_id and incident.status is TriageIncidentStatus.OPEN:
                    protected.update(incident.evidence_ids)
            protected.update(
                attempt.verification_run_id
                for attempt in self.list_repair_attempts()
                if attempt.verification_run_id is not None
            )
            rows = self._connection.execute(
                "SELECT id FROM collection_runs WHERE job_id=? "
                "ORDER BY julianday(started_at) DESC, id DESC",
                (job_id,),
            ).fetchall()
            for row in rows[retain_per_job:]:
                if str(row["id"]) in protected:
                    continue
                self._connection.execute(
                    "DELETE FROM collection_runs WHERE id=? AND job_id=?",
                    (str(row["id"]), job_id),
                )
                deleted += 1
        return deleted

    def _save_collection_job_state_in_transaction(
        self, state: CollectionJobState, payload: str
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO collection_job_states (
                job_id, next_due_at, last_started_at, last_completed_at,
                last_outcome, consecutive_failures, circuit_state, cooldown_until,
                active_lease_id, lease_owner, lease_expires_at, lease_generation, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                next_due_at=excluded.next_due_at, last_started_at=excluded.last_started_at,
                last_completed_at=excluded.last_completed_at, last_outcome=excluded.last_outcome,
                consecutive_failures=excluded.consecutive_failures, circuit_state=excluded.circuit_state,
                cooldown_until=excluded.cooldown_until, active_lease_id=excluded.active_lease_id,
                lease_owner=excluded.lease_owner, lease_expires_at=excluded.lease_expires_at,
                lease_generation=excluded.lease_generation, payload=excluded.payload
            """,
            (
                state.job_id,
                state.next_due_at,
                state.last_started_at,
                state.last_completed_at,
                state.last_outcome.value if state.last_outcome is not None else None,
                state.consecutive_failures,
                state.circuit_state.value,
                state.cooldown_until,
                state.active_lease_id,
                state.lease_owner,
                state.lease_expires_at,
                state.lease_generation,
                payload,
            ),
        )

    def _insert_collection_run_in_transaction(self, run: CollectionRun) -> None:
        payload = _bounded_collection_dump(run)
        existing = self._connection.execute(
            "SELECT payload FROM collection_runs WHERE id=?", (run.id,)
        ).fetchone()
        if existing is not None:
            if str(existing["payload"]) == payload:
                return
            raise ValueError("immutable collection run collision")
        try:
            self._connection.execute(
                "INSERT INTO collection_runs (id, job_id, trigger, started_at, completed_at, "
                "outcome, summary, evidence_ids, error_category, retry_disposition, request_id, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run.id,
                    run.job_id,
                    run.trigger,
                    run.started_at,
                    run.completed_at,
                    run.outcome.value,
                    run.summary,
                    json.dumps(list(run.evidence_ids), separators=(",", ":")),
                    run.error_category,
                    run.retry_disposition,
                    run.request_id,
                    payload,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("immutable collection run collision") from error

    def _insert_collection_request_in_transaction(self, request: CollectionRequest) -> None:
        payload = _bounded_collection_dump(request)
        self._connection.execute(
            "INSERT INTO collection_requests (id, job_id, requester, reason, requested_at, "
            "earliest_execution_at, status, terminal_disposition, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.id,
                request.job_id,
                request.requester,
                request.reason,
                request.requested_at,
                request.earliest_execution_at,
                request.status,
                request.terminal_disposition,
                payload,
            ),
        )

    def _update_collection_request_in_transaction(self, request: CollectionRequest) -> None:
        self._connection.execute(
            "UPDATE collection_requests SET requester=?, reason=?, requested_at=?, "
            "earliest_execution_at=?, status=?, terminal_disposition=?, payload=? WHERE id=?",
            (
                request.requester,
                request.reason,
                request.requested_at,
                request.earliest_execution_at,
                request.status,
                request.terminal_disposition,
                _bounded_collection_dump(request),
                request.id,
            ),
        )

    def _recover_expired_collection_lease_in_transaction(
        self, job: CollectionJob, state: CollectionJobState, now: str
    ) -> None:
        generation = state.lease_generation
        run_id = "run.collection.expired-lease." + hashlib.sha256(
            f"{job.id}:{generation}".encode()
        ).hexdigest()[:48]
        run = CollectionRun(
            id=run_id,
            job_id=job.id,
            trigger="lease_recovery",
            started_at=state.lease_expires_at or now,
            completed_at=now,
            outcome=CollectionOutcome.FAILED,
            summary="expired scheduler lease recovered",
            error_category="expired_lease",
            retry_disposition="reclaim_due",
        )
        self._insert_collection_run_in_transaction(run)
        self._open_collection_incident_in_transaction(job, run)
        recovered = replace(
            state,
            next_due_at=now,
            last_completed_at=now,
            last_outcome=CollectionOutcome.FAILED,
            consecutive_failures=state.consecutive_failures + 1,
            circuit_state=CircuitState.CLOSED,
            cooldown_until=None,
            active_lease_id=None,
            lease_owner=None,
            lease_expires_at=None,
        )
        self._save_collection_job_state_in_transaction(
            recovered, _bounded_collection_dump(recovered)
        )

    def _open_collection_incident_in_transaction(
        self, job: CollectionJob, run: CollectionRun
    ) -> None:
        resource_id = job.resource_id or job.target_id or job.id
        existing_row = self._connection.execute(
            "SELECT payload FROM triage_incidents WHERE job_id=? AND resource_id=? "
            "AND status='open' ORDER BY generation DESC LIMIT 1",
            (job.id, resource_id),
        ).fetchone()
        evidence_ids = tuple(dict.fromkeys((run.id, *run.evidence_ids)))[:64]
        if existing_row is not None:
            existing = _load_dataclass(TriageIncident, str(existing_row["payload"]))
            incident = replace(
                existing,
                latest_failure_at=run.completed_at,
                evidence_ids=tuple(dict.fromkeys((*existing.evidence_ids, *evidence_ids)))[:64],
                status=TriageIncidentStatus.OPEN,
                repair_state="pending",
                resolution=None,
            )
        else:
            max_generation_row = self._connection.execute(
                "SELECT COALESCE(MAX(generation), 0) AS generation FROM triage_incidents "
                "WHERE job_id=?",
                (job.id,),
            ).fetchone()
            generation = int(max_generation_row["generation"]) + 1
            incident_id = "incident.collection." + hashlib.sha256(
                f"{job.id}:{resource_id}:{generation}".encode()
            ).hexdigest()[:48]
            incident = TriageIncident(
                id=incident_id,
                job_id=job.id,
                resource_id=resource_id,
                first_failure_at=run.completed_at,
                latest_failure_at=run.completed_at,
                severity=RiskLevel.MEDIUM,
                owner_domain=job.owner_domain,
                evidence_ids=evidence_ids,
                generation=generation,
            )
        self._upsert_collection_incident_in_transaction(incident)

    def _resolve_collection_incident_in_transaction(
        self, job: CollectionJob, run: CollectionRun
    ) -> None:
        resource_id = job.resource_id or job.target_id or job.id
        row = self._connection.execute(
            "SELECT payload FROM triage_incidents WHERE job_id=? AND resource_id=? "
            "AND status='open' ORDER BY generation DESC LIMIT 1",
            (job.id, resource_id),
        ).fetchone()
        if row is None:
            return
        current = _load_dataclass(TriageIncident, str(row["payload"]))
        incident = replace(
            current,
            evidence_ids=tuple(dict.fromkeys((*current.evidence_ids, run.id)))[:64],
            status=TriageIncidentStatus.RESOLVED,
            repair_state="verified",
            resolution="fresh verification recovered target",
        )
        self._upsert_collection_incident_in_transaction(incident)
        if run.request_id is not None:
            for payload in self._list_collection_payloads("repair_attempts"):
                attempt = _load_dataclass(RepairAttempt, payload)
                if (
                    attempt.incident_id == current.id
                    and run.request_id in attempt.result_evidence_ids
                    and attempt.verification_run_id is None
                ):
                    verified = replace(
                        attempt,
                        outcome="verified",
                        verification_run_id=run.id,
                    )
                    self._connection.execute(
                        "UPDATE repair_attempts SET outcome=?, verification_run_id=?, payload=? WHERE id=?",
                        (
                            verified.outcome,
                            verified.verification_run_id,
                            _bounded_collection_dump(verified),
                            verified.id,
                        ),
                    )

    def _upsert_collection_incident_in_transaction(self, incident: TriageIncident) -> None:
        payload = _bounded_collection_dump(incident)
        try:
            self._connection.execute(
                """
                INSERT INTO triage_incidents (
                    id, job_id, resource_id, first_failure_at, latest_failure_at,
                    severity, owner_domain, evidence_ids, status, repair_state,
                    resolution, generation, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    job_id=excluded.job_id, resource_id=excluded.resource_id,
                    first_failure_at=excluded.first_failure_at, latest_failure_at=excluded.latest_failure_at,
                    severity=excluded.severity, owner_domain=excluded.owner_domain,
                    evidence_ids=excluded.evidence_ids, status=excluded.status,
                    repair_state=excluded.repair_state, resolution=excluded.resolution,
                    generation=excluded.generation, payload=excluded.payload
                """,
                (
                    incident.id,
                    incident.job_id,
                    incident.resource_id,
                    incident.first_failure_at,
                    incident.latest_failure_at,
                    incident.severity.value,
                    incident.owner_domain.value,
                    json.dumps(list(incident.evidence_ids), separators=(",", ":")),
                    incident.status.value,
                    incident.repair_state,
                    incident.resolution,
                    incident.generation,
                    payload,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("triage incident generation collision") from error

    def save_package_inspection_record(self, record: PackageInspectionRecord) -> None:
        payload = _dump(record)
        self._save_immutable_payload(
            table="package_inspection_records",
            record_id=record.id,
            payload=payload,
            insert_sql=(
                "INSERT INTO package_inspection_records (id, payload) "
                "VALUES (?, ?)"
            ),
            insert_values=(record.id, payload),
            collision_message="immutable package inspection collision",
        )

    def load_package_inspection_record(self, record_id: str) -> PackageInspectionRecord:
        return _load_dataclass(
            PackageInspectionRecord,
            self._get_payload("package_inspection_records", record_id),
        )

    def list_package_inspection_records(self) -> tuple[PackageInspectionRecord, ...]:
        return tuple(
            _load_dataclass(PackageInspectionRecord, payload)
            for payload in self._list_payloads("package_inspection_records")
        )

    def save_package_reconciliation_evidence(
        self, evidence: PackageReconciliationEvidence
    ) -> None:
        payload = _dump(evidence)
        self._save_immutable_payload(
            table="package_reconciliation_evidence",
            record_id=evidence.id,
            payload=payload,
            insert_sql=(
                "INSERT INTO package_reconciliation_evidence "
                "(id, snapshot_id, maintenance_batch_id, payload) "
                "VALUES (?, ?, ?, ?)"
            ),
            insert_values=(
                evidence.id,
                evidence.snapshot_id,
                evidence.maintenance_batch_id,
                payload,
            ),
            collision_message="immutable package reconciliation evidence collision",
        )

    def load_package_reconciliation_evidence(
        self, evidence_id: str
    ) -> PackageReconciliationEvidence:
        return _load_dataclass(
            PackageReconciliationEvidence,
            self._get_payload("package_reconciliation_evidence", evidence_id),
        )

    def list_package_reconciliation_evidence(
        self,
    ) -> tuple[PackageReconciliationEvidence, ...]:
        return tuple(
            _load_dataclass(PackageReconciliationEvidence, payload)
            for payload in self._list_payloads("package_reconciliation_evidence")
        )

    def _save_immutable_payload(
        self,
        *,
        table: str,
        record_id: str,
        payload: str,
        insert_sql: str,
        insert_values: tuple[Any, ...],
        collision_message: str,
    ) -> None:
        with self.agent_transaction():
            existing = self._connection.execute(
                f"SELECT payload FROM {table} WHERE id = ?",
                (record_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["payload"]) != payload:
                    raise ValueError(collision_message)
                return
            try:
                self._connection.execute(insert_sql, insert_values)
            except sqlite3.IntegrityError as error:
                existing = self._connection.execute(
                    f"SELECT payload FROM {table} WHERE id = ?",
                    (record_id,),
                ).fetchone()
                if existing is not None and str(existing["payload"]) == payload:
                    return
                raise ValueError(collision_message) from error

    def save_admin_execution(self, result: AdminExecutionResult) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO admin_executions (id, plan_id, payload) VALUES (?, ?, ?)",
            (result.id, result.plan_id, _dump(result)),
        )
        self._commit()

    def claim_admin_execution(self, claim: AdminExecutionClaim) -> None:
        with self.agent_transaction():
            existing = self._connection.execute(
                "SELECT payload FROM admin_execution_claims WHERE plan_id=?",
                (claim.plan_id,),
            ).fetchone()
            if existing is not None:
                raise ValueError("admin execution claim already exists")
            self._connection.execute(
                "INSERT INTO admin_execution_claims (id, plan_id, state, payload) VALUES (?, ?, ?, ?)",
                (claim.id, claim.plan_id, claim.state.value, _dump(claim)),
            )

    def load_admin_execution_claim_for_plan(self, plan_id: str) -> AdminExecutionClaim | None:
        row = self._connection.execute(
            "SELECT payload FROM admin_execution_claims WHERE plan_id=?",
            (plan_id,),
        ).fetchone()
        if row is None:
            return None
        return _load_dataclass(AdminExecutionClaim, str(row["payload"]))

    def list_admin_execution_claims(self) -> tuple[AdminExecutionClaim, ...]:
        return tuple(
            _load_dataclass(AdminExecutionClaim, payload)
            for payload in self._list_payloads("admin_execution_claims")
        )

    def finalize_admin_execution_claim(
        self,
        claim: AdminExecutionClaim,
        result: AdminExecutionResult,
        event: AuditEvent,
    ) -> AdminExecutionClaim:
        if claim.state is not AdminExecutionClaimState.CLAIMED:
            raise ValueError("only a claimed admin execution can be finalized")
        if result.plan_id != claim.plan_id or result.plan_digest != claim.plan_digest:
            raise ValueError("admin execution result does not match its durable claim")
        state = AdminExecutionClaimState(result.status.value)
        finalized = replace(
            claim,
            state=state,
            result_id=result.id,
            finalized_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        )
        with self.agent_transaction():
            current = self.load_admin_execution_claim_for_plan(claim.plan_id)
            if current != claim:
                raise ValueError("admin execution claim changed before finalization")
            self._connection.execute(
                "INSERT OR REPLACE INTO admin_executions (id, plan_id, payload) VALUES (?, ?, ?)",
                (result.id, result.plan_id, _dump(result)),
            )
            self._connection.execute(
                "UPDATE admin_execution_claims SET state=?, payload=? WHERE id=?",
                (finalized.state.value, _dump(finalized), finalized.id),
            )
            self.save_audit_event(event)
        return finalized

    def load_admin_execution(self, result_id: str) -> AdminExecutionResult:
        return _load_dataclass(AdminExecutionResult, self._get_payload("admin_executions", result_id))

    def list_admin_executions(self) -> tuple[AdminExecutionResult, ...]:
        return tuple(_load_dataclass(AdminExecutionResult, payload) for payload in self._list_payloads("admin_executions"))

    def save_admin_history_archive(self, archive: AdminHistoryArchiveRecord) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO admin_history_archives (id, plan_id, payload) VALUES (?, ?, ?)",
            (archive.id, archive.plan_id, _dump(archive)),
        )
        self._commit()

    def load_admin_history_archive(self, archive_id: str) -> AdminHistoryArchiveRecord:
        return _load_dataclass(AdminHistoryArchiveRecord, self._get_payload("admin_history_archives", archive_id))

    def list_admin_history_archives(self) -> tuple[AdminHistoryArchiveRecord, ...]:
        return tuple(_load_dataclass(AdminHistoryArchiveRecord, payload) for payload in self._list_payloads("admin_history_archives"))

    def save_host_security_source_review(self, review: HostSecuritySourceReview) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO host_security_source_reviews (id, remote_address, payload) VALUES (?, ?, ?)",
            (review.id, review.remote_address, _dump(review)),
        )
        self._commit()

    def load_host_security_source_review(self, review_id: str) -> HostSecuritySourceReview:
        return _load_dataclass(HostSecuritySourceReview, self._get_payload("host_security_source_reviews", review_id))

    def list_host_security_source_reviews(self) -> tuple[HostSecuritySourceReview, ...]:
        return tuple(_load_dataclass(HostSecuritySourceReview, payload) for payload in self._list_payloads("host_security_source_reviews"))

    def save_host_security_ids_review_package(self, package: HostSecurityIDSReviewPackage) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO host_security_ids_review_packages (id, plan_id, payload) VALUES (?, ?, ?)",
            (package.id, package.plan_id, _dump(package)),
        )
        self._commit()

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
        self._commit_agent_mutation()

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
        self._commit()

    def load_operation_record(self, record_id: str) -> OperationRecord:
        return _load_dataclass(OperationRecord, self._get_payload("operation_records", record_id))

    def save_storage_adapter_registration(self, registration: StorageAdapterRegistration) -> None:
        self._connection.execute("INSERT OR REPLACE INTO storage_adapter_registrations (id, status, payload) VALUES (?, ?, ?)", (registration.adapter_id, registration.status.value, _dump(registration)))
        self._commit()

    def load_storage_adapter_registration(self, adapter_id: str) -> StorageAdapterRegistration:
        return _load_dataclass(StorageAdapterRegistration, self._get_payload("storage_adapter_registrations", adapter_id))

    def list_storage_adapter_registrations(self) -> tuple[StorageAdapterRegistration, ...]:
        return tuple(_load_dataclass(StorageAdapterRegistration, payload) for payload in self._list_payloads("storage_adapter_registrations"))

    def save_storage_execution_request(self, request: StorageExecutionRequest) -> None:
        existing = self._connection.execute("SELECT payload FROM storage_execution_requests WHERE adapter_id = ? AND project_id = ? AND idempotency_key = ?", (request.adapter_id, request.project_id, request.idempotency_key)).fetchone()
        if existing is not None:
            prior = _load_dataclass(StorageExecutionRequest, str(existing["payload"]))
            if prior.request_digest != request.request_digest:
                raise ValueError("storage idempotency key already belongs to another request")
            return
        self._connection.execute("INSERT INTO storage_execution_requests (id, adapter_id, project_id, idempotency_key, payload) VALUES (?, ?, ?, ?, ?)", (request.request_id, request.adapter_id, request.project_id, request.idempotency_key, _dump(request)))
        self._commit()

    def load_storage_execution_request(self, request_id: str) -> StorageExecutionRequest:
        return _load_dataclass(StorageExecutionRequest, self._get_payload("storage_execution_requests", request_id))

    def save_storage_authorization(self, authorization: StorageAuthorizationRecord) -> None:
        existing = self._connection.execute("SELECT payload FROM storage_authorizations WHERE id=?", (authorization.authorization_ref,)).fetchone()
        payload = _dump(authorization)
        if existing is not None and str(existing["payload"]) != payload:
            raise ValueError("storage authorization reference is immutable")
        self._connection.execute("INSERT OR IGNORE INTO storage_authorizations (id,request_id,status,payload) VALUES (?,?,?,?)", (authorization.authorization_ref, authorization.request_id, authorization.status, payload))
        self._commit()

    def load_storage_authorization(self, authorization_ref: str) -> StorageAuthorizationRecord:
        record=_load_dataclass(StorageAuthorizationRecord, self._get_payload("storage_authorizations", authorization_ref)); revoked=self._connection.execute("SELECT revoked_at FROM storage_authorization_revocations WHERE authorization_ref=?",(authorization_ref,)).fetchone() if self._connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='storage_authorization_revocations'").fetchone() else None
        return replace(record,revoked_at=str(revoked["revoked_at"])) if revoked else record

    def save_storage_root_authorization(self, authorization: StorageRootAuthorizationRecord) -> None:
        existing=self._connection.execute("SELECT payload FROM storage_root_authorizations WHERE id=?",(authorization.authorization_ref,)).fetchone(); payload=_dump(authorization)
        if existing is not None and str(existing["payload"])!=payload: raise ValueError("storage root authorization reference is immutable")
        self._connection.execute("INSERT OR IGNORE INTO storage_root_authorizations(id,project_id,root_id,status,payload) VALUES(?,?,?,?,?)",(authorization.authorization_ref,authorization.project_id,authorization.root_id,authorization.authorization_status,payload)); self._commit()

    def load_storage_root_authorization(self, authorization_ref: str) -> StorageRootAuthorizationRecord:
        record=_load_dataclass(StorageRootAuthorizationRecord,self._get_payload("storage_root_authorizations",authorization_ref)); revoked=self._connection.execute("SELECT revoked_at FROM storage_authorization_revocations WHERE authorization_ref=?",(authorization_ref,)).fetchone() if self._connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='storage_authorization_revocations'").fetchone() else None
        return replace(record,revoked_at=str(revoked["revoked_at"])) if revoked else record

    def list_storage_root_authorizations(self) -> tuple[StorageRootAuthorizationRecord, ...]:
        identifiers = [str(row["id"]) for row in self._connection.execute("SELECT id FROM storage_root_authorizations ORDER BY id")]
        return tuple(self.load_storage_root_authorization(identifier) for identifier in identifiers)

    def save_storage_dispatch_record(self, record: StorageDispatchRecord) -> None:
        self._connection.execute("INSERT OR REPLACE INTO storage_dispatch_records (id, request_id, status, payload) VALUES (?, ?, ?, ?)", (record.id, record.request_id, record.status, _dump(record)))
        self._commit()

    def load_storage_dispatch_record(self, record_id: str) -> StorageDispatchRecord:
        return _load_dataclass(StorageDispatchRecord, self._get_payload("storage_dispatch_records", record_id))

    def save_storage_execution_result(self, result: StorageExecutionResult) -> None:
        record_id = f"{result.request_id}:{result.operation_id}"
        self._connection.execute("INSERT OR REPLACE INTO storage_execution_results (id, request_id, status, payload) VALUES (?, ?, ?, ?)", (record_id, result.request_id, result.status.value, _dump(result)))
        self._commit()

    def load_storage_execution_result(self, request_id: str, operation_id: str) -> StorageExecutionResult:
        return _load_dataclass(StorageExecutionResult, self._get_payload("storage_execution_results", f"{request_id}:{operation_id}"))

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
        self._commit()

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
        self._commit()

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
        self._commit()

    def load_key_broker_token_grant(self, grant_id: str) -> KeyBrokerTokenGrant:
        return _load_dataclass(KeyBrokerTokenGrant, self._get_payload("key_broker_token_grants", grant_id))

    def list_key_broker_token_grants(self) -> tuple[KeyBrokerTokenGrant, ...]:
        return tuple(
            _load_dataclass(KeyBrokerTokenGrant, payload)
            for payload in self._list_payloads("key_broker_token_grants")
        )

    def save_audit_event(self, event: AuditEvent) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO audit_events "
            "(id, subject_id, payload, event_type) VALUES (?, ?, ?, ?)",
            (event.id, event.subject_id, _dump(event), event.event_type.value),
        )
        self._commit_agent_mutation()

    def list_audit_events(
        self,
        *,
        subject_prefix: str | None = None,
        event_type: AuditEventType | str | None = None,
        owner_domain: OwnerDomain | str | None = None,
        limit: int | None = None,
        valid_only: bool = False,
    ) -> tuple[AuditEvent, ...]:
        if valid_only:
            self._require_audit_event_normalization_complete()
        clauses: list[str] = []
        params: list[object] = []
        if valid_only:
            clauses.append("event_type IS NOT NULL")
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
        events: list[AuditEvent] = []
        for row in rows:
            payload = str(row["payload"])
            if valid_only and _validated_audit_event_type(payload) is None:
                continue
            events.append(_load_dataclass(AuditEvent, payload))
        return tuple(events)

    def count_audit_events(
        self,
        *,
        subject_prefix: str | None = None,
        event_type: AuditEventType | str | None = None,
        owner_domain: OwnerDomain | str | None = None,
        risk_level: RiskLevel | str | None = None,
    ) -> int:
        if event_type is not None:
            self._require_audit_event_normalization_complete()
        clauses: list[str] = []
        params: list[object] = []
        if subject_prefix:
            clauses.append("subject_id LIKE ?")
            params.append(f"{subject_prefix}%")
        if event_type:
            clauses.append("event_type = ?")
            params.append(AuditEventType(event_type).value)
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

    def _require_audit_event_normalization_complete(self) -> None:
        row = self._connection.execute(
            "SELECT generation, state FROM audit_event_normalization_state "
            "WHERE id=1"
        ).fetchone()
        if (
            row is None
            or int(row["generation"]) != CURRENT_SCHEMA_VERSION
            or str(row["state"]) != "complete"
        ):
            raise sqlite3.OperationalError(
                "audit event normalization is incomplete"
            )

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
        self._harden_database_files()
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

    def _get_collection_payload(self, table: str, row_id: str) -> str:
        key_column = "job_id" if table == "collection_job_states" else "id"
        row = self._connection.execute(
            f"SELECT payload FROM {table} WHERE {key_column} = ?", (row_id,)
        ).fetchone()
        if row is None:
            raise KeyError(row_id)
        return str(row["payload"])

    def _list_collection_payloads(self, table: str) -> Iterable[str]:
        rows = self._connection.execute(
            f"SELECT payload FROM {table} ORDER BY rowid"
        ).fetchall()
        return (str(row["payload"]) for row in rows)

    def _list_payloads(self, table: str) -> Iterable[str]:
        rows = self._connection.execute(f"SELECT payload FROM {table} ORDER BY id").fetchall()
        return (str(row["payload"]) for row in rows)

def _collection_datetime(value: str, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(None):
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp")
    return parsed.astimezone(UTC)


def _bounded_collection_dump(value: Any) -> str:
    payload = _dump(value)
    if len(payload.encode("utf-8")) > MAX_COLLECTION_PAYLOAD_LENGTH:
        raise ValueError("collection payload exceeds the bounded limit")
    return payload


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


def _validated_audit_event_type(payload: str) -> str | None:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        raw = json.loads(payload, object_pairs_hook=unique_object)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(raw, dict) or set(raw) != {
        "id",
        "event_type",
        "owner_domain",
        "subject_id",
        "summary",
        "risk_level",
        "evidence_ids",
        "occurred_at",
    }:
        return None
    if not all(
        isinstance(raw[key], str)
        for key in (
            "id",
            "event_type",
            "owner_domain",
            "subject_id",
            "summary",
            "risk_level",
        )
    ):
        return None
    if not isinstance(raw["evidence_ids"], list) or not all(
        isinstance(item, str) for item in raw["evidence_ids"]
    ):
        return None
    if raw["occurred_at"] is not None and not isinstance(raw["occurred_at"], str):
        return None
    try:
        event = _load_dataclass(AuditEvent, payload)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return None
    return event.event_type.value


# The provider-neutral driver design uses this descriptive name.  Retain
# SQLiteStore as the established public API for existing callers.
OverseerStore = SQLiteStore
