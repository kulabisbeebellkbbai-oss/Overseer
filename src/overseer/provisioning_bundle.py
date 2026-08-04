"""Frozen, bounded contracts for DonutHole provisioning bundles.

This module contains read-only preflight and immutable bundle construction. It
deliberately contains no persistence, dispatch, or host-operation behavior.
"""
from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from enum import Enum
import hashlib
import json
import math
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from .backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS
from .backup_provisioning import (
    ADAPTER_SOURCE_PATH, GPG_PATH, SOURCE_PATH, DonutHoleBackupProvisioningPlan,
    ProvisioningStep, _validate_plan, build_plan,
)
from .backup_host_operations import capability_digest as reviewed_capability_digest
from .backup_contract import PROVISIONING_CONTRACT_VERSION
from .core import OwnerDomain
from .storage_control import current_root_identity


INTENT_FIELDS = frozenset({
    "schema_version", "request_id", "plan_id", "kind", "project_id",
    "resource_id", "root_id", "policy_revision", "source_commit",
    "requested_by", "reason", "supersedes_plan_id",
})
INTENT_SCHEMA_VERSION = "1"
INTENT_KIND = "donuthole_encrypted_backup_provisioning_v1"
_INTENT_FIELD_ORDER = (
    "schema_version", "request_id", "plan_id", "kind", "project_id",
    "resource_id", "root_id", "policy_revision", "source_commit",
    "requested_by", "reason", "supersedes_plan_id",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_CHECK_STATUSES = frozenset({"passed", "failed"})
_OUTBOX_STATES = frozenset({"pending", "materialized", "dispatched"})
_REVIEW_OWNERS = (
    ("kira", OwnerDomain.KIRA),
    ("obrien", OwnerDomain.OBRIEN),
    ("security", OwnerDomain.ODO_IDS),
    ("sisko", OwnerDomain.SISKO),
)
REQUIRED_PREFLIGHT_CODES = (
    "INTENT_VALID", "SOURCE_COMMIT_MATCH", "RUNTIME_DIGEST_VALID",
    "CAPABILITY_DIGEST_VALID", "GPG_DIGEST_VALID", "ROOT_AUTHORIZATION_CURRENT",
    "DEPENDENCIES_AVAILABLE", "CANONICAL_BOUNDARIES_VALID", "ROLLBACK_PREREQUISITES_VALID",
)
_ROOT_ALIAS = "donuthole-development"
_ROOT_STATUS = "active"
_ROOT_MAX_BYTES = 1073741824
_OVERSEER_TOKEN_SOURCE_FILE = "/home/god/.local/share/overseer/project/state/api-token"
_OVERSEER_TOKEN_FILE = "/etc/codex-development-backups/keys/overseer.token"
_CURSOR_KEY_FILE = "/etc/codex-development-backups/keys/cursor.key"


class ProvisioningBundleError(ValueError):
    """A bounded bundle cannot be built from the authoritative read snapshot."""


def _read_current_root_authorization(
    store_path: str, project_id: str, root_id: str, policy_revision: str,
    root_identity: str, alias: str, status: str, max_bytes: int, target_digest: str,
) -> Mapping[str, object]:
    """Read one current root authorization without opening or changing a store."""
    path = Path(store_path)
    if not path.is_file():
        raise ValueError("no current exact root authorization exists")
    now = datetime.now(UTC)
    try:
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro&immutable=1", uri=True)
        try:
            rows = connection.execute(
                "SELECT root.payload, approval.payload FROM storage_root_authorizations AS root "
                "JOIN approvals AS approval ON approval.id = json_extract(root.payload, '$.approval_id')"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise ValueError("root authorization read is unavailable") from error
    candidates: list[Mapping[str, object]] = []
    supplied = ("root.register", project_id, root_id, policy_revision, root_identity, alias, status, max_bytes, target_digest)
    for root_payload, approval_payload in rows:
        try:
            record = json.loads(root_payload)
            approval = json.loads(approval_payload)
            exact = tuple(record[name] for name in ("action", "project_id", "root_id", "policy_revision", "root_identity", "alias", "status", "max_bytes", "target_digest"))
            expires_at = datetime.fromisoformat(record["expires_at"])
            approved_at = datetime.fromisoformat(record["approved_at"])
            if expires_at.tzinfo is None or approved_at.tzinfo is None:
                continue
            if (
                exact == supplied and record.get("authorization_status") == "approved"
                and not record.get("revoked_at") and approved_at <= now < expires_at
                and approval.get("id") == record.get("approval_id")
                and approval.get("subject_id") == record.get("authorization_ref")
                and approval.get("status") == "approved"
            ):
                candidates.append(record)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            continue
    if not candidates:
        raise ValueError("no current exact root authorization exists")
    candidates.sort(key=lambda record: (str(record["approved_at"]), str(record["authorization_ref"])), reverse=True)
    if len(candidates) > 1 and candidates[0]["approved_at"] == candidates[1]["approved_at"]:
        raise ValueError("current root authorization is ambiguous")
    record = candidates[0]
    return {"ok": True, **record, "mutation_performed": False, "host_mutation_performed": False, "redactions_applied": True}


def _always_true() -> bool:
    return True


class _FrozenMapping(Mapping[str, object]):
    """An immutable mapping that remains compatible with dataclass snapshots."""

    __slots__ = ("_values",)

    def __init__(self, values: Mapping[str, object]) -> None:
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("frozen mappings are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("frozen mappings are immutable")

    def __getitem__(self, key: str) -> object:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __deepcopy__(self, memo: dict[int, object]) -> dict[str, object]:
        copied = {key: copy.deepcopy(value, memo) for key, value in self._values.items()}
        memo[id(self)] = copied
        return copied


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a non-empty canonical string")
    return value


def _digest(value: object, label: str) -> str:
    value = _nonempty_string(value, label)
    if _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def _string_tuple(value: object, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, tuple) or (nonempty and not value):
        raise ValueError(f"{label} must be an immutable tuple")
    values = tuple(_nonempty_string(item, label) for item in value)
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must not contain duplicates")
    return values


def _snapshot_string_tuple(value: object, label: str) -> tuple[str, ...]:
    """Copy a plan string sequence so caller-owned lists cannot survive."""
    if not isinstance(value, (tuple, list)):
        raise ValueError(f"{label} must be a string sequence")
    return tuple(_nonempty_string(item, label) for item in value)


def _freeze_value(value: object) -> object:
    """Copy a JSON-compatible value into an immutable canonical shape."""
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical mappings require string keys")
        return _FrozenMapping({key: _freeze_value(child) for key, child in value.items()})
    if isinstance(value, tuple):
        return tuple(_freeze_value(child) for child in value)
    if isinstance(value, list):
        return tuple(_freeze_value(child) for child in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical values must be finite")
        return value
    raise ValueError("canonical values must be JSON-compatible")


def _frozen_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    frozen = _freeze_value(value)
    assert isinstance(frozen, Mapping)
    return frozen


def _snapshot_steps(value: object, label: str) -> tuple[ProvisioningStep, ...]:
    if not isinstance(value, (tuple, list)) or any(type(step) is not ProvisioningStep for step in value):
        raise ValueError(f"{label} must be a sequence of exact provisioning steps")
    return tuple(
        ProvisioningStep(
            _nonempty_string(step.operation, f"{label} operation"),
            _frozen_mapping(step.arguments, f"{label} arguments"),
        )
        for step in value
    )


def _snapshot_plan(plan: DonutHoleBackupProvisioningPlan) -> DonutHoleBackupProvisioningPlan:
    """Detach bundle-owned values from all caller-owned mutable plan inputs."""
    if not isinstance(plan.root_registrations, (tuple, list)):
        raise ValueError("bundle plan root registrations must be a sequence")
    return replace(
        plan,
        root_authorization_refs=_frozen_mapping(plan.root_authorization_refs, "bundle plan authorization references"),
        root_registrations=tuple(
            _frozen_mapping(registration, "bundle plan root registration")
            for registration in plan.root_registrations
        ),
        evidence_ids=_frozen_mapping(plan.evidence_ids, "bundle plan evidence IDs"),
        steps=_snapshot_steps(plan.steps, "bundle plan steps"),
        rollback_steps=_snapshot_steps(plan.rollback_steps, "bundle plan rollback steps"),
        read_only_paths=_snapshot_string_tuple(plan.read_only_paths, "bundle plan read-only paths"),
        read_write_paths=_snapshot_string_tuple(plan.read_write_paths, "bundle plan read-write paths"),
    )


def _canonical_value(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _canonical_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical mappings require string keys")
        return {key: _canonical_value(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(child) for child in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical values must be finite")
        return value
    raise ValueError("canonical digest value is unsupported")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _canonical_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_digest(value: object) -> str:
    """Return the SHA-256 digest of canonical JSON for a typed value."""
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class ProvisioningIntentV1:
    schema_version: str
    request_id: str
    plan_id: str
    kind: str
    project_id: str
    resource_id: str
    root_id: str
    policy_revision: str
    source_commit: str
    requested_by: str
    reason: str
    supersedes_plan_id: str

    def __post_init__(self) -> None:
        values = tuple(getattr(self, field) for field in _INTENT_FIELD_ORDER)
        if any(not isinstance(value, str) for value in values):
            raise ValueError("exact typed provisioning intent values are required")
        if self.schema_version != INTENT_SCHEMA_VERSION or self.kind != INTENT_KIND:
            raise ValueError("exact typed provisioning intent values are required")
        required = values[:-1]
        if any(not value or value != value.strip() for value in required) or (
            self.supersedes_plan_id and self.supersedes_plan_id != self.supersedes_plan_id.strip()
        ):
            raise ValueError("exact typed provisioning intent values are required")
        if _COMMIT.fullmatch(self.source_commit) is None:
            raise ValueError("exact typed provisioning intent values are required")


def parse_provisioning_intent(payload: Mapping[str, object]) -> ProvisioningIntentV1:
    """Decode exactly one caller-bounded provisioning intent, failing closed."""
    if not isinstance(payload, Mapping) or set(payload) != INTENT_FIELDS:
        raise ValueError("exact typed provisioning intent fields are required")
    if any(not isinstance(name, str) or not isinstance(payload[name], str) for name in INTENT_FIELDS):
        raise ValueError("exact typed provisioning intent values are required")
    try:
        return ProvisioningIntentV1(**{name: payload[name] for name in INTENT_FIELDS})
    except (TypeError, ValueError) as error:
        raise ValueError("exact typed provisioning intent values are required") from error


@dataclass(frozen=True)
class PreflightDependencies:
    """Read-only dependencies needed to resolve one deterministic preflight."""

    source_path: str
    source_head: Callable[[str], str]
    runtime_digest: Callable[[str, str], str]
    capability_digest: Callable[[str, Mapping[str, object]], str]
    file_digest: Callable[[str], str]
    executable_exists: Callable[[str], bool]
    root_path: str = SOURCE_PATH
    root_identity: Callable[[str], str] = current_root_identity
    resolve_root_authorization: Callable[..., Mapping[str, object]] = _read_current_root_authorization
    canonical_boundaries_valid: Callable[[], bool] = _always_true
    rollback_prerequisites_valid: Callable[[], bool] = _always_true
    predecessor_lookup: Callable[[str], ProvisioningBundleV1 | None] | None = None
    authoritative_chain_tip: Callable[[], str | None] | None = None


@dataclass(frozen=True)
class PreflightCheck:
    code: str
    status: str
    evidence_digest: str
    summary: str

    def __post_init__(self) -> None:
        _nonempty_string(self.code, "preflight check code")
        if self.status not in _CHECK_STATUSES:
            raise ValueError("preflight check status is unsupported")
        _digest(self.evidence_digest, "preflight check evidence digest")
        _nonempty_string(self.summary, "preflight check summary")


@dataclass(frozen=True)
class ProvisioningPreflightReport:
    report_id: str
    plan_id: str
    resolved_inputs: Mapping[str, object]
    checks: tuple[PreflightCheck, ...]
    passed: bool
    report_digest: str

    def __post_init__(self) -> None:
        _nonempty_string(self.report_id, "preflight report ID")
        _nonempty_string(self.plan_id, "preflight report plan ID")
        object.__setattr__(self, "resolved_inputs", _frozen_mapping(self.resolved_inputs, "resolved inputs"))
        if not isinstance(self.checks, tuple) or not self.checks or any(type(check) is not PreflightCheck for check in self.checks):
            raise ValueError("preflight checks must be a non-empty immutable tuple")
        if not isinstance(self.passed, bool) or self.passed != all(check.status == "passed" for check in self.checks):
            raise ValueError("preflight passed state must match checks")
        _digest(self.report_digest, "preflight report digest")


def canonical_root_target_digest(root_identity: str) -> str:
    """Return the versioned, code-owned root target binding for an identity."""
    return canonical_digest({"version": "1", "root_identity": _digest(root_identity, "root identity")})


def _check(code: str, passed: bool, evidence: Mapping[str, object], summary: str) -> PreflightCheck:
    return PreflightCheck(code, "passed" if passed else "failed", canonical_digest(evidence), summary)


def _safe_read(callback: Callable[..., object], *arguments: object) -> tuple[object | None, bool]:
    try:
        return callback(*arguments), True
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return None, False


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _valid_commit(value: object) -> bool:
    return isinstance(value, str) and _COMMIT.fullmatch(value) is not None


def _resolved_digest(value: object) -> str:
    return value if _valid_digest(value) else ""


def _resolved_commit(value: object) -> str:
    return value if _valid_commit(value) else ""


def _resolved_authorization_ref(value: object) -> str:
    return value if isinstance(value, str) and value and value == value.strip() else ""


def run_provisioning_preflight(
    store_path: str, intent: ProvisioningIntentV1, dependencies: PreflightDependencies,
) -> ProvisioningPreflightReport:
    """Resolve the fixed authority inputs without changing store or host state."""
    source_head, source_available = _safe_read(dependencies.source_head, dependencies.source_path)
    runtime, runtime_available = _safe_read(
        dependencies.runtime_digest, dependencies.source_path, intent.source_commit,
    )
    capability, capability_available = _safe_read(
        dependencies.capability_digest, intent.source_commit, EXPECTED_BACKUP_TOOL_SCHEMAS,
    )
    gpg, gpg_available = _safe_read(dependencies.file_digest, GPG_PATH)
    executable, executable_available = _safe_read(dependencies.executable_exists, GPG_PATH)
    identity, identity_available = _safe_read(dependencies.root_identity, dependencies.root_path)
    identity_value = _resolved_digest(identity)
    target = canonical_root_target_digest(identity_value) if identity_value else ""
    authority: object | None = None
    authority_available = False
    if identity_value and target:
        authority, authority_available = _safe_read(
            dependencies.resolve_root_authorization,
            store_path, intent.project_id, intent.root_id, intent.policy_revision,
            identity_value, _ROOT_ALIAS, _ROOT_STATUS, _ROOT_MAX_BYTES, target,
        )
    authorization_ref = _resolved_authorization_ref(
        authority.get("authorization_ref") if isinstance(authority, Mapping) else None
    )
    boundaries, boundaries_available = _safe_read(dependencies.canonical_boundaries_valid)
    rollback, rollback_available = _safe_read(dependencies.rollback_prerequisites_valid)

    intent_valid = type(intent) is ProvisioningIntentV1
    source_match = source_available and _valid_commit(source_head) and source_head == intent.source_commit
    runtime_valid = runtime_available and _valid_digest(runtime)
    expected_capability = reviewed_capability_digest(
        intent.source_commit, EXPECTED_BACKUP_TOOL_SCHEMAS, PROVISIONING_CONTRACT_VERSION,
    )
    capability_valid = capability_available and _valid_digest(capability) and capability == expected_capability
    gpg_valid = gpg_available and _valid_digest(gpg)
    authority_current = authority_available and bool(authorization_ref)
    dependencies_available = all((
        source_available, runtime_available, capability_available, gpg_available,
        executable_available, identity_available, authority_available,
    )) and executable is True
    boundaries_valid = (
        boundaries_available and boundaries is True and dependencies.source_path == ADAPTER_SOURCE_PATH
        and dependencies.root_path == SOURCE_PATH
    )
    rollback_valid = rollback_available and rollback is True
    checks = (
        _check("INTENT_VALID", intent_valid, {"valid": intent_valid}, "The bounded intent is valid."),
        _check("SOURCE_COMMIT_MATCH", source_match, {"available": source_available, "matched": source_match}, "The authoritative source commit matches the bounded intent."),
        _check("RUNTIME_DIGEST_VALID", runtime_valid, {"available": runtime_available, "valid": runtime_valid}, "The authoritative runtime digest is valid."),
        _check("CAPABILITY_DIGEST_VALID", capability_valid, {"available": capability_available, "valid": capability_valid}, "The authoritative capability digest is valid."),
        _check("GPG_DIGEST_VALID", gpg_valid, {"available": gpg_available, "valid": gpg_valid}, "The authoritative GPG digest is valid."),
        _check("ROOT_AUTHORIZATION_CURRENT", authority_current, {"available": authority_available, "current": authority_current}, "The exact root authorization is current."),
        _check("DEPENDENCIES_AVAILABLE", dependencies_available, {"available": dependencies_available}, "Required read dependencies are available."),
        _check("CANONICAL_BOUNDARIES_VALID", boundaries_valid, {"available": boundaries_available, "valid": boundaries_valid}, "Canonical boundaries are valid."),
        _check("ROLLBACK_PREREQUISITES_VALID", rollback_valid, {"available": rollback_available, "valid": rollback_valid}, "Rollback prerequisites are valid."),
    )
    resolved_inputs = {
        "source_commit": _resolved_commit(source_head),
        "runtime_digest": _resolved_digest(runtime),
        "capability_digest": _resolved_digest(capability),
        "gpg_sha256": _resolved_digest(gpg),
        "root_identity": identity_value,
        "target_digest": target,
        "authorization_ref": authorization_ref,
    }
    report_id = f"preflight.{intent.plan_id}"
    report_digest = canonical_digest({
        "report_id": report_id, "plan_id": intent.plan_id, "resolved_inputs": resolved_inputs,
        "checks": [asdict(item) for item in checks],
    })
    return ProvisioningPreflightReport(
        report_id, intent.plan_id, resolved_inputs, checks,
        all(item.status == "passed" for item in checks), report_digest,
    )


@dataclass(frozen=True)
class ProvisioningReviewOutboxEntry:
    id: str
    message_id: str
    plan_id: str
    bundle_digest: str
    role: str
    owner_domain: OwnerDomain
    related_resource_id: str
    subject: str
    message: str
    acceptance_criteria: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    state: str = "pending"

    def __post_init__(self) -> None:
        for label, value in (
            ("outbox ID", self.id), ("outbox message ID", self.message_id),
            ("outbox plan ID", self.plan_id), ("outbox resource ID", self.related_resource_id),
            ("outbox subject", self.subject), ("outbox message", self.message),
        ):
            _nonempty_string(value, label)
        _digest(self.bundle_digest, "outbox bundle digest")
        if not isinstance(self.owner_domain, OwnerDomain):
            raise ValueError("outbox owner domain is unsupported")
        if (self.role, self.owner_domain) not in _REVIEW_OWNERS:
            raise ValueError("outbox role and owner domain are unsupported")
        object.__setattr__(self, "acceptance_criteria", _string_tuple(self.acceptance_criteria, "outbox acceptance criteria", nonempty=True))
        evidence_ids = _string_tuple(self.evidence_ids, "outbox evidence IDs", nonempty=True)
        for evidence_id in evidence_ids:
            _digest(evidence_id, "outbox evidence ID")
        object.__setattr__(self, "evidence_ids", evidence_ids)
        if self.state not in _OUTBOX_STATES:
            raise ValueError("outbox state is unsupported")


@dataclass(frozen=True)
class ProvisioningBundleV1:
    schema_version: str
    intent: ProvisioningIntentV1
    plan: DonutHoleBackupProvisioningPlan
    preflight: ProvisioningPreflightReport
    outbox: tuple[ProvisioningReviewOutboxEntry, ...]
    bundle_digest: str
    supersedes_plan_id: str | None
    changed_immutable_inputs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != INTENT_SCHEMA_VERSION:
            raise ValueError("bundle schema version is unsupported")
        if type(self.intent) is not ProvisioningIntentV1 or type(self.plan) is not DonutHoleBackupProvisioningPlan:
            raise ValueError("bundle requires exact typed intent and plan")
        if type(self.preflight) is not ProvisioningPreflightReport:
            raise ValueError("bundle requires an exact preflight report")
        object.__setattr__(self, "plan", _snapshot_plan(self.plan))
        if self.intent.plan_id != self.plan.plan_id:
            raise ValueError("bundle plan ID must match intent")
        if self.preflight.plan_id != self.plan.plan_id:
            raise ValueError("bundle plan ID must match preflight")
        if not isinstance(self.outbox, tuple) or any(type(entry) is not ProvisioningReviewOutboxEntry for entry in self.outbox):
            raise ValueError("bundle requires four exact ordered review outbox entries")
        if tuple((entry.role, entry.owner_domain) for entry in self.outbox) != _REVIEW_OWNERS:
            raise ValueError("bundle requires four exact ordered review outbox entries")
        if any(entry.plan_id != self.plan.plan_id for entry in self.outbox):
            raise ValueError("bundle outbox must bind the exact plan")
        _digest(self.bundle_digest, "bundle digest")
        if any(entry.bundle_digest != self.bundle_digest for entry in self.outbox):
            raise ValueError("bundle outbox digest must match bundle")
        expected_evidence = (self.plan.plan_digest, self.preflight.report_digest, self.bundle_digest)
        if any(entry.evidence_ids != expected_evidence for entry in self.outbox):
            raise ValueError("bundle outbox evidence must be exact and ordered")
        if self.supersedes_plan_id is not None:
            _nonempty_string(self.supersedes_plan_id, "bundle supersedes plan ID")
        expected_supersedes = self.intent.supersedes_plan_id or None
        if self.supersedes_plan_id != expected_supersedes:
            raise ValueError("bundle supersedes plan ID must match intent")
        object.__setattr__(self, "changed_immutable_inputs", _string_tuple(self.changed_immutable_inputs, "changed immutable inputs"))


def _canonical_root_registration(intent: ProvisioningIntentV1, resolved_inputs: Mapping[str, object]) -> Mapping[str, object]:
    return {
        "project_id": intent.project_id,
        "root_id": intent.root_id,
        "policy_revision": intent.policy_revision,
        "host_path": SOURCE_PATH,
        "alias": _ROOT_ALIAS,
        "max_bytes": _ROOT_MAX_BYTES,
        "authorization_ref": str(resolved_inputs["authorization_ref"]),
    }


def _review_outbox(
    intent: ProvisioningIntentV1,
    plan: DonutHoleBackupProvisioningPlan,
    report: ProvisioningPreflightReport,
    bundle_digest_value: str,
) -> tuple[ProvisioningReviewOutboxEntry, ...]:
    evidence_ids = (plan.plan_digest, report.report_digest, bundle_digest_value)
    return tuple(
        ProvisioningReviewOutboxEntry(
            id=f"outbox.{intent.plan_id}.{role}",
            message_id=f"crew.{owner.value}.review-{intent.plan_id}",
            plan_id=intent.plan_id,
            bundle_digest=bundle_digest_value,
            role=role,
            owner_domain=owner,
            related_resource_id=intent.resource_id,
            subject="Review exact DonutHole provisioning bundle",
            message="Review the immutable plan and preflight evidence only.",
            acceptance_criteria=("Review the exact immutable evidence.",),
            evidence_ids=evidence_ids,
        )
        for role, owner in _REVIEW_OWNERS
    )


def _immutable_inputs(
    plan: DonutHoleBackupProvisioningPlan, report: ProvisioningPreflightReport,
) -> Mapping[str, object]:
    return {
        "gpg_sha256": plan.gpg_sha256,
        "adapter_commit": plan.adapter_commit,
        "runtime_digest": plan.runtime_digest,
        "capability_digest": plan.capability_digest,
        "root_authorization_refs": plan.root_authorization_refs,
        "root_registrations": plan.root_registrations,
        "resolved_preflight": report.resolved_inputs,
    }


def changed_immutable_inputs(
    previous: ProvisioningBundleV1 | None,
    plan: DonutHoleBackupProvisioningPlan,
    report: ProvisioningPreflightReport,
) -> tuple[str, ...]:
    """Return sorted immutable differences for a supplied authoritative predecessor."""
    if previous is None:
        return ()
    previous_values = _immutable_inputs(previous.plan, previous.preflight)
    current_values = _immutable_inputs(plan, report)
    return tuple(sorted(
        field for field in current_values if _canonical_value(current_values[field]) != _canonical_value(previous_values[field])
    ))


def _authoritative_predecessor(
    intent: ProvisioningIntentV1, dependencies: PreflightDependencies,
) -> ProvisioningBundleV1 | None:
    if not intent.supersedes_plan_id:
        return None
    if dependencies.predecessor_lookup is None or dependencies.authoritative_chain_tip is None:
        raise ProvisioningBundleError("PREDECESSOR_UNAVAILABLE")
    predecessor, available = _safe_read(dependencies.predecessor_lookup, intent.supersedes_plan_id)
    if not available or type(predecessor) is not ProvisioningBundleV1:
        raise ProvisioningBundleError("PREDECESSOR_UNAVAILABLE")
    tip, tip_available = _safe_read(dependencies.authoritative_chain_tip)
    if not tip_available or tip != intent.supersedes_plan_id:
        raise ProvisioningBundleError("PREDECESSOR_NOT_CURRENT")
    if not _valid_predecessor_contract(predecessor) or predecessor.plan.plan_id != intent.supersedes_plan_id or predecessor.supersedes_plan_id == intent.plan_id:
        raise ProvisioningBundleError("PREDECESSOR_INVALID")
    return predecessor


def _valid_predecessor_contract(predecessor: ProvisioningBundleV1) -> bool:
    """Validate every immutable predecessor binding before chain comparison."""
    try:
        if predecessor.intent.plan_id != predecessor.plan.plan_id or predecessor.preflight.plan_id != predecessor.plan.plan_id:
            return False
        _validate_plan(predecessor.plan)
        if tuple(check.code for check in predecessor.preflight.checks) != REQUIRED_PREFLIGHT_CODES:
            return False
        if not predecessor.preflight.passed or any(check.status != "passed" for check in predecessor.preflight.checks):
            return False
        expected_report = canonical_digest({
            "report_id": predecessor.preflight.report_id, "plan_id": predecessor.preflight.plan_id,
            "resolved_inputs": predecessor.preflight.resolved_inputs,
            "checks": [asdict(item) for item in predecessor.preflight.checks],
        })
        if predecessor.preflight.report_digest != expected_report:
            return False
        expected_evidence = (predecessor.plan.plan_digest, predecessor.preflight.report_digest, predecessor.bundle_digest)
        if (
            tuple((entry.role, entry.owner_domain) for entry in predecessor.outbox) != _REVIEW_OWNERS
            or any(entry.plan_id != predecessor.plan.plan_id or entry.bundle_digest != predecessor.bundle_digest or entry.evidence_ids != expected_evidence for entry in predecessor.outbox)
        ):
            return False
        return bundle_digest(predecessor) == predecessor.bundle_digest
    except (TypeError, ValueError):
        return False


def build_provisioning_bundle(
    store_path: str, intent: ProvisioningIntentV1, dependencies: PreflightDependencies,
) -> ProvisioningBundleV1:
    """Build one immutable, read-only review bundle from the preflight snapshot."""
    report = run_provisioning_preflight(store_path, intent, dependencies)
    if not report.passed:
        raise ProvisioningBundleError("PREFLIGHT_FAILED")
    predecessor = _authoritative_predecessor(intent, dependencies)
    evidence_ids = {
        role: f"crew.{owner.value}.review-{intent.plan_id}"
        for role, owner in _REVIEW_OWNERS
    }
    plan = build_plan(
        intent.plan_id,
        str(report.resolved_inputs["gpg_sha256"]),
        intent.source_commit,
        str(report.resolved_inputs["runtime_digest"]),
        str(report.resolved_inputs["capability_digest"]),
        {str(report.resolved_inputs["target_digest"]): str(report.resolved_inputs["authorization_ref"])},
        (_canonical_root_registration(intent, report.resolved_inputs),),
        _OVERSEER_TOKEN_SOURCE_FILE,
        _OVERSEER_TOKEN_FILE,
        _CURSOR_KEY_FILE,
        evidence_ids,
    )
    changed = changed_immutable_inputs(predecessor, plan, report)
    placeholder_digest = "sha256:" + "0" * 64
    provisional = ProvisioningBundleV1(
        "1", intent, plan, report,
        _review_outbox(intent, plan, report, placeholder_digest),
        placeholder_digest, intent.supersedes_plan_id or None, changed,
    )
    digest = bundle_digest(provisional)
    outbox = _review_outbox(intent, plan, report, digest)
    return ProvisioningBundleV1(
        "1", intent, plan, report, outbox, digest,
        intent.supersedes_plan_id or None, changed,
    )


def canonical_bundle_payload(bundle: ProvisioningBundleV1) -> Mapping[str, object]:
    """Return immutable bundle fields, omitting mutable and derived outbox state.

    An entry's ``bundle_digest`` and matching copy in ``evidence_ids`` are
    self-referential derived values, not independent immutable inputs.
    """
    if type(bundle) is not ProvisioningBundleV1:
        raise ValueError("bundle digest requires an exact provisioning bundle")
    return {
        "schema_version": bundle.schema_version,
        "intent": bundle.intent,
        "plan": bundle.plan,
        "preflight": bundle.preflight,
        "outbox": tuple(
            {
                "id": entry.id,
                "message_id": entry.message_id,
                "plan_id": entry.plan_id,
                "role": entry.role,
                "owner_domain": entry.owner_domain,
                "related_resource_id": entry.related_resource_id,
                "subject": entry.subject,
                "message": entry.message,
                "acceptance_criteria": entry.acceptance_criteria,
                "evidence_ids": entry.evidence_ids[:2],
            }
            for entry in bundle.outbox
        ),
        "supersedes_plan_id": bundle.supersedes_plan_id,
        "changed_immutable_inputs": bundle.changed_immutable_inputs,
    }


def canonical_bundle_bytes(bundle: ProvisioningBundleV1) -> bytes:
    """Return the stable immutable bytes covered by a bundle digest."""
    return _canonical_bytes(canonical_bundle_payload(bundle))


def bundle_digest(bundle: ProvisioningBundleV1) -> str:
    """Digest all immutable bundle fields while excluding mutable outbox state."""
    return "sha256:" + hashlib.sha256(canonical_bundle_bytes(bundle)).hexdigest()


__all__ = [
    "INTENT_FIELDS", "REQUIRED_PREFLIGHT_CODES", "PreflightCheck", "PreflightDependencies",
    "ProvisioningBundleError", "ProvisioningBundleV1", "ProvisioningIntentV1",
    "ProvisioningPreflightReport", "ProvisioningReviewOutboxEntry", "build_provisioning_bundle",
    "bundle_digest", "canonical_bundle_bytes", "canonical_bundle_payload", "canonical_digest",
    "canonical_root_target_digest", "changed_immutable_inputs", "parse_provisioning_intent",
    "run_provisioning_preflight",
]
