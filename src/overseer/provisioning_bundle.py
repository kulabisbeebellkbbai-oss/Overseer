"""Frozen, bounded contracts for DonutHole provisioning bundles.

This module deliberately contains no preflight, persistence, dispatch, or host
operation behavior.  It defines only the immutable values that later slices
will build and persist authoritatively.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, fields, is_dataclass, replace
from enum import Enum
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Mapping

from .backup_provisioning import DonutHoleBackupProvisioningPlan, ProvisioningStep
from .core import OwnerDomain


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


class _FrozenMapping(Mapping[str, object]):
    """An immutable mapping that remains compatible with dataclass snapshots."""

    def __init__(self, values: Mapping[str, object]) -> None:
        self._values = MappingProxyType(dict(values))

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
        if self.supersedes_plan_id is not None:
            _nonempty_string(self.supersedes_plan_id, "bundle supersedes plan ID")
        expected_supersedes = self.intent.supersedes_plan_id or None
        if self.supersedes_plan_id != expected_supersedes:
            raise ValueError("bundle supersedes plan ID must match intent")
        object.__setattr__(self, "changed_immutable_inputs", _string_tuple(self.changed_immutable_inputs, "changed immutable inputs"))


def canonical_bundle_payload(bundle: ProvisioningBundleV1) -> Mapping[str, object]:
    """Return immutable bundle fields, omitting mutable and derived outbox state.

    An entry's ``bundle_digest`` is the self-referential copy of this result,
    so it too is derived rather than an independent immutable input.
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
                "evidence_ids": entry.evidence_ids,
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
    "INTENT_FIELDS", "PreflightCheck", "ProvisioningBundleV1", "ProvisioningIntentV1",
    "ProvisioningPreflightReport", "ProvisioningReviewOutboxEntry", "bundle_digest",
    "canonical_bundle_bytes", "canonical_bundle_payload", "canonical_digest",
    "parse_provisioning_intent",
]
