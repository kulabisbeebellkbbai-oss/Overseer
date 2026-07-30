"""Validated, bounded handoff packages for provider-neutral agent drivers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import secrets
from typing import Callable, Protocol
from uuid import uuid4

from .agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    AgentHandoffPackage,
    ActiveAgentRisk,
    ActiveAgentRiskLevel,
    DriverEpoch,
    FailoverDecision,
    FailoverPolicy,
    ProviderHealthObservation,
    ProviderHealthState,
)

MAX_HANDOFF_DEPTH = 8
MAX_HANDOFF_ITEMS = 256
MAX_HANDOFF_STRING_LENGTH = 4096
_EPHEMERAL_ATTESTATION_KEY = secrets.token_bytes(32)
_EPHEMERAL_PACKAGES: dict[str, AgentHandoffPackage] = {}


def evaluate_failover_evidence(
    *,
    decision_id: str,
    instance_id: str,
    outgoing_epoch: DriverEpoch,
    operation_generation: int,
    policy: FailoverPolicy | None,
    health: tuple[ProviderHealthObservation, ...],
    checkpoint: AgentCheckpoint | None,
    risks: tuple[ActiveAgentRisk, ...],
    candidate_capabilities: Mapping[str, AgentCapabilities],
    healthy_candidates: frozenset[str],
    candidate_readiness: Mapping[str, str],
    required_capabilities: AgentCapabilities,
    evaluated_at: str,
    transition_changed: bool = False,
) -> FailoverDecision:
    """Evaluate persisted evidence without mutation or provider interaction."""
    now = _aware(evaluated_at)
    blockers: list[str] = []
    selected: str | None = None
    if policy is not None and policy.instance_id != instance_id:
        raise ValueError("failover policy belongs to another instance")
    approved_provider_ids = (
        frozenset(policy.approved_fallback_provider_ids) if policy else frozenset()
    )
    if any(
        item.instance_id != instance_id
        or item.provider_id not in {outgoing_epoch.provider_id, *approved_provider_ids}
        for item in health
    ):
        raise ValueError("foreign health evidence is not allowed")
    if any(item.instance_id != instance_id for item in risks):
        raise ValueError("foreign risk evidence is not allowed")
    if checkpoint is not None and (
        checkpoint.instance_id != instance_id
        or checkpoint.driver_epoch_id != outgoing_epoch.id
        or checkpoint.session_id != outgoing_epoch.session_id
    ):
        raise ValueError("foreign checkpoint evidence is not allowed")
    if policy is None or not policy.approved:
        blockers.append("failover policy missing or not approved")
    approval_at = _aware(policy.approved_at) if policy and policy.approved_at else None
    outgoing_health = tuple(
        item
        for item in health
        if item.instance_id == instance_id and item.provider_id == outgoing_epoch.provider_id
    )
    ordered_outgoing = tuple(
        sorted(outgoing_health, key=lambda item: _aware(item.observed_at))
    )
    failure_states = {
        ProviderHealthState.TRANSPORT_FAILURE,
        ProviderHealthState.FAILED,
    }
    trailing_failures: list[ProviderHealthObservation] = []
    for item in reversed(ordered_outgoing):
        if item.state not in failure_states:
            break
        trailing_failures.append(item)
    failures = tuple(reversed(trailing_failures))
    if failures and (approval_at is None or approval_at >= min(_aware(x.observed_at) for x in failures)):
        blockers.append("policy approval does not predate failure sequence")
    if outgoing_health and all(x.state is ProviderHealthState.SLOW for x in outgoing_health):
        blockers.append("slow response is not a failover trigger")
    threshold = policy.failure_threshold if policy else 1
    if len(failures) < threshold:
        blockers.append("failure threshold not reached")
    checkpoint_valid = checkpoint is not None
    if checkpoint is not None:
        try:
            created = _aware(checkpoint.created_at)
            expires = _aware(checkpoint.expires_at) if checkpoint.expires_at else None
        except ValueError:
            checkpoint_valid = False
        else:
            maximum_age = policy.checkpoint_max_age_seconds if policy else 0
            checkpoint_valid = (
                checkpoint.instance_id == instance_id
                and checkpoint.driver_epoch_id == outgoing_epoch.id
                and checkpoint.session_id == outgoing_epoch.session_id
                and timedelta(0) <= now - created <= timedelta(seconds=maximum_age)
                and (expires is None or expires > now)
            )
    if not checkpoint_valid:
        blockers.append("checkpoint missing, stale, expired, or incorrectly bound")
    if any(
        risk.instance_id == instance_id
        and risk.risk_level is ActiveAgentRiskLevel.HIGH
        and not risk.resolved
        for risk in risks
    ):
        blockers.append("unresolved high-risk action")
    if (
        checkpoint is not None
        and checkpoint.evidence.get("status") not in {"ready", "completed", "checkpointed"}
    ) or any(
        risk.instance_id == instance_id and not risk.transferable and not risk.resolved
        for risk in risks
    ):
        blockers.append("non-transferable active operation or checkpoint state")
    ordered = (
        tuple(
            item
            for item in policy.approved_fallback_provider_ids
            if item in healthy_candidates
            and item in candidate_capabilities
            and item in candidate_readiness
        )
        if policy
        else ()
    )
    if not ordered:
        blockers.append("no healthy approved fallback")
    else:
        for provider_id in ordered:
            capabilities = candidate_capabilities.get(provider_id)
            if (
                capabilities is not None
                and capabilities.handoff_import
                and capabilities.supports(required_capabilities)
            ):
                selected = provider_id
                break
        if selected is None:
            blockers.append("fallback capability mismatch or missing handoff_import")
    if transition_changed:
        blockers.append("transition, reservation, or epoch already changed")
    expires_at = now + timedelta(
        seconds=policy.decision_lifetime_seconds if policy else 1
    )
    return FailoverDecision(
        id=decision_id,
        instance_id=instance_id,
        outgoing_epoch_id=outgoing_epoch.id,
        outgoing_provider_id=outgoing_epoch.provider_id,
        operation_generation=operation_generation,
        policy_id=policy.id if policy else None,
        incoming_provider_id=selected if not blockers else None,
        allowed=not blockers,
        blockers=tuple(blockers),
        health_evidence_ids=tuple(item.id for item in health),
        risk_evidence_ids=tuple(item.id for item in risks),
        evidence_timestamps=tuple(
            item
            for item in (
                policy.approved_at if policy else None,
                *(observation.observed_at for observation in health),
                checkpoint.created_at if checkpoint else None,
                checkpoint.expires_at if checkpoint else None,
            )
            if item is not None
        ),
        readiness_evidence_refs=tuple(
            candidate_readiness[item]
            for item in (
                policy.approved_fallback_provider_ids if policy else ()
            )
            if item in candidate_readiness
        ),
        checkpoint_id=checkpoint.id if checkpoint else None,
        evaluated_at=evaluated_at,
        expires_at=expires_at.isoformat(),
    )


def _aware(value: str | None) -> datetime:
    if value is None:
        raise ValueError("timestamp is required")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed


class AgentHandoffStore(Protocol):
    def load_agent_checkpoint(self, checkpoint_id: str) -> AgentCheckpoint: ...

    def save_agent_handoff(self, handoff: AgentHandoffPackage) -> None: ...

    def sign_and_save_agent_handoff(
        self, handoff: AgentHandoffPackage
    ) -> AgentHandoffPackage: ...

    def verify_agent_handoff_attestation(
        self, handoff: AgentHandoffPackage
    ) -> bool: ...


_SENSITIVE_KEY_RE = re.compile(
    r"(?:token|cookie|authorization|password|private[_\s-]?key|bearer|"
    r"secret|credential|api[_\s-]?key|access[_\s-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?:\b(?:authorization|bearer|cookie|password|private[_\s-]?key|token)"
    r"\b\s*[:=]|\bbearer\s+[A-Za-z0-9._~+/-]{4,}|"
    r"resolved[_\s-]?secret|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bsk-[A-Za-z0-9_-]{6,})",
    re.IGNORECASE,
)


class AgentHandoffService:
    """Build and validate handoffs without accepting credential material."""

    def __init__(
        self,
        store: AgentHandoffStore | None = None,
        *,
        clock: Callable[[], str] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.store = store
        self._clock = clock or (
            lambda: datetime.now(timezone.utc).isoformat(timespec="microseconds")
        )
        self._id_factory = id_factory or (lambda: f"handoff.{uuid4().hex}")

    def build(
        self,
        *,
        instance_id: str,
        outgoing_epoch_id: str,
        incoming_provider_id: str,
        objective: str,
        evidence: Mapping[str, object],
        required_capabilities: AgentCapabilities,
        checkpoint_id: str | None = None,
        package_id: str | None = None,
    ) -> AgentHandoffPackage:
        _validate_handoff_bounds(objective)
        _validate_handoff_bounds(evidence)
        _reject_sensitive_material(objective, key="objective")
        _reject_sensitive_material(evidence)
        package = AgentHandoffPackage(
            id=package_id or self._id_factory(),
            instance_id=instance_id,
            outgoing_epoch_id=outgoing_epoch_id,
            incoming_provider_id=incoming_provider_id,
            objective=objective,
            checkpoint_id=checkpoint_id,
            required_capabilities=required_capabilities,
            evidence=evidence,
            created_at=self._clock(),
        )
        if self.store is not None and hasattr(
            self.store, "sign_and_save_agent_handoff"
        ):
            package = self.store.sign_and_save_agent_handoff(package)
        else:
            package = _attest_handoff(package, _EPHEMERAL_ATTESTATION_KEY)
            _EPHEMERAL_PACKAGES[package.id] = package
            if self.store is not None:
                self.store.save_agent_handoff(package)
        return package

    def build_from_store(
        self,
        *,
        instance_id: str,
        outgoing_epoch: DriverEpoch,
        checkpoint: AgentCheckpoint,
        incoming_provider_id: str,
        objective: str,
        required_capabilities: AgentCapabilities,
    ) -> AgentHandoffPackage:
        if (
            checkpoint.instance_id != instance_id
            or checkpoint.driver_epoch_id != outgoing_epoch.id
            or checkpoint.session_id != outgoing_epoch.session_id
            or outgoing_epoch.instance_id != instance_id
        ):
            raise ValueError("checkpoint does not belong to the outgoing driver epoch")
        if self.store is not None:
            try:
                persisted = self.store.load_agent_checkpoint(checkpoint.id)
            except KeyError as error:
                raise ValueError("checkpoint must be persisted before handoff") from error
            if persisted != checkpoint:
                raise ValueError("checkpoint does not match the persisted record")
        return self.build(
            instance_id=instance_id,
            outgoing_epoch_id=outgoing_epoch.id,
            incoming_provider_id=incoming_provider_id,
            objective=objective,
            checkpoint_id=checkpoint.id,
            required_capabilities=required_capabilities,
            evidence={
                "checkpoint_id": checkpoint.id,
                "outgoing_epoch_id": outgoing_epoch.id,
                "status": "ready",
            },
        )

    def validate(
        self,
        package: AgentHandoffPackage,
        incoming_capabilities: AgentCapabilities,
    ) -> AgentHandoffPackage:
        _validate_handoff_bounds(package.objective)
        _validate_handoff_bounds(package.evidence)
        _reject_sensitive_material(package.objective, key="objective")
        _reject_sensitive_material(package.evidence)
        if self.store is not None and hasattr(
            self.store, "verify_agent_handoff_attestation"
        ):
            attested = self.store.verify_agent_handoff_attestation(package)
        else:
            attested = (
                _EPHEMERAL_PACKAGES.get(package.id) == package
                and _verify_handoff(package, _EPHEMERAL_ATTESTATION_KEY)
            )
        if not attested:
            raise ValueError("handoff attestation is missing or invalid")
        if not incoming_capabilities.handoff_import:
            raise ValueError("incoming provider lacks handoff_import capability")
        if not incoming_capabilities.supports(package.required_capabilities):
            raise ValueError("incoming provider lacks required capabilities")
        return package


def canonical_handoff_bytes(package: AgentHandoffPackage) -> bytes:
    from .serialization import to_jsonable

    payload = to_jsonable(replace(package, signature=None))
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _attest_handoff(
    package: AgentHandoffPackage, key: bytes
) -> AgentHandoffPackage:
    versioned = replace(
        package, attestation_version="hmac-sha256-v1", signature=None
    )
    signature = hmac.new(
        key, canonical_handoff_bytes(versioned), hashlib.sha256
    ).hexdigest()
    return replace(versioned, signature=signature)


def _verify_handoff(package: AgentHandoffPackage, key: bytes) -> bool:
    if (
        package.attestation_version != "hmac-sha256-v1"
        or package.signature is None
    ):
        return False
    expected = hmac.new(
        key, canonical_handoff_bytes(package), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, package.signature)


def _validate_handoff_bounds(value: object, *, depth: int = 0) -> None:
    if isinstance(value, str):
        if len(value) > MAX_HANDOFF_STRING_LENGTH:
            raise ValueError("handoff string size exceeds limit")
        return
    if isinstance(value, Mapping):
        if depth > MAX_HANDOFF_DEPTH:
            raise ValueError("handoff nesting depth exceeds limit")
        if len(value) > MAX_HANDOFF_ITEMS:
            raise ValueError("handoff item count exceeds limit")
        for key, child_value in value.items():
            _validate_handoff_bounds(str(key), depth=depth)
            _validate_handoff_bounds(child_value, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if depth > MAX_HANDOFF_DEPTH:
            raise ValueError("handoff nesting depth exceeds limit")
        if len(value) > MAX_HANDOFF_ITEMS:
            raise ValueError("handoff item count exceeds limit")
        for child_value in value:
            _validate_handoff_bounds(child_value, depth=depth + 1)


def _reject_sensitive_material(value: object, *, key: str | None = None) -> None:
    if key is not None and _SENSITIVE_KEY_RE.search(key):
        raise ValueError("handoff contains sensitive material")
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            if not isinstance(child_key, str):
                raise ValueError("handoff evidence keys must be strings")
            _reject_sensitive_material(child_value, key=child_key)
        return
    if isinstance(value, (list, tuple)):
        for child_value in value:
            _reject_sensitive_material(child_value, key=key)
        return
    if isinstance(value, str) and _SENSITIVE_VALUE_RE.search(value):
        raise ValueError("handoff contains sensitive material")
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise TypeError("handoff evidence supports only bounded JSON values")
