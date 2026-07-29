"""Validated, bounded handoff packages for provider-neutral agent drivers."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import re
from typing import Callable, Protocol
from uuid import uuid4

from .agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    AgentHandoffPackage,
    DriverEpoch,
)


class AgentHandoffStore(Protocol):
    def load_agent_checkpoint(self, checkpoint_id: str) -> AgentCheckpoint: ...

    def save_agent_handoff(self, handoff: AgentHandoffPackage) -> None: ...


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
        _reject_sensitive_material(package.objective, key="objective")
        _reject_sensitive_material(package.evidence)
        if not incoming_capabilities.handoff_import:
            raise ValueError("incoming provider lacks handoff_import capability")
        if not incoming_capabilities.supports(package.required_capabilities):
            raise ValueError("incoming provider lacks required capabilities")
        return package


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
