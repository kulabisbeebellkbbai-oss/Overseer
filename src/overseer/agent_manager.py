"""Policy-gated manager for immutable provider driver epochs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable, Protocol
from uuid import uuid4

from .agent_contracts import (
    AgentCheckpoint,
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentErrorCategory,
    AgentOperationState,
    AgentSession,
    DriverEpoch,
)
from .agent_handoff import AgentHandoffService
from .agent_registry import AgentRegistry
from .policy import PolicyDecision
from .store import OverseerStore


class AuthorizationCallback(Protocol):
    def __call__(
        self,
        operation: str,
        context: Mapping[str, object],
    ) -> bool | PolicyDecision: ...


class AgentManagerError(RuntimeError):
    """Base lifecycle manager failure."""


class AgentAuthorizationError(AgentManagerError):
    """Raised when Overseer's policy callback rejects a lifecycle mutation."""


class AgentManagerPausedError(AgentManagerError):
    """Raised when dispatch is attempted against a paused driver epoch."""


class AgentHandoffError(AgentManagerError):
    """Raised after an incoming provider fails to acknowledge a handoff."""


_ACKNOWLEDGED_STATES = {
    AgentOperationState.ACKNOWLEDGED,
    AgentOperationState.RUNNING,
    AgentOperationState.SUCCEEDED,
}
_DISPATCHABLE_STATES = {
    AgentOperationState.ACKNOWLEDGED,
    AgentOperationState.RUNNING,
    AgentOperationState.SUCCEEDED,
}


class AgentManager:
    """Own lifecycle identity and let adapters supply only normalized outcomes."""

    def __init__(
        self,
        registry: AgentRegistry,
        store: OverseerStore,
        *,
        authorization_callback: AuthorizationCallback,
        handoffs: AgentHandoffService | None = None,
        clock: Callable[[], str] | None = None,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        if not callable(authorization_callback):
            raise TypeError("authorization_callback must be callable")
        self.registry = registry
        self.store = store
        self.authorization_callback = authorization_callback
        self._clock = clock or (
            lambda: datetime.now(timezone.utc).isoformat(timespec="microseconds")
        )
        self._id_factory = id_factory or (lambda prefix: f"{prefix}.{uuid4().hex}")
        self.handoffs = handoffs or AgentHandoffService(
            store,
            clock=self._clock,
            id_factory=lambda: self._id_factory("handoff"),
        )

    def activate(self, instance_id: str, initiated_by: str) -> DriverEpoch:
        self._require_authorized(
            "activate",
            {
                "instance_id": instance_id,
                "initiated_by": initiated_by,
            },
        )
        profile = self.registry.profile(instance_id)
        driver = self.registry.driver(instance_id)
        start_result = driver.start(profile)
        if start_result.state not in _ACKNOWLEDGED_STATES:
            category = (
                start_result.error_category or AgentErrorCategory.DISPATCH_REJECTED
            )
            raise AgentManagerError(f"activation failed: {category.value}")
        return self._open_epoch(
            instance_id=instance_id,
            provider_id=driver.provider.id,
            session_id=None,
            reason="activate",
            initiated_by=initiated_by,
            state=AgentOperationState.RUNNING,
        )

    def recover(self, session_id: str, initiated_by: str = "system") -> DriverEpoch:
        session = self.store.load_agent_session(session_id)
        if session.instance_id is None:
            raise AgentManagerError("persisted session has no instance identity")
        self._require_authorized(
            "recover",
            {
                "instance_id": session.instance_id,
                "session_id": session.id,
                "provider_id": session.provider_id,
                "initiated_by": initiated_by,
            },
        )
        driver = self.registry.driver_for_provider(
            session.provider_id,
            instance_id=session.instance_id,
        )
        result = driver.resume(session)
        state = (
            AgentOperationState.RUNNING
            if result.state in _ACKNOWLEDGED_STATES
            else AgentOperationState.BLOCKED
        )
        reason = (
            "recover"
            if state is AgentOperationState.RUNNING
            else f"recovery_failed:{(result.error_category or AgentErrorCategory.DISPATCH_REJECTED).value}"
        )
        return self._open_epoch(
            instance_id=session.instance_id,
            provider_id=session.provider_id,
            session_id=session.id,
            reason=reason,
            initiated_by=initiated_by,
            state=state,
        )

    def active_epoch(self, instance_id: str) -> DriverEpoch:
        epochs = tuple(
            epoch
            for epoch in self.store.list_driver_epochs()
            if epoch.instance_id == instance_id and epoch.closed_at is None
        )
        if not epochs:
            raise KeyError(f"no active driver epoch for {instance_id}")
        return max(epochs, key=lambda epoch: epoch.ordinal)

    def dispatch(
        self,
        instance_id: str,
        prompt: str,
        idempotency_key: str,
        requested_by: str | None = None,
    ) -> AgentDispatchResult:
        recorded = self._dispatch_for_idempotency_key(idempotency_key)
        if recorded is not None:
            if recorded.instance_id != instance_id:
                raise ValueError(
                    "idempotency key belongs to a different agent instance"
                )
            return self._result_from_dispatch(recorded)
        epoch = self.active_epoch(instance_id)
        if epoch.state not in _DISPATCHABLE_STATES:
            raise AgentManagerPausedError(
                f"agent instance {instance_id} is paused in epoch {epoch.id}"
            )
        self._require_authorized(
            "dispatch",
            {
                "instance_id": instance_id,
                "driver_epoch_id": epoch.id,
                "provider_id": epoch.provider_id,
                "idempotency_key": idempotency_key,
                "requested_by": requested_by or "unspecified",
            },
        )
        request = AgentDispatchRequest(
            id=self._id_factory("dispatch"),
            instance_id=instance_id,
            session_id=epoch.session_id,
            driver_epoch_id=epoch.id,
            idempotency_key=idempotency_key,
            prompt=prompt,
            requested_at=self._clock(),
            requested_by=requested_by,
        )
        self.store.save_agent_dispatch(request)
        driver = self.registry.driver_for_provider(
            epoch.provider_id,
            instance_id=instance_id,
        )
        try:
            result = driver.dispatch(request)
        except Exception:
            result = AgentDispatchResult(
                id=self._id_factory("result"),
                request_id=request.id,
                instance_id=request.instance_id,
                session_id=request.session_id,
                driver_epoch_id=request.driver_epoch_id,
                provider_id=epoch.provider_id,
                state=AgentOperationState.FAILED,
                error_category=AgentErrorCategory.PROVIDER_UNAVAILABLE,
            )
        return self.record_provider_result(epoch.id, result)

    def checkpoint(self, instance_id: str) -> AgentCheckpoint:
        epoch = self.active_epoch(instance_id)
        if epoch.state not in _DISPATCHABLE_STATES:
            raise AgentManagerPausedError(
                f"agent instance {instance_id} is paused in epoch {epoch.id}"
            )
        self._require_authorized(
            "checkpoint",
            {
                "instance_id": instance_id,
                "driver_epoch_id": epoch.id,
                "provider_id": epoch.provider_id,
            },
        )
        driver = self.registry.driver_for_provider(
            epoch.provider_id,
            instance_id=instance_id,
        )
        session = self._session_for_epoch(epoch)
        provider_checkpoint = driver.checkpoint(session)
        checkpoint = AgentCheckpoint(
            id=self._id_factory("checkpoint"),
            instance_id=instance_id,
            session_id=epoch.session_id,
            driver_epoch_id=epoch.id,
            evidence=provider_checkpoint.evidence,
            created_at=self._clock(),
            expires_at=provider_checkpoint.expires_at,
        )
        self.store.save_agent_checkpoint(checkpoint)
        return checkpoint

    def manual_handoff(
        self,
        instance_id: str,
        incoming_provider_id: str,
        initiated_by: str,
        approval_id: str,
    ) -> DriverEpoch:
        outgoing = self.active_epoch(instance_id)
        if outgoing.state not in _DISPATCHABLE_STATES:
            raise AgentManagerPausedError(
                f"agent instance {instance_id} is paused in epoch {outgoing.id}"
            )
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id is required")
        self._require_authorized(
            "manual_handoff",
            {
                "approval_id": approval_id,
                "instance_id": instance_id,
                "incoming_provider_id": incoming_provider_id,
                "outgoing_epoch_id": outgoing.id,
                "initiated_by": initiated_by,
            },
        )
        checkpoint = self.checkpoint(instance_id)
        package = self.handoffs.build_from_store(
            instance_id=instance_id,
            outgoing_epoch=outgoing,
            checkpoint=checkpoint,
            incoming_provider_id=incoming_provider_id,
            objective="continue approved work from recorded checkpoint",
            required_capabilities=self.registry.profile(instance_id).required_capabilities,
        )
        incoming_driver = self.registry.driver_for_provider(
            incoming_provider_id,
            instance_id=instance_id,
        )
        incoming_profile = self.registry.profile_for_provider(
            instance_id,
            incoming_provider_id,
        )
        self.handoffs.validate(package, incoming_driver.provider.capabilities)
        incoming = self._open_epoch(
            instance_id=instance_id,
            provider_id=incoming_provider_id,
            session_id=None,
            reason="manual_handoff",
            initiated_by=initiated_by,
            state=AgentOperationState.QUEUED,
        )
        try:
            result = incoming_driver.import_handoff(incoming_profile, package)
        except Exception:
            result = AgentDispatchResult(
                id=self._id_factory("result"),
                request_id=f"handoff.{package.id}",
                instance_id=instance_id,
                session_id=incoming.session_id,
                driver_epoch_id=incoming.id,
                provider_id=incoming_provider_id,
                state=AgentOperationState.FAILED,
                error_category=AgentErrorCategory.PROVIDER_UNAVAILABLE,
            )
        if result.state not in _ACKNOWLEDGED_STATES:
            category = result.error_category or AgentErrorCategory.HANDOFF_INCOMPATIBLE
            paused = replace(
                incoming,
                state=AgentOperationState.BLOCKED,
                reason=f"handoff_failed:{category.value}",
            )
            self.store.save_driver_epoch(paused)
            self.store.save_agent_handoff(
                replace(
                    package,
                    evidence={
                        "checkpoint_id": checkpoint.id,
                        "outgoing_epoch_id": outgoing.id,
                        "status": result.state.value,
                        "reason": category.value,
                    },
                )
            )
            raise AgentHandoffError(category.value)
        incoming = replace(incoming, state=AgentOperationState.RUNNING)
        self.store.save_driver_epoch(incoming)
        self._close_epoch(outgoing, replacement_epoch_id=incoming.id)
        return incoming

    def record_provider_result(
        self,
        epoch_id: str,
        result: AgentDispatchResult,
    ) -> AgentDispatchResult:
        try:
            epoch = self.store.load_driver_epoch(epoch_id)
            active = self.active_epoch(epoch.instance_id)
        except KeyError:
            return self.quarantine_result(
                result,
                reason="unknown_driver_epoch",
            )
        if (
            epoch.closed_at is not None
            or active.id != epoch.id
            or result.driver_epoch_id != epoch.id
            or result.instance_id != epoch.instance_id
            or result.session_id != epoch.session_id
            or result.provider_id != epoch.provider_id
        ):
            return self.quarantine_result(
                result,
                reason="closed_or_inactive_driver_epoch",
            )
        return self._record_dispatch_result(result)

    def quarantine_result(
        self,
        result: AgentDispatchResult,
        *,
        reason: str = "invalid_provider_result",
    ) -> AgentDispatchResult:
        quarantined = replace(
            result,
            state=AgentOperationState.QUARANTINED,
            error_category=AgentErrorCategory.QUARANTINED,
            error_message=None,
            evidence={"reason": reason},
        )
        return self._record_dispatch_result(quarantined)

    def _open_epoch(
        self,
        *,
        instance_id: str,
        provider_id: str,
        session_id: str | None,
        reason: str,
        initiated_by: str,
        state: AgentOperationState,
    ) -> DriverEpoch:
        profile = self.registry.profile_for_provider(instance_id, provider_id)
        ordinal = 1 + max(
            (
                epoch.ordinal
                for epoch in self.store.list_driver_epochs()
                if epoch.instance_id == instance_id
            ),
            default=0,
        )
        selected_session_id = session_id or (
            f"session.{_identifier_fragment(instance_id)}."
            f"{_identifier_fragment(provider_id)}.{ordinal}"
        )
        try:
            self.store.load_agent_session(selected_session_id)
        except KeyError:
            self.store.save_agent_session(
                AgentSession(
                    id=selected_session_id,
                    provider_id=provider_id,
                    external_session_id=selected_session_id,
                    workspace=profile.workspace,
                    transport=profile.transport,
                    capabilities=self.registry.providers[provider_id].capabilities,
                    instance_id=instance_id,
                    model_profile_id=profile.model_profile_id,
                    legacy_references={
                        "status": state.value,
                        "reason": reason,
                        "initiated_by_ref": initiated_by,
                    },
                    discovered_at=self._clock(),
                    last_observed_at=self._clock(),
                )
            )
        epoch = DriverEpoch(
            id=self._id_factory("epoch"),
            instance_id=instance_id,
            session_id=selected_session_id,
            provider_id=provider_id,
            ordinal=ordinal,
            state=state,
            opened_at=self._clock(),
            reason=reason,
        )
        self.store.save_driver_epoch(epoch)
        return epoch

    def _close_epoch(
        self,
        epoch: DriverEpoch,
        *,
        replacement_epoch_id: str,
    ) -> DriverEpoch:
        closed = replace(
            epoch,
            state=AgentOperationState.SUCCEEDED,
            closed_at=self._clock(),
            replacement_epoch_id=replacement_epoch_id,
        )
        self.store.save_driver_epoch(closed)
        return closed

    def _session_for_epoch(self, epoch: DriverEpoch) -> AgentSession:
        try:
            return self.store.load_agent_session(epoch.session_id)
        except KeyError as error:
            raise AgentManagerError(
                f"driver epoch {epoch.id} references an unknown session"
            ) from error

    def _require_authorized(
        self,
        operation: str,
        context: Mapping[str, object],
    ) -> None:
        decision = self.authorization_callback(operation, context)
        allowed = decision.can_proceed() if isinstance(decision, PolicyDecision) else decision
        if allowed is not True:
            raise AgentAuthorizationError(
                f"{operation} rejected by Overseer policy callback"
            )

    def _dispatch_for_idempotency_key(
        self,
        idempotency_key: str,
    ) -> AgentDispatchRequest | None:
        return next(
            (
                dispatch
                for dispatch in self.store.list_agent_dispatches()
                if dispatch.idempotency_key == idempotency_key
            ),
            None,
        )

    def _record_dispatch_result(
        self,
        result: AgentDispatchResult,
    ) -> AgentDispatchResult:
        try:
            request = self.store.load_agent_dispatch(result.request_id)
        except KeyError:
            return replace(result, evidence={"reason": result.evidence.get("reason", "unrecorded")})
        evidence: dict[str, object] = {
            "result_id": result.id,
            "provider_id": result.provider_id,
            "status": result.state.value,
        }
        if result.provider_reference is not None:
            evidence["provider_ref"] = result.provider_reference
        if result.error_category is not None:
            evidence["reason"] = result.error_category.value
        if result.acknowledged_at is not None:
            evidence["acknowledged_at"] = result.acknowledged_at
        if result.completed_at is not None:
            evidence["completed_at"] = result.completed_at
        for key, value in result.evidence.items():
            if key in evidence or key in {"status", "reason"}:
                continue
            if key.endswith(("_id", "_ref", "_at")):
                evidence[key] = value
        self.store.save_agent_dispatch(replace(request, evidence=evidence))
        return replace(result, evidence=evidence)

    def _result_from_dispatch(
        self,
        dispatch: AgentDispatchRequest,
    ) -> AgentDispatchResult:
        evidence = dispatch.evidence
        epoch = self.store.load_driver_epoch(dispatch.driver_epoch_id)
        state = AgentOperationState(
            str(evidence.get("status", AgentOperationState.QUEUED.value))
        )
        reason = evidence.get("reason")
        error_category = None
        if isinstance(reason, str):
            try:
                error_category = AgentErrorCategory(reason)
            except ValueError:
                error_category = None
        return AgentDispatchResult(
            id=str(evidence.get("result_id", f"{dispatch.id}.queued")),
            request_id=dispatch.id,
            instance_id=dispatch.instance_id,
            session_id=dispatch.session_id,
            driver_epoch_id=dispatch.driver_epoch_id,
            provider_id=str(evidence.get("provider_id", epoch.provider_id)),
            state=state,
            error_category=error_category,
            provider_reference=(
                str(evidence["provider_ref"]) if "provider_ref" in evidence else None
            ),
            acknowledged_at=(
                str(evidence["acknowledged_at"])
                if "acknowledged_at" in evidence
                else None
            ),
            completed_at=(
                str(evidence["completed_at"]) if "completed_at" in evidence else None
            ),
            evidence=evidence,
        )


def _identifier_fragment(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value)
