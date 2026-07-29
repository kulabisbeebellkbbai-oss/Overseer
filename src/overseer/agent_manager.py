"""Policy-gated manager for immutable provider driver epochs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timezone
import sqlite3
import time
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
_TERMINAL_RESULT_STATES = {
    AgentOperationState.SUCCEEDED,
    AgentOperationState.CANCELLED,
    AgentOperationState.QUARANTINED,
}
MAX_CHECKPOINT_AGE_SECONDS = 300


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
        open_epochs = self._authoritative_epochs(instance_id)
        if len(open_epochs) == 1:
            return open_epochs[0]
        if len(open_epochs) > 1:
            raise AgentManagerError(
                f"multiple open driver epochs require recovery for {instance_id}"
            )
        profile = self.registry.profile(instance_id)
        driver = self.registry.driver(instance_id)
        reservation_id = self._id_factory("activation")
        if not self.store.reserve_agent_activation(instance_id, reservation_id):
            return self._await_activation_winner(instance_id)
        try:
            start_result = driver.start(profile)
        except Exception:
            self.store.finish_agent_activation(
                instance_id,
                reservation_id,
                "blocked",
                reason=AgentErrorCategory.PROVIDER_UNAVAILABLE.value,
            )
            raise
        if (
            start_result.state not in _ACKNOWLEDGED_STATES
            or start_result.instance_id != instance_id
            or start_result.provider_id != driver.provider.id
        ):
            category = (
                start_result.error_category or AgentErrorCategory.DISPATCH_REJECTED
            )
            self.store.finish_agent_activation(
                instance_id,
                reservation_id,
                "blocked",
                reason=category.value,
            )
            raise AgentManagerError(f"activation failed: {category.value}")
        with self.store.agent_transaction():
            epoch = self._open_epoch(
                instance_id=instance_id,
                provider_id=driver.provider.id,
                session_id=None,
                external_session_id=(
                    start_result.external_session_id or start_result.session_id
                ),
                reason="activate",
                initiated_by=initiated_by,
                state=AgentOperationState.RUNNING,
            )
            self.store.finish_agent_activation(
                instance_id,
                reservation_id,
                "active",
                epoch_id=epoch.id,
            )
        return epoch

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
        open_epochs = self._open_epochs(session.instance_id)
        if open_epochs:
            active = max(open_epochs, key=lambda epoch: epoch.ordinal)
            if len(open_epochs) > 1:
                for stale in open_epochs:
                    if stale.id != active.id:
                        self.store.save_driver_epoch(
                            replace(
                                stale,
                                state=AgentOperationState.QUARANTINED,
                                closed_at=self._clock(),
                                replacement_epoch_id=active.id,
                            )
                        )
            if active.state in _DISPATCHABLE_STATES:
                return active
            if active.session_id != session.id:
                return active
        result = driver.resume(session)
        if (
            result.instance_id != session.instance_id
            or result.provider_id != session.provider_id
            or result.session_id != session.external_session_id
        ):
            raise AgentManagerError("recovery result binding mismatch")
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
        if open_epochs:
            reconciled = replace(active, state=state, reason=reason)
            self.store.save_driver_epoch(reconciled)
            return reconciled
        return self._open_epoch(
            instance_id=session.instance_id,
            provider_id=session.provider_id,
            session_id=session.id,
            external_session_id=session.external_session_id,
            reason=reason,
            initiated_by=initiated_by,
            state=state,
        )

    def active_epoch(self, instance_id: str) -> DriverEpoch:
        epochs = self._authoritative_epochs(instance_id)
        if not epochs:
            raise KeyError(f"no active driver epoch for {instance_id}")
        if len(epochs) > 1:
            raise AgentManagerError(f"multiple open driver epochs for {instance_id}")
        return max(epochs, key=lambda epoch: epoch.ordinal)

    def dispatch(
        self,
        instance_id: str,
        prompt: str,
        idempotency_key: str,
        requested_by: str | None = None,
    ) -> AgentDispatchResult:
        recorded = self._dispatch_for_idempotency_key(instance_id, idempotency_key)
        if recorded is not None:
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
        try:
            self.store.save_agent_dispatch(request)
        except (sqlite3.IntegrityError, ValueError):
            winner = self._dispatch_for_idempotency_key(
                instance_id, idempotency_key
            )
            if winner is None:
                raise
            return self._result_from_dispatch(winner)
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
        checkpoint = self._collect_checkpoint(instance_id)
        self.store.save_agent_checkpoint(checkpoint)
        return checkpoint

    def _collect_checkpoint(
        self,
        instance_id: str,
        epoch: DriverEpoch | None = None,
    ) -> AgentCheckpoint:
        epoch = epoch or self.active_epoch(instance_id)
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
            created_at=provider_checkpoint.created_at,
            expires_at=provider_checkpoint.expires_at,
        )
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
        checkpoint = self._collect_checkpoint(instance_id, outgoing)
        self._validate_checkpoint_for_handoff(checkpoint)
        incoming_driver = self.registry.driver_for_provider(
            incoming_provider_id,
            instance_id=instance_id,
        )
        incoming_profile = self.registry.profile_for_provider(
            instance_id,
            incoming_provider_id,
        )
        with self.store.agent_transaction():
            self.store.save_agent_checkpoint(checkpoint)
            package = self.handoffs.build_from_store(
                instance_id=instance_id,
                outgoing_epoch=outgoing,
                checkpoint=checkpoint,
                incoming_provider_id=incoming_provider_id,
                objective="continue approved work from recorded checkpoint",
                required_capabilities=self.registry.profile(
                    instance_id
                ).required_capabilities,
            )
            self.handoffs.validate(package, incoming_driver.provider.capabilities)
            incoming = self._open_epoch(
                instance_id=instance_id,
                provider_id=incoming_provider_id,
                session_id=None,
                external_session_id=None,
                reason="manual_handoff",
                initiated_by=initiated_by,
                state=AgentOperationState.QUEUED,
                persist_epoch=False,
            )
            package = replace(
                package,
                evidence={
                    **package.evidence,
                    "incoming_epoch_id": incoming.id,
                    "incoming_session_id": incoming.session_id,
                    "status": "importing",
                },
            )
            self.store.save_agent_handoff(package)
            self.store.save_driver_epoch(incoming)
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
        incoming, failure = self._complete_handoff(
            package, outgoing, incoming, result, invalid_state="blocked"
        )
        if failure is not None:
            raise AgentHandoffError(failure.value)
        return incoming

    def reconcile_handoff(
        self,
        handoff_id: str,
        result: AgentDispatchResult,
        *,
        initiated_by: str,
    ) -> DriverEpoch:
        self._require_authorized(
            "reconcile_handoff",
            {
                "handoff_id": handoff_id,
                "initiated_by": initiated_by,
                "result_id": result.id,
            },
        )
        package = self.store.load_agent_handoff(handoff_id)
        if package.evidence.get("status") != "importing":
            raise AgentHandoffError("handoff is not awaiting reconciliation")
        incoming = self.store.load_driver_epoch(
            str(package.evidence["incoming_epoch_id"])
        )
        outgoing = self.store.load_driver_epoch(package.outgoing_epoch_id)
        incoming, failure = self._complete_handoff(
            package, outgoing, incoming, result, invalid_state="quarantined"
        )
        if failure is not None:
            raise AgentHandoffError(failure.value)
        return incoming

    def _complete_handoff(
        self,
        package: AgentHandoffPackage,
        outgoing: DriverEpoch,
        incoming: DriverEpoch,
        result: AgentDispatchResult,
        *,
        invalid_state: str,
    ) -> tuple[DriverEpoch, AgentErrorCategory | None]:
        expected_request_id = f"handoff.{package.id}"
        binding_valid = (
            result.request_id == expected_request_id
            and result.instance_id == package.instance_id
            and result.provider_id == package.incoming_provider_id
            and result.session_id == incoming.session_id
            and result.driver_epoch_id == incoming.id
            and isinstance(result.external_session_id, str)
            and bool(result.external_session_id.strip())
        )
        failure = (
            None
            if result.state in _ACKNOWLEDGED_STATES and binding_valid
            else result.error_category
            if result.state not in _ACKNOWLEDGED_STATES
            and result.error_category is not None
            else AgentErrorCategory.HANDOFF_INCOMPATIBLE
        )
        with self.store.agent_transaction():
            self.store.save_agent_dispatch_result(
                replace(
                    result,
                    error_message=None,
                    evidence=self._safe_result_evidence(result.evidence),
                )
            )
            if failure is not None:
                transition_state = (
                    AgentOperationState.QUARANTINED
                    if invalid_state == "quarantined"
                    else AgentOperationState.BLOCKED
                )
                incoming = replace(
                    incoming,
                    state=transition_state,
                    closed_at=self._clock()
                    if transition_state is AgentOperationState.QUARANTINED
                    else None,
                    reason=f"handoff_failed:{failure.value}",
                )
                self.store.save_driver_epoch(incoming)
                self.store.save_agent_handoff(
                    replace(
                        package,
                        evidence={
                            **package.evidence,
                            "status": invalid_state,
                            "reason": failure.value,
                        },
                    )
                )
            else:
                session = self.store.load_agent_session(incoming.session_id)
                self.store.save_agent_session(
                    replace(
                        session,
                        external_session_id=result.external_session_id,
                        last_observed_at=self._clock(),
                    )
                )
                incoming = replace(incoming, state=AgentOperationState.RUNNING)
                self.store.save_agent_handoff(
                    replace(
                        package,
                        evidence={**package.evidence, "status": "acknowledged"},
                    )
                )
                self._close_epoch(outgoing, replacement_epoch_id=incoming.id)
                self.store.save_driver_epoch(incoming)
        return incoming, failure

    def record_provider_result(
        self,
        epoch_id: str,
        result: AgentDispatchResult,
    ) -> AgentDispatchResult:
        self._require_authorized(
            "record_provider_result",
            {
                "driver_epoch_id": epoch_id,
                "result_id": result.id,
                "request_id": result.request_id,
            },
        )
        try:
            request = self.store.load_agent_dispatch(result.request_id)
        except KeyError:
            return self._quarantine_result(result, "unknown_dispatch_request")
        try:
            epoch = self.store.load_driver_epoch(epoch_id)
            active = self.active_epoch(epoch.instance_id)
        except KeyError:
            return self._quarantine_result(result, "unknown_driver_epoch")
        request_binding_valid = (
            request.instance_id == result.instance_id == epoch.instance_id
            and request.session_id == result.session_id == epoch.session_id
            and request.driver_epoch_id == result.driver_epoch_id == epoch.id
            and result.provider_id == epoch.provider_id
        )
        if not request_binding_valid:
            return self._quarantine_result(
                result, "dispatch_request_binding_mismatch"
            )
        if (
            epoch.closed_at is not None
            or active.id != epoch.id
        ):
            return self._quarantine_result(
                result, "closed_or_inactive_driver_epoch"
            )
        return self._record_dispatch_result(result)

    def quarantine_result(
        self,
        result: AgentDispatchResult,
        *,
        reason: str = "invalid_provider_result",
    ) -> AgentDispatchResult:
        self._require_authorized(
            "quarantine_result",
            {
                "result_id": result.id,
                "request_id": result.request_id,
                "reason": reason,
            },
        )
        return self._quarantine_result(result, reason)

    def _quarantine_result(
        self,
        result: AgentDispatchResult,
        reason: str,
    ) -> AgentDispatchResult:
        evidence = self._safe_result_evidence(result.evidence)
        evidence["source_result_id"] = result.id
        evidence["reason"] = reason
        quarantined = replace(
            result,
            id=self._id_factory("quarantine"),
            state=AgentOperationState.QUARANTINED,
            error_category=AgentErrorCategory.QUARANTINED,
            error_message=None,
            evidence=evidence,
        )
        self.store.save_agent_dispatch_result(quarantined)
        return quarantined

    def _open_epoch(
        self,
        *,
        instance_id: str,
        provider_id: str,
        session_id: str | None,
        external_session_id: str | None,
        reason: str,
        initiated_by: str,
        state: AgentOperationState,
        persist_epoch: bool = True,
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
                    external_session_id=external_session_id,
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
        if persist_epoch:
            if self._open_epochs(instance_id):
                raise AgentManagerError(
                    f"instance {instance_id} already has an open driver epoch"
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

    def _open_epochs(self, instance_id: str) -> tuple[DriverEpoch, ...]:
        return tuple(
            epoch
            for epoch in self.store.list_driver_epochs()
            if epoch.instance_id == instance_id and epoch.closed_at is None
        )

    def _authoritative_epochs(self, instance_id: str) -> tuple[DriverEpoch, ...]:
        transition_epoch_ids = {
            str(epoch_id)
            for package in self.store.list_agent_handoffs()
            if package.instance_id == instance_id
            for epoch_id in (package.evidence.get("incoming_epoch_id"),)
            if epoch_id is not None
        }
        return tuple(
            epoch
            for epoch in self._open_epochs(instance_id)
            if not (
                epoch.id in transition_epoch_ids
                and epoch.state
                in {
                    AgentOperationState.QUEUED,
                    AgentOperationState.BLOCKED,
                    AgentOperationState.QUARANTINED,
                }
            )
        )

    def _await_activation_winner(self, instance_id: str) -> DriverEpoch:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _, state, epoch_id, reason = self.store.load_agent_activation(instance_id)
            if state == "active" and epoch_id is not None:
                return self.store.load_driver_epoch(epoch_id)
            if state == "blocked":
                raise AgentManagerError(
                    f"activation failed: {reason or 'blocked'}"
                )
            time.sleep(0.01)
        raise AgentManagerError("activation reservation did not complete")

    def _validate_checkpoint_for_handoff(
        self,
        checkpoint: AgentCheckpoint,
    ) -> None:
        try:
            now = _aware_datetime(self._clock())
            created_at = _aware_datetime(checkpoint.created_at)
            expires_at = (
                _aware_datetime(checkpoint.expires_at)
                if checkpoint.expires_at is not None
                else None
            )
        except ValueError as error:
            raise AgentHandoffError("checkpoint timestamp is malformed") from error
        age = (now - created_at).total_seconds()
        if age < 0 or age > MAX_CHECKPOINT_AGE_SECONDS:
            raise AgentHandoffError("checkpoint is stale")
        if expires_at is not None and expires_at <= now:
            raise AgentHandoffError("checkpoint is expired")
        if checkpoint.evidence.get("status") not in {
            "ready",
            "completed",
            "checkpointed",
        }:
            raise AgentHandoffError("checkpoint state is not transferable")

    @staticmethod
    def _safe_result_evidence(
        source: Mapping[str, object],
    ) -> dict[str, object]:
        evidence: dict[str, object] = {}
        for key, value in source.items():
            if key.endswith(("_id", "_ref", "_at")) or key in {"status", "reason"}:
                evidence[key] = value
            elif isinstance(value, (int, float, bool)):
                evidence[key] = value
        return evidence

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
        instance_id: str,
        idempotency_key: str,
    ) -> AgentDispatchRequest | None:
        try:
            return self.store.load_agent_dispatch_by_idempotency(
                instance_id, idempotency_key
            )
        except KeyError:
            return None

    def _record_dispatch_result(
        self,
        result: AgentDispatchResult,
    ) -> AgentDispatchResult:
        request = self.store.load_agent_dispatch(result.request_id)
        evidence: dict[str, object] = {
            "result_id": result.id,
            "provider_id": result.provider_id,
            "status": result.state.value,
        }
        if result.provider_reference is not None:
            evidence["provider_ref"] = result.provider_reference
        if result.external_session_id is not None:
            evidence["external_session_id"] = result.external_session_id
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
        recorded = replace(result, error_message=None, evidence=evidence)
        self.store.save_agent_dispatch_result(recorded)
        prior_state = request.evidence.get("status")
        if prior_state not in {state.value for state in _TERMINAL_RESULT_STATES}:
            self.store.save_agent_dispatch(replace(request, evidence=evidence))
        return recorded

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
            external_session_id=(
                str(evidence["external_session_id"])
                if "external_session_id" in evidence
                else None
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


def _aware_datetime(value: str | None) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)
