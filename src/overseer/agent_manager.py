"""Policy-gated manager for immutable provider driver epochs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3
import shutil
import time
from pathlib import Path
from typing import Callable, Protocol
from uuid import uuid4

from .agent_contracts import (
    AgentCheckpoint,
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentErrorCategory,
    AgentHandoffPackage,
    AgentInstanceTransition,
    AgentOperationFenceState,
    AgentOperationReservation,
    AgentOperationState,
    AgentSession,
    AgentTransitionState,
    DriverEpoch,
    FailoverDecision,
    ProviderHealthState,
)
from .agent_handoff import AgentHandoffService, evaluate_failover_evidence
from .agent_operations import AgentOperationBlockedError, AgentOperationCoordinator
from .agent_registry import AgentRegistry
from .audit import AuditEvent, AuditEventType
from .core import OwnerDomain, Resource, RiskLevel
from .policy import PolicyDecision
from .store import OverseerStore


class AuthorizationCallback(Protocol):
    def __call__(
        self,
        operation: str,
        context: Mapping[str, object],
    ) -> bool | PolicyDecision: ...


class SessionResourceFactory(Protocol):
    def __call__(self, session: AgentSession) -> Resource | None: ...


class AgentManagerError(RuntimeError):
    """Base lifecycle manager failure."""


class AgentAuthorizationError(AgentManagerError):
    """Raised when Overseer's policy callback rejects a lifecycle mutation."""


class AgentManagerPausedError(AgentManagerError):
    """Raised when dispatch is attempted against a paused driver epoch."""


class AgentHandoffError(AgentManagerError):
    """Raised after an incoming provider fails to acknowledge a handoff."""


class AgentTransitionRequiredError(AgentManagerPausedError):
    """Raised when explicit transition reconciliation or rollback is required."""

    def __init__(self, transition: AgentInstanceTransition) -> None:
        self.transition = transition
        super().__init__(
            f"agent instance {transition.instance_id} transition "
            f"{transition.state.value} requires reconcile or rollback"
        )


class AgentOperationRequiredError(AgentManagerPausedError):
    """Raised when a coordinator fence requires explicit recovery."""

    def __init__(self, operation: AgentOperationReservation) -> None:
        self.operation = operation
        super().__init__(
            f"agent instance {operation.instance_id} operation generation "
            f"{operation.generation} is fenced and requires reconciliation"
        )


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
_BLOCKING_TRANSITION_STATES = {
    AgentTransitionState.IMPORTING,
    AgentTransitionState.IMPORT_ACKNOWLEDGED,
    AgentTransitionState.RECONCILING,
    AgentTransitionState.FAILED,
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
        operations: AgentOperationCoordinator | None = None,
        session_resource_factory: SessionResourceFactory | None = None,
        activation_lease_seconds: float = 30.0,
        activation_wait_seconds: float = 5.0,
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
        if activation_lease_seconds <= 0 or activation_wait_seconds < 0:
            raise ValueError("activation lease must be positive and wait non-negative")
        self._activation_lease_seconds = activation_lease_seconds
        self._activation_wait_seconds = activation_wait_seconds
        self._activation_owner_id = self._id_factory("manager")
        self.handoffs = handoffs or AgentHandoffService(
            store,
            clock=self._clock,
            id_factory=lambda: self._id_factory("handoff"),
        )
        self.operations = operations or AgentOperationCoordinator(
            store,
            clock=self._clock,
        )
        self.session_resource_factory = session_resource_factory

    def discover(
        self,
        instance_id: str,
        provider_id: str,
        workspace: str | None = None,
    ) -> tuple[AgentSession, ...]:
        self._require_authorized(
            "discover",
            {
                "instance_id": instance_id,
                "provider_id": provider_id,
            },
        )
        try:
            reservation = self.operations.reserve(
                instance_id,
                owner_token=self._id_factory("operation.discovery"),
            )
        except AgentOperationBlockedError as error:
            raise AgentManagerPausedError(str(error)) from error
        try:
            profile = self.registry.profile_for_provider(instance_id, provider_id)
            driver = self.registry.driver_for_provider(
                provider_id,
                instance_id=instance_id,
            )
            discovered = driver.discover(workspace)
            sessions: list[AgentSession] = []
            resources: list[Resource] = []
            for session in discovered:
                if session.provider_id != provider_id:
                    raise AgentManagerError(
                        "discovered session provider binding mismatch"
                    )
                if session.instance_id not in {None, instance_id}:
                    raise AgentManagerError(
                        "discovered session instance binding mismatch"
                    )
                normalized = replace(
                    session,
                    instance_id=instance_id,
                    transport=profile.transport,
                    capabilities=driver.provider.capabilities,
                    model_profile_id=profile.model_profile_id,
                )
                sessions.append(normalized)
                if self.session_resource_factory is not None:
                    resource = self.session_resource_factory(normalized)
                    if resource is not None:
                        resources.append(resource)
            evidence_ids = tuple(
                [
                    *(session.id for session in sessions),
                    *(resource.id for resource in resources),
                ]
            )
            try:
                with self.store.agent_transaction():
                    self.operations.verify_owned(reservation)
                    for provider in self.registry.providers.values():
                        self.store.save_agent_provider(provider)
                    for configured_profile in self.registry.profiles.values():
                        self.store.save_agent_instance_profile(configured_profile)
                    for session in sessions:
                        self.store.save_agent_session(session)
                    for resource in resources:
                        self.store.save_resource(resource)
                    self.store.save_audit_event(
                        AuditEvent(
                            id=self._id_factory("audit.agent.discovery"),
                            event_type=AuditEventType.VERIFIED,
                            owner_domain=OwnerDomain.SISKO,
                            subject_id=(
                                f"agent.discovery:{instance_id}:{provider_id}"
                            ),
                            summary=(
                                "discovered provider sessions through the "
                                "authorized agent manager"
                            ),
                            risk_level=RiskLevel.LOW,
                            evidence_ids=evidence_ids,
                            occurred_at=self._clock(),
                        )
                    )
            except AgentOperationBlockedError as error:
                raise AgentManagerPausedError(str(error)) from error
            return tuple(sessions)
        finally:
            self.operations.release_if_owned(reservation)

    def activate(
        self,
        instance_id: str,
        initiated_by: str,
        *,
        retry_blocked: bool = False,
    ) -> DriverEpoch:
        self._require_authorized(
            "activate",
            {
                "instance_id": instance_id,
                "initiated_by": initiated_by,
            },
        )
        self._raise_transition_required(instance_id)
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
        started_at = self._clock()
        lease_expires_at = (
            _aware_datetime(started_at)
            + timedelta(seconds=self._activation_lease_seconds)
        ).isoformat()
        if not self.store.reserve_agent_activation(
            instance_id,
            reservation_id,
            owner_id=self._activation_owner_id,
            started_at=started_at,
            lease_expires_at=lease_expires_at,
            allow_blocked_retry=retry_blocked,
            observed_at=started_at,
        ):
            return self._await_activation_winner(instance_id)
        activation = self.store.load_agent_activation(instance_id)
        try:
            start_result = driver.start(profile)
        except Exception:
            self.store.finish_agent_activation(
                instance_id,
                reservation_id,
                self._activation_owner_id,
                activation.generation,
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
                self._activation_owner_id,
                activation.generation,
                "blocked",
                reason=category.value,
            )
            raise AgentManagerError(f"activation failed: {category.value}")
        with self.store.agent_transaction():
            self.store.ensure_agent_operation(
                instance_id,
                updated_at=self._clock(),
            )
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
                self._activation_owner_id,
                activation.generation,
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
        self._raise_transition_required(session.instance_id)
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
        self._raise_transition_required(
            instance_id,
            error_type=AgentManagerPausedError,
        )
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
            request = self.operations.accept_dispatch(request)
        except AgentOperationBlockedError as error:
            raise AgentManagerPausedError(str(error)) from error
        except (sqlite3.IntegrityError, ValueError):
            winner = self._dispatch_for_idempotency_key(
                instance_id, idempotency_key
            )
            if winner is None:
                self._raise_transition_required(
                    instance_id,
                    error_type=AgentManagerPausedError,
                )
                raise
            return self._result_from_dispatch(winner)
        driver = self.registry.driver_for_provider(
            epoch.provider_id,
            instance_id=instance_id,
        )
        if not self.operations.claim_dispatch_execution(request):
            result = self.operations.cancelled_result(
                request,
                provider_id=epoch.provider_id,
                result_id=self._id_factory("result"),
            )
            self.operations.complete_dispatch(request, result)
            return self._record_dispatch_result(result)
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
        recorded = self.record_provider_result(epoch.id, result)
        self.operations.complete_dispatch(request, recorded)
        return recorded

    def checkpoint(self, instance_id: str) -> AgentCheckpoint:
        self._raise_transition_required(
            instance_id,
            error_type=AgentManagerPausedError,
        )
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

    def evaluate_failover(
        self, instance_id: str, policy_id: str | None = None
    ) -> FailoverDecision:
        """Return blockers without mutation, or persist one fenced allowed decision."""
        decision = self._evaluate_failover(instance_id, policy_id=policy_id)
        if decision.allowed:
            self.store.save_failover_decision(decision)
        return decision

    def _evaluate_failover(
        self,
        instance_id: str,
        *,
        policy_id: str | None,
        decision_id: str | None = None,
    ) -> FailoverDecision:
        profile = self.registry.profile(instance_id)
        selected_policy_id = policy_id or profile.controlled_failover_policy_ref
        try:
            policy = (
                self.store.load_failover_policy(selected_policy_id)
                if selected_policy_id
                else None
            )
        except KeyError:
            policy = None
        epoch = self.active_epoch(instance_id)
        try:
            operation = self.store.load_agent_operation(instance_id)
        except KeyError:
            # Reading an unevaluated instance must not create a reservation.
            operation_generation = 1
            operation_changed = False
        else:
            operation_generation = operation.generation
            operation_changed = (
                operation.state is not AgentOperationFenceState.OPEN
                or operation.owner_token is not None
            )
        allowed_health_providers = {
            epoch.provider_id,
            *(policy.approved_fallback_provider_ids if policy else ()),
        }
        health = tuple(
            item
            for item in self.store.list_provider_health_observations(instance_id)
            if item.provider_id in allowed_health_providers
        )
        risks = self.store.list_active_agent_risks(instance_id)
        checkpoints = tuple(
            item
            for item in self.store.list_agent_checkpoints()
            if item.instance_id == instance_id and item.driver_epoch_id == epoch.id
        )
        checkpoint = max(
            checkpoints,
            key=lambda item: _aware_datetime(item.created_at),
            default=None,
        )
        latest_health: dict[str, object] = {}
        for item in sorted(
            health, key=lambda record: _aware_datetime(record.observed_at)
        ):
            latest_health[item.provider_id] = item
        healthy_candidates = frozenset(
            provider_id
            for provider_id, item in latest_health.items()
            if item.state is ProviderHealthState.HEALTHY
        )
        candidate_capabilities = {
            provider_id: self.registry.providers[provider_id].capabilities
            for provider_id in (
                policy.approved_fallback_provider_ids if policy else ()
            )
            if provider_id in self.registry.providers
            and provider_id in profile.approved_fallback_provider_ids
        }
        candidate_readiness = {
            provider_id: readiness_ref
            for provider_id in candidate_capabilities
            if (
                readiness_ref := self._provider_readiness_reference(
                    instance_id, provider_id
                )
            )
            is not None
        }
        return evaluate_failover_evidence(
            decision_id=decision_id or self._id_factory("failover-decision"),
            instance_id=instance_id,
            outgoing_epoch=epoch,
            operation_generation=operation_generation,
            policy=policy,
            health=health,
            checkpoint=checkpoint,
            risks=risks,
            candidate_capabilities=candidate_capabilities,
            healthy_candidates=healthy_candidates,
            candidate_readiness=candidate_readiness,
            required_capabilities=profile.required_capabilities,
            evaluated_at=self._clock(),
            transition_changed=operation_changed or self._has_active_transition(instance_id),
        )

    def _provider_readiness_reference(
        self, instance_id: str, provider_id: str
    ) -> str | None:
        provider = self.registry.providers[provider_id]
        if not self.registry.adapter_factory_available(provider.adapter_id):
            return None
        if provider.id in {"qwen-code", "mistral-vibe", "antigravity"}:
            return None
        if not provider.executable_allowlist:
            return None  # gateway readiness needs separately verified configuration
        configured = provider.executable_allowlist[0]
        resolved = (
            str(Path(configured).resolve())
            if Path(configured).is_absolute() and Path(configured).is_file()
            else shutil.which(configured)
        )
        if resolved is None:
            return None
        digest = hashlib.sha256(str(Path(resolved).resolve()).encode()).hexdigest()[:16]
        return f"readiness.{provider_id}.{digest}"

    def execute_failover(
        self,
        instance_id: str,
        decision_id: str,
        initiated_by: str,
        approval_id: str,
    ) -> DriverEpoch:
        if not approval_id.strip():
            raise ValueError("approval_id is required")
        original = self.store.load_failover_decision(decision_id)
        if original.instance_id != instance_id:
            raise AgentHandoffError("failover decision belongs to another instance")
        if not original.allowed or original.consumed_at is not None:
            raise AgentHandoffError("failover decision is blocked or already used")
        if _aware_datetime(original.expires_at) <= _aware_datetime(self._clock()):
            raise AgentHandoffError("failover decision is expired")
        self._require_authorized(
            "controlled_failover",
            {
                "approval_id": approval_id,
                "decision_id": decision_id,
                "instance_id": instance_id,
                "incoming_provider_id": original.incoming_provider_id,
                "initiated_by": initiated_by,
            },
        )
        with self.store.agent_transaction():
            current = self.store.load_failover_decision(decision_id)
            if current != original:
                raise AgentHandoffError("failover decision record changed")
            reevaluated = self._evaluate_failover(
                instance_id,
                policy_id=current.policy_id,
                decision_id=current.id,
            )
            comparable = (
                "instance_id",
                "outgoing_epoch_id",
                "outgoing_provider_id",
                "operation_generation",
                "policy_id",
                "incoming_provider_id",
                "allowed",
                "blockers",
                "health_evidence_ids",
                "risk_evidence_ids",
                "evidence_timestamps",
                "checkpoint_id",
                "id",
            )
            if any(
                getattr(current, field) != getattr(reevaluated, field)
                for field in comparable
            ):
                raise AgentHandoffError("failover evidence or generation changed")
            try:
                reserved_operation = self.operations.reserve(
                    instance_id,
                    owner_token=self._id_factory("operation.failover"),
                )
            except AgentOperationBlockedError as error:
                raise AgentHandoffError(str(error)) from error
            if _aware_datetime(current.expires_at) <= _aware_datetime(self._clock()):
                raise AgentHandoffError("failover decision is expired")
            self.store.consume_failover_decision(
                decision_id,
                expected_generation=current.operation_generation,
                consumed_at=self._clock(),
            )
        assert original.incoming_provider_id is not None
        assert original.checkpoint_id is not None
        return self._perform_handoff(
            instance_id,
            original.incoming_provider_id,
            initiated_by,
            approval_id,
            authorization_operation="controlled_failover",
            reason="controlled_failover",
            authorization_already_proven=True,
            reserved_operation=reserved_operation,
            persisted_checkpoint=self.store.load_agent_checkpoint(
                original.checkpoint_id
            ),
        )

    def _has_active_transition(self, instance_id: str) -> bool:
        try:
            transition = self.store.load_agent_transition(instance_id)
        except KeyError:
            return False
        return transition.state in _BLOCKING_TRANSITION_STATES

    def manual_handoff(
        self,
        instance_id: str,
        incoming_provider_id: str,
        initiated_by: str,
        approval_id: str,
    ) -> DriverEpoch:
        return self._perform_handoff(
            instance_id,
            incoming_provider_id,
            initiated_by,
            approval_id,
            authorization_operation="manual_handoff",
            reason="manual_handoff",
            authorization_already_proven=False,
            reserved_operation=None,
            persisted_checkpoint=None,
        )

    def _perform_handoff(
        self,
        instance_id: str,
        incoming_provider_id: str,
        initiated_by: str,
        approval_id: str,
        *,
        authorization_operation: str,
        reason: str,
        authorization_already_proven: bool,
        reserved_operation: AgentOperationReservation | None,
        persisted_checkpoint: AgentCheckpoint | None,
    ) -> DriverEpoch:
        if reserved_operation is None:
            self._raise_transition_required(
                instance_id,
                error_type=AgentHandoffError,
            )
        elif self._blocking_transition(instance_id) is not None:
            raise AgentHandoffError(
                f"agent instance {instance_id} transition blocks failover"
            )
        outgoing = self.active_epoch(instance_id)
        if outgoing.state not in _DISPATCHABLE_STATES:
            raise AgentManagerPausedError(
                f"agent instance {instance_id} is paused in epoch {outgoing.id}"
            )
        if not isinstance(approval_id, str) or not approval_id.strip():
            raise ValueError("approval_id is required")
        if not authorization_already_proven:
            self._require_authorized(
                authorization_operation,
                {
                    "approval_id": approval_id,
                    "instance_id": instance_id,
                    "incoming_provider_id": incoming_provider_id,
                    "outgoing_epoch_id": outgoing.id,
                    "initiated_by": initiated_by,
                },
            )
        if reserved_operation is None:
            try:
                operation = self.operations.reserve(
                    instance_id,
                    owner_token=self._id_factory("operation"),
                )
            except AgentOperationBlockedError as error:
                raise AgentHandoffError(str(error)) from error
        else:
            operation = reserved_operation
            self.operations.verify_owned(operation)
        outgoing_driver = self.registry.driver_for_provider(
            outgoing.provider_id,
            instance_id=instance_id,
        )
        try:
            self.operations.drain(
                operation,
                driver=outgoing_driver,
                session=self._session_for_epoch(outgoing),
            )
            self.operations.verify_quiescent(operation)
        except AgentOperationBlockedError as error:
            raise AgentHandoffError(str(error)) from error
        if persisted_checkpoint is None:
            checkpoint = self._collect_checkpoint(instance_id, outgoing)
        else:
            checkpoint = self.store.load_agent_checkpoint(persisted_checkpoint.id)
            if checkpoint != persisted_checkpoint:
                raise AgentHandoffError("failover checkpoint record changed")
            if (
                checkpoint.instance_id != instance_id
                or checkpoint.driver_epoch_id != outgoing.id
                or checkpoint.session_id != outgoing.session_id
            ):
                raise AgentHandoffError("failover checkpoint binding changed")
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
                reason=reason,
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
                    "operation_generation": operation.generation,
                    "operation_owner_ref": operation.owner_token,
                    "status": "importing",
                },
            )
            transition = AgentInstanceTransition(
                instance_id=instance_id,
                handoff_id=package.id,
                outgoing_epoch_id=outgoing.id,
                incoming_epoch_id=incoming.id,
                state=AgentTransitionState.IMPORTING,
                updated_at=self._clock(),
            )
            if not self.store.begin_agent_transition(transition):
                raise AgentHandoffError(
                    f"agent instance {instance_id} transition is already active"
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
        result: AgentDispatchResult | None = None,
        *,
        initiated_by: str,
    ) -> DriverEpoch:
        self._require_authorized(
            "reconcile_handoff",
            {
                "handoff_id": handoff_id,
                "initiated_by": initiated_by,
                "result_id": (
                    result.id if result is not None else "durable_acknowledgement"
                ),
            },
        )
        package = self.store.load_agent_handoff(handoff_id)
        transition = self.store.load_agent_transition(package.instance_id)
        if (
            transition.handoff_id != package.id
            or transition.state
            not in {
                AgentTransitionState.IMPORTING,
                AgentTransitionState.IMPORT_ACKNOWLEDGED,
                AgentTransitionState.RECONCILING,
                AgentTransitionState.FAILED,
            }
        ):
            raise AgentHandoffError("handoff is not awaiting reconciliation")
        incoming = self.store.load_driver_epoch(
            str(package.evidence["incoming_epoch_id"])
        )
        outgoing = self.store.load_driver_epoch(package.outgoing_epoch_id)
        if incoming.closed_at is not None:
            raise AgentHandoffError("closed incoming transition requires rollback")
        if transition.state is AgentTransitionState.IMPORT_ACKNOWLEDGED:
            if result is not None:
                durable_result_id = package.evidence.get("import_result_id")
                try:
                    durable_result = self.store.load_agent_dispatch_result(
                        str(durable_result_id)
                    )
                except KeyError as error:
                    raise AgentHandoffError(
                        "durable import acknowledgement result is missing"
                    ) from error
                binding_fields = (
                    "id",
                    "request_id",
                    "instance_id",
                    "provider_id",
                    "external_session_id",
                    "session_id",
                    "driver_epoch_id",
                    "state",
                )
                if any(
                    getattr(result, field) != getattr(durable_result, field)
                    for field in binding_fields
                ):
                    raise AgentHandoffError(
                        "reconciliation contradicts durable import acknowledgement"
                    )
            return self._promote_acknowledged_handoff(package)
        if result is None:
            raise AgentHandoffError(
                "handoff reconciliation requires a provider result"
            )
        with self.store.agent_transaction():
            transition = replace(
                transition,
                state=AgentTransitionState.RECONCILING,
                updated_at=self._clock(),
                reason=None,
            )
            self.store.save_agent_transition(transition)
            package = replace(
                package,
                evidence={**package.evidence, "status": "reconciling"},
            )
            self.store.save_agent_handoff(package)
        incoming, failure = self._complete_handoff(
            package, outgoing, incoming, result, invalid_state="quarantined"
        )
        if failure is not None:
            raise AgentHandoffError(failure.value)
        return incoming

    def rollback_handoff(
        self,
        handoff_id: str,
        *,
        initiated_by: str,
    ) -> DriverEpoch:
        self._require_authorized(
            "rollback_handoff",
            {
                "handoff_id": handoff_id,
                "initiated_by": initiated_by,
            },
        )
        package = self.store.load_agent_handoff(handoff_id)
        transition = self.store.load_agent_transition(package.instance_id)
        if (
            transition.handoff_id != handoff_id
            or transition.state not in _BLOCKING_TRANSITION_STATES
        ):
            raise AgentHandoffError("handoff transition cannot be rolled back")
        outgoing = self.store.load_driver_epoch(transition.outgoing_epoch_id)
        incoming = self.store.load_driver_epoch(transition.incoming_epoch_id)
        if outgoing.closed_at is not None:
            raise AgentHandoffError("closed outgoing epoch cannot be resumed")
        operation = self._operation_for_package(package)
        incoming_driver = self.registry.driver_for_provider(
            incoming.provider_id,
            instance_id=incoming.instance_id,
        )
        try:
            incoming_session = self._durable_incoming_session(package, incoming)
            self.operations.cancel_and_verify(
                operation,
                driver=incoming_driver,
                session=incoming_session,
            )
        except (AgentOperationBlockedError, AgentHandoffError):
            blocked = replace(
                incoming,
                state=AgentOperationState.BLOCKED,
                reason="rollback_cancel_unverified",
            )
            with self.store.agent_transaction():
                self.store.save_driver_epoch(blocked)
                self.store.save_agent_handoff(
                    replace(
                        package,
                        evidence={
                            **package.evidence,
                            "status": "rollback_blocked",
                            "reason": "incoming_cancel_unverified",
                        },
                    )
                )
                if transition.state is not AgentTransitionState.FAILED:
                    self.store.save_agent_transition(
                        replace(
                            transition,
                            state=AgentTransitionState.FAILED,
                            updated_at=self._clock(),
                            reason="incoming_cancel_unverified",
                        )
                    )
            return blocked
        with self.store.agent_transaction():
            if incoming.closed_at is None:
                self.store.save_driver_epoch(
                    replace(
                        incoming,
                        state=AgentOperationState.CANCELLED,
                        closed_at=self._clock(),
                        reason="handoff_rolled_back",
                    )
                )
            outgoing = replace(
                outgoing,
                state=AgentOperationState.RUNNING,
                reason="handoff_rolled_back",
            )
            self.store.save_driver_epoch(outgoing)
            self.store.save_agent_handoff(
                replace(
                    package,
                    evidence={**package.evidence, "status": "rolled_back"},
                )
            )
            self.store.save_agent_transition(
                replace(
                    transition,
                    state=AgentTransitionState.ROLLED_BACK,
                    updated_at=self._clock(),
                    reason="operator_rollback",
                )
            )
            self.operations.release(operation)
        return outgoing

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
        if failure is not None:
            with self.store.agent_transaction():
                self.store.save_agent_dispatch_result(
                    replace(
                        result,
                        error_message=None,
                        evidence=self._safe_result_evidence(result.evidence),
                    )
                )
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
                transition = self.store.load_agent_transition(package.instance_id)
                self.store.save_agent_transition(
                    replace(
                        transition,
                        state=AgentTransitionState.FAILED,
                        updated_at=self._clock(),
                        reason=failure.value,
                    )
                )
            return incoming, failure
        package, incoming = self._persist_import_acknowledgement(
            package,
            incoming,
            result,
        )
        return self._promote_acknowledged_handoff(package), None

    def _persist_import_acknowledgement(
        self,
        package: AgentHandoffPackage,
        incoming: DriverEpoch,
        result: AgentDispatchResult,
    ) -> tuple[AgentHandoffPackage, DriverEpoch]:
        external_session_id = result.external_session_id
        if not isinstance(external_session_id, str) or not external_session_id.strip():
            raise AgentHandoffError("import acknowledgement lacks external session identity")
        normalized = replace(
            result,
            error_message=None,
            evidence=self._safe_result_evidence(result.evidence),
        )
        with self.store.agent_transaction():
            self.store.save_agent_dispatch_result(normalized)
            session = self.store.load_agent_session(incoming.session_id)
            self.store.save_agent_session(
                replace(
                    session,
                    external_session_id=external_session_id,
                    last_observed_at=self._clock(),
                )
            )
            package = replace(
                package,
                evidence={
                    **package.evidence,
                    "status": "import_acknowledged",
                    "import_result_id": normalized.id,
                    "incoming_external_session_id": external_session_id,
                },
            )
            self.store.save_agent_handoff(package)
            transition = self.store.load_agent_transition(package.instance_id)
            self.store.save_agent_transition(
                replace(
                    transition,
                    state=AgentTransitionState.IMPORT_ACKNOWLEDGED,
                    updated_at=self._clock(),
                    reason=None,
                )
            )
        return package, incoming

    def _promote_acknowledged_handoff(
        self,
        package: AgentHandoffPackage,
    ) -> DriverEpoch:
        package = self.store.load_agent_handoff(package.id)
        transition = self.store.load_agent_transition(package.instance_id)
        if transition.state is not AgentTransitionState.IMPORT_ACKNOWLEDGED:
            raise AgentHandoffError("handoff import is not durably acknowledged")
        incoming = self.store.load_driver_epoch(transition.incoming_epoch_id)
        outgoing = self.store.load_driver_epoch(transition.outgoing_epoch_id)
        session = self.store.load_agent_session(incoming.session_id)
        external_session_id = package.evidence.get("incoming_external_session_id")
        result_id = package.evidence.get("import_result_id")
        if (
            not isinstance(external_session_id, str)
            or not external_session_id.strip()
            or session.external_session_id != external_session_id
            or not isinstance(result_id, str)
        ):
            raise AgentHandoffError("durable import acknowledgement binding mismatch")
        try:
            result = self.store.load_agent_dispatch_result(result_id)
        except KeyError as error:
            raise AgentHandoffError(
                "durable import acknowledgement result is missing"
            ) from error
        if (
            result.request_id != f"handoff.{package.id}"
            or result.id != result_id
            or result.instance_id != package.instance_id
            or result.provider_id != package.incoming_provider_id
            or result.session_id != incoming.session_id
            or result.driver_epoch_id != incoming.id
            or result.external_session_id != external_session_id
            or result.state not in _ACKNOWLEDGED_STATES
        ):
            raise AgentHandoffError("durable import result binding mismatch")
        with self.store.agent_transaction():
            incoming = replace(incoming, state=AgentOperationState.RUNNING)
            self.store.save_agent_handoff(
                replace(
                    package,
                    evidence={**package.evidence, "status": "acknowledged"},
                )
            )
            self._close_epoch(outgoing, replacement_epoch_id=incoming.id)
            self.store.save_driver_epoch(incoming)
            self.store.save_agent_transition(
                replace(
                    transition,
                    state=AgentTransitionState.COMPLETED,
                    updated_at=self._clock(),
                    reason=None,
                )
            )
            self.operations.release(self._operation_for_package(package))
        return incoming

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
        if request.evidence.get("status") == AgentOperationState.CANCELLED.value:
            return self._quarantine_result(
                result,
                "cancelled_operation_generation",
            )
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

    def _blocking_transition(
        self,
        instance_id: str,
    ) -> AgentInstanceTransition | None:
        try:
            transition = self.store.load_agent_transition(instance_id)
        except KeyError:
            return None
        if transition.state in _BLOCKING_TRANSITION_STATES:
            return transition
        return None

    def _operation_for_package(
        self,
        package: AgentHandoffPackage,
    ) -> AgentOperationReservation:
        operation = self.store.load_agent_operation(package.instance_id)
        if (
            operation.state is not AgentOperationFenceState.FENCED
            or operation.generation != package.evidence.get("operation_generation")
            or operation.owner_token != package.evidence.get("operation_owner_ref")
        ):
            raise AgentHandoffError("handoff operation reservation binding mismatch")
        return operation

    def _durable_incoming_session(
        self,
        package: AgentHandoffPackage,
        incoming: DriverEpoch,
    ) -> AgentSession:
        session = self._session_for_epoch(incoming)
        external_session_id = package.evidence.get("incoming_external_session_id")
        result_id = package.evidence.get("import_result_id")
        if (
            not isinstance(external_session_id, str)
            or not external_session_id.strip()
            or session.external_session_id != external_session_id
            or not isinstance(result_id, str)
        ):
            raise AgentHandoffError(
                "rollback lacks durable incoming external session identity"
            )
        try:
            result = self.store.load_agent_dispatch_result(result_id)
        except KeyError as error:
            raise AgentHandoffError(
                "rollback durable import acknowledgement result is missing"
            ) from error
        if (
            result.request_id != f"handoff.{package.id}"
            or result.provider_id != incoming.provider_id
            or result.instance_id != incoming.instance_id
            or result.session_id != incoming.session_id
            or result.driver_epoch_id != incoming.id
            or result.external_session_id != external_session_id
            or result.state not in _ACKNOWLEDGED_STATES
        ):
            raise AgentHandoffError(
                "rollback durable import acknowledgement is contradictory"
            )
        return session

    def _raise_transition_required(
        self,
        instance_id: str,
        *,
        error_type: type[AgentManagerError] | None = None,
    ) -> None:
        transition = self._blocking_transition(instance_id)
        if transition is not None:
            if error_type is None:
                raise AgentTransitionRequiredError(transition)
            raise error_type(
                f"agent instance {instance_id} transition "
                f"{transition.state.value} blocks this operation"
            )
        try:
            operation = self.store.load_agent_operation(instance_id)
        except KeyError:
            return
        if operation.state is AgentOperationFenceState.FENCED:
            if error_type is None:
                raise AgentOperationRequiredError(operation)
            raise error_type(
                f"agent instance {instance_id} operation generation "
                f"{operation.generation} is fenced"
            )

    def _await_activation_winner(self, instance_id: str) -> DriverEpoch:
        deadline = time.monotonic() + self._activation_wait_seconds
        while time.monotonic() < deadline:
            reservation = self.store.load_agent_activation(instance_id)
            if reservation.state == "active" and reservation.epoch_id is not None:
                return self.store.load_driver_epoch(reservation.epoch_id)
            if reservation.state == "blocked":
                raise AgentManagerError(
                    f"activation blocked: {reservation.reason or 'unknown'}"
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
        operation_generation = request.evidence.get("operation_generation")
        if isinstance(operation_generation, int):
            evidence["operation_generation"] = operation_generation
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
        status = str(evidence.get("status", AgentOperationState.QUEUED.value))
        state = (
            AgentOperationState.QUEUED
            if status in {"accepted", "executing"}
            else AgentOperationState(status)
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
