"""Generation-bound operation coordination for provider driver lifecycles."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import time
from typing import Callable

from .agent_contracts import (
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentErrorCategory,
    AgentOperationFenceState,
    AgentOperationReservation,
    AgentOperationState,
    AgentSession,
    PrimaryDriver,
)
from .store import OverseerStore


_TERMINAL_DISPATCH_STATUSES = {
    AgentOperationState.SUCCEEDED.value,
    AgentOperationState.FAILED.value,
    AgentOperationState.BLOCKED.value,
    AgentOperationState.CANCELLED.value,
    AgentOperationState.QUARANTINED.value,
}


class AgentOperationBlockedError(RuntimeError):
    """Raised when operation quiescence or cancellation cannot be proven."""


class AgentOperationCoordinator:
    """Fence provider operations and bind dispatch intent to one generation."""

    def __init__(
        self,
        store: OverseerStore,
        *,
        clock: Callable[[], str] | None = None,
        drain_wait_seconds: float = 0.25,
    ) -> None:
        if drain_wait_seconds < 0:
            raise ValueError("drain wait must be non-negative")
        self.store = store
        self._clock = clock or (
            lambda: datetime.now(timezone.utc).isoformat(timespec="microseconds")
        )
        self._drain_wait_seconds = drain_wait_seconds

    def reserve(
        self,
        instance_id: str,
        *,
        owner_token: str,
    ) -> AgentOperationReservation:
        with self.store.agent_transaction():
            current = self.store.ensure_agent_operation(
                instance_id,
                updated_at=self._clock(),
            )
            if current.state is not AgentOperationFenceState.OPEN:
                raise AgentOperationBlockedError(
                    f"agent instance {instance_id} operation is already fenced"
                )
            reserved = replace(
                current,
                state=AgentOperationFenceState.FENCED,
                owner_token=owner_token,
                updated_at=self._clock(),
            )
            self.store.save_agent_operation(
                reserved,
                expected_generation=current.generation,
                expected_state=AgentOperationFenceState.OPEN,
                expected_owner_token=None,
            )
        return reserved

    def require_open(self, instance_id: str) -> AgentOperationReservation:
        operation = self.store.ensure_agent_operation(
            instance_id,
            updated_at=self._clock(),
        )
        if operation.state is not AgentOperationFenceState.OPEN:
            raise AgentOperationBlockedError(
                f"agent instance {instance_id} operation is fenced"
            )
        return operation

    def verify_owned(self, reservation: AgentOperationReservation) -> None:
        try:
            current = self.store.load_agent_operation(reservation.instance_id)
        except KeyError as error:
            raise AgentOperationBlockedError(
                f"agent instance {reservation.instance_id} reservation was lost"
            ) from error
        if current != reservation:
            raise AgentOperationBlockedError(
                f"agent instance {reservation.instance_id} reservation ownership changed"
            )

    def release_if_owned(self, reservation: AgentOperationReservation) -> bool:
        with self.store.agent_transaction():
            try:
                self.verify_owned(reservation)
            except AgentOperationBlockedError:
                return False
            self.release(reservation)
        return True

    def release(self, reservation: AgentOperationReservation) -> AgentOperationReservation:
        released = replace(
            reservation,
            generation=reservation.generation + 1,
            state=AgentOperationFenceState.OPEN,
            owner_token=None,
            updated_at=self._clock(),
        )
        self.store.save_agent_operation(
            released,
            expected_generation=reservation.generation,
            expected_state=AgentOperationFenceState.FENCED,
            expected_owner_token=reservation.owner_token,
        )
        return released

    def accept_dispatch(self, request: AgentDispatchRequest) -> AgentDispatchRequest:
        operation = self.store.ensure_agent_operation(
            request.instance_id,
            updated_at=self._clock(),
        )
        if operation.state is not AgentOperationFenceState.OPEN:
            raise AgentOperationBlockedError(
                f"agent instance {request.instance_id} operation is fenced"
            )
        accepted = replace(
            request,
            evidence={
                **request.evidence,
                "operation_generation": operation.generation,
                "status": "accepted",
            },
        )
        self.store.save_agent_dispatch(accepted)
        return accepted

    def claim_dispatch_execution(self, request: AgentDispatchRequest) -> bool:
        with self.store.agent_transaction():
            current = self.store.load_agent_dispatch(request.id)
            operation = self.store.load_agent_operation(request.instance_id)
            generation = current.evidence.get("operation_generation")
            if current.evidence.get("status") != "accepted":
                return current.evidence.get("status") == "executing"
            may_execute = (
                operation.state is AgentOperationFenceState.OPEN
                and generation == operation.generation
            )
            self.store.save_agent_dispatch(
                replace(
                    current,
                    evidence={
                        **current.evidence,
                        "status": "executing" if may_execute else "cancelled",
                    },
                )
            )
        return may_execute

    def complete_dispatch(
        self,
        request: AgentDispatchRequest,
        result: AgentDispatchResult,
    ) -> AgentDispatchRequest:
        current = self.store.load_agent_dispatch(request.id)
        if (
            current.evidence.get("operation_generation")
            != request.evidence.get("operation_generation")
        ):
            raise AgentOperationBlockedError("dispatch generation binding changed")
        if (
            current.evidence.get("status")
            in {
                AgentOperationState.CANCELLED.value,
                AgentOperationState.QUARANTINED.value,
            }
            and result.state
            not in {
                AgentOperationState.CANCELLED,
                AgentOperationState.QUARANTINED,
            }
        ):
            return current
        completed = replace(
            current,
            evidence={
                **current.evidence,
                "result_id": result.id,
                "provider_id": result.provider_id,
                "status": result.state.value,
                **(
                    {"reason": result.error_category.value}
                    if result.error_category is not None
                    else {}
                ),
            },
        )
        self.store.save_agent_dispatch(completed)
        return completed

    def cancelled_result(
        self,
        request: AgentDispatchRequest,
        *,
        provider_id: str,
        result_id: str,
    ) -> AgentDispatchResult:
        return AgentDispatchResult(
            id=result_id,
            request_id=request.id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            driver_epoch_id=request.driver_epoch_id,
            provider_id=provider_id,
            state=AgentOperationState.CANCELLED,
            error_category=AgentErrorCategory.CANCELLED,
            evidence={
                "operation_generation": request.evidence["operation_generation"],
                "reason": "operation_fenced_before_provider_execution",
            },
        )

    def drain(
        self,
        reservation: AgentOperationReservation,
        *,
        driver: PrimaryDriver,
        session: AgentSession,
    ) -> None:
        self._cancel_unclaimed(reservation)
        deadline = time.monotonic() + self._drain_wait_seconds
        while self._inflight(reservation) and time.monotonic() < deadline:
            time.sleep(0.01)
        if self._inflight(reservation):
            self.cancel_and_verify(
                reservation,
                driver=driver,
                session=session,
            )
        self.verify_quiescent(reservation)

    def verify_quiescent(self, reservation: AgentOperationReservation) -> None:
        if self._inflight(reservation):
            raise AgentOperationBlockedError(
                f"agent instance {reservation.instance_id} is not quiescent"
            )

    def cancel_and_verify(
        self,
        reservation: AgentOperationReservation,
        *,
        driver: PrimaryDriver,
        session: AgentSession,
    ) -> AgentDispatchResult:
        external_session_id = session.external_session_id
        if (
            not isinstance(external_session_id, str)
            or not external_session_id.strip()
        ):
            raise AgentOperationBlockedError(
                "provider cancellation lacks durable external session identity"
            )
        try:
            result = driver.cancel(session)
        except Exception as error:
            raise AgentOperationBlockedError(
                "provider cancellation could not be verified"
            ) from error
        if (
            result.instance_id != reservation.instance_id
            or result.provider_id != session.provider_id
            or result.external_session_id != external_session_id
            or result.state
            not in {
                AgentOperationState.CANCELLED,
                AgentOperationState.SUCCEEDED,
            }
        ):
            raise AgentOperationBlockedError(
                "provider cancellation did not reach a verified terminal state"
            )
        with self.store.agent_transaction():
            current = self.store.load_agent_operation(reservation.instance_id)
            if current != reservation:
                raise AgentOperationBlockedError(
                    "operation reservation changed during cancellation"
                )
            for request in self._inflight(reservation):
                self.store.save_agent_dispatch(
                    replace(
                        request,
                        evidence={**request.evidence, "status": "cancelled"},
                    )
                )
        return result

    def _cancel_unclaimed(self, reservation: AgentOperationReservation) -> None:
        with self.store.agent_transaction():
            current = self.store.load_agent_operation(reservation.instance_id)
            if current != reservation:
                raise AgentOperationBlockedError("operation reservation changed")
            for request in self._inflight(reservation):
                if request.evidence.get("status") == "accepted":
                    self.store.save_agent_dispatch(
                        replace(
                            request,
                            evidence={**request.evidence, "status": "cancelled"},
                        )
                    )

    def _inflight(
        self,
        reservation: AgentOperationReservation,
    ) -> tuple[AgentDispatchRequest, ...]:
        return tuple(
            request
            for request in self.store.list_agent_dispatches()
            if request.instance_id == reservation.instance_id
            and (
                not isinstance(
                    request.evidence.get("operation_generation"),
                    int,
                )
                or int(request.evidence["operation_generation"])
                <= reservation.generation
            )
            and request.evidence.get("status") not in _TERMINAL_DISPATCH_STATUSES
        )
