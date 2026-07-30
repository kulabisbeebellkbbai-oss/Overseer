from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
import pytest

from overseer.agent_contracts import (
    AgentDispatchRequest,
    AgentOperationState,
)
from overseer.agent_manager import (
    AgentManager,
    AgentManagerPausedError,
    AgentTransitionRequiredError,
)
from overseer.agent_operations import (
    AgentOperationBlockedError,
    AgentOperationCoordinator,
)
from overseer.store import OverseerStore
from tests.test_agent_manager import FakeDriver, _allow, _registry


def _request(request_id: str = "dispatch.1") -> AgentDispatchRequest:
    return AgentDispatchRequest(
        id=request_id,
        instance_id="overseer.default",
        session_id="session.codex",
        driver_epoch_id="epoch.codex",
        idempotency_key=request_id,
        prompt="continue",
    )


def test_reservation_prevents_delayed_dispatch_execution(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        coordinator = AgentOperationCoordinator(store)
        request = coordinator.accept_dispatch(_request())

        reservation = coordinator.reserve(
            request.instance_id,
            owner_token="handoff.1",
        )

        assert not coordinator.claim_dispatch_execution(request)
        coordinator.verify_quiescent(reservation)
        stored = store.load_agent_dispatch(request.id)
        assert stored.evidence["status"] == "cancelled"


def test_drain_cancels_and_verifies_executing_dispatches(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    driver = registry.driver("overseer.default")
    assert driver is drivers["codex"]
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        epoch = manager.activate("overseer.default", initiated_by="operator")
        session = store.load_agent_session(epoch.session_id)
        coordinator = AgentOperationCoordinator(store, drain_wait_seconds=0)
        request = coordinator.accept_dispatch(
            replace(
                _request(),
                session_id=epoch.session_id,
                driver_epoch_id=epoch.id,
            )
        )
        assert coordinator.claim_dispatch_execution(request)
        reservation = coordinator.reserve(
            request.instance_id,
            owner_token="handoff.1",
        )

        coordinator.drain(reservation, driver=driver, session=session)

        coordinator.verify_quiescent(reservation)
        assert driver.cancel_calls == 1
        assert (
            store.load_agent_dispatch(request.id).evidence["status"]
            == AgentOperationState.CANCELLED.value
        )


def test_unverified_cancellation_keeps_operation_fenced(tmp_path: Path) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    driver = registry.driver("overseer.default")
    assert driver is drivers["codex"]
    driver.cancel_state = AgentOperationState.FAILED
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        epoch = manager.activate("overseer.default", initiated_by="operator")
        session = store.load_agent_session(epoch.session_id)
        coordinator = AgentOperationCoordinator(store, drain_wait_seconds=0)
        request = coordinator.accept_dispatch(
            replace(
                _request(),
                session_id=epoch.session_id,
                driver_epoch_id=epoch.id,
            )
        )
        assert coordinator.claim_dispatch_execution(request)
        reservation = coordinator.reserve(
            request.instance_id,
            owner_token="handoff.1",
        )

        with pytest.raises(AgentOperationBlockedError, match="cancellation"):
            coordinator.drain(reservation, driver=driver, session=session)

        assert store.load_agent_operation(request.instance_id).state == "fenced"


def test_activation_completion_cas_rejects_stale_generation(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        assert store.reserve_agent_activation(
            "overseer.default",
            "activation.old",
            owner_id="manager.old",
            started_at="2026-07-29T10:00:00+00:00",
            lease_expires_at="2026-07-29T10:01:00+00:00",
            allow_blocked_retry=False,
            observed_at="2026-07-29T10:00:00+00:00",
        )
        assert store.reserve_agent_activation(
            "overseer.default",
            "activation.new",
            owner_id="manager.new",
            started_at="2026-07-29T11:00:00+00:00",
            lease_expires_at="2026-07-29T11:01:00+00:00",
            allow_blocked_retry=False,
            observed_at="2026-07-29T11:00:00+00:00",
        )

        with pytest.raises(ValueError, match="ownership changed"):
            store.finish_agent_activation(
                "overseer.default",
                "activation.old",
                "manager.old",
                1,
                "active",
                epoch_id="epoch.old",
            )


def test_delayed_dispatch_cannot_escape_handoff_fence(tmp_path: Path) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"
    intent_persisted = Event()
    release_dispatch = Event()

    class DelayedDispatchStore(OverseerStore):
        def save_agent_dispatch(self, dispatch: AgentDispatchRequest) -> None:
            super().save_agent_dispatch(dispatch)
            if dispatch.evidence.get("status") == "accepted":
                intent_persisted.set()
                release_dispatch.wait(timeout=5)

    with OverseerStore(path) as store:
        AgentManager(registry, store, authorization_callback=_allow).activate(
            "overseer.default", initiated_by="operator"
        )

    dispatch_results: list[object] = []
    dispatch_errors: list[BaseException] = []

    def dispatch() -> None:
        try:
            with DelayedDispatchStore(path) as store:
                manager = AgentManager(registry, store, authorization_callback=_allow)
                dispatch_results.append(
                    manager.dispatch(
                        "overseer.default",
                        "delayed work",
                        "dispatch.delayed",
                    )
                )
        except BaseException as error:
            dispatch_errors.append(error)

    worker = Thread(target=dispatch)
    worker.start()
    assert intent_persisted.wait(timeout=5)
    with OverseerStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        manager.manual_handoff(
            "overseer.default",
            "claude",
            "operator",
            "approval.delayed-dispatch",
        )
        released = store.load_agent_operation("overseer.default")
        assert released.state == "open"
        assert released.generation == 2
    release_dispatch.set()
    worker.join(timeout=5)

    assert dispatch_errors == []
    assert len(dispatch_results) == 1
    assert dispatch_results[0].state is AgentOperationState.CANCELLED
    assert drivers["codex"].dispatch_calls == 0


def test_rollback_keeps_fence_until_incoming_cancel_is_verified(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"

    class FailPromotionOnceStore(OverseerStore):
        fail_promotion = True

        def save_driver_epoch(self, epoch: object) -> None:
            if self.fail_promotion and getattr(epoch, "closed_at", None) is not None:
                self.fail_promotion = False
                raise RuntimeError("injected phase B failure")
            super().save_driver_epoch(epoch)

    with FailPromotionOnceStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        outgoing = manager.activate("overseer.default", initiated_by="operator")
        with pytest.raises(RuntimeError, match="phase B"):
            manager.manual_handoff(
                "overseer.default",
                "claude",
                "operator",
                "approval.rollback-race",
            )
        handoff_id = store.list_agent_handoffs()[0].id

    incoming_driver = drivers["claude"]
    incoming_driver.cancel_entered = Event()
    incoming_driver.cancel_release = Event()
    rollback_results: list[object] = []

    def rollback() -> None:
        with OverseerStore(path) as store:
            manager = AgentManager(registry, store, authorization_callback=_allow)
            rollback_results.append(
                manager.rollback_handoff(handoff_id, initiated_by="operator")
            )

    worker = Thread(target=rollback)
    worker.start()
    assert incoming_driver.cancel_entered.wait(timeout=5)
    with OverseerStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        with pytest.raises(
            (AgentManagerPausedError, AgentTransitionRequiredError),
            match="transition",
        ):
            manager.dispatch(
                "overseer.default",
                "must remain paused",
                "dispatch.rollback-race",
            )
    incoming_driver.cancel_release.set()
    worker.join(timeout=5)

    assert len(rollback_results) == 1
    assert rollback_results[0].id == outgoing.id
    assert incoming_driver.cancel_calls == 1
    assert incoming_driver.last_cancel_session is not None
    assert (
        incoming_driver.last_cancel_session.external_session_id
        == "external.claude.handoff"
    )
    with OverseerStore(path) as store:
        released = store.load_agent_operation("overseer.default")
        assert released.state == "open"
        assert released.generation == 2


def test_rollback_cancel_failure_does_not_resume_outgoing(tmp_path: Path) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"
    drivers["claude"] = drivers.get("claude") or registry.driver_for_provider(
        "claude", instance_id="overseer.default"
    )
    drivers["claude"].import_state = AgentOperationState.FAILED

    with OverseerStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        manager.activate("overseer.default", initiated_by="operator")
        with pytest.raises(Exception):
            manager.manual_handoff(
                "overseer.default",
                "claude",
                "operator",
                "approval.cancel-failure",
            )
        handoff_id = store.list_agent_handoffs()[0].id
        drivers["claude"].cancel_state = AgentOperationState.FAILED

        blocked = manager.rollback_handoff(handoff_id, initiated_by="operator")

        assert blocked.state is AgentOperationState.BLOCKED
        with pytest.raises(AgentTransitionRequiredError):
            manager.recover(
                store.list_agent_sessions()[0].id,
                initiated_by="operator",
            )


def test_rollback_rejects_local_only_cancel_acknowledgement(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"

    class FailPromotionOnceStore(OverseerStore):
        fail_promotion = True

        def save_driver_epoch(self, epoch: object) -> None:
            if self.fail_promotion and getattr(epoch, "closed_at", None) is not None:
                self.fail_promotion = False
                raise RuntimeError("injected phase B failure")
            super().save_driver_epoch(epoch)

    with FailPromotionOnceStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        manager.activate("overseer.default", initiated_by="operator")
        with pytest.raises(RuntimeError, match="phase B"):
            manager.manual_handoff(
                "overseer.default",
                "claude",
                "operator",
                "approval.local-only-cancel",
            )
        handoff_id = store.list_agent_handoffs()[0].id

    drivers["claude"].cancel_echo_local_only = True
    with OverseerStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        blocked = manager.rollback_handoff(handoff_id, initiated_by="operator")

        assert blocked.state is AgentOperationState.BLOCKED
        assert store.load_agent_operation("overseer.default").state == "fenced"
