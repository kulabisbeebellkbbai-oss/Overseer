from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Event, Thread
import time
from typing import Mapping

import pytest

from overseer.agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentErrorCategory,
    AgentHandoffPackage,
    AgentInstanceProfile,
    AgentOperationState,
    AgentProvider,
    AgentSession,
    AgentTransitionState,
)
from overseer.agent_manager import (
    AgentAuthorizationError,
    AgentHandoffError,
    AgentManager,
    AgentManagerError,
    AgentManagerPausedError,
    AgentTransitionRequiredError,
)
from overseer.agent_registry import AgentRegistry
from overseer.core import OwnerDomain
from overseer.policy import PolicyCheck, PolicyCheckStatus, PolicyDecision
from overseer.store import OverseerStore


class FakeDriver:
    def __init__(
        self,
        provider: AgentProvider,
        profile: AgentInstanceProfile,
        *,
        events: list[str],
    ) -> None:
        self.provider = provider
        self.profile = profile
        self.events = events
        self.dispatch_calls = 0
        self.start_calls = 0
        self.resume_calls = 0
        self.import_state = AgentOperationState.ACKNOWLEDGED
        self.import_overrides: dict[str, str] = {}
        self.checkpoint_expires_at: str | None = None
        self.checkpoint_status = "ready"
        self.checkpoint_created_at = datetime.now(timezone.utc).isoformat()
        self.last_import_result: AgentDispatchResult | None = None
        self.start_entered: Event | None = None
        self.start_release: Event | None = None
        self.start_error_count = 0
        self.import_entered: Event | None = None
        self.import_release: Event | None = None

    def _result(
        self,
        *,
        request_id: str,
        session_id: str,
        epoch_id: str,
        state: AgentOperationState,
        error_category: AgentErrorCategory | None = None,
    ) -> AgentDispatchResult:
        return AgentDispatchResult(
            id=f"result.{request_id}",
            request_id=request_id,
            instance_id=self.profile.id,
            session_id=session_id,
            driver_epoch_id=epoch_id,
            provider_id=self.provider.id,
            state=state,
            error_category=error_category,
            provider_reference=f"provider-ref.{request_id}",
            external_session_id=f"provider-session.{self.provider.id}",
            evidence={"status": state.value, "message_id": f"message.{request_id}"},
        )

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]:
        return ()

    def resolve(self, reference: str) -> AgentSession | None:
        return None

    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult:
        self.start_calls += 1
        self.events.append(f"start:{self.provider.id}")
        if self.start_entered is not None:
            self.start_entered.set()
        if self.start_release is not None:
            self.start_release.wait(timeout=5)
        if self.start_error_count:
            self.start_error_count -= 1
            raise RuntimeError("transient provider start failure")
        return self._result(
            request_id=f"activate.{self.provider.id}",
            session_id=f"external.{self.provider.id}.1",
            epoch_id="pending",
            state=AgentOperationState.ACKNOWLEDGED,
        )

    def resume(self, session: AgentSession) -> AgentDispatchResult:
        self.resume_calls += 1
        self.events.append(f"resume:{self.provider.id}")
        return self._result(
            request_id=f"recover.{self.provider.id}",
            session_id=session.external_session_id,
            epoch_id="pending",
            state=AgentOperationState.RUNNING,
        )

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult:
        self.dispatch_calls += 1
        self.events.append(f"dispatch:{self.provider.id}")
        return self._result(
            request_id=request.id,
            session_id=request.session_id,
            epoch_id=request.driver_epoch_id,
            state=AgentOperationState.SUCCEEDED,
        )

    def inspect(self, session: AgentSession) -> AgentDispatchResult:
        return self._result(
            request_id=f"inspect.{self.provider.id}",
            session_id=session.id,
            epoch_id="pending",
            state=AgentOperationState.ACKNOWLEDGED,
        )

    def checkpoint(self, session: AgentSession) -> AgentCheckpoint:
        self.events.append(f"checkpoint:{self.provider.id}")
        return AgentCheckpoint(
            id=f"provider-checkpoint.{self.provider.id}",
            instance_id=self.profile.id,
            session_id=session.id,
            driver_epoch_id="provider-owned-untrusted-epoch",
            evidence={
                "status": self.checkpoint_status,
                "evidence_id": "evidence.checkpoint",
            },
            created_at=self.checkpoint_created_at,
            expires_at=self.checkpoint_expires_at,
        )

    def cancel(self, session: AgentSession) -> AgentDispatchResult:
        return self._result(
            request_id=f"cancel.{self.provider.id}",
            session_id=session.id,
            epoch_id="pending",
            state=AgentOperationState.CANCELLED,
        )

    def import_handoff(
        self,
        profile: AgentInstanceProfile,
        package: AgentHandoffPackage,
    ) -> AgentDispatchResult:
        self.events.append(f"import:{self.provider.id}")
        if self.import_entered is not None:
            self.import_entered.set()
        if self.import_release is not None:
            self.import_release.wait(timeout=5)
        category = (
            AgentErrorCategory.HANDOFF_INCOMPATIBLE
            if self.import_state is AgentOperationState.FAILED
            else None
        )
        result = self._result(
            request_id=self.import_overrides.get(
                "request_id", f"handoff.{package.id}"
            ),
            session_id=self.import_overrides.get(
                "session_id", str(package.evidence["incoming_session_id"])
            ),
            epoch_id=self.import_overrides.get(
                "driver_epoch_id", str(package.evidence["incoming_epoch_id"])
            ),
            state=self.import_state,
            error_category=category,
        )
        self.last_import_result = replace(
            result,
            instance_id=self.import_overrides.get("instance_id", self.profile.id),
            provider_id=self.import_overrides.get("provider_id", self.provider.id),
            external_session_id=self.import_overrides.get(
                "external_session_id", f"external.{self.provider.id}.handoff"
            ),
        )
        return self.last_import_result


class TrackingStore(OverseerStore):
    def __init__(self, path: Path, events: list[str]) -> None:
        self.events = events
        super().__init__(path)

    def save_agent_checkpoint(self, checkpoint: AgentCheckpoint) -> None:
        self.events.append("store:checkpoint")
        super().save_agent_checkpoint(checkpoint)

    def save_agent_handoff(self, handoff: AgentHandoffPackage) -> None:
        self.events.append("store:handoff")
        super().save_agent_handoff(handoff)

    def save_driver_epoch(self, epoch: object) -> None:
        if getattr(epoch, "closed_at", None) is not None:
            self.events.append("store:close-outgoing")
        super().save_driver_epoch(epoch)


def _registry(
    tmp_path: Path,
    events: list[str],
) -> tuple[AgentRegistry, dict[str, FakeDriver]]:
    path = tmp_path / "providers.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "providers": [
                    {
                        "id": provider_id,
                        "adapter": provider_id,
                        "transport": "interactive_cli",
                        "executable": provider_id,
                        "capabilities": {
                            "interactive_dispatch": True,
                            "session_resume": True,
                            "checkpoints": True,
                            "handoff_import": True,
                        },
                    }
                    for provider_id in ("codex", "claude")
                ],
                "instances": [
                    {
                        "id": "overseer.default",
                        "primary_provider_id": "codex",
                        "workspace": str(tmp_path),
                        "fallback_provider_ids": ["claude"],
                        "required_capabilities": {
                            "checkpoints": True,
                            "handoff_import": True,
                        },
                    }
                ],
            }
        )
    )
    drivers: dict[str, FakeDriver] = {}

    def factory(
        provider: AgentProvider,
        profile: AgentInstanceProfile,
    ) -> FakeDriver:
        driver = drivers.get(provider.id)
        if driver is None:
            events.append(f"factory:{provider.id}")
            driver = FakeDriver(provider, profile, events=events)
            drivers[provider.id] = driver
        return driver

    return (
        AgentRegistry.load(
            path,
            adapter_factories={"codex": factory, "claude": factory},
        ),
        drivers,
    )


def _allow(operation: str, context: Mapping[str, object]) -> bool:
    return True


@pytest.fixture
def manager(
    tmp_path: Path,
) -> tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]]:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    store = TrackingStore(tmp_path / "state.sqlite3", events)
    value = AgentManager(
        registry=registry,
        store=store,
        authorization_callback=_allow,
    )
    yield value, store, drivers, events
    store.close()


def test_dispatch_is_bound_to_active_epoch(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    epoch = value.activate("overseer.default", initiated_by="operator")

    result = value.dispatch(
        instance_id="overseer.default",
        prompt="inspect health",
        idempotency_key="dispatch.health.1",
    )

    assert result.driver_epoch_id == epoch.id
    assert result.session_id == epoch.session_id
    assert result.provider_id == epoch.provider_id


def test_activation_does_not_trust_adapter_owned_session_identity(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    store.save_agent_session(
        AgentSession(
            id="session.codex",
            provider_id="claude",
            external_session_id="external.claude",
            workspace="/other",
            transport=value.registry.providers["claude"].transports[0],
            capabilities=value.registry.providers["claude"].capabilities,
            instance_id="other.instance",
        )
    )

    epoch = value.activate("overseer.default", initiated_by="operator")

    assert epoch.session_id != "session.codex"
    assert store.load_agent_session(epoch.session_id).provider_id == "codex"
    assert (
        store.load_agent_session(epoch.session_id).external_session_id
        == "provider-session.codex"
    )
    assert store.load_agent_session(epoch.session_id).legacy_references[
        "initiated_by_ref"
    ] == "operator"


def test_activate_is_idempotent_when_an_epoch_is_already_open(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, drivers, _ = manager
    first = value.activate("overseer.default", initiated_by="operator")
    second = value.activate("overseer.default", initiated_by="operator")

    assert second == first
    assert drivers["codex"].start_calls == 1
    assert [
        epoch
        for epoch in store.list_driver_epochs()
        if epoch.instance_id == "overseer.default" and epoch.closed_at is None
    ] == [first]


def test_repeated_idempotency_key_returns_recorded_result_without_redispatch(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, _, drivers, _ = manager
    value.activate("overseer.default", initiated_by="operator")

    first = value.dispatch("overseer.default", "continue", "same-key")
    second = value.dispatch("overseer.default", "different text", "same-key")

    assert second == first
    assert drivers["codex"].dispatch_calls == 1


def test_provider_evidence_cannot_override_manager_recorded_result_state(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    epoch = value.activate("overseer.default", initiated_by="operator")
    request = AgentDispatchRequest(
        id="dispatch.untrusted-evidence",
        instance_id=epoch.instance_id,
        session_id=epoch.session_id,
        driver_epoch_id=epoch.id,
        idempotency_key="untrusted-evidence-key",
        prompt="continue",
    )
    store.save_agent_dispatch(request)
    provider_result = AgentDispatchResult(
        id="result.manager-owned",
        request_id=request.id,
        instance_id=epoch.instance_id,
        session_id=epoch.session_id,
        driver_epoch_id=epoch.id,
        provider_id=epoch.provider_id,
        state=AgentOperationState.SUCCEEDED,
        evidence={
            "status": AgentOperationState.FAILED.value,
            "result_id": "result.provider-owned",
            "message_id": "message.safe",
        },
    )

    recorded = value.record_provider_result(epoch.id, provider_result)
    replayed = value.dispatch(
        epoch.instance_id,
        "different text",
        request.idempotency_key,
    )

    assert recorded.evidence["status"] == AgentOperationState.SUCCEEDED.value
    assert recorded.evidence["result_id"] == provider_result.id
    assert recorded.evidence["message_id"] == "message.safe"
    assert replayed == recorded


def test_recorded_result_drops_unbounded_provider_error_message(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    epoch = value.activate("overseer.default", initiated_by="operator")
    request = AgentDispatchRequest(
        id="dispatch.error",
        instance_id=epoch.instance_id,
        session_id=epoch.session_id,
        driver_epoch_id=epoch.id,
        idempotency_key="error-key",
        prompt="continue",
    )
    store.save_agent_dispatch(request)
    result = AgentDispatchResult(
        id="result.error",
        request_id=request.id,
        instance_id=epoch.instance_id,
        session_id=epoch.session_id,
        driver_epoch_id=epoch.id,
        provider_id=epoch.provider_id,
        state=AgentOperationState.FAILED,
        error_category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
        error_message="unbounded provider response body",
    )

    recorded = value.record_provider_result(epoch.id, result)

    assert recorded.error_message is None
    assert store.load_agent_dispatch_result(recorded.id).error_message is None


def test_repeated_idempotency_key_survives_manager_reconstruction(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        first_manager = AgentManager(registry, store, authorization_callback=_allow)
        first_manager.activate("overseer.default", initiated_by="operator")
        first = first_manager.dispatch("overseer.default", "continue", "same-key")

        second_manager = AgentManager(registry, store, authorization_callback=_allow)
        second = second_manager.dispatch(
            "overseer.default",
            "different text",
            "same-key",
        )

    assert second == first
    assert drivers["codex"].dispatch_calls == 1


def test_idempotency_key_cannot_replay_a_different_instance_result(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, _, _, _ = manager
    value.activate("overseer.default", initiated_by="operator")
    value.dispatch("overseer.default", "continue", "instance-bound-key")

    with pytest.raises(KeyError, match="no active driver epoch"):
        value.dispatch("other.instance", "continue", "instance-bound-key")


def test_idempotency_uniqueness_race_reloads_scoped_winner(tmp_path: Path) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"

    class RacingStore(OverseerStore):
        raced = False

        def save_agent_dispatch(self, dispatch: AgentDispatchRequest) -> None:
            if not self.raced:
                self.raced = True
                with OverseerStore(path) as competitor:
                    competitor.save_agent_dispatch(
                        replace(dispatch, id="dispatch.race-winner")
                    )
            super().save_agent_dispatch(dispatch)

    with RacingStore(path) as store:
        value = AgentManager(registry, store, authorization_callback=_allow)
        value.activate("overseer.default", initiated_by="operator")

        result = value.dispatch(
            "overseer.default",
            "continue",
            "race-key",
        )

        assert result.request_id == "dispatch.race-winner"
        assert result.state is AgentOperationState.QUEUED
        assert drivers["codex"].dispatch_calls == 0


def test_late_result_from_closed_epoch_is_quarantined(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    old = value.activate("overseer.default", initiated_by="operator")
    value.manual_handoff(
        "overseer.default",
        incoming_provider_id="claude",
        initiated_by="operator",
        approval_id="approval.1",
    )
    late = AgentDispatchResult(
        id="result.late",
        request_id="dispatch.late",
        instance_id=old.instance_id,
        session_id=old.session_id,
        driver_epoch_id=old.id,
        provider_id=old.provider_id,
        state=AgentOperationState.SUCCEEDED,
        evidence={"status": "late"},
    )

    result = value.record_provider_result(old.id, late)

    assert result.state is AgentOperationState.QUARANTINED
    assert result.error_category is AgentErrorCategory.QUARANTINED
    assert result.evidence["reason"] == "unknown_dispatch_request"
    assert result.id != late.id
    assert result in store.list_agent_dispatch_results()


def test_manual_handoff_closes_outgoing_only_after_incoming_acknowledgement(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, events = manager
    outgoing = value.activate("overseer.default", initiated_by="operator")

    incoming = value.manual_handoff(
        "overseer.default",
        incoming_provider_id="claude",
        initiated_by="operator",
        approval_id="approval.1",
    )

    stored_outgoing = store.load_driver_epoch(outgoing.id)
    assert incoming.ordinal == outgoing.ordinal + 1
    assert stored_outgoing.closed_at is not None
    assert stored_outgoing.replacement_epoch_id == incoming.id
    assert events.index("store:checkpoint") < events.index("store:handoff")
    assert events.index("store:handoff") < events.index("import:claude")
    assert events.index("import:claude") < events.index("store:close-outgoing")


@pytest.mark.parametrize(
    ("field", "bad_value"),
    (
        ("instance_id", "other.instance"),
        ("provider_id", "codex"),
        ("session_id", "session.wrong"),
        ("driver_epoch_id", "epoch.wrong"),
        ("request_id", "handoff.wrong"),
    ),
)
def test_handoff_rejects_acknowledgement_with_mismatched_binding(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
    field: str,
    bad_value: str,
) -> None:
    value, store, drivers, _ = manager
    outgoing = value.activate("overseer.default", initiated_by="operator")
    value.registry.driver_for_provider("claude", instance_id="overseer.default")
    drivers["claude"].import_overrides[field] = bad_value

    with pytest.raises(AgentHandoffError, match="handoff_incompatible"):
        value.manual_handoff(
            "overseer.default",
            incoming_provider_id="claude",
            initiated_by="operator",
            approval_id="approval.invalid-ack",
        )

    paused = store.load_driver_epoch(outgoing.id)
    assert paused.closed_at is None
    assert paused.state is AgentOperationState.RUNNING
    assert value.active_epoch(outgoing.instance_id) == paused
    transition = max(store.list_driver_epochs(), key=lambda epoch: epoch.ordinal)
    assert transition.state is AgentOperationState.BLOCKED


def test_failed_import_pauses_dispatch_until_explicit_rollback(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, drivers, _ = manager
    outgoing = value.activate("overseer.default", initiated_by="operator")
    value.registry.driver_for_provider("claude", instance_id="overseer.default")
    drivers["claude"].import_state = AgentOperationState.FAILED

    with pytest.raises(
        AgentHandoffError,
        match=AgentErrorCategory.HANDOFF_INCOMPATIBLE.value,
    ):
        value.manual_handoff(
            "overseer.default",
            incoming_provider_id="claude",
            initiated_by="operator",
            approval_id="approval.1",
        )

    stored_outgoing = store.load_driver_epoch(outgoing.id)
    assert stored_outgoing.closed_at is None
    assert stored_outgoing.state is AgentOperationState.RUNNING
    assert value.active_epoch(outgoing.instance_id) == stored_outgoing
    assert len(store.list_agent_checkpoints()) == 1
    handoff_evidence = store.list_agent_handoffs()[0].evidence
    assert handoff_evidence["checkpoint_id"] == store.list_agent_checkpoints()[0].id
    assert handoff_evidence["outgoing_epoch_id"] == outgoing.id
    assert handoff_evidence["reason"] == AgentErrorCategory.HANDOFF_INCOMPATIBLE.value
    assert handoff_evidence["status"] == "blocked"
    assert handoff_evidence["incoming_epoch_id"]
    assert handoff_evidence["incoming_session_id"]
    transition = store.load_driver_epoch(str(handoff_evidence["incoming_epoch_id"]))
    assert transition.state is AgentOperationState.BLOCKED
    assert (
        store.load_agent_transition(outgoing.instance_id).state
        is AgentTransitionState.FAILED
    )
    with pytest.raises(AgentManagerPausedError, match="transition"):
        value.dispatch("overseer.default", "must remain paused", "paused-key")

    resumed = value.rollback_handoff(
        store.list_agent_handoffs()[0].id,
        initiated_by="operator",
    )
    assert resumed.id == outgoing.id
    assert (
        store.load_agent_transition(outgoing.instance_id).state
        is AgentTransitionState.ROLLED_BACK
    )
    result = value.dispatch("overseer.default", "continue safely", "outgoing-key")
    assert result.driver_epoch_id == outgoing.id


def test_phase_a_fence_blocks_dispatch_and_competing_handoff(tmp_path: Path) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"
    with OverseerStore(path) as store:
        AgentManager(registry, store, authorization_callback=_allow).activate(
            "overseer.default", initiated_by="operator"
        )

    driver = registry.driver_for_provider("claude", instance_id="overseer.default")
    assert driver is drivers["claude"]
    driver.import_entered = Event()
    driver.import_release = Event()
    errors: list[BaseException] = []

    def handoff() -> None:
        try:
            with OverseerStore(path) as store:
                AgentManager(
                    registry, store, authorization_callback=_allow
                ).manual_handoff(
                    "overseer.default", "claude", "operator", "approval.fence"
                )
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=handoff)
    worker.start()
    assert driver.import_entered.wait(timeout=5)

    with OverseerStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        with pytest.raises(AgentManagerPausedError, match="transition"):
            manager.dispatch("overseer.default", "must not dispatch", "fenced-key")
        with pytest.raises(AgentHandoffError, match="transition"):
            manager.manual_handoff(
                "overseer.default", "claude", "operator", "approval.competing"
            )
        assert store.list_agent_dispatches() == ()

    driver.import_release.set()
    worker.join(timeout=5)
    assert errors == []


def test_manual_handoff_requires_callback_approval_before_any_mutation(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, _ = _registry(tmp_path, events)
    calls: list[tuple[str, Mapping[str, object]]] = []

    def authorize(
        operation: str,
        context: Mapping[str, object],
    ) -> PolicyDecision | bool:
        calls.append((operation, context))
        if operation == "manual_handoff":
            return PolicyDecision(
                subject_id=str(context["approval_id"]),
                subject_kind="agent_handoff",
                status=PolicyCheckStatus.BLOCK,
                checks=(
                    PolicyCheck(
                        "agent.handoff.approval",
                        PolicyCheckStatus.BLOCK,
                        OwnerDomain.SISKO,
                        "approval rejected",
                    ),
                ),
            )
        return True

    with OverseerStore(tmp_path / "state.sqlite3") as store:
        value = AgentManager(registry, store, authorization_callback=authorize)
        outgoing = value.activate("overseer.default", initiated_by="operator")
        with pytest.raises(AgentAuthorizationError, match="manual_handoff"):
            value.manual_handoff(
                "overseer.default",
                incoming_provider_id="claude",
                initiated_by="operator",
                approval_id="approval.denied",
            )

        assert value.active_epoch("overseer.default") == outgoing
        assert store.list_agent_checkpoints() == ()
        assert store.list_agent_handoffs() == ()
        assert calls[-1][0] == "manual_handoff"
        assert calls[-1][1]["approval_id"] == "approval.denied"


def test_dispatch_policy_denial_precedes_request_persistence(tmp_path: Path) -> None:
    events: list[str] = []
    registry, _ = _registry(tmp_path, events)

    def authorize(operation: str, context: Mapping[str, object]) -> bool:
        return operation != "dispatch"

    with OverseerStore(tmp_path / "state.sqlite3") as store:
        value = AgentManager(registry, store, authorization_callback=authorize)
        value.activate("overseer.default", initiated_by="operator")
        with pytest.raises(AgentAuthorizationError, match="dispatch"):
            value.dispatch("overseer.default", "blocked prompt", "blocked-key")
        assert store.list_agent_dispatches() == ()


def test_checkpoint_rebinds_untrusted_adapter_identity_to_active_epoch(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    epoch = value.activate("overseer.default", initiated_by="operator")

    checkpoint = value.checkpoint("overseer.default")

    assert checkpoint.driver_epoch_id == epoch.id
    assert checkpoint.session_id == epoch.session_id
    assert store.load_agent_checkpoint(checkpoint.id) == checkpoint


@pytest.mark.parametrize(
    "expires_at",
    (
        "not-a-timestamp",
        "2026-07-29T00:00:00",
        "2026-07-28T23:59:59+00:00",
    ),
)
def test_handoff_rejects_malformed_naive_or_expired_checkpoint(
    tmp_path: Path,
    expires_at: str,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    now = datetime(2026, 7, 29, tzinfo=timezone.utc)
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        value = AgentManager(
            registry,
            store,
            authorization_callback=_allow,
            clock=lambda: now.isoformat(),
        )
        outgoing = value.activate("overseer.default", initiated_by="operator")
        drivers["codex"].checkpoint_expires_at = expires_at

        with pytest.raises(AgentHandoffError, match="checkpoint"):
            value.manual_handoff(
                "overseer.default",
                "claude",
                "operator",
                "approval.checkpoint",
            )

        assert store.load_driver_epoch(outgoing.id).closed_at is None
        assert store.list_agent_handoffs() == ()


def test_handoff_rejects_nontransferable_checkpoint_state(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, drivers, _ = manager
    outgoing = value.activate("overseer.default", initiated_by="operator")
    drivers["codex"].checkpoint_status = "running"

    with pytest.raises(AgentHandoffError, match="transferable"):
        value.manual_handoff(
            "overseer.default", "claude", "operator", "approval.transfer"
        )

    assert store.load_driver_epoch(outgoing.id).closed_at is None


def test_recover_opens_next_epoch_for_persisted_session(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    first = value.activate("overseer.default", initiated_by="operator")
    store.save_driver_epoch(
        replace(
            first,
            state=AgentOperationState.FAILED,
            closed_at="2026-07-29T00:00:00+00:00",
        )
    )

    recovered = value.recover(first.session_id, initiated_by="operator")

    assert recovered.ordinal == first.ordinal + 1
    assert recovered.provider_id == first.provider_id
    assert recovered.session_id == first.session_id
    assert recovered.state is AgentOperationState.RUNNING

    repeated = value.recover(first.session_id, initiated_by="operator")
    assert repeated == recovered
    assert len(
        [
            epoch
            for epoch in store.list_driver_epochs()
            if epoch.instance_id == first.instance_id and epoch.closed_at is None
        ]
    ) == 1


def test_result_binding_mismatch_quarantines_without_overwriting_request(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    epoch = value.activate("overseer.default", initiated_by="operator")
    winner = value.dispatch("overseer.default", "continue", "winner-key")
    before = store.load_agent_dispatch(winner.request_id)
    mismatched = replace(
        winner,
        id="result.mismatched",
        driver_epoch_id="epoch.other",
        evidence={"message_id": "message.late"},
    )

    quarantined = value.record_provider_result(epoch.id, mismatched)

    assert quarantined.state is AgentOperationState.QUARANTINED
    assert quarantined.evidence["reason"] == "dispatch_request_binding_mismatch"
    assert quarantined.evidence["message_id"] == "message.late"
    assert store.load_agent_dispatch(winner.request_id) == before
    assert {result.id for result in store.list_agent_dispatch_results()} == {
        winner.id,
        quarantined.id,
    }


def test_result_and_quarantine_mutations_require_policy_authorization(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, _ = _registry(tmp_path, events)

    def authorize(operation: str, context: Mapping[str, object]) -> bool:
        return operation not in {"record_provider_result", "quarantine_result"}

    with OverseerStore(tmp_path / "state.sqlite3") as store:
        value = AgentManager(registry, store, authorization_callback=authorize)
        epoch = value.activate("overseer.default", initiated_by="operator")
        result = AgentDispatchResult(
            id="result.denied",
            request_id="request.denied",
            instance_id=epoch.instance_id,
            session_id=epoch.session_id,
            driver_epoch_id=epoch.id,
            provider_id=epoch.provider_id,
            state=AgentOperationState.SUCCEEDED,
        )
        with pytest.raises(AgentAuthorizationError, match="record_provider_result"):
            value.record_provider_result(epoch.id, result)
        with pytest.raises(AgentAuthorizationError, match="quarantine_result"):
            value.quarantine_result(result, reason="denied")
        assert store.list_agent_dispatch_results() == ()


def test_handoff_phase_b_failure_preserves_durable_importing_state(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, _ = _registry(tmp_path, events)

    class FailingStore(OverseerStore):
        def save_driver_epoch(self, epoch: object) -> None:
            if getattr(epoch, "closed_at", None) is not None:
                raise RuntimeError("injected final transition failure")
            super().save_driver_epoch(epoch)

    with FailingStore(tmp_path / "state.sqlite3") as store:
        value = AgentManager(registry, store, authorization_callback=_allow)
        outgoing = value.activate("overseer.default", initiated_by="operator")
        with pytest.raises(RuntimeError, match="final transition"):
            value.manual_handoff(
                "overseer.default",
                "claude",
                "operator",
                "approval.rollback",
            )

        assert store.load_driver_epoch(outgoing.id) == outgoing
        assert len(store.list_agent_checkpoints()) == 1
        handoff = store.list_agent_handoffs()[0]
        assert handoff.evidence["status"] == "importing"
        incoming = store.load_driver_epoch(str(handoff.evidence["incoming_epoch_id"]))
        assert incoming.state is AgentOperationState.QUEUED
        assert incoming.closed_at is None
        assert store.list_agent_dispatch_results() == ()
        with pytest.raises(AgentTransitionRequiredError) as transition_required:
            value.recover(outgoing.session_id, initiated_by="operator")
        assert transition_required.value.transition.handoff_id == handoff.id
        assert store.load_driver_epoch(outgoing.id) == outgoing


def test_provider_checkpoint_created_at_controls_freshness(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, drivers, _ = manager
    outgoing = value.activate("overseer.default", initiated_by="operator")
    drivers["codex"].checkpoint_created_at = "2000-01-01T00:00:00+00:00"

    with pytest.raises(AgentHandoffError, match="stale"):
        value.manual_handoff(
            "overseer.default", "claude", "operator", "approval.stale-provider"
        )

    assert store.load_driver_epoch(outgoing.id).closed_at is None


def test_successful_handoff_persists_verified_external_session_identity(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, store, _, _ = manager
    value.activate("overseer.default", initiated_by="operator")
    incoming = value.manual_handoff(
        "overseer.default", "claude", "operator", "approval.external-session"
    )

    session = store.load_agent_session(incoming.session_id)
    assert session.external_session_id == "external.claude.handoff"
    assert not session.external_session_id.startswith("handoff.")
    assert (
        store.load_agent_transition(incoming.instance_id).state
        is AgentTransitionState.COMPLETED
    )


def test_crash_after_external_success_keeps_importing_state_for_reconciliation(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)

    class FailPromotionOnceStore(OverseerStore):
        fail_promotion = True

        def save_driver_epoch(self, epoch: object) -> None:
            if self.fail_promotion and getattr(epoch, "closed_at", None) is not None:
                self.fail_promotion = False
                raise RuntimeError("injected phase B failure")
            super().save_driver_epoch(epoch)

    with FailPromotionOnceStore(tmp_path / "state.sqlite3") as store:
        value = AgentManager(registry, store, authorization_callback=_allow)
        outgoing = value.activate("overseer.default", initiated_by="operator")
        with pytest.raises(RuntimeError, match="phase B"):
            value.manual_handoff(
                "overseer.default", "claude", "operator", "approval.phase-b"
            )

        handoff = store.list_agent_handoffs()[0]
        assert handoff.evidence["status"] == "importing"
        assert store.list_agent_checkpoints()
        assert store.load_driver_epoch(outgoing.id).closed_at is None
        assert drivers["claude"].last_import_result is not None

        incoming = value.reconcile_handoff(
            handoff.id,
            drivers["claude"].last_import_result,
            initiated_by="operator",
        )

        assert incoming.state is AgentOperationState.RUNNING
        assert store.load_driver_epoch(outgoing.id).closed_at is not None


def test_concurrent_activation_reservation_starts_provider_once(tmp_path: Path) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    registry.driver("overseer.default")
    driver = drivers["codex"]
    driver.start_entered = Event()
    driver.start_release = Event()
    path = tmp_path / "state.sqlite3"
    results: list[object] = []
    errors: list[BaseException] = []

    def activate() -> None:
        try:
            with OverseerStore(path) as store:
                manager = AgentManager(registry, store, authorization_callback=_allow)
                results.append(
                    manager.activate("overseer.default", initiated_by="operator")
                )
        except BaseException as error:
            errors.append(error)

    first = Thread(target=activate)
    second = Thread(target=activate)
    first.start()
    assert driver.start_entered.wait(timeout=5)
    second.start()
    time.sleep(0.1)
    driver.start_release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert errors == []
    assert len(results) == 2
    assert results[0] == results[1]
    assert driver.start_calls == 1


def test_blocked_activation_requires_explicit_retry(tmp_path: Path) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"
    driver = registry.driver("overseer.default")
    assert driver is drivers["codex"]
    driver.start_error_count = 1

    with OverseerStore(path) as store:
        manager = AgentManager(
            registry,
            store,
            authorization_callback=_allow,
            activation_wait_seconds=0.05,
        )
        with pytest.raises(RuntimeError, match="transient"):
            manager.activate("overseer.default", initiated_by="operator")
        with pytest.raises(AgentManagerError, match="blocked"):
            manager.activate("overseer.default", initiated_by="operator")
        epoch = manager.activate(
            "overseer.default",
            initiated_by="operator",
            retry_blocked=True,
        )

    assert epoch.state is AgentOperationState.RUNNING
    assert driver.start_calls == 2


def test_stale_activation_owner_can_be_replaced_but_live_owner_cannot(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"
    now = "2026-07-29T12:00:00+00:00"
    with OverseerStore(path) as store:
        assert store.reserve_agent_activation(
            "overseer.default",
            "activation.dead",
            owner_id="manager.dead",
            started_at="2026-07-29T11:00:00+00:00",
            lease_expires_at="2026-07-29T11:01:00+00:00",
            allow_blocked_retry=False,
            observed_at=now,
        )
        manager = AgentManager(
            registry,
            store,
            authorization_callback=_allow,
            clock=lambda: now,
            activation_wait_seconds=0.05,
        )
        epoch = manager.activate("overseer.default", initiated_by="operator")
        reservation = store.load_agent_activation("overseer.default")

    assert epoch.state is AgentOperationState.RUNNING
    assert reservation.owner_id != "manager.dead"
    assert reservation.generation == 2
    assert drivers["codex"].start_calls == 1

    live_path = tmp_path / "live.sqlite3"
    with OverseerStore(live_path) as store:
        assert store.reserve_agent_activation(
            "overseer.default",
            "activation.live",
            owner_id="manager.live",
            started_at=now,
            lease_expires_at="2026-07-29T13:00:00+00:00",
            allow_blocked_retry=False,
            observed_at=now,
        )
        manager = AgentManager(
            registry,
            store,
            authorization_callback=_allow,
            clock=lambda: now,
            activation_wait_seconds=0.05,
        )
        with pytest.raises(AgentManagerError, match="did not complete"):
            manager.activate("overseer.default", initiated_by="operator")

    assert drivers["codex"].start_calls == 1


def test_concurrent_blocked_retry_starts_one_winning_generation(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, drivers = _registry(tmp_path, events)
    path = tmp_path / "state.sqlite3"
    driver = registry.driver("overseer.default")
    assert driver is drivers["codex"]
    driver.start_error_count = 1
    with OverseerStore(path) as store:
        manager = AgentManager(registry, store, authorization_callback=_allow)
        with pytest.raises(RuntimeError, match="transient"):
            manager.activate("overseer.default", initiated_by="operator")

    driver.start_entered = Event()
    driver.start_release = Event()
    results: list[object] = []
    errors: list[BaseException] = []

    def retry() -> None:
        try:
            with OverseerStore(path) as store:
                manager = AgentManager(registry, store, authorization_callback=_allow)
                results.append(
                    manager.activate(
                        "overseer.default",
                        initiated_by="operator",
                        retry_blocked=True,
                    )
                )
        except BaseException as error:
            errors.append(error)

    first = Thread(target=retry)
    second = Thread(target=retry)
    first.start()
    assert driver.start_entered.wait(timeout=5)
    second.start()
    time.sleep(0.1)
    driver.start_release.set()
    first.join(timeout=5)
    second.join(timeout=5)

    assert errors == []
    assert len(results) == 2
    assert results[0] == results[1]
    assert driver.start_calls == 2


def test_registry_provider_specific_resolution_is_typed_and_scoped(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    registry, _ = _registry(tmp_path, events)

    profile = registry.profile_for_provider("overseer.default", "claude")
    driver = registry.driver_for_provider(
        "claude",
        instance_id="overseer.default",
    )

    assert profile.primary_provider_id == "claude"
    assert profile.primary_adapter_id == "claude"
    assert driver.provider == registry.providers["claude"]
    with pytest.raises(ValueError, match="approved"):
        registry.profile_for_provider("overseer.default", "qwen-code")
