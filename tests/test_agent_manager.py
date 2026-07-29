from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
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
)
from overseer.agent_manager import (
    AgentAuthorizationError,
    AgentHandoffError,
    AgentManager,
    AgentManagerPausedError,
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
        self.import_state = AgentOperationState.ACKNOWLEDGED

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
            evidence={"status": state.value, "message_id": f"message.{request_id}"},
        )

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]:
        return ()

    def resolve(self, reference: str) -> AgentSession | None:
        return None

    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult:
        self.events.append(f"start:{self.provider.id}")
        return self._result(
            request_id=f"activate.{self.provider.id}",
            session_id=f"session.{self.provider.id}",
            epoch_id="pending",
            state=AgentOperationState.ACKNOWLEDGED,
        )

    def resume(self, session: AgentSession) -> AgentDispatchResult:
        self.events.append(f"resume:{self.provider.id}")
        return self._result(
            request_id=f"recover.{self.provider.id}",
            session_id=session.id,
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
            evidence={"status": "ready", "evidence_id": "evidence.checkpoint"},
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
        category = (
            AgentErrorCategory.HANDOFF_INCOMPATIBLE
            if self.import_state is AgentOperationState.FAILED
            else None
        )
        return self._result(
            request_id=f"handoff.{package.id}",
            session_id=f"session.{self.provider.id}",
            epoch_id="provider-owned-untrusted-epoch",
            state=self.import_state,
            error_category=category,
        )


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
    value, _, _, _ = manager
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
    assert store.load_agent_session(epoch.session_id).legacy_references[
        "initiated_by_ref"
    ] == "operator"


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

    with pytest.raises(ValueError, match="different agent instance"):
        value.dispatch("other.instance", "continue", "instance-bound-key")


def test_late_result_from_closed_epoch_is_quarantined(
    manager: tuple[AgentManager, OverseerStore, dict[str, FakeDriver], list[str]],
) -> None:
    value, _, _, _ = manager
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
    assert result.evidence["reason"] == "closed_or_inactive_driver_epoch"


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
    assert events.index("store:handoff") < events.index("factory:claude")
    assert events.index("store:handoff") < events.index("import:claude")
    assert events.index("import:claude") < events.index("store:close-outgoing")


def test_failed_import_leaves_paused_auditable_state_and_outgoing_open(
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
    latest = value.active_epoch("overseer.default")
    assert stored_outgoing.closed_at is None
    assert stored_outgoing.state is AgentOperationState.RUNNING
    assert latest.ordinal == outgoing.ordinal + 1
    assert latest.state is AgentOperationState.BLOCKED
    assert latest.reason == f"handoff_failed:{AgentErrorCategory.HANDOFF_INCOMPATIBLE.value}"
    assert len(store.list_agent_checkpoints()) == 1
    assert store.list_agent_handoffs()[0].evidence == {
        "checkpoint_id": store.list_agent_checkpoints()[0].id,
        "outgoing_epoch_id": outgoing.id,
        "reason": AgentErrorCategory.HANDOFF_INCOMPATIBLE.value,
        "status": AgentOperationState.FAILED.value,
    }
    with pytest.raises(AgentManagerPausedError, match="paused"):
        value.dispatch("overseer.default", "must not run", "paused-key")


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
