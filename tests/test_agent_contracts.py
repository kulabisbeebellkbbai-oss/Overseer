from dataclasses import FrozenInstanceError, replace

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
    AgentTransport,
    DriverEpoch,
    PrimaryDriver,
)


def test_instance_profile_requires_one_primary_provider() -> None:
    with pytest.raises(ValueError, match="primary provider"):
        AgentInstanceProfile(
            id="instance.overseer",
            primary_provider_id="",
            transport=AgentTransport.INTERACTIVE_CLI,
            workspace="/tmp/workspace",
        )


def test_dispatch_requires_epoch_and_idempotency_key() -> None:
    with pytest.raises(ValueError, match="idempotency"):
        AgentDispatchRequest(
            id="dispatch.1",
            instance_id="instance.overseer",
            session_id="session.1",
            driver_epoch_id="epoch.1",
            idempotency_key="",
            prompt="continue",
        )


def test_old_epoch_result_can_be_quarantined_without_losing_evidence() -> None:
    session = AgentSession(
        id="session.1",
        provider_id="codex",
        external_session_id="external.1",
        workspace="/tmp/workspace",
        transport=AgentTransport.INTERACTIVE_CLI,
        capabilities=AgentCapabilities(session_resume=True),
    )
    epoch = DriverEpoch(
        id="epoch.1",
        instance_id="instance.overseer",
        session_id=session.id,
        provider_id=session.provider_id,
        ordinal=1,
        state=AgentOperationState.RUNNING,
    )

    quarantined = replace(epoch, state=AgentOperationState.QUARANTINED)

    assert quarantined.state is AgentOperationState.QUARANTINED
    assert AgentErrorCategory.QUARANTINED.value == "quarantined"


def test_contract_records_are_frozen_and_collections_are_immutable() -> None:
    credential_references = {"provider": "key-provider.codex"}
    profile = AgentInstanceProfile(
        id="instance.overseer",
        primary_provider_id="codex",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/tmp/workspace",
        credential_references=credential_references,
        approved_fallback_provider_ids=("claude",),
    )

    credential_references["provider"] = "changed"

    with pytest.raises(FrozenInstanceError):
        profile.workspace = "/tmp/other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        profile.credential_references["provider"] = "changed"  # type: ignore[index]
    assert profile.credential_references["provider"] == "key-provider.codex"
    assert profile.approved_fallback_provider_ids == ("claude",)


def test_contract_collection_inputs_are_normalized_to_tuples() -> None:
    provider = AgentProvider(
        id="codex",
        adapter_id="codex_cli",
        transports=[AgentTransport.INTERACTIVE_CLI],  # type: ignore[arg-type]
        executable_allowlist=["codex"],  # type: ignore[arg-type]
        profile_ids=["profile.default"],  # type: ignore[arg-type]
    )
    profile = AgentInstanceProfile(
        id="instance.overseer",
        primary_provider_id="codex",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/tmp/workspace",
        approved_fallback_provider_ids=["claude"],  # type: ignore[arg-type]
    )

    assert provider.transports == (AgentTransport.INTERACTIVE_CLI,)
    assert provider.executable_allowlist == ("codex",)
    assert provider.profile_ids == ("profile.default",)
    assert profile.approved_fallback_provider_ids == ("claude",)


def test_capabilities_describe_technical_support_without_granting_policy_access() -> None:
    available = AgentCapabilities(interactive_dispatch=True, checkpoints=True)
    required = AgentCapabilities(interactive_dispatch=True)
    unavailable = AgentCapabilities(handoff_import=True)

    assert available.supports(required)
    assert not available.supports(unavailable)
    assert "permission" not in AgentCapabilities.__dataclass_fields__


def test_primary_driver_protocol_matches_normalized_contract() -> None:
    request = AgentDispatchRequest(
        id="dispatch.1",
        instance_id="instance.overseer",
        session_id="session.1",
        driver_epoch_id="epoch.1",
        idempotency_key="key.1",
        prompt="continue",
    )
    session = AgentSession(
        id=request.session_id,
        provider_id="codex",
        external_session_id="external.1",
        workspace="/tmp/workspace",
        transport=AgentTransport.INTERACTIVE_CLI,
        capabilities=AgentCapabilities(session_resume=True),
    )
    profile = AgentInstanceProfile(
        id=request.instance_id,
        primary_provider_id="codex",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/tmp/workspace",
    )
    result = AgentDispatchResult(
        id="result.1",
        request_id=request.id,
        instance_id=request.instance_id,
        session_id=session.id,
        driver_epoch_id=request.driver_epoch_id,
        provider_id=session.provider_id,
        state=AgentOperationState.ACKNOWLEDGED,
    )
    checkpoint = AgentCheckpoint(
        id="checkpoint.1",
        instance_id=profile.id,
        session_id=session.id,
        driver_epoch_id=request.driver_epoch_id,
    )
    package = AgentHandoffPackage(
        id="handoff.1",
        instance_id=profile.id,
        outgoing_epoch_id=request.driver_epoch_id,
        incoming_provider_id="claude",
        objective="continue",
    )

    class Driver:
        provider = AgentProvider(id="codex", adapter_id="codex_cli")

        def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]:
            return (session,)

        def resolve(self, reference: str) -> AgentSession | None:
            return session if reference == session.id else None

        def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult:
            return result

        def resume(self, session: AgentSession) -> AgentDispatchResult:
            return result

        def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult:
            return result

        def inspect(self, session: AgentSession) -> AgentDispatchResult:
            return result

        def checkpoint(self, session: AgentSession) -> AgentCheckpoint:
            return checkpoint

        def cancel(self, session: AgentSession) -> AgentDispatchResult:
            return result

        def import_handoff(
            self, profile: AgentInstanceProfile, package: AgentHandoffPackage
        ) -> AgentDispatchResult:
            return result

    assert isinstance(Driver(), PrimaryDriver)
