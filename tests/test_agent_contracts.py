from dataclasses import FrozenInstanceError, replace

import pytest

from overseer.agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    CredentialReference,
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
    old_epoch = DriverEpoch(
        id="epoch.1",
        instance_id="instance.overseer",
        session_id=session.id,
        provider_id=session.provider_id,
        ordinal=1,
        state=AgentOperationState.RUNNING,
    )

    late_evidence = {"provider": {"event": "late output"}}
    old_result = AgentDispatchResult(
        id="result.1",
        request_id="dispatch.1",
        instance_id=old_epoch.instance_id,
        session_id=old_epoch.session_id,
        driver_epoch_id=old_epoch.id,
        provider_id=old_epoch.provider_id,
        state=AgentOperationState.SUCCEEDED,
        evidence=late_evidence,
    )
    quarantined = replace(
        old_result,
        state=AgentOperationState.QUARANTINED,
        error_category=AgentErrorCategory.QUARANTINED,
    )

    late_evidence["provider"]["event"] = "mutated after dispatch"

    assert quarantined.state is AgentOperationState.QUARANTINED
    assert quarantined.driver_epoch_id == old_epoch.id
    assert quarantined.provider_id == old_epoch.provider_id
    assert quarantined.evidence["provider"]["event"] == "late output"
    assert AgentErrorCategory.QUARANTINED.value == "quarantined"


def test_contract_records_are_frozen_and_collections_are_immutable() -> None:
    credential_references = {
        "provider": CredentialReference(id="secret://overseer/codex")
    }
    profile = AgentInstanceProfile(
        id="instance.overseer",
        primary_provider_id="codex",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/tmp/workspace",
        credential_references=credential_references,
        approved_fallback_provider_ids=("claude",),
    )

    credential_references["provider"] = CredentialReference(id="secret://changed")

    with pytest.raises(FrozenInstanceError):
        profile.workspace = "/tmp/other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        profile.credential_references["provider"] = CredentialReference(  # type: ignore[index]
            id="secret://changed"
        )
    assert profile.credential_references["provider"] == CredentialReference(
        id="secret://overseer/codex"
    )
    assert profile.approved_fallback_provider_ids == ("claude",)


@pytest.mark.parametrize(
    "credential_value",
    [
        "Bearer plaintext-token",
        {"secret": "nested plaintext"},
    ],
)
def test_instance_profile_rejects_inline_credential_material(
    credential_value: object,
) -> None:
    with pytest.raises((TypeError, ValueError), match="credential reference"):
        AgentInstanceProfile(
            id="instance.overseer",
            primary_provider_id="codex",
            transport=AgentTransport.INTERACTIVE_CLI,
            workspace="/tmp/workspace",
            credential_references={"provider": credential_value},  # type: ignore[arg-type]
        )


def test_instance_profile_accepts_only_validated_credential_references() -> None:
    profile = AgentInstanceProfile(
        id="instance.overseer",
        primary_provider_id="codex",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/tmp/workspace",
        credential_references={
            "provider": CredentialReference(id="secret://overseer/codex")
        },
    )

    assert profile.credential_references == {
        "provider": CredentialReference(id="secret://overseer/codex")
    }


def test_credential_reference_rejects_non_reference_identifier() -> None:
    with pytest.raises(ValueError, match="credential reference"):
        CredentialReference(id="Bearer plaintext-token")


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


def test_nested_evidence_is_copied_and_recursively_immutable() -> None:
    evidence = {"provider": {"events": ["acknowledged"]}}
    result = AgentDispatchResult(
        id="result.1",
        request_id="dispatch.1",
        instance_id="instance.overseer",
        session_id="session.1",
        driver_epoch_id="epoch.1",
        provider_id="codex",
        state=AgentOperationState.ACKNOWLEDGED,
        evidence=evidence,
    )

    evidence["provider"]["events"].append("mutated")

    assert result.evidence["provider"]["events"] == ("acknowledged",)
    with pytest.raises(TypeError):
        result.evidence["provider"]["events"][0] = "mutated"  # type: ignore[index]


def test_unsupported_result_preserves_provider_attribution() -> None:
    request = AgentDispatchRequest(
        id="dispatch.1",
        instance_id="instance.overseer",
        session_id="session.1",
        driver_epoch_id="epoch.1",
        idempotency_key="key.1",
        prompt="continue",
    )

    result = AgentDispatchResult.unsupported(
        request=request,
        provider_id="codex",
        capability="handoff_import",
    )

    assert result.provider_id == "codex"
    assert result.error_category is AgentErrorCategory.UNSUPPORTED_CAPABILITY


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
