from __future__ import annotations

import sqlite3
from pathlib import Path

from overseer.agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    AgentDispatchRequest,
    AgentHandoffPackage,
    AgentInstanceProfile,
    AgentOperationState,
    AgentProvider,
    AgentSession,
    AgentTransport,
    CredentialReference,
    DriverEpoch,
)
from overseer.store import OverseerStore


def _provider(provider_id: str = "claude") -> AgentProvider:
    return AgentProvider(
        id=provider_id,
        adapter_id="claude_cli",
        transports=(AgentTransport.INTERACTIVE_CLI,),
        capabilities=AgentCapabilities(session_resume=True, checkpoints=True),
    )


def _profile(instance_id: str = "instance.1") -> AgentInstanceProfile:
    return AgentInstanceProfile(
        id=instance_id,
        primary_provider_id="claude",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/tmp/workspace",
        credential_references={"provider": CredentialReference("secret://overseer/claude")},
    )


def _session(session_id: str, provider_id: str) -> AgentSession:
    return AgentSession(
        id=session_id,
        provider_id=provider_id,
        external_session_id="external.1",
        workspace="/tmp/workspace",
        transport=AgentTransport.INTERACTIVE_CLI,
        capabilities=AgentCapabilities(session_resume=True),
        instance_id="instance.1",
    )


def _epoch(epoch_id: str, session_id: str, *, ordinal: int) -> DriverEpoch:
    return DriverEpoch(
        id=epoch_id,
        instance_id="instance.1",
        session_id=session_id,
        provider_id="claude",
        ordinal=ordinal,
        state=AgentOperationState.RUNNING,
    )


def _dispatch(dispatch_id: str, epoch_id: str) -> AgentDispatchRequest:
    return AgentDispatchRequest(
        id=dispatch_id,
        instance_id="instance.1",
        session_id="session.1",
        driver_epoch_id=epoch_id,
        idempotency_key="key.1",
        prompt="Continue the approved work.",
    )


def _checkpoint(checkpoint_id: str, epoch_id: str) -> AgentCheckpoint:
    return AgentCheckpoint(
        id=checkpoint_id,
        instance_id="instance.1",
        session_id="session.1",
        driver_epoch_id=epoch_id,
        evidence={"completed": "safe summary"},
    )


def _handoff(handoff_id: str, epoch_id: str) -> AgentHandoffPackage:
    return AgentHandoffPackage(
        id=handoff_id,
        instance_id="instance.1",
        outgoing_epoch_id=epoch_id,
        incoming_provider_id="codex",
        objective="Continue approved work.",
        checkpoint_id="checkpoint.1",
    )


def test_agent_records_round_trip(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        provider = _provider()
        profile = _profile()
        session = _session("session.1", "claude")
        epoch = _epoch("epoch.1", session.id, ordinal=1)
        dispatch = _dispatch("dispatch.1", epoch.id)
        checkpoint = _checkpoint("checkpoint.1", epoch.id)
        handoff = _handoff("handoff.1", epoch.id)

        store.save_agent_provider(provider)
        store.save_agent_instance_profile(profile)
        store.save_agent_session(session)
        store.save_driver_epoch(epoch)
        store.save_agent_dispatch(dispatch)
        store.save_agent_checkpoint(checkpoint)
        store.save_agent_handoff(handoff)

        assert store.load_agent_provider(provider.id) == provider
        assert store.load_agent_instance_profile(profile.id) == profile
        assert store.load_agent_session(session.id) == session
        assert store.load_driver_epoch(epoch.id) == epoch
        assert store.load_agent_dispatch(dispatch.id).idempotency_key == "key.1"
        assert store.load_agent_checkpoint(checkpoint.id) == checkpoint
        assert store.load_agent_handoff(handoff.id) == handoff
        assert store.list_agent_providers() == (provider,)
        assert store.list_agent_instance_profiles() == (profile,)
        assert store.list_agent_sessions() == (session,)
        assert store.list_driver_epochs() == (epoch,)
        assert store.list_agent_dispatches()[0].id == dispatch.id
        assert store.list_agent_checkpoints() == (checkpoint,)
        assert store.list_agent_handoffs() == (handoff,)


def test_schema_migration_is_repeatable(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"

    for _ in range(2):
        with OverseerStore(path) as store:
            assert "agent_driver_v1" in {
                row.version for row in store.list_schema_migrations()
            }

    with sqlite3.connect(path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = ?",
            ("agent_driver_v1",),
        ).fetchone()[0]

    assert count == 1


def test_dispatch_payload_excludes_raw_prompt_transcript(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"

    with OverseerStore(path) as store:
        store.save_agent_dispatch(_dispatch("dispatch.1", "epoch.1"))
        assert store.load_agent_dispatch("dispatch.1").prompt == "[redacted dispatch prompt]"

    with sqlite3.connect(path) as connection:
        payload = connection.execute(
            "SELECT payload FROM agent_dispatches WHERE id = ?", ("dispatch.1",)
        ).fetchone()[0]

    assert "Continue the approved work." not in payload


def test_existing_integer_schema_migration_rows_are_preserved(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            (7, "older migration", "2026-01-01T00:00:00+00:00"),
        )

    with OverseerStore(path) as store:
        assert {row.version for row in store.list_schema_migrations()} >= {
            1,
            7,
            "agent_driver_v1",
        }
