from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
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


def _provider(provider_id: str = "claude", **overrides: object) -> AgentProvider:
    return AgentProvider(
        id=provider_id,
        adapter_id="claude_cli",
        transports=(AgentTransport.INTERACTIVE_CLI,),
        capabilities=AgentCapabilities(session_resume=True, checkpoints=True),
        **overrides,
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
            "SELECT COUNT(*) FROM agent_schema_migrations WHERE version = ?",
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


def test_agent_store_sanitizes_every_record_category_before_writing(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    raw_values = (
        "Bearer provider-raw-secret",
        "sk-live-raw-profile-secret",
        "Bearer session-raw-secret",
        "dispatch-raw-cookie",
        "checkpoint-raw-private-key",
        "handoff-raw-token",
    )
    records = (
        ("provider", _provider(display_name="Bearer provider-raw-secret"), "save_agent_provider"),
        (
            "profile",
            replace(_profile(), model_profile_id="sk-live-raw-profile-secret"),
            "save_agent_instance_profile",
        ),
        (
            "session",
            replace(_session("session.1", "claude"), legacy_references={"authorization": "Bearer session-raw-secret"}),
            "save_agent_session",
        ),
        (
            "dispatch",
            replace(_dispatch("dispatch.1", "epoch.1"), evidence={"cookie": "dispatch-raw-cookie"}),
            "save_agent_dispatch",
        ),
        (
            "checkpoint",
            replace(_checkpoint("checkpoint.1", "epoch.1"), evidence={"private_key": "checkpoint-raw-private-key"}),
            "save_agent_checkpoint",
        ),
        (
            "handoff",
            replace(_handoff("handoff.1", "epoch.1"), evidence={"token": "handoff-raw-token"}),
            "save_agent_handoff",
        ),
    )

    with OverseerStore(path) as store:
        for category, record, method_name in records:
            with pytest.raises(ValueError, match="credential material"):
                getattr(store, method_name)(record)

    database_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    for raw_value in raw_values:
        assert raw_value.encode() not in database_bytes


def test_agent_store_redacts_transcript_fields_in_all_evidence_payloads(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    transcript = "unredacted transcript body"

    with OverseerStore(path) as store:
        session = replace(_session("session.1", "claude"), legacy_references={"transcript": transcript})
        dispatch = replace(_dispatch("dispatch.1", "epoch.1"), evidence={"provider_output": transcript})
        checkpoint = replace(_checkpoint("checkpoint.1", "epoch.1"), evidence={"transcript": transcript})
        handoff = replace(_handoff("handoff.1", "epoch.1"), evidence={"message": transcript})
        store.save_agent_session(session)
        store.save_agent_dispatch(dispatch)
        store.save_agent_checkpoint(checkpoint)
        store.save_agent_handoff(handoff)

        assert store.load_agent_session(session.id).legacy_references["transcript"] == "[redacted agent transcript]"
        assert store.load_agent_dispatch(dispatch.id).evidence["provider_output"] == "[redacted agent transcript]"
        assert store.load_agent_checkpoint(checkpoint.id).evidence["transcript"] == "[redacted agent transcript]"
        assert store.load_agent_handoff(handoff.id).evidence["message"] == "[redacted agent transcript]"

    database_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    assert transcript.encode() not in database_bytes


def test_lifecycle_unique_collisions_and_mutations_preserve_original_history(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        epoch = _epoch("epoch.1", "session.1", ordinal=1)
        store.save_driver_epoch(epoch)
        with pytest.raises(ValueError, match="instance_id and ordinal"):
            store.save_driver_epoch(_epoch("epoch.2", "session.1", ordinal=1))
        assert store.load_driver_epoch(epoch.id) == epoch

        completed = replace(epoch, state=AgentOperationState.SUCCEEDED, closed_at="2026-07-29T00:00:00+00:00")
        store.save_driver_epoch(completed)
        assert store.load_driver_epoch(epoch.id) == completed
        with pytest.raises(ValueError, match="immutable identity"):
            store.save_driver_epoch(replace(completed, provider_id="codex"))
        assert store.load_driver_epoch(epoch.id) == completed

        dispatch = _dispatch("dispatch.1", epoch.id)
        store.save_agent_dispatch(dispatch)
        with pytest.raises(ValueError, match="idempotency key"):
            store.save_agent_dispatch(replace(dispatch, id="dispatch.2"))
        assert store.load_agent_dispatch(dispatch.id).idempotency_key == dispatch.idempotency_key

        store.save_agent_dispatch(replace(dispatch, evidence={"summary": "updated"}))
        assert store.load_agent_dispatch(dispatch.id).evidence == {"summary": "updated"}
        with pytest.raises(ValueError, match="immutable identity"):
            store.save_agent_dispatch(replace(dispatch, driver_epoch_id="epoch.2"))
        assert store.load_agent_dispatch(dispatch.id).driver_epoch_id == epoch.id


def test_existing_integer_schema_migration_rows_and_indexes_are_preserved(tmp_path: Path) -> None:
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
        connection.execute("CREATE INDEX schema_migrations_description_idx ON schema_migrations(description)")
        connection.executemany(
            "INSERT INTO schema_migrations VALUES (?, ?, ?)",
            (
                (10, "tenth migration", "2026-01-10T00:00:00+00:00"),
                (2, "second migration", "2026-01-02T00:00:00+00:00"),
                (1, "first migration", "2026-01-01T00:00:00+00:00"),
            ),
        )

    with OverseerStore(path) as store:
        assert [row.version for row in store.list_schema_migrations()] == [1, 2, 10, "agent_driver_v1"]

    with sqlite3.connect(path) as connection:
        schema = connection.execute("PRAGMA table_info(schema_migrations)").fetchall()
        indexes = connection.execute("PRAGMA index_list(schema_migrations)").fetchall()
        named_count = connection.execute(
            "SELECT COUNT(*) FROM agent_schema_migrations WHERE version = ?",
            ("agent_driver_v1",),
        ).fetchone()[0]

    assert schema[0][2] == "INTEGER"
    assert any(index[1] == "schema_migrations_description_idx" for index in indexes)
    assert named_count == 1


def test_agent_migration_rolls_back_cleanly_and_retries(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"

    class FailingAgentMigrationStore(OverseerStore):
        def _record_agent_schema_migration(self, version: str, description: str) -> None:
            raise RuntimeError("injected agent migration failure")

    with pytest.raises(RuntimeError, match="injected agent migration failure"):
        FailingAgentMigrationStore(path)

    with sqlite3.connect(path) as connection:
        tables_after_failure = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'agent_%'"
            )
        }
    assert tables_after_failure == set()

    with OverseerStore(path) as store:
        assert [row.version for row in store.list_schema_migrations()] == [1, "agent_driver_v1"]
