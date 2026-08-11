from __future__ import annotations

import json
import os
import sqlite3
import stat
import socket
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

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
    CredentialReference,
    DriverEpoch,
)
from overseer.store import CURRENT_SCHEMA_VERSION, OverseerStore


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
        evidence={"status": "completed", "reason": "safe summary"},
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
        handoff = replace(_handoff("handoff.1", "epoch.1"), evidence={"raw_messages": transcript})
        store.save_agent_session(session)
        store.save_agent_dispatch(dispatch)
        store.save_agent_checkpoint(checkpoint)
        store.save_agent_handoff(handoff)

        assert store.load_agent_session(session.id).legacy_references["transcript"] == "[redacted agent transcript]"
        assert store.load_agent_dispatch(dispatch.id).evidence["provider_output"] == "[redacted agent transcript]"
        assert store.load_agent_checkpoint(checkpoint.id).evidence["transcript"] == "[redacted agent transcript]"
        assert store.load_agent_handoff(handoff.id).evidence["raw_messages"] == "[redacted agent transcript]"

    database_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    assert transcript.encode() not in database_bytes


@pytest.mark.parametrize(
    "transcript_key", ("conversation", "history", "raw_output", "body", "content")
)
def test_agent_store_redacts_normalized_dialogue_fields_without_writing_bytes(
    tmp_path: Path, transcript_key: str
) -> None:
    path = tmp_path / "state.sqlite3"
    transcript = f"unredacted {transcript_key} dialogue"

    with OverseerStore(path) as store:
        checkpoint = replace(
            _checkpoint("checkpoint.1", "epoch.1"), evidence={transcript_key: transcript}
        )
        store.save_agent_checkpoint(checkpoint)
        assert store.load_agent_checkpoint(checkpoint.id).evidence[transcript_key] == (
            "[redacted agent transcript]"
        )

    database_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    assert transcript.encode() not in database_bytes


@pytest.mark.parametrize(
    "credential_key",
    (
        "credential",
        "credentials",
        "secret",
        "client-secret",
        "client_secret_value",
        "password",
        "authorization",
        "cookie",
        "private key",
        "access_key",
        "bearer",
        "token",
    ),
)
def test_agent_store_rejects_normalized_credential_keys_without_writing_bytes(
    tmp_path: Path, credential_key: str
) -> None:
    path = tmp_path / "state.sqlite3"
    raw_value = f"value-for-{credential_key}"

    with OverseerStore(path) as store:
        checkpoint = replace(
            _checkpoint("checkpoint.1", "epoch.1"), evidence={credential_key: raw_value}
        )
        with pytest.raises(ValueError, match="credential material"):
            store.save_agent_checkpoint(checkpoint)

    database_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    assert raw_value.encode() not in database_bytes


def test_agent_store_round_trips_safe_normalized_metadata(tmp_path: Path) -> None:
    metadata = {
        "message_id": "message.1",
        "output_tokens": 12,
        "input_tokens": 8,
        "token_count": 20,
        "usage_units": 3,
        "evidence_id": "evidence.1",
        "evidence_ref": "evidence.ref.1",
        "reference": "reference.1",
        "status": "acknowledged",
        "reason": "provider acknowledged request",
        "hash": "sha256:abc123",
        "captured_at": "2026-07-29T00:00:00+00:00",
        "observed_at": "2026-07-29T00:00:01+00:00",
    }

    with OverseerStore(tmp_path / "state.sqlite3") as store:
        session = replace(_session("session.1", "claude"), legacy_references=metadata)
        dispatch = replace(_dispatch("dispatch.1", "epoch.1"), evidence=metadata)
        checkpoint = replace(_checkpoint("checkpoint.1", "epoch.1"), evidence=metadata)
        handoff = replace(_handoff("handoff.1", "epoch.1"), evidence=metadata)
        store.save_agent_session(session)
        store.save_agent_dispatch(dispatch)
        store.save_agent_checkpoint(checkpoint)
        store.save_agent_handoff(handoff)

        assert dict(store.load_agent_session(session.id).legacy_references) == metadata
        assert dict(store.load_agent_dispatch(dispatch.id).evidence) == metadata
        assert dict(store.load_agent_checkpoint(checkpoint.id).evidence) == metadata
        assert dict(store.load_agent_handoff(handoff.id).evidence) == metadata


@pytest.mark.parametrize(
    ("key", "disposition"),
    (
        ("clientSecret", "reject"),
        ("clientSecretValue", "reject"),
        ("apiKey", "reject"),
        ("accessToken", "reject"),
        ("refreshToken", "reject"),
        ("privateKey", "reject"),
        ("rawOutput", "redact"),
        ("rawMessages", "redact"),
        ("message", "redact"),
        ("messages", "redact"),
        ("output", "redact"),
        ("outputs", "redact"),
    ),
)
def test_agent_store_camel_case_sensitive_evidence_never_reaches_sqlite(
    tmp_path: Path, key: str, disposition: str
) -> None:
    path = tmp_path / "state.sqlite3"
    raw_value = f"raw-value-for-{key}"
    checkpoint = replace(_checkpoint("checkpoint.1", "epoch.1"), evidence={key: raw_value})

    with OverseerStore(path) as store:
        if disposition == "reject":
            with pytest.raises(ValueError, match="credential material"):
                store.save_agent_checkpoint(checkpoint)
        else:
            store.save_agent_checkpoint(checkpoint)
            assert store.load_agent_checkpoint(checkpoint.id).evidence[key] == (
                "[redacted agent transcript]"
            )

    database_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    assert raw_value.encode() not in database_bytes


def test_agent_store_redacts_unknown_evidence_strings_but_keeps_safe_scalars(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    unknown_dialogue = "this is an unclassified free-form dialogue string"
    evidence = {
        "note": unknown_dialogue,
        "nested": {"comment": unknown_dialogue, "exit_code": 0, "available": True},
        "retry_limit": 3,
    }

    with OverseerStore(path) as store:
        checkpoint = replace(_checkpoint("checkpoint.1", "epoch.1"), evidence=evidence)
        store.save_agent_checkpoint(checkpoint)
        loaded = store.load_agent_checkpoint(checkpoint.id).evidence
        assert loaded["note"] == "[redacted agent evidence]"
        assert loaded["nested"]["comment"] == "[redacted agent evidence]"
        assert loaded["nested"]["exit_code"] == 0
        assert loaded["nested"]["available"] is True
        assert loaded["retry_limit"] == 3

    database_bytes = b"".join(
        candidate.read_bytes()
        for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"))
        if candidate.exists()
    )
    assert unknown_dialogue.encode() not in database_bytes


def test_session_profile_and_dispatch_allow_only_explicit_mutable_fields(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        session = _session("session.1", "claude")
        store.save_agent_session(session)
        refreshed_session = replace(
            session,
            capabilities=AgentCapabilities(session_resume=True, structured_events=True),
            legacy_references={"status": "ready", "reason": "refreshed"},
            last_observed_at="2026-07-29T00:00:00+00:00",
        )
        store.save_agent_session(refreshed_session)
        assert store.load_agent_session(session.id) == refreshed_session
        with pytest.raises(ValueError, match="immutable identity"):
            store.save_agent_session(replace(refreshed_session, external_session_id="external.2"))

        profile = _profile()
        store.save_agent_instance_profile(profile)
        refreshed_profile = replace(
            profile, detected_capabilities=AgentCapabilities(session_resume=True)
        )
        store.save_agent_instance_profile(refreshed_profile)
        assert store.load_agent_instance_profile(profile.id) == refreshed_profile
        with pytest.raises(ValueError, match="immutable identity"):
            store.save_agent_instance_profile(replace(refreshed_profile, workspace="/other"))

        dispatch = replace(
            _dispatch("dispatch.1", "epoch.1"),
            requested_at="2026-07-29T00:00:00+00:00",
            requested_by="operator.1",
        )
        store.save_agent_dispatch(dispatch)
        store.save_agent_dispatch(replace(dispatch, evidence={"status": "acknowledged"}))
        assert store.load_agent_dispatch(dispatch.id).evidence == {"status": "acknowledged"}
        with pytest.raises(ValueError, match="immutable identity"):
            store.save_agent_dispatch(replace(dispatch, requested_by="operator.2"))


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

        store.save_agent_dispatch(replace(dispatch, evidence={"reason": "updated"}))
        assert store.load_agent_dispatch(dispatch.id).evidence == {"reason": "updated"}
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
        assert [row.version for row in store.list_schema_migrations()] == [
            1,
            2,
            10,
            "agent_driver_v1",
            "agent_driver_v2",
            "agent_driver_v3",
            "agent_driver_v4",
            "agent_driver_v5",
            "agent_driver_v6",
            "agent_driver_v7",
                "agent_driver_v8",
                "agent_driver_v9",
        ]

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
        assert [row.version for row in store.list_schema_migrations()] == [
            CURRENT_SCHEMA_VERSION,
            "agent_driver_v1",
            "agent_driver_v2",
            "agent_driver_v3",
            "agent_driver_v4",
            "agent_driver_v5",
            "agent_driver_v6",
            "agent_driver_v7",
                "agent_driver_v8",
                "agent_driver_v9",
        ]


def test_dispatch_idempotency_is_scoped_by_instance(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        first = _dispatch("dispatch.1", "epoch.1")
        second = replace(
            first,
            id="dispatch.2",
            instance_id="instance.2",
            session_id="session.2",
            driver_epoch_id="epoch.2",
        )
        store.save_agent_dispatch(first)
        store.save_agent_dispatch(second)

        assert (
            store.load_agent_dispatch_by_idempotency("instance.1", "key.1")
            == replace(first, prompt="[redacted dispatch prompt]")
        )
        assert (
            store.load_agent_dispatch_by_idempotency("instance.2", "key.1")
            == replace(second, prompt="[redacted dispatch prompt]")
        )


def test_legacy_global_dispatch_key_schema_migrates_without_losing_rows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    dispatch = _dispatch("dispatch.legacy", "epoch.legacy")
    payload = json.dumps(
        {
            "id": dispatch.id,
            "instance_id": dispatch.instance_id,
            "session_id": dispatch.session_id,
            "driver_epoch_id": dispatch.driver_epoch_id,
            "idempotency_key": dispatch.idempotency_key,
            "prompt": "[redacted dispatch prompt]",
            "requested_at": None,
            "requested_by": None,
            "evidence": {},
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE agent_dispatches (
                id TEXT PRIMARY KEY,
                driver_epoch_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO agent_dispatches VALUES (?, ?, ?, ?, ?)",
            (
                dispatch.id,
                dispatch.driver_epoch_id,
                dispatch.idempotency_key,
                AgentOperationState.QUEUED.value,
                payload,
            ),
        )

    with OverseerStore(path) as store:
        assert store.load_agent_dispatch(dispatch.id) == replace(
            dispatch, prompt="[redacted dispatch prompt]"
        )
        store.save_agent_dispatch(
            replace(
                dispatch,
                id="dispatch.other",
                instance_id="instance.other",
                session_id="session.other",
                driver_epoch_id="epoch.other",
            )
        )
        versions = {row.version for row in store.list_schema_migrations()}

    assert "agent_driver_v2" in versions


def test_agent_dispatch_results_round_trip_as_distinct_attempts(tmp_path: Path) -> None:
    request = _dispatch("dispatch.1", "epoch.1")
    succeeded = AgentDispatchResult(
        id="result.success",
        request_id=request.id,
        instance_id=request.instance_id,
        session_id=request.session_id,
        driver_epoch_id=request.driver_epoch_id,
        provider_id="claude",
        state=AgentOperationState.SUCCEEDED,
        evidence={"message_id": "message.success", "status": "succeeded"},
    )
    quarantined = replace(
        succeeded,
        id="result.quarantine",
        state=AgentOperationState.QUARANTINED,
        error_category=AgentErrorCategory.QUARANTINED,
        evidence={"message_id": "message.late", "reason": "late_epoch"},
    )

    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_agent_dispatch_result(succeeded)
        store.save_agent_dispatch_result(quarantined)
        assert store.load_agent_dispatch_result(succeeded.id) == succeeded
        assert store.list_agent_dispatch_results() == (quarantined, succeeded)


def test_agent_transaction_rolls_back_all_lifecycle_writes(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        with pytest.raises(RuntimeError, match="injected"):
            with store.agent_transaction():
                store.save_agent_checkpoint(_checkpoint("checkpoint.tx", "epoch.tx"))
                store.save_agent_handoff(_handoff("handoff.tx", "epoch.tx"))
                raise RuntimeError("injected transaction failure")

        assert store.list_agent_checkpoints() == ()
        assert store.list_agent_handoffs() == ()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_store_hardens_new_database_and_sqlite_sidecars_under_public_umask(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    previous = os.umask(0o022)
    try:
        with OverseerStore(path) as store:
            store.save_agent_checkpoint(_checkpoint("checkpoint.mode", "epoch.mode"))
            assert _mode(path) == 0o600
            assert store._connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
            assert store._connection.execute("PRAGMA synchronous").fetchone()[0] == 2
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(f"{path}{suffix}")
                if sidecar.exists():
                    assert _mode(sidecar) == 0o600
    finally:
        os.umask(previous)


def test_store_reopen_hardens_legacy_database_without_touching_other_files(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    unrelated = tmp_path / "unrelated.txt"
    sqlite3.connect(path).close()
    path.chmod(0o644)
    unrelated.write_text("keep", encoding="utf-8")
    unrelated.chmod(0o644)

    with OverseerStore(path):
        assert _mode(path) == 0o600

    assert _mode(unrelated) == 0o644


def test_store_rejects_symlink_database_without_chmodding_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target.sqlite3"
    sqlite3.connect(target).close()
    target.chmod(0o644)
    link = tmp_path / "state.sqlite3"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="regular file"):
        OverseerStore(link)

    assert _mode(target) == 0o644


def test_store_rejects_fifo_promptly_without_reader(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    os.mkfifo(path, 0o644)

    started = time.monotonic()
    with pytest.raises(ValueError, match="regular file"):
        OverseerStore(path)

    assert time.monotonic() - started < 1.0
    assert stat.S_ISFIFO(path.stat().st_mode)
    assert _mode(path) == 0o644


def test_store_rejects_unix_socket_promptly(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    try:
        started = time.monotonic()
        with pytest.raises(ValueError, match="regular file"):
            OverseerStore(path)
        assert time.monotonic() - started < 1.0
        assert stat.S_ISSOCK(path.lstat().st_mode)
    finally:
        listener.close()


def test_store_rejects_replaced_database_without_touching_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    replacement = tmp_path / "replacement.txt"
    store = OverseerStore(path)
    replacement.write_text("unrelated replacement", encoding="utf-8")
    replacement.chmod(0o644)
    os.replace(replacement, path)

    with pytest.raises(ValueError, match="identity changed"):
        store.save_agent_checkpoint(_checkpoint("checkpoint.race", "epoch.race"))
    with pytest.raises(ValueError, match="identity changed"):
        store.close()

    assert path.read_text(encoding="utf-8") == "unrelated replacement"
    assert _mode(path) == 0o644


@pytest.mark.parametrize("suffix", ("-wal", "-shm"))
def test_store_rejects_replaced_sidecar_without_touching_replacement(
    tmp_path: Path, suffix: str
) -> None:
    path = tmp_path / "state.sqlite3"
    store = OverseerStore(path)
    # Never replace a live WAL/SHM file: SQLite may still have it mapped and
    # accessing that mapping after replacement can terminate the process with
    # SIGBUS. Close the mapping, then exercise Overseer's identity detector.
    store._connection.close()
    sidecar = Path(f"{path}{suffix}")
    sidecar.write_bytes(b"owned sqlite sidecar")
    sidecar.chmod(0o600)
    store._harden_database_files()
    replacement = tmp_path / f"replacement{suffix}"
    replacement.write_text("unrelated sidecar", encoding="utf-8")
    replacement.chmod(0o644)
    os.replace(replacement, sidecar)

    with pytest.raises(ValueError, match="identity changed"):
        store._harden_database_files()

    assert sidecar.read_text(encoding="utf-8") == "unrelated sidecar"
    assert _mode(sidecar) == 0o644


def test_store_accepts_owner_only_sidecar_rotation_from_nested_connection(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    outer = OverseerStore(path)
    with OverseerStore(path) as nested:
        nested.save_agent_checkpoint(_checkpoint("checkpoint.nested", "epoch.nested"))

    outer.save_agent_checkpoint(_checkpoint("checkpoint.outer", "epoch.outer"))
    outer.close()

    with OverseerStore(path) as reopened:
        assert reopened.load_agent_checkpoint("checkpoint.nested").id == "checkpoint.nested"
        assert reopened.load_agent_checkpoint("checkpoint.outer").id == "checkpoint.outer"


def test_sidecar_disappearance_during_recheck_is_treated_as_checkpoint_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.sqlite3"
    store = OverseerStore(path)
    store._connection.close()
    sidecar = Path(f"{path}-journal")
    sidecar.write_bytes(b"journal removed by checkpoint")
    sidecar.chmod(0o644)
    original_lstat = Path.lstat
    calls = 0

    def disappear_on_recheck(candidate: Path) -> os.stat_result:
        nonlocal calls
        if candidate == sidecar:
            calls += 1
            if calls == 2:
                raise FileNotFoundError(candidate)
        return original_lstat(candidate)

    monkeypatch.setattr(Path, "lstat", disappear_on_recheck)
    try:
        assert store._inspect_sidecar_and_harden(sidecar, "-journal") is None
    finally:
        sidecar.unlink(missing_ok=True)

    assert calls == 2


def test_store_preserves_integrity_with_concurrent_process_readers_and_writers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with OverseerStore(path):
        pass

    worker = """
import json
import sys
from overseer.store import OverseerStore

path, role, worker_id = sys.argv[1:]
if role == "writer":
    with OverseerStore(path) as store:
        for iteration in range(40):
            resource_id = f"stress.{worker_id}.{iteration}"
            store._connection.execute(
                "INSERT INTO resources (id, payload) VALUES (?, ?)",
                (resource_id, json.dumps({"id": resource_id})),
            )
            store._commit()
            with OverseerStore(path) as nested:
                nested._connection.execute("SELECT COUNT(*) FROM resources").fetchone()
else:
    for iteration in range(40):
        with OverseerStore(path) as store:
            store._connection.execute("SELECT COUNT(*) FROM resources").fetchone()
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", worker, str(path), role, str(worker_id)],
            env={**os.environ, "PYTHONPATH": "src"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for worker_id, role in enumerate(("writer", "writer", "reader", "reader"))
    ]
    failures = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=60)
        if process.returncode != 0:
            failures.append((process.returncode, stdout, stderr))

    assert failures == []
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM resources").fetchone()[0] == 80
