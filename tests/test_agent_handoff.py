from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from overseer.agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    AgentHandoffPackage,
    AgentOperationState,
    DriverEpoch,
)
from overseer.agent_handoff import (
    MAX_HANDOFF_DEPTH,
    MAX_HANDOFF_ITEMS,
    MAX_HANDOFF_STRING_LENGTH,
    AgentHandoffService,
)
from overseer.store import OverseerStore


def _epoch() -> DriverEpoch:
    return DriverEpoch(
        id="epoch.1",
        instance_id="overseer.default",
        session_id="session.1",
        provider_id="codex",
        ordinal=1,
        state=AgentOperationState.RUNNING,
    )


def _checkpoint() -> AgentCheckpoint:
    return AgentCheckpoint(
        id="checkpoint.1",
        instance_id="overseer.default",
        session_id="session.1",
        driver_epoch_id="epoch.1",
        evidence={"status": "ready", "evidence_id": "evidence.1"},
    )


def test_handoff_build_rejects_raw_secret_material_before_store() -> None:
    class StoreSpy:
        save_calls = 0

        def save_agent_handoff(self, package: AgentHandoffPackage) -> None:
            self.save_calls += 1

    store = StoreSpy()
    service = AgentHandoffService(store=store)

    with pytest.raises(ValueError, match="sensitive material"):
        service.build(
            instance_id="overseer.default",
            outgoing_epoch_id="epoch.1",
            incoming_provider_id="claude",
            objective="continue",
            evidence={"nested": {"authorization": "Bearer abc123"}},
            required_capabilities=AgentCapabilities(handoff_import=True),
        )

    assert store.save_calls == 0


@pytest.mark.parametrize(
    "evidence",
    (
        {"token": "plain-value"},
        {"cookie": "plain-value"},
        {"password": "plain-value"},
        {"private key": "plain-value"},
        {"note": "Authorization: Bearer abc123"},
        {"note": "Bearer abc123"},
        {"note": "resolved_secret=abc123"},
        {"note": "-----BEGIN PRIVATE KEY-----"},
    ),
)
def test_handoff_recursively_rejects_sensitive_keys_and_values(
    evidence: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="sensitive material"):
        AgentHandoffService().build(
            instance_id="overseer.default",
            outgoing_epoch_id="epoch.1",
            incoming_provider_id="claude",
            objective="continue",
            evidence=evidence,
            required_capabilities=AgentCapabilities(handoff_import=True),
        )


def test_handoff_build_from_store_persists_safe_bounded_package(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        checkpoint = _checkpoint()
        store.save_agent_checkpoint(checkpoint)
        package = AgentHandoffService(store=store).build_from_store(
            instance_id="overseer.default",
            outgoing_epoch=_epoch(),
            checkpoint=checkpoint,
            incoming_provider_id="claude",
            objective="continue approved work",
            required_capabilities=AgentCapabilities(handoff_import=True),
        )

        assert store.load_agent_handoff(package.id) == package
        assert package.checkpoint_id == checkpoint.id
        assert package.evidence["checkpoint_id"] == checkpoint.id
        assert package.evidence["status"] == "ready"
        assert package.attestation_version == "hmac-sha256-v1"
        assert package.signature


def test_handoff_attestation_survives_restart_and_rejects_forgery(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with OverseerStore(path) as store:
        service = AgentHandoffService(store=store)
        package = service.build(
            instance_id="overseer.default",
            outgoing_epoch_id="epoch.1",
            incoming_provider_id="claude",
            objective="continue",
            evidence={"status": "ready"},
            required_capabilities=AgentCapabilities(handoff_import=True),
        )
        assert service.validate(package, AgentCapabilities(handoff_import=True)) == package

    with OverseerStore(path) as reopened:
        service = AgentHandoffService(store=reopened)
        assert service.validate(package, AgentCapabilities(handoff_import=True)) == package
        for forged in (
            replace(package, objective="tampered"),
            replace(package, signature="0" * 64),
            replace(package, signature=None),
            replace(package, attestation_version=None),
        ):
            with pytest.raises(ValueError, match="attestation"):
                service.validate(forged, AgentCapabilities(handoff_import=True))


def test_handoff_attestation_rejects_foreign_and_unpersisted_packages(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "one.sqlite3") as first:
        package = AgentHandoffService(store=first).build(
            instance_id="overseer.default",
            outgoing_epoch_id="epoch.1",
            incoming_provider_id="claude",
            objective="continue",
            evidence={"status": "ready"},
            required_capabilities=AgentCapabilities(handoff_import=True),
        )
    with OverseerStore(tmp_path / "two.sqlite3") as second:
        with pytest.raises(ValueError, match="attestation"):
            AgentHandoffService(store=second).validate(
                package, AgentCapabilities(handoff_import=True)
            )


def test_handoff_validation_requires_import_and_declared_capabilities() -> None:
    package = AgentHandoffService().build(
        instance_id="overseer.default",
        outgoing_epoch_id="epoch.1",
        incoming_provider_id="claude",
        objective="continue",
        evidence={"status": "ready"},
        required_capabilities=AgentCapabilities(
            checkpoints=True,
            handoff_import=True,
        ),
    )

    with pytest.raises(ValueError, match="handoff_import"):
        AgentHandoffService().validate(
            package,
            AgentCapabilities(checkpoints=True),
        )
    with pytest.raises(ValueError, match="required capabilities"):
        AgentHandoffService().validate(
            package,
            AgentCapabilities(handoff_import=True),
        )

    assert (
        AgentHandoffService().validate(
            package,
            AgentCapabilities(checkpoints=True, handoff_import=True),
        )
        == package
    )


def test_handoff_build_from_store_rejects_mismatched_checkpoint() -> None:
    checkpoint = AgentCheckpoint(
        id="checkpoint.other",
        instance_id="other.instance",
        session_id="session.other",
        driver_epoch_id="epoch.other",
    )

    with pytest.raises(ValueError, match="checkpoint"):
        AgentHandoffService().build_from_store(
            instance_id="overseer.default",
            outgoing_epoch=_epoch(),
            checkpoint=checkpoint,
            incoming_provider_id="claude",
            objective="continue",
            required_capabilities=AgentCapabilities(handoff_import=True),
        )


def test_handoff_accepts_values_at_deterministic_size_boundaries() -> None:
    nested: dict[str, object] = {"status": "x" * MAX_HANDOFF_STRING_LENGTH}
    for index in range(MAX_HANDOFF_DEPTH - 1):
        nested = {f"level_{index}": nested}
    evidence = {f"item_{index}": index for index in range(MAX_HANDOFF_ITEMS - 1)}
    evidence["nested"] = nested

    package = AgentHandoffService().build(
        instance_id="overseer.default",
        outgoing_epoch_id="epoch.1",
        incoming_provider_id="claude",
        objective="x" * MAX_HANDOFF_STRING_LENGTH,
        evidence=evidence,
        required_capabilities=AgentCapabilities(handoff_import=True),
    )

    assert len(package.objective) == MAX_HANDOFF_STRING_LENGTH


@pytest.mark.parametrize(
    ("objective", "evidence", "message"),
    (
        ("x" * (MAX_HANDOFF_STRING_LENGTH + 1), {}, "string size"),
        (
            "continue",
            {"status": "x" * (MAX_HANDOFF_STRING_LENGTH + 1)},
            "string size",
        ),
        (
            "continue",
            {f"item_{index}": index for index in range(MAX_HANDOFF_ITEMS + 1)},
            "item count",
        ),
    ),
)
def test_handoff_rejects_values_beyond_deterministic_bounds(
    objective: str,
    evidence: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        AgentHandoffService().build(
            instance_id="overseer.default",
            outgoing_epoch_id="epoch.1",
            incoming_provider_id="claude",
            objective=objective,
            evidence=evidence,
            required_capabilities=AgentCapabilities(handoff_import=True),
        )


def test_handoff_rejects_excessive_nesting_depth() -> None:
    evidence: dict[str, object] = {"status": "ready"}
    for index in range(MAX_HANDOFF_DEPTH + 1):
        evidence = {f"level_{index}": evidence}

    with pytest.raises(ValueError, match="nesting depth"):
        AgentHandoffService().build(
            instance_id="overseer.default",
            outgoing_epoch_id="epoch.1",
            incoming_provider_id="claude",
            objective="continue",
            evidence=evidence,
            required_capabilities=AgentCapabilities(handoff_import=True),
        )


def test_validate_applies_bounds_to_directly_constructed_package() -> None:
    package = AgentHandoffPackage(
        id="handoff.direct",
        instance_id="overseer.default",
        outgoing_epoch_id="epoch.1",
        incoming_provider_id="claude",
        objective="x" * (MAX_HANDOFF_STRING_LENGTH + 1),
        required_capabilities=AgentCapabilities(handoff_import=True),
    )

    with pytest.raises(ValueError, match="string size"):
        AgentHandoffService().validate(
            package,
            AgentCapabilities(handoff_import=True),
        )
