from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import overseer.activation_package as activation_package
import overseer.api as overseer_api
from overseer.cli import collection_jobs_status, collection_scheduler_status
from overseer.collection_models import CollectionOutcome
from overseer.collection_scheduler import CollectionScheduler
from overseer.runtime import (
    RUNTIME_ADAPTER_IDS,
    RUNTIME_JOB_ADAPTER_IDS,
    runtime_collection_adapter_registry,
    seed_default_collection_jobs,
)
from overseer.store import SQLiteStore


COMMAND_NAMES = {
    "quiescence": "verify-maintenance-quiescence",
    "preservation": "preserve-maintenance-state",
    "acceptance": "verify-maintenance-acceptance",
}

STORE_NAMES = (
    "overseer-main",
    "psychlo-bridge",
    "roadex-relay",
)

ACCEPTANCE_CHECK_NAMES = (
    "api",
    "authenticated-ui-data",
    "scheduler-freshness",
    "protected-gateway-read",
    "psychlo-read",
    "roadex-read",
    "credentials",
    "single-writer-inventory",
)


def _write(path: Path, contents: bytes, *, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(contents)
    path.chmod(mode)
    return path


def _contract(tmp_path: Path) -> dict[str, Any]:
    source_root = tmp_path / "legacy"
    destination_root = tmp_path / "migrated"
    source_stores = {
        "overseer-main": source_root / "overseer.sqlite3",
        "psychlo-bridge": source_root / "psychlo.sqlite3",
        "roadex-relay": source_root / "roadex.sqlite3",
        "codex-usage": source_root / "codex-usage.sqlite3",
    }
    destinations = {
        name: destination_root / f"{name}.sqlite3"
        for name in STORE_NAMES
    }
    for name, source in source_stores.items():
        _write(source, f"{name}:database".encode())
        _write(Path(f"{source}-wal"), f"{name}:wal".encode())
        _write(Path(f"{source}-shm"), f"{name}:shm".encode())

    preservation_inputs = {
        "currentRelease": _write(source_root / "current-release.txt", b"release"),
        "credentialsDirectory": source_root / "credentials",
        "userUnitsRuntimeEnv": _write(source_root / "runtime.env", b"RUNTIME=sealed\n"),
        "rollbackBundle": source_root / "rollback-bundle",
    }
    preservation_inputs["credentialsDirectory"].mkdir(mode=0o700)
    _write(preservation_inputs["credentialsDirectory"] / "credential", b"opaque")
    preservation_inputs["rollbackBundle"].mkdir(mode=0o700)
    _write(preservation_inputs["rollbackBundle"] / "rollback.unit", b"unit")

    return {
        "storeBindings": [
            {
                "name": name,
                "sourceDb": str(source_stores[name]),
                "destinationDb": str(destinations[name]),
            }
            for name in STORE_NAMES
        ],
        "deferredStoreBindings": [
            {
                "name": "codex-usage",
                "sourceDb": str(source_stores["codex-usage"]),
                "policy": "preserve-and-resume-unchanged",
            }
        ],
        "preservationInputs": {
            key: str(value) for key, value in preservation_inputs.items()
        },
        "evidenceRoot": str(tmp_path / "evidence"),
        "acceptanceChecks": list(ACCEPTANCE_CHECK_NAMES),
    }


def _install_contract_and_command_guard(
    monkeypatch: pytest.MonkeyPatch,
    contract: dict[str, Any],
    *,
    operation: str,
) -> list[str]:
    command_calls: list[str] = []

    monkeypatch.setattr(
        activation_package,
        "_read_maintenance_contract_file",
        lambda _package_root: contract,
        raising=False,
    )
    monkeypatch.setattr(
        activation_package,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    def sealed_command_guard(*args: object, **kwargs: object) -> None:
        command_name = kwargs.get("command_name")
        if command_name is None and args:
            command_name = args[-1]
        command_calls.append(str(command_name))

    monkeypatch.setattr(
        activation_package,
        "_require_maintenance_active_sealed_command",
        sealed_command_guard,
        raising=False,
    )
    monkeypatch.setattr(
        activation_package,
        "_require_active_phase_command",
        lambda *_args, **_kwargs: pytest.fail(
            f"{operation} must not use the legacy cutover/phase guard"
        ),
        raising=False,
    )
    return command_calls


def _artifact_snapshot(root: Path) -> dict[str, tuple[bytes, int, int, int]]:
    snapshot: dict[str, tuple[bytes, int, int, int]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            metadata = path.stat()
            snapshot[str(path.relative_to(root))] = (
                path.read_bytes(),
                metadata.st_dev,
                metadata.st_ino,
                stat.S_IMODE(metadata.st_mode),
            )
    return snapshot


def _bind_source_identities(contract: dict[str, Any]) -> None:
    for binding in [
        *contract["storeBindings"],
        *contract["deferredStoreBindings"],
    ]:
        source = Path(binding["sourceDb"])
        metadata = source.stat()
        parent = source.parent.stat()
        binding["sourceIdentity"] = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "parentDevice": parent.st_dev,
            "parentInode": parent.st_ino,
            "parentMode": stat.S_IMODE(parent.st_mode),
        }


def test_maintenance_preflight_is_read_only_and_checks_every_store_before_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    _bind_source_identities(contract)
    package_root = tmp_path / "package"
    before = _artifact_snapshot(tmp_path)
    calls = _install_contract_and_command_guard(
        monkeypatch, contract, operation="preflight"
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_writer_unit_preflight",
        lambda _baseline: {"overseer.service": {"ActiveState": "active"}},
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_successor_unit_preflight",
        lambda _baseline: {"overseer-runtime.service": {"ActiveState": "inactive"}},
        raising=False,
    )
    monkeypatch.setattr(
        activation_package,
        "MIN_APPROVED_PACKAGE_IMPORT_HEADROOM_BYTES",
        0,
    )
    destination_calls: list[list[object]] = []
    monkeypatch.setattr(
        activation_package,
        "_maintenance_destination_preflight",
        lambda bindings: destination_calls.append(bindings),
    )

    result = activation_package.verify_maintenance_preflight(package_root)

    assert result["status"] == "preflight_passed"
    assert calls == ["verify-maintenance-preflight"]
    assert destination_calls == [contract["storeBindings"]]
    assert _artifact_snapshot(tmp_path) == before


def test_maintenance_preflight_rejects_store_identity_drift_before_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    _bind_source_identities(contract)
    contract["deferredStoreBindings"][0]["sourceIdentity"]["inode"] += 1
    package_root = tmp_path / "package"
    _install_contract_and_command_guard(
        monkeypatch, contract, operation="preflight"
    )

    with pytest.raises(Exception, match="identity drifted"):
        activation_package.verify_maintenance_preflight(package_root)


def test_maintenance_preflight_rejects_store_mode_drift_before_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    _bind_source_identities(contract)
    source = Path(contract["deferredStoreBindings"][0]["sourceDb"])
    source.chmod(0o644)
    package_root = tmp_path / "package"
    _install_contract_and_command_guard(
        monkeypatch, contract, operation="preflight"
    )

    with pytest.raises(Exception, match="identity drifted"):
        activation_package.verify_maintenance_preflight(package_root)


def test_destination_preflight_accepts_exact_empty_dedicated_principal_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_root = tmp_path / "dedicated-principal"
    destination_root.mkdir(mode=0o700)
    destinations = tuple(
        (name, str(destination_root / f"{name}.sqlite3"))
        for name in STORE_NAMES
    )
    bindings = [
        {"name": name, "destinationDb": destination}
        for name, destination in destinations
    ]
    before = _artifact_snapshot(tmp_path)
    monkeypatch.setattr(
        activation_package,
        "MAINTENANCE_STORE_DESTINATIONS",
        destinations,
    )
    monkeypatch.setattr(activation_package, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package, "APPROVED_OVERSEER_GID", os.getegid())

    activation_package._maintenance_destination_preflight(bindings)

    assert _artifact_snapshot(tmp_path) == before


def test_destination_preflight_rejects_existing_sqlite_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_root = tmp_path / "dedicated-principal"
    destination_root.mkdir(mode=0o700)
    destinations = tuple(
        (name, str(destination_root / f"{name}.sqlite3"))
        for name in STORE_NAMES
    )
    bindings = [
        {"name": name, "destinationDb": destination}
        for name, destination in destinations
    ]
    Path(f"{destinations[1][1]}-wal").write_bytes(b"stale")
    monkeypatch.setattr(
        activation_package,
        "MAINTENANCE_STORE_DESTINATIONS",
        destinations,
    )
    monkeypatch.setattr(activation_package, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package, "APPROVED_OVERSEER_GID", os.getegid())

    with pytest.raises(Exception, match="namespace is not empty"):
        activation_package._maintenance_destination_preflight(bindings)


def test_stop_maintenance_writers_includes_optional_coordination_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    _install_contract_and_command_guard(
        monkeypatch, contract, operation="writer stop"
    )
    active = {unit: True for unit in activation_package._MAINTENANCE_WRITER_UNITS}
    observed_command: list[str] = []

    def unit_state(unit: str) -> dict[str, str]:
        return {
            "LoadState": "loaded",
            "ActiveState": "active" if active[unit] else "inactive",
            "UnitFileState": "enabled",
        }

    class Result:
        returncode = 0

    def run(command: list[str], **_kwargs: object) -> Result:
        observed_command.extend(command)
        for unit in active:
            active[unit] = False
        return Result()

    monkeypatch.setattr(activation_package, "_maintenance_user_unit_state", unit_state)
    monkeypatch.setattr(activation_package.subprocess, "run", run)

    result = activation_package.stop_maintenance_writers(package_root)

    assert result["status"] == "writers_stopped"
    assert "overseer-psychlo-coordination-tick.timer" in observed_command
    assert "overseer-codex-usage-mcp.service" in observed_command


def test_maintenance_subprocess_timeout_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*_args: object, **_kwargs: object) -> None:
        raise activation_package.subprocess.TimeoutExpired("sealed", 1)

    monkeypatch.setattr(activation_package.subprocess, "run", timeout)

    with pytest.raises(Exception, match="sealed timeout"):
        activation_package._run_contract_command_with_lock(
            ["/usr/bin/true"],
            lock_descriptor=9,
            timeout_seconds=1,
        )


def test_operator_dashboard_exposes_only_the_short_lived_gateway_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        overseer_api,
        "operator_dashboard_status",
        lambda *_args, **_kwargs: {"role_focus": {"sisko": {}}},
    )
    monkeypatch.setattr(
        overseer_api,
        "_maintenance_gateway_challenge",
        lambda: "a" * 32,
    )

    result = overseer_api._maintenance_operator_dashboard_status(
        "/unused.sqlite3", include_summaries=False
    )

    assert result == {
        "role_focus": {"sisko": {}},
        "maintenance_gateway_challenge": "a" * 32,
    }


def test_gateway_challenge_replaces_only_a_valid_stale_challenge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "run-overseer"
    runtime.mkdir(mode=0o750)
    stale = _write(runtime / "maintenance-gateway-challenge", b"a" * 32 + b"\n")
    stale.chmod(0o444)
    monkeypatch.setattr(
        activation_package,
        "_MAINTENANCE_GATEWAY_CHALLENGE_PATH",
        stale,
    )
    monkeypatch.setattr(
        activation_package,
        "APPROVED_OVERSEER_GID",
        os.getegid(),
    )
    monkeypatch.setattr(
        activation_package,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package.secrets,
        "token_hex",
        lambda _size: "b" * 32,
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "b" * 32)

    assert activation_package._maintenance_gateway_operator_challenge() is True
    assert not stale.exists()


def test_verify_maintenance_quiescence_is_sealed_and_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    before = _artifact_snapshot(tmp_path)
    calls = _install_contract_and_command_guard(
        monkeypatch, contract, operation="quiescence"
    )

    monkeypatch.setattr(
        activation_package,
        "_maintenance_writer_inventory",
        lambda _contract: (),
        raising=False,
    )
    result = activation_package.verify_maintenance_quiescence(package_root)

    assert result["status"] == "quiesced"
    assert calls == [COMMAND_NAMES["quiescence"]]
    assert _artifact_snapshot(tmp_path) == before


def test_writer_inventory_allows_absent_optional_wal_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    for binding in contract["storeBindings"]:
        source = Path(binding["sourceDb"])
        Path(f"{source}-wal").unlink()
        Path(f"{source}-shm").unlink()
    monkeypatch.setattr(
        activation_package,
        "_legacy_inode_activity",
        lambda *_args, **_kwargs: False,
    )

    assert activation_package._maintenance_writer_inventory(contract) == ()


@pytest.mark.parametrize("open_artifact", ["sourceDb", "sourceDb-wal", "sourceDb-shm"])
def test_verify_maintenance_quiescence_rejects_any_open_store_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    open_artifact: str,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    calls = _install_contract_and_command_guard(
        monkeypatch, contract, operation="quiescence"
    )
    first_binding = contract["storeBindings"][0]
    writer_path = (
        first_binding["sourceDb"]
        if open_artifact == "sourceDb"
        else f"{first_binding['sourceDb']}-{open_artifact.rsplit('-', 1)[-1]}"
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_writer_inventory",
        lambda _contract: (writer_path,),
        raising=False,
    )

    with pytest.raises(Exception, match="writer|quiescen|open"):
        activation_package.verify_maintenance_quiescence(package_root)

    assert calls == [COMMAND_NAMES["quiescence"]]


def test_preserve_maintenance_state_copies_triplets_and_artifacts_with_hashes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    calls = _install_contract_and_command_guard(
        monkeypatch, contract, operation="preservation"
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_writer_inventory",
        lambda _contract: (),
        raising=False,
    )

    result = activation_package.preserve_maintenance_state(package_root)
    evidence_root = Path(contract["evidenceRoot"])

    assert result["status"] == "preserved"
    assert calls == [COMMAND_NAMES["preservation"]]
    assert evidence_root.is_dir()
    assert stat.S_IMODE(evidence_root.stat().st_mode) == 0o700
    assert result["directories"]
    for artifact in result["artifacts"]:
        assert Path(artifact["sourcePath"]).is_absolute()
        assert artifact["sourceUid"] == os.geteuid()
        assert artifact["sourceGid"] == os.getegid()
        assert 0 <= artifact["sourceMode"] <= 0o777

    for binding in contract["storeBindings"]:
        source = Path(binding["sourceDb"])
        destination = evidence_root / "stores" / binding["name"] / source.name
        for source_path, destination_path in (
            (source, destination),
            (Path(f"{source}-wal"), Path(f"{destination}-wal")),
            (Path(f"{source}-shm"), Path(f"{destination}-shm")),
        ):
            assert destination_path.read_bytes() == source_path.read_bytes()
            assert stat.S_IMODE(destination_path.stat().st_mode) == 0o600
            assert hashlib.sha256(destination_path.read_bytes()).hexdigest() in json.dumps(
                result, sort_keys=True
            )

    for name, source_text in contract["preservationInputs"].items():
        source = Path(source_text)
        destination = evidence_root / "inputs" / name
        if source.is_dir():
            assert destination.is_dir()
            assert _artifact_snapshot(destination)
        else:
            assert destination.read_bytes() == source.read_bytes()
        assert stat.S_IMODE(destination.stat().st_mode) in {0o600, 0o700}

    original_stable_read = activation_package._stable_read

    def manifest_only_stable_read(path: Path) -> tuple[bytes, os.stat_result]:
        if path.name != "preservation-manifest.json":
            pytest.fail("preserved artifacts must be verified by streaming hash")
        return original_stable_read(path)

    monkeypatch.setattr(
        activation_package,
        "_stable_read",
        manifest_only_stable_read,
    )
    verified = activation_package.verify_maintenance_preservation(package_root)
    assert verified["status"] == "preservation_verified"
    assert calls[-1] == "verify-maintenance-preservation"
    acceptance_report = evidence_root.with_name("acceptance-report.json")
    _write(acceptance_report, b"{}\n")
    assert activation_package.verify_maintenance_preservation(package_root)[
        "status"
    ] == "preservation_verified"

    unexpected_directory = evidence_root / "unexpected-directory"
    unexpected_directory.mkdir()
    with pytest.raises(Exception, match="unexpected artifacts"):
        activation_package.verify_maintenance_preservation(package_root)
    unexpected_directory.rmdir()

    unexpected_fifo = evidence_root / "unexpected-fifo"
    os.mkfifo(unexpected_fifo)
    with pytest.raises(Exception, match="invalid artifact"):
        activation_package.verify_maintenance_preservation(package_root)
    unexpected_fifo.unlink()

    artifact = next(
        path
        for path in evidence_root.rglob("*")
        if path.is_file() and path.name != "preservation-manifest.json"
    )
    artifact.write_bytes(b"drifted")
    with pytest.raises(Exception, match="drifted"):
        activation_package.verify_maintenance_preservation(package_root)


def test_restore_maintenance_handoff_artifacts_restores_exact_files_and_absence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    system_credentials = tmp_path / "system-credentials"
    system_credentials.mkdir(mode=0o700)
    api_token = _write(system_credentials / "api-token", b"original-token")
    new_only = system_credentials / "new-only"
    system_unit = _write(
        tmp_path / "systemd" / "overseer-api.service",
        b"[Service]\nExecStart=/old\n",
        mode=0o644,
    )
    compatibility_token = _write(
        tmp_path / "legacy" / "api-token",
        b"original-compatibility-token",
    )
    contract["preservationInputs"].update(
        {
            "systemCredentialsDirectory": str(system_credentials),
            "systemApiUnit": str(system_unit),
            "compatibilityApiToken": str(compatibility_token),
        }
    )
    _bind_source_identities(contract)
    _install_contract_and_command_guard(
        monkeypatch,
        contract,
        operation="preservation",
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_writer_inventory",
        lambda _contract: (),
    )
    monkeypatch.setattr(
        activation_package,
        "_MAINTENANCE_HANDOFF_CREDENTIAL_DIRECTORY",
        system_credentials,
    )
    monkeypatch.setattr(
        activation_package,
        "_MAINTENANCE_HANDOFF_CREDENTIAL_NAMES",
        ("api-token", "new-only"),
    )
    monkeypatch.setattr(
        activation_package,
        "_MAINTENANCE_HANDOFF_SYSTEM_INPUTS",
        {"systemApiUnit": system_unit},
    )
    monkeypatch.setattr(
        activation_package,
        "_MAINTENANCE_HANDOFF_COMPATIBILITY_INPUTS",
        {"compatibilityApiToken": compatibility_token},
    )

    activation_package.preserve_maintenance_state(package_root)
    api_token.write_bytes(b"replacement-token")
    system_unit.write_bytes(b"[Service]\nExecStart=/new\n")
    compatibility_token.write_bytes(b"replacement-compatibility-token")
    _write(new_only, b"new-only")
    system_credentials.chmod(0o710)
    monkeypatch.setattr(
        activation_package,
        "_require_maintenance_active_rollback_command",
        lambda *_args, **_kwargs: contract,
    )
    monkeypatch.setattr(
        activation_package,
        "_load_maintenance_state",
        lambda: {"stage": "rollback"},
    )

    result = activation_package.restore_maintenance_handoff_artifacts(package_root)

    assert result == {
        "status": "maintenance_handoff_restored",
        "restoredFileCount": 3,
        "removedFileCount": 1,
        "credentialDirectoryMetadataRestored": True,
    }
    assert api_token.read_bytes() == b"original-token"
    assert system_unit.read_bytes() == b"[Service]\nExecStart=/old\n"
    assert compatibility_token.read_bytes() == b"original-compatibility-token"
    assert not new_only.exists()
    assert stat.S_IMODE(system_credentials.stat().st_mode) == 0o700


def test_restore_maintenance_handoff_artifacts_rejects_early_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    monkeypatch.setattr(
        activation_package,
        "_require_maintenance_active_rollback_command",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        activation_package,
        "_load_maintenance_state",
        lambda: {"stage": "earlyRollback"},
    )

    with pytest.raises(Exception, match="full rollback"):
        activation_package.restore_maintenance_handoff_artifacts(package_root)


def test_remove_unpreserved_handoff_rejects_symlink_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "systemd"
    parent.mkdir(mode=0o700)
    target = parent / "overseer-api.service"
    target.symlink_to(tmp_path / "outside")
    monkeypatch.setattr(
        activation_package,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    with pytest.raises(Exception, match="unsafe"):
        activation_package._maintenance_remove_unpreserved_handoff(target)


def test_preserve_maintenance_state_rejects_oversized_evidence_before_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    _install_contract_and_command_guard(
        monkeypatch,
        contract,
        operation="preservation",
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_writer_inventory",
        lambda _contract: (),
    )
    monkeypatch.setattr(
        activation_package,
        "MAX_APPROVED_PACKAGE_IMPORT_BYTES",
        1,
    )

    with pytest.raises(Exception, match="bounded size"):
        activation_package.preserve_maintenance_state(package_root)

    assert not Path(contract["evidenceRoot"]).exists()


@pytest.mark.parametrize("unsafe_setup", ["overwrite", "symlink"])
def test_preserve_maintenance_state_refuses_overwrite_and_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_setup: str,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    evidence_root = Path(contract["evidenceRoot"])
    evidence_root.mkdir(mode=0o700)
    if unsafe_setup == "overwrite":
        destination = evidence_root / "stores" / "overseer-main" / "overseer.sqlite3"
        destination.parent.mkdir(parents=True, mode=0o700)
        destination.write_bytes(b"do-not-overwrite")
    else:
        destination = evidence_root / "stores"
        destination.symlink_to(tmp_path / "legacy", target_is_directory=True)
    _install_contract_and_command_guard(
        monkeypatch, contract, operation="preservation"
    )

    with pytest.raises(Exception, match="overwrite|exists|symlink|unsafe"):
        activation_package.preserve_maintenance_state(package_root)


def test_verify_maintenance_acceptance_uses_only_bounded_injected_checks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    calls = _install_contract_and_command_guard(
        monkeypatch, contract, operation="acceptance"
    )
    checked: list[str] = []
    other_project = tmp_path / "other-project-state.json"
    other_project.write_text("unchanged\n", encoding="utf-8")
    before = other_project.read_bytes()

    def bounded_check(*args: object, **kwargs: object) -> bool:
        check_name = kwargs.get("check_name")
        if check_name is None and args:
            check_name = args[-1]
        checked.append(str(check_name))
        return True

    monkeypatch.setattr(
        activation_package,
        "_run_bounded_maintenance_acceptance_check",
        bounded_check,
        raising=False,
    )
    monkeypatch.setattr(
        activation_package,
        "_execute_contract_command",
        lambda *_args, **_kwargs: pytest.fail(
            "acceptance must not start services, probes, or collectors"
        ),
        raising=False,
    )
    monkeypatch.setattr(
        activation_package.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("acceptance must not use subprocess"),
        raising=False,
    )

    result = activation_package.verify_maintenance_acceptance(package_root)

    assert result["status"] == "accepted"
    assert checked == list(ACCEPTANCE_CHECK_NAMES)
    assert calls == [COMMAND_NAMES["acceptance"]]
    assert other_project.read_bytes() == before
    report = Path(contract["evidenceRoot"]).with_name("acceptance-report.json")
    assert report.is_file()
    assert not (Path(contract["evidenceRoot"]) / "acceptance-report.json").exists()
    assert activation_package.verify_maintenance_acceptance(package_root) == result


def test_real_bounded_acceptance_dispatch_reads_only_allowlisted_projections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = _contract(tmp_path)
    observed: list[tuple[str, bool]] = []
    responses = {
        "/health": {
            "ok": True,
            "service": "overseer-api",
            "psychloBridgeReady": True,
        },
        "/operator-dashboard": {"role_focus": {"sisko": {}}},
        "/collections/status": {
            "status": "ok",
            "job_count": 2,
            "enabled_job_count": 2,
            "load_bounds": {"global_max": 2},
        },
        "/collections/jobs": {
            "status": "ok",
            "jobs": [
                {
                    "id": job_id,
                    "enabled": True,
                    "interval_seconds": 300,
                    "data_age_seconds": 1,
                    "last_outcome": "succeeded",
                }
                for job_id in activation_package._MAINTENANCE_FRESHNESS_JOB_IDS
            ],
        },
        "/Overseer/operator-dashboard": {"role_focus": {"sisko": {}}},
        "/psychlo/status": {"configured": True, "projections": {}},
        "/roadex/human-decisions": {"items": [], "pending_count": 0},
    }

    def api_read(path: str, *, authenticated: bool = True) -> dict[str, object]:
        observed.append((path, authenticated))
        return responses[path]

    monkeypatch.setattr(activation_package, "_maintenance_api_read", api_read)
    monkeypatch.setattr(
        activation_package,
        "_maintenance_gateway_tls_ready",
        lambda: True,
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_gateway_operator_challenge",
        lambda: True,
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_credentials_valid",
        lambda: True,
    )
    monkeypatch.setattr(
        activation_package,
        "_maintenance_single_writer_inventory_valid",
        lambda _contract: True,
    )

    assert all(
        activation_package._run_bounded_maintenance_acceptance_check(
            contract,
            check_name=name,
        )
        is True
        for name in ACCEPTANCE_CHECK_NAMES
    )
    assert observed == [
        ("/health", False),
        ("/operator-dashboard", True),
        ("/collections/status", True),
        ("/collections/jobs", True),
        ("/psychlo/status", True),
        ("/roadex/human-decisions", True),
    ]


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing", "job=collection.freshness.psychlo-usage reason=missing"),
        ("disabled", "job=collection.freshness.psychlo-usage reason=disabled"),
        ("unsuccessful", "job=collection.freshness.psychlo-usage reason=unsuccessful"),
        ("invalid-interval", "job=collection.freshness.psychlo-usage reason=invalid-interval"),
        ("missing-age", "job=collection.freshness.psychlo-usage reason=missing-age"),
        ("non-finite-age", "job=collection.freshness.psychlo-usage reason=missing-age"),
        ("stale", "job=collection.freshness.psychlo-usage reason=stale"),
    ],
)
def test_scheduler_acceptance_returns_exact_bounded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
    expected: str,
) -> None:
    jobs = [
        {
            "id": job_id,
            "enabled": True,
            "interval_seconds": 300,
            "data_age_seconds": 1,
            "last_outcome": "succeeded",
        }
        for job_id in activation_package._MAINTENANCE_FRESHNESS_JOB_IDS
    ]
    target = next(
        item
        for item in jobs
        if item["id"] == "collection.freshness.psychlo-usage"
    )
    if mutation == "missing":
        jobs.remove(target)
    elif mutation == "disabled":
        target["enabled"] = False
    elif mutation == "unsuccessful":
        target["last_outcome"] = "failed"
    elif mutation == "invalid-interval":
        target["interval_seconds"] = 0
    elif mutation == "missing-age":
        target["data_age_seconds"] = None
    elif mutation == "non-finite-age":
        target["data_age_seconds"] = float("nan")
    else:
        target["data_age_seconds"] = 601

    responses = {
        "/collections/status": {
            "status": "ok",
            "job_count": len(jobs),
            "enabled_job_count": len(jobs),
            "load_bounds": {"global_max": 2},
        },
        "/collections/jobs": {"status": "ok", "jobs": jobs},
    }
    monkeypatch.setattr(
        activation_package,
        "_maintenance_api_read",
        lambda path, **_kwargs: responses[path],
    )

    result = activation_package._run_bounded_maintenance_acceptance_check(
        _contract(tmp_path),
        check_name="scheduler-freshness",
    )

    assert result == expected


def test_maintenance_acceptance_surfaces_bounded_scheduler_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    contract = _contract(tmp_path)
    monkeypatch.setattr(
        activation_package,
        "_require_maintenance_active_sealed_command",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package,
        "_read_maintenance_contract_file",
        lambda _package: contract,
    )
    monkeypatch.setattr(
        activation_package,
        "_run_bounded_maintenance_acceptance_check",
        lambda _contract, *, check_name: (
            "job=collection.git.overseer reason=stale"
            if check_name == "scheduler-freshness"
            else True
        ),
    )

    with pytest.raises(
        activation_package.ActivationPackageError,
        match=(
            "maintenance acceptance check failed: scheduler-freshness: "
            "job=collection.git.overseer reason=stale"
        ),
    ):
        activation_package.verify_maintenance_acceptance(package)


def test_dedicated_bridge_jobs_pass_acceptance_with_real_scheduler_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store_path = tmp_path / "authority.sqlite3"
    monkeypatch.setenv("OVERSEER_DEDICATED_PRINCIPAL", "1")
    seed_default_collection_jobs(store_path)
    required = set(activation_package._MAINTENANCE_FRESHNESS_JOB_IDS)
    bridge_jobs = {
        "collection.freshness.psychlo-usage",
        "collection.freshness.quark-scheduler",
        "collection.git.overseer",
    }
    now = datetime.now(UTC).isoformat()
    with SQLiteStore(store_path) as store:
        for job in store.list_collection_jobs():
            store.save_collection_job(replace(job, enabled=job.id in required))
            state = store.load_collection_job_state(job.id)
            if job.id in required - bridge_jobs:
                state = replace(
                    state,
                    next_due_at="2999-01-01T00:00:00+00:00",
                    last_started_at=now,
                    last_completed_at=now,
                    last_outcome=CollectionOutcome.SUCCEEDED,
                )
            elif job.id in bridge_jobs:
                state = replace(state, next_due_at="2000-01-01T00:00:00+00:00")
            store.save_collection_job_state(state)

    class Bridge:
        def call(self, method: str, request_id: str) -> dict[str, object]:
            if method == "overseer.scheduler.freshness.v1":
                projection: dict[str, object] = {
                    "state": "available",
                    "observed_at": now,
                    "services": [
                        {
                            "job_id": "collection.freshness.psychlo-usage",
                            "outcome": "succeeded",
                            "evidence_id": "freshness.psychlo-usage",
                        },
                        {
                            "job_id": "collection.freshness.quark-scheduler",
                            "outcome": "succeeded",
                            "evidence_id": "freshness.quark-scheduler",
                        },
                    ],
                }
            else:
                assert method == "overseer.git.status.v1"
                projection = {
                    "state": "available",
                    "observed_at": now,
                    "git": {
                        "repository": "overseer",
                        "branch": "main",
                        "head": "c" * 40,
                        "short_head": "c" * 7,
                        "upstream": "origin/main",
                        "ahead": 0,
                        "behind": 0,
                        "dirty": False,
                        "changed": 0,
                        "staged": 0,
                        "unstaged": 0,
                        "untracked": 0,
                        "conflicted": 0,
                        "remote_owner": "example",
                        "remote_repo": "overseer",
                    },
                }
            return {
                "protocol": "overseer.user-bridge.v1",
                "request_id": request_id,
                "method": method,
                "status": "ok",
                "projection": projection,
            }

    scheduler = CollectionScheduler(
        str(store_path),
        adapter_registry=runtime_collection_adapter_registry(user_bridge_client=Bridge()),
        adapter_ids={**RUNTIME_ADAPTER_IDS, **RUNTIME_JOB_ADAPTER_IDS},
    )
    try:
        cycles = [scheduler.run_ready_once() for _job_id in bridge_jobs]
    finally:
        scheduler.shutdown()
    assert [cycle.succeeded for cycle in cycles] == [1, 1, 1]

    responses = {
        "/collections/status": collection_scheduler_status(store_path),
        "/collections/jobs": collection_jobs_status(store_path),
    }
    monkeypatch.setattr(
        activation_package,
        "_maintenance_api_read",
        lambda path, **_kwargs: responses[path],
    )

    assert (
        activation_package._run_bounded_maintenance_acceptance_check(
            _contract(tmp_path),
            check_name="scheduler-freshness",
        )
        is True
    )


def test_maintenance_api_read_uses_a_bounded_dashboard_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import overseer.client as client_module

    clients: list[tuple[str | None, float, int]] = []
    reads: list[tuple[str, bool]] = []

    class FakeClient:
        def __init__(
            self,
            *,
            auth_token_file: str | None,
            timeout_seconds: float,
            max_response_bytes: int,
        ) -> None:
            clients.append(
                (auth_token_file, timeout_seconds, max_response_bytes)
            )

        def _get(
            self,
            path: str,
            *,
            authenticated: bool = True,
        ) -> dict[str, object]:
            reads.append((path, authenticated))
            return {"ok": True}

    monkeypatch.setattr(client_module, "OverseerApiClient", FakeClient)

    assert activation_package._maintenance_api_read(
        "/health", authenticated=False
    ) == {"ok": True}
    assert activation_package._maintenance_api_read("/operator-dashboard") == {
        "ok": True
    }

    assert clients == [
        (None, 5.0, activation_package.MAX_MAINTENANCE_API_RESPONSE_BYTES),
        (
            "/etc/overseer/api-token",
            60.0,
            activation_package.MAX_MAINTENANCE_API_RESPONSE_BYTES,
        ),
    ]
    assert reads == [
        ("/health", False),
        ("/operator-dashboard", True),
    ]


def test_maintenance_api_read_enforces_one_end_to_end_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import overseer.client as client_module

    class TricklingClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def _get(self, _path: str, *, authenticated: bool = True) -> object:
            del authenticated
            while True:
                time.sleep(0.01)

    monkeypatch.setattr(client_module, "OverseerApiClient", TricklingClient)
    monkeypatch.setattr(
        activation_package,
        "MAINTENANCE_API_TIMEOUT_SECONDS",
        0.05,
    )

    started = time.monotonic()
    with pytest.raises(
        activation_package.ActivationPackageError,
        match="maintenance acceptance API read failed",
    ):
        activation_package._maintenance_api_read("/health", authenticated=False)
    assert time.monotonic() - started < 1.0


def test_successor_user_unit_inventory_checks_the_complete_writer_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        "overseer-psychlo-coordination-tick.timer": ("not-found", "inactive", ""),
        "overseer-psychlo-usage.timer": ("loaded", "inactive", "disabled"),
        "overseer-quark-scheduler.timer": ("loaded", "active", "enabled"),
        "overseer-codex-usage-snapshot.timer": ("loaded", "active", "enabled"),
        "overseer-psychlo-coordination-tick.service": ("not-found", "inactive", ""),
        "overseer-psychlo-cycle.service": ("loaded", "inactive", "static"),
        "overseer-psychlo-meter.service": ("loaded", "inactive", "static"),
        "overseer-psychlo-usage.service": ("loaded", "inactive", "static"),
        "overseer-quark-scheduler.service": ("loaded", "inactive", "static"),
        "overseer-codex-usage-snapshot.service": ("loaded", "inactive", "static"),
        "overseer-codex-usage-mcp.service": ("loaded", "active", "enabled"),
        "overseer-api.service": ("loaded", "inactive", "disabled"),
        "overseer.service": ("loaded", "inactive", "disabled"),
    }

    def state(unit: str) -> dict[str, str]:
        load, active, unit_file = expected[unit]
        return {
            "LoadState": load,
            "ActiveState": active,
            "UnitFileState": unit_file,
        }

    monkeypatch.setattr(activation_package, "_maintenance_user_unit_state", state)

    assert activation_package._maintenance_success_user_unit_inventory_valid() is True

    expected["overseer-api.service"] = ("loaded", "active", "disabled")
    assert activation_package._maintenance_success_user_unit_inventory_valid() is False


@pytest.mark.parametrize("failed_check", ACCEPTANCE_CHECK_NAMES)
def test_verify_maintenance_acceptance_requires_every_named_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_check: str,
) -> None:
    contract = _contract(tmp_path)
    package_root = tmp_path / "package"
    calls = _install_contract_and_command_guard(
        monkeypatch, contract, operation="acceptance"
    )

    def bounded_check(*args: object, **kwargs: object) -> bool:
        check_name = kwargs.get("check_name")
        if check_name is None and args:
            check_name = args[-1]
        return str(check_name) != failed_check

    monkeypatch.setattr(
        activation_package,
        "_run_bounded_maintenance_acceptance_check",
        bounded_check,
        raising=False,
    )

    with pytest.raises(Exception, match="acceptance|check|failed"):
        activation_package.verify_maintenance_acceptance(package_root)

    assert calls == [COMMAND_NAMES["acceptance"]]
