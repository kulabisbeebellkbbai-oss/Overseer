from __future__ import annotations

import os
import pwd
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path

import pytest
import overseer.activation_package as activation_package_module

from overseer.activation_package import ActivationPackageError


def _create_sqlite_store(path: Path, *, table: str = "retained_items") -> dict[str, bytes]:
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute(
            f"CREATE TABLE {table}(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.executemany(
            f"INSERT INTO {table}(value) VALUES (?)",
            [("one",), ("two",), ("three",)],
        )
        connection.commit()
        wal = Path(f"{path}-wal").read_bytes()
        shm = Path(f"{path}-shm").read_bytes()
    finally:
        connection.close()

    # Closing the last WAL connection checkpoints and removes its sidecars.
    # Restore the captured, valid sidecars so the test exercises preservation of
    # all three legacy authority artifacts without leaving a writer open.
    Path(f"{path}-wal").write_bytes(wal)
    Path(f"{path}-shm").write_bytes(shm)
    path.chmod(0o600)
    Path(f"{path}-wal").chmod(0o600)
    Path(f"{path}-shm").chmod(0o600)
    return {
        "store": path.read_bytes(),
        "wal": wal,
        "shm": shm,
    }


def _source_args(
    tmp_path: Path,
    source: Path,
    *,
    store_kind: str,
    destination_uid: int | None = None,
    destination_gid: int | None = None,
) -> dict[str, object]:
    source_metadata = source.stat()
    parent_metadata = source.parent.stat()
    return {
        "package_root": tmp_path / "package",
        "source_store": source,
        "backup_store": tmp_path / "isolated-backup" / "backup.sqlite3",
        "destination_store": tmp_path / "destination" / "store.sqlite3",
        "expected_source_device": source_metadata.st_dev,
        "expected_source_inode": source_metadata.st_ino,
        "expected_source_uid": source_metadata.st_uid,
        "expected_source_gid": source_metadata.st_gid,
        "expected_parent_device": parent_metadata.st_dev,
        "expected_parent_inode": parent_metadata.st_ino,
        "expected_parent_mode": stat.S_IMODE(parent_metadata.st_mode),
        "destination_uid": os.getuid() if destination_uid is None else destination_uid,
        "destination_gid": os.getgid() if destination_gid is None else destination_gid,
        "store_kind": store_kind,
    }


def _install_guard_seams(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_parent_lock_mode",
        lambda: 0o700,
    )
    calls: list[dict[str, object]] = []

    def maintenance_guard(*args: object, **kwargs: object) -> None:
        calls.append({"args": args, "kwargs": kwargs})

    monkeypatch.setattr(
        activation_package_module,
        "_require_maintenance_active_sealed_command",
        maintenance_guard,
        raising=False,
    )

    def cutover_guard(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("maintenance storage copy must not use the cutover phase guard")

    monkeypatch.setattr(
        activation_package_module,
        "_require_active_phase_command",
        cutover_guard,
    )
    return calls


def _prepare(**kwargs: object) -> dict[str, object]:
    return activation_package_module.prepare_maintenance_store_copy(**kwargs)


def test_copy_store_accepts_an_existing_exact_non_executor_destination_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"sealed backup")
    source.chmod(0o600)
    destination_parent = tmp_path / "dedicated-principal"
    destination_parent.mkdir(mode=0o700)
    destination = destination_parent / "overseer.sqlite3"
    expected_uid = destination_parent.stat().st_uid
    expected_gid = destination_parent.stat().st_gid
    source_metadata = source.stat()

    monkeypatch.setattr(
        activation_package_module,
        "_validate_store_artifact",
        lambda *_args, **_kwargs: source_metadata,
    )
    monkeypatch.setattr(
        activation_package_module.os,
        "geteuid",
        lambda: expected_uid + 1,
    )
    monkeypatch.setattr(
        activation_package_module.os,
        "getegid",
        lambda: expected_gid + 1,
    )

    activation_package_module._copy_store(
        source,
        destination,
        destination_uid=expected_uid,
        destination_gid=expected_gid,
    )

    assert destination.read_bytes() == b"sealed backup"


def test_destination_namespace_lock_restores_mode_when_owner_change_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_parent = tmp_path / "dedicated-principal"
    destination_parent.mkdir(mode=0o700)
    metadata = destination_parent.stat()

    def fail_owner_change(_descriptor: int, _uid: int, _gid: int) -> None:
        raise OSError("injected owner-change failure")

    monkeypatch.setattr(activation_package_module.os, "fchown", fail_owner_change)

    with pytest.raises(OSError, match="injected owner-change failure"):
        activation_package_module._lock_migration_destination_directory(
            destination_parent,
            destination_uid=metadata.st_uid,
            destination_gid=metadata.st_gid,
            executor_uid=metadata.st_uid,
            executor_gid=metadata.st_gid,
        )

    restored = destination_parent.stat()
    assert (restored.st_uid, restored.st_gid) == (metadata.st_uid, metadata.st_gid)
    assert stat.S_IMODE(restored.st_mode) == 0o700


def _schema_and_counts(path: Path) -> tuple[list[tuple[object, ...]], dict[str, int]]:
    connection = sqlite3.connect(path)
    try:
        schema = connection.execute(
            "SELECT type, name, sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        counts = {
            str((table_name := row[0])): int(
                connection.execute(f"SELECT COUNT(*) FROM \"{table_name}\"").fetchone()[0]
            )
            for row in tables
        }
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    return schema, counts


def test_maintenance_copy_uses_maintenance_guard_and_preserves_authority_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    original = _create_sqlite_store(source)
    source_identity = (source.stat().st_dev, source.stat().st_ino)
    calls = _install_guard_seams(monkeypatch)

    report = _prepare(**_source_args(tmp_path, source, store_kind="overseer"))

    assert report["status"] == "maintenance_store_copy_complete"
    assert calls and calls[0]["kwargs"]["command_name"] == "prepare-maintenance-store-copy"
    assert (source.stat().st_dev, source.stat().st_ino) == source_identity
    assert source.read_bytes() == original["store"]
    assert Path(f"{source}-wal").read_bytes() == original["wal"]
    assert Path(f"{source}-shm").read_bytes() == original["shm"]


def test_maintenance_copy_runs_sqlite_store_migration_only_for_overseer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    calls = _install_guard_seams(monkeypatch)
    real_store = activation_package_module.SQLiteStore
    migrated_paths: list[Path] = []

    class RecordingStore:
        def __init__(self, path: Path) -> None:
            migrated_paths.append(Path(path))
            self._store = real_store(path)

        def close(self) -> None:
            self._store.close()

    monkeypatch.setattr(activation_package_module, "SQLiteStore", RecordingStore)
    args = _source_args(tmp_path, source, store_kind="overseer")

    _prepare(**args)

    assert migrated_paths == [Path(args["destination_store"])]
    assert calls
    destination = Path(args["destination_store"])
    assert destination.stat().st_uid == os.getuid()
    assert destination.stat().st_gid == os.getgid()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert _schema_and_counts(destination)[1]["retained_items"] == 3


def test_maintenance_copy_seals_destination_without_executor_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    args = _source_args(tmp_path, source, store_kind="overseer")

    _prepare(**args)

    destination = Path(args["destination_store"])
    with sqlite3.connect(f"file:{destination}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()


def test_root_maintenance_copy_removes_root_sidecars_before_principal_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the real ownership transition")
    try:
        account = pwd.getpwnam("overseer")
    except KeyError:
        pytest.skip("requires the dedicated overseer account")

    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    destination = tmp_path / "destination" / "overseer.sqlite3"
    destination.parent.mkdir(mode=0o700)
    os.chown(destination.parent, account.pw_uid, account.pw_gid)
    args = _source_args(
        tmp_path,
        source,
        store_kind="overseer",
        destination_uid=account.pw_uid,
        destination_gid=account.pw_gid,
    )
    args["destination_store"] = destination
    real_store = activation_package_module.SQLiteStore
    executor_sidecar_owners: list[tuple[int, int]] = []

    class RootMigrationStore:
        def __init__(self, path: Path) -> None:
            self._store = real_store(path)
            for suffix in ("-wal", "-shm"):
                metadata = Path(f"{path}{suffix}").stat()
                executor_sidecar_owners.append((metadata.st_uid, metadata.st_gid))

        def close(self) -> None:
            self._store.close()

    monkeypatch.setattr(
        activation_package_module,
        "SQLiteStore",
        RootMigrationStore,
    )

    _prepare(**args)

    assert executor_sidecar_owners == [(0, 0), (0, 0)]
    assert (destination.stat().st_uid, destination.stat().st_gid) == (
        account.pw_uid,
        account.pw_gid,
    )
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()


def test_root_maintenance_copy_locks_destination_namespace_through_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the real ownership boundary")
    try:
        account = pwd.getpwnam("overseer")
    except KeyError:
        pytest.skip("requires the dedicated overseer account")

    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    destination = tmp_path / "destination" / "overseer.sqlite3"
    destination.parent.mkdir(mode=0o700)
    os.chown(destination.parent, account.pw_uid, account.pw_gid)
    args = _source_args(
        tmp_path,
        source,
        store_kind="overseer",
        destination_uid=account.pw_uid,
        destination_gid=account.pw_gid,
    )
    args["destination_store"] = destination
    real_evidence = activation_package_module._migration_evidence
    observed_parent: list[tuple[int, int, int]] = []

    def introduce_foreign_sidecar(
        path: Path,
        *,
        counted_tables: tuple[str, ...] | None = None,
    ) -> tuple[dict[str, int], dict[str, object]]:
        result = real_evidence(path, counted_tables=counted_tables)
        if Path(path) == destination:
            metadata = destination.parent.stat()
            observed_parent.append(
                (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
            )
            sidecar = Path(f"{path}-wal")
            sidecar.write_bytes(b"foreign handoff sidecar")
            sidecar.chmod(0o600)
            os.chown(sidecar, account.pw_uid, account.pw_gid)
        return result

    monkeypatch.setattr(
        activation_package_module,
        "_migration_evidence",
        introduce_foreign_sidecar,
    )

    with pytest.raises(ActivationPackageError, match="before ownership handoff"):
        _prepare(**args)

    assert observed_parent == [(0, 0, 0o700)]
    foreign_sidecar = Path(f"{destination}-wal")
    assert foreign_sidecar.exists()
    assert (foreign_sidecar.stat().st_uid, foreign_sidecar.stat().st_gid) == (
        account.pw_uid,
        account.pw_gid,
    )
    assert (destination.parent.stat().st_uid, destination.parent.stat().st_gid) == (
        account.pw_uid,
        account.pw_gid,
    )
    foreign_sidecar.unlink()


def test_maintenance_copy_rechecks_sidecars_immediately_before_owner_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    args = _source_args(tmp_path, source, store_kind="overseer")
    destination = Path(args["destination_store"])
    real_evidence = activation_package_module._migration_evidence

    def introduce_late_sidecar(
        path: Path,
        *,
        counted_tables: tuple[str, ...] | None = None,
    ) -> tuple[dict[str, int], dict[str, object]]:
        result = real_evidence(path, counted_tables=counted_tables)
        if Path(path) == destination:
            sidecar = Path(f"{path}-wal")
            sidecar.write_bytes(b"late executor sidecar")
            sidecar.chmod(0o600)
        return result

    monkeypatch.setattr(
        activation_package_module,
        "_migration_evidence",
        introduce_late_sidecar,
    )

    with pytest.raises(ActivationPackageError, match="before ownership handoff"):
        _prepare(**args)

    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()


def test_migration_sidecar_cleanup_preserves_nonexecutor_artifacts(
    tmp_path: Path,
) -> None:
    sidecar = tmp_path / "destination.sqlite3-wal"
    sidecar.write_bytes(b"foreign sidecar")
    sidecar.chmod(0o600)

    removed = activation_package_module._remove_executor_migration_sidecars(
        (sidecar,),
        executor_uid=os.geteuid() + 1,
        executor_gid=os.getegid() + 1,
    )

    assert removed == []
    assert sidecar.read_bytes() == b"foreign sidecar"


def test_maintenance_copy_preserves_copy_only_schema_and_rows_without_store_migration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "roadex-relay.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source, table="relay_events")
    calls = _install_guard_seams(monkeypatch)
    before_schema, before_counts = _schema_and_counts(source)
    for suffix in ("-wal", "-shm"):
        try:
            Path(f"{source}{suffix}").unlink()
        except FileNotFoundError:
            pass

    def forbidden_store(_path: Path) -> None:
        raise AssertionError("copy-only sidecars must not run SQLiteStore migration")

    monkeypatch.setattr(activation_package_module, "SQLiteStore", forbidden_store)
    args = _source_args(tmp_path, source, store_kind="copy-only")

    _prepare(**args)

    destination = Path(args["destination_store"])
    after_schema, after_counts = _schema_and_counts(destination)
    assert after_schema == before_schema
    assert after_counts == before_counts
    assert calls


def test_copy_only_store_uses_the_kernel_lease_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "roadex-relay.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source, table="relay_events")
    _install_guard_seams(monkeypatch)
    lease_calls: list[int] = []

    @contextmanager
    def lease_barrier(descriptors: tuple[int, ...]):
        lease_calls.append(len(descriptors))
        yield lambda: None

    monkeypatch.setattr(
        activation_package_module,
        "_kernel_read_lease_barrier",
        lease_barrier,
    )

    _prepare(**_source_args(tmp_path, source, store_kind="copy-only"))

    assert lease_calls and lease_calls[0] >= 1


def test_maintenance_copy_rejects_an_open_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    writer = sqlite3.connect(source)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("INSERT INTO retained_items(value) VALUES ('uncommitted')")
        with pytest.raises(ActivationPackageError, match="open writer|open process|quiescen"):
            _prepare(**_source_args(tmp_path, source, store_kind="overseer"))
    finally:
        writer.rollback()
        writer.close()


def test_maintenance_copy_fails_closed_when_a_target_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    args = _source_args(tmp_path, source, store_kind="overseer")
    destination = Path(args["destination_store"])
    destination.parent.mkdir(mode=0o700)
    destination.write_bytes(b"pre-existing")

    with pytest.raises(ActivationPackageError, match="already exists|destination"):
        _prepare(**args)
    assert destination.read_bytes() == b"pre-existing"


def test_maintenance_copy_rejects_a_preexisting_destination_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    args = _source_args(tmp_path, source, store_kind="overseer")
    destination = Path(args["destination_store"])
    destination.parent.mkdir(mode=0o700)
    stale_wal = Path(f"{destination}-wal")
    stale_wal.write_bytes(b"pre-existing sidecar")
    stale_wal.chmod(0o600)

    with pytest.raises(ActivationPackageError, match="sidecar destination already exists"):
        _prepare(**args)

    assert stale_wal.read_bytes() == b"pre-existing sidecar"
    assert not destination.exists()


def test_maintenance_copy_restores_source_access_and_removes_partial_outputs_on_migration_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    source_mode = stat.S_IMODE(source.stat().st_mode)
    source_owner = (source.stat().st_uid, source.stat().st_gid)
    parent_mode = stat.S_IMODE(source.parent.stat().st_mode)
    parent_owner = (source.parent.stat().st_uid, source.parent.stat().st_gid)
    _install_guard_seams(monkeypatch)

    class FailingStore:
        def __init__(self, _path: Path) -> None:
            raise RuntimeError("injected migration failure")

    monkeypatch.setattr(activation_package_module, "SQLiteStore", FailingStore)
    args = _source_args(tmp_path, source, store_kind="overseer")

    with pytest.raises((ActivationPackageError, RuntimeError), match="injected migration failure"):
        _prepare(**args)

    assert (source.stat().st_uid, source.stat().st_gid) == source_owner
    assert stat.S_IMODE(source.stat().st_mode) == source_mode
    assert (source.parent.stat().st_uid, source.parent.stat().st_gid) == parent_owner
    assert stat.S_IMODE(source.parent.stat().st_mode) == parent_mode
    assert stat.S_IMODE(Path(f"{source}-wal").stat().st_mode) == 0o600
    assert stat.S_IMODE(Path(f"{source}-shm").stat().st_mode) == 0o600
    assert not Path(args["backup_store"]).exists()
    assert not Path(args["destination_store"]).exists()
    assert not Path(f"{args['backup_store']}.report.json").exists()


def test_root_maintenance_copy_restores_destination_owner_when_cleanup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the real ownership boundary")
    try:
        account = pwd.getpwnam("overseer")
    except KeyError:
        pytest.skip("requires the dedicated overseer account")

    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    destination = tmp_path / "destination" / "overseer.sqlite3"
    destination.parent.mkdir(mode=0o700)
    os.chown(destination.parent, account.pw_uid, account.pw_gid)
    args = _source_args(
        tmp_path,
        source,
        store_kind="overseer",
        destination_uid=account.pw_uid,
        destination_gid=account.pw_gid,
    )
    args["destination_store"] = destination

    class FailingStore:
        def __init__(self, _path: Path) -> None:
            raise RuntimeError("injected migration failure")

    real_unlink = Path.unlink

    def fail_destination_cleanup(path: Path, *args: object, **kwargs: object) -> None:
        if path == destination:
            raise OSError("injected cleanup failure")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(activation_package_module, "SQLiteStore", FailingStore)
    monkeypatch.setattr(Path, "unlink", fail_destination_cleanup)

    with pytest.raises(ActivationPackageError, match="recovery also failed") as captured:
        _prepare(**args)

    assert isinstance(captured.value.__cause__, RuntimeError)
    assert str(captured.value.__cause__) == "injected migration failure"
    assert (destination.parent.stat().st_uid, destination.parent.stat().st_gid) == (
        account.pw_uid,
        account.pw_gid,
    )
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    real_unlink(destination)


def test_root_maintenance_copy_keeps_destination_locked_through_report_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the real ownership boundary")
    try:
        account = pwd.getpwnam("overseer")
    except KeyError:
        pytest.skip("requires the dedicated overseer account")

    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    destination = tmp_path / "destination" / "overseer.sqlite3"
    destination.parent.mkdir(mode=0o700)
    os.chown(destination.parent, account.pw_uid, account.pw_gid)
    args = _source_args(
        tmp_path,
        source,
        store_kind="overseer",
        destination_uid=account.pw_uid,
        destination_gid=account.pw_gid,
    )
    args["destination_store"] = destination
    real_write_new = activation_package_module._write_new
    observed_parent: list[tuple[int, int, int]] = []

    def fail_report_persistence(path: Path, *args: object, **kwargs: object) -> None:
        if path.name.endswith(".sqlite3.report.json"):
            metadata = destination.parent.stat()
            observed_parent.append(
                (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
            )
            raise OSError("injected report persistence failure")
        real_write_new(path, *args, **kwargs)

    monkeypatch.setattr(
        activation_package_module,
        "_write_new",
        fail_report_persistence,
    )

    with pytest.raises(OSError, match="injected report persistence failure"):
        _prepare(**args)

    assert observed_parent == [(0, 0, 0o700)]
    assert (destination.parent.stat().st_uid, destination.parent.stat().st_gid) == (
        account.pw_uid,
        account.pw_gid,
    )
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert not destination.exists()


def test_root_maintenance_copy_relocks_destination_before_partial_handoff_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the real ownership boundary")
    try:
        account = pwd.getpwnam("overseer")
    except KeyError:
        pytest.skip("requires the dedicated overseer account")

    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    destination = tmp_path / "destination" / "overseer.sqlite3"
    destination.parent.mkdir(mode=0o700)
    os.chown(destination.parent, account.pw_uid, account.pw_gid)
    args = _source_args(
        tmp_path,
        source,
        store_kind="overseer",
        destination_uid=account.pw_uid,
        destination_gid=account.pw_gid,
    )
    args["destination_store"] = destination
    real_fsync = activation_package_module.os.fsync
    fsync_failure_injected = False

    def fail_first_fsync_after_destination_exposure(descriptor: int) -> None:
        nonlocal fsync_failure_injected
        metadata = os.fstat(descriptor)
        if (
            not fsync_failure_injected
            and stat.S_ISDIR(metadata.st_mode)
            and (metadata.st_uid, metadata.st_gid)
            == (account.pw_uid, account.pw_gid)
            and stat.S_IMODE(metadata.st_mode) == 0o700
        ):
            fsync_failure_injected = True
            raise OSError("injected destination handoff fsync failure")
        real_fsync(descriptor)

    real_restore_source = (
        activation_package_module._restore_legacy_store_access_unchecked
    )
    observed_destination_before_source_restore: list[tuple[int, int, int]] = []

    def observe_source_restore(**kwargs: object) -> dict[str, object]:
        metadata = destination.parent.stat()
        observed_destination_before_source_restore.append(
            (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        )
        return real_restore_source(**kwargs)

    monkeypatch.setattr(
        activation_package_module.os,
        "fsync",
        fail_first_fsync_after_destination_exposure,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_restore_legacy_store_access_unchecked",
        observe_source_restore,
    )

    with pytest.raises(OSError, match="injected destination handoff fsync failure"):
        _prepare(**args)

    assert fsync_failure_injected is True
    assert observed_destination_before_source_restore == [(0, 0, 0o700)]
    assert (destination.parent.stat().st_uid, destination.parent.stat().st_gid) == (
        account.pw_uid,
        account.pw_gid,
    )
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert not destination.exists()


def test_maintenance_copy_removes_destination_sidecars_when_handoff_sealing_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "legacy" / "overseer.sqlite3"
    source.parent.mkdir(mode=0o700)
    _create_sqlite_store(source)
    _install_guard_seams(monkeypatch)
    args = _source_args(tmp_path, source, store_kind="overseer")
    destination = Path(args["destination_store"])
    real_normalize = activation_package_module._normalize_copied_expression_indexes

    def fail_destination_handoff(path: Path) -> dict[str, object]:
        result = real_normalize(path)
        if Path(path) == destination:
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{path}{suffix}")
                sidecar.write_bytes(b"executor-owned partial sidecar")
                sidecar.chmod(0o600)
            raise RuntimeError("injected handoff sealing failure")
        return result

    monkeypatch.setattr(
        activation_package_module,
        "_normalize_copied_expression_indexes",
        fail_destination_handoff,
    )

    with pytest.raises(RuntimeError, match="injected handoff sealing failure"):
        _prepare(**args)

    assert not destination.exists()
    assert not Path(f"{destination}-wal").exists()
    assert not Path(f"{destination}-shm").exists()


def test_prepare_maintenance_stores_uses_exact_ordered_contract_bindings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    names_and_kinds = (
        ("overseer-main", "overseer"),
        ("psychlo-bridge", "copy-only"),
        ("roadex-relay", "copy-only"),
    )
    bindings = [
        {
            "name": name,
            "sourceDb": str(tmp_path / "legacy" / f"{name}.sqlite3"),
            "backupDb": str(tmp_path / "backup" / f"{name}.sqlite3"),
            "destinationDb": str(tmp_path / "destination" / f"{name}.sqlite3"),
            "storeKind": kind,
            "sourceIdentity": {
                "device": 1,
                "inode": index + 10,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "mode": 0o600,
                "parentDevice": 1,
                "parentInode": 2,
                "parentMode": 0o700,
            },
        }
        for index, (name, kind) in enumerate(names_and_kinds)
    ]
    guard_calls: list[str] = []
    migration_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_require_maintenance_active_sealed_command",
        lambda *_args, **kwargs: guard_calls.append(str(kwargs["command_name"])),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_read_maintenance_contract_file",
        lambda _package: {"storeBindings": bindings},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_ensure_directory",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_ensure_migration_destination_directory",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_prepare_store_migration_unchecked",
        lambda **kwargs: migration_calls.append(kwargs) or {"status": "ok"},
    )

    result = activation_package_module.prepare_maintenance_stores(package)

    assert result["status"] == "maintenance_stores_prepared"
    assert guard_calls == ["prepare-maintenance-stores"]
    assert [call["store_kind"] for call in migration_calls] == [
        "overseer",
        "copy-only",
        "copy-only",
    ]
    assert [Path(str(call["source_store"])).name for call in migration_calls] == [
        "overseer-main.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
    ]


def test_restore_maintenance_store_access_restores_all_bound_authorities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    bindings = [
        {
            "name": name,
            "sourceDb": str(tmp_path / f"{name}.sqlite3"),
            "sourceIdentity": {
                "device": 1,
                "inode": index + 20,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "mode": 0o600,
                "parentDevice": 1,
                "parentInode": 2,
                "parentMode": 0o700,
            },
        }
        for index, name in enumerate(
            ("overseer-main", "psychlo-bridge", "roadex-relay")
        )
    ]
    restored: list[dict[str, object]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_require_maintenance_active_rollback_command",
        lambda *_args, **_kwargs: {"storeBindings": bindings},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_restore_legacy_store_access_unchecked",
        lambda **kwargs: restored.append(kwargs) or {"restored": True},
    )
    locked: list[list[object]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_lock_maintenance_destination_namespace_for_rollback",
        lambda received: locked.append(received) or (-1, []),
    )

    result = activation_package_module.restore_maintenance_store_access(package)

    assert result["status"] == "maintenance_store_access_restored"
    assert result["destinationNamespace"] == "root-locked-and-process-free"
    assert result["resolvedUnsafeMarkers"] == []
    assert locked == [bindings]
    assert [Path(str(call["source_store"])).name for call in restored] == [
        "overseer-main.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
    ]


def test_restore_maintenance_store_access_blocks_sources_when_destination_is_unsafe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    bindings = [
        {
            "name": name,
            "sourceDb": str(tmp_path / f"{name}.sqlite3"),
            "backupDb": str(tmp_path / "backup" / f"{name}.sqlite3"),
            "destinationDb": str(tmp_path / "destination" / f"{name}.sqlite3"),
            "sourceIdentity": {
                "device": 1,
                "inode": index + 20,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "mode": 0o600,
                "parentDevice": 1,
                "parentInode": 2,
                "parentMode": 0o700,
            },
        }
        for index, name in enumerate(
            ("overseer-main", "psychlo-bridge", "roadex-relay")
        )
    ]
    restored: list[dict[str, object]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_require_maintenance_active_rollback_command",
        lambda *_args, **_kwargs: {"storeBindings": bindings},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_lock_maintenance_destination_namespace_for_rollback",
        lambda _bindings: (_ for _ in ()).throw(
            ActivationPackageError("destination namespace is unsafe")
        ),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_restore_legacy_store_access_unchecked",
        lambda **kwargs: restored.append(kwargs) or {"restored": True},
    )

    with pytest.raises(ActivationPackageError, match="destination namespace is unsafe"):
        activation_package_module.restore_maintenance_store_access(package)

    assert restored == []


def test_restore_maintenance_store_access_holds_destination_lock_through_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    destination_parent = tmp_path / "destination"
    destination_parent.mkdir()
    descriptor = os.open(destination_parent, os.O_RDONLY | os.O_DIRECTORY)
    bindings = [
        {
            "name": name,
            "sourceDb": str(tmp_path / f"{name}.sqlite3"),
            "backupDb": str(tmp_path / "backup" / f"{name}.sqlite3"),
            "destinationDb": str(destination_parent / f"{name}.sqlite3"),
            "sourceIdentity": {
                "device": 1,
                "inode": index + 20,
                "uid": os.getuid(),
                "gid": os.getgid(),
                "mode": 0o600,
                "parentDevice": 1,
                "parentInode": 2,
                "parentMode": 0o700,
            },
        }
        for index, name in enumerate(
            ("overseer-main", "psychlo-bridge", "roadex-relay")
        )
    ]
    monkeypatch.setattr(
        activation_package_module,
        "_require_maintenance_active_rollback_command",
        lambda *_args, **_kwargs: {"storeBindings": bindings},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_lock_maintenance_destination_namespace_for_rollback",
        lambda _bindings: (descriptor, []),
    )
    observed: list[int] = []

    def restore(**_kwargs: object) -> dict[str, object]:
        observed.append(os.fstat(descriptor).st_ino)
        return {"restored": True}

    monkeypatch.setattr(
        activation_package_module,
        "_restore_legacy_store_access_unchecked",
        restore,
    )

    activation_package_module.restore_maintenance_store_access(package)

    assert len(observed) == 3
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_rollback_destination_lock_validates_the_exact_safe_owner_pairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_parent = tmp_path / "destination"
    destination_parent.mkdir(mode=0o700)
    destination = destination_parent / "overseer.sqlite3"
    destination.write_bytes(b"failed successor store")
    destination.chmod(0o600)
    service_owner = (os.geteuid(), os.getegid())
    root_owner = (service_owner[0] + 10000, service_owner[1] + 10000)
    bindings: list[object] = [
        {
            "destinationDb": str(destination),
            "backupDb": str(tmp_path / "backup" / "overseer.sqlite3"),
        }
    ]
    observed_owner_sets: list[frozenset[tuple[int, int]] | None] = []

    def validate(
        path: Path,
        *,
        label: str,
        expected_uid: int | None = None,
        allowed_owners: frozenset[tuple[int, int]] | None = None,
        allowed_modes: frozenset[int] = frozenset({0o600}),
    ) -> os.stat_result:
        del label, expected_uid, allowed_modes
        observed_owner_sets.append(allowed_owners)
        assert allowed_owners == frozenset({root_owner, service_owner})
        return path.lstat()

    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_OVERSEER_UID",
        service_owner[0],
    )
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_OVERSEER_GID",
        service_owner[1],
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: root_owner,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_relock_migration_destination_directory",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_store_artifact",
        validate,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda _uid: (),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_legacy_inode_activity",
        lambda *_args, **_kwargs: (),
    )

    descriptor, markers = (
        activation_package_module._lock_maintenance_destination_namespace_for_rollback(
            bindings
        )
    )
    os.close(descriptor)

    assert markers == []
    assert observed_owner_sets == [frozenset({root_owner, service_owner})]


def test_store_artifact_allowed_owners_rejects_an_unlisted_owner(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "store.sqlite3"
    artifact.write_bytes(b"store")
    artifact.chmod(0o600)

    with pytest.raises(ActivationPackageError, match="unexpected owner"):
        activation_package_module._validate_store_artifact(
            artifact,
            label="rollback destination",
            allowed_owners=frozenset({(os.geteuid() + 10000, os.getegid())}),
        )


def test_store_artifact_allowed_owners_accepts_only_an_exact_pair(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "store.sqlite3"
    artifact.write_bytes(b"store")
    artifact.chmod(0o600)
    actual_owner = (os.geteuid(), os.getegid())

    metadata = activation_package_module._validate_store_artifact(
        artifact,
        label="rollback destination",
        allowed_owners=frozenset({actual_owner, (actual_owner[0] + 10000, 10000)}),
    )
    assert (metadata.st_uid, metadata.st_gid) == actual_owner

    with pytest.raises(ActivationPackageError, match="unexpected owner"):
        activation_package_module._validate_store_artifact(
            artifact,
            label="rollback destination",
            allowed_owners=frozenset(
                {
                    (actual_owner[0], actual_owner[1] + 10000),
                    (actual_owner[0] + 10000, actual_owner[1]),
                }
            ),
        )


@pytest.mark.parametrize(
    ("expected_uid", "allowed_owners", "message"),
    [
        (None, frozenset(), "owner policy is empty"),
        (0, frozenset({(0, 0)}), "owner policy is ambiguous"),
    ],
)
def test_store_artifact_rejects_an_invalid_owner_policy(
    tmp_path: Path,
    expected_uid: int | None,
    allowed_owners: frozenset[tuple[int, int]],
    message: str,
) -> None:
    artifact = tmp_path / "store.sqlite3"
    artifact.write_bytes(b"store")
    artifact.chmod(0o600)

    with pytest.raises(ActivationPackageError, match=message):
        activation_package_module._validate_store_artifact(
            artifact,
            label="rollback destination",
            expected_uid=expected_uid,
            allowed_owners=allowed_owners,
        )


def test_root_rollback_destination_lock_blocks_service_principal_processes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the real ownership boundary")
    try:
        account = pwd.getpwnam("overseer")
    except KeyError:
        pytest.skip("requires the dedicated overseer account")

    destination_parent = tmp_path / "destination"
    destination_parent.mkdir(mode=0o700)
    os.chown(destination_parent, account.pw_uid, account.pw_gid)
    bindings: list[object] = []
    for name in ("overseer", "psychlo", "roadex"):
        destination = destination_parent / f"{name}.sqlite3"
        destination.write_bytes(b"failed successor store")
        destination.chmod(0o600)
        os.chown(destination, account.pw_uid, account.pw_gid)
        bindings.append(
            {
                "destinationDb": str(destination),
                "backupDb": str(tmp_path / "backup" / f"{name}.sqlite3"),
            }
        )
    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda uid: (4242,) if uid == account.pw_uid else (),
    )

    with pytest.raises(ActivationPackageError, match="process exists"):
        activation_package_module._lock_maintenance_destination_namespace_for_rollback(
            bindings
        )

    assert (destination_parent.stat().st_uid, destination_parent.stat().st_gid) == (
        0,
        0,
    )
    assert stat.S_IMODE(destination_parent.stat().st_mode) == 0o700


def test_root_rollback_destination_lock_rejects_real_open_store_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.geteuid() != 0:
        pytest.skip("requires root to exercise the real process scan")
    destination_parent = tmp_path / "destination"
    destination_parent.mkdir(mode=0o700)
    destination = destination_parent / "overseer.sqlite3"
    destination.write_bytes(b"failed successor store")
    destination.chmod(0o600)
    bindings: list[object] = [
        {
            "destinationDb": str(destination),
            "backupDb": str(tmp_path / "backup" / "overseer.sqlite3"),
        }
    ]
    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda _uid: (),
    )

    with destination.open("rb"):
        with pytest.raises(ActivationPackageError, match="remains open"):
            activation_package_module._lock_maintenance_destination_namespace_for_rollback(
                bindings
            )


def test_rollback_destination_lock_rejects_missing_namespace_with_unsafe_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup = tmp_path / "backup" / "overseer.sqlite3"
    backup.parent.mkdir()
    marker = backup.with_suffix(
        f"{backup.suffix}.destination-namespace-unsafe.json"
    )
    marker.write_text("{}\n", encoding="utf-8")
    marker.chmod(0o600)
    bindings: list[object] = [
        {
            "destinationDb": str(tmp_path / "missing" / "overseer.sqlite3"),
            "backupDb": str(backup),
        }
    ]
    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda _uid: (),
    )

    with pytest.raises(ActivationPackageError, match="missing with an unsafe marker"):
        activation_package_module._lock_maintenance_destination_namespace_for_rollback(
            bindings
        )


def test_rollback_destination_lock_rejects_process_when_namespace_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bindings: list[object] = [
        {
            "destinationDb": str(tmp_path / "missing" / "overseer.sqlite3"),
            "backupDb": str(tmp_path / "backup" / "overseer.sqlite3"),
        }
    ]
    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda uid: (4242,) if uid == 984 else (),
    )

    with pytest.raises(ActivationPackageError, match="process exists"):
        activation_package_module._lock_maintenance_destination_namespace_for_rollback(
            bindings
        )
