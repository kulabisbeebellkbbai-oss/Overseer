from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from urllib.error import HTTPError

import pytest
import overseer.activation_package as activation_package_module

from overseer.activation_package import (
    ActivationPackageError,
    activation_package_status,
    build_release_manifest,
    create_human_verifiers,
    finalize_activation_package,
    prepare_final_store_migration,
    record_activation_approval,
    rehearse_store_migration,
    render_systemd_units,
    render_activation_contract,
    restore_legacy_store_access,
    run_canary_acceptance,
    stage_credentials,
    stage_release_payload,
    verify_activation_package,
    verify_canary_attestation,
    verify_rollback_inputs,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]


def _git(checkout: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def _reviewed_checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "checkout"
    package = checkout / "src" / "overseer"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "1.1.6"\n', encoding="utf-8")
    (package / "cli.py").write_text("def main():\n    return 0\n", encoding="utf-8")
    _git(checkout, "init", "-q")
    _git(checkout, "config", "user.email", "overseer-test@localhost")
    _git(checkout, "config", "user.name", "Overseer Test")
    _git(checkout, "add", "src")
    _git(checkout, "commit", "-q", "-m", "fixture")
    return checkout


def _dependencies(tmp_path: Path) -> Path:
    root = tmp_path / "site-packages"
    package = root / "dependency"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    extension = root / "_dependency.so"
    extension.write_bytes(b"binary-extension")
    extension.chmod(0o755)
    return root


def _python(tmp_path: Path) -> Path:
    executable = tmp_path / "python3"
    executable.write_bytes(b"python-runtime")
    executable.chmod(0o755)
    return executable


def _stdlib(tmp_path: Path) -> Path:
    root = tmp_path / "stdlib"
    package = root / "encodings"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("# runtime fixture\n", encoding="utf-8")
    return root


def test_release_manifest_is_stable_closed_and_hashes_exact_inputs(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)

    first = build_release_manifest(checkout, dependencies, python, stdlib)
    second = build_release_manifest(checkout, dependencies, python, stdlib)

    assert first == second
    assert first["schemaVersion"] == "overseer.dedicated-principal-release.v1"
    assert first["sourceCommit"] == _git(checkout, "rev-parse", "HEAD")
    assert first["sourceTree"] == _git(checkout, "rev-parse", "HEAD^{tree}")
    assert first["manifestDigest"] == hashlib.sha256(
        json.dumps(
            {key: value for key, value in first.items() if key not in {"manifestDigest", "releaseRoot"}},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    assert first["releaseRoot"] == (
        f"/opt/overseer/releases/{first['sourceCommit']}-{first['manifestDigest']}"
    )
    assert [item["releasePath"] for item in first["files"]] == [
        "app/src/overseer/__init__.py",
        "app/src/overseer/cli.py",
        "runtime/lib/python3.13/encodings/__init__.py",
        "site-packages/_dependency.so",
        "site-packages/dependency/__init__.py",
    ]
    assert first["rootPython"]["path"] == str(python)
    assert first["rootPython"]["sha256"] == hashlib.sha256(b"python-runtime").hexdigest()
    assert first["rootPython"]["releasePath"] == "runtime/bin/python3.13"


@pytest.mark.skipif(
    not Path("/usr/bin/python3.13").is_file() or not Path("/usr/lib/python3.13").is_dir(),
    reason="host Python 3.13 runtime is unavailable",
)
def test_copied_release_runtime_executes_with_release_local_pythonhome(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = Path("/usr/bin/python3.13")
    stdlib = Path("/usr/lib/python3.13")
    manifest = build_release_manifest(checkout, dependencies, python, stdlib)
    package = tmp_path / "activation-package"
    release = stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )
    staged_python = release / "runtime" / "bin" / "python3.13"
    result = subprocess.run(
        [str(staged_python), "-c", "import json, sqlite3, ssl; print('runtime-ok')"],
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONHOME": str(release / "runtime"),
            "PYTHONPATH": f"{release / 'app' / 'src'}:{release / 'site-packages'}",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "runtime-ok"


def test_release_manifest_rejects_dirty_tree_and_dependency_symlink(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    (checkout / "src" / "overseer" / "cli.py").write_text("changed\n", encoding="utf-8")

    with pytest.raises(ActivationPackageError, match="clean"):
        build_release_manifest(checkout, dependencies, python, stdlib)

    _git(checkout, "checkout", "--", "src/overseer/cli.py")
    (dependencies / "unsafe").symlink_to(dependencies / "dependency")
    with pytest.raises(ActivationPackageError, match="symlink"):
        build_release_manifest(checkout, dependencies, python, stdlib)

    (dependencies / "unsafe").unlink()
    linked_root = tmp_path / "linked-site-packages"
    linked_root.symlink_to(dependencies, target_is_directory=True)
    with pytest.raises(ActivationPackageError, match="roots.*symlink"):
        build_release_manifest(checkout, linked_root, python, stdlib)


def test_stage_release_payload_and_render_units_are_exact(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    manifest = build_release_manifest(checkout, dependencies, python, stdlib)
    package = tmp_path / "activation-package"

    staged_release = stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )
    rendered = render_systemd_units(
        manifest,
        templates_root=ROOT / "systemd",
        output_root=package / "public" / "systemd",
        god_uid=os.getuid(),
        overseer_uid=984,
        python_path=python,
    )

    assert staged_release.name == Path(str(manifest["releaseRoot"])).name
    for item in manifest["files"]:
        content = (staged_release / item["releasePath"]).read_bytes()
        assert hashlib.sha256(content).hexdigest() == item["sha256"]
        assert os.stat(staged_release / item["releasePath"]).st_mode & 0o777 == item["mode"]
    assert (staged_release / "runtime" / "bin" / "python3.13").read_bytes() == b"python-runtime"
    assert (staged_release / "release-manifest.json").read_text(encoding="utf-8") == (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    )
    assert set(rendered) == {
        "overseer-admin-executor.socket",
        "overseer-admin-executor@.service",
        "overseer-api-canary.service",
        "overseer-api.service",
        "overseer-approval-smoke.service",
        "overseer-codex-user-bridge.service",
        "overseer-codex-user-bridge.socket",
        "overseer-runtime.service",
        "overseer-tmpfiles.conf",
    }
    allowlist = json.loads(
        (package / "public" / "config" / "admin-executor-allowlist.json").read_text(
            encoding="utf-8"
        )
    )
    assert allowlist == {
        "schemaVersion": "overseer.admin-executor-allowlist.v1",
        "allowed": [
            {
                "operation": "restart-system-unit",
                "unit": "overseer-approval-smoke.service",
            }
        ],
    }
    for path in rendered.values():
        content = path.read_text(encoding="utf-8")
        assert "@OVERSEER_" not in content
        assert "@GOD_UID@" not in content
    api = rendered["overseer-api.service"].read_text(encoding="utf-8")
    assert f"WorkingDirectory={manifest['releaseRoot']}" in api
    assert (
        f"Environment=PYTHONPATH={manifest['releaseRoot']}/app/src:"
        f"{manifest['releaseRoot']}/site-packages"
    ) in api
    assert f"Environment=PYTHONHOME={manifest['releaseRoot']}/runtime" in api
    assert f"ExecStart={manifest['releaseRoot']}/runtime/bin/python3.13 " in api
    bridge = rendered["overseer-codex-user-bridge.service"].read_text(encoding="utf-8")
    assert "--peer-uid=984" in bridge


def _credential_sources(tmp_path: Path) -> tuple[Path, Path, Path]:
    psychlo = tmp_path / "psychlo-peer-secret"
    roadex = tmp_path / "roadex-peer-secret"
    bindings = tmp_path / "psychlo-project-bindings.json"
    psychlo.write_text("psychlo-secret-material-1234567890", encoding="utf-8")
    roadex.write_text("roadex-secret-material-1234567890", encoding="utf-8")
    bindings.write_text('{"projects":{}}\n', encoding="utf-8")
    for path in (psychlo, roadex, bindings):
        path.chmod(0o600)
    return psychlo, roadex, bindings


def test_stage_credentials_is_owner_only_and_public_metadata_is_secret_free(tmp_path: Path) -> None:
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    package = tmp_path / "activation-package"
    deterministic_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    metadata = stage_credentials(
        package,
        psychlo_secret_file=psychlo,
        roadex_secret_file=roadex,
        psychlo_bindings_file=bindings,
        random_bytes=lambda size: b"A" * size,
        ticket_private_key=deterministic_key,
    )

    private = package / "private" / "credentials"
    public = package / "public"
    assert stat_mode(private / "api-token") == 0o600
    assert stat_mode(private / "psychlo-peer-secret") == 0o600
    assert stat_mode(private / "roadex-project-human-thread-secret") == 0o600
    assert stat_mode(private / "admin-ticket-private-key") == 0o600
    assert stat_mode(public / "config" / "admin-executor-public-key") == 0o644
    assert stat_mode(public / "config" / "psychlo-project-bindings.json") == 0o644
    assert metadata["apiToken"]["rotationRequired"] is True
    assert metadata["humanVerifiers"]["status"] == "awaiting_interactive_input"

    public_bytes = b"".join(path.read_bytes() for path in public.rglob("*") if path.is_file())
    for secret in (
        psychlo.read_bytes(),
        roadex.read_bytes(),
        (private / "api-token").read_bytes(),
        (private / "admin-ticket-private-key").read_bytes(),
    ):
        assert secret not in public_bytes


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_stage_credentials_rejects_insecure_or_linked_sources(tmp_path: Path) -> None:
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    psychlo.chmod(0o644)
    with pytest.raises(ActivationPackageError, match="0600"):
        stage_credentials(
            tmp_path / "package-insecure",
            psychlo_secret_file=psychlo,
            roadex_secret_file=roadex,
            psychlo_bindings_file=bindings,
        )

    psychlo.chmod(0o600)
    linked = tmp_path / "linked-roadex"
    linked.symlink_to(roadex)
    with pytest.raises(ActivationPackageError, match="symlink"):
        stage_credentials(
            tmp_path / "package-linked",
            psychlo_secret_file=psychlo,
            roadex_secret_file=linked,
            psychlo_bindings_file=bindings,
        )


def test_package_staging_rejects_symlinked_or_preexisting_insecure_root(tmp_path: Path) -> None:
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ActivationPackageError, match="directory chain is unsafe"):
        stage_credentials(
            linked_parent / "activation-package",
            psychlo_secret_file=psychlo,
            roadex_secret_file=roadex,
            psychlo_bindings_file=bindings,
        )

    insecure = tmp_path / "insecure-package"
    insecure.mkdir(mode=0o755)
    with pytest.raises(ActivationPackageError, match="owner-controlled mode 0700"):
        stage_credentials(
            insecure,
            psychlo_secret_file=psychlo,
            roadex_secret_file=roadex,
            psychlo_bindings_file=bindings,
        )
    assert stat_mode(insecure) == 0o755


def test_human_verifier_gate_requires_distinct_non_api_secrets(tmp_path: Path) -> None:
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    package = tmp_path / "activation-package"
    stage_credentials(
        package,
        psychlo_secret_file=psychlo,
        roadex_secret_file=roadex,
        psychlo_bindings_file=bindings,
        random_bytes=lambda size: b"B" * size,
        ticket_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
    )
    api_token = (package / "private" / "credentials" / "api-token").read_text(encoding="utf-8").strip()

    assert activation_package_status(package)["status"] == "awaiting_human_verifiers"
    with pytest.raises(ActivationPackageError, match="different"):
        create_human_verifiers(
            package,
            admin_secret="shared-approval-secret-12345",
            roadex_secret="shared-approval-secret-12345",
        )
    with pytest.raises(ActivationPackageError, match="API token"):
        create_human_verifiers(
            package,
            admin_secret=api_token,
            roadex_secret="roadex-approval-secret-12345",
        )

    created = create_human_verifiers(
        package,
        admin_secret="admin-approval-secret-123456",
        roadex_secret="roadex-approval-secret-12345",
    )

    assert created["status"] == "created"
    assert activation_package_status(package)["status"] == "credentials_complete"
    credentials = package / "private" / "credentials"
    assert stat_mode(credentials / "admin-approval-verifier.json") == 0o600
    assert stat_mode(credentials / "roadex-fixture-approval-verifier.json") == 0o600
    public_bytes = b"".join(
        path.read_bytes() for path in (package / "public").rglob("*") if path.is_file()
    )
    assert b"admin-approval-secret" not in public_bytes
    assert b"roadex-approval-secret" not in public_bytes


def test_human_verifier_cli_accepts_secrets_only_from_hidden_prompts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    monkeypatch.setattr(activation_package_module, "APPROVED_PACKAGE_PARENT", tmp_path)
    package = tmp_path / "v1.1.6-abcdef0"
    stage_credentials(
        package,
        psychlo_secret_file=psychlo,
        roadex_secret_file=roadex,
        psychlo_bindings_file=bindings,
        random_bytes=lambda size: b"D" * size,
        ticket_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
    )
    answers = iter(
        (
            "admin-approval-secret-123456",
            "admin-approval-secret-123456",
            "roadex-approval-secret-12345",
            "roadex-approval-secret-12345",
        )
    )
    monkeypatch.setattr(activation_package_module.getpass, "getpass", lambda _prompt: next(answers))

    assert activation_package_module._main(
        ["create-human-verifiers", "--package-root", str(package)]
    ) == 0

    output = capsys.readouterr().out
    assert json.loads(output)["status"] == "created"
    assert "admin-approval-secret" not in output
    assert "roadex-approval-secret" not in output


def _wal_store(path: Path) -> None:
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE retained_items(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    connection.executemany(
        "INSERT INTO retained_items(value) VALUES (?)",
        [("one",), ("two",), ("three",)],
    )
    connection.commit()
    connection.close()
    path.chmod(0o600)


def test_rehearsal_backup_is_consistent_and_migrates_only_copies(tmp_path: Path) -> None:
    source_parent = tmp_path / "legacy-state"
    source_parent.mkdir(mode=0o700)
    source = source_parent / "overseer.sqlite3"
    _wal_store(source)
    source_before = source.read_bytes()
    package = tmp_path / "activation-package"

    report = rehearse_store_migration(
        package,
        source_store=source,
        pages_per_step=1,
        sleep_seconds=0,
    )

    migration = package / "private" / "migration"
    backup = migration / "rehearsal-source.sqlite3"
    migrated = migration / "rehearsal-migrated.sqlite3"
    assert report["status"] == "rehearsal_complete"
    assert report["sourceMutationPerformed"] is False
    assert report["backup"]["integrityCheck"] == "ok"
    assert report["migrated"]["integrityCheck"] == "ok"
    assert report["rowCountsBefore"]["retained_items"] == 3
    assert report["rowCountsAfter"]["retained_items"] == 3
    assert source.read_bytes() == source_before
    assert stat_mode(source) == 0o600
    assert stat_mode(backup) == 0o600
    assert stat_mode(migrated) == 0o600
    with sqlite3.connect(backup) as connection:
        assert connection.execute("SELECT value FROM retained_items ORDER BY id").fetchall() == [
            ("one",),
            ("two",),
            ("three",),
        ]
    with sqlite3.connect(migrated) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchone() == (1,)


def test_rehearsal_backup_remains_consistent_while_wal_writer_commits(tmp_path: Path) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    connection = sqlite3.connect(source)
    connection.executemany(
        "INSERT INTO retained_items(value) VALUES (?)",
        (("x" * 2048,) for _ in range(1024)),
    )
    connection.commit()
    connection.close()
    errors: list[BaseException] = []

    def writer() -> None:
        writer_connection = sqlite3.connect(source, timeout=2)
        try:
            for _ in range(64):
                writer_connection.execute(
                    "INSERT INTO retained_items(value) VALUES (?)",
                    ("concurrent",),
                )
                writer_connection.commit()
                time.sleep(0.002)
        except BaseException as error:
            errors.append(error)
        finally:
            writer_connection.close()

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    report = rehearse_store_migration(
        tmp_path / "activation-package",
        source_store=source,
        pages_per_step=16,
        sleep_seconds=0.001,
    )
    thread.join(timeout=5)

    assert not errors
    assert not thread.is_alive()
    assert report["backup"]["integrityCheck"] == "ok"
    assert report["migrated"]["integrityCheck"] == "ok"
    assert report["rowCountsBefore"] == report["rowCountsAfter"]


def test_rehearsal_backup_rejects_insecure_or_linked_store(tmp_path: Path) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    source.chmod(0o644)
    with pytest.raises(ActivationPackageError, match="0600"):
        rehearse_store_migration(tmp_path / "package-insecure", source_store=source)

    source.chmod(0o600)
    linked = tmp_path / "linked.sqlite3"
    linked.symlink_to(source)
    with pytest.raises(ActivationPackageError, match="symlink"):
        rehearse_store_migration(tmp_path / "package-linked", source_store=linked)


def test_rehearsal_backup_fails_closed_on_integrity_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)

    def reject_integrity(_path: Path) -> str:
        raise ActivationPackageError("migration artifact failed SQLite integrity_check")

    monkeypatch.setattr(activation_package_module, "_integrity_check", reject_integrity)
    with pytest.raises(ActivationPackageError, match="integrity_check"):
        rehearse_store_migration(
            tmp_path / "activation-package",
            source_store=source,
            sleep_seconds=0,
        )


def test_rehearsal_backup_fails_closed_on_retained_row_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)

    class DestructiveMigrationStore:
        def __init__(self, path: Path) -> None:
            with sqlite3.connect(path) as connection:
                connection.execute(
                    "DELETE FROM retained_items WHERE id = "
                    "(SELECT MIN(id) FROM retained_items)"
                )

        def close(self) -> None:
            return None

    monkeypatch.setattr(activation_package_module, "SQLiteStore", DestructiveMigrationStore)
    with pytest.raises(ActivationPackageError, match="retained row count"):
        rehearse_store_migration(
            tmp_path / "activation-package",
            source_store=source,
            sleep_seconds=0,
        )


def test_final_migration_requires_quiescence_and_preserves_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    source_before = source.read_bytes()
    metadata = source.stat()
    parent_metadata = source.parent.stat()
    parent_mode = stat_mode(source.parent)
    backup_parent = tmp_path / "executor-state"
    destination_parent = tmp_path / "authority-state"
    backup_parent.mkdir(mode=0o700)
    destination_parent.mkdir(mode=0o700)
    backup = backup_parent / "final-source.sqlite3"
    destination = destination_parent / "final-migrated.sqlite3"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)

    held_open = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    try:
        with pytest.raises(ActivationPackageError, match="open process"):
            prepare_final_store_migration(
                source_store=source,
                backup_store=backup,
                destination_store=destination,
                expected_source_device=metadata.st_dev,
                expected_source_inode=metadata.st_ino,
                expected_source_uid=os.geteuid(),
                expected_source_gid=os.getegid(),
                expected_parent_device=parent_metadata.st_dev,
                expected_parent_inode=parent_metadata.st_ino,
                expected_parent_mode=parent_mode,
                destination_uid=os.geteuid(),
                destination_gid=os.getegid(),
                sleep_seconds=0,
            )
    finally:
        held_open.close()

    report = prepare_final_store_migration(
        source_store=source,
        backup_store=backup,
        destination_store=destination,
        expected_source_device=metadata.st_dev,
        expected_source_inode=metadata.st_ino,
        expected_source_uid=os.geteuid(),
        expected_source_gid=os.getegid(),
        expected_parent_device=parent_metadata.st_dev,
        expected_parent_inode=parent_metadata.st_ino,
        expected_parent_mode=parent_mode,
        destination_uid=os.geteuid(),
        destination_gid=os.getegid(),
        sleep_seconds=0,
    )

    assert report["status"] == "final_migration_complete"
    assert report["openProcessPreflight"] == "clear"
    assert report["quiescenceLock"] == "parent-and-store-write-access-revoked"
    assert source.read_bytes() == source_before
    assert report["rowCountsBefore"]["retained_items"] == 3
    assert report["rowCountsAfter"]["retained_items"] == 3
    assert stat_mode(backup) == 0o600
    assert stat_mode(destination) == 0o600
    assert stat_mode(source) == 0o400
    assert stat_mode(source.parent) == 0o555
    restored = restore_legacy_store_access(
        source_store=source,
        expected_source_uid=os.geteuid(),
        expected_source_gid=os.getegid(),
        expected_source_device=metadata.st_dev,
        expected_source_inode=metadata.st_ino,
        expected_parent_device=parent_metadata.st_dev,
        expected_parent_inode=parent_metadata.st_ino,
        expected_parent_mode=parent_mode,
    )
    assert restored["restored"] is True
    assert stat_mode(source) == 0o600


def _prepared_package(tmp_path: Path) -> tuple[Path, dict[str, object], Path]:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    manifest = build_release_manifest(checkout, dependencies, python, stdlib)
    package = tmp_path / "activation-package"
    stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )
    render_systemd_units(
        manifest,
        templates_root=ROOT / "systemd",
        output_root=package / "public" / "systemd",
        god_uid=os.getuid(),
        overseer_uid=984,
        python_path=python,
    )
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    stage_credentials(
        package,
        psychlo_secret_file=psychlo,
        roadex_secret_file=roadex,
        psychlo_bindings_file=bindings,
        random_bytes=lambda size: b"C" * size,
        ticket_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
    )
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    rehearse_store_migration(package, source_store=source, sleep_seconds=0)
    return package, manifest, source


def _finalized_package(tmp_path: Path) -> tuple[Path, str]:
    package, manifest, source = _prepared_package(tmp_path)
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    (rollback / "src.py").write_text("rollback input\n", encoding="utf-8")
    render_activation_contract(
        package,
        manifest,
        source_store=source,
        overseer_uid=984,
        overseer_gid=984,
        rollback_inputs={"v1.1.5-release": rollback},
    )
    create_human_verifiers(
        package,
        admin_secret="admin-approval-secret-123456",
        roadex_secret="roadex-approval-secret-12345",
    )
    finalized = finalize_activation_package(package)
    return package, str(finalized["packageDigest"])


def test_prepare_package_cli_stops_at_human_verifier_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    rollback = tmp_path / "rollback-unit"
    rollback.write_text("[Service]\nExecStart=/old/python\n", encoding="utf-8")
    rollback_release = tmp_path / "rollback-release"
    rollback_release.mkdir()
    (rollback_release / "src.py").write_text("old release\n", encoding="utf-8")
    package_parent = tmp_path / "activation-packages"
    package_parent.mkdir(mode=0o700)
    monkeypatch.setattr(activation_package_module, "APPROVED_PACKAGE_PARENT", package_parent)
    package = package_parent / "v1.1.6-abcdef0"

    assert activation_package_module._main(
        [
            "prepare-package",
            "--checkout",
            str(checkout),
            "--dependency-root",
            str(dependencies),
            "--root-python",
            str(python),
            "--stdlib-root",
            str(stdlib),
            "--templates-root",
            str(ROOT / "systemd"),
            "--package-root",
            str(package),
            "--psychlo-secret-file",
            str(psychlo),
            "--roadex-secret-file",
            str(roadex),
            "--psychlo-bindings-file",
            str(bindings),
            "--source-store",
            str(source),
            "--god-uid",
            str(os.getuid()),
            "--overseer-uid",
            "984",
            "--overseer-gid",
            "984",
            "--rollback-input",
            f"v1.1.5-api-unit={rollback}",
            "--rollback-input",
            f"v1.1.5-release={rollback_release}",
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "awaiting_human_verifiers"
    assert result["readyForApproval"] is False
    assert result["packageRoot"] == str(package)
    assert not (package / "public" / "package-manifest.json").exists()


def test_activation_contract_is_exact_nonexecuting_and_has_closed_rollback(tmp_path: Path) -> None:
    package, manifest, source = _prepared_package(tmp_path)
    rollback_release = tmp_path / "v1.1.5-release"
    rollback_release.mkdir()
    (rollback_release / "src.py").write_text("old release\n", encoding="utf-8")
    rollback_unit = tmp_path / "overseer-api.service"
    rollback_unit.write_text("[Service]\nExecStart=/old/python\n", encoding="utf-8")
    rollback_unit.chmod(0o600)

    contract = render_activation_contract(
        package,
        manifest,
        source_store=source,
        overseer_uid=984,
        overseer_gid=984,
        rollback_inputs={
            "v1.1.5-release": rollback_release,
            "v1.1.5-api-unit": rollback_unit,
        },
    )

    encoded = json.dumps(contract, sort_keys=True)
    assert contract["schemaVersion"] == "overseer.dedicated-principal-activation-contract.v1"
    assert contract["liveExecutionApproved"] is False
    assert contract["account"] == {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984}
    assert contract["releaseRoot"] == manifest["releaseRoot"]
    assert "<" not in encoded and ">" not in encoded
    assert "--human-approval-token-file" not in encoded
    assert "systemctl --user" not in encoded
    assert "*" not in encoded
    staging_commands = contract["stagingAndCanaryCommands"]
    cutover_commands = contract["cutoverCommands"]
    commands = [*staging_commands, *cutover_commands]
    assert ["/usr/sbin/groupadd", "--system", "--gid", "984", "overseer"] in commands
    assert [
        "/usr/sbin/useradd",
        "--system",
        "--uid",
        "984",
        "--gid",
        "984",
        "--home-dir",
        "/var/lib/overseer",
        "--shell",
        "/usr/sbin/nologin",
        "overseer",
    ] in commands
    stop_index = next(
        index
        for index, command in enumerate(commands)
        if command[-3:] == ["stop", "overseer.service", "overseer-api.service"]
    )
    migration_index = next(
        index for index, command in enumerate(commands) if "prepare-final-store" in command
    )
    system_start_index = next(
        index
        for index, command in enumerate(commands)
        if command[-2:] == ["overseer-runtime.service", "overseer-api.service"]
    )
    token_copy_index = next(
        index
        for index, command in enumerate(commands)
        if command[-1] == "/home/god/.local/share/overseer/project/state/api-token"
    )
    token_copy = commands[token_copy_index]
    assert token_copy[token_copy.index("-o") + 1] == "root"
    assert token_copy[token_copy.index("-g") + 1] == "god"
    assert token_copy[token_copy.index("-m") + 1] == "0640"
    assert token_copy[-2] == "/etc/overseer/api-token"
    assert "verify-compatibility-token" in commands[token_copy_index + 1]
    canary_health_index = next(
        index for index, command in enumerate(commands) if command[-1] == "http://127.0.0.1:18766/health"
    )
    assert canary_health_index < stop_index < migration_index < system_start_index < token_copy_index
    assert all("overseer.service" not in command for command in staging_commands)
    assert contract["cutoverGate"] == {
        "requiredFunction": "overseer.activation_package.verify_approved_cutover",
        "requiresApprovedPackageDigest": True,
        "requiresRootOwnedApprovalRecord": True,
        "requiresRootOwnedDigestBoundAttestation": True,
        "manualCommandExtractionForbidden": True,
    }
    assert "run-approved-canary" in staging_commands[-2]
    assert "verify-approved-cutover" in cutover_commands[0]
    staging_verify_index = next(
        index for index, command in enumerate(staging_commands) if "verify-approved-staging" in command
    )
    canary_start_index = next(
        index
        for index, command in enumerate(staging_commands)
        if command[-2:] == ["start", "overseer-api-canary.service"]
    )
    assert staging_verify_index < canary_start_index
    assert contract["acceptanceControls"]["negative"] == [
        "ordinary API token cannot approve",
        "wrong human scope cannot approve",
        "cross-scope credential collision is rejected",
        "modified ticket is rejected",
        "expired ticket is rejected",
        "unlisted system unit is rejected",
        "user-service restart operation is rejected",
        "executor socket timeout fails closed",
        "crash-after-claim retry does not issue a second command",
    ]
    assert all("-r" not in command and "-R" not in command for command in commands)
    assert "verify-rollback-bundle" in contract["rollbackCommands"][0]
    assert "v1.1.5-release" in contract["rollbackBundle"]["executionSourceLabel"]
    assert any(
        any("overseer-v1-1-5-rollback-runtime.service" in value for value in command)
        for command in contract["rollbackCommands"]
    )
    assert contract["rollbackCommands"][-1] == [
        "/usr/bin/curl",
        "--fail",
        "--silent",
        "--show-error",
        "http://127.0.0.1:8766/health",
    ]
    rollback = json.loads((package / "public" / "rollback-manifest.json").read_text())
    assert {item["label"] for item in rollback["inputs"]} == {
        "v1.1.5-api-unit",
        "v1.1.5-release",
    }
    assert verify_rollback_inputs(package)["verified"] is True
    rollback_unit.write_text("drift\n", encoding="utf-8")
    with pytest.raises(ActivationPackageError, match="rollback input drift"):
        verify_rollback_inputs(package)


def test_package_finalization_requires_human_gate_and_detects_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, manifest, source = _prepared_package(tmp_path)
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    (rollback / "src.py").write_text("rollback input\n", encoding="utf-8")
    render_activation_contract(
        package,
        manifest,
        source_store=source,
        overseer_uid=984,
        overseer_gid=984,
        rollback_inputs={"v1.1.5-release": rollback},
    )

    with pytest.raises(ActivationPackageError, match="human verifier"):
        finalize_activation_package(package)
    create_human_verifiers(
        package,
        admin_secret="admin-approval-secret-123456",
        roadex_secret="roadex-approval-secret-12345",
    )
    finalized = finalize_activation_package(package)

    assert finalized["status"] == "ready_for_approval"
    assert verify_activation_package(package, finalized["packageDigest"])["verified"] is True
    assert activation_package_status(package)["status"] == "ready_for_approval"
    attestation = tmp_path / "canary-attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "schemaVersion": "overseer.activation-canary-acceptance.v1",
                "status": "passed",
                "packageDigest": finalized["packageDigest"],
                "controls": {
                    name: True
                    for name in activation_package_module.CANARY_REQUIRED_CONTROLS
                },
                "smokeExecutionId": "admin.exec.smoke",
                "smokeReplayId": "admin.exec.smoke",
                "secretValuesRecorded": False,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    attestation.chmod(0o600)
    monkeypatch.setattr(
        activation_package_module,
        "_canary_attestation_path",
        lambda _digest: attestation,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    assert verify_canary_attestation(
        package,
        expected_package_digest=finalized["packageDigest"],
        attestation_path=attestation,
    )["verified"] is True
    incomplete = json.loads(attestation.read_text(encoding="utf-8"))
    incomplete["controls"].pop("unlistedUnitRejected")
    attestation.write_text(
        json.dumps(incomplete, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(ActivationPackageError, match="controls are incomplete"):
        verify_canary_attestation(
            package,
            expected_package_digest=finalized["packageDigest"],
            attestation_path=attestation,
        )
    attestation.write_text(
        json.dumps(
            {
                **incomplete,
                "controls": {
                    name: True
                    for name in activation_package_module.CANARY_REQUIRED_CONTROLS
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    (package / "public" / "activation-contract.json").write_text("drift\n", encoding="utf-8")
    with pytest.raises(ActivationPackageError, match="drift"):
        verify_activation_package(package, finalized["packageDigest"])


def test_root_approval_record_binds_one_exact_sealed_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
    package, digest = _finalized_package(tmp_path)
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_approval_record_path",
        lambda: approval_path,
    )

    recorded = record_activation_approval(
        package,
        expected_package_digest=digest,
    )

    assert recorded["packageDigest"] == digest
    assert recorded["packageRoot"] == str(execution_package.resolve())
    assert recorded["sourcePackageRoot"] == str(package.resolve())
    assert stat_mode(approval_path) == 0o600
    assert verify_activation_package(execution_package, digest)["verified"] is True
    assert (
        execution_package / "public" / "activation-contract.json"
    ).stat().st_ino != (package / "public" / "activation-contract.json").stat().st_ino
    assert activation_package_module._load_activation_approval(execution_package) == recorded
    with pytest.raises(ActivationPackageError, match="already exists"):
        record_activation_approval(package, expected_package_digest=digest)


def test_installed_artifact_verifier_compares_targets_to_sealed_hashes(
    tmp_path: Path,
) -> None:
    package, digest = _finalized_package(tmp_path)
    source = package / "public" / "config" / "admin-executor-allowlist.json"
    target_directory = tmp_path / "installed"
    target_directory.mkdir(mode=0o700)
    target = target_directory / "allowlist.json"
    target.write_bytes(source.read_bytes())
    target.chmod(0o644)
    commands = [
        [
            "/usr/bin/install",
            "-d",
            "-o",
            "god",
            "-g",
            "god",
            "-m",
            "0700",
            str(target_directory),
        ],
        [
            "/usr/bin/install",
            "-o",
            "god",
            "-g",
            "god",
            "-m",
            "0644",
            str(source),
            str(target),
        ],
    ]

    result = activation_package_module._verify_install_results(
        package,
        expected_package_digest=digest,
        commands=commands,
    )

    assert result["verified"] is True
    target.write_text("drift\n", encoding="utf-8")
    with pytest.raises(ActivationPackageError, match="installed activation artifact is invalid"):
        activation_package_module._verify_install_results(
            package,
            expected_package_digest=digest,
            commands=commands,
        )


def test_live_canary_runner_enforces_exact_positive_negative_and_replay_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, digest = _finalized_package(tmp_path)
    installed = tmp_path / "installed-credentials"
    installed.mkdir(mode=0o700)
    for name in (
        "admin-approval-verifier.json",
        "roadex-fixture-approval-verifier.json",
        "api-token",
    ):
        source = package / "private" / "credentials" / name
        target = installed / name
        target.write_bytes(source.read_bytes())
        target.chmod(0o600)
    attestation = tmp_path / "canary-attestation.json"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package_module, "_installed_credential_root", lambda: installed)
    monkeypatch.setattr(
        activation_package_module,
        "verify_installed_staging",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_canary_attestation_path",
        lambda _digest: attestation,
    )

    class FakeClient:
        executions: dict[str, int] = {}

        def __init__(self, *, base_url: str, auth_token: str, approval_token: str | None = None) -> None:
            self.base_url = base_url
            self.auth_token = auth_token
            self.approval_token = approval_token

        def health(self) -> dict[str, object]:
            return {"ok": True, "service": "overseer-api"}

        def _get(self, path: str) -> dict[str, object]:
            assert path == "/health/codex-usage"
            return {"source": "codex.usage.snapshot.v1", "bridge_state": "available"}

        def _post(self, path: str, payload: dict[str, object]) -> dict[str, object]:
            assert path == "/agent-sessions/discover"
            assert payload["instance_id"] == "overseer.activation-canary"
            return {
                "mutation_performed": False,
                "host_mutation_performed": False,
                "bridge_state": "available",
            }

        def plan_admin_change(self, payload: dict[str, object]) -> dict[str, object]:
            return {"plan_id": payload["plan_id"]}

        def approve_admin_change(self, plan_id: str) -> dict[str, object]:
            if self.approval_token != "admin-approval-secret-123456":
                body = io.BytesIO(
                    json.dumps({"reason": "independent_approval_token_required"}).encode("utf-8")
                )
                raise HTTPError(self.base_url, 403, "denied", {}, body)
            return {"approved": True, "approved_by": "sisko", "plan_id": plan_id}

        def execute_admin_change(self, payload: dict[str, object]) -> dict[str, object]:
            plan_id = str(payload["plan_id"])
            self.executions[plan_id] = self.executions.get(plan_id, 0) + 1
            if ".unlisted." in plan_id:
                return {"status": "blocked", "mutation_performed": False, "id": f"exec.{plan_id}"}
            if self.executions[plan_id] == 1:
                return {"status": "completed", "mutation_performed": True, "id": f"exec.{plan_id}"}
            return {
                "status": "completed",
                "mutation_performed": False,
                "replayed": True,
                "id": f"exec.{plan_id}",
            }

    monkeypatch.setattr("overseer.client.OverseerApiClient", FakeClient)

    result = run_canary_acceptance(
        package,
        expected_package_digest=digest,
        admin_secret="admin-approval-secret-123456",
        roadex_secret="roadex-approval-secret-12345",
        attestation_path=attestation,
    )

    assert result["status"] == "passed"
    assert set(result["controls"]) == set(activation_package_module.CANARY_REQUIRED_CONTROLS)
    assert all(result["controls"].values())
    assert result["smokeExecutionId"] == result["smokeReplayId"]
    assert verify_canary_attestation(
        package,
        expected_package_digest=digest,
        attestation_path=attestation,
    )["verified"] is True


def test_root_rollback_bundle_is_exact_and_drift_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, _digest = _finalized_package(tmp_path)
    package_manifest = package / "public" / "rollback-manifest.json"
    document = json.loads(package_manifest.read_text(encoding="utf-8"))
    bundle_root = tmp_path / "root-bundle"
    bundle_root.mkdir(mode=0o755)
    for item in document["inputs"]:
        bundle = item["bundle"]
        for entry in bundle["files"]:
            relative = Path(bundle["relativeRoot"]) / entry["relativePath"]
            source = package / "private" / "rollback-inputs" / relative
            target = bundle_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(int(entry["mode"], 8))
    for directory in sorted(
        (path for path in bundle_root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        directory.chmod(0o555)
    bundle_root.chmod(0o555)
    root_manifest = tmp_path / "root-rollback-manifest.json"
    root_manifest.write_bytes(package_manifest.read_bytes())
    root_manifest.chmod(0o644)
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    verified = activation_package_module.verify_rollback_bundle(
        bundle_root=bundle_root,
        rollback_manifest=root_manifest,
    )

    assert verified["verified"] is True
    first_file = next(path for path in bundle_root.rglob("*") if path.is_file())
    first_file.chmod(0o600)
    first_file.write_text("drift\n", encoding="utf-8")
    first_file.chmod(0o400)
    with pytest.raises(ActivationPackageError, match="bundle artifact drift"):
        activation_package_module.verify_rollback_bundle(
            bundle_root=bundle_root,
            rollback_manifest=root_manifest,
        )


def test_compatibility_token_comes_from_installed_root_state_and_stays_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "installed-api-token"
    source.write_bytes(b"approved-token")
    source.chmod(0o600)
    parent = tmp_path / "legacy-state"
    parent.mkdir(mode=0o700)
    target = parent / "api-token"
    target.write_bytes(source.read_bytes())
    target.chmod(0o640)
    parent.chmod(0o555)
    parent_metadata = parent.stat()
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    verified = activation_package_module.verify_compatibility_token(
        source_token=source,
        target_token=target,
        expected_target_uid=os.geteuid(),
        expected_target_gid=os.getegid(),
        expected_parent_device=parent_metadata.st_dev,
        expected_parent_inode=parent_metadata.st_ino,
    )

    assert verified["verified"] is True
    target.chmod(0o600)
    with pytest.raises(ActivationPackageError, match="compatibility API token"):
        activation_package_module.verify_compatibility_token(
            source_token=source,
            target_token=target,
            expected_target_uid=os.geteuid(),
            expected_target_gid=os.getegid(),
            expected_parent_device=parent_metadata.st_dev,
            expected_parent_inode=parent_metadata.st_ino,
        )


def test_activation_runner_enforces_order_state_and_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    package = tmp_path / "package"
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [["/bin/true", "staging"]],
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval",
        lambda _package: {"packageDigest": digest},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_sealed_package_json",
        lambda *_args, **_kwargs: contract,
    )
    monkeypatch.setattr(
        activation_package_module,
        "verify_approved_cutover",
        lambda _package: {"verified": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )

    first = activation_package_module.execute_approved_activation(package)
    second = activation_package_module.execute_approved_activation(package)

    assert first == {"status": "complete", "packageDigest": digest, "replayed": False}
    assert second == {"status": "complete", "packageDigest": digest, "replayed": True}
    assert calls == [("/bin/true", "staging"), ("/bin/true", "cutover")]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "complete"
    assert state["phase"] == "complete"
    assert state["secretValuesRecorded"] is False


def test_activation_runner_rolls_back_cutover_failure_and_refuses_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "b" * 64
    package = tmp_path / "package"
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [["/bin/true", "staging"]],
        "cutoverCommands": [["/bin/false", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval",
        lambda _package: {"packageDigest": digest},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_sealed_package_json",
        lambda *_args, **_kwargs: contract,
    )
    monkeypatch.setattr(
        activation_package_module,
        "verify_approved_cutover",
        lambda _package: {"verified": True},
    )

    def execute(command: list[str]) -> int:
        calls.append(tuple(command))
        return 1 if command[1] == "cutover" else 0

    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)

    with pytest.raises(ActivationPackageError, match="sealed rollback completed"):
        activation_package_module.execute_approved_activation(package)
    assert calls == [
        ("/bin/true", "staging"),
        ("/bin/false", "cutover"),
        ("/bin/true", "rollback"),
    ]
    assert activation_package_module.execute_approved_rollback(package) == {
        "status": "rolled_back",
        "packageDigest": digest,
        "replayed": True,
    }
    with pytest.raises(ActivationPackageError, match="not safely resumable"):
        activation_package_module.execute_approved_activation(package)
