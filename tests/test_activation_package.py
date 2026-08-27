from __future__ import annotations

import array
import errno
import hashlib
import io
import json
import os
import socket
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
    stage_sqlite_runtime_input,
    verify_activation_package,
    verify_canary_attestation,
    verify_rollback_inputs,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_SQLITE_BINARY_SHA256 = activation_package_module.APPROVED_SQLITE_BINARY_SHA256
PRODUCTION_SQLITE_PROBE = activation_package_module._probe_sqlite_runtime


@pytest.fixture(autouse=True)
def _restore_production_sqlite_digest() -> object:
    yield
    activation_package_module.APPROVED_SQLITE_BINARY_SHA256 = (
        PRODUCTION_SQLITE_BINARY_SHA256
    )
    activation_package_module._probe_sqlite_runtime = PRODUCTION_SQLITE_PROBE


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


def _sqlite_runtime(
    tmp_path: Path,
    *,
    payload: bytes = b"approved-sqlite-runtime",
    package_root: Path | None = None,
) -> tuple[Path, dict[str, object]]:
    source = tmp_path / "sqlite-runtime-source.so.0"
    source.write_bytes(payload)
    source.chmod(0o555)
    activation_package_module.APPROVED_SQLITE_BINARY_SHA256 = hashlib.sha256(
        payload
    ).hexdigest()
    package = package_root or (tmp_path / "activation-package")
    staged = stage_sqlite_runtime_input(package, source_library=source)
    library = Path(str(staged["path"]))
    metadata = library.stat()
    evidence = {
        "version": activation_package_module.APPROVED_SQLITE_VERSION,
        "sourceId": activation_package_module.APPROVED_SQLITE_SOURCE_ID,
        "mappedExpectedLibrary": True,
        "mappedDevice": metadata.st_dev,
        "mappedInode": metadata.st_ino,
        "compileOptions": sorted(activation_package_module.REQUIRED_SQLITE_COMPILE_OPTIONS),
    }
    activation_package_module._probe_sqlite_runtime = (
        lambda _python, _library, _metadata: evidence
    )
    return library, evidence


def test_sqlite_runtime_has_independent_binary_digest_and_reproducible_recipe(
    tmp_path: Path,
) -> None:
    assert PRODUCTION_SQLITE_BINARY_SHA256 == (
        "ca4c66d9a6b3d24b27e05f8d1cfd7ae620e5862df39c96164910885797d6fc2e"
    )
    script = ROOT / "scripts" / "build_sqlite_runtime.sh"
    content = script.read_text(encoding="utf-8")
    assert PRODUCTION_SQLITE_BINARY_SHA256 in content
    assert activation_package_module.APPROVED_SQLITE_ARCHIVE_SHA3_256 in content
    assert "/usr/bin/gcc" in content
    assert stat_mode(script) == 0o555

    unapproved = tmp_path / "unapproved-libsqlite3.so.0"
    unapproved.write_bytes(b"unapproved")
    unapproved.chmod(0o555)
    with pytest.raises(ActivationPackageError, match="independently approved"):
        stage_sqlite_runtime_input(
            tmp_path / "activation-package",
            source_library=unapproved,
        )


def test_sqlite_runtime_stage_cli_creates_only_closed_approved_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = b"approved-cli-sqlite-runtime"
    source = tmp_path / "libsqlite3.so.0"
    source.write_bytes(payload)
    source.chmod(0o555)
    package_parent = tmp_path / "activation-packages"
    package_parent.mkdir(mode=0o700)
    package = package_parent / "v1.1.6-abcdef0"
    monkeypatch.setattr(activation_package_module, "APPROVED_PACKAGE_PARENT", package_parent)
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_SQLITE_BINARY_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )

    assert activation_package_module._main(
        [
            "stage-sqlite-runtime",
            "--source-library",
            str(source),
            "--package-root",
            str(package),
        ]
    ) == 0

    result = json.loads(capsys.readouterr().out)
    target = package / activation_package_module.STAGED_SQLITE_RUNTIME
    assert result["status"] == "staged"
    assert result["path"] == str(target)
    assert target.read_bytes() == payload
    assert stat_mode(target) == 0o555
    assert stat_mode(target.parent) == 0o500
    assert activation_package_module._validate_sqlite_staged_package_destination(package) == package


def test_release_manifest_is_stable_closed_and_hashes_exact_inputs(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, sqlite_evidence = _sqlite_runtime(tmp_path)

    first = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
    )
    second = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
    )

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
    assert first["sqliteRuntime"] == {
        "path": str(sqlite_library),
        "stagedInputPackage": str(tmp_path / "activation-package"),
        "releasePath": "lib/libsqlite3.so.0",
        "sha256": hashlib.sha256(b"approved-sqlite-runtime").hexdigest(),
        "size": len(b"approved-sqlite-runtime"),
        "mode": 0o555,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "device": sqlite_library.stat().st_dev,
        "inode": sqlite_library.stat().st_ino,
        "version": activation_package_module.APPROVED_SQLITE_VERSION,
        "sourceId": activation_package_module.APPROVED_SQLITE_SOURCE_ID,
        "sourceArchiveSha3_256": (
            activation_package_module.APPROVED_SQLITE_ARCHIVE_SHA3_256
        ),
        "buildProvenance": {
            "recipe": activation_package_module.APPROVED_SQLITE_BUILD_RECIPE,
            "compiler": activation_package_module.APPROVED_SQLITE_COMPILER,
            "sourceArchiveUrl": (
                "https://www.sqlite.org/2026/sqlite-autoconf-3530400.tar.gz"
            ),
            "sourceArchiveSha3_256": (
                activation_package_module.APPROVED_SQLITE_ARCHIVE_SHA3_256
            ),
            "binarySha256": hashlib.sha256(b"approved-sqlite-runtime").hexdigest(),
            "compileDefinitions": list(
                activation_package_module.APPROVED_SQLITE_BUILD_DEFINITIONS
            ),
        },
        "compileOptions": sorted(
            activation_package_module.REQUIRED_SQLITE_COMPILE_OPTIONS
        ),
        "walResetFixAttested": True,
    }


@pytest.mark.parametrize(
    "invalid_field",
    (
        "version",
        "sourceId",
        "mappedExpectedLibrary",
        "mappedDevice",
        "mappedInode",
        "compileOptions",
    ),
)
def test_release_manifest_rejects_unapproved_sqlite_runtime_identity(
    tmp_path: Path,
    invalid_field: str,
) -> None:
    checkout = _reviewed_checkout(tmp_path)
    sqlite_library, evidence = _sqlite_runtime(tmp_path)
    invalid_evidence = dict(evidence)
    if invalid_field == "mappedExpectedLibrary":
        invalid_evidence[invalid_field] = False
    elif invalid_field in {"mappedDevice", "mappedInode"}:
        invalid_evidence[invalid_field] = -1
    elif invalid_field == "compileOptions":
        invalid_evidence[invalid_field] = []
    else:
        invalid_evidence[invalid_field] = "unapproved"
    activation_package_module._probe_sqlite_runtime = (
        lambda _python, _library, _metadata: invalid_evidence
    )

    with pytest.raises(ActivationPackageError, match="identity or features"):
        build_release_manifest(
            checkout,
            _dependencies(tmp_path),
            _python(tmp_path),
            _stdlib(tmp_path),
            sqlite_library,
        )


def test_release_manifest_rejects_mutable_or_linked_sqlite_runtime(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, evidence = _sqlite_runtime(tmp_path)
    sqlite_library.chmod(0o755)

    with pytest.raises(ActivationPackageError, match="metadata"):
        build_release_manifest(
            checkout,
            dependencies,
            python,
            stdlib,
            sqlite_library,
        )

    sqlite_library.chmod(0o555)
    linked_library = tmp_path / "linked-libsqlite3.so.0"
    linked_library.symlink_to(sqlite_library)
    with pytest.raises(ActivationPackageError, match="regular file|metadata"):
        build_release_manifest(
            checkout,
            dependencies,
            python,
            stdlib,
            linked_library,
        )


def test_release_manifest_rejects_sqlite_inode_replacement_during_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = _reviewed_checkout(tmp_path)
    sqlite_library, evidence = _sqlite_runtime(tmp_path)
    runtime_directory = sqlite_library.parent

    def replace_during_probe(
        _root_python: Path,
        _sqlite_library: Path,
        _metadata: os.stat_result,
    ) -> dict[str, object]:
        runtime_directory.chmod(0o700)
        sqlite_library.unlink()
        sqlite_library.write_bytes(b"approved-sqlite-runtime")
        sqlite_library.chmod(0o555)
        runtime_directory.chmod(0o500)
        return evidence

    monkeypatch.setattr(
        activation_package_module,
        "_probe_sqlite_runtime",
        replace_during_probe,
    )
    with pytest.raises(ActivationPackageError, match="drifted during attestation"):
        build_release_manifest(
            checkout,
            _dependencies(tmp_path),
            _python(tmp_path),
            _stdlib(tmp_path),
            sqlite_library,
        )

@pytest.mark.skipif(
    not Path("/usr/bin/python3.13").is_file()
    or not Path("/usr/lib/python3.13").is_dir()
    or not Path("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6").is_file(),
    reason="host Python 3.13 runtime is unavailable",
)
def test_copied_release_runtime_executes_with_release_local_pythonhome(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = Path("/usr/bin/python3.13")
    stdlib = Path("/usr/lib/python3.13")
    sqlite_library, sqlite_evidence = _sqlite_runtime(
        tmp_path,
        payload=Path("/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6").read_bytes(),
    )
    manifest = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
    )
    package = tmp_path / "activation-package"
    release = stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )
    staged_python = release / "runtime" / "bin" / "python3.13"
    hostile_userbase = tmp_path / "hostile-userbase"
    hostile_site = hostile_userbase / "lib" / "python3.13" / "site-packages"
    hostile_site.mkdir(parents=True)
    hostile_marker = tmp_path / "hostile-site-loaded"
    (hostile_site / "sitecustomize.py").write_text(
        "import os, pathlib\npathlib.Path(os.environ['HOSTILE_MARKER']).write_text('loaded')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [str(staged_python), "-s", "-P", "-c", "import json, sqlite3, ssl; print('runtime-ok')"],
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONHOME": str(release / "runtime"),
            "PYTHONPATH": f"{release / 'app' / 'src'}:{release / 'site-packages'}",
            "PYTHONUSERBASE": str(hostile_userbase),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "LD_LIBRARY_PATH": str(release / "lib"),
            "HOSTILE_MARKER": str(hostile_marker),
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "runtime-ok"
    assert not hostile_marker.exists()


def test_release_manifest_rejects_dirty_tree_and_dependency_symlink(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, sqlite_evidence = _sqlite_runtime(tmp_path)
    (checkout / "src" / "overseer" / "cli.py").write_text("changed\n", encoding="utf-8")

    with pytest.raises(ActivationPackageError, match="clean"):
        build_release_manifest(
            checkout,
            dependencies,
            python,
            stdlib,
            sqlite_library,
        )

    _git(checkout, "checkout", "--", "src/overseer/cli.py")
    (dependencies / "unsafe").symlink_to(dependencies / "dependency")
    with pytest.raises(ActivationPackageError, match="symlink"):
        build_release_manifest(
            checkout,
            dependencies,
            python,
            stdlib,
            sqlite_library,
        )

    (dependencies / "unsafe").unlink()
    linked_root = tmp_path / "linked-site-packages"
    linked_root.symlink_to(dependencies, target_is_directory=True)
    with pytest.raises(ActivationPackageError, match="roots.*symlink"):
        build_release_manifest(
            checkout,
            linked_root,
            python,
            stdlib,
            sqlite_library,
        )


def test_stage_release_payload_and_render_units_are_exact(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, sqlite_evidence = _sqlite_runtime(tmp_path)
    manifest = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
    )
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
    assert (staged_release / "lib" / "libsqlite3.so.0").read_bytes() == b"approved-sqlite-runtime"
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
    for name in (
        "overseer-admin-executor@.service",
        "overseer-api-canary.service",
        "overseer-api.service",
        "overseer-codex-user-bridge.service",
        "overseer-runtime.service",
    ):
        assert (
            f"Environment=LD_LIBRARY_PATH={manifest['releaseRoot']}/lib"
            in rendered[name].read_text(encoding="utf-8")
        )
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


def _stale_expression_index_store(path: Path, *, journal_mode: str) -> bytes:
    old_timestamp = "2026-01-01T00:00:00Z"
    new_timestamp = "2026-02-01T00:00:00Z"
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            f"PRAGMA journal_mode={journal_mode}"
        ).fetchone()[0].lower() == journal_mode.lower()
        connection.execute(
            "CREATE TABLE host_snapshots (id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE INDEX idx_host_snapshots_captured_at ON host_snapshots "
            "(julianday(json_extract(payload, '$.captured_at')) DESC, id DESC)"
        )
        connection.execute(
            "INSERT INTO host_snapshots(id, payload) VALUES (?, ?)",
            ("snapshot-1", json.dumps({"captured_at": old_timestamp}, separators=(",", ":"))),
        )
        connection.commit()
        if journal_mode.upper() == "WAL":
            assert connection.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)"
            ).fetchone()[0] == 0
    path.chmod(0o600)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            sidecar.chmod(0o600)
    original = path.read_bytes()
    assert original.count(old_timestamp.encode("ascii")) == 1
    changed = original.replace(
        old_timestamp.encode("ascii"),
        new_timestamp.encode("ascii"),
    )
    path.write_bytes(changed)
    path.chmod(0o600)
    return changed


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


def test_copied_expression_index_normalization_repairs_only_the_copy(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "copied.sqlite3"
    changed = _stale_expression_index_store(copied, journal_mode="DELETE")
    with pytest.raises(ActivationPackageError, match="integrity_check"):
        activation_package_module._integrity_check(copied)

    result = activation_package_module._normalize_copied_expression_indexes(copied)

    assert result == {
        "preReindexQuickCheck": "ok",
        "reindexedExpressionIndexes": ["idx_host_snapshots_captured_at"],
        "journalMode": "delete",
        "sourceMutationPerformed": False,
    }
    assert activation_package_module._integrity_check(copied) == "ok"
    assert copied.read_bytes() != changed
    assert not Path(f"{copied}-wal").exists()
    assert not Path(f"{copied}-shm").exists()


def test_rehearsal_normalizes_expression_index_without_mutating_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    source_before = _stale_expression_index_store(source, journal_mode="WAL")

    report = rehearse_store_migration(
        tmp_path / "activation-package",
        source_store=source,
        pages_per_step=-1,
        sleep_seconds=0,
    )

    assert report["copyNormalization"] == {
        "preReindexQuickCheck": "ok",
        "reindexedExpressionIndexes": ["idx_host_snapshots_captured_at"],
        "journalMode": "delete",
        "sourceMutationPerformed": False,
    }
    assert source.read_bytes() == source_before
    assert report["backup"]["integrityCheck"] == "ok"
    assert report["migrated"]["integrityCheck"] == "ok"


def test_copied_expression_index_normalization_rejects_unapproved_schema(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "copied.sqlite3"
    with sqlite3.connect(copied) as connection:
        connection.execute(
            "CREATE TABLE host_snapshots (id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE INDEX idx_host_snapshots_captured_at ON host_snapshots (id)"
        )
    copied.chmod(0o600)

    with pytest.raises(ActivationPackageError, match="schema is unapproved"):
        activation_package_module._normalize_copied_expression_indexes(copied)


def test_rehearsal_backup_remains_consistent_while_wal_writer_commits(tmp_path: Path) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    connection = sqlite3.connect(source)
    connection.executemany(
        "INSERT INTO retained_items(value) VALUES (?)",
        (("x" * 4096,) for _ in range(8192)),
    )
    connection.commit()
    connection.close()
    errors: list[BaseException] = []
    commit_times: list[int] = []
    writer_started = threading.Event()
    stop_writer = threading.Event()

    def writer() -> None:
        writer_connection = sqlite3.connect(source, timeout=2)
        try:
            while not stop_writer.is_set():
                writer_connection.execute(
                    "INSERT INTO retained_items(value) VALUES (?)",
                    ("concurrent",),
                )
                writer_connection.commit()
                commit_times.append(time.time_ns())
                writer_started.set()
        except BaseException as error:
            errors.append(error)
        finally:
            writer_connection.close()

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    assert writer_started.wait(timeout=2)
    try:
        report = rehearse_store_migration(
            tmp_path / "activation-package",
            source_store=source,
            pages_per_step=-1,
            sleep_seconds=0,
        )
    finally:
        stop_writer.set()
    thread.join(timeout=5)

    assert not errors
    assert not thread.is_alive()
    backup_bounds = report["backupBounds"]
    assert backup_bounds["pagesPerStep"] == -1
    assert backup_bounds["sleepSeconds"] == 0
    assert backup_bounds["singleStep"] is True
    assert any(
        backup_bounds["startedUnixNs"] <= committed_at <= backup_bounds["completedUnixNs"]
        for committed_at in commit_times
    )
    assert report["backup"]["integrityCheck"] == "ok"
    assert report["migrated"]["integrityCheck"] == "ok"
    assert report["rowCountsBefore"] == report["rowCountsAfter"]


def test_rehearsal_backup_rejects_non_wal_store(tmp_path: Path) -> None:
    source = tmp_path / "overseer.sqlite3"
    with sqlite3.connect(source) as connection:
        assert connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
        connection.execute("CREATE TABLE retained_items(id INTEGER PRIMARY KEY, value TEXT)")
    source.chmod(0o600)
    package = tmp_path / "activation-package"

    with pytest.raises(ActivationPackageError, match="WAL mode"):
        rehearse_store_migration(
            package,
            source_store=source,
            pages_per_step=-1,
            sleep_seconds=0,
        )

    assert not (package / "private" / "migration" / "rehearsal-source.sqlite3").exists()


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


def test_activation_contract_rejects_a_different_source_than_the_rehearsal(
    tmp_path: Path,
) -> None:
    package, manifest, _source = _prepared_package(tmp_path)
    replacement = tmp_path / "different-overseer.sqlite3"
    _wal_store(replacement)
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    (rollback / "src.py").write_text("rollback input\n", encoding="utf-8")

    with pytest.raises(ActivationPackageError, match="rehearsal source"):
        render_activation_contract(
            package,
            manifest,
            source_store=replacement,
            overseer_uid=984,
            overseer_gid=984,
            rollback_inputs={"v1.1.5-release": rollback},
        )


def test_activation_contract_rejects_source_inode_replacement_after_rehearsal(
    tmp_path: Path,
) -> None:
    package, manifest, source = _prepared_package(tmp_path)
    source.unlink()
    _wal_store(source)
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    (rollback / "src.py").write_text("rollback input\n", encoding="utf-8")

    with pytest.raises(ActivationPackageError, match="rehearsal source"):
        render_activation_contract(
            package,
            manifest,
            source_store=source,
            overseer_uid=984,
            overseer_gid=984,
            rollback_inputs={"v1.1.5-release": rollback},
        )


@pytest.mark.parametrize("pages_per_step", [-2, 0, 4097])
def test_rehearsal_backup_rejects_unapproved_page_step_values(
    tmp_path: Path,
    pages_per_step: int,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)

    with pytest.raises(ActivationPackageError, match="pages_per_step"):
        rehearse_store_migration(
            tmp_path / f"package-{pages_per_step}",
            source_store=source,
            pages_per_step=pages_per_step,
            sleep_seconds=0,
        )


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
    assert report["quiescenceLock"] == "kernel-read-leases-and-write-access-revoked"
    assert report["kernelReadLeaseBarrier"] == "held-through-source-hashes-and-backup"
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


def test_final_migration_copies_and_normalizes_a_crash_retained_wal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    creator = subprocess.run(
        [
            "/usr/bin/python3.13",
            "-c",
            """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode=WAL")
connection.execute("PRAGMA wal_autocheckpoint=0")
connection.execute("CREATE TABLE retained_items(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
connection.executemany(
    "INSERT INTO retained_items(value) VALUES (?)",
    [("one",), ("two",), ("three",)],
)
connection.commit()
os._exit(0)
""",
            str(source),
        ],
        check=False,
    )
    assert creator.returncode == 0
    source.chmod(0o600)
    source_wal = Path(f"{source}-wal")
    source_shm = Path(f"{source}-shm")
    assert source_wal.stat().st_size > 0
    source_wal.chmod(0o600)
    if source_shm.exists():
        source_shm.chmod(0o600)
    source_before = source.read_bytes()
    wal_before = source_wal.read_bytes()
    approved = source.stat()
    parent = source.parent.stat()
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

    report = prepare_final_store_migration(
        source_store=source,
        backup_store=backup,
        destination_store=destination,
        expected_source_device=approved.st_dev,
        expected_source_inode=approved.st_ino,
        expected_source_uid=os.geteuid(),
        expected_source_gid=os.getegid(),
        expected_parent_device=parent.st_dev,
        expected_parent_inode=parent.st_ino,
        expected_parent_mode=parent_mode,
        destination_uid=os.geteuid(),
        destination_gid=os.getegid(),
        sleep_seconds=0,
    )

    assert report["source"]["walCheckpoint"] == "isolated_backup_truncate_complete"
    assert source.read_bytes() == source_before
    assert source_wal.read_bytes() == wal_before
    assert not Path(f"{backup}-wal").exists()
    assert not Path(f"{backup}-shm").exists()
    with sqlite3.connect(backup) as connection:
        assert connection.execute(
            "SELECT value FROM retained_items ORDER BY id"
        ).fetchall() == [("one",), ("two",), ("three",)]
    restore_legacy_store_access(
        source_store=source,
        expected_source_uid=os.geteuid(),
        expected_source_gid=os.getegid(),
        expected_source_device=approved.st_dev,
        expected_source_inode=approved.st_ino,
        expected_parent_device=parent.st_dev,
        expected_parent_inode=parent.st_ino,
        expected_parent_mode=parent_mode,
    )


def test_final_migration_rejects_source_replacement_during_parent_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    approved = source.stat()
    parent = source.parent.stat()
    parent_mode = stat_mode(source.parent)
    backup_parent = tmp_path / "executor-state"
    destination_parent = tmp_path / "authority-state"
    backup_parent.mkdir(mode=0o700)
    destination_parent.mkdir(mode=0o700)
    backup = backup_parent / "final-source.sqlite3"
    destination = destination_parent / "final-migrated.sqlite3"
    displaced = tmp_path / "approved-displaced.sqlite3"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)
    real_fchown = os.fchown
    replacement_performed = False

    def replace_after_parent_ownership_change(
        descriptor: int,
        uid: int,
        gid: int,
    ) -> None:
        nonlocal replacement_performed
        real_fchown(descriptor, uid, gid)
        opened = os.fstat(descriptor)
        if not replacement_performed and (opened.st_dev, opened.st_ino) == (
            parent.st_dev,
            parent.st_ino,
        ):
            replacement_performed = True
            source.rename(displaced)
            _wal_store(source)
            with sqlite3.connect(source) as connection:
                connection.execute(
                    "INSERT INTO retained_items(value) VALUES ('attacker-selected')"
                )

    monkeypatch.setattr(os, "fchown", replace_after_parent_ownership_change)

    with pytest.raises(ActivationPackageError, match="identity drifted"):
        prepare_final_store_migration(
            source_store=source,
            backup_store=backup,
            destination_store=destination,
            expected_source_device=approved.st_dev,
            expected_source_inode=approved.st_ino,
            expected_source_uid=os.geteuid(),
            expected_source_gid=os.getegid(),
            expected_parent_device=parent.st_dev,
            expected_parent_inode=parent.st_ino,
            expected_parent_mode=parent_mode,
            destination_uid=os.geteuid(),
            destination_gid=os.getegid(),
            sleep_seconds=0,
        )

    assert replacement_performed is True
    assert displaced.stat().st_ino == approved.st_ino
    assert not backup.exists()
    assert not destination.exists()
    assert not backup.with_suffix(f"{backup.suffix}.report.json").exists()


def test_final_migration_rejects_closed_fd_shared_mapping(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    approved = source.stat()
    parent = source.parent.stat()
    parent_mode = stat_mode(source.parent)
    backup_parent = tmp_path / "executor-state"
    destination_parent = tmp_path / "authority-state"
    backup_parent.mkdir(mode=0o700)
    destination_parent.mkdir(mode=0o700)
    backup = backup_parent / "final-source.sqlite3"
    destination = destination_parent / "final-migrated.sqlite3"
    unrelated = tmp_path / "mäpped-unrelated.bin"
    unrelated.write_bytes(b"U" * 4096)
    unrelated.chmod(0o600)
    mapper = subprocess.Popen(
        [
            "/usr/bin/python3.13",
            "-c",
            """
import ctypes
import os
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.restype = ctypes.c_void_p
fd = os.open(sys.argv[1], os.O_RDWR)
size = os.fstat(fd).st_size
address = libc.mmap(None, size, 3, 1, fd, 0)
if address == ctypes.c_void_p(-1).value:
    raise OSError(ctypes.get_errno(), "mmap failed")
os.close(fd)
other_fd = os.open(sys.argv[2], os.O_RDONLY)
other_size = os.fstat(other_fd).st_size
other_address = libc.mmap(None, other_size, 1, 2, other_fd, 0)
if other_address == ctypes.c_void_p(-1).value:
    raise OSError(ctypes.get_errno(), "unrelated mmap failed")
os.close(other_fd)
print("ready", flush=True)
sys.stdin.readline()
if libc.munmap(ctypes.c_void_p(address), size) != 0:
    raise OSError(ctypes.get_errno(), "munmap failed")
if libc.munmap(ctypes.c_void_p(other_address), other_size) != 0:
    raise OSError(ctypes.get_errno(), "unrelated munmap failed")
""",
            str(source),
            str(unrelated),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert mapper.stdout is not None
    assert mapper.stdin is not None
    assert mapper.stdout.readline().strip() == "ready"
    assert mapper.pid not in activation_package_module._processes_with_open_inode(
        approved.st_dev,
        approved.st_ino,
    )
    assert mapper.pid in activation_package_module._processes_with_mapped_inode(
        approved.st_dev,
        approved.st_ino,
    )
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)
    try:
        with pytest.raises(ActivationPackageError, match="mapping"):
            prepare_final_store_migration(
                source_store=source,
                backup_store=backup,
                destination_store=destination,
                expected_source_device=approved.st_dev,
                expected_source_inode=approved.st_ino,
                expected_source_uid=os.geteuid(),
                expected_source_gid=os.getegid(),
                expected_parent_device=parent.st_dev,
                expected_parent_inode=parent.st_ino,
                expected_parent_mode=parent_mode,
                destination_uid=os.geteuid(),
                destination_gid=os.getegid(),
                sleep_seconds=0,
            )
    finally:
        mapper.stdin.write("stop\n")
        mapper.stdin.flush()
        mapper.wait(timeout=5)

    assert mapper.returncode == 0
    assert not backup.exists()
    assert not destination.exists()


@pytest.mark.parametrize(
    ("failure_location", "expected_message"),
    (
        ("fd-table", "descriptor table"),
        ("descriptor", "live process descriptor"),
    ),
)
def test_open_inode_scan_fails_closed_for_root_permission_errors(
    monkeypatch: pytest.MonkeyPatch,
    failure_location: str,
    expected_message: str,
) -> None:
    class ProcNode:
        def __init__(self, kind: str, name: str = "") -> None:
            self.kind = kind
            self.name = name

        def __truediv__(self, child: str) -> ProcNode:
            assert self.kind == "process"
            assert child == "fd"
            return ProcNode("fd")

        def iterdir(self) -> tuple[ProcNode, ...]:
            if self.kind == "proc":
                return (ProcNode("process", "4242"),)
            if self.kind == "fd" and failure_location == "fd-table":
                raise PermissionError("descriptor table denied")
            if self.kind == "fd":
                return (ProcNode("descriptor"),)
            raise AssertionError(f"unexpected node kind: {self.kind}")

        def stat(self) -> os.stat_result:
            assert self.kind == "descriptor"
            raise PermissionError("descriptor denied")

    def fake_path(value: str) -> ProcNode:
        assert value == "/proc"
        return ProcNode("proc")

    monkeypatch.setattr(activation_package_module, "Path", fake_path)
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with pytest.raises(ActivationPackageError, match=expected_message):
        activation_package_module._processes_with_open_inode(1, 2)


def test_final_migration_rejects_scm_rights_queued_writable_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    approved = source.stat()
    parent = source.parent.stat()
    parent_mode = stat_mode(source.parent)
    backup_parent = tmp_path / "executor-state"
    destination_parent = tmp_path / "authority-state"
    backup_parent.mkdir(mode=0o700)
    destination_parent.mkdir(mode=0o700)
    backup = backup_parent / "final-source.sqlite3"
    destination = destination_parent / "final-migrated.sqlite3"
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    queued_descriptor = os.open(source, os.O_RDWR)
    try:
        assert sender.sendmsg(
            [b"queued-writer"],
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", [queued_descriptor]),
                )
            ],
        ) == len(b"queued-writer")
    finally:
        os.close(queued_descriptor)

    assert os.getpid() not in activation_package_module._processes_with_open_inode(
        approved.st_dev,
        approved.st_ino,
    )
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)
    try:
        with pytest.raises(ActivationPackageError, match="lease barrier rejected"):
            prepare_final_store_migration(
                source_store=source,
                backup_store=backup,
                destination_store=destination,
                expected_source_device=approved.st_dev,
                expected_source_inode=approved.st_ino,
                expected_source_uid=os.geteuid(),
                expected_source_gid=os.getegid(),
                expected_parent_device=parent.st_dev,
                expected_parent_inode=parent.st_ino,
                expected_parent_mode=parent_mode,
                destination_uid=os.geteuid(),
                destination_gid=os.getegid(),
                sleep_seconds=0,
            )
    finally:
        receiver.close()
        sender.close()

    assert not backup.exists()
    assert not destination.exists()
    assert stat_mode(source) == 0o600
    assert stat_mode(source.parent) == parent_mode


def test_final_migration_rejects_dequeued_write_closed_before_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    approved = source.stat()
    parent = source.parent.stat()
    parent_mode = stat_mode(source.parent)
    backup_parent = tmp_path / "executor-state"
    destination_parent = tmp_path / "authority-state"
    backup_parent.mkdir(mode=0o700)
    destination_parent.mkdir(mode=0o700)
    backup = backup_parent / "final-source.sqlite3"
    destination = destination_parent / "final-migrated.sqlite3"
    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    queued_descriptor = os.open(source, os.O_RDWR)
    try:
        sender.sendmsg(
            [b"queued-writer"],
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", [queued_descriptor]),
                )
            ],
        )
    finally:
        os.close(queued_descriptor)

    real_fcntl = activation_package_module.fcntl.fcntl
    attack_performed = False

    def dequeue_write_and_close(
        descriptor: int,
        command: int,
        *args: object,
    ) -> object:
        nonlocal attack_performed
        if command == activation_package_module.fcntl.F_SETOWN and not attack_performed:
            attack_performed = True
            received = array.array("i")
            _message, ancillary, _flags, _address = receiver.recvmsg(
                1,
                socket.CMSG_SPACE(received.itemsize),
            )
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    received.frombytes(data[: received.itemsize])
            assert len(received) == 1
            attack_descriptor = received[0]
            try:
                time.sleep(0.01)
                content = os.pread(attack_descriptor, approved.st_size, 0)
                offset = content.find(b"three")
                assert offset >= 0
                assert os.pwrite(attack_descriptor, b"PWNED", offset) == len(b"PWNED")
                os.fsync(attack_descriptor)
            finally:
                os.close(attack_descriptor)
        return real_fcntl(descriptor, command, *args)

    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)
    monkeypatch.setattr(activation_package_module.fcntl, "fcntl", dequeue_write_and_close)
    try:
        with pytest.raises(ActivationPackageError, match="descriptor changed before"):
            prepare_final_store_migration(
                source_store=source,
                backup_store=backup,
                destination_store=destination,
                expected_source_device=approved.st_dev,
                expected_source_inode=approved.st_ino,
                expected_source_uid=os.geteuid(),
                expected_source_gid=os.getegid(),
                expected_parent_device=parent.st_dev,
                expected_parent_inode=parent.st_ino,
                expected_parent_mode=parent_mode,
                destination_uid=os.geteuid(),
                destination_gid=os.getegid(),
                sleep_seconds=0,
            )
    finally:
        receiver.close()
        sender.close()

    assert attack_performed is True
    assert not backup.exists()
    assert not destination.exists()
    with sqlite3.connect(source) as connection:
        assert connection.execute(
            "SELECT value FROM retained_items ORDER BY id"
        ).fetchall()[-1] == ("PWNED",)
    assert stat_mode(source) == 0o600
    assert stat_mode(source.parent) == parent_mode


def test_kernel_read_lease_barrier_rejects_a_new_writer(tmp_path: Path) -> None:
    source = tmp_path / "lease-target"
    source.write_bytes(b"lease target")
    descriptor = os.open(source, os.O_RDONLY)
    try:
        with pytest.raises(ActivationPackageError, match="write-open request"):
            with activation_package_module._kernel_read_lease_barrier(
                (descriptor,)
            ) as require_lease_intact:
                child = os.fork()
                if child == 0:
                    try:
                        os.open(source, os.O_RDWR | os.O_NONBLOCK)
                    except BlockingIOError:
                        os._exit(0)
                    except OSError:
                        os._exit(2)
                    os._exit(1)
                _child, status = os.waitpid(child, 0)
                assert os.waitstatus_to_exitcode(status) == 0
                require_lease_intact()
    finally:
        os.close(descriptor)


def test_final_migration_pre_hash_checkpoint_rescans_open_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "overseer.sqlite3"
    _wal_store(source)
    approved = source.stat()
    parent = source.parent.stat()
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
    real_chmod = os.chmod
    holder: subprocess.Popen[str] | None = None

    def spawn_holder_before_hash(
        path: str | os.PathLike[str],
        mode: int,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal holder
        real_chmod(path, mode, *args, **kwargs)
        if (
            holder is None
            and mode == 0o400
            and str(path).startswith("/proc/self/fd/")
            and Path(path).name == source.name
        ):
            holder = subprocess.Popen(
                [
                    "/usr/bin/python3.13",
                    "-c",
                    (
                        "import os,sys;"
                        "fd=os.open(sys.argv[1],os.O_RDONLY);"
                        "print('ready',flush=True);"
                        "sys.stdin.readline();"
                        "os.close(fd)"
                    ),
                    str(source),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert holder.stdout is not None
            assert holder.stdout.readline().strip() == "ready"

    monkeypatch.setattr(os, "chmod", spawn_holder_before_hash)
    try:
        with pytest.raises(ActivationPackageError, match="open process or mapping"):
            prepare_final_store_migration(
                source_store=source,
                backup_store=backup,
                destination_store=destination,
                expected_source_device=approved.st_dev,
                expected_source_inode=approved.st_ino,
                expected_source_uid=os.geteuid(),
                expected_source_gid=os.getegid(),
                expected_parent_device=parent.st_dev,
                expected_parent_inode=parent.st_ino,
                expected_parent_mode=parent_mode,
                destination_uid=os.geteuid(),
                destination_gid=os.getegid(),
                sleep_seconds=0,
            )
    finally:
        if holder is not None:
            assert holder.stdin is not None
            holder.stdin.write("stop\n")
            holder.stdin.flush()
            holder.wait(timeout=5)

    assert holder is not None
    assert holder.returncode == 0
    assert not backup.exists()
    assert not destination.exists()


def _prepared_package(
    tmp_path: Path,
    *,
    stale_expression_index: bool = False,
) -> tuple[Path, dict[str, object], Path]:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, sqlite_evidence = _sqlite_runtime(tmp_path)
    manifest = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
    )
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
    if stale_expression_index:
        _stale_expression_index_store(source, journal_mode="WAL")
    else:
        _wal_store(source)
    rehearse_store_migration(
        package,
        source_store=source,
        pages_per_step=-1,
        sleep_seconds=0,
    )
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


def _reseal_package_manifest_for_test(package: Path) -> str:
    manifest_path = package / "public" / "package-manifest.json"
    try:
        manifest_path.unlink()
    except FileNotFoundError:
        pass
    unsigned = {
        "schemaVersion": activation_package_module.PACKAGE_MANIFEST_SCHEMA,
        "liveExecutionApproved": False,
        "files": activation_package_module._package_file_inventory(package),
        "directories": activation_package_module._package_directory_inventory(package),
    }
    replacement_digest = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(
            {**unsigned, "packageDigest": replacement_digest},
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o644)
    return replacement_digest


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
    sqlite_library, sqlite_evidence = _sqlite_runtime(
        tmp_path,
        package_root=package,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_probe_sqlite_runtime",
        lambda _python, _library, _metadata: sqlite_evidence,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_assert_current_sqlite_runtime",
        lambda _manifest: None,
    )
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
            "--sqlite-library",
            str(sqlite_library),
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
    migration_report = json.loads(
        (package / "private" / "migration" / "migration-report.json").read_text(encoding="utf-8")
    )
    assert migration_report["backupBounds"]["pagesPerStep"] == -1
    assert migration_report["backupBounds"]["sleepSeconds"] == 0
    assert migration_report["backupBounds"]["singleStep"] is True
    assert (
        migration_report["backupBounds"]["startedUnixNs"]
        <= migration_report["backupBounds"]["completedUnixNs"]
    )


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
    assert contract["schemaVersion"] == activation_package_module.ACTIVATION_CONTRACT_SCHEMA
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
    token_verify = commands[token_copy_index + 1]
    assert "verify-compatibility-token" in token_verify
    assert token_verify[token_verify.index("--expected-target-uid") + 1] == "0"
    assert token_verify[token_verify.index("--expected-target-gid") + 1] == str(os.getgid())
    assert token_verify[token_verify.index("--expected-target-uid") + 1] != str(os.getuid())
    canary_health_index = next(
        index
        for index, command in enumerate(commands)
        if command[-3:] == [
            "--unix-socket",
            "/run/overseer-canary/api.sock",
            "http://localhost/health",
        ]
    )
    assert canary_health_index < stop_index < migration_index < system_start_index < token_copy_index
    canary_health = commands[canary_health_index]
    assert "--retry-all-errors" in canary_health
    assert canary_health[canary_health.index("--retry-max-time") + 1] == "15"
    assert all("overseer.service" not in command for command in staging_commands)
    assert contract["cutoverGate"] == {
        "requiredFunction": "overseer.activation_package.verify_approved_cutover",
        "requiresApprovedPackageDigest": True,
        "requiresRootOwnedApprovalRecord": True,
        "requiresRootOwnedPhaseApprovalRecord": True,
        "requiresRootOwnedDigestBoundAttestation": True,
        "manualCommandExtractionForbidden": True,
        "automaticCutoverForbidden": True,
    }
    assert contract["phaseApprovalRecords"] == {
        "schemaVersion": activation_package_module.ACTIVATION_PHASE_APPROVAL_SCHEMA,
        "stagingCanary": {
            "phase": "staging-canary",
            "path": "/var/lib/overseer-executor/approved-activation-phase-staging-canary.json",
            "runner": "execute-approved-staging-canary",
            "requiresRunnerState": "not-started",
        },
        "cutover": {
            "phase": "cutover",
            "path": "/var/lib/overseer-executor/approved-activation-phase-cutover.json",
            "runner": "execute-approved-cutover",
            "requiresRunnerState": "canary_passed_awaiting_cutover_approval",
        },
    }
    assert "run-approved-canary" in staging_commands[-2]
    assert staging_commands[-1] == [
        "/usr/bin/systemctl",
        "stop",
        "overseer-api-canary.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    ]
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
    assert contract["canary"] == {
        "store": "/var/lib/overseer/overseer-canary.sqlite3",
        "unixSocket": "/run/overseer-canary/api.sock",
        "serverPeerUid": 984,
        "allowedClientUid": 0,
        "mustPassBeforeLegacyStop": True,
        "mutatingExecutorAcceptanceRequiresInteractiveAdminApproval": True,
        "failureCleanupCommands": [
            [
                "/usr/bin/systemctl",
                "stop",
                "overseer-api-canary.service",
                "overseer-admin-executor.socket",
                "overseer-codex-user-bridge.socket",
            ]
        ],
    }
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
        any("overseer-v1-1-5-rollback-runtime-" in value for value in command)
        for command in contract["rollbackCommands"]
    )
    rollback_transients = [
        command for command in contract["rollbackCommands"] if command[0] == "/usr/bin/systemd-run"
    ]
    assert len(rollback_transients) == 2
    assert all("--user" not in command for command in rollback_transients)
    assert all("--uid=god" in command and "--gid=god" in command for command in rollback_transients)
    assert all(
        f"--setenv=LD_LIBRARY_PATH={manifest['releaseRoot']}/lib" in command
        for command in rollback_transients
    )


    assert all(
        any(value.startswith("--property=Description=overseer.rollback-transient.v1:") for value in command)
        and any(value.startswith("--setenv=OVERSEER_ROLLBACK_TRANSIENT_ID=") for value in command)
        for command in rollback_transients
    )
    rollback_installs = [
        command
        for command in staging_commands
        if command[0] == "/usr/bin/install"
        and "-d" not in command
        and command[-1].startswith("/opt/overseer/rollback/")
    ]
    assert rollback_installs
    assert all(command[command.index("-o") + 1] == "root" for command in rollback_installs)
    assert all(command[command.index("-g") + 1] == "god" for command in rollback_installs)
    assert all(command[command.index("-m") + 1] in {"0440", "0550"} for command in rollback_installs)
    release_sqlite_installs = [
        command
        for command in staging_commands
        if command[0] == "/usr/bin/install"
        and command[-1] == f"{manifest['releaseRoot']}/lib/libsqlite3.so.0"
    ]
    assert len(release_sqlite_installs) == 1
    assert release_sqlite_installs[0][release_sqlite_installs[0].index("-o") + 1] == "root"
    assert release_sqlite_installs[0][release_sqlite_installs[0].index("-g") + 1] == "root"
    assert release_sqlite_installs[0][release_sqlite_installs[0].index("-m") + 1] == "0555"
    release_python_commands = [
        command
        for command in commands
        if command and command[0] == "/usr/bin/env" and "overseer.activation_package" in command
    ]
    assert release_python_commands
    assert all(
        f"LD_LIBRARY_PATH={manifest['releaseRoot']}/lib" in command
        for command in release_python_commands
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


def test_canary_health_retry_handles_an_initially_missing_unix_socket(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "delayed-api.sock"
    errors: list[BaseException] = []

    def delayed_server() -> None:
        try:
            time.sleep(0.2)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(socket_path))
            listener.listen()
            listener.settimeout(3)
            try:
                peer, _address = listener.accept()
                try:
                    peer.recv(4096)
                    peer.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n"
                        b"Connection: close\r\n\r\n{\"ok\":true}"
                    )
                finally:
                    peer.close()
            finally:
                listener.close()
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=delayed_server, daemon=True)
    thread.start()
    result = subprocess.run(
        [
            "/usr/bin/curl",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "1",
            "--max-time",
            "3",
            "--retry",
            "10",
            "--retry-delay",
            "1",
            "--retry-max-time",
            "15",
            "--retry-all-errors",
            "--unix-socket",
            str(socket_path),
            "http://localhost/health",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    thread.join(timeout=5)

    assert result.returncode == 0, result.stderr
    assert not errors
    assert not thread.is_alive()


@pytest.mark.parametrize(
    "section, field, value",
    (
        (None, "status", "failed"),
        (None, "sourceMutationPerformed", True),
        ("source", "journalMode", "delete"),
        ("backupBounds", "pagesPerStep", 128),
        ("backupBounds", "sleepSeconds", 0.01),
        ("backupBounds", "singleStep", False),
        ("backupBounds", "completedUnixNs", 0),
        ("copyNormalization", "preReindexQuickCheck", "failed"),
        ("copyNormalization", "journalMode", "wal"),
        ("copyNormalization", "sourceMutationPerformed", True),
        ("copyNormalization", "reindexedExpressionIndexes", ["unapproved-index"]),
    ),
)
def test_package_finalization_rejects_unapproved_migration_semantics(
    tmp_path: Path,
    section: str | None,
    field: str,
    value: object,
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
    create_human_verifiers(
        package,
        admin_secret="admin-approval-secret-123456",
        roadex_secret="roadex-approval-secret-12345",
    )
    report_path = package / "private" / "migration" / "migration-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    target = report if section is None else report[section]
    target[field] = value
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    report_path.chmod(0o600)

    with pytest.raises(
        ActivationPackageError,
        match="approved semantics|artifact evidence",
    ):
        finalize_activation_package(package)


def test_package_verification_rejects_self_consistent_unapproved_migration_report(
    tmp_path: Path,
) -> None:
    package, _digest = _finalized_package(tmp_path)
    report_path = package / "private" / "migration" / "migration-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["backupBounds"]["pagesPerStep"] = 128
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    report_path.chmod(0o600)
    replacement_digest = _reseal_package_manifest_for_test(package)

    with pytest.raises(ActivationPackageError, match="approved semantics"):
        verify_activation_package(package, replacement_digest)


def test_package_verification_rejects_omitted_reindex_evidence(
    tmp_path: Path,
) -> None:
    package, manifest, source = _prepared_package(
        tmp_path,
        stale_expression_index=True,
    )
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
    assert isinstance(finalized["packageDigest"], str)
    report_path = package / "private" / "migration" / "migration-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["copyNormalization"]["reindexedExpressionIndexes"] == [
        "idx_host_snapshots_captured_at"
    ]
    report["copyNormalization"]["reindexedExpressionIndexes"] = []
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    report_path.chmod(0o600)
    replacement_digest = _reseal_package_manifest_for_test(package)

    with pytest.raises(ActivationPackageError, match="artifact evidence"):
        verify_activation_package(package, replacement_digest)


def test_package_verification_rejects_deleted_migrated_expression_index(
    tmp_path: Path,
) -> None:
    package, _digest = _finalized_package(tmp_path)
    migrated = package / "private" / "migration" / "rehearsal-migrated.sqlite3"
    with sqlite3.connect(migrated) as connection:
        connection.execute("DROP INDEX idx_host_snapshots_captured_at")
        connection.commit()
        assert connection.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)"
        ).fetchone()[0] == 0
        assert connection.execute(
            "PRAGMA journal_mode=DELETE"
        ).fetchone()[0].lower() == "delete"
    migrated.chmod(0o600)
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{migrated}{suffix}")
        try:
            sidecar.unlink()
        except FileNotFoundError:
            pass

    observed = activation_package_module._sealed_migration_artifact_evidence(
        migrated,
        expected_uid=os.geteuid(),
    )
    assert observed["approvedExpressionIndexes"] == []
    report_path = package / "private" / "migration" / "migration-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["migrated"].update(
        {
            "sha256": observed["sha256"],
            "size": observed["size"],
            "integrityCheck": observed["integrityCheck"],
        }
    )
    report["rowCountsAfter"] = observed["rowCounts"]
    report["schemaAfter"] = observed["schema"]
    report_path.write_text(
        json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    report_path.chmod(0o600)
    replacement_digest = _reseal_package_manifest_for_test(package)

    with pytest.raises(ActivationPackageError, match="artifact evidence"):
        verify_activation_package(package, replacement_digest)


def test_package_finalization_rejects_contract_rehearsal_source_mismatch(
    tmp_path: Path,
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
    create_human_verifiers(
        package,
        admin_secret="admin-approval-secret-123456",
        roadex_secret="roadex-approval-secret-12345",
    )
    contract_path = package / "public" / "activation-contract.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["sourceStore"]["inode"] += 1
    contract_path.write_text(
        json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    contract_path.chmod(0o644)

    with pytest.raises(ActivationPackageError, match="rehearsal source"):
        finalize_activation_package(package)


def test_package_finalization_rejects_missing_migration_database(tmp_path: Path) -> None:
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
    (package / "private" / "migration" / "rehearsal-source.sqlite3").unlink()

    with pytest.raises(ActivationPackageError, match="artifact evidence"):
        finalize_activation_package(package)


@pytest.mark.parametrize("operation", ("delete", "replace"))
def test_package_verification_rejects_resealed_migration_artifact_substitution(
    tmp_path: Path,
    operation: str,
) -> None:
    package, _digest = _finalized_package(tmp_path)
    migration = package / "private" / "migration"
    if operation == "delete":
        (migration / "rehearsal-source.sqlite3").unlink()
    else:
        migrated = migration / "rehearsal-migrated.sqlite3"
        migrated.unlink()
        with sqlite3.connect(migrated) as connection:
            connection.execute(
                "CREATE TABLE retained_items(id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO retained_items(value) VALUES ('replacement')")
        migrated.chmod(0o600)
    replacement_digest = _reseal_package_manifest_for_test(package)

    with pytest.raises(ActivationPackageError, match="artifact evidence"):
        verify_activation_package(package, replacement_digest)


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
    assert recorded["liveExecutionScope"] == "sealed-package-import-and-verification-only"
    assert stat_mode(approval_path) == 0o600
    assert verify_activation_package(execution_package, digest)["verified"] is True
    assert (
        execution_package / "public" / "activation-contract.json"
    ).stat().st_ino != (package / "public" / "activation-contract.json").stat().st_ino
    assert activation_package_module._load_activation_approval(execution_package) == recorded
    with pytest.raises(ActivationPackageError, match="already exists"):
        record_activation_approval(package, expected_package_digest=digest)


def test_phase_approvals_bind_package_and_exact_runner_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "9" * 64
    package = tmp_path / "approved-package"
    package.mkdir()
    state_path = tmp_path / "executor" / "activation-state.json"
    phase_paths = {
        phase: tmp_path / "executor" / f"approved-{phase}.json"
        for phase in ("staging-canary", "cutover")
    }
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_phase_approval_record_path",
        lambda phase: phase_paths[phase],
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval",
        lambda _package: {"packageDigest": digest},
    )

    staging = activation_package_module.record_activation_phase_approval(
        package,
        expected_package_digest=digest,
        phase="staging-canary",
    )

    assert staging["runnerStateDigest"] is None
    assert staging["runnerStateStatus"] == "not-started"
    assert stat_mode(phase_paths["staging-canary"]) == 0o600
    assert activation_package_module._load_activation_phase_approval(
        package,
        phase="staging-canary",
        expected_runner_state=None,
    ) == staging
    with pytest.raises(ActivationPackageError, match="successful canary"):
        activation_package_module.record_activation_phase_approval(
            package,
            expected_package_digest=digest,
            phase="cutover",
        )

    canary_state = activation_package_module._runner_state(
        package_digest=digest,
        status="canary_passed_awaiting_cutover_approval",
        phase="staging-canary",
    )
    activation_package_module._write_activation_state(canary_state)
    cutover = activation_package_module.record_activation_phase_approval(
        package,
        expected_package_digest=digest,
        phase="cutover",
    )

    assert cutover["runnerStateStatus"] == "canary_passed_awaiting_cutover_approval"
    assert cutover["runnerStateDigest"] == hashlib.sha256(
        json.dumps(canary_state, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    assert activation_package_module._load_activation_phase_approval(
        package,
        phase="cutover",
        expected_runner_state=canary_state,
    ) == cutover

    drifted_state = dict(canary_state, status="running")
    with pytest.raises(ActivationPackageError, match="runner state"):
        activation_package_module._load_activation_phase_approval(
            package,
            phase="cutover",
            expected_runner_state=drifted_state,
        )


def test_phase_approval_rejects_unknown_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)

    with pytest.raises(ActivationPackageError, match="activation phase"):
        activation_package_module.record_activation_phase_approval(
            tmp_path,
            expected_package_digest="8" * 64,
            phase="everything",
        )


def test_root_approval_import_streams_files_that_exceed_stable_read_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, digest = _finalized_package(tmp_path)
    migration_store = package / "private" / "migration" / "rehearsal-source.sqlite3"
    stable_read = activation_package_module._stable_read

    def reject_bounded_read(path: Path):
        if Path(path) == migration_store:
            raise ActivationPackageError("release input exceeds the per-file bound")
        return stable_read(path)

    monkeypatch.setattr(activation_package_module, "_stable_read", reject_bounded_read)

    recorded = record_activation_approval(package, expected_package_digest=digest)

    assert recorded["packageDigest"] == digest
    imported_store = execution_package / migration_store.relative_to(package)
    assert imported_store.read_bytes() == migration_store.read_bytes()


def test_root_approval_import_enospc_does_not_publish_partial_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, digest = _finalized_package(tmp_path)
    copy_regular = activation_package_module._copy_package_regular_to_new_path
    attempts = 0

    def fail_during_import(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise OSError(errno.ENOSPC, "injected package import ENOSPC")
        return copy_regular(*args, **kwargs)

    monkeypatch.setattr(
        activation_package_module,
        "_copy_package_regular_to_new_path",
        fail_during_import,
    )

    with pytest.raises(OSError, match="injected package import ENOSPC"):
        record_activation_approval(package, expected_package_digest=digest)

    assert not execution_package.exists()
    assert not approval_path.exists()
    assert not tuple(execution_package.parent.glob(".approved-package.import-*"))


def test_root_approval_import_rejects_sparse_package_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, _digest = _finalized_package(tmp_path)
    sparse = package / "public" / "sparse-import-test.bin"
    with sparse.open("wb") as stream:
        stream.seek(2 * 1024 * 1024)
        stream.write(b"x")
    sparse.chmod(0o644)
    digest = _reseal_package_manifest_for_test(package)

    with pytest.raises(ActivationPackageError, match="sparse"):
        record_activation_approval(package, expected_package_digest=digest)

    assert not execution_package.exists()
    assert not approval_path.exists()


def test_root_approval_import_rejects_same_owner_sparse_swap_during_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, digest = _finalized_package(tmp_path)
    migration_store = package / "private" / "migration" / "rehearsal-source.sqlite3"
    copy_regular = activation_package_module._copy_package_regular_to_new_path
    swapped = False

    def swap_before_descriptor_copy(source: Path, target: Path, **kwargs):
        nonlocal swapped
        if source == migration_store and not swapped:
            swapped = True
            source.unlink()
            with source.open("wb") as stream:
                stream.seek(kwargs["expected_size"] - 1)
                stream.write(b"x")
            source.chmod(kwargs["source_mode"])
        return copy_regular(source, target, **kwargs)

    monkeypatch.setattr(
        activation_package_module,
        "_copy_package_regular_to_new_path",
        swap_before_descriptor_copy,
    )

    with pytest.raises(ActivationPackageError, match="sparse"):
        record_activation_approval(package, expected_package_digest=digest)

    assert swapped is True
    assert not execution_package.exists()
    assert not approval_path.exists()
    assert not tuple(execution_package.parent.glob(".approved-package.import-*"))


def test_root_approval_import_enforces_package_size_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    monkeypatch.setattr(activation_package_module, "MAX_APPROVED_PACKAGE_IMPORT_BYTES", 1)
    package, digest = _finalized_package(tmp_path)

    with pytest.raises(ActivationPackageError, match="size bound"):
        record_activation_approval(package, expected_package_digest=digest)

    assert not execution_package.exists()
    assert not approval_path.exists()


def test_root_approval_import_enforces_free_space_headroom(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, digest = _finalized_package(tmp_path)
    filesystem = os.statvfs(tmp_path)
    unavailable = os.statvfs_result(
        (
            filesystem.f_bsize,
            filesystem.f_frsize,
            filesystem.f_blocks,
            filesystem.f_bfree,
            0,
            filesystem.f_files,
            filesystem.f_ffree,
            filesystem.f_favail,
            filesystem.f_flag,
            filesystem.f_namemax,
        )
    )
    monkeypatch.setattr(activation_package_module.os, "statvfs", lambda _path: unavailable)

    with pytest.raises(ActivationPackageError, match="insufficient free space"):
        record_activation_approval(package, expected_package_digest=digest)

    assert not execution_package.exists()
    assert not approval_path.exists()


def test_root_approval_import_rechecks_headroom_after_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, digest = _finalized_package(tmp_path)
    validate_free_space = activation_package_module._validate_package_import_free_space
    checks = 0

    def consume_reserved_headroom(path: Path, required_size: int) -> None:
        nonlocal checks
        checks += 1
        if checks == 2:
            raise ActivationPackageError("insufficient free space after staging")
        validate_free_space(path, required_size)

    monkeypatch.setattr(
        activation_package_module,
        "_validate_package_import_free_space",
        consume_reserved_headroom,
    )

    with pytest.raises(ActivationPackageError, match="after staging"):
        record_activation_approval(package, expected_package_digest=digest)

    assert checks == 2
    assert not execution_package.exists()
    assert not approval_path.exists()
    assert not tuple(execution_package.parent.glob(".approved-package.import-*"))


def test_root_approval_import_reports_post_publish_durability_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, digest = _finalized_package(tmp_path)
    fsync_directory = activation_package_module._fsync_package_directory

    def fail_published_parent_fsync(path: Path) -> None:
        if path == execution_package.parent and execution_package.exists():
            raise OSError("injected parent fsync failure")
        fsync_directory(path)

    monkeypatch.setattr(
        activation_package_module,
        "_fsync_package_directory",
        fail_published_parent_fsync,
    )

    with pytest.raises(ActivationPackageError, match="durability is indeterminate"):
        record_activation_approval(package, expected_package_digest=digest)

    assert execution_package.is_dir()
    assert not approval_path.exists()
    assert not tuple(execution_package.parent.glob(".approved-package.import-*"))

    monkeypatch.setattr(
        activation_package_module,
        "_fsync_package_directory",
        fsync_directory,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_existing_package_destination",
        lambda selected: Path(selected).resolve(),
    )
    recovered = activation_package_module.recover_activation_approval_import(
        package,
        expected_package_digest=digest,
        action="adopt",
    )

    assert recovered["status"] == "adopted"
    assert recovered["packageDigest"] == digest
    assert approval_path.is_file()


def test_root_approval_import_recovery_removes_invalid_unapproved_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_package = tmp_path / "executor-state" / "approved-package"
    approval_path = tmp_path / "executor-state" / "approved-package.json"
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_EXECUTION_PACKAGE",
        execution_package,
    )
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
    package, digest = _finalized_package(tmp_path)
    execution_package.mkdir(parents=True, mode=0o700)
    (execution_package / "partial-copy").write_text("incomplete\n", encoding="utf-8")
    monkeypatch.setattr(
        activation_package_module,
        "_validate_existing_package_destination",
        lambda selected: Path(selected).resolve(),
    )

    recovered = activation_package_module.recover_activation_approval_import(
        package,
        expected_package_digest=digest,
        action="remove",
    )

    assert recovered == {
        "status": "removed",
        "packageRoot": str(execution_package.resolve()),
        "packageDigest": digest,
        "approvalRecorded": False,
    }
    assert not execution_package.exists()
    assert not approval_path.exists()


def test_root_approval_import_uses_atomic_no_replace_publication(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()

    with pytest.raises(FileExistsError):
        activation_package_module._rename_package_no_replace(source, destination)

    assert source.is_dir()
    assert destination.is_dir()


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
    canary_socket = tmp_path / "api-canary.sock"
    monkeypatch.setattr(
        activation_package_module,
        "_validate_canary_socket",
        lambda *_args, **_kwargs: None,
    )

    class FakeClient:
        executions: dict[str, int] = {}

        def __init__(
            self,
            *,
            base_url: str,
            auth_token: str,
            unix_socket_path: str,
            expected_server_uid: int,
            approval_token: str | None = None,
        ) -> None:
            assert base_url == "http://localhost"
            assert unix_socket_path == str(canary_socket)
            assert expected_server_uid == os.geteuid()
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
        unix_socket_path=canary_socket,
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


def test_live_canary_rejects_prebound_socket_before_connecting_or_attesting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, digest = _finalized_package(tmp_path)
    canary_socket = tmp_path / "prebound-api-canary.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(canary_socket))
    canary_socket.chmod(0o600)
    listener.listen()
    listener.setblocking(False)
    attestation = tmp_path / "canary-attestation.json"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "verify_installed_staging",
        lambda *_args, **_kwargs: {"verified": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid() + 1, os.getegid() + 1),
    )
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_OVERSEER_UID",
        os.geteuid() + 1,
    )
    monkeypatch.setattr(
        activation_package_module,
        "APPROVED_OVERSEER_GID",
        os.getegid() + 1,
    )
    try:
        with pytest.raises(ActivationPackageError, match="socket identity"):
            run_canary_acceptance(
                package,
                expected_package_digest=digest,
                admin_secret="must-not-be-sent",
                roadex_secret="must-not-be-sent-either",
                attestation_path=attestation,
                unix_socket_path=canary_socket,
            )
        with pytest.raises(BlockingIOError):
            listener.accept()
    finally:
        listener.close()

    assert not attestation.exists()


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
        directory.chmod(0o550)
    bundle_root.chmod(0o550)
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


def test_phase_bounded_activation_runner_stops_for_cutover_approval(
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
    phase_loads: list[tuple[str, str | None]] = []

    def load_phase_approval(
        _package: Path,
        *,
        phase: str,
        expected_runner_state: dict[str, object] | None,
    ) -> dict[str, object]:
        phase_loads.append(
            (
                phase,
                None if expected_runner_state is None else str(expected_runner_state["status"]),
            )
        )
        return {"packageDigest": digest, "phase": phase}

    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_phase_approval",
        load_phase_approval,
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

    staged = activation_package_module.execute_approved_staging_canary(package)
    replayed = activation_package_module.execute_approved_staging_canary(package)

    assert staged == {
        "status": "canary_passed_awaiting_cutover_approval",
        "packageDigest": digest,
        "replayed": False,
    }
    assert replayed == {
        "status": "canary_passed_awaiting_cutover_approval",
        "packageDigest": digest,
        "replayed": True,
    }
    assert calls == [("/bin/true", "staging")]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "canary_passed_awaiting_cutover_approval"
    assert state["phase"] == "staging-canary"
    assert state["secretValuesRecorded"] is False
    assert phase_loads == [("staging-canary", None)]

    completed = activation_package_module.execute_approved_cutover(package)

    assert completed == {"status": "complete", "packageDigest": digest, "replayed": False}
    assert calls == [("/bin/true", "staging"), ("/bin/true", "cutover")]
    assert phase_loads == [
        ("staging-canary", None),
        ("cutover", "canary_passed_awaiting_cutover_approval"),
    ]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "complete"
    assert state["phase"] == "complete"


def test_legacy_all_in_one_activation_runner_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "executor" / "activation-state.json"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)

    with pytest.raises(ActivationPackageError, match="separate phase runners"):
        activation_package_module.execute_approved_activation(tmp_path / "package")

    assert not state_path.exists()


def test_cutover_runner_requires_separate_state_bound_phase_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "7" * 64
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
    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="canary_passed_awaiting_cutover_approval",
            phase="staging-canary",
        )
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ActivationPackageError("cutover phase approval is unavailable")
        ),
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(command) or 0,
    )

    with pytest.raises(ActivationPackageError, match="cutover phase approval"):
        activation_package_module.execute_approved_cutover(package)

    assert calls == []
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "canary_passed_awaiting_cutover_approval"


def test_mutating_canary_primitive_requires_the_active_sealed_runner_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "6" * 64
    package = tmp_path / "package"
    command = [
        "/opt/overseer/python",
        "-m",
        "overseer.activation_package",
        "run-approved-canary",
        "--package-root",
        str(package.resolve()),
    ]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "packageRoot": str(package.resolve()),
        "stagingAndCanaryCommands": [command],
    }
    state_path = tmp_path / "executor" / "activation-state.json"
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
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_read_activation_phase_approval",
        lambda _package, *, phase: {
            "phase": phase,
            "packageDigest": digest,
            "runnerStateDigest": None,
            "runnerStateStatus": "not-started",
        },
    )

    with pytest.raises(ActivationPackageError, match="active staging-canary runner"):
        activation_package_module._require_active_phase_command(
            package,
            phase="staging-canary",
            command_name="run-approved-canary",
        )

    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="command_running",
            phase="staging-canary",
            command_index=0,
            command=command,
        )
    )

    activation_package_module._require_active_phase_command(
        package,
        phase="staging-canary",
        command_name="run-approved-canary",
    )

    drifted = activation_package_module._runner_state(
        package_digest=digest,
        status="command_running",
        phase="staging-canary",
        command_index=0,
        command=[*command, "--drift"],
    )
    activation_package_module._write_activation_state(drifted)
    with pytest.raises(ActivationPackageError, match="sealed command"):
        activation_package_module._require_active_phase_command(
            package,
            phase="staging-canary",
            command_name="run-approved-canary",
        )


def test_activation_runner_lock_rejects_concurrent_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "executor" / "activation-state.json"
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    with activation_package_module._activation_execution_lock():
        with pytest.raises(ActivationPackageError, match="holds the execution lock"):
            with activation_package_module._activation_execution_lock():
                raise AssertionError("nested activation lock must not be acquired")


def test_interrupted_staging_recovery_runs_and_records_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "c" * 64
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
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )
    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="command_running",
            phase="staging-canary",
            command_index=0,
            command=["/bin/true", "staging"],
        )
    )

    result = activation_package_module.execute_approved_rollback(package)

    assert result == {
        "status": "aborted_before_cutover",
        "packageDigest": digest,
        "replayed": False,
    }
    assert calls == [("/bin/true", "cleanup")]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"


def _rollback_transient_command() -> list[str]:
    return activation_package_module._bind_rollback_transient_identity(
        [
            "/usr/bin/systemd-run",
            "--collect",
            "--uid=god",
            "--gid=god",
            "--unit=overseer-v1-1-5-rollback-runtime-dddddddddddddddd.service",
            "--service-type=simple",
            "--property=Restart=on-failure",
            "--property=RestartSec=5s",
            "--working-directory=/opt/overseer/rollback/" + "d" * 64 + "/v1.1.5-release",
            "--setenv=PYTHONNOUSERSITE=1",
            "--setenv=PYTHONSAFEPATH=1",
            "--",
            "/bin/true",
        ]
    )


def test_interrupted_rollback_verifies_active_root_transient_instead_of_restarting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "d" * 64
    transient = _rollback_transient_command()
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "rollbackCommands": [["/bin/true", "verify"], transient],
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_inspect_rollback_transient_unit",
        lambda spec: "active",
    )
    prior_state = activation_package_module._runner_state(
        package_digest=digest,
        status="rollback_command_running",
        phase="rollback",
        command_index=1,
        command=transient,
    )

    activation_package_module._execute_rollback_sequence(
        contract,
        package_digest=digest,
        prior_state=prior_state,
    )

    assert calls == [("/bin/true", "verify")]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "rolled_back"


@pytest.mark.parametrize(
    ("states", "expected_command"),
    [
        (["active"], None),
        (["activating", "active"], ["/usr/bin/systemctl", "start"]),
        (["inactive", "active"], ["/usr/bin/systemctl", "restart"]),
        (["failed", "active"], ["/usr/bin/systemctl", "restart"]),
        (["deactivating", "active"], ["/usr/bin/systemctl", "restart"]),
        (["unloaded", "active"], ["/usr/bin/systemd-run"]),
    ],
)
def test_rollback_transient_reconciles_each_interrupted_unit_state(
    monkeypatch: pytest.MonkeyPatch,
    states: list[str],
    expected_command: list[str] | None,
) -> None:
    command = _rollback_transient_command()
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
    }
    observed_states = iter(states)
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_inspect_rollback_transient_unit",
        lambda spec: next(observed_states),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda selected: calls.append(selected) or 0,
    )

    activation_package_module._execute_rollback_transient(contract, command, resume=True)

    if expected_command is None:
        assert calls == []
    else:
        assert calls and calls[0][: len(expected_command)] == expected_command


def test_rollback_transient_rejects_loaded_unit_without_saved_recovery_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = _rollback_transient_command()
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
    }
    monkeypatch.setattr(
        activation_package_module,
        "_inspect_rollback_transient_unit",
        lambda spec: "active",
    )

    with pytest.raises(ActivationPackageError, match="pre-existing"):
        activation_package_module._execute_rollback_transient(contract, command, resume=False)


def test_rollback_transient_snapshot_is_bound_to_all_sealed_properties(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = _rollback_transient_command()
    spec = activation_package_module._rollback_transient_spec(command)
    assert spec is not None
    unit = str(spec["unit"])
    environment = " ".join(str(value) for value in spec["environment"])
    snapshot = {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "Transient": "yes",
        "FragmentPath": f"/run/systemd/transient/{unit}",
        "Description": str(spec["description"]),
        "User": "god",
        "Group": "god",
        "WorkingDirectory": str(spec["workingDirectory"]),
        "Type": "simple",
        "Restart": "on-failure",
        "RestartUSec": "5s",
        "CollectMode": "inactive-or-failed",
        "Environment": environment,
        "ExecStart": "{ path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; start_time=[n/a] }",
        "After": "basic.target",
        "LoadCredential": "",
        "InvocationID": "1" * 32,
    }
    monkeypatch.setattr(
        activation_package_module,
        "_systemctl_show_rollback_unit",
        lambda selected: snapshot,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_verify_rollback_transient_fragment",
        lambda fragment, *, unit: None,
    )

    assert activation_package_module._inspect_rollback_transient_unit(spec) == "active"
    snapshot["Description"] = "unsealed"
    with pytest.raises(ActivationPackageError, match="identity drifted"):
        activation_package_module._inspect_rollback_transient_unit(spec)


def test_rollback_transient_identity_rejects_sealed_argv_drift() -> None:
    command = _rollback_transient_command()
    command[-1] = "/bin/false"

    with pytest.raises(ActivationPackageError, match="identity digest drifted"):
        activation_package_module._rollback_transient_spec(command)


def test_rollback_transient_retries_sealed_start_after_loaded_unit_is_collected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = _rollback_transient_command()
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
    }
    states = iter(["failed", "unloaded", "active"])
    returncodes = iter([1, 0])
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_inspect_rollback_transient_unit",
        lambda spec: next(states),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda selected: calls.append(selected) or next(returncodes),
    )

    activation_package_module._execute_rollback_transient(contract, command, resume=True)

    assert calls[0][:2] == ["/usr/bin/systemctl", "restart"]
    assert calls[1] == command


def test_rollback_recovery_rejects_saved_command_digest_mismatch() -> None:
    commands = [["/bin/true", "verify"], ["/bin/true", "restore"]]
    prior_state = {
        "schemaVersion": activation_package_module.ACTIVATION_RUNNER_STATE_SCHEMA,
        "packageDigest": "d" * 64,
        "phase": "rollback",
        "status": "rollback_command_running",
        "commandIndex": 1,
        "commandDigest": "0" * 64,
    }

    with pytest.raises(ActivationPackageError, match="command digest"):
        activation_package_module._rollback_recovery_boundary(
            prior_state,
            commands=commands,
            package_digest="d" * 64,
        )


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
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_phase_approval",
        lambda _package, *, phase, expected_runner_state: {
            "packageDigest": digest,
            "phase": phase,
        },
    )
    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="canary_passed_awaiting_cutover_approval",
            phase="staging-canary",
        )
    )

    def execute(command: list[str]) -> int:
        calls.append(tuple(command))
        if command[1] == "cutover":
            raise ActivationPackageError("simulated command-start failure")
        return 0

    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)

    with pytest.raises(ActivationPackageError, match="sealed rollback completed"):
        activation_package_module.execute_approved_cutover(package)
    assert calls == [
        ("/bin/false", "cutover"),
        ("/bin/true", "rollback"),
    ]
    assert activation_package_module.execute_approved_rollback(package) == {
        "status": "rolled_back",
        "packageDigest": digest,
        "replayed": True,
    }
    with pytest.raises(ActivationPackageError, match="successful canary"):
        activation_package_module.execute_approved_cutover(package)


def test_cutover_failure_records_recoverable_first_rollback_command_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "e" * 64
    package = tmp_path / "package"
    rollback = ["/bin/true", "rollback-zero"]
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
        "rollbackCommands": [rollback],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
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
        "_load_activation_phase_approval",
        lambda _package, *, phase, expected_runner_state: {
            "packageDigest": digest,
            "phase": phase,
        },
    )
    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="canary_passed_awaiting_cutover_approval",
            phase="staging-canary",
        )
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: 1 if command[1] == "cutover" else 0,
    )

    def crash_before_first_rollback_command(*_args, **_kwargs):
        raise KeyboardInterrupt("simulated process loss")

    monkeypatch.setattr(
        activation_package_module,
        "_execute_rollback_sequence",
        crash_before_first_rollback_command,
    )

    with pytest.raises(KeyboardInterrupt, match="process loss"):
        activation_package_module.execute_approved_cutover(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["phase"] == "rollback"
    assert state["status"] == "rollback_command_running"
    assert state["commandIndex"] == 0
    assert state["commandDigest"] == hashlib.sha256(
        json.dumps(rollback, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
