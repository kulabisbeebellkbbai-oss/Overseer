from __future__ import annotations

import array
import errno
import fcntl
import hashlib
import io
import json
import os
import pty
import shutil
import socket
import sqlite3
import subprocess
import sys
import termios
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
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
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID


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
    templates = checkout / "systemd"
    templates.mkdir()
    for source_name in activation_package_module._SYSTEMD_TEMPLATES:
        shutil.copy2(ROOT / "systemd" / source_name, templates / source_name)
    config = checkout / "config"
    config.mkdir()
    shutil.copy2(
        ROOT / "config" / "admin-executor-allowlist.json",
        config / "admin-executor-allowlist.json",
    )
    _git(checkout, "init", "-q")
    _git(checkout, "config", "user.email", "overseer-test@localhost")
    _git(checkout, "config", "user.name", "Overseer Test")
    _git(checkout, "add", "src", "systemd", "config")
    _git(checkout, "commit", "-q", "-m", "fixture")
    return checkout


def _reviewed_identity(checkout: Path) -> dict[str, str]:
    commit = _git(checkout, "rev-parse", "HEAD^{commit}")
    return {
        "expected_commit": commit,
        "expected_tree": _git(checkout, "rev-parse", f"{commit}^{{tree}}"),
    }


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
        **_reviewed_identity(checkout),
    )
    second = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
        **_reviewed_identity(checkout),
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
    checkout_files = [item for item in first["files"] if item["sourceKind"] == "checkout"]
    assert all(
        len(item["sourceObject"]) == 40
        and item["sourceGitMode"] in {"100644", "100755"}
        for item in checkout_files
    )
    assert {item["sourcePath"] for item in first["controlFiles"]} == {
        *(f"systemd/{name}" for name in activation_package_module._SYSTEMD_TEMPLATES),
        "config/admin-executor-allowlist.json",
    }
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


def test_release_manifest_requires_exact_approved_commit_and_tree(tmp_path: Path) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, _sqlite_evidence = _sqlite_runtime(tmp_path)
    identity = _reviewed_identity(checkout)

    with pytest.raises(ActivationPackageError, match="commit does not match"):
        build_release_manifest(
            checkout,
            dependencies,
            python,
            stdlib,
            sqlite_library,
            expected_commit="0" * 40,
            expected_tree=identity["expected_tree"],
        )
    with pytest.raises(ActivationPackageError, match="tree does not match"):
        build_release_manifest(
            checkout,
            dependencies,
            python,
            stdlib,
            sqlite_library,
            expected_commit=identity["expected_commit"],
            expected_tree="0" * 40,
        )


def test_release_manifest_derives_tree_from_captured_commit_across_head_aba(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, _sqlite_evidence = _sqlite_runtime(tmp_path)
    identity = _reviewed_identity(checkout)
    real_git = activation_package_module._git
    head_tree_requests: list[tuple[str, ...]] = []
    head_commit_requests = 0

    def aba_git(selected: Path, *args: str) -> bytes:
        nonlocal head_commit_requests
        if args == ("rev-parse", "HEAD^{commit}"):
            head_commit_requests += 1
            return identity["expected_commit"].encode("ascii") + b"\n"
        if args == ("rev-parse", "HEAD^{tree}"):
            head_tree_requests.append(args)
            return b"f" * 40 + b"\n"
        return real_git(selected, *args)

    monkeypatch.setattr(activation_package_module, "_git", aba_git)
    manifest = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
        **identity,
    )

    assert manifest["sourceCommit"] == identity["expected_commit"]
    assert manifest["sourceTree"] == identity["expected_tree"]
    assert head_commit_requests == 2
    assert head_tree_requests == []


def test_release_manifest_ignores_git_replace_refs_for_approved_commit(
    tmp_path: Path,
) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, _sqlite_evidence = _sqlite_runtime(tmp_path)
    identity = _reviewed_identity(checkout)
    original_cli = (checkout / "src/overseer/cli.py").read_bytes()
    (checkout / "src/overseer/cli.py").write_text("MALICIOUS = True\n", encoding="utf-8")
    _git(checkout, "add", "src/overseer/cli.py")
    _git(checkout, "commit", "-q", "-m", "replacement")
    replacement_commit = _git(checkout, "rev-parse", "HEAD^{commit}")
    _git(checkout, "reset", "--hard", "-q", identity["expected_commit"])
    _git(checkout, "replace", identity["expected_commit"], replacement_commit)

    manifest = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
        **identity,
    )
    package = tmp_path / "activation-package"
    staged = stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )

    assert (staged / "app/src/overseer/cli.py").read_bytes() == original_cli


def test_release_source_and_controls_are_read_from_the_recorded_git_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkout = _reviewed_checkout(tmp_path)
    dependencies = _dependencies(tmp_path)
    python = _python(tmp_path)
    stdlib = _stdlib(tmp_path)
    sqlite_library, _sqlite_evidence = _sqlite_runtime(tmp_path)
    original_cli = (checkout / "src/overseer/cli.py").read_bytes()
    original_api = (checkout / "systemd/overseer-api-system.service").read_bytes()
    (checkout / "src/overseer/cli.py").write_text("MALICIOUS = True\n", encoding="utf-8")
    (checkout / "systemd/overseer-api-system.service").write_text(
        "[Service]\nExecStart=/bin/false\n",
        encoding="utf-8",
    )
    real_git = activation_package_module._git

    def hide_worktree_status(selected: Path, *args: str) -> bytes:
        if args[:2] == ("status", "--porcelain=v1"):
            return b""
        return real_git(selected, *args)

    monkeypatch.setattr(activation_package_module, "_git", hide_worktree_status)
    distinct_god_uid = 1234
    distinct_god_gid = 2345
    monkeypatch.setattr(
        activation_package_module,
        "_validate_principal_binding",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package_module.pwd,
        "getpwnam",
        lambda _name: type("GodAccount", (), {"pw_gid": distinct_god_gid})(),
    )
    manifest = build_release_manifest(
        checkout,
        dependencies,
        python,
        stdlib,
        sqlite_library,
        **_reviewed_identity(checkout),
    )
    package = tmp_path / "activation-package"
    staged = stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )
    activation_package_module.stage_canary_identity(
        package,
        random_bytes=lambda size: b"I" * size,
    )
    rendered = render_systemd_units(
        manifest,
        templates_root=checkout / "systemd",
        output_root=package / "public/systemd",
        god_uid=distinct_god_uid,
        god_gid=distinct_god_gid,
        overseer_uid=984,
        python_path=python,
    )

    assert (staged / "app/src/overseer/cli.py").read_bytes() == original_cli
    expected_api = original_api
    for placeholder, replacement in {
        b"@OVERSEER_RELEASE@": str(manifest["releaseRoot"]).encode(),
        b"@OVERSEER_PYTHON@": (
            f"{manifest['releaseRoot']}/runtime/bin/python3.13"
        ).encode(),
        b"@GOD_UID@": str(distinct_god_uid).encode(),
        b"@GOD_GID@": str(distinct_god_gid).encode(),
        b"@OVERSEER_UID@": b"984",
    }.items():
        expected_api = expected_api.replace(placeholder, replacement)
    assert rendered["overseer-api.service"].read_bytes() == expected_api
    assert b"/bin/false" not in rendered["overseer-api.service"].read_bytes()
    bridge = rendered["overseer-codex-user-bridge.service"].read_text(encoding="utf-8")
    assert f"User={distinct_god_uid}" in bridge
    assert f"Group={distinct_god_gid}" in bridge


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
            **_reviewed_identity(checkout),
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
            **_reviewed_identity(checkout),
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
            **_reviewed_identity(checkout),
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
            **_reviewed_identity(checkout),
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
        **_reviewed_identity(checkout),
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
            **_reviewed_identity(checkout),
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
            **_reviewed_identity(checkout),
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
            **_reviewed_identity(checkout),
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
        **_reviewed_identity(checkout),
    )
    package = tmp_path / "activation-package"

    staged_release = stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )
    activation_package_module.stage_canary_identity(
        package,
        random_bytes=lambda size: b"I" * size,
    )
    rendered = render_systemd_units(
        manifest,
        templates_root=checkout / "systemd",
        output_root=package / "public" / "systemd",
        god_uid=os.getuid(),
        god_gid=os.getgid(),
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
    for name in ("overseer-api-canary.service", "overseer-api.service"):
        assert (
            "Environment=OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_QUESTION_ENDPOINT="
            "http://127.0.0.1:8780/api/internal/overseer/project-human-thread/questions"
            in rendered[name].read_text(encoding="utf-8")
        )
    canary_instance = json.loads(
        (package / "public/canary-instance.json").read_text(encoding="utf-8")
    )
    canary_state = Path("/var/lib/overseer-canary") / canary_instance["canaryInstanceId"]
    canary_unit = rendered["overseer-api-canary.service"].read_text(encoding="utf-8")
    assert f"--store {canary_state / 'overseer.sqlite3'}" in canary_unit
    assert (
        f"Environment=OVERSEER_PSYCHLO_BRIDGE_DATABASE="
        f"{canary_state / 'psychlo-bridge.sqlite3'}"
    ) in canary_unit
    assert (
        f"Environment=OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_DATABASE="
        f"{canary_state / 'roadex-relay.sqlite3'}"
    ) in canary_unit
    assert "/var/lib/overseer/overseer-canary.sqlite3" not in canary_unit
    assert "/var/lib/overseer/psychlo-canary-bridge.sqlite3" not in canary_unit
    assert "/var/lib/overseer/roadex-canary-relay.sqlite3" not in canary_unit
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
        assert "@GOD_GID@" not in content
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


def _gateway_ca(tmp_path: Path) -> Path:
    path = tmp_path / "roadex-private-ca.crt"
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Gateway CA")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, algorithm=None)
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    path.chmod(0o644)
    return path


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
        protected_gateway_ca_file=_gateway_ca(tmp_path),
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
    with pytest.raises(
        ActivationPackageError,
        match="canary-required store tables",
    ):
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
    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(activation_package_module, "_require_active_rollback_command", lambda *_args, **_kwargs: None)
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
                package_root=tmp_path / "package",
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
        package_root=tmp_path / "package",
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
        package_root=tmp_path / "package",
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
    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(activation_package_module, "_require_active_rollback_command", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)

    report = prepare_final_store_migration(
        package_root=tmp_path / "package",
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
        package_root=tmp_path / "package",
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
    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", lambda *_args, **_kwargs: None)
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
            package_root=tmp_path / "package",
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
    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)
    try:
        with pytest.raises(ActivationPackageError, match="mapping"):
            prepare_final_store_migration(
                package_root=tmp_path / "package",
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
    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_parent_lock_mode", lambda: 0o700)
    try:
        with pytest.raises(ActivationPackageError, match="lease barrier rejected"):
            prepare_final_store_migration(
                package_root=tmp_path / "package",
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
    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", lambda *_args, **_kwargs: None)
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
                package_root=tmp_path / "package",
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
    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", lambda *_args, **_kwargs: None)
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
                package_root=tmp_path / "package",
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
    missing_admin_execution_claims: bool = False,
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
        **_reviewed_identity(checkout),
    )
    package = tmp_path / "activation-package"
    stage_release_payload(
        manifest,
        checkout=checkout,
        dependency_root=dependencies,
        stdlib_root=stdlib,
        package_root=package,
    )
    activation_package_module.stage_canary_identity(
        package,
        random_bytes=lambda size: b"I" * size,
    )
    render_systemd_units(
        manifest,
        templates_root=checkout / "systemd",
        output_root=package / "public" / "systemd",
        god_uid=os.getuid(),
        god_gid=os.getgid(),
        overseer_uid=984,
        python_path=python,
    )
    psychlo, roadex, bindings = _credential_sources(tmp_path)
    stage_credentials(
        package,
        psychlo_secret_file=psychlo,
        roadex_secret_file=roadex,
        psychlo_bindings_file=bindings,
        protected_gateway_ca_file=_gateway_ca(tmp_path),
        random_bytes=lambda size: b"C" * size,
        ticket_private_key=Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
    )
    source = tmp_path / "overseer.sqlite3"
    if stale_expression_index:
        _stale_expression_index_store(source, journal_mode="WAL")
    elif missing_admin_execution_claims:
        store = activation_package_module.SQLiteStore(source)
        store.close()
        with sqlite3.connect(source) as connection:
            connection.execute("DROP TABLE admin_execution_claims")
            connection.commit()
            assert connection.execute(
                "PRAGMA wal_checkpoint(TRUNCATE)"
            ).fetchone()[0] == 0
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
    psychlo = tmp_path / "psychlo" / "bridge.sqlite3"
    psychlo.parent.mkdir()
    _wal_store(psychlo)
    roadex = tmp_path / "roadex" / "relay.sqlite3"
    roadex.parent.mkdir()
    _wal_store(roadex)
    codex_usage = tmp_path / "codex-usage" / "state.sqlite3"
    codex_usage.parent.mkdir()
    _wal_store(codex_usage)
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
        psychlo_store=psychlo,
        roadex_store=roadex,
        codex_usage_store=codex_usage,
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


def test_migration_rehearsal_restores_canary_required_store_tables(
    tmp_path: Path,
) -> None:
    package, _manifest, _source = _prepared_package(
        tmp_path,
        missing_admin_execution_claims=True,
    )
    report = json.loads(
        (package / "private" / "migration" / "migration-report.json").read_text(
            encoding="utf-8"
        )
    )

    assert {
        "admin_change_plans",
        "admin_executions",
        "admin_execution_claims",
        "admin_history_archives",
    } <= set(report["schemaAfter"]["tableNames"])


def test_migration_rehearsal_rejects_schema_after_missing_canary_required_table(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_migration_evidence = activation_package_module._migration_evidence
    evidence_calls = 0

    def omit_canary_table_from_second_schema(
        path: Path,
        *,
        counted_tables: tuple[str, ...] | None = None,
    ) -> tuple[dict[str, int], dict[str, object]]:
        nonlocal evidence_calls
        evidence_calls += 1
        row_counts, schema = real_migration_evidence(
            path,
            counted_tables=counted_tables,
        )
        if evidence_calls == 2:
            schema = {
                **schema,
                "tableNames": [
                    name
                    for name in schema["tableNames"]
                    if name != "admin_execution_claims"
                ],
            }
        return row_counts, schema

    monkeypatch.setattr(
        activation_package_module,
        "_migration_evidence",
        omit_canary_table_from_second_schema,
    )

    with pytest.raises(
        ActivationPackageError,
        match="canary-required store tables",
    ):
        _prepared_package(tmp_path)

    assert evidence_calls == 2


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
    psychlo_store = tmp_path / "psychlo-state" / "bridge.sqlite3"
    psychlo_store.parent.mkdir()
    _wal_store(psychlo_store)
    roadex_store = tmp_path / "roadex-state" / "relay.sqlite3"
    roadex_store.parent.mkdir()
    _wal_store(roadex_store)
    codex_usage_store = tmp_path / "codex-usage-state" / "state.sqlite3"
    codex_usage_store.parent.mkdir()
    _wal_store(codex_usage_store)
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
            "--expected-commit",
            _reviewed_identity(checkout)["expected_commit"],
            "--expected-tree",
            _reviewed_identity(checkout)["expected_tree"],
            "--dependency-root",
            str(dependencies),
            "--root-python",
            str(python),
            "--stdlib-root",
            str(stdlib),
            "--sqlite-library",
            str(sqlite_library),
            "--templates-root",
            str(checkout / "systemd"),
            "--package-root",
            str(package),
            "--psychlo-secret-file",
            str(psychlo),
            "--roadex-secret-file",
            str(roadex),
            "--psychlo-bindings-file",
            str(bindings),
            "--protected-gateway-ca-file",
            str(_gateway_ca(tmp_path)),
            "--source-store",
            str(source),
            "--psychlo-store",
            str(psychlo_store),
            "--roadex-store",
            str(roadex_store),
            "--codex-usage-store",
            str(codex_usage_store),
            "--god-uid",
            str(os.getuid()),
            "--god-gid",
            str(os.getgid()),
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


def test_prepare_package_cli_rejects_god_gid_before_release_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_parent = tmp_path / "activation-packages"
    package_parent.mkdir(mode=0o700)
    monkeypatch.setattr(activation_package_module, "APPROVED_PACKAGE_PARENT", package_parent)
    package = package_parent / "v1.1.6-abcdef0"
    sqlite_library, _sqlite_evidence = _sqlite_runtime(
        tmp_path,
        package_root=package,
    )
    monkeypatch.setattr(
        activation_package_module,
        "build_release_manifest",
        lambda *_args, **_kwargs: pytest.fail(
            "invalid god GID must be rejected before manifest construction"
        ),
    )

    with pytest.raises(ActivationPackageError, match="UID/GID"):
        activation_package_module._main(
            [
                "prepare-package",
                "--checkout",
                str(tmp_path / "checkout"),
                "--expected-commit",
                "0" * 40,
                "--expected-tree",
                "0" * 40,
                "--dependency-root",
                str(tmp_path / "dependencies"),
                "--root-python",
                str(tmp_path / "python"),
                "--stdlib-root",
                str(tmp_path / "stdlib"),
                "--sqlite-library",
                str(sqlite_library),
                "--templates-root",
                str(tmp_path / "systemd"),
                "--package-root",
                str(package),
                "--psychlo-secret-file",
                str(tmp_path / "psychlo-secret"),
                "--roadex-secret-file",
                str(tmp_path / "roadex-secret"),
                "--psychlo-bindings-file",
                str(tmp_path / "bindings.json"),
                "--protected-gateway-ca-file",
                str(tmp_path / "gateway-ca.crt"),
                "--source-store",
                str(tmp_path / "overseer.sqlite3"),
                "--psychlo-store",
                str(tmp_path / "psychlo.sqlite3"),
                "--roadex-store",
                str(tmp_path / "roadex.sqlite3"),
                "--codex-usage-store",
                str(tmp_path / "codex-usage.sqlite3"),
                "--god-uid",
                str(os.getuid()),
                "--god-gid",
                str(os.getgid() + 1),
                "--overseer-uid",
                "984",
                "--overseer-gid",
                "984",
                "--rollback-input",
                f"v1.1.5-release={tmp_path / 'rollback-release'}",
            ]
        )

    assert not (package / "public" / "release").exists()


def test_ensure_dedicated_principal_reuses_exact_existing_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(
        pw_name="overseer",
        pw_uid=984,
        pw_gid=984,
        pw_dir="/var/lib/overseer",
        pw_shell="/usr/sbin/nologin",
    )
    group = SimpleNamespace(gr_name="overseer", gr_gid=984, gr_mem=[])
    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", lambda name: user)
    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", lambda uid: user)
    monkeypatch.setattr(activation_package_module.grp, "getgrnam", lambda name: group)
    monkeypatch.setattr(activation_package_module.grp, "getgrgid", lambda gid: group)
    monkeypatch.setattr(activation_package_module.pwd, "getpwall", lambda: [user])
    monkeypatch.setattr(activation_package_module.grp, "getgrall", lambda: [group])
    monkeypatch.setattr(activation_package_module.os, "getgrouplist", lambda _name, _gid: [984])
    monkeypatch.setattr(
        activation_package_module,
        "_validate_dedicated_principal_password_lock",
        lambda **_kwargs: None,
    )

    def unexpected_run(*args: object, **kwargs: object) -> object:
        raise AssertionError("exact existing principal must not invoke account creation")

    monkeypatch.setattr(activation_package_module.subprocess, "run", unexpected_run)

    assert activation_package_module._ensure_dedicated_principal_identity(
        uid=984,
        gid=984,
        home_dir="/var/lib/overseer",
        shell="/usr/sbin/nologin",
        lock_descriptor=17,
    ) == {
        "status": "existing",
        "user": "overseer",
        "uid": 984,
        "group": "overseer",
        "gid": 984,
    }


def test_ensure_dedicated_principal_creates_only_missing_exact_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state: dict[str, object | None] = {"user": None, "group": None}
    calls: list[list[str]] = []

    def user_by_name(name: str) -> object:
        if name != "overseer" or state["user"] is None:
            raise KeyError(name)
        return state["user"]

    def user_by_uid(uid: int) -> object:
        if uid != 984 or state["user"] is None:
            raise KeyError(uid)
        return state["user"]

    def group_by_name(name: str) -> object:
        if name != "overseer" or state["group"] is None:
            raise KeyError(name)
        return state["group"]

    def group_by_gid(gid: int) -> object:
        if gid != 984 or state["group"] is None:
            raise KeyError(gid)
        return state["group"]

    def create(command: list[str], **kwargs: object) -> object:
        calls.append(command)
        assert kwargs["pass_fds"] == (17,)
        assert kwargs["env"][activation_package_module.ACTIVATION_LOCK_FD_ENV] == "17"
        if command[0] == "/usr/sbin/groupadd":
            state["group"] = SimpleNamespace(gr_name="overseer", gr_gid=984, gr_mem=[])
        elif command[0] == "/usr/sbin/useradd":
            state["user"] = SimpleNamespace(
                pw_name="overseer",
                pw_uid=984,
                pw_gid=984,
                pw_dir="/var/lib/overseer",
                pw_shell="/usr/sbin/nologin",
            )
        else:
            raise AssertionError(f"unexpected principal command: {command}")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", user_by_name)
    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", user_by_uid)
    monkeypatch.setattr(activation_package_module.grp, "getgrnam", group_by_name)
    monkeypatch.setattr(activation_package_module.grp, "getgrgid", group_by_gid)
    monkeypatch.setattr(
        activation_package_module.pwd,
        "getpwall",
        lambda: [] if state["user"] is None else [state["user"]],
    )
    monkeypatch.setattr(
        activation_package_module.grp,
        "getgrall",
        lambda: [] if state["group"] is None else [state["group"]],
    )
    monkeypatch.setattr(activation_package_module.os, "getgrouplist", lambda _name, _gid: [984])
    monkeypatch.setattr(activation_package_module.subprocess, "run", create)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_dedicated_principal_password_lock",
        lambda **_kwargs: None,
    )

    result = activation_package_module._ensure_dedicated_principal_identity(
        uid=984,
        gid=984,
        home_dir="/var/lib/overseer",
        shell="/usr/sbin/nologin",
        lock_descriptor=17,
    )

    assert result["status"] == "created"
    assert calls == [
        ["/usr/sbin/groupadd", "--system", "--gid", "984", "overseer"],
        [
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
        ],
    ]


def test_ensure_dedicated_principal_completes_group_only_prior_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group = SimpleNamespace(gr_name="overseer", gr_gid=984, gr_mem=[])
    user: object | None = None
    calls: list[list[str]] = []

    def user_by_name(name: str) -> object:
        if user is None:
            raise KeyError(name)
        return user

    def user_by_uid(uid: int) -> object:
        if user is None:
            raise KeyError(uid)
        return user

    def create(command: list[str], **kwargs: object) -> object:
        nonlocal user
        calls.append(command)
        user = SimpleNamespace(
            pw_name="overseer",
            pw_uid=984,
            pw_gid=984,
            pw_dir="/var/lib/overseer",
            pw_shell="/usr/sbin/nologin",
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", user_by_name)
    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", user_by_uid)
    monkeypatch.setattr(activation_package_module.grp, "getgrnam", lambda name: group)
    monkeypatch.setattr(activation_package_module.grp, "getgrgid", lambda gid: group)
    monkeypatch.setattr(
        activation_package_module.pwd,
        "getpwall",
        lambda: [] if user is None else [user],
    )
    monkeypatch.setattr(activation_package_module.grp, "getgrall", lambda: [group])
    monkeypatch.setattr(activation_package_module.os, "getgrouplist", lambda _name, _gid: [984])
    monkeypatch.setattr(activation_package_module.subprocess, "run", create)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_dedicated_principal_password_lock",
        lambda **_kwargs: None,
    )

    result = activation_package_module._ensure_dedicated_principal_identity(
        uid=984,
        gid=984,
        home_dir="/var/lib/overseer",
        shell="/usr/sbin/nologin",
        lock_descriptor=19,
    )

    assert result["status"] == "created"
    assert len(calls) == 1
    assert calls[0][0] == "/usr/sbin/useradd"


def test_ensure_dedicated_principal_rejects_nonzero_child_even_after_identity_appears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group: object | None = None

    def missing_user(value: object) -> object:
        raise KeyError(value)

    def group_by_name(name: str) -> object:
        if group is None:
            raise KeyError(name)
        return group

    def group_by_gid(gid: int) -> object:
        if group is None:
            raise KeyError(gid)
        return group

    def failed_create(command: list[str], **kwargs: object) -> object:
        nonlocal group
        group = SimpleNamespace(gr_name="overseer", gr_gid=984, gr_mem=[])
        return SimpleNamespace(returncode=9)

    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", missing_user)
    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", missing_user)
    monkeypatch.setattr(activation_package_module.grp, "getgrnam", group_by_name)
    monkeypatch.setattr(activation_package_module.grp, "getgrgid", group_by_gid)
    monkeypatch.setattr(activation_package_module.pwd, "getpwall", lambda: [])
    monkeypatch.setattr(
        activation_package_module.grp,
        "getgrall",
        lambda: [] if group is None else [group],
    )
    monkeypatch.setattr(activation_package_module.subprocess, "run", failed_create)

    with pytest.raises(ActivationPackageError, match="group creation failed"):
        activation_package_module._ensure_dedicated_principal_identity(
            uid=984,
            gid=984,
            home_dir="/var/lib/overseer",
            shell="/usr/sbin/nologin",
            lock_descriptor=23,
        )


def test_ensure_dedicated_principal_rejects_name_to_uid_drift_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drifted = SimpleNamespace(
        pw_name="overseer",
        pw_uid=985,
        pw_gid=984,
        pw_dir="/var/lib/overseer",
        pw_shell="/usr/sbin/nologin",
    )
    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", lambda name: drifted)

    def missing_uid(uid: int) -> object:
        raise KeyError(uid)

    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", missing_uid)
    monkeypatch.setattr(activation_package_module.pwd, "getpwall", lambda: [drifted])
    monkeypatch.setattr(activation_package_module.grp, "getgrall", lambda: [])

    def unexpected_run(*args: object, **kwargs: object) -> object:
        raise AssertionError("identity drift must be rejected before mutation")

    monkeypatch.setattr(activation_package_module.subprocess, "run", unexpected_run)

    with pytest.raises(ActivationPackageError, match="name or UID"):
        activation_package_module._ensure_dedicated_principal_identity(
            uid=984,
            gid=984,
            home_dir="/var/lib/overseer",
            shell="/usr/sbin/nologin",
            lock_descriptor=17,
        )


@pytest.mark.parametrize(
    ("supplementary_members", "include_foreign_primary"),
    [(["god"], False), ([], True)],
)
def test_dedicated_principal_rejects_supplementary_and_foreign_primary_members(
    monkeypatch: pytest.MonkeyPatch,
    supplementary_members: list[str],
    include_foreign_primary: bool,
) -> None:
    overseer = SimpleNamespace(
        pw_name="overseer",
        pw_uid=984,
        pw_gid=984,
        pw_dir="/var/lib/overseer",
        pw_shell="/usr/sbin/nologin",
    )
    foreign = SimpleNamespace(
        pw_name="foreign",
        pw_uid=985,
        pw_gid=984,
        pw_dir="/var/empty",
        pw_shell="/usr/sbin/nologin",
    )
    group = SimpleNamespace(
        gr_name="overseer",
        gr_gid=984,
        gr_mem=supplementary_members,
    )
    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", lambda name: overseer)
    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", lambda uid: overseer)
    monkeypatch.setattr(activation_package_module.grp, "getgrnam", lambda name: group)
    monkeypatch.setattr(activation_package_module.grp, "getgrgid", lambda gid: group)
    monkeypatch.setattr(
        activation_package_module.pwd,
        "getpwall",
        lambda: [overseer, foreign] if include_foreign_primary else [overseer],
    )
    monkeypatch.setattr(activation_package_module.grp, "getgrall", lambda: [group])

    with pytest.raises(ActivationPackageError, match="membership"):
        activation_package_module._dedicated_principal_presence(
            uid=984,
            gid=984,
            home_dir="/var/lib/overseer",
            shell="/usr/sbin/nologin",
        )


def test_dedicated_principal_rejects_enumerated_foreign_supplementary_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overseer = SimpleNamespace(
        pw_name="overseer",
        pw_uid=984,
        pw_gid=984,
        pw_dir="/var/lib/overseer",
        pw_shell="/usr/sbin/nologin",
    )
    primary = SimpleNamespace(gr_name="overseer", gr_gid=984, gr_mem=[])
    foreign = SimpleNamespace(gr_name="docker", gr_gid=999, gr_mem=["overseer"])
    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", lambda _name: overseer)
    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", lambda _uid: overseer)
    monkeypatch.setattr(activation_package_module.grp, "getgrnam", lambda _name: primary)
    monkeypatch.setattr(activation_package_module.grp, "getgrgid", lambda _gid: primary)
    monkeypatch.setattr(activation_package_module.pwd, "getpwall", lambda: [overseer])
    monkeypatch.setattr(activation_package_module.grp, "getgrall", lambda: [primary, foreign])
    monkeypatch.setattr(activation_package_module.os, "getgrouplist", lambda _name, _gid: [984])

    with pytest.raises(ActivationPackageError, match="foreign supplementary"):
        activation_package_module._dedicated_principal_presence(
            uid=984,
            gid=984,
            home_dir="/var/lib/overseer",
            shell="/usr/sbin/nologin",
        )


def test_dedicated_principal_rejects_initgroups_only_foreign_membership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overseer = SimpleNamespace(
        pw_name="overseer",
        pw_uid=984,
        pw_gid=984,
        pw_dir="/var/lib/overseer",
        pw_shell="/usr/sbin/nologin",
    )
    primary = SimpleNamespace(gr_name="overseer", gr_gid=984, gr_mem=[])
    monkeypatch.setattr(activation_package_module.pwd, "getpwnam", lambda _name: overseer)
    monkeypatch.setattr(activation_package_module.pwd, "getpwuid", lambda _uid: overseer)
    monkeypatch.setattr(activation_package_module.grp, "getgrnam", lambda _name: primary)
    monkeypatch.setattr(activation_package_module.grp, "getgrgid", lambda _gid: primary)
    monkeypatch.setattr(activation_package_module.pwd, "getpwall", lambda: [overseer])
    monkeypatch.setattr(activation_package_module.grp, "getgrall", lambda: [primary])
    monkeypatch.setattr(
        activation_package_module.os,
        "getgrouplist",
        lambda _name, _gid: [984, 999],
    )

    with pytest.raises(ActivationPackageError, match="foreign supplementary"):
        activation_package_module._dedicated_principal_presence(
            uid=984,
            gid=984,
            home_dir="/var/lib/overseer",
            shell="/usr/sbin/nologin",
        )


def test_dedicated_principal_requires_locked_password_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def unlocked(command: list[str], **kwargs: object) -> object:
        observed["command"] = command
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="overseer P 2026-08-27 0 99999 7 -1\n")

    monkeypatch.setattr(activation_package_module.subprocess, "run", unlocked)
    with pytest.raises(ActivationPackageError, match="password.*locked"):
        activation_package_module._validate_dedicated_principal_password_lock(
            lock_descriptor=31
        )
    assert observed["command"] == ["/usr/bin/passwd", "--status", "overseer"]
    kwargs = observed["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["pass_fds"] == (31,)
    assert kwargs["env"][activation_package_module.ACTIVATION_LOCK_FD_ENV] == "31"


def test_dedicated_principal_accepts_only_locked_password_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        activation_package_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="overseer L 2026-08-27 0 99999 7 -1\n",
        ),
    )

    activation_package_module._validate_dedicated_principal_password_lock(
        lock_descriptor=31
    )


def test_ensure_dedicated_principal_requires_active_sealed_staging_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "approved-package"

    def reject(*args: object, **kwargs: object) -> object:
        raise ActivationPackageError("active staging command required")

    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", reject)
    with pytest.raises(ActivationPackageError, match="active staging command required"):
        activation_package_module.ensure_dedicated_principal(package_root=package)


def test_ensure_dedicated_principal_derives_identity_from_active_sealed_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = (tmp_path / "approved-package").resolve()
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": 1000, "gid": 1000},
    }
    observed: dict[str, object] = {}

    def active(*args: object, **kwargs: object) -> object:
        observed["activeArgs"] = args
        observed["activeKwargs"] = kwargs
        return contract, 29

    def ensure_identity(**kwargs: object) -> dict[str, object]:
        observed["identity"] = kwargs
        return {"status": "existing"}

    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", active)
    monkeypatch.setattr(
        activation_package_module,
        "_ensure_dedicated_principal_identity",
        ensure_identity,
    )

    assert activation_package_module.ensure_dedicated_principal(package_root=package) == {
        "status": "existing"
    }
    assert observed["activeKwargs"] == {
        "phase": "staging-canary",
        "command_name": "ensure-dedicated-principal",
        "expected_options": {"--package-root": str(package)},
    }
    assert observed["identity"] == {
        "uid": 984,
        "gid": 984,
        "home_dir": "/var/lib/overseer",
        "shell": "/usr/sbin/nologin",
        "lock_descriptor": 29,
    }


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
    principal_commands = [
        command for command in staging_commands if "ensure-dedicated-principal" in command
    ]
    assert len(principal_commands) == 1
    assert staging_commands[0] == principal_commands[0]
    assert principal_commands[0][-3:] == [
        "ensure-dedicated-principal",
        "--package-root",
        "/var/lib/overseer-executor/approved-package",
    ]
    assert "PYTHONDONTWRITEBYTECODE=1" in principal_commands[0]
    assert "-B" in principal_commands[0]
    assert all(
        not any(Path(argument).name in {"groupadd", "useradd"} for argument in command)
        for command in commands
    )
    for command in commands:
        if command and command[0] == "/usr/bin/install":
            assert command[command.index("-o") + 1] != "overseer"
            assert command[command.index("-g") + 1] != "overseer"
    activation_package_module._validate_contract_principal_bootstrap(
        Path(str(contract["packageRoot"])),
        contract,
    )
    misplaced = dict(contract)
    misplaced_commands = [list(command) for command in staging_commands[1:]]
    misplaced_commands.append(list(staging_commands[0]))
    misplaced["stagingAndCanaryCommands"] = misplaced_commands
    with pytest.raises(ActivationPackageError, match="principal bootstrap"):
        activation_package_module._validate_contract_principal_bootstrap(
            Path(str(contract["packageRoot"])),
            misplaced,
        )
    wrapped_account_command = dict(contract)
    wrapped_account_command["cutoverCommands"] = [
        *cutover_commands,
        ["/usr/bin/env", "/usr/sbin/groupadd", "unexpected"],
    ]
    with pytest.raises(ActivationPackageError, match="principal bootstrap"):
        activation_package_module._validate_contract_principal_bootstrap(
            Path(str(contract["packageRoot"])),
            wrapped_account_command,
        )
    for script in (
        "/usr/sbin/'useradd' unexpected",
        "user''add unexpected",
        "x=/usr/sbin/user; ${x}add unexpected",
    ):
        shell_wrapped_account_command = dict(contract)
        shell_wrapped_account_command["cutoverCommands"] = [
            *cutover_commands,
            ["/bin/sh", "-c", script],
        ]
        with pytest.raises(ActivationPackageError, match="principal bootstrap"):
            activation_package_module._validate_contract_principal_bootstrap(
                Path(str(contract["packageRoot"])),
                shell_wrapped_account_command,
            )
    split_commands = [
        ["/usr/bin/env", "-S", "bash -c '/usr/sbin/useradd unexpected'"],
        ["/usr/bin/env", "-Sbash -c '/usr/sbin/useradd unexpected'"],
        ["/usr/bin/env", "-iSbash -c '/usr/sbin/useradd unexpected'"],
    ]
    split_commands.extend(
        [
            "/usr/bin/env",
            f"{'--split-string'[:prefix_length]}=sh -c '/usr/sbin/groupadd unexpected'",
        ]
        for prefix_length in range(3, len("--split-string") + 1)
    )
    for split_command in split_commands:
        split_wrapped_account_command = dict(contract)
        split_wrapped_account_command["cutoverCommands"] = [
            *cutover_commands,
            split_command,
        ]
        with pytest.raises(ActivationPackageError, match="principal bootstrap"):
            activation_package_module._validate_contract_principal_bootstrap(
                Path(str(contract["packageRoot"])),
                split_wrapped_account_command,
            )
    traversing_release = dict(contract)
    traversing_release["releaseRoot"] = "/opt/overseer/releases/../unexpected"
    with pytest.raises(ActivationPackageError, match="release root"):
        activation_package_module._validate_contract_principal_bootstrap(
            Path(str(contract["packageRoot"])),
            traversing_release,
        )
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
        "overseer-approval-smoke.service",
        "overseer-api-canary.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    ]
    assert "verify-approved-cutover" in cutover_commands[0]
    staging_verify_index = next(
        index for index, command in enumerate(staging_commands) if "verify-approved-staging" in command
    )
    canary_stage_index = next(
        index for index, command in enumerate(staging_commands) if "stage-canary-store" in command
    )
    canary_start_index = next(
        index
        for index, command in enumerate(staging_commands)
        if "handoff-start-canary" in command
    )
    assert canary_stage_index < staging_verify_index < canary_start_index
    assert all(
        command != ["/usr/bin/systemctl", "start", "overseer-api-canary.service"]
        for command in staging_commands
    )
    canary_command_index = next(
        index for index, command in enumerate(staging_commands) if "run-approved-canary" in command
    )
    assert activation_package_module._canary_authorization_boundary_index(
        staging_commands,
        canary_command_index=canary_command_index,
        failure_cleanup_commands=contract["canary"]["failureCleanupCommands"],
    ) == canary_start_index - 1
    with pytest.raises(ActivationPackageError, match="canary cleanup boundary"):
        activation_package_module._canary_authorization_boundary_index(
            staging_commands,
            canary_command_index=canary_command_index,
            failure_cleanup_commands=[["/bin/true", "cleanup"]],
        )
    canary_instance = json.loads(
        (package / "public/canary-instance.json").read_text(encoding="utf-8")
    )
    canary_state = Path("/var/lib/overseer-canary") / canary_instance["canaryInstanceId"]
    assert contract["canary"] == {
        "canaryInstanceId": canary_instance["canaryInstanceId"],
        "stateDirectory": str(canary_state),
        "store": str(canary_state / "overseer.sqlite3"),
        "psychloBridgeDatabase": str(canary_state / "psychlo-bridge.sqlite3"),
        "roadexRelayDatabase": str(canary_state / "roadex-relay.sqlite3"),
        "preserveFailedStateForEvidence": True,
        "ownershipHandoffCommand": "handoff-start-canary",
        "requiresNoExistingServicePrincipalProcesses": True,
        "unixSocket": "/run/overseer-canary/api.sock",
        "serverPeerUid": 984,
        "allowedClientUid": 0,
        "mustPassBeforeLegacyStop": True,
        "mutatingExecutorAcceptanceRequiresInteractiveAdminApproval": True,
        "failureCleanupCommands": [
            [
                "/usr/bin/systemctl",
                "stop",
                "overseer-approval-smoke.service",
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
    assert all(
        f"--uid={os.getuid()}" in command and f"--gid={os.getgid()}" in command
        for command in rollback_transients
    )
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
    package_release_root = (
        Path("/var/lib/overseer-executor/approved-package/public/release")
        / Path(str(manifest["releaseRoot"])).name
    )
    assert f"LD_LIBRARY_PATH={package_release_root}/lib" in principal_commands[0]
    installed_release_python_commands = [
        command for command in release_python_commands if command != principal_commands[0]
    ]
    assert installed_release_python_commands
    assert all(
        f"LD_LIBRARY_PATH={manifest['releaseRoot']}/lib" in command
        for command in installed_release_python_commands
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


def test_sealed_principal_python_command_does_not_write_bytecode(tmp_path: Path) -> None:
    package, manifest, source = _prepared_package(tmp_path)
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    (rollback / "artifact").write_text("rollback\n", encoding="utf-8")
    contract = render_activation_contract(
        package,
        manifest,
        source_store=source,
        overseer_uid=984,
        overseer_gid=984,
        rollback_inputs={"v1.1.5-release": rollback},
    )
    command = list(contract["stagingAndCanaryCommands"][0])
    module_root = tmp_path / "sealed-module"
    module_root.mkdir()
    (module_root / "sealed_probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    executable_index = command.index("-B") - 1
    command[1] = "LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu"
    command[2] = "PYTHONHOME=/usr"
    command[3] = f"PYTHONPATH={module_root}"
    command[executable_index] = sys.executable
    command[executable_index + 1 :] = ["-B", "-s", "-P", "-c", "import sealed_probe"]

    result = subprocess.run(command, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not (module_root / "__pycache__").exists()


def test_canary_store_staging_uses_new_release_bound_directory_and_rejects_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, manifest, _source = _prepared_package(tmp_path)
    tmp_path.chmod(0o755)
    canary_root = tmp_path / "overseer-canary"
    canary_instance_id = json.loads(
        (package / "public/canary-instance.json").read_text(encoding="utf-8")
    )["canaryInstanceId"]
    state_directory = canary_root / canary_instance_id
    store = state_directory / "overseer.sqlite3"
    stale_state = tmp_path / "legacy-overseer-state"
    stale_state.mkdir(mode=0o700)
    stale_fixed_store = stale_state / "overseer-canary.sqlite3"
    stale_fixed_store.write_bytes(b"preserved failed canary evidence")
    stale_fixed_store.chmod(0o600)
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "releaseRoot": str(manifest["releaseRoot"]),
        "account": {
            "user": "overseer",
            "uid": os.geteuid(),
            "group": "overseer",
            "gid": os.getegid(),
        },
        "sourceStore": {"uid": os.geteuid(), "gid": os.getegid()},
        "canary": {
            "canaryInstanceId": canary_instance_id,
            "stateDirectory": str(state_directory),
            "store": str(store),
            "psychloBridgeDatabase": str(state_directory / "psychlo-bridge.sqlite3"),
            "roadexRelayDatabase": str(state_directory / "roadex-relay.sqlite3"),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
        },
    }
    monkeypatch.setattr(activation_package_module, "CANARY_STATE_ROOT", canary_root)
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_GID", os.getegid())
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_require_active_phase_command",
        lambda *_args, **_kwargs: (contract, 29),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval",
        lambda _package: {"packageDigest": "a" * 64},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_canary_identity",
        lambda _package, **_kwargs: {
            "schemaVersion": activation_package_module.CANARY_INSTANCE_SCHEMA,
            "canaryInstanceId": canary_instance_id,
        },
    )

    result = activation_package_module.stage_canary_store(package)

    assert result["verified"] is True
    assert result["stateDirectory"] == str(state_directory)
    assert result["store"] == str(store)
    assert store.is_file()
    assert store.stat().st_mode & 0o777 == 0o600
    assert stale_fixed_store.read_bytes() == b"preserved failed canary evidence"
    assert sorted(path.name for path in state_directory.iterdir()) == [
        "overseer.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
    ]
    assert (state_directory / "psychlo-bridge.sqlite3").stat().st_size == 0
    assert (state_directory / "roadex-relay.sqlite3").stat().st_size == 0
    canary_root.chmod(0o700)
    with pytest.raises(ActivationPackageError, match="canary state root identity or mode"):
        activation_package_module.stage_canary_store(package)
    canary_root.chmod(0o711)
    with pytest.raises(ActivationPackageError, match="state directory already exists"):
        activation_package_module.stage_canary_store(package)


def test_staged_canary_store_verification_rejects_sqlite_sidecars_and_hash_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, manifest, _source = _prepared_package(tmp_path)
    tmp_path.chmod(0o755)
    canary_root = tmp_path / "overseer-canary"
    canary_instance_id = json.loads(
        (package / "public/canary-instance.json").read_text(encoding="utf-8")
    )["canaryInstanceId"]
    state_directory = canary_root / canary_instance_id
    store = state_directory / "overseer.sqlite3"
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "releaseRoot": str(manifest["releaseRoot"]),
        "account": {
            "user": "overseer",
            "uid": os.geteuid(),
            "group": "overseer",
            "gid": os.getegid(),
        },
        "sourceStore": {"uid": os.geteuid(), "gid": os.getegid()},
        "canary": {
            "canaryInstanceId": canary_instance_id,
            "stateDirectory": str(state_directory),
            "store": str(store),
            "psychloBridgeDatabase": str(state_directory / "psychlo-bridge.sqlite3"),
            "roadexRelayDatabase": str(state_directory / "roadex-relay.sqlite3"),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
        },
    }
    monkeypatch.setattr(activation_package_module, "CANARY_STATE_ROOT", canary_root)
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_GID", os.getegid())
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_require_active_phase_command",
        lambda *_args, **_kwargs: (contract, 29),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval",
        lambda _package: {"packageDigest": "a" * 64},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_canary_identity",
        lambda _package, **_kwargs: {
            "schemaVersion": activation_package_module.CANARY_INSTANCE_SCHEMA,
            "canaryInstanceId": canary_instance_id,
        },
    )
    activation_package_module.stage_canary_store(package)
    activation_package_module._verify_staged_canary_store(package, contract)

    for database in (
        store,
        state_directory / "psychlo-bridge.sqlite3",
        state_directory / "roadex-relay.sqlite3",
    ):
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(f"{database}{suffix}")
            sidecar.write_bytes(b"stale sidecar")
            with pytest.raises(ActivationPackageError, match="unexpected canary SQLite artifact"):
                activation_package_module._verify_staged_canary_store(package, contract)
            sidecar.unlink()

    psychlo_database = state_directory / "psychlo-bridge.sqlite3"
    roadex_database = state_directory / "roadex-relay.sqlite3"
    psychlo_database.unlink()
    psychlo_database.symlink_to(roadex_database)
    with pytest.raises(ActivationPackageError, match="regular file|symlink"):
        activation_package_module._verify_staged_canary_store(package, contract)
    psychlo_database.unlink()
    psychlo_database.write_bytes(b"")
    psychlo_database.chmod(0o600)

    roadex_database.unlink()
    os.link(psychlo_database, roadex_database)
    with pytest.raises(ActivationPackageError, match="pristine|single-link"):
        activation_package_module._verify_staged_canary_store(package, contract)
    roadex_database.unlink()
    roadex_database.write_bytes(b"")
    roadex_database.chmod(0o600)

    real_stream_hash = activation_package_module._stream_hash_regular

    def reject_auxiliary_hash(path: Path, **kwargs: object) -> dict[str, object]:
        if path == psychlo_database:
            pytest.fail("nonempty auxiliary database must be rejected before hashing")
        return real_stream_hash(path, **kwargs)

    monkeypatch.setattr(
        activation_package_module,
        "_stream_hash_regular",
        reject_auxiliary_hash,
    )
    psychlo_database.write_bytes(b"oversized")
    with pytest.raises(ActivationPackageError, match="pristine"):
        activation_package_module._verify_staged_canary_store(package, contract)
    psychlo_database.write_bytes(b"")
    monkeypatch.setattr(
        activation_package_module,
        "_stream_hash_regular",
        real_stream_hash,
    )

    drifted_contract = json.loads(json.dumps(contract))
    drifted_contract["canary"]["store"] = str(tmp_path / "overseer-canary.sqlite3")
    with pytest.raises(ActivationPackageError, match="canary state contract drifted"):
        activation_package_module._verify_staged_canary_store(package, drifted_contract)

    with store.open("ab") as target:
        target.write(b"drift")
    real_evidence = activation_package_module._sealed_migration_artifact_evidence

    def reject_target_hash(path: Path, **kwargs: object) -> dict[str, object]:
        if path == store:
            pytest.fail("drifted target must be rejected by size before hashing")
        return real_evidence(path, **kwargs)

    monkeypatch.setattr(
        activation_package_module,
        "_sealed_migration_artifact_evidence",
        reject_target_hash,
    )
    with pytest.raises(ActivationPackageError, match="size"):
        activation_package_module._verify_staged_canary_store(package, contract)


def test_failed_canary_store_copy_fsyncs_the_preserved_instance_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, manifest, _source = _prepared_package(tmp_path)
    tmp_path.chmod(0o755)
    canary_root = tmp_path / "overseer-canary"
    canary_instance_id = json.loads(
        (package / "public/canary-instance.json").read_text(encoding="utf-8")
    )["canaryInstanceId"]
    state_directory = canary_root / canary_instance_id
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "releaseRoot": str(manifest["releaseRoot"]),
        "account": {
            "user": "overseer",
            "uid": os.geteuid(),
            "group": "overseer",
            "gid": os.getegid(),
        },
        "sourceStore": {"uid": os.geteuid(), "gid": os.getegid()},
        "canary": {
            "canaryInstanceId": canary_instance_id,
            "stateDirectory": str(state_directory),
            "store": str(state_directory / "overseer.sqlite3"),
            "psychloBridgeDatabase": str(state_directory / "psychlo-bridge.sqlite3"),
            "roadexRelayDatabase": str(state_directory / "roadex-relay.sqlite3"),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
        },
    }
    monkeypatch.setattr(activation_package_module, "CANARY_STATE_ROOT", canary_root)
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_GID", os.getegid())
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_require_active_phase_command",
        lambda *_args, **_kwargs: (contract, 29),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_canary_identity",
        lambda _package, **_kwargs: {
            "schemaVersion": activation_package_module.CANARY_INSTANCE_SCHEMA,
            "canaryInstanceId": canary_instance_id,
        },
    )
    synced_inodes: set[int] = set()
    real_fsync = os.fsync

    def tracked_fsync(descriptor: int) -> None:
        synced_inodes.add(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", tracked_fsync)
    monkeypatch.setattr(
        activation_package_module,
        "_copy_canary_store_at",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ActivationPackageError("simulated canary copy failure")
        ),
    )

    with pytest.raises(ActivationPackageError, match="simulated canary copy failure"):
        activation_package_module.stage_canary_store(package)

    assert state_directory.is_dir()
    assert state_directory.stat().st_ino in synced_inodes


def test_failed_partial_canary_copy_fsyncs_the_target_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.sqlite3"
    source.write_bytes(b"canary-copy-evidence")
    source.chmod(0o600)
    destination = tmp_path / "destination"
    destination.mkdir(mode=0o700)
    directory_descriptor = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    synced_inodes: set[int] = set()
    real_write = os.write
    real_fsync = os.fsync
    writes = 0

    def partial_then_fail(descriptor: int, value: object) -> int:
        nonlocal writes
        writes += 1
        if writes == 1:
            return real_write(descriptor, memoryview(value)[:1])
        raise OSError("simulated interrupted target write")

    def tracked_fsync(descriptor: int) -> None:
        synced_inodes.add(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    monkeypatch.setattr(os, "write", partial_then_fail)
    monkeypatch.setattr(os, "fsync", tracked_fsync)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    try:
        with pytest.raises(ActivationPackageError, match="staged safely"):
            activation_package_module._copy_canary_store_at(
                source,
                expected_source_uid=os.geteuid(),
                target_directory_descriptor=directory_descriptor,
                target_name="overseer.sqlite3",
            )
    finally:
        os.close(directory_descriptor)

    target = destination / "overseer.sqlite3"
    assert target.stat().st_size == 1
    assert target.stat().st_ino in synced_inodes


def test_canary_handoff_refuses_existing_service_process_then_starts_exact_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, manifest, _source = _prepared_package(tmp_path)
    tmp_path.chmod(0o755)
    canary_root = tmp_path / "overseer-canary"
    canary_instance_id = json.loads(
        (package / "public/canary-instance.json").read_text(encoding="utf-8")
    )["canaryInstanceId"]
    state_directory = canary_root / canary_instance_id
    paths = {
        "canaryInstanceId": canary_instance_id,
        "stateDirectory": state_directory,
        "store": state_directory / "overseer.sqlite3",
        "psychloBridgeDatabase": state_directory / "psychlo-bridge.sqlite3",
        "roadexRelayDatabase": state_directory / "roadex-relay.sqlite3",
    }
    canary_root.mkdir(mode=0o711)
    state_directory.mkdir(mode=0o700)
    shutil.copyfile(
        package / "private/migration/rehearsal-migrated.sqlite3",
        paths["store"],
    )
    for path in (
        paths["store"],
        paths["psychloBridgeDatabase"],
        paths["roadexRelayDatabase"],
    ):
        selected = Path(path)
        if not selected.exists():
            selected.write_bytes(b"")
        selected.chmod(0o600)
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "releaseRoot": str(manifest["releaseRoot"]),
        "account": {
            "user": "overseer",
            "uid": os.geteuid(),
            "group": "overseer",
            "gid": os.getegid(),
        },
        "sourceStore": {"uid": os.geteuid(), "gid": os.getegid()},
        "canary": {
            "canaryInstanceId": canary_instance_id,
            "stateDirectory": str(state_directory),
            "store": str(paths["store"]),
            "psychloBridgeDatabase": str(paths["psychloBridgeDatabase"]),
            "roadexRelayDatabase": str(paths["roadexRelayDatabase"]),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
        },
    }
    monkeypatch.setattr(activation_package_module, "CANARY_STATE_ROOT", canary_root)
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_GID", os.getegid())
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_require_active_phase_command",
        lambda *_args, **_kwargs: (contract, 29),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_state",
        lambda: {"packageDigest": "a" * 64},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_canary_contract_layout",
        lambda *_args, **_kwargs: paths,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_verify_staged_canary_store",
        lambda *_args, **_kwargs: {"verified": True},
    )
    calls: list[list[str]] = []

    def execute_inherited(command: list[str], *, lock_descriptor: int) -> int:
        assert lock_descriptor == 29
        calls.append(command)
        return 3 if "is-active" in command else 0

    monkeypatch.setattr(
        activation_package_module,
        "_execute_inherited_contract_command",
        execute_inherited,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda _uid: (12345,),
        raising=False,
    )

    with pytest.raises(ActivationPackageError, match="service principal process"):
        activation_package_module.handoff_start_canary(package)
    assert calls == [
        [
            "/usr/bin/systemctl",
            "is-active",
            "--quiet",
            "overseer-api-canary.service",
        ]
    ]
    calls.clear()

    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda _uid: (),
        raising=False,
    )
    result = activation_package_module.handoff_start_canary(package)

    assert result["started"] is True
    assert calls == [
        [
            "/usr/bin/systemctl",
            "is-active",
            "--quiet",
            "overseer-api-canary.service",
        ],
        ["/usr/bin/systemctl", "start", "overseer-api-canary.service"],
    ]


def test_inherited_child_executor_works_without_parent_process_global(
    tmp_path: Path,
) -> None:
    lock = tmp_path / "activation.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    os.fchmod(descriptor, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    checkout = Path(__file__).resolve().parents[1]
    script = "\n".join(
        (
            "import os",
            "from pathlib import Path",
            "import overseer.activation_package as package",
            f"package._activation_lock_path = lambda: Path({str(lock)!r})",
            "package._activation_root_identity = lambda: (os.geteuid(), os.getegid())",
            "assert package._ACTIVE_EXECUTION_LOCK_DESCRIPTOR is None",
            (
                "raise SystemExit(package._execute_inherited_contract_command("
                f"['/usr/bin/true'], lock_descriptor={descriptor}))"
            ),
        )
    )
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": str(checkout / "src"),
        activation_package_module.ACTIVATION_LOCK_FD_ENV: str(descriptor),
    }
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-s", "-P", "-c", script],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)

    assert result.returncode == 0, result.stderr


def test_canary_evidence_seal_requires_quiescence_and_root_seals_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o755)
    canary_root = tmp_path / "overseer-canary"
    instance = "ab" * activation_package_module.CANARY_INSTANCE_BYTES
    state_directory = canary_root / instance
    canary_root.mkdir(mode=0o711)
    state_directory.mkdir(mode=0o700)
    names = (
        "overseer.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
        "overseer.sqlite3-wal",
        "roadex-relay.sqlite3-shm",
        ".overseer.sqlite3.admin-authority.lock",
    )
    for name in names:
        path = state_directory / name
        path.write_bytes(
            b"" if name == ".overseer.sqlite3.admin-authority.lock" else name.encode("ascii")
        )
        path.chmod(0o600)
    contract = {
        "canary": {
            "canaryInstanceId": instance,
            "stateDirectory": str(state_directory),
            "store": str(state_directory / "overseer.sqlite3"),
            "psychloBridgeDatabase": str(state_directory / "psychlo-bridge.sqlite3"),
            "roadexRelayDatabase": str(state_directory / "roadex-relay.sqlite3"),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
        }
    }
    monkeypatch.setattr(activation_package_module, "CANARY_STATE_ROOT", canary_root)
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_GID", os.getegid())
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    inactive_checks: list[list[str]] = []

    def inactive_outcome(command: list[str], **_kwargs: object) -> tuple[int, None]:
        inactive_checks.append(command)
        return 3, None

    monkeypatch.setattr(
        activation_package_module,
        "_command_outcome",
        inactive_outcome,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda _uid: (12345,),
    )

    with pytest.raises(ActivationPackageError, match="service principal process"):
        activation_package_module._seal_canary_state_from_contract(contract, required=True)

    monkeypatch.setattr(
        activation_package_module,
        "_processes_for_uid",
        lambda _uid: (),
    )
    fifo = state_directory / "overseer.sqlite3-wal"
    fifo.unlink()
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ActivationPackageError, match="artifact identity"):
        activation_package_module._seal_canary_state_from_contract(
            contract,
            required=True,
        )
    fifo.unlink()
    fifo.write_bytes(b"overseer.sqlite3-wal")
    fifo.chmod(0o600)
    authority_lock = state_directory / ".overseer.sqlite3.admin-authority.lock"
    authority_lock.write_bytes(b"unexpected lock payload")
    with pytest.raises(ActivationPackageError, match="artifact identity"):
        activation_package_module._seal_canary_state_from_contract(
            contract,
            required=True,
        )
    authority_lock.write_bytes(b"")
    unexpected = state_directory / "unexpected-artifact"
    unexpected.write_bytes(b"")
    unexpected.chmod(0o600)
    with pytest.raises(ActivationPackageError, match="invalid artifact"):
        activation_package_module._seal_canary_state_from_contract(
            contract,
            required=True,
        )
    unexpected.unlink()
    hardlink = tmp_path / "authority-lock-hardlink"
    os.link(authority_lock, hardlink)
    with pytest.raises(ActivationPackageError, match="artifact identity"):
        activation_package_module._seal_canary_state_from_contract(
            contract,
            required=True,
        )
    hardlink.unlink()
    held_descriptor = os.open(authority_lock, os.O_RDWR)
    try:
        fcntl.flock(held_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ActivationPackageError, match="authority lock is active"):
            activation_package_module._seal_canary_state_from_contract(
                contract,
                required=True,
            )
    finally:
        fcntl.flock(held_descriptor, fcntl.LOCK_UN)
        os.close(held_descriptor)
    real_flock = activation_package_module.fcntl.flock
    lock_mutated = False

    def mutate_lock_before_sealing(descriptor: int, operation: int) -> None:
        nonlocal lock_mutated
        if operation == fcntl.LOCK_EX | fcntl.LOCK_NB and not lock_mutated:
            writer = os.open(authority_lock, os.O_WRONLY)
            try:
                os.write(writer, b"raced")
            finally:
                os.close(writer)
            lock_mutated = True
        real_flock(descriptor, operation)

    activation_package_module.fcntl.flock = mutate_lock_before_sealing
    try:
        with pytest.raises(ActivationPackageError, match="artifact identity"):
            activation_package_module._seal_canary_state_from_contract(
                contract,
                required=True,
            )
    finally:
        activation_package_module.fcntl.flock = real_flock
    authority_lock.write_bytes(b"")
    inactive_checks.clear()
    result = activation_package_module._seal_canary_state_from_contract(
        contract,
        required=True,
    )

    assert result["sealed"] is True
    assert state_directory.stat().st_mode & 0o777 == 0o500
    assert sorted(path.name for path in state_directory.iterdir()) == sorted(names)
    assert all(path.stat().st_mode & 0o777 == 0o400 for path in state_directory.iterdir())
    before_verification = {
        path.name: (
            path.stat().st_mode,
            path.stat().st_uid,
            path.stat().st_gid,
            path.stat().st_ctime_ns,
        )
        for path in (state_directory, *state_directory.iterdir())
    }
    verified = activation_package_module._verify_sealed_canary_state_from_contract(
        contract,
        required=True,
    )
    after_verification = {
        path.name: (
            path.stat().st_mode,
            path.stat().st_uid,
            path.stat().st_gid,
            path.stat().st_ctime_ns,
        )
        for path in (state_directory, *state_directory.iterdir())
    }
    assert verified["sealed"] is True
    assert after_verification == before_verification
    assert inactive_checks == [
        ["/usr/bin/systemctl", "is-active", "--quiet", "overseer-api-canary.service"]
    ] * 6


def test_resilient_cleanup_seals_canary_evidence_after_stopping_units(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    contract = {"canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]}}
    events: list[str] = []
    original_emit = activation_package_module.emit_activation_progress
    monkeypatch.setattr(
        activation_package_module,
        "_execute_cleanup_sequence",
        lambda *_args, **_kwargs: events.append("stopped"),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **kwargs: events.append(f"sealed:{kwargs['required']}")
        or {"sealed": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_write_recovery_state_best_effort",
        lambda document: events.append(f"checkpoint:{document['status']}") or True,
    )
    monkeypatch.setattr(
        activation_package_module,
        "emit_activation_progress",
        lambda **kwargs: events.append(f"progress:{kwargs['status']}")
        or original_emit(**kwargs),
    )

    assert activation_package_module._execute_resilient_cleanup(
        contract,
        package_digest="a" * 64,
    ) is True
    assert events == [
        "stopped",
        "sealed:False",
        "checkpoint:aborted_before_cutover",
        "progress:evidence-seal-complete",
    ]
    progress_records = [
        json.loads(line) for line in capsys.readouterr().err.splitlines()
    ]
    assert [record["status"] for record in progress_records] == [
        "evidence-seal-complete",
    ]
    assert all(record["secretValuesRecorded"] is False for record in progress_records)


def test_resilient_cleanup_checkpoints_evidence_sealing_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    contract = {"canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]}}
    checkpoints: list[dict[str, object]] = []
    events: list[str] = []
    original_emit = activation_package_module.emit_activation_progress
    monkeypatch.setattr(
        activation_package_module,
        "_execute_cleanup_sequence",
        lambda *_args, **_kwargs: None,
    )

    def fail_sealing(*_args: object, **_kwargs: object) -> dict[str, object]:
        events.append("seal-failed")
        raise ActivationPackageError("evidence sealing failed")

    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        fail_sealing,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_write_recovery_state_best_effort",
        lambda document: checkpoints.append(dict(document))
        or events.append(f"checkpoint:{document['status']}")
        or True,
    )
    monkeypatch.setattr(
        activation_package_module,
        "emit_activation_progress",
        lambda **kwargs: events.append(f"progress:{kwargs['status']}")
        or original_emit(**kwargs),
    )

    with pytest.raises(ActivationPackageError, match="evidence sealing failed"):
        activation_package_module._execute_resilient_cleanup(
            contract,
            package_digest="a" * 64,
            originating_failure="ActivationPackageError",
        )

    assert len(checkpoints) == 1
    assert checkpoints[0]["packageDigest"] == "a" * 64
    assert checkpoints[0]["phase"] == "staging_cleanup"
    assert checkpoints[0]["status"] == "cleanup_evidence_seal_failed"
    assert checkpoints[0]["failure"] == "ActivationPackageError"
    assert checkpoints[0]["secretValuesRecorded"] is False
    assert events == [
        "seal-failed",
        "checkpoint:cleanup_evidence_seal_failed",
        "progress:evidence-seal-failed",
    ]
    progress_records = [
        json.loads(line) for line in capsys.readouterr().err.splitlines()
    ]
    assert [record["status"] for record in progress_records] == [
        "evidence-seal-failed",
    ]


def test_resilient_cleanup_omits_evidence_progress_without_durable_recovery_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    contract = {"canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]}}
    monkeypatch.setattr(
        activation_package_module,
        "_execute_cleanup_sequence",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_write_recovery_state_best_effort",
        lambda _document: False,
    )

    assert activation_package_module._execute_resilient_cleanup(
        contract,
        package_digest="a" * 64,
    ) is False
    assert capsys.readouterr().err == ""


def test_resilient_cleanup_omits_failed_evidence_progress_without_durable_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    contract = {"canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]}}
    monkeypatch.setattr(
        activation_package_module,
        "_execute_cleanup_sequence",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ActivationPackageError("evidence sealing failed")
        ),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_write_recovery_state_best_effort",
        lambda _document: False,
    )

    with pytest.raises(ActivationPackageError, match="evidence sealing failed"):
        activation_package_module._execute_resilient_cleanup(
            contract,
            package_digest="a" * 64,
        )
    assert capsys.readouterr().err == ""


def test_current_schema_cleanup_requires_inventoried_canary_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    checkpoints: list[dict[str, object]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_execute_cleanup_sequence",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_write_recovery_state_best_effort",
        lambda document: checkpoints.append(dict(document)) or True,
    )

    with pytest.raises(ActivationPackageError, match="evidence contract is unavailable"):
        activation_package_module._execute_resilient_cleanup(
            contract,
            package_digest="b" * 64,
            originating_failure="ActivationPackageError",
        )

    assert checkpoints[0]["status"] == "cleanup_evidence_seal_failed"
    assert checkpoints[0]["phase"] == "staging_cleanup"
    assert checkpoints[0]["secretValuesRecorded"] is False


def test_current_schema_aborted_replay_requires_canary_evidence_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "e" * 64
    package = tmp_path / "package"
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.geteuid(), "gid": os.getegid()},
        "stagingAndCanaryCommands": [["/bin/true", "staging"]],
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval_for_rollback",
        lambda _package: {"packageDigest": digest},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_sealed_package_json",
        lambda *_args, **_kwargs: contract,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_state",
        lambda: activation_package_module._runner_state(
            package_digest=digest,
            status="aborted_before_cutover",
            phase="staging_cleanup",
            failure="ActivationPackageError",
        ),
    )

    with pytest.raises(ActivationPackageError, match="evidence contract is unavailable"):
        activation_package_module._execute_approved_rollback_locked(package)


def test_staging_rollback_recovers_and_revalidates_sealed_authority_lock_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "d" * 64
    package = tmp_path / "package"
    package.mkdir()
    tmp_path.chmod(0o755)
    canary_root = tmp_path / "overseer-canary"
    instance = "cd" * activation_package_module.CANARY_INSTANCE_BYTES
    state_directory = canary_root / instance
    canary_root.mkdir(mode=0o711)
    state_directory.mkdir(mode=0o700)
    for name in (
        "overseer.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
    ):
        path = state_directory / name
        path.write_bytes(name.encode("ascii"))
        path.chmod(0o600)
    authority_lock = state_directory / ".overseer.sqlite3.admin-authority.lock"
    authority_lock.write_bytes(b"")
    authority_lock.chmod(0o600)
    cleanup = ["/bin/true", "cleanup"]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {
            "user": "overseer",
            "uid": os.geteuid(),
            "group": "overseer",
            "gid": os.getegid(),
        },
        "sourceStore": {"uid": os.geteuid(), "gid": os.getegid()},
        "stagingAndCanaryCommands": [["/bin/true", "staging"]],
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {
            "canaryInstanceId": instance,
            "stateDirectory": str(state_directory),
            "store": str(state_directory / "overseer.sqlite3"),
            "psychloBridgeDatabase": str(state_directory / "psychlo-bridge.sqlite3"),
            "roadexRelayDatabase": str(state_directory / "roadex-relay.sqlite3"),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
            "failureCleanupCommands": [cleanup],
        },
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    lock_path = tmp_path / "executor" / "activation.lock"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval_for_rollback",
        lambda _package: {"packageDigest": digest},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_sealed_package_json",
        lambda *_args, **_kwargs: contract,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(activation_package_module, "_activation_lock_path", lambda: lock_path)
    monkeypatch.setattr(activation_package_module, "CANARY_STATE_ROOT", canary_root)
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_UID", os.geteuid())
    monkeypatch.setattr(activation_package_module, "APPROVED_OVERSEER_GID", os.getegid())
    monkeypatch.setattr(
        activation_package_module,
        "_validated_command_outcome",
        lambda *_args, **_kwargs: (0, None),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_command_outcome",
        lambda *_args, **_kwargs: (3, None),
    )
    monkeypatch.setattr(activation_package_module, "_processes_for_uid", lambda _uid: ())
    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="cleanup_evidence_seal_failed",
            phase="staging_cleanup",
            failure="ActivationPackageError",
        )
    )

    assert activation_package_module.execute_approved_rollback(package) == {
        "status": "aborted_before_cutover",
        "packageDigest": digest,
        "replayed": False,
    }
    recovered_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert recovered_state["status"] == "aborted_before_cutover"
    assert recovered_state["phase"] == "staging_cleanup"
    assert recovered_state["failure"] == "ActivationPackageError"
    assert recovered_state["secretValuesRecorded"] is False
    assert state_directory.stat().st_mode & 0o777 == 0o500
    assert all(path.stat().st_mode & 0o777 == 0o400 for path in state_directory.iterdir())

    state_directory.chmod(0o700)
    unexpected = state_directory / "unexpected-after-seal"
    unexpected.write_bytes(b"")
    unexpected.chmod(0o400)
    state_directory.chmod(0o500)
    with pytest.raises(ActivationPackageError, match="invalid artifact"):
        activation_package_module.execute_approved_rollback(package)
    state_directory.chmod(0o700)
    unexpected.unlink()
    state_directory.chmod(0o500)
    before_replay = {
        path.name: path.stat().st_ctime_ns
        for path in (state_directory, *state_directory.iterdir())
    }
    assert activation_package_module.execute_approved_rollback(package) == {
        "status": "aborted_before_cutover",
        "packageDigest": digest,
        "replayed": True,
    }
    after_replay = {
        path.name: path.stat().st_ctime_ns
        for path in (state_directory, *state_directory.iterdir())
    }
    assert after_replay == before_replay


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


def test_package_verification_rejects_non_object_migration_report_with_canary_error(
    tmp_path: Path,
) -> None:
    package, _digest = _finalized_package(tmp_path)
    report_path = package / "private" / "migration" / "migration-report.json"
    report_path.write_text("[]\n", encoding="utf-8")
    report_path.chmod(0o600)
    replacement_digest = _reseal_package_manifest_for_test(package)

    with pytest.raises(
        ActivationPackageError,
        match="canary-required store tables",
    ):
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


def test_package_verification_rejects_migrated_store_missing_canary_required_table(
    tmp_path: Path,
) -> None:
    package, _digest = _finalized_package(tmp_path)
    migrated = package / "private" / "migration" / "rehearsal-migrated.sqlite3"
    with sqlite3.connect(migrated) as connection:
        connection.execute("DROP TABLE admin_execution_claims")
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

    report_path = package / "private" / "migration" / "migration-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    observed = activation_package_module._sealed_migration_artifact_evidence(
        migrated,
        expected_uid=os.geteuid(),
        counted_tables=tuple(report["schemaBefore"]["countedTables"]),
    )
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

    with pytest.raises(
        ActivationPackageError,
        match="canary-required store tables",
    ):
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

    with pytest.raises(
        ActivationPackageError,
        match="artifact evidence|canary-required store tables",
    ):
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


def test_canary_migration_expectation_is_bound_to_the_sealed_package_report(
    tmp_path: Path,
) -> None:
    package, digest = _finalized_package(tmp_path)
    report = json.loads(
        (package / "private/migration/migration-report.json").read_text(encoding="utf-8")
    )

    evidence = activation_package_module._expected_canary_migration_evidence(
        package,
        expected_package_digest=digest,
    )

    assert evidence == {
        "sha256": report["migrated"]["sha256"],
        "size": report["migrated"]["size"],
        "integrityCheck": "ok",
    }


def test_canary_identity_validation_is_bound_to_the_approved_package_digest(
    tmp_path: Path,
) -> None:
    package, digest = _finalized_package(tmp_path)
    contract = json.loads(
        (package / "public/activation-contract.json").read_text(encoding="utf-8")
    )
    activation_package_module._validate_canary_contract_layout(
        package,
        contract,
        expected_package_digest=digest,
    )
    identity_path = package / "public/canary-instance.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["canaryInstanceId"] = "0" * 32
    identity_path.write_text(
        json.dumps(identity, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    identity_path.chmod(0o644)

    with pytest.raises(ActivationPackageError, match="document drifted"):
        activation_package_module._validate_canary_contract_layout(
            package,
            contract,
            expected_package_digest=digest,
        )


@pytest.mark.parametrize(
    ("unlisted_status", "replay_status", "expected_error"),
    [
        ("blocked", "completed", None),
        ("failed", "completed", "canary unlisted-unit control did not fail closed"),
        ("blocked", "failed", "canary executor replay control failed"),
    ],
)
def test_live_canary_runner_enforces_exact_positive_negative_and_replay_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unlisted_status: str,
    replay_status: str,
    expected_error: str | None,
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
        "_require_active_canary_command",
        lambda *_args, **_kwargs: None,
    )
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
    monkeypatch.setattr(activation_package_module, "CANARY_API_SOCKET", canary_socket)
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
                return {
                    "status": unlisted_status,
                    "mutation_performed": False,
                    "id": f"exec.{plan_id}",
                }
            if self.executions[plan_id] == 1:
                return {"status": "completed", "mutation_performed": True, "id": f"exec.{plan_id}"}
            return {
                "status": replay_status,
                "mutation_performed": False,
                "replayed": True,
                "id": f"exec.{plan_id}",
            }

    monkeypatch.setattr("overseer.client.OverseerApiClient", FakeClient)

    if expected_error is not None:
        with pytest.raises(ActivationPackageError, match=expected_error):
            run_canary_acceptance(
                package,
                expected_package_digest=digest,
                admin_secret="admin-approval-secret-123456",
                roadex_secret="roadex-approval-secret-12345",
                attestation_path=attestation,
                unix_socket_path=canary_socket,
            )
        assert not attestation.exists()
        return

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
    monkeypatch.setattr(activation_package_module, "CANARY_API_SOCKET", canary_socket)
    monkeypatch.setattr(
        activation_package_module,
        "_canary_attestation_path",
        lambda _digest: attestation,
    )
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_require_active_canary_command",
        lambda *_args, **_kwargs: None,
    )
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
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        lambda command, **_kwargs: calls.append(tuple(command)) or 0,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
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


def test_delayed_human_authorization_precedes_timed_canary_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    digest = "b" * 64
    package = tmp_path / "package"
    credentials = package / "private" / "credentials"
    credentials.mkdir(parents=True)
    admin_secret = "admin-approval-secret-123456"
    roadex_secret = "roadex-approval-secret-12345"
    activation_package_module.write_approval_document(
        credentials / "admin-approval-verifier.json",
        activation_package_module.create_approval_document(
            admin_secret,
            "admin-plan-approval",
        ),
    )
    activation_package_module.write_approval_document(
        credentials / "roadex-fixture-approval-verifier.json",
        activation_package_module.create_approval_document(
            roadex_secret,
            "roadex-fixture-approval",
        ),
    )
    canary_command = [
        "/opt/overseer/python",
        "-m",
        "overseer.activation_package",
        "run-approved-canary",
        "--package-root",
        str(package.resolve()),
    ]
    canary_start = [
        "/opt/overseer/python",
        "-m",
        "overseer.activation_package",
        "handoff-start-canary",
        "--package-root",
        str(package.resolve()),
    ]
    canary_resources_start = [
        "/usr/bin/systemctl",
        "start",
        "overseer-codex-user-bridge.socket",
        "overseer-admin-executor.socket",
    ]
    canary_health = [
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
        str(activation_package_module.CANARY_API_SOCKET),
        "http://localhost/health",
    ]
    canary_stop = [
        "/usr/bin/systemctl",
        "stop",
        "overseer-approval-smoke.service",
        "overseer-api-canary.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    ]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [
            ["/bin/true", "staging"],
            canary_resources_start,
            canary_start,
            canary_health,
            canary_command,
            canary_stop,
        ],
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [canary_stop]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    timeline: list[str] = []
    payloads: list[bytes | None] = []
    simulated_elapsed_seconds = 0
    answers = iter((admin_secret, roadex_secret))

    def delayed_prompt(_descriptor: int, prompt: str) -> str:
        nonlocal simulated_elapsed_seconds
        simulated_elapsed_seconds += 601
        timeline.append(f"prompt:{prompt}")
        return next(answers)

    def execute(command: list[str], *, stdin_payload: bytes | None = None) -> int:
        if command == ["/bin/true", "staging"]:
            timeline.append("staging")
        elif command == canary_resources_start:
            timeline.append("canary-resources-start")
        elif command == canary_start:
            timeline.append("canary-start")
        elif command == canary_command:
            timeline.append("canary-acceptance")
            payloads.append(stdin_payload)
        return 0

    def load_phase_approval(*_args: object, **_kwargs: object) -> dict[str, str]:
        timeline.append("phase-approval-check")
        return {"packageDigest": digest, "phase": "staging-canary"}

    def read_phase_approval(*_args: object, **_kwargs: object) -> dict[str, str]:
        timeline.append("phase-approval-refresh")
        return {"packageDigest": digest, "phase": "staging-canary"}

    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        load_phase_approval,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_read_activation_phase_approval",
        read_phase_approval,
    )
    monkeypatch.setattr(
        activation_package_module,
        "verify_approved_cutover",
        lambda _package: {"verified": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_open_canary_prompt_terminal",
        lambda: os.open(os.devnull, os.O_RDWR),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_read_canary_secret_from_terminal",
        delayed_prompt,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_expected_canary_acceptance_command",
        lambda *_args, **_kwargs: canary_command,
        raising=False,
    )
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)

    result = activation_package_module.execute_approved_staging_canary(package)

    assert result["status"] == "canary_passed_awaiting_cutover_approval"
    assert simulated_elapsed_seconds > 600
    assert timeline == [
        "phase-approval-check",
        "staging",
        "prompt:Admin approval secret for canary: ",
        "prompt:Roadex fixture approval secret for negative control: ",
        "phase-approval-refresh",
        "canary-resources-start",
        "canary-start",
        "canary-acceptance",
    ]
    assert len(payloads) == 1 and payloads[0] is not None
    authorization = json.loads(payloads[0])
    assert authorization == {
        "adminSecret": admin_secret,
        "roadexSecret": roadex_secret,
        "schemaVersion": "overseer.canary-authorization-input.v1",
    }
    state_bytes = state_path.read_bytes()
    assert admin_secret.encode() not in state_bytes
    assert roadex_secret.encode() not in state_bytes
    progress_output = capsys.readouterr().err
    progress_records = [json.loads(line) for line in progress_output.splitlines()]
    progress_statuses = [record["status"] for record in progress_records]
    required_statuses = [
        "phase-started",
        "waiting-for-human-authorization",
        "human-authorization-complete",
        "stage-started",
        "stage-complete",
        "evidence-seal-started",
        "evidence-seal-complete",
        "phase-complete",
    ]
    cursor = 0
    for status in required_statuses:
        cursor = progress_statuses.index(status, cursor) + 1
    assert admin_secret not in progress_output
    assert roadex_secret not in progress_output
    assert all(record["secretValuesRecorded"] is False for record in progress_records)
    assert all(
        admin_secret not in argument
        for command in contract["stagingAndCanaryCommands"]
        for argument in command
    )
    assert all(
        roadex_secret not in argument
        for command in contract["stagingAndCanaryCommands"]
        for argument in command
    )


@pytest.mark.parametrize(
    "malicious_command",
    (
        [
            "/usr/bin/tee",
            "run-approved-canary",
            "--package-root",
            "/var/lib/overseer-executor/approved-package",
        ],
        [
            "/opt/overseer/runtime/bin/python",
            "-m",
            "overseer.not_activation_package",
            "run-approved-canary",
            "--package-root",
            "/var/lib/overseer-executor/approved-package",
        ],
    ),
)
def test_canary_authorization_rejects_nonexact_executable_or_module(
    malicious_command: list[str],
) -> None:
    expected = [
        "/opt/overseer/runtime/bin/python",
        "-B",
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
        "run-approved-canary",
        "--package-root",
        "/var/lib/overseer-executor/approved-package",
    ]

    with pytest.raises(ActivationPackageError, match="exact sealed canary command"):
        activation_package_module._canary_acceptance_command_index(
            [malicious_command],
            expected_command=expected,
        )


def test_canary_cli_proves_runner_provenance_before_reading_secret_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    events: list[str] = []
    monkeypatch.setattr(
        activation_package_module,
        "_validate_existing_package_destination",
        lambda _path: package,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval",
        lambda _package: {"packageDigest": "c" * 64},
    )

    def reject(*_args: object, **_kwargs: object) -> None:
        events.append("preflight")
        raise ActivationPackageError("active staging-canary runner is unavailable")

    def consume() -> tuple[str, str]:
        events.append("stdin-read")
        raise AssertionError("secret input was consumed before runner provenance")

    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", reject)
    monkeypatch.setattr(activation_package_module, "_read_canary_authorization_input", consume)

    with pytest.raises(ActivationPackageError, match="active staging-canary runner"):
        activation_package_module._main(
            ["run-approved-canary", "--package-root", str(package)]
        )

    assert events == ["preflight"]


def test_canary_secret_collection_rejects_missing_secure_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    real_open = os.open
    prompted = False

    def non_tty_open(_path: object, flags: int, mode: int = 0o777) -> int:
        return real_open(os.devnull, flags, mode)

    def prompt(_label: str) -> str:
        nonlocal prompted
        prompted = True
        return "must-not-be-collected"

    monkeypatch.setattr(activation_package_module.os, "open", non_tty_open)
    monkeypatch.setattr(activation_package_module.getpass, "getpass", prompt)

    with pytest.raises(ActivationPackageError, match="secure terminal"):
        activation_package_module._prepare_canary_authorization_input(package)

    assert prompted is False


def test_canary_secret_collection_rejects_echo_suppression_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    master_descriptor, slave_descriptor = pty.openpty()
    real_dup = os.dup
    validated = False

    def tty_open(_path: object, _flags: int, _mode: int = 0o777) -> int:
        return real_dup(slave_descriptor)

    def fail_echo_suppression(
        _descriptor: int,
        _when: int,
        _attributes: list[object],
    ) -> None:
        raise termios.error(errno.EIO, "terminal lost")

    def validate(*_args: object, **_kwargs: object) -> None:
        nonlocal validated
        validated = True

    monkeypatch.setattr(activation_package_module.os, "open", tty_open)
    monkeypatch.setattr(termios, "tcsetattr", fail_echo_suppression)
    monkeypatch.setattr(
        activation_package_module.getpass,
        "getpass",
        lambda _prompt: "must-not-be-collected",
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_canary_authorization",
        validate,
    )

    try:
        with pytest.raises(ActivationPackageError, match="disable terminal echo"):
            activation_package_module._prepare_canary_authorization_input(package)
    finally:
        os.close(master_descriptor)
        os.close(slave_descriptor)

    assert validated is False


@pytest.mark.parametrize(
    "earlier_start",
    (
        ["/usr/bin/systemctl", "restart", "overseer-api-canary.service"],
        ["/usr/bin/systemctl", "restart", "overseer-api-canary"],
    ),
)
def test_canary_boundary_rejects_alternate_earlier_canary_start(
    earlier_start: list[str],
) -> None:
    resources_start = [
        "/usr/bin/systemctl",
        "start",
        "overseer-codex-user-bridge.socket",
        "overseer-admin-executor.socket",
    ]
    service_start = [
        "/usr/bin/systemctl",
        "start",
        "overseer-api-canary.service",
    ]
    health = [
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
        str(activation_package_module.CANARY_API_SOCKET),
        "http://localhost/health",
    ]
    acceptance = [
        "/opt/overseer/python",
        "-m",
        "overseer.activation_package",
        "run-approved-canary",
    ]
    stop = [
        "/usr/bin/systemctl",
        "stop",
        "overseer-approval-smoke.service",
        "overseer-api-canary.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    ]
    commands = [
        earlier_start,
        resources_start,
        service_start,
        health,
        acceptance,
        stop,
    ]

    with pytest.raises(ActivationPackageError, match="canary startup boundary"):
        activation_package_module._canary_authorization_boundary_index(
            commands,
            canary_command_index=4,
            failure_cleanup_commands=[stop],
        )


def test_canary_boundary_requires_exact_canonical_suffix() -> None:
    commands = [
        ["/bin/true", "staging"],
        [
            "/usr/bin/systemctl",
            "start",
            "overseer-codex-user-bridge.socket",
            "overseer-admin-executor.socket",
        ],
        ["/usr/bin/systemctl", "start", "overseer-api-canary.service"],
        ["/usr/bin/curl", "http://localhost/health"],
        [
            "/opt/overseer/python",
            "-m",
            "overseer.activation_package",
            "run-approved-canary",
        ],
        [
            "/usr/bin/systemctl",
            "stop",
            "overseer-approval-smoke.service",
            "overseer-api-canary.service",
            "overseer-admin-executor.socket",
            "overseer-codex-user-bridge.socket",
        ],
    ]

    with pytest.raises(ActivationPackageError, match="canary startup boundary"):
        activation_package_module._canary_authorization_boundary_index(
            commands,
            canary_command_index=4,
            failure_cleanup_commands=[commands[-1]],
        )


def test_canary_authorization_pipe_requires_one_exact_canonical_packet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = {
        "schemaVersion": "overseer.canary-authorization-input.v1",
        "adminSecret": "admin-approval-secret-123456",
        "roadexSecret": "roadex-approval-secret-12345",
    }
    canonical = json.dumps(
        document,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii") + b"\n"
    monkeypatch.setattr(
        activation_package_module.sys,
        "stdin",
        io.TextIOWrapper(io.BytesIO(canonical)),
    )

    assert activation_package_module._read_canary_authorization_input() == (
        document["adminSecret"],
        document["roadexSecret"],
    )

    monkeypatch.setattr(
        activation_package_module.sys,
        "stdin",
        io.TextIOWrapper(io.BytesIO(canonical + b"\n")),
    )
    with pytest.raises(ActivationPackageError, match="contract"):
        activation_package_module._read_canary_authorization_input()


def test_contract_command_delivers_authorization_only_through_anonymous_stdin(
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
    payload = b"test-only-canary-authorization-packet\n"
    command = [
        "/usr/bin/python3",
        "-c",
        (
            "import sys; expected=b'test-only-canary-authorization-packet\\n'; "
            "raise SystemExit(0 if sys.stdin.buffer.read()==expected else 9)"
        ),
    ]

    with activation_package_module._activation_execution_lock():
        assert (
            activation_package_module._execute_contract_command(
                command,
                stdin_payload=payload,
            )
            == 0
        )


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
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
    monkeypatch.setattr(
        activation_package_module,
        "_require_inherited_activation_lock",
        lambda: None,
    )
    expected_options = {"--package-root": str(package.resolve())}

    with pytest.raises(ActivationPackageError, match="active staging-canary runner"):
        activation_package_module._require_active_phase_command(
            package,
            phase="staging-canary",
            command_name="run-approved-canary",
            expected_options=expected_options,
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
        expected_options=expected_options,
    )

    with pytest.raises(ActivationPackageError, match="sealed command arguments"):
        activation_package_module._require_active_phase_command(
            package,
            phase="staging-canary",
            command_name="run-approved-canary",
            expected_options={"--package-root": str(tmp_path / "other-package")},
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
            expected_options=expected_options,
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
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_approval_for_rollback",
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
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
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
            f"--uid={os.getuid()}",
            f"--gid={os.getgid()}",
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
        "User": str(os.getuid()),
        "Group": str(os.getgid()),
        "WorkingDirectory": str(spec["workingDirectory"]),
        "Type": "simple",
        "Restart": "on-failure",
        "RestartUSec": "5s",
        "CollectMode": "inactive-or-failed",
        "Environment": environment,
        "ExecStart": "{ path=/bin/true ; argv[]=/bin/true ; ignore_errors=no ; start_time=[n/a] }",
        "After": "basic.target",
        "LoadCredential": "[unprintable]",
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
        lambda fragment, *, unit, spec: None,
    )

    assert activation_package_module._inspect_rollback_transient_unit(spec) == "active"
    snapshot["Description"] = "unsealed"
    with pytest.raises(ActivationPackageError, match="identity drifted"):
        activation_package_module._inspect_rollback_transient_unit(spec)
    snapshot["Description"] = str(spec["description"])
    snapshot["ExecStartPre"] = (
        "{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no ; start_time=[n/a] }"
    )
    with pytest.raises(ActivationPackageError, match="additional actions drifted"):
        activation_package_module._inspect_rollback_transient_unit(spec)


def test_rollback_transient_fragment_binds_exact_credential_sources() -> None:
    spec = {
        "argv": ["/bin/true"],
        "properties": {
            "LoadCredential": ["sealed-secret:/root/sealed-secret"],
        }
    }
    valid = b"""# transient\n[Service]\nLoadCredential=sealed-secret:/root/sealed-secret\nExecStart=/bin/true\n"""

    activation_package_module._validate_rollback_transient_fragment_contents(valid, spec)

    with pytest.raises(ActivationPackageError, match="credential source drifted"):
        activation_package_module._validate_rollback_transient_fragment_contents(
            valid.replace(b"/root/sealed-secret", b"/root/other-secret"),
            spec,
        )
    with pytest.raises(ActivationPackageError, match="additional actions drifted"):
        activation_package_module._validate_rollback_transient_fragment_contents(
            valid + b"ExecStartPre=/bin/false\n",
            spec,
        )
    with pytest.raises(ActivationPackageError, match="executable drifted"):
        activation_package_module._validate_rollback_transient_fragment_contents(
            valid + b"ExecStart=/bin/false\n",
            spec,
        )
    for prefix in (b"+", b"!", b"!!"):
        with pytest.raises(ActivationPackageError, match="executable drifted"):
            activation_package_module._validate_rollback_transient_fragment_contents(
                valid.replace(b"ExecStart=/bin/true", b"ExecStart=" + prefix + b"/bin/true"),
                spec,
            )


@pytest.mark.parametrize(
    "directive",
    [
        "SetCredential",
        "SetCredentialEncrypted",
        "UnsetEnvironment",
        "TemporaryFileSystem",
        "MountImages",
        "ExtensionImages",
    ],
)
def test_rollback_transient_fragment_rejects_unsealed_injection_directives(
    directive: str,
) -> None:
    spec = {"argv": ["/bin/true"], "properties": {"LoadCredential": []}}
    raw = f"[Service]\nExecStart=/bin/true\n{directive}=unsealed\n".encode("ascii")

    with pytest.raises(ActivationPackageError, match="drifted"):
        activation_package_module._validate_rollback_transient_fragment_contents(raw, spec)


def test_rollback_transient_identity_rejects_sealed_argv_drift() -> None:
    command = _rollback_transient_command()
    command[-1] = "/bin/false"

    with pytest.raises(ActivationPackageError, match="identity digest drifted"):
        activation_package_module._rollback_transient_spec(command)


@pytest.mark.parametrize(
    "extra_options",
    (
        ["--uid", "0"],
        ["--gid", "0"],
        ["--ui=0"],
        ["-p", "User=0"],
    ),
)
def test_rollback_transient_rejects_resealed_alternate_identity_option_grammar(
    extra_options: list[str],
) -> None:
    command = _rollback_transient_command()
    unbound = [
        value
        for value in command
        if not value.startswith("--property=Description=overseer.rollback-transient.v1:")
        and not value.startswith("--setenv=OVERSEER_ROLLBACK_TRANSIENT_ID=")
    ]
    separator = unbound.index("--")
    unbound[separator:separator] = extra_options
    resealed = activation_package_module._bind_rollback_transient_identity(unbound)

    with pytest.raises(ActivationPackageError, match="option grammar"):
        activation_package_module._rollback_transient_spec(resealed)


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


def test_rollback_transient_rejects_numeric_principal_outside_sealed_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command = _rollback_transient_command()
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid() + 1, "gid": os.getgid()},
    }
    monkeypatch.setattr(
        activation_package_module,
        "_inspect_rollback_transient_unit",
        lambda _spec: pytest.fail("mismatched principal must be rejected before unit inspection"),
    )

    with pytest.raises(ActivationPackageError, match="principal does not match"):
        activation_package_module._execute_rollback_transient(contract, command, resume=True)


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
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_approval_for_rollback",
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


def test_cutover_interrupt_before_first_rollback_command_runs_emergency_rollback(
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
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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

    with pytest.raises(ActivationPackageError, match="sealed rollback completed"):
        activation_package_module.execute_approved_cutover(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["phase"] == "rollback"
    assert state["status"] == "rolled_back"
    assert state["commandIndex"] is None
    assert state["commandDigest"] is None


def test_final_migration_public_primitive_requires_active_sealed_cutover_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    source = tmp_path / "source.sqlite3"
    source.touch()
    metadata = source.stat()
    parent_metadata = source.parent.stat()
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)

    def reject(*_args, **_kwargs) -> None:
        raise ActivationPackageError("prepare-final-store requires the active cutover runner")

    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", reject)

    with pytest.raises(ActivationPackageError, match="active cutover runner"):
        prepare_final_store_migration(
            package_root=package,
            source_store=source,
            backup_store=tmp_path / "backup.sqlite3",
            destination_store=tmp_path / "destination.sqlite3",
            expected_source_device=metadata.st_dev,
            expected_source_inode=metadata.st_ino,
            expected_source_uid=metadata.st_uid,
            expected_source_gid=metadata.st_gid,
            expected_parent_device=parent_metadata.st_dev,
            expected_parent_inode=parent_metadata.st_ino,
            expected_parent_mode=stat_mode(source.parent),
            destination_uid=os.geteuid(),
            destination_gid=os.getegid(),
        )


def test_canary_public_primitive_requires_active_sealed_staging_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    attestation = tmp_path / "attestation.json"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_canary_attestation_path",
        lambda _digest: attestation,
    )

    def reject(*_args, **_kwargs) -> None:
        raise ActivationPackageError("run-approved-canary requires the active staging-canary runner")

    monkeypatch.setattr(activation_package_module, "_require_active_phase_command", reject)

    with pytest.raises(ActivationPackageError, match="active staging-canary runner"):
        run_canary_acceptance(
            package,
            expected_package_digest="a" * 64,
            admin_secret="unused-admin-secret",
            roadex_secret="unused-roadex-secret",
            attestation_path=attestation,
        )


def test_cleanup_satisfaction_checks_every_sealed_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def outcome(command: list[str]) -> tuple[int, str | None]:
        unit = command[-1]
        calls.append(unit)
        return (0, None) if unit == "still-active.socket" else (3, None)

    monkeypatch.setattr(activation_package_module, "_command_outcome", outcome)

    assert activation_package_module._cleanup_command_satisfied(
        [
            "/usr/bin/systemctl",
            "stop",
            "inactive.service",
            "still-active.socket",
            "unchecked.socket",
        ]
    ) is False
    assert calls == ["inactive.service", "still-active.socket"]


def test_contract_child_inherits_activation_lock_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "executor" / "activation-state.json"
    observed: dict[str, object] = {}
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    class Result:
        returncode = 0

    def run(*_args, **kwargs):
        observed.update(kwargs)
        for descriptor in kwargs.get("pass_fds", ()):
            os.fstat(descriptor)
        return Result()

    monkeypatch.setattr(activation_package_module.subprocess, "run", run)

    with activation_package_module._activation_execution_lock():
        assert activation_package_module._execute_contract_command(["/bin/true"]) == 0

    pass_fds = observed.get("pass_fds")
    assert isinstance(pass_fds, tuple)
    assert len(pass_fds) == 1


def test_inherited_lock_survives_parent_descriptor_close_until_child_exit(
    tmp_path: Path,
) -> None:
    lock_path = tmp_path / "activation.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    child = subprocess.Popen(
        [
            sys.executable,
            "-B",
            "-s",
            "-P",
            "-c",
            "import os,time; os.fstat(int(os.environ['LOCK_FD'])); time.sleep(0.5)",
        ],
        env={"LOCK_FD": str(descriptor)},
        pass_fds=(descriptor,),
    )
    os.close(descriptor)
    contender = os.open(lock_path, os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert child.wait(timeout=5) == 0
        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)
        os.close(contender)


def test_staging_checkpoint_failure_runs_immediate_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "7" * 64
    package = tmp_path / "package"
    staging = ["/bin/true", "staging"]
    cleanup = ["/bin/true", "cleanup"]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [staging],
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [cleanup]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": digest, "phase": "staging-canary"},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )
    original_write = activation_package_module._write_activation_state

    def fail_completed_state(document: dict[str, object]) -> None:
        if document.get("status") == "command_complete":
            raise OSError("simulated checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_completed_state)

    with pytest.raises(ActivationPackageError, match="checkpoint failed after staging command"):
        activation_package_module.execute_approved_staging_canary(package)

    assert calls == [tuple(staging), tuple(cleanup)]


def test_cutover_checkpoint_failure_runs_immediate_sealed_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "8" * 64
    package = tmp_path / "package"
    cutover = ["/bin/true", "cutover"]
    rollback = ["/bin/true", "rollback"]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [["/bin/true", "staging"]],
        "cutoverCommands": [cutover],
        "rollbackCommands": [rollback],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": digest, "phase": "cutover"},
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
        lambda command: calls.append(tuple(command)) or 0,
    )
    original_write = activation_package_module._write_activation_state

    def fail_completed_state(document: dict[str, object]) -> None:
        if document.get("status") == "command_complete":
            raise OSError("simulated checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_completed_state)

    with pytest.raises(ActivationPackageError, match="checkpoint failed after cutover command"):
        activation_package_module.execute_approved_cutover(package)

    assert calls == [tuple(cutover), tuple(rollback)]


def test_legacy_v1_state_and_package_approval_remain_rollback_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "9" * 64
    package = tmp_path / "package"
    package.mkdir()
    approval_path = tmp_path / "approved-activation-package.json"
    approval_path.write_text(
        json.dumps(
            {
                "schemaVersion": "overseer.activation-package-approval.v1",
                "approved": True,
                "packageRoot": str(package.resolve()),
                "sourcePackageRoot": str(tmp_path / "source-package"),
                "packageDigest": digest,
                "packageFileCount": 42,
                "liveExecutionScope": "staging-canary-and-cutover-for-this-package-only",
            }
        ),
        encoding="utf-8",
    )
    approval_path.chmod(0o600)
    state_path = tmp_path / "activation-state.json"
    state_path.write_text(
        json.dumps(
            {
                "schemaVersion": "overseer.activation-runner-state.v1",
                "packageDigest": digest,
                "status": "command_running",
                "phase": "cutover",
                "commandIndex": 0,
                "commandDigest": "a" * 64,
                "failure": None,
                "updatedAtNs": 1,
                "secretValuesRecorded": False,
            }
        ),
        encoding="utf-8",
    )
    state_path.chmod(0o600)
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
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "verify_activation_package",
        lambda *_args, **_kwargs: {"fileCount": 42},
    )

    approval = activation_package_module._load_activation_approval_for_rollback(package)
    state = activation_package_module._load_activation_state()

    assert approval["schemaVersion"] == "overseer.activation-package-approval.v1"
    assert state is not None
    assert state["schemaVersion"] == "overseer.activation-runner-state.v1"


def test_active_command_guard_requires_an_inherited_runner_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OVERSEER_ACTIVATION_LOCK_FD", raising=False)

    with pytest.raises(ActivationPackageError, match="inherited activation execution lock"):
        activation_package_module._require_inherited_activation_lock()


def test_contract_child_exports_the_inherited_lock_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "executor" / "activation-state.json"
    observed: dict[str, object] = {}
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    class Result:
        returncode = 0

    def run(*_args, **kwargs):
        observed.update(kwargs)
        return Result()

    monkeypatch.setattr(activation_package_module.subprocess, "run", run)

    with activation_package_module._activation_execution_lock():
        activation_package_module._execute_contract_command(["/bin/true"])

    pass_fds = observed["pass_fds"]
    environment = observed["env"]
    assert isinstance(pass_fds, tuple)
    assert isinstance(environment, dict)
    assert environment["OVERSEER_ACTIVATION_LOCK_FD"] == str(pass_fds[0])


def test_cleanup_satisfaction_rejects_systemctl_query_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        activation_package_module,
        "_command_outcome",
        lambda _command: (4, None),
    )

    assert activation_package_module._cleanup_command_satisfied(
        ["/usr/bin/systemctl", "stop", "overseer-api-canary.service"]
    ) is False


def test_failed_staging_command_cleans_up_when_cleanup_checkpoint_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    package = tmp_path / "package"
    staging = ["/bin/false", "staging"]
    cleanup = ["/bin/true", "cleanup"]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [staging],
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [cleanup]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": digest, "phase": "staging-canary"},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )

    def execute(command: list[str]) -> int:
        calls.append(tuple(command))
        return 1 if command == staging else 0

    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)
    original_write = activation_package_module._write_activation_state
    failed_once = False

    def fail_cleanup_checkpoint(document: dict[str, object]) -> None:
        nonlocal failed_once
        if document.get("status") == "cleanup_command_running" and not failed_once:
            failed_once = True
            raise OSError("simulated cleanup checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_cleanup_checkpoint)

    with pytest.raises(ActivationPackageError, match="failed before cutover"):
        activation_package_module.execute_approved_staging_canary(package)

    assert calls == [tuple(staging), tuple(cleanup)]


def test_failed_cutover_command_rolls_back_when_rollback_checkpoint_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "b" * 64
    package = tmp_path / "package"
    cutover = ["/bin/false", "cutover"]
    rollback = ["/bin/true", "rollback"]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [["/bin/true", "staging"]],
        "cutoverCommands": [cutover],
        "rollbackCommands": [rollback],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": digest, "phase": "cutover"},
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
        return 1 if command == cutover else 0

    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)
    original_write = activation_package_module._write_activation_state
    failed_once = False

    def fail_rollback_checkpoint(document: dict[str, object]) -> None:
        nonlocal failed_once
        if document.get("status") == "rollback_command_running" and not failed_once:
            failed_once = True
            raise OSError("simulated rollback checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_rollback_checkpoint)

    with pytest.raises(ActivationPackageError, match="sealed rollback completed"):
        activation_package_module.execute_approved_cutover(package)

    assert calls == [tuple(cutover), tuple(rollback)]


def test_cutover_state_recovery_reconciles_existing_exact_rollback_transients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "c" * 64
    command = ["/usr/bin/systemd-run", "sealed-rollback"]
    contract = {"rollbackCommands": [command]}
    observed: list[bool] = []
    monkeypatch.setattr(activation_package_module, "_write_activation_state", lambda _state: None)
    monkeypatch.setattr(activation_package_module, "_validate_contract_principal_binding", lambda _contract: None)
    monkeypatch.setattr(
        activation_package_module,
        "_rollback_transient_spec",
        lambda _command: {"unit": "sealed.service"},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_rollback_transient",
        lambda _contract, _command, *, resume: observed.append(resume),
    )

    activation_package_module._execute_rollback_sequence(
        contract,
        package_digest=digest,
        prior_state={
            "schemaVersion": activation_package_module.ACTIVATION_RUNNER_STATE_SCHEMA,
            "packageDigest": digest,
            "status": "command_running",
            "phase": "cutover",
            "commandIndex": 0,
            "commandDigest": "d" * 64,
        },
    )

    assert observed == [True]


def test_restore_legacy_store_public_primitive_requires_sealed_rollback_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.sqlite3"
    source.touch()
    metadata = source.stat()
    parent = source.parent.stat()
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)

    def reject(*_args, **_kwargs) -> None:
        raise ActivationPackageError(
            "restore-legacy-store-access requires the active sealed rollback command"
        )

    monkeypatch.setattr(activation_package_module, "_require_active_rollback_command", reject)

    with pytest.raises(ActivationPackageError, match="active sealed rollback command"):
        restore_legacy_store_access(
            package_root=tmp_path / "package",
            source_store=source,
            expected_source_uid=metadata.st_uid,
            expected_source_gid=metadata.st_gid,
            expected_source_device=metadata.st_dev,
            expected_source_inode=metadata.st_ino,
            expected_parent_device=parent.st_dev,
            expected_parent_inode=parent.st_ino,
            expected_parent_mode=stat_mode(source.parent),
        )


def test_manual_rollback_checkpoint_failure_retries_and_records_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "e" * 64
    package = tmp_path / "package"
    rollback = ["/bin/true", "rollback"]
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
        "rollbackCommands": [rollback],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval_for_rollback",
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
            status="command_running",
            phase="cutover",
            command_index=0,
            command=["/bin/true", "cutover"],
        )
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )
    original_write = activation_package_module._write_activation_state
    failed_once = False

    def fail_rollback_completion(document: dict[str, object]) -> None:
        nonlocal failed_once
        if document.get("status") == "rollback_command_complete" and not failed_once:
            failed_once = True
            raise OSError("simulated rollback completion checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_rollback_completion)

    result = activation_package_module.execute_approved_rollback(package)

    assert result["status"] == "rolled_back"
    assert calls == [tuple(rollback), tuple(rollback)]
    final_state = json.loads(state_path.read_text(encoding="utf-8"))
    assert final_state["status"] == "rolled_back"


def test_staging_later_command_entry_checkpoint_failure_runs_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "1" * 64
    package = tmp_path / "package"
    first = ["/bin/true", "first-staging"]
    second = ["/bin/true", "second-staging"]
    cleanup = ["/bin/true", "cleanup"]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [first, second],
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [cleanup]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": digest, "phase": "staging-canary"},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )
    original_write = activation_package_module._write_activation_state

    def fail_second_entry(document: dict[str, object]) -> None:
        if document.get("status") == "command_running" and document.get("commandIndex") == 1:
            raise OSError("simulated later command-entry checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_second_entry)

    with pytest.raises(ActivationPackageError, match="entry checkpoint failed"):
        activation_package_module.execute_approved_staging_canary(package)

    assert calls == [tuple(first), tuple(cleanup)]


def _staging_failure_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    digest: str,
    staging: list[list[str]],
) -> tuple[Path, dict[str, object], Path]:
    package = tmp_path / "package"
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": staging,
        "cutoverCommands": [["/bin/true", "cutover"]],
        "rollbackCommands": [["/bin/true", "rollback"]],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": digest, "phase": "staging-canary"},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )
    return package, contract, state_path


@pytest.mark.parametrize(
    ("schema", "persisted_failure", "expected_failure"),
    (
        (
            activation_package_module.LEGACY_ACTIVATION_RUNNER_STATE_SCHEMA,
            "cutover-exit-7",
            "exit-7",
        ),
        (
            activation_package_module.ACTIVATION_RUNNER_STATE_SCHEMA,
            "cutover-exit-7",
            "exit-7",
        ),
        (
            activation_package_module.LEGACY_ACTIVATION_RUNNER_STATE_SCHEMA,
            "exit--9",
            "exit-137",
        ),
        (
            activation_package_module.ACTIVATION_RUNNER_STATE_SCHEMA,
            "cutover-exit--15",
            "exit-143",
        ),
    ),
)
def test_activation_state_load_normalizes_historical_exit_classification_without_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schema: str,
    persisted_failure: str,
    expected_failure: str,
) -> None:
    state_path = tmp_path / "executor" / "activation-state.json"
    state_path.parent.mkdir(parents=True)
    document = {
        "schemaVersion": schema,
        "packageDigest": "5" * 64,
        "status": "rollback_command_running",
        "phase": "rollback",
        "commandIndex": 0,
        "commandDigest": "4" * 64,
        "failure": persisted_failure,
        "updatedAtNs": 1,
        "secretValuesRecorded": False,
    }
    durable_text = json.dumps(document)
    state_path.write_text(durable_text, encoding="utf-8")
    state_path.chmod(0o600)
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    loaded = activation_package_module._load_activation_state()

    assert loaded is not None
    assert loaded["failure"] == expected_failure
    assert state_path.read_text(encoding="utf-8") == durable_text


@pytest.mark.parametrize(
    "schema",
    (
        activation_package_module.LEGACY_ACTIVATION_RUNNER_STATE_SCHEMA,
        activation_package_module.ACTIVATION_RUNNER_STATE_SCHEMA,
    ),
)
def test_rollback_recovery_accepts_prior_cutover_failure_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    schema: str,
) -> None:
    digest = "4" * 64
    package, contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest=digest,
        staging=[["/bin/true", "staging"]],
    )
    rollback = contract["rollbackCommands"][0]
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval_for_rollback",
        lambda _package: {"packageDigest": digest},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(command) or 0,
    )
    persisted = activation_package_module._runner_state(
        package_digest=digest,
        status="rollback_command_running",
        phase="rollback",
        command_index=0,
        command=rollback,
    )
    persisted["schemaVersion"] = schema
    persisted["failure"] = "cutover-exit-7"
    activation_package_module._write_activation_state(persisted)

    result = activation_package_module.execute_approved_rollback(package)

    assert result == {"status": "rolled_back", "packageDigest": digest, "replayed": False}
    assert calls == [rollback]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "rolled_back"
    assert state["failure"] == "exit-7"
    assert state["secretValuesRecorded"] is False


def test_signaled_staging_command_publishes_shell_style_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="3" * 64,
        staging=[["/bin/false", "staging"]],
    )
    staging = contract["stagingAndCanaryCommands"][0]
    cleanup = contract["canary"]["failureCleanupCommands"][0]
    calls: list[list[str]] = []

    def execute(command: list[str]) -> int:
        calls.append(command)
        return -9 if command == staging else 0

    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)

    with pytest.raises(ActivationPackageError, match="failed before cutover"):
        activation_package_module.execute_approved_staging_canary(package)

    assert calls == [staging, cleanup]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "exit-137"
    assert state["secretValuesRecorded"] is False


def test_signaled_cleanup_command_publishes_shell_style_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "2" * 64
    state_path = tmp_path / "executor" / "activation-state.json"
    cleanup = ["/bin/true", "cleanup"]
    contract = {"canary": {"failureCleanupCommands": [cleanup]}}
    calls = 0

    def execute(_command: list[str]) -> int:
        nonlocal calls
        calls += 1
        return -9 if calls == 1 else 0

    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_validate_contract_principal_binding", lambda _contract: None)
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)

    assert activation_package_module._execute_resilient_cleanup(
        contract,
        package_digest=digest,
        originating_failure="exit-7",
        require_canary_evidence=False,
    ) is True

    assert calls == 2
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "exit-137"
    assert state["secretValuesRecorded"] is False


def test_signaled_cutover_command_reports_shell_style_failure_after_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "1" * 64
    package, contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest=digest,
        staging=[["/bin/true", "staging"]],
    )
    cutover = contract["cutoverCommands"][0]
    rollback = contract["rollbackCommands"][0]
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "verify_approved_cutover",
        lambda _package: {"verified": True},
    )
    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="canary_passed_awaiting_cutover_approval",
            phase="staging-canary",
        )
    )

    def execute(command: list[str]) -> int:
        calls.append(command)
        return -9 if command == cutover else 0

    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)

    with pytest.raises(ActivationPackageError, match="sealed rollback completed"):
        activation_package_module.execute_approved_cutover(package)

    assert calls == [cutover, rollback]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "rolled_back"
    assert state["failure"] == "exit-137"
    assert state["secretValuesRecorded"] is False


def test_failed_staging_command_preserves_bounded_failure_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="f" * 64,
        staging=[["/bin/false", "staging"]],
    )
    staging = contract["stagingAndCanaryCommands"][0]
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: 1 if command == staging else 0,
    )

    with pytest.raises(ActivationPackageError, match="failed before cutover"):
        activation_package_module.execute_approved_staging_canary(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "exit-1"
    assert state["secretValuesRecorded"] is False


def test_staging_later_command_entry_checkpoint_failure_preserves_bounded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, _contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="e" * 64,
        staging=[["/bin/true", "first"], ["/bin/true", "second"]],
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(command) or 0,
    )
    original_write = activation_package_module._write_activation_state

    def fail_second_entry(document: dict[str, object]) -> None:
        if document.get("status") == "command_running" and document.get("commandIndex") == 1:
            raise OSError("simulated later command-entry checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_second_entry)

    with pytest.raises(ActivationPackageError, match="entry checkpoint failed"):
        activation_package_module.execute_approved_staging_canary(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "OSError"
    assert state["secretValuesRecorded"] is False
    assert calls == [["/bin/true", "first"], ["/bin/true", "cleanup"]]


def test_canary_authorization_failure_preserves_bounded_failure_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = ["/bin/true", "run-approved-canary"]
    package, _contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="d" * 64,
        staging=[canary],
    )
    monkeypatch.setattr(
        activation_package_module,
        "_expected_canary_acceptance_command",
        lambda *_args, **_kwargs: canary,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_canary_acceptance_command_index",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_canary_authorization_boundary_index",
        lambda *_args, **_kwargs: 0,
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_prepare_canary_authorization_input",
        lambda _package: (_ for _ in ()).throw(ActivationPackageError("authorization rejected")),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(command) or 0,
    )

    with pytest.raises(ActivationPackageError, match="authorization failed"):
        activation_package_module.execute_approved_staging_canary(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "ActivationPackageError"
    assert state["secretValuesRecorded"] is False
    assert calls == [["/bin/true", "cleanup"]]


def test_authorization_progress_emitter_failure_survives_cleanup_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = ["/bin/true", "run-approved-canary"]
    package, _contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="6" * 64,
        staging=[canary],
    )
    monkeypatch.setattr(
        activation_package_module,
        "_expected_canary_acceptance_command",
        lambda *_args, **_kwargs: canary,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_canary_acceptance_command_index",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_canary_authorization_boundary_index",
        lambda *_args, **_kwargs: 0,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_prepare_canary_authorization_input",
        lambda _package: b"sealed-authorization-input",
    )
    monkeypatch.setattr(
        activation_package_module,
        "_read_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": "6" * 64},
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(command) or 0,
    )

    def fail_authorization_complete(**kwargs: object) -> dict[str, object]:
        if kwargs["status"] == "human-authorization-complete":
            raise OSError("simulated progress sink failure")
        return {}

    monkeypatch.setattr(
        activation_package_module,
        "emit_activation_progress",
        fail_authorization_complete,
    )

    with pytest.raises(ActivationPackageError) as raised:
        activation_package_module.execute_approved_staging_canary(package)

    assert str(raised.value) == "activation progress could not be emitted"
    assert calls == [["/bin/true", "cleanup"]]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"


def test_protected_stage_progress_emitter_failure_survives_containment_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected_start = [
        "/usr/bin/systemctl",
        "start",
        "overseer-admin-executor.socket",
    ]
    package, _contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="7" * 64,
        staging=[protected_start],
    )
    calls: list[list[str]] = []
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(command) or 0,
    )

    def fail_protected_completion(**kwargs: object) -> dict[str, object]:
        if (
            kwargs["status"] == "stage-complete"
            and kwargs["stage"] == "canary-socket-start"
        ):
            raise OSError("simulated progress sink failure")
        return {}

    monkeypatch.setattr(
        activation_package_module,
        "emit_activation_progress",
        fail_protected_completion,
    )

    with pytest.raises(ActivationPackageError) as raised:
        activation_package_module.execute_approved_staging_canary(package)

    assert str(raised.value) == "activation progress could not be emitted"
    assert calls == [protected_start, ["/bin/true", "cleanup"]]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"


def test_staging_command_completion_checkpoint_failure_preserves_bounded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, _contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="c" * 64,
        staging=[["/bin/true", "staging"]],
    )
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", lambda _command: 0)
    original_write = activation_package_module._write_activation_state

    def fail_completion(document: dict[str, object]) -> None:
        if document.get("status") == "command_complete":
            raise OSError("simulated completion checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_completion)

    with pytest.raises(ActivationPackageError, match="checkpoint failed after staging command"):
        activation_package_module.execute_approved_staging_canary(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "OSError"
    assert state["secretValuesRecorded"] is False


def test_cutover_gate_failure_preserves_bounded_failure_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, _contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="b" * 64,
        staging=[["/bin/true", "staging"]],
    )
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", lambda _command: 0)
    monkeypatch.setattr(
        activation_package_module,
        "verify_approved_cutover",
        lambda _package: (_ for _ in ()).throw(ActivationPackageError("cutover denied")),
    )

    with pytest.raises(ActivationPackageError, match="cutover gate failed"):
        activation_package_module.execute_approved_staging_canary(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "ActivationPackageError"
    assert state["secretValuesRecorded"] is False


def test_final_staging_checkpoint_failure_preserves_bounded_failure_after_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, _contract, state_path = _staging_failure_case(
        tmp_path,
        monkeypatch,
        digest="a" * 64,
        staging=[["/bin/true", "staging"]],
    )
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", lambda _command: 0)
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )
    monkeypatch.setattr(
        activation_package_module,
        "verify_approved_cutover",
        lambda _package: {"verified": True},
    )
    original_write = activation_package_module._write_activation_state

    def fail_final_checkpoint(document: dict[str, object]) -> None:
        if document.get("status") == "canary_passed_awaiting_cutover_approval":
            raise OSError("simulated final staging checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_final_checkpoint)

    with pytest.raises(ActivationPackageError, match="final staging checkpoint failed"):
        activation_package_module.execute_approved_staging_canary(package)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "OSError"
    assert state["secretValuesRecorded"] is False


def test_cleanup_command_failure_supersedes_originating_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "9" * 64
    package = tmp_path / "package"
    state_path = tmp_path / "executor" / "activation-state.json"
    cleanup = ["/bin/true", "cleanup"]
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
        "canary": {"failureCleanupCommands": [cleanup]},
    }
    calls = 0

    def execute(_command: list[str]) -> int:
        nonlocal calls
        calls += 1
        return 2 if calls == 1 else 0

    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_validate_contract_principal_binding", lambda _contract: None)
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)

    assert activation_package_module._execute_resilient_cleanup(
        contract,
        package_digest=digest,
        originating_failure="exit-7",
        require_canary_evidence=False,
    ) is True

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "exit-2"
    assert state["secretValuesRecorded"] is False
    assert calls == 2


def test_cleanup_command_failure_survives_cleanup_failed_checkpoint_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "7" * 64
    state_path = tmp_path / "executor" / "activation-state.json"
    cleanup = ["/bin/true", "cleanup"]
    contract = {"canary": {"failureCleanupCommands": [cleanup]}}
    calls = 0

    def execute(_command: list[str]) -> int:
        nonlocal calls
        calls += 1
        return 2 if calls == 1 else 0

    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_validate_contract_principal_binding", lambda _contract: None)
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", execute)
    original_write = activation_package_module._write_activation_state
    checkpoint_failed = False

    def fail_cleanup_failed_checkpoint(document: dict[str, object]) -> None:
        nonlocal checkpoint_failed
        if document.get("status") == "cleanup_failed" and not checkpoint_failed:
            checkpoint_failed = True
            raise OSError("simulated cleanup_failed checkpoint failure")
        original_write(document)

    monkeypatch.setattr(
        activation_package_module,
        "_write_activation_state",
        fail_cleanup_failed_checkpoint,
    )

    assert activation_package_module._execute_resilient_cleanup(
        contract,
        package_digest=digest,
        originating_failure="exit-7",
    ) is True

    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "exit-2"
    assert state["secretValuesRecorded"] is False
    assert checkpoint_failed is True
    assert calls == 2


def test_staging_recovery_preserves_prior_bounded_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "8" * 64
    package = tmp_path / "package"
    cleanup = ["/bin/true", "cleanup"]
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
        "canary": {"failureCleanupCommands": [cleanup]},
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
        "_load_activation_approval_for_rollback",
        lambda _package: {"packageDigest": digest},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_sealed_package_json",
        lambda *_args, **_kwargs: contract,
    )
    monkeypatch.setattr(activation_package_module, "_execute_contract_command", lambda _command: 0)
    monkeypatch.setattr(
        activation_package_module,
        "_seal_canary_state_from_contract",
        lambda *_args, **_kwargs: {"sealed": True},
    )
    activation_package_module._write_activation_state(
        activation_package_module._runner_state(
            package_digest=digest,
            status="command_running",
            phase="staging-canary",
            command_index=0,
            command=["/bin/true", "staging"],
            failure="OSError",
        )
    )

    result = activation_package_module.execute_approved_rollback(package)

    assert result["status"] == "aborted_before_cutover"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "aborted_before_cutover"
    assert state["failure"] == "OSError"
    assert state["secretValuesRecorded"] is False


def test_staging_recovery_rejects_unbounded_prior_failure_before_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "6" * 64
    package = tmp_path / "package"
    cleanup = ["/bin/true", "cleanup"]
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
        "canary": {"failureCleanupCommands": [cleanup]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[list[str]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval_for_rollback",
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
        lambda command: calls.append(command) or 0,
    )
    persisted = activation_package_module._runner_state(
        package_digest=digest,
        status="command_running",
        phase="staging-canary",
        command_index=0,
        command=["/bin/true", "staging"],
    )
    persisted["failure"] = "raw verifier output: denied!"
    activation_package_module._write_activation_state(persisted)

    with pytest.raises(ActivationPackageError, match="failure classification is invalid"):
        activation_package_module.execute_approved_rollback(package)

    assert calls == []
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "command_running"
    assert state["failure"] == "raw verifier output: denied!"


def test_cutover_later_command_entry_checkpoint_failure_runs_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "2" * 64
    package = tmp_path / "package"
    first = ["/bin/true", "first-cutover"]
    second = ["/bin/true", "second-cutover"]
    rollback = ["/bin/true", "rollback"]
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "stagingAndCanaryCommands": [["/bin/true", "staging"]],
        "cutoverCommands": [first, second],
        "rollbackCommands": [rollback],
        "canary": {"failureCleanupCommands": [["/bin/true", "cleanup"]]},
    }
    state_path = tmp_path / "executor" / "activation-state.json"
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_bootstrap",
        lambda *_args: None,
    )
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
        "_load_activation_phase_approval",
        lambda *_args, **_kwargs: {"packageDigest": digest, "phase": "cutover"},
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
        lambda command: calls.append(tuple(command)) or 0,
    )
    original_write = activation_package_module._write_activation_state

    def fail_second_entry(document: dict[str, object]) -> None:
        if document.get("status") == "command_running" and document.get("commandIndex") == 1:
            raise OSError("simulated later command-entry checkpoint failure")
        original_write(document)

    monkeypatch.setattr(activation_package_module, "_write_activation_state", fail_second_entry)

    with pytest.raises(ActivationPackageError, match="entry checkpoint failed"):
        activation_package_module.execute_approved_cutover(package)

    assert calls == [tuple(first), tuple(rollback)]


def test_command_interrupt_is_classified_for_runner_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def interrupt(_command: list[str]) -> int:
        raise KeyboardInterrupt("simulated interrupt")

    monkeypatch.setattr(activation_package_module, "_execute_contract_command", interrupt)

    assert activation_package_module._command_outcome(["/bin/true"]) == (
        127,
        "KeyboardInterrupt",
    )


def test_emergency_cleanup_executes_sealed_stop_during_principal_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup = ["/usr/bin/systemctl", "stop", "overseer-api-canary.service"]
    calls: list[tuple[str, ...]] = []
    contract = {"canary": {"failureCleanupCommands": [cleanup]}}
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_binding",
        lambda _contract: (_ for _ in ()).throw(ActivationPackageError("principal drift")),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )

    activation_package_module._execute_emergency_cleanup_sequence(contract)

    assert calls == [tuple(cleanup)]


def test_emergency_rollback_contains_new_services_before_principal_drift_blocks_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop = ["/usr/bin/systemctl", "stop", "overseer-api.service"]
    transient = _rollback_transient_command()
    calls: list[tuple[str, ...]] = []
    contract = {"rollbackCommands": [stop, transient]}
    monkeypatch.setattr(
        activation_package_module,
        "_validate_contract_principal_binding",
        lambda _contract: (_ for _ in ()).throw(ActivationPackageError("principal drift")),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )

    with pytest.raises(ActivationPackageError, match="principal drift"):
        activation_package_module._execute_emergency_rollback_sequence(contract)

    assert calls == [tuple(stop)]


def test_manual_rollback_reaches_emergency_containment_under_principal_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "3" * 64
    package = tmp_path / "package"
    stop = ["/usr/bin/systemctl", "stop", "overseer-api.service"]
    transient = _rollback_transient_command()
    contract = {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(package.resolve()),
        "account": {"user": "overseer", "uid": 984, "group": "overseer", "gid": 984},
        "sourceStore": {"uid": os.getuid(), "gid": os.getgid()},
        "rollbackCommands": [stop, transient],
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
        "_load_activation_approval_for_rollback",
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
            status="command_running",
            phase="cutover",
            command_index=0,
            command=["/bin/true", "cutover"],
        )
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_principal_binding",
        lambda **_kwargs: (_ for _ in ()).throw(ActivationPackageError("principal drift")),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command: calls.append(tuple(command)) or 0,
    )

    with pytest.raises(ActivationPackageError, match="principal drift"):
        activation_package_module._execute_approved_rollback_locked(package)

    assert calls == [tuple(stop)]


def test_activation_lock_revalidates_path_after_flock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_path = tmp_path / "executor" / "activation-state.json"
    lock_path = state_path.with_name("activation.lock")
    replacement = state_path.with_name("replacement.lock")
    replacement.parent.mkdir(parents=True)
    replacement.parent.chmod(0o700)
    replacement.write_bytes(b"")
    replacement.chmod(0o600)
    original_flock = activation_package_module.fcntl.flock
    replaced = False
    monkeypatch.setattr(activation_package_module, "_activation_state_path", lambda: state_path)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )

    def replace_after_lock(descriptor: int, operation: int) -> None:
        nonlocal replaced
        original_flock(descriptor, operation)
        if operation & activation_package_module.fcntl.LOCK_EX and not replaced:
            replaced = True
            os.replace(replacement, lock_path)

    monkeypatch.setattr(activation_package_module.fcntl, "flock", replace_after_lock)

    with pytest.raises(ActivationPackageError, match="lock path changed"):
        with activation_package_module._activation_execution_lock():
            pytest.fail("replaced activation lock path was accepted")


MAINTENANCE_STAGE_NAMES = (
    "preflight",
    "stopWriters",
    "proveQuiescence",
    "preserveState",
    "installRelease",
    "migrateOfflineStores",
    "switchServices",
    "acceptance",
)


def _maintenance_activation_contract_fixture(package: Path) -> dict[str, object]:
    maintenance = _maintenance_contract_fixture(package)
    return {
        "schemaVersion": activation_package_module.ACTIVATION_CONTRACT_SCHEMA,
        "packageRoot": str(package.resolve()),
        "releaseRoot": "/opt/overseer/releases/current",
        "releaseManifestDigest": "a" * 64,
        "account": {
            "user": "overseer",
            "uid": 984,
            "group": "overseer",
            "gid": 984,
        },
        "sourceStore": {"path": str(package / "legacy.sqlite3")},
        "maintenanceWindow": {
            "stages": [
                {"name": name, "commands": [["/usr/bin/true", name]]}
                for name in MAINTENANCE_STAGE_NAMES
            ],
            "rollbackCommands": [["/usr/bin/true", "rollback"]],
            "rollbackTimeoutSeconds": [60],
            "rollbackWindowTimeoutSeconds": 1800,
            "rollbackStartIndex": 0,
            "stageTimeoutSeconds": {
                name: 60 for name in MAINTENANCE_STAGE_NAMES
            },
            "windowTimeoutSeconds": 5400,
            "secretInputs": [],
            "storeBindings": maintenance["storeBindings"],
            "deferredStoreBindings": maintenance["deferredStoreBindings"],
            "preservationInputs": maintenance["preservationInputs"],
            "evidenceRoot": maintenance["evidenceRoot"],
            "acceptanceChecks": maintenance["acceptanceChecks"],
        },
    }


def _maintenance_contract_fixture(package: Path) -> dict[str, object]:
    return {
        "schemaVersion": "overseer.maintenance-window-contract.v1",
        "packageRoot": str(package.resolve()),
        "releaseManifestDigest": "a" * 64,
        "account": {
            "user": "overseer",
            "uid": 984,
            "group": "overseer",
            "gid": 984,
        },
        "scope": "maintenance-window-for-this-package-only",
        "storeBindings": [
            {
                "name": "overseer-main",
                "sourceDb": str(package / "legacy.sqlite3"),
                "backupDb": str(package / "backup-main.sqlite3"),
                "destinationDb": str(package / "destination-main.sqlite3"),
                "storeKind": "overseer",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 11,
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "parentDevice": 1,
                    "parentInode": 10,
                    "parentMode": 0o700,
                },
            },
            {
                "name": "psychlo-bridge",
                "sourceDb": str(package / "psychlo.sqlite3"),
                "backupDb": str(package / "backup-psychlo.sqlite3"),
                "destinationDb": str(package / "destination-psychlo.sqlite3"),
                "storeKind": "copy-only",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 21,
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "parentDevice": 1,
                    "parentInode": 10,
                    "parentMode": 0o700,
                },
            },
            {
                "name": "roadex-relay",
                "sourceDb": str(package / "roadex.sqlite3"),
                "backupDb": str(package / "backup-roadex.sqlite3"),
                "destinationDb": str(package / "destination-roadex.sqlite3"),
                "storeKind": "copy-only",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 31,
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "parentDevice": 1,
                    "parentInode": 10,
                    "parentMode": 0o700,
                },
            },
        ],
        "deferredStoreBindings": [
            {
                "name": "codex-usage",
                "sourceDb": str(package / "codex-usage.sqlite3"),
                "policy": "preserve-and-resume-unchanged",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 41,
                    "uid": os.getuid(),
                    "gid": os.getgid(),
                    "parentDevice": 1,
                    "parentInode": 10,
                    "parentMode": 0o700,
                },
            }
        ],
        "preservationInputs": {
            "currentRelease": str(package / "current-release"),
            "credentialsDirectory": str(package / "credentials"),
            "userUnitsRuntimeEnv": str(package / "runtime.env"),
            "rollbackBundle": str(package / "rollback"),
            "userRuntimeUnit": str(package / "overseer.service"),
            "userApiUnit": str(package / "overseer-api.service"),
            "psychloCycleUnit": str(package / "overseer-psychlo-cycle.service"),
            "psychloMeterUnit": str(package / "overseer-psychlo-meter.service"),
            "psychloUsageUnit": str(package / "overseer-psychlo-usage.service"),
            "psychloUsageTimer": str(package / "overseer-psychlo-usage.timer"),
            "quarkSchedulerUnit": str(package / "overseer-quark-scheduler.service"),
            "quarkSchedulerTimer": str(package / "overseer-quark-scheduler.timer"),
            "codexUsageMcpUnit": str(package / "overseer-codex-usage-mcp.service"),
            "codexUsageSnapshotUnit": str(package / "overseer-codex-usage-snapshot.service"),
            "codexUsageSnapshotTimer": str(package / "overseer-codex-usage-snapshot.timer"),
        },
        "evidenceRoot": str(package / "evidence"),
        "acceptanceChecks": list(
            activation_package_module._MAINTENANCE_ACCEPTANCE_CHECKS
        ),
        "secretInputs": [],
        "stages": [
            {"name": name, "commands": [["/usr/bin/true", name]]}
            for name in MAINTENANCE_STAGE_NAMES
        ],
        "stageTimeoutSeconds": {name: 60 for name in MAINTENANCE_STAGE_NAMES},
        "windowTimeoutSeconds": 5400,
        "rollbackCommands": [["/usr/bin/true", "rollback"]],
        "rollbackTimeoutSeconds": [60],
        "rollbackWindowTimeoutSeconds": 1800,
        "rollbackStartIndex": 0,
    }


def _write_maintenance_contract_fixture(
    package: Path,
    contract: dict[str, object],
) -> None:
    public = package / "public"
    public.mkdir(parents=True, exist_ok=True)
    (public / "maintenance-window-contract.json").write_text(
        json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (public / "maintenance-window-contract.json").chmod(0o644)
    (public / "package-manifest.json").write_text(
        json.dumps(
            {
                "schemaVersion": activation_package_module.PACKAGE_MANIFEST_SCHEMA,
                "packageDigest": "c" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    (public / "package-manifest.json").chmod(0o644)


def test_render_maintenance_window_contract_is_digest_bound_sibling_with_safe_order(
    tmp_path: Path,
) -> None:
    package = tmp_path / "package"
    (package / "public").mkdir(parents=True)

    contract = activation_package_module.render_maintenance_window_contract(
        package,
        _maintenance_activation_contract_fixture(package),
    )

    contract_path = package / "public" / "maintenance-window-contract.json"
    assert contract_path.is_file()
    assert contract["packageRoot"] == str(package.resolve())
    assert contract["releaseManifestDigest"] == "a" * 64
    assert contract["account"] == {
        "user": "overseer",
        "uid": 984,
        "group": "overseer",
        "gid": 984,
    }
    assert "packageDigest" not in contract
    assert [stage["name"] for stage in contract["stages"]] == list(
        MAINTENANCE_STAGE_NAMES
    )
    assert contract["rollbackCommands"]

    serialized = json.dumps(contract, sort_keys=True)
    for forbidden in (
        "phase-b",
        "staging-canary",
        "cutover",
        "canary",
        "vm",
        "virsh",
        "qemu",
        "claim",
        "firewall",
        "reboot",
    ):
        assert forbidden not in serialized.lower()


def test_render_activation_contract_emits_real_maintenance_window_plan(
    tmp_path: Path,
) -> None:
    package, manifest, source = _prepared_package(tmp_path)
    rollback = tmp_path / "rollback"
    rollback.mkdir()
    (rollback / "src.py").write_text("rollback input\n", encoding="utf-8")
    psychlo = tmp_path / "psychlo" / "bridge.sqlite3"
    psychlo.parent.mkdir()
    _wal_store(psychlo)
    roadex = tmp_path / "roadex" / "relay.sqlite3"
    roadex.parent.mkdir()
    _wal_store(roadex)
    codex_usage = tmp_path / "codex-usage" / "state.sqlite3"
    codex_usage.parent.mkdir()
    _wal_store(codex_usage)

    activation = render_activation_contract(
        package,
        manifest,
        source_store=source,
        overseer_uid=984,
        overseer_gid=984,
        rollback_inputs={"v1.1.5-release": rollback},
        psychlo_store=psychlo,
        roadex_store=roadex,
        codex_usage_store=codex_usage,
    )

    maintenance_path = package / "public" / "maintenance-window-contract.json"
    assert maintenance_path.is_file()
    maintenance = json.loads(maintenance_path.read_text(encoding="utf-8"))
    assert maintenance["releaseManifestDigest"] == manifest["manifestDigest"]
    assert maintenance["rollbackCommands"] != activation["rollbackCommands"]
    assert any(
        "restore-maintenance-store-access" in command
        for command in maintenance["rollbackCommands"]
    )
    assert [binding["name"] for binding in maintenance["storeBindings"]] == [
        "overseer-main",
        "psychlo-bridge",
        "roadex-relay",
    ]
    assert maintenance["acceptanceChecks"] == list(
        activation_package_module._MAINTENANCE_ACCEPTANCE_CHECKS
    )
    stages = {stage["name"]: stage["commands"] for stage in maintenance["stages"]}
    assert any("stop-maintenance-writers" in command for command in stages["stopWriters"])
    assert any("verify-maintenance-quiescence" in command for command in stages["proveQuiescence"])
    assert any("preserve-maintenance-state" in command for command in stages["preserveState"])
    assert any(command[0] == "/usr/bin/install" for command in stages["installRelease"])
    assert any("prepare-maintenance-stores" in command for command in stages["migrateOfflineStores"])
    assert any("overseer-runtime.service" in command for command in stages["switchServices"])
    assert any("verify-maintenance-acceptance" in command for command in stages["acceptance"])
    serialized = json.dumps(maintenance, sort_keys=True).lower()
    for forbidden in ("staging-canary", "phase-b", "virsh", "qemu", "claim", "firewall", "reboot"):
        assert forbidden not in serialized


def test_final_package_manifest_seals_maintenance_window_contract_as_public_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    for relative in ("public", "private/migration"):
        path = package / relative
        path.mkdir(parents=True)
        path.chmod(0o700)
    (package / "private").chmod(0o700)
    package.chmod(0o700)
    contract = _maintenance_contract_fixture(package)
    _write_maintenance_contract_fixture(package, contract)
    (package / "public" / "activation-contract.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (package / "public" / "rollback-manifest.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (package / "private" / "migration" / "migration-report.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    for path in package.rglob("*"):
        if path.is_file():
            path.chmod(0o600 if "private" in path.parts else 0o644)

    monkeypatch.setattr(
        activation_package_module,
        "activation_package_status",
        lambda _package: {"status": "credentials_complete"},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_validate_migration_rehearsal_semantics",
        lambda _package: None,
    )
    (package / "public" / "package-manifest.json").unlink()

    finalized = finalize_activation_package(package)
    manifest = json.loads(
        (package / "public" / "package-manifest.json").read_text(
            encoding="utf-8"
        )
    )

    assert finalized["packageDigest"] == manifest["packageDigest"]
    assert any(
        item["path"] == "public/maintenance-window-contract.json"
        for item in manifest["files"]
    )
    assert verify_activation_package(package, str(finalized["packageDigest"]))[
        "verified"
    ] is True


def test_maintenance_window_approval_is_distinct_root_record_and_rejects_reuse_or_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    contract = _maintenance_contract_fixture(package)
    _write_maintenance_contract_fixture(package, contract)
    approval_path = tmp_path / "approved-maintenance-window.json"
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_root_identity",
        lambda: (os.geteuid(), os.getegid()),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_maintenance_approval_record_path",
        lambda: approval_path,
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "verify_activation_package",
        lambda _package, expected: {
            "verified": True,
            "packageDigest": expected,
        },
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_activation_approval",
        lambda _package: {"packageDigest": "c" * 64},
    )

    approval = activation_package_module.record_maintenance_window_approval(
        package,
        "c" * 64,
        allow_reboot=False,
    )

    assert approval["packageDigest"] == "c" * 64
    assert approval["scope"] == "maintenance-window-for-this-package-only"
    assert approval["allowReboot"] is False
    assert isinstance(approval["planDigest"], str)
    assert len(approval["planDigest"]) == 64
    assert stat_mode(approval_path) == 0o600
    with pytest.raises(ActivationPackageError, match="already exists"):
        activation_package_module.record_maintenance_window_approval(
            package,
            "c" * 64,
            allow_reboot=False,
        )

    approval_path.unlink()
    approval_path.write_text(
        json.dumps(
            {
                **approval,
                "packageDigest": "d" * 64,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    approval_path.chmod(0o600)
    with pytest.raises(ActivationPackageError, match="digest|drift"):
        activation_package_module.verify_approved_maintenance_window(package)


def test_maintenance_window_verification_ignores_legacy_phase_approval_as_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    contract = _maintenance_contract_fixture(package)
    _write_maintenance_contract_fixture(package, contract)
    phase_approval = tmp_path / "approved-activation-phase-staging-canary.json"
    phase_approval.write_text(
        json.dumps(
            {
                "schemaVersion": activation_package_module.ACTIVATION_PHASE_APPROVAL_SCHEMA,
                "approved": True,
                "packageDigest": "c" * 64,
                "phase": "staging-canary",
            }
        ),
        encoding="utf-8",
    )
    phase_approval.chmod(0o600)
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_maintenance_approval_record_path",
        lambda: tmp_path / "missing-maintenance-approval.json",
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_sealed_package_json",
        lambda *_args, **_kwargs: contract,
    )

    with pytest.raises(ActivationPackageError, match="maintenance approval"):
        activation_package_module.verify_approved_maintenance_window(package)


def test_maintenance_window_execution_uses_shared_lock_separate_state_and_checkpointed_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    contract = _maintenance_contract_fixture(package)
    _write_maintenance_contract_fixture(package, contract)
    state_path = tmp_path / "maintenance-state.json"
    legacy_state_path = tmp_path / "activation-state.json"
    legacy_state_path.write_text('{"status":"legacy"}\n', encoding="utf-8")
    approval = {
        "schemaVersion": "overseer.maintenance-window-approval.v1",
        "packageRoot": str(package.resolve()),
        "packageDigest": "c" * 64,
        "planDigest": activation_package_module.maintenance_plan_digest(contract),
        "scope": "maintenance-window-for-this-package-only",
        "allowReboot": False,
    }
    lock_events: list[str] = []
    calls: list[tuple[str, ...]] = []

    class Lock:
        def __enter__(self) -> "Lock":
            lock_events.append("acquired")
            return self

        def __exit__(self, *_args: object) -> None:
            lock_events.append("released")

    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_activation_execution_lock",
        lambda: Lock(),
    )
    monkeypatch.setattr(
        activation_package_module,
        "_maintenance_state_path",
        lambda: state_path,
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_state_path",
        lambda: legacy_state_path,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_load_maintenance_approval",
        lambda _package: approval,
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_sealed_package_json",
        lambda *_args, **_kwargs: contract,
    )
    monkeypatch.setattr(
        activation_package_module,
        "verify_activation_package",
        lambda *_args, **_kwargs: {"verified": True, "packageDigest": "c" * 64},
    )
    monkeypatch.setattr(
        activation_package_module,
        "_execute_contract_command",
        lambda command, **_kwargs: calls.append(tuple(command)) or 0,
    )

    result = activation_package_module.execute_approved_maintenance_window(package)

    assert result["status"] == "complete"
    assert lock_events == ["acquired", "released"]
    assert calls == [
        ("/usr/bin/true", stage_name)
        for stage_name in MAINTENANCE_STAGE_NAMES
    ]
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "complete"
    assert state["packageDigest"] == "c" * 64
    assert json.loads(legacy_state_path.read_text(encoding="utf-8"))["status"] == "legacy"


def test_maintenance_window_rollback_accepts_only_maintenance_state_and_cli_has_separate_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / "package"
    package.mkdir()
    legacy_state_path = tmp_path / "activation-state.json"
    legacy_state_path.write_text('{"status":"command_running"}\n', encoding="utf-8")
    monkeypatch.setattr(activation_package_module, "_require_root_activation", lambda: None)
    monkeypatch.setattr(
        activation_package_module,
        "_maintenance_state_path",
        lambda: tmp_path / "missing-maintenance-state.json",
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "_activation_state_path",
        lambda: legacy_state_path,
    )

    with pytest.raises(ActivationPackageError, match="maintenance state"):
        activation_package_module.execute_approved_maintenance_rollback(package)

    observed: list[str] = []
    monkeypatch.setattr(
        activation_package_module,
        "record_maintenance_window_approval",
        lambda *_args, **_kwargs: observed.append("record") or {"status": "recorded"},
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "verify_approved_maintenance_window",
        lambda *_args, **_kwargs: observed.append("verify") or {"status": "verified"},
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "execute_approved_maintenance_window",
        lambda *_args, **_kwargs: observed.append("execute") or {"status": "complete"},
        raising=False,
    )
    monkeypatch.setattr(
        activation_package_module,
        "execute_approved_maintenance_rollback",
        lambda *_args, **_kwargs: observed.append("rollback") or {"status": "rolled_back"},
        raising=False,
    )

    for command in (
        "record-maintenance-window-approval",
        "verify-approved-maintenance-window",
        "execute-approved-maintenance-window",
        "execute-approved-maintenance-rollback",
    ):
        argv = [command, "--package-root", str(package)]
        if command == "record-maintenance-window-approval":
            argv.extend(["--expected-package-digest", "c" * 64])
        assert activation_package_module._main(argv) == 0

    assert observed == ["record", "verify", "execute", "rollback"]
