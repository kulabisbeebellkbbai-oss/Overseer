"""Prepare a closed dedicated-principal activation package without activation.

This module performs only owner-scoped staging.  It never invokes sudo,
systemctl, useradd, groupadd, a shell, or a gateway operation.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import getpass
import grp
import hashlib
import json
import math
import os
import pwd
import re
import secrets
import shlex
import sqlite3
import stat
import subprocess
import time
from contextlib import contextmanager
from urllib.parse import quote
from pathlib import Path, PurePosixPath
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .approval_auth import (
    create_approval_document,
    load_approval_verifier,
    write_approval_document,
)
from .store import SQLiteStore


RELEASE_SCHEMA = "overseer.dedicated-principal-release.v1"
ACTIVATION_CONTRACT_SCHEMA = "overseer.dedicated-principal-activation-contract.v1"
ROLLBACK_MANIFEST_SCHEMA = "overseer.dedicated-principal-rollback.v1"
PACKAGE_MANIFEST_SCHEMA = "overseer.dedicated-principal-package.v1"
ACTIVATION_APPROVAL_SCHEMA = "overseer.activation-package-approval.v1"
RELEASES_ROOT = PurePosixPath("/opt/overseer/releases")
MAX_RELEASE_FILE_BYTES = 128 * 1024 * 1024
MAX_STAGED_SECRET_BYTES = 512
APPROVED_OVERSEER_UID = 984
APPROVED_OVERSEER_GID = 984
APPROVED_PACKAGE_PARENT = Path("/home/god/.local/share/overseer/activation-packages")
APPROVED_EXECUTION_PACKAGE = Path("/var/lib/overseer-executor/approved-package")
APPROVED_SQLITE_VERSION = "3.53.4"
APPROVED_SQLITE_SOURCE_ID = (
    "2026-07-24 19:02:57 "
    "bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc"
)
APPROVED_SQLITE_ARCHIVE_SHA3_256 = (
    "454e45f61c6bd75b7420e7190732dea03ce6639c63ada47bbc592f67fc340338"
)
APPROVED_SQLITE_BINARY_SHA256 = (
    "ca4c66d9a6b3d24b27e05f8d1cfd7ae620e5862df39c96164910885797d6fc2e"
)
APPROVED_SQLITE_BUILD_RECIPE = "overseer.sqlite-3.53.4-gcc-14.2.0.v1"
APPROVED_SQLITE_COMPILER = "gcc (Debian 14.2.0-19) 14.2.0"
APPROVED_SQLITE_BUILD_DEFINITIONS = (
    "SQLITE_DEFAULT_AUTOVACUUM=1",
    "SQLITE_DEFAULT_CACHE_SIZE=-2000",
    "SQLITE_DEFAULT_RECURSIVE_TRIGGERS=1",
    "SQLITE_DEFAULT_SYNCHRONOUS=2",
    "SQLITE_DEFAULT_WAL_SYNCHRONOUS=2",
    "SQLITE_DEFAULT_WORKER_THREADS=0",
    "SQLITE_DIRECT_OVERFLOW_READ",
    "SQLITE_ENABLE_COLUMN_METADATA",
    "SQLITE_ENABLE_DBPAGE_VTAB",
    "SQLITE_ENABLE_DBSTAT_VTAB",
    "SQLITE_ENABLE_FTS3",
    "SQLITE_ENABLE_FTS3_PARENTHESIS",
    "SQLITE_ENABLE_FTS3_TOKENIZER",
    "SQLITE_ENABLE_FTS4",
    "SQLITE_ENABLE_FTS5",
    "SQLITE_ENABLE_LOAD_EXTENSION",
    "SQLITE_ENABLE_MATH_FUNCTIONS",
    "SQLITE_ENABLE_PREUPDATE_HOOK",
    "SQLITE_ENABLE_RTREE",
    "SQLITE_ENABLE_SESSION",
    "SQLITE_ENABLE_STMTVTAB",
    "SQLITE_ENABLE_UNLOCK_NOTIFY",
    "SQLITE_ENABLE_UPDATE_DELETE_LIMIT",
    "SQLITE_MAX_VARIABLE_NUMBER=250000",
    "SQLITE_SECURE_DELETE",
    "SQLITE_SOUNDEX",
    "SQLITE_THREADSAFE=1",
    "SQLITE_USE_URI",
)
STAGED_SQLITE_RUNTIME = PurePosixPath("private/runtime-input/libsqlite3.so.0")
REQUIRED_SQLITE_COMPILE_OPTIONS = frozenset(
    {
        "ENABLE_COLUMN_METADATA",
        "ENABLE_FTS5",
        "ENABLE_MATH_FUNCTIONS",
        "ENABLE_PREUPDATE_HOOK",
        "ENABLE_RTREE",
        "ENABLE_SESSION",
        "ENABLE_UNLOCK_NOTIFY",
        "MAX_VARIABLE_NUMBER=250000",
        "THREADSAFE=1",
        "USE_URI",
    }
)
CANARY_REQUIRED_CONTROLS = (
    "apiHealth",
    "usageBridgeBounded",
    "sessionBridgeReadOnly",
    "ordinaryTokenApprovalRejected",
    "wrongScopeApprovalRejected",
    "adminScopeApprovedBySisko",
    "allowlistedSmokeExecutedOnce",
    "samePlanReplayNoMutation",
    "unlistedUnitRejected",
)
ROLLBACK_TRANSIENT_MARKER = "overseer.rollback-transient.v1:"
MIGRATION_KEY_TABLES = (
    "schema_migrations",
    "agent_schema_migrations",
    "resources",
    "claims",
    "approvals",
    "audit_events",
    "admin_change_plans",
    "admin_executions",
    "collection_jobs",
    "collection_runs",
    "dashboard_projections",
    "runtime_heartbeats",
    "triage_incidents",
    "repair_attempts",
    "crew_messages",
    "decisions",
)
_HEX = frozenset("0123456789abcdef")
_SYSTEMD_TEMPLATES = {
    "overseer-admin-executor.socket": "overseer-admin-executor.socket",
    "overseer-admin-executor@.service": "overseer-admin-executor@.service",
    "overseer-api-canary.service": "overseer-api-canary.service",
    "overseer-api-system.service": "overseer-api.service",
    "overseer-approval-smoke.service": "overseer-approval-smoke.service",
    "overseer-codex-user-bridge.service": "overseer-codex-user-bridge.service",
    "overseer-codex-user-bridge.socket": "overseer-codex-user-bridge.socket",
    "overseer-runtime-system.service": "overseer-runtime.service",
    "overseer-tmpfiles.conf": "overseer-tmpfiles.conf",
}


class ActivationPackageError(ValueError):
    """Raised when a package input or staged artifact is unsafe or unstable."""


def _validate_principal_binding(*, god_uid: int, overseer_uid: int, overseer_gid: int) -> None:
    if (overseer_uid, overseer_gid) != (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID):
        raise ActivationPackageError("dedicated principal must use the approved UID/GID 984")
    try:
        god = pwd.getpwnam("god")
    except KeyError as error:
        raise ActivationPackageError("approved god account is unavailable") from error
    if god.pw_uid != god_uid:
        raise ActivationPackageError("god UID does not match the approved local account")
    try:
        existing_user = pwd.getpwuid(overseer_uid)
    except KeyError:
        existing_user = None
    if existing_user is not None and (
        existing_user.pw_name != "overseer" or existing_user.pw_gid != overseer_gid
    ):
        raise ActivationPackageError("approved Overseer UID is assigned to another account")
    try:
        existing_group = grp.getgrgid(overseer_gid)
    except KeyError:
        existing_group = None
    if existing_group is not None and existing_group.gr_name != "overseer":
        raise ActivationPackageError("approved Overseer GID is assigned to another group")


def _validate_new_package_destination(package_root: str | os.PathLike[str]) -> Path:
    package = Path(package_root).absolute()
    parent = APPROVED_PACKAGE_PARENT.absolute()
    _ensure_directory(parent)
    if package.parent != parent:
        raise ActivationPackageError("activation package must be staged below the approved Overseer package root")
    if re.fullmatch(r"v1\.1\.6-[0-9a-f]{7,40}", package.name) is None:
        raise ActivationPackageError("activation package directory name is invalid")
    if package.exists() or package.is_symlink():
        raise ActivationPackageError("activation package destination must not already exist")
    return package


def _validate_existing_package_destination(package_root: str | os.PathLike[str]) -> Path:
    package = Path(package_root).absolute()
    if package == APPROVED_EXECUTION_PACKAGE.absolute():
        parent = package.parent
        try:
            parent_metadata = parent.lstat()
            package_metadata = package.lstat()
        except OSError as error:
            raise ActivationPackageError("approved execution package is unavailable") from error
        root_uid, root_gid = _activation_root_identity()
        if (
            parent.is_symlink()
            or package.is_symlink()
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or not stat.S_ISDIR(package_metadata.st_mode)
            or (parent_metadata.st_uid, parent_metadata.st_gid) != (root_uid, root_gid)
            or (package_metadata.st_uid, package_metadata.st_gid) != (root_uid, root_gid)
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or stat.S_IMODE(package_metadata.st_mode) != 0o700
        ):
            raise ActivationPackageError("approved execution package ownership or mode is invalid")
        return package
    parent = APPROVED_PACKAGE_PARENT.absolute()
    if package.parent != parent or re.fullmatch(r"v1\.1\.6-[0-9a-f]{7,40}", package.name) is None:
        raise ActivationPackageError("activation package is outside the approved Overseer package root")
    try:
        parent_metadata = parent.lstat()
        package_metadata = package.lstat()
    except OSError as error:
        raise ActivationPackageError("activation package is unavailable") from error
    if (
        parent.is_symlink()
        or package.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or not stat.S_ISDIR(package_metadata.st_mode)
        or parent_metadata.st_uid != package_metadata.st_uid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or stat.S_IMODE(package_metadata.st_mode) != 0o700
    ):
        raise ActivationPackageError("activation package ownership or mode is invalid")
    return package


def _validate_sqlite_staged_package_destination(
    package_root: str | os.PathLike[str],
) -> Path:
    package = _validate_existing_package_destination(package_root)
    observed_files: list[str] = []
    observed_directories: list[str] = []
    for directory, directories, files in os.walk(package, followlinks=False):
        base = Path(directory)
        for name in directories:
            child = base / name
            if child.is_symlink():
                raise ActivationPackageError("SQLite-staged package contains a directory symlink")
            observed_directories.append(child.relative_to(package).as_posix())
        for name in files:
            child = base / name
            if child.is_symlink():
                raise ActivationPackageError("SQLite-staged package contains a file symlink")
            observed_files.append(child.relative_to(package).as_posix())
    if sorted(observed_directories) != ["private", "private/runtime-input"] or sorted(
        observed_files
    ) != [STAGED_SQLITE_RUNTIME.as_posix()]:
        raise ActivationPackageError("package must contain only the staged SQLite runtime")
    return package


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ActivationPackageError("activation package value is not canonical JSON") from error


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(checkout: Path, *args: str) -> bytes:
    result = subprocess.run(
        ("git", "-C", str(checkout), *args),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ActivationPackageError("reviewed Git checkout could not be inspected")
    return result.stdout


def _stable_read(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise ActivationPackageError(f"release input is not a regular file: {path}")
        if before.st_nlink != 1:
            raise ActivationPackageError(f"release input must be single-link: {path}")
        if before.st_size > MAX_RELEASE_FILE_BYTES:
            raise ActivationPackageError(f"release input exceeds the per-file bound: {path}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino
                or opened.st_size != before.st_size
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
            ):
                raise ActivationPackageError(f"release input changed while opening: {path}")
            data = bytearray()
            while len(data) <= MAX_RELEASE_FILE_BYTES:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, MAX_RELEASE_FILE_BYTES + 1 - len(data)),
                )
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        lexical_after = path.lstat()
        state = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if state(before) != state(after) or state(before) != state(lexical_after):
            raise ActivationPackageError(f"release input changed while reading: {path}")
        if len(data) != opened.st_size or len(data) > MAX_RELEASE_FILE_BYTES:
            raise ActivationPackageError(f"release input was not read completely: {path}")
        return bytes(data), opened
    except ActivationPackageError:
        raise
    except OSError as error:
        raise ActivationPackageError(f"release input could not be safely read: {path}") from error


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ActivationPackageError("release path is unsafe")
    return path.as_posix()


def _source_inventory(checkout: Path) -> tuple[str, ...]:
    raw = _git(checkout, "ls-tree", "-r", "--name-only", "-z", "HEAD", "--", "src/overseer")
    result = tuple(sorted(item.decode("utf-8", "strict") for item in raw.split(b"\0") if item))
    if not result:
        raise ActivationPackageError("reviewed runtime source inventory is empty")
    return result


def _dependency_inventory(root: Path) -> tuple[str, ...]:
    if not root.is_dir() or root.is_symlink():
        raise ActivationPackageError("dependency root is unavailable or is a symlink")
    result: list[str] = []
    for directory, directories, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in tuple(directories):
            path = base / name
            if path.is_symlink():
                raise ActivationPackageError("dependency runtime contains a symlink")
            if name == "__pycache__":
                directories.remove(name)
        for name in files:
            path = base / name
            if path.is_symlink():
                raise ActivationPackageError("dependency runtime contains a symlink")
            if path.suffix in {".pyc", ".pyo"}:
                continue
            result.append(_safe_relative(path.relative_to(root).as_posix()))
    if not result:
        raise ActivationPackageError("dependency runtime inventory is empty")
    return tuple(sorted(result))


def _runtime_inventory(root: Path) -> tuple[str, ...]:
    if not root.is_dir() or root.is_symlink():
        raise ActivationPackageError("standard-library root is unavailable or is a symlink")
    result: list[str] = []
    for directory, directories, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in tuple(directories):
            path = base / name
            if path.is_symlink():
                raise ActivationPackageError("standard-library runtime contains a directory symlink")
            if name == "__pycache__":
                directories.remove(name)
        for name in files:
            path = base / name
            if path.suffix in {".pyc", ".pyo"}:
                continue
            if path.is_symlink():
                try:
                    resolved = path.resolve(strict=True)
                except OSError as error:
                    raise ActivationPackageError("standard-library runtime contains a broken symlink") from error
                if not resolved.is_file() or resolved.is_symlink():
                    raise ActivationPackageError("standard-library symlink target is not a regular file")
            result.append(_safe_relative(path.relative_to(root).as_posix()))
    if not result:
        raise ActivationPackageError("standard-library runtime inventory is empty")
    return tuple(sorted(result))


def _runtime_read(root: Path, source_path: str) -> tuple[bytes, os.stat_result, str]:
    lexical = root / _safe_relative(source_path)
    selected = lexical
    if lexical.is_symlink():
        try:
            selected = lexical.resolve(strict=True)
        except OSError as error:
            raise ActivationPackageError("standard-library symlink could not be resolved") from error
    content, metadata = _stable_read(selected)
    return content, metadata, str(selected)


def _file_entry(
    *,
    source_kind: str,
    source_root: Path,
    source_path: str,
    release_path: str,
) -> dict[str, object]:
    content, metadata = _stable_read(source_root / source_path)
    return {
        "releasePath": _safe_relative(release_path),
        "sourceKind": source_kind,
        "sourcePath": _safe_relative(source_path),
        "sha256": _sha256(content),
        "size": len(content),
        "mode": 0o555 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o444,
    }


def _probe_sqlite_runtime(
    root_python: Path,
    sqlite_library: Path,
    expected_metadata: os.stat_result,
) -> dict[str, object]:
    script = """
import json
import os
import sqlite3
from pathlib import Path

expected_device = int(os.environ['OVERSEER_EXPECTED_SQLITE_DEVICE'])
expected_inode = int(os.environ['OVERSEER_EXPECTED_SQLITE_INODE'])
mapped_expected = False
for line in Path('/proc/self/maps').read_text(encoding='utf-8').splitlines():
    fields = line.split()
    if len(fields) < 5 or ':' not in fields[3]:
        continue
    major, minor = (int(value, 16) for value in fields[3].split(':', 1))
    if os.makedev(major, minor) == expected_device and int(fields[4]) == expected_inode:
        mapped_expected = True
        break
with sqlite3.connect(':memory:') as connection:
    result = {
        'version': sqlite3.sqlite_version,
        'sourceId': connection.execute('SELECT sqlite_source_id()').fetchone()[0],
        'compileOptions': sorted(row[0] for row in connection.execute('PRAGMA compile_options')),
        'mappedExpectedLibrary': mapped_expected,
        'mappedDevice': expected_device if mapped_expected else None,
        'mappedInode': expected_inode if mapped_expected else None,
    }
print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':')))
"""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(sqlite_library, flags)
    except OSError as error:
        raise ActivationPackageError("approved SQLite runtime could not be opened for probing") from error
    state = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    try:
        opened_before = os.fstat(descriptor)
        if state(opened_before) != state(expected_metadata):
            raise ActivationPackageError("approved SQLite runtime changed before probing")
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LD_LIBRARY_PATH": str(sqlite_library.parent),
            "LD_PRELOAD": f"/proc/self/fd/{descriptor}",
            "OVERSEER_EXPECTED_SQLITE_DEVICE": str(expected_metadata.st_dev),
            "OVERSEER_EXPECTED_SQLITE_INODE": str(expected_metadata.st_ino),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
        try:
            result = subprocess.run(
                [str(root_python), "-I", "-s", "-P", "-c", script],
                cwd="/",
                capture_output=True,
                text=True,
                check=False,
                env=environment,
                pass_fds=(descriptor,),
            )
        except OSError as error:
            raise ActivationPackageError("approved SQLite runtime probe could not start") from error
        opened_after = os.fstat(descriptor)
        lexical_after = sqlite_library.lstat()
        if state(opened_after) != state(expected_metadata) or state(lexical_after) != state(
            expected_metadata
        ):
            raise ActivationPackageError("approved SQLite runtime changed during probing")
    finally:
        os.close(descriptor)
    try:
        evidence = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("approved SQLite runtime probe output is invalid") from error
    if result.returncode != 0 or not isinstance(evidence, dict):
        raise ActivationPackageError("approved SQLite runtime probe failed")
    return evidence


def _validated_sqlite_runtime(
    *,
    root_python: Path,
    sqlite_library: Path,
) -> dict[str, object]:
    raw, metadata = _stable_read(sqlite_library)
    package = sqlite_library.parent.parent.parent
    expected_path = package / STAGED_SQLITE_RUNTIME
    directory_metadata: list[tuple[Path, int]] = [
        (package, 0o700),
        (package / "private", 0o700),
        (package / "private" / "runtime-input", 0o500),
    ]
    if (
        sqlite_library.absolute() != expected_path.absolute()
        or sqlite_library.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or _sha256(raw) != APPROVED_SQLITE_BINARY_SHA256
    ):
        raise ActivationPackageError("approved SQLite runtime library metadata is invalid")
    for directory, expected_mode in directory_metadata:
        try:
            directory_stat = directory.lstat()
        except OSError as error:
            raise ActivationPackageError("approved SQLite staging directory is unavailable") from error
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or stat.S_IMODE(directory_stat.st_mode) != expected_mode
        ):
            raise ActivationPackageError("approved SQLite staging directory metadata is invalid")
    evidence = _probe_sqlite_runtime(root_python, sqlite_library, metadata)
    options = evidence.get("compileOptions")
    if (
        evidence.get("version") != APPROVED_SQLITE_VERSION
        or evidence.get("sourceId") != APPROVED_SQLITE_SOURCE_ID
        or evidence.get("mappedExpectedLibrary") is not True
        or evidence.get("mappedDevice") != metadata.st_dev
        or evidence.get("mappedInode") != metadata.st_ino
        or not isinstance(options, list)
        or not all(isinstance(value, str) for value in options)
        or not REQUIRED_SQLITE_COMPILE_OPTIONS.issubset(set(options))
    ):
        raise ActivationPackageError("approved SQLite runtime identity or features are invalid")
    confirmed_raw, confirmed_metadata = _stable_read(sqlite_library)
    if (
        confirmed_metadata.st_dev != metadata.st_dev
        or confirmed_metadata.st_ino != metadata.st_ino
        or _sha256(confirmed_raw) != APPROVED_SQLITE_BINARY_SHA256
    ):
        raise ActivationPackageError("approved SQLite runtime drifted during attestation")
    return {
        "path": str(sqlite_library),
        "stagedInputPackage": str(package),
        "releasePath": "lib/libsqlite3.so.0",
        "sha256": APPROVED_SQLITE_BINARY_SHA256,
        "size": len(raw),
        "mode": 0o555,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "version": APPROVED_SQLITE_VERSION,
        "sourceId": APPROVED_SQLITE_SOURCE_ID,
        "sourceArchiveSha3_256": APPROVED_SQLITE_ARCHIVE_SHA3_256,
        "buildProvenance": {
            "recipe": APPROVED_SQLITE_BUILD_RECIPE,
            "compiler": APPROVED_SQLITE_COMPILER,
            "sourceArchiveUrl": "https://www.sqlite.org/2026/sqlite-autoconf-3530400.tar.gz",
            "sourceArchiveSha3_256": APPROVED_SQLITE_ARCHIVE_SHA3_256,
            "binarySha256": APPROVED_SQLITE_BINARY_SHA256,
            "compileDefinitions": list(APPROVED_SQLITE_BUILD_DEFINITIONS),
        },
        "compileOptions": sorted(options),
        "walResetFixAttested": True,
    }


def _assert_current_sqlite_runtime(manifest: Mapping[str, object]) -> None:
    sqlite_runtime = manifest.get("sqliteRuntime")
    if not isinstance(sqlite_runtime, Mapping) or not isinstance(sqlite_runtime.get("path"), str):
        raise ActivationPackageError("release SQLite runtime manifest is invalid")
    expected = Path(str(sqlite_runtime["path"]))
    try:
        raw, metadata = _stable_read(expected)
        mapped: set[tuple[int, int]] = set()
        for line in Path("/proc/self/maps").read_text(encoding="utf-8").splitlines():
            fields = line.split()
            if len(fields) < 5 or ":" not in fields[3]:
                continue
            major, minor = (int(value, 16) for value in fields[3].split(":", 1))
            mapped.add((os.makedev(major, minor), int(fields[4])))
        with sqlite3.connect(":memory:") as connection:
            source_id = str(connection.execute("SELECT sqlite_source_id()").fetchone()[0])
            options = {str(row[0]) for row in connection.execute("PRAGMA compile_options")}
    except (OSError, ValueError, sqlite3.Error, TypeError, IndexError) as error:
        raise ActivationPackageError("current SQLite runtime could not be attested") from error
    if (
        sqlite3.sqlite_version != APPROVED_SQLITE_VERSION
        or source_id != APPROVED_SQLITE_SOURCE_ID
        or _sha256(raw) != APPROVED_SQLITE_BINARY_SHA256
        or metadata.st_dev != sqlite_runtime.get("device")
        or metadata.st_ino != sqlite_runtime.get("inode")
        or (metadata.st_dev, metadata.st_ino) not in mapped
        or not REQUIRED_SQLITE_COMPILE_OPTIONS.issubset(options)
    ):
        raise ActivationPackageError("package preparation is not using the approved SQLite runtime")


def build_release_manifest(
    checkout: str | os.PathLike[str],
    dependency_root: str | os.PathLike[str],
    root_python: str | os.PathLike[str],
    stdlib_root: str | os.PathLike[str],
    sqlite_library: str | os.PathLike[str],
) -> dict[str, object]:
    """Build a deterministic manifest from a clean reviewed checkout."""

    lexical_checkout = Path(checkout)
    lexical_dependencies = Path(dependency_root)
    lexical_stdlib = Path(stdlib_root)
    if lexical_checkout.is_symlink() or lexical_dependencies.is_symlink() or lexical_stdlib.is_symlink():
        raise ActivationPackageError("release roots must not be symlinks")
    selected_checkout = lexical_checkout.resolve()
    selected_dependencies = lexical_dependencies.resolve()
    selected_stdlib = lexical_stdlib.resolve()
    selected_python = Path(root_python)
    selected_sqlite = Path(sqlite_library)
    if _git(selected_checkout, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ActivationPackageError("reviewed Git checkout must be clean")
    commit = _git(selected_checkout, "rev-parse", "HEAD^{commit}").strip().decode("ascii").lower()
    tree = _git(selected_checkout, "rev-parse", "HEAD^{tree}").strip().decode("ascii").lower()
    if len(commit) != 40 or set(commit) - _HEX or len(tree) != 40 or set(tree) - _HEX:
        raise ActivationPackageError("reviewed Git identity is invalid")

    files = [
        _file_entry(
            source_kind="checkout",
            source_root=selected_checkout,
            source_path=path,
            release_path=f"app/{path}",
        )
        for path in _source_inventory(selected_checkout)
    ]
    files.extend(
        _file_entry(
            source_kind="dependency",
            source_root=selected_dependencies,
            source_path=path,
            release_path=f"site-packages/{path}",
        )
        for path in _dependency_inventory(selected_dependencies)
    )
    for path in _runtime_inventory(selected_stdlib):
        content, metadata, resolved = _runtime_read(selected_stdlib, path)
        files.append(
            {
                "releasePath": _safe_relative(f"runtime/lib/python3.13/{path}"),
                "sourceKind": "stdlib",
                "sourcePath": path,
                "sourceResolvedPath": resolved,
                "sha256": _sha256(content),
                "size": len(content),
                "mode": 0o555 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o444,
            }
        )
    files.sort(key=lambda item: str(item["releasePath"]))
    paths = [str(item["releasePath"]) for item in files]
    if paths != sorted(set(paths)):
        raise ActivationPackageError("release inventory paths are not unique")

    python_content, python_metadata = _stable_read(selected_python)
    sqlite_runtime = _validated_sqlite_runtime(
        root_python=selected_python,
        sqlite_library=selected_sqlite,
    )
    unsigned: dict[str, object] = {
        "schemaVersion": RELEASE_SCHEMA,
        "sourceCommit": commit,
        "sourceTree": tree,
        "files": files,
        "rootPython": {
            "path": str(selected_python),
            "releasePath": "runtime/bin/python3.13",
            "sha256": _sha256(python_content),
            "size": len(python_content),
            "mode": stat.S_IMODE(python_metadata.st_mode),
            "uid": python_metadata.st_uid,
            "gid": python_metadata.st_gid,
        },
        "sqliteRuntime": sqlite_runtime,
    }
    digest = _sha256(_canonical(unsigned))
    manifest = {
        **unsigned,
        "manifestDigest": digest,
        "releaseRoot": str(RELEASES_ROOT / f"{commit}-{digest}"),
    }
    if (
        _git(selected_checkout, "rev-parse", "HEAD^{commit}").strip().decode("ascii").lower() != commit
        or _git(selected_checkout, "rev-parse", "HEAD^{tree}").strip().decode("ascii").lower() != tree
        or _git(selected_checkout, "status", "--porcelain=v1", "--untracked-files=all").strip()
    ):
        raise ActivationPackageError("reviewed Git checkout changed while building the manifest")
    return manifest


def _ensure_directory(
    path: Path,
    mode: int = 0o700,
    *,
    enforce_existing_mode: bool = True,
) -> None:
    """Create a directory chain without following or chmodding existing parents."""

    selected = path.absolute()
    missing: list[Path] = []
    cursor = selected
    while True:
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            missing.append(cursor)
            parent = cursor.parent
            if parent == cursor:
                raise ActivationPackageError(f"package directory has no existing anchor: {path}")
            cursor = parent
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ActivationPackageError(f"package directory chain is unsafe: {cursor}")
        break
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=mode)
        except FileExistsError:
            metadata = directory.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ActivationPackageError(f"package directory chain changed: {directory}")
        else:
            os.chmod(directory, mode)
    metadata = selected.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ActivationPackageError(f"package directory is unsafe: {path}")
    if missing:
        os.chmod(selected, mode)
    elif enforce_existing_mode and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise ActivationPackageError(
            f"existing package directory must be owner-controlled mode {mode:04o}: {path}"
        )


def _write_new(path: Path, content: bytes, mode: int) -> None:
    _ensure_directory(path.parent, enforce_existing_mode=False)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("package write made no progress")
                view = view[written:]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except FileExistsError as error:
        raise ActivationPackageError(f"package artifact already exists: {path}") from error


def stage_sqlite_runtime_input(
    package_root: str | os.PathLike[str],
    *,
    source_library: str | os.PathLike[str],
) -> dict[str, object]:
    """Copy the independently approved SQLite binary to a closed package inode."""

    source = Path(source_library)
    raw, metadata = _stable_read(source)
    if (
        source.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or _sha256(raw) != APPROVED_SQLITE_BINARY_SHA256
    ):
        raise ActivationPackageError("SQLite runtime source is not the independently approved binary")
    package = Path(package_root)
    _ensure_directory(package)
    _ensure_directory(package / "private")
    runtime_input = package / "private" / "runtime-input"
    _ensure_directory(runtime_input)
    target = package / STAGED_SQLITE_RUNTIME
    _write_new(target, raw, 0o555)
    confirmed, confirmed_metadata = _stable_read(target)
    if (
        _sha256(confirmed) != APPROVED_SQLITE_BINARY_SHA256
        or confirmed_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(confirmed_metadata.st_mode) != 0o555
    ):
        raise ActivationPackageError("staged SQLite runtime identity is invalid")
    os.chmod(runtime_input, 0o500)
    return {
        "status": "staged",
        "path": str(target.absolute()),
        "sha256": APPROVED_SQLITE_BINARY_SHA256,
        "device": confirmed_metadata.st_dev,
        "inode": confirmed_metadata.st_ino,
        "buildRecipe": APPROVED_SQLITE_BUILD_RECIPE,
    }


def _read_secret(path: Path, *, label: str) -> bytes:
    try:
        lexical = path.lstat()
    except OSError as error:
        raise ActivationPackageError(f"{label} could not be inspected") from error
    if path.is_symlink():
        raise ActivationPackageError(f"{label} must not be a symlink")
    if not stat.S_ISREG(lexical.st_mode) or lexical.st_nlink != 1:
        raise ActivationPackageError(f"{label} must be a single-link regular file")
    if lexical.st_uid != os.geteuid():
        raise ActivationPackageError(f"{label} has an unexpected owner")
    if stat.S_IMODE(lexical.st_mode) != 0o600:
        raise ActivationPackageError(f"{label} must have mode 0600")
    content, opened = _stable_read(path)
    if opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600:
        raise ActivationPackageError(f"{label} metadata changed")
    if not content or len(content) > MAX_STAGED_SECRET_BYTES:
        raise ActivationPackageError(f"{label} has an invalid size")
    if any(byte <= 0x20 or byte == 0x7F for byte in content):
        raise ActivationPackageError(f"{label} is not canonical secret data")
    return content


def _credential_entry(*, target: str, content: bytes, source: str | None, mode: int) -> dict[str, object]:
    return {
        "target": target,
        "source": source,
        "mode": f"{mode:04o}",
        "size": len(content),
        "sha256": _sha256(content),
    }


def stage_credentials(
    package_root: str | os.PathLike[str],
    *,
    psychlo_secret_file: str | os.PathLike[str],
    roadex_secret_file: str | os.PathLike[str],
    psychlo_bindings_file: str | os.PathLike[str],
    random_bytes=secrets.token_bytes,
    ticket_private_key: Ed25519PrivateKey | None = None,
) -> dict[str, object]:
    """Stage machine credentials without printing or exposing their values."""

    package = Path(package_root)
    _ensure_directory(package)
    private = package / "private" / "credentials"
    public_config = package / "public" / "config"
    _ensure_directory(private)
    _ensure_directory(public_config)

    psychlo_path = Path(psychlo_secret_file)
    roadex_path = Path(roadex_secret_file)
    bindings_path = Path(psychlo_bindings_file)
    psychlo = _read_secret(psychlo_path, label="Psychlo peer secret")
    roadex = _read_secret(roadex_path, label="Roadex relay secret")
    bindings, bindings_metadata = _stable_read(bindings_path)
    if bindings_metadata.st_uid != os.geteuid() or stat.S_IMODE(bindings_metadata.st_mode) != 0o600:
        raise ActivationPackageError("Psychlo bindings snapshot must be owner-only mode 0600")
    try:
        parsed_bindings = json.loads(bindings)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("Psychlo bindings snapshot is not valid JSON") from error
    if not isinstance(parsed_bindings, dict):
        raise ActivationPackageError("Psychlo bindings snapshot must be a JSON object")

    generated = random_bytes(48)
    if type(generated) is not bytes or len(generated) != 48:
        raise ActivationPackageError("API token entropy source returned an invalid value")
    api_token = base64.urlsafe_b64encode(generated).rstrip(b"=")
    key = ticket_private_key or Ed25519PrivateKey.generate()
    private_key = key.private_bytes_raw()
    public_key = key.public_key().public_bytes_raw()

    staged = {
        private / "api-token": (api_token, 0o600),
        private / "psychlo-peer-secret": (psychlo, 0o600),
        private / "roadex-project-human-thread-secret": (roadex, 0o600),
        private / "admin-ticket-private-key": (private_key, 0o600),
        public_config / "admin-executor-public-key": (public_key, 0o644),
        public_config / "psychlo-project-bindings.json": (bindings, 0o644),
    }
    for path, (content, mode) in staged.items():
        _write_new(path, content, mode)

    metadata: dict[str, object] = {
        "schemaVersion": "overseer.activation-credentials.v1",
        "apiToken": {
            **_credential_entry(
                target="/etc/overseer/api-token",
                content=api_token,
                source=None,
                mode=0o600,
            ),
            "rotationRequired": True,
            "compatibilityCopy": "/home/god/.local/share/overseer/project/state/api-token",
        },
        "psychloPeerSecret": _credential_entry(
            target="/etc/overseer/psychlo-peer-secret",
            content=psychlo,
            source=str(psychlo_path),
            mode=0o600,
        ),
        "roadexRelaySecret": _credential_entry(
            target="/etc/overseer/roadex-project-human-thread-secret",
            content=roadex,
            source=str(roadex_path),
            mode=0o600,
        ),
        "psychloBindings": _credential_entry(
            target="/etc/overseer/psychlo-project-bindings.json",
            content=bindings,
            source=str(bindings_path),
            mode=0o644,
        ),
        "adminTicketPrivateKey": _credential_entry(
            target="/etc/overseer/admin-ticket-private-key",
            content=private_key,
            source=None,
            mode=0o600,
        ),
        "adminTicketPublicKey": _credential_entry(
            target="/etc/overseer/admin-executor-public-key",
            content=public_key,
            source=None,
            mode=0o644,
        ),
        "humanVerifiers": {
            "status": "awaiting_interactive_input",
            "adminScope": "admin-plan-approval",
            "roadexScope": "roadex-fixture-approval",
            "secretsMustDiffer": True,
            "secretsMustDifferFromApiToken": True,
        },
    }
    _write_new(
        package / "public" / "credential-metadata.json",
        _canonical(metadata) + b"\n",
        0o644,
    )
    return metadata


def create_human_verifiers(
    package_root: str | os.PathLike[str],
    *,
    admin_secret: str,
    roadex_secret: str,
) -> dict[str, object]:
    """Create both scoped verifier documents after one local interactive entry."""

    if secrets.compare_digest(admin_secret, roadex_secret):
        raise ActivationPackageError("admin and Roadex approval secrets must be different")
    package = Path(package_root)
    private = package / "private" / "credentials"
    api_path = private / "api-token"
    try:
        api_raw, api_metadata = _stable_read(api_path)
        if api_metadata.st_uid != os.geteuid() or stat.S_IMODE(api_metadata.st_mode) != 0o600:
            raise ActivationPackageError("staged API token metadata is invalid")
        api_token = api_raw.decode("ascii", "strict")
    except (OSError, UnicodeDecodeError) as error:
        raise ActivationPackageError("staged API token is unavailable") from error
    if secrets.compare_digest(admin_secret, api_token) or secrets.compare_digest(roadex_secret, api_token):
        raise ActivationPackageError("human approval secrets must differ from the API token")

    admin_path = private / "admin-approval-verifier.json"
    roadex_path = private / "roadex-fixture-approval-verifier.json"
    attestation_path = package / "public" / "human-verifier-separation.json"
    if any(path.exists() or path.is_symlink() for path in (admin_path, roadex_path, attestation_path)):
        raise ActivationPackageError("human verifier artifacts already exist")
    try:
        admin_document = create_approval_document(admin_secret, "admin-plan-approval")
        roadex_document = create_approval_document(roadex_secret, "roadex-fixture-approval")
        admin_verifier = write_approval_document(admin_path, admin_document)
        roadex_verifier = write_approval_document(roadex_path, roadex_document)
        admin_raw, _ = _stable_read(admin_path)
        roadex_raw, _ = _stable_read(roadex_path)
        attestation = {
            "schemaVersion": "overseer.human-verifier-separation.v1",
            "adminScope": admin_verifier.scope,
            "roadexScope": roadex_verifier.scope,
            "adminDocumentSha256": _sha256(admin_raw),
            "roadexDocumentSha256": _sha256(roadex_raw),
            "differentSecretsConfirmed": True,
            "apiTokenExcluded": True,
        }
        _write_new(attestation_path, _canonical(attestation) + b"\n", 0o644)
    except BaseException:
        for path in (admin_path, roadex_path, attestation_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    return {"status": "created", "adminScope": admin_verifier.scope, "roadexScope": roadex_verifier.scope}


def activation_package_status(package_root: str | os.PathLike[str]) -> dict[str, object]:
    """Report the credential gate without returning credential contents."""

    package = Path(package_root)
    package_manifest = package / "public" / "package-manifest.json"
    if package_manifest.exists() or package_manifest.is_symlink():
        if package_manifest.is_symlink() or not package_manifest.is_file():
            raise ActivationPackageError("package manifest is unsafe")
        try:
            document = json.loads(package_manifest.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ActivationPackageError("package manifest is invalid") from error
        digest = document.get("packageDigest") if isinstance(document, dict) else None
        if not isinstance(digest, str):
            raise ActivationPackageError("package manifest digest is invalid")
        verify_activation_package(package, digest)
        return {
            "status": "ready_for_approval",
            "readyForApproval": True,
            "packageDigest": digest,
        }
    private = package / "private" / "credentials"
    admin_path = private / "admin-approval-verifier.json"
    roadex_path = private / "roadex-fixture-approval-verifier.json"
    attestation_path = package / "public" / "human-verifier-separation.json"
    present = tuple(path.is_file() and not path.is_symlink() for path in (admin_path, roadex_path, attestation_path))
    if not any(present):
        return {"status": "awaiting_human_verifiers", "readyForApproval": False}
    if not all(present):
        raise ActivationPackageError("human verifier gate is only partially staged")
    admin = load_approval_verifier(admin_path)
    roadex = load_approval_verifier(roadex_path)
    api_raw, api_metadata = _stable_read(private / "api-token")
    if api_metadata.st_uid != os.geteuid() or stat.S_IMODE(api_metadata.st_mode) != 0o600:
        raise ActivationPackageError("staged API token metadata is invalid")
    try:
        api_token = api_raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ActivationPackageError("staged API token is invalid") from error
    if admin.scope != "admin-plan-approval" or roadex.scope != "roadex-fixture-approval":
        raise ActivationPackageError("human verifier scopes are invalid")
    if admin.verify(api_token) or roadex.verify(api_token):
        raise ActivationPackageError("staged API token authenticates as a human approval secret")
    admin_raw, _ = _stable_read(admin_path)
    roadex_raw, _ = _stable_read(roadex_path)
    try:
        attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("human verifier separation attestation is invalid") from error
    expected = {
        "schemaVersion": "overseer.human-verifier-separation.v1",
        "adminScope": "admin-plan-approval",
        "roadexScope": "roadex-fixture-approval",
        "adminDocumentSha256": _sha256(admin_raw),
        "roadexDocumentSha256": _sha256(roadex_raw),
        "differentSecretsConfirmed": True,
        "apiTokenExcluded": True,
    }
    if attestation != expected:
        raise ActivationPackageError("human verifier separation attestation does not match the documents")
    return {"status": "credentials_complete", "readyForApproval": False}


def _validate_store_artifact(
    path: Path,
    *,
    label: str,
    expected_uid: int | None = None,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ActivationPackageError(f"{label} could not be inspected") from error
    if path.is_symlink():
        raise ActivationPackageError(f"{label} must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ActivationPackageError(f"{label} must be a single-link regular file")
    selected_uid = os.geteuid() if expected_uid is None else expected_uid
    if metadata.st_uid != selected_uid:
        raise ActivationPackageError(f"{label} has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ActivationPackageError(f"{label} must have mode 0600")
    return metadata


def _hash_file(path: Path) -> tuple[str, int]:
    metadata = _validate_store_artifact(path, label="migration artifact")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ActivationPackageError("migration artifact changed while opening")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    lexical_after = path.lstat()
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(metadata) != identity(after) or identity(metadata) != identity(lexical_after):
        raise ActivationPackageError("migration artifact changed while hashing")
    if size != metadata.st_size:
        raise ActivationPackageError("migration artifact was not read completely")
    return digest.hexdigest(), size


def _copy_store(source: Path, target: Path) -> None:
    source_metadata = _validate_store_artifact(source, label="rehearsal backup")
    _ensure_directory(target.parent)
    source_fd = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    target_fd: int | None = None
    try:
        opened = os.fstat(source_fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            source_metadata.st_dev,
            source_metadata.st_ino,
            source_metadata.st_size,
        ):
            raise ActivationPackageError("rehearsal backup changed while opening")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        target_fd = os.open(target, flags, 0o600)
        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise OSError("migration copy made no progress")
                copied += written
                view = view[written:]
        if copied != opened.st_size:
            raise ActivationPackageError("rehearsal backup copy was truncated")
        os.fchmod(target_fd, 0o600)
        os.fsync(target_fd)
    except BaseException:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)


def _sqlite_uri(path: Path, mode: str = "ro") -> str:
    return f"file:{quote(path.as_posix(), safe='/')}?mode={mode}"


def _integrity_check(path: Path) -> str:
    connection = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=5)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        connection.close()
    result = str(row[0]) if row else "missing"
    if result != "ok":
        raise ActivationPackageError("migration artifact failed SQLite integrity_check")
    return result


def _migration_evidence(
    path: Path,
    *,
    counted_tables: tuple[str, ...] | None = None,
) -> tuple[dict[str, int], dict[str, object]]:
    connection = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=5)
    try:
        names = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        selected = list(counted_tables) if counted_tables is not None else [
            name for name in MIGRATION_KEY_TABLES if name in names
        ]
        if counted_tables is not None and any(name not in names for name in selected):
            raise ActivationPackageError("migration lost a counted table")
        if counted_tables is None and not selected:
            if len(names) > 32:
                raise ActivationPackageError("migration store has no known key tables and exceeds fallback bounds")
            selected = names
        result: dict[str, int] = {}
        for name in selected:
            quoted = name.replace('"', '""')
            result[name] = int(connection.execute(f'SELECT COUNT(*) FROM "{quoted}"').fetchone()[0])
        schema_rows = [
            {
                "type": str(row[0]),
                "name": str(row[1]),
                "table": str(row[2]),
                "sqlSha256": _sha256(str(row[3] or "").encode("utf-8")),
            }
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        ]
        schema = {
            "objectCount": len(schema_rows),
            "digest": _sha256(_canonical(schema_rows)),
            "tableNames": names,
            "countedTables": selected,
        }
        return result, schema
    finally:
        connection.close()


def rehearse_store_migration(
    package_root: str | os.PathLike[str],
    *,
    source_store: str | os.PathLike[str],
    pages_per_step: int = 128,
    sleep_seconds: float = 0.02,
) -> dict[str, object]:
    """Create an online backup and migrate only a second copied canary."""

    if type(pages_per_step) is not int or not (
        pages_per_step == -1 or 1 <= pages_per_step <= 4096
    ):
        raise ActivationPackageError("backup pages_per_step is outside the bounded range")
    if (
        type(sleep_seconds) not in (int, float)
        or not math.isfinite(sleep_seconds)
        or not 0 <= sleep_seconds <= 1
    ):
        raise ActivationPackageError("backup sleep_seconds is outside the bounded range")
    source = Path(source_store)
    before = _validate_store_artifact(source, label="source SQLite store")
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{source}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            _validate_store_artifact(sidecar, label=f"source SQLite {suffix} sidecar")

    package = Path(package_root)
    migration = package / "private" / "migration"
    _ensure_directory(package)
    if migration.exists() or migration.is_symlink():
        raise ActivationPackageError("migration rehearsal destination already exists")
    _ensure_directory(migration)
    backup = migration / "rehearsal-source.sqlite3"
    migrated = migration / "rehearsal-migrated.sqlite3"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(backup, flags, 0o600)
    os.close(descriptor)
    source_connection = sqlite3.connect(_sqlite_uri(source), uri=True, timeout=5)
    target_connection = sqlite3.connect(backup, timeout=5)
    source_journal_mode = ""
    backup_started_unix_ns = 0
    backup_completed_unix_ns = 0
    try:
        journal_row = source_connection.execute("PRAGMA journal_mode").fetchone()
        source_journal_mode = str(journal_row[0]).lower() if journal_row else ""
        if source_journal_mode != "wal":
            raise ActivationPackageError("source SQLite store must remain in WAL mode")

        def progress(_status: int, remaining: int, _total: int) -> None:
            if remaining and sleep_seconds:
                time.sleep(float(sleep_seconds))

        backup_started_unix_ns = time.time_ns()
        source_connection.backup(
            target_connection,
            pages=pages_per_step,
            progress=progress,
            sleep=0,
        )
        backup_completed_unix_ns = time.time_ns()
        target_connection.commit()
    except BaseException:
        target_connection.close()
        source_connection.close()
        try:
            backup.unlink()
        except FileNotFoundError:
            pass
        raise
    else:
        target_connection.close()
        source_connection.close()
    os.chmod(backup, 0o600)
    after = source.lstat()
    stable_identity = lambda item: (item.st_dev, item.st_ino, item.st_uid, item.st_mode, item.st_nlink)
    if stable_identity(before) != stable_identity(after):
        raise ActivationPackageError("source SQLite identity changed during backup")

    backup_integrity = _integrity_check(backup)
    row_counts_before, schema_before = _migration_evidence(backup)
    backup_digest, backup_size = _hash_file(backup)
    _copy_store(backup, migrated)
    store = SQLiteStore(migrated)
    store.close()
    migrated_integrity = _integrity_check(migrated)
    row_counts_after, schema_after = _migration_evidence(
        migrated,
        counted_tables=tuple(str(name) for name in schema_before["countedTables"]),
    )
    for table, count in row_counts_before.items():
        if table in {"schema_migrations", "agent_schema_migrations"}:
            if row_counts_after.get(table, 0) < count:
                raise ActivationPackageError(f"schema history lost rows during migration: {table}")
        elif row_counts_after.get(table) != count:
            raise ActivationPackageError(f"migration changed retained row count: {table}")
    migrated_digest, migrated_size = _hash_file(migrated)
    report: dict[str, object] = {
        "schemaVersion": "overseer.activation-migration-rehearsal.v1",
        "status": "rehearsal_complete",
        "source": {
            "path": str(source),
            "device": before.st_dev,
            "inode": before.st_ino,
            "mode": "0600",
            "sizeAtStart": before.st_size,
            "journalMode": source_journal_mode,
        },
        "backup": {
            "path": str(backup),
            "sha256": backup_digest,
            "size": backup_size,
            "integrityCheck": backup_integrity,
        },
        "migrated": {
            "path": str(migrated),
            "sha256": migrated_digest,
            "size": migrated_size,
            "integrityCheck": migrated_integrity,
        },
        "rowCountsBefore": row_counts_before,
        "rowCountsAfter": row_counts_after,
        "schemaBefore": schema_before,
        "schemaAfter": schema_after,
        "rowCountPolicy": "fixed-key-tables-or-bounded-fallback",
        "backupBounds": {
            "pagesPerStep": pages_per_step,
            "sleepSeconds": sleep_seconds,
            "singleStep": pages_per_step == -1,
            "startedUnixNs": backup_started_unix_ns,
            "completedUnixNs": backup_completed_unix_ns,
        },
        "sourceMutationPerformed": False,
        "finalQuiescedBackupRequired": True,
    }
    _write_new(migration / "migration-report.json", _canonical(report) + b"\n", 0o600)
    return report


def _processes_with_open_inode(device: int, inode: int) -> tuple[int, ...]:
    """Return processes with the exact source inode open, without shell tools."""

    result: set[int] = set()
    proc = Path("/proc")
    try:
        process_directories = tuple(proc.iterdir())
    except OSError as error:
        raise ActivationPackageError("open-process preflight could not inspect /proc") from error
    for process in process_directories:
        if not process.name.isdecimal():
            continue
        descriptors = process / "fd"
        try:
            open_descriptors = tuple(descriptors.iterdir())
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for descriptor in open_descriptors:
            try:
                metadata = descriptor.stat()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if (metadata.st_dev, metadata.st_ino) == (device, inode):
                result.add(int(process.name))
                break
    return tuple(sorted(result))


def _artifact_identity(path: Path) -> tuple[int, ...] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_root_activation() -> None:
    if os.geteuid() != 0:
        raise ActivationPackageError("final store migration must run as root after explicit activation approval")


def _activation_root_identity() -> tuple[int, int]:
    return 0, 0


def _activation_parent_lock_mode() -> int:
    return 0o500


def _legacy_store_paths(source: Path) -> tuple[Path, ...]:
    return (source, Path(f"{source}-wal"), Path(f"{source}-shm"))


def restore_legacy_store_access(
    *,
    source_store: str | os.PathLike[str],
    expected_source_uid: int,
    expected_source_gid: int,
    expected_source_device: int,
    expected_source_inode: int,
    expected_parent_device: int,
    expected_parent_inode: int,
    expected_parent_mode: int,
) -> dict[str, object]:
    """Restore only the captured v1.1.5 store access needed for rollback."""

    for value, label in (
        (expected_source_uid, "source UID"),
        (expected_source_gid, "source GID"),
        (expected_source_device, "source device"),
        (expected_source_inode, "source inode"),
        (expected_parent_device, "source parent device"),
        (expected_parent_inode, "source parent inode"),
    ):
        if type(value) is not int or value < 0:
            raise ActivationPackageError(f"legacy store {label} is invalid")
    _require_root_activation()
    source = Path(source_store)
    parent = source.parent
    parent_metadata = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_dev != expected_parent_device
        or parent_metadata.st_ino != expected_parent_inode
    ):
        raise ActivationPackageError("legacy store parent is unsafe")
    restored: list[str] = []
    for path in _legacy_store_paths(source):
        if not path.exists() and not path.is_symlink():
            continue
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationPackageError("legacy store rollback artifact is unsafe")
        if path == source and (
            metadata.st_dev != expected_source_device
            or metadata.st_ino != expected_source_inode
        ):
            raise ActivationPackageError("legacy authority store identity drifted during rollback")
        os.chown(path, expected_source_uid, expected_source_gid)
        os.chmod(path, 0o600)
        restored.append(str(path))
    if str(source) not in restored:
        raise ActivationPackageError("legacy authority store is missing during rollback")
    if type(expected_parent_mode) is not int or expected_parent_mode not in {0o700, 0o750, 0o770, 0o775}:
        raise ActivationPackageError("legacy store parent rollback mode is invalid")
    os.chown(parent, expected_source_uid, expected_source_gid)
    os.chmod(parent, expected_parent_mode)
    return {
        "restored": True,
        "sourceStore": str(source),
        "restoredArtifacts": restored,
        "uid": expected_source_uid,
        "gid": expected_source_gid,
        "mode": "0600",
        "parentMode": f"{expected_parent_mode:04o}",
    }


def prepare_final_store_migration(
    *,
    source_store: str | os.PathLike[str],
    backup_store: str | os.PathLike[str],
    destination_store: str | os.PathLike[str],
    expected_source_device: int,
    expected_source_inode: int,
    expected_source_uid: int,
    expected_source_gid: int,
    expected_parent_device: int,
    expected_parent_inode: int,
    expected_parent_mode: int,
    destination_uid: int,
    destination_gid: int,
    pages_per_step: int = 128,
    sleep_seconds: float = 0.02,
) -> dict[str, object]:
    """Create the final backup and migrated store after all legacy writers stop.

    This is an activation-only primitive.  It never stops services and refuses
    to start when any process already has the exact source inode open.
    """

    for value, label in (
        (expected_source_device, "source device"),
        (expected_source_inode, "source inode"),
        (expected_source_uid, "source UID"),
        (expected_source_gid, "source GID"),
        (expected_parent_device, "source parent device"),
        (expected_parent_inode, "source parent inode"),
        (expected_parent_mode, "source parent mode"),
        (destination_uid, "destination UID"),
        (destination_gid, "destination GID"),
    ):
        if type(value) is not int or value < 0:
            raise ActivationPackageError(f"{label} is invalid")
    if type(pages_per_step) is not int or not 1 <= pages_per_step <= 4096:
        raise ActivationPackageError("backup pages_per_step is outside the bounded range")
    if (
        type(sleep_seconds) not in (int, float)
        or not math.isfinite(sleep_seconds)
        or not 0 <= sleep_seconds <= 1
    ):
        raise ActivationPackageError("backup sleep_seconds is outside the bounded range")
    if expected_parent_mode not in {0o700, 0o750, 0o770, 0o775}:
        raise ActivationPackageError("final migration source parent mode is unsupported")
    _require_root_activation()

    source = Path(source_store)
    backup = Path(backup_store)
    destination = Path(destination_store)
    source_metadata = _validate_store_artifact(
        source,
        label="final migration source SQLite store",
        expected_uid=expected_source_uid,
    )
    if (source_metadata.st_dev, source_metadata.st_ino) != (
        expected_source_device,
        expected_source_inode,
    ):
        raise ActivationPackageError("final migration source identity drifted")
    if source_metadata.st_gid != expected_source_gid:
        raise ActivationPackageError("final migration source group drifted")
    parent = source.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise ActivationPackageError("final migration source parent could not be inspected") from error
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_source_uid
        or parent_metadata.st_gid != expected_source_gid
        or parent_metadata.st_dev != expected_parent_device
        or parent_metadata.st_ino != expected_parent_inode
        or stat.S_IMODE(parent_metadata.st_mode) != expected_parent_mode
    ):
        raise ActivationPackageError("final migration source parent is not the approved private directory")
    sidecars = tuple(Path(f"{source}{suffix}") for suffix in ("-wal", "-shm"))
    sidecar_before = {str(path): _artifact_identity(path) for path in sidecars}
    for path in sidecars:
        if path.exists() or path.is_symlink():
            _validate_store_artifact(
                path,
                label="final migration SQLite sidecar",
                expected_uid=expected_source_uid,
            )
            if path.lstat().st_gid != expected_source_gid:
                raise ActivationPackageError("final migration SQLite sidecar group drifted")
    for target, label in ((backup, "final backup"), (destination, "final migrated store")):
        if target.exists() or target.is_symlink():
            raise ActivationPackageError(f"{label} destination already exists")
        if target.parent.is_symlink() or not target.parent.is_dir():
            raise ActivationPackageError(f"{label} parent directory is unsafe")

    root_uid, root_gid = _activation_root_identity()
    lock_acquired = False
    try:
        os.chown(parent, root_uid, root_gid)
        os.chmod(parent, _activation_parent_lock_mode())
        for path in _legacy_store_paths(source):
            if path.exists() or path.is_symlink():
                metadata = path.lstat()
                if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ActivationPackageError("legacy store changed while acquiring the quiescence lock")
                os.chown(path, root_uid, root_gid)
                os.chmod(path, 0o600)
        lock_acquired = True
        if _processes_with_open_inode(source_metadata.st_dev, source_metadata.st_ino):
            raise ActivationPackageError("final migration source still has an open process")

        wal = sidecars[0]
        checkpoint = "not_required"
        if wal.exists() and wal.stat().st_size:
            checkpoint_connection = sqlite3.connect(source, timeout=5)
            try:
                row = checkpoint_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            finally:
                checkpoint_connection.close()
            if row is None or int(row[0]) != 0:
                raise ActivationPackageError("final migration WAL checkpoint did not quiesce")
            checkpoint = "truncate_complete"
        for path in _legacy_store_paths(source):
            if path.exists():
                os.chmod(path, 0o400)
        locked_source = source.lstat()
        source_digest_before = _stream_hash_regular(
            source,
            label="locked legacy authority store",
        )

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(backup, flags, 0o600)
        os.close(descriptor)
        source_connection = sqlite3.connect(_sqlite_uri(source), uri=True, timeout=5)
        target_connection = sqlite3.connect(backup, timeout=5)
        try:
            def progress(_status: int, remaining: int, _total: int) -> None:
                if remaining and sleep_seconds:
                    time.sleep(float(sleep_seconds))

            source_connection.backup(
                target_connection,
                pages=pages_per_step,
                progress=progress,
                sleep=0,
            )
            target_connection.commit()
        finally:
            target_connection.close()
            source_connection.close()
        os.chmod(backup, 0o600)
        source_digest_after = _stream_hash_regular(
            source,
            label="locked legacy authority store",
        )
        if source_digest_before != source_digest_after:
            raise ActivationPackageError("final migration source content changed during backup")
        if _processes_with_open_inode(source_metadata.st_dev, source_metadata.st_ino):
            raise ActivationPackageError("final migration source acquired another open process")
        sidecar_after = {str(path): _artifact_identity(path) for path in sidecars}

        backup_integrity = _integrity_check(backup)
        before_counts, schema_before = _migration_evidence(backup)
        backup_digest, backup_size = _hash_file(backup)
        _copy_store(backup, destination)
        migrated_store = SQLiteStore(destination)
        migrated_store.close()
        migrated_integrity = _integrity_check(destination)
        after_counts, schema_after = _migration_evidence(
            destination,
            counted_tables=tuple(str(name) for name in schema_before["countedTables"]),
        )
        for table, count in before_counts.items():
            if table in {"schema_migrations", "agent_schema_migrations"}:
                if after_counts.get(table, 0) < count:
                    raise ActivationPackageError(f"schema history lost rows during final migration: {table}")
            elif after_counts.get(table) != count:
                raise ActivationPackageError(f"final migration changed retained row count: {table}")
        migrated_digest, migrated_size = _hash_file(destination)
        os.chown(destination, destination_uid, destination_gid)
        os.chmod(destination, 0o600)
        final_metadata = destination.lstat()
        if (
            final_metadata.st_uid != destination_uid
            or final_metadata.st_gid != destination_gid
            or stat.S_IMODE(final_metadata.st_mode) != 0o600
        ):
            raise ActivationPackageError("final migrated store ownership is invalid")
        report: dict[str, object] = {
            "schemaVersion": "overseer.activation-final-migration.v1",
            "status": "final_migration_complete",
            "source": {
                "path": str(source.resolve()),
                "device": source_metadata.st_dev,
                "inode": source_metadata.st_ino,
                "originalUid": source_metadata.st_uid,
                "originalGid": source_metadata.st_gid,
                "retainedUid": locked_source.st_uid,
                "retainedGid": locked_source.st_gid,
                "retainedMode": "0400",
                "sha256": source_digest_after["sha256"],
                "walCheckpoint": checkpoint,
            },
            "backup": {
                "path": str(backup.resolve()),
                "sha256": backup_digest,
                "size": backup_size,
                "integrityCheck": backup_integrity,
            },
            "migrated": {
                "path": str(destination.resolve()),
                "sha256BeforeOwnershipChange": migrated_digest,
                "size": migrated_size,
                "uid": destination_uid,
                "gid": destination_gid,
                "mode": "0600",
                "integrityCheck": migrated_integrity,
            },
            "rowCountsBefore": before_counts,
            "rowCountsAfter": after_counts,
            "schemaBefore": schema_before,
            "schemaAfter": schema_after,
            "quiescenceLock": "parent-and-store-write-access-revoked",
            "retainedParentLock": {
                "uid": root_uid,
                "gid": expected_source_gid,
                "mode": "0555",
                "restoredOnlyByRollbackOrFailure": True,
            },
            "openProcessPreflight": "clear",
            "sidecarsAtStart": sidecar_before,
            "sidecarsAfterBackup": sidecar_after,
        }
        report_path = backup.with_suffix(f"{backup.suffix}.report.json")
        _write_new(report_path, _canonical(report) + b"\n", 0o600)
        os.chown(parent, root_uid, expected_source_gid)
        os.chmod(parent, 0o555)
        return report
    except BaseException:
        if lock_acquired:
            try:
                restore_legacy_store_access(
                    source_store=source,
                    expected_source_uid=expected_source_uid,
                    expected_source_gid=expected_source_gid,
                    expected_source_device=expected_source_device,
                    expected_source_inode=expected_source_inode,
                    expected_parent_device=expected_parent_device,
                    expected_parent_inode=expected_parent_inode,
                    expected_parent_mode=expected_parent_mode,
                )
            except BaseException as restore_error:
                raise ActivationPackageError(
                    "final migration failed and legacy store access restoration also failed"
                ) from restore_error
        for target in (destination, backup):
            try:
                target.unlink()
            except FileNotFoundError:
                pass
        raise


def stage_release_payload(
    manifest: Mapping[str, object],
    *,
    checkout: str | os.PathLike[str],
    dependency_root: str | os.PathLike[str],
    stdlib_root: str | os.PathLike[str],
    package_root: str | os.PathLike[str],
) -> Path:
    """Copy every manifest-bound byte into a new owner-only package payload."""

    files = manifest.get("files")
    release_root = manifest.get("releaseRoot")
    if manifest.get("schemaVersion") != RELEASE_SCHEMA or not isinstance(files, list) or not isinstance(release_root, str):
        raise ActivationPackageError("release manifest is invalid")
    package = Path(package_root)
    _ensure_directory(package)
    target = package / "public" / "release" / Path(release_root).name
    if target.exists() or target.is_symlink():
        raise ActivationPackageError("staged release destination already exists")
    _ensure_directory(target)
    roots = {
        "checkout": Path(checkout).resolve(),
        "dependency": Path(dependency_root).resolve(),
        "stdlib": Path(stdlib_root).resolve(),
    }
    for item in files:
        if not isinstance(item, Mapping) or item.get("sourceKind") not in roots:
            raise ActivationPackageError("release file manifest is invalid")
        source_path = str(item.get("sourcePath", ""))
        release_path = str(item.get("releasePath", ""))
        if item["sourceKind"] == "stdlib":
            content, _metadata, resolved = _runtime_read(roots["stdlib"], source_path)
            if resolved != item.get("sourceResolvedPath"):
                raise ActivationPackageError(f"standard-library source drifted after manifest: {source_path}")
        else:
            content, _metadata = _stable_read(roots[str(item["sourceKind"])] / _safe_relative(source_path))
        if (
            len(content) != item.get("size")
            or _sha256(content) != item.get("sha256")
            or item.get("mode") not in {0o444, 0o555}
        ):
            raise ActivationPackageError(f"release source drifted after manifest: {source_path}")
        _write_new(target / _safe_relative(release_path), content, int(item["mode"]))
    root_python = manifest.get("rootPython")
    if not isinstance(root_python, Mapping):
        raise ActivationPackageError("release Python manifest is invalid")
    python_path = root_python.get("path")
    python_release_path = root_python.get("releasePath")
    if not isinstance(python_path, str) or not isinstance(python_release_path, str):
        raise ActivationPackageError("release Python manifest is invalid")
    python_content, _python_metadata = _stable_read(Path(python_path))
    if len(python_content) != root_python.get("size") or _sha256(python_content) != root_python.get("sha256"):
        raise ActivationPackageError("root Python drifted after manifest")
    _write_new(target / _safe_relative(python_release_path), python_content, 0o555)
    sqlite_runtime = manifest.get("sqliteRuntime")
    if not isinstance(sqlite_runtime, Mapping):
        raise ActivationPackageError("release SQLite runtime manifest is invalid")
    sqlite_path = sqlite_runtime.get("path")
    sqlite_release_path = sqlite_runtime.get("releasePath")
    if not isinstance(sqlite_path, str) or not isinstance(sqlite_release_path, str):
        raise ActivationPackageError("release SQLite runtime manifest is invalid")
    if sqlite_runtime.get("stagedInputPackage") != str(package.absolute()):
        raise ActivationPackageError("release SQLite runtime is bound to a different package")
    sqlite_content, sqlite_metadata = _stable_read(Path(sqlite_path))
    if (
        len(sqlite_content) != sqlite_runtime.get("size")
        or _sha256(sqlite_content) != APPROVED_SQLITE_BINARY_SHA256
        or sqlite_runtime.get("sha256") != APPROVED_SQLITE_BINARY_SHA256
        or sqlite_metadata.st_dev != sqlite_runtime.get("device")
        or sqlite_metadata.st_ino != sqlite_runtime.get("inode")
        or sqlite_runtime.get("version") != APPROVED_SQLITE_VERSION
        or sqlite_runtime.get("sourceId") != APPROVED_SQLITE_SOURCE_ID
        or sqlite_runtime.get("walResetFixAttested") is not True
    ):
        raise ActivationPackageError("approved SQLite runtime drifted after manifest")
    _write_new(target / _safe_relative(sqlite_release_path), sqlite_content, 0o555)
    _write_new(target / "release-manifest.json", _canonical(dict(manifest)) + b"\n", 0o444)
    return target


def render_systemd_units(
    manifest: Mapping[str, object],
    *,
    templates_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    god_uid: int,
    overseer_uid: int,
    python_path: str | os.PathLike[str],
) -> dict[str, Path]:
    """Render the closed systemd contract into a new package directory."""

    release_root = manifest.get("releaseRoot")
    if not isinstance(release_root, str) or not release_root.startswith("/opt/overseer/releases/"):
        raise ActivationPackageError("release root is invalid")
    for value, label in ((god_uid, "god UID"), (overseer_uid, "overseer UID")):
        if type(value) is not int or value < 1:
            raise ActivationPackageError(f"{label} is invalid")
    _validate_principal_binding(
        god_uid=god_uid,
        overseer_uid=overseer_uid,
        overseer_gid=overseer_uid,
    )
    templates = Path(templates_root)
    output = Path(output_root)
    if output.exists() or output.is_symlink():
        raise ActivationPackageError("rendered unit destination already exists")
    _ensure_directory(output)
    root_python = manifest.get("rootPython")
    if not isinstance(root_python, Mapping):
        raise ActivationPackageError("release Python manifest is invalid")
    source_python = root_python.get("path")
    release_python = root_python.get("releasePath")
    if source_python != str(Path(python_path)) or not isinstance(release_python, str):
        raise ActivationPackageError("rendered interpreter does not match the release manifest")
    replacements = {
        "@OVERSEER_RELEASE@": release_root,
        "@OVERSEER_PYTHON@": str(PurePosixPath(release_root) / _safe_relative(release_python)),
        "@GOD_UID@": str(god_uid),
        "@OVERSEER_UID@": str(overseer_uid),
    }
    result: dict[str, Path] = {}
    for source_name, target_name in _SYSTEMD_TEMPLATES.items():
        content, _metadata = _stable_read(templates / source_name)
        text = content.decode("utf-8", "strict")
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        if "@OVERSEER_" in text or "@GOD_UID@" in text:
            raise ActivationPackageError(f"rendered unit has an unresolved placeholder: {source_name}")
        target = output / target_name
        _write_new(target, text.encode("utf-8"), 0o644)
        result[target_name] = target
    allowlist_source = templates.parent / "config" / "admin-executor-allowlist.json"
    allowlist, _metadata = _stable_read(allowlist_source)
    try:
        parsed_allowlist = json.loads(allowlist)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("admin executor allowlist is not valid JSON") from error
    expected_allowlist = {
        "schemaVersion": "overseer.admin-executor-allowlist.v1",
        "allowed": [
            {
                "operation": "restart-system-unit",
                "unit": "overseer-approval-smoke.service",
            }
        ],
    }
    if parsed_allowlist != expected_allowlist:
        raise ActivationPackageError("admin executor allowlist exceeds the v1.1.6 smoke boundary")
    allowlist_target = output.parent / "config" / "admin-executor-allowlist.json"
    _write_new(allowlist_target, _canonical(parsed_allowlist) + b"\n", 0o644)
    return result


def _stream_hash_regular(path: Path, *, label: str) -> dict[str, object]:
    """Hash one regular file while binding its complete descriptor identity."""

    try:
        before = path.lstat()
    except OSError as error:
        raise ActivationPackageError(f"{label} could not be inspected") from error
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise ActivationPackageError(f"{label} must be a regular file, not a symlink")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
        ):
            raise ActivationPackageError(f"{label} changed while opening")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    lexical_after = path.lstat()
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    if identity(before) != identity(after) or identity(before) != identity(lexical_after):
        raise ActivationPackageError(f"{label} changed while hashing")
    if size != before.st_size:
        raise ActivationPackageError(f"{label} was not read completely")
    return {
        "sha256": digest.hexdigest(),
        "size": size,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
        "uid": before.st_uid,
        "gid": before.st_gid,
        "links": before.st_nlink,
    }


def _tree_inventory(root: Path, *, label: str) -> list[dict[str, object]]:
    if root.is_symlink() or not root.is_dir():
        raise ActivationPackageError(f"{label} must be a directory, not a symlink")
    result: list[dict[str, object]] = []
    for directory, directories, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in directories:
            path = base / name
            if path.is_symlink():
                raise ActivationPackageError(f"{label} contains a symlink")
        for name in files:
            path = base / name
            relative = _safe_relative(path.relative_to(root).as_posix())
            result.append(
                {
                    "relativePath": relative,
                    **_stream_hash_regular(path, label=f"{label} file"),
                }
            )
    result.sort(key=lambda item: str(item["relativePath"]))
    return result


def _rollback_input(label: str, path: Path) -> dict[str, object]:
    if _safe_relative(label) != label or "/" in label:
        raise ActivationPackageError("rollback input label is unsafe")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ActivationPackageError(f"rollback input is unavailable: {label}") from error
    if path.is_symlink():
        raise ActivationPackageError(f"rollback input is a symlink: {label}")
    if stat.S_ISREG(metadata.st_mode):
        return {
            "label": label,
            "path": str(path.resolve()),
            "kind": "file",
            **_stream_hash_regular(path, label=f"rollback input {label}"),
        }
    if stat.S_ISDIR(metadata.st_mode):
        entries = _tree_inventory(path, label=f"rollback input {label}")
        return {
            "label": label,
            "path": str(path.resolve()),
            "kind": "directory",
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "entries": entries,
            "treeDigest": _sha256(_canonical(entries)),
        }
    raise ActivationPackageError(f"rollback input has an unsupported type: {label}")


def _stage_rollback_inputs(
    package: Path,
    items: list[dict[str, object]],
) -> None:
    staging_root = package / "private" / "rollback-inputs"
    _ensure_directory(staging_root)
    for item in items:
        label = str(item["label"])
        source = Path(str(item["path"]))
        relative_root = _safe_relative(label)
        kind = item.get("kind")
        if kind == "file":
            raw, metadata = _stable_read(source)
            if len(raw) != item.get("size") or _sha256(raw) != item.get("sha256"):
                raise ActivationPackageError(f"rollback input drifted while staging: {label}")
            staged_mode = 0o500 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o400
            bundle_mode = 0o550 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o440
            staged_relative = f"{relative_root}/artifact"
            _write_new(staging_root / staged_relative, raw, staged_mode)
            item["bundle"] = {
                "relativeRoot": relative_root,
                "files": [{"relativePath": "artifact", "mode": f"{bundle_mode:04o}"}],
            }
            continue
        if kind != "directory" or not isinstance(item.get("entries"), list):
            raise ActivationPackageError("rollback bundle input is invalid")
        bundled_files: list[dict[str, object]] = []
        for entry in item["entries"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("relativePath"), str):
                raise ActivationPackageError("rollback bundle directory entry is invalid")
            relative = _safe_relative(str(entry["relativePath"]))
            raw, metadata = _stable_read(source / relative)
            if len(raw) != entry.get("size") or _sha256(raw) != entry.get("sha256"):
                raise ActivationPackageError(f"rollback input drifted while staging: {label}/{relative}")
            staged_mode = 0o500 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o400
            bundle_mode = 0o550 if stat.S_IMODE(metadata.st_mode) & 0o111 else 0o440
            _write_new(staging_root / relative_root / relative, raw, staged_mode)
            bundled_files.append({"relativePath": relative, "mode": f"{bundle_mode:04o}"})
        item["bundle"] = {
            "relativeRoot": relative_root,
            "files": bundled_files,
        }


def _rollback_bundle_install_commands(
    package: Path,
    rollback_items: list[dict[str, object]],
    bundle_root: Path,
) -> list[list[str]]:
    staging_root = package / "private" / "rollback-inputs"
    directories = {bundle_root}
    file_commands: list[list[str]] = []
    for item in rollback_items:
        bundle = item.get("bundle")
        if not isinstance(bundle, Mapping) or not isinstance(bundle.get("relativeRoot"), str):
            raise ActivationPackageError("rollback bundle manifest is invalid")
        relative_root = Path(_safe_relative(str(bundle["relativeRoot"])))
        files = bundle.get("files")
        if not isinstance(files, list):
            raise ActivationPackageError("rollback bundle file manifest is invalid")
        for entry in files:
            if not isinstance(entry, Mapping):
                raise ActivationPackageError("rollback bundle file entry is invalid")
            relative = Path(_safe_relative(str(entry.get("relativePath", ""))))
            mode = str(entry.get("mode", ""))
            if mode not in {"0440", "0550"}:
                raise ActivationPackageError("rollback bundle file mode is invalid")
            target = bundle_root / relative_root / relative
            directories.update(target.parents)
            file_commands.append(
                [
                    "/usr/bin/install",
                    "-o",
                    "root",
                    "-g",
                    "god",
                    "-m",
                    mode,
                    str(staging_root / relative_root / relative),
                    str(target),
                ]
            )
    selected = sorted(
        (path for path in directories if str(path).startswith(str(bundle_root))),
        key=lambda path: (len(path.parts), str(path)),
    )
    directory_commands = [
        ["/usr/bin/install", "-d", "-o", "root", "-g", "god", "-m", "0750", str(path)]
        for path in selected
    ]
    freeze_commands = [["/usr/bin/chmod", "0550", str(path)] for path in reversed(selected)]
    return [*directory_commands, *file_commands, *freeze_commands]


def verify_rollback_bundle(
    *,
    bundle_root: str | os.PathLike[str],
    rollback_manifest: str | os.PathLike[str],
) -> dict[str, object]:
    """Verify the immutable root-owned rollback bundle used for execution."""

    _require_root_activation()
    root = Path(bundle_root)
    manifest_path = Path(rollback_manifest)
    root_uid, root_gid = _activation_root_identity()
    bundle_gid = pwd.getpwnam("god").pw_gid
    root_metadata = root.lstat()
    if (
        root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != root_uid
        or root_metadata.st_gid != bundle_gid
        or stat.S_IMODE(root_metadata.st_mode) != 0o550
    ):
        raise ActivationPackageError("root rollback bundle directory is invalid")
    manifest_raw, manifest_metadata = _stable_read(manifest_path)
    if (
        manifest_metadata.st_uid != root_uid
        or manifest_metadata.st_gid != root_gid
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o644
    ):
        raise ActivationPackageError("root rollback manifest metadata is invalid")
    try:
        document = json.loads(manifest_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("root rollback manifest is invalid") from error
    if not isinstance(document, dict):
        raise ActivationPackageError("root rollback manifest schema is invalid")
    items = document.get("inputs")
    if (
        document.get("schemaVersion") != ROLLBACK_MANIFEST_SCHEMA
        or document.get("preserveInputs") is not True
        or document.get("restoreMigratedDatabaseToLegacyAuthority") is not False
        or not isinstance(items, list)
    ):
        raise ActivationPackageError("root rollback manifest schema is invalid")
    expected_paths: set[str] = set()
    verified_files = 0
    for item in items:
        bundle = item.get("bundle") if isinstance(item, dict) else None
        if not isinstance(bundle, dict) or not isinstance(bundle.get("relativeRoot"), str):
            raise ActivationPackageError("root rollback bundle binding is invalid")
        relative_root = _safe_relative(bundle["relativeRoot"])
        expected_by_relative: dict[str, Mapping[str, object]] = {}
        if item.get("kind") == "file":
            expected_by_relative["artifact"] = item
        elif item.get("kind") == "directory" and isinstance(item.get("entries"), list):
            expected_by_relative = {
                str(entry["relativePath"]): entry
                for entry in item["entries"]
                if isinstance(entry, Mapping) and isinstance(entry.get("relativePath"), str)
            }
        else:
            raise ActivationPackageError("root rollback bundle input kind is invalid")
        files = bundle.get("files")
        if not isinstance(files, list) or len(files) != len(expected_by_relative):
            raise ActivationPackageError("root rollback bundle file count is invalid")
        for bundled in files:
            if not isinstance(bundled, Mapping) or not isinstance(bundled.get("relativePath"), str):
                raise ActivationPackageError("root rollback bundle file binding is invalid")
            relative = _safe_relative(str(bundled["relativePath"]))
            expected = expected_by_relative.get(relative)
            if expected is None:
                raise ActivationPackageError("root rollback bundle has an unexpected file")
            path = root / relative_root / relative
            observed = _stream_hash_regular(path, label="root rollback bundle artifact")
            if (
                observed["sha256"] != expected.get("sha256")
                or observed["size"] != expected.get("size")
                or observed["uid"] != root_uid
                or observed["gid"] != bundle_gid
                or observed["mode"] != bundled.get("mode")
                or observed["links"] != 1
            ):
                raise ActivationPackageError("root rollback bundle artifact drift detected")
            expected_paths.add((Path(relative_root) / relative).as_posix())
            verified_files += 1
    observed_paths: set[str] = set()
    for path in root.rglob("*"):
        metadata = path.lstat()
        if path.is_symlink():
            raise ActivationPackageError("root rollback bundle contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            if (
                metadata.st_uid != root_uid
                or metadata.st_gid != bundle_gid
                or stat.S_IMODE(metadata.st_mode) != 0o550
            ):
                raise ActivationPackageError("root rollback bundle directory metadata drifted")
        elif stat.S_ISREG(metadata.st_mode):
            observed_paths.add(path.relative_to(root).as_posix())
        else:
            raise ActivationPackageError("root rollback bundle contains an unsupported artifact")
    if observed_paths != expected_paths:
        raise ActivationPackageError("root rollback bundle contains unexpected or missing artifacts")
    return {
        "verified": True,
        "fileCount": verified_files,
        "rollbackManifestSha256": _sha256(manifest_raw),
    }


def verify_rollback_inputs(package_root: str | os.PathLike[str]) -> dict[str, object]:
    """Re-hash every captured rollback input and fail closed on any drift."""

    package = Path(package_root)
    try:
        package_owner = package.lstat().st_uid
    except OSError as error:
        raise ActivationPackageError("activation package root is unavailable") from error
    manifest_path = package / "public" / "rollback-manifest.json"
    try:
        raw, metadata = _stable_read(manifest_path)
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("rollback manifest is invalid") from error
    if metadata.st_uid != package_owner or stat.S_IMODE(metadata.st_mode) != 0o644:
        raise ActivationPackageError("rollback manifest metadata is invalid")
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion") != ROLLBACK_MANIFEST_SCHEMA
        or document.get("preserveInputs") is not True
        or document.get("restoreMigratedDatabaseToLegacyAuthority") is not False
        or not isinstance(document.get("inputs"), list)
    ):
        raise ActivationPackageError("rollback manifest schema is invalid")
    observed: list[dict[str, object]] = []
    expected_inputs: list[dict[str, object]] = []
    for item in document["inputs"]:
        if not isinstance(item, dict) or not isinstance(item.get("label"), str) or not isinstance(item.get("path"), str):
            raise ActivationPackageError("rollback manifest input is invalid")
        observed.append(_rollback_input(item["label"], Path(item["path"])))
        expected_inputs.append({key: value for key, value in item.items() if key != "bundle"})
    if observed != expected_inputs:
        raise ActivationPackageError("rollback input drift detected")
    return {
        "verified": True,
        "inputCount": len(observed),
        "rollbackManifestSha256": _sha256(raw),
    }


def _bind_rollback_transient_identity(command: list[str]) -> list[str]:
    """Bind one root-manager transient unit to every sealed launch argument."""

    if command.count("--") != 1 or command[0] != "/usr/bin/systemd-run":
        raise ActivationPackageError("rollback transient command is invalid")
    if any(ROLLBACK_TRANSIENT_MARKER in value for value in command):
        raise ActivationPackageError("rollback transient command is already identity-bound")
    separator = command.index("--")
    digest = _sha256(_canonical(command))
    marker = f"{ROLLBACK_TRANSIENT_MARKER}{digest}"
    return [
        *command[:separator],
        f"--property=Description={marker}",
        f"--setenv=OVERSEER_ROLLBACK_TRANSIENT_ID={digest}",
        *command[separator:],
    ]


def _package_file_inventory(package: Path) -> list[dict[str, object]]:
    if package.is_symlink() or not package.is_dir():
        raise ActivationPackageError("activation package root is unsafe")
    package_owner = package.lstat().st_uid
    manifest_relative = "public/package-manifest.json"
    result: list[dict[str, object]] = []
    for directory, directories, files in os.walk(package, followlinks=False):
        base = Path(directory)
        for name in directories:
            child = base / name
            if child.is_symlink():
                raise ActivationPackageError("activation package contains a directory symlink")
        for name in files:
            path = base / name
            relative = _safe_relative(path.relative_to(package).as_posix())
            if relative == manifest_relative:
                continue
            details = _stream_hash_regular(path, label="activation package artifact")
            if details["uid"] != package_owner:
                raise ActivationPackageError("activation package artifact has an unexpected owner")
            if details["links"] != 1:
                raise ActivationPackageError("activation package artifact must be single-link")
            result.append(
                {
                    "path": relative,
                    "sha256": details["sha256"],
                    "size": details["size"],
                    "mode": details["mode"],
                    "links": details["links"],
                    "ownerBinding": "package-root-owner",
                }
            )
    result.sort(key=lambda item: str(item["path"]))
    if not result:
        raise ActivationPackageError("activation package is empty")
    return result


def _package_directory_inventory(package: Path) -> list[dict[str, object]]:
    package_owner = package.lstat().st_uid
    result: list[dict[str, object]] = []
    for directory, directories, _files in os.walk(package, followlinks=False):
        path = Path(directory)
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != package_owner
            or mode not in {0o500, 0o700}
        ):
            raise ActivationPackageError("activation package directory ownership or mode is invalid")
        for name in directories:
            if (path / name).is_symlink():
                raise ActivationPackageError("activation package contains a directory symlink")
        relative = "." if path == package else _safe_relative(path.relative_to(package).as_posix())
        result.append(
            {
                "path": relative,
                "mode": f"{mode:04o}",
                "ownerBinding": "package-root-owner",
            }
        )
    result.sort(key=lambda item: str(item["path"]))
    return result


def _release_install_commands(package: Path, manifest: Mapping[str, object]) -> list[list[str]]:
    release_root = Path(str(manifest["releaseRoot"]))
    staged_root = package / "public" / "release" / release_root.name
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ActivationPackageError("release file manifest is invalid")
    directories = {release_root}
    commands: list[list[str]] = []
    for item in files:
        if not isinstance(item, Mapping):
            raise ActivationPackageError("release file manifest is invalid")
        relative = Path(_safe_relative(str(item.get("releasePath", ""))))
        target = release_root / relative
        directories.update(target.parents)
        mode = item.get("mode")
        if mode not in {0o444, 0o555}:
            raise ActivationPackageError("release file mode is invalid")
        commands.append(
            [
                "/usr/bin/install",
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                f"{int(mode):04o}",
                str(staged_root / relative),
                str(target),
            ]
        )
    root_python = manifest.get("rootPython")
    if not isinstance(root_python, Mapping) or not isinstance(root_python.get("releasePath"), str):
        raise ActivationPackageError("release Python manifest is invalid")
    python_relative = Path(_safe_relative(str(root_python["releasePath"])))
    python_target = release_root / python_relative
    directories.update(python_target.parents)
    commands.append(
        [
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0555",
            str(staged_root / python_relative),
            str(python_target),
        ]
    )
    sqlite_runtime = manifest.get("sqliteRuntime")
    if not isinstance(sqlite_runtime, Mapping) or not isinstance(sqlite_runtime.get("releasePath"), str):
        raise ActivationPackageError("release SQLite runtime manifest is invalid")
    sqlite_relative = Path(_safe_relative(str(sqlite_runtime["releasePath"])))
    sqlite_target = release_root / sqlite_relative
    directories.update(sqlite_target.parents)
    commands.append(
        [
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0555",
            str(staged_root / sqlite_relative),
            str(sqlite_target),
        ]
    )
    selected_directories = sorted(
        (directory for directory in directories if str(directory).startswith(str(release_root))),
        key=lambda path: (len(path.parts), str(path)),
    )
    directory_commands = [
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", str(path)]
        for path in selected_directories
    ]
    manifest_command = [
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0444",
        str(staged_root / "release-manifest.json"),
        str(release_root / "release-manifest.json"),
    ]
    freeze_commands = [
        ["/usr/bin/chmod", "0555", str(path)]
        for path in reversed(selected_directories)
    ]
    return [*directory_commands, *commands, manifest_command, *freeze_commands]


def render_activation_contract(
    package_root: str | os.PathLike[str],
    release_manifest: Mapping[str, object],
    *,
    source_store: str | os.PathLike[str],
    overseer_uid: int,
    overseer_gid: int,
    rollback_inputs: Mapping[str, str | os.PathLike[str]],
) -> dict[str, object]:
    """Render, but never execute, exact root activation and rollback argv."""

    if type(overseer_uid) is not int or type(overseer_gid) is not int:
        raise ActivationPackageError("dedicated principal UID and GID must be integers")
    if overseer_uid < 1 or overseer_gid < 1:
        raise ActivationPackageError("dedicated principal UID and GID must be positive")
    if release_manifest.get("schemaVersion") != RELEASE_SCHEMA:
        raise ActivationPackageError("release manifest is invalid")
    package = Path(package_root).resolve()
    source = Path(source_store)
    source_metadata = _validate_store_artifact(source, label="activation source SQLite store")
    try:
        god = pwd.getpwnam("god")
    except KeyError as error:
        raise ActivationPackageError("approved god account is unavailable") from error
    _validate_principal_binding(
        god_uid=god.pw_uid,
        overseer_uid=overseer_uid,
        overseer_gid=overseer_gid,
    )
    if (source_metadata.st_uid, source_metadata.st_gid) != (god.pw_uid, god.pw_gid):
        raise ActivationPackageError("activation source store is not owned by the approved god account")
    source_parent = source.parent
    parent_metadata = source_parent.lstat()
    parent_mode = stat.S_IMODE(parent_metadata.st_mode)
    if (
        source_parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or (parent_metadata.st_uid, parent_metadata.st_gid) != (god.pw_uid, god.pw_gid)
        or parent_mode not in {0o700, 0o750, 0o770, 0o775}
    ):
        raise ActivationPackageError("activation source parent identity or mode is unsupported")
    if not rollback_inputs:
        raise ActivationPackageError("rollback inputs are required")
    rollback_items = [
        _rollback_input(label, Path(path)) for label, path in sorted(rollback_inputs.items())
    ]
    rollback_release = next(
        (item for item in rollback_items if item.get("label") == "v1.1.5-release"),
        None,
    )
    if rollback_release is None or rollback_release.get("kind") != "directory":
        raise ActivationPackageError("root rollback execution requires the v1.1.5-release directory input")
    _stage_rollback_inputs(package, rollback_items)
    rollback_manifest = {
        "schemaVersion": ROLLBACK_MANIFEST_SCHEMA,
        "preserveInputs": True,
        "restoreMigratedDatabaseToLegacyAuthority": False,
        "inputs": rollback_items,
    }
    rollback_path = package / "public" / "rollback-manifest.json"
    _write_new(rollback_path, _canonical(rollback_manifest) + b"\n", 0o644)

    execution_package = APPROVED_EXECUTION_PACKAGE.absolute()
    public = execution_package / "public"
    private = execution_package / "private"
    release_root = str(release_manifest["releaseRoot"])
    manifest_digest = release_manifest.get("manifestDigest")
    if not isinstance(manifest_digest, str) or len(manifest_digest) != 64 or set(manifest_digest) - _HEX:
        raise ActivationPackageError("release manifest digest is invalid")
    rollback_bundle_root = Path(f"/opt/overseer/rollback/{manifest_digest}")
    install_commands: list[list[str]] = [
        ["/usr/sbin/groupadd", "--system", "--gid", str(overseer_gid), "overseer"],
        [
            "/usr/sbin/useradd",
            "--system",
            "--uid",
            str(overseer_uid),
            "--gid",
            str(overseer_gid),
            "--home-dir",
            "/var/lib/overseer",
            "--shell",
            "/usr/sbin/nologin",
            "overseer",
        ],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/opt/overseer"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/opt/overseer/releases"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/opt/overseer/rollback"],
        ["/usr/bin/install", "-d", "-o", "overseer", "-g", "overseer", "-m", "0700", "/var/lib/overseer"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", "/var/lib/overseer-executor"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", "/var/lib/overseer-executor/activation-package"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", "/var/lib/overseer-executor/activation-package/public"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "overseer", "-m", "0750", "/etc/overseer"],
        *_release_install_commands(execution_package, release_manifest),
        *_rollback_bundle_install_commands(execution_package, rollback_items, rollback_bundle_root),
        [
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
            str(public / "rollback-manifest.json"),
            "/var/lib/overseer-executor/activation-package/public/rollback-manifest.json",
        ],
    ]
    config_installs = (
        (private / "credentials" / "admin-approval-verifier.json", "/etc/overseer/admin-approval-verifier.json", "overseer", "overseer", "0600"),
        (private / "credentials" / "roadex-fixture-approval-verifier.json", "/etc/overseer/roadex-fixture-approval-verifier.json", "overseer", "overseer", "0600"),
        (private / "credentials" / "api-token", "/etc/overseer/api-token", "root", "root", "0600"),
        (private / "credentials" / "psychlo-peer-secret", "/etc/overseer/psychlo-peer-secret", "root", "root", "0600"),
        (private / "credentials" / "roadex-project-human-thread-secret", "/etc/overseer/roadex-project-human-thread-secret", "root", "root", "0600"),
        (public / "config" / "psychlo-project-bindings.json", "/etc/overseer/psychlo-project-bindings.json", "root", "root", "0644"),
        (public / "config" / "admin-executor-public-key", "/etc/overseer/admin-executor-public-key", "root", "root", "0644"),
        (public / "config" / "admin-executor-allowlist.json", "/etc/overseer/admin-executor-allowlist.json", "root", "root", "0644"),
        (private / "credentials" / "admin-ticket-private-key", "/etc/overseer/admin-ticket-private-key", "overseer", "overseer", "0600"),
    )
    install_commands.extend(
        ["/usr/bin/install", "-o", owner, "-g", group, "-m", mode, str(source_path), target]
        for source_path, target, owner, group, mode in config_installs
    )
    unit_targets = {
        "overseer-admin-executor.socket": "/etc/systemd/system/overseer-admin-executor.socket",
        "overseer-admin-executor@.service": "/etc/systemd/system/overseer-admin-executor@.service",
        "overseer-api-canary.service": "/etc/systemd/system/overseer-api-canary.service",
        "overseer-api.service": "/etc/systemd/system/overseer-api.service",
        "overseer-approval-smoke.service": "/etc/systemd/system/overseer-approval-smoke.service",
        "overseer-codex-user-bridge.service": "/etc/systemd/system/overseer-codex-user-bridge.service",
        "overseer-codex-user-bridge.socket": "/etc/systemd/system/overseer-codex-user-bridge.socket",
        "overseer-runtime.service": "/etc/systemd/system/overseer-runtime.service",
        "overseer-tmpfiles.conf": "/etc/tmpfiles.d/overseer.conf",
    }
    install_commands.extend(
        [
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
            str(public / "systemd" / name),
            target,
        ]
        for name, target in unit_targets.items()
    )
    release_python = release_manifest.get("rootPython")
    if (
        not isinstance(release_python, Mapping)
        or not isinstance(release_python.get("path"), str)
        or not isinstance(release_python.get("releasePath"), str)
    ):
        raise ActivationPackageError("release Python manifest is invalid")
    final_backup = Path(
        f"/var/lib/overseer-executor/v1.1.6-source-{manifest_digest}.sqlite3"
    )
    final_store = Path("/var/lib/overseer/overseer.sqlite3")
    migration_command = [
        "/usr/bin/env",
        f"LD_LIBRARY_PATH={release_root}/lib",
        f"PYTHONHOME={release_root}/runtime",
        f"PYTHONPATH={release_root}/app/src:{release_root}/site-packages",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        str(PurePosixPath(release_root) / _safe_relative(str(release_python["releasePath"]))),
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
        "prepare-final-store",
        "--source-store",
        str(source.resolve()),
        "--backup-store",
        str(final_backup),
        "--destination-store",
        str(final_store),
        "--expected-source-device",
        str(source_metadata.st_dev),
        "--expected-source-inode",
        str(source_metadata.st_ino),
        "--expected-source-uid",
        str(source_metadata.st_uid),
        "--expected-source-gid",
        str(source_metadata.st_gid),
        "--expected-parent-device",
        str(parent_metadata.st_dev),
        "--expected-parent-inode",
        str(parent_metadata.st_ino),
        "--expected-parent-mode",
        str(parent_mode),
        "--destination-uid",
        str(overseer_uid),
        "--destination-gid",
        str(overseer_gid),
        "--pages-per-step",
        "128",
        "--sleep-seconds",
        "0.02",
    ]
    user_systemctl = [
        "/usr/sbin/runuser",
        "--user",
        "god",
        "--",
        "/usr/bin/env",
        f"XDG_RUNTIME_DIR=/run/user/{source_metadata.st_uid}",
        "/usr/bin/systemctl",
        "--user",
    ]
    rollback_systemd_run = [
        "/usr/bin/systemd-run",
        "--collect",
        "--uid=god",
        "--gid=god",
    ]
    activation_python = [
        "/usr/bin/env",
        f"LD_LIBRARY_PATH={release_root}/lib",
        f"PYTHONHOME={release_root}/runtime",
        f"PYTHONPATH={release_root}/app/src:{release_root}/site-packages",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        str(PurePosixPath(release_root) / _safe_relative(str(release_python["releasePath"]))),
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
    ]
    rollback_tag = manifest_digest[:16]
    rollback_runtime_unit = f"overseer-v1-1-5-rollback-runtime-{rollback_tag}.service"
    rollback_api_unit = f"overseer-v1-1-5-rollback-api-{rollback_tag}.service"
    canary_commands = [
        [
            "/usr/bin/install",
            "-o",
            "overseer",
            "-g",
            "overseer",
            "-m",
            "0600",
            str(private / "migration" / "rehearsal-migrated.sqlite3"),
            "/var/lib/overseer/overseer-canary.sqlite3",
        ],
        [*activation_python, "verify-approved-staging", "--package-root", str(execution_package)],
        ["/usr/bin/systemctl", "daemon-reload"],
        ["/usr/bin/systemd-tmpfiles", "--create", "/etc/tmpfiles.d/overseer.conf"],
        [
            "/usr/bin/systemctl",
            "start",
            "overseer-codex-user-bridge.socket",
            "overseer-admin-executor.socket",
        ],
        ["/usr/bin/systemctl", "start", "overseer-api-canary.service"],
        ["/usr/bin/curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:18766/health"],
        [*activation_python, "run-approved-canary", "--package-root", str(execution_package)],
        ["/usr/bin/systemctl", "stop", "overseer-api-canary.service"],
    ]
    cutover_commands = [
        [*activation_python, "verify-approved-cutover", "--package-root", str(execution_package)],
        [*user_systemctl, "stop", "overseer.service", "overseer-api.service"],
        migration_command,
        ["/usr/bin/systemctl", "daemon-reload"],
        ["/usr/bin/systemd-tmpfiles", "--create", "/etc/tmpfiles.d/overseer.conf"],
        ["/usr/bin/systemctl", "enable", "--now", "overseer-codex-user-bridge.socket", "overseer-admin-executor.socket"],
        ["/usr/bin/systemctl", "enable", "--now", "overseer-runtime.service", "overseer-api.service"],
        [
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "god",
            "-m",
            "0640",
            "/etc/overseer/api-token",
            "/home/god/.local/share/overseer/project/state/api-token",
        ],
        [
            *activation_python,
            "verify-compatibility-token",
            "--source-token",
            "/etc/overseer/api-token",
            "--target-token",
            "/home/god/.local/share/overseer/project/state/api-token",
            "--expected-target-uid",
            "0",
            "--expected-target-gid",
            str(god.pw_gid),
            "--expected-parent-device",
            str(parent_metadata.st_dev),
            "--expected-parent-inode",
            str(parent_metadata.st_ino),
        ],
        ["/usr/bin/curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8766/health"],
    ]
    rollback_runtime_command = _bind_rollback_transient_identity(
        [
            *rollback_systemd_run,
            f"--unit={rollback_runtime_unit}",
            "--service-type=simple",
            "--property=Restart=on-failure",
            "--property=RestartSec=5s",
            f"--working-directory={rollback_bundle_root / 'v1.1.5-release'}",
            f"--setenv=PYTHONHOME={release_root}/runtime",
            f"--setenv=LD_LIBRARY_PATH={release_root}/lib",
            f"--setenv=PYTHONPATH={rollback_bundle_root / 'v1.1.5-release' / 'src'}:{release_root}/site-packages",
            "--setenv=PYTHONNOUSERSITE=1",
            "--setenv=PYTHONSAFEPATH=1",
            "--",
            str(PurePosixPath(release_root) / _safe_relative(str(release_python["releasePath"]))),
            "-s",
            "-P",
            "-m",
            "overseer.cli",
            "run",
            "--store",
            str(source.resolve()),
        ]
    )
    rollback_api_command = _bind_rollback_transient_identity(
        [
            *rollback_systemd_run,
            f"--unit={rollback_api_unit}",
            "--service-type=simple",
            "--property=Restart=on-failure",
            "--property=RestartSec=5s",
            f"--property=After={rollback_runtime_unit}",
            "--property=LoadCredential=psychlo-overseer-peer-secret:/home/god/.config/psychlo/overseer-peer-secret",
            "--property=LoadCredential=roadex-project-human-thread-secret:/home/god/.config/overseer/project-human-thread-relay.secret",
            f"--working-directory={rollback_bundle_root / 'v1.1.5-release'}",
            f"--setenv=PYTHONHOME={release_root}/runtime",
            f"--setenv=LD_LIBRARY_PATH={release_root}/lib",
            f"--setenv=PYTHONPATH={rollback_bundle_root / 'v1.1.5-release' / 'src'}:{release_root}/site-packages",
            "--setenv=PYTHONDONTWRITEBYTECODE=1",
            "--setenv=PYTHONNOUSERSITE=1",
            "--setenv=PYTHONSAFEPATH=1",
            "--setenv=OVERSEER_PSYCHLO_ENDPOINT=http://127.0.0.1:8798",
            "--setenv=OVERSEER_PSYCHLO_BRIDGE_DATABASE=/home/god/.local/share/overseer/psychlo/bridge.sqlite3",
            "--setenv=OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE=/home/god/.config/overseer/psychlo-project-bindings.json",
            "--setenv=OVERSEER_PSYCHLO_PEER_SECRET_FILE=%d/psychlo-overseer-peer-secret",
            "--setenv=OVERSEER_PSYCHLO_POLICY_VERSION=2026-08-08",
            "--setenv=OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_SECRET_FILE=%d/roadex-project-human-thread-secret",
            "--setenv=OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_DATABASE=/home/god/.local/share/overseer/project-human-thread/relay.sqlite3",
            "--setenv=OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_QUESTION_ENDPOINT=http://127.0.0.1:8780/api/internal/overseer/project-human-thread/questions",
            "--",
            str(PurePosixPath(release_root) / _safe_relative(str(release_python["releasePath"]))),
            "-s",
            "-P",
            "-m",
            "overseer.cli",
            "serve-api",
            "--store",
            str(source.resolve()),
            "--host",
            "127.0.0.1",
            "--port",
            "8766",
            "--auth-token-file",
            "/home/god/.local/share/overseer/project/state/api-token",
        ]
    )
    rollback_commands = [
        [
            *activation_python,
            "verify-rollback-bundle",
            "--bundle-root",
            str(rollback_bundle_root),
            "--rollback-manifest",
            "/var/lib/overseer-executor/activation-package/public/rollback-manifest.json",
        ],
        ["/usr/bin/systemctl", "stop", "overseer-api.service", "overseer-runtime.service", "overseer-admin-executor.socket", "overseer-codex-user-bridge.socket"],
        ["/usr/bin/systemctl", "disable", "overseer-api.service", "overseer-runtime.service", "overseer-admin-executor.socket", "overseer-codex-user-bridge.socket"],
        ["/usr/bin/systemctl", "daemon-reload"],
        [
            *activation_python,
            "restore-legacy-store-access",
            "--source-store",
            str(source.resolve()),
            "--expected-source-uid",
            str(source_metadata.st_uid),
            "--expected-source-gid",
            str(source_metadata.st_gid),
            "--expected-source-device",
            str(source_metadata.st_dev),
            "--expected-source-inode",
            str(source_metadata.st_ino),
            "--expected-parent-device",
            str(parent_metadata.st_dev),
            "--expected-parent-inode",
            str(parent_metadata.st_ino),
            "--expected-parent-mode",
            str(parent_mode),
        ],
        rollback_runtime_command,
        rollback_api_command,
        ["/usr/bin/curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8766/health"],
    ]
    contract: dict[str, object] = {
        "schemaVersion": ACTIVATION_CONTRACT_SCHEMA,
        "liveExecutionApproved": False,
        "requiresSeparateDigestBoundApproval": True,
        "requiresEuid": 0,
        "packageRoot": str(execution_package),
        "releaseRoot": release_root,
        "releaseManifestDigest": release_manifest.get("manifestDigest"),
        "approvalRecord": {
            "path": str(_activation_approval_record_path()),
            "schemaVersion": ACTIVATION_APPROVAL_SCHEMA,
            "mustBeRootOwnedMode": "0600",
            "mustBindFinalPackageDigest": True,
        },
        "account": {
            "user": "overseer",
            "uid": overseer_uid,
            "group": "overseer",
            "gid": overseer_gid,
        },
        "sourceStore": {
            "path": str(source.resolve()),
            "device": source_metadata.st_dev,
            "inode": source_metadata.st_ino,
            "uid": source_metadata.st_uid,
            "gid": source_metadata.st_gid,
            "mode": "0600",
            "parent": {
                "path": str(source_parent.resolve()),
                "device": parent_metadata.st_dev,
                "inode": parent_metadata.st_ino,
                "uid": parent_metadata.st_uid,
                "gid": parent_metadata.st_gid,
                "mode": f"{parent_mode:04o}",
            },
        },
        "requiredAtExecution": [
            {
                "kind": "quiesced-source-store",
                "path": str(source.resolve()),
                "mustHaveNoOpenProcesses": True,
                "migrationBackup": str(final_backup),
                "migrationDestination": str(final_store),
            }
        ],
        "stagingAndCanaryCommands": [*install_commands, *canary_commands],
        "cutoverCommands": cutover_commands,
        "cutoverGate": {
            "requiredFunction": "overseer.activation_package.verify_approved_cutover",
            "requiresApprovedPackageDigest": True,
            "requiresRootOwnedApprovalRecord": True,
            "requiresRootOwnedDigestBoundAttestation": True,
            "manualCommandExtractionForbidden": True,
        },
        "canary": {
            "store": "/var/lib/overseer/overseer-canary.sqlite3",
            "loopbackHealth": "http://127.0.0.1:18766/health",
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
        },
        "acceptanceControls": {
            "positive": [
                "direct loopback canary health",
                "bounded user-bridge session projection",
                "bounded user-bridge usage projection",
                "admin approval of the exact smoke-plan digest",
                "single allowlisted approval-smoke restart receipt",
                "same-nonce replay returns the stored receipt without execution",
            ],
            "negative": [
                "ordinary API token cannot approve",
                "wrong human scope cannot approve",
                "cross-scope credential collision is rejected",
                "modified ticket is rejected",
                "expired ticket is rejected",
                "unlisted system unit is rejected",
                "user-service restart operation is rejected",
                "executor socket timeout fails closed",
                "crash-after-claim retry does not issue a second command",
            ],
        },
        "rollbackCommands": rollback_commands,
        "rollbackManifest": str(public / "rollback-manifest.json"),
        "rollbackBundle": {
            "root": str(rollback_bundle_root),
            "executionSourceLabel": "v1.1.5-release",
            "rootOwnedReadOnly": True,
            "usesTransientUserUnits": True,
        },
        "stopConditions": [
            "package digest or artifact identity drift",
            "UID or GID 984 is no longer free or resolves to a different account",
            "human verifier gate is incomplete",
            "final quiesced migration artifact is absent or unverified",
            "v1.1.5 rollback input hash drift",
            "direct or protected-gateway health check failure",
        ],
    }
    encoded = _canonical(contract)
    if b"<" in encoded or b">" in encoded:
        raise ActivationPackageError("activation contract contains an unresolved value")
    _write_new(package / "public" / "activation-contract.json", encoded + b"\n", 0o644)
    return contract


def _validate_migration_rehearsal_semantics(package: Path) -> dict[str, object]:
    report_path = package / "private" / "migration" / "migration-report.json"
    try:
        raw, metadata = _stable_read(report_path)
        report = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("migration rehearsal report is invalid") from error
    bounds = report.get("backupBounds") if isinstance(report, dict) else None
    source = report.get("source") if isinstance(report, dict) else None
    backup = report.get("backup") if isinstance(report, dict) else None
    migrated = report.get("migrated") if isinstance(report, dict) else None
    started = bounds.get("startedUnixNs") if isinstance(bounds, dict) else None
    completed = bounds.get("completedUnixNs") if isinstance(bounds, dict) else None
    before_counts = report.get("rowCountsBefore") if isinstance(report, dict) else None
    after_counts = report.get("rowCountsAfter") if isinstance(report, dict) else None
    row_counts_valid = isinstance(before_counts, dict) and isinstance(after_counts, dict)
    if row_counts_valid:
        for table, count in before_counts.items():
            observed = after_counts.get(table)
            if (
                not isinstance(table, str)
                or type(count) is not int
                or type(observed) is not int
                or count < 0
                or observed < 0
                or (
                    observed < count
                    if table in {"schema_migrations", "agent_schema_migrations"}
                    else observed != count
                )
            ):
                row_counts_valid = False
                break
    package_owner = package.lstat().st_uid
    if (
        metadata.st_uid != package_owner
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(report, dict)
        or report.get("schemaVersion") != "overseer.activation-migration-rehearsal.v1"
        or report.get("status") != "rehearsal_complete"
        or report.get("sourceMutationPerformed") is not False
        or not isinstance(source, dict)
        or source.get("journalMode") != "wal"
        or not isinstance(backup, dict)
        or backup.get("integrityCheck") != "ok"
        or not isinstance(migrated, dict)
        or migrated.get("integrityCheck") != "ok"
        or not row_counts_valid
        or not isinstance(bounds, dict)
        or type(bounds.get("pagesPerStep")) is not int
        or bounds.get("pagesPerStep") != -1
        or type(bounds.get("sleepSeconds")) not in (int, float)
        or bounds.get("sleepSeconds") != 0
        or bounds.get("singleStep") is not True
        or type(started) is not int
        or type(completed) is not int
        or started <= 0
        or completed <= started
    ):
        raise ActivationPackageError("migration rehearsal report does not prove approved semantics")
    return report


def finalize_activation_package(package_root: str | os.PathLike[str]) -> dict[str, object]:
    """Seal every currently staged byte after the interactive verifier gate."""

    package = Path(package_root).resolve()
    status = activation_package_status(package)
    if status["status"] == "ready_for_approval":
        raise ActivationPackageError("activation package is already finalized")
    if status["status"] != "credentials_complete":
        raise ActivationPackageError("human verifier gate is incomplete")
    required = (
        package / "public" / "activation-contract.json",
        package / "public" / "rollback-manifest.json",
        package / "private" / "migration" / "migration-report.json",
    )
    if any(not path.is_file() or path.is_symlink() for path in required):
        raise ActivationPackageError("activation package is missing a required artifact")
    _validate_migration_rehearsal_semantics(package)
    files = _package_file_inventory(package)
    directories = _package_directory_inventory(package)
    unsigned = {
        "schemaVersion": PACKAGE_MANIFEST_SCHEMA,
        "liveExecutionApproved": False,
        "files": files,
        "directories": directories,
    }
    digest = _sha256(_canonical(unsigned))
    document = {**unsigned, "packageDigest": digest}
    _write_new(package / "public" / "package-manifest.json", _canonical(document) + b"\n", 0o644)
    return {"status": "ready_for_approval", "packageDigest": digest, "fileCount": len(files)}


def verify_activation_package(
    package_root: str | os.PathLike[str],
    expected_digest: str,
) -> dict[str, object]:
    """Verify the sealed package without returning any private contents."""

    if len(expected_digest) != 64 or set(expected_digest) - _HEX:
        raise ActivationPackageError("expected package digest is invalid")
    package = Path(package_root).resolve()
    manifest_path = package / "public" / "package-manifest.json"
    try:
        raw, metadata = _stable_read(manifest_path)
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("package manifest is invalid") from error
    package_owner = package.lstat().st_uid
    if metadata.st_uid != package_owner or stat.S_IMODE(metadata.st_mode) != 0o644:
        raise ActivationPackageError("package manifest metadata is invalid")
    if not isinstance(document, dict) or document.get("schemaVersion") != PACKAGE_MANIFEST_SCHEMA:
        raise ActivationPackageError("package manifest schema is invalid")
    recorded_digest = document.get("packageDigest")
    unsigned = {key: value for key, value in document.items() if key != "packageDigest"}
    if recorded_digest != expected_digest or _sha256(_canonical(unsigned)) != expected_digest:
        raise ActivationPackageError("package manifest digest drift detected")
    observed_files = _package_file_inventory(package)
    observed_directories = _package_directory_inventory(package)
    if document.get("files") != observed_files or document.get("directories") != observed_directories:
        raise ActivationPackageError("activation package artifact drift detected")
    _validate_migration_rehearsal_semantics(package)
    return {"verified": True, "packageDigest": expected_digest, "fileCount": len(observed_files)}


def _activation_approval_record_path() -> Path:
    return Path("/var/lib/overseer-executor/approved-activation-package.json")


def _installed_credential_root() -> Path:
    return Path("/etc/overseer")


def _import_approved_execution_package(
    source_package: Path,
    *,
    expected_package_digest: str,
) -> Path:
    destination = APPROVED_EXECUTION_PACKAGE.absolute()
    if destination.exists() or destination.is_symlink():
        raise ActivationPackageError("approved execution package destination already exists")
    _ensure_directory(destination.parent)
    _ensure_directory(destination)
    directory_modes: list[tuple[Path, int]] = []
    for directory, directories, files in os.walk(source_package, followlinks=False):
        source_directory = Path(directory)
        relative_directory = source_directory.relative_to(source_package)
        target_directory = destination / relative_directory
        source_directory_metadata = source_directory.lstat()
        source_directory_mode = stat.S_IMODE(source_directory_metadata.st_mode)
        if (
            source_directory.is_symlink()
            or source_directory_metadata.st_uid != source_package.lstat().st_uid
            or source_directory_mode not in {0o500, 0o700}
        ):
            raise ActivationPackageError("source activation package directory mode is invalid")
        _ensure_directory(target_directory)
        directory_modes.append((target_directory, source_directory_mode))
        for name in directories:
            source_child = source_directory / name
            if source_child.is_symlink():
                raise ActivationPackageError("source activation package contains a directory symlink")
            _ensure_directory(target_directory / name)
        for name in files:
            source = source_directory / name
            relative = _safe_relative(source.relative_to(source_package).as_posix())
            raw, metadata = _stable_read(source)
            mode = stat.S_IMODE(metadata.st_mode)
            if mode not in {0o400, 0o444, 0o500, 0o555, 0o600, 0o644}:
                raise ActivationPackageError("source activation package file mode is invalid")
            _write_new(destination / relative, raw, mode)
    for target_directory, mode in sorted(
        directory_modes,
        key=lambda item: len(item[0].parts),
        reverse=True,
    ):
        os.chmod(target_directory, mode)
    verify_activation_package(destination, expected_package_digest)
    return destination


def record_activation_approval(
    package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
) -> dict[str, object]:
    """Record one explicit, root-owned approval for an exact sealed package."""

    _require_root_activation()
    source_package = Path(package_root).resolve()
    verified = verify_activation_package(source_package, expected_package_digest)
    package = _import_approved_execution_package(
        source_package,
        expected_package_digest=expected_package_digest,
    )
    contract = _sealed_package_json(
        package,
        expected_package_digest=expected_package_digest,
        relative_path="public/activation-contract.json",
    )
    if contract.get("packageRoot") != str(package):
        raise ActivationPackageError("sealed activation contract does not bind the execution package")
    target = _activation_approval_record_path()
    document = {
        "schemaVersion": ACTIVATION_APPROVAL_SCHEMA,
        "approved": True,
        "packageRoot": str(package),
        "sourcePackageRoot": str(source_package),
        "packageDigest": expected_package_digest,
        "packageFileCount": verified["fileCount"],
        "liveExecutionScope": "staging-canary-and-cutover-for-this-package-only",
    }
    _write_new(target, _canonical(document) + b"\n", 0o600)
    return document


def _load_activation_approval(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    package = Path(package_root).resolve()
    target = _activation_approval_record_path()
    try:
        raw, metadata = _stable_read(target)
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("activation approval record is unavailable or invalid") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(document, dict)
        or document.get("schemaVersion") != ACTIVATION_APPROVAL_SCHEMA
        or document.get("approved") is not True
        or document.get("packageRoot") != str(package)
        or document.get("liveExecutionScope")
        != "staging-canary-and-cutover-for-this-package-only"
    ):
        raise ActivationPackageError("activation approval record metadata or scope is invalid")
    digest = document.get("packageDigest")
    if not isinstance(digest, str):
        raise ActivationPackageError("activation approval record digest is invalid")
    verified = verify_activation_package(package, digest)
    if document.get("packageFileCount") != verified["fileCount"]:
        raise ActivationPackageError("activation approval record file count drifted")
    return document


def _sealed_package_json(
    package: Path,
    *,
    expected_package_digest: str,
    relative_path: str,
) -> dict[str, object]:
    verify_activation_package(package, expected_package_digest)
    manifest = _read_bound_package_manifest(package, expected_package_digest)
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        raise ActivationPackageError("sealed package file inventory is invalid")
    expected = next(
        (
            item
            for item in entries
            if isinstance(item, dict) and item.get("path") == relative_path
        ),
        None,
    )
    if expected is None:
        raise ActivationPackageError("sealed package document is not inventoried")
    raw, metadata = _stable_read(package / _safe_relative(relative_path))
    if (
        len(raw) != expected.get("size")
        or _sha256(raw) != expected.get("sha256")
        or f"{stat.S_IMODE(metadata.st_mode):04o}" != expected.get("mode")
    ):
        raise ActivationPackageError("sealed package document drifted while loading")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("sealed package document is invalid JSON") from error
    if not isinstance(document, dict):
        raise ActivationPackageError("sealed package document must be a JSON object")
    return document


def _read_bound_package_manifest(
    package: Path,
    expected_package_digest: str,
) -> dict[str, object]:
    try:
        raw, metadata = _stable_read(package / "public" / "package-manifest.json")
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("package manifest is invalid") from error
    package_owner = package.lstat().st_uid
    if (
        metadata.st_uid != package_owner
        or stat.S_IMODE(metadata.st_mode) != 0o644
        or not isinstance(document, dict)
        or document.get("schemaVersion") != PACKAGE_MANIFEST_SCHEMA
    ):
        raise ActivationPackageError("package manifest metadata or schema is invalid")
    recorded_digest = document.get("packageDigest")
    unsigned = {key: value for key, value in document.items() if key != "packageDigest"}
    if (
        recorded_digest != expected_package_digest
        or _sha256(_canonical(unsigned)) != expected_package_digest
    ):
        raise ActivationPackageError("package manifest digest drift detected")
    return document


def _account_ids(owner: str, group: str) -> tuple[int, int]:
    try:
        return pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError as error:
        raise ActivationPackageError("installed activation owner or group is unavailable") from error


def _validate_contract_principal_binding(contract: Mapping[str, object]) -> None:
    if (
        contract.get("schemaVersion") != ACTIVATION_CONTRACT_SCHEMA
        or contract.get("liveExecutionApproved") is not False
        or contract.get("requiresSeparateDigestBoundApproval") is not True
        or contract.get("requiresEuid") != 0
    ):
        raise ActivationPackageError("activation contract authority boundary is invalid")
    account = contract.get("account")
    source_store = contract.get("sourceStore")
    if not isinstance(account, Mapping) or not isinstance(source_store, Mapping):
        raise ActivationPackageError("activation principal contract is invalid")
    if account != {
        "user": "overseer",
        "uid": APPROVED_OVERSEER_UID,
        "group": "overseer",
        "gid": APPROVED_OVERSEER_GID,
    }:
        raise ActivationPackageError("activation dedicated-principal binding drifted")
    god_uid = source_store.get("uid")
    god_gid = source_store.get("gid")
    if type(god_uid) is not int or type(god_gid) is not int:
        raise ActivationPackageError("activation god principal binding is invalid")
    _validate_principal_binding(
        god_uid=god_uid,
        overseer_uid=APPROVED_OVERSEER_UID,
        overseer_gid=APPROVED_OVERSEER_GID,
    )
    god = pwd.getpwnam("god")
    if god.pw_gid != god_gid:
        raise ActivationPackageError("god primary group does not match the sealed activation contract")


def _verify_install_results(
    package: Path,
    *,
    expected_package_digest: str,
    commands: list[object],
) -> dict[str, object]:
    verify_activation_package(package, expected_package_digest)
    manifest = _read_bound_package_manifest(package, expected_package_digest)
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        raise ActivationPackageError("sealed package file inventory is invalid")
    package_files = {
        str(item["path"]): item
        for item in entries
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    expected_files: dict[Path, tuple[dict[str, object], int, int, int]] = {}
    expected_directories: dict[Path, tuple[int, int, int]] = {}
    for raw_command in commands:
        if not isinstance(raw_command, list) or not all(isinstance(value, str) for value in raw_command):
            raise ActivationPackageError("activation install command is invalid")
        command = list(raw_command)
        if (
            len(command) == 3
            and command[0] == "/usr/bin/chmod"
            and command[1] in {"0550", "0555"}
        ):
            target = Path(command[2])
            if target not in expected_directories:
                raise ActivationPackageError("activation directory freeze target was not installed")
            uid, gid, _mode = expected_directories[target]
            expected_directories[target] = (uid, gid, int(command[1], 8))
            continue
        if not command or command[0] != "/usr/bin/install":
            continue
        try:
            owner = command[command.index("-o") + 1]
            group = command[command.index("-g") + 1]
            mode = int(command[command.index("-m") + 1], 8)
        except (ValueError, IndexError) as error:
            raise ActivationPackageError("activation install command metadata is invalid") from error
        uid, gid = _account_ids(owner, group)
        if "-d" in command:
            targets = command[command.index("-m") + 2 :]
            if not targets:
                raise ActivationPackageError("activation directory install has no target")
            for target in targets:
                expected_directories[Path(target)] = (uid, gid, mode)
            continue
        source = Path(command[-2])
        target = Path(command[-1])
        try:
            relative = _safe_relative(source.relative_to(package).as_posix())
        except ValueError as error:
            raise ActivationPackageError("activation file install source is outside the sealed package") from error
        expected = package_files.get(relative)
        if expected is None:
            raise ActivationPackageError("activation file install source is not package-bound")
        expected_files[target] = (expected, uid, gid, mode)
    for target, (uid, gid, mode) in expected_directories.items():
        metadata = target.lstat()
        if (
            target.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise ActivationPackageError(f"installed activation directory is invalid: {target}")
    for target, (expected, uid, gid, mode) in expected_files.items():
        observed = _stream_hash_regular(target, label="installed activation artifact")
        if (
            observed["sha256"] != expected.get("sha256")
            or observed["size"] != expected.get("size")
            or observed["uid"] != uid
            or observed["gid"] != gid
            or observed["mode"] != f"{mode:04o}"
            or observed["links"] != 1
        ):
            raise ActivationPackageError(f"installed activation artifact is invalid: {target}")
    if not expected_files or not expected_directories:
        raise ActivationPackageError("activation install contract is empty")
    return {
        "verified": True,
        "installedFileCount": len(expected_files),
        "installedDirectoryCount": len(expected_directories),
    }


def verify_installed_staging(
    package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
) -> dict[str, object]:
    """Verify every installed staging artifact against the approved package."""

    _require_root_activation()
    package = Path(package_root).resolve()
    contract = _sealed_package_json(
        package,
        expected_package_digest=expected_package_digest,
        relative_path="public/activation-contract.json",
    )
    commands = contract.get("stagingAndCanaryCommands")
    if not isinstance(commands, list):
        raise ActivationPackageError("activation staging command contract is invalid")
    _validate_contract_principal_binding(contract)
    return _verify_install_results(
        package,
        expected_package_digest=expected_package_digest,
        commands=commands,
    )


def verify_compatibility_token(
    *,
    source_token: str | os.PathLike[str],
    target_token: str | os.PathLike[str],
    expected_target_uid: int,
    expected_target_gid: int,
    expected_parent_device: int,
    expected_parent_inode: int,
) -> dict[str, object]:
    """Verify the post-start client token copy from protected installed state."""

    _require_root_activation()
    source = Path(source_token)
    target = Path(target_token)
    root_uid, root_gid = _activation_root_identity()
    source_details = _stream_hash_regular(source, label="installed API token")
    target_details = _stream_hash_regular(target, label="compatibility API token")
    parent_metadata = target.parent.lstat()
    if (
        source_details["uid"] != root_uid
        or source_details["gid"] != root_gid
        or source_details["mode"] != "0600"
        or target_details["uid"] != expected_target_uid
        or target_details["gid"] != expected_target_gid
        or target_details["mode"] != "0640"
        or source_details["sha256"] != target_details["sha256"]
        or source_details["size"] != target_details["size"]
        or target.parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_dev != expected_parent_device
        or parent_metadata.st_ino != expected_parent_inode
        or parent_metadata.st_uid != root_uid
        or parent_metadata.st_gid != expected_target_gid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o555
    ):
        raise ActivationPackageError("compatibility API token copy or retained parent lock is invalid")
    return {
        "verified": True,
        "sha256": source_details["sha256"],
        "size": source_details["size"],
        "target": str(target),
    }


def run_canary_acceptance(
    package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
    admin_secret: str,
    roadex_secret: str,
    attestation_path: str | os.PathLike[str],
    base_url: str = "http://127.0.0.1:18766",
) -> dict[str, object]:
    """Run mandatory live canary controls and create a root-owned attestation."""

    from urllib.error import HTTPError

    from .client import OverseerApiClient

    _require_root_activation()
    package = Path(package_root)
    verified = verify_activation_package(package, expected_package_digest)
    verify_installed_staging(package, expected_package_digest=expected_package_digest)
    credential_root = _installed_credential_root()
    admin_verifier = load_approval_verifier(
        credential_root / "admin-approval-verifier.json",
        expected_owner_uid=APPROVED_OVERSEER_UID,
    )
    roadex_verifier = load_approval_verifier(
        credential_root / "roadex-fixture-approval-verifier.json",
        expected_owner_uid=APPROVED_OVERSEER_UID,
    )
    token_raw, token_metadata = _stable_read(credential_root / "api-token")
    root_uid, root_gid = _activation_root_identity()
    if (
        token_metadata.st_uid != root_uid
        or token_metadata.st_gid != root_gid
        or stat.S_IMODE(token_metadata.st_mode) != 0o600
    ):
        raise ActivationPackageError("canary API token metadata is invalid")
    try:
        api_token = token_raw.decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise ActivationPackageError("canary API token is invalid") from error
    if not admin_verifier.verify(admin_secret) or roadex_verifier.verify(admin_secret):
        raise ActivationPackageError("admin canary secret does not match exactly one approved scope")
    if not roadex_verifier.verify(roadex_secret) or admin_verifier.verify(roadex_secret):
        raise ActivationPackageError("Roadex canary secret does not match exactly one approved scope")

    ordinary = OverseerApiClient(base_url=base_url, auth_token=api_token)
    admin = OverseerApiClient(
        base_url=base_url,
        auth_token=api_token,
        approval_token=admin_secret,
    )
    wrong_scope = OverseerApiClient(
        base_url=base_url,
        auth_token=api_token,
        approval_token=roadex_secret,
    )
    ordinary_as_approval = OverseerApiClient(
        base_url=base_url,
        auth_token=api_token,
        approval_token=api_token,
    )

    def denied_reason(call) -> str:
        try:
            call()
        except HTTPError as error:
            try:
                payload = json.loads(error.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as parse_error:
                raise ActivationPackageError("canary denial response is invalid") from parse_error
            if error.code != 403 or not isinstance(payload, dict):
                raise ActivationPackageError("canary denial did not fail closed")
            return str(payload.get("reason") or payload.get("error") or "")
        raise ActivationPackageError("canary negative control was unexpectedly accepted")

    health = ordinary.health()
    if health.get("ok") is not True or health.get("service") != "overseer-api":
        raise ActivationPackageError("canary API health control failed")
    usage = ordinary._get("/health/codex-usage")
    if usage.get("source") != "codex.usage.snapshot.v1" or usage.get("bridge_state") not in {
        "available",
        "stale",
        "unavailable",
        "error",
    }:
        raise ActivationPackageError("canary usage bridge control failed")
    sessions = ordinary._post(
        "/agent-sessions/discover",
        {"provider_id": "codex", "instance_id": "overseer.activation-canary"},
    )
    if (
        sessions.get("mutation_performed") is not False
        or sessions.get("host_mutation_performed") is not False
        or sessions.get("bridge_state") not in {"available", "stale", "unavailable", "error"}
    ):
        raise ActivationPackageError("canary session bridge control failed")

    suffix = expected_package_digest[:16]
    smoke_plan_id = f"admin.activation-canary.smoke.{suffix}"
    smoke_payload = {
        "plan_id": smoke_plan_id,
        "kind": "system_service_restart",
        "target": "overseer-approval-smoke.service",
        "reason": "verify the v1.1.6 dedicated-principal approval boundary",
        "current_state": "inactive",
    }
    ordinary.plan_admin_change(smoke_payload)
    ordinary_denial = denied_reason(lambda: ordinary_as_approval.approve_admin_change(smoke_plan_id))
    wrong_scope_denial = denied_reason(lambda: wrong_scope.approve_admin_change(smoke_plan_id))
    approved = admin.approve_admin_change(smoke_plan_id)
    if approved.get("approved") is not True or approved.get("approved_by") != "sisko":
        raise ActivationPackageError("canary admin approval control failed")
    executed = ordinary.execute_admin_change({"plan_id": smoke_plan_id})
    replayed = ordinary.execute_admin_change({"plan_id": smoke_plan_id})
    if (
        executed.get("status") != "completed"
        or executed.get("mutation_performed") is not True
        or replayed.get("replayed") is not True
        or replayed.get("mutation_performed") is not False
        or replayed.get("id") != executed.get("id")
    ):
        raise ActivationPackageError("canary executor replay control failed")

    unlisted_plan_id = f"admin.activation-canary.unlisted.{suffix}"
    ordinary.plan_admin_change(
        {
            "plan_id": unlisted_plan_id,
            "kind": "system_service_restart",
            "target": "overseer-api.service",
            "reason": "prove the canary executor rejects an unlisted system unit",
            "current_state": "inactive",
        }
    )
    admin.approve_admin_change(unlisted_plan_id)
    unlisted = ordinary.execute_admin_change({"plan_id": unlisted_plan_id})
    if unlisted.get("status") not in {"blocked", "failed"} or unlisted.get("mutation_performed") is not False:
        raise ActivationPackageError("canary unlisted-unit control did not fail closed")

    controls = {
        "apiHealth": True,
        "usageBridgeBounded": True,
        "sessionBridgeReadOnly": True,
        "ordinaryTokenApprovalRejected": ordinary_denial == "independent_approval_token_required",
        "wrongScopeApprovalRejected": wrong_scope_denial == "independent_approval_token_required",
        "adminScopeApprovedBySisko": True,
        "allowlistedSmokeExecutedOnce": True,
        "samePlanReplayNoMutation": True,
        "unlistedUnitRejected": True,
    }
    if (
        len(controls) != len(CANARY_REQUIRED_CONTROLS)
        or set(controls) != set(CANARY_REQUIRED_CONTROLS)
        or not all(controls.values())
    ):
        raise ActivationPackageError("one or more canary controls did not pass exactly")
    sealed_contract = _sealed_package_json(
        package.resolve(),
        expected_package_digest=expected_package_digest,
        relative_path="public/activation-contract.json",
    )
    release_manifest_digest = sealed_contract.get("releaseManifestDigest")
    if not isinstance(release_manifest_digest, str):
        raise ActivationPackageError("canary activation contract release digest is invalid")
    attestation = {
        "schemaVersion": "overseer.activation-canary-acceptance.v1",
        "status": "passed",
        "packageDigest": expected_package_digest,
        "packageFileCount": verified["fileCount"],
        "releaseManifestDigest": release_manifest_digest,
        "controls": controls,
        "smokeExecutionId": executed["id"],
        "smokeReplayId": replayed["id"],
        "secretValuesRecorded": False,
    }
    target = Path(attestation_path)
    if target != _canary_attestation_path(expected_package_digest):
        raise ActivationPackageError("canary attestation path is not digest-bound")
    _write_new(target, _canonical(attestation) + b"\n", 0o600)
    return attestation


def verify_canary_attestation(
    package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
    attestation_path: str | os.PathLike[str],
) -> dict[str, object]:
    """Verify the root-owned live canary gate before exposing cutover commands."""

    verify_activation_package(package_root, expected_package_digest)
    target = Path(attestation_path)
    expected_path = _canary_attestation_path(expected_package_digest)
    if target != expected_path:
        raise ActivationPackageError("canary attestation path is not digest-bound")
    raw, metadata = _stable_read(target)
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ActivationPackageError("canary attestation metadata is invalid")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("canary attestation is invalid") from error
    controls = document.get("controls") if isinstance(document, dict) else None
    if (
        document.get("schemaVersion") != "overseer.activation-canary-acceptance.v1"
        or document.get("status") != "passed"
        or document.get("packageDigest") != expected_package_digest
        or not isinstance(controls, dict)
        or len(controls) != len(CANARY_REQUIRED_CONTROLS)
        or set(controls) != set(CANARY_REQUIRED_CONTROLS)
        or not all(value is True for value in controls.values())
        or document.get("secretValuesRecorded") is not False
        or document.get("smokeExecutionId") != document.get("smokeReplayId")
    ):
        raise ActivationPackageError("canary attestation controls are incomplete")
    return {"verified": True, "packageDigest": expected_package_digest, "controls": controls}


def verify_approved_cutover(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Enforce the root-owned package approval and live canary gates."""

    _require_root_activation()
    approval = _load_activation_approval(package_root)
    digest = str(approval["packageDigest"])
    installed = verify_installed_staging(
        package_root,
        expected_package_digest=digest,
    )
    canary = verify_canary_attestation(
        package_root,
        expected_package_digest=digest,
        attestation_path=_canary_attestation_path(digest),
    )
    return {
        "verified": True,
        "packageDigest": digest,
        "approvalRecord": str(_activation_approval_record_path()),
        "installed": installed,
        "canary": canary,
    }


def verify_approved_staging(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Verify root approval and installed bytes before any staged service starts."""

    _require_root_activation()
    approval = _load_activation_approval(package_root)
    digest = str(approval["packageDigest"])
    installed = verify_installed_staging(
        package_root,
        expected_package_digest=digest,
    )
    return {
        "verified": True,
        "packageDigest": digest,
        "approvalRecord": str(_activation_approval_record_path()),
        "installed": installed,
    }


def _activation_state_path() -> Path:
    return Path("/var/lib/overseer-executor/activation-state.json")


def _activation_lock_path() -> Path:
    return _activation_state_path().with_name("activation.lock")


@contextmanager
def _activation_execution_lock():
    target = _activation_lock_path()
    _ensure_directory(target.parent)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as error:
        raise ActivationPackageError("activation execution lock could not be opened") from error
    root_uid, root_gid = _activation_root_identity()
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationPackageError("activation execution lock is unsafe")
        os.fchown(descriptor, root_uid, root_gid)
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ActivationPackageError("another activation or rollback runner holds the execution lock") from error
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _load_activation_state() -> dict[str, object] | None:
    target = _activation_state_path()
    try:
        target.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ActivationPackageError("activation runner state could not be read") from error
    raw, metadata = _stable_read(target)
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ActivationPackageError("activation runner state metadata is invalid")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("activation runner state is invalid") from error
    if not isinstance(document, dict) or document.get("schemaVersion") != "overseer.activation-runner-state.v1":
        raise ActivationPackageError("activation runner state schema is invalid")
    return document


def _write_activation_state(document: Mapping[str, object]) -> None:
    target = _activation_state_path()
    _ensure_directory(target.parent)
    root_uid, root_gid = _activation_root_identity()
    temporary = target.with_name(f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        payload = _canonical(dict(document)) + b"\n"
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("activation state write made no progress")
            view = view[written:]
        os.fchown(descriptor, root_uid, root_gid)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
        parent_descriptor = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _contract_commands(contract: Mapping[str, object], field: str) -> list[list[str]]:
    raw = contract.get(field)
    if not isinstance(raw, list) or not raw:
        raise ActivationPackageError(f"activation contract {field} is empty or invalid")
    result: list[list[str]] = []
    for command in raw:
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(value, str) and value for value in command)
            or not str(command[0]).startswith("/")
        ):
            raise ActivationPackageError(f"activation contract {field} contains an invalid argv")
        result.append(list(command))
    return result


def _execute_contract_command(command: list[str]) -> int:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    try:
        result = subprocess.run(
            command,
            stdin=None,
            stdout=None,
            stderr=None,
            check=False,
            env=environment,
        )
    except OSError as error:
        raise ActivationPackageError(f"activation command could not start: {command[0]}") from error
    return int(result.returncode)


def _command_outcome(command: list[str]) -> tuple[int, str | None]:
    try:
        return _execute_contract_command(command), None
    except Exception as error:
        return 127, type(error).__name__


def _validated_command_outcome(
    contract: Mapping[str, object],
    command: list[str],
) -> tuple[int, str | None]:
    try:
        _validate_contract_principal_binding(contract)
    except Exception as error:
        return 126, type(error).__name__
    return _command_outcome(command)


def _cleanup_commands(contract: Mapping[str, object]) -> list[list[str]]:
    canary = contract.get("canary")
    raw = canary.get("failureCleanupCommands") if isinstance(canary, Mapping) else None
    if not isinstance(raw, list) or not raw:
        raise ActivationPackageError("activation canary cleanup contract is empty or invalid")
    result: list[list[str]] = []
    for command in raw:
        if (
            not isinstance(command, list)
            or not command
            or not all(isinstance(value, str) and value for value in command)
            or not command[0].startswith("/")
        ):
            raise ActivationPackageError("activation canary cleanup command is invalid")
        result.append(list(command))
    return result


def _cleanup_command_satisfied(command: list[str]) -> bool:
    if len(command) < 4 or command[:2] != ["/usr/bin/systemctl", "stop"]:
        return False
    for unit in command[2:]:
        returncode, start_error = _command_outcome(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit]
        )
        if start_error is not None or returncode == 0:
            return False
    return True


def _runner_state(
    *,
    package_digest: str,
    status: str,
    phase: str,
    command_index: int | None = None,
    command: list[str] | None = None,
    failure: str | None = None,
) -> dict[str, object]:
    return {
        "schemaVersion": "overseer.activation-runner-state.v1",
        "packageDigest": package_digest,
        "status": status,
        "phase": phase,
        "commandIndex": command_index,
        "commandDigest": _sha256(_canonical(command)) if command is not None else None,
        "failure": failure,
        "updatedAtNs": time.time_ns(),
        "secretValuesRecorded": False,
    }


def _execute_cleanup_sequence(
    contract: Mapping[str, object],
    *,
    package_digest: str,
) -> None:
    for index, command in enumerate(_cleanup_commands(contract)):
        _write_activation_state(
            _runner_state(
                package_digest=package_digest,
                status="cleanup_command_running",
                phase="staging_cleanup",
                command_index=index,
                command=command,
            )
        )
        returncode, start_error = _validated_command_outcome(contract, command)
        if returncode != 0 and not (
            start_error is None and _cleanup_command_satisfied(command)
        ):
            _write_activation_state(
                _runner_state(
                    package_digest=package_digest,
                    status="cleanup_failed",
                    phase="staging_cleanup",
                    command_index=index,
                    command=command,
                    failure=start_error or f"exit-{returncode}",
                )
            )
            raise ActivationPackageError("staging cleanup command failed")
        _write_activation_state(
            _runner_state(
                package_digest=package_digest,
                status="cleanup_command_complete",
                phase="staging_cleanup",
                command_index=index,
                command=command,
            )
        )


def _rollback_transient_spec(command: list[str]) -> dict[str, object] | None:
    if not command or command[0] != "/usr/bin/systemd-run":
        return None
    if (
        command.count("--") != 1
        or command.count("--collect") != 1
        or command.count("--uid=god") != 1
        or command.count("--gid=god") != 1
        or command.count("--service-type=simple") != 1
        or any(value.startswith("--uid=") and value != "--uid=god" for value in command)
        or any(value.startswith("--gid=") and value != "--gid=god" for value in command)
        or any(value.startswith("--service-type=") and value != "--service-type=simple" for value in command)
        or "--user" in command
    ):
        raise ActivationPackageError("sealed rollback transient command is invalid")
    unit_values = [value.removeprefix("--unit=") for value in command if value.startswith("--unit=")]
    working_values = [
        value.removeprefix("--working-directory=")
        for value in command
        if value.startswith("--working-directory=")
    ]
    description_values = [
        value.removeprefix("--property=Description=")
        for value in command
        if value.startswith("--property=Description=")
    ]
    marker_values = [
        value.removeprefix("--setenv=OVERSEER_ROLLBACK_TRANSIENT_ID=")
        for value in command
        if value.startswith("--setenv=OVERSEER_ROLLBACK_TRANSIENT_ID=")
    ]
    if (
        len(unit_values) != 1
        or re.fullmatch(r"overseer-v1-1-5-rollback-(runtime|api)-[0-9a-f]{16}\.service", unit_values[0]) is None
        or len(working_values) != 1
        or not working_values[0].startswith("/opt/overseer/rollback/")
        or len(description_values) != 1
        or len(marker_values) != 1
        or not description_values[0].startswith(ROLLBACK_TRANSIENT_MARKER)
    ):
        raise ActivationPackageError("rollback transient identity fields are invalid")
    marker_digest = description_values[0].removeprefix(ROLLBACK_TRANSIENT_MARKER)
    if marker_digest != marker_values[0] or len(marker_digest) != 64 or set(marker_digest) - _HEX:
        raise ActivationPackageError("rollback transient identity marker is invalid")
    marker_arguments = {
        f"--property=Description={description_values[0]}",
        f"--setenv=OVERSEER_ROLLBACK_TRANSIENT_ID={marker_digest}",
    }
    unbound = [value for value in command if value not in marker_arguments]
    if _sha256(_canonical(unbound)) != marker_digest:
        raise ActivationPackageError("rollback transient identity digest drifted")
    separator = command.index("--")
    argv = command[separator + 1 :]
    if not argv or not argv[0].startswith("/"):
        raise ActivationPackageError("rollback transient executable is invalid")
    properties: dict[str, list[str]] = {}
    for value in command[:separator]:
        if not value.startswith("--property="):
            continue
        assignment = value.removeprefix("--property=")
        key, separator_value, property_value = assignment.partition("=")
        if not key or not separator_value:
            raise ActivationPackageError("rollback transient property is invalid")
        properties.setdefault(key, []).append(property_value)
    environment = [
        value.removeprefix("--setenv=")
        for value in command[:separator]
        if value.startswith("--setenv=")
    ]
    environment_names = [value.partition("=")[0] for value in environment]
    unit_kind = "runtime" if "-runtime-" in unit_values[0] else "api"
    expected_runtime_unit = unit_values[0].replace("-api-", "-runtime-")
    expected_credentials = {
        "psychlo-overseer-peer-secret:/home/god/.config/psychlo/overseer-peer-secret",
        "roadex-project-human-thread-secret:/home/god/.config/overseer/project-human-thread-relay.secret",
    }
    expected_property_names = {"Description", "Restart", "RestartSec"}
    if unit_kind == "api":
        expected_property_names.update({"After", "LoadCredential"})
    if (
        set(properties) != expected_property_names
        or len(properties["Description"]) != 1
        or properties.get("Restart") != ["on-failure"]
        or properties.get("RestartSec") != ["5s"]
        or (unit_kind == "runtime" and ("After" in properties or "LoadCredential" in properties))
        or (unit_kind == "api" and properties.get("After") != [expected_runtime_unit])
        or (unit_kind == "api" and set(properties.get("LoadCredential", [])) != expected_credentials)
        or len(environment_names) != len(set(environment_names))
        or any(not name for name in environment_names)
    ):
        raise ActivationPackageError("rollback transient sealed properties are invalid")
    return {
        "unit": unit_values[0],
        "workingDirectory": working_values[0],
        "description": description_values[0],
        "environment": environment,
        "properties": properties,
        "argv": argv,
    }


def _systemctl_show_rollback_unit(unit: str) -> dict[str, str]:
    names = (
        "LoadState",
        "ActiveState",
        "SubState",
        "Transient",
        "FragmentPath",
        "Description",
        "User",
        "Group",
        "WorkingDirectory",
        "Type",
        "Restart",
        "RestartUSec",
        "CollectMode",
        "Environment",
        "ExecStart",
        "After",
        "LoadCredential",
        "InvocationID",
    )
    command = [
        "/usr/bin/systemctl",
        "show",
        "--no-pager",
        *[f"--property={name}" for name in names],
        unit,
    ]
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )
    except OSError as error:
        raise ActivationPackageError("rollback transient unit inspection could not start") from error
    if result.returncode != 0:
        raise ActivationPackageError("rollback transient unit inspection failed")
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in names and key not in observed:
            observed[key] = value
    if "LoadState" not in observed or "ActiveState" not in observed:
        raise ActivationPackageError("rollback transient unit inspection was incomplete")
    return observed


def _show_words(value: str, *, label: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError as error:
        raise ActivationPackageError(f"rollback transient {label} is invalid") from error


def _verify_rollback_transient_fragment(fragment: Path, *, unit: str) -> None:
    expected_fragment = Path("/run/systemd/transient") / unit
    try:
        fragment_metadata = fragment.lstat()
    except OSError as error:
        raise ActivationPackageError("rollback transient unit file is unavailable") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        fragment != expected_fragment
        or fragment.is_symlink()
        or not stat.S_ISREG(fragment_metadata.st_mode)
        or fragment_metadata.st_uid != root_uid
        or fragment_metadata.st_gid != root_gid
        or fragment_metadata.st_nlink != 1
        or stat.S_IMODE(fragment_metadata.st_mode) & 0o022
    ):
        raise ActivationPackageError("rollback transient unit file identity drifted")


def _inspect_rollback_transient_unit(spec: Mapping[str, object]) -> str:
    unit = str(spec["unit"])
    observed = _systemctl_show_rollback_unit(unit)
    load_state = observed.get("LoadState")
    active_state = observed.get("ActiveState")
    if load_state == "not-found":
        return "unloaded"
    if load_state != "loaded" or not active_state:
        raise ActivationPackageError("rollback transient unit load state is invalid")
    fragment = Path(observed.get("FragmentPath", ""))
    _verify_rollback_transient_fragment(fragment, unit=unit)
    invocation_id = observed.get("InvocationID", "")
    allowed_substates = {
        "active": {"running"},
        "activating": {"start", "start-pre", "start-post", "auto-restart"},
        "inactive": {"dead"},
        "failed": {"failed"},
        "deactivating": {
            "stop",
            "stop-sigterm",
            "stop-sigkill",
            "final-sigterm",
            "final-sigkill",
        },
    }
    if (
        observed.get("Transient") != "yes"
        or observed.get("Description") != spec["description"]
        or observed.get("User") != "god"
        or observed.get("Group") != "god"
        or observed.get("WorkingDirectory") != spec["workingDirectory"]
        or observed.get("Type") != "simple"
        or observed.get("CollectMode") != "inactive-or-failed"
        or observed.get("SubState") not in allowed_substates.get(active_state, set())
        or (invocation_id and re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None)
        or (active_state != "inactive" and not invocation_id)
    ):
        raise ActivationPackageError("rollback transient unit identity drifted")
    properties = spec.get("properties")
    if not isinstance(properties, Mapping):
        raise ActivationPackageError("rollback transient sealed properties are invalid")
    if observed.get("Restart") != properties.get("Restart", [None])[0]:
        raise ActivationPackageError("rollback transient restart policy drifted")
    if observed.get("RestartUSec") != properties.get("RestartSec", [None])[0]:
        raise ActivationPackageError("rollback transient restart timing drifted")
    expected_after = set(properties.get("After", []))
    if not expected_after.issubset(set(_show_words(observed.get("After", ""), label="ordering"))):
        raise ActivationPackageError("rollback transient ordering drifted")
    expected_credentials = set(properties.get("LoadCredential", []))
    if expected_credentials and observed.get("LoadCredential") != "[unprintable]":
        raise ActivationPackageError("rollback transient credential binding drifted")
    if not expected_credentials and observed.get("LoadCredential"):
        raise ActivationPackageError("rollback transient unexpected credential binding")
    credential_directory = f"/run/credentials/{unit}"
    expected_environment = {
        str(value).replace("%d", credential_directory) for value in spec["environment"]
    }
    if set(_show_words(observed.get("Environment", ""), label="environment")) != expected_environment:
        raise ActivationPackageError("rollback transient environment drifted")
    exec_match = re.search(r"(?:^| ; )argv\[\]=(.*?) ; ignore_errors=", observed.get("ExecStart", ""))
    if exec_match is None or _show_words(exec_match.group(1), label="command") != spec["argv"]:
        raise ActivationPackageError("rollback transient executable drifted")
    return active_state


def _rollback_recovery_boundary(
    prior_state: Mapping[str, object] | None,
    *,
    commands: list[list[str]],
    package_digest: str,
) -> int | None:
    if prior_state is None or prior_state.get("phase") != "rollback":
        return None
    if (
        prior_state.get("schemaVersion") != "overseer.activation-runner-state.v1"
        or prior_state.get("packageDigest") != package_digest
        or prior_state.get("status")
        not in {"rollback_command_running", "rollback_command_complete", "rollback_failed"}
    ):
        raise ActivationPackageError("rollback recovery state binding is invalid")
    index = prior_state.get("commandIndex")
    if type(index) is not int or not 0 <= index < len(commands):
        raise ActivationPackageError("rollback recovery command index is invalid")
    if prior_state.get("commandDigest") != _sha256(_canonical(commands[index])):
        raise ActivationPackageError("rollback recovery command digest is invalid")
    return index


def _execute_rollback_transient(
    contract: Mapping[str, object],
    command: list[str],
    *,
    resume: bool,
) -> None:
    spec = _rollback_transient_spec(command)
    if spec is None:
        raise ActivationPackageError("rollback transient command is unavailable")

    def inspect() -> str:
        _validate_contract_principal_binding(contract)
        return _inspect_rollback_transient_unit(spec)

    state = inspect()
    if not resume and state != "unloaded":
        raise ActivationPackageError("unexpected pre-existing rollback transient unit")
    if state == "active":
        return
    action = command
    if state == "activating":
        action = ["/usr/bin/systemctl", "start", str(spec["unit"])]
    elif state in {"inactive", "failed", "deactivating"}:
        action = ["/usr/bin/systemctl", "restart", str(spec["unit"])]
    elif state != "unloaded":
        raise ActivationPackageError("rollback transient unit state is not recoverable")
    returncode, start_error = _validated_command_outcome(contract, action)
    if returncode != 0 and action is not command:
        raced_state = inspect()
        if raced_state == "unloaded":
            returncode, start_error = _validated_command_outcome(contract, command)
    if returncode != 0:
        detail = start_error or f"exit-{returncode}"
        raise ActivationPackageError(f"rollback transient unit start failed: {detail}")
    if inspect() != "active":
        raise ActivationPackageError("rollback transient unit did not become active")


def _execute_rollback_sequence(
    contract: Mapping[str, object],
    *,
    package_digest: str,
    prior_state: Mapping[str, object] | None = None,
    originating_failure: str | None = None,
) -> None:
    commands = _contract_commands(contract, "rollbackCommands")
    recovery_boundary = _rollback_recovery_boundary(
        prior_state,
        commands=commands,
        package_digest=package_digest,
    )
    for index, command in enumerate(commands):
        try:
            _validate_contract_principal_binding(contract)
        except Exception as error:
            _write_activation_state(
                _runner_state(
                    package_digest=package_digest,
                    status="rollback_failed",
                    phase="rollback",
                    command_index=index,
                    command=command,
                    failure=type(error).__name__,
                )
            )
            raise ActivationPackageError("rollback principal binding drifted") from error
        _write_activation_state(
            _runner_state(
                package_digest=package_digest,
                status="rollback_command_running",
                phase="rollback",
                command_index=index,
                command=command,
                failure=originating_failure,
            )
        )
        transient = _rollback_transient_spec(command)
        if transient is not None:
            try:
                _execute_rollback_transient(
                    contract,
                    command,
                    resume=recovery_boundary is not None and index <= recovery_boundary,
                )
            except Exception as error:
                _write_activation_state(
                    _runner_state(
                        package_digest=package_digest,
                        status="rollback_failed",
                        phase="rollback",
                        command_index=index,
                        command=command,
                        failure=type(error).__name__,
                    )
                )
                raise ActivationPackageError("sealed rollback transient command failed") from error
        else:
            returncode, start_error = _command_outcome(command)
            if returncode != 0:
                _write_activation_state(
                    _runner_state(
                        package_digest=package_digest,
                        status="rollback_failed",
                        phase="rollback",
                        command_index=index,
                        command=command,
                        failure=start_error or f"exit-{returncode}",
                    )
                )
                raise ActivationPackageError("sealed rollback command failed")
        _write_activation_state(
            _runner_state(
                package_digest=package_digest,
                status="rollback_command_complete",
                phase="rollback",
                command_index=index,
                command=command,
                failure=originating_failure,
            )
        )
    _write_activation_state(
        _runner_state(
            package_digest=package_digest,
            status="rolled_back",
            phase="rollback",
            failure=originating_failure,
        )
    )


def _execute_approved_activation_locked(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Execute one sealed activation contract in order through a fail-closed state machine."""

    _require_root_activation()
    package = Path(package_root).resolve()
    approval = _load_activation_approval(package)
    digest = str(approval["packageDigest"])
    contract = _sealed_package_json(
        package,
        expected_package_digest=digest,
        relative_path="public/activation-contract.json",
    )
    if contract.get("packageRoot") != str(package):
        raise ActivationPackageError("activation contract package root is not approval-bound")
    _validate_contract_principal_binding(contract)
    existing = _load_activation_state()
    if existing is not None:
        if (
            existing.get("packageDigest") == digest
            and existing.get("status") == "complete"
            and existing.get("phase") == "complete"
        ):
            return {"status": "complete", "packageDigest": digest, "replayed": True}
        raise ActivationPackageError(
            "activation runner state is not safely resumable; use the sealed rollback path"
        )
    staging = _contract_commands(contract, "stagingAndCanaryCommands")
    cutover = _contract_commands(contract, "cutoverCommands")
    rollback = _contract_commands(contract, "rollbackCommands")
    _cleanup_commands(contract)

    _write_activation_state(_runner_state(package_digest=digest, status="running", phase="staging"))
    for index, command in enumerate(staging):
        _write_activation_state(
            _runner_state(
                package_digest=digest,
                status="command_running",
                phase="staging",
                command_index=index,
                command=command,
            )
        )
        returncode, start_error = _validated_command_outcome(contract, command)
        if returncode != 0:
            command_failure = start_error or f"exit-{returncode}"
            _execute_cleanup_sequence(contract, package_digest=digest)
            _write_activation_state(
                _runner_state(
                    package_digest=digest,
                    status="failed_before_cutover",
                    phase="staging",
                    command_index=index,
                    command=command,
                    failure=command_failure,
                )
            )
            raise ActivationPackageError("staged activation command failed before cutover")
        _write_activation_state(
            _runner_state(
                package_digest=digest,
                status="command_complete",
                phase="staging",
                command_index=index,
                command=command,
            )
        )

    try:
        verify_approved_cutover(package)
    except Exception as error:
        _execute_cleanup_sequence(contract, package_digest=digest)
        _write_activation_state(
            _runner_state(
                package_digest=digest,
                status="failed_before_cutover",
                phase="staging_cleanup",
                failure=type(error).__name__,
            )
        )
        raise ActivationPackageError("cutover gate failed after staging cleanup") from error
    _write_activation_state(_runner_state(package_digest=digest, status="running", phase="cutover"))
    for index, command in enumerate(cutover):
        _write_activation_state(
            _runner_state(
                package_digest=digest,
                status="command_running",
                phase="cutover",
                command_index=index,
                command=command,
            )
        )
        returncode, start_error = _validated_command_outcome(contract, command)
        if returncode != 0:
            command_failure = start_error or f"cutover-exit-{returncode}"
            _write_activation_state(
                _runner_state(
                    package_digest=digest,
                    status="rollback_command_running",
                    phase="rollback",
                    command_index=0,
                    command=rollback[0],
                    failure=command_failure,
                )
            )
            try:
                _execute_rollback_sequence(
                    contract,
                    package_digest=digest,
                    originating_failure=command_failure,
                )
            except ActivationPackageError as error:
                raise ActivationPackageError(
                    "cutover failed and sealed rollback did not complete"
                ) from error
            raise ActivationPackageError("cutover failed and the sealed rollback completed")
        _write_activation_state(
            _runner_state(
                package_digest=digest,
                status="command_complete",
                phase="cutover",
                command_index=index,
                command=command,
            )
        )
    _write_activation_state(_runner_state(package_digest=digest, status="complete", phase="complete"))
    return {"status": "complete", "packageDigest": digest, "replayed": False}


def _execute_approved_rollback_locked(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Recover an interrupted/failed cutover through only the sealed rollback commands."""

    _require_root_activation()
    package = Path(package_root).resolve()
    approval = _load_activation_approval(package)
    digest = str(approval["packageDigest"])
    contract = _sealed_package_json(
        package,
        expected_package_digest=digest,
        relative_path="public/activation-contract.json",
    )
    if contract.get("packageRoot") != str(package):
        raise ActivationPackageError("activation contract package root is not approval-bound")
    _validate_contract_principal_binding(contract)
    state = _load_activation_state()
    if state is None or state.get("packageDigest") != digest:
        raise ActivationPackageError("no matching activation runner state exists for rollback")
    if state.get("status") == "rolled_back":
        return {"status": "rolled_back", "packageDigest": digest, "replayed": True}
    if state.get("status") == "aborted_before_cutover":
        return {
            "status": "aborted_before_cutover",
            "packageDigest": digest,
            "replayed": True,
        }
    if state.get("phase") in {"staging", "staging_cleanup"}:
        _execute_cleanup_sequence(contract, package_digest=digest)
        _write_activation_state(
            _runner_state(
                package_digest=digest,
                status="aborted_before_cutover",
                phase="staging_cleanup",
            )
        )
        return {"status": "aborted_before_cutover", "packageDigest": digest, "replayed": False}
    if state.get("phase") not in {"cutover", "rollback"}:
        raise ActivationPackageError("activation runner state is not eligible for sealed rollback")
    _execute_rollback_sequence(
        contract,
        package_digest=digest,
        prior_state=state,
        originating_failure=str(state.get("failure")) if state.get("failure") else None,
    )
    return {"status": "rolled_back", "packageDigest": digest, "replayed": False}


def execute_approved_activation(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    with _activation_execution_lock():
        return _execute_approved_activation_locked(package_root)


def execute_approved_rollback(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    with _activation_execution_lock():
        return _execute_approved_rollback_locked(package_root)


def _canary_attestation_path(package_digest: str) -> Path:
    return Path(f"/var/lib/overseer-executor/canary-{package_digest}.json")


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m overseer.activation_package",
        description="Run one exact activation-package primitive.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    sqlite_stage = commands.add_parser(
        "stage-sqlite-runtime",
        help="copy the independently approved SQLite binary to a closed package inode",
    )
    sqlite_stage.add_argument("--source-library", required=True)
    sqlite_stage.add_argument("--package-root", required=True)
    prepare = commands.add_parser(
        "prepare-package",
        help="stage a closed owner-only package without activating it",
    )
    prepare.add_argument("--checkout", required=True)
    prepare.add_argument("--dependency-root", required=True)
    prepare.add_argument("--root-python", required=True)
    prepare.add_argument("--stdlib-root", required=True)
    prepare.add_argument("--sqlite-library", required=True)
    prepare.add_argument("--templates-root", required=True)
    prepare.add_argument("--package-root", required=True)
    prepare.add_argument("--psychlo-secret-file", required=True)
    prepare.add_argument("--roadex-secret-file", required=True)
    prepare.add_argument("--psychlo-bindings-file", required=True)
    prepare.add_argument("--source-store", required=True)
    prepare.add_argument("--god-uid", required=True, type=int)
    prepare.add_argument("--overseer-uid", required=True, type=int)
    prepare.add_argument("--overseer-gid", required=True, type=int)
    prepare.add_argument("--rollback-input", required=True, action="append")
    human_verifiers = commands.add_parser(
        "create-human-verifiers",
        help="interactively create both separate scoped human approval verifiers",
    )
    human_verifiers.add_argument("--package-root", required=True)
    finalize = commands.add_parser(
        "finalize-package",
        help="seal a prepared package after the human-verifier gate",
    )
    finalize.add_argument("--package-root", required=True)
    verify = commands.add_parser(
        "verify-package",
        help="verify every byte in a sealed package against its expected digest",
    )
    verify.add_argument("--package-root", required=True)
    verify.add_argument("--expected-digest", required=True)
    status = commands.add_parser(
        "status",
        help="report the current package gate without returning private contents",
    )
    status.add_argument("--package-root", required=True)
    verify_rollback = commands.add_parser(
        "verify-rollback",
        help="verify every captured rollback input before restoration",
    )
    verify_rollback.add_argument("--package-root", required=True)
    verify_root_rollback = commands.add_parser(
        "verify-rollback-bundle",
        help="verify the immutable root-owned rollback execution bundle",
    )
    verify_root_rollback.add_argument("--bundle-root", required=True)
    verify_root_rollback.add_argument("--rollback-manifest", required=True)
    restore_legacy = commands.add_parser(
        "restore-legacy-store-access",
        help="restore the exact legacy store access needed for approved rollback",
    )
    restore_legacy.add_argument("--source-store", required=True)
    restore_legacy.add_argument("--expected-source-uid", required=True, type=int)
    restore_legacy.add_argument("--expected-source-gid", required=True, type=int)
    restore_legacy.add_argument("--expected-source-device", required=True, type=int)
    restore_legacy.add_argument("--expected-source-inode", required=True, type=int)
    restore_legacy.add_argument("--expected-parent-device", required=True, type=int)
    restore_legacy.add_argument("--expected-parent-inode", required=True, type=int)
    restore_legacy.add_argument("--expected-parent-mode", required=True, type=int)
    record_approval = commands.add_parser(
        "record-activation-approval",
        help="record a root-owned approval for one exact sealed package digest",
    )
    record_approval.add_argument("--package-root", required=True)
    record_approval.add_argument("--expected-package-digest", required=True)
    approved_canary = commands.add_parser(
        "run-approved-canary",
        help="run mandatory live canary controls for the root-approved package",
    )
    approved_canary.add_argument("--package-root", required=True)
    approved_staging = commands.add_parser(
        "verify-approved-staging",
        help="verify approval and installed artifacts before staged services start",
    )
    approved_staging.add_argument("--package-root", required=True)
    approved_cutover = commands.add_parser(
        "verify-approved-cutover",
        help="verify package approval, installed artifacts, and canary attestation",
    )
    approved_cutover.add_argument("--package-root", required=True)
    compatibility_token = commands.add_parser(
        "verify-compatibility-token",
        help="verify the protected post-start client token copy",
    )
    compatibility_token.add_argument("--source-token", required=True)
    compatibility_token.add_argument("--target-token", required=True)
    compatibility_token.add_argument("--expected-target-uid", required=True, type=int)
    compatibility_token.add_argument("--expected-target-gid", required=True, type=int)
    compatibility_token.add_argument("--expected-parent-device", required=True, type=int)
    compatibility_token.add_argument("--expected-parent-inode", required=True, type=int)
    execute_activation = commands.add_parser(
        "execute-approved-activation",
        help="execute the sealed activation and rollback state machine",
    )
    execute_activation.add_argument("--package-root", required=True)
    execute_rollback = commands.add_parser(
        "execute-approved-rollback",
        help="recover an interrupted cutover through the sealed rollback contract",
    )
    execute_rollback.add_argument("--package-root", required=True)
    final_store = commands.add_parser(
        "prepare-final-store",
        help="create the final migrated authority store after legacy writers are stopped",
    )
    final_store.add_argument("--source-store", required=True)
    final_store.add_argument("--backup-store", required=True)
    final_store.add_argument("--destination-store", required=True)
    final_store.add_argument("--expected-source-device", required=True, type=int)
    final_store.add_argument("--expected-source-inode", required=True, type=int)
    final_store.add_argument("--expected-source-uid", required=True, type=int)
    final_store.add_argument("--expected-source-gid", required=True, type=int)
    final_store.add_argument("--expected-parent-device", required=True, type=int)
    final_store.add_argument("--expected-parent-inode", required=True, type=int)
    final_store.add_argument("--expected-parent-mode", required=True, type=int)
    final_store.add_argument("--destination-uid", required=True, type=int)
    final_store.add_argument("--destination-gid", required=True, type=int)
    final_store.add_argument("--pages-per-step", required=True, type=int)
    final_store.add_argument("--sleep-seconds", required=True, type=float)
    args = parser.parse_args(argv)
    if args.command == "stage-sqlite-runtime":
        package_root = _validate_new_package_destination(args.package_root)
        result = stage_sqlite_runtime_input(
            package_root,
            source_library=args.source_library,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "prepare-package":
        package_root = _validate_sqlite_staged_package_destination(args.package_root)
        _validate_principal_binding(
            god_uid=args.god_uid,
            overseer_uid=args.overseer_uid,
            overseer_gid=args.overseer_gid,
        )
        rollback_inputs: dict[str, str] = {}
        for raw in args.rollback_input:
            label, separator, path = raw.partition("=")
            if not separator or not label or not path or label in rollback_inputs:
                raise ActivationPackageError("rollback input must be a unique LABEL=PATH value")
            rollback_inputs[label] = path
        manifest = build_release_manifest(
            args.checkout,
            args.dependency_root,
            args.root_python,
            args.stdlib_root,
            args.sqlite_library,
        )
        _assert_current_sqlite_runtime(manifest)
        stage_release_payload(
            manifest,
            checkout=args.checkout,
            dependency_root=args.dependency_root,
            stdlib_root=args.stdlib_root,
            package_root=package_root,
        )
        render_systemd_units(
            manifest,
            templates_root=args.templates_root,
            output_root=package_root / "public" / "systemd",
            god_uid=args.god_uid,
            overseer_uid=args.overseer_uid,
            python_path=args.root_python,
        )
        stage_credentials(
            package_root,
            psychlo_secret_file=args.psychlo_secret_file,
            roadex_secret_file=args.roadex_secret_file,
            psychlo_bindings_file=args.psychlo_bindings_file,
        )
        rehearse_store_migration(
            package_root,
            source_store=args.source_store,
            pages_per_step=-1,
            sleep_seconds=0,
        )
        render_activation_contract(
            package_root,
            manifest,
            source_store=args.source_store,
            overseer_uid=args.overseer_uid,
            overseer_gid=args.overseer_gid,
            rollback_inputs=rollback_inputs,
        )
        result = {
            **activation_package_status(package_root),
            "packageRoot": str(package_root),
            "releaseManifestDigest": manifest["manifestDigest"],
            "sourceCommit": manifest["sourceCommit"],
        }
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "create-human-verifiers":
        package_root = _validate_existing_package_destination(args.package_root)
        admin_secret = getpass.getpass("Admin approval secret: ")
        admin_confirmation = getpass.getpass("Confirm admin approval secret: ")
        if not secrets.compare_digest(admin_secret, admin_confirmation):
            raise ActivationPackageError("admin approval secret confirmation does not match")
        roadex_secret = getpass.getpass("Roadex fixture approval secret: ")
        roadex_confirmation = getpass.getpass("Confirm Roadex fixture approval secret: ")
        if not secrets.compare_digest(roadex_secret, roadex_confirmation):
            raise ActivationPackageError("Roadex approval secret confirmation does not match")
        result = create_human_verifiers(
            package_root,
            admin_secret=admin_secret,
            roadex_secret=roadex_secret,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "finalize-package":
        result = finalize_activation_package(_validate_existing_package_destination(args.package_root))
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-package":
        result = verify_activation_package(
            _validate_existing_package_destination(args.package_root),
            args.expected_digest,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "status":
        result = activation_package_status(_validate_existing_package_destination(args.package_root))
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-rollback":
        result = verify_rollback_inputs(args.package_root)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-rollback-bundle":
        result = verify_rollback_bundle(
            bundle_root=args.bundle_root,
            rollback_manifest=args.rollback_manifest,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "restore-legacy-store-access":
        result = restore_legacy_store_access(
            source_store=args.source_store,
            expected_source_uid=args.expected_source_uid,
            expected_source_gid=args.expected_source_gid,
            expected_source_device=args.expected_source_device,
            expected_source_inode=args.expected_source_inode,
            expected_parent_device=args.expected_parent_device,
            expected_parent_inode=args.expected_parent_inode,
            expected_parent_mode=args.expected_parent_mode,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "record-activation-approval":
        result = record_activation_approval(
            _validate_existing_package_destination(args.package_root),
            expected_package_digest=args.expected_package_digest,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "run-approved-canary":
        package = _validate_existing_package_destination(args.package_root)
        approval = _load_activation_approval(package)
        digest = str(approval["packageDigest"])
        admin_secret = getpass.getpass("Admin approval secret for canary: ")
        roadex_secret = getpass.getpass("Roadex fixture approval secret for negative control: ")
        result = run_canary_acceptance(
            package,
            expected_package_digest=digest,
            admin_secret=admin_secret,
            roadex_secret=roadex_secret,
            attestation_path=_canary_attestation_path(digest),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-approved-staging":
        result = verify_approved_staging(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-approved-cutover":
        result = verify_approved_cutover(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-compatibility-token":
        result = verify_compatibility_token(
            source_token=args.source_token,
            target_token=args.target_token,
            expected_target_uid=args.expected_target_uid,
            expected_target_gid=args.expected_target_gid,
            expected_parent_device=args.expected_parent_device,
            expected_parent_inode=args.expected_parent_inode,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "execute-approved-activation":
        result = execute_approved_activation(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "execute-approved-rollback":
        result = execute_approved_rollback(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "prepare-final-store":
        report = prepare_final_store_migration(
            source_store=args.source_store,
            backup_store=args.backup_store,
            destination_store=args.destination_store,
            expected_source_device=args.expected_source_device,
            expected_source_inode=args.expected_source_inode,
            expected_source_uid=args.expected_source_uid,
            expected_source_gid=args.expected_source_gid,
            expected_parent_device=args.expected_parent_device,
            expected_parent_inode=args.expected_parent_inode,
            expected_parent_mode=args.expected_parent_mode,
            destination_uid=args.destination_uid,
            destination_gid=args.destination_gid,
            pages_per_step=args.pages_per_step,
            sleep_seconds=args.sleep_seconds,
        )
        print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    raise AssertionError("unreachable activation package command")


__all__ = [
    "ACTIVATION_CONTRACT_SCHEMA",
    "ActivationPackageError",
    "PACKAGE_MANIFEST_SCHEMA",
    "RELEASE_SCHEMA",
    "ROLLBACK_MANIFEST_SCHEMA",
    "activation_package_status",
    "build_release_manifest",
    "create_human_verifiers",
    "execute_approved_activation",
    "execute_approved_rollback",
    "finalize_activation_package",
    "prepare_final_store_migration",
    "record_activation_approval",
    "rehearse_store_migration",
    "render_activation_contract",
    "render_systemd_units",
    "restore_legacy_store_access",
    "run_canary_acceptance",
    "stage_credentials",
    "stage_release_payload",
    "verify_activation_package",
    "verify_approved_cutover",
    "verify_approved_staging",
    "verify_canary_attestation",
    "verify_compatibility_token",
    "verify_installed_staging",
    "verify_rollback_inputs",
    "verify_rollback_bundle",
]


if __name__ == "__main__":
    raise SystemExit(_main())
