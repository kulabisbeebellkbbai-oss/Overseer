"""Prepare and execute a closed, separately approved activation package.

Preparation commands perform only owner-scoped staging. Privileged phase
runners execute only sealed package commands after their independent approval;
the guarded principal bootstrap may invoke exact ``groupadd`` or ``useradd``
commands. The module never invokes sudo, a shell, or a gateway operation.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
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
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import termios
import time
from contextlib import contextmanager
from urllib.parse import quote
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .admin_authority import admin_authority_lock_path
from .activation_progress import classify_phase_b_command, emit_activation_progress
from .approval_auth import (
    create_approval_document,
    load_approval_verifier,
    write_approval_document,
)
from .maintenance_window import (
    MAINTENANCE_APPROVAL_SCHEMA,
    MAINTENANCE_CONTRACT_SCHEMA,
    MAINTENANCE_EXPECTED_ACTIVE_UNITS,
    MAINTENANCE_RUNNER_STATE_SCHEMA,
    MAINTENANCE_STORE_DESTINATIONS,
    MAINTENANCE_SUCCESSOR_SYSTEM_UNITS,
    MAINTENANCE_WRITER_UNITS,
    execute_maintenance_contract,
    maintenance_plan_digest,
    validate_maintenance_approval,
    validate_maintenance_contract,
)
from .store import SQLiteStore


RELEASE_SCHEMA = "overseer.dedicated-principal-release.v1"
ACTIVATION_CONTRACT_SCHEMA = "overseer.dedicated-principal-activation-contract.v2"
ROLLBACK_MANIFEST_SCHEMA = "overseer.dedicated-principal-rollback.v1"
PACKAGE_MANIFEST_SCHEMA = "overseer.dedicated-principal-package.v1"
ACTIVATION_APPROVAL_SCHEMA = "overseer.activation-package-approval.v2"
ACTIVATION_PHASE_APPROVAL_SCHEMA = "overseer.activation-phase-approval.v1"
ACTIVATION_RUNNER_STATE_SCHEMA = "overseer.activation-runner-state.v2"
MAINTENANCE_ROLLBACK_RETRY_APPROVAL_SCHEMA = (
    "overseer.maintenance-rollback-retry-approval.v1"
)
APPROVED_PACKAGE_RETIREMENT_INTENT_SCHEMA = (
    "overseer.approved-package-retirement-intent.v1"
)
APPROVED_PACKAGE_RETIREMENT_RECEIPT_SCHEMA = (
    "overseer.approved-package-retirement-receipt.v1"
)
LEGACY_ACTIVATION_APPROVAL_SCHEMA = "overseer.activation-package-approval.v1"
LEGACY_ACTIVATION_CONTRACT_SCHEMA = "overseer.dedicated-principal-activation-contract.v1"
LEGACY_ACTIVATION_RUNNER_STATE_SCHEMA = "overseer.activation-runner-state.v1"
ACTIVATION_PHASES = frozenset({"staging-canary", "cutover"})
RELEASES_ROOT = PurePosixPath("/opt/overseer/releases")
MAX_RELEASE_FILE_BYTES = 128 * 1024 * 1024
MAX_APPROVED_PACKAGE_IMPORT_BYTES = 16 * 1024 * 1024 * 1024
MIN_APPROVED_PACKAGE_IMPORT_HEADROOM_BYTES = 1024 * 1024 * 1024
MAX_STAGED_SECRET_BYTES = 512
MAINTENANCE_API_TIMEOUT_SECONDS = 5.0
MAINTENANCE_DASHBOARD_API_TIMEOUT_SECONDS = 60.0
MAINTENANCE_SCHEDULER_CONVERGENCE_TIMEOUT_SECONDS = 600.0
MAINTENANCE_SCHEDULER_POLL_INTERVAL_SECONDS = 15.0
MAX_MAINTENANCE_API_RESPONSE_BYTES = 16 * 1024 * 1024
APPROVED_OVERSEER_UID = 984
APPROVED_OVERSEER_GID = 984
APPROVED_PACKAGE_PARENT = Path("/home/god/.local/share/overseer/activation-packages")
APPROVED_EXECUTION_PACKAGE = Path("/var/lib/overseer-executor/approved-package")
CANARY_API_SOCKET = Path("/run/overseer-canary/api.sock")
CANARY_STATE_ROOT = Path("/var/lib/overseer-canary")
CANARY_INSTANCE_SCHEMA = "overseer.canary-instance.v1"
CANARY_INSTANCE_BYTES = 16
ACTIVATION_LOCK_FD_ENV = "OVERSEER_ACTIVATION_LOCK_FD"
CANARY_AUTHORIZATION_INPUT_SCHEMA = "overseer.canary-authorization-input.v1"
MAX_CANARY_AUTHORIZATION_INPUT_BYTES = 1024
_ACTIVE_EXECUTION_LOCK_DESCRIPTOR: int | None = None
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
CANARY_REQUIRED_STORE_TABLES = frozenset(
    {
        "admin_change_plans",
        "admin_executions",
        "admin_execution_claims",
        "admin_history_archives",
    }
)
COPIED_EXPRESSION_INDEX_SQL = {
    "idx_host_snapshots_captured_at": (
        "CREATE INDEX idx_host_snapshots_captured_at ON host_snapshots "
        "(julianday(json_extract(payload, '$.captured_at')) DESC, id DESC)"
    ),
}
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
_CONTROL_SOURCE_PATHS = (
    *(f"systemd/{name}" for name in _SYSTEMD_TEMPLATES),
    "config/admin-executor-allowlist.json",
)
_FORBIDDEN_COMMAND_INTERPRETERS = frozenset(
    {"sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh"}
)


class ActivationPackageError(ValueError):
    """Raised when a package input or staged artifact is unsafe or unstable."""


class _ActivationProgressEmissionError(ActivationPackageError):
    """Identify telemetry failures so recovery cannot silently suppress them."""


class _CleanupCommandFailure(ActivationPackageError):
    """Carry only the bounded classification of a failed cleanup command."""

    def __init__(self, failure: str) -> None:
        self.failure = failure
        super().__init__("staging cleanup command failed")


class _MaintenanceSchedulerConvergenceDeadline(ActivationPackageError):
    """Stop scheduler projection reads at the sealed convergence deadline."""


def _validate_principal_binding(
    *,
    god_uid: int,
    god_gid: int,
    overseer_uid: int,
    overseer_gid: int,
) -> None:
    if (overseer_uid, overseer_gid) != (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID):
        raise ActivationPackageError("dedicated principal must use the approved UID/GID 984")
    try:
        god = pwd.getpwnam("god")
    except KeyError as error:
        raise ActivationPackageError("approved god account is unavailable") from error
    if (god.pw_uid, god.pw_gid) != (god_uid, god_gid):
        raise ActivationPackageError("god UID/GID does not match the approved local account")
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


def _optional_user_by_name(name: str) -> pwd.struct_passwd | None:
    try:
        return pwd.getpwnam(name)
    except KeyError:
        return None


def _optional_user_by_uid(uid: int) -> pwd.struct_passwd | None:
    try:
        return pwd.getpwuid(uid)
    except KeyError:
        return None


def _optional_group_by_name(name: str) -> grp.struct_group | None:
    try:
        return grp.getgrnam(name)
    except KeyError:
        return None


def _optional_group_by_gid(gid: int) -> grp.struct_group | None:
    try:
        return grp.getgrgid(gid)
    except KeyError:
        return None


def _dedicated_principal_presence(
    *,
    uid: int,
    gid: int,
    home_dir: str,
    shell: str,
) -> tuple[bool, bool]:
    if (
        uid != APPROVED_OVERSEER_UID
        or gid != APPROVED_OVERSEER_GID
        or home_dir != "/var/lib/overseer"
        or shell != "/usr/sbin/nologin"
    ):
        raise ActivationPackageError("dedicated principal request is not approved")
    user_by_name = _optional_user_by_name("overseer")
    user_by_uid = _optional_user_by_uid(uid)
    if (user_by_name is None) != (user_by_uid is None):
        raise ActivationPackageError("dedicated principal user name or UID is assigned differently")
    if user_by_name is not None and (
        user_by_name.pw_name != "overseer"
        or user_by_name.pw_uid != uid
        or user_by_name.pw_gid != gid
        or user_by_name.pw_dir != home_dir
        or user_by_name.pw_shell != shell
        or user_by_uid is None
        or user_by_uid.pw_name != user_by_name.pw_name
        or user_by_uid.pw_uid != user_by_name.pw_uid
        or user_by_uid.pw_gid != user_by_name.pw_gid
        or user_by_uid.pw_dir != user_by_name.pw_dir
        or user_by_uid.pw_shell != user_by_name.pw_shell
    ):
        raise ActivationPackageError("dedicated principal user identity drifted")
    group_by_name = _optional_group_by_name("overseer")
    group_by_gid = _optional_group_by_gid(gid)
    if (group_by_name is None) != (group_by_gid is None):
        raise ActivationPackageError("dedicated principal group name or GID is assigned differently")
    if group_by_name is not None:
        if (
            group_by_name.gr_name != "overseer"
            or group_by_name.gr_gid != gid
            or group_by_gid is None
            or group_by_gid.gr_name != group_by_name.gr_name
            or group_by_gid.gr_gid != group_by_name.gr_gid
        ):
            raise ActivationPackageError("dedicated principal group identity drifted")
        if tuple(group_by_name.gr_mem) or tuple(group_by_gid.gr_mem):
            raise ActivationPackageError(
                "dedicated principal group membership is not empty"
            )
    enumerated_users = tuple(pwd.getpwall())
    enumerated_groups = tuple(grp.getgrall())
    name_users = tuple(item for item in enumerated_users if item.pw_name == "overseer")
    uid_users = tuple(item for item in enumerated_users if item.pw_uid == uid)
    name_groups = tuple(item for item in enumerated_groups if item.gr_name == "overseer")
    gid_groups = tuple(item for item in enumerated_groups if item.gr_gid == gid)
    if user_by_name is None:
        if name_users or uid_users:
            raise ActivationPackageError("dedicated principal user enumeration drifted")
    elif len(name_users) != 1 or len(uid_users) != 1 or name_users[0] != uid_users[0]:
        raise ActivationPackageError("dedicated principal user enumeration drifted")
    if group_by_name is None:
        if name_groups or gid_groups:
            raise ActivationPackageError("dedicated principal group enumeration drifted")
    elif len(name_groups) != 1 or len(gid_groups) != 1 or name_groups[0] != gid_groups[0]:
        raise ActivationPackageError("dedicated principal group enumeration drifted")
    primary_members = tuple(item.pw_name for item in enumerated_users if item.pw_gid == gid)
    expected_primary_members = ("overseer",) if user_by_name is not None else ()
    if primary_members != expected_primary_members:
        raise ActivationPackageError(
            "dedicated principal primary group membership is not exclusive"
        )
    if user_by_name is not None:
        foreign_explicit_memberships = tuple(
            item.gr_gid
            for item in enumerated_groups
            if item.gr_gid != gid and "overseer" in tuple(item.gr_mem)
        )
        try:
            effective_groups = tuple(sorted(os.getgrouplist("overseer", gid)))
        except OSError as error:
            raise ActivationPackageError(
                "dedicated principal supplementary groups could not be resolved"
            ) from error
        if foreign_explicit_memberships or effective_groups != (gid,):
            raise ActivationPackageError(
                "dedicated principal foreign supplementary group membership exists"
            )
    return user_by_name is not None, group_by_name is not None


def _principal_command_environment(lock_descriptor: int) -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        ACTIVATION_LOCK_FD_ENV: str(lock_descriptor),
    }


def _run_principal_creation_command(command: list[str], *, lock_descriptor: int) -> int:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=_principal_command_environment(lock_descriptor),
            pass_fds=(lock_descriptor,),
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActivationPackageError("dedicated principal creation command could not start") from error
    return result.returncode


def _validate_dedicated_principal_password_lock(*, lock_descriptor: int) -> None:
    try:
        result = subprocess.run(
            ["/usr/bin/passwd", "--status", "overseer"],
            capture_output=True,
            text=True,
            check=False,
            env=_principal_command_environment(lock_descriptor),
            pass_fds=(lock_descriptor,),
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActivationPackageError(
            "dedicated principal password lock status could not be read"
        ) from error
    fields = result.stdout.strip().split()
    if (
        result.returncode != 0
        or len(fields) < 2
        or fields[0] != "overseer"
        or fields[1] not in {"L", "LK"}
    ):
        raise ActivationPackageError("dedicated principal password is not locked")


def _ensure_dedicated_principal_identity(
    *,
    uid: int,
    gid: int,
    home_dir: str,
    shell: str,
    lock_descriptor: int,
) -> dict[str, object]:
    """Create missing dedicated-principal entries or reuse only their exact identity."""

    user_exists, group_exists = _dedicated_principal_presence(
        uid=uid,
        gid=gid,
        home_dir=home_dir,
        shell=shell,
    )
    if user_exists and not group_exists:
        raise ActivationPackageError("dedicated principal user exists without its approved group")
    initially_complete = user_exists and group_exists
    if not group_exists:
        returncode = _run_principal_creation_command(
            ["/usr/sbin/groupadd", "--system", "--gid", str(gid), "overseer"],
            lock_descriptor=lock_descriptor,
        )
        if returncode != 0:
            raise ActivationPackageError("dedicated principal group creation failed")
        user_exists, group_exists = _dedicated_principal_presence(
            uid=uid,
            gid=gid,
            home_dir=home_dir,
            shell=shell,
        )
        if not group_exists:
            raise ActivationPackageError("dedicated principal group creation did not persist")
    if not user_exists:
        returncode = _run_principal_creation_command(
            [
                "/usr/sbin/useradd",
                "--system",
                "--uid",
                str(uid),
                "--gid",
                str(gid),
                "--home-dir",
                home_dir,
                "--shell",
                shell,
                "overseer",
            ],
            lock_descriptor=lock_descriptor,
        )
        if returncode != 0:
            raise ActivationPackageError("dedicated principal user creation failed")
        user_exists, group_exists = _dedicated_principal_presence(
            uid=uid,
            gid=gid,
            home_dir=home_dir,
            shell=shell,
        )
    if not user_exists or not group_exists:
        raise ActivationPackageError("dedicated principal creation did not produce the approved identity")
    _validate_dedicated_principal_password_lock(lock_descriptor=lock_descriptor)
    return {
        "status": "existing" if initially_complete else "created",
        "user": "overseer",
        "uid": uid,
        "group": "overseer",
        "gid": gid,
    }


def ensure_dedicated_principal(
    *,
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Run provisioning only as an exact active staging or maintenance command."""

    package = Path(package_root).resolve()
    maintenance_state = _load_maintenance_state() if os.geteuid() == 0 else None
    if (
        maintenance_state is not None
        and maintenance_state.get("stage") == "switchServices"
        and maintenance_state.get("status") in {"before_command", "command_running"}
    ):
        contract, lock_descriptor = _require_maintenance_active_sealed_command(
            package,
            command_name="ensure-dedicated-principal",
            expected_options={"--package-root": str(package)},
        )
        try:
            validate_maintenance_contract(contract)
        except ValueError as error:
            raise ActivationPackageError(
                "maintenance dedicated-principal binding is invalid"
            ) from error
    else:
        contract, lock_descriptor = _require_active_phase_command(
            package,
            phase="staging-canary",
            command_name="ensure-dedicated-principal",
            expected_options={"--package-root": str(package)},
        )
        _validate_contract_principal_schema(contract)
    return _ensure_dedicated_principal_identity(
        uid=APPROVED_OVERSEER_UID,
        gid=APPROVED_OVERSEER_GID,
        home_dir="/var/lib/overseer",
        shell="/usr/sbin/nologin",
        lock_descriptor=lock_descriptor,
    )


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
        ("/usr/bin/git", "-C", str(checkout), *args),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        env={
            "HOME": "/nonexistent",
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_NO_REPLACE_OBJECTS": "1",
        },
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


def _git_tree_inventory(
    checkout: Path,
    *,
    tree: str,
    pathspec: str,
) -> tuple[dict[str, str], ...]:
    if len(tree) != 40 or set(tree) - _HEX:
        raise ActivationPackageError("reviewed Git tree identity is invalid")
    safe_pathspec = _safe_relative(pathspec)
    raw = _git(checkout, "ls-tree", "-r", "-z", tree, "--", safe_pathspec)
    result: list[dict[str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", 1)
            encoded_mode, encoded_type, encoded_object = metadata.split(b" ", 2)
            mode = encoded_mode.decode("ascii")
            object_type = encoded_type.decode("ascii")
            object_id = encoded_object.decode("ascii").lower()
            path = _safe_relative(encoded_path.decode("utf-8", "strict"))
        except (ValueError, UnicodeError) as error:
            raise ActivationPackageError("reviewed Git tree entry is invalid") from error
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or len(object_id) != 40
            or set(object_id) - _HEX
            or not (path == safe_pathspec or path.startswith(f"{safe_pathspec}/"))
        ):
            raise ActivationPackageError("reviewed Git tree entry is not an approved file")
        result.append(
            {
                "sourcePath": path,
                "sourceObject": object_id,
                "sourceGitMode": mode,
            }
        )
    return tuple(sorted(result, key=lambda item: item["sourcePath"]))


def _git_blob(checkout: Path, object_id: str) -> bytes:
    if len(object_id) != 40 or set(object_id) - _HEX:
        raise ActivationPackageError("reviewed Git blob identity is invalid")
    try:
        size = int(_git(checkout, "cat-file", "-s", object_id).strip().decode("ascii"))
    except (ValueError, UnicodeError) as error:
        raise ActivationPackageError("reviewed Git blob size is invalid") from error
    if size < 0 or size > MAX_RELEASE_FILE_BYTES:
        raise ActivationPackageError("reviewed Git blob exceeds the per-file bound")
    content = _git(checkout, "cat-file", "blob", object_id)
    git_digest = hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content
    ).hexdigest()
    if len(content) != size or git_digest != object_id:
        raise ActivationPackageError("reviewed Git blob content does not match its identity")
    return content


def _source_inventory(checkout: Path, *, tree: str) -> tuple[dict[str, str], ...]:
    result = _git_tree_inventory(
        checkout,
        tree=tree,
        pathspec="src/overseer",
    )
    if not result:
        raise ActivationPackageError("reviewed runtime source inventory is empty")
    return result


def _git_file_entry(
    checkout: Path,
    tree_entry: Mapping[str, str],
    *,
    release_path: str | None,
) -> dict[str, object]:
    source_path = _safe_relative(str(tree_entry.get("sourcePath", "")))
    source_object = str(tree_entry.get("sourceObject", ""))
    source_mode = str(tree_entry.get("sourceGitMode", ""))
    if source_mode not in {"100644", "100755"}:
        raise ActivationPackageError("reviewed Git file mode is invalid")
    content = _git_blob(checkout, source_object)
    result: dict[str, object] = {
        "sourcePath": source_path,
        "sourceObject": source_object,
        "sourceGitMode": source_mode,
        "sha256": _sha256(content),
        "size": len(content),
        "mode": 0o555 if source_mode == "100755" else 0o444,
    }
    if release_path is not None:
        result.update(
            {
                "releasePath": _safe_relative(release_path),
                "sourceKind": "checkout",
            }
        )
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
    *,
    expected_commit: str,
    expected_tree: str,
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
    if (
        len(expected_commit) != 40
        or set(expected_commit) - _HEX
        or len(expected_tree) != 40
        or set(expected_tree) - _HEX
    ):
        raise ActivationPackageError("approved Git identity is invalid")
    if _git(selected_checkout, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ActivationPackageError("reviewed Git checkout must be clean")
    commit = _git(selected_checkout, "rev-parse", "HEAD^{commit}").strip().decode("ascii").lower()
    if commit != expected_commit:
        raise ActivationPackageError("reviewed Git commit does not match approval")
    tree = _git(selected_checkout, "rev-parse", f"{commit}^{{tree}}").strip().decode("ascii").lower()
    if tree != expected_tree:
        raise ActivationPackageError("reviewed Git tree does not match the approved commit")

    files = [
        _git_file_entry(
            selected_checkout,
            item,
            release_path=f"app/{item['sourcePath']}",
        )
        for item in _source_inventory(selected_checkout, tree=tree)
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
    control_files: list[dict[str, object]] = []
    for path in _CONTROL_SOURCE_PATHS:
        entries = _git_tree_inventory(
            selected_checkout,
            tree=tree,
            pathspec=path,
        )
        if len(entries) != 1 or entries[0]["sourcePath"] != path:
            raise ActivationPackageError("reviewed activation control inventory is incomplete")
        control_files.append(
            _git_file_entry(
                selected_checkout,
                entries[0],
                release_path=None,
            )
        )
    unsigned: dict[str, object] = {
        "schemaVersion": RELEASE_SCHEMA,
        "sourceCommit": commit,
        "sourceTree": tree,
        "files": files,
        "controlFiles": control_files,
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
        or _git(selected_checkout, "rev-parse", f"{commit}^{{tree}}").strip().decode("ascii").lower() != tree
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
    protected_gateway_ca_file: str | os.PathLike[str] | None = None,
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
    gateway_ca: bytes | None = None
    gateway_ca_path: Path | None = None
    if protected_gateway_ca_file is not None:
        gateway_ca_path = Path(protected_gateway_ca_file)
        gateway_ca, gateway_ca_metadata = _stable_read(gateway_ca_path)
        if (
            gateway_ca_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(gateway_ca_metadata.st_mode) != 0o644
            or not gateway_ca.startswith(b"-----BEGIN CERTIFICATE-----\n")
            or not gateway_ca.rstrip().endswith(b"-----END CERTIFICATE-----")
        ):
            raise ActivationPackageError(
                "Protected Gateway CA snapshot is invalid"
            )
        try:
            import ssl

            ssl.create_default_context(cadata=gateway_ca.decode("ascii", "strict"))
        except (UnicodeDecodeError, ValueError, ssl.SSLError) as error:
            raise ActivationPackageError(
                "Protected Gateway CA snapshot is not a valid trust anchor"
            ) from error

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
    if gateway_ca is not None:
        staged[public_config / "protected-gateway-ca.crt"] = (gateway_ca, 0o644)
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
        "protectedGatewayCa": (
            None
            if gateway_ca is None or gateway_ca_path is None
            else _credential_entry(
                target="/etc/overseer/protected-gateway-ca.crt",
                content=gateway_ca,
                source=str(gateway_ca_path),
                mode=0o644,
            )
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
    allowed_owners: frozenset[tuple[int, int]] | None = None,
    allowed_modes: frozenset[int] = frozenset({0o600}),
) -> os.stat_result:
    if expected_uid is not None and allowed_owners is not None:
        raise ActivationPackageError(f"{label} owner policy is ambiguous")
    if allowed_owners is not None and not allowed_owners:
        raise ActivationPackageError(f"{label} owner policy is empty")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ActivationPackageError(f"{label} could not be inspected") from error
    if path.is_symlink():
        raise ActivationPackageError(f"{label} must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ActivationPackageError(f"{label} must be a single-link regular file")
    selected_uid = os.geteuid() if expected_uid is None else expected_uid
    if allowed_owners is not None:
        owner_is_allowed = (metadata.st_uid, metadata.st_gid) in allowed_owners
    else:
        owner_is_allowed = metadata.st_uid == selected_uid
    if not owner_is_allowed:
        raise ActivationPackageError(f"{label} has an unexpected owner")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in allowed_modes:
        if allowed_modes == frozenset({0o600}):
            raise ActivationPackageError(f"{label} must have mode 0600")
        raise ActivationPackageError(f"{label} has an unsupported mode")
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


def _validate_migration_destination_directory(
    target_parent: Path,
    *,
    destination_uid: int,
    destination_gid: int,
) -> os.stat_result:
    try:
        parent_metadata = target_parent.lstat()
    except OSError as error:
        raise ActivationPackageError(
            "migration destination directory could not be inspected"
        ) from error
    if (
        target_parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or (parent_metadata.st_uid, parent_metadata.st_gid)
        != (destination_uid, destination_gid)
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        raise ActivationPackageError(
            "migration destination directory identity or mode is invalid"
        )
    return parent_metadata


def _ensure_migration_destination_directory(
    target_parent: Path,
    *,
    destination_uid: int,
    destination_gid: int,
) -> None:
    """Require the sealed owner, creating only a current-user destination."""

    try:
        target_parent.lstat()
    except FileNotFoundError:
        if destination_uid != os.geteuid() or destination_gid != os.getegid():
            raise ActivationPackageError(
                "migration destination directory must be provisioned for its sealed owner"
            )
        _ensure_directory(target_parent)
    except OSError as error:
        raise ActivationPackageError(
            "migration destination directory could not be inspected"
        ) from error
    _validate_migration_destination_directory(
        target_parent,
        destination_uid=destination_uid,
        destination_gid=destination_gid,
    )


def _lock_migration_destination_directory(
    target_parent: Path,
    *,
    destination_uid: int,
    destination_gid: int,
    executor_uid: int,
    executor_gid: int,
) -> tuple[int, tuple[int, int]]:
    """Revoke destination-principal writes and bind the directory inode."""

    expected = _validate_migration_destination_directory(
        target_parent,
        destination_uid=destination_uid,
        destination_gid=destination_gid,
    )
    descriptor = -1
    transition_started = False
    try:
        descriptor = os.open(
            target_parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        lexical = target_parent.lstat()
        if (
            target_parent.is_symlink()
            or not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
            or (lexical.st_dev, lexical.st_ino) != (expected.st_dev, expected.st_ino)
            or (opened.st_uid, opened.st_gid)
            != (destination_uid, destination_gid)
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise ActivationPackageError(
                "migration destination directory changed while opening"
            )
        # Revoke all access before ownership changes so a partial transition
        # never leaves the destination principal with a writable namespace.
        os.fchmod(descriptor, 0)
        transition_started = True
        os.fchown(descriptor, executor_uid, executor_gid)
        os.fchmod(descriptor, 0o700)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        lexical = target_parent.lstat()
        if (
            (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino)
            or (lexical.st_dev, lexical.st_ino) != (expected.st_dev, expected.st_ino)
            or (opened.st_uid, opened.st_gid) != (executor_uid, executor_gid)
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise ActivationPackageError(
                "migration destination directory lock could not be verified"
            )
        return descriptor, (expected.st_dev, expected.st_ino)
    except BaseException:
        restore_error: BaseException | None = None
        if transition_started:
            owner_error: BaseException | None = None
            try:
                os.fchmod(descriptor, 0)
                os.fchown(descriptor, destination_uid, destination_gid)
            except BaseException as failure:
                owner_error = failure
            try:
                current = os.fstat(descriptor)
                os.fchmod(
                    descriptor,
                    0o700
                    if (current.st_uid, current.st_gid)
                    == (destination_uid, destination_gid)
                    else 0,
                )
                os.fsync(descriptor)
            except BaseException as failure:
                restore_error = failure
            current = os.fstat(descriptor)
            if (
                (current.st_uid, current.st_gid)
                != (destination_uid, destination_gid)
                or stat.S_IMODE(current.st_mode) != 0o700
            ):
                restore_error = restore_error or owner_error or ActivationPackageError(
                    "migration destination ownership was not restored"
                )
        if descriptor >= 0:
            os.close(descriptor)
        if restore_error is not None:
            raise ActivationPackageError(
                "migration destination lock failed and ownership restoration failed"
            ) from restore_error
        raise


def _restore_migration_destination_directory(
    descriptor: int,
    target_parent: Path,
    *,
    expected_identity: tuple[int, int],
    destination_uid: int,
    destination_gid: int,
    executor_uid: int,
    executor_gid: int,
) -> None:
    """Restore the sealed destination owner after the offline handoff."""

    opened = os.fstat(descriptor)
    lexical = target_parent.lstat()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != expected_identity
        or (lexical.st_dev, lexical.st_ino) != expected_identity
        or (opened.st_uid, opened.st_gid)
        not in {
            (executor_uid, executor_gid),
            (destination_uid, destination_gid),
        }
        or stat.S_IMODE(opened.st_mode) not in {0, 0o700}
    ):
        raise ActivationPackageError(
            "migration destination directory changed before ownership restoration"
        )
    os.fchmod(descriptor, 0)
    os.fchown(descriptor, destination_uid, destination_gid)
    os.fchmod(descriptor, 0o700)
    os.fsync(descriptor)
    opened = os.fstat(descriptor)
    lexical = target_parent.lstat()
    if (
        (opened.st_dev, opened.st_ino) != expected_identity
        or (lexical.st_dev, lexical.st_ino) != expected_identity
        or (opened.st_uid, opened.st_gid) != (destination_uid, destination_gid)
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise ActivationPackageError(
            "migration destination directory ownership restoration failed"
        )


def _relock_migration_destination_directory(
    descriptor: int,
    target_parent: Path,
    *,
    expected_identity: tuple[int, int],
    destination_uid: int,
    destination_gid: int,
    executor_uid: int,
    executor_gid: int,
) -> None:
    """Revoke destination access again before any migration recovery work."""

    opened = os.fstat(descriptor)
    lexical = target_parent.lstat()
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (opened.st_dev, opened.st_ino) != expected_identity
        or (lexical.st_dev, lexical.st_ino) != expected_identity
        or (opened.st_uid, opened.st_gid)
        not in {
            (executor_uid, executor_gid),
            (destination_uid, destination_gid),
        }
        or stat.S_IMODE(opened.st_mode) not in {0, 0o700}
    ):
        raise ActivationPackageError(
            "migration destination directory changed before recovery relock"
        )
    os.fchmod(descriptor, 0)
    os.fchown(descriptor, executor_uid, executor_gid)
    os.fchmod(descriptor, 0o700)
    os.fsync(descriptor)
    opened = os.fstat(descriptor)
    lexical = target_parent.lstat()
    if (
        (opened.st_dev, opened.st_ino) != expected_identity
        or (lexical.st_dev, lexical.st_ino) != expected_identity
        or (opened.st_uid, opened.st_gid) != (executor_uid, executor_gid)
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise ActivationPackageError(
            "migration destination directory recovery relock failed"
        )


def _migration_destination_recovery_is_quiesced(
    descriptor: int,
    target_parent: Path,
    *,
    expected_identity: tuple[int, int],
    executor_uid: int,
    executor_gid: int,
) -> bool:
    """Return whether recovery may proceed without destination-principal writes."""

    try:
        opened = os.fstat(descriptor)
        lexical = target_parent.lstat()
    except OSError:
        return False
    mode = stat.S_IMODE(opened.st_mode)
    return (
        stat.S_ISDIR(opened.st_mode)
        and (opened.st_dev, opened.st_ino) == expected_identity
        and (lexical.st_dev, lexical.st_ino) == expected_identity
        and (
            mode == 0
            or (
                (opened.st_uid, opened.st_gid) == (executor_uid, executor_gid)
                and mode == 0o700
            )
        )
    )


def _copy_store(
    source: Path,
    target: Path,
    *,
    destination_uid: int,
    destination_gid: int,
) -> None:
    source_metadata = _validate_store_artifact(source, label="rehearsal backup")
    _ensure_migration_destination_directory(
        target.parent,
        destination_uid=destination_uid,
        destination_gid=destination_gid,
    )
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


def _approved_expression_indexes_from_connection(
    connection: sqlite3.Connection,
) -> list[str]:
    present: list[str] = []
    for name, expected_sql in sorted(COPIED_EXPRESSION_INDEX_SQL.items()):
        row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?",
            (name,),
        ).fetchone()
        if row is None:
            continue
        if str(row[0]) != expected_sql:
            raise ActivationPackageError(
                f"copied migration expression index schema is unapproved: {name}"
            )
        present.append(name)
    return present


def _normalize_copied_expression_indexes(path: Path) -> dict[str, object]:
    """Rebuild exact approved expression indexes only on a copied store."""

    _validate_store_artifact(path, label="copied migration store")
    connection = sqlite3.connect(_sqlite_uri(path, mode="rw"), uri=True, timeout=5)
    reindexed: list[str] = []
    try:
        quick_rows = [str(row[0]) for row in connection.execute("PRAGMA quick_check(1)")]
        if quick_rows != ["ok"]:
            raise ActivationPackageError(
                "copied migration store failed pre-reindex quick_check"
            )
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint is None or int(checkpoint[0]) != 0:
            raise ActivationPackageError(
                "copied migration store WAL could not be normalized"
            )
        journal = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if journal is None or str(journal[0]).lower() != "delete":
            raise ActivationPackageError(
                "copied migration store did not leave WAL journal mode"
            )
        for name in _approved_expression_indexes_from_connection(connection):
            quoted = name.replace('"', '""')
            connection.execute(f'REINDEX "{quoted}"')
            reindexed.append(name)
        connection.commit()
    finally:
        connection.close()

    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        try:
            metadata = sidecar.lstat()
        except FileNotFoundError:
            continue
        if (
            sidecar.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ActivationPackageError(
                "copied migration store retained an unsafe SQLite sidecar"
            )
        sidecar.unlink()
    os.chmod(path, 0o600)
    return {
        "preReindexQuickCheck": "ok",
        "reindexedExpressionIndexes": reindexed,
        "journalMode": "delete",
        "sourceMutationPerformed": False,
    }


def _migration_evidence_from_connection(
    connection: sqlite3.Connection,
    *,
    counted_tables: tuple[str, ...] | None = None,
) -> tuple[dict[str, int], dict[str, object]]:
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


def _migration_evidence(
    path: Path,
    *,
    counted_tables: tuple[str, ...] | None = None,
) -> tuple[dict[str, int], dict[str, object]]:
    connection = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=5)
    try:
        return _migration_evidence_from_connection(
            connection,
            counted_tables=counted_tables,
        )
    finally:
        connection.close()


def _require_canary_store_schema(schema: object) -> None:
    if not isinstance(schema, Mapping):
        raise ActivationPackageError(
            "migration rehearsal is missing canary-required store tables"
        )
    table_names = schema.get("tableNames")
    if not isinstance(table_names, list) or any(
        not isinstance(name, str) for name in table_names
    ) or not CANARY_REQUIRED_STORE_TABLES.issubset(table_names):
        raise ActivationPackageError(
            "migration rehearsal is missing canary-required store tables"
        )


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

    copy_normalization = _normalize_copied_expression_indexes(backup)
    backup_integrity = _integrity_check(backup)
    row_counts_before, schema_before = _migration_evidence(backup)
    backup_digest, backup_size = _hash_file(backup)
    _copy_store(
        backup,
        migrated,
        destination_uid=os.geteuid(),
        destination_gid=os.getegid(),
    )
    store = SQLiteStore(migrated)
    store.close()
    migrated_integrity = _integrity_check(migrated)
    row_counts_after, schema_after = _migration_evidence(
        migrated,
        counted_tables=tuple(str(name) for name in schema_before["countedTables"]),
    )
    _require_canary_store_schema(schema_after)
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
            "path": str(source.resolve()),
            "device": before.st_dev,
            "inode": before.st_ino,
            "uid": before.st_uid,
            "gid": before.st_gid,
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
        "copyNormalization": copy_normalization,
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


def _processes_with_open_inode(
    device: int,
    inode: int,
    *,
    excluded_pids: frozenset[int] = frozenset(),
) -> tuple[int, ...]:
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
        process_id = int(process.name)
        if process_id in excluded_pids:
            continue
        descriptors = process / "fd"
        try:
            open_descriptors = tuple(descriptors.iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as error:
            if os.geteuid() == 0:
                raise ActivationPackageError(
                    "open-process preflight could not inspect a live process descriptor table"
                ) from error
            continue
        for descriptor in open_descriptors:
            try:
                metadata = descriptor.stat()
            except (FileNotFoundError, ProcessLookupError):
                continue
            except PermissionError as error:
                if os.geteuid() == 0:
                    raise ActivationPackageError(
                        "open-process preflight could not inspect a live process descriptor"
                    ) from error
                continue
            if (metadata.st_dev, metadata.st_ino) == (device, inode):
                result.add(process_id)
                break
    return tuple(sorted(result))


def _processes_with_mapped_inode(
    device: int,
    inode: int,
    *,
    excluded_pids: frozenset[int] = frozenset(),
) -> tuple[int, ...]:
    """Return processes mapping the exact inode, including closed-fd mappings."""

    result: set[int] = set()
    try:
        process_directories = tuple(Path("/proc").iterdir())
    except OSError as error:
        raise ActivationPackageError("mapped-process preflight could not inspect /proc") from error
    for process in process_directories:
        if not process.name.isdecimal():
            continue
        process_id = int(process.name)
        if process_id in excluded_pids:
            continue
        try:
            lines = (process / "maps").read_bytes().splitlines()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as error:
            if os.geteuid() == 0:
                raise ActivationPackageError(
                    "mapped-process preflight could not inspect a relevant live process"
                ) from error
            continue
        for line in lines:
            fields = line.split(maxsplit=5)
            if len(fields) < 5 or not fields[4].isdigit() or int(fields[4]) != inode:
                continue
            try:
                major_text, minor_text = fields[3].split(b":", 1)
                mapped_device = os.makedev(int(major_text, 16), int(minor_text, 16))
            except (ValueError, OSError):
                continue
            if mapped_device == device:
                result.add(process_id)
                break
    return tuple(sorted(result))


def _legacy_inode_activity(
    identities: tuple[tuple[int, int], ...],
    *,
    include_open_files: bool,
    exclude_current_process: bool = False,
) -> tuple[int, ...]:
    excluded_pids = frozenset({os.getpid()}) if exclude_current_process else frozenset()
    result: set[int] = set()
    for device, inode in identities:
        if include_open_files:
            result.update(
                _processes_with_open_inode(
                    device,
                    inode,
                    excluded_pids=excluded_pids,
                )
            )
        result.update(
            _processes_with_mapped_inode(
                device,
                inode,
                excluded_pids=excluded_pids,
            )
        )
    return tuple(sorted(result))


@contextmanager
def _kernel_read_lease_barrier(
    descriptors: tuple[int, ...],
) -> object:
    """Hold Linux read leases so hidden writable references fail closed."""

    required_constants = ("F_SETLEASE", "F_GETLEASE", "F_SETOWN")
    if any(not hasattr(fcntl, name) for name in required_constants):
        raise ActivationPackageError("kernel read lease support is unavailable")
    unique_descriptors = tuple(dict.fromkeys(descriptors))
    if not unique_descriptors:
        raise ActivationPackageError("kernel read lease barrier has no artifacts")

    break_requested = False

    def mark_break_requested(_signum: int, _frame: object) -> None:
        nonlocal break_requested
        break_requested = True

    try:
        previous_handler = signal.getsignal(signal.SIGIO)
        signal.signal(signal.SIGIO, mark_break_requested)
    except (OSError, RuntimeError, ValueError) as error:
        raise ActivationPackageError(
            "kernel read lease break monitoring could not be installed"
        ) from error

    leased: list[int] = []

    def require_intact() -> None:
        if break_requested:
            raise ActivationPackageError(
                "kernel read lease barrier received a write-open request"
            )
        try:
            intact = all(
                fcntl.fcntl(descriptor, fcntl.F_GETLEASE) == fcntl.F_RDLCK
                for descriptor in leased
            )
        except OSError as error:
            raise ActivationPackageError(
                "kernel read lease barrier could not be verified"
            ) from error
        if not intact:
            raise ActivationPackageError("kernel read lease barrier was lost")

    try:
        try:
            for descriptor in unique_descriptors:
                fcntl.fcntl(descriptor, fcntl.F_SETOWN, os.getpid())
                fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_RDLCK)
                leased.append(descriptor)
        except OSError as error:
            raise ActivationPackageError(
                "kernel read lease barrier rejected a writable reference or mapping"
            ) from error
        require_intact()
        yield require_intact
        require_intact()
    finally:
        release_error: OSError | None = None
        for descriptor in reversed(leased):
            try:
                fcntl.fcntl(descriptor, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            except OSError as error:
                release_error = release_error or error
        try:
            signal.signal(signal.SIGIO, previous_handler)
        except (OSError, RuntimeError, ValueError) as error:
            if release_error is None:
                release_error = OSError(str(error))
        if release_error is not None:
            raise ActivationPackageError(
                "kernel read lease barrier could not be released cleanly"
            ) from release_error


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _artifact_identity(path: Path) -> tuple[int, ...] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    return _metadata_identity(metadata)


def _remove_executor_migration_sidecars(
    paths: tuple[Path, ...],
    *,
    executor_uid: int,
    executor_gid: int,
) -> list[str]:
    """Remove only owner-only sidecars attributable to this executor."""

    removed: list[str] = []
    for path in paths:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid)
            != (executor_uid, executor_gid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            continue
        descriptor = -1
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            if _metadata_identity(os.fstat(descriptor)) != _metadata_identity(
                metadata
            ):
                continue
            try:
                lexical = path.lstat()
            except FileNotFoundError:
                continue
            if _metadata_identity(lexical) != _metadata_identity(metadata):
                continue
            path.unlink()
            removed.append(str(path))
        except FileNotFoundError:
            continue
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return removed


def _require_root_activation() -> None:
    if os.geteuid() != 0:
        raise ActivationPackageError("final store migration must run as root after explicit activation approval")


def _activation_root_identity() -> tuple[int, int]:
    return 0, 0


def _activation_parent_lock_mode() -> int:
    return 0o500


def _legacy_store_paths(source: Path) -> tuple[Path, ...]:
    return (source, Path(f"{source}-wal"), Path(f"{source}-shm"))


def _restore_legacy_store_access_unchecked(
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


def restore_legacy_store_access(
    *,
    package_root: str | os.PathLike[str],
    source_store: str | os.PathLike[str],
    expected_source_uid: int,
    expected_source_gid: int,
    expected_source_device: int,
    expected_source_inode: int,
    expected_parent_device: int,
    expected_parent_inode: int,
    expected_parent_mode: int,
) -> dict[str, object]:
    """Restore legacy access only as the exact active sealed rollback command."""

    source = Path(source_store).resolve()
    _require_active_rollback_command(
        package_root,
        command_name="restore-legacy-store-access",
        expected_options={
            "--source-store": str(source),
            "--expected-source-uid": str(expected_source_uid),
            "--expected-source-gid": str(expected_source_gid),
            "--expected-source-device": str(expected_source_device),
            "--expected-source-inode": str(expected_source_inode),
            "--expected-parent-device": str(expected_parent_device),
            "--expected-parent-inode": str(expected_parent_inode),
            "--expected-parent-mode": str(expected_parent_mode),
        },
    )
    return _restore_legacy_store_access_unchecked(
        source_store=source,
        expected_source_uid=expected_source_uid,
        expected_source_gid=expected_source_gid,
        expected_source_device=expected_source_device,
        expected_source_inode=expected_source_inode,
        expected_parent_device=expected_parent_device,
        expected_parent_inode=expected_parent_inode,
        expected_parent_mode=expected_parent_mode,
    )


def prepare_final_store_migration(
    *,
    package_root: str | os.PathLike[str],
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
    """Create the final backup and migrated store after legacy writers stop."""

    _require_active_phase_command(
        package_root,
        phase="cutover",
        command_name="prepare-final-store",
        expected_options={
            "--package-root": str(Path(package_root).resolve()),
            "--source-store": str(Path(source_store).resolve()),
            "--backup-store": str(Path(backup_store).resolve()),
            "--destination-store": str(Path(destination_store).resolve()),
            "--expected-source-device": str(expected_source_device),
            "--expected-source-inode": str(expected_source_inode),
            "--expected-source-uid": str(expected_source_uid),
            "--expected-source-gid": str(expected_source_gid),
            "--expected-parent-device": str(expected_parent_device),
            "--expected-parent-inode": str(expected_parent_inode),
            "--expected-parent-mode": str(expected_parent_mode),
            "--destination-uid": str(destination_uid),
            "--destination-gid": str(destination_gid),
            "--pages-per-step": str(pages_per_step),
            "--sleep-seconds": str(sleep_seconds),
        },
    )
    return _prepare_store_migration_unchecked(
        package_root=package_root,
        source_store=source_store,
        backup_store=backup_store,
        destination_store=destination_store,
        expected_source_device=expected_source_device,
        expected_source_inode=expected_source_inode,
        expected_source_uid=expected_source_uid,
        expected_source_gid=expected_source_gid,
        expected_parent_device=expected_parent_device,
        expected_parent_inode=expected_parent_inode,
        expected_parent_mode=expected_parent_mode,
        destination_uid=destination_uid,
        destination_gid=destination_gid,
        pages_per_step=pages_per_step,
        sleep_seconds=sleep_seconds,
    )


def _prepare_store_migration_unchecked(
    *,
    package_root: str | os.PathLike[str],
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
    store_kind: str = "overseer",
    result_status: str = "final_migration_complete",
) -> dict[str, object]:
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
    if store_kind not in {"overseer", "copy-only"}:
        raise ActivationPackageError("maintenance store kind is unsupported")
    if not isinstance(result_status, str) or not result_status:
        raise ActivationPackageError("store migration result status is invalid")
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
    legacy_inode_identities = (
        (source_metadata.st_dev, source_metadata.st_ino),
        *(
            (identity[0], identity[1])
            for identity in sidecar_before.values()
            if identity is not None
        ),
    )
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
    backup_sidecars = tuple(Path(f"{backup}{suffix}") for suffix in ("-wal", "-shm"))
    if any(path.exists() or path.is_symlink() for path in backup_sidecars):
        raise ActivationPackageError("final backup sidecar destination already exists")
    destination_sidecars = tuple(
        Path(f"{destination}{suffix}") for suffix in ("-wal", "-shm")
    )
    destination_unsafe_marker = backup.with_suffix(
        f"{backup.suffix}.destination-namespace-unsafe.json"
    )
    if any(path.exists() or path.is_symlink() for path in destination_sidecars):
        raise ActivationPackageError(
            "final migrated store sidecar destination already exists"
        )
    if destination_unsafe_marker.exists() or destination_unsafe_marker.is_symlink():
        raise ActivationPackageError(
            "migration destination unsafe marker already exists"
        )

    root_uid, root_gid = _activation_root_identity()
    lock_acquired = False
    parent_descriptor: int | None = None
    destination_parent_descriptor: int | None = None
    destination_parent_identity: tuple[int, int] | None = None
    destination_parent_locked = False
    source_descriptor: int | None = None
    legacy_descriptors: list[int] = []
    captured_descriptor_identities: dict[int, tuple[int, ...]] = {}
    try:
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_parent = os.fstat(parent_descriptor)
        if (
            opened_parent.st_dev != expected_parent_device
            or opened_parent.st_ino != expected_parent_inode
            or opened_parent.st_uid != expected_source_uid
            or opened_parent.st_gid != expected_source_gid
            or stat.S_IMODE(opened_parent.st_mode) != expected_parent_mode
        ):
            raise ActivationPackageError("final migration source parent changed while opening")
        os.fchown(parent_descriptor, root_uid, root_gid)
        os.fchmod(parent_descriptor, _activation_parent_lock_mode())
        bound_parent = Path(f"/proc/self/fd/{parent_descriptor}")
        bound_source = bound_parent / source.name
        try:
            post_lock_source = _validate_store_artifact(
                bound_source,
                label="post-lock final migration source SQLite store",
                expected_uid=expected_source_uid,
            )
            lexical_parent = parent.lstat()
            lexical_source = source.lstat()
            if (
                lexical_parent.st_dev != expected_parent_device
                or lexical_parent.st_ino != expected_parent_inode
                or post_lock_source.st_dev != expected_source_device
                or post_lock_source.st_ino != expected_source_inode
                or post_lock_source.st_gid != expected_source_gid
                or lexical_source.st_dev != expected_source_device
                or lexical_source.st_ino != expected_source_inode
            ):
                raise ActivationPackageError(
                    "final migration source identity drifted while acquiring the parent lock"
                )
        except BaseException:
            os.fchown(parent_descriptor, expected_source_uid, expected_source_gid)
            os.fchmod(parent_descriptor, expected_parent_mode)
            raise
        lock_acquired = True
        active_legacy_processes = _legacy_inode_activity(
            legacy_inode_identities,
            include_open_files=True,
        )
        if active_legacy_processes:
            raise ActivationPackageError(
                "final migration SQLite artifacts still have an open process or mapping"
            )

        bound_paths = tuple(bound_parent / path.name for path in _legacy_store_paths(source))
        for original_path, path in zip(_legacy_store_paths(source), bound_paths, strict=True):
            if path.exists() or path.is_symlink():
                metadata = path.lstat()
                if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise ActivationPackageError("legacy store changed while acquiring the quiescence lock")
                expected_identity = (
                    (
                        source_metadata.st_dev,
                        source_metadata.st_ino,
                        source_metadata.st_mode,
                        source_metadata.st_uid,
                        source_metadata.st_gid,
                        source_metadata.st_nlink,
                        source_metadata.st_size,
                        source_metadata.st_mtime_ns,
                        source_metadata.st_ctime_ns,
                    )
                    if original_path == source
                    else sidecar_before[str(original_path)]
                )
                observed_identity = _artifact_identity(path)
                if expected_identity is None or observed_identity != expected_identity:
                    raise ActivationPackageError(
                        "legacy store changed while acquiring the quiescence lock"
                    )
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    os.close(descriptor)
                    raise ActivationPackageError(
                        "legacy store changed while opening under the quiescence lock"
                    )
                legacy_descriptors.append(descriptor)
                captured_descriptor_identities[descriptor] = expected_identity
                if original_path == source:
                    source_descriptor = descriptor
            elif original_path == source or sidecar_before[str(original_path)] is not None:
                raise ActivationPackageError(
                    "legacy store changed while acquiring the quiescence lock"
                )

        if source_descriptor is None:
            raise ActivationPackageError("locked legacy authority descriptor is unavailable")
        lease_context = _kernel_read_lease_barrier(tuple(legacy_descriptors))
        with lease_context as require_lease_intact:
            if any(
                _metadata_identity(os.fstat(descriptor)) != expected_identity
                for descriptor, expected_identity in captured_descriptor_identities.items()
            ):
                raise ActivationPackageError(
                    "legacy store descriptor changed before the kernel lease barrier"
                )
            for original_path, path in zip(
                _legacy_store_paths(source),
                bound_paths,
                strict=True,
            ):
                expected_identity = (
                    (
                        source_metadata.st_dev,
                        source_metadata.st_ino,
                        source_metadata.st_mode,
                        source_metadata.st_uid,
                        source_metadata.st_gid,
                        source_metadata.st_nlink,
                        source_metadata.st_size,
                        source_metadata.st_mtime_ns,
                        source_metadata.st_ctime_ns,
                    )
                    if original_path == source
                    else sidecar_before[str(original_path)]
                )
                if expected_identity is not None and _artifact_identity(path) != expected_identity:
                    raise ActivationPackageError(
                        "legacy store pathname changed before the kernel lease barrier"
                    )
            for descriptor in legacy_descriptors:
                os.fchown(descriptor, root_uid, root_gid)
                os.fchmod(descriptor, 0o600)
            descriptor_by_identity = {
                (metadata.st_dev, metadata.st_ino): descriptor
                for descriptor, metadata in (
                    (descriptor, os.fstat(descriptor))
                    for descriptor in legacy_descriptors
                )
            }
            for path in bound_paths:
                if not path.exists():
                    continue
                metadata = path.lstat()
                if (
                    path.is_symlink()
                    or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                ):
                    raise ActivationPackageError(
                        "legacy store changed under the kernel lease barrier"
                    )
                if (metadata.st_dev, metadata.st_ino) not in descriptor_by_identity:
                    raise ActivationPackageError(
                        "legacy store pathname changed under the kernel lease barrier"
                    )
                os.chmod(path, 0o400)
            quiesced_inode_identities = tuple(descriptor_by_identity)
            locked_source = os.fstat(source_descriptor)
            if _legacy_inode_activity(
                quiesced_inode_identities,
                include_open_files=True,
                exclude_current_process=True,
            ):
                raise ActivationPackageError(
                    "final migration SQLite artifacts retained an open process or mapping"
                )
            require_lease_intact()
            source_digest_before = _stream_hash_open_regular(
                source_descriptor,
                label="locked legacy authority store",
                guard=require_lease_intact,
            )
            _copy_open_regular_to_new_path(
                source_descriptor,
                backup,
                label="locked legacy authority store",
                guard=require_lease_intact,
            )
            wal = bound_paths[1]
            source_wal_present = wal.exists() and wal.stat().st_size > 0
            if source_wal_present:
                wal_metadata = wal.lstat()
                wal_descriptor = descriptor_by_identity.get(
                    (wal_metadata.st_dev, wal_metadata.st_ino)
                )
                if wal_descriptor is None:
                    raise ActivationPackageError(
                        "locked legacy WAL descriptor is unavailable"
                    )
                _copy_open_regular_to_new_path(
                    wal_descriptor,
                    backup_sidecars[0],
                    label="locked legacy WAL",
                    guard=require_lease_intact,
                )
            require_lease_intact()
            checkpoint_connection = sqlite3.connect(
                _sqlite_uri(backup, mode="rw"),
                uri=True,
                timeout=5,
            )
            try:
                row = checkpoint_connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                journal_row = checkpoint_connection.execute(
                    "PRAGMA journal_mode=DELETE"
                ).fetchone()
            finally:
                checkpoint_connection.close()
            if row is None or int(row[0]) != 0:
                raise ActivationPackageError(
                    "isolated final backup WAL checkpoint did not quiesce"
                )
            if journal_row is None or str(journal_row[0]).lower() != "delete":
                raise ActivationPackageError(
                    "isolated final backup did not leave WAL journal mode"
                )
            checkpoint = (
                "isolated_backup_truncate_complete"
                if source_wal_present
                else "not_required"
            )
            require_lease_intact()
            if backup_sidecars[0].exists() and backup_sidecars[0].stat().st_size:
                raise ActivationPackageError(
                    "isolated final backup retained WAL content after checkpoint"
                )
            for path in backup_sidecars:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            os.chmod(backup, 0o600)
            source_digest_after = _stream_hash_open_regular(
                source_descriptor,
                label="locked legacy authority store",
                guard=require_lease_intact,
            )
            if source_digest_before != source_digest_after:
                raise ActivationPackageError(
                    "final migration source content changed during backup"
                )
        for descriptor in legacy_descriptors:
            os.close(descriptor)
        legacy_descriptors.clear()
        if _legacy_inode_activity(quiesced_inode_identities, include_open_files=True):
            raise ActivationPackageError(
                "final migration SQLite artifacts acquired another open process or mapping"
            )
        sidecar_after = {
            str(original): _artifact_identity(bound)
            for original, bound in zip(sidecars, bound_paths[1:], strict=True)
        }

        if store_kind == "overseer":
            copy_normalization = _normalize_copied_expression_indexes(backup)
        else:
            copy_normalization = {
                "preReindexQuickCheck": "not-run",
                "reindexedExpressionIndexes": [],
                "journalMode": "delete",
                "sourceMutationPerformed": False,
            }
        backup_integrity = _integrity_check(backup)
        before_counts, schema_before = _migration_evidence(backup)
        backup_digest, backup_size = _hash_file(backup)
        destination_parent_descriptor, destination_parent_identity = (
            _lock_migration_destination_directory(
                destination.parent,
                destination_uid=destination_uid,
                destination_gid=destination_gid,
                executor_uid=root_uid,
                executor_gid=root_gid,
            )
        )
        destination_parent_locked = True
        if destination_parent_identity == (expected_parent_device, expected_parent_inode):
            raise ActivationPackageError(
                "migration source and destination directories must be distinct"
            )
        if destination.exists() or destination.is_symlink():
            raise ActivationPackageError(
                "final migrated store destination appeared after namespace lock"
            )
        if any(path.exists() or path.is_symlink() for path in destination_sidecars):
            raise ActivationPackageError(
                "final migrated store sidecar appeared after namespace lock"
            )
        _copy_store(
            backup,
            destination,
            destination_uid=root_uid,
            destination_gid=root_gid,
        )
        if store_kind == "overseer":
            migrated_store = SQLiteStore(destination)
            migrated_store.close()
            # SQLiteStore enables WAL while applying schema migrations.  This
            # helper is still running as the activation executor, so those
            # sidecars belong to root rather than to the sealed destination
            # principal.  Return the offline copy to a sidecar-free DELETE
            # journal namespace before changing its owner; the successor will
            # create fresh WAL/SHM artifacts under its own identity.
            _normalize_copied_expression_indexes(destination)
        migrated_integrity = _integrity_check(destination)
        after_counts, schema_after = _migration_evidence(
            destination,
            counted_tables=tuple(str(name) for name in schema_before["countedTables"]),
        )
        if store_kind == "copy-only" and (
            schema_after != schema_before or after_counts != before_counts
        ):
            raise ActivationPackageError(
                "copy-only maintenance store changed schema or retained row counts"
            )
        for table, count in before_counts.items():
            if table in {"schema_migrations", "agent_schema_migrations"}:
                if after_counts.get(table, 0) < count:
                    raise ActivationPackageError(f"schema history lost rows during final migration: {table}")
            elif after_counts.get(table) != count:
                raise ActivationPackageError(f"final migration changed retained row count: {table}")
        migrated_digest, migrated_size = _hash_file(destination)
        if any(
            path.exists() or path.is_symlink()
            for path in destination_sidecars
        ):
            raise ActivationPackageError(
                "final migrated store retained a sidecar before ownership handoff"
            )
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
            "status": result_status,
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
            "copyNormalization": copy_normalization,
            "quiescenceLock": "kernel-read-leases-and-write-access-revoked",
            "kernelReadLeaseBarrier": "held-through-source-hashes-and-backup",
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
        final_parent = parent.lstat()
        final_source = source.lstat()
        if (
            final_parent.st_dev != expected_parent_device
            or final_parent.st_ino != expected_parent_inode
            or final_source.st_dev != expected_source_device
            or final_source.st_ino != expected_source_inode
        ):
            raise ActivationPackageError("final migration source pathname drifted while locked")
        report_path = backup.with_suffix(f"{backup.suffix}.report.json")
        _write_new(report_path, _canonical(report) + b"\n", 0o600)
        os.fchown(parent_descriptor, root_uid, expected_source_gid)
        os.fchmod(parent_descriptor, 0o555)
        _restore_migration_destination_directory(
            destination_parent_descriptor,
            destination.parent,
            expected_identity=destination_parent_identity,
            destination_uid=destination_uid,
            destination_gid=destination_gid,
            executor_uid=root_uid,
            executor_gid=root_gid,
        )
        destination_parent_locked = False
        return report
    except BaseException as original_error:
        recovery_failures: list[tuple[str, BaseException]] = []
        destination_recovery_safe = True
        if (
            destination_parent_locked
            and destination_parent_descriptor is not None
            and destination_parent_identity is not None
        ):
            try:
                _relock_migration_destination_directory(
                    destination_parent_descriptor,
                    destination.parent,
                    expected_identity=destination_parent_identity,
                    destination_uid=destination_uid,
                    destination_gid=destination_gid,
                    executor_uid=root_uid,
                    executor_gid=root_gid,
                )
            except BaseException as error:
                recovery_failures.append(("destination namespace relock", error))
                destination_recovery_safe = (
                    _migration_destination_recovery_is_quiesced(
                        destination_parent_descriptor,
                        destination.parent,
                        expected_identity=destination_parent_identity,
                        executor_uid=root_uid,
                        executor_gid=root_gid,
                    )
                )
        if lock_acquired and destination_recovery_safe:
            try:
                _restore_legacy_store_access_unchecked(
                    source_store=source,
                    expected_source_uid=expected_source_uid,
                    expected_source_gid=expected_source_gid,
                    expected_source_device=expected_source_device,
                    expected_source_inode=expected_source_inode,
                    expected_parent_device=expected_parent_device,
                    expected_parent_inode=expected_parent_inode,
                    expected_parent_mode=expected_parent_mode,
                )
            except BaseException as error:
                recovery_failures.append(("legacy store access restoration", error))
        elif lock_acquired:
            recovery_failures.append(
                (
                    "legacy store access restoration skipped",
                    ActivationPackageError(
                        "destination namespace is not safely quiesced"
                    ),
                )
            )
        if not destination_recovery_safe:
            try:
                _write_new(
                    destination_unsafe_marker,
                    _canonical(
                        {
                            "schemaVersion": (
                                "overseer.maintenance-destination-namespace-unsafe.v1"
                            ),
                            "status": "destination_namespace_unsafe",
                            "destinationDb": str(destination.resolve()),
                        }
                    )
                    + b"\n",
                    0o600,
                )
            except BaseException as error:
                recovery_failures.append(
                    ("destination unsafe marker persistence", error)
                )
        if destination_recovery_safe:
            try:
                if destination_parent_descriptor is not None:
                    _remove_executor_migration_sidecars(
                        destination_sidecars,
                        executor_uid=root_uid,
                        executor_gid=root_gid,
                    )
            except BaseException as error:
                recovery_failures.append(("destination sidecar cleanup", error))
            cleanup_targets = [
                backup,
                *backup_sidecars,
                backup.with_suffix(f"{backup.suffix}.report.json"),
                destination_unsafe_marker,
            ]
            if destination_parent_descriptor is not None:
                cleanup_targets.insert(0, destination)
            for target in cleanup_targets:
                try:
                    target.unlink()
                except FileNotFoundError:
                    pass
                except BaseException as error:
                    recovery_failures.append(("migration artifact cleanup", error))
            if (
                destination_parent_locked
                and destination_parent_descriptor is not None
                and destination_parent_identity is not None
            ):
                try:
                    _restore_migration_destination_directory(
                        destination_parent_descriptor,
                        destination.parent,
                        expected_identity=destination_parent_identity,
                        destination_uid=destination_uid,
                        destination_gid=destination_gid,
                        executor_uid=root_uid,
                        executor_gid=root_gid,
                    )
                    destination_parent_locked = False
                except BaseException as error:
                    recovery_failures.append(
                        ("destination ownership restoration", error)
                    )
        if recovery_failures:
            labels = ", ".join(label for label, _error in recovery_failures)
            failure = ActivationPackageError(
                f"final migration failed and recovery also failed: {labels}"
            )
            for label, error in recovery_failures:
                failure.add_note(f"{label}: {type(error).__name__}: {error}")
            raise failure from original_error
        raise
    finally:
        for descriptor in legacy_descriptors:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if destination_parent_descriptor is not None:
            os.close(destination_parent_descriptor)


def prepare_maintenance_store_copy(
    *,
    package_root: str | os.PathLike[str],
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
    store_kind: str,
    pages_per_step: int = 128,
    sleep_seconds: float = 0.02,
) -> dict[str, object]:
    """Prepare a migrated copy and retain the source as locked rollback authority."""

    if store_kind not in {"overseer", "copy-only"}:
        raise ActivationPackageError("maintenance store kind is unsupported")
    options = {
        "--package-root": str(Path(package_root).resolve()),
        "--source-store": str(Path(source_store).resolve()),
        "--backup-store": str(Path(backup_store).resolve()),
        "--destination-store": str(Path(destination_store).resolve()),
        "--expected-source-device": str(expected_source_device),
        "--expected-source-inode": str(expected_source_inode),
        "--expected-source-uid": str(expected_source_uid),
        "--expected-source-gid": str(expected_source_gid),
        "--expected-parent-device": str(expected_parent_device),
        "--expected-parent-inode": str(expected_parent_inode),
        "--expected-parent-mode": str(expected_parent_mode),
        "--destination-uid": str(destination_uid),
        "--destination-gid": str(destination_gid),
        "--store-kind": store_kind,
        "--pages-per-step": str(pages_per_step),
        "--sleep-seconds": str(sleep_seconds),
    }
    _require_maintenance_active_sealed_command(
        package_root,
        command_name="prepare-maintenance-store-copy",
        expected_options=options,
    )
    # Maintenance copies are prepared in isolated destinations; unlike the
    # already-provisioned cutover paths, their private parents may not exist.
    _ensure_directory(
        Path(backup_store).resolve().parent,
        enforce_existing_mode=False,
    )
    _ensure_migration_destination_directory(
        Path(destination_store).resolve().parent,
        destination_uid=destination_uid,
        destination_gid=destination_gid,
    )
    return _prepare_store_migration_unchecked(
        package_root=package_root,
        source_store=source_store,
        backup_store=backup_store,
        destination_store=destination_store,
        expected_source_device=expected_source_device,
        expected_source_inode=expected_source_inode,
        expected_source_uid=expected_source_uid,
        expected_source_gid=expected_source_gid,
        expected_parent_device=expected_parent_device,
        expected_parent_inode=expected_parent_inode,
        expected_parent_mode=expected_parent_mode,
        destination_uid=destination_uid,
        destination_gid=destination_gid,
        pages_per_step=pages_per_step,
        sleep_seconds=sleep_seconds,
        store_kind=store_kind,
        result_status="maintenance_store_copy_complete",
    )


def prepare_maintenance_stores(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Prepare the exact three offline stores sealed into the maintenance plan."""

    package = Path(package_root).resolve()
    _require_maintenance_active_sealed_command(
        package,
        command_name="prepare-maintenance-stores",
        expected_options={"--package-root": str(package)},
    )
    contract = _read_maintenance_contract_file(package)
    bindings = contract.get("storeBindings")
    if not isinstance(bindings, list) or len(bindings) != 3:
        raise ActivationPackageError("maintenance store bindings are invalid")
    reports: list[dict[str, object]] = []
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise ActivationPackageError("maintenance store binding is invalid")
        identity = binding.get("sourceIdentity")
        if not isinstance(identity, Mapping):
            raise ActivationPackageError("maintenance store source identity is invalid")
        backup = Path(str(binding.get("backupDb", ""))).resolve()
        destination = Path(str(binding.get("destinationDb", ""))).resolve()
        _ensure_directory(backup.parent, enforce_existing_mode=False)
        _ensure_migration_destination_directory(
            destination.parent,
            destination_uid=APPROVED_OVERSEER_UID,
            destination_gid=APPROVED_OVERSEER_GID,
        )
        reports.append(
            _prepare_store_migration_unchecked(
                package_root=package,
                source_store=str(binding.get("sourceDb", "")),
                backup_store=backup,
                destination_store=destination,
                expected_source_device=int(identity["device"]),
                expected_source_inode=int(identity["inode"]),
                expected_source_uid=int(identity["uid"]),
                expected_source_gid=int(identity["gid"]),
                expected_parent_device=int(identity["parentDevice"]),
                expected_parent_inode=int(identity["parentInode"]),
                expected_parent_mode=int(identity["parentMode"]),
                destination_uid=APPROVED_OVERSEER_UID,
                destination_gid=APPROVED_OVERSEER_GID,
                pages_per_step=128,
                sleep_seconds=0.02,
                store_kind=str(binding.get("storeKind", "")),
                result_status="maintenance_store_copy_complete",
            )
        )
    return {"status": "maintenance_stores_prepared", "stores": reports}


def _require_maintenance_active_rollback_command(
    package_root: str | os.PathLike[str],
    *,
    command_name: str,
    expected_options: Mapping[str, str],
) -> dict[str, object]:
    """Require one exact command in the sealed maintenance rollback sequence."""

    _require_inherited_activation_lock()
    package = Path(package_root).resolve()
    approval = _load_maintenance_approval(package)
    package_digest = str(approval["packageDigest"])
    contract = _sealed_maintenance_contract(package, package_digest=package_digest)
    plan_digest = maintenance_plan_digest(contract)
    state = _load_maintenance_state()
    if (
        state is None
        or state.get("schemaVersion") != MAINTENANCE_RUNNER_STATE_SCHEMA
        or state.get("packageDigest") != package_digest
        or state.get("planDigest") != plan_digest
        or state.get("stage") not in {"rollback", "earlyRollback"}
        or state.get("status")
        not in {"before_rollback_command", "rollback_command_running"}
        or state.get("writersStopped") is not True
    ):
        raise ActivationPackageError(
            f"{command_name} requires the active sealed maintenance rollback"
        )
    command_field = (
        "earlyRollbackCommands"
        if state.get("stage") == "earlyRollback"
        else "rollbackCommands"
    )
    commands = _contract_commands(contract, command_field)
    index = state.get("commandIndex")
    if type(index) is not int or not 0 <= index < len(commands):
        raise ActivationPackageError(
            "maintenance rollback state is not bound to a sealed command"
        )
    command = commands[index]
    if state.get("commandDigest") != _sha256(_canonical(command)):
        raise ActivationPackageError(
            "maintenance rollback state is not bound to the sealed command"
        )
    if _sealed_command_options(command, command_name=command_name) != dict(
        expected_options
    ):
        raise ActivationPackageError(
            "maintenance rollback call does not match the sealed command arguments"
        )
    return contract


def _lock_maintenance_destination_namespace_for_rollback(
    bindings: list[object],
) -> tuple[int, list[str]]:
    """Quarantine failed successor stores before restoring legacy writers."""

    destinations: list[Path] = []
    markers: list[Path] = []
    for binding in bindings:
        if not isinstance(binding, Mapping):
            raise ActivationPackageError(
                "maintenance rollback store binding is invalid"
            )
        destination = Path(str(binding.get("destinationDb", ""))).resolve()
        backup = Path(str(binding.get("backupDb", ""))).resolve()
        if not destination.is_absolute() or not backup.is_absolute():
            raise ActivationPackageError(
                "maintenance rollback destination binding is invalid"
            )
        destinations.append(destination)
        markers.append(
            backup.with_suffix(f"{backup.suffix}.destination-namespace-unsafe.json")
        )
    parents = {destination.parent for destination in destinations}
    if len(parents) != 1:
        raise ActivationPackageError(
            "maintenance rollback destinations do not share one namespace"
        )
    target_parent = next(iter(parents))
    root_uid, root_gid = _activation_root_identity()
    try:
        initial = target_parent.lstat()
    except FileNotFoundError:
        if any(marker.exists() or marker.is_symlink() for marker in markers):
            raise ActivationPackageError(
                "maintenance rollback destination namespace is missing with an unsafe marker"
            )
        if _processes_for_uid(APPROVED_OVERSEER_UID):
            raise ActivationPackageError(
                "service principal process exists while rollback destination is missing"
            )
        if any(
            path.exists() or path.is_symlink()
            for destination in destinations
            for path in _legacy_store_paths(destination)
        ):
            raise ActivationPackageError(
                "maintenance rollback destination namespace disappeared"
            )
        return -1, []
    except OSError as error:
        raise ActivationPackageError(
            "maintenance rollback destination namespace could not be inspected"
        ) from error
    if (
        target_parent.is_symlink()
        or not stat.S_ISDIR(initial.st_mode)
        or (initial.st_uid, initial.st_gid)
        not in {
            (root_uid, root_gid),
            (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID),
        }
        or stat.S_IMODE(initial.st_mode) not in {0, 0o700}
    ):
        raise ActivationPackageError(
            "maintenance rollback destination namespace is unsafe"
        )
    descriptor = os.open(
        target_parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    identity = (initial.st_dev, initial.st_ino)
    try:
        opened = os.fstat(descriptor)
        lexical = target_parent.lstat()
        if (
            (opened.st_dev, opened.st_ino) != identity
            or (lexical.st_dev, lexical.st_ino) != identity
        ):
            raise ActivationPackageError(
                "maintenance rollback destination namespace changed while opening"
            )
        _relock_migration_destination_directory(
            descriptor,
            target_parent,
            expected_identity=identity,
            destination_uid=APPROVED_OVERSEER_UID,
            destination_gid=APPROVED_OVERSEER_GID,
            executor_uid=root_uid,
            executor_gid=root_gid,
        )
        running = _processes_for_uid(APPROVED_OVERSEER_UID)
        if running:
            raise ActivationPackageError(
                "service principal process exists during maintenance rollback"
            )
        artifact_identities: list[tuple[int, int]] = []
        for destination in destinations:
            for path in _legacy_store_paths(destination):
                if not path.exists() and not path.is_symlink():
                    continue
                metadata = _validate_store_artifact(
                    path,
                    label="maintenance rollback destination SQLite artifact",
                    allowed_owners=frozenset(
                        {
                            (root_uid, root_gid),
                            (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID),
                        }
                    ),
                )
                artifact_identities.append((metadata.st_dev, metadata.st_ino))
        if artifact_identities and _legacy_inode_activity(
            tuple(artifact_identities),
            include_open_files=True,
        ):
            raise ActivationPackageError(
                "maintenance rollback destination SQLite artifact remains open"
            )
        resolved_markers: list[str] = []
        for marker, destination in zip(markers, destinations, strict=True):
            if not marker.exists() and not marker.is_symlink():
                continue
            metadata = _validate_store_artifact(
                marker,
                label="maintenance destination unsafe marker",
                expected_uid=root_uid,
            )
            if metadata.st_gid != root_gid:
                raise ActivationPackageError(
                    "maintenance destination unsafe marker group is invalid"
                )
            raw, _metadata = _stable_read(marker)
            try:
                document = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ActivationPackageError(
                    "maintenance destination unsafe marker is invalid"
                ) from error
            if document != {
                "schemaVersion": (
                    "overseer.maintenance-destination-namespace-unsafe.v1"
                ),
                "status": "destination_namespace_unsafe",
                "destinationDb": str(destination),
            }:
                raise ActivationPackageError(
                    "maintenance destination unsafe marker drifted"
                )
            resolved_markers.append(str(marker))
        return descriptor, resolved_markers
    except BaseException:
        os.close(descriptor)
        raise


def _maintenance_rollback_directory_identity(
    metadata: os.stat_result,
) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _maintenance_rollback_archive_paths(
    contract: Mapping[str, object],
) -> tuple[Path, Path, Path, Path]:
    evidence_value = contract.get("evidenceRoot")
    if not isinstance(evidence_value, str) or not evidence_value.startswith("/"):
        raise ActivationPackageError(
            "maintenance rollback evidence root is invalid"
        )
    evidence_root = Path(evidence_value)
    workspace = evidence_root.parent
    if workspace == evidence_root or evidence_root.name != "preserved":
        raise ActivationPackageError(
            "maintenance rollback evidence root is invalid"
        )
    root_uid, root_gid = _activation_root_identity()
    try:
        metadata = workspace.lstat()
    except OSError as error:
        raise ActivationPackageError(
            "maintenance rollback evidence workspace is unavailable"
        ) from error
    if (
        workspace.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != (root_uid, root_gid)
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ActivationPackageError(
            "maintenance rollback evidence workspace is unsafe"
        )
    return (
        workspace,
        workspace / "failed-successor-store",
        workspace / "failed-successor-store-intent.json",
        workspace / "failed-successor-store-receipt.json",
    )


def _maintenance_rollback_record(
    path: Path,
    expected: Mapping[str, object],
    *,
    label: str,
) -> dict[str, object]:
    payload = _canonical(dict(expected)) + b"\n"
    root_uid, root_gid = _activation_root_identity()
    try:
        path.lstat()
    except FileNotFoundError:
        _write_new(path, payload, 0o600)
        _fsync_package_directory(path.parent)
        raw, metadata = _stable_read(path)
    except OSError as error:
        raise ActivationPackageError(f"{label} could not be read") from error
    else:
        raw, metadata = _stable_read(path)
    if (
        raw != payload
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (metadata.st_uid, metadata.st_gid) != (root_uid, root_gid)
        or metadata.st_nlink != 1
    ):
        raise ActivationPackageError(f"{label} binding is invalid")
    return dict(expected)


def _maintenance_rollback_replacement_identity(
    path: Path,
    *,
    normalize_root_lock: bool = False,
) -> dict[str, int]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ActivationPackageError(
            "maintenance rollback replacement namespace is unavailable"
        ) from error
    root_uid, root_gid = _activation_root_identity()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid)
        not in (
            {(APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID), (root_uid, root_gid)}
            if normalize_root_lock
            else {(APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID)}
        )
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ActivationPackageError(
            "maintenance rollback replacement namespace is unsafe"
        )
    try:
        if any(path.iterdir()):
            raise ActivationPackageError(
                "maintenance rollback replacement namespace is not empty"
            )
    except OSError as error:
        raise ActivationPackageError(
            "maintenance rollback replacement namespace could not be inventoried"
        ) from error
    if (
        normalize_root_lock
        and (metadata.st_uid, metadata.st_gid) == (root_uid, root_gid)
        and (root_uid, root_gid)
        != (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID)
    ):
        try:
            os.chown(
                path,
                APPROVED_OVERSEER_UID,
                APPROVED_OVERSEER_GID,
                follow_symlinks=False,
            )
            _fsync_package_directory(path.parent)
            metadata = path.lstat()
        except OSError as error:
            raise ActivationPackageError(
                "maintenance rollback replacement ownership could not be restored"
            ) from error
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid)
            != (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ActivationPackageError(
                "maintenance rollback replacement ownership is invalid"
            )
    return _maintenance_rollback_directory_identity(metadata)


def _maintenance_rollback_create_empty_namespace(path: Path) -> dict[str, int]:
    root_uid, root_gid = _activation_root_identity()
    try:
        parent = path.parent.lstat()
    except OSError as error:
        raise ActivationPackageError(
            "maintenance rollback destination parent is unavailable"
        ) from error
    if (
        path.parent.is_symlink()
        or not stat.S_ISDIR(parent.st_mode)
        or (parent.st_uid, parent.st_gid) != (root_uid, root_gid)
    ):
        raise ActivationPackageError(
            "maintenance rollback destination parent is unsafe"
        )
    descriptor = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (
            parent.st_dev,
            parent.st_ino,
        ):
            raise ActivationPackageError(
                "maintenance rollback destination parent changed"
            )
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=descriptor)
        except FileExistsError:
            pass
        os.chown(
            path.name,
            APPROVED_OVERSEER_UID,
            APPROVED_OVERSEER_GID,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        os.chmod(
            path.name,
            0o700,
            dir_fd=descriptor,
            follow_symlinks=False,
        )
        os.fsync(descriptor)
    except OSError as error:
        raise ActivationPackageError(
            "maintenance rollback replacement namespace could not be created"
        ) from error
    finally:
        os.close(descriptor)
    return _maintenance_rollback_replacement_identity(path)


def _archive_maintenance_destination_namespace_for_rollback(
    contract: Mapping[str, object],
    bindings: list[object],
    destination_descriptor: int,
) -> dict[str, object]:
    """Durably preserve a failed successor and recreate its empty namespace."""

    destinations = [
        Path(str(binding.get("destinationDb", ""))).resolve()
        for binding in bindings
        if isinstance(binding, Mapping)
    ]
    if len(destinations) != len(bindings) or not destinations:
        raise ActivationPackageError(
            "maintenance rollback destination binding is invalid"
        )
    parents = {destination.parent for destination in destinations}
    if len(parents) != 1:
        raise ActivationPackageError(
            "maintenance rollback destinations do not share one namespace"
        )
    source = next(iter(parents))
    workspace, archive, intent_path, receipt_path = (
        _maintenance_rollback_archive_paths(contract)
    )
    archive_exists = archive.exists() or archive.is_symlink()
    intent_exists = intent_path.exists() or intent_path.is_symlink()
    receipt_exists = receipt_path.exists() or receipt_path.is_symlink()
    if archive_exists and not intent_exists:
        raise ActivationPackageError(
            "maintenance rollback archive has conflicting unbound state"
        )
    if receipt_exists and not intent_exists:
        raise ActivationPackageError(
            "maintenance rollback archive has conflicting receipt state"
        )

    source_identity: dict[str, int] | None = None
    if not intent_exists:
        if destination_descriptor >= 0:
            opened = os.fstat(destination_descriptor)
            try:
                lexical = source.lstat()
            except OSError as error:
                raise ActivationPackageError(
                    "maintenance rollback destination namespace changed"
                ) from error
            if (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino):
                raise ActivationPackageError(
                    "maintenance rollback destination namespace changed"
                )
            source_identity = _maintenance_rollback_directory_identity(opened)
        intent = {
            "schemaVersion": "overseer.maintenance-failed-successor-intent.v1",
            "status": "prepared",
            "contractDigest": _sha256(_canonical(contract)),
            "sourceDirectory": str(source),
            "archiveDirectory": str(archive),
            "destinationNames": sorted(path.name for path in destinations),
            "archiveExpected": source_identity is not None,
            "sourceIdentity": source_identity,
        }
        _maintenance_rollback_record(
            intent_path,
            intent,
            label="maintenance rollback archive intent",
        )
    else:
        try:
            intent_raw, _intent_metadata = _stable_read(intent_path)
            intent = json.loads(intent_raw)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ActivationPackageError(
                "maintenance rollback archive intent is invalid"
            ) from error
        expected_common = {
            "schemaVersion": "overseer.maintenance-failed-successor-intent.v1",
            "status": "prepared",
            "contractDigest": _sha256(_canonical(contract)),
            "sourceDirectory": str(source),
            "archiveDirectory": str(archive),
            "destinationNames": sorted(path.name for path in destinations),
        }
        if (
            not isinstance(intent, dict)
            or any(intent.get(key) != value for key, value in expected_common.items())
            or type(intent.get("archiveExpected")) is not bool
            or (
                intent.get("archiveExpected") is True
                and not isinstance(intent.get("sourceIdentity"), Mapping)
            )
            or (
                intent.get("archiveExpected") is False
                and intent.get("sourceIdentity") is not None
            )
        ):
            raise ActivationPackageError(
                "maintenance rollback archive intent binding is invalid"
            )
        _maintenance_rollback_record(
            intent_path,
            intent,
            label="maintenance rollback archive intent",
        )
        source_identity_value = intent.get("sourceIdentity")
        source_identity = (
            dict(source_identity_value)
            if isinstance(source_identity_value, Mapping)
            else None
        )

    if receipt_exists and archive_exists is not intent["archiveExpected"]:
        raise ActivationPackageError(
            "maintenance rollback archive has conflicting receipt state"
        )

    if intent["archiveExpected"] is True and not archive_exists:
        if destination_descriptor < 0 or source_identity is None:
            raise ActivationPackageError(
                "maintenance rollback archive source disappeared"
            )
        opened_identity = _maintenance_rollback_directory_identity(
            os.fstat(destination_descriptor)
        )
        if opened_identity != source_identity:
            raise ActivationPackageError(
                "maintenance rollback archive source identity drifted"
            )
        try:
            _rename_package_no_replace(source, archive)
        except (FileExistsError, OSError) as error:
            raise ActivationPackageError(
                "maintenance rollback archive publication failed"
            ) from error
        _fsync_package_directory(source.parent)
        _fsync_package_directory(workspace)
        archive_exists = True
    elif intent["archiveExpected"] is False and archive_exists:
        raise ActivationPackageError(
            "maintenance rollback archive has conflicting unexpected state"
        )

    archive_identity: dict[str, int] | None = None
    if archive_exists:
        try:
            archive_metadata = archive.lstat()
        except OSError as error:
            raise ActivationPackageError(
                "maintenance rollback archive is unavailable"
            ) from error
        root_uid, root_gid = _activation_root_identity()
        archive_identity = _maintenance_rollback_directory_identity(
            archive_metadata
        )
        if (
            archive.is_symlink()
            or not stat.S_ISDIR(archive_metadata.st_mode)
            or (archive_metadata.st_uid, archive_metadata.st_gid)
            != (root_uid, root_gid)
            or stat.S_IMODE(archive_metadata.st_mode) != 0o700
            or archive_identity != source_identity
        ):
            raise ActivationPackageError(
                "maintenance rollback archive identity is invalid"
            )

    if source.exists() or source.is_symlink():
        replacement_identity = _maintenance_rollback_replacement_identity(
            source,
            normalize_root_lock=True,
        )
        if source_identity is not None and replacement_identity == source_identity:
            raise ActivationPackageError(
                "maintenance rollback failed successor was not archived"
            )
    else:
        replacement_identity = _maintenance_rollback_create_empty_namespace(source)
    receipt = {
        "schemaVersion": "overseer.maintenance-failed-successor-receipt.v1",
        "status": "archived_and_recreated",
        "contractDigest": intent["contractDigest"],
        "sourceDirectory": str(source),
        "archiveDirectory": str(archive) if archive_identity is not None else None,
        "archiveIdentity": archive_identity,
        "replacementIdentity": replacement_identity,
    }
    replayed = receipt_exists
    _maintenance_rollback_record(
        receipt_path,
        receipt,
        label="maintenance rollback archive receipt",
    )
    _fsync_package_directory(workspace)
    _fsync_package_directory(source.parent)
    return {
        "status": "destination_namespace_archived",
        "archiveRoot": str(archive) if archive_identity is not None else None,
        "replacementRoot": str(source),
        "replayed": replayed,
    }


def restore_maintenance_store_access(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Restore all three legacy store authorities during sealed rollback only."""

    package = Path(package_root).resolve()
    contract = _require_maintenance_active_rollback_command(
        package,
        command_name="restore-maintenance-store-access",
        expected_options={"--package-root": str(package)},
    )
    restored: list[dict[str, object]] = []
    bindings = contract.get("storeBindings")
    if not isinstance(bindings, list) or len(bindings) != 3:
        raise ActivationPackageError("maintenance rollback store bindings are invalid")
    destination_descriptor, resolved_markers = (
        _lock_maintenance_destination_namespace_for_rollback(bindings)
    )
    try:
        archive_result = (
            _archive_maintenance_destination_namespace_for_rollback(
                contract,
                bindings,
                destination_descriptor,
            )
        )
        for binding in bindings:
            if not isinstance(binding, Mapping) or not isinstance(
                binding.get("sourceIdentity"), Mapping
            ):
                raise ActivationPackageError(
                    "maintenance rollback store binding is invalid"
                )
            identity = binding["sourceIdentity"]
            restored.append(
                _restore_legacy_store_access_unchecked(
                    source_store=str(binding.get("sourceDb", "")),
                    expected_source_uid=int(identity["uid"]),
                    expected_source_gid=int(identity["gid"]),
                    expected_source_device=int(identity["device"]),
                    expected_source_inode=int(identity["inode"]),
                    expected_parent_device=int(identity["parentDevice"]),
                    expected_parent_inode=int(identity["parentInode"]),
                    expected_parent_mode=int(identity["parentMode"]),
                )
            )
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
    return {
        "status": "maintenance_store_access_restored",
        "stores": restored,
        "destinationNamespace": "archived-and-recreated-empty",
        "failedSuccessorArchive": archive_result,
        "resolvedUnsafeMarkers": resolved_markers,
    }


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
    source_tree = manifest.get("sourceTree")
    if (
        manifest.get("schemaVersion") != RELEASE_SCHEMA
        or not isinstance(files, list)
        or not isinstance(release_root, str)
        or not isinstance(source_tree, str)
    ):
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
    checkout_inventory = {
        item["sourcePath"]: item
        for item in _source_inventory(roots["checkout"], tree=source_tree)
    }
    for item in files:
        if not isinstance(item, Mapping) or item.get("sourceKind") not in roots:
            raise ActivationPackageError("release file manifest is invalid")
        source_path = str(item.get("sourcePath", ""))
        release_path = str(item.get("releasePath", ""))
        if item["sourceKind"] == "checkout":
            git_entry = checkout_inventory.get(source_path)
            if (
                git_entry is None
                or git_entry["sourceObject"] != item.get("sourceObject")
                or git_entry["sourceGitMode"] != item.get("sourceGitMode")
            ):
                raise ActivationPackageError(
                    f"release Git source drifted after manifest: {source_path}"
                )
            content = _git_blob(roots["checkout"], git_entry["sourceObject"])
        elif item["sourceKind"] == "stdlib":
            content, _metadata, resolved = _runtime_read(roots["stdlib"], source_path)
            if resolved != item.get("sourceResolvedPath"):
                raise ActivationPackageError(f"standard-library source drifted after manifest: {source_path}")
        else:
            content, _metadata = _stable_read(
                roots[str(item["sourceKind"])] / _safe_relative(source_path)
            )
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


def stage_canary_identity(
    package_root: str | os.PathLike[str],
    *,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> dict[str, object]:
    """Create the opaque canary namespace identity before package sealing."""

    package = Path(package_root).absolute()
    public = package / "public"
    _ensure_directory(public)
    try:
        random_value = random_bytes(CANARY_INSTANCE_BYTES)
    except Exception as error:
        raise ActivationPackageError("canary instance identity generation failed") from error
    if not isinstance(random_value, bytes) or len(random_value) != CANARY_INSTANCE_BYTES:
        raise ActivationPackageError("canary instance identity source returned invalid bytes")
    document: dict[str, object] = {
        "schemaVersion": CANARY_INSTANCE_SCHEMA,
        "canaryInstanceId": random_value.hex(),
    }
    _write_new(
        public / "canary-instance.json",
        _canonical(document) + b"\n",
        0o644,
    )
    return document


def _load_canary_identity(
    package: Path,
    *,
    expected_package_digest: str | None = None,
) -> dict[str, object]:
    if expected_package_digest is None:
        path = package / "public" / "canary-instance.json"
        try:
            raw, metadata = _stable_read(path)
            document = json.loads(raw)
            package_owner = package.lstat().st_uid
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ActivationPackageError("canary instance identity is invalid") from error
        if (
            metadata.st_uid != package_owner
            or stat.S_IMODE(metadata.st_mode) != 0o644
            or metadata.st_nlink != 1
        ):
            raise ActivationPackageError("canary instance identity metadata is invalid")
    else:
        document = _bound_package_json(
            package,
            expected_package_digest=expected_package_digest,
            relative_path="public/canary-instance.json",
        )
    if not isinstance(document, dict) or set(document) != {
        "schemaVersion",
        "canaryInstanceId",
    }:
        raise ActivationPackageError("canary instance identity schema is invalid")
    instance_id = document.get("canaryInstanceId")
    if (
        document.get("schemaVersion") != CANARY_INSTANCE_SCHEMA
        or not isinstance(instance_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", instance_id) is None
    ):
        raise ActivationPackageError("canary instance identity value is invalid")
    return document


def _canary_state_paths(
    package: Path,
    *,
    expected_package_digest: str | None = None,
) -> dict[str, Path | str]:
    identity = _load_canary_identity(
        package,
        expected_package_digest=expected_package_digest,
    )
    instance_id = str(identity["canaryInstanceId"])
    state_directory = CANARY_STATE_ROOT / instance_id
    return {
        "canaryInstanceId": instance_id,
        "stateDirectory": state_directory,
        "store": state_directory / "overseer.sqlite3",
        "psychloBridgeDatabase": state_directory / "psychlo-bridge.sqlite3",
        "roadexRelayDatabase": state_directory / "roadex-relay.sqlite3",
    }


def render_systemd_units(
    manifest: Mapping[str, object],
    *,
    templates_root: str | os.PathLike[str],
    output_root: str | os.PathLike[str],
    god_uid: int,
    god_gid: int,
    overseer_uid: int,
    python_path: str | os.PathLike[str],
) -> dict[str, Path]:
    """Render the closed systemd contract into a new package directory."""

    release_root = manifest.get("releaseRoot")
    if not isinstance(release_root, str) or not release_root.startswith("/opt/overseer/releases/"):
        raise ActivationPackageError("release root is invalid")
    for value, label in (
        (god_uid, "god UID"),
        (god_gid, "god GID"),
        (overseer_uid, "overseer UID"),
    ):
        if type(value) is not int or value < 1:
            raise ActivationPackageError(f"{label} is invalid")
    _validate_principal_binding(
        god_uid=god_uid,
        god_gid=god_gid,
        overseer_uid=overseer_uid,
        overseer_gid=overseer_uid,
    )
    templates = Path(templates_root)
    if templates.is_symlink() or templates.name != "systemd":
        raise ActivationPackageError("systemd template root is invalid")
    checkout = templates.resolve().parent
    source_tree = manifest.get("sourceTree")
    control_files = manifest.get("controlFiles")
    if not isinstance(source_tree, str) or not isinstance(control_files, list):
        raise ActivationPackageError("activation control manifest is invalid")
    control_by_path = {
        str(item.get("sourcePath")): item
        for item in control_files
        if isinstance(item, Mapping) and isinstance(item.get("sourcePath"), str)
    }
    if len(control_by_path) != len(_CONTROL_SOURCE_PATHS) or set(control_by_path) != set(
        _CONTROL_SOURCE_PATHS
    ):
        raise ActivationPackageError("activation control manifest is incomplete")

    def control_content(source_path: str) -> bytes:
        entries = _git_tree_inventory(
            checkout,
            tree=source_tree,
            pathspec=source_path,
        )
        expected = control_by_path[source_path]
        if (
            len(entries) != 1
            or entries[0]["sourcePath"] != source_path
            or entries[0]["sourceObject"] != expected.get("sourceObject")
            or entries[0]["sourceGitMode"] != expected.get("sourceGitMode")
        ):
            raise ActivationPackageError("activation control Git binding drifted")
        content = _git_blob(checkout, entries[0]["sourceObject"])
        if (
            _sha256(content) != expected.get("sha256")
            or len(content) != expected.get("size")
        ):
            raise ActivationPackageError("activation control content drifted")
        return content

    output = Path(output_root)
    if output.name != "systemd" or output.parent.name != "public":
        raise ActivationPackageError("rendered systemd destination is outside the package layout")
    canary_paths = _canary_state_paths(output.parent.parent)
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
        "@GOD_GID@": str(god_gid),
        "@OVERSEER_UID@": str(overseer_uid),
        "@OVERSEER_CANARY_STATE@": str(canary_paths["stateDirectory"]),
    }
    result: dict[str, Path] = {}
    for source_name, target_name in _SYSTEMD_TEMPLATES.items():
        content = control_content(f"systemd/{source_name}")
        text = content.decode("utf-8", "strict")
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        if "@OVERSEER_" in text or "@GOD_UID@" in text or "@GOD_GID@" in text:
            raise ActivationPackageError(f"rendered unit has an unresolved placeholder: {source_name}")
        target = output / target_name
        _write_new(target, text.encode("utf-8"), 0o644)
        result[target_name] = target
    allowlist = control_content("config/admin-executor-allowlist.json")
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


def _stream_hash_open_regular(
    descriptor: int,
    *,
    label: str,
    guard: Callable[[], None] | None = None,
) -> dict[str, object]:
    """Hash one already-open regular file without reopening its pathname."""

    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ActivationPackageError(f"{label} descriptor is not a single-link regular file")
    digest = hashlib.sha256()
    size = 0
    while size < before.st_size:
        if guard is not None:
            guard()
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - size), size)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    if guard is not None:
        guard()
    after = os.fstat(descriptor)
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
    if identity(before) != identity(after):
        raise ActivationPackageError(f"{label} descriptor changed while hashing")
    if size != before.st_size:
        raise ActivationPackageError(f"{label} descriptor was not read completely")
    return {
        "sha256": digest.hexdigest(),
        "size": size,
        "mode": f"{stat.S_IMODE(before.st_mode):04o}",
        "uid": before.st_uid,
        "gid": before.st_gid,
        "links": before.st_nlink,
    }


def _copy_open_regular_to_new_path(
    source_descriptor: int,
    target: Path,
    *,
    label: str,
    guard: Callable[[], None],
) -> None:
    """Copy one descriptor-bound regular file while a caller-owned guard holds."""

    before = os.fstat(source_descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ActivationPackageError(f"{label} descriptor is not a single-link regular file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    target_descriptor: int | None = None
    try:
        target_descriptor = os.open(target, flags, 0o600)
        copied = 0
        while copied < before.st_size:
            guard()
            chunk = os.pread(
                source_descriptor,
                min(1024 * 1024, before.st_size - copied),
                copied,
            )
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError("descriptor-bound migration copy made no progress")
                copied += written
                view = view[written:]
        guard()
        after = os.fstat(source_descriptor)
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
        if identity(before) != identity(after) or copied != before.st_size:
            raise ActivationPackageError(f"{label} changed during descriptor-bound copy")
        os.fchmod(target_descriptor, 0o600)
        os.fsync(target_descriptor)
    except BaseException:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        if target_descriptor is not None:
            os.close(target_descriptor)


def _stream_hash_regular(
    path: Path,
    *,
    label: str,
    expected_size: int | None = None,
) -> dict[str, object]:
    """Hash one regular file while binding its complete descriptor identity."""

    try:
        before = path.lstat()
    except OSError as error:
        raise ActivationPackageError(f"{label} could not be inspected") from error
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise ActivationPackageError(f"{label} must be a regular file, not a symlink")
    if expected_size is not None and before.st_size != expected_size:
        raise ActivationPackageError(f"{label} has an unexpected size")
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
        if expected_size is not None and opened.st_size != expected_size:
            raise ActivationPackageError(f"{label} has an unexpected size")
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


def _source_store_identity(path: Path, metadata: os.stat_result) -> dict[str, object]:
    return {
        "path": str(path.resolve()),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def _validate_rehearsal_source_binding(
    package: Path,
    source: Path,
    source_metadata: os.stat_result,
) -> None:
    report_path = package / "private" / "migration" / "migration-report.json"
    try:
        raw, _metadata = _stable_read(report_path)
        report = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("migration rehearsal report is invalid") from error
    recorded = report.get("source") if isinstance(report, dict) else None
    expected = _source_store_identity(source, source_metadata)
    if not isinstance(recorded, dict) or any(
        recorded.get(field) != value for field, value in expected.items()
    ):
        raise ActivationPackageError(
            "activation source store does not match the migration rehearsal source"
        )


def render_activation_contract(
    package_root: str | os.PathLike[str],
    release_manifest: Mapping[str, object],
    *,
    source_store: str | os.PathLike[str],
    overseer_uid: int,
    overseer_gid: int,
    rollback_inputs: Mapping[str, str | os.PathLike[str]],
    psychlo_store: str | os.PathLike[str] | None = None,
    roadex_store: str | os.PathLike[str] | None = None,
    codex_usage_store: str | os.PathLike[str] | None = None,
) -> dict[str, object]:
    """Render, but never execute, exact root activation and rollback argv."""

    if type(overseer_uid) is not int or type(overseer_gid) is not int:
        raise ActivationPackageError("dedicated principal UID and GID must be integers")
    if overseer_uid < 1 or overseer_gid < 1:
        raise ActivationPackageError("dedicated principal UID and GID must be positive")
    if release_manifest.get("schemaVersion") != RELEASE_SCHEMA:
        raise ActivationPackageError("release manifest is invalid")
    package = Path(package_root).resolve()
    canary_paths = _canary_state_paths(package)
    source = Path(source_store)
    source_metadata = _validate_store_artifact(source, label="activation source SQLite store")
    _validate_rehearsal_source_binding(package, source, source_metadata)
    try:
        god = pwd.getpwnam("god")
    except KeyError as error:
        raise ActivationPackageError("approved god account is unavailable") from error
    _validate_principal_binding(
        god_uid=god.pw_uid,
        god_gid=god.pw_gid,
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
    maintenance_inputs = (psychlo_store, roadex_store, codex_usage_store)
    if any(value is not None for value in maintenance_inputs) and not all(
        value is not None for value in maintenance_inputs
    ):
        raise ActivationPackageError(
            "maintenance-window Psychlo, Roadex, and Codex Usage stores must be supplied together"
        )
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
    release_python = release_manifest.get("rootPython")
    if (
        not isinstance(release_python, Mapping)
        or not isinstance(release_python.get("path"), str)
        or not isinstance(release_python.get("releasePath"), str)
    ):
        raise ActivationPackageError("release Python manifest is invalid")
    package_release_root = (
        execution_package / "public" / "release" / PurePosixPath(release_root).name
    )
    package_activation_python = [
        "/usr/bin/env",
        f"LD_LIBRARY_PATH={package_release_root}/lib",
        f"PYTHONHOME={package_release_root}/runtime",
        f"PYTHONPATH={package_release_root}/app/src:{package_release_root}/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        str(package_release_root / _safe_relative(str(release_python["releasePath"]))),
        "-B",
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
    ]
    install_commands: list[list[str]] = [
        [
            *package_activation_python,
            "ensure-dedicated-principal",
            "--package-root",
            str(execution_package),
        ],
        [
            "/usr/bin/install",
            "-d",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0755",
            "/opt/overseer",
        ],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/opt/overseer/releases"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0755", "/opt/overseer/rollback"],
        [
            "/usr/bin/install",
            "-d",
            "-o",
            str(overseer_uid),
            "-g",
            str(overseer_gid),
            "-m",
            "0700",
            "/var/lib/overseer",
        ],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", "/var/lib/overseer-executor"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", "/var/lib/overseer-executor/activation-package"],
        ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", "/var/lib/overseer-executor/activation-package/public"],
        [
            "/usr/bin/install",
            "-d",
            "-o",
            "0",
            "-g",
            str(overseer_gid),
            "-m",
            "0710",
            "/etc/overseer",
        ],
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
    staged_gateway_ca = package / "public" / "config" / "protected-gateway-ca.crt"
    gateway_ca_source = public / "config" / "protected-gateway-ca.crt"
    has_gateway_ca = staged_gateway_ca.is_file() and not staged_gateway_ca.is_symlink()
    config_installs = (
        (private / "credentials" / "admin-approval-verifier.json", "/etc/overseer/admin-approval-verifier.json", str(overseer_uid), str(overseer_gid), "0600"),
        (private / "credentials" / "roadex-fixture-approval-verifier.json", "/etc/overseer/roadex-fixture-approval-verifier.json", str(overseer_uid), str(overseer_gid), "0600"),
        (private / "credentials" / "api-token", "/etc/overseer/api-token", "root", "root", "0600"),
        (private / "credentials" / "psychlo-peer-secret", "/etc/overseer/psychlo-peer-secret", "root", "root", "0600"),
        (private / "credentials" / "roadex-project-human-thread-secret", "/etc/overseer/roadex-project-human-thread-secret", "root", "root", "0600"),
        (public / "config" / "psychlo-project-bindings.json", "/etc/overseer/psychlo-project-bindings.json", "root", "root", "0644"),
        (public / "config" / "admin-executor-public-key", "/etc/overseer/admin-executor-public-key", "root", "root", "0644"),
        (public / "config" / "admin-executor-allowlist.json", "/etc/overseer/admin-executor-allowlist.json", "root", "root", "0644"),
        (private / "credentials" / "admin-ticket-private-key", "/etc/overseer/admin-ticket-private-key", str(overseer_uid), str(overseer_gid), "0600"),
    ) + (
        (
            (
                gateway_ca_source,
                "/etc/overseer/protected-gateway-ca.crt",
                "root",
                "root",
                "0644",
            ),
        )
        if has_gateway_ca
        else ()
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
    final_backup = Path(
        f"/var/lib/overseer-executor/v1.1.6-source-{manifest_digest}.sqlite3"
    )
    final_store = Path("/var/lib/overseer/overseer.sqlite3")
    migration_command = [
        "/usr/bin/env",
        f"LD_LIBRARY_PATH={release_root}/lib",
        f"PYTHONHOME={release_root}/runtime",
        f"PYTHONPATH={release_root}/app/src:{release_root}/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        str(PurePosixPath(release_root) / _safe_relative(str(release_python["releasePath"]))),
        "-B",
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
        "prepare-final-store",
        "--package-root",
        str(execution_package),
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
        f"--uid={source_metadata.st_uid}",
        f"--gid={source_metadata.st_gid}",
    ]
    activation_python = [
        "/usr/bin/env",
        f"LD_LIBRARY_PATH={release_root}/lib",
        f"PYTHONHOME={release_root}/runtime",
        f"PYTHONPATH={release_root}/app/src:{release_root}/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        str(PurePosixPath(release_root) / _safe_relative(str(release_python["releasePath"]))),
        "-B",
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
            *activation_python,
            "stage-canary-store",
            "--package-root",
            str(execution_package),
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
        [
            *activation_python,
            "handoff-start-canary",
            "--package-root",
            str(execution_package),
        ],
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
            str(CANARY_API_SOCKET),
            "http://localhost/health",
        ],
        [*activation_python, "run-approved-canary", "--package-root", str(execution_package)],
        [
            "/usr/bin/systemctl",
            "stop",
            "overseer-approval-smoke.service",
            "overseer-api-canary.service",
            "overseer-admin-executor.socket",
            "overseer-codex-user-bridge.socket",
        ],
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
            "--package-root",
            str(execution_package),
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
    maintenance_window: dict[str, object] | None = None
    if (
        psychlo_store is not None
        and roadex_store is not None
        and codex_usage_store is not None
    ):
        if not has_gateway_ca:
            raise ActivationPackageError(
                "maintenance-window package requires the Protected Gateway CA snapshot"
            )
        maintenance_evidence_root = Path(
            f"/var/lib/overseer-executor/maintenance-{manifest_digest}"
        )

        def maintenance_binding(
            *,
            name: str,
            selected_source: Path,
            store_kind: str,
            destination: Path,
            allowed_source_modes: frozenset[int] = frozenset({0o600}),
        ) -> dict[str, object]:
            selected_metadata = _validate_store_artifact(
                selected_source,
                label=f"maintenance {name} SQLite store",
                expected_uid=god.pw_uid,
                allowed_modes=allowed_source_modes,
            )
            if selected_metadata.st_gid != god.pw_gid:
                raise ActivationPackageError(
                    f"maintenance {name} SQLite store has an unexpected group"
                )
            selected_parent = selected_source.parent
            try:
                selected_parent_metadata = selected_parent.lstat()
            except OSError as error:
                raise ActivationPackageError(
                    f"maintenance {name} SQLite store parent could not be inspected"
                ) from error
            selected_parent_mode = stat.S_IMODE(selected_parent_metadata.st_mode)
            if (
                selected_parent.is_symlink()
                or not stat.S_ISDIR(selected_parent_metadata.st_mode)
                or (
                    selected_parent_metadata.st_uid,
                    selected_parent_metadata.st_gid,
                )
                != (god.pw_uid, god.pw_gid)
                or selected_parent_mode not in {0o700, 0o750, 0o770, 0o775}
            ):
                raise ActivationPackageError(
                    f"maintenance {name} SQLite store parent identity or mode is unsupported"
                )
            return {
                "name": name,
                "sourceDb": str(selected_source.resolve()),
                "backupDb": str(
                    maintenance_evidence_root / "offline" / f"{name}.sqlite3"
                ),
                "destinationDb": str(destination),
                "storeKind": store_kind,
                "sourceIdentity": {
                    "device": selected_metadata.st_dev,
                    "inode": selected_metadata.st_ino,
                    "uid": selected_metadata.st_uid,
                    "gid": selected_metadata.st_gid,
                    "mode": stat.S_IMODE(selected_metadata.st_mode),
                    "parentDevice": selected_parent_metadata.st_dev,
                    "parentInode": selected_parent_metadata.st_ino,
                    "parentMode": selected_parent_mode,
                },
            }

        store_bindings = [
            maintenance_binding(
                name="overseer-main",
                selected_source=source,
                store_kind="overseer",
                destination=Path("/var/lib/overseer/overseer.sqlite3"),
            ),
            maintenance_binding(
                name="psychlo-bridge",
                selected_source=Path(psychlo_store),
                store_kind="copy-only",
                destination=Path("/var/lib/overseer/psychlo-bridge.sqlite3"),
            ),
            maintenance_binding(
                name="roadex-relay",
                selected_source=Path(roadex_store),
                store_kind="copy-only",
                destination=Path("/var/lib/overseer/roadex-relay.sqlite3"),
            ),
        ]
        deferred_store_bindings = [
            {
                key: value
                for key, value in maintenance_binding(
                    name="codex-usage",
                    selected_source=Path(codex_usage_store),
                    store_kind="copy-only",
                    destination=Path("/var/lib/overseer/codex-usage-deferred.sqlite3"),
                    allowed_source_modes=frozenset({0o600, 0o644}),
                ).items()
                if key not in {"backupDb", "destinationDb", "storeKind"}
            }
        ]
        deferred_store_bindings[0]["policy"] = "preserve-and-resume-unchanged"
        writer_unit_baseline = _capture_maintenance_writer_unit_baseline()
        successor_unit_baseline = _capture_maintenance_successor_unit_baseline()
        mutable_handoff_prefixes = (
            "/etc/overseer",
            "/etc/systemd/system",
            "/etc/tmpfiles.d",
            "/var/lib/overseer",
        )
        maintenance_excluded_unit_targets = {
            "/etc/systemd/system/overseer-api-canary.service",
            "/etc/systemd/system/overseer-approval-smoke.service",
        }
        maintenance_excluded_target_prefixes = (
            "/var/lib/overseer-executor/activation-package",
        )
        maintenance_immutable_install_commands: list[list[str]] = []
        maintenance_handoff_install_commands: list[list[str]] = []
        for command in install_commands:
            if (
                command
                and command[0] == "/usr/bin/install"
                and (
                    command[-1] in maintenance_excluded_unit_targets
                    or any(
                        command[-1] == prefix
                        or command[-1].startswith(prefix + "/")
                        for prefix in maintenance_excluded_target_prefixes
                    )
                )
            ):
                continue
            mutates_handoff_state = "ensure-dedicated-principal" in command
            if command and command[0] == "/usr/bin/install":
                target = command[-1]
                mutates_handoff_state = mutates_handoff_state or any(
                    target == prefix or target.startswith(prefix + "/")
                    for prefix in mutable_handoff_prefixes
                )
            (
                maintenance_handoff_install_commands
                if mutates_handoff_state
                else maintenance_immutable_install_commands
            ).append(command)
        maintenance_immutable_install_commands.append(
            [
                *package_activation_python,
                "verify-maintenance-installed-release",
                "--package-root",
                str(execution_package),
            ]
        )
        maintenance_rollback_commands = [
            [
                "/usr/bin/systemctl",
                "stop",
                "overseer-api.service",
                "overseer-runtime.service",
                "overseer-admin-executor.socket",
                "overseer-codex-user-bridge.socket",
            ],
            [
                "/usr/bin/systemctl",
                "disable",
                "overseer-api.service",
                "overseer-runtime.service",
                "overseer-admin-executor.socket",
                "overseer-codex-user-bridge.socket",
            ],
            ["/usr/bin/systemctl", "daemon-reload"],
            [
                *package_activation_python,
                "verify-rollback-bundle",
                "--bundle-root",
                str(rollback_bundle_root),
                "--rollback-manifest",
                str(execution_package / "public" / "rollback-manifest.json"),
            ],
            [
                *package_activation_python,
                "restore-maintenance-store-access",
                "--package-root",
                str(execution_package),
            ],
            [
                *package_activation_python,
                "restore-maintenance-handoff-artifacts",
                "--package-root",
                str(execution_package),
            ],
            ["/usr/bin/systemctl", "daemon-reload"],
            [
                *package_activation_python,
                "restore-maintenance-writers",
                "--package-root",
                str(execution_package),
            ],
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
                "15",
                "--retry-delay",
                "2",
                "--retry-max-time",
                "45",
                "--retry-all-errors",
                "http://127.0.0.1:8766/health",
            ],
        ]
        maintenance_early_rollback_commands = [
            [
                *package_activation_python,
                "restop-maintenance-writers",
                "--package-root",
                str(execution_package),
            ],
            [
                *package_activation_python,
                "restore-maintenance-writers",
                "--package-root",
                str(execution_package),
            ],
        ]
        maintenance_window = {
        "storeBindings": store_bindings,
        "deferredStoreBindings": deferred_store_bindings,
        "writerUnitBaseline": writer_unit_baseline,
        "successorUnitBaseline": successor_unit_baseline,
        "preservationInputs": {
            "currentRelease": str(rollback_release["path"]),
            "credentialsDirectory": "/home/god/.config/overseer",
            "userUnitsRuntimeEnv": "/home/god/.config/overseer/runtime.env",
            "rollbackBundle": str(
                execution_package
                / "private"
                / "rollback-inputs"
                / "v1.1.5-release"
            ),
            "userRuntimeUnit": "/home/god/.config/systemd/user/overseer.service",
            "userApiUnit": "/home/god/.config/systemd/user/overseer-api.service",
            "psychloCycleUnit": "/home/god/.config/systemd/user/overseer-psychlo-cycle.service",
            "psychloMeterUnit": "/home/god/.config/systemd/user/overseer-psychlo-meter.service",
            "psychloUsageUnit": "/home/god/.config/systemd/user/overseer-psychlo-usage.service",
            "psychloUsageTimer": "/home/god/.config/systemd/user/overseer-psychlo-usage.timer",
            "quarkSchedulerUnit": "/home/god/.config/systemd/user/overseer-quark-scheduler.service",
            "quarkSchedulerTimer": "/home/god/.config/systemd/user/overseer-quark-scheduler.timer",
            "codexUsageMcpUnit": "/home/god/.config/systemd/user/overseer-codex-usage-mcp.service",
            "codexUsageSnapshotUnit": "/home/god/.config/systemd/user/overseer-codex-usage-snapshot.service",
            "codexUsageSnapshotTimer": "/home/god/.config/systemd/user/overseer-codex-usage-snapshot.timer",
            "systemCredentialsDirectory": "/etc/overseer",
            "systemAdminSocketUnit": "/etc/systemd/system/overseer-admin-executor.socket",
            "systemAdminServiceUnit": "/etc/systemd/system/overseer-admin-executor@.service",
            "systemApiUnit": "/etc/systemd/system/overseer-api.service",
            "systemUserBridgeServiceUnit": "/etc/systemd/system/overseer-codex-user-bridge.service",
            "systemUserBridgeSocketUnit": "/etc/systemd/system/overseer-codex-user-bridge.socket",
            "systemRuntimeUnit": "/etc/systemd/system/overseer-runtime.service",
            "systemTmpfilesRule": "/etc/tmpfiles.d/overseer.conf",
            "compatibilityApiToken": "/home/god/.local/share/overseer/project/state/api-token",
        },
        "evidenceRoot": str(maintenance_evidence_root / "preserved"),
        "acceptanceChecks": list(_MAINTENANCE_ACCEPTANCE_CHECKS),
        "stages": [
            {
                "name": "preflight",
                "commands": [
                    [
                        *package_activation_python,
                        "verify-maintenance-preflight",
                        "--package-root",
                        str(execution_package),
                    ]
                ],
            },
            {
                "name": "stopWriters",
                "commands": [
                    [
                        *package_activation_python,
                        "stop-maintenance-writers",
                        "--package-root",
                        str(execution_package),
                    ]
                ],
            },
            {
                "name": "proveQuiescence",
                "commands": [
                    [
                        *package_activation_python,
                        "verify-maintenance-quiescence",
                        "--package-root",
                        str(execution_package),
                    ]
                ],
            },
            {
                "name": "preserveState",
                "commands": [
                    [
                        *package_activation_python,
                        "preserve-maintenance-state",
                        "--package-root",
                        str(execution_package),
                    ]
                ],
            },
            {
                "name": "installRelease",
                "commands": maintenance_immutable_install_commands,
            },
            {
                "name": "migrateOfflineStores",
                "commands": [
                    [
                        *activation_python,
                        "prepare-maintenance-stores",
                        "--package-root",
                        str(execution_package),
                    ]
                ],
            },
            {
                "name": "switchServices",
                "commands": [
                    [
                        *package_activation_python,
                        "verify-maintenance-preservation",
                        "--package-root",
                        str(execution_package),
                    ],
                    *maintenance_handoff_install_commands,
                    [
                        *user_systemctl,
                        "disable",
                        "overseer-psychlo-usage.timer",
                        "overseer-psychlo-cycle.service",
                        "overseer-psychlo-meter.service",
                        "overseer-psychlo-usage.service",
                        "overseer-api.service",
                        "overseer.service",
                    ],
                    [
                        *package_activation_python,
                        "verify-maintenance-quiescence",
                        "--package-root",
                        str(execution_package),
                    ],
                    *cutover_commands[3:-1],
                    [
                        *user_systemctl,
                        "start",
                        "overseer-quark-scheduler.timer",
                        "overseer-codex-usage-mcp.service",
                        "overseer-codex-usage-snapshot.timer",
                    ],
                ],
            },
            {
                "name": "acceptance",
                "commands": [
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
                        "15",
                        "--retry-delay",
                        "2",
                        "--retry-max-time",
                        "45",
                        "--retry-all-errors",
                        "http://127.0.0.1:8766/health",
                    ],
                    [
                        *activation_python,
                        "verify-maintenance-acceptance",
                        "--package-root",
                        str(execution_package),
                    ],
                ],
            },
        ],
        "stageTimeoutSeconds": {
            "preflight": 120,
            "stopWriters": 120,
            "proveQuiescence": 120,
            "preserveState": 1800,
            "installRelease": 900,
            "migrateOfflineStores": 1800,
            "switchServices": 300,
            "acceptance": 900,
        },
        "windowTimeoutSeconds": 5400,
        "earlyRollbackCommands": maintenance_early_rollback_commands,
        "earlyRollbackTimeoutSeconds": [120, 300],
        "earlyRollbackWindowTimeoutSeconds": 600,
        "earlyRollbackStartIndex": 1,
        "rollbackCommands": maintenance_rollback_commands,
        "rollbackTimeoutSeconds": [120, 120, 60, 300, 300, 300, 60, 300, 60],
        "rollbackWindowTimeoutSeconds": 1800,
        "rollbackStartIndex": 7,
        "secretInputs": [],
        }
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
            "executionScope": "sealed-package-import-and-verification-only",
        },
        "phaseApprovalRecords": {
            "schemaVersion": ACTIVATION_PHASE_APPROVAL_SCHEMA,
            "stagingCanary": {
                "phase": "staging-canary",
                "path": str(_activation_phase_approval_record_path("staging-canary")),
                "runner": "execute-approved-staging-canary",
                "requiresRunnerState": "not-started",
            },
            "cutover": {
                "phase": "cutover",
                "path": str(_activation_phase_approval_record_path("cutover")),
                "runner": "execute-approved-cutover",
                "requiresRunnerState": "canary_passed_awaiting_cutover_approval",
            },
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
            "requiresRootOwnedPhaseApprovalRecord": True,
            "requiresRootOwnedDigestBoundAttestation": True,
            "manualCommandExtractionForbidden": True,
            "automaticCutoverForbidden": True,
        },
        "canary": {
            "canaryInstanceId": str(canary_paths["canaryInstanceId"]),
            "stateDirectory": str(canary_paths["stateDirectory"]),
            "store": str(canary_paths["store"]),
            "psychloBridgeDatabase": str(canary_paths["psychloBridgeDatabase"]),
            "roadexRelayDatabase": str(canary_paths["roadexRelayDatabase"]),
            "preserveFailedStateForEvidence": True,
            "ownershipHandoffCommand": "handoff-start-canary",
            "requiresNoExistingServicePrincipalProcesses": True,
            "unixSocket": str(CANARY_API_SOCKET),
            "serverPeerUid": overseer_uid,
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
        },
        "acceptanceControls": {
            "positive": [
                "authenticated Unix-socket canary health",
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
    if maintenance_window is not None:
        contract["maintenanceWindow"] = maintenance_window
    encoded = _canonical(contract)
    if b"<" in encoded or b">" in encoded:
        raise ActivationPackageError("activation contract contains an unresolved value")
    if maintenance_window is not None:
        render_maintenance_window_contract(package, contract)
    _write_new(package / "public" / "activation-contract.json", encoded + b"\n", 0o644)
    return contract


def _sealed_migration_artifact_evidence(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int | None = None,
    expected_size: int | None = None,
    counted_tables: tuple[str, ...] | None = None,
) -> dict[str, object]:
    metadata = _validate_store_artifact(
        path,
        label="sealed migration artifact",
        expected_uid=expected_uid,
    )
    if expected_gid is not None and metadata.st_gid != expected_gid:
        raise ActivationPackageError("sealed migration artifact has an unexpected group")
    if expected_size is not None:
        if expected_size < 0 or expected_size > MAX_APPROVED_PACKAGE_IMPORT_BYTES:
            raise ActivationPackageError("sealed migration artifact expected size is invalid")
        if metadata.st_size != expected_size:
            raise ActivationPackageError("sealed migration artifact has an unexpected size")
        if metadata.st_blocks * 512 < expected_size:
            raise ActivationPackageError("sealed migration artifact must not be sparse")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ActivationPackageError("sealed migration artifact could not be opened") from error
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    try:
        opened = os.fstat(descriptor)
        if identity(opened) != identity(metadata):
            raise ActivationPackageError("sealed migration artifact changed while opening")
        if expected_size is not None and opened.st_size != expected_size:
            raise ActivationPackageError("sealed migration artifact has an unexpected size")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        connection = sqlite3.connect(
            f"file:/proc/self/fd/{descriptor}?mode=ro&immutable=1",
            uri=True,
            timeout=5,
        )
        try:
            integrity_row = connection.execute("PRAGMA integrity_check").fetchone()
            integrity = str(integrity_row[0]) if integrity_row else "missing"
            if integrity != "ok":
                raise ActivationPackageError(
                    "sealed migration artifact failed SQLite integrity_check"
                )
            expression_indexes = _approved_expression_indexes_from_connection(
                connection
            )
            row_counts, schema = _migration_evidence_from_connection(
                connection,
                counted_tables=counted_tables,
            )
        finally:
            connection.close()
        after = os.fstat(descriptor)
        lexical_after = path.lstat()
        if identity(after) != identity(metadata) or identity(lexical_after) != identity(metadata):
            raise ActivationPackageError("sealed migration artifact changed during verification")
        if size != metadata.st_size:
            raise ActivationPackageError("sealed migration artifact was not read completely")
    except sqlite3.Error as error:
        raise ActivationPackageError("sealed migration artifact is not valid SQLite") from error
    except OSError as error:
        raise ActivationPackageError("sealed migration artifact changed or became unreadable") from error
    finally:
        os.close(descriptor)
    return {
        "sha256": digest.hexdigest(),
        "size": size,
        "integrityCheck": integrity,
        "approvedExpressionIndexes": expression_indexes,
        "rowCounts": row_counts,
        "schema": schema,
    }


def render_maintenance_window_contract(
    package_root: str | os.PathLike[str],
    activation_contract: Mapping[str, object],
) -> dict[str, object]:
    """Render the independent maintenance contract beside the legacy contract."""

    package = Path(package_root).resolve()
    if activation_contract.get("schemaVersion") != ACTIVATION_CONTRACT_SCHEMA:
        raise ActivationPackageError("activation contract is invalid")
    activation_package_root = activation_contract.get("packageRoot")
    if (
        not isinstance(activation_package_root, str)
        or not activation_package_root.startswith("/")
    ):
        raise ActivationPackageError("activation contract package root is not bound")
    release_digest = activation_contract.get("releaseManifestDigest")
    account = activation_contract.get("account")
    maintenance = activation_contract.get("maintenanceWindow")
    if not isinstance(release_digest, str) or not isinstance(account, Mapping):
        raise ActivationPackageError("activation contract maintenance binding is invalid")
    if not isinstance(maintenance, Mapping):
        raise ActivationPackageError("activation contract maintenance window is missing")
    document = {
        "schemaVersion": MAINTENANCE_CONTRACT_SCHEMA,
        "packageRoot": activation_package_root,
        "releaseManifestDigest": release_digest,
        "account": dict(account),
        "scope": "maintenance-window-for-this-package-only",
        "writerUnitBaseline": maintenance.get("writerUnitBaseline"),
        "successorUnitBaseline": maintenance.get("successorUnitBaseline"),
        "storeBindings": maintenance.get("storeBindings"),
        "deferredStoreBindings": maintenance.get("deferredStoreBindings"),
        "preservationInputs": maintenance.get("preservationInputs"),
        "evidenceRoot": maintenance.get("evidenceRoot"),
        "acceptanceChecks": maintenance.get("acceptanceChecks"),
        "stages": maintenance.get("stages"),
        "stageTimeoutSeconds": maintenance.get("stageTimeoutSeconds"),
        "windowTimeoutSeconds": maintenance.get("windowTimeoutSeconds"),
        "earlyRollbackCommands": maintenance.get("earlyRollbackCommands"),
        "earlyRollbackTimeoutSeconds": maintenance.get(
            "earlyRollbackTimeoutSeconds"
        ),
        "earlyRollbackWindowTimeoutSeconds": maintenance.get(
            "earlyRollbackWindowTimeoutSeconds"
        ),
        "earlyRollbackStartIndex": maintenance.get("earlyRollbackStartIndex"),
        "rollbackCommands": maintenance.get("rollbackCommands"),
        "rollbackTimeoutSeconds": maintenance.get("rollbackTimeoutSeconds"),
        "rollbackWindowTimeoutSeconds": maintenance.get(
            "rollbackWindowTimeoutSeconds"
        ),
        "rollbackStartIndex": maintenance.get("rollbackStartIndex"),
        "secretInputs": maintenance.get("secretInputs"),
    }
    try:
        validate_maintenance_contract(document)
    except ValueError as error:
        raise ActivationPackageError("maintenance contract is invalid") from error
    target = package / "public" / "maintenance-window-contract.json"
    _write_new(target, _canonical(document) + b"\n", 0o644)
    return document


def _validate_migration_rehearsal_semantics(package: Path) -> dict[str, object]:
    report_path = package / "private" / "migration" / "migration-report.json"
    try:
        raw, metadata = _stable_read(report_path)
        report = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("migration rehearsal report is invalid") from error
    try:
        contract_raw, _contract_metadata = _stable_read(
            package / "public" / "activation-contract.json"
        )
        contract = json.loads(contract_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("activation contract is invalid") from error
    bounds = report.get("backupBounds") if isinstance(report, dict) else None
    source = report.get("source") if isinstance(report, dict) else None
    contract_source = contract.get("sourceStore") if isinstance(contract, dict) else None
    backup = report.get("backup") if isinstance(report, dict) else None
    migrated = report.get("migrated") if isinstance(report, dict) else None
    started = bounds.get("startedUnixNs") if isinstance(bounds, dict) else None
    completed = bounds.get("completedUnixNs") if isinstance(bounds, dict) else None
    before_counts = report.get("rowCountsBefore") if isinstance(report, dict) else None
    after_counts = report.get("rowCountsAfter") if isinstance(report, dict) else None
    schema_before = report.get("schemaBefore") if isinstance(report, dict) else None
    schema_after = report.get("schemaAfter") if isinstance(report, dict) else None
    normalization = report.get("copyNormalization") if isinstance(report, dict) else None
    reindexed = (
        normalization.get("reindexedExpressionIndexes")
        if isinstance(normalization, dict)
        else None
    )
    package_owner = package.lstat().st_uid
    backup_path = package / "private" / "migration" / "rehearsal-source.sqlite3"
    migrated_path = package / "private" / "migration" / "rehearsal-migrated.sqlite3"
    try:
        observed_backup = _sealed_migration_artifact_evidence(
            backup_path,
            expected_uid=package_owner,
        )
        backup_schema = observed_backup["schema"]
        if not isinstance(backup_schema, dict) or not isinstance(
            backup_schema.get("countedTables"),
            list,
        ):
            raise ActivationPackageError("sealed backup schema evidence is invalid")
        counted_tables = tuple(str(value) for value in backup_schema["countedTables"])
        observed_migrated = _sealed_migration_artifact_evidence(
            migrated_path,
            expected_uid=package_owner,
            counted_tables=counted_tables,
        )
    except ActivationPackageError as error:
        raise ActivationPackageError("migration rehearsal artifact evidence is invalid") from error
    _require_canary_store_schema(schema_after)
    _require_canary_store_schema(observed_migrated["schema"])
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
    artifact_evidence_valid = (
        isinstance(backup, dict)
        and isinstance(migrated, dict)
        and isinstance(backup.get("path"), str)
        and isinstance(migrated.get("path"), str)
        and Path(str(backup["path"])).name == backup_path.name
        and Path(str(migrated["path"])).name == migrated_path.name
        and backup.get("sha256") == observed_backup["sha256"]
        and backup.get("size") == observed_backup["size"]
        and backup.get("integrityCheck") == observed_backup["integrityCheck"]
        and migrated.get("sha256") == observed_migrated["sha256"]
        and migrated.get("size") == observed_migrated["size"]
        and migrated.get("integrityCheck") == observed_migrated["integrityCheck"]
        and reindexed == observed_backup["approvedExpressionIndexes"]
        and observed_migrated["approvedExpressionIndexes"]
        == sorted(COPIED_EXPRESSION_INDEX_SQL)
        and before_counts == observed_backup["rowCounts"]
        and after_counts == observed_migrated["rowCounts"]
        and schema_before == observed_backup["schema"]
        and schema_after == observed_migrated["schema"]
        and isinstance(before_counts, dict)
        and bool(before_counts)
        and isinstance(after_counts, dict)
        and bool(after_counts)
    )
    if not artifact_evidence_valid:
        raise ActivationPackageError("migration rehearsal artifact evidence does not match sealed databases")
    source_binding_fields = ("path", "device", "inode", "uid", "gid", "mode")
    if (
        not isinstance(source, dict)
        or not isinstance(contract_source, dict)
        or any(source.get(field) != contract_source.get(field) for field in source_binding_fields)
    ):
        raise ActivationPackageError(
            "activation contract source does not match the migration rehearsal source"
        )
    if (
        metadata.st_uid != package_owner
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(report, dict)
        or report.get("schemaVersion") != "overseer.activation-migration-rehearsal.v1"
        or report.get("status") != "rehearsal_complete"
        or report.get("sourceMutationPerformed") is not False
        or source.get("journalMode") != "wal"
        or not isinstance(normalization, dict)
        or normalization.get("preReindexQuickCheck") != "ok"
        or normalization.get("journalMode") != "delete"
        or normalization.get("sourceMutationPerformed") is not False
        or not isinstance(reindexed, list)
        or any(not isinstance(name, str) for name in reindexed)
        or reindexed != sorted(reindexed)
        or len(reindexed) != len(set(reindexed))
        or any(name not in COPIED_EXPRESSION_INDEX_SQL for name in reindexed)
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
    try:
        activation_raw, _activation_metadata = _stable_read(required[0])
        activation_contract = json.loads(activation_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("activation contract is invalid") from error
    if not isinstance(activation_contract, dict):
        raise ActivationPackageError("activation contract is invalid")
    if "maintenanceWindow" in activation_contract:
        maintenance_path = package / "public" / "maintenance-window-contract.json"
        if not maintenance_path.is_file() or maintenance_path.is_symlink():
            raise ActivationPackageError(
                "maintenance-capable package is missing its maintenance contract"
            )
        _read_maintenance_contract_file(package, require_bound_package=False)
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


def _maintenance_approval_record_path() -> Path:
    return Path("/var/lib/overseer-executor/approved-maintenance-window.json")


def _maintenance_state_path() -> Path:
    return Path("/var/lib/overseer-executor/maintenance-window-state.json")


def _maintenance_rollback_retry_approval_path(state_digest: str) -> Path:
    if len(state_digest) != 64 or set(state_digest) - _HEX:
        raise ActivationPackageError(
            "maintenance rollback retry state digest is invalid"
        )
    return Path(
        "/var/lib/overseer-executor/"
        f"approved-maintenance-rollback-retry-{state_digest}.json"
    )


def _activation_phase_approval_record_path(phase: str) -> Path:
    if phase not in ACTIVATION_PHASES:
        raise ActivationPackageError("unsupported activation phase")
    return Path(f"/var/lib/overseer-executor/approved-activation-phase-{phase}.json")


def _installed_credential_root() -> Path:
    return Path("/etc/overseer")


def _copy_package_regular_to_new_path(
    source: Path,
    target: Path,
    *,
    package_owner: int,
    source_mode: int,
    expected_size: int,
) -> int:
    """Stream one descriptor-bound package file into a new destination path."""

    try:
        before = source.lstat()
    except OSError as error:
        raise ActivationPackageError("source activation package file could not be inspected") from error
    if (
        source.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != package_owner
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != source_mode
        or before.st_size != expected_size
    ):
        raise ActivationPackageError("source activation package file metadata is invalid")
    source_descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    target_descriptor: int | None = None
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
    try:
        opened = os.fstat(source_descriptor)
        if identity(opened) != identity(before):
            raise ActivationPackageError("source activation package file changed while opening")
        if opened.st_blocks * 512 < expected_size:
            raise ActivationPackageError("sparse activation package files are not allowed")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        target_descriptor = os.open(target, flags, 0o600)
        copied = 0
        while copied < before.st_size:
            chunk = os.read(source_descriptor, min(1024 * 1024, before.st_size - copied))
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError("activation package copy made no progress")
                copied += written
                view = view[written:]
        after = os.fstat(source_descriptor)
        try:
            lexical_after = source.lstat()
        except OSError as error:
            raise ActivationPackageError("source activation package file changed during copy") from error
        if (
            identity(after) != identity(before)
            or identity(lexical_after) != identity(before)
            or copied != before.st_size
        ):
            raise ActivationPackageError("source activation package file changed during copy")
        os.fchmod(target_descriptor, source_mode)
        os.fsync(target_descriptor)
        target_metadata = os.fstat(target_descriptor)
        if (
            not stat.S_ISREG(target_metadata.st_mode)
            or target_metadata.st_nlink != 1
            or target_metadata.st_size != expected_size
            or stat.S_IMODE(target_metadata.st_mode) != source_mode
        ):
            raise ActivationPackageError("imported activation package file metadata is invalid")
    except BaseException:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_descriptor)
        if target_descriptor is not None:
            os.close(target_descriptor)
    return copied


def _remove_failed_package_import(stage: Path, *, destination: Path) -> None:
    """Remove only a private temporary sibling created by the package importer."""

    expected_prefix = f".{destination.name}.import-"
    if stage.parent != destination.parent or not stage.name.startswith(expected_prefix):
        raise ActivationPackageError("refusing unsafe package import cleanup target")
    try:
        metadata = stage.lstat()
    except FileNotFoundError:
        return
    import_owner = os.geteuid()
    if (
        stage.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != import_owner
    ):
        raise ActivationPackageError("package import cleanup target is unsafe")
    for directory, directories, _files in os.walk(stage, topdown=True, followlinks=False):
        path = Path(directory)
        directory_metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != import_owner
        ):
            raise ActivationPackageError("package import cleanup tree is unsafe")
        os.chmod(path, 0o700)
        for name in directories:
            child = path / name
            child_metadata = child.lstat()
            if (
                child.is_symlink()
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_uid != import_owner
            ):
                raise ActivationPackageError("package import cleanup tree is unsafe")
            os.chmod(child, 0o700)
    shutil.rmtree(stage)


def _package_import_expectations(
    source_package: Path,
    expected_package_digest: str,
) -> tuple[dict[str, tuple[int, int]], int]:
    """Derive the exact import path, mode, and byte budget from the sealed manifest."""

    manifest = _read_bound_package_manifest(source_package, expected_package_digest)
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ActivationPackageError("package manifest file inventory is invalid")
    expectations: dict[str, tuple[int, int]] = {}
    total_size = 0
    for item in files:
        if not isinstance(item, Mapping):
            raise ActivationPackageError("package manifest file inventory is invalid")
        path = item.get("path")
        size = item.get("size")
        mode = item.get("mode")
        if (
            not isinstance(path, str)
            or _safe_relative(path) != path
            or path == "public/package-manifest.json"
            or type(size) is not int
            or size < 0
            or not isinstance(mode, str)
            or mode not in {"0400", "0444", "0500", "0555", "0600", "0644"}
            or item.get("links") != 1
            or item.get("ownerBinding") != "package-root-owner"
            or path in expectations
        ):
            raise ActivationPackageError("package manifest file inventory is invalid")
        expectations[path] = (size, int(mode, 8))
        total_size += size
    manifest_path = source_package / "public" / "package-manifest.json"
    _manifest_raw, manifest_metadata = _stable_read(manifest_path)
    if (
        manifest_metadata.st_uid != source_package.lstat().st_uid
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o644
        or manifest_metadata.st_nlink != 1
    ):
        raise ActivationPackageError("package manifest metadata is invalid")
    expectations["public/package-manifest.json"] = (manifest_metadata.st_size, 0o644)
    total_size += manifest_metadata.st_size
    if total_size > MAX_APPROVED_PACKAGE_IMPORT_BYTES:
        raise ActivationPackageError("activation package exceeds the approved import size bound")
    return expectations, total_size


def _validate_package_import_free_space(destination_parent: Path, required_size: int) -> None:
    """Require an exact free-space budget at the current import checkpoint."""

    filesystem = os.statvfs(destination_parent)
    available_size = filesystem.f_bavail * filesystem.f_frsize
    if available_size < required_size:
        raise ActivationPackageError("insufficient free space for bounded activation package import")


def _fsync_package_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ActivationPackageError("activation package directory changed before fsync")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rename_package_no_replace(source: Path, destination: Path) -> None:
    """Publish a staged package atomically without replacing any destination."""

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise ActivationPackageError("atomic no-replace package publication is unavailable") from error
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(destination),
        1,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise FileExistsError(error_number, "approved execution package destination already exists", destination)
        raise OSError(error_number, os.strerror(error_number), destination)


def _import_approved_execution_package(
    source_package: Path,
    *,
    expected_package_digest: str,
) -> Path:
    destination = APPROVED_EXECUTION_PACKAGE.absolute()
    if destination.exists() or destination.is_symlink():
        raise ActivationPackageError("approved execution package destination already exists")
    _ensure_directory(destination.parent)
    expectations, expected_total_size = _package_import_expectations(
        source_package,
        expected_package_digest,
    )
    import_headroom = max(
        expected_total_size,
        MIN_APPROVED_PACKAGE_IMPORT_HEADROOM_BYTES,
    )
    _validate_package_import_free_space(
        destination.parent,
        expected_total_size + import_headroom,
    )
    stage = destination.with_name(
        f".{destination.name}.import-{os.getpid()}-{secrets.token_hex(8)}"
    )
    _ensure_directory(stage)
    package_owner = source_package.lstat().st_uid
    directory_modes: list[tuple[Path, int]] = []
    copied_paths: set[str] = set()
    copied_total_size = 0
    published = False
    try:
        for directory, directories, files in os.walk(source_package, followlinks=False):
            source_directory = Path(directory)
            relative_directory = source_directory.relative_to(source_package)
            target_directory = stage / relative_directory
            source_directory_metadata = source_directory.lstat()
            source_directory_mode = stat.S_IMODE(source_directory_metadata.st_mode)
            if (
                source_directory.is_symlink()
                or source_directory_metadata.st_uid != package_owner
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
                expected = expectations.get(relative)
                if expected is None or relative in copied_paths:
                    raise ActivationPackageError("source activation package file inventory drifted")
                expected_size, mode = expected
                copied_size = _copy_package_regular_to_new_path(
                    source,
                    stage / relative,
                    package_owner=package_owner,
                    source_mode=mode,
                    expected_size=expected_size,
                )
                copied_paths.add(relative)
                copied_total_size += copied_size
                if copied_total_size > expected_total_size:
                    raise ActivationPackageError("activation package import exceeded its sealed byte budget")
        if copied_paths != set(expectations) or copied_total_size != expected_total_size:
            raise ActivationPackageError("activation package import did not consume its sealed byte budget")
        for target_directory, mode in sorted(
            directory_modes,
            key=lambda item: len(item[0].parts),
            reverse=True,
        ):
            os.chmod(target_directory, mode)
            _fsync_package_directory(target_directory)
        verify_activation_package(stage, expected_package_digest)
        _validate_package_import_free_space(destination.parent, import_headroom)
        _rename_package_no_replace(stage, destination)
        published = True
        try:
            _fsync_package_directory(destination.parent)
        except BaseException as error:
            raise ActivationPackageError(
                "approved execution package was published but parent durability is indeterminate"
            ) from error
    except BaseException:
        if not published:
            _remove_failed_package_import(stage, destination=destination)
        raise
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
    target = _activation_approval_record_path()
    if target.exists() or target.is_symlink():
        raise ActivationPackageError("activation approval record already exists")
    package = _import_approved_execution_package(
        source_package,
        expected_package_digest=expected_package_digest,
    )
    return _write_activation_approval_for_imported_package(
        package,
        source_package=source_package,
        expected_package_digest=expected_package_digest,
        verified=verified,
    )


def _write_activation_approval_for_imported_package(
    package: Path,
    *,
    source_package: Path,
    expected_package_digest: str,
    verified: Mapping[str, object],
) -> dict[str, object]:
    """Write approval only after an exact root-owned execution copy is verified."""

    contract = _sealed_package_json(
        package,
        expected_package_digest=expected_package_digest,
        relative_path="public/activation-contract.json",
    )
    if contract.get("packageRoot") != str(package):
        raise ActivationPackageError("sealed activation contract does not bind the execution package")
    target = _activation_approval_record_path()
    if target.exists() or target.is_symlink():
        raise ActivationPackageError("activation approval record already exists")
    document = {
        "schemaVersion": ACTIVATION_APPROVAL_SCHEMA,
        "approved": True,
        "packageRoot": str(package),
        "sourcePackageRoot": str(source_package),
        "packageDigest": expected_package_digest,
        "packageFileCount": verified["fileCount"],
        "liveExecutionScope": "sealed-package-import-and-verification-only",
    }
    _write_new(target, _canonical(document) + b"\n", 0o600)
    return document


def recover_activation_approval_import(
    source_package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
    action: str,
) -> dict[str, object]:
    """Adopt or remove an unapproved root-owned package left by interrupted publication."""

    _require_root_activation()
    if action not in {"adopt", "remove"}:
        raise ActivationPackageError("unsupported activation approval import recovery action")
    source_package = _validate_existing_package_destination(source_package_root)
    source_verified = verify_activation_package(source_package, expected_package_digest)
    target = _activation_approval_record_path()
    if target.exists() or target.is_symlink():
        raise ActivationPackageError("activation approval record already exists")
    package = _validate_existing_package_destination(APPROVED_EXECUTION_PACKAGE)
    if action == "adopt":
        imported_verified = verify_activation_package(package, expected_package_digest)
        if imported_verified != source_verified:
            raise ActivationPackageError("published execution package verification differs from source")
        _fsync_package_directory(package.parent)
        document = _write_activation_approval_for_imported_package(
            package,
            source_package=source_package,
            expected_package_digest=expected_package_digest,
            verified=source_verified,
        )
        return {"status": "adopted", **document}
    shutil.rmtree(package)
    _fsync_package_directory(package.parent)
    return {
        "status": "removed",
        "packageRoot": str(package),
        "packageDigest": expected_package_digest,
        "approvalRecorded": False,
    }


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
        != "sealed-package-import-and-verification-only"
    ):
        raise ActivationPackageError("activation approval record metadata or scope is invalid")
    digest = document.get("packageDigest")
    if not isinstance(digest, str):
        raise ActivationPackageError("activation approval record digest is invalid")
    verified = verify_activation_package(package, digest)
    if document.get("packageFileCount") != verified["fileCount"]:
        raise ActivationPackageError("activation approval record file count drifted")
    return document


def _read_maintenance_contract_file(
    package: Path,
    *,
    require_bound_package: bool = True,
) -> dict[str, object]:
    target = package / "public" / "maintenance-window-contract.json"
    try:
        raw, metadata = _stable_read(target)
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("maintenance contract is unavailable or invalid") from error
    try:
        package_owner = package.lstat().st_uid
    except OSError as error:
        raise ActivationPackageError("maintenance package root is unavailable") from error
    if (
        not isinstance(document, dict)
        or metadata.st_uid != package_owner
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        raise ActivationPackageError("maintenance contract metadata is invalid")
    try:
        validate_maintenance_contract(document)
    except ValueError as error:
        raise ActivationPackageError("maintenance contract is invalid") from error
    if require_bound_package and document.get("packageRoot") != str(package):
        raise ActivationPackageError(
            "maintenance contract package root is not the approved package"
        )
    return document


def _sealed_maintenance_contract(
    package: Path,
    *,
    package_digest: str,
) -> dict[str, object]:
    try:
        contract = _sealed_package_json(
            package,
            expected_package_digest=package_digest,
            relative_path="public/maintenance-window-contract.json",
        )
        validate_maintenance_contract(contract)
    except ActivationPackageError:
        raise
    except ValueError as error:
        raise ActivationPackageError("maintenance contract is invalid") from error
    if contract.get("packageRoot") != str(package):
        raise ActivationPackageError(
            "maintenance contract package root is not the approved package"
        )
    return contract


def _load_maintenance_approval(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    package = Path(package_root).resolve()
    target = _maintenance_approval_record_path()
    try:
        raw, metadata = _stable_read(target)
        document = json.loads(raw)
    except ActivationPackageError as error:
        raise ActivationPackageError(
            "maintenance approval record is unavailable or invalid"
        ) from error
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError(
            "maintenance approval record is unavailable or invalid"
        ) from error
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(document, dict)
    ):
        raise ActivationPackageError("maintenance approval record metadata is invalid")
    package_digest = document.get("packageDigest")
    plan_digest = document.get("planDigest")
    if not isinstance(package_digest, str) or not isinstance(plan_digest, str):
        raise ActivationPackageError("maintenance approval record digest is invalid")
    package_approval = _load_activation_approval(package)
    if package_approval.get("packageDigest") != package_digest:
        raise ActivationPackageError(
            "maintenance approval digest is not bound to the imported package approval"
        )
    verify_activation_package(package, package_digest)
    contract = _sealed_maintenance_contract(package, package_digest=package_digest)
    try:
        validate_maintenance_approval(
            document,
            str(package),
            package_digest,
            maintenance_plan_digest(contract),
            False,
        )
    except ValueError as error:
        raise ActivationPackageError("maintenance approval record binding is invalid") from error
    return document


def record_maintenance_window_approval(
    package_root: str | os.PathLike[str],
    expected_package_digest: str,
    *,
    allow_reboot: bool = False,
) -> dict[str, object]:
    """Record only the separate, no-reboot approval for one sealed package."""

    _require_root_activation()
    if os.geteuid() == 0 and _load_maintenance_state() is not None:
        raise ActivationPackageError(
            "maintenance approval requires an unstarted maintenance runner state"
        )
    if allow_reboot is not False:
        raise ActivationPackageError("maintenance approval must set allowReboot=false")
    package = Path(package_root).resolve()
    package_approval = _load_activation_approval(package)
    if package_approval.get("packageDigest") != expected_package_digest:
        raise ActivationPackageError(
            "maintenance approval digest does not match imported package approval"
        )
    verify_activation_package(package, expected_package_digest)
    contract = _read_maintenance_contract_file(package)
    plan_digest = maintenance_plan_digest(contract)
    target = _maintenance_approval_record_path()
    if target.exists() or target.is_symlink():
        raise ActivationPackageError("maintenance approval record already exists")
    document = {
        "schemaVersion": MAINTENANCE_APPROVAL_SCHEMA,
        "scope": "maintenance-window-for-this-package-only",
        "packageRoot": str(package),
        "packageDigest": expected_package_digest,
        "planDigest": plan_digest,
        "allowReboot": False,
    }
    try:
        validate_maintenance_approval(
            document,
            str(package),
            expected_package_digest,
            plan_digest,
            False,
        )
    except ValueError as error:
        raise ActivationPackageError("maintenance approval binding is invalid") from error
    _write_new(target, _canonical(document) + b"\n", 0o600)
    return document


def _maintenance_rollback_retry_approval_document(
    package: Path,
    state: Mapping[str, object],
) -> tuple[dict[str, object], str]:
    if (
        state.get("schemaVersion") != MAINTENANCE_RUNNER_STATE_SCHEMA
        or state.get("status") != "rollback_failed"
        or state.get("stage") not in {"rollback", "earlyRollback"}
        or state.get("writersStopped") is not True
        or not isinstance(state.get("packageDigest"), str)
        or not isinstance(state.get("planDigest"), str)
    ):
        raise ActivationPackageError(
            "maintenance state is not eligible for rollback retry approval"
        )
    state_digest = _sha256(_canonical(dict(state)))
    return (
        {
            "schemaVersion": MAINTENANCE_ROLLBACK_RETRY_APPROVAL_SCHEMA,
            "scope": "maintenance-rollback-retry-for-this-failed-state-only",
            "packageRoot": str(package),
            "packageDigest": state["packageDigest"],
            "planDigest": state["planDigest"],
            "failedStateDigest": state_digest,
        },
        state_digest,
    )


def _load_maintenance_rollback_retry_approval(
    package: Path,
    state: Mapping[str, object],
) -> dict[str, object]:
    expected, state_digest = _maintenance_rollback_retry_approval_document(
        package,
        state,
    )
    target = _maintenance_rollback_retry_approval_path(state_digest)
    try:
        raw, metadata = _stable_read(target)
        document = json.loads(raw)
    except (
        ActivationPackageError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise ActivationPackageError(
            "maintenance rollback retry approval is required"
        ) from error
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or document != expected
    ):
        raise ActivationPackageError(
            "maintenance rollback retry approval is invalid"
        )
    return expected


def _consume_maintenance_rollback_retry_approval(
    package: Path,
    state: Mapping[str, object],
    approval: Mapping[str, object],
) -> Path:
    """Atomically consume one exact retry approval before command zero."""

    expected, state_digest = _maintenance_rollback_retry_approval_document(
        package,
        state,
    )
    if dict(approval) != expected:
        raise ActivationPackageError(
            "maintenance rollback retry approval changed before consumption"
        )
    target = _maintenance_rollback_retry_approval_path(state_digest)
    try:
        raw, before = _stable_read(target)
    except (ActivationPackageError, OSError) as error:
        raise ActivationPackageError(
            "maintenance rollback retry approval changed before consumption"
        ) from error
    root_uid, root_gid = _activation_root_identity()
    if (
        raw != _canonical(expected) + b"\n"
        or (before.st_uid, before.st_gid) != (root_uid, root_gid)
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise ActivationPackageError(
            "maintenance rollback retry approval changed before consumption"
        )
    consumed = target.with_name(
        f"consumed-{target.stem}-{time.time_ns()}-{secrets.token_hex(8)}.json"
    )
    if consumed.exists() or consumed.is_symlink():
        raise ActivationPackageError(
            "maintenance rollback retry consumption destination exists"
        )
    try:
        _rename_package_no_replace(target, consumed)
        _fsync_package_directory(target.parent)
        consumed_raw, after = _stable_read(consumed)
    except OSError as error:
        raise ActivationPackageError(
            "maintenance rollback retry approval could not be consumed"
        ) from error
    if (
        consumed_raw != raw
        or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        or (after.st_uid, after.st_gid) != (before.st_uid, before.st_gid)
        or stat.S_IMODE(after.st_mode) != 0o600
    ):
        raise ActivationPackageError(
            "consumed maintenance rollback retry approval is invalid"
        )
    return consumed


def record_maintenance_rollback_retry_approval(
    package_root: str | os.PathLike[str],
    expected_package_digest: str,
    expected_state_digest: str,
) -> dict[str, object]:
    """Approve one retry for one exact terminal failed rollback state."""

    _require_root_activation()
    package = Path(package_root).resolve()
    state = _load_maintenance_state()
    if state is None:
        raise ActivationPackageError(
            "maintenance rollback retry requires a failed runner state"
        )
    document, state_digest = _maintenance_rollback_retry_approval_document(
        package,
        state,
    )
    if document["packageDigest"] != expected_package_digest:
        raise ActivationPackageError(
            "maintenance rollback retry package digest does not match"
        )
    if state_digest != expected_state_digest:
        raise ActivationPackageError(
            "maintenance rollback retry state digest does not match"
        )
    approval = _load_maintenance_approval(package)
    if (
        approval.get("packageDigest") != document["packageDigest"]
        or approval.get("planDigest") != document["planDigest"]
    ):
        raise ActivationPackageError(
            "maintenance rollback retry is not bound to the active approval"
        )
    target = _maintenance_rollback_retry_approval_path(state_digest)
    if target.exists() or target.is_symlink():
        raise ActivationPackageError(
            "maintenance rollback retry approval already exists"
        )
    _write_new(target, _canonical(document) + b"\n", 0o600)
    return document


def verify_approved_maintenance_window(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Verify the separate maintenance approval and its sealed contract."""

    _require_root_activation()
    package = Path(package_root).resolve()
    approval = _load_maintenance_approval(package)
    digest = str(approval["packageDigest"])
    contract = _sealed_maintenance_contract(package, package_digest=digest)
    plan_digest = maintenance_plan_digest(contract)
    if approval.get("planDigest") != plan_digest:
        raise ActivationPackageError("maintenance approval plan digest drifted")
    return {
        "status": "verified",
        "packageDigest": digest,
        "planDigest": plan_digest,
        "allowReboot": False,
    }


def _load_activation_approval_for_rollback(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Load current or legacy package authority only for sealed recovery."""

    package = Path(package_root).resolve()
    target = _activation_approval_record_path()
    try:
        raw, metadata = _stable_read(target)
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("activation rollback approval is unavailable or invalid") from error
    schema = document.get("schemaVersion") if isinstance(document, dict) else None
    expected_scope = {
        ACTIVATION_APPROVAL_SCHEMA: "sealed-package-import-and-verification-only",
        LEGACY_ACTIVATION_APPROVAL_SCHEMA: (
            "staging-canary-and-cutover-for-this-package-only"
        ),
    }.get(schema)
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(document, dict)
        or expected_scope is None
        or document.get("approved") is not True
        or document.get("packageRoot") != str(package)
        or document.get("liveExecutionScope") != expected_scope
    ):
        raise ActivationPackageError("activation rollback approval metadata or scope is invalid")
    digest = document.get("packageDigest")
    if not isinstance(digest, str):
        raise ActivationPackageError("activation rollback approval digest is invalid")
    verified = verify_activation_package(package, digest)
    if document.get("packageFileCount") != verified["fileCount"]:
        raise ActivationPackageError("activation rollback approval file count drifted")
    return document


def _sealed_package_json(
    package: Path,
    *,
    expected_package_digest: str,
    relative_path: str,
) -> dict[str, object]:
    verify_activation_package(package, expected_package_digest)
    return _bound_package_json(
        package,
        expected_package_digest=expected_package_digest,
        relative_path=relative_path,
    )


def _bound_package_json(
    package: Path,
    *,
    expected_package_digest: str,
    relative_path: str,
) -> dict[str, object]:
    """Read one manifest-bound JSON file without re-verifying unrelated files."""

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
        owner_id = int(owner) if owner.isdecimal() else pwd.getpwnam(owner).pw_uid
        group_id = int(group) if group.isdecimal() else grp.getgrnam(group).gr_gid
        return owner_id, group_id
    except (KeyError, ValueError) as error:
        raise ActivationPackageError("installed activation owner or group is unavailable") from error


def _validate_contract_principal_schema(contract: Mapping[str, object]) -> tuple[int, int]:
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
    return god_uid, god_gid


def _validate_canary_contract_layout(
    package: Path,
    contract: Mapping[str, object],
    *,
    expected_package_digest: str | None = None,
) -> dict[str, Path | str]:
    paths = _canary_state_paths(
        package,
        expected_package_digest=expected_package_digest,
    )
    canary = contract.get("canary")
    if not isinstance(canary, Mapping):
        raise ActivationPackageError("activation canary state contract is invalid")
    expected = {
        "canaryInstanceId": str(paths["canaryInstanceId"]),
        "stateDirectory": str(paths["stateDirectory"]),
        "store": str(paths["store"]),
        "psychloBridgeDatabase": str(paths["psychloBridgeDatabase"]),
        "roadexRelayDatabase": str(paths["roadexRelayDatabase"]),
        "preserveFailedStateForEvidence": True,
        "ownershipHandoffCommand": "handoff-start-canary",
        "requiresNoExistingServicePrincipalProcesses": True,
    }
    if any(canary.get(name) != value for name, value in expected.items()):
        raise ActivationPackageError("activation canary state contract drifted")
    state_directory = Path(str(paths["stateDirectory"]))
    if (
        not state_directory.is_absolute()
        or state_directory.parent != CANARY_STATE_ROOT
        or any(Path(str(paths[name])).parent != state_directory for name in (
            "store",
            "psychloBridgeDatabase",
            "roadexRelayDatabase",
        ))
    ):
        raise ActivationPackageError("activation canary state path is invalid")
    return paths


def _open_verified_directory(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    label: str,
) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        lexical = path.lstat()
    except OSError as error:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise ActivationPackageError(f"{label} could not be opened safely") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(lexical.st_mode)
        or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
        or opened.st_uid != expected_uid
        or opened.st_gid != expected_gid
        or stat.S_IMODE(opened.st_mode) != expected_mode
    ):
        os.close(descriptor)
        raise ActivationPackageError(f"{label} identity or mode is invalid")
    return descriptor


def _ensure_canary_state_root() -> tuple[int, int]:
    root_uid, root_gid = _activation_root_identity()
    parent = CANARY_STATE_ROOT.parent
    parent_descriptor = _open_verified_directory(
        parent,
        expected_uid=root_uid,
        expected_gid=root_gid,
        expected_mode=0o755,
        label="canary state root parent",
    )
    if CANARY_STATE_ROOT.name in {"", ".", ".."}:
        os.close(parent_descriptor)
        raise ActivationPackageError("canary state root name is invalid")
    created = False
    root_descriptor = -1
    try:
        try:
            os.mkdir(CANARY_STATE_ROOT.name, 0o711, dir_fd=parent_descriptor)
            created = True
        except FileExistsError:
            pass
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        root_descriptor = os.open(
            CANARY_STATE_ROOT.name,
            flags,
            dir_fd=parent_descriptor,
        )
        if created:
            os.fchown(root_descriptor, root_uid, root_gid)
            os.fchmod(root_descriptor, 0o711)
            os.fsync(root_descriptor)
            os.fsync(parent_descriptor)
        root_metadata = os.fstat(root_descriptor)
        lexical = CANARY_STATE_ROOT.lstat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or CANARY_STATE_ROOT.is_symlink()
            or (root_metadata.st_dev, root_metadata.st_ino)
            != (lexical.st_dev, lexical.st_ino)
            or root_metadata.st_uid != root_uid
            or root_metadata.st_gid != root_gid
            or stat.S_IMODE(root_metadata.st_mode) != 0o711
        ):
            raise ActivationPackageError("canary state root identity or mode is invalid")
        return parent_descriptor, root_descriptor
    except BaseException:
        sync_error: OSError | None = None
        for descriptor in (root_descriptor, parent_descriptor):
            if descriptor < 0:
                continue
            try:
                os.fsync(descriptor)
            except OSError as error:
                if sync_error is None:
                    sync_error = error
        if root_descriptor >= 0:
            os.close(root_descriptor)
        os.close(parent_descriptor)
        if sync_error is not None:
            raise ActivationPackageError(
                "canary state root failure evidence could not be made durable"
            ) from sync_error
        raise


def _copy_canary_store_at(
    source: Path,
    *,
    expected_source_uid: int,
    target_directory_descriptor: int,
    target_name: str,
) -> None:
    source_metadata = _validate_store_artifact(
        source,
        label="sealed canary migration source",
        expected_uid=expected_source_uid,
    )
    try:
        source_descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise ActivationPackageError("sealed canary migration source could not be opened") from error
    target_descriptor = -1
    try:
        opened_source = os.fstat(source_descriptor)
        if _metadata_identity(opened_source) != _metadata_identity(source_metadata):
            raise ActivationPackageError("sealed canary migration source changed while opening")
        target_descriptor = os.open(
            target_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=target_directory_descriptor,
        )
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError("canary store copy made no progress")
                copied += written
                view = view[written:]
        if copied != opened_source.st_size:
            raise ActivationPackageError("canary store copy was truncated")
        root_uid, root_gid = _activation_root_identity()
        os.fchown(target_descriptor, root_uid, root_gid)
        os.fchmod(target_descriptor, 0o600)
        os.fsync(target_descriptor)
        if _metadata_identity(os.fstat(source_descriptor)) != _metadata_identity(source_metadata):
            raise ActivationPackageError("sealed canary migration source changed during copy")
    except OSError as error:
        raise ActivationPackageError("canary store could not be staged safely") from error
    finally:
        sync_error: OSError | None = None
        if target_descriptor >= 0:
            try:
                os.fsync(target_descriptor)
            except OSError as error:
                sync_error = error
            os.close(target_descriptor)
        os.close(source_descriptor)
        if sync_error is not None:
            raise ActivationPackageError(
                "failed canary store copy could not be made durable"
            ) from sync_error


def _create_empty_canary_database_at(
    *,
    target_directory_descriptor: int,
    target_name: str,
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            target_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=target_directory_descriptor,
        )
        root_uid, root_gid = _activation_root_identity()
        os.fchown(descriptor, root_uid, root_gid)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    except OSError as error:
        raise ActivationPackageError("disposable canary database could not be created safely") from error
    finally:
        sync_error: OSError | None = None
        if descriptor >= 0:
            try:
                os.fsync(descriptor)
            except OSError as error:
                sync_error = error
            os.close(descriptor)
        if sync_error is not None:
            raise ActivationPackageError(
                "failed disposable canary database could not be made durable"
            ) from sync_error


def _expected_canary_migration_evidence(
    package: Path,
    *,
    expected_package_digest: str,
) -> dict[str, object]:
    report = _bound_package_json(
        package,
        expected_package_digest=expected_package_digest,
        relative_path="private/migration/migration-report.json",
    )
    migrated = report.get("migrated")
    if (
        report.get("schemaVersion") != "overseer.activation-migration-rehearsal.v1"
        or report.get("status") != "rehearsal_complete"
        or report.get("sourceMutationPerformed") is not False
        or not isinstance(migrated, Mapping)
        or not isinstance(migrated.get("sha256"), str)
        or len(str(migrated["sha256"])) != 64
        or set(str(migrated["sha256"])) - _HEX
        or type(migrated.get("size")) is not int
        or int(migrated["size"]) < 0
        or migrated.get("integrityCheck") != "ok"
    ):
        raise ActivationPackageError("sealed canary migration evidence is invalid")
    return {
        "sha256": str(migrated["sha256"]),
        "size": int(migrated["size"]),
        "integrityCheck": "ok",
    }


def _verify_staged_canary_store(
    package: Path,
    contract: Mapping[str, object],
    *,
    expected_package_digest: str | None = None,
    pre_handoff: bool = False,
) -> dict[str, object]:
    paths = _validate_canary_contract_layout(
        package,
        contract,
        expected_package_digest=expected_package_digest,
    )
    root_uid, root_gid = _activation_root_identity()
    parent_descriptor = -1
    root_descriptor = -1
    state_descriptor = -1
    state_directory = Path(str(paths["stateDirectory"]))
    expected_uid = root_uid if pre_handoff else APPROVED_OVERSEER_UID
    expected_gid = root_gid if pre_handoff else APPROVED_OVERSEER_GID
    if expected_package_digest is None:
        source_evidence = _sealed_migration_artifact_evidence(
            package / "private" / "migration" / "rehearsal-migrated.sqlite3",
            expected_uid=package.lstat().st_uid,
        )
        expected_evidence = {
            name: source_evidence[name]
            for name in ("sha256", "size", "integrityCheck")
        }
    else:
        expected_evidence = _expected_canary_migration_evidence(
            package,
            expected_package_digest=expected_package_digest,
        )
    expected_size = int(expected_evidence["size"])
    if expected_size > MAX_APPROVED_PACKAGE_IMPORT_BYTES:
        raise ActivationPackageError("staged canary store expected size exceeds the approved bound")
    try:
        parent_descriptor = _open_verified_directory(
            CANARY_STATE_ROOT.parent,
            expected_uid=root_uid,
            expected_gid=root_gid,
            expected_mode=0o755,
            label="canary state root parent",
        )
        root_descriptor = _open_verified_directory(
            CANARY_STATE_ROOT,
            expected_uid=root_uid,
            expected_gid=root_gid,
            expected_mode=0o711,
            label="canary state root",
        )
        state_descriptor = _open_verified_directory(
            state_directory,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_mode=0o700,
            label="package-bound canary state directory",
        )
        expected_entries = [
            "overseer.sqlite3",
            "psychlo-bridge.sqlite3",
            "roadex-relay.sqlite3",
        ]
        entries = sorted(os.listdir(state_descriptor))
        if entries != expected_entries:
            raise ActivationPackageError("unexpected canary SQLite artifact exists before startup")
        target_path = Path(str(paths["store"]))
        target_metadata = _validate_store_artifact(
            target_path,
            label="staged canary store",
            expected_uid=expected_uid,
        )
        if target_metadata.st_gid != expected_gid:
            raise ActivationPackageError("staged canary store has an unexpected group")
        if target_metadata.st_size != expected_size:
            raise ActivationPackageError("staged canary store has an unexpected size")
        if target_metadata.st_blocks * 512 < expected_size:
            raise ActivationPackageError("staged canary store must not be sparse")
        target_evidence = _sealed_migration_artifact_evidence(
            target_path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_size=expected_size,
        )
        if any(target_evidence.get(name) != value for name, value in expected_evidence.items()):
            raise ActivationPackageError("staged canary store content or SQLite evidence drifted")
        _require_canary_store_schema(target_evidence.get("schema"))
        for name in ("psychloBridgeDatabase", "roadexRelayDatabase"):
            disposable_path = Path(str(paths[name]))
            disposable_metadata = _validate_store_artifact(
                disposable_path,
                label="empty disposable canary database",
                expected_uid=expected_uid,
            )
            if disposable_metadata.st_gid != expected_gid or disposable_metadata.st_size != 0:
                raise ActivationPackageError("disposable canary database is not pristine")
            disposable = _stream_hash_regular(
                disposable_path,
                label="empty disposable canary database",
                expected_size=0,
            )
            if (
                disposable["size"] != 0
                or disposable["uid"] != expected_uid
                or disposable["gid"] != expected_gid
                or disposable["mode"] != "0600"
                or disposable["links"] != 1
            ):
                raise ActivationPackageError("disposable canary database is not pristine")
        return {
            "verified": True,
            "canaryInstanceId": str(paths["canaryInstanceId"]),
            "stateDirectory": str(state_directory),
            "store": str(paths["store"]),
            "sha256": str(target_evidence["sha256"]),
            "size": int(target_evidence["size"]),
            "sidecarFree": True,
            "handoffRequired": pre_handoff,
        }
    finally:
        for descriptor in (state_descriptor, root_descriptor, parent_descriptor):
            if descriptor >= 0:
                os.close(descriptor)


def stage_canary_store(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Publish a new package-bound canary store without reusing SQLite state."""

    _require_root_activation()
    package = Path(package_root).resolve()
    contract, _lock_descriptor = _require_active_phase_command(
        package,
        phase="staging-canary",
        command_name="stage-canary-store",
        expected_options={"--package-root": str(package)},
    )
    expected_digest: str | None = None
    if (package / "public" / "package-manifest.json").is_file():
        active_state = _load_activation_state()
        active_digest = (
            active_state.get("packageDigest")
            if isinstance(active_state, Mapping)
            else None
        )
        if (
            not isinstance(active_digest, str)
            or len(active_digest) != 64
            or set(active_digest) - _HEX
        ):
            raise ActivationPackageError("active canary staging package digest is unavailable")
        expected_digest = active_digest
    paths = _validate_canary_contract_layout(
        package,
        contract,
        expected_package_digest=expected_digest,
    )
    source = package / "private" / "migration" / "rehearsal-migrated.sqlite3"
    _validate_store_artifact(
        source,
        label="sealed canary migration source",
        expected_uid=package.lstat().st_uid,
    )
    parent_descriptor, root_descriptor = _ensure_canary_state_root()
    state_descriptor = -1
    instance_id = str(paths["canaryInstanceId"])
    try:
        try:
            os.mkdir(instance_id, 0o700, dir_fd=root_descriptor)
        except FileExistsError as error:
            raise ActivationPackageError("package-bound canary state directory already exists") from error
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        state_descriptor = os.open(instance_id, flags, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
        os.fsync(state_descriptor)
        created = os.fstat(state_descriptor)
        if (
            created.st_uid != _activation_root_identity()[0]
            or created.st_gid != _activation_root_identity()[1]
            or stat.S_IMODE(created.st_mode) != 0o700
        ):
            raise ActivationPackageError("new canary state directory identity is invalid")
        _copy_canary_store_at(
            source,
            expected_source_uid=package.lstat().st_uid,
            target_directory_descriptor=state_descriptor,
            target_name="overseer.sqlite3",
        )
        os.fsync(state_descriptor)
        for name in ("psychlo-bridge.sqlite3", "roadex-relay.sqlite3"):
            _create_empty_canary_database_at(
                target_directory_descriptor=state_descriptor,
                target_name=name,
            )
            os.fsync(state_descriptor)
        if sorted(os.listdir(state_descriptor)) != [
            "overseer.sqlite3",
            "psychlo-bridge.sqlite3",
            "roadex-relay.sqlite3",
        ]:
            raise ActivationPackageError("unexpected canary SQLite artifact appeared during staging")
        os.fsync(root_descriptor)
    finally:
        sync_error: OSError | None = None
        for descriptor in (state_descriptor, root_descriptor):
            if descriptor < 0:
                continue
            try:
                os.fsync(descriptor)
            except OSError as error:
                if sync_error is None:
                    sync_error = error
        for descriptor in (state_descriptor, root_descriptor, parent_descriptor):
            if descriptor >= 0:
                os.close(descriptor)
        if sync_error is not None:
            raise ActivationPackageError("canary staging evidence could not be made durable") from sync_error
    return _verify_staged_canary_store(
        package,
        contract,
        expected_package_digest=expected_digest,
        pre_handoff=True,
    )


def _processes_for_uid(uid: int) -> tuple[int, ...]:
    """Return processes carrying the dedicated UID in any credential slot."""

    if uid < 0:
        raise ActivationPackageError("service principal UID is invalid")
    matches: list[int] = []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as error:
        raise ActivationPackageError("service principal processes could not be inspected") from error
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            lines = (entry / "status").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ActivationPackageError(
                "service principal process credentials could not be inspected"
            ) from error
        uid_line = next((line for line in lines if line.startswith("Uid:")), None)
        if uid_line is None:
            raise ActivationPackageError("service principal process credentials are incomplete")
        try:
            process_uids = tuple(int(value) for value in uid_line.split()[1:])
        except ValueError as error:
            raise ActivationPackageError("service principal process credentials are invalid") from error
        if len(process_uids) != 4:
            raise ActivationPackageError("service principal process credentials are invalid")
        if uid in process_uids:
            matches.append(int(entry.name))
    return tuple(sorted(matches))


def _handoff_canary_state(paths: Mapping[str, Path | str]) -> None:
    """Transfer one root-owned verified namespace to the dedicated principal."""

    root_uid, root_gid = _activation_root_identity()
    parent_descriptor = -1
    root_descriptor = -1
    state_descriptor = -1
    file_descriptors: list[int] = []
    expected_names = (
        "overseer.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
    )
    try:
        parent_descriptor = _open_verified_directory(
            CANARY_STATE_ROOT.parent,
            expected_uid=root_uid,
            expected_gid=root_gid,
            expected_mode=0o755,
            label="canary state root parent",
        )
        root_descriptor = _open_verified_directory(
            CANARY_STATE_ROOT,
            expected_uid=root_uid,
            expected_gid=root_gid,
            expected_mode=0o711,
            label="canary state root",
        )
        state_descriptor = _open_verified_directory(
            Path(str(paths["stateDirectory"])),
            expected_uid=root_uid,
            expected_gid=root_gid,
            expected_mode=0o700,
            label="package-bound canary state directory",
        )
        if tuple(sorted(os.listdir(state_descriptor))) != expected_names:
            raise ActivationPackageError("canary ownership handoff found unexpected state")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        for name in expected_names:
            try:
                descriptor = os.open(name, flags, dir_fd=state_descriptor)
                file_descriptors.append(descriptor)
                lexical = os.stat(name, dir_fd=state_descriptor, follow_symlinks=False)
            except OSError as error:
                raise ActivationPackageError(
                    "canary ownership handoff artifact could not be opened safely"
                ) from error
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(lexical.st_mode)
                or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
                or opened.st_uid != root_uid
                or opened.st_gid != root_gid
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != 0o600
            ):
                raise ActivationPackageError("canary ownership handoff artifact is invalid")
        running = _processes_for_uid(APPROVED_OVERSEER_UID)
        if running:
            raise ActivationPackageError("service principal process exists before canary handoff")
        for descriptor in file_descriptors:
            os.fchown(descriptor, APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        os.fchown(state_descriptor, APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID)
        os.fchmod(state_descriptor, 0o700)
        os.fsync(state_descriptor)
        os.fsync(root_descriptor)
    except OSError as error:
        raise ActivationPackageError("canary ownership handoff failed safely") from error
    finally:
        sync_error: OSError | None = None
        for descriptor in (*file_descriptors, state_descriptor, root_descriptor):
            if descriptor < 0:
                continue
            try:
                os.fsync(descriptor)
            except OSError as error:
                if sync_error is None:
                    sync_error = error
        for descriptor in (*file_descriptors, state_descriptor, root_descriptor, parent_descriptor):
            if descriptor >= 0:
                os.close(descriptor)
        if sync_error is not None:
            raise ActivationPackageError(
                "canary ownership handoff evidence could not be made durable"
            ) from sync_error


def _canary_state_paths_from_contract(
    contract: Mapping[str, object],
) -> dict[str, Path | str] | None:
    canary = contract.get("canary")
    if not isinstance(canary, Mapping):
        return None
    names = (
        "canaryInstanceId",
        "stateDirectory",
        "store",
        "psychloBridgeDatabase",
        "roadexRelayDatabase",
    )
    if any(not isinstance(canary.get(name), str) for name in names):
        return None
    instance = str(canary["canaryInstanceId"])
    state_directory = Path(str(canary["stateDirectory"]))
    paths: dict[str, Path | str] = {
        "canaryInstanceId": instance,
        "stateDirectory": state_directory,
        "store": Path(str(canary["store"])),
        "psychloBridgeDatabase": Path(str(canary["psychloBridgeDatabase"])),
        "roadexRelayDatabase": Path(str(canary["roadexRelayDatabase"])),
    }
    expected = {
        "store": state_directory / "overseer.sqlite3",
        "psychloBridgeDatabase": state_directory / "psychlo-bridge.sqlite3",
        "roadexRelayDatabase": state_directory / "roadex-relay.sqlite3",
    }
    if (
        len(instance) != CANARY_INSTANCE_BYTES * 2
        or set(instance) - _HEX
        or state_directory != CANARY_STATE_ROOT / instance
        or any(paths[name] != value for name, value in expected.items())
        or canary.get("preserveFailedStateForEvidence") is not True
        or canary.get("ownershipHandoffCommand") != "handoff-start-canary"
        or canary.get("requiresNoExistingServicePrincipalProcesses") is not True
    ):
        raise ActivationPackageError("activation canary evidence path contract drifted")
    return paths


def _inspect_canary_state_from_contract(
    contract: Mapping[str, object],
    *,
    required: bool,
    seal: bool,
) -> dict[str, object]:
    """Validate stopped canary evidence and optionally root-seal it."""

    paths = _canary_state_paths_from_contract(contract)
    if paths is None:
        if required:
            raise ActivationPackageError("activation canary evidence contract is unavailable")
        return {"sealed": False, "status": "not-inventoried"}
    state_directory = Path(str(paths["stateDirectory"]))
    try:
        state_directory.lstat()
    except FileNotFoundError:
        if required:
            raise ActivationPackageError("canary evidence namespace is unavailable")
        return {"sealed": False, "status": "absent"}
    except OSError as error:
        raise ActivationPackageError("canary evidence namespace could not be inspected") from error
    inactive = ["/usr/bin/systemctl", "stop", "overseer-api-canary.service"]

    def require_quiescence() -> None:
        if not _cleanup_command_satisfied(inactive):
            raise ActivationPackageError(
                "canary service is not quiescent during evidence sealing"
            )
        if _processes_for_uid(APPROVED_OVERSEER_UID):
            raise ActivationPackageError(
                "service principal process exists during evidence sealing"
            )

    require_quiescence()

    root_uid, root_gid = _activation_root_identity()
    parent_descriptor = -1
    root_descriptor = -1
    state_descriptor = -1
    file_descriptors: list[int] = []
    validated_descriptors: list[int] = []
    base_names = {
        "overseer.sqlite3",
        "psychlo-bridge.sqlite3",
        "roadex-relay.sqlite3",
    }
    authority_lock_name = admin_authority_lock_path(paths["store"]).name
    allowed_names = set(base_names)
    allowed_names.add(authority_lock_name)
    for base in base_names:
        allowed_names.update(f"{base}{suffix}" for suffix in ("-wal", "-shm", "-journal"))
    try:
        parent_descriptor = _open_verified_directory(
            CANARY_STATE_ROOT.parent,
            expected_uid=root_uid,
            expected_gid=root_gid,
            expected_mode=0o755,
            label="canary state root parent",
        )
        root_descriptor = _open_verified_directory(
            CANARY_STATE_ROOT,
            expected_uid=root_uid,
            expected_gid=root_gid,
            expected_mode=0o711,
            label="canary state root",
        )
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        instance = state_directory.name
        state_descriptor = os.open(instance, flags, dir_fd=root_descriptor)
        opened_state = os.fstat(state_descriptor)
        lexical_state = os.stat(
            instance,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
        state_owner = (opened_state.st_uid, opened_state.st_gid)
        if (
            not stat.S_ISDIR(opened_state.st_mode)
            or not stat.S_ISDIR(lexical_state.st_mode)
            or (opened_state.st_dev, opened_state.st_ino)
            != (lexical_state.st_dev, lexical_state.st_ino)
            or state_owner
            not in {
                (root_uid, root_gid),
                (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID),
            }
            or stat.S_IMODE(opened_state.st_mode) not in {0o700, 0o500}
            or (
                stat.S_IMODE(opened_state.st_mode) == 0o500
                and state_owner != (root_uid, root_gid)
            )
            or (
                not seal
                and (
                    state_owner != (root_uid, root_gid)
                    or stat.S_IMODE(opened_state.st_mode) != 0o500
                )
            )
        ):
            raise ActivationPackageError("canary evidence namespace identity is invalid")
        entries = set(os.listdir(state_descriptor))
        if not base_names.issubset(entries) or not entries.issubset(allowed_names):
            raise ActivationPackageError("canary evidence namespace contains an invalid artifact")
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        total_size = 0
        for name in sorted(entries):
            descriptor = os.open(name, file_flags, dir_fd=state_descriptor)
            file_descriptors.append(descriptor)
            opened = os.fstat(descriptor)
            lexical = os.stat(name, dir_fd=state_descriptor, follow_symlinks=False)
            owner = (opened.st_uid, opened.st_gid)
            mode = stat.S_IMODE(opened.st_mode)
            total_size += opened.st_size
            if (
                not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(lexical.st_mode)
                or (opened.st_dev, opened.st_ino) != (lexical.st_dev, lexical.st_ino)
                or opened.st_nlink != 1
                or owner
                not in {
                    (root_uid, root_gid),
                    (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID),
                }
                or mode not in {0o600, 0o400}
                or (mode == 0o400 and owner != (root_uid, root_gid))
                or (not seal and (owner != (root_uid, root_gid) or mode != 0o400))
                or (name == authority_lock_name and opened.st_size != 0)
                or opened.st_size > MAX_APPROVED_PACKAGE_IMPORT_BYTES
                or total_size > MAX_APPROVED_PACKAGE_IMPORT_BYTES
            ):
                raise ActivationPackageError("canary evidence artifact identity is invalid")
            if name == authority_lock_name:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise ActivationPackageError(
                        "canary authority lock is active during evidence sealing"
                    ) from error
                locked = os.fstat(descriptor)
                lexical_locked = os.stat(
                    name,
                    dir_fd=state_descriptor,
                    follow_symlinks=False,
                )
                locked_owner = (locked.st_uid, locked.st_gid)
                locked_mode = stat.S_IMODE(locked.st_mode)
                if (
                    not stat.S_ISREG(locked.st_mode)
                    or not stat.S_ISREG(lexical_locked.st_mode)
                    or (locked.st_dev, locked.st_ino)
                    != (lexical_locked.st_dev, lexical_locked.st_ino)
                    or locked.st_nlink != 1
                    or lexical_locked.st_nlink != 1
                    or locked.st_size != 0
                    or locked_owner
                    not in {
                        (root_uid, root_gid),
                        (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID),
                    }
                    or locked_mode not in {0o600, 0o400}
                    or (
                        locked_mode == 0o400
                        and locked_owner != (root_uid, root_gid)
                    )
                    or (
                        not seal
                        and (
                            locked_owner != (root_uid, root_gid)
                            or locked_mode != 0o400
                        )
                    )
                ):
                    raise ActivationPackageError(
                        "canary evidence artifact identity is invalid"
                    )
            validated_descriptors.append(descriptor)
        require_quiescence()
        if seal:
            for descriptor in validated_descriptors:
                os.fchown(descriptor, root_uid, root_gid)
                os.fchmod(descriptor, 0o400)
                os.fsync(descriptor)
            os.fchown(state_descriptor, root_uid, root_gid)
            os.fchmod(state_descriptor, 0o500)
            os.fsync(state_descriptor)
            os.fsync(root_descriptor)
        require_quiescence()
    except OSError as error:
        raise ActivationPackageError("canary evidence namespace could not be sealed safely") from error
    finally:
        sync_error: OSError | None = None
        if seal:
            for descriptor in (*validated_descriptors, state_descriptor, root_descriptor):
                if descriptor < 0:
                    continue
                try:
                    os.fsync(descriptor)
                except OSError as error:
                    if sync_error is None:
                        sync_error = error
        for descriptor in (*file_descriptors, state_descriptor, root_descriptor, parent_descriptor):
            if descriptor >= 0:
                os.close(descriptor)
        if sync_error is not None:
            raise ActivationPackageError(
                "canary evidence sealing could not be made durable"
            ) from sync_error
    return {
        "sealed": True,
        "status": "root-read-only",
        "stateDirectory": str(state_directory),
        "artifactCount": len(file_descriptors),
    }


def _seal_canary_state_from_contract(
    contract: Mapping[str, object],
    *,
    required: bool,
) -> dict[str, object]:
    return _inspect_canary_state_from_contract(contract, required=required, seal=True)


def _verify_sealed_canary_state_from_contract(
    contract: Mapping[str, object],
    *,
    required: bool,
) -> dict[str, object]:
    return _inspect_canary_state_from_contract(contract, required=required, seal=False)


def handoff_start_canary(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Narrow the verified-state race and start the exact canary unit."""

    _require_root_activation()
    package = Path(package_root).resolve()
    contract, lock_descriptor = _require_active_phase_command(
        package,
        phase="staging-canary",
        command_name="handoff-start-canary",
        expected_options={"--package-root": str(package)},
    )
    active_state = _load_activation_state()
    expected_digest = active_state.get("packageDigest") if isinstance(active_state, Mapping) else None
    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != 64
        or set(expected_digest) - _HEX
    ):
        raise ActivationPackageError("active canary handoff package digest is unavailable")
    paths = _validate_canary_contract_layout(
        package,
        contract,
        expected_package_digest=expected_digest,
    )
    _verify_staged_canary_store(
        package,
        contract,
        expected_package_digest=expected_digest,
        pre_handoff=True,
    )
    inactive_command = [
        "/usr/bin/systemctl",
        "is-active",
        "--quiet",
        "overseer-api-canary.service",
    ]
    if (
        _execute_inherited_contract_command(
            inactive_command,
            lock_descriptor=lock_descriptor,
        )
        != 3
    ):
        raise ActivationPackageError("canary service is not inactive before ownership handoff")
    if _processes_for_uid(APPROVED_OVERSEER_UID):
        raise ActivationPackageError("service principal process exists before canary handoff")
    _handoff_canary_state(paths)
    start_command = ["/usr/bin/systemctl", "start", "overseer-api-canary.service"]
    if (
        _execute_inherited_contract_command(
            start_command,
            lock_descriptor=lock_descriptor,
        )
        != 0
    ):
        raise ActivationPackageError("canary service failed to start after ownership handoff")
    return {
        "started": True,
        "packageDigest": expected_digest,
        "stateDirectory": str(paths["stateDirectory"]),
    }


def _validate_contract_principal_binding(contract: Mapping[str, object]) -> None:
    god_uid, god_gid = _validate_contract_principal_schema(contract)
    _validate_principal_binding(
        god_uid=god_uid,
        god_gid=god_gid,
        overseer_uid=APPROVED_OVERSEER_UID,
        overseer_gid=APPROVED_OVERSEER_GID,
    )


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


def verify_maintenance_installed_release(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Re-hash every sealed immutable install before offline migration."""

    package = Path(package_root).resolve()
    contract, _lock_descriptor = _require_maintenance_active_sealed_command(
        package,
        command_name="verify-maintenance-installed-release",
        expected_options={"--package-root": str(package)},
    )
    approval = _load_maintenance_approval(package)
    package_digest = approval.get("packageDigest")
    stages = contract.get("stages")
    if not isinstance(package_digest, str) or not isinstance(stages, list):
        raise ActivationPackageError(
            "maintenance immutable install verification binding is invalid"
        )
    stage = next(
        (
            item
            for item in stages
            if isinstance(item, Mapping) and item.get("name") == "installRelease"
        ),
        None,
    )
    if not isinstance(stage, Mapping):
        raise ActivationPackageError(
            "maintenance immutable install stage is unavailable"
        )
    commands = stage.get("commands")
    if not isinstance(commands, list):
        raise ActivationPackageError(
            "maintenance immutable install commands are invalid"
        )
    return _verify_install_results(
        package,
        expected_package_digest=package_digest,
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


def _validate_canary_socket(
    socket_path: Path,
    *,
    expected_owner_uid: int,
    expected_owner_gid: int,
) -> os.stat_result:
    if not socket_path.is_absolute() or socket_path.is_symlink():
        raise ActivationPackageError("canary API socket path is invalid")
    try:
        metadata = socket_path.lstat()
        parent_metadata = socket_path.parent.lstat()
    except OSError as error:
        raise ActivationPackageError("canary API socket is unavailable") from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != expected_owner_uid
        or metadata.st_gid != expected_owner_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or socket_path.parent.is_symlink()
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != expected_owner_uid
        or parent_metadata.st_gid != expected_owner_gid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        raise ActivationPackageError("canary API socket identity is invalid")
    return metadata


def _validate_canary_authorization(
    credential_root: Path,
    *,
    expected_owner_uid: int,
    admin_secret: str,
    roadex_secret: str,
) -> None:
    admin_verifier = load_approval_verifier(
        credential_root / "admin-approval-verifier.json",
        expected_owner_uid=expected_owner_uid,
    )
    roadex_verifier = load_approval_verifier(
        credential_root / "roadex-fixture-approval-verifier.json",
        expected_owner_uid=expected_owner_uid,
    )
    if (
        admin_verifier.scope != "admin-plan-approval"
        or roadex_verifier.scope != "roadex-fixture-approval"
    ):
        raise ActivationPackageError("canary approval verifier scopes are invalid")
    if not admin_verifier.verify(admin_secret) or roadex_verifier.verify(admin_secret):
        raise ActivationPackageError(
            "admin canary secret does not match exactly one approved scope"
        )
    if not roadex_verifier.verify(roadex_secret) or admin_verifier.verify(roadex_secret):
        raise ActivationPackageError(
            "Roadex canary secret does not match exactly one approved scope"
        )


def _prepare_canary_authorization_input(package: Path) -> bytes:
    descriptor = _open_canary_prompt_terminal()
    try:
        admin_secret = _read_canary_secret_from_terminal(
            descriptor,
            "Admin approval secret for canary: ",
        )
        roadex_secret = _read_canary_secret_from_terminal(
            descriptor,
            "Roadex fixture approval secret for negative control: ",
        )
    finally:
        os.close(descriptor)
    _validate_canary_authorization(
        package / "private" / "credentials",
        expected_owner_uid=package.lstat().st_uid,
        admin_secret=admin_secret,
        roadex_secret=roadex_secret,
    )
    payload = _canonical(
        {
            "schemaVersion": CANARY_AUTHORIZATION_INPUT_SCHEMA,
            "adminSecret": admin_secret,
            "roadexSecret": roadex_secret,
        }
    ) + b"\n"
    if len(payload) > MAX_CANARY_AUTHORIZATION_INPUT_BYTES:
        raise ActivationPackageError(
            "canary authorization input exceeds its maximum size"
        )
    return payload


def _open_canary_prompt_terminal() -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOCTTY", 0)
    descriptor = -1
    accepted = False
    try:
        descriptor = os.open("/dev/tty", flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISCHR(metadata.st_mode) or not os.isatty(descriptor):
            raise ActivationPackageError(
                "canary authorization requires a secure terminal"
            )
        accepted = True
        return descriptor
    except ActivationPackageError:
        raise
    except OSError as error:
        raise ActivationPackageError(
            "canary authorization requires a secure terminal"
        ) from error
    finally:
        if descriptor >= 0 and not accepted:
            os.close(descriptor)


def _read_canary_secret_from_terminal(descriptor: int, prompt: str) -> str:
    if not os.isatty(descriptor):
        raise ActivationPackageError("canary authorization terminal was lost")
    try:
        original = termios.tcgetattr(descriptor)
    except termios.error as error:
        raise ActivationPackageError("canary authorization terminal was lost") from error
    hidden = original[:]
    hidden[3] &= ~termios.ECHO
    change_flags = termios.TCSAFLUSH
    if hasattr(termios, "TCSASOFT"):
        change_flags |= termios.TCSASOFT
    try:
        termios.tcsetattr(descriptor, change_flags, hidden)
    except termios.error as error:
        raise ActivationPackageError(
            "canary authorization could not disable terminal echo"
        ) from error

    secret_bytes = bytearray()
    read_error: BaseException | None = None
    try:
        prompt_bytes = prompt.encode("ascii", "strict")
        written = 0
        while written < len(prompt_bytes):
            count = os.write(descriptor, prompt_bytes[written:])
            if count <= 0:
                raise OSError(errno.EIO, "terminal write failed")
            written += count
        while True:
            value = os.read(descriptor, 1)
            if not value:
                raise OSError(errno.EIO, "terminal input ended")
            if value in {b"\n", b"\r"}:
                break
            secret_bytes.extend(value)
            if len(secret_bytes) > MAX_CANARY_AUTHORIZATION_INPUT_BYTES:
                raise ActivationPackageError(
                    "canary authorization input exceeds its maximum size"
                )
    except BaseException as error:
        read_error = error
    finally:
        restore_error: termios.error | None = None
        try:
            termios.tcsetattr(descriptor, change_flags, original)
        except termios.error as error:
            restore_error = error
        try:
            os.write(descriptor, b"\n")
        except OSError:
            if read_error is None and restore_error is None:
                read_error = OSError(errno.EIO, "terminal write failed")
    if restore_error is not None:
        secret_bytes[:] = b"\0" * len(secret_bytes)
        raise ActivationPackageError(
            "canary authorization could not restore terminal echo"
        ) from restore_error
    if read_error is not None:
        secret_bytes[:] = b"\0" * len(secret_bytes)
        if isinstance(read_error, ActivationPackageError):
            raise read_error
        raise ActivationPackageError("canary authorization terminal was lost") from read_error
    try:
        return secret_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ActivationPackageError("canary authorization input is invalid") from error
    finally:
        secret_bytes[:] = b"\0" * len(secret_bytes)


def _read_canary_authorization_input() -> tuple[str, str]:
    if sys.stdin.isatty():
        raise ActivationPackageError(
            "canary authorization must be supplied by the active staging runner"
        )
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(MAX_CANARY_AUTHORIZATION_INPUT_BYTES + 1)
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise ActivationPackageError("canary authorization input is invalid") from error
    if len(raw) > MAX_CANARY_AUTHORIZATION_INPUT_BYTES:
        raise ActivationPackageError(
            "canary authorization input exceeds its maximum size"
        )
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("canary authorization input is invalid") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schemaVersion", "adminSecret", "roadexSecret"}
        or document.get("schemaVersion") != CANARY_AUTHORIZATION_INPUT_SCHEMA
        or type(document.get("adminSecret")) is not str
        or type(document.get("roadexSecret")) is not str
        or raw != _canonical(document) + b"\n"
    ):
        raise ActivationPackageError("canary authorization input contract is invalid")
    return str(document["adminSecret"]), str(document["roadexSecret"])


def _require_active_canary_command(
    package: Path,
    *,
    expected_package_digest: str,
) -> tuple[dict[str, object], int]:
    contract, lock_descriptor = _require_active_phase_command(
        package,
        phase="staging-canary",
        command_name="run-approved-canary",
        expected_options={"--package-root": str(package)},
        expected_package_digest=expected_package_digest,
    )
    commands = _contract_commands(contract, "stagingAndCanaryCommands")
    expected_command = _expected_canary_acceptance_command(
        package,
        expected_package_digest=expected_package_digest,
        contract=contract,
    )
    _canary_acceptance_command_index(
        commands,
        expected_command=expected_command,
    )
    state = _load_activation_state()
    index = state.get("commandIndex") if isinstance(state, Mapping) else None
    if type(index) is not int or commands[index] != expected_command:
        raise ActivationPackageError(
            "active runner command is not the exact sealed canary command"
        )
    return contract, lock_descriptor


def run_canary_acceptance(
    package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
    admin_secret: str,
    roadex_secret: str,
    attestation_path: str | os.PathLike[str],
    base_url: str = "http://localhost",
    unix_socket_path: str | os.PathLike[str] = CANARY_API_SOCKET,
) -> dict[str, object]:
    """Run mandatory live canary controls and create a root-owned attestation."""

    from urllib.error import HTTPError

    from .client import OverseerApiClient

    _require_root_activation()
    package = Path(package_root).resolve()
    if (
        base_url != "http://localhost"
        or Path(unix_socket_path) != CANARY_API_SOCKET
        or Path(attestation_path) != _canary_attestation_path(expected_package_digest)
    ):
        raise ActivationPackageError("canary runtime arguments are not the sealed command arguments")
    _require_active_canary_command(
        package,
        expected_package_digest=expected_package_digest,
    )
    verified = verify_activation_package(package, expected_package_digest)
    verify_installed_staging(package, expected_package_digest=expected_package_digest)
    root_uid, root_gid = _activation_root_identity()
    canary_socket = Path(unix_socket_path)
    _validate_canary_socket(
        canary_socket,
        expected_owner_uid=APPROVED_OVERSEER_UID,
        expected_owner_gid=APPROVED_OVERSEER_GID,
    )
    credential_root = _installed_credential_root()
    _validate_canary_authorization(
        credential_root,
        expected_owner_uid=APPROVED_OVERSEER_UID,
        admin_secret=admin_secret,
        roadex_secret=roadex_secret,
    )
    token_raw, token_metadata = _stable_read(credential_root / "api-token")
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

    client_transport = {
        "base_url": base_url,
        "auth_token": api_token,
        "unix_socket_path": str(canary_socket),
        "expected_server_uid": APPROVED_OVERSEER_UID,
    }
    ordinary = OverseerApiClient(**client_transport)
    admin = OverseerApiClient(
        **client_transport,
        approval_token=admin_secret,
    )
    wrong_scope = OverseerApiClient(
        **client_transport,
        approval_token=roadex_secret,
    )
    ordinary_as_approval = OverseerApiClient(
        **client_transport,
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
        or replayed.get("status") != "completed"
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
    if (
        unlisted.get("status") != "blocked"
        or unlisted.get("mutation_performed") is not False
    ):
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
    package = Path(package_root).resolve()
    contract = _bound_package_json(
        package,
        expected_package_digest=digest,
        relative_path="public/activation-contract.json",
    )
    canary_store = _verify_staged_canary_store(
        package,
        contract,
        expected_package_digest=digest,
        pre_handoff=True,
    )
    return {
        "verified": True,
        "packageDigest": digest,
        "approvalRecord": str(_activation_approval_record_path()),
        "installed": installed,
        "canaryStore": canary_store,
    }


def _activation_state_path() -> Path:
    return Path("/var/lib/overseer-executor/activation-state.json")


def _load_maintenance_state() -> dict[str, object] | None:
    target = _maintenance_state_path()
    try:
        target.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ActivationPackageError("maintenance runner state could not be read") from error
    raw, metadata = _stable_read(target)
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ActivationPackageError("maintenance runner state metadata is invalid")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("maintenance runner state is invalid") from error
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion") != MAINTENANCE_RUNNER_STATE_SCHEMA
        or not isinstance(document.get("packageDigest"), str)
        or not isinstance(document.get("status"), str)
    ):
        raise ActivationPackageError("maintenance runner state schema is invalid")
    return document


def _write_maintenance_state(document: Mapping[str, object]) -> None:
    target = _maintenance_state_path()
    _ensure_directory(target.parent)
    root_uid, root_gid = _activation_root_identity()
    if os.geteuid() != 0 and (root_uid, root_gid) == (0, 0):
        root_uid, root_gid = os.geteuid(), os.getegid()
    temporary = target.with_name(
        f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
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
                raise OSError("maintenance state write made no progress")
            view = view[written:]
        os.fchown(descriptor, root_uid, root_gid)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
        parent_descriptor = os.open(
            target.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
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


def _activation_lock_path() -> Path:
    return _activation_state_path().with_name("activation.lock")


def _require_active_execution_lock_descriptor() -> int:
    descriptor = _ACTIVE_EXECUTION_LOCK_DESCRIPTOR
    if descriptor is None:
        raise ActivationPackageError("activation command requires the active execution lock")
    target = _activation_lock_path()
    try:
        inherited = os.fstat(descriptor)
        lexical = target.lstat()
    except OSError as error:
        raise ActivationPackageError("active execution lock is unavailable") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        target.is_symlink()
        or not stat.S_ISREG(inherited.st_mode)
        or not stat.S_ISREG(lexical.st_mode)
        or inherited.st_nlink != 1
        or lexical.st_nlink != 1
        or inherited.st_uid != root_uid
        or inherited.st_gid != root_gid
        or stat.S_IMODE(inherited.st_mode) != 0o600
        or (inherited.st_dev, inherited.st_ino) != (lexical.st_dev, lexical.st_ino)
    ):
        raise ActivationPackageError("active execution lock identity is invalid")
    return descriptor


def _require_inherited_activation_lock() -> int:
    """Prove this primitive inherited the runner's exact locked descriptor."""

    raw_descriptor = os.environ.get(ACTIVATION_LOCK_FD_ENV, "")
    if re.fullmatch(r"[0-9]+", raw_descriptor) is None:
        raise ActivationPackageError("active command requires the inherited activation execution lock")
    descriptor = int(raw_descriptor)
    if descriptor < 3:
        raise ActivationPackageError("inherited activation execution lock descriptor is invalid")
    target = _activation_lock_path()
    try:
        inherited = os.fstat(descriptor)
        lexical = target.lstat()
    except OSError as error:
        raise ActivationPackageError("inherited activation execution lock is unavailable") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        target.is_symlink()
        or not stat.S_ISREG(inherited.st_mode)
        or not stat.S_ISREG(lexical.st_mode)
        or inherited.st_nlink != 1
        or lexical.st_nlink != 1
        or inherited.st_uid != root_uid
        or inherited.st_gid != root_gid
        or stat.S_IMODE(inherited.st_mode) != 0o600
        or (inherited.st_dev, inherited.st_ino) != (lexical.st_dev, lexical.st_ino)
    ):
        raise ActivationPackageError("inherited activation execution lock identity is invalid")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise ActivationPackageError("activation execution lock was not inherited by this command") from error
    return descriptor


@contextmanager
def _activation_execution_lock():
    global _ACTIVE_EXECUTION_LOCK_DESCRIPTOR

    target = _activation_lock_path()
    _ensure_directory(target.parent)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o600)
    except OSError as error:
        raise ActivationPackageError("activation execution lock could not be opened") from error
    root_uid, root_gid = _activation_root_identity()
    registered = False
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
        locked = os.fstat(descriptor)
        try:
            lexical = target.lstat()
        except OSError as error:
            raise ActivationPackageError("activation execution lock path changed after locking") from error
        if (
            target.is_symlink()
            or not stat.S_ISREG(lexical.st_mode)
            or lexical.st_nlink != 1
            or lexical.st_uid != root_uid
            or lexical.st_gid != root_gid
            or stat.S_IMODE(lexical.st_mode) != 0o600
            or (locked.st_dev, locked.st_ino) != (lexical.st_dev, lexical.st_ino)
        ):
            raise ActivationPackageError("activation execution lock path changed after locking")
        if _ACTIVE_EXECUTION_LOCK_DESCRIPTOR is not None:
            raise ActivationPackageError("activation execution lock registration is already active")
        _ACTIVE_EXECUTION_LOCK_DESCRIPTOR = descriptor
        registered = True
        yield
    finally:
        if registered and _ACTIVE_EXECUTION_LOCK_DESCRIPTOR == descriptor:
            _ACTIVE_EXECUTION_LOCK_DESCRIPTOR = None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _validate_bounded_failure_classification(failure: object) -> str | None:
    if failure is None:
        return None
    if isinstance(failure, str) and (
        re.fullmatch(r"exit-[0-9]+", failure) is not None
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", failure) is not None
    ):
        return failure
    raise ActivationPackageError("activation runner failure classification is invalid")


def _classify_command_failure(returncode: int, start_error: str | None) -> str:
    if start_error is not None:
        classification = _validate_bounded_failure_classification(start_error)
        if classification is None or classification.startswith("exit-"):
            raise ActivationPackageError(
                "activation command start-error classification is invalid"
            )
        return classification
    exit_status = returncode if returncode >= 0 else 128 + abs(returncode)
    return f"exit-{exit_status}"


def _normalize_persisted_failure_classification(failure: object) -> object:
    if not isinstance(failure, str):
        return failure
    match = re.fullmatch(r"(?:cutover-)?exit-(-?[0-9]+)", failure)
    if match is None:
        return failure
    return _classify_command_failure(int(match.group(1)), None)


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
    if (
        not isinstance(document, dict)
        or document.get("schemaVersion")
        not in {ACTIVATION_RUNNER_STATE_SCHEMA, LEGACY_ACTIVATION_RUNNER_STATE_SCHEMA}
    ):
        raise ActivationPackageError("activation runner state schema is invalid")
    persisted_failure = document.get("failure")
    normalized_failure = _normalize_persisted_failure_classification(persisted_failure)
    validated_failure = _validate_bounded_failure_classification(normalized_failure)
    if normalized_failure != persisted_failure:
        document["failure"] = validated_failure
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


def _phase_runner_state_digest(state: Mapping[str, object] | None) -> str | None:
    return None if state is None else _sha256(_canonical(dict(state)))


def _validate_phase_prerequisite(
    phase: str,
    state: Mapping[str, object] | None,
    *,
    package_digest: str,
) -> None:
    if phase == "staging-canary":
        if state is not None:
            raise ActivationPackageError("staging-canary phase requires an unstarted runner state")
        return
    if phase != "cutover":
        raise ActivationPackageError("unsupported activation phase")
    if (
        state is None
        or state.get("schemaVersion") != ACTIVATION_RUNNER_STATE_SCHEMA
        or state.get("packageDigest") != package_digest
        or state.get("phase") != "staging-canary"
        or state.get("status") != "canary_passed_awaiting_cutover_approval"
    ):
        raise ActivationPackageError("cutover phase requires a successful canary runner state")


def _read_activation_phase_approval(
    package_root: str | os.PathLike[str],
    *,
    phase: str,
) -> dict[str, object]:
    if phase not in ACTIVATION_PHASES:
        raise ActivationPackageError("unsupported activation phase")
    package = Path(package_root).resolve()
    package_approval = _load_activation_approval(package)
    package_digest = str(package_approval["packageDigest"])
    target = _activation_phase_approval_record_path(phase)
    try:
        raw, metadata = _stable_read(target)
        document = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError(f"{phase} phase approval is unavailable or invalid") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(document, dict)
        or document.get("schemaVersion") != ACTIVATION_PHASE_APPROVAL_SCHEMA
        or document.get("approved") is not True
        or document.get("packageRoot") != str(package)
        or document.get("packageDigest") != package_digest
        or document.get("phase") != phase
        or document.get("executionScope") != f"{phase}-for-this-package-only"
    ):
        raise ActivationPackageError(f"{phase} phase approval metadata is invalid")
    state_digest = document.get("runnerStateDigest")
    state_status = document.get("runnerStateStatus")
    if phase == "staging-canary":
        if state_digest is not None or state_status != "not-started":
            raise ActivationPackageError("staging-canary phase approval prerequisite is invalid")
    elif (
        not isinstance(state_digest, str)
        or len(state_digest) != 64
        or set(state_digest) - _HEX
        or state_status != "canary_passed_awaiting_cutover_approval"
    ):
        raise ActivationPackageError("cutover phase approval prerequisite is invalid")
    return document


def _load_activation_phase_approval(
    package_root: str | os.PathLike[str],
    *,
    phase: str,
    expected_runner_state: Mapping[str, object] | None,
) -> dict[str, object]:
    package = Path(package_root).resolve()
    package_approval = _load_activation_approval(package)
    package_digest = str(package_approval["packageDigest"])
    observed_state = _load_activation_state()
    if observed_state != expected_runner_state:
        raise ActivationPackageError("activation phase approval runner state changed")
    _validate_phase_prerequisite(
        phase,
        observed_state,
        package_digest=package_digest,
    )
    document = _read_activation_phase_approval(package, phase=phase)
    if (
        document.get("runnerStateDigest") != _phase_runner_state_digest(observed_state)
        or document.get("runnerStateStatus")
        != ("not-started" if observed_state is None else str(observed_state.get("status")))
    ):
        raise ActivationPackageError(f"{phase} phase approval runner state is invalid")
    return document


def _sealed_command_options(command: list[str], *, command_name: str) -> dict[str, str]:
    if command.count(command_name) != 1:
        raise ActivationPackageError("active runner command name is not uniquely sealed")
    tail = command[command.index(command_name) + 1 :]
    if len(tail) % 2:
        raise ActivationPackageError("active runner command arguments are malformed")
    options: dict[str, str] = {}
    for index in range(0, len(tail), 2):
        name, value = tail[index : index + 2]
        if not name.startswith("--") or "=" in name or name in options or not value:
            raise ActivationPackageError("active runner command arguments are malformed")
        options[name] = value
    return options


def _require_active_phase_command(
    package_root: str | os.PathLike[str],
    *,
    phase: str,
    command_name: str,
    expected_options: Mapping[str, str],
    expected_package_digest: str | None = None,
) -> tuple[dict[str, object], int]:
    lock_descriptor = _require_inherited_activation_lock()
    package = Path(package_root).resolve()
    package_approval = _load_activation_approval(package)
    package_digest = str(package_approval["packageDigest"])
    if expected_package_digest is not None and package_digest != expected_package_digest:
        raise ActivationPackageError("active runner package digest does not match the command")
    contract = _sealed_package_json(
        package,
        expected_package_digest=package_digest,
        relative_path="public/activation-contract.json",
    )
    state = _load_activation_state()
    if (
        state is None
        or state.get("schemaVersion") != ACTIVATION_RUNNER_STATE_SCHEMA
        or state.get("packageDigest") != package_digest
        or state.get("phase") != phase
        or state.get("status") != "command_running"
    ):
        raise ActivationPackageError(f"{command_name} requires the active {phase} runner")
    _read_activation_phase_approval(package, phase=phase)
    field = "stagingAndCanaryCommands" if phase == "staging-canary" else "cutoverCommands"
    commands = _contract_commands(contract, field)
    index = state.get("commandIndex")
    if type(index) is not int or not 0 <= index < len(commands):
        raise ActivationPackageError("active runner state is not bound to a sealed command")
    command = commands[index]
    if state.get("commandDigest") != _sha256(_canonical(command)):
        raise ActivationPackageError("active runner state is not bound to the sealed command")
    if _sealed_command_options(command, command_name=command_name) != dict(expected_options):
        raise ActivationPackageError("active runner call does not match the sealed command arguments")
    return contract, lock_descriptor


def _require_maintenance_active_sealed_command(
    package_root: str | os.PathLike[str],
    *,
    command_name: str,
    expected_options: Mapping[str, str],
    expected_package_digest: str | None = None,
) -> tuple[dict[str, object], int]:
    """Require one exact command in the separately approved maintenance run."""

    lock_descriptor = _require_inherited_activation_lock()
    package = Path(package_root).resolve()
    approval = _load_maintenance_approval(package)
    package_digest = str(approval["packageDigest"])
    if expected_package_digest is not None and package_digest != expected_package_digest:
        raise ActivationPackageError("active maintenance package digest does not match the command")
    contract = _sealed_maintenance_contract(package, package_digest=package_digest)
    plan_digest = maintenance_plan_digest(contract)
    if approval.get("planDigest") != plan_digest or approval.get("allowReboot") is not False:
        raise ActivationPackageError("active maintenance approval plan binding is invalid")
    expected_stages = {
        "verify-maintenance-preflight": ("preflight",),
        "stop-maintenance-writers": ("stopWriters",),
        "verify-maintenance-quiescence": ("proveQuiescence", "switchServices"),
        "preserve-maintenance-state": ("preserveState",),
        "verify-maintenance-installed-release": ("installRelease",),
        "verify-maintenance-preservation": ("switchServices",),
        "ensure-dedicated-principal": ("switchServices",),
        "prepare-maintenance-store-copy": ("migrateOfflineStores",),
        "prepare-maintenance-stores": ("migrateOfflineStores",),
        "verify-maintenance-acceptance": ("acceptance",),
    }.get(command_name)
    if expected_stages is None:
        raise ActivationPackageError("maintenance command is not allowlisted")
    state = _load_maintenance_state()
    current_stage = None if state is None else state.get("stage")
    if (
        state is None
        or state.get("schemaVersion") != MAINTENANCE_RUNNER_STATE_SCHEMA
        or state.get("packageDigest") != package_digest
        or state.get("planDigest") != plan_digest
        or current_stage not in expected_stages
        or state.get("status")
        not in {"before_command", "command_running", "writer_stop_in_progress"}
        or state.get("writersStopped")
        is not (current_stage != "preflight")
    ):
        raise ActivationPackageError(
            f"{command_name} requires the active sealed maintenance command"
        )
    stages = contract.get("stages")
    if not isinstance(stages, list):
        raise ActivationPackageError("maintenance contract stages are invalid")
    stage = next(
        (
            candidate
            for candidate in stages
            if isinstance(candidate, Mapping)
            and candidate.get("name") == current_stage
        ),
        None,
    )
    if not isinstance(stage, Mapping):
        raise ActivationPackageError("maintenance command stage is missing")
    commands = _contract_commands(stage, "commands")
    index = state.get("commandIndex")
    if type(index) is not int or not 0 <= index < len(commands):
        raise ActivationPackageError("maintenance state is not bound to a sealed command")
    command = commands[index]
    if state.get("commandDigest") != _sha256(_canonical(command)):
        raise ActivationPackageError("maintenance state is not bound to the sealed command")
    if _sealed_command_options(command, command_name=command_name) != dict(expected_options):
        raise ActivationPackageError(
            "maintenance call does not match the sealed command arguments"
        )
    return contract, lock_descriptor


def _require_active_rollback_command(
    package_root: str | os.PathLike[str],
    *,
    command_name: str,
    expected_options: Mapping[str, str],
) -> None:
    _require_inherited_activation_lock()
    package = Path(package_root).resolve()
    package_approval = _load_activation_approval_for_rollback(package)
    package_digest = str(package_approval["packageDigest"])
    sealed_contract = _sealed_package_json(
        package,
        expected_package_digest=package_digest,
        relative_path="public/activation-contract.json",
    )
    schema = sealed_contract.get("schemaVersion")
    contract = _normalize_rollback_contract(sealed_contract)
    state = _load_activation_state()
    if (
        state is None
        or state.get("schemaVersion")
        not in {ACTIVATION_RUNNER_STATE_SCHEMA, LEGACY_ACTIVATION_RUNNER_STATE_SCHEMA}
        or state.get("packageDigest") != package_digest
        or state.get("phase") != "rollback"
        or state.get("status") != "rollback_command_running"
    ):
        raise ActivationPackageError(
            f"{command_name} requires the active sealed rollback command"
        )
    commands = _contract_commands(contract, "rollbackCommands")
    index = state.get("commandIndex")
    if type(index) is not int or not 0 <= index < len(commands):
        raise ActivationPackageError("active rollback state is not bound to a sealed command")
    command = commands[index]
    if state.get("commandDigest") != _sha256(_canonical(command)):
        raise ActivationPackageError("active rollback state is not bound to the sealed command")
    expected = dict(expected_options)
    if schema == ACTIVATION_CONTRACT_SCHEMA:
        expected["--package-root"] = str(package)
    if _sealed_command_options(command, command_name=command_name) != expected:
        raise ActivationPackageError("active rollback call does not match the sealed command arguments")


def _record_activation_phase_approval_locked(
    package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
    phase: str,
) -> dict[str, object]:
    _require_root_activation()
    if phase not in ACTIVATION_PHASES:
        raise ActivationPackageError("unsupported activation phase")
    package = Path(package_root).resolve()
    package_approval = _load_activation_approval(package)
    package_digest = str(package_approval["packageDigest"])
    if package_digest != expected_package_digest:
        raise ActivationPackageError("activation phase approval package digest does not match")
    state = _load_activation_state()
    _validate_phase_prerequisite(phase, state, package_digest=package_digest)
    target = _activation_phase_approval_record_path(phase)
    if target.exists() or target.is_symlink():
        raise ActivationPackageError(f"{phase} phase approval record already exists")
    document = {
        "schemaVersion": ACTIVATION_PHASE_APPROVAL_SCHEMA,
        "approved": True,
        "packageRoot": str(package),
        "packageDigest": package_digest,
        "phase": phase,
        "executionScope": f"{phase}-for-this-package-only",
        "runnerStateDigest": _phase_runner_state_digest(state),
        "runnerStateStatus": "not-started" if state is None else str(state.get("status")),
    }
    _write_new(target, _canonical(document) + b"\n", 0o600)
    return document


def record_activation_phase_approval(
    package_root: str | os.PathLike[str],
    *,
    expected_package_digest: str,
    phase: str,
) -> dict[str, object]:
    """Record one root-owned approval for one exact activation phase and state."""

    if phase not in ACTIVATION_PHASES:
        _require_root_activation()
        raise ActivationPackageError("unsupported activation phase")
    with _activation_execution_lock():
        return _record_activation_phase_approval_locked(
            package_root,
            expected_package_digest=expected_package_digest,
            phase=phase,
        )


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


def _run_contract_command_with_lock(
    command: list[str],
    *,
    lock_descriptor: int,
    stdin_payload: bytes | None = None,
    timeout_seconds: int | None = None,
) -> int:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        ACTIVATION_LOCK_FD_ENV: str(lock_descriptor),
    }
    try:
        if stdin_payload is None:
            result = subprocess.run(
                command,
                stdin=None,
                stdout=None,
                stderr=None,
                check=False,
                env=environment,
                pass_fds=(lock_descriptor,),
                timeout=timeout_seconds,
            )
        else:
            result = subprocess.run(
                command,
                input=stdin_payload,
                stdout=None,
                stderr=None,
                check=False,
                env=environment,
                pass_fds=(lock_descriptor,),
                timeout=timeout_seconds,
            )
    except subprocess.TimeoutExpired as error:
        raise ActivationPackageError(
            f"activation command exceeded its sealed timeout: {command[0]}"
        ) from error
    except OSError as error:
        raise ActivationPackageError(f"activation command could not start: {command[0]}") from error
    return int(result.returncode)


def _execute_contract_command(
    command: list[str],
    *,
    stdin_payload: bytes | None = None,
    timeout_seconds: int | None = None,
) -> int:
    return _run_contract_command_with_lock(
        command,
        lock_descriptor=_require_active_execution_lock_descriptor(),
        stdin_payload=stdin_payload,
        timeout_seconds=timeout_seconds,
    )


def _execute_inherited_contract_command(
    command: list[str],
    *,
    lock_descriptor: int,
    stdin_payload: bytes | None = None,
) -> int:
    inherited = _require_inherited_activation_lock()
    if inherited != lock_descriptor:
        raise ActivationPackageError("inherited activation lock descriptor changed")
    return _run_contract_command_with_lock(
        command,
        lock_descriptor=lock_descriptor,
        stdin_payload=stdin_payload,
    )


def _command_outcome(
    command: list[str],
    *,
    stdin_payload: bytes | None = None,
) -> tuple[int, str | None]:
    try:
        if stdin_payload is None:
            return _execute_contract_command(command), None
        return _execute_contract_command(command, stdin_payload=stdin_payload), None
    except BaseException as error:
        return 127, type(error).__name__


def _validated_command_outcome(
    contract: Mapping[str, object],
    command: list[str],
    *,
    stdin_payload: bytes | None = None,
) -> tuple[int, str | None]:
    try:
        _validate_contract_principal_binding(contract)
    except BaseException as error:
        return 126, type(error).__name__
    return _command_outcome(command, stdin_payload=stdin_payload)


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
    if len(command) < 3 or command[:2] != ["/usr/bin/systemctl", "stop"]:
        return False
    for unit in command[2:]:
        returncode, start_error = _command_outcome(
            ["/usr/bin/systemctl", "is-active", "--quiet", unit]
        )
        if start_error is not None or returncode != 3:
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
        "schemaVersion": ACTIVATION_RUNNER_STATE_SCHEMA,
        "packageDigest": package_digest,
        "status": status,
        "phase": phase,
        "commandIndex": command_index,
        "commandDigest": _sha256(_canonical(command)) if command is not None else None,
        "failure": _validate_bounded_failure_classification(failure),
        "updatedAtNs": time.time_ns(),
        "secretValuesRecorded": False,
    }


def _emit_activation_progress(
    *,
    package_digest: str,
    phase: str,
    status: str,
    stage: str,
    command_index: int | None = None,
    failure: str | None = None,
) -> None:
    try:
        emit_activation_progress(
            package_digest=package_digest,
            phase=phase,
            status=status,
            stage=stage,
            command_index=command_index,
            failure=failure,
        )
    except BaseException as error:
        raise _ActivationProgressEmissionError(
            "activation progress could not be emitted"
        ) from error


def _execute_cleanup_sequence(
    contract: Mapping[str, object],
    *,
    package_digest: str,
    originating_failure: str | None = None,
) -> None:
    for index, command in enumerate(_cleanup_commands(contract)):
        _write_activation_state(
            _runner_state(
                package_digest=package_digest,
                status="cleanup_command_running",
                phase="staging_cleanup",
                command_index=index,
                command=command,
                failure=originating_failure,
            )
        )
        if index == 0:
            _emit_activation_progress(
                package_digest=package_digest,
                phase="staging-canary",
                status="cleanup-started",
                stage="cleanup",
                command_index=index,
                failure=originating_failure,
            )
        _emit_activation_progress(
            package_digest=package_digest,
            phase="staging-canary",
            status="stage-started",
            stage="cleanup",
            command_index=index,
            failure=originating_failure,
        )
        returncode, start_error = _validated_command_outcome(contract, command)
        if returncode != 0 and not (
            start_error is None and _cleanup_command_satisfied(command)
        ):
            cleanup_failure = _classify_command_failure(returncode, start_error)
            try:
                _write_activation_state(
                    _runner_state(
                        package_digest=package_digest,
                        status="cleanup_failed",
                        phase="staging_cleanup",
                        command_index=index,
                        command=command,
                        failure=cleanup_failure,
                    )
                )
            except BaseException as checkpoint_error:
                raise _CleanupCommandFailure(cleanup_failure) from checkpoint_error
            _emit_activation_progress(
                package_digest=package_digest,
                phase="staging-canary",
                status="cleanup-failed",
                stage="cleanup",
                command_index=index,
                failure=cleanup_failure,
            )
            raise _CleanupCommandFailure(cleanup_failure)
        _write_activation_state(
            _runner_state(
                package_digest=package_digest,
                status="cleanup_command_complete",
                phase="staging_cleanup",
                command_index=index,
                command=command,
                failure=originating_failure,
            )
        )
        _emit_activation_progress(
            package_digest=package_digest,
            phase="staging-canary",
            status="stage-complete",
            stage="cleanup",
            command_index=index,
            failure=originating_failure,
        )
    _emit_activation_progress(
        package_digest=package_digest,
        phase="staging-canary",
        status="cleanup-complete",
        stage="cleanup",
        failure=originating_failure,
    )


def _execute_emergency_cleanup_sequence(contract: Mapping[str, object]) -> None:
    """Stop every sealed staging unit when runner-state persistence is unavailable."""

    for command in _cleanup_commands(contract):
        # Containment must not be suppressed by NSS/account drift. These are
        # already sealed stop-only commands and do not start a principal.
        returncode, start_error = _command_outcome(command)
        if returncode != 0 and not (
            start_error is None and _cleanup_command_satisfied(command)
        ):
            detail = _classify_command_failure(returncode, start_error)
            raise ActivationPackageError(
                f"emergency staging cleanup command failed: {detail}"
            )


def _write_recovery_state_best_effort(document: Mapping[str, object]) -> bool:
    try:
        _write_activation_state(document)
    except BaseException:
        return False
    return True


def _execute_resilient_cleanup(
    contract: Mapping[str, object],
    *,
    package_digest: str,
    originating_failure: str | None = None,
    require_canary_evidence: bool | None = None,
) -> bool:
    try:
        _execute_cleanup_sequence(
            contract,
            package_digest=package_digest,
            originating_failure=originating_failure,
        )
    except _ActivationProgressEmissionError as progress_error:
        try:
            _execute_emergency_cleanup_sequence(contract)
        except BaseException as containment_error:
            raise progress_error from containment_error
        raise
    except _CleanupCommandFailure as error:
        _execute_emergency_cleanup_sequence(contract)
        originating_failure = error.failure
    except BaseException:
        _execute_emergency_cleanup_sequence(contract)
    if require_canary_evidence is None:
        require_canary_evidence = (
            contract.get("schemaVersion") == ACTIVATION_CONTRACT_SCHEMA
        )
    try:
        _seal_canary_state_from_contract(
            contract,
            required=require_canary_evidence,
        )
    except BaseException:
        recovery_durable = _write_recovery_state_best_effort(
            _runner_state(
                package_digest=package_digest,
                status="cleanup_evidence_seal_failed",
                phase="staging_cleanup",
                failure=originating_failure,
            )
        )
        if recovery_durable:
            _emit_activation_progress(
                package_digest=package_digest,
                phase="staging-canary",
                status="evidence-seal-failed",
                stage="evidence-seal",
                failure=originating_failure,
            )
        raise
    recovery_durable = _write_recovery_state_best_effort(
        _runner_state(
            package_digest=package_digest,
            status="aborted_before_cutover",
            phase="staging_cleanup",
            failure=originating_failure,
        )
    )
    if recovery_durable:
        _emit_activation_progress(
            package_digest=package_digest,
            phase="staging-canary",
            status="evidence-seal-complete",
            stage="evidence-seal",
            failure=originating_failure,
        )
    return recovery_durable


def _raise_progress_error_after_staging_containment(
    contract: Mapping[str, object],
    *,
    package_digest: str,
    progress_error: _ActivationProgressEmissionError,
) -> None:
    try:
        _execute_resilient_cleanup(
            contract,
            package_digest=package_digest,
            originating_failure=type(progress_error).__name__,
        )
    except BaseException as containment_error:
        raise progress_error from containment_error
    raise progress_error


def _rollback_transient_spec(command: list[str]) -> dict[str, object] | None:
    if not command or command[0] != "/usr/bin/systemd-run":
        return None
    uid_values = [value.removeprefix("--uid=") for value in command if value.startswith("--uid=")]
    gid_values = [value.removeprefix("--gid=") for value in command if value.startswith("--gid=")]
    if (
        command.count("--") != 1
        or command.count("--collect") != 1
        or len(uid_values) != 1
        or len(gid_values) != 1
        or re.fullmatch(r"[1-9][0-9]*", uid_values[0]) is None
        or re.fullmatch(r"[1-9][0-9]*", gid_values[0]) is None
        or command.count("--service-type=simple") != 1
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
    expected_preamble = [
        "/usr/bin/systemd-run",
        "--collect",
        f"--uid={uid_values[0]}",
        f"--gid={gid_values[0]}",
    ]
    allowed_option = lambda value: (
        value.startswith("--unit=")
        or value == "--service-type=simple"
        or value.startswith("--property=")
        or value.startswith("--working-directory=")
        or value.startswith("--setenv=")
    )
    if command[:4] != expected_preamble or any(
        not allowed_option(value) for value in command[4:separator]
    ):
        raise ActivationPackageError("sealed rollback transient option grammar is invalid")
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
        "user": uid_values[0],
        "group": gid_values[0],
        "workingDirectory": working_values[0],
        "description": description_values[0],
        "environment": environment,
        "properties": properties,
        "argv": argv,
    }


_ROLLBACK_TRANSIENT_ACTION_PROPERTIES = (
    "ExecCondition",
    "ExecStartPre",
    "ExecStartPost",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "EnvironmentFiles",
    "PassEnvironment",
    "UnsetEnvironment",
    "RootDirectory",
    "RootImage",
    "TemporaryFileSystem",
    "MountImages",
    "ExtensionImages",
    "BindPaths",
    "BindReadOnlyPaths",
    "SetCredential",
    "SetCredentialEncrypted",
    "LoadCredentialEncrypted",
    "ImportCredential",
)


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
        "DropInPaths",
        *_ROLLBACK_TRANSIENT_ACTION_PROPERTIES,
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


def _validate_rollback_transient_fragment_contents(
    raw: bytes,
    spec: Mapping[str, object],
) -> None:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise ActivationPackageError("rollback transient unit file encoding drifted") from error
    credentials: list[str] = []
    executable_entries: list[list[str]] = []
    forbidden = {
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
        "EnvironmentFile",
        "PassEnvironment",
        "UnsetEnvironment",
        "RootDirectory",
        "RootImage",
        "TemporaryFileSystem",
        "MountImages",
        "ExtensionImages",
        "BindPaths",
        "BindReadOnlyPaths",
        "SetCredential",
        "SetCredentialEncrypted",
    }
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or stripped.startswith("["):
            continue
        name, separator, value = stripped.partition("=")
        if not separator or not name:
            raise ActivationPackageError("rollback transient unit file syntax drifted")
        if name in forbidden and value:
            raise ActivationPackageError("rollback transient additional actions drifted")
        if name in {"LoadCredentialEncrypted", "ImportCredential"} and value:
            raise ActivationPackageError("rollback transient credential source drifted")
        if name == "LoadCredential":
            credentials.append(value)
        if name == "ExecStart" and value:
            executable_entries.append(_show_words(value, label="unit-file command"))
    properties = spec.get("properties")
    if not isinstance(properties, Mapping):
        raise ActivationPackageError("rollback transient sealed properties are invalid")
    expected_credentials = properties.get("LoadCredential", [])
    if (
        not isinstance(expected_credentials, list)
        or not all(isinstance(value, str) and value for value in expected_credentials)
        or sorted(credentials) != sorted(expected_credentials)
    ):
        raise ActivationPackageError("rollback transient credential source drifted")
    argv = spec.get("argv")
    if (
        not isinstance(argv, list)
        or not all(isinstance(value, str) and value for value in argv)
        or executable_entries != [argv]
    ):
        raise ActivationPackageError("rollback transient executable drifted")


def _verify_rollback_transient_fragment(
    fragment: Path,
    *,
    unit: str,
    spec: Mapping[str, object],
) -> None:
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
    raw, opened = _stable_read(fragment)
    if (
        opened.st_uid != root_uid
        or opened.st_gid != root_gid
        or stat.S_IMODE(opened.st_mode) & 0o022
    ):
        raise ActivationPackageError("rollback transient unit file identity drifted")
    _validate_rollback_transient_fragment_contents(raw, spec)


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
    _verify_rollback_transient_fragment(fragment, unit=unit, spec=spec)
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
        or observed.get("User") != spec["user"]
        or observed.get("Group") != spec["group"]
        or observed.get("WorkingDirectory") != spec["workingDirectory"]
        or observed.get("Type") != "simple"
        or observed.get("CollectMode") != "inactive-or-failed"
        or observed.get("DropInPaths")
        or any(observed.get(name) for name in _ROLLBACK_TRANSIENT_ACTION_PROPERTIES)
        or observed.get("SubState") not in allowed_substates.get(active_state, set())
        or (invocation_id and re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None)
        or (active_state != "inactive" and not invocation_id)
    ):
        if any(observed.get(name) for name in _ROLLBACK_TRANSIENT_ACTION_PROPERTIES):
            raise ActivationPackageError("rollback transient additional actions drifted")
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
        prior_state.get("schemaVersion")
        not in {ACTIVATION_RUNNER_STATE_SCHEMA, LEGACY_ACTIVATION_RUNNER_STATE_SCHEMA}
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
    god_uid, god_gid = _validate_contract_principal_schema(contract)
    if spec.get("user") != str(god_uid) or spec.get("group") != str(god_gid):
        raise ActivationPackageError(
            "rollback transient principal does not match the sealed activation contract"
        )

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
        detail = _classify_command_failure(returncode, start_error)
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
    recover_from_cutover = prior_state is not None and prior_state.get("phase") == "cutover"
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
                    resume=(
                        recover_from_cutover
                        or (recovery_boundary is not None and index <= recovery_boundary)
                    ),
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
                        failure=_classify_command_failure(returncode, start_error),
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


def _sealed_restore_legacy_arguments(command: list[str]) -> dict[str, object] | None:
    command_name = "restore-legacy-store-access"
    if command_name not in command:
        return None
    options = _sealed_command_options(command, command_name=command_name)
    options.pop("--package-root", None)
    expected = {
        "--source-store",
        "--expected-source-uid",
        "--expected-source-gid",
        "--expected-source-device",
        "--expected-source-inode",
        "--expected-parent-device",
        "--expected-parent-inode",
        "--expected-parent-mode",
    }
    if set(options) != expected:
        raise ActivationPackageError("sealed rollback store-restore command is invalid")
    try:
        return {
            "source_store": options["--source-store"],
            "expected_source_uid": int(options["--expected-source-uid"]),
            "expected_source_gid": int(options["--expected-source-gid"]),
            "expected_source_device": int(options["--expected-source-device"]),
            "expected_source_inode": int(options["--expected-source-inode"]),
            "expected_parent_device": int(options["--expected-parent-device"]),
            "expected_parent_inode": int(options["--expected-parent-inode"]),
            "expected_parent_mode": int(options["--expected-parent-mode"]),
        }
    except ValueError as error:
        raise ActivationPackageError("sealed rollback store-restore values are invalid") from error


def _execute_emergency_rollback_sequence(contract: Mapping[str, object]) -> None:
    """Run sealed rollback without checkpoints when state publication has failed."""

    for command in _contract_commands(contract, "rollbackCommands"):
        restore_arguments = _sealed_restore_legacy_arguments(command)
        if restore_arguments is not None:
            _restore_legacy_store_access_unchecked(**restore_arguments)
            continue
        if _rollback_transient_spec(command) is not None:
            # Stopping the successor and restoring numeric ownership are safe
            # containment under principal drift. Starting a named-principal
            # legacy transient is not, so revalidate immediately before it.
            _validate_contract_principal_binding(contract)
            _execute_rollback_transient(contract, command, resume=True)
            continue
        returncode, start_error = _command_outcome(command)
        if returncode != 0:
            detail = _classify_command_failure(returncode, start_error)
            raise ActivationPackageError(
                f"emergency sealed rollback command failed: {detail}"
            )


def _execute_resilient_rollback(
    contract: Mapping[str, object],
    *,
    package_digest: str,
    prior_state: Mapping[str, object] | None,
    originating_failure: str | None,
) -> bool:
    try:
        _execute_rollback_sequence(
            contract,
            package_digest=package_digest,
            prior_state=prior_state,
            originating_failure=originating_failure,
        )
    except BaseException:
        _execute_emergency_rollback_sequence(contract)
        return _write_recovery_state_best_effort(
            _runner_state(
                package_digest=package_digest,
                status="rolled_back",
                phase="rollback",
                failure=originating_failure,
            )
        )
    return True


def _validate_contract_principal_bootstrap(
    package: Path,
    contract: Mapping[str, object],
) -> None:
    release_root = contract.get("releaseRoot")
    if not isinstance(release_root, str):
        raise ActivationPackageError("activation principal bootstrap release root is invalid")
    release_path = PurePosixPath(release_root)
    if (
        release_path.parent != PurePosixPath("/opt/overseer/releases")
        or release_path.name in {"", ".", ".."}
    ):
        raise ActivationPackageError("activation principal bootstrap release root is invalid")
    package_release_root = package / "public" / "release" / release_path.name
    expected = [
        "/usr/bin/env",
        f"LD_LIBRARY_PATH={package_release_root}/lib",
        f"PYTHONHOME={package_release_root}/runtime",
        f"PYTHONPATH={package_release_root}/app/src:{package_release_root}/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        str(package_release_root / "runtime/bin/python3.13"),
        "-B",
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
        "ensure-dedicated-principal",
        "--package-root",
        str(package),
    ]
    staging = _contract_commands(contract, "stagingAndCanaryCommands")
    all_commands = [
        *staging,
        *_contract_commands(contract, "cutoverCommands"),
        *_contract_commands(contract, "rollbackCommands"),
    ]

    def uses_forbidden_interpreter(command: list[str]) -> bool:
        for argument in command:
            if PurePosixPath(argument).name in _FORBIDDEN_COMMAND_INTERPRETERS:
                return True
        for env_index, executable in enumerate(command):
            if PurePosixPath(executable).name != "env":
                continue
            for argument in command[env_index + 1 :]:
                if argument.startswith("/") and "=" not in argument:
                    break
                option = argument.partition("=")[0]
                if (
                    len(option) > 2
                    and option.startswith("--")
                    and "--split-string".startswith(option)
                ) or (
                    option.startswith("-")
                    and not option.startswith("--")
                    and "S" in option[1:]
                ):
                    return True
        return False

    if (
        staging[0] != expected
        or sum(command.count("ensure-dedicated-principal") for command in all_commands) != 1
        or any(
            re.search(r"(?:^|[/\s])(?:groupadd|useradd)(?:$|\s)", argument) is not None
            for command in all_commands
            for argument in command
        )
        or any(uses_forbidden_interpreter(command) for command in all_commands)
    ):
        raise ActivationPackageError("activation principal bootstrap command is invalid")


def _approved_activation_contract(
    package_root: str | os.PathLike[str],
) -> tuple[Path, str, dict[str, object]]:
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
    _validate_contract_principal_bootstrap(package, contract)
    return package, digest, contract


def _normalize_rollback_contract(contract: Mapping[str, object]) -> dict[str, object]:
    """Validate a sealed current/legacy contract and normalize only its schema tag."""

    schema = contract.get("schemaVersion")
    if schema not in {ACTIVATION_CONTRACT_SCHEMA, LEGACY_ACTIVATION_CONTRACT_SCHEMA}:
        raise ActivationPackageError("sealed rollback contract schema is invalid")
    normalized = dict(contract)
    normalized["schemaVersion"] = ACTIVATION_CONTRACT_SCHEMA
    _validate_contract_principal_schema(normalized)
    return normalized


def _expected_canary_acceptance_command(
    package: Path,
    *,
    expected_package_digest: str,
    contract: Mapping[str, object],
) -> list[str]:
    release_root_raw = contract.get("releaseRoot")
    if not isinstance(release_root_raw, str):
        raise ActivationPackageError("sealed canary release root is invalid")
    release_root = PurePosixPath(release_root_raw)
    if (
        release_root.parent != RELEASES_ROOT
        or release_root.name in {"", ".", ".."}
    ):
        raise ActivationPackageError("sealed canary release root is invalid")
    release_manifest = _sealed_package_json(
        package,
        expected_package_digest=expected_package_digest,
        relative_path=f"public/release/{release_root.name}/release-manifest.json",
    )
    root_python = release_manifest.get("rootPython")
    if (
        release_manifest.get("schemaVersion") != RELEASE_SCHEMA
        or release_manifest.get("releaseRoot") != release_root_raw
        or release_manifest.get("manifestDigest")
        != contract.get("releaseManifestDigest")
        or not isinstance(root_python, Mapping)
        or not isinstance(root_python.get("releasePath"), str)
    ):
        raise ActivationPackageError("sealed canary release manifest is invalid")
    python = release_root / _safe_relative(str(root_python["releasePath"]))
    return [
        "/usr/bin/env",
        f"LD_LIBRARY_PATH={release_root}/lib",
        f"PYTHONHOME={release_root}/runtime",
        f"PYTHONPATH={release_root}/app/src:{release_root}/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        str(python),
        "-B",
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
        "run-approved-canary",
        "--package-root",
        str(package),
    ]


def _canary_acceptance_command_index(
    commands: list[list[str]],
    *,
    expected_command: list[str],
) -> int:
    named_indexes = [
        index
        for index, command in enumerate(commands)
        if "run-approved-canary" in command
    ]
    exact_indexes = [
        index for index, command in enumerate(commands) if command == expected_command
    ]
    if len(named_indexes) != 1 or exact_indexes != named_indexes:
        raise ActivationPackageError(
            "staging contract does not contain one exact sealed canary command"
        )
    return exact_indexes[0]


def _canary_authorization_boundary_index(
    commands: list[list[str]],
    *,
    canary_command_index: int,
    failure_cleanup_commands: list[list[str]],
) -> int:
    resources_start = [
        "/usr/bin/systemctl",
        "start",
        "overseer-codex-user-bridge.socket",
        "overseer-admin-executor.socket",
    ]
    service_start: list[str] = []
    if 0 <= canary_command_index < len(commands):
        canary_command = commands[canary_command_index]
        if canary_command.count("run-approved-canary") == 1:
            command_index = canary_command.index("run-approved-canary")
            service_start = [
                *canary_command[:command_index],
                "handoff-start-canary",
                *canary_command[command_index + 1 :],
            ]
    health_check = [
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
        str(CANARY_API_SOCKET),
        "http://localhost/health",
    ]
    stop = [
        "/usr/bin/systemctl",
        "stop",
        "overseer-approval-smoke.service",
        "overseer-api-canary.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    ]
    resource_indexes = [
        index for index, command in enumerate(commands) if command == resources_start
    ]
    service_indexes = [
        index for index, command in enumerate(commands) if command == service_start
    ]
    boundary = resource_indexes[0] if len(resource_indexes) == 1 else -1
    protected_unit_names = {
        "overseer-approval-smoke.service",
        "overseer-api-canary.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    }
    earlier_protected_commands = [
        command
        for command in commands[: max(boundary, 0)]
        if (
            any(argument in protected_unit_names for argument in command)
            or "handoff-start-canary" in command
            or (
                command
                and PurePosixPath(command[0]).name == "systemctl"
                and command != ["/usr/bin/systemctl", "daemon-reload"]
            )
        )
    ]
    expected_suffix = (
        [resources_start, service_start, health_check, commands[canary_command_index], stop]
        if 0 <= canary_command_index < len(commands)
        else []
    )
    if failure_cleanup_commands != [stop]:
        raise ActivationPackageError(
            "sealed staging contract has an invalid canary cleanup boundary"
        )
    if (
        len(resource_indexes) != 1
        or len(service_indexes) != 1
        or earlier_protected_commands
        or canary_command_index != boundary + 3
        or commands[boundary:] != expected_suffix
    ):
        raise ActivationPackageError(
            "sealed staging contract has an invalid canary startup boundary"
        )
    return boundary


def _execute_approved_staging_canary_locked(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Execute only the separately approved staging and live-canary phase."""

    package, digest, contract = _approved_activation_contract(package_root)
    existing = _load_activation_state()
    if existing is not None:
        if (
            existing.get("packageDigest") == digest
            and existing.get("status") == "canary_passed_awaiting_cutover_approval"
            and existing.get("phase") == "staging-canary"
        ):
            return {
                "status": "canary_passed_awaiting_cutover_approval",
                "packageDigest": digest,
                "replayed": True,
            }
        raise ActivationPackageError(
            "staging-canary runner state is not safely resumable; use the sealed rollback path"
        )
    _load_activation_phase_approval(
        package,
        phase="staging-canary",
        expected_runner_state=None,
    )
    staging = _contract_commands(contract, "stagingAndCanaryCommands")
    cleanup_commands = _cleanup_commands(contract)
    canary_command_index: int | None = None
    authorization_boundary_index: int | None = None
    if any("run-approved-canary" in command for command in staging):
        expected_canary_command = _expected_canary_acceptance_command(
            package,
            expected_package_digest=digest,
            contract=contract,
        )
        canary_command_index = _canary_acceptance_command_index(
            staging,
            expected_command=expected_canary_command,
        )
        authorization_boundary_index = _canary_authorization_boundary_index(
            staging,
            canary_command_index=canary_command_index,
            failure_cleanup_commands=cleanup_commands,
        )
    canary_authorization_input: bytes | None = None

    _write_activation_state(
        _runner_state(package_digest=digest, status="running", phase="staging-canary")
    )
    _emit_activation_progress(
        package_digest=digest,
        phase="staging-canary",
        status="phase-started",
        stage="unknown-sealed-command",
    )
    for index, command in enumerate(staging):
        if index == authorization_boundary_index:
            pre_prompt_state = _load_activation_state()
            try:
                _emit_activation_progress(
                    package_digest=digest,
                    phase="staging-canary",
                    status="waiting-for-human-authorization",
                    stage="human-authorization",
                    command_index=index,
                )
                canary_authorization_input = _prepare_canary_authorization_input(package)
                refreshed_package, refreshed_digest, refreshed_contract = (
                    _approved_activation_contract(package)
                )
                refreshed_staging = _contract_commands(
                    refreshed_contract,
                    "stagingAndCanaryCommands",
                )
                refreshed_expected_canary = _expected_canary_acceptance_command(
                    refreshed_package,
                    expected_package_digest=refreshed_digest,
                    contract=refreshed_contract,
                )
                refreshed_canary_index = _canary_acceptance_command_index(
                    refreshed_staging,
                    expected_command=refreshed_expected_canary,
                )
                refreshed_boundary_index = _canary_authorization_boundary_index(
                    refreshed_staging,
                    canary_command_index=refreshed_canary_index,
                    failure_cleanup_commands=_cleanup_commands(refreshed_contract),
                )
                _read_activation_phase_approval(
                    package,
                    phase="staging-canary",
                )
                _require_active_execution_lock_descriptor()
                if (
                    refreshed_package != package
                    or refreshed_digest != digest
                    or _canonical(refreshed_contract) != _canonical(contract)
                    or refreshed_staging != staging
                    or refreshed_canary_index != canary_command_index
                    or refreshed_boundary_index != authorization_boundary_index
                    or _load_activation_state() != pre_prompt_state
                ):
                    raise ActivationPackageError(
                        "staging authority changed during canary authorization"
                    )
                _emit_activation_progress(
                    package_digest=refreshed_digest,
                    phase="staging-canary",
                    status="human-authorization-complete",
                    stage="human-authorization",
                    command_index=index,
                )
            except _ActivationProgressEmissionError as progress_error:
                canary_authorization_input = None
                _raise_progress_error_after_staging_containment(
                    contract,
                    package_digest=digest,
                    progress_error=progress_error,
                )
            except BaseException as authorization_error:
                canary_authorization_input = None
                try:
                    cleanup_durable = _execute_resilient_cleanup(
                        contract,
                        package_digest=digest,
                        originating_failure=type(authorization_error).__name__,
                    )
                except _ActivationProgressEmissionError:
                    raise
                except BaseException as cleanup_error:
                    raise ActivationPackageError(
                        "canary authorization failed and sealed cleanup did not complete"
                    ) from cleanup_error
                if not cleanup_durable:
                    raise ActivationPackageError(
                        "canary authorization failed; cleanup completed but terminal recovery state is not durable"
                    ) from authorization_error
                raise ActivationPackageError(
                    "canary authorization failed before canary startup; immediate cleanup completed"
                ) from authorization_error
        command_state = _runner_state(
            package_digest=digest,
            status="command_running",
            phase="staging-canary",
            command_index=index,
            command=command,
        )
        try:
            _write_activation_state(command_state)
            _emit_activation_progress(
                package_digest=digest,
                phase="staging-canary",
                status="stage-started",
                stage=classify_phase_b_command(command),
                command_index=index,
            )
        except _ActivationProgressEmissionError as progress_error:
            _raise_progress_error_after_staging_containment(
                contract,
                package_digest=digest,
                progress_error=progress_error,
            )
        except BaseException as checkpoint_error:
            try:
                cleanup_durable = _execute_resilient_cleanup(
                    contract,
                    package_digest=digest,
                    originating_failure=type(checkpoint_error).__name__,
                )
            except _ActivationProgressEmissionError:
                raise
            except BaseException as cleanup_error:
                raise ActivationPackageError(
                    "staging command entry checkpoint failed and sealed cleanup did not complete"
                ) from cleanup_error
            if not cleanup_durable:
                raise ActivationPackageError(
                    "staging command entry checkpoint failed; cleanup completed but terminal recovery state is not durable"
                ) from checkpoint_error
            raise ActivationPackageError(
                "staging command entry checkpoint failed; immediate cleanup completed"
            ) from checkpoint_error
        command_input = (
            canary_authorization_input
            if index == canary_command_index
            else None
        )
        try:
            returncode, start_error = _validated_command_outcome(
                contract,
                command,
                stdin_payload=command_input,
            )
        finally:
            if index == canary_command_index:
                canary_authorization_input = None
        if returncode != 0:
            canary_authorization_input = None
            command_failure = _classify_command_failure(returncode, start_error)
            try:
                cleanup_durable = _execute_resilient_cleanup(
                    contract,
                    package_digest=digest,
                    originating_failure=command_failure,
                )
            except _ActivationProgressEmissionError:
                raise
            except BaseException as cleanup_error:
                raise ActivationPackageError(
                    "staged activation command failed and sealed cleanup did not complete"
                ) from cleanup_error
            if not cleanup_durable:
                raise ActivationPackageError(
                    "staged activation command failed; cleanup completed but terminal recovery state is not durable"
                )
            raise ActivationPackageError("staged activation command failed before cutover")
        try:
            _write_activation_state(
                _runner_state(
                    package_digest=digest,
                    status="command_complete",
                    phase="staging-canary",
                    command_index=index,
                    command=command,
                )
            )
            _emit_activation_progress(
                package_digest=digest,
                phase="staging-canary",
                status="stage-complete",
                stage=classify_phase_b_command(command),
                command_index=index,
            )
        except _ActivationProgressEmissionError as progress_error:
            _raise_progress_error_after_staging_containment(
                contract,
                package_digest=digest,
                progress_error=progress_error,
            )
        except BaseException as checkpoint_error:
            try:
                cleanup_durable = _execute_resilient_cleanup(
                    contract,
                    package_digest=digest,
                    originating_failure=type(checkpoint_error).__name__,
                )
            except _ActivationProgressEmissionError:
                raise
            except BaseException as cleanup_error:
                raise ActivationPackageError(
                    "checkpoint failed after staging command and immediate cleanup failed"
                ) from cleanup_error
            if not cleanup_durable:
                raise ActivationPackageError(
                    "checkpoint failed after staging command; cleanup completed but terminal recovery state is not durable"
                ) from checkpoint_error
            raise ActivationPackageError(
                "checkpoint failed after staging command; immediate cleanup completed"
            ) from checkpoint_error

    try:
        _emit_activation_progress(
            package_digest=digest,
            phase="staging-canary",
            status="evidence-seal-started",
            stage="evidence-seal",
        )
        _seal_canary_state_from_contract(contract, required=True)
        _emit_activation_progress(
            package_digest=digest,
            phase="staging-canary",
            status="evidence-seal-complete",
            stage="evidence-seal",
        )
        verify_approved_cutover(package)
    except _ActivationProgressEmissionError as progress_error:
        _raise_progress_error_after_staging_containment(
            contract,
            package_digest=digest,
            progress_error=progress_error,
        )
    except BaseException as error:
        try:
            cleanup_durable = _execute_resilient_cleanup(
                contract,
                package_digest=digest,
                originating_failure=type(error).__name__,
            )
        except _ActivationProgressEmissionError:
            raise
        except BaseException as cleanup_error:
            raise ActivationPackageError(
                "cutover gate failed and sealed staging cleanup did not complete"
            ) from cleanup_error
        if not cleanup_durable:
            raise ActivationPackageError(
                "cutover gate failed; cleanup completed but terminal recovery state is not durable"
            ) from error
        raise ActivationPackageError("cutover gate failed after staging cleanup") from error
    try:
        _write_activation_state(
            _runner_state(
                package_digest=digest,
                status="canary_passed_awaiting_cutover_approval",
                phase="staging-canary",
            )
        )
        _emit_activation_progress(
            package_digest=digest,
            phase="staging-canary",
            status="phase-complete",
            stage="unknown-sealed-command",
        )
    except _ActivationProgressEmissionError as progress_error:
        _raise_progress_error_after_staging_containment(
            contract,
            package_digest=digest,
            progress_error=progress_error,
        )
    except BaseException as checkpoint_error:
        try:
            cleanup_durable = _execute_resilient_cleanup(
                contract,
                package_digest=digest,
                originating_failure=type(checkpoint_error).__name__,
            )
        except _ActivationProgressEmissionError:
            raise
        except BaseException as cleanup_error:
            raise ActivationPackageError(
                "final staging checkpoint failed and immediate cleanup failed"
            ) from cleanup_error
        if not cleanup_durable:
            raise ActivationPackageError(
                "final staging checkpoint failed; cleanup completed but terminal recovery state is not durable"
            ) from checkpoint_error
        raise ActivationPackageError(
            "final staging checkpoint failed; immediate cleanup completed"
        ) from checkpoint_error
    return {
        "status": "canary_passed_awaiting_cutover_approval",
        "packageDigest": digest,
        "replayed": False,
    }


def _execute_approved_cutover_locked(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Resume one successful canary only after a separate state-bound approval."""

    package, digest, contract = _approved_activation_contract(package_root)
    existing = _load_activation_state()
    if (
        existing is not None
        and existing.get("packageDigest") == digest
        and existing.get("status") == "complete"
        and existing.get("phase") == "complete"
    ):
        return {"status": "complete", "packageDigest": digest, "replayed": True}
    _validate_phase_prerequisite("cutover", existing, package_digest=digest)
    _load_activation_phase_approval(
        package,
        phase="cutover",
        expected_runner_state=existing,
    )
    cutover = _contract_commands(contract, "cutoverCommands")
    rollback = _contract_commands(contract, "rollbackCommands")
    cutover_running_state = _runner_state(
        package_digest=digest,
        status="running",
        phase="cutover",
    )
    _write_activation_state(cutover_running_state)
    completed_state: dict[str, object] | None = None
    for index, command in enumerate(cutover):
        command_state = _runner_state(
            package_digest=digest,
            status="command_running",
            phase="cutover",
            command_index=index,
            command=command,
        )
        try:
            _write_activation_state(command_state)
        except BaseException as checkpoint_error:
            try:
                rollback_durable = _execute_resilient_rollback(
                    contract,
                    package_digest=digest,
                    prior_state=completed_state or cutover_running_state,
                    originating_failure=type(checkpoint_error).__name__,
                )
            except BaseException as rollback_error:
                raise ActivationPackageError(
                    "cutover command entry checkpoint failed and sealed rollback did not complete"
                ) from rollback_error
            if not rollback_durable:
                raise ActivationPackageError(
                    "cutover command entry checkpoint failed; rollback completed but terminal recovery state is not durable"
                ) from checkpoint_error
            raise ActivationPackageError(
                "cutover command entry checkpoint failed; immediate sealed rollback completed"
            ) from checkpoint_error
        returncode, start_error = _validated_command_outcome(contract, command)
        if returncode != 0:
            command_failure = _classify_command_failure(returncode, start_error)
            rollback_state = _runner_state(
                package_digest=digest,
                status="rollback_command_running",
                phase="rollback",
                command_index=0,
                command=rollback[0],
                failure=command_failure,
            )
            try:
                _write_activation_state(rollback_state)
                recovery_state: Mapping[str, object] = rollback_state
            except BaseException:
                recovery_state = command_state
            try:
                rollback_durable = _execute_resilient_rollback(
                    contract,
                    package_digest=digest,
                    prior_state=recovery_state,
                    originating_failure=command_failure,
                )
            except BaseException as error:
                raise ActivationPackageError(
                    "cutover failed and sealed rollback did not complete"
                ) from error
            if not rollback_durable:
                raise ActivationPackageError(
                    "cutover failed; sealed rollback completed but terminal recovery state is not durable"
                )
            raise ActivationPackageError("cutover failed and the sealed rollback completed")
        completed_state = _runner_state(
            package_digest=digest,
            status="command_complete",
            phase="cutover",
            command_index=index,
            command=command,
        )
        try:
            _write_activation_state(completed_state)
        except BaseException as checkpoint_error:
            try:
                rollback_durable = _execute_resilient_rollback(
                    contract,
                    package_digest=digest,
                    prior_state=command_state,
                    originating_failure=type(checkpoint_error).__name__,
                )
            except BaseException as rollback_error:
                raise ActivationPackageError(
                    "checkpoint failed after cutover command and immediate sealed rollback failed"
                ) from rollback_error
            if not rollback_durable:
                raise ActivationPackageError(
                    "checkpoint failed after cutover command; rollback completed but terminal recovery state is not durable"
                ) from checkpoint_error
            raise ActivationPackageError(
                "checkpoint failed after cutover command; immediate sealed rollback completed"
            ) from checkpoint_error
    try:
        _write_activation_state(
            _runner_state(package_digest=digest, status="complete", phase="complete")
        )
    except BaseException as checkpoint_error:
        try:
            rollback_durable = _execute_resilient_rollback(
                contract,
                package_digest=digest,
                prior_state=completed_state,
                originating_failure=type(checkpoint_error).__name__,
            )
        except BaseException as rollback_error:
            raise ActivationPackageError(
                "final cutover checkpoint failed and immediate sealed rollback failed"
            ) from rollback_error
        if not rollback_durable:
            raise ActivationPackageError(
                "final cutover checkpoint failed; rollback completed but terminal recovery state is not durable"
            ) from checkpoint_error
        raise ActivationPackageError(
            "final cutover checkpoint failed; immediate sealed rollback completed"
        ) from checkpoint_error
    return {"status": "complete", "packageDigest": digest, "replayed": False}


def _execute_approved_rollback_locked(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Recover an interrupted/failed cutover through only the sealed rollback commands."""

    _require_root_activation()
    package = Path(package_root).resolve()
    approval = _load_activation_approval_for_rollback(package)
    digest = str(approval["packageDigest"])
    sealed_contract = _sealed_package_json(
        package,
        expected_package_digest=digest,
        relative_path="public/activation-contract.json",
    )
    require_canary_evidence = (
        sealed_contract.get("schemaVersion") == ACTIVATION_CONTRACT_SCHEMA
    )
    contract = _normalize_rollback_contract(sealed_contract)
    if contract.get("packageRoot") != str(package):
        raise ActivationPackageError("activation contract package root is not approval-bound")
    state = _load_activation_state()
    if state is None or state.get("packageDigest") != digest:
        raise ActivationPackageError("no matching activation runner state exists for rollback")
    if state.get("status") == "rolled_back":
        return {"status": "rolled_back", "packageDigest": digest, "replayed": True}
    if state.get("status") == "aborted_before_cutover":
        _verify_sealed_canary_state_from_contract(
            contract,
            required=require_canary_evidence,
        )
        return {
            "status": "aborted_before_cutover",
            "packageDigest": digest,
            "replayed": True,
        }
    if state.get("phase") in {"staging", "staging-canary", "staging_cleanup"}:
        prior_failure = _validate_bounded_failure_classification(state.get("failure"))
        if not _execute_resilient_cleanup(
            contract,
            package_digest=digest,
            originating_failure=prior_failure,
            require_canary_evidence=require_canary_evidence,
        ):
            raise ActivationPackageError(
                "staging cleanup completed but terminal recovery state is not durable"
            )
        return {"status": "aborted_before_cutover", "packageDigest": digest, "replayed": False}
    if state.get("phase") not in {"cutover", "rollback"}:
        raise ActivationPackageError("activation runner state is not eligible for sealed rollback")
    if not _execute_resilient_rollback(
        contract,
        package_digest=digest,
        prior_state=state,
        originating_failure=_validate_bounded_failure_classification(state.get("failure")),
    ):
        raise ActivationPackageError(
            "sealed rollback completed but terminal recovery state is not durable"
        )
    return {"status": "rolled_back", "packageDigest": digest, "replayed": False}


def execute_approved_activation(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Fail closed so legacy callers cannot cross the separate approval boundary."""

    _require_root_activation()
    raise ActivationPackageError(
        "activation requires separate phase runners: execute-approved-staging-canary then execute-approved-cutover"
    )


_MAINTENANCE_WRITER_UNITS = MAINTENANCE_WRITER_UNITS
_MAINTENANCE_PRIOR_ACTIVE_UNITS = MAINTENANCE_EXPECTED_ACTIVE_UNITS
_MAINTENANCE_OPTIONAL_WRITER_UNITS = {
    "overseer-psychlo-coordination-tick.timer",
    "overseer-psychlo-coordination-tick.service",
}


def _maintenance_user_systemctl_command(*arguments: str) -> list[str]:
    god = pwd.getpwnam("god")
    return [
        "/usr/sbin/runuser",
        "--user",
        "god",
        "--",
        "/usr/bin/env",
        f"XDG_RUNTIME_DIR=/run/user/{god.pw_uid}",
        "/usr/bin/systemctl",
        "--user",
        *arguments,
    ]


def _maintenance_user_systemctl_inspection_command(*arguments: str) -> list[str]:
    """Inspect the god user manager as root or as god during package staging."""

    god = pwd.getpwnam("god")
    if os.geteuid() == 0:
        return _maintenance_user_systemctl_command(*arguments)
    if os.geteuid() == god.pw_uid:
        return [
            "/usr/bin/env",
            f"XDG_RUNTIME_DIR=/run/user/{god.pw_uid}",
            "/usr/bin/systemctl",
            "--user",
            *arguments,
        ]
    raise ActivationPackageError(
        "maintenance writer unit inspection requires root or the god account"
    )


def _maintenance_user_unit_state(unit: str) -> dict[str, str]:
    if unit not in _MAINTENANCE_WRITER_UNITS:
        raise ActivationPackageError("maintenance writer unit is not allowlisted")
    try:
        result = subprocess.run(
            _maintenance_user_systemctl_inspection_command(
                "show",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=UnitFileState",
                unit,
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActivationPackageError(
            "maintenance writer unit state could not be inspected"
        ) from error
    if result.returncode != 0:
        raise ActivationPackageError("maintenance writer unit state inspection failed")
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            observed[key] = value
    if set(observed) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise ActivationPackageError("maintenance writer unit state is incomplete")
    return observed


def _capture_maintenance_writer_unit_baseline() -> list[dict[str, str]]:
    """Capture only the exact stable writer profile supported by this package."""

    observed = {
        unit: _maintenance_user_unit_state(unit)
        for unit in _MAINTENANCE_WRITER_UNITS
    }
    for unit, state in observed.items():
        if unit in _MAINTENANCE_OPTIONAL_WRITER_UNITS:
            if state["LoadState"] not in {"loaded", "not-found"}:
                raise ActivationPackageError("optional maintenance writer unit is unsafe")
            continue
        if state["LoadState"] != "loaded":
            raise ActivationPackageError("required maintenance writer unit is unavailable")
    for unit in _MAINTENANCE_PRIOR_ACTIVE_UNITS:
        state = observed[unit]
        if state["ActiveState"] != "active" or state["UnitFileState"] != "enabled":
            raise ActivationPackageError(
                "maintenance writer unit no longer matches the sealed active baseline"
            )
    for unit in set(_MAINTENANCE_WRITER_UNITS) - set(
        _MAINTENANCE_PRIOR_ACTIVE_UNITS
    ) - _MAINTENANCE_OPTIONAL_WRITER_UNITS:
        state = observed[unit]
        if state["ActiveState"] != "inactive" or state["UnitFileState"] != "static":
            raise ActivationPackageError(
                "maintenance writer unit does not match the stable inactive baseline"
            )
    for unit in _MAINTENANCE_OPTIONAL_WRITER_UNITS:
        state = observed[unit]
        if state != {
            "LoadState": "not-found",
            "ActiveState": "inactive",
            "UnitFileState": "",
        }:
            raise ActivationPackageError(
                "legacy Psychlo coordination units must be absent before packaging"
            )
    return [
        {
            "unit": unit,
            "loadState": observed[unit]["LoadState"],
            "activeState": observed[unit]["ActiveState"],
            "unitFileState": observed[unit]["UnitFileState"],
        }
        for unit in _MAINTENANCE_WRITER_UNITS
    ]


def _maintenance_writer_unit_preflight(
    baseline: object,
) -> dict[str, dict[str, str]]:
    """Require the current writer inventory to equal the sealed package baseline."""

    if not isinstance(baseline, list):
        raise ActivationPackageError("maintenance writer unit baseline is invalid")
    expected = {
        str(entry.get("unit")): {
            "LoadState": entry.get("loadState"),
            "ActiveState": entry.get("activeState"),
            "UnitFileState": entry.get("unitFileState"),
        }
        for entry in baseline
        if isinstance(entry, Mapping)
    }
    if tuple(expected) != _MAINTENANCE_WRITER_UNITS:
        raise ActivationPackageError("maintenance writer unit baseline is invalid")
    observed = {
        unit: _maintenance_user_unit_state(unit)
        for unit in _MAINTENANCE_WRITER_UNITS
    }
    if observed != expected:
        raise ActivationPackageError(
            "maintenance writer units drifted from the sealed writer unit baseline"
        )
    return observed


def _maintenance_system_unit_state(unit: str) -> dict[str, str]:
    if unit not in MAINTENANCE_SUCCESSOR_SYSTEM_UNITS:
        raise ActivationPackageError("maintenance successor unit is not allowlisted")
    try:
        result = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=UnitFileState",
                unit,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActivationPackageError(
            "maintenance successor unit state could not be inspected"
        ) from error
    if result.returncode != 0:
        raise ActivationPackageError(
            "maintenance successor unit state inspection failed"
        )
    observed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            observed[key] = value
    if set(observed) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise ActivationPackageError(
            "maintenance successor unit state is incomplete"
        )
    return observed


def _capture_maintenance_successor_unit_baseline() -> list[dict[str, str]]:
    """Capture the exact inactive successor system-unit profile."""

    observed = {
        unit: _maintenance_system_unit_state(unit)
        for unit in MAINTENANCE_SUCCESSOR_SYSTEM_UNITS
    }
    expected = {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "UnitFileState": "disabled",
    }
    if any(state != expected for state in observed.values()):
        raise ActivationPackageError(
            "maintenance successor units must be loaded, inactive, and disabled"
        )
    return [
        {
            "unit": unit,
            "loadState": observed[unit]["LoadState"],
            "activeState": observed[unit]["ActiveState"],
            "unitFileState": observed[unit]["UnitFileState"],
        }
        for unit in MAINTENANCE_SUCCESSOR_SYSTEM_UNITS
    ]


def _maintenance_successor_unit_preflight(
    baseline: object,
) -> dict[str, dict[str, str]]:
    """Require successor system units to equal the sealed inactive baseline."""

    if not isinstance(baseline, list):
        raise ActivationPackageError("maintenance successor unit baseline is invalid")
    expected = {
        str(entry.get("unit")): {
            "LoadState": entry.get("loadState"),
            "ActiveState": entry.get("activeState"),
            "UnitFileState": entry.get("unitFileState"),
        }
        for entry in baseline
        if isinstance(entry, Mapping)
    }
    if tuple(expected) != MAINTENANCE_SUCCESSOR_SYSTEM_UNITS:
        raise ActivationPackageError("maintenance successor unit baseline is invalid")
    observed = {
        unit: _maintenance_system_unit_state(unit)
        for unit in MAINTENANCE_SUCCESSOR_SYSTEM_UNITS
    }
    if observed != expected:
        raise ActivationPackageError(
            "maintenance successor units drifted from the sealed unit baseline"
        )
    return observed


def _maintenance_store_binding_identity_valid(binding: Mapping[str, object]) -> bool:
    source_value = binding.get("sourceDb")
    identity = binding.get("sourceIdentity")
    if not isinstance(source_value, str) or not isinstance(identity, Mapping):
        return False
    source = Path(source_value)
    try:
        source_metadata = source.lstat()
        parent_metadata = source.parent.lstat()
    except OSError:
        return False
    return (
        not source.is_symlink()
        and not source.parent.is_symlink()
        and stat.S_ISREG(source_metadata.st_mode)
        and source_metadata.st_nlink == 1
        and stat.S_ISDIR(parent_metadata.st_mode)
        and source_metadata.st_dev == identity.get("device")
        and source_metadata.st_ino == identity.get("inode")
        and source_metadata.st_uid == identity.get("uid")
        and source_metadata.st_gid == identity.get("gid")
        and stat.S_IMODE(source_metadata.st_mode) == identity.get("mode")
        and parent_metadata.st_dev == identity.get("parentDevice")
        and parent_metadata.st_ino == identity.get("parentInode")
        and stat.S_IMODE(parent_metadata.st_mode) == identity.get("parentMode")
    )


def _maintenance_destination_preflight(bindings: list[object]) -> None:
    """Read-only validation of the fixed empty dedicated-principal targets."""

    if len(bindings) != len(MAINTENANCE_STORE_DESTINATIONS):
        raise ActivationPackageError("maintenance destination bindings are invalid")
    for binding, (expected_name, expected_path) in zip(
        bindings,
        MAINTENANCE_STORE_DESTINATIONS,
        strict=True,
    ):
        if (
            not isinstance(binding, Mapping)
            or binding.get("name") != expected_name
            or binding.get("destinationDb") != expected_path
        ):
            raise ActivationPackageError("maintenance destination binding is invalid")
        destination = Path(expected_path)
        _validate_migration_destination_directory(
            destination.parent,
            destination_uid=APPROVED_OVERSEER_UID,
            destination_gid=APPROVED_OVERSEER_GID,
        )
        for candidate in (
            destination,
            Path(f"{destination}-wal"),
            Path(f"{destination}-shm"),
        ):
            if candidate.exists() or candidate.is_symlink():
                raise ActivationPackageError(
                    "maintenance destination namespace is not empty"
                )


def verify_maintenance_preflight(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Fail closed on all discoverable inputs before any writer is stopped."""

    package = Path(package_root).resolve()
    _require_maintenance_active_sealed_command(
        package_root,
        command_name="verify-maintenance-preflight",
        expected_options={"--package-root": str(package)},
    )
    contract = _read_maintenance_contract_file(package)
    bindings = contract.get("storeBindings")
    deferred = contract.get("deferredStoreBindings")
    inputs = contract.get("preservationInputs")
    writer_baseline = contract.get("writerUnitBaseline")
    successor_baseline = contract.get("successorUnitBaseline")
    evidence_value = contract.get("evidenceRoot")
    if (
        not isinstance(bindings, list)
        or not isinstance(deferred, list)
        or not isinstance(inputs, Mapping)
        or not isinstance(evidence_value, str)
    ):
        raise ActivationPackageError("maintenance preflight contract is invalid")
    all_bindings = [*bindings, *deferred]
    if not all(
        isinstance(binding, Mapping)
        and _maintenance_store_binding_identity_valid(binding)
        for binding in all_bindings
    ):
        raise ActivationPackageError("maintenance source identity drifted before writer stop")
    _maintenance_destination_preflight(bindings)
    required_bytes = _maintenance_preservation_required_bytes(all_bindings, inputs)
    evidence_root = Path(evidence_value)
    if evidence_root.exists() or evidence_root.is_symlink():
        raise ActivationPackageError("maintenance evidence root already exists")
    anchor = evidence_root.parent
    while not anchor.exists() and anchor.parent != anchor:
        anchor = anchor.parent
    try:
        anchor_metadata = anchor.lstat()
        available = shutil.disk_usage(anchor).free
    except OSError as error:
        raise ActivationPackageError("maintenance evidence capacity could not be verified") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        anchor.is_symlink()
        or not stat.S_ISDIR(anchor_metadata.st_mode)
        or (anchor_metadata.st_uid, anchor_metadata.st_gid) != (root_uid, root_gid)
    ):
        raise ActivationPackageError("maintenance evidence parent is unsafe")
    if available < required_bytes + MIN_APPROVED_PACKAGE_IMPORT_HEADROOM_BYTES:
        raise ActivationPackageError("maintenance evidence storage headroom is insufficient")
    unit_states = _maintenance_writer_unit_preflight(writer_baseline)
    successor_states = _maintenance_successor_unit_preflight(successor_baseline)
    return {
        "status": "preflight_passed",
        "requiredBytes": required_bytes,
        "writerUnitCount": len(unit_states),
        "successorUnitCount": len(successor_states),
    }


def _stop_maintenance_writers_unchecked() -> dict[str, object]:
    """Idempotently stop every loaded allowlisted Overseer user writer."""

    states = {
        unit: _maintenance_user_unit_state(unit)
        for unit in _MAINTENANCE_WRITER_UNITS
    }
    loaded = [unit for unit, state in states.items() if state["LoadState"] == "loaded"]
    if loaded:
        try:
            result = subprocess.run(
                _maintenance_user_systemctl_command("stop", *loaded),
                check=False,
                timeout=90,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ActivationPackageError("maintenance writer stop failed") from error
        if result.returncode != 0:
            raise ActivationPackageError("maintenance writer stop failed")
    remaining = [
        unit
        for unit in loaded
        if _maintenance_user_unit_state(unit)["ActiveState"] != "inactive"
    ]
    if remaining:
        raise ActivationPackageError("maintenance writer stop did not quiesce all units")
    return {"status": "writers_stopped", "unitCount": len(loaded)}


def stop_maintenance_writers(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Stop every loaded Overseer user writer under one sealed helper."""

    package = Path(package_root).resolve()
    _require_maintenance_active_sealed_command(
        package_root,
        command_name="stop-maintenance-writers",
        expected_options={"--package-root": str(package)},
    )
    return _stop_maintenance_writers_unchecked()


def restop_maintenance_writers(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Reassert writer quiescence during sealed early rollback."""

    package = Path(package_root).resolve()
    _require_maintenance_active_rollback_command(
        package_root,
        command_name="restop-maintenance-writers",
        expected_options={"--package-root": str(package)},
    )
    return _stop_maintenance_writers_unchecked()


def restore_maintenance_writers(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Restore the exact preflight-active user units after safe rollback."""

    package = Path(package_root).resolve()
    contract = _require_maintenance_active_rollback_command(
        package_root,
        command_name="restore-maintenance-writers",
        expected_options={"--package-root": str(package)},
    )
    baseline = contract.get("writerUnitBaseline")
    if not isinstance(baseline, list):
        raise ActivationPackageError("maintenance writer restoration baseline is invalid")
    active_units = [
        str(entry.get("unit"))
        for entry in baseline
        if isinstance(entry, Mapping) and entry.get("activeState") == "active"
    ]
    if not active_units or any(
        not isinstance(entry, Mapping)
        or entry.get("unit") not in _MAINTENANCE_WRITER_UNITS
        or (
            entry.get("activeState") == "active"
            and entry.get("unitFileState") != "enabled"
        )
        for entry in baseline
    ):
        raise ActivationPackageError("maintenance writer restoration baseline is invalid")
    try:
        result = subprocess.run(
            _maintenance_user_systemctl_command("enable", "--now", *active_units),
            check=False,
            timeout=120,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActivationPackageError("maintenance writer restoration failed") from error
    if result.returncode != 0 or any(
        _maintenance_user_unit_state(unit)["ActiveState"] != "active"
        for unit in active_units
    ):
        raise ActivationPackageError("maintenance writer restoration failed")
    return {
        "status": "writers_restored",
        "unitCount": len(active_units),
    }


def _maintenance_writer_inventory(
    contract: Mapping[str, object],
) -> tuple[str, ...]:
    """Return only bounded source paths whose store inode is still active."""

    bindings = contract.get("storeBindings")
    deferred = contract.get("deferredStoreBindings", [])
    if not isinstance(bindings, list) or not bindings or len(bindings) > 16:
        raise ActivationPackageError("maintenance store bindings are invalid")
    if not isinstance(deferred, list) or len(deferred) > 16:
        raise ActivationPackageError("maintenance deferred store bindings are invalid")
    active: list[str] = []
    for binding in [*bindings, *deferred]:
        if not isinstance(binding, Mapping):
            raise ActivationPackageError("maintenance store binding is invalid")
        source_value = binding.get("sourceDb")
        if not isinstance(source_value, str) or not source_value.startswith("/"):
            raise ActivationPackageError("maintenance store source is invalid")
        source = Path(source_value)
        for artifact_index, artifact in enumerate(_legacy_store_paths(source)):
            try:
                metadata = artifact.lstat()
            except FileNotFoundError:
                if artifact_index == 0:
                    raise ActivationPackageError(
                        "maintenance authority store is unavailable"
                    )
                continue
            except OSError as error:
                raise ActivationPackageError(
                    "maintenance store artifact could not be inspected"
                ) from error
            if artifact.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise ActivationPackageError("maintenance store artifact is unsafe")
            if _legacy_inode_activity(
                ((metadata.st_dev, metadata.st_ino),),
                include_open_files=True,
            ):
                active.append(str(artifact))
                if len(active) >= 64:
                    return tuple(active)
    return tuple(active)


def verify_maintenance_quiescence(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Verify maintenance stores are quiesced without performing any writes."""

    package = Path(package_root).resolve()
    _require_maintenance_active_sealed_command(
        package_root,
        command_name="verify-maintenance-quiescence",
        expected_options={"--package-root": str(package)},
    )
    contract = _read_maintenance_contract_file(package)
    writers = _maintenance_writer_inventory(contract)
    if writers:
        raise ActivationPackageError(
            "maintenance writers remain active for bounded store paths"
        )
    return {"status": "quiesced", "writerPaths": []}


_MAINTENANCE_ACCEPTANCE_CHECKS = (
    "api",
    "authenticated-ui-data",
    "scheduler-freshness",
    "protected-gateway-read",
    "psychlo-read",
    "roadex-read",
    "credentials",
    "single-writer-inventory",
)
_MAINTENANCE_FRESHNESS_JOB_IDS = (
    "collection.discovery.physical",
    "collection.discovery.storage",
    "collection.discovery.virtual",
    "collection.freshness.psychlo-usage",
    "collection.freshness.quark-scheduler",
    "collection.git.overseer",
    "collection.host.inspection",
    "collection.host.security",
    "collection.package.inspection",
    "collection.storage.capacity",
)
_MAINTENANCE_GATEWAY_CHALLENGE_PATH = Path(
    "/run/overseer/maintenance-gateway-challenge"
)
_MAINTENANCE_HANDOFF_CREDENTIAL_DIRECTORY = Path("/etc/overseer")
_MAINTENANCE_HANDOFF_CREDENTIAL_NAMES = (
    "admin-approval-verifier.json",
    "roadex-fixture-approval-verifier.json",
    "api-token",
    "psychlo-peer-secret",
    "roadex-project-human-thread-secret",
    "psychlo-project-bindings.json",
    "admin-executor-public-key",
    "admin-executor-allowlist.json",
    "admin-ticket-private-key",
    "protected-gateway-ca.crt",
)
_MAINTENANCE_HANDOFF_SYSTEM_INPUTS = {
    "systemAdminSocketUnit": Path(
        "/etc/systemd/system/overseer-admin-executor.socket"
    ),
    "systemAdminServiceUnit": Path(
        "/etc/systemd/system/overseer-admin-executor@.service"
    ),
    "systemApiUnit": Path("/etc/systemd/system/overseer-api.service"),
    "systemUserBridgeServiceUnit": Path(
        "/etc/systemd/system/overseer-codex-user-bridge.service"
    ),
    "systemUserBridgeSocketUnit": Path(
        "/etc/systemd/system/overseer-codex-user-bridge.socket"
    ),
    "systemRuntimeUnit": Path("/etc/systemd/system/overseer-runtime.service"),
    "systemTmpfilesRule": Path("/etc/tmpfiles.d/overseer.conf"),
}
_MAINTENANCE_HANDOFF_COMPATIBILITY_INPUTS = {
    "compatibilityApiToken": Path(
        "/home/god/.local/share/overseer/project/state/api-token"
    ),
}


def _maintenance_copy_regular(source: Path, target: Path) -> dict[str, object]:
    try:
        before = source.lstat()
    except OSError as error:
        raise ActivationPackageError("maintenance preservation input is unavailable") from error
    if (
        source.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > MAX_APPROVED_PACKAGE_IMPORT_BYTES
    ):
        raise ActivationPackageError("maintenance preservation input is unsafe")
    if target.exists() or target.is_symlink():
        raise ActivationPackageError("maintenance evidence destination already exists")
    _ensure_directory(target.parent)
    source_descriptor = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    target_descriptor = -1
    digest = hashlib.sha256()
    copied = 0
    try:
        opened = os.fstat(source_descriptor)
        expected_identity = _metadata_identity(before)
        if _metadata_identity(opened) != expected_identity:
            raise ActivationPackageError("maintenance preservation input changed while opening")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        target_descriptor = os.open(target, flags, 0o600)
        while True:
            chunk = os.read(source_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            copied += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError("maintenance evidence copy made no progress")
                view = view[written:]
        after = os.fstat(source_descriptor)
        lexical_after = source.lstat()
        if (
            _metadata_identity(after) != expected_identity
            or _metadata_identity(lexical_after) != expected_identity
            or copied != before.st_size
        ):
            raise ActivationPackageError("maintenance preservation input changed during copy")
        os.fchmod(target_descriptor, 0o600)
        os.fsync(target_descriptor)
    except BaseException:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(source_descriptor)
        if target_descriptor >= 0:
            os.close(target_descriptor)
    return {
        "path": str(target),
        "sha256": digest.hexdigest(),
        "size": copied,
        "mode": "0600",
        "sourcePath": str(source),
        "sourceDevice": before.st_dev,
        "sourceInode": before.st_ino,
        "sourceUid": before.st_uid,
        "sourceGid": before.st_gid,
        "sourceMode": stat.S_IMODE(before.st_mode),
    }


def _maintenance_copy_tree(
    source: Path,
    target: Path,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    try:
        metadata = source.lstat()
    except OSError as error:
        raise ActivationPackageError("maintenance preservation directory is unavailable") from error
    if source.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ActivationPackageError("maintenance preservation directory is unsafe")
    if target.exists() or target.is_symlink():
        raise ActivationPackageError("maintenance evidence destination already exists")
    inventory_before = _tree_inventory(
        source,
        label="maintenance preservation directory",
    )
    if len(inventory_before) > 100_000:
        raise ActivationPackageError("maintenance preservation tree is too large")
    _ensure_directory(target)
    os.chmod(target, 0o700)
    artifacts: list[dict[str, object]] = []
    for entry in inventory_before:
        relative = Path(str(entry["relativePath"]))
        destination = target / relative
        _ensure_directory(destination.parent, enforce_existing_mode=False)
        artifacts.append(_maintenance_copy_regular(source / relative, destination))
    inventory_after = _tree_inventory(
        source,
        label="maintenance preservation directory",
    )
    try:
        metadata_after = source.lstat()
    except OSError as error:
        raise ActivationPackageError(
            "maintenance preservation directory changed during copy"
        ) from error
    if (
        inventory_after != inventory_before
        or _metadata_identity(metadata_after) != _metadata_identity(metadata)
    ):
        raise ActivationPackageError(
            "maintenance preservation directory changed during copy"
        )
    return artifacts, {
        "path": str(target),
        "mode": "0700",
        "sourcePath": str(source),
        "sourceDevice": metadata.st_dev,
        "sourceInode": metadata.st_ino,
        "sourceUid": metadata.st_uid,
        "sourceGid": metadata.st_gid,
        "sourceMode": stat.S_IMODE(metadata.st_mode),
    }


def _maintenance_preservation_required_bytes(
    bindings: list[object],
    inputs: Mapping[str, object],
) -> int:
    """Calculate a bounded preservation size before creating evidence."""

    selected_paths: list[Path] = []
    for binding in bindings:
        if not isinstance(binding, Mapping) or not isinstance(
            binding.get("sourceDb"), str
        ):
            raise ActivationPackageError("maintenance store binding is invalid")
        selected_paths.extend(_legacy_store_paths(Path(str(binding["sourceDb"]))))
    for value in inputs.values():
        if not isinstance(value, str) or not value.startswith("/"):
            raise ActivationPackageError("maintenance preservation input is invalid")
        selected_paths.append(Path(value))
    total = 0
    for selected in selected_paths:
        try:
            metadata = selected.lstat()
        except FileNotFoundError:
            if selected.name.endswith(("-wal", "-shm")):
                continue
            raise ActivationPackageError(
                "maintenance preservation input is unavailable"
            )
        except OSError as error:
            raise ActivationPackageError(
                "maintenance preservation input could not be inspected"
            ) from error
        if selected.is_symlink():
            raise ActivationPackageError("maintenance preservation input is unsafe")
        if stat.S_ISREG(metadata.st_mode):
            total += metadata.st_size
        elif stat.S_ISDIR(metadata.st_mode):
            entries = _tree_inventory(
                selected,
                label="maintenance preservation directory",
            )
            if len(entries) > 100_000:
                raise ActivationPackageError(
                    "maintenance preservation tree is too large"
                )
            total += sum(int(entry["size"]) for entry in entries)
        else:
            raise ActivationPackageError("maintenance preservation input is unsafe")
        if total > MAX_APPROVED_PACKAGE_IMPORT_BYTES:
            raise ActivationPackageError(
                "maintenance preservation exceeds the bounded size"
            )
    return total


def preserve_maintenance_state(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Copy exact quiesced authority and rollback inputs into owner-only evidence."""

    package = Path(package_root).resolve()
    _require_maintenance_active_sealed_command(
        package_root,
        command_name="preserve-maintenance-state",
        expected_options={"--package-root": str(package)},
    )
    contract = _read_maintenance_contract_file(package)
    if _maintenance_writer_inventory(contract):
        raise ActivationPackageError("maintenance preservation requires quiesced writers")
    root_value = contract.get("evidenceRoot")
    bindings = contract.get("storeBindings")
    deferred = contract.get("deferredStoreBindings")
    inputs = contract.get("preservationInputs")
    if (
        not isinstance(root_value, str)
        or not root_value.startswith("/")
        or not isinstance(bindings, list)
        or not isinstance(deferred, list)
        or not isinstance(inputs, Mapping)
    ):
        raise ActivationPackageError("maintenance preservation contract is invalid")
    evidence_root = Path(root_value)
    if evidence_root.is_symlink():
        raise ActivationPackageError("maintenance evidence root is a symlink")
    if evidence_root.exists():
        metadata = evidence_root.lstat()
        root_uid, root_gid = _activation_root_identity()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or (metadata.st_uid, metadata.st_gid) != (root_uid, root_gid)
        ):
            raise ActivationPackageError("maintenance evidence root is unsafe")
    else:
        required_bytes = _maintenance_preservation_required_bytes(
            [*bindings, *deferred], inputs
        )
        capacity_anchor = evidence_root.parent
        while not capacity_anchor.exists() and capacity_anchor.parent != capacity_anchor:
            capacity_anchor = capacity_anchor.parent
        try:
            available = shutil.disk_usage(capacity_anchor).free
        except OSError as error:
            raise ActivationPackageError(
                "maintenance evidence capacity could not be verified"
            ) from error
        if available < required_bytes + MIN_APPROVED_PACKAGE_IMPORT_HEADROOM_BYTES:
            raise ActivationPackageError(
                "maintenance evidence storage headroom is insufficient"
            )
        _ensure_directory(evidence_root)
        os.chmod(evidence_root, 0o700)
    artifacts: list[dict[str, object]] = []
    directories: list[dict[str, object]] = []
    for binding in [*bindings, *deferred]:
        if not isinstance(binding, Mapping):
            raise ActivationPackageError("maintenance store binding is invalid")
        name = binding.get("name")
        source_value = binding.get("sourceDb")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name)
            or not isinstance(source_value, str)
            or not source_value.startswith("/")
        ):
            raise ActivationPackageError("maintenance store binding is invalid")
        source = Path(source_value)
        destination = evidence_root / "stores" / name / source.name
        for source_path, destination_path in zip(
            _legacy_store_paths(source),
            _legacy_store_paths(destination),
            strict=True,
        ):
            if source_path.exists() or source_path.is_symlink():
                artifacts.append(_maintenance_copy_regular(source_path, destination_path))
    for name, source_value in sorted(inputs.items()):
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", name)
            or not isinstance(source_value, str)
            or not source_value.startswith("/")
        ):
            raise ActivationPackageError("maintenance preservation input is invalid")
        source = Path(source_value)
        destination = evidence_root / "inputs" / name
        if source.is_dir() and not source.is_symlink():
            copied, directory = _maintenance_copy_tree(source, destination)
            artifacts.extend(copied)
            directories.append(directory)
        else:
            artifacts.append(_maintenance_copy_regular(source, destination))
    manifest = {
        "schemaVersion": "overseer.maintenance-preservation.v1",
        "status": "preserved",
        "evidenceRoot": str(evidence_root),
        "artifacts": artifacts,
        "directories": directories,
    }
    manifest_path = evidence_root / "preservation-manifest.json"
    _write_new(manifest_path, _canonical(manifest) + b"\n", 0o600)
    for directory in sorted(
        (path for path in evidence_root.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        _fsync_package_directory(directory)
    _fsync_package_directory(evidence_root)
    return manifest


def _verify_maintenance_preservation_unchecked(
    contract: Mapping[str, object],
) -> dict[str, object]:
    """Verify the sealed preservation namespace after command authorization."""

    root_value = contract.get("evidenceRoot")
    if not isinstance(root_value, str) or not root_value.startswith("/"):
        raise ActivationPackageError("maintenance evidence root is invalid")
    evidence_root = Path(root_value)
    manifest_path = evidence_root / "preservation-manifest.json"
    try:
        raw, manifest_metadata = _stable_read(manifest_path)
        manifest = json.loads(raw)
        root_metadata = evidence_root.lstat()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationPackageError("maintenance preservation manifest is invalid") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != "overseer.maintenance-preservation.v1"
        or manifest.get("status") != "preserved"
        or manifest.get("evidenceRoot") != str(evidence_root)
        or not isinstance(manifest.get("artifacts"), list)
        or not isinstance(manifest.get("directories"), list)
        or evidence_root.is_symlink()
        or not stat.S_ISDIR(root_metadata.st_mode)
        or (root_metadata.st_uid, root_metadata.st_gid) != (root_uid, root_gid)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or (manifest_metadata.st_uid, manifest_metadata.st_gid) != (root_uid, root_gid)
        or stat.S_IMODE(manifest_metadata.st_mode) != 0o600
    ):
        raise ActivationPackageError("maintenance preservation namespace is unsafe")
    expected_paths = {manifest_path}
    for item in manifest["artifacts"]:
        if not isinstance(item, Mapping):
            raise ActivationPackageError("maintenance preservation artifact is invalid")
        path_value = item.get("path")
        source_value = item.get("sourcePath")
        if (
            not isinstance(path_value, str)
            or not isinstance(source_value, str)
            or not source_value.startswith("/")
            or any(
                type(item.get(field)) is not int or int(item[field]) < 0
                for field in (
                    "sourceDevice",
                    "sourceInode",
                    "sourceUid",
                    "sourceGid",
                    "sourceMode",
                )
            )
            or int(item["sourceMode"]) > 0o777
        ):
            raise ActivationPackageError("maintenance preservation artifact is invalid")
        path = Path(path_value)
        try:
            path.relative_to(evidence_root)
        except ValueError as error:
            raise ActivationPackageError(
                "maintenance preservation artifact is invalid"
            ) from error
        try:
            details = _stream_hash_regular(
                path,
                label="maintenance preservation artifact",
                expected_size=(
                    int(item["size"])
                    if type(item.get("size")) is int
                    else None
                ),
            )
        except ActivationPackageError as error:
            raise ActivationPackageError(
                "maintenance preservation artifact drifted"
            ) from error
        if (
            item.get("sha256") != details["sha256"]
            or item.get("size") != details["size"]
            or item.get("mode") != "0600"
            or (details["uid"], details["gid"]) != (root_uid, root_gid)
            or details["mode"] != "0600"
            or details["links"] != 1
        ):
            raise ActivationPackageError("maintenance preservation artifact drifted")
        if path in expected_paths:
            raise ActivationPackageError("maintenance preservation artifact is duplicated")
        expected_paths.add(path)
    expected_directories: set[Path] = set()

    def record_expected_parents(path: Path) -> None:
        parent = path.parent
        while parent != evidence_root:
            try:
                parent.relative_to(evidence_root)
            except ValueError as error:
                raise ActivationPackageError(
                    "maintenance preservation parent is invalid"
                ) from error
            expected_directories.add(parent)
            parent = parent.parent

    for path in expected_paths:
        record_expected_parents(path)

    observed_directories: set[str] = set()
    for item in manifest["directories"]:
        if not isinstance(item, Mapping):
            raise ActivationPackageError("maintenance preservation directory is invalid")
        path_value = item.get("path")
        source_value = item.get("sourcePath")
        if (
            not isinstance(path_value, str)
            or not isinstance(source_value, str)
            or not source_value.startswith("/")
            or source_value in observed_directories
            or item.get("mode") != "0700"
            or any(
                type(item.get(field)) is not int or int(item[field]) < 0
                for field in (
                    "sourceDevice",
                    "sourceInode",
                    "sourceUid",
                    "sourceGid",
                    "sourceMode",
                )
            )
            or int(item["sourceMode"]) > 0o777
        ):
            raise ActivationPackageError("maintenance preservation directory is invalid")
        path = Path(path_value)
        try:
            path.relative_to(evidence_root)
            metadata = path.lstat()
        except (OSError, ValueError) as error:
            raise ActivationPackageError(
                "maintenance preservation directory is invalid"
            ) from error
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != (root_uid, root_gid)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ActivationPackageError("maintenance preservation directory drifted")
        expected_directories.add(path)
        record_expected_parents(path)
        if source_value in observed_directories:
            raise ActivationPackageError("maintenance preservation directory is duplicated")
        observed_directories.add(source_value)
    observed_paths: set[Path] = set()
    observed_directory_paths: set[Path] = set()
    for path in evidence_root.rglob("*"):
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ActivationPackageError(
                "maintenance preservation namespace could not be inspected"
            ) from error
        if path.is_symlink():
            raise ActivationPackageError(
                "maintenance preservation namespace contains an invalid artifact"
            )
        if stat.S_ISREG(metadata.st_mode):
            observed_paths.add(path)
        elif stat.S_ISDIR(metadata.st_mode):
            observed_directory_paths.add(path)
        else:
            raise ActivationPackageError(
                "maintenance preservation namespace contains an invalid artifact"
            )
    if (
        observed_paths != expected_paths
        or observed_directory_paths != expected_directories
    ):
        raise ActivationPackageError(
            "maintenance preservation namespace contains unexpected artifacts"
        )
    return manifest


def verify_maintenance_preservation(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Re-hash the complete root-owned preservation namespace before handoff."""

    package = Path(package_root).resolve()
    _require_maintenance_active_sealed_command(
        package_root,
        command_name="verify-maintenance-preservation",
        expected_options={"--package-root": str(package)},
    )
    contract = _read_maintenance_contract_file(package)
    manifest = _verify_maintenance_preservation_unchecked(contract)
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ActivationPackageError("maintenance preservation manifest is invalid")
    return {"status": "preservation_verified", "artifactCount": len(artifacts)}


def _maintenance_validate_restore_parent(
    parent: Path,
    *,
    preserved_directory: Mapping[str, object] | None = None,
    expected_identity: Mapping[str, object] | None = None,
) -> os.stat_result:
    """Validate an exact rollback target parent without following links."""

    try:
        metadata = parent.lstat()
    except OSError as error:
        raise ActivationPackageError(
            "maintenance handoff restore parent is unavailable"
        ) from error
    root_uid, root_gid = _activation_root_identity()
    if parent.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
        raise ActivationPackageError("maintenance handoff restore parent is unsafe")
    if preserved_directory is not None and expected_identity is not None:
        raise ActivationPackageError("maintenance restore parent binding is ambiguous")
    if preserved_directory is not None:
        if (
            preserved_directory.get("sourcePath") != str(parent)
            or metadata.st_dev != preserved_directory.get("sourceDevice")
            or metadata.st_ino != preserved_directory.get("sourceInode")
            or metadata.st_uid != root_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ActivationPackageError(
                "maintenance credential directory identity drifted"
            )
    elif expected_identity is not None:
        if (
            metadata.st_dev != expected_identity.get("parentDevice")
            or metadata.st_ino != expected_identity.get("parentInode")
            or metadata.st_uid != expected_identity.get("uid")
            or metadata.st_gid != expected_identity.get("gid")
            or stat.S_IMODE(metadata.st_mode)
            != expected_identity.get("parentMode")
        ):
            raise ActivationPackageError(
                "maintenance compatibility-token parent identity drifted"
            )
    elif (
        (metadata.st_uid, metadata.st_gid) != (root_uid, root_gid)
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ActivationPackageError("maintenance handoff restore parent is unsafe")
    return metadata


def _maintenance_restore_regular(
    evidence: Path,
    target: Path,
    artifact: Mapping[str, object],
    *,
    preserved_directory: Mapping[str, object] | None = None,
    expected_parent_identity: Mapping[str, object] | None = None,
) -> None:
    """Atomically restore one exact preserved handoff file."""

    _maintenance_validate_restore_parent(
        target.parent,
        preserved_directory=preserved_directory,
        expected_identity=expected_parent_identity,
    )
    try:
        target_metadata = target.lstat()
    except FileNotFoundError:
        target_metadata = None
    except OSError as error:
        raise ActivationPackageError(
            "maintenance handoff target could not be inspected"
        ) from error
    if target_metadata is not None and (
        target.is_symlink()
        or not stat.S_ISREG(target_metadata.st_mode)
        or target_metadata.st_nlink != 1
    ):
        raise ActivationPackageError("maintenance handoff target is unsafe")
    content, evidence_metadata = _stable_read(evidence)
    root_uid, root_gid = _activation_root_identity()
    source_uid = artifact.get("sourceUid")
    source_gid = artifact.get("sourceGid")
    source_mode = artifact.get("sourceMode")
    if (
        artifact.get("path") != str(evidence)
        or artifact.get("sourcePath") != str(target)
        or artifact.get("sha256") != _sha256(content)
        or artifact.get("size") != len(content)
        or (evidence_metadata.st_uid, evidence_metadata.st_gid)
        != (root_uid, root_gid)
        or type(source_uid) is not int
        or type(source_gid) is not int
        or type(source_mode) is not int
        or source_uid < 0
        or source_gid < 0
        or not 0 <= source_mode <= 0o777
    ):
        raise ActivationPackageError("maintenance preserved handoff artifact is invalid")
    temporary = target.with_name(
        f".{target.name}.maintenance-rollback-{os.getpid()}-{secrets.token_hex(8)}"
    )
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("maintenance handoff restore made no progress")
            view = view[written:]
        os.fchown(descriptor, source_uid, source_gid)
        os.fchmod(descriptor, source_mode)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, target)
        _fsync_package_directory(target.parent)
    except OSError as error:
        raise ActivationPackageError("maintenance handoff restore failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _maintenance_remove_unpreserved_handoff(
    target: Path,
    *,
    preserved_directory: Mapping[str, object] | None = None,
    expected_parent_identity: Mapping[str, object] | None = None,
) -> bool:
    """Remove only an exact newly installed file that was absent before handoff."""

    _maintenance_validate_restore_parent(
        target.parent,
        preserved_directory=preserved_directory,
        expected_identity=expected_parent_identity,
    )
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        raise ActivationPackageError(
            "maintenance handoff target could not be inspected"
        ) from error
    if target.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ActivationPackageError("maintenance handoff target is unsafe")
    try:
        target.unlink()
        _fsync_package_directory(target.parent)
    except OSError as error:
        raise ActivationPackageError("maintenance handoff removal failed") from error
    return True


def _maintenance_restore_directory_metadata(
    directory: Path,
    preserved: Mapping[str, object],
) -> None:
    """Restore preserved ownership and mode on an unchanged directory inode."""

    _maintenance_validate_restore_parent(
        directory,
        preserved_directory=preserved,
    )
    source_uid = preserved.get("sourceUid")
    source_gid = preserved.get("sourceGid")
    source_mode = preserved.get("sourceMode")
    if (
        type(source_uid) is not int
        or type(source_gid) is not int
        or type(source_mode) is not int
        or source_uid < 0
        or source_gid < 0
        or not 0 <= source_mode <= 0o777
    ):
        raise ActivationPackageError(
            "maintenance preserved directory metadata is invalid"
        )
    descriptor = -1
    try:
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            metadata.st_dev != preserved.get("sourceDevice")
            or metadata.st_ino != preserved.get("sourceInode")
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise ActivationPackageError(
                "maintenance credential directory identity drifted"
            )
        os.fchown(descriptor, source_uid, source_gid)
        os.fchmod(descriptor, source_mode)
        os.fsync(descriptor)
    except OSError as error:
        raise ActivationPackageError(
            "maintenance credential directory metadata restore failed"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def restore_maintenance_handoff_artifacts(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Restore exact pre-switch credentials and units during full rollback."""

    package = Path(package_root).resolve()
    contract = _require_maintenance_active_rollback_command(
        package,
        command_name="restore-maintenance-handoff-artifacts",
        expected_options={"--package-root": str(package)},
    )
    state = _load_maintenance_state()
    if state is None or state.get("stage") != "rollback":
        raise ActivationPackageError(
            "maintenance handoff artifacts require the full rollback profile"
        )
    manifest = _verify_maintenance_preservation_unchecked(contract)
    inputs = contract.get("preservationInputs")
    root_value = contract.get("evidenceRoot")
    artifacts = manifest.get("artifacts")
    directories = manifest.get("directories")
    if (
        not isinstance(inputs, Mapping)
        or not isinstance(root_value, str)
        or not isinstance(artifacts, list)
        or not isinstance(directories, list)
        or inputs.get("systemCredentialsDirectory")
        != str(_MAINTENANCE_HANDOFF_CREDENTIAL_DIRECTORY)
        or any(
            inputs.get(name) != str(target)
            for name, target in _MAINTENANCE_HANDOFF_SYSTEM_INPUTS.items()
        )
        or any(
            inputs.get(name) != str(target)
            for name, target in _MAINTENANCE_HANDOFF_COMPATIBILITY_INPUTS.items()
        )
    ):
        raise ActivationPackageError(
            "maintenance handoff restoration binding is invalid"
        )
    evidence_root = Path(root_value)
    credential_evidence = (
        evidence_root / "inputs" / "systemCredentialsDirectory"
    )
    credential_directories = [
        item
        for item in directories
        if isinstance(item, Mapping)
        and item.get("sourcePath") == str(_MAINTENANCE_HANDOFF_CREDENTIAL_DIRECTORY)
    ]
    if (
        len(credential_directories) != 1
        or credential_directories[0].get("path") != str(credential_evidence)
    ):
        raise ActivationPackageError(
            "maintenance credential directory preservation is invalid"
        )
    credential_directory = credential_directories[0]
    expected: dict[
        Path,
        tuple[
            Path,
            Mapping[str, object] | None,
            Mapping[str, object] | None,
        ],
    ] = {
        _MAINTENANCE_HANDOFF_CREDENTIAL_DIRECTORY / name: (
            credential_evidence / name,
            credential_directory,
            None,
        )
        for name in _MAINTENANCE_HANDOFF_CREDENTIAL_NAMES
    }
    expected.update(
        {
            target: (evidence_root / "inputs" / name, None, None)
            for name, target in _MAINTENANCE_HANDOFF_SYSTEM_INPUTS.items()
        }
    )
    bindings = contract.get("storeBindings")
    main_binding = (
        next(
            (
                item
                for item in bindings
                if isinstance(item, Mapping) and item.get("name") == "overseer-main"
            ),
            None,
        )
        if isinstance(bindings, list)
        else None
    )
    main_identity = (
        main_binding.get("sourceIdentity")
        if isinstance(main_binding, Mapping)
        else None
    )
    if not isinstance(main_identity, Mapping):
        raise ActivationPackageError(
            "maintenance compatibility-token parent binding is invalid"
        )
    expected.update(
        {
            target: (evidence_root / "inputs" / name, None, main_identity)
            for name, target in _MAINTENANCE_HANDOFF_COMPATIBILITY_INPUTS.items()
        }
    )
    restored = 0
    removed = 0
    for target, (
        evidence,
        preserved_directory,
        expected_parent_identity,
    ) in expected.items():
        matches = [
            item
            for item in artifacts
            if isinstance(item, Mapping) and item.get("sourcePath") == str(target)
        ]
        if len(matches) > 1 or (
            matches and matches[0].get("path") != str(evidence)
        ):
            raise ActivationPackageError(
                "maintenance handoff artifact preservation is ambiguous"
            )
        if matches:
            _maintenance_restore_regular(
                evidence,
                target,
                matches[0],
                preserved_directory=preserved_directory,
                expected_parent_identity=expected_parent_identity,
            )
            restored += 1
        elif _maintenance_remove_unpreserved_handoff(
            target,
            preserved_directory=preserved_directory,
            expected_parent_identity=expected_parent_identity,
        ):
            removed += 1
    _maintenance_restore_directory_metadata(
        _MAINTENANCE_HANDOFF_CREDENTIAL_DIRECTORY,
        credential_directory,
    )
    return {
        "status": "maintenance_handoff_restored",
        "restoredFileCount": restored,
        "removedFileCount": removed,
        "credentialDirectoryMetadataRestored": True,
    }


def _run_bounded_maintenance_acceptance_check(
    contract: Mapping[str, object],
    *,
    check_name: str,
    scheduler_deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> bool | str:
    if check_name == "api":
        payload = _maintenance_api_read("/health", authenticated=False)
        return (
            payload.get("ok") is True
            and payload.get("service") == "overseer-api"
            and payload.get("psychloBridgeReady") is True
        )
    if check_name == "authenticated-ui-data":
        payload = _maintenance_api_read("/operator-dashboard")
        return isinstance(payload.get("role_focus"), Mapping) and bool(
            payload["role_focus"]
        )
    if check_name == "scheduler-freshness":
        def read_scheduler_projection(path: str) -> dict[str, object]:
            if scheduler_deadline is None:
                return _maintenance_api_read(path)
            remaining = scheduler_deadline - monotonic()
            if remaining <= 0:
                raise _MaintenanceSchedulerConvergenceDeadline(
                    "maintenance scheduler convergence deadline expired"
                )
            try:
                return _maintenance_api_read(
                    path,
                    timeout_seconds=min(MAINTENANCE_API_TIMEOUT_SECONDS, remaining),
                )
            except ActivationPackageError as error:
                if monotonic() >= scheduler_deadline:
                    raise _MaintenanceSchedulerConvergenceDeadline(
                        "maintenance scheduler convergence deadline expired"
                    ) from error
                raise

        payload = read_scheduler_projection("/collections/status")
        jobs_payload = read_scheduler_projection("/collections/jobs")
        jobs = jobs_payload.get("jobs")
        if not (
            payload.get("status") == "ok"
            and type(payload.get("job_count")) is int
            and int(payload["job_count"]) > 0
            and type(payload.get("enabled_job_count")) is int
            and int(payload["enabled_job_count"]) > 0
            and isinstance(payload.get("load_bounds"), Mapping)
            and jobs_payload.get("status") == "ok"
            and isinstance(jobs, list)
        ):
            return "reason=status-invalid"
        by_id = {
            str(item.get("id")): item
            for item in jobs
            if isinstance(item, Mapping)
        }
        failures: list[str] = []
        for job_id in _MAINTENANCE_FRESHNESS_JOB_IDS:
            item = by_id.get(job_id)
            if not isinstance(item, Mapping):
                failures.append(f"job={job_id} reason=missing")
                continue
            interval = item.get("interval_seconds")
            age = item.get("data_age_seconds")
            if item.get("enabled") is not True:
                failures.append(f"job={job_id} reason=disabled")
            elif item.get("last_outcome") != "succeeded":
                failures.append(f"job={job_id} reason=unsuccessful")
            elif type(interval) is not int or interval <= 0:
                failures.append(f"job={job_id} reason=invalid-interval")
            elif (
                isinstance(age, bool)
                or not isinstance(age, (int, float))
                or not math.isfinite(float(age))
                or age < 0
            ):
                failures.append(f"job={job_id} reason=missing-age")
            elif age > max(interval * 2, 300):
                failures.append(f"job={job_id} reason=stale")
        return "; ".join(failures) if failures else True
    if check_name == "protected-gateway-read":
        # Prove the actual TLS listener, then require a human to echo the
        # short-lived value read through an authenticated /Overseer session.
        if not _maintenance_gateway_tls_ready():
            return False
        return _maintenance_gateway_operator_challenge()
    if check_name == "psychlo-read":
        payload = _maintenance_api_read("/psychlo/status")
        return payload.get("configured") is True and isinstance(
            payload.get("projections"), Mapping
        )
    if check_name == "roadex-read":
        payload = _maintenance_api_read("/roadex/human-decisions")
        return isinstance(payload.get("items"), list) and type(
            payload.get("pending_count")
        ) is int
    if check_name == "credentials":
        return _maintenance_credentials_valid()
    if check_name == "single-writer-inventory":
        return _maintenance_single_writer_inventory_valid(contract)
    raise ActivationPackageError(
        f"maintenance acceptance check is not allowlisted: {check_name}"
    )


def _wait_for_maintenance_scheduler_freshness(
    contract: Mapping[str, object],
    *,
    timeout_seconds: float = MAINTENANCE_SCHEDULER_CONVERGENCE_TIMEOUT_SECONDS,
    poll_interval_seconds: float = MAINTENANCE_SCHEDULER_POLL_INTERVAL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> bool | str:
    """Poll read-only scheduler projections until fresh or the deadline expires."""

    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds < 0
        or isinstance(poll_interval_seconds, bool)
        or not isinstance(poll_interval_seconds, (int, float))
        or not math.isfinite(float(poll_interval_seconds))
        or poll_interval_seconds <= 0
    ):
        raise ActivationPackageError(
            "maintenance scheduler convergence bounds are invalid"
        )
    deadline = monotonic() + float(timeout_seconds)
    last_result: bool | str = "reason=deadline-expired"
    while True:
        if monotonic() >= deadline:
            return last_result
        try:
            result = _run_bounded_maintenance_acceptance_check(
                contract,
                check_name="scheduler-freshness",
                scheduler_deadline=deadline,
                monotonic=monotonic,
            )
        except _MaintenanceSchedulerConvergenceDeadline:
            return last_result
        if monotonic() > deadline:
            return last_result
        if result is True:
            return True
        last_result = result
        remaining = deadline - monotonic()
        if remaining <= 0:
            return last_result
        sleeper(min(float(poll_interval_seconds), remaining))


def _maintenance_api_read(
    path: str,
    *,
    authenticated: bool = True,
    timeout_seconds: float | None = None,
) -> dict[str, object]:
    """Perform one bounded local GET without triggering a collector."""

    from .client import OverseerApiClient

    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or "?" in path
        or "#" in path
    ):
        raise ActivationPackageError("maintenance acceptance API path is invalid")
    try:
        default_timeout_seconds = (
            MAINTENANCE_DASHBOARD_API_TIMEOUT_SECONDS
            if path == "/operator-dashboard"
            else MAINTENANCE_API_TIMEOUT_SECONDS
        )
        if timeout_seconds is None:
            timeout_seconds = default_timeout_seconds
        elif (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(float(timeout_seconds))
            or timeout_seconds <= 0
        ):
            raise ActivationPackageError(
                "maintenance acceptance API timeout is invalid"
            )
        else:
            timeout_seconds = min(
                default_timeout_seconds,
                float(timeout_seconds),
            )
        with _maintenance_api_deadline(timeout_seconds):
            client = OverseerApiClient(
                auth_token_file=("/etc/overseer/api-token" if authenticated else None),
                timeout_seconds=timeout_seconds,
                max_response_bytes=MAX_MAINTENANCE_API_RESPONSE_BYTES,
            )
            payload = client._get(path, authenticated=authenticated)
    except Exception as error:
        raise ActivationPackageError(
            "maintenance acceptance API read failed"
        ) from error
    if not isinstance(payload, dict):
        raise ActivationPackageError(
            "maintenance acceptance API response is invalid"
        )
    return payload


@contextmanager
def _maintenance_api_deadline(timeout_seconds: float):
    """Bound the entire local acceptance request, including trickled reads."""

    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer != (0.0, 0.0):
        raise ActivationPackageError(
            "maintenance acceptance API deadline timer is unavailable"
        )
    previous_handler = signal.getsignal(signal.SIGALRM)

    def deadline_expired(_signum: int, _frame: object) -> None:
        raise TimeoutError("maintenance acceptance API deadline expired")

    try:
        signal.signal(signal.SIGALRM, deadline_expired)
        signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)


def _maintenance_gateway_tls_ready() -> bool:
    """Read the authenticated gateway's public TLS login surface only."""

    import ssl
    from urllib.request import Request, urlopen

    ca_file = "/etc/overseer/protected-gateway-ca.crt"
    try:
        context = ssl.create_default_context(cafile=ca_file)
        request = Request(
            "https://roadex.home.arpa:9443/",
            headers={"User-Agent": "Overseer-maintenance-acceptance/1"},
            method="GET",
        )
        with urlopen(request, timeout=5.0, context=context) as response:
            if response.status != 200:
                return False
            body = response.read(256 * 1024 + 1)
    except Exception:
        return False
    return (
        len(body) <= 256 * 1024
        and b"<title>Protected Service Gateway</title>" in body
        and b'<form method="post" action="/auth/login"' in body
    )


def _maintenance_gateway_operator_challenge() -> bool:
    """Require one bounded human-confirmed read through the existing gateway."""

    challenge = secrets.token_hex(16)
    path = _MAINTENANCE_GATEWAY_CHALLENGE_PATH
    created = False
    try:
        root_uid, _root_gid = _activation_root_identity()
        parent_metadata = path.parent.lstat()
        if (
            path.parent.is_symlink()
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != root_uid
            or parent_metadata.st_gid != APPROVED_OVERSEER_GID
            or stat.S_IMODE(parent_metadata.st_mode) != 0o750
        ):
            return False
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            stale, stale_metadata = _stable_read(path)
            if (
                stale_metadata.st_uid != root_uid
                or stat.S_IMODE(stale_metadata.st_mode) != 0o444
                or not re.fullmatch(rb"[0-9a-f]{32}\n", stale)
            ):
                return False
            path.unlink()
            _fsync_package_directory(path.parent)
        _write_new(path, (challenge + "\n").encode("ascii"), 0o444)
        created = True
        entered = input(
            "Open the authenticated Protected Gateway Overseer dashboard, "
            "copy maintenance_gateway_challenge, and enter it here before "
            "this command times out: "
        ).strip()
        return secrets.compare_digest(entered, challenge)
    except (EOFError, KeyboardInterrupt, OSError):
        return False
    finally:
        if created:
            try:
                path.unlink()
                _fsync_package_directory(path.parent)
            except FileNotFoundError:
                pass
            except OSError:
                return False


def _maintenance_credentials_valid() -> bool:
    root_uid, root_gid = _activation_root_identity()
    expected = {
        "/etc/overseer/api-token": (root_uid, root_gid, 0o600),
        "/etc/overseer/psychlo-peer-secret": (root_uid, root_gid, 0o600),
        "/etc/overseer/roadex-project-human-thread-secret": (
            root_uid,
            root_gid,
            0o600,
        ),
        "/etc/overseer/psychlo-project-bindings.json": (
            root_uid,
            root_gid,
            0o644,
        ),
        "/etc/overseer/protected-gateway-ca.crt": (
            root_uid,
            root_gid,
            0o644,
        ),
        "/etc/overseer/admin-approval-verifier.json": (
            APPROVED_OVERSEER_UID,
            APPROVED_OVERSEER_GID,
            0o600,
        ),
        "/etc/overseer/roadex-fixture-approval-verifier.json": (
            APPROVED_OVERSEER_UID,
            APPROVED_OVERSEER_GID,
            0o600,
        ),
        "/etc/overseer/admin-ticket-private-key": (
            APPROVED_OVERSEER_UID,
            APPROVED_OVERSEER_GID,
            0o600,
        ),
        "/etc/overseer/admin-executor-public-key": (
            root_uid,
            root_gid,
            0o644,
        ),
    }
    for raw_path, expected_metadata in expected.items():
        path = Path(raw_path)
        try:
            metadata = path.lstat()
        except OSError:
            return False
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
            != expected_metadata
        ):
            return False
    return True


def _maintenance_success_user_unit_inventory_valid() -> bool:
    """Verify every legacy/continuing user unit against the successor profile."""

    exact = {
        "overseer-psychlo-coordination-tick.timer": ("not-found", "inactive", ""),
        "overseer-psychlo-usage.timer": ("loaded", "inactive", "disabled"),
        "overseer-quark-scheduler.timer": ("loaded", "active", "enabled"),
        "overseer-codex-usage-snapshot.timer": ("loaded", "active", "enabled"),
        "overseer-psychlo-coordination-tick.service": ("not-found", "inactive", ""),
        "overseer-psychlo-cycle.service": ("loaded", "inactive", "static"),
        "overseer-psychlo-meter.service": ("loaded", "inactive", "static"),
        "overseer-psychlo-usage.service": ("loaded", "inactive", "static"),
        "overseer-codex-usage-mcp.service": ("loaded", "active", "enabled"),
        "overseer-api.service": ("loaded", "inactive", "disabled"),
        "overseer.service": ("loaded", "inactive", "disabled"),
    }
    timer_oneshots = {
        "overseer-quark-scheduler.service",
        "overseer-codex-usage-snapshot.service",
    }
    try:
        for unit in _MAINTENANCE_WRITER_UNITS:
            state = _maintenance_user_unit_state(unit)
            observed = (
                state["LoadState"],
                state["ActiveState"],
                state["UnitFileState"],
            )
            if unit in timer_oneshots:
                if observed not in {
                    ("loaded", "inactive", "static"),
                    ("loaded", "active", "static"),
                }:
                    return False
            elif observed != exact.get(unit):
                return False
    except (KeyError, ActivationPackageError):
        return False
    return True


def _maintenance_single_writer_inventory_valid(
    contract: Mapping[str, object],
) -> bool:
    bindings = contract.get("storeBindings")
    if not isinstance(bindings, list) or len(bindings) != 3:
        return False
    root_uid, _root_gid = _activation_root_identity()
    for binding in bindings:
        if not isinstance(binding, Mapping):
            return False
        source = Path(str(binding.get("sourceDb", "")))
        destination = Path(str(binding.get("destinationDb", "")))
        try:
            source_metadata = source.lstat()
            source_parent_metadata = source.parent.lstat()
            destination_metadata = destination.lstat()
        except OSError:
            return False
        if (
            source.is_symlink()
            or destination.is_symlink()
            or not stat.S_ISREG(source_metadata.st_mode)
            or not stat.S_ISREG(destination_metadata.st_mode)
            or source_metadata.st_uid != root_uid
            or stat.S_IMODE(source_metadata.st_mode) != 0o400
            or source_parent_metadata.st_uid != root_uid
            or stat.S_IMODE(source_parent_metadata.st_mode) != 0o555
            or (
                destination_metadata.st_uid,
                destination_metadata.st_gid,
                stat.S_IMODE(destination_metadata.st_mode),
            )
            != (APPROVED_OVERSEER_UID, APPROVED_OVERSEER_GID, 0o600)
        ):
            return False
        identities: list[tuple[int, int]] = []
        for artifact in _legacy_store_paths(source):
            try:
                metadata = artifact.lstat()
            except FileNotFoundError:
                continue
            except OSError:
                return False
            if artifact.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                return False
            identities.append((metadata.st_dev, metadata.st_ino))
        if identities and _legacy_inode_activity(
            tuple(identities),
            include_open_files=True,
        ):
            return False
    deferred = contract.get("deferredStoreBindings")
    if (
        not isinstance(deferred, list)
        or len(deferred) != 1
        or not isinstance(deferred[0], Mapping)
        or not _maintenance_store_binding_identity_valid(deferred[0])
    ):
        return False
    try:
        if not _maintenance_success_user_unit_inventory_valid():
            return False
        expected_system = (
            "overseer-runtime.service",
            "overseer-api.service",
            "overseer-admin-executor.socket",
            "overseer-codex-user-bridge.socket",
        )
        for unit in expected_system:
            result = subprocess.run(
                [
                    "/usr/bin/systemctl",
                    "show",
                    "--no-pager",
                    "--property=LoadState",
                    "--property=ActiveState",
                    unit,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
            )
            if (
                result.returncode != 0
                or "LoadState=loaded" not in result.stdout.splitlines()
                or "ActiveState=active" not in result.stdout.splitlines()
            ):
                return False
    except (OSError, subprocess.TimeoutExpired, ActivationPackageError):
        return False
    return True


def verify_maintenance_acceptance(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Run the exact sealed bounded maintenance acceptance checks."""

    package = Path(package_root).resolve()
    _require_maintenance_active_sealed_command(
        package_root,
        command_name="verify-maintenance-acceptance",
        expected_options={"--package-root": str(package)},
    )
    contract = _read_maintenance_contract_file(package)
    checks = contract.get("acceptanceChecks")
    if checks != list(_MAINTENANCE_ACCEPTANCE_CHECKS):
        raise ActivationPackageError("maintenance acceptance contract is invalid")
    results: dict[str, bool] = {}
    for check_name in _MAINTENANCE_ACCEPTANCE_CHECKS:
        result = (
            _wait_for_maintenance_scheduler_freshness(contract)
            if check_name == "scheduler-freshness"
            else _run_bounded_maintenance_acceptance_check(
                contract,
                check_name=check_name,
            )
        )
        if result is not True:
            detail = f": {result}" if isinstance(result, str) else ""
            raise ActivationPackageError(
                f"maintenance acceptance check failed: {check_name}{detail}"
            )
        results[check_name] = True
    evidence_root = contract.get("evidenceRoot")
    if not isinstance(evidence_root, str) or not evidence_root.startswith("/"):
        raise ActivationPackageError("maintenance acceptance evidence root is invalid")
    preservation_root = Path(evidence_root)
    if preservation_root.parent == preservation_root:
        raise ActivationPackageError("maintenance acceptance evidence root is invalid")
    report = {
        "schemaVersion": "overseer.maintenance-acceptance.v1",
        "status": "accepted",
        "planDigest": _sha256(_canonical(contract)),
        "checks": results,
    }
    report_path = preservation_root.with_name("acceptance-report.json")
    payload = _canonical(report) + b"\n"
    try:
        report_path.lstat()
    except FileNotFoundError:
        _write_new(report_path, payload, 0o600)
    except OSError as error:
        raise ActivationPackageError(
            "maintenance acceptance report could not be inspected"
        ) from error
    else:
        existing, metadata = _stable_read(report_path)
        root_uid, root_gid = _activation_root_identity()
        if (
            existing != payload
            or (metadata.st_uid, metadata.st_gid) != (root_uid, root_gid)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ActivationPackageError(
                "maintenance acceptance report conflicts with this plan"
            )
    return report


def _execute_maintenance_contract_command(
    command: list[str], timeout_seconds: int
) -> int:
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
        raise ActivationPackageError("maintenance command timeout is invalid")
    return _execute_contract_command(command, timeout_seconds=timeout_seconds)


def execute_approved_maintenance_window(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Execute only the separately approved sealed maintenance contract."""

    with _activation_execution_lock():
        _require_root_activation()
        package = Path(package_root).resolve()
        approval = _load_maintenance_approval(package)
        digest = str(approval["packageDigest"])
        contract = _sealed_maintenance_contract(package, package_digest=digest)
        plan_digest = maintenance_plan_digest(contract)
        try:
            validate_maintenance_approval(
                approval,
                str(package),
                digest,
                plan_digest,
                False,
            )
        except ValueError as error:
            raise ActivationPackageError("maintenance approval binding is invalid") from error

        prior = _load_maintenance_state()
        if prior is not None:
            if (
                prior.get("packageDigest") != digest
                or prior.get("planDigest") != plan_digest
            ):
                raise ActivationPackageError("maintenance runner state binding is invalid")
            if prior.get("status") == "complete":
                return {
                    "status": "complete",
                    "packageDigest": digest,
                    "planDigest": plan_digest,
                    "replayed": True,
                }
            preflight_command = contract["stages"][0]["commands"][0]
            retryable_pre_stop = (
                prior.get("status")
                in {
                    "before_command",
                    "after_command",
                    "failed_before_stopWriters",
                }
                and prior.get("stage") == "preflight"
                and prior.get("commandIndex") == 0
                and prior.get("commandDigest")
                == _sha256(_canonical(preflight_command))
                and prior.get("writersStopped") is False
            )
            if not retryable_pre_stop:
                raise ActivationPackageError("maintenance runner state already exists")

        def checkpoint(state: dict[str, object]) -> None:
            _write_maintenance_state(
                {
                    **state,
                    "planDigest": plan_digest,
                }
            )

        try:
            execute_maintenance_contract(
                contract,
                digest,
                _execute_maintenance_contract_command,
                checkpoint,
            )
        except ActivationPackageError:
            raise
        except BaseException as error:
            raise ActivationPackageError("maintenance window execution failed") from error
        return {
            "status": "complete",
            "packageDigest": digest,
            "planDigest": plan_digest,
            "replayed": False,
        }


def execute_approved_maintenance_rollback(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    """Execute sealed maintenance rollback for one matching nonterminal state."""

    package = Path(package_root).resolve()
    if _load_maintenance_state() is None:
        raise ActivationPackageError("maintenance state is required for rollback")
    with _activation_execution_lock():
        _require_root_activation()
        state = _load_maintenance_state()
        if state is None:
            raise ActivationPackageError("maintenance state is required for rollback")
        retry_approval: dict[str, object] | None = None
        if state.get("status") == "rollback_failed":
            retry_approval = _load_maintenance_rollback_retry_approval(
                package,
                state,
            )
        if state.get("status") in {
            "complete",
            "rolled_back",
            "failed_before_stopWriters",
        }:
            if state.get("status") == "rolled_back":
                return {
                    "status": "rolled_back",
                    "packageDigest": state.get("packageDigest"),
                    "replayed": True,
                }
            raise ActivationPackageError("maintenance state is not eligible for rollback")
        if state.get("writersStopped") is not True:
            raise ActivationPackageError(
                "maintenance rollback requires a completed writer-stop boundary"
            )
        approval = _load_maintenance_approval(package)
        digest = str(approval["packageDigest"])
        contract = _sealed_maintenance_contract(package, package_digest=digest)
        plan_digest = maintenance_plan_digest(contract)
        if (
            state.get("packageDigest") != digest
            or state.get("planDigest") != plan_digest
        ):
            raise ActivationPackageError("maintenance state binding is invalid")
        try:
            validate_maintenance_approval(
                approval,
                str(package),
                digest,
                plan_digest,
                False,
            )
        except ValueError as error:
            raise ActivationPackageError("maintenance approval binding is invalid") from error

        retry_approval_record: Path | None = None
        if retry_approval is not None:
            retry_approval_record = _consume_maintenance_rollback_retry_approval(
                package,
                state,
                retry_approval,
            )
            _write_maintenance_state(
                {
                    "schemaVersion": MAINTENANCE_RUNNER_STATE_SCHEMA,
                    "packageDigest": digest,
                    "planDigest": plan_digest,
                    "status": "rollback_retry_authorized",
                    "stage": state.get("stage"),
                    "writersStopped": True,
                    "failedStateDigest": retry_approval["failedStateDigest"],
                    "retryApprovalRecord": str(retry_approval_record),
                }
            )

        original_stage = state.get("stage")
        use_early_rollback = original_stage in {
            "stopWriters",
            "proveQuiescence",
            "preserveState",
            "installRelease",
            "earlyRollback",
        }
        command_field = (
            "earlyRollbackCommands" if use_early_rollback else "rollbackCommands"
        )
        timeout_field = (
            "earlyRollbackTimeoutSeconds"
            if use_early_rollback
            else "rollbackTimeoutSeconds"
        )
        start_field = (
            "earlyRollbackStartIndex" if use_early_rollback else "rollbackStartIndex"
        )
        window_field = (
            "earlyRollbackWindowTimeoutSeconds"
            if use_early_rollback
            else "rollbackWindowTimeoutSeconds"
        )
        rollback_stage = "earlyRollback" if use_early_rollback else "rollback"
        rollback_commands = contract[command_field]
        rollback_timeouts = contract[timeout_field]
        rollback_start_index = int(contract[start_field])
        rollback_error: BaseException | None = None
        rollback_deadline = time.monotonic() + int(contract[window_field])
        for index, command in enumerate(rollback_commands):
            if rollback_error is not None and index >= rollback_start_index:
                break
            checkpoint = {
                "schemaVersion": MAINTENANCE_RUNNER_STATE_SCHEMA,
                "packageDigest": digest,
                "planDigest": plan_digest,
                "status": "before_rollback_command",
                "stage": rollback_stage,
                "commandIndex": index,
                "commandDigest": _sha256(_canonical(command)),
                "writersStopped": True,
            }
            _write_maintenance_state(checkpoint)
            try:
                remaining = int(rollback_deadline - time.monotonic())
                if remaining < 1:
                    raise ActivationPackageError(
                        "maintenance rollback exceeded its sealed deadline"
                    )
                result = _execute_maintenance_contract_command(
                    list(command), min(int(rollback_timeouts[index]), remaining)
                )
                if type(result) is int and result != 0:
                    raise ActivationPackageError("maintenance rollback command returned nonzero status")
            except BaseException as error:
                if rollback_error is None:
                    rollback_error = error
                continue
            _write_maintenance_state(
                {
                    **checkpoint,
                    "status": "after_rollback_command",
                }
            )
        if rollback_error is not None:
            _write_maintenance_state(
                {
                    "schemaVersion": MAINTENANCE_RUNNER_STATE_SCHEMA,
                    "packageDigest": digest,
                    "planDigest": plan_digest,
                    "status": "rollback_failed",
                    "stage": rollback_stage,
                    "writersStopped": True,
                    "failure": type(rollback_error).__name__,
                }
            )
            if isinstance(rollback_error, ActivationPackageError):
                raise rollback_error
            raise ActivationPackageError("maintenance rollback command failed") from rollback_error
        _write_maintenance_state(
            {
                "schemaVersion": MAINTENANCE_RUNNER_STATE_SCHEMA,
                "packageDigest": digest,
                "planDigest": plan_digest,
                "status": "rolled_back",
                "stage": rollback_stage,
                "writersStopped": True,
            }
        )
        return {
            "status": "rolled_back",
            "packageDigest": digest,
            "replayed": False,
            "retryApproved": retry_approval is not None,
            "retryApprovalRecord": (
                None
                if retry_approval_record is None
                else str(retry_approval_record)
            ),
        }


def execute_approved_staging_canary(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    with _activation_execution_lock():
        return _execute_approved_staging_canary_locked(package_root)


def execute_approved_cutover(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    with _activation_execution_lock():
        return _execute_approved_cutover_locked(package_root)


def execute_approved_rollback(
    package_root: str | os.PathLike[str],
) -> dict[str, object]:
    with _activation_execution_lock():
        return _execute_approved_rollback_locked(package_root)


def _canary_attestation_path(package_digest: str) -> Path:
    return Path(f"/var/lib/overseer-executor/canary-{package_digest}.json")


def _approved_package_retirement_archive_root() -> Path:
    """Return the private namespace for retired approved packages."""

    return Path("/var/lib/overseer-executor/retired-packages")


def _retirement_digest(value: str, *, label: str) -> str:
    if len(value) != 64 or set(value) - _HEX:
        raise ActivationPackageError(f"{label} is invalid")
    return value


def _retirement_require_absent(path: Path, *, label: str) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise ActivationPackageError(f"{label} could not be inspected") from error
    if path.is_symlink():
        raise ActivationPackageError(f"{label} is an unsafe symlink")
    raise ActivationPackageError(f"{label} exists")


def _retirement_validate_private_directory(path: Path, *, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ActivationPackageError(f"{label} is unavailable") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ActivationPackageError(f"{label} is unsafe")
    return metadata


def _retirement_load_root_record(
    path: Path,
    *,
    label: str,
) -> tuple[dict[str, object], bytes, os.stat_result]:
    try:
        raw, metadata = _stable_read(path)
        document = json.loads(raw)
    except (
        ActivationPackageError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise ActivationPackageError(f"{label} is unavailable or invalid") from error
    root_uid, root_gid = _activation_root_identity()
    if (
        metadata.st_uid != root_uid
        or metadata.st_gid != root_gid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not isinstance(document, dict)
    ):
        raise ActivationPackageError(f"{label} metadata is invalid")
    return document, raw, metadata


def _retirement_inode_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
    )


def _retirement_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _retirement_observe_artifact(
    path: Path,
    *,
    name: str,
    kind: str,
    package_digest: str | None = None,
    owner_identity: tuple[int, int] | None = None,
) -> dict[str, object]:
    """Return a stable, root-owned identity and content inventory."""

    if path.name != name or _safe_relative(name) != name or "/" in name:
        raise ActivationPackageError("retirement artifact name is unsafe")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ActivationPackageError(
            f"retirement artifact is unavailable: {name}"
        ) from error
    expected_uid, expected_gid = (
        _activation_root_identity()
        if owner_identity is None
        else owner_identity
    )
    base = {
        "name": name,
        "kind": kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "links": metadata.st_nlink,
    }
    if (
        path.is_symlink()
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
    ):
        raise ActivationPackageError(f"retirement artifact is unsafe: {name}")
    if kind == "file":
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationPackageError(f"retirement artifact is unsafe: {name}")
        observed = _stream_hash_regular(path, label=f"retirement artifact {name}")
        after = path.lstat()
        if _retirement_inode_identity(after) != _retirement_inode_identity(metadata):
            raise ActivationPackageError(
                f"retirement artifact changed while inventorying: {name}"
            )
        if observed["mode"] != "0600":
            raise ActivationPackageError(
                f"retirement record mode is unsafe: {name}"
            )
        return {**base, "sha256": observed["sha256"], "size": observed["size"]}
    if kind not in {"directory", "package"}:
        raise ActivationPackageError("retirement artifact kind is invalid")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ActivationPackageError(f"retirement artifact is unsafe: {name}")
    directories: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    for directory, child_directories, child_files in os.walk(
        path,
        followlinks=False,
    ):
        current = Path(directory)
        current_metadata = current.lstat()
        if (
            current.is_symlink()
            or not stat.S_ISDIR(current_metadata.st_mode)
            or current_metadata.st_uid != expected_uid
            or current_metadata.st_gid != expected_gid
            or stat.S_IMODE(current_metadata.st_mode) & 0o022
        ):
            raise ActivationPackageError(
                f"retirement artifact directory is unsafe: {name}"
            )
        relative = (
            "."
            if current == path
            else _safe_relative(current.relative_to(path).as_posix())
        )
        directories.append(
            {
                "path": relative,
                "mode": f"{stat.S_IMODE(current_metadata.st_mode):04o}",
                "uid": current_metadata.st_uid,
                "gid": current_metadata.st_gid,
                "device": current_metadata.st_dev,
                "inode": current_metadata.st_ino,
                "links": current_metadata.st_nlink,
            }
        )
        for child_name in child_directories:
            child = current / child_name
            if child.is_symlink():
                raise ActivationPackageError(
                    f"retirement artifact contains a symlink: {name}"
                )
        for child_name in child_files:
            child = current / child_name
            relative_file = _safe_relative(child.relative_to(path).as_posix())
            child_before = child.lstat()
            child_details = _stream_hash_regular(
                child,
                label=f"retirement artifact {name}",
            )
            child_after = child.lstat()
            if (
                _retirement_inode_identity(child_before)
                != _retirement_inode_identity(child_after)
                or child_details["uid"] != expected_uid
                or child_details["gid"] != expected_gid
                or child_details["links"] != 1
                or int(str(child_details["mode"]), 8) & 0o022
            ):
                raise ActivationPackageError(
                    f"retirement artifact file is unsafe: {name}"
                )
            files.append(
                {
                    "path": relative_file,
                    "device": child_after.st_dev,
                    "inode": child_after.st_ino,
                    **child_details,
                }
            )
        current_after = current.lstat()
        if _retirement_inode_identity(current_after) != _retirement_inode_identity(
            current_metadata
        ):
            raise ActivationPackageError(
                f"retirement artifact changed while inventorying: {name}"
            )
    directories.sort(key=lambda item: str(item["path"]))
    files.sort(key=lambda item: str(item["path"]))
    root_after = path.lstat()
    if _retirement_inode_identity(root_after) != _retirement_inode_identity(metadata):
        raise ActivationPackageError(
            f"retirement artifact changed while inventorying: {name}"
        )
    inventory = {"directories": directories, "files": files}
    result = {
        **base,
        **inventory,
        "treeDigest": _sha256(_canonical(inventory)),
        "fileCount": len(files),
    }
    if kind == "package":
        if package_digest is None:
            raise ActivationPackageError("retirement package digest is required")
        verified = verify_activation_package(path, package_digest)
        result["packageDigest"] = package_digest
        result["packageFileCount"] = verified["fileCount"]
    return result


def _retirement_record_artifact(
    path: Path,
    *,
    kind: str,
    package_digest: str | None = None,
    expected_document: Mapping[str, object] | None = None,
) -> dict[str, object]:
    record_metadata: os.stat_result | None = None
    record_raw: bytes | None = None
    if expected_document is not None:
        observed_document, record_raw, record_metadata = _retirement_load_root_record(
            path,
            label=f"retirement record {path.name}",
        )
        if observed_document != dict(expected_document):
            raise ActivationPackageError(
                f"retirement record changed before inventory: {path.name}"
            )
    result = {
        "sourcePath": str(path),
        **_retirement_observe_artifact(
            path,
            name=path.name,
            kind=kind,
            package_digest=package_digest,
        ),
    }
    if (
        record_metadata is not None
        and record_raw is not None
        and (
            result.get("device") != record_metadata.st_dev
            or result.get("inode") != record_metadata.st_ino
            or result.get("sha256") != _sha256(record_raw)
            or result.get("size") != len(record_raw)
        )
    ):
        raise ActivationPackageError(
            f"retirement record changed while inventorying: {path.name}"
        )
    return result


def _retirement_successor_package_evidence(
    package: Path,
    *,
    package_digest: str,
) -> dict[str, object]:
    validated = _validate_existing_package_destination(package)
    if validated != package:
        raise ActivationPackageError("successor package path changed")
    try:
        metadata = package.lstat()
    except OSError as error:
        raise ActivationPackageError("successor package is unavailable") from error
    return _retirement_observe_artifact(
        package,
        name=package.name,
        kind="package",
        package_digest=package_digest,
        owner_identity=(metadata.st_uid, metadata.st_gid),
    )


def _retirement_verify_successor_package(
    package: Path,
    *,
    package_digest: str,
    expected: object,
) -> None:
    if not isinstance(expected, Mapping):
        raise ActivationPackageError("successor package evidence is invalid")
    observed = _retirement_successor_package_evidence(
        package,
        package_digest=package_digest,
    )
    if observed != dict(expected):
        raise ActivationPackageError("successor package identity or content drifted")


def _retirement_verify_artifact(
    path: Path,
    expected: Mapping[str, object],
) -> None:
    name = expected.get("name")
    kind = expected.get("kind")
    if not isinstance(name, str) or not isinstance(kind, str):
        raise ActivationPackageError("retirement intent artifact is invalid")
    package_digest = expected.get("packageDigest")
    if package_digest is not None and not isinstance(package_digest, str):
        raise ActivationPackageError("retirement intent package digest is invalid")
    observed = _retirement_observe_artifact(
        path,
        name=name,
        kind=kind,
        package_digest=package_digest,
    )
    recorded = {key: value for key, value in expected.items() if key != "sourcePath"}
    if observed != recorded:
        raise ActivationPackageError(f"retirement artifact drifted: {name}")


def _retirement_fsync_private_directory(path: Path, *, label: str) -> None:
    before = _retirement_validate_private_directory(path, label=label)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if _retirement_directory_identity(os.fstat(descriptor)) != (
            _retirement_directory_identity(before)
        ):
            raise ActivationPackageError(f"{label} changed before fsync")
        os.fsync(descriptor)
        lexical = path.lstat()
        if _retirement_directory_identity(os.fstat(descriptor)) != (
            _retirement_directory_identity(lexical)
        ):
            raise ActivationPackageError(f"{label} changed during fsync")
    finally:
        os.close(descriptor)


def _retirement_rename_entry_no_replace(source: Path, destination: Path) -> None:
    """Rename one entry inside a validated private directory and fsync it."""

    if (
        source.parent != destination.parent
        or _safe_relative(source.name) != source.name
        or _safe_relative(destination.name) != destination.name
        or "/" in source.name
        or "/" in destination.name
    ):
        raise ActivationPackageError("retirement publication path is unsafe")
    parent = source.parent
    before = _retirement_validate_private_directory(
        parent,
        label="retirement publication directory",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(parent, flags)
    try:
        if _retirement_directory_identity(os.fstat(descriptor)) != (
            _retirement_directory_identity(before)
        ):
            raise ActivationPackageError(
                "retirement publication directory changed before rename"
            )
        try:
            source_metadata = os.stat(
                source.name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ActivationPackageError(
                "retirement publication source is unavailable"
            ) from error
        if stat.S_ISLNK(source_metadata.st_mode):
            raise ActivationPackageError(
                "retirement publication source is an unsafe symlink"
            )
        try:
            os.stat(
                destination.name,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ActivationPackageError(
                "retirement publication destination could not be inspected"
            ) from error
        else:
            raise ActivationPackageError(
                "retirement publication destination already exists"
            )
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renameat2 = libc.renameat2
        except AttributeError as error:
            raise ActivationPackageError(
                "atomic no-replace retirement publication is unavailable"
            ) from error
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            descriptor,
            os.fsencode(source.name),
            descriptor,
            os.fsencode(destination.name),
            1,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(
                    error_number,
                    "retirement publication destination already exists",
                    destination,
                )
            raise OSError(error_number, os.strerror(error_number), destination)
        if _retirement_directory_identity(os.fstat(descriptor)) != (
            _retirement_directory_identity(before)
        ):
            raise ActivationPackageError(
                "retirement publication directory changed during rename"
            )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _retirement_rename_artifact_no_replace(
    source: Path,
    destination: Path,
    expected: Mapping[str, object],
) -> None:
    """Rename one exact inode between validated root-owned directories."""

    source_parent = source.parent
    destination_parent = destination.parent
    source_parent_metadata = _retirement_validate_private_directory(
        source_parent,
        label="retirement source directory",
    )
    destination_parent_metadata = _retirement_validate_private_directory(
        destination_parent,
        label="retirement destination directory",
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    source_descriptor = os.open(source_parent, flags)
    destination_descriptor = os.open(destination_parent, flags)
    try:
        if (
            _retirement_directory_identity(os.fstat(source_descriptor))
            != _retirement_directory_identity(source_parent_metadata)
            or _retirement_directory_identity(os.fstat(destination_descriptor))
            != _retirement_directory_identity(destination_parent_metadata)
        ):
            raise ActivationPackageError(
                "retirement artifact parent changed before rename"
            )
        try:
            source_metadata = os.stat(
                source.name,
                dir_fd=source_descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ActivationPackageError(
                "retirement artifact changed before rename"
            ) from error
        if (
            source_metadata.st_dev != expected.get("device")
            or source_metadata.st_ino != expected.get("inode")
            or f"{stat.S_IMODE(source_metadata.st_mode):04o}"
            != expected.get("mode")
            or source_metadata.st_uid != expected.get("uid")
            or source_metadata.st_gid != expected.get("gid")
            or source_metadata.st_nlink != expected.get("links")
        ):
            raise ActivationPackageError(
                "retirement artifact identity changed before rename"
            )
        try:
            os.stat(
                destination.name,
                dir_fd=destination_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ActivationPackageError(
                "retirement destination could not be inspected"
            ) from error
        else:
            raise ActivationPackageError("retirement destination already exists")
        libc = ctypes.CDLL(None, use_errno=True)
        try:
            renameat2 = libc.renameat2
        except AttributeError as error:
            raise ActivationPackageError(
                "atomic no-replace retirement move is unavailable"
            ) from error
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            source_descriptor,
            os.fsencode(source.name),
            destination_descriptor,
            os.fsencode(destination.name),
            1,
        )
        if result != 0:
            error_number = ctypes.get_errno()
            if error_number == errno.EEXIST:
                raise FileExistsError(
                    error_number,
                    "retirement destination already exists",
                    destination,
                )
            raise OSError(error_number, os.strerror(error_number), destination)
        if (
            _retirement_directory_identity(os.fstat(source_descriptor))
            != _retirement_directory_identity(source_parent_metadata)
            or _retirement_directory_identity(os.fstat(destination_descriptor))
            != _retirement_directory_identity(destination_parent_metadata)
        ):
            raise ActivationPackageError(
                "retirement artifact parent changed during rename"
            )
    finally:
        os.close(destination_descriptor)
        os.close(source_descriptor)


def _retirement_active_retry_approvals_absent(executor_root: Path) -> None:
    for path in sorted(executor_root.glob("approved-maintenance-rollback-retry-*.json")):
        if path.is_symlink():
            raise ActivationPackageError(
                "active maintenance rollback retry approval is an unsafe symlink"
            )
        raise ActivationPackageError(
            "active maintenance rollback retry approval exists"
        )


def _retirement_bound_consumed_retries(
    executor_root: Path,
    *,
    package: Path,
    package_digest: str,
    plan_digest: str,
) -> list[Path]:
    result: list[Path] = []
    for path in sorted(
        executor_root.glob("consumed-approved-maintenance-rollback-retry-*.json")
    ):
        document, _raw, _metadata = _retirement_load_root_record(
            path,
            label="consumed maintenance rollback retry approval",
        )
        if (
            document.get("schemaVersion")
            == MAINTENANCE_ROLLBACK_RETRY_APPROVAL_SCHEMA
            and document.get("scope")
            == "maintenance-rollback-retry-for-this-failed-state-only"
            and document.get("packageRoot") == str(package)
            and document.get("packageDigest") == package_digest
            and document.get("planDigest") == plan_digest
            and isinstance(document.get("failedStateDigest"), str)
        ):
            result.append(path)
    return result


def _retirement_health_preflight() -> dict[str, object]:
    health = _maintenance_api_read("/health", authenticated=False)
    required = {
        "ok": True,
        "psychloBridgeReady": True,
        "service": "overseer-api",
    }
    if any(health.get(key) != value for key, value in required.items()):
        raise ActivationPackageError("Overseer health is not ready for retirement")
    return required


def _retirement_fresh_intent(
    successor_package: Path,
    *,
    successor_digest: str,
    predecessor_digest: str,
    plan_digest: str,
    final_archive: Path,
) -> dict[str, object]:
    package = _validate_existing_package_destination(APPROVED_EXECUTION_PACKAGE)
    executor_root = package.parent
    package_approval = _load_activation_approval(package)
    if package_approval.get("packageDigest") != predecessor_digest:
        raise ActivationPackageError(
            "predecessor package digest does not match the imported approval"
        )
    maintenance_approval = _load_maintenance_approval(package)
    if maintenance_approval.get("packageDigest") != predecessor_digest:
        raise ActivationPackageError(
            "predecessor package digest does not match maintenance approval"
        )
    if maintenance_approval.get("planDigest") != plan_digest:
        raise ActivationPackageError(
            "maintenance plan digest does not match maintenance approval"
        )
    state = _load_maintenance_state()
    if (
        state is None
        or state.get("schemaVersion") != MAINTENANCE_RUNNER_STATE_SCHEMA
        or state.get("packageDigest") != predecessor_digest
        or state.get("planDigest") != plan_digest
        or state.get("status") != "rolled_back"
        or state.get("stage") not in {"rollback", "earlyRollback"}
        or state.get("writersStopped") is not True
    ):
        raise ActivationPackageError(
            "maintenance runner state is not exactly rolled back"
        )
    _retirement_require_absent(
        _activation_state_path(),
        label="activation runner state",
    )
    for phase in sorted(ACTIVATION_PHASES):
        _retirement_require_absent(
            _activation_phase_approval_record_path(phase),
            label=f"{phase} phase approval",
        )
    _retirement_active_retry_approvals_absent(executor_root)
    contract = _sealed_maintenance_contract(
        package,
        package_digest=predecessor_digest,
    )
    release_digest = contract.get("releaseManifestDigest")
    if (
        not isinstance(release_digest, str)
        or len(release_digest) != 64
        or set(release_digest) - _HEX
    ):
        raise ActivationPackageError("maintenance release manifest digest is invalid")
    maintenance_workspace = executor_root / f"maintenance-{release_digest}"
    if contract.get("evidenceRoot") != str(maintenance_workspace / "preserved"):
        raise ActivationPackageError(
            "maintenance evidence root is outside the bound workspace"
        )
    writer_unit_baseline = contract.get("writerUnitBaseline")
    successor_unit_baseline = contract.get("successorUnitBaseline")
    _maintenance_writer_unit_preflight(writer_unit_baseline)
    _maintenance_successor_unit_preflight(successor_unit_baseline)
    health = _retirement_health_preflight()
    successor_package_evidence = _retirement_successor_package_evidence(
        successor_package,
        package_digest=successor_digest,
    )
    artifacts = [
        _retirement_record_artifact(
            package,
            kind="package",
            package_digest=predecessor_digest,
        ),
        _retirement_record_artifact(
            _activation_approval_record_path(),
            kind="file",
            expected_document=package_approval,
        ),
        _retirement_record_artifact(
            _maintenance_approval_record_path(),
            kind="file",
            expected_document=maintenance_approval,
        ),
        _retirement_record_artifact(
            _maintenance_state_path(),
            kind="file",
            expected_document=state,
        ),
        _retirement_record_artifact(
            maintenance_workspace,
            kind="directory",
        ),
    ]
    destination_namespace = executor_root / f"destination-namespace-before-{plan_digest}"
    canary_path = _canary_attestation_path(predecessor_digest)
    for optional_path, kind in (
        (destination_namespace, "directory"),
        (canary_path, "file"),
    ):
        try:
            optional_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ActivationPackageError(
                "optional predecessor artifact could not be inspected"
            ) from error
        artifacts.append(_retirement_record_artifact(optional_path, kind=kind))
    for retry in _retirement_bound_consumed_retries(
        executor_root,
        package=package,
        package_digest=predecessor_digest,
        plan_digest=plan_digest,
    ):
        artifacts.append(_retirement_record_artifact(retry, kind="file"))
    artifacts.sort(key=lambda item: str(item["name"]))
    names = [str(item["name"]) for item in artifacts]
    if len(names) != len(set(names)):
        raise ActivationPackageError("retirement artifact names are ambiguous")
    return {
        "schemaVersion": APPROVED_PACKAGE_RETIREMENT_INTENT_SCHEMA,
        "status": "prepared",
        "predecessorPackageDigest": predecessor_digest,
        "successorPackageDigest": successor_digest,
        "maintenancePlanDigest": plan_digest,
        "releaseManifestDigest": release_digest,
        "successorPackageRoot": str(successor_package),
        "successorPackageEvidence": successor_package_evidence,
        "archiveRoot": str(final_archive),
        "writerUnitBaseline": writer_unit_baseline,
        "successorUnitBaseline": successor_unit_baseline,
        "health": health,
        "artifacts": artifacts,
    }


def _retirement_validate_intent(
    intent: Mapping[str, object],
    *,
    successor_package: Path,
    successor_digest: str,
    predecessor_digest: str,
    plan_digest: str,
    final_archive: Path,
    require_live_preflight: bool,
) -> list[dict[str, object]]:
    artifacts = intent.get("artifacts")
    release_digest = intent.get("releaseManifestDigest")
    if (
        intent.get("schemaVersion") != APPROVED_PACKAGE_RETIREMENT_INTENT_SCHEMA
        or intent.get("status") != "prepared"
        or intent.get("predecessorPackageDigest") != predecessor_digest
        or intent.get("successorPackageDigest") != successor_digest
        or intent.get("maintenancePlanDigest") != plan_digest
        or not isinstance(release_digest, str)
        or len(release_digest) != 64
        or set(release_digest) - _HEX
        or intent.get("successorPackageRoot") != str(successor_package)
        or intent.get("archiveRoot") != str(final_archive)
        or not isinstance(intent.get("successorPackageEvidence"), Mapping)
        or not isinstance(artifacts, list)
        or not artifacts
        or not isinstance(intent.get("writerUnitBaseline"), list)
        or not isinstance(intent.get("successorUnitBaseline"), list)
        or intent.get("health")
        != {
            "ok": True,
            "psychloBridgeReady": True,
            "service": "overseer-api",
        }
    ):
        raise ActivationPackageError("retirement intent binding is invalid")
    selected: list[dict[str, object]] = []
    names: set[str] = set()
    executor_root = APPROVED_EXECUTION_PACKAGE.parent
    exact_allowed = {
        APPROVED_EXECUTION_PACKAGE.name,
        _activation_approval_record_path().name,
        _maintenance_approval_record_path().name,
        _maintenance_state_path().name,
        f"maintenance-{release_digest}",
        f"destination-namespace-before-{plan_digest}",
        _canary_attestation_path(predecessor_digest).name,
    }
    for item in artifacts:
        if not isinstance(item, dict):
            raise ActivationPackageError("retirement intent artifact is invalid")
        name = item.get("name")
        source = item.get("sourcePath")
        kind = item.get("kind")
        expected_kind = None
        if isinstance(name, str):
            expected_kind = (
                "package"
                if name == APPROVED_EXECUTION_PACKAGE.name
                else (
                    "directory"
                    if name
                    in {
                        f"maintenance-{release_digest}",
                        f"destination-namespace-before-{plan_digest}",
                    }
                    else "file"
                )
            )
        if (
            not isinstance(name, str)
            or _safe_relative(name) != name
            or "/" in name
            or name in names
            or not isinstance(source, str)
            or Path(source).name != name
            or Path(source).parent != executor_root
            or kind != expected_kind
            or (
                name not in exact_allowed
                and not name.startswith(
                    "consumed-approved-maintenance-rollback-retry-"
                )
            )
        ):
            raise ActivationPackageError("retirement intent artifact path is invalid")
        names.add(name)
        selected.append(item)
    required = {
        APPROVED_EXECUTION_PACKAGE.name,
        _activation_approval_record_path().name,
        _maintenance_approval_record_path().name,
        _maintenance_state_path().name,
        f"maintenance-{release_digest}",
    }
    if not required.issubset(names):
        raise ActivationPackageError("retirement intent is missing a required artifact")
    _retirement_verify_successor_package(
        successor_package,
        package_digest=successor_digest,
        expected=intent.get("successorPackageEvidence"),
    )
    if require_live_preflight:
        _maintenance_writer_unit_preflight(intent.get("writerUnitBaseline"))
        _maintenance_successor_unit_preflight(intent.get("successorUnitBaseline"))
        _retirement_health_preflight()
        _retirement_active_retry_approvals_absent(APPROVED_EXECUTION_PACKAGE.parent)
        _retirement_require_absent(
            _activation_state_path(),
            label="activation runner state",
        )
        for phase in sorted(ACTIVATION_PHASES):
            _retirement_require_absent(
                _activation_phase_approval_record_path(phase),
                label=f"{phase} phase approval",
            )
    return selected


def _retirement_receipt(
    intent: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schemaVersion": APPROVED_PACKAGE_RETIREMENT_RECEIPT_SCHEMA,
        "status": "retired",
        "predecessorPackageDigest": intent["predecessorPackageDigest"],
        "successorPackageDigest": intent["successorPackageDigest"],
        "maintenancePlanDigest": intent["maintenancePlanDigest"],
        "releaseManifestDigest": intent["releaseManifestDigest"],
        "successorPackageRoot": intent["successorPackageRoot"],
        "successorPackageEvidence": intent["successorPackageEvidence"],
        "archiveRoot": intent["archiveRoot"],
        "liveServiceMutationPerformed": False,
        "artifacts": intent["artifacts"],
    }


def _retirement_read_record(path: Path, *, label: str) -> dict[str, object]:
    document, _raw, _metadata = _retirement_load_root_record(path, label=label)
    return document


def _retirement_publish_record(
    directory: Path,
    *,
    name: str,
    document: Mapping[str, object],
) -> None:
    """Durably publish a deterministic record without replacing any inode."""

    target = directory / name
    temporary = directory / f".{name}.new"
    expected = _canonical(dict(document)) + b"\n"
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise ActivationPackageError(
            f"retirement record could not be inspected: {name}"
        ) from error
    else:
        observed, _metadata = _stable_read(target)
        if observed != expected:
            raise ActivationPackageError(
                f"retirement record binding is invalid: {name}"
            )
        _retirement_fsync_private_directory(
            directory,
            label="retirement record directory",
        )
        return
    try:
        temporary.lstat()
    except FileNotFoundError:
        _write_new(temporary, expected, 0o600)
        _retirement_fsync_private_directory(
            directory,
            label="retirement record directory",
        )
    except OSError as error:
        raise ActivationPackageError(
            f"retirement record staging path could not be inspected: {name}"
        ) from error
    else:
        observed, metadata = _stable_read(temporary)
        root_uid, root_gid = _activation_root_identity()
        if (
            observed != expected
            or metadata.st_uid != root_uid
            or metadata.st_gid != root_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ActivationPackageError(
                f"retirement staged record binding is invalid: {name}"
            )
    _retirement_rename_entry_no_replace(temporary, target)
    _retirement_fsync_private_directory(
        directory,
        label="retirement record directory",
    )


def _retirement_verify_complete_archive(
    final_archive: Path,
    *,
    successor_package: Path,
    successor_digest: str,
    predecessor_digest: str,
    plan_digest: str,
) -> dict[str, object]:
    _retirement_validate_private_directory(
        final_archive,
        label="retirement archive",
    )
    intent = _retirement_read_record(
        final_archive / "retirement-intent.json",
        label="retirement intent",
    )
    artifacts = _retirement_validate_intent(
        intent,
        successor_package=successor_package,
        successor_digest=successor_digest,
        predecessor_digest=predecessor_digest,
        plan_digest=plan_digest,
        final_archive=final_archive,
        require_live_preflight=False,
    )
    receipt = _retirement_read_record(
        final_archive / "retirement-receipt.json",
        label="retirement receipt",
    )
    if receipt != _retirement_receipt(intent):
        raise ActivationPackageError("retirement receipt binding is invalid")
    expected_names = {
        "retirement-intent.json",
        "retirement-receipt.json",
        *(str(item["name"]) for item in artifacts),
    }
    if {path.name for path in final_archive.iterdir()} != expected_names:
        raise ActivationPackageError(
            "retirement archive contains unexpected or missing artifacts"
        )
    for item in artifacts:
        source = Path(str(item["sourcePath"]))
        if source.exists() or source.is_symlink():
            raise ActivationPackageError(
                "retirement source remains after archive publication"
            )
        _retirement_verify_artifact(final_archive / str(item["name"]), item)
    return {
        "status": "retired",
        "predecessorPackageDigest": predecessor_digest,
        "successorPackageDigest": successor_digest,
        "maintenancePlanDigest": plan_digest,
        "archiveRoot": str(final_archive),
        "artifactCount": len(artifacts),
        "replayed": True,
    }


def _retire_approved_package_locked(
    successor_package: Path,
    *,
    successor_digest: str,
    predecessor_digest: str,
    plan_digest: str,
) -> dict[str, object]:
    archive_parent = _approved_package_retirement_archive_root()
    final_archive = archive_parent / predecessor_digest
    pending_archive = archive_parent / f".pending-{predecessor_digest}"
    try:
        archive_parent.lstat()
    except FileNotFoundError:
        archive_parent_exists = False
    except OSError as error:
        raise ActivationPackageError(
            "retirement archive namespace could not be inspected"
        ) from error
    else:
        archive_parent_exists = True
        _retirement_validate_private_directory(
            archive_parent,
            label="retirement archive namespace",
        )
    if final_archive.exists() or final_archive.is_symlink():
        if pending_archive.exists() or pending_archive.is_symlink():
            raise ActivationPackageError(
                "retirement archive has conflicting final and pending state"
            )
        _retirement_fsync_private_directory(
            archive_parent,
            label="retirement archive namespace",
        )
        return _retirement_verify_complete_archive(
            final_archive,
            successor_package=successor_package,
            successor_digest=successor_digest,
            predecessor_digest=predecessor_digest,
            plan_digest=plan_digest,
        )
    if pending_archive.exists() or pending_archive.is_symlink():
        _retirement_validate_private_directory(
            pending_archive,
            label="pending retirement archive",
        )
        try:
            (pending_archive / "retirement-intent.json").lstat()
        except FileNotFoundError:
            intent = _retirement_fresh_intent(
                successor_package,
                successor_digest=successor_digest,
                predecessor_digest=predecessor_digest,
                plan_digest=plan_digest,
                final_archive=final_archive,
            )
            _retirement_publish_record(
                pending_archive,
                name="retirement-intent.json",
                document=intent,
            )
        except OSError as error:
            raise ActivationPackageError(
                "retirement intent could not be inspected"
            ) from error
        else:
            intent = _retirement_read_record(
                pending_archive / "retirement-intent.json",
                label="retirement intent",
            )
    else:
        intent = _retirement_fresh_intent(
            successor_package,
            successor_digest=successor_digest,
            predecessor_digest=predecessor_digest,
            plan_digest=plan_digest,
            final_archive=final_archive,
        )
        if not archive_parent_exists:
            _ensure_directory(archive_parent, mode=0o700)
            _retirement_validate_private_directory(
                archive_parent,
                label="retirement archive namespace",
            )
            _retirement_fsync_private_directory(
                archive_parent.parent,
                label="retirement executor directory",
            )
        pending_archive.mkdir(mode=0o700)
        _retirement_validate_private_directory(
            pending_archive,
            label="pending retirement archive",
        )
        _retirement_fsync_private_directory(
            archive_parent,
            label="retirement archive namespace",
        )
        _retirement_publish_record(
            pending_archive,
            name="retirement-intent.json",
            document=intent,
        )
    artifacts = _retirement_validate_intent(
        intent,
        successor_package=successor_package,
        successor_digest=successor_digest,
        predecessor_digest=predecessor_digest,
        plan_digest=plan_digest,
        final_archive=final_archive,
        require_live_preflight=True,
    )
    for item in artifacts:
        source = Path(str(item["sourcePath"]))
        destination = pending_archive / str(item["name"])
        source_exists = source.exists() or source.is_symlink()
        destination_exists = destination.exists() or destination.is_symlink()
        if source_exists == destination_exists:
            raise ActivationPackageError(
                f"retirement artifact has ambiguous transaction state: {item['name']}"
            )
        if source_exists:
            _retirement_verify_artifact(source, item)
            _retirement_rename_artifact_no_replace(source, destination, item)
        _retirement_verify_artifact(destination, item)
        _retirement_fsync_private_directory(
            source.parent,
            label="retirement executor directory",
        )
        _retirement_fsync_private_directory(
            pending_archive,
            label="pending retirement archive",
        )
    receipt = _retirement_receipt(intent)
    _retirement_publish_record(
        pending_archive,
        name="retirement-receipt.json",
        document=receipt,
    )
    expected_pending_names = {
        "retirement-intent.json",
        "retirement-receipt.json",
        *(str(item["name"]) for item in artifacts),
    }
    if {path.name for path in pending_archive.iterdir()} != expected_pending_names:
        raise ActivationPackageError(
            "pending retirement archive contains an unexpected artifact"
        )
    _retirement_verify_successor_package(
        successor_package,
        package_digest=successor_digest,
        expected=intent.get("successorPackageEvidence"),
    )
    _retirement_rename_entry_no_replace(pending_archive, final_archive)
    _retirement_fsync_private_directory(
        archive_parent,
        label="retirement archive namespace",
    )
    result = _retirement_verify_complete_archive(
        final_archive,
        successor_package=successor_package,
        successor_digest=successor_digest,
        predecessor_digest=predecessor_digest,
        plan_digest=plan_digest,
    )
    return {**result, "replayed": False}


def retire_approved_package(
    successor_package_root: str | os.PathLike[str],
    *,
    expected_successor_package_digest: str,
    expected_predecessor_package_digest: str,
    expected_maintenance_plan_digest: str,
) -> dict[str, object]:
    """Archive one terminal predecessor without changing live services."""

    _require_root_activation()
    successor_digest = _retirement_digest(
        expected_successor_package_digest,
        label="successor package digest",
    )
    predecessor_digest = _retirement_digest(
        expected_predecessor_package_digest,
        label="predecessor package digest",
    )
    plan_digest = _retirement_digest(
        expected_maintenance_plan_digest,
        label="maintenance plan digest",
    )
    if successor_digest == predecessor_digest:
        raise ActivationPackageError(
            "successor and predecessor package digests must differ"
        )
    with _activation_execution_lock():
        successor_package = _validate_existing_package_destination(
            successor_package_root
        )
        verify_activation_package(successor_package, successor_digest)
        return _retire_approved_package_locked(
            successor_package,
            successor_digest=successor_digest,
            predecessor_digest=predecessor_digest,
            plan_digest=plan_digest,
        )


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
    prepare.add_argument("--expected-commit", required=True)
    prepare.add_argument("--expected-tree", required=True)
    prepare.add_argument("--dependency-root", required=True)
    prepare.add_argument("--root-python", required=True)
    prepare.add_argument("--stdlib-root", required=True)
    prepare.add_argument("--sqlite-library", required=True)
    prepare.add_argument("--templates-root", required=True)
    prepare.add_argument("--package-root", required=True)
    prepare.add_argument("--psychlo-secret-file", required=True)
    prepare.add_argument("--roadex-secret-file", required=True)
    prepare.add_argument("--psychlo-bindings-file", required=True)
    prepare.add_argument("--protected-gateway-ca-file", required=True)
    prepare.add_argument("--source-store", required=True)
    prepare.add_argument("--psychlo-store", required=True)
    prepare.add_argument("--roadex-store", required=True)
    prepare.add_argument("--codex-usage-store", required=True)
    prepare.add_argument("--god-uid", required=True, type=int)
    prepare.add_argument("--god-gid", required=True, type=int)
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
    restore_legacy.add_argument("--package-root")
    restore_legacy.add_argument("--source-store", required=True)
    restore_legacy.add_argument("--expected-source-uid", required=True, type=int)
    restore_legacy.add_argument("--expected-source-gid", required=True, type=int)
    restore_legacy.add_argument("--expected-source-device", required=True, type=int)
    restore_legacy.add_argument("--expected-source-inode", required=True, type=int)
    restore_legacy.add_argument("--expected-parent-device", required=True, type=int)
    restore_legacy.add_argument("--expected-parent-inode", required=True, type=int)
    restore_legacy.add_argument("--expected-parent-mode", required=True, type=int)
    ensure_principal = commands.add_parser(
        "ensure-dedicated-principal",
        help="create or reuse only the exact approved dedicated principal",
    )
    ensure_principal.add_argument("--package-root", required=True)
    maintenance_preflight = commands.add_parser(
        "verify-maintenance-preflight",
        help="verify every discoverable maintenance input before writer shutdown",
    )
    maintenance_preflight.add_argument("--package-root", required=True)
    maintenance_stop_writers = commands.add_parser(
        "stop-maintenance-writers",
        help="stop the complete allowlisted Overseer user-writer set",
    )
    maintenance_stop_writers.add_argument("--package-root", required=True)
    maintenance_quiescence = commands.add_parser(
        "verify-maintenance-quiescence",
        help="prove the exact maintenance stores have no open writer artifacts",
    )
    maintenance_quiescence.add_argument("--package-root", required=True)
    maintenance_preservation = commands.add_parser(
        "preserve-maintenance-state",
        help="copy the sealed maintenance rollback evidence before installation",
    )
    maintenance_preservation.add_argument("--package-root", required=True)
    maintenance_verify_installed = commands.add_parser(
        "verify-maintenance-installed-release",
        help="re-hash every immutable installed release artifact before migration",
    )
    maintenance_verify_installed.add_argument("--package-root", required=True)
    maintenance_verify_preservation = commands.add_parser(
        "verify-maintenance-preservation",
        help="re-hash the root-owned maintenance evidence before service handoff",
    )
    maintenance_verify_preservation.add_argument("--package-root", required=True)
    maintenance_stores = commands.add_parser(
        "prepare-maintenance-stores",
        help="prepare the exact three offline maintenance stores",
    )
    maintenance_stores.add_argument("--package-root", required=True)
    maintenance_restore = commands.add_parser(
        "restore-maintenance-store-access",
        help="restore all sealed legacy store authorities during maintenance rollback",
    )
    maintenance_restore.add_argument("--package-root", required=True)
    maintenance_restore_handoff = commands.add_parser(
        "restore-maintenance-handoff-artifacts",
        help="restore exact preserved credentials and units during full rollback",
    )
    maintenance_restore_handoff.add_argument("--package-root", required=True)
    maintenance_restop_writers = commands.add_parser(
        "restop-maintenance-writers",
        help="reassert writer quiescence during sealed early rollback",
    )
    maintenance_restop_writers.add_argument("--package-root", required=True)
    maintenance_restore_writers = commands.add_parser(
        "restore-maintenance-writers",
        help="restore the exact preflight-active writer units during rollback",
    )
    maintenance_restore_writers.add_argument("--package-root", required=True)
    maintenance_acceptance = commands.add_parser(
        "verify-maintenance-acceptance",
        help="run the exact bounded maintenance acceptance set",
    )
    maintenance_acceptance.add_argument("--package-root", required=True)
    canary_store = commands.add_parser(
        "stage-canary-store",
        help="publish a new package-bound canary SQLite state directory",
    )
    canary_store.add_argument("--package-root", required=True)
    canary_handoff = commands.add_parser(
        "handoff-start-canary",
        help="transfer verified canary state and immediately start the exact canary unit",
    )
    canary_handoff.add_argument("--package-root", required=True)
    record_approval = commands.add_parser(
        "record-activation-approval",
        help="record a root-owned approval for one exact sealed package digest",
    )
    record_approval.add_argument("--package-root", required=True)
    record_approval.add_argument("--expected-package-digest", required=True)
    record_phase_approval = commands.add_parser(
        "record-activation-phase-approval",
        help="record a root-owned approval for one exact package phase and runner state",
    )
    record_phase_approval.add_argument("--package-root", required=True)
    record_phase_approval.add_argument("--expected-package-digest", required=True)
    record_phase_approval.add_argument(
        "--phase",
        required=True,
        choices=tuple(sorted(ACTIVATION_PHASES)),
    )
    record_maintenance_approval = commands.add_parser(
        "record-maintenance-window-approval",
        help="record the separate no-reboot approval for one maintenance contract",
    )
    record_maintenance_approval.add_argument("--package-root", required=True)
    record_maintenance_approval.add_argument("--expected-package-digest", required=True)
    record_maintenance_retry = commands.add_parser(
        "record-maintenance-rollback-retry-approval",
        help="approve one retry for one exact failed maintenance rollback state",
    )
    record_maintenance_retry.add_argument("--package-root", required=True)
    record_maintenance_retry.add_argument("--expected-package-digest", required=True)
    record_maintenance_retry.add_argument("--expected-state-digest", required=True)
    verify_maintenance = commands.add_parser(
        "verify-approved-maintenance-window",
        help="verify the separate maintenance approval and sealed contract",
    )
    verify_maintenance.add_argument("--package-root", required=True)
    recover_approval_import = commands.add_parser(
        "recover-activation-approval-import",
        help="adopt or remove an unapproved package left by interrupted root import",
    )
    recover_approval_import.add_argument("--source-package-root", required=True)
    recover_approval_import.add_argument("--expected-package-digest", required=True)
    recover_approval_import.add_argument(
        "--action",
        required=True,
        choices=("adopt", "remove"),
    )
    retire_package = commands.add_parser(
        "retire-approved-package",
        help="archive one exact terminal predecessor without changing services",
    )
    retire_package.add_argument("--successor-package-root", required=True)
    retire_package.add_argument(
        "--expected-successor-package-digest",
        required=True,
    )
    retire_package.add_argument(
        "--expected-predecessor-package-digest",
        required=True,
    )
    retire_package.add_argument(
        "--expected-maintenance-plan-digest",
        required=True,
    )
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
        help="fail closed; activation now requires separately approved phase runners",
    )
    execute_activation.add_argument("--package-root", required=True)
    execute_staging_canary = commands.add_parser(
        "execute-approved-staging-canary",
        help="execute only the separately approved staging and live-canary phase",
    )
    execute_staging_canary.add_argument("--package-root", required=True)
    execute_cutover = commands.add_parser(
        "execute-approved-cutover",
        help="resume cutover only after a separately approved successful canary state",
    )
    execute_cutover.add_argument("--package-root", required=True)
    execute_rollback = commands.add_parser(
        "execute-approved-rollback",
        help="recover an interrupted cutover through the sealed rollback contract",
    )
    execute_rollback.add_argument("--package-root", required=True)
    execute_maintenance = commands.add_parser(
        "execute-approved-maintenance-window",
        help="execute the separately approved maintenance window",
    )
    execute_maintenance.add_argument("--package-root", required=True)
    execute_maintenance_rollback = commands.add_parser(
        "execute-approved-maintenance-rollback",
        help="execute sealed rollback for an interrupted maintenance window",
    )
    execute_maintenance_rollback.add_argument("--package-root", required=True)
    final_store = commands.add_parser(
        "prepare-final-store",
        help="create the final migrated authority store after legacy writers are stopped",
    )
    final_store.add_argument("--package-root", required=True)
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
            god_gid=args.god_gid,
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
            expected_commit=args.expected_commit,
            expected_tree=args.expected_tree,
        )
        _assert_current_sqlite_runtime(manifest)
        stage_release_payload(
            manifest,
            checkout=args.checkout,
            dependency_root=args.dependency_root,
            stdlib_root=args.stdlib_root,
            package_root=package_root,
        )
        stage_canary_identity(package_root)
        render_systemd_units(
            manifest,
            templates_root=args.templates_root,
            output_root=package_root / "public" / "systemd",
            god_uid=args.god_uid,
            god_gid=args.god_gid,
            overseer_uid=args.overseer_uid,
            python_path=args.root_python,
        )
        stage_credentials(
            package_root,
            psychlo_secret_file=args.psychlo_secret_file,
            roadex_secret_file=args.roadex_secret_file,
            psychlo_bindings_file=args.psychlo_bindings_file,
            protected_gateway_ca_file=args.protected_gateway_ca_file,
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
            psychlo_store=args.psychlo_store,
            roadex_store=args.roadex_store,
            codex_usage_store=args.codex_usage_store,
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
            package_root=(
                _validate_existing_package_destination(args.package_root)
                if args.package_root
                else APPROVED_EXECUTION_PACKAGE
            ),
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
    if args.command == "ensure-dedicated-principal":
        result = ensure_dedicated_principal(
            package_root=_validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-maintenance-preflight":
        result = verify_maintenance_preflight(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "stop-maintenance-writers":
        result = stop_maintenance_writers(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-maintenance-quiescence":
        result = verify_maintenance_quiescence(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "preserve-maintenance-state":
        result = preserve_maintenance_state(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-maintenance-installed-release":
        result = verify_maintenance_installed_release(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-maintenance-preservation":
        result = verify_maintenance_preservation(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "prepare-maintenance-stores":
        result = prepare_maintenance_stores(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "restore-maintenance-store-access":
        result = restore_maintenance_store_access(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "restore-maintenance-handoff-artifacts":
        result = restore_maintenance_handoff_artifacts(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "restop-maintenance-writers":
        result = restop_maintenance_writers(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "restore-maintenance-writers":
        result = restore_maintenance_writers(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-maintenance-acceptance":
        result = verify_maintenance_acceptance(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "stage-canary-store":
        result = stage_canary_store(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "handoff-start-canary":
        result = handoff_start_canary(
            _validate_existing_package_destination(args.package_root),
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
    if args.command == "record-activation-phase-approval":
        result = record_activation_phase_approval(
            _validate_existing_package_destination(args.package_root),
            expected_package_digest=args.expected_package_digest,
            phase=args.phase,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "record-maintenance-window-approval":
        result = record_maintenance_window_approval(
            args.package_root,
            args.expected_package_digest,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "record-maintenance-rollback-retry-approval":
        result = record_maintenance_rollback_retry_approval(
            args.package_root,
            args.expected_package_digest,
            args.expected_state_digest,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "verify-approved-maintenance-window":
        result = verify_approved_maintenance_window(
            args.package_root,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "recover-activation-approval-import":
        result = recover_activation_approval_import(
            args.source_package_root,
            expected_package_digest=args.expected_package_digest,
            action=args.action,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "retire-approved-package":
        result = retire_approved_package(
            args.successor_package_root,
            expected_successor_package_digest=args.expected_successor_package_digest,
            expected_predecessor_package_digest=(
                args.expected_predecessor_package_digest
            ),
            expected_maintenance_plan_digest=args.expected_maintenance_plan_digest,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "run-approved-canary":
        package = _validate_existing_package_destination(args.package_root)
        approval = _load_activation_approval(package)
        digest = str(approval["packageDigest"])
        _require_active_canary_command(
            package,
            expected_package_digest=digest,
        )
        admin_secret, roadex_secret = _read_canary_authorization_input()
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
    if args.command == "execute-approved-staging-canary":
        result = execute_approved_staging_canary(
            _validate_existing_package_destination(args.package_root),
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "execute-approved-cutover":
        result = execute_approved_cutover(
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
    if args.command == "execute-approved-maintenance-window":
        result = execute_approved_maintenance_window(
            args.package_root,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "execute-approved-maintenance-rollback":
        result = execute_approved_maintenance_rollback(
            args.package_root,
        )
        print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "prepare-final-store":
        report = prepare_final_store_migration(
            package_root=_validate_existing_package_destination(args.package_root),
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
    "ACTIVATION_PHASE_APPROVAL_SCHEMA",
    "APPROVED_PACKAGE_RETIREMENT_INTENT_SCHEMA",
    "APPROVED_PACKAGE_RETIREMENT_RECEIPT_SCHEMA",
    "ActivationPackageError",
    "MAINTENANCE_APPROVAL_SCHEMA",
    "MAINTENANCE_CONTRACT_SCHEMA",
    "MAINTENANCE_ROLLBACK_RETRY_APPROVAL_SCHEMA",
    "MAINTENANCE_RUNNER_STATE_SCHEMA",
    "PACKAGE_MANIFEST_SCHEMA",
    "RELEASE_SCHEMA",
    "ROLLBACK_MANIFEST_SCHEMA",
    "activation_package_status",
    "build_release_manifest",
    "create_human_verifiers",
    "execute_approved_activation",
    "execute_approved_cutover",
    "execute_approved_maintenance_rollback",
    "execute_approved_maintenance_window",
    "execute_approved_rollback",
    "execute_approved_staging_canary",
    "ensure_dedicated_principal",
    "finalize_activation_package",
    "handoff_start_canary",
    "prepare_final_store_migration",
    "recover_activation_approval_import",
    "retire_approved_package",
    "record_activation_approval",
    "record_activation_phase_approval",
    "record_maintenance_rollback_retry_approval",
    "rehearse_store_migration",
    "render_activation_contract",
    "render_maintenance_window_contract",
    "render_systemd_units",
    "restop_maintenance_writers",
    "restore_maintenance_handoff_artifacts",
    "restore_legacy_store_access",
    "run_canary_acceptance",
    "stage_canary_identity",
    "stage_canary_store",
    "stage_credentials",
    "stage_release_payload",
    "verify_activation_package",
    "verify_approved_cutover",
    "verify_approved_staging",
    "verify_canary_attestation",
    "verify_compatibility_token",
    "verify_installed_staging",
    "verify_maintenance_installed_release",
    "verify_rollback_inputs",
    "verify_rollback_bundle",
]


if __name__ == "__main__":
    raise SystemExit(_main())
