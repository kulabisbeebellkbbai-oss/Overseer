#!/usr/bin/python3.13
"""Preflight and render an inert disposable Phase B rehearsal plan.

``preflight`` performs read-only checks. ``render-plan`` revalidates the exact
owner against the authoritative local registry, then emits canonical JSON
containing a separately approved future script. This module has
no VM, image, package, service, or activation mutation subcommand.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import uuid
import zipfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree
from xml.sax.saxutils import escape


BASE_IMAGE_URL = (
    "https://cloud.debian.org/images/cloud/trixie/latest/"
    "debian-13-genericcloud-amd64.qcow2"
)
BASE_IMAGE_SHA512 = (
    "184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003"
)
LIBVIRT_URI = "qemu:///session"
MACHINE_TYPE = "pc-i440fx-10.0"
MEMORY_MIB = 2048
VCPUS = 2
OVERLAY_GIB = 8
DEFAULT_BASE_IMAGE = Path(
    "/var/lib/overseer-phase-b-rehearsal/debian-13-genericcloud-amd64.qcow2"
)
FIRMWARE_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
FIRMWARE_CODE_SHA256 = "624e06de18b4fa535e90db7160d00d3d07d206422b89999bf1e27d920264e4e0"
FIRMWARE_VARS_TEMPLATE = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
FIRMWARE_VARS_SHA256 = "5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e"
DEFAULT_RUNTIME_SITE = Path("/usr/lib/python3/dist-packages")
DEFAULT_TEMP_PARENT = Path("/var/tmp")
DEFAULT_CODEX_PROJECTS_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
SESSION_RUNTIME_DIR = Path("/run/user") / str(os.geteuid())
REHEARSAL_SCHEMA = "overseer.phase-b-disposable-rehearsal-plan.v8"
OWNER_BINDING_SCHEMA = "overseer.phase-b-rehearsal-owner-binding.v2"
ARTIFACT_MANIFEST_SCHEMA = "overseer.rehearsal-artifact-manifest.v1"
RESULT_SCHEMA = "overseer.phase-b-disposable-rehearsal.v1"
RESULT_TIMEOUT_SECONDS = 960
SHUTDOWN_TIMEOUT_SECONDS = 120
MAX_SERIAL_BYTES = 1024 * 1024
MAX_SERIAL_LINE_BYTES = 64 * 1024
MAX_SOURCE_FILES = 2048
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_RUNTIME_FILES = 1024
MAX_RUNTIME_BYTES = 64 * 1024 * 1024
MAX_CODEX_PROJECTS_REGISTRY_BYTES = 8 * 1024 * 1024
MAX_CODEX_EXECUTABLE_BYTES = 536870912
MAX_PROCESS_CMDLINE_BYTES = 65536
MAX_PROCESS_ANCESTORS = 128

EXACT_TOOLS = {
    "awk": "/usr/bin/awk",
    "bash": "/usr/bin/bash",
    "cat": "/usr/bin/cat",
    "env": "/usr/bin/env",
    "genisoimage": "/usr/bin/genisoimage",
    "git": "/usr/bin/git",
    "grep": "/usr/bin/grep",
    "id": "/usr/bin/id",
    "install": "/usr/bin/install",
    "mkfifo": "/usr/bin/mkfifo",
    "mkdir": "/usr/bin/mkdir",
    "mktemp": "/usr/bin/mktemp",
    "python": "/usr/bin/python3.13",
    "qemu-img": "/usr/bin/qemu-img",
    "rm": "/usr/bin/rm",
    "rmdir": "/usr/bin/rmdir",
    "sha256sum": "/usr/bin/sha256sum",
    "sha512sum": "/usr/bin/sha512sum",
    "sleep": "/usr/bin/sleep",
    "stat": "/usr/bin/stat",
    "timeout": "/usr/bin/timeout",
    "tmux": "/usr/bin/tmux",
    "virsh": "/usr/bin/virsh",
}
REQUIRED_TOOLS = tuple(EXACT_TOOLS)
MINIMAL_ENV = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "XDG_RUNTIME_DIR": str(SESSION_RUNTIME_DIR),
}

TASK_TWO_PLACEHOLDERS = (
    "/etc/systemd/system/overseer-approval-smoke.service",
    "/etc/systemd/system/overseer-api-canary.service",
    "/etc/systemd/system/overseer-admin-executor.socket",
    "/etc/systemd/system/overseer-admin-executor@.service",
    "/etc/systemd/system/overseer-codex-user-bridge.socket",
    "/etc/systemd/system/overseer-codex-user-bridge.service",
)
REQUIRED_IMPORTS = (
    "cryptography",
    "overseer.cli",
    "overseer.user_bridge",
    "overseer.admin_executor",
)
REQUIRED_CONTROLS = frozenset(
    {
        "systemdCredentials",
        "secureTty",
        "socketActivation",
        "unixPeerIdentity",
        "apiHealth",
        "usageBridge",
        "sessionBridge",
        "allowlistedRestart",
        "replayNoMutation",
        "unlistedRejected",
        "authorityLockCreated",
        "quiescentStop",
        "evidenceSealed",
        "cleanupStateDurable",
        "rollbackReplay",
    }
)

_FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HOST_PATH = re.compile(r"/[A-Za-z0-9._/+ \-]+\Z")
_ARTIFACT_PATH = re.compile(r"[A-Za-z0-9._/+@ \-]+\Z")
_PYTHON_VERSION = re.compile(r"3\.13\.[0-9]+\Z")
_PYTHON_ABI = re.compile(r"cpython-313-[A-Za-z0-9_.-]+\Z")
_CODEX_EXECUTABLE_PATH = re.compile(
    r"/home/god/\.codex/packages/standalone/releases/"
    r"[0-9]+\.[0-9]+\.[0-9]+-x86_64-unknown-linux-musl/bin/codex\Z"
)
_RUN_NAMESPACE = uuid.UUID("4c7e2e88-e69b-5a43-9896-ffae89196717")
_CODEX_REGISTRY_FIELDS = (
    "conversation_id",
    "label",
    "project",
    "command",
    "launcher",
    "created_at",
    "updated_at",
    "source",
    "notes",
)
_OWNER_BINDING_KEYS = frozenset(
    {
        "schemaVersion",
        "status",
        "conversationId",
        "project",
        "ownerProjectToplevel",
        "sourceRoot",
        "gitCommonDirectory",
        "ownerProjectDevice",
        "ownerProjectInode",
        "sourceRootDevice",
        "sourceRootInode",
        "gitCommonDirectoryDevice",
        "gitCommonDirectoryInode",
        "registry",
        "registryDevice",
        "registryInode",
        "registryRow",
        "registrySha256",
        "registryRowDigest",
        "launcherDevice",
        "launcherInode",
        "launcherSha256",
        "codexExecutable",
        "codexExecutableDevice",
        "codexExecutableInode",
        "codexExecutableSha256",
        "codexArgv",
        "bindingDigest",
    }
)
_OWNER_REGISTRY_ROW_KEYS = frozenset(
    {"conversationId", "project", "command", "launcher"}
)
_REPOSITORY_IDENTITY_KEYS = frozenset(
    {"topLevel", "device", "inode", "commonDirectory", "commonDevice", "commonInode"}
)
_GIT_SAFE_FLAGS = (
    "--no-optional-locks",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
)


class PreflightError(RuntimeError):
    """Raised when an exact inert rehearsal precondition is absent."""


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_full_source_commit(source_commit: str) -> None:
    if not isinstance(source_commit, str) or _FULL_SHA.fullmatch(source_commit) is None:
        raise PreflightError("source commit must be a lowercase full 40-character SHA")


def _require_exact_conversation_id(value: object, *, label: str) -> str:
    if not isinstance(value, str):
        raise PreflightError(f"{label} conversation id is invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise PreflightError(f"{label} conversation id is invalid") from error
    if str(parsed) != value:
        raise PreflightError(f"{label} conversation id is invalid")
    return value


def _open_codex_projects_registry(path: Path) -> int:
    _validate_host_path(path, "Codex projects registry")
    parts = path.parts[1:]
    if not parts:
        raise PreflightError("Codex projects registry path is unsafe")
    cloexec = getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | cloexec | nofollow | getattr(os, "O_DIRECTORY", 0)
    parent_descriptor = -1
    try:
        parent_descriptor = os.open("/", directory_flags)
        for component in parts[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=parent_descriptor)
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        return os.open(
            parts[-1], os.O_RDONLY | cloexec | nofollow, dir_fd=parent_descriptor
        )
    except OSError as error:
        raise PreflightError("Codex projects registry is unavailable") from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _open_nofollow_directory(path: Path, *, label: str) -> int:
    _validate_host_path(path, label)
    parts = path.parts[1:]
    if not parts:
        raise PreflightError(f"{label} path is unsafe")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    parent_descriptor = -1
    try:
        parent_descriptor = os.open("/", flags)
        for component in parts:
            next_descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        descriptor = parent_descriptor
        parent_descriptor = -1
        return descriptor
    except OSError as error:
        raise PreflightError(f"{label} is unavailable or linked") from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _git_at_directory_descriptor(
    descriptor: int, *arguments: str, preserve_output: bool = False
) -> str:
    completed = subprocess.run(
        (
            EXACT_TOOLS["git"],
            *_GIT_SAFE_FLAGS,
            "-C",
            f"/proc/self/fd/{descriptor}",
            *arguments,
        ),
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=MINIMAL_ENV,
        pass_fds=(descriptor,),
    )
    return completed.stdout if preserve_output else completed.stdout.strip()


def _read_only_repository_identity(path: Path) -> dict[str, object]:
    descriptor = _open_nofollow_directory(path, label="repository path")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid():
            raise PreflightError("repository path object is unsafe")
        if _git_at_directory_descriptor(descriptor, "rev-parse", "--show-prefix"):
            raise PreflightError("repository path is not the Git worktree top level")
        common_directory = Path(
            _git_at_directory_descriptor(
                descriptor,
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            )
        )
        _validate_host_path(common_directory, "Git common directory")
        common_descriptor = _open_nofollow_directory(
            common_directory, label="Git common directory"
        )
        try:
            common_state = os.fstat(common_descriptor)
            repeated_common = Path(
                _git_at_directory_descriptor(
                    descriptor,
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                )
            )
            repeated_descriptor = _open_nofollow_directory(
                common_directory, label="Git common directory"
            )
            try:
                repeated_common_state = os.fstat(repeated_descriptor)
            finally:
                os.close(repeated_descriptor)
        finally:
            os.close(common_descriptor)
        after = os.fstat(descriptor)
        reopened_descriptor = _open_nofollow_directory(path, label="repository path")
        try:
            reopened = os.fstat(reopened_descriptor)
        finally:
            os.close(reopened_descriptor)
        directory_identity = (before.st_dev, before.st_ino)
        if (
            repeated_common != common_directory
            or (common_state.st_dev, common_state.st_ino)
            != (repeated_common_state.st_dev, repeated_common_state.st_ino)
            or directory_identity != (after.st_dev, after.st_ino)
            or directory_identity != (reopened.st_dev, reopened.st_ino)
        ):
            raise PreflightError("repository identity changed during the read-only probe")
        return {
            "topLevel": str(path),
            "device": before.st_dev,
            "inode": before.st_ino,
            "commonDirectory": str(common_directory),
            "commonDevice": common_state.st_dev,
            "commonInode": common_state.st_ino,
        }
    except subprocess.CalledProcessError as error:
        raise PreflightError("repository identity probe failed") from error
    finally:
        os.close(descriptor)


def _read_only_source_git_state(path: Path) -> dict[str, str]:
    descriptor = _open_nofollow_directory(path, label="source Git state repository")
    identity = _root_directory_identity(descriptor)
    try:
        status = _git_at_directory_descriptor(
            descriptor, "status", "--porcelain", "--untracked-files=all"
        )
        head = _git_at_directory_descriptor(descriptor, "rev-parse", "HEAD")
        files = _git_at_directory_descriptor(
            descriptor, "ls-files", "-z", preserve_output=True
        )
        if _root_directory_identity(descriptor) != identity:
            raise PreflightError("source Git state repository changed while probed")
        reopened = _open_nofollow_directory(path, label="source Git state repository")
        try:
            if _root_directory_identity(reopened) != identity:
                raise PreflightError("source Git state repository changed while probed")
        finally:
            os.close(reopened)
        return {"status": status, "head": head, "files": files}
    except subprocess.CalledProcessError as error:
        raise PreflightError("source Git state probe failed") from error
    finally:
        os.close(descriptor)


def _read_codex_projects_registry(path: Path) -> bytes:
    descriptor = _open_codex_projects_registry(path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or before.st_size > MAX_CODEX_PROJECTS_REGISTRY_BYTES
        ):
            raise PreflightError("Codex projects registry object is unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, MAX_CODEX_PROJECTS_REGISTRY_BYTES + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > MAX_CODEX_PROJECTS_REGISTRY_BYTES:
                raise PreflightError("Codex projects registry exceeds the bounded size")
        after = os.fstat(descriptor)
        before_state = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_state = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        payload = b"".join(chunks)
        if before_state != after_state or len(payload) != before.st_size:
            raise PreflightError("Codex projects registry changed while it was read")
        pathname_descriptor = _open_codex_projects_registry(path)
        try:
            pathname_state = os.fstat(pathname_descriptor)
        finally:
            os.close(pathname_descriptor)
        pathname_identity = (
            pathname_state.st_dev,
            pathname_state.st_ino,
            pathname_state.st_size,
            pathname_state.st_mtime_ns,
            pathname_state.st_ctime_ns,
        )
        if (
            pathname_identity != after_state
            or not stat.S_ISREG(pathname_state.st_mode)
            or pathname_state.st_nlink != 1
            or pathname_state.st_uid != os.geteuid()
            or pathname_state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise PreflightError(
                "Codex projects registry changed or was replaced after it was read"
            )
        return payload
    finally:
        os.close(descriptor)


def _codex_registry_object_identity(path: Path) -> dict[str, int]:
    descriptor = _open_codex_projects_registry(path)
    try:
        state = os.fstat(descriptor)
        if (
            not stat.S_ISREG(state.st_mode)
            or state.st_uid != os.geteuid()
            or state.st_nlink != 1
            or state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise PreflightError("Codex projects registry object is unsafe")
        return {"device": state.st_dev, "inode": state.st_ino}
    finally:
        os.close(descriptor)


def _open_nofollow_regular_path(path: Path, *, label: str) -> int:
    _validate_host_path(path, label)
    parts = path.parts[1:]
    if not parts:
        raise PreflightError(f"{label} path is unsafe")
    cloexec = getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | cloexec | nofollow | getattr(os, "O_DIRECTORY", 0)
    parent_descriptor = -1
    try:
        parent_descriptor = os.open("/", directory_flags)
        for component in parts[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=parent_descriptor)
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        return os.open(
            parts[-1], os.O_RDONLY | cloexec | nofollow, dir_fd=parent_descriptor
        )
    except OSError as error:
        raise PreflightError(f"{label} is unavailable or linked") from error
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _read_launcher_evidence(
    path: Path, *, conversation_id: str, project: Path, command: str
) -> dict[str, object]:
    descriptor = _open_nofollow_regular_path(path, label="registered owner launcher")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not before.st_mode & stat.S_IXUSR
            or before.st_size > 65536
        ):
            raise PreflightError("registered owner launcher object is unsafe")
        payload = b""
        while len(payload) <= 65536:
            block = os.read(descriptor, min(65537 - len(payload), 65536))
            if not block:
                break
            payload += block
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(payload) != before.st_size
        ):
            raise PreflightError("registered owner launcher changed while read")
    finally:
        os.close(descriptor)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError("registered owner launcher encoding is invalid") from error
    lines = text.splitlines()
    if lines[:3] != ["#!/usr/bin/env bash", "set -euo pipefail", ""] or len(lines) != 4:
        raise PreflightError("registered owner launcher content is invalid")
    try:
        outer = shlex.split(lines[3])
    except ValueError as error:
        raise PreflightError("registered owner launcher content is invalid") from error
    if outer != [
        "exec",
        "/usr/bin/tmux",
        "new-session",
        "-A",
        "-s",
        command,
        "-c",
        str(project),
        f"/home/god/.local/bin/codex-memory-session resume {conversation_id} --cd '{project}'",
    ]:
        raise PreflightError("registered owner launcher content is invalid")
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _read_bounded_proc_file(
    process_descriptor: int, name: str, *, limit: int
) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=process_descriptor,
    )
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(65536, limit + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > limit:
                raise PreflightError("owner process metadata exceeds its bound")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _parse_process_stat(payload: bytes, *, expected_pid: int) -> tuple[int, int]:
    marker = payload.rfind(b") ")
    if marker < 1:
        raise PreflightError("owner process metadata is invalid")
    try:
        parsed_pid = int(payload[: payload.index(b" ")])
        fields = payload[marker + 2 :].split()
        parent_pid = int(fields[1])
        start_time = int(fields[19])
    except (IndexError, ValueError) as error:
        raise PreflightError("owner process metadata is invalid") from error
    if parsed_pid != expected_pid or parent_pid < 0 or start_time <= 0:
        raise PreflightError("owner process metadata is invalid")
    return parent_pid, start_time


def _read_process_snapshot(pid: int, *, include_executable: bool) -> dict[str, object]:
    if pid <= 0:
        raise PreflightError("owner process ancestry is invalid")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        process_descriptor = os.open(f"/proc/{pid}", flags)
    except OSError as error:
        raise PreflightError("owner process ancestry is unavailable") from error
    try:
        process_state = os.fstat(process_descriptor)
        if not stat.S_ISDIR(process_state.st_mode) or process_state.st_uid != os.geteuid():
            raise PreflightError("owner process ancestry is unsafe")
        before_stat = _read_bounded_proc_file(process_descriptor, "stat", limit=65536)
        parent_pid, start_time = _parse_process_stat(before_stat, expected_pid=pid)
        cmdline_payload = _read_bounded_proc_file(
            process_descriptor, "cmdline", limit=MAX_PROCESS_CMDLINE_BYTES
        )
        try:
            argv = [
                item.decode("utf-8")
                for item in cmdline_payload.split(b"\0")
                if item
            ]
        except UnicodeDecodeError as error:
            raise PreflightError("owner process command line is invalid") from error
        snapshot: dict[str, object] = {
            "pid": pid,
            "parentPid": parent_pid,
            "startTime": start_time,
            "argv": argv,
        }
        try:
            executable_path = Path(os.readlink("exe", dir_fd=process_descriptor))
            executable_descriptor = os.open(
                "exe",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                dir_fd=process_descriptor,
            )
        except OSError as error:
            raise PreflightError("owner process executable is unavailable") from error
        try:
            _validate_host_path(executable_path, "owner process executable")
            executable_before = os.fstat(executable_descriptor)
            if not stat.S_ISREG(executable_before.st_mode):
                raise PreflightError("owner process executable is unsafe")
            snapshot.update(
                {
                    "executable": str(executable_path),
                    "executableDevice": executable_before.st_dev,
                    "executableInode": executable_before.st_ino,
                }
            )
            if include_executable:
                if (
                    _CODEX_EXECUTABLE_PATH.fullmatch(str(executable_path)) is None
                    or executable_before.st_uid != os.geteuid()
                    or executable_before.st_nlink != 1
                    or executable_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                    or not executable_before.st_mode & stat.S_IXUSR
                    or executable_before.st_size > MAX_CODEX_EXECUTABLE_BYTES
                ):
                    raise PreflightError("owner Codex executable is unsafe")
                digest = hashlib.sha256()
                total = 0
                while True:
                    block = os.read(executable_descriptor, 1048576)
                    if not block:
                        break
                    digest.update(block)
                    total += len(block)
                    if total > MAX_CODEX_EXECUTABLE_BYTES:
                        raise PreflightError("owner Codex executable exceeds its bound")
                snapshot["executableSha256"] = digest.hexdigest()
            executable_after = os.fstat(executable_descriptor)
            executable_identity = (
                executable_before.st_dev,
                executable_before.st_ino,
                executable_before.st_size,
                executable_before.st_mtime_ns,
                executable_before.st_ctime_ns,
            )
            if executable_identity != (
                executable_after.st_dev,
                executable_after.st_ino,
                executable_after.st_size,
                executable_after.st_mtime_ns,
                executable_after.st_ctime_ns,
            ) or (include_executable and total != executable_before.st_size):
                raise PreflightError("owner process executable changed while read")
        finally:
            os.close(executable_descriptor)
        try:
            repeated_executable_path = Path(os.readlink("exe", dir_fd=process_descriptor))
            repeated_executable = os.open(
                "exe",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                dir_fd=process_descriptor,
            )
        except OSError as error:
            raise PreflightError("owner process executable changed") from error
        try:
            repeated_executable_state = os.fstat(repeated_executable)
        finally:
            os.close(repeated_executable)
        if (
            repeated_executable_path != executable_path
            or executable_identity
            != (
                repeated_executable_state.st_dev,
                repeated_executable_state.st_ino,
                repeated_executable_state.st_size,
                repeated_executable_state.st_mtime_ns,
                repeated_executable_state.st_ctime_ns,
            )
        ):
            raise PreflightError("owner process executable changed")
        if (
            _read_bounded_proc_file(
                process_descriptor, "cmdline", limit=MAX_PROCESS_CMDLINE_BYTES
            )
            != cmdline_payload
        ):
            raise PreflightError("owner process command line changed")
        after_stat = _read_bounded_proc_file(process_descriptor, "stat", limit=65536)
        after_parent, after_start = _parse_process_stat(after_stat, expected_pid=pid)
        if (after_parent, after_start) != (parent_pid, start_time):
            raise PreflightError("owner process changed while inspected")
        return snapshot
    finally:
        os.close(process_descriptor)


def _read_owner_process_ancestry() -> list[dict[str, object]]:
    current = os.getppid()
    seen: set[int] = set()
    ancestry: list[dict[str, object]] = []
    for _ in range(MAX_PROCESS_ANCESTORS):
        if current <= 0 or current in seen:
            raise PreflightError("owner process ancestry is invalid")
        seen.add(current)
        metadata = _read_process_snapshot(current, include_executable=False)
        ancestry.append(metadata)
        parent = metadata["parentPid"]
        if not isinstance(parent, int) or isinstance(parent, bool):
            raise PreflightError("owner process ancestry is invalid")
        if parent == 1:
            break
        current = parent
    else:
        raise PreflightError("owner process ancestry exceeds its bound")
    return ancestry


def _looks_like_codex_process(record: Mapping[str, object]) -> bool:
    executable = record.get("executable")
    argv = record.get("argv")
    if not isinstance(executable, str) or not isinstance(argv, list) or any(
        not isinstance(item, str) for item in argv
    ):
        raise PreflightError("owner process ancestry record is invalid")
    return (
        Path(executable).name == "codex"
        or any(Path(item).name == "codex" for item in argv)
        or any("@openai/codex" in item for item in argv)
    )


def _read_owner_process_evidence(
    *, conversation_id: str, project: Path
) -> dict[str, object]:
    expected_argv = ["codex", "resume", conversation_id, "--cd", str(project)]
    ancestry = _read_owner_process_ancestry()
    codex_paths = [
        record
        for record in ancestry
        if _looks_like_codex_process(record)
    ]
    if len(codex_paths) != 1:
        raise PreflightError(
            "preflight does not have exactly one Codex process ancestor"
        )
    candidate = codex_paths[0]
    candidate_identity = (
        candidate["executableDevice"],
        candidate["executableInode"],
    )
    if sum(
        (
            record["executableDevice"],
            record["executableInode"],
        )
        == candidate_identity
        for record in ancestry
    ) != 1:
        raise PreflightError("preflight has multiple Codex process ancestors")
    if candidate["argv"] != expected_argv:
        raise PreflightError("the sole Codex ancestor is not the exact owner process")
    match = _read_process_snapshot(
        int(candidate["pid"]), include_executable=True
    )
    for stable_field in (
        "pid",
        "parentPid",
        "startTime",
        "argv",
        "executable",
        "executableDevice",
        "executableInode",
    ):
        if match[stable_field] != candidate[stable_field]:
            raise PreflightError("owner Codex process changed while inspected")
    if _read_owner_process_ancestry() != ancestry:
        raise PreflightError("owner process ancestry changed while inspected")
    return {
        "executable": match["executable"],
        "device": match["executableDevice"],
        "inode": match["executableInode"],
        "sha256": match["executableSha256"],
        "argv": match["argv"],
    }


def _owner_binding_from_registry(
    *,
    owner_thread: str,
    owner_project: Path,
    registry: Path,
    registry_payload: bytes,
    registry_identity_reader: Callable[[Path], dict[str, int]] | None = None,
    launcher_evidence_reader: Callable[..., dict[str, object]] | None = None,
    owner_process_evidence_reader: Callable[..., dict[str, object]] | None = None,
) -> dict[str, object]:
    if registry_identity_reader is None:
        registry_identity_reader = _codex_registry_object_identity
    if launcher_evidence_reader is None:
        launcher_evidence_reader = _read_launcher_evidence
    if owner_process_evidence_reader is None:
        owner_process_evidence_reader = _read_owner_process_evidence
    conversation_id = _require_exact_conversation_id(owner_thread, label="owner")
    _validate_host_path(owner_project, "owner project")
    _validate_host_path(registry, "Codex projects registry")
    if registry != DEFAULT_CODEX_PROJECTS_REGISTRY:
        raise PreflightError("Codex projects registry is not the authoritative registry")
    try:
        text = registry_payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError("Codex projects registry encoding is invalid") from error
    if "\0" in text:
        raise PreflightError("Codex projects registry encoding is invalid")
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    matches: list[dict[str, str]] = []
    target_uuid = uuid.UUID(conversation_id)
    try:
        if tuple(reader.fieldnames or ()) != _CODEX_REGISTRY_FIELDS:
            raise PreflightError("Codex projects registry header is invalid")
        for row in reader:
            if None in row or any(not isinstance(row.get(field), str) for field in _CODEX_REGISTRY_FIELDS):
                raise PreflightError("Codex projects registry row is invalid")
            try:
                row_uuid = uuid.UUID(row["conversation_id"])
            except (ValueError, AttributeError):
                continue
            if row_uuid == target_uuid:
                if str(row_uuid) != row["conversation_id"]:
                    raise PreflightError(
                        "owner conversation id has a noncanonical registry alias"
                    )
                matches.append({field: row[field] for field in _CODEX_REGISTRY_FIELDS})
    except csv.Error as error:
        raise PreflightError("Codex projects registry CSV is invalid") from error
    if len(matches) != 1:
        raise PreflightError("owner conversation id must appear exactly once in the Codex projects registry")
    match = matches[0]
    if match["project"] != str(owner_project):
        raise PreflightError("registered owner project does not match the exact requested owner project")
    command = match["command"]
    expected_command = f"codex-overseer-{conversation_id}"
    if command != expected_command:
        raise PreflightError("registered owner command is invalid")
    launcher = Path(match["launcher"])
    _validate_host_path(launcher, "registered owner launcher")
    expected_launcher = Path("/home/god/.local/bin") / expected_command
    if launcher != expected_launcher:
        raise PreflightError("registered owner launcher is invalid")
    registry_identity = registry_identity_reader(registry)
    launcher_evidence = launcher_evidence_reader(
        launcher,
        conversation_id=conversation_id,
        project=owner_project,
        command=command,
    )
    process_evidence = owner_process_evidence_reader(
        conversation_id=conversation_id,
        project=owner_project,
    )
    if set(registry_identity) != {"device", "inode"} or set(launcher_evidence) != {
        "device",
        "inode",
        "sha256",
    }:
        raise PreflightError("registered owner object identity is invalid")
    if set(process_evidence) != {"executable", "device", "inode", "sha256", "argv"}:
        raise PreflightError("owner Codex process evidence is invalid")
    process_executable = process_evidence["executable"]
    process_digest = process_evidence["sha256"]
    process_device = process_evidence["device"]
    process_inode = process_evidence["inode"]
    expected_codex_argv = [
        "codex",
        "resume",
        conversation_id,
        "--cd",
        str(owner_project),
    ]
    if not isinstance(process_executable, str):
        raise PreflightError("owner Codex process evidence is invalid")
    _validate_host_path(Path(process_executable), "owner Codex executable")
    if (
        _CODEX_EXECUTABLE_PATH.fullmatch(process_executable) is None
        or
        not isinstance(process_device, int)
        or isinstance(process_device, bool)
        or process_device < 0
        or not isinstance(process_inode, int)
        or isinstance(process_inode, bool)
        or process_inode <= 0
        or not isinstance(process_digest, str)
        or _SHA256.fullmatch(process_digest) is None
        or process_evidence["argv"] != expected_codex_argv
    ):
        raise PreflightError("owner Codex process evidence is invalid")
    row_binding: dict[str, object] = {
        "conversationId": conversation_id,
        "project": str(owner_project),
        "command": command,
        "launcher": str(launcher),
    }
    binding: dict[str, object] = {
        "schemaVersion": OWNER_BINDING_SCHEMA,
        "status": "passed",
        "conversationId": conversation_id,
        "project": str(owner_project),
        "registry": str(registry),
        "registryDevice": registry_identity["device"],
        "registryInode": registry_identity["inode"],
        "registryRow": row_binding,
        "registrySha256": hashlib.sha256(registry_payload).hexdigest(),
        "registryRowDigest": hashlib.sha256(canonical_json(row_binding).encode()).hexdigest(),
        "launcherDevice": launcher_evidence["device"],
        "launcherInode": launcher_evidence["inode"],
        "launcherSha256": launcher_evidence["sha256"],
        "codexExecutable": process_executable,
        "codexExecutableDevice": process_device,
        "codexExecutableInode": process_inode,
        "codexExecutableSha256": process_digest,
        "codexArgv": expected_codex_argv,
    }
    binding["bindingDigest"] = hashlib.sha256(canonical_json(binding).encode()).hexdigest()
    return binding


def _bind_owner_repository(
    binding: Mapping[str, object],
    *,
    owner_identity: Mapping[str, object],
    source_identity: Mapping[str, object],
    expected_source_root: Path,
) -> dict[str, object]:
    repository_fields = {
        "ownerProjectToplevel",
        "sourceRoot",
        "gitCommonDirectory",
        "ownerProjectDevice",
        "ownerProjectInode",
        "sourceRootDevice",
        "sourceRootInode",
        "gitCommonDirectoryDevice",
        "gitCommonDirectoryInode",
    }
    if set(binding) != _OWNER_BINDING_KEYS - repository_fields:
        raise PreflightError("owner binding fields are invalid")
    owner = _validate_repository_identity(owner_identity, label="owner project repository")
    source = _validate_repository_identity(source_identity, label="source repository")
    if owner["topLevel"] != binding["project"]:
        raise PreflightError("owner project repository is not its exact Git top level")
    if source["topLevel"] != str(expected_source_root):
        raise PreflightError("source repository is not its exact Git worktree top level")
    if (
        owner["commonDirectory"] != source["commonDirectory"]
        or owner["commonDevice"] != source["commonDevice"]
        or owner["commonInode"] != source["commonInode"]
    ):
        raise PreflightError("owner project repository does not match the rehearsed source")
    enriched = dict(binding)
    enriched.pop("bindingDigest")
    enriched.update(
        {
            "ownerProjectToplevel": owner["topLevel"],
            "sourceRoot": source["topLevel"],
            "gitCommonDirectory": owner["commonDirectory"],
            "ownerProjectDevice": owner["device"],
            "ownerProjectInode": owner["inode"],
            "sourceRootDevice": source["device"],
            "sourceRootInode": source["inode"],
            "gitCommonDirectoryDevice": owner["commonDevice"],
            "gitCommonDirectoryInode": owner["commonInode"],
        }
    )
    enriched["bindingDigest"] = hashlib.sha256(canonical_json(enriched).encode()).hexdigest()
    return enriched


def _validate_repository_identity(
    value: Mapping[str, object], *, label: str
) -> dict[str, object]:
    if set(value) != _REPOSITORY_IDENTITY_KEYS:
        raise PreflightError(f"{label} identity fields are invalid")
    record = dict(value)
    top_level = Path(record["topLevel"])
    common_directory = Path(record["commonDirectory"])
    _validate_host_path(top_level, f"{label} top level")
    _validate_host_path(common_directory, f"{label} common directory")
    for field in ("device", "inode", "commonDevice", "commonInode"):
        field_value = record[field]
        if (
            not isinstance(field_value, int)
            or isinstance(field_value, bool)
            or field_value < 0
            or (field in {"inode", "commonInode"} and field_value == 0)
        ):
            raise PreflightError(f"{label} identity is invalid")
    return record


def _validate_owner_binding(value: Mapping[str, object]) -> dict[str, object]:
    try:
        if set(value) != _OWNER_BINDING_KEYS:
            raise PreflightError("owner binding fields are invalid")
        binding = dict(value)
        supplied_binding_digest = binding.pop("bindingDigest")
        if (
            binding["schemaVersion"] != OWNER_BINDING_SCHEMA
            or binding["status"] != "passed"
            or not isinstance(supplied_binding_digest, str)
            or _SHA256.fullmatch(supplied_binding_digest) is None
            or hashlib.sha256(canonical_json(binding).encode()).hexdigest()
            != supplied_binding_digest
        ):
            raise PreflightError("owner binding digest is invalid")
        conversation_id = _require_exact_conversation_id(
            binding["conversationId"], label="owner binding"
        )
        project = Path(binding["project"])
        owner_toplevel = Path(binding["ownerProjectToplevel"])
        source_root = Path(binding["sourceRoot"])
        git_common_directory = Path(binding["gitCommonDirectory"])
        registry = Path(binding["registry"])
        codex_executable = Path(binding["codexExecutable"])
        _validate_host_path(project, "owner binding project")
        _validate_host_path(owner_toplevel, "owner binding owner project repository")
        _validate_host_path(source_root, "owner binding source repository")
        _validate_host_path(git_common_directory, "owner binding Git common directory")
        _validate_host_path(registry, "owner binding registry")
        _validate_host_path(codex_executable, "owner binding Codex executable")
        if _CODEX_EXECUTABLE_PATH.fullmatch(str(codex_executable)) is None:
            raise PreflightError("owner binding Codex executable path is invalid")
        _validate_repository_identity(
            {
                "topLevel": str(owner_toplevel),
                "device": binding["ownerProjectDevice"],
                "inode": binding["ownerProjectInode"],
                "commonDirectory": str(git_common_directory),
                "commonDevice": binding["gitCommonDirectoryDevice"],
                "commonInode": binding["gitCommonDirectoryInode"],
            },
            label="owner binding owner project repository",
        )
        _validate_repository_identity(
            {
                "topLevel": str(source_root),
                "device": binding["sourceRootDevice"],
                "inode": binding["sourceRootInode"],
                "commonDirectory": str(git_common_directory),
                "commonDevice": binding["gitCommonDirectoryDevice"],
                "commonInode": binding["gitCommonDirectoryInode"],
            },
            label="owner binding source repository",
        )
        if owner_toplevel != project:
            raise PreflightError("owner binding owner project repository is invalid")
        if registry != DEFAULT_CODEX_PROJECTS_REGISTRY:
            raise PreflightError("owner binding registry is not authoritative")
        row = binding["registryRow"]
        if not isinstance(row, Mapping) or set(row) != _OWNER_REGISTRY_ROW_KEYS:
            raise PreflightError("owner binding registry row is invalid")
        row_binding = dict(row)
        expected_command = f"codex-overseer-{conversation_id}"
        expected_launcher = str(Path("/home/god/.local/bin") / expected_command)
        if (
            row_binding["conversationId"] != conversation_id
            or row_binding["project"] != str(project)
            or row_binding["command"] != expected_command
            or row_binding["launcher"] != expected_launcher
        ):
            raise PreflightError("owner binding registry row is invalid")
        _validate_host_path(Path(row_binding["launcher"]), "owner binding launcher")
        registry_digest = binding["registrySha256"]
        if not isinstance(registry_digest, str) or _SHA256.fullmatch(registry_digest) is None:
            raise PreflightError("owner binding registry digest is invalid")
        for identity_field in (
            "registryDevice",
            "registryInode",
            "launcherDevice",
            "launcherInode",
            "codexExecutableDevice",
            "codexExecutableInode",
        ):
            identity_value = binding[identity_field]
            if (
                not isinstance(identity_value, int)
                or isinstance(identity_value, bool)
                or identity_value < 0
                or (identity_field.endswith("Inode") and identity_value == 0)
            ):
                raise PreflightError("owner binding object identity is invalid")
        launcher_digest = binding["launcherSha256"]
        if not isinstance(launcher_digest, str) or _SHA256.fullmatch(launcher_digest) is None:
            raise PreflightError("owner binding launcher digest is invalid")
        codex_executable_digest = binding["codexExecutableSha256"]
        if (
            not isinstance(codex_executable_digest, str)
            or _SHA256.fullmatch(codex_executable_digest) is None
        ):
            raise PreflightError("owner binding Codex executable digest is invalid")
        expected_codex_argv = [
            "codex",
            "resume",
            conversation_id,
            "--cd",
            str(project),
        ]
        if binding["codexArgv"] != expected_codex_argv:
            raise PreflightError("owner binding Codex process command is invalid")
        supplied_row_digest = binding["registryRowDigest"]
        if (
            not isinstance(supplied_row_digest, str)
            or _SHA256.fullmatch(supplied_row_digest) is None
            or hashlib.sha256(canonical_json(row_binding).encode()).hexdigest()
            != supplied_row_digest
        ):
            raise PreflightError("owner binding registry row digest is invalid")
        return {**binding, "bindingDigest": supplied_binding_digest}
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, PreflightError):
            raise
        raise PreflightError("owner binding is invalid") from error


def _validate_owner_binding_live(
    value: Mapping[str, object], *, source_root: Path
) -> dict[str, object]:
    validated = _validate_owner_binding(value)
    if validated["sourceRoot"] != str(source_root):
        raise PreflightError("owner binding source repository does not match the rendered source")
    registry = Path(validated["registry"])
    try:
        registry_binding = _owner_binding_from_registry(
            owner_thread=str(validated["conversationId"]),
            owner_project=Path(str(validated["project"])),
            registry=registry,
            registry_payload=_read_codex_projects_registry(registry),
        )
        owner_identity = _read_only_repository_identity(
            Path(str(validated["project"]))
        )
        source_identity = _read_only_repository_identity(source_root)
    except PreflightError as error:
        raise PreflightError(
            "owner binding does not match the live Codex projects registry or repository identity"
        ) from error
    current = _bind_owner_repository(
        registry_binding,
        owner_identity=owner_identity,
        source_identity=source_identity,
        expected_source_root=source_root,
    )
    if current != validated:
        raise PreflightError("owner binding does not match the live Codex projects registry")
    return current


def _validate_host_path(path: Path, label: str) -> None:
    text = str(path)
    if (
        not path.is_absolute()
        or text == "/"
        or _HOST_PATH.fullmatch(text) is None
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise PreflightError(f"{label} path is unsafe")


def _safe_artifact_path(value: object) -> str:
    if not isinstance(value, str) or _ARTIFACT_PATH.fullmatch(value) is None:
        raise PreflightError("artifact path is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PreflightError("artifact path is unsafe")
    return value


def _normalized_file_mode(mode: int) -> int:
    return 0o755 if mode & stat.S_IXUSR else 0o644


def _open_relative_artifact(root_descriptor: int, relative: str) -> int:
    relative = _safe_artifact_path(relative)
    parts = PurePosixPath(relative).parts
    cloexec = getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | cloexec | nofollow | getattr(os, "O_DIRECTORY", 0)
    parent_descriptor = os.dup(root_descriptor)
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(
                component, directory_flags, dir_fd=parent_descriptor
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        return os.open(
            parts[-1], os.O_RDONLY | cloexec | nofollow, dir_fd=parent_descriptor
        )
    except OSError as error:
        raise PreflightError(f"artifact file is unavailable: {relative}") from error
    finally:
        os.close(parent_descriptor)


def _read_regular_file_at(
    root_descriptor: int, relative: str
) -> tuple[bytes, int]:
    relative = _safe_artifact_path(relative)
    descriptor = _open_relative_artifact(root_descriptor, relative)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PreflightError(f"artifact file is not a single-link regular file: {relative}")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        before_state = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_state = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_state != after_state:
            raise PreflightError(f"artifact file changed while it was read: {relative}")
        payload = b"".join(chunks)
        if len(payload) != before.st_size:
            raise PreflightError(f"artifact file changed while it was read: {relative}")
        return payload, _normalized_file_mode(before.st_mode)
    finally:
        os.close(descriptor)


def _root_directory_identity(descriptor: int) -> tuple[int, int]:
    state = os.fstat(descriptor)
    if not stat.S_ISDIR(state.st_mode) or state.st_uid != os.geteuid():
        raise PreflightError("artifact root directory object is unsafe")
    return state.st_dev, state.st_ino


def _verify_artifact_root(root: Path, descriptor: int, identity: tuple[int, int]) -> None:
    if _root_directory_identity(descriptor) != identity:
        raise PreflightError("artifact root directory changed while it was read")
    reopened = _open_nofollow_directory(root, label="artifact root directory")
    try:
        if _root_directory_identity(reopened) != identity:
            raise PreflightError("artifact root directory changed while it was read")
    finally:
        os.close(reopened)


def _read_regular_file(root: Path, relative: str) -> tuple[bytes, int]:
    root_descriptor = _open_nofollow_directory(root, label="artifact root directory")
    identity = _root_directory_identity(root_descriptor)
    try:
        result = _read_regular_file_at(root_descriptor, relative)
        _verify_artifact_root(root, root_descriptor, identity)
        return result
    finally:
        os.close(root_descriptor)


def _archive_bytes(entries: Sequence[tuple[str, int, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, strict_timestamps=True) as archive:
        for relative, mode, payload in entries:
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (mode & 0xFFFF) << 16
            info.extra = b""
            info.comment = b""
            archive.writestr(info, payload)
    return output.getvalue()


def _manifest_from_paths(
    root: Path,
    paths: Sequence[str],
    *,
    kind: str,
    max_files: int,
    max_bytes: int,
) -> dict[str, object]:
    unique = sorted(set(paths))
    if not unique or len(unique) != len(paths) or len(unique) > max_files:
        raise PreflightError(f"{kind} artifact file inventory is invalid")
    root_descriptor = _open_nofollow_directory(root, label=f"{kind} artifact root")
    root_identity = _root_directory_identity(root_descriptor)
    try:
        records: list[dict[str, object]] = []
        entries: list[tuple[str, int, bytes]] = []
        total = 0
        for relative in unique:
            payload, mode = _read_regular_file_at(root_descriptor, relative)
            total += len(payload)
            if total > max_bytes:
                raise PreflightError(f"{kind} artifact exceeds the bounded size")
            records.append(
                {
                    "path": relative,
                    "mode": mode,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            entries.append((relative, mode, payload))
        _verify_artifact_root(root, root_descriptor, root_identity)
    finally:
        os.close(root_descriptor)
    archive = _archive_bytes(entries)
    return {
        "schemaVersion": ARTIFACT_MANIFEST_SCHEMA,
        "kind": kind,
        "fileCount": len(records),
        "totalBytes": total,
        "archiveSha256": hashlib.sha256(archive).hexdigest(),
        "files": records,
    }


def build_source_manifest(root: Path, tracked_paths: Sequence[str]) -> dict[str, object]:
    """Build a deterministic manifest from Git-tracked regular files only."""

    return _manifest_from_paths(
        root,
        tuple(tracked_paths),
        kind="source",
        max_files=MAX_SOURCE_FILES,
        max_bytes=MAX_SOURCE_BYTES,
    )


def build_runtime_manifest(root: Path) -> dict[str, object]:
    """Build the bounded offline runtime subset required by the guest."""

    cryptography = root / "cryptography"
    if not cryptography.is_dir() or cryptography.is_symlink():
        raise PreflightError("runtime cryptography package is unavailable")
    paths: list[str] = []
    for candidate in cryptography.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        if "__pycache__" in candidate.parts or candidate.suffix == ".pyc":
            continue
        if candidate.is_symlink():
            raise PreflightError(f"runtime artifact contains a linked file: {relative}")
        if candidate.is_file():
            paths.append(relative)
    backends = sorted(root.glob("_cffi_backend*.so"))
    if not backends:
        raise PreflightError("runtime CFFI backend is unavailable")
    paths.extend(item.relative_to(root).as_posix() for item in backends)
    return _manifest_from_paths(
        root,
        tuple(paths),
        kind="runtime",
        max_files=MAX_RUNTIME_FILES,
        max_bytes=MAX_RUNTIME_BYTES,
    )


def _validate_artifact_manifest(
    manifest: Mapping[str, object], *, kind: str
) -> dict[str, object]:
    record = dict(manifest)
    if set(record) != {
        "schemaVersion",
        "kind",
        "fileCount",
        "totalBytes",
        "archiveSha256",
        "files",
    }:
        raise PreflightError(f"{kind} artifact manifest keys are invalid")
    files = record.get("files")
    max_files, max_bytes = (
        (MAX_SOURCE_FILES, MAX_SOURCE_BYTES)
        if kind == "source"
        else (MAX_RUNTIME_FILES, MAX_RUNTIME_BYTES)
    )
    if (
        record.get("schemaVersion") != ARTIFACT_MANIFEST_SCHEMA
        or record.get("kind") != kind
        or not isinstance(files, list)
        or not files
        or len(files) > max_files
        or record.get("fileCount") != len(files)
        or not isinstance(record.get("archiveSha256"), str)
        or _SHA256.fullmatch(record["archiveSha256"]) is None
    ):
        raise PreflightError(f"{kind} artifact manifest is invalid")
    normalized: list[dict[str, object]] = []
    total = 0
    previous = ""
    for item in files:
        if not isinstance(item, Mapping) or set(item) != {"path", "mode", "size", "sha256"}:
            raise PreflightError(f"{kind} artifact manifest is invalid")
        path = _safe_artifact_path(item.get("path"))
        size = item.get("size")
        mode = item.get("mode")
        digest = item.get("sha256")
        if (
            path <= previous
            or mode not in {0o644, 0o755}
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(digest, str)
            or _SHA256.fullmatch(digest) is None
        ):
            raise PreflightError(f"{kind} artifact manifest is invalid")
        previous = path
        total += size
        normalized.append({"path": path, "mode": mode, "size": size, "sha256": digest})
    if total > max_bytes or record.get("totalBytes") != total:
        raise PreflightError(f"{kind} artifact manifest is invalid")
    record["files"] = normalized
    return record


def build_artifact_archive(root: Path, manifest: Mapping[str, object]) -> bytes:
    """Revalidate exact content and return its deterministic stored ZIP."""

    kind = manifest.get("kind")
    if kind not in {"source", "runtime"}:
        raise PreflightError("artifact manifest kind is invalid")
    validated = _validate_artifact_manifest(manifest, kind=kind)
    root_descriptor = _open_nofollow_directory(root, label=f"{kind} artifact root")
    root_identity = _root_directory_identity(root_descriptor)
    try:
        entries: list[tuple[str, int, bytes]] = []
        for item in validated["files"]:
            payload, mode = _read_regular_file_at(root_descriptor, item["path"])
            if (
                mode != item["mode"]
                or len(payload) != item["size"]
                or hashlib.sha256(payload).hexdigest() != item["sha256"]
            ):
                raise PreflightError(f"{kind} artifact changed after manifest")
            entries.append((item["path"], mode, payload))
        _verify_artifact_root(root, root_descriptor, root_identity)
    finally:
        os.close(root_descriptor)
    archive = _archive_bytes(entries)
    if hashlib.sha256(archive).hexdigest() != validated["archiveSha256"]:
        raise PreflightError(f"{kind} artifact changed after manifest")
    return archive


def _runtime_probe_python() -> str:
    return "\n".join(
        (
            "import fcntl,hashlib,importlib,importlib.abc,importlib.machinery,json,os,stat,sys,sysconfig",
            "from pathlib import Path",
            "sys.dont_write_bytecode=True",
            "sys.pycache_prefix='/proc/overseer-disabled-bytecode-cache'",
            "source=Path(os.path.abspath(sys.argv[1]))",
            "runtime=Path(os.path.abspath(sys.argv[2]))",
            "source_manifest=json.loads(sys.argv[3])",
            "runtime_manifest=json.loads(sys.argv[4])",
            "source_modules=source/'src'",
            "stdlib=Path(sysconfig.get_path('stdlib')).resolve(strict=True)",
            "platstdlib=Path(sysconfig.get_path('platstdlib')).resolve(strict=True)",
            "stdlib_dynamic=(stdlib/'lib-dynload').resolve(strict=True)",
            "def lexical(value): return os.path.abspath(os.path.normpath(os.fspath(value)))",
            "DIR_FLAGS=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_DIRECTORY",
            "def open_root(path):",
            " parts=Path(path).parts[1:]",
            " if not parts: raise ImportError('manifest root path is invalid')",
            " fd=os.open('/',DIR_FLAGS)",
            " try:",
            "  for part in parts:",
            "   next_fd=os.open(part,DIR_FLAGS,dir_fd=fd); os.close(fd); fd=next_fd",
            "  return fd",
            " except BaseException: os.close(fd); raise",
            "source_fd=open_root(source)",
            "runtime_fd=open_root(runtime)",
            "def allowed(root,root_fd,manifest): return {lexical(root/item['path']):(root_fd,item['path'],item) for item in manifest['files']}",
            "allowed_source=allowed(source,source_fd,source_manifest)",
            "allowed_runtime=allowed(runtime,runtime_fd,runtime_manifest)",
            "def open_relative(root_fd,relative):",
            " parts=Path(relative).parts",
            " if not parts or Path(relative).is_absolute() or any(part in ('','.','..') for part in parts): raise ImportError('manifested import path is invalid')",
            " parent=os.dup(root_fd)",
            " try:",
            "  for part in parts[:-1]:",
            "   next_fd=os.open(part,DIR_FLAGS,dir_fd=parent); os.close(parent); parent=next_fd",
            "  return os.open(parts[-1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)",
            " finally: os.close(parent)",
            "def read_verified(root_fd,relative,record):",
            " fd=open_relative(root_fd,relative)",
            " try:",
            "  before=os.fstat(fd)",
            "  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: raise ImportError('manifested import is not a single-link regular file')",
            "  chunks=[]",
            "  while True:",
            "   block=os.read(fd,1048576)",
            "   if not block: break",
            "   chunks.append(block)",
            "  after=os.fstat(fd)",
            " finally: os.close(fd)",
            " if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise ImportError('manifested import changed while read')",
            " payload=b''.join(chunks)",
            " mode=0o755 if before.st_mode&stat.S_IXUSR else 0o644",
            " if mode!=record['mode'] or len(payload)!=record['size'] or hashlib.sha256(payload).hexdigest()!=record['sha256']: raise ImportError('manifested import content mismatch')",
            " return payload",
            "class ManifestSourceLoader(importlib.abc.Loader):",
            " def __init__(self,origin,root_fd,relative,record): self.origin=origin; self.root_fd=root_fd; self.relative=relative; self.record=record",
            " def create_module(self,spec): return None",
            " def exec_module(self,module): exec(compile(read_verified(self.root_fd,self.relative,self.record),self.origin,'exec',dont_inherit=True),module.__dict__)",
            "class ManifestNativeLoader(importlib.abc.Loader):",
            " def __init__(self,fullname,origin,root_fd,relative,record):",
            "  self.fullname=fullname; self.origin=origin; self.fd=os.memfd_create('overseer-manifested-native',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)",
            "  payload=read_verified(root_fd,relative,record)",
            "  view=memoryview(payload)",
            "  while view:",
            "   written=os.write(self.fd,view); view=view[written:]",
            "  os.lseek(self.fd,0,os.SEEK_SET)",
            "  fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)",
            "  self.sealed_origin=f'/proc/self/fd/{self.fd}'",
            "  self.delegate=importlib.machinery.ExtensionFileLoader(fullname,self.sealed_origin)",
            " def _delegate(self,spec,method,*args):",
            "  loader,origin=spec.loader,spec.origin; spec.loader,spec.origin=self.delegate,self.sealed_origin",
            "  try: return getattr(self.delegate,method)(spec,*args) if method=='create_module' else getattr(self.delegate,method)(*args)",
            "  finally: spec.loader,spec.origin=loader,origin",
            " def create_module(self,spec):",
            "  return self._delegate(spec,'create_module')",
            " def exec_module(self,module):",
            "  spec=module.__spec__; self._delegate(spec,'exec_module',module); module.__file__=self.origin; os.close(self.fd); self.fd=-1",
            " def __del__(self):",
            "  if getattr(self,'fd',-1)>=0: os.close(self.fd)",
            "class ManifestFinder(importlib.abc.MetaPathFinder):",
            " def find_spec(self,fullname,path=None,target=None):",
            "  spec=importlib.machinery.PathFinder.find_spec(fullname,path,target)",
            "  if spec is None or spec.origin in (None,'built-in','frozen'): return spec",
            "  origin=lexical(spec.origin)",
            "  in_source=Path(origin).is_relative_to(source)",
            "  in_runtime=Path(origin).is_relative_to(runtime)",
            "  entry=allowed_source.get(origin) if in_source else allowed_runtime.get(origin) if in_runtime else None",
            "  if in_source and entry is None: raise ImportError('source origin is not manifested')",
            "  if in_runtime and entry is None: raise ImportError('runtime origin is not manifested')",
            "  if entry is not None:",
            "   root_fd,relative,record=entry",
            "   spec.loader=ManifestSourceLoader(origin,root_fd,relative,record) if origin.endswith(('.py','.pyw')) else ManifestNativeLoader(fullname,origin,root_fd,relative,record)",
            "  return spec",
            "sys.meta_path.insert(sys.meta_path.index(importlib.machinery.PathFinder),ManifestFinder())",
            "sys.path[:]=list(dict.fromkeys(map(str,(source_modules,runtime,stdlib,platstdlib,stdlib_dynamic))))",
            "assert sys.version_info[:2] == (3,13)",
            f"names={REQUIRED_IMPORTS!r}",
            "origins={}",
            "for name in names:",
            " module=importlib.import_module(name)",
            " origin=Path(lexical(module.__file__))",
            " expected=runtime if name == 'cryptography' else source_modules",
            " origin.relative_to(expected)",
            " origins[name]=str(origin)",
            "digest=lambda value: __import__('hashlib').sha256(json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()).hexdigest()",
            "record={'status':'passed','noBytecode':True,'python':str(Path(sys.executable).resolve()),'pythonVersion':'.'.join(map(str,sys.version_info[:3])),'pythonAbi':sysconfig.get_config_var('SOABI'),'sourceRoot':str(source),'runtimeSite':str(runtime),'sourceManifestDigest':digest(source_manifest),'runtimeManifestDigest':digest(runtime_manifest),'imports':origins}",
            "print(json.dumps(record,ensure_ascii=True,sort_keys=True,separators=(',',':')))",
        )
    )


def _validate_runtime_probe(
    probe: Mapping[str, object],
    *,
    source_root: Path,
    runtime_site: Path,
    source_manifest_digest: str,
    runtime_manifest_digest: str,
) -> dict[str, object]:
    record = dict(probe)
    if set(record) != {
        "status",
        "noBytecode",
        "python",
        "pythonVersion",
        "pythonAbi",
        "sourceRoot",
        "runtimeSite",
        "sourceManifestDigest",
        "runtimeManifestDigest",
        "imports",
    }:
        raise PreflightError("runtime probe is not the exact passed no-bytecode result")
    if (
        record.get("status") != "passed"
        or record.get("noBytecode") is not True
        or record.get("python") != EXACT_TOOLS["python"]
        or record.get("sourceRoot") != str(source_root)
        or record.get("runtimeSite") != str(runtime_site)
        or record.get("sourceManifestDigest") != source_manifest_digest
        or record.get("runtimeManifestDigest") != runtime_manifest_digest
        or not isinstance(record.get("pythonVersion"), str)
        or _PYTHON_VERSION.fullmatch(record["pythonVersion"]) is None
        or not isinstance(record.get("pythonAbi"), str)
        or _PYTHON_ABI.fullmatch(record["pythonAbi"]) is None
    ):
        raise PreflightError("runtime probe is not the exact passed no-bytecode result")
    imports = record.get("imports")
    if not isinstance(imports, Mapping) or set(imports) != set(REQUIRED_IMPORTS):
        raise PreflightError("runtime probe is not the exact passed no-bytecode result")
    normalized: dict[str, str] = {}
    for name in REQUIRED_IMPORTS:
        value = imports.get(name)
        if not isinstance(value, str):
            raise PreflightError("runtime probe is not the exact passed no-bytecode result")
        origin = Path(value)
        _validate_host_path(origin, "runtime probe import")
        expected = runtime_site if name == "cryptography" else source_root / "src"
        if not origin.is_relative_to(expected):
            raise PreflightError("runtime probe is not the exact passed no-bytecode result")
        normalized[name] = value
    record["imports"] = normalized
    return record


def _capability_probe_record() -> dict[str, object]:
    return {
        "status": "passed",
        "libvirtUri": LIBVIRT_URI,
        "domain": "kvm",
        "arch": "x86_64",
        "machine": MACHINE_TYPE,
        "filesystem": {"supported": True, "driverType": "path"},
        "firmware": {
            "mode": "efi",
            "loader": str(FIRMWARE_CODE),
            "loaderType": "pflash",
            "loaderReadonly": True,
            "loaderSecure": False,
            "loaderSha256": FIRMWARE_CODE_SHA256,
            "varsTemplate": str(FIRMWARE_VARS_TEMPLATE),
            "varsTemplateSha256": FIRMWARE_VARS_SHA256,
        },
    }


def _validate_capability_probe(probe: Mapping[str, object]) -> dict[str, object]:
    expected = _capability_probe_record()
    if dict(probe) != expected:
        raise PreflightError("capability probe is not the exact passed KVM filesystem result")
    return expected


def _parse_domain_capabilities(value: str) -> dict[str, object]:
    try:
        root = ElementTree.fromstring(value)
    except ElementTree.ParseError as error:
        raise PreflightError("KVM domain capabilities are unavailable") from error
    filesystem = root.find("./devices/filesystem")
    drivers = {
        item.text
        for item in root.findall("./devices/filesystem/enum[@name='driverType']/value")
    }
    firmware = {item.text for item in root.findall("./os/enum[@name='firmware']/value")}
    loaders = {item.text for item in root.findall("./os/loader/value")}
    loader_types = {
        item.text for item in root.findall("./os/loader/enum[@name='type']/value")
    }
    loader_readonly = {
        item.text for item in root.findall("./os/loader/enum[@name='readonly']/value")
    }
    loader_secure = {
        item.text for item in root.findall("./os/loader/enum[@name='secure']/value")
    }
    if (
        root.findtext("domain") != "kvm"
        or root.findtext("arch") != "x86_64"
        or root.findtext("machine") != MACHINE_TYPE
        or filesystem is None
        or filesystem.get("supported") != "yes"
        or "path" not in drivers
        or "efi" not in firmware
        or str(FIRMWARE_CODE) not in loaders
        or "pflash" not in loader_types
        or "yes" not in loader_readonly
        or "no" not in loader_secure
    ):
        raise PreflightError("KVM path filesystem capability is unavailable")
    return _capability_probe_record()


def _capability_probe_python() -> str:
    return "\n".join(
        (
            "import json,sys",
            "from xml.etree import ElementTree",
            "root=ElementTree.fromstring(sys.stdin.read())",
            "filesystem=root.find('./devices/filesystem')",
            "drivers={item.text for item in root.findall(\"./devices/filesystem/enum[@name='driverType']/value\")}",
            "firmware={item.text for item in root.findall(\"./os/enum[@name='firmware']/value\")}",
            "loaders={item.text for item in root.findall('./os/loader/value')}",
            "loader_types={item.text for item in root.findall(\"./os/loader/enum[@name='type']/value\")}",
            "loader_readonly={item.text for item in root.findall(\"./os/loader/enum[@name='readonly']/value\")}",
            "loader_secure={item.text for item in root.findall(\"./os/loader/enum[@name='secure']/value\")}",
            "assert root.findtext('domain') == 'kvm'",
            "assert root.findtext('arch') == 'x86_64'",
            f"assert root.findtext('machine') == {MACHINE_TYPE!r}",
            "assert filesystem is not None and filesystem.get('supported') == 'yes'",
            "assert 'path' in drivers",
            "assert 'efi' in firmware",
            f"assert {str(FIRMWARE_CODE)!r} in loaders",
            "assert 'pflash' in loader_types",
            "assert 'yes' in loader_readonly",
            "assert 'no' in loader_secure",
            f"record={_capability_probe_record()!r}",
            "print(json.dumps(record,ensure_ascii=True,sort_keys=True,separators=(',',':')))",
        )
    )


def _read_only_runner(command: tuple[str, ...]) -> str:
    """Run one explicit read-only probe with exact executables and environment."""

    label = command[0]
    if label == "git-status":
        argv = (
            EXACT_TOOLS["git"],
            *_GIT_SAFE_FLAGS,
            "-C",
            command[1],
            "status",
            "--porcelain",
            "--untracked-files=all",
        )
    elif label == "git-toplevel":
        argv = (
            EXACT_TOOLS["git"],
            *_GIT_SAFE_FLAGS,
            "-C",
            command[1],
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
        )
    elif label == "git-common-dir":
        argv = (
            EXACT_TOOLS["git"],
            *_GIT_SAFE_FLAGS,
            "-C",
            command[1],
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        )
    elif label == "git-head":
        argv = (
            EXACT_TOOLS["git"],
            *_GIT_SAFE_FLAGS,
            "-C",
            command[1],
            "rev-parse",
            "HEAD",
        )
    elif label == "git-files":
        argv = (
            EXACT_TOOLS["git"],
            *_GIT_SAFE_FLAGS,
            "-C",
            command[1],
            "ls-files",
            "-z",
        )
    elif label == "libvirt-uri":
        argv = (EXACT_TOOLS["virsh"], "--connect", LIBVIRT_URI, "uri")
    elif label == "domains":
        argv = (EXACT_TOOLS["virsh"], "--connect", LIBVIRT_URI, "list", "--all", "--name")
    elif label == "domain-capabilities":
        argv = (
            EXACT_TOOLS["virsh"],
            "--connect",
            LIBVIRT_URI,
            "domcapabilities",
            "--virttype",
            "kvm",
            "--arch",
            "x86_64",
            "--machine",
            MACHINE_TYPE,
        )
    elif label == "qemu-img-info":
        argv = (
            EXACT_TOOLS["qemu-img"],
            "info",
            "--output=json",
            "--force-share",
            command[1],
        )
    elif label == "import-probe":
        argv = (
            EXACT_TOOLS["python"],
            "-B",
            "-s",
            "-P",
            "-S",
            "-c",
            _runtime_probe_python(),
            command[1],
            command[2],
            command[3],
            command[4],
        )
    else:
        raise PreflightError(f"unsupported preflight probe: {label}")
    completed = subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=MINIMAL_ENV,
    )
    return completed.stdout if label == "git-files" else completed.stdout.strip()


def _require_path_state(
    path: Path,
    *,
    label: str,
    expected_kind: str,
    access_mode: int,
    path_exists: Callable[[Path], bool],
    path_stat: Callable[[Path], object],
    path_access: Callable[[Path, int], bool],
    is_symlink: Callable[[Path], bool],
) -> int:
    if not path_exists(path) or is_symlink(path):
        raise PreflightError(f"{label} is missing or linked")
    try:
        mode = path_stat(path).st_mode
    except OSError as error:
        raise PreflightError(f"{label} state is unavailable") from error
    kind_ok = {
        "directory": stat.S_ISDIR,
        "regular": stat.S_ISREG,
        "character": stat.S_ISCHR,
    }[expected_kind](mode)
    if not kind_ok:
        raise PreflightError(f"{label} is not a {expected_kind} object")
    if not path_access(path, access_mode):
        raise PreflightError(f"{label} is not caller-accessible")
    return mode


def _validate_temp_mode(mode: int) -> None:
    if mode & (stat.S_IWGRP | stat.S_IWOTH) and not mode & stat.S_ISVTX:
        raise PreflightError("temporary path permissions are unsafe")


def _validate_session_runtime_directory(
    *,
    path_exists: Callable[[Path], bool],
    path_stat: Callable[[Path], object],
    path_access: Callable[[Path, int], bool],
    is_symlink: Callable[[Path], bool],
) -> None:
    """Bind libvirt probes and execution to this caller's private user session."""

    expected = Path("/run/user") / str(os.geteuid())
    if SESSION_RUNTIME_DIR != expected:
        raise PreflightError("session runtime path is not the exact caller path")
    if not path_exists(expected) or is_symlink(expected):
        raise PreflightError("session runtime directory is missing or linked")
    try:
        state = path_stat(expected)
    except OSError as error:
        raise PreflightError("session runtime directory state is unavailable") from error
    if not stat.S_ISDIR(state.st_mode):
        raise PreflightError("session runtime path is not a directory object")
    if state.st_uid != os.geteuid():
        raise PreflightError("session runtime directory ownership is unsafe")
    if stat.S_IMODE(state.st_mode) != 0o700:
        raise PreflightError("session runtime directory permissions are unsafe")
    if not path_access(expected, os.R_OK | os.W_OK | os.X_OK):
        raise PreflightError("session runtime directory is not caller-accessible")


def _validate_exact_tools(
    *,
    tool_exists: Callable[[Path], bool],
    tool_stat: Callable[[Path], object],
    tool_access: Callable[[Path, int], bool],
) -> None:
    for label, value in EXACT_TOOLS.items():
        path = Path(value)
        try:
            state = tool_stat(path)
        except OSError as error:
            raise PreflightError(f"required tooling is missing: {label}") from error
        if (
            not tool_exists(path)
            or not stat.S_ISREG(state.st_mode)
            or state.st_uid != 0
            or state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or getattr(state, "st_nlink", 1) != 1
            or not tool_access(path, os.R_OK | os.X_OK)
        ):
            raise PreflightError(f"required tooling is unsafe or missing: {label}")


def _manifest_digest(manifest: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_json(manifest).encode()).hexdigest()


def _run_identity(
    source_commit: str, source_manifest_digest: str, runtime_manifest_digest: str
) -> tuple[str, str, str]:
    material = f"{source_commit}:{source_manifest_digest}:{runtime_manifest_digest}"
    run_id = hashlib.sha256(material.encode()).hexdigest()
    vm_uuid = str(uuid.uuid5(_RUN_NAMESPACE, material))
    vm_name = (
        f"overseer-phase-b-rehearsal-"
        f"{source_commit[:12]}-{source_manifest_digest[:12]}"
    )
    return run_id, vm_uuid, vm_name


def _plan_inputs(
    *, source_manifest: Mapping[str, object], runtime_manifest: Mapping[str, object]
) -> dict[str, object]:
    return {
        "networkDevices": [],
        "hostFilesystemShares": [],
        "sourceArtifact": {
            "isoPath": "source.zip",
            "manifestPath": "source-manifest.json",
            "manifest": dict(source_manifest),
            "manifestDigest": _manifest_digest(source_manifest),
        },
        "runtimeArtifact": {
            "isoPath": "runtime.zip",
            "manifestPath": "runtime-manifest.json",
            "manifest": dict(runtime_manifest),
            "manifestDigest": _manifest_digest(runtime_manifest),
        },
    }


def preflight(
    *,
    source_commit: str,
    repo_root: Path,
    source_root: Path,
    owner_thread: str,
    owner_project: Path,
    codex_projects_registry: Path = DEFAULT_CODEX_PROJECTS_REGISTRY,
    registry_reader: Callable[[Path], bytes] = _read_codex_projects_registry,
    registry_identity_reader: Callable[
        [Path], dict[str, int]
    ] = _codex_registry_object_identity,
    launcher_evidence_reader: Callable[..., dict[str, object]] = _read_launcher_evidence,
    owner_process_evidence_reader: Callable[
        ..., dict[str, object]
    ] = _read_owner_process_evidence,
    runtime_site: Path = DEFAULT_RUNTIME_SITE,
    base_image: Path = DEFAULT_BASE_IMAGE,
    temp_parent: Path = DEFAULT_TEMP_PARENT,
    runner: Callable[[tuple[str, ...]], str] = _read_only_runner,
    repository_identity_probe: Callable[
        [Path], dict[str, object]
    ] = _read_only_repository_identity,
    source_git_probe: Callable[[Path], dict[str, str]] = _read_only_source_git_state,
    path_exists: Callable[[Path], bool] = lambda path: path.exists(),
    path_stat: Callable[[Path], object] = lambda path: path.stat(),
    path_access: Callable[[Path, int], bool] = os.access,
    is_symlink: Callable[[Path], bool] = lambda path: path.is_symlink(),
    image_sha512: Callable[[Path], str] = sha512_file,
    firmware_sha256: Callable[[Path], str] = sha256_file,
    tool_exists: Callable[[Path], bool] = lambda path: path.exists(),
    tool_stat: Callable[[Path], object] = lambda path: path.stat(),
    tool_access: Callable[[Path, int], bool] = os.access,
    source_manifest_builder: Callable[
        [Path, Sequence[str]], dict[str, object]
    ] = build_source_manifest,
    runtime_manifest_builder: Callable[[Path], dict[str, object]] = build_runtime_manifest,
) -> dict[str, object]:
    """Perform only read-only checks and return digest-bindable evidence."""

    _require_full_source_commit(source_commit)
    for path, label in (
        (repo_root, "repository"),
        (source_root, "source"),
        (owner_project, "owner project"),
        (codex_projects_registry, "Codex projects registry"),
        (runtime_site, "runtime"),
        (base_image, "base image"),
        (FIRMWARE_CODE, "firmware code"),
        (FIRMWARE_VARS_TEMPLATE, "firmware variables template"),
        (temp_parent, "temporary"),
        (SESSION_RUNTIME_DIR, "session runtime"),
    ):
        _validate_host_path(path, label)
    if repo_root != source_root:
        raise PreflightError("source path must be the validated repository root")
    if codex_projects_registry != DEFAULT_CODEX_PROJECTS_REGISTRY:
        raise PreflightError("Codex projects registry is not the authoritative registry")
    registry_mode = _require_path_state(
        codex_projects_registry,
        label="Codex projects registry",
        expected_kind="regular",
        access_mode=os.R_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    try:
        registry_state = path_stat(codex_projects_registry)
    except OSError as error:
        raise PreflightError("Codex projects registry state is unavailable") from error
    if (
        registry_state.st_uid != os.geteuid()
        or getattr(registry_state, "st_nlink", 1) != 1
        or registry_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise PreflightError("Codex projects registry object is unsafe")
    owner_binding = _owner_binding_from_registry(
        owner_thread=owner_thread,
        owner_project=owner_project,
        registry=codex_projects_registry,
        registry_payload=registry_reader(codex_projects_registry),
        registry_identity_reader=registry_identity_reader,
        launcher_evidence_reader=launcher_evidence_reader,
        owner_process_evidence_reader=owner_process_evidence_reader,
    )
    _validate_session_runtime_directory(
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    try:
        owner_identity = repository_identity_probe(owner_project)
        source_identity = repository_identity_probe(source_root)
    except (OSError, ValueError) as error:
        raise PreflightError("owner project repository identity is unavailable") from error
    owner_binding = _bind_owner_repository(
        owner_binding,
        owner_identity=owner_identity,
        source_identity=source_identity,
        expected_source_root=source_root,
    )
    git_state = source_git_probe(repo_root)
    if set(git_state) != {"status", "head", "files"} or any(
        not isinstance(git_state[field], str) for field in ("status", "head", "files")
    ):
        raise PreflightError("source Git state probe is invalid")
    if git_state["status"]:
        raise PreflightError("source tree is dirty")
    if git_state["head"] != source_commit:
        raise PreflightError("source commit does not match the requested full SHA")
    tracked_raw = git_state["files"]
    if "\n" in tracked_raw and "\0" not in tracked_raw:
        raise PreflightError("tracked source inventory is not NUL-delimited")
    tracked = tuple(item for item in tracked_raw.split("\0") if item)

    kvm = Path("/dev/kvm")
    _require_path_state(
        kvm,
        label="KVM device",
        expected_kind="character",
        access_mode=os.R_OK | os.W_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    source_mode = _require_path_state(
        source_root,
        label="source path",
        expected_kind="directory",
        access_mode=os.R_OK | os.X_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    runtime_mode = _require_path_state(
        runtime_site,
        label="runtime path",
        expected_kind="directory",
        access_mode=os.R_OK | os.X_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    base_mode = _require_path_state(
        base_image,
        label="base image",
        expected_kind="regular",
        access_mode=os.R_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    firmware_code_mode = _require_path_state(
        FIRMWARE_CODE,
        label="firmware code",
        expected_kind="regular",
        access_mode=os.R_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    firmware_vars_mode = _require_path_state(
        FIRMWARE_VARS_TEMPLATE,
        label="firmware variables template",
        expected_kind="regular",
        access_mode=os.R_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    temp_mode = _require_path_state(
        temp_parent,
        label="temporary path",
        expected_kind="directory",
        access_mode=os.R_OK | os.W_OK | os.X_OK,
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    if source_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PreflightError("source path permissions are unsafe")
    if runtime_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PreflightError("runtime path permissions are unsafe")
    if base_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PreflightError("base image permissions are unsafe")
    if firmware_code_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PreflightError("firmware code permissions are unsafe")
    if firmware_vars_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PreflightError("firmware variables template permissions are unsafe")
    for path, label in (
        (FIRMWARE_CODE, "firmware code"),
        (FIRMWARE_VARS_TEMPLATE, "firmware variables template"),
    ):
        try:
            firmware_state = path_stat(path)
        except OSError as error:
            raise PreflightError(f"{label} state is unavailable") from error
        if firmware_state.st_uid != 0 or getattr(firmware_state, "st_nlink", 1) != 1:
            raise PreflightError(f"{label} ownership is unsafe")
    _validate_temp_mode(temp_mode)
    _validate_exact_tools(
        tool_exists=tool_exists, tool_stat=tool_stat, tool_access=tool_access
    )

    source_manifest = _validate_artifact_manifest(
        source_manifest_builder(source_root, tracked), kind="source"
    )
    runtime_manifest = _validate_artifact_manifest(
        runtime_manifest_builder(runtime_site), kind="runtime"
    )
    source_manifest_digest = _manifest_digest(source_manifest)
    runtime_manifest_digest = _manifest_digest(runtime_manifest)
    run_id, vm_uuid, target_name = _run_identity(
        source_commit, source_manifest_digest, runtime_manifest_digest
    )

    if runner(("libvirt-uri",)) != LIBVIRT_URI:
        raise PreflightError("libvirt URI is not qemu:///session")
    domains = {line.strip() for line in runner(("domains",)).splitlines() if line.strip()}
    if target_name in domains:
        raise PreflightError(f"target VM already exists: {target_name}")
    capability_probe = _parse_domain_capabilities(runner(("domain-capabilities",)))
    capability_probe_digest = _manifest_digest(capability_probe)
    try:
        image_info = json.loads(runner(("qemu-img-info", str(base_image))))
    except (json.JSONDecodeError, TypeError) as error:
        raise PreflightError("base image qcow2 metadata is unavailable") from error
    if not isinstance(image_info, dict) or image_info.get("format") != "qcow2":
        raise PreflightError("base image is not qcow2")
    if any(key in image_info for key in ("backing-filename", "full-backing-filename")):
        raise PreflightError("base image must not have a backing file")
    try:
        if image_sha512(base_image).lower() != BASE_IMAGE_SHA512:
            raise PreflightError("base image SHA-512 is unverified")
    except (OSError, ValueError, AttributeError) as error:
        raise PreflightError("base image SHA-512 could not be verified") from error
    for path, expected, label in (
        (FIRMWARE_CODE, FIRMWARE_CODE_SHA256, "firmware code"),
        (
            FIRMWARE_VARS_TEMPLATE,
            FIRMWARE_VARS_SHA256,
            "firmware variables template",
        ),
    ):
        try:
            if firmware_sha256(path).lower() != expected:
                raise PreflightError(f"{label} SHA-256 is unverified")
        except (OSError, ValueError, AttributeError) as error:
            raise PreflightError(f"{label} SHA-256 could not be verified") from error

    try:
        probe_output = json.loads(
            runner(
                (
                    "import-probe",
                    str(source_root),
                    str(runtime_site),
                    canonical_json(source_manifest),
                    canonical_json(runtime_manifest),
                )
            )
        )
    except (json.JSONDecodeError, TypeError) as error:
        raise PreflightError("runtime import probe failed") from error
    if not isinstance(probe_output, Mapping):
        raise PreflightError("runtime import probe failed")
    try:
        runtime_probe = _validate_runtime_probe(
            probe_output,
            source_root=source_root,
            runtime_site=runtime_site,
            source_manifest_digest=source_manifest_digest,
            runtime_manifest_digest=runtime_manifest_digest,
        )
    except PreflightError as error:
        raise PreflightError("runtime import probe failed") from error
    final_owner_identity = _validate_repository_identity(
        repository_identity_probe(owner_project), label="owner project repository"
    )
    final_source_identity = _validate_repository_identity(
        repository_identity_probe(source_root), label="source repository"
    )
    if final_owner_identity != owner_identity or final_source_identity != source_identity:
        raise PreflightError("owner or source repository identity changed during preflight")
    probe_digest = _manifest_digest(runtime_probe)
    inputs = _plan_inputs(
        source_manifest=source_manifest, runtime_manifest=runtime_manifest
    )
    return {
        "status": "passed",
        "sourceCommit": source_commit,
        "runId": run_id,
        "targetVm": target_name,
        "targetVmUuid": vm_uuid,
        "libvirtUri": LIBVIRT_URI,
        "baseImageSha512": BASE_IMAGE_SHA512,
        "firmware": dict(_capability_probe_record()["firmware"]),
        "runtimeProbe": runtime_probe,
        "runtimeProbeDigest": probe_digest,
        "capabilityProbe": capability_probe,
        "capabilityProbeDigest": capability_probe_digest,
        "sourceManifest": source_manifest,
        "sourceManifestDigest": source_manifest_digest,
        "runtimeManifest": runtime_manifest,
        "runtimeManifestDigest": runtime_manifest_digest,
        "planInputs": inputs,
        "checkedTools": dict(EXACT_TOOLS),
        "sessionRuntimeDirectory": str(SESSION_RUNTIME_DIR),
        "ownerBinding": owner_binding,
        "tempDirectoryCreated": False,
    }


def _artifact_extractor_python() -> str:
    return r"""import hashlib,json,os,stat,sys,zipfile
from pathlib import Path,PurePosixPath

archive_path,manifest_path,destination,expected_digest=sys.argv[1:]
manifest=json.loads(Path(manifest_path).read_text(encoding="ascii"))
canonical=json.dumps(manifest,ensure_ascii=True,sort_keys=True,separators=(",",":"))
if hashlib.sha256(canonical.encode()).hexdigest()!=expected_digest:
    raise SystemExit("artifact manifest digest mismatch")
if set(manifest)!={"schemaVersion","kind","fileCount","totalBytes","archiveSha256","files"}:
    raise SystemExit("artifact manifest keys invalid")
archive_bytes=Path(archive_path).read_bytes()
if hashlib.sha256(archive_bytes).hexdigest()!=manifest["archiveSha256"]:
    raise SystemExit("artifact archive digest mismatch")
root=Path(destination)
if root.exists():
    if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
        raise SystemExit("artifact destination is not an empty directory")
else:
    root.mkdir(parents=True,exist_ok=False)
with zipfile.ZipFile(archive_path,"r") as archive:
    infos=archive.infolist()
    files=manifest["files"]
    if len(infos)!=len(files) or [item.filename for item in infos]!=[item["path"] for item in files]:
        raise SystemExit("artifact archive inventory mismatch")
    total=0
    for info,item in zip(infos,files,strict=True):
        relative=PurePosixPath(item["path"])
        if relative.is_absolute() or any(part in {"",".",".."} for part in relative.parts):
            raise SystemExit("artifact archive path invalid")
        mode=(info.external_attr>>16)&0xFFFF
        if info.is_dir() or stat.S_IFMT(mode) not in {0,stat.S_IFREG} or (mode&0o777)!=item["mode"]:
            raise SystemExit("artifact archive mode invalid")
        payload=archive.read(info)
        total+=len(payload)
        if len(payload)!=item["size"] or hashlib.sha256(payload).hexdigest()!=item["sha256"]:
            raise SystemExit("artifact archive content mismatch")
        target=root.joinpath(*relative.parts)
        target.parent.mkdir(parents=True,exist_ok=True)
        descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,item["mode"])
        try:
            view=memoryview(payload)
            while view:
                written=os.write(descriptor,view)
                view=view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(target,item["mode"],follow_symlinks=False)
if total!=manifest["totalBytes"]:
    raise SystemExit("artifact archive total mismatch")
"""


def _cloud_init(
    runtime_probe: Mapping[str, object],
    source_commit: str,
    source_manifest_digest: str,
    runtime_manifest_digest: str,
) -> str:
    _require_full_source_commit(source_commit)
    python_abi = runtime_probe["pythonAbi"]
    if not isinstance(python_abi, str) or _PYTHON_ABI.fullmatch(python_abi) is None:
        raise PreflightError("runtime probe Python ABI is invalid")
    extractor = _artifact_extractor_python()
    lines = [
        "#cloud-config",
        "users: []",
        "disable_root: true",
        "ssh_pwauth: false",
        "ssh_deletekeys: true",
        "write_files:",
        "  - path: /usr/local/sbin/overseer-extract-artifacts.py",
        "    owner: root:root",
        "    permissions: '0500'",
        "    content: |",
    ]
    lines.extend(f"      {line}" for line in extractor.splitlines())
    lines.extend(
        (
            "  - path: /etc/overseer-phase-b-rehearsal/source-commit",
            "    owner: root:root",
            "    permissions: '0444'",
            "    content: |",
            f"      {source_commit}",
        )
    )
    for path in TASK_TWO_PLACEHOLDERS:
        lines.extend(
            (
                f"  - path: {path}",
                "    owner: root:root",
                "    permissions: '0644'",
                "    content: ''",
            )
        )
    placeholders = " ".join(TASK_TWO_PLACEHOLDERS)
    lines.extend(
        (
            "runcmd:",
            "  - |",
            "    /usr/bin/bash -ceu '",
            "      /usr/bin/install -d -m 0700 /mnt/overseer-seed",
            "      /usr/bin/mount -o ro LABEL=cidata /mnt/overseer-seed",
            "      /usr/bin/python3.13 -B -s -P -S /usr/local/sbin/overseer-extract-artifacts.py /mnt/overseer-seed/source.zip /mnt/overseer-seed/source-manifest.json /opt/overseer-source "
            + source_manifest_digest,
            "      /usr/bin/python3.13 -B -s -P -S /usr/local/sbin/overseer-extract-artifacts.py /mnt/overseer-seed/runtime.zip /mnt/overseer-seed/runtime-manifest.json /usr/local/lib/python3.13/dist-packages "
            + runtime_manifest_digest,
            "      /usr/bin/mount --bind /opt/overseer-source /opt/overseer-source",
            "      /usr/bin/mount -o remount,bind,ro,nosuid,nodev /opt/overseer-source",
            "      /usr/bin/mount --bind /usr/local/lib/python3.13/dist-packages /usr/local/lib/python3.13/dist-packages",
            "      /usr/bin/mount -o remount,bind,ro,nosuid,nodev /usr/local/lib/python3.13/dist-packages",
            "      /usr/sbin/groupadd --gid 984 overseer",
            "      /usr/sbin/useradd --uid 984 --gid 984 --no-create-home --shell /usr/sbin/nologin overseer",
            "      /usr/sbin/groupadd --gid 1000 god",
            "      /usr/sbin/useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash god",
            "      test \"$(getent passwd 984 | cut -d: -f1,3,4)\" = overseer:984:984",
            "      test \"$(getent passwd 1000 | cut -d: -f1,3,4)\" = god:1000:1000",
            f'      PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONPATH=/opt/overseer-source/src:/usr/local/lib/python3.13/dist-packages /usr/bin/python3.13 -B -s -P -S -c "import sys,sysconfig; from pathlib import Path; assert sys.version_info[:2] == (3,13); assert sysconfig.get_config_var(\\"SOABI\\") == \\"{python_abi}\\"; import cryptography; import overseer.cli; import overseer.user_bridge; import overseer.admin_executor; import _cffi_backend; runtime=Path(\\"/usr/local/lib/python3.13/dist-packages\\").resolve(); source=Path(\\"/opt/overseer-source/src\\").resolve(); Path(cryptography.__file__).resolve().relative_to(runtime); Path(_cffi_backend.__file__).resolve().relative_to(runtime); Path(overseer.cli.__file__).resolve().relative_to(source); Path(overseer.user_bridge.__file__).resolve().relative_to(source); Path(overseer.admin_executor.__file__).resolve().relative_to(source)"',
            "      /usr/bin/install -D -m 0755 /opt/overseer-source/tests/phase_b_rehearsal/guest_rehearsal.py /opt/overseer-phase-b-rehearsal/guest_rehearsal.py",
            "      /usr/bin/install -D -m 0644 /opt/overseer-source/tests/phase_b_rehearsal/guest_rehearsal.service /etc/systemd/system/overseer-phase-b-rehearsal.service",
            f"      for placeholder in {placeholders}; do test ! -s \"$placeholder\"; chown root:root \"$placeholder\"; chmod 0644 \"$placeholder\"; done",
            "      /usr/bin/systemctl daemon-reload",
            "      /usr/bin/systemctl start overseer-phase-b-rehearsal.service",
            "    '",
        )
    )
    return "\n".join(lines) + "\n"


def _meta_data(vm_name: str) -> str:
    return f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n"


def _domain_xml(*, vm_name: str, vm_uuid: str, run_id: str) -> str:
    return f"""<domain type='kvm'>
  <name>{escape(vm_name)}</name>
  <uuid>{escape(vm_uuid)}</uuid>
  <metadata><overseer:run xmlns:overseer='urn:overseer:phase-b-rehearsal' id='{run_id}'/></metadata>
  <memory unit='MiB'>{MEMORY_MIB}</memory>
  <currentMemory unit='MiB'>{MEMORY_MIB}</currentMemory>
  <vcpu placement='static'>{VCPUS}</vcpu>
  <os firmware='efi'>
    <type arch='x86_64' machine='{MACHINE_TYPE}'>hvm</type>
    <loader readonly='yes' secure='no' type='pflash'>{escape(str(FIRMWARE_CODE))}</loader>
    <nvram template='{escape(str(FIRMWARE_VARS_TEMPLATE))}'>${{NVRAM}}</nvram>
    <boot dev='hd'/>
  </os>
  <features><acpi/></features>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='${{OVERLAY}}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='${{SEED_ISO}}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <serial type='pipe'>
      <source path='${{SERIAL_PIPE}}'/>
      <target type='isa-serial' port='0'/>
    </serial>
    <console type='pty'><target type='serial' port='0'/></console>
  </devices>
</domain>
"""


def _result_validator_python() -> str:
    controls = repr(sorted(REQUIRED_CONTROLS))
    return f"""import json,re,sys

MAX_SERIAL_BYTES={MAX_SERIAL_BYTES}
MAX_SERIAL_LINE_BYTES={MAX_SERIAL_LINE_BYTES}
begin=b"OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN"
end=b"OVERSEER_PHASE_B_REHEARSAL_RESULT_END"
total=0
buffer=b""
begin_count=0
end_count=0
state="before"
payload=None
with open(sys.argv[1],"rb",buffering=0) as stream:
    while True:
        chunk=stream.read(65536)
        if not chunk: break
        total+=len(chunk)
        if total>MAX_SERIAL_BYTES: raise SystemExit("serial output exceeded the bounded limit")
        buffer+=chunk
        if len(buffer)>MAX_SERIAL_LINE_BYTES and b"\\n" not in buffer:
            raise SystemExit("serial output line exceeded the bounded limit")
        while b"\\n" in buffer:
            raw,buffer=buffer.split(b"\\n",1)
            if len(raw)>MAX_SERIAL_LINE_BYTES: raise SystemExit("serial output line exceeded the bounded limit")
            raw.decode("utf-8","strict")
            if raw==begin:
                begin_count+=1
                if state!="before": raise SystemExit("exactly one complete sentinel pair is required")
                state="payload"
            elif raw==end:
                end_count+=1
                if state!="end": raise SystemExit("sentinel pair must frame exactly one JSON line")
                state="after"
            elif state=="payload":
                payload=raw.decode("utf-8","strict")
                state="end"
            elif state=="end":
                raise SystemExit("sentinel pair must frame exactly one JSON line")
if buffer:
    if len(buffer)>MAX_SERIAL_LINE_BYTES: raise SystemExit("serial output line exceeded the bounded limit")
    buffer.decode("utf-8","strict")
    if buffer in {{begin,end}}: raise SystemExit("exactly one complete sentinel pair is required")
if begin_count!=1 or end_count!=1 or state!="after" or payload is None:
    raise SystemExit("exactly one complete sentinel pair is required")
record=json.loads(payload)
canonical=json.dumps(record,ensure_ascii=True,sort_keys=True,separators=(",",":"))
if canonical!=payload: raise SystemExit("result is not canonical JSON")
if set(record)!={{"schemaVersion","status","stage","controls","identifiers","failure"}}: raise SystemExit("result key set is invalid")
if record.get("schemaVersion")!="{RESULT_SCHEMA}": raise SystemExit("result schema is invalid")
if record.get("status")!="passed" or record.get("stage")!="phase-complete": raise SystemExit("rehearsal did not pass completely")
required_controls={controls}
actual=record.get("controls")
if not isinstance(actual,dict) or set(actual)!=set(required_controls) or any(value is not True for value in actual.values()): raise SystemExit("result controls are incomplete")
if record.get("failure") is not None: raise SystemExit("passing result contains failure data")
identifiers=record.get("identifiers")
if not isinstance(identifiers,dict): raise SystemExit("identifiers are invalid")
secret_markers=re.compile(r"(?:secret|token|password|credential|verifier|private[_ -]?key|argv|environment|human[_ -]?input)",re.I)
for key,value in identifiers.items():
    if secret_markers.search(str(key)) or secret_markers.search(str(value)): raise SystemExit("result contains a secret marker")
for forbidden in ("phase-b-rehearsal-admin-secret","phase-b-rehearsal-roadex-secret","phase-b-rehearsal-api-token"):
    if forbidden in payload: raise SystemExit("result contains secret material")
print(payload)
"""


def _firmware_validator_python() -> str:
    return r"""import hashlib,os,stat,sys
if len(sys.argv)!=5: raise SystemExit("firmware validator argument set is invalid")
def verify(path,expected):
    if len(expected)!=64 or expected.lower()!=expected or any(value not in "0123456789abcdef" for value in expected): raise SystemExit("firmware digest is invalid")
    try: path_state=os.lstat(path)
    except OSError as error: raise SystemExit("firmware path is unavailable") from error
    if not stat.S_ISREG(path_state.st_mode) or path_state.st_uid!=0 or path_state.st_nlink!=1 or path_state.st_mode&(stat.S_IWGRP|stat.S_IWOTH): raise SystemExit("firmware path state is unsafe")
    flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
    try: descriptor=os.open(path,flags)
    except OSError as error: raise SystemExit("firmware path cannot be opened safely") from error
    try:
        before=os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1 or before.st_mode&(stat.S_IWGRP|stat.S_IWOTH): raise SystemExit("firmware descriptor state is unsafe")
        if (path_state.st_dev,path_state.st_ino)!=(before.st_dev,before.st_ino): raise SystemExit("firmware path changed before read")
        digest=hashlib.sha256()
        while True:
            block=os.read(descriptor,1048576)
            if not block: break
            digest.update(block)
        after=os.fstat(descriptor)
    finally:
        os.close(descriptor)
    before_state=(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
    after_state=(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid,after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
    if before_state!=after_state: raise SystemExit("firmware changed while read")
    if digest.hexdigest()!=expected: raise SystemExit("firmware digest does not match the approved value")
verify(sys.argv[1],sys.argv[2])
verify(sys.argv[3],sys.argv[4])
"""


def _archive_builder_python() -> str:
    return r"""import hashlib,io,json,os,stat,sys,zipfile
from pathlib import Path,PurePosixPath
root=Path(os.path.abspath(sys.argv[1]))
manifest=json.loads(sys.argv[2])
output=Path(os.path.abspath(sys.argv[3]))
DIR_FLAGS=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_DIRECTORY
def open_root(path):
    parts=Path(os.path.abspath(path)).parts[1:]
    if not parts: raise SystemExit("artifact root path invalid")
    fd=os.open("/",DIR_FLAGS)
    try:
        for part in parts:
            next_fd=os.open(part,DIR_FLAGS,dir_fd=fd);os.close(fd);fd=next_fd
        return fd
    except BaseException:
        os.close(fd);raise
def open_relative(root_fd,relative):
    parts=relative.parts
    parent=os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd=os.open(part,DIR_FLAGS,dir_fd=parent);os.close(parent);parent=next_fd
        return os.open(parts[-1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
    finally:
        os.close(parent)
root_fd=open_root(root)
root_state=os.fstat(root_fd)
entries=[]
for item in manifest["files"]:
    relative=PurePosixPath(item["path"])
    if relative.is_absolute() or any(part in {"",".",".."} for part in relative.parts): raise SystemExit("artifact path invalid")
    fd=open_relative(root_fd,relative)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: raise SystemExit("artifact object invalid")
        chunks=[]
        while True:
            block=os.read(fd,1048576)
            if not block: break
            chunks.append(block)
        after=os.fstat(fd)
    finally:
        os.close(fd)
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise SystemExit("artifact changed after manifest")
    payload=b"".join(chunks)
    mode=0o755 if before.st_mode&stat.S_IXUSR else 0o644
    if mode!=item["mode"] or len(payload)!=item["size"] or hashlib.sha256(payload).hexdigest()!=item["sha256"]: raise SystemExit("artifact changed after manifest")
    entries.append((item["path"],mode,payload))
after_root=os.fstat(root_fd)
reopened_root=open_root(root)
try: reopened_root_state=os.fstat(reopened_root)
finally: os.close(reopened_root)
if (root_state.st_dev,root_state.st_ino)!=(after_root.st_dev,after_root.st_ino) or (root_state.st_dev,root_state.st_ino)!=(reopened_root_state.st_dev,reopened_root_state.st_ino): raise SystemExit("artifact root changed after manifest")
os.close(root_fd)
buffer=io.BytesIO()
with zipfile.ZipFile(buffer,"w",compression=zipfile.ZIP_STORED,strict_timestamps=True) as archive:
    for relative,mode,payload in entries:
        info=zipfile.ZipInfo(relative,date_time=(1980,1,1,0,0,0))
        info.compress_type=zipfile.ZIP_STORED
        info.create_system=3
        info.external_attr=(mode&0xFFFF)<<16
        info.extra=b""
        info.comment=b""
        archive.writestr(info,payload)
payload=buffer.getvalue()
if hashlib.sha256(payload).hexdigest()!=manifest["archiveSha256"]: raise SystemExit("artifact changed after manifest")
output_parent_fd=open_root(output.parent)
try: fd=os.open(output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output_parent_fd)
except BaseException: os.close(output_parent_fd);raise
try:
    view=memoryview(payload)
    while view:
        written=os.write(fd,view)
        view=view[written:]
    os.fsync(fd)
finally:
    os.close(fd)
    os.close(output_parent_fd)
"""


def _serial_collector_python() -> str:
    return r"""import os,select,sys
pipe,log,status,stop,max_bytes,max_line=sys.argv[1:]
max_bytes=int(max_bytes);max_line=int(max_line)
fd=os.open(pipe,os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC)
out=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
total=0
line=bytearray()
terminal=None
def publish(value):
    global terminal
    if terminal is None or (value=="overflow" and terminal!="overflow"):
        temp=status+".tmp"
        try: os.unlink(temp)
        except FileNotFoundError: pass
        with open(temp,"x",encoding="ascii") as stream:
            stream.write(value+"\n");stream.flush();os.fsync(stream.fileno())
        os.replace(temp,status)
        terminal=value
try:
    while True:
        had_data=False
        ready,_,_=select.select([fd],[],[],0.2)
        if ready:
            try: block=os.read(fd,65536)
            except BlockingIOError: block=b""
            if block:
                had_data=True
                remaining=max_bytes-total
                if remaining>0:
                    written=block[:remaining]
                    os.write(out,written)
                    total+=len(written)
                if len(block)>remaining: publish("overflow")
                for byte in block:
                    if byte==10:
                        if bytes(line)==b"OVERSEER_PHASE_B_REHEARSAL_RESULT_END": publish("complete")
                        line.clear()
                    elif len(line)<=max_line:
                        line.append(byte)
                    if len(line)>max_line: publish("overflow")
        if os.path.exists(stop) and not had_data: break
finally:
    os.fsync(out);os.close(out);os.close(fd)
"""


def _ownership_validator_python() -> str:
    return r"""import re,sys
from xml.etree import ElementTree
root=ElementTree.fromstring(sys.stdin.read())
root_allowed={"name","uuid","metadata","memory","currentMemory","vcpu","os","features","cpu","clock","on_poweroff","on_reboot","on_crash","devices"}
root_attrs_ok=set(root.attrib)<={"type","id"} and root.get("type")=="kvm" and ("id" not in root.attrib or root.get("id").isdigit())
active="id" in root.attrib
root_counts_ok=all(len(root.findall(tag))==1 for tag in ("name","uuid","metadata","memory","currentMemory","vcpu","os","features","on_poweroff","on_reboot","on_crash","devices")) and len(root.findall("cpu"))<=1 and len(root.findall("clock"))<=1
if not root_attrs_ok or not root_counts_ok or any(item.tag not in root_allowed for item in list(root)): raise SystemExit(1)
def whitespace_only(value):
    return value is None or not value.strip()
if not whitespace_only(root.text) or any(not whitespace_only(item.tail) or list(item) and not whitespace_only(item.text) for item in root.iter()): raise SystemExit(1)
def leaf_ok(node,attrs,text):
    return node is not None and node.attrib==attrs and (node.text==text if text is not None else whitespace_only(node.text)) and not list(node)
name=root.find("name"); uuid=root.find("uuid")
if not leaf_ok(name,{},sys.argv[1]) or not leaf_ok(uuid,{},sys.argv[2]): raise SystemExit(1)
def memory_ok(name):
    node=root.find(name)
    return node is not None and node.attrib in ({"unit":"MiB"},{"unit":"KiB"}) and node.text==("2048" if node.get("unit")=="MiB" else "2097152") and not list(node)
vcpu=root.find("vcpu")
vcpu_valid=vcpu is not None and vcpu.text=="2" and vcpu.attrib in ({"placement":"static"},{"placement":"static","current":"2"}) and not list(vcpu)
os_node=root.find("os"); os_children=[] if os_node is None else list(os_node); os_type=None if os_node is None else os_node.find("type"); firmwares=[] if os_node is None else os_node.findall("firmware"); loaders=[] if os_node is None else os_node.findall("loader"); nvrams=[] if os_node is None else os_node.findall("nvram"); boots=[] if os_node is None else os_node.findall("boot")
firmware_children=[] if not firmwares else list(firmwares[0])
rendered_efi=[item.tag for item in os_children]==["type","loader","nvram","boot"] and not firmwares and leaf_ok(loaders[0],{"readonly":"yes","secure":"no","type":"pflash"},sys.argv[9]) and leaf_ok(nvrams[0],{"template":sys.argv[10]},sys.argv[8])
canonical_firmware=len(firmwares)==1 and firmwares[0].attrib=={} and [item.tag for item in firmware_children]==["feature","feature"] and leaf_ok(firmware_children[0],{"enabled":"no","name":"enrolled-keys"},None) and leaf_ok(firmware_children[1],{"enabled":"no","name":"secure-boot"},None)
canonical_efi=[item.tag for item in os_children]==["type","firmware","loader","nvram","boot"] and canonical_firmware and leaf_ok(loaders[0],{"readonly":"yes","secure":"no","type":"pflash","format":"raw"},sys.argv[9]) and leaf_ok(nvrams[0],{"template":sys.argv[10],"templateFormat":"raw","format":"raw"},sys.argv[8])
os_valid=os_node is not None and os_node.attrib=={"firmware":"efi"} and len(os_node.findall("type"))==1 and len(loaders)==1 and len(nvrams)==1 and len(boots)==1 and os_type.text=="hvm" and os_type.attrib=={"arch":"x86_64","machine":sys.argv[11]} and not list(os_type) and (rendered_efi or canonical_efi) and boots[0].attrib=={"dev":"hd"} and whitespace_only(boots[0].text) and not list(boots[0])
features=root.find("features"); feature_children=[] if features is None else list(features)
features_valid=features is not None and features.attrib=={} and len(feature_children)==1 and leaf_ok(feature_children[0],{},None) and feature_children[0].tag=="acpi"
cpus=root.findall("cpu"); cpu_model=None if not cpus else cpus[0].find("model")
cpu_features=[] if not cpus else cpus[0].findall("feature")
inactive_cpu_valid=not cpus or len(cpus)==1 and cpus[0].attrib=={"mode":"custom","match":"exact","check":"none"} and len(list(cpus[0]))==1 and leaf_ok(cpu_model,{"fallback":"forbid"},"qemu64")
active_cpu_contract=[("x2apic","require"),("hypervisor","require"),("lahf_lm","require"),("svm","disable")]
active_cpu_valid=len(cpus)==1 and cpus[0].attrib=={"mode":"custom","match":"exact","check":"full"} and [item.tag for item in list(cpus[0])]==["model","feature","feature","feature","feature"] and leaf_ok(cpu_model,{"fallback":"forbid"},"qemu64") and [(item.get("name"),item.get("policy")) for item in cpu_features]==active_cpu_contract and all(set(item.attrib)=={"name","policy"} and whitespace_only(item.text) and not list(item) for item in cpu_features)
cpu_valid=active_cpu_valid if active else inactive_cpu_valid
clocks=root.findall("clock"); clock_valid=not clocks or len(clocks)==1 and clocks[0].attrib=={"offset":"utc"} and whitespace_only(clocks[0].text) and not list(clocks[0])
power_valid=leaf_ok(root.find("on_poweroff"),{},"destroy") and leaf_ok(root.find("on_reboot"),{},"restart") and leaf_ok(root.find("on_crash"),{},"destroy")
if not memory_ok("memory") or not memory_ok("currentMemory") or not vcpu_valid or not os_valid or not features_valid or not cpu_valid or not clock_valid or not power_valid: raise SystemExit(1)
metadata=root.find("./metadata")
markers=[] if metadata is None else list(metadata)
marker=markers[0] if len(markers)==1 and markers[0].tag=="{urn:overseer:phase-b-rehearsal}run" else None
devices=root.find("./devices")
children=[] if devices is None else list(devices)
allowed={"disk","serial","console","controller","input","memballoon","emulator","audio"}
if metadata is None or metadata.attrib!={} or marker is None or marker.attrib!={"id":sys.argv[3]} or not whitespace_only(marker.text) or list(marker) or devices is None or devices.attrib!={} or any(item.tag not in allowed for item in children): raise SystemExit(1)
hex_value=re.compile(r"0x[0-9a-fA-F]+")
alias_name=re.compile(r"[A-Za-z0-9_.-]{1,128}")
def generated_child_ok(item):
    if list(item) or not whitespace_only(item.text): return False
    if item.tag=="alias": return set(item.attrib)=={"name"} and alias_name.fullmatch(item.get("name", "")) is not None
    if item.tag!="address": return False
    kind=item.get("type")
    if kind=="pci":
        return set(item.attrib) in ({"type","domain","bus","slot","function"},{"type","domain","bus","slot","function","multifunction"}) and all(hex_value.fullmatch(item.get(key,"")) is not None for key in ("domain","bus","slot","function")) and item.get("multifunction") in {None,"on","off"}
    if kind=="drive": return set(item.attrib)=={"type","controller","bus","target","unit"} and all(item.get(key,"").isdigit() for key in ("controller","bus","target","unit"))
    if kind=="isa": return set(item.attrib)=={"type","iobase","irq"} and hex_value.fullmatch(item.get("iobase","")) is not None and item.get("irq","").isdigit()
    return False
def children_exact(item,required,optional=()):
    tags=[child.tag for child in list(item)]
    return whitespace_only(item.text) and all(tags.count(tag)==1 for tag in required) and all(tags.count(tag)<=1 for tag in optional) and tags.count("alias")<=1 and tags.count("address")<=1 and all(tag in set(required)|set(optional)|{"alias","address"} for tag in tags) and all(child.tag in set(required)|set(optional) or generated_child_ok(child) for child in list(item))
disks=root.findall("./devices/disk")
def backing_store_ok(item):
    if item is None: return True
    children=list(item); terminal=item.find("backingStore"); format_node=item.find("format"); source=item.find("source")
    return item.attrib=={"type":"file","index":"3"} and [child.tag for child in children]==["format","source","backingStore"] and leaf_ok(format_node,{"type":"qcow2"},None) and leaf_ok(source,{"file":sys.argv[7]},None) and leaf_ok(terminal,{},None)
def disk_ok(item,device,path,driver_type,target,bus,readonly):
    driver=item.find("driver");source=item.find("source");target_node=item.find("target");backing=item.find("backingStore")
    readonly_node=item.find("readonly")
    source_attrs={"file":path}
    if active: source_attrs["index"]="2" if device=="disk" else "1"
    backing_allowed=(device=="disk" and ((active and backing_store_ok(backing)) or (not active and backing is None))) or (device=="cdrom" and ((active and leaf_ok(backing,{},None)) or (not active and backing is None)))
    return item.attrib=={"type":"file","device":device} and children_exact(item,("driver","source","target"),("readonly","backingStore")) and leaf_ok(driver,{"name":"qemu","type":driver_type},None) and leaf_ok(source,source_attrs,None) and leaf_ok(target_node,{"dev":target,"bus":bus},None) and (readonly_node is not None)==readonly and (readonly_node is None or leaf_ok(readonly_node,{},None)) and backing_allowed
disk_valid=len(disks)==2 and any(disk_ok(item,"disk",sys.argv[4],"qcow2","vda","virtio",False) for item in disks) and any(disk_ok(item,"cdrom",sys.argv[5],"raw","sda","sata",True) for item in disks)
serials=root.findall("./devices/serial")
consoles=root.findall("./devices/console")
serial=serials[0] if len(serials)==1 else None
serial_source=None if serial is None else serial.find("source")
serial_target=None if serial is None else serial.find("target")
console=consoles[0] if len(consoles)==1 else None
console_target=None if console is None else console.find("target")
console_source=None if console is None else console.find("source")
serial_model=None if serial_target is None else serial_target.find("model")
serial_target_text_valid=serial_target is not None and (serial_target.text is None or not serial_target.text.strip())
serial_target_valid=serial_target is not None and serial_target.attrib=={"type":"isa-serial","port":"0"} and serial_target_text_valid and ((not list(serial_target)) or len(list(serial_target))==1 and leaf_ok(serial_model,{"name":"isa-serial"},None))
serial_alias=None if serial is None else serial.find("alias")
serial_shape_valid=([item.tag for item in list(serial)]==["source","target","alias"] and leaf_ok(serial_alias,{"name":"serial0"},None)) if active else [item.tag for item in list(serial)]==["source","target"]
serial_valid=serial is not None and serial.attrib=={"type":"pipe"} and serial_shape_valid and leaf_ok(serial_source,{"path":sys.argv[6]},None) and serial_target_valid
tty=None if console is None else console.get("tty"); tty_valid=tty is not None and re.fullmatch(r"/dev/pts/[0-9]+",tty) is not None
console_alias=None if console is None else console.find("alias")
inactive_console_pty_valid=not active and console is not None and console.attrib=={"type":"pty"} and [item.tag for item in list(console)]==["target"] and console_source is None and console_alias is None and leaf_ok(console_target,{"type":"serial","port":"0"},None)
active_console_pty_valid=active and console is not None and tty_valid and console.attrib=={"type":"pty","tty":tty} and children_exact(console,("target","source")) and leaf_ok(console_target,{"type":"serial","port":"0"},None) and leaf_ok(console_source,{"path":tty},None) and leaf_ok(console_alias,{"name":"serial0"},None)
console_pty_valid=inactive_console_pty_valid or active_console_pty_valid
console_pipe_shape=([item.tag for item in list(console)]==["source","target","alias"] and leaf_ok(console_alias,{"name":"serial0"},None)) if active else [item.tag for item in list(console)]==["source","target"]
console_pipe_valid=console is not None and console.attrib=={"type":"pipe"} and console_pipe_shape and leaf_ok(console_source,{"path":sys.argv[6]},None) and leaf_ok(console_target,{"type":"serial","port":"0"},None)
console_valid=console_pty_valid or console_pipe_valid
emulators=root.findall("./devices/emulator")
emulator_valid=not emulators or len(emulators)==1 and leaf_ok(emulators[0],{},"/usr/bin/qemu-system-x86_64")
inputs=root.findall("./devices/input")
input_forms={(item.get("type"),item.get("bus")) for item in inputs}
inputs_valid=len(inputs)==len(input_forms) and input_forms<={("mouse","ps2"),("keyboard","ps2")} and all(item.attrib=={"type":item.get("type"),"bus":"ps2"} and children_exact(item,()) for item in inputs)
controllers=root.findall("./devices/controller")
controller_forms={(item.get("type"),item.get("index"),item.get("model")) for item in controllers}
controller_allowed={("pci","0","pci-root"),("usb","0","piix3-uhci"),("sata","0",None)}
controllers_valid=len(controllers)==len(controller_forms) and controller_forms<=controller_allowed and all(set(item.attrib)==({"type","index"} if item.get("model") is None else {"type","index","model"}) and children_exact(item,()) for item in controllers)
balloons=root.findall("./devices/memballoon")
balloons_valid=not balloons or len(balloons)==1 and balloons[0].attrib=={"model":"virtio"} and children_exact(balloons[0],())
audios=root.findall("./devices/audio")
audios_valid=not audios or len(audios)==1 and audios[0].attrib=={"id":"1","type":"none"} and children_exact(audios[0],())
if not disk_valid or not serial_valid or not console_valid or not emulator_valid or not inputs_valid or not controllers_valid or not balloons_valid or not audios_valid:
    raise SystemExit(1)
"""


def _future_owner_validator_python(
    owner_binding: Mapping[str, object],
    *,
    source_commit: str,
    source_manifest: Mapping[str, object],
) -> str:
    expected_binding = canonical_json(owner_binding)
    expected_paths = sorted(str(item["path"]) for item in source_manifest["files"])
    expected_binding_keys = sorted(_OWNER_BINDING_KEYS)
    expected_registry_fields = list(_CODEX_REGISTRY_FIELDS)
    return f'''import csv,hashlib,io,json,os,re,shlex,stat,subprocess,sys,uuid
from pathlib import Path
expected=json.loads({expected_binding!r})
expected_paths={expected_paths!r}
expected_binding_keys={expected_binding_keys!r}
expected_registry_fields={expected_registry_fields!r}
DIR_FLAGS=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_DIRECTORY
def open_dir(path):
 parts=Path(os.path.abspath(path)).parts[1:]
 if not parts: raise SystemExit("owner validation path invalid")
 fd=os.open("/",DIR_FLAGS)
 try:
  for part in parts:
   next_fd=os.open(part,DIR_FLAGS,dir_fd=fd);os.close(fd);fd=next_fd
  return fd
 except BaseException: os.close(fd);raise
def open_file(path):
 absolute=Path(os.path.abspath(path));parts=absolute.parts[1:]
 parent=open_dir(absolute.parent)
 try: return os.open(parts[-1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=parent)
 finally: os.close(parent)
def read_file(path,limit):
 fd=open_file(path)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or before.st_mode&(stat.S_IWGRP|stat.S_IWOTH) or before.st_size>limit: raise SystemExit("owner validation object unsafe")
  chunks=[];total=0
  while True:
   block=os.read(fd,min(1048576,limit+1-total))
   if not block: break
   chunks.append(block);total+=len(block)
   if total>limit: raise SystemExit("owner validation object oversized")
  after=os.fstat(fd)
 finally: os.close(fd)
 reopened=open_file(path)
 try: current=os.fstat(reopened)
 finally: os.close(reopened)
 identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
 if identity(before)!=identity(after) or identity(before)!=identity(current): raise SystemExit("owner validation object changed")
 return b"".join(chunks),before
def git(fd,*args,preserve=False):
 completed=subprocess.run(("/usr/bin/git","--no-optional-locks","-c","core.fsmonitor=false","-c","core.untrackedCache=false","-C",f"/proc/self/fd/{{fd}}",*args),check=True,capture_output=True,text=True,stdin=subprocess.DEVNULL,pass_fds=(fd,))
 return completed.stdout if preserve else completed.stdout.strip()
def repository(path,device,inode):
 fd=open_dir(path);state=os.fstat(fd)
 if (state.st_dev,state.st_ino)!=(device,inode) or state.st_uid!=os.geteuid(): raise SystemExit("owner repository identity mismatch")
 if git(fd,"rev-parse","--show-prefix"): raise SystemExit("owner repository is not top level")
 common=git(fd,"rev-parse","--path-format=absolute","--git-common-dir")
 if common!=expected["gitCommonDirectory"]: raise SystemExit("owner common Git directory mismatch")
 common_fd=open_dir(common)
 try: common_state=os.fstat(common_fd)
 finally: os.close(common_fd)
 if (common_state.st_dev,common_state.st_ino)!=(expected["gitCommonDirectoryDevice"],expected["gitCommonDirectoryInode"]): raise SystemExit("owner common Git identity mismatch")
 reopened=open_dir(path)
 try: reopened_state=os.fstat(reopened)
 finally: os.close(reopened)
 if (reopened_state.st_dev,reopened_state.st_ino)!=(device,inode): raise SystemExit("owner repository path changed")
 return fd,state,common,common_state
canonical=lambda value:json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(",",":"))
if sorted(expected)!=expected_binding_keys: raise SystemExit("owner binding fields mismatch")
supplied_digest=expected.pop("bindingDigest")
if hashlib.sha256(canonical(expected).encode()).hexdigest()!=supplied_digest: raise SystemExit("owner binding digest mismatch")
expected["bindingDigest"]=supplied_digest
registry_payload,registry_state=read_file(expected["registry"],8388608)
if (registry_state.st_dev,registry_state.st_ino)!=(expected["registryDevice"],expected["registryInode"]) or hashlib.sha256(registry_payload).hexdigest()!=expected["registrySha256"]: raise SystemExit("owner registry mismatch")
try: registry_text=registry_payload.decode("utf-8")
except UnicodeDecodeError as error: raise SystemExit("owner registry encoding invalid") from error
def select_owner_row(registry_text):
 if "\\0" in registry_text: raise SystemExit("owner registry encoding invalid")
 reader=csv.DictReader(io.StringIO(registry_text,newline=""),strict=True)
 if list(reader.fieldnames or ())!=expected_registry_fields: raise SystemExit("owner registry header invalid")
 try: target_uuid=uuid.UUID(expected["conversationId"])
 except (ValueError,AttributeError) as error: raise SystemExit("owner binding conversation invalid") from error
 matches=[]
 try:
  for row in reader:
   if None in row or any(not isinstance(row.get(field),str) for field in expected_registry_fields): raise SystemExit("owner registry row invalid")
   try: row_uuid=uuid.UUID(row["conversation_id"])
   except (ValueError,AttributeError): continue
   if row_uuid==target_uuid:
    if str(row_uuid)!=row["conversation_id"]: raise SystemExit("owner registry contains a noncanonical conversation alias")
    matches.append(row)
 except csv.Error as error: raise SystemExit("owner registry CSV invalid") from error
 if len(matches)!=1: raise SystemExit("owner registry exact row unavailable")
 return matches[0]
matched=select_owner_row(registry_text)
row_binding=dict(conversationId=matched["conversation_id"],project=matched["project"],command=matched["command"],launcher=matched["launcher"])
try: canonical_conversation=str(uuid.UUID(row_binding["conversationId"]))
except (ValueError,AttributeError) as error: raise SystemExit("owner registry conversation invalid") from error
derived_command="codex-overseer-"+canonical_conversation
derived_launcher="/home/god/.local/bin/"+derived_command
derived_row=dict(conversationId=canonical_conversation,project=expected["project"],command=derived_command,launcher=derived_launcher)
if row_binding!=derived_row or row_binding!=expected["registryRow"] or hashlib.sha256(canonical(row_binding).encode()).hexdigest()!=expected["registryRowDigest"]: raise SystemExit("owner registry row mismatch")
if expected["schemaVersion"]!="overseer.phase-b-rehearsal-owner-binding.v2" or expected["status"]!="passed" or expected["conversationId"]!=canonical_conversation or expected["ownerProjectToplevel"]!=row_binding["project"] or expected["registry"]!="/home/god/.codex/codex-projects.csv": raise SystemExit("owner binding semantics invalid")
launcher_path=expected["registryRow"]["launcher"]
launcher_payload,launcher_state=read_file(launcher_path,65536)
if (launcher_state.st_dev,launcher_state.st_ino)!=(expected["launcherDevice"],expected["launcherInode"]) or hashlib.sha256(launcher_payload).hexdigest()!=expected["launcherSha256"]: raise SystemExit("owner launcher mismatch")
try: launcher_text=launcher_payload.decode("utf-8")
except UnicodeDecodeError as error: raise SystemExit("owner launcher encoding invalid") from error
launcher_lines=launcher_text.splitlines()
if launcher_lines[:3]!=["#!/usr/bin/env bash","set -euo pipefail",""] or len(launcher_lines)!=4: raise SystemExit("owner launcher semantics invalid")
try: launcher_tokens=shlex.split(launcher_lines[3])
except ValueError as error: raise SystemExit("owner launcher semantics invalid") from error
expected_launcher_tokens=["exec","/usr/bin/tmux","new-session","-A","-s",row_binding["command"],"-c",row_binding["project"],"/home/god/.local/bin/codex-memory-session resume "+row_binding["conversationId"]+" --cd '"+row_binding["project"]+"'"]
if launcher_tokens!=expected_launcher_tokens: raise SystemExit("owner launcher semantics invalid")
owner_fd,owner_state,owner_common,owner_common_state=repository(expected["project"],expected["ownerProjectDevice"],expected["ownerProjectInode"])
source_fd,source_state,source_common,source_common_state=repository(expected["sourceRoot"],expected["sourceRootDevice"],expected["sourceRootInode"])
try:
 if git(source_fd,"rev-parse","HEAD")!={source_commit!r}: raise SystemExit("source commit mismatch")
 if git(source_fd,"status","--porcelain","--untracked-files=all"): raise SystemExit("source tree dirty")
 actual_paths=sorted(item for item in git(source_fd,"ls-files","-z",preserve=True).split("\\0") if item)
 if actual_paths!=expected_paths: raise SystemExit("source tracked inventory mismatch")
finally:
 os.close(owner_fd);os.close(source_fd)
def proc_read(fd,name,limit):
 child=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=fd)
 try:
  chunks=[];total=0
  while True:
   block=os.read(child,min(65536,limit+1-total))
   if not block: break
   chunks.append(block);total+=len(block)
   if total>limit: raise SystemExit("owner process metadata oversized")
  return b"".join(chunks)
 finally: os.close(child)
def proc_stat(payload,pid):
 marker=payload.rfind(b") ")
 if marker<1: raise SystemExit("owner process metadata invalid")
 try:
  parsed=int(payload[:payload.index(b" ")]);fields=payload[marker+2:].split();parent=int(fields[1]);started=int(fields[19])
 except (IndexError,ValueError) as error: raise SystemExit("owner process metadata invalid") from error
 if parsed!=pid or parent<0 or started<=0: raise SystemExit("owner process metadata invalid")
 return parent,started
def open_process(pid):
 if pid<=0: raise SystemExit("owner process ancestry invalid")
 fd=os.open("/proc/"+str(pid),DIR_FLAGS);state=os.fstat(fd)
 if not stat.S_ISDIR(state.st_mode) or state.st_uid!=os.geteuid(): os.close(fd);raise SystemExit("owner process ancestry unsafe")
 return fd
def classify_codex(executable_path,argv,device,inode):
 codex_named=os.path.basename(executable_path)=="codex" or any(os.path.basename(item)=="codex" for item in argv) or any("@openai/codex" in item for item in argv)
 bound_identity=(device,inode)==(expected["codexExecutableDevice"],expected["codexExecutableInode"])
 if codex_named or bound_identity:
  if executable_path!=expected["codexExecutable"] or not bound_identity: raise SystemExit("unexpected Codex process in owner ancestry")
  return True
 return False
def process(pid):
 fd=open_process(pid)
 try:
  before_parent,before_started=proc_stat(proc_read(fd,"stat",65536),pid)
  cmdline=proc_read(fd,"cmdline",65536)
  try: argv=[item.decode("utf-8") for item in cmdline.split(b"\\0") if item]
  except UnicodeDecodeError as error: raise SystemExit("owner process command line invalid") from error
  record=dict(pid=pid,parentPid=before_parent,startTime=before_started,argv=argv)
  try: executable_path=os.readlink("exe",dir_fd=fd);executable_fd=os.open("exe",os.O_RDONLY|os.O_CLOEXEC,dir_fd=fd)
  except OSError as error: raise SystemExit("owner process executable unavailable") from error
  try:
   before=os.fstat(executable_fd)
   if not stat.S_ISREG(before.st_mode): raise SystemExit("owner process executable unsafe")
   record.update(executable=executable_path,executableDevice=before.st_dev,executableInode=before.st_ino)
   record["isCodex"]=classify_codex(executable_path,argv,before.st_dev,before.st_ino)
   if record["isCodex"]:
    if before.st_uid!=os.geteuid() or before.st_nlink!=1 or before.st_mode&(stat.S_IWGRP|stat.S_IWOTH) or not before.st_mode&stat.S_IXUSR or before.st_size>536870912: raise SystemExit("owner Codex executable unsafe")
    digest=hashlib.sha256();total=0
    while True:
     block=os.read(executable_fd,1048576)
     if not block: break
     digest.update(block);total+=len(block)
     if total>536870912: raise SystemExit("owner Codex executable oversized")
    if total!=before.st_size or digest.hexdigest()!=expected["codexExecutableSha256"]: raise SystemExit("owner Codex executable mismatch")
    record["executableSha256"]=digest.hexdigest()
   after=os.fstat(executable_fd)
  finally: os.close(executable_fd)
  identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
  try: repeated_path=os.readlink("exe",dir_fd=fd);repeated_fd=os.open("exe",os.O_RDONLY|os.O_CLOEXEC,dir_fd=fd)
  except OSError as error: raise SystemExit("owner process executable changed") from error
  try: repeated=os.fstat(repeated_fd)
  finally: os.close(repeated_fd)
  if identity(before)!=identity(after) or identity(before)!=identity(repeated) or executable_path!=repeated_path: raise SystemExit("owner process executable changed")
  if proc_read(fd,"cmdline",65536)!=cmdline: raise SystemExit("owner process command line changed")
  after_parent,after_started=proc_stat(proc_read(fd,"stat",65536),pid)
  if (before_parent,before_started)!=(after_parent,after_started): raise SystemExit("owner process changed")
  return record
 finally: os.close(fd)
def ancestry_snapshot():
 current=os.getppid();seen=set();records=[]
 for _ in range(128):
  if current<=0 or current in seen: raise SystemExit("owner process ancestry invalid")
  seen.add(current);record=process(current);records.append(record)
  if record["parentPid"]==1: break
  current=record["parentPid"]
 else: raise SystemExit("owner process ancestry oversized")
 return records
def pane_snapshot():
 lines=subprocess.run(("/usr/bin/tmux","list-panes","-s","-t","="+expected["registryRow"]["command"],"-F","#{{session_id}}\\t#{{session_name}}\\t#{{window_id}}\\t#{{pane_id}}\\t#{{pane_pid}}\\t#{{pane_tty}}"),check=True,capture_output=True,text=True,stdin=subprocess.DEVNULL).stdout.splitlines()
 panes=[]
 for line in lines:
  fields=line.split("\\t")
  if len(fields)!=6 or re.fullmatch(r"[$][0-9]+",fields[0]) is None or fields[1]!=expected["registryRow"]["command"] or re.fullmatch(r"@[0-9]+",fields[2]) is None or re.fullmatch(r"%[0-9]+",fields[3]) is None or not fields[4].isdigit() or int(fields[4])<=0 or re.fullmatch(r"/dev/pts/[0-9]+",fields[5]) is None: raise SystemExit("exact owner session pane metadata invalid")
  panes.append((fields[0],fields[1],fields[2],fields[3],int(fields[4]),fields[5]))
 return panes
def authorize(first_ancestry,first_panes,second_ancestry,second_panes):
 if first_ancestry!=second_ancestry: raise SystemExit("owner process ancestry changed during authorization")
 if first_panes!=second_panes: raise SystemExit("exact owner session panes changed during authorization")
 ancestry=[record["pid"] for record in second_ancestry]
 codex=[record for record in second_ancestry if record["isCodex"]]
 if len(codex)!=1 or codex[0]["argv"]!=expected["codexArgv"]: raise SystemExit("execution is not beneath exactly one exact owner Codex process")
 owner_panes=[pane for pane in second_panes if pane[4] in ancestry]
 if len(owner_panes)!=1: raise SystemExit("execution is not descended from the exact owner session pane")
 pane_pid=owner_panes[0][4]
 if pane_pid not in ancestry or ancestry.index(codex[0]["pid"])>=ancestry.index(pane_pid): raise SystemExit("owner process lineage is invalid")
 return codex[0]
first_ancestry=ancestry_snapshot();first_panes=pane_snapshot()
second_ancestry=ancestry_snapshot();second_panes=pane_snapshot()
owner_process=authorize(first_ancestry,first_panes,second_ancestry,second_panes)
reconstructed=dict(
 schemaVersion="overseer.phase-b-rehearsal-owner-binding.v2",status="passed",
 conversationId=row_binding["conversationId"],project=row_binding["project"],ownerProjectToplevel=row_binding["project"],
 sourceRoot=expected["sourceRoot"],gitCommonDirectory=owner_common,
 ownerProjectDevice=owner_state.st_dev,ownerProjectInode=owner_state.st_ino,
 sourceRootDevice=source_state.st_dev,sourceRootInode=source_state.st_ino,
 gitCommonDirectoryDevice=owner_common_state.st_dev,gitCommonDirectoryInode=owner_common_state.st_ino,
 registry="/home/god/.codex/codex-projects.csv",registryDevice=registry_state.st_dev,registryInode=registry_state.st_ino,
 registryRow=row_binding,registrySha256=hashlib.sha256(registry_payload).hexdigest(),registryRowDigest=hashlib.sha256(canonical(row_binding).encode()).hexdigest(),
 launcherDevice=launcher_state.st_dev,launcherInode=launcher_state.st_ino,launcherSha256=hashlib.sha256(launcher_payload).hexdigest(),
 codexExecutable=owner_process["executable"],codexExecutableDevice=owner_process["executableDevice"],codexExecutableInode=owner_process["executableInode"],codexExecutableSha256=owner_process["executableSha256"],codexArgv=owner_process["argv"],
)
reconstructed["bindingDigest"]=hashlib.sha256(canonical(reconstructed).encode()).hexdigest()
if canonical(reconstructed)!=canonical(expected): raise SystemExit("complete owner binding reconstruction mismatch")
'''


def _future_script(
    *,
    source_commit: str,
    vm_name: str,
    vm_uuid: str,
    run_id: str,
    source_root: Path,
    runtime_site: Path,
    source_manifest: Mapping[str, object],
    runtime_manifest: Mapping[str, object],
    runtime_probe: Mapping[str, object],
    runtime_probe_digest: str,
    capability_probe: Mapping[str, object],
    capability_probe_digest: str,
    base_image: Path,
    temp_parent: Path,
    domain_xml: str,
    cloud_init: str,
    meta_data: str,
    owner_binding: Mapping[str, object],
) -> str:
    validator = _result_validator_python()
    collector = _serial_collector_python()
    archive_builder = _archive_builder_python()
    ownership_validator = _ownership_validator_python()
    firmware_validator = _firmware_validator_python()
    runtime_probe_code = _runtime_probe_python()
    capability_probe_code = _capability_probe_python()
    owner_validator = _future_owner_validator_python(
        owner_binding,
        source_commit=source_commit,
        source_manifest=source_manifest,
    )
    source_manifest_json = canonical_json(source_manifest)
    runtime_manifest_json = canonical_json(runtime_manifest)
    runtime_probe_json = canonical_json(runtime_probe)
    capability_probe_json = canonical_json(capability_probe)
    return f"""#!/usr/bin/bash
set -Eeuo pipefail
umask 077
unset BASH_ENV CDPATH ENV GLOBIGNORE LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD PYTHONHOME PYTHONPATH
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
export GIT_OPTIONAL_LOCKS=0
export GIT_TERMINAL_PROMPT=0
export XDG_RUNTIME_DIR={shlex.quote(str(SESSION_RUNTIME_DIR))}

readonly LIBVIRT_URI={shlex.quote(LIBVIRT_URI)}
readonly MACHINE_TYPE={shlex.quote(MACHINE_TYPE)}
readonly SOURCE_COMMIT={shlex.quote(source_commit)}
readonly VM_NAME={shlex.quote(vm_name)}
readonly VM_UUID={shlex.quote(vm_uuid)}
readonly RUN_ID={shlex.quote(run_id)}
readonly SOURCE_ROOT={shlex.quote(str(source_root))}
readonly RUNTIME_SITE={shlex.quote(str(runtime_site))}
readonly BASE_IMAGE={shlex.quote(str(base_image))}
readonly FIRMWARE_CODE={shlex.quote(str(FIRMWARE_CODE))}
readonly FIRMWARE_CODE_SHA256={shlex.quote(FIRMWARE_CODE_SHA256)}
readonly FIRMWARE_VARS_TEMPLATE={shlex.quote(str(FIRMWARE_VARS_TEMPLATE))}
readonly FIRMWARE_VARS_SHA256={shlex.quote(FIRMWARE_VARS_SHA256)}
readonly TEMP_PARENT={shlex.quote(str(temp_parent))}
readonly EXPECTED_SHA512={shlex.quote(BASE_IMAGE_SHA512)}
readonly EXPECTED_SOURCE_MANIFEST_JSON={shlex.quote(source_manifest_json)}
readonly EXPECTED_RUNTIME_MANIFEST_JSON={shlex.quote(runtime_manifest_json)}
readonly EXPECTED_RUNTIME_PROBE_JSON={shlex.quote(runtime_probe_json)}
readonly EXPECTED_RUNTIME_PROBE_SHA256={shlex.quote(runtime_probe_digest)}
readonly EXPECTED_CAPABILITY_PROBE_JSON={shlex.quote(capability_probe_json)}
readonly EXPECTED_CAPABILITY_PROBE_SHA256={shlex.quote(capability_probe_digest)}
readonly RESULT_TIMEOUT_SECONDS={RESULT_TIMEOUT_SECONDS}
readonly SHUTDOWN_TIMEOUT_SECONDS={SHUTDOWN_TIMEOUT_SECONDS}
readonly MAX_SERIAL_BYTES={MAX_SERIAL_BYTES}
readonly MAX_SERIAL_LINE_BYTES={MAX_SERIAL_LINE_BYTES}
readonly EXPECTED_SESSION_RUNTIME_DIR={shlex.quote(str(SESSION_RUNTIME_DIR))}
readonly RUN_LOCK="$XDG_RUNTIME_DIR/overseer-phase-b-rehearsal.lock"

TEMP_DIR=""
OVERLAY=""
SEED_ISO=""
NVRAM=""
SERIAL_PIPE=""
SERIAL_LOG=""
SERIAL_STATUS=""
SERIAL_STOP=""
SERIAL_COLLECTOR=""
COLLECTOR_PID=""
DOMAIN_XML=""
USER_DATA=""
META_DATA=""
SOURCE_ARCHIVE=""
RUNTIME_ARCHIVE=""
SOURCE_MANIFEST_FILE=""
RUNTIME_MANIFEST_FILE=""
LOCK_HELD=0

validate_firmware_runtime() {{
  /usr/bin/python3.13 -B -s -P -S -c {shlex.quote(firmware_validator)} "$FIRMWARE_CODE" "$FIRMWARE_CODE_SHA256" "$FIRMWARE_VARS_TEMPLATE" "$FIRMWARE_VARS_SHA256"
}}

validate_exact_owner() {{
  /usr/bin/python3.13 -B -s -P -S -c {shlex.quote(owner_validator)}
}}

validate_session_runtime() {{
  local actual
  if [[ "$XDG_RUNTIME_DIR" == "$EXPECTED_SESSION_RUNTIME_DIR" ]] &&
     [[ -d "$XDG_RUNTIME_DIR" && ! -L "$XDG_RUNTIME_DIR" ]] &&
     actual="$(/usr/bin/stat -Lc '%u:%a' -- "$XDG_RUNTIME_DIR")" &&
     [[ "$actual" == "$(/usr/bin/id -u):700" ]] &&
     [[ -r "$XDG_RUNTIME_DIR" && -w "$XDG_RUNTIME_DIR" && -x "$XDG_RUNTIME_DIR" ]]; then
    return 0
  fi
  printf '%s\n' 'session runtime directory is not the exact private caller directory' >&2
  return 1
}}

domain_presence() {{
  local names uuids name_count uuid_count actual_uuid actual_name
  if ! names="$(/usr/bin/virsh --connect "$LIBVIRT_URI" list --all --name 2>/dev/null)"; then return 2; fi
  if ! uuids="$(/usr/bin/virsh --connect "$LIBVIRT_URI" list --all --uuid 2>/dev/null)"; then return 2; fi
  if ! name_count="$(printf '%s\\n' "$names" | /usr/bin/awk -v expected="$VM_NAME" '$0 == expected {{ count++ }} END {{ print count + 0 }}')"; then return 2; fi
  if ! uuid_count="$(printf '%s\\n' "$uuids" | /usr/bin/awk -v expected="$VM_UUID" '$0 == expected {{ count++ }} END {{ print count + 0 }}')"; then return 2; fi
  if [[ "$name_count" == 0 && "$uuid_count" == 0 ]]; then return 1; fi
  [[ "$name_count" == 1 && "$uuid_count" == 1 ]] || return 2
  if ! actual_uuid="$(/usr/bin/virsh --connect "$LIBVIRT_URI" domuuid "$VM_NAME" 2>/dev/null)" || [[ "$actual_uuid" != "$VM_UUID" ]]; then return 2; fi
  if ! actual_name="$(/usr/bin/virsh --connect "$LIBVIRT_URI" domname "$VM_UUID" 2>/dev/null)" || [[ "$actual_name" != "$VM_NAME" ]]; then return 2; fi
  return 0
}}

verify_domain_ownership() {{
  local presence actual_uuid xml
  verify_lock || return 2
  if domain_presence; then presence=0; else presence=$?; fi
  case "$presence" in 1) return 1;; 2) return 2;; esac
  if ! actual_uuid="$(/usr/bin/virsh --connect "$LIBVIRT_URI" domuuid "$VM_NAME" 2>/dev/null)" || [[ "$actual_uuid" != "$VM_UUID" ]]; then return 2; fi
  if ! xml="$(/usr/bin/virsh --connect "$LIBVIRT_URI" dumpxml "$VM_UUID" 2>/dev/null)"; then return 2; fi
  if ! printf '%s' "$xml" | /usr/bin/python3.13 -B -s -P -S -c {shlex.quote(ownership_validator)} "$VM_NAME" "$VM_UUID" "$RUN_ID" "$OVERLAY" "$SEED_ISO" "$SERIAL_PIPE" "$BASE_IMAGE" "$NVRAM" "$FIRMWARE_CODE" "$FIRMWARE_VARS_TEMPLATE" "$MACHINE_TYPE"; then return 2; fi
  return 0
}}

domain_state() {{
  verify_domain_ownership || return 2
  /usr/bin/virsh --connect "$LIBVIRT_URI" domstate "$VM_UUID" 2>/dev/null
}}

wait_for_inactive() {{
  local deadline=$((SECONDS + SHUTDOWN_TIMEOUT_SECONDS)) state ownership
  while true; do
    if verify_domain_ownership; then ownership=0; else ownership=$?; fi
    case "$ownership" in 1) return 0;; 2) return 1;; esac
    if ! state="$(domain_state)"; then return 1; fi
    case "$state" in
      "shut off") return 0;;
      "running"|"in shutdown") ;;
      *) return 1;;
    esac
    (( SECONDS < deadline )) || return 1
    /usr/bin/sleep 2
  done
}}

shutdown_and_undefine() {{
  local ownership state
  if verify_domain_ownership; then ownership=0; else ownership=$?; fi
  case "$ownership" in 1) return 0;; 2) return 1;; esac
  if ! state="$(domain_state)"; then return 1; fi
  case "$state" in
    "shut off") ;;
    "running")
      /usr/bin/virsh --connect "$LIBVIRT_URI" shutdown "$VM_UUID" >/dev/null 2>&1 || return 1
      wait_for_inactive || return 1
      ;;
    "in shutdown") wait_for_inactive || return 1;;
    *) return 1;;
  esac
  verify_domain_ownership || return 1
  if ! state="$(domain_state)" || [[ "$state" != "shut off" ]]; then return 1; fi
  /usr/bin/virsh --connect "$LIBVIRT_URI" undefine "$VM_UUID" --nvram >/dev/null 2>&1 || return 1
  if domain_presence; then return 1; else ownership=$?; fi
  [[ "$ownership" -eq 1 ]]
}}

temp_layout_is_exact() {{
  [[ -n "$TEMP_DIR" ]] &&
  [[ "$OVERLAY" == "$TEMP_DIR/overlay.qcow2" ]] &&
  [[ "$SEED_ISO" == "$TEMP_DIR/seed.iso" ]] &&
  [[ "$NVRAM" == "$TEMP_DIR/nvram.fd" ]] &&
  [[ "$SERIAL_PIPE" == "$TEMP_DIR/serial" ]] &&
  [[ "$SERIAL_LOG" == "$TEMP_DIR/serial.log" ]] &&
  [[ "$SERIAL_STATUS" == "$TEMP_DIR/serial.status" ]] &&
  [[ "$SERIAL_STOP" == "$TEMP_DIR/serial.stop" ]] &&
  [[ "$SERIAL_COLLECTOR" == "$TEMP_DIR/serial-collector.py" ]] &&
  [[ "$DOMAIN_XML" == "$TEMP_DIR/domain.xml" ]] &&
  [[ "$USER_DATA" == "$TEMP_DIR/user-data" ]] &&
  [[ "$META_DATA" == "$TEMP_DIR/meta-data" ]] &&
  [[ "$SOURCE_ARCHIVE" == "$TEMP_DIR/source.zip" ]] &&
  [[ "$RUNTIME_ARCHIVE" == "$TEMP_DIR/runtime.zip" ]] &&
  [[ "$SOURCE_MANIFEST_FILE" == "$TEMP_DIR/source-manifest.json" ]] &&
  [[ "$RUNTIME_MANIFEST_FILE" == "$TEMP_DIR/runtime-manifest.json" ]]
}}

stop_collector() {{
  if [[ -n "$COLLECTOR_PID" ]]; then
    : >"$SERIAL_STOP"
    wait "$COLLECTOR_PID" 2>/dev/null || true
    COLLECTOR_PID=""
  fi
}}

verify_lock() {{
  (( LOCK_HELD == 1 )) &&
  [[ -f "$RUN_LOCK/run-id" ]] &&
  [[ "$(<"$RUN_LOCK/run-id")" == "$RUN_ID" ]]
}}

release_lock() {{
  if (( LOCK_HELD == 1 )); then
    verify_lock || return 1
    /usr/bin/rm -f -- "$RUN_LOCK/run-id"
    /usr/bin/rmdir -- "$RUN_LOCK" || return 1
    LOCK_HELD=0
  fi
}}

cleanup() {{
  local original_status="${{1:-1}}" cleanup_status=0 confirmed_absent=0
  trap - EXIT INT TERM
  set +e
  stop_collector
  if shutdown_and_undefine; then confirmed_absent=1; else cleanup_status=1; fi
  if (( confirmed_absent == 1 )) && temp_layout_is_exact; then
    /usr/bin/rm -f -- "$DOMAIN_XML" "$USER_DATA" "$META_DATA" "$OVERLAY" "$SEED_ISO" "$NVRAM" "$SERIAL_LOG" "$SERIAL_STATUS" "$SERIAL_STOP" "$SERIAL_COLLECTOR" "$SERIAL_PIPE.in" "$SERIAL_PIPE.out" "$SOURCE_ARCHIVE" "$RUNTIME_ARCHIVE" "$SOURCE_MANIFEST_FILE" "$RUNTIME_MANIFEST_FILE"
    /usr/bin/rmdir -- "$TEMP_DIR" || cleanup_status=1
  elif [[ -n "$TEMP_DIR" ]]; then
    printf '%s\\n' 'cleanup retained exact temporary artifacts because domain ownership/state was not confirmed' >&2
  fi
  if (( confirmed_absent == 1 )); then release_lock || cleanup_status=1; fi
  if (( original_status == 0 && cleanup_status != 0 )); then original_status=1; fi
  exit "$original_status"
}}

trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

validate_exact_owner
validate_session_runtime

if ! /usr/bin/mkdir "$RUN_LOCK" 2>/dev/null; then
  printf '%s\\n' 'another Phase B rehearsal owns the execution lock' >&2
  exit 1
fi
LOCK_HELD=1
printf '%s' "$RUN_ID" >"$RUN_LOCK/run-id"

if domain_presence; then
  printf '%s\\n' 'target VM already exists at future execution boundary' >&2
  exit 1
else
  presence=$?
  [[ "$presence" -eq 1 ]] || {{ printf '%s\\n' 'libvirt domain inventory is unavailable at future execution boundary' >&2; exit 1; }}
fi
ACTUAL_RUNTIME_PROBE_JSON="$(/usr/bin/python3.13 -B -s -P -S -c {shlex.quote(runtime_probe_code)} "$SOURCE_ROOT" "$RUNTIME_SITE" "$EXPECTED_SOURCE_MANIFEST_JSON" "$EXPECTED_RUNTIME_MANIFEST_JSON")"
[[ "$ACTUAL_RUNTIME_PROBE_JSON" == "$EXPECTED_RUNTIME_PROBE_JSON" ]]
[[ "$(printf '%s' "$ACTUAL_RUNTIME_PROBE_JSON" | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')" == "$EXPECTED_RUNTIME_PROBE_SHA256" ]]
ACTUAL_CAPABILITY_PROBE_JSON="$(/usr/bin/virsh --connect "$LIBVIRT_URI" domcapabilities --virttype kvm --arch x86_64 --machine "$MACHINE_TYPE" | /usr/bin/python3.13 -B -s -P -S -c {shlex.quote(capability_probe_code)})"
[[ "$ACTUAL_CAPABILITY_PROBE_JSON" == "$EXPECTED_CAPABILITY_PROBE_JSON" ]]
[[ "$(printf '%s' "$ACTUAL_CAPABILITY_PROBE_JSON" | /usr/bin/sha256sum | /usr/bin/awk '{{print $1}}')" == "$EXPECTED_CAPABILITY_PROBE_SHA256" ]]
validate_firmware_runtime

TEMP_DIR="$(/usr/bin/mktemp -d -p "$TEMP_PARENT" overseer-phase-b-rehearsal.XXXXXX)"
OVERLAY="$TEMP_DIR/overlay.qcow2"
SEED_ISO="$TEMP_DIR/seed.iso"
NVRAM="$TEMP_DIR/nvram.fd"
SERIAL_PIPE="$TEMP_DIR/serial"
SERIAL_LOG="$TEMP_DIR/serial.log"
SERIAL_STATUS="$TEMP_DIR/serial.status"
SERIAL_STOP="$TEMP_DIR/serial.stop"
SERIAL_COLLECTOR="$TEMP_DIR/serial-collector.py"
DOMAIN_XML="$TEMP_DIR/domain.xml"
USER_DATA="$TEMP_DIR/user-data"
META_DATA="$TEMP_DIR/meta-data"
SOURCE_ARCHIVE="$TEMP_DIR/source.zip"
RUNTIME_ARCHIVE="$TEMP_DIR/runtime.zip"
SOURCE_MANIFEST_FILE="$TEMP_DIR/source-manifest.json"
RUNTIME_MANIFEST_FILE="$TEMP_DIR/runtime-manifest.json"
temp_layout_is_exact

/usr/bin/install -m 0600 /dev/null "$USER_DATA"
/usr/bin/install -m 0600 /dev/null "$META_DATA"
/usr/bin/install -m 0600 /dev/null "$DOMAIN_XML"
/usr/bin/install -m 0600 /dev/null "$SOURCE_MANIFEST_FILE"
/usr/bin/install -m 0600 /dev/null "$RUNTIME_MANIFEST_FILE"
/usr/bin/install -m 0600 /dev/null "$SERIAL_COLLECTOR"
printf '%s' "$EXPECTED_SOURCE_MANIFEST_JSON" >"$SOURCE_MANIFEST_FILE"
printf '%s' "$EXPECTED_RUNTIME_MANIFEST_JSON" >"$RUNTIME_MANIFEST_FILE"
/usr/bin/python3.13 -B -s -P -S -c {shlex.quote(archive_builder)} "$SOURCE_ROOT" "$EXPECTED_SOURCE_MANIFEST_JSON" "$SOURCE_ARCHIVE"
/usr/bin/python3.13 -B -s -P -S -c {shlex.quote(archive_builder)} "$RUNTIME_SITE" "$EXPECTED_RUNTIME_MANIFEST_JSON" "$RUNTIME_ARCHIVE"
/usr/bin/cat >"$SERIAL_COLLECTOR" <<'PY_SERIAL_COLLECTOR'
{collector}PY_SERIAL_COLLECTOR

printf '%s  %s\\n' "$EXPECTED_SHA512" "$BASE_IMAGE" | /usr/bin/sha512sum --check -
/usr/bin/qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY" {OVERLAY_GIB}G
/usr/bin/install -m 0600 "$FIRMWARE_VARS_TEMPLATE" "$NVRAM"
printf '%s  %s\n' "$FIRMWARE_VARS_SHA256" "$NVRAM" | /usr/bin/sha256sum --check -
/usr/bin/cat >"$USER_DATA" <<'CLOUD_INIT'
{cloud_init}CLOUD_INIT
/usr/bin/cat >"$META_DATA" <<'META_DATA'
{meta_data}META_DATA
/usr/bin/genisoimage -quiet -output "$SEED_ISO" -volid cidata -joliet -rock -graft-points "user-data=$USER_DATA" "meta-data=$META_DATA" "source.zip=$SOURCE_ARCHIVE" "runtime.zip=$RUNTIME_ARCHIVE" "source-manifest.json=$SOURCE_MANIFEST_FILE" "runtime-manifest.json=$RUNTIME_MANIFEST_FILE"

/usr/bin/mkfifo -m 0600 "$SERIAL_PIPE.in" "$SERIAL_PIPE.out"
/usr/bin/python3.13 -B -s -P -S "$SERIAL_COLLECTOR" "$SERIAL_PIPE.out" "$SERIAL_LOG" "$SERIAL_STATUS" "$SERIAL_STOP" "$MAX_SERIAL_BYTES" "$MAX_SERIAL_LINE_BYTES" &
COLLECTOR_PID=$!

/usr/bin/cat >"$DOMAIN_XML" <<DOMAIN_XML
{domain_xml}DOMAIN_XML
verify_lock
validate_firmware_runtime
/usr/bin/virsh --connect "$LIBVIRT_URI" define --validate "$DOMAIN_XML"
verify_domain_ownership
/usr/bin/virsh --connect "$LIBVIRT_URI" autostart --disable "$VM_UUID"
/usr/bin/virsh --connect "$LIBVIRT_URI" dominfo "$VM_UUID" | /usr/bin/awk -F: '/^Autostart/ {{gsub(/[[:space:]]/, "", $2); print $2}}' | /usr/bin/grep -qx disable
verify_domain_ownership
/usr/bin/virsh --connect "$LIBVIRT_URI" start "$VM_UUID"

if ! /usr/bin/timeout --foreground "${{RESULT_TIMEOUT_SECONDS}}s" /usr/bin/bash -c '
  status="$1"
  while [[ ! -s "$status" ]]; do /usr/bin/sleep 1; done
' /usr/bin/bash "$SERIAL_STATUS"; then
  printf '%s\\n' 'bounded rehearsal result wait expired' >&2
  exit 1
fi
SERIAL_RESULT="$(<"$SERIAL_STATUS")"
if [[ "$SERIAL_RESULT" == "overflow" ]]; then
  printf '%s\\n' 'serial output exceeded the bounded limit' >&2
  exit 1
fi
[[ "$SERIAL_RESULT" == "complete" ]]
shutdown_and_undefine
stop_collector
SERIAL_RESULT="$(<"$SERIAL_STATUS")"
if [[ "$SERIAL_RESULT" == "overflow" ]]; then
  printf '%s\\n' 'serial output exceeded the bounded limit after completion' >&2
  exit 1
fi
[[ "$SERIAL_RESULT" == "complete" ]]
/usr/bin/python3.13 -B -s -P -S - "$SERIAL_LOG" <<'PY_RESULT_VALIDATOR'
{validator}PY_RESULT_VALIDATOR
"""


def render_plan(
    *,
    source_commit: str,
    source_root: Path,
    runtime_site: Path,
    source_manifest: Mapping[str, object],
    runtime_manifest: Mapping[str, object],
    runtime_probe: Mapping[str, object],
    capability_probe: Mapping[str, object],
    owner_binding: Mapping[str, object],
    base_image: Path = DEFAULT_BASE_IMAGE,
    temp_parent: Path = DEFAULT_TEMP_PARENT,
) -> dict[str, object]:
    """Revalidate the owner, then render canonical plan data and its approval digest."""

    _require_full_source_commit(source_commit)
    for path, label in (
        (source_root, "source"),
        (runtime_site, "runtime"),
        (base_image, "base image"),
        (temp_parent, "temporary"),
    ):
        _validate_host_path(path, label)
    validated_owner_binding = _validate_owner_binding_live(
        owner_binding, source_root=source_root
    )
    validated_source_manifest = _validate_artifact_manifest(source_manifest, kind="source")
    validated_runtime_manifest = _validate_artifact_manifest(runtime_manifest, kind="runtime")
    source_manifest_digest = _manifest_digest(validated_source_manifest)
    runtime_manifest_digest = _manifest_digest(validated_runtime_manifest)
    validated_probe = _validate_runtime_probe(
        runtime_probe,
        source_root=source_root,
        runtime_site=runtime_site,
        source_manifest_digest=source_manifest_digest,
        runtime_manifest_digest=runtime_manifest_digest,
    )
    probe_digest = _manifest_digest(validated_probe)
    validated_capability = _validate_capability_probe(capability_probe)
    capability_digest = _manifest_digest(validated_capability)
    run_id, vm_uuid, vm_name = _run_identity(
        source_commit, source_manifest_digest, runtime_manifest_digest
    )
    cloud_init = _cloud_init(
        validated_probe,
        source_commit,
        source_manifest_digest,
        runtime_manifest_digest,
    )
    meta_data = _meta_data(vm_name)
    domain_xml = _domain_xml(vm_name=vm_name, vm_uuid=vm_uuid, run_id=run_id)
    inputs = _plan_inputs(
        source_manifest=validated_source_manifest,
        runtime_manifest=validated_runtime_manifest,
    )
    script = _future_script(
        source_commit=source_commit,
        vm_name=vm_name,
        vm_uuid=vm_uuid,
        run_id=run_id,
        source_root=source_root,
        runtime_site=runtime_site,
        source_manifest=validated_source_manifest,
        runtime_manifest=validated_runtime_manifest,
        runtime_probe=validated_probe,
        runtime_probe_digest=probe_digest,
        capability_probe=validated_capability,
        capability_probe_digest=capability_digest,
        base_image=base_image,
        temp_parent=temp_parent,
        domain_xml=domain_xml,
        cloud_init=cloud_init,
        meta_data=meta_data,
        owner_binding=validated_owner_binding,
    )
    plan: dict[str, object] = {
        "schemaVersion": REHEARSAL_SCHEMA,
        "sourceCommit": source_commit,
        "ownerBinding": validated_owner_binding,
        "image": {
            "url": BASE_IMAGE_URL,
            "sha512": BASE_IMAGE_SHA512,
            "localPath": str(base_image),
            "format": "qcow2",
        },
        "firmware": {
            **dict(_capability_probe_record()["firmware"]),
            "nvramPath": "$TEMP_DIR/nvram.fd",
            "nvramMode": "0600",
        },
        "libvirtUri": LIBVIRT_URI,
        "vm": {
            "name": vm_name,
            "uuid": vm_uuid,
            "runId": run_id,
            "memoryMiB": MEMORY_MIB,
            "vcpus": VCPUS,
            "overlayGiB": OVERLAY_GIB,
            "network": "none",
            "autostart": False,
            "lifecycle": "temporary-persistent-owned-explicit-undefine",
        },
        "sourceArtifact": inputs["sourceArtifact"],
        "runtimeArtifact": inputs["runtimeArtifact"],
        "hostFilesystemShares": [],
        "networkDevices": [],
        "tempParent": str(temp_parent),
        "serialLog": {
            "directory": "<fresh-mktemp-dir>",
            "path": "$TEMP_DIR/serial.log",
            "mode": "0600",
            "transport": "bounded-pipe-collector",
            "maxBytes": MAX_SERIAL_BYTES,
            "maxLineBytes": MAX_SERIAL_LINE_BYTES,
        },
        "runtimeProbe": validated_probe,
        "runtimeProbeDigest": probe_digest,
        "capabilityProbe": validated_capability,
        "capabilityProbeDigest": capability_digest,
        "taskTwoPlaceholders": list(TASK_TWO_PLACEHOLDERS),
        "cloudInit": cloud_init,
        "metaData": meta_data,
        "domainXml": domain_xml,
        "futureScript": script,
        "futureScriptSha256": hashlib.sha256(script.encode()).hexdigest(),
        "sessionRuntimeDirectory": str(SESSION_RUNTIME_DIR),
        "executionEnvironment": dict(MINIMAL_ENV),
        "executionCommand": [
            EXACT_TOOLS["env"],
            "-i",
            *(f"{key}={value}" for key, value in sorted(MINIMAL_ENV.items())),
            EXACT_TOOLS["bash"],
            "<approved-future-script>",
        ],
        "approvalBoundary": "planDigest",
        "exclusions": ["package import", "host service action", "Phase B", "cutover"],
    }
    return {
        "plan": plan,
        "planDigest": hashlib.sha256(canonical_json(plan).encode()).hexdigest(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    preflight_parser = subparsers.add_parser("preflight")
    render_parser = subparsers.add_parser("render-plan")
    for sub in (preflight_parser, render_parser):
        sub.add_argument("--source-commit", required=True)
        sub.add_argument("--source-root", type=Path, default=Path.cwd())
        sub.add_argument("--runtime-site", type=Path, default=DEFAULT_RUNTIME_SITE)
        sub.add_argument("--base-image", type=Path, default=DEFAULT_BASE_IMAGE)
        sub.add_argument("--temp-parent", type=Path, default=DEFAULT_TEMP_PARENT)
    preflight_parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    preflight_parser.add_argument("--owner-thread", required=True)
    preflight_parser.add_argument("--owner-project", type=Path, required=True)
    render_parser.add_argument("--source-manifest-json", required=True)
    render_parser.add_argument("--runtime-manifest-json", required=True)
    render_parser.add_argument("--runtime-probe-json", required=True)
    render_parser.add_argument("--capability-probe-json", required=True)
    render_parser.add_argument("--owner-binding-json", required=True)
    return parser


def _json_object(value: str, label: str) -> dict[str, object]:
    try:
        record = json.loads(value)
    except json.JSONDecodeError as error:
        raise PreflightError(f"{label} JSON is invalid") from error
    if not isinstance(record, dict):
        raise PreflightError(f"{label} JSON is invalid")
    return record


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.subcommand == "preflight":
            result = preflight(
                source_commit=args.source_commit,
                repo_root=args.repo_root,
                source_root=args.source_root,
                owner_thread=args.owner_thread,
                owner_project=args.owner_project,
                runtime_site=args.runtime_site,
                base_image=args.base_image,
                temp_parent=args.temp_parent,
            )
        else:
            result = render_plan(
                source_commit=args.source_commit,
                source_root=args.source_root,
                runtime_site=args.runtime_site,
                source_manifest=_json_object(args.source_manifest_json, "source manifest"),
                runtime_manifest=_json_object(args.runtime_manifest_json, "runtime manifest"),
                runtime_probe=_json_object(args.runtime_probe_json, "runtime probe"),
                capability_probe=_json_object(args.capability_probe_json, "capability probe"),
                owner_binding=_json_object(args.owner_binding_json, "owner binding"),
                base_image=args.base_image,
                temp_parent=args.temp_parent,
            )
    except (PreflightError, subprocess.CalledProcessError) as error:
        print(canonical_json({"status": "rejected", "reason": str(error)}), file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
