"""Explicit privileged host operations for an exact approved backup plan.

Importing this module is inert. Construction requires an explicit privilege
confirmation and root identity; execution accepts only byte-for-byte plan steps.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import errno
import re
import secrets
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import pwd
import grp
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping

from .backup_contract import (
    PROVISIONING_CONTRACT_VERSION,
    load_packaged_provisioning_contract,
    runtime_artifact_identity,
)
from .backup_provisioning import DonutHoleBackupProvisioningPlan, ProvisioningStep

PRIVILEGED_CONFIRMATION="execute-exact-donuthole-backup-provisioning-plan"
OPERATOR_USER="god"
def _reviewed_backup_tool_schemas() -> dict[str, object]:
    contract = load_packaged_provisioning_contract()
    tools = contract.raw["mcp_tools"]
    if not isinstance(tools, Mapping):
        raise RuntimeError("reviewed provisioning contract tool schemas are invalid")
    return json.loads(json.dumps(tools, sort_keys=True, separators=(",", ":")))


EXPECTED_BACKUP_TOOL_SCHEMAS = _reviewed_backup_tool_schemas()
RUNTIME_EXCLUDED={".git",".venv",".codex",".agents","__pycache__",".pytest_cache","tests","docs"}
MAX_REDACTED_DIAGNOSTIC_LINE_BYTES=4096
MAX_WRAPPER_DIAGNOSTIC_BYTES=8192
MAX_BOUNDARY_BYTES = 16 * 1024 * 1024
MAX_BOUNDARY_COUNT = 64
_PRIVILEGED_BOUNDARY_HELPER = r'''
import ctypes, errno, hashlib, json, os, pwd, re, secrets, stat, sys, time

MAX_BYTES = 16 * 1024 * 1024

def emit(value):
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")))

def owner_ids(name):
    item = pwd.getpwnam(name)
    return item.pw_uid, item.pw_gid

def digest_fd(fd):
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_BYTES:
            raise ValueError("oversized")
        digest.update(chunk)
    return total, "sha256:" + digest.hexdigest()

def attest(path, owner, mode, barrier=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"status": "absent"}
    try:
        item = os.fstat(fd)
        uid, gid = owner_ids(owner)
        if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or item.st_uid != uid or item.st_gid != gid or stat.S_IMODE(item.st_mode) != int(mode):
            return {"status": "unsafe"}
        if barrier is not None:
            open(barrier + ".ready", "wb").close()
            while not os.path.exists(barrier + ".go"):
                time.sleep(0.001)
        size, digest = digest_fd(fd)
        final = os.fstat(fd)
        if (final.st_dev, final.st_ino, final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode), final.st_nlink, final.st_size) != (item.st_dev, item.st_ino, item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode), item.st_nlink, size):
            return {"status": "unsafe"}
        return {"status": "present", "dev": item.st_dev, "ino": item.st_ino, "uid": item.st_uid, "gid": item.st_gid, "mode": stat.S_IMODE(item.st_mode), "nlink": item.st_nlink, "size": size, "digest": digest}
    finally:
        os.close(fd)

def unlink_exact(path, owner, mode, expected_dev, expected_ino, expected):
    def parse_identity(value):
        if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
            raise ValueError("noncanonical identity")
        parsed = int(value, 10)
        if parsed > (1 << 64) - 1:
            raise ValueError("identity overflow")
        return parsed
    expected_dev = parse_identity(expected_dev)
    expected_ino = parse_identity(expected_ino)
    parent, name = os.path.split(path)
    parent_fd = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        except FileNotFoundError:
            return {"status": "conflict"}
        try:
            item = os.fstat(fd)
            uid, gid = owner_ids(owner)
            if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or
                    item.st_uid != uid or item.st_gid != gid or
                    stat.S_IMODE(item.st_mode) != int(mode)):
                return {"status": "unsafe"}
            if item.st_dev != expected_dev or item.st_ino != expected_ino:
                return {"status": "conflict"}
            size, digest = digest_fd(fd)
            final = os.fstat(fd)
            if (final.st_dev, final.st_ino, final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode), final.st_nlink, final.st_size) != (item.st_dev, item.st_ino, item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode), item.st_nlink, size):
                return {"status": "unsafe"}
            if digest != expected:
                return {"status": "conflict"}
            try:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return {"status": "conflict"}
            if named.st_dev != item.st_dev or named.st_ino != item.st_ino:
                return {"status": "conflict"}
            if named.st_dev != expected_dev or named.st_ino != expected_ino:
                return {"status": "conflict"}
            os.unlink(name, dir_fd=parent_fd)
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return {"status": "removed", "size": size}
            return {"status": "conflict"}
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)

def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        raise ValueError("noncanonical identity")
    parsed = int(value, 10)
    if parsed > (1 << 64) - 1:
        raise ValueError("identity overflow")
    return parsed

def rename_noreplace(parent_fd, old_name, new_name):
    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise OSError(errno.ENOSYS, "renameat2 unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(parent_fd, old_name.encode(), parent_fd, new_name.encode(), 1)
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))

def stream_scandir(path):
    entries = os.scandir(path)
    try:
        yield from entries
    finally:
        entries.close()

def runtime_digest_fd(root_fd, commit):
    files = []
    total = 0
    excluded = {".git", ".venv", ".codex", ".agents", "__pycache__", ".pytest_cache", "tests", "docs"}
    def walk(fd, prefix=()):
        nonlocal total
        entries = sorted(os.scandir(fd), key=lambda entry: entry.name)
        for entry in entries:
            relative = prefix + (entry.name,)
            if any(part in excluded for part in relative):
                continue
            item = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(item.st_mode) or (not stat.S_ISDIR(item.st_mode) and not stat.S_ISREG(item.st_mode)):
                raise OSError(errno.ELOOP, "unsupported runtime entry")
            if stat.S_ISDIR(item.st_mode):
                child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (item.st_dev, item.st_ino, item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)):
                        raise OSError(errno.EAGAIN, "runtime entry replaced")
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
            else:
                file_fd = os.open(entry.name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened = os.fstat(file_fd)
                    if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode), opened.st_nlink) != (item.st_dev, item.st_ino, item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode), item.st_nlink):
                        raise OSError(errno.EAGAIN, "runtime entry replaced")
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(file_fd, 1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_BYTES:
                            raise ValueError("oversized")
                        digest.update(chunk)
                    files.append({"path": "/".join(relative), "mode": stat.S_IMODE(item.st_mode), "sha256": "sha256:" + digest.hexdigest()})
                finally:
                    os.close(file_fd)
    walk(root_fd)
    payload = json.dumps({"version": 1, "commit": commit, "files": files}, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()

def claim_directory(path, expected_dev, expected_ino, expected_uid, expected_gid, expected_mode, recursive, expected_digest=None, commit=None, barrier=None, verify_digest=True, child_barrier=None):
    expected_dev = identity(expected_dev)
    expected_ino = identity(expected_ino)
    expected_uid = identity(expected_uid)
    expected_gid = identity(expected_gid)
    expected_mode = identity(expected_mode)
    parent, name = os.path.split(path)
    parent_fd = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            item = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return {"status": "absent"}
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            return {"status": "unsafe"}
        if (item.st_dev, item.st_ino, item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) != (expected_dev, expected_ino, expected_uid, expected_gid, expected_mode):
            return {"status": "conflict"}
        if barrier is not None:
            open(barrier + ".ready", "wb").close()
            deadline = time.monotonic() + 10
            while not os.path.exists(barrier + ".go"):
                if time.monotonic() >= deadline:
                    return {"status": "error"}
                time.sleep(0.001)
        for _ in range(8):
            quarantine = ".overseer-claim-" + secrets.token_hex(16)
            try:
                rename_noreplace(parent_fd, name, quarantine)
                break
            except FileExistsError:
                continue
        else:
            return {"status": "error"}
        claimed_fd = None
        try:
            claimed_fd = os.open(quarantine, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
            claimed = os.fstat(claimed_fd)
            if (claimed.st_dev, claimed.st_ino) != (expected_dev, expected_ino):
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    rename_noreplace(parent_fd, quarantine, name)
                return {"status": "conflict"}
            if (claimed.st_uid, claimed.st_gid, stat.S_IMODE(claimed.st_mode)) != (expected_uid, expected_gid, expected_mode):
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    rename_noreplace(parent_fd, quarantine, name)
                return {"status": "conflict"}
            if not recursive and os.listdir(claimed_fd):
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    rename_noreplace(parent_fd, quarantine, name)
                return {"status": "conflict"}
            if recursive:
                if verify_digest and (not isinstance(expected_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest) or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit)):
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        rename_noreplace(parent_fd, quarantine, name)
                    return {"status": "conflict"}
                digest = runtime_digest_fd(claimed_fd, commit) if verify_digest else None
                if verify_digest and digest != expected_digest:
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        rename_noreplace(parent_fd, quarantine, name)
                    return {"status": "conflict"}
                references = runtime_references(os.path.abspath(os.path.join(parent or ".", quarantine)), ignored_pid=os.getpid(), logical_path=os.path.abspath(path))
                if references.get("status") != "clear":
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        rename_noreplace(parent_fd, quarantine, name)
                    return {"status": "conflict"}
            root_device = claimed.st_dev
            child_pause_used = False
            def remove_tree(fd):
                nonlocal child_pause_used
                for entry in stream_scandir(fd):
                    child = entry.name
                    child_stat = os.stat(child, dir_fd=fd, follow_symlinks=False)
                    if child_stat.st_dev != root_device:
                        raise OSError(errno.EXDEV, "descendant device differs")
                    if not stat.S_ISLNK(child_stat.st_mode) and (not stat.S_ISDIR(child_stat.st_mode) and not stat.S_ISREG(child_stat.st_mode)):
                        raise OSError(errno.ELOOP, "unexpected entry")
                    quarantine_child = ".overseer-child-" + secrets.token_hex(16)
                    rename_noreplace(fd, child, quarantine_child)
                    try:
                        if child_barrier is not None and not child_pause_used:
                            child_pause_used = True
                            open(child_barrier + ".ready", "wb").close()
                            deadline = time.monotonic() + 10
                            while not os.path.exists(child_barrier + ".go"):
                                if time.monotonic() >= deadline:
                                    raise OSError(errno.ETIMEDOUT, "child barrier timed out")
                                time.sleep(0.001)
                            try:
                                os.stat(child, dir_fd=fd, follow_symlinks=False)
                            except FileNotFoundError:
                                pass
                            else:
                                raise OSError(errno.EEXIST, "child name replaced")
                        if stat.S_ISDIR(child_stat.st_mode):
                            child_fd = os.open(quarantine_child, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
                            try:
                                opened = os.fstat(child_fd)
                                if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (child_stat.st_dev, child_stat.st_ino, child_stat.st_uid, child_stat.st_gid, stat.S_IMODE(child_stat.st_mode)):
                                    raise OSError(errno.EAGAIN, "entry replaced")
                                remove_tree(child_fd)
                            finally:
                                os.close(child_fd)
                            os.rmdir(quarantine_child, dir_fd=fd)
                        elif stat.S_ISLNK(child_stat.st_mode):
                            opened = os.stat(quarantine_child, dir_fd=fd, follow_symlinks=False)
                            if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_gid) != (child_stat.st_dev, child_stat.st_ino, child_stat.st_mode, child_stat.st_uid, child_stat.st_gid):
                                raise OSError(errno.EAGAIN, "symlink replaced")
                            os.unlink(quarantine_child, dir_fd=fd)
                        else:
                            child_fd = os.open(quarantine_child, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=fd)
                            try:
                                opened = os.fstat(child_fd)
                                if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (child_stat.st_dev, child_stat.st_ino, child_stat.st_uid, child_stat.st_gid, stat.S_IMODE(child_stat.st_mode)):
                                    raise OSError(errno.EAGAIN, "entry replaced")
                            finally:
                                os.close(child_fd)
                            os.unlink(quarantine_child, dir_fd=fd)
                    except OSError:
                        try:
                            rename_noreplace(fd, quarantine_child, child)
                        except OSError:
                            raise OSError(errno.EEXIST, "child restoration ambiguous")
                        raise
            if recursive:
                remove_tree(claimed_fd)
            os.rmdir(quarantine, dir_fd=parent_fd)
            return {"status": "removed"}
        except OSError as error:
            try:
                if claimed_fd is not None:
                    try:
                        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        rename_noreplace(parent_fd, quarantine, name)
                    else:
                        return {"status": "error"}
            except OSError:
                return {"status": "error"}
            return {"status": "conflict" if error.errno in (errno.ENOTEMPTY, errno.EEXIST, errno.EAGAIN, errno.ELOOP, errno.EXDEV) else "error"}
        finally:
            if claimed_fd is not None:
                os.close(claimed_fd)
    finally:
        os.close(parent_fd)

def promote_exact(source, destination, expected_dev, expected_ino, expected_uid, expected_gid, expected_mode):
    expected_dev = identity(expected_dev)
    expected_ino = identity(expected_ino)
    expected_uid = identity(expected_uid)
    expected_gid = identity(expected_gid)
    expected_mode = identity(expected_mode)
    source_parent, source_name = os.path.split(source)
    destination_parent, destination_name = os.path.split(destination)
    if os.path.realpath(source_parent or ".") != os.path.realpath(destination_parent or "."):
        return {"status": "conflict"}
    parent_fd = os.open(source_parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            item = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return {"status": "conflict"}
        if not stat.S_ISDIR(item.st_mode) or (item.st_dev, item.st_ino, item.st_uid, item.st_gid, stat.S_IMODE(item.st_mode)) != (expected_dev, expected_ino, expected_uid, expected_gid, expected_mode):
            return {"status": "conflict"}
        try:
            os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
            return {"status": "conflict"}
        except FileNotFoundError:
            pass
        rename_noreplace(parent_fd, source_name, destination_name)
        final = os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        return {"status": "promoted"} if (final.st_dev, final.st_ino, final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode)) == (expected_dev, expected_ino, expected_uid, expected_gid, expected_mode) else {"status": "error"}
    except FileExistsError:
        return {"status": "conflict"}
    finally:
        os.close(parent_fd)

def absent(path):
    parent, name = os.path.split(path)
    parent_fd = os.open(parent or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        try:
            item = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return {"status": "absent"}
        return {"status": "unsafe" if stat.S_ISLNK(item.st_mode) else "present"}
    finally:
        os.close(parent_fd)

def attest_dir(path, owner, mode):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {"status": "absent"}
    try:
        item = os.fstat(fd)
        uid, gid = owner_ids(owner)
        if not stat.S_ISDIR(item.st_mode) or item.st_nlink < 2 or item.st_uid != uid or item.st_gid != gid or stat.S_IMODE(item.st_mode) != int(mode):
            return {"status": "unsafe"}
        return {"status": "present", "dev": item.st_dev, "ino": item.st_ino, "uid": item.st_uid, "gid": item.st_gid, "mode": stat.S_IMODE(item.st_mode), "nlink": item.st_nlink}
    finally:
        os.close(fd)

def inside(root, candidate):
    if candidate.endswith(" (deleted)"):
        candidate = candidate[:-10]
    resolved = os.path.realpath(candidate)
    return resolved == root or resolved.startswith(root + os.sep)

def lexical_inside(root, candidate):
    if candidate.endswith(" (deleted)"):
        candidate = candidate[:-10]
    if not candidate.startswith("/"):
        return False
    normalized = os.path.normpath(candidate)
    return normalized == root or normalized.startswith(root + os.sep)

def runtime_references(path, ignored_pid=None, proc_root="/proc", logical_path=None):
    root = os.path.realpath(path)
    lexical_root = os.path.abspath(os.path.normpath(logical_path or path))
    count = 0
    for entry in stream_scandir(proc_root):
        if not entry.name.isdigit():
            continue
        if ignored_pid is not None and int(entry.name) == ignored_pid:
            continue
        base = os.path.join(proc_root, entry.name)
        for relative in ("cwd", "root", "exe"):
            try:
                if inside(root, os.readlink(os.path.join(base, relative))):
                    count += 1
                    if count > 64:
                        return {"status": "error"}
                    return {"status": "referenced", "count": count}
            except FileNotFoundError:
                continue
            except OSError:
                return {"status": "error"}
        try:
            fd_dir = os.path.join(base, "fd")
            for descriptor in stream_scandir(fd_dir):
                try:
                    if inside(root, os.readlink(descriptor.path)):
                        count += 1
                        return {"status": "referenced", "count": count}
                except FileNotFoundError:
                    continue
                except OSError:
                    return {"status": "error"}
        except FileNotFoundError:
            pass
        except OSError:
            return {"status": "error"}
        try:
            with open(os.path.join(base, "maps"), "rb", buffering=0) as maps:
                data = maps.read(128 * 1024)
            if len(data) == 128 * 1024:
                return {"status": "error"}
            for line in data.decode("utf-8", "strict").splitlines():
                fields = line.split()
                if len(fields) >= 6 and inside(root, " ".join(fields[5:])):
                    count += 1
                    return {"status": "referenced", "count": count}
        except FileNotFoundError:
            pass
        except (OSError, UnicodeError):
            return {"status": "error"}
        try:
            with open(os.path.join(base, "cmdline"), "rb", buffering=0) as cmdline:
                data = cmdline.read(128 * 1024 + 1)
            if not data:
                continue
            if len(data) > 128 * 1024 or not data.endswith(b"\0"):
                return {"status": "error"}
            arguments = data.rstrip(b"\0").split(b"\0")
            if not arguments or not arguments[0]:
                return {"status": "error"}
            decoded = arguments[0].decode("utf-8", "strict")
            if lexical_inside(lexical_root, decoded):
                count += 1
                return {"status": "referenced", "count": count}
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            return {"status": "error"}
    return {"status": "clear", "count": 0}

try:
    operation = sys.argv[1]
    if operation == "attest":
        result = attest(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else None)
    elif operation == "dir_attest":
        result = attest_dir(sys.argv[2], sys.argv[3], sys.argv[4])
    elif operation == "unlink":
        result = unlink_exact(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])
    elif operation == "rmdir":
        result = claim_directory(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], False, None, None, sys.argv[8] if len(sys.argv) > 8 else None)
    elif operation == "remove_tree":
        result = claim_directory(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], True, sys.argv[8] if len(sys.argv) > 8 else None, sys.argv[9] if len(sys.argv) > 9 else None, sys.argv[10] if len(sys.argv) > 10 and sys.argv[10] else None, True, sys.argv[11] if len(sys.argv) > 11 and sys.argv[11] else None)
    elif operation == "remove_staging_tree":
        result = claim_directory(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], True, None, None, sys.argv[10] if len(sys.argv) > 10 and sys.argv[10] else None, False, sys.argv[11] if len(sys.argv) > 11 and sys.argv[11] else None)
    elif operation == "promote":
        result = promote_exact(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8])
    elif operation == "absence":
        result = absent(sys.argv[2])
    elif operation == "references":
        result = runtime_references(sys.argv[2], ignored_pid=os.getpid(), proc_root=sys.argv[3] if len(sys.argv) > 3 else "/proc")
    else:
        result = {"status": "error"}
    emit(result)
except (OSError, KeyError, TypeError, ValueError):
    emit({"status": "error"})
'''
WRAPPER_ERROR_PATTERNS=(
    (re.compile(r"^sudo: a password is required$"),"SUDO_AUTH_REQUIRED"),
    (re.compile(r"^sudo: unknown user .{1,128}$"),"SUDO_TARGET_USER_INVALID"),
    (re.compile(r"^sudo: unable to execute .{1,2048}: Permission denied$"),"SUDO_EXEC_PERMISSION_DENIED"),
    (re.compile(r"^sudo: unable to execute .{1,2048}: No such file or directory$"),"SUDO_EXEC_NOT_FOUND"),
    (re.compile(r"^sudo: (?:account validation failure, is your account locked\?|PAM account management error: .{1,512})$"),"SUDO_ACCOUNT_REJECTED"),
)

class RedactedHostOperationError(RuntimeError):
    """A stable diagnostic safe to persist outside the privileged adapter."""
    def __init__(self,code:str)->None:
        self.code=code if re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}",code) else "PROCESS_FAILED"
        super().__init__(f"allowlisted host operation failed ({self.code})")


class HostOperationDisposition(str, Enum):
    CHANGED = "changed"
    VERIFIED_NOOP = "verified_noop"


_SAFE_EVIDENCE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SAFE_CODES = frozenset({
    "ACL_APPLIED", "ACL_REMOVED", "BACKUP_POLICY_VERIFIED", "CODEX_MCP_URL_VERIFIED",
    "CONFIG_ALREADY_CURRENT", "CONFIG_ALREADY_ABSENT", "CONFIG_CONFLICT", "CONFIG_INSTALLED", "CONFIG_REMOVED", "CURSOR_KEY_REMOVED", "CURSOR_KEY_ALREADY_ABSENT",
    "DIRECTORY_ALREADY_ABSENT", "DIRECTORY_ALREADY_CURRENT", "DIRECTORY_CONFLICT",
    "DIRECTORY_CREATED", "DIRECTORY_REMOVED", "DIRECTORY_CONFLICT", "ENDPOINT_READY", "ENDPOINT_CONFLICT", "GPG_IDENTITY_VERIFIED",
    "MCP_SCHEMA_VERIFIED", "ROOTS_ALREADY_REGISTERED", "ROOTS_REGISTERED", "ROOT_CONFLICT",
    "RUNTIME_ALREADY_ABSENT", "RUNTIME_ALREADY_CURRENT", "RUNTIME_CONFLICT", "RUNTIME_INSTALLED",
    "RUNTIME_REMOVED", "SECRET_ALREADY_ABSENT", "SECRET_ALREADY_PRESENT", "SECRET_CONFLICT",
    "SECRET_CREATED", "SECRET_REMOVED", "SOURCE_ALREADY_PUBLISHED", "SYSTEMD_ATTESTATION_INVALID",
    "SYSTEMD_UNIT_ALREADY_CURRENT", "SYSTEMD_UNIT_ALREADY_ABSENT", "SYSTEMD_UNIT_CONFLICT", "SYSTEMD_UNIT_INSTALLED", "SYSTEMD_UNIT_REMOVED",
    "SYSTEM_SERVICE_DISABLED", "SYSTEM_SERVICE_RESTARTED", "SYSTEM_USER_ALREADY_CURRENT",
    "SYSTEM_USER_CONFLICT", "SYSTEM_USER_CREATED", "SYSTEM_USER_ALREADY_ABSENT", "SYSTEM_USER_REMOVED", "SYSTEM_USER_RETAINED_WITH_STATE",
    "TOKEN_ALREADY_PRESENT", "TOKEN_ALREADY_ABSENT", "TOKEN_CONFLICT", "TOKEN_INSTALLED", "TOKEN_REMOVED", "FILE_CONFLICT",
    "USER_SERVICE_DISABLED", "USER_SERVICE_ENABLED", "USER_SERVICE_NOT_RESTORED", "SECRET_RETAINED_WITH_BACKUPS", "PROCESS_FAILED",
})
_SAFE_EVIDENCE_KEYS = frozenset({
    "active_enter_timestamp_monotonic", "config_digest", "identity_digest", "runtime_digest",
    "source_commit_verified", "unit_digest", "roots_added", "roots_verified", "acl_verified", "dev", "ino", "uid", "gid", "mode",
        "enabled", "active", "metadata_verified", "size_bytes", "previously_enabled", "previously_active", "service_verified", "acl_present_before",
})
_FORBIDDEN_EVIDENCE_TERMS = ("stdout", "stderr", "secret", "token", "password", "private", "path", "content", "raw")


@dataclass(frozen=True)
class HostOperationResult:
    disposition: HostOperationDisposition
    safe_code: str
    evidence: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, HostOperationDisposition):
            raise ValueError("host operation disposition is invalid")
        if not isinstance(self.safe_code, str) or self.safe_code not in _SAFE_CODES:
            raise ValueError("host operation safe code is invalid")
        if not isinstance(self.evidence, Mapping):
            raise ValueError("host operation evidence is invalid")
        for key, value in self.evidence.items():
            if not isinstance(key, str) or key not in _SAFE_EVIDENCE_KEYS or any(term in key.lower() for term in _FORBIDDEN_EVIDENCE_TERMS):
                raise ValueError("host operation evidence key is unsafe")
            if isinstance(value, bool):
                continue
            if key in {"dev", "ino", "uid", "gid", "mode"} and isinstance(value, str) and re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
                if int(value) <= (1 << 64) - 1 and (key != "mode" or int(value) <= 0o7777):
                    continue
                raise ValueError("host operation identity evidence is unsafe")
            if type(value) is int and 0 <= value <= 1_000_000_000:
                continue
            if key in {"active_enter_timestamp_monotonic", "dev", "ino", "uid", "gid", "mode"} and isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,38}", value):
                continue
            if isinstance(value, str) and (_SAFE_DIGEST.fullmatch(value) or (key == "source_commit_verified" and value in {"true", "false"})):
                continue
            raise ValueError("host operation evidence value is unsafe")
        object.__setattr__(self, "evidence", dict(self.evidence))

    @classmethod
    def changed(cls, safe_code: str, evidence: Mapping[str, object] | None = None) -> "HostOperationResult":
        return cls(HostOperationDisposition.CHANGED, safe_code, {} if evidence is None else evidence)

    @classmethod
    def verified_noop(cls, safe_code: str, evidence: Mapping[str, object] | None = None) -> "HostOperationResult":
        return cls(HostOperationDisposition.VERIFIED_NOOP, safe_code, {} if evidence is None else evidence)

class ConcreteHostProvisioningAdapter:
    _operation_codes = {
        "verify_published_adapter_source": {"SOURCE_ALREADY_PUBLISHED"}, "install_runtime": {"RUNTIME_ALREADY_CURRENT", "RUNTIME_INSTALLED"},
        "verify_endpoint_migration_ready": {"ENDPOINT_READY"}, "ensure_system_user": {"SYSTEM_USER_ALREADY_CURRENT", "SYSTEM_USER_CREATED"},
        "ensure_directory": {"DIRECTORY_ALREADY_CURRENT", "DIRECTORY_CREATED"}, "generate_secret_file": {"SECRET_ALREADY_PRESENT", "SECRET_CREATED"},
        "generate_cursor_key": {"SECRET_ALREADY_PRESENT", "SECRET_CREATED"}, "install_overseer_api_token": {"TOKEN_ALREADY_PRESENT", "TOKEN_INSTALLED"},
        "ensure_read_only_acl": {"ACL_APPLIED"}, "install_private_config": {"CONFIG_ALREADY_CURRENT", "CONFIG_INSTALLED"},
        "register_authorized_roots": {"ROOTS_ALREADY_REGISTERED", "ROOTS_REGISTERED"}, "stop_disable_user_service": {"USER_SERVICE_DISABLED"},
        "install_systemd_unit": {"SYSTEMD_UNIT_ALREADY_CURRENT", "SYSTEMD_UNIT_INSTALLED"}, "start_enable_system_service": {"SYSTEM_SERVICE_RESTARTED"},
        "verify_mcp_service": {"MCP_SCHEMA_VERIFIED"}, "verify_codex_url": {"CODEX_MCP_URL_VERIFIED"}, "verify_gpg_identity": {"GPG_IDENTITY_VERIFIED"},
        "verify_backup_policy": {"BACKUP_POLICY_VERIFIED"}, "stop_disable_system_service": {"SYSTEM_SERVICE_DISABLED"},
        "remove_systemd_unit": {"SYSTEMD_UNIT_REMOVED", "SYSTEMD_UNIT_ALREADY_ABSENT"}, "restore_enable_user_service": {"USER_SERVICE_ENABLED", "USER_SERVICE_NOT_RESTORED"},
        "remove_private_config": {"CONFIG_REMOVED", "CONFIG_ALREADY_ABSENT"}, "remove_read_only_acl": {"ACL_REMOVED"},
        "remove_cursor_key_if_unreferenced": {"CURSOR_KEY_REMOVED", "CURSOR_KEY_ALREADY_ABSENT"}, "remove_overseer_api_token": {"TOKEN_REMOVED", "TOKEN_ALREADY_ABSENT"},
        "remove_secret_file_if_no_backups": {"SECRET_REMOVED", "SECRET_ALREADY_ABSENT", "SECRET_RETAINED_WITH_BACKUPS"}, "remove_directory_if_empty": {"DIRECTORY_REMOVED", "DIRECTORY_ALREADY_ABSENT"},
        "remove_system_user_if_unused": {"SYSTEM_USER_REMOVED", "SYSTEM_USER_ALREADY_ABSENT", "SYSTEM_USER_RETAINED_WITH_STATE"},
        "remove_runtime_if_unreferenced": {"RUNTIME_REMOVED", "RUNTIME_ALREADY_ABSENT"},
    }
    def __init__(self,plan:DonutHoleBackupProvisioningPlan,*,privileged_confirmation:str,runner:Callable[...,object]=subprocess.run,euid_provider:Callable[[],int]=os.geteuid,username_provider:Callable[[int],str]=lambda uid:pwd.getpwuid(uid).pw_name,mcp_tool_loader:Callable[[str],list[Mapping[str,object]]]|None=None,mcp_retry_delays:tuple[float,...]=(0.25,0.5,1.0,2.0,2.0),sleep:Callable[[float],None]=time.sleep)->None:
        uid=euid_provider()
        if privileged_confirmation!=PRIVILEGED_CONFIRMATION or uid==0 or username_provider(uid)!=OPERATOR_USER: raise PermissionError("explicit god-operator provisioning construction is required")
        if any(isinstance(delay,bool) or not isinstance(delay,(int,float)) or not math.isfinite(delay) or delay<0 for delay in mcp_retry_delays): raise ValueError("MCP retry delays must be finite non-negative numbers")
        self.plan=plan; self._allowed=tuple((*plan.steps,*plan.rollback_steps)); self._run_process=runner; self._mcp_tool_loader=mcp_tool_loader or _load_mcp_tools; self._mcp_retry_delays=tuple(float(delay) for delay in mcp_retry_delays); self._sleep=sleep; self._rollback_prestate={}; self._active_rollback_ordinal=None
        self._dispatch = {
            "verify_published_adapter_source": self._verify_published_adapter_source, "install_runtime": self._install_runtime,
            "verify_endpoint_migration_ready": self._verify_endpoint_migration_ready, "ensure_system_user": self._ensure_system_user,
            "ensure_directory": self._ensure_directory, "generate_secret_file": self._generate_secret_file,
            "install_overseer_api_token": self._install_overseer_api_token, "generate_cursor_key": self._generate_cursor_key,
            "ensure_read_only_acl": self._ensure_read_only_acl, "install_private_config": self._install_private_config,
            "register_authorized_roots": self._register_authorized_roots, "stop_disable_user_service": self._stop_disable_user_service,
            "install_systemd_unit": self._install_systemd_unit, "start_enable_system_service": self._start_enable_system_service,
            "verify_mcp_service": self._verify_mcp_service, "verify_codex_url": self._verify_codex_url,
            "verify_gpg_identity": self._verify_gpg_identity, "verify_backup_policy": self._verify_backup_policy,
            "stop_disable_system_service": self._stop_disable_system_service, "remove_systemd_unit": self._remove_systemd_unit,
            "restore_enable_user_service": self._restore_enable_user_service, "remove_private_config": self._remove_private_config,
            "remove_read_only_acl": self._remove_read_only_acl, "remove_cursor_key_if_unreferenced": self._remove_cursor_key_if_unreferenced,
            "remove_overseer_api_token": self._remove_overseer_api_token, "remove_secret_file_if_no_backups": self._remove_secret_file_if_no_backups,
            "remove_directory_if_empty": self._remove_directory_if_empty, "remove_system_user_if_unused": self._remove_system_user_if_unused,
            "remove_runtime_if_unreferenced": self._remove_runtime_if_unreferenced,
        }

    def execute(self,step:ProvisioningStep)->Mapping[str,object]:
        if step not in self._allowed: raise ValueError("host provisioning step is not an exact approved plan step")
        handler=self._dispatch.get(step.operation)
        if handler is None: raise ValueError("approved operation has no concrete host implementation")
        result = handler(dict(step.arguments))
        if not isinstance(result, HostOperationResult):
            raise ValueError("host provisioning result is invalid")
        if result.safe_code not in self._operation_codes.get(step.operation, set()):
            raise ValueError("host operation safe code is not approved for this operation")
        return {"ok": True, "operation": step.operation, "disposition": result.disposition.value, "safe_code": result.safe_code, "evidence": dict(result.evidence), "redactions_applied": True}

    def set_rollback_prestate(self, plan_step_ordinal, evidence):
        self._rollback_prestate[plan_step_ordinal] = evidence
        self._active_rollback_ordinal = plan_step_ordinal

    def _rollback_expected(self, key, fallback=None):
        evidence = self._rollback_prestate.get(self._active_rollback_ordinal)
        if evidence is not None and key in evidence.evidence:
            return evidence.evidence[key]
        return fallback

    def _run(self,argv:list[str],*,acceptable=(0,))->object:
        if not argv or any(not isinstance(value,str) or "\x00" in value for value in argv): raise ValueError("invalid process argument vector")
        result=self._run_process(argv,shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        stdout = getattr(result, "stdout", b"")
        if not isinstance(stdout, (bytes, bytearray)) or len(stdout) > MAX_WRAPPER_DIAGNOSTIC_BYTES:
            raise RedactedHostOperationError("PROCESS_STDOUT_OVERSIZED" if isinstance(stdout, (bytes, bytearray)) else "PROCESS_OUTPUT_TYPE_INVALID")
        stderr = getattr(result, "stderr", b"")
        if not isinstance(stderr, (bytes, bytearray)):
            raise RedactedHostOperationError("PROCESS_OUTPUT_TYPE_INVALID")
        if getattr(result,"returncode",1) not in acceptable:
            raise RedactedHostOperationError(_redacted_process_error_code(getattr(result,"stderr",b"")))
        return result
    def _sudo(self,argv:list[str],*,user:str|None=None,acceptable=(0,)):
        prefix=["/usr/bin/sudo"]+(["-u",user] if user else [])+["--"]
        return self._run(prefix+argv,acceptable=acceptable)

    def _verify_published_adapter_source(self,a):
        _require_contract_identity(a)
        result=self._run(["/usr/bin/git","-C",a["path"],"rev-parse","HEAD"])
        if getattr(result,"stdout",b"").decode().strip()!=a["commit"]: raise RuntimeError("published adapter commit mismatch")
        if capability_digest(a["commit"],EXPECTED_BACKUP_TOOL_SCHEMAS,a["provisioning_contract_version"])!=a["capability_digest"]: raise RuntimeError("published capability digest mismatch")
        return HostOperationResult.verified_noop("SOURCE_ALREADY_PUBLISHED", {"source_commit_verified": True})
    def _install_runtime(self,a):
        if runtime_digest(a["source"],a["commit"])!=a["runtime_digest"]: raise RuntimeError("published runtime artifact digest mismatch")
        destination = Path(a["destination"])
        try: destination_info = destination.lstat()
        except FileNotFoundError: destination_info = None
        if destination_info is not None:
            if stat.S_ISLNK(destination_info.st_mode) or not stat.S_ISDIR(destination_info.st_mode): raise RedactedHostOperationError("RUNTIME_CONFLICT")
            try: expected_owner = pwd.getpwnam(a.get("owner", "root"))
            except KeyError: raise RedactedHostOperationError("RUNTIME_CONFLICT") from None
            if (destination_info.st_uid, destination_info.st_gid, stat.S_IMODE(destination_info.st_mode)) != (expected_owner.pw_uid, expected_owner.pw_gid, 0o755): raise RedactedHostOperationError("RUNTIME_CONFLICT")
            existing = runtime_digest(destination, a["commit"])
            if existing == a["runtime_digest"]:
                return HostOperationResult.verified_noop("RUNTIME_ALREADY_CURRENT", {"runtime_digest": existing, "metadata_verified": True, "dev": str(destination_info.st_dev), "ino": str(destination_info.st_ino), "uid": str(destination_info.st_uid), "gid": str(destination_info.st_gid), "mode": str(stat.S_IMODE(destination_info.st_mode))})
            raise RedactedHostOperationError("RUNTIME_CONFLICT")
        excludes=[f"--exclude={name}" for name in sorted(RUNTIME_EXCLUDED)]
        staging = destination.parent / (".overseer-runtime-staging-" + secrets.token_hex(16))
        creation_info = None
        staging_info = None
        promoted_info = None
        try:
            self._sudo(["/usr/bin/install","-d","-m","0700","-o",a.get("owner", "root"),"-g",a.get("owner", "root"),str(staging)])
            creation_info = staging.lstat()
            self._sudo(["/usr/bin/rsync","-a","--delete",*excludes,a["source"].rstrip("/")+"/",str(staging).rstrip("/")+"/"])
            self._sudo(["/usr/bin/python3","-m","venv",str(staging)+"/.venv"])
            self._sudo([str(staging)+"/.venv/bin/pip","install",str(staging)])
            self._sudo([str(staging)+"/.venv/bin/python","-c","import theunderdark.production_cli"])
            self._sudo(["/usr/bin/chown","-R",a.get("owner", "root")+":"+a.get("owner", "root"),str(staging)])
            self._sudo(["/usr/bin/chmod","0755",str(staging)])
            staging_info = staging.lstat()
            if creation_info is None or (staging_info.st_dev, staging_info.st_ino) != (creation_info.st_dev, creation_info.st_ino): raise RedactedHostOperationError("RUNTIME_CONFLICT")
            if runtime_digest(staging,a["commit"])!=a["runtime_digest"]: raise RuntimeError("installed runtime digest mismatch")
            promoted = self._boundary("promote", str(staging), str(destination), str(staging_info.st_dev), str(staging_info.st_ino), str(staging_info.st_uid), str(staging_info.st_gid), str(stat.S_IMODE(staging_info.st_mode)))
            if promoted.get("status") != "promoted": raise RedactedHostOperationError("RUNTIME_CONFLICT")
            promoted_info = staging_info
            final = destination.lstat()
            if (final.st_dev, final.st_ino, final.st_uid, final.st_gid, stat.S_IMODE(final.st_mode)) != (staging_info.st_dev, staging_info.st_ino, staging_info.st_uid, staging_info.st_gid, stat.S_IMODE(staging_info.st_mode)) or runtime_digest(destination,a["commit"])!=a["runtime_digest"]: raise RedactedHostOperationError("RUNTIME_CONFLICT")
            return HostOperationResult.changed("RUNTIME_INSTALLED", {"runtime_digest": a["runtime_digest"], "metadata_verified": True, "dev": str(final.st_dev), "ino": str(final.st_ino), "uid": str(final.st_uid), "gid": str(final.st_gid), "mode": str(stat.S_IMODE(final.st_mode))})
        except Exception:
            try:
                cleanup_path = destination if promoted_info is not None else staging
                cleanup_info = promoted_info if promoted_info is not None else staging_info
                if cleanup_info is None:
                    if creation_info is None: raise RedactedHostOperationError("RUNTIME_CONFLICT")
                    current_info = staging.lstat()
                    if (current_info.st_dev, current_info.st_ino) != (creation_info.st_dev, creation_info.st_ino): raise RedactedHostOperationError("RUNTIME_CONFLICT")
                    cleanup_info = current_info
                if cleanup_info is None: raise RedactedHostOperationError("RUNTIME_CONFLICT")
                cleanup_operation = "remove_tree" if promoted_info is not None else "remove_staging_tree"
                cleanup_arguments = (str(cleanup_path), str(cleanup_info.st_dev), str(cleanup_info.st_ino), str(cleanup_info.st_uid), str(cleanup_info.st_gid), str(stat.S_IMODE(cleanup_info.st_mode)))
                if cleanup_operation == "remove_tree":
                    cleanup_arguments += (a["runtime_digest"], a["commit"])
                cleaned = self._boundary(cleanup_operation, *cleanup_arguments)
                if cleaned.get("status") not in {"removed", "absent"}:
                    raise RedactedHostOperationError("RUNTIME_CONFLICT")
            except FileNotFoundError:
                pass
            except Exception as cleanup_error:
                raise RedactedHostOperationError("RUNTIME_CONFLICT") from cleanup_error
            raise
    def _verify_endpoint_migration_ready(self,a):
        if a.get("host") != "127.0.0.1" or a.get("port") != 8799 or a.get("forbid_simultaneous_user_and_system_service") is not True:
            raise RedactedHostOperationError("ENDPOINT_CONFLICT")
        self._run(["/usr/bin/systemctl","--user","is-active","theunderdark-mcp.service"],acceptable=(0,))
        system = self._run(["/usr/bin/systemctl","is-active","theunderdark-donuthole.service"],acceptable=(3, 4))
        if getattr(system, "returncode", 0) == 0: raise RedactedHostOperationError("ENDPOINT_CONFLICT")
        return HostOperationResult.verified_noop("ENDPOINT_READY")
    def _ensure_system_user(self,a):
        probe = self._run(["/usr/bin/getent", "passwd", a["name"]], acceptable=(0, 2))
        output = getattr(probe, "stdout", b"")
        if getattr(probe, "returncode", 1) == 0:
            fields = output.decode("utf-8", "strict").strip().split(":")
            if len(fields) == 7 and fields[0] == a["name"] and fields[5] == a["home"] and fields[6] == a["shell"] and fields[2].isdigit() and fields[3].isdigit() and int(fields[2]) < 1000:
                return HostOperationResult.verified_noop("SYSTEM_USER_ALREADY_CURRENT")
            raise RedactedHostOperationError("SYSTEM_USER_CONFLICT")
        created = self._sudo(["/usr/sbin/useradd","--system","--home-dir",a["home"],"--shell",a["shell"],a["name"]],acceptable=(0,9))
        if getattr(created, "returncode", 1) not in {0, 9}: raise RedactedHostOperationError("SYSTEM_USER_CONFLICT")
        post = self._run(["/usr/bin/getent", "passwd", a["name"]], acceptable=(0, 2))
        fields = getattr(post, "stdout", b"").decode("utf-8", "strict").strip().split(":")
        if getattr(post, "returncode", 1) != 0 or len(fields) != 7 or fields[0] != a["name"] or fields[5] != a["home"] or fields[6] != a["shell"] or not fields[2].isdigit() or not fields[3].isdigit() or int(fields[2]) >= 1000:
            raise RedactedHostOperationError("SYSTEM_USER_CONFLICT")
        return HostOperationResult.changed("SYSTEM_USER_CREATED", {"metadata_verified": True})
    def _ensure_directory(self,a):
        local = self._directory_identity(a["path"], a["owner"], int(a["mode"]))
        if local is not None:
            return HostOperationResult.verified_noop("DIRECTORY_ALREADY_CURRENT", {"metadata_verified": True, **{key: str(local[key]) for key in ("dev", "ino", "uid", "gid", "mode")}})
        probe = self._run(["/usr/bin/stat", "-c", "%u:%g:%a:%h:%F", a["path"]], acceptable=(0, 1))
        if getattr(probe, "returncode", 1) == 0:
            fields = getattr(probe, "stdout", b"").decode("utf-8", "strict").strip().split(":")
            try: expected = pwd.getpwnam(a["owner"])
            except KeyError: raise RedactedHostOperationError("DIRECTORY_CONFLICT") from None
            if len(fields) == 5 and fields[0] == str(expected.pw_uid) and fields[1] == str(expected.pw_gid) and int(fields[2], 8) == int(a["mode"]) and int(fields[3]) >= 2 and fields[4] == "directory":
                identity = self._directory_identity(a["path"], a["owner"], int(a["mode"]))
                if identity is None:
                    raise RedactedHostOperationError("DIRECTORY_CONFLICT")
                return HostOperationResult.verified_noop("DIRECTORY_ALREADY_CURRENT", {"metadata_verified": True, **{key: str(identity[key]) for key in ("dev", "ino", "uid", "gid", "mode")}})
            raise RedactedHostOperationError("DIRECTORY_CONFLICT")
        self._sudo(["/usr/bin/install","-d","-m",format(a["mode"],"04o"),"-o",a["owner"],"-g",a["owner"],a["path"]])
        identity = self._directory_identity(a["path"], a["owner"], int(a["mode"]))
        if identity is None:
            raise RedactedHostOperationError("DIRECTORY_CONFLICT")
        return HostOperationResult.changed("DIRECTORY_CREATED", {"metadata_verified": True, **{key: str(identity[key]) for key in ("dev", "ino", "uid", "gid", "mode")}})

    def _directory_identity(self, path, owner, mode):
        try:
            return _safe_existing_directory_identity(path, owner, mode)
        except PermissionError:
            result = self._boundary("dir_attest", path, owner, str(mode))
            if result.get("status") == "absent":
                return None
            if result.get("status") != "present":
                raise RedactedHostOperationError("DIRECTORY_CONFLICT")
            return {key: result[key] for key in ("dev", "ino", "uid", "gid", "mode")} | {"privileged": True}
    def _generate_secret_file(self,a): return self._secret(a,binary=False)
    def _generate_cursor_key(self,a): return self._secret(a,binary=True)
    def _secret(self,a,binary):
        existing = self._file_identity(a["path"], a["owner"], int(a["mode"]))
        if existing is not None:
            expected_size = int(a["bytes"]) if binary else int(a["bytes"]) * 2
            if existing["size"] == expected_size: return HostOperationResult.verified_noop("SECRET_ALREADY_PRESENT", {"size_bytes": expected_size, "metadata_verified": True, "identity_digest": existing["digest"]})
            raise RedactedHostOperationError("SECRET_CONFLICT")
        random_bytes = int(a["bytes"])
        expected_size = random_bytes if binary else random_bytes * 2
        self._sudo(["/usr/bin/openssl","rand",*([] if binary else ["-hex"]),"-out",a["path"],str(random_bytes)]); self._sudo(["/usr/bin/chmod",format(a["mode"],"04o"),a["path"]]); self._sudo(["/usr/bin/chown",a["owner"]+":"+a["owner"],a["path"]]);
        post = self._file_identity(a["path"], a["owner"], int(a["mode"]))
        if post is None or post["size"] != expected_size: raise RedactedHostOperationError("SECRET_CONFLICT")
        return HostOperationResult.changed("SECRET_CREATED", {"size_bytes": expected_size, "metadata_verified": True, "identity_digest": post["digest"]})
    def _install_overseer_api_token(self,a):
        flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)
        try: fd=os.open(a["source_path"],flags)
        except OSError as exc: raise PermissionError("source token must be a private regular non-symlink file") from exc
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)&0o077: raise PermissionError("source token must be a private regular non-symlink file")
            data=b""
            while True:
                chunk=os.read(fd,65536)
                if not chunk: break
                data+=chunk
                if len(data)>65536: raise ValueError("source token exceeds bounded size")
        finally: os.close(fd)
        if not data.strip(): raise ValueError("source token is empty")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        existing = self._file_identity(a["destination_path"], a["owner"], int(a["mode"]))
        if existing is not None:
            if existing["digest"] == digest: return HostOperationResult.verified_noop("TOKEN_ALREADY_PRESENT", {"identity_digest": digest, "metadata_verified": True})
            raise RedactedHostOperationError("TOKEN_CONFLICT")
        self._install_bytes(a["destination_path"],data,a["mode"],a["owner"])
        post = self._file_identity(a["destination_path"], a["owner"], int(a["mode"]))
        if post is None or post["digest"] != digest: raise RedactedHostOperationError("TOKEN_CONFLICT")
        return HostOperationResult.changed("TOKEN_INSTALLED", {"identity_digest": digest, "metadata_verified": True})
    def _ensure_read_only_acl(self,a):
        before = self._acl_state(a)
        if before == "exact": return HostOperationResult.verified_noop("ACL_APPLIED", {"acl_verified": True, "acl_present_before": True})
        if before == "conflict": raise RedactedHostOperationError("FILE_CONFLICT")
        self._sudo(["/usr/bin/setfacl","-R","-m",f"u:{a['principal']}:{a['permissions']}",a["path"]])
        if self._acl_state(a) != "exact": raise RedactedHostOperationError("FILE_CONFLICT")
        return HostOperationResult.changed("ACL_APPLIED", {"acl_verified": True, "acl_present_before": False})
    def _install_private_config(self,a):
        encoded=json.dumps(a["config"],sort_keys=True,separators=(",",":")).encode()
        if "sha256:"+hashlib.sha256(encoded).hexdigest()!=a["config_digest"]: raise ValueError("config digest mismatch")
        existing_info = self._file_identity(a["path"], a["owner"], int(a["mode"]))
        existing = None if existing_info is None else existing_info["digest"]
        if existing is not None:
            if existing == a["config_digest"]: return HostOperationResult.verified_noop("CONFIG_ALREADY_CURRENT", {"config_digest": existing})
            raise RedactedHostOperationError("CONFIG_CONFLICT")
        self._install_bytes(a["path"],encoded,a["mode"],a["owner"])
        post = self._file_identity(a["path"], a["owner"], int(a["mode"]))
        if post is None or post["digest"] != a["config_digest"]: raise RedactedHostOperationError("CONFIG_CONFLICT")
        return HostOperationResult.changed("CONFIG_INSTALLED", {"config_digest": a["config_digest"], "metadata_verified": True})
    def _register_authorized_roots(self,a):
        changed = 0
        for item in a["registrations"]:
            argv = ["/opt/theunderdark/.venv/bin/theunderdark-production","register-root","--config","/etc/codex-development-backups/donuthole.json","--project-id",item["project_id"],"--root-id",item["root_id"],"--policy-revision",item["policy_revision"],"--host-path",item["host_path"],"--alias",item["alias"],"--max-bytes",str(item["max_bytes"]),"--authorization-ref",item["authorization_ref"]]
            try:
                self._sudo(argv,user="donuthole-backup")
                verify = self._sudo([*argv, "--verify-exact"], user="donuthole-backup")
                if not _exact_root_probe(verify): raise RedactedHostOperationError("ROOT_CONFLICT")
                changed += 1
            except RedactedHostOperationError as error:
                if error.code != "ROOT_EXISTS": raise
                probe = self._sudo([*argv, "--verify-exact"], user="donuthole-backup")
                if not _exact_root_probe(probe): raise RedactedHostOperationError("ROOT_CONFLICT")
        return HostOperationResult.changed("ROOTS_REGISTERED", {"roots_added": changed}) if changed else HostOperationResult.verified_noop("ROOTS_ALREADY_REGISTERED", {"roots_verified": len(a["registrations"])})
    def _stop_disable_user_service(self,a):
        before = self._service_state(a["unit"], user=True)
        previously_enabled = before[0] == "enabled"
        previously_active = before[1] == "active"
        if before[0] == "disabled" and before[1] == "inactive": return HostOperationResult.verified_noop("USER_SERVICE_DISABLED", {"previously_enabled": False, "previously_active": False, "service_verified": True})
        self._run(["/usr/bin/systemctl","--user","disable","--now",a["unit"]])
        after = self._service_state(a["unit"], user=True)
        if after[0] != "disabled" or after[1] != "inactive": raise RedactedHostOperationError("SYSTEMD_ATTESTATION_INVALID")
        return HostOperationResult.changed("USER_SERVICE_DISABLED", {"previously_enabled": previously_enabled, "previously_active": previously_active, "service_verified": True})
    def _start_enable_system_service(self,a):
        before = self._service_state(a["unit"], user=False)
        self._sudo(["/usr/bin/systemctl", "enable", a["unit"]])
        self._sudo(["/usr/bin/systemctl", "restart", a["unit"]])
        state = self._service_state(a["unit"], user=False)
        monotonic = state[2]
        if state[0] != "enabled" or state[1] != "active" or not monotonic.isdigit() or int(monotonic) <= int(before[2] or "0"):
            raise RedactedHostOperationError("SYSTEMD_ATTESTATION_INVALID")
        return HostOperationResult.changed("SYSTEM_SERVICE_RESTARTED", {"active_enter_timestamp_monotonic": monotonic})
    def _stop_disable_system_service(self,a):
        before = self._service_state(a["unit"], user=False)
        if before[0] == "disabled" and before[1] == "inactive": return HostOperationResult.verified_noop("SYSTEM_SERVICE_DISABLED", {"service_verified": True})
        self._sudo(["/usr/bin/systemctl","disable","--now",a["unit"]])
        after = self._service_state(a["unit"], user=False)
        if after[0] != "disabled" or after[1] != "inactive": raise RedactedHostOperationError("SYSTEMD_ATTESTATION_INVALID")
        return HostOperationResult.changed("SYSTEM_SERVICE_DISABLED", {"service_verified": True})
    def _restore_enable_user_service(self,a):
        previous = self._rollback_expected("previously_enabled", True)
        previously_active = self._rollback_expected("previously_active", True)
        if previous is False: return HostOperationResult.verified_noop("USER_SERVICE_NOT_RESTORED", {"service_verified": True})
        if previously_active:
            self._run(["/usr/bin/systemctl","--user","enable","--now",a["unit"]])
        else:
            self._run(["/usr/bin/systemctl","--user","enable",a["unit"]])
        state = self._service_state(a["unit"], user=True)
        if state[0] != "enabled" or state[1] != ("active" if previously_active else "inactive"): raise RedactedHostOperationError("SYSTEMD_ATTESTATION_INVALID")
        return HostOperationResult.changed("USER_SERVICE_ENABLED", {"service_verified": True})
    def _service_state(self, unit, *, user):
        prefix = ["/usr/bin/systemctl"] + (["--user"] if user else [])
        result = self._run(prefix + ["show", unit, "--property=UnitFileState,ActiveState,ActiveEnterTimestampMonotonic", "--value"])
        output = getattr(result, "stdout", b"")
        try: values = bytes(output).decode("utf-8", "strict").strip().splitlines()
        except (TypeError, UnicodeDecodeError): raise RedactedHostOperationError("SYSTEMD_ATTESTATION_INVALID") from None
        if len(values) != 3 or values[0] not in {"enabled", "disabled", "static", "masked"} or values[1] not in {"active", "inactive", "failed"} or (values[2] and not values[2].isdigit()):
            raise RedactedHostOperationError("SYSTEMD_ATTESTATION_INVALID")
        return values[0], values[1], values[2]
    def _install_systemd_unit(self,a):
        expected = hashlib.sha256(_unit(a["properties"]).encode()).hexdigest()
        approved_unit_digest = a.get("unit_digest") or getattr(self.plan, "unit_digest", None)
        rendered_plan_digest = _object_digest(a["properties"])
        if not isinstance(approved_unit_digest, str) or approved_unit_digest != rendered_plan_digest:
            raise RedactedHostOperationError("SYSTEMD_UNIT_CONFLICT")
        existing_info = self._file_identity(a["path"], "root", 0o644)
        existing = None if existing_info is None else existing_info["digest"]
        if existing is not None:
            if existing == "sha256:" + expected: return HostOperationResult.verified_noop("SYSTEMD_UNIT_ALREADY_CURRENT", {"unit_digest": existing})
            raise RedactedHostOperationError("SYSTEMD_UNIT_CONFLICT")
        self._install_bytes(a["path"],_unit(a["properties"]).encode(),0o644,"root"); self._sudo(["/usr/bin/systemctl","daemon-reload"])
        post = self._file_identity(a["path"], "root", 0o644)
        if post is None or post["digest"] != "sha256:" + expected: raise RedactedHostOperationError("SYSTEMD_UNIT_CONFLICT")
        return HostOperationResult.changed("SYSTEMD_UNIT_INSTALLED", {"unit_digest": approved_unit_digest or "sha256:" + expected, "identity_digest": "sha256:" + expected, "metadata_verified": True})
    def _remove_systemd_unit(self,a): return self._remove_exact_file(a["path"], a.get("identity_digest") or self._rollback_expected("identity_digest"), "root", 0o644, "SYSTEMD_UNIT_REMOVED", "SYSTEMD_UNIT_ALREADY_ABSENT", daemon_reload=True)
    def _verify_mcp_service(self,a):
        for delay in (*self._mcp_retry_delays,None):
            try:
                tools=self._mcp_tool_loader(a["url"])
                break
            except (urllib.error.URLError,TimeoutError,ConnectionError) as error:
                if isinstance(error,urllib.error.HTTPError): raise
                if delay is None: raise RedactedHostOperationError("MCP_SERVICE_NOT_READY") from None
                self._sleep(delay)
        normalized={str(tool.get("name")):_normalize_schema(tool.get("inputSchema")) for tool in tools if tool.get("name") in a["required_tools"]}; expected={name:EXPECTED_BACKUP_TOOL_SCHEMAS[name] for name in a["required_tools"]}
        if normalized!=expected or capability_digest(self.plan.adapter_commit,normalized,a["provisioning_contract_version"])!=a["capability_digest"]: raise RuntimeError("MCP capability verification failed")
        return HostOperationResult.verified_noop("MCP_SCHEMA_VERIFIED")
    def _verify_codex_url(self,a):
        result=self._run(["/home/god/.local/bin/codex","mcp","get","theunderdark","--json"])
        try: value=json.loads(getattr(result,"stdout",b"").decode())
        except Exception as exc: raise RuntimeError("Codex MCP configuration is unreadable") from exc
        configured=value.get("transport",{}).get("url") or value.get("url")
        if configured!=a["url"]: raise RuntimeError("Codex MCP URL does not match approved endpoint")
        return HostOperationResult.verified_noop("CODEX_MCP_URL_VERIFIED")
    def _verify_gpg_identity(self,a):
        if _digest_file(a["path"])!=a["sha256"]: raise RuntimeError("GPG identity mismatch")
        return HostOperationResult.verified_noop("GPG_IDENTITY_VERIFIED", {"identity_digest": a["sha256"]})
    def _verify_backup_policy(self,a):
        if a!={"retention":3,"plaintext_archive":False,"restore_required":True}: raise ValueError("backup policy mismatch")
        return HostOperationResult.verified_noop("BACKUP_POLICY_VERIFIED")
    def _remove_private_config(self,a): return self._remove_exact_file(a["path"], a.get("config_digest") or self._rollback_expected("config_digest", getattr(self.plan, "config_digest", None)), a.get("owner", getattr(self.plan, "system_user", "")), int(a.get("mode", 0o600)), "CONFIG_REMOVED", "CONFIG_ALREADY_ABSENT")
    def _remove_read_only_acl(self,a):
        before = self._acl_state(a)
        if before == "absent": return HostOperationResult.verified_noop("ACL_REMOVED", {"acl_verified": True})
        if before == "conflict": raise RedactedHostOperationError("FILE_CONFLICT")
        self._sudo(["/usr/bin/setfacl","-R","-x",f"u:{a['principal']}",a["path"]],acceptable=(0,))
        if self._acl_state(a) != "absent": raise RedactedHostOperationError("FILE_CONFLICT")
        return HostOperationResult.changed("ACL_REMOVED", {"acl_verified": True})
    def _remove_cursor_key_if_unreferenced(self,a): return self._remove_exact_file(a["path"], a.get("digest") or self._rollback_expected("identity_digest"), a.get("owner", getattr(self.plan, "system_user", "")), int(a.get("mode", 0o600)), "CURSOR_KEY_REMOVED", "CURSOR_KEY_ALREADY_ABSENT")
    def _remove_overseer_api_token(self,a):
        source = a.get("source_path", getattr(self.plan, "overseer_token_source_file", None))
        expected = a.get("digest") or self._rollback_expected("identity_digest")
        if expected is None and isinstance(source, str): expected = _digest_file(source)
        return self._remove_exact_file(a["path"], expected, a.get("owner", getattr(self.plan, "system_user", "")), int(a.get("mode", 0o600)), "TOKEN_REMOVED", "TOKEN_ALREADY_ABSENT")
    def _remove_secret_file_if_no_backups(self,a):
        result=self._sudo(["/usr/bin/find",a["artifact_dir"],"-mindepth","1","-print","-quit"],acceptable=(0,1))
        if getattr(result,"stdout",b"").strip(): return HostOperationResult.verified_noop("SECRET_RETAINED_WITH_BACKUPS")
        return self._remove_exact_file(a["path"], a.get("digest") or self._rollback_expected("identity_digest"), a.get("owner", getattr(self.plan, "system_user", "")), int(a.get("mode", 0o600)), "SECRET_REMOVED", "SECRET_ALREADY_ABSENT")
    def _remove_directory_if_empty(self,a):
        identity = {key: a.get(key) or self._rollback_expected(key) for key in ("dev", "ino", "uid", "gid", "mode")}
        if any(identity[key] is None for key in identity): raise RedactedHostOperationError("DIRECTORY_CONFLICT")
        try:
            result = self._boundary("rmdir", a["path"], *(str(identity[key]) for key in ("dev", "ino", "uid", "gid", "mode")))
        except RedactedHostOperationError as error:
            raise RedactedHostOperationError("DIRECTORY_CONFLICT") from error
        if result.get("status") == "removed": return HostOperationResult.changed("DIRECTORY_REMOVED", {"metadata_verified": True})
        if result.get("status") == "absent": return HostOperationResult.verified_noop("DIRECTORY_ALREADY_ABSENT")
        raise RedactedHostOperationError("DIRECTORY_CONFLICT")
    def _remove_system_user_if_unused(self,a):
        processes = self._sudo(["/usr/bin/pgrep", "-u", a["name"]], acceptable=(0, 1))
        if getattr(processes, "returncode", 1) == 0:
            raise RedactedHostOperationError("SYSTEM_USER_CONFLICT")
        present=self._sudo(["/usr/bin/test","-e",a["retained_path"]],acceptable=(0,1)).returncode==0
        if present:
            retained=self._sudo(["/usr/bin/find",a["retained_path"],"-mindepth","1","-print","-quit"])
            if getattr(retained,"stdout",b"").strip(): return HostOperationResult.verified_noop("SYSTEM_USER_RETAINED_WITH_STATE")
        removed=self._sudo(["/usr/sbin/userdel",a["name"]],acceptable=(0,6))
        if getattr(removed,"returncode",1)==0: return HostOperationResult.changed("SYSTEM_USER_REMOVED")
        if getattr(removed,"returncode",1)==6: return HostOperationResult.verified_noop("SYSTEM_USER_ALREADY_ABSENT")
        raise RedactedHostOperationError("SYSTEM_USER_CONFLICT")
    def _remove_runtime_if_unreferenced(self,a):
        expected = a.get("runtime_digest") or self._rollback_expected("runtime_digest", getattr(self.plan, "runtime_digest", None))
        if not isinstance(expected, str) or not _SAFE_DIGEST.fullmatch(expected): raise RedactedHostOperationError("RUNTIME_CONFLICT")
        identity = {key: a.get(key) or self._rollback_expected(key) for key in ("dev", "ino", "uid", "gid", "mode")}
        identity = {key: "0" if identity[key] is None else identity[key] for key in identity}
        try:
            result = self._boundary("remove_tree", a["path"], *(str(identity[key]) for key in ("dev", "ino", "uid", "gid", "mode")), expected, getattr(self.plan, "adapter_commit", ""))
        except RedactedHostOperationError as error:
            raise RedactedHostOperationError("RUNTIME_CONFLICT") from error
        if result.get("status") == "absent": return HostOperationResult.verified_noop("RUNTIME_ALREADY_ABSENT")
        if result.get("status") != "removed": raise RedactedHostOperationError("RUNTIME_CONFLICT")
        if self._boundary("absence", a["path"]).get("status") != "absent": raise RedactedHostOperationError("RUNTIME_CONFLICT")
        return HostOperationResult.changed("RUNTIME_REMOVED", {"runtime_digest": expected, "metadata_verified": True})
    def _install_bytes(self,path,data,mode,owner):
        fd,name=tempfile.mkstemp(prefix="overseer-provision-"); staging=Path(name)
        try:
            with os.fdopen(fd,"wb") as output: output.write(data); output.flush(); os.fsync(output.fileno())
            self._sudo(["/usr/bin/install","-m",format(mode,"04o"),"-o",owner,"-g",owner,str(staging),path])
        finally: staging.unlink(missing_ok=True)
    def _acl_state(self, a):
        result = self._sudo(["/usr/bin/getfacl", "-cp", "--", a["path"]], acceptable=(0, 1))
        if getattr(result, "returncode", 1) != 0: return "absent"
        output = getattr(result, "stdout", b"")
        if not isinstance(output, (bytes, bytearray)) or len(output) > MAX_WRAPPER_DIAGNOSTIC_BYTES: raise RedactedHostOperationError("PROCESS_STDOUT_OVERSIZED")
        try: lines = bytes(output).decode("utf-8", "strict").splitlines()
        except UnicodeDecodeError: raise RedactedHostOperationError("FILE_CONFLICT") from None
        matches = [line for line in lines if line.startswith("user:" + a["principal"] + ":")]
        if not matches: return "absent"
        return "exact" if matches == ["user:" + a["principal"] + ":" + a["permissions"]] else "conflict"
    def _file_identity(self, path, owner, mode):
        try:
            return _safe_existing_file_identity(path, owner, mode)
        except PermissionError:
            result = self._boundary("attest", path, owner, str(mode))
            if result.get("status") == "absent":
                return None
            if result.get("status") != "present":
                raise RedactedHostOperationError("FILE_CONFLICT")
            return {"digest": result["digest"], "size": result["size"], "dev": result["dev"], "ino": result["ino"], "privileged": True}

    def _boundary(self, operation, *arguments):
        result = self._sudo(["/usr/bin/python3", "-c", _PRIVILEGED_BOUNDARY_HELPER, operation, *map(os.fspath, arguments)])
        output = getattr(result, "stdout", b"")
        if not isinstance(output, (bytes, bytearray)) or len(output) > 4096:
            raise RedactedHostOperationError("FILE_CONFLICT")
        try:
            value = json.loads(bytes(output).decode("ascii", "strict"))
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            raise RedactedHostOperationError("FILE_CONFLICT") from None
        if type(value) is not dict or not isinstance(value.get("status"), str):
            raise RedactedHostOperationError("FILE_CONFLICT")
        status = value["status"]
        shapes = {
            "attest": {"absent": {"status"}, "unsafe": {"status"}, "present": {"status", "dev", "ino", "uid", "gid", "mode", "nlink", "size", "digest"}},
            "dir_attest": {"absent": {"status"}, "unsafe": {"status"}, "present": {"status", "dev", "ino", "uid", "gid", "mode", "nlink"}},
            "unlink": {"absent": {"status"}, "unsafe": {"status"}, "conflict": {"status"}, "removed": {"status", "size"}},
            "rmdir": {item: {"status"} for item in ("absent", "unsafe", "conflict", "removed", "error")},
            "remove_tree": {item: {"status"} for item in ("absent", "unsafe", "conflict", "removed", "error")},
            "remove_staging_tree": {item: {"status"} for item in ("absent", "unsafe", "conflict", "removed", "error")},
            "promote": {item: {"status"} for item in ("conflict", "promoted", "error")},
            "absence": {item: {"status"} for item in ("absent", "unsafe", "present")},
            "references": {"error": {"status"}, "clear": {"status", "count"}, "referenced": {"status", "count"}},
        }
        expected = shapes.get(operation, {}).get(status)
        if expected is None or set(value) != expected:
            raise RedactedHostOperationError("FILE_CONFLICT")
        bounds = {
            "dev": (0, (1 << 64) - 1), "ino": (0, (1 << 64) - 1),
            "uid": (0, (1 << 32) - 1), "gid": (0, (1 << 32) - 1),
            "mode": (0, 0o7777), "nlink": (1, (1 << 32) - 1),
            "size": (0, MAX_BOUNDARY_BYTES), "count": (0, MAX_BOUNDARY_COUNT),
        }
        for key in expected - {"status", "digest"}:
            lower, upper = bounds[key]
            if type(value[key]) is not int or not lower <= value[key] <= upper:
                raise RedactedHostOperationError("FILE_CONFLICT")
        if "digest" in value and (not isinstance(value["digest"], str) or not _SAFE_DIGEST.fullmatch(value["digest"])):
            raise RedactedHostOperationError("FILE_CONFLICT")
        return value
    def _remove_exact_file(self, path, expected_digest, owner, mode, changed_code, absent_code, daemon_reload=False):
        identity = self._file_identity(path, owner, mode)
        if identity is None: return HostOperationResult.verified_noop(absent_code)
        if not isinstance(expected_digest, str) or identity["digest"] != expected_digest:
            raise RedactedHostOperationError("FILE_CONFLICT")
        if identity.get("privileged"):
            result = self._boundary("unlink", path, owner, str(mode), str(identity["dev"]), str(identity["ino"]), expected_digest)
            if result.get("status") != "removed":
                raise RedactedHostOperationError("FILE_CONFLICT")
            if daemon_reload: self._sudo(["/usr/bin/systemctl", "daemon-reload"])
            return HostOperationResult.changed(changed_code, {"metadata_verified": True})
        # Re-read the no-follow identity immediately before removal.  The
        # digest was computed from the inspected fd; do not unlink a pathname
        # that has since been replaced by a symlink, hard link, or foreign
        # inode.  A replacement is a conflict, never an idempotent absence.
        current = _safe_existing_file_identity(path, owner, mode)
        if current is None or current["dev"] != identity["dev"] or current["ino"] != identity["ino"] or current["digest"] != identity["digest"]:
            raise RedactedHostOperationError("FILE_CONFLICT")
        os.unlink(os.fspath(path))
        if not _safe_lstat_absent(path): raise RedactedHostOperationError("FILE_CONFLICT")
        if daemon_reload: self._sudo(["/usr/bin/systemctl", "daemon-reload"])
        return HostOperationResult.changed(changed_code, {"metadata_verified": True})
    def _unlink(self,path,daemon_reload=False):
        present=self._sudo(["/usr/bin/test","-e",path],acceptable=(0,1)).returncode==0
        self._sudo(["/usr/bin/rm","-f","--",path])
        if daemon_reload: self._sudo(["/usr/bin/systemctl","daemon-reload"])
        return present

def _redacted_child_error_code(stderr):
    """Extract only a bounded final structured diagnostic emitted by a child."""
    if not isinstance(stderr,(bytes,bytearray)): return "PROCESS_FAILED"
    lines=bytes(stderr).splitlines(); final=next((line for line in reversed(lines) if line.strip()),b"")
    if not final or len(final)>MAX_REDACTED_DIAGNOSTIC_LINE_BYTES: return "PROCESS_FAILED"
    try: diagnostic=json.loads(final.decode("utf-8","strict"))
    except (UnicodeDecodeError,json.JSONDecodeError): return "PROCESS_FAILED"
    if not isinstance(diagnostic,dict) or set(diagnostic) != {"ok", "error", "redactions_applied"}:
        return "PROCESS_FAILED"
    if diagnostic["ok"] is not False or diagnostic["redactions_applied"] is not True:
        return "PROCESS_FAILED"
    error=diagnostic["error"]
    candidate=error.get("code") if isinstance(error,dict) and set(error) == {"code"} else None
    return candidate if isinstance(candidate,str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}",candidate) else "PROCESS_FAILED"

def _exact_root_probe(result):
    output = getattr(result, "stdout", b"")
    if not isinstance(output, (bytes, bytearray)) or len(output) > MAX_WRAPPER_DIAGNOSTIC_BYTES:
        raise RedactedHostOperationError("ROOT_CONFLICT")
    try:
        value = json.loads(bytes(output).decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RedactedHostOperationError("ROOT_CONFLICT") from None
    return type(value) is dict and set(value) == {"exact"} and value["exact"] is True

def _redacted_process_error_code(stderr):
    child=_redacted_child_error_code(stderr)
    if child!="PROCESS_FAILED": return child
    if not isinstance(stderr,(bytes,bytearray)): return "PROCESS_OUTPUT_TYPE_INVALID"
    if len(stderr)>MAX_WRAPPER_DIAGNOSTIC_BYTES: return "PROCESS_STDERR_OVERSIZED"
    try: lines=bytes(stderr).decode("utf-8","strict").splitlines()
    except UnicodeDecodeError: return "PROCESS_STDERR_ENCODING_INVALID"
    nonempty=[line.strip() for line in lines if line.strip()]
    if not nonempty: return "PROCESS_STDERR_EMPTY"
    final=nonempty[-1]
    if len(final.encode())>MAX_REDACTED_DIAGNOSTIC_LINE_BYTES: return "PROCESS_STDERR_FINAL_LINE_OVERSIZED"
    wrapper=next((code for pattern,code in WRAPPER_ERROR_PATTERNS if pattern.fullmatch(final)),None)
    if wrapper: return wrapper
    return "PROCESS_STDERR_SINGLE_LINE_UNCLASSIFIED" if len(nonempty)==1 else "PROCESS_STDERR_MULTILINE_UNCLASSIFIED"

def _digest_file(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(os.fspath(path), flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode): raise RedactedHostOperationError("FILE_CONFLICT")
        digest=hashlib.sha256()
        while True:
            chunk=os.read(fd, 1024*1024)
            if not chunk: break
            digest.update(chunk)
        return "sha256:"+digest.hexdigest()
    finally:
        os.close(fd)

def _safe_existing_file_mode(path):
    target = Path(path)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RedactedHostOperationError("FILE_CONFLICT")
    return stat.S_IMODE(info.st_mode)

def _safe_existing_file_identity(path, owner, mode):
    target = os.fspath(path)
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise RedactedHostOperationError("FILE_CONFLICT") from None
        raise
    try:
        info = os.fstat(fd)
        try:
            expected = pwd.getpwnam(owner)
        except (KeyError, TypeError):
            raise RedactedHostOperationError("FILE_CONFLICT") from None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != expected.pw_uid or info.st_gid != expected.pw_gid or stat.S_IMODE(info.st_mode) != mode:
            raise RedactedHostOperationError("FILE_CONFLICT")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            digest.update(chunk)
        return {"dev": info.st_dev, "ino": info.st_ino, "digest": "sha256:" + digest.hexdigest(), "size": info.st_size}
    finally:
        os.close(fd)

def _safe_existing_directory_identity(path, owner, mode):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.fspath(path), flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise RedactedHostOperationError("DIRECTORY_CONFLICT") from None
        raise
    try:
        info = os.fstat(fd)
        parent_path = os.path.dirname(os.path.abspath(os.fspath(path))) or "."
        parent_info = os.stat(parent_path, follow_symlinks=False)
        if parent_info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise RedactedHostOperationError("DIRECTORY_CONFLICT")
        try: expected = pwd.getpwnam(owner)
        except KeyError: raise RedactedHostOperationError("DIRECTORY_CONFLICT") from None
        if not stat.S_ISDIR(info.st_mode) or info.st_nlink < 2 or info.st_uid != expected.pw_uid or info.st_gid != expected.pw_gid or stat.S_IMODE(info.st_mode) != mode:
            raise RedactedHostOperationError("DIRECTORY_CONFLICT")
        return {"dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    finally:
        os.close(fd)

def _safe_lstat_absent(path):
    try:
        os.lstat(os.fspath(path))
    except FileNotFoundError:
        return True
    return False

def _safe_existing_file_digest(path):
    target = Path(path)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RedactedHostOperationError("FILE_CONFLICT")
    return _digest_file(target)
def runtime_digest(path,commit):
    root=Path(path); files=[]
    root_info = root.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode): raise ValueError("runtime tree contains unsupported root")
    for item in sorted(root.rglob("*")):
        relative=item.relative_to(root)
        if any(part in RUNTIME_EXCLUDED for part in relative.parts): continue
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or (not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode)): raise ValueError("runtime tree contains unsupported entries")
        if stat.S_ISREG(info.st_mode): files.append({"path":relative.as_posix(),"mode":stat.S_IMODE(info.st_mode),"sha256":_digest_file(item)})
    return _object_digest({"version":1,"commit":commit,"files":files})
def capability_digest(commit: str, schemas: Mapping[str, object], provisioning_contract_version: str = PROVISIONING_CONTRACT_VERSION) -> str: return _object_digest({"version":2,"commit":commit,"provisioning_contract_version":provisioning_contract_version,"tools":schemas})
def _object_digest(value): return "sha256:"+hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).hexdigest()
def _require_contract_identity(arguments):
    version=arguments.get("provisioning_contract_version")
    expected=runtime_artifact_identity(arguments.get("commit"),EXPECTED_BACKUP_TOOL_SCHEMAS) if isinstance(arguments.get("commit"),str) else None
    if version!=PROVISIONING_CONTRACT_VERSION or arguments.get("runtime_artifact_identity")!=expected: raise RuntimeError("published contract identity mismatch")
def _normalize_schema(value):
    if not isinstance(value,Mapping) or value.get("type")!="object" or value.get("additionalProperties") is not False or not isinstance(value.get("properties"),Mapping) or not isinstance(value.get("required"),list): raise ValueError("tool schema is not strict")
    return _normalize_schema_value(value)
def _normalize_schema_value(value):
    if isinstance(value,Mapping):
        normalized={str(name):_normalize_schema_value(child) for name,child in value.items() if name!="title"}
        if isinstance(normalized.get("required"),list): normalized["required"]=sorted(normalized["required"])
        return normalized
    if isinstance(value,list): return [_normalize_schema_value(child) for child in value]
    return value
def _load_mcp_tools(url):
    session=None
    def post(payload):
        nonlocal session
        headers={"content-type":"application/json","accept":"application/json, text/event-stream"}
        if session: headers["mcp-session-id"]=session
        request=urllib.request.Request(url,data=json.dumps(payload,separators=(",",":")).encode(),headers=headers,method="POST")
        with urllib.request.urlopen(request,timeout=10) as response:
            session=response.headers.get("mcp-session-id") or session; body=response.read(2_097_153).decode()
        data=next((line[5:].strip() for line in body.splitlines() if line.startswith("data:")),None)
        return json.loads(data if data is not None else body) if body else {}
    initialized=post({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"overseer-provisioner","version":"1"}}})
    if "result" not in initialized: raise RuntimeError("MCP initialize failed")
    post({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
    listed=post({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}); tools=listed.get("result",{}).get("tools") if isinstance(listed,Mapping) else None
    if not isinstance(tools,list): raise RuntimeError("MCP tools/list failed")
    return tools
def _unit(p):
    return "[Service]\nUser="+p["user"]+"\nExecStart="+" ".join(_sd_quote(value) for value in p["exec_start"])+"\nUMask="+p["umask"]+"\nPrivateTmp=yes\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nReadOnlyPaths="+" ".join(_sd_quote(value) for value in p["read_only_paths"])+"\nReadWritePaths="+" ".join(_sd_quote(value) for value in p["read_write_paths"])+"\nRestrictAddressFamilies="+" ".join(p["restrict_address_families"])+"\n[Install]\nWantedBy=multi-user.target\n"
def _sd_quote(value): return '"'+str(value).replace("\\","\\\\").replace('"','\\"')+'"'

__all__=["ConcreteHostProvisioningAdapter","EXPECTED_BACKUP_TOOL_SCHEMAS","HostOperationDisposition","HostOperationResult","PRIVILEGED_CONFIRMATION","RUNTIME_EXCLUDED","RedactedHostOperationError","capability_digest","runtime_digest"]
