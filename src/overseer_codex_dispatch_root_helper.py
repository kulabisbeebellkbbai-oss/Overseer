"""Root-owned external supervisor for immutable Overseer dispatch activation.

This file is installed from its reviewed Git blob.  It is deliberately
stdlib-only and must run as uid 0 from /usr/local/libexec.  The unprivileged
coordinator supplies one canonical length-framed capability stream; this
helper independently validates that closed capability before any effect.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


SCHEMA = "overseer.codex-dispatch-system-activation.v1"
HELPER_PATH = "/usr/local/libexec/overseer-codex-dispatch-activation"
AUTHORITY_PATH = "/etc/overseer/codex-dispatch-authority.json"
SYSTEM_UNIT = "/etc/systemd/system/overseer-api.service"
SYSTEM_ENABLE_LINK = "/etc/systemd/system/multi-user.target.wants/overseer-api.service"
SYSTEM_CGROUP_PROCS = "/sys/fs/cgroup/system.slice/overseer-api.service/cgroup.procs"
STATE_ROOT = "/var/lib/overseer/codex-dispatch-activation"
SYSTEMCTL = "/usr/bin/systemctl"
CODEX_BINARY = "/usr/local/bin/codex"
CODEX_SOCKET = "/home/god/.codex/app-server-control/app-server-control.sock"
CODEX_SETTINGS = "/home/god/.codex/app-server-daemon/settings.json"
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
PROC_ROOT = "/proc"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _exact(stream, size: int) -> bytes:
    value = b""
    while len(value) < size:
        chunk = stream.read(size - len(value))
        if not chunk:
            raise RuntimeError("truncated capability stream")
        value += chunk
    return value


def _frame(stream) -> bytes:
    return _exact(stream, struct.unpack(">Q", _exact(stream, 8))[0])


def _safe_relative(value: object) -> str:
    if (not isinstance(value, str) or not value or value.startswith("/")
            or ".." in value.split("/") or "//" in value):
        raise ValueError("unsafe relative path")
    return value


def _stable_file(path: str, *, uid: int, mode: int, digest: str | None) -> tuple[bytes, os.stat_result]:
    lexical = os.lstat(path)
    if not stat.S_ISREG(lexical.st_mode) or lexical.st_uid != uid or lexical.st_nlink != 1:
        raise ValueError("bound file identity is unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        content = b""
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            content += chunk
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                             item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if (identity(lexical) != identity(before) or identity(before) != identity(after)
            or stat.S_IMODE(after.st_mode) != mode
            or (digest is not None and hashlib.sha256(content).hexdigest() != digest)):
        raise ValueError("bound file changed")
    return content, after


def _rename_noreplace(source_dir: int, source: str, target_dir: int, target: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(source_dir, source.encode(), target_dir, target.encode(), 1) != 0:
        raise OSError(ctypes.get_errno(), "no-replace rename failed")


def _root_directory(path: str, mode: int) -> int:
    value = Path(path)
    value.mkdir(parents=True, mode=mode, exist_ok=True)
    info = value.lstat()
    if (not stat.S_ISDIR(info.st_mode) or value.is_symlink() or info.st_uid != 0
            or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022):
        raise ValueError("root state directory is unsafe")
    return os.open(value, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)


def _directory_at(parent_fd: int, name: str, mode: int) -> int:
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                 dir_fd=parent_fd)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise ValueError("root release directory is unsafe")
    return fd


def _install_release(capability: dict[str, object], stream) -> None:
    manifest = capability["manifest"]
    if (not isinstance(manifest, dict) or manifest.get("manifestDigest") != capability["manifestDigest"]
            or manifest.get("releaseRoot") != capability["releaseRoot"]):
        raise ValueError("release manifest binding is invalid")
    unsigned = {key: manifest[key] for key in manifest if key not in {"manifestDigest", "releaseRoot"}}
    if _digest(unsigned) != capability["manifestDigest"]:
        raise ValueError("release manifest digest changed")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("release file inventory is empty")
    paths = [item.get("releasePath") for item in files if isinstance(item, dict)]
    if len(paths) != len(files) or paths != sorted(set(paths)):
        raise ValueError("release file inventory is not closed and sorted")
    opt = os.lstat("/opt")
    opt_identity = (opt.st_dev, opt.st_ino, opt.st_uid, opt.st_gid, stat.S_IMODE(opt.st_mode))
    if not stat.S_ISDIR(opt.st_mode) or opt.st_uid != 0 or opt.st_gid != 0 or stat.S_IMODE(opt.st_mode) & 0o022:
        raise ValueError("/opt trust root is unsafe")
    opt_fd = os.open("/opt", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    opened: dict[str, int] = {}
    try:
        current = os.fstat(opt_fd)
        if opt_identity != (current.st_dev, current.st_ino, current.st_uid, current.st_gid,
                            stat.S_IMODE(current.st_mode)):
            raise ValueError("/opt identity changed")
        overseer_fd = _directory_at(opt_fd, "overseer", 0o555)
        releases_fd = _directory_at(overseer_fd, "releases", 0o555)
        final_name = str(capability["releaseRoot"]).rsplit("/", 1)[1]
        expected_final = f"{manifest['sourceCommit']}-{capability['manifestDigest']}"
        if final_name != expected_final:
            raise ValueError("release final name is not content addressed")
        action = str(capability["journalActionId"])
        staging_name = f".{final_name}.{action}.staging-inert"
        try:
            final_fd = os.open(final_name, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                               dir_fd=releases_fd)
        except FileNotFoundError:
            final_fd = None
        if final_fd is not None:
            try:
                for item in files:
                    data = _frame(stream)
                    if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                        raise ValueError("retry stream frame does not match manifest")
                    parts = _safe_relative(item["releasePath"]).split("/")
                    directory_fd = final_fd
                    temporary_fds = []
                    try:
                        for part in parts[:-1]:
                            directory_fd = os.open(part, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
                                                   dir_fd=directory_fd)
                            temporary_fds.append(directory_fd)
                        fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
                        existing = b""
                        while True:
                            chunk = os.read(fd, 1024 * 1024)
                            if not chunk:
                                break
                            existing += chunk
                        info = os.fstat(fd); os.close(fd)
                        if (existing != data or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                                or stat.S_IMODE(info.st_mode) != item["mode"]):
                            raise ValueError("published release conflicts with approved manifest")
                    finally:
                        for temporary in temporary_fds:
                            os.close(temporary)
                mf = os.open("release-manifest.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=final_fd)
                existing_manifest = b""
                while True:
                    chunk = os.read(mf, 1024 * 1024)
                    if not chunk:
                        break
                    existing_manifest += chunk
                info = os.fstat(mf); os.close(mf)
                if (existing_manifest != _canonical(manifest) + b"\n" or info.st_uid != 0 or info.st_gid != 0
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o444):
                    raise ValueError("published release manifest changed")
                return
            finally:
                os.close(final_fd); os.close(releases_fd); os.close(overseer_fd)
        try:
            staging_fd = _directory_at(releases_fd, staging_name, 0o700)
        except ValueError:
            raise
        opened[""] = staging_fd

        def parent(parts: list[str]) -> int:
            key = ""
            fd = staging_fd
            for part in parts:
                _safe_relative(part)
                key += "/" + part
                if key not in opened:
                    opened[key] = _directory_at(fd, part, 0o700)
                fd = opened[key]
            return fd

        for item in files:
            if set(item) != {"releasePath", "sourceKind", "sourcePath", "sha256", "size", "mode"}:
                raise ValueError("release file schema is invalid")
            relative = _safe_relative(item["releasePath"])
            data = _frame(stream)
            if (len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]
                    or item["mode"] not in {0o444, 0o555}):
                raise ValueError("release stream frame does not match manifest")
            parts = relative.split("/")
            parent_fd = parent(parts[:-1])
            try:
                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                             item["mode"], dir_fd=parent_fd)
            except FileExistsError:
                fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
                existing = b""
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    existing += chunk
                info = os.fstat(fd)
                os.close(fd)
                if (existing != data or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != item["mode"]):
                    raise ValueError("partial release staging conflicts with approved manifest")
                continue
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("release write made no progress")
                    view = view[written:]
                os.fchmod(fd, item["mode"])
                os.fsync(fd)
            finally:
                os.close(fd)
        manifest_bytes = _canonical(manifest) + b"\n"
        try:
            mf = os.open("release-manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o444, dir_fd=staging_fd)
        except FileExistsError:
            mf = os.open("release-manifest.json", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=staging_fd)
            existing = b""
            while True:
                chunk = os.read(mf, 1024 * 1024)
                if not chunk:
                    break
                existing += chunk
            info = os.fstat(mf)
            os.close(mf)
            if (existing != manifest_bytes or info.st_uid != 0 or info.st_gid != 0
                    or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o444):
                raise ValueError("partial release manifest conflicts with approved manifest")
        else:
            try:
                view = memoryview(manifest_bytes)
                while view:
                    written = os.write(mf, view)
                    if written <= 0:
                        raise OSError("release manifest write made no progress")
                    view = view[written:]
                os.fchmod(mf, 0o444)
                os.fsync(mf)
            finally:
                os.close(mf)
        for _, fd in sorted(opened.items(), key=lambda pair: pair[0].count("/"), reverse=True):
            os.fchmod(fd, 0o555)
            os.fsync(fd)
        try:
            _rename_noreplace(releases_fd, staging_name, releases_fd, final_name)
        except FileExistsError:
            # A completed prior attempt is accepted only after the immutable
            # launcher performs its full manifest validation at service start.
            pass
        os.fsync(releases_fd)
        os.fsync(overseer_fd)
        os.fsync(opt_fd)
        after = os.lstat("/opt")
        if opt_identity != (after.st_dev, after.st_ino, after.st_uid, after.st_gid,
                            stat.S_IMODE(after.st_mode)):
            raise ValueError("/opt metadata changed outside child creation")
        os.close(releases_fd)
        os.close(overseer_fd)
    finally:
        for fd in set(opened.values()):
            try:
                os.close(fd)
            except OSError:
                pass
        os.close(opt_fd)


def _atomic_root_file(path: str, content: bytes, mode: int) -> tuple[int, int]:
    parent = str(Path(path).parent)
    parent_fd = _root_directory(parent, 0o755)
    name = Path(path).name
    temporary = f".{name}.{os.getpid()}.new"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                     mode, dir_fd=parent_fd)
        try:
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("root file write made no progress")
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
            info = os.fstat(fd)
        finally:
            os.close(fd)
        _rename_noreplace(parent_fd, temporary, parent_fd, name)
        os.fsync(parent_fd)
        return info.st_dev, info.st_ino
    finally:
        os.close(parent_fd)


def _install_or_verify_root_file(path: str, content: bytes, mode: int) -> tuple[int, int]:
    if os.path.lexists(path):
        existing, info = _stable_file(path, uid=0, mode=mode,
                                      digest=hashlib.sha256(content).hexdigest())
        if existing != content or info.st_gid != 0:
            raise ValueError("existing root file is not the approved exact file")
        return info.st_dev, info.st_ino
    return _atomic_root_file(path, content, mode)


def _journal_path(plan_digest: str) -> str:
    return f"{STATE_ROOT}/{plan_digest}.journal.json"


_JOURNAL_CRASH_HOOK = lambda _phase: None


def _journal_prior_path(plan_digest: str) -> str:
    return f"{STATE_ROOT}/.{plan_digest}.journal.prior.json"


def _decode_journal(content: bytes, plan_digest: str) -> dict[str, object]:
    value = json.loads(content)
    expected = {"schemaVersion", "planDigest", "phase", "journalActionId",
                "userResourceQuarantines", "oldSystemUnitQuarantine", "systemUnitIdentity",
                "priorSystemServiceState", "priorDaemonState", "daemonOwnership", "daemonEvidence",
                "lastError", "generation", "recordDigest"}
    phases = {"intent-system-unit", "intent-daemon", "daemon-ready", "intent-stop-prior-system",
              "prior-system-stopped", "system-unit-installed", "release-installed",
              "user-service-quarantined", "old-api-stopped", "system-service-started",
              "verified", "rollback-pending", "rollback-system-stopped",
              "rollback-new-unit-quarantined", "rollback-old-unit-restored",
              "rollback-system-reloaded", "rollback-prior-system-enabled",
              "rollback-prior-system-active", "rollback-user-resources-restored",
              "rollback-user-manager-reloaded", "rollback-user-api-started", "rolled-back"}
    if (not isinstance(value, dict) or set(value) != expected or value["schemaVersion"] != SCHEMA
            or value["planDigest"] != plan_digest or value["phase"] not in phases
            or not isinstance(value["generation"], int) or value["generation"] < 1
            or not isinstance(value["recordDigest"], str)
            or value["recordDigest"] != _digest({key: value[key] for key in value if key != "recordDigest"})
            or content != _canonical(value) + b"\n"
            or not isinstance(value["priorSystemServiceState"], dict)
            or set(value["priorSystemServiceState"]) != {"present", "enabled", "active"}
            or any(not isinstance(value["priorSystemServiceState"][key], bool)
                   for key in ("present", "enabled", "active"))):
        raise ValueError("root activation journal is invalid")
    return value


def _journal_candidate(path: str, plan_digest: str) -> tuple[dict[str, object], bytes] | None:
    try:
        content, info = _stable_file(path, uid=0, mode=0o600, digest=None)
    except FileNotFoundError:
        return None
    if info.st_gid != 0:
        raise ValueError("root activation journal group is invalid")
    return _decode_journal(content, plan_digest), content


def _journal_candidates(plan_digest: str) -> list[tuple[dict[str, object], bytes]]:
    candidates = []
    errors = []
    for path in (_journal_path(plan_digest), _journal_prior_path(plan_digest)):
        try:
            candidate = _journal_candidate(path, plan_digest)
        except (ValueError, json.JSONDecodeError) as error:
            errors.append(error)
            continue
        if candidate is not None:
            candidates.append(candidate)
    if not candidates and errors:
        raise ValueError("no valid root activation journal generation remains") from errors[0]
    return candidates


def _atomic_replace_journal(parent_fd: int, name: str, content: bytes, generation: int) -> None:
    temporary = f".{name}.{os.getpid()}.{generation}.new"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("journal write made no progress")
            view = view[written:]
        os.fchmod(fd, 0o600); os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    os.fsync(parent_fd)


def _write_journal(value: dict[str, object]) -> None:
    plan_digest = str(value["planDigest"])
    path = _journal_path(plan_digest); prior_path = _journal_prior_path(plan_digest)
    candidates = _journal_candidates(plan_digest)
    generation = max((int(item[0]["generation"]) for item in candidates), default=0) + 1
    unsigned = {key: item for key, item in value.items() if key not in {"generation", "recordDigest"}}
    unsigned["generation"] = generation
    record = {**unsigned, "recordDigest": _digest(unsigned)}
    content = _canonical(record) + b"\n"
    parent_fd = _root_directory(str(Path(path).parent), 0o700)
    try:
        _atomic_replace_journal(parent_fd, f".{Path(path).name}.{generation}.pending", content, generation)
        pending = f".{Path(path).name}.{generation}.pending"
        _JOURNAL_CRASH_HOOK("new-fsynced")
        if candidates:
            newest = max(candidates, key=lambda item: int(item[0]["generation"]))
            _atomic_replace_journal(parent_fd, Path(prior_path).name, newest[1], generation)
        _JOURNAL_CRASH_HOOK("prior-replaced")
        os.replace(pending, Path(path).name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        _JOURNAL_CRASH_HOOK("active-replaced")
    finally:
        os.close(parent_fd)
    value.clear(); value.update(record)


def _read_journal(plan_digest: str) -> dict[str, object]:
    candidates = _journal_candidates(plan_digest)
    if not candidates:
        raise FileNotFoundError(_journal_path(plan_digest))
    return max(candidates, key=lambda item: int(item[0]["generation"]))[0]


def _run_systemctl(*arguments: str) -> None:
    completed = subprocess.run((SYSTEMCTL, *arguments), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=SAFE_ENV, check=False, timeout=60)
    if completed.returncode != 0:
        raise RuntimeError("root system manager action failed")


def _run_user_systemctl(*arguments: str) -> None:
    command = ("/usr/sbin/runuser", "-u", "god", "--", "/usr/bin/env", "-i",
               "PATH=/usr/bin:/bin", "LC_ALL=C", "XDG_RUNTIME_DIR=/run/user/1000",
               "/usr/bin/systemctl", "--user", *arguments)
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=SAFE_ENV, check=False, timeout=60)
    if completed.returncode != 0:
        raise RuntimeError("user service restoration action failed")


def _run_codex(*arguments: str) -> dict[str, object]:
    command = ("/usr/sbin/runuser", "-u", "god", "--", "/usr/bin/env", "-i",
               "HOME=/home/god", "CODEX_HOME=/home/god/.codex", "XDG_RUNTIME_DIR=/run/user/1000",
               "PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C", CODEX_BINARY, *arguments)
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=SAFE_ENV, check=False, timeout=120)
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError("Codex daemon command failed")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Codex daemon command output is not JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Codex daemon command output is invalid")
    return value


def _validate_codex_binary(binding: dict[str, object]) -> None:
    required = {"path", "resolvedPath", "entryDevice", "entryInode", "entryMode", "device",
                "inode", "mode", "links", "sha256", "size"}
    if not isinstance(binding, dict) or set(binding) != required or binding["path"] != CODEX_BINARY:
        raise ValueError("Codex binary binding is invalid")
    content, info = _stable_file(str(binding["resolvedPath"]), uid=0, mode=int(binding["mode"]),
                                 digest=str(binding["sha256"]))
    entry = os.lstat(CODEX_BINARY)
    if ((entry.st_dev, entry.st_ino, stat.S_IMODE(entry.st_mode))
            != (binding["entryDevice"], binding["entryInode"], binding["entryMode"])
            or (info.st_dev, info.st_ino, info.st_nlink, len(content))
            != (binding["device"], binding["inode"], binding["links"], binding["size"])
            or os.path.realpath(CODEX_BINARY) != binding["resolvedPath"]):
        raise ValueError("Codex binary identity changed")


def _codex_daemon_evidence() -> dict[str, object]:
    version = _run_codex("app-server", "daemon", "version")
    required = {"cliVersion", "daemonVersion", "state", "remoteControlEnabled", "socketPath"}
    if (set(version) != required or version["state"] != "running"
            or version["remoteControlEnabled"] is not False or version["socketPath"] != CODEX_SOCKET):
        raise ValueError("Codex daemon version contract is invalid")
    info = os.lstat(CODEX_SOCKET)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 1000:
        raise ValueError("Codex daemon socket is unsafe")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(CODEX_SOCKET)
        pid, uid, gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    finally:
        client.close()
    if uid != 1000 or gid != 1000:
        raise ValueError("Codex daemon peer identity is invalid")
    return {"version": version, "peerPid": pid, "peerUid": uid, "peerGid": gid,
            "peerStartTicks": _process_start_ticks(pid), "socketDevice": info.st_dev,
            "socketInode": info.st_ino,
            "peerCmdlineHex": Path(f"{PROC_ROOT}/{pid}/cmdline").read_bytes().hex(),
            "peerCgroup": Path(f"{PROC_ROOT}/{pid}/cgroup").read_text().strip()}


def _ensure_codex_daemon(capability: dict[str, object], journal: dict[str, object]) -> None:
    daemon = capability["codexDaemon"]
    _validate_codex_binary(daemon["binary"])
    running = os.path.lexists(CODEX_SOCKET)
    if not journal["daemonOwnership"]:
        if running != daemon["priorRunning"]:
            raise ValueError("Codex daemon prior state changed")
        journal["priorDaemonState"] = {"running": daemon["priorRunning"],
                                       "remoteControlEnabled": daemon["priorRemoteControlEnabled"],
                                       "settings": daemon["priorSettings"]}
        journal["daemonOwnership"] = "preexisting" if running else "start-issued"
        journal["phase"] = "intent-daemon"; _write_journal(journal)
    if running and journal["daemonOwnership"] == "start-issued":
        journal["daemonOwnership"] = "started-by-operation"
    if running and daemon["priorRemoteControlEnabled"] is True:
        _run_codex("app-server", "daemon", "disable-remote-control")
    if not running:
        bootstrap = _run_codex("app-server", "daemon", "bootstrap")
        if (set(bootstrap) != {"status", "backend", "autoUpdateEnabled", "remoteControlEnabled",
                              "managedCodexPath", "managedCodexVersion", "socketPath", "cliVersion",
                              "appServerVersion"}
                or bootstrap["status"] != "bootstrapped" or bootstrap["backend"] != "pid"
                or bootstrap["autoUpdateEnabled"] is not True
                or bootstrap["remoteControlEnabled"] is not False or bootstrap["socketPath"] != CODEX_SOCKET):
            raise ValueError("Codex daemon bootstrap protocol is invalid")
        disabled = _run_codex("app-server", "daemon", "disable-remote-control")
        if (not {"status", "remoteControlEnabled", "socketPath", "cliVersion"} <= set(disabled)
                or disabled["status"] not in {"disabled", "alreadyDisabled"}
                or disabled["remoteControlEnabled"] is not False or disabled["socketPath"] != CODEX_SOCKET):
            raise ValueError("Codex daemon remote-control protocol is invalid")
        if not os.path.lexists(CODEX_SOCKET):
            _run_codex("app-server", "daemon", "start")
        journal["daemonOwnership"] = "started-by-operation"
    evidence = _codex_daemon_evidence()
    if daemon["priorRunning"] and daemon["priorEvidence"] != evidence:
        raise ValueError("preexisting Codex daemon peer/version identity changed")
    journal["daemonEvidence"] = evidence
    journal["phase"] = "daemon-ready"; _write_journal(journal)


def _system_service_enabled() -> bool:
    if not os.path.lexists(SYSTEM_ENABLE_LINK):
        return False
    info = os.lstat(SYSTEM_ENABLE_LINK)
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != 0
            or os.path.realpath(SYSTEM_ENABLE_LINK) != SYSTEM_UNIT):
        raise ValueError("root system service enablement link is unsafe")
    return True


def _system_service_active() -> bool:
    return bool(_service_pids(SYSTEM_CGROUP_PROCS))


def _verify_system_unit(capability: dict[str, object], identity: tuple[int, int]) -> None:
    content, info = _stable_file(SYSTEM_UNIT, uid=0, mode=0o644,
                                 digest=str(capability["systemUnitSha256"]))
    if (content != str(capability["systemUnit"]).encode() or info.st_gid != 0
            or (info.st_dev, info.st_ino) != identity):
        raise ValueError("effective root system unit file changed")


def _service_pids(path: str) -> list[int]:
    try:
        values = Path(path).read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        return []
    return [int(value) for value in values if value]


def _process_start_ticks(pid: int) -> int:
    raw = Path(f"{PROC_ROOT}/{pid}/stat").read_text(encoding="ascii")
    fields = raw[raw.rfind(")") + 2:].split()
    if len(fields) <= 19:
        raise ValueError("process stat is truncated")
    return int(fields[19])


def _attest_loopback_listener(pid: int) -> dict[str, int]:
    expected_cgroup = "0::/system.slice/overseer-api.service"
    if Path(f"{PROC_ROOT}/{pid}/cgroup").read_text(encoding="ascii").strip() != expected_cgroup:
        raise ValueError("listener process cgroup is not the system service")
    listener_inodes: list[int] = []
    for table, loopback in (("tcp", "0100007F"),
                            ("tcp6", "00000000000000000000000001000000")):
        path = Path(f"{PROC_ROOT}/net/{table}")
        try:
            lines = path.read_text(encoding="ascii").splitlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            address, port = fields[1].rsplit(":", 1)
            if port.upper() != "223E":
                continue
            if address.upper() != loopback:
                raise ValueError("Overseer port has a non-loopback listener")
            listener_inodes.append(int(fields[9]))
    if len(listener_inodes) != 1:
        raise ValueError("exactly one loopback Overseer listener is required")
    inode = listener_inodes[0]
    owners: set[int] = set()
    for process_dir in Path(PROC_ROOT).iterdir():
        if not process_dir.name.isdigit():
            continue
        try:
            descriptors = (process_dir / "fd").iterdir()
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor)
                except FileNotFoundError:
                    continue
                except PermissionError as error:
                    raise ValueError("cannot prove listener descriptor ownership") from error
                if target == f"socket:[{inode}]":
                    owners.add(int(process_dir.name))
        except (FileNotFoundError, NotADirectoryError):
            continue
        except PermissionError as error:
            raise ValueError("cannot enumerate listener process ownership") from error
    if owners != {pid}:
        raise ValueError("Overseer listener belongs to a foreign process")
    return {"inode": inode, "pid": pid, "startTicks": _process_start_ticks(pid)}


def _verify_bound_health(pid: int) -> dict[str, int]:
    pidfd = os.pidfd_open(pid, 0)
    poller = select.poll(); poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    try:
        if poller.poll(0):
            raise ValueError("root system API process exited before health verification")
        listener = _attest_loopback_listener(pid)
        with urllib.request.urlopen("http://127.0.0.1:8766/health", timeout=5) as response:
            health = json.loads(response.read())
            if (response.status != 200 or health != {"ok": True, "service": "overseer-api",
                                                     "psychloBridgeReady": True}):
                raise ValueError("root system API and Psychlo bridge readiness failed")
        if poller.poll(0) or _attest_loopback_listener(pid) != listener:
            raise ValueError("root system API listener changed during health verification")
        return listener
    finally:
        os.close(pidfd)


def _wait_no_user_api(timeout: float = 20.0) -> None:
    path = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/overseer-api.service/cgroup.procs"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _service_pids(path):
            return
        time.sleep(0.1)
    raise RuntimeError("old user API restarted after quarantine")


def _require_port_free() -> None:
    import socket
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        probe.bind(("127.0.0.1", 8766))
    except OSError as error:
        raise RuntimeError("Overseer API port remains occupied") from error
    finally:
        probe.close()


def _verify_system_api(capability: dict[str, object]) -> dict[str, object]:
    cgroup_path = "/sys/fs/cgroup/system.slice/overseer-api.service/cgroup.procs"
    deadline = time.monotonic() + 30.0
    pid = None
    while time.monotonic() < deadline:
        pids = _service_pids(cgroup_path)
        if len(pids) == 1:
            pid = pids[0]
            break
        time.sleep(0.1)
    if pid is None:
        raise RuntimeError("root system Overseer API did not start uniquely")
    expected_exec = next(line[len("ExecStart="):] for line in str(capability["systemUnit"]).splitlines()
                         if line.startswith("ExecStart="))
    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
    if cmdline != b"\0".join(item.encode() for item in expected_exec.split(" ")) + b"\0":
        raise ValueError("root system API argv is not exact")
    if os.readlink(f"/proc/{pid}/cwd") != capability["releaseRoot"]:
        raise ValueError("root system API WorkingDirectory is not the immutable release")
    status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
              for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line}
    if status.get("Uid") != "1000\t1000\t1000\t1000" or status.get("Gid") != "1000\t1000\t1000\t1000":
        raise ValueError("root system API does not run as god")
    if _service_pids("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/overseer-api.service/cgroup.procs"):
        raise ValueError("duplicate user Overseer API exists")
    listener = _verify_bound_health(pid)
    return {"pid": pid, "cgroup": "0::/system.slice/overseer-api.service",
            "startTicks": listener["startTicks"], "listenerInode": listener["inode"],
            "cwd": capability["releaseRoot"], "unitSha256": capability["systemUnitSha256"]}


def _wait_restored_user_api(capability: dict[str, object], timeout: float = 30.0) -> None:
    path = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/overseer-api.service/cgroup.procs"
    expected = capability["oldApiBinding"]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pids = _service_pids(path)
        if len(pids) == 1:
            pid = pids[0]
            if (Path(f"/proc/{pid}/cmdline").read_bytes().hex() == expected["cmdlineHex"]
                    and os.readlink(f"/proc/{pid}/cwd") == expected["cwd"]):
                return
        time.sleep(0.1)
    raise RuntimeError("prior user Overseer API was not restored exactly")


def _validate_capability(value: object, approved_digest: str) -> dict[str, object]:
    keys = {
        "schemaVersion", "planDigest", "manifest", "manifestDigest", "releaseRoot",
        "systemUnit", "systemUnitSha256", "bootstrapHelperSha256", "rootHelperPath",
        "bootstrapHelperGitBlob", "bootstrapHelperSize", "bootstrapInlineSha256",
        "rootAuthorityPath", "approvalRecordId", "approvalRecordDigest", "rootPythonIdentity",
        "oldUserResources", "oldSystemUnit", "priorSystemServiceState",
        "oldApiBinding", "managerBinding", "journalActionId", "codexDaemon",
        "rollback", "receiptStore",
    }
    if not isinstance(value, dict) or set(value) != keys or value["schemaVersion"] != SCHEMA:
        raise ValueError("activation capability schema is invalid")
    supplied = value["planDigest"]
    unsigned = {key: value[key] for key in value if key != "planDigest"}
    if supplied != approved_digest or supplied != _digest(unsigned):
        raise ValueError("activation capability is not the approved plan")
    if value["rootHelperPath"] != HELPER_PATH:
        raise ValueError("activation helper path is invalid")
    if value["rootAuthorityPath"] != AUTHORITY_PATH:
        raise ValueError("activation authority path is invalid")
    unit = value["systemUnit"]
    if not isinstance(unit, str) or hashlib.sha256(unit.encode()).hexdigest() != value["systemUnitSha256"]:
        raise ValueError("system unit binding is invalid")
    resources = value["oldUserResources"]
    if not isinstance(resources, list) or any(not isinstance(item, dict) for item in resources):
        raise ValueError("old user unit inventory is invalid")
    old_system = value["oldSystemUnit"]
    old_keys = {"path", "sha256", "device", "inode", "mode", "uid", "size", "enabled", "active",
                "activeProcess"}
    if (old_system is not None
            and (not isinstance(old_system, dict) or set(old_system) != old_keys
                 or not isinstance(old_system["enabled"], bool)
                 or not isinstance(old_system["active"], bool))):
        raise ValueError("preexisting system unit binding is invalid")
    prior = value["priorSystemServiceState"]
    expected_prior = {
        "present": old_system is not None,
        "enabled": bool(old_system and old_system["enabled"]),
        "active": bool(old_system and old_system["active"]),
    }
    if prior != expected_prior:
        raise ValueError("prior root system service state binding is invalid")
    daemon = value["codexDaemon"]
    if (not isinstance(daemon, dict)
            or set(daemon) != {"binary", "socketPath", "priorRunning", "priorEvidence", "priorSettings",
                               "priorRemoteControlEnabled", "uid", "gid"}
            or daemon["socketPath"] != CODEX_SOCKET or daemon["uid"] != 1000 or daemon["gid"] != 1000
            or not isinstance(daemon["priorRunning"], bool)
            or daemon["priorRemoteControlEnabled"] not in {None, False, True}
            or (daemon["priorSettings"] is not None
                and (not isinstance(daemon["priorSettings"], dict)
                     or set(daemon["priorSettings"]) != {"sha256", "size", "mode", "uid"}))):
        raise ValueError("Codex daemon capability is invalid")
    return value


def _load_root_authority(capability: dict[str, object]) -> dict[str, object]:
    unsigned = {
        "schemaVersion": "overseer.codex-dispatch-root-authority.v1",
        "planDigest": capability["planDigest"],
        "helperGitBlob": capability["bootstrapHelperGitBlob"],
        "helperSha256": capability["bootstrapHelperSha256"],
        "helperSize": capability["bootstrapHelperSize"],
        "rootHelperPath": HELPER_PATH, "rootAuthorityPath": AUTHORITY_PATH,
        "bootstrapInlineSha256": capability["bootstrapInlineSha256"],
        "systemUnitSha256": capability["systemUnitSha256"],
        "releaseManifestDigest": capability["manifestDigest"],
        "approvalRecordId": capability["approvalRecordId"],
        "approvalRecordDigest": capability["approvalRecordDigest"],
    }
    expected = {**unsigned, "authorityDigest": _digest(unsigned)}
    content, info = _stable_file(AUTHORITY_PATH, uid=0, mode=0o400, digest=None)
    if info.st_gid != 0 or content != _canonical(expected) + b"\n":
        raise ValueError("root dispatch authority does not exactly authorize this capability")
    return expected


def _validate_python_invocation(capability: dict[str, object], action: str, digest: str) -> None:
    expected_argv = ["/usr/bin/python3", "-I", "-S", HELPER_PATH, action, digest]
    if list(getattr(sys, "orig_argv", ())) != expected_argv or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError("root helper Python invocation is not exact")
    binding = capability["rootPythonIdentity"]
    required = {"path", "resolvedPath", "entryDevice", "entryInode", "entryMode", "device",
                "inode", "mode", "links", "sha256", "size"}
    if (not isinstance(binding, dict) or set(binding) != required
            or not isinstance(capability["manifest"], dict)
            or binding != capability["manifest"].get("rootPython")
            or binding["path"] != "/usr/bin/python3"):
        raise ValueError("root Python identity binding is invalid")
    content, info = _stable_file(str(binding["resolvedPath"]), uid=0, mode=int(binding["mode"]),
                                 digest=str(binding["sha256"]))
    entry = os.lstat("/usr/bin/python3")
    if (not stat.S_ISLNK(entry.st_mode)
            or (entry.st_dev, entry.st_ino, stat.S_IMODE(entry.st_mode))
            != (binding["entryDevice"], binding["entryInode"], binding["entryMode"])
            or (info.st_dev, info.st_ino, info.st_nlink, len(content))
            != (binding["device"], binding["inode"], binding["links"], binding["size"])
            or os.path.realpath("/usr/bin/python3") != binding["resolvedPath"]
            or os.readlink(f"{PROC_ROOT}/self/exe") != binding["resolvedPath"]):
        raise ValueError("root Python identity changed")


def _prepare_system_unit(capability: dict[str, object], journal: dict[str, object]) -> tuple[int, int]:
    old = capability["oldSystemUnit"]
    if old is not None:
        if not isinstance(old, dict) or set(old) != {"path", "sha256", "device", "inode", "mode", "uid", "size", "enabled", "active", "activeProcess"}:
            raise ValueError("preexisting system unit binding is invalid")
        quarantine = f"/etc/systemd/system/.overseer-api.service.{capability['journalActionId']}.prior-inert"
        if journal.get("oldSystemUnitQuarantine"):
            if journal["oldSystemUnitQuarantine"] != quarantine:
                raise ValueError("preexisting system unit quarantine journal changed")
        elif os.path.exists(SYSTEM_UNIT):
            content, info = _stable_file(SYSTEM_UNIT, uid=0, mode=int(old["mode"]), digest=str(old["sha256"]))
            if (info.st_dev, info.st_ino, len(content)) != (old["device"], old["inode"], old["size"]):
                raise ValueError("preexisting system unit identity changed")
            parent_fd = os.open("/etc/systemd/system", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _rename_noreplace(parent_fd, "overseer-api.service", parent_fd, Path(quarantine).name)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        retained, retained_info = _stable_file(quarantine, uid=0, mode=int(old["mode"]), digest=str(old["sha256"]))
        if (retained_info.st_dev, retained_info.st_ino, len(retained)) != (old["device"], old["inode"], old["size"]):
            raise ValueError("preexisting system unit quarantine changed")
        if not journal.get("oldSystemUnitQuarantine"):
            journal["oldSystemUnitQuarantine"] = quarantine
            _write_journal(journal)
    elif os.path.exists(SYSTEM_UNIT):
        # Retry accepts only the exact newly installed unit.
        return _install_or_verify_root_file(SYSTEM_UNIT, str(capability["systemUnit"]).encode(), 0o644)
    return _install_or_verify_root_file(SYSTEM_UNIT, str(capability["systemUnit"]).encode(), 0o644)


def _quarantine_user_resources(capability: dict[str, object], journal: dict[str, object]) -> None:
    retained = []
    for item in capability["oldUserResources"]:
        expected = {"path", "sha256", "device", "inode", "mode", "uid", "size"}
        if set(item) != expected or item["uid"] != 1000:
            raise ValueError("old user resource binding is invalid")
        path = str(item["path"])
        parent_fd = os.open(str(Path(path).parent), os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
        quarantine = f".{Path(path).name}.{capability['journalActionId']}.system-migration-inert"
        try:
            active_exists = True
            try:
                os.stat(Path(path).name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                active_exists = False
            quarantine_exists = True
            try:
                os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                quarantine_exists = False
            if active_exists and quarantine_exists:
                raise ValueError("old user resource and quarantine both exist")
            bound_path = path if active_exists else str(Path(path).parent / quarantine)
            content, info = _stable_file(bound_path, uid=1000, mode=int(item["mode"]), digest=str(item["sha256"]))
            if (info.st_dev, info.st_ino, len(content)) != (item["device"], item["inode"], item["size"]):
                raise ValueError("old user resource identity changed")
            if active_exists:
                _rename_noreplace(parent_fd, Path(path).name, parent_fd, quarantine)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        retained.append({"activePath": path, "quarantinePath": str(Path(path).parent / quarantine),
                         "device": info.st_dev, "inode": info.st_ino, "sha256": item["sha256"]})
    journal["userResourceQuarantines"] = retained


def _restore_exact_quarantine(active: str, quarantine: str, expected: dict[str, object], *, uid: int) -> None:
    """Restore once, or attest an exact prior restore after a crash."""
    active_exists = os.path.lexists(active)
    quarantine_exists = os.path.lexists(quarantine)
    if active_exists == quarantine_exists:
        raise ValueError("restore requires exactly one active or quarantined resource")
    source = quarantine if quarantine_exists else active
    content, info = _stable_file(source, uid=uid, mode=int(expected["mode"]),
                                 digest=str(expected["sha256"]))
    if (info.st_dev, info.st_ino, len(content)) != (
            expected["device"], expected["inode"], expected["size"]):
        raise ValueError("restored resource identity changed")
    if active_exists:
        return
    active_parent = str(Path(active).parent)
    quarantine_parent = str(Path(quarantine).parent)
    if active_parent != quarantine_parent:
        raise ValueError("quarantine escaped its bound parent")
    parent_fd = os.open(active_parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _rename_noreplace(parent_fd, Path(quarantine).name, parent_fd, Path(active).name)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    restored, restored_info = _stable_file(active, uid=uid, mode=int(expected["mode"]),
                                           digest=str(expected["sha256"]))
    if ((restored_info.st_dev, restored_info.st_ino, len(restored))
            != (expected["device"], expected["inode"], expected["size"])):
        raise ValueError("restored resource changed during rename")


def _pin_and_signal(binding: dict[str, object], signum: int | signal.Signals) -> None:
    pid = int(binding["pid"] if "pid" in binding else binding["peerPid"])
    if binding["bootId"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        raise ValueError("approved process boot identity changed")
    if _process_start_ticks(pid) != int(binding["startTicks"]):
        raise ValueError("approved process start identity changed")
    cgroup = Path(f"{PROC_ROOT}/{pid}/cgroup").read_text(encoding="ascii").strip()
    if cgroup != binding["cgroup"]:
        raise ValueError("approved process cgroup changed")
    cmdline = Path(f"{PROC_ROOT}/{pid}/cmdline").read_bytes()
    if "cmdlineHex" in binding and cmdline.hex() != binding["cmdlineHex"]:
        raise ValueError("approved API command changed")
    if "argv" in binding and cmdline != b"\0".join(item.encode() for item in binding["argv"]) + b"\0":
        raise ValueError("approved manager command changed")
    pidfd = os.pidfd_open(pid, 0)
    try:
        os.pidfd_send_signal(pidfd, signum)
    finally:
        os.close(pidfd)


def _stop_prior_system_service(capability: dict[str, object], journal: dict[str, object]) -> None:
    old_system = capability["oldSystemUnit"]
    if old_system is None or not old_system["active"]:
        return
    if _system_service_active():
        binding = old_system["activeProcess"]
        if not isinstance(binding, dict):
            raise ValueError("prior active root service process binding is absent")
        _pin_and_signal(binding, 0)
        journal["phase"] = "intent-stop-prior-system"; _write_journal(journal)
        _run_systemctl("stop", "overseer-api.service")
    if _system_service_active():
        raise RuntimeError("prior root system service did not stop before unit replacement")
    journal["phase"] = "prior-system-stopped"; _write_journal(journal)


def _restore_codex_daemon(journal: dict[str, object]) -> None:
    if journal.get("daemonOwnership") == "started-by-operation":
        _run_codex("app-server", "daemon", "stop")
        if os.path.lexists(CODEX_SOCKET):
            raise RuntimeError("operation-started Codex daemon did not stop")
        journal["daemonOwnership"] = "stopped-by-rollback"; _write_journal(journal)
    prior = journal.get("priorDaemonState")
    if not isinstance(prior, dict):
        return
    if prior.get("remoteControlEnabled") is True:
        _run_codex("app-server", "daemon", "enable-remote-control")
    settings = prior.get("settings")
    if settings is None:
        if os.path.lexists(CODEX_SETTINGS):
            lexical = os.lstat(CODEX_SETTINGS)
            mode = stat.S_IMODE(lexical.st_mode)
            if mode & 0o022:
                raise ValueError("operation-created Codex daemon settings are unsafe")
            content, info = _stable_file(CODEX_SETTINGS, uid=1000, mode=mode, digest=None)
            if json.loads(content) != {"remoteControlEnabled": False}:
                raise ValueError("operation-created Codex daemon settings changed")
            parent_fd = os.open(str(Path(CODEX_SETTINGS).parent),
                                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                inert = f".settings.{journal['journalActionId']}.rollback-inert.json"
                _rename_noreplace(parent_fd, Path(CODEX_SETTINGS).name, parent_fd, inert)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    else:
        content, _ = _stable_file(CODEX_SETTINGS, uid=1000, mode=int(settings["mode"]),
                                  digest=str(settings["sha256"]))
        if len(content) != settings["size"]:
            raise ValueError("prior Codex daemon settings were not restored exactly")


def _activate(capability: dict[str, object], stream) -> None:
    plan_digest = str(capability["planDigest"])
    if os.path.exists(_journal_path(plan_digest)):
        journal = _read_journal(plan_digest)
        if journal["journalActionId"] != capability["journalActionId"] or journal["phase"] in {"rolled-back"}:
            raise ValueError("root activation journal is terminal or belongs to another action")
    else:
        journal = {"schemaVersion": SCHEMA, "planDigest": plan_digest, "phase": "intent-system-unit",
                   "journalActionId": capability["journalActionId"], "userResourceQuarantines": [],
                   "oldSystemUnitQuarantine": "", "systemUnitIdentity": None, "lastError": ""}
        journal["priorSystemServiceState"] = dict(capability["priorSystemServiceState"])
        journal["priorDaemonState"] = None
        journal["daemonOwnership"] = ""
        journal["daemonEvidence"] = None
        _write_journal(journal)
    _ensure_codex_daemon(capability, journal)
    _install_release(capability, stream)
    journal["phase"] = "release-installed"
    _write_journal(journal)
    _stop_prior_system_service(capability, journal)
    unit_identity = _prepare_system_unit(capability, journal)
    journal["systemUnitIdentity"] = list(unit_identity)
    journal["phase"] = "system-unit-installed"
    _write_journal(journal)
    _quarantine_user_resources(capability, journal)
    journal["phase"] = "user-service-quarantined"
    _write_journal(journal)
    _pin_and_signal(dict(capability["managerBinding"]), signal.SIGHUP)
    try:
        _pin_and_signal(dict(capability["oldApiBinding"]), signal.SIGKILL)
    except (FileNotFoundError, ProcessLookupError):
        pass
    _wait_no_user_api()
    _require_port_free()
    journal["phase"] = "old-api-stopped"
    _write_journal(journal)
    _verify_system_unit(capability, unit_identity)
    _run_systemctl("daemon-reload")
    _verify_system_unit(capability, unit_identity)
    _run_systemctl("enable", "--now", "overseer-api.service")
    journal["phase"] = "system-service-started"
    _write_journal(journal)
    _verify_system_unit(capability, unit_identity)
    _verify_system_api(capability)
    journal["phase"] = "verified"
    _write_journal(journal)


def _rollback(capability: dict[str, object]) -> None:
    # Rollback is externally supervised: stop system service first so the
    # helper never kills the process executing its own control path.
    journal = _read_journal(str(capability["planDigest"]))
    if journal["journalActionId"] != capability["journalActionId"]:
        raise ValueError("rollback journal action identity changed")
    prior_state = journal["priorSystemServiceState"]
    if prior_state != capability["priorSystemServiceState"]:
        raise ValueError("prior root system service journal binding changed")
    if journal["phase"] == "rolled-back":
        return
    rollback_phases = (
        "rollback-pending", "rollback-system-stopped", "rollback-new-unit-quarantined",
        "rollback-old-unit-restored", "rollback-system-reloaded",
        "rollback-prior-system-enabled", "rollback-prior-system-active",
        "rollback-user-resources-restored", "rollback-user-manager-reloaded",
        "rollback-user-api-started", "rolled-back",
    )
    if journal["phase"] not in rollback_phases:
        journal["phase"] = "rollback-pending"; _write_journal(journal)
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-system-stopped"):
        identity = journal["systemUnitIdentity"]
        if identity is not None:
            if not isinstance(identity, list) or len(identity) != 2:
                raise ValueError("operation-owned system unit journal identity is invalid")
            _verify_system_unit(capability, (int(identity[0]), int(identity[1])))
            if _system_service_active():
                _run_systemctl("disable", "--now", "overseer-api.service")
            else:
                _run_systemctl("disable", "overseer-api.service")
        journal["phase"] = "rollback-system-stopped"; _write_journal(journal)
    system_parent = str(Path(SYSTEM_UNIT).parent)
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-new-unit-quarantined"):
        parent_fd = os.open(system_parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if os.path.lexists(SYSTEM_UNIT):
                try:
                    content, info = _stable_file(SYSTEM_UNIT, uid=0, mode=0o644,
                                                 digest=str(capability["systemUnitSha256"]))
                    recorded = journal["systemUnitIdentity"]
                    if content != str(capability["systemUnit"]).encode():
                        raise ValueError("operation-owned system unit changed before rollback")
                    if recorded is None:
                        journal["systemUnitIdentity"] = [info.st_dev, info.st_ino]
                        _write_journal(journal)
                    elif recorded != [info.st_dev, info.st_ino]:
                        raise ValueError("operation-owned system unit changed before rollback")
                except ValueError:
                    old = capability["oldSystemUnit"]
                    if old is None:
                        raise
                    prior, prior_info = _stable_file(SYSTEM_UNIT, uid=0, mode=int(old["mode"]),
                                                     digest=str(old["sha256"]))
                    if ((prior_info.st_dev, prior_info.st_ino, len(prior))
                            != (old["device"], old["inode"], old["size"])):
                        raise ValueError("restored prior system unit identity changed")
                    journal["phase"] = "rollback-old-unit-restored"; _write_journal(journal)
                else:
                    inert = f".overseer-api.service.{capability['journalActionId']}.new-system-inert"
                    _rename_noreplace(parent_fd, Path(SYSTEM_UNIT).name, parent_fd, inert)
                    os.fsync(parent_fd)
            if journal["phase"] != "rollback-old-unit-restored":
                journal["phase"] = "rollback-new-unit-quarantined"; _write_journal(journal)
        finally:
            os.close(parent_fd)
    old = capability["oldSystemUnit"]
    if old is not None:
        quarantine = journal["oldSystemUnitQuarantine"]
        if not quarantine:
            raise ValueError("prior root system unit quarantine is absent")
        # This is also an attestation on every retry after restoration: when
        # the quarantine is already gone, only the exact old active inode is
        # accepted.
        _restore_exact_quarantine(SYSTEM_UNIT, str(quarantine), old, uid=0)
    elif os.path.lexists(SYSTEM_UNIT):
        raise ValueError("system unit path unexpectedly occupied during rollback")
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-old-unit-restored"):
        journal["phase"] = "rollback-old-unit-restored"; _write_journal(journal)
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-system-reloaded"):
        _run_systemctl("daemon-reload")
        journal["phase"] = "rollback-system-reloaded"; _write_journal(journal)
    if prior_state["enabled"]:
        if not _system_service_enabled():
            _run_systemctl("enable", "overseer-api.service")
        if not _system_service_enabled():
            raise RuntimeError("prior root system service enablement was not restored")
    elif _system_service_enabled():
        raise ValueError("restored prior root system service was unexpectedly enabled")
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-prior-system-enabled"):
        journal["phase"] = "rollback-prior-system-enabled"; _write_journal(journal)
    if prior_state["active"]:
        if not _system_service_active():
            _run_systemctl("start", "overseer-api.service")
        if not _system_service_active():
            raise RuntimeError("prior root system service activity was not restored")
    elif _system_service_active():
        raise ValueError("restored prior root system service was unexpectedly active")
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-prior-system-active"):
        journal["phase"] = "rollback-prior-system-active"; _write_journal(journal)
    by_active = {item["activePath"]: item for item in journal["userResourceQuarantines"]}
    for expected in capability["oldUserResources"]:
        active = str(expected["path"])
        record = by_active.get(active)
        if not isinstance(record, dict):
            raise ValueError("prior user resource quarantine journal is incomplete")
        # Re-attest already restored resources on every later-phase retry.
        _restore_exact_quarantine(active, str(record["quarantinePath"]), expected, uid=1000)
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-user-resources-restored"):
        journal["phase"] = "rollback-user-resources-restored"; _write_journal(journal)
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-user-manager-reloaded"):
        _pin_and_signal(dict(capability["managerBinding"]), signal.SIGHUP)
        journal["phase"] = "rollback-user-manager-reloaded"; _write_journal(journal)
    if rollback_phases.index(journal["phase"]) < rollback_phases.index("rollback-user-api-started"):
        _run_user_systemctl("start", "overseer-api.service")
        journal["phase"] = "rollback-user-api-started"; _write_journal(journal)
    _wait_restored_user_api(capability)
    _restore_codex_daemon(journal)
    journal["phase"] = "rolled-back"; journal["lastError"] = ""; _write_journal(journal)


def _verify(capability: dict[str, object]) -> None:
    journal = _read_journal(str(capability["planDigest"]))
    if journal["phase"] != "verified" or journal["journalActionId"] != capability["journalActionId"]:
        raise ValueError("root activation journal is not verified")
    identity = journal["systemUnitIdentity"]
    if not isinstance(identity, list) or len(identity) != 2:
        raise ValueError("root system unit journal identity is invalid")
    _verify_system_unit(capability, (int(identity[0]), int(identity[1])))
    _verify_system_api(capability)


def main(argv: list[str] | None = None) -> int:
    if os.geteuid() != 0 or str(Path(sys.argv[0]).resolve()) != HELPER_PATH:
        raise RuntimeError("root activation helper must run from its installed immutable path")
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2 or arguments[0] not in {"activate", "rollback", "verify"}:
        raise RuntimeError("root activation helper command is invalid")
    raw = _frame(sys.stdin.buffer)
    value = json.loads(raw)
    if raw != _canonical(value):
        raise RuntimeError("activation capability is not canonical")
    capability = _validate_capability(value, arguments[1])
    _validate_python_invocation(capability, arguments[0], arguments[1])
    _load_root_authority(capability)
    if arguments[0] == "activate":
        _activate(capability, sys.stdin.buffer)
    elif arguments[0] == "rollback":
        _rollback(capability)
    else:
        _verify(capability)
    if sys.stdin.buffer.read(1):
        raise RuntimeError("activation capability stream contains trailing data")
    print(json.dumps({"status": "completed", "planDigest": arguments[1]}, sort_keys=True,
                     separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
