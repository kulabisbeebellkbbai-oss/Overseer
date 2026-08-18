"""Immutable-release authority for structured Codex dispatch activation.

This module deliberately separates *staging* from effects.  Staging describes
the complete root-owned release and the exact privileged argv that an approved
executor may issue.  It never invokes sudo, systemctl, busctl, or a shell.

The vNext executor is intentionally built around two kernel identities: the
approved systemd --user manager pidfd and the existing Overseer API pidfd.  A
reload is SIGHUP to the pinned manager and a restart is SIGKILL to the pinned
API process, whose ``Restart=on-failure`` unit contract is part of the plan.
No D-Bus reply or pathname is activation authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import grp
import signal
import stat
import subprocess
import threading
import time
import urllib.request
from contextvars import ContextVar
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping, Sequence

from .admin import (
    AdminChangeKind, AdminChangePlan, AdminCommandResult, AdminCommandStep,
    AdminExecutionResult, AdminExecutionStatus,
)
from .core import ApprovalLevel, OwnerDomain, RiskLevel


RELEASE_SCHEMA = "overseer.codex-dispatch-release.v1"
RELEASE_PLAN_SCHEMA = "overseer.codex-dispatch-release-activation.v1"
CANONICAL_CHECKOUT = Path(__file__).resolve().parents[2]
DEPENDENCY_ROOT = Path(
    "/home/god/.local/share/overseer/venvs/"
    "psychlo-v1-1-cryptography-46.0.7-86d2f47/lib/python3.13/site-packages"
)
RELEASES_ROOT = Path("/opt/overseer/releases")
ROOT_PYTHON = Path("/usr/bin/python3")
SUDO = "/usr/bin/sudo"
INSTALL = "/usr/bin/install"
SERVICE_NAME = "overseer-api.service"
DROP_IN_RELATIVE_PATH = ".config/systemd/user/overseer-api.service.d/10-overseer-codex-dispatch.conf"
HEALTH_URL = "http://127.0.0.1:8766/health"
RELEASE_LAUNCHER = "app/src/overseer_codex_dispatch_release_launcher.py"
SOURCE_PREFIX = PurePosixPath("app")
DEPENDENCY_PREFIX = PurePosixPath("site-packages")
MANIFEST_NAME = "release-manifest.json"
UNIT_PATH = Path("/home/god/.config/systemd/user/overseer-api.service")
CGROUP_PATH = Path(
    f"/sys/fs/cgroup/user.slice/user-{os.geteuid()}.slice/"
    f"user@{os.geteuid()}.service/app.slice/{SERVICE_NAME}/cgroup.procs"
)
EXPECTED_CGROUP = (
    f"0::/user.slice/user-{os.geteuid()}.slice/user@{os.geteuid()}.service/"
    f"app.slice/{SERVICE_NAME}"
)
JOURNAL_SCHEMA = "overseer.codex-dispatch-release-journal.v1"
_HEX = frozenset("0123456789abcdef")
_EXECUTION_CONTEXT: ContextVar[tuple["ReleaseActivationSpec", str, str] | None] = ContextVar(
    "codex_dispatch_release_execution", default=None
)
_EXECUTION_MUTEX = threading.Lock()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _stable_read(path: Path, *, require_single_link: bool = True) -> tuple[bytes, os.stat_result]:
    lexical = path.lstat()
    if not stat.S_ISREG(lexical.st_mode) or path.is_symlink():
        raise ValueError(f"release input is not a regular non-symlink file: {path}")
    if require_single_link and lexical.st_nlink != 1:
        raise ValueError(f"release input is not single-link: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = lambda item: (
        item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns,
    )
    if identity(lexical) != identity(before) or identity(before) != identity(after):
        raise ValueError(f"release input changed during stable read: {path}")
    return b"".join(chunks), after


def _git(*args: str) -> bytes:
    completed = subprocess.run(
        ("/usr/bin/git", "--no-replace-objects", "-C", str(CANONICAL_CHECKOUT), *args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        },
    )
    if completed.returncode != 0:
        raise ValueError("reviewed Git object lookup failed")
    return completed.stdout


@dataclass(frozen=True, order=True)
class ReleaseFile:
    release_path: str
    source_kind: str
    source_path: str
    sha256: str
    size: int
    mode: int

    def __post_init__(self) -> None:
        relative = PurePosixPath(self.release_path)
        if relative.is_absolute() or ".." in relative.parts or str(relative) != self.release_path:
            raise ValueError("release file path must be canonical and relative")
        if self.source_kind not in {"checkout", "dependency"}:
            raise ValueError("release source kind is invalid")
        source = PurePosixPath(self.source_path)
        if source.is_absolute() or ".." in source.parts or str(source) != self.source_path:
            raise ValueError("release source path must be canonical and relative")
        if len(self.sha256) != 64 or not set(self.sha256) <= _HEX:
            raise ValueError("release file digest is invalid")
        if self.size < 0 or self.mode not in {0o444, 0o555}:
            raise ValueError("release file size or immutable mode is invalid")

    def to_json(self) -> dict[str, object]:
        return {
            "releasePath": self.release_path, "sourceKind": self.source_kind,
            "sourcePath": self.source_path, "sha256": self.sha256,
            "size": self.size, "mode": self.mode,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> "ReleaseFile":
        expected = {"releasePath", "sourceKind", "sourcePath", "sha256", "size", "mode"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("release file entry has an open or malformed schema")
        if not isinstance(value["size"], int) or isinstance(value["size"], bool):
            raise ValueError("release file size is invalid")
        if not isinstance(value["mode"], int) or isinstance(value["mode"], bool):
            raise ValueError("release file mode is invalid")
        return cls(
            str(value["releasePath"]), str(value["sourceKind"]), str(value["sourcePath"]),
            str(value["sha256"]), int(value["size"]), int(value["mode"]),
        )


@dataclass(frozen=True)
class ImmutableReleaseManifest:
    source_commit: str
    source_tree: str
    files: tuple[ReleaseFile, ...]
    root_python: Mapping[str, object]
    unit_contract_sha256: str

    def __post_init__(self) -> None:
        if len(self.source_commit) not in {40, 64} or not set(self.source_commit) <= _HEX:
            raise ValueError("release source commit is invalid")
        if len(self.source_tree) not in {40, 64} or not set(self.source_tree) <= _HEX:
            raise ValueError("release source tree is invalid")
        paths = [item.release_path for item in self.files]
        if not self.files or paths != sorted(set(paths)):
            raise ValueError("release file inventory must be nonempty, sorted, and unique")
        if RELEASE_LAUNCHER not in paths:
            raise ValueError("release launcher is absent from the reviewed release")
        python_keys = {
            "path", "resolvedPath", "entryDevice", "entryInode", "entryMode",
            "device", "inode", "mode", "links", "sha256", "size",
        }
        python = self.root_python
        if (not isinstance(python, Mapping) or set(python) != python_keys
                or python["path"] != str(ROOT_PYTHON)
                or not isinstance(python["resolvedPath"], str)
                or not str(python["resolvedPath"]).startswith("/usr/bin/python3")
                or any(not isinstance(python[name], int) or isinstance(python[name], bool) or int(python[name]) < 0
                       for name in ("entryDevice", "entryInode", "entryMode", "device", "inode", "mode", "links", "size"))
                or python["links"] != 1
                or not isinstance(python["sha256"], str) or len(str(python["sha256"])) != 64
                or not set(str(python["sha256"])) <= _HEX):
            raise ValueError("root Python manifest identity is malformed")
        if len(self.unit_contract_sha256) != 64 or not set(self.unit_contract_sha256) <= _HEX:
            raise ValueError("unit contract digest is invalid")

    def unsigned_json(self) -> dict[str, object]:
        return {
            "schemaVersion": RELEASE_SCHEMA, "sourceCommit": self.source_commit,
            "sourceTree": self.source_tree, "files": [item.to_json() for item in self.files],
            "rootPython": dict(self.root_python),
            "unitContractSha256": self.unit_contract_sha256,
        }

    @property
    def digest(self) -> str:
        return _sha256(_canonical(self.unsigned_json()))

    @property
    def release_root(self) -> Path:
        return RELEASES_ROOT / f"{self.source_commit}-{self.digest}"

    def to_json(self) -> dict[str, object]:
        return {**self.unsigned_json(), "manifestDigest": self.digest,
                "releaseRoot": str(self.release_root)}

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> "ImmutableReleaseManifest":
        expected = {
            "schemaVersion", "sourceCommit", "sourceTree", "files", "rootPython",
            "unitContractSha256", "manifestDigest", "releaseRoot",
        }
        if not isinstance(value, Mapping) or set(value) != expected or value["schemaVersion"] != RELEASE_SCHEMA:
            raise ValueError("immutable release manifest has an open or unsupported schema")
        raw_files = value["files"]
        if not isinstance(raw_files, list):
            raise ValueError("immutable release files are invalid")
        manifest = cls(
            str(value["sourceCommit"]), str(value["sourceTree"]),
            tuple(ReleaseFile.from_json(item) for item in raw_files),
            dict(value["rootPython"]) if isinstance(value["rootPython"], Mapping) else {},
            str(value["unitContractSha256"]),
        )
        if value["manifestDigest"] != manifest.digest or value["releaseRoot"] != str(manifest.release_root):
            raise ValueError("immutable release manifest digest or root is invalid")
        return manifest


@dataclass(frozen=True)
class ReleaseActivationSpec:
    manifest: ImmutableReleaseManifest
    manager_binding: Mapping[str, object]
    old_api_binding: Mapping[str, object]
    unit_contract: str

    def to_json(self) -> dict[str, object]:
        return {
            "schemaVersion": RELEASE_PLAN_SCHEMA,
            "manifest": self.manifest.to_json(),
            "managerBinding": dict(self.manager_binding),
            "oldApiBinding": dict(self.old_api_binding),
            "unitContract": self.unit_contract,
        }

    @classmethod
    def from_json(cls, value: Mapping[str, object]) -> "ReleaseActivationSpec":
        expected = {"schemaVersion", "manifest", "managerBinding", "oldApiBinding", "unitContract"}
        if not isinstance(value, Mapping) or set(value) != expected or value["schemaVersion"] != RELEASE_PLAN_SCHEMA:
            raise ValueError("release activation spec has an open or unsupported schema")
        if not isinstance(value["manifest"], Mapping) or not isinstance(value["managerBinding"], Mapping) or not isinstance(value["oldApiBinding"], Mapping):
            raise ValueError("release activation spec bindings are malformed")
        if not isinstance(value["unitContract"], str):
            raise ValueError("release activation unit contract is malformed")
        spec = cls(
            ImmutableReleaseManifest.from_json(value["manifest"]), dict(value["managerBinding"]),
            dict(value["oldApiBinding"]), value["unitContract"],
        )
        if _sha256(spec.unit_contract.encode()) != spec.manifest.unit_contract_sha256:
            raise ValueError("release activation unit contract digest changed")
        return spec


def _root_identity(path: Path) -> dict[str, object]:
    lexical = path.lstat()
    if lexical.st_uid != 0 or (not stat.S_ISLNK(lexical.st_mode) and stat.S_IMODE(lexical.st_mode) & 0o022):
        raise ValueError("root Python entry is not root-owned and immutable")
    resolved = path.resolve(strict=True)
    content, info = _stable_read(resolved)
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("root Python is not root-owned and immutable")
    return {
        "path": str(path), "resolvedPath": str(resolved),
        "entryDevice": lexical.st_dev, "entryInode": lexical.st_ino,
        "entryMode": stat.S_IMODE(lexical.st_mode),
        "device": info.st_dev, "inode": info.st_ino,
        "mode": stat.S_IMODE(info.st_mode), "links": info.st_nlink,
        "sha256": _sha256(content), "size": info.st_size,
    }


def _tracked_checkout_files() -> tuple[str, ...]:
    names = _git("ls-tree", "-r", "--name-only", "-z", "HEAD").split(b"\0")
    decoded = sorted(item.decode("utf-8", "strict") for item in names if item)
    if not decoded:
        raise ValueError("reviewed checkout inventory is empty")
    return tuple(decoded)


def _dependency_files() -> tuple[str, ...]:
    if not DEPENDENCY_ROOT.is_dir() or DEPENDENCY_ROOT.is_symlink():
        raise ValueError("fixed dependency root is unavailable or unsafe")
    result: list[str] = []
    for directory, directories, files in os.walk(DEPENDENCY_ROOT, followlinks=False):
        base = Path(directory)
        for name in directories:
            if (base / name).is_symlink():
                raise ValueError("dependency runtime contains a symlink")
        for name in files:
            path = base / name
            if path.is_symlink():
                raise ValueError("dependency runtime contains a symlink")
            result.append(path.relative_to(DEPENDENCY_ROOT).as_posix())
    if not result:
        raise ValueError("complete dependency runtime is empty")
    return tuple(sorted(result))


def _manifest_file(source_kind: str, relative: str) -> ReleaseFile:
    root = CANONICAL_CHECKOUT if source_kind == "checkout" else DEPENDENCY_ROOT
    prefix = SOURCE_PREFIX if source_kind == "checkout" else DEPENDENCY_PREFIX
    content, info = _stable_read(root / relative)
    mode = 0o555 if stat.S_IMODE(info.st_mode) & 0o111 else 0o444
    return ReleaseFile((prefix / relative).as_posix(), source_kind, relative, _sha256(content), len(content), mode)


def build_immutable_release_manifest(*, unit_contract: bytes) -> ImmutableReleaseManifest:
    """Build a closed manifest only from the fixed reviewed roots."""
    commit = _git("rev-parse", "HEAD").strip().decode().lower()
    tree = _git("rev-parse", "HEAD^{tree}").strip().decode().lower()
    if _git("status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("reviewed checkout has tracked changes")
    files = tuple(sorted(
        (_manifest_file("checkout", item) for item in _tracked_checkout_files()),
        key=lambda item: item.release_path,
    ) + sorted(
        (_manifest_file("dependency", item) for item in _dependency_files()),
        key=lambda item: item.release_path,
    ))
    # Close the read/manifest race by checking the tracked state again.
    if _git("rev-parse", "HEAD").strip().decode().lower() != commit or _git(
        "rev-parse", "HEAD^{tree}"
    ).strip().decode().lower() != tree or _git("status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("reviewed checkout changed while building release manifest")
    return ImmutableReleaseManifest(commit, tree, files, _root_identity(ROOT_PYTHON), _sha256(unit_contract))


def release_drop_in_content(manifest: ImmutableReleaseManifest) -> bytes:
    root = manifest.release_root
    command = (
        str(ROOT_PYTHON), "-I", "-S", str(root / RELEASE_LAUNCHER),
        "--release-root", str(root), "--manifest", str(root / MANIFEST_NAME),
        "--manifest-digest", manifest.digest, "--", "serve-api", "--store",
        "/home/god/.local/share/overseer/project/state/overseer.sqlite3",
        "--host", "127.0.0.1", "--port", "8766", "--auth-token-file",
        "/home/god/.local/share/overseer/project/state/api-token",
    )
    # All arguments are closed constants or hex/path components without systemd
    # metacharacters.  Reject instead of quoting an unexpected value.
    if any(not item or any(character.isspace() or character in "\\\"'`$;" for character in item) for item in command):
        raise ValueError("release service argv contains an unsafe systemd token")
    return (
        "[Service]\nEnvironment=OVERSEER_CODEX_APP_SERVER_DISPATCH=1\n"
        "Environment=PYTHONPATH=\nExecStart=\nExecStart=" + " ".join(command) + "\n"
    ).encode()


def _install_commands(manifest: ImmutableReleaseManifest) -> tuple[tuple[str, ...], ...]:
    release_root = manifest.release_root
    directories = {RELEASES_ROOT.parent, RELEASES_ROOT, release_root}
    for item in manifest.files:
        destination = release_root / item.release_path
        directories.update(destination.parents)
    directories = {path for path in directories if path == release_root or release_root in path.parents}
    commands: list[tuple[str, ...]] = []
    for directory in sorted(directories, key=lambda item: (len(item.parts), str(item))):
        commands.append((SUDO, "-n", INSTALL, "-d", "-o", "root", "-g", "root", "-m", "0555", str(directory)))
    for item in manifest.files:
        source_root = CANONICAL_CHECKOUT if item.source_kind == "checkout" else DEPENDENCY_ROOT
        commands.append((
            SUDO, "-n", INSTALL, "-o", "root", "-g", "root", "-m", format(item.mode, "04o"),
            str(source_root / item.source_path), str(release_root / item.release_path),
        ))
    staging = Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local/state/overseer/codex-dispatch" / f"{manifest.digest}.release-manifest.json"
    commands.append((SUDO, "-n", INSTALL, "-o", "root", "-g", "root", "-m", "0444", str(staging), str(release_root / MANIFEST_NAME)))
    return tuple(commands)


def plan_immutable_release_activation(
    plan_id: str,
    reason: str,
    manifest: ImmutableReleaseManifest,
    *,
    manager_binding: Mapping[str, object],
    unit_contract: bytes,
    current_state: str = "mutable checkout service",
) -> AdminChangePlan:
    """Create the exact HIGH/HUMAN/SISKO plan; this function has no effects."""
    if not plan_id.strip() or not reason.strip():
        raise ValueError("plan id and reason are required")
    if _sha256(unit_contract) != manifest.unit_contract_sha256:
        raise ValueError("pre-attested restart unit contract is not manifest-bound")
    drop_in = release_drop_in_content(manifest)
    commands = _install_commands(manifest)
    metadata = {
        "schemaVersion": RELEASE_PLAN_SCHEMA,
        "manifest": manifest.to_json(),
        "managerBinding": dict(manager_binding),
        "rootInstallCommands": [list(command) for command in commands],
        "dropInSha256": _sha256(drop_in),
        "dropInContent": drop_in.decode("ascii"),
        "unitContractSha256": _sha256(unit_contract),
        "lifecycle": {
            "reload": "pidfd_send_signal(manager,SIGHUP)",
            "restart": "pidfd_send_signal(oldOverseerApi,SIGKILL)",
            "proof": "new-pid-startticks-cgroup-cmdline-cwd-health",
            "dbusAuthority": False,
        },
        "rollback": {
            "release": "retain inert immutable release for audited cleanup",
            "dropIn": "quarantine exact operation-owned drop-in",
            "service": "SIGHUP pinned manager then SIGKILL current release API and attest restored API",
        },
    }
    digest = _sha256(_canonical(metadata))
    marker = lambda name: ("__overseer_codex_dispatch_release_v1", name, plan_id, digest)
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION,
        owner_domain=OwnerDomain.SISKO,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=SERVICE_NAME,
        reason=reason,
        current_state=current_state,
        proposed_state=f"root-owned immutable reviewed release {manifest.release_root}",
        steps=(
            AdminCommandStep("Install approved immutable release", marker("install-release"), "issue only the manifest-bound sudo install argv after approval"),
            AdminCommandStep("Install exact user service drop-in", marker("install-drop-in"), "atomically install the approved service binding"),
            AdminCommandStep("Reload pinned user manager", marker("reload-manager"), "send SIGHUP through the approved live manager pidfd"),
            AdminCommandStep("Restart pinned Overseer API", marker("restart-api"), "SIGKILL the attested old API pid and require Restart=on-failure replacement"),
        ),
        rollback_steps=(AdminCommandStep("Rollback exact release activation", marker("rollback"), "quarantine only operation-owned active files and restore the prior service"),),
        risks=(
            "root-owned files are installed under the exact approved release path",
            "Overseer API is force-stopped and must be restarted by the pre-attested unit policy",
            "manager drift, partial install, timeout, or process mismatch causes rollback",
        ),
        verification_steps=(
            AdminCommandStep("Verify immutable root release", marker("verify-release"), "verify every root-owned directory and stable single-link file digest"),
            AdminCommandStep("Verify replacement process", marker("verify-api"), "verify new pid, startticks, cgroup, argv, cwd, mapped source roots, and health"),
            AdminCommandStep("Verify local Codex proxy", marker("verify-proxy"), "verify local structured dispatch without remote control"),
        ),
        adapter_metadata=metadata,
    )


def validate_sudo_install_argv(command: Sequence[str], manifest: ImmutableReleaseManifest) -> None:
    if tuple(command) not in _install_commands(manifest):
        raise ValueError("privileged command is outside the approved sudo install allowlist")
    if tuple(command[:3]) != (SUDO, "-n", INSTALL):
        raise ValueError("privileged command must use fixed sudo -n install argv")


def verify_installed_release(manifest: ImmutableReleaseManifest) -> None:
    root_info = manifest.release_root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or manifest.release_root.is_symlink()
            or root_info.st_uid != 0 or root_info.st_gid != 0
            or stat.S_IMODE(root_info.st_mode) & 0o222):
        raise ValueError("release root is not root-owned and immutable")
    for item in manifest.files:
        path = manifest.release_root / item.release_path
        content, info = _stable_read(path)
        if (info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != item.mode
                or len(content) != item.size or _sha256(content) != item.sha256):
            raise ValueError(f"installed release file does not match manifest: {item.release_path}")
        current = path.parent
        while current != manifest.release_root.parent:
            directory = current.lstat()
            if (not stat.S_ISDIR(directory.st_mode) or current.is_symlink()
                    or directory.st_uid != 0 or directory.st_gid != 0
                    or stat.S_IMODE(directory.st_mode) & 0o222):
                raise ValueError(f"installed release directory is unsafe: {current}")
            if current == manifest.release_root:
                break
            current = current.parent
    manifest_content, manifest_info = _stable_read(manifest.release_root / MANIFEST_NAME)
    if (manifest_info.st_uid != 0 or manifest_info.st_gid != 0 or manifest_info.st_nlink != 1
            or stat.S_IMODE(manifest_info.st_mode) != 0o444
            or manifest_content != _canonical(manifest.to_json()) + b"\n"):
        raise ValueError("installed release manifest is not exact root-owned immutable data")


def send_pinned_signal(pidfd: int, expected_pid: int, signum: signal.Signals) -> None:
    """Signal only a caller-attested live pidfd; never rediscover by pathname."""
    if not isinstance(pidfd, int) or pidfd < 0 or not isinstance(expected_pid, int) or expected_pid <= 1:
        raise ValueError("pinned process identity is invalid")
    if signum not in {signal.SIGHUP, signal.SIGKILL}:
        raise ValueError("activation signal is outside the closed lifecycle contract")
    signal.pidfd_send_signal(pidfd, signum)


def assert_no_dbus_commands(commands: Iterable[Sequence[str]]) -> None:
    for command in commands:
        if command and Path(command[0]).name in {"busctl", "systemctl"}:
            raise ValueError("D-Bus and systemctl commands are not activation authority")


def _unit_contract() -> bytes:
    content, info = _stable_read(UNIT_PATH)
    private_group = False
    if info.st_gid == pwd.getpwuid(os.geteuid()).pw_gid:
        group = grp.getgrgid(info.st_gid)
        same_gid_users = [entry.pw_uid for entry in pwd.getpwall() if entry.pw_gid == info.st_gid]
        private_group = same_gid_users == [os.geteuid()] and set(group.gr_mem) <= {pwd.getpwuid(os.geteuid()).pw_name}
    mode = stat.S_IMODE(info.st_mode)
    if (info.st_uid != os.geteuid() or mode & 0o002
            or (mode & 0o020 and not private_group)):
        raise ValueError("Overseer API unit is not an owner-controlled immutable approval input")
    text = content.decode("utf-8", "strict")
    if "\nRestart=on-failure\n" not in f"\n{text}":
        raise ValueError("Overseer API unit is not pre-attested Restart=on-failure")
    return content


def _proc_bytes(pid: int, name: str) -> bytes:
    path = Path(f"/proc/{pid}/{name}")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks: list[bytes] = []
        while True:
            value = os.read(fd, 1024 * 1024)
            if not value:
                break
            chunks.append(value)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _proc_start_ticks(pid: int) -> int:
    value = _proc_bytes(pid, "stat").decode("ascii", "strict")
    end = value.rfind(")")
    if end < 0:
        raise ValueError("process stat is malformed")
    return int(value[end + 2:].split()[19])


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if not value:
        raise ValueError("kernel boot identity is unavailable")
    return value


def _api_pid_from_cgroup() -> int:
    content = CGROUP_PATH.read_text(encoding="ascii")
    pids = [int(item) for item in content.splitlines() if item]
    if len(pids) != 1 or pids[0] <= 1:
        raise ValueError("Overseer API cgroup does not contain exactly one process")
    return pids[0]


def _capture_api_binding(pid: int | None = None) -> dict[str, object]:
    pid = _api_pid_from_cgroup() if pid is None else pid
    pidfd = os.pidfd_open(pid, 0)
    try:
        binding = {
            "bootId": _boot_id(), "pid": pid, "startTicks": _proc_start_ticks(pid),
            "cgroup": _proc_bytes(pid, "cgroup").decode("ascii", "strict").strip(),
            "cmdlineHex": _proc_bytes(pid, "cmdline").hex(),
            "cwd": os.readlink(f"/proc/{pid}/cwd"),
        }
        if binding["cgroup"] != EXPECTED_CGROUP:
            raise ValueError("Overseer API process is outside the exact service cgroup")
        if _proc_start_ticks(pid) != binding["startTicks"] or _boot_id() != binding["bootId"]:
            raise ValueError("Overseer API process changed during attestation")
        return binding
    finally:
        os.close(pidfd)


def _capture_manager_binding() -> dict[str, object]:
    # SO_PEERCRED is used only to identify and pin the user manager.  No D-Bus
    # request or reply is ever used as an effect or proof.
    from .codex_dispatch_activation import _capture_user_bus_peer_binding

    return dict(_capture_user_bus_peer_binding())


def build_codex_dispatch_activation_spec() -> ReleaseActivationSpec:
    unit = _unit_contract()
    return ReleaseActivationSpec(
        build_immutable_release_manifest(unit_contract=unit),
        _capture_manager_binding(), _capture_api_binding(), unit.decode("utf-8", "strict"),
    )


def plan_codex_dispatch_activation(
    plan_id: str,
    spec: ReleaseActivationSpec,
    reason: str,
    current_state: str = "mutable checkout service",
) -> AdminChangePlan:
    plan = plan_immutable_release_activation(
        plan_id, reason, spec.manifest, manager_binding=spec.manager_binding,
        unit_contract=spec.unit_contract.encode(), current_state=current_state,
    )
    metadata = dict(plan.adapter_metadata)
    metadata["spec"] = spec.to_json()
    metadata["specDigest"] = _sha256(_canonical(spec.to_json()))
    plan_digest = _sha256(_canonical(metadata))
    def rebind(step: AdminCommandStep) -> AdminCommandStep:
        if len(step.command) != 4 or step.command[0] != "__overseer_codex_dispatch_release_v1":
            raise ValueError("release activation plan contains a noncanonical marker")
        return replace(step, command=(*step.command[:3], plan_digest))
    return replace(
        plan, adapter_metadata=metadata,
        steps=tuple(rebind(step) for step in plan.steps),
        rollback_steps=tuple(rebind(step) for step in plan.rollback_steps),
        verification_steps=tuple(rebind(step) for step in plan.verification_steps),
    )


def _normalize_plan(plan: AdminChangePlan) -> AdminChangePlan:
    return replace(
        plan, approved=False, approved_by=None, approved_at=None, canceled=False,
        canceled_by=None, canceled_at=None, cancellation_reason=None, archived=False,
        archived_by=None, archived_at=None, archive_record_id=None,
    )


def validate_codex_dispatch_activation_plan(plan: AdminChangePlan) -> ReleaseActivationSpec:
    if AdminChangeKind(plan.kind) != AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION:
        raise ValueError("plan is not a Codex dispatch activation plan")
    metadata = plan.adapter_metadata
    if not isinstance(metadata, dict) or not isinstance(metadata.get("spec"), dict):
        raise ValueError("release activation plan spec is absent")
    spec = ReleaseActivationSpec.from_json(metadata["spec"])
    if metadata.get("specDigest") != _sha256(_canonical(spec.to_json())):
        raise ValueError("release activation plan spec digest changed")
    canonical = plan_codex_dispatch_activation(plan.id, spec, plan.reason, plan.current_state)
    if _normalize_plan(plan) != canonical:
        raise ValueError("release activation plan is not exact and canonical")
    return spec


def verify_reviewed_source_binding(spec: ReleaseActivationSpec) -> None:
    """Pre-effect verification of the approved checkout/dependency inputs."""
    current = build_immutable_release_manifest(unit_contract=spec.unit_contract.encode())
    if current != spec.manifest:
        raise ValueError("approved immutable release inputs changed; restage approval")
    if _unit_contract().decode("utf-8", "strict") != spec.unit_contract:
        raise ValueError("approved service unit contract changed; restage approval")
    if _capture_manager_binding() != dict(spec.manager_binding):
        raise ValueError("approved user manager changed; restage approval")
    if _capture_api_binding() != dict(spec.old_api_binding):
        raise ValueError("approved existing Overseer API changed; restage approval")


def _state_root() -> Path:
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local/state/overseer/codex-dispatch-release"


def _journal_path(plan_id: str) -> Path:
    safe = hashlib.sha256(plan_id.encode()).hexdigest()
    return _state_root() / f"{safe}.journal.json"


def _atomic_owner_write(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or path.parent.is_symlink() or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise ValueError("release activation state directory is unsafe")
    temporary = path.parent / f".{path.name}.{os.getpid()}.{threading.get_ident()}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        os.write(fd, content)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _load_journal(plan_id: str, spec_digest: str) -> dict[str, object] | None:
    path = _journal_path(plan_id)
    if not path.exists():
        return None
    content, info = _stable_read(path)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("release activation journal is unsafe")
    value = json.loads(content)
    expected = {
        "schemaVersion", "planId", "specDigest", "phase", "installedCommands",
        "releaseOwnership", "dropInOwnership", "dropInQuarantine", "lastError",
    }
    phases = {
        "install-intent", "release-installed", "dropin-intent", "dropin-installed",
        "reload-intent", "reloaded", "restart-intent", "restarted", "verified",
        "rollback-pending", "rolled-back",
    }
    if (not isinstance(value, dict) or set(value) != expected or value["schemaVersion"] != JOURNAL_SCHEMA
            or value["planId"] != plan_id or value["specDigest"] != spec_digest
            or value["phase"] not in phases or value["releaseOwnership"] not in {"install-issued", "operation-owned", "inert-partial"}
            or value["dropInOwnership"] not in {"absent", "write-issued", "operation-owned", "preexisting", "quarantined"}
            or not isinstance(value["installedCommands"], int)):
        raise ValueError("release activation journal schema or authority is invalid")
    return value


def _write_journal(value: Mapping[str, object]) -> None:
    _atomic_owner_write(_journal_path(str(value["planId"])), _canonical(value) + b"\n")


def _new_journal(plan_id: str, spec_digest: str) -> dict[str, object]:
    return {
        "schemaVersion": JOURNAL_SCHEMA, "planId": plan_id, "specDigest": spec_digest,
        "phase": "install-intent", "installedCommands": 0,
        "releaseOwnership": "install-issued", "dropInOwnership": "absent",
        "dropInQuarantine": "", "lastError": "",
    }


def _drop_in_path() -> Path:
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / DROP_IN_RELATIVE_PATH


def _manifest_staging_path(manifest: ImmutableReleaseManifest) -> Path:
    return Path(pwd.getpwuid(os.geteuid()).pw_dir) / ".local/state/overseer/codex-dispatch" / f"{manifest.digest}.release-manifest.json"


def _stage_manifest_file(manifest: ImmutableReleaseManifest) -> None:
    path = _manifest_staging_path(manifest)
    content = _canonical(manifest.to_json()) + b"\n"
    if path.exists():
        existing, info = _stable_read(path)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or existing != content:
            raise ValueError("release manifest staging file is unsafe or mismatched")
        return
    _atomic_owner_write(path, content)


def _run_install(command: Sequence[str], manifest: ImmutableReleaseManifest) -> None:
    validate_sudo_install_argv(command, manifest)
    completed = subprocess.run(
        tuple(command), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError("approved root release install command failed")


def _install_release(plan_id: str, spec: ReleaseActivationSpec, digest: str) -> str:
    journal = _load_journal(plan_id, digest) or _new_journal(plan_id, digest)
    if journal["phase"] == "rolled-back":
        raise ValueError("approved release activation plan is terminal after rollback")
    _stage_manifest_file(spec.manifest)
    commands = _install_commands(spec.manifest)
    journal["phase"] = "install-intent"
    _write_journal(journal)
    for index, command in enumerate(commands):
        if index < int(journal["installedCommands"]):
            continue
        _run_install(command, spec.manifest)
        journal["installedCommands"] = index + 1
        journal["releaseOwnership"] = "operation-owned"
        _write_journal(journal)
    verify_installed_release(spec.manifest)
    journal["phase"] = "release-installed"
    _write_journal(journal)
    return "approved immutable root release installed and verified"


def _install_drop_in(plan_id: str, spec: ReleaseActivationSpec, digest: str) -> str:
    journal = _load_journal(plan_id, digest)
    if journal is None or journal["phase"] not in {"release-installed", "dropin-intent"}:
        raise ValueError("immutable release must be installed before the service drop-in")
    path = _drop_in_path()
    content = release_drop_in_content(spec.manifest)
    prior_write_intent = (
        journal["phase"] == "dropin-intent" and journal["dropInOwnership"] == "write-issued"
    )
    existed_before_intent = path.exists()
    journal["phase"] = "dropin-intent"
    journal["dropInOwnership"] = "write-issued"
    _write_journal(journal)
    if path.exists():
        existing, info = _stable_read(path)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or existing != content:
            raise ValueError("existing dispatch drop-in is not the exact secure approved file")
        journal["dropInOwnership"] = (
            "operation-owned" if prior_write_intent or not existed_before_intent else "preexisting"
        )
    else:
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        journal["dropInOwnership"] = "operation-owned"
    journal["phase"] = "dropin-installed"
    _write_journal(journal)
    return "exact operation-bound user service drop-in installed"


def _manager_pidfd(spec: ReleaseActivationSpec) -> tuple[int, int]:
    binding = _capture_manager_binding()
    if binding != dict(spec.manager_binding):
        raise ValueError("approved user manager identity drifted")
    pid = int(binding["peerPid"])
    return pid, os.pidfd_open(pid, 0)


def _api_pidfd(binding: Mapping[str, object]) -> tuple[int, int]:
    current = _capture_api_binding()
    if current != dict(binding):
        raise ValueError("approved Overseer API identity drifted")
    pid = int(current["pid"])
    return pid, os.pidfd_open(pid, 0)


def _wait_for_api(predicate: Callable[[Mapping[str, object]], bool], *, old_pid: int, timeout: float = 30.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            binding = _capture_api_binding()
            if int(binding["pid"]) != old_pid and predicate(binding):
                return binding
        except (OSError, ValueError) as error:
            last_error = error
        time.sleep(0.1)
    raise RuntimeError("Overseer API replacement was not observed within the approved bound") from last_error


def _expected_release_cmdline(spec: ReleaseActivationSpec) -> bytes:
    drop_in = release_drop_in_content(spec.manifest).decode("ascii")
    line = next(item for item in drop_in.splitlines() if item.startswith("ExecStart=/usr/bin/python3"))
    return b"\0".join(item.encode() for item in line[len("ExecStart="):].split(" ")) + b"\0"


def _attest_release_api(spec: ReleaseActivationSpec, binding: Mapping[str, object]) -> None:
    if bytes.fromhex(str(binding["cmdlineHex"])) != _expected_release_cmdline(spec):
        raise ValueError("replacement Overseer API argv is not the approved immutable release command")
    if binding["cwd"] != str(spec.manifest.release_root):
        raise ValueError("replacement Overseer API cwd is not the immutable release")
    pid = int(binding["pid"])
    for line in _proc_bytes(pid, "maps").decode("utf-8", "replace").splitlines():
        fields = line.split()
        if not fields or not fields[-1].startswith("/"):
            continue
        mapped = Path(fields[-1])
        if str(mapped).startswith(str(CANONICAL_CHECKOUT)) or str(mapped).startswith(str(DEPENDENCY_ROOT)):
            raise ValueError("replacement API maps mutable checkout or dependency code")
        if str(mapped).startswith(str(spec.manifest.release_root)):
            info = mapped.lstat()
            if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o222:
                raise ValueError("replacement API mapped an unsafe release file")
    with urllib.request.urlopen(HEALTH_URL, timeout=5) as response:
        if response.status != 200:
            raise ValueError("replacement Overseer API health check failed")


def _reload(plan_id: str, spec: ReleaseActivationSpec, digest: str) -> str:
    journal = _load_journal(plan_id, digest)
    if journal is None or journal["phase"] not in {"dropin-installed", "reload-intent"}:
        raise ValueError("exact drop-in must be installed before manager reload")
    journal["phase"] = "reload-intent"
    _write_journal(journal)
    manager_pid, pidfd = _manager_pidfd(spec)
    try:
        send_pinned_signal(pidfd, manager_pid, signal.SIGHUP)
        time.sleep(0.2)
        if _capture_manager_binding() != dict(spec.manager_binding):
            raise ValueError("user manager changed across SIGHUP reload")
    finally:
        os.close(pidfd)
    journal["phase"] = "reloaded"
    _write_journal(journal)
    return "pinned user manager reloaded by pidfd SIGHUP"


def _restart(plan_id: str, spec: ReleaseActivationSpec, digest: str) -> str:
    journal = _load_journal(plan_id, digest)
    if journal is None or journal["phase"] not in {"reloaded", "restart-intent"}:
        raise ValueError("pinned manager reload must complete before API restart")
    journal["phase"] = "restart-intent"
    _write_journal(journal)
    old_pid, pidfd = _api_pidfd(spec.old_api_binding)
    try:
        send_pinned_signal(pidfd, old_pid, signal.SIGKILL)
    finally:
        os.close(pidfd)
    replacement = _wait_for_api(lambda value: True, old_pid=old_pid)
    _attest_release_api(spec, replacement)
    if _capture_manager_binding() != dict(spec.manager_binding):
        raise ValueError("user manager changed across API replacement")
    journal["phase"] = "restarted"
    _write_journal(journal)
    return "Overseer API replaced and attested from immutable release"


def _quarantine_dropin(journal: dict[str, object]) -> None:
    if journal["dropInOwnership"] not in {"write-issued", "operation-owned"}:
        return
    path = _drop_in_path()
    if not path.exists():
        journal["dropInOwnership"] = "quarantined"
        return
    quarantine = path.parent / f".{path.name}.{journal['specDigest']}.rollback-inert"
    if quarantine.exists():
        raise ValueError("rollback quarantine already exists unexpectedly")
    os.rename(path, quarantine)
    journal["dropInOwnership"] = "quarantined"
    journal["dropInQuarantine"] = str(quarantine)


def _rollback(plan_id: str, spec: ReleaseActivationSpec, digest: str) -> str:
    journal = _load_journal(plan_id, digest)
    if journal is None:
        return "no operation-owned release activation effects exist"
    if journal["phase"] == "rolled-back":
        return "release activation already rolled back"
    prior_phase = str(journal["phase"])
    journal["phase"] = "rollback-pending"
    _write_journal(journal)
    try:
        _quarantine_dropin(journal)
        if int(journal["installedCommands"]) < len(_install_commands(spec.manifest)):
            journal["releaseOwnership"] = "inert-partial"
        _write_journal(journal)
        manager_pid, manager_fd = _manager_pidfd(spec)
        try:
            send_pinned_signal(manager_fd, manager_pid, signal.SIGHUP)
            time.sleep(0.2)
        finally:
            os.close(manager_fd)
        needs_restored_api = prior_phase in {"restart-intent", "restarted", "rollback-pending"}
        try:
            current = _capture_api_binding()
        except (OSError, ValueError):
            current = None
        if current is not None and str(current["cwd"]) == str(spec.manifest.release_root):
            current_pid = int(current["pid"])
            current_fd = os.pidfd_open(current_pid, 0)
            try:
                send_pinned_signal(current_fd, current_pid, signal.SIGKILL)
            finally:
                os.close(current_fd)
            restored = _wait_for_api(
                lambda value: value["cmdlineHex"] == spec.old_api_binding["cmdlineHex"] and value["cwd"] == spec.old_api_binding["cwd"],
                old_pid=current_pid,
            )
            if restored["cgroup"] != EXPECTED_CGROUP:
                raise ValueError("restored Overseer API cgroup is invalid")
            current = restored
        elif current is None and needs_restored_api:
            current = _wait_for_api(
                lambda value: value["cmdlineHex"] == spec.old_api_binding["cmdlineHex"] and value["cwd"] == spec.old_api_binding["cwd"],
                old_pid=int(spec.old_api_binding["pid"]),
            )
        if current is not None and str(current["cwd"]) != str(spec.manifest.release_root):
            if (current["cmdlineHex"] != spec.old_api_binding["cmdlineHex"]
                    or current["cwd"] != spec.old_api_binding["cwd"]):
                raise ValueError("rollback did not restore the approved prior API command")
        if _capture_manager_binding() != dict(spec.manager_binding):
            raise ValueError("manager changed during rollback")
        journal["phase"] = "rolled-back"
        journal["lastError"] = ""
        _write_journal(journal)
        return "release activation rolled back; root release retained inert for audited cleanup"
    except Exception as error:
        journal["phase"] = "rollback-pending"
        journal["lastError"] = type(error).__name__
        _write_journal(journal)
        raise


def _parse_marker(command: Sequence[str]) -> tuple[str, str, ReleaseActivationSpec, str]:
    if len(command) != 4 or command[0] != "__overseer_codex_dispatch_release_v1":
        raise ValueError("release activation marker is malformed")
    operation, plan_id, digest = command[1:]
    context = _EXECUTION_CONTEXT.get()
    if context is None or context[1] != plan_id or context[2] != digest:
        raise ValueError("release activation marker lacks exact active plan authority")
    spec = context[0]
    return operation, plan_id, spec, digest


def execute_codex_dispatch_activation_marker(command: Sequence[str]) -> tuple[int, str, str]:
    try:
        operation, plan_id, spec, digest = _parse_marker(command)
        if operation == "install-release":
            return 0, _install_release(plan_id, spec, digest), ""
        if operation == "install-drop-in":
            return 0, _install_drop_in(plan_id, spec, digest), ""
        if operation == "reload-manager":
            return 0, _reload(plan_id, spec, digest), ""
        if operation == "restart-api":
            return 0, _restart(plan_id, spec, digest), ""
        if operation == "rollback":
            return 0, _rollback(plan_id, spec, digest), ""
        if operation == "verify-release":
            verify_installed_release(spec.manifest)
            return 0, "immutable release verified", ""
        if operation == "verify-api":
            binding = _capture_api_binding()
            _attest_release_api(spec, binding)
            return 0, "immutable release API verified", ""
        if operation == "verify-proxy":
            from .codex_dispatch_activation import _probe_proxy
            _probe_proxy()
            journal = _load_journal(plan_id, digest)
            if journal is not None:
                journal["phase"] = "verified"
                _write_journal(journal)
            return 0, "local Codex proxy verified", ""
        raise ValueError("release activation marker operation is unsupported")
    except Exception as error:
        return 1, "", f"release activation operation failed: {type(error).__name__}: {error}"


def execute_codex_dispatch_activation_plan(
    plan: AdminChangePlan,
    *,
    runner: Callable[[AdminCommandStep], AdminCommandResult] | None = None,
    adapter_enabled: bool = False,
) -> AdminExecutionResult:
    if not adapter_enabled:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, "exact approved adapter enablement is required", ())
    try:
        spec = validate_codex_dispatch_activation_plan(plan)
    except (OSError, ValueError) as error:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, str(error), ())
    if not plan.approved or plan.canceled or plan.archived:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, "release activation requires an uncanceled HUMAN-approved plan", ())
    digest = str(plan.steps[0].command[3])
    journal = _load_journal(plan.id, digest)
    if journal is not None and journal["phase"] in {"rolled-back", "verified"}:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, "approved release activation plan is terminal and cannot be reused", ())
    try:
        verify_reviewed_source_binding(spec)
    except (OSError, ValueError) as error:
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, str(error), ())
    if not _EXECUTION_MUTEX.acquire(blocking=False):
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, "another release activation owns the lifecycle", ())
    from .codex_dispatch_activation import _activation_lock
    lock_context = _activation_lock()
    try:
        validate_lock = lock_context.__enter__()
    except Exception as error:
        _EXECUTION_MUTEX.release()
        return AdminExecutionResult(f"admin.exec.{plan.id}.blocked", plan.id, AdminExecutionStatus.BLOCKED, f"stable activation lock unavailable: {error}", ())
    token = _EXECUTION_CONTEXT.set((spec, plan.id, digest))
    try:
        if runner is None:
            runner = lambda step: AdminCommandResult(step.title, step.command, *execute_codex_dispatch_activation_marker(step.command))
        commands: list[AdminCommandResult] = []
        for step in plan.steps:
            validate_lock()
            try:
                result = runner(step)
            except Exception as error:
                result = AdminCommandResult(step.title, step.command, 1, stderr=type(error).__name__)
            commands.append(result)
            validate_lock()
            if result.exit_code != 0:
                rollback = tuple(runner(item) for item in plan.rollback_steps)
                return AdminExecutionResult(f"admin.exec.{plan.id}.failed", plan.id, AdminExecutionStatus.FAILED, f"immutable release activation failed during {step.title}; rollback attempted", tuple(commands), rollback_results=rollback)
        verification: list[AdminCommandResult] = []
        for step in plan.verification_steps:
            validate_lock()
            result = runner(step)
            validate_lock()
            verification.append(result)
            if result.exit_code != 0:
                rollback = tuple(runner(item) for item in plan.rollback_steps)
                return AdminExecutionResult(f"admin.exec.{plan.id}.failed", plan.id, AdminExecutionStatus.FAILED, f"immutable release verification failed during {step.title}; rollback attempted", tuple(commands), tuple(verification), rollback)
        return AdminExecutionResult(f"admin.exec.{plan.id}.completed", plan.id, AdminExecutionStatus.COMPLETED, "approved immutable Codex dispatch release activated and verified", tuple(commands), tuple(verification))
    finally:
        _EXECUTION_CONTEXT.reset(token)
        lock_context.__exit__(None, None, None)
        _EXECUTION_MUTEX.release()


def require_isolated_activation_entry() -> None:
    # The production CLI remains entered through the reviewed isolated wrapper.
    from .codex_dispatch_activation import require_isolated_activation_entry as legacy_gate
    legacy_gate()


__all__ = [
    "ImmutableReleaseManifest", "ReleaseActivationSpec", "ReleaseFile", "RELEASE_PLAN_SCHEMA", "RELEASE_SCHEMA",
    "assert_no_dbus_commands", "build_immutable_release_manifest",
    "build_codex_dispatch_activation_spec", "execute_codex_dispatch_activation_marker",
    "execute_codex_dispatch_activation_plan", "plan_codex_dispatch_activation",
    "plan_immutable_release_activation", "release_drop_in_content", "require_isolated_activation_entry",
    "send_pinned_signal", "validate_codex_dispatch_activation_plan", "verify_reviewed_source_binding",
    "validate_sudo_install_argv", "verify_installed_release",
]
