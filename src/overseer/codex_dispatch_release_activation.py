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
import signal
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping, Sequence

from .admin import AdminChangeKind, AdminChangePlan, AdminCommandStep
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
_HEX = frozenset("0123456789abcdef")


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


__all__ = [
    "ImmutableReleaseManifest", "ReleaseFile", "RELEASE_PLAN_SCHEMA", "RELEASE_SCHEMA",
    "assert_no_dbus_commands", "build_immutable_release_manifest",
    "plan_immutable_release_activation", "release_drop_in_content", "send_pinned_signal",
    "validate_sudo_install_argv", "verify_installed_release",
]
