"""Stdlib-only isolated trust launcher for reviewed Overseer dispatch.

Invoke this file directly with a fixed interpreter using ``-I -S``.  It does
not import checkout or site code until the complete reviewed source binding is
verified.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import json
import os
import stat
import subprocess
import sys
from pathlib import Path


SCHEMA = "overseer.codex-dispatch-activation.v4"
SERVICE_NAME = "overseer-api.service"
DROP_IN_RELATIVE_PATH = ".config/systemd/user/overseer-api.service.d/10-overseer-codex-dispatch.conf"
DAEMON_SOCKET = "app-server-control/app-server-control.sock"
HEALTH_URL = "http://127.0.0.1:8766/health"
EXECUTABLE_SUFFIXES = tuple(dict.fromkeys(
    (".py", ".pyc", ".pyd", *importlib.machinery.EXTENSION_SUFFIXES)
))
DEPENDENCY_EXECUTABLE_SUFFIXES = tuple(dict.fromkeys(
    (".py", ".pyd", *importlib.machinery.EXTENSION_SUFFIXES)
))
ALLOWED_ACTIVATION_COMMANDS = {
    "stage-codex-dispatch-activation",
    "codex-dispatch-activation-status",
    "execute-codex-dispatch-activation",
}
SERVICE_PAYLOAD = (
    "serve-api", "--store", "/home/god/.local/share/overseer/project/state/overseer.sqlite3",
    "--host", "127.0.0.1", "--port", "8766", "--auth-token-file",
    "/home/god/.local/share/overseer/project/state/api-token",
)
SERVICE_STORE = "/home/god/.local/share/overseer/project/state/overseer.sqlite3"


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("/usr/bin/git", "-C", str(root), *arguments),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=15,
    )
    if completed.returncode != 0:
        raise RuntimeError("reviewed Git binding probe failed")
    return completed.stdout.strip()


def _inventory(root: Path) -> tuple[str, ...]:
    tracked = tuple(sorted(
        item for item in _git(root, "ls-files", "--", "src").splitlines()
        if item.endswith(EXECUTABLE_SUFFIXES)
    ))
    untracked_candidates = tuple(sorted(
        item for item in _git(root, "ls-files", "--others", "--", "src").splitlines()
        if item.endswith(EXECUTABLE_SUFFIXES)
    ))
    tracked_sources = set(item for item in tracked if item.endswith(".py"))
    untracked = tuple(
        item for item in untracked_candidates
        if not _is_nonexecutable_cache(item, tracked_sources)
    )
    if untracked:
        raise ValueError("untracked executable Python or import artifact exists under reviewed src")
    if not tracked or "src/overseer_codex_dispatch_launcher.py" not in tracked:
        raise ValueError("reviewed executable source inventory is incomplete")
    return tracked


def _is_nonexecutable_cache(relative: str, tracked_sources: set[str]) -> bool:
    path = Path(relative)
    if path.suffix != ".pyc" or path.parent.name != "__pycache__" or ".cpython-" not in path.name:
        return False
    source_name = path.name.split(".cpython-", 1)[0] + ".py"
    return str(path.parent.parent / source_name) in tracked_sources


def _module_digest(root: Path, inventory: tuple[str, ...]) -> str:
    hasher = hashlib.sha256()
    for relative in inventory:
        path = root / relative
        lexical = path.lstat()
        if not stat.S_ISREG(lexical.st_mode) or lexical.st_uid != os.geteuid() or lexical.st_nlink != 1:
            raise ValueError("reviewed executable source is unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            if _stat_binding(before) != _stat_binding(lexical):
                raise ValueError("reviewed executable source changed before read")
            first = _read_all(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            second = _read_all(fd)
            after = os.fstat(fd)
            lexical_after = path.lstat()
            if (first != second or _stat_binding(after) != _stat_binding(before)
                    or _stat_binding(lexical_after) != _stat_binding(before)):
                raise ValueError("reviewed executable source changed during read")
        finally:
            os.close(fd)
        hasher.update(relative.encode() + b"\0" + first)
    return hasher.hexdigest()


def _dependency_digest_once(root: Path) -> str:
    root_info = root.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
            or stat.S_IMODE(root_info.st_mode) & 0o002):
        raise ValueError("reviewed dependency root is unsafe")
    inventory: list[str] = []
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directory_info = directory_path.lstat()
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != os.geteuid()
                or stat.S_IMODE(directory_info.st_mode) & 0o002):
            raise ValueError("reviewed dependency directory is unsafe")
        if any((directory_path / name).is_symlink() for name in names):
            raise ValueError("reviewed dependency tree contains a symlink")
        for name in files:
            path = directory_path / name
            if path.is_symlink():
                raise ValueError("reviewed dependency tree contains a symlink")
            relative = path.relative_to(root).as_posix()
            if relative.endswith(DEPENDENCY_EXECUTABLE_SUFFIXES):
                inventory.append(relative)
    if not inventory:
        raise ValueError("reviewed executable dependency inventory is empty")
    hasher = hashlib.sha256()
    for relative in sorted(inventory):
        path = root / relative
        lexical = path.lstat()
        if (not stat.S_ISREG(lexical.st_mode) or lexical.st_uid != os.geteuid()
                or lexical.st_nlink != 1 or stat.S_IMODE(lexical.st_mode) & 0o002):
            raise ValueError("reviewed executable dependency is unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            first = _read_all(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            second = _read_all(fd)
            after = os.fstat(fd)
            lexical_after = path.lstat()
            if (first != second or _stat_binding(before) != _stat_binding(lexical)
                    or _stat_binding(after) != _stat_binding(before)
                    or _stat_binding(lexical_after) != _stat_binding(before)):
                raise ValueError("reviewed executable dependency changed during read")
        finally:
            os.close(fd)
        hasher.update(relative.encode() + b"\0" + first)
    return hasher.hexdigest()


def _dependency_digest(root: Path) -> str:
    first = _dependency_digest_once(root)
    second = _dependency_digest_once(root)
    if first != second:
        raise ValueError("reviewed executable dependency inventory changed during validation")
    return first


def _stat_binding(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _validate(args: argparse.Namespace) -> Path:
    if not sys.flags.isolated or not sys.flags.no_site:
        raise RuntimeError("isolated launcher requires fixed interpreter flags -I -S")
    root = Path(args.source_root)
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise ValueError("reviewed source root is unsafe")
    inventory = _inventory(root)
    if _git(root, "status", "--porcelain", "--untracked-files=no", "--", "src", "pyproject.toml"):
        raise ValueError("reviewed source checkout is dirty")
    commit = _git(root, "rev-parse", "HEAD").lower()
    tree = _git(root, "rev-parse", "HEAD^{tree}").lower()
    module = _module_digest(root, inventory)
    review = _digest({
        "reviewScope": "structured-codex-dispatch",
        "reviewAuthority": "canonical-overseer-checkout",
        "sourceCommit": commit,
        "sourceTreeDigest": tree,
        "sourceModuleDigest": module,
        "sourceFiles": list(inventory),
    })
    spec = {
        "schemaVersion": SCHEMA,
        "sourceCommit": commit,
        "sourceTreeDigest": tree,
        "sourceModuleDigest": module,
        "reviewDigest": review,
        "dependencyDigest": args.dependency_digest.lower(),
        "bootstrapBinding": json.loads(args.bootstrap_binding),
        "serviceName": SERVICE_NAME,
        "dropInRelativePath": DROP_IN_RELATIVE_PATH,
        "daemonSocket": DAEMON_SOCKET,
        "healthUrl": HEALTH_URL,
        "sourceFiles": list(inventory),
    }
    actual = (commit, tree, module, review, _digest(spec))
    expected = (
        args.source_commit.lower(), args.source_tree.lower(), args.source_module.lower(),
        args.review_digest.lower(), args.spec_digest.lower(),
    )
    if actual != expected:
        raise ValueError("reviewed source/spec binding changed")
    if (_git(root, "rev-parse", "HEAD").lower() != commit
            or _git(root, "rev-parse", "HEAD^{tree}").lower() != tree
            or _git(root, "status", "--porcelain", "--untracked-files=no", "--", "src", "pyproject.toml")):
        raise ValueError("reviewed source binding changed during validation")
    return root


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="overseer-codex-dispatch-isolated")
    parser.add_argument("mode", choices=("probe", "service", "activation-cli"))
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-module", required=True)
    parser.add_argument("--review-digest", required=True)
    parser.add_argument("--spec-digest", required=True)
    parser.add_argument("--dependency-digest", required=True)
    parser.add_argument("--bootstrap-binding", required=True)
    parser.add_argument("--site-packages")
    parser.add_argument("payload", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        if not sys.flags.isolated or not sys.flags.no_site:
            raise RuntimeError("isolated launcher requires fixed interpreter flags -I -S")
        args = _parser().parse_args(argv)
        root = _validate(args)
        site_packages = Path(args.site_packages or "")
        if (not site_packages.is_absolute() or not site_packages.is_dir()
                or site_packages.is_symlink()):
            raise ValueError("reviewed site-packages path is unavailable")
        if _dependency_digest(site_packages) != args.dependency_digest.lower():
            raise ValueError("reviewed executable dependency digest changed")
        if args.mode == "probe":
            return 0
        payload = list(args.payload)
        if payload[:1] == ["--"]:
            payload = payload[1:]
        if not payload:
            raise ValueError("isolated dispatch payload is required")
        if args.mode == "activation-cli" and payload[0] not in ALLOWED_ACTIVATION_COMMANDS:
            raise ValueError("isolated activation CLI command is not allowed")
        if args.mode == "activation-cli":
            stores = [payload[index + 1] for index, item in enumerate(payload[:-1]) if item == "--store"]
            if stores != [SERVICE_STORE]:
                raise ValueError("isolated activation CLI store binding is invalid")
        if args.mode == "service" and tuple(payload) != SERVICE_PAYLOAD:
            raise ValueError("isolated service payload is not the exact reviewed command")
        if _dependency_digest(site_packages) != args.dependency_digest.lower():
            raise ValueError("reviewed executable dependency digest changed before import")
        interpreter_path_hooks = tuple(sys.path_hooks)
        source_only_hook = importlib.machinery.FileFinder.path_hook(
            (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES),
        )
        dependency_hook = importlib.machinery.FileFinder.path_hook(
            (importlib.machinery.SourceFileLoader, importlib.machinery.SOURCE_SUFFIXES),
            (importlib.machinery.ExtensionFileLoader, importlib.machinery.EXTENSION_SUFFIXES),
        )
        source_directory = root / "src"

        def reviewed_path_hook(path: str):
            candidate = Path(path)
            try:
                candidate.relative_to(source_directory)
            except ValueError:
                try:
                    candidate.relative_to(site_packages)
                except ValueError as error:
                    raise ImportError("import path is outside reviewed roots") from error
                return dependency_hook(path)
            return source_only_hook(path)

        sys.path_hooks[:] = [reviewed_path_hook, *interpreter_path_hooks]
        sys.path_importer_cache.clear()
        sys.path.insert(0, str(site_packages))
        sys.path.insert(0, str(root / "src"))
        _validate(args)
        from overseer.codex_dispatch_activation import authorize_isolated_activation_entry
        authorize_isolated_activation_entry(args.spec_digest)
        from overseer.cli import main as overseer_main
        return overseer_main(payload)
    except Exception as error:
        print(f"isolated launcher rejected dispatch: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
