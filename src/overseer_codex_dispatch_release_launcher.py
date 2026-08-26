"""Pre-import verifier/launcher for a root-owned Overseer release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path


SERVICE_PAYLOAD = (
    "serve-api",
    "--store", "/home/god/.local/share/overseer/project/state/overseer.sqlite3",
    "--host", "127.0.0.1",
    "--port", "8766",
    "--auth-token-file", "/home/god/.local/share/overseer/project/state/api-token",
    "--human-approval-token-file", "/home/god/.local/share/overseer/project/state/human-approval-token",
    "--human-approval-identity", "sisko",
)


def _validated_service_payload(payload: list[str]) -> list[str]:
    if tuple(payload) != ("--", *SERVICE_PAYLOAD):
        raise RuntimeError("release launcher payload is not the reviewed service entry")
    return list(SERVICE_PAYLOAD)


def _read_stable(path: Path) -> tuple[bytes, os.stat_result]:
    lexical = path.lstat()
    if not stat.S_ISREG(lexical.st_mode) or path.is_symlink() or lexical.st_nlink != 1:
        raise RuntimeError("release file identity is unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                             item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if identity(lexical) != identity(before) or identity(before) != identity(after):
        raise RuntimeError("release file changed during verification")
    return b"".join(chunks), after


def _verify(release_root: Path, manifest_path: Path, expected_digest: str) -> None:
    if release_root != Path("/opt/overseer/releases") / release_root.name or manifest_path != release_root / "release-manifest.json":
        raise RuntimeError("release paths are not canonical")
    raw, manifest_info = _read_stable(manifest_path)
    if manifest_info.st_uid != 0 or manifest_info.st_gid != 0 or stat.S_IMODE(manifest_info.st_mode) != 0o444:
        raise RuntimeError("release manifest is not root-owned immutable data")
    value = json.loads(raw)
    supplied = value.pop("manifestDigest", None)
    supplied_root = value.pop("releaseRoot", None)
    digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if digest != expected_digest or supplied != digest or supplied_root != str(release_root):
        raise RuntimeError("release manifest binding failed")
    python = value["rootPython"]
    executable = Path(str(python["resolvedPath"]))
    executable_content, executable_info = _read_stable(executable)
    if (Path(str(python["path"])) != Path("/usr/bin/python3")
            or Path("/usr/bin/python3").resolve(strict=True) != executable
            or executable_info.st_uid != 0 or executable_info.st_gid != 0
            or stat.S_IMODE(executable_info.st_mode) & 0o022
            or executable_info.st_dev != python["device"] or executable_info.st_ino != python["inode"]
            or hashlib.sha256(executable_content).hexdigest() != python["sha256"]):
        raise RuntimeError("root Python identity changed")
    for item in value["files"]:
        path = release_root / item["releasePath"]
        content, info = _read_stable(path)
        if (info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != item["mode"]
                or len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"]):
            raise RuntimeError("release file verification failed")
        current = path.parent
        while current != release_root.parent:
            directory = current.lstat()
            if (not stat.S_ISDIR(directory.st_mode) or current.is_symlink()
                    or directory.st_uid != 0 or directory.st_gid != 0
                    or stat.S_IMODE(directory.st_mode) & 0o222):
                raise RuntimeError("release directory identity is unsafe")
            if current == release_root:
                break
            current = current.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--release-root", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-digest", required=True)
    parser.add_argument("payload", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    release_root = Path(args.release_root)
    _verify(release_root, Path(args.manifest), args.manifest_digest)
    payload = _validated_service_payload(args.payload)
    # ``-I -S`` retains only root-owned standard-library entries.  Add the two
    # verified release roots explicitly without enabling user/site imports.
    sys.path.insert(0, str(release_root / "site-packages"))
    sys.path.insert(0, str(release_root / "app/src"))
    from overseer.cli import main as overseer_main
    return overseer_main(payload)


if __name__ == "__main__":
    raise SystemExit(main())
