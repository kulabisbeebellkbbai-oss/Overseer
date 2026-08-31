#!/usr/bin/python3.13
"""Preflight and render an inert disposable Phase B rehearsal plan.

``preflight`` performs read-only checks. ``render-plan`` is pure and emits
canonical JSON containing a separately approved future script. This module has
no VM, image, package, service, or activation mutation subcommand.
"""

from __future__ import annotations

import argparse
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
SESSION_RUNTIME_DIR = Path("/run/user") / str(os.geteuid())
REHEARSAL_SCHEMA = "overseer.phase-b-disposable-rehearsal-plan.v6"
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
_RUN_NAMESPACE = uuid.UUID("4c7e2e88-e69b-5a43-9896-ffae89196717")
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


def _read_regular_file(root: Path, relative: str) -> tuple[bytes, int]:
    relative = _safe_artifact_path(relative)
    target = root.joinpath(*PurePosixPath(relative).parts)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise PreflightError(f"artifact file is unavailable: {relative}") from error
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
    records: list[dict[str, object]] = []
    entries: list[tuple[str, int, bytes]] = []
    total = 0
    for relative in unique:
        payload, mode = _read_regular_file(root, relative)
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
    entries: list[tuple[str, int, bytes]] = []
    for item in validated["files"]:
        payload, mode = _read_regular_file(root, item["path"])
        if (
            mode != item["mode"]
            or len(payload) != item["size"]
            or hashlib.sha256(payload).hexdigest() != item["sha256"]
        ):
            raise PreflightError(f"{kind} artifact changed after manifest")
        entries.append((item["path"], mode, payload))
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
            "source=Path(sys.argv[1]).resolve(strict=True)",
            "runtime=Path(sys.argv[2]).resolve(strict=True)",
            "source_manifest=json.loads(sys.argv[3])",
            "runtime_manifest=json.loads(sys.argv[4])",
            "source_modules=(source/'src').resolve(strict=True)",
            "stdlib=Path(sysconfig.get_path('stdlib')).resolve(strict=True)",
            "platstdlib=Path(sysconfig.get_path('platstdlib')).resolve(strict=True)",
            "stdlib_dynamic=(stdlib/'lib-dynload').resolve(strict=True)",
            "def lexical(value): return os.path.abspath(os.path.normpath(os.fspath(value)))",
            "def allowed(root,manifest): return {lexical(root/item['path']):item for item in manifest['files']}",
            "allowed_source=allowed(source,source_manifest)",
            "allowed_runtime=allowed(runtime,runtime_manifest)",
            "def read_verified(origin,record):",
            " fd=os.open(origin,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)",
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
            " def __init__(self,origin,record): self.origin=origin; self.record=record",
            " def create_module(self,spec): return None",
            " def exec_module(self,module): exec(compile(read_verified(self.origin,self.record),self.origin,'exec',dont_inherit=True),module.__dict__)",
            "class ManifestNativeLoader(importlib.abc.Loader):",
            " def __init__(self,fullname,origin,record):",
            "  self.fullname=fullname; self.origin=origin; self.fd=os.memfd_create('overseer-manifested-native',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)",
            "  payload=read_verified(origin,record)",
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
            "  record=allowed_source.get(origin) if in_source else allowed_runtime.get(origin) if in_runtime else None",
            "  if in_source and record is None: raise ImportError('source origin is not manifested')",
            "  if in_runtime and record is None: raise ImportError('runtime origin is not manifested')",
            "  if record is not None: spec.loader=ManifestSourceLoader(origin,record) if origin.endswith(('.py','.pyw')) else ManifestNativeLoader(fullname,origin,record)",
            "  return spec",
            "sys.meta_path.insert(sys.meta_path.index(importlib.machinery.PathFinder),ManifestFinder())",
            "sys.path[:]=list(dict.fromkeys(map(str,(source_modules,runtime,stdlib,platstdlib,stdlib_dynamic))))",
            "assert sys.version_info[:2] == (3,13)",
            f"names={REQUIRED_IMPORTS!r}",
            "origins={}",
            "for name in names:",
            " module=importlib.import_module(name)",
            " origin=Path(module.__file__).resolve(strict=True)",
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
    runtime_site: Path = DEFAULT_RUNTIME_SITE,
    base_image: Path = DEFAULT_BASE_IMAGE,
    temp_parent: Path = DEFAULT_TEMP_PARENT,
    runner: Callable[[tuple[str, ...]], str] = _read_only_runner,
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
    _validate_session_runtime_directory(
        path_exists=path_exists,
        path_stat=path_stat,
        path_access=path_access,
        is_symlink=is_symlink,
    )
    if runner(("git-status", str(repo_root))):
        raise PreflightError("source tree is dirty")
    if runner(("git-head", str(repo_root))) != source_commit:
        raise PreflightError("source commit does not match the requested full SHA")
    tracked_raw = runner(("git-files", str(repo_root)))
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
root=Path(sys.argv[1])
manifest=json.loads(sys.argv[2])
output=Path(sys.argv[3])
entries=[]
for item in manifest["files"]:
    relative=PurePosixPath(item["path"])
    if relative.is_absolute() or any(part in {"",".",".."} for part in relative.parts): raise SystemExit("artifact path invalid")
    target=root.joinpath(*relative.parts)
    fd=os.open(target,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
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
fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
try:
    view=memoryview(payload)
    while view:
        written=os.write(fd,view)
        view=view[written:]
    os.fsync(fd)
finally:
    os.close(fd)
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
) -> str:
    validator = _result_validator_python()
    collector = _serial_collector_python()
    archive_builder = _archive_builder_python()
    ownership_validator = _ownership_validator_python()
    firmware_validator = _firmware_validator_python()
    runtime_probe_code = _runtime_probe_python()
    capability_probe_code = _capability_probe_python()
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
[[ "$(/usr/bin/git --no-optional-locks -c core.fsmonitor=false -c core.untrackedCache=false -C "$SOURCE_ROOT" rev-parse HEAD)" == "$SOURCE_COMMIT" ]]
[[ -z "$(/usr/bin/git --no-optional-locks -c core.fsmonitor=false -c core.untrackedCache=false -C "$SOURCE_ROOT" status --porcelain --untracked-files=all)" ]]
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
    base_image: Path = DEFAULT_BASE_IMAGE,
    temp_parent: Path = DEFAULT_TEMP_PARENT,
) -> dict[str, object]:
    """Purely render canonical plan data and a separate approval digest."""

    _require_full_source_commit(source_commit)
    for path, label in (
        (source_root, "source"),
        (runtime_site, "runtime"),
        (base_image, "base image"),
        (temp_parent, "temporary"),
    ):
        _validate_host_path(path, label)
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
    )
    plan: dict[str, object] = {
        "schemaVersion": REHEARSAL_SCHEMA,
        "sourceCommit": source_commit,
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
    render_parser.add_argument("--source-manifest-json", required=True)
    render_parser.add_argument("--runtime-manifest-json", required=True)
    render_parser.add_argument("--runtime-probe-json", required=True)
    render_parser.add_argument("--capability-probe-json", required=True)
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
