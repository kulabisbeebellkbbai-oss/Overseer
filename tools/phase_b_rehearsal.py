#!/usr/bin/env python3
"""Render and preflight an inert, disposable Phase B VM rehearsal plan.

This module deliberately has no VM lifecycle implementation.  ``preflight``
only reads local state, and ``render-plan`` is a pure serialization operation.
The commands in a rendered plan are future commands for a separately approved
operator round; they are never executed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from xml.sax.saxutils import escape


BASE_IMAGE_URL = (
    "https://cloud.debian.org/images/cloud/trixie/latest/"
    "debian-13-genericcloud-amd64.qcow2"
)
BASE_IMAGE_SHA512 = (
    "184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003"
)
LIBVIRT_URI = "qemu:///session"
MEMORY_MIB = 2048
VCPUS = 2
OVERLAY_GIB = 8
SOURCE_MOUNT_TAG = "overseer-source"
DEFAULT_BASE_IMAGE = Path(
    "/var/lib/overseer-phase-b-rehearsal/debian-13-genericcloud-amd64.qcow2"
)
DEFAULT_TEMP_PARENT = Path("/var/tmp")
DEFAULT_SOURCE_SHARE_SPEC = "ro,9p,tag=overseer-source"
REHEARSAL_SCHEMA = "overseer.phase-b-disposable-rehearsal-plan.v1"

TASK_TWO_PLACEHOLDERS = (
    "/etc/systemd/system/overseer-approval-smoke.service",
    "/etc/systemd/system/overseer-api-canary.service",
    "/etc/systemd/system/overseer-admin-executor.socket",
    "/etc/systemd/system/overseer-admin-executor@.service",
    "/etc/systemd/system/overseer-codex-user-bridge.socket",
    "/etc/systemd/system/overseer-codex-user-bridge.service",
)
REQUIRED_TOOLS = (
    "git",
    "virsh",
    "qemu-img",
    "cloud-localds",
    "sha512sum",
    "mktemp",
    "timeout",
)
_FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")


class PreflightError(RuntimeError):
    """Raised when the exact read-only rehearsal preconditions are absent."""


def canonical_json(value: object) -> str:
    """Serialize JSON deterministically for both output and digesting."""

    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _require_full_source_commit(source_commit: str) -> None:
    if not isinstance(source_commit, str) or _FULL_SHA.fullmatch(source_commit) is None:
        raise PreflightError("source commit must be a lowercase full 40-character SHA")


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_only_runner(command: tuple[str, ...]) -> str:
    """Run one of four explicitly read-only probes.

    The symbolic first argument makes the allowed surface obvious to injected
    test runners and prevents callers from smuggling arbitrary commands into
    this helper.
    """

    label = command[0]
    if label == "git-status":
        argv = ("git", "-C", command[1], "status", "--porcelain", "--untracked-files=all")
    elif label == "git-head":
        argv = ("git", "-C", command[1], "rev-parse", "HEAD")
    elif label == "libvirt-uri":
        argv = ("virsh", "--connect", LIBVIRT_URI, "uri")
    elif label == "domains":
        argv = ("virsh", "--connect", LIBVIRT_URI, "list", "--all", "--name")
    else:
        raise PreflightError(f"unsupported preflight probe: {label}")
    completed = subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return completed.stdout.strip()


def _safe_temp_parent(path: Path, *, path_exists: Callable[[Path], bool]) -> None:
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise PreflightError("temporary parent path is unsafe")
    if not path_exists(path) or path.is_symlink() or not path.is_dir():
        raise PreflightError("temporary parent path is unsafe")
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise PreflightError("temporary parent path is unsafe") from error
    if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
        raise PreflightError("temporary parent path is unsafe")
    if mode & stat.S_IWGRP:
        raise PreflightError("temporary parent path is unsafe")


def _safe_serial_path(serial_log: Path | str | None, temp_parent: Path) -> None:
    if serial_log is None:
        return
    rendered = str(serial_log)
    if rendered == "$TEMP_DIR/serial.log":
        return
    path = Path(serial_log)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path.name != "serial.log"
        or path.parent != temp_parent
    ):
        raise PreflightError("serial log path is unsafe")


def preflight(
    *,
    source_commit: str,
    repo_root: Path,
    runner: Callable[[tuple[str, ...]], str] = _read_only_runner,
    path_exists: Callable[[Path], bool] = lambda path: path.exists(),
    is_regular_file: Callable[[Path], bool] = lambda path: path.is_file(),
    image_sha512: Callable[[Path], str] = sha512_file,
    which: Callable[[str], str | None] = shutil.which,
    base_image: Path = DEFAULT_BASE_IMAGE,
    temp_parent: Path = DEFAULT_TEMP_PARENT,
    serial_log: Path | str | None = None,
    source_share_spec: str = DEFAULT_SOURCE_SHARE_SPEC,
    network_devices: Sequence[str] = (),
) -> dict[str, object]:
    """Perform only fail-closed checks; never create or mutate an artifact."""

    _require_full_source_commit(source_commit)
    repo_text = str(repo_root)
    if runner(("git-status", repo_text)):
        raise PreflightError("source tree is dirty")
    actual_head = runner(("git-head", repo_text))
    if actual_head != source_commit:
        raise PreflightError("source commit does not match the requested full SHA")
    if not path_exists(Path("/dev/kvm")):
        raise PreflightError("/dev/KVM is missing")
    if runner(("libvirt-uri",)) != LIBVIRT_URI:
        raise PreflightError("libvirt URI is not qemu:///session")

    target_name = f"overseer-phase-b-rehearsal-{source_commit[:7]}"
    domains = {line.strip() for line in runner(("domains",)).splitlines() if line.strip()}
    if target_name in domains:
        raise PreflightError(f"target VM already exists: {target_name}")
    if source_share_spec != DEFAULT_SOURCE_SHARE_SPEC or "rw" in source_share_spec.lower():
        raise PreflightError("source-share specification is writable")
    if tuple(network_devices):
        raise PreflightError("network devices are not allowed")

    if not path_exists(base_image) or not is_regular_file(base_image):
        raise PreflightError("base image is missing")
    try:
        observed_sha512 = image_sha512(base_image).lower()
    except (OSError, ValueError) as error:
        raise PreflightError("base image SHA-512 could not be verified") from error
    if observed_sha512 != BASE_IMAGE_SHA512:
        raise PreflightError("base image SHA-512 is unverified")
    missing_tools = [name for name in REQUIRED_TOOLS if which(name) is None]
    if missing_tools:
        raise PreflightError("required tooling is missing: " + ",".join(missing_tools))
    _safe_temp_parent(temp_parent, path_exists=path_exists)
    _safe_serial_path(serial_log, temp_parent)

    return {
        "status": "passed",
        "sourceCommit": source_commit,
        "targetVm": target_name,
        "libvirtUri": LIBVIRT_URI,
        "baseImageSha512": BASE_IMAGE_SHA512,
        "checkedTools": list(REQUIRED_TOOLS),
        "tempDirectoryCreated": False,
    }


def _cloud_init() -> str:
    lines = [
        "#cloud-config",
        "write_files:",
    ]
    for path in TASK_TWO_PLACEHOLDERS:
        lines.extend(
            (
                f"  - path: {path}",
                "    owner: root:root",
                "    permissions: '0644'",
                "    content: ''",
            )
        )
    return "\n".join(lines) + "\n"


def _domain_xml(*, vm_name: str, source_root: Path) -> str:
    source = escape(str(source_root))
    return f"""<domain type='kvm'>
  <name>{escape(vm_name)}</name>
  <memory unit='MiB'>{MEMORY_MIB}</memory>
  <currentMemory unit='MiB'>{MEMORY_MIB}</currentMemory>
  <vcpu placement='static'>{VCPUS}</vcpu>
  <os><type arch='x86_64'>hvm</type><boot dev='hd'/></os>
  <features><acpi/></features>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$OVERLAY'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <filesystem type='mount' accessmode='passthrough'>
      <driver type='path' name='9p'/>
      <source dir='{source}'/>
      <target dir='{SOURCE_MOUNT_TAG}'/>
      <readonly/>
    </filesystem>
    <serial type='file'><source path='$SERIAL_LOG'/></serial>
    <console type='file'><source path='$SERIAL_LOG'/></console>
    <graphics type='none'/>
  </devices>
</domain>
"""


def _future_commands(
    *, vm_name: str, base_image: Path, temp_parent: Path, source_root: Path
) -> list[str]:
    return [
        f"TEMP_PARENT={shlex.quote(str(temp_parent))}; BASE_IMAGE={shlex.quote(str(base_image))}; VM_NAME={shlex.quote(vm_name)}",
        'TEMP_DIR="$(mktemp -d -p "$TEMP_PARENT" overseer-phase-b-rehearsal.XXXXXX)"',
        'SERIAL_LOG="$TEMP_DIR/serial.log"; OVERLAY="$TEMP_DIR/overlay.qcow2"; SEED_ISO="$TEMP_DIR/seed.iso"; install -m 0600 /dev/null "$SERIAL_LOG"',
        f'printf "%s  %s\\n" "{BASE_IMAGE_SHA512}" "$BASE_IMAGE" | sha512sum --check -',
        'qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY" 8G',
        "cloud-localds --disk-format=iso9660 \"$SEED_ISO\" <(cat <<'CLOUD_INIT'\n"
        + _cloud_init()
        + "CLOUD_INIT\n) <(printf '%s\\n' 'instance-id: overseer-phase-b-rehearsal')",
        "virsh --connect qemu:///session define --transient <(cat <<'DOMAIN_XML'\n"
        + _domain_xml(vm_name=vm_name, source_root=source_root)
        + "DOMAIN_XML\n)",
        'virsh --connect qemu:///session autostart --disable "$VM_NAME"',
        'virsh --connect qemu:///session start "$VM_NAME"',
        'timeout --foreground 180s virsh --connect qemu:///session console "$VM_NAME" --force > "$SERIAL_LOG"',
        "awk '/OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN/{capture=1; next} /OVERSEER_PHASE_B_REHEARSAL_RESULT_END/{capture=0} capture' \"$SERIAL_LOG\"",
        'virsh --connect qemu:///session shutdown "$VM_NAME"',
        "timeout 60s sh -c 'while [ \"$(virsh --connect qemu:///session domstate \"$VM_NAME\")\" != \"shut off\" ]; do sleep 1; done'",
        'virsh --connect qemu:///session undefine "$VM_NAME"',
        'rm -f -- "$OVERLAY" "$SEED_ISO" "$SERIAL_LOG"; rmdir -- "$TEMP_DIR"',
    ]


def render_plan(
    *,
    source_commit: str,
    source_root: Path,
    temp_parent: Path,
    base_image: Path = DEFAULT_BASE_IMAGE,
) -> dict[str, object]:
    """Return canonical plan data and its separate approval-bound digest."""

    _require_full_source_commit(source_commit)
    vm_name = f"overseer-phase-b-rehearsal-{source_commit[:7]}"
    plan: dict[str, object] = {
        "schemaVersion": REHEARSAL_SCHEMA,
        "sourceCommit": source_commit,
        "image": {"url": BASE_IMAGE_URL, "sha512": BASE_IMAGE_SHA512, "localPath": str(base_image)},
        "libvirtUri": LIBVIRT_URI,
        "vm": {
            "name": vm_name,
            "memoryMiB": MEMORY_MIB,
            "vcpus": VCPUS,
            "overlayGiB": OVERLAY_GIB,
            "network": "none",
            "autostart": False,
        },
        "sourceMount": {"type": "9p", "tag": SOURCE_MOUNT_TAG, "readOnly": True},
        "tempParent": str(temp_parent),
        "serialLog": {
            "directory": "<fresh-mktemp-dir>",
            "path": "$TEMP_DIR/serial.log",
            "mode": "0600",
        },
        "taskTwoPlaceholders": list(TASK_TWO_PLACEHOLDERS),
        "cloudInit": _cloud_init(),
        "domainXml": _domain_xml(vm_name=vm_name, source_root=source_root),
        "futureCommands": _future_commands(
            vm_name=vm_name,
            base_image=base_image,
            temp_parent=temp_parent,
            source_root=source_root,
        ),
        "approvalBoundary": "planDigest",
        "exclusions": ["package import", "host service action", "Phase B", "cutover"],
    }
    digest = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    return {"plan": plan, "planDigest": digest}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    for name in ("preflight", "render-plan"):
        sub = subparsers.add_parser(name)
        sub.add_argument("--source-commit", required=True)
        sub.add_argument("--repo-root", type=Path, default=Path.cwd())
        sub.add_argument("--source-root", type=Path, default=Path.cwd())
        sub.add_argument("--base-image", type=Path, default=DEFAULT_BASE_IMAGE)
        sub.add_argument("--temp-parent", type=Path, default=DEFAULT_TEMP_PARENT)
        sub.add_argument("--serial-log", type=str)
        sub.add_argument("--source-share-spec", default=DEFAULT_SOURCE_SHARE_SPEC)
        sub.add_argument("--network-device", action="append", default=[])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.subcommand == "preflight":
            result = preflight(
                source_commit=args.source_commit,
                repo_root=args.repo_root,
                base_image=args.base_image,
                temp_parent=args.temp_parent,
                serial_log=args.serial_log,
                source_share_spec=args.source_share_spec,
                network_devices=args.network_device,
            )
        else:
            result = render_plan(
                source_commit=args.source_commit,
                source_root=args.source_root,
                temp_parent=args.temp_parent,
                base_image=args.base_image,
            )
    except PreflightError as error:
        print(canonical_json({"status": "rejected", "reason": str(error)}), file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
