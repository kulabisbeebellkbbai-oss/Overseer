#!/usr/bin/env python3
"""Preflight and render an inert disposable Phase B rehearsal plan.

``preflight`` performs only read-only checks. ``render-plan`` is pure and
emits canonical JSON containing data artifacts, including one future Bash
script. This module has no VM, image, package, or service mutation path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
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
MEMORY_MIB = 2048
VCPUS = 2
OVERLAY_GIB = 8
SOURCE_MOUNT_TAG = "overseer-source"
RUNTIME_MOUNT_TAG = "overseer-runtime-site"
DEFAULT_BASE_IMAGE = Path(
    "/var/lib/overseer-phase-b-rehearsal/debian-13-genericcloud-amd64.qcow2"
)
DEFAULT_RUNTIME_SITE = Path("/usr/lib/python3/dist-packages")
DEFAULT_TEMP_PARENT = Path("/var/tmp")
REHEARSAL_SCHEMA = "overseer.phase-b-disposable-rehearsal-plan.v2"
RESULT_SCHEMA = "overseer.phase-b-disposable-rehearsal.v1"
RESULT_TIMEOUT_SECONDS = 960

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
REQUIRED_TOOLS = (
    "git",
    "virsh",
    "qemu-img",
    "cloud-localds",
    "sha512sum",
    "mktemp",
    "timeout",
    "bash",
    "awk",
    "cat",
    "grep",
    "install",
    "rm",
    "rmdir",
    "sleep",
    "python3",
)

_FULL_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HOST_PATH = re.compile(r"/[A-Za-z0-9._/+ \-]+\Z")


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


def _runtime_probe_record(*, source_root: Path, runtime_site: Path) -> dict[str, object]:
    return {
        "status": "passed",
        "noBytecode": True,
        "python": "/usr/bin/python3",
        "sourceRoot": str(source_root),
        "runtimeSite": str(runtime_site),
        "imports": list(REQUIRED_IMPORTS),
    }


def _validate_runtime_probe(
    probe: Mapping[str, object], *, source_root: Path, runtime_site: Path
) -> dict[str, object]:
    expected = _runtime_probe_record(source_root=source_root, runtime_site=runtime_site)
    if dict(probe) != expected:
        raise PreflightError("runtime probe is not the exact passed no-bytecode result")
    return expected


def _read_only_runner(command: tuple[str, ...]) -> str:
    """Run one explicit read-only probe selected by a symbolic label."""

    label = command[0]
    env: dict[str, str] | None = None
    if label == "git-status":
        argv = ("git", "-C", command[1], "status", "--porcelain", "--untracked-files=all")
    elif label == "git-head":
        argv = ("git", "-C", command[1], "rev-parse", "HEAD")
    elif label == "libvirt-uri":
        argv = ("virsh", "--connect", LIBVIRT_URI, "uri")
    elif label == "domains":
        argv = ("virsh", "--connect", LIBVIRT_URI, "list", "--all", "--name")
    elif label == "domain-capabilities":
        argv = (
            "virsh",
            "--connect",
            LIBVIRT_URI,
            "domcapabilities",
            "--virttype",
            "kvm",
            "--arch",
            "x86_64",
        )
    elif label == "qemu-img-info":
        argv = ("qemu-img", "info", "--output=json", "--force-share", command[1])
    elif label == "import-probe":
        probe_code = (
            "import importlib,json,sys;"
            "sys.dont_write_bytecode=True;"
            "sys.path.insert(0,sys.argv[1]+'/src');"
            "sys.path.insert(1,sys.argv[2]);"
            f"names={REQUIRED_IMPORTS!r};"
            "[importlib.import_module(name) for name in names];"
            "print(json.dumps({'imports':list(names),'noBytecode':True,'status':'passed'},"
            "sort_keys=True,separators=(',',':')))"
        )
        argv = ("python3", "-B", "-s", "-P", "-c", probe_code, command[1], command[2])
        env = os.environ.copy()
        env.update(
            {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "LC_ALL": "C",
            }
        )
    else:
        raise PreflightError(f"unsupported preflight probe: {label}")
    completed = subprocess.run(
        argv,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    return completed.stdout.strip()


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
    writable = mode & (stat.S_IWGRP | stat.S_IWOTH)
    if writable and not mode & stat.S_ISVTX:
        raise PreflightError("temporary path permissions are unsafe")


def _domain_xml(*, vm_name: str, source_root: Path, runtime_site: Path) -> str:
    source = escape(str(source_root))
    runtime = escape(str(runtime_site))
    return f"""<domain type='kvm'>
  <name>{escape(vm_name)}</name>
  <memory unit='MiB'>{MEMORY_MIB}</memory>
  <currentMemory unit='MiB'>{MEMORY_MIB}</currentMemory>
  <vcpu placement='static'>{VCPUS}</vcpu>
  <os><type arch='x86_64'>hvm</type><boot dev='hd'/></os>
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
    <filesystem type='mount' accessmode='passthrough'>
      <driver type='path' name='9p'/>
      <source dir='{source}'/>
      <target dir='{SOURCE_MOUNT_TAG}'/>
      <readonly/>
    </filesystem>
    <filesystem type='mount' accessmode='passthrough'>
      <driver type='path' name='9p'/>
      <source dir='{runtime}'/>
      <target dir='{RUNTIME_MOUNT_TAG}'/>
      <readonly/>
    </filesystem>
    <serial type='file'>
      <source path='${{SERIAL_LOG}}' append='on'/>
      <target type='isa-serial' port='0'/>
    </serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <graphics type='none'/>
  </devices>
</domain>
"""


def _plan_inputs(*, source_root: Path, runtime_site: Path) -> dict[str, object]:
    xml = _domain_xml(vm_name="overseer-phase-b-rehearsal-0000000", source_root=source_root, runtime_site=runtime_site)
    root = ElementTree.fromstring(xml)
    filesystems = {
        item.find("target").attrib["dir"]: item
        for item in root.findall("./devices/filesystem")
    }
    source_share = filesystems.get(SOURCE_MOUNT_TAG)
    runtime_share = filesystems.get(RUNTIME_MOUNT_TAG)
    if (
        source_share is None
        or runtime_share is None
        or source_share.find("readonly") is None
        or runtime_share.find("readonly") is None
    ):
        raise PreflightError("rendered source or runtime share is writable")
    interfaces = root.findall("./devices/interface")
    if interfaces:
        raise PreflightError("rendered plan contains a network device")
    return {
        "networkDevices": [],
        "sourceMount": {
            "hostPath": str(source_root),
            "tag": SOURCE_MOUNT_TAG,
            "type": "9p",
            "readOnly": True,
        },
        "runtimeMount": {
            "hostPath": str(runtime_site),
            "tag": RUNTIME_MOUNT_TAG,
            "type": "9p",
            "readOnly": True,
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
    which: Callable[[str], str | None] = shutil.which,
) -> dict[str, object]:
    """Perform only read-only checks and return digest-bindable evidence."""

    _require_full_source_commit(source_commit)
    for path, label in (
        (repo_root, "repository"),
        (source_root, "source"),
        (runtime_site, "runtime"),
        (base_image, "base image"),
        (temp_parent, "temporary"),
    ):
        _validate_host_path(path, label)

    if runner(("git-status", str(repo_root))):
        raise PreflightError("source tree is dirty")
    if runner(("git-head", str(repo_root))) != source_commit:
        raise PreflightError("source commit does not match the requested full SHA")

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
    _validate_temp_mode(temp_mode)

    missing = [name for name in REQUIRED_TOOLS if which(name) is None]
    if missing:
        raise PreflightError("required tooling is missing: " + ",".join(missing))
    if runner(("libvirt-uri",)) != LIBVIRT_URI:
        raise PreflightError("libvirt URI is not qemu:///session")
    target_name = f"overseer-phase-b-rehearsal-{source_commit[:7]}"
    domains = {line.strip() for line in runner(("domains",)).splitlines() if line.strip()}
    if target_name in domains:
        raise PreflightError(f"target VM already exists: {target_name}")

    try:
        capabilities = ElementTree.fromstring(runner(("domain-capabilities",)))
    except ElementTree.ParseError as error:
        raise PreflightError("KVM domain capabilities are unavailable") from error
    if capabilities.findtext("domain") != "kvm":
        raise PreflightError("KVM domain capabilities are unavailable")
    try:
        image_info = json.loads(runner(("qemu-img-info", str(base_image))))
    except (json.JSONDecodeError, TypeError) as error:
        raise PreflightError("base image qcow2 metadata is unavailable") from error
    if not isinstance(image_info, dict) or image_info.get("format") != "qcow2":
        raise PreflightError("base image is not qcow2")
    try:
        if image_sha512(base_image).lower() != BASE_IMAGE_SHA512:
            raise PreflightError("base image SHA-512 is unverified")
    except (OSError, ValueError, AttributeError) as error:
        raise PreflightError("base image SHA-512 could not be verified") from error

    try:
        probe_output = json.loads(
            runner(("import-probe", str(source_root), str(runtime_site)))
        )
    except (json.JSONDecodeError, TypeError) as error:
        raise PreflightError("runtime import probe failed") from error
    expected_probe_output = {
        "status": "passed",
        "noBytecode": True,
        "imports": list(REQUIRED_IMPORTS),
    }
    if probe_output != expected_probe_output:
        raise PreflightError("runtime import probe failed")
    runtime_probe = _runtime_probe_record(
        source_root=source_root, runtime_site=runtime_site
    )
    probe_digest = hashlib.sha256(canonical_json(runtime_probe).encode()).hexdigest()
    inputs = _plan_inputs(source_root=source_root, runtime_site=runtime_site)
    return {
        "status": "passed",
        "sourceCommit": source_commit,
        "targetVm": target_name,
        "libvirtUri": LIBVIRT_URI,
        "baseImageSha512": BASE_IMAGE_SHA512,
        "runtimeProbe": runtime_probe,
        "runtimeProbeDigest": probe_digest,
        "planInputs": inputs,
        "checkedTools": list(REQUIRED_TOOLS),
        "tempDirectoryCreated": False,
    }


def _cloud_init() -> str:
    lines = [
        "#cloud-config",
        "users: []",
        "disable_root: true",
        "ssh_pwauth: false",
        "ssh_deletekeys: true",
        "bootcmd:",
        "  - [mkdir, -p, /mnt/overseer-source]",
        "  - [mkdir, -p, /mnt/overseer-runtime-site]",
        "mounts:",
        "  - [overseer-source, /mnt/overseer-source, 9p, 'trans=virtio,version=9p2000.L,ro,nosuid,nodev,noexec', '0', '0']",
        "  - [overseer-runtime-site, /mnt/overseer-runtime-site, 9p, 'trans=virtio,version=9p2000.L,ro,nosuid,nodev,noexec', '0', '0']",
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
    placeholders = " ".join(TASK_TWO_PLACEHOLDERS)
    lines.extend(
        (
            "runcmd:",
            "  - |",
            "    /usr/bin/bash -ceu '",
            "      groupadd --gid 984 overseer",
            "      useradd --uid 984 --gid 984 --no-create-home --shell /usr/sbin/nologin overseer",
            "      groupadd --gid 1000 god",
            "      useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash god",
            "      test \"$(getent passwd 984 | cut -d: -f1,3,4)\" = overseer:984:984",
            "      test \"$(getent passwd 1000 | cut -d: -f1,3,4)\" = god:1000:1000",
            "      install -d -m 0755 /usr/local/lib/python3.13/dist-packages",
            "      cp -a /mnt/overseer-runtime-site/. /usr/local/lib/python3.13/dist-packages/",
            "      install -D -m 0755 /mnt/overseer-source/tests/phase_b_rehearsal/guest_rehearsal.py /opt/overseer-phase-b-rehearsal/guest_rehearsal.py",
            "      install -D -m 0644 /mnt/overseer-source/tests/phase_b_rehearsal/guest_rehearsal.service /etc/systemd/system/overseer-phase-b-rehearsal.service",
            f"      for placeholder in {placeholders}; do test ! -s \"$placeholder\"; chown root:root \"$placeholder\"; chmod 0644 \"$placeholder\"; done",
            "      systemctl daemon-reload",
            "      systemctl start overseer-phase-b-rehearsal.service",
            "    '",
        )
    )
    return "\n".join(lines) + "\n"


def _meta_data(vm_name: str) -> str:
    return f"instance-id: {vm_name}\nlocal-hostname: {vm_name}\n"


def _result_validator_python() -> str:
    controls = repr(sorted(REQUIRED_CONTROLS))
    return f"""import json
import re
import sys
from pathlib import Path

begin = "OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN"
end = "OVERSEER_PHASE_B_REHEARSAL_RESULT_END"
lines = Path(sys.argv[1]).read_text(encoding="utf-8", errors="strict").splitlines()
begin_indexes = [index for index, line in enumerate(lines) if line == begin]
end_indexes = [index for index, line in enumerate(lines) if line == end]
if len(begin_indexes) != 1 or len(end_indexes) != 1:
    raise SystemExit("exactly one complete sentinel pair is required")
if end_indexes[0] != begin_indexes[0] + 2:
    raise SystemExit("sentinel pair must frame exactly one JSON line")
payload = lines[begin_indexes[0] + 1]
record = json.loads(payload)
canonical = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
if canonical != payload:
    raise SystemExit("result is not canonical JSON")
if set(record) != {{"schemaVersion", "status", "stage", "controls", "identifiers", "failure"}}:
    raise SystemExit("result key set is invalid")
if record.get("schemaVersion") != "{RESULT_SCHEMA}":
    raise SystemExit("result schema is invalid")
if record.get("status") != "passed" or record.get("stage") != "phase-complete":
    raise SystemExit("rehearsal did not pass completely")
required_controls = {controls}
controls = record.get("controls")
if not isinstance(controls, dict) or set(controls) != set(required_controls):
    raise SystemExit("result controls are incomplete")
if any(value is not True for value in controls.values()):
    raise SystemExit("a required control did not pass")
if record.get("failure") is not None:
    raise SystemExit("passing result contains failure data")
identifiers = record.get("identifiers")
if not isinstance(identifiers, dict):
    raise SystemExit("identifiers are invalid")
secret_markers = re.compile(r"(?:secret|token|password|credential|verifier|private[_ -]?key|argv|environment|human[_ -]?input)", re.I)
for key, value in identifiers.items():
    if secret_markers.search(str(key)) or secret_markers.search(str(value)):
        raise SystemExit("result contains a secret marker")
for forbidden in ("phase-b-rehearsal-admin-secret", "phase-b-rehearsal-roadex-secret", "phase-b-rehearsal-api-token"):
    if forbidden in payload:
        raise SystemExit("result contains secret material")
print(payload)
"""


def _future_script(
    *,
    source_commit: str,
    vm_name: str,
    source_root: Path,
    runtime_site: Path,
    base_image: Path,
    temp_parent: Path,
    domain_xml: str,
    cloud_init: str,
    meta_data: str,
) -> str:
    validator = _result_validator_python()
    return f"""#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C

readonly LIBVIRT_URI={shlex.quote(LIBVIRT_URI)}
readonly SOURCE_COMMIT={shlex.quote(source_commit)}
readonly VM_NAME={shlex.quote(vm_name)}
readonly SOURCE_ROOT={shlex.quote(str(source_root))}
readonly RUNTIME_SITE={shlex.quote(str(runtime_site))}
readonly BASE_IMAGE={shlex.quote(str(base_image))}
readonly TEMP_PARENT={shlex.quote(str(temp_parent))}
readonly EXPECTED_SHA512={shlex.quote(BASE_IMAGE_SHA512)}
readonly RESULT_TIMEOUT_SECONDS={RESULT_TIMEOUT_SECONDS}
readonly SHUTDOWN_TIMEOUT_SECONDS=120

TEMP_DIR=""
OVERLAY=""
SEED_ISO=""
SERIAL_LOG=""
DOMAIN_XML=""
USER_DATA=""
META_DATA=""

domain_exists() {{
  virsh --connect "$LIBVIRT_URI" dominfo "$VM_NAME" >/dev/null 2>&1
}}

domain_is_inactive() {{
  [[ "$(virsh --connect "$LIBVIRT_URI" domstate "$VM_NAME" 2>/dev/null || true)" == "shut off" ]]
}}

wait_for_inactive() {{
  local deadline=$((SECONDS + SHUTDOWN_TIMEOUT_SECONDS))
  while domain_exists && ! domain_is_inactive; do
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
  ! domain_exists || domain_is_inactive
}}

temp_layout_is_exact() {{
  [[ -n "$TEMP_DIR" ]] &&
  [[ "$OVERLAY" == "$TEMP_DIR/overlay.qcow2" ]] &&
  [[ "$SEED_ISO" == "$TEMP_DIR/seed.iso" ]] &&
  [[ "$SERIAL_LOG" == "$TEMP_DIR/serial.log" ]] &&
  [[ "$DOMAIN_XML" == "$TEMP_DIR/domain.xml" ]] &&
  [[ "$USER_DATA" == "$TEMP_DIR/user-data" ]] &&
  [[ "$META_DATA" == "$TEMP_DIR/meta-data" ]]
}}

cleanup() {{
  local original_status="${{1:-1}}"
  local cleanup_status=0
  trap - EXIT INT TERM
  set +e
  if domain_exists; then
    if ! domain_is_inactive; then
      virsh --connect "$LIBVIRT_URI" shutdown "$VM_NAME" >/dev/null 2>&1 || cleanup_status=1
      wait_for_inactive || cleanup_status=1
    fi
    if (( cleanup_status == 0 )) && domain_is_inactive; then
      virsh --connect "$LIBVIRT_URI" undefine "$VM_NAME" >/dev/null 2>&1 || cleanup_status=1
    fi
  fi
  if domain_exists; then
    cleanup_status=1
  fi
  if (( cleanup_status == 0 )) && temp_layout_is_exact; then
    rm -f -- "$DOMAIN_XML" "$USER_DATA" "$META_DATA" "$OVERLAY" "$SEED_ISO" "$SERIAL_LOG"
    rmdir -- "$TEMP_DIR" || cleanup_status=1
  elif [[ -n "$TEMP_DIR" ]]; then
    printf '%s\n' 'cleanup retained exact temporary artifacts because the domain was not confirmed inactive' >&2
  fi
  if (( original_status == 0 && cleanup_status != 0 )); then
    original_status=1
  fi
  exit "$original_status"
}}

trap 'cleanup $?' EXIT
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

[[ "$LIBVIRT_URI" == "qemu:///session" ]]
[[ "$VM_NAME" == {shlex.quote(vm_name)} ]]
[[ "$SOURCE_ROOT" == {shlex.quote(str(source_root))} ]]
[[ "$RUNTIME_SITE" == {shlex.quote(str(runtime_site))} ]]
[[ "$BASE_IMAGE" == {shlex.quote(str(base_image))} ]]
[[ "$TEMP_PARENT" == {shlex.quote(str(temp_parent))} ]]
if domain_exists; then
  printf '%s\n' 'target VM already exists at future execution boundary' >&2
  exit 1
fi
[[ "$(git -C "$SOURCE_ROOT" rev-parse HEAD)" == "$SOURCE_COMMIT" ]]
[[ -z "$(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=all)" ]]

TEMP_DIR="$(mktemp -d -p "$TEMP_PARENT" overseer-phase-b-rehearsal.XXXXXX)"
OVERLAY="$TEMP_DIR/overlay.qcow2"
SEED_ISO="$TEMP_DIR/seed.iso"
SERIAL_LOG="$TEMP_DIR/serial.log"
DOMAIN_XML="$TEMP_DIR/domain.xml"
USER_DATA="$TEMP_DIR/user-data"
META_DATA="$TEMP_DIR/meta-data"
temp_layout_is_exact
install -m 0600 /dev/null "$SERIAL_LOG"
install -m 0600 /dev/null "$USER_DATA"
install -m 0600 /dev/null "$META_DATA"
install -m 0600 /dev/null "$DOMAIN_XML"

printf '%s  %s\n' "$EXPECTED_SHA512" "$BASE_IMAGE" | sha512sum --check -
qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY" {OVERLAY_GIB}G

cat >"$USER_DATA" <<'CLOUD_INIT'
{cloud_init}CLOUD_INIT
cat >"$META_DATA" <<'META_DATA'
{meta_data}META_DATA
cloud-localds --disk-format=iso9660 "$SEED_ISO" "$USER_DATA" "$META_DATA"

cat >"$DOMAIN_XML" <<DOMAIN_XML
{domain_xml}DOMAIN_XML
virsh --connect "$LIBVIRT_URI" define --validate "$DOMAIN_XML"
virsh --connect "$LIBVIRT_URI" autostart --disable "$VM_NAME"
virsh --connect "$LIBVIRT_URI" dominfo "$VM_NAME" | awk -F: '/^Autostart/ {{gsub(/[[:space:]]/, "", $2); print $2}}' | grep -qx disable
virsh --connect "$LIBVIRT_URI" start "$VM_NAME"

if ! timeout --foreground "${{RESULT_TIMEOUT_SECONDS}}s" bash -c '
  serial_log="$1"
  while ! grep -Fq "OVERSEER_PHASE_B_REHEARSAL_RESULT_END" "$serial_log"; do
    sleep 2
  done
' bash "$SERIAL_LOG"; then
  printf '%s\n' 'bounded rehearsal result wait expired' >&2
  exit 1
fi

python3 -B -s -P - "$SERIAL_LOG" <<'PY_RESULT_VALIDATOR'
{validator}PY_RESULT_VALIDATOR

if domain_exists && ! domain_is_inactive; then
  virsh --connect "$LIBVIRT_URI" shutdown "$VM_NAME"
fi
wait_for_inactive
domain_is_inactive
virsh --connect "$LIBVIRT_URI" undefine "$VM_NAME"
"""


def render_plan(
    *,
    source_commit: str,
    source_root: Path,
    runtime_site: Path,
    runtime_probe: Mapping[str, object],
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
    validated_probe = _validate_runtime_probe(
        runtime_probe, source_root=source_root, runtime_site=runtime_site
    )
    probe_digest = hashlib.sha256(canonical_json(validated_probe).encode()).hexdigest()
    vm_name = f"overseer-phase-b-rehearsal-{source_commit[:7]}"
    cloud_init = _cloud_init()
    meta_data = _meta_data(vm_name)
    domain_xml = _domain_xml(
        vm_name=vm_name, source_root=source_root, runtime_site=runtime_site
    )
    inputs = _plan_inputs(source_root=source_root, runtime_site=runtime_site)
    script = _future_script(
        source_commit=source_commit,
        vm_name=vm_name,
        source_root=source_root,
        runtime_site=runtime_site,
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
        "libvirtUri": LIBVIRT_URI,
        "vm": {
            "name": vm_name,
            "memoryMiB": MEMORY_MIB,
            "vcpus": VCPUS,
            "overlayGiB": OVERLAY_GIB,
            "network": "none",
            "autostart": False,
            "lifecycle": "temporary-persistent-explicit-undefine",
        },
        "sourceMount": inputs["sourceMount"],
        "runtimeSite": inputs["runtimeMount"],
        "networkDevices": inputs["networkDevices"],
        "tempParent": str(temp_parent),
        "serialLog": {
            "directory": "<fresh-mktemp-dir>",
            "path": "$TEMP_DIR/serial.log",
            "mode": "0600",
            "writer": "libvirt-append-only",
        },
        "runtimeProbe": validated_probe,
        "runtimeProbeDigest": probe_digest,
        "taskTwoPlaceholders": list(TASK_TWO_PLACEHOLDERS),
        "cloudInit": cloud_init,
        "metaData": meta_data,
        "domainXml": domain_xml,
        "futureScript": script,
        "futureScriptSha256": hashlib.sha256(script.encode()).hexdigest(),
        "approvalBoundary": "planDigest",
        "exclusions": ["package import", "host service action", "Phase B", "cutover"],
    }
    digest = hashlib.sha256(canonical_json(plan).encode()).hexdigest()
    return {"plan": plan, "planDigest": digest}


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
    render_parser.add_argument("--runtime-probe-json", required=True)
    return parser


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
            try:
                runtime_probe = json.loads(args.runtime_probe_json)
            except json.JSONDecodeError as error:
                raise PreflightError("runtime probe JSON is invalid") from error
            if not isinstance(runtime_probe, dict):
                raise PreflightError("runtime probe JSON is invalid")
            result = render_plan(
                source_commit=args.source_commit,
                source_root=args.source_root,
                runtime_site=args.runtime_site,
                runtime_probe=runtime_probe,
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
