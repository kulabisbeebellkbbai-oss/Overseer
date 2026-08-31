from __future__ import annotations

import ast
import hashlib
import importlib.util
import inspect
import json
import os
import py_compile
import shlex
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest


TOOL = Path(__file__).parents[1] / "tools" / "phase_b_rehearsal.py"
ACTIVE_DUMPXML_FIXTURE = (
    Path(__file__).parent / "fixtures" / "phase_b_rehearsal_active_dumpxml.xml"
)
INACTIVE_EFI_DUMPXML_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "phase_b_rehearsal_inactive_efi_dumpxml.xml"
)
SOURCE_COMMIT = "54a53bc34078c42a4303d6fe4de7e517a9e8f44b"
SOURCE_ROOT = Path("/home/god/Documents/Codex Workspace/Overseer/source")
RUNTIME_SITE = Path("/usr/lib/python3/dist-packages")
BASE_IMAGE = Path("/var/lib/overseer-phase-b-rehearsal/debian-13-genericcloud-amd64.qcow2")
FIRMWARE_CODE = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
FIRMWARE_VARS_TEMPLATE = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
MACHINE_TYPE = "pc-i440fx-10.0"
TEMP_PARENT = Path("/var/tmp")
SESSION_RUNTIME_DIR = Path(f"/run/user/{os.geteuid()}")
OWNER_THREAD = "01a0354f-d735-76d1-852c-f364b6e6af56"
OWNER_PROJECT = Path("/home/god/Documents/Codex Workspace/Overseer")
CODEX_PROJECTS_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
OWNER_PROJECT_DEVICE = 65025
OWNER_PROJECT_INODE = 57303685
SOURCE_ROOT_DEVICE = 65025
SOURCE_ROOT_INODE = 1201523
GIT_COMMON_DEVICE = 65025
GIT_COMMON_INODE = 57304002
REGISTRY_DEVICE = 65025
REGISTRY_INODE = 58100001
LAUNCHER_DEVICE = 65025
LAUNCHER_INODE = 58100002
LAUNCHER_SHA256 = "e" * 64
CODEX_EXECUTABLE = Path(
    "/home/god/.codex/packages/standalone/releases/0.151.0-x86_64-unknown-linux-musl/bin/codex"
)
CODEX_EXECUTABLE_DEVICE = 65025
CODEX_EXECUTABLE_INODE = 58100003
CODEX_EXECUTABLE_SHA256 = "f" * 64
EXPECTED_IMPORTS = (
    "cryptography",
    "overseer.cli",
    "overseer.user_bridge",
    "overseer.admin_executor",
)
EXPECTED_PYTHON_VERSION = "3.13.5"
EXPECTED_PYTHON_ABI = "cpython-313-x86_64-linux-gnu"
MANIFEST_SCHEMA = "overseer.rehearsal-artifact-manifest.v1"
EXPECTED_CONTROLS = frozenset(
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


def load_tool():
    spec = importlib.util.spec_from_file_location("phase_b_rehearsal_tool", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runtime_probe() -> dict[str, object]:
    return {
        "status": "passed",
        "noBytecode": True,
        "python": "/usr/bin/python3.13",
        "pythonVersion": EXPECTED_PYTHON_VERSION,
        "pythonAbi": EXPECTED_PYTHON_ABI,
        "sourceRoot": str(SOURCE_ROOT),
        "runtimeSite": str(RUNTIME_SITE),
        "sourceManifestDigest": hashlib.sha256(
            json.dumps(
                artifact_manifest("source"),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "runtimeManifestDigest": hashlib.sha256(
            json.dumps(
                artifact_manifest("runtime"),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "imports": {
            "cryptography": str(RUNTIME_SITE / "cryptography/__init__.py"),
            "overseer.cli": str(SOURCE_ROOT / "src/overseer/cli.py"),
            "overseer.user_bridge": str(SOURCE_ROOT / "src/overseer/user_bridge.py"),
            "overseer.admin_executor": str(SOURCE_ROOT / "src/overseer/admin_executor.py"),
        },
    }


def capability_probe() -> dict[str, object]:
    return {
        "status": "passed",
        "libvirtUri": "qemu:///session",
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
            "loaderSha256": "624e06de18b4fa535e90db7160d00d3d07d206422b89999bf1e27d920264e4e0",
            "varsTemplate": str(FIRMWARE_VARS_TEMPLATE),
            "varsTemplateSha256": "5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e",
        },
    }


def artifact_manifest(kind: str) -> dict[str, object]:
    if kind == "source":
        files = [
            {
                "path": "src/overseer/cli.py",
                "mode": 0o644,
                "size": 12,
                "sha256": "1" * 64,
            },
            {
                "path": "tests/phase_b_rehearsal/guest_rehearsal.py",
                "mode": 0o644,
                "size": 34,
                "sha256": "2" * 64,
            },
        ]
    else:
        files = [
            {
                "path": "cryptography/__init__.py",
                "mode": 0o644,
                "size": 8,
                "sha256": "3" * 64,
            },
            {
                "path": "_cffi_backend.cpython-313-x86_64-linux-gnu.so",
                "mode": 0o644,
                "size": 16,
                "sha256": "4" * 64,
            },
        ]
    files.sort(key=lambda item: item["path"])
    return {
        "schemaVersion": MANIFEST_SCHEMA,
        "kind": kind,
        "fileCount": len(files),
        "totalBytes": sum(item["size"] for item in files),
        "archiveSha256": ("a" if kind == "source" else "b") * 64,
        "files": files,
    }


def manifest_digest(module, manifest: dict[str, object]) -> str:
    return hashlib.sha256(module.canonical_json(manifest).encode()).hexdigest()


def owner_binding(module, *, conversation_id: str = OWNER_THREAD) -> dict[str, object]:
    registry_payload = owner_registry_bytes(conversation_id=conversation_id)
    row = {
        "conversationId": conversation_id,
        "project": str(OWNER_PROJECT),
        "command": f"codex-overseer-{conversation_id}",
        "launcher": f"/home/god/.local/bin/codex-overseer-{conversation_id}",
    }
    record: dict[str, object] = {
        "schemaVersion": "overseer.phase-b-rehearsal-owner-binding.v2",
        "status": "passed",
        "conversationId": conversation_id,
        "project": str(OWNER_PROJECT),
        "ownerProjectToplevel": str(OWNER_PROJECT),
        "sourceRoot": str(SOURCE_ROOT),
        "gitCommonDirectory": str(OWNER_PROJECT / ".git"),
        "ownerProjectDevice": OWNER_PROJECT_DEVICE,
        "ownerProjectInode": OWNER_PROJECT_INODE,
        "sourceRootDevice": SOURCE_ROOT_DEVICE,
        "sourceRootInode": SOURCE_ROOT_INODE,
        "gitCommonDirectoryDevice": GIT_COMMON_DEVICE,
        "gitCommonDirectoryInode": GIT_COMMON_INODE,
        "registry": str(CODEX_PROJECTS_REGISTRY),
        "registryDevice": REGISTRY_DEVICE,
        "registryInode": REGISTRY_INODE,
        "registryRow": row,
        "registrySha256": hashlib.sha256(registry_payload).hexdigest(),
        "registryRowDigest": hashlib.sha256(module.canonical_json(row).encode()).hexdigest(),
        "launcherDevice": LAUNCHER_DEVICE,
        "launcherInode": LAUNCHER_INODE,
        "launcherSha256": LAUNCHER_SHA256,
        "codexExecutable": str(CODEX_EXECUTABLE),
        "codexExecutableDevice": CODEX_EXECUTABLE_DEVICE,
        "codexExecutableInode": CODEX_EXECUTABLE_INODE,
        "codexExecutableSha256": CODEX_EXECUTABLE_SHA256,
        "codexArgv": ["codex", "resume", conversation_id, "--cd", str(OWNER_PROJECT)],
    }
    record["bindingDigest"] = hashlib.sha256(module.canonical_json(record).encode()).hexdigest()
    return record


def owner_registry_bytes(
    *, conversation_id: str = OWNER_THREAD, project: Path = OWNER_PROJECT, duplicate: bool = False
) -> bytes:
    header = "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
    row = (
        f"{conversation_id},Overseer,{project},codex-overseer-{conversation_id},"
        f"/home/god/.local/bin/codex-overseer-{conversation_id},"
        "2026-08-24T19:47:00+00:00,2026-08-31T11:34:13+00:00,codex-state,\n"
    )
    return (header + row + (row if duplicate else "")).encode("utf-8")


def render(module, **overrides: object) -> dict[str, object]:
    registry_payload = overrides.pop("_registry_payload", None)
    repository_identities = overrides.pop("_repository_identities", None)
    values: dict[str, object] = {
        "source_commit": SOURCE_COMMIT,
        "source_root": SOURCE_ROOT,
        "runtime_site": RUNTIME_SITE,
        "runtime_probe": runtime_probe(),
        "capability_probe": capability_probe(),
        "source_manifest": artifact_manifest("source"),
        "runtime_manifest": artifact_manifest("runtime"),
        "owner_binding": owner_binding(module),
        "base_image": BASE_IMAGE,
        "temp_parent": TEMP_PARENT,
    }
    values.update(overrides)
    selected_binding = values["owner_binding"]
    assert isinstance(selected_binding, dict)
    if registry_payload is None:
        registry_payload = owner_registry_bytes(
            conversation_id=str(selected_binding["conversationId"]),
            project=Path(str(selected_binding["project"])),
        )
    module._read_codex_projects_registry = lambda path: registry_payload
    module._codex_registry_object_identity = lambda path: {
        "device": selected_binding["registryDevice"],
        "inode": selected_binding["registryInode"],
    }
    module._read_launcher_evidence = lambda path, **kwargs: {
        "device": selected_binding["launcherDevice"],
        "inode": selected_binding["launcherInode"],
        "sha256": selected_binding["launcherSha256"],
    }
    module._read_owner_process_evidence = lambda **kwargs: {
        "executable": selected_binding["codexExecutable"],
        "device": selected_binding["codexExecutableDevice"],
        "inode": selected_binding["codexExecutableInode"],
        "sha256": selected_binding["codexExecutableSha256"],
        "argv": selected_binding["codexArgv"],
    }
    if repository_identities is None:
        repository_identities = {
            Path(str(selected_binding["ownerProjectToplevel"])): {
                "topLevel": str(selected_binding["ownerProjectToplevel"]),
                "device": selected_binding["ownerProjectDevice"],
                "inode": selected_binding["ownerProjectInode"],
                "commonDirectory": str(selected_binding["gitCommonDirectory"]),
                "commonDevice": selected_binding["gitCommonDirectoryDevice"],
                "commonInode": selected_binding["gitCommonDirectoryInode"],
            },
            Path(str(selected_binding["sourceRoot"])): {
                "topLevel": str(selected_binding["sourceRoot"]),
                "device": selected_binding["sourceRootDevice"],
                "inode": selected_binding["sourceRootInode"],
                "commonDirectory": str(selected_binding["gitCommonDirectory"]),
                "commonDevice": selected_binding["gitCommonDirectoryDevice"],
                "commonInode": selected_binding["gitCommonDirectoryInode"],
            },
        }
    module._read_only_repository_identity = lambda path: repository_identities[path]
    return module.render_plan(**values)


def fake_stat(path: Path) -> SimpleNamespace:
    modes = {
        Path("/dev/kvm"): stat.S_IFCHR | 0o660,
        SOURCE_ROOT: stat.S_IFDIR | 0o755,
        RUNTIME_SITE: stat.S_IFDIR | 0o755,
        BASE_IMAGE: stat.S_IFREG | 0o640,
        FIRMWARE_CODE: stat.S_IFREG | 0o644,
        FIRMWARE_VARS_TEMPLATE: stat.S_IFREG | 0o644,
        TEMP_PARENT: stat.S_IFDIR | 0o1777,
        SESSION_RUNTIME_DIR: stat.S_IFDIR | 0o700,
        CODEX_PROJECTS_REGISTRY: stat.S_IFREG | 0o600,
    }
    firmware_paths = {FIRMWARE_CODE, FIRMWARE_VARS_TEMPLATE}
    return SimpleNamespace(
        st_mode=modes[path],
        st_uid=0 if path in firmware_paths else os.geteuid(),
        st_gid=0 if path in firmware_paths else os.getegid(),
        st_nlink=1,
    )


def repository_identity(path: Path) -> dict[str, object]:
    if path == OWNER_PROJECT:
        device, inode = OWNER_PROJECT_DEVICE, OWNER_PROJECT_INODE
    else:
        assert path == SOURCE_ROOT
        device, inode = SOURCE_ROOT_DEVICE, SOURCE_ROOT_INODE
    return {
        "topLevel": str(path),
        "device": device,
        "inode": inode,
        "commonDirectory": str(OWNER_PROJECT / ".git"),
        "commonDevice": GIT_COMMON_DEVICE,
        "commonInode": GIT_COMMON_INODE,
    }


def valid_preflight_kwargs(module) -> dict[str, object]:
    responses = {
        "git-status": "",
        "git-head": SOURCE_COMMIT,
        "git-files": "src/overseer/cli.py\0tests/phase_b_rehearsal/guest_rehearsal.py\0",
        "libvirt-uri": module.LIBVIRT_URI,
        "domains": "",
        "domain-capabilities": (
            "<domainCapabilities><domain>kvm</domain><arch>x86_64</arch>"
            f"<machine>{MACHINE_TYPE}</machine>"
            "<os supported='yes'><enum name='firmware'><value>efi</value></enum>"
            "<loader supported='yes'><value>/usr/share/OVMF/OVMF_CODE_4M.fd</value>"
            "<enum name='type'><value>pflash</value></enum>"
            "<enum name='readonly'><value>yes</value></enum>"
            "<enum name='secure'><value>no</value></enum></loader></os><devices>"
            "<filesystem supported='yes'><enum name='driverType'><value>path</value>"
            "</enum></filesystem></devices></domainCapabilities>"
        ),
        "qemu-img-info": json.dumps({"format": "qcow2", "filename": str(BASE_IMAGE)}),
        "import-probe": json.dumps(runtime_probe()),
    }
    return {
        "source_commit": SOURCE_COMMIT,
        "repo_root": SOURCE_ROOT,
        "source_root": SOURCE_ROOT,
        "owner_thread": OWNER_THREAD,
        "owner_project": OWNER_PROJECT,
        "codex_projects_registry": CODEX_PROJECTS_REGISTRY,
        "registry_reader": lambda path: owner_registry_bytes(),
        "registry_identity_reader": lambda path: {
            "device": REGISTRY_DEVICE,
            "inode": REGISTRY_INODE,
        },
        "launcher_evidence_reader": lambda path, **kwargs: {
            "device": LAUNCHER_DEVICE,
            "inode": LAUNCHER_INODE,
            "sha256": LAUNCHER_SHA256,
        },
        "owner_process_evidence_reader": lambda **kwargs: {
            "executable": str(CODEX_EXECUTABLE),
            "device": CODEX_EXECUTABLE_DEVICE,
            "inode": CODEX_EXECUTABLE_INODE,
            "sha256": CODEX_EXECUTABLE_SHA256,
            "argv": ["codex", "resume", OWNER_THREAD, "--cd", str(OWNER_PROJECT)],
        },
        "runtime_site": RUNTIME_SITE,
        "base_image": BASE_IMAGE,
        "temp_parent": TEMP_PARENT,
        "runner": lambda command: responses[command[0]],
        "repository_identity_probe": repository_identity,
        "source_git_probe": lambda path: {
            "status": responses["git-status"],
            "head": responses["git-head"],
            "files": responses["git-files"],
        },
        "path_exists": lambda path: path
        in {
            Path("/dev/kvm"),
            SOURCE_ROOT,
            RUNTIME_SITE,
            BASE_IMAGE,
            FIRMWARE_CODE,
            FIRMWARE_VARS_TEMPLATE,
            TEMP_PARENT,
            SESSION_RUNTIME_DIR,
            CODEX_PROJECTS_REGISTRY,
        },
        "path_stat": fake_stat,
        "path_access": lambda path, mode: True,
        "is_symlink": lambda path: False,
        "image_sha512": lambda path: module.BASE_IMAGE_SHA512,
        "firmware_sha256": lambda path: {
            FIRMWARE_CODE: module.FIRMWARE_CODE_SHA256,
            FIRMWARE_VARS_TEMPLATE: module.FIRMWARE_VARS_SHA256,
        }[path],
        "tool_exists": lambda path: str(path) in set(module.EXACT_TOOLS.values()),
        "tool_stat": lambda path: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
        ),
        "tool_access": lambda path, mode: True,
        "source_manifest_builder": lambda root, tracked: artifact_manifest("source"),
        "runtime_manifest_builder": lambda root: artifact_manifest("runtime"),
    }


def test_constants_pin_image_runtime_and_complete_future_tooling() -> None:
    module = load_tool()
    assert module.BASE_IMAGE_URL.endswith("debian-13-genericcloud-amd64.qcow2")
    assert module.BASE_IMAGE_SHA512 == (
        "184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003"
    )
    assert module.DEFAULT_RUNTIME_SITE == RUNTIME_SITE
    assert module.MACHINE_TYPE == MACHINE_TYPE
    assert module.REHEARSAL_SCHEMA == "overseer.phase-b-disposable-rehearsal-plan.v8"
    assert module.OWNER_BINDING_SCHEMA == "overseer.phase-b-rehearsal-owner-binding.v2"
    assert module.DEFAULT_CODEX_PROJECTS_REGISTRY == CODEX_PROJECTS_REGISTRY
    assert module.SESSION_RUNTIME_DIR == SESSION_RUNTIME_DIR
    assert module.MINIMAL_ENV["XDG_RUNTIME_DIR"] == str(SESSION_RUNTIME_DIR)
    assert module.MAX_SERIAL_BYTES == 1024 * 1024
    assert module.MAX_SERIAL_LINE_BYTES == 64 * 1024
    assert module.EXACT_TOOLS["python"] == "/usr/bin/python3.13"
    assert module.EXACT_TOOLS["genisoimage"] == "/usr/bin/genisoimage"
    assert "cloud-localds" not in module.EXACT_TOOLS
    assert all(Path(value).is_absolute() for value in module.EXACT_TOOLS.values())


def test_preflight_accepts_sticky_var_tmp_and_binds_runtime_probe() -> None:
    module = load_tool()
    result = module.preflight(**valid_preflight_kwargs(module))

    assert result["status"] == "passed"
    assert result["runtimeProbe"] == runtime_probe()
    assert result["runtimeProbeDigest"] == hashlib.sha256(
        module.canonical_json(runtime_probe()).encode()
    ).hexdigest()
    assert result["capabilityProbe"] == capability_probe()
    assert result["capabilityProbeDigest"] == hashlib.sha256(
        module.canonical_json(capability_probe()).encode()
    ).hexdigest()
    assert result["planInputs"]["networkDevices"] == []
    assert result["planInputs"]["sourceArtifact"]["manifest"] == artifact_manifest("source")
    assert result["planInputs"]["runtimeArtifact"]["manifest"] == artifact_manifest("runtime")
    assert result["tempDirectoryCreated"] is False
    assert result["sessionRuntimeDirectory"] == str(SESSION_RUNTIME_DIR)
    assert result["ownerBinding"] == owner_binding(module)


def test_preflight_binds_one_exact_registered_owner_before_probes() -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    result = module.preflight(**values)

    assert result["ownerBinding"]["conversationId"] == OWNER_THREAD
    assert result["ownerBinding"]["project"] == str(OWNER_PROJECT)
    assert result["ownerBinding"]["registryRowDigest"] == hashlib.sha256(
        module.canonical_json(result["ownerBinding"]["registryRow"]).encode()
    ).hexdigest()
    assert result["ownerBinding"]["codexExecutable"] == str(CODEX_EXECUTABLE)
    assert result["ownerBinding"]["codexArgv"] == [
        "codex",
        "resume",
        OWNER_THREAD,
        "--cd",
        str(OWNER_PROJECT),
    ]


def test_owner_process_evidence_requires_one_exact_codex_ancestor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_tool()
    expected_argv = ["codex", "resume", OWNER_THREAD, "--cd", str(OWNER_PROJECT)]
    snapshots = {
        40: {
            "pid": 40,
            "parentPid": 30,
            "startTime": 4,
            "argv": ["bash"],
            "executable": "/usr/bin/bash",
            "executableDevice": 1,
            "executableInode": 40,
        },
        30: {
            "pid": 30,
            "parentPid": 20,
            "startTime": 3,
            "argv": expected_argv,
            "executable": str(CODEX_EXECUTABLE),
            "executableDevice": CODEX_EXECUTABLE_DEVICE,
            "executableInode": CODEX_EXECUTABLE_INODE,
            "executableSha256": CODEX_EXECUTABLE_SHA256,
        },
        20: {
            "pid": 20,
            "parentPid": 1,
            "startTime": 2,
            "argv": ["tmux"],
            "executable": "/usr/bin/tmux",
            "executableDevice": 1,
            "executableInode": 20,
        },
    }
    monkeypatch.setattr(module.os, "getppid", lambda: 40)
    monkeypatch.setattr(
        module,
        "_read_process_snapshot",
        lambda pid, *, include_executable: snapshots[pid],
    )

    result = module._read_owner_process_evidence(
        conversation_id=OWNER_THREAD,
        project=OWNER_PROJECT,
    )

    assert result == {
        "executable": str(CODEX_EXECUTABLE),
        "device": CODEX_EXECUTABLE_DEVICE,
        "inode": CODEX_EXECUTABLE_INODE,
        "sha256": CODEX_EXECUTABLE_SHA256,
        "argv": expected_argv,
    }


def test_owner_process_evidence_rejects_nested_different_codex_ancestor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_tool()
    owner_argv = ["codex", "resume", OWNER_THREAD, "--cd", str(OWNER_PROJECT)]
    other = "019fefa5-f52a-74f3-8179-715e12d9cd2e"
    snapshots = {
        40: {
            "pid": 40,
            "parentPid": 30,
            "startTime": 4,
            "argv": ["codex", "resume", other, "--cd", str(OWNER_PROJECT)],
            "executable": "/opt/openai-codex/bin/codex",
            "executableDevice": CODEX_EXECUTABLE_DEVICE + 1,
            "executableInode": CODEX_EXECUTABLE_INODE + 1,
        },
        30: {
            "pid": 30,
            "parentPid": 20,
            "startTime": 3,
            "argv": owner_argv,
            "executable": str(CODEX_EXECUTABLE),
            "executableDevice": CODEX_EXECUTABLE_DEVICE,
            "executableInode": CODEX_EXECUTABLE_INODE,
        },
        20: {
            "pid": 20,
            "parentPid": 1,
            "startTime": 2,
            "argv": ["tmux"],
            "executable": "/usr/bin/tmux",
            "executableDevice": 1,
            "executableInode": 20,
        },
    }
    monkeypatch.setattr(module.os, "getppid", lambda: 40)
    monkeypatch.setattr(
        module,
        "_read_process_snapshot",
        lambda pid, *, include_executable: snapshots[pid],
    )

    with pytest.raises(module.PreflightError, match="exactly one Codex"):
        module._read_owner_process_evidence(
            conversation_id=OWNER_THREAD,
            project=OWNER_PROJECT,
        )


def test_owner_process_evidence_rejects_pid_reuse_between_ancestry_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_tool()
    expected_argv = ["codex", "resume", OWNER_THREAD, "--cd", str(OWNER_PROJECT)]
    snapshots = {
        40: {
            "pid": 40,
            "parentPid": 30,
            "startTime": 4,
            "argv": ["bash"],
            "executable": "/usr/bin/bash",
            "executableDevice": 1,
            "executableInode": 40,
        },
        30: {
            "pid": 30,
            "parentPid": 20,
            "startTime": 3,
            "argv": expected_argv,
            "executable": str(CODEX_EXECUTABLE),
            "executableDevice": CODEX_EXECUTABLE_DEVICE,
            "executableInode": CODEX_EXECUTABLE_INODE,
            "executableSha256": CODEX_EXECUTABLE_SHA256,
        },
        20: {
            "pid": 20,
            "parentPid": 1,
            "startTime": 2,
            "argv": ["tmux"],
            "executable": "/usr/bin/tmux",
            "executableDevice": 1,
            "executableInode": 20,
        },
    }
    calls = 0

    def changing_snapshot(pid: int, *, include_executable: bool) -> dict[str, object]:
        nonlocal calls
        calls += 1
        result = dict(snapshots[pid])
        if calls > 4 and pid == 40:
            result["startTime"] = 99
        return result

    monkeypatch.setattr(module.os, "getppid", lambda: 40)
    monkeypatch.setattr(module, "_read_process_snapshot", changing_snapshot)

    with pytest.raises(module.PreflightError, match="ancestry changed"):
        module._read_owner_process_evidence(
            conversation_id=OWNER_THREAD,
            project=OWNER_PROJECT,
        )


def test_future_owner_validator_is_valid_python_and_requires_process_lineage() -> None:
    module = load_tool()
    validator = module._future_owner_validator_python(
        owner_binding(module),
        source_commit=SOURCE_COMMIT,
        source_manifest=artifact_manifest("source"),
    )

    compile(validator, "<future-owner-validator>", "exec")
    assert "ttyname" not in validator
    assert "os.getppid()" in validator
    assert "pane_pid not in ancestry" in validator
    assert "first_ancestry=ancestry_snapshot();first_panes=pane_snapshot()" in validator
    assert "second_ancestry=ancestry_snapshot();second_panes=pane_snapshot()" in validator
    assert "first_ancestry!=second_ancestry" in validator
    assert "first_panes!=second_panes" in validator


def _generated_owner_authorizer(module):
    validator = module._future_owner_validator_python(
        owner_binding(module),
        source_commit=SOURCE_COMMIT,
        source_manifest=artifact_manifest("source"),
    )
    parsed = ast.parse(validator)
    authorize = next(
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name == "authorize"
    )
    namespace = {"expected": {"codexArgv": ["codex", "resume", OWNER_THREAD, "--cd", str(OWNER_PROJECT)]}}
    exec(compile(ast.Module(body=[authorize], type_ignores=[]), "<owner-authorizer>", "exec"), namespace)
    return namespace["authorize"]


def _generated_codex_classifier(module):
    validator = module._future_owner_validator_python(
        owner_binding(module),
        source_commit=SOURCE_COMMIT,
        source_manifest=artifact_manifest("source"),
    )
    parsed = ast.parse(validator)
    classify = next(
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name == "classify_codex"
    )
    namespace = {
        "os": os,
        "expected": {
            "codexExecutable": str(CODEX_EXECUTABLE),
            "codexExecutableDevice": CODEX_EXECUTABLE_DEVICE,
            "codexExecutableInode": CODEX_EXECUTABLE_INODE,
        },
    }
    exec(
        compile(
            ast.Module(body=[classify], type_ignores=[]),
            "<codex-classifier>",
            "exec",
        ),
        namespace,
    )
    return namespace["classify_codex"]


def _generated_owner_row_selector(module):
    validator = module._future_owner_validator_python(
        owner_binding(module),
        source_commit=SOURCE_COMMIT,
        source_manifest=artifact_manifest("source"),
    )
    parsed = ast.parse(validator)
    selector = next(
        node
        for node in parsed.body
        if isinstance(node, ast.FunctionDef) and node.name == "select_owner_row"
    )
    namespace = {
        "csv": module.csv,
        "io": module.io,
        "uuid": module.uuid,
        "expected": {"conversationId": OWNER_THREAD},
        "expected_registry_fields": list(module._CODEX_REGISTRY_FIELDS),
    }
    exec(
        compile(
            ast.Module(body=[selector], type_ignores=[]),
            "<owner-row-selector>",
            "exec",
        ),
        namespace,
    )
    return namespace["select_owner_row"]


def test_generated_owner_row_selector_rejects_canonical_uuid_alias_duplicate() -> None:
    module = load_tool()
    select_owner_row = _generated_owner_row_selector(module)
    payload = owner_registry_bytes()
    row = payload.splitlines(keepends=True)[1]
    alias = row.replace(OWNER_THREAD.encode(), OWNER_THREAD.upper().encode())

    selected = select_owner_row(payload.decode("utf-8"))
    assert selected["conversation_id"] == OWNER_THREAD
    with pytest.raises(SystemExit, match="noncanonical"):
        select_owner_row((payload + alias).decode("utf-8"))


def test_generated_codex_classifier_accepts_only_bound_executable() -> None:
    module = load_tool()
    classify = _generated_codex_classifier(module)

    assert classify(
        str(CODEX_EXECUTABLE),
        ["codex", "resume", OWNER_THREAD],
        CODEX_EXECUTABLE_DEVICE,
        CODEX_EXECUTABLE_INODE,
    ) is True
    assert classify("/usr/bin/bash", ["bash"], 1, 2) is False


@pytest.mark.parametrize(
    ("path", "argv", "device", "inode"),
    (
        ("/opt/alternate/bin/codex", ["other"], 1, 2),
        ("/usr/bin/node", ["/opt/alternate/bin/codex"], 1, 2),
        ("/usr/bin/node", ["node", "/opt/alternate/bin/codex"], 1, 2),
        ("/usr/bin/node", ["node", "/opt/@openai/codex/bin/codex.js"], 1, 2),
        ("/tmp/bound-hardlink", ["other"], CODEX_EXECUTABLE_DEVICE, CODEX_EXECUTABLE_INODE),
    ),
)
def test_generated_codex_classifier_rejects_non_bound_codex_signals(
    path: str, argv: list[str], device: int, inode: int
) -> None:
    module = load_tool()
    classify = _generated_codex_classifier(module)

    with pytest.raises(SystemExit):
        classify(path, argv, device, inode)


def _valid_generated_owner_lineage() -> tuple[
    list[dict[str, object]], list[tuple[str, str, str, str, int, str]]
]:
    owner_argv = ["codex", "resume", OWNER_THREAD, "--cd", str(OWNER_PROJECT)]
    return (
        [
            {"pid": 50, "parentPid": 40, "startTime": 5, "argv": ["bash"], "isCodex": False},
            {"pid": 40, "parentPid": 30, "startTime": 4, "argv": owner_argv, "isCodex": True},
            {"pid": 30, "parentPid": 20, "startTime": 3, "argv": ["owner-wrapper"], "isCodex": False},
            {"pid": 20, "parentPid": 1, "startTime": 2, "argv": ["tmux"], "isCodex": False},
        ],
        [("$7", f"codex-overseer-{OWNER_THREAD}", "@3", "%4", 30, "/dev/pts/3")],
    )


def test_generated_owner_authorizer_accepts_stable_exact_lineage() -> None:
    module = load_tool()
    authorize = _generated_owner_authorizer(module)
    ancestry, panes = _valid_generated_owner_lineage()

    authorize(ancestry, panes, list(ancestry), list(panes))


@pytest.mark.parametrize(
    "case",
    ("pid-reuse", "ancestor-exit", "pane-recreation", "nested-codex", "foreign-pane"),
)
def test_generated_owner_authorizer_rejects_unstable_or_foreign_lineage(
    case: str,
) -> None:
    module = load_tool()
    authorize = _generated_owner_authorizer(module)
    first_ancestry, first_panes = _valid_generated_owner_lineage()
    second_ancestry = [dict(record) for record in first_ancestry]
    second_panes = list(first_panes)
    if case == "pid-reuse":
        second_ancestry[0]["startTime"] = 99
    elif case == "ancestor-exit":
        second_ancestry.pop()
    elif case == "pane-recreation":
        second_panes = [
            ("$8", f"codex-overseer-{OWNER_THREAD}", "@4", "%5", 31, "/dev/pts/4")
        ]
    elif case == "nested-codex":
        nested = {
            "pid": 45,
            "parentPid": 40,
            "startTime": 45,
            "argv": ["codex", "resume", "019fefa5-f52a-74f3-8179-715e12d9cd2e"],
            "isCodex": True,
        }
        first_ancestry.insert(1, nested)
        second_ancestry.insert(1, dict(nested))
    else:
        first_panes = [
            ("$7", f"codex-overseer-{OWNER_THREAD}", "@3", "%4", 99, "/dev/pts/9")
        ]
        second_panes = list(first_panes)

    with pytest.raises(SystemExit):
        authorize(first_ancestry, first_panes, second_ancestry, second_panes)


def test_launcher_evidence_rejects_trailing_command_tokens(tmp_path: Path) -> None:
    module = load_tool()
    launcher = tmp_path / "launcher"
    command = f"codex-overseer-{OWNER_THREAD}"
    canonical = Path("/home/god/.local/bin") / command
    payload = canonical.read_text(encoding="utf-8").rstrip("\n") + " trailing extra\n"
    launcher.write_text(payload, encoding="utf-8")
    launcher.chmod(0o700)

    with pytest.raises(module.PreflightError, match="launcher content"):
        module._read_launcher_evidence(
            launcher,
            conversation_id=OWNER_THREAD,
            project=OWNER_PROJECT,
            command=command,
        )


@pytest.mark.parametrize("field", ("command", "launcher"))
def test_preflight_rejects_registry_command_or_launcher_not_bound_to_exact_owner(
    field: str,
) -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    registry = owner_registry_bytes()
    other = "019fefa5-f52a-74f3-8179-715e12d9cd2e"
    if field == "command":
        registry = registry.replace(
            f"codex-overseer-{OWNER_THREAD}".encode(),
            f"codex-overseer-{other}".encode(),
            1,
        )
    else:
        registry = registry.replace(
            f"/home/god/.local/bin/codex-overseer-{OWNER_THREAD}".encode(),
            f"/home/god/.local/bin/codex-overseer-{other}".encode(),
            1,
        )
    values["registry_reader"] = lambda path: registry

    with pytest.raises(module.PreflightError, match=field):
        module.preflight(**values)


def test_preflight_rejects_owner_project_from_different_git_repository() -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    def mismatched_identity(path: Path) -> dict[str, object]:
        identity = repository_identity(path)
        if path == SOURCE_ROOT:
            identity["commonDirectory"] = "/home/god/Documents/Codex Workspace/Other/.git"
            identity["commonInode"] = GIT_COMMON_INODE + 1
        return identity

    values["repository_identity_probe"] = mismatched_identity

    with pytest.raises(module.PreflightError, match="owner project repository"):
        module.preflight(**values)


def test_preflight_rejects_source_replacement_after_initial_identity_probe() -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    source_replaced = False

    def source_git_probe(path: Path) -> dict[str, str]:
        nonlocal source_replaced
        source_replaced = True
        return {
            "status": "",
            "head": SOURCE_COMMIT,
            "files": "src/overseer/cli.py\0tests/phase_b_rehearsal/guest_rehearsal.py\0",
        }

    def identity_probe(path: Path) -> dict[str, object]:
        identity = repository_identity(path)
        if path == SOURCE_ROOT and source_replaced:
            identity["inode"] = SOURCE_ROOT_INODE + 1
        return identity

    values["source_git_probe"] = source_git_probe
    values["repository_identity_probe"] = identity_probe

    with pytest.raises(module.PreflightError, match="changed during preflight"):
        module.preflight(**values)


def test_default_registry_reader_rejects_ancestor_symlink(tmp_path: Path) -> None:
    module = load_tool()
    real = tmp_path / "real"
    real.mkdir()
    registry = real / "codex-projects.csv"
    registry.write_bytes(owner_registry_bytes())
    registry.chmod(0o600)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(module.PreflightError, match="registry"):
        module._read_codex_projects_registry(linked / registry.name)


def test_default_registry_reader_rejects_post_read_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_tool()
    registry = tmp_path / "codex-projects.csv"
    registry.write_bytes(owner_registry_bytes())
    registry.chmod(0o600)
    moved = tmp_path / "replaced.csv"
    real_read = module.os.read
    replaced = False

    def replacing_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        payload = real_read(descriptor, size)
        if not payload and not replaced:
            registry.rename(moved)
            registry.write_bytes(owner_registry_bytes())
            registry.chmod(0o600)
            replaced = True
        return payload

    monkeypatch.setattr(module.os, "read", replacing_read)

    with pytest.raises(module.PreflightError, match="changed|replaced"):
        module._read_codex_projects_registry(registry)


def test_default_registry_reader_rejects_post_read_ancestor_symlink_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_tool()
    parent = tmp_path / "authoritative"
    parent.mkdir()
    registry = parent / "codex-projects.csv"
    registry.write_bytes(owner_registry_bytes())
    registry.chmod(0o600)
    moved = tmp_path / "moved"
    real_read = module.os.read
    replaced = False

    def replacing_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        payload = real_read(descriptor, size)
        if not payload and not replaced:
            parent.rename(moved)
            parent.symlink_to(moved, target_is_directory=True)
            replaced = True
        return payload

    monkeypatch.setattr(module.os, "read", replacing_read)

    with pytest.raises(module.PreflightError, match="registry"):
        module._read_codex_projects_registry(registry)


def test_repository_identity_rejects_non_toplevel_directory(tmp_path: Path) -> None:
    module = load_tool()
    repository = tmp_path / "repository"
    subprocess.run(["/usr/bin/git", "init", "-q", str(repository)], check=True)
    nested = repository / "nested"
    nested.mkdir()

    with pytest.raises(module.PreflightError, match="top level"):
        module._read_only_repository_identity(nested)


def test_repository_identity_rejects_ancestor_replacement_during_git_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_tool()
    repository = tmp_path / "repository"
    subprocess.run(["/usr/bin/git", "init", "-q", str(repository)], check=True)
    moved = tmp_path / "moved"
    real_run = module.subprocess.run
    replaced = False

    def replacing_run(*args: object, **kwargs: object):
        nonlocal replaced
        completed = real_run(*args, **kwargs)
        if not replaced:
            repository.rename(moved)
            repository.symlink_to(moved, target_is_directory=True)
            replaced = True
        return completed

    monkeypatch.setattr(module.subprocess, "run", replacing_run)

    with pytest.raises(module.PreflightError, match="repository"):
        module._read_only_repository_identity(repository)


def test_source_git_state_rejects_ancestor_replacement_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_tool()
    repository = tmp_path / "repository"
    subprocess.run(["/usr/bin/git", "init", "-q", str(repository)], check=True)
    (repository / "tracked.txt").write_text("approved\n", encoding="utf-8")
    subprocess.run(["/usr/bin/git", "-C", str(repository), "add", "tracked.txt"], check=True)
    subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(repository),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    moved = tmp_path / "moved"
    real_run = module.subprocess.run
    replaced = False

    def replacing_run(*args: object, **kwargs: object):
        nonlocal replaced
        completed = real_run(*args, **kwargs)
        if not replaced:
            repository.rename(moved)
            repository.symlink_to(moved, target_is_directory=True)
            replaced = True
        return completed

    monkeypatch.setattr(module.subprocess, "run", replacing_run)

    with pytest.raises(module.PreflightError, match="Git state"):
        module._read_only_source_git_state(repository)


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("alias", "conversation id"),
        ("missing", "exactly once"),
        ("duplicate", "exactly once"),
        ("canonical-alias-duplicate", "noncanonical"),
        ("wrong-project", "owner project"),
        ("linked-registry", "registry"),
        ("malformed-registry", "header"),
        ("unterminated-quoted-field", "CSV"),
        ("unterminated-quoted-header", "CSV"),
        ("wrong-registry-owner", "registry object"),
        ("unsafe-registry-mode", "registry object"),
    ),
)
def test_preflight_rejects_inexact_owner_before_any_probe(case: str, message: str) -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    calls: list[tuple[str, ...]] = []
    original_runner = values["runner"]
    values["runner"] = lambda command: calls.append(command) or original_runner(command)
    if case == "alias":
        values["owner_thread"] = "approval-smoke-v1-1-6"
    elif case == "missing":
        values["registry_reader"] = lambda path: owner_registry_bytes(
            conversation_id="019fefa5-f52a-74f3-8179-715e12d9cd2e"
        )
    elif case == "duplicate":
        values["registry_reader"] = lambda path: owner_registry_bytes(duplicate=True)
    elif case == "canonical-alias-duplicate":
        payload = owner_registry_bytes()
        row = payload.splitlines(keepends=True)[1]
        alias = row.replace(OWNER_THREAD.encode(), OWNER_THREAD.upper().encode())
        values["registry_reader"] = lambda path: payload + alias
    elif case == "wrong-project":
        values["registry_reader"] = lambda path: owner_registry_bytes(
            project=Path("/home/god/Documents/Codex Workspace/Roadex")
        )
    elif case == "linked-registry":
        original_is_symlink = values["is_symlink"]
        values["is_symlink"] = lambda path: (
            path == CODEX_PROJECTS_REGISTRY or original_is_symlink(path)
        )
    elif case == "malformed-registry":
        values["registry_reader"] = lambda path: b"conversation_id,project\n"
    elif case == "unterminated-quoted-field":
        values["registry_reader"] = lambda path: owner_registry_bytes().replace(
            b"codex-state,\n", b'codex-state,"unterminated\n'
        )
    elif case == "unterminated-quoted-header":
        values["registry_reader"] = lambda path: (
            b'conversation_id,label,project,command,launcher,created_at,updated_at,source,"notes\n'
        )
    else:
        original_stat = values["path_stat"]

        def path_stat(path: Path):
            state = original_stat(path)
            if path != CODEX_PROJECTS_REGISTRY:
                return state
            return SimpleNamespace(
                st_mode=(
                    stat.S_IFREG | 0o620
                    if case == "unsafe-registry-mode"
                    else state.st_mode
                ),
                st_uid=(
                    state.st_uid
                    if case == "unsafe-registry-mode"
                    else os.geteuid() + 1
                ),
                st_gid=state.st_gid,
                st_nlink=1,
            )

        values["path_stat"] = path_stat

    with pytest.raises(module.PreflightError, match=message):
        module.preflight(**values)

    assert calls == []


@pytest.mark.parametrize(
    "case",
    ("missing", "linked", "wrong-owner", "unsafe-mode"),
)
def test_preflight_rejects_unsafe_session_runtime_before_any_probe(case: str) -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    calls: list[tuple[str, ...]] = []
    original_runner = values["runner"]
    values["runner"] = lambda command: calls.append(command) or original_runner(command)
    if case == "missing":
        original_exists = values["path_exists"]
        values["path_exists"] = lambda path: path != SESSION_RUNTIME_DIR and original_exists(path)
    elif case == "linked":
        values["is_symlink"] = lambda path: path == SESSION_RUNTIME_DIR
    else:
        original_stat = values["path_stat"]

        def path_stat(path: Path):
            state = original_stat(path)
            if path != SESSION_RUNTIME_DIR:
                return state
            if case == "wrong-owner":
                return SimpleNamespace(
                    st_mode=state.st_mode,
                    st_uid=os.geteuid() + 1,
                    st_gid=state.st_gid,
                    st_nlink=1,
                )
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o750,
                st_uid=state.st_uid,
                st_gid=state.st_gid,
                st_nlink=1,
            )

        values["path_stat"] = path_stat

    with pytest.raises(module.PreflightError, match="session runtime"):
        module.preflight(**values)

    assert calls == []


@pytest.mark.parametrize("machine", ("", "pc-i440fx-9.2"))
def test_preflight_rejects_missing_or_wrong_machine_capability(machine: str) -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    original_runner = values["runner"]

    def runner(command: tuple[str, ...]) -> str:
        value = original_runner(command)
        if command[0] != "domain-capabilities":
            return value
        if not machine:
            return value.replace(f"<machine>{MACHINE_TYPE}</machine>", "")
        return value.replace(MACHINE_TYPE, machine)

    values["runner"] = runner
    with pytest.raises(module.PreflightError, match="KVM path filesystem capability"):
        module.preflight(**values)


@pytest.mark.parametrize(
    "firmware_path",
    (FIRMWARE_CODE, FIRMWARE_VARS_TEMPLATE),
)
def test_preflight_rejects_unverified_firmware_digest(firmware_path: Path) -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    expected = values["firmware_sha256"]
    values["firmware_sha256"] = lambda path: (
        "0" * 64 if path == firmware_path else expected(path)
    )

    with pytest.raises(module.PreflightError, match="firmware.*SHA-256"):
        module.preflight(**values)


@pytest.mark.parametrize(
    "firmware_path",
    (FIRMWARE_CODE, FIRMWARE_VARS_TEMPLATE),
)
def test_preflight_rejects_linked_firmware(firmware_path: Path) -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    values["is_symlink"] = lambda path: path == firmware_path

    with pytest.raises(module.PreflightError, match="firmware.*missing or linked"):
        module.preflight(**values)


def test_preflight_rejects_domain_capabilities_without_exact_uefi_loader() -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    original_runner = values["runner"]
    values["runner"] = lambda command: (
        "<domainCapabilities><domain>kvm</domain><arch>x86_64</arch><devices>"
        "<filesystem supported='yes'><enum name='driverType'><value>path</value>"
        "</enum></filesystem></devices></domainCapabilities>"
        if command[0] == "domain-capabilities"
        else original_runner(command)
    )

    with pytest.raises(module.PreflightError, match="KVM path filesystem capability"):
        module.preflight(**values)


def _run_domain_ownership_validator(module, plan: dict[str, object], root: ET.Element):
    return subprocess.run(
        (
            sys.executable,
            "-B",
            "-s",
            "-P",
            "-S",
            "-c",
            module._ownership_validator_python(),
            plan["vm"]["name"],
            plan["vm"]["uuid"],
            plan["vm"]["runId"],
            "/tmp/owned/overlay.qcow2",
            "/tmp/owned/seed.iso",
            "/tmp/owned/serial",
            str(BASE_IMAGE),
            "/tmp/owned/nvram.fd",
            str(FIRMWARE_CODE),
            str(FIRMWARE_VARS_TEMPLATE),
            MACHINE_TYPE,
        ),
        input=ET.tostring(root, encoding="unicode"),
        check=False,
        capture_output=True,
        text=True,
    )


def _captured_active_dumpxml_root(
    plan: dict[str, object], *, with_uefi: bool
) -> ET.Element:
    xml = ACTIVE_DUMPXML_FIXTURE.read_text(encoding="utf-8")
    replacements = {
        "${VM_NAME}": str(plan["vm"]["name"]),
        "${VM_UUID}": str(plan["vm"]["uuid"]),
        "${RUN_ID}": str(plan["vm"]["runId"]),
        "${OVERLAY}": "/tmp/owned/overlay.qcow2",
        "${SEED_ISO}": "/tmp/owned/seed.iso",
        "${SERIAL_PIPE}": "/tmp/owned/serial",
        "${BASE_IMAGE}": str(BASE_IMAGE),
    }
    for placeholder, value in replacements.items():
        xml = xml.replace(placeholder, value)
    root = ET.fromstring(xml)
    if with_uefi:
        os_node = root.find("./os")
        boot = root.find("./os/boot")
        assert os_node is not None and boot is not None
        os_node.set("firmware", "efi")
        loader = ET.Element(
            "loader",
            {"readonly": "yes", "secure": "no", "type": "pflash"},
        )
        loader.text = str(FIRMWARE_CODE)
        nvram = ET.Element(
            "nvram", {"template": str(FIRMWARE_VARS_TEMPLATE)}
        )
        nvram.text = "/tmp/owned/nvram.fd"
        os_node.insert(list(os_node).index(boot), loader)
        os_node.insert(list(os_node).index(boot), nvram)
    return root


def _captured_inactive_efi_dumpxml_root(plan: dict[str, object]) -> ET.Element:
    xml = INACTIVE_EFI_DUMPXML_FIXTURE.read_text(encoding="utf-8")
    replacements = {
        "${VM_NAME}": str(plan["vm"]["name"]),
        "${VM_UUID}": str(plan["vm"]["uuid"]),
        "${RUN_ID}": str(plan["vm"]["runId"]),
        "${OVERLAY}": "/tmp/owned/overlay.qcow2",
        "${SEED_ISO}": "/tmp/owned/seed.iso",
        "${SERIAL_PIPE}": "/tmp/owned/serial",
        "${NVRAM}": "/tmp/owned/nvram.fd",
    }
    for placeholder, value in replacements.items():
        xml = xml.replace(placeholder, value)
    return ET.fromstring(xml)


def test_domain_ownership_validator_accepts_observed_inactive_efi_normalization() -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = _captured_inactive_efi_dumpxml_root(plan)

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode == 0, completed.stderr


def test_domain_ownership_validator_accepts_canonical_efi_during_active_attestation() -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = _captured_active_dumpxml_root(plan, with_uefi=True)
    os_node = root.find("./os")
    loader = root.find("./os/loader")
    nvram = root.find("./os/nvram")
    assert os_node is not None and loader is not None and nvram is not None
    firmware = ET.Element("firmware")
    ET.SubElement(firmware, "feature", {"enabled": "no", "name": "enrolled-keys"})
    ET.SubElement(firmware, "feature", {"enabled": "no", "name": "secure-boot"})
    os_node.insert(list(os_node).index(loader), firmware)
    loader.set("format", "raw")
    nvram.set("templateFormat", "raw")
    nvram.set("format", "raw")

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "mutation",
    (
        "enrolled-keys-enabled",
        "secure-boot-enabled",
        "extra-firmware-feature",
        "reordered-firmware-features",
        "loader-format",
        "nvram-format",
        "nvram-template-format",
    ),
)
def test_domain_ownership_validator_rejects_mutated_inactive_efi_normalization(
    mutation: str,
) -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = _captured_inactive_efi_dumpxml_root(plan)
    firmware = root.find("./os/firmware")
    loader = root.find("./os/loader")
    nvram = root.find("./os/nvram")
    assert firmware is not None and loader is not None and nvram is not None
    if mutation == "enrolled-keys-enabled":
        firmware.find("./feature[@name='enrolled-keys']").set("enabled", "yes")
    elif mutation == "secure-boot-enabled":
        firmware.find("./feature[@name='secure-boot']").set("enabled", "yes")
    elif mutation == "extra-firmware-feature":
        ET.SubElement(firmware, "feature", {"enabled": "no", "name": "unknown"})
    elif mutation == "reordered-firmware-features":
        firmware[:] = list(reversed(list(firmware)))
    elif mutation == "loader-format":
        loader.set("format", "qcow2")
    elif mutation == "nvram-format":
        nvram.set("format", "qcow2")
    else:
        nvram.set("templateFormat", "qcow2")

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


def test_domain_ownership_validator_accepts_captured_active_libvirt_normalization() -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = _captured_active_dumpxml_root(plan, with_uefi=True)

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode == 0, completed.stderr


def test_domain_ownership_validator_rejects_captured_bios_boot_domain() -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = _captured_active_dumpxml_root(plan, with_uefi=False)

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


@pytest.mark.parametrize(
    "mutation",
    (
        "cpu-feature-policy",
        "disk-source-index",
        "backing-index",
        "cdrom-index",
        "console-alias",
        "firmware-loader",
        "nvram-path",
    ),
)
def test_domain_ownership_validator_rejects_mutated_captured_active_xml(
    mutation: str,
) -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = _captured_active_dumpxml_root(plan, with_uefi=True)
    if mutation == "cpu-feature-policy":
        feature = root.find("./cpu/feature[@name='x2apic']")
        assert feature is not None
        feature.set("policy", "optional")
    elif mutation == "disk-source-index":
        source = root.find("./devices/disk[@device='disk']/source")
        assert source is not None
        source.set("index", "9")
    elif mutation == "backing-index":
        backing = root.find("./devices/disk[@device='disk']/backingStore")
        assert backing is not None
        backing.set("index", "9")
    elif mutation == "cdrom-index":
        source = root.find("./devices/disk[@device='cdrom']/source")
        assert source is not None
        source.set("index", "9")
    elif mutation == "console-alias":
        alias = root.find("./devices/console/alias")
        assert alias is not None
        alias.set("name", "foreign-console")
    elif mutation == "firmware-loader":
        loader = root.find("./os/loader")
        assert loader is not None
        loader.text = "/tmp/foreign-firmware.fd"
    else:
        nvram = root.find("./os/nvram")
        assert nvram is not None
        nvram.text = "/tmp/foreign-nvram.fd"

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


def _libvirt_pipe_console_root(
    module,
    *,
    active: bool = False,
) -> tuple[dict[str, object], ET.Element]:
    plan = render(module)["plan"]
    root = ET.fromstring(
        plan["domainXml"]
        .replace("$" + "{OVERLAY}", "/tmp/owned/overlay.qcow2")
        .replace("$" + "{SEED_ISO}", "/tmp/owned/seed.iso")
        .replace("$" + "{SERIAL_PIPE}", "/tmp/owned/serial")
        .replace("$" + "{NVRAM}", "/tmp/owned/nvram.fd")
    )
    serial_target = root.find("./devices/serial/target")
    console = root.find("./devices/console")
    assert serial_target is not None and console is not None
    ET.SubElement(serial_target, "model", {"name": "isa-serial"})
    console.clear()
    console.set("type", "pipe")
    ET.SubElement(console, "source", {"path": "/tmp/owned/serial"})
    ET.SubElement(console, "target", {"type": "serial", "port": "0"})
    if active:
        root.set("id", "7")
        os_type = root.find("./os/type")
        assert os_type is not None
        os_type.set("machine", "pc-i440fx-10.0")
        overlay = next(
            disk
            for disk in root.findall("./devices/disk")
            if disk.attrib["device"] == "disk"
        )
        overlay_source = overlay.find("source")
        assert overlay_source is not None
        overlay_source.set("index", "2")
        backing = ET.SubElement(overlay, "backingStore", {"type": "file", "index": "3"})
        ET.SubElement(backing, "format", {"type": "qcow2"})
        ET.SubElement(backing, "source", {"file": str(BASE_IMAGE)})
        ET.SubElement(backing, "backingStore")
        cdrom = next(
            disk
            for disk in root.findall("./devices/disk")
            if disk.attrib["device"] == "cdrom"
        )
        cdrom_source = cdrom.find("source")
        assert cdrom_source is not None
        cdrom_source.set("index", "1")
        ET.SubElement(cdrom, "backingStore")
        serial = root.find("./devices/serial")
        assert serial is not None
        ET.SubElement(serial, "alias", {"name": "serial0"})
        ET.SubElement(console, "alias", {"name": "serial0"})
        cpu = ET.SubElement(
            root, "cpu", {"mode": "custom", "match": "exact", "check": "full"}
        )
        ET.SubElement(cpu, "model", {"fallback": "forbid"}).text = "qemu64"
        for name, policy in (
            ("x2apic", "require"),
            ("hypervisor", "require"),
            ("lahf_lm", "require"),
            ("svm", "disable"),
        ):
            ET.SubElement(cpu, "feature", {"policy": policy, "name": name})
        ET.SubElement(root, "clock", {"offset": "utc"})
    ET.indent(root, space="  ")
    return plan, root


@pytest.mark.parametrize("active", (False, True))
def test_domain_ownership_validator_accepts_exact_libvirt_pipe_console_normalization(
    active: bool,
) -> None:
    module = load_tool()
    plan, root = _libvirt_pipe_console_root(module, active=active)

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode == 0, completed.stderr


def test_domain_ownership_validator_rejects_foreign_libvirt_pipe_console_source() -> None:
    module = load_tool()
    plan, root = _libvirt_pipe_console_root(module)
    source = root.find("./devices/console/source")
    assert source is not None
    source.set("path", "/tmp/foreign/serial")

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


@pytest.mark.parametrize(
    ("attribute", "value"),
    (("name", "foreign-model"), ("text", "unapproved")),
)
def test_domain_ownership_validator_rejects_mutated_libvirt_serial_model(
    attribute: str,
    value: str,
) -> None:
    module = load_tool()
    plan, root = _libvirt_pipe_console_root(module)
    target = root.find("./devices/serial/target")
    model = root.find("./devices/serial/target/model")
    assert target is not None and model is not None
    if attribute == "text":
        target.text = value
    else:
        model.set(attribute, value)

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


@pytest.mark.parametrize(
    "mutation",
    ("model-tail", "console-text", "source-tail", "console-address"),
)
def test_domain_ownership_validator_rejects_pipe_console_mixed_content_and_metadata(
    mutation: str,
) -> None:
    module = load_tool()
    plan, root = _libvirt_pipe_console_root(module)
    console = root.find("./devices/console")
    source = root.find("./devices/console/source")
    model = root.find("./devices/serial/target/model")
    assert console is not None and source is not None and model is not None
    if mutation == "model-tail":
        model.tail = "UNAPPROVED"
    elif mutation == "console-text":
        console.text = "UNAPPROVED"
    elif mutation == "source-tail":
        source.tail = "UNAPPROVED"
    else:
        ET.SubElement(
            console,
            "address",
            {
                "type": "pci",
                "domain": "0x0000",
                "bus": "0x00",
                "slot": "0x03",
                "function": "0x0",
            },
        )

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


def test_domain_ownership_validator_accepts_whitespace_only_libvirt_model_text() -> None:
    module = load_tool()
    plan, root = _libvirt_pipe_console_root(module)
    model = root.find("./devices/serial/target/model")
    assert model is not None
    model.text = " \n "

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "path",
    (
        "./os/boot",
        "./clock",
        "./metadata/{urn:overseer:phase-b-rehearsal}run",
    ),
)
def test_domain_ownership_validator_rejects_text_in_empty_leaf_nodes(path: str) -> None:
    module = load_tool()
    plan, root = _libvirt_pipe_console_root(module)
    node = root.find(path)
    if path == "./clock" and node is None:
        node = ET.SubElement(root, "clock", {"offset": "utc"})
    assert node is not None
    node.text = "UNAPPROVED"

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("dirty", "dirty"),
        ("missing-kvm", "KVM"),
        ("regular-kvm", "character"),
        ("inaccessible-kvm", "accessible"),
        ("unsafe-source", "source path"),
        ("different-source", "validated repository"),
        ("relative-runtime", "runtime path"),
        ("traversal-image", "base image path"),
        ("unsafe-temp", "temporary path"),
        ("raw-image", "qcow2"),
        ("backed-image", "backing"),
        ("failed-import", "import probe"),
        ("missing-filesystem", "filesystem"),
        ("missing-path-driver", "filesystem"),
        ("missing-tool", "tooling"),
    ),
)
def test_preflight_rejects_unsafe_kvm_path_image_runtime_and_tool_states(case: str, message: str) -> None:
    module = load_tool()
    values = valid_preflight_kwargs(module)
    original_runner = values["runner"]
    if case == "dirty":
        values["source_git_probe"] = lambda path: {
            "status": " M file",
            "head": SOURCE_COMMIT,
            "files": "src/overseer/cli.py\0tests/phase_b_rehearsal/guest_rehearsal.py\0",
        }
    elif case == "missing-kvm":
        values["path_exists"] = lambda path: path != Path("/dev/kvm")
    elif case == "regular-kvm":
        values["path_stat"] = lambda path: SimpleNamespace(
            st_mode=(stat.S_IFREG | 0o660) if path == Path("/dev/kvm") else fake_stat(path).st_mode,
            st_uid=os.geteuid(),
            st_gid=os.getegid(),
        )
    elif case == "inaccessible-kvm":
        values["path_access"] = lambda path, mode: path != Path("/dev/kvm")
    elif case == "unsafe-source":
        values["source_root"] = Path("/unsafe/$source")
    elif case == "different-source":
        values["source_root"] = SOURCE_ROOT / "copy"
    elif case == "relative-runtime":
        values["runtime_site"] = Path("relative/runtime")
    elif case == "traversal-image":
        values["base_image"] = Path("/unsafe/../base.qcow2")
    elif case == "unsafe-temp":
        values["temp_parent"] = Path("/tmp/unsafe;path")
    elif case == "raw-image":
        values["runner"] = lambda command: '{"format":"raw"}' if command[0] == "qemu-img-info" else original_runner(command)
    elif case == "backed-image":
        values["runner"] = lambda command: (
            '{"format":"qcow2","backing-filename":"/tmp/unapproved-base"}'
            if command[0] == "qemu-img-info"
            else original_runner(command)
        )
    elif case == "failed-import":
        values["runner"] = lambda command: '{"status":"failed"}' if command[0] == "import-probe" else original_runner(command)
    elif case == "missing-filesystem":
        values["runner"] = lambda command: (
            "<domainCapabilities><domain>kvm</domain><arch>x86_64</arch><devices>"
            "<filesystem supported='no'/></devices></domainCapabilities>"
            if command[0] == "domain-capabilities"
            else original_runner(command)
        )
    elif case == "missing-path-driver":
        values["runner"] = lambda command: (
            "<domainCapabilities><domain>kvm</domain><arch>x86_64</arch><devices>"
            "<filesystem supported='yes'><enum name='driverType'><value>virtiofs</value>"
            "</enum></filesystem></devices></domainCapabilities>"
            if command[0] == "domain-capabilities"
            else original_runner(command)
        )
    elif case == "missing-tool":
        values["tool_exists"] = lambda path: str(path) != module.EXACT_TOOLS["awk"]
    with pytest.raises(module.PreflightError, match=message):
        module.preflight(**values)


def test_preflight_plan_shape_is_derived_not_caller_asserted() -> None:
    module = load_tool()
    parameters = inspect.signature(module.preflight).parameters
    assert "source_share_spec" not in parameters
    assert "network_devices" not in parameters


def test_preflight_uses_only_read_only_probe_labels() -> None:
    module = load_tool()
    calls: list[tuple[str, ...]] = []
    values = valid_preflight_kwargs(module)
    original = values["runner"]

    def runner(command: tuple[str, ...]) -> str:
        calls.append(command)
        return original(command)

    values["runner"] = runner
    module.preflight(**values)

    assert {command[0] for command in calls} == {
        "libvirt-uri",
        "domains",
        "domain-capabilities",
        "qemu-img-info",
        "import-probe",
    }
    assert not any({"define", "start", "shutdown", "undefine", "create", "rm"} & set(command) for command in calls)


def test_default_runner_import_probe_is_no_bytecode_and_all_commands_are_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_tool()
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def fake_run(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return SimpleNamespace(stdout="{}\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    probes = (
        ("git-status", str(SOURCE_ROOT)),
        ("git-head", str(SOURCE_ROOT)),
        ("git-files", str(SOURCE_ROOT)),
        ("libvirt-uri",),
        ("domains",),
        ("domain-capabilities",),
        ("qemu-img-info", str(BASE_IMAGE)),
        (
            "import-probe",
            str(SOURCE_ROOT),
            str(RUNTIME_SITE),
            module.canonical_json(artifact_manifest("source")),
            module.canonical_json(artifact_manifest("runtime")),
        ),
    )
    for probe in probes:
        module._read_only_runner(probe)

    rendered = "\n".join(" ".join(argv) for argv, _ in calls)
    assert " define " not in rendered and " start " not in rendered and " shutdown " not in rendered
    import_argv, import_kwargs = calls[-1]
    assert import_argv[:6] == ("/usr/bin/python3.13", "-B", "-s", "-P", "-S", "-c")
    assert all(name in import_argv[6] for name in EXPECTED_IMPORTS)
    assert "ManifestFinder" in import_argv[6]
    assert "sys.pycache_prefix" in import_argv[6]
    assert "sys.version_info[:2] == (3,13)" in import_argv[6]
    assert import_kwargs["env"] == module.MINIMAL_ENV
    for argv, kwargs in calls:
        assert Path(argv[0]).is_absolute()
        assert kwargs["env"] == module.MINIMAL_ENV

    capability_argv = next(argv for argv, _ in calls if "domcapabilities" in argv)
    assert capability_argv[-2:] == ("--machine", MACHINE_TYPE)


def test_default_runner_ignores_path_pythonpath_and_loader_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_tool()
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    monkeypatch.setenv("PATH", "/tmp/hostile")
    monkeypatch.setenv("PYTHONPATH", "/tmp/hostile-python")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/hostile.so")

    def fake_run(argv, **kwargs):
        calls.append((tuple(argv), kwargs))
        return SimpleNamespace(stdout="\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    module._read_only_runner(("git-head", str(SOURCE_ROOT)))

    assert calls == [
        (
            (
                "/usr/bin/git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-C",
                str(SOURCE_ROOT),
                "rev-parse",
                "HEAD",
            ),
            {
                "check": True,
                "capture_output": True,
                "text": True,
                "stdin": subprocess.DEVNULL,
                "env": module.MINIMAL_ENV,
            },
        )
    ]


def test_git_status_disables_configured_fsmonitor_and_optional_locks(
    tmp_path: Path,
) -> None:
    module = load_tool()
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(("/usr/bin/git", "init", "-q", str(repository)), check=True)
    marker = tmp_path / "fsmonitor-ran"
    helper = tmp_path / "fsmonitor-helper"
    helper.write_text(
        "#!/usr/bin/bash\nprintf ran >" + shlex.quote(str(marker)) + "\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)
    subprocess.run(
        ("/usr/bin/git", "-C", str(repository), "config", "core.fsmonitor", str(helper)),
        check=True,
    )

    assert module._read_only_runner(("git-status", str(repository))) == ""
    assert not marker.exists()
    assert module.MINIMAL_ENV["GIT_OPTIONAL_LOCKS"] == "0"
    assert module.MINIMAL_ENV["GIT_CONFIG_NOSYSTEM"] == "1"


def test_source_manifest_is_tracked_only_and_rejects_post_plan_replacement(
    tmp_path: Path,
) -> None:
    module = load_tool()
    root = tmp_path / "source"
    tracked = root / "src/overseer/cli.py"
    ignored_pyc = root / "src/overseer/__pycache__/cli.cpython-313.pyc"
    ignored_secret = root / ".env.secret"
    tracked.parent.mkdir(parents=True)
    ignored_pyc.parent.mkdir(parents=True)
    tracked.write_text("VALUE = 'tracked'\n", encoding="utf-8")
    py_compile.compile(str(tracked), cfile=str(ignored_pyc), doraise=True)
    ignored_secret.write_text("do-not-package\n", encoding="utf-8")

    manifest = module.build_source_manifest(root, ("src/overseer/cli.py",))
    paths = {item["path"] for item in manifest["files"]}

    assert paths == {"src/overseer/cli.py"}
    assert not any("__pycache__" in path or path.endswith(".pyc") for path in paths)
    assert ".env.secret" not in paths
    assert b"do-not-package" not in module.build_artifact_archive(root, manifest)

    tracked.write_text("VALUE = 'replaced'\n", encoding="utf-8")
    with pytest.raises(module.PreflightError, match="changed after manifest"):
        module.build_artifact_archive(root, manifest)


def test_source_manifest_rejects_symlinked_ancestor_directory(tmp_path: Path) -> None:
    module = load_tool()
    root = tmp_path / "source"
    outside = tmp_path / "outside"
    package = outside / "overseer"
    root.mkdir()
    package.mkdir(parents=True)
    (package / "cli.py").write_text("VALUE = 'outside'\n", encoding="utf-8")
    (root / "src").symlink_to(outside, target_is_directory=True)

    with pytest.raises(module.PreflightError, match="artifact file"):
        module.build_source_manifest(root, ("src/overseer/cli.py",))


def test_import_probe_ignores_valid_adjacent_untracked_bytecode(
    tmp_path: Path,
) -> None:
    module = load_tool()
    source = tmp_path / "source"
    package = source / "src/overseer"
    runtime = tmp_path / "runtime"
    cryptography = runtime / "cryptography"
    package.mkdir(parents=True)
    cryptography.mkdir(parents=True)
    marker = tmp_path / "malicious-bytecode-ran"
    malicious = f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n"
    benign = "VALUE = 'benign'\n"
    benign += "#" * (len(malicious) - len(benign) - 1) + "\n"
    assert len(benign) == len(malicious)
    cli = package / "cli.py"
    cli.write_text(malicious, encoding="utf-8")
    timestamp = 1_700_000_000
    os.utime(cli, (timestamp, timestamp))
    pycache = package / "__pycache__"
    pycache.mkdir()
    pyc = pycache / f"cli.{sys.implementation.cache_tag}.pyc"
    py_compile.compile(str(cli), cfile=str(pyc), doraise=True)
    cli.write_text(benign, encoding="utf-8")
    os.utime(cli, (timestamp, timestamp))
    for relative in ("__init__.py", "user_bridge.py", "admin_executor.py"):
        (package / relative).write_text("VALUE = 'safe'\n", encoding="utf-8")
    (cryptography / "__init__.py").write_text("VALUE = 'safe'\n", encoding="utf-8")
    (runtime / "_cffi_backend.cpython-313-x86_64-linux-gnu.so").write_bytes(b"fixture")
    tracked = (
        "src/overseer/__init__.py",
        "src/overseer/admin_executor.py",
        "src/overseer/cli.py",
        "src/overseer/user_bridge.py",
    )
    source_manifest = module.build_source_manifest(source, tracked)
    runtime_manifest = module.build_runtime_manifest(runtime)

    output = module._read_only_runner(
        (
            "import-probe",
            str(source),
            str(runtime),
            module.canonical_json(source_manifest),
            module.canonical_json(runtime_manifest),
        )
    )

    assert json.loads(output)["status"] == "passed"
    assert not marker.exists()


def test_import_probe_rejects_manifested_path_replacement_before_execution(
    tmp_path: Path,
) -> None:
    module = load_tool()
    source = tmp_path / "source"
    package = source / "src/overseer"
    runtime = tmp_path / "runtime"
    cryptography = runtime / "cryptography"
    package.mkdir(parents=True)
    cryptography.mkdir(parents=True)
    for relative in ("__init__.py", "cli.py", "user_bridge.py", "admin_executor.py"):
        (package / relative).write_text("VALUE = 'approved'\n", encoding="utf-8")
    (cryptography / "__init__.py").write_text("VALUE = 'approved'\n", encoding="utf-8")
    (runtime / "_cffi_backend.cpython-313-x86_64-linux-gnu.so").write_bytes(b"fixture")
    tracked = tuple(
        f"src/overseer/{name}"
        for name in ("__init__.py", "admin_executor.py", "cli.py", "user_bridge.py")
    )
    source_manifest = module.build_source_manifest(source, tracked)
    runtime_manifest = module.build_runtime_manifest(runtime)
    marker = tmp_path / "replacement-executed"
    (package / "cli.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )

    with pytest.raises(subprocess.CalledProcessError):
        module._read_only_runner(
            (
                "import-probe",
                str(source),
                str(runtime),
                module.canonical_json(source_manifest),
                module.canonical_json(runtime_manifest),
            )
        )

    assert not marker.exists()


def test_import_probe_rejects_manifested_symlink_escape_before_execution(
    tmp_path: Path,
) -> None:
    module = load_tool()
    source = tmp_path / "source"
    package = source / "src/overseer"
    runtime = tmp_path / "runtime"
    cryptography = runtime / "cryptography"
    package.mkdir(parents=True)
    cryptography.mkdir(parents=True)
    for relative in ("__init__.py", "cli.py", "user_bridge.py", "admin_executor.py"):
        (package / relative).write_text("VALUE = 'approved'\n", encoding="utf-8")
    (cryptography / "__init__.py").write_text("VALUE = 'approved'\n", encoding="utf-8")
    (runtime / "_cffi_backend.cpython-313-x86_64-linux-gnu.so").write_bytes(b"fixture")
    tracked = tuple(
        f"src/overseer/{name}"
        for name in ("__init__.py", "admin_executor.py", "cli.py", "user_bridge.py")
    )
    source_manifest = module.build_source_manifest(source, tracked)
    runtime_manifest = module.build_runtime_manifest(runtime)
    marker = tmp_path / "symlink-escape-executed"
    escaped = tmp_path / "escaped-cli.py"
    escaped.write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    (package / "cli.py").unlink()
    (package / "cli.py").symlink_to(escaped)

    with pytest.raises(subprocess.CalledProcessError):
        module._read_only_runner(
            (
                "import-probe",
                str(source),
                str(runtime),
                module.canonical_json(source_manifest),
                module.canonical_json(runtime_manifest),
            )
        )

    assert not marker.exists()


def test_import_probe_rejects_symlinked_ancestor_before_manifested_code_execution(
    tmp_path: Path,
) -> None:
    module = load_tool()
    source = tmp_path / "source"
    source_tree = source / "src"
    package = source_tree / "overseer"
    runtime = tmp_path / "runtime"
    cryptography = runtime / "cryptography"
    package.mkdir(parents=True)
    cryptography.mkdir(parents=True)
    marker = tmp_path / "ancestor-code-executed"
    for relative in ("__init__.py", "user_bridge.py", "admin_executor.py"):
        (package / relative).write_text("VALUE = 'approved'\n", encoding="utf-8")
    (package / "cli.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n",
        encoding="utf-8",
    )
    (cryptography / "__init__.py").write_text("VALUE = 'approved'\n", encoding="utf-8")
    (runtime / "_cffi_backend.cpython-313-x86_64-linux-gnu.so").write_bytes(b"fixture")
    tracked = tuple(
        f"src/overseer/{name}"
        for name in ("__init__.py", "admin_executor.py", "cli.py", "user_bridge.py")
    )
    source_manifest = module.build_source_manifest(source, tracked)
    runtime_manifest = module.build_runtime_manifest(runtime)
    outside = tmp_path / "outside-src"
    source_tree.rename(outside)
    source_tree.symlink_to(outside, target_is_directory=True)

    with pytest.raises(subprocess.CalledProcessError):
        module._read_only_runner(
            (
                "import-probe",
                str(source),
                str(runtime),
                module.canonical_json(source_manifest),
                module.canonical_json(runtime_manifest),
            )
        )

    assert not marker.exists()


def test_future_archive_builder_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    module = load_tool()
    root = tmp_path / "source"
    directory = root / "src"
    directory.mkdir(parents=True)
    (directory / "file.py").write_text("VALUE = 'approved'\n", encoding="utf-8")
    manifest = module.build_source_manifest(root, ("src/file.py",))
    moved = tmp_path / "outside-src"
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)

    completed = subprocess.run(
        (
            sys.executable,
            "-B",
            "-s",
            "-P",
            "-c",
            module._archive_builder_python(),
            str(root),
            module.canonical_json(manifest),
            str(tmp_path / "source.zip"),
        ),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )

    assert completed.returncode != 0


def test_render_plan_is_read_only_canonical_and_probe_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_tool()
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("render ran subprocess"))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("render spawned process"))

    rendered = render(module)
    plan = rendered["plan"]
    assert plan["schemaVersion"] == "overseer.phase-b-disposable-rehearsal-plan.v8"
    assert module.canonical_json(rendered) == json.dumps(rendered, sort_keys=True, separators=(",", ":"))
    assert rendered["planDigest"] == hashlib.sha256(module.canonical_json(plan).encode()).hexdigest()
    assert plan["sourceArtifact"]["manifest"] == artifact_manifest("source")
    assert plan["runtimeArtifact"]["manifest"] == artifact_manifest("runtime")
    assert plan["sourceArtifact"]["manifestDigest"] == manifest_digest(
        module, artifact_manifest("source")
    )
    assert plan["runtimeArtifact"]["manifestDigest"] == manifest_digest(
        module, artifact_manifest("runtime")
    )
    assert plan["runtimeProbe"] == runtime_probe()
    assert plan["runtimeProbeDigest"] == hashlib.sha256(module.canonical_json(runtime_probe()).encode()).hexdigest()
    assert plan["capabilityProbe"] == capability_probe()
    assert plan["capabilityProbeDigest"] == hashlib.sha256(
        module.canonical_json(capability_probe()).encode()
    ).hexdigest()
    assert plan["futureScriptSha256"] == hashlib.sha256(plan["futureScript"].encode()).hexdigest()
    assert plan["executionCommand"][:2] == ["/usr/bin/env", "-i"]
    assert plan["executionCommand"][-2:] == [
        "/usr/bin/bash",
        "<approved-future-script>",
    ]
    assert plan["sessionRuntimeDirectory"] == str(SESSION_RUNTIME_DIR)
    assert plan["executionEnvironment"]["XDG_RUNTIME_DIR"] == str(
        SESSION_RUNTIME_DIR
    )
    assert f"XDG_RUNTIME_DIR={SESSION_RUNTIME_DIR}" in plan["executionCommand"]
    assert plan["ownerBinding"] == owner_binding(module)


def test_render_plan_digest_changes_with_exact_owner_binding() -> None:
    module = load_tool()
    first = render(module)
    second_owner = "019fefa5-f52a-74f3-8179-715e12d9cd2e"
    second = render(module, owner_binding=owner_binding(module, conversation_id=second_owner))

    assert first["plan"]["ownerBinding"]["conversationId"] == OWNER_THREAD
    assert second["plan"]["ownerBinding"]["conversationId"] == second_owner
    assert first["planDigest"] != second["planDigest"]


def test_render_plan_rejects_digest_valid_binding_not_in_live_registry() -> None:
    module = load_tool()
    attacker = "019fefa5-f52a-74f3-8179-715e12d9cd2e"
    binding = owner_binding(module, conversation_id=attacker)
    module._read_codex_projects_registry = lambda path: owner_registry_bytes()

    with pytest.raises(module.PreflightError, match="live Codex projects registry"):
        render(
            module,
            owner_binding=binding,
            _registry_payload=owner_registry_bytes(),
        )


def test_render_plan_rejects_owner_binding_for_a_different_source_repository() -> None:
    module = load_tool()
    different_source = Path("/home/god/Documents/Codex Workspace/Other/source")
    probe = runtime_probe()
    probe["sourceRoot"] = str(different_source)
    imports = probe["imports"]
    assert isinstance(imports, dict)
    for name in ("overseer.cli", "overseer.user_bridge", "overseer.admin_executor"):
        imports[name] = str(imports[name]).replace(str(SOURCE_ROOT), str(different_source))

    with pytest.raises(module.PreflightError, match="owner binding source repository"):
        render(
            module,
            source_root=different_source,
            runtime_probe=probe,
        )


@pytest.mark.parametrize("case", ("alias", "tampered-row", "tampered-binding"))
def test_render_plan_rejects_invalid_owner_binding(case: str) -> None:
    module = load_tool()
    binding = owner_binding(module)
    if case == "alias":
        binding["conversationId"] = "approval-smoke-v1-1-6"
    elif case == "tampered-row":
        binding["registryRow"]["project"] = "/home/god/Documents/Codex Workspace/Roadex"
    else:
        binding["bindingDigest"] = "0" * 64

    with pytest.raises(module.PreflightError, match="owner binding"):
        render(module, owner_binding=binding)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("codexExecutable", "/tmp/codex"),
        ("codexExecutableInode", 0),
        ("codexExecutableSha256", "0" * 63),
        ("codexArgv", ["codex", "resume", OWNER_THREAD, "--cd", "/tmp"]),
    ),
)
def test_render_plan_rejects_semantically_forged_codex_process_binding(
    field: str, value: object
) -> None:
    module = load_tool()
    binding = owner_binding(module)
    binding[field] = value
    binding.pop("bindingDigest")
    binding["bindingDigest"] = hashlib.sha256(
        module.canonical_json(binding).encode()
    ).hexdigest()

    with pytest.raises(module.PreflightError, match="owner binding"):
        render(module, owner_binding=binding)


def test_domain_xml_parses_and_has_seed_only_no_host_share_with_owned_pipe_serial() -> None:
    module = load_tool()
    root = ET.fromstring(render(module)["plan"]["domainXml"])

    assert root.findtext("name").startswith("overseer-phase-b-rehearsal-54a53bc34078-")
    assert root.findtext("uuid") == render(module)["plan"]["vm"]["uuid"]
    marker = root.find("./metadata/{urn:overseer:phase-b-rehearsal}run")
    assert marker is not None
    assert marker.attrib["id"] == render(module)["plan"]["vm"]["runId"]
    assert root.findtext("memory") == "2048"
    assert root.findtext("vcpu") == "2"
    os_type = root.find("./os/type")
    assert os_type is not None
    assert os_type.attrib == {"arch": "x86_64", "machine": MACHINE_TYPE}
    loader = root.find("./os/loader")
    nvram = root.find("./os/nvram")
    assert loader is not None
    assert loader.attrib == {"readonly": "yes", "secure": "no", "type": "pflash"}
    assert loader.text == str(FIRMWARE_CODE)
    assert nvram is not None and nvram.attrib == {
        "template": str(FIRMWARE_VARS_TEMPLATE)
    }
    assert nvram.text == "${NVRAM}"
    disks = root.findall("./devices/disk")
    assert len(disks) == 2
    overlay = next(disk for disk in disks if disk.attrib["device"] == "disk")
    seed = next(disk for disk in disks if disk.attrib["device"] == "cdrom")
    assert overlay.find("source").attrib["file"] == "${OVERLAY}"
    assert seed.find("source").attrib["file"] == "${SEED_ISO}"
    assert seed.find("readonly") is not None
    assert root.findall("./devices/filesystem") == []
    assert root.find("./devices/interface") is None
    assert root.find("./devices/graphics") is None
    assert root.find("./devices/serial").attrib == {"type": "pipe"}
    assert root.find("./devices/serial/source").attrib == {"path": "${SERIAL_PIPE}"}


@pytest.mark.parametrize(
    "mutation",
    (
        "filesystem",
        "hostdev",
        "channel",
        "duplicate-disk",
        "changed-driver",
        "emulator",
        "evdev",
        "qemu-commandline",
        "kernel",
        "seclabel",
        "disk-auth",
        "serial-protocol",
        "host-cpu",
        "metadata-extra",
        "wrong-backing",
        "wrong-console-tty",
        "active-missing-backing",
        "active-missing-pty",
    ),
)
def test_domain_ownership_validator_rejects_unapproved_devices(
    mutation: str,
) -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = ET.fromstring(
        plan["domainXml"]
        .replace("${OVERLAY}", "/tmp/owned/overlay.qcow2")
        .replace("${SEED_ISO}", "/tmp/owned/seed.iso")
        .replace("${SERIAL_PIPE}", "/tmp/owned/serial")
        .replace("${NVRAM}", "/tmp/owned/nvram.fd")
    )
    devices = root.find("./devices")
    assert devices is not None
    if mutation == "filesystem":
        ET.SubElement(devices, "filesystem", {"type": "mount"})
    elif mutation == "hostdev":
        ET.SubElement(devices, "hostdev", {"mode": "subsystem", "type": "usb"})
    elif mutation == "channel":
        ET.SubElement(devices, "channel", {"type": "unix"})
    elif mutation == "duplicate-disk":
        devices.append(ET.fromstring(ET.tostring(devices.findall("disk")[0])))
    elif mutation == "changed-driver":
        devices.findall("disk")[0].find("driver").set("type", "raw")
    elif mutation == "emulator":
        ET.SubElement(devices, "emulator").text = "/tmp/unapproved-emulator"
    elif mutation == "evdev":
        input_node = ET.SubElement(devices, "input", {"type": "evdev"})
        ET.SubElement(input_node, "source", {"dev": "/dev/input/event0"})
    elif mutation == "qemu-commandline":
        commandline = ET.SubElement(
            root, "{http://libvirt.org/schemas/domain/qemu/1.0}commandline"
        )
        ET.SubElement(commandline, "{http://libvirt.org/schemas/domain/qemu/1.0}arg", {"value": "-netdev"})
    elif mutation == "kernel":
        ET.SubElement(root.find("os"), "kernel").text = "/tmp/unapproved-kernel"
    elif mutation == "seclabel":
        ET.SubElement(root, "seclabel", {"type": "none"})
    elif mutation == "disk-auth":
        ET.SubElement(devices.findall("disk")[0], "auth", {"username": "unapproved"})
    elif mutation == "serial-protocol":
        ET.SubElement(devices.find("serial"), "protocol", {"type": "raw"})
    elif mutation == "host-cpu":
        ET.SubElement(root, "cpu", {"mode": "host-passthrough"})
    elif mutation == "metadata-extra":
        ET.SubElement(root.find("metadata"), "unapproved")
    elif mutation == "wrong-backing":
        backing = ET.SubElement(
            devices.findall("disk")[0], "backingStore", {"type": "file", "index": "1"}
        )
        ET.SubElement(backing, "format", {"type": "qcow2"})
        ET.SubElement(backing, "source", {"file": "/tmp/unapproved-base.qcow2"})
        ET.SubElement(backing, "backingStore")
    elif mutation == "wrong-console-tty":
        console = devices.find("console")
        console.set("tty", "/dev/pts/7")
        ET.SubElement(console, "source", {"path": "/dev/pts/8"})
    elif mutation == "active-missing-backing":
        root.set("id", "7")
        console = devices.find("console")
        console.set("tty", "/dev/pts/7")
        ET.SubElement(console, "source", {"path": "/dev/pts/7"})
    else:
        root.set("id", "7")
        backing = ET.SubElement(
            devices.findall("disk")[0], "backingStore", {"type": "file", "index": "1"}
        )
        ET.SubElement(backing, "format", {"type": "qcow2"})
        ET.SubElement(backing, "source", {"file": str(BASE_IMAGE)})
        ET.SubElement(backing, "backingStore")
    completed = _run_domain_ownership_validator(module, plan, root)
    assert completed.returncode != 0


def test_domain_ownership_validator_accepts_only_the_rendered_device_contract() -> None:
    module = load_tool()
    plan = render(module)["plan"]
    xml = (
        plan["domainXml"]
        .replace("${OVERLAY}", "/tmp/owned/overlay.qcow2")
        .replace("${SEED_ISO}", "/tmp/owned/seed.iso")
        .replace("${SERIAL_PIPE}", "/tmp/owned/serial")
        .replace("${NVRAM}", "/tmp/owned/nvram.fd")
    )
    completed = _run_domain_ownership_validator(module, plan, ET.fromstring(xml))
    assert completed.returncode == 0, completed.stderr


def test_domain_ownership_validator_accepts_exact_libvirt_auto_devices() -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = ET.fromstring(
        plan["domainXml"]
        .replace("${OVERLAY}", "/tmp/owned/overlay.qcow2")
        .replace("${SEED_ISO}", "/tmp/owned/seed.iso")
        .replace("${SERIAL_PIPE}", "/tmp/owned/serial")
        .replace("${NVRAM}", "/tmp/owned/nvram.fd")
    )
    devices = root.find("./devices")
    assert devices is not None
    root.set("id", "7")
    ET.SubElement(devices, "emulator").text = "/usr/bin/qemu-system-x86_64"
    ET.SubElement(devices, "controller", {"type": "pci", "index": "0", "model": "pci-root"})
    ET.SubElement(devices, "controller", {"type": "usb", "index": "0", "model": "piix3-uhci"})
    ET.SubElement(devices, "controller", {"type": "sata", "index": "0"})
    ET.SubElement(devices, "input", {"type": "mouse", "bus": "ps2"})
    ET.SubElement(devices, "input", {"type": "keyboard", "bus": "ps2"})
    ET.SubElement(devices, "audio", {"id": "1", "type": "none"})
    balloon = ET.SubElement(devices, "memballoon", {"model": "virtio"})
    ET.SubElement(
        balloon,
        "address",
        {
            "type": "pci",
            "domain": "0x0000",
            "bus": "0x00",
            "slot": "0x03",
            "function": "0x0",
        },
    )
    ET.SubElement(balloon, "alias", {"name": "balloon0"})
    disks = devices.findall("disk")
    disks[0].find("source").set("index", "2")
    ET.SubElement(
        disks[0],
        "address",
        {
            "type": "pci",
            "domain": "0x0000",
            "bus": "0x00",
            "slot": "0x02",
            "function": "0x0",
        },
    )
    ET.SubElement(disks[0], "alias", {"name": "virtio-disk0"})
    backing = ET.SubElement(disks[0], "backingStore", {"type": "file", "index": "3"})
    ET.SubElement(backing, "format", {"type": "qcow2"})
    ET.SubElement(backing, "source", {"file": str(BASE_IMAGE)})
    ET.SubElement(backing, "backingStore")
    disks[1].find("source").set("index", "1")
    ET.SubElement(disks[1], "backingStore")
    ET.SubElement(
        disks[1],
        "address",
        {"type": "drive", "controller": "0", "bus": "0", "target": "0", "unit": "0"},
    )
    serial = devices.find("serial")
    console = devices.find("console")
    assert serial is not None and console is not None
    ET.SubElement(serial, "alias", {"name": "serial0"})
    console.set("tty", "/dev/pts/7")
    ET.SubElement(console, "source", {"path": "/dev/pts/7"})
    ET.SubElement(console, "alias", {"name": "serial0"})
    os_type = root.find("./os/type")
    assert os_type is not None
    os_type.set("machine", "pc-i440fx-10.0")
    cpu = ET.SubElement(root, "cpu", {"mode": "custom", "match": "exact", "check": "full"})
    ET.SubElement(cpu, "model", {"fallback": "forbid"}).text = "qemu64"
    for name, policy in (
        ("x2apic", "require"),
        ("hypervisor", "require"),
        ("lahf_lm", "require"),
        ("svm", "disable"),
    ):
        ET.SubElement(cpu, "feature", {"policy": policy, "name": name})
    ET.SubElement(root, "clock", {"offset": "utc"})
    completed = _run_domain_ownership_validator(module, plan, root)
    assert completed.returncode == 0, completed.stderr


def test_domain_ownership_validator_rejects_foreign_active_pty_console_alias() -> None:
    module = load_tool()
    plan = render(module)["plan"]
    root = ET.fromstring(
        plan["domainXml"]
        .replace("${OVERLAY}", "/tmp/owned/overlay.qcow2")
        .replace("${SEED_ISO}", "/tmp/owned/seed.iso")
        .replace("${SERIAL_PIPE}", "/tmp/owned/serial")
        .replace("${NVRAM}", "/tmp/owned/nvram.fd")
    )
    root.set("id", "7")
    disks = root.findall("./devices/disk")
    disks[0].find("source").set("index", "2")
    backing = ET.SubElement(disks[0], "backingStore", {"type": "file", "index": "3"})
    ET.SubElement(backing, "format", {"type": "qcow2"})
    ET.SubElement(backing, "source", {"file": str(BASE_IMAGE)})
    ET.SubElement(backing, "backingStore")
    disks[1].find("source").set("index", "1")
    ET.SubElement(disks[1], "backingStore")
    serial = root.find("./devices/serial")
    console = root.find("./devices/console")
    assert serial is not None and console is not None
    ET.SubElement(serial, "alias", {"name": "serial0"})
    console.set("tty", "/dev/pts/7")
    ET.SubElement(console, "source", {"path": "/dev/pts/7"})
    ET.SubElement(console, "alias", {"name": "foreign-console"})
    cpu = ET.SubElement(root, "cpu", {"mode": "custom", "match": "exact", "check": "full"})
    ET.SubElement(cpu, "model", {"fallback": "forbid"}).text = "qemu64"
    for name, policy in (
        ("x2apic", "require"),
        ("hypervisor", "require"),
        ("lahf_lm", "require"),
        ("svm", "disable"),
    ):
        ET.SubElement(cpu, "feature", {"policy": policy, "name": name})
    ET.SubElement(root, "clock", {"offset": "utc"})

    completed = _run_domain_ownership_validator(module, plan, root)

    assert completed.returncode != 0


def test_concrete_domain_xml_passes_installed_libvirt_schema(tmp_path: Path) -> None:
    validator = shutil.which("virt-xml-validate")
    if validator is None:
        pytest.skip("virt-xml-validate is not installed")
    module = load_tool()
    xml = render(module)["plan"]["domainXml"]
    xml = xml.replace("${OVERLAY}", str(tmp_path / "overlay.qcow2"))
    xml = xml.replace("${SEED_ISO}", str(tmp_path / "seed.iso"))
    xml = xml.replace("${SERIAL_PIPE}", str(tmp_path / "serial"))
    xml = xml.replace("${NVRAM}", str(tmp_path / "nvram.fd"))
    domain_xml = tmp_path / "domain.xml"
    domain_xml.write_text(xml, encoding="utf-8")

    completed = subprocess.run(
        (validator, str(domain_xml)),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )

    assert completed.returncode == 0, completed.stderr


def test_cloud_init_installs_complete_task_two_guest_contract() -> None:
    module = load_tool()
    cloud = render(module)["plan"]["cloudInit"]

    for required in (
        "users: []",
        "groupadd --gid 984 overseer",
        "useradd --uid 984 --gid 984",
        "groupadd --gid 1000 god",
        "useradd --uid 1000 --gid 1000",
        "LABEL=cidata",
        "/mnt/overseer-seed",
        "source.zip",
        "runtime.zip",
        "source-manifest.json",
        "runtime-manifest.json",
        "/opt/overseer-source",
        "mount --bind /opt/overseer-source /opt/overseer-source",
        "remount,bind,ro,nosuid,nodev",
        "/usr/local/lib/python3.13/dist-packages",
        "remount,bind,ro,nosuid,nodev /usr/local/lib/python3.13/dist-packages",
        EXPECTED_PYTHON_ABI,
        "import cryptography; import overseer.cli; import overseer.user_bridge; import overseer.admin_executor",
        "relative_to(runtime)",
        "import _cffi_backend",
        "/usr/bin/python3.13 -B -s -P -S -c",
        "/etc/overseer-phase-b-rehearsal/source-commit",
        SOURCE_COMMIT,
        "permissions: '0444'",
        "guest_rehearsal.py",
        "guest_rehearsal.service",
        "systemctl daemon-reload",
        "systemctl start overseer-phase-b-rehearsal.service",
    ):
        assert required in cloud
    assert cloud.count("/usr/bin/python3.13 -B -s -P -S /usr/local/sbin/overseer-extract-artifacts.py") == 2
    probe = module._runtime_probe_python()
    assert "os.memfd_create" in probe
    assert "F_ADD_SEALS" in probe and "F_SEAL_WRITE" in probe
    for path in module.TASK_TWO_PLACEHOLDERS:
        entry = cloud[cloud.index(f"path: {path}") :]
        assert "owner: root:root" in entry[:160]
        assert "permissions: '0644'" in entry[:160]
        assert "content: ''" in entry[:160]
    source_commit_entry = cloud[
        cloud.index("path: /etc/overseer-phase-b-rehearsal/source-commit") :
    ]
    assert "owner: root:root" in source_commit_entry[:220]
    assert "permissions: '0444'" in source_commit_entry[:220]
    assert f"content: |\n      {SOURCE_COMMIT}\n" in source_commit_entry[:220]


def test_future_script_has_valid_persistent_lifecycle_strict_traps_and_exact_cleanup() -> None:
    module = load_tool()
    script = render(module)["plan"]["futureScript"]

    assert script.startswith("#!/usr/bin/bash\nset -Eeuo pipefail\numask 077\n")
    assert "export PATH=/usr/sbin:/usr/bin:/sbin:/bin" in script
    assert "export LC_ALL=C" in script
    assert f"export XDG_RUNTIME_DIR={SESSION_RUNTIME_DIR}" in script
    assert 'readonly RUN_LOCK="$XDG_RUNTIME_DIR/overseer-phase-b-rehearsal.lock"' in script
    assert "validate_session_runtime()" in script
    assert '[[ "$XDG_RUNTIME_DIR" == "$EXPECTED_SESSION_RUNTIME_DIR" ]]' in script
    assert '[[ -d "$XDG_RUNTIME_DIR" && ! -L "$XDG_RUNTIME_DIR" ]]' in script
    assert "/usr/bin/stat -Lc '%u:%a' -- \"$XDG_RUNTIME_DIR\"" in script
    assert script.index("validate_session_runtime\n") < script.index(
        'if ! /usr/bin/mkdir "$RUN_LOCK"'
    )
    assert script.index("validate_session_runtime\n") < script.rindex(
        "if domain_presence; then"
    )
    assert "trap 'cleanup $?\' EXIT" in script
    assert "trap 'cleanup 130' INT" in script
    assert "trap 'cleanup 143' TERM" in script
    assert "virsh --connect \"$LIBVIRT_URI\" define --validate \"$DOMAIN_XML\"" in script
    assert "define --transient" not in script and "virsh create" not in script
    assert "<<DOMAIN_XML" in script and "<<'DOMAIN_XML'" not in script
    disable = script.index("autostart --disable")
    start = script.index('start "$VM_UUID"')
    assert disable < start
    assert script.rindex("verify_domain_ownership", disable, start) > disable
    assert "target VM already exists at future execution boundary" in script
    assert "validate_exact_owner()" in script
    assert script.index("validate_exact_owner\n") < script.index(
        'if ! /usr/bin/mkdir "$RUN_LOCK"'
    )
    assert OWNER_THREAD in script
    assert '"/proc/self/fd/{fd}"' in script
    assert '"/usr/bin/tmux","list-panes","-s","-t","="+' in script
    assert '"#{session_id}\\t#{session_name}\\t#{window_id}\\t#{pane_id}\\t#{pane_pid}\\t#{pane_tty}"' in script
    assert "os.getppid()" in script
    assert 'open_process(pid)' in script
    assert 'if pane_pid not in ancestry' in script
    assert 'codex=[record for record in second_ancestry if record["isCodex"]]' in script
    assert 'len(codex)!=1 or codex[0]["argv"]!=expected["codexArgv"]' in script
    assert 'expected["codexExecutableDevice"]' in script
    assert 'expected["codexExecutableInode"]' in script
    assert 'digest.hexdigest()!=expected["codexExecutableSha256"]' in script
    assert "classify_codex(executable_path,argv,before.st_dev,before.st_ino)" in script
    assert "complete owner binding reconstruction mismatch" in script
    assert "launcher_tokens!=expected_launcher_tokens" in script
    assert "ttyname" not in script
    assert 'git(source_fd,"rev-parse","HEAD")' in script
    assert 'git(source_fd,"status","--porcelain","--untracked-files=all")' in script
    assert "artifact changed after manifest" in script
    assert "source-manifest.json" in script and "runtime-manifest.json" in script
    assert "/usr/bin/genisoimage" in script
    assert "cloud-localds" not in script
    assert "mkdir \"$RUN_LOCK\"" in script
    assert "verify_domain_ownership" in script
    assert "domuuid" in script and "dumpxml" in script
    assert "readonly EXPECTED_RUNTIME_PROBE_JSON=" in script
    assert "readonly EXPECTED_CAPABILITY_PROBE_JSON=" in script
    assert f"readonly FIRMWARE_CODE={FIRMWARE_CODE}" in script
    assert f"readonly FIRMWARE_VARS_TEMPLATE={FIRMWARE_VARS_TEMPLATE}" in script
    assert f"readonly MACHINE_TYPE={MACHINE_TYPE}" in script
    assert 'NVRAM="$TEMP_DIR/nvram.fd"' in script
    assert '"$FIRMWARE_VARS_TEMPLATE" "$NVRAM"' in script
    assert "ACTUAL_RUNTIME_PROBE_JSON=" in script
    assert "ACTUAL_CAPABILITY_PROBE_JSON=" in script
    assert script.index("ACTUAL_RUNTIME_PROBE_JSON=") < script.index("qemu-img create")
    assert script.index("ACTUAL_CAPABILITY_PROBE_JSON=") < script.index("qemu-img create")
    assert "virsh console" not in script
    assert "readonly RESULT_TIMEOUT_SECONDS=960" in script
    assert "wait_for_inactive" in script
    assert 'shutdown "$VM_UUID"' in script
    assert 'undefine "$VM_UUID" --nvram' in script
    assert 'start "$VM_UUID"' in script
    assert 'autostart --disable "$VM_UUID"' in script
    assert 'domstate "$VM_UUID"' in script
    assert 'dumpxml "$VM_UUID"' in script
    assert 'dominfo "$VM_UUID"' in script
    assert 'list --all --uuid' in script
    assert 'domcapabilities --virttype kvm --arch x86_64 --machine "$MACHINE_TYPE"' in script
    runtime_firmware_call = script.index("\nvalidate_firmware_runtime\n")
    assert script.index("ACTUAL_CAPABILITY_PROBE_JSON=") < runtime_firmware_call
    assert runtime_firmware_call < script.index('TEMP_DIR="$(/usr/bin/mktemp')
    assert "rm -rf" not in script and "rm -r" not in script
    assert script.count('SERIAL_RESULT="$(<"$SERIAL_STATUS")"') == 2
    assert script.rindex('SERIAL_RESULT="$(<"$SERIAL_STATUS")"') > script.index("stop_collector")
    cleanup_line = next(
        line
        for line in script.splitlines()
        if line.strip().startswith("/usr/bin/rm -f --") and "$DOMAIN_XML" in line
    )
    for exact in (
        "$DOMAIN_XML",
        "$USER_DATA",
        "$META_DATA",
        "$OVERLAY",
        "$SEED_ISO",
        "$NVRAM",
        "$SERIAL_LOG",
    ):
        assert exact in cleanup_line
    assert "$BASE_IMAGE" not in cleanup_line and "$SOURCE_ROOT" not in cleanup_line and "$RUNTIME_SITE" not in cleanup_line


def _run_firmware_validator(
    module,
    code: Path,
    code_digest: str,
    variables: Path,
    variables_digest: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (
            sys.executable,
            "-B",
            "-s",
            "-P",
            "-S",
            "-c",
            module._firmware_validator_python(),
            str(code),
            code_digest,
            str(variables),
            variables_digest,
        ),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


def test_runtime_firmware_validator_accepts_exact_pinned_root_owned_files() -> None:
    module = load_tool()

    completed = _run_firmware_validator(
        module,
        FIRMWARE_CODE,
        module.FIRMWARE_CODE_SHA256,
        FIRMWARE_VARS_TEMPLATE,
        module.FIRMWARE_VARS_SHA256,
    )

    assert completed.returncode == 0, completed.stderr


def test_runtime_firmware_validator_rejects_symlink_and_non_root_file(tmp_path: Path) -> None:
    module = load_tool()
    linked = tmp_path / "firmware.fd"
    linked.symlink_to(FIRMWARE_CODE)
    copied = tmp_path / "vars.fd"
    copied.write_bytes(FIRMWARE_VARS_TEMPLATE.read_bytes())

    linked_result = _run_firmware_validator(
        module,
        linked,
        module.FIRMWARE_CODE_SHA256,
        FIRMWARE_VARS_TEMPLATE,
        module.FIRMWARE_VARS_SHA256,
    )
    copied_result = _run_firmware_validator(
        module,
        FIRMWARE_CODE,
        module.FIRMWARE_CODE_SHA256,
        copied,
        module.FIRMWARE_VARS_SHA256,
    )

    assert linked_result.returncode != 0
    assert copied_result.returncode != 0


def _run_cleanup_harness(
    script: str,
    temp_dir: Path,
    virsh_function: str,
    *,
    domain_xml: str | None = None,
    vm_name: str = "overseer-phase-b-rehearsal-54a53bc",
    vm_uuid: str = "00000000-0000-5000-8000-000000000000",
    run_id: str = "a" * 64,
) -> subprocess.CompletedProcess[str]:
    start = script.index("domain_presence() {")
    end = script.index("trap 'cleanup $?' EXIT")
    helpers = script[start:end].replace("/usr/bin/virsh", "virsh")
    paths = {
        "OVERLAY": temp_dir / "overlay.qcow2",
        "SEED_ISO": temp_dir / "seed.iso",
        "NVRAM": temp_dir / "nvram.fd",
        "SERIAL_PIPE": temp_dir / "serial",
        "SERIAL_LOG": temp_dir / "serial.log",
        "SERIAL_STATUS": temp_dir / "serial.status",
        "SERIAL_STOP": temp_dir / "serial.stop",
        "SERIAL_COLLECTOR": temp_dir / "serial-collector.py",
        "DOMAIN_XML": temp_dir / "domain.xml",
        "USER_DATA": temp_dir / "user-data",
        "META_DATA": temp_dir / "meta-data",
        "SOURCE_ARCHIVE": temp_dir / "source.zip",
        "RUNTIME_ARCHIVE": temp_dir / "runtime.zip",
        "SOURCE_MANIFEST_FILE": temp_dir / "source-manifest.json",
        "RUNTIME_MANIFEST_FILE": temp_dir / "runtime-manifest.json",
    }
    temp_dir.mkdir()
    for name, path in paths.items():
        if name != "SERIAL_PIPE":
            content = domain_xml if name == "DOMAIN_XML" and domain_xml is not None else "fixture"
            path.write_text(content, encoding="utf-8")
    for suffix in (".in", ".out"):
        Path(str(paths["SERIAL_PIPE"]) + suffix).write_text("fixture", encoding="utf-8")
    run_lock = temp_dir.parent / (temp_dir.name + "-lock")
    run_lock.mkdir()
    (run_lock / "run-id").write_text(run_id, encoding="ascii")
    assignments = [
        "set -Eeuo pipefail",
        "LIBVIRT_URI=qemu:///session",
        f"VM_NAME={shlex.quote(vm_name)}",
        f"VM_UUID={shlex.quote(vm_uuid)}",
        f"RUN_ID={shlex.quote(run_id)}",
        f"BASE_IMAGE={shlex.quote(str(BASE_IMAGE))}",
        f"FIRMWARE_CODE={shlex.quote(str(FIRMWARE_CODE))}",
        f"FIRMWARE_VARS_TEMPLATE={shlex.quote(str(FIRMWARE_VARS_TEMPLATE))}",
        "SHUTDOWN_TIMEOUT_SECONDS=1",
        "COLLECTOR_PID=",
        "LOCK_HELD=1",
        f"RUN_LOCK={shlex.quote(str(run_lock))}",
        f"TEMP_DIR={shlex.quote(str(temp_dir))}",
        *(f"{name}={shlex.quote(str(path))}" for name, path in paths.items()),
        virsh_function,
        helpers,
        "cleanup 0",
    ]
    return subprocess.run(
        ("bash", "-c", "\n".join(assignments)),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


@pytest.mark.parametrize(
    "virsh_function",
    (
        "virsh() { return 9; }",
        "virsh() { case \"$*\" in *\" list --all --name\") printf '%s\\n' \"$VM_NAME\"; return 0;; *\" list --all --uuid\") printf '%s\\n' \"$VM_UUID\"; return 0;; *\" domuuid \"*) printf '%s\\n' \"$VM_UUID\"; return 0;; *\" domname \"*) printf '%s\\n' \"$VM_NAME\"; return 0;; *\" dumpxml \"*) /usr/bin/cat \"$DOMAIN_XML\"; return 0;; *\" domstate \"*) return 9;; *) return 9;; esac; }",
    ),
)
def test_cleanup_retains_every_artifact_when_libvirt_state_is_unknown(
    tmp_path: Path, virsh_function: str
) -> None:
    module = load_tool()
    temp_dir = tmp_path / "unknown-state"

    completed = _run_cleanup_harness(
        render(module)["plan"]["futureScript"], temp_dir, virsh_function
    )

    assert completed.returncode != 0
    assert temp_dir.is_dir()
    assert {path.name for path in temp_dir.iterdir()} == {
        "overlay.qcow2",
        "seed.iso",
        "nvram.fd",
        "serial.in",
        "serial.out",
        "serial.log",
        "serial.status",
        "serial.stop",
        "serial-collector.py",
        "domain.xml",
        "user-data",
        "meta-data",
        "source.zip",
        "runtime.zip",
        "source-manifest.json",
        "runtime-manifest.json",
    }


@pytest.mark.parametrize("unsafe_state", ("paused", "crashed", "pmsuspended", "blocked"))
def test_cleanup_never_mutates_an_owned_domain_in_an_unsafe_state(
    tmp_path: Path,
    unsafe_state: str,
) -> None:
    module = load_tool()
    plan, root = _libvirt_pipe_console_root(module, active=True)
    temp_dir = tmp_path / f"unsafe-{unsafe_state}"
    calls = tmp_path / f"{unsafe_state}.calls"
    virsh = (
        f"virsh() {{ printf '%s\\n' \"$*\" >>{shlex.quote(str(calls))}; "
        "case \"$*\" in "
        "*\" list --all --name\") printf '%s\\n' \"$VM_NAME\"; return 0;; "
        "*\" list --all --uuid\") printf '%s\\n' \"$VM_UUID\"; return 0;; "
        "*\" domuuid \"*) printf '%s\\n' \"$VM_UUID\"; return 0;; "
        "*\" domname \"*) printf '%s\\n' \"$VM_NAME\"; return 0;; "
        "*\" dumpxml \"*) /usr/bin/cat \"$DOMAIN_XML\"; return 0;; "
        f"*\" domstate \"*) printf '%s\\n' {shlex.quote(unsafe_state)}; return 0;; "
        "*\" shutdown \"*) return 9;; "
        "*) return 9;; esac; }"
    )
    domain_xml = (
        ET.tostring(root, encoding="unicode")
        .replace("/tmp/owned/overlay.qcow2", str(temp_dir / "overlay.qcow2"))
        .replace("/tmp/owned/seed.iso", str(temp_dir / "seed.iso"))
        .replace("/tmp/owned/serial", str(temp_dir / "serial"))
        .replace("/tmp/owned/nvram.fd", str(temp_dir / "nvram.fd"))
    )

    completed = _run_cleanup_harness(
        render(module)["plan"]["futureScript"],
        temp_dir,
        virsh,
        domain_xml=domain_xml,
        vm_name=plan["vm"]["name"],
        vm_uuid=plan["vm"]["uuid"],
        run_id=plan["vm"]["runId"],
    )

    assert completed.returncode != 0
    assert temp_dir.is_dir()
    observed = calls.read_text(encoding="utf-8")
    assert " shutdown " not in observed
    assert " undefine " not in observed


def test_cleanup_deletes_exact_artifacts_only_after_authoritative_absence(tmp_path: Path) -> None:
    module = load_tool()
    temp_dir = tmp_path / "absent-state"

    completed = _run_cleanup_harness(
        render(module)["plan"]["futureScript"],
        temp_dir,
        "virsh() { case \"$*\" in *\" list --all --name\") return 0;; *\" list --all --uuid\") return 0;; *) return 9;; esac; }",
    )

    assert completed.returncode == 0, completed.stderr
    assert not temp_dir.exists()


def test_cleanup_never_mutates_a_same_name_foreign_domain(tmp_path: Path) -> None:
    module = load_tool()
    temp_dir = tmp_path / "foreign-domain"
    calls = tmp_path / "virsh.calls"
    virsh = (
        f"virsh() {{ printf '%s\\n' \"$*\" >>{shlex.quote(str(calls))}; "
        "case \"$*\" in "
        "*\" list --all --name\") printf '%s\\n' \"$VM_NAME\"; return 0;; "
        "*\" list --all --uuid\") printf '%s\\n' 11111111-1111-5111-8111-111111111111; return 0;; "
        "*\" domuuid \"*) printf '%s\\n' 11111111-1111-5111-8111-111111111111; return 0;; "
        "*) return 9;; esac; }"
    )

    completed = _run_cleanup_harness(
        render(module)["plan"]["futureScript"], temp_dir, virsh
    )

    assert completed.returncode != 0
    assert temp_dir.is_dir()
    observed = calls.read_text(encoding="utf-8")
    assert " list --all --uuid" in observed
    assert " shutdown " not in observed
    assert " undefine " not in observed


def test_cleanup_retains_artifacts_when_owned_uuid_was_renamed(tmp_path: Path) -> None:
    module = load_tool()
    temp_dir = tmp_path / "renamed-owned-domain"
    calls = tmp_path / "renamed.calls"
    virsh = (
        f"virsh() {{ printf '%s\\n' \"$*\" >>{shlex.quote(str(calls))}; "
        "case \"$*\" in "
        "*\" list --all --name\") printf '%s\\n' renamed-owned-domain; return 0;; "
        "*\" list --all --uuid\") printf '%s\\n' \"$VM_UUID\"; return 0;; "
        "*\" domname \"*) printf '%s\\n' renamed-owned-domain; return 0;; "
        "*) return 9;; esac; }"
    )

    completed = _run_cleanup_harness(
        render(module)["plan"]["futureScript"], temp_dir, virsh
    )

    assert completed.returncode != 0
    assert temp_dir.is_dir()
    observed = calls.read_text(encoding="utf-8")
    assert " list --all --uuid" in observed
    assert " shutdown " not in observed
    assert " undefine " not in observed


def test_future_script_requires_one_canonical_passing_secret_free_result() -> None:
    module = load_tool()
    script = render(module)["plan"]["futureScript"]

    assert "OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN" in script
    assert "OVERSEER_PHASE_B_REHEARSAL_RESULT_END" in script
    assert "MAX_SERIAL_BYTES" in script and "MAX_SERIAL_LINE_BYTES" in script
    assert "serial output exceeded the bounded limit" in script
    assert "read_text" not in module._result_validator_python()
    assert "overseer.phase-b-disposable-rehearsal.v1" in script
    assert 'record.get("status")!="passed"' in script
    assert "canonical!=payload" in script
    secret_marker_line = next(
        line for line in script.splitlines() if line.startswith("secret_markers=")
    )
    assert "credential" in secret_marker_line
    for control in EXPECTED_CONTROLS:
        assert control in script


def _passing_serial_record(module) -> bytes:
    record = {
        "schemaVersion": module.RESULT_SCHEMA,
        "status": "passed",
        "stage": "phase-complete",
        "controls": {name: True for name in sorted(EXPECTED_CONTROLS)},
        "identifiers": {"runId": "fixture"},
        "failure": None,
    }
    payload = module.canonical_json(record).encode()
    return (
        b"OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN\n"
        + payload
        + b"\nOVERSEER_PHASE_B_REHEARSAL_RESULT_END\n"
    )


def _run_result_validator(module, tmp_path: Path, content: bytes) -> subprocess.CompletedProcess[str]:
    serial = tmp_path / "serial.log"
    serial.write_bytes(content)
    return subprocess.run(
        (sys.executable, "-B", "-s", "-P", "-c", module._result_validator_python(), str(serial)),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


def test_streaming_result_validator_accepts_near_limit_canonical_result(
    tmp_path: Path,
) -> None:
    module = load_tool()
    frame = _passing_serial_record(module)
    padding_lines = (module.MAX_SERIAL_BYTES - len(frame)) // 2 - 1
    padding = b"x\n" * padding_lines

    completed = _run_result_validator(module, tmp_path, padding + frame)

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("content_builder", "message"),
    (
        (
            lambda module: b"x\n" * (module.MAX_SERIAL_BYTES // 2 + 1),
            "serial output exceeded",
        ),
        (lambda module: b"x" * (module.MAX_SERIAL_LINE_BYTES + 1) + b"\n", "line exceeded"),
        (lambda module: _passing_serial_record(module) * 2, "exactly one"),
        (lambda module: b"\xff\n" + _passing_serial_record(module), "codec"),
    ),
)
def test_streaming_result_validator_rejects_bounded_and_framing_attacks(
    tmp_path: Path, content_builder, message: str
) -> None:
    module = load_tool()

    completed = _run_result_validator(module, tmp_path, content_builder(module))

    assert completed.returncode != 0
    assert message.lower() in completed.stderr.lower()


def test_serial_collector_upgrades_complete_to_late_overflow(tmp_path: Path) -> None:
    module = load_tool()
    pipe = tmp_path / "serial.out"
    log = tmp_path / "serial.log"
    status = tmp_path / "serial.status"
    stop = tmp_path / "serial.stop"
    os.mkfifo(pipe, 0o600)
    process = subprocess.Popen(
        (
            sys.executable,
            "-B",
            "-s",
            "-P",
            "-c",
            module._serial_collector_python(),
            str(pipe),
            str(log),
            str(status),
            str(stop),
            str(module.MAX_SERIAL_BYTES),
            str(module.MAX_SERIAL_LINE_BYTES),
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    with pipe.open("wb", buffering=0) as stream:
        stream.write(_passing_serial_record(module))
        stream.write(b"x\n" * (module.MAX_SERIAL_BYTES // 2 + 1))
    deadline = time.monotonic() + 5
    while (not status.exists() or status.read_text(encoding="ascii").strip() != "overflow") and time.monotonic() < deadline:
        time.sleep(0.01)
    stop.write_text("stop\n", encoding="ascii")
    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0, (stdout, stderr)
    assert status.read_text(encoding="ascii").strip() == "overflow"
    assert log.stat().st_size <= module.MAX_SERIAL_BYTES


def test_guest_extractor_rejects_manifest_or_archive_tampering(tmp_path: Path) -> None:
    module = load_tool()
    root = tmp_path / "source"
    root.mkdir()
    (root / "file.py").write_text("VALUE = 1\n", encoding="utf-8")
    manifest = module.build_source_manifest(root, ("file.py",))
    archive = module.build_artifact_archive(root, manifest)
    archive_path = tmp_path / "source.zip"
    manifest_path = tmp_path / "source-manifest.json"
    archive_path.write_bytes(archive)
    manifest_path.write_text(module.canonical_json(manifest), encoding="ascii")
    digest = hashlib.sha256(module.canonical_json(manifest).encode()).hexdigest()

    valid = subprocess.run(
        (
            sys.executable,
            "-B",
            "-s",
            "-P",
            "-c",
            module._artifact_extractor_python(),
            str(archive_path),
            str(manifest_path),
            str(tmp_path / "valid"),
            digest,
        ),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert valid.returncode == 0, valid.stderr
    assert (tmp_path / "valid/file.py").read_text(encoding="utf-8") == "VALUE = 1\n"

    archive_path.write_bytes(archive + b"tamper")
    tampered = subprocess.run(
        (
            sys.executable,
            "-B",
            "-s",
            "-P",
            "-c",
            module._artifact_extractor_python(),
            str(archive_path),
            str(manifest_path),
            str(tmp_path / "tampered"),
            digest,
        ),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert tampered.returncode != 0
    assert "archive digest mismatch" in tampered.stderr


@pytest.mark.parametrize(
    "override",
    (
        {"source_root": Path("/bad/$source")},
        {"runtime_site": Path("/bad/`runtime`")},
        {"base_image": Path("relative/base.qcow2")},
        {"temp_parent": Path("/")},
    ),
)
def test_render_rejects_unsafe_host_paths_before_rendering(override: dict[str, Path]) -> None:
    module = load_tool()
    with pytest.raises(module.PreflightError, match="path"):
        render(module, **override)


def test_render_rejects_unpassed_or_mismatched_runtime_probe() -> None:
    module = load_tool()
    failed = runtime_probe()
    failed["status"] = "failed"
    with pytest.raises(module.PreflightError, match="runtime probe"):
        render(module, runtime_probe=failed)

    mismatched = runtime_probe()
    mismatched["runtimeSite"] = "/other/runtime"
    with pytest.raises(module.PreflightError, match="runtime probe"):
        render(module, runtime_probe=mismatched)

    wrong_origin = runtime_probe()
    wrong_origin["imports"] = dict(wrong_origin["imports"])
    wrong_origin["imports"]["cryptography"] = "/usr/local/lib/python3.13/site-packages/cryptography/__init__.py"
    with pytest.raises(module.PreflightError, match="runtime probe"):
        render(module, runtime_probe=wrong_origin)

    wrong_abi = runtime_probe()
    wrong_abi["pythonAbi"] = "cpython-312-x86_64-linux-gnu"
    with pytest.raises(module.PreflightError, match="runtime probe"):
        render(module, runtime_probe=wrong_abi)


def test_render_rejects_unpassed_or_mismatched_capability_probe() -> None:
    module = load_tool()
    failed = capability_probe()
    failed["status"] = "failed"
    with pytest.raises(module.PreflightError, match="capability probe"):
        render(module, capability_probe=failed)

    wrong_driver = capability_probe()
    wrong_driver["filesystem"] = {"supported": True, "driverType": "virtiofs"}
    with pytest.raises(module.PreflightError, match="capability probe"):
        render(module, capability_probe=wrong_driver)
