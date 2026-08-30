from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import shlex
import shutil
import stat
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest


TOOL = Path(__file__).parents[1] / "tools" / "phase_b_rehearsal.py"
SOURCE_COMMIT = "54a53bc34078c42a4303d6fe4de7e517a9e8f44b"
SOURCE_ROOT = Path("/home/god/Documents/Codex Workspace/Overseer/source")
RUNTIME_SITE = Path("/usr/lib/python3/dist-packages")
BASE_IMAGE = Path("/var/lib/overseer-phase-b-rehearsal/debian-13-genericcloud-amd64.qcow2")
TEMP_PARENT = Path("/var/tmp")
EXPECTED_IMPORTS = (
    "cryptography",
    "overseer.cli",
    "overseer.user_bridge",
    "overseer.admin_executor",
)
EXPECTED_PYTHON_VERSION = "3.13.5"
EXPECTED_PYTHON_ABI = "cpython-313-x86_64-linux-gnu"
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
        "filesystem": {"supported": True, "driverType": "path"},
    }


def render(module, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "source_commit": SOURCE_COMMIT,
        "source_root": SOURCE_ROOT,
        "runtime_site": RUNTIME_SITE,
        "runtime_probe": runtime_probe(),
        "capability_probe": capability_probe(),
        "base_image": BASE_IMAGE,
        "temp_parent": TEMP_PARENT,
    }
    values.update(overrides)
    return module.render_plan(**values)


def fake_stat(path: Path) -> SimpleNamespace:
    modes = {
        Path("/dev/kvm"): stat.S_IFCHR | 0o660,
        SOURCE_ROOT: stat.S_IFDIR | 0o755,
        RUNTIME_SITE: stat.S_IFDIR | 0o755,
        BASE_IMAGE: stat.S_IFREG | 0o640,
        TEMP_PARENT: stat.S_IFDIR | 0o1777,
    }
    return SimpleNamespace(st_mode=modes[path], st_uid=os.geteuid(), st_gid=os.getegid())


def valid_preflight_kwargs(module) -> dict[str, object]:
    responses = {
        "git-status": "",
        "git-head": SOURCE_COMMIT,
        "libvirt-uri": module.LIBVIRT_URI,
        "domains": "",
        "domain-capabilities": (
            "<domainCapabilities><domain>kvm</domain><arch>x86_64</arch><devices>"
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
        "runtime_site": RUNTIME_SITE,
        "base_image": BASE_IMAGE,
        "temp_parent": TEMP_PARENT,
        "runner": lambda command: responses[command[0]],
        "path_exists": lambda path: path in {Path("/dev/kvm"), SOURCE_ROOT, RUNTIME_SITE, BASE_IMAGE, TEMP_PARENT},
        "path_stat": fake_stat,
        "path_access": lambda path, mode: True,
        "is_symlink": lambda path: False,
        "image_sha512": lambda path: module.BASE_IMAGE_SHA512,
        "which": lambda name: f"/usr/bin/{name}",
    }


def test_constants_pin_image_runtime_and_complete_future_tooling() -> None:
    module = load_tool()
    assert module.BASE_IMAGE_URL.endswith("debian-13-genericcloud-amd64.qcow2")
    assert module.BASE_IMAGE_SHA512 == (
        "184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003"
    )
    assert module.DEFAULT_RUNTIME_SITE == RUNTIME_SITE
    assert module.RUNTIME_MOUNT_TAG == "overseer-runtime-site"
    assert set(
        (
            "bash",
            "awk",
            "cat",
            "grep",
            "install",
            "rm",
            "rmdir",
            "sha256sum",
            "sleep",
            "python3",
            "timeout",
        )
    ) <= set(module.REQUIRED_TOOLS)


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
    assert result["planInputs"]["sourceMount"]["readOnly"] is True
    assert result["planInputs"]["runtimeMount"]["readOnly"] is True
    assert result["tempDirectoryCreated"] is False


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("dirty", "dirty"),
        ("missing-kvm", "KVM"),
        ("regular-kvm", "character"),
        ("inaccessible-kvm", "accessible"),
        ("unsafe-source", "source path"),
        ("relative-runtime", "runtime path"),
        ("traversal-image", "base image path"),
        ("unsafe-temp", "temporary path"),
        ("raw-image", "qcow2"),
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
        values["runner"] = lambda command: " M file" if command[0] == "git-status" else original_runner(command)
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
    elif case == "relative-runtime":
        values["runtime_site"] = Path("relative/runtime")
    elif case == "traversal-image":
        values["base_image"] = Path("/unsafe/../base.qcow2")
    elif case == "unsafe-temp":
        values["temp_parent"] = Path("/tmp/unsafe;path")
    elif case == "raw-image":
        values["runner"] = lambda command: '{"format":"raw"}' if command[0] == "qemu-img-info" else original_runner(command)
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
        values["which"] = lambda name: None if name == "awk" else f"/usr/bin/{name}"
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
        "git-status",
        "git-head",
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
        ("libvirt-uri",),
        ("domains",),
        ("domain-capabilities",),
        ("qemu-img-info", str(BASE_IMAGE)),
        ("import-probe", str(SOURCE_ROOT), str(RUNTIME_SITE)),
    )
    for probe in probes:
        module._read_only_runner(probe)

    rendered = "\n".join(" ".join(argv) for argv, _ in calls)
    assert " define " not in rendered and " start " not in rendered and " shutdown " not in rendered
    import_argv, import_kwargs = calls[-1]
    assert import_argv[:6] == ("python3", "-B", "-s", "-P", "-S", "-c")
    assert all(name in import_argv[6] for name in EXPECTED_IMPORTS)
    assert "relative_to(expected)" in import_argv[6]
    assert "sys.version_info[:2] == (3,13)" in import_argv[6]
    assert import_kwargs["env"]["PYTHONDONTWRITEBYTECODE"] == "1"


def test_render_plan_is_pure_canonical_and_probe_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_tool()
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("render ran subprocess"))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("render spawned process"))

    rendered = render(module)
    plan = rendered["plan"]
    assert plan["schemaVersion"] == "overseer.phase-b-disposable-rehearsal-plan.v3"
    assert module.canonical_json(rendered) == json.dumps(rendered, sort_keys=True, separators=(",", ":"))
    assert rendered["planDigest"] == hashlib.sha256(module.canonical_json(plan).encode()).hexdigest()
    assert plan["runtimeSite"]["hostPath"] == str(RUNTIME_SITE)
    assert plan["runtimeProbe"] == runtime_probe()
    assert plan["runtimeProbeDigest"] == hashlib.sha256(module.canonical_json(runtime_probe()).encode()).hexdigest()
    assert plan["capabilityProbe"] == capability_probe()
    assert plan["capabilityProbeDigest"] == hashlib.sha256(
        module.canonical_json(capability_probe()).encode()
    ).hexdigest()
    assert plan["futureScriptSha256"] == hashlib.sha256(plan["futureScript"].encode()).hexdigest()


def test_domain_xml_parses_and_has_seed_runtime_source_readonly_without_network() -> None:
    module = load_tool()
    root = ET.fromstring(render(module)["plan"]["domainXml"])

    assert root.findtext("name") == "overseer-phase-b-rehearsal-54a53bc"
    assert root.findtext("memory") == "2048"
    assert root.findtext("vcpu") == "2"
    disks = root.findall("./devices/disk")
    assert len(disks) == 2
    overlay = next(disk for disk in disks if disk.attrib["device"] == "disk")
    seed = next(disk for disk in disks if disk.attrib["device"] == "cdrom")
    assert overlay.find("source").attrib["file"] == "${OVERLAY}"
    assert seed.find("source").attrib["file"] == "${SEED_ISO}"
    assert seed.find("readonly") is not None
    filesystems = {item.find("target").attrib["dir"]: item for item in root.findall("./devices/filesystem")}
    assert set(filesystems) == {"overseer-source", "overseer-runtime-site"}
    assert filesystems["overseer-source"].find("source").attrib["dir"] == str(SOURCE_ROOT)
    assert filesystems["overseer-runtime-site"].find("source").attrib["dir"] == str(RUNTIME_SITE)
    assert all(item.find("readonly") is not None for item in filesystems.values())
    assert all(item.find("driver").attrib == {"type": "path"} for item in filesystems.values())
    assert root.find("./devices/interface") is None
    assert root.find("./devices/graphics") is None
    assert root.find("./devices/serial/source").attrib == {"path": "${SERIAL_LOG}", "append": "on"}


def test_concrete_domain_xml_passes_installed_libvirt_schema(tmp_path: Path) -> None:
    validator = shutil.which("virt-xml-validate")
    if validator is None:
        pytest.skip("virt-xml-validate is not installed")
    module = load_tool()
    xml = render(module)["plan"]["domainXml"]
    xml = xml.replace("${OVERLAY}", str(tmp_path / "overlay.qcow2"))
    xml = xml.replace("${SEED_ISO}", str(tmp_path / "seed.iso"))
    xml = xml.replace("${SERIAL_LOG}", str(tmp_path / "serial.log"))
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
        "overseer-source",
        "/mnt/overseer-source",
        "overseer-runtime-site",
        "/mnt/overseer-runtime-site",
        "trans=virtio,version=9p2000.L,ro",
        "/usr/local/lib/python3.13/dist-packages",
        EXPECTED_PYTHON_ABI,
        "import cryptography; import overseer.cli; import overseer.user_bridge; import overseer.admin_executor",
        "/etc/overseer-phase-b-rehearsal/source-commit",
        SOURCE_COMMIT,
        "permissions: '0444'",
        "guest_rehearsal.py",
        "guest_rehearsal.service",
        "systemctl daemon-reload",
        "systemctl start overseer-phase-b-rehearsal.service",
    ):
        assert required in cloud
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

    assert script.startswith("#!/usr/bin/env bash\nset -Eeuo pipefail\numask 077\n")
    assert "export PATH=/usr/sbin:/usr/bin:/sbin:/bin" in script
    assert "export LC_ALL=C" in script
    assert "trap 'cleanup $?\' EXIT" in script
    assert "trap 'cleanup 130' INT" in script
    assert "trap 'cleanup 143' TERM" in script
    assert "virsh --connect \"$LIBVIRT_URI\" define --validate \"$DOMAIN_XML\"" in script
    assert "define --transient" not in script and "virsh create" not in script
    assert "<<DOMAIN_XML" in script and "<<'DOMAIN_XML'" not in script
    disable = script.index("autostart --disable")
    start = script.index('start "$VM_NAME"')
    assert disable < start
    assert "target VM already exists at future execution boundary" in script
    assert 'git -C "$SOURCE_ROOT" rev-parse HEAD' in script
    assert 'git -C "$SOURCE_ROOT" status --porcelain' in script
    assert "readonly EXPECTED_RUNTIME_PROBE_JSON=" in script
    assert "readonly EXPECTED_CAPABILITY_PROBE_JSON=" in script
    assert "ACTUAL_RUNTIME_PROBE_JSON=" in script
    assert "ACTUAL_CAPABILITY_PROBE_JSON=" in script
    assert script.index("ACTUAL_RUNTIME_PROBE_JSON=") < script.index("qemu-img create")
    assert script.index("ACTUAL_CAPABILITY_PROBE_JSON=") < script.index("qemu-img create")
    assert "virsh console" not in script
    assert "readonly RESULT_TIMEOUT_SECONDS=960" in script
    assert "wait_for_inactive" in script
    assert 'shutdown "$VM_NAME"' in script
    assert 'undefine "$VM_NAME"' in script
    assert "rm -rf" not in script and "rm -r" not in script
    cleanup_line = next(line for line in script.splitlines() if line.strip().startswith("rm -f --"))
    for exact in ("$DOMAIN_XML", "$USER_DATA", "$META_DATA", "$OVERLAY", "$SEED_ISO", "$SERIAL_LOG"):
        assert exact in cleanup_line
    assert "$BASE_IMAGE" not in cleanup_line and "$SOURCE_ROOT" not in cleanup_line and "$RUNTIME_SITE" not in cleanup_line


def _run_cleanup_harness(script: str, temp_dir: Path, virsh_function: str) -> subprocess.CompletedProcess[str]:
    start = script.index("domain_presence() {")
    end = script.index("trap 'cleanup $?' EXIT")
    helpers = script[start:end]
    paths = {
        "OVERLAY": temp_dir / "overlay.qcow2",
        "SEED_ISO": temp_dir / "seed.iso",
        "SERIAL_LOG": temp_dir / "serial.log",
        "DOMAIN_XML": temp_dir / "domain.xml",
        "USER_DATA": temp_dir / "user-data",
        "META_DATA": temp_dir / "meta-data",
    }
    temp_dir.mkdir()
    for path in paths.values():
        path.write_text("fixture", encoding="utf-8")
    assignments = [
        "set -Eeuo pipefail",
        "LIBVIRT_URI=qemu:///session",
        "VM_NAME=overseer-phase-b-rehearsal-54a53bc",
        "SHUTDOWN_TIMEOUT_SECONDS=1",
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
        "virsh() { case \"$*\" in *\" list --all --name\") printf '%s\\n' \"$VM_NAME\"; return 0;; *\" domstate \"*) return 9;; *) return 9;; esac; }",
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
        "serial.log",
        "domain.xml",
        "user-data",
        "meta-data",
    }


def test_cleanup_deletes_exact_artifacts_only_after_authoritative_absence(tmp_path: Path) -> None:
    module = load_tool()
    temp_dir = tmp_path / "absent-state"

    completed = _run_cleanup_harness(
        render(module)["plan"]["futureScript"],
        temp_dir,
        "virsh() { case \"$*\" in *\" list --all --name\") return 0;; *) return 9;; esac; }",
    )

    assert completed.returncode == 0, completed.stderr
    assert not temp_dir.exists()


def test_future_script_requires_one_canonical_passing_secret_free_result() -> None:
    module = load_tool()
    script = render(module)["plan"]["futureScript"]

    assert "OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN" in script
    assert "OVERSEER_PHASE_B_REHEARSAL_RESULT_END" in script
    assert "begin_indexes" in script and "end_indexes" in script
    assert "len(begin_indexes) != 1" in script and "len(end_indexes) != 1" in script
    assert "overseer.phase-b-disposable-rehearsal.v1" in script
    assert 'record.get("status") != "passed"' in script
    assert "canonical != payload" in script
    secret_marker_line = next(line for line in script.splitlines() if line.startswith("secret_markers ="))
    assert "credential" in secret_marker_line
    for control in EXPECTED_CONTROLS:
        assert control in script


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
