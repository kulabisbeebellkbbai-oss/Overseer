from __future__ import annotations

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
        "filesystem": {"supported": True, "driverType": "path"},
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


def render(module, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "source_commit": SOURCE_COMMIT,
        "source_root": SOURCE_ROOT,
        "runtime_site": RUNTIME_SITE,
        "runtime_probe": runtime_probe(),
        "capability_probe": capability_probe(),
        "source_manifest": artifact_manifest("source"),
        "runtime_manifest": artifact_manifest("runtime"),
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
        "git-files": "src/overseer/cli.py\0tests/phase_b_rehearsal/guest_rehearsal.py\0",
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
    assert module.REHEARSAL_SCHEMA == "overseer.phase-b-disposable-rehearsal-plan.v4"
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
        "git-status",
        "git-head",
        "git-files",
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
            ("/usr/bin/git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"),
            {
                "check": True,
                "capture_output": True,
                "text": True,
                "stdin": subprocess.DEVNULL,
                "env": module.MINIMAL_ENV,
            },
        )
    ]


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


def test_render_plan_is_pure_canonical_and_probe_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_tool()
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: pytest.fail("render ran subprocess"))
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("render spawned process"))

    rendered = render(module)
    plan = rendered["plan"]
    assert plan["schemaVersion"] == "overseer.phase-b-disposable-rehearsal-plan.v4"
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


def test_concrete_domain_xml_passes_installed_libvirt_schema(tmp_path: Path) -> None:
    validator = shutil.which("virt-xml-validate")
    if validator is None:
        pytest.skip("virt-xml-validate is not installed")
    module = load_tool()
    xml = render(module)["plan"]["domainXml"]
    xml = xml.replace("${OVERLAY}", str(tmp_path / "overlay.qcow2"))
    xml = xml.replace("${SEED_ISO}", str(tmp_path / "seed.iso"))
    xml = xml.replace("${SERIAL_PIPE}", str(tmp_path / "serial"))
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

    assert script.startswith("#!/usr/bin/bash\nset -Eeuo pipefail\numask 077\n")
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
    assert script.rindex("verify_domain_ownership", disable, start) > disable
    assert "target VM already exists at future execution boundary" in script
    assert "/usr/bin/git -C \"$SOURCE_ROOT\" rev-parse HEAD" in script
    assert "/usr/bin/git -C \"$SOURCE_ROOT\" status --porcelain" in script
    assert "artifact changed after manifest" in script
    assert "source-manifest.json" in script and "runtime-manifest.json" in script
    assert "/usr/bin/genisoimage" in script
    assert "cloud-localds" not in script
    assert "mkdir \"$RUN_LOCK\"" in script
    assert "verify_domain_ownership" in script
    assert "domuuid" in script and "dumpxml" in script
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
    cleanup_line = next(
        line
        for line in script.splitlines()
        if line.strip().startswith("/usr/bin/rm -f --") and "$DOMAIN_XML" in line
    )
    for exact in ("$DOMAIN_XML", "$USER_DATA", "$META_DATA", "$OVERLAY", "$SEED_ISO", "$SERIAL_LOG"):
        assert exact in cleanup_line
    assert "$BASE_IMAGE" not in cleanup_line and "$SOURCE_ROOT" not in cleanup_line and "$RUNTIME_SITE" not in cleanup_line


def _run_cleanup_harness(script: str, temp_dir: Path, virsh_function: str) -> subprocess.CompletedProcess[str]:
    start = script.index("domain_presence() {")
    end = script.index("trap 'cleanup $?' EXIT")
    helpers = script[start:end].replace("/usr/bin/virsh", "virsh")
    paths = {
        "OVERLAY": temp_dir / "overlay.qcow2",
        "SEED_ISO": temp_dir / "seed.iso",
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
            path.write_text("fixture", encoding="utf-8")
    for suffix in (".in", ".out"):
        Path(str(paths["SERIAL_PIPE"]) + suffix).write_text("fixture", encoding="utf-8")
    run_lock = temp_dir.parent / (temp_dir.name + "-lock")
    run_lock.mkdir()
    (run_lock / "run-id").write_text("a" * 64, encoding="ascii")
    assignments = [
        "set -Eeuo pipefail",
        "LIBVIRT_URI=qemu:///session",
        "VM_NAME=overseer-phase-b-rehearsal-54a53bc",
        "VM_UUID=00000000-0000-5000-8000-000000000000",
        "RUN_ID=" + "a" * 64,
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


def test_cleanup_never_mutates_a_same_name_foreign_domain(tmp_path: Path) -> None:
    module = load_tool()
    temp_dir = tmp_path / "foreign-domain"
    calls = tmp_path / "virsh.calls"
    virsh = (
        f"virsh() {{ printf '%s\\n' \"$*\" >>{shlex.quote(str(calls))}; "
        "case \"$*\" in "
        "*\" list --all --name\") printf '%s\\n' \"$VM_NAME\"; return 0;; "
        "*\" domuuid \"*) printf '%s\\n' 11111111-1111-5111-8111-111111111111; return 0;; "
        "*) return 9;; esac; }"
    )

    completed = _run_cleanup_harness(
        render(module)["plan"]["futureScript"], temp_dir, virsh
    )

    assert completed.returncode != 0
    assert temp_dir.is_dir()
    observed = calls.read_text(encoding="utf-8")
    assert " domuuid " in observed
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
