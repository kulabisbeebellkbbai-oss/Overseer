from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


TOOL = Path(__file__).parents[1] / "tools" / "phase_b_rehearsal.py"
SOURCE_COMMIT = "5ecb64e4a4afc9ed4f2b12ebf418a9f6a14a5cc8"


def load_tool():
    spec = importlib.util.spec_from_file_location("phase_b_rehearsal_tool", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_preflight_kwargs(tmp_path: Path) -> dict[str, object]:
    module = load_tool()
    responses = {
        "git-status": "",
        "git-head": SOURCE_COMMIT,
        "libvirt-uri": module.LIBVIRT_URI,
        "domains": "",
    }
    return {
        "source_commit": SOURCE_COMMIT,
        "repo_root": tmp_path,
        "runner": lambda command: responses[command[0]],
        "path_exists": lambda path: True,
        "is_regular_file": lambda path: True,
        "image_sha512": lambda path: module.BASE_IMAGE_SHA512,
        "which": lambda name: f"/usr/bin/{name}",
        "temp_parent": tmp_path,
    }


def test_constants_pin_the_approved_image_and_runtime_shape() -> None:
    module = load_tool()

    assert module.BASE_IMAGE_URL == (
        "https://cloud.debian.org/images/cloud/trixie/latest/"
        "debian-13-genericcloud-amd64.qcow2"
    )
    assert module.BASE_IMAGE_SHA512 == (
        "184761b0dad0f9ace02f9298050ca96ce3caa39a461a47706d47ff9698b59933918b91b40177fbd4d392f6446af8b4d18ecb94caca988169b19641606bf34003"
    )
    assert module.LIBVIRT_URI == "qemu:///session"
    assert module.MEMORY_MIB == 2048
    assert module.VCPUS == 2
    assert module.OVERLAY_GIB == 8


def test_preflight_rejects_each_fail_closed_condition(tmp_path: Path) -> None:
    module = load_tool()
    cases = (
        ("dirty tree", {"responses": {"git-status": " M file.py"}}, "dirty"),
        ("wrong full source SHA", {"responses": {"git-head": "a" * 40}}, "source commit"),
        ("missing KVM", {"path_exists": lambda path: False}, "KVM"),
        ("wrong URI", {"responses": {"libvirt-uri": "qemu:///system"}}, "libvirt URI"),
        ("existing VM", {"responses": {"domains": "overseer-phase-b-rehearsal-5ecb64e"}}, "already exists"),
        ("writable share", {"source_share_spec": "rw,9p,tag=overseer-source"}, "writable"),
        ("network device", {"network_devices": ("interface",)}, "network"),
        ("missing image", {"path_exists": lambda path: path != module.DEFAULT_BASE_IMAGE}, "base image"),
        ("unverified image", {"image_sha512": lambda path: "0" * 128}, "SHA-512"),
        ("missing tooling", {"which": lambda name: None}, "tooling"),
        ("unsafe temp", {"temp_parent": Path("/")}, "temporary"),
        ("unsafe serial", {"serial_log": Path("/var/log/serial.log")}, "serial"),
    )

    for label, overrides, message in cases:
        kwargs = valid_preflight_kwargs(tmp_path)
        responses = overrides.pop("responses", None)
        if responses is not None:
            base_responses = {
                "git-status": "",
                "git-head": SOURCE_COMMIT,
                "libvirt-uri": module.LIBVIRT_URI,
                "domains": "",
            }
            base_responses.update(responses)
            kwargs["runner"] = lambda command, values=base_responses: values[command[0]]
        kwargs.update(overrides)
        with pytest.raises(module.PreflightError, match=message):
            module.preflight(**kwargs)


def test_preflight_uses_only_injected_readers_and_read_only_commands(tmp_path: Path) -> None:
    module = load_tool()
    calls: list[tuple[str, ...]] = []

    def runner(command: tuple[str, ...]) -> str:
        calls.append(command)
        return {
            "git-status": "",
            "git-head": SOURCE_COMMIT,
            "libvirt-uri": module.LIBVIRT_URI,
            "domains": "",
        }[command[0]]

    kwargs = valid_preflight_kwargs(tmp_path)
    kwargs["runner"] = runner
    module.preflight(**kwargs)

    assert calls
    assert all(command[:1] in (("git-status",), ("git-head",), ("libvirt-uri",), ("domains",)) for command in calls)
    assert all("define" not in command and "start" not in command and "destroy" not in command for command in calls)


def test_preflight_does_not_create_the_future_temp_directory(tmp_path: Path) -> None:
    module = load_tool()
    before = tuple(tmp_path.iterdir())

    module.preflight(**valid_preflight_kwargs(tmp_path))

    assert tuple(tmp_path.iterdir()) == before


def test_render_plan_is_pure_and_contains_the_complete_future_choreography(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_tool()

    def fail_if_spawned(*args: object, **kwargs: object) -> None:
        raise AssertionError("render-plan executed a subprocess")

    monkeypatch.setattr(subprocess, "run", fail_if_spawned)
    monkeypatch.setattr(subprocess, "Popen", fail_if_spawned)
    rendered = module.render_plan(
        source_commit=SOURCE_COMMIT,
        source_root=tmp_path,
        temp_parent=tmp_path,
    )

    encoded = module.canonical_json(rendered)
    assert encoded == json.dumps(rendered, sort_keys=True, separators=(",", ":"))
    assert rendered["planDigest"] == hashlib.sha256(
        module.canonical_json(rendered["plan"]).encode()
    ).hexdigest()
    plan = rendered["plan"]
    assert plan["vm"] == {
        "name": "overseer-phase-b-rehearsal-5ecb64e",
        "memoryMiB": 2048,
        "vcpus": 2,
        "overlayGiB": 8,
        "network": "none",
        "autostart": False,
    }
    assert plan["sourceMount"] == {"tag": "overseer-source", "readOnly": True, "type": "9p"}
    assert plan["tempParent"] == str(tmp_path)
    assert plan["serialLog"] == {"directory": "<fresh-mktemp-dir>", "mode": "0600", "path": "$TEMP_DIR/serial.log"}
    commands = "\n".join(plan["futureCommands"])
    for required in (
        "sha512sum",
        "qemu-img create",
        "cloud-localds",
        "virsh --connect qemu:///session define --transient",
        "virsh --connect qemu:///session start",
        "timeout",
        "OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN",
        "virsh --connect qemu:///session shutdown",
        "virsh --connect qemu:///session undefine",
        'rm -f -- "$OVERLAY" "$SEED_ISO" "$SERIAL_LOG"',
    ):
        assert required in commands
    assert "<interface" not in plan["domainXml"]
    assert "overseer-approved-phase-b" not in commands
    assert "systemctl restart" not in commands
    assert plan["exclusions"] == ["package import", "host service action", "Phase B", "cutover"]


def test_cloud_init_has_exact_empty_task_two_placeholders() -> None:
    module = load_tool()
    plan = module.render_plan(source_commit=SOURCE_COMMIT, source_root=Path("/src"), temp_parent=Path("/tmp"))["plan"]
    cloud_init = plan["cloudInit"]
    for path in module.TASK_TWO_PLACEHOLDERS:
        assert f"path: {path}" in cloud_init
        assert "owner: root:root" in cloud_init
        assert "permissions: '0644'" in cloud_init
        assert "content: ''" in cloud_init


@pytest.mark.parametrize("commit", ["5ecb64e", "not-a-sha", "A" * 40])
def test_render_plan_rejects_noncanonical_source_commit(commit: str) -> None:
    module = load_tool()
    with pytest.raises(module.PreflightError, match="source commit"):
        module.render_plan(source_commit=commit, source_root=Path("/src"), temp_parent=Path("/tmp"))
