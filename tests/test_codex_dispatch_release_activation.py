from __future__ import annotations

import hashlib
import json
import signal
from pathlib import Path

import pytest

from overseer.codex_dispatch_release_activation import (
    ImmutableReleaseManifest,
    RELEASE_PLAN_SCHEMA,
    ReleaseFile,
    assert_no_dbus_commands,
    plan_immutable_release_activation,
    release_drop_in_content,
    send_pinned_signal,
    validate_sudo_install_argv,
)
from overseer.core import ApprovalLevel, OwnerDomain, RiskLevel


def _manifest() -> ImmutableReleaseManifest:
    launcher = b"reviewed launcher"
    dependency = b"reviewed dependency"
    return ImmutableReleaseManifest(
        "a" * 40,
        "b" * 40,
        (
            ReleaseFile(
                "app/src/overseer_codex_dispatch_release_launcher.py", "checkout",
                "src/overseer_codex_dispatch_release_launcher.py",
                hashlib.sha256(launcher).hexdigest(), len(launcher), 0o444,
            ),
            ReleaseFile(
                "site-packages/example/__init__.py", "dependency",
                "example/__init__.py", hashlib.sha256(dependency).hexdigest(),
                len(dependency), 0o444,
            ),
        ),
        {
            "path": "/usr/bin/python3", "device": 1, "inode": 2, "mode": 0o755,
            "links": 1, "sha256": "c" * 64, "size": 100,
        },
        hashlib.sha256(b"Restart=on-failure\n").hexdigest(),
    )


def test_manifest_is_content_addressed_under_exact_root_release_path():
    manifest = _manifest()
    encoded = manifest.to_json()

    assert manifest.release_root == Path(
        f"/opt/overseer/releases/{'a' * 40}-{manifest.digest}"
    )
    assert encoded["manifestDigest"] == manifest.digest
    assert ImmutableReleaseManifest.from_json(encoded) == manifest
    tampered = json.loads(json.dumps(encoded))
    tampered["files"][0]["sha256"] = "d" * 64
    with pytest.raises(ValueError, match="digest or root"):
        ImmutableReleaseManifest.from_json(tampered)


def test_stage_is_high_human_sisko_and_binds_root_mutation_without_running_it(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: pytest.fail("stage executed a command"))
    manifest = _manifest()

    plan = plan_immutable_release_activation(
        "admin.codex-release.v1", "activate reviewed immutable dispatch", manifest,
        manager_binding={"bootId": "boot", "peerPid": 1329, "startTicks": 15378},
        unit_contract=b"Restart=on-failure\n",
    )

    assert plan.owner_domain is OwnerDomain.SISKO
    assert plan.risk_level is RiskLevel.HIGH
    assert plan.approval_level is ApprovalLevel.HUMAN
    assert plan.approved is False
    assert plan.adapter_metadata["schemaVersion"] == RELEASE_PLAN_SCHEMA
    commands = plan.adapter_metadata["rootInstallCommands"]
    assert commands
    assert all(command[:3] == ["/usr/bin/sudo", "-n", "/usr/bin/install"] for command in commands)
    assert plan.adapter_metadata["lifecycle"] == {
        "reload": "pidfd_send_signal(manager,SIGHUP)",
        "restart": "pidfd_send_signal(oldOverseerApi,SIGKILL)",
        "proof": "new-pid-startticks-cgroup-cmdline-cwd-health",
        "dbusAuthority": False,
    }
    assert str(manifest.release_root) in plan.proposed_state


def test_drop_in_executes_only_root_python_and_root_owned_release():
    manifest = _manifest()
    content = release_drop_in_content(manifest).decode()

    assert "ExecStart=/usr/bin/python3 -I -S " in content
    assert str(manifest.release_root) in content
    assert "/home/god/Documents/Codex Workspace/Overseer" not in content
    assert "busctl" not in content and "systemctl" not in content


def test_sudo_allowlist_rejects_shell_extra_flag_and_alternate_destination():
    manifest = _manifest()
    plan = plan_immutable_release_activation(
        "admin.codex-release.v1", "activate reviewed immutable dispatch", manifest,
        manager_binding={"bootId": "boot", "peerPid": 1329, "startTicks": 15378},
        unit_contract=b"Restart=on-failure\n",
    )
    approved = tuple(plan.adapter_metadata["rootInstallCommands"][0])
    validate_sudo_install_argv(approved, manifest)

    for evil in (
        ("/usr/bin/sudo", "-n", "/bin/sh", "-c", "id"),
        (*approved, "--preserve-context"),
        (*approved[:-1], "/opt/overseer/releases/alternate"),
    ):
        with pytest.raises(ValueError, match="allowlist|fixed sudo"):
            validate_sudo_install_argv(evil, manifest)


def test_fake_bus_is_irrelevant_and_dbus_commands_are_rejected():
    assert_no_dbus_commands((("/usr/bin/sudo", "-n", "/usr/bin/install"),))
    for command in (("/usr/bin/busctl", "get-property"), ("/usr/bin/systemctl", "--user")):
        with pytest.raises(ValueError, match="not activation authority"):
            assert_no_dbus_commands((command,))


def test_lifecycle_signals_use_only_pidfd_and_closed_signal_set(monkeypatch):
    calls = []
    monkeypatch.setattr(signal, "pidfd_send_signal", lambda pidfd, signum: calls.append((pidfd, signum)))

    send_pinned_signal(9, 1329, signal.SIGHUP)
    send_pinned_signal(10, 8822, signal.SIGKILL)

    assert calls == [(9, signal.SIGHUP), (10, signal.SIGKILL)]
    with pytest.raises(ValueError, match="closed lifecycle"):
        send_pinned_signal(9, 1329, signal.SIGTERM)
    with pytest.raises(ValueError, match="identity"):
        send_pinned_signal(-1, 1329, signal.SIGHUP)


def test_manifest_rejects_duplicate_and_path_escape_entries():
    item = _manifest().files[0]
    with pytest.raises(ValueError, match="sorted, and unique"):
        ImmutableReleaseManifest(
            "a" * 40, "b" * 40, (item, item), {"path": "/usr/bin/python3"}, "c" * 64,
        )
    with pytest.raises(ValueError, match="canonical and relative"):
        ReleaseFile("../escape", "checkout", "src/x.py", "d" * 64, 1, 0o444)
