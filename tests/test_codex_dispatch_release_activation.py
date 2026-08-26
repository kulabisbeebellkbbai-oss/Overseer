from __future__ import annotations

import hashlib
import json
import os
import signal
import struct
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from overseer_codex_dispatch_release_launcher import SERVICE_PAYLOAD, _validated_service_payload

from overseer import codex_dispatch_release_activation as release_module
from overseer.codex_dispatch_release_activation import (
    ImmutableReleaseManifest,
    RELEASE_PLAN_SCHEMA,
    ReleaseFile,
    assert_no_dbus_commands,
    execute_codex_dispatch_activation_plan,
    plan_immutable_release_activation,
    plan_codex_dispatch_activation,
    release_drop_in_content,
    send_pinned_signal,
    validate_sudo_install_argv,
)
from overseer.core import ApprovalLevel, OwnerDomain, RiskLevel
from overseer.admin import AdminCommandResult


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
            "path": "/usr/bin/python3", "resolvedPath": "/usr/bin/python3.13",
            "entryDevice": 1, "entryInode": 1, "entryMode": 0o777,
            "device": 1, "inode": 2, "mode": 0o755, "links": 1,
            "sha256": "c" * 64, "size": 100,
        },
        hashlib.sha256(b"Restart=on-failure\n").hexdigest(),
    )


def _spec():
    from overseer.codex_dispatch_release_activation import ReleaseActivationSpec

    return ReleaseActivationSpec(
        _manifest(), {"peerPid": 1329, "bootId": "boot", "startTicks": 15378},
        {"pid": 8822, "bootId": "boot", "startTicks": 44, "cmdlineHex": "00", "cwd": "/old"},
        "Restart=on-failure\n",
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
    assert len(commands) == 1
    assert commands[0][:6] == ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-S", "-c"]
    assert commands[0][-2:] == [manifest.digest, str(manifest.release_root)]
    assert plan.adapter_metadata["rootHelperSha256"] == hashlib.sha256(
        release_module.ROOT_RELEASE_HELPER.encode()
    ).hexdigest()
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
    assert "--human-approval-token-file /home/god/.local/share/overseer/project/state/human-approval-token" in content
    assert "--human-approval-identity sisko" in content
    assert "/home/god/Documents/Codex Workspace/Overseer" not in content
    assert "busctl" not in content and "systemctl" not in content


def test_release_launcher_requires_the_exact_credential_separated_payload():
    assert _validated_service_payload(["--", *SERVICE_PAYLOAD]) == list(SERVICE_PAYLOAD)

    without_approval_credential = list(SERVICE_PAYLOAD[:9])
    with pytest.raises(RuntimeError, match="reviewed service entry"):
        _validated_service_payload(["--", *without_approval_credential])

    changed = list(SERVICE_PAYLOAD)
    changed[changed.index("--human-approval-identity") + 1] = "obrien"
    with pytest.raises(RuntimeError, match="reviewed service entry"):
        _validated_service_payload(["--", *changed])


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
            "a" * 40, "b" * 40, (item, item), _manifest().root_python, "c" * 64,
        )
    with pytest.raises(ValueError, match="canonical and relative"):
        ReleaseFile("../escape", "checkout", "src/x.py", "d" * 64, 1, 0o444)


def test_exact_adapter_and_human_approval_gate_precede_source_or_effects(monkeypatch):
    from overseer import codex_dispatch_release_activation as release

    plan = plan_codex_dispatch_activation("admin.release", _spec(), "activate")
    monkeypatch.setattr(release, "verify_reviewed_source_binding", lambda spec: pytest.fail("gate ran source verification"))
    assert execute_codex_dispatch_activation_plan(plan, adapter_enabled=False).status.value == "blocked"
    assert execute_codex_dispatch_activation_plan(plan, adapter_enabled=True).status.value == "blocked"


def test_approved_plan_uses_only_exact_context_bound_markers(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    monkeypatch.setattr(release, "_state_root", lambda: tmp_path)
    monkeypatch.setattr(release, "verify_reviewed_source_binding", lambda spec: None)
    plan = replace(
        plan_codex_dispatch_activation("admin.release", _spec(), "activate"),
        approved=True, approved_by="sisko", approved_at="2026-08-18T00:00:00+00:00",
    )
    seen = []
    result = execute_codex_dispatch_activation_plan(
        plan, adapter_enabled=True,
        runner=lambda step: seen.append(step.command) or AdminCommandResult(step.title, step.command, 0),
    )
    assert result.status.value == "completed"
    assert seen == [step.command for step in (*plan.steps, *plan.verification_steps)]
    code, _, error = release.execute_codex_dispatch_activation_marker(plan.steps[0].command)
    assert code == 1 and "lacks exact active plan authority" in error


def test_manager_drift_rejects_before_signal(monkeypatch):
    from overseer import codex_dispatch_release_activation as release

    monkeypatch.setattr(release, "_capture_manager_binding", lambda: {"peerPid": 9999})
    monkeypatch.setattr(os, "pidfd_open", lambda *args: pytest.fail("drift opened pidfd"))
    with pytest.raises(ValueError, match="drifted"):
        release._manager_pidfd(_spec())


def test_wrong_new_api_cmdline_and_cwd_are_rejected_before_health(monkeypatch):
    from overseer import codex_dispatch_release_activation as release

    monkeypatch.setattr(release.urllib.request, "urlopen", lambda *args, **kwargs: pytest.fail("health ran"))
    binding = {
        "pid": 77, "cmdlineHex": b"/evil/wrapper\0".hex(),
        "cwd": str(_manifest().release_root), "cgroup": release.EXPECTED_CGROUP,
    }
    with pytest.raises(ValueError, match="argv"):
        release._attest_release_api(_spec(), binding)
    binding["cmdlineHex"] = release._expected_release_cmdline(_spec()).hex()
    binding["cwd"] = "/tmp/mutable"
    with pytest.raises(ValueError, match="cwd"):
        release._attest_release_api(_spec(), binding)


def test_no_restart_observed_fails_closed(monkeypatch):
    from overseer import codex_dispatch_release_activation as release

    clock = iter((0.0, 0.0, 0.2))
    monkeypatch.setattr(release.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(release.time, "sleep", lambda value: None)
    monkeypatch.setattr(release, "_capture_api_binding", lambda: {"pid": 10})
    with pytest.raises(RuntimeError, match="not observed"):
        release._wait_for_api(lambda value: True, old_pid=10, timeout=0.1)


def test_partial_root_install_journal_rolls_back_to_inert_terminal(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    spec = _spec()
    plan = plan_codex_dispatch_activation("admin.partial", spec, "activate")
    digest = plan.steps[0].command[3]
    commands = (
        ("/usr/bin/sudo", "-n", "/usr/bin/install", "first"),
        ("/usr/bin/sudo", "-n", "/usr/bin/install", "second"),
    )
    monkeypatch.setattr(release, "_state_root", lambda: tmp_path)
    monkeypatch.setattr(release, "_install_commands", lambda manifest: commands)
    calls = []
    def install(command, manifest):
        calls.append(command)
        if len(calls) == 2:
            raise RuntimeError("injected partial install crash")
    monkeypatch.setattr(release, "_run_install", install)

    with pytest.raises(RuntimeError, match="partial install"):
        release._install_release("admin.partial", spec, digest)
    journal = release._load_journal("admin.partial", digest)
    assert journal["phase"] == "install-intent"
    assert journal["installedCommands"] == 1

    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    monkeypatch.setattr(release, "_manager_pidfd", lambda value: (1329, read_fd))
    monkeypatch.setattr(release, "send_pinned_signal", lambda *args: None)
    monkeypatch.setattr(release.time, "sleep", lambda value: None)
    monkeypatch.setattr(release, "_capture_api_binding", lambda: (_ for _ in ()).throw(ValueError("absent")))
    monkeypatch.setattr(release, "_capture_manager_binding", lambda: dict(spec.manager_binding))
    assert "retained inert" in release._rollback("admin.partial", spec, digest)
    journal = release._load_journal("admin.partial", digest)
    assert journal["phase"] == "rolled-back"
    assert journal["releaseOwnership"] == "inert-partial"
    assert execute_codex_dispatch_activation_plan(
        replace(plan, approved=True, approved_by="sisko", approved_at="2026-08-18T00:00:00+00:00"),
        adapter_enabled=True,
    ).status.value == "blocked"


def test_dropin_retry_after_intent_effect_preserves_operation_ownership(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    spec = _spec()
    plan = plan_codex_dispatch_activation("admin.dropin-crash", spec, "activate")
    digest = plan.steps[0].command[3]
    monkeypatch.setattr(release, "_state_root", lambda: tmp_path / "state")
    monkeypatch.setattr(release, "_drop_in_path", lambda: tmp_path / "dropin.conf")
    journal = release._new_journal("admin.dropin-crash", digest, spec.manifest)
    journal.update({
        "phase": "dropin-intent", "installedCommands": 1,
        "releaseOwnership": "operation-owned", "dropInOwnership": "write-issued",
    })
    release._write_journal(journal)
    path = release._drop_in_path()
    path.write_bytes(release_drop_in_content(spec.manifest))
    path.chmod(0o600)

    assert "operation-bound" in release._install_drop_in("admin.dropin-crash", spec, digest)
    recovered = release._load_journal("admin.dropin-crash", digest)
    assert recovered["phase"] == "dropin-installed"
    assert recovered["dropInOwnership"] == "operation-owned"


def test_root_helper_stream_uses_pinned_descriptor_when_source_path_is_swapped(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    source = tmp_path / "src/overseer_codex_dispatch_release_launcher.py"
    source.parent.mkdir(parents=True)
    original = b"reviewed pinned bytes"
    source.write_bytes(original)
    item = ReleaseFile(
        "app/src/overseer_codex_dispatch_release_launcher.py", "checkout",
        "src/overseer_codex_dispatch_release_launcher.py",
        hashlib.sha256(original).hexdigest(), len(original), 0o444,
    )
    manifest = ImmutableReleaseManifest(
        "a" * 40, "b" * 40, (item,), _manifest().root_python,
        hashlib.sha256(b"Restart=on-failure\n").hexdigest(),
    )
    monkeypatch.setattr(release, "CANONICAL_CHECKOUT", tmp_path)
    captured = bytearray()

    class Stdin:
        def write(self, value):
            captured.extend(value)
            return len(value)
        def close(self):
            return None

    class Process:
        def __init__(self):
            self.stdin = Stdin()
            self.returncode = 0
            source.rename(source.with_suffix(".reviewed-held"))
            source.write_bytes(b"same-euid replacement")
        def communicate(self, timeout=None):
            return (json.dumps({"status": "installed", "manifestDigest": manifest.digest,
                                "releaseRoot": str(manifest.release_root)}).encode(), b"")
        def poll(self):
            return self.returncode

    monkeypatch.setattr(release.subprocess, "Popen", lambda *args, **kwargs: Process())
    release._run_install(release._install_commands(manifest)[0], manifest)

    manifest_length = int.from_bytes(captured[:8], "big")
    offset = 8 + manifest_length
    content_length = int.from_bytes(captured[offset:offset + 8], "big")
    assert bytes(captured[offset + 8:]) == original
    assert content_length == len(original)


def test_root_helper_command_rejects_injected_or_self_consistent_alternate_authority():
    manifest = _manifest()
    approved = list(release_module._install_commands(manifest)[0])
    for index, replacement in ((6, release_module.ROOT_RELEASE_HELPER + "\nprint('evil')"),
                               (-2, "e" * 64), (-1, "/opt/overseer/releases/alternate")):
        evil = approved.copy()
        evil[index] = replacement
        with pytest.raises(ValueError, match="allowlist|fixed isolated"):
            validate_sudo_install_argv(evil, manifest)


def test_root_helper_rejects_alternate_manifest_before_root_path_access():
    manifest = _manifest()
    alternate_value = json.loads(json.dumps(manifest.to_json()))
    alternate_value["unitContractSha256"] = "e" * 64
    unsigned = {key: alternate_value[key] for key in alternate_value if key not in {"manifestDigest", "releaseRoot"}}
    alternate_digest = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    alternate_value["manifestDigest"] = alternate_digest
    alternate_value["releaseRoot"] = f"/opt/overseer/releases/{manifest.source_commit}-{alternate_digest}"
    raw = json.dumps(alternate_value, sort_keys=True, separators=(",", ":")).encode()
    completed = subprocess.run(
        ("/usr/bin/python3", "-I", "-S", "-c", release_module.ROOT_RELEASE_HELPER,
         manifest.digest, str(manifest.release_root)),
        input=struct.pack(">Q", len(raw)) + raw, capture_output=True, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    assert completed.returncode != 0
    assert b"AssertionError" in completed.stderr


def test_staging_never_includes_or_changes_opt_metadata():
    before = os.stat("/opt", follow_symlinks=False)
    manifest = _manifest()
    plan = plan_immutable_release_activation(
        "admin.opt-invariant", "bind root helper without touching opt", manifest,
        manager_binding={"peerPid": 1329}, unit_contract=b"Restart=on-failure\n",
    )
    after = os.stat("/opt", follow_symlinks=False)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_gid,
                              value.st_mode & 0o7777)
    assert identity(after) == identity(before)
    command = plan.adapter_metadata["rootInstallCommands"][0]
    assert command[-1] == str(manifest.release_root)
    assert "/opt" not in command[:-1]


def test_dropin_parent_symlink_is_rejected(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    spec = _spec()
    plan = plan_codex_dispatch_activation("admin.parent-link", spec, "activate")
    digest = plan.steps[0].command[3]
    monkeypatch.setattr(release, "_state_root", lambda: tmp_path / "state")
    real_parent = tmp_path / "real"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    monkeypatch.setattr(release, "_drop_in_path", lambda: linked_parent / "dropin.conf")
    journal = release._new_journal("admin.parent-link", digest, spec.manifest)
    journal["phase"] = "release-installed"
    journal["releaseOwnership"] = "operation-owned"
    release._write_journal(journal)
    with pytest.raises(ValueError, match="directory|owner-only|unsafe"):
        release._install_drop_in("admin.parent-link", spec, digest)


def test_dropin_replacement_before_hup_prevents_signal(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    spec = _spec()
    plan = plan_codex_dispatch_activation("admin.hup-race", spec, "activate")
    digest = plan.steps[0].command[3]
    monkeypatch.setattr(release, "_state_root", lambda: tmp_path)
    journal = release._new_journal("admin.hup-race", digest, spec.manifest)
    journal.update({"phase": "dropin-installed", "releaseOwnership": "operation-owned",
                    "dropInOwnership": "operation-owned"})
    release._write_journal(journal)
    calls = []
    monkeypatch.setattr(release, "_revalidate_drop_in", lambda *args: (_ for _ in ()).throw(ValueError("replaced")))
    monkeypatch.setattr(release, "send_pinned_signal", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="replaced"):
        release._reload("admin.hup-race", spec, digest)
    assert calls == []


def test_dropin_replacement_after_hup_is_detected_before_api_kill(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    spec = _spec()
    plan = plan_codex_dispatch_activation("admin.after-hup-race", spec, "activate")
    digest = plan.steps[0].command[3]
    monkeypatch.setattr(release, "_state_root", lambda: tmp_path)
    journal = release._new_journal("admin.after-hup-race", digest, spec.manifest)
    journal.update({"phase": "dropin-installed", "releaseOwnership": "operation-owned",
                    "dropInOwnership": "operation-owned"})
    release._write_journal(journal)
    validations = []
    def validate(*args):
        validations.append(1)
        if len(validations) == 3:
            raise ValueError("replacement after HUP")
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    monkeypatch.setattr(release, "_revalidate_drop_in", validate)
    monkeypatch.setattr(release, "_manager_pidfd", lambda value: (1329, read_fd))
    signals = []
    monkeypatch.setattr(release, "send_pinned_signal", lambda *args: signals.append(args[-1]))
    with pytest.raises(ValueError, match="after HUP"):
        release._reload("admin.after-hup-race", spec, digest)
    assert signals == [signal.SIGHUP]


def test_rollback_never_quarantines_replacement_inode(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    parent = tmp_path / "dropins"
    parent.mkdir(mode=0o700)
    path = parent / "10-overseer-codex-dispatch.conf"
    approved = b"approved drop-in"
    path.write_bytes(approved)
    path.chmod(0o600)
    identity = path.lstat()
    monkeypatch.setattr(release, "_drop_in_path", lambda: path)
    journal = {
        "dropInOwnership": "operation-owned", "dropInDigest": hashlib.sha256(approved).hexdigest(),
        "dropInDevice": identity.st_dev, "dropInInode": identity.st_ino,
        "specDigest": "f" * 64, "dropInQuarantine": "",
        "dropInQuarantineDevice": None, "dropInQuarantineInode": None,
    }
    path.rename(parent / "original-retained")
    replacement = b"unrelated replacement"
    path.write_bytes(replacement)
    path.chmod(0o600)

    with pytest.raises(ValueError, match="changed|inode"):
        release._quarantine_dropin(journal)
    assert path.read_bytes() == replacement
    assert not any(item.name.endswith("rollback-inert") for item in parent.iterdir())


def test_operation_dropin_quarantine_is_noreplace_and_retry_idempotent(monkeypatch, tmp_path):
    from overseer import codex_dispatch_release_activation as release

    parent = tmp_path / "dropins"
    parent.mkdir(mode=0o700)
    path = parent / "10-overseer-codex-dispatch.conf"
    approved = b"approved drop-in"
    path.write_bytes(approved)
    path.chmod(0o600)
    identity = path.lstat()
    monkeypatch.setattr(release, "_drop_in_path", lambda: path)
    journal = {
        "dropInOwnership": "operation-owned", "dropInDigest": hashlib.sha256(approved).hexdigest(),
        "dropInDevice": identity.st_dev, "dropInInode": identity.st_ino,
        "specDigest": "f" * 64, "dropInQuarantine": "",
        "dropInQuarantineDevice": None, "dropInQuarantineInode": None,
    }
    release._quarantine_dropin(journal)
    quarantine = Path(journal["dropInQuarantine"])
    assert not path.exists() and quarantine.read_bytes() == approved
    release._quarantine_dropin(journal)
    assert quarantine.read_bytes() == approved
