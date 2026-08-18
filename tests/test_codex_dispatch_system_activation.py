from __future__ import annotations

import hashlib
import inspect
import os
import subprocess
from dataclasses import replace

import pytest

from overseer.admin import AdminCommandResult
from overseer.codex_dispatch_release_activation import ImmutableReleaseManifest, ReleaseFile
from overseer import codex_dispatch_system_activation as system
from overseer.core import ApprovalLevel, OwnerDomain, RiskLevel


def _manifest() -> ImmutableReleaseManifest:
    launcher = b"reviewed launcher"
    return ImmutableReleaseManifest(
        "a" * 40, "b" * 40,
        (ReleaseFile("app/src/overseer_codex_dispatch_release_launcher.py", "checkout",
                     "src/overseer_codex_dispatch_release_launcher.py",
                     hashlib.sha256(launcher).hexdigest(), len(launcher), 0o444),),
        {"path": "/usr/bin/python3", "resolvedPath": "/usr/bin/python3.13",
         "entryDevice": 1, "entryInode": 1, "entryMode": 0o777,
         "device": 1, "inode": 2, "mode": 0o755, "links": 1,
         "sha256": "c" * 64, "size": 100},
        hashlib.sha256(b"system-unit-v1").hexdigest(),
    )


def _spec() -> system.SystemActivationSpec:
    manifest = _manifest()
    return system.SystemActivationSpec(
        manifest,
        {"sourceCommit": "a" * 40, "blob": "d" * 40, "sha256": "e" * 64,
         "size": 123, "path": system.ROOT_HELPER_SOURCE},
        {"bootId": "boot", "peerPid": 1329, "startTicks": 44},
        {"bootId": "boot", "pid": 8822, "startTicks": 55, "cmdlineHex": "00", "cwd": "/old"},
        ({"path": "/home/god/.config/systemd/user/overseer-api.service", "sha256": "f" * 64,
          "device": 1, "inode": 3, "mode": 0o664, "uid": 1000, "size": 10},),
        None,
        system.system_unit_content(manifest),
    )


def test_plan_binds_exact_two_stage_external_root_migration():
    spec = _spec()
    plan = system.plan_codex_dispatch_activation("admin.system-v2", spec, "migrate")

    assert plan.owner_domain is OwnerDomain.SISKO
    assert plan.risk_level is RiskLevel.HIGH
    assert plan.approval_level is ApprovalLevel.HUMAN
    assert plan.target == "system/overseer-api.service"
    assert [step.command[1] for step in plan.steps] == ["bootstrap-helper", "activate-system"]
    assert plan.adapter_metadata["externalCliOnly"] is True
    assert plan.adapter_metadata["apiExecutionAllowed"] is False
    bootstrap = plan.adapter_metadata["bootstrapCommand"]
    assert bootstrap[:6] == ["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-S", "-c"]
    assert bootstrap[-2:] == [spec.helper_blob["sha256"], str(system.ROOT_HELPER_PATH)]
    assert plan.adapter_metadata["activateCommand"] == [
        "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-S",
        str(system.ROOT_HELPER_PATH), "activate",
        spec.capability(plan.id)["planDigest"],
    ]
    assert plan.adapter_metadata["rollbackCommand"] == [
        "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-S",
        str(system.ROOT_HELPER_PATH), "rollback",
        spec.capability(plan.id)["planDigest"],
    ]
    assert spec.capability(plan.id)["rootPythonIdentity"] == spec.manifest.root_python
    assert spec.capability(plan.id)["priorSystemServiceState"] == {
        "present": False, "enabled": False, "active": False,
    }
    assert system.validate_codex_dispatch_activation_plan(plan) == spec


def test_complete_system_unit_is_root_service_and_ignores_user_unit_search_paths():
    spec = _spec()
    unit = spec.system_unit
    assert "User=god\nGroup=god\n" in unit
    assert f"WorkingDirectory={spec.manifest.release_root}\n" in unit
    assert "ExecStart=/usr/bin/python3 -I -S " in unit
    assert "Restart=on-failure\n" in unit
    assert "NoNewPrivileges=true\n" in unit
    assert "ProtectSystem=strict\n" in unit
    assert "/etc/systemd/system/overseer-api.service" not in unit
    assert ".config/systemd/user" not in unit


def test_api_ui_execution_is_rejected_before_spec_or_runner(monkeypatch):
    plan = replace(system.plan_codex_dispatch_activation("admin.system-v2", _spec(), "migrate"),
                   approved=True, approved_by="sisko", approved_at="2026-08-18T00:00:00+00:00")
    monkeypatch.setattr(system, "verify_system_activation_spec", lambda value: pytest.fail("verified"))
    result = system.execute_codex_dispatch_activation_plan(
        plan, adapter_enabled=True,
        runner=lambda step: pytest.fail("runner called"),
    )
    assert result.status.value == "blocked"
    assert "API/UI" in result.summary


def test_generic_non_external_stage_context_is_rejected_before_host_capture():
    with pytest.raises(ValueError, match="external isolated CLI"):
        system.require_external_activation_context()


def test_external_cli_context_runs_only_exact_typed_markers(monkeypatch):
    spec = _spec()
    plan = replace(system.plan_codex_dispatch_activation("admin.system-v2", spec, "migrate"),
                   approved=True, approved_by="sisko", approved_at="2026-08-18T00:00:00+00:00")
    monkeypatch.setattr(system, "_reject_api_context", lambda: None)
    monkeypatch.setattr(system, "verify_system_activation_spec", lambda value: None)
    seen = []
    with system.external_activation_cli():
        result = system.execute_codex_dispatch_activation_plan(
            plan, adapter_enabled=True,
            runner=lambda step: seen.append(step.command) or AdminCommandResult(step.title, step.command, 0),
        )
    assert result.status.value == "completed"
    assert seen == [step.command for step in (*plan.steps, *plan.verification_steps)]


def test_swapped_coordinator_cannot_change_bootstrap_command_or_helper_digest(monkeypatch):
    plan = system.plan_codex_dispatch_activation("admin.system-v2", _spec(), "migrate")
    metadata = dict(plan.adapter_metadata)
    command = list(metadata["bootstrapCommand"])
    command[-2] = "0" * 64
    metadata["bootstrapCommand"] = command
    with pytest.raises(ValueError, match="canonical"):
        system.validate_codex_dispatch_activation_plan(replace(plan, adapter_metadata=metadata))

    metadata = dict(plan.adapter_metadata)
    altered_spec = dict(metadata["spec"])
    helper = dict(altered_spec["helperBlob"])
    helper["blob"] = "1" * 40
    altered_spec["helperBlob"] = helper
    metadata["spec"] = altered_spec
    altered = system.validate_codex_dispatch_activation_plan(replace(plan, adapter_metadata=metadata))
    monkeypatch.setattr(system, "build_immutable_release_manifest", lambda **kwargs: altered.manifest)
    monkeypatch.setattr(system, "_helper_blob", lambda: dict(_spec().helper_blob))
    monkeypatch.setattr(system, "_old_user_resources", lambda: altered.old_user_resources)
    monkeypatch.setattr(system, "_old_system_unit", lambda: altered.old_system_unit)
    monkeypatch.setattr(system, "_capture_manager_binding", lambda: dict(altered.manager_binding))
    monkeypatch.setattr(system, "_capture_api_binding", lambda: dict(altered.old_api_binding))
    with pytest.raises(ValueError, match="helper Git blob"):
        system.verify_system_activation_spec(altered)


def test_root_helper_artifact_has_crash_resume_port_conflict_and_external_rollback_contract():
    import overseer_codex_dispatch_root_helper as helper

    source = inspect.getsource(helper)
    assert "journalActionId" in source and "staging-inert" in source
    assert "partial release staging conflicts" in source
    assert "Overseer API port remains occupied" in source
    assert source.index('_run_systemctl("disable", "--now"') < source.index("prior user resource quarantine")
    assert "_wait_restored_user_api" in source
    assert "system.slice/overseer-api.service" in source
    assert "user-1000.slice" in source


def test_root_helper_capability_rejects_extra_fields_and_wrong_working_directory():
    import overseer_codex_dispatch_root_helper as helper

    capability = _spec().capability("admin.system-v2")
    with pytest.raises(ValueError, match="schema"):
        helper._validate_capability({**capability, "extra": True}, capability["planDigest"])
    unsigned = {key: capability[key] for key in capability if key != "planDigest"}
    unsigned["systemUnit"] = str(unsigned["systemUnit"]).replace(
        f"WorkingDirectory={capability['releaseRoot']}", "WorkingDirectory=/tmp/mutable"
    )
    unsigned["systemUnitSha256"] = hashlib.sha256(str(unsigned["systemUnit"]).encode()).hexdigest()
    altered = {**unsigned, "planDigest": helper._digest(unsigned)}
    with pytest.raises(ValueError, match="directive"):
        helper._validate_capability(altered, altered["planDigest"])


def test_root_helper_restore_is_crash_retry_idempotent_and_never_replaces(tmp_path):
    import overseer_codex_dispatch_root_helper as helper

    active = tmp_path / "overseer-api.service"
    quarantine = tmp_path / ".overseer-api.service.prior-inert"
    quarantine.write_bytes(b"prior unit")
    quarantine.chmod(0o600)
    info = quarantine.stat()
    expected = {"sha256": hashlib.sha256(b"prior unit").hexdigest(),
                "device": info.st_dev, "inode": info.st_ino, "mode": 0o600,
                "size": info.st_size}

    helper._restore_exact_quarantine(str(active), str(quarantine), expected, uid=os.geteuid())
    helper._restore_exact_quarantine(str(active), str(quarantine), expected, uid=os.geteuid())
    assert active.read_bytes() == b"prior unit"
    assert not quarantine.exists()

    quarantine.write_bytes(b"prior unit")
    quarantine.chmod(0o600)
    with pytest.raises(ValueError, match="exactly one"):
        helper._restore_exact_quarantine(str(active), str(quarantine), expected, uid=os.geteuid())
    assert active.read_bytes() == b"prior unit"
    assert quarantine.read_bytes() == b"prior unit"


def test_root_helper_is_read_only_and_requires_exact_python_argv(tmp_path):
    helper = tmp_path / "overseer-codex-dispatch-activation"
    helper.write_bytes((system.CANONICAL_CHECKOUT / system.ROOT_HELPER_SOURCE).read_bytes())
    helper.chmod(0o444)

    with pytest.raises(PermissionError):
        subprocess.run([str(helper), "verify", "0" * 64], check=False)
    completed = subprocess.run(
        ["/usr/bin/python3", "-I", "-S", str(helper), "verify", "0" * 64],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    assert completed.returncode != 0
    assert "installed immutable path" in completed.stderr


def test_listener_attestation_binds_loopback_socket_to_exact_pid(monkeypatch, tmp_path):
    import overseer_codex_dispatch_root_helper as helper

    proc = tmp_path / "proc"
    pid = 4321
    (proc / str(pid) / "fd").mkdir(parents=True)
    (proc / str(pid) / "stat").write_text(f"{pid} (overseer) S " + " ".join(["0"] * 18 + ["777"] + ["0"] * 20))
    (proc / str(pid) / "cgroup").write_text("0::/system.slice/overseer-api.service\n")
    (proc / "net").mkdir()
    (proc / "net" / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        "   0: 0100007F:223E 00000000:0000 0A 0:0 00:0 0 1000 0 998877\n"
    )
    (proc / "net" / "tcp6").write_text("")
    os.symlink("socket:[998877]", proc / str(pid) / "fd" / "9")
    monkeypatch.setattr(helper, "PROC_ROOT", str(proc))

    evidence = helper._attest_loopback_listener(pid)
    assert evidence == {"inode": 998877, "pid": pid, "startTicks": 777}

    (proc / "9999" / "fd").mkdir(parents=True)
    os.symlink("socket:[998877]", proc / "9999" / "fd" / "3")
    with pytest.raises(ValueError, match="foreign process"):
        helper._attest_loopback_listener(pid)

    (proc / "net" / "tcp").write_text(
        "header\n   0: 00000000:223E 00000000:0000 0A 0:0 00:0 0 1000 0 998877\n"
    )
    with pytest.raises(ValueError, match="non-loopback"):
        helper._attest_loopback_listener(pid)


def test_health_200_is_rejected_when_listener_identity_changes(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    evidence = [
        {"inode": 1, "pid": 4321, "startTicks": 777},
        {"inode": 2, "pid": 4321, "startTicks": 777},
    ]

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(helper, "_attest_loopback_listener", lambda _pid: evidence.pop(0))
    monkeypatch.setattr(helper.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())
    read_fd, write_fd = os.pipe()
    monkeypatch.setattr(helper.os, "pidfd_open", lambda *_args: os.dup(read_fd))
    try:
        with pytest.raises(ValueError, match="changed during health"):
            helper._verify_bound_health(4321)
    finally:
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.parametrize(
    ("initial_phase", "unexpected"),
    [
        ("rollback-new-unit-quarantined", {"stop-system"}),
        ("rollback-old-unit-restored", {"stop-system"}),
        ("rollback-system-reloaded", {"stop-system", "daemon-reload"}),
        ("rollback-prior-system-enabled", {"stop-system", "daemon-reload"}),
        ("rollback-prior-system-active", {"stop-system", "daemon-reload"}),
        ("rollback-user-resources-restored", {"stop-system", "daemon-reload"}),
        ("rollback-user-manager-reloaded", {"stop-system", "daemon-reload", "hup"}),
        ("rollback-user-api-started", {"stop-system", "daemon-reload", "hup", "start-user"}),
    ],
)
def test_rollback_resumes_after_each_persisted_restoration_boundary(monkeypatch, initial_phase, unexpected):
    import overseer_codex_dispatch_root_helper as helper

    calls = []
    journal = {
        "schemaVersion": helper.SCHEMA, "planDigest": "d" * 64, "phase": initial_phase,
        "journalActionId": "action", "userResourceQuarantines": [
            {"activePath": "/old/user.conf", "quarantinePath": "/old/.user.conf.inert",
             "device": 2, "inode": 3, "sha256": "b" * 64},
        ],
        "oldSystemUnitQuarantine": "/etc/systemd/system/.old.inert",
        "systemUnitIdentity": [4, 5],
        "priorSystemServiceState": {"present": True, "enabled": False, "active": False},
        "lastError": "",
    }
    old_unit = {"path": helper.SYSTEM_UNIT, "sha256": "a" * 64, "device": 1,
                "inode": 2, "mode": 0o644, "uid": 0, "size": 10,
                "enabled": False, "active": False}
    old_user = {"path": "/old/user.conf", "sha256": "b" * 64, "device": 2,
                "inode": 3, "mode": 0o600, "uid": 1000, "size": 11}
    capability = {"planDigest": "d" * 64, "journalActionId": "action",
                  "systemUnit": "new", "systemUnitSha256": "c" * 64,
                  "oldSystemUnit": old_unit, "oldUserResources": [old_user],
                  "priorSystemServiceState": {"present": True, "enabled": False, "active": False},
                  "managerBinding": {}, "oldApiBinding": {}}
    monkeypatch.setattr(helper, "_read_journal", lambda _digest: journal)
    monkeypatch.setattr(helper, "_write_journal", lambda value: calls.append(value["phase"]))
    monkeypatch.setattr(helper, "_run_systemctl", lambda *args: calls.append("daemon-reload" if args == ("daemon-reload",) else "stop-system"))
    monkeypatch.setattr(helper, "_system_service_enabled", lambda: False)
    monkeypatch.setattr(helper, "_system_service_active", lambda: False)
    monkeypatch.setattr(helper, "_restore_exact_quarantine", lambda active, *_args, **_kwargs: calls.append("restore-unit" if active == helper.SYSTEM_UNIT else "restore-user"))
    monkeypatch.setattr(helper, "_pin_and_signal", lambda *_args: calls.append("hup"))
    monkeypatch.setattr(helper, "_run_user_systemctl", lambda *_args: calls.append("start-user"))
    monkeypatch.setattr(helper, "_wait_restored_user_api", lambda *_args: calls.append("attest-user"))

    helper._rollback(capability)

    assert not (unexpected & set(calls))
    assert calls[-2:] == ["attest-user", "rolled-back"]


def test_rollback_stops_only_after_operation_owned_unit_attestation(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    calls = []
    journal = {
        "schemaVersion": helper.SCHEMA, "planDigest": "d" * 64, "phase": "rollback-pending",
        "journalActionId": "action", "userResourceQuarantines": [],
        "oldSystemUnitQuarantine": "", "systemUnitIdentity": [4, 5],
        "priorSystemServiceState": {"present": False, "enabled": False, "active": False},
        "lastError": "",
    }
    capability = {"planDigest": "d" * 64, "journalActionId": "action",
                  "systemUnit": "new", "systemUnitSha256": "c" * 64,
                  "oldSystemUnit": None, "oldUserResources": [],
                  "priorSystemServiceState": dict(journal["priorSystemServiceState"])}

    class Crash(RuntimeError):
        pass

    monkeypatch.setattr(helper, "_read_journal", lambda _digest: journal)
    monkeypatch.setattr(helper, "_verify_system_unit", lambda *_args: calls.append("attest-owned"))
    monkeypatch.setattr(helper, "_system_service_active", lambda: True)
    monkeypatch.setattr(helper, "_run_systemctl", lambda *args: calls.append(args))
    monkeypatch.setattr(
        helper, "_write_journal",
        lambda value: (_ for _ in ()).throw(Crash()) if value["phase"] == "rollback-system-stopped" else None,
    )

    with pytest.raises(Crash):
        helper._rollback(capability)
    assert calls == ["attest-owned", ("disable", "--now", "overseer-api.service")]


def test_rollback_rejects_prior_service_state_journal_drift_before_stop(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    journal = {
        "schemaVersion": helper.SCHEMA, "planDigest": "d" * 64, "phase": "rollback-pending",
        "journalActionId": "action", "userResourceQuarantines": [],
        "oldSystemUnitQuarantine": "", "systemUnitIdentity": [4, 5],
        "priorSystemServiceState": {"present": False, "enabled": True, "active": False},
        "lastError": "",
    }
    capability = {"planDigest": "d" * 64, "journalActionId": "action",
                  "priorSystemServiceState": {"present": False, "enabled": False, "active": False}}
    monkeypatch.setattr(helper, "_read_journal", lambda _digest: journal)
    monkeypatch.setattr(helper, "_run_systemctl", lambda *_args: pytest.fail("stop called"))
    with pytest.raises(ValueError, match="journal binding"):
        helper._rollback(capability)


def test_rollback_restores_prior_enabled_active_state_without_repeated_disable(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    calls = []
    state = {"enabled": False, "active": False}
    prior = {"present": True, "enabled": True, "active": True}
    journal = {
        "schemaVersion": helper.SCHEMA, "planDigest": "d" * 64,
        "phase": "rollback-old-unit-restored", "journalActionId": "action",
        "userResourceQuarantines": [], "oldSystemUnitQuarantine": "/old.inert",
        "systemUnitIdentity": [4, 5], "priorSystemServiceState": prior, "lastError": "",
    }
    old = {"path": helper.SYSTEM_UNIT, "sha256": "a" * 64, "device": 1, "inode": 2,
           "mode": 0o644, "uid": 0, "size": 10, "enabled": True, "active": True}
    capability = {"planDigest": "d" * 64, "journalActionId": "action",
                  "systemUnit": "new", "systemUnitSha256": "c" * 64,
                  "oldSystemUnit": old, "oldUserResources": [],
                  "priorSystemServiceState": prior, "managerBinding": {}, "oldApiBinding": {}}

    def run_systemctl(*args):
        calls.append(args)
        if args[0] == "enable":
            state["enabled"] = True
        elif args[0] == "start":
            state["active"] = True

    monkeypatch.setattr(helper, "_read_journal", lambda _digest: journal)
    monkeypatch.setattr(helper, "_write_journal", lambda _value: None)
    monkeypatch.setattr(helper, "_restore_exact_quarantine", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_run_systemctl", run_systemctl)
    monkeypatch.setattr(helper, "_system_service_enabled", lambda: state["enabled"])
    monkeypatch.setattr(helper, "_system_service_active", lambda: state["active"])
    monkeypatch.setattr(helper, "_pin_and_signal", lambda *_args: None)
    monkeypatch.setattr(helper, "_run_user_systemctl", lambda *_args: None)
    monkeypatch.setattr(helper, "_wait_restored_user_api", lambda *_args: None)

    helper._rollback(capability)
    assert ("disable", "--now", "overseer-api.service") not in calls
    assert ("disable", "overseer-api.service") not in calls
    assert calls == [("daemon-reload",), ("enable", "overseer-api.service"),
                     ("start", "overseer-api.service")]
