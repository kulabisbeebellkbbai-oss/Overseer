from __future__ import annotations

import hashlib
import inspect
import os
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
        "/usr/bin/sudo", "-n", str(system.ROOT_HELPER_PATH), "activate",
        spec.capability(plan.id)["planDigest"],
    ]
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
