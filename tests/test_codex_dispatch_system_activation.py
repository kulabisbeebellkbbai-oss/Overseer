from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

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
        {"binary": {"path": "/usr/local/bin/codex", "resolvedPath": "/usr/local/lib/codex.js",
                    "entryDevice": 1, "entryInode": 2, "entryMode": 0o777,
                    "device": 1, "inode": 3, "mode": 0o644, "links": 1,
                    "sha256": "9" * 64, "size": 100},
         "socketPath": "/home/god/.codex/app-server-control/app-server-control.sock",
         "priorRunning": False, "priorEvidence": None,
         "priorRemoteControlEnabled": None, "priorSettings": None, "uid": 1000, "gid": 1000},
        {"path": "/home/god/.config/psychlo/overseer-peer-secret", "sha256": "8" * 64,
         "device": 1, "inode": 4, "mode": 0o600, "uid": 1000, "gid": 1000,
         "links": 1, "size": 64},
    )


def test_plan_binds_closed_out_of_band_authority_ceremony_and_external_root_migration():
    spec = _spec()
    plan = system.plan_codex_dispatch_activation("admin.system-v2", spec, "migrate")

    assert plan.owner_domain is OwnerDomain.SISKO
    assert plan.risk_level is RiskLevel.HIGH
    assert plan.approval_level is ApprovalLevel.HUMAN
    assert plan.target == "system/overseer-api.service"
    assert [step.command[1] for step in plan.steps] == ["activate-system"]
    assert plan.adapter_metadata["externalCliOnly"] is True
    assert plan.adapter_metadata["apiExecutionAllowed"] is False
    artifact = plan.adapter_metadata["ceremonyArtifact"]
    assert artifact["rootAuthorityPath"] == str(system.ROOT_AUTHORITY_ROOT / f"{artifact['planDigest']}.json")
    assert artifact["activeAuthorityPath"] == str(system.ROOT_ACTIVE_AUTHORITY_PATH)
    assert set(artifact) == {"schemaVersion", "planDigest", "helperGitBlob", "helperSha256",
                             "helperSize", "rootHelperPath", "rootAuthorityPath",
                             "activeAuthorityPath", "instructions"}
    published = json.dumps(plan.adapter_metadata, sort_keys=True)
    assert "/usr/bin/sudo" not in published
    assert "CEREMONY_INSTALLER" not in published
    assert "command" not in plan.adapter_metadata
    assert spec.capability(plan.id)["rootPythonIdentity"] == spec.manifest.root_python
    assert spec.capability(plan.id)["priorSystemServiceState"] == {
        "present": False, "enabled": False, "active": False,
    }
    assert system.validate_codex_dispatch_activation_plan(plan) == spec


def test_product_has_no_authority_bootstrap_execution_command():
    import overseer.cli as cli

    system_source = inspect.getsource(system)
    cli_source = inspect.getsource(cli)
    assert "def bootstrap_codex_dispatch_authority" not in system_source
    assert '"bootstrap-codex-dispatch-authority"' not in cli_source
    assert "bootstrap_codex_dispatch_authority_status" not in cli_source
    assert "CEREMONY_INSTALLER" not in system_source


def test_authority_export_loads_stored_approved_plan_and_binds_real_approval(monkeypatch, tmp_path):
    from overseer.cli import export_codex_dispatch_authority_data_status
    from overseer.store import SQLiteStore

    store_path = tmp_path / "overseer.sqlite3"
    plan = replace(system.plan_codex_dispatch_activation("admin.system-v2", _spec(), "migrate"),
                   approved=True, approved_by="sisko", approved_at="2026-08-18T21:30:00+00:00")
    store = SQLiteStore(store_path)
    try:
        store.save_admin_change_plan(plan)
    finally:
        store.close()
    monkeypatch.setattr(system, "_reject_api_context", lambda: None)
    with system.external_activation_cli():
        result = export_codex_dispatch_authority_data_status(store_path, plan.id)
    approval = result["authorityRecord"]["approval"]
    assert approval == {
        "planId": plan.id, "approvedBy": "sisko", "approvedAt": plan.approved_at,
        "kind": "codex_app_server_dispatch_activation", "riskLevel": "high",
        "approvalLevel": "human", "ownerDomain": "sisko",
        "target": "system/overseer-api.service",
    }
    assert "command" not in json.dumps(result, sort_keys=True).lower()
    assert "sudo" not in json.dumps(result, sort_keys=True).lower()


def test_authority_export_rejects_noncanonical_or_non_sisko_stored_approval(monkeypatch, tmp_path):
    from overseer.cli import export_codex_dispatch_authority_data_status
    from overseer.store import SQLiteStore

    monkeypatch.setattr(system, "_reject_api_context", lambda: None)
    for suffix, approved_by, approved_at in (
        ("wrong-owner", "captain", "2026-08-18T21:30:00+00:00"),
        ("noncanonical-time", "sisko", "2026-08-18T21:30:00Z"),
    ):
        store_path = tmp_path / f"{suffix}.sqlite3"
        plan = replace(system.plan_codex_dispatch_activation(f"admin.{suffix}", _spec(), "migrate"),
                       approved=True, approved_by=approved_by, approved_at=approved_at)
        store = SQLiteStore(store_path)
        try:
            store.save_admin_change_plan(plan)
        finally:
            store.close()
        with system.external_activation_cli(), pytest.raises(ValueError, match="approved"):
            export_codex_dispatch_authority_data_status(store_path, plan.id)


def test_complete_system_unit_is_root_service_and_ignores_user_unit_search_paths():
    spec = _spec()
    unit = spec.system_unit
    assert "User=god\nGroup=god\n" in unit
    assert f"WorkingDirectory={spec.manifest.release_root}\n" in unit
    assert "ExecStart=/usr/bin/python3 -I -S " in unit
    assert "Restart=on-failure\n" in unit
    assert "NoNewPrivileges=true\n" in unit
    assert "ProtectSystem=strict\n" in unit
    assert "Environment=OVERSEER_PSYCHLO_PEER_SECRET_FILE=%d/psychlo-overseer-peer-secret\n" in unit
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
    monkeypatch.setattr(system, "_authority_files_present", lambda _spec, _plan_id: True)
    monkeypatch.setattr(system, "verify_system_activation_spec", lambda value: None)
    seen = []
    with system.external_activation_cli():
        result = system.execute_codex_dispatch_activation_plan(
            plan, adapter_enabled=True,
            runner=lambda step: seen.append(step.command) or AdminCommandResult(step.title, step.command, 0),
        )
    assert result.status.value == "completed"
    assert seen == [step.command for step in (*plan.steps, *plan.verification_steps)]


def test_external_execute_rejects_non_sisko_approval_before_root_authority(monkeypatch):
    plan = replace(system.plan_codex_dispatch_activation("admin.system-v2", _spec(), "migrate"),
                   approved=True, approved_by="captain", approved_at="2026-08-18T00:00:00+00:00")
    monkeypatch.setattr(system, "_reject_api_context", lambda: None)
    monkeypatch.setattr(system, "_authority_files_present", lambda *_args: pytest.fail("authority probed"))
    with system.external_activation_cli():
        result = system.execute_codex_dispatch_activation_plan(plan, adapter_enabled=True)
    assert result.status.value == "blocked"
    assert "HUMAN/SISKO" in result.summary


def test_swapped_coordinator_cannot_change_bootstrap_command_or_helper_digest(monkeypatch):
    plan = system.plan_codex_dispatch_activation("admin.system-v2", _spec(), "migrate")
    metadata = dict(plan.adapter_metadata)
    artifact = dict(metadata["ceremonyArtifact"])
    artifact["helperSha256"] = "0" * 64
    metadata["ceremonyArtifact"] = artifact
    with pytest.raises(ValueError, match="canonical"):
        system.validate_codex_dispatch_activation_plan(replace(plan, adapter_metadata=metadata))

    metadata = dict(plan.adapter_metadata)
    altered_spec = dict(metadata["spec"])
    helper = dict(altered_spec["helperBlob"])
    helper["blob"] = "1" * 40
    altered_spec["helperBlob"] = helper
    metadata["spec"] = altered_spec
    with pytest.raises(ValueError, match="canonical"):
        system.validate_codex_dispatch_activation_plan(replace(plan, adapter_metadata=metadata))


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


def test_root_helper_capability_rejects_extra_fields_and_authority_rejects_self_signed_unit(monkeypatch, tmp_path):
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
    helper._validate_capability(altered, altered["planDigest"])
    original_plan = replace(system.plan_codex_dispatch_activation("admin.system-v2", _spec(), "migrate"),
                            approved=True, approved_by="sisko", approved_at="2026-08-18T21:30:00+00:00")
    original_authority = system._approved_authority_record(original_plan, _spec())

    class Info:
        st_gid = 0

    authority_root = tmp_path / "authorities"
    authority_root.mkdir()
    monkeypatch.setattr(helper, "AUTHORITY_ROOT", str(authority_root))
    monkeypatch.setattr(
        helper, "_open_existing_authority_directory",
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY),
    )
    monkeypatch.setattr(
        helper, "_stable_file",
        lambda path, **_kwargs: ((b"h" * 123, Info()) if path == helper.HELPER_PATH
                                 else (helper._canonical(original_authority) + b"\n", Info())),
    )
    with pytest.raises(ValueError, match="does not exactly authorize"):
        helper._load_root_authority(altered)


def test_root_helper_rejects_historical_authority_after_active_pointer_supersession(monkeypatch, tmp_path):
    import overseer_codex_dispatch_root_helper as helper

    spec = _spec()
    plan = replace(system.plan_codex_dispatch_activation("admin.system-v2", spec, "migrate"),
                   approved=True, approved_by="sisko", approved_at="2026-08-18T21:30:00+00:00")
    capability = spec.capability(plan.id)
    authority = system._approved_authority_record(plan, spec)
    unsigned_pointer = {
        "schemaVersion": "overseer.codex-dispatch-active-authority.v1",
        "generation": 2, "planDigest": "f" * 64, "authorityDigest": "e" * 64,
        "authorityPath": f"/etc/overseer/codex-dispatch-authorities/{'f' * 64}.json",
        "supersedesPlanDigest": capability["planDigest"],
    }
    pointer = {**unsigned_pointer, "recordDigest": helper._digest(unsigned_pointer)}
    root = tmp_path / "authorities"; root.mkdir()
    monkeypatch.setattr(helper, "AUTHORITY_ROOT", str(root))
    monkeypatch.setattr(helper, "ACTIVE_AUTHORITY_PATH", str(root / "active.json"))
    authority["rootAuthorityPath"] = str(root / f"{capability['planDigest']}.json")
    authority["activeAuthorityPath"] = helper.ACTIVE_AUTHORITY_PATH
    authority["authorityDigest"] = helper._digest(
        {key: authority[key] for key in authority if key != "authorityDigest"}
    )
    monkeypatch.setattr(helper, "_open_existing_authority_directory",
                        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))

    class Info:
        st_gid = 0

    def stable(path, **_kwargs):
        if path == helper.HELPER_PATH:
            return b"h" * 123, Info()
        if path == helper.ACTIVE_AUTHORITY_PATH:
            return helper._canonical(pointer) + b"\n", Info()
        return helper._canonical(authority) + b"\n", Info()

    monkeypatch.setattr(helper, "_stable_file", stable)
    with pytest.raises(ValueError, match="currently active"):
        helper._load_root_authority(capability)


def test_root_helper_rejects_active_pointer_that_supersedes_itself(monkeypatch, tmp_path):
    import overseer_codex_dispatch_root_helper as helper

    spec = _spec()
    plan = replace(system.plan_codex_dispatch_activation("admin.system-v2", spec, "migrate"),
                   approved=True, approved_by="sisko", approved_at="2026-08-18T21:30:00+00:00")
    capability = spec.capability(plan.id)
    authority = system._approved_authority_record(plan, spec)
    root = tmp_path / "authorities"; root.mkdir()
    monkeypatch.setattr(helper, "AUTHORITY_ROOT", str(root))
    monkeypatch.setattr(helper, "ACTIVE_AUTHORITY_PATH", str(root / "active.json"))
    authority["rootAuthorityPath"] = str(root / f"{capability['planDigest']}.json")
    authority["activeAuthorityPath"] = helper.ACTIVE_AUTHORITY_PATH
    authority["authorityDigest"] = helper._digest(
        {key: authority[key] for key in authority if key != "authorityDigest"}
    )
    unsigned_pointer = {
        "schemaVersion": "overseer.codex-dispatch-active-authority.v1",
        "generation": 2, "planDigest": capability["planDigest"],
        "authorityDigest": authority["authorityDigest"],
        "authorityPath": authority["rootAuthorityPath"],
        "supersedesPlanDigest": capability["planDigest"],
    }
    pointer = {**unsigned_pointer, "recordDigest": helper._digest(unsigned_pointer)}
    monkeypatch.setattr(helper, "_open_existing_authority_directory",
                        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))

    class Info:
        st_gid = 0

    def stable(path, **_kwargs):
        if path == helper.HELPER_PATH:
            return b"h" * 123, Info()
        if path == helper.ACTIVE_AUTHORITY_PATH:
            return helper._canonical(pointer) + b"\n", Info()
        return helper._canonical(authority) + b"\n", Info()

    monkeypatch.setattr(helper, "_stable_file", stable)
    with pytest.raises(ValueError, match="currently active"):
        helper._load_root_authority(capability)


def test_per_plan_authority_paths_rotate_without_overwriting_prior_records():
    first = system.plan_codex_dispatch_activation("admin.system-v2-a", _spec(), "migrate")
    second = system.plan_codex_dispatch_activation("admin.system-v2-b", _spec(), "migrate")
    first_artifact = first.adapter_metadata["ceremonyArtifact"]
    second_artifact = second.adapter_metadata["ceremonyArtifact"]
    assert first_artifact["rootAuthorityPath"] != second_artifact["rootAuthorityPath"]
    assert first_artifact["rootAuthorityPath"].endswith(f"/{first_artifact['planDigest']}.json")
    assert second_artifact["rootAuthorityPath"].endswith(f"/{second_artifact['planDigest']}.json")
    assert first_artifact["activeAuthorityPath"] == second_artifact["activeAuthorityPath"]


def test_authority_directory_rejects_symlink_before_record_read(tmp_path):
    import overseer_codex_dispatch_root_helper as helper

    real = tmp_path / "real"
    real.mkdir(mode=0o755)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match="authority directory"):
        helper._open_existing_authority_directory(str(alias), uid=os.geteuid())


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

        def read(self):
            return b'{"ok":true,"service":"overseer-api","psychloBridgeReady":true}'

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


def test_signed_psychlo_readiness_probe_binds_exact_request_and_secret(monkeypatch, tmp_path):
    import overseer_codex_dispatch_root_helper as helper

    secret = b"r" * 64
    secret_path = tmp_path / "overseer-peer-secret"
    secret_path.write_bytes(secret)
    secret_path.chmod(0o600)
    info = secret_path.stat()
    monkeypatch.setattr(helper, "PSYCHLO_SECRET", str(secret_path))
    capability = {
        "planDigest": "d" * 64,
        "psychloPeerSecret": {
            "path": str(secret_path), "sha256": hashlib.sha256(secret).hexdigest(),
            "device": info.st_dev, "inode": info.st_ino, "mode": 0o600,
            "uid": os.geteuid(), "gid": os.getegid(), "links": 1, "size": len(secret),
        },
    }

    class Response:
        status = 200

        def __init__(self, request):
            request_body = request.data
            outer = json.loads(request_body)
            payload = outer["payload"]
            self.body = json.dumps({
                "accepted": True, "schemaVersion": "psychlo.readiness-probe-receipt.v1",
                "probeId": payload["probeId"], "service": "psychlo", "ready": True,
                "requestDigest": payload["requestDigest"],
            }, separators=(",", ":")).encode()
            timestamp = outer["occurredAt"]
            response_nonce = "response_readiness_123456"
            signature = hmac.new(
                secret,
                helper._canonical_peer_response(
                    "readiness-probe", outer["messageId"],
                    request.headers["X-psychlo-peer-nonce"], hashlib.sha256(request_body).hexdigest(),
                    timestamp, response_nonce, self.body,
                ), hashlib.sha256,
            ).hexdigest()
            self.headers = {
                "x-psychlo-peer-response-kind": "readiness-probe",
                "x-psychlo-peer-response-timestamp": timestamp,
                "x-psychlo-peer-response-nonce": response_nonce,
                "x-psychlo-peer-response-signature": signature,
            }

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(helper.urllib.request, "urlopen", lambda request, **_kwargs: Response(request))
    receipt = helper._verify_psychlo_readiness(capability)
    assert receipt["service"] == "psychlo"
    assert receipt["ready"] is True


def test_signed_psychlo_readiness_rejects_unsigned_boolean_receipt(monkeypatch, tmp_path):
    import overseer_codex_dispatch_root_helper as helper

    secret = b"s" * 64
    secret_path = tmp_path / "secret"
    secret_path.write_bytes(secret); secret_path.chmod(0o600)
    info = secret_path.stat()
    monkeypatch.setattr(helper, "PSYCHLO_SECRET", str(secret_path))
    capability = {"planDigest": "e" * 64, "psychloPeerSecret": {
        "path": str(secret_path), "sha256": hashlib.sha256(secret).hexdigest(),
        "device": info.st_dev, "inode": info.st_ino, "mode": 0o600,
        "uid": os.geteuid(), "gid": os.getegid(), "links": 1, "size": len(secret),
    }}

    class Unsigned:
        status = 200
        headers = {}
        def read(self): return b'{"accepted":true,"ready":true}'
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    monkeypatch.setattr(helper.urllib.request, "urlopen", lambda *_args, **_kwargs: Unsigned())
    with pytest.raises(ValueError, match="signed Psychlo readiness"):
        helper._verify_psychlo_readiness(capability)


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
                "enabled": False, "active": False, "activeProcess": None}
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


def test_rollback_before_any_quarantine_attests_baseline_without_restore_or_signal(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    journal = {
        "phase": "intent-system-unit", "planDigest": "d" * 64, "journalActionId": "action",
        "systemUnitIdentity": None, "oldSystemUnitQuarantine": "",
        "userResourceQuarantines": [], "daemonOwnership": "", "priorDaemonState": None,
        "priorSystemServiceState": {"present": True, "enabled": True, "active": True},
    }
    old_system = {"path": helper.SYSTEM_UNIT, "sha256": "a" * 64, "device": 1, "inode": 2,
                  "mode": 0o644, "uid": 0, "size": 10, "enabled": True, "active": True,
                  "activeProcess": {}}
    old_user = {"path": "/old/user.service", "sha256": "b" * 64, "device": 3, "inode": 4,
                "mode": 0o600, "uid": 1000, "size": 11}
    capability = {"planDigest": "d" * 64, "journalActionId": "action",
                  "oldSystemUnit": old_system, "oldUserResources": [old_user],
                  "priorSystemServiceState": dict(journal["priorSystemServiceState"])}
    writes = []
    monkeypatch.setattr(helper, "_read_journal", lambda _digest: journal)
    monkeypatch.setattr(helper, "_write_journal", lambda value: writes.append(value["phase"]))
    monkeypatch.setattr(helper, "_attest_unchanged_pre_activation_resources", lambda *_args: None)
    monkeypatch.setattr(helper, "_restore_codex_daemon", lambda _journal: None)
    monkeypatch.setattr(helper, "_restore_exact_quarantine", lambda *_args, **_kwargs: pytest.fail("restore called"))
    monkeypatch.setattr(helper, "_run_systemctl", lambda *_args: pytest.fail("systemctl called"))
    monkeypatch.setattr(helper, "_pin_and_signal", lambda *_args: pytest.fail("signal called"))

    helper._rollback(capability)
    assert writes == ["rolled-back"]


def test_rollback_after_prior_stop_but_before_quarantine_restores_only_prior_activity(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    journal = {
        "phase": "prior-system-stopped", "planDigest": "d" * 64, "journalActionId": "action",
        "systemUnitIdentity": None, "oldSystemUnitQuarantine": "", "userResourceQuarantines": [],
        "daemonOwnership": "", "priorDaemonState": None,
        "priorSystemServiceState": {"present": True, "enabled": True, "active": True},
    }
    capability = {"planDigest": "d" * 64, "journalActionId": "action",
                  "oldSystemUnit": {"active": True}, "oldUserResources": [],
                  "priorSystemServiceState": dict(journal["priorSystemServiceState"])}
    calls = []
    monkeypatch.setattr(helper, "_read_journal", lambda _digest: journal)
    monkeypatch.setattr(helper, "_restore_pre_quarantine_baseline", lambda _capability: calls.append("restore-prior-activity"))
    monkeypatch.setattr(helper, "_restore_codex_daemon", lambda _journal: None)
    monkeypatch.setattr(helper, "_write_journal", lambda value: calls.append(value["phase"]))
    monkeypatch.setattr(helper, "_restore_exact_quarantine", lambda *_args, **_kwargs: pytest.fail("quarantine restore called"))
    monkeypatch.setattr(helper, "_pin_and_signal", lambda *_args: pytest.fail("signal called"))

    helper._rollback(capability)
    assert calls == ["restore-prior-activity", "rolled-back"]


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
           "mode": 0o644, "uid": 0, "size": 10, "enabled": True, "active": True,
           "activeProcess": {}}
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


@pytest.mark.parametrize(
    ("crash_window", "expected_phase"),
    [("new-fsynced", "release-installed"),
     ("prior-replaced", "release-installed"),
     ("active-replaced", "release-installed")],
)
def test_journal_recovers_newest_committed_generation_at_every_replace_window(
        monkeypatch, tmp_path, crash_window, expected_phase):
    import overseer_codex_dispatch_root_helper as helper

    monkeypatch.setattr(helper, "STATE_ROOT", str(tmp_path))
    original_stable = helper._stable_file
    monkeypatch.setattr(
        helper, "_stable_file",
        lambda path, *, uid, mode, digest: (
            lambda result: (result[0], SimpleNamespace(st_gid=0))
        )(original_stable(path, uid=os.geteuid(), mode=mode, digest=digest)),
    )

    def user_directory(path, mode):
        os.makedirs(path, mode=mode, exist_ok=True)
        return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(helper, "_root_directory", user_directory)
    journal = {
        "schemaVersion": helper.SCHEMA, "planDigest": "d" * 64,
        "phase": "intent-system-unit", "journalActionId": "action",
        "userResourceQuarantines": [], "oldSystemUnitQuarantine": "",
        "systemUnitIdentity": None,
        "priorSystemServiceState": {"present": False, "enabled": False, "active": False},
        "priorDaemonState": None, "daemonOwnership": "", "daemonEvidence": None,
        "lastError": "",
    }
    helper._write_journal(journal)
    journal["phase"] = "release-installed"

    class Crash(RuntimeError):
        pass

    monkeypatch.setattr(
        helper, "_JOURNAL_CRASH_HOOK",
        lambda phase: (_ for _ in ()).throw(Crash()) if phase == crash_window else None,
    )
    with pytest.raises(Crash):
        helper._write_journal(journal)
    recovered = helper._read_journal("d" * 64)
    assert recovered["phase"] == expected_phase
    assert recovered["recordDigest"] == helper._digest(
        {key: recovered[key] for key in recovered if key != "recordDigest"}
    )
    if crash_window == "active-replaced":
        Path(helper._journal_path("d" * 64)).write_bytes(b"corrupt\n")
        assert helper._read_journal("d" * 64)["phase"] == "intent-system-unit"


@pytest.mark.parametrize("crash_window", ["new-fsynced", "prior-replaced"])
def test_journal_adopts_pending_generation_and_next_write_survives_restart(
        monkeypatch, tmp_path, crash_window):
    import overseer_codex_dispatch_root_helper as helper

    monkeypatch.setattr(helper, "STATE_ROOT", str(tmp_path))
    original_stable = helper._stable_file
    monkeypatch.setattr(
        helper, "_stable_file",
        lambda path, *, uid, mode, digest: (
            lambda result: (result[0], SimpleNamespace(st_gid=0))
        )(original_stable(path, uid=os.geteuid(), mode=mode, digest=digest)),
    )

    def user_directory(path, mode):
        os.makedirs(path, mode=mode, exist_ok=True)
        return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW)

    monkeypatch.setattr(helper, "_root_directory", user_directory)
    journal = {
        "schemaVersion": helper.SCHEMA, "planDigest": "e" * 64,
        "phase": "intent-system-unit", "journalActionId": "action",
        "userResourceQuarantines": [], "oldSystemUnitQuarantine": "",
        "systemUnitIdentity": None,
        "priorSystemServiceState": {"present": False, "enabled": False, "active": False},
        "priorDaemonState": None, "daemonOwnership": "", "daemonEvidence": None,
        "lastError": "",
    }
    helper._write_journal(journal)
    journal["phase"] = "release-installed"

    class Crash(RuntimeError):
        pass

    monkeypatch.setattr(
        helper, "_JOURNAL_CRASH_HOOK",
        lambda phase: (_ for _ in ()).throw(Crash()) if phase == crash_window else None,
    )
    with pytest.raises(Crash):
        helper._write_journal(journal)

    # A fresh helper process must adopt the fully fsynced pending generation,
    # then be able to publish the following generation without stale-name poison.
    assert helper._read_journal("e" * 64)["phase"] == "release-installed"
    monkeypatch.setattr(helper, "_JOURNAL_CRASH_HOOK", lambda _phase: None)
    recovered = helper._read_journal("e" * 64)
    recovered["phase"] = "daemon-ready"
    helper._write_journal(recovered)
    final = helper._read_journal("e" * 64)
    assert final["phase"] == "daemon-ready"
    assert final["generation"] == 3
    assert not list(tmp_path.glob("*.pending"))


def test_codex_daemon_start_intent_is_journaled_and_remote_control_is_disabled(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    calls = []
    daemon = _spec().codex_daemon
    capability = {"codexDaemon": daemon}
    journal = {"daemonOwnership": "", "priorDaemonState": None,
               "daemonEvidence": None, "phase": "intent-system-unit"}
    monkeypatch.setattr(helper, "_validate_codex_binary", lambda _binding: calls.append("binary-attested"))
    monkeypatch.setattr(helper.os.path, "lexists", lambda path: False if path == helper.CODEX_SOCKET else os.path.lexists(path))
    monkeypatch.setattr(helper, "_write_journal", lambda value: calls.append((value["phase"], value["daemonOwnership"])))
    def run_codex(*args):
        calls.append(args)
        if args[-1] == "bootstrap":
            return {"status": "bootstrapped", "backend": "pid", "autoUpdateEnabled": True,
                    "remoteControlEnabled": False, "managedCodexPath": "/managed/codex",
                    "managedCodexVersion": None, "socketPath": helper.CODEX_SOCKET,
                    "cliVersion": "1", "appServerVersion": "1"}
        if args[-1] == "disable-remote-control":
            return {"status": "disabled", "remoteControlEnabled": False,
                    "socketPath": helper.CODEX_SOCKET, "cliVersion": "1"}
        return {}

    monkeypatch.setattr(helper, "_run_codex", run_codex)
    evidence = {"version": {"remoteControlEnabled": False}, "peerPid": 8}
    monkeypatch.setattr(helper, "_codex_daemon_evidence", lambda: evidence)

    helper._ensure_codex_daemon(capability, journal)

    assert ("intent-daemon", "start-issued") in calls
    assert ("app-server", "daemon", "bootstrap") in calls
    assert ("app-server", "daemon", "disable-remote-control") in calls
    assert ("app-server", "daemon", "start") in calls
    assert journal["daemonOwnership"] == "started-by-operation"
    assert journal["daemonEvidence"] == evidence


def test_prior_active_root_service_is_attested_then_stopped_before_replacement(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    calls = []
    states = iter((True, False))
    capability = {"oldSystemUnit": {"active": True, "activeProcess": {"pid": 7}}}
    journal = {"phase": "release-installed"}
    monkeypatch.setattr(helper, "_system_service_active", lambda: next(states))
    monkeypatch.setattr(helper, "_pin_and_signal", lambda binding, signum: calls.append(("attest", binding, int(signum))))
    monkeypatch.setattr(helper, "_write_journal", lambda value: calls.append(("journal", value["phase"])))
    monkeypatch.setattr(helper, "_run_systemctl", lambda *args: calls.append(("systemctl", args)))

    helper._stop_prior_system_service(capability, journal)

    assert calls[0][0] == "attest"
    assert calls[1:] == [("journal", "intent-stop-prior-system"),
                         ("systemctl", ("stop", "overseer-api.service")),
                         ("journal", "prior-system-stopped")]


def test_prior_root_service_stop_crash_retry_does_not_repeat_stop(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    calls = []
    capability = {"oldSystemUnit": {"active": True, "activeProcess": {"pid": 7}}}
    journal = {"phase": "intent-stop-prior-system"}
    monkeypatch.setattr(helper, "_system_service_active", lambda: False)
    monkeypatch.setattr(helper, "_pin_and_signal", lambda *_args: pytest.fail("reattested dead process"))
    monkeypatch.setattr(helper, "_run_systemctl", lambda *_args: pytest.fail("repeated stop"))
    monkeypatch.setattr(helper, "_write_journal", lambda value: calls.append(value["phase"]))
    helper._stop_prior_system_service(capability, journal)
    assert calls == ["prior-system-stopped"]


@pytest.mark.parametrize("phase", ["prior-system-stopped", "system-unit-installed",
                                    "system-service-started", "verified"])
def test_prior_root_service_quiesce_is_not_repeated_after_journaled_boundary(monkeypatch, phase):
    import overseer_codex_dispatch_root_helper as helper

    capability = {"oldSystemUnit": {"active": True, "activeProcess": {"pid": 7}}}
    journal = {"phase": phase}
    monkeypatch.setattr(helper, "_system_service_active", lambda: pytest.fail("reprobed prior service"))
    monkeypatch.setattr(helper, "_pin_and_signal", lambda *_args: pytest.fail("resignalled prior PID"))
    monkeypatch.setattr(helper, "_run_systemctl", lambda *_args: pytest.fail("repeated prior stop"))
    monkeypatch.setattr(helper, "_write_journal", lambda _value: pytest.fail("rewrote stop phase"))

    helper._stop_prior_system_service(capability, journal)


@pytest.mark.parametrize("phase", ["system-service-started", "verified"])
def test_activation_retry_after_system_service_start_resumes_attestation_only(monkeypatch, phase):
    import overseer_codex_dispatch_root_helper as helper

    writes = []
    evidence = {"peerPid": 19, "peerStartTicks": 44}
    journal = {
        "phase": phase, "journalActionId": "action", "systemUnitIdentity": [8, 9],
        "daemonEvidence": evidence,
    }
    capability = {
        "planDigest": "f" * 64, "journalActionId": "action",
        "codexDaemon": {"binary": {}}, "systemUnitSha256": "a" * 64,
    }
    monkeypatch.setattr(helper.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(helper, "_read_journal", lambda _digest: journal)
    monkeypatch.setattr(helper, "_validate_codex_binary", lambda _binding: None)
    monkeypatch.setattr(helper, "_codex_daemon_evidence", lambda: evidence)
    monkeypatch.setattr(helper, "_install_release", lambda _capability, _stream: None)
    monkeypatch.setattr(helper, "_verify_system_unit", lambda _capability, identity: identity == (8, 9) or pytest.fail("wrong unit"))
    monkeypatch.setattr(helper, "_verify_system_api", lambda _capability: {"pid": 23})
    monkeypatch.setattr(helper, "_write_journal", lambda value: writes.append(value["phase"]))
    monkeypatch.setattr(helper, "_ensure_codex_daemon", lambda *_args: pytest.fail("restarted daemon stage"))
    monkeypatch.setattr(helper, "_stop_prior_system_service", lambda *_args: pytest.fail("repeated prior stop"))
    monkeypatch.setattr(helper, "_prepare_system_unit", lambda *_args: pytest.fail("reinstalled system unit"))
    monkeypatch.setattr(helper, "_pin_and_signal", lambda *_args: pytest.fail("repeated process signal"))
    monkeypatch.setattr(helper, "_run_systemctl", lambda *_args: pytest.fail("repeated service mutation"))

    helper._activate(capability, object())

    assert journal["phase"] == "verified"
    assert writes == ([] if phase == "verified" else ["verified"])


def test_daemon_rollback_attests_already_stopped_operation_daemon_without_second_stop(monkeypatch):
    import overseer_codex_dispatch_root_helper as helper

    calls = []
    journal = {
        "daemonOwnership": "started-by-operation",
        "daemonEvidence": {"peerPid": 17, "peerStartTicks": 99},
        "priorDaemonState": None,
    }
    monkeypatch.setattr(helper.os.path, "lexists", lambda path: False if path == helper.CODEX_SOCKET else os.path.lexists(path))
    monkeypatch.setattr(
        helper, "_run_codex",
        lambda *args: calls.append(args) or {
            "cliVersion": "1", "daemonVersion": "1", "state": "stopped",
            "remoteControlEnabled": False, "socketPath": helper.CODEX_SOCKET,
        },
    )
    monkeypatch.setattr(helper, "_process_start_ticks", lambda _pid: (_ for _ in ()).throw(FileNotFoundError()))
    monkeypatch.setattr(helper, "_write_journal", lambda value: calls.append(("journal", value["daemonOwnership"])))

    helper._restore_codex_daemon(journal)

    assert ("app-server", "daemon", "stop") not in calls
    assert calls == [("app-server", "daemon", "version"), ("journal", "stopped-by-rollback")]
