from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


GUEST_SCRIPT = Path(__file__).parent / "phase_b_rehearsal" / "guest_rehearsal.py"
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


def load_guest_module():
    spec = importlib.util.spec_from_file_location("phase_b_guest_rehearsal", GUEST_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_guest_module_import_is_safe_and_exposes_contract_constants() -> None:
    module = load_guest_module()

    assert module.REHEARSAL_ROOT == Path("/var/lib/overseer-phase-b-rehearsal")
    assert module.CANARY_UID == 984
    assert module.BRIDGE_UID == 1000
    assert module.REQUIRED_CONTROLS == EXPECTED_CONTROLS


def test_import_boundary_does_not_spawn_systemd_or_other_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_spawned(*args: object, **kwargs: object) -> None:
        raise AssertionError("guest import spawned a process")

    monkeypatch.setattr(subprocess, "run", fail_if_spawned)
    load_guest_module()


def test_result_serializer_emits_one_bounded_canonical_record() -> None:
    module = load_guest_module()

    encoded = module.serialize_result(
        status="passed",
        stage="phase-complete",
        controls={control: True for control in EXPECTED_CONTROLS},
        identifiers={"runId": "phase-b-rehearsal-1"},
    )

    record = json.loads(encoded)
    assert set(record) == {"schemaVersion", "status", "stage", "controls", "identifiers", "failure"}
    assert record["schemaVersion"] == "overseer.phase-b-disposable-rehearsal.v1"
    assert record["status"] == "passed"
    assert record["failure"] is None
    assert record["controls"] == {control: True for control in sorted(EXPECTED_CONTROLS)}
    assert encoded == json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    (
        ({"status": "running"}, "status"),
        ({"status": "failed", "stage": "raw verifier output"}, "stage"),
        ({"status": "failed", "stage": "cleanup", "failure": "x" * 129}, "failure"),
        ({"status": "passed", "stage": "phase-complete", "identifiers": {"adminSecret": "x"}}, "key"),
        (
            {
                "status": "passed",
                "stage": "phase-complete",
                "identifiers": {"runId": "phase-b-rehearsal-admin-secret"},
            },
            "value",
        ),
    ),
)
def test_result_serializer_rejects_secret_bearing_or_unbounded_fields(
    kwargs: dict[str, object], reason: str
) -> None:
    module = load_guest_module()
    controls = {control: True for control in EXPECTED_CONTROLS}
    arguments = {
        "status": "passed",
        "stage": "phase-complete",
        "controls": controls,
    }
    arguments.update(kwargs)

    with pytest.raises(ValueError, match=reason):
        module.serialize_result(**arguments)


def test_serial_result_has_exact_sentinels_and_one_json_object() -> None:
    module = load_guest_module()
    record = module.serialize_result(
        status="failed",
        stage="preflight",
        failure="PreflightError",
        controls={control: False for control in EXPECTED_CONTROLS},
    )

    framed = module.frame_serial_result(record)
    lines = framed.splitlines()
    assert lines[0] == "OVERSEER_PHASE_B_REHEARSAL_RESULT_BEGIN"
    assert lines[-1] == "OVERSEER_PHASE_B_REHEARSAL_RESULT_END"
    assert len(lines) == 3
    assert json.loads(lines[1]) == json.loads(record)


def test_serial_framer_revalidates_secret_bearing_values() -> None:
    module = load_guest_module()
    controls = {control: True for control in EXPECTED_CONTROLS}
    record = {
        "schemaVersion": "overseer.phase-b-disposable-rehearsal.v1",
        "status": "passed",
        "stage": "phase-complete",
        "controls": controls,
        "identifiers": {"runId": "phase-b-rehearsal-api-token"},
        "failure": None,
    }

    with pytest.raises(ValueError, match="contract"):
        module.frame_serial_result(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def valid_preflight_snapshot() -> dict[str, object]:
    return {
        "euid": 0,
        "pid1": "systemd",
        "sourceIsDirectory": True,
        "sourceIsSymlink": False,
        "sourceMountReadOnly": True,
        "interfaces": {"lo": "unknown", "eth0": "down"},
        "users": {
            984: {"name": "overseer", "uid": 984, "gid": 984},
            1000: {"name": "god", "uid": 1000, "gid": 1000},
        },
        "groups": {
            984: {"name": "overseer", "gid": 984},
            1000: {"name": "god", "gid": 1000},
        },
    }


@pytest.mark.parametrize(
    ("mutate", "reason"),
    (
        (lambda value: value.update(euid=1000), "root"),
        (lambda value: value.update(pid1="init"), "systemd"),
        (lambda value: value.update(sourceIsDirectory=False), "read-only mount"),
        (lambda value: value.update(sourceIsSymlink=True), "read-only mount"),
        (lambda value: value.update(sourceMountReadOnly=False), "read-only mount"),
        (lambda value: value.update(interfaces={"lo": "unknown", "eth0": "up"}), "network"),
        (lambda value: value["users"][984].update(name="wrong"), "identity 984"),
        (lambda value: value["users"][984].update(gid=1000), "identity 984"),
        (lambda value: value["groups"][984].update(name="wrong"), "identity 984"),
        (lambda value: value["users"][1000].update(name="wrong"), "identity 1000"),
        (lambda value: value["users"][1000].update(gid=984), "identity 1000"),
        (lambda value: value["groups"][1000].update(name="wrong"), "identity 1000"),
    ),
)
def test_preflight_rejects_every_unsafe_guest_condition(mutate, reason: str) -> None:
    module = load_guest_module()
    snapshot = valid_preflight_snapshot()
    mutate(snapshot)

    with pytest.raises(module.PreflightError, match=reason):
        module.validate_preflight_snapshot(snapshot)


def test_preflight_accepts_only_the_complete_guest_contract() -> None:
    module = load_guest_module()
    module.validate_preflight_snapshot(valid_preflight_snapshot())


def test_rendered_units_use_real_credentials_and_production_socket_contracts() -> None:
    module = load_guest_module()
    units = module.render_guest_units(
        source_root=Path("/mnt/overseer-source"),
        python_path=Path("/usr/bin/python3"),
        state_directory=Path("/var/lib/overseer-canary/0123456789abcdef0123456789abcdef"),
    )

    canary = units["overseer-api-canary.service"]
    for entry in (
        "LoadCredential=api-token:/etc/overseer-phase-b-rehearsal/api-token",
        "LoadCredential=admin-approval-verifier.json:/etc/overseer-phase-b-rehearsal/admin-approval-verifier.json",
        "LoadCredential=roadex-fixture-approval-verifier.json:/etc/overseer-phase-b-rehearsal/roadex-fixture-approval-verifier.json",
        "LoadCredential=admin-ticket-private-key:/etc/overseer-phase-b-rehearsal/admin-ticket-private-key",
        "Environment=OVERSEER_DEDICATED_PRINCIPAL=1",
        "Environment=OVERSEER_ADMIN_TICKET_PRIVATE_KEY=%d/admin-ticket-private-key",
        "Environment=OVERSEER_ADMIN_EXECUTOR_SOCKET=/run/overseer/admin-executor.sock",
        "Environment=OVERSEER_USER_BRIDGE_SOCKET=/run/overseer/codex-user-bridge.sock",
        "Environment=OVERSEER_USER_BRIDGE_SERVER_UID=1000",
        "--auth-token-file %d/api-token",
        "--admin-approval-verifier-file %d/admin-approval-verifier.json",
        "--roadex-fixture-approval-verifier-file %d/roadex-fixture-approval-verifier.json",
    ):
        assert entry in canary
    assert "/run/overseer-phase-b-rehearsal/bridge.sock" not in canary
    assert "ListenStream=/run/overseer/codex-user-bridge.sock" in units["overseer-codex-user-bridge.socket"]
    assert "ListenStream=/run/overseer/admin-executor.sock" in units["overseer-admin-executor.socket"]


def test_canary_namespace_contract_has_traversable_production_ownership() -> None:
    module = load_guest_module()
    contract = module.canary_namespace_contract(
        Path("/var/lib/overseer-canary/0123456789abcdef0123456789abcdef")
    )

    assert contract["stateDirectory"] == {"uid": 984, "gid": 984, "mode": 0o700}
    assert contract["store"] == {"uid": 984, "gid": 984, "mode": 0o600}
    assert contract["runtimeParent"] == {"uid": 0, "gid": 984, "mode": 0o710}
    assert contract["executorSocket"] == {"uid": 984, "gid": 0, "mode": 0o600}
    assert contract["bridgeSocket"] == {"uid": 984, "gid": 0, "mode": 0o600}
    assert contract["apiRuntime"] == {"uid": 984, "gid": 984, "mode": 0o700}
    assert contract["apiSocket"] == {"uid": 984, "gid": 984, "mode": 0o600}


def test_handoff_rejects_unexpected_artifacts_and_applies_uid_984(tmp_path: Path) -> None:
    module = load_guest_module()
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    for name in ("overseer.sqlite3", "psychlo-bridge.sqlite3", "roadex-relay.sqlite3"):
        (state / name).write_bytes(b"sqlite")
        (state / name).chmod(0o600)
    calls: list[tuple[str, str, int, int]] = []

    module.handoff_canary_namespace(
        state,
        expected_owner_uid=os.geteuid(),
        expected_owner_gid=os.getegid(),
        chown=lambda path, uid, gid: calls.append(("chown", Path(path).name, uid, gid)),
        chmod=lambda path, mode: calls.append(("chmod", Path(path).name, mode, 0)),
    )

    assert {call[1] for call in calls if call[0] == "chown"} == {
        "state", "overseer.sqlite3", "psychlo-bridge.sqlite3", "roadex-relay.sqlite3"
    }
    assert all(call[2:] == (984, 984) for call in calls if call[0] == "chown")
    (state / "unexpected").write_text("no", encoding="ascii")
    with pytest.raises(module.RehearsalError, match="unexpected"):
        module.handoff_canary_namespace(
            state,
            expected_owner_uid=os.geteuid(),
            expected_owner_gid=os.getegid(),
            chown=lambda *args: None,
            chmod=lambda *args: None,
        )


def complete_control_evidence() -> dict[str, dict[str, bool]]:
    return {control: {"observed": True} for control in EXPECTED_CONTROLS}


@pytest.mark.parametrize("control", sorted(EXPECTED_CONTROLS))
def test_no_control_passes_without_observed_evidence(control: str) -> None:
    module = load_guest_module()
    evidence = complete_control_evidence()
    evidence[control]["observed"] = False

    with pytest.raises(module.RehearsalError, match=control):
        module.controls_from_evidence(evidence)


def test_systemd_runtime_evidence_requires_properties_metadata_and_activation_delta() -> None:
    module = load_guest_module()
    evidence = module.verify_systemd_runtime_evidence(
        load_credentials={
            "api-token", "admin-approval-verifier.json",
            "roadex-fixture-approval-verifier.json", "admin-ticket-private-key",
        },
        socket_metadata={
            "executor": {"uid": 984, "gid": 0, "mode": 0o600},
            "bridge": {"uid": 984, "gid": 0, "mode": 0o600},
            "api": {"uid": 984, "gid": 984, "mode": 0o600},
        },
        accepted_before={"executor": 0, "bridge": 0},
        accepted_after={"executor": 1, "bridge": 1},
        receipt_observed=True,
    )
    assert evidence == {"systemdCredentials": {"observed": True}, "socketActivation": {"observed": True}}

    with pytest.raises(module.RehearsalError, match="activation"):
        module.verify_systemd_runtime_evidence(
            load_credentials={"api-token"}, socket_metadata={},
            accepted_before={"executor": 1, "bridge": 1},
            accepted_after={"executor": 1, "bridge": 1}, receipt_observed=False,
        )


def test_authority_lock_inspection_uses_real_sqlite_sibling_and_never_creates(tmp_path: Path) -> None:
    module = load_guest_module()
    store = tmp_path / "overseer.sqlite3"
    store.write_bytes(b"")
    lock = tmp_path / ".overseer.sqlite3.admin-authority.lock"
    with pytest.raises(module.RehearsalError, match="authority lock"):
        module.inspect_authority_lock(store, expected_uid=os.geteuid())
    assert not lock.exists()
    lock.write_bytes(b"")
    lock.chmod(0o600)
    assert module.inspect_authority_lock(store, expected_uid=os.geteuid()) is True


def test_real_hidden_reader_uses_pty_and_durable_ordering(tmp_path: Path) -> None:
    module = load_guest_module()
    ledger = tmp_path / "progress.jsonl"

    assert module.exercise_production_hidden_reader(ledger) is True
    module.record_progress(ledger, "systemd-start")
    events = [json.loads(line)["event"] for line in ledger.read_text(encoding="ascii").splitlines()]
    assert events.index("authorization-complete") < events.index("systemd-start")


def test_production_cleanup_and_rollback_entrypoints_are_required() -> None:
    module = load_guest_module()
    calls: list[str] = []

    class Activation:
        ACTIVATION_CONTRACT_SCHEMA = "contract.v2"

        def _execute_resilient_cleanup(self, *args, **kwargs):
            calls.append("cleanup")
            return True

        def execute_approved_rollback(self, package_root):
            calls.append("rollback")
            return {"status": "aborted_before_cutover", "replayed": True}

    before = {"artifact": "digest"}
    result = module.run_production_cleanup_and_replay(
        Activation(), contract={"schemaVersion": "contract.v2"}, package_root=Path("/guest/package"),
        package_digest="a" * 64, snapshot=lambda: dict(before),
    )
    assert result == {"status": "aborted_before_cutover", "replayed": True}
    assert calls == ["cleanup", "rollback"]


def test_stop_aggregates_failures_and_keeps_cleanup_needed() -> None:
    module = load_guest_module()
    module._UNITS_MAY_BE_ACTIVE = True

    def failed_systemctl(*arguments: str, check: bool = True):
        action = arguments[0]
        return SimpleNamespace(returncode=1 if action == "stop" else 0, stdout="active\n", stderr="")

    with pytest.raises(module.RehearsalError, match="cleanup"):
        module.stop_disposable_units(systemctl=failed_systemctl, processes_for_uid=lambda uid: (4242,))
    assert module._UNITS_MAY_BE_ACTIVE is True


def test_stop_clears_cleanup_needed_only_after_all_units_and_uid_are_quiescent() -> None:
    module = load_guest_module()
    module._UNITS_MAY_BE_ACTIVE = True

    def stopped_systemctl(*arguments: str, check: bool = True):
        return SimpleNamespace(returncode=0 if arguments[0] == "stop" else 3, stdout="inactive\n", stderr="")

    module.stop_disposable_units(systemctl=stopped_systemctl, processes_for_uid=lambda uid: ())
    assert module._UNITS_MAY_BE_ACTIVE is False


def test_stage_tracker_retains_provisioning_across_exception() -> None:
    module = load_guest_module()
    tracker = module.StageTracker()
    tracker.advance("provisioning")
    try:
        raise module.RehearsalError("failed")
    except module.RehearsalError:
        pass
    assert tracker.current == "provisioning"


def test_guest_marker_powers_off_after_any_main_error(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_guest_module()
    powered_off: list[bool] = []
    monkeypatch.setenv("OVERSEER_PHASE_B_GUEST", "1")
    monkeypatch.setattr(module, "_run_rehearsal", lambda tracker: (_ for _ in ()).throw(module.PreflightError("bad")))
    monkeypatch.setattr(module, "_poweroff_guest", lambda: powered_off.append(True))
    monkeypatch.setattr(module, "stop_disposable_units", lambda **kwargs: None)

    assert module.main([]) == 1
    assert powered_off == [True]


def test_outer_service_allows_only_explicit_guest_and_unit_paths() -> None:
    service = (GUEST_SCRIPT.parent / "guest_rehearsal.service").read_text(encoding="utf-8")
    assert "Environment=OVERSEER_PHASE_B_GUEST=1" in service
    for path in (
        "/etc/overseer-phase-b-rehearsal",
        "/run/overseer",
        "/run/overseer-canary",
        "/var/lib/overseer-canary",
        "/var/lib/overseer-executor",
        "/etc/systemd/system/overseer-api-canary.service",
        "/etc/systemd/system/overseer-admin-executor.socket",
        "/etc/systemd/system/overseer-admin-executor@.service",
        "/etc/systemd/system/overseer-codex-user-bridge.socket",
        "/etc/systemd/system/overseer-codex-user-bridge.service",
    ):
        assert path in service
    assert "ReadWritePaths=/etc/systemd/system\n" not in service
