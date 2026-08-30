from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

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
