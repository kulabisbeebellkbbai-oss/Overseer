from __future__ import annotations

import io
import json

import pytest

from overseer.activation_progress import classify_phase_b_command, emit_activation_progress


VALID_STAGES = {
    "principal-bootstrap",
    "release-install",
    "credential-install",
    "unit-install",
    "canary-store-stage",
    "staging-verification",
    "systemd-reload",
    "runtime-directory-create",
    "human-authorization",
    "canary-socket-start",
    "canary-service-start",
    "canary-health",
    "canary-acceptance",
    "canary-stop",
    "evidence-seal",
    "cleanup",
    "unknown-sealed-command",
}


def test_emit_activation_progress_writes_one_canonical_schema_record() -> None:
    stream = io.StringIO()

    result = emit_activation_progress(
        package_digest="a" * 64,
        phase="staging-canary",
        status="stage-started",
        stage="canary-health",
        command_index=3,
        failure="exit-7",
        stream=stream,
    )

    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert set(record) == {
        "schemaVersion",
        "packageDigest",
        "phase",
        "status",
        "stage",
        "commandIndex",
        "failure",
        "secretValuesRecorded",
    }
    assert record == result
    assert record["schemaVersion"] == "overseer.activation-progress.v1"
    assert record["packageDigest"] == "a" * 64
    assert record["commandIndex"] == 3
    assert record["failure"] == "exit-7"
    assert record["secretValuesRecorded"] is False
    assert stream.getvalue() == json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("phase", "not-a-phase"),
        ("status", "not-a-status"),
        ("stage", "not-a-stage"),
        ("failure", "raw verifier output: " + "x" * 256),
        ("command_index", True),
        ("command_index", 1.5),
    ),
)
def test_emit_activation_progress_rejects_unbounded_or_unknown_values(
    field: str,
    value: object,
) -> None:
    arguments: dict[str, object] = {
        "package_digest": "b" * 64,
        "phase": "staging-canary",
        "status": "phase-started",
        "stage": "unknown-sealed-command",
        "stream": io.StringIO(),
    }
    arguments[field] = value

    with pytest.raises(ValueError):
        emit_activation_progress(**arguments)


@pytest.mark.parametrize(
    ("command", "expected"),
    (
        (["/opt/overseer/python", "ensure-dedicated-principal"], "principal-bootstrap"),
        (["/usr/bin/install", "-d", "/opt/overseer/releases"], "release-install"),
        (["/usr/bin/install", "/tmp/api-token", "/etc/overseer/api-token"], "credential-install"),
        (["/usr/bin/install", "/tmp/unit", "/etc/systemd/system/overseer-api.service"], "unit-install"),
        (["/opt/overseer/python", "stage-canary-store"], "canary-store-stage"),
        (["/opt/overseer/python", "verify-approved-staging"], "staging-verification"),
        (["/usr/bin/systemctl", "daemon-reload"], "systemd-reload"),
        (["/usr/bin/systemd-tmpfiles", "--create", "/etc/tmpfiles.d/overseer.conf"], "runtime-directory-create"),
        (["/usr/bin/systemctl", "start", "overseer-admin-executor.socket"], "canary-socket-start"),
        (["/opt/overseer/python", "handoff-start-canary"], "canary-service-start"),
        (["/usr/bin/curl", "--unix-socket", "/run/overseer-canary/api.sock", "http://localhost/health"], "canary-health"),
        (["/opt/overseer/python", "run-approved-canary"], "canary-acceptance"),
        (["/usr/bin/systemctl", "stop", "overseer-api-canary.service"], "canary-stop"),
        (["/usr/bin/true", "unrecognized"], "unknown-sealed-command"),
    ),
)
def test_classify_phase_b_command_returns_only_bounded_stages(
    command: list[str],
    expected: str,
) -> None:
    assert expected in VALID_STAGES
    assert classify_phase_b_command(command) == expected
