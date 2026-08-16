from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

import overseer.psychlo_cycle_activation as cycle_activation
from overseer.admin import (
    AdminAdapterStatus,
    AdminChangeKind,
    ApprovalLevel,
    OwnerDomain,
    RiskLevel,
    admin_execution_capability_for,
    execute_admin_change_plan,
)
from overseer.psychlo_cycle_activation import (
    PsychloCycleActivationSpec,
    acquire_psychlo_cycle_activation_lock,
    execute_psychlo_cycle_activation_marker,
    plan_psychlo_recurring_cycle_activation,
    psychlo_cycle_activation_plan_digest,
    psychlo_cycle_activation_replay_verified,
    psychlo_cycle_activation_spec_from_private_file,
    validate_psychlo_cycle_activation_plan,
)


ROOT = Path(__file__).resolve().parents[1]
CODEX = Path("/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin/codex")


def _git(*args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(ROOT), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _private_file(path: Path, content: bytes) -> Path:
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _manifest(tmp_path: Path) -> dict[str, object]:
    installed = tmp_path / "units"
    installed.mkdir(mode=0o700)
    backups = tmp_path / "backups"
    backups.mkdir(mode=0o700)
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    auth = _private_file(config / "auth.json", b'{"tokens":{"access_token":"test"}}')
    signing = _private_file(config / "authority.pem", b"test-private-key")
    return {
        "schemaVersion": "overseer.psychlo-recurring-cycle-activation.v1",
        "sourceRoot": str(ROOT),
        "sourceCommit": _git("rev-parse", "HEAD"),
        "sourceTreeDigest": _git("rev-parse", "HEAD^{tree}"),
        "installedUnitDirectory": str(installed),
        "backupDirectory": str(backups / "psychlo-cycle"),
        "activationMarker": str(config / "producer-enabled"),
        "codexExecutable": str(CODEX),
        "codexExecutableSha256": hashlib.sha256(CODEX.read_bytes()).hexdigest(),
        "meterCredential": str(auth),
        "signingCredential": str(signing),
        "timerUnit": "overseer-psychlo-usage.timer",
        "cycleUnit": "overseer-psychlo-cycle.service",
        "meterUnit": "overseer-psychlo-meter.service",
        "deliveryUnit": "overseer-psychlo-usage.service",
    }


def test_manifest_is_closed_and_canonical(tmp_path: Path):
    manifest = _manifest(tmp_path)
    spec = PsychloCycleActivationSpec.from_json(manifest)

    assert spec.schema_version == "overseer.psychlo-recurring-cycle-activation.v1"
    assert spec.unit_names == (
        "overseer-psychlo-meter.service",
        "overseer-psychlo-usage.service",
        "overseer-psychlo-cycle.service",
        "overseer-psychlo-usage.timer",
    )
    assert psychlo_cycle_activation_plan_digest(spec) == psychlo_cycle_activation_plan_digest(
        PsychloCycleActivationSpec.from_json(json.loads(json.dumps(manifest, sort_keys=True)))
    )

    with pytest.raises(ValueError, match="exact keys"):
        PsychloCycleActivationSpec.from_json({**manifest, "commands": ["/bin/sh"]})


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("timerUnit", "other.timer", "timerUnit"),
        ("cycleUnit", "other.service", "cycleUnit"),
        ("sourceTreeDigest", "0" * 40, "source tree"),
        ("codexExecutableSha256", "0" * 64, "Codex executable digest"),
    ],
)
def test_manifest_rejects_identity_drift(tmp_path: Path, field: str, value: str, message: str):
    manifest = _manifest(tmp_path)
    manifest[field] = value
    with pytest.raises(ValueError, match=message):
        PsychloCycleActivationSpec.from_json(manifest)


def test_manifest_rejects_unsafe_credentials(tmp_path: Path):
    manifest = _manifest(tmp_path)
    Path(str(manifest["meterCredential"])).chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        PsychloCycleActivationSpec.from_json(manifest)


def test_private_manifest_stages_typed_plan_without_executing(tmp_path: Path):
    from overseer.cli import plan_admin_change_status

    manifest_path = tmp_path / "activation.json"
    manifest_path.write_text(json.dumps(_manifest(tmp_path), sort_keys=True), encoding="utf-8")
    manifest_path.chmod(0o600)
    spec = psychlo_cycle_activation_spec_from_private_file(manifest_path)
    status = plan_admin_change_status(
        tmp_path / "overseer.sqlite3",
        "admin.psychlo-cycle.activate.20260816",
        AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION.value,
        "overseer-psychlo-usage.timer",
        "activate approved recurring accounting",
        "disabled",
        psychlo_cycle_spec=spec,
    )

    assert status["kind"] == "psychlo_recurring_cycle_activation"
    assert status["approval_level"] == "human"
    assert status["approved"] is False
    assert not spec.activation_marker.exists()

    manifest_path.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        psychlo_cycle_activation_spec_from_private_file(manifest_path)


def test_plan_is_high_risk_human_approved_and_disabled_by_default(tmp_path: Path):
    spec = PsychloCycleActivationSpec.from_json(_manifest(tmp_path))
    plan = plan_psychlo_recurring_cycle_activation(
        "admin.psychlo-cycle.activate.20260816",
        spec,
        "activate approved cycle",
        "disabled",
    )

    assert plan.kind == AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION
    assert plan.owner_domain == OwnerDomain.OBRIEN
    assert plan.risk_level == RiskLevel.HIGH
    assert plan.approval_level == ApprovalLevel.HUMAN
    assert plan.approved is False
    assert plan.adapter_metadata["specDigest"] == psychlo_cycle_activation_plan_digest(spec)
    assert all(
        step.command[0].startswith("__overseer_psychlo_cycle_")
        for step in plan.steps + plan.rollback_steps + plan.verification_steps
    )
    assert admin_execution_capability_for(plan.kind).status == AdminAdapterStatus.DISABLED


def test_approved_plan_rejects_immutable_mutation(tmp_path: Path):
    spec = PsychloCycleActivationSpec.from_json(_manifest(tmp_path))
    plan = plan_psychlo_recurring_cycle_activation("admin.cycle", spec, "activate", "disabled")
    approved = replace(plan, approved=True, approved_by="human-user", approved_at="2026-08-16T12:00:00Z")
    validate_psychlo_cycle_activation_plan(approved)

    with pytest.raises(ValueError, match="canonical"):
        validate_psychlo_cycle_activation_plan(replace(approved, target="other.timer"))
    with pytest.raises(ValueError, match="canonical"):
        validate_psychlo_cycle_activation_plan(
            replace(approved, steps=(replace(approved.steps[0], title="changed"), *approved.steps[1:]))
        )


def _completed(args: tuple[str, ...], returncode: int = 0):
    return subprocess.CompletedProcess(args, returncode, stdout="ok", stderr="")


def test_fixed_marker_lifecycle_installs_canaries_and_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    spec = PsychloCycleActivationSpec.from_json(_manifest(tmp_path))
    plan = plan_psychlo_recurring_cycle_activation("admin.cycle", spec, "activate", "disabled")
    calls: list[tuple[str, ...]] = []

    def systemctl(args):
        value = tuple(args)
        calls.append(value)
        return _completed(value, 1 if value[0] == "is-enabled" and len(calls) == 1 else 0)

    observations = iter((("old", "old-digest"), ("new", "new-digest")))
    monkeypatch.setattr(cycle_activation, "_observation_identity", lambda: next(observations))
    monkeypatch.setattr(cycle_activation, "_delivered_observation", lambda observation_id: observation_id == "new")

    for step in plan.steps:
        code, _, error = execute_psychlo_cycle_activation_marker(step.command, systemctl_runner=systemctl)
        assert (code, error) == (0, "")
    code, _, error = execute_psychlo_cycle_activation_marker(plan.verification_steps[0].command, systemctl_runner=systemctl)

    assert (code, error) == (0, "")
    assert calls == [
        ("is-enabled", "overseer-psychlo-usage.timer"),
        ("daemon-reload",),
        ("start", "--wait", "overseer-psychlo-cycle.service"),
        ("enable", "--now", "overseer-psychlo-usage.timer"),
        ("is-enabled", "overseer-psychlo-usage.timer"),
        ("is-active", "overseer-psychlo-usage.timer"),
    ]
    assert json.loads(spec.activation_marker.read_text())["planId"] == plan.id
    for name, digest in spec.unit_sha256:
        assert hashlib.sha256((spec.installed_unit_directory / name).read_bytes()).hexdigest() == digest
    assert psychlo_cycle_activation_replay_verified(plan, systemctl_runner=systemctl) is True


def test_meter_canary_failure_prevents_timer_enable_and_triggers_rollback(tmp_path: Path):
    spec = PsychloCycleActivationSpec.from_json(_manifest(tmp_path))
    plan = replace(
        plan_psychlo_recurring_cycle_activation("admin.cycle", spec, "activate", "disabled"),
        approved=True,
        approved_by="human-user",
        approved_at="2026-08-16T12:00:00Z",
    )
    seen: list[str] = []

    def runner(step):
        from overseer.admin import AdminCommandResult

        operation = step.command[0]
        seen.append(operation)
        return AdminCommandResult(step.title, step.command, 1 if operation.endswith("_canary") else 0, "", "meter failed")

    result = execute_admin_change_plan(
        plan,
        runner=runner,
        enabled_adapter_kinds=(AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION,),
    )

    assert result.status.value == "failed"
    assert "__overseer_psychlo_cycle_enable_timer" not in seen
    assert seen[-1] == "__overseer_psychlo_cycle_rollback"


def test_rollback_restores_partial_install_before_marker_publication(tmp_path: Path):
    spec = PsychloCycleActivationSpec.from_json(_manifest(tmp_path))
    plan = plan_psychlo_recurring_cycle_activation("admin.cycle", spec, "activate", "disabled")
    old_meter = b"old-meter-unit\n"
    (spec.installed_unit_directory / spec.meter_unit).write_bytes(old_meter)

    def systemctl(args):
        value = tuple(args)
        return _completed(value, 1 if value[0] == "is-enabled" else 0)

    for step in plan.steps[:2]:
        assert execute_psychlo_cycle_activation_marker(step.command, systemctl_runner=systemctl)[0] == 0
    assert not spec.activation_marker.exists()
    assert (spec.installed_unit_directory / spec.cycle_unit).exists()

    code, _, error = execute_psychlo_cycle_activation_marker(plan.rollback_steps[0].command, systemctl_runner=systemctl)

    assert (code, error) == (0, "")
    assert (spec.installed_unit_directory / spec.meter_unit).read_bytes() == old_meter
    assert not (spec.installed_unit_directory / spec.cycle_unit).exists()
    assert not spec.activation_marker.exists()


def test_concurrent_exact_plan_is_blocked_before_commands_or_rollback(tmp_path: Path):
    spec = PsychloCycleActivationSpec.from_json(_manifest(tmp_path))
    plan = replace(
        plan_psychlo_recurring_cycle_activation("admin.cycle", spec, "activate", "disabled"),
        approved=True,
        approved_by="human-user",
        approved_at="2026-08-16T12:00:00Z",
    )
    lock = acquire_psychlo_cycle_activation_lock(plan)
    called = False

    def runner(_step):
        nonlocal called
        called = True
        raise AssertionError("contender must not run commands")

    try:
        result = execute_admin_change_plan(
            plan,
            runner=runner,
            enabled_adapter_kinds=(AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION,),
        )
    finally:
        lock.release()

    assert result.status.value == "blocked"
    assert called is False
