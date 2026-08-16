from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from overseer.admin import (
    AdminAdapterStatus,
    AdminChangeKind,
    ApprovalLevel,
    OwnerDomain,
    RiskLevel,
    admin_execution_capability_for,
)
from overseer.psychlo_cycle_activation import (
    PsychloCycleActivationSpec,
    plan_psychlo_recurring_cycle_activation,
    psychlo_cycle_activation_plan_digest,
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
