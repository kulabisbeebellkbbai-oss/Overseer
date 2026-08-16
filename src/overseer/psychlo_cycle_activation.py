"""Immutable, approval-gated activation of the Psychlo recurring accounting cycle."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

from .admin import AdminChangeKind, AdminChangePlan, AdminCommandStep
from .core import ApprovalLevel, OwnerDomain, RiskLevel


SCHEMA_VERSION = "overseer.psychlo-recurring-cycle-activation.v1"
EXPECTED_CODEX_EXECUTABLE = Path(
    "/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin/codex"
)
EXPECTED_UNITS = {
    "timerUnit": "overseer-psychlo-usage.timer",
    "cycleUnit": "overseer-psychlo-cycle.service",
    "meterUnit": "overseer-psychlo-meter.service",
    "deliveryUnit": "overseer-psychlo-usage.service",
}
_EXPECTED_KEYS = {
    "schemaVersion",
    "sourceRoot",
    "sourceCommit",
    "sourceTreeDigest",
    "installedUnitDirectory",
    "backupDirectory",
    "activationMarker",
    "codexExecutable",
    "codexExecutableSha256",
    "meterCredential",
    "signingCredential",
    *EXPECTED_UNITS.keys(),
}
_HEX_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_absolute_path(value: object, label: str, *, must_exist: bool) -> Path:
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        raise ValueError(f"{label} must be a canonical absolute path")
    path = Path(value)
    if any(part in {".", ".."} for part in path.parts):
        raise ValueError(f"{label} must not contain dot path components")
    current = Path("/")
    parts = path.parts[1:] if must_exist else path.parent.parts[1:]
    for part in parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} must not traverse symlinks")
    if must_exist and not path.exists():
        raise ValueError(f"{label} does not exist")
    return path


def _owner_only_regular(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} must be an owner-only regular file")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError(f"{label} must be an owner-only regular file")


def _owner_controlled_directory(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} must be an owner-controlled directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError(f"{label} must be an owner-controlled directory")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_identity(source_root: Path, ref: str) -> str:
    completed = subprocess.run(
        ("/usr/bin/git", "-C", str(source_root), "rev-parse", "--verify", ref),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "XDG_CONFIG_HOME": "/nonexistent",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_NOGLOBAL": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        },
    )
    if completed.returncode != 0:
        raise ValueError(f"cannot verify source identity: {ref}")
    return completed.stdout.strip().lower()


@dataclass(frozen=True)
class PsychloCycleActivationSpec:
    schema_version: str
    source_root: Path
    source_commit: str
    source_tree_digest: str
    installed_unit_directory: Path
    backup_directory: Path
    activation_marker: Path
    codex_executable: Path
    codex_executable_sha256: str
    meter_credential: Path
    signing_credential: Path
    timer_unit: str
    cycle_unit: str
    meter_unit: str
    delivery_unit: str
    unit_sha256: tuple[tuple[str, str], ...]

    @property
    def unit_names(self) -> tuple[str, ...]:
        return (self.meter_unit, self.delivery_unit, self.cycle_unit, self.timer_unit)

    def to_json(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "sourceRoot": str(self.source_root),
            "sourceCommit": self.source_commit,
            "sourceTreeDigest": self.source_tree_digest,
            "installedUnitDirectory": str(self.installed_unit_directory),
            "backupDirectory": str(self.backup_directory),
            "activationMarker": str(self.activation_marker),
            "codexExecutable": str(self.codex_executable),
            "codexExecutableSha256": self.codex_executable_sha256,
            "meterCredential": str(self.meter_credential),
            "signingCredential": str(self.signing_credential),
            "timerUnit": self.timer_unit,
            "cycleUnit": self.cycle_unit,
            "meterUnit": self.meter_unit,
            "deliveryUnit": self.delivery_unit,
            "unitSha256": dict(self.unit_sha256),
        }

    @classmethod
    def from_json(cls, value: dict[str, object]) -> "PsychloCycleActivationSpec":
        if not isinstance(value, dict) or set(value) != _EXPECTED_KEYS:
            raise ValueError("Psychlo cycle activation manifest must contain exact keys")
        if value["schemaVersion"] != SCHEMA_VERSION:
            raise ValueError("unsupported Psychlo cycle activation schemaVersion")
        source_root = _canonical_absolute_path(value["sourceRoot"], "sourceRoot", must_exist=True)
        if not source_root.is_dir():
            raise ValueError("sourceRoot must be a directory")
        source_commit = str(value["sourceCommit"]).lower()
        source_tree_digest = str(value["sourceTreeDigest"]).lower()
        if not _HEX_RE.fullmatch(source_commit) or _git_identity(source_root, "HEAD") != source_commit:
            raise ValueError("source commit does not match the current checkout")
        if not _HEX_RE.fullmatch(source_tree_digest) or _git_identity(source_root, "HEAD^{tree}") != source_tree_digest:
            raise ValueError("source tree digest does not match the current checkout")
        installed = _canonical_absolute_path(value["installedUnitDirectory"], "installedUnitDirectory", must_exist=True)
        _owner_controlled_directory(installed, "installedUnitDirectory")
        backup = _canonical_absolute_path(value["backupDirectory"], "backupDirectory", must_exist=False)
        _owner_controlled_directory(backup.parent, "backupDirectory parent")
        marker = _canonical_absolute_path(value["activationMarker"], "activationMarker", must_exist=False)
        _owner_controlled_directory(marker.parent, "activationMarker parent")
        if marker.exists():
            _owner_only_regular(marker, "activationMarker")
        codex = _canonical_absolute_path(value["codexExecutable"], "codexExecutable", must_exist=True)
        if codex != EXPECTED_CODEX_EXECUTABLE:
            raise ValueError("codexExecutable is not the reviewed Codex deployment path")
        codex_digest = str(value["codexExecutableSha256"]).lower()
        if not _SHA256_RE.fullmatch(codex_digest) or _sha256(codex) != codex_digest:
            raise ValueError("Codex executable digest does not match")
        auth = _canonical_absolute_path(value["meterCredential"], "meterCredential", must_exist=True)
        signing = _canonical_absolute_path(value["signingCredential"], "signingCredential", must_exist=True)
        _owner_only_regular(auth, "meterCredential")
        _owner_only_regular(signing, "signingCredential")
        for field, expected in EXPECTED_UNITS.items():
            if value[field] != expected:
                raise ValueError(f"{field} must be {expected}")
        unit_names = (
            str(value["meterUnit"]),
            str(value["deliveryUnit"]),
            str(value["cycleUnit"]),
            str(value["timerUnit"]),
        )
        unit_hashes = []
        for name in unit_names:
            unit_path = source_root / "systemd" / name
            if not unit_path.is_file() or unit_path.is_symlink():
                raise ValueError(f"reviewed source unit is missing: {name}")
            unit_hashes.append((name, _sha256(unit_path)))
        return cls(
            schema_version=SCHEMA_VERSION,
            source_root=source_root,
            source_commit=source_commit,
            source_tree_digest=source_tree_digest,
            installed_unit_directory=installed,
            backup_directory=backup,
            activation_marker=marker,
            codex_executable=codex,
            codex_executable_sha256=codex_digest,
            meter_credential=auth,
            signing_credential=signing,
            timer_unit=str(value["timerUnit"]),
            cycle_unit=str(value["cycleUnit"]),
            meter_unit=str(value["meterUnit"]),
            delivery_unit=str(value["deliveryUnit"]),
            unit_sha256=tuple(sorted(unit_hashes)),
        )


def psychlo_cycle_activation_plan_digest(spec: PsychloCycleActivationSpec) -> str:
    return hashlib.sha256(_canonical_json(spec.to_json()).encode()).hexdigest()


def _canonical_plan(
    plan_id: str,
    spec: PsychloCycleActivationSpec,
    reason: str,
    current_state: str,
) -> AdminChangePlan:
    digest = psychlo_cycle_activation_plan_digest(spec)
    marker_args = (digest, _canonical_json(spec.to_json()))
    return AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=spec.timer_unit,
        reason=reason,
        current_state=current_state,
        proposed_state=f"install reviewed Psychlo accounting cycle and enable {spec.timer_unit} after a successful canary",
        steps=(
            AdminCommandStep("Back up current unit and timer state", ("__overseer_psychlo_cycle_backup", *marker_args), "preserve exact rollback state"),
            AdminCommandStep("Install reviewed cycle units", ("__overseer_psychlo_cycle_install_units", *marker_args), "install only approved unit bytes"),
            AdminCommandStep("Publish producer activation marker", ("__overseer_psychlo_cycle_publish_marker", *marker_args), "activate the reviewed credential boundary"),
            AdminCommandStep("Reload user systemd", ("__overseer_psychlo_cycle_daemon_reload", *marker_args), "load approved unit bytes"),
            AdminCommandStep("Run one accounting-cycle canary", ("__overseer_psychlo_cycle_canary", *marker_args), "prove fresh observation and durable receipt"),
            AdminCommandStep("Enable recurring timer", ("__overseer_psychlo_cycle_enable_timer", *marker_args), "enable recurrence only after canary success"),
        ),
        rollback_steps=(
            AdminCommandStep("Disable recurrence and restore prior state", ("__overseer_psychlo_cycle_rollback", *marker_args), "restore units and timer state without deleting durable accounting data"),
        ),
        risks=(
            "a bad meter cycle can delay newly eligible approved project work",
            "a bad timer activation can create repeated failed accounting attempts",
            "Codex authentication is exposed only to the scoped meter credential namespace",
        ),
        verification_steps=(
            AdminCommandStep("Verify recurring cycle activation", ("__overseer_psychlo_cycle_verify", *marker_args), "confirm timer, units, observation, and receipt identities"),
        ),
        adapter_metadata={"spec": spec.to_json(), "specDigest": digest},
    )


def plan_psychlo_recurring_cycle_activation(
    plan_id: str,
    spec: PsychloCycleActivationSpec,
    reason: str,
    current_state: str = "unknown",
) -> AdminChangePlan:
    if not plan_id.strip() or not reason.strip():
        raise ValueError("plan_id and reason are required")
    return _canonical_plan(plan_id, spec, reason, current_state)


def validate_psychlo_cycle_activation_plan(plan: AdminChangePlan) -> PsychloCycleActivationSpec:
    metadata = plan.adapter_metadata
    if not isinstance(metadata, dict) or set(metadata) != {"spec", "specDigest"} or not isinstance(metadata["spec"], dict):
        raise ValueError("Psychlo cycle activation plan metadata is invalid")
    raw_spec = dict(metadata["spec"])
    raw_spec.pop("unitSha256", None)
    spec = PsychloCycleActivationSpec.from_json(raw_spec)
    if metadata["specDigest"] != psychlo_cycle_activation_plan_digest(spec):
        raise ValueError("Psychlo cycle activation plan digest is invalid")
    canonical = _canonical_plan(plan.id, spec, plan.reason, plan.current_state)
    normalized = replace(
        plan,
        approved=False,
        approved_by=None,
        approved_at=None,
        canceled=False,
        canceled_by=None,
        canceled_at=None,
        cancellation_reason=None,
        archived=False,
        archived_by=None,
        archived_at=None,
        archive_record_id=None,
    )
    if normalized != canonical:
        raise ValueError("Psychlo cycle activation plan is not canonical")
    return spec
