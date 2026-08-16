"""Immutable, approval-gated activation of the Psychlo recurring accounting cycle."""

from __future__ import annotations

from dataclasses import dataclass, replace
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Callable, Sequence

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
_MAX_MANIFEST_BYTES = 128 * 1024


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


def psychlo_cycle_activation_spec_from_private_file(path: Path | str) -> "PsychloCycleActivationSpec":
    selected = Path(path)
    descriptor = os.open(selected, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Psychlo cycle activation manifest must be an owner-only regular file")
        if info.st_size <= 0 or info.st_size > _MAX_MANIFEST_BYTES:
            raise ValueError("Psychlo cycle activation manifest size is invalid")
        content = bytearray()
        while len(content) <= _MAX_MANIFEST_BYTES:
            chunk = os.read(descriptor, min(8192, _MAX_MANIFEST_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Psychlo cycle activation manifest is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Psychlo cycle activation manifest must be a JSON object")
    return PsychloCycleActivationSpec.from_json(value)


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
    marker_args = (plan_id, digest, _canonical_json(spec.to_json()))
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


class PsychloCycleActivationBusy(RuntimeError):
    """Another process owns this exact activation target."""


@dataclass
class PsychloCycleActivationLock:
    descriptor: int

    def release(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def acquire_psychlo_cycle_activation_lock(plan: AdminChangePlan) -> PsychloCycleActivationLock:
    spec = validate_psychlo_cycle_activation_plan(plan)
    identity = hashlib.sha256(str(spec.installed_unit_directory).encode()).hexdigest()
    path = spec.backup_directory.parent / f".psychlo-cycle-{identity}.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Psychlo cycle activation lock is not owner-only")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PsychloCycleActivationBusy("Psychlo cycle activation lifecycle is busy") from error
        return PsychloCycleActivationLock(descriptor)
    except Exception:
        os.close(descriptor)
        raise


SystemctlRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def _default_systemctl(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    uid = os.getuid()
    home = pwd.getpwuid(uid).pw_dir
    return subprocess.run(
        ("/usr/bin/systemctl", "--user", *args),
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={
            "PATH": "/usr/bin:/bin",
            "HOME": home,
            "XDG_RUNTIME_DIR": f"/run/user/{uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus",
            "LANG": "C",
            "LC_ALL": "C",
        },
    )


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_create(path: Path, content: bytes, mode: int) -> None:
    """Publish a complete immutable file without replacing an existing path."""
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _marker_context(command: Sequence[str]) -> tuple[str, str, PsychloCycleActivationSpec]:
    if len(command) != 4 or not command[0].startswith("__overseer_psychlo_cycle_"):
        raise ValueError("Psychlo cycle marker command is invalid")
    plan_id, expected_digest, encoded = command[1:]
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise ValueError("Psychlo cycle marker spec is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("Psychlo cycle marker spec is invalid")
    value.pop("unitSha256", None)
    spec = PsychloCycleActivationSpec.from_json(value)
    if psychlo_cycle_activation_plan_digest(spec) != expected_digest:
        raise ValueError("Psychlo cycle marker digest mismatch")
    return plan_id, expected_digest, spec


def _ownership(plan_id: str, digest: str) -> dict[str, str]:
    return {"planId": plan_id, "specDigest": digest}


def _backup_record(spec: PsychloCycleActivationSpec) -> Path:
    return spec.backup_directory / "record.json"


def _completion_record(spec: PsychloCycleActivationSpec) -> Path:
    return spec.backup_directory / "completed.json"


def _load_owned_json(path: Path, expected: dict[str, str], label: str) -> dict[str, Any]:
    _owner_only_regular(path, label)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or any(value.get(key) != item for key, item in expected.items()):
        raise ValueError(f"{label} ownership mismatch")
    return value


def _run_checked(runner: SystemctlRunner, args: Sequence[str], label: str) -> subprocess.CompletedProcess[str]:
    completed = runner(args)
    if completed.returncode != 0:
        raise RuntimeError(f"{label} failed: {completed.stderr.strip()[:300]}")
    return completed


def _next_timer_trigger(runner: SystemctlRunner, timer_unit: str) -> int:
    """Return the timer's finite next monotonic trigger or fail closed."""
    completed = _run_checked(
        runner,
        ("show", timer_unit, "--property=NextElapseUSecMonotonic", "--value"),
        "verify recurring timer next trigger",
    )
    raw = completed.stdout.strip()
    if "=" in raw:
        # Be tolerant of a runner/systemctl version that includes the property
        # name even though --value was requested, while still requiring one
        # scalar value.
        property_name, raw = raw.split("=", 1)
        if property_name != "NextElapseUSecMonotonic":
            raise RuntimeError("recurring timer next trigger property is invalid")
        raw = raw.strip()
    if not raw or raw.lower() in {"infinity", "n/a", "unknown"}:
        raise RuntimeError("recurring timer has no finite next trigger")
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise RuntimeError("recurring timer next trigger is not an integer") from error
    if value <= 0:
        raise RuntimeError("recurring timer has no finite next trigger")
    return value


def _backup(plan_id: str, digest: str, spec: PsychloCycleActivationSpec, runner: SystemctlRunner) -> str:
    expected = _ownership(plan_id, digest)
    record_path = _backup_record(spec)
    if record_path.exists():
        _load_owned_json(record_path, expected, "Psychlo cycle backup record")
        return "backup replay verified"
    if spec.backup_directory.exists():
        raise ValueError("unowned Psychlo cycle backup directory already exists")
    enabled = runner(("is-enabled", spec.timer_unit)).returncode == 0
    units: dict[str, object] = {}
    for name in spec.unit_names:
        installed = spec.installed_unit_directory / name
        if installed.exists():
            if installed.is_symlink() or not installed.is_file():
                raise ValueError(f"installed unit is not a regular file: {name}")
            content = installed.read_bytes()
            units[name] = {"present": True, "sha256": hashlib.sha256(content).hexdigest(), "content": base64.b64encode(content).decode()}
        else:
            units[name] = {"present": False}
    record = {**expected, "timerPreviouslyEnabled": enabled, "units": units}
    staging = Path(tempfile.mkdtemp(prefix=f".{spec.backup_directory.name}.", dir=spec.backup_directory.parent))
    try:
        staging.chmod(0o700)
        _atomic_create(staging / "record.json", (_canonical_json(record) + "\n").encode(), 0o600)
        os.rename(staging, spec.backup_directory)
        parent = os.open(spec.backup_directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return "backup recorded"


def _install(plan_id: str, digest: str, spec: PsychloCycleActivationSpec) -> str:
    _load_owned_json(_backup_record(spec), _ownership(plan_id, digest), "Psychlo cycle backup record")
    for name, expected_hash in spec.unit_sha256:
        source = spec.source_root / "systemd" / name
        if _sha256(source) != expected_hash:
            raise ValueError(f"reviewed unit changed after approval: {name}")
        _atomic_write(spec.installed_unit_directory / name, source.read_bytes(), 0o644)
    return "reviewed units installed"


def _publish_marker(plan_id: str, digest: str, spec: PsychloCycleActivationSpec) -> str:
    expected = _ownership(plan_id, digest)
    if spec.activation_marker.exists():
        _load_owned_json(spec.activation_marker, expected, "Psychlo cycle activation marker")
        return "activation marker replay verified"
    _atomic_create(spec.activation_marker, (_canonical_json(expected) + "\n").encode(), 0o600)
    return "activation marker published"


def _observation_identity() -> tuple[str | None, str | None]:
    path = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/share/overseer/psychlo-meter/latest-observation.json"
    if not path.exists():
        return None, None
    value = json.loads(path.read_text(encoding="utf-8"))
    return value.get("observationId"), value.get("digest")


def _delivered_observation(observation_id: str) -> bool:
    import sqlite3

    ledger = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/share/overseer/psychlo/usage-attribution.sqlite3"
    if not ledger.exists():
        return False
    connection = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT state,receipt_json FROM usage_snapshot_intents WHERE observation_id=?",
            (observation_id,),
        ).fetchone()
    finally:
        connection.close()
    return bool(row and row[0] == "delivered" and row[1])


def _canary(spec: PsychloCycleActivationSpec, runner: SystemctlRunner) -> str:
    _, before_digest = _observation_identity()
    _run_checked(runner, ("start", "--wait", spec.cycle_unit), "Psychlo accounting cycle canary")
    observation_id, after_digest = _observation_identity()
    if not observation_id or not after_digest or after_digest == before_digest:
        raise RuntimeError("Psychlo accounting cycle canary did not publish a fresh observation")
    if not _delivered_observation(observation_id):
        raise RuntimeError("Psychlo accounting cycle canary lacks a durable delivery receipt")
    return f"canary delivered observation {observation_id}"


def _verify_installed(spec: PsychloCycleActivationSpec) -> None:
    for name, expected in spec.unit_sha256:
        path = spec.installed_unit_directory / name
        if not path.is_file() or path.is_symlink() or _sha256(path) != expected:
            raise ValueError(f"installed unit verification failed: {name}")


def _rollback(plan_id: str, digest: str, spec: PsychloCycleActivationSpec, runner: SystemctlRunner) -> str:
    expected = _ownership(plan_id, digest)
    record = _load_owned_json(_backup_record(spec), expected, "Psychlo cycle backup record")
    if spec.activation_marker.exists():
        _load_owned_json(spec.activation_marker, expected, "Psychlo cycle activation marker")
    runner(("disable", "--now", spec.timer_unit))
    units = record.get("units")
    if not isinstance(units, dict):
        raise ValueError("Psychlo cycle backup unit record is invalid")
    for name in spec.unit_names:
        item = units.get(name)
        if not isinstance(item, dict):
            raise ValueError("Psychlo cycle backup unit record is invalid")
        installed = spec.installed_unit_directory / name
        if item.get("present") is True:
            content = base64.b64decode(str(item["content"]), validate=True)
            if hashlib.sha256(content).hexdigest() != item.get("sha256"):
                raise ValueError("Psychlo cycle backup content digest mismatch")
            _atomic_write(installed, content, 0o644)
        elif installed.exists():
            installed.unlink()
    if spec.activation_marker.exists():
        spec.activation_marker.unlink()
    _run_checked(runner, ("daemon-reload",), "user systemd rollback reload")
    if record.get("timerPreviouslyEnabled") is True:
        _run_checked(runner, ("enable", "--now", spec.timer_unit), "restore prior timer state")
    return "recurring cycle rolled back"


def execute_psychlo_cycle_activation_marker(
    command: Sequence[str],
    *,
    systemctl_runner: SystemctlRunner | None = None,
) -> tuple[int, str, str]:
    plan_id, digest, spec = _marker_context(command)
    runner = systemctl_runner or _default_systemctl
    operation = command[0]
    try:
        if operation == "__overseer_psychlo_cycle_backup":
            result = _backup(plan_id, digest, spec, runner)
        elif operation == "__overseer_psychlo_cycle_install_units":
            result = _install(plan_id, digest, spec)
        elif operation == "__overseer_psychlo_cycle_publish_marker":
            result = _publish_marker(plan_id, digest, spec)
        elif operation == "__overseer_psychlo_cycle_daemon_reload":
            _run_checked(runner, ("daemon-reload",), "user systemd reload")
            result = "user systemd reloaded"
        elif operation == "__overseer_psychlo_cycle_canary":
            result = _canary(spec, runner)
        elif operation == "__overseer_psychlo_cycle_enable_timer":
            _run_checked(runner, ("enable", "--now", spec.timer_unit), "enable recurring Psychlo timer")
            result = "recurring timer enabled"
        elif operation == "__overseer_psychlo_cycle_verify":
            _verify_installed(spec)
            _load_owned_json(spec.activation_marker, _ownership(plan_id, digest), "Psychlo cycle activation marker")
            _run_checked(runner, ("is-enabled", spec.timer_unit), "verify recurring timer enabled")
            _run_checked(runner, ("is-active", spec.timer_unit), "verify recurring timer active")
            _next_timer_trigger(runner, spec.timer_unit)
            _atomic_write(
                _completion_record(spec),
                (_canonical_json(_ownership(plan_id, digest)) + "\n").encode(),
                0o600,
            )
            result = "recurring cycle verified"
        elif operation == "__overseer_psychlo_cycle_rollback":
            result = _rollback(plan_id, digest, spec, runner)
        else:
            raise ValueError("unsupported Psychlo cycle marker operation")
        return 0, result, ""
    except (OSError, RuntimeError, ValueError) as error:
        return 1, "", str(error)


def psychlo_cycle_activation_replay_verified(
    plan: AdminChangePlan,
    *,
    systemctl_runner: SystemctlRunner | None = None,
) -> bool:
    """Return true only when a prior exact execution remains fully active."""
    try:
        spec = validate_psychlo_cycle_activation_plan(plan)
        expected = _ownership(plan.id, psychlo_cycle_activation_plan_digest(spec))
        _load_owned_json(_completion_record(spec), expected, "Psychlo cycle completion record")
        _load_owned_json(spec.activation_marker, expected, "Psychlo cycle activation marker")
        _verify_installed(spec)
        runner = systemctl_runner or _default_systemctl
        if runner(("is-enabled", spec.timer_unit)).returncode != 0:
            return False
        if runner(("is-active", spec.timer_unit)).returncode != 0:
            return False
        _next_timer_trigger(runner, spec.timer_unit)
        return True
    except (OSError, RuntimeError, ValueError):
        return False
