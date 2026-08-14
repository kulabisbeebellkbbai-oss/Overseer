"""Deterministic, approval-gated Python virtual-environment provisioning.

This module deliberately keeps the runtime isolated from the system Python.
Plans contain a typed immutable manifest; the generic admin executor only
reaches this adapter after both the exact plan and the adapter enablement have
been approved.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .core import ApprovalLevel, OwnerDomain, RiskLevel


PYTHON_VENV_METADATA_KEY = "python_venv"
PYTHON_VENV_PREFLIGHT_MARKER = "__overseer_python_venv_preflight__"
PYTHON_VENV_MARKER = "__overseer_python_venv_marker__"
PYTHON_VENV_REMOVE_MARKER = "__overseer_python_venv_remove_owned__"
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?$")
_PACKAGE_LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)\s+(.+)$")
_DISALLOWED_LOCK_TOKENS = (
    "git+",
    "svn+",
    "hg+",
    "bzr+",
    "-e",
    "--editable",
    "--index-url",
    "--extra-index-url",
    "--find-links",
    "--trusted-host",
    "--no-binary",
    "--only-binary",
    "--requirement",
    "-r ",
    "--constraint",
    "-c ",
    "http://",
    "https://",
    "file:",
)


@dataclass(frozen=True)
class PythonVenvArtifact:
    """An immutable resolver/runtime artifact reference."""

    name: str
    url: str
    version: str
    sha256: str


@dataclass(frozen=True)
class PythonVenvProvisionSpec:
    """Typed immutable inputs for one isolated Python runtime."""

    venv_path: str
    source_root: str
    repository_root: str
    requirements_lock_path: str
    requirements_lock_digest: str
    artifacts: tuple[PythonVenvArtifact, ...]
    resolver: str
    resolver_version: str
    resolver_provenance: str
    python_version: str
    import_name: str
    expected_version: str
    resolver_executable: str | None = None
    resolver_executable_sha256: str | None = None
    source_commit: str | None = None
    source_tree_digest: str | None = None
    pyproject_digest: str | None = None
    wheelhouse_path: str | None = None
    existing_destination_attestation: str | None = None

    @property
    def manifest_digest(self) -> str:
        payload = asdict(self)
        payload["artifacts"] = [asdict(artifact) for artifact in self.artifacts]
        return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def python_venv_spec_to_metadata(spec: PythonVenvProvisionSpec) -> dict[str, Any]:
    payload = asdict(spec)
    payload["artifacts"] = [asdict(artifact) for artifact in spec.artifacts]
    return {**payload, "manifest_digest": spec.manifest_digest}


def python_venv_spec_from_metadata(payload: dict[str, Any]) -> PythonVenvProvisionSpec:
    values = dict(payload)
    values.pop("manifest_digest", None)
    values.pop("plan_digest", None)
    values["artifacts"] = tuple(PythonVenvArtifact(**artifact) for artifact in values.get("artifacts", ()))
    return PythonVenvProvisionSpec(**values)


def _path_without_following_symlinks(path: str | Path, *, must_exist: bool, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError(f"{label} must be absolute")
    current = Path(candidate.anchor)
    parts = candidate.parts[1:]
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if must_exist:
                raise ValueError(f"{label} does not exist: {candidate}") from None
            break
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} contains a symlink: {current}")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError(f"{label} parent is not a directory: {current}")
    return candidate


def _owner_only_directory(path: Path, *, label: str, allow_sticky_shared: bool = False) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"{label} must be a directory")
    if info.st_uid != os.getuid():
        raise ValueError(f"{label} is not owned by the current user")
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o022 or (mode & 0o007 and not (allow_sticky_shared and mode & stat.S_ISVTX)):
        raise ValueError(f"{label} must be owner-only")


def _validate_digest(value: str, label: str) -> None:
    if not _SHA256_RE.fullmatch(value or ""):
        raise ValueError(f"{label} must be a 64-character SHA256 digest")


def _validate_lock_file(spec: PythonVenvProvisionSpec) -> dict[str, tuple[str, frozenset[str]]]:
    lock = _path_without_following_symlinks(spec.requirements_lock_path, must_exist=True, label="requirements lock")
    info = lock.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("requirements lock must be a regular file")
    actual = hashlib.sha256(lock.read_bytes()).hexdigest()
    if actual.lower() != spec.requirements_lock_digest.lower():
        raise ValueError("requirements lock digest does not match the immutable manifest")
    names: dict[str, tuple[str, frozenset[str]]] = {}
    for line_number, raw_line in enumerate(lock.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lowered = line.lower()
        if any(token in lowered for token in _DISALLOWED_LOCK_TOKENS):
            raise ValueError(f"requirements lock line {line_number} contains a disallowed source or option")
        if ";" in line or " @ " in line or " @" in line:
            raise ValueError(f"requirements lock line {line_number} contains a marker or direct reference")
        match = _PACKAGE_LINE_RE.fullmatch(line)
        if not match:
            raise ValueError(f"requirements lock line {line_number} must pin package==version with hashes")
        normalized_name = match.group(1).lower().replace("_", "-")
        if normalized_name in names:
            raise ValueError(f"requirements lock contains duplicate package: {match.group(1)}")
        hashes = re.findall(r"--hash=sha256:([0-9a-fA-F]{64})(?:\s|$)", match.group(3))
        if not hashes or any(len(item) != 64 for item in hashes):
            raise ValueError(f"requirements lock line {line_number} must contain SHA256 hashes")
        names[normalized_name] = (match.group(2), frozenset(item.lower() for item in hashes))
    if not names:
        raise ValueError("requirements lock must contain at least one pinned package")
    return names


def _wheel_identity(filename: str) -> tuple[str, str]:
    parts = Path(filename).stem.split("-")
    if len(parts) < 5:
        raise ValueError(f"wheel filename is not a valid versioned wheel: {filename}")
    distribution = "-".join(parts[:-4]).lower().replace("_", "-")
    version = parts[-4]
    if not distribution or not version:
        raise ValueError(f"wheel filename is missing distribution or version: {filename}")
    return distribution, version


def _validate_wheelhouse(spec: PythonVenvProvisionSpec, lock_entries: dict[str, tuple[str, frozenset[str]]]) -> None:
    if not spec.wheelhouse_path:
        raise ValueError("offline owner-safe wheelhouse is required")
    wheelhouse = _path_without_following_symlinks(spec.wheelhouse_path, must_exist=True, label="wheelhouse")
    _owner_only_directory(wheelhouse, label="wheelhouse")
    wheel_artifacts = [
        artifact
        for artifact in spec.artifacts
        if artifact.name.lower().endswith(".whl") or Path(artifact.url).name.lower().endswith(".whl")
    ]
    seen_wheel_names: set[str] = set()
    for item in sorted(wheelhouse.iterdir()):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"wheelhouse contains a symlink: {item}")
        if not stat.S_ISREG(info.st_mode) or item.suffix != ".whl":
            raise ValueError(f"wheelhouse may contain only regular wheel files: {item}")
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError(f"wheelhouse artifact is not owner-controlled: {item}")
        digest = hashlib.sha256(item.read_bytes()).hexdigest()
        distribution, version = _wheel_identity(item.name)
        matching = [
            artifact
            for artifact in wheel_artifacts
            if artifact.name == item.name or Path(artifact.url).name == item.name
        ]
        if len(matching) != 1 or matching[0].version != version or matching[0].sha256.lower() != digest:
            raise ValueError(f"wheelhouse artifact parity mismatch: {item.name}")
        locked = lock_entries.get(distribution)
        if locked is None or locked[0] != version or digest not in locked[1]:
            raise ValueError(f"wheelhouse artifact does not match requirements lock: {item.name}")
        seen_wheel_names.add(item.name)
    expected_wheels = {artifact.name if artifact.name.lower().endswith(".whl") else Path(artifact.url).name for artifact in wheel_artifacts}
    if seen_wheel_names != expected_wheels:
        raise ValueError("wheelhouse artifacts do not exactly match the immutable wheel manifest")


def validate_python_venv_spec(spec: PythonVenvProvisionSpec) -> None:
    """Validate all immutable and path-safety invariants before execution."""

    if spec.resolver not in {"uv", "python"} and not spec.resolver.startswith("/"):
        raise ValueError("resolver must be uv, python, or a vetted absolute interpreter path")
    if spec.resolver.startswith("/"):
        resolver_path = Path(spec.resolver)
        if resolver_path.parent not in {Path("/usr/bin"), Path("/usr/local/bin")} or not resolver_path.name.startswith("python3"):
            raise ValueError("absolute resolver must be a vetted Python interpreter under /usr/bin or /usr/local/bin")
    if not spec.resolver_version.strip() or not spec.resolver_provenance.strip():
        raise ValueError("resolver version and provenance are required")
    if not spec.import_name.strip() or not spec.import_name.isidentifier() or not spec.expected_version.strip():
        raise ValueError("strict import name and expected version are required")
    if not spec.resolver_executable or not spec.resolver_executable_sha256:
        raise ValueError("exact approved resolver executable path and digest are required")
    resolver_executable = _path_without_following_symlinks(spec.resolver_executable, must_exist=True, label="resolver executable")
    resolver_info = resolver_executable.lstat()
    if not stat.S_ISREG(resolver_info.st_mode) or stat.S_IMODE(resolver_info.st_mode) & 0o022:
        raise ValueError("resolver executable must be a non-writable regular file")
    if not resolver_info.st_mode & stat.S_IXUSR:
        raise ValueError("resolver executable must be owner-executable")
    if resolver_info.st_uid not in {0, os.getuid()}:
        raise ValueError("resolver executable must be owned by root or the current user")
    _validate_digest(spec.resolver_executable_sha256, "resolver executable SHA256")
    if hashlib.sha256(resolver_executable.read_bytes()).hexdigest().lower() != spec.resolver_executable_sha256.lower():
        raise ValueError("resolver executable digest does not match the immutable manifest")
    if spec.resolver == "python" and not resolver_executable.name.startswith("python3"):
        raise ValueError("python resolver executable must be a Python 3 interpreter")
    if not spec.import_name.strip() or not spec.expected_version.strip():
        raise ValueError("import name and expected version are required")
    if not spec.source_commit and not spec.source_tree_digest and not spec.pyproject_digest:
        raise ValueError("source commit, source tree digest, or pyproject digest is required")
    if spec.source_commit and not _COMMIT_RE.fullmatch(spec.source_commit):
        raise ValueError("source commit must be a full 40- or 64-character hexadecimal id")
    for value, label in (
        (spec.source_tree_digest, "source tree digest"),
        (spec.pyproject_digest, "pyproject digest"),
        (spec.requirements_lock_digest, "requirements lock digest"),
    ):
        if value:
            if label == "source tree digest":
                if not _COMMIT_RE.fullmatch(value):
                    raise ValueError("source tree digest must be a full 40- or 64-character hexadecimal id")
            else:
                _validate_digest(value, label)
    if not spec.artifacts:
        raise ValueError("at least one immutable resolver/runtime artifact is required")
    artifact_names: set[str] = set()
    for artifact in spec.artifacts:
        if not artifact.name.strip() or artifact.name in artifact_names:
            raise ValueError("artifact names must be non-empty and unique")
        artifact_names.add(artifact.name)
        if not artifact.url.startswith("https://"):
            raise ValueError("artifact URLs must use HTTPS")
        if not artifact.version.strip():
            raise ValueError(f"artifact version is required: {artifact.name}")
        _validate_digest(artifact.sha256, f"artifact {artifact.name} SHA256")

    repository_root = _path_without_following_symlinks(spec.repository_root, must_exist=True, label="repository root")
    source_root = _path_without_following_symlinks(spec.source_root, must_exist=True, label="source root")
    if not repository_root.is_dir():
        raise ValueError("repository root must be a directory")
    if repository_root.stat().st_uid != os.getuid():
        raise ValueError("repository root is not owned by the current user")
    if not source_root.is_dir():
        raise ValueError("source root must be a directory")
    try:
        source_root.relative_to(repository_root)
    except ValueError:
        raise ValueError("source root must be inside repository root") from None
    if spec.source_commit or spec.source_tree_digest:
        git_target = str(source_root)
        for git_ref, label in ((spec.source_commit, "source commit"), (spec.source_tree_digest, "source tree digest")):
            if not git_ref:
                continue
            verify_args = ("git", "-C", git_target, "rev-parse", "--verify", "HEAD" if label == "source commit" else "HEAD^{tree}")
            completed = subprocess.run(verify_args, check=False, capture_output=True, text=True, stdin=subprocess.DEVNULL)
            if completed.returncode != 0 or completed.stdout.strip().lower() != git_ref.lower():
                raise ValueError(f"{label} does not match the current source checkout")
    if spec.pyproject_digest:
        pyproject = _path_without_following_symlinks(source_root / "pyproject.toml", must_exist=True, label="pyproject")
        actual_pyproject_digest = hashlib.sha256(pyproject.read_bytes()).hexdigest()
        if actual_pyproject_digest.lower() != spec.pyproject_digest.lower():
            raise ValueError("pyproject digest does not match the immutable manifest")
    target = _path_without_following_symlinks(spec.venv_path, must_exist=False, label="venv target")
    if target.exists():
        raise ValueError("venv target already exists; insert-only provisioning refuses overwrite")
    try:
        target.relative_to(repository_root)
    except ValueError:
        pass
    else:
        raise ValueError("venv target must be outside repository root")
    target_parent = target.parent
    _path_without_following_symlinks(target_parent, must_exist=True, label="venv target parent")
    _owner_only_directory(target_parent, label="venv target parent", allow_sticky_shared=True)
    if spec.expected_version not in target.name:
        raise ValueError("venv target must be a final versioned path containing expected_version")
    lock_entries = _validate_lock_file(spec)
    _validate_wheelhouse(spec, lock_entries)


def plan_python_hashed_venv_provision(
    plan_id: str,
    spec: PythonVenvProvisionSpec,
    reason: str,
    current_state: str = "unknown",
):
    """Build a high-risk, human-approved plan without changing host state."""

    validate_python_venv_spec(spec)
    from .admin import AdminChangeKind, AdminChangePlan, AdminCommandStep

    metadata = python_venv_spec_to_metadata(spec)
    python_executable = str(Path(spec.venv_path) / "bin" / "python")
    resolver = (spec.resolver_executable,)
    venv_command = (
        (*resolver, "venv", "--offline", "--no-python-downloads", "--python", spec.python_version, spec.venv_path)
        if spec.resolver == "uv"
        else (*resolver, "-m", "venv", spec.venv_path)
    )
    if spec.resolver == "uv":
        install_command = (
            *resolver,
            "pip",
            "sync",
            "--offline",
            "--python",
            python_executable,
            "--require-hashes",
            "--no-deps",
            "--only-binary=:all:",
            *( ("--no-index", "--find-links", spec.wheelhouse_path) if spec.wheelhouse_path else () ),
            spec.requirements_lock_path,
        )
    else:
        install_command = (
            python_executable,
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--no-deps",
            "--only-binary=:all:",
            *( ("--no-index", "--find-links", spec.wheelhouse_path) if spec.wheelhouse_path else () ),
            "-r",
            spec.requirements_lock_path,
        )
    environment = (
        ("PATH", f"{Path(spec.resolver_executable).parent}:/usr/bin:/bin"),
        ("PIP_CONFIG_FILE", os.devnull),
        ("PIP_NO_INDEX", "1"),
        ("PYTHONNOUSERSITE", "1"),
        ("PYTHONPATH", ""),
        ("UV_OFFLINE", "1"),
        ("UV_PYTHON_DOWNLOADS", "never"),
    )
    plan = AdminChangePlan(
        id=plan_id,
        kind=AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,
        owner_domain=OwnerDomain.OBRIEN,
        risk_level=RiskLevel.HIGH,
        approval_level=ApprovalLevel.HUMAN,
        target=spec.venv_path,
        reason=reason,
        current_state=current_state,
        proposed_state=f"create immutable isolated Python {spec.python_version} runtime at {spec.venv_path}",
        steps=(
            AdminCommandStep(PYTHON_VENV_PREFLIGHT_MARKER, (PYTHON_VENV_PREFLIGHT_MARKER, spec.venv_path, spec.manifest_digest), "recheck the immutable manifest and insert-only destination immediately before creation"),
            AdminCommandStep("Create final versioned Python venv", venv_command, "create the new runtime directly at its final path; overwrite and --clear are forbidden"),
            AdminCommandStep(PYTHON_VENV_MARKER, (PYTHON_VENV_MARKER, spec.venv_path, spec.manifest_digest), "mark the exact newly-created runtime before package mutation so failed installs can roll back safely"),
            AdminCommandStep("Install hash-pinned wheels", install_command, "install only lockfile-pinned hashed wheels into the isolated venv" , environment=environment, clear_environment=True),
        ),
        rollback_steps=(
            AdminCommandStep("Remove marker-owned Python venv", (PYTHON_VENV_REMOVE_MARKER, spec.venv_path, spec.manifest_digest), "remove only the exact newly-created runtime bearing this plan marker"),
        ),
        risks=(
            "isolated runtime files are created outside the repository",
            "resolver and wheel artifacts are immutable and hash-verified",
            "system Python and unrelated environments are unchanged",
            "rollback is only permitted for this plan's marker-owned runtime",
        ),
        verification_steps=(
            AdminCommandStep("Verify isolated interpreter", (python_executable, "-c", f"import platform; assert platform.python_version() == {spec.python_version!r}"), "confirm the new venv interpreter exactly matches the requested runtime"),
            AdminCommandStep("Verify managed import and version", (python_executable, "-c", f"import {spec.import_name}; assert getattr({spec.import_name}, '__version__', None) == {spec.expected_version!r}"), "confirm the expected import and version are present inside the new venv"),
        ),
        adapter_metadata={PYTHON_VENV_METADATA_KEY: metadata},
    )
    plan_digest = python_venv_plan_digest(plan)
    plan_metadata = dict(plan.adapter_metadata)
    plan_metadata[PYTHON_VENV_METADATA_KEY] = {**metadata, "plan_digest": plan_digest}
    return replace(plan, adapter_metadata=plan_metadata)


def _plan_shape(plan) -> dict[str, Any]:
    def step_shape(step) -> dict[str, Any]:
        payload: dict[str, Any] = {"title": step.title, "command": list(step.command), "reason": step.reason}
        if getattr(step, "environment", ()):
            payload["environment"] = {key: value for key, value in step.environment}
        if getattr(step, "clear_environment", False):
            payload["clear_environment"] = True
        return payload

    metadata = dict(getattr(plan, "adapter_metadata", {}).get(PYTHON_VENV_METADATA_KEY, {}))
    metadata.pop("plan_digest", None)
    return {
        "kind": str(plan.kind),
        "target": plan.target,
        "reason": plan.reason,
        "current_state": plan.current_state,
        "proposed_state": plan.proposed_state,
        "steps": [step_shape(step) for step in plan.steps],
        "rollback_steps": [step_shape(step) for step in plan.rollback_steps],
        "verification_steps": [step_shape(step) for step in plan.verification_steps],
        "risks": list(plan.risks),
        "manifest": metadata,
    }


def python_venv_plan_digest(plan) -> str:
    return hashlib.sha256(_canonical_json(_plan_shape(plan)).encode("utf-8")).hexdigest()


def validate_python_venv_plan(plan) -> PythonVenvProvisionSpec:
    metadata = getattr(plan, "adapter_metadata", {}).get(PYTHON_VENV_METADATA_KEY)
    if not isinstance(metadata, dict):
        raise ValueError("python_hashed_venv_provision plan is missing its typed manifest")
    spec = python_venv_spec_from_metadata(metadata)
    expected_digest = metadata.get("manifest_digest")
    if expected_digest != spec.manifest_digest:
        raise ValueError("python venv manifest digest is not stable")
    validate_python_venv_spec(spec)
    if plan.target != spec.venv_path:
        raise ValueError("python venv plan target does not match its manifest")
    canonical = plan_python_hashed_venv_provision(plan.id, spec, plan.reason, plan.current_state)
    if metadata.get("plan_digest") != python_venv_plan_digest(canonical):
        raise ValueError("python venv plan digest is not stable")
    if plan.steps != canonical.steps or plan.rollback_steps != canonical.rollback_steps or plan.verification_steps != canonical.verification_steps:
        raise ValueError("python venv canonical plan command boundary does not match its immutable manifest")
    if plan.adapter_metadata != canonical.adapter_metadata:
        raise ValueError("python venv plan metadata does not match its immutable manifest")
    return spec


def execute_python_venv_marker(command: tuple[str, ...]) -> tuple[int, str, str]:
    """Execute an internal marker operation; never follows a path symlink."""

    marker = command[0]
    if marker == PYTHON_VENV_PREFLIGHT_MARKER:
        _, target_text, _digest = command
        _path_without_following_symlinks(target_text, must_exist=False, label="venv target")
        if Path(target_text).exists():
            return 1, "", "refusing creation: exact insert-only target already exists"
        return 0, "immutable Python venv manifest and empty target revalidated", ""
    if marker == PYTHON_VENV_MARKER:
        _, target_text, digest = command
        target = _path_without_following_symlinks(target_text, must_exist=True, label="venv target")
        if target.lstat().st_uid != os.getuid() or stat.S_IMODE(target.lstat().st_mode) & 0o022:
            raise ValueError("venv target is not owner-controlled")
        os.chmod(target, 0o700, follow_symlinks=False)
        marker_path = target / ".overseer-python-venv-owner"
        try:
            marker_info = marker_path.lstat()
        except FileNotFoundError:
            marker_info = None
        if marker_info is not None:
            raise ValueError("venv ownership marker already exists")
        marker_path.write_text(digest + "\n", encoding="utf-8")
        os.chmod(marker_path, 0o600, follow_symlinks=False)
        return 0, "marker recorded", ""
    if marker == PYTHON_VENV_REMOVE_MARKER:
        _, target_text, digest = command
        target = _path_without_following_symlinks(target_text, must_exist=True, label="venv target")
        if target.lstat().st_uid != os.getuid() or stat.S_IMODE(target.lstat().st_mode) & 0o022:
            raise ValueError("venv target is not owner-controlled")
        marker_path = target / ".overseer-python-venv-owner"
        try:
            marker_info = marker_path.lstat()
        except FileNotFoundError:
            return 1, "", "refusing rollback: exact plan ownership marker is absent or mismatched"
        if (
            stat.S_ISLNK(marker_info.st_mode)
            or not stat.S_ISREG(marker_info.st_mode)
            or marker_info.st_uid != os.getuid()
            or stat.S_IMODE(marker_info.st_mode) & 0o077
            or marker_path.read_text(encoding="utf-8").strip() != digest
        ):
            return 1, "", "refusing rollback: exact plan ownership marker is absent or mismatched"
        shutil.rmtree(target)
        return 0, "marker-owned venv removed", ""
    raise ValueError(f"unknown Python venv marker command: {marker}")


__all__ = [
    "PYTHON_VENV_METADATA_KEY",
    "PYTHON_VENV_MARKER",
    "PYTHON_VENV_PREFLIGHT_MARKER",
    "PYTHON_VENV_REMOVE_MARKER",
    "PythonVenvArtifact",
    "PythonVenvProvisionSpec",
    "execute_python_venv_marker",
    "plan_python_hashed_venv_provision",
    "python_venv_plan_digest",
    "python_venv_spec_from_metadata",
    "python_venv_spec_to_metadata",
    "validate_python_venv_plan",
    "validate_python_venv_spec",
]
