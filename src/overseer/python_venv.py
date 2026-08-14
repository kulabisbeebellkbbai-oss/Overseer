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
PYTHON_VENV_INPUTS_MARKER = ".overseer-python-venv-inputs-owner"
PYTHON_VENV_PLAN_DIGEST_PLACEHOLDER = "__overseer_python_venv_plan_digest__"
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
    git_executable: str | None = None
    git_executable_sha256: str | None = None
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


def _owner_controlled_directory(path: Path, *, label: str) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"{label} must be a regular directory without symlinks")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError(f"{label} must be owned by the current user and not group/world writable")


def _owner_safe_regular_file(path: Path, *, label: str, allow_root: bool = False) -> os.stat_result:
    """Return an owner-controlled regular-file stat without following links."""
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} must be a regular file without symlinks")
    allowed_owners = {os.getuid(), 0} if allow_root else {os.getuid()}
    if info.st_uid not in allowed_owners or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError(f"{label} must be owned by the current user and not group/world writable")
    return info


def _owner_safe_executable(path_text: str, digest: str, *, label: str) -> Path:
    path = _path_without_following_symlinks(path_text, must_exist=True, label=label)
    info = _owner_safe_regular_file(path, label=label, allow_root=True)
    if not info.st_mode & stat.S_IXUSR:
        raise ValueError(f"{label} must be owner-executable")
    _validate_digest(digest, f"{label} SHA256")
    if hashlib.sha256(path.read_bytes()).hexdigest().lower() != digest.lower():
        raise ValueError(f"{label} digest does not match the immutable manifest")
    return path


def _validate_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{label} must be a 64-character SHA256 digest")


def _validate_lock_file(spec: PythonVenvProvisionSpec) -> dict[str, tuple[str, frozenset[str]]]:
    lock = _path_without_following_symlinks(spec.requirements_lock_path, must_exist=True, label="requirements lock")
    _owner_safe_regular_file(lock, label="requirements lock")
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


def _sealed_inputs_root(spec: PythonVenvProvisionSpec) -> Path:
    return Path(spec.venv_path).parent / f".overseer-python-inputs-{spec.manifest_digest}"


def _wheel_manifest(spec: PythonVenvProvisionSpec) -> tuple[dict[str, str], ...]:
    entries = []
    for artifact in spec.artifacts:
        name = artifact.name if artifact.name.lower().endswith(".whl") else Path(artifact.url).name
        if name.lower().endswith(".whl"):
            entries.append({"name": name, "sha256": artifact.sha256.lower(), "version": artifact.version})
    return tuple(sorted(entries, key=lambda item: item["name"]))


def _execution_environment(spec: PythonVenvProvisionSpec) -> tuple[tuple[str, str], ...]:
    return (
        ("PATH", f"{Path(spec.resolver_executable).parent}:/usr/bin:/bin"),
        ("PIP_CONFIG_FILE", os.devnull),
        ("PIP_NO_INDEX", "1"),
        ("PIP_DISABLE_PIP_VERSION_CHECK", "1"),
        ("PIP_ROOT_USER_ACTION", "ignore"),
        ("PYTHONHOME", ""),
        ("PYTHONNOUSERSITE", "1"),
        ("PYTHONPATH", ""),
        ("UV_OFFLINE", "1"),
        ("UV_PYTHON_DOWNLOADS", "never"),
    )


def validate_python_venv_spec(spec: PythonVenvProvisionSpec, *, allow_existing_target: bool = False) -> None:
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
    resolver_executable = _owner_safe_executable(
        spec.resolver_executable,
        spec.resolver_executable_sha256,
        label="resolver executable",
    )
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
    _owner_controlled_directory(repository_root, label="repository root")
    if not source_root.is_dir():
        raise ValueError("source root must be a directory")
    _owner_controlled_directory(source_root, label="source root")
    try:
        source_root.relative_to(repository_root)
    except ValueError:
        raise ValueError("source root must be inside repository root") from None
    if spec.source_commit or spec.source_tree_digest:
        if not spec.git_executable or not spec.git_executable_sha256:
            raise ValueError("exact approved git executable path and digest are required for git source verification")
        git_executable = _owner_safe_executable(
            spec.git_executable,
            spec.git_executable_sha256,
            label="git executable",
        )
        git_target = str(source_root)
        for git_ref, label in ((spec.source_commit, "source commit"), (spec.source_tree_digest, "source tree digest")):
            if not git_ref:
                continue
            verify_args = (str(git_executable), "-C", git_target, "rev-parse", "--verify", "HEAD" if label == "source commit" else "HEAD^{tree}")
            git_environment = {
                "PATH": f"{git_executable.parent}:/usr/bin:/bin",
                "HOME": "/nonexistent",
                "XDG_CONFIG_HOME": "/nonexistent",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_NOGLOBAL": "1",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
                "LANG": "C",
            }
            completed = subprocess.run(
                verify_args,
                check=False,
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
                env=git_environment,
            )
            if completed.returncode != 0 or completed.stdout.strip().lower() != git_ref.lower():
                raise ValueError(f"{label} does not match the current source checkout")
    if spec.pyproject_digest:
        pyproject = _path_without_following_symlinks(source_root / "pyproject.toml", must_exist=True, label="pyproject")
        _owner_safe_regular_file(pyproject, label="pyproject")
        actual_pyproject_digest = hashlib.sha256(pyproject.read_bytes()).hexdigest()
        if actual_pyproject_digest.lower() != spec.pyproject_digest.lower():
            raise ValueError("pyproject digest does not match the immutable manifest")
    target = _path_without_following_symlinks(spec.venv_path, must_exist=False, label="venv target")
    if target.exists() and not allow_existing_target:
        raise ValueError("venv target already exists; insert-only provisioning refuses overwrite")
    if target.exists():
        info = target.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("existing venv target is not an owner-controlled 0700 directory")
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
    _owner_safe_regular_file(
        _path_without_following_symlinks(spec.requirements_lock_path, must_exist=True, label="requirements lock"),
        label="requirements lock",
    )
    lock_entries = _validate_lock_file(spec)
    _validate_wheelhouse(spec, lock_entries)


def plan_python_hashed_venv_provision(
    plan_id: str,
    spec: PythonVenvProvisionSpec,
    reason: str,
    current_state: str = "unknown",
    *,
    allow_existing_target: bool = False,
):
    """Build a high-risk, human-approved plan without changing host state."""

    validate_python_venv_spec(spec, allow_existing_target=allow_existing_target)
    from .admin import AdminChangeKind, AdminChangePlan, AdminCommandStep

    metadata = python_venv_spec_to_metadata(spec)
    python_executable = str(Path(spec.venv_path) / "bin" / "python")
    sealed_root = _sealed_inputs_root(spec)
    sealed_lock = str(sealed_root / "requirements.lock")
    sealed_wheelhouse = str(sealed_root / "wheelhouse")
    wheel_manifest_json = _canonical_json(list(_wheel_manifest(spec)))
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
            "--no-index",
            "--find-links",
            sealed_wheelhouse,
            sealed_lock,
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
            "--no-index",
            "--find-links",
            sealed_wheelhouse,
            "-r",
            sealed_lock,
        )
    environment = _execution_environment(spec)
    preflight_command = (
        PYTHON_VENV_PREFLIGHT_MARKER,
        spec.venv_path,
        PYTHON_VENV_PLAN_DIGEST_PLACEHOLDER,
        spec.manifest_digest,
        spec.requirements_lock_path,
        spec.requirements_lock_digest,
        spec.wheelhouse_path,
        str(sealed_root),
        wheel_manifest_json,
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
            AdminCommandStep(PYTHON_VENV_PREFLIGHT_MARKER, preflight_command, "seal the exact hash-verified lock and wheel inputs and recheck the insert-only destination immediately before creation"),
            AdminCommandStep("Create final versioned Python venv", venv_command, "create the new runtime directly at its final path; overwrite and --clear are forbidden", environment=environment, clear_environment=True),
            AdminCommandStep(PYTHON_VENV_MARKER, (PYTHON_VENV_MARKER, spec.venv_path, PYTHON_VENV_PLAN_DIGEST_PLACEHOLDER), "verify the exact plan-owned runtime marker before package mutation so failed installs can roll back safely"),
            AdminCommandStep("Install hash-pinned wheels", install_command, "install only lockfile-pinned hashed wheels into the isolated venv" , environment=environment, clear_environment=True),
        ),
        rollback_steps=(
            AdminCommandStep("Remove marker-owned Python venv", (PYTHON_VENV_REMOVE_MARKER, spec.venv_path, PYTHON_VENV_PLAN_DIGEST_PLACEHOLDER, str(sealed_root)), "remove only the exact newly-created runtime and sealed inputs bearing this plan marker"),
        ),
        risks=(
            "isolated runtime files are created outside the repository",
            "resolver and wheel artifacts are immutable and hash-verified",
            "system Python and unrelated environments are unchanged",
            "rollback is only permitted for this plan's marker-owned runtime",
        ),
        verification_steps=(
            AdminCommandStep("Verify isolated interpreter", (python_executable, "-c", f"import platform; assert platform.python_version() == {spec.python_version!r}"), "confirm the new venv interpreter exactly matches the requested runtime", environment=environment, clear_environment=True),
            AdminCommandStep("Verify managed import and version", (python_executable, "-c", f"import {spec.import_name}; assert getattr({spec.import_name}, '__version__', None) == {spec.expected_version!r}"), "confirm the expected import and version are present inside the new venv", environment=environment, clear_environment=True),
        ),
        adapter_metadata={PYTHON_VENV_METADATA_KEY: metadata},
    )
    plan_digest = python_venv_plan_digest(plan)
    def bind_plan_digest(step):
        if step.command and step.command[0] in {
            PYTHON_VENV_PREFLIGHT_MARKER,
            PYTHON_VENV_MARKER,
            PYTHON_VENV_REMOVE_MARKER,
        }:
            return replace(step, command=(*step.command[:2], plan_digest, *step.command[3:]))
        return step
    plan_metadata = dict(plan.adapter_metadata)
    plan_metadata[PYTHON_VENV_METADATA_KEY] = {**metadata, "plan_digest": plan_digest}
    return replace(
        plan,
        steps=tuple(bind_plan_digest(step) for step in plan.steps),
        rollback_steps=tuple(bind_plan_digest(step) for step in plan.rollback_steps),
        adapter_metadata=plan_metadata,
    )


def _plan_shape(plan) -> dict[str, Any]:
    def step_shape(step) -> dict[str, Any]:
        command = list(step.command)
        if command and command[0] in {
            PYTHON_VENV_PREFLIGHT_MARKER,
            PYTHON_VENV_MARKER,
            PYTHON_VENV_REMOVE_MARKER,
        } and len(command) > 2:
            command[2] = PYTHON_VENV_PLAN_DIGEST_PLACEHOLDER
        payload: dict[str, Any] = {"title": step.title, "command": command, "reason": step.reason}
        if getattr(step, "environment", ()):
            payload["environment"] = {key: value for key, value in step.environment}
        if getattr(step, "clear_environment", False):
            payload["clear_environment"] = True
        return payload

    metadata = dict(getattr(plan, "adapter_metadata", {}).get(PYTHON_VENV_METADATA_KEY, {}))
    metadata.pop("plan_digest", None)
    return {
        "id": plan.id,
        "kind": str(plan.kind),
        "owner_domain": str(plan.owner_domain),
        "risk_level": str(plan.risk_level),
        "approval_level": str(plan.approval_level),
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
    from .admin import AdminChangeKind

    if plan.kind != AdminChangeKind.PYTHON_HASHED_VENV_PROVISION:
        raise ValueError("python venv plan kind is not python_hashed_venv_provision")
    if plan.owner_domain != OwnerDomain.OBRIEN:
        raise ValueError("python venv plan owner domain must be OBRIEN")
    if plan.risk_level != RiskLevel.HIGH:
        raise ValueError("python venv plan risk level must be HIGH")
    if plan.approval_level != ApprovalLevel.HUMAN:
        raise ValueError("python venv plan approval level must be HUMAN")
    metadata = getattr(plan, "adapter_metadata", {}).get(PYTHON_VENV_METADATA_KEY)
    if not isinstance(metadata, dict):
        raise ValueError("python_hashed_venv_provision plan is missing its typed manifest")
    spec = python_venv_spec_from_metadata(metadata)
    expected_digest = metadata.get("manifest_digest")
    if expected_digest != spec.manifest_digest:
        raise ValueError("python venv manifest digest is not stable")
    validate_python_venv_spec(spec, allow_existing_target=True)
    if plan.target != spec.venv_path:
        raise ValueError("python venv plan target does not match its manifest")
    if Path(spec.venv_path).exists():
        _verify_owner_marker(
            Path(spec.venv_path) / ".overseer-python-venv-owner",
            metadata.get("plan_digest", ""),
            label="venv ownership marker",
        )
    if metadata.get("plan_digest") != python_venv_plan_digest(plan):
        raise ValueError("python venv canonical immutable plan header or command digest does not match approval")
    canonical = plan_python_hashed_venv_provision(
        plan.id,
        spec,
        plan.reason,
        plan.current_state,
        allow_existing_target=Path(spec.venv_path).exists(),
    )
    if metadata.get("plan_digest") != python_venv_plan_digest(canonical):
        raise ValueError("python venv plan digest is not stable")
    if plan.steps != canonical.steps or plan.rollback_steps != canonical.rollback_steps or plan.verification_steps != canonical.verification_steps:
        raise ValueError("python venv canonical plan command boundary does not match its immutable manifest")
    if plan.adapter_metadata != canonical.adapter_metadata:
        raise ValueError("python venv plan metadata does not match its immutable manifest")
    return spec


def _read_owner_file_bytes(path: Path, *, label: str) -> bytes:
    """Read one immutable input through an O_NOFOLLOW descriptor."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file without symlinks")
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError(f"{label} must be owned by the current user and not group/world writable")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_sealed_file(path: Path, content: bytes, *, label: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(fd, content[offset:])
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)


def _verify_owner_marker(path: Path, digest: str, *, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise ValueError(f"{label} is absent or mismatched") from None
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
        or path.read_text(encoding="utf-8").strip() != digest
    ):
        raise ValueError(f"{label} is absent or mismatched")


def _ensure_plan_owned_target(target_text: str, plan_digest: str) -> Path:
    """Atomically claim the final target before an external venv tool runs."""
    target = _path_without_following_symlinks(target_text, must_exist=False, label="venv target")
    _owner_only_directory(target.parent, label="venv target parent", allow_sticky_shared=True)
    created = False
    try:
        info = target.lstat()
    except FileNotFoundError:
        try:
            os.mkdir(target, 0o700)
            created = True
        except FileExistsError:
            pass
        info = target.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError("venv target is not an owner-controlled directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("venv target is not an owner-controlled 0700 directory")
    marker_path = target / ".overseer-python-venv-owner"
    try:
        marker_info = marker_path.lstat()
    except FileNotFoundError:
        if not created:
            raise ValueError("preexisting venv target lacks the exact plan ownership marker") from None
        _write_sealed_file(marker_path, plan_digest.encode("ascii") + b"\n", label="venv ownership marker")
    else:
        if stat.S_ISLNK(marker_info.st_mode) or not stat.S_ISREG(marker_info.st_mode):
            raise ValueError("venv ownership marker is not a regular file")
        _verify_owner_marker(marker_path, plan_digest, label="venv ownership marker")
    os.chmod(target, 0o700, follow_symlinks=False)
    return target


def _seal_python_venv_inputs(command: tuple[str, ...]) -> tuple[int, str, str]:
    (
        _marker,
        target_text,
        plan_digest,
        manifest_digest,
        lock_text,
        lock_digest,
        wheelhouse_text,
        sealed_text,
        wheel_manifest_text,
    ) = command
    _validate_digest(plan_digest, "plan digest")
    _validate_digest(manifest_digest, "manifest digest")
    target = _ensure_plan_owned_target(target_text, plan_digest)
    _validate_digest(lock_digest, "requirements lock SHA256")
    lock_path = _path_without_following_symlinks(lock_text, must_exist=True, label="requirements lock")
    _owner_safe_regular_file(lock_path, label="requirements lock")
    lock_bytes = _read_owner_file_bytes(lock_path, label="requirements lock")
    if hashlib.sha256(lock_bytes).hexdigest().lower() != lock_digest.lower():
        return 1, "", "refusing seal: requirements lock changed after validation"
    wheelhouse = _path_without_following_symlinks(wheelhouse_text, must_exist=True, label="wheelhouse")
    _owner_only_directory(wheelhouse, label="wheelhouse")
    try:
        wheel_manifest = json.loads(wheel_manifest_text)
    except json.JSONDecodeError as error:
        raise ValueError("wheel manifest is not canonical JSON") from error
    if not isinstance(wheel_manifest, list) or _canonical_json(wheel_manifest) != wheel_manifest_text:
        raise ValueError("wheel manifest is not canonical JSON")
    expected_names: set[str] = set()
    wheel_bytes: list[tuple[str, bytes]] = []
    for entry in wheel_manifest:
        if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "version"}:
            raise ValueError("wheel manifest entry is malformed")
        name = entry["name"]
        if not isinstance(name, str) or not name or Path(name).name != name or not name.lower().endswith(".whl"):
            raise ValueError("wheel manifest contains an unsafe wheel name")
        if name in expected_names:
            raise ValueError("wheel manifest contains duplicate wheel names")
        expected_names.add(name)
        _validate_digest(entry["sha256"], f"wheel {name} SHA256")
        wheel_path = _path_without_following_symlinks(wheelhouse / name, must_exist=True, label=f"wheel {name}")
        content = _read_owner_file_bytes(wheel_path, label=f"wheel {name}")
        if hashlib.sha256(content).hexdigest().lower() != entry["sha256"].lower():
            return 1, "", f"refusing seal: wheel changed after validation: {name}"
        wheel_bytes.append((name, content))
    actual_names = {item.name for item in wheelhouse.iterdir() if item.is_file() and item.suffix == ".whl"}
    if actual_names != expected_names:
        return 1, "", "refusing seal: wheelhouse contents changed after validation"
    seal_root = _path_without_following_symlinks(sealed_text, must_exist=False, label="sealed input area")
    if seal_root.exists():
        _owner_only_directory(seal_root, label="sealed input area")
        _verify_owner_marker(seal_root / PYTHON_VENV_INPUTS_MARKER, plan_digest, label="sealed input ownership marker")
        shutil.rmtree(seal_root)
    try:
        os.mkdir(seal_root, 0o700)
        _owner_only_directory(seal_root, label="sealed input area")
        _write_sealed_file(seal_root / PYTHON_VENV_INPUTS_MARKER, plan_digest.encode("ascii") + b"\n", label="sealed input marker")
        sealed_wheelhouse = seal_root / "wheelhouse"
        os.mkdir(sealed_wheelhouse, 0o700)
        _write_sealed_file(seal_root / "requirements.lock", lock_bytes, label="sealed requirements lock")
        for name, content in wheel_bytes:
            _write_sealed_file(sealed_wheelhouse / name, content, label=f"sealed wheel {name}")
        return 0, "immutable lock and wheel inputs sealed", ""
    except Exception:
        try:
            if seal_root.is_dir() and not seal_root.is_symlink() and seal_root.lstat().st_uid == os.getuid():
                shutil.rmtree(seal_root)
        except OSError:
            pass
        raise


def execute_python_venv_marker(command: tuple[str, ...]) -> tuple[int, str, str]:
    """Execute an internal marker operation; never follows a path symlink."""

    marker = command[0]
    if marker == PYTHON_VENV_PREFLIGHT_MARKER:
        return _seal_python_venv_inputs(command)
    if marker == PYTHON_VENV_MARKER:
        _, target_text, digest = command
        target = _path_without_following_symlinks(target_text, must_exist=True, label="venv target")
        info = target.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("venv target is not an owner-controlled 0700 directory")
        _verify_owner_marker(target / ".overseer-python-venv-owner", digest, label="venv ownership marker")
        return 0, "marker verified", ""
    if marker == PYTHON_VENV_REMOVE_MARKER:
        _, target_text, digest, *sealed_parts = command
        target = _path_without_following_symlinks(target_text, must_exist=False, label="venv target")
        sealed_root = None
        if sealed_parts:
            sealed_root = _path_without_following_symlinks(sealed_parts[0], must_exist=False, label="sealed input area")
        removed = False
        if target.exists():
            if target.lstat().st_uid != os.getuid() or stat.S_IMODE(target.lstat().st_mode) & 0o022:
                raise ValueError("venv target is not owner-controlled")
            _verify_owner_marker(
                target / ".overseer-python-venv-owner",
                digest,
                label="exact plan ownership marker",
            )
            shutil.rmtree(target)
            removed = True
        if sealed_root is not None and sealed_root.exists():
            if not sealed_root.is_dir() or sealed_root.is_symlink() or sealed_root.lstat().st_uid != os.getuid():
                raise ValueError("sealed input area is not owner-controlled")
            marker_path = sealed_root / PYTHON_VENV_INPUTS_MARKER
            try:
                marker_info = marker_path.lstat()
            except FileNotFoundError:
                return 1, "", "refusing rollback: sealed input ownership marker is absent"
            if (
                stat.S_ISLNK(marker_info.st_mode)
                or not stat.S_ISREG(marker_info.st_mode)
                or marker_info.st_uid != os.getuid()
                or stat.S_IMODE(marker_info.st_mode) & 0o077
                or marker_path.read_text(encoding="utf-8").strip() != digest
            ):
                return 1, "", "refusing rollback: sealed input ownership marker is absent or mismatched"
            shutil.rmtree(sealed_root)
            removed = True
        return (0, "marker-owned venv and sealed inputs removed", "") if removed else (0, "nothing to remove", "")
    raise ValueError(f"unknown Python venv marker command: {marker}")


__all__ = [
    "PYTHON_VENV_METADATA_KEY",
    "PYTHON_VENV_MARKER",
    "PYTHON_VENV_PREFLIGHT_MARKER",
    "PYTHON_VENV_REMOVE_MARKER",
    "PYTHON_VENV_INPUTS_MARKER",
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
