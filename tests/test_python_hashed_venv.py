from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from overseer import (
    AdminAdapterStatus,
    AdminChangeKind,
    AdminCommandResult,
    AdminExecutionStatus,
    approve_admin_change_plan,
    admin_execution_capability_for,
    execute_admin_change_plan,
    plan_python_hashed_venv_provision,
)
from overseer.admin import AdminCommandStep, run_admin_command_step
from overseer.python_venv import PythonVenvArtifact, PythonVenvProvisionSpec, validate_python_venv_spec


def _fixture_spec(root: Path, *, target: Path | None = None, **overrides) -> PythonVenvProvisionSpec:
    repo = root / "repo"
    repo.mkdir(exist_ok=True)
    lock = repo / "requirements.lock"
    lock.write_text("example==1.2.3 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    (root / "wheelhouse").mkdir(exist_ok=True)
    (root / "wheelhouse").chmod(0o700)
    managed = root / "managed-venvs"
    if not managed.exists():
        managed.mkdir()
        managed.chmod(0o700)
    digest = hashlib.sha256(lock.read_bytes()).hexdigest()
    values = dict(
        venv_path=str(target or (root / "managed-venvs" / "psychlo-1.2.3")),
        source_root=str(repo),
        repository_root=str(repo),
        source_commit="1" * 40,
        requirements_lock_path=str(lock),
        requirements_lock_digest=digest,
        wheelhouse_path=str(root / "wheelhouse"),
        artifacts=(
            PythonVenvArtifact(
                name="uv",
                url="https://github.com/astral-sh/uv/releases/download/0.8.0/uv-x86_64-unknown-linux-gnu.tar.gz",
                version="0.8.0",
                sha256="b" * 64,
            ),
        ),
        resolver="uv",
        resolver_version="0.8.0",
        resolver_provenance="approved internal artifact mirror manifest uv-0.8.0",
        python_version="3.13",
        import_name="example",
        expected_version="1.2.3",
    )
    values.update(overrides)
    return PythonVenvProvisionSpec(**values)


def test_hash_pinned_venv_plan_records_immutable_inputs_and_commands():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = plan_python_hashed_venv_provision(
            "admin.python.venv.psychlo",
            spec,
            "provision isolated Psychlo runtime",
            "runtime venv absent",
        )

    assert plan.kind == AdminChangeKind.PYTHON_HASHED_VENV_PROVISION
    assert plan.approval_level.value == "human"
    assert plan.risk_level.value == "high"
    assert plan.adapter_metadata["python_venv"]["requirements_lock_digest"] == spec.requirements_lock_digest
    commands = [step.command for step in plan.steps]
    assert ("uv", "venv", "--python", "3.13", spec.venv_path) in commands
    assert any("--require-hashes" in command for command in commands)
    assert any("--no-deps" in command for command in commands)
    assert plan.verification_steps[-1].command[-1].find("import example") >= 0


def test_hash_pinned_venv_requires_owner_safe_path_outside_repository():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root, target=root / "repo" / ".venv")
        with pytest.raises(ValueError, match="outside repository"):
            validate_python_venv_spec(spec)


def test_hash_pinned_venv_rejects_symlinked_target_parent():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        outside = root / "outside"
        outside.mkdir()
        managed = root / "managed-venvs"
        managed.symlink_to(outside, target_is_directory=True)
        spec = _fixture_spec(root, target=managed / "psychlo")
        with pytest.raises(ValueError, match="symlink"):
            validate_python_venv_spec(spec)


def test_hash_pinned_venv_rejects_lock_digest_or_artifact_drift():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root, requirements_lock_digest="c" * 64)
        with pytest.raises(ValueError, match="requirements lock digest"):
            validate_python_venv_spec(spec)
        with pytest.raises(ValueError, match="SHA256"):
            validate_python_venv_spec(
                _fixture_spec(
                    root,
                    artifacts=(PythonVenvArtifact("uv", "https://example.test/uv", "0.8.0", "bad"),),
                )
            )


def test_hash_pinned_venv_is_blocked_without_exact_adapter_approval():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = approve_admin_change_plan(
            plan_python_hashed_venv_provision("admin.python.venv.blocked", spec, "test", "absent"),
            "human",
        )
    result = execute_admin_change_plan(plan, runner=lambda step: pytest.fail("blocked plan ran a command"))
    assert result.status == AdminExecutionStatus.BLOCKED
    assert admin_execution_capability_for(plan.kind).status == AdminAdapterStatus.DISABLED


def test_hash_pinned_venv_executes_only_with_enabled_adapter_and_keeps_rollback_exact():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = approve_admin_change_plan(
            plan_python_hashed_venv_provision("admin.python.venv.exec", spec, "test", "absent"),
            "human",
        )
        seen = []

        def runner(step):
            seen.append(step.command)
            return AdminCommandResult(step.title, step.command, 0, "ok")

        result = execute_admin_change_plan(
            plan,
            enabled_adapter_kinds=(AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,),
            runner=runner,
        )
    assert result.status == AdminExecutionStatus.COMPLETED
    assert any(command[0] == "__overseer_python_venv_remove_owned__" and command[1] == spec.venv_path for command in (step.command for step in plan.rollback_steps))
    assert admin_execution_capability_for(plan.kind, (plan.kind,)).status == AdminAdapterStatus.ENABLED


def test_hash_pinned_venv_marker_rollback_removes_only_owned_target():
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "runtime-1.2.3"
        target.mkdir()
        target.chmod(0o755)
        digest = "d" * 64
        marked = run_admin_command_step(
            AdminCommandStep("mark", ("__overseer_python_venv_marker__", str(target), digest), "mark")
        )
        removed = run_admin_command_step(
            AdminCommandStep("remove", ("__overseer_python_venv_remove_owned__", str(target), digest), "remove")
        )
    assert marked.exit_code == 0
    assert removed.exit_code == 0


def test_hash_pinned_venv_lock_rejects_vcs_ranges_and_duplicate_packages():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        lock = Path(spec.requirements_lock_path)
        content = "example>=1.2 --hash=sha256:" + "a" * 64 + "\n"
        lock.write_text(content, encoding="utf-8")
        spec = replace(spec, requirements_lock_digest=hashlib.sha256(lock.read_bytes()).hexdigest())
        with pytest.raises(ValueError, match="must pin"):
            validate_python_venv_spec(spec)
