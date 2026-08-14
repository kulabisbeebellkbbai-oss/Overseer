from __future__ import annotations

import hashlib
import os
import tempfile
import threading
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
import overseer.python_venv as python_venv

from overseer import (
    AdminAdapterStatus,
    AdminChangeKind,
    AdminCommandResult,
    AdminExecutionStatus,
    ApprovalLevel,
    approve_admin_change_plan,
    admin_execution_capability_for,
    execute_admin_change_plan,
    plan_python_hashed_venv_provision,
)
from overseer.admin import AdminCommandStep, run_admin_command_step
from overseer.core import RiskLevel
from overseer.python_venv import (
    PythonVenvArtifact,
    PythonVenvProvisionSpec,
    acquire_python_venv_execution_lock,
    validate_python_venv_spec,
)
from overseer.serialization import to_jsonable


def _fixture_spec(root: Path, *, target: Path | None = None, **overrides) -> PythonVenvProvisionSpec:
    repo = root / "repo"
    repo.mkdir(exist_ok=True)
    repo.chmod(0o700)
    pyproject = repo / "pyproject.toml"
    pyproject.write_text("[project]\nname='fixture'\nversion='1.0.0'\n", encoding="utf-8")
    pyproject.chmod(0o600)
    wheel = root / "wheelhouse" / "example-1.2.3-py3-none-any.whl"
    wheel.parent.mkdir(exist_ok=True)
    wheel.write_bytes(b"fixture wheel bytes")
    wheel.chmod(0o600)
    wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    lock = repo / "requirements.lock"
    lock.write_text("example==1.2.3 --hash=sha256:" + wheel_digest + "\n", encoding="utf-8")
    lock.chmod(0o600)
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
        pyproject_digest=hashlib.sha256((repo / "pyproject.toml").read_bytes()).hexdigest(),
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
            PythonVenvArtifact(
                name=wheel.name,
                url="https://example.test/example-1.2.3-py3-none-any.whl",
                version="1.2.3",
                sha256=wheel_digest,
            ),
        ),
        resolver="python",
        resolver_executable="/usr/bin/python3.13",
        resolver_executable_sha256=hashlib.sha256(Path("/usr/bin/python3.13").read_bytes()).hexdigest(),
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
    assert (spec.resolver_executable, "-m", "venv", spec.venv_path) in commands
    assert any("--require-hashes" in command for command in commands)
    assert any("--no-deps" in command for command in commands)
    assert plan.verification_steps[-1].command[-1].find("import example") >= 0


def test_hash_pinned_venv_requires_owner_safe_path_outside_repository():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root, target=root / "repo" / ".venv")
        with pytest.raises(ValueError, match="outside repository"):
            validate_python_venv_spec(spec)


def test_hash_pinned_venv_rejects_lexical_alias_components_before_lock_identity():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root, target=f"{root}/managed-venvs/./psychlo-1.2.3")
        with pytest.raises(ValueError, match="lexical"):
            validate_python_venv_spec(spec)


def test_hash_pinned_venv_canonical_lock_rejects_alias_contender():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        winner = approve_admin_change_plan(
            plan_python_hashed_venv_provision("admin.python.venv.canonical-lock", spec, "test", "absent"),
            "human",
        )
        alias_metadata = dict(winner.adapter_metadata["python_venv"])
        alias_metadata["venv_path"] = f"{root}/managed-venvs/./psychlo-1.2.3"
        alias_plan = replace(
            winner,
            target=alias_metadata["venv_path"],
            adapter_metadata={"python_venv": alias_metadata},
        )
        with acquire_python_venv_execution_lock(winner):
            contender = execute_admin_change_plan(
                alias_plan,
                runner=lambda step: pytest.fail("alias contender command ran"),
                enabled_adapter_kinds=(AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,),
            )
    assert contender.status == AdminExecutionStatus.BLOCKED
    assert "lexical" in contender.summary


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
        target.chmod(0o700)
        digest = "d" * 64
        marker = target / ".overseer-python-venv-owner"
        marker.write_text(digest + "\n", encoding="utf-8")
        marker.chmod(0o600)
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


def test_hash_pinned_venv_requires_strict_import_name_and_actual_wheel_parity():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root, import_name="example.bad")
        with pytest.raises(ValueError, match="strict import"):
            validate_python_venv_spec(spec)
        wheel = Path(spec.wheelhouse_path) / "example-1.2.3-py3-none-any.whl"
        wheel.write_bytes(b"drift")
        with pytest.raises(ValueError, match="wheelhouse artifact|requirements lock"):
            validate_python_venv_spec(replace(spec, import_name="example"))


def test_hash_pinned_venv_reconstructs_canonical_commands_before_execution():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = approve_admin_change_plan(
            plan_python_hashed_venv_provision("admin.python.venv.tampered", spec, "test", "absent"),
            "human",
        )
        tampered = replace(plan, steps=plan.steps + (AdminCommandStep("unexpected", ("touch", "/tmp/bad"), "bad"),))
        result = execute_admin_change_plan(
            tampered,
            enabled_adapter_kinds=(AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,),
            runner=lambda step: pytest.fail("tampered plan executed a command"),
        )
    assert result.status == AdminExecutionStatus.BLOCKED
    assert "canonical" in result.summary


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    (("risk_level", RiskLevel.LOW, "risk level"), ("approval_level", ApprovalLevel.NONE, "approval level")),
)
def test_hash_pinned_venv_cannot_execute_after_approval_header_downgrade(field, value, expected):
    with tempfile.TemporaryDirectory() as directory:
        spec = _fixture_spec(Path(directory))
        plan = approve_admin_change_plan(
            plan_python_hashed_venv_provision("admin.python.venv.header", spec, "test", "absent"),
            "human",
        )
        tampered = replace(plan, **{field: value})
        result = execute_admin_change_plan(
            tampered,
            enabled_adapter_kinds=(AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,),
            runner=lambda step: pytest.fail("tampered plan executed a command"),
        )
    assert result.status == AdminExecutionStatus.BLOCKED
    assert expected in result.summary


def test_hash_pinned_venv_preflight_seals_inputs_and_rollback_removes_only_seal():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = plan_python_hashed_venv_provision("admin.python.venv.seal", spec, "test", "absent")
        preflight = run_admin_command_step(plan.steps[0])
        seal_root = Path(plan.steps[0].command[7])
        assert preflight.exit_code == 0
        assert (seal_root / "requirements.lock").read_bytes() == Path(spec.requirements_lock_path).read_bytes()
        assert (seal_root / "wheelhouse" / "example-1.2.3-py3-none-any.whl").read_bytes()
        Path(spec.requirements_lock_path).write_text("example==9.9.9\n", encoding="utf-8")
        rollback = run_admin_command_step(plan.rollback_steps[0])
        assert rollback.exit_code == 0
        assert not seal_root.exists()


def test_hash_pinned_venv_preflight_claims_final_target_and_replays_partial_state():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = plan_python_hashed_venv_provision("admin.python.venv.replay", spec, "test", "absent")
        first = run_admin_command_step(plan.steps[0])
        target = Path(spec.venv_path)
        marker = target / ".overseer-python-venv-owner"
        seal_root = Path(plan.steps[0].command[7])
        assert first.exit_code == 0
        assert target.stat().st_mode & 0o777 == 0o700
        assert marker.read_text(encoding="utf-8").strip() == plan.adapter_metadata["python_venv"]["plan_digest"]
        assert marker.read_text(encoding="utf-8").strip() != spec.manifest_digest
        (target / "partial.txt").write_text("crash residue", encoding="utf-8")
        replay = run_admin_command_step(plan.steps[0])
        assert replay.exit_code == 0
        assert target.exists() and seal_root.exists()
        rollback = run_admin_command_step(plan.rollback_steps[0])
        assert rollback.exit_code == 0
        assert not target.exists() and not seal_root.exists()


def test_hash_pinned_venv_preflight_rejects_unmarked_preexisting_target():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = plan_python_hashed_venv_provision("admin.python.venv.unmarked", spec, "test", "absent")
        target = Path(spec.venv_path)
        target.mkdir(mode=0o700)
        result = run_admin_command_step(plan.steps[0])
    assert result.exit_code != 0
    assert "marker" in result.stderr or "ownership" in result.stderr


def test_hash_pinned_venv_orphan_temp_cleanup_requires_exact_marker():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = plan_python_hashed_venv_provision("admin.python.venv.orphans", spec, "test", "absent")
        parent = Path(spec.venv_path).parent
        prefix = f".overseer-python-venv-{plan.adapter_metadata['python_venv']['plan_digest']}.tmp-"
        unmarked = parent / f"{prefix}unmarked"
        unmarked.mkdir(mode=0o700)
        exact = parent / f"{prefix}exact"
        exact.mkdir(mode=0o700)
        marker = exact / ".overseer-python-venv-owner"
        marker.write_text(plan.adapter_metadata["python_venv"]["plan_digest"] + "\n", encoding="utf-8")
        marker.chmod(0o600)
        result = run_admin_command_step(plan.steps[0])
        assert result.exit_code == 0
        assert unmarked.exists()
        assert not exact.exists()


def test_hash_pinned_venv_seal_pre_marker_blocks_without_deleting_target():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = plan_python_hashed_venv_provision("admin.python.venv.seal-pre-marker", spec, "test", "absent")
        seal_root = Path(plan.steps[0].command[7])
        seal_root.mkdir(mode=0o700)
        result = run_admin_command_step(plan.steps[0])
        target = Path(spec.venv_path)
        assert result.exit_code != 0
        assert target.exists()
        assert "sealed input ownership marker" in result.stderr


def test_hash_pinned_venv_rollback_validates_seal_before_deleting_target():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        plan = plan_python_hashed_venv_provision("admin.python.venv.rollback-seal", spec, "test", "absent")
        assert run_admin_command_step(plan.steps[0]).exit_code == 0
        seal_root = Path(plan.steps[0].command[7])
        seal_marker = seal_root / ".overseer-python-venv-inputs-owner"
        seal_marker.write_text("e" * 64 + "\n", encoding="utf-8")
        result = run_admin_command_step(plan.rollback_steps[0])
        target = Path(spec.venv_path)
        assert result.exit_code != 0
        assert target.exists()
        assert seal_root.exists()


def test_hash_pinned_venv_git_verification_clears_hostile_environment(monkeypatch):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        git_path = Path("/usr/bin/git")
        spec = _fixture_spec(
            root,
            source_commit="a" * 40,
            git_executable=str(git_path),
            git_executable_sha256=hashlib.sha256(git_path.read_bytes()).hexdigest(),
        )
        captured = {}

        class Completed:
            returncode = 0
            stdout = "a" * 40 + "\n"

        def fake_run(args, **kwargs):
            captured.update(kwargs)
            return Completed()

        monkeypatch.setattr(python_venv.subprocess, "run", fake_run)
        monkeypatch.setenv("GIT_DIR", "/hostile/git")
        monkeypatch.setenv("GIT_WORK_TREE", "/hostile/tree")
        monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/hostile/objects")
        monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/hostile/alternates")
        validate_python_venv_spec(spec)

    environment = captured["env"]
    assert environment["HOME"] == "/nonexistent"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_CONFIG_NOGLOBAL"] == "1"
    for hostile in ("GIT_DIR", "GIT_WORK_TREE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        assert hostile not in environment


def test_hash_pinned_venv_lifecycle_lock_blocks_contender_without_rollback():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        spec = _fixture_spec(root)
        winner = approve_admin_change_plan(
            plan_python_hashed_venv_provision("admin.python.venv.lock-winner", spec, "test", "absent"),
            "human",
        )
        contender = approve_admin_change_plan(
            plan_python_hashed_venv_provision("admin.python.venv.lock-contender", spec, "test", "absent"),
            "human",
        )
        entered_publication = threading.Event()
        release_winner = threading.Event()
        winner_results = []

        def winner_runner(step):
            if step.command and step.command[0] == "__overseer_python_venv_preflight__":
                result = run_admin_command_step(step)
                entered_publication.set()
                assert release_winner.wait(5)
                return result
            return AdminCommandResult(step.title, step.command, 0, "winner")

        def run_winner():
            winner_results.append(
                execute_admin_change_plan(
                    winner,
                    runner=winner_runner,
                    enabled_adapter_kinds=(AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,),
                )
            )

        thread = threading.Thread(target=run_winner)
        thread.start()
        assert entered_publication.wait(5)
        contender_result = execute_admin_change_plan(
            contender,
            runner=lambda step: pytest.fail("contender command or rollback ran"),
            enabled_adapter_kinds=(AdminChangeKind.PYTHON_HASHED_VENV_PROVISION,),
        )
        release_winner.set()
        thread.join(timeout=5)
        target = Path(spec.venv_path)
        seal_root = Path(winner.steps[0].command[7])
        target_exists = target.exists()
        seal_exists = seal_root.exists()

    assert winner_results and winner_results[0].status == AdminExecutionStatus.COMPLETED
    assert contender_result.status == AdminExecutionStatus.BLOCKED
    assert "busy" in contender_result.summary
    assert target_exists
    assert seal_exists


def test_legacy_empty_environment_serialization_is_unchanged():
    step = AdminCommandStep("legacy", ("echo", "ok"), "legacy step")
    assert to_jsonable(step) == {"title": "legacy", "command": ["echo", "ok"], "reason": "legacy step"}


def test_legacy_omissions_do_not_apply_to_unrelated_dataclasses():
    @dataclass(frozen=True)
    class UnrelatedRecord:
        environment: tuple[tuple[str, str], ...] = ()
        clear_environment: bool = False
        adapter_metadata: dict[str, object] | None = None

    assert to_jsonable(UnrelatedRecord()) == {
        "environment": [],
        "clear_environment": False,
        "adapter_metadata": None,
    }
