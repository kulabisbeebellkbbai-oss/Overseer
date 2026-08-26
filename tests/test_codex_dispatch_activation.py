from __future__ import annotations

import json
import hashlib
import os
import py_compile
import stat
import socket
import subprocess
import threading
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

import overseer.codex_dispatch_activation as activation
from overseer.admin import AdminChangeKind, AdminCommandResult, ApprovalLevel, OwnerDomain, RiskLevel
from overseer.codex_dispatch_activation import (
    CODEX_DISPATCH_ACTIVATION_SCHEMA,
    DAEMON_SOCKET_RELATIVE_PATH,
    CodexDispatchActivationSpec,
    execute_codex_dispatch_activation_marker,
    execute_codex_dispatch_activation_plan,
    plan_codex_dispatch_activation,
    validate_codex_dispatch_activation_plan,
)


def _spec() -> CodexDispatchActivationSpec:
    source_commit = "a" * 40
    source_tree = "b" * 40
    source_module = "c" * 64
    bootstrap_binding = {**_fixture_bootstrap_binding(), "sourceCommit": source_commit, "sourceTree": source_tree}
    return CodexDispatchActivationSpec(
        CODEX_DISPATCH_ACTIVATION_SCHEMA,
        source_commit,
        source_tree,
        source_module,
        activation._review_digest(source_commit, source_tree, source_module),
        dependency_digest="d" * 64,
        bootstrap_binding=bootstrap_binding,
        bus_peer_binding=activation._capture_user_bus_peer_binding(),
        launcher_blob=str(bootstrap_binding["launcherBlob"]),
        launcher_sha256=str(bootstrap_binding["launcherSha256"]),
        launcher_size=int(bootstrap_binding["launcherSize"]),
        source_files=activation._reviewed_source_files(),
    )


def _fixture_bootstrap_binding(source_commit: str | None = None, source_tree: str | None = None) -> dict[str, object]:
    common_git_dir = Path(activation._git(("rev-parse", "--git-common-dir"))).resolve()
    with patch.object(activation, "CANONICAL_SOURCE_ROOT", common_git_dir.parent):
        return activation._bootstrap_binding(source_commit, source_tree)


def _plan() -> object:
    return plan_codex_dispatch_activation("admin.codex-dispatch.test", _spec(), "activate reviewed dispatch", "disabled")


def _approved_plan():
    return replace(_plan(), approved=True, approved_by="sisko", approved_at="2026-08-18T00:00:00+00:00")


def _bootstrap_output() -> str:
    return json.dumps({
        "status": "bootstrapped",
        "backend": "pid",
        "autoUpdateEnabled": True,
        "remoteControlEnabled": False,
        "managedCodexPath": str(activation.CODEX_HOME / "packages/standalone/current/codex"),
        "managedCodexVersion": "0.147.0",
        "socketPath": str(activation.CODEX_HOME / activation.DAEMON_SOCKET_RELATIVE_PATH),
        "cliVersion": "0.147.0",
        "appServerVersion": "0.147.0",
    })


def _remote_disabled_output() -> str:
    return json.dumps({
        "status": "alreadyDisabled",
        "backend": "pid",
        "remoteControlEnabled": False,
        "socketPath": str(activation.CODEX_HOME / activation.DAEMON_SOCKET_RELATIVE_PATH),
        "cliVersion": "0.147.0",
        "appServerVersion": "0.147.0",
    })


def _busctl_environment(*values: str) -> str:
    return json.dumps({"type": "as", "data": list(values)})


def _busctl_execstart(command: tuple[str, ...], *, path: str | None = None) -> str:
    return json.dumps({
        "type": "a(sasbttttuii)",
        "data": [[path or command[0], list(command), False, 0, 0, 0, 0, 0, 0, 0]],
    })


def test_plan_is_exact_high_human_sisko_and_fixed_socket():
    plan = _plan()
    assert plan.kind == AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION
    assert plan.owner_domain == OwnerDomain.SISKO
    assert plan.risk_level == RiskLevel.HIGH
    assert plan.approval_level == ApprovalLevel.HUMAN
    assert plan.approved is False
    assert plan.adapter_metadata["spec"]["daemonSocket"] == DAEMON_SOCKET_RELATIVE_PATH
    assert all(step.command[0].startswith("__overseer_codex_dispatch_") for step in plan.steps + plan.rollback_steps + plan.verification_steps)
    assert "--remote-control" not in sum((list(step.command) for step in plan.steps), [])


def test_isolated_command_uses_root_python_and_in_memory_reviewed_blob():
    spec = _spec()
    command = activation._isolated_launcher_command(spec, "activation-cli", ("codex-dispatch-activation-status",))
    assert command[:4] == ("/usr/bin/python3", "-I", "-S", "-c")
    assert str(activation.ISOLATED_LAUNCHER) not in command
    assert command[4] == activation.IMMUTABLE_BOOTSTRAP
    config = json.loads(command[5])
    assert config["launcherBlob"] == spec.bootstrap_binding["launcherBlob"]
    assert config["sourceRoot"] == str(activation.CANONICAL_SOURCE_ROOT)
    assert config["sitePackages"] == str(activation.SERVICE_SITE_PACKAGES)


def test_root_binary_identity_rejects_user_owned_interpreter_symlink(tmp_path: Path):
    target = tmp_path / "python-real"
    target.write_bytes(b"binary")
    target.chmod(0o700)
    link = tmp_path / "python"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="root-owned"):
        activation._root_binary_identity(link, "Python")


def test_mutable_checkout_launcher_is_never_executed(tmp_path: Path):
    spec = _spec()
    command = activation._isolated_launcher_command(spec, "probe", ())
    launcher = activation.ISOLATED_LAUNCHER
    original = launcher.read_bytes()
    sentinel = tmp_path / "mutable-launcher-executed"
    try:
        launcher.write_text(
            f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n",
            encoding="utf-8",
        )
        completed = subprocess.run(command, capture_output=True, text=True, check=False, env={
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        })
        assert completed.returncode != 0
        assert not sentinel.exists()
    finally:
        launcher.write_bytes(original)


def test_bootstrap_rejects_unrelated_or_arbitrary_self_consistent_blob_before_exec():
    head = activation._git(("rev-parse", "HEAD"))
    tree = activation._git(("rev-parse", "HEAD^{tree}"))
    binding = _fixture_bootstrap_binding(head, tree)
    spec = replace(_spec(), source_commit=head, source_tree_digest=tree,
                   bootstrap_binding=binding,
                   launcher_blob=str(binding["launcherBlob"]),
                   launcher_sha256=str(binding["launcherSha256"]),
                   launcher_size=int(binding["launcherSize"]))
    command = list(activation._isolated_launcher_command(spec, "probe", ()))
    config = json.loads(command[5])
    unrelated = subprocess.check_output(
        ("git", "-C", str(activation.CANONICAL_SOURCE_ROOT), "rev-parse", f"{head}:src/overseer/core.py"),
        text=True,
    ).strip()
    unrelated_bytes = subprocess.check_output(
        ("git", "-C", str(activation.CANONICAL_SOURCE_ROOT), "cat-file", "blob", unrelated),
    )
    candidates = [
        (unrelated, hashlib.sha256(unrelated_bytes).hexdigest(), len(unrelated_bytes)),
        ("f" * 40, hashlib.sha256(b"arbitrary").hexdigest(), len(b"arbitrary")),
    ]
    for blob, digest, size in candidates:
        tampered = dict(config)
        tampered.update(launcherBlob=blob, launcherSha256=digest, launcherSize=size)
        tampered["bootstrapBinding"] = {
            **tampered["bootstrapBinding"], "launcherBlob": blob, "launcherSha256": digest, "launcherSize": size,
        }
        command[5] = activation._canonical(tampered)
        completed = subprocess.run(command, capture_output=True, text=True, check=False, env={
            "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        })
        assert completed.returncode != 0


def test_service_bootstrap_rejects_approved_manager_drift_before_launcher_import():
    head = activation._git(("rev-parse", "HEAD"))
    tree = activation._git(("rev-parse", "HEAD^{tree}"))
    binding = _fixture_bootstrap_binding(head, tree)
    spec = replace(_spec(), source_commit=head, source_tree_digest=tree,
                   bootstrap_binding=binding,
                   launcher_blob=str(binding["launcherBlob"]),
                   launcher_sha256=str(binding["launcherSha256"]),
                   launcher_size=int(binding["launcherSize"]))
    drifted = {**spec.bus_peer_binding, "startTicks": int(spec.bus_peer_binding["startTicks"]) + 1}
    spec = replace(spec, bus_peer_binding=drifted)
    payload = (
        "serve-api", "--store", str(activation.SERVICE_STORE), "--host", "127.0.0.1", "--port", "8766",
        "--auth-token-file", str(activation.SERVICE_TOKEN),
        "--human-approval-token-file", str(activation.SERVICE_HUMAN_APPROVAL_TOKEN),
        "--human-approval-identity", "sisko",
    )
    completed = subprocess.run(
        activation._isolated_launcher_command(spec, "service", payload),
        capture_output=True, text=True, check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    assert completed.returncode != 0


def test_caller_manifest_and_source_root_cannot_supply_authority(tmp_path: Path):
    with pytest.raises(ValueError, match="not authoritative"):
        activation.codex_dispatch_activation_spec_from_private_file(tmp_path / "manifest.json")
    spec = _spec()
    assert spec.source_root == activation.CANONICAL_SOURCE_ROOT
    with pytest.raises(ValueError, match="exact keys"):
        CodexDispatchActivationSpec.from_json({**spec.to_json(), "sourceRoot": "/tmp/untrusted"})


def test_reviewed_source_inventory_rejects_untracked_python_but_allows_unrelated_files(monkeypatch: pytest.MonkeyPatch):
    tracked = "src/overseer/a.py\nsrc/overseer/agent_adapters/codex.py\n"

    def clean_git(command):
        return "" if "--others" in command else tracked

    monkeypatch.setattr(activation, "_git", clean_git)
    assert activation._reviewed_source_files() == (
        "src/overseer/a.py",
        "src/overseer/agent_adapters/codex.py",
    )

    def untracked_git(command):
        return "src/overseer/injected.py" if "--others" in command else tracked

    monkeypatch.setattr(activation, "_git", untracked_git)
    with pytest.raises(ValueError, match="untracked Python"):
        activation._reviewed_source_files()


def test_reviewed_source_inventory_rejects_untracked_native_extension(monkeypatch: pytest.MonkeyPatch):
    tracked = "src/overseer/a.py\nsrc/overseer_codex_dispatch_launcher.py\n"

    def git(command):
        if "--others" in command:
            return "src/overseer/injected.cpython-313-x86_64-linux-gnu.so"
        return tracked

    monkeypatch.setattr(activation, "_git", git)
    with pytest.raises(ValueError, match="executable import artifact"):
        activation._reviewed_source_files()


def test_dependency_digest_changes_for_injected_python_or_native_extension(tmp_path: Path):
    tmp_path.chmod(0o700)
    (tmp_path / "package").mkdir()
    (tmp_path / "package").chmod(0o700)
    module = tmp_path / "package/module.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    module.chmod(0o600)
    initial = activation._dependency_digest(tmp_path)
    injected = tmp_path / "package/injected.cpython-313-x86_64-linux-gnu.so"
    injected.write_bytes(b"native")
    injected.chmod(0o600)
    assert activation._dependency_digest(tmp_path) != initial
    injected.unlink()
    module.write_text("VALUE = 2\n", encoding="utf-8")
    assert activation._dependency_digest(tmp_path) != initial


def test_reviewed_source_inventory_covers_preimport_python_anywhere_under_src(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[str, ...]] = []

    def git(command):
        calls.append(tuple(command))
        if "--others" in command:
            return "src/sitecustomize.py"
        return "src/overseer/__init__.py\nsrc/launcher.py"

    monkeypatch.setattr(activation, "_git", git)
    with pytest.raises(ValueError, match="untracked Python"):
        activation._reviewed_source_files()
    assert calls
    assert all(command[-1] == "src" for command in calls)
    assert all("--exclude-standard" not in command for command in calls)


def test_reviewed_source_inventory_rejects_untracked_sourceless_bytecode(monkeypatch: pytest.MonkeyPatch):
    tracked = "src/overseer/__init__.py\nsrc/overseer/cli.py\n"

    def git(command):
        return "src/sitecustomize.pyc" if "--others" in command else tracked

    monkeypatch.setattr(activation, "_git", git)
    with pytest.raises(ValueError, match="untracked Python"):
        activation._reviewed_source_files()


def test_dispatch_drop_in_uses_isolated_launcher_and_exact_service_arguments():
    content = activation._drop_in_content(_spec()).decode("utf-8")
    assert "Environment=PYTHONPATH=" in content
    assert "ExecStart=" in content
    assert " -I -S " in content
    assert "overseer_codex_dispatch_launcher.py" in content
    assert "serve-api" in content
    assert "/home/god/.local/share/overseer/project/state/overseer.sqlite3" in content
    assert "--host" in content and "127.0.0.1" in content and "--port" in content and "8766" in content
    assert "--auth-token-file" in content
    assert "/home/god/.local/share/overseer/project/state/api-token" in content
    assert "--human-approval-token-file" in content
    assert "/home/god/.local/share/overseer/project/state/human-approval-token" in content
    assert "--human-approval-identity" in content and "sisko" in content


def test_isolated_launcher_rejects_nonisolated_invocation_before_dispatch():
    launcher = activation.CANONICAL_SOURCE_ROOT / "src/overseer_codex_dispatch_launcher.py"
    assert launcher.is_file(), "isolated launcher is missing"
    completed = subprocess.run(
        ["/usr/bin/python3", str(launcher), "probe"],
        capture_output=True,
        text=True,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    assert completed.returncode != 0
    assert "-I -S" in completed.stderr


def test_activation_cli_stage_and_execute_fail_closed_outside_launcher(tmp_path: Path):
    from overseer import cli

    with pytest.raises(RuntimeError, match="isolated launcher"):
        cli.main([
            "stage-codex-dispatch-activation", "--store", str(tmp_path / "store.sqlite3"),
            "--plan-id", "admin.isolated.test", "--reason", "test isolated boundary",
        ])
    with pytest.raises(RuntimeError, match="isolated launcher"):
        cli.main([
            "execute-codex-dispatch-activation", "--store", str(tmp_path / "store.sqlite3"),
            "--plan-id", "admin.isolated.test",
        ])


def _isolated_probe_fixture(tmp_path: Path) -> tuple[Path, list[str]]:
    root = tmp_path / "reviewed"
    launcher = root / "src/overseer_codex_dispatch_launcher.py"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes((activation.CANONICAL_SOURCE_ROOT / "src/overseer_codex_dispatch_launcher.py").read_bytes())
    (root / "src/overseer").mkdir()
    (root / "src/overseer/__init__.py").write_text("", encoding="utf-8")
    (root / "src/overseer/codex_dispatch_activation.py").write_text(
        "def authorize_isolated_activation_entry(_digest): return None\n",
        encoding="utf-8",
    )
    (root / "src/overseer/cli.py").write_text(
        "import cryptography, pydantic, starlette\ndef main(_argv): return 0\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='1'\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(root)), check=True)
    subprocess.run(("git", "-C", str(root), "add", "src", "pyproject.toml"), check=True)
    subprocess.run(
        ("git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"),
        check=True,
    )
    inventory = tuple(sorted(
        item for item in subprocess.check_output(("git", "-C", str(root), "ls-files", "--", "src"), text=True).splitlines()
        if item.endswith((".py", ".pyc"))
    ))
    module_hasher = hashlib.sha256()
    for relative in inventory:
        module_hasher.update(relative.encode() + b"\0" + (root / relative).read_bytes())
    commit = subprocess.check_output(("git", "-C", str(root), "rev-parse", "HEAD"), text=True).strip()
    tree = subprocess.check_output(("git", "-C", str(root), "rev-parse", "HEAD^{tree}"), text=True).strip()
    module = module_hasher.hexdigest()
    review = activation._review_digest(commit, tree, module, inventory)
    site_packages = activation.SERVICE_SITE_PACKAGES
    dependency = activation._dependency_digest(site_packages)
    bootstrap_binding = {**_fixture_bootstrap_binding(), "sourceCommit": commit, "sourceTree": tree}
    spec = CodexDispatchActivationSpec(
        CODEX_DISPATCH_ACTIVATION_SCHEMA, commit, tree, module, review, dependency, source_files=inventory,
        bootstrap_binding=bootstrap_binding,
        bus_peer_binding=activation._capture_user_bus_peer_binding(),
        launcher_blob=str(bootstrap_binding["launcherBlob"]),
        launcher_sha256=str(bootstrap_binding["launcherSha256"]),
        launcher_size=int(bootstrap_binding["launcherSize"]),
    )
    arguments = [
        "/usr/bin/python3", "-I", "-S", str(launcher),
        "--source-root", str(root), "--source-commit", commit, "--source-tree", tree,
        "--source-module", module, "--review-digest", review,
        "--spec-digest", activation.codex_dispatch_activation_plan_digest(spec),
        "--dependency-digest", dependency, "--bootstrap-binding", activation._canonical(spec.bootstrap_binding),
        "--bus-peer-binding", activation._canonical(spec.bus_peer_binding),
        "--launcher-blob", spec.launcher_blob, "--launcher-sha256", spec.launcher_sha256,
        "--launcher-size", str(spec.launcher_size),
        "--site-packages", str(site_packages), "probe",
    ]
    return launcher, arguments


def test_isolated_launcher_blocks_transient_sitecustomize_and_sourceless_pyc(tmp_path: Path):
    _, arguments = _isolated_probe_fixture(tmp_path)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    sentinel = tmp_path / "executed"
    transient = attacker / "sitecustomize.py"
    transient.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\nPath(__file__).unlink()\n",
        encoding="utf-8",
    )
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONPATH": str(attacker)}
    clean = subprocess.run(arguments, capture_output=True, text=True, check=False, env=environment)
    assert clean.returncode == 0, clean.stderr
    assert transient.exists()
    assert not sentinel.exists()

    site_packages = activation.SERVICE_SITE_PACKAGES
    service = arguments[:-1] + [
        "service", "--",
        "serve-api", "--store", str(activation.SERVICE_STORE), "--host", "127.0.0.1", "--port", "8766",
        "--auth-token-file", str(activation.SERVICE_TOKEN),
        "--human-approval-token-file", str(activation.SERVICE_HUMAN_APPROVAL_TOKEN),
        "--human-approval-identity", "sisko",
    ]
    imported = subprocess.run(service, capture_output=True, text=True, check=False, env=environment)
    assert imported.returncode == 0, imported.stderr

    root = Path(arguments[arguments.index("--source-root") + 1])
    malicious_source = tmp_path / "sitecustomize-source.py"
    malicious_source.write_text(f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('pyc')\n", encoding="utf-8")
    py_compile.compile(str(malicious_source), cfile=str(root / "src/sitecustomize.pyc"), doraise=True)
    malicious_source.unlink()
    rejected = subprocess.run(arguments, capture_output=True, text=True, check=False, env=environment)
    assert rejected.returncode != 0
    assert "untracked executable Python" in rejected.stderr
    assert not sentinel.exists()


def test_isolated_launcher_rejects_dependency_injection_before_import(tmp_path: Path):
    _, arguments = _isolated_probe_fixture(tmp_path)
    dependency_root = tmp_path / "reviewed-dependencies"
    dependency_root.mkdir(mode=0o700)
    dependency_module = dependency_root / "allowed.py"
    dependency_module.write_text("VALUE = 1\n", encoding="utf-8")
    dependency_module.chmod(0o600)
    dependency_digest = activation._dependency_digest(dependency_root)
    source_root = Path(arguments[arguments.index("--source-root") + 1])
    inventory = tuple(sorted(
        item for item in subprocess.check_output(
            ("git", "-C", str(source_root), "ls-files", "--", "src"), text=True,
        ).splitlines() if item.endswith(activation.SOURCE_EXECUTABLE_SUFFIXES)
    ))
    bootstrap_binding = {**_fixture_bootstrap_binding(),
         "sourceCommit": arguments[arguments.index("--source-commit") + 1],
         "sourceTree": arguments[arguments.index("--source-tree") + 1]}
    spec = CodexDispatchActivationSpec(
        CODEX_DISPATCH_ACTIVATION_SCHEMA,
        arguments[arguments.index("--source-commit") + 1],
        arguments[arguments.index("--source-tree") + 1],
        arguments[arguments.index("--source-module") + 1],
        arguments[arguments.index("--review-digest") + 1],
        dependency_digest,
        bootstrap_binding,
        activation._capture_user_bus_peer_binding(),
        str(bootstrap_binding["launcherBlob"]), str(bootstrap_binding["launcherSha256"]),
        int(bootstrap_binding["launcherSize"]),
        source_files=inventory,
    )
    arguments[arguments.index("--site-packages") + 1] = str(dependency_root)
    arguments[arguments.index("--dependency-digest") + 1] = dependency_digest
    arguments[arguments.index("--spec-digest") + 1] = activation.codex_dispatch_activation_plan_digest(spec)
    injected = dependency_root / "injected.cpython-313-x86_64-linux-gnu.so"
    injected.write_bytes(b"not executable")
    injected.chmod(0o600)
    completed = subprocess.run(arguments, capture_output=True, text=True, check=False, env={
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
    })
    assert completed.returncode != 0
    assert "dependency digest changed" in completed.stderr


def test_plan_rejects_review_digest_or_metadata_drift():
    plan = _plan()
    validate_codex_dispatch_activation_plan(plan)
    with pytest.raises(ValueError, match="digest"):
        validate_codex_dispatch_activation_plan(replace(plan, adapter_metadata={**plan.adapter_metadata, "specDigest": "e" * 64}))
    raw = dict(plan.adapter_metadata["spec"])
    raw["reviewDigest"] = "e" * 64
    with pytest.raises(ValueError, match="review digest"):
        validate_codex_dispatch_activation_plan(replace(plan, adapter_metadata={"spec": raw, "specDigest": "e" * 64}))


def test_marker_rejects_mutation_before_source_binding(monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    marker = plan.steps[0].command
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: (_ for _ in ()).throw(ValueError("source rejected")))
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    code, out, err = execute_codex_dispatch_activation_marker(marker)
    assert code == 1
    assert not out
    assert "source rejected" in err
    assert calls == []


def test_marker_bootstrap_proves_remote_control_contract(monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "EUID_HOME", Path("/tmp") / f"codex-dispatch-bootstrap-{id(plan)}")
    monkeypatch.setattr(activation, "CODEX_HOME", activation.EUID_HOME / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(
        activation,
        "_bootstrap_state",
        lambda: activation._BootstrapState(False, False, None, "not-running"),
    )
    calls: list[tuple[str, ...]] = []

    def run_checked(command, **_kwargs):
        calls.append(tuple(command))
        return _bootstrap_output() if command[-1] == "bootstrap" else _remote_disabled_output()

    monkeypatch.setattr(activation, "_run_checked", run_checked)
    code, out, err = execute_codex_dispatch_activation_marker(plan.steps[0].command)
    assert code == 0, err
    assert out == "daemon bootstrapped without remote control"
    assert calls == [("codex", "app-server", "daemon", "bootstrap"), ("codex", "app-server", "daemon", "disable-remote-control")]


def test_daemon_contract_accepts_real_valid_payload_and_rejects_socket_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    payload = json.dumps({
        "cliVersion": "0.147.0",
        "daemonVersion": "0.147.0",
        "state": "running",
        "remoteControlEnabled": False,
        "socketPath": str(tmp_path / ".codex" / "app-server-control/app-server-control.sock"),
    })
    assert activation._daemon_contract(payload)["remoteControlEnabled"] is False
    with pytest.raises(ValueError, match="remote control|socket"):
        activation._daemon_contract(payload.replace("app-server-control.sock", "wrong.sock"))


def test_existing_exact_dropin_requires_private_single_link_regular_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    drop_in, _, _, _ = activation._paths()
    drop_in.parent.mkdir(parents=True)
    drop_in.parent.chmod(0o700)
    drop_in.write_bytes(activation.DROP_IN_CONTENT)
    drop_in.chmod(0o600)
    assert activation._install_drop_in(plan.id, plan.steps[0].command[2]) == "exact owner-only service drop-in already present"
    assert activation._load_journal(plan.id, plan.steps[0].command[2])["dropInOwnership"] == "preexisting"
    drop_in.unlink()
    target = tmp_path / "target.conf"
    target.write_bytes(activation.DROP_IN_CONTENT)
    target.chmod(0o600)
    drop_in.symlink_to(target)
    with pytest.raises(ValueError, match="regular|owner-only"):
        activation._install_drop_in(plan.id, plan.steps[0].command[2])
    drop_in.unlink()
    drop_in.write_bytes(activation.DROP_IN_CONTENT)
    drop_in.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        activation._install_drop_in(plan.id, plan.steps[0].command[2])
    drop_in.chmod(0o600)
    hardlink = tmp_path / "hardlink.conf"
    hardlink.hardlink_to(drop_in)
    with pytest.raises(ValueError, match="single-link"):
        activation._install_drop_in(plan.id, plan.steps[0].command[2])


def test_secure_dropin_read_rejects_path_replacement_after_fd_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "drop-in.conf"
    path.write_bytes(activation.DROP_IN_CONTENT)
    path.chmod(0o600)
    original_read = activation.os.read
    replaced = False

    def replacing_read(fd, size):
        nonlocal replaced
        data = original_read(fd, size)
        if not replaced:
            replaced = True
            replacement = tmp_path / "replacement.conf"
            replacement.write_bytes(activation.DROP_IN_CONTENT)
            replacement.chmod(0o600)
            path.rename(tmp_path / "old.conf")
            replacement.rename(path)
        return data

    monkeypatch.setattr(activation.os, "read", replacing_read)
    with pytest.raises(ValueError, match="changed during"):
        activation._secure_read_exact(path, activation.DROP_IN_CONTENT)


def test_secure_dropin_read_rejects_in_place_rewrite_between_double_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "drop-in.conf"
    path.write_bytes(activation.DROP_IN_CONTENT)
    path.chmod(0o600)
    original_read = activation.os.read
    rewritten = False

    def rewriting_read(fd, size):
        nonlocal rewritten
        data = original_read(fd, size)
        if not rewritten:
            rewritten = True
            with path.open("r+b") as stream:
                stream.seek(0)
                stream.write(b"X" * len(activation.DROP_IN_CONTENT))
                stream.flush()
                os.fsync(stream.fileno())
        return data

    monkeypatch.setattr(activation.os, "read", rewriting_read)
    with pytest.raises(ValueError, match="changed during|stable"):
        activation._secure_read_exact(path, activation.DROP_IN_CONTENT)


def test_activation_lock_rejects_symlink_and_unsafe_mode_without_chmod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    _, _, lock, _ = activation._paths()
    lock.parent.mkdir(parents=True, mode=0o700)
    target = tmp_path / "target.lock"
    target.write_text("keep", encoding="utf-8")
    target.chmod(0o644)
    lock.symlink_to(target)
    with pytest.raises(OSError):
        with activation._activation_lock():
            pass
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    lock.unlink()
    lock.write_text("", encoding="utf-8")
    lock.chmod(0o666)
    with pytest.raises(ValueError, match="owner-only"):
        with activation._activation_lock():
            pass
    assert stat.S_IMODE(lock.stat().st_mode) == 0o666
    lock.chmod(0o600)
    hardlink = tmp_path / "hardlink.lock"
    hardlink.hardlink_to(lock)
    with pytest.raises(ValueError, match="private"):
        with activation._activation_lock():
            pass


def test_activation_lock_detects_replacement_and_keeps_second_owner_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    _, _, lock, _ = activation._paths()
    replaced = lock.with_name("replaced.lock")
    with pytest.raises(ValueError, match="changed|replaced"):
        with activation._activation_lock() as validate_lock:
            lock.rename(replaced)
            lock.write_bytes(b"")
            lock.chmod(0o600)
            with pytest.raises(RuntimeError, match="already running"):
                with activation._activation_lock():
                    pass
            validate_lock()


def test_activation_lock_acquires_stable_runtime_anchor_before_local_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    events: list[str] = []

    @contextmanager
    def runtime_anchor():
        events.append("runtime-enter")
        yield lambda: events.append("runtime-validate")
        events.append("runtime-exit")

    monkeypatch.setattr(activation, "_runtime_anchor_lock", runtime_anchor, raising=False)
    with activation._activation_lock() as validate:
        events.append("body")
        validate()
    assert events[0] == "runtime-enter"
    assert events[-1] == "runtime-exit"
    assert events.count("runtime-validate") >= 2


def test_journal_secure_read_rejects_symlink_and_unknown_enums(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    digest = plan.steps[0].command[2]
    value = activation._journal(plan.id, digest)
    activation._write_journal(value)
    _, journal, _, _ = activation._paths()
    real = tmp_path / "real-journal.json"
    journal.rename(real)
    journal.symlink_to(real)
    with pytest.raises((OSError, ValueError)):
        activation._load_journal(plan.id, digest)
    journal.unlink()
    value["phase"] = "invented"
    activation._atomic_write(journal, (activation._canonical(value) + "\n").encode())
    with pytest.raises(ValueError, match="phase"):
        activation._load_journal(plan.id, digest)
    journal.chmod(0o644)
    with pytest.raises(ValueError, match="owner-only"):
        activation._load_journal(plan.id, digest)


def test_environment_verification_preserves_existing_variables(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: _busctl_environment(
        "PATH=/usr/bin", "OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "OTHER=ok",
    ))
    activation._verify_environment()
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: _busctl_environment(
        "OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "OVERSEER_CODEX_APP_SERVER_DISPATCH=1",
    ))
    with pytest.raises(ValueError, match="exactly one"):
        activation._verify_environment()


def test_environment_verification_requires_effective_isolated_execstart(monkeypatch: pytest.MonkeyPatch):
    spec = _spec()
    command = activation._isolated_launcher_command(
        spec,
        "service",
        (
            "serve-api", "--store", str(activation.SERVICE_STORE), "--host", "127.0.0.1", "--port", "8766",
            "--auth-token-file", str(activation.SERVICE_TOKEN),
            "--human-approval-token-file", str(activation.SERVICE_HUMAN_APPROVAL_TOKEN),
            "--human-approval-identity", "sisko",
        ),
    )

    def checked(command_args, **_kwargs):
        if any("ExecStart" in item for item in command_args):
            return _busctl_execstart(command)
        return _busctl_environment("OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "PYTHONPATH=", "OTHER=ok")

    monkeypatch.setattr(activation, "_run_checked", checked)
    activation._verify_environment(spec)
    monkeypatch.setattr(
        activation,
        "_run_checked",
        lambda command_args, **_kwargs: (
            _busctl_execstart(("/usr/bin/python3", "-m", "overseer.cli"))
            if any("ExecStart" in item for item in command_args)
            else _busctl_environment("OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "PYTHONPATH=")
        ),
    )
    with pytest.raises(ValueError, match="ExecStart"):
        activation._verify_environment(spec)


def test_environment_verification_rejects_wrapper_containing_expected_tokens(monkeypatch: pytest.MonkeyPatch):
    spec = _spec()
    expected = activation._isolated_launcher_command(
        spec,
        "service",
        (
            "serve-api", "--store", str(activation.SERVICE_STORE), "--host", "127.0.0.1", "--port", "8766",
            "--auth-token-file", str(activation.SERVICE_TOKEN),
            "--human-approval-token-file", str(activation.SERVICE_HUMAN_APPROVAL_TOKEN),
            "--human-approval-identity", "sisko",
        ),
    )

    def checked(command_args, **_kwargs):
        if any("ExecStart" in item for item in command_args):
            evil = ["/bin/sh", "-c", " ".join(expected)]
            return _busctl_execstart(tuple(evil), path="/bin/sh")
        return _busctl_environment("OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "PYTHONPATH=")

    monkeypatch.setattr(activation, "_run_checked", checked)
    with pytest.raises(ValueError, match="ExecStart"):
        activation._verify_environment(spec)


def test_restart_rejects_alternate_effective_execstart_before_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    spec = _spec()
    expected = activation._isolated_launcher_command(
        spec,
        "service",
        (
            "serve-api", "--store", str(activation.SERVICE_STORE), "--host", "127.0.0.1", "--port", "8766",
            "--auth-token-file", str(activation.SERVICE_TOKEN),
            "--human-approval-token-file", str(activation.SERVICE_HUMAN_APPROVAL_TOKEN),
            "--human-approval-identity", "sisko",
        ),
    )
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(activation, "_revalidate_journal_drop_in", lambda *_args: None)
    calls: list[tuple[str, ...]] = []

    def checked(command_args, **_kwargs):
        calls.append(tuple(command_args))
        if any("ExecStart" in item for item in command_args):
            return _busctl_execstart(("/bin/sh", "-c", " ".join(expected)), path="/bin/sh")
        return _busctl_environment("OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "PYTHONPATH=")

    monkeypatch.setattr(activation, "_run_checked", checked)
    code, _, error = execute_codex_dispatch_activation_marker(plan.steps[4].command)
    assert code == 1
    assert "ExecStart" in error
    assert ("/usr/bin/systemctl", "--user", "restart", activation.SERVICE_NAME) not in calls


@pytest.mark.parametrize("payload", [
    "not-json",
    json.dumps({"type": "wrong", "data": []}),
    json.dumps({"type": "as", "data": [], "extra": True}),
    json.dumps({"type": "as", "data": [1]}),
])
def test_busctl_environment_contract_rejects_text_wrong_types_and_extras(payload: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: payload)
    with pytest.raises((ValueError, json.JSONDecodeError)):
        activation._verify_environment()


def test_busctl_uses_exact_fixed_service_property_contract(monkeypatch: pytest.MonkeyPatch):
    spec = _spec()
    expected = activation._isolated_launcher_command(
        spec, "service", (
            "serve-api", "--store", str(activation.SERVICE_STORE), "--host", "127.0.0.1", "--port", "8766",
            "--auth-token-file", str(activation.SERVICE_TOKEN),
            "--human-approval-token-file", str(activation.SERVICE_HUMAN_APPROVAL_TOKEN),
            "--human-approval-identity", "sisko",
        ),
    )
    calls: list[tuple[str, ...]] = []

    def checked(command, **_kwargs):
        calls.append(tuple(command))
        return (_busctl_execstart(expected) if command[-1] == "ExecStart"
                else _busctl_environment("OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "PYTHONPATH="))

    monkeypatch.setattr(activation, "_run_checked", checked)
    activation._verify_environment(spec)
    prefix = (
        activation.BUSCTL, f"--address={activation.USER_BUS_ADDRESS}", "--json=short", "get-property", activation.SYSTEMD_BUS_NAME,
        activation.SERVICE_OBJECT, activation.SERVICE_INTERFACE,
    )
    assert calls == [(*prefix, "Environment"), (*prefix, "ExecStart")]


def test_user_bus_socket_validation_rejects_missing_wrong_type_and_replacement(tmp_path: Path):
    tmp_path.chmod(0o700)
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileNotFoundError):
            activation._validate_user_bus_socket(directory_fd)
        (tmp_path / "bus").write_text("not a socket", encoding="utf-8")
        with pytest.raises(ValueError, match="socket"):
            activation._validate_user_bus_socket(directory_fd)
        (tmp_path / "bus").unlink()
        first_socket = socket.socket(socket.AF_UNIX)
        first_socket.bind(str(tmp_path / "bus"))
        binding = activation._validate_user_bus_socket(directory_fd)
        (tmp_path / "bus").unlink()
        second_socket = socket.socket(socket.AF_UNIX)
        second_socket.bind(str(tmp_path / "bus"))
        try:
            with pytest.raises(ValueError, match="changed"):
                activation._validate_user_bus_socket(directory_fd, binding)
        finally:
            second_socket.close()
            first_socket.close()
    finally:
        os.close(directory_fd)


def test_fixed_address_busctl_contract_works_with_sanitized_environment():
    value = activation._read_user_bus_property("Environment", "as")
    assert isinstance(value, list)
    assert all(isinstance(item, str) for item in value)


def test_fixed_address_busctl_contract_works_under_env_i():
    command = (
        activation.BUSCTL, f"--address={activation.USER_BUS_ADDRESS}", "--json=short", "get-property",
        activation.SYSTEMD_BUS_NAME, activation.SERVICE_OBJECT, activation.SERVICE_INTERFACE, "Environment",
    )
    completed = subprocess.run(command, capture_output=True, text=True, check=False, env={})
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["type"] == "as"


def test_systemctl_runner_uses_only_fixed_validated_runtime_environment(monkeypatch: pytest.MonkeyPatch):
    peer = activation._capture_user_bus_peer_binding()
    captured: dict[str, object] = {}

    def checked(command, **kwargs):
        captured.update(command=tuple(command), env=kwargs["env"])
        return "active"

    monkeypatch.setattr(activation, "_run_checked", checked)
    assert activation._run_user_systemctl(("is-active", activation.SERVICE_NAME), peer) == "active"
    assert captured["command"] == ("/usr/bin/systemctl", "--user", "is-active", activation.SERVICE_NAME)
    assert captured["env"] == {
        **activation._safe_env(), "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
    }
    assert "DBUS_SESSION_BUS_ADDRESS" not in captured["env"]


def test_systemctl_read_only_probe_works_with_fixed_runtime_environment():
    peer = activation._capture_user_bus_peer_binding()
    assert activation._run_user_systemctl(("is-active", activation.SERVICE_NAME), peer) == "active"


@pytest.mark.parametrize("message", ["missing runtime directory", "fake runtime directory"])
def test_systemctl_rejects_missing_or_fake_runtime_anchor_before_command(
    message: str, monkeypatch: pytest.MonkeyPatch,
):
    peer = _spec().bus_peer_binding
    @contextmanager
    def rejected(**_kwargs):
        raise ValueError(message)
        yield

    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_validated_user_bus", rejected)
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "")
    with pytest.raises(ValueError, match=message):
        activation._run_user_systemctl(("is-active", activation.SERVICE_NAME), peer)
    assert calls == []


def test_systemctl_failure_revalidates_peer_on_exception(monkeypatch: pytest.MonkeyPatch):
    validations: list[str] = []
    peer = _spec().bus_peer_binding

    @contextmanager
    def validated(**_kwargs):
        def validate():
            validations.append("validated")
        yield validate

    monkeypatch.setattr(activation, "_validated_user_bus", validated)
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("failed")))
    with pytest.raises(RuntimeError, match="failed"):
        activation._run_user_systemctl(("daemon-reload",), peer)
    assert len(validations) == 2


def test_same_euid_fake_user_bus_peer_is_rejected():
    first, second = socket.socketpair(socket.AF_UNIX)
    try:
        with pytest.raises(ValueError, match="systemd user manager"):
            activation._validate_user_bus_peer(first)
    finally:
        first.close()
        second.close()


def test_live_staged_spec_captures_exact_current_user_manager_identity():
    binding = activation._capture_user_bus_peer_binding()
    assert binding["peerUid"] == os.geteuid()
    assert binding["peerGid"] == os.getegid()
    assert binding["ppid"] == 1
    assert binding["argv"] == ["/usr/lib/systemd/systemd", "--user"]


@pytest.mark.parametrize("field,replacement", [
    ("peerPid", 999999),
    ("startTicks", 1),
    ("bootId", "00000000-0000-0000-0000-000000000000"),
])
def test_approved_user_manager_pid_starttick_and_boot_drift_reject_before_busctl(
    field: str, replacement: object, monkeypatch: pytest.MonkeyPatch,
):
    expected = activation._capture_user_bus_peer_binding()
    expected[field] = replacement
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "")
    with pytest.raises(ValueError, match="approved staged identity"):
        activation._read_user_bus_property("Environment", "as", expected)
    assert calls == []


@pytest.mark.parametrize("bad_field", [True, -1, 2**64])
def test_busctl_execstart_contract_rejects_invalid_runtime_field_types(bad_field: object, monkeypatch: pytest.MonkeyPatch):
    spec = _spec()
    expected = activation._isolated_launcher_command(
        spec, "service", (
            "serve-api", "--store", str(activation.SERVICE_STORE), "--host", "127.0.0.1", "--port", "8766",
            "--auth-token-file", str(activation.SERVICE_TOKEN),
            "--human-approval-token-file", str(activation.SERVICE_HUMAN_APPROVAL_TOKEN),
            "--human-approval-identity", "sisko",
        ),
    )
    invalid = json.loads(_busctl_execstart(expected))
    invalid["data"][0][3] = bad_field
    monkeypatch.setattr(
        activation, "_run_checked",
        lambda command, **_kwargs: json.dumps(invalid) if command[-1] == "ExecStart"
        else _busctl_environment("OVERSEER_CODEX_APP_SERVER_DISPATCH=1", "PYTHONPATH="),
    )
    with pytest.raises(ValueError, match="ExecStart"):
        activation._verify_environment(spec)


def test_preexisting_invalid_daemon_is_not_started_or_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    _, _, _, socket_path = activation._paths()
    socket_path.parent.mkdir(parents=True)
    socket_path.write_bytes(b"existing-invalid")
    monkeypatch.setattr(activation, "_daemon_status", lambda: (_ for _ in ()).throw(ValueError("invalid preexisting daemon")))
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[1].command)
    assert code == 1
    assert "invalid preexisting" in err
    assert not any(command[-1:] == ("start",) for command in calls)
    assert not any(command[-1:] == ("stop",) for command in calls)


def test_genuine_preexisting_valid_daemon_is_not_owned_by_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(activation, "_daemon_status", lambda: "running-valid")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[1].command)
    assert code == 0, err
    assert activation._load_journal(plan.id, plan.steps[1].command[2])["daemonOwnership"] == "preexisting"
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert not any(command[-1:] == ("stop",) for command in calls)


def test_start_crash_after_effect_is_reconciled_from_intent_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(activation, "_daemon_status", lambda: "not-running")
    original = activation._run_checked

    def crash_after_start(command, **kwargs):
        if tuple(command) == ("codex", "app-server", "daemon", "start"):
            _, _, _, socket_path = activation._paths()
            socket_path.parent.mkdir(parents=True, exist_ok=True)
            socket_path.write_bytes(b"running")
            raise RuntimeError("crash after daemon effect")
        return original(command, **kwargs)

    monkeypatch.setattr(activation, "_run_checked", crash_after_start)
    plan = _plan()
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[1].command)
    assert code == 1
    assert "crash after daemon effect" in err
    journal = activation._load_journal(plan.id, plan.steps[1].command[2])
    assert journal["phase"] == "intent-start"
    assert journal["daemonOwnership"] == "start-issued"
    monkeypatch.setattr(activation, "_daemon_status", lambda: "running-valid")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    retry_code, _, retry_err = execute_codex_dispatch_activation_marker(plan.steps[1].command)
    assert retry_code == 0, retry_err
    assert activation._load_journal(plan.id, plan.steps[1].command[2])["daemonOwnership"] == "started-by-operation"
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert ("codex", "app-server", "daemon", "stop") in calls


def test_drop_in_crash_after_write_is_reconciled_from_intent_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    original = activation._publish_drop_in_noreplace

    def crash_after_dropin(path, content=activation.DROP_IN_CONTENT):
        original(path, content)
        raise RuntimeError("crash after drop-in effect")

    monkeypatch.setattr(activation, "_publish_drop_in_noreplace", crash_after_dropin)
    plan = _plan()
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[2].command)
    assert code == 1
    assert "crash after drop-in effect" in err
    drop_in, _, _, _ = activation._paths()
    assert drop_in.exists()
    journal = activation._load_journal(plan.id, plan.steps[2].command[2])
    assert journal["phase"] == "intent-drop-in"
    assert journal["dropInOwnership"] == "write-issued"
    monkeypatch.setattr(activation, "_publish_drop_in_noreplace", original)
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    retry_code, _, retry_err = execute_codex_dispatch_activation_marker(plan.steps[2].command)
    assert retry_code == 0, retry_err
    assert activation._load_journal(plan.id, plan.steps[2].command[2])["dropInOwnership"] == "created-by-operation"
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert not drop_in.exists()


def test_retry_owned_resources_are_rolled_back_after_later_verification_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    plan = _approved_plan()
    state = {"daemon_running": False, "configured": False, "updater": False, "remote": None}

    def daemon_status():
        return "running-valid" if state["daemon_running"] else "not-running"

    monkeypatch.setattr(activation, "_daemon_status", daemon_status)
    monkeypatch.setattr(
        activation,
        "_bootstrap_state",
        lambda: activation._BootstrapState(
            state["configured"], state["updater"], state["remote"], daemon_status()
        ),
    )

    def run_checked(command, **_kwargs):
        command = tuple(command)
        if command[-1:] == ("bootstrap",):
            state.update(daemon_running=True, configured=True, updater=True, remote=False)
            return _bootstrap_output()
        if command[-1:] == ("disable-remote-control",):
            return _remote_disabled_output()
        if command[-1:] == ("start",):
            state["daemon_running"] = True
        elif command[-1:] == ("stop",):
            state["daemon_running"] = False
        return "ok"

    monkeypatch.setattr(activation, "_run_checked", run_checked)

    def runner(step):
        if step.title == "Verify daemon version":
            return AdminCommandResult(step.title, step.command, 1, stderr="verification injected failure")
        code, stdout, stderr = execute_codex_dispatch_activation_marker(step.command)
        return AdminCommandResult(step.title, step.command, code, stdout, stderr)

    result = execute_codex_dispatch_activation_plan(plan, runner=runner, adapter_enabled=True)
    assert result.status.value == "failed"
    drop_in, _, _, _ = activation._paths()
    journal = activation._load_journal(plan.id, plan.steps[0].command[2])
    assert not drop_in.exists()
    assert state["daemon_running"] is False
    assert journal["phase"] == "rollback-pending"
    assert journal["dropInOwnership"] == "quarantined"
    assert Path(str(journal["dropInQuarantinePath"])).exists()
    assert journal["daemonOwnership"] == "stopped"
    assert journal["bootstrapOwnership"] == "residual"


def test_bootstrap_crash_retry_reconciles_and_rollback_reports_residual(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    state = {"configured": False, "updater": False, "remote": None, "daemon": False}

    def bootstrap_state():
        return activation._BootstrapState(
            state["configured"], state["updater"], state["remote"],
            "running-valid" if state["daemon"] else "not-running",
        )

    monkeypatch.setattr(activation, "_bootstrap_state", bootstrap_state)
    monkeypatch.setattr(
        activation,
        "_daemon_status",
        lambda: "running-valid" if state["daemon"] else "not-running",
    )

    def crash_after_bootstrap(command, **_kwargs):
        if tuple(command)[-1:] == ("bootstrap",):
            state.update(configured=True, updater=True, remote=False, daemon=True)
            raise RuntimeError("crash after bootstrap effect")
        return _remote_disabled_output()

    monkeypatch.setattr(activation, "_run_checked", crash_after_bootstrap)
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[0].command)
    assert code == 1
    assert "crash after bootstrap effect" in err
    journal = activation._load_journal(plan.id, plan.steps[0].command[2])
    assert journal["phase"] == "intent-bootstrap"
    assert journal["bootstrapOwnership"] == "bootstrap-issued"
    calls: list[tuple[str, ...]] = []

    def after_crash(command, **_kwargs):
        command = tuple(command)
        calls.append(command)
        if command[-1:] == ("stop",):
            state["daemon"] = False
        return "ok"

    monkeypatch.setattr(activation, "_run_checked", after_crash)
    retry_code, retry_out, retry_err = execute_codex_dispatch_activation_marker(plan.steps[0].command)
    assert retry_code == 0, retry_err
    assert "reconciled" in retry_out
    assert not calls
    rollback_code, _, rollback_err = execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)
    assert rollback_code == 1
    assert "residual bootstrap" in rollback_err
    journal = activation._load_journal(plan.id, plan.steps[0].command[2])
    assert journal["phase"] == "rollback-pending"
    assert journal["bootstrapOwnership"] == "residual"
    assert journal["daemonOwnership"] == "stopped"
    assert ("codex", "app-server", "daemon", "stop") in calls


def test_genuine_preexisting_bootstrap_and_disabled_remote_state_are_preserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(
        activation,
        "_bootstrap_state",
        lambda: activation._BootstrapState(True, True, False, "running-valid"),
    )
    calls: list[tuple[str, ...]] = []

    def run_checked(command, **_kwargs):
        command = tuple(command)
        calls.append(command)
        if command[-1:] == ("bootstrap",):
            return _bootstrap_output()
        if command[-1:] == ("disable-remote-control",):
            return _remote_disabled_output()
        return "ok"

    monkeypatch.setattr(activation, "_run_checked", run_checked)
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[0].command)
    assert code == 0, err
    journal = activation._load_journal(plan.id, plan.steps[0].command[2])
    assert journal["bootstrapOwnership"] == "preexisting"
    assert journal["remoteControlOwnership"] == "preexisting-disabled"
    assert journal["daemonOwnership"] == "preexisting"
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert not any(command[-1:] == ("stop",) for command in calls)


def test_stop_failure_keeps_retryable_rollback_phase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    spec = CodexDispatchActivationSpec.from_json(plan.adapter_metadata["spec"])
    activation._write_journal(activation._journal(
        plan.id, plan.steps[0].command[2], "started", spec=spec, daemonOwnership="started-by-operation",
    ))
    monkeypatch.setattr(activation, "_daemon_status", lambda: "running-valid")
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: (_ for _ in ()).throw(RuntimeError("stop failed")) if tuple(command)[-1:] == ("stop",) else "ok")
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 1
    assert activation._load_journal(plan.id, plan.steps[0].command[2])["phase"] == "rollback-pending"
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert activation._load_journal(plan.id, plan.steps[0].command[2])["phase"] == "rolled-back"


def test_disabled_adapter_gate_does_not_run_commands(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    called = False

    def runner(_step):
        nonlocal called
        called = True
        return AdminCommandResult("unexpected", (), 0)

    result = execute_codex_dispatch_activation_plan(_approved_plan(), runner=runner)
    assert result.status.value == "blocked"
    assert called is False


def test_runner_timeout_after_effect_is_audited_failure_with_rollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _approved_plan()
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    rolled_back = False

    def runner(step):
        nonlocal rolled_back
        if step.title == "Rollback exact dispatch drop-in":
            rolled_back = True
            return AdminCommandResult(step.title, step.command, 0, stdout="rolled back")
        if step.title == "Start local Codex app-server":
            raise subprocess.TimeoutExpired(step.command, 30)
        return AdminCommandResult(step.title, step.command, 0)

    result = execute_codex_dispatch_activation_plan(plan, runner=runner, adapter_enabled=True)
    assert result.status.value == "failed"
    assert rolled_back is True
    assert result.command_results[-1].exit_code == 1
    assert result.rollback_results[0].exit_code == 0


def test_marker_normalizes_probe_index_error(monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "_probe_proxy", lambda: (_ for _ in ()).throw(IndexError("empty response")))
    code, stdout, stderr = execute_codex_dispatch_activation_marker(plan.verification_steps[1].command)
    assert code == 1
    assert stdout == ""
    assert "activation operation failed" in stderr


def test_rollback_is_safe_when_drop_in_was_removed_and_retry_is_idempotent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    plan = _plan()
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[2].command)
    assert code == 0, err
    drop_in, journal, _, _ = activation._paths()
    installed_journal = activation._load_journal(plan.id, plan.steps[2].command[2])
    assert installed_journal["dropInDevice"] == drop_in.stat().st_dev
    assert installed_journal["dropInInode"] == drop_in.stat().st_ino
    drop_in.unlink()
    rollback = plan.rollback_steps[0].command
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 0
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 0
    assert journal.exists()
    assert calls.count(("/usr/bin/systemctl", "--user", "daemon-reload")) == 1


def test_rollback_quarantines_replacement_after_validation_without_deleting_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[2].command)
    assert code == 0, err
    drop_in, _, _, _ = activation._paths()
    replacement = drop_in.parent / "replacement.conf"
    replacement.write_bytes(activation.DROP_IN_CONTENT)
    replacement.chmod(0o600)
    saved_original = drop_in.parent / "saved-original.conf"
    original_rename = activation.os.rename
    original_noreplace = activation._rename_noreplace_at
    raced = False

    def replacing_rename(src, dst, *, dir_fd):
        nonlocal raced
        if not raced and src == drop_in.name and str(dst).startswith(f".{drop_in.name}.rollback-"):
            raced = True
            original_rename(src, saved_original.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            original_rename(replacement.name, src, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return original_noreplace(src, dst, dir_fd=dir_fd)

    monkeypatch.setattr(activation, "_rename_noreplace_at", replacing_rename)
    rollback_code, _, rollback_err = execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)
    assert rollback_code == 1
    assert "identity" in rollback_err or "changed" in rollback_err
    assert saved_original.exists()
    quarantined = list(drop_in.parent.glob(f".{drop_in.name}.rollback-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == activation.DROP_IN_CONTENT
    assert activation._load_journal(plan.id, plan.steps[0].command[2])["phase"] == "rollback-pending"


def test_normal_rollback_retains_inert_quarantine_and_never_unlinks_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    expected_drop_in = activation._drop_in_content(CodexDispatchActivationSpec.from_json(plan.adapter_metadata["spec"]))
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    assert execute_codex_dispatch_activation_marker(plan.steps[2].command)[0] == 0
    drop_in, _, _, _ = activation._paths()
    unrelated = drop_in.parent / "unrelated.txt"
    unrelated.write_text("preserve me", encoding="utf-8")
    original_unlink = activation.os.unlink

    def reject_quarantine_unlink(path, *args, **kwargs):
        if ".rollback-" in str(path):
            raise AssertionError("rollback must retain inert quarantine")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(activation.os, "unlink", reject_quarantine_unlink)
    rollback = plan.rollback_steps[0].command
    code, out, err = execute_codex_dispatch_activation_marker(rollback)
    assert code == 0, err
    assert "retained" in out
    assert not drop_in.exists()
    quarantined = list(drop_in.parent.glob(f".{drop_in.name}.rollback-*"))
    assert len(quarantined) == 1
    assert not quarantined[0].name.endswith(".conf")
    assert quarantined[0] not in list(drop_in.parent.glob("*.conf"))
    assert quarantined[0].read_bytes() == expected_drop_in
    assert unrelated.read_text(encoding="utf-8") == "preserve me"
    inode = quarantined[0].stat().st_ino
    journal = activation._load_journal(plan.id, plan.steps[0].command[2])
    assert journal["phase"] == "rolled-back"
    assert journal["dropInOwnership"] == "quarantined"
    assert journal["dropInQuarantinePath"] == str(quarantined[0])
    assert journal["dropInQuarantineInode"] == inode
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 0
    assert quarantined[0].stat().st_ino == inode


def test_rollback_never_replaces_concurrently_created_quarantine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    expected_drop_in = activation._drop_in_content(CodexDispatchActivationSpec.from_json(plan.adapter_metadata["spec"]))
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    assert execute_codex_dispatch_activation_marker(plan.steps[2].command)[0] == 0
    drop_in, _, _, _ = activation._paths()
    original_noreplace = activation._rename_noreplace_at
    unrelated = b"unrelated concurrent quarantine"

    def create_destination_before_rename(source: str, destination: str, *, dir_fd: int):
        fd = activation.os.open(
            destination,
            activation.os.O_WRONLY | activation.os.O_CREAT | activation.os.O_EXCL,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            activation.os.write(fd, unrelated)
        finally:
            activation.os.close(fd)
        return original_noreplace(source, destination, dir_fd=dir_fd)

    monkeypatch.setattr(activation, "_rename_noreplace_at", create_destination_before_rename)
    code, _, error = execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)
    assert code == 1
    assert "already exists" in error
    assert drop_in.read_bytes() == expected_drop_in
    quarantined = list(drop_in.parent.glob(f".{drop_in.name}.rollback-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == unrelated
    assert activation._load_journal(plan.id, plan.steps[0].command[2])["phase"] == "rollback-pending"


def test_rollback_retries_from_exact_quarantine_after_rename_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    plan = _plan()
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    assert execute_codex_dispatch_activation_marker(plan.steps[2].command)[0] == 0
    drop_in, _, _, _ = activation._paths()
    original_rename = activation._rename_noreplace_at
    crashed = False

    def crash_after_rename(src, dst, *, dir_fd):
        nonlocal crashed
        original_rename(src, dst, dir_fd=dir_fd)
        if not crashed and src == drop_in.name:
            crashed = True
            raise RuntimeError("crash after quarantine rename")

    monkeypatch.setattr(activation, "_rename_noreplace_at", crash_after_rename)
    rollback = plan.rollback_steps[0].command
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 1
    assert not drop_in.exists()
    assert len(list(drop_in.parent.glob(f".{drop_in.name}.rollback-*"))) == 1
    monkeypatch.setattr(activation, "_rename_noreplace_at", original_rename)
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 0
    quarantined = list(drop_in.parent.glob(f".{drop_in.name}.rollback-*"))
    assert len(quarantined) == 1
    inode = quarantined[0].stat().st_ino
    journal = activation._load_journal(plan.id, plan.steps[0].command[2])
    assert journal["phase"] == "rolled-back"
    assert journal["dropInOwnership"] == "quarantined"
    assert journal["dropInQuarantinePath"] == str(quarantined[0])
    assert journal["dropInQuarantineInode"] == inode
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 0
    assert quarantined[0].stat().st_ino == inode


def test_rolled_back_approved_plan_is_terminal_before_any_effect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    plan = _approved_plan()
    spec = CodexDispatchActivationSpec.from_json(plan.adapter_metadata["spec"])
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    digest = plan.steps[0].command[2]
    assert activation._install_drop_in(plan.id, digest, spec) == "exact owner-only service drop-in installed"
    assert activation._rollback(plan.id, digest, spec).startswith("exact Codex dispatch activation rolled back")
    drop_in, _, _, _ = activation._paths()
    journal_before = activation._load_journal(plan.id, digest)
    quarantine = Path(str(journal_before["dropInQuarantinePath"]))
    assert not drop_in.exists()
    assert quarantine.exists()
    effects: list[str] = []

    def runner(step):
        effects.append(step.title)
        return AdminCommandResult(step.title, step.command, 0)

    result = execute_codex_dispatch_activation_plan(plan, runner=runner, adapter_enabled=True)
    assert result.status.value == "blocked"
    assert "terminal" in result.summary or "rolled back" in result.summary
    assert effects == []
    assert not drop_in.exists()
    assert quarantine.exists()


def test_install_never_overwrites_concurrent_mismatched_drop_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    drop_in, _, _, _ = activation._paths()
    raced = False

    def concurrent_publish(_source_fd: int, destination: str, *, dir_fd: int):
        nonlocal raced
        if destination == drop_in.name and not raced:
            raced = True
            fd = activation.os.open(
                destination,
                activation.os.O_WRONLY | activation.os.O_CREAT | activation.os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            try:
                activation.os.write(fd, b"[Service]\nEnvironment=UNREVIEWED=1\n")
            finally:
                activation.os.close(fd)
        raise FileExistsError("concurrent drop-in")

    monkeypatch.setattr(activation, "_link_fd_noreplace_at", concurrent_publish, raising=False)
    with pytest.raises(ValueError, match="reviewed|concurrent|content"):
        activation._install_drop_in(plan.id, plan.steps[0].command[2])
    assert drop_in.read_bytes() == b"[Service]\nEnvironment=UNREVIEWED=1\n"


def test_install_accepts_concurrent_exact_drop_in_only_as_preexisting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    drop_in, _, _, _ = activation._paths()

    def concurrent_publish(_source_fd: int, destination: str, *, dir_fd: int):
        fd = activation.os.open(
            destination,
            activation.os.O_WRONLY | activation.os.O_CREAT | activation.os.O_EXCL,
            0o600,
            dir_fd=dir_fd,
        )
        try:
            activation.os.write(fd, activation.DROP_IN_CONTENT)
        finally:
            activation.os.close(fd)
        raise FileExistsError("concurrent exact drop-in")

    monkeypatch.setattr(activation, "_link_fd_noreplace_at", concurrent_publish)
    result = activation._install_drop_in(plan.id, plan.steps[0].command[2])
    assert result == "exact owner-only service drop-in concurrently present"
    assert drop_in.read_bytes() == activation.DROP_IN_CONTENT
    journal = activation._load_journal(plan.id, plan.steps[0].command[2])
    assert journal["dropInOwnership"] == "preexisting"
    assert journal["dropInDevice"] is None
    assert journal["dropInInode"] is None


def test_rollback_reconciles_daemon_started_by_operation_even_if_already_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    spec = CodexDispatchActivationSpec.from_json(plan.adapter_metadata["spec"])
    journal = activation._journal(
        plan.id, plan.steps[0].command[2], "started", spec=spec, daemonOwnership="started-by-operation",
    )
    activation._write_journal(journal)
    monkeypatch.setattr(activation, "_daemon_status", lambda: "running-valid")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert ("codex", "app-server", "daemon", "stop") in calls


def test_concurrent_execution_allows_only_one_owner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    entered = threading.Event()
    release = threading.Event()

    def runner(step):
        if step.title == "Bootstrap local Codex app-server":
            entered.set()
            release.wait(2)
        return AdminCommandResult(step.title, step.command, 0)

    results: list[object] = []
    first = threading.Thread(target=lambda: results.append(execute_codex_dispatch_activation_plan(_approved_plan(), runner=runner, adapter_enabled=True)))
    first.start()
    assert entered.wait(2)
    second = execute_codex_dispatch_activation_plan(_approved_plan(), runner=runner, adapter_enabled=True)
    release.set()
    first.join(2)
    assert second.status.value == "blocked"
    assert any(item.status.value == "completed" for item in results)


def test_stage_status_and_execute_persist_exact_approval_and_adapter_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from overseer import cli
    from overseer import codex_dispatch_release_activation as release
    from overseer import codex_dispatch_system_activation as system

    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    store = tmp_path / "overseer.sqlite3"
    launcher = release.ReleaseFile(
        "app/src/overseer_codex_dispatch_release_launcher.py", "checkout",
        "src/overseer_codex_dispatch_release_launcher.py", "d" * 64, 1, 0o444,
    )
    unit = "[Service]\nRestart=on-failure\n"
    manifest = release.ImmutableReleaseManifest(
        "a" * 40, "b" * 40, (launcher,),
        {"path": "/usr/bin/python3", "resolvedPath": "/usr/bin/python3.13",
         "entryDevice": 1, "entryInode": 1, "entryMode": 0o777,
         "device": 1, "inode": 2, "mode": 0o755, "links": 1,
         "sha256": "c" * 64, "size": 100},
        hashlib.sha256(unit.encode()).hexdigest(),
    )
    system_spec = system.SystemActivationSpec(
        manifest,
        {"sourceCommit": "a" * 40, "blob": "d" * 40, "sha256": "e" * 64,
         "size": 123, "path": system.ROOT_HELPER_SOURCE},
        {"bootId": "boot", "peerPid": 1329, "startTicks": 44},
        {"bootId": "boot", "pid": 99, "startTicks": 55, "cmdlineHex": "00", "cwd": "/old"},
        (), None, system.system_unit_content(manifest),
    )
    monkeypatch.setattr(cli, "build_codex_dispatch_activation_spec", lambda: system_spec)
    with system.external_activation_cli():
        staged = cli.plan_admin_change_status(
            store, "admin.codex-dispatch.e2e", AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION.value,
            "overseer-api.service", "activate reviewed dispatch", "disabled",
        )
    assert staged["approved"] is False
    approved = cli.approve_admin_change_status(store, "admin.codex-dispatch.e2e", "sisko", "2026-08-18T00:00:00+00:00")
    assert approved["approved"] is True
    with pytest.raises(ValueError, match="does not require enablement approval"):
        cli.request_admin_adapter_enablement_status(
            store,
            AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION.value,
            "sisko",
        )
    monkeypatch.setattr(system, "_reject_api_context", lambda: None)
    monkeypatch.setattr(system, "_authority_files_present", lambda _spec, _plan_id: True)
    monkeypatch.setattr(system, "verify_system_activation_spec", lambda _spec: None)
    runner = lambda step: pytest.fail(f"retired activation ran {step.command}")
    blocked = cli.execute_admin_change_status(store, "admin.codex-dispatch.e2e", runner=runner)
    assert blocked["status"] == "blocked"
    assert "retired" in blocked["summary"]
    with system.external_activation_cli():
        result = cli.execute_admin_change_status(store, "admin.codex-dispatch.e2e", runner=runner)
    assert result["status"] == "blocked"
    assert "retired" in result["summary"]
    with cli.SQLiteStore(store) as persisted:
        assert persisted.load_admin_change_plan("admin.codex-dispatch.e2e").approved is True
