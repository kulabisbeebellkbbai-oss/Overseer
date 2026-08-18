from __future__ import annotations

import json
import threading
from dataclasses import replace
from pathlib import Path

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
    return CodexDispatchActivationSpec(
        CODEX_DISPATCH_ACTIVATION_SCHEMA,
        source_commit,
        source_tree,
        source_module,
        activation._review_digest(source_commit, source_tree, source_module),
    )


def _plan() -> object:
    return plan_codex_dispatch_activation("admin.codex-dispatch.test", _spec(), "activate reviewed dispatch", "disabled")


def _approved_plan():
    return replace(_plan(), approved=True, approved_by="sisko", approved_at="2026-08-18T00:00:00+00:00")


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


def test_caller_manifest_and_source_root_cannot_supply_authority(tmp_path: Path):
    with pytest.raises(ValueError, match="not authoritative"):
        activation.codex_dispatch_activation_spec_from_private_file(tmp_path / "manifest.json")
    spec = _spec()
    assert spec.source_root == activation.CANONICAL_SOURCE_ROOT
    with pytest.raises(ValueError, match="exact keys"):
        CodexDispatchActivationSpec.from_json({**spec.to_json(), "sourceRoot": "/tmp/untrusted"})


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
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
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


def test_environment_verification_preserves_existing_variables(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "PATH=/usr/bin OVERSEER_CODEX_APP_SERVER_DISPATCH=1 OTHER=ok")
    activation._verify_environment()
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "OVERSEER_CODEX_APP_SERVER_DISPATCH=1 OVERSEER_CODEX_APP_SERVER_DISPATCH=1")
    with pytest.raises(ValueError, match="exactly one"):
        activation._verify_environment()


def test_preexisting_invalid_daemon_is_not_started_or_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    _, _, _, socket_path = activation._paths()
    socket_path.parent.mkdir(parents=True)
    socket_path.write_bytes(b"existing-invalid")
    monkeypatch.setattr(activation, "_daemon_status", lambda: (_ for _ in ()).throw(ValueError("invalid preexisting daemon")))
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    code, _, err = execute_codex_dispatch_activation_marker(_plan().steps[1].command)
    assert code == 1
    assert "invalid preexisting" in err
    assert not any(command[-1:] == ("start",) for command in calls)
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
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert ("codex", "app-server", "daemon", "stop") in calls


def test_drop_in_crash_after_write_is_reconciled_from_intent_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    original = activation._atomic_write

    def crash_after_dropin(path, content, mode=0o600):
        original(path, content, mode)
        if path.name == "10-overseer-codex-dispatch.conf":
            raise RuntimeError("crash after drop-in effect")

    monkeypatch.setattr(activation, "_atomic_write", crash_after_dropin)
    plan = _plan()
    code, _, err = execute_codex_dispatch_activation_marker(plan.steps[2].command)
    assert code == 1
    assert "crash after drop-in effect" in err
    drop_in, _, _, _ = activation._paths()
    assert drop_in.exists()
    journal = activation._load_journal(plan.id, plan.steps[2].command[2])
    assert journal["phase"] == "intent-drop-in"
    assert journal["dropInOwnership"] == "write-issued"
    monkeypatch.setattr(activation, "_atomic_write", original)
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "ok")
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert not drop_in.exists()


def test_stop_failure_keeps_retryable_rollback_phase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    activation._write_journal(activation._journal(plan.id, plan.steps[0].command[2], "started", daemonOwnership="started-by-operation"))
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
    drop_in.unlink()
    rollback = plan.rollback_steps[0].command
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 0
    assert execute_codex_dispatch_activation_marker(rollback)[0] == 0
    assert journal.exists()
    assert calls.count(("systemctl", "--user", "daemon-reload")) == 1


def test_rollback_reconciles_daemon_started_by_operation_even_if_already_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "EUID_HOME", tmp_path)
    monkeypatch.setattr(activation, "CODEX_HOME", tmp_path / ".codex")
    plan = _plan()
    journal = activation._journal(plan.id, plan.steps[0].command[2], "started", daemonOwnership="started-by-operation")
    activation._write_journal(journal)
    monkeypatch.setattr(activation, "_daemon_status", lambda: "running-valid")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    assert execute_codex_dispatch_activation_marker(plan.rollback_steps[0].command)[0] == 0
    assert ("codex", "app-server", "daemon", "stop") in calls


def test_concurrent_execution_allows_only_one_owner(monkeypatch: pytest.MonkeyPatch):
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

    store = tmp_path / "overseer.sqlite3"
    monkeypatch.setattr(cli, "build_codex_dispatch_activation_spec", _spec)
    staged = cli.plan_admin_change_status(
        store, "admin.codex-dispatch.e2e", AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION.value,
        "overseer-api.service", "activate reviewed dispatch", "disabled",
    )
    assert staged["approved"] is False
    approved = cli.approve_admin_change_status(store, "admin.codex-dispatch.e2e", "sisko", "2026-08-18T00:00:00+00:00")
    assert approved["approved"] is True
    request = cli.request_admin_adapter_enablement_status(store, AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION.value, "sisko")
    cli.approve_admin_adapter_enablement_status(store, request["approval_id"], "sisko", "2026-08-18T00:01:00+00:00")
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    runner = lambda step: AdminCommandResult(step.title, step.command, 0)
    result = cli.execute_admin_change_status(store, "admin.codex-dispatch.e2e", runner=runner)
    assert result["status"] == "completed"
    with cli.SQLiteStore(store) as persisted:
        assert persisted.load_admin_change_plan("admin.codex-dispatch.e2e").approved is True
