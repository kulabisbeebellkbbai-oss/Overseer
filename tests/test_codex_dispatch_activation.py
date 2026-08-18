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
    monkeypatch.setattr(activation, "verify_reviewed_source_binding", lambda _spec: None)
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(activation, "_run_checked", lambda command, **_kwargs: calls.append(tuple(command)) or "ok")
    code, out, err = execute_codex_dispatch_activation_marker(plan.steps[0].command)
    assert code == 0, err
    assert out == "daemon bootstrapped without remote control"
    assert calls == [("codex", "app-server", "daemon", "bootstrap"), ("codex", "app-server", "daemon", "disable-remote-control")]


def test_environment_verification_preserves_existing_variables(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "PATH=/usr/bin OVERSEER_CODEX_APP_SERVER_DISPATCH=1 OTHER=ok")
    activation._verify_environment()
    monkeypatch.setattr(activation, "_run_checked", lambda *_args, **_kwargs: "OVERSEER_CODEX_APP_SERVER_DISPATCH=1 OVERSEER_CODEX_APP_SERVER_DISPATCH=1")
    with pytest.raises(ValueError, match="exactly one"):
        activation._verify_environment()


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
    journal = activation._journal(plan.id, plan.steps[0].command[2], "started", daemonStartedByOperation=True)
    activation._write_journal(journal)
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
