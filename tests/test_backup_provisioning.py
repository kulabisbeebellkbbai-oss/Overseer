from datetime import UTC, datetime

import pytest

from overseer.backup_provisioning import AllowlistedHostProvisioningAdapter, DedicatedProvisioningAdapter, ProvisioningStep, approve_plan, build_plan, execute_plan, execute_plan_api, list_plans, stage_plan
from overseer.core import OwnerDomain, RiskLevel
from overseer.crew import CrewMessage, CrewMessageStatus, CrewReviewStatus
from overseer.store import SQLiteStore


ROLES = {"kira": OwnerDomain.KIRA, "obrien": OwnerDomain.OBRIEN, "security": OwnerDomain.ODO_IDS, "sisko": OwnerDomain.SISKO}


def seeded(tmp_path):
    path = tmp_path / "state.sqlite3"; now = datetime.now(UTC).isoformat(); evidence = {}
    with SQLiteStore(path) as store:
        for role, domain in ROLES.items():
            identifier = f"crew.{role}.backup"; evidence[role] = identifier
            store.save_crew_message(CrewMessage(identifier, domain, "Backup review", "Approved exact provisioning plan", RiskLevel.HIGH, CrewMessageStatus.ACKNOWLEDGED, domain.value, now, now, related_plan_id="backup-provision.donuthole", review_status=CrewReviewStatus.APPROVED, decided_by=domain.value, decided_at=now))
    registration = {"project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1", "host_path": "/home/god/Documents/Codex Workspace/DonutHole", "alias": "donuthole-source", "max_bytes": 1073741824, "authorization_ref": "root-auth.donuthole"}
    return str(path), build_plan("backup-provision.donuthole", "sha256:" + "a" * 64, "b" * 40, "sha256:" + "d" * 64, "sha256:" + "c" * 64, {"sha256:" + "e" * 64: "root-auth.donuthole"}, (registration,), "/run/user/1000/overseer-api-token", "/etc/codex-development-backups/keys/overseer.token", "/etc/codex-development-backups/keys/cursor.key", evidence)


def test_stage_is_immutable_and_binds_all_terminal_evidence(tmp_path):
    path, plan = seeded(tmp_path); staged = stage_plan(path, plan)
    assert staged["status"] == "staged" and staged["host_mutation_performed"] is False
    assert len(list_plans(path)["items"]) == 1
    changed = build_plan(plan.plan_id, "sha256:" + "b" * 64, plan.adapter_commit, plan.runtime_digest, plan.capability_digest, plan.root_authorization_refs, plan.root_registrations, plan.overseer_token_source_file, plan.overseer_token_file, plan.cursor_key_file, plan.evidence_ids)
    with pytest.raises(ValueError, match="immutable"):
        stage_plan(path, changed)


def test_plan_requires_exact_live_authority_inputs_and_registers_before_start(tmp_path):
    _, plan = seeded(tmp_path)
    names = [step.operation for step in plan.steps]
    assert names.index("register_authorized_roots") < names.index("start_enable_system_service")
    registration = next(step for step in plan.steps if step.operation == "register_authorized_roots")
    assert registration.arguments["tool"] == "underdark_root_register"
    assert registration.arguments["authorization_endpoint"] == "http://127.0.0.1:8766/storage/roots/verify"
    assert set(registration.arguments["registrations"][0]) == {"project_id", "root_id", "policy_revision", "host_path", "alias", "max_bytes", "authorization_ref"}
    token = next(step for step in plan.steps if step.operation == "install_overseer_api_token")
    cursor = next(step for step in plan.steps if step.operation == "generate_cursor_key")
    assert token.arguments == {"source_path": plan.overseer_token_source_file, "destination_path": plan.overseer_token_file, "mode": 0o600, "owner": "donuthole-backup", "return_value": False}
    assert cursor.arguments == {"path": plan.cursor_key_file, "mode": 0o600, "owner": "donuthole-backup", "bytes": 32, "return_value": False}
    assert names.index("install_overseer_api_token") < names.index("install_private_config") < names.index("register_authorized_roots")
    assert names.index("generate_cursor_key") < names.index("install_private_config")
    with pytest.raises(ValueError):
        build_plan(plan.plan_id, plan.gpg_sha256, plan.adapter_commit, plan.runtime_digest, plan.capability_digest, {}, plan.root_registrations, plan.overseer_token_source_file, plan.overseer_token_file, plan.cursor_key_file, plan.evidence_ids)


def test_stage_allows_pending_review_but_approval_requires_terminal_evidence(tmp_path):
    path, plan = seeded(tmp_path)
    with SQLiteStore(path) as store:
        item = store.load_crew_message(plan.evidence_ids["security"])
        store.save_crew_message(item.__class__(**{**item.__dict__, "review_status": CrewReviewStatus.PENDING, "decided_by": None, "decided_at": None}))
    assert stage_plan(path, plan)["status"] == "staged"
    with pytest.raises(ValueError, match="security"):
        approve_plan(path, plan.plan_id, "operator-human")


def test_execution_rechecks_terminal_evidence_after_approval(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan); approve_plan(path, plan.plan_id, "operator-human")
    with SQLiteStore(path) as store:
        item = store.load_crew_message(plan.evidence_ids["kira"])
        store.save_crew_message(item.__class__(**{**item.__dict__, "review_status": CrewReviewStatus.CORRECTION_REQUESTED}))
    with pytest.raises(ValueError, match="kira"):
        execute_plan(path, plan.plan_id, DedicatedProvisioningAdapter({}))


def test_sisko_and_security_dispatch_recognize_exact_backup_plan_without_admin_dispatch(tmp_path):
    from overseer.cli import _automatic_crew_review, _dispatch_odo_ids_message, _dispatch_sisko_message
    path, plan = seeded(tmp_path); stage_plan(path, plan); now = datetime.now(UTC).isoformat()
    with SQLiteStore(path) as store:
        sisko = store.load_crew_message(plan.evidence_ids["sisko"])
        security = store.load_crew_message(plan.evidence_ids["security"])
    sisko = sisko.__class__(**{**sisko.__dict__, "related_plan_id": plan.plan_id})
    security = security.__class__(**{**security.__dict__, "related_plan_id": plan.plan_id})
    sisko_result = _dispatch_sisko_message(path, sisko, "dispatcher", now)
    security_result = _dispatch_odo_ids_message(path, security, "dispatcher", now)
    assert sisko_result["status"] == "dispatched" and "admin plan" not in sisko_result["reason"]
    assert security_result["status"] == "dispatched" and "admin plan" not in security_result["reason"]
    assert sisko_result["actions"][0]["kind"] == "donuthole_encrypted_backup_provisioning_v1"
    assert security_result["actions"][0]["plan_digest"] == plan.plan_digest
    automatic = _automatic_crew_review(path, security, security_result, CrewMessageStatus.ACKNOWLEDGED, "dispatch.security", "dispatcher", now)
    assert automatic["review_status"] == CrewReviewStatus.APPROVED
    assert automatic["decided_by"] == OwnerDomain.ODO_IDS.value
    sisko_automatic = _automatic_crew_review(path, sisko, sisko_result, CrewMessageStatus.ACKNOWLEDGED, "dispatch.sisko", "dispatcher", now)
    assert sisko_automatic["review_status"] == CrewReviewStatus.APPROVED
    assert sisko_result["actions"][0]["independent_human_approval_required"] is True


def test_approval_must_be_independent_and_execution_requires_adapter(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan)
    with pytest.raises(ValueError, match="independent"):
        approve_plan(path, plan.plan_id, "sisko")
    with pytest.raises(ValueError, match="independent"):
        approve_plan(path, plan.plan_id, "kira")
    approve_plan(path, plan.plan_id, "operator-human")
    with pytest.raises(ValueError, match="adapter"):
        execute_plan(path, plan.plan_id)


def test_exact_dedicated_operations_execute_without_secret_output(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan); approve_plan(path, plan.plan_id, "operator-human")
    seen = []
    operations = {step.operation: (lambda args, operation=step.operation: seen.append((operation, args)) or {"ok": True, "secret": "must-not-return"}) for step in plan.steps}
    result = execute_plan(path, plan.plan_id, DedicatedProvisioningAdapter(operations))
    assert result["status"] == "executed" and result["host_mutation_performed"] is True
    assert [name for name, _ in seen] == [step.operation for step in plan.steps]
    assert "must-not-return" not in repr(result) and result["redactions_applied"] is True


def test_plan_has_exact_boundaries_sandbox_rollback_and_retention(tmp_path):
    _, plan = seeded(tmp_path); rendered = repr(plan)
    assert "donuthole-backup" in rendered and "/var/lib/codex-development-backups/donuthole" in rendered
    assert "ReadWritePaths" not in rendered  # structured properties, never a shell/unit text blob
    unit = next(step for step in plan.steps if step.operation == "install_systemd_unit")
    assert unit.arguments["properties"]["read_only_paths"] == (plan.source_path, plan.config_path, plan.key_path, plan.overseer_token_file, plan.cursor_key_file)
    assert unit.arguments["properties"]["read_write_paths"] == (f"{plan.backup_path}/artifacts", f"{plan.backup_path}/state")
    assert unit.arguments["properties"]["umask"] == "0077"
    assert unit.arguments["properties"]["restrict_address_families"] == ("AF_UNIX", "AF_INET")
    assert unit.arguments["properties"]["exec_start"] == ("/opt/theunderdark/.venv/bin/theunderdark-production", "serve", "--config", plan.config_path)
    assert plan.key_path == "/etc/codex-development-backups/keys/donuthole.gpg-passphrase"
    assert "load_credential" not in unit.arguments["properties"]
    key = next(step for step in plan.steps if step.operation == "generate_secret_file")
    config = next(step for step in plan.steps if step.operation == "install_private_config")
    assert key.arguments["owner"] == "donuthole-backup" and key.arguments["mode"] == 0o600
    binding = config.arguments["config"]["backup_bindings"][0]
    assert binding["passphrase_file"] == plan.key_path and binding["source_root"] == plan.source_path
    assert set(config.arguments["config"]) == {"host", "port", "state_dir", "journal_path", "admission_path", "pagination_path", "registry_path", "overseer_authorization_endpoint", "overseer_root_endpoint", "overseer_token_file", "cursor_key_file", "root_authorization_refs", "limits", "backup_bindings"}
    assert plan.retention_count == 3 and len(plan.rollback_steps) == 14


def test_adapter_rejects_unallowlisted_operation():
    adapter = DedicatedProvisioningAdapter({})
    with pytest.raises(ValueError, match="allowlisted"):
        from overseer.backup_provisioning import ProvisioningStep
        adapter.execute(ProvisioningStep("run_shell", {"command": "sh"}))


def test_host_adapter_requires_privilege_and_exact_plan_step(tmp_path):
    _, plan = seeded(tmp_path)
    with pytest.raises(PermissionError): AllowlistedHostProvisioningAdapter(plan, {})
    adapter = AllowlistedHostProvisioningAdapter(plan, {plan.steps[0].operation: lambda _: {"ok": True}}, privileged=True)
    assert adapter.execute(plan.steps[0])["ok"] is True
    with pytest.raises(ValueError, match="exact allowlisted"):
        adapter.execute(ProvisioningStep(plan.steps[0].operation, {"path": "/tmp/changed"}))


def test_execute_api_requires_exact_confirmation_and_configured_host_adapter(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan); approve_plan(path, plan.plan_id, "operator-human")
    with pytest.raises(ValueError, match="confirmation"):
        execute_plan_api(path, {"plan_id": plan.plan_id, "privileged_confirmation": "yes"})
    with pytest.raises(ValueError, match="not configured"):
        execute_plan_api(path, {"plan_id": plan.plan_id, "privileged_confirmation": "execute-exact-donuthole-backup-provisioning-plan"})


def test_partial_failure_rolls_back_in_reverse_and_records_redacted_terminal_state(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan); approve_plan(path, plan.plan_id, "operator-human")
    calls = []; forward = {step.operation for step in plan.steps}; rollback = {step.operation for step in plan.rollback_steps}
    def operation(name):
        def run(_args):
            calls.append(name)
            if name == "ensure_system_user": raise RuntimeError("secret failure detail")
            return {"ok": True, "detail": "secret result"}
        return run
    adapter = DedicatedProvisioningAdapter({name: operation(name) for name in forward | rollback})
    with pytest.raises(RuntimeError): execute_plan(path, plan.plan_id, adapter)
    item = list_plans(path)["items"][0]
    assert item["status"] == "rolled_back" and "secret failure detail" not in repr(item) and "secret result" not in repr(item)
    assert calls[-len(plan.rollback_steps):] == [step.operation for step in reversed(plan.rollback_steps)]
