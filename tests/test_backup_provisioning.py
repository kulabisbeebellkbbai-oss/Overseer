from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import sqlite3
import threading
from http.server import ThreadingHTTPServer
from urllib.request import urlopen

import pytest

from overseer import backup_provisioning as backup_provisioning_module
from overseer import api as api_module
from overseer import provisioning_bundle as provisioning_bundle_module
from overseer.backup_contract import PROVISIONING_CONTRACT_VERSION, runtime_artifact_identity
from overseer.backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS, capability_digest
from overseer.backup_host_operations import RedactedHostOperationError
from overseer.backup_provisioning import AllowlistedHostProvisioningAdapter, DedicatedProvisioningAdapter, ProvisioningStatus, ProvisioningStep, _dump, _load, approve_plan, approve_plan_api, build_plan, decide_roadex_human_plan, execute_plan, execute_plan_api, list_plans, list_roadex_human_decisions, review_plan, save_staged_plan_source, stage_plan, stage_plan_api
from overseer.core import OwnerDomain, Resource, ResourceType, RiskLevel
from overseer.crew import CrewMessage, CrewMessageStatus, CrewReviewStatus
from overseer.store import SQLiteStore
from overseer.api import make_api_handler
from overseer.storage_control import approve_authorization, current_root_identity, materialize_authorization, revoke_authorization, stage_authorization


ROLES = {"kira": OwnerDomain.KIRA, "obrien": OwnerDomain.OBRIEN, "security": OwnerDomain.ODO_IDS, "sisko": OwnerDomain.SISKO}


def seeded(tmp_path):
    path = tmp_path / "state.sqlite3"; now = datetime.now(UTC).isoformat(); evidence = {}
    with SQLiteStore(path) as store:
        for role, domain in ROLES.items():
            identifier = f"crew.{role}.backup"; evidence[role] = identifier
            store.save_crew_message(CrewMessage(identifier, domain, "Backup review", "Approved exact provisioning plan", RiskLevel.HIGH, CrewMessageStatus.ACKNOWLEDGED, domain.value, now, now, related_plan_id="backup-provision.donuthole", review_status=CrewReviewStatus.APPROVED, decided_by=domain.value, decided_at=now))
    registration = {"project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1", "host_path": "/home/god/Documents/Codex Workspace/DonutHole", "alias": "donuthole-source", "max_bytes": 1073741824, "authorization_ref": "root-auth.donuthole"}
    return str(path), build_plan("backup-provision.donuthole", "sha256:" + "a" * 64, "b" * 40, "sha256:" + "d" * 64, "sha256:" + "c" * 64, {"sha256:" + "e" * 64: "root-auth.donuthole"}, (registration,), "/run/user/1000/overseer-api-token", "/etc/codex-development-backups/keys/overseer.token", "/etc/codex-development-backups/keys/cursor.key", evidence)


def _typed_bundle_with_reviews(tmp_path, review_count=4, correction_index=None):
    from tests.test_provisioning_bundle import (
        _task5_forge_claimed_terminal,
        _task5_record_terminal_dispatch,
        authoritative_bundle_fixture,
        stage_expected_bundle,
    )

    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, bundle)
    for index, entry in enumerate(bundle.outbox[:review_count]):
        decided_at = f"2026-08-02T12:0{index}:00+00:00"
        if index == correction_index:
            _task5_forge_claimed_terminal(
                store_path,
                entry,
                review_status=CrewReviewStatus.CORRECTION_REQUESTED,
                claim_at=decided_at,
                decided_at=decided_at,
                audit_summary=(
                    f"{entry.owner_domain.value} dispatch skipped: "
                    "exact immutable provisioning review passed"
                ),
            )
            provisioning_bundle_module._complete_review_outbox_dispatch(
                store_path, entry.id,
            )
            continue
        provisioning_bundle_module.materialize_review_outbox(store_path, entry.id)
        _entry, _message, claimed = (
            provisioning_bundle_module._claim_review_outbox_dispatch(
                store_path,
                entry.id,
                "independent-dispatcher",
                decided_at,
            )
        )
        assert claimed is True
        _task5_record_terminal_dispatch(
            store_path, entry, decided_at,
        )
        provisioning_bundle_module._complete_review_outbox_dispatch(
            store_path, entry.id,
        )
    return store_path, bundle.plan, bundle


def _plan_row_exists(store_path, plan_id):
    connection = sqlite3.connect(store_path)
    try:
        return connection.execute(
            "SELECT 1 FROM backup_provisioning_plans WHERE id=?", (plan_id,),
        ).fetchone() is not None
    finally:
        connection.close()


def _raw_stage_payload(plan):
    return {
        "plan_id": plan.plan_id,
        "gpg_sha256": plan.gpg_sha256,
        "adapter_commit": plan.adapter_commit,
        "runtime_digest": plan.runtime_digest,
        "capability_digest": plan.capability_digest,
        "root_authorization_refs": dict(plan.root_authorization_refs),
        "root_registrations": [dict(item) for item in plan.root_registrations],
        "overseer_token_source_file": plan.overseer_token_source_file,
        "overseer_token_file": plan.overseer_token_file,
        "cursor_key_file": plan.cursor_key_file,
        "evidence_ids": dict(plan.evidence_ids),
    }


def _approval_control_rows(store_path):
    connection = sqlite3.connect(store_path)
    try:
        return tuple(
            (
                table,
                tuple(connection.execute(
                    f"SELECT * FROM {table} ORDER BY 1"
                ).fetchall()),
            )
            for table in (
                "backup_provisioning_plans",
                "roadex_approval_bindings",
                "provisioning_preflight_reports",
                "provisioning_bundles",
                "provisioning_review_outbox",
                "crew_messages",
                "audit_events",
            )
        )
    finally:
        connection.close()


def test_unknown_approval_blocker_does_not_expose_internal_exception_text():
    secret = "/private/path?token=fake-secret"

    code, explanation = backup_provisioning_module._approval_blocker(
        KeyError(secret),
    )

    assert code == "REVIEW_EVIDENCE_NOT_CURRENT"
    assert secret not in explanation
    assert "current VERIFIED completion receipts" in explanation


def test_typed_human_approval_requires_all_exact_completion_receipts(tmp_path):
    store_path, plan, bundle = _typed_bundle_with_reviews(
        tmp_path, review_count=3,
    )
    before = _approval_control_rows(store_path)

    with pytest.raises(ValueError, match="^REVIEW_EVIDENCE_NOT_CURRENT$"):
        approve_plan(store_path, plan.plan_id, "independent-human")

    assert _approval_control_rows(store_path) == before
    assert _task6_plan(store_path, plan.plan_id).status == ProvisioningStatus.STAGED
    assert all(entry.state == "pending" for entry in bundle.outbox)


@pytest.mark.parametrize("corruption", ("missing", "digest"))
def test_typed_human_approval_rejects_missing_or_stale_preflight(
    tmp_path, corruption,
):
    store_path, plan, bundle = _typed_bundle_with_reviews(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        if corruption == "missing":
            connection.execute(
                "DELETE FROM provisioning_preflight_reports WHERE id=?",
                (bundle.preflight.report_id,),
            )
        else:
            connection.execute(
                "UPDATE provisioning_preflight_reports SET report_digest=? WHERE id=?",
                ("sha256:" + "f" * 64, bundle.preflight.report_id),
            )
        connection.commit()
    finally:
        connection.close()
    before = _approval_control_rows(store_path)

    with pytest.raises(ValueError, match="^PREFLIGHT_NOT_CURRENT$"):
        approve_plan(store_path, plan.plan_id, "independent-human")

    assert _approval_control_rows(store_path) == before


def test_typed_human_approval_rejects_forged_completion_receipt(tmp_path):
    store_path, plan, bundle = _typed_bundle_with_reviews(tmp_path)
    completion_id = (
        f"audit.{bundle.outbox[0].message_id}."
        "provisioning-review-dispatch-complete"
    )
    connection = sqlite3.connect(store_path)
    try:
        payload = json.loads(connection.execute(
            "SELECT payload FROM audit_events WHERE id=?", (completion_id,),
        ).fetchone()[0])
        payload["summary"] = "forged completion"
        connection.execute(
            "UPDATE audit_events SET payload=? WHERE id=?",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")), completion_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ValueError, match="^REVIEW_EVIDENCE_NOT_CURRENT$"):
        approve_plan(store_path, plan.plan_id, "independent-human")


def test_typed_human_approval_maps_legitimate_correction_to_stable_blocker(
    tmp_path,
):
    store_path, plan, _bundle = _typed_bundle_with_reviews(
        tmp_path, correction_index=0,
    )

    with pytest.raises(ValueError, match="^REVIEW_EVIDENCE_NOT_CURRENT$"):
        approve_plan(store_path, plan.plan_id, "independent-human")

    queue = list_roadex_human_decisions(store_path)
    assert queue["items"][0]["blocker_codes"] == [
        "REVIEW_EVIDENCE_NOT_CURRENT",
    ]
    assert "all four exact provisioning reviews" in (
        queue["items"][0]["blockers"][0].lower()
    )


def test_exact_typed_human_approval_is_read_only_until_atomic_plan_update(tmp_path):
    store_path, plan, bundle = _typed_bundle_with_reviews(tmp_path)
    outbox_before = tuple(
        provisioning_bundle_module._dump_review_outbox_entry(entry)
        for entry in bundle.outbox
    )

    result = approve_plan(store_path, plan.plan_id, "independent-human")

    assert result["status"] == ProvisioningStatus.APPROVED.value
    with SQLiteStore(store_path) as store:
        assert tuple(record[4] for record in (
            store.list_provisioning_review_outbox_records(plan.plan_id)
        )) == outbox_before


def test_typed_approval_rechecks_current_root_authority_after_staging(tmp_path):
    store_path, plan, _bundle = _typed_bundle_with_reviews(tmp_path)
    revoke_authorization(store_path, "root-auth.current", "human", "crew.kira.root-review")

    with pytest.raises(ValueError, match="^PREFLIGHT_NOT_CURRENT$"):
        approve_plan(store_path, plan.plan_id, "independent-human")

    assert _task6_plan(store_path, plan.plan_id).status == ProvisioningStatus.STAGED


def test_typed_approval_rechecks_current_chain_tip_after_successor_staging(tmp_path):
    from tests.test_provisioning_bundle import (
        authoritative_bundle_fixture,
        expected_preview_digests,
        intent_fixture,
        stage_expected_bundle,
    )

    store_path, predecessor = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, predecessor)
    successor_dependencies = provisioning_bundle_module._PreflightDependencies(
        source_path="/home/god/Documents/Codex Workspace/TheUnderdark",
        source_head=lambda _path: "b" * 40,
        runtime_digest=lambda _path, _commit: "sha256:" + "d" * 64,
        capability_digest=lambda commit, schemas: capability_digest(commit, schemas, "1"),
        file_digest=lambda _path: "sha256:" + "a" * 64,
        executable_exists=lambda _path: True,
        root_identity=lambda _path: "sha256:" + "e" * 64,
        canonical_boundaries_valid=lambda: True,
        rollback_prerequisites_valid=lambda: True,
        predecessor_lookup=lambda _plan_id: predecessor,
        authoritative_chain_tip=lambda _scope: predecessor.plan.plan_id,
    )
    successor = provisioning_bundle_module._build_provisioning_bundle_with_dependencies(
        store_path,
        intent_fixture(
            plan_id="backup-provision.donuthole.v21.20260802",
            supersedes_plan_id=predecessor.plan.plan_id,
        ),
        successor_dependencies,
    )
    provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
        store_path,
        successor.intent,
        successor_dependencies,
        expected_preview_digests(successor),
    )

    with pytest.raises(ValueError, match="^SUCCESSOR_REQUIRED$"):
        approve_plan(store_path, predecessor.plan.plan_id, "independent-human")

    assert _task6_plan(store_path, predecessor.plan.plan_id).status == ProvisioningStatus.STAGED


def test_approval_rejects_noncanonical_evidence_actor_without_mutation(tmp_path):
    store_path, plan, _bundle = _typed_bundle_with_reviews(tmp_path)
    before = _approval_control_rows(store_path)

    with pytest.raises(ValueError, match="^independent human identity is required$"):
        approve_plan_api(store_path, {"plan_id": plan.plan_id, "approved_by": " kira "})
    with pytest.raises(ValueError, match="^independent human identity is required$"):
        approve_plan(store_path, plan.plan_id, " kira ")

    assert _approval_control_rows(store_path) == before
    assert _task6_plan(store_path, plan.plan_id).status == ProvisioningStatus.STAGED


@pytest.mark.parametrize("actor", ("KIRA", "Kira"))
def test_approval_rejects_case_variant_evidence_actor_without_mutation(tmp_path, actor):
    store_path, plan, _bundle = _typed_bundle_with_reviews(tmp_path)
    before = _approval_control_rows(store_path)

    with pytest.raises(ValueError, match="^independent human identity is required$"):
        approve_plan(store_path, plan.plan_id, actor)

    assert _approval_control_rows(store_path) == before
    assert _task6_plan(store_path, plan.plan_id).status == ProvisioningStatus.STAGED


def test_approval_rejects_case_variant_evidence_requester_without_mutation(tmp_path):
    store_path, plan = seeded(tmp_path)
    stage_plan(store_path, plan)
    with SQLiteStore(store_path) as store:
        message = store.load_crew_message(plan.evidence_ids["obrien"])
        store.save_crew_message(replace(message, requested_by="INDEPENDENT-HUMAN"))
    before = _approval_control_rows(store_path)

    with pytest.raises(ValueError, match="^independent human identity is required$"):
        approve_plan(store_path, plan.plan_id, "independent-human")

    assert _approval_control_rows(store_path) == before
    assert _task6_plan(store_path, plan.plan_id).status == ProvisioningStatus.STAGED


@pytest.mark.parametrize("decision", ("deny", "request_revision"))
@pytest.mark.parametrize("actor", ("kira", "KIRA", "Kira", " obrien ", ""))
def test_roadex_decisions_reject_non_independent_humans_without_mutation(
    tmp_path, decision, actor,
):
    store_path, plan = seeded(tmp_path)
    stage_plan(store_path, plan)
    before = _approval_control_rows(store_path)

    with pytest.raises(ValueError, match="^independent human identity is required$"):
        decide_roadex_human_plan(store_path, plan.plan_id, decision, actor, "Needs revision")

    assert _approval_control_rows(store_path) == before
    assert _task6_plan(store_path, plan.plan_id).status == ProvisioningStatus.STAGED


def test_roadex_readiness_redacts_unexpected_exception_directly(tmp_path, monkeypatch):
    path, plan = seeded(tmp_path)
    stage_plan(path, plan)
    secret = "/private/path?token=unexpected-secret"
    monkeypatch.setattr(
        backup_provisioning_module,
        "_require_approval_readiness",
        lambda _store, _plan: (_ for _ in ()).throw(RuntimeError(secret)),
    )

    result = list_roadex_human_decisions(path)

    assert result["items"][0]["blocker_codes"] == ["REVIEW_EVIDENCE_NOT_CURRENT"]
    assert result["items"][0]["blockers"] == [
        "All four exact provisioning reviews must be approved with current VERIFIED completion receipts."
    ]
    assert secret not in repr(result)


def test_roadex_readiness_public_route_redacts_unexpected_exception(
    tmp_path, monkeypatch,
):
    path, plan = seeded(tmp_path)
    stage_plan(path, plan)
    secret = "/private/path?token=route-secret"
    monkeypatch.setattr(
        api_module,
        "list_roadex_human_decisions",
        lambda _path: (_ for _ in ()).throw(RuntimeError(secret)),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_api_handler(path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(
            f"http://127.0.0.1:{server.server_address[1]}/roadex/human-decisions",
            timeout=5,
        ) as response:
            payload = json.loads(response.read())
            assert response.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert payload == {
        "error": "review evidence is not current",
        "code": "REVIEW_EVIDENCE_NOT_CURRENT",
    }
    assert secret not in repr(payload)


def test_roadex_readiness_is_server_derived_and_has_zero_data_mutation(tmp_path):
    store_path, plan, _bundle = _typed_bundle_with_reviews(tmp_path)
    before = _approval_control_rows(store_path)

    queue = list_roadex_human_decisions(store_path)

    assert queue["mutation_performed"] is False
    assert queue["items"][0]["plan_id"] == plan.plan_id
    assert queue["items"][0]["ready"] is True
    assert queue["items"][0]["blocker_codes"] == []
    assert queue["items"][0]["blockers"] == []
    assert _approval_control_rows(store_path) == before


def test_roadex_readiness_uses_one_consistent_read_snapshot(
    tmp_path, monkeypatch,
):
    store_path, plan, bundle = _typed_bundle_with_reviews(tmp_path)
    verifier_reached = threading.Event()
    writer_finished = threading.Event()
    real_verify = (
        provisioning_bundle_module.verify_exact_completed_review_outbox_set
    )
    completion_id = (
        f"audit.{bundle.outbox[0].message_id}."
        "provisioning-review-dispatch-complete"
    )

    def delete_completion():
        assert verifier_reached.wait(timeout=10)
        connection = sqlite3.connect(store_path, timeout=10)
        try:
            connection.execute("DELETE FROM audit_events WHERE id=?", (completion_id,))
            connection.commit()
        finally:
            connection.close()
        writer_finished.set()

    def verify_after_writer(store, exact_bundle):
        verifier_reached.set()
        assert writer_finished.wait(timeout=10)
        return real_verify(store, exact_bundle)

    monkeypatch.setattr(
        provisioning_bundle_module,
        "verify_exact_completed_review_outbox_set",
        verify_after_writer,
    )
    writer = threading.Thread(target=delete_completion)
    writer.start()
    first = list_roadex_human_decisions(store_path)
    writer.join(timeout=10)
    monkeypatch.setattr(
        provisioning_bundle_module,
        "verify_exact_completed_review_outbox_set",
        real_verify,
    )

    assert not writer.is_alive()
    assert first["items"][0]["plan_id"] == plan.plan_id
    assert first["items"][0]["ready"] is True
    second = list_roadex_human_decisions(store_path)
    assert second["items"][0]["ready"] is False
    assert second["items"][0]["blocker_codes"] == [
        "REVIEW_EVIDENCE_NOT_CURRENT",
    ]


def test_enabled_store_legacy_staged_plan_requires_nontransferring_successor(
    tmp_path,
):
    store_path, _typed_plan, _bundle = _typed_bundle_with_reviews(tmp_path)
    legacy_path, legacy = seeded(tmp_path)
    assert legacy_path == store_path
    stage_plan(store_path, legacy)
    legacy_evidence = tuple(legacy.evidence_ids.values())

    with pytest.raises(ValueError, match="^SUCCESSOR_REQUIRED$"):
        approve_plan(store_path, legacy.plan_id, "independent-human")

    assert _task6_plan(store_path, legacy.plan_id).status == ProvisioningStatus.STAGED
    assert tuple(legacy.evidence_ids.values()) == legacy_evidence


def test_legacy_approved_plan_remains_listable_and_executable_after_activation(
    tmp_path,
):
    store_path, plan = seeded(tmp_path)
    stage_plan(store_path, plan)
    approve_plan(store_path, plan.plan_id, "independent-human")
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(
            "INSERT INTO provisioning_preflight_reports VALUES (?,?,?,?)",
            (
                "preflight.feature-boundary",
                "plan.future",
                "sha256:" + "f" * 64,
                "{}",
            ),
        )
        connection.commit()
    finally:
        connection.close()

    listed = list_plans(store_path)

    assert listed["items"][0]["plan_id"] == plan.plan_id
    assert listed["items"][0]["status"] == ProvisioningStatus.APPROVED.value
    handlers = {
        step.operation: (lambda _arguments: {"ok": True})
        for step in plan.steps
    }
    executed = execute_plan(
        store_path,
        plan.plan_id,
        DedicatedProvisioningAdapter(handlers),
    )
    assert executed["status"] == ProvisioningStatus.EXECUTED.value


def test_raw_stage_is_allowed_before_and_blocked_after_persisted_feature_boundary(
    tmp_path,
):
    legacy_path, legacy = seeded(tmp_path / "legacy-open")
    assert stage_plan_api(legacy_path, _raw_stage_payload(legacy))["status"] == "staged"

    store_path, _typed_plan, _bundle = _typed_bundle_with_reviews(tmp_path / "enabled")
    _path, blocked = seeded(tmp_path / "enabled")
    assert _path == store_path
    with pytest.raises(ValueError, match="^TYPED_BUNDLE_REQUIRED$"):
        stage_plan_api(store_path, _raw_stage_payload(blocked))
    assert _plan_row_exists(store_path, blocked.plan_id) is False


@pytest.mark.parametrize(
    "artifact_sql",
    (
        "INSERT INTO provisioning_preflight_reports VALUES "
        "('preflight.partial','plan.partial','sha256:" + "a" * 64 + "','{}')",
        "INSERT INTO provisioning_bundles VALUES "
        "('plan.partial','plan.partial','sha256:" + "b" * 64 + "','{}')",
        "INSERT INTO provisioning_review_outbox VALUES "
        "('outbox.partial','plan.partial','kira','pending','{}')",
        "INSERT INTO roadex_approval_bindings VALUES "
        "('approval.donuthole.partial','roadex-human-decision','plan.partial','{}')",
    ),
)
def test_any_partial_typed_artifact_fails_closed_for_raw_stage(
    tmp_path, artifact_sql,
):
    store_path, plan = seeded(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(artifact_sql)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ValueError, match="^TYPED_BUNDLE_REQUIRED$"):
        stage_plan_api(store_path, _raw_stage_payload(plan))


def test_concurrent_first_bundle_commit_closes_raw_stage_before_insert(
    tmp_path, monkeypatch,
):
    from tests.test_provisioning_bundle import (
        authoritative_bundle_fixture,
        stage_expected_bundle,
    )

    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    _path, raw_plan = seeded(tmp_path)
    assert _path == store_path
    raw_validated = threading.Event()
    resume_raw = threading.Event()
    real_validate = backup_provisioning_module._validate_plan
    outcome: dict[str, object] = {}

    def paused_validate(plan):
        real_validate(plan)
        if plan.plan_id == raw_plan.plan_id:
            raw_validated.set()
            assert resume_raw.wait(timeout=10)

    def raw_stage():
        try:
            outcome["result"] = stage_plan_api(
                store_path, _raw_stage_payload(raw_plan),
            )
        except Exception as error:
            outcome["error"] = error

    monkeypatch.setattr(backup_provisioning_module, "_validate_plan", paused_validate)
    thread = threading.Thread(target=raw_stage)
    thread.start()
    assert raw_validated.wait(timeout=10)
    stage_expected_bundle(store_path, bundle)
    resume_raw.set()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert str(outcome.get("error")) == "TYPED_BUNDLE_REQUIRED"
    assert "result" not in outcome
    assert _plan_row_exists(store_path, raw_plan.plan_id) is False


@pytest.mark.parametrize(
    ("operation", "expected_status"),
    (("approve", ProvisioningStatus.APPROVED), ("deny", ProvisioningStatus.DENIED)),
)
def test_gate_and_human_plan_update_are_one_locked_transaction(
    tmp_path, monkeypatch, operation, expected_status,
):
    store_path, plan, _bundle = _typed_bundle_with_reviews(tmp_path)
    gate_reached = threading.Event()
    writer_attempting = threading.Event()
    writer_finished = threading.Event()
    finished_before_gate_return: list[bool] = []
    writer_observed_status: list[ProvisioningStatus] = []
    real_require = backup_provisioning_module._require_terminal_evidence
    evidence_id = plan.evidence_ids["obrien"]

    def paused_gate(store, exact_plan):
        real_require(store, exact_plan)
        gate_reached.set()
        assert writer_attempting.wait(timeout=10)
        finished_before_gate_return.append(writer_finished.wait(timeout=0.5))

    def competing_writer():
        assert gate_reached.wait(timeout=10)
        writer_attempting.set()
        with SQLiteStore(store_path) as store:
            message = store.load_crew_message(evidence_id)
            store.save_crew_message(replace(
                message,
                decision_reason="concurrent replacement",
            ))
            writer_observed_status.append(
                backup_provisioning_module._stored(store, plan.plan_id).status
            )
        writer_finished.set()

    monkeypatch.setattr(
        backup_provisioning_module, "_require_terminal_evidence", paused_gate,
    )
    writer = threading.Thread(target=competing_writer)
    writer.start()
    if operation == "approve":
        approve_plan(store_path, plan.plan_id, "independent-human")
    else:
        decide_roadex_human_plan(
            store_path, plan.plan_id, "deny", "independent-human", "deny",
        )
    writer.join(timeout=10)

    assert finished_before_gate_return == [False]
    assert writer_observed_status == [expected_status]
    assert not writer.is_alive()


def _task6_plan(store_path, plan_id):
    with SQLiteStore(store_path) as store:
        return backup_provisioning_module._stored(store, plan_id)


def test_stage_is_immutable_and_binds_all_terminal_evidence(tmp_path):
    path, plan = seeded(tmp_path); staged = stage_plan(path, plan)
    assert staged["status"] == "staged" and staged["host_mutation_performed"] is False
    assert len(list_plans(path)["items"]) == 1
    changed = build_plan(plan.plan_id, "sha256:" + "b" * 64, plan.adapter_commit, plan.runtime_digest, plan.capability_digest, plan.root_authorization_refs, plan.root_registrations, plan.overseer_token_source_file, plan.overseer_token_file, plan.cursor_key_file, plan.evidence_ids)
    with pytest.raises(ValueError, match="immutable"):
        stage_plan(path, changed)


def test_atomic_bundle_source_rejects_non_staged_plan_before_persistence(tmp_path):
    path, plan = seeded(tmp_path)
    non_staged = replace(
        plan,
        status=ProvisioningStatus.APPROVED,
        approved_by="human-user",
        approved_at=datetime.now(UTC).isoformat(),
    )

    with SQLiteStore(path) as store:
        with pytest.raises(ValueError, match="staged"):
            save_staged_plan_source(store, non_staged)
        assert store.registered_source_exists(
            "backup-provisioning-plan", plan.plan_id,
        ) is False


def test_plan_derives_contract_and_runtime_artifact_identity_from_reviewed_inputs(tmp_path):
    _, plan = seeded(tmp_path)

    assert plan.provisioning_contract_version == PROVISIONING_CONTRACT_VERSION
    assert plan.runtime_artifact_identity == runtime_artifact_identity(
        plan.adapter_commit,
        EXPECTED_BACKUP_TOOL_SCHEMAS,
    )
    assert plan.capability_digest == capability_digest(
        plan.adapter_commit,
        EXPECTED_BACKUP_TOOL_SCHEMAS,
        PROVISIONING_CONTRACT_VERSION,
    )
    assert plan.capability_digest != "sha256:" + "c" * 64


def test_plan_rejects_changed_runtime_artifact_identity_before_staging(tmp_path):
    path, plan = seeded(tmp_path)
    changed = replace(plan, runtime_artifact_identity="sha256:" + "0" * 64)

    with pytest.raises(ValueError, match="runtime artifact identity"):
        stage_plan(path, changed)
    with pytest.raises(ValueError, match="provisioning contract version"):
        stage_plan(path, replace(plan, provisioning_contract_version="2"))


def test_plan_decode_rejects_unbound_contract_identity_fields(tmp_path):
    _, plan = seeded(tmp_path)
    payload = _dump(plan)

    decoded = _load(payload)
    assert decoded.provisioning_contract_version == plan.provisioning_contract_version
    assert decoded.runtime_artifact_identity == plan.runtime_artifact_identity
    with pytest.raises(ValueError, match="provisioning contract version"):
        _load(payload.replace('"provisioning_contract_version":"1",', ""))
    with pytest.raises(ValueError, match="runtime artifact identity"):
        _load(payload.replace('"runtime_artifact_identity":"' + plan.runtime_artifact_identity + '",', ""))


def test_kira_review_rejects_superseded_root_authorization(tmp_path):
    store_path=str(tmp_path/"state.sqlite3"); root=tmp_path/"donuthole"; root.mkdir(); now=datetime.now(UTC)-timedelta(seconds=5); identity=current_root_identity(str(root)); target="sha256:"+"e"*64
    evidence={role:f"crew.{role}.current-root-review" for role in ROLES}
    with SQLiteStore(store_path) as store:
        store.save_resource(Resource("storage.donuthole","DonutHole storage",ResourceType.VIRTUAL_ASSET,OwnerDomain.KIRA,RiskLevel.HIGH))
        store.save_crew_message(CrewMessage("crew.kira.root-authorization",OwnerDomain.KIRA,"Root review","Approved root",RiskLevel.HIGH,CrewMessageStatus.ACKNOWLEDGED,review_status=CrewReviewStatus.APPROVED,decided_by="kira",decided_at=now.isoformat()))
        for role,domain in ROLES.items():
            store.save_crew_message(CrewMessage(evidence[role],domain,"Plan review","Pending",RiskLevel.HIGH,CrewMessageStatus.OPEN,related_plan_id="backup-provision.current-root-review"))
    refs=[]
    for index,ref in enumerate(("root-auth-old","root-auth-current")):
        payload={"authorization_ref":ref,"action":"root.register","project_id":"project.donuthole","root_id":"backup-root","policy_revision":"1","root_identity":identity,"alias":"donuthole-source","status":"active","max_bytes":1073741824,"target_digest":target,"expires_at":(now+timedelta(minutes=10)).isoformat()}
        stage_authorization(store_path,"root",payload,"crew.kira.root-authorization","kira",now.isoformat())
        approved_at=(now+timedelta(seconds=index)).isoformat(); approve_authorization(store_path,ref,"human",approved_at); materialize_authorization(store_path,ref,approved_at); refs.append(ref)
    registration={"project_id":"project.donuthole","root_id":"backup-root","policy_revision":"1","host_path":str(root),"alias":"donuthole-source","max_bytes":1073741824,"authorization_ref":refs[0]}
    plan=build_plan("backup-provision.current-root-review","sha256:"+"a"*64,"b"*40,"sha256:"+"d"*64,"sha256:"+"c"*64,{target:refs[0]},(registration,),"/run/user/1000/overseer-api-token","/etc/codex-development-backups/keys/overseer.token","/etc/codex-development-backups/keys/cursor.key",evidence)
    stage_plan(store_path,plan)
    result=review_plan(store_path,plan.plan_id,"kira")
    assert result["ok"] is False
    assert any("current exact root authorization" in failure for failure in result["failures"])


def test_roadex_human_decision_card_lists_only_exact_ready_plan(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan)
    result = list_roadex_human_decisions(path)
    assert result["pending_count"] == 1
    item = result["items"][0]
    assert item["source"] == "Roadex" and item["owner"] == "Sisko"
    assert item["plan_id"] == plan.plan_id and item["plan_digest"] == plan.plan_digest
    assert item["human_approval_required"] is True and item["ready"] is True
    assert item["impact"] and item["risks"] and item["rollback"]


def test_roadex_human_decision_uses_latest_staged_plan_not_lexicographic_id(tmp_path):
    path, template = seeded(tmp_path)

    def plan_for(plan_id):
        with SQLiteStore(path) as store:
            for evidence_id in template.evidence_ids.values():
                message = store.load_crew_message(evidence_id)
                store.save_crew_message(replace(message, related_plan_id=plan_id))
        return build_plan(plan_id, template.gpg_sha256, template.adapter_commit, template.runtime_digest, template.capability_digest, template.root_authorization_refs, template.root_registrations, template.overseer_token_source_file, template.overseer_token_file, template.cursor_key_file, template.evidence_ids)

    older = plan_for("backup-provision.donuthole.v9.20260802")
    stage_plan(path, older)
    decide_roadex_human_plan(path, older.plan_id, "deny", "human-user", "Superseded")
    latest = plan_for("backup-provision.donuthole.v11.20260802")
    stage_plan(path, latest)

    result = list_roadex_human_decisions(path)
    assert result["pending_count"] == 1
    assert [item["plan_id"] for item in result["items"]] == [latest.plan_id]


def test_roadex_human_decision_does_not_resurface_staged_predecessor(tmp_path):
    path, template = seeded(tmp_path)

    def plan_for(plan_id):
        with SQLiteStore(path) as store:
            for evidence_id in template.evidence_ids.values():
                message = store.load_crew_message(evidence_id)
                store.save_crew_message(replace(message, related_plan_id=plan_id))
        return build_plan(plan_id, template.gpg_sha256, template.adapter_commit, template.runtime_digest, template.capability_digest, template.root_authorization_refs, template.root_registrations, template.overseer_token_source_file, template.overseer_token_file, template.cursor_key_file, template.evidence_ids)

    predecessor = plan_for("backup-provision.donuthole.v12.20260802")
    stage_plan(path, predecessor)
    successor = plan_for("backup-provision.donuthole.v13.20260802")
    stage_plan(path, successor)
    decide_roadex_human_plan(path, successor.plan_id, "deny", "human-user", "Terminal successor")

    result = list_roadex_human_decisions(path)
    assert result["pending_count"] == 0
    assert result["items"] == []


@pytest.mark.parametrize(("decision", "status"), (("deny", "denied"), ("request_revision", "revision_requested")))
def test_roadex_human_denial_and_revision_are_terminal_without_host_mutation(tmp_path, decision, status):
    path, plan = seeded(tmp_path); stage_plan(path, plan)
    result = decide_roadex_human_plan(path, plan.plan_id, decision, "human-user", "Needs a safer revision")
    assert result["action_status"] == status
    assert result["host_mutation_performed"] is False
    assert list_plans(path)["items"][0]["status"] == status


def test_roadex_human_approval_executes_exact_plan_to_terminal_evidence(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan); calls = []
    def factory(exact_plan):
        assert exact_plan.plan_id == plan.plan_id
        return DedicatedProvisioningAdapter({step.operation: (lambda _args, name=step.operation: calls.append(name) or {"ok": True}) for step in exact_plan.steps})
    result = decide_roadex_human_plan(path, plan.plan_id, "approve", "human-user", "", factory)
    assert result["action_status"] == "executed" and result["host_mutation_performed"] is True
    assert calls == [step.operation for step in plan.steps]
    assert list_plans(path)["items"][0]["evidence_digest"].startswith("sha256:")


def test_roadex_approval_fails_closed_before_approval_without_host_adapter(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan)
    with pytest.raises(ValueError, match="adapter"):
        decide_roadex_human_plan(path, plan.plan_id, "approve", "human-user", "")
    assert list_plans(path)["items"][0]["status"] == "staged"


def test_roadex_approval_stays_staged_when_host_adapter_construction_fails(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan)
    def unavailable(_plan):
        raise PermissionError("host adapter unavailable")
    with pytest.raises(PermissionError, match="unavailable"):
        decide_roadex_human_plan(path, plan.plan_id, "approve", "human-user", "", unavailable)
    assert list_plans(path)["items"][0]["status"] == "staged"


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


def test_stage_allows_missing_reviews_so_plan_precedes_dispatchable_messages(tmp_path):
    path, plan = seeded(tmp_path)
    with SQLiteStore(path) as store:
        store._connection.execute("DELETE FROM crew_messages")
        store._commit()

    result = stage_plan(path, plan)

    assert result["status"] == "staged"
    queue = list_roadex_human_decisions(path)
    assert queue["pending_count"] == 1
    assert queue["items"][0]["ready"] is False
    assert queue["items"][0]["blockers"]


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

def test_kira_and_obrien_route_exact_backup_plan_without_discovery_or_packages(monkeypatch):
    from types import SimpleNamespace
    import overseer.cli as cli
    plan={"ok":True,"kind":"donuthole_encrypted_backup_provisioning_v1","plan_id":"backup-provision.donuthole","plan_digest":"sha256:"+"a"*64,"host_mutation_performed":False}
    monkeypatch.setattr(cli,"_backup_provisioning_review_item",lambda *_args,**_kwargs:dict(plan))
    message=SimpleNamespace(related_plan_id="backup-provision.donuthole",related_resource_id="storage.donuthole",id="crew.review",owner_domain=OwnerDomain.KIRA)
    kira=cli._dispatch_kira_message("unused",message,"dispatcher",datetime.now(UTC).isoformat())
    message.owner_domain=OwnerDomain.OBRIEN
    obrien=cli._dispatch_obrien_message("unused",message,"dispatcher",datetime.now(UTC).isoformat())
    assert kira["status"]==obrien["status"]=="dispatched"
    assert kira["actions"]==obrien["actions"]==[plan]


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
    assert unit.arguments["properties"]["exec_start"] == (
        "/opt/theunderdark/.venv/bin/theunderdark-production", "serve",
        "--config", plan.config_path, "--runtime-root", "/opt/theunderdark",
        "--expected-runtime-digest", plan.runtime_digest,
        "--expected-config-digest", plan.config_digest,
        "--source-commit", plan.adapter_commit,
    )
    assert plan.key_path == "/etc/codex-development-backups/keys/donuthole.gpg-passphrase"
    assert "load_credential" not in unit.arguments["properties"]
    key = next(step for step in plan.steps if step.operation == "generate_secret_file")
    config = next(step for step in plan.steps if step.operation == "install_private_config")
    assert key.arguments["owner"] == "donuthole-backup" and key.arguments["mode"] == 0o600
    binding = config.arguments["config"]["backup_bindings"][0]
    assert binding["passphrase_file"] == plan.key_path and binding["source_root"] == plan.source_path
    remove_user = next(step for step in plan.rollback_steps if step.operation == "remove_system_user_if_unused")
    assert remove_user.arguments == {"name": "donuthole-backup", "retained_path": plan.backup_path}
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


def test_partial_failure_uses_declared_dependency_safe_rollback_order_and_records_redacted_terminal_state(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan); approve_plan(path, plan.plan_id, "operator-human")
    calls = []; forward = {step.operation for step in plan.steps}; rollback = {step.operation for step in plan.rollback_steps}
    def operation(name):
        def run(_args):
            calls.append(name)
            if name == "ensure_system_user": raise RedactedHostOperationError("PRIVATE_STATE_INVALID")
            return {"ok": True, "detail": "secret result"}
        return run
    adapter = DedicatedProvisioningAdapter({name: operation(name) for name in forward | rollback})
    with pytest.raises(RuntimeError): execute_plan(path, plan.plan_id, adapter)
    item = list_plans(path)["items"][0]
    assert item["status"] == "rolled_back" and item["failed_operation"] == "ensure_system_user" and item["error_code"] == "PRIVATE_STATE_INVALID"
    assert "secret failure detail" not in repr(item) and "secret result" not in repr(item)
    assert calls[-len(plan.rollback_steps):] == [step.operation for step in plan.rollback_steps]
    names = [step.operation for step in plan.rollback_steps]
    assert names.index("remove_read_only_acl") < names.index("remove_system_user_if_unused")
    assert names.index("remove_directory_if_empty") < names.index("remove_system_user_if_unused")


def test_unstructured_failure_records_only_generic_redacted_code(tmp_path):
    path, plan = seeded(tmp_path); stage_plan(path, plan); approve_plan(path, plan.plan_id, "operator-human")
    def fail(_args): raise RuntimeError("token=private path=/secret")
    operations = {step.operation: (fail if step.operation == "verify_endpoint_migration_ready" else lambda _args: {"ok": True}) for step in (*plan.steps, *plan.rollback_steps)}
    with pytest.raises(RuntimeError): execute_plan(path, plan.plan_id, DedicatedProvisioningAdapter(operations))
    item = list_plans(path)["items"][0]
    assert item["failed_operation"] == "verify_endpoint_migration_ready" and item["error_code"] == "OPERATION_FAILED"
    assert "token=private" not in repr(item) and "/secret" not in repr(item)
