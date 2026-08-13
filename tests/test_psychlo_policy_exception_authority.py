from __future__ import annotations

from pathlib import Path

import pytest

from overseer.admin import approve_admin_change_plan
from overseer.psychlo_bridge import PsychloBridge
from overseer.psychlo_contracts import policy_exception_request_digest
from overseer.psychlo_store import PsychloBridgeStore
from overseer.store import SQLiteStore


NOW = "2026-08-12T12:01:00+00:00"


def request(request_id: str = "exception-authority") -> dict:
    value = {
        "schemaVersion": "psychlo.policy-exception-request.v1",
        "id": request_id,
        "requestedRuleId": "enforce-safety-reserve",
        "policyRevision": 4,
        "scopeDigest": "e" * 64,
        "decisionVersion": "decision-v1",
        "actorId": "operator-1",
        "requestedValue": False,
        "reason": "bounded safety drill",
        "activatedAt": "2026-08-12T12:00:00.000Z",
        "expiresAt": "2026-08-13T00:00:00.000Z",
        "correlationId": f"corr-{request_id}",
        "idempotencyKey": f"key-{request_id}",
        "occurredAt": "2026-08-12T12:00:00.000Z",
    }
    value["digest"] = policy_exception_request_digest(value)
    return value


def bridge(tmp_path: Path, *, sent: list | None = None, now: str = NOW):
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    projected = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    outbound = sent if sent is not None else []
    return (
        PsychloBridge(
            store=projected,
            dispatcher=lambda *_: "unused",
            sender=lambda kind, message_id, payload: outbound.append((kind, message_id, payload)) or {"accepted": True},
            callback_origin="http://127.0.0.1:8766",
            clock=lambda: now,
            approval_store=primary,
        ),
        primary,
    )


def test_signed_request_stages_exact_non_executable_authority_atomically(tmp_path: Path):
    value = request()
    bridge_instance, primary = bridge(tmp_path)
    result = bridge_instance.receive_policy_exception_request(value, message_id="signed-message")

    assert result["status"] == "pending"
    plan = primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-authority")
    approval = primary.load_approval("approval.psychlo.policy-exception.exception-authority")
    binding = primary.load_roadex_approval_binding(plan.id)
    assert plan.kind.value == "psychlo_policy_exception"
    assert plan.can_execute() is False
    assert plan.approved is False
    assert approval.status.value == "pending"
    assert approval.approval_level.value == "human"
    assert binding.source_id == plan.id
    assert binding.scope_digest


def test_staging_binding_failure_rolls_back_plan_and_approval_then_retry_succeeds(tmp_path: Path, monkeypatch):
    value = request("exception-atomic-stage")
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    original = primary.save_roadex_approval_binding

    def fail_binding(_binding):
        raise RuntimeError("injected binding failure")

    monkeypatch.setattr(primary, "save_roadex_approval_binding", fail_binding)
    with pytest.raises(RuntimeError, match="injected binding failure"):
        primary.stage_psychlo_policy_exception_authority(value, created_at=NOW)
    assert primary.list_admin_change_plans() == ()
    assert primary.list_approvals() == ()
    with pytest.raises(KeyError):
        primary.load_roadex_approval_binding("admin.psychlo.policy-exception.exception-atomic-stage")

    monkeypatch.setattr(primary, "save_roadex_approval_binding", original)
    staged = primary.stage_psychlo_policy_exception_authority(value, created_at=NOW)
    assert staged["inserted"] is True
    assert primary.load_admin_change_plan(staged["planId"])
    assert primary.load_approval(staged["approvalId"])
    assert primary.load_roadex_approval_binding(staged["planId"])


def test_generic_admin_approval_cannot_authorize_policy_exception(tmp_path: Path):
    value = request("exception-generic-block")
    bridge_instance, primary = bridge(tmp_path)
    bridge_instance.receive_policy_exception_request(value)
    plan = primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-generic-block")

    with pytest.raises(ValueError):
        approve_admin_change_plan(plan, "human-user", NOW)
    with pytest.raises(ValueError, match="pending|authority"):
        bridge_instance.authorize_policy_exception(
            "approval.psychlo.policy-exception.exception-generic-block", value
        )


def test_dedicated_decision_commits_pair_and_forwards_signed_outcome(tmp_path: Path):
    value = request("exception-approve")
    sent: list = []
    bridge_instance, primary = bridge(tmp_path, sent=sent)
    bridge_instance.receive_policy_exception_request(value)

    result = bridge_instance.decide_policy_exception_authority(
        {
            "request_id": value["id"],
            "decision": "approve",
            "decided_by": "human-user",
            "reason": "approved for the bounded drill",
        }
    )
    assert result["status"] == "approved"
    assert sent[-1][0] == "policy-exception-outcome"
    assert primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-approve").approved
    assert primary.load_approval("approval.psychlo.policy-exception.exception-approve").status.value == "approved"


def test_dedicated_rejection_cancels_pair_and_forwards_rejection(tmp_path: Path):
    value = request("exception-reject")
    sent: list = []
    bridge_instance, primary = bridge(tmp_path, sent=sent)
    bridge_instance.receive_policy_exception_request(value)

    result = bridge_instance.decide_policy_exception_authority(
        {
            "exception_id": value["id"],
            "decision": "deny",
            "decided_by": "human-user",
            "reason": "safety reserve remains mandatory",
        }
    )
    assert result["status"] == "rejected"
    assert sent[-1][2]["status"] == "rejected"
    assert primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-reject").canceled
    assert primary.load_approval("approval.psychlo.policy-exception.exception-reject").status.value == "rejected"


def test_decision_write_failure_rolls_back_both_authority_records(tmp_path: Path, monkeypatch):
    value = request("exception-atomic-decision")
    bridge_instance, primary = bridge(tmp_path)
    bridge_instance.receive_policy_exception_request(value)
    original = primary.save_approval

    def fail_approval(_approval):
        raise RuntimeError("injected approval decision failure")

    monkeypatch.setattr(primary, "save_approval", fail_approval)
    with pytest.raises(RuntimeError, match="injected approval decision failure"):
        bridge_instance.decide_policy_exception_authority(
            {
                "request_id": value["id"],
                "decision": "approve",
                "decided_by": "human-user",
                "reason": "approved for the bounded drill",
            }
        )
    plan = primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-atomic-decision")
    approval = primary.load_approval("approval.psychlo.policy-exception.exception-atomic-decision")
    assert plan.approved is False and plan.canceled is False
    assert approval.status.value == "pending"
    assert primary.psychlo_policy_exception_decision(value["id"]) is None

    monkeypatch.setattr(primary, "save_approval", original)
    result = bridge_instance.decide_policy_exception_authority(
        {
            "request_id": value["id"],
            "decision": "approve",
            "decided_by": "human-user",
            "reason": "approved for the bounded drill",
        }
    )
    assert result["status"] == "approved"


def test_restart_replay_does_not_duplicate_authority(tmp_path: Path):
    value = request("exception-replay")
    first, primary = bridge(tmp_path)
    first.receive_policy_exception_request(value, message_id="first")
    second, _ = bridge(tmp_path)
    replay = second.receive_policy_exception_request(value, message_id="second")
    assert replay["replay"] is True
    assert len(primary.list_approvals()) == 1
    assert len(primary.list_admin_change_plans()) == 1


def test_dedicated_decision_replay_returns_stable_outcome(tmp_path: Path):
    value = request("exception-decision-replay")
    bridge_instance, _ = bridge(tmp_path)
    bridge_instance.receive_policy_exception_request(value)
    payload = {
        "request_id": value["id"],
        "decision": "approve",
        "decided_by": "human-user",
        "reason": "approved for the bounded drill",
    }
    first = bridge_instance.decide_policy_exception_authority(payload)
    second = bridge_instance.decide_policy_exception_authority(payload)
    assert first["status"] == second["status"] == "approved"
    assert second["replay"] is True


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("decision", "deny"),
        ("decided_by", "other-human"),
        ("reason", "changed reason"),
        ("decided_at", "2026-08-12T12:02:00+00:00"),
    ],
)
def test_dedicated_decision_replay_rejects_changed_identity(tmp_path: Path, field: str, changed: str):
    value = request(f"exception-decision-conflict-{field}")
    bridge_instance, _ = bridge(tmp_path)
    payload = {
        "request_id": value["id"],
        "decision": "approve",
        "decided_by": "human-user",
        "reason": "approved for the bounded drill",
        "decided_at": NOW,
    }
    bridge_instance.receive_policy_exception_request(value)
    bridge_instance.decide_policy_exception_authority(payload)
    altered = {**payload, field: changed}
    with pytest.raises(ValueError, match="decision conflict"):
        bridge_instance.decide_policy_exception_authority(altered)


def test_late_approval_expires_primary_pair_and_bridge_request_atomically(tmp_path: Path):
    value = request(
        "exception-late-approval",
    )
    value["expiresAt"] = "2026-08-12T12:02:00.000Z"
    value["digest"] = policy_exception_request_digest(value)
    bridge_instance, primary = bridge(tmp_path, now="2026-08-12T12:01:00+00:00")
    bridge_instance.receive_policy_exception_request(value)
    bridge_instance.clock = lambda: "2026-08-12T12:03:00+00:00"

    result = bridge_instance.decide_policy_exception_authority(
        {
            "request_id": value["id"],
            "decision": "approve",
            "decided_by": "human-user",
            "reason": "approval arrived too late",
        }
    )
    plan = primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-late-approval")
    approval = primary.load_approval("approval.psychlo.policy-exception.exception-late-approval")
    assert result["status"] == "expired"
    assert plan.canceled is True and plan.approved is False
    assert approval.status.value == "expired"
    assert bridge_instance.store.policy_exception_request(value["id"])["state"] == "expired"


def test_restart_after_approved_outcome_delivery_failure_expires_primary_authority(tmp_path: Path):
    value = request("exception-approved-undelivered")
    value["expiresAt"] = "2026-08-12T12:02:00.000Z"
    value["digest"] = policy_exception_request_digest(value)
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    projected_path = tmp_path / "bridge.sqlite3"
    projected = PsychloBridgeStore(projected_path)
    first = PsychloBridge(
        store=projected,
        dispatcher=lambda *_: "unused",
        sender=lambda *_: {"accepted": False},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: "2026-08-12T12:01:00+00:00",
        approval_store=primary,
    )
    first.receive_policy_exception_request(value)
    with pytest.raises(ValueError, match="forward-pending"):
        first.decide_policy_exception_authority(
            {
                "request_id": value["id"],
                "decision": "approve",
                "decided_by": "human-user",
                "reason": "approved before expiry",
            }
        )
    assert primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-approved-undelivered").approved
    assert primary.load_approval("approval.psychlo.policy-exception.exception-approved-undelivered").status.value == "approved"
    projected.connection.close()

    restarted_store = PsychloBridgeStore(projected_path)
    sent: list = []
    PsychloBridge(
        store=restarted_store,
        dispatcher=lambda *_: "unused",
        sender=lambda *args: sent.append(args) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: "2026-08-12T12:03:00+00:00",
        approval_store=primary,
    )
    plan = primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-approved-undelivered")
    approval = primary.load_approval("approval.psychlo.policy-exception.exception-approved-undelivered")
    assert restarted_store.policy_exception_request(value["id"])["state"] == "expired"
    assert plan.canceled is True and plan.approved is False
    assert approval.status.value == "expired"
    assert primary.psychlo_policy_exception_authority_expiration(value["id"])["originalDecision"] == "approved"
    assert sent == []
    replay = restarted_store.policy_exception_request(value["id"])
    assert replay["state"] == "expired" and replay["outcome"]["status"] == "approved"

    restarted = PsychloBridge(
        store=restarted_store,
        dispatcher=lambda *_: "unused",
        sender=lambda *_: {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: "2026-08-12T12:04:00+00:00",
        approval_store=primary,
    )
    terminal = restarted.receive_policy_exception_request(value)
    assert terminal["status"] == "expired"
    assert "outcome" not in terminal


def test_authorize_after_expiry_expires_preapproved_undelivered_authority(tmp_path: Path):
    value = request("exception-authorize-after-expiry")
    value["expiresAt"] = "2026-08-12T12:02:00.000Z"
    value["digest"] = policy_exception_request_digest(value)
    bridge_instance, primary = bridge(tmp_path, now="2026-08-12T12:01:00+00:00")
    bridge_instance.receive_policy_exception_request(value)
    primary.decide_psychlo_policy_exception_authority(
        value["id"], "approved", "human-user", "approved before expiry", decided_at="2026-08-12T12:01:30+00:00"
    )
    bridge_instance.clock = lambda: "2026-08-12T12:03:00+00:00"

    result = bridge_instance.authorize_policy_exception(
        f"approval.psychlo.policy-exception.{value['id']}", value
    )
    plan = primary.load_admin_change_plan(f"admin.psychlo.policy-exception.{value['id']}")
    approval = primary.load_approval(f"approval.psychlo.policy-exception.{value['id']}")
    assert result["status"] == "expired"
    assert plan.canceled and not plan.approved
    assert approval.status.value == "expired"
    assert bridge_instance.store.policy_exception_request(value["id"])["state"] == "expired"


def test_restart_after_delivered_approval_does_not_expire_primary_authority(tmp_path: Path):
    value = request("exception-approved-delivered")
    value["expiresAt"] = "2026-08-12T12:02:00.000Z"
    value["digest"] = policy_exception_request_digest(value)
    bridge_instance, primary = bridge(tmp_path, now="2026-08-12T12:01:00+00:00")
    bridge_instance.receive_policy_exception_request(value)
    result = bridge_instance.decide_policy_exception_authority(
        {
            "request_id": value["id"],
            "decision": "approve",
            "decided_by": "human-user",
            "reason": "approved and delivered before expiry",
        }
    )
    assert result["status"] == "approved"
    bridge_instance.clock = lambda: "2026-08-12T12:03:00+00:00"
    bridge_instance._recover_policy_exception_records()
    assert bridge_instance.store.policy_exception_request(value["id"])["state"] == "approved"
    assert primary.load_admin_change_plan("admin.psychlo.policy-exception.exception-approved-delivered").approved
    assert primary.load_approval("approval.psychlo.policy-exception.exception-approved-delivered").status.value == "approved"
    assert primary.psychlo_policy_exception_authority_expiration(value["id"]) is None
