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


def bridge(tmp_path: Path, *, sent: list | None = None):
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    projected = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    outbound = sent if sent is not None else []
    return (
        PsychloBridge(
            store=projected,
            dispatcher=lambda *_: "unused",
            sender=lambda kind, message_id, payload: outbound.append((kind, message_id, payload)) or {"accepted": True},
            callback_origin="http://127.0.0.1:8766",
            clock=lambda: NOW,
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
