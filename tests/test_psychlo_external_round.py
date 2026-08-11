from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from overseer.psychlo_bridge import PsychloBridge
from overseer.psychlo_store import PsychloBridgeStore
from overseer.psychlo_contracts import canonical_digest


NOW = "2026-08-10T02:00:00+00:00"


def external_payload():
    payload = {"reconciliationId": "reconcile-1", "externalExecutionId": "execution-1", "projectId": "arcade", "aTeamId": "team-1", "planId": "plan-1", "planVersion": "v1", "projectLeadId": "lead-1", "threadId": "thread-1", "repository": {"pathIdentity": "repo-identity", "beforeHead": "a" * 40, "afterHead": "b" * 40, "dirtyDigest": "c" * 64}, "startingCheckpoint": "checkpoint-start", "terminalCheckpoint": "checkpoint-end", "terminalStatus": "blocked", "deliveredScope": "scope", "remainingWork": "remaining", "blockers": ["gate"], "explicitGate": "approve next round", "evidenceIds": ["evidence-1"], "correlationId": "corr-1", "idempotencyKey": "reconcile-1", "occurredAt": NOW, "schemaVersion": "psychlo.external-round.v1"}
    payload["digest"] = canonical_digest(payload)
    return payload


def test_external_round_persists_separately_before_forward_and_creates_gate(tmp_path: Path):
    forwarded = []
    bridge = None
    def send(kind, message_id, payload):
        forwarded.append((kind, message_id, payload))
        if kind == "external-round":
            bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "roadex-callback-v7", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
        return {"accepted": True}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    receipt = bridge.receive_external_round(external_payload())
    assert receipt["status"] == "reconciled"
    assert bridge.store.external_execution("reconcile-1") is not None
    assert bridge.store.active_round() is None
    assert forwarded[0][0] == "external-round"
    assert not any(item[0] == "decision-stage" for item in forwarded)
    assert bridge.store.decision("roadex:external:reconcile-1")[2] == "staged"


def test_external_round_uses_exact_psychlo_gate_receipt_once(tmp_path: Path):
    forwarded = []
    bridge = None
    def send(kind, message_id, payload):
        forwarded.append((kind, message_id, payload))
        if kind == "external-round":
            bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "roadex-callback-v7", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
        return {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    first = bridge.receive_external_round(external_payload())
    replay = bridge.receive_external_round(external_payload())
    assert first["decisionId"] == replay["decisionId"] == "roadex:external:reconcile-1"
    assert [item[0] for item in forwarded] == ["external-round"]
    assert bridge.store.decision("roadex:external:reconcile-1")[2] == "staged"


def test_external_round_exact_replay_conflict_and_forward_retry_survive_restart(tmp_path: Path):
    payload = external_payload()
    attempts = []
    def send(kind, message_id, body):
        attempts.append(kind)
        if len(attempts) == 1 and kind == "external-round":
            raise ValueError("peer unavailable")
        return {"accepted": True}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    first = bridge.receive_external_round(payload)
    assert first["status"] == "forward-pending"
    restarted = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert restarted.receive_external_round(payload)["receiptId"] == first["receiptId"]
    conflict = {**payload, "deliveredScope": "different", "digest": canonical_digest({**payload, "deliveredScope": "different", "digest": None})}
    try:
        restarted.receive_external_round(conflict)
    except ValueError as error:
        assert "conflict" in str(error)
    else:
        raise AssertionError("conflicting external identity was accepted")


def test_approved_external_decide_settles_one_gate_and_releases_only_a_fresh_bounded_round(tmp_path: Path):
    dispatched = []
    forwarded = []
    bridge = None
    def send(kind, message_id, payload):
        forwarded.append((kind, message_id, payload))
        if kind == "external-round":
            bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "roadex-callback-v7", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
        return {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}} if kind == "external-round" else {"accepted": True}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda lead, prompt: dispatched.append((lead, prompt)) or "fresh-dispatch", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=lambda: "fresh-capability-1234567890abcdef")
    bridge.receive_external_round(external_payload())
    request = {"roundId": "fresh-round", "projectId": "arcade", "projectLeadId": "lead-1", "planId": "plan-1", "planVersion": "v1", "correlationId": "fresh-corr", "idempotencyKey": "fresh-round", "snapshotId": "snapshot-2", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "gate-proximity"}
    try:
        bridge.request_round(request)
    except ValueError as error:
        assert str(error) == "decision_pending"
    else:
        raise AssertionError("pending external decision did not block dispatch")
    result = bridge.decide("roadex:external:reconcile-1", "approve", "human-user", "approved bounded continuation")
    assert result["action_status"] == "approved"
    assert bridge.store.decision("roadex:external:reconcile-1")[2] == "approved"
    assert bridge.store.external_execution("reconcile-1")["receipt"]["decisionStatus"] == "approved"
    assert [item[0] for item in forwarded] == ["external-round", "decision-outcome"]
    bridge.request_round(request)
    assert len(dispatched) == 1
    assert bridge.decide("roadex:external:reconcile-1", "approve", "human-user", "approved bounded continuation") == result
    assert len([item for item in forwarded if item[0] == "decision-outcome"]) == 1
    try:
        bridge.decide("roadex:external:reconcile-1", "deny", "human-user", "conflict")
    except ValueError as error:
        assert "conflict" in str(error)
    else:
        raise AssertionError("conflicting external decision was accepted")


def test_rejected_and_expired_external_decisions_remain_blocked(tmp_path: Path):
    for outcome in ("deny", "request_revision"):
        bridge = None
        def send(kind, message_id, payload):
            if kind == "external-round":
                bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "roadex-callback-v7", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
                return {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}}
            return {"accepted": True}
        bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / f"{outcome}.sqlite3"), dispatcher=lambda *_: "fresh-dispatch", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
        bridge.receive_external_round(external_payload())
        bridge.decide("roadex:external:reconcile-1", outcome, "human-user", "not approved")
        assert bridge.store.decision("roadex:external:reconcile-1")[2] == "rejected"
        assert bridge.store.external_execution("reconcile-1")["receipt"]["decisionStatus"] == "rejected"
        try:
            bridge.request_round({"roundId": "fresh-round", "projectId": "arcade", "projectLeadId": "lead-1", "planId": "plan-1", "planVersion": "v1", "correlationId": "fresh-corr", "idempotencyKey": "fresh-round", "snapshotId": "snapshot-2", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "gate-proximity"})
        except ValueError as error:
            assert str(error) == "decision_pending"
        else:
            raise AssertionError("rejected external gate released a round")


def test_external_decision_restart_repairs_interstep_settlement_and_expired_outcome(tmp_path: Path):
    forwarded = []
    bridge = None
    def send(kind, message_id, payload):
        forwarded.append((kind, message_id, payload))
        if kind == "external-round":
            bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "roadex-callback-v7", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
        return {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}} if kind == "external-round" else {"accepted": True}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.receive_external_round(external_payload())
    def crash_before_settlement(*args, **kwargs):
        raise RuntimeError("crash before settlement")
    bridge.store.settle_external_decision = crash_before_settlement
    try:
        bridge.decide("roadex:external:reconcile-1", "approve", "human-user", "approved")
    except RuntimeError as error:
        assert "crash" in str(error)
    else:
        raise AssertionError("inter-step crash was not reproduced")
    restarted = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert restarted.store.decision("roadex:external:reconcile-1")[2] == "approved"
    assert restarted.store.external_execution("reconcile-1")["receipt"]["decisionStatus"] == "approved"
    assert len([item for item in forwarded if item[0] == "decision-outcome"]) == 2

    expired_bridge = None
    def expired_send(kind, message_id, payload):
        if kind == "external-round":
            expired_bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "roadex-callback-v7", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
            return {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}}
        return {"accepted": True}
    expired_bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "expired.sqlite3"), dispatcher=lambda *_: "unused", sender=expired_send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    expired_bridge.receive_external_round(external_payload())
    expired_bridge.receive_external_decision_outcome({"decisionId": "roadex:external:reconcile-1", "status": "expired"})
    assert expired_bridge.store.decision("roadex:external:reconcile-1")[2] == "expired"
    assert expired_bridge.store.external_execution("reconcile-1")["receipt"]["decisionStatus"] == "expired"


def test_external_gate_binds_callback_workflow_and_rejects_conflicting_workflow(tmp_path: Path):
    bridge = None
    def send(kind, message_id, payload):
        if kind == "external-round":
            bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "configured-roadex-workflow", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
        return {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.receive_external_round(external_payload())
    assert bridge.store.external_execution("reconcile-1")["gateWorkflowId"] == "configured-roadex-workflow"
    try:
        bridge.stage_decision({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": "wrong-workflow", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
    except ValueError as error:
        assert "workflow" in str(error)
    else:
        raise AssertionError("conflicting callback workflow was accepted")


def test_external_callback_validates_before_mutation_wrong_first_then_correct_retry_and_restart(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    bridge.receive_external_round(external_payload())
    malformed = {"decisionId": "roadex:external:reconcile-1", "projectId": "wrong-project", "planId": "plan-1", "workflowId": "configured-roadex-workflow", "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]}
    try:
        bridge.stage_decision(malformed)
    except ValueError as error:
        assert "identity" in str(error)
    else:
        raise AssertionError("malformed first callback was accepted")
    assert bridge.store.decision("roadex:external:reconcile-1") is None
    assert bridge.store.external_execution("reconcile-1")["gateWorkflowId"] is None
    correct = {**malformed, "projectId": "arcade"}
    assert bridge.stage_decision(correct)["accepted"] is True
    restarted = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert restarted.stage_decision(correct)["accepted"] is True
    assert restarted.store.external_execution("reconcile-1")["gateWorkflowId"] == "configured-roadex-workflow"


def test_external_first_callbacks_serialize_one_exact_winner_and_conflicting_loser(tmp_path: Path):
    seed = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    seed.receive_external_round(external_payload())
    requests = []
    for workflow in ("workflow-a", "workflow-b"):
        requests.append({"decisionId": "roadex:external:reconcile-1", "projectId": "arcade", "planId": "plan-1", "workflowId": workflow, "decisionVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "roadex:external:reconcile-1", "question": "approve next round", "resultProvenanceId": external_payload()["digest"]})
    def callback(request):
        bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
        try:
            return bridge.stage_decision(request)
        except ValueError as error:
            return str(error)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(callback, requests))
    assert sum(result == {"accepted": True, "receipt": {**requests[index], "sourceId": "overseer", "provenanceId": f"roadex:{requests[index]['decisionId']}", "status": "staged"}} for index, result in enumerate(results)) == 1
    winner = PsychloBridgeStore(tmp_path / "bridge.sqlite3").external_execution("reconcile-1")
    assert winner["gateWorkflowId"] in {"workflow-a", "workflow-b"}
