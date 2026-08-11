from __future__ import annotations

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
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda kind, message_id, payload: forwarded.append((kind, message_id, payload)) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    receipt = bridge.receive_external_round(external_payload())
    assert receipt["status"] == "reconciled"
    assert bridge.store.external_execution("reconcile-1") is not None
    assert bridge.store.active_round() is None
    assert forwarded[0][0] == "external-round"
    assert not any(item[0] == "decision-stage" for item in forwarded)
    assert bridge.store.decision("roadex:external:reconcile-1") is None


def test_external_round_uses_exact_psychlo_gate_receipt_once(tmp_path: Path):
    forwarded = []
    def send(kind, message_id, payload):
        forwarded.append((kind, message_id, payload))
        return {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    first = bridge.receive_external_round(external_payload())
    replay = bridge.receive_external_round(external_payload())
    assert first["decisionId"] == replay["decisionId"] == "roadex:external:reconcile-1"
    assert [item[0] for item in forwarded] == ["external-round"]
    assert bridge.store.decision("roadex:external:reconcile-1") is None


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


def test_approved_external_outcome_releases_only_a_fresh_bounded_round(tmp_path: Path):
    dispatched = []
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda lead, prompt: dispatched.append((lead, prompt)) or "fresh-dispatch", sender=lambda *_: {"accepted": True, "receipt": {"decisionId": "roadex:external:reconcile-1", "decisionStatus": "pending"}}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=lambda: "fresh-capability-1234567890abcdef")
    bridge.receive_external_round(external_payload())
    request = {"roundId": "fresh-round", "projectId": "arcade", "projectLeadId": "lead-1", "planId": "plan-1", "planVersion": "v1", "correlationId": "fresh-corr", "idempotencyKey": "fresh-round", "snapshotId": "snapshot-2", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "approved continuation"}
    try:
        bridge.request_round(request)
    except ValueError as error:
        assert str(error) == "decision_pending"
    else:
        raise AssertionError("pending external decision did not block dispatch")
    bridge.receive_external_decision_outcome({"decisionId": "roadex:external:reconcile-1", "status": "approved"})
    bridge.request_round(request)
    assert len(dispatched) == 1
