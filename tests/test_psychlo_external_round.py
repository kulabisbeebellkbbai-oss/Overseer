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
    assert any(item[0] == "decision-stage" for item in forwarded)


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
