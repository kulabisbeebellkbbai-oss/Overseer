from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import subprocess

import pytest

from overseer.admin import approve_admin_change_plan, cancel_admin_change_plan, plan_psychlo_legacy_process_observation
from overseer.psychlo_bridge import PsychloBridge
from overseer.psychlo_process_attestation import admin_plan_digest, manifest_digest
from overseer.psychlo_store import PsychloBridgeStore
from overseer.psychlo_legacy_abandonment import (
    LegacyAbandonmentError,
    execute_legacy_abandonment,
    finalize_legacy_abandonment,
    stage_legacy_abandonment,
)
from overseer.psychlo_contracts import canonical_digest
from overseer.store import SQLiteStore
from tests.test_psychlo_process_attestation_v2 import _manifest as _process_manifest


NOW = "2099-01-01T00:00:10+00:00"
ENVELOPE_SCHEMA = "overseer.psychlo.legacy-round-abandon-envelope.v1"
ENVELOPE_SCHEMA_V2 = "overseer.psychlo.legacy-round-abandon-envelope.v2"


def _payload_action(payload):
    return payload.get("action", payload)


def _runtime(tmp_path, *, sender=None, observation_approved_at=NOW, request_thread_id="old-conversation"):
    bridge_store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    request = {
        "roundId": "round-arcade", "projectId": "arcade", "projectLeadId": "hermione",
        "planId": "arcade-plan", "planVersion": "1.0",
        "snapshotId": "snapshot-1", "policyVersion": "policy-1", "correlationId": "corr-1", "idempotencyKey": "idem-1",
        "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected",
        "priorityRationale": "manual-priority",
    }
    if request_thread_id is not None:
        request["threadId"] = request_thread_id
    receipt = {**request, "sourceId": "hermione", "provenanceId": "overseer-dispatch:round-arcade", "status": "accepted"}
    capability = "capability-arcade-123"
    binding = {"conversationId": "old-conversation", "sessionId": "old-session"}
    bridge_store.record_round(request, receipt, capability)
    bridge_store.start_round_dispatch("round-arcade", request, capability, NOW, binding=binding, prompt_digest="4" * 64)
    bridge_store.record_round_prompt_delivery_phase("round-arcade", request, capability, binding, "4" * 64, "submitted", now=NOW, expected_phase="prepared")
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    request_digest = bridge_store._round_request_digest(request)
    capability_hash = bridge_store.connection.execute("SELECT capability_hash FROM rounds WHERE round_id='round-arcade'").fetchone()[0]
    binding_digest = __import__("hashlib").sha256(json.dumps(binding, separators=(",", ":")).encode()).hexdigest()
    delivery = bridge_store.round_prompt_delivery("round-arcade")
    delivery_digest = __import__("overseer.psychlo_legacy_abandonment", fromlist=["_delivery_digest"])._delivery_digest(delivery)
    manifest = _process_manifest("round-arcade", "observation-plan")
    manifest["requestDigest"] = request_digest
    manifest["bridge"] = {"dispatchState": "started", "resultPresent": False, "deliveryPhase": "submitted", "recoveryPresent": False, "failurePresent": False, "cancelPresent": False, "requestDigest": request_digest, "capabilityHash": capability_hash, "bindingDigest": binding_digest, "promptDigest": "4" * 64}
    observation_digest = manifest_digest(manifest)
    source = manifest["source"]
    observation_plan = plan_psychlo_legacy_process_observation("observation-plan", "round-arcade", observation_digest, source["commit"], source["treeDigest"], source["moduleDigest"])
    primary.save_admin_change_plan(approve_admin_change_plan(observation_plan, "sisko", observation_approved_at))
    primary._connection.execute("INSERT INTO psychlo_process_observations(observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at) VALUES (?,?,?,?,?,'recorded',?,?,?)", ("observation-round-arcade", "round-arcade", "observation-plan", observation_digest, admin_plan_digest(primary.load_admin_change_plan("observation-plan")), json.dumps(manifest, sort_keys=True, separators=(",", ":")), NOW, NOW))
    primary._connection.commit()
    sent = []
    if sender is None:
        def sender(kind, key, payload):
            sent.append((kind, key, payload))
            action = _payload_action(payload)
            return {"accepted": True, "actionId": action["actionId"], "actionDigest": action["actionDigest"], "roundId": action["roundId"], "requestDigest": action["requestDigest"], "status": "legacy-abandoned-uncertain", "status_code": 202}
    bridge = PsychloBridge(store=bridge_store, dispatcher=lambda *args: "", sender=sender, callback_origin="http://127.0.0.1", approval_store=primary, clock=lambda: NOW, recover=False)
    bridge._test_sent = sent
    return bridge, primary


def _stage(bridge):
    return stage_legacy_abandonment(bridge=bridge, plan_id="abandon-plan", observation_plan_id="observation-plan", round_id="round-arcade", successor_plan_id="arcade-plan-2", successor_plan_version="2.0", successor_conversation_id="new-conversation", successor_thread_id="new-thread")


def _stage_v2(bridge):
    return stage_legacy_abandonment(bridge=bridge, plan_id="abandon-plan", observation_plan_id="observation-plan", round_id="round-arcade", successor_plan_id="arcade-plan-2", successor_plan_version="2.0", successor_conversation_id="new-conversation", successor_thread_id="new-thread", delivery_conversation_id="old-conversation")


def test_v2_historical_misbinding_freezes_both_thread_identities_and_replays_exact_envelope(tmp_path):
    bridge, primary = _runtime(tmp_path, request_thread_id="requested-thread")
    binding_before = bridge.store.round_binding("round-arcade")
    staged = _stage_v2(bridge)
    intent = bridge.store.legacy_abandonment(staged["actionId"])
    action = intent["payload"]
    plan = primary.load_admin_change_plan("abandon-plan")
    metadata = plan.adapter_metadata["legacy_abandonment"]
    assert action["requestedThreadId"] == "requested-thread"
    assert action["deliveryConversationId"] == "old-conversation"
    assert action["originalPlan"]["conversationId"] == "old-conversation"
    assert action["originalPlan"]["threadId"] == "requested-thread"
    assert metadata["requestedThreadId"] == "requested-thread"
    assert metadata["deliveryConversationId"] == "old-conversation"
    assert metadata["bindingDigest"] == action["delivery"]["bindingDigest"]
    assert metadata["promptDigest"] == action["delivery"]["promptDigest"]
    assert bridge.store.round_binding("round-arcade") == binding_before

    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", NOW))
    execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    envelope = bridge._test_sent[0][2]
    assert set(envelope) == {"schemaVersion", "action", "requestedThreadId", "deliveryConversationId"}
    assert envelope["schemaVersion"] == ENVELOPE_SCHEMA_V2
    assert envelope["requestedThreadId"] == "requested-thread"
    assert envelope["deliveryConversationId"] == "old-conversation"
    assert envelope["action"] == action["wire"]
    replay = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert replay["replay"] is True
    assert len(bridge._test_sent) == 1
    assert bridge.store.round_binding("round-arcade") == binding_before


def test_v2_historical_misbinding_requires_the_immutable_delivery_binding(tmp_path):
    bridge, _primary = _runtime(tmp_path, request_thread_id="requested-thread")
    with pytest.raises(LegacyAbandonmentError, match="delivery conversation.*binding"):
        stage_legacy_abandonment(
            bridge=bridge, plan_id="abandon-plan", observation_plan_id="observation-plan",
            round_id="round-arcade", successor_plan_id="arcade-plan-2",
            successor_plan_version="2.0", successor_conversation_id="new-conversation",
            successor_thread_id="new-thread", delivery_conversation_id="arbitrary-conversation",
        )


def test_v2_historical_misbinding_is_only_stageable_for_submitted_delivery(tmp_path):
    bridge, _primary = _runtime(tmp_path, request_thread_id="requested-thread")
    bridge.store.connection.execute(
        "UPDATE round_prompt_deliveries SET phase='prepared' WHERE round_id=?",
        ("round-arcade",),
    )
    with pytest.raises(LegacyAbandonmentError, match="submitted prompt delivery"):
        _stage_v2(bridge)
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2") is None


def test_v2_historical_misbinding_rejects_tampered_frozen_identity_before_send(tmp_path):
    bridge, primary = _runtime(tmp_path, request_thread_id="requested-thread")
    staged = _stage_v2(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    intent = bridge.store.legacy_abandonment(staged["actionId"])
    payload = intent["payload"]
    payload["requestedThreadId"] = "attacker-thread"
    bridge.store.connection.execute(
        "UPDATE legacy_abandonment_intents SET payload_json=? WHERE action_id=?",
        (json.dumps(payload, separators=(",", ":")), staged["actionId"]),
    )
    with pytest.raises(LegacyAbandonmentError, match="plan or action identity changed"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge._test_sent == []


def test_stage_is_high_human_sisko_and_non_executable(tmp_path):
    bridge, primary = _runtime(tmp_path)
    result = _stage(bridge)
    plan = primary.load_admin_change_plan("abandon-plan")
    assert result["state"] == "claimed"
    assert plan.kind.value == "psychlo_legacy_abandonment"
    assert plan.risk_level.value == "high" and plan.approval_level.value == "human" and plan.owner_domain.value == "sisko"
    assert plan.can_execute() is False
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "submitted"


def test_stage_exact_replay_returns_frozen_intent_and_divergence_conflicts(tmp_path):
    bridge, primary = _runtime(tmp_path)
    first = _stage(bridge)
    replay = _stage(bridge)
    assert replay["replayed"] is True
    assert replay["actionDigest"] == first["actionDigest"]
    with pytest.raises(LegacyAbandonmentError, match="identity conflict"):
        stage_legacy_abandonment(
            bridge=bridge, plan_id="abandon-plan", observation_plan_id="observation-plan",
            round_id="round-arcade", successor_plan_id="arcade-plan-2",
            successor_plan_version="2.0", successor_conversation_id="new-conversation",
            successor_thread_id="divergent-thread",
        )


@pytest.mark.parametrize(
    ("conversation_id", "thread_id"),
    [("old-conversation", "new-thread"), ("new-conversation", "old-conversation")],
)
def test_successor_conversation_and_thread_must_each_be_distinct(tmp_path, conversation_id, thread_id):
    bridge, primary = _runtime(tmp_path)
    with pytest.raises((LegacyAbandonmentError, ValueError), match="successor.*distinct"):
        stage_legacy_abandonment(
            bridge=bridge, plan_id="abandon-plan", observation_plan_id="observation-plan",
            round_id="round-arcade", successor_plan_id="arcade-plan-2",
            successor_plan_version="2.0", successor_conversation_id=conversation_id,
            successor_thread_id=thread_id,
        )


def test_stage_derives_original_thread_from_binding_for_canonical_request_without_thread_id(tmp_path):
    bridge, primary = _runtime(tmp_path, request_thread_id=None)

    staged = _stage(bridge)

    intent = bridge.store.legacy_abandonment(staged["actionId"])
    assert intent["payload"]["originalPlan"]["threadId"] == "old-conversation"
    plan = primary.load_admin_change_plan("abandon-plan")
    assert plan.adapter_metadata["legacy_abandonment"]["originalThreadId"] == "old-conversation"


def test_stage_rejects_legacy_request_thread_that_differs_from_binding(tmp_path):
    bridge, _primary_store = _runtime(tmp_path, request_thread_id="different-thread")

    with pytest.raises(LegacyAbandonmentError, match="original thread.*binding"):
        _stage(bridge)


def test_stage_rejects_invalid_legacy_request_thread_even_when_binding_is_valid(tmp_path):
    bridge, _primary_store = _runtime(tmp_path, request_thread_id="invalid thread")

    with pytest.raises(LegacyAbandonmentError, match="original thread id is invalid"):
        _stage(bridge)


def test_execute_fences_delivery_and_persists_terminal_non_result(tmp_path):
    bridge, primary = _runtime(tmp_path)
    staged = _stage(bridge)
    frozen_intent = bridge.store.legacy_abandonment(staged["actionId"])
    frozen_wire = frozen_intent["payload"]["wire"]
    plan = primary.load_admin_change_plan("abandon-plan")
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", NOW))
    result = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert result["status"] == "legacy-abandoned-uncertain"
    record = bridge.store.get_round("round-arcade")
    assert record[4] == "legacy-abandoned" and record[5] is None and record[6] is False
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "abandonment-fence"
    assert bridge.store.legacy_abandonment(result["actionId"])["state"] == "completed"
    assert bridge._test_sent[0][0] == "round-legacy-abandon"
    envelope = bridge._test_sent[0][2]
    assert set(envelope) == {"schemaVersion", "action", "originalConversationId"}
    assert envelope["schemaVersion"] == ENVELOPE_SCHEMA
    assert envelope["originalConversationId"] == "old-conversation"
    wire = envelope["action"]
    assert wire == frozen_wire
    assert wire["actionDigest"] == staged["actionDigest"]
    assert bridge.store.legacy_abandonment(staged["actionId"])["payload"]["wire"] == frozen_wire
    assert wire["schemaVersion"] == "psychlo.legacy-round-abandon.v1"
    assert {key: wire[key] for key in ("successorPlanId", "successorPlanVersion", "successorConversationId", "successorThreadId")} == {"successorPlanId": "arcade-plan-2", "successorPlanVersion": "2.0", "successorConversationId": "new-conversation", "successorThreadId": "new-thread"}
    assert wire["actionDigest"] == canonical_digest({key: value for key, value in wire.items() if key != "actionDigest"})
    replay = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert replay["replay"] is True


def test_signed_wire_successor_identity_cannot_be_substituted(tmp_path):
    bridge, primary = _runtime(tmp_path)
    staged = _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    intent = bridge.store.legacy_abandonment(staged["actionId"])
    payload = intent["payload"]
    payload["wire"]["successorConversationId"] = "substituted-conversation"
    bridge.store.connection.execute(
        "UPDATE legacy_abandonment_intents SET payload_json=? WHERE action_id=?",
        (json.dumps(payload, separators=(",", ":")), staged["actionId"]),
    )
    with pytest.raises(LegacyAbandonmentError, match="wire binding changed"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge._test_sent == []


def test_transport_original_conversation_substitution_is_rejected_before_send(tmp_path):
    bridge, primary = _runtime(tmp_path)
    staged = _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    intent = bridge.store.legacy_abandonment(staged["actionId"])
    payload = intent["payload"]
    payload["originalPlan"]["conversationId"] = "substituted-conversation"
    bridge.store.connection.execute(
        "UPDATE legacy_abandonment_intents SET payload_json=? WHERE action_id=?",
        (json.dumps(payload, separators=(",", ":")), staged["actionId"]),
    )

    with pytest.raises(LegacyAbandonmentError, match="plan or action identity changed"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")

    assert bridge._test_sent == []


def test_existing_peer_pending_approved_claim_resumes_with_transport_envelope(tmp_path):
    from overseer.psychlo_legacy_abandonment import _immutable_plan_digest

    bridge, primary = _runtime(tmp_path)
    staged = _stage(bridge)
    approved = approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW)
    primary.save_admin_change_plan(approved)
    intent = bridge.store.legacy_abandonment(staged["actionId"])
    frozen_payload = json.loads(json.dumps(intent["payload"]))
    bridge.store.claim_legacy_abandonment(staged["actionId"], staged["actionDigest"], now=NOW)
    primary.claim_psychlo_legacy_abandonment_execution(
        "abandon-plan", staged["actionId"], staged["actionDigest"],
        _immutable_plan_digest(approved), claimed_at=NOW,
    )

    result = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")

    assert result["status"] == "legacy-abandoned-uncertain"
    envelope = bridge._test_sent[0][2]
    assert envelope == {
        "schemaVersion": ENVELOPE_SCHEMA,
        "action": frozen_payload["wire"],
        "originalConversationId": frozen_payload["originalPlan"]["conversationId"],
    }
    completed = bridge.store.legacy_abandonment(staged["actionId"])
    assert completed["payload"] == frozen_payload
    assert completed["actionDigest"] == staged["actionDigest"]


def test_wire_is_accepted_by_psychlo_contract_parser(tmp_path):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    wire = bridge._test_sent[0][2]["action"]
    configured = os.environ.get("PSYCHLO_LEGACY_ABANDONMENT_PARSER")
    workspace = Path(__file__).resolve().parents[4]
    candidates = [
        Path(configured) if configured else None,
        workspace / "Psychlo" / ".worktrees" / "psychlo-legacy-abandon" / "dist" / "contracts" / "legacy-round-abandonment.js",
        workspace / "Psychlo" / "dist" / "contracts" / "legacy-round-abandonment.js",
    ]
    parser = next((candidate for candidate in candidates if candidate is not None and candidate.is_file()), None)
    if parser is None:
        pytest.skip("Psychlo legacy abandonment contract parser is not built")
    local_fixture = json.loads((Path(__file__).parent / "fixtures" / "psychlo-f0015d6-overseer-peer-fixtures.json").read_text(encoding="utf-8"))["legacyRoundAbandonment"]
    psychlo_fixture_path = parser.parents[2] / "docs" / "contracts" / "psychlo-overseer-peer-fixtures.json"
    psychlo_fixture = json.loads(psychlo_fixture_path.read_text(encoding="utf-8"))["legacyRoundAbandonment"]
    assert local_fixture == psychlo_fixture
    fixture_action = local_fixture["action"]
    fixture_body = {key: value for key, value in fixture_action.items() if key != "actionDigest"}
    assert json.dumps(fixture_body, sort_keys=True, separators=(",", ":")) == local_fixture["canonicalActionBody"]
    assert canonical_digest(fixture_body) == "d03a56210541ffb2307dbabba647fe80ef71bef8682b8b0795225b1c761fa56c"
    script = """
const { parseLegacyRoundAbandonment } = await import(process.argv[1]);
let body = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => body += chunk);
process.stdin.on('end', () => process.stdout.write(JSON.stringify(parseLegacyRoundAbandonment(JSON.parse(body)))));
"""
    completed = subprocess.run(
        ["node", "--input-type=module", "-e", script, parser.as_uri()],
        input=json.dumps(wire), text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == wire


def test_transport_failure_leaves_replayable_outbox(tmp_path):
    calls = []
    def sender(kind, key, payload):
        calls.append(payload)
        if len(calls) == 1:
            raise RuntimeError("transport down")
        action = _payload_action(payload)
        return {"accepted": True, "actionId": action["actionId"], "actionDigest": action["actionDigest"], "roundId": action["roundId"], "requestDigest": action["requestDigest"], "status": "legacy-abandoned-uncertain", "status_code": 202}
    bridge, primary = _runtime(tmp_path, sender=sender)
    _stage(bridge)
    plan = primary.load_admin_change_plan("abandon-plan")
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", NOW))
    with pytest.raises(RuntimeError):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    action_id = "legacy-abandonment:round-arcade:arcade-plan-2"
    assert bridge.store.legacy_abandonment(action_id)["state"] == "peer-pending"
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "abandonment-fence"
    result = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert result["status"] == "legacy-abandoned-uncertain"
    assert calls[0] == calls[1]
    assert json.dumps(calls[0], sort_keys=True, separators=(",", ":")) == json.dumps(calls[1], sort_keys=True, separators=(",", ":"))


def test_cancellation_wins_before_authoritative_execution_claim(tmp_path):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    approved = approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW)
    primary.save_admin_change_plan(approved)
    primary.save_admin_change_plan(cancel_admin_change_plan(approved, "sisko", "withdrawn", NOW))
    with pytest.raises(LegacyAbandonmentError, match="approved Sisko plan"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge._test_sent == []
    assert primary.psychlo_legacy_abandonment_execution_claim("abandon-plan") is None
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")["state"] == "claimed"
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "submitted"


@pytest.mark.parametrize("competitor", ["recovery", "failure", "cancellation"])
def test_competing_bridge_intent_wins_without_sticking_authority_claim(tmp_path, competitor):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    approved = approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW)
    primary.save_admin_change_plan(approved)
    store = bridge.store
    if competitor == "recovery":
        store.connection.execute("INSERT INTO round_recoveries(round_id,request_digest,capability_hash,idempotency_key,state,updated_at) VALUES (?,?,?,?,?,?)", ("round-arcade", "1" * 64, "2" * 64, "recovery-idem", "uncertain", NOW))
    elif competitor == "failure":
        store.connection.execute("INSERT INTO operational_failure_intents(round_id,request_digest,capability_hash,idempotency_key,payload_json,payload_digest,state,updated_at) VALUES (?,?,?,?,?,?,?,?)", ("round-arcade", "1" * 64, "2" * 64, "failure-idem", "{}", "3" * 64, "queued", NOW))
    else:
        store.connection.execute("INSERT INTO round_cancellations(cancellation_id,round_id,request_digest,attestation_json,receipt_json,inserted_at) VALUES (?,?,?,?,?,?)", ("cancel", "round-arcade", "1" * 64, "{}", "{}", NOW))
    with pytest.raises((LegacyAbandonmentError, ValueError)):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge._test_sent == []
    assert primary.psychlo_legacy_abandonment_execution_claim("abandon-plan") is None
    replacement = replace(approved, reason="replacement remains possible before execution claim")
    primary.save_admin_change_plan(replacement)
    assert primary.load_admin_change_plan("abandon-plan").reason == replacement.reason
    primary.save_admin_change_plan(cancel_admin_change_plan(replacement, "sisko", "competitor won", NOW))
    assert primary.load_admin_change_plan("abandon-plan").canceled is True


def test_primary_claim_failure_releases_unsent_bridge_reservation(tmp_path, monkeypatch):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    approved = approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW)
    primary.save_admin_change_plan(approved)
    monkeypatch.setattr(
        primary,
        "claim_psychlo_legacy_abandonment_execution",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("authority changed")),
    )
    with pytest.raises(LegacyAbandonmentError, match="execution claim failed"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge._test_sent == []
    intent = bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")
    assert intent["state"] == "claimed"
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "submitted"
    primary.save_admin_change_plan(cancel_admin_change_plan(approved, "sisko", "claim failed", NOW))


def test_crash_after_bridge_reservation_can_be_canceled_and_releases_on_replay(tmp_path, monkeypatch):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    approved = approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW)
    primary.save_admin_change_plan(approved)
    original_claim = primary.claim_psychlo_legacy_abandonment_execution
    monkeypatch.setattr(
        primary,
        "claim_psychlo_legacy_abandonment_execution",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("crash before primary claim")),
    )
    with pytest.raises(RuntimeError, match="crash before primary claim"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert primary.psychlo_legacy_abandonment_execution_claim("abandon-plan") is None
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")["state"] == "peer-pending"
    primary.save_admin_change_plan(cancel_admin_change_plan(approved, "sisko", "cancel after crash", NOW))
    monkeypatch.setattr(primary, "claim_psychlo_legacy_abandonment_execution", original_claim)
    with pytest.raises(LegacyAbandonmentError, match="approved Sisko plan"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge._test_sent == []
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")["state"] == "claimed"
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "submitted"


def test_crash_after_primary_claim_keeps_fence_and_retries_exactly(tmp_path, monkeypatch):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    approved = approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW)
    primary.save_admin_change_plan(approved)
    original_claim = primary.claim_psychlo_legacy_abandonment_execution
    def claim_then_crash(*args, **kwargs):
        original_claim(*args, **kwargs)
        raise RuntimeError("crash after primary claim")
    monkeypatch.setattr(primary, "claim_psychlo_legacy_abandonment_execution", claim_then_crash)
    with pytest.raises(RuntimeError, match="crash after primary claim"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge._test_sent == []
    assert primary.psychlo_legacy_abandonment_execution_claim("abandon-plan")["state"] == "claimed"
    with pytest.raises(ValueError, match="execution claim"):
        primary.save_admin_change_plan(cancel_admin_change_plan(approved, "sisko", "too late", NOW))
    monkeypatch.setattr(primary, "claim_psychlo_legacy_abandonment_execution", original_claim)
    result = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert result["status"] == "legacy-abandoned-uncertain"
    assert len(bridge._test_sent) == 1


def test_execution_claim_wins_and_prohibits_late_cancellation(tmp_path):
    def unavailable(*_args):
        raise RuntimeError("transport down")
    bridge, primary = _runtime(tmp_path, sender=unavailable)
    _stage(bridge)
    approved = approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW)
    primary.save_admin_change_plan(approved)
    with pytest.raises(RuntimeError, match="transport down"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    claim = primary.psychlo_legacy_abandonment_execution_claim("abandon-plan")
    assert claim is not None and claim["state"] == "claimed"
    with pytest.raises(ValueError, match="execution claim"):
        primary.save_admin_change_plan(cancel_admin_change_plan(approved, "sisko", "too late", NOW))
    assert primary.load_admin_change_plan("abandon-plan").canceled is False


def test_crash_after_bridge_completion_replays_without_resending(tmp_path, monkeypatch):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    original_complete = primary.complete_psychlo_legacy_abandonment_execution
    failures = 0
    def crash_once(*args, **kwargs):
        nonlocal failures
        failures += 1
        if failures == 1:
            raise RuntimeError("primary completion crash")
        return original_complete(*args, **kwargs)
    monkeypatch.setattr(primary, "complete_psychlo_legacy_abandonment_execution", crash_once)
    with pytest.raises(RuntimeError, match="primary completion crash"):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert len(bridge._test_sent) == 1
    replay = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert replay["replay"] is True
    assert len(bridge._test_sent) == 1
    assert primary.psychlo_legacy_abandonment_execution_claim("abandon-plan")["state"] == "completed"


def test_invalid_peer_response_remains_pending_and_replays_after_remote_commit(tmp_path):
    calls = []
    def sender(kind, key, payload):
        calls.append(dict(payload))
        action = _payload_action(payload)
        if len(calls) == 1:
            # The receiver may have committed before its response was
            # truncated or corrupted in transport.
            return {"accepted": True, "actionId": action["actionId"]}
        return {"accepted": True, "actionId": action["actionId"], "actionDigest": action["actionDigest"], "roundId": action["roundId"], "requestDigest": action["requestDigest"], "status": "already-abandoned", "status_code": 202}
    bridge, primary = _runtime(tmp_path, sender=sender)
    _stage(bridge)
    plan = primary.load_admin_change_plan("abandon-plan")
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", NOW))
    with pytest.raises(LegacyAbandonmentError):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")["state"] == "peer-pending"
    assert bridge.store.get_round("round-arcade")[4] == "started"
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "abandonment-fence"
    result = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert result["status"] == "legacy-abandoned-uncertain"
    assert calls[0] == calls[1]


@pytest.mark.parametrize("invalid", [None, {}, {"accepted": False}, "truncated"])
def test_every_unverifiable_peer_response_stays_replayable(tmp_path, invalid):
    bridge, primary = _runtime(tmp_path, sender=lambda *_args: invalid)
    _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    with pytest.raises(LegacyAbandonmentError):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    intent = bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")
    assert intent["state"] == "peer-pending" and intent["receipt"] is None
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "abandonment-fence"


@pytest.mark.parametrize("status_code", [200, 201, 409, "202", None])
def test_peer_transport_status_must_be_exact_for_abandonment(tmp_path, status_code):
    def sender(_kind, _key, payload):
        action = _payload_action(payload)
        response = {"accepted": True, "actionId": action["actionId"], "actionDigest": action["actionDigest"], "roundId": action["roundId"], "requestDigest": action["requestDigest"], "status": "already-abandoned"}
        if status_code is not None:
            response["status_code"] = status_code
        return response
    bridge, primary = _runtime(tmp_path, sender=sender)
    _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    with pytest.raises(LegacyAbandonmentError):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")["state"] == "peer-pending"


def test_peer_response_rejects_extra_transport_or_body_fields(tmp_path):
    def sender(_kind, _key, payload):
        action = _payload_action(payload)
        return {"accepted": True, "actionId": action["actionId"], "actionDigest": action["actionDigest"], "roundId": action["roundId"], "requestDigest": action["requestDigest"], "status": "already-abandoned", "status_code": 202, "extra": "forbidden"}
    bridge, primary = _runtime(tmp_path, sender=sender)
    _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    with pytest.raises(LegacyAbandonmentError):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")["state"] == "peer-pending"


def test_abandonment_fence_rejects_recovery_and_late_result(tmp_path):
    bridge, primary = _runtime(tmp_path)
    staged = _stage(bridge)
    bridge.store.claim_legacy_abandonment(staged["actionId"], staged["actionDigest"], now=NOW)
    request, _receipt, _hash, capability, _state, _result, _forwarded = bridge.store.get_round("round-arcade")
    with pytest.raises(ValueError, match="fenced by legacy abandonment"):
        bridge.store.claim_round_recovery("round-arcade", request, capability, owner_id="owner", lease_expires_at="2099-01-01T00:01:00+00:00", now=NOW)
    with pytest.raises(ValueError, match="fenced or no longer expected"):
        bridge.store.record_result("round-arcade", {"roundId": "round-arcade", "occurredAt": NOW}, NOW)


def test_competing_recovery_wins_before_abandonment_claim(tmp_path):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    plan = primary.load_admin_change_plan("abandon-plan")
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", NOW))
    request, _receipt, _hash, capability, _state, _result, _forwarded = bridge.store.get_round("round-arcade")
    assert bridge.store.claim_round_recovery("round-arcade", request, capability, owner_id="owner", lease_expires_at="2099-01-01T00:01:00+00:00", now=NOW)
    with pytest.raises(LegacyAbandonmentError):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")


def test_only_known_terminal_states_release_single_stream(tmp_path):
    bridge, primary = _runtime(tmp_path)
    bridge.store.connection.execute("UPDATE rounds SET dispatch_state='future-terminal-looking' WHERE round_id='round-arcade'")
    assert bridge.store.active_round() == "round-arcade"
    with pytest.raises(ValueError, match="single_stream_busy"):
        bridge.store.record_single_stream_round({"roundId": "round-next"}, {}, "capability-next")
    bridge.store.connection.execute("UPDATE rounds SET dispatch_state='legacy-abandoned' WHERE round_id='round-arcade'")
    assert bridge.store.active_round() is None
    bridge.store.record_single_stream_round({"roundId": "round-next"}, {}, "capability-next")


@pytest.mark.parametrize("competitor", ["recovery", "failure", "cancellation"])
def test_abandonment_claim_rejects_every_competing_intent(tmp_path, competitor):
    bridge, primary = _runtime(tmp_path)
    staged = _stage(bridge)
    store = bridge.store
    if competitor == "recovery":
        store.connection.execute("INSERT INTO round_recoveries(round_id,request_digest,capability_hash,idempotency_key,state,updated_at) VALUES (?,?,?,?,?,?)", ("round-arcade", "1" * 64, "2" * 64, "recovery-idem", "uncertain", NOW))
    elif competitor == "failure":
        store.connection.execute("INSERT INTO operational_failure_intents(round_id,request_digest,capability_hash,idempotency_key,payload_json,payload_digest,state,updated_at) VALUES (?,?,?,?,?,?,?,?)", ("round-arcade", "1" * 64, "2" * 64, "failure-idem", "{}", "3" * 64, "queued", NOW))
    else:
        store.connection.execute("INSERT INTO round_cancellations(cancellation_id,round_id,request_digest,attestation_json,receipt_json,inserted_at) VALUES (?,?,?,?,?,?)", ("cancel", "round-arcade", "1" * 64, "{}", "{}", NOW))
    with pytest.raises(ValueError, match="changed before claim"):
        store.claim_legacy_abandonment(staged["actionId"], staged["actionDigest"], now=NOW)


def test_source_observation_requires_exact_utc_sisko_authority(tmp_path):
    bridge, primary = _runtime(tmp_path, observation_approved_at="2099-01-01T01:00:10+01:00")
    with pytest.raises(LegacyAbandonmentError, match="invalid"):
        _stage(bridge)


def test_strict_distinct_store_guard_rejects_missing_same_alias_and_hardlink(tmp_path):
    from overseer.psychlo_bridge import _strict_distinct_store_paths, create_bridge_from_environment

    bridge = tmp_path / "bridge.sqlite3"
    primary = tmp_path / "primary.sqlite3"
    with pytest.raises(ValueError, match="OVERSEER_STORE_DATABASE"):
        create_bridge_from_environment(
            {"OVERSEER_PSYCHLO_BRIDGE_DATABASE": str(bridge)},
            recover=False,
            require_distinct_authority_store=True,
        )
    with pytest.raises(ValueError, match="required"):
        _strict_distinct_store_paths(None, None)
    with pytest.raises(ValueError, match="preexist|required"):
        _strict_distinct_store_paths(str(bridge), str(primary))
    bridge.touch(mode=0o600)
    primary.touch(mode=0o600)
    with pytest.raises(ValueError, match="distinct"):
        _strict_distinct_store_paths(str(bridge), str(bridge))
    alias = tmp_path / "bridge-alias.sqlite3"
    alias.symlink_to(bridge)
    with pytest.raises(ValueError, match="canonical"):
        _strict_distinct_store_paths(str(alias), str(primary))
    hardlink = tmp_path / "bridge-hardlink.sqlite3"
    os.link(bridge, hardlink)
    with pytest.raises(ValueError, match="unique"):
        _strict_distinct_store_paths(str(bridge), str(primary))
    hardlink.unlink()
    bridge_identity, primary_identity = _strict_distinct_store_paths(str(bridge), str(primary))
    assert bridge_identity != primary_identity


def test_strict_store_accepts_live_style_private_primary_group_parent(tmp_path):
    from overseer.psychlo_bridge import _strict_store_path_identity

    tmp_path.chmod(0o775)
    database = tmp_path / "primary.sqlite3"
    database.touch(mode=0o600)
    path, identity = _strict_store_path_identity(str(database), "primary authority")
    metadata = database.stat()
    assert path == database
    assert identity == (metadata.st_dev, metadata.st_ino)


def test_strict_store_rejects_foreign_group_writable_parent(tmp_path, monkeypatch):
    from overseer import psychlo_bridge

    tmp_path.chmod(0o775)
    database = tmp_path / "primary.sqlite3"
    database.touch(mode=0o600)
    foreign_gid = os.getegid() + 1
    monkeypatch.setattr(psychlo_bridge.os, "getegid", lambda: foreign_gid)
    with pytest.raises(ValueError, match="parent is not trusted"):
        psychlo_bridge._strict_store_path_identity(str(database), "primary authority")


def test_strict_store_rejects_other_writable_parent(tmp_path):
    from overseer.psychlo_bridge import _strict_store_path_identity

    tmp_path.chmod(0o777)
    database = tmp_path / "primary.sqlite3"
    database.touch(mode=0o600)
    with pytest.raises(ValueError, match="parent is not trusted"):
        _strict_store_path_identity(str(database), "primary authority")


def test_strict_store_rejects_symlink_and_noncanonical_path(tmp_path):
    from overseer.psychlo_bridge import _strict_store_path_identity

    database = tmp_path / "primary.sqlite3"
    database.touch(mode=0o600)
    alias = tmp_path / "primary-alias.sqlite3"
    alias.symlink_to(database)
    with pytest.raises(ValueError, match="not canonical"):
        _strict_store_path_identity(str(alias), "primary authority")
    (tmp_path / "nested").mkdir()
    noncanonical = tmp_path / "nested" / ".." / database.name
    with pytest.raises(ValueError, match="not canonical"):
        _strict_store_path_identity(str(noncanonical), "primary authority")


def test_strict_store_rejects_multilink_and_nonprivate_database(tmp_path):
    from overseer.psychlo_bridge import _strict_store_path_identity

    database = tmp_path / "primary.sqlite3"
    database.touch(mode=0o600)
    hardlink = tmp_path / "primary-hardlink.sqlite3"
    os.link(database, hardlink)
    with pytest.raises(ValueError, match="unique owned private"):
        _strict_store_path_identity(str(database), "primary authority")
    hardlink.unlink()
    database.chmod(0o640)
    with pytest.raises(ValueError, match="unique owned private"):
        _strict_store_path_identity(str(database), "primary authority")


def test_legacy_abandonment_cli_requires_strict_distinct_authority_store(monkeypatch):
    from overseer import psychlo_bridge_cli

    calls = []
    marker = object()
    monkeypatch.setattr(
        psychlo_bridge_cli,
        "create_bridge_from_environment",
        lambda *, recover=True, require_distinct_authority_store=False: calls.append((recover, require_distinct_authority_store)) or marker,
    )
    assert psychlo_bridge_cli._create_legacy_abandonment_bridge() is marker
    assert calls == [(False, True)]


def test_every_legacy_abandonment_cli_operation_uses_strict_bridge(monkeypatch, capsys):
    from overseer import psychlo_bridge_cli

    class Bridge:
        def stage_legacy_abandonment(self, **_kwargs):
            return {"staged": True}

        def finalize_legacy_abandonment(self, **_kwargs):
            return {"completed": False}

        def execute_legacy_abandonment(self, **_kwargs):
            return {"accepted": True}

    calls = []
    monkeypatch.setattr(psychlo_bridge_cli, "_create_legacy_abandonment_bridge", lambda: calls.append("strict") or Bridge())
    commands = [
        ["stage-legacy-abandonment", "--round-id", "round", "--plan-id", "plan", "--observation-plan-id", "observation-plan", "--successor-plan-id", "successor", "--successor-plan-version", "2", "--successor-conversation-id", "conversation", "--successor-thread-id", "thread"],
        ["finalize-legacy-abandonment", "--plan-id", "plan"],
        ["execute-legacy-abandonment", "--plan-id", "plan"],
    ]
    for command in commands:
        assert psychlo_bridge_cli.main(command) == 0
    assert calls == ["strict", "strict", "strict"]
    assert len(capsys.readouterr().out.splitlines()) == 3
