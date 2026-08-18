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


def _runtime(tmp_path, *, sender=None, observation_approved_at=NOW):
    bridge_store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    request = {
        "roundId": "round-arcade", "projectId": "arcade", "projectLeadId": "hermione",
        "planId": "arcade-plan", "planVersion": "1.0", "threadId": "old-thread",
        "snapshotId": "snapshot-1", "policyVersion": "policy-1", "correlationId": "corr-1", "idempotencyKey": "idem-1",
    }
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
            return {"accepted": True, "actionId": payload["actionId"], "actionDigest": payload["actionDigest"], "roundId": payload["roundId"], "requestDigest": payload["requestDigest"], "status": "legacy-abandoned-uncertain"}
    bridge = PsychloBridge(store=bridge_store, dispatcher=lambda *args: "", sender=sender, callback_origin="http://127.0.0.1", approval_store=primary, clock=lambda: NOW, recover=False)
    bridge._test_sent = sent
    return bridge, primary


def _stage(bridge):
    return stage_legacy_abandonment(bridge=bridge, plan_id="abandon-plan", observation_plan_id="observation-plan", round_id="round-arcade", successor_plan_id="arcade-plan-2", successor_plan_version="2.0", successor_conversation_id="new-conversation", successor_thread_id="new-thread")


def test_stage_is_high_human_sisko_and_non_executable(tmp_path):
    bridge, primary = _runtime(tmp_path)
    result = _stage(bridge)
    plan = primary.load_admin_change_plan("abandon-plan")
    assert result["state"] == "claimed"
    assert plan.kind.value == "psychlo_legacy_abandonment"
    assert plan.risk_level.value == "high" and plan.approval_level.value == "human" and plan.owner_domain.value == "sisko"
    assert plan.can_execute() is False
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "submitted"


def test_execute_fences_delivery_and_persists_terminal_non_result(tmp_path):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    plan = primary.load_admin_change_plan("abandon-plan")
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", NOW))
    result = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert result["status"] == "legacy-abandoned-uncertain"
    record = bridge.store.get_round("round-arcade")
    assert record[4] == "legacy-abandoned" and record[5] is None and record[6] is False
    assert bridge.store.round_prompt_delivery("round-arcade")["phase"] == "abandonment-fence"
    assert bridge.store.legacy_abandonment(result["actionId"])["state"] == "completed"
    assert bridge._test_sent[0][0] == "round-legacy-abandon"
    assert set(bridge._test_sent[0][2]) == {"schemaVersion", "actionId", "actionDigest", "roundId", "projectId", "requestDigest", "planId", "planVersion", "observationId", "observationDigest", "reason", "occurredAt"}
    wire = bridge._test_sent[0][2]
    assert wire["schemaVersion"] == "psychlo.legacy-round-abandon.v1"
    assert wire["actionDigest"] == canonical_digest({key: value for key, value in wire.items() if key != "actionDigest"})
    replay = execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert replay["replay"] is True


def test_wire_is_accepted_by_psychlo_contract_parser(tmp_path):
    bridge, primary = _runtime(tmp_path)
    _stage(bridge)
    primary.save_admin_change_plan(approve_admin_change_plan(primary.load_admin_change_plan("abandon-plan"), "sisko", NOW))
    execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    wire = bridge._test_sent[0][2]
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
    assert canonical_digest(fixture_body) == "f11c897d6c7d61ff4935891a8538c8f6bd95301807916997678495691f6eb4d8"
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
        return {"accepted": True, "actionId": payload["actionId"], "actionDigest": payload["actionDigest"], "roundId": payload["roundId"], "requestDigest": payload["requestDigest"], "status": "legacy-abandoned-uncertain"}
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


def test_peer_rejection_is_terminal_and_never_changes_round(tmp_path):
    def sender(kind, key, payload):
        return {"accepted": False, "actionId": payload["actionId"], "actionDigest": payload["actionDigest"], "roundId": payload["roundId"], "requestDigest": payload["requestDigest"], "status": "rejected"}
    bridge, primary = _runtime(tmp_path, sender=sender)
    _stage(bridge)
    plan = primary.load_admin_change_plan("abandon-plan")
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", NOW))
    with pytest.raises(LegacyAbandonmentError):
        execute_legacy_abandonment(bridge=bridge, plan_id="abandon-plan")
    assert bridge.store.legacy_abandonment("legacy-abandonment:round-arcade:arcade-plan-2")["state"] == "rejected"
    assert bridge.store.get_round("round-arcade")[4] == "started"


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
