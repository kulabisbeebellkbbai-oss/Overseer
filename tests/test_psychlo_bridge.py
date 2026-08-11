from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
import threading
from http.server import ThreadingHTTPServer
from http.client import HTTPConnection

from overseer.api import make_api_handler

from overseer.psychlo_bridge import (
    PsychloBridge,
    PsychloBridgeStore,
    derive_usage_snapshot,
    sign_peer_message,
    verify_peer_request,
    _read_secret,
)


SECRET = b"0123456789abcdef0123456789abcdef"
NOW = "2026-08-10T02:00:00+00:00"


def test_admin_canary_and_later_ceiling_initiators_require_separate_approvals(tmp_path: Path):
    sent = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge = PsychloBridge(store=store, dispatcher=lambda *_: "unused", sender=lambda kind, mid, payload: sent.append((kind, mid, payload)) or {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    approval = {"status": "approved", "kind": "concurrency-canary", "provenanceId": "admin-canary-approval"}
    canary = {"authorizationId": "canary-1", "targetTemporaryCeiling": 2, "expectedGlobalCeiling": 1, "expectedRevision": 0, "projects": [{"projectId": "p1", "planId": "plan-1", "planVersion": "v1", "leadId": "lead-1"}, {"projectId": "p2", "planId": "plan-2", "planVersion": "v1", "leadId": "lead-2"}], "workflowId": "roadex-test", "decisionVersion": "v1", "deadline": "2026-08-10T03:00:00+00:00", "correlationId": "canary-corr", "idempotencyKey": "canary-key", "occurredAt": NOW}
    assert bridge.initiate_concurrency_canary_authorization(approval, canary)["inserted"] is True
    assert sent[-1][0] == "concurrency-canary-authorization"
    store.record_protocol("concurrency-canary-result", "canary-result-1", "canary-result-key", "a" * 64, {"resultId": "canary-result-1"})
    ceiling = {"authorizationId": "ceiling-1", "ceiling": 2, "expectedRevision": 0, "revision": 1, "canaryResultId": "canary-result-1", "projectId": "p1", "planId": "plan-1", "workflowId": "roadex-test", "decisionVersion": "v1", "correlationId": "ceiling-corr", "idempotencyKey": "ceiling-key", "occurredAt": NOW}
    assert bridge.initiate_concurrency_ceiling_authorization({"status": "approved", "kind": "concurrency-ceiling", "provenanceId": "admin-ceiling"}, ceiling)["inserted"] is True


def test_verifies_exact_signed_psychlo_request_once(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    body = json.dumps({"kind": "round-request", "messageId": "round-1", "occurredAt": NOW, "payload": {"roundId": "round-1"}}, separators=(",", ":")).encode()
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-1", NOW, "nonce_1234567890abcdef", body)
    assert verify_peer_request(SECRET, store, "round-request", body, headers, now=NOW, expected_authority="127.0.0.1:8766")["messageId"] == "round-1"
    try:
        verify_peer_request(SECRET, store, "round-request", body, headers, now=NOW, expected_authority="127.0.0.1:8766")
    except ValueError as error:
        assert str(error) == "replay"
    else:
        raise AssertionError("replay was accepted")


def test_peer_verification_accepts_one_exact_injected_authority_only(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    body = json.dumps({"kind": "round-request", "messageId": "round-dynamic", "occurredAt": NOW, "payload": {"roundId": "round-dynamic"}}, separators=(",", ":")).encode()
    authority = "127.0.0.1:43127"
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-dynamic", NOW, "nonce_dynamic_123456", body, authority=authority)
    assert verify_peer_request(SECRET, store, "round-request", body, headers, now=NOW, expected_authority=authority)["messageId"] == "round-dynamic"


def test_peer_verification_rejects_wrong_or_missing_injected_authority(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    body = json.dumps({"kind": "round-request", "messageId": "round-host", "occurredAt": NOW, "payload": {"roundId": "round-host"}}, separators=(",", ":")).encode()
    authority = "127.0.0.1:43128"
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-host", NOW, "nonce_host_123456789", body, authority=authority)
    wrong = {**headers, "host": "127.0.0.1:43129"}
    for candidate in (wrong, {key: value for key, value in headers.items() if key != "host"}):
        try:
            verify_peer_request(SECRET, store, "round-request", body, candidate, now=NOW, expected_authority=authority)
        except ValueError as error:
            assert str(error) == "invalid_headers"
        else:
            raise AssertionError("wrong or missing authority was accepted")


def test_derives_prior_day_unused_weekly_capacity_from_provider_delta_only():
    history = [
        {"observed_at": "2026-08-10T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 30, "remaining_percent": 70, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
        {"observed_at": "2026-08-09T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 25, "remaining_percent": 75, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
    ]
    snapshot = derive_usage_snapshot(history, policy_version="2026-08-09")
    assert round(snapshot["snapshot"]["unusedPriorDayWeeklyCapacity"], 6) == round(100 / 7 - 5, 6)
    assert snapshot["snapshot"]["weeklyRemainingCapacity"] == 70


def test_usage_snapshot_denies_missing_same_reset_prior_day_history():
    history = [{"observed_at": "2026-08-10T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"window_minutes": 10080, "used_percent": 30, "remaining_percent": 70, "resets_at": "2026-08-16T00:00:00+00:00"}]}]}]
    try:
        derive_usage_snapshot(history, policy_version="2026-08-09")
    except ValueError as error:
        assert "prior-day" in str(error)
    else:
        raise AssertionError("missing history was accepted")


def test_emit_usage_ignores_malformed_lead_result_and_uses_provider_snapshot(tmp_path: Path):
    sent = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    store.record_round({"roundId": "round-bad"}, {}, "capability-bad")
    store.record_result("round-bad", {"occurredAt": "not-a-timestamp", "actualUsageCost": "not-a-number"})
    bridge = PsychloBridge(
        store=store,
        dispatcher=lambda _lead, _prompt: "unused",
        sender=lambda kind, message_id, payload: sent.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )
    history = [
        {"observed_at": "2026-08-10T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 30, "remaining_percent": 70, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
        {"observed_at": "2026-08-09T02:00:00+00:00", "rate_limits": [{"limit_id": "codex", "windows": [{"duration_minutes": 10080, "used_percent": 25, "remaining_percent": 75, "resets_at": "2026-08-16T00:00:00+00:00"}]}]},
    ]
    bridge.emit_usage(history, "2026-08-09")
    assert sent[0][0] == "usage-snapshot"
    assert round(sent[0][2]["snapshot"]["unusedPriorDayWeeklyCapacity"], 6) == round(100 / 7 - 5, 6)


def test_private_peer_secret_rejects_symlink_and_group_readable_file(tmp_path: Path):
    secret = tmp_path / "secret"
    secret.write_bytes(SECRET); secret.chmod(0o640)
    try:
        _read_secret(secret)
    except ValueError:
        pass
    else:
        raise AssertionError("group-readable secret was accepted")
    secret.chmod(0o600)
    link = tmp_path / "secret-link"; link.symlink_to(secret)
    try:
        _read_secret(link)
    except ValueError:
        pass
    else:
        raise AssertionError("symlink secret was accepted")


def test_dispatches_one_round_and_forwards_one_bound_result(tmp_path: Path):
    dispatched = []
    forwarded = []
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge = PsychloBridge(
        store=store,
        dispatcher=lambda project_lead_id, prompt: dispatched.append((project_lead_id, prompt)) or "dispatch:1",
        sender=lambda kind, message_id, payload: forwarded.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
        token_factory=lambda: "capability_1234567890abcdef1234567890",
    )
    request = {"roundId": "round-1", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-1", "idempotencyKey": "round-1", "snapshotId": "snapshot-1", "policyVersion": "2026-08-09", "expectedUsageCost": 5, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "sole-eligible-project"}
    receipt = bridge.request_round(request)
    assert receipt["receipt"]["status"] == "accepted"
    assert len(dispatched) == 1
    assert "approved A-Team project lead" in dispatched[0][1]
    result = {**request, "sourceId": "member-hermione", "provenanceId": "result:1", "status": "completed", "actualUsageCost": 4, "deliveredScope": "foundation", "remainingEstimate": 8, "blockers": [], "questions": [], "reachedExplicitGates": [], "occurredAt": NOW}
    accepted = bridge.receive_round_result("capability_1234567890abcdef1234567890", result)
    assert accepted == {"accepted": True}
    assert forwarded == [("round-result", "result:1", result)]
    assert bridge.request_round(request) == receipt


def test_retries_a_durably_reserved_round_after_dispatch_failure(tmp_path: Path):
    attempts = []
    def dispatch(_lead, _prompt):
        attempts.append("attempt")
        if len(attempts) == 1: raise ValueError("provider unavailable")
        return "dispatch:recovered"
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=dispatch, sender=lambda *_args: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, token_factory=lambda: "capability_retry_1234567890abcdef")
    request = {"roundId": "round-retry", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-retry", "idempotencyKey": "round-retry", "snapshotId": "snapshot-retry", "policyVersion": "2026-08-09", "expectedUsageCost": 5, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "sole-eligible-project"}
    try:
        bridge.request_round(request)
    except ValueError as error:
        assert str(error) == "provider unavailable"
    else:
        raise AssertionError("dispatch failure was hidden")
    recovered = bridge.reconcile_round(request)
    assert recovered["receipt"]["provenanceId"] == "dispatch:recovered"
    assert len(attempts) == 2


def test_stages_and_completes_roadex_decision(tmp_path: Path):
    forwarded = []
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"),
        dispatcher=lambda _lead, _prompt: "unused",
        sender=lambda kind, message_id, payload: forwarded.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )
    request = {"decisionId": "decision-1", "projectId": "arcade", "planId": "arcade-plan", "workflowId": "psychlo-roadex", "decisionVersion": "v1", "correlationId": "corr-decision", "idempotencyKey": "decision-1", "question": "Create the private GitHub repository?"}
    assert bridge.stage_decision(request)["receipt"]["status"] == "staged"
    item = bridge.list_decisions()[0]
    assert item["human_approval_required"] is True
    bridge.decide("decision-1", "approve", "human-user", "")
    assert forwarded[0][0] == "decision-outcome"
    assert forwarded[0][2]["status"] == "approved"


def test_registers_an_admitted_plan_and_publishes_initial_scheduling(tmp_path: Path):
    sent = []
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda _lead, _prompt: "unused",
        sender=lambda kind, message_id, payload: sent.append((kind, message_id, payload)) or {"accepted": True},
        callback_origin="http://127.0.0.1:8766", clock=lambda: NOW,
    )
    envelope = {"project": {"id": "arcade", "planId": "arcade-plan", "planVersion": "v1"}, "projectLead": {"id": "member-hermione"}, "plan": {"constraints": ["security review required"], "tasks": [{"id": "t1", "dependencyIds": []}, {"id": "t2", "dependencyIds": ["t1"]}]}}
    result = bridge.register_project({"envelope": envelope, "receipt": {"receiptId": "receipt-arcade"}})
    assert result == {"accepted": True}
    assert sent[0][0] == "scheduling-input"
    assert sent[0][2] == {"projectId": "arcade", "projectLeadId": "member-hermione", "state": "managed", "remainingEffort": "standard", "hasSecurityImpact": True, "hasDependencyImpact": True, "gateDistance": 2, "expectedUsageCost": 1, "correlationId": "psychlo-scheduling:receipt-arcade", "idempotencyKey": "psychlo-scheduling:receipt-arcade", "occurredAt": NOW}
    bridge.register_project({"envelope": envelope, "receipt": {"receiptId": "receipt-arcade"}})
    assert len(sent) == 1


def test_private_http_round_route_uses_hmac_not_admin_bearer(tmp_path: Path):
    class Sender:
        secret = SECRET
        def __call__(self, _kind, _message_id, _payload): return {"accepted": True}
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"),
        dispatcher=lambda _lead, _prompt: "dispatch:http",
        sender=Sender(), callback_origin="http://127.0.0.1:8766", clock=lambda: NOW,
        token_factory=lambda: "capability_http_1234567890abcdef",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_api_handler(str(tmp_path / "overseer.sqlite3"), "admin-secret", psychlo_bridge=bridge))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    request_payload = {"roundId": "round-http", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-http", "idempotencyKey": "round-http", "snapshotId": "snapshot-http", "policyVersion": "2026-08-09", "expectedUsageCost": 5, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "sole-eligible-project"}
    timestamp = datetime.now(UTC).isoformat()
    body = json.dumps({"kind": "round-request", "messageId": "round-http", "occurredAt": timestamp, "payload": request_payload}, separators=(",", ":")).encode()
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-request", "round-http", timestamp, "nonce_http_1234567890", body)
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("POST", "/psychlo/rounds", body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        assert response.status == 202, response_body
        assert json.loads(response_body)["receipt"]["status"] == "accepted"
        connection.request("POST", "/psychlo/rounds", body=body, headers=headers)
        replay = connection.getresponse()
        assert replay.status == 409
        replay.read()
        connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_task11_telemetry_sampling_keeps_cumulative_counters_and_provider_binding(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    base = {"projectId": "arcade", "planId": "plan-1", "roundId": "round-1", "threadId": "thread-1", "model": "gpt-5.6-luna", "featureClass": "backend", "activeMs": 1, "waitingMs": 0, "providerSnapshotId": "snapshot-1", "providerCapturedAt": NOW, "attribution": "isolated", "sourceId": "overseer", "correlationId": "corr", "occurredAt": NOW}
    first = bridge.record_telemetry_checkpoint({**base, "checkpointId": "checkpoint-1", "idempotencyKey": "checkpoint-1", "sampleKind": "baseline", "cumulative": {"cachedInput": 1, "uncachedInput": 1, "output": 1, "reasoning": 1, "total": 4}})
    second = bridge.record_telemetry_checkpoint({**base, "checkpointId": "checkpoint-2", "idempotencyKey": "checkpoint-2", "sampleKind": "completed-turn", "cumulative": {"cachedInput": 2, "uncachedInput": 2, "output": 2, "reasoning": 2, "total": 8}})
    assert first["inserted"] is True and second["checkpoint"]["delta"]["total"] == 4
    try:
        bridge.record_telemetry_checkpoint({**base, "checkpointId": "checkpoint-3", "idempotencyKey": "checkpoint-3", "sampleKind": "terminal", "providerSnapshotId": "snapshot-2", "cumulative": {"cachedInput": 3, "uncachedInput": 3, "output": 3, "reasoning": 3, "total": 12}})
    except ValueError as error:
        assert "provider" in str(error)
    else:
        raise AssertionError("provider binding changed")


def test_task11_telemetry_exact_replay_returns_stored_derived_delta_after_restart(tmp_path: Path):
    payload = {"checkpointId": "checkpoint-replay", "projectId": "arcade", "planId": "plan-1", "roundId": "round-replay", "threadId": "thread-1", "model": "gpt-5.6-luna", "featureClass": "backend", "sampleKind": "baseline", "cumulative": {"cachedInput": 1, "uncachedInput": 1, "output": 1, "reasoning": 1, "total": 4}, "activeMs": 1, "waitingMs": 0, "providerSnapshotId": "snapshot-1", "providerCapturedAt": NOW, "attribution": "isolated", "sourceId": "overseer", "correlationId": "corr", "idempotencyKey": "checkpoint-replay", "occurredAt": NOW}
    first_bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    first = first_bridge.record_telemetry_checkpoint(payload)
    restarted = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    replay = restarted.record_telemetry_checkpoint(payload)
    assert replay["replay"] is True
    assert replay["checkpoint"] == first["checkpoint"]


def test_task11_learning_adapter_failure_isolated_and_retry_attempts_monotonic(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    observation = {"id": "observation-1", "featureProfile": {"taskClass": "python-feature", "model": "gpt-5.6-luna"}, "outcome": {"status": "completed", "observedAt": NOW}, "sourceId": "overseer", "correlationId": "corr", "idempotencyKey": "observation-1", "occurredAt": NOW}
    bridge.record_learning_observation(observation)
    calls = []
    assert bridge.deliver_learning_pending({"skiller": lambda item: calls.append(item) or (_ for _ in ()).throw(RuntimeError("down"))})["failed"] == 1
    assert bridge.deliver_learning_pending({"skiller": lambda item: calls.append(item)})["delivered"] == 1
    assert bridge.store.learning_observation("observation-1")["attempts"]["skiller"] == 2
