from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from overseer.api import make_api_handler
from overseer.psychlo_bridge import PsychloBridge, PsychloBridgeStore, sign_peer_message
from overseer.psychlo_contracts import canonical_digest


NOW = "2026-08-17T20:00:00+00:00"
SECRET = b"0123456789abcdef0123456789abcdef"


def _round(round_id: str = "round-cancel-pending") -> dict:
    return {
        "roundId": round_id,
        "projectId": "arcade",
        "projectLeadId": "member-hermione",
        "planId": "arcade-plan",
        "planVersion": "v1",
        "correlationId": f"corr-{round_id}",
        "idempotencyKey": f"request-{round_id}",
        "snapshotId": f"snapshot-{round_id}",
        "policyVersion": "2026-08-09",
        "expectedUsageCost": 1,
        "scope": "one bounded round",
        "selectionReason": "priority-selected",
        "priorityRationale": "manual-priority",
    }


def _record_pending(store: PsychloBridgeStore, request: dict) -> None:
    receipt = {
        **request,
        "sourceId": request["projectLeadId"],
        "provenanceId": f"overseer-dispatch:{request['roundId']}",
        "status": "accepted",
    }
    store.record_round(request, receipt, f"capability:{request['roundId']}")


def _cancellation(request: dict, cancellation_id: str = "cancel-round-cancel-pending") -> dict:
    return {
        "cancellationId": cancellation_id,
        "request": request,
        "requestDigest": canonical_digest(request),
    }


class _NoDispatch:
    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("round cancellation must never dispatch")


def _bridge(store: PsychloBridgeStore, dispatcher: _NoDispatch | None = None) -> PsychloBridge:
    return PsychloBridge(
        store=store,
        dispatcher=dispatcher or _NoDispatch(),
        sender=lambda *_args: {"accepted": True},
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
        recover=False,
    )


def test_cancel_pending_round_is_terminal_idempotent_and_survives_restart(tmp_path: Path):
    store_path = tmp_path / "bridge.sqlite3"
    store = PsychloBridgeStore(store_path)
    request = _round()
    _record_pending(store, request)
    dispatcher = _NoDispatch()
    bridge = _bridge(store, dispatcher)

    first = bridge.cancel_round_before_start(_cancellation(request))

    assert first["accepted"] is True
    assert first["inserted"] is True
    receipt = first["receipt"]
    assert receipt == {
        "schemaVersion": "psychlo.round-cancel-before-start.v1",
        "kind": "round-cancel-before-start",
        "status": "cancelled",
        "roundId": request["roundId"],
        "projectId": request["projectId"],
        "requestDigest": canonical_digest(request),
        "before": {
            "dispatchState": "pending",
            "startedAt": None,
            "codexBinding": None,
            "result": None,
            "recovery": False,
            "operationalFailure": False,
        },
        "cancelledAt": NOW,
        "digest": canonical_digest({key: value for key, value in receipt.items() if key != "digest"}),
    }
    assert store.get_round(request["roundId"])[4] == "cancelled-before-start"
    assert store.active_round() is None
    assert store.active_rounds() == []
    assert dispatcher.calls == []
    bridge.close()

    restarted_dispatcher = _NoDispatch()
    restarted = _bridge(PsychloBridgeStore(store_path), restarted_dispatcher)
    replay = restarted.cancel_round_before_start(_cancellation(request))
    assert replay == {"accepted": True, "inserted": False, "receipt": receipt}
    assert restarted.store.round_cancellation(request["roundId"])["receipt"] == receipt
    assert restarted_dispatcher.calls == []
    restarted.close()


@pytest.mark.parametrize("unsafe", ("started", "binding", "result", "recovery", "operational-failure"))
def test_cancel_pending_round_rejects_any_started_or_recovery_state(tmp_path: Path, unsafe: str):
    store = PsychloBridgeStore(tmp_path / f"{unsafe}.sqlite3")
    request = _round(f"round-{unsafe}")
    _record_pending(store, request)
    if unsafe == "started":
        store.mark_dispatch_started(request["roundId"], NOW)
    elif unsafe == "binding":
        store.bind_round_execution(request["roundId"], {"conversationId": "conversation", "sessionId": "session", "rolloutPathDigest": "a" * 64, "rolloutDev": 1, "rolloutIno": 2})
    elif unsafe == "result":
        store.connection.execute("UPDATE rounds SET result_json='{}' WHERE round_id=?", (request["roundId"],))
    elif unsafe == "recovery":
        store.connection.execute("INSERT INTO round_recoveries(round_id,request_digest,capability_hash,idempotency_key,state,attempts,updated_at) SELECT round_id,?,capability_hash,?,'claimed',0,? FROM rounds WHERE round_id=?", (canonical_digest(request), request["idempotencyKey"], NOW, request["roundId"]))
    else:
        store.connection.execute("INSERT INTO operational_failure_intents(round_id,request_digest,capability_hash,idempotency_key,payload_json,payload_digest,state,updated_at) SELECT round_id,?,capability_hash,?,'{}',?,'queued',? FROM rounds WHERE round_id=?", (canonical_digest(request), f"failure-{request['roundId']}", hashlib.sha256(request["roundId"].encode()).hexdigest(), NOW, request["roundId"]))

    with pytest.raises(ValueError, match="pending|before start|cancellation"):
        _bridge(store).cancel_round_before_start(_cancellation(request, f"cancel-{unsafe}"))

    assert store.round_cancellation(request["roundId"]) is None
    assert store.get_round(request["roundId"])[4] != "cancelled-before-start"


def test_cancel_pending_round_binds_exact_request_digest_and_cancellation_id(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    request = _round()
    _record_pending(store, request)
    bridge = _bridge(store)
    for invalid in (
        {**_cancellation(request), "requestDigest": "0" * 64},
        {**_cancellation(request), "request": {**request, "planVersion": "v2"}},
        {**_cancellation(request), "extra": True},
        {key: value for key, value in _cancellation(request).items() if key != "cancellationId"},
    ):
        with pytest.raises(ValueError, match="cancellation|digest|request"):
            bridge.cancel_round_before_start(invalid)
    first = bridge.cancel_round_before_start(_cancellation(request, "cancel-one"))
    assert first["inserted"] is True
    with pytest.raises(ValueError, match="conflict"):
        bridge.cancel_round_before_start(_cancellation(request, "cancel-two"))
    second = _round("round-cancel-second")
    _record_pending(store, second)
    with pytest.raises(ValueError, match="conflict"):
        bridge.cancel_round_before_start(_cancellation(second, "cancel-one"))
    assert store.get_round(second["roundId"])[4] == "pending"
    assert store.round_cancellation(second["roundId"]) is None


def test_unknown_future_round_state_remains_active_and_blocks_admission(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    request = _round()
    _record_pending(store, request)
    store.connection.execute("UPDATE rounds SET dispatch_state='unknown-future-state' WHERE round_id=?", (request["roundId"],))
    assert store.active_round() == request["roundId"]
    assert store.active_rounds() == [request]
    second = _round("round-after-unknown-state")
    with pytest.raises(ValueError, match="single_stream_busy"):
        store.record_single_stream_round(second, {**second, "sourceId": second["projectLeadId"], "provenanceId": "must-not-admit", "status": "accepted"}, "capability:round-after-unknown-state")


def test_signed_http_round_cancel_route_returns_persisted_receipt(tmp_path: Path):
    class Sender:
        secret = SECRET

        def __call__(self, *_args):
            return {"accepted": True}

    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    request = _round("round-http-cancel")
    _record_pending(store, request)
    dispatcher = _NoDispatch()
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=Sender(), callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, recover=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_api_handler(str(tmp_path / "overseer.sqlite3"), "admin-secret", psychlo_bridge=bridge))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    timestamp = datetime.now(UTC).isoformat()
    payload = _cancellation(request, "cancel-http")
    body = json.dumps({"kind": "round-cancel-before-start", "messageId": "cancel-http", "occurredAt": timestamp, "payload": payload}, separators=(",", ":")).encode()
    headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-cancel-before-start", "cancel-http", timestamp, "nonce_round_cancel_http_123456", body)
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("POST", "/psychlo/rounds/cancel-before-start", body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        assert response.status == 202, response_body
        result = json.loads(response_body)
        assert result["receipt"]["status"] == "cancelled"
        assert result["receipt"]["roundId"] == request["roundId"]
        assert dispatcher.calls == []
        mismatch_payload = _cancellation(request, "payload-cancellation-id")
        mismatch_body = json.dumps({"kind": "round-cancel-before-start", "messageId": "signed-message-id", "occurredAt": timestamp, "payload": mismatch_payload}, separators=(",", ":")).encode()
        mismatch_headers = sign_peer_message(SECRET, "psychlo-to-overseer", "round-cancel-before-start", "signed-message-id", timestamp, "nonce_round_cancel_mismatch_123456", mismatch_body)
        connection.request("POST", "/psychlo/rounds/cancel-before-start", body=mismatch_body, headers=mismatch_headers)
        mismatch = connection.getresponse()
        assert mismatch.status == 400
        assert json.loads(mismatch.read())["error"] == "round cancellation request is invalid"
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        bridge.close()
