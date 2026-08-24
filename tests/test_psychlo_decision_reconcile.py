from __future__ import annotations

from pathlib import Path
from datetime import UTC, datetime
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import hashlib
import json
import socket
import threading
from dataclasses import replace

import pytest

from overseer.api import _decide_roadex_human, make_api_handler
from overseer.cli import approve_claim_status, request_claim_status
from overseer.core import ApprovalLevel, OwnerDomain, Resource, ResourceType, RiskLevel
from overseer.psychlo_bridge import PsychloBridge, PsychloBridgeStore, sign_peer_message, verify_peer_response
from overseer.store import SQLiteStore


NOW = "2026-08-20T18:00:00+00:00"
PEER_SECRET = b"0123456789abcdef0123456789abcdef"


def _request() -> dict[str, str]:
    return {
        "decisionId": "decision:arcade:task-7",
        "projectId": "arcade",
        "planId": "arcade-plan",
        "workflowId": "roadex-arcade",
        "decisionVersion": "v6",
        "correlationId": "result:arcade:task-7",
        "idempotencyKey": "decision:arcade:task-7",
        "question": "May the next round continue after the task-7 gate?",
        "continuationMode": "same-plan",
        "roundId": "round:arcade:v6:7",
        "resultProvenanceId": "result:arcade:task-7",
    }


def _bridge(tmp_path: Path) -> tuple[PsychloBridge, list[tuple[str, str, dict[str, str]]]]:
    forwarded: list[tuple[str, str, dict[str, str]]] = []

    class Sender:
        secret = PEER_SECRET

        def __call__(self, kind: str, message_id: str, payload: dict[str, str]) -> dict[str, bool]:
            forwarded.append((kind, message_id, dict(payload)))
            return {"accepted": True}

    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"),
        dispatcher=lambda *_args, **_kwargs: "unused",
        sender=Sender(),
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )
    return bridge, forwarded


def test_api_supplies_a_canonical_reason_for_an_approved_psychlo_decision(tmp_path: Path) -> None:
    bridge, forwarded = _bridge(tmp_path)
    request = _request()
    bridge.stage_decision(request)

    result = _decide_roadex_human(
        str(tmp_path / "primary.sqlite3"),
        {"plan_id": request["decisionId"], "decision": "approve", "decided_by": "human-user", "reason": ""},
        None,
        bridge,
    )

    assert result["action_status"] == "approved"
    assert forwarded == [("decision-outcome", request["decisionId"], {**request, "sourceId": "overseer", "provenanceId": f"roadex-outcome:{request['decisionId']}:approved", "status": "approved"})]
    assert bridge.store.decision_record(request["decisionId"])["reason"] == "Approved by human-user in Overseer."


def test_api_approves_and_activates_the_exact_structurally_bound_claim_before_delivering_outcome(tmp_path: Path) -> None:
    primary_path = tmp_path / "primary.sqlite3"
    resource_id = "resource.loopback.ephemeral.arcade.task7"
    claim_id = "claim.arcade.task7.loopback.bound"
    store = SQLiteStore(primary_path)
    store.save_resource(Resource(id=resource_id, name="Arcade loopback", type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    store.close()
    requested = request_claim_status(
        primary_path, claim_id, resource_id, "lease", "thread-arcade", "dax",
        "one smoke test", "bind loopback", "low",
        activation_group_id="group.claim.arcade.task7.loopback.bound",
        lifecycle_id="lifecycle.arcade.task7",
    )
    bridge, forwarded = _bridge(tmp_path)
    request = {**_request(), "resourceClaimId": claim_id}
    bridge.stage_decision(request)

    with pytest.raises(ValueError, match="owner-domain approval"):
        _decide_roadex_human(
            str(primary_path),
            {"plan_id": request["decisionId"], "decision": "approve", "decided_by": "human-user", "reason": "Approved exact claim."},
            None,
            bridge,
        )

    approve_claim_status(primary_path, requested["approval_id"], OwnerDomain.DAX.value)
    result = _decide_roadex_human(
        str(primary_path),
        {"plan_id": request["decisionId"], "decision": "approve", "decided_by": "human-user", "reason": "Approved exact claim."},
        None,
        bridge,
    )

    store = SQLiteStore(primary_path)
    try:
        assert store.load_approval(requested["approval_id"]).status.value == "approved"
        assert store.load_claim(claim_id).status.value == "active"
    finally:
        store.close()
    assert result["action_status"] == "approved"
    assert forwarded[0][2]["resourceClaimId"] == claim_id

    replay = _decide_roadex_human(
        str(primary_path),
        {"plan_id": request["decisionId"], "decision": "approve", "decided_by": "human-user", "reason": "Approved exact claim."},
        None,
        bridge,
    )
    assert replay["mutation_performed"] is False
    assert len(forwarded) == 1


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("approval_level", ApprovalLevel.HUMAN, "approval level is not ROLE"),
        ("owner_domain", OwnerDomain.SISKO, "approval owner domain does not match claim owner role"),
        ("decided_by", OwnerDomain.SISKO.value, "approval actor does not match claim owner role"),
    ],
)
def test_bound_role_approval_identity_mismatch_cannot_activate_or_deliver_human_decision(
    tmp_path: Path,
    field: str,
    replacement: object,
    message: str,
) -> None:
    primary_path = tmp_path / "primary.sqlite3"
    resource_id = "resource.loopback.ephemeral.arcade.task7"
    claim_id = "claim.arcade.task7.loopback.bound"
    store = SQLiteStore(primary_path)
    store.save_resource(Resource(id=resource_id, name="Arcade loopback", type=ResourceType.VIRTUAL_ASSET, owner_domain=OwnerDomain.DAX, risk_level=RiskLevel.LOW))
    store.close()
    requested = request_claim_status(
        primary_path, claim_id, resource_id, "lease", "thread-arcade", "dax",
        "one smoke test", "bind loopback", "low",
        activation_group_id="group.claim.arcade.task7.loopback.bound",
        lifecycle_id="lifecycle.arcade.task7",
    )
    approve_claim_status(primary_path, requested["approval_id"], OwnerDomain.DAX.value)

    store = SQLiteStore(primary_path)
    try:
        approval = store.load_approval(requested["approval_id"])
        store.save_approval(replace(approval, **{field: replacement}))
    finally:
        store.close()

    bridge, forwarded = _bridge(tmp_path)
    request = {**_request(), "resourceClaimId": claim_id}
    bridge.stage_decision(request)

    with pytest.raises(ValueError, match=message):
        _decide_roadex_human(
            str(primary_path),
            {"plan_id": request["decisionId"], "decision": "approve", "decided_by": "human-user", "reason": "Approved exact claim."},
            None,
            bridge,
        )

    store = SQLiteStore(primary_path)
    try:
        assert store.load_claim(claim_id).status.value == "requested"
    finally:
        store.close()
    assert forwarded == []
    assert bridge.store.decision_record(request["decisionId"])["status"] == "pending"


def test_reconcile_decision_returns_exact_pending_identity(tmp_path: Path) -> None:
    bridge, _ = _bridge(tmp_path)
    request = _request()
    bridge.stage_decision(request)

    result = bridge.reconcile_decision(request)

    assert result["accepted"] is True
    assert result["receipt"] == {**request, "sourceId": "overseer", "status": "pending"}
    assert "provenanceId" not in result["receipt"]
    assert not {"decidedBy", "decidedAt", "reason"} & set(result["receipt"])
    assert set(result) == {"accepted", "receipt"}


def test_reconcile_decision_returns_approved_provenance_and_human_metadata(tmp_path: Path) -> None:
    bridge, forwarded = _bridge(tmp_path)
    request = _request()
    bridge.stage_decision(request)
    bridge.decide(request["decisionId"], "approve", "odo", "approved exact gate")

    result = bridge.reconcile_decision(request)

    assert result["receipt"]["status"] == "approved"
    assert result["receipt"]["provenanceId"] == "roadex-outcome:decision:arcade:task-7:approved"
    assert result["receipt"]["continuationMode"] == "same-plan"
    assert result["receipt"]["decidedBy"] == "odo"
    assert result["receipt"]["decidedAt"] == NOW
    assert result["receipt"]["reason"] == "approved exact gate"
    assert set(result) == {"accepted", "receipt"}
    assert forwarded[0][0] == "decision-outcome"


def test_request_revision_is_a_distinct_terminal_directive(tmp_path: Path) -> None:
    bridge, forwarded = _bridge(tmp_path)
    request = _request()
    bridge.stage_decision(request)
    bridge.decide(request["decisionId"], "request_revision", "odo", "please revise the task scope")

    result = bridge.reconcile_decision(request)

    assert result["receipt"]["status"] == "revision-requested"
    assert result["receipt"]["status"] == "revision-requested"
    assert forwarded[0][2]["status"] == "revision-requested"


def test_stage_rejects_an_unbound_continuation_mode(tmp_path: Path) -> None:
    bridge, _ = _bridge(tmp_path)

    with pytest.raises(ValueError, match="continuation mode is invalid"):
        bridge.stage_decision({**_request(), "continuationMode": "approve-and-choose-later"})


@pytest.mark.parametrize("reason", ["", "   ", "\t\n"])
def test_empty_decision_reason_leaves_staged_decision_without_intent(tmp_path: Path, reason: str) -> None:
    bridge, _ = _bridge(tmp_path)
    request = _request()
    bridge.stage_decision(request)

    with pytest.raises(ValueError, match="reason are required"):
        bridge.decide(request["decisionId"], "approve", "odo", reason)

    assert bridge.store.decision_record(request["decisionId"])["status"] == "pending"
    assert bridge.store.decision_intent(request["decisionId"]) is None


def test_direct_decision_persists_terminal_state_before_a_lost_push_response(tmp_path: Path) -> None:
    class LostResponseSender:
        secret = PEER_SECRET

        def __init__(self) -> None:
            self.outcomes: list[dict[str, str]] = []

        def __call__(self, kind: str, _message_id: str, payload: dict[str, str]) -> dict[str, bool]:
            if kind == "decision-outcome":
                self.outcomes.append(dict(payload))
                raise RuntimeError("peer response lost")
            return {"accepted": True}

    sender = LostResponseSender()
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"),
        dispatcher=lambda *_args, **_kwargs: "unused",
        sender=sender,
        callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )
    request = _request()
    bridge.stage_decision(request)

    with pytest.raises(RuntimeError, match="peer response lost"):
        bridge.decide(request["decisionId"], "approve", "odo", "approved exact gate")

    assert bridge.store.decision_record(request["decisionId"])["status"] == "approved"
    assert bridge.store.decision_intent(request["decisionId"])["status"] == "pending"
    assert bridge.reconcile_decision(request)["receipt"]["status"] == "approved"
    assert len(sender.outcomes) == 1
    bridge.close()


def test_restart_retries_exact_direct_decision_intent_and_replays_idempotently(tmp_path: Path) -> None:
    database = tmp_path / "bridge.sqlite3"
    template, _ = _bridge(tmp_path)
    template.close()
    request = _request()

    class FailingSender:
        secret = PEER_SECRET

        def __call__(self, kind: str, _message_id: str, _payload: dict[str, str]) -> dict[str, bool]:
            if kind == "decision-outcome":
                raise RuntimeError("peer response lost")
            return {"accepted": True}

    initial = PsychloBridge(store=PsychloBridgeStore(database), dispatcher=lambda *_args, **_kwargs: "unused", sender=FailingSender(), callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    initial.stage_decision(request)
    with pytest.raises(RuntimeError, match="peer response lost"):
        initial.decide(request["decisionId"], "approve", "odo", "approved exact gate")
    initial.close()

    calls: list[tuple[str, dict[str, str]]] = []

    class RecoveringSender:
        secret = PEER_SECRET

        def __call__(self, kind: str, _message_id: str, payload: dict[str, str]) -> dict[str, bool]:
            calls.append((kind, dict(payload)))
            return {"accepted": True}

    restarted = PsychloBridge(store=PsychloBridgeStore(database), dispatcher=lambda *_args, **_kwargs: "unused", sender=RecoveringSender(), callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    assert restarted.store.decision_intent(request["decisionId"])["status"] == "settled"
    assert len(calls) == 1
    assert calls[0][0] == "decision-outcome"
    replay = restarted.decide(request["decisionId"], "approve", "odo", "approved exact gate")
    assert replay["action_status"] == "approved"
    assert replay["mutation_performed"] is False
    assert len(calls) == 1
    with pytest.raises(ValueError, match="decision conflict"):
        restarted.decide(request["decisionId"], "approve", "odo", "changed reason")
    restarted.close()


@pytest.mark.parametrize(
    "field",
    ["projectId", "planId", "workflowId", "decisionVersion", "correlationId", "idempotencyKey", "question", "continuationMode", "roundId", "resultProvenanceId"],
)
def test_reconcile_decision_rejects_identity_drift(tmp_path: Path, field: str) -> None:
    bridge, _ = _bridge(tmp_path)
    request = _request()
    bridge.stage_decision(request)
    changed = {**request, field: request[field] + ":changed"}

    with pytest.raises(ValueError, match="decision identity conflict"):
        bridge.reconcile_decision(changed)


def test_reconcile_decision_rejects_unknown_decision(tmp_path: Path) -> None:
    bridge, _ = _bridge(tmp_path)

    with pytest.raises(ValueError, match="exact staged Psychlo decision"):
        bridge.reconcile_decision({**_request(), "decisionId": "decision:unknown"})


def test_http_reconciliation_is_authenticated_and_response_bound(tmp_path: Path) -> None:
    secret = PEER_SECRET
    bridge, _ = _bridge(tmp_path)
    request = _request()
    bridge.stage_decision(request)
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    handler = make_api_handler(
        str(tmp_path / "primary.sqlite3"),
        psychlo_bridge=bridge,
        psychlo_peer_authority=f"127.0.0.1:{port}",
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        message_id = request["decisionId"]
        timestamp = datetime.now(UTC).isoformat()
        body = json.dumps({"kind": "decision-reconcile", "messageId": message_id, "occurredAt": timestamp, "payload": request}, separators=(",", ":")).encode()
        headers = sign_peer_message(secret, "psychlo-to-overseer", "decision-reconcile", message_id, timestamp, "request-nonce-123456", body, authority=f"127.0.0.1:{server.server_port}")
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("POST", "/psychlo/decisions/reconcile", body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        assert response.status == 202, raw
        assert json.loads(raw)["receipt"]["status"] == "pending"
        verify_peer_response(
            secret,
            "decision-reconcile",
            raw,
            {key.lower(): value for key, value in response.getheaders()},
            request_message_id=message_id,
            request_nonce=headers["x-psychlo-peer-nonce"],
            request_digest=hashlib.sha256(body).hexdigest(),
            now=timestamp,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_http_decision_stage_requires_the_canonical_safe_transport_identity(tmp_path: Path) -> None:
    secret = PEER_SECRET
    bridge, _ = _bridge(tmp_path)
    decision_id = "roadex:round:arcade:usage-attribution-f8b71029532e11a147aaa752:worktree:arcade@2578756:task7-source-reviewed-207-tests"
    request = {**_request(), "decisionId": decision_id, "idempotencyKey": "decision:arcade:task-7:unsafe-provenance"}
    expected_message_id = f"decision:{hashlib.sha256(decision_id.encode()).hexdigest()}"
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    handler = make_api_handler(
        str(tmp_path / "primary.sqlite3"),
        psychlo_bridge=bridge,
        psychlo_peer_authority=f"127.0.0.1:{port}",
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        def post(message_id: str, nonce: str) -> tuple[int, dict[str, object]]:
            timestamp = datetime.now(UTC).isoformat()
            body = json.dumps({"kind": "decision-stage", "messageId": message_id, "occurredAt": timestamp, "payload": request}, separators=(",", ":")).encode()
            headers = sign_peer_message(secret, "psychlo-to-overseer", "decision-stage", message_id, timestamp, nonce, body, authority=f"127.0.0.1:{server.server_port}")
            connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request("POST", "/psychlo/decisions", body=body, headers=headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())

        wrong_status, wrong_body = post(f"decision:{'0' * 64}", "request-wrong-id-123456")
        assert wrong_status == 400, wrong_body
        assert bridge.store.decision_record(decision_id) is None

        status, body = post(expected_message_id, "request-exact-id-123456")
        assert status == 202, body
        assert body["receipt"]["decisionId"] == decision_id
        assert bridge.store.decision_record(decision_id)["request"] == request
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
