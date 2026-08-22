from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

from overseer.roadex_project_threads import (
    RECEIPT_DOMAIN,
    REQUEST_DOMAIN,
    REQUEST_SCHEMA,
    RoadexProjectThreadRelay,
    RoadexProjectThreadStore,
    ProjectThreadContractError,
    relay_sha256,
    request_headers,
    stable_json,
    QUESTION_RECEIPT_DOMAIN,
    QUESTION_RECEIPT_SCHEMA,
    QUESTION_ENDPOINT_PATH,
    PSYCHLO_RELAY_RECEIPT_SCHEMA,
    RoadexQuestionSender,
    question_request_headers,
)


SECRET = b"roadex-overseer-project-thread-relay-secret-32"
NOW = "2026-08-22T12:00:00.000Z"
CONVERSATION = "019fc36f-0570-7623-912f-6da8181eda2d"


def test_question_endpoint_matches_the_live_roadex_internal_route():
    assert QUESTION_ENDPOINT_PATH == "/api/internal/overseer/project-human-thread/questions"


def binding(*, status: str = "active", generation: int = 1, record_id: str | None = None) -> dict:
    value = {
        "schemaVersion": "roadex.project-human-thread-binding.v1",
        "bindingId": f"project-human-thread:arcade:{generation}",
        "projectId": "arcade",
        "root": {"canonicalPath": "/srv/arcade", "dev": "1", "ino": "2"},
        "purpose": "human-interaction",
        "conversationId": CONVERSATION,
        "generation": generation,
        "status": status,
        "predecessorGeneration": None if generation == 1 else generation - 1,
        "creationMode": "created",
        "provenanceDigest": "a" * 64,
        "createdAt": NOW,
        "updatedAt": NOW,
        "retiredAt": NOW if status == "retired" else None,
    }
    value["recordDigest"] = relay_sha256(stable_json(value))
    return value


def message(*, message_id: str = "human-message-1", content: str = "Do you want to deploy and test the app?") -> dict:
    value = {
        "schemaVersion": "roadex.project-human-thread-message.v1",
        "messageId": message_id,
        "projectId": "arcade",
        "conversationId": CONVERSATION,
        "generation": 1,
        "kind": "question",
        "content": content,
        "choices": [],
        "contentDigest": relay_sha256(content),
        "correlationId": "correlation-1",
        "idempotencyKey": f"key-{message_id[:150]}",
        "occurredAt": NOW,
    }
    value["messageDigest"] = relay_sha256(stable_json(value))
    return value


def envelope(record_type: str, record: dict, record_id: str, *, nonce: str) -> tuple[bytes, dict[str, str]]:
    digest_key = {"binding": "recordDigest", "message": "messageDigest", "response": "responseDigest"}[record_type]
    body = stable_json({"schemaVersion": REQUEST_SCHEMA, "recordType": record_type, "recordId": record_id, "recordDigest": record[digest_key], "record": record}).encode()
    return body, request_headers(SECRET, body, NOW, nonce)


def accepted_receipt(body: bytes, headers: dict[str, str]) -> dict:
    request = json.loads(body)
    return {"schemaVersion": PSYCHLO_RELAY_RECEIPT_SCHEMA, "accepted": True, "recordType": request["recordType"], "recordId": request["recordId"], "recordDigest": request["recordDigest"], "state": "inserted"}


def relay(tmp_path: Path, forwarder=None) -> RoadexProjectThreadRelay:
    return RoadexProjectThreadRelay(store=RoadexProjectThreadStore(tmp_path / "relay.sqlite"), secret=SECRET, clock=lambda: NOW, forwarder=forwarder)


def test_binding_lifecycle_uses_independent_event_id_and_message_requires_current_binding(tmp_path: Path):
    service = relay(tmp_path)
    body, headers = envelope("binding", binding(), "binding-event-create-1", nonce="request-nonce-0001")
    assert service.receive(body, headers).status == 202
    message_body, message_headers = envelope("message", message(), "message-event-1", nonce="request-nonce-0002")
    with pytest.raises(ValueError, match="unsupported"):
        service.receive(message_body, message_headers)
    retired_body, retired_headers = envelope("binding", binding(status="retired"), "binding-event-retire-1", nonce="request-nonce-0003")
    assert service.receive(retired_body, retired_headers).status == 202
    service.store.close()


def test_persists_inbox_and_outbox_before_forward_and_recovers_after_restart(tmp_path: Path):
    calls = []
    first = relay(tmp_path, forwarder=lambda *_: (_ for _ in ()).throw(RuntimeError("lost response")))
    body, headers = envelope("binding", binding(), "binding-event-1", nonce="request-nonce-0010")
    first.receive(body, headers)
    assert first.store.state("binding-event-1") == "pending"
    assert first.forward_pending() == {"delivered": 0, "failed": 1}
    first.store.close()

    def forward(record_type, record_id, record):
        calls.append((record_type, record_id, record["recordDigest"]))
        return {"schemaVersion": PSYCHLO_RELAY_RECEIPT_SCHEMA, "accepted": True, "recordType": record_type, "recordId": record_id, "recordDigest": record["recordDigest"], "state": "inserted"}

    second = relay(tmp_path, forwarder=forward)
    assert second.forward_pending() == {"delivered": 1, "failed": 0}
    assert second.store.state("binding-event-1") == "delivered"
    assert calls == [("binding", "binding-event-1", binding()["recordDigest"])]
    second.store.close()


def test_replay_returns_byte_identical_signed_receipt_and_conflicts_are_rejected(tmp_path: Path):
    service = relay(tmp_path)
    body, headers = envelope("binding", binding(), "binding-event-replay", nonce="request-nonce-0020")
    first = service.receive(body, headers)
    second = service.receive(body, headers)
    assert second == first
    altered = binding(); altered["root"]["canonicalPath"] = "/srv/other"; altered["recordDigest"] = relay_sha256(stable_json({k: v for k, v in altered.items() if k != "recordDigest"}))
    with pytest.raises(ValueError, match="conflict"):
        service.receive(*envelope("binding", altered, "binding-event-replay", nonce="request-nonce-0021"))
    changed_nonce_headers = dict(headers)
    changed_nonce_headers["x-roadex-relay-nonce"] = "request-nonce-0022"
    changed_nonce_headers["x-roadex-relay-signature"] = request_headers(SECRET, body, NOW, changed_nonce_headers["x-roadex-relay-nonce"])["x-roadex-relay-signature"]
    with pytest.raises(ValueError, match="conflict"):
        service.receive(body, changed_nonce_headers)
    body2, headers2 = envelope("binding", binding(), "binding-event-other", nonce="request-nonce-0023")
    headers2["x-roadex-relay-nonce"] = headers["x-roadex-relay-nonce"]
    headers2["x-roadex-relay-signature"] = request_headers(SECRET, body2, NOW, headers2["x-roadex-relay-nonce"])["x-roadex-relay-signature"]
    with pytest.raises(ValueError, match="nonce"):
        service.receive(body2, headers2)
    service.store.close()


def test_rejects_approval_shaped_records_but_allows_ordinary_text(tmp_path: Path):
    service = relay(tmp_path)
    bad = message(content="approved deploy decision")
    bad["approved"] = True
    bad["messageDigest"] = relay_sha256(stable_json(bad))
    with pytest.raises(ValueError, match="unsupported|fields|approval"):
        service.receive(*envelope("message", bad, "message-approval-shaped", nonce="request-nonce-0030"))
    body, headers = envelope("binding", binding(), "binding-valid-text", nonce="request-nonce-0031")
    assert service.receive(body, headers).status == 202
    body, headers = envelope("message", message(content="Do you want to deploy and test the app?"), "message-valid-text", nonce="request-nonce-0032")
    with pytest.raises(ValueError, match="unsupported"):
        service.receive(body, headers)
    service.store.close()


@pytest.mark.parametrize("invalid_timestamp", [
    "2026-08-22 12:00:00+00:00",
    "2026-08-22T12:00:00+0000",
])
def test_rejects_timestamp_forms_the_typescript_contract_rejects_before_persistence(
    tmp_path: Path, invalid_timestamp: str,
):
    service = relay(tmp_path)
    invalid = binding()
    invalid["updatedAt"] = invalid_timestamp
    invalid["recordDigest"] = relay_sha256(stable_json({k: v for k, v in invalid.items() if k != "recordDigest"}))
    with pytest.raises(ValueError, match="updatedAt is invalid"):
        service.receive(*envelope("binding", invalid, "binding-invalid-timestamp", nonce="request-nonce-0033"))
    assert service.store.existing("binding-invalid-timestamp") is None
    service.store.close()


def test_concurrent_duplicate_delivery_has_one_receipt_and_one_outbox(tmp_path: Path):
    body, headers = envelope("binding", binding(), "binding-concurrent", nonce="request-nonce-0040")
    service = relay(tmp_path)
    def attempt():
        return service.receive(body, headers)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: attempt(), range(8)))
    assert all(result.body == results[0].body and result.headers == results[0].headers for result in results)
    with sqlite3.connect(tmp_path / "relay.sqlite") as connection:
        assert connection.execute("SELECT count(*) FROM roadex_project_thread_relay_inbox").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM roadex_project_thread_relay_outbox").fetchone()[0] == 1
    service.store.close()


def question_receipt(body: bytes, headers: dict[str, str], *, record_id: str | None = None, record_digest: str | None = None) -> dict:
    request = json.loads(body)
    occurred_at = "2026-08-22T12:00:01.000Z"
    receipt = {"schemaVersion": QUESTION_RECEIPT_SCHEMA, "accepted": True, "messageId": record_id or request["message"]["messageId"], "messageDigest": record_digest or request["message"]["messageDigest"], "requestNonce": headers["x-overseer-question-nonce"], "receiptNonce": "question-receipt-0001", "occurredAt": occurred_at}
    encoded = stable_json(receipt).encode()
    import hmac
    signature = hmac.new(SECRET, "\n".join((QUESTION_RECEIPT_DOMAIN, occurred_at, headers["x-overseer-question-nonce"], relay_sha256(encoded))).encode(), hashlib.sha256).hexdigest()
    return {"status": 202, "body": encoded, "headers": {"x-roadex-question-timestamp": occurred_at, "x-roadex-question-signature": signature}}


def test_psychlo_question_egress_persists_before_send_and_replays_after_restart(tmp_path: Path):
    path = tmp_path / "relay.sqlite"
    calls: list[tuple[bytes, dict[str, str]]] = []
    first = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: NOW, send=lambda body, headers: calls.append((body, dict(headers))) or (_ for _ in ()).throw(RuntimeError("lost response")))
    first.enqueue(message())
    with pytest.raises(RuntimeError, match="lost response"):
        first.deliver("human-message-1")
    first.close()
    second = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, send=lambda body, headers: calls.append((body, dict(headers))) or question_receipt(body, headers))
    assert second.retry_pending() == {"delivered": 1, "failed": 0}
    assert calls[0] == calls[1]
    second.close()


def test_psychlo_question_egress_rejects_substituted_receipt_and_concurrent_claim(tmp_path: Path):
    release = False
    def send(body, headers):
        return question_receipt(body, headers, record_id="other-message")
    sender = RoadexQuestionSender(store=RoadexProjectThreadStore(tmp_path / "relay.sqlite"), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: NOW, send=send)
    sender.enqueue(message())
    with pytest.raises(ValueError, match="binding"):
        sender.deliver("human-message-1")
    sender.close()


def test_psychlo_question_egress_recovers_stale_claim_after_restart(tmp_path: Path):
    path = tmp_path / "relay.sqlite"
    first = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: "2026-08-22T12:00:00.000Z", send=lambda *_: (_ for _ in ()).throw(RuntimeError("crash")))
    first.enqueue(message())
    with pytest.raises(RuntimeError): first.deliver("human-message-1")
    with first.store._lock:
        first.store.connection.execute("UPDATE roadex_project_thread_question_outbox SET state='sending',claimed_at=? WHERE record_id=?", ("2026-08-22T10:00:00.000Z", "human-message-1"))
    first.close()
    second = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: "2026-08-22T12:00:00.000Z", send=lambda body, headers: question_receipt(body, headers))
    assert second.deliver("human-message-1")["state"] == "delivered"
    second.close()


def test_psychlo_question_retry_pending_recovers_stale_claim_after_restart(tmp_path: Path):
    path = tmp_path / "relay.sqlite"
    first = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: "2026-08-22T12:00:00.000Z", send=lambda *_: (_ for _ in ()).throw(RuntimeError("crash")))
    first.enqueue(message())
    with pytest.raises(RuntimeError):
        first.deliver("human-message-1")
    with first.store._lock:
        first.store.connection.execute("UPDATE roadex_project_thread_question_outbox SET state='sending',claimed_at=? WHERE record_id=?", ("2026-08-22T10:00:00.000Z", "human-message-1"))
    first.close()
    second = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: "2026-08-22T12:00:00.000Z", send=lambda body, headers: question_receipt(body, headers))
    assert second.retry_pending() == {"delivered": 1, "failed": 0}
    assert second.store.connection.execute("SELECT state FROM roadex_project_thread_question_outbox WHERE record_id=?", ("human-message-1",)).fetchone()[0] == "delivered"
    second.close()


def test_psychlo_question_egress_concurrent_claim_is_single_owner(tmp_path: Path):
    path = tmp_path / "relay.sqlite"
    first = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: "2026-08-22T12:00:00.000Z", send=lambda *_: (_ for _ in ()).throw(RuntimeError("held")))
    first.enqueue(message())
    with pytest.raises(RuntimeError): first.deliver("human-message-1")
    with first.store._lock:
        first.store.connection.execute("UPDATE roadex_project_thread_question_outbox SET state='sending',claimed_at=? WHERE record_id=?", ("2026-08-22T12:00:00.000Z", "human-message-1"))
    second = RoadexQuestionSender(store=RoadexProjectThreadStore(path), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: "2026-08-22T12:00:00.000Z", send=lambda body, headers: question_receipt(body, headers))
    assert second.retry_pending() == {"delivered": 0, "failed": 0}
    with pytest.raises(ValueError, match="claimed"):
        second.deliver("human-message-1")
    first.close(); second.close()


def test_psychlo_question_ack_uses_bounded_persistence_identity(tmp_path: Path):
    sender = RoadexQuestionSender(store=RoadexProjectThreadStore(tmp_path / "relay.sqlite"), secret=SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: NOW, send=lambda *_: {"status": 202, "body": b"{}", "headers": {}})
    relay = RoadexProjectThreadRelay(store=sender.store, secret=SECRET, clock=lambda: NOW, question_sender=sender)
    result = relay.receive_psychlo_question(message(message_id="a" * 160))
    assert len(result["persistenceId"]) <= 160
    assert result["schemaVersion"] == "overseer.psychlo.project-human-thread-question-receipt.v1"
    relay.close()
