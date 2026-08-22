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
)


SECRET = b"roadex-overseer-project-thread-relay-secret-32"
NOW = "2026-08-22T12:00:00.000Z"
CONVERSATION = "019fc36f-0570-7623-912f-6da8181eda2d"


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
        "idempotencyKey": f"key-{message_id}",
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
    return {"accepted": True, "recordType": request["recordType"], "recordId": request["recordId"], "recordDigest": request["recordDigest"]}


def relay(tmp_path: Path, forwarder=None) -> RoadexProjectThreadRelay:
    return RoadexProjectThreadRelay(store=RoadexProjectThreadStore(tmp_path / "relay.sqlite"), secret=SECRET, clock=lambda: NOW, forwarder=forwarder)


def test_binding_lifecycle_uses_independent_event_id_and_message_requires_current_binding(tmp_path: Path):
    service = relay(tmp_path)
    body, headers = envelope("binding", binding(), "binding-event-create-1", nonce="request-nonce-0001")
    assert service.receive(body, headers).status == 202
    message_body, message_headers = envelope("message", message(), "message-event-1", nonce="request-nonce-0002")
    assert service.receive(message_body, message_headers).status == 202
    retired_body, retired_headers = envelope("binding", binding(status="retired"), "binding-event-retire-1", nonce="request-nonce-0003")
    assert service.receive(retired_body, retired_headers).status == 202
    with pytest.raises(ValueError, match="not current"):
        service.receive(*envelope("message", message(message_id="message-event-2"), "message-event-2", nonce="request-nonce-0004"))
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
        return {"accepted": True, "receipt": {"recordType": record_type, "recordId": record_id, "recordDigest": record["recordDigest"]}}

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
    with pytest.raises(ValueError, match="fields|approval"):
        service.receive(*envelope("message", bad, "message-approval-shaped", nonce="request-nonce-0030"))
    body, headers = envelope("binding", binding(), "binding-valid-text", nonce="request-nonce-0031")
    assert service.receive(body, headers).status == 202
    body, headers = envelope("message", message(content="Do you want to deploy and test the app?"), "message-valid-text", nonce="request-nonce-0032")
    assert service.receive(body, headers).status == 202
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
