from __future__ import annotations

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import threading
from datetime import UTC, datetime

from overseer.api import make_api_handler
from overseer.psychlo_bridge import PsychloBridge, PsychloBridgeStore, PsychloPeerSender, create_bridge_from_environment, sign_peer_message
from overseer.roadex_project_threads import (
    QUESTION_ENDPOINT_PATH,
    RoadexProjectThreadRelay,
    RoadexProjectThreadStore,
    RoadexQuestionSender,
    relay_sha256,
    request_headers,
    stable_json,
)


ROADEX_SECRET = b"roadex-overseer-project-thread-relay-secret-32"
PSYCHLO_SECRET = b"psychlo-overseer-project-thread-peer-secret-32"
NOW = "2026-08-22T12:00:00.000Z"
CONVERSATION = "019fc36f-0573-9123-912f-6da8181eda2d"


def binding() -> dict:
    value = {
        "schemaVersion": "roadex.project-human-thread-binding.v1", "bindingId": "project-human-thread:arcade:1", "projectId": "arcade",
        "root": {"canonicalPath": "/srv/arcade", "dev": "1", "ino": "2"}, "purpose": "human-interaction", "conversationId": CONVERSATION,
        "generation": 1, "status": "active", "predecessorGeneration": None, "creationMode": "created", "provenanceDigest": "a" * 64,
        "createdAt": NOW, "updatedAt": NOW, "retiredAt": None,
    }
    value["recordDigest"] = relay_sha256(stable_json(value))
    return value


def message() -> dict:
    value = {
        "schemaVersion": "roadex.project-human-thread-message.v1", "messageId": "human-message-api-1", "projectId": "arcade", "conversationId": CONVERSATION,
        "generation": 1, "kind": "question", "content": "Do you want to deploy and test the app?", "choices": [],
        "contentDigest": relay_sha256("Do you want to deploy and test the app?"), "correlationId": "correlation-api-1", "idempotencyKey": "key-api-1", "occurredAt": NOW,
    }
    value["messageDigest"] = relay_sha256(stable_json(value))
    return value


def envelope(record_type: str, record: dict, record_id: str) -> tuple[bytes, dict[str, str]]:
    digest = record.get("recordDigest", record.get("messageDigest"))
    body = stable_json({"schemaVersion": "roadex.overseer.project-human-thread-relay.v1", "recordType": record_type, "recordId": record_id, "recordDigest": digest, "record": record}).encode()
    return body, request_headers(ROADEX_SECRET, body, NOW, "request-api-0001")


def test_raw_roadex_route_is_hmac_only_and_before_generic_auth(tmp_path: Path):
    relay = RoadexProjectThreadRelay(store=RoadexProjectThreadStore(tmp_path / "relay.sqlite"), secret=ROADEX_SECRET, clock=lambda: NOW)
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "psychlo.sqlite"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_thread_relay=relay)
    # The production authority is 127.0.0.1:8766; use the ephemeral test
    # authority explicitly so duplicate/host checks remain exercised.
    import socket
    probe = socket.socket(); probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]; probe.close()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_api_handler(str(tmp_path / "primary.sqlite"), "admin-token", psychlo_bridge=bridge, roadex_relay_authority=f"127.0.0.1:{port}"))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        body, headers = envelope("binding", binding(), "binding-api-event-1")
        headers["host"] = f"127.0.0.1:{server.server_port}"
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("POST", "/api/roadex/project-human-thread-relay", body=body, headers=headers)
        response = connection.getresponse(); received = response.read()
        assert response.status == 202
        assert json.loads(received)["recordId"] == "binding-api-event-1"
        connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5); bridge.close()


def test_psychlo_question_peer_is_durable_and_separate_from_roadex_ingress(tmp_path: Path):
    question_calls = []
    question_sender = RoadexQuestionSender(store=RoadexProjectThreadStore(tmp_path / "relay.sqlite"), secret=ROADEX_SECRET, endpoint="http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH, clock=lambda: NOW, send=lambda body, headers: question_calls.append((body, headers)) or {"status": 202, "body": b"{}", "headers": {}})
    relay = RoadexProjectThreadRelay(store=question_sender.store, secret=ROADEX_SECRET, clock=lambda: NOW, question_sender=question_sender)
    peer_sender = PsychloPeerSender("http://127.0.0.1:8798", PSYCHLO_SECRET, clock=lambda: NOW)
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "psychlo.sqlite"), dispatcher=lambda *_: "unused", sender=peer_sender, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, project_thread_relay=relay)
    # Reserve a test authority and use the same authority in the signed peer
    # request and API handler; no live listener is contacted by the test.
    import socket
    probe = socket.socket(); probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]; probe.close()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_api_handler(str(tmp_path / "primary.sqlite"), "admin-token", psychlo_bridge=bridge, psychlo_peer_authority=f"127.0.0.1:{port}"))
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        item = message()
        timestamp = datetime.now(UTC).isoformat()
        outer = {"kind": "project-human-thread-question", "messageId": item["messageId"], "occurredAt": timestamp, "payload": item}
        body = json.dumps(outer, separators=(",", ":")).encode()
        headers = sign_peer_message(PSYCHLO_SECRET, "psychlo-to-overseer", "project-human-thread-question", item["messageId"], timestamp, "question-peer-nonce-0001", body, authority=f"127.0.0.1:{port}")
        connection = HTTPConnection("127.0.0.1", port, timeout=5)
        connection.request("POST", "/psychlo/project-human-thread/questions", body=body, headers=headers)
        response = connection.getresponse(); payload = json.loads(response.read())
        assert response.status == 202 and payload["accepted"] is True, payload
        assert question_sender.store.connection.execute("SELECT state FROM roadex_project_thread_question_outbox WHERE record_id=?", (item["messageId"],)).fetchone()[0] == "pending"
        connection.close()
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5); bridge.close()


def test_factory_constructs_distinct_relay_secret_and_database(tmp_path: Path):
    psychlo_secret_file = tmp_path / "psychlo.secret"
    roadex_secret_file = tmp_path / "roadex.secret"
    bindings_file = tmp_path / "bindings.json"
    psychlo_secret_file.write_bytes(PSYCHLO_SECRET); roadex_secret_file.write_bytes(ROADEX_SECRET); bindings_file.write_text("{}")
    for path in (psychlo_secret_file, roadex_secret_file, bindings_file): path.chmod(0o600)
    bridge = create_bridge_from_environment({
        "OVERSEER_PSYCHLO_BRIDGE_DATABASE": str(tmp_path / "psychlo.sqlite"),
        "OVERSEER_STORE_DATABASE": str(tmp_path / "primary.sqlite"),
        "OVERSEER_PSYCHLO_PEER_SECRET_FILE": str(psychlo_secret_file),
        "OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE": str(bindings_file),
        "OVERSEER_PSYCHLO_ENDPOINT": "http://127.0.0.1:8798",
        "OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_SECRET_FILE": str(roadex_secret_file),
        "OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_DATABASE": str(tmp_path / "roadex-thread.sqlite"),
        "OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_QUESTION_ENDPOINT": "http://127.0.0.1:8780" + QUESTION_ENDPOINT_PATH,
    }, recover=False)
    try:
        assert bridge.project_thread_relay is not None
        assert bridge.project_thread_relay.secret == ROADEX_SECRET
        assert bridge.peer_secret == PSYCHLO_SECRET
        assert bridge.project_thread_relay.store.filename == tmp_path / "roadex-thread.sqlite"
    finally:
        bridge.close()
