from __future__ import annotations

import json
import os
import socket
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from overseer import api as api_module
from overseer.api import BoundedThreadingUnixHTTPServer, make_api_handler
from overseer.client import OverseerApiClient
from overseer.store import SQLiteStore


class FakeUserBridge:
    def __init__(self, projections: dict[str, dict]) -> None:
        self.projections = projections
        self.calls: list[str] = []

    def call(self, method: str, request_id: str) -> dict:
        assert request_id.startswith("api-")
        self.calls.append(method)
        return {"status": "ok", "projection": self.projections[method]}


class ApiServer:
    def __init__(self, store_path: Path, bridge: FakeUserBridge | None = None) -> None:
        SQLiteStore(store_path).close()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_api_handler(str(store_path), "ordinary-token", user_bridge_client=bridge),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(f"{self.url}{path}", data=body, method=method)
        request.add_header("Authorization", "Bearer ordinary-token")
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())


@pytest.fixture
def dedicated(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("OVERSEER_DEDICATED_PRINCIPAL", "1")


def test_codex_usage_is_explicitly_unavailable_without_user_bridge(
    tmp_path: Path, dedicated, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ForbiddenTracker:
        def __init__(self, *args, **kwargs) -> None:
            raise AssertionError("dedicated API must not open the user usage database")

    monkeypatch.setattr(api_module, "CodexUsageTracker", ForbiddenTracker)
    server = ApiServer(tmp_path / "state.sqlite3")
    try:
        status, payload = server.request("GET", "/health/codex-usage")
    finally:
        server.close()

    assert status == 200
    assert payload["available"] is False
    assert payload["bridge_state"] == "unavailable"
    assert payload["source"] == "codex.usage.snapshot.v1"


def test_codex_usage_projection_comes_only_from_user_bridge(tmp_path: Path, dedicated) -> None:
    bridge = FakeUserBridge(
        {
            "codex.usage.snapshot.v1": {
                "state": "available",
                "observed_at": "2026-08-26T12:00:00+00:00",
                "windows": [
                    {"name": "weekly", "used": 12, "remaining": 88, "reset_at": "2026-09-01T00:00:00+00:00"}
                ],
            }
        }
    )
    server = ApiServer(tmp_path / "state.sqlite3", bridge)
    try:
        status, payload = server.request("GET", "/health/codex-usage")
        second_status, second_payload = server.request("GET", "/health/codex-usage")
    finally:
        server.close()

    assert status == 200
    assert payload["available"] is True
    assert payload["bridge_state"] == "available"
    assert payload["rate_limits"][0]["limit_name"] == "weekly"
    assert second_status == 200
    assert second_payload == payload
    assert bridge.calls == ["codex.usage.snapshot.v1"]


def test_system_api_builds_bridge_client_only_from_fixed_environment(
    dedicated, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "OVERSEER_USER_BRIDGE_SOCKET", "/run/overseer/codex-user-bridge.sock"
    )
    monkeypatch.setenv("OVERSEER_USER_BRIDGE_SERVER_UID", "1000")

    client = api_module.user_bridge_client_from_environment()

    assert client is not None
    assert str(client.socket_path) == "/run/overseer/codex-user-bridge.sock"
    assert client.expected_server_uid == 1000


def test_system_api_rejects_invalid_bridge_uid_configuration(
    dedicated, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "OVERSEER_USER_BRIDGE_SOCKET", "/run/overseer/codex-user-bridge.sock"
    )
    monkeypatch.setenv("OVERSEER_USER_BRIDGE_SERVER_UID", "not-a-uid")

    with pytest.raises(ValueError, match="bridge server UID"):
        api_module.user_bridge_client_from_environment()


def test_session_discovery_uses_closed_bridge_contract_and_rejects_paths(
    tmp_path: Path, dedicated
) -> None:
    bridge = FakeUserBridge(
        {
            "codex.sessions.list.v1": {
                "state": "available",
                "observed_at": "2026-08-26T12:00:00+00:00",
                "sessions": [
                    {
                        "session_id": "codex.redacted-session",
                        "project_id": "overseer",
                        "status": "registered",
                        "last_seen_at": "2026-08-26T11:59:00+00:00",
                    }
                ],
            }
        }
    )
    server = ApiServer(tmp_path / "state.sqlite3", bridge)
    try:
        status, payload = server.request(
            "POST",
            "/agent-sessions/discover",
            {"provider_id": "codex", "instance_id": "overseer.default"},
        )
        rejected_status, rejected = server.request(
            "POST",
            "/agent-sessions/discover",
            {
                "provider_id": "codex",
                "instance_id": "overseer.default",
                "codex_projects_registry": "/home/god/.codex/codex-projects.csv",
            },
        )
    finally:
        server.close()

    assert status == 200
    assert payload["bridge_state"] == "available"
    assert payload["sessions"][0]["session_id"] == "codex.redacted-session"
    assert payload["mutation_performed"] is False
    assert rejected_status == 400
    assert rejected["error"] == "unknown dedicated session discovery fields"
    assert bridge.calls == ["codex.sessions.list.v1"]


@pytest.mark.parametrize(
    "method, path, payload",
    [
        ("GET", "/documents/status", None),
        ("GET", "/documents/evidence", None),
        ("GET", "/git/status", None),
        ("GET", "/virtual/operations", None),
        ("GET", "/identity/evidence", None),
        ("POST", "/agent-dispatches", {}),
        ("POST", "/agent-recovery", {}),
        ("POST", "/documents/search", {}),
        ("POST", "/virtual/discover-listeners", {}),
        ("POST", "/identity/rotation-requests/execute", {}),
    ],
)
def test_deferred_user_integrations_report_disabled_without_fallback(
    tmp_path: Path, dedicated, method: str, path: str, payload: dict | None
) -> None:
    server = ApiServer(tmp_path / "state.sqlite3")
    try:
        status, response = server.request(method, path, payload)
    finally:
        server.close()

    assert status == (200 if method == "GET" else 409)
    assert response["status"] == "disabled"
    assert response["reason"] == "typed_user_bridge_method_not_available"
    assert response["host_mutation_performed"] is False


def test_unix_api_listener_and_client_authenticate_kernel_peer_uids(
    tmp_path: Path,
) -> None:
    store = tmp_path / "state.sqlite3"
    SQLiteStore(store).close()
    socket_path = tmp_path / "api.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen()
    server = BoundedThreadingUnixHTTPServer(
        listener.fileno(),
        make_api_handler(str(store), "ordinary-token"),
        socket_path=str(socket_path),
        allowed_peer_uid=os.geteuid(),
        socket_owner_uid=os.geteuid(),
        socket_owner_gid=os.getegid(),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = OverseerApiClient(
            base_url="http://localhost",
            auth_token="ordinary-token",
            unix_socket_path=str(socket_path),
            expected_server_uid=os.geteuid(),
        )
        health = client.health()
        assert health["ok"] is True
        assert health["service"] == "overseer-api"
    finally:
        server.shutdown()
        server.server_close()
        listener.close()
        thread.join(timeout=5)


def test_unix_client_sends_no_http_or_secret_to_wrong_uid_peer(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "impersonator.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    socket_path.chmod(0o600)
    listener.listen()
    received: list[bytes] = []

    def capture() -> None:
        peer, _address = listener.accept()
        try:
            peer.settimeout(2)
            received.append(peer.recv(4096))
        finally:
            peer.close()

    thread = threading.Thread(target=capture, daemon=True)
    thread.start()
    client = OverseerApiClient(
        base_url="http://localhost",
        auth_token="must-not-leak",
        unix_socket_path=str(socket_path),
        expected_server_uid=os.geteuid() + 1,
    )
    try:
        with pytest.raises(PermissionError, match="peer UID"):
            client.service_status()
    finally:
        thread.join(timeout=5)
        listener.close()

    assert received == [b""]
