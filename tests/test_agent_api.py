from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from overseer import (
    ApprovalLevel,
    ApprovalRequest,
    ApprovalStatus,
    OwnerDomain,
    SQLiteStore,
)
from overseer.api import make_api_handler
from overseer.cli import main
from overseer.client import OverseerApiClient


class ApiResponse:
    def __init__(self, status_code: int, headers, body: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self._payload = json.loads(body.decode("utf-8"))

    def json(self) -> dict[str, object]:
        return self._payload


class LocalAPI:
    def __init__(
        self,
        store_path: Path,
        *,
        auth_token: str | None = None,
    ) -> None:
        self.store_path = store_path
        self.auth_token = auth_token

    def __enter__(self) -> LocalAPI:
        handler = make_api_handler(str(self.store_path), self.auth_token)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def get(self, path: str, *, authenticated: bool = True) -> ApiResponse:
        return self._request("GET", path, authenticated=authenticated)

    def post_json(
        self,
        path: str,
        payload: dict[str, object],
        *,
        authenticated: bool = True,
    ) -> ApiResponse:
        return self._request(
            "POST",
            path,
            payload=payload,
            authenticated=authenticated,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        authenticated: bool,
    ) -> ApiResponse:
        headers = {"content-type": "application/json"}
        if authenticated and self.auth_token is not None:
            headers["authorization"] = f"Bearer {self.auth_token}"
        request = Request(
            f"{self.base_url}{path}",
            data=(
                json.dumps(payload).encode("utf-8")
                if payload is not None
                else None
            ),
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=5) as response:
                return ApiResponse(response.status, response.headers, response.read())
        except HTTPError as error:
            return ApiResponse(error.code, error.headers, error.read())


@pytest.fixture
def api(tmp_path: Path) -> LocalAPI:
    with LocalAPI(tmp_path / "overseer.sqlite3") as value:
        yield value


def test_agent_provider_inventory(api: LocalAPI) -> None:
    client = OverseerApiClient(base_url=api.base_url)

    response = client.list_agent_providers()

    assert {row["id"] for row in response["providers"]} >= {"codex", "claude"}
    assert all("executable_path" not in row for row in response["providers"])


def test_agent_inventory_uses_existing_api_authentication(tmp_path: Path) -> None:
    with LocalAPI(
        tmp_path / "overseer.sqlite3",
        auth_token="test-token",
    ) as protected:
        unauthorized = protected.get("/agent-providers", authenticated=False)
        authorized = protected.get("/agent-providers")

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200


def test_manual_handoff_requires_approval_id(api: LocalAPI) -> None:
    response = api.post_json(
        "/agent-handoffs",
        {
            "instance_id": "overseer.default",
            "incoming_provider_id": "claude",
            "initiated_by": "operator",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "approval_id is required"


def test_dispatch_requires_idempotency_key(api: LocalAPI) -> None:
    response = api.post_json(
        "/agent-dispatches",
        {
            "instance_id": "overseer.default",
            "prompt": "inspect health",
            "requested_by": "operator",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"] == "idempotency_key is required"


def test_failover_requires_explicit_provider_and_approval(api: LocalAPI) -> None:
    missing_provider = api.post_json(
        "/agent-failover",
        {
            "instance_id": "overseer.default",
            "approval_id": "approval.agent-failover",
            "initiated_by": "operator",
        },
    )
    missing_approval = api.post_json(
        "/agent-failover",
        {
            "instance_id": "overseer.default",
            "incoming_provider_id": "claude",
            "initiated_by": "operator",
        },
    )

    assert missing_provider.status_code == 400
    assert missing_provider.json()["error"] == "incoming_provider_id is required"
    assert missing_approval.status_code == 400
    assert missing_approval.json()["error"] == "approval_id is required"


def test_agent_session_and_dispatch_lists_are_persisted_store_views(
    api: LocalAPI,
) -> None:
    sessions = api.get("/agent-sessions")
    dispatches = api.get("/agent-dispatches")

    assert sessions.status_code == 200
    assert sessions.json() == {"sessions": []}
    assert dispatches.status_code == 200
    assert dispatches.json() == {"dispatches": [], "results": []}


def test_legacy_discovery_route_delegates_to_generic_handler(
    api: LocalAPI,
    tmp_path: Path,
) -> None:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
        "conversation-1,Example,.,codex-example,/bin/codex-example,"
        "2026-07-29T00:00:00+00:00,2026-07-29T00:00:00+00:00,registry,\n",
        encoding="utf-8",
    )
    payload = {"codex_projects_registry": str(registry)}

    legacy = api.post_json("/codex-projects/discover-threads", payload)
    generic = api.post_json(
        "/agent-sessions/discover",
        {
            **payload,
            "provider_id": "codex",
            "instance_id": "overseer.default",
        },
    )

    assert legacy.status_code == 200
    assert generic.status_code == 200
    assert legacy.json()["resources"] == generic.json()["resources"]
    assert legacy.json()["items"] == generic.json()["items"]
    assert legacy.headers["Deprecation"] == "true"
    assert legacy.headers["Link"] == '</agent-sessions/discover>; rel="successor-version"'


@pytest.mark.parametrize(
    "command",
    [
        "agent-providers",
        "agent-instances",
        "discover-agent-sessions",
        "agent-session-status",
        "dispatch-agent-goal",
        "checkpoint-agent",
        "recover-agent",
        "handoff-agent",
        "failover-agent",
    ],
)
def test_generic_agent_cli_commands_are_registered(command: str) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main([command, "--help"])

    assert exit_info.value.code == 0


def test_agent_provider_cli_prints_provider_neutral_inventory(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["agent-providers"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert {row["id"] for row in payload["providers"]} >= {"codex", "claude"}


def test_handoff_rejects_an_approval_for_an_unrelated_subject(
    api: LocalAPI,
) -> None:
    store = SQLiteStore(api.store_path)
    store.save_approval(
        ApprovalRequest(
            id="approval.unrelated",
            subject_id="agent-handoff:another.instance:claude",
            approval_level=ApprovalLevel.HUMAN,
            requester_thread="operator",
            owner_domain=OwnerDomain.SISKO,
            reason="approval belongs to another agent instance",
            status=ApprovalStatus.APPROVED,
            decided_by="operator",
        )
    )
    store.close()

    response = api.post_json(
        "/agent-handoffs",
        {
            "instance_id": "overseer.default",
            "incoming_provider_id": "claude",
            "initiated_by": "operator",
            "approval_id": "approval.unrelated",
        },
    )

    assert response.status_code == 403
    assert response.json()["error"] == (
        "manual_handoff rejected by Overseer policy callback"
    )


def test_agent_discovery_records_bounded_audit_evidence(
    api: LocalAPI,
    tmp_path: Path,
) -> None:
    registry = tmp_path / "empty-codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n",
        encoding="utf-8",
    )

    response = api.post_json(
        "/agent-sessions/discover",
        {
            "provider_id": "codex",
            "instance_id": "overseer.default",
            "codex_projects_registry": str(registry),
        },
    )
    store = SQLiteStore(api.store_path)
    events = store.list_audit_events(subject_prefix="agent.discovery:")
    store.close()

    assert response.status_code == 200
    assert len(events) == 1
    assert events[0].subject_id == "agent.discovery:overseer.default:codex"
    assert events[0].evidence_ids == ()
