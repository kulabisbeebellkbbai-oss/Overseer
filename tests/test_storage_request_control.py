from __future__ import annotations

import json
import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from overseer.storage_control import create_execution_request, create_execution_request_api
from overseer.storage_control_cli import main as storage_control_main
from overseer.store import SQLiteStore
from tests.test_storage_adapter import claim, registration
from tests.test_agent_api import LocalAPI


def payload(now: datetime, **changes) -> dict[str, object]:
    value: dict[str, object] = {
        "request_id": "request-create-1",
        "adapter_id": "storage-adapter.theunderdark",
        "adapter_revision": 1,
        "project_id": "project.donuthole",
        "resource_id": "storage.donuthole",
        "root_id": "root",
        "action": "file.write",
        "parameters": {"relative_path": "backups/run-1", "content": "data", "content_digest": {"algorithm": "sha256", "value": hashlib.sha256(b"data").hexdigest()}, "write_mode": "create_only", "content_encoding": "utf8", "expected_prior_digest": None},
        "policy_revision": "1",
        "claim_id": "claim-1",
        "approval_id": "approval-request-create-1",
        "authorization_ref": "authorization-request-create-1",
        "idempotency_key": "idempotency-request-create-1",
        "requested_by": "project.donuthole",
        "reason": "Create one approved bounded directory",
        "acceptance_criteria": ["directory exists", "terminal evidence verified"],
        "limits": {"max_bytes": 1, "max_items": 1},
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
    }
    value.update(changes)
    return value


def seed(path, now: datetime, *, enabled=True) -> None:
    adapter = registration()
    if not enabled:
        adapter = replace(adapter, status=adapter.status.SUSPENDED)
    with SQLiteStore(path) as store:
        store.save_claim(claim(now))
        store.save_storage_adapter_registration(adapter)


def test_supported_creation_computes_digest_and_round_trips_immutably(tmp_path) -> None:
    path = tmp_path / "state.sqlite3"
    now = datetime.now(UTC)
    seed(path, now)
    created = create_execution_request(str(path), payload(now), now.isoformat())
    assert created["ok"] and created["status"] == "stored"
    assert created["request_digest"].startswith("sha256:")
    assert "parameters" not in created and "reason" not in created
    with SQLiteStore(path) as store:
        stored = store.load_storage_execution_request("request-create-1")
    assert stored.request_digest == stored.canonical_digest()
    assert stored.parameters["relative_path"] == "backups/run-1"

    assert create_execution_request(str(path), payload(now), now.isoformat())["request_digest"] == created["request_digest"]
    with pytest.raises(ValueError, match="idempotency"):
        create_execution_request(str(path), payload(now, reason="changed"), now.isoformat())


@pytest.mark.parametrize(
    "changes",
    [
        {"unexpected": True},
        {"project_id": "project.other"},
        {"claim_id": "claim-missing"},
        {"adapter_revision": 2},
        {"expires_at": "2000-01-01T00:00:00+00:00"},
        {"parameters": {"relative_path": "../escape", "content": "data", "content_digest": {"algorithm": "sha256", "value": "0" * 64}, "write_mode": "create_only", "content_encoding": "utf8", "expected_prior_digest": None}},
        {"parameters": {"relative_path": "safe"}},
        {"limits": {"max_bytes": 0, "max_items": 1}},
    ],
)
def test_creation_fails_closed_for_mismatch_and_ambiguous_input(tmp_path, changes) -> None:
    path = tmp_path / "state.sqlite3"
    now = datetime.now(UTC)
    seed(path, now)
    request_payload = payload(now)
    if "unexpected" in changes:
        request_payload["unexpected"] = changes["unexpected"]
    else:
        request_payload.update(changes)
    with pytest.raises((ValueError, KeyError)):
        create_execution_request(str(path), request_payload, now.isoformat())
    with SQLiteStore(path) as store:
        with pytest.raises(KeyError):
            store.load_storage_execution_request("request-create-1")


def test_disabled_adapter_and_short_claim_are_rejected(tmp_path) -> None:
    now = datetime.now(UTC)
    disabled = tmp_path / "disabled.sqlite3"
    seed(disabled, now, enabled=False)
    with pytest.raises(ValueError, match="adapter"):
        create_execution_request(str(disabled), payload(now), now.isoformat())

    short = tmp_path / "short.sqlite3"
    with SQLiteStore(short) as store:
        store.save_storage_adapter_registration(registration())
        store.save_claim(replace(claim(now), expires_at=(now + timedelta(minutes=1)).isoformat()))
    with pytest.raises(ValueError, match="claim"):
        create_execution_request(str(short), payload(now), now.isoformat())


def test_api_wrapper_and_cli_use_the_same_supported_boundary(tmp_path, capsys) -> None:
    now = datetime.now(UTC)
    api_path = tmp_path / "api.sqlite3"
    seed(api_path, now)
    response = create_execution_request_api(str(api_path), {"payload": payload(now)})
    assert response["status"] == "stored" and response["redactions_applied"] is True
    with pytest.raises(ValueError, match="envelope"):
        create_execution_request_api(str(api_path), {"payload": payload(now), "extra": True})

    cli_path = tmp_path / "cli.sqlite3"
    seed(cli_path, now)
    assert storage_control_main([
        "--store", str(cli_path), "request-create", "--payload-json", json.dumps(payload(now)),
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "stored" and "parameters" not in output


def test_authenticated_admin_api_creates_redacted_request_record(tmp_path) -> None:
    now = datetime.now(UTC)
    path = tmp_path / "http.sqlite3"
    seed(path, now)
    with LocalAPI(path, auth_token="admin-token") as api:
        response = api.post_json("/storage/control/requests", {"payload": payload(now)}, authenticated=True)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "stored" and body["redactions_applied"] is True
    assert "parameters" not in body and "reason" not in body
