from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from overseer.api import make_api_handler
from overseer.collection_models import CollectionJob, CollectionJobKind, CollectionJobState
from overseer.collection_scheduler import CollectionScheduler
from overseer.core import OwnerDomain
from overseer.client import OverseerApiClient
from overseer.store import SQLiteStore


class ApiHarness:
    def __init__(self, store_path: Path, token: str = "admin-secret") -> None:
        self.store_path = store_path
        self.token = token
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url = ""

    def __enter__(self) -> "ApiHarness":
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), make_api_handler(str(self.store_path), self.token)
        )
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        assert self.server is not None
        self.server.shutdown()
        self.server.server_close()
        assert self.thread is not None
        self.thread.join(timeout=5)

    def request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        *,
        authenticated: bool = True,
    ) -> tuple[int, dict, dict[str, str]]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = Request(f"{self.url}{path}", data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if authenticated:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read()), dict(response.headers)
        except HTTPError as error:
            return error.code, json.loads(error.read()), dict(error.headers)

    def get(self, path: str, *, authenticated: bool = True):
        return self.request("GET", path, authenticated=authenticated)

    def post(self, path: str, payload: dict, *, authenticated: bool = True):
        return self.request("POST", path, payload, authenticated=authenticated)


def seed_job(
    store_path: Path,
    job_id: str = "collection.health.api",
    *,
    enabled: bool = True,
    state: CollectionJobState | None = None,
) -> None:
    with SQLiteStore(store_path) as store:
        store.save_collection_job(
            CollectionJob(
                id=job_id,
                kind=CollectionJobKind.HEALTH_PROBE,
                owner_domain=OwnerDomain.JULIAN,
                resource_id="resource.api",
                target_id="health.api",
                enabled=enabled,
            ),
            state=state,
        )


def test_scheduler_routes_exist_under_protected_prefix(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with ApiHarness(store_path) as api:
        assert api.get("/Overseer/collections/status")[0] == 200
        assert api.post(
            "/Overseer/collections/jobs/collection.health.api/run",
            {"requested_by": "operator", "reason": "verify after incident"},
        )[0] == 202


def test_run_request_enqueues_without_calling_adapter(tmp_path: Path, monkeypatch) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    monkeypatch.setattr(
        CollectionScheduler,
        "run_ready_once",
        lambda *_: pytest.fail("inline collection"),
    )
    with ApiHarness(store_path) as api:
        status, result, _ = api.post(
            "/Overseer/collections/jobs/collection.health.api/run",
            {"requested_by": "operator", "reason": "verify after incident"},
        )
    assert status == 202
    assert result["status"] in {"queued", "coalesced"}
    assert result["request_id"].startswith("request.collection.")
    assert "earliest_execution_at" in result
    assert set(result["circuit"]) == {"state", "cooldown_until"}
    assert "verify after incident" not in json.dumps(result)


def test_scheduler_get_routes_use_authentication_and_prefix_contract(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    routes = (
        "/collections/status",
        "/collections/jobs",
        "/collections/runs",
        "/collections/incidents",
        "/collections/runbooks",
    )
    with ApiHarness(store_path) as api:
        for route in routes:
            assert api.get(f"/Overseer{route}", authenticated=False)[0] == 401
            assert api.get(route, authenticated=False)[0] == 401
            assert api.get(f"/Overseer{route}")[0] == 200
            assert api.get(route)[0] == 200


def test_control_routes_require_admin_token_and_reject_extra_fields(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with ApiHarness(store_path) as api:
        assert api.post(
            "/Overseer/collections/jobs/collection.health.api/run",
            {"requested_by": "operator", "reason": "x"},
            authenticated=False,
        )[0] == 401
        status, body, _ = api.post(
            "/Overseer/collections/jobs/collection.health.api/run",
            {"requested_by": "operator", "reason": "x", "extra": False},
        )
    assert status == 400
    assert "exact collection control fields" in body["error"]


def test_suspend_preserves_active_lease_and_generation(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    state = CollectionJobState(
        job_id="collection.health.api",
        next_due_at="2026-08-24T12:00:00+00:00",
        active_lease_id="lease.api",
        lease_owner="scheduler.local",
        lease_expires_at="2026-08-24T12:05:00+00:00",
        lease_generation=7,
    )
    seed_job(store_path, state=state)
    with ApiHarness(store_path) as api:
        status, _, _ = api.post(
            "/collections/jobs/collection.health.api/suspend",
            {"requested_by": "operator", "reason": "pause during maintenance"},
        )
    assert status == 200
    with SQLiteStore(store_path) as store:
        job = store.list_collection_jobs()[0]
        saved_state = store.load_collection_job_state("collection.health.api")
    assert job.enabled is False
    assert saved_state is not None
    assert saved_state.active_lease_id == "lease.api"
    assert saved_state.lease_generation == 7


def test_collection_projections_are_bounded_and_do_not_echo_reason(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with SQLiteStore(store_path) as store:
        store.request_collection_run(
            "collection.health.api", "operator", "do not expose this reason"
        )
    with ApiHarness(store_path) as api:
        for route in (
            "/collections/status?limit=1",
            "/collections/jobs?limit=1",
            "/collections/runs?limit=1",
            "/collections/incidents?limit=1",
            "/collections/runbooks?limit=1",
        ):
            status, body, _ = api.get(route)
            assert status == 200
            serialized = json.dumps(body)
            assert "do not expose this reason" not in serialized
            assert "response_body" not in serialized
            assert "password" not in serialized


def test_deprecated_health_probe_route_only_enqueues_and_sets_successor_headers(
    tmp_path: Path, monkeypatch
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    monkeypatch.setattr(
        CollectionScheduler,
        "run_ready_once",
        lambda *_: pytest.fail("deprecated route probed inline"),
    )
    with ApiHarness(store_path) as api:
        status, body, headers = api.post("/Overseer/health/probes/run", {})
    assert status == 202
    assert headers["Deprecation"] == "true"
    assert headers["Link"] == "</Overseer/collections/jobs>; rel=\"successor\""
    assert body["request_count"] == 1
    assert len(body["requests"]) == 1
    assert "reason" not in json.dumps(body)


def test_client_collection_methods_preserve_prefix_and_filters(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with ApiHarness(store_path) as api:
        client = OverseerApiClient(
            base_url=f"{api.url}/Overseer", auth_token=api.token
        )
        assert client.collection_jobs(job_id="collection.health.api", limit=1)[
            "returned_count"
        ] == 1
        assert client.request_collection_run(
            "collection.health.api", "operator", "client request"
        )["status"] in {"queued", "coalesced"}
