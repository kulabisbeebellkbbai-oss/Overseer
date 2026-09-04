from __future__ import annotations

import json
from http.client import HTTPConnection
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

import overseer.api as api_module
from overseer.api import BoundedThreadingHTTPServer, make_api_handler
from overseer.collection_models import (
    CircuitState,
    CollectionJob,
    CollectionJobKind,
    CollectionJobState,
    CollectionOutcome,
    CollectionRun,
)
from overseer.collection_scheduler import CollectionScheduler
from overseer.core import OwnerDomain
from overseer.client import OverseerApiClient
from overseer.store import SQLiteStore


class ApiHarness:
    def __init__(self, store_path: Path, token: str = "admin-secret") -> None:
        self.store_path = store_path
        self.token = token
        self.server: BoundedThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url = ""

    def __enter__(self) -> "ApiHarness":
        self.server = BoundedThreadingHTTPServer(
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

    def raw_post(
        self,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes = b"",
    ) -> tuple[int, dict, dict[str, str]]:
        host, port = self.server.server_address
        connection = HTTPConnection(host, port, timeout=2)
        try:
            connection.putrequest("POST", path)
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, json.loads(response.read()), dict(response.headers)
        finally:
            connection.close()


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


@pytest.mark.parametrize("prefix", ["", "/Overseer"])
@pytest.mark.parametrize(
    "content_length",
    [None, "not-a-number", "-1", "0", str(api_module.API_JSON_MAX_BODY_BYTES + 1)],
)
def test_collection_control_rejects_invalid_content_length_before_body_read(
    tmp_path: Path, prefix: str, content_length: str | None
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    headers = [
        ("Authorization", "Bearer admin-secret"),
        ("Content-Type", "application/json"),
    ]
    if content_length is not None:
        headers.append(("Content-Length", content_length))
    with ApiHarness(store_path) as api:
        status, body, _ = api.raw_post(
            f"{prefix}/collections/jobs/collection.health.api/run",
            headers,
            body=b"{}",
        )
    assert status == 400
    assert body == {"error": "invalid_content_length"}


@pytest.mark.parametrize(
    "path",
    [
        "/collections/jobs/collection.health.api/run",
        "/Overseer/collections/jobs/collection.health.api/run",
        "/claims/request",
        "/Overseer/claims/request",
    ],
)
def test_json_routes_reject_duplicate_content_length_before_body_read(
    tmp_path: Path, path: str
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with ApiHarness(store_path) as api:
        status, body, _ = api.raw_post(
            path,
            [
                ("Authorization", "Bearer admin-secret"),
                ("Content-Type", "application/json"),
                ("Content-Length", "2"),
                ("Content-Length", "2"),
            ],
            body=b"{}",
        )
    assert status == 400
    assert body == {"error": "invalid_content_length"}


@pytest.mark.parametrize("path", ["/claims/request", "/Overseer/claims/request"])
@pytest.mark.parametrize("content_length", [None, "not-a-number", "-1", str(api_module.API_JSON_MAX_BODY_BYTES + 1)])
def test_general_json_route_rejects_invalid_content_length_before_body_read(
    tmp_path: Path, path: str, content_length: str | None
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    headers = [
        ("Authorization", "Bearer admin-secret"),
        ("Content-Type", "application/json"),
    ]
    if content_length is not None:
        headers.append(("Content-Length", content_length))
    with ApiHarness(store_path) as api:
        status, body, _ = api.raw_post(path, headers, body=b"{}")
    assert status == 400
    assert body == {"error": "invalid_content_length"}


def test_bounded_server_returns_deterministic_overload_without_waiting_for_handlers(
    tmp_path: Path, monkeypatch
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    started = threading.Event()
    release = threading.Event()
    state_lock = threading.Lock()
    started_count = 0

    def blocked_projection(*args, **kwargs):
        nonlocal started_count
        with state_lock:
            started_count += 1
            if started_count == 2:
                started.set()
        assert release.wait(timeout=2)
        return {"status": "ok"}

    monkeypatch.setattr(api_module, "_collection_scheduler_projection", blocked_projection)
    server = BoundedThreadingHTTPServer(
        ("127.0.0.1", 0), make_api_handler(str(store_path), "admin-secret"), max_workers=2
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    def get_status() -> int:
        connection = HTTPConnection(host, port, timeout=2)
        try:
            connection.request(
                "GET",
                "/collections/status",
                headers={"Authorization": "Bearer admin-secret"},
            )
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_two = [pool.submit(get_status), pool.submit(get_status)]
            assert started.wait(timeout=2)
            assert get_status() == 503
            release.set()
            assert [future.result(timeout=2) for future in first_two] == [200, 200]
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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


def test_collection_runs_filter_has_exact_total_and_limit(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with SQLiteStore(store_path) as store:
        for run in (
            CollectionRun(
                id="run.failed.old",
                job_id="collection.health.api",
                trigger="scheduled",
                started_at="2026-08-24T11:58:00+00:00",
                completed_at="2026-08-24T11:58:01+00:00",
                outcome=CollectionOutcome.FAILED,
            ),
            CollectionRun(
                id="run.succeeded",
                job_id="collection.health.api",
                trigger="scheduled",
                started_at="2026-08-24T11:59:00+00:00",
                completed_at="2026-08-24T11:59:01+00:00",
                outcome=CollectionOutcome.SUCCEEDED,
            ),
            CollectionRun(
                id="run.failed.new",
                job_id="collection.health.api",
                trigger="scheduled",
                started_at="2026-08-24T12:00:00+00:00",
                completed_at="2026-08-24T12:00:01+00:00",
                outcome=CollectionOutcome.FAILED,
            ),
        ):
            store.save_collection_run(run)

    with ApiHarness(store_path) as api:
        status, body, _ = api.get("/collections/runs?status=failed&limit=1")

    assert status == 200
    assert body["total_count"] == 2
    assert body["returned_count"] == 1
    assert body["truncated"] is True
    assert body["runs"][0]["id"] == "run.failed.new"


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
        for route, successor in (
            ("/health/probes/run", "</collections/jobs>; rel=\"successor\""),
            (
                "/Overseer/health/probes/run",
                "</Overseer/collections/jobs>; rel=\"successor\"",
            ),
        ):
            status, body, headers = api.post(route, {})
            assert status == 202
            assert headers["Deprecation"] == "true"
            assert headers["Link"] == successor
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


def test_encoded_unicode_slash_job_id_round_trips_direct_and_prefix(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    job_id = "collection.health/東京"
    seed_job(store_path, job_id)
    with ApiHarness(store_path) as api:
        for base_url in (api.url, f"{api.url}/Overseer"):
            client = OverseerApiClient(base_url=base_url, auth_token=api.token)
            result = client.collection_jobs(job_id=job_id, limit=1)
            assert result["returned_count"] == 1
            assert result["jobs"][0]["id"] == job_id
            queued = client.request_collection_run(job_id, "operator", "encoded id")
            assert queued["status"] in {"queued", "coalesced"}


@pytest.mark.parametrize("encoded_id", ["bad%ZZ", "bad%FF", "a" * 161])
def test_malformed_or_overlong_encoded_job_id_is_a_bounded_bad_request(
    tmp_path: Path, encoded_id: str
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with ApiHarness(store_path) as api:
        status, body, _ = api.post(
            f"/Overseer/collections/jobs/{encoded_id}/run",
            {"requested_by": "operator", "reason": "invalid id"},
        )
    assert status == 400
    assert "secret" not in json.dumps(body).lower()


def test_suspend_resume_retries_are_noops_and_preserve_one_deterministic_audit(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    state = CollectionJobState(
        job_id="collection.health.api",
        next_due_at="2026-08-24T12:00:00+00:00",
        last_completed_at="2026-08-24T11:59:00+00:00",
        last_outcome="failed",
        consecutive_failures=2,
        circuit_state=CircuitState.OPEN,
        cooldown_until="2026-08-24T12:10:00+00:00",
        active_lease_id="lease.api",
        lease_owner="scheduler.local",
        lease_expires_at="2026-08-24T12:05:00+00:00",
        lease_generation=7,
    )
    seed_job(store_path, state=state)
    with SQLiteStore(store_path) as store:
        pending = store.request_collection_run(
            "collection.health.api", "operator", "retain this request"
        )
        before_state = store.load_collection_job_state("collection.health.api")
    with ApiHarness(store_path) as api:
        first_status, first, _ = api.post(
            "/collections/jobs/collection.health.api/suspend",
            {"requested_by": "operator", "reason": "pause"},
        )
        second_status, second, _ = api.post(
            "/collections/jobs/collection.health.api/suspend",
            {"requested_by": "operator", "reason": "pause retry"},
        )
    with SQLiteStore(store_path) as store:
        after_state = store.load_collection_job_state("collection.health.api")
        requests = store.list_collection_requests()
        audits = store.list_audit_events(subject_prefix="collection.health.api")
    assert first_status == second_status == 200
    assert first["changed"] is True
    assert second["changed"] is False
    assert first["audit_id"] == second["audit_id"]
    assert after_state == before_state
    assert requests == (pending,)
    assert len(audits) == 1


def test_concurrent_identical_resume_controls_create_one_transition_and_audit(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path, enabled=False)
    with ApiHarness(store_path) as api:
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(
                pool.map(
                    lambda _: api.post(
                        "/Overseer/collections/jobs/collection.health.api/resume",
                        {"requested_by": "operator", "reason": "resume"},
                    ),
                    (1, 2),
                )
            )
    assert [item[0] for item in results] == [200, 200]
    assert sorted(item[1]["changed"] for item in results) == [False, True]
    assert len({item[1]["audit_id"] for item in results}) == 1
    with SQLiteStore(store_path) as store:
        assert store.load_collection_job("collection.health.api").enabled is True
        assert len(store.list_audit_events(subject_prefix="collection.health.api")) == 1


def test_deprecated_health_enqueue_is_fixed_bounded_and_reports_truncation(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    job_ids = [f"collection.health.{index:03d}" for index in range(60)]
    for job_id in job_ids:
        seed_job(store_path, job_id)
    with ApiHarness(store_path) as api:
        status, body, headers = api.post("/health/probes/run", {})
    assert status == 202
    assert headers["Deprecation"] == "true"
    assert body["total_count"] == 60
    assert body["returned_count"] < body["total_count"]
    assert body["truncated"] is True
    assert len(body["requests"]) == body["returned_count"]
    assert "deprecated health probe compatibility request" not in json.dumps(body)
    with SQLiteStore(store_path) as store:
        assert len(store.list_collection_requests()) == body["returned_count"]


def test_collection_query_schemas_reject_ignored_status_and_unknown_fields(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    with ApiHarness(store_path) as api:
        assert api.get("/collections/status?status=open")[0] == 400
        assert api.get("/collections/status?status=enabled")[0] == 400
        assert api.get("/collections/runbooks?status=open")[0] == 400
        assert api.get("/collections/jobs?status=open")[0] == 400
        assert api.get("/collections/jobs?unexpected=1")[0] == 400


def test_collection_get_maps_unexpected_errors_to_bounded_500(
    tmp_path: Path, monkeypatch
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)

    def fail(*args, **kwargs):
        raise RuntimeError("database secret should not escape")

    monkeypatch.setattr(api_module, "collection_jobs_status", fail)
    with ApiHarness(store_path) as api:
        status, body, _ = api.get("/Overseer/collections/jobs")
    assert status == 500
    assert body == {"error": "internal_error"}
    assert "secret" not in json.dumps(body)


def test_collection_control_preserves_deprecation_headers_on_internal_error(
    tmp_path: Path, monkeypatch
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    seed_job(store_path)
    monkeypatch.setattr(
        api_module,
        "_legacy_health_probe_requests",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret")),
    )
    with ApiHarness(store_path) as api:
        status, body, headers = api.post("/Overseer/health/probes/run", {})
    assert status == 500
    assert body == {"error": "internal_error"}
    assert headers["Deprecation"] == "true"
    assert "secret" not in json.dumps(body)
