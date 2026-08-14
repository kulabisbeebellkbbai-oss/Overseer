"""Quark-managed remote testing queue profiles, leases, and controls."""

from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_PROFILE_ID = "remote-testing.tank-msi"
DEFAULT_QUEUE_ROOT = "local-secrets/remote-testing"
CONTROL_FILENAME = "quark-control.json"
DEFAULT_REMOTE_HOST = "god@10.50.0.100"
DEFAULT_TEST_ACCOUNT_ID = "tank-msi-gateway-test"
TEST_TOKEN_PREFIX = "qrt_"
MAX_TEST_TOKEN_TTL_MINUTES = 120
FORBIDDEN_TRANSPORTS = ("god@192.168.68.xxx", "192.168.68.xxx")
SUPPORTED_AGENT_KINDS = ("windows", "android", "ios", "macos", "linux", "browser", "gateway")
SUPPORTED_JOB_TYPES = (
    "ping",
    "overseer.http_status",
    "overseer.auth_panel_smoke",
    "overseer.admin_approve_smoke",
    "overseer.full_ui_regression",
    "overseer.performance_regression",
    "protected_gateway.request_sequence",
    "tank.local_facility_request",
    "roadex.authenticated_session_prompt",
    "roadex.project_creation_flow",
    "psychlo.authenticated_browser_verify",
)
SCOPED_TOKEN_REQUIRED_JOB_TYPES = (
    "roadex.authenticated_session_prompt",
    "psychlo.authenticated_browser_verify",
)
SENSITIVE_KEY_PARTS = (
    "token",
    "cookie",
    "secret",
    "password",
    "api_key",
    "apikey",
    "bearer",
    "authorization",
    "local_storage",
    "storage_state",
)


def remote_testing_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    queue_root = _queue_root(root)
    state = _load_control_state(root)
    state = _with_default_profile(state, root)
    leases = [_lease_status(item) for item in state.get("leases", {}).values()]
    return {
        "project_root": str(root),
        "queue_root": str(queue_root),
        "contract_path": str(queue_root / "QUEUE_CONTRACT.md"),
        "connection_profiles": list(state.get("profiles", {}).values()),
        "test_accounts": [_redacted_account_status(item) for item in state.get("test_accounts", {}).values()],
        "test_token_grants": [_redacted_token_status(item) for item in state.get("test_tokens", {}).values()],
        "recent_test_auth_events": list(state.get("test_auth_events", []))[-20:],
        "default_profile_id": state.get("default_profile_id", DEFAULT_PROFILE_ID),
        "adapter_status": _adapter_status(queue_root, state),
        "lease_profile": {
            "owner": "quark",
            "manager": "Tank on MSI",
            "default_ttl_minutes": 120,
            "protected_gateway_required": True,
            "forbidden_transports": list(FORBIDDEN_TRANSPORTS),
            "mutating_jobs": "disabled unless a disposable fixture is supplied by the job contract",
            "secret_policy": "raw tokens, cookies, browser storage, and credentials are never accepted in queue jobs",
        },
        "supported_job_types": list(SUPPORTED_JOB_TYPES),
        "queue_counts": _queue_counts(queue_root),
        "active_leases": [item for item in leases if item["status"] == "active"],
        "leases": leases,
        "pending_jobs": _job_summaries(queue_root / "jobs" / "pending", "pending", limit=20),
        "claimed_jobs": _job_summaries(queue_root / "jobs" / "claimed", "claimed", limit=20),
        "recent_results": _recent_results(queue_root, limit=20),
        "control_actions": [
            "record-remote-testing-profile",
            "request-remote-testing-lease",
            "enqueue-remote-test-job",
            "collect-remote-test-results",
            "record-remote-testing-account",
            "issue-remote-testing-token",
            "revoke-remote-testing-token",
        ],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def record_remote_testing_account_status(
    project_root: str | Path,
    account_id: str = DEFAULT_TEST_ACCOUNT_ID,
    display_name: str = "Tank/MSI gateway test account",
    agent_kind: str = "windows",
    agent_id: str = "tank-msi",
    allowed_projects: tuple[str, ...] | list[str] = ("*",),
    allowed_service_paths: tuple[str, ...] | list[str] = ("*",),
    allowed_gateway_origins: tuple[str, ...] | list[str] = ("*",),
    gateway_principal: str = "owner",
    enabled: bool = True,
    recorded_by: str = "quark",
) -> dict[str, object]:
    if agent_kind not in SUPPORTED_AGENT_KINDS:
        raise ValueError("unsupported agent_kind")
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    now = _now()
    account = {
        "account_id": _required_id(account_id, "account_id"),
        "display_name": display_name,
        "owner": "quark",
        "security_owner": "odo",
        "agent_kind": agent_kind,
        "agent_id": _required_id(agent_id, "agent_id"),
        "enabled": bool(enabled),
        "default_access": "read_only",
        "allowed_projects": _normalized_scope_list(allowed_projects, allow_wildcard=True),
        "allowed_service_paths": _normalized_service_paths(allowed_service_paths, allow_wildcard=True),
        "allowed_gateway_origins": _normalized_scope_list(allowed_gateway_origins, allow_wildcard=True),
        "gateway_principal": _required_id(gateway_principal, "gateway_principal"),
        "mutation_policy": "deny_by_default; exact job grant required",
        "monitoring": {
            "owner": "odo",
            "events": [
                "issued",
                "used",
                "denied",
                "revoked",
                "expired",
                "source_mismatch",
                "scope_violation",
                "mutation_attempt",
            ],
            "auto_disable_on_scope_violation": True,
        },
        "recorded_by": recorded_by,
        "recorded_at": now,
        "updated_at": now,
    }
    state.setdefault("test_accounts", {})[account["account_id"]] = account
    _save_control_state(root, state)
    _record_auth_event(state, account["account_id"], None, "account_recorded", "quark", {"enabled": bool(enabled)})
    _save_control_state(root, state)
    return {
        "account": _redacted_account_status(account),
        "status": remote_testing_status(root),
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def issue_remote_testing_token_status(
    project_root: str | Path,
    account_id: str = DEFAULT_TEST_ACCOUNT_ID,
    lease_id: str | None = None,
    job_id: str | None = None,
    project: str = "Overseer",
    thread_id: str | None = None,
    service_paths: tuple[str, ...] | list[str] = ("/Overseer",),
    gateway_origins: tuple[str, ...] | list[str] = ("https://roadex.home.arpa:9443",),
    allowed_methods: tuple[str, ...] | list[str] = ("GET", "HEAD", "OPTIONS"),
    allowed_routes: tuple[str, ...] | list[str] = ("*",),
    ttl_minutes: int = 30,
    mutates: bool = False,
    mutation_scope: dict[str, object] | None = None,
    issued_by: str = "quark",
) -> dict[str, object]:
    if ttl_minutes <= 0:
        raise ValueError("ttl_minutes must be positive")
    ttl_minutes = min(ttl_minutes, MAX_TEST_TOKEN_TTL_MINUTES)
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    account = state.get("test_accounts", {}).get(account_id)
    if not account:
        account = record_remote_testing_account_status(root, account_id=account_id, recorded_by=issued_by)["account"]
        state = _with_default_profile(_load_control_state(root), root)
        account = state.get("test_accounts", {}).get(account_id)
    if not account or not account.get("enabled", False):
        raise ValueError("remote testing account is disabled")
    if lease_id:
        lease = state.get("leases", {}).get(lease_id)
        if not lease or _lease_status(lease)["status"] != "active":
            raise ValueError("lease_id is not active")
        if job_id and job_id not in lease.get("job_ids", []):
            raise ValueError("job_id is not registered on the lease")
    normalized_methods = tuple(str(method).upper() for method in allowed_methods)
    if mutates and not mutation_scope:
        raise ValueError("mutating test tokens require an exact mutation_scope")
    if mutates:
        scope_methods = _normalized_scope_list(
            mutation_scope.get("allowed_methods", mutation_scope.get("methods", [])),
            allow_wildcard=False,
        )
        scope_routes = _normalized_routes(mutation_scope.get("allowed_routes", mutation_scope.get("routes", [])))
        if not scope_methods or not scope_routes:
            raise ValueError("mutating test tokens require mutation_scope.allowed_methods and mutation_scope.allowed_routes")
    if not mutates and any(method not in {"GET", "HEAD", "OPTIONS"} for method in normalized_methods):
        raise ValueError("read-only test tokens may only allow GET, HEAD, or OPTIONS")
    token_id = f"rtt.{_safe_id(account_id)}.{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.{secrets.token_hex(4)}"
    raw_token = f"{TEST_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=ttl_minutes)
    grant = {
        "token_id": token_id,
        "token_hash": token_hash,
        "account_id": account_id,
        "lease_id": lease_id,
        "job_id": job_id,
        "project": project,
        "thread_id": thread_id,
        "service_paths": _normalized_service_paths(service_paths, allow_wildcard=True),
        "gateway_origins": _normalized_scope_list(gateway_origins, allow_wildcard=True),
        "allowed_methods": list(normalized_methods),
        "allowed_routes": _normalized_routes(allowed_routes),
        "mutates": bool(mutates),
        "mutation_scope": mutation_scope or {},
        "status": "active",
        "issued_by": issued_by,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "token_source": f"remote-testing-token:{token_id}",
        "token_path": str(_write_token_file(root, token_id, raw_token)),
        "redaction": {
            "raw_token_returned": False,
            "token_hash_prefix": token_hash[:19],
        },
    }
    state.setdefault("test_tokens", {})[token_id] = grant
    _record_auth_event(state, account_id, token_id, "token_issued", issued_by, _redacted_token_status(grant))
    _save_control_state(root, state)
    return {
        "token": _redacted_token_status(grant),
        "token_source": grant["token_source"],
        "token_path": grant["token_path"],
        "status": remote_testing_status(root),
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def revoke_remote_testing_token_status(
    project_root: str | Path,
    token_id: str,
    revoked_by: str = "quark",
    reason: str = "test complete",
) -> dict[str, object]:
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    grant = state.get("test_tokens", {}).get(token_id)
    if not grant:
        raise ValueError("token_id is not registered")
    grant["status"] = "revoked"
    grant["revoked_by"] = revoked_by
    grant["revoked_at"] = _now()
    grant["revoke_reason"] = reason
    token_path = Path(str(grant.get("token_path", "")))
    if token_path.exists() and _is_relative_to(token_path.resolve(), _queue_root(root).resolve()):
        token_path.unlink()
    state.setdefault("test_tokens", {})[token_id] = grant
    _record_auth_event(state, str(grant.get("account_id")), token_id, "token_revoked", revoked_by, {"reason": reason})
    _save_control_state(root, state)
    return {
        "token": _redacted_token_status(grant),
        "status": remote_testing_status(root),
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def validate_remote_testing_token(
    project_root: str | Path,
    raw_token: str,
    method: str,
    raw_path: str,
    normalized_path: str,
) -> dict[str, object] | None:
    if not raw_token.startswith(TEST_TOKEN_PREFIX):
        return None
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    token_hash = _hash_token(raw_token)
    def deny(account_id: str | None, token_id: str | None, reason: str) -> dict[str, object]:
        denied = _auth_denied(state, account_id, token_id, reason, method, raw_path)
        _save_control_state(root, state)
        return denied

    grant = next((item for item in state.get("test_tokens", {}).values() if item.get("token_hash") == token_hash), None)
    if not grant:
        return deny(None, None, "unknown_token")
    account_id = str(grant.get("account_id"))
    account = state.get("test_accounts", {}).get(account_id)
    if not account or not account.get("enabled", False):
        return deny(account_id, str(grant.get("token_id")), "account_disabled")
    token_id = str(grant.get("token_id"))
    status = str(grant.get("status", "active"))
    if status != "active":
        return deny(account_id, token_id, f"token_{status}")
    if _is_expired(str(grant.get("expires_at", ""))):
        grant["status"] = "expired"
        state.setdefault("test_tokens", {})[token_id] = grant
        return deny(account_id, token_id, "token_expired")
    method = method.upper()
    if method not in set(grant.get("allowed_methods", [])):
        return deny(account_id, token_id, "method_not_allowed")
    if method not in {"GET", "HEAD", "OPTIONS"} and not grant.get("mutates", False):
        return deny(account_id, token_id, "mutation_not_allowed")
    if not _path_matches_service_scope(raw_path, grant.get("service_paths", [])):
        return deny(account_id, token_id, "service_path_not_allowed")
    if not _route_allowed(normalized_path, grant.get("allowed_routes", [])):
        return deny(account_id, token_id, "route_not_allowed")
    if method not in {"GET", "HEAD", "OPTIONS"} and not _mutation_scope_allowed(grant, method, raw_path, normalized_path):
        return deny(account_id, token_id, "mutation_scope_not_allowed")
    _record_auth_event(
        state,
        account_id,
        token_id,
        "token_used",
        "api",
        {"method": method, "path": _redacted_path(raw_path), "normalized_path": _redacted_path(normalized_path)},
    )
    _save_control_state(root, state)
    return {
        "authorized": True,
        "auth_type": "remote_testing_token",
        "account_id": account_id,
        "token_id": token_id,
        "project": grant.get("project"),
        "thread_id": grant.get("thread_id"),
        "mutates": bool(grant.get("mutates", False)),
        "gateway_principal": str(account.get("gateway_principal", "")),
    }


def record_remote_testing_profile_status(
    project_root: str | Path,
    profile_id: str = DEFAULT_PROFILE_ID,
    display_name: str = "Tank on MSI remote testing queue",
    worker_hint: str = "overseer-msi-test-agent",
    queue_root: str = DEFAULT_QUEUE_ROOT,
    base_url: str = "http://127.0.0.1:8766",
    ui_path: str = "/Overseer/ui",
    gateway_path: str = "/Overseer",
    token_source: str = "state/api-token",
    recorded_by: str = "quark",
    remote_host: str = DEFAULT_REMOTE_HOST,
) -> dict[str, object]:
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    profile = {
        "profile_id": _required_id(profile_id, "profile_id"),
        "display_name": display_name,
        "owner": "quark",
        "remote_operator": "Tank",
        "remote_host": remote_host,
        "remote_node": "MSI",
        "transport": "protected_gateway_or_vpn_reachable_ssh",
        "protected_gateway_required": True,
        "forbidden_transports": list(FORBIDDEN_TRANSPORTS),
        "worker_status_path": "%LOCALAPPDATA%/OverseerMsiTestAgent/status.json",
        "launcher": "Captures/overseer-msi-test-agent-start.ps1",
        "worker_hint": worker_hint,
        "queue_root": queue_root,
        "base_url": base_url,
        "ui_path": ui_path,
        "gateway_path": gateway_path,
        "token_source": token_source,
        "supported_job_types": list(SUPPORTED_JOB_TYPES),
        "redaction": {
            "raw_tokens": False,
            "raw_cookies": False,
            "raw_browser_storage": False,
            "raw_response_bodies": False,
            "allowed": ["endpoint names", "HTTP status codes", "short hashes", "validation stages", "findings"],
        },
        "recorded_by": recorded_by,
        "recorded_at": _now(),
    }
    state.setdefault("profiles", {})[profile["profile_id"]] = profile
    state["default_profile_id"] = profile["profile_id"]
    _save_control_state(root, state)
    return {
        "profile": profile,
        "status": remote_testing_status(root),
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def request_remote_testing_lease_status(
    project_root: str | Path,
    lease_id: str,
    project: str,
    purpose: str,
    requested_by: str = "quark",
    job_types: tuple[str, ...] | list[str] = ("ping",),
    ttl_minutes: int = 120,
    priority: str = "normal",
    profile_id: str = DEFAULT_PROFILE_ID,
) -> dict[str, object]:
    if ttl_minutes <= 0:
        raise ValueError("ttl_minutes must be positive")
    invalid = [item for item in job_types if item not in SUPPORTED_JOB_TYPES]
    if invalid:
        raise ValueError(f"unsupported job type(s): {', '.join(invalid)}")
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    if profile_id not in state.get("profiles", {}):
        raise ValueError("profile_id is not registered")
    now = datetime.now(UTC)
    lease = {
        "lease_id": _required_id(lease_id, "lease_id"),
        "profile_id": profile_id,
        "project": project,
        "purpose": purpose,
        "requested_by": requested_by,
        "requested_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=ttl_minutes)).isoformat(),
        "priority": priority,
        "job_types": list(job_types),
        "status": "active",
        "job_ids": [],
    }
    state.setdefault("leases", {})[lease["lease_id"]] = lease
    _save_control_state(root, state)
    return {
        "lease": _lease_status(lease),
        "status": remote_testing_status(root),
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def enqueue_remote_test_job_status(
    project_root: str | Path,
    lease_id: str,
    job_type: str,
    requested_by: str = "quark",
    project: str = "Overseer",
    params: dict[str, object] | None = None,
    base_url: str = "http://127.0.0.1:8766",
    ui_path: str = "/Overseer/ui",
    gateway_path: str = "/Overseer",
    token_source: str = "state/api-token",
    auth_token_id: str | None = None,
    mutates: bool = False,
) -> dict[str, object]:
    if job_type not in SUPPORTED_JOB_TYPES:
        raise ValueError("unsupported job_type")
    _assert_redacted_safe(params or {})
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    lease = state.get("leases", {}).get(lease_id)
    if not lease:
        raise ValueError("lease_id is not active or registered")
    lease_view = _lease_status(lease)
    if lease_view["status"] != "active":
        raise ValueError("lease is not active")
    if job_type not in lease.get("job_types", []):
        raise ValueError("job_type is not allowed by lease")
    if mutates and not _fixture_allows_mutation(params or {}):
        raise ValueError("mutating remote test jobs require an explicit disposable fixture")
    if job_type in SCOPED_TOKEN_REQUIRED_JOB_TYPES and not auth_token_id:
        raise ValueError(f"{job_type} requires a Quark-issued auth_token_id")
    if auth_token_id:
        grant = state.get("test_tokens", {}).get(auth_token_id)
        if not grant or str(grant.get("status")) != "active":
            raise ValueError("auth_token_id is not active")
        if grant.get("lease_id") and grant.get("lease_id") != lease_id:
            raise ValueError("auth_token_id is not scoped to this lease")
        if str(grant.get("project")) != project:
            raise ValueError("auth_token_id is not scoped to this project")
        if not _path_matches_service_scope(gateway_path, grant.get("service_paths", [])):
            raise ValueError("auth_token_id is not scoped to this gateway path")
        if base_url not in set(grant.get("gateway_origins", [])) and "*" not in set(grant.get("gateway_origins", [])):
            raise ValueError("auth_token_id is not scoped to this gateway origin")
        if mutates and not grant.get("mutates", False):
            raise ValueError("auth_token_id does not authorize mutation")
        token_source = f"remote-testing-token:{auth_token_id}"
    queue_root = _queue_root(root)
    for subdir in ("pending", "claimed", "done", "failed"):
        (queue_root / "jobs" / subdir).mkdir(parents=True, exist_ok=True)
    created_at = datetime.now(UTC)
    short_id = _safe_id(f"{lease_id}-{job_type}")[:40]
    job_id = f"job-{created_at.strftime('%Y%m%dT%H%M%SZ')}-{_safe_id(job_type)}-{short_id}"
    job = {
        "schema": "overseer.remote-test-job.v1",
        "job_id": job_id,
        "job_type": job_type,
        "created_at": created_at.isoformat(),
        "requested_by": requested_by,
        "project": project,
        "base_url": base_url,
        "ui_path": ui_path,
        "gateway_path": gateway_path,
        "token_source": token_source,
        "auth_token_id": auth_token_id,
        "lease_id": lease_id,
        "mutates": bool(mutates),
        "redaction": {
            "return_raw_tokens": False,
            "return_raw_cookies": False,
            "return_browser_storage": False,
            "return_raw_response_bodies": False,
        },
        "params": params or {},
    }
    filename = f"{created_at.strftime('%Y%m%dT%H%M%SZ')}-{_safe_id(job_type)}-{short_id}.json"
    job_path = queue_root / "jobs" / "pending" / filename
    job_path.write_text(json.dumps(job, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lease.setdefault("job_ids", []).append(job_id)
    lease["last_job_id"] = job_id
    lease["updated_at"] = created_at.isoformat()
    state.setdefault("leases", {})[lease_id] = lease
    _save_control_state(root, state)
    return {
        "job": _redacted_job_summary(job, "pending"),
        "job_path": str(job_path),
        "lease": _lease_status(lease),
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def collect_remote_test_results_status(project_root: str | Path, lease_id: str | None = None, job_id: str | None = None) -> dict[str, object]:
    root = Path(project_root)
    status = remote_testing_status(root)
    results = status["recent_results"]
    if lease_id:
        lease = next((item for item in status["leases"] if item["lease_id"] == lease_id), None)
        allowed = set(lease.get("job_ids", [])) if lease else set()
        results = [item for item in results if item.get("job_id") in allowed]
    if job_id:
        results = [item for item in results if item.get("job_id") == job_id]
    return {
        "queue_root": status["queue_root"],
        "lease_id": lease_id,
        "job_id": job_id,
        "results": results,
        "result_count": len(results),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _queue_root(project_root: Path) -> Path:
    return project_root / DEFAULT_QUEUE_ROOT


def _control_path(project_root: Path) -> Path:
    return _queue_root(project_root) / CONTROL_FILENAME


def _load_control_state(project_root: Path) -> dict[str, Any]:
    path = _control_path(project_root)
    if not path.exists():
        return {"schema": "overseer.remote-testing-control.v1", "profiles": {}, "leases": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("remote testing control state must be a JSON object")
    data.setdefault("profiles", {})
    data.setdefault("leases", {})
    return data


def _save_control_state(project_root: Path, state: dict[str, Any]) -> None:
    path = _control_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_token_file(project_root: Path, token_id: str, raw_token: str) -> Path:
    token_dir = _queue_root(project_root) / "tokens"
    token_dir.mkdir(parents=True, exist_ok=True)
    token_path = token_dir / f"{_safe_id(token_id)}.token"
    token_path.write_text(raw_token + "\n", encoding="utf-8")
    os.chmod(token_path, 0o600)
    return token_path


def _hash_token(raw_token: str) -> str:
    return "sha256:" + hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _normalized_scope_list(values: tuple[str, ...] | list[str], allow_wildcard: bool = False) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if not item:
            continue
        if item == "*" and not allow_wildcard:
            raise ValueError("wildcard scope is not allowed here")
        if item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    if not normalized:
        raise ValueError("scope list cannot be empty")
    return normalized


def _normalized_service_paths(values: tuple[str, ...] | list[str], allow_wildcard: bool = False) -> list[str]:
    normalized = _normalized_scope_list(values, allow_wildcard=allow_wildcard)
    for path in normalized:
        if path == "*":
            continue
        if not path.startswith("/"):
            raise ValueError("service paths must start with /")
        if "//" in path:
            raise ValueError("service paths must not contain empty path segments")
    return normalized


def _normalized_routes(values: tuple[str, ...] | list[str]) -> list[str]:
    normalized = _normalized_scope_list(values, allow_wildcard=True)
    for path in normalized:
        if path == "*":
            continue
        if not path.startswith("/"):
            raise ValueError("routes must start with /")
    return normalized


def _redacted_account_status(account: dict[str, Any]) -> dict[str, object]:
    return {
        "account_id": account.get("account_id"),
        "display_name": account.get("display_name"),
        "owner": account.get("owner"),
        "security_owner": account.get("security_owner"),
        "agent_kind": account.get("agent_kind"),
        "agent_id": account.get("agent_id"),
        "enabled": bool(account.get("enabled", False)),
        "default_access": account.get("default_access"),
        "allowed_projects": account.get("allowed_projects", []),
        "allowed_service_paths": account.get("allowed_service_paths", []),
        "allowed_gateway_origins": account.get("allowed_gateway_origins", []),
        "gateway_principal": account.get("gateway_principal"),
        "mutation_policy": account.get("mutation_policy"),
        "monitoring": account.get("monitoring", {}),
        "recorded_by": account.get("recorded_by"),
        "recorded_at": account.get("recorded_at"),
        "updated_at": account.get("updated_at"),
    }


def _redacted_token_status(grant: dict[str, Any]) -> dict[str, object]:
    return {
        "token_id": grant.get("token_id"),
        "account_id": grant.get("account_id"),
        "lease_id": grant.get("lease_id"),
        "job_id": grant.get("job_id"),
        "project": grant.get("project"),
        "thread_id": grant.get("thread_id"),
        "service_paths": grant.get("service_paths", []),
        "gateway_origins": grant.get("gateway_origins", []),
        "allowed_methods": grant.get("allowed_methods", []),
        "allowed_routes": grant.get("allowed_routes", []),
        "mutates": bool(grant.get("mutates", False)),
        "mutation_scope": grant.get("mutation_scope", {}),
        "status": grant.get("status"),
        "issued_by": grant.get("issued_by"),
        "issued_at": grant.get("issued_at"),
        "expires_at": grant.get("expires_at"),
        "revoked_by": grant.get("revoked_by"),
        "revoked_at": grant.get("revoked_at"),
        "revoke_reason": grant.get("revoke_reason"),
        "token_source": grant.get("token_source"),
        "token_hash_prefix": str(grant.get("token_hash", ""))[:19],
    }


def _record_auth_event(
    state: dict[str, Any],
    account_id: str | None,
    token_id: str | None,
    event_type: str,
    actor: str,
    evidence: dict[str, object] | None = None,
) -> None:
    events = state.setdefault("test_auth_events", [])
    events.append(
        {
            "event_id": f"auth-event.{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}.{_safe_id(event_type)}",
            "event_type": event_type,
            "account_id": account_id,
            "token_id": token_id,
            "actor": actor,
            "occurred_at": _now(),
            "owner": "odo",
            "evidence": evidence or {},
            "raw_token_returned": False,
        }
    )
    del events[:-200]


def _auth_denied(
    state: dict[str, Any],
    account_id: str | None,
    token_id: str | None,
    reason: str,
    method: str,
    path: str,
) -> dict[str, object]:
    _record_auth_event(
        state,
        account_id,
        token_id,
        "token_denied",
        "api",
        {"reason": reason, "method": method, "path": _redacted_path(path)},
    )
    if account_id and reason in {
        "service_path_not_allowed",
        "route_not_allowed",
        "method_not_allowed",
        "mutation_not_allowed",
        "mutation_scope_not_allowed",
    }:
        account = state.get("test_accounts", {}).get(account_id)
        if account and account.get("monitoring", {}).get("auto_disable_on_scope_violation", False):
            account["enabled"] = False
            account["disabled_by"] = "odo"
            account["disabled_at"] = _now()
            account["disable_reason"] = reason
            state.setdefault("test_accounts", {})[account_id] = account
    return {"authorized": False, "auth_type": "remote_testing_token", "reason": reason}


def _path_matches_service_scope(raw_path: str, service_paths: list[str]) -> bool:
    if "*" in service_paths:
        return True
    for service_path in service_paths:
        if raw_path == service_path or raw_path.startswith(f"{service_path}/"):
            return True
    return False


def _route_allowed(normalized_path: str, allowed_routes: list[str]) -> bool:
    if "*" in allowed_routes:
        return True
    for route in allowed_routes:
        if route.endswith("/*") and normalized_path.startswith(route[:-1]):
            return True
        if ":" in route:
            pattern = re.sub(r":[A-Za-z][A-Za-z0-9_]*", r"[^/]+", re.escape(route).replace(r"\:", ":"))
            if re.fullmatch(pattern, normalized_path):
                return True
        if normalized_path == route:
            return True
    return False


def _mutation_scope_allowed(grant: dict[str, Any], method: str, raw_path: str, normalized_path: str) -> bool:
    scope = grant.get("mutation_scope") or {}
    if not isinstance(scope, dict):
        return False
    methods = _normalized_scope_list(scope.get("allowed_methods", scope.get("methods", [])), allow_wildcard=False)
    routes = _normalized_routes(scope.get("allowed_routes", scope.get("routes", [])))
    raw_service_paths = scope.get("service_paths", [])
    service_paths = _normalized_service_paths(raw_service_paths, allow_wildcard=False) if raw_service_paths else []
    if method.upper() not in set(methods):
        return False
    if routes and not _route_allowed(normalized_path, routes):
        return False
    if service_paths and not _path_matches_service_scope(raw_path, service_paths):
        return False
    return True


def _is_expired(expires_at: str) -> bool:
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    return expires <= datetime.now(UTC)


def _redacted_path(path: str) -> str:
    return path.split("?", maxsplit=1)[0]


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _with_default_profile(state: dict[str, Any], project_root: Path) -> dict[str, Any]:
    profiles = state.setdefault("profiles", {})
    if DEFAULT_PROFILE_ID not in profiles:
        profiles[DEFAULT_PROFILE_ID] = {
            "profile_id": DEFAULT_PROFILE_ID,
            "display_name": "Tank on MSI remote testing queue",
            "owner": "quark",
            "remote_operator": "Tank",
            "remote_host": DEFAULT_REMOTE_HOST,
            "remote_node": "MSI",
            "transport": "protected_gateway_or_vpn_reachable_ssh",
            "protected_gateway_required": True,
            "forbidden_transports": list(FORBIDDEN_TRANSPORTS),
            "worker_status_path": "%LOCALAPPDATA%/OverseerMsiTestAgent/status.json",
            "launcher": "Captures/overseer-msi-test-agent-start.ps1",
            "worker_hint": "overseer-msi-test-agent",
            "queue_root": DEFAULT_QUEUE_ROOT,
            "base_url": "http://127.0.0.1:8766",
            "ui_path": "/Overseer/ui",
            "gateway_path": "/Overseer",
            "token_source": "state/api-token",
            "supported_job_types": list(SUPPORTED_JOB_TYPES),
            "redaction": {
                "raw_tokens": False,
                "raw_cookies": False,
                "raw_browser_storage": False,
                "raw_response_bodies": False,
            },
            "recorded_by": "quark",
            "recorded_at": _now(),
        }
    state.setdefault("default_profile_id", DEFAULT_PROFILE_ID)
    return state


def _adapter_status(queue_root: Path, state: dict[str, Any]) -> dict[str, object]:
    latest = _recent_results(queue_root, limit=1)
    contract_exists = (queue_root / "QUEUE_CONTRACT.md").exists()
    pending_dir = queue_root / "jobs" / "pending"
    return {
        "status": "configured" if contract_exists and pending_dir.exists() else "needs_setup",
        "queue_exists": queue_root.exists(),
        "contract_exists": contract_exists,
        "default_profile_id": state.get("default_profile_id", DEFAULT_PROFILE_ID),
        "latest_result_job": latest[0].get("job_id") if latest else None,
        "latest_result_status": latest[0].get("status") if latest else None,
    }


def _queue_counts(queue_root: Path) -> dict[str, int]:
    return {
        name: _count_json_files(queue_root / "jobs" / name)
        for name in ("pending", "claimed", "done", "failed")
    }


def _count_json_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.glob("*.json") if item.is_file())


def _job_summaries(path: Path, status: str, limit: int) -> list[dict[str, object]]:
    if not path.exists():
        return []
    rows = []
    for item in sorted(path.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
        rows.append(_redacted_file_summary(item, status))
    return rows


def _recent_results(queue_root: Path, limit: int) -> list[dict[str, object]]:
    files: list[tuple[float, str, Path]] = []
    for status in ("done", "failed"):
        folder = queue_root / "jobs" / status
        if not folder.exists():
            continue
        files.extend((item.stat().st_mtime, status, item) for item in folder.glob("*.json") if item.is_file())
    return [_redacted_file_summary(item, status) for _, status, item in sorted(files, reverse=True)[:limit]]


def _redacted_file_summary(path: Path, queue_status: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"file": path.name, "queue_status": queue_status, "status": "unreadable"}
    if not isinstance(payload, dict):
        return {"file": path.name, "queue_status": queue_status, "status": "invalid"}
    return _redacted_job_summary(payload, queue_status) | {"file": path.name}


def _redacted_job_summary(payload: dict[str, Any], queue_status: str) -> dict[str, object]:
    return {
        "job_id": payload.get("job_id"),
        "job_type": payload.get("job_type"),
        "queue_status": queue_status,
        "status": payload.get("status") or queue_status,
        "stage": payload.get("stage") or payload.get("validation_stage"),
        "project": payload.get("project"),
        "requested_by": payload.get("requested_by"),
        "lease_id": payload.get("lease_id"),
        "auth_token_id": payload.get("auth_token_id"),
        "token_source": payload.get("token_source"),
        "mutates": bool(payload.get("mutates", False)),
        "worker": payload.get("worker") or payload.get("worker_name"),
        "observed_request_count": payload.get("observed_request_count"),
        "console_error_count": payload.get("console_error_count"),
        "findings": payload.get("findings", []),
    }


def _lease_status(lease: dict[str, Any]) -> dict[str, object]:
    expires_at = str(lease.get("expires_at", ""))
    status = str(lease.get("status", "active"))
    try:
        expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        expires = None
    if expires is not None and expires <= datetime.now(UTC):
        status = "expired"
    return {
        "lease_id": lease.get("lease_id"),
        "profile_id": lease.get("profile_id"),
        "project": lease.get("project"),
        "purpose": lease.get("purpose"),
        "requested_by": lease.get("requested_by"),
        "requested_at": lease.get("requested_at"),
        "expires_at": expires_at,
        "priority": lease.get("priority"),
        "job_types": lease.get("job_types", []),
        "job_ids": lease.get("job_ids", []),
        "last_job_id": lease.get("last_job_id"),
        "status": status,
    }


def _fixture_allows_mutation(params: dict[str, object]) -> bool:
    if params.get("fixture_id") or params.get("disposable_fixture"):
        return True
    return (
        params.get("allow_mutation") is True
        and params.get("require_explicit_user_approval") is True
    )


def _assert_redacted_safe(value: object, path: str = "params") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered != "mutation_authorization" and any(part in lowered for part in SENSITIVE_KEY_PARTS):
                raise ValueError(f"{path}.{key} may contain secret material and cannot be queued")
            _assert_redacted_safe(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _assert_redacted_safe(item, f"{path}[{index}]")
        return
    if isinstance(value, str) and re.search(r"\bBearer\s+\S+|sk-[A-Za-z0-9_-]+", value):
        raise ValueError(f"{path} appears to contain secret material and cannot be queued")


def _required_id(value: str, field: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{field} is required")
    return value


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-").lower()
    return cleaned or "remote-test"


def _now() -> str:
    return datetime.now(UTC).isoformat()
