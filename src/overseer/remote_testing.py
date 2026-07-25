"""Quark-managed remote testing queue profiles, leases, and controls."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_PROFILE_ID = "remote-testing.tank-msi"
DEFAULT_QUEUE_ROOT = "local-secrets/remote-testing"
CONTROL_FILENAME = "quark-control.json"
SUPPORTED_JOB_TYPES = (
    "ping",
    "overseer.http_status",
    "overseer.auth_panel_smoke",
    "overseer.admin_approve_smoke",
    "overseer.full_ui_regression",
    "overseer.performance_regression",
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
        "default_profile_id": state.get("default_profile_id", DEFAULT_PROFILE_ID),
        "adapter_status": _adapter_status(queue_root, state),
        "lease_profile": {
            "owner": "quark",
            "manager": "Tank on MSI",
            "default_ttl_minutes": 120,
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
        ],
        "mutation_performed": False,
        "host_mutation_performed": False,
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
) -> dict[str, object]:
    root = Path(project_root)
    state = _with_default_profile(_load_control_state(root), root)
    profile = {
        "profile_id": _required_id(profile_id, "profile_id"),
        "display_name": display_name,
        "owner": "quark",
        "remote_operator": "Tank",
        "remote_host": "MSI",
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


def _with_default_profile(state: dict[str, Any], project_root: Path) -> dict[str, Any]:
    profiles = state.setdefault("profiles", {})
    if DEFAULT_PROFILE_ID not in profiles:
        profiles[DEFAULT_PROFILE_ID] = {
            "profile_id": DEFAULT_PROFILE_ID,
            "display_name": "Tank on MSI remote testing queue",
            "owner": "quark",
            "remote_operator": "Tank",
            "remote_host": "MSI",
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
    return bool(params.get("fixture_id") or params.get("disposable_fixture"))


def _assert_redacted_safe(value: object, path: str = "params") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
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
