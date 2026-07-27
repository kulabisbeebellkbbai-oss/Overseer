"""Staged identity, SSH key, and secret rotation requests for Odo."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path


def identity_rotation_requests_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    return {
        "root": str(root),
        "requests": data["requests"],
        "executions": data["executions"],
        "request_count": len(data["requests"]),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def identity_rotation_execution_readiness_status(project_root: str | Path, request_id: str | None = None) -> dict[str, object]:
    root = Path(project_root)
    requests = _read_registry(root)["requests"]
    if request_id:
        requests = [request for request in requests if request.get("id") == request_id]
    items = [_readiness_row(request) for request in requests]
    return {
        "root": str(root),
        "items": items,
        "request_count": len(items),
        "ready_count": sum(1 for item in items if item["readiness_state"] == "ready_for_manual_runbook"),
        "mutation_performed": False,
        "host_mutation_performed": False,
        "next_step": "approve a request and attach an explicit provider runbook before live credential or account mutation",
    }


def stage_identity_rotation_request_status(
    project_root: str | Path,
    subject: str,
    subject_type: str = "secret",
    requested_by: str = "odo",
    reason: str = "stage identity or secret rotation review",
    urgency: str = "medium",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    request_id = f"identity-rotation.{_safe_id(subject_type)}.{_safe_id(subject)}"
    row = {
        "id": request_id,
        "subject": _redact_subject(subject),
        "subject_type": subject_type,
        "requested_by": requested_by,
        "reason": reason,
        "urgency": urgency,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "guardrails": [
            "do not disclose, copy, print, or commit secret material",
            "verify dependent services and rollback before credential changes",
            "do not change users, groups, SSH keys, API keys, service accounts, or token files without explicit approval",
        ],
        "next_step": "human approval required before rotating credentials or changing account access",
    }
    _upsert(data["requests"], row)
    _write_registry(root, data)
    return {"request": row, "mutation_performed": True, "host_mutation_performed": False}


def approve_identity_rotation_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "sisko",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, request_id)
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"identity rotation request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "approval_required": False,
            "next_step": "execute approved identity rotation through local fixture or attach an approved live provider runbook",
        }
    )
    _write_registry(root, data)
    return {"request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_identity_rotation_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "odo",
    mode: str = "local_fixture",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, request_id)
    now = executed_at or _now()
    if row.get("status") != "approved":
        return _record_execution(root, data, row, request_id, executed_by, mode, now, "blocked", "request is not approved")
    if mode != "local_fixture":
        return _record_execution(root, data, row, request_id, executed_by, mode, now, "blocked", "live identity rotation provider is not enabled")
    manifest = _write_execution_manifest(root, row, executed_by, mode, now)
    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "execution_mode": mode,
            "manifest_path": manifest["manifest_path"],
            "next_step": "fixture execution complete; use manifest as approval-path evidence before adding a live provider",
        }
    )
    execution = _execution_record(row, request_id, executed_by, mode, now, "completed", "", manifest["manifest_path"])
    _upsert(data["executions"], execution)
    _write_registry(root, data)
    return {
        "request": row,
        "execution": execution,
        "manifest": manifest,
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def _readiness_row(request: dict[str, object]) -> dict[str, object]:
    status = str(request.get("status") or "waiting_approval")
    approved = status in {"approved", "ready", "ready_for_execution"} or request.get("approval_required") is False
    blockers = []
    readiness_state = "completed" if status == "completed" else "waiting_approval"
    if not approved:
        blockers.append("Sisko approval required before rotation or account change")
    if request.get("subject_type") in {"secret", "api_key", "service_account", "ssh_key", "user", "group"}:
        blockers.append("live provider adapter is not enabled for this subject type")
    if approved and status != "completed":
        readiness_state = "ready_for_manual_runbook"
    return {
        "request_id": request.get("id") or "unknown",
        "subject_type": request.get("subject_type") or "secret",
        "subject": request.get("subject") or "unspecified",
        "status": status,
        "readiness_state": readiness_state,
        "approval_required": not approved,
        "can_execute": False,
        "execution_modes": ["manual_runbook", "local_fixture"],
        "live_execution_available": False,
        "blockers": blockers,
        "safeguards": [
            "do not disclose, copy, print, or commit secret material",
            "capture dependency impact and rollback plan before any credential change",
            "disable or scope replacement credentials before retiring the old credential",
            "route suspicious custody findings to Odo before execution",
        ],
        "next_step": _readiness_next_step(status, approved),
    }


def _readiness_next_step(status: str, approved: bool) -> str:
    if status == "completed":
        return "fixture execution complete; review manifest before adding a live provider"
    if not approved:
        return "Sisko approval required"
    return "attach provider runbook or execute the local fixture path"


def _registry_path(root: Path) -> Path:
    return root / "state" / "identity-rotation-requests.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    if not path.exists():
        return {"requests": [], "executions": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"requests": [], "executions": []}
    return {"requests": list(data.get("requests") or []), "executions": list(data.get("executions") or [])}


def _write_registry(root: Path, data: dict[str, object]) -> None:
    path = _registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _upsert(rows: list[dict[str, object]], row: dict[str, object]) -> None:
    existing = next((index for index, item in enumerate(rows) if item["id"] == row["id"]), None)
    if existing is None:
        rows.append(row)
        return
    if "created_at" in rows[existing] or "created_at" in row:
        row["created_at"] = rows[existing].get("created_at") or row.get("created_at")
    rows[existing] = row


def _find_request(data: dict[str, list[dict[str, object]]], request_id: str) -> dict[str, object]:
    for row in data["requests"]:
        if row.get("id") == request_id:
            return row
    raise ValueError(f"identity rotation request not found: {request_id}")


def _write_execution_manifest(root: Path, row: dict[str, object], executed_by: str, mode: str, executed_at: str) -> dict[str, object]:
    manifest = {
        "request_id": row.get("id"),
        "subject": row.get("subject"),
        "subject_type": row.get("subject_type"),
        "executed_by": executed_by,
        "executed_at": executed_at,
        "mode": mode,
        "credential_material": "[not-read]",
        "host_mutation_performed": False,
        "validation": [
            "request approved",
            "fixture execution only",
            "no credential material read or written",
        ],
    }
    path = root / "state" / "identity-rotation-manifests" / f"{_safe_id(str(row.get('id') or 'request'))}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {**manifest, "manifest_path": _relative_or_name(root, path)}


def _record_execution(
    root: Path,
    data: dict[str, list[dict[str, object]]],
    row: dict[str, object],
    request_id: str,
    executed_by: str,
    mode: str,
    executed_at: str,
    status: str,
    error: str,
) -> dict[str, object]:
    execution = _execution_record(row, request_id, executed_by, mode, executed_at, status, error, "")
    _upsert(data["executions"], execution)
    if status == "blocked":
        row.update({"status": "approved" if row.get("status") == "approved" else row.get("status"), "updated_at": executed_at, "next_step": error})
    _write_registry(root, data)
    return {"request": row, "execution": execution, "mutation_performed": True, "host_mutation_performed": False}


def _execution_record(
    row: dict[str, object],
    request_id: str,
    executed_by: str,
    mode: str,
    executed_at: str,
    status: str,
    error: str,
    manifest_path: str,
) -> dict[str, object]:
    return {
        "id": f"identity-rotation-execution.{_safe_id(request_id)}",
        "request_id": request_id,
        "subject": row.get("subject") or "unspecified",
        "subject_type": row.get("subject_type") or "secret",
        "status": status,
        "mode": mode,
        "executed_by": executed_by,
        "executed_at": executed_at,
        "manifest_path": manifest_path,
        "error": error,
    }


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip()).strip("-")
    return cleaned or "item"


def _redact_subject(value: str) -> str:
    text = str(value).strip()
    if not text:
        return "unspecified"
    if "/" in text:
        path = Path(text)
        if text.startswith("/"):
            return f".../{path.name}" if path.name else "local-path"
    if len(text) > 80:
        return f"{text[:77]}..."
    return text


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
