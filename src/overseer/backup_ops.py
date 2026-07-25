"""Staged backup, restore-test, and cleanup records for Kira."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path


def backup_operations_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    return {
        "root": str(root),
        "jobs": data["jobs"],
        "job_count": len(data["jobs"]),
        "restore_tests": data["restore_tests"],
        "restore_test_count": len(data["restore_tests"]),
        "cleanup_requests": data["cleanup_requests"],
        "cleanup_request_count": len(data["cleanup_requests"]),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def record_backup_job_status(
    project_root: str | Path,
    job_id: str,
    target: str,
    schedule: str = "manual",
    retention: str = "operator-defined",
    requested_by: str = "kira",
    risk_level: str = "medium",
    status: str = "staged",
    notes: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": _safe_id(job_id),
        "target": _redact_path(target),
        "schedule": schedule,
        "retention": retention,
        "requested_by": requested_by,
        "risk_level": risk_level,
        "status": status,
        "notes": notes,
        "updated_at": now,
        "next_step": "stage backup execution plan with validation and rollback before live file operations",
    }
    existing = next((index for index, item in enumerate(data["jobs"]) if item["id"] == row["id"]), None)
    if existing is None:
        row["created_at"] = now
        data["jobs"].append(row)
    else:
        row["created_at"] = data["jobs"][existing].get("created_at") or now
        data["jobs"][existing] = row
    _write_registry(root, data)
    return {"job": row, "mutation_performed": True, "host_mutation_performed": False}


def record_restore_test_status(
    project_root: str | Path,
    test_id: str,
    job_id: str,
    restore_point: str,
    status: str = "planned",
    validated_by: str = "kira",
    notes: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": _safe_id(test_id),
        "job_id": _safe_id(job_id),
        "restore_point": _redact_path(restore_point),
        "status": status,
        "validated_by": validated_by,
        "notes": notes,
        "updated_at": now,
        "next_step": "perform restore verification only in an approved isolated target",
    }
    existing = next((index for index, item in enumerate(data["restore_tests"]) if item["id"] == row["id"]), None)
    if existing is None:
        row["created_at"] = now
        data["restore_tests"].append(row)
    else:
        row["created_at"] = data["restore_tests"][existing].get("created_at") or now
        data["restore_tests"][existing] = row
    _write_registry(root, data)
    return {"restore_test": row, "mutation_performed": True, "host_mutation_performed": False}


def stage_backup_cleanup_request_status(
    project_root: str | Path,
    path: str,
    requested_by: str = "kira",
    reason: str = "review generated storage cleanup candidate",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    request_id = f"backup-cleanup.{_safe_id(path)}"
    row = {
        "id": request_id,
        "path": _redact_path(path),
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "next_step": "human approval required before deleting backup, restore, or generated storage files",
    }
    existing = next((index for index, item in enumerate(data["cleanup_requests"]) if item["id"] == row["id"]), None)
    if existing is None:
        data["cleanup_requests"].append(row)
    else:
        row["created_at"] = data["cleanup_requests"][existing].get("created_at") or now
        data["cleanup_requests"][existing] = row
    _write_registry(root, data)
    return {"cleanup_request": row, "mutation_performed": True, "host_mutation_performed": False}


def _registry_path(root: Path) -> Path:
    return root / "state" / "backup-operations.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    if not path.exists():
        return {"jobs": [], "restore_tests": [], "cleanup_requests": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"jobs": [], "restore_tests": [], "cleanup_requests": []}
    return {
        "jobs": list(data.get("jobs") or []),
        "restore_tests": list(data.get("restore_tests") or []),
        "cleanup_requests": list(data.get("cleanup_requests") or []),
    }


def _write_registry(root: Path, data: dict[str, object]) -> None:
    path = _registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip()).strip("-")
    return cleaned or "item"


def _redact_path(value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if str(value).startswith("/"):
        return f".../{path.name}" if path.name else "local-path"
    return str(value)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
