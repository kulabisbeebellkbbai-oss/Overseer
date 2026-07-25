"""Staged backup, restore-test, and cleanup records for Kira."""

from __future__ import annotations

import json
import re
import shutil
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


def approve_backup_cleanup_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "kira",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_cleanup_request(data, request_id)
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"cleanup request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved backup cleanup after final path and manifest validation",
        }
    )
    _write_registry(root, data)
    return {"cleanup_request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_backup_cleanup_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "kira",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_cleanup_request(data, request_id)
    now = executed_at or _now()
    try:
        _validate_cleanup_request_ready(row)
        target = _cleanup_target(root, str(row.get("path") or ""))
        manifest = _cleanup_manifest(root, target, request_id, now)
        _delete_cleanup_target(target)
    except ValueError as error:
        row.update(
            {
                "status": "blocked",
                "executed_by": executed_by,
                "executed_at": now,
                "updated_at": now,
                "execution_error": str(error),
                "next_step": "review blocked cleanup request and stage a corrected project-relative cleanup path",
            }
        )
        _write_registry(root, data)
        return {
            "cleanup_request": row,
            "status": "blocked",
            "summary": str(error),
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    except OSError as error:
        row.update(
            {
                "status": "failed",
                "executed_by": executed_by,
                "executed_at": now,
                "updated_at": now,
                "execution_error": str(error),
                "next_step": "inspect partial cleanup state and retry only after Kira verifies storage safety",
            }
        )
        _write_registry(root, data)
        return {
            "cleanup_request": row,
            "status": "failed",
            "summary": str(error),
            "mutation_performed": True,
            "host_mutation_performed": True,
        }

    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "manifest_path": manifest["manifest_path"],
            "deleted_entries": manifest["entry_count"],
            "deleted_bytes": manifest["total_bytes"],
            "next_step": "cleanup completed; continue monitoring backup and restore evidence",
        }
    )
    _write_registry(root, data)
    return {
        "cleanup_request": row,
        "status": "completed",
        "manifest": manifest,
        "mutation_performed": True,
        "host_mutation_performed": True,
    }


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


def _find_cleanup_request(data: dict[str, list[dict[str, object]]], request_id: str) -> dict[str, object]:
    cleaned = _safe_id(request_id.removeprefix("backup-cleanup."))
    candidates = {request_id, f"backup-cleanup.{cleaned}"}
    for row in data["cleanup_requests"]:
        if row.get("id") in candidates:
            return row
    raise ValueError(f"backup cleanup request does not exist: {request_id}")


def _validate_cleanup_request_ready(row: dict[str, object]) -> None:
    if row.get("status") != "approved":
        raise ValueError("backup cleanup request must be approved before execution")
    if not row.get("approved_by"):
        raise ValueError("backup cleanup request approval metadata is missing")


def _cleanup_target(root: Path, raw_path: str) -> Path:
    if not raw_path.strip():
        raise ValueError("cleanup path is required")
    candidate = Path(raw_path)
    if candidate.is_absolute() or "~" in candidate.parts or ".." in candidate.parts:
        raise ValueError("cleanup path must be project-relative and cannot include parent traversal")
    if candidate.parts[0] not in {"artifacts", "backups"}:
        raise ValueError("cleanup execution is limited to project artifacts/ and backups/ paths")
    target = (root / candidate).resolve()
    root_resolved = root.resolve()
    if target == root_resolved or root_resolved not in target.parents:
        raise ValueError("cleanup target must stay inside the project root")
    if not target.exists():
        raise ValueError("cleanup target does not exist")
    return target


def _cleanup_manifest(root: Path, target: Path, request_id: str, created_at: str) -> dict[str, object]:
    entries = []
    total_bytes = 0
    paths = [target, *sorted(target.rglob("*"))] if target.is_dir() else [target]
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        size = 0 if path.is_dir() else stat.st_size
        total_bytes += size
        entries.append(
            {
                "path": _relative_or_name(root, path),
                "kind": "directory" if path.is_dir() else "file",
                "bytes": size,
            }
        )
    manifest = {
        "request_id": request_id,
        "created_at": created_at,
        "target": _relative_or_name(root, target),
        "entry_count": len(entries),
        "total_bytes": total_bytes,
        "entries": entries,
    }
    manifest_dir = root / "local-secrets" / "backup-cleanup-manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{_safe_id(request_id)}-{_safe_id(created_at)}.json"
    manifest["manifest_path"] = _relative_or_name(root, manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _delete_cleanup_target(target: Path) -> None:
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()


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


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
