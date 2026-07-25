"""Staged virtual runtime, snapshot, and restore records for Dax."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path


def virtual_operations_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    return {
        "root": str(root),
        "runtime_records": data["runtime_records"],
        "runtime_record_count": len(data["runtime_records"]),
        "snapshot_requests": data["snapshot_requests"],
        "snapshot_request_count": len(data["snapshot_requests"]),
        "restore_requests": data["restore_requests"],
        "restore_request_count": len(data["restore_requests"]),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def record_virtual_runtime_status(
    project_root: str | Path,
    resource_id: str,
    kind: str = "vm",
    state: str = "observed",
    adapter: str = "manual",
    ports: tuple[int, ...] | list[int] | None = None,
    snapshot_hint: str = "",
    notes: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "resource_id": _safe_id(resource_id),
        "kind": kind,
        "state": state,
        "adapter": adapter,
        "ports": sorted(int(port) for port in (ports or ())),
        "snapshot_hint": _redact_path(snapshot_hint),
        "notes": notes,
        "updated_at": now,
        "next_step": "request checkout or stage snapshot/restore plan before mutating this virtual asset",
    }
    existing = next((index for index, item in enumerate(data["runtime_records"]) if item["resource_id"] == row["resource_id"]), None)
    if existing is None:
        row["created_at"] = now
        data["runtime_records"].append(row)
    else:
        row["created_at"] = data["runtime_records"][existing].get("created_at") or now
        data["runtime_records"][existing] = row
    _write_registry(root, data)
    return {"runtime_record": row, "mutation_performed": True, "host_mutation_performed": False}


def stage_virtual_snapshot_request_status(
    project_root: str | Path,
    resource_id: str,
    requested_by: str = "dax",
    reason: str = "stage virtual snapshot before maintenance",
    snapshot_name: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": f"virtual-snapshot.{_safe_id(resource_id)}",
        "resource_id": _safe_id(resource_id),
        "snapshot_name": _safe_id(snapshot_name) if snapshot_name else "",
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "guardrails": [
            "verify checkout claim before touching runtime state",
            "capture rollback target before destructive maintenance",
            "do not start, stop, pause, snapshot, restore, or delete without an approved live adapter plan",
        ],
        "next_step": "human approval required before invoking VM, container, emulator, gateway, or proxy snapshot adapters",
    }
    _upsert(data["snapshot_requests"], row)
    _write_registry(root, data)
    return {"snapshot_request": row, "mutation_performed": True, "host_mutation_performed": False}


def stage_virtual_restore_request_status(
    project_root: str | Path,
    resource_id: str,
    restore_point: str,
    requested_by: str = "dax",
    reason: str = "stage virtual restore after failed change",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": f"virtual-restore.{_safe_id(resource_id)}",
        "resource_id": _safe_id(resource_id),
        "restore_point": _redact_path(restore_point),
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "guardrails": [
            "confirm active users and claims before restore",
            "preserve failed-state evidence before rollback",
            "do not start, stop, pause, snapshot, restore, or delete without an approved live adapter plan",
        ],
        "next_step": "human approval required before invoking VM, container, emulator, gateway, or proxy restore adapters",
    }
    _upsert(data["restore_requests"], row)
    _write_registry(root, data)
    return {"restore_request": row, "mutation_performed": True, "host_mutation_performed": False}


def _registry_path(root: Path) -> Path:
    return root / "state" / "virtual-operations.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    if not path.exists():
        return {"runtime_records": [], "snapshot_requests": [], "restore_requests": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"runtime_records": [], "snapshot_requests": [], "restore_requests": []}
    return {
        "runtime_records": list(data.get("runtime_records") or []),
        "snapshot_requests": list(data.get("snapshot_requests") or []),
        "restore_requests": list(data.get("restore_requests") or []),
    }


def _write_registry(root: Path, data: dict[str, object]) -> None:
    path = _registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _upsert(rows: list[dict[str, object]], row: dict[str, object]) -> None:
    existing = next((index for index, item in enumerate(rows) if item["id"] == row["id"]), None)
    if existing is None:
        rows.append(row)
        return
    row["created_at"] = rows[existing].get("created_at") or row["created_at"]
    rows[existing] = row


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
