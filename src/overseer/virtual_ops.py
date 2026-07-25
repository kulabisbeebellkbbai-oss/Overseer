"""Staged virtual runtime, snapshot, and restore records for Dax."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
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
        "execution_records": data["execution_records"],
        "execution_record_count": len(data["execution_records"]),
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


def approve_virtual_snapshot_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "sisko",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "snapshot_requests", request_id, "virtual-snapshot")
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"snapshot request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved virtual snapshot after checkout, provider, and target validation",
        }
    )
    _write_registry(root, data)
    return {"snapshot_request": row, "mutation_performed": True, "host_mutation_performed": False}


def approve_virtual_restore_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "sisko",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "restore_requests", request_id, "virtual-restore")
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"restore request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved virtual restore after checkout, evidence-preservation, provider, and target validation",
        }
    )
    _write_registry(root, data)
    return {"restore_request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_virtual_snapshot_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "dax",
    provider: str = "local_fixture",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "snapshot_requests", request_id, "virtual-snapshot")
    now = executed_at or _now()
    try:
        _validate_request_ready(row, "snapshot")
        runtime = _find_runtime_record(data, str(row.get("resource_id") or ""))
        manifest = _execute_snapshot(root, row, runtime, provider, now)
    except ValueError as error:
        return _record_blocked_execution(root, data, row, "snapshot", request_id, executed_by, now, str(error))
    except OSError as error:
        return _record_failed_execution(root, data, row, "snapshot", request_id, executed_by, now, str(error))
    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "manifest_path": manifest["manifest_path"],
            "next_step": "snapshot completed; use this restore point for rollback if later runtime work fails",
        }
    )
    _append_execution(data, row, "snapshot", request_id, executed_by, now, "completed", provider, manifest=manifest)
    _write_registry(root, data)
    return {
        "snapshot_request": row,
        "status": "completed",
        "manifest": manifest,
        "mutation_performed": True,
        "host_mutation_performed": provider != "local_fixture",
    }


def execute_virtual_restore_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "dax",
    provider: str = "local_fixture",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "restore_requests", request_id, "virtual-restore")
    now = executed_at or _now()
    try:
        _validate_request_ready(row, "restore")
        runtime = _find_runtime_record(data, str(row.get("resource_id") or ""))
        manifest = _execute_restore(root, row, runtime, provider, now)
    except ValueError as error:
        return _record_blocked_execution(root, data, row, "restore", request_id, executed_by, now, str(error))
    except OSError as error:
        return _record_failed_execution(root, data, row, "restore", request_id, executed_by, now, str(error))
    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "manifest_path": manifest["manifest_path"],
            "next_step": "restore completed; run Julian health validation before returning the runtime to service",
        }
    )
    _append_execution(data, row, "restore", request_id, executed_by, now, "completed", provider, manifest=manifest)
    _write_registry(root, data)
    return {
        "restore_request": row,
        "status": "completed",
        "manifest": manifest,
        "mutation_performed": True,
        "host_mutation_performed": provider != "local_fixture",
    }


def _registry_path(root: Path) -> Path:
    return root / "state" / "virtual-operations.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    if not path.exists():
        return {"runtime_records": [], "snapshot_requests": [], "restore_requests": [], "execution_records": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"runtime_records": [], "snapshot_requests": [], "restore_requests": [], "execution_records": []}
    return {
        "runtime_records": list(data.get("runtime_records") or []),
        "snapshot_requests": list(data.get("snapshot_requests") or []),
        "restore_requests": list(data.get("restore_requests") or []),
        "execution_records": list(data.get("execution_records") or []),
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


def _find_request(data: dict[str, list[dict[str, object]]], key: str, request_id: str, prefix: str) -> dict[str, object]:
    cleaned = _safe_id(request_id.removeprefix(f"{prefix}."))
    candidates = {request_id, f"{prefix}.{cleaned}"}
    for row in data[key]:
        if row.get("id") in candidates:
            return row
    raise ValueError(f"{prefix} request does not exist: {request_id}")


def _find_runtime_record(data: dict[str, list[dict[str, object]]], resource_id: str) -> dict[str, object]:
    cleaned = _safe_id(resource_id)
    for row in data["runtime_records"]:
        if row.get("resource_id") == cleaned:
            return row
    raise ValueError(f"virtual runtime record does not exist: {cleaned}")


def _validate_request_ready(row: dict[str, object], action: str) -> None:
    if row.get("status") != "approved":
        raise ValueError(f"virtual {action} request must be approved before execution")
    if not row.get("approved_by"):
        raise ValueError(f"virtual {action} request approval metadata is missing")


def _execute_snapshot(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    if provider == "qemu_img":
        return _execute_qemu_snapshot(root, row, runtime, executed_at)
    if provider != "local_fixture":
        raise ValueError(f"virtual provider is not implemented for live execution: {provider}")
    target = _fixture_target(root, runtime)
    snapshot_name = _safe_id(str(row.get("snapshot_name") or row.get("id") or "snapshot"))
    snapshot_dir = root / "local-secrets" / "virtual-runtime-snapshots" / _safe_id(str(row["resource_id"])) / snapshot_name
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.parent.mkdir(parents=True, exist_ok=True)
    if target.is_dir():
        shutil.copytree(target, snapshot_dir)
    else:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, snapshot_dir / target.name)
    return _write_manifest(root, row, "snapshot", provider, target, snapshot_dir, executed_at)


def _execute_restore(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    if provider == "qemu_img":
        return _execute_qemu_restore(root, row, runtime, executed_at)
    if provider != "local_fixture":
        raise ValueError(f"virtual provider is not implemented for live execution: {provider}")
    target = _fixture_target(root, runtime)
    restore_point = _fixture_restore_point(root, str(row.get("resource_id") or ""), str(row.get("restore_point") or ""))
    preserved = root / "local-secrets" / "virtual-runtime-preserved" / _safe_id(str(row["resource_id"])) / _safe_id(executed_at)
    if target.exists():
        preserved.parent.mkdir(parents=True, exist_ok=True)
        if target.is_dir():
            shutil.copytree(target, preserved)
            shutil.rmtree(target)
        else:
            preserved.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, preserved / target.name)
            target.unlink()
    if restore_point.is_dir():
        shutil.copytree(restore_point, target)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(restore_point, target)
    return _write_manifest(root, row, "restore", provider, restore_point, target, executed_at, preserved=preserved)


def _fixture_target(root: Path, runtime: dict[str, object]) -> Path:
    if runtime.get("adapter") != "local_fixture":
        raise ValueError("local_fixture execution requires a runtime record with adapter=local_fixture")
    hint = str(runtime.get("snapshot_hint") or "")
    if not hint.strip():
        raise ValueError("local_fixture execution requires a project-relative snapshot_hint target")
    target = _project_relative_path(root, hint)
    allowed = (root / "local-secrets" / "virtual-runtime-targets").resolve()
    if target != allowed and allowed not in target.parents:
        raise ValueError("local_fixture target must stay under local-secrets/virtual-runtime-targets")
    if not target.exists():
        raise ValueError("local_fixture target does not exist")
    return target


def _fixture_restore_point(root: Path, resource_id: str, restore_point: str) -> Path:
    if not restore_point.strip():
        raise ValueError("restore_point is required")
    candidate = _project_relative_path(root, restore_point)
    snapshots_root = (root / "local-secrets" / "virtual-runtime-snapshots" / _safe_id(resource_id)).resolve()
    if not candidate.exists():
        candidate = snapshots_root / _safe_id(restore_point)
    candidate = candidate.resolve()
    if candidate != snapshots_root and snapshots_root not in candidate.parents:
        raise ValueError("local_fixture restore point must stay under local-secrets/virtual-runtime-snapshots")
    if not candidate.exists():
        raise ValueError("local_fixture restore point does not exist")
    return candidate


def _execute_qemu_snapshot(root: Path, row: dict[str, object], runtime: dict[str, object], executed_at: str) -> dict[str, object]:
    target = _qemu_image_target(root, runtime)
    snapshot_name = _safe_id(str(row.get("snapshot_name") or row.get("id") or "snapshot"))
    before = _qemu_image_info(target)
    _run_qemu_img(("snapshot", "-c", snapshot_name, str(target)))
    after = _qemu_image_info(target)
    return _write_manifest(
        root,
        row,
        "snapshot",
        "qemu_img",
        target,
        target,
        executed_at,
        provider_metadata={"snapshot_name": snapshot_name, "before": before, "after": after},
    )


def _execute_qemu_restore(root: Path, row: dict[str, object], runtime: dict[str, object], executed_at: str) -> dict[str, object]:
    target = _qemu_image_target(root, runtime)
    restore_point = _safe_id(str(row.get("restore_point") or ""))
    if not restore_point:
        raise ValueError("restore_point is required")
    preserved = _preserve_qemu_image(root, target, str(row["resource_id"]), executed_at)
    before = _qemu_image_info(target)
    _run_qemu_img(("snapshot", "-a", restore_point, str(target)))
    after = _qemu_image_info(target)
    return _write_manifest(
        root,
        row,
        "restore",
        "qemu_img",
        target,
        target,
        executed_at,
        preserved=preserved,
        provider_metadata={"restore_point": restore_point, "before": before, "after": after},
    )


def _qemu_image_target(root: Path, runtime: dict[str, object]) -> Path:
    if runtime.get("adapter") != "qemu_img":
        raise ValueError("qemu_img execution requires a runtime record with adapter=qemu_img")
    if shutil.which("qemu-img") is None:
        raise ValueError("qemu-img is not available")
    hint = str(runtime.get("snapshot_hint") or "")
    if not hint.strip():
        raise ValueError("qemu_img execution requires a project-relative snapshot_hint qcow2 image")
    target = _project_relative_path(root, hint)
    allowed = (root / "local-secrets" / "virtual-runtime-targets").resolve()
    if target != allowed and allowed not in target.parents:
        raise ValueError("qemu_img target must stay under local-secrets/virtual-runtime-targets")
    if target.suffix != ".qcow2":
        raise ValueError("qemu_img target must be a .qcow2 image")
    if not target.exists():
        raise ValueError("qemu_img target does not exist")
    info = _qemu_image_info(target)
    if info.get("format") != "qcow2":
        raise ValueError("qemu_img target must report qcow2 format")
    return target


def _preserve_qemu_image(root: Path, target: Path, resource_id: str, executed_at: str) -> Path:
    preserved = root / "local-secrets" / "virtual-runtime-preserved" / _safe_id(resource_id) / f"{_safe_id(executed_at)}.qcow2"
    preserved.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, preserved)
    return preserved


def _qemu_image_info(target: Path) -> dict[str, object]:
    output = _run_qemu_img(("info", "--output=json", str(target)))
    try:
        data = json.loads(output)
    except json.JSONDecodeError as error:
        raise ValueError(f"qemu-img info returned invalid JSON: {error}") from error
    return {
        "format": data.get("format"),
        "virtual_size": data.get("virtual-size"),
        "actual_size": data.get("actual-size"),
        "snapshots": [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "vm_state_size": item.get("vm-state-size"),
            }
            for item in data.get("snapshots", [])
            if isinstance(item, dict)
        ],
    }


def _run_qemu_img(args: tuple[str, ...]) -> str:
    command = ("qemu-img", *args)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=15.0)
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"qemu-img timed out: {' '.join(command)}") from error
    except OSError as error:
        raise ValueError(f"qemu-img failed to start: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise ValueError(f"qemu-img {' '.join(args[:2])} failed: {stderr}")
    return completed.stdout.strip()


def _project_relative_path(root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute() or "~" in path.parts or ".." in path.parts:
        raise ValueError("virtual execution paths must be project-relative and cannot include parent traversal")
    target = (root / path).resolve()
    root_resolved = root.resolve()
    if target == root_resolved or root_resolved not in target.parents:
        raise ValueError("virtual execution path must stay inside the project root")
    return target


def _write_manifest(
    root: Path,
    row: dict[str, object],
    action: str,
    provider: str,
    source: Path,
    target: Path,
    executed_at: str,
    preserved: Path | None = None,
    provider_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    manifest_dir = root / "local-secrets" / "virtual-runtime-manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "request_id": row["id"],
        "resource_id": row["resource_id"],
        "action": action,
        "provider": provider,
        "executed_at": executed_at,
        "source": _relative_or_name(root, source),
        "target": _relative_or_name(root, target),
        "preserved": _relative_or_name(root, preserved) if preserved else "",
        "provider_metadata": provider_metadata or {},
        "entries": _manifest_entries(root, target),
    }
    manifest["entry_count"] = len(manifest["entries"])
    manifest_path = manifest_dir / f"{_safe_id(str(row['id']))}-{_safe_id(executed_at)}.json"
    manifest["manifest_path"] = _relative_or_name(root, manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _manifest_entries(root: Path, target: Path) -> list[dict[str, object]]:
    paths = [target, *sorted(target.rglob("*"))] if target.is_dir() else [target]
    entries = []
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        entries.append(
            {
                "path": _relative_or_name(root, path),
                "kind": "directory" if path.is_dir() else "file",
                "bytes": 0 if path.is_dir() else stat.st_size,
            }
        )
    return entries


def _record_blocked_execution(
    root: Path,
    data: dict[str, list[dict[str, object]]],
    row: dict[str, object],
    action: str,
    request_id: str,
    executed_by: str,
    executed_at: str,
    error: str,
) -> dict[str, object]:
    row.update(
        {
            "status": "blocked",
            "executed_by": executed_by,
            "executed_at": executed_at,
            "updated_at": executed_at,
            "execution_error": error,
            "next_step": "declare a supported disposable runtime target or approved provider adapter before retrying",
        }
    )
    _append_execution(data, row, action, request_id, executed_by, executed_at, "blocked", "", error=error)
    _write_registry(root, data)
    return {
        f"{action}_request": row,
        "status": "blocked",
        "summary": error,
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def _record_failed_execution(
    root: Path,
    data: dict[str, list[dict[str, object]]],
    row: dict[str, object],
    action: str,
    request_id: str,
    executed_by: str,
    executed_at: str,
    error: str,
) -> dict[str, object]:
    row.update(
        {
            "status": "failed",
            "executed_by": executed_by,
            "executed_at": executed_at,
            "updated_at": executed_at,
            "execution_error": error,
            "next_step": "inspect partial virtual runtime state and retry only after Dax validates provider safety",
        }
    )
    _append_execution(data, row, action, request_id, executed_by, executed_at, "failed", "", error=error)
    _write_registry(root, data)
    return {
        f"{action}_request": row,
        "status": "failed",
        "summary": error,
        "mutation_performed": True,
        "host_mutation_performed": True,
    }


def _append_execution(
    data: dict[str, list[dict[str, object]]],
    row: dict[str, object],
    action: str,
    request_id: str,
    executed_by: str,
    executed_at: str,
    status: str,
    provider: str,
    manifest: dict[str, object] | None = None,
    error: str = "",
) -> None:
    data["execution_records"].append(
        {
            "id": f"virtual-execution.{_safe_id(request_id)}.{_safe_id(executed_at)}",
            "request_id": row.get("id") or request_id,
            "resource_id": row.get("resource_id"),
            "action": action,
            "status": status,
            "provider": provider,
            "executed_by": executed_by,
            "executed_at": executed_at,
            "manifest_path": (manifest or {}).get("manifest_path", ""),
            "error": error,
        }
    )


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


def _relative_or_name(root: Path, path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
