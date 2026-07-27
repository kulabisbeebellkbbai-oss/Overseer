"""Read-only storage, backup, and recovery evidence for Kira."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .backup_ops import backup_operations_status


def storage_evidence_status(project_root: str | Path | None = None) -> dict[str, object]:
    root = Path(project_root or Path.cwd())
    mounts = _df_rows()
    backup_markers = _backup_markers(root)
    backup_ops = backup_operations_status(root)
    growth_history = storage_growth_history_status(root)
    return {
        "root": str(root),
        "mounts": mounts,
        "mount_count": len(mounts),
        "backup_markers": backup_markers,
        "backup_marker_count": len(backup_markers),
        "restore_tests": backup_ops["restore_tests"] or [marker for marker in backup_markers if "restore" in marker["path"].lower()],
        "backup_jobs": backup_ops["jobs"],
        "backup_requests": backup_ops["backup_requests"],
        "restore_requests": backup_ops["restore_requests"],
        "cleanup_requests": backup_ops["cleanup_requests"],
        "backup_provider_targets": backup_ops["provider_targets"],
        "backup_provider_classes": backup_ops["provider_classes"],
        "backup_provider_readiness": backup_ops["provider_readiness"],
        "backup_provider_standard": backup_ops["provider_standard"],
        "smart_health": _smart_health_rows(),
        "cleanup_candidates": _cleanup_candidates(root),
        "capacity_summary": _capacity_summary(),
        "growth_samples": growth_history["snapshots"],
        "growth_sample_count": growth_history["snapshot_count"],
        "growth_trends": growth_history["trends"],
        "growth_retention": growth_history["retention"],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def storage_growth_history_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_growth_registry(root)
    snapshots = sorted(data["snapshots"], key=lambda item: str(item.get("captured_at") or item.get("id")), reverse=True)
    return {
        "root": str(root),
        "snapshots": snapshots,
        "snapshot_count": len(snapshots),
        "trends": _growth_trend_rows(snapshots),
        "retention": data.get("retention", {"max_snapshots": 250}),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def capture_storage_growth_snapshot_status(
    project_root: str | Path,
    snapshot_id: str = "",
    requested_by: str = "kira",
    notes: str = "",
    max_snapshots: int = 250,
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_growth_registry(root)
    now = _now()
    row = {
        "id": _safe_id(snapshot_id) if snapshot_id else f"storage-growth.{now.replace(':', '').replace('-', '')}",
        "captured_at": now,
        "requested_by": requested_by,
        "mounts": [_growth_mount_sample(mount) for mount in _df_rows()],
        "root_capacity": _capacity_summary(),
        "notes": notes,
        "next_step": "compare against previous storage growth snapshots and investigate fast-growing filesystems before capacity becomes urgent",
    }
    _upsert_snapshot(data["snapshots"], row)
    data["snapshots"] = sorted(data["snapshots"], key=lambda item: str(item.get("captured_at") or item.get("id")), reverse=True)[: max(1, int(max_snapshots))]
    data["retention"] = {"max_snapshots": max(1, int(max_snapshots))}
    _write_growth_registry(root, data)
    return {"snapshot": row, "mutation_performed": True, "host_mutation_performed": False}


def _df_rows() -> list[dict[str, object]]:
    try:
        completed = subprocess.run(("df", "-P", "-T"), check=False, capture_output=True, text=True, timeout=1.5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    rows = []
    for line in completed.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        rows.append(
            {
                "source": _redact_device(parts[0]),
                "type": parts[1],
                "size": parts[2],
                "used": parts[3],
                "available": parts[4],
                "use_percent": parts[5],
                "mount": _redact_mount(parts[6]),
                "status": _usage_status(parts[5]),
            }
        )
    return rows


def _backup_markers(root: Path) -> list[dict[str, object]]:
    search_roots = [root / "state", root / "backups", root / "docs", root / "local-secrets"]
    markers: list[dict[str, object]] = []
    for search_root in search_roots:
        if not search_root.exists():
            continue
        for path in sorted(search_root.glob("**/*")):
            if len(markers) >= 50:
                break
            name = path.name.lower()
            if "backup" in name or "restore" in name:
                markers.append(
                    {
                        "path": _relative_or_name(root, path),
                        "kind": "directory" if path.is_dir() else "file",
                        "status": "candidate",
                    }
                )
    return markers


def _cleanup_candidates(root: Path) -> list[dict[str, object]]:
    candidates = []
    for relative in ("artifacts", ".pytest_cache"):
        path = root / relative
        if path.exists():
            candidates.append({"path": relative, "kind": "generated", "status": "review_before_delete"})
    return candidates


def _smart_health_rows() -> list[dict[str, object]]:
    if shutil.which("smartctl") is None:
        return [{"device": "smartctl", "available": False, "status": "not_installed"}]
    rows = []
    for device in sorted(Path("/dev").glob("sd?"))[:8]:
        try:
            completed = subprocess.run(("smartctl", "-H", str(device)), check=False, capture_output=True, text=True, timeout=2.0)
        except subprocess.TimeoutExpired:
            rows.append({"device": device.name, "available": True, "status": "timeout"})
            continue
        status = "unknown"
        output = completed.stdout + completed.stderr
        if "PASSED" in output:
            status = "passed"
        elif "FAILED" in output:
            status = "failed"
        rows.append({"device": device.name, "available": True, "exit_code": completed.returncode, "status": status})
    return rows


def _capacity_summary() -> dict[str, object]:
    usage = shutil.disk_usage("/")
    return {
        "mount": "/",
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "status": "attention" if usage.free < usage.total * 0.1 else "ok",
    }


def _growth_trend_rows(snapshots: list[dict[str, object]]) -> list[dict[str, object]]:
    by_mount: dict[str, list[dict[str, object]]] = {}
    for snapshot in snapshots:
        for mount in snapshot.get("mounts") or []:
            key = str(mount.get("mount") or "unknown")
            by_mount.setdefault(key, []).append({**mount, "captured_at": snapshot.get("captured_at")})
    rows = []
    for mount, samples in sorted(by_mount.items()):
        ordered = sorted(samples, key=lambda item: str(item.get("captured_at") or ""))
        latest = ordered[-1]
        oldest = ordered[0]
        latest_used = _int_or_none(latest.get("used_bytes"))
        oldest_used = _int_or_none(oldest.get("used_bytes"))
        elapsed_days = _elapsed_days(oldest.get("captured_at"), latest.get("captured_at"))
        if len(ordered) < 2 or latest_used is None or oldest_used is None or not elapsed_days:
            daily_growth = None
            status = "needs_history"
            next_step = "capture another storage growth snapshot after normal workload activity"
        else:
            daily_growth = round((latest_used - oldest_used) / elapsed_days)
            status = _growth_status(daily_growth, latest.get("status"))
            next_step = _growth_next_step(status)
        rows.append(
            {
                "mount": mount,
                "samples": len(ordered),
                "oldest_captured_at": oldest.get("captured_at"),
                "latest_captured_at": latest.get("captured_at"),
                "latest_used_bytes": latest_used,
                "latest_available_bytes": _int_or_none(latest.get("available_bytes")),
                "latest_use_percent": latest.get("use_percent"),
                "daily_growth_bytes": daily_growth,
                "status": status,
                "next_step": next_step,
            }
        )
    if not rows:
        rows.append(
            {
                "mount": "/",
                "samples": 0,
                "status": "needs_history",
                "next_step": "capture the first storage growth snapshot from Assets",
            }
        )
    return rows


def _growth_mount_sample(mount: dict[str, object]) -> dict[str, object]:
    return {
        "source": mount.get("source"),
        "type": mount.get("type"),
        "mount": mount.get("mount"),
        "size_bytes": _kilobytes_to_bytes(mount.get("size")),
        "used_bytes": _kilobytes_to_bytes(mount.get("used")),
        "available_bytes": _kilobytes_to_bytes(mount.get("available")),
        "use_percent": mount.get("use_percent"),
        "status": mount.get("status"),
    }


def _growth_status(daily_growth_bytes: int, latest_status: object) -> str:
    if latest_status in {"critical", "warning"}:
        return str(latest_status)
    if daily_growth_bytes > 1024 * 1024 * 1024:
        return "attention"
    if daily_growth_bytes < 0:
        return "shrinking"
    return "ok"


def _growth_next_step(status: str) -> str:
    if status in {"critical", "warning", "attention"}:
        return "review large-file, backup, database, cache, and log growth before the next maintenance window"
    if status == "shrinking":
        return "confirm cleanup or rotation was expected and no restore evidence was lost"
    return "keep capturing storage growth snapshots during normal operations"


def _growth_registry_path(root: Path) -> Path:
    return root / "state" / "storage-growth-history.json"


def _read_growth_registry(root: Path) -> dict[str, object]:
    path = _growth_registry_path(root)
    if not path.exists():
        return {"snapshots": [], "retention": {"max_snapshots": 250}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"snapshots": [], "retention": {"max_snapshots": 250}}
    return {
        "snapshots": list(data.get("snapshots") or []),
        "retention": dict(data.get("retention") or {"max_snapshots": 250}),
    }


def _write_growth_registry(root: Path, data: dict[str, object]) -> None:
    path = _growth_registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _upsert_snapshot(rows: list[dict[str, object]], row: dict[str, object]) -> None:
    existing = next((index for index, item in enumerate(rows) if item.get("id") == row["id"]), None)
    if existing is None:
        rows.append(row)
    else:
        rows[existing] = row


def _kilobytes_to_bytes(value: object) -> int | None:
    numeric = _int_or_none(value)
    return None if numeric is None else numeric * 1024


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _elapsed_days(start: object, end: object) -> float | None:
    try:
        start_dt = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return None
    seconds = (end_dt - start_dt).total_seconds()
    if seconds <= 0:
        return None
    return seconds / 86400


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip()).strip("-")
    return cleaned or "storage-growth"


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _usage_status(percent: str) -> str:
    try:
        value = int(percent.rstrip("%"))
    except ValueError:
        return "unknown"
    if value >= 95:
        return "critical"
    if value >= 85:
        return "warning"
    return "ok"


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _redact_device(value: str) -> str:
    return value if value.startswith(("tmpfs", "udev", "overlay")) else Path(value).name


def _redact_mount(value: str) -> str:
    if value in {"/", "/boot", "/home", "/tmp", "/var", "/run"}:
        return value
    if value.startswith("/"):
        return f".../{Path(value).name}"
    return value
