"""Read-only storage, backup, and recovery evidence for Kira."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .backup_ops import backup_operations_status


def storage_evidence_status(project_root: str | Path | None = None) -> dict[str, object]:
    root = Path(project_root or Path.cwd())
    mounts = _df_rows()
    backup_markers = _backup_markers(root)
    backup_ops = backup_operations_status(root)
    return {
        "root": str(root),
        "mounts": mounts,
        "mount_count": len(mounts),
        "backup_markers": backup_markers,
        "backup_marker_count": len(backup_markers),
        "restore_tests": backup_ops["restore_tests"] or [marker for marker in backup_markers if "restore" in marker["path"].lower()],
        "backup_jobs": backup_ops["jobs"],
        "cleanup_requests": backup_ops["cleanup_requests"],
        "smart_health": _smart_health_rows(),
        "cleanup_candidates": _cleanup_candidates(root),
        "capacity_summary": _capacity_summary(),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


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
