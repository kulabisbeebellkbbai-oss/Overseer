"""Durable metric history snapshots for Julian."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

from .observability_trends import observability_trends_status


def metric_history_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    return {
        "root": str(root),
        "snapshots": data["snapshots"],
        "snapshot_count": len(data["snapshots"]),
        "retention": data.get("retention", {"max_snapshots": 250}),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def capture_metric_history_status(
    store_path: str | Path,
    project_root: str | Path,
    snapshot_id: str = "",
    requested_by: str = "julian",
    notes: str = "",
    max_snapshots: int = 250,
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    trends = observability_trends_status(store_path)
    now = _now()
    row = {
        "id": _safe_id(snapshot_id) if snapshot_id else f"metric-history.{now.replace(':', '').replace('-', '')}",
        "captured_at": now,
        "requested_by": requested_by,
        "health_evidence": trends["health_evidence"],
        "host_snapshots": trends["host_snapshots"],
        "resource_count": len(trends["resource_trends"]),
        "attention_resources": [
            item["resource_id"]
            for item in trends["resource_trends"]
            if item.get("error_rate_status") == "attention" or item.get("latest_status") != "healthy"
        ],
        "notes": notes,
        "next_step": "compare against previous metric history snapshots for regressions and recurring unhealthy resources",
    }
    _upsert(data["snapshots"], row)
    data["snapshots"] = sorted(data["snapshots"], key=lambda item: str(item.get("captured_at") or item.get("id")), reverse=True)[: max(1, int(max_snapshots))]
    data["retention"] = {"max_snapshots": max(1, int(max_snapshots))}
    _write_registry(root, data)
    return {"snapshot": row, "mutation_performed": True, "host_mutation_performed": False}


def _registry_path(root: Path) -> Path:
    return root / "state" / "metric-history.json"


def _read_registry(root: Path) -> dict[str, object]:
    path = _registry_path(root)
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


def _write_registry(root: Path, data: dict[str, object]) -> None:
    path = _registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _upsert(rows: list[dict[str, object]], row: dict[str, object]) -> None:
    existing = next((index for index, item in enumerate(rows) if item["id"] == row["id"]), None)
    if existing is None:
        rows.append(row)
    else:
        rows[existing] = row


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip()).strip("-")
    return cleaned or "metric-history"


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
