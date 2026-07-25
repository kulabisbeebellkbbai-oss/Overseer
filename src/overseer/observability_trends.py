"""Read-only trend summaries from stored health and host evidence."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from .health import HealthStatus


def observability_trends_status(store_path: str | Path) -> dict[str, object]:
    from .store import SQLiteStore

    store = SQLiteStore(store_path)
    try:
        evidence = store.list_health_evidence()
        snapshots = store.list_host_snapshots()
    finally:
        store.close()
    by_resource: dict[str, list[object]] = {}
    for item in evidence:
        by_resource.setdefault(item.resource_id, []).append(item)
    return {
        "store": str(Path(store_path)),
        "health_evidence": len(evidence),
        "host_snapshots": len(snapshots),
        "resource_trends": [_resource_trend(resource_id, items) for resource_id, items in sorted(by_resource.items())],
        "host_snapshot_trends": [
            {
                "snapshot_id": snapshot.id,
                "captured_at": snapshot.captured_at,
                "hostname": snapshot.hostname,
                "observation_count": len(snapshot.observations),
            }
            for snapshot in sorted(snapshots, key=lambda item: item.captured_at or item.id, reverse=True)[:20]
        ],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _resource_trend(resource_id: str, items: list[object]) -> dict[str, object]:
    statuses = Counter(item.observed_status.value for item in items)
    ordered = sorted(items, key=lambda item: item.captured_at or item.id)
    latest = ordered[-1] if ordered else None
    failures = statuses[HealthStatus.FAILED.value] + statuses[HealthStatus.DEGRADED.value] + statuses[HealthStatus.UNKNOWN.value]
    return {
        "resource_id": resource_id,
        "samples": len(items),
        "healthy": statuses[HealthStatus.HEALTHY.value],
        "unhealthy": failures,
        "latest_status": latest.observed_status.value if latest else "unknown",
        "latest_at": latest.captured_at if latest else None,
        "error_rate_status": "attention" if failures else "ok",
    }
