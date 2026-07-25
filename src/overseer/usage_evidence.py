"""Read-only usage, quota, and cost evidence for Quark."""

from __future__ import annotations

from pathlib import Path

from .store import SQLiteStore


def usage_evidence_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        limits = store.list_usage_limits()
        requests = store.list_usage_continuation_requests()
        dispatches = store.list_usage_continuation_dispatches()
    finally:
        store.close()
    return {
        "store": str(Path(store_path)),
        "limits": len(limits),
        "queued_requests": len(requests),
        "dispatches": len(dispatches),
        "limit_evidence": [
            {
                "limit_id": limit.id,
                "resource_id": limit.resource_id,
                "kind": limit.kind.value,
                "remaining": limit.remaining,
                "capacity": limit.capacity,
                "used": max(0, limit.capacity - limit.remaining),
                "usage_percent": _usage_percent(limit.capacity, limit.remaining),
                "window": limit.window,
                "resets_at": limit.resets_at,
                "confidence": limit.confidence,
                "status": _limit_status(limit.capacity, limit.remaining, limit.confidence),
                "next_step": _limit_next_step(limit.remaining, limit.resets_at, limit.confidence),
            }
            for limit in limits
        ],
        "allocation_by_thread": _allocation_by_thread(requests),
        "continuation_queue": [
            {
                "request_id": request.id,
                "limit_id": request.limit_id,
                "resource_id": request.resource_id,
                "owner_thread": request.owner_thread,
                "requested_units": request.requested_units,
                "status": "queued",
                "earliest_start": request.earliest_start,
                "deadline": request.deadline,
            }
            for request in requests
        ],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _usage_percent(capacity: int, remaining: int) -> int:
    if capacity <= 0:
        return 0
    return int(max(0, min(capacity, capacity - remaining)) / capacity * 100)


def _limit_status(capacity: int, remaining: int, confidence: float) -> str:
    if confidence < 0.5:
        return "low_confidence"
    if remaining <= 0:
        return "exhausted"
    if capacity > 0 and remaining <= max(1, int(capacity * 0.1)):
        return "near_exhaustion"
    return "available"


def _limit_next_step(remaining: int, resets_at: str | None, confidence: float) -> str:
    if confidence < 0.5:
        return "verify provider reset policy before dispatch"
    if remaining <= 0 and resets_at:
        return "hold queued work until reset"
    if remaining <= 0:
        return "record reset time before dispatch"
    return "dispatch within remaining capacity"


def _allocation_by_thread(requests: tuple[object, ...]) -> list[dict[str, object]]:
    allocations: dict[str, int] = {}
    counts: dict[str, int] = {}
    for request in requests:
        allocations[request.owner_thread] = allocations.get(request.owner_thread, 0) + request.requested_units
        counts[request.owner_thread] = counts.get(request.owner_thread, 0) + 1
    return [
        {
            "owner_thread": owner_thread,
            "requests": counts[owner_thread],
            "requested_units": units,
            "status": "queued",
        }
        for owner_thread, units in sorted(allocations.items())
    ]
