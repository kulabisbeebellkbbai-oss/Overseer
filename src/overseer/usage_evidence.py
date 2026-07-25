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
        "exhaustion_forecast": _exhaustion_forecast(limits, requests),
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


def _exhaustion_forecast(limits: tuple[object, ...], requests: tuple[object, ...]) -> list[dict[str, object]]:
    requests_by_limit: dict[str, list[object]] = {}
    for request in requests:
        requests_by_limit.setdefault(request.limit_id, []).append(request)
    rows = []
    known_limit_ids = {limit.id for limit in limits}
    for limit in limits:
        queued = requests_by_limit.get(limit.id, [])
        queued_units = sum(max(0, request.requested_units) for request in queued)
        remaining_after_queue = limit.remaining - queued_units
        deficit_units = max(0, queued_units - limit.remaining)
        rows.append(
            {
                "limit_id": limit.id,
                "resource_id": limit.resource_id,
                "remaining": limit.remaining,
                "queued_requests": len(queued),
                "queued_units": queued_units,
                "remaining_after_queue": remaining_after_queue,
                "deficit_units": deficit_units,
                "resets_at": limit.resets_at,
                "status": _forecast_status(limit.remaining, queued_units, limit.resets_at, limit.confidence),
                "next_step": _forecast_next_step(limit.remaining, queued_units, limit.resets_at, limit.confidence),
            }
        )
    for limit_id, queued in sorted(requests_by_limit.items()):
        if limit_id in known_limit_ids:
            continue
        rows.append(
            {
                "limit_id": limit_id,
                "resource_id": queued[0].resource_id if queued else "",
                "remaining": 0,
                "queued_requests": len(queued),
                "queued_units": sum(max(0, request.requested_units) for request in queued),
                "remaining_after_queue": 0,
                "deficit_units": sum(max(0, request.requested_units) for request in queued),
                "resets_at": None,
                "status": "missing_limit",
                "next_step": "register usage limit before dispatch",
            }
        )
    return rows


def _forecast_status(remaining: int, queued_units: int, resets_at: str | None, confidence: float) -> str:
    if confidence < 0.5:
        return "low_confidence"
    if queued_units <= 0:
        return "no_queue"
    if remaining >= queued_units:
        return "fits_now"
    if resets_at:
        return "queue_until_reset"
    return "blocked_no_reset"


def _forecast_next_step(remaining: int, queued_units: int, resets_at: str | None, confidence: float) -> str:
    if confidence < 0.5:
        return "verify provider reset policy before dispatch"
    if queued_units <= 0:
        return "no queued continuation work"
    if remaining >= queued_units:
        return "dispatch queued work within remaining capacity"
    if resets_at:
        return "hold queued work until reset"
    return "record reset time or reduce queued work"
