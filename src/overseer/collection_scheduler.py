"""Bounded, restart-safe collection scheduling."""

from __future__ import annotations

import hashlib
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable

from .collection_adapters import (
    CollectionAdapterRegistry,
    CollectionExecution,
    default_collection_adapter_registry,
)
from .collection_deadline import CollectionDeadlineExceeded, collection_deadline_scope
from .collection_models import (
    CircuitState,
    CollectionJob,
    CollectionOutcome,
    CollectionRun,
)
from .collection_policy import job_is_due
from .store import SQLiteStore

DEFAULT_MAX_WORKERS = 2
MAX_PER_CONCURRENCY_KEY = 1
DEFAULT_LEASE_GRACE_SECONDS = 300


@dataclass(frozen=True)
class SchedulerCycle:
    claimed: int
    started: int
    succeeded: int
    failed: int
    blocked: int
    timed_out: int
    next_due_at: str | None


@dataclass
class _ActiveWork:
    job: CollectionJob
    future: Future[CollectionExecution] | None
    lease_id: str
    lease_generation: int
    started_at: str
    deadline: float
    request_id: str | None = None
    timed_out: bool = False
    completion_handled: bool = False
    started: bool = False


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _parse_now(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("scheduler clock must return an ISO-8601 UTC timestamp")
    return parsed.astimezone(UTC)


def _run_id(job_id: str, lease_id: str, generation: int) -> str:
    digest = hashlib.sha256(f"{job_id}:{lease_id}:{generation}".encode()).hexdigest()[:48]
    return f"run.collection.{digest}"


def _not_before_started(started_at: str, completed_at: str) -> str:
    """Keep fast worker completion valid when the coordinator clock was sampled first."""
    started = _parse_now(started_at)
    completed = _parse_now(completed_at)
    return max(started, completed).isoformat()


class CollectionScheduler:
    def __init__(
        self,
        store_path: str | Path,
        adapter_registry: CollectionAdapterRegistry | None = None,
        *,
        max_workers: int = DEFAULT_MAX_WORKERS,
        worker_id: str = "scheduler.local",
        clock: Callable[[], str] | None = None,
        adapter_ids: dict[object, str] | None = None,
        shutdown_timeout_seconds: float = 5.0,
    ) -> None:
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 0 < max_workers <= DEFAULT_MAX_WORKERS:
            raise ValueError("scheduler max_workers must be between one and two")
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise ValueError("scheduler worker id is required")
        self.store_path = str(store_path)
        self.registry = adapter_registry or default_collection_adapter_registry()
        self.max_workers = max_workers
        self.worker_id = worker_id
        self.clock = clock or _utc_now
        self.adapter_ids = adapter_ids or {}
        self.shutdown_timeout_seconds = max(0.1, float(shutdown_timeout_seconds))
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="overseer-collection")
        self._active: dict[str, _ActiveWork] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._closed = False
        self._completion_event = threading.Event()

    def _now(self, now: str | None) -> str:
        value = now if now is not None else self.clock()
        _parse_now(value)
        return value

    def _adapter_id(self, job: CollectionJob) -> str | None:
        return (
            self.adapter_ids.get(job.id)
            or self.adapter_ids.get(job.kind)
            or self.adapter_ids.get(job.kind.value)
        )

    def _active_keys(self) -> set[str]:
        with self._lock:
            return {work.job.concurrency_key for work in self._active.values()}

    def _due_candidates(self, now: str, excluded_keys: set[str]) -> list[CollectionJob]:
        with SQLiteStore(self.store_path) as store:
            jobs = store.list_collection_jobs()
            states = {state.job_id: state for state in store.list_collection_job_states()}
            requests = {
                request.job_id: request
                for request in store.list_collection_requests()
                if request.status == "pending"
                and (request.earliest_execution_at is None or _parse_now(request.earliest_execution_at) <= _parse_now(now))
            }
        candidates = [
            job for job in jobs
            if job.enabled
            and job.concurrency_key not in excluded_keys
            and job.id in states
            and (
                job_is_due(states[job.id], now)
                or (job.id in requests and states[job.id].circuit_state is CircuitState.CLOSED)
            )
        ]
        return sorted(candidates, key=lambda job: (-job.priority, requests.get(job.id).requested_at if job.id in requests else states[job.id].next_due_at, job.id))

    def _claim_one(self, job: CollectionJob, now: str) -> tuple[CollectionJob, str, int] | None:
        lease_seconds = max(DEFAULT_LEASE_GRACE_SECONDS, job.timeout_seconds * 4)
        lease_expires = (_parse_now(now) + timedelta(seconds=lease_seconds)).isoformat()
        with SQLiteStore(self.store_path) as store:
            claimed = store.claim_due_collection_jobs(
                now,
                self.worker_id,
                lease_expires,
                limit=1,
                include_pending_requests=True,
                job_id=job.id,
            )
            if not claimed or claimed[0].id != job.id:
                return None
            state = store.load_collection_job_state(job.id)
        if state.active_lease_id is None or state.lease_owner != self.worker_id:
            return None
        return job, state.active_lease_id, state.lease_generation

    def _submit(self, job: CollectionJob, lease_id: str, generation: int, now: str, request_id: str | None) -> _ActiveWork:
        adapter = self.registry.resolve(job, self._adapter_id(job))
        work = _ActiveWork(
            job=job,
            future=None,
            lease_id=lease_id,
            lease_generation=generation,
            started_at=now,
            deadline=float("inf"),
            request_id=request_id,
        )
        # Reserve the in-memory slot before submission. The wrapper starts the
        # deadline at the actual callable boundary, excluding queue time.
        self._active[lease_id] = work
        future = self._executor.submit(self._run_adapter, adapter, work)
        work.future = future
        future.add_done_callback(lambda _future, lease=lease_id: self._on_future_done(lease))
        return work

    def _run_adapter(self, adapter: object, work: _ActiveWork) -> CollectionExecution:
        with self._lock:
            if self._active.get(work.lease_id) is work:
                work.started = True
                work.started_at = self._now(None)
                work.deadline = time.monotonic() + work.job.timeout_seconds
        with collection_deadline_scope(work.deadline):
            return adapter.collect(work.job, self.store_path)  # type: ignore[attr-defined]

    def _on_future_done(self, lease_id: str) -> None:
        with self._lock:
            work = self._active.get(lease_id)
            if work is None:
                return
            if not work.timed_out:
                self._completion_event.set()
                return
            if work.completion_handled:
                return
            work.completion_handled = True
            job_id = work.job.id
            generation = work.lease_generation
        try:
            with SQLiteStore(self.store_path) as store:
                store.release_collection_lease(job_id, lease_id, generation)
        finally:
            with self._lock:
                if self._active.get(lease_id) is work:
                    self._active.pop(lease_id, None)
                self._completion_event.set()

    def _timeout(self, work: _ActiveWork, now: str) -> None:
        with self._lock:
            if work.timed_out or self._active.get(work.lease_id) is not work:
                return
            work.timed_out = True
            completed_at = _not_before_started(work.started_at, now)
            run = CollectionRun(
                id=_run_id(work.job.id, work.lease_id, work.lease_generation),
                job_id=work.job.id,
                trigger="scheduled",
                started_at=work.started_at,
                completed_at=completed_at,
                outcome=CollectionOutcome.TIMED_OUT,
                summary="collection deadline exceeded",
                error_category="timeout",
                retry_disposition="backoff",
                request_id=work.request_id,
            )
            # Keep the coordinator lock through persistence so a completion
            # callback cannot release the lease before the timeout run exists.
            with SQLiteStore(self.store_path) as store:
                store.record_collection_timeout(run, work.lease_id, work.lease_generation)

    def _finish(self, work: _ActiveWork, now: str) -> tuple[int, int, int]:
        """Return ``(succeeded, failed, timed_out)`` for one completed future."""
        with self._lock:
            if self._active.get(work.lease_id) is not work or work.completion_handled:
                return 0, 0, 0
            work.completion_handled = True
        if work.timed_out:
            with SQLiteStore(self.store_path) as store:
                store.release_collection_lease(work.job.id, work.lease_id, work.lease_generation)
            with self._lock:
                if self._active.get(work.lease_id) is work:
                    self._active.pop(work.lease_id, None)
                self._completion_event.set()
            return 0, 0, 0
        try:
            if work.future is None:
                raise RuntimeError("collection future was not installed")
            execution = work.future.result()
            if not isinstance(execution, CollectionExecution):
                raise TypeError("collection adapter returned an invalid execution")
        except CollectionDeadlineExceeded:
            execution = CollectionExecution(
                CollectionOutcome.TIMED_OUT,
                "collection deadline exceeded before persistence",
                failure_category="timeout",
            )
        except BaseException:
            execution = CollectionExecution(
                CollectionOutcome.FAILED,
                "collection adapter failed internally",
                failure_category="internal_error",
            )
        completed_at = _not_before_started(work.started_at, now)
        run = CollectionRun(
            id=_run_id(work.job.id, work.lease_id, work.lease_generation),
            job_id=work.job.id,
            trigger="scheduled",
            started_at=work.started_at,
            completed_at=completed_at,
            outcome=execution.outcome,
            # Adapter summaries are diagnostics, not a scheduler evidence
            # channel. Persist only the bounded outcome label.
            summary=f"collection {execution.outcome.value}",
            evidence_ids=execution.evidence_ids,
            error_category=(execution.failure_category if execution.failure_category in {
                "", "timeout", "unavailable", "contract_mismatch", "authentication",
                "resource_conflict", "policy_blocked", "stale", "adapter_error", "internal_error",
            } else "adapter_error"),
            retry_disposition="backoff" if execution.outcome is not CollectionOutcome.SUCCEEDED else "none",
            request_id=work.request_id,
        )
        with SQLiteStore(self.store_path) as store:
            store.complete_collection_run(run, work.lease_id, work.lease_generation)
        with self._lock:
            if self._active.get(work.lease_id) is work:
                self._active.pop(work.lease_id, None)
            self._completion_event.set()
        if execution.outcome is CollectionOutcome.SUCCEEDED:
            return 1, 0, 0
        return 0, 1, 1 if execution.outcome is CollectionOutcome.TIMED_OUT else 0
    def _reap_done(self, now: str) -> tuple[int, int, int]:
        counts = [0, 0, 0]
        with self._lock:
            works = tuple(self._active.values())
        for work in works:
            if work.future is not None and work.future.done():
                if work.timed_out:
                    result = self._finish(work, now)
                elif time.monotonic() >= work.deadline:
                    self._timeout(work, now)
                    result = self._finish(work, now)
                else:
                    result = self._finish(work, now)
                for index, value in enumerate(result):
                    counts[index] += value
        return tuple(counts)  # type: ignore[return-value]

    def run_ready_once(self, now: str | None = None) -> SchedulerCycle:
        current = self._now(now)
        with self._lock:
            if self._closed:
                raise RuntimeError("collection scheduler is shut down")
            succeeded, failed, timed_out = self._reap_done(current)
            claimed = started = blocked = 0
            new_work: list[_ActiveWork] = []
            excluded = self._active_keys()
            while len(self._active) < self.max_workers:
                candidates = self._due_candidates(current, excluded | {work.job.concurrency_key for work in new_work})
                if not candidates:
                    break
                candidate = candidates[0]
                try:
                    self.registry.resolve(candidate, self._adapter_id(candidate))
                except ValueError:
                    blocked += 1
                    excluded.add(candidate.concurrency_key)
                    continue
                result = self._claim_one(candidate, current)
                if result is None:
                    excluded.add(candidate.concurrency_key)
                    continue
                job, lease_id, generation = result
                with SQLiteStore(self.store_path) as store:
                    request_id = next(
                        (
                            request.id
                            for request in store.list_collection_requests()
                            if request.job_id == job.id
                            and request.status == "pending"
                            and (request.earliest_execution_at is None or _parse_now(request.earliest_execution_at) <= _parse_now(current))
                        ),
                        None,
                    )
                claimed += 1
                work = self._submit(job, lease_id, generation, current, request_id)
                new_work.append(work)
                excluded.add(job.concurrency_key)
                started += 1

        pending = set(work.lease_id for work in new_work)
        while pending:
            progress = False
            for lease_id in tuple(pending):
                with self._lock:
                    work = self._active.get(lease_id)
                if work is None:
                    pending.remove(lease_id)
                    progress = True
                    continue
                if not work.timed_out and work.started and work.future is not None and not work.future.done() and time.monotonic() >= work.deadline:
                    self._timeout(work, current)
                    failed += 1
                    timed_out += 1
                    pending.remove(lease_id)
                    progress = True
                    continue
                if work.future is not None and work.future.done():
                    done = self._finish(work, current)
                    succeeded += done[0]
                    failed += done[1]
                    timed_out += done[2]
                    pending.remove(lease_id)
                    progress = True
            if pending and not progress:
                self._completion_event.wait(0.005)
                self._completion_event.clear()

        with SQLiteStore(self.store_path) as store:
            next_due = [state.next_due_at for state in store.list_collection_job_states() if state.active_lease_id is None]
        return SchedulerCycle(
            claimed=claimed,
            started=started,
            succeeded=succeeded,
            failed=failed,
            blocked=blocked,
            timed_out=timed_out,
            next_due_at=min(next_due) if next_due else None,
        )

    def run_forever(self, maximum_idle_seconds: float = 5.0) -> None:
        if maximum_idle_seconds <= 0:
            raise ValueError("maximum idle seconds must be positive")
        while not self._stop.is_set():
            cycle = self.run_ready_once()
            if self._stop.wait(min(maximum_idle_seconds, 0.25 if cycle.started else maximum_idle_seconds)):
                break

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
        self._stop.set()
        deadline = time.monotonic() + self.shutdown_timeout_seconds
        while time.monotonic() < deadline:
            with self._lock:
                active = tuple(self._active.values())
            if not active:
                break
            current = self._now(None)
            for work in active:
                if work.started and not work.timed_out and time.monotonic() >= work.deadline:
                    self._timeout(work, current)
            self._reap_done(current)
            self._completion_event.wait(min(0.005, max(0.0, deadline - time.monotonic())))
            self._completion_event.clear()
        with self._lock:
            has_active = bool(self._active)
        self._executor.shutdown(wait=not has_active, cancel_futures=False)
        with self._lock:
            self._closed = True

    def __enter__(self) -> CollectionScheduler:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.shutdown()


def scheduler_status(store_path: str | Path) -> dict[str, object]:
    with SQLiteStore(store_path) as store:
        jobs = store.list_collection_jobs()
        states = store.list_collection_job_states()
        runs = store.list_collection_runs()
        incidents = store.list_triage_incidents()
    open_incidents = sum(1 for incident in incidents if incident.status.value == "open")
    circuit_count = sum(1 for state in states if state.circuit_state is CircuitState.OPEN)
    return {
        "max_workers": DEFAULT_MAX_WORKERS,
        "max_per_concurrency_key": MAX_PER_CONCURRENCY_KEY,
        "load_bounds": {
            "global_max": DEFAULT_MAX_WORKERS,
            "per_concurrency_key_max": MAX_PER_CONCURRENCY_KEY,
        },
        "job_count": len(jobs),
        "active_count": sum(1 for state in states if state.active_lease_id is not None),
        "queue_depth": sum(1 for state in states if state.active_lease_id is None),
        "run_count": len(runs),
        "open_incident_count": open_incidents,
        "incident_count": open_incidents,
        "circuit_count": circuit_count,
        "next_due_at": min((state.next_due_at for state in states if state.active_lease_id is None), default=None),
    }
