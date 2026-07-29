"""Usage-aware, checkpointed Codex work scheduling for Quark."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from collections import deque
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class WorkState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CHECKPOINTED = "checkpointed"
    WAITING_CAPACITY = "waiting_capacity"
    COMPLETED = "completed"
    RECONCILE_REQUIRED = "reconcile_required"


@dataclass(frozen=True)
class QuarkUsagePolicy:
    hard_reserve_points: float = 15
    uncertainty_points: float = 2
    max_slice_points: float = 5
    max_concurrent_work: int = 1
    stale_after_minutes: int = 30
    emergency_floor_points: float = 5

    def __post_init__(self) -> None:
        if self.hard_reserve_points < self.emergency_floor_points:
            raise ValueError("hard reserve cannot be below the emergency floor")
        if self.uncertainty_points < 0:
            raise ValueError("uncertainty points cannot be negative")
        if self.max_slice_points <= 0:
            raise ValueError("max slice points must be positive")
        if self.max_concurrent_work < 1:
            raise ValueError("max concurrent work must be positive")


@dataclass(frozen=True)
class CodexWorkItem:
    id: str
    project_id: str
    owner_thread: str
    limit_id: str
    intent: str
    estimated_quota_points: float
    estimated_tokens: int | None = None
    priority: int = 50
    state: WorkState = WorkState.QUEUED
    reserved_quota_points: float = 0
    generation: int = 0
    checkpoint_ref: str | None = None
    pause_reason: str | None = None
    resume_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None

    def __post_init__(self) -> None:
        if not self.id.strip() or not self.project_id.strip() or not self.owner_thread.strip():
            raise ValueError("work id, project id, and owner thread are required")
        if self.estimated_quota_points <= 0:
            raise ValueError("estimated quota points must be positive")
        if self.reserved_quota_points < 0:
            raise ValueError("reserved quota points cannot be negative")
        if self.priority < 0 or self.priority > 100:
            raise ValueError("priority must be between 0 and 100")

    def with_state(self, state: WorkState, **changes: Any) -> "CodexWorkItem":
        return replace(self, state=state, **changes)


@dataclass(frozen=True)
class WorkAllocation:
    work_id: str
    project_id: str
    owner_thread: str
    generation: int
    allocated_quota_points: float


@dataclass(frozen=True)
class QuarkWorkPlan:
    allocations: tuple[WorkAllocation, ...]
    remaining_before_plan: float
    active_reservations: float
    guardrail_floor: float
    spendable_capacity: float
    remaining_after_plan: float
    reason: str


def plan_quark_work(
    policy: QuarkUsagePolicy,
    remaining_points: float,
    work: tuple[CodexWorkItem, ...],
) -> QuarkWorkPlan:
    if remaining_points < 0 or remaining_points > 100:
        raise ValueError("remaining points must be between 0 and 100")
    active_reservations = sum(
        item.reserved_quota_points
        for item in work
        if item.state is WorkState.RUNNING
    )
    guardrail_floor = policy.hard_reserve_points + policy.uncertainty_points
    spendable = max(0.0, remaining_points - guardrail_floor - active_reservations)
    if spendable <= 0:
        return QuarkWorkPlan(
            (),
            remaining_points,
            active_reservations,
            guardrail_floor,
            0,
            remaining_points,
            "capacity is at the reserve and uncertainty floor",
        )

    eligible = [
        item
        for item in work
        if item.state in {WorkState.QUEUED, WorkState.CHECKPOINTED, WorkState.WAITING_CAPACITY}
    ]
    by_project: dict[str, deque[CodexWorkItem]] = {}
    for item in sorted(eligible, key=lambda candidate: (-candidate.priority, candidate.id)):
        by_project.setdefault(item.project_id, deque()).append(item)
    project_order = deque(sorted(by_project))
    allocated_by_work: dict[str, float] = {}
    allocations: list[WorkAllocation] = []
    available = spendable

    while available > 0 and project_order:
        project_id = project_order.popleft()
        queue = by_project[project_id]
        item = queue[0]
        remaining_estimate = item.estimated_quota_points - allocated_by_work.get(item.id, 0)
        allocation = min(policy.max_slice_points, remaining_estimate, available)
        if allocation > 0:
            allocations.append(
                WorkAllocation(
                    work_id=item.id,
                    project_id=item.project_id,
                    owner_thread=item.owner_thread,
                    generation=item.generation + 1,
                    allocated_quota_points=allocation,
                )
            )
            allocated_by_work[item.id] = allocated_by_work.get(item.id, 0) + allocation
            available -= allocation
        if allocated_by_work.get(item.id, 0) >= item.estimated_quota_points:
            queue.popleft()
        if queue:
            project_order.append(project_id)

    allocated_total = spendable - available
    remaining_after = remaining_points - active_reservations - allocated_total
    reason = (
        "allocated all spendable capacity while preserving reserve"
        if available == 0
        else "all queued estimated work is allocated and unused capacity remains"
    )
    return QuarkWorkPlan(
        tuple(allocations),
        remaining_points,
        active_reservations,
        guardrail_floor,
        spendable,
        remaining_after,
        reason,
    )


class QuarkWorkStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS quark_work_items (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                state TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS quark_work_slices (
                work_id TEXT NOT NULL,
                generation INTEGER NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (work_id, generation)
            );
            """
        )

    def close(self) -> None:
        self.connection.close()

    def save_work(self, item: CodexWorkItem) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO quark_work_items (id, project_id, state, payload) VALUES (?, ?, ?, ?)",
            (item.id, item.project_id, item.state.value, json.dumps(_work_payload(item), sort_keys=True)),
        )
        self.connection.commit()

    def load_work(self, work_id: str) -> CodexWorkItem:
        row = self.connection.execute(
            "SELECT payload FROM quark_work_items WHERE id = ?", (work_id,)
        ).fetchone()
        if row is None:
            raise KeyError(work_id)
        return _work_from_payload(json.loads(row["payload"]))

    def list_work(self) -> tuple[CodexWorkItem, ...]:
        rows = self.connection.execute(
            "SELECT payload FROM quark_work_items ORDER BY project_id, id"
        ).fetchall()
        return tuple(_work_from_payload(json.loads(row["payload"])) for row in rows)

    def record_slice_start(
        self,
        work_id: str,
        generation: int,
        quota_before: float,
        lifetime_tokens_before: int | None,
        observed_at: str,
    ) -> None:
        item = self.load_work(work_id)
        payload = {
            "work_id": work_id,
            "project_id": item.project_id,
            "generation": generation,
            "quota_before": quota_before,
            "quota_after": None,
            "lifetime_tokens_before": lifetime_tokens_before,
            "lifetime_tokens_after": None,
            "actual_quota_points": None,
            "actual_tokens": None,
            "started_at": observed_at,
            "checkpointed_at": None,
            "checkpoint_ref": None,
            "completed": False,
            # A scheduler reservation prevents Quark from double-booking its own
            # queue; it does not exclude other Codex clients from account usage.
            "attribution_confidence": "shared",
        }
        self.connection.execute(
            "INSERT OR REPLACE INTO quark_work_slices (work_id, generation, payload) VALUES (?, ?, ?)",
            (work_id, generation, json.dumps(payload, sort_keys=True)),
        )
        self.connection.commit()
        self.save_work(
            item.with_state(
                WorkState.RUNNING,
                generation=generation,
                updated_at=observed_at,
            )
        )

    def record_slice_checkpoint(
        self,
        work_id: str,
        generation: int,
        quota_after: float,
        lifetime_tokens_after: int | None,
        observed_at: str,
        completed: bool,
        checkpoint_ref: str | None,
    ) -> None:
        row = self.connection.execute(
            "SELECT payload FROM quark_work_slices WHERE work_id = ? AND generation = ?",
            (work_id, generation),
        ).fetchone()
        if row is None:
            raise KeyError((work_id, generation))
        payload = json.loads(row["payload"])
        payload["quota_after"] = quota_after
        payload["lifetime_tokens_after"] = lifetime_tokens_after
        payload["actual_quota_points"] = max(0.0, payload["quota_before"] - quota_after)
        before_tokens = payload.get("lifetime_tokens_before")
        payload["actual_tokens"] = (
            max(0, lifetime_tokens_after - before_tokens)
            if isinstance(before_tokens, int) and isinstance(lifetime_tokens_after, int)
            else None
        )
        payload["checkpointed_at"] = observed_at
        payload["checkpoint_ref"] = checkpoint_ref
        payload["completed"] = completed
        self.connection.execute(
            "UPDATE quark_work_slices SET payload = ? WHERE work_id = ? AND generation = ?",
            (json.dumps(payload, sort_keys=True), work_id, generation),
        )
        self.connection.commit()
        item = self.load_work(work_id)
        self.save_work(
            item.with_state(
                WorkState.COMPLETED if completed else WorkState.CHECKPOINTED,
                reserved_quota_points=0,
                checkpoint_ref=checkpoint_ref,
                pause_reason=None,
                resume_at=None,
                updated_at=observed_at,
            )
        )

    def mark_waiting_capacity(self, work_id: str, resume_at: str | None, reason: str) -> None:
        item = self.load_work(work_id)
        self.save_work(
            item.with_state(
                WorkState.WAITING_CAPACITY,
                reserved_quota_points=0,
                pause_reason=reason,
                resume_at=resume_at,
            )
        )

    def project_effort(self, project_id: str) -> dict[str, Any]:
        work = tuple(item for item in self.list_work() if item.project_id == project_id)
        rows = self.connection.execute(
            "SELECT payload FROM quark_work_slices ORDER BY work_id, generation"
        ).fetchall()
        slices = [
            json.loads(row["payload"])
            for row in rows
            if json.loads(row["payload"]).get("project_id") == project_id
        ]
        states: dict[str, int] = {}
        for item in work:
            states[item.state.value] = states.get(item.state.value, 0) + 1
        return {
            "project_id": project_id,
            "work_items": len(work),
            "estimated_quota_points": sum(item.estimated_quota_points for item in work),
            "estimated_tokens": sum(item.estimated_tokens or 0 for item in work),
            "actual_quota_points": sum(item.get("actual_quota_points") or 0 for item in slices),
            "actual_tokens": sum(item.get("actual_tokens") or 0 for item in slices),
            "completed_slices": sum(1 for item in slices if item.get("checkpointed_at")),
            "work_states": states,
            "attribution": sorted({item.get("attribution_confidence", "unknown") for item in slices}),
        }


class CodexExecSliceAdapter:
    """Run one resumable noninteractive Codex turn as a natural checkpoint."""

    def __init__(self, codex_path: str = "codex", runner=subprocess.run):
        self.codex_path = codex_path
        self.runner = runner

    def run_slice(
        self,
        item: CodexWorkItem,
        allocated_quota_points: float,
        prompt: str,
    ) -> dict[str, Any]:
        completed = self.runner(
            [
                self.codex_path,
                "exec",
                "resume",
                item.owner_thread,
                prompt,
                "--json",
            ],
            text=True,
            capture_output=True,
        )
        output = completed.stdout or ""
        work_completed = "QUARK_WORK_COMPLETED" in output
        checkpoint_ref = None
        for line in output.splitlines():
            if "QUARK_CHECKPOINT:" in line:
                checkpoint_ref = line.split("QUARK_CHECKPOINT:", 1)[1].strip().strip('"')
        return {
            "status": "completed" if work_completed else "checkpointed",
            "completed": work_completed,
            "checkpoint_ref": checkpoint_ref,
            "exit_code": completed.returncode,
            "stdout": output,
            "stderr": completed.stderr or "",
            "allocated_quota_points": allocated_quota_points,
        }


class QuarkSchedulerService:
    """Plan and optionally execute one usage-bounded scheduling cycle."""

    def __init__(
        self,
        store: QuarkWorkStore,
        usage_source: Any,
        executor: Any,
        policy: QuarkUsagePolicy | None = None,
    ):
        self.store = store
        self.usage_source = usage_source
        self.executor = executor
        self.policy = policy or QuarkUsagePolicy()

    def run_cycle(self, execute: bool = False, limit_id: str = "codex") -> dict[str, Any]:
        before = self.usage_source.refresh()
        window = _usage_window(before, limit_id)
        work = tuple(item for item in self.store.list_work() if item.limit_id == limit_id)
        plan = plan_quark_work(self.policy, window["remaining_percent"], work)
        if not plan.allocations:
            for item in work:
                if item.state in {
                    WorkState.QUEUED,
                    WorkState.CHECKPOINTED,
                    WorkState.WAITING_CAPACITY,
                }:
                    self.store.mark_waiting_capacity(
                        item.id,
                        resume_at=window.get("resets_at"),
                        reason=plan.reason,
                    )
            return {
                "planned": 0,
                "executed": 0,
                "plan": _plan_payload(plan),
                "resume_at": window.get("resets_at"),
                "reason": plan.reason,
            }

        selected = plan.allocations[: self.policy.max_concurrent_work]
        if not execute:
            return {
                "planned": len(selected),
                "executed": 0,
                "allocations": [asdict(item) for item in selected],
                "plan": _plan_payload(plan),
                "reason": "dry-run plan; no Codex work was started",
            }

        results = []
        for allocation in selected:
            item = self.store.load_work(allocation.work_id)
            started_at = before.get("observed_at") or _timestamp()
            reserved = item.with_state(
                WorkState.RUNNING,
                reserved_quota_points=allocation.allocated_quota_points,
                generation=allocation.generation,
                updated_at=started_at,
            )
            self.store.save_work(reserved)
            self.store.record_slice_start(
                item.id,
                allocation.generation,
                quota_before=window["remaining_percent"],
                lifetime_tokens_before=_lifetime_tokens(before),
                observed_at=started_at,
            )
            prompt = _checkpoint_prompt(item, allocation)
            result = self.executor.run_slice(
                item,
                allocation.allocated_quota_points,
                prompt,
            )
            after = self.usage_source.refresh()
            after_window = _usage_window(after, limit_id)
            if result.get("exit_code") not in (None, 0):
                failed = self.store.load_work(item.id).with_state(
                    WorkState.RECONCILE_REQUIRED,
                    reserved_quota_points=0,
                    pause_reason="Codex slice failed or was interrupted; reconcile workspace before resuming",
                    updated_at=after.get("observed_at") or _timestamp(),
                )
                self.store.save_work(failed)
            else:
                self.store.record_slice_checkpoint(
                    work_id=item.id,
                    generation=allocation.generation,
                    quota_after=after_window["remaining_percent"],
                    lifetime_tokens_after=_lifetime_tokens(after),
                    observed_at=after.get("observed_at") or _timestamp(),
                    completed=bool(result.get("completed")),
                    checkpoint_ref=result.get("checkpoint_ref"),
                )
            results.append(
                {
                    "work_id": item.id,
                    "generation": allocation.generation,
                    "allocated_quota_points": allocation.allocated_quota_points,
                    "status": result.get("status"),
                    "exit_code": result.get("exit_code"),
                    "checkpoint_ref": result.get("checkpoint_ref"),
                }
            )
        return {
            "planned": len(selected),
            "executed": len(results),
            "results": results,
            "plan": _plan_payload(plan),
            "reason": "bounded Codex slices reached a natural turn checkpoint",
        }


def _work_payload(item: CodexWorkItem) -> dict[str, Any]:
    payload = asdict(item)
    payload["state"] = item.state.value
    return payload


def _work_from_payload(payload: dict[str, Any]) -> CodexWorkItem:
    payload["state"] = WorkState(payload["state"])
    return CodexWorkItem(**payload)


def _usage_window(snapshot: dict[str, Any], limit_id: str) -> dict[str, Any]:
    for limit in snapshot.get("rate_limits", []):
        if limit.get("limit_id") != limit_id:
            continue
        for window in limit.get("windows", []):
            if window.get("name") == "primary" and isinstance(window.get("remaining_percent"), (int, float)):
                return window
    raise ValueError(f"usage snapshot does not include a primary window for {limit_id}")


def _lifetime_tokens(snapshot: dict[str, Any]) -> int | None:
    value = snapshot.get("account_usage", {}).get("lifetime_tokens")
    return value if isinstance(value, int) else None


def _checkpoint_prompt(item: CodexWorkItem, allocation: WorkAllocation) -> str:
    return (
        f"Quark work slice {item.id} generation {allocation.generation}. "
        f"Continue this durable project work: {item.intent}. "
        "Work only through one bounded, coherent step. Before ending, create a durable checkpoint "
        "(commit when appropriate, otherwise preserve a clean status and exact next action). "
        "End with `QUARK_CHECKPOINT: <reference>` when more work remains, or "
        "`QUARK_WORK_COMPLETED` when the requested work is genuinely finished. "
        "Do not start another broad step after the checkpoint."
    )


def _plan_payload(plan: QuarkWorkPlan) -> dict[str, Any]:
    payload = asdict(plan)
    payload["allocations"] = [asdict(item) for item in plan.allocations]
    return payload


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()
