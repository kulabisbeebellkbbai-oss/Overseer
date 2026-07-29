"""Provider-native, usage-aware checkpointed work scheduling for Quark."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from collections import deque
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from numbers import Real
from pathlib import Path
from typing import Any, Mapping


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
class AgentWorkItem:
    id: str
    project_id: str
    agent_session_id: str | None = None
    provider_id: str = "codex"
    limit_id: str = "codex"
    intent: str = ""
    estimated_units: float | None = None
    usage_unit: str = "quota_points"
    owner_thread: str | None = None
    priority: int = 50
    state: WorkState = WorkState.QUEUED
    reserved_units: float = 0
    generation: int = 0
    checkpoint_ref: str | None = None
    driver_epoch_id: str | None = None
    pause_reason: str | None = None
    resume_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    # Compatibility fields for the existing Codex usage MCP and persisted rows.
    estimated_quota_points: float | None = None
    estimated_tokens: int | None = None
    reserved_quota_points: float | None = None

    def __post_init__(self) -> None:
        if isinstance(self.intent, Real) and not isinstance(self.intent, bool):
            legacy_limit_id = self.provider_id
            legacy_intent = self.limit_id
            legacy_estimated_units = float(self.intent)
            legacy_estimated_tokens = (
                int(self.estimated_units)
                if isinstance(self.estimated_units, int)
                else None
            )
            object.__setattr__(self, "owner_thread", self.agent_session_id)
            object.__setattr__(self, "agent_session_id", None)
            object.__setattr__(self, "limit_id", legacy_limit_id)
            object.__setattr__(self, "provider_id", "codex")
            object.__setattr__(self, "intent", legacy_intent)
            object.__setattr__(self, "estimated_units", legacy_estimated_units)
            object.__setattr__(self, "estimated_tokens", legacy_estimated_tokens)
        estimate = (
            self.estimated_units
            if self.estimated_units is not None
            else self.estimated_quota_points
        )
        reserved = (
            self.reserved_units
            if self.reserved_quota_points is None
            else self.reserved_quota_points
        )
        if not self.id.strip() or not self.project_id.strip():
            raise ValueError("work id and project id are required")
        if not self.provider_id.strip() or not self.limit_id.strip():
            raise ValueError("provider id and limit id are required")
        if not self.usage_unit.strip():
            raise ValueError("usage unit is required")
        if not (self.agent_session_id or self.owner_thread):
            raise ValueError("agent session id or owner thread is required")
        if estimate is None or estimate <= 0:
            raise ValueError("estimated units must be positive")
        if reserved < 0:
            raise ValueError("reserved units cannot be negative")
        if self.priority < 0 or self.priority > 100:
            raise ValueError("priority must be between 0 and 100")
        object.__setattr__(self, "estimated_units", float(estimate))
        object.__setattr__(self, "reserved_units", float(reserved))
        if self.provider_id == "codex" and self.usage_unit == "quota_points":
            object.__setattr__(self, "estimated_quota_points", float(estimate))
            object.__setattr__(self, "reserved_quota_points", float(reserved))

    def with_state(self, state: WorkState, **changes: Any) -> "AgentWorkItem":
        if "reserved_quota_points" in changes and "reserved_units" not in changes:
            changes["reserved_units"] = changes["reserved_quota_points"]
        if "reserved_units" in changes and "reserved_quota_points" not in changes:
            changes["reserved_quota_points"] = (
                changes["reserved_units"]
                if self.provider_id == "codex" and self.usage_unit == "quota_points"
                else None
            )
        return replace(self, state=state, **changes)


CodexWorkItem = AgentWorkItem


@dataclass(frozen=True)
class WorkAllocation:
    work_id: str
    project_id: str
    agent_session_id: str | None
    provider_id: str
    limit_id: str
    usage_unit: str
    owner_thread: str | None
    generation: int
    allocated_units: float

    @property
    def allocated_quota_points(self) -> float:
        """Compatibility projection for Codex percentage-point callers."""
        return self.allocated_units


@dataclass(frozen=True)
class QuarkWorkPlan:
    allocations: tuple[WorkAllocation, ...]
    remaining_before_plan: float | dict[str, float | None]
    active_reservations: float | dict[str, float]
    guardrail_floor: float | dict[str, float]
    spendable_capacity: float | dict[str, float]
    remaining_after_plan: float | dict[str, float | None]
    reason: str


def plan_quark_work(
    policy: QuarkUsagePolicy,
    remaining_points: float | Mapping[str, float | None],
    work: tuple[AgentWorkItem, ...],
) -> QuarkWorkPlan:
    compatibility_scalar = not isinstance(remaining_points, Mapping)
    if compatibility_scalar:
        scalar_capacity = float(remaining_points)
        if scalar_capacity < 0 or scalar_capacity > 100:
            raise ValueError("remaining points must be between 0 and 100")
        limit_ids = {item.limit_id for item in work}
        if len(limit_ids) > 1:
            raise ValueError("mixed-provider work requires capacity by limit id")
        capacity_by_limit: dict[str, float | None] = {
            next(iter(limit_ids), "codex"): scalar_capacity
        }
    else:
        capacity_by_limit = dict(remaining_points)
        if any(
            value is not None and (not isinstance(value, (int, float)) or value < 0)
            for value in capacity_by_limit.values()
        ):
            raise ValueError("provider capacity must be non-negative or unknown")
        for item in work:
            capacity_by_limit.setdefault(item.limit_id, None)

    guardrail = policy.hard_reserve_points + policy.uncertainty_points
    active_by_limit: dict[str, float] = {}
    spendable_by_limit: dict[str, float] = {}
    remaining_after_by_limit: dict[str, float | None] = {}
    allocations: list[WorkAllocation] = []
    unknown_limit_ids: list[str] = []
    exhausted_limit_ids: list[str] = []
    unused_capacity = False

    for limit_id in sorted(capacity_by_limit):
        capacity = capacity_by_limit[limit_id]
        limit_work = tuple(item for item in work if item.limit_id == limit_id)
        active = sum(
            item.reserved_units
            for item in limit_work
            if item.state is WorkState.RUNNING
        )
        active_by_limit[limit_id] = active
        if capacity is None:
            unknown_limit_ids.append(limit_id)
            spendable_by_limit[limit_id] = 0
            remaining_after_by_limit[limit_id] = None
            continue
        spendable = max(0.0, float(capacity) - guardrail - active)
        spendable_by_limit[limit_id] = spendable
        remaining_after_by_limit[limit_id] = float(capacity)
        if spendable <= 0:
            exhausted_limit_ids.append(limit_id)
            continue

        eligible = [
            item
            for item in limit_work
            if item.state
            in {
                WorkState.QUEUED,
                WorkState.CHECKPOINTED,
                WorkState.WAITING_CAPACITY,
            }
        ]
        by_project: dict[str, deque[AgentWorkItem]] = {}
        for item in sorted(
            eligible, key=lambda candidate: (-candidate.priority, candidate.id)
        ):
            by_project.setdefault(item.project_id, deque()).append(item)
        project_order = deque(sorted(by_project))
        allocated_by_work: dict[str, float] = {}
        available = spendable

        while available > 0 and project_order:
            project_id = project_order.popleft()
            queue = by_project[project_id]
            item = queue[0]
            remaining_estimate = item.estimated_units - allocated_by_work.get(
                item.id, 0
            )
            allocation = min(
                policy.max_slice_points, remaining_estimate, available
            )
            if allocation > 0:
                allocations.append(
                    WorkAllocation(
                        work_id=item.id,
                        project_id=item.project_id,
                        agent_session_id=item.agent_session_id,
                        provider_id=item.provider_id,
                        limit_id=item.limit_id,
                        usage_unit=item.usage_unit,
                        owner_thread=item.owner_thread,
                        generation=item.generation + 1,
                        allocated_units=allocation,
                    )
                )
                allocated_by_work[item.id] = (
                    allocated_by_work.get(item.id, 0) + allocation
                )
                available -= allocation
            if allocated_by_work.get(item.id, 0) >= item.estimated_units:
                queue.popleft()
            if queue:
                project_order.append(project_id)

        allocated_total = spendable - available
        remaining_after_by_limit[limit_id] = (
            float(capacity) - active - allocated_total
        )
        unused_capacity = unused_capacity or available > 0

    if unknown_limit_ids:
        reason = (
            "unknown capacity blocks provider work for "
            + ", ".join(unknown_limit_ids)
        )
    elif not allocations and exhausted_limit_ids:
        reason = "capacity is at the reserve and uncertainty floor"
    elif unused_capacity:
        reason = "all queued estimated work is allocated and unused capacity remains"
    else:
        reason = "allocated all spendable capacity while preserving reserve"

    if compatibility_scalar:
        limit_id = next(iter(capacity_by_limit))
        return QuarkWorkPlan(
            tuple(allocations),
            float(capacity_by_limit[limit_id]),
            active_by_limit[limit_id],
            guardrail,
            spendable_by_limit[limit_id],
            remaining_after_by_limit[limit_id],
            reason,
        )
    return QuarkWorkPlan(
        tuple(allocations),
        dict(capacity_by_limit),
        active_by_limit,
        {limit_id: guardrail for limit_id in capacity_by_limit},
        spendable_by_limit,
        remaining_after_by_limit,
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

    def save_work(self, item: AgentWorkItem) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO quark_work_items (id, project_id, state, payload) VALUES (?, ?, ?, ?)",
            (item.id, item.project_id, item.state.value, json.dumps(_work_payload(item), sort_keys=True)),
        )
        self.connection.commit()

    def load_work(self, work_id: str) -> AgentWorkItem:
        row = self.connection.execute(
            "SELECT payload FROM quark_work_items WHERE id = ?", (work_id,)
        ).fetchone()
        if row is None:
            raise KeyError(work_id)
        return _work_from_payload(json.loads(row["payload"]))

    def list_work(self) -> tuple[AgentWorkItem, ...]:
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
            "provider_id": item.provider_id,
            "limit_id": item.limit_id,
            "usage_unit": item.usage_unit,
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
                reserved_units=0,
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
                reserved_units=0,
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
        estimated_by_limit = {
            limit_id: sum(
                item.estimated_units
                for item in work
                if item.limit_id == limit_id
            )
            for limit_id in sorted({item.limit_id for item in work})
        }
        actual_by_limit = {
            limit_id: sum(
                item.get("actual_quota_points") or 0
                for item in slices
                if item.get("limit_id", "codex") == limit_id
            )
            for limit_id in sorted(
                {
                    str(item.get("limit_id", "codex"))
                    for item in slices
                }
            )
        }
        codex_only = all(
            item.provider_id == "codex" and item.usage_unit == "quota_points"
            for item in work
        )
        return {
            "project_id": project_id,
            "work_items": len(work),
            "estimated_by_limit": estimated_by_limit,
            "actual_by_limit": actual_by_limit,
            "estimated_quota_points": (
                sum(item.estimated_units for item in work)
                if codex_only
                else None
            ),
            "estimated_tokens": sum(item.estimated_tokens or 0 for item in work),
            "actual_quota_points": (
                sum(item.get("actual_quota_points") or 0 for item in slices)
                if codex_only
                else None
            ),
            "actual_tokens": sum(item.get("actual_tokens") or 0 for item in slices),
            "completed_slices": sum(1 for item in slices if item.get("checkpointed_at")),
            "work_states": states,
            "attribution": sorted({item.get("attribution_confidence", "unknown") for item in slices}),
        }


class ProviderWorkExecutor:
    """Dispatch one bounded slice through AgentManager or the Codex façade."""

    def __init__(
        self,
        codex_path: object = "codex",
        runner=subprocess.run,
        *,
        agent_manager: Any | None = None,
    ):
        if not isinstance(codex_path, str):
            if agent_manager is not None:
                raise TypeError("agent manager was provided twice")
            agent_manager = codex_path
            codex_path = "codex"
        self.agent_manager = agent_manager
        self.codex_path = codex_path
        self.runner = runner

    def run_slice(
        self,
        item: AgentWorkItem,
        allocated_quota_points: float,
        prompt: str,
    ) -> dict[str, Any]:
        if self.agent_manager is not None and item.agent_session_id is not None:
            epoch = self.agent_manager.recover(
                item.agent_session_id,
                initiated_by="quark",
            )
            if epoch.provider_id != item.provider_id:
                raise ValueError("recovered provider does not match work provider")
            result = self.agent_manager.dispatch(
                epoch.instance_id,
                prompt,
                f"quark:{item.id}:{item.generation + 1}",
                requested_by="quark",
            )
            state = getattr(result.state, "value", str(result.state))
            return {
                "status": state,
                "completed": state == "succeeded",
                "checkpoint_ref": None,
                "exit_code": 0,
                "allocated_units": allocated_quota_points,
                "usage_unit": item.usage_unit,
                "provider_id": item.provider_id,
                "driver_epoch_id": epoch.id,
            }
        if not item.owner_thread:
            raise ValueError("legacy Codex execution requires owner_thread")
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


CodexExecSliceAdapter = ProviderWorkExecutor


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
        remaining_capacity = _window_remaining_capacity(window)
        codex_compatibility = limit_id == "codex" and all(
            item.provider_id == "codex" and item.usage_unit == "quota_points"
            for item in work
        )
        capacity_argument: float | Mapping[str, float | None] = (
            remaining_capacity
            if codex_compatibility and remaining_capacity is not None
            else {limit_id: remaining_capacity}
        )
        plan = plan_quark_work(self.policy, capacity_argument, work)
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
                "allocations": [_allocation_payload(item) for item in selected],
                "plan": _plan_payload(plan),
                "reason": "dry-run plan; no agent work was started",
            }

        results = []
        for allocation in selected:
            item = self.store.load_work(allocation.work_id)
            started_at = before.get("observed_at") or _timestamp()
            reserved = item.with_state(
                WorkState.RUNNING,
                reserved_units=allocation.allocated_units,
                generation=allocation.generation,
                updated_at=started_at,
            )
            self.store.save_work(reserved)
            self.store.record_slice_start(
                item.id,
                allocation.generation,
                quota_before=remaining_capacity,
                lifetime_tokens_before=_lifetime_tokens(before),
                observed_at=started_at,
            )
            prompt = _checkpoint_prompt(item, allocation)
            result = self.executor.run_slice(
                item,
                allocation.allocated_units,
                prompt,
            )
            after = self.usage_source.refresh()
            after_window = _usage_window(after, limit_id)
            after_remaining_capacity = _window_remaining_capacity(after_window)
            if result.get("exit_code") not in (None, 0):
                failed = self.store.load_work(item.id).with_state(
                    WorkState.RECONCILE_REQUIRED,
                    reserved_units=0,
                    pause_reason="agent slice failed or was interrupted; reconcile workspace before resuming",
                    updated_at=after.get("observed_at") or _timestamp(),
                )
                self.store.save_work(failed)
            else:
                self.store.record_slice_checkpoint(
                    work_id=item.id,
                    generation=allocation.generation,
                    quota_after=after_remaining_capacity,
                    lifetime_tokens_after=_lifetime_tokens(after),
                    observed_at=after.get("observed_at") or _timestamp(),
                    completed=bool(result.get("completed")),
                    checkpoint_ref=result.get("checkpoint_ref"),
                )
            results.append(
                {
                    "work_id": item.id,
                    "generation": allocation.generation,
                    "allocated_units": allocation.allocated_units,
                    "allocated_quota_points": allocation.allocated_units,
                    "usage_unit": allocation.usage_unit,
                    "provider_id": allocation.provider_id,
                    "limit_id": allocation.limit_id,
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
            "reason": "bounded agent slices reached a natural turn checkpoint",
        }


def _work_payload(item: AgentWorkItem) -> dict[str, Any]:
    payload = asdict(item)
    payload["state"] = item.state.value
    return payload


def _work_from_payload(payload: dict[str, Any]) -> AgentWorkItem:
    payload["state"] = WorkState(payload["state"])
    return AgentWorkItem(**payload)


def _usage_window(snapshot: dict[str, Any], limit_id: str) -> dict[str, Any]:
    for limit in snapshot.get("rate_limits", []):
        if limit.get("limit_id") != limit_id:
            continue
        for window in limit.get("windows", []):
            if window.get("name") == "primary":
                return window
    raise ValueError(f"usage snapshot does not include a primary window for {limit_id}")


def _window_remaining_capacity(window: Mapping[str, Any]) -> float | None:
    for key in ("remaining_units", "remaining", "remaining_percent"):
        value = window.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return None


def _lifetime_tokens(snapshot: dict[str, Any]) -> int | None:
    value = snapshot.get("account_usage", {}).get("lifetime_tokens")
    return value if isinstance(value, int) else None


def _checkpoint_prompt(item: AgentWorkItem, allocation: WorkAllocation) -> str:
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
    payload["allocations"] = [
        _allocation_payload(item) for item in plan.allocations
    ]
    return payload


def _allocation_payload(allocation: WorkAllocation) -> dict[str, Any]:
    payload = asdict(allocation)
    if (
        allocation.provider_id == "codex"
        and allocation.usage_unit == "quota_points"
    ):
        payload["allocated_quota_points"] = allocation.allocated_units
    return payload


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()
