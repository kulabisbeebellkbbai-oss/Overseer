"""Provider-native, usage-aware checkpointed work scheduling for Quark."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from collections import deque
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping

from .agent_contracts import AgentOperationState


class WorkState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CHECKPOINTED = "checkpointed"
    WAITING_CAPACITY = "waiting_capacity"
    COMPLETED = "completed"
    BLOCKED = "blocked"
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


@dataclass(frozen=True, init=False)
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
    provider_dispatch_id: str | None = None
    provider_result_id: str | None = None
    provider_reference: str | None = None
    provider_idempotency_key: str | None = None
    provider_dispatch_state: str | None = None
    # Compatibility fields for the existing Codex usage MCP and persisted rows.
    estimated_quota_points: float | None = None
    estimated_tokens: int | None = None
    reserved_quota_points: float | None = None

    def __init__(
        self,
        id: str,
        project_id: str,
        owner_thread: str | None = None,
        limit_id: str = "codex",
        intent: str = "",
        estimated_quota_points: float | None = None,
        estimated_tokens: int | None = None,
        priority: int = 50,
        state: WorkState = WorkState.QUEUED,
        reserved_quota_points: float | None = 0,
        generation: int = 0,
        checkpoint_ref: str | None = None,
        pause_reason: str | None = None,
        resume_at: str | None = None,
        created_at: str | None = None,
        updated_at: str | None = None,
        *,
        agent_session_id: str | None = None,
        provider_id: str = "codex",
        estimated_units: float | None = None,
        usage_unit: str = "quota_points",
        reserved_units: float | None = None,
        driver_epoch_id: str | None = None,
        provider_dispatch_id: str | None = None,
        provider_result_id: str | None = None,
        provider_reference: str | None = None,
        provider_idempotency_key: str | None = None,
        provider_dispatch_state: str | None = None,
    ) -> None:
        estimate = estimated_units if estimated_units is not None else estimated_quota_points
        reserved = (
            reserved_units
            if reserved_units is not None
            else (reserved_quota_points or 0)
        )
        if not id.strip() or not project_id.strip():
            raise ValueError("work id and project id are required")
        if not provider_id.strip() or not limit_id.strip():
            raise ValueError("provider id and limit id are required")
        if not usage_unit.strip():
            raise ValueError("usage unit is required")
        if not (agent_session_id or owner_thread):
            raise ValueError("agent session id or owner thread is required")
        if estimate is None or estimate <= 0:
            raise ValueError("estimated units must be positive")
        if reserved < 0:
            raise ValueError("reserved units cannot be negative")
        if priority < 0 or priority > 100:
            raise ValueError("priority must be between 0 and 100")
        values = {
            "id": id,
            "project_id": project_id,
            "agent_session_id": agent_session_id,
            "provider_id": provider_id,
            "limit_id": limit_id,
            "intent": intent,
            "estimated_units": float(estimate),
            "usage_unit": usage_unit,
            "owner_thread": owner_thread,
            "priority": priority,
            "state": WorkState(state),
            "reserved_units": float(reserved),
            "generation": generation,
            "checkpoint_ref": checkpoint_ref,
            "driver_epoch_id": driver_epoch_id,
            "pause_reason": pause_reason,
            "resume_at": resume_at,
            "created_at": created_at,
            "updated_at": updated_at,
            "provider_dispatch_id": provider_dispatch_id,
            "provider_result_id": provider_result_id,
            "provider_reference": provider_reference,
            "provider_idempotency_key": provider_idempotency_key,
            "provider_dispatch_state": provider_dispatch_state,
            "estimated_quota_points": estimated_quota_points,
            "estimated_tokens": estimated_tokens,
            "reserved_quota_points": reserved_quota_points,
        }
        if provider_id == "codex" and usage_unit == "quota_points":
            values["estimated_quota_points"] = float(estimate)
            values["reserved_quota_points"] = float(reserved)
        for name, value in values.items():
            object.__setattr__(self, name, value)

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
            "actual_units": None,
            "capacity_confidence": "observed",
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
            "provider_dispatch_id": item.provider_dispatch_id,
            "provider_result_id": item.provider_result_id,
            "provider_reference": item.provider_reference,
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
        payload["capacity_confidence"] = "observed"
        payload["lifetime_tokens_after"] = lifetime_tokens_after
        payload["actual_units"] = max(
            0.0, payload["quota_before"] - quota_after
        )
        payload["actual_quota_points"] = (
            payload["actual_units"]
            if payload.get("provider_id", "codex") == "codex"
            and payload.get("usage_unit", "quota_points") == "quota_points"
            else None
        )
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

    def record_slice_observation(
        self,
        work_id: str,
        generation: int,
        *,
        capacity_after: float | None,
        lifetime_tokens_after: int | None,
        observed_at: str,
        capacity_confidence: str,
        provider_dispatch_id: str | None = None,
        provider_result_id: str | None = None,
        provider_reference: str | None = None,
    ) -> None:
        row = self.connection.execute(
            "SELECT payload FROM quark_work_slices WHERE work_id = ? AND generation = ?",
            (work_id, generation),
        ).fetchone()
        if row is None:
            raise KeyError((work_id, generation))
        payload = json.loads(row["payload"])
        payload["quota_after"] = capacity_after
        payload["capacity_confidence"] = capacity_confidence
        payload["lifetime_tokens_after"] = lifetime_tokens_after
        payload["actual_units"] = (
            max(0.0, payload["quota_before"] - capacity_after)
            if isinstance(capacity_after, (int, float))
            else None
        )
        payload["actual_quota_points"] = (
            payload["actual_units"]
            if payload.get("provider_id", "codex") == "codex"
            and payload.get("usage_unit", "quota_points") == "quota_points"
            else None
        )
        before_tokens = payload.get("lifetime_tokens_before")
        payload["actual_tokens"] = (
            max(0, lifetime_tokens_after - before_tokens)
            if isinstance(before_tokens, int)
            and isinstance(lifetime_tokens_after, int)
            else None
        )
        payload["last_observed_at"] = observed_at
        payload["provider_dispatch_id"] = provider_dispatch_id
        payload["provider_result_id"] = provider_result_id
        payload["provider_reference"] = provider_reference
        self.connection.execute(
            "UPDATE quark_work_slices SET payload = ? "
            "WHERE work_id = ? AND generation = ?",
            (json.dumps(payload, sort_keys=True), work_id, generation),
        )
        self.connection.commit()

    def list_slices(self, work_id: str | None = None) -> tuple[dict[str, Any], ...]:
        if work_id is None:
            rows = self.connection.execute(
                "SELECT payload FROM quark_work_slices "
                "ORDER BY work_id, generation"
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT payload FROM quark_work_slices "
                "WHERE work_id = ? ORDER BY generation",
                (work_id,),
            ).fetchall()
        return tuple(json.loads(row["payload"]) for row in rows)

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
        estimated_units_by_limit = {
            limit_id: sum(
                item.estimated_units
                for item in work
                if item.limit_id == limit_id
            )
            for limit_id in sorted({item.limit_id for item in work})
        }
        actual_units_by_limit = {
            limit_id: sum(
                item.get("actual_units")
                if item.get("actual_units") is not None
                else item.get("actual_quota_points") or 0
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
        estimated_units_by_provider = {
            provider_id: sum(
                item.estimated_units
                for item in work
                if item.provider_id == provider_id
            )
            for provider_id in sorted({item.provider_id for item in work})
        }
        actual_units_by_provider = {
            provider_id: sum(
                item.get("actual_units")
                if item.get("actual_units") is not None
                else item.get("actual_quota_points") or 0
                for item in slices
                if item.get("provider_id", "codex") == provider_id
            )
            for provider_id in sorted(
                {str(item.get("provider_id", "codex")) for item in slices}
            )
        }
        estimated_tokens_by_limit = {
            limit_id: sum(
                item.estimated_tokens or 0
                for item in work
                if item.limit_id == limit_id
            )
            for limit_id in sorted({item.limit_id for item in work})
        }
        estimated_tokens_by_provider = {
            provider_id: sum(
                item.estimated_tokens or 0
                for item in work
                if item.provider_id == provider_id
            )
            for provider_id in sorted({item.provider_id for item in work})
        }
        actual_tokens_by_limit = {
            limit_id: sum(
                item.get("actual_tokens") or 0
                for item in slices
                if item.get("limit_id", "codex") == limit_id
            )
            for limit_id in sorted(
                {str(item.get("limit_id", "codex")) for item in slices}
            )
        }
        actual_tokens_by_provider = {
            provider_id: sum(
                item.get("actual_tokens") or 0
                for item in slices
                if item.get("provider_id", "codex") == provider_id
            )
            for provider_id in sorted(
                {str(item.get("provider_id", "codex")) for item in slices}
            )
        }
        legacy_codex_only = bool(work) and all(
            item.agent_session_id is None
            and item.provider_id == "codex"
            and item.usage_unit == "quota_points"
            for item in work
        )
        return {
            "project_id": project_id,
            "work_items": len(work),
            "estimated_by_limit": estimated_units_by_limit,
            "actual_by_limit": actual_units_by_limit,
            "estimated_units_by_limit": estimated_units_by_limit,
            "actual_units_by_limit": actual_units_by_limit,
            "estimated_units_by_provider": estimated_units_by_provider,
            "actual_units_by_provider": actual_units_by_provider,
            "estimated_tokens_by_limit": estimated_tokens_by_limit,
            "actual_tokens_by_limit": actual_tokens_by_limit,
            "estimated_tokens_by_provider": estimated_tokens_by_provider,
            "actual_tokens_by_provider": actual_tokens_by_provider,
            "estimated_quota_points": (
                sum(item.estimated_units for item in work)
                if legacy_codex_only
                else None
            ),
            "estimated_tokens": (
                sum(item.estimated_tokens or 0 for item in work)
                if legacy_codex_only
                else None
            ),
            "actual_quota_points": (
                sum(item.get("actual_quota_points") or 0 for item in slices)
                if legacy_codex_only
                else None
            ),
            "actual_tokens": (
                sum(item.get("actual_tokens") or 0 for item in slices)
                if legacy_codex_only
                else None
            ),
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
            return self._provider_result(
                item,
                epoch,
                result,
                allocated_quota_points,
                f"quark:{item.id}:{item.generation + 1}",
            )
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
            "terminal": True,
            "successful": completed.returncode == 0,
            "checkpoint_ref": checkpoint_ref,
            "exit_code": completed.returncode,
            "stdout": output,
            "stderr": completed.stderr or "",
            "allocated_quota_points": allocated_quota_points,
        }

    def reconcile_slice(
        self,
        item: AgentWorkItem,
        prompt: str,
    ) -> dict[str, Any]:
        if self.agent_manager is None or item.agent_session_id is None:
            raise ValueError(
                "provider reconciliation requires agent manager and session id"
            )
        if not item.provider_idempotency_key:
            raise ValueError("provider reconciliation requires idempotency key")
        epoch = self.agent_manager.recover(
            item.agent_session_id,
            initiated_by="quark",
        )
        result = self.agent_manager.dispatch(
            epoch.instance_id,
            prompt,
            item.provider_idempotency_key,
            requested_by="quark",
        )
        return self._provider_result(
            item,
            epoch,
            result,
            item.reserved_units,
            item.provider_idempotency_key,
        )

    @staticmethod
    def _provider_result(
        item: AgentWorkItem,
        epoch: Any,
        result: Any,
        allocated_units: float,
        idempotency_key: str,
    ) -> dict[str, Any]:
        state = AgentOperationState(
            getattr(result.state, "value", str(result.state))
        )
        terminal = state in {
            AgentOperationState.SUCCEEDED,
            AgentOperationState.FAILED,
            AgentOperationState.BLOCKED,
            AgentOperationState.CANCELLED,
            AgentOperationState.QUARANTINED,
        }
        successful = state is AgentOperationState.SUCCEEDED
        return {
            "status": state.value,
            "completed": successful,
            "terminal": terminal,
            "successful": successful,
            "checkpoint_ref": getattr(result, "provider_reference", None),
            "exit_code": 0 if successful else (1 if terminal else None),
            "allocated_units": allocated_units,
            "usage_unit": item.usage_unit,
            "provider_id": item.provider_id,
            "driver_epoch_id": epoch.id,
            "provider_dispatch_id": getattr(result, "request_id", None),
            "provider_result_id": getattr(result, "id", None),
            "provider_reference": getattr(
                result, "provider_reference", None
            ),
            "idempotency_key": idempotency_key,
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
        reconcile_results: list[dict[str, Any]] = []
        if execute and hasattr(self.executor, "reconcile_slice"):
            for running in tuple(
                item
                for item in work
                if item.state is WorkState.RUNNING
                and item.agent_session_id is not None
                and item.provider_dispatch_id is not None
            ):
                result = self.executor.reconcile_slice(
                    running,
                    _checkpoint_prompt(
                        running,
                        WorkAllocation(
                            work_id=running.id,
                            project_id=running.project_id,
                            agent_session_id=running.agent_session_id,
                            provider_id=running.provider_id,
                            limit_id=running.limit_id,
                            usage_unit=running.usage_unit,
                            owner_thread=running.owner_thread,
                            generation=running.generation,
                            allocated_units=running.reserved_units,
                        ),
                    ),
                )
                reconcile_results.append(
                    self._persist_execution_result(
                        running,
                        result,
                        capacity_after=remaining_capacity,
                        snapshot=before,
                    )
                )
            work = tuple(
                item
                for item in self.store.list_work()
                if item.limit_id == limit_id
            )
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
                "reconciled": len(reconcile_results),
                "reconcile_results": reconcile_results,
                "plan": _plan_payload(plan),
                "resume_at": window.get("resets_at"),
                "reason": plan.reason,
            }

        selected = plan.allocations[: self.policy.max_concurrent_work]
        if not execute:
            return {
                "planned": len(selected),
                "executed": 0,
                "reconciled": len(reconcile_results),
                "reconcile_results": reconcile_results,
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
            results.append(
                self._persist_execution_result(
                    self.store.load_work(item.id),
                    result,
                    capacity_after=after_remaining_capacity,
                    snapshot=after,
                )
            )
        return {
            "planned": len(selected),
            "executed": len(results),
            "reconciled": len(reconcile_results),
            "reconcile_results": reconcile_results,
            "results": results,
            "plan": _plan_payload(plan),
            "reason": "bounded agent slices reached a natural turn checkpoint",
        }

    def _persist_execution_result(
        self,
        item: AgentWorkItem,
        result: Mapping[str, Any],
        *,
        capacity_after: float | None,
        snapshot: Mapping[str, Any],
    ) -> dict[str, Any]:
        observed_at = str(snapshot.get("observed_at") or _timestamp())
        confidence = (
            "observed" if capacity_after is not None else "unknown"
        )
        self.store.record_slice_observation(
            item.id,
            item.generation,
            capacity_after=capacity_after,
            lifetime_tokens_after=_lifetime_tokens(dict(snapshot)),
            observed_at=observed_at,
            capacity_confidence=confidence,
            provider_dispatch_id=result.get("provider_dispatch_id"),
            provider_result_id=result.get("provider_result_id"),
            provider_reference=result.get("provider_reference"),
        )
        changes = {
            "provider_dispatch_id": result.get("provider_dispatch_id"),
            "provider_result_id": result.get("provider_result_id"),
            "provider_reference": result.get("provider_reference"),
            "provider_idempotency_key": result.get("idempotency_key"),
            "provider_dispatch_state": result.get("status"),
            "updated_at": observed_at,
        }
        terminal = bool(
            result.get(
                "terminal",
                result.get("exit_code") is not None,
            )
        )
        successful = bool(
            result.get(
                "successful",
                result.get("exit_code") in (None, 0),
            )
        )
        if not terminal:
            self.store.save_work(
                item.with_state(
                    WorkState.RUNNING,
                    **changes,
                )
            )
        elif successful and capacity_after is not None:
            self.store.save_work(item.with_state(item.state, **changes))
            self.store.record_slice_checkpoint(
                work_id=item.id,
                generation=item.generation,
                quota_after=capacity_after,
                lifetime_tokens_after=_lifetime_tokens(dict(snapshot)),
                observed_at=observed_at,
                completed=bool(result.get("completed")),
                checkpoint_ref=result.get("checkpoint_ref"),
            )
        elif successful:
            self.store.save_work(
                item.with_state(
                    WorkState.RECONCILE_REQUIRED,
                    pause_reason=(
                        "provider completed but post-dispatch capacity "
                        "is unknown; reconcile usage before resuming"
                    ),
                    **changes,
                )
            )
        else:
            target_state = (
                WorkState.BLOCKED
                if result.get("status") == AgentOperationState.BLOCKED.value
                else WorkState.RECONCILE_REQUIRED
            )
            self.store.save_work(
                item.with_state(
                    target_state,
                    reserved_units=0,
                    pause_reason=(
                        "provider dispatch ended without success: "
                        f"{result.get('status', 'unknown')}"
                    ),
                    **changes,
                )
            )
        return {
            "work_id": item.id,
            "generation": item.generation,
            "allocated_units": item.reserved_units,
            "allocated_quota_points": (
                item.reserved_units
                if item.provider_id == "codex"
                and item.usage_unit == "quota_points"
                else None
            ),
            "usage_unit": item.usage_unit,
            "provider_id": item.provider_id,
            "limit_id": item.limit_id,
            "status": result.get("status"),
            "exit_code": result.get("exit_code"),
            "checkpoint_ref": result.get("checkpoint_ref"),
            "provider_dispatch_id": result.get("provider_dispatch_id"),
            "provider_result_id": result.get("provider_result_id"),
            "provider_reference": result.get("provider_reference"),
            "capacity_confidence": confidence,
        }


def _work_payload(item: AgentWorkItem) -> dict[str, Any]:
    payload = asdict(item)
    payload["state"] = item.state.value
    return payload


def _codex_work_payload(item: AgentWorkItem) -> dict[str, Any]:
    """Exact compatibility payload for the Codex usage MCP."""
    return {
        "id": item.id,
        "project_id": item.project_id,
        "owner_thread": item.owner_thread,
        "limit_id": item.limit_id,
        "intent": item.intent,
        "estimated_quota_points": item.estimated_quota_points,
        "estimated_tokens": item.estimated_tokens,
        "priority": item.priority,
        "state": item.state.value,
        "reserved_quota_points": item.reserved_quota_points,
        "generation": item.generation,
        "checkpoint_ref": item.checkpoint_ref,
        "pause_reason": item.pause_reason,
        "resume_at": item.resume_at,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def _codex_queue_payload(
    items: tuple[AgentWorkItem, ...],
) -> dict[str, Any]:
    return {
        "items": [_codex_work_payload(item) for item in items],
        "counts": {
            state: sum(1 for item in items if item.state.value == state)
            for state in sorted({item.state.value for item in items})
        },
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


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
