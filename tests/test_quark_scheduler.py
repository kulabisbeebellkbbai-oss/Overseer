from __future__ import annotations

from pathlib import Path

from overseer.quark_scheduler import (
    CodexExecSliceAdapter,
    CodexWorkItem,
    QuarkSchedulerService,
    QuarkUsagePolicy,
    QuarkWorkStore,
    WorkState,
    plan_quark_work,
)


def _work(work_id: str, project: str, estimate: float, priority: int = 50) -> CodexWorkItem:
    return CodexWorkItem(
        id=work_id,
        project_id=project,
        owner_thread=f"thread-{project}",
        limit_id="codex",
        intent=f"continue {project}",
        estimated_quota_points=estimate,
        priority=priority,
    )


def test_planner_preserves_reserve_without_stranding_spendable_capacity():
    policy = QuarkUsagePolicy(hard_reserve_points=15, uncertainty_points=0, max_slice_points=30)
    plan = plan_quark_work(
        policy,
        remaining_points=100,
        work=(
            _work("a1", "alpha", 60),
            _work("b1", "beta", 60),
        ),
    )

    assert sum(item.allocated_quota_points for item in plan.allocations) == 85
    assert plan.remaining_after_plan == 15
    assert {item.project_id for item in plan.allocations[:2]} == {"alpha", "beta"}
    assert plan.reason == "allocated all spendable capacity while preserving reserve"


def test_planner_pauses_when_only_guardrail_reserve_remains():
    policy = QuarkUsagePolicy(hard_reserve_points=15, uncertainty_points=2, max_slice_points=5)
    plan = plan_quark_work(policy, remaining_points=17, work=(_work("a1", "alpha", 10),))

    assert plan.allocations == ()
    assert plan.remaining_after_plan == 17
    assert plan.reason == "capacity is at the reserve and uncertainty floor"


def test_planner_accounts_for_active_reservations_atomically():
    policy = QuarkUsagePolicy(hard_reserve_points=15, uncertainty_points=2, max_slice_points=10)
    running = _work("running", "alpha", 10)
    running = running.with_state(WorkState.RUNNING, reserved_quota_points=8)
    plan = plan_quark_work(
        policy,
        remaining_points=40,
        work=(running, _work("queued", "beta", 30)),
    )

    assert sum(item.allocated_quota_points for item in plan.allocations) == 15
    assert plan.active_reservations == 8
    assert plan.remaining_after_plan == 17


def test_store_tracks_project_estimates_and_actual_effort(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("a1", "alpha", 8))
    store.record_slice_start(
        work_id="a1",
        generation=1,
        quota_before=80,
        lifetime_tokens_before=1_000,
        observed_at="2026-07-29T10:00:00+00:00",
    )
    store.record_slice_checkpoint(
        work_id="a1",
        generation=1,
        quota_after=77,
        lifetime_tokens_after=1_600,
        observed_at="2026-07-29T10:20:00+00:00",
        completed=False,
        checkpoint_ref="commit:abc123",
    )

    summary = store.project_effort("alpha")

    assert summary["estimated_quota_points"] == 8
    assert summary["actual_quota_points"] == 3
    assert summary["actual_tokens"] == 600
    assert summary["completed_slices"] == 1
    assert summary["work_states"] == {"checkpointed": 1}
    assert summary["attribution"] == ["shared"]


def test_checkpointed_work_becomes_waiting_when_capacity_is_below_floor(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("a1", "alpha", 8))
    store.mark_waiting_capacity(
        "a1",
        resume_at="2026-08-04T13:56:35+00:00",
        reason="reserve floor reached",
    )

    item = store.load_work("a1")

    assert item.state is WorkState.WAITING_CAPACITY
    assert item.resume_at == "2026-08-04T13:56:35+00:00"
    assert item.pause_reason == "reserve floor reached"


class FakeUsageSource:
    def __init__(self, snapshots):
        self.snapshots = iter(snapshots)

    def refresh(self):
        return next(self.snapshots)


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def run_slice(self, item, allocation, prompt):
        self.calls.append((item, allocation, prompt))
        return {
            "status": "checkpointed",
            "checkpoint_ref": "commit:def456",
            "completed": False,
            "exit_code": 0,
        }


def _snapshot(remaining: float, lifetime_tokens: int):
    return {
        "observed_at": "2026-07-29T10:00:00+00:00",
        "rate_limits": [
            {
                "limit_id": "codex",
                "windows": [
                    {
                        "name": "primary",
                        "remaining_percent": remaining,
                        "resets_at": "2026-08-04T13:56:35+00:00",
                    }
                ],
            }
        ],
        "account_usage": {"lifetime_tokens": lifetime_tokens},
    }


def test_cycle_runs_one_bounded_slice_and_reconciles_usage(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("a1", "alpha", 8))
    executor = FakeExecutor()
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource((_snapshot(84, 1_000), _snapshot(82, 1_600))),
        executor=executor,
    )

    status = service.run_cycle(execute=True)

    assert status["executed"] == 1
    assert "a1" in executor.calls[0][2]
    assert "durable checkpoint" in executor.calls[0][2]
    assert store.load_work("a1").state is WorkState.CHECKPOINTED
    assert store.project_effort("alpha")["actual_quota_points"] == 2
    assert store.project_effort("alpha")["actual_tokens"] == 600
    assert store.project_effort("alpha")["attribution"] == ["shared"]


def test_cycle_marks_queue_waiting_when_reserve_floor_is_reached(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("a1", "alpha", 8))
    executor = FakeExecutor()
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource((_snapshot(17, 1_000),)),
        executor=executor,
    )

    status = service.run_cycle(execute=True)

    assert status["executed"] == 0
    assert executor.calls == []
    assert store.load_work("a1").state is WorkState.WAITING_CAPACITY
    assert store.load_work("a1").resume_at == "2026-08-04T13:56:35+00:00"


def test_codex_exec_adapter_uses_resumable_bounded_turn():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))

        class Result:
            returncode = 0
            stdout = '{"type":"turn.completed"}\n'
            stderr = ""

        return Result()

    adapter = CodexExecSliceAdapter(codex_path="/opt/codex", runner=runner)
    result = adapter.run_slice(_work("a1", "alpha", 8), 5, "checkpoint prompt")

    assert calls[0][0] == [
        "/opt/codex",
        "exec",
        "resume",
        "thread-alpha",
        "checkpoint prompt",
        "--json",
    ]
    assert result["status"] == "checkpointed"
    assert result["completed"] is False
