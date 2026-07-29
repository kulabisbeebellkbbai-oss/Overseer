from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from overseer.quark_scheduler import (
    AgentWorkItem,
    CodexExecSliceAdapter,
    CodexWorkItem,
    ProviderWorkExecutor,
    QuarkSchedulerService,
    QuarkUsagePolicy,
    QuarkWorkStore,
    WorkState,
    plan_quark_work,
)
from overseer.quark_scheduler_cli import build_parser


def _agent_work(
    work_id: str,
    project: str,
    provider_id: str,
    limit_id: str,
    estimate: float,
    *,
    usage_unit: str = "native_units",
) -> AgentWorkItem:
    return AgentWorkItem(
        id=work_id,
        project_id=project,
        agent_session_id=f"session.{provider_id}.{project}",
        provider_id=provider_id,
        limit_id=limit_id,
        intent=f"continue {project}",
        estimated_units=estimate,
        usage_unit=usage_unit,
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


def test_mixed_provider_work_keeps_native_limit_ids():
    work = (
        _agent_work("work.codex", "project-a", "codex", "limit.codex.points", 5),
        _agent_work(
            "work.claude",
            "project-b",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
    )

    plan = plan_quark_work(
        QuarkUsagePolicy(),
        {"limit.codex.points": 20, "limit.claude.tokens": 30},
        work,
    )

    assert {row.limit_id for row in plan.allocations} == {
        "limit.codex.points",
        "limit.claude.tokens",
    }
    assert {
        row.limit_id: row.usage_unit for row in plan.allocations
    } == {
        "limit.codex.points": "native_units",
        "limit.claude.tokens": "tokens",
    }


def test_unknown_provider_capacity_uses_conservative_policy():
    plan = plan_quark_work(
        QuarkUsagePolicy(),
        {"limit.claude.tokens": None},
        (
            _agent_work(
                "work.1",
                "project-a",
                "claude",
                "limit.claude.tokens",
                8,
                usage_unit="tokens",
            ),
        ),
    )

    assert plan.allocations == ()
    assert "unknown capacity" in plan.reason


def test_missing_provider_capacity_uses_conservative_policy():
    plan = plan_quark_work(
        QuarkUsagePolicy(),
        {},
        (
            _agent_work(
                "work.1",
                "project-a",
                "claude",
                "limit.claude.tokens",
                8,
                usage_unit="tokens",
            ),
        ),
    )

    assert plan.allocations == ()
    assert "unknown capacity" in plan.reason


def test_compatibility_names_alias_provider_neutral_scheduler_types():
    assert CodexWorkItem is AgentWorkItem
    assert CodexExecSliceAdapter is ProviderWorkExecutor


def test_codex_work_item_preserves_legacy_positional_constructor():
    item = CodexWorkItem(
        "work.legacy",
        "project-a",
        "thread-project-a",
        "codex",
        "continue project-a",
        5,
    )

    assert item.owner_thread == "thread-project-a"
    assert item.agent_session_id is None
    assert item.limit_id == "codex"
    assert item.intent == "continue project-a"
    assert item.estimated_quota_points == 5


def test_provider_executor_recovers_and_dispatches_through_agent_manager():
    class FakeAgentManager:
        def __init__(self):
            self.calls = []

        def recover(self, session_id, initiated_by="system"):
            self.calls.append(("recover", session_id, initiated_by))
            return SimpleNamespace(
                id="epoch.claude.1",
                instance_id="agent.claude.1",
                provider_id="claude",
            )

        def dispatch(
            self,
            instance_id,
            prompt,
            idempotency_key,
            requested_by=None,
        ):
            self.calls.append(
                (
                    "dispatch",
                    instance_id,
                    prompt,
                    idempotency_key,
                    requested_by,
                )
            )
            return SimpleNamespace(state=SimpleNamespace(value="running"))

    manager = FakeAgentManager()
    executor = ProviderWorkExecutor(manager)
    item = _agent_work(
        "work.1",
        "project-a",
        "claude",
        "limit.claude.tokens",
        8,
        usage_unit="tokens",
    )

    result = executor.run_slice(item, 5, "checkpoint prompt")

    assert manager.calls == [
        ("recover", "session.claude.project-a", "quark"),
        (
            "dispatch",
            "agent.claude.1",
            "checkpoint prompt",
            "quark:work.1:1",
            "quark",
        ),
    ]
    assert result["provider_id"] == "claude"
    assert result["usage_unit"] == "tokens"


def test_scheduler_cli_accepts_provider_native_work_fields():
    args = build_parser().parse_args(
        [
            "register-work",
            "--work-id",
            "work.claude",
            "--project-id",
            "project-a",
            "--agent-session-id",
            "session.claude.1",
            "--provider-id",
            "claude",
            "--limit-id",
            "limit.claude.tokens",
            "--intent",
            "continue implementation",
            "--estimated-units",
            "8000",
            "--usage-unit",
            "tokens",
        ]
    )

    assert args.agent_session_id == "session.claude.1"
    assert args.provider_id == "claude"
    assert args.estimated_units == 8000
    assert args.usage_unit == "tokens"


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


def _native_snapshot(limit_id: str, remaining: float | None):
    return {
        "observed_at": "2026-07-29T10:00:00+00:00",
        "rate_limits": [
            {
                "limit_id": limit_id,
                "windows": [
                    {
                        "name": "primary",
                        "remaining": remaining,
                        "usage_unit": "tokens",
                        "resets_at": "2026-08-04T13:56:35+00:00",
                    }
                ],
            }
        ],
    }


def test_cycle_plans_provider_native_capacity_without_percent_conversion(
    tmp_path: Path,
):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        _agent_work(
            "work.claude",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8000,
            usage_unit="tokens",
        )
    )
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource(
            (_native_snapshot("limit.claude.tokens", 80_000),)
        ),
        executor=FakeExecutor(),
    )

    status = service.run_cycle(
        execute=False,
        limit_id="limit.claude.tokens",
    )

    assert status["allocations"][0]["limit_id"] == "limit.claude.tokens"
    assert status["allocations"][0]["usage_unit"] == "tokens"
    assert status["plan"]["remaining_before_plan"] == {
        "limit.claude.tokens": 80_000
    }


def test_cycle_blocks_unknown_provider_native_capacity(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        _agent_work(
            "work.claude",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8000,
            usage_unit="tokens",
        )
    )
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource(
            (_native_snapshot("limit.claude.tokens", None),)
        ),
        executor=FakeExecutor(),
    )

    status = service.run_cycle(
        execute=False,
        limit_id="limit.claude.tokens",
    )

    assert status["planned"] == 0
    assert "unknown capacity" in status["reason"]


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


def test_codex_exec_adapter_preserves_legacy_positional_constructor():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))

        class Result:
            returncode = 0
            stdout = '{"type":"turn.completed"}\n'
            stderr = ""

        return Result()

    adapter = CodexExecSliceAdapter("/opt/codex", runner)
    adapter.run_slice(_work("a1", "alpha", 8), 5, "checkpoint prompt")

    assert calls[0][0][0] == "/opt/codex"
