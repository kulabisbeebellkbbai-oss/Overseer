from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from overseer.agent_contracts import AgentOperationState
from overseer.quark_scheduler import (
    AgentWorkItem,
    CodexExecSliceAdapter,
    CodexWorkItem,
    ProviderWorkExecutor,
    QuarkSchedulerService,
    QuarkUsagePolicy,
    QuarkWorkStore,
    WorkState,
    _codex_cycle_payload,
    _codex_project_effort_payload,
    _codex_queue_payload,
    _codex_work_payload,
    plan_quark_work,
)
from overseer.quark_scheduler_cli import build_parser
import overseer.quark_scheduler_cli as quark_scheduler_cli


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


def test_codex_work_item_preserves_eighth_legacy_positional_field():
    item = CodexWorkItem(
        "work.legacy",
        "project-a",
        "thread-project-a",
        "codex",
        "continue project-a",
        5,
        1_000,
        77,
    )

    assert item.owner_thread == "thread-project-a"
    assert item.estimated_tokens == 1_000
    assert item.priority == 77


def test_codex_work_item_preserves_full_legacy_positional_constructor():
    item = CodexWorkItem(
        "work.legacy",
        "project-a",
        "thread-project-a",
        "codex",
        "continue project-a",
        5,
        1_000,
        77,
        WorkState.CHECKPOINTED,
        2,
        3,
        "commit:abc",
        "paused",
        "2026-08-01T00:00:00+00:00",
        "2026-07-29T00:00:00+00:00",
        "2026-07-30T00:00:00+00:00",
    )

    assert item.owner_thread == "thread-project-a"
    assert item.priority == 77
    assert item.state is WorkState.CHECKPOINTED
    assert item.reserved_quota_points == 2
    assert item.generation == 3
    assert item.checkpoint_ref == "commit:abc"
    assert item.pause_reason == "paused"
    assert item.resume_at == "2026-08-01T00:00:00+00:00"
    assert item.created_at == "2026-07-29T00:00:00+00:00"
    assert item.updated_at == "2026-07-30T00:00:00+00:00"


def test_codex_mcp_work_payload_preserves_exact_legacy_shape():
    item = _work("work.legacy", "project-a", 5)

    assert _codex_work_payload(item) == {
        "id": "work.legacy",
        "project_id": "project-a",
        "owner_thread": "thread-project-a",
        "limit_id": "codex",
        "intent": "continue project-a",
        "estimated_quota_points": 5.0,
        "estimated_tokens": None,
        "priority": 50,
        "state": "queued",
        "reserved_quota_points": 0.0,
        "generation": 0,
        "checkpoint_ref": None,
        "pause_reason": None,
        "resume_at": None,
        "created_at": None,
        "updated_at": None,
    }


def test_codex_mcp_queue_payload_preserves_exact_legacy_shape():
    item = _work("work.legacy", "project-a", 5)

    assert _codex_queue_payload((item,)) == {
        "items": [_codex_work_payload(item)],
        "counts": {"queued": 1},
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def test_provider_executor_recovers_and_dispatches_through_agent_manager():
    class FakeAgentManager:
        def __init__(self):
            self.calls = []
            self.store = SimpleNamespace(
                load_agent_session=lambda session_id: SimpleNamespace(
                    id=session_id,
                    provider_id="claude",
                )
            )

        def recover(self, session_id, initiated_by="system"):
            self.calls.append(("recover", session_id, initiated_by))
            return SimpleNamespace(
                id="epoch.claude.1",
                instance_id="agent.claude.1",
                session_id=session_id,
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
            return SimpleNamespace(
                state=SimpleNamespace(value="running"),
                provider_id="claude",
                session_id="session.claude.project-a",
                driver_epoch_id="epoch.claude.1",
            )

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


def test_provider_executor_preserves_nonterminal_acknowledgement():
    class FakeAgentManager:
        def __init__(self):
            self.store = SimpleNamespace(
                load_agent_session=lambda session_id: SimpleNamespace(
                    id=session_id,
                    provider_id="claude",
                )
            )

        def recover(self, session_id, initiated_by="system"):
            return SimpleNamespace(
                id="epoch.claude.1",
                instance_id="agent.claude.1",
                session_id=session_id,
                provider_id="claude",
            )

        def dispatch(self, *args, **kwargs):
            return SimpleNamespace(
                id="result.claude.1",
                request_id="dispatch.claude.1",
                provider_reference="provider-job-1",
                provider_id="claude",
                session_id="session.claude.project-a",
                driver_epoch_id="epoch.claude.1",
                state=AgentOperationState.ACKNOWLEDGED,
            )

    result = ProviderWorkExecutor(FakeAgentManager()).run_slice(
        _agent_work(
            "work.1",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
        5,
        "checkpoint prompt",
    )

    assert result["terminal"] is False
    assert result["successful"] is False
    assert result["exit_code"] is None
    assert result["provider_dispatch_id"] == "dispatch.claude.1"
    assert result["provider_result_id"] == "result.claude.1"
    assert result["provider_reference"] == "provider-job-1"


def test_provider_executor_reconcile_blocks_persisted_session_provider_mismatch():
    class FakeAgentManager:
        def __init__(self):
            self.calls = []
            self.store = SimpleNamespace(
                load_agent_session=lambda _session_id: SimpleNamespace(
                    id="session.claude.project-a",
                    provider_id="codex",
                )
            )

        def recover(self, *args, **kwargs):
            self.calls.append(("recover", args, kwargs))

        def dispatch(self, *args, **kwargs):
            self.calls.append(("dispatch", args, kwargs))

    manager = FakeAgentManager()
    item = replace(
        _agent_work(
            "work.1",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
        state=WorkState.RUNNING,
        generation=1,
        reserved_units=5,
        provider_dispatch_id="dispatch.claude.1",
        provider_idempotency_key="quark:work.1:1",
    )

    result = ProviderWorkExecutor(manager).reconcile_slice(
        item,
        "checkpoint prompt",
    )

    assert result["status"] == "policy_blocked"
    assert result["terminal"] is True
    assert result["successful"] is False
    assert "persisted session provider" in result["error_reason"]
    assert manager.calls == []


def test_provider_executor_reconcile_blocks_stale_persisted_work_binding(
    tmp_path: Path,
):
    class FakeAgentManager:
        def __init__(self):
            self.calls = []
            self.store = SimpleNamespace(
                load_agent_session=lambda session_id: SimpleNamespace(
                    id=session_id,
                    provider_id="claude",
                )
            )

        def recover(self, *args, **kwargs):
            self.calls.append(("recover", args, kwargs))

        def dispatch(self, *args, **kwargs):
            self.calls.append(("dispatch", args, kwargs))

    item = replace(
        _agent_work(
            "work.1",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
        state=WorkState.RUNNING,
        generation=1,
        reserved_units=5,
        provider_dispatch_id="dispatch.claude.1",
        provider_idempotency_key="quark:work.1:1",
    )
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        replace(item, agent_session_id="session.claude.reassigned")
    )
    manager = FakeAgentManager()

    result = ProviderWorkExecutor(
        manager,
        work_store=store,
    ).reconcile_slice(item, "checkpoint prompt")

    assert result["status"] == "policy_blocked"
    assert "persisted work binding mismatch" in result["error_reason"]
    assert "agent_session_id" in result["error_reason"]
    assert manager.calls == []


def test_provider_executor_reconcile_blocks_stale_dispatch_replay(
    tmp_path: Path,
):
    class FakeAgentManager:
        def __init__(self):
            self.calls = []
            self.store = SimpleNamespace(
                load_agent_session=lambda session_id: SimpleNamespace(
                    id=session_id,
                    provider_id="claude",
                )
            )

        def recover(self, session_id, initiated_by="system"):
            self.calls.append(("recover", session_id, initiated_by))
            return SimpleNamespace(
                id="epoch.claude.1",
                instance_id="agent.claude.1",
                session_id=session_id,
                provider_id="claude",
            )

        def dispatch(self, *args, **kwargs):
            self.calls.append(("dispatch", args, kwargs))

    stale = replace(
        _agent_work(
            "work.1",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
        state=WorkState.RUNNING,
        generation=1,
        reserved_units=5,
        driver_epoch_id="epoch.claude.1",
        provider_dispatch_id="dispatch.claude.1",
        provider_result_id="result.claude.1",
        provider_idempotency_key="quark:work.1:1",
    )
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        replace(
            stale,
            generation=2,
            provider_dispatch_id="dispatch.claude.2",
            provider_result_id="result.claude.2",
            provider_idempotency_key="quark:work.1:2",
        )
    )
    manager = FakeAgentManager()

    result = ProviderWorkExecutor(
        manager,
        work_store=store,
    ).reconcile_slice(stale, "checkpoint prompt")

    assert result["status"] == "policy_blocked"
    assert "persisted work binding mismatch" in result["error_reason"]
    assert manager.calls == []


def test_provider_executor_initial_dispatch_accepts_expected_generation_transition(
    tmp_path: Path,
):
    class FakeAgentManager:
        def __init__(self):
            self.store = SimpleNamespace(
                load_agent_session=lambda session_id: SimpleNamespace(
                    id=session_id,
                    provider_id="claude",
                )
            )
            self.dispatches = []

        def recover(self, session_id, initiated_by="system"):
            return SimpleNamespace(
                id="epoch.claude.1",
                instance_id="agent.claude.1",
                session_id=session_id,
                provider_id="claude",
            )

        def dispatch(self, *args, **kwargs):
            self.dispatches.append((args, kwargs))
            return SimpleNamespace(
                id="result.claude.2",
                request_id="dispatch.claude.2",
                provider_reference="provider-job-2",
                provider_id="claude",
                session_id="session.claude.project-a",
                driver_epoch_id="epoch.claude.1",
                state=AgentOperationState.ACKNOWLEDGED,
            )

    queued = replace(
        _agent_work(
            "work.1",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
        state=WorkState.CHECKPOINTED,
        generation=1,
        driver_epoch_id="epoch.claude.1",
        provider_dispatch_id="dispatch.claude.1",
        provider_result_id="result.claude.1",
        provider_reference="provider-job-1",
        provider_idempotency_key="quark:work.1:1",
        provider_dispatch_state="succeeded",
    )
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        replace(
            queued,
            state=WorkState.RUNNING,
            generation=2,
            reserved_units=5,
        )
    )
    manager = FakeAgentManager()

    result = ProviderWorkExecutor(
        manager,
        work_store=store,
    ).run_slice(queued, 5, "checkpoint prompt")

    assert result["status"] == "acknowledged"
    assert result["provider_dispatch_id"] == "dispatch.claude.2"
    assert len(manager.dispatches) == 1


def test_provider_executor_reconcile_blocks_recovered_epoch_session_mismatch():
    class FakeAgentManager:
        def __init__(self):
            self.calls = []
            self.store = SimpleNamespace(
                load_agent_session=lambda _session_id: SimpleNamespace(
                    id="session.claude.project-a",
                    provider_id="claude",
                )
            )

        def recover(self, session_id, initiated_by="system"):
            self.calls.append(("recover", session_id, initiated_by))
            return SimpleNamespace(
                id="epoch.claude.1",
                instance_id="agent.claude.1",
                session_id="session.claude.wrong",
                provider_id="claude",
            )

        def dispatch(self, *args, **kwargs):
            self.calls.append(("dispatch", args, kwargs))

    manager = FakeAgentManager()
    item = replace(
        _agent_work(
            "work.1",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
        state=WorkState.RUNNING,
        generation=1,
        reserved_units=5,
        provider_dispatch_id="dispatch.claude.1",
        provider_idempotency_key="quark:work.1:1",
    )

    result = ProviderWorkExecutor(manager).reconcile_slice(
        item,
        "checkpoint prompt",
    )

    assert result["status"] == "policy_blocked"
    assert "recovered epoch session" in result["error_reason"]
    assert [call[0] for call in manager.calls] == ["recover"]


def test_provider_executor_reconcile_rejects_mismatched_result_bindings():
    class FakeAgentManager:
        def __init__(self):
            self.store = SimpleNamespace(
                load_agent_session=lambda session_id: SimpleNamespace(
                    id=session_id,
                    provider_id="claude",
                )
            )

        def recover(self, session_id, initiated_by="system"):
            return SimpleNamespace(
                id="epoch.claude.1",
                instance_id="agent.claude.1",
                session_id=session_id,
                provider_id="claude",
            )

        def dispatch(self, *args, **kwargs):
            return SimpleNamespace(
                id="result.wrong.1",
                request_id="dispatch.wrong.1",
                provider_reference="wrong-provider-job",
                provider_id="codex",
                session_id="session.codex.wrong",
                driver_epoch_id="epoch.codex.wrong",
                state=AgentOperationState.SUCCEEDED,
            )

    item = replace(
        _agent_work(
            "work.1",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        ),
        state=WorkState.RUNNING,
        generation=1,
        reserved_units=5,
        driver_epoch_id="epoch.claude.1",
        provider_dispatch_id="dispatch.claude.1",
        provider_result_id="result.claude.1",
        provider_reference="provider-job-1",
        provider_idempotency_key="quark:work.1:1",
    )

    result = ProviderWorkExecutor(FakeAgentManager()).reconcile_slice(
        item,
        "checkpoint prompt",
    )

    assert result["status"] == "policy_blocked"
    assert "provider result binding mismatch" in result["error_reason"]
    assert result["provider_dispatch_id"] == "dispatch.claude.1"
    assert result["provider_result_id"] == "result.claude.1"
    assert result["provider_reference"] == "provider-job-1"


def test_scheduler_cli_accepts_provider_native_work_fields():
    args = build_parser().parse_args(
        [
            "register-agent-work",
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


def test_scheduler_cli_requires_explicit_usage_unit_for_generic_work(tmp_path: Path):
    args = build_parser().parse_args(
        [
            "--db",
            str(tmp_path / "quark.sqlite3"),
            "register-agent-work",
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
        ]
    )

    assert args.usage_unit is None
    with pytest.raises(ValueError, match="--usage-unit"):
        quark_scheduler_cli.run(args)


def test_scheduler_cli_preserves_legacy_codex_register_shape(tmp_path: Path):
    args = build_parser().parse_args(
        [
            "--db",
            str(tmp_path / "quark.sqlite3"),
            "register-work",
            "--work-id",
            "work.codex",
            "--project-id",
            "project-a",
            "--owner-thread",
            "thread-project-a",
            "--intent",
            "continue implementation",
            "--estimated-quota-points",
            "5",
        ]
    )

    result = quark_scheduler_cli.run(args)

    assert result == {
        "work": _codex_work_payload(
            replace(
                _work("work.codex", "project-a", 5),
                intent="continue implementation",
            )
        ),
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def test_scheduler_cli_mixed_queue_keeps_legacy_rows_exact(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    legacy = _work("work.codex", "mixed", 5)
    store.save_work(legacy)
    store.save_work(
        _agent_work(
            "work.claude",
            "mixed",
            "claude",
            "limit.claude.tokens",
            100,
            usage_unit="tokens",
        )
    )
    store.close()

    result = quark_scheduler_cli.run(
        build_parser().parse_args(
            ["--db", str(tmp_path / "quark.sqlite3"), "queue"]
        )
    )

    assert result == {
        "items": [_codex_work_payload(legacy)],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def test_scheduler_cli_agent_queue_is_separate_expanded_surface(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    generic = _agent_work(
        "work.claude",
        "mixed",
        "claude",
        "limit.claude.tokens",
        100,
        usage_unit="tokens",
    )
    store.save_work(_work("work.codex", "mixed", 5))
    store.save_work(generic)
    store.close()

    result = quark_scheduler_cli.run(
        build_parser().parse_args(
            ["--db", str(tmp_path / "quark.sqlite3"), "agent-queue"]
        )
    )

    assert result["items"] == [quark_scheduler_cli._work_payload(generic)]
    assert result["counts"] == {"queued": 1}


def test_scheduler_cli_mixed_project_effort_keeps_legacy_nine_fields(
    tmp_path: Path,
):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("work.codex", "mixed", 5))
    store.save_work(
        _agent_work(
            "work.claude",
            "mixed",
            "claude",
            "limit.claude.tokens",
            100,
            usage_unit="tokens",
        )
    )
    store.close()

    result = quark_scheduler_cli.run(
        build_parser().parse_args(
            [
                "--db",
                str(tmp_path / "quark.sqlite3"),
                "project-effort",
                "--project-id",
                "mixed",
            ]
        )
    )

    assert result == {
        "project_id": "mixed",
        "work_items": 1,
        "estimated_quota_points": 5,
        "estimated_tokens": 0,
        "actual_quota_points": 0,
        "actual_tokens": 0,
        "completed_slices": 0,
        "work_states": {"queued": 1},
        "attribution": [],
    }


def test_scheduler_cli_empty_legacy_effort_uses_numeric_zero_totals(
    tmp_path: Path,
):
    result = quark_scheduler_cli.run(
        build_parser().parse_args(
            [
                "--db",
                str(tmp_path / "quark.sqlite3"),
                "project-effort",
                "--project-id",
                "missing",
            ]
        )
    )

    assert result == {
        "project_id": "missing",
        "work_items": 0,
        "estimated_quota_points": 0,
        "estimated_tokens": 0,
        "actual_quota_points": 0,
        "actual_tokens": 0,
        "completed_slices": 0,
        "work_states": {},
        "attribution": [],
    }


def test_scheduler_cli_mixed_plan_uses_only_legacy_codex_rows(
    tmp_path: Path,
    monkeypatch,
):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("work.codex", "mixed", 5))
    store.save_work(
        _agent_work(
            "work.claude",
            "mixed",
            "claude",
            "codex",
            100,
            usage_unit="tokens",
        )
    )
    store.close()
    monkeypatch.setattr(
        quark_scheduler_cli,
        "CodexUsageTracker",
        lambda _path: FakeUsageSource((_snapshot(84, 1000),)),
    )

    result = quark_scheduler_cli.run(
        build_parser().parse_args(
            ["--db", str(tmp_path / "quark.sqlite3"), "plan"]
        )
    )

    assert result["planned"] == 1
    assert result["allocations"] == [
        {
            "work_id": "work.codex",
            "project_id": "mixed",
            "owner_thread": "thread-mixed",
            "generation": 1,
            "allocated_quota_points": 5,
        }
    ]
    assert "reconciled" not in result


def test_scheduler_cli_mixed_run_cycle_preserves_legacy_result_snapshot(
    tmp_path: Path,
    monkeypatch,
):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("work.codex", "mixed", 5))
    store.save_work(
        _agent_work(
            "work.claude",
            "mixed",
            "claude",
            "codex",
            100,
            usage_unit="tokens",
        )
    )
    store.close()
    usage = FakeUsageSource(
        (_snapshot(84, 1000), _snapshot(82, 1400))
    )
    monkeypatch.setattr(
        quark_scheduler_cli,
        "CodexUsageTracker",
        lambda _path: usage,
    )
    monkeypatch.setattr(
        quark_scheduler_cli,
        "CodexExecSliceAdapter",
        lambda: FakeExecutor(),
    )

    result = quark_scheduler_cli.run(
        build_parser().parse_args(
            ["--db", str(tmp_path / "quark.sqlite3"), "run-cycle"]
        )
    )

    assert result["planned"] == 1
    assert result["executed"] == 1
    assert result["results"] == [
        {
            "work_id": "work.codex",
            "generation": 1,
            "allocated_quota_points": 5,
            "status": "checkpointed",
            "exit_code": 0,
            "checkpoint_ref": "commit:def456",
        }
    ]
    assert "reconcile_results" not in result


def test_scheduler_cli_accepts_explicit_agent_manager_configuration():
    args = build_parser().parse_args(
        [
            "--db",
            "/tmp/quark.sqlite3",
            "agent-run-cycle",
            "--limit-id",
            "limit.claude.tokens",
            "--agent-registry",
            "/tmp/providers.json",
            "--agent-registry-local",
            "/tmp/providers.local.json",
            "--codex-projects-registry",
            "/tmp/codex-projects.csv",
        ]
    )

    assert args.agent_registry == "/tmp/providers.json"
    assert args.agent_registry_local == "/tmp/providers.local.json"
    assert args.codex_projects_registry == "/tmp/codex-projects.csv"


def test_scheduler_entrypoint_builds_manager_executor_for_generic_work(
    tmp_path: Path,
):
    manager = object()
    calls = []

    def manager_factory(
        store,
        registry_path,
        local_registry_path,
        *,
        codex_projects_registry,
    ):
        calls.append(
            (
                store.path,
                registry_path,
                local_registry_path,
                codex_projects_registry,
            )
        )
        return manager

    executor, manager_store = quark_scheduler_cli._provider_executor_for_work(
        (
            _agent_work(
                "work.claude",
                "project-a",
                "claude",
                "limit.claude.tokens",
                8,
                usage_unit="tokens",
            ),
        ),
        db_path=tmp_path / "quark.sqlite3",
        agent_registry="/tmp/providers.json",
        agent_registry_local="/tmp/providers.local.json",
        codex_projects_registry="/tmp/codex-projects.csv",
        manager_factory=manager_factory,
    )
    try:
        assert executor.agent_manager is manager
        assert calls == [
            (
                tmp_path / "quark.sqlite3",
                "/tmp/providers.json",
                "/tmp/providers.local.json",
                "/tmp/codex-projects.csv",
            )
        ]
    finally:
        manager_store.close()


def test_scheduler_entrypoint_keeps_legacy_codex_executor(tmp_path: Path):
    executor, manager_store = quark_scheduler_cli._provider_executor_for_work(
        (_work("work.codex", "project-a", 5),),
        db_path=tmp_path / "quark.sqlite3",
        agent_registry="/tmp/providers.json",
        agent_registry_local=None,
        codex_projects_registry="/tmp/codex-projects.csv",
    )

    assert executor.agent_manager is None
    assert manager_store is None


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


def test_project_effort_never_sums_mixed_provider_tokens(tmp_path: Path):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        replace(
            _agent_work(
                "work.codex",
                "mixed",
                "codex",
                "limit.codex.points",
                5,
                usage_unit="quota_points",
            ),
            estimated_tokens=100,
        )
    )
    store.save_work(
        replace(
            _agent_work(
                "work.claude",
                "mixed",
                "claude",
                "limit.claude.tokens",
                8,
                usage_unit="tokens",
            ),
            estimated_tokens=200,
        )
    )

    summary = store.project_effort("mixed")

    assert summary["estimated_tokens"] is None
    assert summary["estimated_tokens_by_limit"] == {
        "limit.claude.tokens": {"claude": {"tokens": 200}},
        "limit.codex.points": {"codex": {"quota_points": 100}},
    }
    assert summary["estimated_tokens_by_provider"] == {
        "claude": {"limit.claude.tokens": {"tokens": 200}},
        "codex": {"limit.codex.points": {"quota_points": 100}},
    }
    assert 300 not in summary.values()


def test_project_effort_keeps_native_units_in_provider_limit_unit_buckets(
    tmp_path: Path,
):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        _agent_work(
            "work.tokens",
            "mixed",
            "claude",
            "limit.claude.tokens",
            100,
            usage_unit="tokens",
        )
    )
    store.save_work(
        _agent_work(
            "work.requests",
            "mixed",
            "claude",
            "limit.claude.requests",
            5,
            usage_unit="requests",
        )
    )

    summary = store.project_effort("mixed")

    assert summary["estimated_units_by_provider"] == {
        "claude": {
            "limit.claude.requests": {"requests": 5},
            "limit.claude.tokens": {"tokens": 100},
        }
    }
    assert 105 not in summary.values()


def test_codex_project_effort_serializer_preserves_nine_field_baseline():
    expanded = {
        "project_id": "project-a",
        "work_items": 1,
        "estimated_quota_points": 5,
        "estimated_tokens": 100,
        "actual_quota_points": 2,
        "actual_tokens": 40,
        "completed_slices": 1,
        "work_states": {"checkpointed": 1},
        "attribution": ["shared"],
        "estimated_units_by_provider": {"codex": {"codex": {"quota_points": 5}}},
    }

    assert _codex_project_effort_payload(expanded) == {
        "project_id": "project-a",
        "work_items": 1,
        "estimated_quota_points": 5,
        "estimated_tokens": 100,
        "actual_quota_points": 2,
        "actual_tokens": 40,
        "completed_slices": 1,
        "work_states": {"checkpointed": 1},
        "attribution": ["shared"],
    }


def test_codex_project_effort_serializer_uses_zero_for_empty_project():
    assert _codex_project_effort_payload(
        {
            "project_id": "missing",
            "work_items": 0,
            "estimated_quota_points": None,
            "estimated_tokens": None,
            "actual_quota_points": None,
            "actual_tokens": None,
            "completed_slices": 0,
            "work_states": {},
            "attribution": [],
        }
    ) == {
        "project_id": "missing",
        "work_items": 0,
        "estimated_quota_points": 0,
        "estimated_tokens": 0,
        "actual_quota_points": 0,
        "actual_tokens": 0,
        "completed_slices": 0,
        "work_states": {},
        "attribution": [],
    }


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


def test_cycle_blocks_usage_window_unit_mismatch_before_allocation(tmp_path: Path):
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
    mismatch = _native_snapshot("limit.claude.tokens", 80_000)
    mismatch["rate_limits"][0]["windows"][0]["usage_unit"] = "requests"
    executor = FakeExecutor()
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource((mismatch,)),
        executor=executor,
    )

    status = service.run_cycle(
        execute=False,
        limit_id="limit.claude.tokens",
    )

    assert status["planned"] == 0
    assert "usage unit mismatch" in status["reason"]
    assert executor.calls == []


def test_codex_cycle_serializer_preserves_legacy_dry_plan_snapshot(
    tmp_path: Path,
):
    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(_work("a1", "alpha", 8))
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource((_snapshot(84, 1_000),)),
        executor=FakeExecutor(),
    )

    result = _codex_cycle_payload(service.run_cycle(execute=False))

    assert result == {
        "planned": 1,
        "executed": 0,
        "allocations": [
            {
                "work_id": "a1",
                "project_id": "alpha",
                "owner_thread": "thread-alpha",
                "generation": 1,
                "allocated_quota_points": 5,
            }
        ],
        "plan": {
            "allocations": [
                {
                    "work_id": "a1",
                    "project_id": "alpha",
                    "owner_thread": "thread-alpha",
                    "generation": 1,
                    "allocated_quota_points": 5,
                },
                {
                    "work_id": "a1",
                    "project_id": "alpha",
                    "owner_thread": "thread-alpha",
                    "generation": 1,
                    "allocated_quota_points": 3,
                },
            ],
            "remaining_before_plan": 84,
            "active_reservations": 0,
            "guardrail_floor": 17,
            "spendable_capacity": 67,
            "remaining_after_plan": 76,
            "reason": "all queued estimated work is allocated and unused capacity remains",
        },
        "reason": "dry-run plan; no Codex work was started",
    }


def test_cycle_keeps_nonterminal_provider_dispatch_running(tmp_path: Path):
    class NonterminalExecutor:
        def run_slice(self, item, allocation, prompt):
            return {
                "status": "acknowledged",
                "terminal": False,
                "successful": False,
                "provider_dispatch_id": "dispatch.claude.1",
                "provider_result_id": "result.claude.1",
                "provider_reference": "provider-job-1",
                "idempotency_key": "quark:work.claude:1",
                "exit_code": None,
            }

    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        _agent_work(
            "work.claude",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        )
    )
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource(
            (
                _native_snapshot("limit.claude.tokens", 80_000),
                _native_snapshot("limit.claude.tokens", 79_995),
            )
        ),
        executor=NonterminalExecutor(),
    )

    status = service.run_cycle(
        execute=True,
        limit_id="limit.claude.tokens",
    )
    item = store.load_work("work.claude")

    assert status["results"][0]["status"] == "acknowledged"
    assert item.state is WorkState.RUNNING
    assert item.reserved_units == 5
    assert item.provider_dispatch_id == "dispatch.claude.1"
    assert item.provider_reference == "provider-job-1"


def test_cycle_reconciles_nonterminal_provider_dispatch_on_later_cycle(
    tmp_path: Path,
):
    class ReconcilingExecutor:
        def __init__(self):
            self.reconciled = []

        def reconcile_slice(self, item, prompt):
            self.reconciled.append(item.provider_dispatch_id)
            return {
                "status": "succeeded",
                "terminal": True,
                "successful": True,
                "completed": True,
                "provider_dispatch_id": item.provider_dispatch_id,
                "provider_result_id": "result.claude.2",
                "provider_reference": item.provider_reference,
                "idempotency_key": item.provider_idempotency_key,
                "checkpoint_ref": "provider-job-1",
                "exit_code": 0,
            }

    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        replace(
            _agent_work(
                "work.claude",
                "project-a",
                "claude",
                "limit.claude.tokens",
                8,
                usage_unit="tokens",
            ),
            state=WorkState.RUNNING,
            reserved_units=5,
            generation=1,
            provider_dispatch_id="dispatch.claude.1",
            provider_result_id="result.claude.1",
            provider_reference="provider-job-1",
            provider_idempotency_key="quark:work.claude:1",
        )
    )
    store.record_slice_start(
        "work.claude",
        1,
        quota_before=80_000,
        lifetime_tokens_before=None,
        observed_at="2026-07-29T10:00:00+00:00",
    )
    executor = ReconcilingExecutor()
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource(
            (_native_snapshot("limit.claude.tokens", 79_995),)
        ),
        executor=executor,
    )

    status = service.run_cycle(
        execute=True,
        limit_id="limit.claude.tokens",
    )

    assert executor.reconciled == ["dispatch.claude.1"]
    assert status["reconciled"] == 1
    assert store.load_work("work.claude").state is WorkState.COMPLETED
    assert store.load_work("work.claude").reserved_units == 0


def test_cycle_persists_unknown_post_dispatch_capacity_without_crashing(
    tmp_path: Path,
):
    class SuccessfulExecutor:
        def run_slice(self, item, allocation, prompt):
            return {
                "status": "succeeded",
                "terminal": True,
                "successful": True,
                "completed": True,
                "provider_dispatch_id": "dispatch.claude.1",
                "provider_result_id": "result.claude.1",
                "provider_reference": "provider-job-1",
                "idempotency_key": "quark:work.claude:1",
                "checkpoint_ref": "provider-job-1",
                "exit_code": 0,
            }

    store = QuarkWorkStore(tmp_path / "quark.sqlite3")
    store.save_work(
        _agent_work(
            "work.claude",
            "project-a",
            "claude",
            "limit.claude.tokens",
            8,
            usage_unit="tokens",
        )
    )
    service = QuarkSchedulerService(
        store,
        usage_source=FakeUsageSource(
            (
                _native_snapshot("limit.claude.tokens", 80_000),
                _native_snapshot("limit.claude.tokens", None),
            )
        ),
        executor=SuccessfulExecutor(),
    )

    status = service.run_cycle(
        execute=True,
        limit_id="limit.claude.tokens",
    )
    item = store.load_work("work.claude")
    slices = store.list_slices("work.claude")

    assert status["results"][0]["capacity_confidence"] == "unknown"
    assert item.state is WorkState.RECONCILE_REQUIRED
    assert item.reserved_units == 5
    assert slices[0]["capacity_confidence"] == "unknown"
    assert slices[0]["actual_units"] is None

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
