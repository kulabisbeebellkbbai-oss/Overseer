"""CLI and timer entrypoint for Quark's checkpointed Codex work scheduler."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .codex_usage import CodexUsageTracker
from .cli import DEFAULT_AGENT_REGISTRY, _agent_manager
from .quark_scheduler import (
    AgentWorkItem,
    CodexExecSliceAdapter,
    ProviderWorkExecutor,
    QuarkSchedulerService,
    QuarkUsagePolicy,
    QuarkWorkStore,
    _codex_cycle_payload,
    _codex_project_effort_payload,
    _codex_work_payload,
    _legacy_codex_work,
    _work_payload,
)
from .store import SQLiteStore


class PersistedUsageLimitSource:
    """Read one provider-native UsageLimit from Overseer's durable store."""

    def __init__(self, db_path: str | Path, limit_id: str):
        self.db_path = Path(db_path)
        self.limit_id = limit_id

    def refresh(self) -> dict[str, Any]:
        store = SQLiteStore(self.db_path)
        try:
            try:
                limit = store.load_usage_limit(self.limit_id)
            except KeyError:
                remaining = None
                resets_at = None
                observed_at = datetime.now(UTC).isoformat()
                usage_unit = "unknown"
            else:
                remaining = limit.remaining
                resets_at = limit.resets_at
                observed_at = limit.observed_at or datetime.now(UTC).isoformat()
                usage_unit = limit.kind.value
            return {
                "observed_at": observed_at,
                "rate_limits": [
                    {
                        "limit_id": self.limit_id,
                        "windows": [
                            {
                                "name": "primary",
                                "remaining": remaining,
                                "resets_at": resets_at,
                                "usage_unit": usage_unit,
                            }
                        ],
                    }
                ],
            }
        finally:
            store.close()


def _provider_executor_for_work(
    work: tuple[AgentWorkItem, ...],
    *,
    db_path: str | Path,
    agent_registry: str | Path,
    agent_registry_local: str | Path | None,
    codex_projects_registry: str | Path,
    manager_factory: Callable[..., Any] = _agent_manager,
    work_store: QuarkWorkStore | None = None,
) -> tuple[ProviderWorkExecutor, SQLiteStore | None]:
    if not any(item.agent_session_id is not None for item in work):
        return CodexExecSliceAdapter(), None
    manager_store = SQLiteStore(db_path)
    try:
        manager = manager_factory(
            manager_store,
            agent_registry,
            agent_registry_local,
            codex_projects_registry=codex_projects_registry,
        )
    except Exception:
        manager_store.close()
        raise
    return (
        ProviderWorkExecutor(
            agent_manager=manager,
            work_store=work_store,
        ),
        manager_store,
    )


def _policy(args: argparse.Namespace) -> QuarkUsagePolicy:
    return QuarkUsagePolicy(
        hard_reserve_points=args.hard_reserve,
        uncertainty_points=args.uncertainty,
        max_slice_points=args.max_slice,
        max_concurrent_work=args.max_concurrent,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Quark usage-aware Codex work scheduler")
    parser.add_argument("--db", type=Path, default=Path("state/codex-usage.sqlite3"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register-work")
    register.add_argument("--work-id", required=True)
    register.add_argument("--project-id", required=True)
    register.add_argument("--owner-thread", required=True)
    register.add_argument("--intent", required=True)
    register.add_argument("--estimated-quota-points", required=True, type=float)
    register.add_argument("--estimated-tokens", type=int)
    register.add_argument("--priority", type=int, default=50)
    register.add_argument("--limit-id", default="codex")

    register_agent = subparsers.add_parser("register-agent-work")
    register_agent.add_argument("--work-id", required=True)
    register_agent.add_argument("--project-id", required=True)
    register_agent.add_argument("--agent-session-id", required=True)
    register_agent.add_argument("--provider-id", required=True)
    register_agent.add_argument("--intent", required=True)
    register_agent.add_argument("--estimated-units", required=True, type=float)
    register_agent.add_argument("--usage-unit")
    register_agent.add_argument("--estimated-tokens", type=int)
    register_agent.add_argument("--priority", type=int, default=50)
    register_agent.add_argument("--limit-id", required=True)

    subparsers.add_parser("queue")
    subparsers.add_parser("agent-queue")
    effort = subparsers.add_parser("project-effort")
    effort.add_argument("--project-id", required=True)
    agent_effort = subparsers.add_parser("agent-project-effort")
    agent_effort.add_argument("--project-id", required=True)

    for name in ("plan", "run-cycle", "agent-plan", "agent-run-cycle"):
        command = subparsers.add_parser(name)
        command.add_argument("--limit-id", default="codex")
        command.add_argument("--hard-reserve", type=float, default=15)
        command.add_argument("--uncertainty", type=float, default=2)
        command.add_argument("--max-slice", type=float, default=5)
        command.add_argument("--max-concurrent", type=int, default=1)
        command.add_argument(
            "--agent-registry",
            default=str(DEFAULT_AGENT_REGISTRY),
        )
        command.add_argument("--agent-registry-local")
        command.add_argument(
            "--codex-projects-registry",
            default="/home/god/.codex/codex-projects.csv",
        )
    return parser


def run(args: argparse.Namespace) -> dict:
    store = QuarkWorkStore(args.db)
    try:
        if args.command == "register-work":
            item = AgentWorkItem(
                id=args.work_id,
                project_id=args.project_id,
                provider_id="codex",
                owner_thread=args.owner_thread,
                limit_id=args.limit_id,
                intent=args.intent,
                estimated_units=args.estimated_quota_points,
                usage_unit="quota_points",
                estimated_quota_points=args.estimated_quota_points,
                estimated_tokens=args.estimated_tokens,
                priority=args.priority,
            )
            store.save_work(item)
            return {
                "work": _codex_work_payload(item),
                "mutation_performed": True,
                "host_mutation_performed": False,
            }
        if args.command == "register-agent-work":
            if not args.usage_unit:
                raise ValueError(
                    "--usage-unit is required for provider-native work"
                )
            item = AgentWorkItem(
                id=args.work_id,
                project_id=args.project_id,
                agent_session_id=args.agent_session_id,
                provider_id=args.provider_id,
                limit_id=args.limit_id,
                intent=args.intent,
                estimated_units=args.estimated_units,
                usage_unit=args.usage_unit,
                estimated_tokens=args.estimated_tokens,
                priority=args.priority,
            )
            store.save_work(item)
            return {
                "work": _work_payload(item),
                "mutation_performed": True,
                "host_mutation_performed": False,
            }
        if args.command == "queue":
            items = tuple(
                item
                for item in store.list_work()
                if _legacy_codex_work((item,))
            )
            return {
                "items": [_codex_work_payload(item) for item in items],
                "mutation_performed": False,
                "host_mutation_performed": False,
            }
        if args.command == "agent-queue":
            items = tuple(
                item
                for item in store.list_work()
                if item.agent_session_id is not None
            )
            return {
                "items": [_work_payload(item) for item in items],
                "counts": {
                    state: sum(
                        1 for item in items if item.state.value == state
                    )
                    for state in sorted(
                        {item.state.value for item in items}
                    )
                },
                "mutation_performed": False,
                "host_mutation_performed": False,
            }
        if args.command == "project-effort":
            return _codex_project_effort_payload(
                store.project_effort(
                    args.project_id,
                    work_filter=lambda item: _legacy_codex_work((item,)),
                )
            )
        if args.command == "agent-project-effort":
            return store.project_effort(
                args.project_id,
                work_filter=lambda item: item.agent_session_id is not None,
            )
        provider_native = args.command in {"agent-plan", "agent-run-cycle"}
        work_filter = (
            (lambda item: item.agent_session_id is not None)
            if provider_native
            else (lambda item: _legacy_codex_work((item,)))
        )
        work = tuple(
            item
            for item in store.list_work()
            if item.limit_id == args.limit_id and work_filter(item)
        )
        executor, manager_store = _provider_executor_for_work(
            work,
            db_path=args.db,
            agent_registry=args.agent_registry,
            agent_registry_local=args.agent_registry_local,
            codex_projects_registry=args.codex_projects_registry,
            work_store=store,
        )
        try:
            usage_source = (
                PersistedUsageLimitSource(args.db, args.limit_id)
                if provider_native
                else CodexUsageTracker(args.db)
            )
            service = QuarkSchedulerService(
                store,
                usage_source=usage_source,
                executor=executor,
                policy=_policy(args),
                work_filter=work_filter,
            )
            result = service.run_cycle(
                execute=args.command in {"run-cycle", "agent-run-cycle"},
                limit_id=args.limit_id,
            )
            return (
                result if provider_native else _codex_cycle_payload(result)
            )
        finally:
            if manager_store is not None:
                manager_store.close()
    finally:
        store.close()


def main() -> None:
    args = build_parser().parse_args()
    print(json.dumps(run(args), sort_keys=True))


if __name__ == "__main__":
    main()
