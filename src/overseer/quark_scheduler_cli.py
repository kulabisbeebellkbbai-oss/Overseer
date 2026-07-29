"""CLI and timer entrypoint for Quark's checkpointed Codex work scheduler."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .codex_usage import CodexUsageTracker
from .quark_scheduler import (
    CodexExecSliceAdapter,
    CodexWorkItem,
    QuarkSchedulerService,
    QuarkUsagePolicy,
    QuarkWorkStore,
    _work_payload,
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

    subparsers.add_parser("queue")
    effort = subparsers.add_parser("project-effort")
    effort.add_argument("--project-id", required=True)

    for name in ("plan", "run-cycle"):
        command = subparsers.add_parser(name)
        command.add_argument("--limit-id", default="codex")
        command.add_argument("--hard-reserve", type=float, default=15)
        command.add_argument("--uncertainty", type=float, default=2)
        command.add_argument("--max-slice", type=float, default=5)
        command.add_argument("--max-concurrent", type=int, default=1)
    return parser


def run(args: argparse.Namespace) -> dict:
    store = QuarkWorkStore(args.db)
    try:
        if args.command == "register-work":
            item = CodexWorkItem(
                id=args.work_id,
                project_id=args.project_id,
                owner_thread=args.owner_thread,
                limit_id=args.limit_id,
                intent=args.intent,
                estimated_quota_points=args.estimated_quota_points,
                estimated_tokens=args.estimated_tokens,
                priority=args.priority,
            )
            store.save_work(item)
            return {"work": _work_payload(item), "mutation_performed": True, "host_mutation_performed": False}
        if args.command == "queue":
            return {
                "items": [_work_payload(item) for item in store.list_work()],
                "mutation_performed": False,
                "host_mutation_performed": False,
            }
        if args.command == "project-effort":
            return store.project_effort(args.project_id)
        tracker = CodexUsageTracker(args.db)
        service = QuarkSchedulerService(
            store,
            usage_source=tracker,
            executor=CodexExecSliceAdapter(),
            policy=_policy(args),
        )
        return service.run_cycle(execute=args.command == "run-cycle", limit_id=args.limit_id)
    finally:
        store.close()


def main() -> None:
    args = build_parser().parse_args()
    print(json.dumps(run(args), sort_keys=True))


if __name__ == "__main__":
    main()
