"""Loopback-only Streamable HTTP MCP server for Codex usage information."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse

from .codex_usage import CodexUsageTracker
from .quark_scheduler import (
    CodexWorkItem,
    QuarkSchedulerService,
    QuarkUsagePolicy,
    QuarkWorkStore,
    _codex_queue_payload,
    _codex_work_payload,
)
from .quark_scheduler_cli import (
    DEFAULT_AGENT_REGISTRY,
    PersistedUsageLimitSource,
    _provider_executor_for_work,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8797


def create_server(
    db_path: Path | str | None = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    tracker: CodexUsageTracker | None = None,
    agent_registry_path: str | Path = DEFAULT_AGENT_REGISTRY,
    local_agent_registry_path: str | Path | None = None,
    codex_projects_registry: str | Path = "/home/god/.codex/codex-projects.csv",
) -> FastMCP:
    if host != DEFAULT_HOST:
        raise ValueError("Codex usage MCP must bind to 127.0.0.1; use the protected gateway for approved remote access.")
    usage = tracker or CodexUsageTracker(db_path)
    mcp = FastMCP(
        "codex-usage",
        instructions=(
            "Read authoritative Codex quota windows, amounts used and remaining when disclosed, reset times, "
            "account token usage, local snapshot history, clearly labeled usage heuristics, and Quark's "
            "reserve-aware checkpointed work queue."
        ),
        host=host,
        port=port,
        streamable_http_path="/mcp",
        stateless_http=True,
    )

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_request):
        return JSONResponse({"status": "ok", "service": "codex-usage", "source": "codex_app_server"})

    @mcp.tool()
    def refresh_usage() -> dict:
        """Read current authoritative Codex usage and append a local metadata-only snapshot."""
        return usage.refresh()

    @mcp.tool()
    def get_usage_summary(refresh: bool = True) -> dict:
        """Return all available quota windows, used/remaining amounts, credits, reset times, and account usage."""
        return usage.latest(refresh=refresh)

    @mcp.tool()
    def get_usage_history(limit: int = 100) -> list[dict]:
        """Return recent metadata-only usage snapshots, newest first."""
        return usage.history(limit=limit)

    @mcp.tool()
    def get_usage_heuristics(refresh: bool = False) -> dict:
        """Return burn-rate forecasts, token trends, capacity posture, and a usage recommendation."""
        return usage.heuristics(refresh=refresh)

    @mcp.tool()
    def get_source_status() -> dict:
        """Describe the live source, last successful observation, snapshot count, and disclosure caveats."""
        return usage.source_status()

    @mcp.tool()
    def register_quark_work(
        work_id: str,
        project_id: str,
        owner_thread: str,
        intent: str,
        estimated_quota_points: float,
        estimated_tokens: int | None = None,
        priority: int = 50,
        limit_id: str = "codex",
    ) -> dict:
        """Queue checkpointable Codex work with an estimate and stable project/thread identity."""
        store = QuarkWorkStore(usage.db_path)
        try:
            item = CodexWorkItem(
                id=work_id,
                project_id=project_id,
                owner_thread=owner_thread,
                limit_id=limit_id,
                intent=intent,
                estimated_quota_points=estimated_quota_points,
                estimated_tokens=estimated_tokens,
                priority=priority,
            )
            store.save_work(item)
            return {
                "work": _codex_work_payload(item),
                "mutation_performed": True,
                "host_mutation_performed": False,
                "next_step": "run a dry Quark work plan before enabling execution",
            }
        finally:
            store.close()

    @mcp.tool()
    def get_quark_work_queue() -> dict:
        """Return queued, running, checkpointed, waiting, and completed Quark work."""
        store = QuarkWorkStore(usage.db_path)
        try:
            items = store.list_work()
            return _codex_queue_payload(items)
        finally:
            store.close()

    @mcp.tool()
    def plan_quark_work_cycle(
        execute: bool = False,
        limit_id: str = "codex",
        hard_reserve_points: float = 15,
        uncertainty_points: float = 2,
        max_slice_points: float = 5,
        max_concurrent_work: int = 1,
    ) -> dict:
        """Plan work against fresh usage; execute only explicitly requested bounded Codex turns."""
        store = QuarkWorkStore(usage.db_path)
        try:
            work = tuple(
                item
                for item in store.list_work()
                if item.limit_id == limit_id
            )
            executor, manager_store = _provider_executor_for_work(
                work,
                db_path=usage.db_path,
                agent_registry=agent_registry_path,
                agent_registry_local=local_agent_registry_path,
                codex_projects_registry=codex_projects_registry,
            )
            try:
                usage_source = (
                    PersistedUsageLimitSource(usage.db_path, limit_id)
                    if any(
                        item.agent_session_id is not None for item in work
                    )
                    else usage
                )
                service = QuarkSchedulerService(
                    store,
                    usage_source=usage_source,
                    executor=executor,
                    policy=QuarkUsagePolicy(
                        hard_reserve_points=hard_reserve_points,
                        uncertainty_points=uncertainty_points,
                        max_slice_points=max_slice_points,
                        max_concurrent_work=max_concurrent_work,
                    ),
                )
                result = service.run_cycle(
                    execute=execute,
                    limit_id=limit_id,
                )
                result["mutation_performed"] = bool(
                    execute
                    and (
                        result.get("executed")
                        or result.get("reconciled")
                    )
                )
                result["host_mutation_performed"] = bool(
                    execute
                    and (
                        result.get("executed")
                        or result.get("reconciled")
                    )
                )
                return result
            finally:
                if manager_store is not None:
                    manager_store.close()
        finally:
            store.close()

    @mcp.tool()
    def get_quark_project_effort(project_id: str) -> dict:
        """Return estimated versus actual quota points and token effort for one project."""
        store = QuarkWorkStore(usage.db_path)
        try:
            result = store.project_effort(project_id)
            result["mutation_performed"] = False
            result["host_mutation_performed"] = False
            return result
        finally:
            store.close()

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve Codex usage information over loopback-only MCP.")
    parser.add_argument("--host", default=os.environ.get("OVERSEER_CODEX_USAGE_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.environ.get("OVERSEER_CODEX_USAGE_PORT", DEFAULT_PORT)))
    parser.add_argument("--db", default=os.environ.get("OVERSEER_CODEX_USAGE_DB", "state/codex-usage.sqlite3"))
    parser.add_argument(
        "--agent-registry",
        default=os.environ.get(
            "OVERSEER_AGENT_REGISTRY",
            str(DEFAULT_AGENT_REGISTRY),
        ),
    )
    parser.add_argument(
        "--agent-registry-local",
        default=os.environ.get("OVERSEER_AGENT_REGISTRY_LOCAL"),
    )
    parser.add_argument(
        "--codex-projects-registry",
        default=os.environ.get(
            "OVERSEER_CODEX_PROJECTS_REGISTRY",
            "/home/god/.codex/codex-projects.csv",
        ),
    )
    args = parser.parse_args()
    create_server(
        args.db,
        args.host,
        args.port,
        agent_registry_path=args.agent_registry,
        local_agent_registry_path=args.agent_registry_local,
        codex_projects_registry=args.codex_projects_registry,
    ).run(transport="streamable-http")


if __name__ == "__main__":
    main()
