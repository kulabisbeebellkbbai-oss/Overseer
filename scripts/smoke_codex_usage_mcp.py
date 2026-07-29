from __future__ import annotations

import argparse
import asyncio

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def smoke(endpoint: str, health_url: str) -> None:
    response = httpx.get(health_url, timeout=5)
    response.raise_for_status()
    if response.json().get("status") != "ok":
        raise RuntimeError("unexpected health response")
    async with streamablehttp_client(endpoint) as (read, write, _session_id):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            required = {
                "refresh_usage",
                "get_usage_summary",
                "get_usage_history",
                "get_usage_heuristics",
                "get_source_status",
                "register_quark_work",
                "get_quark_work_queue",
                "plan_quark_work_cycle",
                "get_quark_project_effort",
            }
            if missing := required - names:
                raise RuntimeError(f"missing tools: {sorted(missing)}")
            result = await session.call_tool("get_usage_summary", {"refresh": True})
            if result.isError:
                raise RuntimeError("get_usage_summary returned an MCP error")
            invalid = await session.call_tool("get_usage_history", {"limit": 0})
            if not invalid.isError:
                raise RuntimeError("invalid history limit did not return a controlled MCP error")
    print(f"ok endpoint={endpoint} tools={len(names)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default="http://127.0.0.1:8797/mcp")
    parser.add_argument("--health", default="http://127.0.0.1:8797/health")
    args = parser.parse_args()
    asyncio.run(smoke(args.endpoint, args.health))


if __name__ == "__main__":
    main()
