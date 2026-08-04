"""Disposable Capability A composition across the reviewed repository boundary."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping


_REQUIRED_ENVIRONMENT = ("THEUNDERDARK_PYTHON", "THEUNDERDARK_SOURCE")


class SynchronousMCPBridge:
    """Run one real in-process MCP call to completion without storage substitutes."""

    def __init__(self, mcp: object) -> None:
        self._mcp = mcp

    def list_tools(self) -> list[str]:
        async def invoke() -> list[str]:
            tools = await self._mcp.list_tools()
            return sorted(str(tool.name) for tool in tools)

        return asyncio.run(invoke())

    def call_tool(self, name: str, arguments: Mapping[str, object]) -> Mapping[str, object]:
        async def invoke() -> Mapping[str, object]:
            from mcp.shared.memory import create_connected_server_and_client_session

            async with create_connected_server_and_client_session(self._mcp) as client:
                response = await client.call_tool(name, dict(arguments))
            structured = getattr(response, "structuredContent", None)
            if isinstance(structured, Mapping):
                return dict(structured)
            content = getattr(response, "content", ())
            if len(content) != 1 or not isinstance(getattr(content[0], "text", None), str):
                raise RuntimeError("production MCP response did not contain one JSON envelope")
            decoded = json.loads(content[0].text)
            if not isinstance(decoded, dict):
                raise RuntimeError("production MCP response envelope was not an object")
            return decoded

        return asyncio.run(invoke())


def run_acceptance_scenario(contract_path: Path, scenario_name: str, workspace: Path) -> dict[str, object]:
    """Launch clean-install composition with explicit external interpreter/source paths."""

    missing = [name for name in _REQUIRED_ENVIRONMENT if not os.environ.get(name)]
    if missing:
        raise RuntimeError("cross-repository acceptance requires " + ", ".join(missing))
    contract_path = contract_path.resolve(strict=True)
    workspace = workspace.resolve()
    source = Path(os.environ["THEUNDERDARK_SOURCE"]).resolve(strict=True)
    interpreter = Path(os.environ["THEUNDERDARK_PYTHON"])
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise RuntimeError("THEUNDERDARK_PYTHON must be an explicit executable path")
    builder = source / "tests" / "test_backup_production_integration.py"
    if not builder.is_file():
        raise RuntimeError("TheUnderdark disposable composition builder is unavailable")
    completed = subprocess.run(
        [
            str(interpreter),
            str(Path(__file__).resolve()),
            "--child",
            str(contract_path),
            scenario_name,
            str(workspace),
            str(builder),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join((
                str(source / "src"),
                str(source),
                str(Path(__file__).resolve().parents[2] / "src"),
                os.environ.get("PYTHONPATH", ""),
            )),
        },
    )
    if completed.returncode:
        raise RuntimeError("disposable acceptance subprocess failed: " + completed.stderr.strip())
    result = json.loads(completed.stdout)
    if not isinstance(result, dict):
        raise RuntimeError("disposable acceptance subprocess returned an invalid result")
    return result


def _load_builder(path: Path):
    spec = importlib.util.spec_from_file_location("theunderdark_disposable_composition", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load TheUnderdark disposable composition builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.build_real_service


def _child_run(contract_path: Path, scenario_name: str, workspace: Path, builder_path: Path) -> dict[str, object]:
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    scenarios = {item["name"]: item for item in contract["scenarios"]}
    if scenario_name != "clean_install" or scenario_name not in scenarios:
        raise ValueError("only the clean_install scenario belongs to Capability A Task 4")
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = workspace / "disposable-root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    for name in ("alpha.txt", "bravo.txt", "charlie.txt"):
        (root / name).write_text(name + "\n", encoding="utf-8")
    (nested / "delta.txt").write_text("delta\n", encoding="utf-8")
    registration = contract["root_registration"]
    authority_path = workspace / "authority.json"
    authority = {
        "project_id": registration["project_id"],
        "root_id": registration["root_id"],
        "policy_revision": registration["policy_revision"],
        "alias": registration["alias"],
        "max_bytes": registration["max_bytes"],
        "root_path": str(root.resolve()),
    }
    authority_path.write_text(json.dumps(authority, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    authority_path.chmod(0o400)
    authority_digest = "sha256:" + hashlib.sha256(authority_path.read_bytes()).hexdigest()
    service = _load_builder(builder_path)(workspace, authority_path)
    from theunderdark.production_app import create_production_mcp
    from overseer.storage_adapter import MCPBoundedStorageAdapterClient

    bridge = SynchronousMCPBridge(create_production_mcp(service))
    adapter = MCPBoundedStorageAdapterClient(bridge.call_tool, adapter_revision=1)
    health = adapter.health()
    project_envelope = adapter.project_get(registration["project_id"])
    root_envelope = adapter.root_get(registration["project_id"], registration["root_id"])
    first = adapter.directory_list(registration["project_id"], registration["root_id"], "", registration["policy_revision"], limit=2)
    second = adapter.directory_list(registration["project_id"], registration["root_id"], "", registration["policy_revision"], cursor=first["result"]["next_cursor"], limit=2)
    nested_envelope = adapter.directory_list(registration["project_id"], registration["root_id"], "nested", registration["policy_revision"], limit=2)
    if authority_path.read_bytes() != json.dumps(authority, sort_keys=True, separators=(",", ":")).encode():
        raise AssertionError("authority bytes changed after real component composition")
    first_result = first["result"]
    second_result = second["result"]
    entries = [entry["name"] for entry in first_result["entries"] + second_result["entries"]]
    if first_result["snapshot_identity"] != second_result["snapshot_identity"]:
        raise AssertionError("pagination did not retain a stable snapshot identity")
    if first_result["total_count"] != second_result["total_count"] or len(entries) != len(set(entries)):
        raise AssertionError("pagination did not preserve a complete duplicate-free traversal")
    return {
        "initialized": {"health": health, "tools": bridge.list_tools()},
        "project": {"name": "DonutHole", "project_id": registration["project_id"], "roots": project_envelope["result"]["roots"]},
        "root": {**root_envelope["result"], "relative_path": ""},
        "root_listing": {"relative_path": "", "entries": [entry["name"] for entry in first_result["entries"]]},
        "nested_listing": {"relative_path": "nested", "entries": [entry["name"] for entry in nested_envelope["result"]["entries"]]},
        "pagination": {
            "entries": entries,
            "next_cursor": second_result["next_cursor"],
            "page_size": 2,
            "snapshot_identity": first_result["snapshot_identity"],
            "total_count": first_result["total_count"],
        },
        "authority": {"digest": authority_digest, "unchanged": True},
    }


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", action="store_true")
    parser.add_argument("contract_path", type=Path)
    parser.add_argument("scenario_name")
    parser.add_argument("workspace", type=Path)
    parser.add_argument("builder_path", type=Path)
    arguments = parser.parse_args()
    if not arguments.child:
        raise SystemExit("this support module is invoked by run_acceptance_scenario")
    print(json.dumps(_child_run(arguments.contract_path, arguments.scenario_name, arguments.workspace, arguments.builder_path), sort_keys=True))


if __name__ == "__main__":
    _main()
