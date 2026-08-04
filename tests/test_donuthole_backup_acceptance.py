from __future__ import annotations

from pathlib import Path

import pytest

from tests.support.donuthole_backup_acceptance import SynchronousMCPBridge, run_acceptance_scenario


CONTRACT_FIXTURE = Path(__file__).parent / "fixtures/contracts/donuthole_backup_provisioning_v1.json"


def test_bridge_discovers_tools_in_its_first_call_boundary() -> None:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("bridge-test")

    @mcp.tool(name="fixture_echo")
    def echo(value: str) -> dict[str, str]:
        return {"value": value}

    bridge = SynchronousMCPBridge(mcp)
    assert bridge.call_tool("fixture_echo", {"value": "safe"}) == {"value": "safe"}
    assert bridge.discovered_tools == ("fixture_echo",)


def test_clean_install_acceptance_uses_real_disposable_components(tmp_path: Path) -> None:
    result = run_acceptance_scenario(CONTRACT_FIXTURE, "clean_install", tmp_path)

    assert {
        "underdark_directory_list",
        "underdark_health_get",
        "underdark_project_get",
        "underdark_root_get",
    } <= set(result["initialized"]["tools"])
    assert result["initialized"]["health"]["ok"] is True
    assert result["project"]["name"] == "DonutHole"
    assert result["project"]["project_id"] == "project.donuthole"
    assert result["root"]["relative_path"] == ""
    assert result["root_listing"]["relative_path"] == ""
    assert result["root_listing"]["entries"] == ["alpha.txt", "bravo.txt"]
    assert result["nested_listing"]["relative_path"] == "nested"
    assert result["nested_listing"]["entries"] == ["delta.txt"]
    assert result["pagination"]["entries"] == ["alpha.txt", "bravo.txt", "charlie.txt", "nested"]
    assert result["pagination"]["next_cursor"] is None
    assert result["pagination"]["page_size"] == 2
    assert result["pagination"]["snapshot_identity"].startswith("snapshot-")
    assert result["pagination"]["total_count"] == 4
    assert len(result["pagination"]["entries"]) == len(set(result["pagination"]["entries"]))
    assert result["authority"]["unchanged"] is True
