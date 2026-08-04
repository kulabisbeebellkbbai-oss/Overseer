from __future__ import annotations

from pathlib import Path

import pytest

from tests.support import donuthole_backup_acceptance as acceptance
from tests.support.donuthole_backup_acceptance import SynchronousMCPBridge, run_acceptance_scenario


CONTRACT_FIXTURE = Path(__file__).parent / "fixtures/contracts/donuthole_backup_provisioning_v1.json"


def _assert_recursively_redacted(value: object, *, workspace: Path) -> None:
    if isinstance(value, dict):
        for child in value.values():
            _assert_recursively_redacted(child, workspace=workspace)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_recursively_redacted(child, workspace=workspace)
    elif isinstance(value, str):
        assert not value.startswith("/")
        assert str(workspace) not in value
        assert "disposable encrypted backup passphrase" not in value
        assert "disposable-test-token" not in value


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
    assert result["runtime_identity"]["previous"] is None
    assert result["runtime_identity"]["installed"] == result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["matches_plan"] is True
    assert result["terminal_status"] == "acceptance_passed"


def test_clean_install_read_path_does_not_require_gpg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(acceptance, "_gpg_available", lambda: False)

    result = run_acceptance_scenario(CONTRACT_FIXTURE, "clean_install", tmp_path)

    assert "backup" not in result
    assert "restore" not in result


def test_backup_restore_skips_only_when_gpg_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(acceptance, "_gpg_available", lambda: False)

    with pytest.raises(pytest.skip.Exception, match="encrypted backup acceptance requires gpg"):
        run_acceptance_scenario(CONTRACT_FIXTURE, "clean_install", tmp_path, include_backup_restore=True)


def test_sealed_authority_status_rejects_changed_bytes_or_mode(tmp_path: Path) -> None:
    authority = tmp_path / "authority.json"
    authority.write_text("{}", encoding="utf-8")
    authority.chmod(0o600)

    assert acceptance._sealed_authority_status(authority, b"{}") is False

    authority.chmod(0o400)
    assert acceptance._sealed_authority_status(authority, b'{"changed":true}') is False


def test_clean_install_performs_disposable_backup_and_restore_through_real_adapter(tmp_path: Path) -> None:
    result = run_acceptance_scenario(CONTRACT_FIXTURE, "clean_install", tmp_path, include_backup_restore=True)

    assert result["backup"]["status"] == "completed"
    assert result["backup"]["request_digest"].startswith("sha256:")
    assert len(result["backup"]["request_digest"]) == 71
    assert result["restore"]["status"] == "verified"
    assert result["restore"]["request_digest"] != result["backup"]["request_digest"]
    assert result["restore"]["restored_content_digest"] == result["backup"]["source_content_digest"]
    assert result["runtime_identity"]["installed"] == result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["matches_plan"] is True
    _assert_recursively_redacted(result, workspace=tmp_path)


def test_clean_install_rejects_tampered_installed_runtime_bytes(tmp_path: Path) -> None:
    result = run_acceptance_scenario(
        CONTRACT_FIXTURE,
        "clean_install",
        tmp_path,
        tamper_installed_runtime=True,
    )

    assert result["runtime_identity"]["previous"] is None
    assert result["runtime_identity"]["installed"] != result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["matches_plan"] is False
    assert result["terminal_status"] == "acceptance_failed"
    assert result["evidence"] == {"code": "runtime_identity_mismatch", "redacted": True}
    _assert_recursively_redacted(result, workspace=tmp_path)


def test_active_service_upgrade_converges_and_matches_planned_runtime(tmp_path: Path) -> None:
    result = run_acceptance_scenario(CONTRACT_FIXTURE, "active_service_upgrade", tmp_path)

    assert result["registration_disposition"] == "verified_no_op"
    assert result["runtime_identity"]["previous"] != result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["installed"] == result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["matches_plan"] is True
    assert result["terminal_status"] == "acceptance_passed"
    assert result["root_listing"]["relative_path"] == ""
    _assert_recursively_redacted(result, workspace=tmp_path)


def test_active_service_upgrade_rejects_stale_installed_runtime(tmp_path: Path) -> None:
    result = run_acceptance_scenario(
        CONTRACT_FIXTURE,
        "active_service_upgrade",
        tmp_path,
        retain_previous_runtime=True,
    )

    assert result["registration_disposition"] == "verified_no_op"
    assert result["runtime_identity"]["matches_plan"] is False
    assert result["terminal_status"] == "acceptance_failed"
    assert result["evidence"] == {"code": "runtime_identity_mismatch", "redacted": True}
    assert result["root_listing"]["relative_path"] == ""
    _assert_recursively_redacted(result, workspace=tmp_path)


def test_active_service_upgrade_rejects_tampered_installed_runtime_bytes(tmp_path: Path) -> None:
    result = run_acceptance_scenario(
        CONTRACT_FIXTURE,
        "active_service_upgrade",
        tmp_path,
        tamper_installed_runtime=True,
    )

    assert result["runtime_identity"]["installed"] != result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["matches_plan"] is False
    assert result["terminal_status"] == "acceptance_failed"
    assert result["evidence"] == {"code": "runtime_identity_mismatch", "redacted": True}
    _assert_recursively_redacted(result, workspace=tmp_path)
