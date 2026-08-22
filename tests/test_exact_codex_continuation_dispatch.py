from pathlib import Path

import pytest

from overseer.codex_projects import CodexProjectThreadAdapter
from overseer.cli import approve_claim_status, request_claim_status
from overseer.core import OwnerDomain, Resource, ResourceType, RiskLevel
from overseer.store import SQLiteStore


class _Runner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run_bounded(self, command, input_text=None, **kwargs):
        self.commands.append(tuple(command))
        raise AssertionError("exact preflight must not invoke tmux for an alias")


def test_exact_codex_dispatch_rejects_alias_and_prefix_before_tmux(tmp_path: Path) -> None:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
        "conversation-full-123,Arcade,/workspace/arcade,arcade-command,/bin/arcade-launcher,,,,\n",
        encoding="utf-8",
    )
    runner = _Runner()
    adapter = CodexProjectThreadAdapter(
        registry_path=registry,
        tmux_path="/tmp/tmux",
        codex_memory_session_path="/tmp/codex-memory-session",
        runner=runner,
    )

    for alias in ("Arcade", "arcade-command", "/bin/arcade-launcher", "/workspace/arcade", "conversation-full"):
        result = adapter.dispatch_prompt_exact(alias, "approved continuation")
        assert result.status == "not_found"
        assert result.resume_result.conversation_id is None

    assert runner.commands == []


def test_role_approval_requires_explicit_lifecycle_and_group_bindings(tmp_path: Path) -> None:
    path = tmp_path / "overseer.sqlite3"
    store = SQLiteStore(path)
    store.save_resource(
        Resource(
            id="proxy.unbound",
            name="Unbound proxy",
            type=ResourceType.VIRTUAL_ASSET,
            owner_domain=OwnerDomain.DAX,
            risk_level=RiskLevel.LOW,
        )
    )
    store.close()
    requested = request_claim_status(
        path,
        "claim.unbound",
        "proxy.unbound",
        "lease",
        "conversation-full-123",
        OwnerDomain.DAX.value,
        "bounded test",
        "bind proxy",
        RiskLevel.LOW.value,
    )

    with pytest.raises(ValueError, match="explicit lifecycle"):
        approve_claim_status(path, str(requested["approval_id"]), OwnerDomain.DAX.value)

    store = SQLiteStore(path)
    assert store.load_approval(str(requested["approval_id"])).status.value == "pending"
    assert store.list_claim_approval_continuations() == ()
    store.close()
