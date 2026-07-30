from __future__ import annotations

import json
import subprocess
from pathlib import Path

from overseer.agent_adapters.codex import CodexDriver
from overseer.agent_contracts import AgentOperationState, PrimaryDriver
from overseer.agent_registry import AgentRegistry
from overseer.codex_projects import (
    CodexProjectThreadAdapter,
    codex_project_thread_resources,
    legacy_codex_session_resource,
)


def test_agent_provider_docs_cover_required_safety_boundaries() -> None:
    architecture = Path("docs/agent-provider-architecture.md").read_text(
        encoding="utf-8"
    )
    contract = Path("docs/provider-adapter-contract.md").read_text(encoding="utf-8")
    migration = Path("docs/agent-provider-migration.md").read_text(encoding="utf-8")

    for phrase in (
        "one primary driver",
        "driver epoch",
        "manual handoff",
        "controlled failover",
        "old-epoch output",
        "provider-native usage",
    ):
        assert phrase in architecture
    assert "argument arrays" in contract
    assert "unsupported_capability" in contract
    assert "/codex-projects/" in migration
    assert "one migration cycle" in migration
    assert "rollback" in migration


class LegacyRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.inputs: list[str | None] = []

    def __call__(
        self,
        command: list[str],
        input: str | None = None,
        text: bool = True,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(tuple(command))
        self.inputs.append(input)
        if command[1] == "has-session":
            return subprocess.CompletedProcess(command, 1, "", "missing")
        return subprocess.CompletedProcess(command, 0, "started", "")


def _codex_csv(tmp_path: Path) -> Path:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
        "conversation-1,Example,/workspace/example,example,/bin/example,"
        "2026-07-28T10:00:00+00:00,2026-07-29T10:00:00+00:00,registry,\n",
        encoding="utf-8",
    )
    return registry


def test_legacy_codex_resource_id_is_preserved(tmp_path: Path) -> None:
    adapter = CodexProjectThreadAdapter(registry_path=_codex_csv(tmp_path))

    resource = codex_project_thread_resources(adapter.list_threads())[0]

    assert resource.id == "thread.codex.example"


def test_legacy_csv_import_links_generic_session(tmp_path: Path) -> None:
    sessions = CodexDriver.from_legacy_registry(_codex_csv(tmp_path)).discover()

    assert sessions[0].legacy_references["resource_id"] == "thread.codex.example"
    assert sessions[0].id == "session.codex.example"


def test_legacy_resource_links_back_to_generic_session(tmp_path: Path) -> None:
    session = CodexDriver.from_legacy_registry(_codex_csv(tmp_path)).discover()[0]

    resource = legacy_codex_session_resource(session)

    assert resource.id == "thread.codex.example"
    assert resource.identifiers["agent_session_id"] == session.id
    assert resource.identifiers["conversation_id"] == session.external_session_id


def test_legacy_facade_preserves_resume_dto_and_commands(tmp_path: Path) -> None:
    runner = LegacyRunner()
    adapter = CodexProjectThreadAdapter(
        registry_path=_codex_csv(tmp_path),
        tmux_path="/tmp/tmux",
        codex_memory_session_path="/tmp/codex-memory-session",
        runner=runner,
    )

    result = adapter.resume("example")

    assert result.status == "resumed"
    assert result.reason == "codex project thread resumed in detached tmux session"
    assert result.owner_thread == "example"
    assert result.conversation_id == "conversation-1"
    assert result.project == "/workspace/example"
    assert result.command == "example"
    assert result.launcher == "/bin/example"
    assert result.exit_code == 0
    assert result.stdout == "started"
    assert result.stderr == ""


def test_real_codex_factory_is_compatible_with_hardened_registry(
    tmp_path: Path,
) -> None:
    config = tmp_path / "providers.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "providers": [
                    {
                        "id": "codex",
                        "adapter": "codex",
                        "transport": "interactive_cli",
                        "executable": "codex",
                        "capabilities": {
                            "session_discovery": True,
                            "session_resume": True,
                            "interactive_dispatch": True,
                            "checkpoints": True,
                            "handoff_import": True,
                            "usage_observation": True,
                        },
                    }
                ],
                "instances": [
                    {
                        "id": "overseer.default",
                        "primary_provider_id": "codex",
                        "workspace": "/workspace/example",
                        "fallback_provider_ids": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    registry = AgentRegistry.load(config)

    driver = registry.driver("overseer.default")

    assert isinstance(driver, PrimaryDriver)
    assert isinstance(driver, CodexDriver)
    assert driver.provider == registry.providers["codex"]
    assert driver.profile == registry.profile("overseer.default")


def test_legacy_facade_submits_whitespace_prompt_with_exact_tmux_sequence(
    tmp_path: Path,
) -> None:
    runner = LegacyRunner()
    adapter = CodexProjectThreadAdapter(
        registry_path=_codex_csv(tmp_path),
        tmux_path="/tmp/tmux",
        codex_memory_session_path="/tmp/codex-memory-session",
        runner=runner,
    )
    prompt = " \t\n"

    result = adapter.dispatch_prompt("example", prompt)

    assert result.status == "prompt_dispatched"
    assert runner.commands == [
        ("/tmp/tmux", "has-session", "-t", "example"),
        (
            "/tmp/tmux",
            "new-session",
            "-d",
            "-s",
            "example",
            "-c",
            "/workspace/example",
            "/tmp/codex-memory-session",
            "resume",
            "conversation-1",
            "--cd",
            "/workspace/example",
        ),
        ("/tmp/tmux", "capture-pane", "-p", "-t", "example", "-S", "-200"),
        ("/tmp/tmux", "load-buffer", "-b", "overseer-dispatch", "-"),
        ("/tmp/tmux", "paste-buffer", "-b", "overseer-dispatch", "-t", "example"),
        ("/tmp/tmux", "send-keys", "-t", "example", "Enter"),
        ("/tmp/tmux", "capture-pane", "-p", "-t", "example", "-S", "-200"),
    ]
    assert runner.inputs[3] == prompt


def test_legacy_resolve_uses_original_keys_before_generic_session_ids(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
        "conversation-alpha,Alpha,/workspace/alpha,alpha,/bin/alpha,"
        "2026-07-28T10:00:00+00:00,2026-07-29T10:00:00+00:00,registry,\n"
        "conversation-later,Later,/workspace/later,session.codex.alpha,/bin/later,"
        "2026-07-28T10:00:00+00:00,2026-07-29T10:00:00+00:00,registry,\n",
        encoding="utf-8",
    )
    adapter = CodexProjectThreadAdapter(registry_path=registry)

    generic = adapter.driver.resolve("session.codex.alpha")
    legacy = adapter.resolve("session.codex.alpha")

    assert generic is not None
    assert generic.external_session_id == "conversation-alpha"
    assert legacy is not None
    assert legacy.conversation_id == "conversation-later"
