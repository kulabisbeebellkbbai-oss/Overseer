from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from overseer.agent_contracts import AgentTransport, CredentialReference, PrimaryDriver
from overseer.agent_adapters.base_cli import CliCommandRunner
from overseer.agent_registry import AgentRegistry


def _provider(provider_id: str, executable: str | None = None) -> dict[str, object]:
    return {
        "id": provider_id,
        "adapter": "codex" if provider_id == "codex" else "claude",
        "transport": "interactive_cli",
        "executable": executable or provider_id,
        "capabilities": {"session_resume": True},
    }


def _instance(
    instance_id: str,
    provider_id: str,
    fallbacks: list[str] | None = None,
    **overrides: object,
) -> dict[str, object]:
    return {
        "id": instance_id,
        "primary_provider_id": provider_id,
        "workspace": ".",
        "fallback_provider_ids": fallbacks or [],
        **overrides,
    }


def _write_registry(
    tmp_path: Path,
    *,
    providers: list[dict[str, object]] | None = None,
    instances: list[dict[str, object]] | None = None,
) -> Path:
    config = tmp_path / "providers.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "providers": providers or [_provider("codex", "codex")],
                "instances": instances
                or [_instance("overseer.default", "codex")],
            }
        )
    )
    return config


def test_registry_rejects_shell_command_strings(tmp_path: Path) -> None:
    config = tmp_path / "providers.json"
    config.write_text(
        json.dumps(
            {
                "providers": [
                    {
                        "id": "claude",
                        "adapter": "claude",
                        "transport": "interactive_cli",
                        "executable": "claude --dangerously-skip-permissions",
                        "capabilities": {"session_resume": True},
                    }
                ],
                "instances": [],
            }
        )
    )

    with pytest.raises(ValueError, match="executable name"):
        AgentRegistry.load(config)


def test_registry_rejects_cyclic_fallbacks(tmp_path: Path) -> None:
    config = _write_registry(
        tmp_path,
        providers=[_provider("codex", "codex"), _provider("claude", "claude")],
        instances=[
            _instance("one", "codex", ["claude"]),
            _instance("two", "claude", ["codex"]),
        ],
    )

    with pytest.raises(ValueError, match="fallback cycle"):
        AgentRegistry.load(config)


def test_local_override_cannot_contain_secret_values(tmp_path: Path) -> None:
    committed = _write_registry(tmp_path)
    local = tmp_path / "local.json"
    local.write_text(json.dumps({"providers": {"codex": {"api_key": "secret"}}}))

    with pytest.raises(ValueError, match="secret reference"):
        AgentRegistry.load(committed, local)


def test_registry_builds_immutable_profile_and_configured_driver(tmp_path: Path) -> None:
    config = _write_registry(
        tmp_path,
        instances=[
            _instance(
                "overseer.default",
                "codex",
                credential_references={"provider": "secret://overseer/codex"},
            )
        ],
    )

    registry = AgentRegistry.load(config)
    profile = registry.profile("overseer.default")
    driver = registry.driver("overseer.default")

    assert profile.transport is AgentTransport.INTERACTIVE_CLI
    assert profile.credential_references["provider"] == CredentialReference(
        id="secret://overseer/codex"
    )
    assert isinstance(driver, PrimaryDriver)
    assert driver.provider.id == "codex"


def test_registry_rejects_inline_secret_keys_except_secret_reference_keys(
    tmp_path: Path,
) -> None:
    config = _write_registry(
        tmp_path,
        instances=[
            _instance(
                "overseer.default",
                "codex",
                provider_secret_ref="secret://overseer/codex",
            )
        ],
    )

    registry = AgentRegistry.load(config)
    assert registry.profile("overseer.default").id == "overseer.default"

    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "providers": [_provider("codex", "codex")],
                "instances": [
                    _instance(
                        "overseer.default",
                        "codex",
                        provider_api_key="plaintext",
                    )
                ],
            }
        )
    )
    with pytest.raises(ValueError, match="secret reference"):
        AgentRegistry.load(config)


def test_registry_rejects_non_allowlisted_executable(tmp_path: Path) -> None:
    config = _write_registry(
        tmp_path,
        providers=[_provider("codex", "python")],
    )

    with pytest.raises(ValueError, match="allowlisted"):
        AgentRegistry.load(config)


def test_committed_provider_configuration_loads() -> None:
    config = Path(__file__).parents[1] / "config" / "agent-providers.json"

    registry = AgentRegistry.load(config)

    assert registry.profile("overseer.default").primary_provider_id == "codex"


def test_cli_runner_uses_argv_environment_and_captured_text_output() -> None:
    runner = CliCommandRunner(
        executable_allowlist=(sys.executable,),
        environment={"RUNNER_TEST_ENV": "configured"},
    )

    completed = runner.run(
        (
            sys.executable,
            "-c",
            "import os, sys; print(os.environ['RUNNER_TEST_ENV']); print(sys.stdin.read())",
        ),
        input_text="request text",
    )

    assert completed.returncode == 0
    assert completed.stdout == "configured\nrequest text\n"
    assert completed.stderr == ""


def test_cli_runner_rejects_shell_strings_and_non_allowlisted_programs() -> None:
    runner = CliCommandRunner(
        executable_allowlist=("codex",),
        environment={},
    )

    with pytest.raises(TypeError, match="Sequence"):
        runner.run("codex --dangerously-skip-permissions")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="allowlisted"):
        runner.run(("claude", "--version"))
