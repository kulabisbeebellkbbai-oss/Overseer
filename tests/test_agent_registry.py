from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from overseer.agent_contracts import (
    AgentCapabilities,
    AgentProvider,
    AgentTransport,
    CredentialReference,
    PrimaryDriver,
)
from overseer.agent_adapters.base_cli import CliCommandRunner
from overseer.agent_registry import AgentAdapterUnavailableError, AgentRegistry
from overseer.cli import agent_providers_status


def _provider(
    provider_id: str,
    executable: str | None = None,
    *,
    capabilities: dict[str, bool] | None = None,
) -> dict[str, object]:
    return {
        "id": provider_id,
        "adapter": "codex" if provider_id == "codex" else "claude",
        "transport": (
            "interactive_cli" if provider_id == "codex" else "noninteractive_cli"
        ),
        "executable": executable or provider_id,
        "capabilities": capabilities or {"session_resume": True, "handoff_import": True},
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


class _FactoryDriver:
    def __init__(self, provider: AgentProvider) -> None:
        self.provider = provider

    def discover(self, workspace: str | None = None):
        return ()

    def resolve(self, reference: str):
        return None

    def start(self, profile):
        raise NotImplementedError

    def resume(self, session):
        raise NotImplementedError

    def dispatch(self, request):
        raise NotImplementedError

    def inspect(self, session):
        raise NotImplementedError

    def checkpoint(self, session):
        raise NotImplementedError

    def cancel(self, session):
        raise NotImplementedError

    def import_handoff(self, profile, package):
        raise NotImplementedError


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


def test_registry_rejects_duplicate_fallback_order_entries(tmp_path: Path) -> None:
    config = _write_registry(
        tmp_path,
        providers=[_provider("codex", "codex"), _provider("claude", "claude")],
        instances=[_instance("overseer.default", "codex", ["claude", "claude"])],
    )

    with pytest.raises(ValueError, match="unique"):
        AgentRegistry.load(config)


def test_registry_requires_each_fallback_to_support_required_capabilities(
    tmp_path: Path,
) -> None:
    config = _write_registry(
        tmp_path,
        providers=[
            _provider("codex", "codex"),
            _provider("claude", "claude", capabilities={"session_resume": True}),
        ],
        instances=[_instance("overseer.default", "codex", ["claude"])],
    )

    with pytest.raises(ValueError, match="required capabilities"):
        AgentRegistry.load(config)


def test_local_override_cannot_contain_secret_values(tmp_path: Path) -> None:
    committed = _write_registry(tmp_path)
    local = tmp_path / "local.json"
    local.write_text(json.dumps({"providers": {"codex": {"api_key": "secret"}}}))

    with pytest.raises(ValueError, match="secret reference"):
        AgentRegistry.load(committed, local)


@pytest.mark.parametrize(
    ("section", "override"),
    [
        ("providers", {"codex": {"adapter": "claude"}}),
        ("providers", {"codex": {"transport": "gateway"}}),
        ("providers", {"codex": {"capabilities": {"handoff_import": False}}}),
        ("instances", {"overseer.default": {"fallback_provider_ids": ["claude"]}}),
    ],
)
def test_local_override_cannot_rewrite_committed_provider_or_failover_policy(
    tmp_path: Path, section: str, override: dict[str, object]
) -> None:
    committed = _write_registry(
        tmp_path,
        providers=[_provider("codex", "codex"), _provider("claude", "claude")],
    )
    local = tmp_path / "local.json"
    local.write_text(json.dumps({section: override}))

    with pytest.raises(ValueError, match="local override"):
        AgentRegistry.load(committed, local)


def test_registry_rejects_invalid_adapter_transport_executable_combination(
    tmp_path: Path,
) -> None:
    config = _write_registry(
        tmp_path,
        providers=[
            {
                **_provider("codex", "claude"),
                "adapter": "codex",
            }
        ],
    )

    with pytest.raises(ValueError, match="combination"):
        AgentRegistry.load(config)


def test_local_executable_path_must_be_canonical_and_match_provider_policy(
    tmp_path: Path,
) -> None:
    committed = _write_registry(tmp_path)
    executable = tmp_path / "user-bin" / "codex"
    executable.parent.mkdir()
    executable.write_text("placeholder")
    local = tmp_path / "local.json"
    local.write_text(json.dumps({"providers": {"codex": {"executable_path": str(executable)}}}))

    registry = AgentRegistry.load(committed, local)

    assert registry.providers["codex"].executable_allowlist == (str(executable.resolve()),)

    local.write_text(
        json.dumps(
            {"providers": {"codex": {"executable_path": str(tmp_path / "user-bin" / "claude")}}}
        )
    )
    with pytest.raises(ValueError, match="basename"):
        AgentRegistry.load(committed, local)


def test_committed_configuration_cannot_set_machine_local_executable_path(
    tmp_path: Path,
) -> None:
    config = _write_registry(
        tmp_path,
        providers=[{**_provider("codex", "codex"), "executable_path": "/opt/user/codex"}],
    )

    with pytest.raises(ValueError, match="machine-local"):
        AgentRegistry.load(config)


def test_registry_builds_immutable_profile_and_reports_unavailable_adapter(tmp_path: Path) -> None:
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

    assert profile.transport is AgentTransport.INTERACTIVE_CLI
    assert profile.credential_references["provider"] == CredentialReference(
        id="secret://overseer/codex"
    )
    with pytest.raises(AgentAdapterUnavailableError, match="codex"):
        registry.driver("overseer.default")


def test_registry_instantiates_only_explicitly_registered_adapter_factory(
    tmp_path: Path,
) -> None:
    class Driver:
        provider = None

        def discover(self, workspace: str | None = None):
            return ()

        def resolve(self, reference: str):
            return None

        def start(self, profile):
            raise NotImplementedError

        def resume(self, session):
            raise NotImplementedError

        def dispatch(self, request):
            raise NotImplementedError

        def inspect(self, session):
            raise NotImplementedError

        def checkpoint(self, session):
            raise NotImplementedError

        def cancel(self, session):
            raise NotImplementedError

        def import_handoff(self, profile, package):
            raise NotImplementedError

    def build_driver(provider, profile):
        driver = Driver()
        driver.provider = provider
        return driver

    registry = AgentRegistry.load(
        _write_registry(tmp_path),
        adapter_factories={"codex": build_driver},
    )

    driver = registry.driver("overseer.default")
    assert isinstance(driver, PrimaryDriver)
    assert driver.provider.id == "codex"


@pytest.mark.parametrize(
    "returned_provider",
    [
        AgentProvider(
            id="claude",
            adapter_id="claude",
            transports=(AgentTransport.INTERACTIVE_CLI,),
            executable_allowlist=("claude",),
        ),
        AgentProvider(
            id="codex",
            adapter_id="codex",
            capabilities=AgentCapabilities(session_resume=True),
            transports=(AgentTransport.INTERACTIVE_CLI,),
            executable_allowlist=("codex",),
        ),
    ],
)
def test_registry_rejects_adapter_factory_driver_with_mismatched_provider(
    tmp_path: Path, returned_provider: AgentProvider
) -> None:
    registry = AgentRegistry.load(
        _write_registry(tmp_path),
        adapter_factories={"codex": lambda provider, profile: _FactoryDriver(returned_provider)},
    )

    with pytest.raises(AgentAdapterUnavailableError, match="provider claims"):
        registry.driver("overseer.default")


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
    assert registry.profile("overseer.default").credential_references[
        "provider_secret_ref"
    ] == CredentialReference(id="secret://overseer/codex")

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


@pytest.mark.parametrize("secret_key", ["private_key", "access_key", "cookie", "bearer"])
def test_registry_rejects_common_inline_secret_key_names(
    tmp_path: Path, secret_key: str
) -> None:
    config = _write_registry(
        tmp_path,
        providers=[{**_provider("codex", "codex"), secret_key: "plaintext"}],
    )

    with pytest.raises(ValueError, match="secret reference"):
        AgentRegistry.load(config)


def test_registry_rejects_unknown_committed_top_level_sections(tmp_path: Path) -> None:
    config = _write_registry(tmp_path)
    payload = json.loads(config.read_text())
    payload["unreviewed"] = {"enabled": True}
    config.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="unknown sections"):
        AgentRegistry.load(config)


def test_registry_requires_profile_credential_references_required_by_provider(
    tmp_path: Path,
) -> None:
    provider = {
        **_provider("codex", "codex"),
        "required_secret_references": ["provider_api"],
    }
    config = _write_registry(tmp_path, providers=[provider])

    with pytest.raises(ValueError, match="required credential reference"):
        AgentRegistry.load(config)

    config = _write_registry(
        tmp_path,
        providers=[provider],
        instances=[
            _instance(
                "overseer.default",
                "codex",
                credential_references={"provider_api": "secret://overseer/codex"},
            )
        ],
    )
    registry = AgentRegistry.load(config)

    assert registry.providers["codex"].required_secret_references == ("provider_api",)


def test_registry_requires_profile_credential_references_required_by_fallbacks(
    tmp_path: Path,
) -> None:
    fallback = {
        **_provider("claude", "claude"),
        "required_secret_references": ["fallback_api"],
    }
    config = _write_registry(
        tmp_path,
        providers=[_provider("codex", "codex"), fallback],
        instances=[_instance("overseer.default", "codex", ["claude"])],
    )

    with pytest.raises(ValueError, match="required credential reference"):
        AgentRegistry.load(config)

    config = _write_registry(
        tmp_path,
        providers=[_provider("codex", "codex"), fallback],
        instances=[
            _instance(
                "overseer.default",
                "codex",
                ["claude"],
                credential_references={"fallback_api": "secret://overseer/claude"},
            )
        ],
    )

    assert AgentRegistry.load(config).profile("overseer.default").credential_references[
        "fallback_api"
    ] == CredentialReference(id="secret://overseer/claude")


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
    for provider_id in ("qwen-code", "mistral-vibe", "antigravity"):
        provider = registry.providers[provider_id]
        assert not any(vars(provider.capabilities).values())
        assert registry.adapter_factory_available(provider.adapter_id)


@pytest.mark.parametrize(
    ("provider_id", "adapter_id", "executable"),
    [
        ("qwen-code", "qwen_code", "qwen"),
        ("mistral-vibe", "mistral_vibe", "vibe"),
    ],
)
def test_unavailable_provider_local_executable_override_constructs_but_stays_unavailable(
    tmp_path: Path, provider_id: str, adapter_id: str, executable: str
) -> None:
    committed = _write_registry(
        tmp_path,
        providers=[{
            "id": provider_id, "adapter": adapter_id,
            "transport": "interactive_cli", "executable": executable,
            "capabilities": {},
        }],
        instances=[_instance("overseer.unavailable", provider_id)],
    )
    executable_path = (tmp_path / executable).resolve()
    local = tmp_path / "providers.local.json"
    local.write_text(json.dumps({
        "providers": {provider_id: {"executable_path": str(executable_path)}}
    }))

    registry = AgentRegistry.load(committed, local)

    assert registry.driver("overseer.unavailable").provider.id == provider_id
    assert registry.driver_for_provider(
        provider_id, instance_id="overseer.unavailable"
    ).provider.id == provider_id
    row = agent_providers_status(committed, local)["providers"][0]
    assert row["installed"] is True
    assert row["available"] is False
    assert row["unavailable_reason"]["type"] == "executable_not_installed"


def test_cli_runner_uses_argv_environment_and_captured_text_output() -> None:
    executable_name = Path(sys.executable).resolve().name
    runner = CliCommandRunner(
        executable_path=sys.executable,
        executable_allowlist=(executable_name,),
        environment={"RUNNER_TEST_ENV": "configured"},
    )

    completed = runner.run(
        (
            executable_name,
            "-c",
            "import os, sys; print(os.environ['RUNNER_TEST_ENV']); print(sys.stdin.read())",
        ),
        input_text="request text",
    )

    assert completed.returncode == 0
    assert completed.stdout == "configured\nrequest text\n"
    assert completed.stderr == ""


def test_cli_runner_ignores_caller_path_when_resolving_the_executable(
    tmp_path: Path,
) -> None:
    executable_name = Path(sys.executable).resolve().name
    runner = CliCommandRunner(
        executable_path=sys.executable,
        executable_allowlist=(executable_name,),
        environment={"PATH": str(tmp_path)},
    )

    completed = runner.run(
        (executable_name, "-c", "import sys; print(sys.executable)")
    )

    assert completed.stdout.strip() == str(Path(sys.executable).resolve())


def test_cli_runner_rejects_shell_strings_and_non_allowlisted_programs() -> None:
    runner = CliCommandRunner(
        executable_path=sys.executable,
        executable_allowlist=(Path(sys.executable).resolve().name,),
        environment={},
    )

    with pytest.raises(TypeError, match="Sequence"):
        runner.run("codex --dangerously-skip-permissions")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="allowlisted"):
        runner.run(("claude", "--version"))
