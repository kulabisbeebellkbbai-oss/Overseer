from __future__ import annotations

import subprocess
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Callable

import pytest

from overseer.agent_adapters.codex import CodexDriver
from overseer.agent_adapters.claude import ClaudeDriver
from overseer.agent_adapters.antigravity import antigravity_adapter_factory
from overseer.agent_adapters.mistral_vibe import mistral_vibe_adapter_factory
from overseer.agent_adapters.qwen_code import qwen_code_adapter_factory
from overseer.agent_adapters.base_cli import CliCommandRunner, CliOutputLimitExceeded
from overseer.agent_contracts import (
    AgentCapabilities,
    AgentDispatchRequest,
    AgentErrorCategory,
    AgentHandoffPackage,
    AgentInstanceProfile,
    AgentOperationState,
    AgentProvider,
    AgentSession,
    AgentTransport,
    PrimaryDriver,
)
from overseer.agent_operations import AgentOperationCoordinator
from overseer.store import OverseerStore


@pytest.mark.parametrize(
    ("provider_id", "adapter_id", "transport", "executable", "factory"),
    [
        ("qwen-code", "qwen_code", AgentTransport.INTERACTIVE_CLI, "qwen", qwen_code_adapter_factory),
        ("mistral-vibe", "mistral_vibe", AgentTransport.INTERACTIVE_CLI, "vibe", mistral_vibe_adapter_factory),
        ("antigravity", "antigravity", AgentTransport.GATEWAY, None, antigravity_adapter_factory),
    ],
)
def test_unverified_adapters_never_invoke_provider_interfaces(
    tmp_path: Path,
    provider_id: str,
    adapter_id: str,
    transport: AgentTransport,
    executable: str | None,
    factory,
) -> None:
    provider = AgentProvider(
        id=provider_id,
        adapter_id=adapter_id,
        capabilities=AgentCapabilities(),
        transports=(transport,),
        executable_allowlist=(executable,) if executable else (),
    )
    profile = AgentInstanceProfile(
        id="overseer.unavailable",
        primary_provider_id=provider_id,
        primary_adapter_id=adapter_id,
        transport=transport,
        workspace=str(tmp_path),
    )
    driver = factory(provider, profile)
    request = AgentDispatchRequest(
        id="dispatch.unavailable",
        instance_id=profile.id,
        session_id="session.unavailable",
        driver_epoch_id="epoch.unavailable",
        idempotency_key="unavailable.1",
        prompt="do not execute",
    )
    session = AgentSession(
        id=request.session_id,
        provider_id=provider_id,
        external_session_id="external.unavailable",
        workspace=str(tmp_path),
        transport=transport,
        capabilities=AgentCapabilities(),
        instance_id=profile.id,
        legacy_references={"driver_epoch_id": request.driver_epoch_id},
    )

    assert driver.discover() == ()
    assert driver.resolve("anything") is None
    for result in (
        driver.start(profile),
        driver.resume(session),
        driver.dispatch(request),
        driver.inspect(session),
        driver.cancel(session),
    ):
        assert result.provider_id == provider_id
        assert result.error_category is AgentErrorCategory.PROVIDER_UNAVAILABLE
        assert result.state is AgentOperationState.FAILED
    checkpoint = driver.checkpoint(session)
    assert checkpoint.instance_id == profile.id
    assert checkpoint.session_id == session.id
    assert checkpoint.driver_epoch_id == request.driver_epoch_id
    assert checkpoint.evidence == {"unsupported_capability": "checkpoints"}


@pytest.mark.parametrize(
    ("provider_id", "adapter_id", "transport", "executable", "factory"),
    [
        ("qwen-code", "qwen_code", AgentTransport.INTERACTIVE_CLI, "qwen", qwen_code_adapter_factory),
        ("mistral-vibe", "mistral_vibe", AgentTransport.INTERACTIVE_CLI, "vibe", mistral_vibe_adapter_factory),
    ],
)
def test_unavailable_cli_adapters_accept_registry_valid_absolute_executable(
    tmp_path: Path, provider_id: str, adapter_id: str, transport, executable: str, factory
) -> None:
    executable_path = tmp_path / executable
    provider = AgentProvider(
        id=provider_id, adapter_id=adapter_id, transports=(transport,),
        executable_allowlist=(str(executable_path.resolve()),),
    )
    profile = AgentInstanceProfile(
        id="overseer.unavailable", primary_provider_id=provider_id,
        primary_adapter_id=adapter_id, transport=transport, workspace=str(tmp_path),
    )
    assert factory(provider, profile).discover() == ()

    for invalid in (("relative/path",), (str(tmp_path / "wrong"),), (executable, executable)):
        bad_provider = replace(provider, executable_allowlist=invalid)
        with pytest.raises(ValueError, match="executable selection"):
            factory(bad_provider, profile)


@pytest.mark.parametrize(
    ("provider_id", "adapter_id", "transport", "executable", "factory"),
    [
        ("qwen-code", "qwen_code", AgentTransport.INTERACTIVE_CLI, "qwen", qwen_code_adapter_factory),
        ("mistral-vibe", "mistral_vibe", AgentTransport.INTERACTIVE_CLI, "vibe", mistral_vibe_adapter_factory),
        ("antigravity", "antigravity", AgentTransport.GATEWAY, None, antigravity_adapter_factory),
    ],
)
def test_unavailable_adapter_handoff_preserves_supplied_bindings(
    tmp_path: Path, provider_id: str, adapter_id: str, transport, executable, factory
) -> None:
    provider = AgentProvider(
        id=provider_id, adapter_id=adapter_id, transports=(transport,),
        executable_allowlist=(executable,) if executable else (),
    )
    profile = AgentInstanceProfile(
        id="overseer.unavailable", primary_provider_id=provider_id,
        primary_adapter_id=adapter_id, transport=transport, workspace=str(tmp_path),
    )
    package = AgentHandoffPackage(
        id="handoff.unavailable", instance_id=profile.id,
        outgoing_epoch_id="epoch.outgoing", incoming_provider_id=provider_id,
        objective="continue safely",
        evidence={"incoming_session_id": "session.incoming", "incoming_epoch_id": "epoch.incoming"},
    )

    result = factory(provider, profile).import_handoff(profile, package)

    assert (result.request_id, result.instance_id, result.session_id) == (
        "handoff.handoff.unavailable", profile.id, "session.incoming"
    )
    assert result.driver_epoch_id == "epoch.incoming"
    assert result.provider_id == provider_id
    assert result.error_category is AgentErrorCategory.PROVIDER_UNAVAILABLE
    assert result.evidence == {"provider_unavailable": True}
    assert "objective" not in json.dumps(dict(result.evidence))


class RecordingRunner:
    def __init__(self, *, reject_prompt: bool = False) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.inputs: list[str | None] = []
        self.capture_count = 0
        self.reject_prompt = reject_prompt

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
        if command[1] == "capture-pane":
            self.capture_count += 1
            output = "Codex ready"
            if self.reject_prompt and self.capture_count == 2:
                output = "Message exceeds maximum length allowed"
            return subprocess.CompletedProcess(command, 0, output, "")
        return subprocess.CompletedProcess(command, 0, "ok", "")


AdapterFactory = Callable[[str], PrimaryDriver]


@pytest.fixture
def fake_claude(tmp_path: Path) -> Path:
    executable = tmp_path / "claude"
    executable.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "mode = os.environ.get('FAKE_CLAUDE_MODE', 'success')\n"
        "prompt = sys.stdin.read()\n"
        "def option(name):\n"
        " i = sys.argv.index(name) if name in sys.argv else -1\n"
        " return sys.argv[i + 1] if i >= 0 else None\n"
        "session_id = option('--resume') or option('--session-id')\n"
        "if mode == 'nonzero':\n"
        " print('authentication failed', file=sys.stderr); raise SystemExit(2)\n"
        "if mode == 'malformed': print('{bad json'); raise SystemExit(0)\n"
        "if mode == 'oversized': print('x' * 70000); raise SystemExit(0)\n"
        "if mode == 'oversized_stderr': print('x' * 70000, file=sys.stderr); raise SystemExit(0)\n"
        "if mode == 'json_error':\n"
        " print(json.dumps({'type': 'result', 'is_error': True, 'result': 'request rejected', "
        "'session_id': session_id})); raise SystemExit(0)\n"
        "if mode == 'spoof_identity': session_id = '00000000-0000-4000-8000-000000000099'\n"
        "if mode == 'system_shape':\n"
        " print(json.dumps({'type':'system','subtype':'init','is_error':False,'session_id':session_id})); raise SystemExit(0)\n"
        "if mode == 'unknown_subtype':\n"
        " print(json.dumps({'type':'result','subtype':'mystery','is_error':False,'session_id':session_id})); raise SystemExit(0)\n"
        "if mode == 'missing_is_error':\n"
        " print(json.dumps({'type':'result','subtype':'success','session_id':session_id})); raise SystemExit(0)\n"
        "if mode == 'nonboolean_is_error':\n"
        " print(json.dumps({'type':'result','subtype':'success','is_error':'false','session_id':session_id})); raise SystemExit(0)\n"
        "print(json.dumps({'type': 'result', 'subtype': 'success', "
        "'is_error': False, 'result': 'private transcript must not persist', "
        "'session_id': session_id, 'duration_ms': 10, "
        "'num_turns': 1, 'prompt_echo': prompt}))\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return executable


def _claude_adapter(
    fake_claude: Path,
    workspace: Path,
    *,
    mode: str = "success",
    external_session_id: str | None = None,
) -> ClaudeDriver:
    capabilities = AgentCapabilities(
        session_resume=True,
        noninteractive_dispatch=True,
        structured_events=False,
        handoff_import=True,
    )
    provider = AgentProvider(
        id="claude",
        adapter_id="claude",
        capabilities=capabilities,
        transports=(AgentTransport.NONINTERACTIVE_CLI,),
        executable_allowlist=(str(fake_claude),),
    )
    profile = AgentInstanceProfile(
        id="overseer.default",
        primary_provider_id="claude",
        primary_adapter_id="claude",
        transport=AgentTransport.NONINTERACTIVE_CLI,
        workspace=str(workspace),
        external_session_id=external_session_id,
        declared_capabilities=capabilities,
    )
    runner = CliCommandRunner(
        executable_path=fake_claude,
        executable_allowlist=(str(fake_claude),),
        environment={**os.environ, "FAKE_CLAUDE_MODE": mode},
    )
    return ClaudeDriver(provider, profile, runner=runner)


@pytest.fixture
def codex_csv(tmp_path: Path) -> Path:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
        "conversation-1,Example,/workspace/example,example,/bin/example,"
        "2026-07-28T10:00:00+00:00,2026-07-29T10:00:00+00:00,registry,\n",
        encoding="utf-8",
    )
    return registry


@pytest.fixture
def adapter_factory(codex_csv: Path) -> AdapterFactory:
    def factory(provider_id: str) -> PrimaryDriver:
        capabilities = AgentCapabilities(
            session_discovery=True,
            session_resume=True,
            interactive_dispatch=True,
            checkpoints=True,
            handoff_import=True,
            usage_observation=True,
        )
        provider = AgentProvider(
            id=provider_id,
            adapter_id="codex",
            capabilities=capabilities,
            transports=(AgentTransport.INTERACTIVE_CLI,),
            executable_allowlist=("codex",),
        )
        profile = AgentInstanceProfile(
            id="overseer.default",
            primary_provider_id=provider_id,
            primary_adapter_id="codex",
            transport=AgentTransport.INTERACTIVE_CLI,
            workspace="/workspace/example",
            declared_capabilities=capabilities,
        )
        return CodexDriver(
            provider=provider,
            profile=profile,
            registry_path=codex_csv,
            tmux_path="/tmp/tmux",
            codex_memory_session_path="/tmp/codex-memory-session",
            runner=RecordingRunner(),
        )

    return factory


@pytest.mark.parametrize("provider_id", ["codex"])
def test_adapter_contract_discovers_and_resumes(
    provider_id: str,
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory(provider_id)

    session = adapter.discover()[0]
    result = adapter.resume(session)

    assert session.provider_id == provider_id
    assert session.instance_id == "overseer.default"
    assert session.external_session_id == "conversation-1"
    assert result.state in {
        AgentOperationState.ACKNOWLEDGED,
        AgentOperationState.RUNNING,
    }
    assert result.provider_id == provider_id
    assert result.instance_id == session.instance_id
    assert result.session_id == session.external_session_id
    assert result.external_session_id == session.external_session_id


def test_dispatch_preserves_request_bindings_and_exact_tmux_sequence(
    codex_csv: Path,
) -> None:
    runner = RecordingRunner()
    adapter = CodexDriver.from_legacy_registry(
        codex_csv,
        instance_id="overseer.default",
        workspace="/workspace/example",
        tmux_path="/tmp/tmux",
        codex_memory_session_path="/tmp/codex-memory-session",
        runner=runner,
    )
    session = adapter.discover()[0]
    request = AgentDispatchRequest(
        id="dispatch.1",
        instance_id="overseer.default",
        session_id=session.id,
        driver_epoch_id="epoch.7",
        idempotency_key="dispatch-key.1",
        prompt="Continue the approved work.",
    )

    result = adapter.dispatch(request)

    assert result.request_id == request.id
    assert result.instance_id == request.instance_id
    assert result.session_id == request.session_id
    assert result.driver_epoch_id == request.driver_epoch_id
    assert result.provider_id == "codex"
    assert result.external_session_id == "conversation-1"
    assert result.state is AgentOperationState.ACKNOWLEDGED
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
    assert runner.inputs[3] == request.prompt


def test_dispatch_reports_codex_rejection_without_losing_request_bindings(
    codex_csv: Path,
) -> None:
    adapter = CodexDriver.from_legacy_registry(
        codex_csv,
        instance_id="overseer.default",
        workspace="/workspace/example",
        tmux_path="/tmp/tmux",
        codex_memory_session_path="/tmp/codex-memory-session",
        runner=RecordingRunner(reject_prompt=True),
    )
    session = adapter.discover()[0]
    request = AgentDispatchRequest(
        id="dispatch.rejected",
        instance_id="overseer.default",
        session_id=session.id,
        driver_epoch_id="epoch.rejected",
        idempotency_key="dispatch-key.rejected",
        prompt="x" * 20,
    )

    result = adapter.dispatch(request)

    assert result.state is AgentOperationState.FAILED
    assert result.request_id == request.id
    assert result.session_id == request.session_id
    assert result.driver_epoch_id == request.driver_epoch_id
    assert result.error_message == "codex project rejected prompt: message exceeds maximum length"


def test_codex_capability_claims_are_truthful(adapter_factory: AdapterFactory) -> None:
    adapter = adapter_factory("codex")

    assert adapter.provider.capabilities.session_discovery
    assert adapter.provider.capabilities.session_resume
    assert adapter.provider.capabilities.interactive_dispatch
    assert adapter.provider.capabilities.checkpoints
    assert adapter.provider.capabilities.handoff_import
    assert not adapter.provider.capabilities.structured_events
    assert not adapter.provider.capabilities.noninteractive_dispatch
    assert not adapter.provider.capabilities.cancellation


def test_codex_rejects_provider_claims_for_unsupported_native_operations(
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory("codex")
    provider = replace(
        adapter.provider,
        capabilities=replace(adapter.provider.capabilities, cancellation=True),
    )

    with pytest.raises(ValueError, match="unsupported capability claims"):
        CodexDriver(
            provider,
            adapter.profile,
            registry_path=adapter.registry_path,
            runner=RecordingRunner(),
        )


def test_checkpoint_and_unsupported_cancellation_report_durable_identity(
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory("codex")
    session = adapter.discover()[0]

    checkpoint = adapter.checkpoint(session)
    cancelled = adapter.cancel(session)

    assert checkpoint.instance_id == session.instance_id
    assert checkpoint.session_id == session.id
    assert checkpoint.evidence["status"] == "ready"
    assert checkpoint.created_at is not None
    assert cancelled.instance_id == session.instance_id
    assert cancelled.session_id == session.external_session_id
    assert cancelled.external_session_id == session.external_session_id
    assert cancelled.state is AgentOperationState.FAILED
    assert cancelled.error_category is AgentErrorCategory.UNSUPPORTED_CAPABILITY


def test_handoff_import_binds_manager_owned_session_epoch_and_external_identity(
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory("codex")
    package = AgentHandoffPackage(
        id="handoff.1",
        instance_id="overseer.default",
        outgoing_epoch_id="epoch.outgoing",
        incoming_provider_id="codex",
        objective="Continue the approved work from the checkpoint.",
        evidence={
            "incoming_session_id": "session.overseer.default.codex.2",
            "incoming_epoch_id": "epoch.incoming",
        },
    )

    result = adapter.import_handoff(adapter.profile, package)

    assert result.request_id == "handoff.handoff.1"
    assert result.instance_id == package.instance_id
    assert result.provider_id == package.incoming_provider_id
    assert result.session_id == "session.overseer.default.codex.2"
    assert result.driver_epoch_id == "epoch.incoming"
    assert result.external_session_id == "conversation-1"
    assert result.state is AgentOperationState.ACKNOWLEDGED


def test_dispatch_result_completes_generation_bound_operation(
    tmp_path: Path,
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory("codex")
    session = adapter.discover()[0]
    store = OverseerStore(tmp_path / "overseer.sqlite3")
    coordinator = AgentOperationCoordinator(store)
    request = AgentDispatchRequest(
        id="dispatch.coordinated",
        instance_id="overseer.default",
        session_id=session.id,
        driver_epoch_id="epoch.coordinated",
        idempotency_key="dispatch-key.coordinated",
        prompt="Continue coordinated work.",
    )
    accepted = coordinator.accept_dispatch(request)
    assert coordinator.claim_dispatch_execution(accepted)

    result = adapter.dispatch(accepted)
    completed = coordinator.complete_dispatch(accepted, result)

    assert completed.evidence["result_id"] == result.id
    assert completed.evidence["provider_id"] == "codex"
    assert completed.evidence["status"] == AgentOperationState.ACKNOWLEDGED.value
    store.close()


def test_profile_does_not_fall_open_to_sole_mismatched_legacy_session(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
        "wrong-conversation,Wrong,/workspace/wrong,wrong,/bin/wrong,"
        "2026-07-28T10:00:00+00:00,2026-07-29T10:00:00+00:00,registry,\n",
        encoding="utf-8",
    )
    runner = RecordingRunner()
    capabilities = AgentCapabilities(
        session_discovery=True,
        session_resume=True,
        interactive_dispatch=True,
    )
    provider = AgentProvider(
        id="codex",
        adapter_id="codex",
        capabilities=capabilities,
        transports=(AgentTransport.INTERACTIVE_CLI,),
        executable_allowlist=("codex",),
    )
    profile = AgentInstanceProfile(
        id="overseer.default",
        primary_provider_id="codex",
        primary_adapter_id="codex",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/workspace/expected",
        declared_capabilities=capabilities,
    )
    adapter = CodexDriver(
        provider,
        profile,
        registry_path=registry,
        tmux_path="/tmp/tmux",
        codex_memory_session_path="/tmp/codex-memory-session",
        runner=runner,
    )

    result = adapter.start(profile)

    assert result.state is AgentOperationState.FAILED
    assert result.error_category is AgentErrorCategory.SESSION_NOT_FOUND
    assert runner.commands == []


def test_required_external_session_does_not_fall_through_to_workspace_match(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\n"
        "other-conversation,Other,/workspace/expected,other,/bin/other,"
        "2026-07-28T10:00:00+00:00,2026-07-29T10:00:00+00:00,registry,\n",
        encoding="utf-8",
    )
    runner = RecordingRunner()
    capabilities = AgentCapabilities(
        session_discovery=True,
        session_resume=True,
        interactive_dispatch=True,
    )
    provider = AgentProvider(
        id="codex",
        adapter_id="codex",
        capabilities=capabilities,
        transports=(AgentTransport.INTERACTIVE_CLI,),
        executable_allowlist=("codex",),
    )
    profile = AgentInstanceProfile(
        id="overseer.default",
        primary_provider_id="codex",
        primary_adapter_id="codex",
        transport=AgentTransport.INTERACTIVE_CLI,
        workspace="/workspace/expected",
        external_session_id="required-conversation",
        declared_capabilities=capabilities,
    )
    adapter = CodexDriver(
        provider,
        profile,
        registry_path=registry,
        tmux_path="/tmp/tmux",
        codex_memory_session_path="/tmp/codex-memory-session",
        runner=runner,
    )

    result = adapter.start(profile)

    assert result.state is AgentOperationState.FAILED
    assert result.error_category is AgentErrorCategory.SESSION_NOT_FOUND
    assert result.external_session_id is None
    assert runner.commands == []


def test_claude_dispatch_is_bounded_confined_and_privacy_safe(
    fake_claude: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    adapter = _claude_adapter(fake_claude, workspace)
    request = AgentDispatchRequest(
        id="dispatch.claude.1",
        instance_id="overseer.default",
        session_id="session.overseer.default.claude.1",
        driver_epoch_id="epoch.claude.1",
        idempotency_key="key.claude.1",
        prompt="Continue the approved task.",
    )

    result = adapter.dispatch(request)

    assert result.state is AgentOperationState.SUCCEEDED
    assert result.request_id == request.id
    assert result.instance_id == request.instance_id
    assert result.session_id == request.session_id
    assert result.driver_epoch_id == request.driver_epoch_id
    expected_session_id = adapter.last_invocation.argv[
        adapter.last_invocation.argv.index("--session-id") + 1
    ]
    assert result.external_session_id == expected_session_id
    assert result.evidence == {
        "result_type": "result",
        "result_subtype": "success",
        "provider_session_id": expected_session_id,
    }
    assert "private transcript" not in repr(result)
    assert adapter.last_invocation.cwd == str(workspace.resolve())
    assert adapter.last_invocation.input_text == request.prompt
    assert "--permission-mode" in adapter.last_invocation.argv
    assert "plan" in adapter.last_invocation.argv
    assert "--max-budget-usd" in adapter.last_invocation.argv
    assert "--session-id" in adapter.last_invocation.argv
    assert not {
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
        "bypassPermissions",
    }.intersection(adapter.last_invocation.argv)


@pytest.mark.parametrize(
    ("mode", "category"),
    [
        ("json_error", AgentErrorCategory.DISPATCH_REJECTED),
        ("nonzero", AgentErrorCategory.PROVIDER_UNAVAILABLE),
        ("malformed", AgentErrorCategory.PROVIDER_PROTOCOL_ERROR),
        ("oversized", AgentErrorCategory.PROVIDER_PROTOCOL_ERROR),
    ],
)
def test_claude_normalizes_provider_failures_without_raw_output(
    fake_claude: Path,
    tmp_path: Path,
    mode: str,
    category: AgentErrorCategory,
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    adapter = _claude_adapter(fake_claude, workspace, mode=mode)
    request = AgentDispatchRequest(
        id=f"dispatch.claude.{mode}",
        instance_id="overseer.default",
        session_id="session.claude.1",
        driver_epoch_id="epoch.claude.1",
        idempotency_key=f"key.claude.{mode}",
        prompt="bounded prompt",
    )

    result = adapter.dispatch(request)

    assert result.state is AgentOperationState.FAILED
    assert result.error_category is category
    assert "authentication failed" not in repr(result)
    assert "request rejected" not in repr(result)


@pytest.mark.parametrize(
    ("mode", "stream"),
    [("oversized", "stdout"), ("oversized_stderr", "stderr")],
)
def test_cli_runner_bounds_real_process_output_before_materializing_it(
    fake_claude: Path, tmp_path: Path, mode: str, stream: str
) -> None:
    runner = CliCommandRunner(
        executable_path=fake_claude,
        executable_allowlist=(str(fake_claude),),
        environment={**os.environ, "FAKE_CLAUDE_MODE": mode},
    )

    with pytest.raises(CliOutputLimitExceeded, match=stream):
        runner.run_bounded(
            ["claude", "--session-id", "00000000-0000-4000-8000-000000000001"],
            input_text="bounded",
            cwd=tmp_path,
            stdout_limit_bytes=1024,
            stderr_limit_bytes=1024,
        )


def test_claude_resume_requires_proven_external_identity(
    fake_claude: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    adapter = _claude_adapter(fake_claude, workspace)
    session = AgentSession(
        id="session.claude.1",
        provider_id="claude",
        external_session_id="00000000-0000-4000-8000-000000000001",
        workspace=str(workspace),
        transport=AgentTransport.NONINTERACTIVE_CLI,
        capabilities=adapter.provider.capabilities,
        instance_id="overseer.default",
    )

    result = adapter.resume(session)

    assert result.state is AgentOperationState.SUCCEEDED
    resume_index = adapter.last_invocation.argv.index("--resume")
    assert (
        adapter.last_invocation.argv[resume_index + 1]
        == "00000000-0000-4000-8000-000000000001"
    )
    assert result.external_session_id == "00000000-0000-4000-8000-000000000001"
    assert result.session_id == session.id


def test_claude_handoff_prompt_contains_only_normalized_identifiers(
    fake_claude: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    adapter = _claude_adapter(fake_claude, workspace)
    package = AgentHandoffPackage(
        id="handoff.claude.1",
        instance_id="overseer.default",
        outgoing_epoch_id="epoch.codex.1",
        incoming_provider_id="claude",
        objective="Continue the approved objective.",
        checkpoint_id="checkpoint.safe.1",
        evidence={
            "incoming_session_id": "session.claude.2",
            "incoming_epoch_id": "epoch.claude.2",
            "secret_payload": "must-never-appear",
        },
    )

    result = adapter.import_handoff(adapter.profile, package)

    assert result.session_id == "session.claude.2"
    assert result.driver_epoch_id == "epoch.claude.2"
    assert "Continue the approved objective." in adapter.last_invocation.input_text
    assert "checkpoint.safe.1" in adapter.last_invocation.input_text
    assert "handoff.claude.1" in adapter.last_invocation.input_text
    assert "must-never-appear" not in adapter.last_invocation.input_text


@pytest.mark.parametrize("resume", [False, True])
def test_claude_rejects_spoofed_provider_session_identity(
    fake_claude: Path, tmp_path: Path, resume: bool
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    external = "00000000-0000-4000-8000-000000000001" if resume else None
    adapter = _claude_adapter(
        fake_claude, workspace, mode="spoof_identity", external_session_id=external
    )
    request = AgentDispatchRequest(
        id="dispatch.claude.spoof",
        instance_id="overseer.default",
        session_id="session.claude.spoof",
        driver_epoch_id="epoch.claude.spoof",
        idempotency_key="key.claude.spoof",
        prompt="continue",
    )

    result = adapter.dispatch(request)

    assert result.state is AgentOperationState.FAILED
    assert result.error_category is AgentErrorCategory.PROVIDER_PROTOCOL_ERROR
    assert result.external_session_id is None


@pytest.mark.parametrize(
    "mode",
    ["system_shape", "unknown_subtype", "missing_is_error", "nonboolean_is_error"],
)
def test_claude_rejects_nonterminal_or_ambiguous_json_shapes(
    fake_claude: Path, tmp_path: Path, mode: str
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    adapter = _claude_adapter(fake_claude, workspace, mode=mode)
    request = AgentDispatchRequest(
        id=f"dispatch.claude.{mode}",
        instance_id="overseer.default",
        session_id="session.claude.shape",
        driver_epoch_id="epoch.claude.shape",
        idempotency_key=f"key.claude.{mode}",
        prompt="continue",
    )

    result = adapter.dispatch(request)

    assert result.state is AgentOperationState.FAILED
    assert result.error_category is AgentErrorCategory.PROVIDER_PROTOCOL_ERROR


def test_claude_handoff_rejects_foreign_bindings(
    fake_claude: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    adapter = _claude_adapter(fake_claude, workspace)
    valid = AgentHandoffPackage(
        id="handoff.claude.foreign",
        instance_id="overseer.default",
        outgoing_epoch_id="epoch.codex.1",
        incoming_provider_id="claude",
        objective="Continue.",
        evidence={
            "incoming_session_id": "session.claude.2",
            "incoming_epoch_id": "epoch.claude.2",
        },
    )

    with pytest.raises(ValueError, match="profile"):
        adapter.import_handoff(replace(adapter.profile, id="foreign"), valid)
    with pytest.raises(ValueError, match="instance"):
        adapter.import_handoff(
            adapter.profile, replace(valid, instance_id="foreign.instance")
        )
    with pytest.raises(ValueError, match="provider"):
        adapter.import_handoff(
            adapter.profile, replace(valid, incoming_provider_id="codex")
        )


def test_claude_unsupported_operations_do_not_scrape_or_emulate(
    fake_claude: Path, tmp_path: Path
) -> None:
    workspace = tmp_path / "trusted"
    workspace.mkdir()
    adapter = _claude_adapter(fake_claude, workspace)
    session = AgentSession(
        id="session.claude.1",
        provider_id="claude",
        external_session_id=None,
        workspace=str(workspace),
        transport=AgentTransport.NONINTERACTIVE_CLI,
        capabilities=adapter.provider.capabilities,
        instance_id="overseer.default",
    )

    assert adapter.discover() == ()
    assert adapter.resolve("anything") is None
    assert adapter.checkpoint(session).evidence["unsupported_capability"] == "checkpoints"
    assert adapter.cancel(session).error_category is AgentErrorCategory.UNSUPPORTED_CAPABILITY


@pytest.mark.live_agent
def test_live_claude_disposable_structured_dispatch(tmp_path: Path) -> None:
    if os.environ.get("OVERSEER_LIVE_AGENT_PROVIDER") != "claude":
        pytest.skip("live Claude disabled: OVERSEER_LIVE_AGENT_PROVIDER is not claude")
    executable_name = shutil.which("claude")
    if executable_name is None:
        pytest.skip("live Claude disabled: executable is unavailable")
    workspace = tmp_path / "disposable-claude-workspace"
    workspace.mkdir()
    auth_runner = CliCommandRunner(
        executable_path=executable_name,
        executable_allowlist=(Path(executable_name).name, str(Path(executable_name).resolve())),
        environment=dict(os.environ),
    )
    try:
        auth_status = auth_runner.run_bounded(
            ["claude", "auth", "status", "--json"],
            timeout_seconds=15,
            cwd=workspace,
            stdout_limit_bytes=8192,
            stderr_limit_bytes=8192,
        )
        auth_payload = json.loads(auth_status.stdout)
    except (
        OSError,
        subprocess.TimeoutExpired,
        CliOutputLimitExceeded,
        json.JSONDecodeError,
    ):
        pytest.skip("live Claude disabled: auth status could not be verified")
    if (
        auth_status.returncode != 0
        or not isinstance(auth_payload, dict)
        or auth_payload.get("loggedIn") is not True
    ):
        pytest.skip("live Claude disabled: Claude auth status is unauthenticated")
    adapter = _claude_adapter(Path(executable_name), workspace)
    request = AgentDispatchRequest(
        id="dispatch.claude.live",
        instance_id="overseer.default",
        session_id="session.claude.live",
        driver_epoch_id="epoch.claude.live",
        idempotency_key="key.claude.live",
        prompt="Reply with the single word READY. Do not modify files or use tools.",
    )

    result = adapter.dispatch(request)

    assert result.state is AgentOperationState.SUCCEEDED
    assert result.external_session_id
