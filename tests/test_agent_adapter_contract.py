from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Callable

import pytest

from overseer.agent_adapters.codex import CodexDriver
from overseer.agent_contracts import (
    AgentCapabilities,
    AgentDispatchRequest,
    AgentErrorCategory,
    AgentHandoffPackage,
    AgentInstanceProfile,
    AgentOperationState,
    AgentProvider,
    AgentTransport,
    PrimaryDriver,
)
from overseer.agent_operations import AgentOperationCoordinator
from overseer.store import OverseerStore


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
