"""Legacy Codex project façade backed by the provider-neutral Codex driver."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess

from .agent_adapters.codex import (
    DEFAULT_CODEX_MEMORY_SESSION,
    DEFAULT_CODEX_PROJECTS_REGISTRY,
    DEFAULT_TMUX,
    PROMPT_REJECTION_MARKERS,
    CodexDriver,
    LegacyPromptDetails,
    LegacyResumeDetails,
    legacy_codex_session_resource,
)
from .agent_contracts import AgentSession
from .core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel


@dataclass(frozen=True)
class CodexProjectThread:
    conversation_id: str
    label: str
    project: str
    command: str
    launcher: str


@dataclass(frozen=True)
class CodexProjectResumeResult:
    owner_thread: str
    status: str
    reason: str
    conversation_id: str | None = None
    project: str | None = None
    command: str | None = None
    launcher: str | None = None
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class CodexProjectPromptDispatchResult:
    owner_thread: str
    status: str
    reason: str
    resume_result: CodexProjectResumeResult
    prompt_exit_code: int | None = None
    enter_exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""


class CodexProjectThreadAdapter:
    """Compatibility surface retaining the original DTOs and call signatures."""

    def __init__(
        self,
        registry_path: str | Path = DEFAULT_CODEX_PROJECTS_REGISTRY,
        tmux_path: str | Path = DEFAULT_TMUX,
        codex_memory_session_path: str | Path = DEFAULT_CODEX_MEMORY_SESSION,
        runner=subprocess.run,
    ) -> None:
        self.registry_path = Path(registry_path)
        self.tmux_path = Path(tmux_path)
        self.codex_memory_session_path = Path(codex_memory_session_path)
        self.runner = runner
        self.driver = CodexDriver.from_legacy_registry(
            self.registry_path,
            tmux_path=self.tmux_path,
            codex_memory_session_path=self.codex_memory_session_path,
            runner=runner,
        )

    def list_threads(self) -> tuple[CodexProjectThread, ...]:
        return tuple(_thread_from_session(session) for session in self.driver.discover())

    def resolve(self, owner_thread: str) -> CodexProjectThread | None:
        session = self._resolve_legacy_session(owner_thread)
        return _thread_from_session(session) if session is not None else None

    def resume(self, owner_thread: str) -> CodexProjectResumeResult:
        session = self._resolve_legacy_session(owner_thread)
        if session is None:
            return CodexProjectResumeResult(
                owner_thread=owner_thread,
                status="not_found",
                reason="owner_thread was not found in codex-projects registry",
            )
        result = self.driver.resume(session)
        details = self.driver.legacy_resume_details(result)
        return _legacy_resume_result(owner_thread, session, details)

    def dispatch_prompt(
        self,
        owner_thread: str,
        prompt: str,
    ) -> CodexProjectPromptDispatchResult:
        session = self._resolve_legacy_session(owner_thread)
        if session is None:
            resume_result = CodexProjectResumeResult(
                owner_thread=owner_thread,
                status="not_found",
                reason="owner_thread was not found in codex-projects registry",
            )
            return CodexProjectPromptDispatchResult(
                owner_thread=owner_thread,
                status=resume_result.status,
                reason=resume_result.reason,
                resume_result=resume_result,
            )
        result = self.driver.dispatch_legacy(session, prompt)
        details = self.driver.legacy_prompt_details(result)
        return _legacy_prompt_result(owner_thread, session, details)

    def _resolve_legacy_session(self, owner_thread: str) -> AgentSession | None:
        wanted = owner_thread.strip()
        if not wanted:
            return None
        for session in self.driver.discover():
            thread = _thread_from_session(session)
            if wanted == thread.conversation_id:
                return session
            if wanted == thread.command:
                return session
            if wanted == thread.launcher:
                return session
            if wanted == thread.project:
                return session
            if thread.conversation_id.startswith(wanted):
                return session
        return None


def codex_project_thread_resource(thread: CodexProjectThread) -> Resource:
    return Resource(
        id=f"thread.codex.{_resource_id_part(thread.command or thread.conversation_id)}",
        name=thread.label,
        type=ResourceType.USAGE_LIMITED_SERVICE,
        owner_domain=OwnerDomain.QUARK,
        risk_level=RiskLevel.LOW,
        state=ResourceState.AVAILABLE,
        identifiers={
            "conversation_id": thread.conversation_id,
            "project": thread.project,
            "command": thread.command,
            "launcher": thread.launcher,
        },
        notes="Codex project thread imported from local codex-projects registry",
    )


def codex_project_thread_resources(
    threads: tuple[CodexProjectThread, ...],
) -> tuple[Resource, ...]:
    return tuple(codex_project_thread_resource(thread) for thread in threads)


def _thread_from_session(session: AgentSession) -> CodexProjectThread:
    references = session.legacy_references
    return CodexProjectThread(
        conversation_id=session.external_session_id or "",
        label=str(references.get("label", session.external_session_id or session.id)),
        project=session.workspace,
        command=str(references.get("command", "")),
        launcher=str(references.get("launcher", "")),
    )


def _legacy_resume_result(
    owner_thread: str,
    session: AgentSession,
    details: LegacyResumeDetails,
) -> CodexProjectResumeResult:
    thread = _thread_from_session(session)
    return CodexProjectResumeResult(
        owner_thread=owner_thread,
        status=details.status,
        reason=details.reason,
        conversation_id=thread.conversation_id,
        project=thread.project,
        command=thread.command,
        launcher=thread.launcher,
        exit_code=details.exit_code,
        stdout=details.stdout,
        stderr=details.stderr,
    )


def _legacy_prompt_result(
    owner_thread: str,
    session: AgentSession,
    details: LegacyPromptDetails,
) -> CodexProjectPromptDispatchResult:
    return CodexProjectPromptDispatchResult(
        owner_thread=owner_thread,
        status=details.status,
        reason=details.reason,
        resume_result=_legacy_resume_result(owner_thread, session, details.resume),
        prompt_exit_code=details.prompt_exit_code,
        enter_exit_code=details.enter_exit_code,
        stdout=details.stdout,
        stderr=details.stderr,
    )


def _resource_id_part(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip().lower()).strip("-")
    return cleaned or "unknown"


__all__ = [
    "CodexProjectPromptDispatchResult",
    "CodexProjectResumeResult",
    "CodexProjectThread",
    "CodexProjectThreadAdapter",
    "DEFAULT_CODEX_MEMORY_SESSION",
    "DEFAULT_CODEX_PROJECTS_REGISTRY",
    "DEFAULT_TMUX",
    "PROMPT_REJECTION_MARKERS",
    "codex_project_thread_resource",
    "codex_project_thread_resources",
    "legacy_codex_session_resource",
]
