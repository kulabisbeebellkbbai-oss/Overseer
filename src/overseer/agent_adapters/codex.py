"""Codex primary-driver adapter backed by the legacy CSV and tmux protocol."""

from __future__ import annotations

import csv
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess
from typing import Callable

from ..agent_contracts import (
    AgentCapabilities,
    AgentCheckpoint,
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentErrorCategory,
    AgentHandoffPackage,
    AgentInstanceProfile,
    AgentOperationState,
    AgentProvider,
    AgentSession,
    AgentTransport,
)
from ..core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from .base_cli import CliCommandRunner


DEFAULT_CODEX_PROJECTS_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
DEFAULT_CODEX_MEMORY_SESSION = Path("/home/god/.local/bin/codex-memory-session")
DEFAULT_TMUX = Path("/usr/bin/tmux")
PROMPT_REJECTION_MARKERS = (
    "message exceeds maximum length",
    "maximum length allowed",
)

_CODEX_CAPABILITIES = AgentCapabilities(
    session_discovery=True,
    session_resume=True,
    interactive_dispatch=True,
    structured_events=False,
    checkpoints=True,
    cancellation=False,
    delegated_workers=False,
    usage_observation=True,
    handoff_import=True,
)

SubprocessRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class LegacyResumeDetails:
    status: str
    reason: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True)
class LegacyPromptDetails:
    status: str
    reason: str
    resume: LegacyResumeDetails
    prompt_exit_code: int | None = None
    enter_exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""


class CodexDriver:
    """Provider-neutral Codex behavior with legacy tmux compatibility."""

    def __init__(
        self,
        provider: AgentProvider,
        profile: AgentInstanceProfile,
        *,
        registry_path: str | Path = DEFAULT_CODEX_PROJECTS_REGISTRY,
        tmux_path: str | Path = DEFAULT_TMUX,
        codex_memory_session_path: str | Path = DEFAULT_CODEX_MEMORY_SESSION,
        runner: CliCommandRunner | SubprocessRunner | None = None,
    ) -> None:
        if provider.id != "codex" or provider.adapter_id != "codex":
            raise ValueError("CodexDriver requires the codex provider and adapter")
        if profile.primary_provider_id != provider.id:
            raise ValueError("CodexDriver profile does not select its provider")
        if profile.transport is not AgentTransport.INTERACTIVE_CLI:
            raise ValueError("CodexDriver requires interactive_cli transport")
        if not provider.capabilities.supports(
            AgentCapabilities(
                session_discovery=True,
                session_resume=True,
                interactive_dispatch=True,
            )
        ):
            raise ValueError("Codex provider lacks required legacy capabilities")
        if any(
            (
                provider.capabilities.noninteractive_dispatch,
                provider.capabilities.structured_events,
                provider.capabilities.cancellation,
                provider.capabilities.delegated_workers,
            )
        ):
            raise ValueError("Codex provider has unsupported capability claims")
        self.provider = provider
        self.profile = profile
        self.registry_path = Path(registry_path)
        self.tmux_path = Path(tmux_path)
        self.codex_memory_session_path = Path(codex_memory_session_path)
        self.runner = runner or CliCommandRunner(
            executable_path=self.tmux_path,
            executable_allowlist=(self.tmux_path.name, str(self.tmux_path)),
            environment=dict(os.environ),
        )
        self._legacy_resume_details: dict[str, LegacyResumeDetails] = {}
        self._legacy_prompt_details: dict[str, LegacyPromptDetails] = {}

    @classmethod
    def from_legacy_registry(
        cls,
        registry_path: str | Path = DEFAULT_CODEX_PROJECTS_REGISTRY,
        *,
        instance_id: str = "legacy.codex",
        workspace: str = ".",
        provider: AgentProvider | None = None,
        profile: AgentInstanceProfile | None = None,
        tmux_path: str | Path = DEFAULT_TMUX,
        codex_memory_session_path: str | Path = DEFAULT_CODEX_MEMORY_SESSION,
        runner: CliCommandRunner | SubprocessRunner | None = None,
    ) -> CodexDriver:
        selected_provider = provider or AgentProvider(
            id="codex",
            adapter_id="codex",
            capabilities=_CODEX_CAPABILITIES,
            transports=(AgentTransport.INTERACTIVE_CLI,),
            executable_allowlist=("codex",),
        )
        selected_profile = profile or AgentInstanceProfile(
            id=instance_id,
            primary_provider_id=selected_provider.id,
            primary_adapter_id=selected_provider.adapter_id,
            transport=AgentTransport.INTERACTIVE_CLI,
            workspace=workspace,
            declared_capabilities=selected_provider.capabilities,
        )
        return cls(
            selected_provider,
            selected_profile,
            registry_path=registry_path,
            tmux_path=tmux_path,
            codex_memory_session_path=codex_memory_session_path,
            runner=runner,
        )

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]:
        if not self.registry_path.exists():
            return ()
        sessions: list[AgentSession] = []
        with self.registry_path.open("r", newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                conversation_id = str(row.get("conversation_id", "")).strip()
                project = str(row.get("project", "")).strip()
                command = str(row.get("command", "")).strip()
                launcher = str(row.get("launcher", "")).strip()
                if not conversation_id or not project or not command:
                    continue
                if workspace is not None and project != workspace:
                    continue
                resource_id = f"thread.codex.{_resource_id_part(command or conversation_id)}"
                sessions.append(
                    AgentSession(
                        id=f"session.codex.{_resource_id_part(command or conversation_id)}",
                        provider_id=self.provider.id,
                        external_session_id=conversation_id,
                        workspace=project,
                        transport=AgentTransport.INTERACTIVE_CLI,
                        capabilities=self.provider.capabilities,
                        instance_id=self.profile.id,
                        model_profile_id=self.profile.model_profile_id,
                        legacy_references={
                            "resource_id": resource_id,
                            "conversation_id": conversation_id,
                            "label": str(row.get("label", "")).strip()
                            or conversation_id,
                            "project": project,
                            "command": command,
                            "launcher": launcher,
                            "source": str(row.get("source", "")).strip(),
                            "notes": str(row.get("notes", "")).strip(),
                        },
                        discovered_at=_optional_text(row.get("created_at")),
                        last_observed_at=_optional_text(row.get("updated_at")),
                    )
                )
        return tuple(sessions)

    def resolve(self, reference: str) -> AgentSession | None:
        wanted = reference.strip()
        if not wanted:
            return None
        for session in self.discover():
            references = session.legacy_references
            exact = {
                session.id,
                session.external_session_id,
                session.workspace,
                str(references.get("command", "")),
                str(references.get("launcher", "")),
                str(references.get("resource_id", "")),
            }
            if wanted in exact:
                return session
            if session.external_session_id and session.external_session_id.startswith(wanted):
                return session
        return None

    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult:
        request_id = f"start.{_identifier_part(profile.id)}"
        session = self._session_for_profile(profile)
        if session is None:
            return self._failure_result(
                request_id=request_id,
                instance_id=profile.id,
                session_id=f"unavailable.{_identifier_part(profile.id)}",
                driver_epoch_id="pending",
                category=AgentErrorCategory.SESSION_NOT_FOUND,
                message="no legacy Codex session matches the configured profile",
            )
        result = self.resume(session)
        return replace(
            result,
            id=f"result.{request_id}",
            request_id=request_id,
            instance_id=profile.id,
            state=(
                AgentOperationState.ACKNOWLEDGED
                if result.state is AgentOperationState.RUNNING
                else result.state
            ),
        )

    def resume(self, session: AgentSession) -> AgentDispatchResult:
        request_id = f"resume.{_identifier_part(session.id)}"
        resolved = self._validated_session(session)
        if resolved is None:
            details = LegacyResumeDetails(
                status="not_found",
                reason="owner_thread was not found in codex-projects registry",
            )
            result = self._failure_result(
                request_id=request_id,
                instance_id=session.instance_id or self.profile.id,
                session_id=session.external_session_id or session.id,
                driver_epoch_id=_session_epoch_id(session),
                category=AgentErrorCategory.SESSION_NOT_FOUND,
                message=details.reason,
                external_session_id=session.external_session_id,
            )
            self._legacy_resume_details[result.id] = details
            return result
        result, details = self._resume_session(
            resolved,
            request_id=request_id,
            result_session_id=resolved.external_session_id or resolved.id,
            driver_epoch_id=_session_epoch_id(session),
        )
        self._legacy_resume_details[result.id] = details
        return result

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult:
        if request.instance_id != self.profile.id:
            return self._failure_result(
                request_id=request.id,
                instance_id=request.instance_id,
                session_id=request.session_id,
                driver_epoch_id=request.driver_epoch_id,
                category=AgentErrorCategory.CONFIGURATION_ERROR,
                message="dispatch instance does not match Codex driver profile",
            )
        session = self.resolve(request.session_id) or self._session_for_profile(self.profile)
        if session is None:
            resume_details = LegacyResumeDetails(
                status="not_found",
                reason="owner_thread was not found in codex-projects registry",
            )
            details = LegacyPromptDetails(
                status="not_found",
                reason=resume_details.reason,
                resume=resume_details,
            )
            result = self._failure_result(
                request_id=request.id,
                instance_id=request.instance_id,
                session_id=request.session_id,
                driver_epoch_id=request.driver_epoch_id,
                category=AgentErrorCategory.SESSION_NOT_FOUND,
                message=details.reason,
            )
            self._legacy_prompt_details[result.id] = details
            return result
        return self._dispatch_session(session, request)

    def dispatch_legacy(
        self,
        session: AgentSession,
        prompt: str,
    ) -> AgentDispatchResult:
        """Dispatch the exact legacy prompt without weakening the generic DTO."""

        if not isinstance(prompt, str):
            raise TypeError("legacy prompt must be a string")
        resolved = self._validated_session(session)
        if resolved is None:
            raise ValueError("cannot dispatch to an unknown Codex session")
        request = AgentDispatchRequest(
            id=f"legacy.dispatch.{resolved.id}",
            instance_id=self.profile.id,
            session_id=resolved.id,
            driver_epoch_id="legacy.codex",
            idempotency_key=f"legacy.dispatch.{resolved.id}",
            prompt="legacy compatibility dispatch",
        )
        return self._dispatch_session(
            resolved,
            request,
            prompt_text=prompt,
        )

    def inspect(self, session: AgentSession) -> AgentDispatchResult:
        request_id = f"inspect.{_identifier_part(session.id)}"
        resolved = self._validated_session(session)
        if resolved is None:
            return self._failure_result(
                request_id=request_id,
                instance_id=session.instance_id or self.profile.id,
                session_id=session.external_session_id or session.id,
                driver_epoch_id=_session_epoch_id(session),
                category=AgentErrorCategory.SESSION_NOT_FOUND,
                message="Codex session was not found",
                external_session_id=session.external_session_id,
            )
        completed = self._run(self._capture_pane_command(resolved))
        if completed.returncode != 0:
            return self._failure_result(
                request_id=request_id,
                instance_id=resolved.instance_id or self.profile.id,
                session_id=resolved.external_session_id or resolved.id,
                driver_epoch_id=_session_epoch_id(session),
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                message="tmux pane inspection failed",
                external_session_id=resolved.external_session_id,
                provider_reference=_legacy_text(resolved, "command"),
            )
        return AgentDispatchResult(
            id=f"result.{request_id}",
            request_id=request_id,
            instance_id=resolved.instance_id or self.profile.id,
            session_id=resolved.external_session_id or resolved.id,
            driver_epoch_id=_session_epoch_id(session),
            provider_id=self.provider.id,
            state=AgentOperationState.RUNNING,
            provider_reference=_legacy_text(resolved, "command"),
            external_session_id=resolved.external_session_id,
            evidence={"status": "running"},
        )

    def checkpoint(self, session: AgentSession) -> AgentCheckpoint:
        resolved = self._validated_session(session)
        if resolved is None:
            raise ValueError("cannot checkpoint an unknown Codex session")
        return AgentCheckpoint(
            id=f"checkpoint.codex.{_identifier_part(resolved.id)}",
            instance_id=resolved.instance_id or self.profile.id,
            session_id=resolved.id,
            driver_epoch_id=_session_epoch_id(session),
            evidence={
                "status": "ready",
                "provider_session_id": resolved.external_session_id or resolved.id,
                "provider_resource_id": str(
                    resolved.legacy_references.get("resource_id", "")
                ),
            },
            created_at=datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        )

    def cancel(self, session: AgentSession) -> AgentDispatchResult:
        request = AgentDispatchRequest(
            id=f"cancel.{_identifier_part(session.id)}",
            instance_id=session.instance_id or self.profile.id,
            session_id=session.external_session_id or session.id,
            driver_epoch_id=_session_epoch_id(session),
            idempotency_key=f"cancel.{_identifier_part(session.id)}",
            prompt="Codex cancellation capability check",
        )
        result = AgentDispatchResult.unsupported(
            request, self.provider.id, "cancellation"
        )
        return replace(
            result,
            external_session_id=session.external_session_id,
            provider_reference=_legacy_text(session, "command"),
        )

    def import_handoff(
        self,
        profile: AgentInstanceProfile,
        package: AgentHandoffPackage,
    ) -> AgentDispatchResult:
        incoming_session_id = package.evidence.get("incoming_session_id")
        incoming_epoch_id = package.evidence.get("incoming_epoch_id")
        request_id = f"handoff.{package.id}"
        if (
            profile.id != package.instance_id
            or package.incoming_provider_id != self.provider.id
            or not isinstance(incoming_session_id, str)
            or not incoming_session_id.strip()
            or not isinstance(incoming_epoch_id, str)
            or not incoming_epoch_id.strip()
        ):
            return self._failure_result(
                request_id=request_id,
                instance_id=package.instance_id,
                session_id=(
                    incoming_session_id
                    if isinstance(incoming_session_id, str) and incoming_session_id
                    else f"unavailable.{_identifier_part(package.instance_id)}"
                ),
                driver_epoch_id=(
                    incoming_epoch_id
                    if isinstance(incoming_epoch_id, str) and incoming_epoch_id
                    else "pending"
                ),
                category=AgentErrorCategory.HANDOFF_INCOMPATIBLE,
                message="Codex handoff package bindings are incomplete",
            )
        request = AgentDispatchRequest(
            id=request_id,
            instance_id=package.instance_id,
            session_id=incoming_session_id,
            driver_epoch_id=incoming_epoch_id,
            idempotency_key=request_id,
            prompt=package.objective,
        )
        return self.dispatch(request)

    def legacy_resume_details(self, result: AgentDispatchResult) -> LegacyResumeDetails:
        return self._legacy_resume_details[result.id]

    def legacy_prompt_details(self, result: AgentDispatchResult) -> LegacyPromptDetails:
        return self._legacy_prompt_details[result.id]

    def _validated_session(self, session: AgentSession) -> AgentSession | None:
        if (
            session.provider_id != self.provider.id
            or session.instance_id not in {None, self.profile.id}
        ):
            return None
        return self.resolve(session.id) or (
            self.resolve(session.external_session_id)
            if session.external_session_id is not None
            else None
        )

    def _session_for_profile(
        self, profile: AgentInstanceProfile
    ) -> AgentSession | None:
        if profile.external_session_id is not None:
            for session in self.discover():
                if session.external_session_id == profile.external_session_id:
                    return session
        workspace_sessions = self.discover(profile.workspace)
        if len(workspace_sessions) == 1:
            return workspace_sessions[0]
        return None

    def _resume_session(
        self,
        session: AgentSession,
        *,
        request_id: str,
        result_session_id: str,
        driver_epoch_id: str,
    ) -> tuple[AgentDispatchResult, LegacyResumeDetails]:
        command_name = _legacy_text(session, "command")
        if self._tmux_session_exists(command_name):
            details = LegacyResumeDetails(
                status="already_running",
                reason="codex project tmux session already exists",
            )
            return (
                self._success_result(
                    request_id=request_id,
                    instance_id=session.instance_id or self.profile.id,
                    session_id=result_session_id,
                    driver_epoch_id=driver_epoch_id,
                    state=AgentOperationState.RUNNING,
                    session=session,
                    status=details.status,
                    reason=details.reason,
                ),
                details,
            )
        command = [
            str(self.tmux_path),
            "new-session",
            "-d",
            "-s",
            command_name,
            "-c",
            session.workspace,
            str(self.codex_memory_session_path),
            "resume",
            session.external_session_id or "",
            "--cd",
            session.workspace,
        ]
        completed = self._run(command)
        status = "resumed" if completed.returncode == 0 else "failed"
        reason = (
            "codex project thread resumed in detached tmux session"
            if completed.returncode == 0
            else "tmux resume command failed"
        )
        details = LegacyResumeDetails(
            status=status,
            reason=reason,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if completed.returncode == 0:
            return (
                self._success_result(
                    request_id=request_id,
                    instance_id=session.instance_id or self.profile.id,
                    session_id=result_session_id,
                    driver_epoch_id=driver_epoch_id,
                    state=AgentOperationState.RUNNING,
                    session=session,
                    status=status,
                    reason=reason,
                    exit_code=completed.returncode,
                ),
                details,
            )
        return (
            self._failure_result(
                request_id=request_id,
                instance_id=session.instance_id or self.profile.id,
                session_id=result_session_id,
                driver_epoch_id=driver_epoch_id,
                category=AgentErrorCategory.PROVIDER_UNAVAILABLE,
                message=reason,
                external_session_id=session.external_session_id,
                provider_reference=command_name,
                evidence={"status": status, "reason": reason, "exit_code": completed.returncode},
            ),
            details,
        )

    def _dispatch_session(
        self,
        session: AgentSession,
        request: AgentDispatchRequest,
        *,
        prompt_text: str | None = None,
    ) -> AgentDispatchResult:
        resume_result, resume_details = self._resume_session(
            session,
            request_id=f"{request.id}.resume",
            result_session_id=session.external_session_id or session.id,
            driver_epoch_id=request.driver_epoch_id,
        )
        self._legacy_resume_details[resume_result.id] = resume_details
        if resume_result.state not in {
            AgentOperationState.ACKNOWLEDGED,
            AgentOperationState.RUNNING,
        }:
            details = LegacyPromptDetails(
                status=resume_details.status,
                reason=resume_details.reason,
                resume=resume_details,
                stdout=resume_details.stdout,
                stderr=resume_details.stderr,
            )
            result = replace(
                resume_result,
                id=f"result.{_identifier_part(request.id)}",
                request_id=request.id,
                session_id=request.session_id,
                driver_epoch_id=request.driver_epoch_id,
            )
            self._legacy_prompt_details[result.id] = details
            return result
        pane_command = self._capture_pane_command(session)
        baseline_result = self._run(pane_command)
        baseline_output = (
            baseline_result.stdout.casefold() if baseline_result.returncode == 0 else ""
        )
        prompt_result = self._run(
            [str(self.tmux_path), "load-buffer", "-b", "overseer-dispatch", "-"],
            input_text=request.prompt if prompt_text is None else prompt_text,
        )
        if prompt_result.returncode != 0:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="failed",
                reason="tmux prompt buffer load failed",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                prompt_exit_code=prompt_result.returncode,
                stdout=prompt_result.stdout,
                stderr=prompt_result.stderr,
            )
        paste_result = self._run(
            [
                str(self.tmux_path),
                "paste-buffer",
                "-b",
                "overseer-dispatch",
                "-t",
                _legacy_text(session, "command"),
            ]
        )
        if paste_result.returncode != 0:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="failed",
                reason="tmux prompt paste failed",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                prompt_exit_code=prompt_result.returncode,
                enter_exit_code=paste_result.returncode,
                stdout=paste_result.stdout,
                stderr=paste_result.stderr,
            )
        enter_result = self._run(
            [
                str(self.tmux_path),
                "send-keys",
                "-t",
                _legacy_text(session, "command"),
                "Enter",
            ]
        )
        if enter_result.returncode != 0:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="failed",
                reason="tmux prompt submit failed",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                prompt_exit_code=prompt_result.returncode,
                enter_exit_code=enter_result.returncode,
                stdout=enter_result.stdout,
                stderr=enter_result.stderr,
            )
        pane_result = self._run(pane_command)
        pane_output = pane_result.stdout.casefold() if pane_result.returncode == 0 else ""
        rejection_marker = next(
            (
                marker
                for marker in PROMPT_REJECTION_MARKERS
                if pane_output.count(marker) > baseline_output.count(marker)
            ),
            None,
        )
        if rejection_marker is not None:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="prompt_rejected",
                reason=f"codex project rejected prompt: {rejection_marker}",
                category=AgentErrorCategory.DISPATCH_REJECTED,
                prompt_exit_code=prompt_result.returncode,
                enter_exit_code=enter_result.returncode,
                stdout=pane_result.stdout,
                stderr=pane_result.stderr,
            )
        reason = "prompt submitted to codex project; advisory result not yet confirmed"
        details = LegacyPromptDetails(
            status="prompt_dispatched",
            reason=reason,
            resume=resume_details,
            prompt_exit_code=prompt_result.returncode,
            enter_exit_code=enter_result.returncode,
            stdout=enter_result.stdout,
            stderr=enter_result.stderr,
        )
        result = self._success_result(
            request_id=request.id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            driver_epoch_id=request.driver_epoch_id,
            state=AgentOperationState.ACKNOWLEDGED,
            session=session,
            status=details.status,
            reason=reason,
            exit_code=enter_result.returncode,
        )
        self._legacy_prompt_details[result.id] = details
        return result

    def _prompt_failure(
        self,
        request: AgentDispatchRequest,
        session: AgentSession,
        resume_details: LegacyResumeDetails,
        *,
        status: str,
        reason: str,
        category: AgentErrorCategory,
        prompt_exit_code: int | None = None,
        enter_exit_code: int | None = None,
        stdout: str = "",
        stderr: str = "",
    ) -> AgentDispatchResult:
        details = LegacyPromptDetails(
            status=status,
            reason=reason,
            resume=resume_details,
            prompt_exit_code=prompt_exit_code,
            enter_exit_code=enter_exit_code,
            stdout=stdout,
            stderr=stderr,
        )
        result = self._failure_result(
            request_id=request.id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            driver_epoch_id=request.driver_epoch_id,
            category=category,
            message=reason,
            external_session_id=session.external_session_id,
            provider_reference=_legacy_text(session, "command"),
            evidence={
                "status": status,
                "reason": reason,
                **(
                    {"prompt_exit_code": prompt_exit_code}
                    if prompt_exit_code is not None
                    else {}
                ),
                **(
                    {"enter_exit_code": enter_exit_code}
                    if enter_exit_code is not None
                    else {}
                ),
            },
        )
        self._legacy_prompt_details[result.id] = details
        return result

    def _success_result(
        self,
        *,
        request_id: str,
        instance_id: str,
        session_id: str,
        driver_epoch_id: str,
        state: AgentOperationState,
        session: AgentSession,
        status: str,
        reason: str,
        exit_code: int | None = None,
    ) -> AgentDispatchResult:
        return AgentDispatchResult(
            id=f"result.{_identifier_part(request_id)}",
            request_id=request_id,
            instance_id=instance_id,
            session_id=session_id,
            driver_epoch_id=driver_epoch_id,
            provider_id=self.provider.id,
            state=state,
            provider_reference=_legacy_text(session, "command"),
            external_session_id=session.external_session_id,
            evidence={
                "status": status,
                "reason": reason,
                **({"exit_code": exit_code} if exit_code is not None else {}),
            },
        )

    def _failure_result(
        self,
        *,
        request_id: str,
        instance_id: str,
        session_id: str,
        driver_epoch_id: str,
        category: AgentErrorCategory,
        message: str,
        external_session_id: str | None = None,
        provider_reference: str | None = None,
        evidence: dict[str, object] | None = None,
    ) -> AgentDispatchResult:
        return AgentDispatchResult(
            id=f"result.{_identifier_part(request_id)}",
            request_id=request_id,
            instance_id=instance_id,
            session_id=session_id,
            driver_epoch_id=driver_epoch_id,
            provider_id=self.provider.id,
            state=AgentOperationState.FAILED,
            error_category=category,
            error_message=message,
            provider_reference=provider_reference,
            external_session_id=external_session_id,
            evidence=evidence or {"status": "failed", "reason": category.value},
        )

    def _capture_pane_command(self, session: AgentSession) -> list[str]:
        return [
            str(self.tmux_path),
            "capture-pane",
            "-p",
            "-t",
            _legacy_text(session, "command"),
            "-S",
            "-200",
        ]

    def _tmux_session_exists(self, session: str) -> bool:
        completed = self._run(
            [str(self.tmux_path), "has-session", "-t", session]
        )
        return completed.returncode == 0

    def _run(
        self,
        command: list[str],
        *,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if isinstance(self.runner, CliCommandRunner):
            return self.runner.run(command, input_text=input_text)
        if input_text is None:
            return self.runner(command, text=True, capture_output=True)
        return self.runner(
            command,
            input=input_text,
            text=True,
            capture_output=True,
        )


def codex_adapter_factory(
    provider: AgentProvider,
    profile: AgentInstanceProfile,
) -> CodexDriver:
    """Build the installed Codex adapter for the hardened registry."""

    return CodexDriver(provider, profile)


def legacy_codex_session_resource(session: AgentSession) -> Resource:
    """Map an imported generic Codex session to its unchanged legacy resource."""

    if session.provider_id != "codex":
        raise ValueError("legacy Codex resources require a codex session")
    resource_id = str(
        session.legacy_references.get(
            "resource_id",
            f"thread.codex.{_resource_id_part(session.id)}",
        )
    )
    return Resource(
        id=resource_id,
        name=str(
            session.legacy_references.get(
                "label", session.external_session_id or session.id
            )
        ),
        type=ResourceType.USAGE_LIMITED_SERVICE,
        owner_domain=OwnerDomain.QUARK,
        risk_level=RiskLevel.LOW,
        state=ResourceState.AVAILABLE,
        identifiers={
            "conversation_id": session.external_session_id or "",
            "project": session.workspace,
            "command": _legacy_text(session, "command"),
            "launcher": _legacy_text(session, "launcher"),
            "agent_session_id": session.id,
        },
        notes="Codex project thread imported from local codex-projects registry",
    )


def _legacy_text(session: AgentSession, key: str) -> str:
    return str(session.legacy_references.get(key, ""))


def _optional_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _session_epoch_id(session: AgentSession) -> str:
    epoch_id = session.legacy_references.get("driver_epoch_id")
    return str(epoch_id) if isinstance(epoch_id, str) and epoch_id else "pending"


def _identifier_part(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-")
    return cleaned or "unknown"


def _resource_id_part(value: str) -> str:
    return _identifier_part(value.lower())


__all__ = [
    "CodexDriver",
    "DEFAULT_CODEX_MEMORY_SESSION",
    "DEFAULT_CODEX_PROJECTS_REGISTRY",
    "DEFAULT_TMUX",
    "LegacyPromptDetails",
    "LegacyResumeDetails",
    "PROMPT_REJECTION_MARKERS",
    "codex_adapter_factory",
    "legacy_codex_session_resource",
]
