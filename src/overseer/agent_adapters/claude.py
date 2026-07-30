"""Safe noninteractive Claude Code primary-driver adapter."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from ..agent_contracts import (
    AgentCheckpoint,
    AgentDispatchRequest,
    AgentDispatchResult,
    AgentErrorCategory,
    AgentHandoffPackage,
    AgentInstanceProfile,
    AgentOperationState,
    AgentProvider,
    AgentRecoveryRequest,
    AgentSession,
    AgentTransport,
)
from .base_cli import CliCommandRunner, CliOutputLimitExceeded


MAX_PROMPT_BYTES = 32_768
MAX_OUTPUT_BYTES = 65_536
_DANGEROUS_ARGUMENTS = frozenset(
    {
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
        "bypassPermissions",
    }
)


@dataclass(frozen=True)
class ClaudeInvocation:
    argv: tuple[str, ...]
    cwd: str
    input_text: str


class ClaudeDriver:
    """Claude Code adapter restricted to fixture-proven structured CLI behavior."""

    def __init__(
        self,
        provider: AgentProvider,
        profile: AgentInstanceProfile,
        *,
        runner: CliCommandRunner | None = None,
    ) -> None:
        if provider.id != "claude" or provider.adapter_id != "claude":
            raise ValueError("ClaudeDriver requires the claude provider and adapter")
        if profile.primary_provider_id != "claude":
            raise ValueError("ClaudeDriver profile does not select its provider")
        if profile.transport is not AgentTransport.NONINTERACTIVE_CLI:
            raise ValueError("ClaudeDriver requires noninteractive_cli transport")
        required = (
            provider.capabilities.session_resume,
            provider.capabilities.noninteractive_dispatch,
            provider.capabilities.handoff_import,
        )
        if not all(required):
            raise ValueError("Claude provider lacks required proven capabilities")
        unsupported = (
            provider.capabilities.session_discovery,
            provider.capabilities.interactive_dispatch,
            provider.capabilities.structured_events,
            provider.capabilities.checkpoints,
            provider.capabilities.cancellation,
            provider.capabilities.delegated_workers,
            provider.capabilities.usage_observation,
        )
        if any(unsupported):
            raise ValueError("Claude provider has unsupported capability claims")
        workspace = Path(profile.workspace)
        if not workspace.is_absolute():
            raise ValueError("Claude workspace must be an absolute trusted path")
        self.workspace = workspace.resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("Claude workspace must be a directory")
        self.provider = provider
        self.profile = profile
        if runner is None:
            executable = provider.executable_allowlist[0]
            executable_path = Path(executable)
            if not executable_path.is_absolute():
                raise ValueError("Claude requires a locally resolved executable path")
            runner = CliCommandRunner(
                executable_path=executable_path,
                executable_allowlist=provider.executable_allowlist,
                environment=dict(os.environ),
            )
        self.runner = runner
        self.last_invocation: ClaudeInvocation | None = None

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]:
        return ()

    def resolve(self, reference: str) -> AgentSession | None:
        return None

    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult:
        session_id = f"session.{profile.id}.claude"
        request = AgentDispatchRequest(
            id=f"start.{profile.id}",
            instance_id=profile.id,
            session_id=session_id,
            driver_epoch_id="pending",
            idempotency_key=f"start.{profile.id}",
            prompt="Start the approved Overseer objective.",
        )
        return self.dispatch(request)

    def resume(self, session: AgentSession) -> AgentDispatchResult:
        if not self._valid_session(session) or not session.external_session_id:
            return self._failure(
                request_id=f"resume.{session.id}",
                instance_id=session.instance_id or self.profile.id,
                session_id=session.id,
                epoch_id=self._epoch_id(session),
                category=AgentErrorCategory.SESSION_NOT_FOUND,
                message="Claude resume requires a proven external session identity",
            )
        request = AgentDispatchRequest(
            id=f"resume.{session.id}",
            instance_id=session.instance_id or self.profile.id,
            session_id=session.id,
            driver_epoch_id=self._epoch_id(session),
            idempotency_key=f"resume.{session.id}",
            prompt="Continue the approved Overseer objective.",
        )
        return self._invoke(request, external_session_id=session.external_session_id)

    def recover(
        self, request: AgentRecoveryRequest, session: AgentSession
    ) -> AgentDispatchResult:
        result = self.resume(session)
        return replace(
            result,
            id=f"result.{request.id}",
            request_id=request.id,
            driver_epoch_id=request.driver_epoch_id,
            evidence={
                **result.evidence,
                "recovery_request_id": request.id,
                "adapter_id": self.provider.adapter_id,
            },
        )

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult:
        if request.instance_id != self.profile.id:
            return self._failure(
                request.id,
                request.instance_id,
                request.session_id,
                request.driver_epoch_id,
                AgentErrorCategory.CONFIGURATION_ERROR,
                "dispatch instance does not match Claude driver profile",
            )
        return self._invoke(request, external_session_id=self.profile.external_session_id)

    def inspect(self, session: AgentSession) -> AgentDispatchResult:
        return self._unsupported_session(session, "inspection")

    def checkpoint(self, session: AgentSession) -> AgentCheckpoint:
        return AgentCheckpoint(
            id=f"checkpoint.unsupported.{session.id}",
            instance_id=session.instance_id or self.profile.id,
            session_id=session.id,
            driver_epoch_id=self._epoch_id(session),
            evidence={"unsupported_capability": "checkpoints"},
            created_at=self._now(),
        )

    def cancel(self, session: AgentSession) -> AgentDispatchResult:
        return self._unsupported_session(session, "cancellation")

    def import_handoff(
        self, profile: AgentInstanceProfile, package: AgentHandoffPackage
    ) -> AgentDispatchResult:
        if profile != self.profile:
            raise ValueError("handoff profile does not match Claude driver profile")
        if package.instance_id != self.profile.id:
            raise ValueError("handoff instance does not match Claude driver profile")
        if package.incoming_provider_id != self.provider.id:
            raise ValueError("handoff incoming provider does not match Claude")
        session_id = self._evidence_identifier(package, "incoming_session_id")
        epoch_id = self._evidence_identifier(package, "incoming_epoch_id")
        checkpoint = package.checkpoint_id or "none"
        prompt = (
            f"Continue objective: {package.objective}\n"
            f"Handoff ID: {package.id}\n"
            f"Checkpoint ID: {checkpoint}\n"
            f"Outgoing epoch ID: {package.outgoing_epoch_id}"
        )
        request = AgentDispatchRequest(
            id=f"handoff.{package.id}",
            instance_id=package.instance_id,
            session_id=session_id,
            driver_epoch_id=epoch_id,
            idempotency_key=f"handoff.{package.id}",
            prompt=prompt,
        )
        return self._invoke(request, external_session_id=profile.external_session_id)

    def _invoke(
        self, request: AgentDispatchRequest, *, external_session_id: str | None
    ) -> AgentDispatchResult:
        if len(request.prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            return self._failure(
                request.id,
                request.instance_id,
                request.session_id,
                request.driver_epoch_id,
                AgentErrorCategory.DISPATCH_REJECTED,
                "Claude prompt exceeds adapter limit",
            )
        argv = [
            Path(self.runner.executable_path).name,
            "--print",
            "--output-format",
            "json",
            "--permission-mode",
            "plan",
            "--max-budget-usd",
            "1.00",
        ]
        if external_session_id:
            try:
                expected_session_id = str(uuid.UUID(external_session_id))
            except (ValueError, AttributeError):
                return self._protocol_failure(
                    request, "Claude external session identity is not a UUID"
                )
            argv.extend(("--resume", external_session_id))
        else:
            expected_session_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"overseer:{request.instance_id}:{request.session_id}",
                )
            )
            argv.extend(("--session-id", expected_session_id))
        if _DANGEROUS_ARGUMENTS.intersection(argv):
            raise RuntimeError("dangerous Claude permission flag rejected")
        self.last_invocation = ClaudeInvocation(
            argv=tuple(argv), cwd=str(self.workspace), input_text=request.prompt
        )
        try:
            completed = self.runner.run_bounded(
                argv,
                input_text=request.prompt,
                timeout_seconds=30,
                cwd=self.workspace,
                stdout_limit_bytes=MAX_OUTPUT_BYTES,
                stderr_limit_bytes=MAX_OUTPUT_BYTES,
            )
        except CliOutputLimitExceeded:
            return self._protocol_failure(request, "Claude output exceeds adapter limit")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return self._failure(
                request.id,
                request.instance_id,
                request.session_id,
                request.driver_epoch_id,
                AgentErrorCategory.PROVIDER_UNAVAILABLE,
                "Claude CLI invocation failed",
            )
        if completed.returncode != 0:
            return self._failure(
                request.id,
                request.instance_id,
                request.session_id,
                request.driver_epoch_id,
                AgentErrorCategory.PROVIDER_UNAVAILABLE,
                "Claude CLI exited unsuccessfully",
            )
        try:
            payload = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError):
            return self._protocol_failure(request, "Claude returned malformed JSON")
        if not isinstance(payload, dict):
            return self._protocol_failure(request, "Claude JSON result must be an object")
        provider_session_id = payload.get("session_id")
        if not isinstance(provider_session_id, str) or not provider_session_id.strip():
            return self._protocol_failure(request, "Claude result omitted session identity")
        if provider_session_id != expected_session_id:
            return self._protocol_failure(request, "Claude result session identity mismatch")
        if payload.get("type") != "result":
            return self._protocol_failure(request, "Claude JSON is not a terminal result")
        is_error = payload.get("is_error")
        if not isinstance(is_error, bool):
            return self._protocol_failure(request, "Claude result is_error must be boolean")
        if is_error:
            return self._failure(
                request.id,
                request.instance_id,
                request.session_id,
                request.driver_epoch_id,
                AgentErrorCategory.DISPATCH_REJECTED,
                "Claude rejected the dispatch",
                external_session_id=provider_session_id,
            )
        result_subtype = payload.get("subtype")
        if result_subtype != "success":
            return self._protocol_failure(request, "Claude result subtype is unsupported")
        return AgentDispatchResult(
            id=f"result.{request.id}",
            request_id=request.id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            driver_epoch_id=request.driver_epoch_id,
            provider_id="claude",
            state=AgentOperationState.SUCCEEDED,
            external_session_id=provider_session_id,
            completed_at=self._now(),
            evidence={
                "result_type": "result",
                "result_subtype": result_subtype,
                "provider_session_id": provider_session_id,
            },
        )

    def _protocol_failure(
        self, request: AgentDispatchRequest, message: str
    ) -> AgentDispatchResult:
        return self._failure(
            request.id,
            request.instance_id,
            request.session_id,
            request.driver_epoch_id,
            AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
            message,
        )

    def _unsupported_session(
        self, session: AgentSession, capability: str
    ) -> AgentDispatchResult:
        return self._failure(
            f"{capability}.{session.id}",
            session.instance_id or self.profile.id,
            session.id,
            self._epoch_id(session),
            AgentErrorCategory.UNSUPPORTED_CAPABILITY,
            f"unsupported capability: {capability}",
            external_session_id=session.external_session_id,
            evidence={"unsupported_capability": capability},
        )

    def _failure(
        self,
        request_id: str,
        instance_id: str,
        session_id: str,
        epoch_id: str,
        category: AgentErrorCategory,
        message: str,
        *,
        external_session_id: str | None = None,
        evidence: dict[str, object] | None = None,
    ) -> AgentDispatchResult:
        return AgentDispatchResult(
            id=f"result.{request_id}",
            request_id=request_id,
            instance_id=instance_id,
            session_id=session_id,
            driver_epoch_id=epoch_id,
            provider_id="claude",
            state=AgentOperationState.FAILED,
            error_category=category,
            error_message=message,
            external_session_id=external_session_id,
            completed_at=self._now(),
            evidence=evidence or {},
        )

    def _valid_session(self, session: AgentSession) -> bool:
        return (
            session.provider_id == "claude"
            and session.instance_id in {None, self.profile.id}
            and Path(session.workspace).resolve() == self.workspace
        )

    @staticmethod
    def _epoch_id(session: AgentSession) -> str:
        epoch = session.legacy_references.get("driver_epoch_id")
        return epoch if isinstance(epoch, str) and epoch else "pending"

    @staticmethod
    def _evidence_identifier(package: AgentHandoffPackage, key: str) -> str:
        value = package.evidence.get(key)
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]*", value
        ):
            raise ValueError(f"handoff requires normalized {key}")
        return value

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()


def claude_adapter_factory(
    provider: AgentProvider, profile: AgentInstanceProfile
) -> ClaudeDriver:
    return ClaudeDriver(provider, profile)
