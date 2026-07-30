"""Honest unavailable adapter for the locally unverified Qwen Code interface."""

from __future__ import annotations

from datetime import datetime, timezone

from ..agent_contracts import (
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


class UnavailablePrimaryDriver:
    """Recognize a configured provider without pretending its interface works."""

    provider_id: str
    adapter_id: str
    transport: AgentTransport
    executable_allowlist: tuple[str, ...]

    def __init__(self, provider: AgentProvider, profile: AgentInstanceProfile) -> None:
        if provider.id != self.provider_id or provider.adapter_id != self.adapter_id:
            raise ValueError(f"{self.adapter_id} factory received the wrong provider")
        if provider.transports != (self.transport,):
            raise ValueError(f"{self.adapter_id} provider transport is not verified")
        if provider.executable_allowlist != self.executable_allowlist:
            raise ValueError(f"{self.adapter_id} executable selection is not verified")
        if profile.primary_provider_id != self.provider_id:
            raise ValueError(f"{self.adapter_id} profile does not select its provider")
        if profile.primary_adapter_id != self.adapter_id:
            raise ValueError(f"{self.adapter_id} profile does not select its adapter")
        if profile.transport is not self.transport:
            raise ValueError(f"{self.adapter_id} profile transport is not verified")
        if any(vars(provider.capabilities).values()):
            raise ValueError(f"{self.adapter_id} has unverified capability claims")
        if any(vars(profile.declared_capabilities).values()):
            raise ValueError(f"{self.adapter_id} profile has unverified capability claims")
        self.provider = provider
        self.profile = profile

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]:
        return ()

    def resolve(self, reference: str) -> AgentSession | None:
        return None

    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult:
        if profile != self.profile:
            raise ValueError("start profile does not match unavailable driver profile")
        return self._unavailable(
            f"start.{profile.id}", profile.id, f"session.{profile.id}.{self.provider_id}", "pending"
        )

    def resume(self, session: AgentSession) -> AgentDispatchResult:
        return self._session_unavailable("resume", session)

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult:
        return self._unavailable(
            request.id,
            request.instance_id,
            request.session_id,
            request.driver_epoch_id,
            external_session_id=None,
        )

    def inspect(self, session: AgentSession) -> AgentDispatchResult:
        return self._session_unavailable("inspect", session)

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
        return self._session_unavailable("cancel", session)

    def import_handoff(
        self, profile: AgentInstanceProfile, package: AgentHandoffPackage
    ) -> AgentDispatchResult:
        if profile != self.profile:
            raise ValueError("handoff profile does not match unavailable driver profile")
        if package.instance_id != profile.id:
            raise ValueError("handoff instance does not match unavailable driver profile")
        if package.incoming_provider_id != self.provider_id:
            raise ValueError("handoff incoming provider does not match unavailable driver")
        session_id = package.evidence.get("incoming_session_id")
        epoch_id = package.evidence.get("incoming_epoch_id")
        return self._unavailable(
            f"handoff.{package.id}",
            package.instance_id,
            session_id if isinstance(session_id, str) and session_id else f"session.{package.id}",
            epoch_id if isinstance(epoch_id, str) and epoch_id else package.outgoing_epoch_id,
        )

    def _session_unavailable(
        self, operation: str, session: AgentSession
    ) -> AgentDispatchResult:
        return self._unavailable(
            f"{operation}.{session.id}",
            session.instance_id or self.profile.id,
            session.id,
            self._epoch_id(session),
            external_session_id=session.external_session_id,
        )

    def _unavailable(
        self,
        request_id: str,
        instance_id: str,
        session_id: str,
        epoch_id: str,
        *,
        external_session_id: str | None = None,
    ) -> AgentDispatchResult:
        return AgentDispatchResult(
            id=f"result.{request_id}",
            request_id=request_id,
            instance_id=instance_id,
            session_id=session_id,
            driver_epoch_id=epoch_id,
            provider_id=self.provider_id,
            state=AgentOperationState.FAILED,
            error_category=AgentErrorCategory.PROVIDER_UNAVAILABLE,
            error_message="provider interface is not locally verified",
            external_session_id=external_session_id,
            completed_at=self._now(),
            evidence={"provider_unavailable": True},
        )

    @staticmethod
    def _epoch_id(session: AgentSession) -> str:
        epoch = session.legacy_references.get("driver_epoch_id")
        return epoch if isinstance(epoch, str) and epoch else "pending"

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()


class QwenCodeDriver(UnavailablePrimaryDriver):
    provider_id = "qwen-code"
    adapter_id = "qwen_code"
    transport = AgentTransport.INTERACTIVE_CLI
    executable_allowlist = ("qwen",)


def qwen_code_adapter_factory(
    provider: AgentProvider, profile: AgentInstanceProfile
) -> QwenCodeDriver:
    return QwenCodeDriver(provider, profile)
