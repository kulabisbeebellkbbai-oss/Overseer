"""Codex primary-driver adapter backed by the legacy CSV and tmux protocol."""

from __future__ import annotations

import csv
import fcntl
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Callable, Protocol

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
    AgentRecoveryRequest,
    AgentSession,
    AgentTransport,
)
from ..core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel
from .base_cli import CliCommandRunner, CliOutputLimitExceeded


DEFAULT_CODEX_PROJECTS_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
DEFAULT_CODEX_MEMORY_SESSION = Path("/home/god/.local/bin/codex-memory-session")
DEFAULT_CODEX_STATE_DATABASE = Path("/home/god/.codex/state_5.sqlite")
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

CODEX_COMMAND_TIMEOUT_SECONDS = 30
CODEX_OUTPUT_LIMIT_BYTES = 65_536
# Codex's interactive prompt keeps pasted text in its bracketed paste
# aggregation window for a short period. Sending Enter immediately after
# paste-buffer can leave the text queued instead of submitting it. Keep this
# interval explicit and bounded so dispatch has one deterministic submit
# attempt and tests can inject a non-blocking sleeper.
# Live Codex testing showed submission only after more than four seconds of
# post-paste aggregation. A 4.5 second margin stays bounded while covering
# that observed boundary before the single Enter attempt.
CODEX_PASTE_SETTLE_SECONDS = 4.5


_THREAD_DISPATCH_LOCKS_GUARD = threading.Lock()
_THREAD_DISPATCH_LOCKS: dict[str, threading.RLock] = {}


@contextmanager
def _thread_dispatch_lock(session: AgentSession):
    """Serialize every local transport touching one immutable Codex thread."""
    key = session.external_session_id or session.id
    with _THREAD_DISPATCH_LOCKS_GUARD:
        lock = _THREAD_DISPATCH_LOCKS.setdefault(key, threading.RLock())
    with lock:
        yield


def _structured_thread_marker(root: Path, session: AgentSession) -> Path:
    thread_id = session.external_session_id or session.id
    return root / (hashlib.sha256(thread_id.encode("utf-8")).hexdigest() + ".structured")


class BoundedCommandRunner(Protocol):
    executable_path: str | Path

    def run_bounded(
        self,
        argv: list[str],
        input_text: str | None = None,
        timeout_seconds: float = 30,
        cwd: str | Path | None = None,
        *,
        stdout_limit_bytes: int,
        stderr_limit_bytes: int,
    ) -> subprocess.CompletedProcess[str]: ...


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


class PromptDeliveryEvidence(Protocol):
    """Bounded evidence reader for one exact prompt dispatch."""

    def confirm(self, prompt: str) -> bool: ...


class StructuredTurnClient(Protocol):
    def submit_bound_turn(
        self,
        *,
        thread_id: str,
        prompt: str,
        client_message_id: str,
        cwd: str,
        phase_callback: Callable[[str], None],
    ) -> dict[str, str]: ...


class RolloutPromptDeliveryEvidence:
    """Confirm a prompt through the newly appended Codex rollout records."""

    def __init__(self, session: AgentSession, *, state_database: str | Path = DEFAULT_CODEX_STATE_DATABASE) -> None:
        self._session_id = session.id
        self._conversation_id = session.external_session_id or session.id
        self._rollout = _rollout_path_for_session(session, Path(state_database))
        metadata = self._rollout.stat(follow_symlinks=False)
        self._identity = (metadata.st_dev, metadata.st_ino)
        self._offset = metadata.st_size

    def provenance(self, *, found: bool = False) -> dict[str, object]:
        return {"found": found, "conversationId": self._conversation_id, "sessionId": self._session_id, "rolloutPathDigest": hashlib.sha256(str(self._rollout).encode("utf-8")).hexdigest(), "rolloutDev": self._identity[0], "rolloutIno": self._identity[1]}

    def confirm(self, prompt: str) -> bool:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                descriptor = os.open(self._rollout, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    metadata = os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) != self._identity:
                        return False
                    appended = os.pread(descriptor, 256 * 1024, self._offset).decode("utf-8")
                finally:
                    os.close(descriptor)
            except (OSError, UnicodeError):
                return False
            for line in appended.splitlines():
                try:
                    record = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if _rollout_user_prompt(record) == prompt:
                    return True
            time.sleep(0.25)
        return False

    def scan_existing(self, prompt: str) -> bool:
        """Scan the complete bound rollout, including records before recovery."""
        return bool(self.scan_existing_provenance(prompt)["found"])

    def scan_existing_provenance(self, prompt: str) -> dict[str, object]:
        """Scan the complete rollout and return its immutable identity."""
        descriptor: int | None = None
        try:
            descriptor = os.open(self._rollout, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != self._identity:
                raise ValueError("rollout identity changed")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = None
                for line in stream:
                    try:
                        if _rollout_user_prompt(json.loads(line)) == prompt:
                            return self.provenance(found=True)
                    except (ValueError, TypeError):
                        continue
        except UnicodeError as error:
            raise ValueError("rollout scan failed") from error
        except OSError as error:
            raise ValueError("rollout scan unavailable") from error
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        return self.provenance(found=False)


def _jsonl_records(content: str):
    for line in content.splitlines():
        try:
            yield json.loads(line)
        except (ValueError, TypeError):
            continue


def _rollout_path_for_session(session: AgentSession, state_database: Path) -> Path:
    conversation_id = session.external_session_id or session.id
    try:
        with sqlite3.connect(f"file:{state_database}?mode=ro", uri=True, timeout=1.0) as database:
            row = database.execute("SELECT rollout_path FROM threads WHERE id = ?", (conversation_id,)).fetchone()
    except (OSError, sqlite3.Error) as error:
        raise ValueError("Codex rollout index is unavailable") from error
    if row is None or not isinstance(row[0], str) or not row[0].strip():
        raise ValueError("Codex rollout is not bound to the conversation")
    rollout = Path(row[0])
    if not rollout.is_absolute():
        raise ValueError("Codex rollout path is not absolute")
    try:
        resolved = rollout.resolve(strict=True)
        sessions_root = Path("/home/god/.codex/sessions").resolve(strict=True)
        relative = resolved.relative_to(sessions_root)
        metadata = resolved.stat()
    except (OSError, ValueError) as error:
        raise ValueError("Codex rollout path is not private") from error
    # Codex currently creates its private state tree as 0775/0664 under the
    # user's primary, single-member group. Trust that existing boundary while
    # rejecting a foreign group, any world-writable file, or a non-owner file.
    if not resolved.is_file() or metadata.st_uid != os.getuid() or metadata.st_gid != os.getegid() or metadata.st_mode & 0o002:
        raise ValueError("Codex rollout path is not private")
    current = sessions_root
    for component in relative.parts[:-1]:
        current = current / component
        parent = current.stat(follow_symlinks=False)
        if not current.is_dir() or parent.st_uid != os.getuid() or parent.st_gid != os.getegid() or parent.st_mode & 0o002:
            raise ValueError("Codex rollout path is not private")
    return resolved


def _rollout_user_prompt(record: object) -> str | None:
    if not isinstance(record, dict):
        return None
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return None
    if record.get("type") == "event_msg" and payload.get("type") == "user_message":
        message = payload.get("message")
        return message if isinstance(message, str) else None
    if record.get("type") != "response_item" or payload.get("role") != "user" or payload.get("type") != "message":
        return None
    content = payload.get("content")
    if not isinstance(content, list):
        return None
    text = "".join(
        item.get("text", "")
        for item in content
        if isinstance(item, dict) and item.get("type") == "input_text" and isinstance(item.get("text", ""), str)
    )
    return text or None


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
        runner: BoundedCommandRunner | None = None,
        delivery_evidence_factory=None,
        structured_turn_client: StructuredTurnClient | None = None,
        structured_thread_fence_root: str | Path | None = None,
        sleep: Callable[[float], None] = time.sleep,
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
        self.runner: BoundedCommandRunner = runner or CliCommandRunner(
            executable_path=self.tmux_path,
            executable_allowlist=(self.tmux_path.name, str(self.tmux_path)),
            environment=dict(os.environ),
        )
        if not callable(getattr(self.runner, "run_bounded", None)):
            raise TypeError("Codex runner must implement bounded command capture")
        self._legacy_resume_details: dict[str, LegacyResumeDetails] = {}
        self._legacy_prompt_details: dict[str, LegacyPromptDetails] = {}
        self.delivery_evidence_factory = delivery_evidence_factory or (lambda session: RolloutPromptDeliveryEvidence(session))
        self.structured_turn_client = structured_turn_client
        self.structured_thread_fence_root = Path(
            structured_thread_fence_root
            if structured_thread_fence_root is not None
            else self.registry_path.parent / ".overseer-structured-threads"
        )
        if not callable(sleep):
            raise TypeError("Codex sleep hook must be callable")
        self._sleep = sleep

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
        delivery_evidence_factory=None,
        structured_turn_client: StructuredTurnClient | None = None,
        structured_thread_fence_root: str | Path | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> CodexDriver:
        selected_structured_turn_client = structured_turn_client
        if selected_structured_turn_client is None and os.environ.get("OVERSEER_CODEX_APP_SERVER_DISPATCH") == "1":
            from ..codex_usage import CodexAppServerClient

            selected_structured_turn_client = CodexAppServerClient(timeout=15.0)
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
            delivery_evidence_factory=delivery_evidence_factory,
            structured_turn_client=selected_structured_turn_client,
            structured_thread_fence_root=structured_thread_fence_root,
            sleep=sleep,
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
        *,
        idempotency_key: str | None = None,
        prompt_marker: str | None = None,
        phase_callback: Callable[[str], None] | None = None,
    ) -> AgentDispatchResult:
        """Dispatch the exact legacy prompt without weakening the generic DTO."""

        request = self.prepare_legacy_dispatch(
            session,
            prompt,
            idempotency_key=idempotency_key,
        )
        resolved = self._validated_session(session)
        if resolved is None:
            raise ValueError("cannot dispatch to an unknown Codex session")
        return self._dispatch_session(
            resolved,
            request,
            prompt_text=prompt,
            prompt_marker=prompt_marker,
            phase_callback=phase_callback,
        )

    def prepare_legacy_dispatch(
        self,
        session: AgentSession,
        prompt: str,
        *,
        idempotency_key: str | None = None,
    ) -> AgentDispatchRequest:
        """Return the stable dispatch identity without producing an external effect."""

        if not isinstance(prompt, str):
            raise TypeError("legacy prompt must be a string")
        resolved = self._validated_session(session)
        if resolved is None:
            raise ValueError("cannot dispatch to an unknown Codex session")
        dispatch_key = idempotency_key or f"legacy.dispatch.{resolved.id}"
        if not isinstance(dispatch_key, str) or not dispatch_key.strip():
            raise ValueError("legacy dispatch idempotency key must be non-empty")
        return AgentDispatchRequest(
            id=(f"legacy.dispatch.{resolved.id}" if idempotency_key is None else f"legacy.dispatch.{hashlib.sha256(dispatch_key.encode()).hexdigest()}"),
            instance_id=self.profile.id,
            session_id=resolved.id,
            driver_epoch_id="legacy.codex",
            idempotency_key=dispatch_key,
            prompt="legacy compatibility dispatch",
        )

    def scan_rollout_prompt(self, session: AgentSession, prompt: str) -> dict[str, object]:
        """Return whether the exact prompt is already recorded in the rollout."""
        resolved = self._validated_session(session)
        if resolved is None:
            raise ValueError("cannot scan an unknown Codex session")
        return RolloutPromptDeliveryEvidence(resolved).scan_existing_provenance(prompt)

    def rollout_provenance(self, session: AgentSession) -> dict[str, object]:
        resolved = self._validated_session(session)
        if resolved is None:
            raise ValueError("cannot inspect an unknown Codex session")
        return RolloutPromptDeliveryEvidence(resolved).provenance()

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
            return None
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
        with self._thread_operation_lock(session):
            return self._resume_session_locked(
                session,
                request_id=request_id,
                result_session_id=result_session_id,
                driver_epoch_id=driver_epoch_id,
            )

    def _resume_session_locked(
        self,
        session: AgentSession,
        *,
        request_id: str,
        result_session_id: str,
        driver_epoch_id: str,
    ) -> tuple[AgentDispatchResult, LegacyResumeDetails]:
        if self._structured_thread_is_fenced(session):
            details = LegacyResumeDetails(
                status="failed",
                reason="structured Codex thread cannot be resumed through tmux",
            )
            return (
                self._failure_result(
                    request_id=request_id,
                    instance_id=session.instance_id or self.profile.id,
                    session_id=result_session_id,
                    driver_epoch_id=driver_epoch_id,
                    category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                    message=details.reason,
                    external_session_id=session.external_session_id,
                    provider_reference=_legacy_text(session, "command"),
                ),
                details,
            )
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
        prompt_marker: str | None = None,
        phase_callback: Callable[[str], None] | None = None,
    ) -> AgentDispatchResult:
        with self._thread_operation_lock(session):
            return self._dispatch_session_locked(
                session,
                request,
                prompt_text=prompt_text,
                prompt_marker=prompt_marker,
                phase_callback=phase_callback,
            )

    def _dispatch_session_locked(
        self,
        session: AgentSession,
        request: AgentDispatchRequest,
        *,
        prompt_text: str | None = None,
        prompt_marker: str | None = None,
        phase_callback: Callable[[str], None] | None = None,
    ) -> AgentDispatchResult:
        dispatch_prompt = request.prompt if prompt_text is None else prompt_text
        # Structured app-server delivery is a round-only transport.  The
        # durable phase callback is the bridge-owned external-effect fence;
        # ordinary coordination and supervisor dispatches intentionally stay
        # on the legacy path even when the feature is enabled.
        if self.structured_turn_client is not None and phase_callback is not None:
            return self._dispatch_structured_session(
                session,
                request,
                dispatch_prompt,
                prompt_marker=prompt_marker,
                phase_callback=phase_callback,
            )
        # The outer dispatch operation already owns the process and file
        # locks, so call the locked resume primitive directly.
        resume_result, resume_details = self._resume_session_locked(
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
        delivery_evidence: PromptDeliveryEvidence | None = None
        if prompt_marker is not None:
            try:
                delivery_evidence = self.delivery_evidence_factory(session)
            except (OSError, ValueError):
                return self._prompt_failure(
                    request,
                    session,
                    resume_details,
                    status="delivery_unconfirmed",
                    reason="codex rollout is not bound to the exact conversation",
                    category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                )
        pane_command = self._capture_pane_command(session)
        baseline_result = self._run(pane_command)
        baseline_output = (
            baseline_result.stdout.casefold() if baseline_result.returncode == 0 else ""
        )
        if phase_callback is not None:
            try:
                phase_callback("prepared")
            except Exception as error:
                return self._prompt_failure(
                    request,
                    session,
                    resume_details,
                    status="failed",
                    reason="codex dispatch phase persistence failed",
                    category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                    stderr=str(error),
                )
        prompt_result = self._run(
            [str(self.tmux_path), "load-buffer", "-b", "overseer-dispatch", "-"],
            input_text=dispatch_prompt,
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
        if phase_callback is not None:
            try:
                phase_callback("paste-intent")
            except Exception as error:
                return self._prompt_failure(
                    request,
                    session,
                    resume_details,
                    status="failed",
                    reason="codex dispatch phase persistence failed",
                    category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                    prompt_exit_code=prompt_result.returncode,
                    stdout=prompt_result.stdout,
                    stderr=str(error),
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
        # Codex aggregates bracketed paste input for a short window. Wait for
        # that window to close before the one and only submit key; retrying
        # Enter or pasting again could duplicate an already accepted prompt.
        try:
            self._sleep(CODEX_PASTE_SETTLE_SECONDS)
        except Exception as error:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="failed",
                reason="tmux prompt settle wait failed",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                prompt_exit_code=prompt_result.returncode,
                stdout=paste_result.stdout,
                stderr=str(error),
            )
        if phase_callback is not None:
            try:
                phase_callback("submit-intent")
            except Exception as error:
                return self._prompt_failure(
                    request,
                    session,
                    resume_details,
                    status="failed",
                    reason="codex dispatch phase persistence failed",
                    category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                    prompt_exit_code=prompt_result.returncode,
                    stdout=paste_result.stdout,
                    stderr=str(error),
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
        if phase_callback is not None:
            try:
                phase_callback("submitted")
            except Exception as error:
                return self._prompt_failure(
                    request,
                    session,
                    resume_details,
                    status="failed",
                    reason="codex dispatch phase persistence failed",
                    category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                    prompt_exit_code=prompt_result.returncode,
                    enter_exit_code=enter_result.returncode,
                    stdout=enter_result.stdout,
                    stderr=str(error),
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
        # A successful tmux paste/send-keys sequence only proves that tmux
        # accepted the commands.  A resumed legacy session may still be idle
        # (or attached to a stale Codex process), in which case treating the
        # sequence as an ACK falsely confirms this bounded round.  Require a
        # successful pane capture whose content changed after submission as
        # the minimum observable delivery proof.  The bridge persists the
        # resulting dispatch only after this boundary.
        if delivery_evidence is not None and (baseline_result.returncode != 0 or pane_result.returncode != 0):
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="delivery_unconfirmed",
                reason="codex project did not confirm prompt delivery",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                prompt_exit_code=prompt_result.returncode,
                enter_exit_code=enter_result.returncode,
                stdout=pane_result.stdout,
                stderr=pane_result.stderr,
            )
        if delivery_evidence is not None and not delivery_evidence.confirm(dispatch_prompt):
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="delivery_unconfirmed",
                reason="codex rollout did not record the exact prompt",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
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
            evidence={
                "prompt_digest": hashlib.sha256(dispatch_prompt.encode("utf-8")).hexdigest(),
                "delivery_proof": "rollout-user-message" if delivery_evidence is not None else "legacy-tmux-advisory",
                **({"prompt_marker": prompt_marker} if prompt_marker is not None else {}),
            },
        )
        self._legacy_prompt_details[result.id] = details
        return result

    def _dispatch_structured_session(
        self,
        session: AgentSession,
        request: AgentDispatchRequest,
        dispatch_prompt: str,
        *,
        prompt_marker: str | None,
        phase_callback: Callable[[str], None] | None,
    ) -> AgentDispatchResult:
        thread_id = session.external_session_id
        resume_details = LegacyResumeDetails(
            status="structured",
            reason="codex app-server exact thread binding",
        )
        if not isinstance(thread_id, str) or not thread_id.strip() or phase_callback is None:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="delivery_unconfirmed",
                reason="codex structured dispatch lacks durable thread or phase binding",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
            )
        session_check = self._run(
            [
                str(self.tmux_path),
                "has-session",
                "-t",
                _legacy_text(session, "command"),
            ]
        )
        if session_check.returncode == 0:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="delivery_unconfirmed",
                reason="live interactive codex session prevents structured dispatch",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
            )
        if session_check.returncode != 1:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="delivery_unconfirmed",
                reason="codex interactive session absence could not be proven",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
            )
        try:
            with self._claim_structured_thread(session):
                # Recheck after publishing the durable structured-only fence.
                # Every Overseer legacy path observes this marker; the second
                # tmux probe closes the internal check-to-submit window.
                fenced_session_check = self._run(
                    [str(self.tmux_path), "has-session", "-t", _legacy_text(session, "command")]
                )
                if fenced_session_check.returncode == 0:
                    raise RuntimeError("live interactive codex session prevents structured dispatch")
                if fenced_session_check.returncode != 1:
                    raise RuntimeError("codex interactive session absence could not be proven")
                evidence = self.structured_turn_client.submit_bound_turn(
                    thread_id=thread_id,
                    prompt=dispatch_prompt,
                    client_message_id=request.id,
                    cwd=session.workspace,
                    phase_callback=phase_callback,
                )
        except Exception as error:
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="delivery_unconfirmed",
                reason="codex structured turn was not confirmed",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
                stderr=str(error),
            )
        expected_digest = hashlib.sha256(dispatch_prompt.encode("utf-8")).hexdigest()
        if (
            not isinstance(evidence, dict)
            or set(evidence) != {"thread_id", "turn_id", "client_message_id", "prompt_digest", "delivery_proof"}
            or evidence.get("thread_id") != thread_id
            or evidence.get("client_message_id") != request.id
            or evidence.get("prompt_digest") != expected_digest
            or evidence.get("delivery_proof") != "app-server-user-message"
            or not isinstance(evidence.get("turn_id"), str)
            or not evidence["turn_id"].strip()
        ):
            return self._prompt_failure(
                request,
                session,
                resume_details,
                status="delivery_unconfirmed",
                reason="codex structured turn proof is invalid",
                category=AgentErrorCategory.PROVIDER_PROTOCOL_ERROR,
            )
        reason = "prompt submitted through codex app-server and confirmed as an exact user message"
        details = LegacyPromptDetails(status="prompt_dispatched", reason=reason, resume=resume_details)
        result = self._success_result(
            request_id=request.id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            driver_epoch_id=request.driver_epoch_id,
            state=AgentOperationState.ACKNOWLEDGED,
            session=session,
            status=details.status,
            reason=reason,
            evidence={
                "prompt_digest": expected_digest,
                "delivery_proof": "app-server-user-message",
                "turn_id": evidence["turn_id"],
                "client_message_id": request.id,
                **({"prompt_marker": prompt_marker} if prompt_marker is not None else {}),
            },
        )
        self._legacy_prompt_details[result.id] = details
        return result

    def _structured_thread_is_fenced(self, session: AgentSession) -> bool:
        marker = _structured_thread_marker(self.structured_thread_fence_root, session)
        try:
            metadata = marker.lstat()
        except FileNotFoundError:
            return False
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            return True
        return True

    def _ensure_structured_fence_root(self) -> Path:
        root = self.structured_thread_fence_root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = root.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise RuntimeError("structured Codex thread fence directory is unsafe")
        return root

    @contextmanager
    def _thread_operation_lock(self, session: AgentSession):
        """Serialize legacy and structured effects across processes."""
        with _thread_dispatch_lock(session):
            root = self._ensure_structured_fence_root()
            thread_id = session.external_session_id or session.id
            lock_path = root / (hashlib.sha256(thread_id.encode("utf-8")).hexdigest() + ".lock")
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1
                ):
                    raise RuntimeError("Codex thread operation lock is unsafe")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                os.close(descriptor)

    @contextmanager
    def _claim_structured_thread(self, session: AgentSession):
        root = self._ensure_structured_fence_root()
        marker = _structured_thread_marker(root, session)
        descriptor = os.open(marker, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink != 1
            ):
                raise RuntimeError("structured Codex thread fence is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            thread_digest = hashlib.sha256((session.external_session_id or session.id).encode("utf-8")).hexdigest()
            os.lseek(descriptor, 0, os.SEEK_SET)
            existing = os.read(descriptor, 65).decode("ascii")
            if existing not in {"", thread_digest}:
                raise RuntimeError("structured Codex thread fence binding conflicts")
            if not existing:
                if os.write(descriptor, thread_digest.encode("ascii")) != len(thread_digest):
                    raise RuntimeError("structured Codex thread fence write was incomplete")
                os.fsync(descriptor)
                root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
                try:
                    os.fsync(root_descriptor)
                finally:
                    os.close(root_descriptor)
            yield
        finally:
            os.close(descriptor)

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
        evidence: dict[str, object] | None = None,
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
                **(evidence or {}),
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
        try:
            return self.runner.run_bounded(
                command,
                input_text=input_text,
                timeout_seconds=CODEX_COMMAND_TIMEOUT_SECONDS,
                stdout_limit_bytes=CODEX_OUTPUT_LIMIT_BYTES,
                stderr_limit_bytes=CODEX_OUTPUT_LIMIT_BYTES,
            )
        except CliOutputLimitExceeded:
            return subprocess.CompletedProcess(
                command, 125, "", "provider output exceeded configured limit"
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(
                command, 124, "", "provider command timed out"
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
