"""Adapter for the local codex-projects thread registry."""

from __future__ import annotations

import csv
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .core import OwnerDomain, Resource, ResourceState, ResourceType, RiskLevel


DEFAULT_CODEX_PROJECTS_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
DEFAULT_CODEX_MEMORY_SESSION = Path("/home/god/.local/bin/codex-memory-session")
DEFAULT_TMUX = Path("/usr/bin/tmux")
PROMPT_REJECTION_MARKERS = (
    "message exceeds maximum length",
    "maximum length allowed",
)


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

    def list_threads(self) -> tuple[CodexProjectThread, ...]:
        if not self.registry_path.exists():
            return ()
        threads: list[CodexProjectThread] = []
        with self.registry_path.open("r", newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                conversation_id = str(row.get("conversation_id", "")).strip()
                project = str(row.get("project", "")).strip()
                command = str(row.get("command", "")).strip()
                launcher = str(row.get("launcher", "")).strip()
                if not conversation_id or not project or not command:
                    continue
                threads.append(
                    CodexProjectThread(
                        conversation_id=conversation_id,
                        label=str(row.get("label", "")).strip() or conversation_id,
                        project=project,
                        command=command,
                        launcher=launcher,
                    )
                )
        return tuple(threads)

    def resolve(self, owner_thread: str) -> CodexProjectThread | None:
        wanted = owner_thread.strip()
        if not wanted:
            return None
        for thread in self.list_threads():
            if wanted in {thread.conversation_id, thread.command, thread.launcher, thread.project}:
                return thread
            if thread.conversation_id.startswith(wanted):
                return thread
        return None

    def resume(self, owner_thread: str) -> CodexProjectResumeResult:
        thread = self.resolve(owner_thread)
        if thread is None:
            return CodexProjectResumeResult(
                owner_thread=owner_thread,
                status="not_found",
                reason="owner_thread was not found in codex-projects registry",
            )
        if self._tmux_session_exists(thread.command):
            return CodexProjectResumeResult(
                owner_thread=owner_thread,
                status="already_running",
                reason="codex project tmux session already exists",
                **_thread_result_fields(thread),
            )
        command = [
            str(self.tmux_path),
            "new-session",
            "-d",
            "-s",
            thread.command,
            "-c",
            thread.project,
            str(self.codex_memory_session_path),
            "resume",
            thread.conversation_id,
            "--cd",
            thread.project,
        ]
        completed = self.runner(command, text=True, capture_output=True)
        status = "resumed" if completed.returncode == 0 else "failed"
        reason = "codex project thread resumed in detached tmux session" if completed.returncode == 0 else "tmux resume command failed"
        return CodexProjectResumeResult(
            owner_thread=owner_thread,
            status=status,
            reason=reason,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            **_thread_result_fields(thread),
        )

    def dispatch_prompt(self, owner_thread: str, prompt: str) -> CodexProjectPromptDispatchResult:
        resume_result = self.resume(owner_thread)
        if resume_result.status not in {"resumed", "already_running"}:
            return CodexProjectPromptDispatchResult(
                owner_thread=owner_thread,
                status=resume_result.status,
                reason=resume_result.reason,
                resume_result=resume_result,
                stdout=resume_result.stdout,
                stderr=resume_result.stderr,
            )
        if not resume_result.command:
            return CodexProjectPromptDispatchResult(
                owner_thread=owner_thread,
                status="failed",
                reason="resolved codex-project thread did not include a tmux command name",
                resume_result=resume_result,
            )
        pane_command = [
            str(self.tmux_path),
            "capture-pane",
            "-p",
            "-t",
            resume_result.command,
            "-S",
            "-200",
        ]
        baseline_pane_result = self.runner(
            pane_command,
            text=True,
            capture_output=True,
        )
        baseline_pane_output = (
            baseline_pane_result.stdout.casefold()
            if baseline_pane_result.returncode == 0
            else ""
        )
        prompt_result = self.runner(
            [str(self.tmux_path), "load-buffer", "-b", "overseer-dispatch", "-"],
            input=prompt,
            text=True,
            capture_output=True,
        )
        if prompt_result.returncode != 0:
            return CodexProjectPromptDispatchResult(
                owner_thread=owner_thread,
                status="failed",
                reason="tmux prompt buffer load failed",
                resume_result=resume_result,
                prompt_exit_code=prompt_result.returncode,
                stdout=prompt_result.stdout,
                stderr=prompt_result.stderr,
            )
        paste_result = self.runner(
            [str(self.tmux_path), "paste-buffer", "-b", "overseer-dispatch", "-t", resume_result.command],
            text=True,
            capture_output=True,
        )
        if paste_result.returncode != 0:
            return CodexProjectPromptDispatchResult(
                owner_thread=owner_thread,
                status="failed",
                reason="tmux prompt paste failed",
                resume_result=resume_result,
                prompt_exit_code=prompt_result.returncode,
                enter_exit_code=paste_result.returncode,
                stdout=paste_result.stdout,
                stderr=paste_result.stderr,
            )
        enter_result = self.runner(
            [str(self.tmux_path), "send-keys", "-t", resume_result.command, "Enter"],
            text=True,
            capture_output=True,
        )
        if enter_result.returncode != 0:
            return CodexProjectPromptDispatchResult(
                owner_thread=owner_thread,
                status="failed",
                reason="tmux prompt submit failed",
                resume_result=resume_result,
                prompt_exit_code=prompt_result.returncode,
                enter_exit_code=enter_result.returncode,
                stdout=enter_result.stdout,
                stderr=enter_result.stderr,
            )
        pane_result = self.runner(
            pane_command,
            text=True,
            capture_output=True,
        )
        pane_output = pane_result.stdout.casefold() if pane_result.returncode == 0 else ""
        rejection_marker = next(
            (
                marker
                for marker in PROMPT_REJECTION_MARKERS
                if pane_output.count(marker) > baseline_pane_output.count(marker)
            ),
            None,
        )
        if rejection_marker is not None:
            return CodexProjectPromptDispatchResult(
                owner_thread=owner_thread,
                status="prompt_rejected",
                reason=f"codex project rejected prompt: {rejection_marker}",
                resume_result=resume_result,
                prompt_exit_code=prompt_result.returncode,
                enter_exit_code=enter_result.returncode,
                stdout=pane_result.stdout,
                stderr=pane_result.stderr,
            )
        return CodexProjectPromptDispatchResult(
            owner_thread=owner_thread,
            status="prompt_dispatched",
            reason="prompt submitted to codex project; advisory result not yet confirmed",
            resume_result=resume_result,
            prompt_exit_code=prompt_result.returncode,
            enter_exit_code=enter_result.returncode,
            stdout=enter_result.stdout,
            stderr=enter_result.stderr,
        )

    def _tmux_session_exists(self, session: str) -> bool:
        completed = self.runner(
            [str(self.tmux_path), "has-session", "-t", session],
            text=True,
            capture_output=True,
        )
        return completed.returncode == 0


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


def codex_project_thread_resources(threads: tuple[CodexProjectThread, ...]) -> tuple[Resource, ...]:
    return tuple(codex_project_thread_resource(thread) for thread in threads)


def _thread_result_fields(thread: CodexProjectThread) -> dict[str, str]:
    return {
        "conversation_id": thread.conversation_id,
        "project": thread.project,
        "command": thread.command,
        "launcher": thread.launcher,
    }


def _resource_id_part(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip().lower()).strip("-")
    return cleaned or "unknown"
