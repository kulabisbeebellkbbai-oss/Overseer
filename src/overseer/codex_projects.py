"""Adapter for the local codex-projects thread registry."""

from __future__ import annotations

import csv
import subprocess
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CODEX_PROJECTS_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
DEFAULT_CODEX_MEMORY_SESSION = Path("/home/god/.local/bin/codex-memory-session")
DEFAULT_TMUX = Path("/usr/bin/tmux")


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

    def _tmux_session_exists(self, session: str) -> bool:
        completed = self.runner(
            [str(self.tmux_path), "has-session", "-t", session],
            text=True,
            capture_output=True,
        )
        return completed.returncode == 0


def _thread_result_fields(thread: CodexProjectThread) -> dict[str, str]:
    return {
        "conversation_id": thread.conversation_id,
        "project": thread.project,
        "command": thread.command,
        "launcher": thread.launcher,
    }
