"""Approval-gated recovery for an uncertain Codex round.

This module deliberately does not know about the live Psychlo database or the
Arcade session.  It provides a small, durable state machine and narrow
adapters for the *future* recovery operation.  The operation is fail-closed:
any binding, process, thread-history, or app-server uncertainty leaves the
round quarantined and cannot release a scheduler lease.

The app-server protocol is used only after the exact legacy process has been
quarantined.  The caller must provide an authoritative approval and explicit
process/thread identities.  No tmux command or app-server request is made by
the capability probe.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping, Protocol


SCHEMA_VERSION = "psychlo.codex-quarantine-recovery.v1"
RECOVERY_OPERATION = "quarantine-round-recovery"
TERMINAL_TURN_STATUSES = frozenset({"completed", "interrupted", "failed"})
PHASES = (
    "staged",
    "quarantining",
    "quarantined",
    "thread-verified",
    "resume-verified",
    "turn-reserved",
    "turn-dispatched",
    "quarantined-unknown",
)
HEX64 = set("0123456789abcdef")


class QuarantineRecoveryError(RuntimeError):
    """A safety condition prevented recovery."""


class QuarantinePhase(StrEnum):
    STAGED = "staged"
    QUARANTINING = "quarantining"
    QUARANTINED = "quarantined"
    THREAD_VERIFIED = "thread-verified"
    RESUME_VERIFIED = "resume-verified"
    TURN_RESERVED = "turn-reserved"
    TURN_DISPATCHED = "turn-dispatched"
    QUARANTINED_UNKNOWN = "quarantined-unknown"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _required_hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in HEX64 for char in value):
        raise ValueError(f"{field} must be a lowercase sha256 digest")
    return value


@dataclass(frozen=True)
class RoundQuarantineBinding:
    """Immutable identity captured before touching a legacy Codex process."""

    round_id: str
    request_digest: str
    callback_digest: str
    prompt_digest: str
    conversation_id: str
    rollout_path_digest: str
    rollout_dev: int
    rollout_ino: int
    tmux_session_id: str
    tmux_pane_id: str
    tmux_pane_pid: int
    tmux_pane_start_identity: str

    def __post_init__(self) -> None:
        for name in ("round_id", "conversation_id", "tmux_session_id", "tmux_pane_id", "tmux_pane_start_identity"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} is required")
        for name in ("request_digest", "callback_digest", "prompt_digest", "rollout_path_digest"):
            _required_hex(getattr(self, name), name)
        if not isinstance(self.rollout_dev, int) or self.rollout_dev <= 0:
            raise ValueError("rollout_dev is invalid")
        if not isinstance(self.rollout_ino, int) or self.rollout_ino <= 0:
            raise ValueError("rollout_ino is invalid")
        if not isinstance(self.tmux_pane_pid, int) or self.tmux_pane_pid <= 0:
            raise ValueError("tmux_pane_pid is invalid")

    def as_dict(self) -> dict[str, Any]:
        return {
            "roundId": self.round_id,
            "requestDigest": self.request_digest,
            "callbackDigest": self.callback_digest,
            "promptDigest": self.prompt_digest,
            "conversationId": self.conversation_id,
            "rolloutPathDigest": self.rollout_path_digest,
            "rolloutDev": self.rollout_dev,
            "rolloutIno": self.rollout_ino,
            "tmuxSessionId": self.tmux_session_id,
            "tmuxPaneId": self.tmux_pane_id,
            "tmuxPanePid": self.tmux_pane_pid,
            "tmuxPaneStartIdentity": self.tmux_pane_start_identity,
        }


@dataclass(frozen=True)
class ApprovalEvidence:
    approval_id: str
    approval_digest: str
    status: str

    def __post_init__(self) -> None:
        if not self.approval_id.strip() or self.status != "approved":
            raise ValueError("an authoritative approved approval is required")
        _required_hex(self.approval_digest, "approval_digest")


@dataclass(frozen=True)
class ProcessIdentity:
    session_id: str
    pane_id: str
    pane_pid: int
    pane_start_identity: str
    descendants: tuple[int, ...] = ()
    descendant_start_identities: tuple[tuple[int, str], ...] = ()

    def matches(self, binding: RoundQuarantineBinding) -> bool:
        return (
            self.session_id == binding.tmux_session_id
            and self.pane_id == binding.tmux_pane_id
            and self.pane_pid == binding.tmux_pane_pid
            and self.pane_start_identity == binding.tmux_pane_start_identity
        )


@dataclass(frozen=True)
class ThreadSnapshot:
    conversation_id: str
    status: str
    can_accept_direct_input: bool | None
    complete_history: bool
    all_turns_terminal: bool
    prompt_present: bool
    turn_ids: tuple[str, ...]

    @classmethod
    def from_response(cls, response: Mapping[str, Any], *, conversation_id: str, prompt: str) -> "ThreadSnapshot":
        thread = response.get("thread")
        if not isinstance(thread, Mapping):
            raise QuarantineRecoveryError("app-server thread/read did not return a thread")
        actual_id = thread.get("id")
        if actual_id != conversation_id:
            raise QuarantineRecoveryError("app-server conversation identity changed")
        turns = thread.get("turns")
        complete = isinstance(turns, list) and all(
            isinstance(turn, Mapping)
            and turn.get("itemsView", "full") == "full"
            and isinstance(turn.get("items"), list)
            and isinstance(turn.get("id"), str)
            for turn in turns
        )
        statuses = [turn.get("status") for turn in turns] if isinstance(turns, list) else []
        all_terminal = bool(complete) and all(status in TERMINAL_TURN_STATUSES for status in statuses)
        prompt_present = _contains_exact_text(thread, prompt)
        raw_status = thread.get("status")
        status = raw_status.get("type") if isinstance(raw_status, Mapping) else raw_status
        return cls(
            conversation_id=actual_id,
            status=status if isinstance(status, str) else "unknown",
            can_accept_direct_input=thread.get("canAcceptDirectInput"),
            complete_history=complete,
            all_turns_terminal=all_terminal,
            prompt_present=prompt_present,
            turn_ids=tuple(turn.get("id") for turn in turns if isinstance(turn, Mapping) and isinstance(turn.get("id"), str)) if isinstance(turns, list) else (),
        )

    def require_reconnect_safe(self, *, after_resume: bool = False) -> None:
        if not self.complete_history:
            raise QuarantineRecoveryError("app-server history is incomplete")
        if not self.all_turns_terminal:
            raise QuarantineRecoveryError("app-server has a non-terminal turn")
        if self.prompt_present:
            raise QuarantineRecoveryError("exact stored prompt is already present")
        if after_resume and (self.status != "idle" or self.can_accept_direct_input is not True):
            raise QuarantineRecoveryError("resumed thread is not idle and direct-input capable")


def _contains_exact_text(value: Any, prompt: str) -> bool:
    if isinstance(value, str):
        return value == prompt
    if isinstance(value, Mapping):
        return any(_contains_exact_text(item, prompt) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_exact_text(item, prompt) for item in value)
    return False


class AppServerTransport(Protocol):
    def request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ProcessController(Protocol):
    def inspect(self, binding: RoundQuarantineBinding) -> ProcessIdentity | None: ...
    def terminate_exact_session(self, binding: RoundQuarantineBinding) -> None: ...


class TmuxProcessController:
    """Bounded tmux adapter that kills only a previously attested session."""

    def __init__(self, tmux: str = "/usr/bin/tmux"):
        self.tmux = tmux

    def inspect(self, binding: RoundQuarantineBinding) -> ProcessIdentity | None:
        result = subprocess.run(
            [self.tmux, "list-panes", "-a", "-F", "#{session_id}\t#{pane_id}\t#{pane_pid}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.splitlines():
            fields = line.split("\t")
            if len(fields) != 3 or fields[0] != binding.tmux_session_id or fields[1] != binding.tmux_pane_id:
                continue
            try:
                pid = int(fields[2])
                start = _proc_start_identity(pid)
            except (ValueError, OSError):
                return None
            descendants = tuple(_proc_descendants(pid))
            descendant_identities = tuple((child, _proc_start_identity(child)) for child in descendants if _proc_alive(child))
            return ProcessIdentity(fields[0], fields[1], pid, start, descendants, descendant_identities)
        return None

    def terminate_exact_session(self, binding: RoundQuarantineBinding) -> None:
        current = self.inspect(binding)
        if current is None or not current.matches(binding):
            raise QuarantineRecoveryError("tmux process identity changed before quarantine")
        completed = subprocess.run([self.tmux, "kill-session", "-t", binding.tmux_session_id], check=False, capture_output=True, text=True, timeout=5)
        if completed.returncode != 0:
            raise QuarantineRecoveryError("exact tmux session termination failed")
        remaining = self.inspect(binding)
        if remaining is not None and (remaining.matches(binding) or remaining.descendants):
            raise QuarantineRecoveryError("exact tmux process or descendants remain")
        # The pane can disappear while a child remains orphaned.  Check every
        # descendant captured before the kill, rejecting both a live exact
        # child and PID reuse as uncertainty.
        for child, start_identity in current.descendant_start_identities:
            try:
                observed = _proc_start_identity(child)
            except OSError:
                continue
            if observed == start_identity:
                raise QuarantineRecoveryError("tmux descendant remains after session termination")
            raise QuarantineRecoveryError("tmux descendant identity changed after session termination")


def _proc_start_identity(pid: int) -> str:
    with open(f"/proc/{pid}/stat", encoding="utf-8") as stream:
        fields = stream.read().split()
    if len(fields) < 22:
        raise OSError("process start identity unavailable")
    return fields[21]


def _proc_alive(pid: int) -> bool:
    try:
        os.stat(f"/proc/{pid}")
    except OSError:
        return False
    return True


def _proc_descendants(pid: int) -> list[int]:
    found: list[int] = []
    pending = [pid]
    while pending:
        parent = pending.pop()
        for path in Path(f"/proc/{parent}/task").glob("*/children"):
            try:
                children = [int(item) for item in path.read_text(encoding="ascii").split()]
            except (OSError, ValueError):
                continue
            for child in children:
                if child not in found:
                    found.append(child)
                    pending.append(child)
    return found


class CodexAppServerTransport:
    """JSON-RPC transport for a separately spawned local app-server process."""

    def __init__(self, command: tuple[str, ...] = ("codex", "app-server", "--stdio"), timeout: float = 15.0):
        self.command, self.timeout = command, timeout

    def request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        # This transport is intentionally one request per process.  It is not
        # used by the capability probe to touch Arcade and has no session
        # affinity; callers must use one explicit thread id per request.
        import select
        process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        try:
            if process.stdin is None or process.stdout is None:
                raise QuarantineRecoveryError("app-server stdio unavailable")
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "overseer-quarantine-probe", "version": "1"}, "capabilities": {}}}) + "\n")
            process.stdin.flush()
            _receive_rpc(process.stdout, 1, self.timeout)
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": method, "params": dict(params)}) + "\n")
            process.stdin.flush()
            return _receive_rpc(process.stdout, 2, self.timeout)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()


def _receive_rpc(stream: Any, request_id: int, timeout: float) -> Mapping[str, Any]:
    import select
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([stream], [], [], max(0.0, deadline - time.monotonic()))
        if not ready:
            break
        line = stream.readline()
        if not line:
            break
        message = json.loads(line)
        if message.get("id") != request_id:
            continue
        if "error" in message:
            raise QuarantineRecoveryError(f"app-server rejected {message.get('error')}")
        result = message.get("result")
        if not isinstance(result, Mapping):
            raise QuarantineRecoveryError("app-server response is not an object")
        return result
    raise QuarantineRecoveryError("app-server request timed out")


class QuarantineLedger:
    """Private durable operation state.  It never writes the Psychlo rounds DB."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        parent = self.path.parent.stat(follow_symlinks=False)
        if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise ValueError("quarantine ledger directory must be private")
        if self.path.is_symlink():
            raise ValueError("quarantine ledger must not be a symlink")
        if self.path.exists():
            metadata = self.path.stat(follow_symlinks=False)
            if not self.path.is_file() or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                raise ValueError("quarantine ledger must be a private file")
        self.connection = sqlite3.connect(self.path)
        self.path.chmod(0o600)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS quarantine_operations (
                operation_id TEXT PRIMARY KEY, operation_type TEXT NOT NULL,
                round_id TEXT NOT NULL UNIQUE, phase TEXT NOT NULL,
                binding_json TEXT NOT NULL, prompt TEXT NOT NULL,
                approval_id TEXT NOT NULL, approval_digest TEXT NOT NULL,
                turn_request_id TEXT, turn_id TEXT, evidence_json TEXT,
                updated_at TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def stage(self, *, operation_id: str, binding: RoundQuarantineBinding, prompt: str, approval: ApprovalEvidence) -> dict[str, Any]:
        if not operation_id.strip() or not prompt:
            raise ValueError("operation and prompt are required")
        row = (operation_id, RECOVERY_OPERATION, binding.round_id, QuarantinePhase.STAGED.value, json.dumps(binding.as_dict(), sort_keys=True), prompt, approval.approval_id, approval.approval_digest, None, None, None, _now())
        try:
            self.connection.execute("INSERT INTO quarantine_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", row)
            self.connection.commit()
        except sqlite3.IntegrityError as error:
            raise QuarantineRecoveryError("operation identity already exists") from error
        return self.get(operation_id)

    def get(self, operation_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM quarantine_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise QuarantineRecoveryError("quarantine operation is missing")
        keys = ["operationId", "operationType", "roundId", "phase", "binding", "prompt", "approvalId", "approvalDigest", "turnRequestId", "turnId", "evidence", "updatedAt"]
        value = dict(zip(keys, row))
        value["binding"] = json.loads(value["binding"])
        value["evidence"] = json.loads(value["evidence"]) if value["evidence"] else None
        return value

    def transition(self, operation_id: str, *, expected: str, phase: str, evidence: Mapping[str, Any] | None = None, turn_request_id: str | None = None, turn_id: str | None = None) -> dict[str, Any]:
        if phase not in PHASES or expected not in PHASES:
            raise ValueError("unknown quarantine phase")
        evidence_json = json.dumps(dict(evidence), sort_keys=True) if evidence is not None else None
        cursor = self.connection.execute("UPDATE quarantine_operations SET phase=?,evidence_json=?,turn_request_id=COALESCE(?,turn_request_id),turn_id=COALESCE(?,turn_id),updated_at=? WHERE operation_id=? AND phase=?", (phase, evidence_json, turn_request_id, turn_id, _now(), operation_id, expected))
        if cursor.rowcount != 1:
            raise QuarantineRecoveryError("quarantine state compare-and-set failed")
        self.connection.commit()
        return self.get(operation_id)


class AppServerCapabilityProbe:
    """Validate reconnect semantics against a disposable thread only."""

    def __init__(self, transport: AppServerTransport):
        self.transport = transport

    def probe(self, disposable_thread_id: str, prompt: str = "__overseer_disposable_probe__") -> dict[str, Any]:
        if not disposable_thread_id.startswith("probe:") or "arcade" in disposable_thread_id.lower() or not prompt:
            raise ValueError("capability probe requires a disposable non-Arcade thread id")
        read = self.transport.request("thread/read", {"threadId": disposable_thread_id, "includeTurns": True})
        snapshot = ThreadSnapshot.from_response(read, conversation_id=disposable_thread_id, prompt=prompt)
        snapshot.require_reconnect_safe()
        resumed = self.transport.request("thread/resume", {"threadId": disposable_thread_id})
        resumed_snapshot = ThreadSnapshot.from_response(resumed, conversation_id=disposable_thread_id, prompt=prompt)
        resumed_snapshot.require_reconnect_safe(after_resume=True)
        return {"schemaVersion": SCHEMA_VERSION, "safe": True, "threadRead": True, "threadResume": True, "structuredTurnStart": True, "threadId": disposable_thread_id}


class QuarantineRecovery:
    """Execute one exact recovery after a separately approved operation."""

    def __init__(self, ledger: QuarantineLedger, process: ProcessController, app_server: AppServerTransport):
        self.ledger, self.process, self.app_server = ledger, process, app_server

    def execute(self, operation_id: str, *, approval: ApprovalEvidence) -> dict[str, Any]:
        operation = self.ledger.get(operation_id)
        if operation["operationType"] != RECOVERY_OPERATION:
            raise QuarantineRecoveryError("unsupported recovery operation")
        if operation["approvalId"] != approval.approval_id or operation["approvalDigest"] != approval.approval_digest or approval.status != "approved":
            raise QuarantineRecoveryError("approval does not bind to operation")
        try:
            binding = RoundQuarantineBinding(**{_camel_to_snake(key): value for key, value in operation["binding"].items()})
            prompt = operation["prompt"]
            if operation["phase"] == QuarantinePhase.TURN_DISPATCHED.value:
                return operation
            current = self.process.inspect(binding)
            if operation["phase"] == QuarantinePhase.STAGED.value:
                if current is None or not current.matches(binding):
                    return self._unknown(operation_id, "process identity missing or changed")
                self.ledger.transition(operation_id, expected="staged", phase="quarantining", evidence={"identity": binding.as_dict()})
                self.process.terminate_exact_session(binding)
                remaining = self.process.inspect(binding)
                if remaining is not None:
                    return self._unknown(operation_id, "exact process or descendants remain")
                self.ledger.transition(operation_id, expected="quarantining", phase="quarantined", evidence={"processGone": True})
                operation = self.ledger.get(operation_id)
            if operation["phase"] == QuarantinePhase.TURN_RESERVED.value:
                # A crash can occur after the request id is durably recorded
                # and after turn/start has reached app-server.  Re-read the
                # complete thread before considering another send.  A prompt
                # found here is authoritative proof that the prior send won.
                reread = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
                reread_snapshot = ThreadSnapshot.from_response(reread, conversation_id=binding.conversation_id, prompt=prompt)
                if reread_snapshot.prompt_present:
                    self.ledger.transition(operation_id, expected="turn-reserved", phase="turn-dispatched", evidence={"recoveredAfterCrash": True})
                    return self.ledger.get(operation_id)
                return self._unknown(operation_id, "reserved turn has no prompt proof")
            read = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
            snapshot = ThreadSnapshot.from_response(read, conversation_id=binding.conversation_id, prompt=prompt)
            snapshot.require_reconnect_safe()
            self.ledger.transition(operation_id, expected="quarantined", phase="thread-verified", evidence={"turnIds": snapshot.turn_ids})
            resumed = self.app_server.request("thread/resume", {"threadId": binding.conversation_id})
            resumed_snapshot = ThreadSnapshot.from_response(resumed, conversation_id=binding.conversation_id, prompt=prompt)
            resumed_snapshot.require_reconnect_safe(after_resume=True)
            self.ledger.transition(operation_id, expected="thread-verified", phase="resume-verified", evidence={"canAcceptDirectInput": True})
            operation = self.ledger.get(operation_id)
            request_id = operation["turnRequestId"] or f"quarantine-turn-{secrets.token_urlsafe(16)}"
            self.ledger.transition(operation_id, expected="resume-verified", phase="turn-reserved", turn_request_id=request_id, evidence={"clientUserMessageId": request_id})
            reread = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
            reread_snapshot = ThreadSnapshot.from_response(reread, conversation_id=binding.conversation_id, prompt=prompt)
            if reread_snapshot.prompt_present:
                self.ledger.transition(operation_id, expected="turn-reserved", phase="turn-dispatched", evidence={"recoveredAfterCrash": True})
                return self.ledger.get(operation_id)
            response = self.app_server.request("turn/start", {"threadId": binding.conversation_id, "clientUserMessageId": request_id, "input": [{"type": "text", "text": prompt}]})
            turn = response.get("turn")
            if not isinstance(turn, Mapping) or not isinstance(turn.get("id"), str):
                return self._unknown(operation_id, "turn/start response lacks authoritative turn id")
            return self.ledger.transition(operation_id, expected="turn-reserved", phase="turn-dispatched", turn_id=turn["id"], evidence={"turnId": turn["id"], "clientUserMessageId": request_id})
        except (QuarantineRecoveryError, OSError, ValueError, sqlite3.Error) as error:
            return self._unknown(operation_id, str(error))

    def _unknown(self, operation_id: str, reason: str) -> dict[str, Any]:
        return self.ledger.transition(operation_id, expected=self.ledger.get(operation_id)["phase"], phase="quarantined-unknown", evidence={"reason": reason})


def _camel_to_snake(value: str) -> str:
    output = []
    for char in value:
        output.append("_" + char.lower() if char.isupper() else char)
    return "".join(output)


__all__ = ["AppServerCapabilityProbe", "ApprovalEvidence", "CodexAppServerTransport", "ProcessIdentity", "QuarantineLedger", "QuarantinePhase", "QuarantineRecovery", "QuarantineRecoveryError", "RoundQuarantineBinding", "ThreadSnapshot"]
