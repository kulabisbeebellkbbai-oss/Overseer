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

import dataclasses
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
    "turn-confirmed",
    "quarantined-unknown",
)
ALLOWED_NEXT = {
    "staged": {"quarantining", "quarantined-unknown"},
    "quarantining": {"quarantined", "quarantined-unknown"},
    "quarantined": {"thread-verified", "quarantined-unknown"},
    "thread-verified": {"resume-verified", "quarantined-unknown"},
    "resume-verified": {"turn-reserved", "quarantined-unknown"},
    "turn-reserved": {"turn-dispatched", "quarantined-unknown"},
    "turn-dispatched": {"turn-confirmed", "quarantined-unknown"},
    "turn-confirmed": set(),
    "quarantined-unknown": set(),
}
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
    TURN_CONFIRMED = "turn-confirmed"
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
    tmux_socket: str
    tmux_server_start_identity: str
    tmux_session_id: str
    tmux_pane_id: str
    tmux_pane_pid: int
    tmux_pane_start_identity: str
    tmux_cgroup: str

    def __post_init__(self) -> None:
        for name in ("round_id", "conversation_id", "tmux_socket", "tmux_server_start_identity", "tmux_session_id", "tmux_pane_id", "tmux_pane_start_identity", "tmux_cgroup"):
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
            "tmuxSocket": self.tmux_socket,
            "tmuxServerStartIdentity": self.tmux_server_start_identity,
            "tmuxSessionId": self.tmux_session_id,
            "tmuxPaneId": self.tmux_pane_id,
            "tmuxPanePid": self.tmux_pane_pid,
            "tmuxPaneStartIdentity": self.tmux_pane_start_identity,
            "tmuxCgroup": self.tmux_cgroup,
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
    server_start_identity: str = ""
    cgroup: str = ""
    descendants: tuple[int, ...] = ()
    descendant_start_identities: tuple[tuple[int, str], ...] = ()

    def matches(self, binding: RoundQuarantineBinding) -> bool:
        return (
            self.session_id == binding.tmux_session_id
            and self.pane_id == binding.tmux_pane_id
            and self.pane_pid == binding.tmux_pane_pid
            and self.pane_start_identity == binding.tmux_pane_start_identity
            and self.server_start_identity == binding.tmux_server_start_identity
            and self.cgroup == binding.tmux_cgroup
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
    matching_user_message: bool = False
    matching_turn_id: str | None = None

    @classmethod
    def from_response(cls, response: Mapping[str, Any], *, conversation_id: str, prompt: str, client_user_message_id: str | None = None, turn_id: str | None = None) -> "ThreadSnapshot":
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
        matching_turn_id = None
        matching_user_message = False
        prompt_present = False
        if isinstance(turns, list):
            for turn in turns:
                if not isinstance(turn, Mapping) or not isinstance(turn.get("items"), list):
                    continue
                for item in turn["items"]:
                    if not isinstance(item, Mapping) or item.get("type") != "userMessage":
                        continue
                    content = item.get("content")
                    exact = isinstance(content, list) and any(
                        isinstance(entry, Mapping) and entry.get("type") == "text" and entry.get("text") == prompt
                        for entry in content
                    )
                    if not exact:
                        continue
                    if client_user_message_id is None:
                        prompt_present = True
                    elif item.get("clientId") == client_user_message_id and (turn_id is None or turn.get("id") == turn_id):
                        prompt_present = True
                        matching_user_message = True
                        matching_turn_id = turn.get("id") if isinstance(turn.get("id"), str) else None
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
            matching_user_message=matching_user_message,
            matching_turn_id=matching_turn_id,
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


class RoundAuthority(Protocol):
    """Authoritative bridge/round store, never a caller-supplied projection."""

    def load_recovery_target(self, round_id: str) -> Mapping[str, Any]: ...
    def revalidate_recovery_target(self, round_id: str, operation_id: str, phase: str) -> Mapping[str, Any]: ...

    def claim_recovery_target(self, round_id: str, operation_id: str, phase: str) -> Mapping[str, Any]: ...
    def project_confirmed(self, round_id: str, operation_id: str, evidence: Mapping[str, Any]) -> Mapping[str, Any]: ...


class ApprovalAuthority(Protocol):
    def load_approved_plan(self, approval_id: str) -> Mapping[str, Any]: ...


class SQLiteStoreApprovalAuthority:
    """Read an approved immutable AdminChangePlan from Overseer's store."""

    def __init__(self, store: Any):
        self.store = store

    def load_approved_plan(self, approval_id: str) -> Mapping[str, Any]:
        try:
            approval = self.store.load_approval(approval_id)
            plan_id = approval.subject_id
            if str(approval.status.value if hasattr(approval.status, "value") else approval.status) != "approved":
                raise QuarantineRecoveryError("authoritative approval request is not approved")
        except (AttributeError, KeyError):
            plan_id = approval_id
        plan = self.store.load_admin_change_plan(plan_id)
        if not plan.approved or plan.canceled or plan.archived:
            raise QuarantineRecoveryError("authoritative AdminChangePlan is not approved and active")
        payload = dataclasses.asdict(plan)
        digest = plan.adapter_metadata.get("planDigest") if isinstance(plan.adapter_metadata, Mapping) else None
        if not isinstance(digest, str) or not digest:
            digest = _digest(json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")))
        return {"approvalId": approval_id, "status": "approved", "target": plan.target, "planDigest": digest, "planId": plan.id}


class PsychloBridgeRoundAuthority:
    """Authoritative adapter over PsychloBridgeStore's durable round tables."""

    def __init__(self, store: Any, *, prompt_loader: Any):
        self.store = store
        self.prompt_loader = prompt_loader

    def load_recovery_target(self, round_id: str) -> Mapping[str, Any]:
        record = self.store.get_round(round_id)
        if record is None:
            raise QuarantineRecoveryError("authoritative round is missing")
        request, _receipt, _hash, capability, state, result, _forwarded = record
        delivery = self.store.round_prompt_delivery(round_id)
        failure = self.store.operational_failure_intent(round_id)
        recovery = self.store.round_recovery(round_id)
        cancellation = self.store.round_cancellation(round_id)
        raw_binding = self.store.round_binding(round_id)
        prompt = self.prompt_loader(request, capability)
        if not isinstance(raw_binding, Mapping):
            raise QuarantineRecoveryError("authoritative bridge round has no complete execution binding")
        return {
            "roundId": round_id,
            "state": state,
            "result": result,
            "deliveryPhase": delivery.get("phase") if isinstance(delivery, Mapping) else None,
            "failure": failure,
            "recovery": recovery,
            "cancellation": cancellation,
            "binding": dict(raw_binding),
            "deliveryBinding": delivery.get("binding") if isinstance(delivery, Mapping) else None,
            "prompt": prompt,
        }

    def revalidate_recovery_target(self, round_id: str, operation_id: str, phase: str) -> Mapping[str, Any]:
        # The store read is deliberately repeated at every destructive edge.
        # A future integration may additionally bind operation_id to the
        # bridge's own recovery claim; absence of that claim is a blocker.
        target = self.load_recovery_target(round_id)
        recovery = self.store.round_recovery(round_id)
        if not isinstance(recovery, Mapping) or recovery.get("ownerId") != operation_id or recovery.get("state") != "claimed":
            raise QuarantineRecoveryError("authoritative bridge recovery claim is unavailable")
        return target

    def project_confirmed(self, round_id: str, operation_id: str, evidence: Mapping[str, Any]) -> Mapping[str, Any]:
        target = self.load_recovery_target(round_id)
        recovery = target.get("recovery")
        if not isinstance(recovery, Mapping) or recovery.get("ownerId") != operation_id or recovery.get("state") != "claimed":
            raise QuarantineRecoveryError("authoritative bridge recovery claim is unavailable for projection")
        record = self.store.get_round(round_id)
        if record is None:
            raise QuarantineRecoveryError("authoritative round disappeared before projection")
        request, receipt, _hash, capability, state, result, _forwarded = record
        delivery = target.get("deliveryBinding")
        if not isinstance(delivery, Mapping):
            raise QuarantineRecoveryError("authoritative prompt-delivery binding is missing")
        prompt_digest = target["binding"].get("promptDigest") if isinstance(target.get("binding"), Mapping) else None
        if not isinstance(prompt_digest, str):
            prompt_digest = _digest(str(target["prompt"]))
        self.store.record_round_prompt_delivery_phase(round_id, request, capability, delivery, prompt_digest, "confirmed", now=_now(), expected_phase="submitted")
        projected_receipt = {**receipt, "status": "accepted", "provenanceId": f"overseer-quarantine-recovery:{round_id}", "recoveryEvidence": dict(evidence)}
        self.store.complete_round_recovery_dispatch(round_id, operation_id, str(recovery.get("claimToken")), projected_receipt, evidence, now=_now())
        return {"projected": True, "roundId": round_id, "dispatchState": "dispatched"}

    def claim_recovery_target(self, round_id: str, operation_id: str, phase: str) -> Mapping[str, Any]:
        target = self.load_recovery_target(round_id)
        request, _receipt, _hash, capability, _state, _result, _forwarded = self.store.get_round(round_id)
        acquired = self.store.claim_round_recovery(round_id, request, capability, owner_id=operation_id, lease_expires_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(), now=_now())
        if not acquired:
            existing = self.store.round_recovery(round_id)
            if not isinstance(existing, Mapping) or existing.get("ownerId") != operation_id or existing.get("state") != "claimed":
                raise QuarantineRecoveryError("authoritative bridge recovery claim is unavailable")
        return target


def _validate_authoritative_target(target: Mapping[str, Any], *, round_id: str, binding: RoundQuarantineBinding | None = None, prompt: str | None = None, allow_recovery_owner: str | None = None) -> tuple[RoundQuarantineBinding, str]:
    if target.get("roundId") != round_id or target.get("state") != "started" or target.get("result") is not None:
        raise QuarantineRecoveryError("authoritative round is not started and resultless")
    if target.get("deliveryPhase") != "submitted":
        raise QuarantineRecoveryError("authoritative delivery phase is not submitted")
    recovery = target.get("recovery")
    recovery_allowed = isinstance(recovery, Mapping) and recovery.get("ownerId") == allow_recovery_owner and recovery.get("state") == "claimed"
    if target.get("failure") is not None or (recovery is not None and not recovery_allowed) or target.get("cancellation") is not None:
        raise QuarantineRecoveryError("authoritative round has a conflicting terminal or recovery record")
    raw_binding = target.get("binding")
    if not isinstance(raw_binding, Mapping):
        raise QuarantineRecoveryError("authoritative round binding is missing")
    try:
        authoritative = RoundQuarantineBinding(**{_camel_to_snake(str(key)): value for key, value in raw_binding.items()})
    except (TypeError, ValueError) as error:
        raise QuarantineRecoveryError("authoritative round binding is invalid") from error
    if authoritative.round_id != round_id:
        raise QuarantineRecoveryError("authoritative binding round mismatch")
    if binding is not None and authoritative != binding:
        raise QuarantineRecoveryError("caller binding differs from authoritative binding")
    exact_prompt = target.get("prompt")
    if not isinstance(exact_prompt, str) or not exact_prompt or _digest(exact_prompt) != authoritative.prompt_digest:
        raise QuarantineRecoveryError("authoritative prompt digest does not match binding")
    if prompt is not None and prompt != exact_prompt:
        raise QuarantineRecoveryError("caller prompt differs from authoritative prompt")
    return authoritative, exact_prompt


class TmuxProcessController:
    """Bounded tmux adapter that kills only a previously attested session."""

    def __init__(self, tmux: str = "/usr/bin/tmux"):
        self.tmux = tmux

    def inspect(self, binding: RoundQuarantineBinding) -> ProcessIdentity | None:
        result = subprocess.run(
            [self.tmux, "-S", binding.tmux_socket, "list-panes", "-a", "-F", "#{session_id}\t#{pane_id}\t#{pane_pid}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            raise QuarantineRecoveryError("tmux list-panes failed")
        server_identity = _tmux_server_start_identity(self.tmux, binding.tmux_socket)
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
            return ProcessIdentity(fields[0], fields[1], pid, start, server_identity, _proc_cgroup(pid), descendants, descendant_identities)
        return None

    def terminate_exact_session(self, binding: RoundQuarantineBinding) -> None:
        current = self.inspect(binding)
        if current is None or not current.matches(binding):
            raise QuarantineRecoveryError("tmux process identity changed before quarantine")
        # Revalidation occurs immediately before the destructive command.  A
        # pidfd pins the exact pane process across PID reuse; the tmux socket,
        # server identity, session id, pane id, pid starttime and cgroup all
        # remain fenced by the binding.
        try:
            pane_pidfd = os.pidfd_open(current.pane_pid, 0)
        except (AttributeError, OSError) as error:
            raise QuarantineRecoveryError("pidfd fence unavailable") from error
        try:
            completed = subprocess.run([self.tmux, "-S", binding.tmux_socket, "kill-session", "-t", binding.tmux_session_id], check=False, capture_output=True, text=True, timeout=5)
        finally:
            os.close(pane_pidfd)
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
        content = stream.read()
    # comm is enclosed in parentheses and may contain spaces.  Split only
    # after the final closing parenthesis; field 22 is tail index 19 because
    # the tail begins at field 3 (state).
    closing = content.rfind(")")
    if closing < 0:
        raise OSError("process stat identity unavailable")
    fields = content[closing + 2 :].split()
    if len(fields) <= 19:
        raise OSError("process start identity unavailable")
    return fields[19]


def _proc_cgroup(pid: int) -> str:
    with open(f"/proc/{pid}/cgroup", encoding="ascii") as stream:
        value = "|".join(sorted(line.strip() for line in stream if line.strip()))
    if not value:
        raise OSError("process cgroup identity unavailable")
    return value


def _tmux_server_start_identity(tmux: str, socket: str) -> str:
    info = subprocess.run([tmux, "-S", socket, "info"], check=False, capture_output=True, text=True, timeout=5)
    if info.returncode != 0:
        raise QuarantineRecoveryError("tmux info failed")
    for line in info.stdout.splitlines():
        fields = line.split()
        if fields and fields[0].lower().startswith("pid"):
            for candidate in fields[1:]:
                try:
                    pid = int(candidate.rstrip(":"))
                except ValueError:
                    continue
                return _proc_start_identity(pid)
    raise QuarantineRecoveryError("tmux server identity unavailable")


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
        self._process: subprocess.Popen[str] | None = None
        self._next_id = 1

    def request(self, method: str, params: Mapping[str, Any]) -> Mapping[str, Any]:
        process = self._process
        if process is None or process.poll() is not None:
            process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
            self._process = process
            if process.stdin is None or process.stdout is None:
                self.close()
                raise QuarantineRecoveryError("app-server stdio unavailable")
            initialize_id = self._next_id
            self._next_id += 1
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": initialize_id, "method": "initialize", "params": {"clientInfo": {"name": "overseer-quarantine-recovery", "version": "1"}, "capabilities": {}}}) + "\n")
            process.stdin.flush()
            _receive_rpc(process.stdout, initialize_id, self.timeout)
        if process.stdin is None or process.stdout is None:
            raise QuarantineRecoveryError("app-server stdio unavailable")
        request_id = self._next_id
        self._next_id += 1
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}) + "\n")
        process.stdin.flush()
        try:
            return _receive_rpc(process.stdout, request_id, self.timeout)
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        process, self._process = self._process, None
        if process is None:
            return
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
                owner_id TEXT, lease_expires_at TEXT,
                updated_at TEXT NOT NULL
            )"""
        )
        for column, definition in (("owner_id", "TEXT"), ("lease_expires_at", "TEXT")):
            try:
                self.connection.execute(f"ALTER TABLE quarantine_operations ADD COLUMN {column} {definition}")
            except sqlite3.OperationalError:
                pass
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def stage(self, *, operation_id: str, binding: RoundQuarantineBinding, prompt: str, approval: ApprovalEvidence, round_authority: RoundAuthority, approval_authority: ApprovalAuthority) -> dict[str, Any]:
        if not operation_id.strip() or not prompt:
            raise ValueError("operation and prompt are required")
        authoritative_target = round_authority.load_recovery_target(binding.round_id)
        authoritative_binding, authoritative_prompt = _validate_authoritative_target(authoritative_target, round_id=binding.round_id, binding=binding, prompt=prompt)
        plan = approval_authority.load_approved_plan(approval.approval_id)
        if not isinstance(plan, Mapping) or plan.get("approvalId", approval.approval_id) != approval.approval_id or plan.get("status") != "approved" or plan.get("target") != binding.round_id:
            raise QuarantineRecoveryError("authoritative approval target or status is invalid")
        authoritative_digest = plan.get("planDigest") or plan.get("digest")
        if authoritative_digest != approval.approval_digest:
            raise QuarantineRecoveryError("approval digest does not match authoritative plan")
        # The values persisted in the operation are sourced from the round and
        # approval stores above, not from caller assertions.
        row = (operation_id, RECOVERY_OPERATION, authoritative_binding.round_id, QuarantinePhase.STAGED.value, json.dumps(authoritative_binding.as_dict(), sort_keys=True), authoritative_prompt, approval.approval_id, str(authoritative_digest), None, None, None, None, None, _now())
        try:
            self.connection.execute("INSERT INTO quarantine_operations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
            self.connection.commit()
        except sqlite3.IntegrityError as error:
            raise QuarantineRecoveryError("operation identity already exists") from error
        return self.get(operation_id)

    def get(self, operation_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT operation_id,operation_type,round_id,phase,binding_json,prompt,approval_id,approval_digest,turn_request_id,turn_id,evidence_json,updated_at,owner_id,lease_expires_at FROM quarantine_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise QuarantineRecoveryError("quarantine operation is missing")
        keys = ["operationId", "operationType", "roundId", "phase", "binding", "prompt", "approvalId", "approvalDigest", "turnRequestId", "turnId", "evidence", "updatedAt", "ownerId", "leaseExpiresAt"]
        value = dict(zip(keys, row))
        value["binding"] = json.loads(value["binding"])
        value["evidence"] = json.loads(value["evidence"]) if value["evidence"] else None
        return value

    def claim(self, operation_id: str, *, owner_id: str, lease_expires_at: str) -> bool:
        if not owner_id.strip() or not lease_expires_at.strip():
            raise ValueError("quarantine worker identity is required")
        now = _now()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.get(operation_id)
            if current["phase"] in {QuarantinePhase.TURN_CONFIRMED.value, QuarantinePhase.QUARANTINED_UNKNOWN.value}:
                self.connection.execute("COMMIT")
                return False
            if current["ownerId"] and current["ownerId"] != owner_id and current["leaseExpiresAt"] and current["leaseExpiresAt"] > now:
                self.connection.execute("COMMIT")
                return False
            self.connection.execute("UPDATE quarantine_operations SET owner_id=?,lease_expires_at=?,updated_at=? WHERE operation_id=?", (owner_id, lease_expires_at, now, operation_id))
            self.connection.execute("COMMIT")
            return True
        except Exception:
            self.connection.execute("ROLLBACK")
            raise

    def transition(self, operation_id: str, *, expected: str, phase: str, evidence: Mapping[str, Any] | None = None, turn_request_id: str | None = None, turn_id: str | None = None, owner_id: str | None = None) -> dict[str, Any]:
        if phase not in PHASES or expected not in PHASES:
            raise ValueError("unknown quarantine phase")
        if phase not in ALLOWED_NEXT[expected]:
            raise QuarantineRecoveryError("quarantine phase transition is not allowed")
        evidence_json = json.dumps(dict(evidence), sort_keys=True) if evidence is not None else None
        owner_clause = " AND owner_id=?" if owner_id is not None else ""
        args = (phase, evidence_json, turn_request_id, turn_id, _now(), operation_id, expected, owner_id) if owner_id is not None else (phase, evidence_json, turn_request_id, turn_id, _now(), operation_id, expected)
        cursor = self.connection.execute(f"UPDATE quarantine_operations SET phase=?,evidence_json=?,turn_request_id=COALESCE(?,turn_request_id),turn_id=COALESCE(?,turn_id),updated_at=? WHERE operation_id=? AND phase=?{owner_clause}", args)
        if cursor.rowcount != 1:
            raise QuarantineRecoveryError("quarantine state compare-and-set failed")
        self.connection.commit()
        return self.get(operation_id)


class AppServerCapabilityProbe:
    """Validate reconnect semantics by exercising a disposable thread."""

    def __init__(self, transport: AppServerTransport):
        self.transport = transport

    def probe(self, disposable_thread_id: str | None = None, prompt: str = "__overseer_disposable_probe__", *, reconnect_transport: AppServerTransport | None = None) -> dict[str, Any]:
        # The label is only a test-run correlation id.  It is never used as a
        # live thread id; thread/start must create the disposable thread.
        if disposable_thread_id is not None and (not disposable_thread_id.startswith("probe:") or "arcade" in disposable_thread_id.lower()):
            raise ValueError("capability probe requires a disposable non-Arcade label")
        if not prompt or reconnect_transport is None or reconnect_transport is self.transport:
            raise ValueError("capability probe requires a separate reconnect server")
        created = self.transport.request("thread/start", {"ephemeral": True, "threadSource": "appServer"})
        thread = created.get("thread")
        created_id = thread.get("id") if isinstance(thread, Mapping) else None
        if not isinstance(created_id, str) or not created_id:
            raise QuarantineRecoveryError("disposable thread/start did not return a thread id")
        client_id = f"probe-user-{secrets.token_urlsafe(12)}"
        started = self.transport.request("turn/start", {"threadId": created_id, "clientUserMessageId": client_id, "input": [{"type": "text", "text": prompt}]})
        turn = started.get("turn")
        turn_id = turn.get("id") if isinstance(turn, Mapping) else None
        if not isinstance(turn_id, str) or not turn_id:
            raise QuarantineRecoveryError("disposable turn/start did not return a turn id")
        read = reconnect_transport.request("thread/read", {"threadId": created_id, "includeTurns": True})
        snapshot = ThreadSnapshot.from_response(read, conversation_id=created_id, prompt=prompt, client_user_message_id=client_id, turn_id=turn_id)
        if not snapshot.complete_history or not snapshot.all_turns_terminal or not snapshot.prompt_present or not snapshot.matching_user_message:
            raise QuarantineRecoveryError("disposable reconnect proof is incomplete")
        resumed = reconnect_transport.request("thread/resume", {"threadId": created_id})
        resumed_snapshot = ThreadSnapshot.from_response(resumed, conversation_id=created_id, prompt=prompt, client_user_message_id=client_id, turn_id=turn_id)
        if not resumed_snapshot.complete_history or not resumed_snapshot.all_turns_terminal or not resumed_snapshot.prompt_present or not resumed_snapshot.matching_user_message:
            raise QuarantineRecoveryError("disposable resume proof is incomplete")
        return {"schemaVersion": SCHEMA_VERSION, "safe": True, "threadRead": True, "threadResume": True, "structuredTurnStart": True, "threadId": created_id, "turnId": turn_id, "clientUserMessageId": client_id, "exactUserMessageProof": True}


class QuarantineRecovery:
    """Execute one exact recovery after a separately approved operation."""

    def __init__(self, ledger: QuarantineLedger, process: ProcessController, app_server: AppServerTransport, *, round_authority: RoundAuthority, approval_authority: ApprovalAuthority):
        self.ledger, self.process, self.app_server = ledger, process, app_server
        self.round_authority, self.approval_authority = round_authority, approval_authority

    def execute(self, operation_id: str, *, approval: ApprovalEvidence) -> dict[str, Any]:
        operation = self.ledger.get(operation_id)
        if operation["operationType"] != RECOVERY_OPERATION:
            raise QuarantineRecoveryError("unsupported recovery operation")
        plan = self.approval_authority.load_approved_plan(operation["approvalId"])
        if (
            not isinstance(plan, Mapping)
            or plan.get("approvalId", operation["approvalId"]) != operation["approvalId"]
            or plan.get("status") != "approved"
            or plan.get("target") != operation["roundId"]
            or (plan.get("planDigest") or plan.get("digest")) != operation["approvalDigest"]
            or operation["approvalId"] != approval.approval_id
            or operation["approvalDigest"] != approval.approval_digest
            or approval.status != "approved"
        ):
            raise QuarantineRecoveryError("approval does not bind to operation")
        owner_id = f"quarantine:{os.getpid()}:{secrets.token_hex(8)}"
        if not self.ledger.claim(operation_id, owner_id=owner_id, lease_expires_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat()):
            return self.ledger.get(operation_id)
        try:
            binding = RoundQuarantineBinding(**{_camel_to_snake(key): value for key, value in operation["binding"].items()})
            prompt = operation["prompt"]
            authority_method = "claim_recovery_target" if operation["phase"] == QuarantinePhase.STAGED.value else "revalidate_recovery_target"
            authority_fn = getattr(self.round_authority, authority_method, self.round_authority.revalidate_recovery_target)
            authoritative_target = authority_fn(binding.round_id, operation_id, operation["phase"])
            binding, prompt = _validate_authoritative_target(authoritative_target, round_id=binding.round_id, binding=binding, prompt=prompt, allow_recovery_owner=operation_id)
            if operation["phase"] == QuarantinePhase.TURN_CONFIRMED.value:
                return operation
            if operation["phase"] == QuarantinePhase.TURN_DISPATCHED.value:
                proof = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
                snapshot = ThreadSnapshot.from_response(proof, conversation_id=binding.conversation_id, prompt=prompt, client_user_message_id=operation["turnRequestId"], turn_id=operation["turnId"])
                if not snapshot.prompt_present or not snapshot.matching_user_message:
                    return self._unknown(operation_id, "post-turn structured user-message proof is missing")
                self._project(operation_id, binding.round_id, {"turnId": operation["turnId"], "clientUserMessageId": operation["turnRequestId"], "postTurnProof": True})
                return self.ledger.transition(operation_id, expected="turn-dispatched", phase="turn-confirmed", evidence={"turnId": operation["turnId"], "postTurnProof": True}, owner_id=owner_id)
            current = self.process.inspect(binding)
            if operation["phase"] == QuarantinePhase.STAGED.value:
                if current is None or not current.matches(binding):
                    return self._unknown(operation_id, "process identity missing or changed")
                self.ledger.transition(operation_id, expected="staged", phase="quarantining", evidence={"identity": binding.as_dict()}, owner_id=owner_id)
                self.process.terminate_exact_session(binding)
                remaining = self.process.inspect(binding)
                if remaining is not None:
                    return self._unknown(operation_id, "exact process or descendants remain")
                self.ledger.transition(operation_id, expected="quarantining", phase="quarantined", evidence={"processGone": True}, owner_id=owner_id)
                operation = self.ledger.get(operation_id)
                authoritative_target = self.round_authority.revalidate_recovery_target(binding.round_id, operation_id, "quarantined")
                _validate_authoritative_target(authoritative_target, round_id=binding.round_id, binding=binding, prompt=prompt, allow_recovery_owner=operation_id)
            if operation["phase"] == QuarantinePhase.TURN_RESERVED.value:
                # A crash can occur after the request id is durably recorded
                # and after turn/start has reached app-server.  Re-read the
                # complete thread before considering another send.  A prompt
                # found here is authoritative proof that the prior send won.
                reread = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
                reread_snapshot = ThreadSnapshot.from_response(reread, conversation_id=binding.conversation_id, prompt=prompt, client_user_message_id=operation["turnRequestId"], turn_id=operation["turnId"])
                if reread_snapshot.prompt_present and reread_snapshot.matching_user_message:
                    self.round_authority.revalidate_recovery_target(binding.round_id, operation_id, "turn-reserved")
                    self._project(operation_id, binding.round_id, {"turnId": reread_snapshot.matching_turn_id, "clientUserMessageId": operation["turnRequestId"], "postTurnProof": True})
                    self.ledger.transition(operation_id, expected="turn-reserved", phase="turn-dispatched", turn_id=reread_snapshot.matching_turn_id, evidence={"recoveredAfterCrash": True}, owner_id=owner_id)
                    return self.ledger.transition(operation_id, expected="turn-dispatched", phase="turn-confirmed", evidence={"recoveredAfterCrash": True, "postTurnProof": True}, owner_id=owner_id)
                return self._unknown(operation_id, "reserved turn has no prompt proof")
            read = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
            snapshot = ThreadSnapshot.from_response(read, conversation_id=binding.conversation_id, prompt=prompt)
            snapshot.require_reconnect_safe()
            self.ledger.transition(operation_id, expected="quarantined", phase="thread-verified", evidence={"turnIds": snapshot.turn_ids}, owner_id=owner_id)
            resumed = self.app_server.request("thread/resume", {"threadId": binding.conversation_id})
            resumed_snapshot = ThreadSnapshot.from_response(resumed, conversation_id=binding.conversation_id, prompt=prompt)
            resumed_snapshot.require_reconnect_safe(after_resume=True)
            self.ledger.transition(operation_id, expected="thread-verified", phase="resume-verified", evidence={"canAcceptDirectInput": True}, owner_id=owner_id)
            operation = self.ledger.get(operation_id)
            request_id = operation["turnRequestId"] or f"quarantine-turn-{secrets.token_urlsafe(16)}"
            self.ledger.transition(operation_id, expected="resume-verified", phase="turn-reserved", turn_request_id=request_id, evidence={"clientUserMessageId": request_id}, owner_id=owner_id)
            reread = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
            reread_snapshot = ThreadSnapshot.from_response(reread, conversation_id=binding.conversation_id, prompt=prompt, client_user_message_id=request_id)
            if reread_snapshot.prompt_present and reread_snapshot.matching_user_message:
                self.round_authority.revalidate_recovery_target(binding.round_id, operation_id, "turn-reserved")
                self._project(operation_id, binding.round_id, {"turnId": reread_snapshot.matching_turn_id, "clientUserMessageId": request_id, "postTurnProof": True})
                self.ledger.transition(operation_id, expected="turn-reserved", phase="turn-dispatched", turn_id=reread_snapshot.matching_turn_id, evidence={"recoveredAfterCrash": True}, owner_id=owner_id)
                return self.ledger.transition(operation_id, expected="turn-dispatched", phase="turn-confirmed", evidence={"recoveredAfterCrash": True, "postTurnProof": True}, owner_id=owner_id)
            authority_fn = getattr(self.round_authority, "claim_recovery_target", self.round_authority.revalidate_recovery_target)
            authority_fn(binding.round_id, operation_id, "before-turn-send")
            response = self.app_server.request("turn/start", {"threadId": binding.conversation_id, "clientUserMessageId": request_id, "input": [{"type": "text", "text": prompt}]})
            turn = response.get("turn")
            if not isinstance(turn, Mapping) or not isinstance(turn.get("id"), str):
                return self._unknown(operation_id, "turn/start response lacks authoritative turn id")
            self.round_authority.revalidate_recovery_target(binding.round_id, operation_id, "before-turn-confirmation")
            post = self.app_server.request("thread/read", {"threadId": binding.conversation_id, "includeTurns": True})
            post_snapshot = ThreadSnapshot.from_response(post, conversation_id=binding.conversation_id, prompt=prompt, client_user_message_id=request_id, turn_id=turn["id"])
            if not post_snapshot.prompt_present or not post_snapshot.matching_user_message:
                return self._unknown(operation_id, "post-turn structured user-message proof is missing")
            self._project(operation_id, binding.round_id, {"turnId": turn["id"], "clientUserMessageId": request_id, "postTurnProof": True})
            dispatched = self.ledger.transition(operation_id, expected="turn-reserved", phase="turn-dispatched", turn_id=turn["id"], evidence={"turnId": turn["id"], "clientUserMessageId": request_id, "postTurnProof": True}, owner_id=owner_id)
            return self.ledger.transition(operation_id, expected="turn-dispatched", phase="turn-confirmed", evidence={"turnId": turn["id"], "postTurnProof": True}, owner_id=owner_id)
        except (QuarantineRecoveryError, OSError, ValueError, sqlite3.Error) as error:
            return self._unknown(operation_id, str(error))

    def _project(self, operation_id: str, round_id: str, evidence: Mapping[str, Any]) -> Mapping[str, Any]:
        project = getattr(self.round_authority, "project_confirmed", None)
        if not callable(project):
            raise QuarantineRecoveryError("authoritative success projection is unavailable")
        return project(round_id, operation_id, evidence)

    def _unknown(self, operation_id: str, reason: str) -> dict[str, Any]:
        current = self.ledger.get(operation_id)
        if current["phase"] in {QuarantinePhase.TURN_CONFIRMED.value, QuarantinePhase.QUARANTINED_UNKNOWN.value}:
            return current
        # A worker that lost the durable claim must never overwrite the
        # winning worker's in-flight state with quarantined-unknown.
        if current.get("ownerId") is None:
            return current
        owner_id = current["ownerId"]
        try:
            return self.ledger.transition(operation_id, expected=current["phase"], phase="quarantined-unknown", evidence={"reason": reason}, owner_id=owner_id)
        except QuarantineRecoveryError:
            return self.ledger.get(operation_id)


def _camel_to_snake(value: str) -> str:
    output = []
    for char in value:
        output.append("_" + char.lower() if char.isupper() else char)
    return "".join(output)


__all__ = ["AppServerCapabilityProbe", "ApprovalEvidence", "CodexAppServerTransport", "ProcessIdentity", "QuarantineLedger", "QuarantinePhase", "QuarantineRecovery", "QuarantineRecoveryError", "RoundQuarantineBinding", "ThreadSnapshot"]
