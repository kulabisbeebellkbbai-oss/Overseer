from __future__ import annotations

from pathlib import Path

import pytest

from overseer.codex_quarantine_recovery import (
    AppServerCapabilityProbe,
    ApprovalEvidence,
    ProcessIdentity,
    QuarantineLedger,
    QuarantineRecovery,
    QuarantineRecoveryError,
    RoundQuarantineBinding,
    ThreadSnapshot,
)


PROMPT = "resume arcade exact prompt"


def binding() -> RoundQuarantineBinding:
    return RoundQuarantineBinding(
        round_id="round:arcade:test",
        request_digest="a" * 64,
        callback_digest="b" * 64,
        prompt_digest="c" * 64,
        conversation_id="019fe9c9-8eee-75c2-a447-f32d80d2651e",
        rollout_path_digest="d" * 64,
        rollout_dev=11,
        rollout_ino=22,
        tmux_session_id="$1",
        tmux_pane_id="%1",
        tmux_pane_pid=1234,
        tmux_pane_start_identity="987654",
    )


def thread(thread_id: str, *, prompt: str | None = None, can_accept: bool = True, status: str = "idle") -> dict:
    content = [{"type": "text", "text": prompt}] if prompt is not None else []
    return {
        "thread": {
            "id": thread_id,
            "canAcceptDirectInput": can_accept,
            "status": {"type": status},
            "turns": [{"id": "turn-old", "status": "completed", "itemsView": "full", "items": [{"id": "item-old", "type": "agentMessage", "text": "done"}]}]
            if prompt is None
            else [{"id": "turn-new", "status": "inProgress", "itemsView": "full", "items": [{"id": "item-new", "type": "userMessage", "content": content}]}],
        }
    }


class FakeProcess:
    def __init__(self):
        self.gone = False
        self.terminated = []

    def inspect(self, value):
        if self.gone:
            return None
        return ProcessIdentity(value.tmux_session_id, value.tmux_pane_id, value.tmux_pane_pid, value.tmux_pane_start_identity)

    def terminate_exact_session(self, value):
        self.terminated.append(value)
        self.gone = True


class FakeServer:
    def __init__(self, conversation_id: str, *, prompt_after_send: bool = True):
        self.conversation_id = conversation_id
        self.prompt_after_send = prompt_after_send
        self.calls = []
        self.sent = False

    def request(self, method, params):
        self.calls.append((method, dict(params)))
        assert params.get("threadId") in {None, self.conversation_id}
        if method == "thread/read":
            return thread(self.conversation_id, prompt=PROMPT if self.sent else None)
        if method == "thread/resume":
            return thread(self.conversation_id)
        if method == "turn/start":
            self.sent = True
            return {"turn": {"id": "turn-recovery-1", "status": "inProgress", "items": []}}
        raise AssertionError(method)


def stage(ledger: QuarantineLedger):
    return ledger.stage(operation_id="op-1", binding=binding(), prompt=PROMPT, approval=ApprovalEvidence("approval-1", "e" * 64, "approved"))


def test_recovery_quarantines_exact_process_and_dispatches_structured_turn(tmp_path: Path):
    ledger = QuarantineLedger(tmp_path / "quarantine.sqlite3")
    process = FakeProcess()
    server = FakeServer(binding().conversation_id)
    stage(ledger)

    result = QuarantineRecovery(ledger, process, server).execute("op-1", approval=ApprovalEvidence("approval-1", "e" * 64, "approved"))

    assert result["phase"] == "turn-dispatched"
    assert result["turnId"] == "turn-recovery-1"
    assert process.gone is True
    assert [call[0] for call in server.calls] == ["thread/read", "thread/resume", "thread/read", "turn/start"]
    assert server.calls[-1][1]["input"] == [{"type": "text", "text": PROMPT}]
    assert server.calls[-1][1]["clientUserMessageId"] == result["turnRequestId"]
    ledger.close()


def test_recovery_is_crash_safe_after_turn_reservation(tmp_path: Path):
    ledger = QuarantineLedger(tmp_path / "quarantine.sqlite3")
    process = FakeProcess()
    server = FakeServer(binding().conversation_id)
    stage(ledger)
    ledger.transition("op-1", expected="staged", phase="quarantining")
    process.gone = True
    ledger.transition("op-1", expected="quarantining", phase="quarantined")
    ledger.transition("op-1", expected="quarantined", phase="thread-verified")
    ledger.transition("op-1", expected="thread-verified", phase="resume-verified")
    ledger.transition("op-1", expected="resume-verified", phase="turn-reserved", turn_request_id="request-persisted")
    server.sent = True

    result = QuarantineRecovery(ledger, process, server).execute("op-1", approval=ApprovalEvidence("approval-1", "e" * 64, "approved"))

    assert result["phase"] == "turn-dispatched"
    assert result["turnRequestId"] == "request-persisted"
    assert not any(method == "turn/start" for method, _ in server.calls)
    ledger.close()


def test_uncertainty_is_quarantined_unknown_and_does_not_send(tmp_path: Path):
    ledger = QuarantineLedger(tmp_path / "quarantine.sqlite3")
    process = FakeProcess()
    server = FakeServer(binding().conversation_id)
    stage(ledger)
    server.request = lambda method, params: thread(binding().conversation_id, prompt=PROMPT) if method == "thread/read" else thread(binding().conversation_id)
    process.terminate_exact_session = lambda value: (_ for _ in ()).throw(QuarantineRecoveryError("termination uncertain"))

    result = QuarantineRecovery(ledger, process, server).execute("op-1", approval=ApprovalEvidence("approval-1", "e" * 64, "approved"))

    assert result["phase"] == "quarantined-unknown"
    assert result["evidence"]["reason"] == "termination uncertain"
    ledger.close()


def test_capability_probe_requires_disposable_thread_and_never_turn_start():
    class ProbeServer:
        def __init__(self):
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            return thread("probe:disposable-1")

    server = ProbeServer()
    with pytest.raises(ValueError, match="disposable"):
        AppServerCapabilityProbe(server).probe("round:arcade:test")
    with pytest.raises(ValueError, match="disposable"):
        AppServerCapabilityProbe(server).probe("probe:arcade-test")
    assert server.calls == []


def test_thread_snapshot_rejects_incomplete_turn_items():
    response = thread("probe:disposable-1")
    response["thread"]["turns"][0]["itemsView"] = "summary"
    snapshot = ThreadSnapshot.from_response(response, conversation_id="probe:disposable-1", prompt=PROMPT)
    with pytest.raises(QuarantineRecoveryError, match="incomplete"):
        snapshot.require_reconnect_safe()
