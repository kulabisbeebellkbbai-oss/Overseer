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
import hashlib


PROMPT = "resume arcade exact prompt"


def binding() -> RoundQuarantineBinding:
    return RoundQuarantineBinding(
        round_id="round:arcade:test",
        request_digest="a" * 64,
        callback_digest="b" * 64,
        prompt_digest=hashlib.sha256(PROMPT.encode()).hexdigest(),
        conversation_id="019fe9c9-8eee-75c2-a447-f32d80d2651e",
        rollout_path_digest="d" * 64,
        rollout_dev=11,
        rollout_ino=22,
        tmux_socket="/tmp/tmux-test.sock",
        tmux_server_start_identity="server-start",
        tmux_session_id="$1",
        tmux_pane_id="%1",
        tmux_pane_pid=1234,
        tmux_pane_start_identity="987654",
        tmux_cgroup="0::/user.slice/codex",
    )


def thread(thread_id: str, *, prompt: str | None = None, client_id: str | None = None, turn_id: str = "turn-new", can_accept: bool = True, status: str = "idle", turn_status: str = "completed") -> dict:
    content = [{"type": "text", "text": prompt}] if prompt is not None else []
    return {
        "thread": {
            "id": thread_id,
            "canAcceptDirectInput": can_accept,
            "status": {"type": status},
            "turns": [{"id": "turn-old", "status": "completed", "itemsView": "full", "items": [{"id": "item-old", "type": "agentMessage", "text": "done"}]}]
            if prompt is None
            else [{"id": turn_id, "status": turn_status, "itemsView": "full", "items": [{"id": "item-new", "type": "userMessage", "clientId": client_id, "content": content}]}],
        }
    }


class FakeProcess:
    def __init__(self):
        self.gone = False
        self.terminated = []

    def inspect(self, value):
        if self.gone:
            return None
        return ProcessIdentity(value.tmux_session_id, value.tmux_pane_id, value.tmux_pane_pid, value.tmux_pane_start_identity, value.tmux_server_start_identity, value.tmux_cgroup)

    def terminate_exact_session(self, value):
        self.terminated.append(value)
        self.gone = True


class FakeServer:
    def __init__(self, conversation_id: str, *, prompt_after_send: bool = True):
        self.conversation_id = conversation_id
        self.prompt_after_send = prompt_after_send
        self.calls = []
        self.sent = False
        self.client_id = None

    def request(self, method, params):
        self.calls.append((method, dict(params)))
        assert params.get("threadId") in {None, self.conversation_id}
        if method == "thread/read":
            return thread(self.conversation_id, prompt=PROMPT if self.sent else None, client_id=self.client_id, turn_id="turn-recovery-1")
        if method == "thread/resume":
            return thread(self.conversation_id)
        if method == "turn/start":
            self.sent = True
            self.client_id = params["clientUserMessageId"]
            return {"turn": {"id": "turn-recovery-1", "status": "inProgress", "items": []}}
        raise AssertionError(method)


class FakeAuthority:
    def __init__(self):
        self.calls = []

    def load_recovery_target(self, round_id):
        return {"roundId": round_id, "state": "started", "result": None, "deliveryPhase": "submitted", "failure": None, "recovery": None, "cancellation": None, "binding": binding().as_dict(), "prompt": PROMPT}

    def revalidate_recovery_target(self, round_id, operation_id, phase):
        self.calls.append(phase)
        return self.load_recovery_target(round_id)

    def claim_recovery_target(self, round_id, operation_id, phase):
        self.calls.append("claim:" + phase)
        return self.load_recovery_target(round_id)

    def project_confirmed(self, round_id, operation_id, evidence):
        self.calls.append("project")
        return {"projected": True, "roundId": round_id}


class FakeApprovals:
    def load_approved_plan(self, approval_id):
        return {"approvalId": approval_id, "status": "approved", "target": binding().round_id, "planDigest": "e" * 64}


def stage(ledger: QuarantineLedger):
    approval = ApprovalEvidence("approval-1", "e" * 64, "approved")
    return ledger.stage(operation_id="op-1", binding=binding(), prompt=PROMPT, approval=approval, round_authority=FakeAuthority(), approval_authority=FakeApprovals())


def recovery(ledger, process, server):
    return QuarantineRecovery(ledger, process, server, round_authority=FakeAuthority(), approval_authority=FakeApprovals())


def test_recovery_quarantines_exact_process_and_dispatches_structured_turn(tmp_path: Path):
    ledger = QuarantineLedger(tmp_path / "quarantine.sqlite3")
    process = FakeProcess()
    server = FakeServer(binding().conversation_id)
    stage(ledger)

    result = recovery(ledger, process, server).execute("op-1", approval=ApprovalEvidence("approval-1", "e" * 64, "approved"))

    assert result["phase"] == "turn-confirmed"
    assert result["turnId"] == "turn-recovery-1"
    assert process.gone is True
    assert [call[0] for call in server.calls] == ["thread/read", "thread/resume", "thread/read", "turn/start", "thread/read"]
    assert server.calls[-2][1]["input"] == [{"type": "text", "text": PROMPT}]
    assert server.calls[-2][1]["clientUserMessageId"] == result["turnRequestId"]
    ledger.close()


def test_recovery_is_crash_safe_after_turn_reservation(tmp_path: Path):
    ledger = QuarantineLedger(tmp_path / "quarantine.sqlite3")
    process = FakeProcess()
    server = FakeServer(binding().conversation_id)
    stage(ledger)
    ledger.claim("op-1", owner_id="test", lease_expires_at="2000-01-01T00:00:00+00:00")
    ledger.transition("op-1", expected="staged", phase="quarantining", owner_id="test")
    process.gone = True
    ledger.transition("op-1", expected="quarantining", phase="quarantined", owner_id="test")
    ledger.transition("op-1", expected="quarantined", phase="thread-verified", owner_id="test")
    ledger.transition("op-1", expected="thread-verified", phase="resume-verified", owner_id="test")
    ledger.transition("op-1", expected="resume-verified", phase="turn-reserved", turn_request_id="request-persisted", owner_id="test")
    server.sent = True
    server.client_id = "request-persisted"

    result = recovery(ledger, process, server).execute("op-1", approval=ApprovalEvidence("approval-1", "e" * 64, "approved"))

    assert result["phase"] == "turn-confirmed"
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

    result = recovery(ledger, process, server).execute("op-1", approval=ApprovalEvidence("approval-1", "e" * 64, "approved"))

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


def test_stage_rejects_prompt_digest_or_authoritative_binding_mismatch(tmp_path: Path):
    ledger = QuarantineLedger(tmp_path / "quarantine.sqlite3")
    authority = FakeAuthority()
    target = authority.load_recovery_target(binding().round_id)
    target["prompt"] = "caller or bridge mismatch"
    authority.load_recovery_target = lambda _round_id: target
    with pytest.raises(QuarantineRecoveryError, match="digest"):
        ledger.stage(operation_id="op-1", binding=binding(), prompt=PROMPT, approval=ApprovalEvidence("approval-1", "e" * 64, "approved"), round_authority=authority, approval_authority=FakeApprovals())
    ledger.close()


def test_structured_agent_message_mention_does_not_prove_user_prompt():
    response = thread("probe:disposable-1")
    response["thread"]["turns"][0]["items"] = [{"id": "agent", "type": "agentMessage", "text": PROMPT}]
    snapshot = ThreadSnapshot.from_response(response, conversation_id="probe:disposable-1", prompt=PROMPT)
    assert snapshot.prompt_present is False


def test_proc_stat_parser_handles_spaces_in_comm(monkeypatch):
    from overseer.codex_quarantine_recovery import _proc_start_identity

    class FakeFile:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return "42 (codex worker with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22\n"

    monkeypatch.setattr("builtins.open", lambda *args, **kwargs: FakeFile())
    assert _proc_start_identity(42) == "19"


def test_ledger_phase_is_monotonic_and_claim_is_single_owner(tmp_path: Path):
    ledger = QuarantineLedger(tmp_path / "quarantine.sqlite3")
    stage(ledger)
    assert ledger.claim("op-1", owner_id="owner-a", lease_expires_at="9999-01-01T00:00:00+00:00") is True
    assert ledger.claim("op-1", owner_id="owner-b", lease_expires_at="9999-01-01T00:00:00+00:00") is False
    with pytest.raises(QuarantineRecoveryError, match="not allowed"):
        ledger.transition("op-1", expected="staged", phase="turn-confirmed", owner_id="owner-a")
    ledger.close()


def test_capability_probe_creates_turn_and_reconnects_with_exact_proof():
    class DisposableServer:
        def __init__(self, shared):
            self.calls = []
            self.shared = shared

        def request(self, method, params):
            self.calls.append((method, params))
            if method == "thread/start":
                return {"thread": {"id": "created-disposable-thread"}}
            if method == "turn/start":
                self.shared["client_id"] = params["clientUserMessageId"]
                return {"turn": {"id": "probe-turn", "status": "completed", "items": []}}
            if method in {"thread/read", "thread/resume"}:
                return thread("created-disposable-thread", prompt="probe prompt", client_id=self.shared["client_id"], turn_id="probe-turn", turn_status="completed")
            raise AssertionError(method)

    shared = {}
    creator, reconnect = DisposableServer(shared), DisposableServer(shared)
    result = AppServerCapabilityProbe(creator).probe("probe:run-1", prompt="probe prompt", reconnect_transport=reconnect)
    assert result["structuredTurnStart"] is True
    assert result["exactUserMessageProof"] is True
    assert [method for method, _ in creator.calls] == ["thread/start", "turn/start"]
    assert [method for method, _ in reconnect.calls] == ["thread/read", "thread/resume"]


def test_bridge_authority_projects_only_claimed_submitted_round():
    from overseer.codex_quarantine_recovery import PsychloBridgeRoundAuthority

    class StoreDouble:
        def __init__(self):
            self.claimed = None
            self.delivery = {"phase": "submitted", "binding": {"conversationId": binding().conversation_id, "sessionId": "session", "rolloutPathDigest": "d" * 64, "rolloutDev": 11, "rolloutIno": 22}}

        def get_round(self, round_id):
            return ({"roundId": round_id, "idempotencyKey": "idempotency"}, {"roundId": round_id, "status": "pending"}, "hash", "capability-token", "started", None, False)

        def round_prompt_delivery(self, _round_id):
            return self.delivery

        def operational_failure_intent(self, _round_id):
            return None

        def round_recovery(self, _round_id):
            return self.claimed

        def round_cancellation(self, _round_id):
            return None

        def round_binding(self, _round_id):
            return binding().as_dict()

        def claim_round_recovery(self, round_id, request, capability, *, owner_id, lease_expires_at, now):
            self.claimed = {"roundId": round_id, "ownerId": owner_id, "state": "claimed", "claimToken": "claim-token"}
            return True

        def record_round_prompt_delivery_phase(self, *args, **kwargs):
            assert args[5] == "confirmed"
            assert kwargs["expected_phase"] == "submitted"
            self.delivery["phase"] = "confirmed"

        def complete_round_recovery_dispatch(self, round_id, owner_id, claim_token, receipt, evidence, *, now):
            assert owner_id == "operation-1"
            assert claim_token == "claim-token"
            assert receipt["status"] == "accepted"
            self.claimed["state"] = "completed"

    store = StoreDouble()
    authority = PsychloBridgeRoundAuthority(store, prompt_loader=lambda request, capability: PROMPT)
    target = authority.load_recovery_target(binding().round_id)
    assert target["deliveryPhase"] == "submitted"
    claimed = authority.claim_recovery_target(binding().round_id, "operation-1", "staged")
    assert claimed["roundId"] == binding().round_id
    assert authority.revalidate_recovery_target(binding().round_id, "operation-1", "before-turn-send")["state"] == "started"
    assert authority.project_confirmed(binding().round_id, "operation-1", {"postTurnProof": True})["projected"] is True
    assert store.delivery["phase"] == "confirmed"
    assert store.claimed["state"] == "completed"
