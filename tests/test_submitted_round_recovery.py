from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from overseer.psychlo_bridge import PsychloBridge
from overseer.psychlo_bridge_cli import build_parser
from overseer.psychlo_store import PsychloBridgeStore
from overseer.agent_adapters.codex import CodexDriver
from overseer.agent_contracts import AgentCapabilities, AgentInstanceProfile, AgentProvider, AgentTransport


NOW = "2026-08-17T15:00:00+00:00"
BINDING = {"conversationId": "conversation-arcade", "sessionId": "session-arcade", "rolloutPathDigest": "a" * 64, "rolloutDev": 1, "rolloutIno": 2}


def _request() -> dict:
    return {
        "roundId": "round:arcade:submitted-recovery",
        "projectId": "arcade", "projectLeadId": "lead-arcade", "planId": "plan-arcade",
        "planVersion": "v1", "correlationId": "corr-arcade", "idempotencyKey": "round:arcade:submitted-recovery",
        "snapshotId": "snapshot-arcade", "policyVersion": "2026-08-09", "expectedUsageCost": 1,
        "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "gate-proximity",
    }


def _seed(store: PsychloBridgeStore, bridge: PsychloBridge) -> tuple[dict, str, str]:
    request = _request()
    capability = "cap-arcade-submitted-1234567890abcdef"
    receipt = {**request, "sourceId": request["projectLeadId"], "provenanceId": "overseer-dispatch:" + request["roundId"], "status": "accepted"}
    store.record_single_stream_round(request, receipt, capability)
    prompt = bridge._round_prompt(request, capability)
    digest = hashlib.sha256(prompt.encode()).hexdigest()
    assert store.start_round_dispatch(request["roundId"], request, capability, NOW, binding=BINDING, prompt_digest=digest)
    store.record_round_prompt_delivery_phase(request["roundId"], request, capability, BINDING, digest, "submitted", now=NOW, expected_phase="prepared")
    return request, capability, prompt


class Dispatcher:
    def __init__(self, *, found_after_submit: bool = True, proof: bool = True):
        self.found_after_submit = found_after_submit
        self.proof = proof
        self.submits = 0
        self.scans = 0

    def scan_rollout(self, _lead: str, _prompt: str):
        self.scans += 1
        return {"found": self.scans > 1 and self.found_after_submit, **BINDING}

    def prove_queued_input(self, _lead: str, prompt: str):
        if not self.proof:
            raise ValueError("queued terminal input cannot be proven byte-exact")
        return {"proof": "attested-queued-input", "promptDigest": hashlib.sha256(prompt.encode()).hexdigest(), "rollout": BINDING}

    def submit_queued_input(self, _lead: str, _prompt: str, *, idempotency_key: str, proof):
        self.submits += 1
        assert proof["proof"] == "attested-queued-input"
        return {"dispatchId": "submitted:" + idempotency_key}


def test_cli_exposes_distinct_submitted_round_recovery_command():
    args = build_parser().parse_args(["recover-submitted-round", "--round-id", "round-1", "--owner-id", "owner-1"])
    assert args.command == "recover-submitted-round"
    assert args.round_id == "round-1"
    assert args.owner_id == "owner-1"


def test_submitted_round_recovery_persists_intent_then_one_enter_and_post_proof(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    dispatcher = Dispatcher()
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request, _capability, _prompt = _seed(store, bridge)

    result = bridge.recover_submitted_round(request["roundId"], owner_id="owner-1")

    assert result["status"] == "recovered"
    assert dispatcher.submits == 1
    assert store.get_round(request["roundId"])[4] == "dispatched"
    assert store.round_prompt_delivery(request["roundId"])["phase"] == "confirmed"
    intent = store.submitted_round_recovery_intent(request["roundId"])
    assert intent is not None and intent["state"] == "completed"


def test_submitted_round_recovery_fails_before_intent_without_exact_input_proof(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    dispatcher = Dispatcher(proof=False)
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request, _capability, _prompt = _seed(store, bridge)

    with pytest.raises(ValueError, match="byte-exact"):
        bridge.recover_submitted_round(request["roundId"], owner_id="owner-1")
    assert dispatcher.submits == 0
    assert store.submitted_round_recovery_intent(request["roundId"]) is None
    assert store.get_round(request["roundId"])[4] == "started"


def test_missing_post_enter_proof_fences_intent_and_never_retries(tmp_path: Path):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    dispatcher = Dispatcher(found_after_submit=False)
    bridge = PsychloBridge(store=store, dispatcher=dispatcher, sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    request, _capability, _prompt = _seed(store, bridge)

    with pytest.raises(ValueError, match="delivery proof"):
        bridge.recover_submitted_round(request["roundId"], owner_id="owner-1")
    with pytest.raises(ValueError, match="already attempted"):
        bridge.recover_submitted_round(request["roundId"], owner_id="owner-2")
    assert dispatcher.submits == 1
    assert store.get_round(request["roundId"])[4] == "started"
    assert store.submitted_round_recovery_intent(request["roundId"])["state"] == "uncertain"


def test_codex_queued_submit_uses_exact_proof_and_one_enter_without_paste(tmp_path: Path, monkeypatch):
    registry = tmp_path / "codex-projects.csv"
    registry.write_text("conversation_id,label,project,command,launcher,created_at,updated_at,source,notes\nconversation-1,Arcade,/workspace/arcade,arcade,/bin/arcade,now,now,registry,\n", encoding="utf-8")
    commands = []
    prompt = "Continue the approved round."

    class Runner:
        executable_path = "/tmp/tmux"

        def run_bounded(self, command, input_text=None, **_kwargs):
            commands.append((tuple(command), input_text))
            if command[1] == "has-session":
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[1] == "capture-pane":
                return subprocess.CompletedProcess(command, 0, "Codex> " + prompt, "")
            return subprocess.CompletedProcess(command, 0, "", "")

    provider = AgentProvider(id="codex", adapter_id="codex", capabilities=AgentCapabilities(session_discovery=True, session_resume=True, interactive_dispatch=True), transports=(AgentTransport.INTERACTIVE_CLI,), executable_allowlist=("codex",))
    profile = AgentInstanceProfile(id="overseer.default", primary_provider_id="codex", primary_adapter_id="codex", transport=AgentTransport.INTERACTIVE_CLI, workspace="/workspace/arcade")
    proof_value = {"proof": "attested-queued-input", "promptDigest": hashlib.sha256(prompt.encode()).hexdigest(), "rollout": {"conversationId": "conversation-1", "sessionId": "session.codex.arcade", "rolloutPathDigest": "a" * 64, "rolloutDev": 1, "rolloutIno": 2}}
    driver = CodexDriver(provider, profile, registry_path=registry, tmux_path="/tmp/tmux", runner=Runner(), queued_input_proof_factory=lambda _session, _prompt: proof_value)
    session = driver.discover()[0]

    proof = driver.prove_queued_prompt(session, prompt)
    dispatch_id = driver.submit_queued_prompt(session, prompt, idempotency_key="round-1", proof=proof)

    assert dispatch_id.startswith("submitted.")
    assert sum(command[0][1] == "send-keys" and command[0][-1] == "Enter" for command in commands) == 1
    assert not any(command[0][1] in {"load-buffer", "paste-buffer", "capture-pane"} for command in commands)
