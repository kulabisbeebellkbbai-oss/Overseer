from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from overseer.psychlo_bridge import PsychloBridge, PsychloBridgeStore


NOW = "2026-08-18T12:00:00+00:00"


def _request(*, thread_id: str | None = None) -> dict:
    value = {
        "roundId": "round-thread-binding",
        "projectId": "arcade",
        "projectLeadId": "lead-arcade",
        "planId": "plan-arcade",
        "planVersion": "v1",
        "correlationId": "corr-thread-binding",
        "idempotencyKey": "request-thread-binding",
        "snapshotId": "snapshot-thread-binding",
        "policyVersion": "policy-thread-binding",
        "expectedUsageCost": 1,
        "scope": "one bounded round",
        "selectionReason": "priority-selected",
        "priorityRationale": "manual-priority",
    }
    if thread_id is not None:
        value["threadId"] = thread_id
    return value


class _ThreadAwareDispatcher:
    def __init__(self, *, static_conversation: str = "conversation-old", available: set[str] | None = None):
        self.static_conversation = static_conversation
        self.available = {static_conversation} if available is None else available
        self.binding_calls: list[tuple[str, str | None, str | None]] = []
        self.dispatch_calls: list[tuple[str, str | None, str | None]] = []

    def binding_provenance(self, lead: str, *, conversation_id: str | None = None, thread_id: str | None = None):
        self.binding_calls.append((lead, conversation_id, thread_id))
        target = conversation_id or self.static_conversation
        if target not in self.available:
            raise ValueError("bound project lead conversation is unavailable")
        return {"conversationId": target, "sessionId": f"session-{target}", "rolloutPathDigest": "a" * 64, "rolloutDev": 1, "rolloutIno": 2}

    def __call__(self, lead: str, _prompt: str, *, idempotency_key: str, conversation_id: str | None = None, thread_id: str | None = None):
        self.dispatch_calls.append((lead, conversation_id, thread_id))
        return "dispatch-thread-binding"


def test_signed_arbitrary_thread_id_cannot_replace_protected_static_binding(tmp_path: Path):
    dispatcher = _ThreadAwareDispatcher()
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=dispatcher,
        sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )

    with pytest.raises(ValueError, match="not authorized"):
        bridge.request_round(_request(thread_id="conversation-attacker"))

    assert dispatcher.dispatch_calls == []
    assert bridge.store.get_round("round-thread-binding")[4] == "pending"


def test_legacy_threadless_request_keeps_static_binding_and_dispatches(tmp_path: Path):
    dispatcher = _ThreadAwareDispatcher()
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=dispatcher,
        sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )

    result = bridge.request_round(_request())

    assert result["accepted"] is True
    assert dispatcher.dispatch_calls == [("lead-arcade", None, None)]
    assert bridge.store.round_binding("round-thread-binding")["conversationId"] == "conversation-old"


def test_exact_thread_dispatch_passes_thread_and_provenance_to_actual_dispatcher(tmp_path: Path):
    dispatcher = _ThreadAwareDispatcher()
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=dispatcher,
        sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )

    result = bridge.request_round(_request(thread_id="conversation-old"))

    assert result["accepted"] is True
    assert dispatcher.binding_calls == [("lead-arcade", None, "conversation-old")]
    assert dispatcher.dispatch_calls == [("lead-arcade", None, "conversation-old")]


def test_requested_unavailable_conversation_fails_before_dispatch(tmp_path: Path):
    dispatcher = _ThreadAwareDispatcher(available=set())
    bridge = PsychloBridge(
        store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=dispatcher,
        sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )

    with pytest.raises(ValueError, match="unavailable"):
        bridge.request_round(_request(thread_id="conversation-old"))

    assert dispatcher.dispatch_calls == []


def _completed_successor_intent(store: PsychloBridgeStore, *, plan_id: str = "plan-successor", plan_version: str = "v2") -> None:
    payload = {
        "projectId": "arcade", "roundId": "round-old", "planId": "admin-abandonment",
        "planDigest": "d" * 64, "wire": {"signed": True},
        "successorPlan": {
            "successorPlanId": plan_id, "successorPlanVersion": plan_version,
            "successorConversationId": "conversation-successor", "successorThreadId": "thread-successor",
        },
    }
    store.stage_legacy_abandonment("action-successor", "round-old", "a" * 64, payload, now=NOW)
    store.connection.execute("UPDATE legacy_abandonment_intents SET state='completed' WHERE action_id='action-successor'")


def test_completed_approved_successor_binds_exact_conversation_and_dispatch_call(tmp_path: Path, monkeypatch):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _completed_successor_intent(store)
    dispatcher = _ThreadAwareDispatcher(static_conversation="conversation-old", available={"conversation-successor"})
    primary = SimpleNamespace(load_admin_change_plan=lambda _plan_id: object())
    monkeypatch.setattr("overseer.psychlo_legacy_abandonment._require_approved_sisko_plan", lambda *_args: None)
    monkeypatch.setattr("overseer.psychlo_legacy_abandonment._expected_plan", lambda *_args: object())
    monkeypatch.setattr("overseer.psychlo_legacy_abandonment._immutable_plan_digest", lambda *_args: "d" * 64)
    monkeypatch.setattr("overseer.psychlo_legacy_abandonment._validate_wire", lambda *_args: {"signed": True})
    bridge = PsychloBridge(
        store=store, dispatcher=dispatcher, approval_store=primary,
        sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )

    request = {**_request(thread_id="thread-successor"), "planId": "plan-successor", "planVersion": "v2"}
    result = bridge.request_round(request)

    assert result["accepted"] is True
    assert dispatcher.binding_calls == [("lead-arcade", "conversation-successor", "thread-successor")]
    assert dispatcher.dispatch_calls == [("lead-arcade", "conversation-successor", "thread-successor")]


def test_successor_thread_with_mismatched_plan_is_rejected_before_dispatch(tmp_path: Path, monkeypatch):
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    _completed_successor_intent(store)
    dispatcher = _ThreadAwareDispatcher(available={"conversation-successor"})
    primary = SimpleNamespace(load_admin_change_plan=lambda _plan_id: object())
    bridge = PsychloBridge(
        store=store, dispatcher=dispatcher, approval_store=primary,
        sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766",
        clock=lambda: NOW,
    )
    request = {**_request(thread_id="thread-successor"), "planId": "wrong-plan", "planVersion": "v2"}

    with pytest.raises(ValueError, match="successor round plan identity"):
        bridge.request_round(request)

    assert dispatcher.dispatch_calls == []
