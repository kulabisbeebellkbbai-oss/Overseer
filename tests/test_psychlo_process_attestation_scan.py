from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from overseer.psychlo_bridge import CodexProjectDispatcher
from overseer.psychlo_process_attestation import (
    ProcessAttestationError,
    _collect_bound_rollout_evidence,
)


BOUND = {
    "conversationId": "conversation-arcade",
    "sessionId": "session-arcade",
    "rolloutPathDigest": "a" * 64,
    "rolloutDev": 1,
    "rolloutIno": 2,
}


def test_provenance_rich_scan_is_closed_and_routed_to_stored_delivery_conversation():
    calls: list[tuple[str, str, str]] = []

    def scanner(lead, prompt, *, conversation_id):
        calls.append(("scan", lead, conversation_id))
        return {"found": False, **BOUND}

    def binding_loader(lead, *, conversation_id):
        calls.append(("binding", lead, conversation_id))
        return dict(BOUND)

    assert _collect_bound_rollout_evidence(scanner, binding_loader, "member-hermione", "prompt", BOUND) == {
        "found": False,
        **BOUND,
    }
    assert calls == [
        ("scan", "member-hermione", "conversation-arcade"),
        ("binding", "member-hermione", "conversation-arcade"),
    ]


def test_legacy_false_scan_requires_independent_exact_binding_provenance():
    assert _collect_bound_rollout_evidence(
        lambda *_args, **_kwargs: False,
        lambda *_args, **_kwargs: dict(BOUND),
        "member-hermione",
        "prompt",
        BOUND,
    )["found"] is False


@pytest.mark.parametrize(
    "scan",
    [
        True,
        {"found": True, **BOUND},
        {"found": False, **BOUND, "unexpected": "field"},
        {"found": False, **{key: value for key, value in BOUND.items() if key != "rolloutIno"}},
        {"found": False, **{**BOUND, "conversationId": "conversation-other"}},
    ],
)
def test_scan_rejects_nonnegative_or_nonexact_provenance(scan):
    with pytest.raises(ProcessAttestationError):
        _collect_bound_rollout_evidence(
            lambda *_args, **_kwargs: scan,
            lambda *_args, **_kwargs: dict(BOUND),
            "member-hermione",
            "prompt",
            BOUND,
        )


def test_legacy_false_scan_rejects_binding_identity_drift():
    drifted = {**BOUND, "rolloutPathDigest": "b" * 64}
    with pytest.raises(ProcessAttestationError):
        _collect_bound_rollout_evidence(
            lambda *_args, **_kwargs: False,
            lambda *_args, **_kwargs: drifted,
            "member-hermione",
            "prompt",
            BOUND,
        )


def test_codex_project_dispatcher_preserves_provenance_rich_scan(monkeypatch, tmp_path: Path):
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps({"member-hermione": {"conversationId": BOUND["conversationId"]}}))
    bindings.chmod(0o600)
    session = SimpleNamespace(id="session-arcade", external_session_id=BOUND["conversationId"])

    class Driver:
        def discover(self):
            return [session]

        def scan_rollout_prompt(self, _session, _prompt):
            return {"found": False, **BOUND}

        def rollout_provenance(self, _session):
            return dict(BOUND)

    monkeypatch.setattr("overseer.agent_adapters.codex.CodexDriver.from_legacy_registry", lambda: Driver())
    dispatcher = CodexProjectDispatcher(bindings)
    result = dispatcher.scan_rollout(
        "member-hermione",
        "prompt",
        conversation_id=BOUND["conversationId"],
    )
    assert result == {"found": False, **BOUND}


@pytest.mark.parametrize(
    "raw_scan",
    [
        {"found": False, **{**BOUND, "conversationId": "conversation-other"}},
        {"found": False, **BOUND, "unexpected": "field"},
        {"found": False, **{**BOUND, "rolloutPathDigest": "b" * 64}},
    ],
)
def test_codex_project_dispatcher_rejects_raw_scan_provenance_laundering(
    monkeypatch, tmp_path: Path, raw_scan
):
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps({"member-hermione": {"conversationId": BOUND["conversationId"]}}))
    bindings.chmod(0o600)
    session = SimpleNamespace(id="session-arcade", external_session_id=BOUND["conversationId"])

    class Driver:
        def discover(self):
            return [session]

        def scan_rollout_prompt(self, _session, _prompt):
            return raw_scan

        def rollout_provenance(self, _session):
            return dict(BOUND)

    monkeypatch.setattr("overseer.agent_adapters.codex.CodexDriver.from_legacy_registry", lambda: Driver())
    dispatcher = CodexProjectDispatcher(bindings)
    with pytest.raises(ValueError, match="rollout scan|identity provenance"):
        dispatcher.scan_rollout(
            "member-hermione",
            "prompt",
            conversation_id=BOUND["conversationId"],
        )


def test_codex_project_dispatcher_legacy_bool_uses_independent_provenance(monkeypatch, tmp_path: Path):
    bindings = tmp_path / "bindings.json"
    bindings.write_text(json.dumps({"member-hermione": {"conversationId": BOUND["conversationId"]}}))
    bindings.chmod(0o600)
    session = SimpleNamespace(id="session-arcade", external_session_id=BOUND["conversationId"])

    class Driver:
        def discover(self):
            return [session]

        def scan_rollout_prompt(self, _session, _prompt):
            return False

        def rollout_provenance(self, _session):
            return dict(BOUND)

    monkeypatch.setattr("overseer.agent_adapters.codex.CodexDriver.from_legacy_registry", lambda: Driver())
    dispatcher = CodexProjectDispatcher(bindings)
    assert dispatcher.scan_rollout(
        "member-hermione", "prompt", conversation_id=BOUND["conversationId"]
    ) == {"found": False, **BOUND}
