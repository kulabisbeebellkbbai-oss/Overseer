from __future__ import annotations

from pathlib import Path

from overseer.psychlo_bridge import PsychloBridge
from overseer.psychlo_store import PsychloBridgeStore
from overseer.psychlo_contracts import learning_observation_digest


NOW = "2026-08-10T02:00:00+00:00"


def test_learning_pull_delivers_sanitized_observations_then_acks(tmp_path: Path):
    calls = []
    observation = {"id": "observation-123", "featureProfile": {"taskClass": "python-feature", "model": "gpt-5.6-luna", "expectedComponents": 2, "buildGate": True}, "outcome": {"status": "completed", "observedAt": NOW}}
    observation = {**observation, "digest": learning_observation_digest(observation), "state": "queued"}
    def send(kind, message_id, payload):
        calls.append((kind, message_id, payload))
        if kind == "learning-pull":
            return {"accepted": True, "observations": [observation]}
        return {"accepted": True}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    result = bridge.pull_learning("skiller", {"skiller": lambda item: None})
    assert result["delivered"] == 1
    assert [item[0] for item in calls] == ["learning-pull", "learning-ack"]


def test_learning_observation_rejects_nested_or_unbounded_values_before_persistence(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    payload = {"id": "observation-123", "featureProfile": {"taskClass": ["python-feature"]}, "outcome": {"status": "completed", "observedAt": NOW}}
    try:
        bridge.record_learning_observation(payload)
    except ValueError:
        pass
    else:
        raise AssertionError("nested learning value was persisted")
    assert bridge.store.learning_observation("observation-123") is None


def test_learning_adapter_failure_does_not_ack_and_retry_is_monotonic(tmp_path: Path):
    calls = []
    observation = {"id": "observation-123", "featureProfile": {"taskClass": "python-feature"}, "outcome": {"status": "completed", "observedAt": NOW}}
    observation = {**observation, "digest": learning_observation_digest(observation), "state": "queued"}
    def send(kind, message_id, payload):
        calls.append(kind)
        return {"accepted": True, "observations": [observation]} if kind == "learning-pull" else {"accepted": True}
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=send, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    first = bridge.pull_learning("skiller", {"skiller": lambda _: (_ for _ in ()).throw(RuntimeError("down"))})
    assert first == {"delivered": 0, "failed": 1}
    assert calls == ["learning-pull"]
    assert bridge.store.learning_observation("observation-123")["attempts"]["skiller"] == 1
    second = bridge.pull_learning("skiller", {"skiller": lambda _: None})
    assert second == {"delivered": 1, "failed": 0}
    assert calls == ["learning-pull", "learning-pull", "learning-ack"]
    assert bridge.store.learning_observation("observation-123")["attempts"]["skiller"] == 2


def test_learning_advisory_is_strictly_persisted_and_replayed(tmp_path: Path):
    bridge = PsychloBridge(store=PsychloBridgeStore(tmp_path / "bridge.sqlite3"), dispatcher=lambda *_: "unused", sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW)
    advisory = {"source": "skiller", "version": "psychlo-estimate-v1", "digest": "a" * 64, "confidence": 0.75, "evidenceLineage": ["sha256:" + "b" * 64], "featureClass": "python-feature", "expectedUsage": 3, "signatureValid": True, "compatible": True, "observedAt": NOW}
    first = bridge.receive_learning_advisory({"prior": advisory})
    replay = bridge.receive_learning_advisory({"prior": advisory})
    assert first["prior"] == replay["prior"] == advisory
    try:
        bridge.receive_learning_advisory({"prior": {**advisory, "confidence": 0.25}})
    except ValueError as error:
        assert "conflict" in str(error)
    else:
        raise AssertionError("learning advisory conflict was accepted")
