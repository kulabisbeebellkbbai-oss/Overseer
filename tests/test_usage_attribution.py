from __future__ import annotations

import hashlib
import json
import multiprocessing
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from overseer.psychlo_contracts import canonical_digest, parse_usage_snapshot_v11
from overseer.usage_attribution import (
    UsageAttributionError,
    UsageAttributionLedger,
    UsageSnapshotPreSendError,
    UsageSnapshotProducer,
)


AUTHORITY = "meter-psychlo-dedicated"
ACCOUNT = "account-psychlo"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
RESET = "2026-08-12T00:00:00+00:00"
INTERVAL_START = RESET
INTERVAL_END = "2026-08-13T00:00:00+00:00"


def _sealed(value: dict) -> dict:
    import base64
    body = {key: item for key, item in value.items() if key not in {"digest", "signature"}}
    signature = base64.b64encode(PRIVATE_KEY.sign(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())).decode()
    return {**body, "signature": signature, "digest": canonical_digest(body)}


def _observation(**changes: object) -> dict:
    value = {
        "observationId": "observation-20260812",
        "authorityId": AUTHORITY,
        "authorityBindingId": "binding-psychlo-codex",
        "authorityBindingDigest": "a" * 64,
        "measurementScope": "exclusive-metered-intervals",
        "accountId": ACCOUNT,
        "providerId": "codex",
        "limitId": "codex.weekly",
        "usageUnit": "quota_points",
        "providerResetAt": RESET,
        "intervalStart": INTERVAL_START,
        "intervalEnd": INTERVAL_END,
        "totalConsumed": 42,
        "weeklyQuota": 700,
        "weeklyRemainingCapacity": 658,
        "unusedPriorDayWeeklyCapacity": 58,
        "decisionVersion": "meter-v1",
        "correlationId": "meter-correlation-20260812",
        "idempotencyKey": "meter-observation-20260812",
        "occurredAt": INTERVAL_END,
    }
    return _sealed({**value, **changes})


def _receipt(**changes: object) -> dict:
    value = {
        "receiptId": "receipt-round-1",
        "observationId": "observation-20260812",
        "authorityId": AUTHORITY,
        "authorityBindingId": "binding-psychlo-codex",
        "authorityBindingDigest": "a" * 64,
        "measurementScope": "exclusive-metered-intervals",
        "accountId": ACCOUNT,
        "providerId": "codex",
        "limitId": "codex.weekly",
        "usageUnit": "quota_points",
        "providerResetAt": RESET,
        "projectId": "psychlo",
        "planId": "psychlo-v1-1",
        "planVersion": "v1.1",
        "aTeamId": "a-team-psychlo",
        "projectLeadId": "lead-psychlo",
        "roundId": "round-1",
        "dispatchId": "dispatch-1",
        "resultId": "result-1",
        "startedAt": "2026-08-12T01:00:00+00:00",
        "settledAt": "2026-08-12T02:00:00+00:00",
        "consumed": 12,
        "correlationId": "receipt-correlation-1",
        "idempotencyKey": "receipt-idempotency-1",
        "occurredAt": "2026-08-12T02:00:00+00:00",
    }
    return _sealed({**value, **changes})


def _ledger(path: Path) -> UsageAttributionLedger:
    def validate(value: dict) -> None:
        expected = {"projectId": "psychlo", "planId": "psychlo-v1-1", "planVersion": "v1.1", "aTeamId": "a-team-psychlo", "projectLeadId": "lead-psychlo"}
        if any(value.get(key) != item for key, item in expected.items()): raise UsageAttributionError("receipt does not bind to a managed project identity")
    return UsageAttributionLedger(path, approved_authority_id=AUTHORITY, approved_authority_binding_id="binding-psychlo-codex", approved_authority_binding_digest="a" * 64, approved_account_id=ACCOUNT, approved_authority_public_key=PUBLIC_KEY, receipt_identity_validator=validate)


def _delivery_response(payload: dict, **changes: object) -> dict:
    snapshot = payload["snapshot"]
    receipt = {
        "kind": "usage-snapshot",
        "messageId": payload["messageId"],
        "correlationId": payload["correlationId"],
        "idempotencyKey": payload["idempotencyKey"],
        "snapshotId": snapshot["id"],
        "snapshotDigest": snapshot["digest"],
        "envelopeDigest": payload["digest"],
        "persistenceId": "psychlo-persistence-1",
        "outcome": "inserted",
    }
    return {"receipt": {**receipt, **changes}}


def test_authoritative_observation_and_bound_receipts_produce_exact_psychlo_payload(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    ledger.record_execution_receipt(
        _receipt(
            receiptId="receipt-round-2",
            roundId="round-2",
            dispatchId="dispatch-2",
            resultId="result-2",
            startedAt="2026-08-12T03:00:00+00:00",
            settledAt="2026-08-12T04:00:00+00:00",
            consumed=8,
            correlationId="receipt-correlation-2",
            idempotencyKey="receipt-idempotency-2",
            occurredAt="2026-08-12T04:00:00+00:00",
        )
    )
    sent: list[tuple[str, str, dict]] = []

    def sender(kind: str, message_id: str, payload: dict) -> dict:
        assert kind == "usage-snapshot"
        assert ledger.delivery_intent(payload["idempotencyKey"]) is not None
        sent.append((kind, message_id, payload))
        return _delivery_response(payload)

    producer = UsageSnapshotProducer(ledger, sender=sender)
    result = producer.emit("observation-20260812", policy_version="2026-08-13")
    envelope = result["payload"]
    snapshot = envelope["snapshot"]
    assert set(snapshot) == {
        "schemaVersion", "id", "sourceId", "capturedAt", "policyVersion",
        "providerResetAt", "scopeDigest", "decisionVersion",
        "unusedPriorDayWeeklyCapacity", "weeklyQuota", "weeklyRemainingCapacity",
        "dailyConsumed", "otherDevelopmentConsumed", "digest",
    }
    assert snapshot["dailyConsumed"] == 20
    assert snapshot["otherDevelopmentConsumed"] == 22
    assert snapshot["dailyConsumed"] + snapshot["otherDevelopmentConsumed"] == snapshot["weeklyQuota"] - snapshot["weeklyRemainingCapacity"]
    assert snapshot["unusedPriorDayWeeklyCapacity"] == 58.0
    assert result["replay"] is False
    assert sent[0][0:2] == ("usage-snapshot", envelope["idempotencyKey"])
    assert parse_usage_snapshot_v11(envelope) == envelope
    assert envelope["snapshot"]["digest"] == canonical_digest({key: value for key, value in snapshot.items() if key != "digest"})


def test_global_percentages_tokens_defaults_and_unbound_receipts_fail_closed(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    with pytest.raises(UsageAttributionError, match="authority|measurement|absolute"):
        ledger.record_provider_observation(
            _observation(
                measurementScope="provider-global",
                totalConsumed=None,
                weeklyQuota=None,
                weeklyRemainingCapacity=None,
            )
        )
    with pytest.raises(UsageAttributionError, match="signature"):
        ledger.record_provider_observation({**_observation(), "signature": "AAAA"})
    ledger.record_provider_observation(_observation())
    with pytest.raises(UsageAttributionError, match="binding|identity"):
        ledger.record_execution_receipt(_receipt(projectId="other-project", authorityBindingDigest="b" * 64))
    with pytest.raises(UsageAttributionError, match="receipt|identity"):
        ledger.record_execution_receipt(_receipt(resultId=None))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("consumed", 60, "negative residual"),
        ("usageUnit", "tokens", "unit"),
        ("accountId", "account-other", "account"),
        ("providerResetAt", "2026-08-23T00:00:00+00:00", "reset"),
    ],
)
def test_receipts_reject_mismatched_scope_or_negative_residual(tmp_path: Path, field: str, value: object, message: str):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    with pytest.raises(UsageAttributionError, match=message):
        ledger.record_execution_receipt(_receipt(**{field: value}))


def test_overlapping_receipts_are_rejected_within_one_observation(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    with pytest.raises(UsageAttributionError, match="overlap"):
        ledger.record_execution_receipt(
            _receipt(
                receiptId="receipt-overlap",
                roundId="round-overlap",
                dispatchId="dispatch-overlap",
                resultId="result-overlap",
                startedAt="2026-08-12T01:30:00+00:00",
                settledAt="2026-08-12T02:30:00+00:00",
                occurredAt="2026-08-12T02:30:00+00:00",
                correlationId="receipt-correlation-overlap",
                idempotencyKey="receipt-idempotency-overlap",
            )
        )


def test_next_reset_receipts_are_scoped_to_their_exact_observation(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt(consumed=42))
    next_reset = "2026-08-13T00:00:00+00:00"
    ledger.record_provider_observation(_observation(observationId="observation-20260813", providerResetAt=next_reset, intervalStart=next_reset, intervalEnd="2026-08-14T00:00:00+00:00", occurredAt="2026-08-14T00:00:00+00:00", totalConsumed=5, weeklyRemainingCapacity=695, correlationId="meter-correlation-20260813", idempotencyKey="meter-observation-20260813"))
    ledger.record_execution_receipt(_receipt(receiptId="receipt-next", observationId="observation-20260813", providerResetAt=next_reset, roundId="round-2", dispatchId="dispatch-2", resultId="result-2", startedAt="2026-08-13T01:00:00+00:00", settledAt="2026-08-13T02:00:00+00:00", consumed=5, correlationId="receipt-next", idempotencyKey="receipt-next", occurredAt="2026-08-13T02:00:00+00:00"))
    assert len(ledger.receipts_for_observation(ledger.observation("observation-20260813"))) == 1


def test_snapshot_and_delivery_intent_are_immutable_and_replay_after_restart(tmp_path: Path):
    path = tmp_path / "usage-attribution.sqlite3"
    ledger = _ledger(path)
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    calls: list[tuple[str, str]] = []
    producer = UsageSnapshotProducer(ledger, sender=lambda kind, message_id, payload: calls.append((kind, message_id)) or _delivery_response(payload))
    first = producer.emit("observation-20260812", policy_version="2026-08-13")
    assert first["replay"] is False
    ledger.connection.close()
    restarted = _ledger(path)
    replay = UsageSnapshotProducer(restarted, sender=lambda *_: pytest.fail("delivered replay must not resend" )).emit("observation-20260812", policy_version="2026-08-13")
    assert replay["replay"] is True
    assert replay["payload"] == first["payload"]
    with pytest.raises(UsageAttributionError, match="immutable|conflict"):
        restarted.record_provider_observation(_observation(weeklyQuota=701, totalConsumed=43))
    assert calls == [("usage-snapshot", first["payload"]["idempotencyKey"])]


def test_delivery_failure_is_durable_and_retry_wins_exactly_once(tmp_path: Path):
    path = tmp_path / "usage-attribution.sqlite3"
    ledger = _ledger(path)
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    with pytest.raises(RuntimeError, match="send failed"):
        UsageSnapshotProducer(ledger, sender=lambda *_: (_ for _ in ()).throw(RuntimeError("send failed"))).emit("observation-20260812", policy_version="2026-08-13")
    pending = ledger.delivery_intent_for_observation("observation-20260812")
    assert pending is not None and pending["state"] == "uncertain"
    sent: list[tuple[str, str]] = []
    retry = UsageSnapshotProducer(ledger, sender=lambda kind, message_id, payload: sent.append((kind, message_id)) or _delivery_response(payload)).emit("observation-20260812", policy_version="2026-08-13")
    assert retry["replay"] is False
    assert sent == [("usage-snapshot", retry["payload"]["idempotencyKey"])]


def test_pre_send_failure_remains_pending_and_later_valid_receipt_delivers(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    with pytest.raises(RuntimeError, match="local setup"):
        UsageSnapshotProducer(
            ledger,
            sender=lambda *_: pytest.fail("external sender must not run"),
            before_send=lambda: (_ for _ in ()).throw(RuntimeError("local setup")),
        ).emit("observation-20260812", policy_version="2026-08-13")
    assert ledger.delivery_intent_for_observation("observation-20260812")["state"] == "pending"
    result = UsageSnapshotProducer(ledger, sender=lambda _kind, _message_id, payload: _delivery_response(payload)).emit("observation-20260812", policy_version="2026-08-13")
    assert result["receipt"]["outcome"] == "inserted"


def test_sender_pre_send_marker_is_retryable_but_ordinary_failure_is_uncertain(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    with pytest.raises(UsageSnapshotPreSendError):
        UsageSnapshotProducer(ledger, sender=lambda *_: (_ for _ in ()).throw(UsageSnapshotPreSendError("connect"))).emit("observation-20260812", policy_version="2026-08-13")
    assert ledger.delivery_intent_for_observation("observation-20260812")["state"] == "pending"


@pytest.mark.parametrize("response", [{"status_code": 202}, {"status_code": 409}, {"accepted": True}])
def test_non_receipts_are_uncertain_and_never_mark_delivered(tmp_path: Path, response: dict):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    with pytest.raises(UsageAttributionError):
        UsageSnapshotProducer(ledger, sender=lambda *_: response).emit("observation-20260812", policy_version="2026-08-13")
    intent = ledger.delivery_intent_for_observation("observation-20260812")
    assert intent["state"] == "uncertain" and intent["receipt"] is None


def test_mismatched_receipt_is_uncertain_and_exact_payload_is_retried(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    sent: list[dict] = []
    def mismatched(_kind: str, _message_id: str, payload: dict) -> dict:
        sent.append(payload)
        return _delivery_response(payload, envelopeDigest="f" * 64)
    with pytest.raises(UsageAttributionError, match="mismatch"):
        UsageSnapshotProducer(ledger, sender=mismatched).emit("observation-20260812", policy_version="2026-08-13")
    original = ledger.delivery_intent_for_observation("observation-20260812")["payload"]
    result = UsageSnapshotProducer(ledger, sender=lambda _kind, _message_id, payload: _delivery_response(payload, outcome="duplicate")).emit("observation-20260812", policy_version="2026-08-13")
    assert result["receipt"]["outcome"] == "duplicate"
    assert sent[0] == original


def test_duplicate_receipt_survives_restart_without_resend(tmp_path: Path):
    path = tmp_path / "usage-attribution.sqlite3"
    ledger = _ledger(path)
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    first = UsageSnapshotProducer(ledger, sender=lambda _kind, _message_id, payload: _delivery_response(payload, outcome="duplicate")).emit("observation-20260812", policy_version="2026-08-13")
    stored = ledger.delivery_intent_for_observation("observation-20260812")
    ledger.connection.close()
    restarted = _ledger(path)
    replay = UsageSnapshotProducer(restarted, sender=lambda *_: pytest.fail("duplicate delivery receipt must prevent resend")).emit("observation-20260812", policy_version="2026-08-13")
    assert replay["replay"] is True and replay["receipt"] == first["receipt"] == stored["receipt"]


def test_uncertain_delivery_has_one_bounded_exact_payload_retry(tmp_path: Path):
    ledger = _ledger(tmp_path / "usage-attribution.sqlite3")
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    with pytest.raises(RuntimeError):
        UsageSnapshotProducer(ledger, sender=lambda *_: (_ for _ in ()).throw(RuntimeError("ambiguous"))).emit("observation-20260812", policy_version="2026-08-13")
    with pytest.raises(RuntimeError):
        UsageSnapshotProducer(ledger, sender=lambda *_: (_ for _ in ()).throw(RuntimeError("ambiguous again"))).emit("observation-20260812", policy_version="2026-08-13")
    with pytest.raises(UsageAttributionError, match="retry limit"):
        UsageSnapshotProducer(ledger, sender=lambda *_: pytest.fail("retry budget must be exhausted")).emit("observation-20260812", policy_version="2026-08-13")
    with pytest.raises(UsageAttributionError, match="immutable"):
        UsageSnapshotProducer(ledger, sender=lambda *_: pytest.fail("replacement envelope must not be sent")).emit("observation-20260812", policy_version="different-policy")


def test_post_send_crash_recovers_exact_payload_and_corrupt_intent_fails_closed(tmp_path: Path):
    path = tmp_path / "usage-attribution.sqlite3"
    ledger = _ledger(path)
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    first: list[dict] = []
    with pytest.raises(SystemExit):
        UsageSnapshotProducer(ledger, sender=lambda kind, message_id, payload: first.append(payload) or _delivery_response(payload), after_send=lambda: (_ for _ in ()).throw(SystemExit(9))).emit("observation-20260812", policy_version="2026-08-13")
    assert ledger.delivery_intent_for_observation("observation-20260812")["state"] == "sending"
    ledger.connection.close()
    restarted = _ledger(path)
    second: list[dict] = []
    recovered = UsageSnapshotProducer(restarted, sender=lambda kind, message_id, payload: second.append(payload) or _delivery_response(payload)).emit("observation-20260812", policy_version="2026-08-13")
    assert recovered["replay"] is False and first == second
    restarted.connection.execute("UPDATE usage_snapshot_intents SET digest=?", ("0" * 64,))
    restarted.connection.close()
    with pytest.raises(UsageAttributionError, match="corrupt snapshot intent"):
        _ledger(path)


def test_corrupt_persisted_receipt_fails_closed_on_restart(tmp_path: Path):
    path = tmp_path / "usage-attribution.sqlite3"
    ledger = _ledger(path)
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    UsageSnapshotProducer(ledger, sender=lambda _kind, _message_id, payload: _delivery_response(payload)).emit("observation-20260812", policy_version="2026-08-13")
    ledger.connection.execute("UPDATE usage_snapshot_intents SET receipt_json=?", ('{"kind":"usage-snapshot"}',))
    ledger.connection.close()
    with pytest.raises(UsageAttributionError, match="corrupt snapshot intent receipt"):
        _ledger(path)


def _cross_process_emit(path: str, ready, result_queue) -> None:
    ledger = _ledger(Path(path))
    producer = UsageSnapshotProducer(ledger, sender=lambda _kind, _message_id, payload: _delivery_response(payload))
    ready.wait(10)
    try:
        result_queue.put(producer.emit("observation-20260812", policy_version="2026-08-13")["replay"])
    except Exception as error:  # pragma: no cover - assertion reports child failure
        result_queue.put(f"error:{error}")


def test_cross_process_delivery_intent_has_one_winner(tmp_path: Path):
    path = tmp_path / "usage-attribution.sqlite3"
    ledger = _ledger(path)
    ledger.record_provider_observation(_observation())
    ledger.record_execution_receipt(_receipt())
    ready = multiprocessing.Event()
    queue = multiprocessing.Queue()
    processes = [multiprocessing.Process(target=_cross_process_emit, args=(str(path), ready, queue)) for _ in range(2)]
    for process in processes:
        process.start()
    ready.set()
    results = [queue.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
    assert sorted(results) == [False, True]


def test_migration_rolls_back_and_corrupt_ledger_is_rejected(tmp_path: Path):
    path = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE usage_attribution_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO usage_attribution_meta VALUES ('schema_version', '1');
        CREATE TABLE usage_observations (observation_id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload_json TEXT NOT NULL, inserted_at TEXT NOT NULL);
        INSERT INTO usage_observations VALUES ('bad', 'not-a-digest', '{"observationId":"bad"}', '2026-08-12T00:00:00+00:00');
        """
    )
    connection.commit()
    connection.close()
    path.chmod(0o600)
    with pytest.raises(UsageAttributionError, match="migration|corrupt"):
        _ledger(path)
    connection = sqlite3.connect(path)
    assert connection.execute("SELECT value FROM usage_attribution_meta WHERE key='schema_version'").fetchone()[0] == "1"
    assert connection.execute("PRAGMA table_info(usage_observations)").fetchall()[-1][1] == "inserted_at"
    connection.close()


def test_ledger_rejects_symlink_and_group_accessible_state(tmp_path: Path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    target = private / "target.sqlite3"
    target.touch(mode=0o600)
    link = private / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(UsageAttributionError, match="private"):
        _ledger(link)
    target.chmod(0o640)
    with pytest.raises(UsageAttributionError, match="private"):
        _ledger(target)
    private.chmod(0o750)
    with pytest.raises(UsageAttributionError, match="directory"):
        _ledger(private / "new.sqlite3")
