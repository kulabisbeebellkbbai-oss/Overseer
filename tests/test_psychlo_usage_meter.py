from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from overseer.psychlo_contracts import ContractError, canonical_digest, parse_usage_snapshot_v12
from overseer.psychlo_usage_meter import (
    MeterAuthority,
    ProviderPercentageMeter,
    ProviderPercentageMeterConfig,
    atomic_publish_observation,
    derive_provider_window,
)
from overseer.psychlo_usage_meter_cli import main as meter_main
from overseer.usage_attribution import UsageAttributionLedger, UsageAttributionError, UsageSnapshotProducer


PRIVATE = Ed25519PrivateKey.generate()
PUBLIC = PRIVATE.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
AUTHORITY = MeterAuthority(
    authority_id="meter-psychlo-dedicated",
    authority_binding_id="binding-psychlo-codex",
    authority_binding_digest="a" * 64,
    account_id="account-psychlo",
    public_key=PUBLIC,
)
CONFIG = ProviderPercentageMeterConfig(
    provider_id="codex",
    limit_id="codex",
    window_name="primary",
    decision_version="provider-percentage-v1",
)
RAW = {
    "rateLimitsByLimitId": {
        "codex": {
            "limitId": "codex",
            "primary": {"usedPercent": 37, "windowDurationMins": 60, "resetsAt": 1786000000},
            "secondary": {"usedPercent": 2, "windowDurationMins": 10080, "resetsAt": 1786600000},
        },
    },
}


def _private_pem() -> bytes:
    return PRIVATE.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _ledger(path: Path) -> UsageAttributionLedger:
    return UsageAttributionLedger(
        path,
        approved_authority_id=AUTHORITY.authority_id,
        approved_authority_binding_id=AUTHORITY.authority_binding_id,
        approved_authority_binding_digest=AUTHORITY.authority_binding_digest,
        approved_account_id=AUTHORITY.account_id,
        approved_authority_public_key=AUTHORITY.public_key,
        receipt_identity_validator=lambda _: None,
    )


def test_exact_provider_limit_and_window_selection_and_integral_percentages():
    meter = ProviderPercentageMeter(AUTHORITY, CONFIG, PRIVATE)
    observation = meter.observe(RAW, observed_at="2026-08-06T06:30:00+00:00")
    assert observation["usageUnit"] == "provider-percentage-points"
    assert observation["totalConsumed"] == 37
    assert observation["weeklyQuota"] == 100
    assert observation["weeklyRemainingCapacity"] == 63
    assert observation["unusedPriorDayWeeklyCapacity"] == 0
    assert observation["providerResetAt"] == "2026-08-06T06:06:40+00:00"
    assert observation["intervalStart"] == observation["providerResetAt"]
    assert observation["intervalEnd"] == observation["occurredAt"]
    assert isinstance(observation["signature"], str)
    assert canonical_digest({key: value for key, value in observation.items() if key not in {"digest", "signature"}}) == observation["digest"]


def test_window_start_is_next_reset_minus_exact_duration():
    assert derive_provider_window("2026-08-15T12:00:00+00:00", 60) == (
        "2026-08-15T11:00:00+00:00", "2026-08-15T12:00:00+00:00"
    )
    with pytest.raises(ValueError, match="duration"):
        derive_provider_window("2026-08-15T12:00:00+00:00", 0)


def test_meter_rejects_non_integral_or_out_of_range_percentages():
    meter = ProviderPercentageMeter(AUTHORITY, CONFIG, PRIVATE)
    with pytest.raises(ValueError, match="integral"):
        meter.observe({"rateLimitsByLimitId": {"codex": {"primary": {"usedPercent": 37.5, "windowDurationMins": 60, "resetsAt": 1786000000}}}}, observed_at="2026-08-15T12:00:00+00:00")
    with pytest.raises(ValueError, match="0..100"):
        meter.observe({"rateLimitsByLimitId": {"codex": {"primary": {"usedPercent": 101, "windowDurationMins": 60, "resetsAt": 1786000000}}}}, observed_at="2026-08-15T12:00:00+00:00")


def test_meter_rejects_inconsistent_limit_identity_and_outside_window_time():
    meter = ProviderPercentageMeter(AUTHORITY, CONFIG, PRIVATE)
    with pytest.raises(ValueError, match="identity is inconsistent"):
        meter.observe({"rateLimitsByLimitId": {"codex": {"limitId": "other", "primary": {"usedPercent": 37, "windowDurationMins": 60, "resetsAt": 1786000000}}}}, observed_at="2026-08-06T06:30:00+00:00")
    with pytest.raises(ValueError, match="inside the current provider window"):
        meter.observe(RAW, observed_at="2026-08-06T05:30:00+00:00")


def test_private_key_must_match_authority_public_key():
    with pytest.raises(ValueError, match="public key"):
        ProviderPercentageMeter(AUTHORITY.__class__(**{**AUTHORITY.__dict__, "public_key": os.urandom(32)}), CONFIG, PRIVATE)


def test_atomic_publication_rejects_symlink_and_keeps_owner_only(tmp_path: Path):
    target = tmp_path / "latest-observation.json"
    target.write_text("old", encoding="utf-8")
    target.chmod(0o600)
    observation = ProviderPercentageMeter(AUTHORITY, CONFIG, PRIVATE).observe(RAW, observed_at="2026-08-06T06:30:00+00:00")
    published = atomic_publish_observation(target, observation)
    assert published == target
    assert json.loads(target.read_text(encoding="utf-8"))["usageUnit"] == "provider-percentage-points"
    assert target.stat().st_mode & 0o077 == 0
    target.unlink()
    target.symlink_to(tmp_path / "other")
    with pytest.raises(ValueError, match="symlink"):
        atomic_publish_observation(target, observation)


def test_atomic_publication_requires_an_existing_private_directory(tmp_path: Path):
    observation = ProviderPercentageMeter(AUTHORITY, CONFIG, PRIVATE).observe(RAW, observed_at="2026-08-06T06:30:00+00:00")
    with pytest.raises(ValueError, match="already exist"):
        atomic_publish_observation(tmp_path / "missing" / "latest-observation.json", observation)


def test_atomic_publication_rejects_a_symlinked_parent(tmp_path: Path):
    observation = ProviderPercentageMeter(AUTHORITY, CONFIG, PRIVATE).observe(RAW, observed_at="2026-08-06T06:30:00+00:00")
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="must not be a symlink"):
        atomic_publish_observation(linked / "latest-observation.json", observation)


class _RateLimitClient:
    def read_rate_limits(self):
        return RAW


def test_cli_reads_private_inputs_and_publishes_without_exposing_the_key(tmp_path: Path, capsys):
    authority_path = tmp_path / "authority.json"
    config_path = tmp_path / "meter.json"
    key_path = tmp_path / "authority.pem"
    output_path = tmp_path / "latest-observation.json"
    authority_path.write_text(json.dumps({
        "authorityId": AUTHORITY.authority_id,
        "authorityBindingId": AUTHORITY.authority_binding_id,
        "authorityBindingDigest": AUTHORITY.authority_binding_digest,
        "accountId": AUTHORITY.account_id,
        "publicKey": base64.b64encode(AUTHORITY.public_key).decode("ascii"),
    }), encoding="utf-8")
    config_path.write_text(json.dumps({
        "providerId": CONFIG.provider_id,
        "limitId": CONFIG.limit_id,
        "windowName": CONFIG.window_name,
        "decisionVersion": CONFIG.decision_version,
    }), encoding="utf-8")
    key_path.write_bytes(_private_pem())
    for path in (authority_path, config_path, key_path):
        path.chmod(0o600)

    assert meter_main([
        "--authority", str(authority_path), "--meter-config", str(config_path),
        "--private-key", str(key_path), "--output", str(output_path),
    ], client=_RateLimitClient(), clock=lambda: "2026-08-06T06:30:00+00:00") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["published"] is True
    assert "signature" not in result
    assert output_path.stat().st_mode & 0o077 == 0


def test_cli_rejects_symlinked_private_key(tmp_path: Path, capsys):
    real_key = tmp_path / "real.pem"
    real_key.write_bytes(_private_pem())
    real_key.chmod(0o600)
    linked_key = tmp_path / "linked.pem"
    linked_key.symlink_to(real_key)
    authority_path = tmp_path / "authority.json"
    config_path = tmp_path / "meter.json"
    authority_path.write_text(json.dumps({"authorityId": AUTHORITY.authority_id, "authorityBindingId": AUTHORITY.authority_binding_id, "authorityBindingDigest": AUTHORITY.authority_binding_digest, "accountId": AUTHORITY.account_id, "publicKey": base64.b64encode(AUTHORITY.public_key).decode("ascii")}), encoding="utf-8")
    config_path.write_text(json.dumps({"providerId": CONFIG.provider_id, "limitId": CONFIG.limit_id, "windowName": CONFIG.window_name, "decisionVersion": CONFIG.decision_version}), encoding="utf-8")
    authority_path.chmod(0o600); config_path.chmod(0o600)
    assert meter_main(["--authority", str(authority_path), "--meter-config", str(config_path), "--private-key", str(linked_key), "--output", str(tmp_path / "latest-observation.json")], client=_RateLimitClient()) == 1
    assert "not a symlink" in capsys.readouterr().err


def test_v12_snapshot_is_emitted_from_attribution_ledger_without_provider_conversion(tmp_path: Path):
    observation = ProviderPercentageMeter(AUTHORITY, CONFIG, PRIVATE).observe(RAW, observed_at="2026-08-06T06:30:00+00:00")
    ledger = _ledger(tmp_path / "ledger.sqlite3")
    ledger.record_provider_observation(observation)
    result = UsageSnapshotProducer(ledger, sender=lambda _kind, _id, payload: {"receipt": {
        "kind": "usage-snapshot", "messageId": payload["messageId"], "correlationId": payload["correlationId"],
        "idempotencyKey": payload["idempotencyKey"], "snapshotId": payload["snapshot"]["id"],
        "snapshotDigest": payload["snapshot"]["digest"], "envelopeDigest": payload["digest"],
        "persistenceId": "persist-1", "outcome": "inserted",
    }}).emit(observation["observationId"], policy_version="provider-percentage-v1")
    snapshot = result["payload"]["snapshot"]
    assert result["delivered"] is True
    assert snapshot["schemaVersion"] == "psychlo.usage-snapshot.v1.2"
    assert snapshot["weeklyQuota"] == 100
    assert snapshot["weeklyRemainingCapacity"] == 63
    assert snapshot["otherDevelopmentConsumed"] == 37
    assert snapshot["accounting"]["unit"] == "provider-percentage-points"
    parse_usage_snapshot_v12(result["payload"])
