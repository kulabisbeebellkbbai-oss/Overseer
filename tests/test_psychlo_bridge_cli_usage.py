from pathlib import Path
import base64
from types import SimpleNamespace

import pytest

import overseer.psychlo_bridge_cli as cli
from overseer.psychlo_bridge_cli import _closed_json, _usage_delivery_output, build_parser


def test_usage_authority_input_is_private_bounded_and_no_follow(tmp_path: Path):
    authority = tmp_path / "authority.json"
    authority.write_text('{"authorityId":"meter","authorityBindingId":"binding","authorityBindingDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","accountId":"account","publicKey":"key"}', encoding="utf-8")
    authority.chmod(0o600)
    value = _closed_json(authority, {"authorityId", "authorityBindingId", "authorityBindingDigest", "accountId", "publicKey"})
    assert value["authorityId"] == "meter"
    authority.chmod(0o640)
    with pytest.raises(ValueError, match="unsafe"):
        _closed_json(authority, None)
    authority.chmod(0o600)
    link = tmp_path / "authority-link.json"
    link.symlink_to(authority)
    with pytest.raises(OSError):
        _closed_json(link, None)


def test_usage_authority_input_rejects_extra_keys_and_oversize(tmp_path: Path):
    authority = tmp_path / "authority.json"
    authority.write_text('{"authorityId":"meter","extra":"no"}', encoding="utf-8")
    authority.chmod(0o600)
    with pytest.raises(ValueError, match="configuration"):
        _closed_json(authority, {"authorityId"})
    authority.write_bytes(b" " * (1024 * 1024 + 1))
    authority.chmod(0o600)
    with pytest.raises(ValueError, match="unsafe|large"):
        _closed_json(authority, None)


class _IntentLedger:
    def __init__(self, intent: dict):
        self.intent = intent

    def delivery_intent(self, key: str) -> dict | None:
        return self.intent if self.intent.get("payload", {}).get("idempotencyKey") == key else None


def _cli_payload_and_receipt(outcome: str = "inserted") -> tuple[dict, dict]:
    payload = {
        "messageId": "usage-attribution-snapshot",
        "correlationId": "psychlo:usage-attribution-snapshot",
        "idempotencyKey": "usage-attribution-snapshot",
        "digest": "b" * 64,
        "snapshot": {"id": "usage-attribution-snapshot", "digest": "a" * 64},
    }
    receipt = {
        "kind": "usage-snapshot",
        "messageId": payload["messageId"],
        "correlationId": payload["correlationId"],
        "idempotencyKey": payload["idempotencyKey"],
        "snapshotId": payload["snapshot"]["id"],
        "snapshotDigest": payload["snapshot"]["digest"],
        "envelopeDigest": payload["digest"],
        "persistenceId": "psychlo-persistence-1",
        "outcome": outcome,
    }
    return payload, receipt


@pytest.mark.parametrize("outcome", ["inserted", "duplicate"])
def test_cli_reports_only_persisted_delivery_as_success(outcome: str):
    payload, receipt = _cli_payload_and_receipt(outcome)
    ledger = _IntentLedger({"payload": payload, "state": "delivered", "receipt": receipt})
    output, exit_code = _usage_delivery_output(
        {"payload": payload, "state": "delivered", "delivered": True, "replay": outcome == "duplicate", "receipt": receipt},
        ledger,
    )
    assert exit_code == 0
    assert output == {"delivered": True, "state": "delivered", "replay": outcome == "duplicate", "receipt": receipt}


def test_cli_active_lease_is_in_progress_and_not_replay_success():
    payload, _ = _cli_payload_and_receipt()
    ledger = _IntentLedger({"payload": payload, "state": "sending", "receipt": None})
    output, exit_code = _usage_delivery_output(
        {"payload": payload, "state": "sending", "delivered": False, "replay": False, "receipt": None},
        ledger,
    )
    assert exit_code == 1
    assert output == {
        "delivered": False,
        "state": "sending",
        "replay": False,
        "idempotencyKey": payload["idempotencyKey"],
        "messageId": payload["messageId"],
    }


@pytest.mark.parametrize("value", ["0", "-1", "86401", "not-an-integer"])
def test_cli_rejects_out_of_bounds_delivery_lease_seconds(value: str):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["emit-usage", "--delivery-lease-seconds", value])


def test_cli_accepts_bounded_delivery_lease_seconds_and_preserves_default():
    parser = build_parser()
    assert parser.parse_args(["emit-usage"]).delivery_lease_seconds == 300
    assert parser.parse_args(["emit-usage", "--delivery-lease-seconds", "86400"]).delivery_lease_seconds == 86400


def test_cli_propagates_delivery_lease_to_usage_ledger(monkeypatch, tmp_path: Path, capsys):
    captured = {}

    class Ledger:
        def __init__(self, _path, **kwargs):
            captured.update(kwargs)

        def record_provider_observation(self, _observation):
            pass

        def record_execution_receipt(self, _receipt):
            pass

        def delivery_intent(self, _key):
            return None

    class Producer:
        def __init__(self, _ledger, *, sender):
            assert callable(sender)

        def emit(self, _observation_id, *, policy_version):
            assert policy_version == "policy-test"
            return {"payload": {"idempotencyKey": "snapshot-test"}, "state": "pending", "replay": False}

    authority = {
        "authorityId": "meter",
        "authorityBindingId": "binding",
        "authorityBindingDigest": "a" * 64,
        "accountId": "account",
        "publicKey": base64.b64encode(b"k" * 32).decode(),
    }
    observation = {"observationId": "observation-test"}
    monkeypatch.setattr(cli, "create_bridge_from_environment", lambda: SimpleNamespace(sender=lambda *_: {}, store=object()))
    monkeypatch.setattr(cli, "_closed_json", lambda path, keys: authority if keys is not None else ([] if Path(path).name == "receipts.json" else observation))
    monkeypatch.setattr(cli, "UsageAttributionLedger", Ledger)
    monkeypatch.setattr(cli, "UsageSnapshotProducer", Producer)

    exit_code = cli.main([
        "emit-usage",
        "--policy-version",
        "policy-test",
        "--delivery-lease-seconds",
        "17",
        "--attribution-ledger",
        str(tmp_path / "ledger.sqlite3"),
        "--authority-config",
        str(tmp_path / "authority.json"),
        "--observation-file",
        str(tmp_path / "observation.json"),
        "--receipt-file",
        str(tmp_path / "receipts.json"),
    ])
    assert exit_code == 1
    assert captured["lease_seconds"] == 17
    assert '"delivered": false' in capsys.readouterr().out
