"""Scheduled Psychlo bridge operations."""

from __future__ import annotations

import argparse
import json
import os
import base64
from pathlib import Path

from .psychlo_bridge import MAX_BODY_BYTES, _read_private_file, create_bridge_from_environment
from .usage_attribution import UsageAttributionLedger, UsageSnapshotProducer, managed_receipt_validator


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one bounded Psychlo bridge operation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    emit = subparsers.add_parser("emit-usage")
    emit.add_argument("--policy-version", default=os.environ.get("OVERSEER_PSYCHLO_POLICY_VERSION", "2026-08-09"))
    emit.add_argument("--attribution-ledger", default=os.environ.get("OVERSEER_PSYCHLO_USAGE_ATTRIBUTION_LEDGER"))
    emit.add_argument("--authority-config", default=os.environ.get("OVERSEER_PSYCHLO_USAGE_AUTHORITY_FILE"))
    emit.add_argument("--observation-file", default=os.environ.get("OVERSEER_PSYCHLO_USAGE_OBSERVATION_FILE"))
    emit.add_argument("--receipt-file", default=os.environ.get("OVERSEER_PSYCHLO_USAGE_RECEIPTS_FILE"))
    sync = subparsers.add_parser("sync-projects")
    sync.add_argument("--handoff-file", default=os.environ.get("OVERSEER_A_TEAM_HANDOFF_FILE", "/home/god/Documents/Codex Workspace/The A-Team/data/handoffs.json"))
    subparsers.add_parser("tick")
    args = parser.parse_args(argv)
    if args.command == "emit-usage":
        bridge = create_bridge_from_environment()
        if not all((args.attribution_ledger, args.authority_config, args.observation_file, args.receipt_file)):
            raise ValueError("strict usage attribution configuration is required")
        authority = _closed_json(Path(args.authority_config), {"authorityId", "authorityBindingId", "authorityBindingDigest", "accountId", "publicKey"})
        observation = _closed_json(Path(args.observation_file), None)
        receipts = _closed_json(Path(args.receipt_file), None)
        if not isinstance(receipts, list): raise ValueError("usage receipt input must be an array")
        ledger = UsageAttributionLedger(args.attribution_ledger, approved_authority_id=authority["authorityId"], approved_authority_binding_id=authority["authorityBindingId"], approved_authority_binding_digest=authority["authorityBindingDigest"], approved_account_id=authority["accountId"], approved_authority_public_key=base64.b64decode(authority["publicKey"], validate=True), receipt_identity_validator=managed_receipt_validator(bridge.store))
        ledger.record_provider_observation(observation)
        for receipt in receipts:
            if not isinstance(receipt, dict): raise ValueError("usage receipt input is invalid")
            ledger.record_execution_receipt(receipt)
        result = UsageSnapshotProducer(ledger, sender=bridge.sender).emit(str(observation["observationId"]), policy_version=args.policy_version)
        print(json.dumps({"delivered": True, "replay": result["replay"], "receipt": result.get("receipt")}, sort_keys=True))
        return 0
    if args.command == "sync-projects":
        bridge = create_bridge_from_environment()
        with open(args.handoff_file, encoding="utf-8") as handle:
            payload = json.load(handle)
        records = payload.get("records", []) if isinstance(payload, dict) else []
        synchronized = 0
        for record in records:
            if not isinstance(record, dict) or record.get("state") != "delivered" or not isinstance(record.get("receipt"), dict):
                continue
            bridge.register_project({"envelope": record.get("envelope"), "receipt": record["receipt"]})
            synchronized += 1
        print(json.dumps({"accepted": True, "synchronized": synchronized}, sort_keys=True))
        return 0
    if args.command == "tick":
        bridge = create_bridge_from_environment()
        print(json.dumps(bridge.tick(), sort_keys=True))
        return 0
    return 2


def _closed_json(path: Path, keys: set[str] | None) -> object:
    value = json.loads(_read_private_file(path, maximum_bytes=MAX_BODY_BYTES))
    if keys is not None and (not isinstance(value, dict) or set(value) != keys or any(not isinstance(value[key], str) for key in keys)):
        raise ValueError("usage authority configuration is invalid")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
