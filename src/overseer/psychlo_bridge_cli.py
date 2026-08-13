"""Scheduled Psychlo bridge operations."""

from __future__ import annotations

import argparse
import json
import os
import base64
from pathlib import Path

from .psychlo_bridge import MAX_BODY_BYTES, _read_private_file, create_bridge_from_environment
from .usage_attribution import UsageAttributionLedger, UsageSnapshotProducer, _validate_usage_snapshot_receipt, managed_receipt_validator


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
        output, exit_code = _usage_delivery_output(result, ledger)
        print(json.dumps(output, sort_keys=True))
        return exit_code
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


def _usage_delivery_output(result: object, ledger: UsageAttributionLedger) -> tuple[dict[str, object], int]:
    """Render only a durably persisted delivery as CLI success."""
    if isinstance(result, dict):
        payload = result.get("payload")
        receipt = result.get("receipt")
        state = result.get("state")
    else:
        payload = receipt = state = None
    persisted = None
    if isinstance(payload, dict) and isinstance(payload.get("idempotencyKey"), str):
        persisted = ledger.delivery_intent(payload["idempotencyKey"])
    if state == "delivered" and isinstance(payload, dict) and isinstance(receipt, dict) and persisted is not None:
        try:
            validated = _validate_usage_snapshot_receipt(receipt, payload)
        except Exception:
            validated = None
        persisted_receipt = persisted.get("receipt") if isinstance(persisted, dict) else None
        if (
            persisted.get("state") == "delivered"
            and isinstance(validated, dict)
            and isinstance(persisted_receipt, dict)
            and persisted_receipt == validated
            and validated.get("outcome") in {"inserted", "duplicate"}
        ):
            return {
                "delivered": True,
                "state": "delivered",
                "replay": bool(result.get("replay")),
                "receipt": persisted_receipt,
            }, 0
    safe_state = state if state in {"pending", "sending", "uncertain", "rejected"} else "not-delivered"
    safe: dict[str, object] = {"delivered": False, "state": safe_state, "replay": False}
    if isinstance(payload, dict):
        for field in ("idempotencyKey", "messageId"):
            value = payload.get(field)
            if isinstance(value, str) and 0 < len(value) <= 200:
                safe[field] = value
    return safe, 1


if __name__ == "__main__":
    raise SystemExit(main())
