"""Operator CLI for the dedicated backup-provisioning control plane."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .backup_provisioning import approve_plan_api, execute_plan_api, list_plans, stage_plan_api
from .backup_host_operations import ConcreteHostProvisioningAdapter
from .provisioning_bundle import bundle_status, preflight_bundle_api, stage_bundle_api


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="overseer-backup-provisioning")
    parser.add_argument("--store", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage")
    stage.add_argument("--plan-json", required=True)
    commands.add_parser("list")
    approve = commands.add_parser("approve")
    approve.add_argument("--plan-id", required=True)
    approve.add_argument("--approved-by", required=True)
    execute = commands.add_parser("execute")
    execute.add_argument("--plan-id", required=True)
    execute.add_argument("--privileged-confirmation", required=True)
    bundle_preflight = commands.add_parser("bundle-preflight")
    bundle_preflight.add_argument("--intent-json", required=True)
    bundle_stage = commands.add_parser("bundle-stage")
    bundle_stage.add_argument("--intent-json", required=True)
    bundle_stage.add_argument("--expected-preflight-digest", required=True)
    bundle_stage.add_argument("--expected-bundle-digest", required=True)
    bundle_status_parser = commands.add_parser("bundle-status")
    bundle_status_parser.add_argument("--plan-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "stage":
        result = stage_plan_api(args.store, json.loads(Path(args.plan_json).read_text()))
    elif args.command == "list":
        result = list_plans(args.store)
    elif args.command == "approve":
        result = approve_plan_api(
            args.store,
            {"plan_id": args.plan_id, "approved_by": args.approved_by},
        )
    elif args.command == "execute":
        confirmation = args.privileged_confirmation
        result = execute_plan_api(
            args.store,
            {"plan_id": args.plan_id, "privileged_confirmation": confirmation},
            adapter_factory=lambda plan: ConcreteHostProvisioningAdapter(
                plan, privileged_confirmation=confirmation,
            ),
        )
    elif args.command == "bundle-preflight":
        result = preflight_bundle_api(
            args.store,
            {"intent": json.loads(Path(args.intent_json).read_text())},
        )
    elif args.command == "bundle-stage":
        result = stage_bundle_api(
            args.store,
            {
                "intent": json.loads(Path(args.intent_json).read_text()),
                "expected_preflight_digest": args.expected_preflight_digest,
                "expected_bundle_digest": args.expected_bundle_digest,
            },
        )
    else:
        result = bundle_status(args.store, args.plan_id)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
