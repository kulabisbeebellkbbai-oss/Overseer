"""Operator CLI for the dedicated backup-provisioning control plane."""
from __future__ import annotations
import argparse,json
from pathlib import Path
from .backup_provisioning import approve_plan_api,execute_plan_api,list_plans,stage_plan_api
from .backup_host_operations import ConcreteHostProvisioningAdapter

def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(prog="overseer-backup-provisioning"); parser.add_argument("--store",required=True)
    commands=parser.add_subparsers(dest="command",required=True)
    stage=commands.add_parser("stage"); stage.add_argument("--plan-json",required=True)
    commands.add_parser("list")
    approve=commands.add_parser("approve"); approve.add_argument("--plan-id",required=True); approve.add_argument("--approved-by",required=True)
    execute=commands.add_parser("execute"); execute.add_argument("--plan-id",required=True); execute.add_argument("--privileged-confirmation",required=True)
    args=parser.parse_args(argv)
    if args.command=="stage": result=stage_plan_api(args.store,json.loads(Path(args.plan_json).read_text()))
    elif args.command=="list": result=list_plans(args.store)
    elif args.command=="approve": result=approve_plan_api(args.store,{"plan_id":args.plan_id,"approved_by":args.approved_by})
    else:
        confirmation=args.privileged_confirmation
        result=execute_plan_api(args.store,{"plan_id":args.plan_id,"privileged_confirmation":confirmation},adapter_factory=lambda plan:ConcreteHostProvisioningAdapter(plan,privileged_confirmation=confirmation))
    print(json.dumps(result,sort_keys=True)); return 0

if __name__=="__main__": raise SystemExit(main())
