from __future__ import annotations
import argparse,json
from .storage_control import create_execution_request,stage_authorization,list_authorizations,materialize_authorization,revoke_authorization
def main(argv=None):
    p=argparse.ArgumentParser(prog="overseer-storage-control"); p.add_argument("--store",required=True); sub=p.add_subparsers(dest="command",required=True)
    stage=sub.add_parser("stage"); stage.add_argument("--kind",choices=("root","operation"),required=True); stage.add_argument("--payload-json",required=True); stage.add_argument("--crew-evidence-id",required=True); stage.add_argument("--crew-owner",choices=("kira","obrien"),required=True)
    sub.add_parser("list").add_argument("--kind",choices=("root","operation"))
    materialize=sub.add_parser("materialize"); materialize.add_argument("--authorization-ref",required=True)
    approve=sub.add_parser("approve"); approve.add_argument("--authorization-ref",required=True); approve.add_argument("--approved-by",required=True)
    revoke=sub.add_parser("revoke"); revoke.add_argument("--authorization-ref",required=True); revoke.add_argument("--revoked-by",required=True); revoke.add_argument("--evidence-id",required=True)
    create=sub.add_parser("request-create"); create.add_argument("--payload-json",required=True)
    a=p.parse_args(argv)
    if a.command=="stage": result=stage_authorization(a.store,a.kind,json.loads(a.payload_json),a.crew_evidence_id,a.crew_owner)
    elif a.command=="list": result=list_authorizations(a.store,a.kind)
    elif a.command=="materialize": result=materialize_authorization(a.store,a.authorization_ref)
    elif a.command=="approve":
        from .storage_control import approve_authorization
        result=approve_authorization(a.store,a.authorization_ref,a.approved_by)
    elif a.command=="revoke": result=revoke_authorization(a.store,a.authorization_ref,a.revoked_by,a.evidence_id)
    else: result=create_execution_request(a.store,json.loads(a.payload_json))
    print(json.dumps(result,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
