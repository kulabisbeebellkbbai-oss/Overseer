# Admin Change Plans

Admin change plans are Overseer's bridge from observed host evidence to real IT actions. A plan is not execution. It is the approval artifact that must exist before package installs, service restarts, firewall changes, network exposure, or active blocking actions.

## Included Fields

- Current state.
- Proposed new state.
- Exact command steps.
- Reason for each step.
- Risks and expected impact.
- Rollback commands.
- Verification commands.
- Required approval level.

## Supported Plan Types

- `user_service_restart`
- `apt_install`
- `firewall_allow_tcp`
- `block_ip`

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --kind user_service_restart --target overseer-api.service --reason "reload approved code" --current-state active
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.install.nmap --kind apt_install --target nmap --reason "enable approved local audit"
PYTHONPATH=src python3 -m overseer.cli plan-admin-change --store state/overseer.sqlite3 --plan-id admin.firewall.8443 --kind firewall_allow_tcp --target tcp/8443 --port 8443 --reason "publish approved local service"
PYTHONPATH=src python3 -m overseer.cli authorizations-required --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli approve-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api --approved-by sisko
PYTHONPATH=src python3 -m overseer.cli cancel-admin-change --store state/overseer.sqlite3 --plan-id admin.block.example --canceled-by odo --reason "reserved documentation address; no observed hostile traffic"
PYTHONPATH=src python3 -m overseer.cli execute-admin-change --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api
PYTHONPATH=src python3 -m overseer.cli admin-executions --store state/overseer.sqlite3
```

## Boundary

The planner never runs live commands. It produces the exact change list required by the approval gate. A future live adapter must verify `approved=true`, execute only the approved steps, record evidence, and preserve rollback status.

Recording approval does not execute the plan. It only updates the stored approval metadata so a future execution adapter can see that a specific command list was approved.

Canceling a plan keeps the record visible but removes it from the pending authorization queue and prevents execution. Use cancellation for placeholders, superseded plans, or plans created from disproven evidence.

Live execution is currently limited to approved `user_service_restart` plans. Package installs, firewall rules, IP blocks, network exposure, and privilege changes remain blocked even if a plan is approved.

Execution results are persisted and can be reviewed with `admin-executions` or the loopback API. Blocked execution attempts are also persisted so O'Brien and Sisko can see why a plan did not run.

Every execution attempt also writes an audit event keyed to the admin plan. Completed executions use `executed`; blocked or failed attempts use `blocked` and cite the execution result id as evidence.
