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
```

## Boundary

The planner never runs live commands. It produces the exact change list required by the approval gate. A future live adapter must verify `approved=true`, execute only the approved steps, record evidence, and preserve rollback status.

Recording approval does not execute the plan. It only updates the stored approval metadata so a future execution adapter can see that a specific command list was approved.
