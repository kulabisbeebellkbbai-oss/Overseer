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
PYTHONPATH=src python3 -m overseer.cli admin-summary --store state/overseer.sqlite3
```

## Boundary

The planner never runs live commands. It produces the exact change list required by the approval gate. A future live adapter must verify `approved=true`, execute only the approved steps, record evidence, and preserve rollback status.

Recording approval does not execute the plan. It only updates the stored approval metadata so a future execution adapter can see that a specific command list was approved.

Live admin execution is now described by an explicit adapter capability table. Approved user-service restart plans are enabled by default. Package install, firewall allow/deny, and source-block adapters remain disabled unless the same store contains an approved adapter enablement request for that exact kind. The readiness view reports each plan's `adapter_status` so disabled live actions cannot be confused with ready Overseer execution. Use `admin-adapter-enablement-plan` or `GET /admin/adapter-enablement-plan` to generate the required read-only approval plan before any disabled adapter is enabled.

Adapter enablement requests persist the human approval record for that work. Approval changes only the effective adapter capability for that store and kind; it does not approve any specific host change, modify the host, or run commands. Each admin plan must still pass its own approval, IDS review when applicable, command-boundary validation, execution recording, and verification.

Canceling a plan keeps the record visible but removes it from the pending authorization queue and prevents execution. Use cancellation for placeholders, superseded plans, or plans created from disproven evidence.

Live execution is currently limited to approved `user_service_restart` plans. Package installs, firewall rules, IP blocks, network exposure, and privilege changes remain blocked even if a plan is approved.

Execution results are persisted and can be reviewed with `admin-executions` or the loopback API. Blocked execution attempts are also persisted so O'Brien and Sisko can see why a plan did not run.

Every execution attempt also writes an audit event keyed to the admin plan. Completed executions use `executed`; blocked or failed attempts use `blocked` and cite the execution result id as evidence.

`admin-summary` is the compact operator view for O'Brien and Sisko. It reports plan counts, pending authorizations, executable plans, execution counts by status, pending plan details, and recent admin audit events.

For firewall-affecting plans, `authorizations-required` and `admin-summary` also report the IDS/firewall review gate. The queue distinguishes missing packages, prepared packages that need prompt export, exported prompts that need submission, submitted packages waiting for advisory results, revision-required packages, and accepted advisory results that are ready for human approval.

IDS/firewall review package lifecycle changes also write audit events keyed to the package id. Preparing and submitting a package use `requested`, prompt export uses `verified`, accepted results use `approved`, and revision-required results use `rejected`.
