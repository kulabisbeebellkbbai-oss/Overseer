# Local API

The Overseer API is a loopback-only HTTP surface for local Codex threads and tools that should not shell out to the CLI for every operation.

## Boundary

- The API may bind only to `127.0.0.1` or `localhost`.
- No firewall rule is created.
- No external address is exposed.
- It uses the same explicit SQLite store path as the CLI and user service.

## Run

```bash
PYTHONPATH=src python3 -m overseer.cli serve-api --store state/overseer.sqlite3 --host 127.0.0.1 --port 8766 --auth-token-file state/api-token
```

`GET /health` is always available for local service monitoring. All other endpoints require `Authorization: Bearer <token>` when `--auth-token-file` is configured.

## Read Endpoints

- `GET /health`
- `GET /service-status`
- `GET /runtime-status`
- `GET /command-summary`
- `GET /operator-dashboard`
- `GET /maintenance-summary`
- `GET /alerts-summary`
- `GET /security-summary`
- `GET /usage-summary`
- `GET /physical-summary`
- `GET /virtual-summary`
- `GET /health-summary`
- `GET /health-efficiency`
- `GET /host/security`
- `GET /admin/authorizations-required`
- `GET /admin/executions`
- `GET /admin/summary`
- `GET /state`

## Claim Endpoints

- `POST /claims/request`
- `POST /claims/approve`
- `POST /claims/activate`
- `POST /claims/release`
- `POST /host/inspect`
- `POST /admin/plans`
- `POST /admin/approve`
- `POST /admin/cancel`
- `POST /admin/execute`

All request bodies are JSON objects. Claim operations use the same field names as the CLI options, with underscores instead of hyphens.

`POST /host/inspect` captures read-only host evidence and persists it to the API store.
`POST /admin/plans` creates and persists an approval-gated admin change plan without executing it.
`POST /admin/approve` records approval metadata for a stored plan without executing it.
`POST /admin/cancel` marks a stored plan canceled without deleting history or executing it.
`POST /admin/execute` executes only a stored plan that passes the existing approval and completeness gates, then persists the result. Current live execution support is limited to approved user-service restart plans; unsupported or unapproved plans return persisted `blocked` results.
`GET /admin/executions` lists persisted admin execution results, including blocked and failed attempts.
`GET /admin/summary` returns a compact operator view of admin plans, pending authorizations, execution outcomes, and recent admin audit events.

`GET /command-summary` returns Sisko's compact cross-domain view of service freshness, resources, claims, health targets, usage limits, physical assets, virtual assets, admin plans, and alerts without persisting new records.
`GET /operator-dashboard` returns a unified role-focused dashboard with overall status, attention counts, and embedded command, physical, virtual, maintenance, security, usage, health, and health-efficiency summaries.
`GET /maintenance-summary` returns O'Brien's compact view of maintenance targets, install/restart plans, pending approvals, rollback and verification readiness, and execution results.
`GET /runtime-status` returns service heartbeat freshness and host inspection freshness in a compact monitoring payload. Freshness states are `ok`, `warning`, `high`, or `missing`. Non-OK freshness states persist stable `alert` audit events in the same store.
`GET /alerts-summary` returns only persisted `alert` audit events, with counts by risk and owner domain for quick Odo/Julian review.
`GET /security-summary` returns Odo's compact view of security surfaces, alert audit events, latest host security findings, and protective firewall/block plans.
`GET /usage-summary` returns persisted usage-limit counts, available or exhausted capacity, unknown reset counts, low-confidence counts, next reset time, and per-limit detail for Quark review.
`GET /physical-summary` returns persisted physical identity counts, checkout readiness, power risk, storage risk, and per-asset detail for Kira review.
`GET /virtual-summary` returns persisted virtual asset counts, checkout readiness, active claims, queued claims, reserved ports, and per-asset detail for Dax review.
`GET /health-efficiency` returns Julian's compact service-health view of target status counts, probe-type coverage, owner routing, recovery requirements, and latest failures.

## Python Client

Local Python tools can use `overseer.client.OverseerApiClient` to read the token file and call the API:

```python
from overseer.client import OverseerApiClient

client = OverseerApiClient(auth_token_file="state/api-token")
runtime = client.runtime_status()
command = client.command_summary()
dashboard = client.operator_dashboard()
maintenance = client.maintenance_summary()
alerts = client.alerts_summary()
security = client.security_summary()
usage = client.usage_summary()
physical = client.physical_summary()
virtual = client.virtual_summary()
efficiency = client.health_efficiency()
summary = client.health_summary()
snapshot = client.inspect_host()
plan = client.plan_admin_change(
    {
        "plan_id": "admin.restart.overseer-api",
        "kind": "user_service_restart",
        "target": "overseer-api.service",
        "reason": "reload approved code",
    }
)
pending = client.authorizations_required()
approved = client.approve_admin_change({"plan_id": "admin.restart.overseer-api", "approved_by": "sisko"})
execution = client.execute_admin_change({"plan_id": "admin.restart.overseer-api"})
executions = client.admin_executions()
admin = client.admin_summary()
canceled = client.cancel_admin_change(
    {
        "plan_id": "admin.block.example",
        "canceled_by": "odo",
        "cancellation_reason": "reserved documentation address; no observed hostile traffic",
    }
)
```

## Installed User Service

The approved local service is installed as:

```text
/home/god/.config/systemd/user/overseer-api.service
```

The installed service reads its bearer token from an ignored local file:

```text
/home/god/.local/share/overseer/project/state/api-token
```

Rollback:

```bash
systemctl --user disable --now overseer-api.service
```
