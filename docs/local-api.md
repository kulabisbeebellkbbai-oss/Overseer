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
- `GET /health-summary`
- `GET /state`

## Claim Endpoints

- `POST /claims/request`
- `POST /claims/approve`
- `POST /claims/activate`
- `POST /claims/release`
- `POST /host/inspect`
- `POST /admin/plans`

All request bodies are JSON objects. Claim operations use the same field names as the CLI options, with underscores instead of hyphens.

`POST /host/inspect` captures read-only host evidence and persists it to the API store.
`POST /admin/plans` creates and persists an approval-gated admin change plan without executing it.

## Python Client

Local Python tools can use `overseer.client.OverseerApiClient` to read the token file and call the API:

```python
from overseer.client import OverseerApiClient

client = OverseerApiClient(auth_token_file="state/api-token")
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
