# Local API

The Overseer API is a loopback-only HTTP surface for local Codex threads and tools that should not shell out to the CLI for every operation.

## Boundary

- The API may bind only to `127.0.0.1` or `localhost`.
- No firewall rule is created.
- No external address is exposed.
- It uses the same explicit SQLite store path as the CLI and user service.

## Run

```bash
PYTHONPATH=src python3 -m overseer.cli serve-api --store state/overseer.sqlite3 --host 127.0.0.1 --port 8766
```

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

All request bodies are JSON objects. Claim operations use the same field names as the CLI options, with underscores instead of hyphens.

## Installed User Service

The approved local service is installed as:

```text
/home/god/.config/systemd/user/overseer-api.service
```

Rollback:

```bash
systemctl --user disable --now overseer-api.service
```
