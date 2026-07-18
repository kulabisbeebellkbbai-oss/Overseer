# Live Health Probes

Live health probes are the first approved live adapter. They perform a read-only HTTP or HTTPS request against an explicit operator-provided URL and convert the result into existing health evidence.

## Boundaries

- The probe only runs when an operator passes a target URL.
- The probe performs an HTTP GET and does not mutate service state.
- The probe does not follow host discovery, scan ports, install daemons, or touch firewall rules.
- Probe output contains status, content type, latency, and a short body summary only.
- Health evidence is persisted only when an explicit SQLite store path is provided.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.local --name Local --url http://127.0.0.1:8791/health --probe-type json --expected-content-type application/json
PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.local --name Local --url http://127.0.0.1:8791/health --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli probe-config --config config/overseer.json --store state/overseer.sqlite3
```
