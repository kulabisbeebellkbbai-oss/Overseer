# Live Health Probes

Live health probes are the first approved live adapter. They perform a read-only HTTP, HTTPS, or MCP readiness request against an explicit operator-provided target and convert the result into existing health evidence.

## Boundaries

- In v1.1, a stored health target runs only when its scheduler-owned job is due;
  an operator/API run-now action queues or coalesces a request and never runs
  the probe inline. Direct CLI probing remains an explicit diagnostic surface.
- The probe performs an HTTP GET and does not mutate service state.
- MCP probes perform a non-mutating streamable HTTP `initialize` request against the MCP endpoint, which covers services like MarkItDown that do not expose a separate `/health` route.
- The probe does not follow host discovery, scan ports, install daemons, or touch firewall rules.
- Probe output contains status, content type, latency, and a short body summary only.
- Health evidence is persisted only when an explicit SQLite store path is provided.

## v1.1 scheduling and failure handling

Health targets seed stable `health_probe` jobs. The compatible default is a
120-second interval, zero jitter, 30-second timeout, and `triage_only` repair
policy when optional schedule fields are absent. The scheduler applies bounded
leases, backoff, circuit cooldown, evidence retention, and durable incident
state. Read `docs/v1.1-operations.md` for status/request commands and the
approval boundary for repairs.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.local --name Local --url http://127.0.0.1:8791/health --probe-type json --expected-content-type application/json
PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.mcp.markitdown --name 'MarkItDown MCP Initialize' --url http://127.0.0.1:8792/mcp --probe-type mcp --expected-content-type application/json
PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.local --name Local --url http://127.0.0.1:8791/health --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli probe-config --config config/overseer.json --store state/overseer.sqlite3
```
