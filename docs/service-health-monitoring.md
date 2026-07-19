# Service Health Monitoring Model

Julian owns service health and efficiency. Health work records exact failing paths, maps failures to owner domains, and requires recovery evidence before incidents close.

## Health Targets

Health targets represent things Overseer can check without mutating state:

- MCP service endpoint,
- hosted page,
- HTTPS endpoint,
- HTML response,
- JSON response,
- process or systemd unit,
- local command,
- log-derived incident.

Required fields:

- `id`
- `resource_id`
- `name`
- `probe_type`
- `target`
- `owner_domain`
- `expected_status`
- `expected_content_type`
- `failure_owner`
- `recovery_required`

## Probe Result Fields

A probe result records the observed state:

- `target`: exact endpoint, command, path, process, or service tested.
- `probe_type`: `http`, `https`, `mcp`, `html`, `json`, `process`, `command`, `log`, or `manual`.
- `status_code`: HTTP status when available.
- `content_type`: response content type when available.
- `body_summary`: short safe summary, never raw secrets.
- `error`: exact error text when the probe failed.
- `latency_ms`: elapsed time when available.
- `captured_at`

## Status Classification

Julian classifies results into:

- `healthy`: expected status and content were observed.
- `degraded`: response exists but is slow, unexpected, or incomplete.
- `failed`: endpoint, command, parser, or service failed.
- `unknown`: insufficient evidence.
- `recovered`: prior failure is now healthy and recovery evidence is attached.

Default classification:

- Transport or command errors are `failed`.
- HTTP 5xx is `failed`.
- HTTP 4xx is `degraded` unless the endpoint expects that status.
- Invalid JSON on a JSON target is `failed`.
- Non-HTML content on an HTML target is `degraded`.
- Latency above the configured threshold is `degraded`.
- Missing target or missing result is `unknown`.

## Owner Mapping

Failures map to owner domains:

- MCP service errors: Julian first, then O'Brien if service restart or patching is required.
- Hosted page errors: Julian first, Dax if proxy/gateway topology is involved.
- HTTPS errors: Julian first, Dax or Odo if certificate, proxy, or exposure boundaries are involved.
- HTML/JSON errors: Julian first, owning application thread second.
- Security-looking failures: Odo.
- Maintenance-induced failures: O'Brien.

## Recovery Gate

An incident can close only when:

- the same target or an explicitly equivalent target is probed,
- result class is `healthy` or `recovered`,
- recovery evidence links to the original failure,
- affected claims have release conditions satisfied,
- audit log records the close action.

## First Slice

The first executable slice should:

1. Classify probe results without requiring live network calls.
2. Preserve exact target and error fields.
3. Map failures to an owner domain.
4. Require recovery evidence before closure.

## Health Efficiency Summary

Julian's compact operator read model is available with:

```bash
PYTHONPATH=src python3 -m overseer.cli health-efficiency --store state/overseer.sqlite3
```

It summarizes target status counts, probe-type coverage, owner routing, recovery requirements, missing evidence, and latest failures for MCP, hosted page, HTTPS, HTML, JSON, process, command, log, and manual health checks.

## Live Process Probes

Julian can run read-only process probes for explicit process targets:

```bash
PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.overseer.api --name "Overseer API" --probe-type process --url systemd:user:overseer-api.service --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli probe-health --resource-id svc.example --name "Example PID" --probe-type process --url pid:1234 --store state/overseer.sqlite3
```

Supported process target forms:

- `systemd:user:<unit>`: checks `systemctl --user is-active <unit>`.
- `systemd:system:<unit>`: checks `systemctl is-active <unit>`.
- `pid:<pid>`: checks that a process ID is present with `ps`.
- any other value: checks for a matching process with `pgrep -af`.

These probes only observe process state. They do not start, stop, restart, enable, disable, install, remove, or reconfigure services.
