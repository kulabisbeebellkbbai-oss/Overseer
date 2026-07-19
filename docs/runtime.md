# Runtime

The runtime entrypoint can run a single foreground tick against an explicit SQLite store, and this workstation has an approved user systemd service installed for continuous local operation.

## Boundaries

- The user systemd unit is local machine state and is not committed to the repository.
- The service uses a no-space symlink at `/home/god/.local/share/overseer/project` because systemd rejected the workspace path with spaces as a working directory.
- No host scheduler is modified.
- Runtime state is read from an explicit SQLite store path.
- The runtime writes a heartbeat on each tick and reports stored resource, usage-limit, health-target, health-evidence, physical-identity, runtime-heartbeat, and audit counts.
- Configured health probes are read-only HTTP requests and run only when `--probe-health-targets` is supplied.
- Runtime health evidence is pruned per target with `--health-evidence-retention-per-target`.
- Host inspection snapshots are read-only command and file observations and run only when `--inspect-host` is supplied.
- Enabling host inspection in the installed user service changes the service runtime command and requires an explicit approved admin plan before restart.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once
PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once --probe-health-targets --health-evidence-retention-per-target 5
PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once --inspect-host
PYTHONPATH=src python3 -m overseer.cli service-status --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli runtime-status --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli daemon-migration-plan --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli request-daemon-migration --store state/overseer.sqlite3 --requested-by sisko
PYTHONPATH=src python3 -m overseer.cli alerts-summary --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli health-summary --store state/overseer.sqlite3 --fail-on-unhealthy
```

`runtime-status` is the monitor-friendly surface for Julian and Odo. It reports the service heartbeat, latest host inspection snapshot id and capture time, freshness state, and current high/warning host security finding counts without requiring consumers to parse raw snapshots.

`daemon-migration-plan` is a read-only Sisko gate for foreground-to-daemon migration. `request-daemon-migration` and `approve-daemon-migration` record the approval state required before changing user service enablement or runtime commands; they do not edit systemd state or restart services.

Default freshness thresholds:

- Runtime heartbeat: `warning` at 90 seconds, `high` at 300 seconds.
- Host inspection snapshot: `warning` at 120 seconds, `high` at 600 seconds.
- Missing host inspection evidence is reported as `missing`.
- Non-OK freshness states persist `alert` audit events with stable IDs so repeated status reads do not flood duplicate records.

`alerts-summary` reports persisted alert audit events only, grouped by risk and owner domain.

## Local User Service

Installed local unit:

```text
/home/god/.config/systemd/user/overseer.service
```

Runtime command:

```bash
/usr/bin/python3 -m overseer.cli run --store /home/god/.local/share/overseer/project/state/overseer.sqlite3 --probe-health-targets --health-evidence-retention-per-target 5
```

Operator commands:

```bash
systemctl --user status overseer.service --no-pager
journalctl --user -u overseer.service --no-pager -n 80
systemctl --user disable --now overseer.service
```
