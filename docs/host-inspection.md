# Host Inspection

Host inspection is Overseer's read-only system evidence layer for admin and DevOps decisions.

## Boundary

- Runs only read-only commands.
- Does not install packages, restart services, edit firewall rules, change routes, or modify permissions.
- Persists snapshots only when an explicit SQLite store path is supplied.
- Any future mutation based on a snapshot still requires the normal approval gate.

## Captured Evidence

- Hostname and OS identity from `/etc/os-release`.
- Kernel and machine details from `uname -a`.
- Running user services from `systemctl --user list-units`.
- Listening TCP sockets from `ss -ltnp`.
- Storage availability from `df -h`.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli inspect-host
PYTHONPATH=src python3 -m overseer.cli inspect-host --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli discover-user-services --store state/overseer.sqlite3
```

Persisted snapshots appear in `list-state` under `host_snapshots`.

`discover-user-services` captures the same read-only host snapshot, registers each running systemd user service as a `service` resource owned by Julian, and creates a matching process health target for stored health probes. It does not start, stop, restart, enable, disable, or edit any service.

## Security Assessment

Odo's first host assessment flags TCP listeners that are not bound to loopback. This is read-only and does not change firewall rules or service bind addresses.

```bash
PYTHONPATH=src python3 -m overseer.cli assess-host-security --store state/overseer.sqlite3
```

High findings mean an externally bound listener exists and should be reviewed through an approval-gated admin change plan before any firewall or bind-address change is made.
