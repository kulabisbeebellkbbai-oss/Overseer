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
```

Persisted snapshots appear in `list-state` under `host_snapshots`.
