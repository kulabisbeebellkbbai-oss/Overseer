# Runtime

The runtime entrypoint is the shape of the future Overseer daemon. The first version can run a single foreground tick against an explicit SQLite store, and this workstation has an approved user systemd service installed for continuous local operation.

## Boundaries

- The user systemd unit is local machine state and is not committed to the repository.
- The service uses a no-space symlink at `/home/god/.local/share/overseer/project` because systemd rejected the workspace path with spaces as a working directory.
- No host scheduler is modified.
- Runtime state is read from an explicit SQLite store path.
- The runtime writes a heartbeat on each tick and reports stored resource, usage-limit, health-target, health-evidence, physical-identity, runtime-heartbeat, and audit counts.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once
PYTHONPATH=src python3 -m overseer.cli service-status --store state/overseer.sqlite3
```

## Local User Service

Installed local unit:

```text
/home/god/.config/systemd/user/overseer.service
```

Runtime command:

```bash
/usr/bin/python3 -m overseer.cli run --store /home/god/.local/share/overseer/project/state/overseer.sqlite3
```

Operator commands:

```bash
systemctl --user status overseer.service --no-pager
journalctl --user -u overseer.service --no-pager -n 80
systemctl --user disable --now overseer.service
```
