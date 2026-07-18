# Runtime

The runtime entrypoint is the shape of the future Overseer daemon. The first version is operator-started and foreground-only; it can run a single tick against an explicit SQLite store.

## Boundaries

- No systemd unit is installed.
- No background service is started automatically.
- No host scheduler is modified.
- Runtime state is read from an explicit SQLite store path.
- The first tick reports stored resource, usage-limit, and audit counts only.

## CLI

```bash
PYTHONPATH=src python3 -m overseer.cli run --store state/overseer.sqlite3 --once
```
