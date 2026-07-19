# Config Seeding

Config seeding imports operator-provided JSON configuration into an explicit SQLite store. It is useful for preparing known resources, usage limits, health targets, and physical identities before live discovery exists.

## Command Shape

```bash
PYTHONPATH=src python3 -m overseer.cli seed-config --config config/overseer.json --store state/overseer.sqlite3
```

## Boundaries

- Both config and store paths must be explicit.
- Seeding does not probe devices, services, or network state.
- Seeded physical identities are operator-declared records; they do not prove the device is currently connected.
- Seeding does not execute maintenance, security, package, or scheduler actions.
- Runtime SQLite files remain ignored by `.gitignore`.
