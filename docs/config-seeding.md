# Config Seeding

Config seeding imports operator-provided JSON configuration into an explicit SQLite store. It is useful for preparing known resources and usage limits before live discovery exists.

## Command Shape

```bash
PYTHONPATH=src python3 -m overseer.cli seed-config --config config/overseer.json --store state/overseer.sqlite3
```

## Boundaries

- Both config and store paths must be explicit.
- Seeding does not probe devices, services, or network state.
- Seeding does not execute maintenance, security, package, or scheduler actions.
- Runtime SQLite files remain ignored by `.gitignore`.
