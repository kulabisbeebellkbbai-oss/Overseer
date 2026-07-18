# Adapters And Dry Run

Adapters are the boundary between Overseer's coordination model and the local machine. The first adapter slice is intentionally dry-run only: it defines contracts and records intended operations without touching services, devices, packages, firewall rules, or daemon state.

## Adapter Categories

- health probes
- maintenance runners
- physical asset discovery
- security action runners
- usage-limit probes

## Dry-Run Rules

- Dry-run execution may create evidence records in memory.
- Dry-run execution may not change host state.
- Live adapters must be explicit dependencies.
- Live adapters must be wrapped by approval and audit gates before use.
- Security, package-manager, firewall, device, and daemon operations remain authorization-bound.

## Execution Result

Every adapter call should report:

- execution id
- action name
- target resource id
- mode: dry run or live
- status: skipped, planned, completed, blocked, or failed
- owner domain
- summary
- evidence ids
