# Adapters And Dry Run

Adapters are the boundary between Overseer's coordination model and the local machine. The first adapter slice is intentionally dry-run only: it defines contracts and records intended operations without touching services, devices, packages, firewall rules, or daemon state.

## Agent provider adapters

Agent adapters are isolated translations of a verified provider interface.
They construct subprocess argument arrays, run with `shell=False`, confine the
workspace, bound input/output/time, verify session identity, and normalize
results without exposing provider output. Unsupported operations return
`unsupported_capability`; dry-run code must not scrape a GUI, fabricate a
session, or emulate cancellation.

Ordinary tests use `tests/fake_agent_provider.py`. The Claude adapter is proven
through fake-executable, identity, protocol, bounded-output, recovery, and
manager handoff tests. The `live_agent` test requires explicit provider opt-in,
local authentication, and a disposable workspace and is excluded from normal
regression. No live provider prompt was run for this release. Qwen Code,
Mistral Vibe, and Antigravity remain unavailable until their programmatic
interfaces are verified; no command should be inferred from a product name.

The complete implementation checklist is in
`docs/provider-adapter-contract.md`.

## Adapter Categories

- health probes
- maintenance runners, including package install, package index refresh, package upgrade, and user-service restart adapters
- provider-specific installers for non-apt software such as Flatpak, npm, pipx,
  or snap packages
- physical asset discovery
- security action runners
- usage-limit probes

## Dry-Run Rules

- Dry-run execution may create evidence records in memory.
- Dry-run execution may not change host state.
- Live adapters must be explicit dependencies.
- Live adapters must be wrapped by approval and audit gates before use.
- Security, package-manager, firewall, device, and daemon operations remain authorization-bound.
- Apt adapters must reject provider-prefixed package identifiers instead of
  passing them to `apt-get`; those requests need a provider-specific adapter.

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
