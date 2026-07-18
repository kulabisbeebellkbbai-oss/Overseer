# Overseer

Overseer is a local resource manager for coordinating shared machine services, physical assets, virtual assets, usage-limited services, maintenance, updates, and security actions across multiple Codex projects or threads.

Its purpose is to prevent conflicting work by tracking ownership, checkout state, locks, limits, health, and safe timing for resources such as the Protected Gateway, USB and serial devices, emulators, VMs, gateways, proxies, MCP services, hosted pages, update pipelines, storage arrays, and power-sensitive assets.

The first release should include a working initial slice for every major domain:

- physical asset checkout
- virtual asset checkout
- service health monitoring
- maintenance and update scheduling
- usage-limit scheduling
- security monitoring and protective actions

## Project Layout

- `src/` - application source code
- `tests/` - automated tests
- `assets/` - static or generated project assets
- `docs/` - project summary, role map, gates, and design notes

## Current Status

- Approved project summary: `docs/project-summary.md`
- DS9-inspired agent role map: `docs/agents.md`
- Initial quality gates: `docs/quality-gates.md`
- Command and safety model: `docs/command-safety-model.md`
- Virtual asset checkout: `docs/virtual-asset-checkout.md`
- Service health monitoring: `docs/service-health-monitoring.md`
- Physical asset checkout: `docs/physical-asset-checkout.md`
- Maintenance and patch operations: `docs/maintenance-and-patch-operations.md`
- Security monitoring: `docs/security-monitoring.md`

No runtime stack has been selected yet. Do not commit secrets, credentials, local databases, live service state, or personal exports.
