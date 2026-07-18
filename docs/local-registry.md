# Local Registry

The first usable Overseer core is an in-memory registry. It is intentionally not a daemon or database yet; it gives the project a tested coordination surface before persistence, background probes, or live host actions are introduced.

## Responsibilities

- register resources
- accept resource claims from project threads
- run the shared conflict and approval decision model
- activate claims that are allowed
- queue conflicting claims
- preserve escalation decisions for approvals
- release active claims by id
- keep local state inspectable during tests and early prototypes

## Boundaries

- No secrets are stored.
- No local device, service, firewall, package manager, or database state is changed.
- The registry is process-local and should be replaced or backed by durable storage later.
- Audit logging is represented by stored decision records for now.

## Immediate Growth Path

1. Add durable storage after the data contracts stabilize.
2. Add a command API around the registry.
3. Add adapters for health probes, device discovery, usage-limit probes, and maintenance runners.
4. Add event logs and approval records.
5. Add a CLI or local service interface.
