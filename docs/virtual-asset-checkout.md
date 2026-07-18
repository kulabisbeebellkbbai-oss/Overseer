# Virtual Asset Checkout Model

Dax owns checkout and deconfliction for emulators, VMs, gateways, proxies, and virtual topologies. This model extends the command and safety model with virtual-resource-specific identity, dependency, and conflict rules.

## Virtual Resource Types

- `emulator`: Android emulator, MCU simulator, QEMU instance, Renode target, or similar runtime.
- `vm`: local virtual machine or containerized host with durable state.
- `gateway`: local gateway, protected gateway, VPN gateway, or routed service boundary.
- `proxy`: HTTP, SOCKS, MCP, reverse proxy, tunnel, or port-forwarding service.
- `network_segment`: named subnet, bridge, NAT segment, or isolated lab network.
- `composite_topology`: a grouped topology containing multiple virtual resources.

## Identity Fields

Virtual resources must include enough identity to avoid alias collisions:

- `resource_id`
- `kind`
- `display_name`
- `owner_domain`: `dax`
- `risk_level`
- `host`
- `ports`
- `networks`
- `state_path`
- `process_hint`
- `config_paths`
- `depends_on`
- `exclusive_groups`

Examples:

- Android emulator: AVD name, console port, adb serial, snapshot state path.
- VM: hypervisor, VM name, UUID, bridge, storage image path.
- Gateway: bind address, managed route table, firewall dependency, protected service list.
- Proxy: listen port, upstream target, config file, credential boundary.

## Lease Fields

Virtual leases use the shared claim fields plus:

- `topology_scope`: isolated resource, network segment, gateway chain, or composite.
- `port_reservations`: host ports reserved by the lease.
- `route_changes`: planned route or proxy changes.
- `state_mutation`: none, ephemeral, snapshot, persistent.
- `rollback_hint`: how to restore virtual state.
- `release_probe`: command or health check proving release.

## Conflict Rules

Virtual work conflicts when any of these overlap:

- same resource ID,
- same exclusive group,
- same host port,
- same gateway or proxy chain,
- same mutable state path,
- same network segment with write/topology intent,
- dependency resource held by another exclusive claim,
- active security quarantine,
- active health degradation that blocks risky changes.

Default behavior:

- Read-only observation can share a resource when no exclusive lease exists.
- Topology changes require exclusive access to all affected gateways, proxies, and network segments.
- Persistent-state mutations require rollback evidence or a snapshot plan.
- Gateway and proxy changes are high risk by default and require Sisko or human approval depending on exposure.
- Expired leases become operator-review items before reuse.

## Required Release Evidence

A virtual asset is releasable only when:

- reserved ports are free or intentionally retained,
- temporary routes or proxy rules are removed,
- mutated state is committed, reverted, or snapshotted,
- dependent resources have matching release state,
- Julian's health check passes for affected services,
- audit entries link the release evidence.

## First Slice

The first executable slice should support:

1. Registering virtual resources with ports, networks, dependencies, and exclusive groups.
2. Requesting an exclusive lease.
3. Blocking conflicts on resource ID, port, dependency, and exclusive group.
4. Queueing compatible requests.
5. Releasing a lease only with a release condition.

## CLI Flow

```bash
PYTHONPATH=src python3 -m overseer.cli request-claim --store state/overseer.sqlite3 --claim-id claim.gateway --resource-id gateway.protected --claim-type lease --owner-thread thread-a --owner-role dax --intent "use gateway" --requested-action "bind gateway" --risk-level low
PYTHONPATH=src python3 -m overseer.cli approve-claim --store state/overseer.sqlite3 --approval-id approval.claim.gateway --decided-by sisko
PYTHONPATH=src python3 -m overseer.cli activate-claim --store state/overseer.sqlite3 --claim-id claim.gateway --approval-id approval.claim.gateway
PYTHONPATH=src python3 -m overseer.cli release-claim --store state/overseer.sqlite3 --claim-id claim.gateway
PYTHONPATH=src python3 -m overseer.cli virtual-summary --store state/overseer.sqlite3
```

`virtual-summary` is Dax's compact read model for persisted virtual resources. It reports asset counts, checkout readiness, active and queued claims, reserved ports, counts by virtual kind, state, and risk, plus per-asset topology identity details.
