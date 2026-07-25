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

## Live Listener Discovery

Dax can discover local TCP listeners as virtual assets from read-only host inspection evidence:

```bash
PYTHONPATH=src python3 -m overseer.cli discover-virtual-listeners --store state/overseer.sqlite3
```

The adapter reads the existing `ss -ltnp` host-inspection observation and persists one `listener.tcp.*` virtual resource per unique listener. It does not change firewall rules, routes, service definitions, processes, proxies, or network bindings.

Discovered listener assets include:

- `kind`: `gateway` for all-interface listeners, otherwise `proxy`.
- `protocol`: `tcp`.
- `bind_scope`: `loopback`, `all_interfaces`, or `non_loopback`.
- `host` and `ports`.
- `exclusive_groups`: `tcp.<port>` plus the listener-specific `tcp.<host>.<port>` group.
- `process_hint`: the source evidence line from `ss`.

Risk routing is conservative: loopback listeners are low risk, non-loopback listeners are medium risk, and all-interface listeners are high risk.

## Runtime Operations Registry

Dax also maintains a local state registry for virtual runtime observations and
staged lifecycle requests. The registry is stored under ignored project state
and is safe to update from the UI because it records intent and evidence only.

Protected gateway routes:

- `GET /Overseer/virtual/operations`
- `POST /Overseer/virtual/runtime-records`
- `POST /Overseer/virtual/snapshot-requests`
- `POST /Overseer/virtual/snapshot-requests/approve`
- `POST /Overseer/virtual/snapshot-requests/execute`
- `POST /Overseer/virtual/restore-requests`
- `POST /Overseer/virtual/restore-requests/approve`
- `POST /Overseer/virtual/restore-requests/execute`

Operator controls live on the Claims page:

- Virtual Runtime Record records observed state, adapter, ports, and snapshot
  hints.
- Virtual Snapshot Request stages a snapshot plan and waits for approval.
- Virtual Restore Request stages a rollback plan and waits for approval.

Snapshot and restore execution is implemented first through the conservative
`local_fixture` adapter. It only operates on project-relative targets under
`local-secrets/virtual-runtime-targets` and writes manifests under
`local-secrets/virtual-runtime-manifests`. This lets Dax exercise the full
approval and rollback lifecycle in regression without touching real hypervisor,
container, emulator, gateway, proxy, or tunnel state.

CLI:

```bash
PYTHONPATH=src python3 -m overseer.cli record-virtual-runtime --project-root . --resource-id vm.fixture --adapter local_fixture --snapshot-hint local-secrets/virtual-runtime-targets/vm.fixture
PYTHONPATH=src python3 -m overseer.cli stage-virtual-snapshot --project-root . --resource-id vm.fixture --snapshot-name before-change
PYTHONPATH=src python3 -m overseer.cli approve-virtual-snapshot --project-root . --request-id virtual-snapshot.vm.fixture --approved-by sisko
PYTHONPATH=src python3 -m overseer.cli execute-virtual-snapshot --project-root . --request-id virtual-snapshot.vm.fixture
PYTHONPATH=src python3 -m overseer.cli stage-virtual-restore --project-root . --resource-id vm.fixture --restore-point before-change
PYTHONPATH=src python3 -m overseer.cli approve-virtual-restore --project-root . --request-id virtual-restore.vm.fixture --approved-by sisko
PYTHONPATH=src python3 -m overseer.cli execute-virtual-restore --project-root . --request-id virtual-restore.vm.fixture
```

Docker, Podman, libvirt/QEMU, VirtualBox, Android Emulator, Renode, and gateway
provider adapters remain explicit live-provider work. Until one of those
providers is implemented and selected for a declared disposable target,
execution returns a blocked record rather than mutating the host.
