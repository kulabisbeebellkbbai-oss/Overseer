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
- `POST /Overseer/virtual/target-setup-requests`
- `POST /Overseer/virtual/target-setup-requests/result`
- `POST /Overseer/virtual/runtime-records`
- `POST /Overseer/virtual/lifecycle/execute`
- `POST /Overseer/virtual/snapshot-requests`
- `POST /Overseer/virtual/snapshot-requests/approve`
- `POST /Overseer/virtual/snapshot-requests/execute`
- `POST /Overseer/virtual/restore-requests`
- `POST /Overseer/virtual/restore-requests/approve`
- `POST /Overseer/virtual/restore-requests/execute`

Operator controls live on the Claims page:

- Virtual Runtime Record records observed state, adapter, ports, and snapshot
  hints.
- Real Provider Target Setup stages approval-required target creation requests
  for Docker, Podman, libvirt, qemu process, Renode, Android Emulator,
  and gateway/proxy targets.
- Target Setup Result records Dax's evidence after an approved setup batch is
  executed. It marks each provider target completed, blocked, failed, or
  partial without performing host mutation itself.
- Virtual Lifecycle executes `inspect`, `start`, or `stop` against approved
  disposable Docker, Podman, libvirt, qemu process, Renode, Android Emulator, or
  gateway/proxy runtime records and writes lifecycle manifests.
- Virtual Snapshot Request stages a snapshot plan and waits for approval.
- Virtual Restore Request stages a rollback plan and waits for approval.

Snapshot and restore execution is implemented through conservative approved
provider adapters. Every path requires a staged and approved request, a runtime
record with the selected adapter, and a declared disposable target before Dax
mutates anything.

Provider coverage:

- `local_fixture`: copies project-local files or directories under
  `local-secrets/virtual-runtime-targets` for regression-safe workflow tests.
- `qemu_img`: uses `qemu-img snapshot -c` and `qemu-img snapshot -a` against
  stopped disposable qcow2 images.
- `qemu_process`: uses the qcow2 snapshot path after verifying the disposable
  QEMU pidfile is not running.
- `libvirt`: uses the qcow2 snapshot path after verifying the disposable domain
  is stopped.
- `docker` and `podman`: export disposable container filesystems to
  `container.tar`, preserve the pre-restore container export when present, and
  recreate the disposable container with `--network none`.
- `renode` and `gateway_proxy`: copy file-backed disposable scripts or configs
  under `local-secrets/virtual-runtime-targets` or
  `local-secrets/virtual-runtime-configs`.
- `android_emulator`: copies only an approved disposable AVD directory under
  `~/.android/avd/<resource_id>.avd`.

Execution writes manifests under `local-secrets/virtual-runtime-manifests` and
preserves pre-restore state under `local-secrets/virtual-runtime-preserved`
where the provider supports local preservation.

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

VirtualBox is not part of the required provider setup path. Dax can add it later
as an optional provider only if a trusted package source and host virtualization
stack decision are explicitly approved.

`qemu_img` guardrails:

- runtime record `adapter` must be `qemu_img`, or `qemu_process`/`libvirt` when
  that provider is intentionally selected;
- `snapshot_hint` must point to a project-relative `.qcow2` image under
  `local-secrets/virtual-runtime-targets`;
- `qemu-img info --output=json` must report `qcow2`;
- `qemu_process` must not be running;
- `libvirt` domains must be stopped;
- restore preserves the pre-restore image under
  `local-secrets/virtual-runtime-preserved`;
- Dax writes execution manifests under `local-secrets/virtual-runtime-manifests`.

Lifecycle execution is available for approved disposable provider targets:

```bash
PYTHONPATH=src python3 -m overseer.cli execute-virtual-lifecycle --project-root . --resource-id overseer-dax-disposable-proxy --action inspect
PYTHONPATH=src python3 -m overseer.cli execute-virtual-lifecycle --project-root . --resource-id overseer-dax-disposable-docker --action start
PYTHONPATH=src python3 -m overseer.cli execute-virtual-lifecycle --project-root . --resource-id overseer-dax-disposable-docker --action stop
```

The lifecycle path rejects non-disposable runtime records, unsupported providers,
and unsafe project paths. `inspect` records evidence only. `start` and `stop`
mutate only the named disposable provider target and write execution manifests
under `local-secrets/virtual-runtime-manifests`.

## Target Setup Batch

Dax can stage the full provider-target approval batch without changing the host:

```bash
PYTHONPATH=src python3 -m overseer.cli stage-virtual-target-setup-batch --project-root . --scope all
```

The staged records include current state, proposed state, exact proposed
commands or actions, risks, and rollback plan. They are review artifacts only.
They do not install packages, change groups, start processes, create VMs,
create containers, bind ports, create networks, or write gateway configs.

After Sisko or the human approves and Dax executes the setup outside the
staging call, Dax records the evidence. For providers with an implemented
disposable setup executor, Dax can execute and record evidence in one step:

```bash
PYTHONPATH=src python3 -m overseer.cli execute-virtual-target-setup --project-root . --provider gateway_proxy --approved-by sisko
```

Dax can also record an externally completed setup:

```bash
PYTHONPATH=src python3 -m overseer.cli record-virtual-target-setup-result --project-root . --provider docker --status completed --evidence "container exists with network none"
```

Completion records clear the target setup approval requirement for that
provider. Blocked, failed, and partial records keep approval required and surface
the supplied evidence as the next resolution target.

## Read-Only Provider Inventory

The Claims page also includes Runtime Provider Inventory, Provider Depth
Coverage, Virtual Capacity Summary, and Image Provenance Review. Dax gathers
read-only Docker container rows from `docker ps -a --format '{{json .}}'`,
Podman rows from `podman ps -a --format json`, libvirt VM rows from
`virsh list --all --name` plus `virsh domstate`, qemu qcow2 image rows from
staged files under `local-secrets/virtual-runtime-targets`, and registered
runtime depth rows for qemu process, Renode, Android Emulator, and
gateway/proxy records. Qemu image inventory includes the project-relative image
path, format status, virtual size, actual size, and internal snapshot names.
Container inventory includes CPU, memory, network, and block-I/O fields when
`docker stats` or `podman stats` can read them without mutating runtime state.
Registered qemu process, Renode, Android Emulator, and gateway/proxy rows infer
network posture from ports and local runtime notes.
Dax also reports CLI availability in Runtime Adapter Availability. Commands use
short timeouts and return unavailable inventory rows when a CLI exists but the
daemon, rootless runtime, or libvirt session is not accessible.

Inventory, capacity, and provenance rows are evidence only. They do not start,
stop, snapshot, restore, or destroy runtimes. Any mutation still requires a Dax
claim plus the staged lifecycle or snapshot/restore execution workflow.
