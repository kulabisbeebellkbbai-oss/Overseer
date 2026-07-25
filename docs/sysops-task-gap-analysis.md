# SysOps, DevOps, And Admin Task Gap Analysis

Owner: Ezri
Source UI reviewed: Overview, Admin, Assets, Claims, Security, Health, Usage,
Documents, and Audit operator pages.
Source runbook reviewed: `docs/operator-workflows.md`.

## Purpose

This document inventories the expected work a combined DevOps, SysOps, and
sysadmin team performs on a local workstation or small server environment, then
compares that expectation to the current Overseer operator UI. The goal is to
identify which work is already visible, which work is partially available, and
which gaps should become future UI workflows or backend capabilities.

## Current Overseer UI Coverage

Overseer currently exposes these primary operator surfaces:

- Overview: command status, crew metrics, dispatch queue, drilldowns.
- Admin: service discovery, package update plans, admin plans, approvals,
  execution readiness, adapter enablement, archive/restore, policy helper, and
  policy warning approval.
- Assets: physical discovery, storage discovery, listener discovery, and
  resource registration.
- Claims: resource lease requests, approvals, activation, release, and cleanup.
- Security: host inspection, listener remediation planning, remote source
  review, source block planning, and IDS review package handling.
- Health: health probes, health targets, service summaries, and efficiency
  summaries.
- Usage: quota and usage-limit records, continuation requests, ready-work
  dispatch, and Codex thread discovery.
- Documents: documentation search, folder listing, note writing, knowledge
  capture, account-level git status, and current-repo links.
- Audit: audit events and approval history.

## Baseline Expected Team Tasks

### Command, Triage, And Governance

- Maintain an operator overview for current system state.
- Prioritize incidents, pending changes, blocked work, and approvals.
- Route work to the correct owner.
- Track open tasks, handoffs, dispatch failures, and owner acknowledgements.
- Maintain approval policy and human-approval boundaries.
- Record decisions and evidence.
- Review audit history for completed work.
- Produce periodic readiness, risk, and operations reports.

Coverage: strong for dashboard, routing, approvals, audit, and crew messages.

Gaps:

- No dedicated incident lifecycle board with severity, SLA, owner, timeline,
  impacted resources, and post-incident review.
- No explicit change-calendar or maintenance-window calendar view.
- No service-level objective or SLA/SLO tracking by service.
- No formal risk register or recurring review cadence.

### Service Inventory And Runtime Operations

- Discover services and daemons.
- Track enabled, disabled, running, failed, and unknown services.
- Inspect logs and recent failures.
- Restart, stop, start, reload, enable, or disable services through policy gates.
- Track dependency chains and blast radius.
- Track service ownership, contacts, runbooks, and escalation path.
- Track config files, environment files, secrets references, and unit files.
- Detect orphaned services or unexpected processes.

Coverage: strong for non-privileged service evidence. Overseer can discover
user services, stage admin changes, show service health summaries, register
health targets, run probes, show redacted log evidence, show bounded user
journal excerpts, detect journal access status, stage system-journal access
requests, and route service issues through Julian or O'Brien.

Gaps:

- No first-class service detail page with unit metadata, dependencies, recent
  journal excerpts, restart history, config paths, and owning runbook.
- No approved privileged system-journal capture runner after a staged request is
  approved.
- No direct service action workflow for start, stop, restart, reload, enable, or
  disable with readiness evidence and rollback.
- No process tree or per-process resource usage explorer.
- No dependency-impact analysis before service changes.

### Patch, Package, And Software Lifecycle

- Check package update availability.
- Plan updates with rollback notes.
- Apply approved updates.
- Roll back failed updates when feasible.
- Track package pins, held packages, versions, repositories, and provenance.
- Track installed software outside apt, including pip, npm, cargo, snap, flatpak,
  AppImage, local builds, and manual binaries.
- Track CVEs and advisories affecting installed packages.
- Schedule update windows and blackout windows.
- Validate services after updates.

Coverage: strong for apt-oriented planning, admin approval, package-manager
evidence, package provenance, maintenance scheduling, and cached NVD/Debian
advisory correlation. The UI can plan package updates, show package status,
stage admin plans, approve plans, execute approved admin plans, refresh
advisory feeds, and link findings back to source advisories.

Gaps:

- No dedicated installed-software inventory across package managers and manual
  installs.
- No patch compliance dashboard by severity, age, package, and host area.
- No rollback execution tracker tied to post-update health checks.
- No automated release-note and advisory impact summary per pending update.

### Security Operations

- Inspect host security posture.
- Review exposed listeners, ports, and bound addresses.
- Classify remote sources and suspicious traffic.
- Stage firewall or source-block plans.
- Coordinate IDS/IPS reviews.
- Track active incidents, containment, eradication, recovery, and lessons
  learned.
- Review authentication failures, privilege changes, sudo use, SSH activity,
  local account changes, and persistence mechanisms.
- Monitor file integrity for sensitive paths.
- Track security baselines and drift.
- Review secrets exposure risk.
- Track vulnerability findings and remediation status.

Coverage: strong for listener review, host inspection, source review, block
planning, IDS package workflow, firewall provenance, desired-policy diffing, and
desired-policy enforcement staging. Audit supports evidence retention.

Gaps:

- No active incident lifecycle board.
- No security baseline drift dashboard.
- No auth log, sudo log, SSH log, or account-change review panel.
- No file-integrity monitoring view.
- No vulnerability/CVE finding registry with remediation status.
- No secrets exposure scan result panel.
- No approved firewall execution runner after IDS review and human approval.
- No containment timeline or recovery checklist.

### Networking, Gateway, And Proxy Operations

- Inventory listeners, gateways, proxies, tunnels, and exposed ports.
- Track ownership of ports and gateway routes.
- Detect conflicts before services bind or routes change.
- Review DNS, routing, VPN, and firewall behavior.
- Validate TLS certificates, HTTPS health, redirects, headers, and JSON/HTML
  response health.
- Track protected gateway routes and authentication behavior.
- Review failed requests, status-code trends, and latency.

Coverage: partial. Dax and Odo cover virtual assets, listeners, gateway/proxy
claims, and source review. Julian covers HTTP and content health through probes.

Gaps:

- No route table, DNS resolver, VPN, or interface status view.
- No TLS certificate expiry and chain validation panel.
- No protected-gateway route inventory with upstream mapping.
- No request log explorer or status-code trend dashboard.
- No port-conflict simulation before a planned service launch.
- No network throughput, packet error, or interface saturation view.

### Storage, Filesystem, Backup, And Recovery

- Inventory disks, partitions, mounts, filesystems, storage arrays, and USB
  storage.
- Track free space, inode pressure, read-only mounts, SMART health, and I/O
  errors.
- Track backup jobs, retention, restore points, and restore test status.
- Review large files, growth trends, and cleanup candidates.
- Track database locations and backup exclusions.
- Protect secrets, credentials, local databases, personal exports, and ignored
  local state.

Coverage: strong for storage discovery, resource registration, mount-health
dashboard, SMART availability, backup job records, restore-test records, cleanup
request staging, marker discovery, and capacity summaries. Claims can protect
shared storage before changes. Live backup, restore, and cleanup execution
remain approval-bound.

Gaps:

- No approved live backup or restore execution runner.
- No filesystem growth trend panel.
- No storage risk alerts for local databases, WAL files, or ignored exports.
- No encryption status or removable-media trust workflow.

### Physical Devices, Power, And Lab Assets

- Inventory USB, serial, COM ports, development boards, attached devices,
  storage arrays, and power-managed devices.
- Track device identity, current owner, intended use, and firmware state.
- Detect new, missing, or changed devices.
- Reserve exclusive physical assets.
- Track power state, battery/UPS state, thermal state, and safe shutdown needs.
- Maintain device runbooks and calibration/maintenance history.

Coverage: partial. Assets supports physical discovery and registration, while
Claims supports checkout and release.

Gaps:

- No device detail page with identity history, firmware state, by-id path,
  serial number, last owner, and maintenance notes.
- No power/UPS/thermal dashboard.
- No safe attach/detach workflow.
- No scheduled physical asset audit.
- No calibration, firmware, or hardware maintenance history view.

### Virtualization, Containers, Emulators, And Sandboxes

- Inventory VMs, containers, emulators, local gateways, proxies, tunnels, and
  reserved ports.
- Track leases, owners, expiration, conflicts, and cleanup candidates.
- Start, stop, snapshot, restore, and destroy virtual assets under policy.
- Track image provenance, versions, network exposure, and disk usage.
- Detect stale or abandoned leases.

Coverage: strong for checkout, conflict prevention, staged lifecycle planning,
and approved disposable execution. Dax covers virtual claims, listener
discovery, leases, release, cleanup, runtime state records, staged
snapshot/restore requests, approved `local_fixture` workflow execution,
`qemu_img` qcow2 snapshot/restore, stopped `qemu_process` and `libvirt`
image-backed snapshot/restore, Docker/Podman container export/import
snapshot/restore, file-backed Renode/proxy snapshot/restore, and approved
disposable Android AVD directory snapshot/restore with manifests under
`local-secrets`.

Gaps:

- No approved live adapter inventory with state, image, CPU, memory, disk,
  network, and owner gathered directly from every backend. Dax now surfaces
  read-only Docker and virsh provider inventory when those CLIs are available,
  plus qemu qcow2 image format, size, and internal snapshot metadata for staged
  images under `local-secrets/virtual-runtime-targets`. CPU, memory, running
  disk usage, network topology, Podman, QEMU process, emulator, Renode, and
  gateway/proxy depth still need provider-specific collectors.
- No approved running-domain libvirt snapshot policy, VirtualBox provider,
  destroy action, or generalized snapshot/restore for non-disposable targets.
  Provider snapshot/restore is intentionally limited to approved disposable
  targets and stopped image-backed runtime state.
- No container image vulnerability/provenance panel.
- No resource-capacity planning for CPU, memory, disk, and port pools.

### Observability, Health, And Performance

- Track service uptime, probe status, latency, error rates, and content
  correctness.
- Review unhealthy services and logs.
- Track host CPU, memory, disk I/O, network I/O, load average, temperature, and
  process resource usage.
- Track MCP server errors, hosted page failures, HTTP status, HTML/JSON errors,
  and performance regressions.
- Trend performance over time and alert on regressions.
- Validate recovery after maintenance or security actions.

Coverage: strong for retained service evidence and operator visibility. Julian
can register targets, run probes, view summaries, show service health and
efficiency, inspect host resource summaries, view redacted log evidence, use
bounded user-journal excerpts, stage system-journal access requests, review
health trend history, and capture durable metric history snapshots. Regression
tests cover UI and endpoint performance.

Gaps:

- No deep host resource dashboard for CPU, memory, I/O, network, load, and
  thermal trends beyond retained snapshot summaries.
- No full latency trend graph or error-rate chart beyond retained trend tables.
- No dependency-aware health rollup.

### Usage Limits, Quotas, Costs, And Continuations

- Track API quotas, rate limits, cooldowns, daily/weekly/monthly renewals, and
  usage-limited services.
- Schedule continuation work after reset.
- Avoid retries during cooldowns.
- Track cost, credits, budget, and usage allocation by project or service.
- Alert on exhausted, low-confidence, or unknown limit state.

Coverage: strong for local quota records, continuation requests, and dispatch.
Quark can discover Codex project threads and schedule continuation work.

Gaps:

- No cost or credit tracking.
- No provider-specific quota adapters displayed with reset policies and
  confidence level.
- No historical usage graph.
- No forecast for exhaustion time.
- No cross-project allocation report.

### Configuration, Policy, Compliance, And Drift

- Track active policies and exceptions.
- Compare current state against desired baselines.
- Review policy warnings, accepted risks, and expiry.
- Track config drift for services, firewall, packages, users, system settings,
  and protected gateway.
- Maintain compliance checklists and evidence.
- Review local-only secret handling and ignored files.

Coverage: partial. Admin exposes active policy profile, policy helper, policy
warning request/approval, and audit history.

Gaps:

- No desired-state baseline inventory.
- No drift-detection dashboard.
- No exception expiry and renewal workflow.
- No compliance evidence matrix.
- No local secret inventory or rotation reminder panel.

### Documentation, Knowledge, And Git

- Search runbooks and operational notes.
- Capture decisions, audit summaries, and knowledge from completed work.
- Keep runbooks linked from operational pages.
- Track git repositories, dirty working trees, remote links, and branch state.
- Track release notes, changelogs, deployment docs, architecture records, and
  postmortems.

Coverage: strong for documentation search, folder listing, note writing,
knowledge capture, account-level git status, and workflow runbooks.

Gaps:

- No document freshness or stale-runbook report.
- No required-runbook coverage matrix by service/resource.
- No architecture decision record index.
- No release/changelog dashboard.
- No repo maintenance workflows for branch hygiene, stale worktrees, CI status,
  or dependency update status.

### User, Access, Secrets, And Identity Administration

- Review local users, groups, sudoers, SSH keys, service accounts, API keys,
  token files, and credential age.
- Track access grants, revocations, and privilege changes.
- Detect unauthorized credential files or secret leakage.
- Rotate secrets and document custody.
- Enforce least privilege.

Coverage: partial to strong for review and staging. Odo shows local
user/group/service-account summaries, SSH public key custody hashes, secret-file
custody markers, rotation reminders, and staged identity/secret rotation
requests without exposing secret contents.

Gaps:

- No authorized_keys deep review workflow.
- No API key age, scope, provider, and quota inventory beyond local secret
  custody markers.
- No service-account registry.
- No secret scanning summary tied to remediation plans.
- No approved live credential rotation, account modification, or revocation
  executor.

## Highest Priority UI Gaps

1. Incident lifecycle board for security, health, maintenance, and service
   failures.
2. Service detail page with logs, dependencies, unit/config metadata, recent
   actions, and linked runbooks.
3. Host resource dashboard for CPU, memory, disk, I/O, network, thermal, and
   process usage.
4. Maintenance schedule editor with blackout windows, recurring tasks, and
   post-change validation.
5. Patch compliance and software inventory across apt and non-apt installs.
6. Security baseline drift, auth-log review, firewall diff/provenance, and
   vulnerability registry.
7. Storage health, backup/restore, and capacity planning.
8. VM/container/emulator runtime inventory and snapshot/restore workflows.
9. Secret, user, group, SSH key, and service-account administration.
10. Documentation freshness, runbook coverage, and ADR/release-note indexing.

## Suggested Crew Ownership

- Sisko: incident board, risk register, approvals, policy exceptions, and
  operational reporting.
- Kira: storage health, physical device identity, power/UPS, thermal, and
  removable media workflows.
- O'Brien: package inventory, patch compliance, update execution, rollback,
  maintenance windows, service actions, and config drift.
- Odo: security baseline, auth logs, firewall diff/provenance, vulnerability
  findings, incidents, secrets exposure, and containment workflows.
- Quark: provider quotas, cost tracking, usage forecasting, and continuation
  scheduling.
- Dax: VM/container/emulator inventory, snapshots, port pools, gateway routes,
  proxy ownership, and conflict simulation.
- Julian: host resources, service detail health, log evidence, latency/error
  trends, dependency health, and post-change validation.
- Ezri: runbook coverage, document freshness, ADR index, release/changelog
  index, and knowledge capture quality.

## Conclusion

Overseer already covers the central coordination loop: discover, register,
claim, plan, approve, execute, monitor, document, and audit. The largest gaps
are not basic coordination gaps. They are depth gaps: service detail, incident
lifecycle, host metrics, patch compliance, security baseline drift, storage and
backup operations, identity/secret administration, and richer evidence views for
approvals.

The next UI expansion should add drilldown pages and evidence panels for these
areas rather than adding more summary cards. Operators need enough linked
evidence to decide whether Sisko can approve automatically, whether human
approval is required, or whether a crew member must revise the plan.

## Implementation Pass 1

The first gap-coverage pass added a read-only aggregate endpoint and dashboard
panels for every gap category in this assessment. The implemented surface is:

```text
/Overseer/operations/gap-coverage
```

Visible UI panels now include Incident Board, Risk Register, Operations
Coverage, Change Calendar, Patch And Software Inventory, Compliance And Drift,
Storage And Backup, Physical Lifecycle, Virtual Runtime Inventory, Security
Baseline Drift, Identity And Secrets, Network Gateway Analysis, Host Resources,
Log Evidence, Service Details, Service Actions, Observability And Performance,
Cost And Forecast Coverage, and Documentation Coverage.

This closes category visibility for the gap list. Remaining work is deeper
workflow implementation: incident state transitions, service detail drilldowns,
maintenance schedule editing, package provenance and CVE correlation, firewall
diff/provenance, backup and restore jobs, VM/container runtime adapters, trend
storage, desired-state drift detection, document freshness, and identity/secret
rotation workflows.

## Implementation Pass 2

The second pass added durable operation workflow staging for every major gap
category. Sisko and the owner crew can now create records from best-practice
templates, move them through lifecycle states, and preserve transition history
without mutating the host.

Implemented API and UI surfaces:

```text
/Overseer/operations/workflows
/Overseer/operations/workflows/stage
/Overseer/operations/records
/Overseer/operations/records/transition
```

The workflow templates cover incident lifecycle, maintenance windows, service
detail reviews, security baseline drift, storage backup and recovery, virtual
runtime inventory, usage cost forecasting, documentation freshness, and
identity/access review. This gives the crew a consistent way to stage work to
the last safe point before an approval-gated live action.

Remaining work after this pass is specialized evidence collection and live
adapter execution: journal excerpts, dependency graphs, CVE feeds, firewall
ruleset provenance, SMART details, backup execution/restore tests, VM/container
snapshot execution, metric trend storage, baseline drift engines, and secret
rotation execution. Those areas touch external tools or live host state and
should continue through the existing Admin, Security, Claims, Health, and
approval gates.

## Implementation Pass 3

The third pass added specialized read-only evidence adapters and UI panels for
the remaining gap areas that can be handled before live execution approval:

- Julian: `/Overseer/health/service-evidence`
- Odo: `/Overseer/security/evidence` and `/Overseer/identity/evidence`
- Kira: `/Overseer/storage/evidence`
- Dax: `/Overseer/virtual/evidence`
- Quark: `/Overseer/usage/evidence`
- O'Brien: `/Overseer/maintenance/software-evidence`
- O'Brien: `/Overseer/maintenance/schedules`
- Sisko: `/Overseer/compliance/evidence`
- Ezri: `/Overseer/documents/evidence`

These adapters are read-only and return `host_mutation_performed: false`. They
give approval decisions direct supporting evidence without running package
updates, changing services, touching firewall rules, rotating credentials,
deleting backups, or mutating VMs/containers.

Implementation Pass 4 added durable maintenance schedules with recurring
windows, blackout notes, rollback expectations, validation requirements, owner,
risk, and status. This replaces the earlier crew-message fallback for adjusting
service schedules.

Implementation Pass 5 added incident lifecycle and post-incident checklist
views, observability trend summaries from retained evidence, bounded
`journalctl --user` excerpts for service units, system-journal access request
staging, SMART health availability,
runtime adapter availability, firewall desired-policy diff rows, patch metadata
age, local release-note references, and desired-state drift rows.

Implementation Pass 6 added CVE/advisory feed integration for O'Brien through
`/Overseer/maintenance/advisories` and
`/Overseer/maintenance/advisories/refresh`. Dashboard reads use the local cache;
refresh actions can fetch NVD CVE API 2.0 and Debian Security Tracker JSON
records into ignored state without changing host packages.

Implementation Pass 7 added Dax virtual runtime records, staged virtual
snapshot requests, staged virtual restore requests, Julian metric history
snapshots, read-only performance regression history from local artifacts, and
Odo identity/secret rotation request staging. These write or read ignored local
state only and do not mutate live virtual assets, credentials, accounts, or
privileged host resources.

Implementation Pass 8 added Sisko desired-state drift comparison and Julian
service dependency graph depth. Desired-state checks compare safe project-local
baselines such as required files, required directories, `.gitignore` guards, and
JSON validity without reading secrets or mutating host state. Service evidence
now includes dependency graph nodes, edges, dependency ownership, risk, health,
missing dependency rows, and next-step guidance before service changes.

Implementation Pass 9 added Quark queued-demand exhaustion forecasting. Usage
evidence now compares queued continuation demand against remaining capacity and
reset times, reports deficit units, flags missing limit records, and gives
dispatch, hold, or reset-recording guidance without spending quota or calling
external providers.

Remaining gaps now require either live adapters, elevated access, long-running
persistence, or environment-specific policy wiring: approved privileged/system
journal content capture after staged requests, approved firewall execution after
IDS review and human approval, approved live backup execution, approved restore
execution, VM/container live adapter inventory and snapshot/restore execution,
deep performance charts, and secret/service-account rotation execution.
