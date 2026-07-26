# Operations Gap Coverage

This runbook documents the implementation passes from Ezri's sysops task gap
analysis into the Overseer UI. The current implementation is intentionally
read-only or staged: it gives operators visibility, evidence pointers,
lifecycle records, and decision surfaces without making live host changes.

## API

Protected endpoint:

```text
/Overseer/operations/gap-coverage
/Overseer/operations/workflows
/Overseer/operations/workflows/stage
/Overseer/operations/records
/Overseer/operations/records/transition
/Overseer/health/service-evidence
/Overseer/security/evidence
/Overseer/storage/evidence
/Overseer/virtual/evidence
/Overseer/documents/evidence
/Overseer/usage/evidence
/Overseer/identity/evidence
/Overseer/identity/rotation-requests
/Overseer/maintenance/software-evidence
/Overseer/maintenance/advisories
/Overseer/maintenance/schedules
/Overseer/compliance/evidence
/Overseer/incidents/lifecycle
/Overseer/observability/trends
/Overseer/observability/metric-history
/Overseer/observability/performance-history
```

The endpoint aggregates:

- incident board rows.
- risk register rows.
- change calendar rows.
- service detail and service action rows.
- redacted log evidence rows.
- host resource metrics.
- software inventory summary.
- security baseline drift rows.
- network and gateway analysis.
- storage and backup summary.
- physical lifecycle rows.
- virtual runtime rows.
- observability and performance rows plus durable metric history snapshots and
  regression performance history.
- usage cost and forecast rows.
- compliance and drift rows.
- documentation coverage summary.
- identity and secret access summary plus staged rotation requests.

`/Overseer/operations/workflows` lists best-practice templates for the major
gap categories. `/Overseer/operations/workflows/stage` creates a durable staged
operation record from one of those templates. `/Overseer/operations/records`
creates or updates a specific record, and `/Overseer/operations/records/transition`
moves that record through its lifecycle while retaining transition history.

## Specialized Evidence Adapters

The third pass added read-only evidence depth for the remaining gap categories:

- Julian: service metadata, health evidence, redacted log snippets, bounded
  `journalctl --user` excerpts, dependency IDs, recent admin plans, trend
  history, post-change validation checklist, dependency graph and dependency
  health evidence, journal access status, staged system-journal access
  requests, and approved bounded system-journal capture with redacted local
  evidence artifacts.
- Odo: stored-snapshot firewall provenance, listener exposure evidence,
  firewall desired-policy diff, desired-policy enforcement staging with IDS
  review package preparation, protective plan provenance, identity/access review,
  SSH key custody hashes, secret-file custody markers, rotation reminders, and
  staged identity/secret rotation requests. Odo also has fixture-only firewall
  execution for approved firewall/source-block plans after IDS review, plan
  approval, and adapter enablement; the fixture persists execution/audit records
  and ignored local manifests without changing host firewall state.
- Kira: mount health, backup/restore markers, backup job registry, restore-test
  records, cleanup requests, capacity summary, and cleanup candidates, plus
  SMART health when `smartctl` is available without extra privileges.
- Dax: virtual runtime evidence, claim state, port-pool conflicts, snapshot
  readiness, runtime adapter availability, runtime state records, staged
  snapshot requests, staged restore requests, and cleanup evidence.
- Quark: quota evidence, exhaustion status, continuation queue, allocation by
  owner thread, and queued-demand exhaustion forecast with reset guidance.
- O'Brien: package-manager availability, apt provenance, held packages, and
  patch readiness checks, plus durable maintenance schedule records with
  blackout, rollback, validation fields, patch metadata age, local release
  note references, and cached CVE/advisory correlation from NVD and Debian
  Security Tracker feeds.
- Sisko: policy exceptions, desired-state baselines, local-secret guard checks,
  read-only desired-state drift comparison, compliance evidence matrix,
  incident lifecycle, and post-incident checklist.
- Ezri: runbook coverage, documented workflow index, stale-doc candidates, ADR
  index, and release/changelog index.

## UI Surfaces

- Overview: Incident Board, Risk Register, Operations Coverage, Stage
  Operations Workflow, Record Operation, Transition Operation, Operation
  Records, Incident Lifecycle, Incident Sources, and Post Incident Checklist.
- Admin: Change Calendar, Patch And Software Inventory, Package Manager
  Evidence, Package Provenance, Release Note References, Advisory Refresh,
  Advisory Feed Status, Advisory Sources, Advisory Package Summary, Advisory
  Severity, Advisory Findings, Patch Readiness, Compliance And Drift, Policy
  Exceptions, Desired State Baselines, Desired State Drift, Local Secret Guards,
  Compliance Evidence Matrix, Maintenance Schedule, and Maintenance Schedules.
- Assets: Storage And Backup, Mount Health, SMART Health, Backup Markers,
  Backup Jobs, Restore Tests, Backup Cleanup Requests, approved cleanup
  execution with local manifests, Storage Cleanup Candidates, Capacity
  Summary, and Physical Lifecycle.
- Claims: Virtual Runtime Evidence, Virtual Runtime Records, Virtual Snapshot
  Requests, Virtual Restore Requests, Port Pool Evidence, Virtual Cleanup
  Evidence, Runtime Adapter Availability, and Virtual Runtime Inventory.
- Security: Security Baseline Drift, Identity And Secrets, Network Gateway
  Analysis, Security Baseline Checks, Firewall Provenance, Firewall Policy
  Diff, Firewall Policy Enforcement, Listener Exposure Evidence, Protective
  Plan Provenance, Identity Access Review, SSH Key Custody, Secret File Custody,
  Rotation Reminders, and Identity Rotation Requests.
- Health: Host Resources, Log Evidence, Service Details, Service Actions,
  Service Evidence, Service Dependency Nodes, Service Dependency Edges, Service
  Validation Checklist, Redacted Service Logs, Journal Excerpts, Journal Access
  Status, System Journal Requests,
  Observability And Performance, Health Trend History, Metric History
  Snapshots, Performance Regression History, and Host Snapshot Trend.
- Usage: Quota Evidence, Exhaustion Forecast, Continuation Queue Evidence, Usage
  Allocation By Thread, and Cost And Forecast Coverage.
- Documents: Documentation Coverage, Runbook Coverage, Workflow Coverage, Stale
  Document Candidates, ADR Index, and Release Index.

## Approval Boundary

The new surfaces do not execute package updates, service changes, firewall
changes, account changes, secret rotation, backup deletion, VM/container
mutation, or remote-access changes. When a row requires action, the operator
should stage the work through the existing Admin, Security, Claims, Usage, or
crew-channel workflow so Sisko can apply policy and approval gates.

## Remaining Depth Work

The current passes cover every gap category with a visible surface, durable
workflow record, read-only evidence adapter, incident lifecycle, trend summary,
schedule editor, and advisory feed correlation. The remaining work requires
live adapter execution, elevated access, long-running persistence, or
environment-specific policy wiring:

- deeper privileged/system journal capture policy for any future sudo, group,
  or daemon-privilege escalation. The current runner handles only approved
  bounded reads available to the running Overseer process.
- live firewall desired-policy execution after IDS review and human approval.
  Fixture-only execution now verifies the approval path without mutating host
  firewall state.
- approved live backup execution and restore execution.
- VM/container/emulator live adapter depth beyond approved disposable targets:
  running-domain snapshot policy, non-disposable destroy policy, and broader
  host-specific inventory enrichment. Dax now supports approved disposable
  lifecycle actions plus provider snapshot/restore/destroy for local fixtures,
  stopped qcow2 images, stopped qemu/libvirt image targets, containers,
  file-backed Renode/proxy targets, and approved disposable Android AVD
  directories, with read-only provider-depth, capacity, and image provenance
  evidence.
- container image vulnerability scanner installation is still a package-source
  setup gate when Trivy is absent, but Dax now has staged, approved, read-only
  scan requests and summarized scan results.
- secret rotation execution and service-account change execution.

## Tests

Run:

```bash
python3 -m pytest -q tests/test_operations_gap_coverage.py
```

Include this file in the full regression package after any change to the gap
coverage endpoint, UI panels, or sysops task inventory.
