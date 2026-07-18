# Command and Safety Model

This document defines Sisko's command workflow for Overseer. It is the shared contract for resource ownership, conflict handling, approvals, auditability, and cross-domain handoffs.

## Core Principles

- Overseer records intent before action.
- Shared resources require explicit ownership through a checkout, lock, or lease.
- High-risk actions require approval before execution.
- Every state transition records evidence or a reason.
- A resource is not available again until its release condition is satisfied.
- Human operator decisions override automation when risk or ownership is unclear.

## Resource Model

A resource is any local service, device, endpoint, virtual asset, quota-bound service, maintenance target, or security-sensitive surface that multiple projects or threads may need.

Required fields:

- `id`: stable local identifier, unique inside Overseer.
- `name`: human-readable label.
- `type`: one of `physical_asset`, `virtual_asset`, `service`, `usage_limited_service`, `maintenance_target`, `security_surface`, or `composite`.
- `owner_domain`: responsible role, such as `kira`, `dax`, `julian`, `obrien`, `odo`, `quark`, or `sisko`.
- `risk_level`: `low`, `medium`, `high`, or `critical`.
- `state`: `available`, `checked_out`, `locked`, `maintenance`, `degraded`, `incident`, `quarantined`, or `retired`.
- `identifiers`: structured identity details for the resource type.
- `dependencies`: other resource IDs that must be considered before checkout.
- `current_claim_id`: active claim when the resource is not freely available.
- `last_verified_at`: timestamp of the last identity or health check.
- `notes`: operator-facing context that is safe to persist.

Resource-specific identity examples:

- Physical assets: USB path, serial path, VID/PID, serial number, device role, power sensitivity.
- Virtual assets: VM name, emulator profile, proxy name, gateway name, bound ports, network segment.
- Services: service name, systemd unit, local URL, health endpoint, process identity.
- Usage-limited services: quota type, limit window, renewal time, remaining capacity source.
- Security surfaces: firewall, gateway, IDS sensor, credential boundary, exposed service.

## Claim Model

A claim records temporary control of a resource.

Claim types:

- `checkout`: exclusive use for planned work.
- `lock`: short critical section that blocks conflicting changes.
- `lease`: time-bound ownership that can expire or renew.
- `hold`: reservation for scheduled future work.
- `quarantine`: protective hold created by security or health concerns.

Required fields:

- `id`: stable claim identifier.
- `resource_id`: claimed resource.
- `claim_type`: checkout, lock, lease, hold, or quarantine.
- `owner_thread`: requesting project thread or process.
- `owner_role`: responsible Overseer role.
- `intent`: concise reason for the claim.
- `requested_action`: planned action or protected state.
- `risk_level`: expected blast radius of the claim.
- `status`: `requested`, `approved`, `active`, `blocked`, `queued`, `releasing`, `released`, `expired`, or `revoked`.
- `created_at`: request timestamp.
- `starts_at`: planned or actual start.
- `expires_at`: lease or hold expiration, when applicable.
- `release_condition`: objective condition that makes the resource available again.
- `approval_id`: approval record when required.
- `evidence_ids`: related audit or health evidence.

## Ownership Rules

- A resource can have only one active exclusive claim.
- A resource can have multiple read-only observation claims if they do not change state.
- Claims on a composite resource also affect its dependencies.
- A higher-risk claim can preempt a lower-risk queued claim only with Sisko approval.
- Security quarantine blocks all non-security work until Odo or Sisko releases it.
- Expired leases do not automatically permit risky reuse; they become operator-review items.

## Conflict Resolution

When a new claim conflicts with an active claim, Overseer chooses one of these outcomes:

- `allow`: no conflict or read-only compatible use.
- `queue`: compatible but must wait for current release condition.
- `block`: incompatible or unsafe.
- `escalate`: requires Sisko or human decision.
- `quarantine`: security or health evidence indicates protective isolation.

Conflict checks must consider:

- direct resource identity,
- dependencies,
- owner domain,
- risk level,
- requested action,
- active incidents,
- maintenance windows,
- usage-limit windows,
- security posture,
- release conditions.

Default decisions:

- Write/write conflicts block.
- Maintenance/change conflicts block unless part of the same approved maintenance plan.
- Security incidents quarantine affected resources.
- Usage-limited work queues until Quark confirms capacity or renewal.
- Health-degraded services block risky changes until Julian confirms baseline evidence.
- Virtual topology changes block overlapping gateway, proxy, emulator, or VM claims.
- Physical-device use blocks other physical access until Kira confirms release.

## Approval Gates

Approvals are required when a requested action can change a privileged, shared, fragile, or externally visible state.

Approval levels:

- `none`: safe read-only observation.
- `role`: owner role approval is enough.
- `sisko`: cross-domain or high-risk approval.
- `human`: explicit operator approval required.

Human approval is required for:

- network, gateway, firewall, proxy, routing, or exposed-service changes,
- software installs, updates, or patch deployment,
- service restarts that can interrupt active work,
- security protective actions that alter access or availability,
- hardware flashing or hardware-affecting actions,
- credential, secret, permission, or privilege-boundary changes,
- deletion of remote repositories or durable state.

Approval records must include:

- `id`,
- `requested_by`,
- `approver`,
- `approval_level`,
- `scope`,
- `risk_summary`,
- `allowed_actions`,
- `expires_at`,
- `decision`: approved, denied, or revoked,
- `decision_reason`,
- `created_at`,
- `decided_at`.

## Audit Log

Every command decision and resource state transition writes an audit entry.

Required fields:

- `id`: stable audit entry identifier.
- `timestamp`: event time.
- `actor`: human, thread, or Overseer role.
- `action`: requested or completed action.
- `resource_id`: affected resource.
- `claim_id`: related claim, if any.
- `approval_id`: related approval, if any.
- `previous_state`: state before action.
- `new_state`: state after action.
- `result`: succeeded, failed, blocked, queued, approved, denied, or escalated.
- `reason`: concise why.
- `evidence`: references to health checks, commands, files, logs, or operator notes.

Audit entries must not store secrets, credentials, raw tokens, private keys, or personal exports.

## Health Evidence

Health evidence is Julian's primary handoff format and can be attached to claims, approvals, or audit entries.

Required fields:

- `id`,
- `resource_id`,
- `probe_type`: command, HTTP, HTTPS, MCP, file, process, log, or manual.
- `target`: exact command, endpoint, path, service, or process tested.
- `observed_status`: healthy, degraded, failed, unknown, or recovered.
- `observed_error`: exact error or empty if healthy.
- `captured_at`,
- `captured_by`,
- `owner_domain`,
- `recovery_required`: true or false.

Evidence should be specific enough for another thread to reproduce the check.

## Release Conditions

A release condition is the objective rule for making a claimed resource available again.

Common release conditions:

- work completed and post-check passed,
- maintenance rollback completed,
- health recovered,
- security quarantine cleared,
- usage limit renewed,
- operator released manually,
- lease expired and operator reviewed,
- dependent resource released.

Release must record:

- who released the resource,
- why it is safe to release,
- final resource state,
- evidence IDs,
- follow-up risk if any.

## Cross-Domain Handoffs

Sisko owns handoffs when a claim crosses domains.

Default handoff map:

- Physical identity or device availability: Kira.
- Virtual topology or emulator/VM/gateway/proxy conflicts: Dax.
- Service health, endpoint failures, or recovery evidence: Julian.
- Installs, patches, restarts, and maintenance windows: O'Brien.
- Security events, audits, intrusion signals, and active defense: Odo.
- Quotas, renewal windows, rate limits, and continuation timing: Quark.
- Documentation, runbooks, and durable handoff notes: Ezri.

A handoff must include the resource ID, claim ID, current state, requested decision, risk level, and evidence links.

## Initial State Machine

Resource states:

```text
available -> requested -> checked_out -> releasing -> available
available -> locked -> releasing -> available
available -> maintenance -> releasing -> available
available -> degraded -> maintenance|incident|available
available -> incident -> quarantined|maintenance|available
quarantined -> releasing -> available
```

Claim states:

```text
requested -> approved -> active -> releasing -> released
requested -> blocked
requested -> queued -> approved -> active
active -> expired -> released|revoked|approved
active -> revoked
```

## First Implementation Slice

The first implementation should prove this loop:

1. Register a resource.
2. Request a checkout.
3. Detect whether the checkout conflicts.
4. Require approval when the risk level demands it.
5. Activate a claim.
6. Attach audit and health evidence.
7. Release the claim only when the release condition is satisfied.

This slice should support at least one resource from each core domain: physical asset, virtual asset, service health target, maintenance target, usage-limited service, and security surface.
