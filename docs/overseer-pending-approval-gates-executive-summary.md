# Overseer Pending Approval Gates — Executive Summary

**Prepared:** 2026-07-28  
**Source of truth:** Live Overseer store at the time of review  
**Purpose:** Consolidate current approval decisions into one operator-facing
decision sheet. Completing this document records intent only; it does not update
the Overseer store or execute any change.

## Executive overview

Six distinct decisions are pending:

| Priority | Area | Decision | Current gate |
|---|---|---|---|
| Critical | Host firewall, TCP/22 | Source-scoped SSH access policy | IDS advisory result required before human approval |
| Critical | Host firewall, TCP/9443 | Source-scoped protected-service policy | IDS advisory result required before human approval |
| High | Penpot | Accept residual image vulnerabilities for the combined update | Human risk acceptance |
| High | Package maintenance | Upgrade `libtiff6` using one of two duplicate plans | Sisko approval; duplicate must be resolved |
| Medium | Protected gateway | Allow Dax/MSI authentication smoke-test claim | Dax role approval |

Recommended order:

1. Resolve the duplicate `libtiff6` plans by selecting at most one.
2. Decide whether to accept the Penpot residual risk after confirming the backup
   thread has completed the required backup evidence.
3. Approve or retire the old protected-gateway smoke-test claim.
4. Do not approve either firewall plan until Intrusion Detection returns an
   accepted advisory result.

No additional pending adapter-enablement, archive, claim-cleanup,
daemon-migration, restore, virtual-operation, image-scan, or backup-operation
approval records were found. Backup implementation work is owned by the other
thread and was not changed during this review.

## Decision 1 — `libtiff6` security upgrade

**Risk:** High  
**Owner:** O'Brien; Sisko approval required  
**Change:** Upgrade `libtiff6` from `4.7.0-3+deb13u2` to
`4.7.0-3+deb13u3` from stable-security. The approved path simulates the upgrade,
runs an `apt-get --only-upgrade`, and verifies the installed package version.

Two equivalent active plans exist:

- `admin.apt.upgrade.package-inspection-2026-07-20t17-42-23-00-00`
- `admin.apt.upgrade.package-inspection-2026-07-20t18-59-57-00-00`

**Recommendation:** Do not approve both. Prefer the newer plan only if a fresh
package inspection confirms that its version and command list are still current;
otherwise cancel both and restage from current package metadata.

### Operator selection

Select exactly one:

- [ ] Approve the newer plan and cancel/supersede the older duplicate.
- [ ] Approve the older plan and cancel/supersede the newer duplicate.
- [X] Cancel both and stage a fresh package inspection.
- [ ] Defer until a named maintenance window: ______________________________
- [ ] Hold `libtiff6` and record an exception.

Approval or cancellation reason:
recommended plan is approved
> 

Approved/selected by: Chris 
Decision date: 7-28-26  
Signature or explicit approval statement:
Approved

> 

## Decision 2 — Penpot combined image risk reduction

**Risk:** High  
**Plan:** `admin.compose.penpot.combined-risk-reduction.20260726`  
**Pending approval:**
`approval.admin.policy.warning.admin.compose.penpot.combined-risk-reduction.20260726.admin.scan.residual-findings`

The combined Docker Compose plan is already approved, but execution remains
blocked on explicit human acceptance of residual vulnerability findings. The
declared combined findings are 4 critical and 55 high:

- frontend: 5 high
- backend: 16 high
- exporter: 2 critical and 10 high
- MCP: 2 critical and 10 high
- PostgreSQL: 1 critical and 14 high

The planned state combines Penpot application version 2.17 with
`postgres:15-alpine`. Execution includes a Compose restart and must retain
backup, rollback, and post-start verification evidence.

### Operator selection

Select one:

- [X] Accept `admin.scan.residual-findings` and allow the already-approved
  combined plan to proceed after backup readiness is confirmed.
- [ ] Defer pending newer image scans or upstream remediations.
- [ ] Cancel the combined plan and retain the current deployment.
- [ ] Request a revised plan with these constraints:

> 

I explicitly acknowledge that this is risk reduction, not a clean vulnerability
remediation:

- [X] Yes
- [ ] No

Approved/selected by: Chris  
Decision date: 7-28-26  
Signature or explicit approval statement:
Approved
> 

## Decision 3 — Protected-gateway authentication smoke test

**Risk:** Medium  
**Claim:** `claim.crew.dax.protected-gateway-auth-smoke-testing.20260720212548`  
**Approval:**
`approval.claim.crew.dax.protected-gateway-auth-smoke-testing.20260720212548`

The requested Dax lease would allow an MSI agent to perform authentication smoke
testing against the protected Overseer gateway and collect redacted evidence.
The record is old, has no expiry or release condition, and declares no mutation.

**Recommendation:** Approve only if the test is still needed and first add a
bounded expiry and release condition. Otherwise retire the stale request.

### Operator selection

Select one:

- [X] Approve the claim after adding an expiry and release condition.
- [ ] Defer while confirming whether the MSI test is still required.
- [ ] Retire/supersede the stale claim.

Required expiry: follow recomended guidlines  
Required release condition: follow recomended guidlines

> 

Approved/selected by: Chris  
Decision date: 7-28-26  
Signature or explicit approval statement:
Approved
> 

## Decision 4 — TCP/22 SSH firewall policy

**Risk:** Critical  
**Plan:** `admin.host-security.deny-tcp.22`  
**Current state:** SSH listens on all IPv4 and IPv6 interfaces.  
**Proposed state:** Allow `192.168.68.115/32`; reject and rate-limit-log other
inbound IPv4 and IPv6 sources through firewalld.

**Hard gate:** The IDS package
`ids-review.admin.host-security.deny-tcp.22` is submitted but has no advisory
result. Human approval is not valid until Intrusion Detection accepts the exact
plan.

### Operator selection — current stage

Select one:

- [X] Await the Intrusion Detection advisory result. **Recommended current
  choice.**
- [ ] Request a revision to the intended-source list or logging policy.
- [ ] Cancel the plan and leave the listener reachable while investigation
  continues.
- [ ] Cancel the firewall plan and instead prepare a plan to bind or stop SSH.

Requested revision, trusted-source correction, or cancellation reason:
Force the IDS to proceed with the advisory.  If it doesn't remediation of the system is needed to prevent stuck workflows
> 

Future approval after an accepted IDS advisory:

- [ ] Approve the exact IDS-accepted plan.
- [ ] Do not approve; request another revision.
- [X] Approve the advisory review being forced or workflow revision if stuck

Approved/selected by: Chris
Decision date: 7-28-26  
IDS advisory evidence ID: _______________  
Signature or explicit approval statement:
Approved
> 

## Decision 5 — TCP/9443 protected-service firewall policy

**Risk:** Critical  
**Plan:** `admin.host-security.deny-tcp.9443`  
**Current state:** A service listens on `10.50.0.100:9443`.  
**Proposed state:** Allow `10.70.0.10/32`, `10.70.0.11/32`, and
`10.70.0.12/32`; reject and rate-limit-log all other inbound IPv4 and IPv6
sources through firewalld.

**Hard gate:** The IDS package
`ids-review.admin.host-security.deny-tcp.9443` is submitted but has no advisory
result. Human approval is not valid until Intrusion Detection accepts the exact
plan.

### Operator selection — current stage

Select one:

- [X] Await the Intrusion Detection advisory result. **Recommended current
  choice.**
- [ ] Request a revision to the intended-source list or logging policy.
- [ ] Cancel the plan and leave the listener reachable while investigation
  continues.
- [ ] Cancel the firewall plan and instead prepare a plan to bind or stop the
  service.

Requested revision, trusted-source correction, or cancellation reason:
Force the IDS to proceed with the advisory.  If it doesn't remediation of the system is needed to prevent stuck workflows

> 

Future approval after an accepted IDS advisory:

- [ ] Approve the exact IDS-accepted plan.
- [ ] Do not approve; request another revision.
- [X] Approve the advisory review being forced or workflow revision if stuck

Approved/selected by: Chris
Decision date: 7-28-26  
IDS advisory evidence ID: _______________  
Signature or explicit approval statement:
Approved
> 

## Standing gate — remote GUI control

This is not a queued approval record, but it is a standing human gate worth
keeping visible. Every activation or use of the remote GUI channel requires
explicit approval for the named workflow.

For a future request, select one:

- [ ] Approve remote GUI control only for this workflow:

> 

- [ ] Require a direct CLI, API, or MCP path instead.
- [ ] Reject remote GUI control.

Expiration or stop condition: _______________________________________________

## Final authorization

Completing checkboxes above does not itself mutate Overseer. After completing
this sheet, return it with an explicit instruction identifying which selected
decisions should be recorded in the live store. Approval recording and execution
remain separate actions.

Overall operator name: Chris 
Review date: 7-28-26

- [ ] Record only the selected approval decisions; do not execute changes.
- [ ] Record selected approvals and present a separate execution plan.
- [ ] Make no live-state changes; retain this document as a draft.

Final instruction:
record the decisions and begin development

> 

## Evidence used

- Live `approvals-summary --status pending`
- Live `authorizations-required`
- Live `admin-summary`, `admin-execution-readiness`, and `claim-review`
- Live IDS review package summary and advisory prompt artifacts
- `docs/penpot-safer-image-depth.md`
- `docs/security/remote-gui-control-plan.md`
- MCP calculator validation for distinct-item and Penpot finding totals

