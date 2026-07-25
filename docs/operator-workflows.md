# Operator Workflows

This runbook maps Overseer's operator dashboard to task workflows. Use Ezri's
Documents page as the index: choose a workflow row, then use the filled search,
folder, and note path fields to find this source.

## General Pattern

1. Start on Overview and check the command crew metrics.
2. Open the crew page that owns the issue.
3. Read the summary cards, tables, recent requests, and blocked dispatches.
4. Use row links to fill the relevant form fields.
5. Stage work as far as the UI allows.
6. Approve only when the page shows the approval surface and the evidence is
   sufficient.
7. Use Audit to verify what happened.

Do not paste secrets, tokens, cookies, raw browser storage, local database
exports, or unrelated personal data into notes or crew messages.

## Overview

### Review Command Status

Use this to decide where attention is needed.

1. Open Overview.
2. Review Sisko, Odo, Julian, O'Brien, Runtime, Crew Queue, and Dispatch Blocks.
3. Click a metric or crew card to drill into the source page.
4. If the crew queue is high, click Dispatch Open.
5. If dispatch blocks remain, open Audit and review Recent Crew Dispatches.

### Dispatch Open Crew Requests

Use this when crew messages are waiting for their owner.

1. Open Overview.
2. Review Command Crew and Recent Crew Dispatches.
3. Click Dispatch Open.
4. Open the owner page for any blocked dispatch.
5. Read the Blocked Reasons table before sending more instructions.

### Record An Operations Workflow

Use this when a sysops/devops/admin task needs durable tracking but does not
yet have a specialized workflow editor.

1. Open Overview.
2. Review Incident Board, Risk Register, and Operations Coverage.
3. In Record Operation, choose the Kind, Owner, Status, and Severity.
4. Fill Subject, Summary, Next Step, and optional Resource or Evidence IDs.
5. Use Metadata only for non-secret structured details.
6. Click Record.
7. Verify the row appears in Operation Records and Audit if follow-up work is
   needed.

### Stage A Gap Workflow From A Template

Use this when Ezri's gap analysis identifies a missing deep workflow and the
crew should start tracking it immediately.

1. Open Overview.
2. Review Operations Coverage and Workflow Templates.
3. Click the template row that matches the work area.
4. Fill optional Record ID or Resource if the default is too broad.
5. Keep Requested By as `sisko` unless a human approval level is required.
6. Click Stage Workflow.
7. Verify the new record appears in Operation Records with status `staged`.

### Transition An Operations Record

Use this when a staged operations item has moved through triage, execution
planning, approval waiting, verification, or closure.

1. Open Overview.
2. Select the Operation Records row.
3. Choose the new status in Transition Operation.
4. Update Next Step to the last remaining safe action.
5. Add a short non-secret Note that explains the evidence reviewed.
6. Click Transition.
7. Confirm the record status and transition history update.

### Send A Crew Request

Use this when the right action is investigation or planning, not direct
execution.

1. Open the page owned by the responsible crew member.
2. Find that crew member's Channel panel.
3. Fill Subject, Priority, By, and any Resource, Plan, or Limit reference.
4. Write the issue as the desired outcome plus known evidence.
5. Click Send Request.
6. Click Dispatch Open or wait for Sisko dispatch.

## Admin: Sisko And O'Brien

### Approve A Pending Admin Request

Use this when an admin plan is staged and waiting for approval.

1. Open Admin.
2. Review Approval Decisions and Execution Readiness.
3. Click the plan id from a table when available; it fills the approval fields.
4. Confirm the kind, target, reason, readiness state, and policy evidence.
5. Fill Approved By with `sisko` unless a human approval level is required.
6. Click Approve.
7. Do not click Execute until readiness shows the plan can execute.

### Request Changes For A Plan

Use this when a plan is wrong, incomplete, or lacks evidence.

1. Open Admin.
2. Select the plan from Approval Decisions or Execution Readiness.
3. Fill Cancel Plan, Canceled By, and Cancel Reason.
4. State the specific revision required.
5. Click Cancel.
6. Send an O'Brien or owner crew request if a replacement plan is needed.

### Plan A Service Restart Or Admin Change

Use this for service restarts, package work, firewall work, or other admin
changes.

1. Open Admin.
2. In Plan Admin Change, choose Kind.
3. Fill Target, Reason, Current State, and Package or Port when relevant.
4. Click Plan Change.
5. Review policy and readiness output.
6. Approve and execute only through the separate approval and execution panels.

### Execute An Approved Admin Plan

Use this after a plan is approved and readiness says it can run.

1. Open Admin.
2. Review Execution Readiness.
3. Fill Execute Plan with the plan id.
4. Confirm the approval id is present where required.
5. Click Execute.
6. Open Audit and Admin Executions afterward to confirm outcome.

### Plan Package Updates

Use this to keep packages up to date without applying changes blindly.

1. Open Admin.
2. Review Upgradable Packages.
3. Click Plan Updates when you want to stage plans for review without running
   live package commands.
4. Review generated plans, rollback notes, and readiness.

### Run Package Maintenance Cycle

Use this when O'Brien should keep apt-managed system packages current through
the approved live maintenance path.

1. Open Admin.
2. Review Upgradable Packages, Advisory Feed Status, and Admin Readiness.
3. Click Run Package Cycle.
4. O'Brien refreshes apt metadata, inspects refreshed package state, stages
   detected upgrades, records approved apt adapter enablement for the store,
   advances Sisko-level approvals, and executes only plans that pass policy.
5. Open Admin Executions and Audit to confirm completed, blocked, or failed
   evidence.
6. If the cycle blocks or fails, review readiness, policy, rollback, and
   execution evidence before retrying.

### Refresh CVE Advisory Feeds

Use this before approving package updates or when O'Brien needs current
vulnerability context for tracked packages.

1. Open Admin.
2. Review Advisory Feed Status, Advisory Package Summary, and Advisory Findings.
3. In Advisory Refresh, set Packages to the Debian package names to check.
4. Choose NVD for general CVE keyword coverage, Debian for Debian Security
   Tracker package impact, or Both when the package needs both views.
5. Set Max Results low enough to keep the panel focused.
6. Use Dry Run to verify the refresh request shape without network access or
   cache writes.
7. Click Refresh Advisories.
8. Review Advisory Findings and open source links before approving package
   update plans.

### Discover User Services

Use this to refresh service inventory before maintenance or diagnostics.

1. Open Admin.
2. Click Discover Services.
3. Review generated service resources and readiness.
4. If a service is unknown or suspicious, send it to Odo for review.
5. If a service is unhealthy, open Health and hand it to Julian.

### Enable A Live Adapter

Use this when a live adapter is needed for updates, installs, or host actions.

1. Open Admin.
2. Review Adapter Capabilities.
3. Select the adapter kind.
4. Click Request in Adapter Enablement.
5. Review the approval request before enabling anything live.

### Approve Adapter Enablement

Use this after the adapter request is reviewed.

1. Open Admin.
2. Fill Approval ID and Approved By.
3. Confirm the adapter scope is limited to the intended capability.
4. Click Approve.
5. Recheck Adapter Capabilities.

### Archive Or Restore Admin History

Use these workflows to manage old admin-plan records without losing audit
evidence.

1. Open Admin.
2. Review Archive Candidates or Archived Plans.
3. Request archive or restore.
4. Approve the request separately.
5. Run Archive or Restore only after approval.
6. Verify the result in Audit.

### Customize Policy Defaults

Use this after all non-policy development is complete or when site rules need
formal tuning.

1. Open Admin.
2. Review Policy Customization Helper.
3. Fill profile name and description.
4. Answer each policy question.
5. Click Build Profile.
6. Review generated policy before making it the operational default.

### Accept And Approve A Policy Warning

Use this only when a warning is understood and accepted.

1. Open Admin.
2. Fill Plan ID and Check ID.
3. Click Request.
4. Review the resulting pending approval.
5. Fill Approval ID and Approved By.
6. Click Approve.

### Adjust Service Schedule

Use this when O'Brien needs to record or adjust recurring maintenance windows,
blackouts, rollback expectations, and validation requirements.

1. Open Admin.
2. Review Change Calendar, Maintenance Schedules, Patch Readiness, and Service
   Evidence if a service is affected.
3. In Maintenance Schedule, fill Schedule ID, Target, Recurrence, Window,
   Timezone, Blackout, Validation, Rollback, Status, Owner, and Risk.
4. Keep Metadata limited to non-secret structured details.
5. Click Record Schedule.
6. Verify the row appears in Maintenance Schedules.
7. If the schedule affects usage limits, open Usage and create or review a
   continuation request.

## Assets: Kira And Dax

### Discover Physical Devices

1. Open Assets.
2. Click Discover Devices.
3. Review Physical Assets.
4. Click a resource id to prepare a claim if the device needs checkout.
5. Send unknown or unexpected devices to Odo.

### Discover Storage Arrays

1. Open Assets.
2. Click Discover Storage.
3. Review storage entries in Physical Assets.
4. Claim or register resources before work that changes storage state.

### Discover Listeners As Virtual Assets

1. Open Assets.
2. Click Discover Listeners.
3. Review Virtual Assets.
4. Open Claims for expected leases.
5. Open Security for unknown exposed listeners.

### Register A Managed Resource

1. Open Assets.
2. Fill Resource ID, Name, Type, Owner, Risk, and optional Identifiers.
3. Click Record Resource.
4. Open Claims if the resource needs checkout or lock control.

### Record A Backup Job

1. Open Assets.
2. Review Storage And Backup, Capacity Summary, and Backup Markers.
3. Fill Job ID, Target, Schedule, Retention, Risk, Status, Requested By, and
   optional Notes.
4. Click Record Job.
5. Verify the job appears in Backup Jobs.
6. Use Admin for any live backup execution plan; this registry does not copy or
   delete files.

### Record A Restore Test

1. Open Assets.
2. Review Backup Jobs and Backup Markers.
3. Fill Test ID, Job ID, Restore Point, Status, Validated By, and optional
   Notes.
4. Click Record Test.
5. Verify the result appears in Restore Tests.
6. Run actual restore verification only in an approved isolated target.

### Stage Backup Cleanup Request

1. Open Assets.
2. Review Storage Cleanup Candidates and Backup Cleanup Requests.
3. Fill Path, Requested By, and Reason.
4. Click Stage Request.
5. Review the generated Request ID and path before approval.

### Approve Backup Cleanup Request

1. Open Assets.
2. Review Backup Cleanup Requests.
3. Click the request row to fill Request ID and path details.
4. Confirm the target is project-relative and limited to generated artifacts or
   backups.
5. Fill Approved By.
6. Click Approve.

### Execute Backup Cleanup Request

1. Open Assets.
2. Review the approved Backup Cleanup Request.
3. Confirm the target is inside `artifacts/` or `backups/`.
4. Fill Executed By.
5. Click Execute.
6. Review Backup Cleanup Requests afterward for completed, blocked, or failed
   status and the generated cleanup manifest path.

CLI equivalent:

```bash
PYTHONPATH=src python3 -m overseer.cli stage-backup-cleanup --project-root . --path artifacts/old-run --requested-by kira
PYTHONPATH=src python3 -m overseer.cli approve-backup-cleanup --project-root . --request-id backup-cleanup.artifacts-old-run --approved-by kira
PYTHONPATH=src python3 -m overseer.cli execute-backup-cleanup --project-root . --request-id backup-cleanup.artifacts-old-run --executed-by kira
```

## Claims: Dax

### View VM Leases And Virtual Claims

1. Open Claims.
2. Review Active, Queued, Review, and Cleanup metrics.
3. Read the Claims table for resource id, status, type, and next step.
4. Click resource ids to populate claim fields.
5. Review Virtual Runtime Evidence, Runtime Records, Snapshot Requests,
   Restore Requests, and Execution Records for current Dax state.
6. Use Cleanup Candidates for stale or expired leases.

### Record Virtual Runtime State

1. Open Claims.
2. Review Virtual Runtime Evidence and Runtime Adapter Availability.
3. Fill Resource ID, Kind, State, Adapter, Ports, Snapshot Hint, and Notes.
4. Click Record Runtime.
5. Verify the row appears in Virtual Runtime Records.
6. Use this for observed state only; it does not start, stop, snapshot,
   restore, or delete virtual assets.

### Stage Virtual Snapshot Request

1. Open Claims.
2. Review claims, conflicts, runtime state, and adapter availability.
3. Click a runtime record or fill Resource ID, Snapshot Name, Requested By, and
   Reason.
4. Click Stage Snapshot.
5. Review the staged request row and confirm the next step.

### Approve Virtual Snapshot Request

1. Open Claims.
2. Review claims, runtime record, adapter, snapshot target, and staged
   snapshot request.
3. Click the staged snapshot request row to fill Request ID.
4. Fill Approved By.
5. Click Approve.
6. Confirm the request status changes to approved.

### Execute Virtual Snapshot Request

1. Open Claims.
2. Confirm the snapshot request is approved.
3. Fill Request ID, Executed By, and Provider.
4. Click Execute.
5. Review Virtual Execution Records and manifest path.
6. Real Docker, Podman, libvirt/QEMU, emulator, gateway, or proxy providers
   remain blocked until their live adapters and exact disposable targets are
   declared.

### Stage Virtual Restore Request

1. Open Claims.
2. Review claims, conflicts, runtime state, and the failed-state evidence that
   must be preserved before rollback.
3. Click a snapshot request or fill Resource ID, Restore Point, Requested By,
   and Reason.
4. Click Stage Restore.
5. Review the staged request row and confirm the next step.

### Approve Virtual Restore Request

1. Open Claims.
2. Review claims, runtime record, failed-state evidence, restore point, and
   staged restore request.
3. Click the staged restore request row to fill Request ID.
4. Fill Approved By.
5. Click Approve.
6. Confirm the request status changes to approved.

### Execute Virtual Restore Request

1. Open Claims.
2. Confirm the restore request is approved.
3. Fill Request ID, Executed By, and Provider.
4. Click Execute.
5. Review Virtual Execution Records and manifest path.
6. Have Julian validate service health before returning the runtime to service.
7. Real Docker, Podman, libvirt/QEMU, emulator, gateway, or proxy providers
   remain blocked until their live adapters and exact disposable targets are
   declared.

### Request A VM, Port, Gateway, Or Device Claim

1. Open Claims.
2. Fill Claim ID, Resource ID, Type, Thread, Owner, Risk, and Intent.
3. Add Port, Expiry, and Release Condition when relevant.
4. Click Request Claim.
5. Wait for approval before using exclusive resources.

### Approve A Resource Claim

1. Open Claims.
2. Review the claim and any conflicting active claim.
3. Fill Approval ID and Decided By.
4. Click Approve.
5. Activate only after approval.

### Activate An Approved Claim

1. Open Claims.
2. Fill Claim ID and optional Approval ID.
3. Click Activate.
4. Confirm the claim appears active.

### Release A Claim

1. Open Claims.
2. Fill Claim ID, Released By, and Reason.
3. Click Release.
4. Verify the resource is available or has the expected next step.

### Clean Up Stale Or Expired Claims

1. Open Claims.
2. Review Cleanup Candidates.
3. Fill Claim ID and Requested By.
4. Click Request.
5. Approve and Execute only after reviewing cleanup action and evidence.

## Security: Odo

### Inspect Host Security Posture

1. Open Security.
2. Click Inspect Host.
3. Review High, Warning, Listener Review Queue, Source Review Queue, and Plans.
4. Unknown usage should be sent to Odo through the channel.

### Stage Listener Remediation Plans

1. Open Security.
2. Review Listener Review Queue.
3. Click Plan Listener Queue.
4. Open Admin to review generated protective plans.
5. Approve only after evidence and policy gates are satisfied.

### Plan One Listener Remediation

1. Open Security.
2. Fill Listener, Action, Snapshot ID, Plan ID, and Reason.
3. Click Plan.
4. Review the generated plan in Admin before execution.

### Review A Remote Source

1. Open Security.
2. Fill Remote Address, Listener, Disposition, Snapshot ID, and Rationale.
3. Click Record.
4. If hostile, stage a block plan rather than editing firewall rules manually.

### Plan A Source Block

1. Open Security.
2. Fill Source Review ID, Action, optional Plan ID, and Reason.
3. Click Plan Block.
4. Open Admin for approval and execution readiness.

### Stage Firewall Policy Enforcement

Use this when `config/desired-firewall.json` contains a desired rule that should
be turned into an approval-bound firewall plan.

1. Open Security.
2. Review Firewall Provenance and Firewall Policy Diff.
3. Click the diff row for the exact desired rule; it fills Rule Index, Plan ID,
   and IDS plan fields.
4. Confirm the desired rule action and port match the intended policy.
5. Click Stage Enforcement.
6. Review the staged admin plan and prepared IDS review package.
7. Export or dispatch the IDS review package before requesting Sisko approval.
8. Do not apply, reload, or enforce firewall changes until human approval is
   present after IDS review.

### Stage Identity Rotation Request

Use this when Odo finds a local secret, API key, SSH key, user, group, or
service account that needs rotation or access review.

1. Open Security.
2. Review Identity And Secrets, SSH Key Custody, Secret File Custody, and
   Rotation Reminders.
3. Click a custody or reminder row when available; it fills the rotation
   subject fields.
4. Confirm Subject, Type, Urgency, Requested By, and Reason.
5. Click Stage Request.
6. Review Identity Rotation Requests.
7. Do not print, copy, rotate, delete, or replace any credential or account
   until human approval is present.

### Prepare, Export, Dispatch, And Record IDS Review

1. Open Security.
2. Prepare a package with Plan ID and optional Source Review ID.
3. Export the review prompt when external analysis is needed.
4. Dispatch the package to the owner thread when ready.
5. Record the result as accepted or revision required.
6. Return to Admin for any protective action approval.

## Health: Julian

### View Logs From An Unhealthy Service

1. Open Health.
2. Review Unhealthy, Recovery, and Failures metrics.
3. Open Health Targets and click the affected resource row when available.
4. Click Run Probes.
5. Review Service Evidence, Redacted Service Logs, Journal Excerpts, and
   Journal Access Status.
6. If the registered log target is readable, use Redacted Service Logs for a
   bounded non-secret sample.
7. If user-journal evidence exists, use Journal Excerpts.
8. If system journal access is required, use Stage System Journal Access
   Request and wait for human approval before reading privileged log contents.

### Stage System Journal Access Request

Use this when Julian needs system-level journal evidence that is not already
available through the current user journal.

1. Open Health.
2. Review Journal Access Status and System Journal Requests.
3. Click a System Journal Requests row when available; it fills Resource ID and
   Unit.
4. Confirm the Reason describes the diagnostic need without secrets.
5. Click Stage Request.
6. Review the resulting operation record on Overview.
7. Do not read privileged system journal contents until human approval is
   present.

### Capture Metric History Snapshot

1. Open Health.
2. Review Observability And Performance, Health Trend History, and Host
   Snapshot Trend.
3. Fill optional Snapshot ID, Requested By, Retention, and Notes.
4. Click Capture Metrics.
5. Verify the row appears in Metric History Snapshots.
6. Use this before and after maintenance, remediation, or gateway changes so
   Julian can compare retained trend snapshots.

### Run Health Probes

1. Open Health.
2. Click Run Probes.
3. Review Health Targets for status, recovery requirement, and error.
4. Send recovery work to the owning crew member.

### Register A Health Target

1. Open Health.
2. Fill Target ID, Resource ID, Name, Probe type, Target, and expected HTTP or
   content type fields when relevant.
3. Click Record Target.
4. Run probes to confirm the target is usable.

## Usage: Quark

### Check An Exhausted Limit Refresh

1. Open Usage.
2. Review Exhausted and Low Confidence metrics.
3. Read Usage Limits.
4. Check the `resets_at` column for the next refresh time.
5. If work should resume later, create a continuation request.

### Record A Usage Limit

1. Open Usage.
2. Fill Limit ID, Resource ID, Kind, Window, Capacity, Remaining, Confidence,
   and optional Resets At.
3. Click Record Limit.
4. Verify it appears in Usage Limits.

### Request Continuation After Quota Refresh

1. Open Usage.
2. Fill Request ID, Limit ID, Resource ID, Owner Thread, Units, Risk, and Intent.
3. Add Earliest Start or Deadline when needed.
4. Click Request.
5. Dispatch only when the limit has renewed or policy says the work can run.

### Dispatch Ready Continuation Work

1. Open Usage.
2. Review Usage Limits and continuation state.
3. Set Dispatched By.
4. Enable Resume Codex Projects only when resuming project threads is intended.
5. Click Dispatch Ready.

### Discover Codex Project Threads

1. Open Usage.
2. Click Discover Codex Threads.
3. Review usage-limited service and continuation state.
4. Record limits for API-keyed MCP services that have daily, weekly, or monthly
   quotas.

## Documents: Ezri

### Search Documentation

1. Open Documents.
2. Fill Query and Context.
3. Click Search.
4. Use the result to choose the source runbook or knowledge note.

### List A Documentation Folder

1. Open Documents.
2. Fill Folder, for example `Overseer/Runbooks`.
3. Click List Folder.
4. Click folder rows such as `Runbooks/` to navigate.

### Write An Approved Note

1. Open Documents.
2. Fill Path under an allowed prefix such as `Overseer/` or `Inbox/`.
3. Select append or replace.
4. Fill Content.
5. Click Save.
6. Never write secrets or raw local exports.

### Capture Crew And Audit Knowledge

1. Open Documents.
2. Review Capture Queue and Capture Candidates.
3. Set the capture limit.
4. Click Capture.
5. Verify the generated notes under `Overseer/Knowledge/`.

### View Git Account Status

1. Open Documents.
2. Review Account Repositories, Dirty Repos, Remote Repos, Git Runtime, Current
   Repo Links, and Current Working Tree.
3. Click repository links to fill search context or open external GitHub links.
4. Do not commit, pull, push, reset, or checkout from this dashboard.

## Audit: Sisko

### View Audit Log

1. Open Audit.
2. Review Recent Audit.
3. Click owner domains to drill into the owning crew page.
4. Use event ids and summaries as decision evidence.

### Review Approval History

1. Open Audit.
2. Review Approvals.
3. Click an approval id to fill Admin approval fields when follow-up action is
   needed.
4. Verify final decisions have matching audit evidence.
