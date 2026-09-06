# Overseer Dedicated Collector Bridge Repair Design

Status: approved for source implementation, tests, review, and replacement
package preparation. Package import and every activation phase remain
unapproved.

## Problem

The maintenance-window successor runs the autonomous runtime as the dedicated
`overseer` principal. That runtime deliberately disables collection families
which depend on the `god` user session. The maintenance acceptance contract
simultaneously requires the Psychlo timer freshness, Quark timer freshness,
and Overseer Git jobs to be enabled and fresh. The real successor therefore
cannot pass even though the API and authenticated UI are healthy.

The current acceptance unit test hides the conflict by fabricating every
required job as enabled. A failed maintenance rollback also leaves the
migrated `/var/lib/overseer` namespace root-locked in place, forcing a manual
cleanup before a later package can pass preflight.

## Considered approaches

1. Extend the existing authenticated read-only user bridge with fixed
   collection projections. This preserves principal separation, keeps
   collection schedules authoritative in the dedicated runtime, and exposes
   no caller-selected path, unit, command, or parameter. This is the approved
   approach.
2. Remove the three jobs from maintenance acceptance. This would permit
   activation while silently dropping required operational coverage and is
   rejected.
3. Keep a second user-owned collection runtime after cutover. This would
   preserve access but create two schedulers and a dual-writer boundary. It is
   rejected for v1.1.6.

## Bridge contract

The existing `overseer.user-bridge.v1` socket and peer-credential checks stay
unchanged. Two new empty-parameter methods are added:

- `overseer.scheduler.freshness.v1` returns bounded outcomes for exactly
  `collection.freshness.psychlo-usage` and
  `collection.freshness.quark-scheduler` after inspecting their fixed user
  timer/service pairs.
- `overseer.git.status.v1` returns a bounded, redacted status projection for
  the fixed Overseer checkout. It excludes filesystem paths, arbitrary remote
  URLs, credentials, environment, command text, and caller-selected refs.

The user-owned provider may execute only fixed argv for `/usr/bin/systemctl`
and `/usr/bin/git`, with a fixed environment, optional Git locks and external
helpers disabled, fixed source paths, hard total deadlines, output bounds, and
no shell. Projection methods use isolated concurrency slots. The systemd
service exposes only the
user bus and the Overseer checkout required by these providers. Private Codex
material and other projects remain absent from its mount namespace.

The dedicated runtime receives the bridge client through the same fixed
socket and expected-server-UID environment contract already used by the API.
It force-enables only the three named built-in jobs. Existing custom Git jobs and
the mutation-capable crew, usage-continuation, knowledge-capture, and station
audit families remain disabled. A stale bridge projection becomes a failed
stale collection rather than fresh evidence. Bridge errors become bounded
blocked or failed collection runs and normal triage evidence; they never cause fallback
access to user files or `systemctl --user` from the authority process.

The Git adapter writes the sanitized bridge result through the existing
durable dashboard-projection contract. UI reads continue to use stored
Overseer data and cannot invoke the provider directly.

## Acceptance diagnostics

Maintenance acceptance continues to require all existing core jobs. Instead
of returning only `scheduler-freshness`, a scheduler failure identifies the
first exact job and one bounded reason: missing, disabled, unsuccessful,
invalid interval, missing age, or stale. It includes no source payload or
private provider error.

An integration test uses a real temporary store, dedicated-principal seeding,
the real collection adapters with a fake typed bridge client, scheduler state,
API status serializers, and maintenance acceptance. It must fail against the
old behavior and pass only when the runtime and acceptance contracts agree.

## Rollback destination hygiene

Full rollback keeps the current safety order: stop and disable successor
units, verify the rollback bundle, root-lock and prove the failed successor
namespace process-free, and restore legacy source access. While the verified
destination descriptor remains held, the runner atomically moves the entire
failed successor namespace to the deterministic sibling of the sealed
preservation root named `failed-successor-store`.

The move is no-replace and same-filesystem only. An existing archive must
match the interrupted rollback's source identity; any conflicting path fails
closed. After a successful or replay-verified move, the runner creates a new
empty `/var/lib/overseer` owned by numeric `984:984` with mode `0700` and
verifies it before legacy writers can restart. Failed databases and sidecars
remain preserved in root-owned evidence; they are not deleted or copied over
legacy authority.

## Verification and activation boundary

Focused bridge, scheduler, acceptance, storage, contract, and systemd tests
must pass, followed by the complete repository suite. Independent correctness
review and a final defensive security review must find no unresolved critical
or important issue. The owner-scoped replacement package must be regenerated
and independently verified. Work stops before package import, maintenance
approval, service changes, Phase B, canary, cutover, reboot, VM work, claim
changes, or gateway/firewall changes.
