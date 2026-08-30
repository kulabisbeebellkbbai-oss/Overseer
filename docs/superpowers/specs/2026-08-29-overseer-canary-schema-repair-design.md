# Overseer Canary Schema Repair Design

## Context

The replacement v1.1.6 Phase B runner reached the disposable API health
control and then failed while creating the approval smoke plan. The canary
journal reported `sqlite3.OperationalError: no such table:
admin_execution_claims`. Cleanup completed, the durable runner state became
`aborted_before_cutover`, no canary attestation was created, and cutover
remained unapproved.

The table is already part of `SQLiteStore.initialize()` and therefore belongs
to the current schema version. The defect is that `_schema_is_current()` does
not require it. A copied store carrying current migration markers can therefore
skip initialization while lacking a table required by the approval executor.
The package rehearsal records complete schema evidence but does not currently
reject a migrated store that lacks canary-critical tables. Finally, successful
cleanup overwrites the bounded originating failure classification with `null`,
making terminal diagnosis depend on transient terminal or journal output.

A later replacement-package run exposed a second independent defect: the
fixed canary database pathname could retain SQLite sidecars from an earlier
failed package. The replacement therefore also requires a fresh opaque
package namespace and must not transfer that namespace to the service account
until all bounded verification is complete.

## Scope and boundaries

This repair will:

- make current-schema detection require the complete crash-safe admin execution
  table group;
- reject package migration/finalization when the migrated rehearsal store lacks
  tables required by mandatory canary controls;
- preserve a bounded originating failure classification through staging
  cleanup and terminal `aborted_before_cutover` state;
- stage each canary in a new no-replace root-owned namespace, reject stale or
  oversized SQLite artifacts before hashing, and couple the final ownership
  handoff directly to the exact canary service start;
- add regression tests for each behavior;
- run implementation review, final security review, and full project/package
  verification;
- generate and independently verify a replacement owner package.

This repair will not:

- modify another project;
- mutate the live v1.1.5 store or services;
- repair or rerun the failed package in place;
- archive or import the replacement package;
- create staging-canary or cutover approval records;
- execute staging, canary, cutover, rollback, or a service restart.

## Considered approaches

### A. Minimal table-list patch

Add only `admin_execution_claims` to `_schema_is_current()`. This fixes the
observed startup path with the smallest diff, but package finalization could
still seal a malformed migrated database if a later refactor bypasses normal
store initialization. It also leaves terminal failure evidence erased.

### B. Defense in depth with bounded diagnostics (selected)

Require the full crash-safe admin execution table group in
`_schema_is_current()`, add an explicit canary-required schema subset check to
migration rehearsal and sealed rehearsal validation, and carry only bounded
failure classifications through cleanup. This catches the defect both when a
store opens and before a package can be sealed, while retaining fail-closed
cleanup and secret-handling boundaries.

### C. New schema-version migration

Increment `CURRENT_SCHEMA_VERSION` and add a dedicated migration. This would be
appropriate for a genuinely new schema feature, but the table is already in
the v12 initializer and runtime code already assumes it exists. A version bump
would also rerun unrelated audit normalization over the large store. It adds
operational load without improving this bounded repair.

## Detailed design

### Store currentness

`src/overseer/store.py` will define one immutable set containing the schema
objects required for current runtime operation. The existing
`_schema_is_current()` query and exact-set comparison will use it. The set will
include `admin_change_plans`, `admin_executions`,
`admin_execution_claims`, and `admin_history_archives` in addition to the
objects already checked.

The schema version remains 12. Opening a v12 store missing any required object
will take the existing idempotent initialization path, create the absent table,
and return current only after the complete predicate passes. A store opened
under a bounded collection deadline will continue to fail closed instead of
performing an implicit migration.

### Package migration gate

`src/overseer/activation_package.py` will define the canary-required store table
subset used by approval planning, approval execution, replay protection, and
history handling. Immediately after migrating the rehearsal copy, package
preparation will assert that `schemaAfter.tableNames` contains that complete
subset. Sealed rehearsal validation will repeat the same assertion against the
independently reopened migrated artifact and the signed report.

The check is subset-based: existing and future unrelated tables remain allowed,
while any missing canary-critical table blocks package preparation or
finalization before activation approval is possible.

### Failure preservation

The staging cleanup helpers will accept an optional `originating_failure`.
Callers will provide only an already-bounded value:

- `exit-N` or a command-start exception class for a failed sealed command;
- an exception class name for authorization, checkpoint, or gate failures.

Cleanup command states and the terminal `aborted_before_cutover` state will
retain that value. A cleanup failure may replace it only with the bounded
cleanup failure already recorded by the current implementation. Raw exception
messages, subprocess output, verifier input, approval tokens, and credentials
will never be written to runner state.

### Canary namespace and ownership handoff

Preparation seals a random 128-bit hexadecimal canary instance identifier.
Phase B creates `/var/lib/overseer-canary/<instance-id>` with no-replace
semantics and copies the authority database plus the two empty integration
databases into it. The parent, namespace, and database files remain root-owned
through installed-artifact and SQLite verification. Expected migration size is
loaded from digest-bound report evidence and checked, together with the
approved package-size ceiling and non-sparse allocation, before any target
hash or integrity scan. The two auxiliary databases must be single-link,
zero-length regular files before their hashes are read.

The sealed startup suffix contains `handoff-start-canary` instead of a direct
`systemctl start` command. After the local hidden verifier prompts, that
primitive proves the active runner command and inherited lock, rejects any
existing process carrying the dedicated UID, descriptor-opens the exact
root-owned namespace and three expected files, rechecks the process boundary,
transfers only those objects to UID/GID 984, fsyncs the resulting metadata, and
immediately starts only `overseer-api-canary.service`. A failed or completed
namespace is retained as immutable package-specific evidence and is never
reused by another package.

### Error handling and retry behavior

The failed package remains terminal and non-resumable. The repair does not add
an in-place retry path. Any failure still invokes the sealed cleanup sequence;
if durable cleanup-state publication fails, emergency cleanup remains the
fallback. Import, Phase B, and cutover continue to require separate exact-digest
approvals for the eventual replacement package.

## Testing

Tests will be written and observed failing before production changes.

1. A schema-current regression will create a valid current v12 store, remove
   `admin_execution_claims`, reopen it normally, and prove initialization
   restores the table. A bounded collection open of the same incomplete schema
   will continue to reject it as not pre-migrated.
2. A migration rehearsal regression will start from a current-marked store
   missing the claim table and prove the migrated rehearsal schema contains the
   complete canary-required subset.
3. A sealed rehearsal validation regression will remove a required table from
   a migrated artifact, refresh only untrusted report fields as needed by the
   fixture, and prove finalization still rejects the independently observed
   schema.
4. Runner cleanup regressions will prove command, authorization, checkpoint,
   and cutover-gate failure classifications survive in terminal state while
   `secretValuesRecorded` remains false.
5. Focused store and activation-package suites will run before the complete
   project suite. Package generation will then run from a clean committed
   worktree, followed by an independent full-tree package verification.
6. Namespace regressions will prove stale fixed-path sidecars cannot enter a
   new package, namespace reuse fails closed, all database sidecars and link
   substitutions are rejected, target size is rejected before hashing, and an
   existing UID 984 process blocks the sealed ownership handoff and service
   start.

## Security review criteria

Review must confirm that:

- schema checks operate on independently opened SQLite artifacts, not report
  assertions alone;
- no source or live store is mutated during rehearsal verification;
- required-table checks cannot be satisfied by views, indexes, temporary
  objects, or attacker-controlled names outside `sqlite_master` table rows;
- failure preservation records only bounded classifications and cannot expose
  verifier secrets or subprocess output;
- cleanup remains mandatory and terminal state cannot authorize cutover;
- the replacement package remains unapproved and unexecuted.

## Deliverables and activation boundary

The implementation deliverables are source and test changes, updated operator
documentation if command behavior changes, review evidence, a clean commit, and
a sealed owner package with its new digest and independent verification result.
The handoff stops before archive/import. A later explicit approval must name the
replacement digest before any root activation artifact is changed.
