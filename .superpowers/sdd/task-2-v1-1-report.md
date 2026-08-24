# Task 2 implementation report: immutable package evidence

Date: 2026-08-24
Status: DONE
Implementation commit: `78fc5cd` (`Integrate immutable package inspection evidence`)

## Scope and implementation

Task 2 ports only the bounded immutable package evidence from the reviewed
O'Brien branch. The unfinished reconciliation workflow and the historical
workflow fixtures were not imported.

`src/overseer/packages.py` now provides:

- `PackageInspectionRecord`;
- `PackageReconciliationEvidence`;
- `package_state_fingerprint()`;
- `package_inspection_record()`.

The package state fingerprint is a canonical SHA-256 digest of the sorted
package update fields. The inspection record identity includes the snapshot
identity plus a digest of captured time, command, exit code, fingerprint, and
stderr, so package-state changes produce different content-addressed IDs even
when timestamps match.

`src/overseer/store.py` now provides insert/load/list methods for both record
types. Persistence uses the current `_dump()` JSON serialization. On an
existing ID, the stored serialized payload must match byte-for-byte; an exact
retry is a no-op and a different payload raises the appropriate immutable
collision `ValueError`. New records use plain `INSERT`; neither immutable
package table uses `INSERT OR REPLACE`. The methods use the existing
`_commit_agent_mutation()` boundary so they also participate correctly in an
outer agent transaction.

## TDD evidence

### RED

Command:

```text
PYTHONPATH=src pytest -q tests/test_package_reconciliation.py
```

Before production changes, collection failed as expected because the new
contract was absent:

```text
ImportError: cannot import name 'PackageReconciliationEvidence' from 'overseer.packages'
```

The failure was a missing production interface, not a test typo.

### GREEN

After the minimal implementation:

```text
PYTHONPATH=src pytest -q tests/test_package_reconciliation.py
4 passed
```

The tests cover content-addressed identity, exact-payload idempotency,
same-ID/different-payload rejection, round trips, and v10-to-v11 migration
preservation.

## Schema and migration decisions

- `CURRENT_SCHEMA_VERSION` advances from 10 to 11.
- v11 adds `package_inspection_records(id PRIMARY KEY, payload)`.
- v11 adds `package_reconciliation_evidence(id PRIMARY KEY, snapshot_id,
  maintenance_batch_id, payload)` plus indexes on `snapshot_id` and
  `maintenance_batch_id`.
- The tables are created in the existing idempotent initialization DDL. The
  current-schema predicate also requires both tables, so a database claiming
  v11 but missing either table is repaired by the existing initialization path.
- Existing migration rows and ordering remain intact. A fresh database keeps
  the bootstrap description; a pre-v11 database receives v11 with description
  `persist immutable package inspection evidence`. The migration regression
  test verifies the preserved v10 row followed by v11 and preserved data.
- The existing audit normalization generation follows the current schema
  version as before; no migration ordering or rollback mechanism was replaced.
- `tests/test_agent_store.py` was updated only to expect the new v11 row in its
  preserved migration-history assertion.

## Incomplete-work and branch disposition evidence

The authoritative register is
`docs/v1.1-incomplete-work-disposition.md`. No branch or worktree was deleted,
pruned, switched, merged, rebased, or modified.

Reviewed package branch `feature/obrien-package-reconciliation` had these
three unique commits:

- `1f908e60875ce0ff1b00a7bb686d1b65a3a53f68` — package reconciliation plan;
- `3a086c7a43f3345e67c6a2ae3197acb919a6dd2c` — immutable package evidence;
- `119f961c4ae8803ce5a41570b51035640db8af6d` — workflow fixtures deferred.

Reviewed `fix/quarantine-round-recovery` had:

- `2e8ad99b0f25f52c4b35a4545c41e482d71c49b0` — approval-gated recovery;
- `1b4cbb1fc2e35f61edd9cc0c31c0d0e23a384d18` — hardened recovery authority.

The patch-equivalent branches checked against `main` and preserved are:
`fix/arcade-dispatch-delivery-proof`, `fix/claim-approval-continuation`,
`fix/false-submitted-delivery-proof`, `fix/process-attestation-scan-contract`,
`fix/psychlo-bridge-cli-v2`, `fix/psychlo-decision-reconcile`,
`fix/psychlo-legacy-abandon-envelope`, `fix/psychlo-legacy-abandonment`,
`fix/psychlo-original-thread-binding`, `fix/psychlo-thread-aware-dispatch`,
`feature/overseer-roadex-project-thread-relay`,
`fix/successor-process-observation-collector`, and
`fix/workspace-package-routing`.

The zero-delta branches checked against `main` and preserved are:
`fix/claim-role-approval-handoff`, `fix/psychlo-legacy-process-attestation`,
`feature/psychlo-percentage-meter`, `feature/psychlo-v1-1-counterpart`, and
`feature/python-hashed-venv-adapter`.

`feature/reusable-approval-facility` remains separate DonutHole work.
`fix/submitted-round-recovery` remains in place with its observed dirty files:
`src/overseer/agent_adapters/codex.py`, `src/overseer/psychlo_bridge.py`,
`src/overseer/psychlo_bridge_cli.py`, `src/overseer/psychlo_store.py`, and
`tests/test_submitted_round_recovery.py`.

Cleanup remains separately authorized only after a later live
session/attachment audit identifies exact targets and confirms ownership and
dirty-state safety.

## Verification

Passed:

- `PYTHONPATH=src pytest -q tests/test_package_reconciliation.py tests/test_core.py -k package`
  — 30 passed, 359 deselected;
- `PYTHONPATH=src pytest -q tests/test_agent_store.py -k 'schema or migration' tests/test_roadex_approval_fixture.py`
  — 8 passed, 56 deselected;
- `PYTHONPATH=src pytest -q tests/test_agent_store.py tests/test_roadex_approval_fixture.py`
  — 64 passed;
- `PYTHONPATH=src python3 -m compileall -q src/overseer/packages.py src/overseer/store.py`;
- `git diff --check` and staged `git diff --cached --check`.

No live Overseer service, user data, gateway, integration, original checkout,
or other worktree was touched. The broader historical baseline failures listed
in the v1.1 design were not re-run; the affected package/core/store tests are
green. Remaining reconciliation workflow and cleanup work are intentionally
out of scope and remain approval/specification gated.
