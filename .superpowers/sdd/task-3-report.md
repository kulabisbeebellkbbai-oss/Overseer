# Task 3 Report: Atomic Provisioning-Bundle Persistence

## Outcome

Implemented Capability B Task 3 and the approved reusable-facility delta. Schema version 3 adds immutable preflight-report, provisioning-bundle, and review-outbox records. `stage_authoritative_bundle()` validates the exact bundle, rechecks current root authority before opening the persistence store, and uses `stage_bound_roadex_approval()` as the sole agent transaction. Its callback writes the staged source, preflight report, bundle, and four review-outbox records before the immutable binding is saved.

Exact replay does not re-enter the callback and reports `mutation_performed: false`. Replayed partial or changed sets fail closed without reconstruction. Persisted source, binding, preflight, bundle, and outbox records are reloaded and verified byte-for-byte; indexed digest metadata is also checked. No crew message is created in this slice, and there is no public API, approval, dispatch, provisioning, or host mutation.

## Files

- `src/overseer/store.py`: schema version 3 plus transaction-aware immutable storage helpers.
- `src/overseer/backup_provisioning.py`: exact staged-source serialization and persistence helper.
- `src/overseer/provisioning_bundle.py`: binding draft, authority recheck, atomic staging, exact persistence verification, and safe staging projection.
- `tests/test_provisioning_bundle.py`, `tests/test_backup_provisioning.py`, `tests/test_roadex_approval_status.py`, `tests/test_core.py`: rollback at every boundary, replay, root-drift, integrity, binding scope, and schema tests.

## TDD and verification evidence

Initial expected RED commands:

- `pytest -q tests/test_provisioning_bundle.py -k 'atomic or idempotent or serialized'` failed because `stage_authoritative_bundle` was absent.
- `pytest -q tests/test_core.py -k 'bootstrap_schema or atomic_bundle_tables'` failed because the schema was version 2 and the version-3 tables/index were absent.
- `pytest -q tests/test_provisioning_bundle.py -k 'tampered_indexed or tampered_preflight'` failed because indexed metadata was not checked.
- `pytest -q tests/test_backup_provisioning.py -k 'atomic_bundle_source'` failed because the source helper was absent.

Passing verification:

- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_core.py -k 'schema or migration or atomic or idempotent or provisioning'` — 141 passed.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_roadex_approval_status.py -k 'atomic or binding or replay or rollback'` — 63 passed.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_roadex_approval_status.py tests/test_core.py -k 'not test_roadex_human_scope_and_source_evidence_digest_use_exact_contract'` — 640 passed, 1 deselected.
- `git diff --check` — passed.

## Concern retained for coordinator review

The unfiltered touched-suite run has one reproducible, unrelated baseline failure: `tests/test_roadex_approval_status.py::test_roadex_human_scope_and_source_evidence_digest_use_exact_contract` expects source-evidence digest `sha256:0d127...` but obtains `sha256:327b...`. This slice does not modify `roadex_approval_status.py`, plan construction, or source-evidence-digest behavior, so its canonical expectation was intentionally not changed. Security-review dispatch was attempted but no agent slot was available; the coordinator will run the independent review after this commit.
