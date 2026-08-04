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

The unfiltered touched-suite run has one reproducible, unrelated baseline failure: `tests/test_roadex_approval_status.py::test_roadex_human_scope_and_source_evidence_digest_use_exact_contract` expects source-evidence digest `sha256:0d127...` but obtains `sha256:327b...`. The initial slice did not modify `roadex_approval_status.py`; the correction wave below changes only its transaction callback flow and does not change plan construction or source-evidence-digest behavior. The canonical fixture expectation was intentionally not changed.

## Correction wave after independent review

The independent review identified three staging-boundary defects. The correction keeps `stage_bound_roadex_approval()` as the sole transaction owner and adds two optional callbacks: a locked validator immediately after its existing `BEGIN IMMEDIATE`, and a bound-record verifier after binding insert/load but before commit. Existing callers omit both callbacks and retain their prior behavior. Provisioning uses the locked callback to run the same canonical schema, Kira evidence, approval, revocation, expiry, ambiguity, and exact-root selection against the already-open connection. It uses the verifier callback to prove the complete source, binding, report, bundle, and four-row outbox while rollback is still possible. Exact replay runs both callbacks but continues to skip source persistence.

The staging boundary now accepts only an exact `ProvisioningIntentV1`, exact `PreflightDependencies`, and `ProvisioningPreviewDigests`. It rebuilds from authoritative dependencies on every initial or replay attempt and compares the expected plan, preflight, and bundle digests before opening the persistence store. There is no prebuilt-bundle compatibility overload. Arbitrary mappings, missing or malformed preview digests, digest mismatches, and typed objects carrying extra forbidden attributes fail before writes.

Correction RED evidence:

- `pytest -q tests/test_provisioning_bundle.py tests/test_roadex_approval_status.py -k correction` — 5 expected failures: omitted fourth outbox left source, binding, report, bundle, and three outbox rows committed; initial and replay root revocations injected after the outer check were not observed; both transaction callback arguments were absent.
- `pytest -q tests/test_provisioning_bundle.py -k 'correction_typed_stage'` — 2 expected failures because `ProvisioningPreviewDigests` and the typed rebuild boundary were absent.
- `pytest -q tests/test_provisioning_bundle.py -k 'extra_attributes_on_typed_inputs'` — 1 expected failure proving class identity alone accepted a tainted typed intent.

Correction verification:

- `pytest -q tests/test_provisioning_bundle.py tests/test_roadex_approval_status.py -k correction` — 8 passed.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_roadex_approval_status.py -k 'correction or atomic or binding or replay or rollback'` — 70 passed, 207 deselected.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py tests/test_core.py -k 'schema or migration or atomic or idempotent or provisioning or correction'` — 149 passed, 363 deselected.
- Full touched suite before the final typed-object exactness hardening — 647 passed and the same one documented Roadex fixture assertion failed.
- Final full touched suite excluding only that baseline assertion — 648 passed, 1 deselected.
- Final standalone baseline assertion — the same expected `sha256:0d127...` versus actual `sha256:327b...` mismatch.

No live database, service, gateway, remote host, approval, dispatch, provisioning, deployment, restart, or push action was performed.
