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

## Final trusted-boundary correction

The final independent review found that the public staging function still
accepted caller-constructed preflight dependencies. The public boundary now
accepts exactly `(store_path, ProvisioningIntentV1,
ProvisioningPreviewDigests)`. Public preview and preflight functions likewise
accept only the store path and typed intent. The dependency record and all
dependency-injected execution helpers are private and absent from `__all__`.

Every public staging attempt constructs a fresh server-owned dependency set.
The factory fixes the reviewed adapter and source paths, reads the real Git
HEAD, uses the reviewed runtime and capability digest implementations, hashes
and checks the exact GPG executable, resolves the exact current root identity
and authorization, validates code-owned canonical boundaries and packaged
rollback scenarios, and loads exact persisted predecessor bundles and the
current chain tip from a stable read-only store snapshot. The snapshot reader
rejects sidecars, identity drift, malformed rows, inexact serialized bundles,
inconsistent indexed metadata, and corruption. The chain resolver rejects broken
links, forks, cycles, disconnected history, and a non-current predecessor. Both
leave the real database bytes, timestamps, and sidecar set unchanged.

The private injected helper retains the prior one-transaction staging flow,
locked root validation, precommit persisted-set verification, exact replay
callback suppression, and typed-object guards. The public wrapper validates
typed inputs before constructing production dependencies. Supplying a fourth
dependency argument therefore raises `TypeError` before any callback or write.

Trusted-boundary RED evidence:

- `pytest -q tests/test_provisioning_bundle.py -k trusted_boundary` — 4 expected
  failures: a fourth caller dependency argument was accepted, public signatures
  and exports exposed dependency injection, the trusted factory was absent, and
  the public three-argument stage call was unavailable.
- The added corrupted-store case initially failed because the chain reader
  correctly rejected the store but exposed a lower-level root-authority error;
  the public-facing failure is now normalized to `persisted provisioning chain
  is unavailable`.

Final correction verification:

- `pytest -q tests/test_provisioning_bundle.py -k trusted_boundary` — 4 passed,
  114 deselected.
- `pytest -q tests/test_provisioning_bundle.py` — 118 passed.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py
  tests/test_core.py -k 'schema or migration or atomic or idempotent or
  provisioning or correction'` — 154 passed, 363 deselected.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py
  tests/test_roadex_approval_status.py -k 'correction or atomic or binding or
  replay or rollback'` — 72 passed, 210 deselected.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py
  tests/test_roadex_approval_status.py tests/test_core.py -k 'not
  test_roadex_human_scope_and_source_evidence_digest_use_exact_contract'` — 652
  passed, 1 deselected.
- `python3 -m compileall -q src/overseer/provisioning_bundle.py
  tests/test_provisioning_bundle.py` and `git diff --check` — passed.

The initial unfiltered repository run produced 1269 passed, 6 skipped, and 10
failures. One failure was Task 3-owned: the integer-migration preservation test
had not yet added schema migration `3` to its exact ordered expectation. The
follow-up below corrects that regression. The remaining nine failures are eight
disposable cross-repository acceptance failures lacking the `mcp` package and/or
required `THEUNDERDARK_PYTHON` and `THEUNDERDARK_SOURCE` environment, plus the
already documented Roadex fixture expecting `sha256:0d127...` while obtaining
`sha256:327b7...`. No acceptance environment or unrelated module was changed.

No live database, production source checkout, service, gateway, remote host,
approval, dispatch, provisioning, deployment, restart, push, or host mutation
was performed during this correction.

## Schema-migration expectation follow-up

The full-suite review correctly identified that schema version 3 makes integer
migration `3` part of the exact preserved ordering. The existing agent-store
test now expects `[1, 2, 3, 10, ...]` while retaining its checks that the
pre-existing integer rows, integer column affinity, custom description index,
and named agent migration remain preserved.

The observed unfiltered-suite assertion was the RED evidence. Follow-up GREEN
verification:

- `pytest -q tests/test_agent_store.py::test_existing_integer_schema_migration_rows_and_indexes_are_preserved`
  — 1 passed.
- `pytest -q tests/test_agent_store.py -k migration` — 3 passed, 51 deselected.
- `pytest -q tests/test_core.py -k 'schema or migration'` — 5 passed, 366
  deselected.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py
  tests/test_core.py tests/test_agent_store.py -k 'schema or migration or atomic
  or idempotent or provisioning or correction'` — 158 passed, 413 deselected.

## Final production-hardening correction

The final production review identified three remaining fail-closed gaps. First,
the production runtime digest used live worktree bytes under a Git HEAD label.
Production now opens the fixed adapter repository without following any path
component symlink, pins its directory descriptor, securely retraverses the full
path before and after each read, and invokes read-only Git commands through the
descriptor. The runtime evidence is reconstructed from the named commit's
bounded object tree and blobs using the reviewed exclusions, canonical paths,
0644/0755 modes, per-blob SHA-256 values, and deterministic version-1 payload.
Dirty tracked and untracked worktree bytes are never evidence. Malformed,
oversized, missing, symlink, submodule, unsupported, duplicate, unsafe-path, and
object-read cases fail with redacted errors. Git output, member count, path,
individual blob, aggregate bytes, and elapsed reads are bounded; ambient Git
environment overrides are removed and optional locks are disabled.

Second, the exact GPG digest now requires `O_NOATIME` and compares complete
descriptor and path-entry metadata before and after every bounded read. The
digest is retained locally until the owned descriptor closes successfully.
Ordinary open, read, metadata, and close failures return only the redacted
unavailable error; `BaseException` cleanup signals continue to propagate.

Third, the chain scope is now derived only from typed code-owned identity:
kind, project, fixed workspace, resource, root, and policy revision. Production
preview rejects a new empty-predecessor root when that exact scope already has a
different root. The same rule and successor-tip topology are rechecked from
exact persisted bundles after `BEGIN IMMEDIATE`, closing the preview/write race.
Exact replay remains allowed, a distinct typed scope may start a root, and two
concurrent same-scope attempts commit at most one bundle.

Production-hardening RED evidence:

- `pytest -q tests/test_provisioning_bundle.py -k 'production_runtime_digest or
  production_git_boundary or production_gpg_digest or locked_chain or
  concurrent_same_scope'` — 16 failed, 2 passed, 118 deselected. Failures proved
  dirty tracked/untracked influence; symlink and repository-identity-race
  acceptance; malformed, symlink, submodule, tree, oversized, and missing-object
  Git acceptance; absent `O_NOATIME`; descriptor and entry metadata drift;
  swallowed or leaked ordinary close errors; sequential second roots; and two
  concurrent roots committing. The existing short-read rejection and
  `BaseException` propagation controls were already green.

Production-hardening GREEN verification:

- The exact RED selection — 18 passed, 118 deselected.
- `pytest -q tests/test_provisioning_bundle.py` — 136 passed.
- Broad schema, migration, atomic, idempotent, provisioning, correction, Git,
  GPG, locked-chain, and concurrent-root selection — 176 passed, 413 deselected.
- Correction, atomic, binding, replay, rollback, trusted-boundary, locked-chain,
  and concurrent-root selection — 77 passed, 223 deselected.
- Full Task 3 touched suite excluding only the documented Roadex digest fixture
  assertion — 724 passed, 1 deselected.
- `python3 -m compileall -q src/overseer/provisioning_bundle.py
  tests/test_provisioning_bundle.py` and `git diff --check` — passed.

Disposable cross-repository acceptance was not runnable: the `mcp` package,
`THEUNDERDARK_PYTHON`, and `THEUNDERDARK_SOURCE` were all absent. No live source
checkout, production database, service, gateway, remote host, approval,
dispatch, provisioning, deployment, restart, or push action was performed.

## Git-session and evidence-source correction

The final security review found that the production evidence reader pinned only
the worktree root. It now creates one descriptor-owned Git session for each
production read. The session accepts only a real, non-symlink `.git` directory;
pins and rechecks worktree, Git directory, config, HEAD, active ref,
packed-refs, refs, objects, and bounded recursive object/ref metadata; and
rejects gitfiles/worktrees, links, alternates, shared stores, promisor/partial
metadata, grafts, loose or packed replacement refs, includes, and
object-interpretation configuration. Every Git subprocess uses both
`--no-replace-objects` and `GIT_NO_REPLACE_OBJECTS=1`, while unsafe ambient Git
overrides fail closed.

Runtime evidence opens one such session, requires its authenticated HEAD to
equal the requested commit before reconstruction, verifies commit/tree/blob
object identifiers against the exact returned object bytes, rebuilds the tree
without replacements, validates tracked live path type and canonical 0644/0755
mode without reading live file bytes, and rechecks all pinned identity and HEAD
state before return. The operation owns one monotonic deadline across all Git
reads, with output/member/path/blob/aggregate/process caps. The GPG reader now
also has an explicit executable-size cap and one elapsed-read deadline while
retaining `O_NOATIME`, stable metadata, successful-close-before-return, and
`BaseException` cleanup behavior.

### RED evidence

- `pytest -q tests/test_provisioning_bundle.py -k 'loose_and_packed_replacement
  or grafts_and_ambient or gitfiles_and_external or symlinked_git_components or
  shared_and_partial or unchanged_head_session or noncanonical_live or
  object_id_content_mismatch or aggregate_deadline or oversized_and_slow'`
  initially reported 14 failures and 1 pass. The failures proved acceptance of
  loose and packed replacement refs, grafts, gitfile/symlink metadata,
  HEAD drift, noncanonical modes, and counterfeit blob bytes; explicit GPG
  caps were absent. Two fixture-parent setup errors were corrected before
  production edits.
- `pytest -q tests/test_provisioning_bundle.py::test_production_git_boundary_rejects_symlinked_git_components --tb=short`
  then reported 1 failure and 4 passes: an unused nested `objects/zz` symlink
  was not pinned. This drove the bounded recursive metadata snapshot.

### GREEN verification

- The full security selection passed after the session correction, covering
  loose/packed replacement refs, grafts, gitfiles/external gitdirs,
  alternates/shared/partial clones, linked Git components, HEAD moves before
  and during runtime, 0664/0775 mode rejection, commit/tree/blob byte-ID
  mismatch, aggregate deadline, GPG size/time bounds, and descriptor/process
  cleanup.
- `pytest -q tests/test_provisioning_bundle.py` — 156 passed.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py
  tests/test_core.py -k 'schema or migration or atomic or idempotent or
  provisioning or correction'` — 192 passed, 363 deselected.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py
  tests/test_roadex_approval_status.py -k 'correction or atomic or binding or
  replay or rollback or trusted_boundary or locked_chain or concurrent_root'`
  — 76 passed, 244 deselected.
- `python3 -m compileall -q src/overseer/provisioning_bundle.py
  tests/test_provisioning_bundle.py` and `git diff --check` — passed.

Configured disposable cross-repository acceptance was attempted but remains an
environment prerequisite: `mcp` is not installed and `THEUNDERDARK_PYTHON` and
`THEUNDERDARK_SOURCE` are unset. The paired command produced 8 prerequisite
failures, 24 passes, and 5 skips; no source, database, service, gateway,
approval, dispatch, provisioning, deployment, restart, or push mutation was
performed.

## Final Git-parser and operation-lifetime correction

The last independent review found four remaining Git-session gaps. A promisor
marker under `objects/pack` could be accepted when no related configuration was
present. The shared deadline began only after the initial repository snapshot.
Raw Git trees did not reject duplicate component names or enforce Git's
directory-aware byte ordering before descent. Finally, an ordinary process
cleanup failure could prevent a later owned stdout close attempt.

Production now rejects every case-insensitive `.promisor` marker beneath the
pinned pack metadata tree independently of configuration. One deadline is
created before repository path traversal and is checked around every open,
metadata operation, bounded descriptor read, recursive snapshot, config/ref and
object validation, live-entry validation, identity recheck, subprocess read,
and successful finalization. Owned descriptor and process cleanup remains
outside the fail-fast deadline checks so it is still attempted after expiry.

Raw tree parsing now rejects duplicate byte names and noncanonical order before
any child tree is read, using Git's comparison rule that treats a directory as
if its name ends with `/`. Process cleanup independently attempts termination,
bounded wait, and stdout close; ordinary failures produce only the redacted
unavailable result, while control-flow `BaseException` failures are preserved
after all cleanup attempts.

### RED evidence

- `python3 -m py_compile tests/test_provisioning_bundle.py && pytest -q
  tests/test_provisioning_bundle.py -k 'pack_promisor_markers or
  deadline_includes_initial or hash_valid_duplicate or hash_valid_noncanonical
  or force_no_replacements'` — 8 failed, 155 deselected. Four marker variants
  were accepted, initial snapshot time was excluded, two hash-valid malformed
  trees were descended, and a cleanup wait failure skipped stdout close.
- The first correction run reported 7 passed and 1 failed because the deadline
  regression required a second snapshot after the first snapshot had already
  exhausted the deadline. The test was split into deterministic first-open and
  first-snapshot cases and now expects the required immediate fail-closed abort.

### GREEN verification

- Corrected focus including independent terminate/wait/close cleanup — 11
  passed, 155 deselected.
- Expanded Git/session security selection — 37 passed, 129 deselected.
- `pytest -q tests/test_provisioning_bundle.py` — 166 passed.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py
  tests/test_roadex_approval_status.py tests/test_core.py -k 'not
  test_roadex_human_scope_and_source_evidence_digest_use_exact_contract'` — 700
  passed, 1 deselected in 80.62 seconds.
- `python3 -m py_compile src/overseer/provisioning_bundle.py
  tests/test_provisioning_bundle.py` and `git diff --check` — passed.

The previously documented disposable acceptance prerequisites remain absent and
were not changed. No live source checkout, production database, service,
gateway, remote host, approval, dispatch, provisioning, deployment, restart,
push, or other external mutation was performed.
