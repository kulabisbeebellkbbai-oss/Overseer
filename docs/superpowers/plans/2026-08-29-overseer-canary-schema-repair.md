# Overseer Canary Schema Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent current-marked Overseer stores and activation packages from omitting canary-critical admin tables, and preserve bounded staging failure evidence through mandatory cleanup.

**Architecture:** The store currentness fast path and package migration verifier will share explicit immutable required-table contracts at their respective trust boundaries. Staging cleanup will carry only a bounded originating failure classification into durable terminal state while retaining the existing cleanup-failure override and fail-closed behavior.

**Tech Stack:** Python 3.13, `sqlite3`, `pytest`, Overseer activation package tooling, systemd command contracts

## Global Constraints

- Keep `CURRENT_SCHEMA_VERSION` at `12`; the omitted table already belongs to the current initializer.
- Do not mutate the live v1.1.5 store, live services, or any other project.
- Do not repair or rerun the failed package in place.
- Do not archive, import, approve, execute, restart, roll back, or cut over the replacement package.
- Package migration checks must inspect independently opened SQLite artifacts and require real `sqlite_master` table rows.
- Failure state may contain only bounded classifications such as `exit-N` or an exception class name; it must never contain messages, output, verifier input, tokens, or credentials.
- Cleanup remains mandatory and terminal `aborted_before_cutover` state cannot authorize cutover.

---

### Task 1: Repair store schema currentness

**Files:**
- Modify: `src/overseer/store.py:91,751-837`
- Test: `tests/test_collection_store.py:140-200`

**Interfaces:**
- Consumes: `SQLiteStore(path)` and `collection_deadline_scope(deadline)`.
- Produces: `_SCHEMA_CURRENT_REQUIRED_TABLES: frozenset[str]` and an exact currentness predicate that includes the crash-safe admin table group.

- [ ] **Step 1: Write the failing normal-open regression**

Add a test that creates a complete store, closes it, drops `admin_execution_claims` with a direct SQLite connection, reopens it through `SQLiteStore`, and asserts that the table exists and `_schema_is_current()` is true:

```python
def test_current_marked_store_recreates_missing_admin_execution_claim_table(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path):
        pass
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE admin_execution_claims")
        connection.commit()

    with SQLiteStore(path) as reopened:
        table = reopened._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            ("admin_execution_claims",),
        ).fetchone()
        assert table is not None
        assert reopened._schema_is_current()
```

- [ ] **Step 2: Write the failing bounded-open regression**

Add this separate bounded-open test:

```python
def test_collection_context_rejects_current_marked_store_missing_admin_execution_claim_table(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with SQLiteStore(path):
        pass
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE admin_execution_claims")
        connection.commit()

    with collection_deadline_scope(time.monotonic() + 5.0):
        with pytest.raises(RuntimeError, match="pre-migrated SQLite store"):
            SQLiteStore(path)

    with sqlite3.connect(path) as connection:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            ("admin_execution_claims",),
        ).fetchone()
    assert table is None
```

- [ ] **Step 3: Run the two tests and verify the expected failures**

Run:

```bash
pytest -q \
  tests/test_collection_store.py::test_current_marked_store_recreates_missing_admin_execution_claim_table \
  tests/test_collection_store.py::test_collection_context_rejects_current_marked_store_missing_admin_execution_claim_table
```

Expected before implementation: the normal open does not recreate the table, and the bounded open does not reject the incomplete current-marked store.

- [ ] **Step 4: Implement the immutable required-table set**

Define this complete immutable set beside `CURRENT_SCHEMA_VERSION`:

```python
_SCHEMA_CURRENT_REQUIRED_TABLES = frozenset(
    {
        "schema_migrations",
        "agent_schema_migrations",
        "roadex_approval_fixtures",
        "psychlo_legacy_abandonment_execution_claims",
        "claim_approval_continuations",
        "claim_activation_groups",
        "claim_approval_continuation_attempts",
        "audit_event_normalization_state",
        "package_inspection_records",
        "package_reconciliation_evidence",
        "collection_jobs",
        "collection_job_states",
        "collection_requests",
        "collection_runs",
        "triage_incidents",
        "repair_runbooks",
        "repair_attempts",
        "dashboard_projections",
        "admin_change_plans",
        "admin_executions",
        "admin_execution_claims",
        "admin_history_archives",
    }
)
```

Replace the hard-coded `IN` query with placeholders generated from the sorted constant, pass the names as bound parameters, and compare the observed set exactly to `_SCHEMA_CURRENT_REQUIRED_TABLES`.

- [ ] **Step 5: Verify both regressions and the surrounding store suite**

Run:

```bash
pytest -q tests/test_collection_store.py
```

Expected: all collection-store tests pass; normal open repairs the absent table and bounded collection open remains read-only/fail-closed.

- [ ] **Step 6: Commit the store repair**

```bash
git add src/overseer/store.py tests/test_collection_store.py
git commit -m "Repair current store admin execution schema"
```

---

### Task 2: Add package-time canary schema gates

**Files:**
- Modify: `src/overseer/activation_package.py:1870-1950,4402-4510`
- Test: `tests/test_activation_package.py:2040-2145,3300-3415`

**Interfaces:**
- Consumes: migration evidence dictionaries containing `tableNames: list[str]`.
- Produces: `CANARY_REQUIRED_STORE_TABLES: frozenset[str]` and `_require_canary_store_schema(schema: object) -> None`.

- [ ] **Step 1: Write the failing migration-rehearsal regression**

Extend `_prepared_package` with `missing_admin_execution_claims: bool = False`. When requested, create and close a real `SQLiteStore(source)` so the source has current v12 markers and the complete initializer schema, then use a direct `sqlite3.connect(source)` block to drop `admin_execution_claims`, commit, and checkpoint the WAL. Keep `_wal_store(source)` for the existing minimal-source path. Add a test that calls `_prepared_package(tmp_path, missing_admin_execution_claims=True)`, reads `private/migration/migration-report.json`, and asserts the complete canary-required table subset is present in `report["schemaAfter"]["tableNames"]`.

- [ ] **Step 2: Run the rehearsal regression and verify it fails**

Run:

```bash
pytest -q tests/test_activation_package.py::test_migration_rehearsal_restores_canary_required_store_tables
```

Expected before implementation: the rehearsal reports a migrated artifact that still lacks `admin_execution_claims`.

- [ ] **Step 3: Implement the preparation-time schema requirement**

Define the immutable canary subset:

```python
CANARY_REQUIRED_STORE_TABLES = frozenset(
    {
        "admin_change_plans",
        "admin_executions",
        "admin_execution_claims",
        "admin_history_archives",
    }
)
```

Implement `_require_canary_store_schema` so it rejects a non-list `tableNames`, non-string entries, or a missing required name with `ActivationPackageError("migration rehearsal is missing canary-required store tables")`. Call it immediately after obtaining `schema_after` in `rehearse_store_migration`.

- [ ] **Step 4: Verify the rehearsal regression passes**

Run:

```bash
pytest -q tests/test_activation_package.py::test_migration_rehearsal_restores_canary_required_store_tables
```

Expected: pass, with all four canary-required tables observed after migration.

- [ ] **Step 5: Write the failing sealed-artifact regression**

Using `_finalized_package`, open `private/migration/rehearsal-migrated.sqlite3`, drop `admin_execution_claims`, checkpoint/truncate WAL state, switch to delete journal mode, and remove absent sidecars exactly as the existing deleted-index test does. Recompute `_sealed_migration_artifact_evidence`, update the report's migrated digest/size/integrity, `rowCountsAfter`, and `schemaAfter`, reseal only the test manifest, then assert `verify_activation_package` raises `ActivationPackageError` matching `canary-required store tables`.

- [ ] **Step 6: Run the sealed-artifact regression and verify it fails for the missing behavior**

Run:

```bash
pytest -q tests/test_activation_package.py::test_package_verification_rejects_migrated_store_missing_canary_required_table
```

Expected before sealed validation is added: verification accepts the internally consistent but incomplete migrated artifact.

- [ ] **Step 7: Apply the schema requirement independently during sealed validation**

In `_validate_migration_rehearsal_semantics`, invoke `_require_canary_store_schema` on both the report `schemaAfter` mapping and `observed_migrated["schema"]` after independently reopening the migrated database. Keep the existing report-to-artifact equality check.

- [ ] **Step 8: Verify focused migration and package tests**

Run:

```bash
pytest -q \
  tests/test_activation_package.py::test_migration_rehearsal_restores_canary_required_store_tables \
  tests/test_activation_package.py::test_package_verification_rejects_migrated_store_missing_canary_required_table \
  tests/test_activation_package.py::test_package_verification_rejects_deleted_migrated_expression_index
```

Expected: all selected tests pass.

- [ ] **Step 9: Commit the package schema gate**

```bash
git add src/overseer/activation_package.py tests/test_activation_package.py
git commit -m "Gate activation packages on canary schema"
```

---

### Task 3: Preserve bounded staging failures through cleanup

**Files:**
- Modify: `src/overseer/activation_package.py:6481-6565,7485-7665`
- Test: `tests/test_activation_package.py:6280-6830`

**Interfaces:**
- Consumes: `originating_failure: str | None` already bounded by `_command_outcome` or `type(error).__name__`.
- Produces: `_execute_cleanup_sequence(contract: Mapping[str, object], *, package_digest: str, originating_failure: str | None = None) -> None` and `_execute_resilient_cleanup(contract: Mapping[str, object], *, package_digest: str, originating_failure: str | None = None) -> bool`.

- [ ] **Step 1: Write failing terminal-state regressions**

Extend the existing staging command failure and later command-entry checkpoint tests to load the terminal state and assert:

```python
assert state["status"] == "aborted_before_cutover"
assert state["failure"] == "exit-1"  # command failure
assert state["secretValuesRecorded"] is False
```

For the checkpoint case, assert `state["failure"] == "OSError"`. Add equivalent authorization-boundary and post-command checkpoint tests that inject `ActivationPackageError` and `OSError` respectively, then assert the same bounded class-only behavior.

- [ ] **Step 2: Run the new failure tests and verify they fail**

Run:

```bash
pytest -q \
  tests/test_activation_package.py::test_failed_staging_command_preserves_bounded_failure_after_cleanup \
  tests/test_activation_package.py::test_staging_later_command_entry_checkpoint_failure_preserves_bounded_failure \
  tests/test_activation_package.py::test_canary_authorization_failure_preserves_bounded_failure_after_cleanup \
  tests/test_activation_package.py::test_staging_command_completion_checkpoint_failure_preserves_bounded_failure
```

Expected before implementation: terminal `failure` is `None` because successful cleanup overwrites the originating classification.

- [ ] **Step 3: Thread the bounded classification through cleanup**

Add `originating_failure: str | None = None` to both cleanup helper signatures. Include it in cleanup running/completed states and in terminal `aborted_before_cutover`. Keep cleanup command failure behavior as the existing `start_error or f"exit-{returncode}"`, so an actual cleanup failure supersedes the originating value.

- [ ] **Step 4: Supply bounded values at every staging failure call site**

Use these exact sources:

```python
originating_failure=type(authorization_error).__name__
originating_failure=type(checkpoint_error).__name__
originating_failure=start_error or f"exit-{returncode}"
```

Apply the same exception-class pattern to later staging checkpoint/gate failures. Do not pass `str(error)` or subprocess output.

- [ ] **Step 5: Verify focused runner tests**

Run:

```bash
pytest -q tests/test_activation_package.py -k "staging and (failure or checkpoint or authorization or cleanup)"
```

Expected: selected runner tests pass and every inspected terminal state retains a bounded failure with `secretValuesRecorded` false.

- [ ] **Step 6: Commit bounded failure preservation**

```bash
git add src/overseer/activation_package.py tests/test_activation_package.py
git commit -m "Preserve staging failure through cleanup"
```

---

### Task 4: Review, verify, and prepare the replacement owner package

**Files:**
- Modify only if required by review: files already listed in Tasks 1-3
- Create: owner package under `/home/god/.local/share/overseer/activation-packages/` with the exact seven-character final commit suffix
- Verify: complete repository tests and sealed package contents

**Interfaces:**
- Consumes: clean reviewed Git commit and the existing owner-side package preparation workflow.
- Produces: a sealed, independently verified owner package digest with no import or activation approval.

- [ ] **Step 1: Run the complete source test suite**

```bash
pytest -q
```

Expected: zero failures.

- [ ] **Step 2: Request implementation code review**

Give a fresh `gpt-5.6-terra` reviewer the approved design, implementation plan, base commit `68a1694`, and current head. Require findings ordered by severity with file/line references. Resolve every critical or important finding test-first and rerun the complete suite.

- [ ] **Step 3: Request final security review**

Give a fresh `gpt-daybreak-blue-latest` reviewer the final diff and the security criteria from the design. Require explicit checks for independent SQLite evidence, live/source immutability, `sqlite_master` table typing, bounded diagnostics, secret exclusion, mandatory cleanup, cutover separation, and package non-execution. Use `gpt-5.6-terra` only if the security model is unavailable.

- [ ] **Step 4: Commit any reviewed fixes and rerun full verification**

```bash
git status --short
pytest -q
git status --short
```

Expected: tests pass and the worktree is clean after the final reviewed commit.

- [ ] **Step 5: Prepare a new owner package from the clean commit**

Resolve and validate the immutable local inputs, then run the two inert package-preparation primitives:

```bash
OVERSEER_CHECKOUT=$(pwd -P)
OVERSEER_COMMIT=$(git rev-parse HEAD^{commit})
OVERSEER_TREE=$(git rev-parse "${OVERSEER_COMMIT}^{tree}")
OVERSEER_SHORT=$(git rev-parse --short=7 "${OVERSEER_COMMIT}")
OVERSEER_PACKAGE="/home/god/.local/share/overseer/activation-packages/v1.1.6-${OVERSEER_SHORT}"
OVERSEER_PRIOR_PACKAGE=/home/god/.local/share/overseer/activation-packages/v1.1.6-b70dc0c
OVERSEER_PRIOR_RELEASE=$(find "${OVERSEER_PRIOR_PACKAGE}/public/release" -mindepth 1 -maxdepth 1 -type d -print -quit)

test -n "${OVERSEER_PRIOR_RELEASE}"
test ! -e "${OVERSEER_PACKAGE}"
test "$(git status --porcelain)" = ""

PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /usr/bin/python3.13 -B -s -P \
  -m overseer.activation_package stage-sqlite-runtime \
  --source-library /home/god/.local/share/overseer/build-inputs/sqlite-3.53.4-ca4c66d9/libsqlite3.so.0 \
  --package-root "${OVERSEER_PACKAGE}"

nice -n 10 ionice -c 3 env PYTHONDONTWRITEBYTECODE=1 \
  LD_LIBRARY_PATH="${OVERSEER_PACKAGE}/private/runtime-input" \
  PYTHONPATH=src /usr/bin/python3.13 -B -s -P \
  -m overseer.activation_package prepare-package \
  --checkout "${OVERSEER_CHECKOUT}" \
  --expected-commit "${OVERSEER_COMMIT}" \
  --expected-tree "${OVERSEER_TREE}" \
  --dependency-root "${OVERSEER_PRIOR_RELEASE}/site-packages" \
  --root-python /usr/bin/python3.13 \
  --stdlib-root /usr/lib/python3.13 \
  --sqlite-library "${OVERSEER_PACKAGE}/private/runtime-input/libsqlite3.so.0" \
  --templates-root "${OVERSEER_CHECKOUT}/systemd" \
  --package-root "${OVERSEER_PACKAGE}" \
  --psychlo-secret-file /home/god/.config/psychlo/overseer-peer-secret \
  --roadex-secret-file /home/god/.config/overseer/project-human-thread-relay.secret \
  --psychlo-bindings-file /home/god/.config/overseer/psychlo-project-bindings.json \
  --source-store /home/god/Documents/Codex\ Workspace/Overseer/state/overseer.sqlite3 \
  --god-uid "$(id -u god)" --god-gid "$(id -g god)" \
  --overseer-uid "$(id -u overseer)" --overseer-gid "$(id -g overseer)" \
  --rollback-input "v1.1.5-release=${OVERSEER_PRIOR_PACKAGE}/private/rollback-inputs/v1.1.5-release" \
  --rollback-input "v1.1.5-api-unit=${OVERSEER_PRIOR_PACKAGE}/private/rollback-inputs/v1.1.5-api-unit" \
  --rollback-input "v1.1.5-api-dropins=${OVERSEER_PRIOR_PACKAGE}/private/rollback-inputs/v1.1.5-api-dropins" \
  --rollback-input "v1.1.5-python=${OVERSEER_PRIOR_PACKAGE}/private/rollback-inputs/v1.1.5-python" \
  --rollback-input "v1.1.5-runtime-unit=${OVERSEER_PRIOR_PACKAGE}/private/rollback-inputs/v1.1.5-runtime-unit" \
  --rollback-input "v1.1.5-runtime-env=${OVERSEER_PRIOR_PACKAGE}/private/rollback-inputs/v1.1.5-runtime-env" \
  --rollback-input "v1.1.5-approved-activation=${OVERSEER_PRIOR_PACKAGE}/private/rollback-inputs/v1.1.5-approved-activation"
```

Expected: status `awaiting_human_verifiers`. Reuse only local owner-side verifier documents if the package workflow validates that reuse without plaintext; otherwise stop at the hidden interactive verifier gate. Never place secrets in chat, argv, environment, logs, or test output.

- [ ] **Step 6: Independently verify the package tree and digest**

After verifier creation, finalize and independently verify with:

```bash
FINALIZE_JSON=$(PYTHONDONTWRITEBYTECODE=1 \
  LD_LIBRARY_PATH="${OVERSEER_PACKAGE}/private/runtime-input" \
  PYTHONPATH=src /usr/bin/python3.13 -B -s -P \
  -m overseer.activation_package finalize-package \
  --package-root "${OVERSEER_PACKAGE}")
OVERSEER_DIGEST=$(printf '%s' "${FINALIZE_JSON}" | jq -er '.packageDigest')
PYTHONDONTWRITEBYTECODE=1 \
  LD_LIBRARY_PATH="${OVERSEER_PACKAGE}/private/runtime-input" \
  PYTHONPATH=src /usr/bin/python3.13 -B -s -P \
  -m overseer.activation_package verify-package \
  --package-root "${OVERSEER_PACKAGE}" \
  --expected-digest "${OVERSEER_DIGEST}"
```

Confirm migration report status, the complete canary-required schema subset, `sourceMutationPerformed: false`, sealed manifest consistency, and no activation approval files.

- [ ] **Step 7: Confirm the activation boundary**

Read-only checks must prove no archive/import was created, no Phase B or cutover approval exists for the new digest, no staging/canary/cutover command ran, and live services were not restarted.
