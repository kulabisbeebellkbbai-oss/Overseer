# Task 9 Independent Review — approved after correction

## Scope and review boundary

Reviewed `92be49a` and `7c07406` against parent `4ff624a` in the isolated
`feature/overseer-v1-1-autonomous-operations` worktree. This review did not
install, reload, enable, start, stop, restart, or otherwise modify a live unit,
store, gateway, timer, or external project.

## Prior findings — resolved by the correction

### Important — the source unit cannot start with the documented portable environment

- **Location:** `systemd/overseer.service:8-9`,
  `tests/test_collection_systemd.py:13,33`, and
  `docs/v1.1-operations.md:22-34`.
- **Evidence:** `systemd-analyze verify systemd/overseer.service` exits nonzero
  with `overseer.service: Command ${OVERSEER_PYTHON} is not executable: No such
  file or directory`.
- **Impact:** systemd requires a literal executable for `ExecStart` argv zero;
  an environment variable cannot be that executable. `Environment=` also does
  not expand `${OVERSEER_INSTALL}` into `PYTHONPATH`, so the documented source
  checkout is not importable as claimed. The green test only asserts those
  invalid literal strings, so it preserves the fault.
- **Required portable fix:** keep `EnvironmentFile=`, use a literal launcher,
  for example
  `ExecStart=/usr/bin/env ${OVERSEER_PYTHON} -m overseer.cli run --store ${OVERSEER_STORE}`.
  Put a resolved absolute `PYTHONPATH=/absolute/path/to/Overseer/src` in the
  0600 environment file (rather than deriving it with `Environment=`), then
  update the source-unit contract test and all environment-file documentation.
  The no-listener, no-legacy-bulk-flag, and no-install properties must remain.
- **Safe validation:** a disposable unit with that literal `/usr/bin/env`
  launcher and a local `runtime.env` passed
  `systemd-analyze verify /tmp/overseer-task9-review/overseer.service` with exit
  status zero. No unit was installed or activated.

### Important — the canary/migration/activation documentation is not executable enough for the required gate

- **Location:** `docs/v1.1-operations.md:132-165`.
- **Evidence:** the section identifies necessary outcomes, but it provides no
  exact command sequence for a WAL-safe disposable SQLite copy, migration/open,
  `seed-collection-jobs`, scheduler `run --once` canary, status/queue checks,
  post-activation verification, or rollback. Step 4 says the future plan must
  name those commands instead of supplying reviewed source commands.
- **Impact:** an operator cannot reproduce the requested disposable-store
  canary or prove the required migration and forensic boundaries before a
  separately approved activation. A naive file copy can omit active SQLite WAL
  state, undermining the stated preservation requirement.
- **Required fix:** document a source-safe, read-only/recoverable canary
  procedure with explicit placeholder variables and commands, including the
  SQLite backup/copy method that preserves WAL-consistent state; exact
  migration/seed and `run --once` commands; expected bounded status/queue
  evidence; the reviewed unit rendering/hash validation; explicit live
  verification commands; rollback inputs/commands; and preservation locations
  for the database, `-wal`, `-shm`, journal, logs, migrations, hashes, and
  approval/audit evidence. Keep actual installation, daemon reload, and service
  activation behind the separately approved plan.

## Verified requirements outside the findings

- `pytest -q tests/test_collection_systemd.py tests/test_collection_runtime.py
  tests/test_collection_api.py tests/test_performance_regression.py` passed
  (`39 passed`).
- `git diff --check 4ff624a..7c07406` passed; the task diff contains only the
  promised unit, tests, README, and operations documentation.
- The unit invokes the autonomous `overseer.cli run` command with an explicit
  store and contains neither an API listener nor legacy bulk collector flags.
  CLI help confirms those flags are retained only as deprecated family
  selectors, not service-unit inputs.
- The CLI exposes `collection-scheduler-status`, `request-collection-run`, and
  `seed-collection-jobs`; the runtime uses the bounded scheduler and durable
  status/queue surfaces.
- Existing `overseer-psychlo-*` and `overseer-quark-scheduler.*` service/timer
  sources were inspected and `systemd-analyze verify` passed for the selected
  pairs. Task 9 does not modify them; v1.1 documents freshness observation
  rather than duplicate ownership.
- Documentation correctly keeps API serving separate, preserves gateway-prefix
  compatibility and external-project non-mutation boundaries, and states the
  low-risk versus approval-required repair boundary.

## Correction re-review: `856497c` and `0a74029`

### Findings

No Blocking, Critical, or Important findings remain in the corrected Task 9
scope.

- **Resolved unit portability finding:** `systemd/overseer.service:8-9` now
  uses literal `/usr/bin/test` for the installation check and literal
  `/usr/bin/env --` as `ExecStart` argv zero. Fully resolved `PYTHONPATH` is
  supplied by the 0600 environment file rather than recursively derived in
  `Environment=`. Real `systemd-analyze verify systemd/overseer.service`
  completed with exit status zero; the disposable verifier contract also runs
  `systemd-analyze` without installing a unit.
- **Resolved reproducibility finding:**
  `docs/v1.1-operations.md:141-335` provides an exact placeholder-bound,
  WAL-consistent disposable canary. It uses SQLite's read-only online backup,
  refuses canary overwrite, seeds/migrates only the disposable store, disables
  every unsafe collector before `run --once`, and records bounded scheduler,
  queue/coalescing, status, and checksum evidence.
- **Activation and rollback contract:**
  `docs/v1.1-operations.md:338-711` keeps all mutating commands explicitly
  approval-bound. It captures prior unit/environment manifests at
  `$OVERSEER_ROLLBACK_ROOT/prior-config.sha256`, stores the canonical backup
  manifest at `$OVERSEER_ROLLBACK_ROOT/pre-v1.1.sqlite3.sha256`, captures raw
  stopped database-sidecar evidence in `$OVERSEER_ROLLBACK_ROOT/prior-store.sha256`,
  and verifies forensic manifests under `$OVERSEER_FORENSIC_ROOT`. Rollback
  independently restores runtime enablement, runtime activity, and API
  activity, failing closed for unsupported prior states.
- **Secret and compatibility boundary:** prefix verification reads the token
  internally from its path and uses `urllib.request`; no bearer token is placed
  in shell argv or emitted into the documented output. The runbook continues
  to prohibit live changes before approval and preserves Psychlo/Quark external
  timer ownership, gateway-prefix/API compatibility, and external-project
  non-mutation boundaries.

### Re-review evidence

- `systemd-analyze verify systemd/overseer.service`: passed (exit status zero).
- `PYTHONPATH=src pytest -q tests/test_collection_systemd.py
  tests/test_collection_runtime.py tests/test_collection_api.py
  tests/test_performance_regression.py`: `41 passed`.
- `git diff --check 79983c7..0a74029`: passed. The correction touches only the
  source unit, its tests, README/runtime/runbook documentation, and Task 9
  evidence; it does not modify a live unit/store/service or any external
  project.

## Decision and residual activation risks

Task 9 is **APPROVED** as corrected source and documentation. This approval is
not authorization to activate it. A separately approved, exact live change
plan and successful disposable-store canary remain required before any unit
installation, daemon reload, migration, enablement, start, restart, or rollback
operation. This source review does not establish live interpreter, store,
API-process, existing-timer, filesystem-permission, or rollback-artifact
readiness on the host.
