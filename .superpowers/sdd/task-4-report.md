# Task 4 Report: Public Provisioning Bundle Interfaces

## Scope

Capability B Task 4 exposes the reviewed Task 3 server-owned preflight,
authoritative stage, and exact persisted-status boundaries through narrow helper,
HTTP, and CLI surfaces. It does not add approval, dispatch, provisioning,
execution, deployment, service, gateway, remote-host, or host-mutation behavior.

## Initial RED evidence

- `python3 -m py_compile tests/test_provisioning_bundle.py && pytest -q
  tests/test_provisioning_bundle.py -k 'bundle_api or bundle_cli or
  bundle_status'` — 9 failed, 166 deselected. The failures were the expected
  missing `preflight_bundle_api`, `stage_bundle_api`, and `bundle_status`
  interfaces and missing `bundle-preflight` CLI command.

Production files were unchanged before this RED run.

- Surface RED: `python3 -m py_compile tests/test_core.py
  tests/test_provisioning_bundle.py && pytest -q tests/test_core.py
  tests/test_provisioning_bundle.py -k 'public_bundle_routes or bundle_cli'` —
  3 failed, 553 deselected. Both authenticated bundle POST routes were missing,
  the redaction case returned 404 instead of a bounded error, and the CLI
  rejected `bundle-preflight` as an unknown command. `api.py` and the CLI were
  unchanged before this run.

## Reviewer correction RED evidence

- Explicitly committed and closed persisted-member deletion regressions,
  snapshot size/deadline/cleanup tests, unstable and unbounded CLI file tests,
  CLI helper failure/exit/redaction tests: 27 expected failures.
- Exact bundle request length/deadline and HTTP error mapping tests: 4 expected
  failures. Missing or negative lengths reached the handler, oversized lengths
  were not 413, the bundle reader had no socket deadline, operational failures
  were 400, and unexpected exceptions were not 500.
- One-deadline CLI open/stat/read/JSON/close tests plus fail-closed ordinary
  descriptor-close handling: 6 expected failures. The existing BaseException
  cleanup test already passed.

No corresponding production behavior was changed before each correction RED
run.

## Final reviewer correction RED evidence

- The pinned-status and realistic-cap selection produced 8 expected failures:
  the old 64 MiB cap rejected a valid 70 MiB SQLite database, status still
  copied the database into one bytes object twice, the read-only store helper
  and progress handler were absent, and deadline/close hooks were absent.
- The HTTP framing/deadline selection produced 3 expected failures:
  `Transfer-Encoding` and `Trailer` reached the helper, and the reader still
  used buffered `read(length)` instead of partial reads with exact remaining
  timeouts and BaseException restoration. The real slow-trickle platform test
  was already bounded by the kernel socket timeout, while the deterministic
  partial-reader tests exposed the missing aggregate-deadline semantics.
- A disposable `/proc/self/fd/<O_NOATIME fd>` probe proved same-inode SQLite
  access, `mode=ro&immutable=1`, query-only mode, zero busy timeout, and no
  sidecars. A realistic freshly-written-database test then correctly exposed
  that SQLite reopens the proc-fd target without `O_NOATIME` and changes source
  atime. That direct-source proc-fd design was discarded; this diagnostic is
  superseded by the final disposable pinned proc-fd plus actual-SQLite-fd audit.
  Replacement fixed-buffer streaming tests produced 8 expected failures before
  the fallback was implemented.
- The final deadline/progress-cleanup selection produced 4 expected failures:
  the deadline was only 10 seconds, the progress handler was installed after
  PRAGMAs, and ordinary or BaseException progress-handler cleanup failure
  skipped connection close.
- The final ownership/TOCTOU correction produced 3 expected focused failures:
  SQLite opened the disposable by its visible `/tmp` pathname, deterministic
  replacement changed the queried database, and a fail-once temp-descriptor
  close during partial streaming lost ownership. Production code was unchanged
  before this RED run.

## Outcome

The helper boundary now accepts only the exact public shapes. Preflight parses
one typed intent mapping and constructs a fresh server-owned bundle preview.
Its deterministic redacted projection contains the request, plan, bundle, and
preflight identifiers and exact plan/preflight/bundle digests, with both
mutation flags false. Stage accepts only the intent and two expected digests,
validates their shape before authority reads, builds a fresh preview solely to
derive the code-owned plan digest, constructs an exact
`ProvisioningPreviewDigests`, and calls the reviewed three-argument
`stage_authoritative_bundle()`. A second server-owned rebuild inside that
function remains authoritative; mismatch is returned only as
`AUTHORITATIVE_REBUILD_MISMATCH`, before persistence.

`bundle_status()` validates one exact plan ID and opens the source once through
the reviewed no-follow/no-sidecar `O_NOATIME` descriptor boundary. It streams
the source in fixed 1 MiB buffers into a private disposable file, hashes while
copying, and hashes the source again after queries without ever constructing a
whole-database bytes object. One outer resource object exists before acquisition
and owns every partial source fd, parent fd, temp fd/path, SQLite connection,
read-only store, and audited SQLite database fd as each becomes available. The
streaming helper accepts caller-owned resources and performs no cleanup.

The disposable fd remains open and pinned through SQLite open. SQLite receives
only `file:/proc/self/fd/<temp-fd>?mode=ro&immutable=1`. Descriptor snapshots
before and after `sqlite3.connect` identify and record the actual SQLite DB fd
whose device/inode/mode/size matches the pinned disposable. That exact fd is
re-fstat'd after all status queries and before close, while the pinned bytes and
identity are re-hashed and checked. Replacement before open, or replacement
that is restored after SQLite opens it, therefore fails closed and cannot
influence a returned status. An owned pathname is unlinked only when its current
regular-file device/inode still matches the pinned snapshot; a different
replacement inode is never removed as owned cleanup.

The code-owned 2 GiB database cap is above the current 778,797,056-byte
authoritative store, and the 60-second aggregate deadline covers traversal,
both streaming passes, temp write/fsync/open, queries, verification, close, and
cleanup. The private SQLite connection is query-only, zero-busy-timeout, and
installs a deadline progress handler before PRAGMA/query work. It bypasses all
`SQLiteStore` initialization, migration, hardening, and write lifecycle while
reusing the exact Task 3 loader methods through a private read-only subclass.
The indexed loader queries and SQLite progress handler bound database work.

It then uses the reviewed bundle, binding,
source, preflight, and outbox loaders/verifier. Missing requested bundles are
distinct from incomplete or corrupt persisted sets: only a missing initial
bundle row is `BUNDLE_NOT_FOUND`; every missing, malformed, or inconsistent
persisted member is `BUNDLE_STATUS_INTEGRITY_ERROR`. Deadline, cap, progress,
hash mismatch, sidecar, identity/metadata drift, close, or cleanup failures are
the single `BUNDLE_STATUS_UNAVAILABLE` code. Cleanup independently attempts
progress clear, SQLite close, temp-fd close, temp unlink, source-fd close, and
parent-fd close; it retries each cleanup once and continues after ordinary or
fatal failures. Persistent ordinary and fatal cleanup failures are retained
separately: an earlier fatal primary is preserved, while fatal cleanup outranks
an ordinary primary. The connection must close successfully before return. The
projection is stable and redacted, includes current exact review-outbox states,
and reports both mutation flags false. The source database bytes, timestamps,
and sidecar set remain unchanged on success and failure.

The loopback API exposes only authenticated admin-token POST preflight, POST
stage, and exact GET status routes. Missing credentials, a server without an
admin token, and authenticated remote-testing tokens cannot access them.
Duplicate, blank, or extra GET parameters and POST query strings fail closed.
Raw bundle POST remains absent. Bundle failures use an allowlisted error code
and never serialize an unexpected exception or path. Bundle POST alone now
requires one exact nonnegative `Content-Length`, caps bodies at 64 KiB, applies
one aggregate socket/read deadline, and uses bounded `read1` partial reads. It
sets the socket timeout to the exact remaining monotonic time before every
partial read and restores the prior timeout on success, error, or BaseException.
Any `Transfer-Encoding` or `Trailer` framing metadata is rejected before body
read or helper invocation. Truncated or ambiguous input returns 400, oversized
input returns 413 before body read, not-found/integrity/unavailable map to
404/409/503, and unexpected failures map to a redacted 500. Legacy request body
parsing is unchanged.

The dedicated CLI now adds `bundle-preflight`, `bundle-stage`, and
`bundle-status`, delegating directly to the public helper layer. Bundle intent
files use a capped exact no-follow regular-file descriptor read with stable
before/after identity, one monotonic open/stat/read/JSON/close deadline, and
fail-closed cleanup. New commands emit bounded redacted JSON and use exit 2 for
client-invalid/stale input and exit 1 for not-found, integrity, and unavailable
conditions. Their legacy `stage`, `list`, `approve`, and `execute` commands
retain their original dispatch behavior and execution-adapter boundary.

The CLI filesystem deadline remains elapsed-time fail-closed around every
bounded open/stat/pread/JSON/close operation. A hard `SIGALRM` boundary is not
safe here: `main()` is also a callable library entry point used in worker
threads and shared test/process contexts, while POSIX signal handlers and
timers are process-global and main-thread-only. Installing one could interrupt
unrelated work or corrupt a caller's timer state. A helper process would add a
new process/protocol boundary disproportionate to a 64 KiB stable regular-file
read. Size, exact identity, no-follow, incremental pread, elapsed deadline, and
fail-closed cleanup bounds are therefore retained without claiming preemption.

## GREEN verification

- Integrated helper/API/CLI/authentication/redaction/status selection — 23
  passed, 537 deselected.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning.py`
  — 212 passed before the final two route/signature test additions.
- Core authentication, backup, and legacy-route selection — 4 passed, 369
  deselected.
- Full Task 3/4 touched suite excluding only the documented unrelated Roadex
  digest fixture assertion — 722 passed, 1 deselected in 83.87 seconds.
- Python compilation and `git diff --check` are included in the final commit
  gate below.

Reviewer correction verification:

- Expanded correction selection: 45 passed, 557 deselected.
- Bundle-focused API/status/CLI selection: 233 passed, 369 deselected.
- Full provisioning suites: 253 passed.
- Full touched core and provisioning suites: 630 passed in 83.90 seconds.
- Deterministic CLI deadline/close verification: 7 passed, 213 deselected.

Final reviewer correction verification:

- Status fallback/cap/deadline/progress/cleanup selection: 15 passed.
- HTTP framing, partial-read, timeout-restoration, and slow-trickle selection:
  5 passed.
- All status and CLI tests: 50 passed; all core bundle-route tests: 12 passed.
- Full provisioning suites: 259 passed.
- Established four-file touched suite excluding the documented unrelated
  Roadex digest fixture: 777 passed, 1 deselected in 89.99 seconds.

Final ownership/TOCTOU correction verification:

- Focused status selection — 35 passed, 204 deselected.
- Full provisioning suites — 267 passed.
- Established four-file touched suite excluding the documented unrelated
  Roadex digest fixture — 783 passed, 1 deselected in 89.85 seconds.
- Python compilation and `git diff --check` are included in the final commit
  gate.

Earlier acceptance attempts with unset variables or the wrong TheUnderdark
source root produced prerequisite/import failures; those results are retained
only as superseded diagnostic history. The authoritative final configured
disposable acceptance was:

```bash
THEUNDERDARK_PYTHON='/home/god/Documents/Codex Workspace/TheUnderdark/.venv/bin/python'
THEUNDERDARK_SOURCE='/home/god/Documents/Codex Workspace/TheUnderdark/.worktrees/donuthole-contract-acceptance'
'/home/god/Documents/Codex Workspace/TheUnderdark/.venv/bin/python' -m pytest -q tests/test_donuthole_backup_acceptance.py
```

Result: 10 passed in 6.58 seconds. No dependency, source checkout, live
database, service, gateway, remote host, approval, dispatch, provisioning,
deployment, restart, push, or external state was changed.
