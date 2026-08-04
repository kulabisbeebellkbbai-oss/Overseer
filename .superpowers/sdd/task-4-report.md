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
  atime. The proc-fd design was discarded. Replacement fixed-buffer streaming
  tests produced 8 expected failures before the fallback was implemented.
- The final deadline/progress-cleanup selection produced 4 expected failures:
  the deadline was only 10 seconds, the progress handler was installed after
  PRAGMAs, and ordinary or BaseException progress-handler cleanup failure
  skipped connection close.

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
the reviewed no-follow/no-sidecar `O_NOATIME` descriptor boundary. Because the
platform's SQLite proc-fd reopen changes source atime, it uses the explicitly
allowed fallback: a 1 MiB fixed-buffer stream into a private disposable file,
with incremental SHA-256 while copying and a second incremental source hash
after queries. It never creates a whole-database bytes object. The code-owned
2 GiB database cap is above the current 778,797,056-byte authoritative store,
and the 60-second aggregate deadline covers traversal, both streaming passes,
temp write/fsync/open, queries, verification, close, and cleanup. The private
SQLite connection is `mode=ro&immutable=1`, query-only, zero-busy-timeout, and
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
the single `BUNDLE_STATUS_UNAVAILABLE` code. Temp cleanup is unconditional and
the read-only SQLite connection must close successfully before return. The projection
is stable and redacted, includes current exact review-outbox states, and reports
both mutation flags false. The source database bytes, timestamps, and sidecar
set remain unchanged on success and failure.

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

Configured disposable cross-repository acceptance was attempted with
`pytest -q tests/test_donuthole_backup_acceptance.py`. It produced 2 passes and
8 prerequisite failures because `mcp` is not installed and
`THEUNDERDARK_PYTHON` plus `THEUNDERDARK_SOURCE` are unset. No dependency,
environment, source checkout, live database, service, gateway, remote host,
approval, dispatch, provisioning, deployment, restart, push, or host state was
changed.

The configured acceptance was also rerun through the available TheUnderdark
virtual environment with explicit `THEUNDERDARK_PYTHON` and
`THEUNDERDARK_SOURCE`. It produced 3 passes and 7 failures. MCP discovery now
passes; the seven disposable composition scenarios are blocked because the
current TheUnderdark `tests/test_backup_production_integration.py` no longer
exports the expected `build_real_service` builder. No checkout, dependency,
environment, or external state was changed.
