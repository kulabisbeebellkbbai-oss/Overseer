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

`bundle_status()` validates one exact plan ID, copies the pinned control-store
bytes through the reviewed no-follow/no-sidecar snapshot boundary, and opens
only the disposable snapshot. It then uses the reviewed bundle, binding,
source, preflight, and outbox loaders/verifier. Missing requested bundles are
distinct from incomplete or corrupt persisted sets: only a missing initial
bundle row is `BUNDLE_NOT_FOUND`; every missing, malformed, or inconsistent
persisted member is `BUNDLE_STATUS_INTEGRITY_ERROR`. Status snapshots are
capped at 64 MiB and one monotonic deadline covers source traversal/open, both
stable reads, temp creation/write/fsync/open, verification/loaders, and cleanup.
Deadline, cap, cleanup, or snapshot instability failures are the single
`BUNDLE_STATUS_UNAVAILABLE` code. Temp cleanup is unconditional. The projection
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
a socket/read deadline, rejects truncated or ambiguous input with 400, returns
413 before reading oversized input, maps not-found/integrity/unavailable to
404/409/503, and maps unexpected failures to a redacted 500. Legacy request
body parsing is unchanged.

The dedicated CLI now adds `bundle-preflight`, `bundle-stage`, and
`bundle-status`, delegating directly to the public helper layer. Bundle intent
files use a capped exact no-follow regular-file descriptor read with stable
before/after identity, one monotonic open/stat/read/JSON/close deadline, and
fail-closed cleanup. New commands emit bounded redacted JSON and use exit 2 for
client-invalid/stale input and exit 1 for not-found, integrity, and unavailable
conditions. Their legacy `stage`, `list`, `approve`, and `execute` commands
retain their original dispatch behavior and execution-adapter boundary.

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

Configured disposable cross-repository acceptance was attempted with
`pytest -q tests/test_donuthole_backup_acceptance.py`. It produced 2 passes and
8 prerequisite failures because `mcp` is not installed and
`THEUNDERDARK_PYTHON` plus `THEUNDERDARK_SOURCE` are unset. No dependency,
environment, source checkout, live database, service, gateway, remote host,
approval, dispatch, provisioning, deployment, restart, push, or host state was
changed.
