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
distinct from incomplete or corrupt persisted sets. The projection is stable
and redacted, includes current exact review-outbox states, and reports both
mutation flags false. The source database bytes, timestamps, and sidecar set
remain unchanged on success and failure.

The loopback API exposes only authenticated admin-token POST preflight, POST
stage, and exact GET status routes. Missing credentials, a server without an
admin token, and authenticated remote-testing tokens cannot access them.
Duplicate, blank, or extra GET parameters and POST query strings fail closed.
Raw bundle POST remains absent. Bundle failures use an allowlisted error code
and never serialize an unexpected exception or path.

The dedicated CLI now adds `bundle-preflight`, `bundle-stage`, and
`bundle-status`, delegating directly to the public helper layer. Its legacy
`stage`, `list`, `approve`, and `execute` commands retain their original
dispatch behavior and execution-adapter boundary.

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

Configured disposable cross-repository acceptance was attempted with
`pytest -q tests/test_donuthole_backup_acceptance.py`. It produced 2 passes and
8 prerequisite failures because `mcp` is not installed and
`THEUNDERDARK_PYTHON` plus `THEUNDERDARK_SOURCE` are unset. No dependency,
environment, source checkout, live database, service, gateway, remote host,
approval, dispatch, provisioning, deployment, restart, push, or host state was
changed.
