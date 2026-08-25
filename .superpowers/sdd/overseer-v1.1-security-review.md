# Overseer v1.1 Final Defensive Security Re-review

## Verdict

**APPROVED** at final reviewed head
`08bafba756caa35b6cbacb73b8d223b7bafbac3a`.

No release-blocking security finding remains in the reviewed range. This is
approval of the reviewed source and operating procedure, not authorization to
install, migrate, start, restart, enable, or expose a live service. Live
activation remains subject to the exact approval-only procedure in
`docs/v1.1-operations.md`.

## Scope and constraints

- Branch: `feature/overseer-v1-1-autonomous-operations`
- Review base: `24dd06f`
- Review head: `08bafba756caa35b6cbacb73b8d223b7bafbac3a`
- Reviewed the complete `24dd06f..08bafba` range, including the previously
  approved source at `a3ef611`, the documentation correction at `e6fcb20`,
  the release-identity metadata/test delta at `24cc860`, and the regenerated
  tracked egg-info at `08bafba`.
- Reassessed collection policy, reseeding, scheduler claims and leases, repair,
  API limits, systemd/activation provenance, Psychlo, Roadex, Codex delivery,
  Protected Gateway prefix behavior, secret handling, and mutation gates.
- Used repository-local tests, disposable SQLite stores, and disposable
  loopback HTTP servers only.
- Did not modify source, live services, live stores, user configuration,
  gateway/firewall/IDS policy, or external projects. This report is the only
  review artifact changed and it was not committed.

## Remediation matrix

| Finding | Status | Defensive verification |
|---|---|---|
| SEC-01: unsafe action families enabled by default | Remediated | Fresh `crew_dispatch`, `usage_continuation`, `knowledge_capture`, and `station_audit` jobs are created disabled. Deprecated runtime flags cannot authorize them. An already enabled job remains enabled only as durable pre-existing policy; fresh/default service startup cannot manufacture that authorization. Collection resume/suspend remains an admin-token control and records a durable policy-transition audit; its bounded requester/reason strings are validated context, not persisted identity evidence. |
| SEC-02: reseeding reversed suspension | Remediated | Definition refresh copies the existing enabled state and does not replace scheduler state. Active lease ID/generation survive refresh. Suspended action jobs remain suspended, explicitly authorized jobs remain enabled, and jobs for disabled health targets remain disabled. |
| SEC-03: candidate/claim divergence and cross-process key race | Remediated | The scheduler passes the exact selected job ID into the store claim. The `BEGIN IMMEDIATE` claim transaction selects and leases that exact row and excludes any unexpired lease sharing its concurrency key across SQLite connections. Expired leases produce failure/incident evidence before reclaim; exact lease generation fences stale completion. |
| SEC-04: dirty-source activation | Remediated | The runbook rejects tracked, untracked, and matching ignored entries; binds commit and tree IDs; verifies a tracked-source hash manifest; binds interpreter, sorted dependency snapshot, exact environment file, source unit, and rendered unit; and repeats source/config/dependency checks immediately before service start. |
| SEC-05: unbounded HTTP body/thread handling | Remediated | JSON requests require one decimal `Content-Length`, reject missing/duplicate/invalid/oversized lengths before reading, use bounded header/body/connection timeouts, and run under a bounded handler semaphore with deterministic overload rejection. Root and `/Overseer` collection/general JSON routes share the same limits. |

## Verification evidence

Repository identity and hygiene:

```text
git rev-parse HEAD
08bafba756caa35b6cbacb73b8d223b7bafbac3a

git rev-parse --abbrev-ref HEAD
feature/overseer-v1-1-autonomous-operations

git diff --check 24dd06f..08bafba
exit 0

git diff --check a3ef611..08bafba
exit 0
```

The post-approval range contains these narrow commits:

```text
git show --stat e6fcb20
docs/v1.1-operations.md | 4 +++-

git show --stat 24cc860
README.md                            |  4 +++-
pyproject.toml                       |  2 +-
src/overseer/codex_usage.py          |  6 +++---
src/overseer_local.egg-info/PKG-INFO |  6 ++++--
tests/test_release_metadata.py       | 20 ++++++++++++++++++++

git show --stat 08bafba
src/overseer_local.egg-info/PKG-INFO         |  45 ++++++++++--
src/overseer_local.egg-info/SOURCES.txt      | 106 ++++++++++++++++++++++++++-
src/overseer_local.egg-info/entry_points.txt |   3 +
src/overseer_local.egg-info/requires.txt     |   4 +
```

It replaces the inaccurate statement that policy-control requester/reason
strings are persisted evidence. The corrected runbook now matches the
implementation: the admin token authorizes the control, the state transition
has a durable audit, and requester/reason are bounded validated context that
must not contain secrets and are not persisted as identity evidence.

The release-identity commit consistently sets `1.1.0` in the canonical
`pyproject.toml` project version, tracked `PKG-INFO` version header, README
release statement, and the Codex usage, meter, and structured-dispatch
`clientInfo` payloads. It does not change client names, JSON-RPC methods,
capabilities, subprocess commands, environment allowlisting, transport,
authentication, thread identity, delivery proof, or any approval boundary.

Commit `08bafba` changes only tracked generated egg-info. A fresh build from a
tracked-only `git archive` excluded the committed egg-info before generation
and used pip's temporary isolated build environment with `--no-deps` and
`--no-cache-dir`; it did not install Overseer or alter the host interpreter.
The resulting `PKG-INFO`, `SOURCES.txt`, `entry_points.txt`, and `requires.txt`
were byte-for-byte identical to the committed files. Parsed dependencies and
console entry points match `pyproject.toml`, the `PKG-INFO` description matches
`README.md`, every path listed by `SOURCES.txt` exists, and the wheel filename
and embedded metadata retain release identity `1.1.0`.

An auxiliary source-completeness assertion initially failed only because
setuptools' generated `SOURCES.txt` omits `tests/__init__.py`. This is not a
generation mismatch: a clean regeneration produced the identical manifest,
and the wheel does not package the test tree as runtime code.

Fresh exact-head release metadata command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:cacheprovider \
  tests/test_release_metadata.py
```

Result: `1 passed in 0.20s`. The test count was independently validated
through `calculator.calculate_arithmetic` (`1 + 0 = 1`).

Fresh final-head release/Codex usage command:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:cacheprovider \
  tests/test_release_metadata.py tests/test_codex_usage.py
```

Result: `19 passed in 0.27s`. The test count was independently validated
through `calculator.calculate_arithmetic` (`19 + 0 = 19`).

Documentation-correction regression command at `e6fcb20`:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:cacheprovider \
  tests/test_collection_systemd.py tests/test_collection_runtime.py
```

Result: `22 passed in 1.42s`. The test count was independently validated
through `calculator.calculate_arithmetic` (`22 + 0 = 22`).

The prior full targeted local/read-only security command at the
security-boundary-equivalent source `a3ef611` was:

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:cacheprovider \
  tests/test_collection_policy.py \
  tests/test_collection_store.py \
  tests/test_collection_scheduler.py \
  tests/test_collection_runtime.py \
  tests/test_collection_repair.py \
  tests/test_collection_api.py \
  tests/test_collection_systemd.py \
  tests/test_performance_regression.py \
  tests/test_psychlo_bridge.py \
  tests/test_psychlo_decision_reconcile.py \
  tests/test_roadex_approval_fixture.py \
  tests/test_codex_dispatch_activation.py \
  tests/test_api_store_binding.py \
  tests/test_core.py
```

Result: `879 passed in 145.27s`. The test count was independently validated
through `calculator.calculate_arithmetic` (`879 + 0 = 879`).

Additional disposable socket probes shortened the configured timeout only in
the test process and verified:

- incomplete headers are closed at the header deadline;
- a partial root-prefix JSON body returns `400 request_body_timeout`;
- a partial `/Overseer` JSON body returns `400 request_body_timeout`.

All three probes passed. The probe count was independently validated through
`calculator.calculate_arithmetic` (`3 + 0 = 3`). The focused systemd test also
ran a real disposable `systemd-analyze verify` without installing or reloading
a unit.

## Defensive reassessment

### Release metadata and Codex usage boundary

The exact `a3ef611..08bafba` diff contains the documentation correction,
release metadata, informational Codex `clientInfo.version` literals, README
wording, release tests, and regenerated egg-info only. The generated metadata
now agrees with canonical `pyproject.toml` and `README.md`, including version,
dependencies, optional test dependency, console entry points, description,
and source manifest generation. The Codex app-server clients still send the
same names and empty capabilities over the same bounded subprocess/JSON-RPC
paths. No executable source, token handling, environment forwarding, method
selection, thread binding, prompt delivery identity, authority, approval,
transport, or mutation logic changed.

### Scheduler leases and stale workers

Exact candidate claims and cross-connection concurrency-key exclusion are now
transactional. A stale worker cannot commit a completion after its lease has
been reclaimed because completion requires the exact current lease ID and
generation. A timed-out worker retains its lease while the local future is
still running, and the same concurrency key remains unavailable until that
worker exits or the durable lease expires.

SQLite fencing cannot stop code that is already executing. After the
five-minute lease grace expires, a second process may reclaim work while a
non-cooperative stale callback still exists. The packaged single-instance
service, disabled-by-default unsafe families, bounded callback batches, and
idempotent/exact authority records reduce this risk, but mutating integration
callbacks must continue to use idempotency keys and side-effect fencing.

### Approval, IDS, host, and external-project gates

- The packaged runtime cannot enable action families by seeding or by legacy
  flags. Enabling one is a separate admin-authorized durable policy action.
- Explicit-approval admin plans remain exact-plan bound. Firewall/network work
  still requires accepted IDS evidence and the existing approval/adapter gates.
- Automatic repair is limited to exact preapproved low-risk read-only retry or
  bounded evidence pruning. A service restart repair stages a plan and returns
  `approval_required`; it does not restart a service inline.
- Existing action-family integrations can perform their established operations
  only after that family has been durably enabled. This broad enablement must be
  treated as operational authorization, not as a harmless monitoring toggle.
- No code in this review changed another project, its service, or its store.

### Secrets, paths, request bodies, and logs

Collection runs persist bounded outcome labels rather than adapter summaries,
tracebacks, response bodies, or raw command output. API projections do not echo
collection-request reasons. Token files remain outside argv in the operating
procedure, environment permissions are checked, and the API remains loopback
only.

Queue-run request reasons are durable database content. They are bounded and
not returned by collection projections, but operators must not put tokens,
passwords, private keys, or other secrets in those fields. In contrast, the
generic suspend/resume policy transition records the durable state-transition
audit but does not retain its caller-supplied requester/reason strings. Commit
`e6fcb20` now documents that distinction accurately and does not describe
those strings as identity or authorization evidence.

### Psychlo signatures and replay

Psychlo requests retain exact authority, content-length, kind, message ID,
timestamp, nonce, body, and HMAC binding. Request nonces are claimed durably.
Responses bind the triggering request message ID, request nonce, request body
digest, response timestamp, and response nonce; the active sender supplies a
nonce claimer. Replaying an old response against a new request fails because
the newly generated request nonce and digest binding differ. Generic callers of
the low-level response verifier must continue to provide a nonce claimer for a
trust-bearing flow.

### Roadex authority and Codex delivery identity

Roadex human decisions require the exact staged record and pre-existing bound
ROLE approval. Claim, resource, owner domain, approval level, subject, deciding
identity, and independent human/admin token boundaries remain checked before
activation. The Codex dispatch path continues to require the approved existing
conversation/source binding and exact delivery identity; caller-supplied source
roots or manifests cannot create authority. The targeted identity and
reconciliation suites passed.

### Protected Gateway compatibility

Collection GET/control routes and their authentication, bounded body handling,
deprecation successor links, and client construction work through both the root
path and `/Overseer`. Raw custom-HMAC Psychlo/Roadex transport endpoints remain
exact-path protocols by design; a gateway must preserve their signed authority
and path contract rather than silently prefix-rewrite them.

## Remaining non-blocking risks and operational conditions

1. The current development worktree contains ignored caches and review
   artifacts. The new `--ignored=matching` provenance check correctly rejects
   it as an activation source. Activation must use a clean reviewed deployment
   tree whose commit, tree, tracked manifest, interpreter, dependencies,
   environment, and rendered unit match the approved evidence.
2. A sorted `pip freeze` hash binds the reviewed dependency inventory, not every
   byte in site-packages. Use a dedicated immutable environment and preserve
   package-manager/wheel provenance if stronger supply-chain attestation is
   required.
3. Duplicate manually started runtimes remain an operational hazard after lease
   expiry for non-cancellable callbacks. Keep one managed runtime instance and
   require idempotent side-effect contracts for any explicitly enabled action
   family.
4. Admin bearer tokens authorize policy controls but do not provide strong
   per-human attribution. The durable transition audit proves the state change,
   not the real-world identity behind a shared token.
5. Generic JSON endpoints rely on the local/protected gateway to normalize or
   reject ambiguous transfer-encoding combinations. Keep the backend loopback
   only and preserve the gateway's strict request-framing policy.
## Approval gate

**APPROVED for Overseer v1.1 source/release preparation at exact final reviewed
head `08bafba756caa35b6cbacb73b8d223b7bafbac3a`.**

**Not approved by this review:** installation, migration of the live store,
service start/restart/enablement, gateway or firewall changes, or mutation of
external projects. Those remain separate exact-plan approval and verification
steps.
