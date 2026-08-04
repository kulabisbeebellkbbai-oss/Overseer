# Delta Task 3 implementation and correction report

## Scope and ownership

Implemented the typed-staging transport boundary across the two isolated
worktrees:

- Overseer: `src/overseer/api.py`, `tests/test_core.py`,
  `tests/test_ui_regression.py`.
- Roadex: `src/server/approvalWorkflowMcp.ts`,
  `src/server/approvalWorkflowHost.ts`, `src/server/sessionService.ts`, and
  their matching tests.

The established Roadex status provider, coordinator, and continuation files
were not modified. No main checkout, DonutHole checkout, live store/service,
approval, deployment, protected host, gateway, firewall/IDS, or push was
touched.

## RED/GREEN evidence

Tests were added before the corresponding implementation changes.

### Overseer

RED:

```text
python3 -m pytest -q tests/test_core.py -k roadex_stage_locator_is_derived_from_persisted_binding
1 failed, 382 deselected
AttributeError: module 'overseer.api' has no attribute 'stage_roadex_approval_api'
```

GREEN:

```text
python3 -m pytest -q tests/test_core.py -k roadex_stage_locator_is_derived_from_persisted_binding
1 passed, 382 deselected

python3 -m pytest -q tests/test_ui_regression.py -k roadex_typed_stage_rejects_caller_supplied_locator_fields
1 passed, 25 deselected
```

The API test patches the staged result with caller-overridden-looking values
and verifies that the returned locator is reconstructed from the persisted
binding instead. The protected route test verifies that caller-supplied
locator fields are rejected.

### Roadex

RED:

```text
npm test -- --run tests/approvalWorkflowHost.test.ts -t 'stages typed intent|locator scope differs'
2 failed, 9 skipped
Expected typed-intent requests were rejected as request_invalid before the
adapter existed.
```

GREEN:

```text
npm test -- --run tests/approvalWorkflowHost.test.ts -t 'stages typed intent|locator scope differs'
2 passed, 9 skipped

npm test -- --run tests/approvalWorkflowMcp.test.ts -t 'submits typed intent|caller-supplied approval'
2 passed, 8 skipped

npm test -- --run tests/sessionService.test.ts -t 'keeps typed staging'
1 passed, 87 skipped
```

The host tests verify typed intent submission, registration using only the
returned `{provider, approvalRef}`, and fail-closed scope mismatch. The MCP
tests verify that approval, authorization, evidence, crew, execution, and
source-status fields cannot be supplied by the caller. The session test
verifies staging is an injected transport and does not create Roadex approval
state.

Existing lifecycle/status/coordinator/continuation coverage remained green,
including read-only polling, exactly-once same-thread continuation, revision,
rejection, provider delay, session close, ambiguous dispatch, and restart
recovery cases.

## Implementation summary

Overseer now exposes `POST /roadex/approval-stage`. It accepts exactly one
typed `intent`, internally performs the authoritative preflight and stage with
server-owned preview digests, loads the resulting persisted binding, and
returns only the normalized exact locator. No caller-provided authorization
reference, evidence digest, crew identifier, approval field, execution field,
or source status is accepted at this boundary.

Roadex now submits only typed intent through the MCP adapter. The workflow host
requires an authoritative staged locator, validates its exact shape and
project/workspace/resource scope against the managed run, and passes only the
returned provider/reference pair into the existing coordinator. Roadex does
not persist a parallel approval lifecycle or decision record.

## Verification

Required Roadex commands:

```text
npm test -- tests/approvalLifecycleIntegration.test.ts tests/approvalStatusProvider.test.ts tests/approvalCoordinator.test.ts tests/approvalWorkflowMcp.test.ts
4 files passed, 108 tests passed

npm run lint
passed

npm run build
passed (TypeScript build and Vite production build)
```

Additional Roadex verification:

```text
npm test
51 files passed, 533 tests passed
```

Focused Overseer/API/projection verification:

```text
python3 -m pytest -q tests/test_core.py tests/test_ui_regression.py tests/test_roadex_approval_status.py tests/test_approval_source_cross_repo_contract.py
547 passed, 3 failed
```

The three failures are pre-existing failures in untouched human-projection
coverage:

- `test_roadex_human_scope_and_source_evidence_digest_use_exact_contract`
  (expected digest mismatch).
- `test_roadex_human_projection_accepts_producer_decision_outputs[deny-rejected]`
  (the existing `kira` identity is rejected as non-independent).
- `test_roadex_human_projection_accepts_producer_decision_outputs[request_revision-changes-requested]`
  (same existing identity validation failure).

No Task 3 file is involved in those failures. `git diff --check` passed in both
worktrees.

## Commits

- Overseer: `c66e371` — `Expose binding-derived Roadex approval locator`
- Roadex: `46af6b1` — `Connect typed approval staging to workflow host`

## Concerns and boundaries

1. The relevant broader Overseer projection suite is not fully green for the
   three pre-existing failures listed above; this task did not alter their
   source or tests.
2. The Roadex host/session adapter is intentionally injected. The existing
   production composition file is outside the Task 3 ownership list, so no
   live Overseer endpoint wiring was added in this task. No live service was
   started or changed.
3. The two source worktrees were clean after their implementation commits;
   this report is the requested follow-up documentation change in the
   Overseer worktree.

## Delta Task 3 correction update

The rejected implementation was corrected under
`.superpowers/sdd/delta-task-3-correction-brief.md` across the pinned isolated
worktrees. The correction preserves the established Roadex
`approvalStatusProvider.ts`, `approvalCoordinator.ts`, and
`approvalContinuation.ts` paths and adds no parallel lifecycle or decision
store.

### Correction evidence

- Roadex now accepts only the exact closed `ProvisioningIntentV1` wire schema:
  all twelve fields are required, extra fields and invalid types are rejected,
  schema/kind/source-commit/string-trimming rules are enforced, and no
  authority, evidence, crew, approval, execution, or source-status field can
  be projected through the MCP boundary.
- Roadex now composes a bounded production transport to exactly
  `http://127.0.0.1:8766/roadex/approval-stage`, using the existing root-owned
  Overseer token reader. It sends exactly `{intent}`, validates authentication,
  HTTP status/framing/content length/size, exact locator shape and scope,
  aborts on timeout, and returns only redacted failures.
- The workflow host passes an `AbortSignal` through staging and checks the
  timed-out/settled guard immediately before durable wait registration. A
  staging promise released after timeout registers zero waits.
- Startup composition now passes the real staging transport to the host; the
  composition test constructs this path without starting a service.
- Overseer validates the exact intent at `/roadex/approval-stage`, rejects
  query strings with `INVALID_ROADEX_APPROVAL_STAGE_REQUEST`, reconstructs
  the locator from the persisted binding, and has a deterministic real-stage
  test proving the returned reference is loadable from SQLite.

### TDD and verification

The focused Roadex RED run failed because the production transport and
composition were absent and because late staging registered after timeout.
After the minimal implementation, the focused correction suite passed:

```text
npm test -- --run tests/approvalWorkflowMcp.test.ts tests/overseerApprovalStageTransport.test.ts tests/approvalWorkflowComposition.test.ts tests/approvalWorkflowHost.test.ts tests/sessionService.test.ts
5 files passed, 117 tests passed

npm test -- tests/approvalLifecycleIntegration.test.ts tests/approvalStatusProvider.test.ts tests/approvalCoordinator.test.ts tests/approvalWorkflowMcp.test.ts
4 files passed, 108 tests passed

npm test
53 files passed, 540 tests passed

npm run lint
passed

npm run build
passed (TypeScript build and Vite production build)
```

Focused Overseer verification passed the new API/projection/staging tests,
including the deterministic real-stage test:

```text
python3 -m pytest -q tests/test_core.py -k 'roadex_stage_real_bundle_returns_sqlite_loadable_binding or roadex_stage_locator_is_derived_from_persisted_binding'
2 passed

python3 -m pytest -q tests/test_ui_regression.py -k 'roadex_typed_stage_rejects_caller_supplied_locator_fields'
1 passed

python3 -m pytest -q tests/test_core.py tests/test_ui_regression.py tests/test_roadex_approval_status.py tests/test_approval_source_cross_repo_contract.py
547 passed, 3 failed
```

The three failures remain the same pre-existing untouched projection failures
from the original report: the exact human-scope/source-evidence digest case
and the two `kira` independence cases for rejected/changes-requested
producer decisions. No correction file is involved.

### Correction commits and boundaries

- Roadex source: `7369f59a6c5c7fdf611a9f9b839531603114bf18` — `fix: correct authoritative approval staging`
- Overseer source: `10bc64417344de2d699b58d75e724144b455daf0` — `fix: harden Roadex approval staging API`

No main checkout, DonutHole checkout, live store/service, approval,
deployment, protected host, gateway, firewall/IDS, or push was touched. The
report update is committed separately in the Overseer worktree after the
source commits above.
