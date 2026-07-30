# Task 8 Report

## Files

- `src/overseer/ui.py`
- `tests/test_ui_regression.py`
- `tests/test_ui_full_regression.py`
- `tests/test_codex_usage.py`
- `src/overseer/cli.py` (review-approved read-only usage status)
- `src/overseer/api.py` (review-approved authenticated usage route)
- `tests/test_agent_api.py`

## RED evidence

`pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_codex_usage.py -x`
failed at the first new dashboard assertion:

- `1 failed, 4 passed`
- missing `Primary AI Driver`

## GREEN evidence

- Initial focused UI suite: `23 passed in 6.22s`
- Review-correction focused agent API/UI/workflow suite:
  `50 passed in 12.10s`
- Review-correction full suite: `704 passed in 101.93s`
- Second-review focused API/UI/workflow suite: `52 passed in 12.66s`
- Second-review full suite: `706 passed in 102.52s`
- Third-review focused API/UI/workflow suite: `52 passed in 12.86s`
- Third-review full suite: `706 passed in 102.47s`
- Final failover-logic focused suite: `52 passed in 12.85s`
- Final failover-logic full suite: `706 passed in 102.68s`
- Node v24 executed the extracted production `providerGate` and
  `validatedTransferPayload` functions against ready, unavailable, unknown,
  required-capability, valid-payload, and missing-approval cases.
- Node also executed production `renderDriver()` with real-shape fixtures,
  proving it renders without a `ReferenceError`, then changed discovery and
  incoming selections and verified the actual rendered disabled states and
  exact blocker titles.
- `python3 -m py_compile src/overseer/ui.py`: passed
- `git diff --check`: passed

## Browser evidence

The repository has no Playwright/browser harness or browser dependency. A
best-effort Google Chrome headless screenshot attempt was made for the required
viewport sizes, but the installed Chrome process terminated with
`Trace/breakpoint trap (core dumped)` before producing screenshots. Browser
viewport verification is therefore an explicit environment blocker. Static
regressions cover breakpoint boundaries, preference cycling/persistence hooks,
effective-mode state, reduced motion, action wiring, and capability gating.

## Behavior and compatibility

- Added a provider-neutral Primary AI Driver view consuming the four generic
  inventory/session/dispatch endpoints plus authenticated persisted usage
  evidence.
- Added discovery, recovery, checkpoint, approval-confirmed handoff, and
  approval-confirmed failover controls.
- Cancellation is disabled with accessible blocker text when unsupported.
- Provider readiness/blockers, capability matrix, epoch/checkpoint/recovery,
  fallback order, and native usage units are rendered without credentials,
  transcripts, or checkpoint payload content.
- Rendering uses the exact API fields (`approved_fallback_provider_ids`,
  `active_epoch`, session and dispatch `id`, `driver_epoch_id`, and result
  `request_id`/`state`). Actions fail closed on provider readiness and their
  exact capability.
- Gates now recompute from operator-selected discovery, session, incoming, and
  fallback destinations. Failover also verifies approved-fallback membership.
- Instance status includes policy readiness/blocker, current checkpoint ID, and
  current transition state using persisted records only.
- Current-driver readiness is separate from failover-policy readiness. An
  unavailable outgoing provider is failover context and does not block a
  healthy compatible approved fallback; missing controlled-failover policy has
  deterministic precedence and fails closed.
- Cancellation is a disabled non-action because no backend route exists, and is
  intentionally omitted from normal workflow metadata.
- `/agent-usage` performs no provider calls and reports the configured source,
  persisted value/remaining, exact persisted `UsageLimit.kind` unit, and
  observation/reset timestamps; missing evidence remains explicit.
- Existing Codex usage panels and legacy Codex action remain Codex-specific.
- Added persistent auto/desktop/tablet/mobile modes with breakpoint-driven auto
  resolution, resize recomputation, accessible saved/effective mode state,
  reduced motion, visible focus, and 44px layout control.

## Risks

- No backend cancellation route exists yet, so the cancellation control is
  intentionally fail-closed and its handler reports the provider capability
  blocker if invoked programmatically.
- The real-browser viewport matrix must be rerun when a working browser harness
  is available.

## Commit

Initial implementation: `02e652ae9fda2798d52d6a631d6d1ce9502f5d39`

Review correction: `7c7e3764a591a34a7a7d734bc431a3e5f3b4ad1f`

Second review correction: `f5864158b1cb6594d28ba935e4be151ce122c30a`

Third review correction: `6746640cdd513a19045dda4756643304dfbe46fa`

Final failover-logic correction: `b701656a8b3161dcf8e04104648c47e6cb75ab29`
