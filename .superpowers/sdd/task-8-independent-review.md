# Task 8 independent review

Reviewed range: `c74333e..fece97b` on
`feature/overseer-v1-1-autonomous-operations`.

## Findings

### Important — established operator-console regression is left failing

- `tests/test_core.py:4040` still asserts that the dashboard contains the
  removed `data-action="run-health-probes"` control. Task 8 intentionally removes
  that UI action in favor of the queue-only scheduler control
  (`src/overseer/ui.py:1287`, `src/overseer/ui.py:2423`). Consequently,
  `PYTHONPATH=src pytest -q tests/test_core.py -k 'operator_console or git_status or documents_routes'`
  fails: `1 failed, 5 passed`.

  Update the obsolete assertion to test the scheduler projection and queue-only
  control contract (and explicitly reject the direct-probe dashboard action).
  The deprecated API compatibility route can remain tested independently; this
  is a stale UI contract, not a reason to restore direct collection from the
  browser.

## Strengths

- Scheduler state is fetched as authenticated bounded projections and shares
  the existing refresh promise and four-request worker cap
  (`src/overseer/ui.py:1107-1219`).
- The new controls issue only the encoded per-job queue request, expose
  request/circuit/cooldown information, and preserve a pending state and
  focus destination (`src/overseer/ui.py:1265-1298`,
  `src/overseer/ui.py:2359-2372`).
- The protected-prefix join, responsive-mode contract, forced-narrow layout
  containment, reduced-motion rules, and non-submit Cancel controls are
  covered by the scoped UI regressions and documented browser acceptance.
- The scoped diff touches only Task 8 UI/test/runbook/report files; no API,
  scheduler, service, gateway, original checkout, or external project changed.

## Verification

- `PYTHONPATH=src pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py` — `47 passed`.
- `PYTHONPATH=src pytest -q tests/test_core.py -k 'operator_console or git_status or documents_routes'` — `1 failed, 5 passed` (finding above).
- `git diff --check c74333e..fece97b` — passed.

## Assessment

**Not approved yet.** Task 8’s implementation meets the autonomous,
queue-only UI direction and its focused tests pass, but it must reconcile the
established operator-console regression before Task 8 can be accepted.

Residual risk after that correction: browser acceptance is recorded from a
disposable prefixed harness in the Task 8 report; it should be retained as a
required pre-activation check rather than treating it as evidence about a live
gateway deployment.
