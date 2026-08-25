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

## Re-review after dashboard compatibility correction

Reviewed correction range: `c58b867..16647db`, specifically implementation
commit `c918635` and its report commit `16647db`.

### Findings

No blocking or important findings remain.

The previous finding is resolved at `tests/test_core.py:4040-4048`. The
operator-console test now requires all four scheduler projections, per-job and
filtered queue controls, and the encoded queue request. It explicitly rejects
the obsolete direct-probe action and browser `POST /health/probes/run`.

Deprecated API compatibility remains independently covered in
`tests/test_collection_api.py`: it verifies direct and `/Overseer` prefixed
routes, `202`, `Deprecation: true`, the successor link, queue-only behavior,
bounded/truncated enqueue results, and preserved deprecation headers on a
bounded internal error.

### Re-review verification

- `PYTHONPATH=src pytest -q tests/test_core.py -k 'operator_console or git_status or documents_routes'` — `6 passed, 379 deselected`.
- `PYTHONPATH=src pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py` — `47 passed`.
- `PYTHONPATH=src pytest -q tests/test_collection_api.py -k 'health_probes_run or deprecated or successor'` — `2 passed, 16 deselected`.
- `git diff --check c58b867..16647db` — passed.

### Final assessment

**Approved.** The correction resolves the sole prior Important finding without
restoring direct browser collection or weakening deprecated API compatibility.
The correction diff is limited to the stale regression assertion and Task 8
documentation; no live service, gateway, API implementation, or external
project was modified.

Residual risk: the recorded browser pass uses a disposable prefixed harness,
so it remains a pre-activation requirement rather than proof of a live gateway
deployment.
