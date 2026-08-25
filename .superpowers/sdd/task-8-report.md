# Task 8 Report: Bounded scheduler dashboard

## Status

DONE. Implementation commit: `95ede0b` (`Show autonomous operations in dashboard`).
The report commit follows this implementation commit. No live UI, service,
gateway, original checkout, other worktree, or `.superpowers/sdd/progress.md`
was touched.

## TDD evidence

### RED

Added static and Node-backed assertions for scheduler endpoints, queue-only
actions, data ages, circuit badges, payloads, pending-job disabling, focus
restoration, layout boundaries/cycle, and refresh coalescing. The required
focused command failed before implementation as expected:

```text
$ PYTHONPATH=src pytest -q tests/test_ui_regression.py -k collection
F                                                                        [100%]
1 failed, 27 deselected
AssertionError: 'collectionsStatus: "/collections/status"' not found
```

The failure was the missing Task 8 scheduler projection contract, not a test
collection or syntax error.

### GREEN

The exact Task 8 suites passed after implementation:

```text
$ PYTHONPATH=src pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py
44 passed in 20.40s
```

Additional verification passed:

```text
$ PYTHONPATH=src python3 -m compileall -q src/overseer tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py
passed
$ PYTHONPATH=src python3 -c 'from overseer.ui import OPERATOR_CONSOLE_HTML; print(OPERATOR_CONSOLE_HTML)' | awk '/^  <script>$/{inside=1; next} /^  <\/script>$/{inside=0} inside' | node --check
passed
$ git diff --check
passed
```

## Implementation

- Registered `/collections/status`, `/collections/jobs`, `/collections/runs`,
  and `/collections/incidents` in the existing endpoint map. They flow through
  the existing single `refreshPromise` and `mapEndpointEntries(endpointEntries, 4)`.
- Removed the dashboard's direct health-probe POST action and control. Run Now
  is available per job and through a selected filtered job, and only enqueues
  `POST /collections/jobs/{job_id}/run` with bounded `requested_by` and `reason`.
- Rendered scheduler heartbeat, active jobs, pending requests, overdue jobs,
  open circuits, incidents, job schedule/circuit/cooldown/lease/backoff/freshness,
  bounded run evidence, and incident/repair disposition.
- Rendered queue response status, request ID, earliest execution, and
  circuit/cooldown. Repeated Run Now submission stays disabled while the job is
  pending; rerenders preserve focus for controls, views, and the scheduler
  filter.
- Kept the 30-second refresh GET-only and coalesced with focus, visibility, and
  manual refresh. The header now reports last UI refresh separately from
  observed evidence/data ages.
- Preserved the existing visual system and automatic/manual responsive modes,
  including <=700 mobile, 701-1024 tablet, >1024 desktop, local persistence and
  fallback, saved/effective announcements, reduced motion, visible focus,
  semantic tables, and 44px scheduler controls. Cancel controls are explicitly
  `type="button"`.
- Updated `docs/ui-regression-testing.md` with scheduler and disposable
  protected-prefix acceptance steps.

## Controller Playwright acceptance checklist

Pending controller execution; not run or claimed here.

- [ ] Use the configured Playwright MCP against a disposable prefix-aware
  harness at `/Overseer/ui`, not a live service or gateway deployment.
- [ ] Verify authenticated `/Overseer/collections/status`, `/jobs`, `/runs`,
  and `/incidents` GETs, no console errors, no unauthorized panel requests,
  and no `POST /Overseer/health/probes/run`.
- [ ] Verify per-job and filtered Run Now enqueue behavior, bounded payload,
  queued/coalesced response, request ID, earliest execution, circuit/cooldown,
  pending disablement, and focus restoration.
- [ ] Verify 390x844, 820x1180, and 1440x1000; automatic mode; every forced
  mode; 700/701/1024/1025 boundaries; reload persistence; no horizontal
  overflow; readable tables; reduced motion; and 44px targets.
- [ ] Verify the top-right auto/desktop/tablet/mobile control exposes saved and
  effective modes to assistive technology, and Cancel remains non-submit.

## Files

- `src/overseer/ui.py`
- `tests/test_ui_regression.py`
- `tests/test_ui_full_regression.py`
- `tests/test_performance_regression.py`
- `docs/ui-regression-testing.md`
- `.superpowers/sdd/task-8-report.md`
