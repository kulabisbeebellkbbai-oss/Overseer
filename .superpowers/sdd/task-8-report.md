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

## Browser evidence correction

The controller's disposable prefix-aware run reported three dashboard load
failures. Local read-only reproduction against the same API handler showed the
route contracts were valid and the fixture was incomplete:

- `/Overseer/runtime-status` returned `404 {"error":"missing record: overseer"}`
  when the heartbeat existed under `runtime.overseer.browser`. The supported
  runtime projection loads the heartbeat record named `overseer`.
- `/Overseer/host/security/listener-review-queue` and
  `/Overseer/host/security/source-review-queue` returned `400
  {"error":"no host snapshots are available"}` when no host inspection
  snapshot was seeded. These are the supported read-only queue routes; they do
  not require a replacement query contract. The disposable harness must seed
  the expected heartbeat and a host snapshot before browser acceptance.

No endpoint names, protected-prefix joining, API handlers, live services, or
external systems were changed. A regression test now statically enforces the
exact runtime, Odo queue, scheduler projection, and `/Overseer` base-path
registrations.

The independent browser UI findings were fixed in implementation commit
`dfda11d` (`Preserve scheduler focus and narrow layouts`):

- Per-job and filtered Run Now rerenders capture their trigger identity. When
  the trigger becomes disabled, focus moves to the programmatically focusable
  live action-status destination (`role="status"`, `aria-live="polite"`,
  `tabindex="-1"`). Node-backed DOM-shaped tests assert the resulting
  `document.activeElement` for both trigger paths.
- Filtered Run Now preserves `state.selectedCollectionRunJob` across projection
  rerenders and keeps the selected option and pending disablement.
- A null `earliest_execution_at` with an open circuit now renders the circuit
  cooldown (`cooldown until ...`) or `blocked by open circuit`, rather than
  incorrectly saying only `scheduler decides`.
- Forced desktop at the narrow 390px viewport uses intrinsic min-content
  constraints, bounded scheduler pills, local table scrolling, and 44px
  scheduler controls. The CSS regression explicitly rejects page-level
  overflow masking and checks the narrow forced-desktop contract.

Correction verification for `524e744` (`Restore scheduler focus and contain metrics`):

```text
$ PYTHONPATH=src pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py
47 passed in 20.40s
$ PYTHONPATH=src python3 -m compileall -q src/overseer tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py
passed
$ PYTHONPATH=src python3 -c 'from overseer.ui import OPERATOR_CONSOLE_HTML; print(OPERATOR_CONSOLE_HTML)' | awk '/^  <script>$/{inside=1; next} /^  <\/script>$/{inside=0} inside' | node --check
passed
$ git diff --check
passed
```

The report commit follows `524e744`. Controller Playwright acceptance remains
pending and is not claimed here; it must rerun against the repaired disposable
fixture at `/Overseer/ui`, including per-job and filtered focus restoration,
selected-filter persistence, forced-desktop 390px overflow/content bounds,
and the exact protected-prefix GET matrix.

## Follow-up browser correction

The real Playwright rerun against the clean prefixed fixture exposed a timing
gap in `dfda11d`: Chromium moved focus to `body` as soon as the focused Run Now
button was disabled, before `refresh()` could render the pending projection.
The rerender therefore captured BODY and the prior fallback had no trigger to
restore.

The follow-up fix captures `captureFocusTarget(source ||
document.activeElement)` before setting `source.disabled`, then explicitly
calls `restoreFocusTarget(focusTarget)` after the successful refresh (and on
the error path). The Node fixture models the browser transition to BODY and
asserts `document.activeElement` ends at the focusable `#action-status` for
both a per-job trigger and a distinct filtered trigger.

The same correction adds intrinsic metric containment for real scheduler data:
metric grid children and `.metric .value` have `min-width: 0`, bounded width,
`overflow-wrap: anywhere`, and `word-break: break-word`. Long observed
timestamps, request IDs, and cooldown values are exercised by Node fixtures;
table overflow remains confined to `.table-scroll`.

The follow-up source/test/docs commit is `524e744`. The report commit follows
after this verification. Controller Playwright acceptance remains controller-owned and
must confirm zero document overflow at 390px in auto/mobile and forced desktop,
with readable metric content bounds and `#action-status` focus.

## Follow-up filtered-selection and overview containment correction

The next disposable-fixture rerun found that the fresh-load filtered Run Now
button stayed disabled after selecting `collection.usage.quota`: the delegated
change handler updated `state.selectedCollectionRunJob` and returned without
updating the already-rendered button. `selectCollectionRunJob()` now updates
the state and synchronizes the filtered control immediately. It enables only
an existing, non-pending projected job, and keeps empty, unknown, projection-
pending, and locally pending jobs disabled. The existing queue path remains
queue-only and restores focus to the focusable `#action-status` after rerender.

The same correction extends intrinsic containment to `.metric` and
`.crew-card` children and their row content with bounded width and wrapping.
This addresses overview long text such as `executable plans` and Odo Firewall
crew content under forced desktop at 390px without page-level overflow hiding;
local `.table-scroll` overflow remains unchanged.

The source/test/docs correction commit and final report commit are recorded
below after verification. Controller Playwright acceptance remains
controller-owned and must confirm the real 390px document bounds in every
forced mode.

Correction verification for `2d1bc5d` (`Sync filtered scheduler controls`):

```text
$ PYTHONPATH=src pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py
47 passed in 20.36s
$ PYTHONPATH=src python3 -m compileall -q src/overseer tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_performance_regression.py
passed
$ PYTHONPATH=src python3 -c 'from overseer.ui import OPERATOR_CONSOLE_HTML; print(OPERATOR_CONSOLE_HTML)' | awk '/^  <script>$/{inside=1; next} /^  <\/script>$/{inside=0} inside' | node --check
passed
$ git diff --check
passed
```

The final report commit follows `2d1bc5d`; controller Playwright acceptance is
still pending and is not claimed here.
