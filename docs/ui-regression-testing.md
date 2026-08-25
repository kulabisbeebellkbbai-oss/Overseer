# UI Regression Testing

Ezri owns the durable runbook for UI workflow evidence, while Julian owns health/error interpretation and Dax owns protected gateway path coordination.

## Local Test Layers

Run the fast Python regression tests first:

```bash
python3 -m pytest tests/test_ui_regression.py -q
```

Run the full operator UI workflow contract suite when changing pages, actions,
forms, drilldowns, or approval surfaces:

```bash
python3 -m pytest tests/test_ui_full_regression.py -q
```

Run the focused UI/API checks inside the main suite when changing the dashboard:

```bash
python3 -m pytest tests/test_core.py -q -k 'operator_console or git_status or documents_routes'
```

Run the full suite before handoff:

```bash
python3 -m pytest tests/test_core.py tests/test_ui_regression.py tests/test_ui_full_regression.py -q
```

Run the packaged full local regression suite when a single report artifact is
needed:

```bash
python3 scripts/run_full_regression.py
```

The package runs:

- operator functional tests for protected-gateway auth, panel endpoints,
  navigation, forms, safe actions, Ezri workflow coverage, and control routing.
- operations gap coverage tests for the sysops/devops/admin surfaces generated
  from Ezri's gap analysis.
- operator performance tests for protected-gateway console load, protected panel
  endpoint timing, and safe workflow route timing.
- the complete project pytest suite.

## Protected Gateway Regression Scope

The protected gateway path is `/Overseer`. The regression suite must verify:

- `/Overseer` and `/Overseer/ui` serve the operator console HTML.
- the token input `#token` is present on gateway-loaded pages.
- gateway mode sets `apiBase` to `/Overseer`.
- gateway mode uses `sessionStorage` for the token.
- `/Overseer/operator-dashboard` returns `200` and includes nonempty `role_focus`
  data for the command crew.
- `/Overseer/git/status` returns `200` and includes account-level repository
  data for the local workspace root.
- authenticated `/Overseer/...` panel endpoints do not return `401`.
- safe POST actions route through `/Overseer/...`.
- every navigation page has a section, renderer, station heading, expected crew
  channel, and expected action controls.
- every visible UI action is handled by `actionRequest` and maps to an existing
  backend route.
- every action form field referenced by JavaScript exists in the rendered UI
  contract.
- safe disposable workflows execute through gateway routes; high-risk workflows
  remain wired but are not executed without explicit fixtures.

Empty-store application responses such as missing heartbeat or missing host snapshot may return `400` or `404`; those are not auth regressions. A protected-gateway UI auth regression is a missing console, missing `#token`, `401` after token submission, or a route that bypasses `/Overseer` unexpectedly.

## Tank Remote Testing Queue

Tank's MSI test thread:

```text
019f816f-7619-7c10-9195-e102a492d33c
```

Queue root:

```text
/home/god/Documents/Codex Workspace/Overseer/local-secrets/remote-testing
```

Queue jobs are local-only and must never include raw API tokens, cookies, browser storage values, or local database exports. Results should report only endpoint names, HTTP status summaries, validation stage, auth-header presence, token-hash match, storage-key hashes, and non-sensitive body hashes.

Quark coordinates Tank/MSI through the protected gateway or VPN-reachable route
`god@10.50.0.100`. Do not configure project threads or Quark jobs to use
`god@192.168.68.xxx` or depend on the `192.168.68.xxx` LAN path.

Tank runner supports:

- `ping`
- `overseer.http_status`
- `overseer.auth_panel_smoke` with gateway-aware expected endpoint matching
- `overseer.admin_approve_smoke` with explicit disposable fixture params
- `overseer.full_ui_regression` when Tank has installed the current queue
  contract; otherwise Tank should return `partial` with runner-support findings
- `overseer.performance_regression` when Tank has installed the current queue
  contract; otherwise Tank should return `partial` or `blocked` with
  runner-support findings

The runner returns only endpoint names, methods, status codes, auth-header
booleans, short token/body hashes, validation stages, and findings. It must not
return raw tokens, cookies, browser storage, page HTML, screenshots with secrets,
or local database exports.

## Standard Remote Job Batch

Use these jobs for a full UI auth regression pass:

1. `ping`
2. `overseer.http_status`
3. `overseer.auth_panel_smoke`
4. `overseer.auth_panel_smoke` with `ui_path=/Overseer/ui`
5. `overseer.auth_panel_smoke` for browser storage scope comparison
6. `overseer.admin_approve_smoke` with `dry_run_only=true`
7. `overseer.full_ui_regression` with `ui_path=/Overseer/ui`

Admin approval smoke must remain blocked unless a disposable non-live fixture exists. Do not approve package, firewall, security, or live admin plans for a route test.

For protected-gateway browser jobs, expected panel endpoint paths must include
the gateway prefix, for example `/Overseer/usage-summary`. Runner v2 handles
gateway-prefixed expected paths directly.

Include `/Overseer/operator-dashboard`, `/Overseer/git/status`,
`/Overseer/host/security/listener-review-queue`, and
`/Overseer/host/security/source-review-queue` in protected-gateway browser jobs.
The job should fail if the dashboard request is missing, lacks Authorization,
returns a non-`200` status, or does not provide command crew role data.

The full UI regression job should open every command view, verify crew channel
visibility, check drilldown controls, check approval decision controls without
executing live changes, and exercise Ezri's Workflows panel plus Documents
folder navigation. Ezri-specific assertions must include the `Workflows` panel,
the `UI regression testing` row, filling
`Overseer/Runbooks/ui-regression-testing.md`, listing `Overseer/Runbooks`, and
clicking `Runbooks/` from the root folder.

The full UI regression job should also verify every Ezri workflow row listed in
`docs/operator-workflows.md`, including split workflows where one runbook
section maps to several UI controls.

The performance regression job should measure protected-gateway browser load,
all-panel completion, command-view switching, and authenticated endpoint
round-trips. It must fail on any `401`, any `5xx`, or any exceeded budget.

Admin approval smoke needs an explicit disposable fixture contract before it can
mutate anything. The fixture must identify a test-only admin plan whose kind is
safe to cancel immediately after the route check, and the runner must report
only the route, method, auth-header presence, status, and redacted response
shape. If the runner cannot consume a fixture plan id, the correct result is
`blocked`; do not use a real maintenance, security, firewall, or package plan as
the smoke target.

## Autonomous Operations Scheduler Acceptance

Task 8 treats the dashboard as a bounded scheduler projection. The browser must
load these authenticated GET projections through the same base path as the
console:

- `/collections/status`
- `/collections/jobs`
- `/collections/runs`
- `/collections/incidents`

Use a disposable prefix-aware API harness before any protected deployment. The
harness should serve the console at `/Overseer/ui`, accept the test bearer
token, and return bounded fixtures containing a scheduler heartbeat, active and
pending counts, an overdue job, an open circuit with cooldown, a lease,
freshness/data-age fields, a retry/backoff disposition, and an incident with
repair disposition. Verify that the console requests `/Overseer/collections/...`
and never calls `POST /Overseer/health/probes/run`.

The legacy evidence projections remain part of the authenticated dashboard GET
contract and retain these exact registrations: `/Overseer/runtime-status`,
`/Overseer/host/security/listener-review-queue`, and
`/Overseer/host/security/source-review-queue`. Seed the runtime heartbeat under
the `overseer` record expected by `runtime-status` (a differently named record
such as `runtime.overseer.browser` is not equivalent). Seed at least one host
inspection snapshot before checking the Odo queues; both queue routes return a
bounded `400` with `no host snapshots are available` when that fixture
prerequisite is absent. The disposable harness must satisfy these prerequisites
so fixture omissions do not produce a browser `partial` load.

In the harness, click one per-job `Run now` control and one filtered `Run now`
control. Confirm that each request is a queue-only
`POST /Overseer/collections/jobs/{job_id}/run` with the bounded
`requested_by`/`reason` payload. Confirm the response renders request ID,
`queued` or `coalesced`, earliest execution, and circuit/cooldown state; repeat
the click while the request is pending and verify the same job control is
disabled. Confirm the 30-second refresh and focus/visibility/manual refresh
triggers issue GET projections only and coalesce through one refresh promise.

At `390x844`, `820x1180`, and `1440x1000`, verify automatic mode, every forced
mode, no horizontal overflow (including forced desktop at 390px), visible focus
restoration after a scheduler rerender, preserved selected filtered-job state,
readable tables, 44px controls including scheduler Run Now targets,
reduced-motion behavior, and the top-right auto/desktop/tablet/mobile control
with saved/effective mode announcement. Explicitly test the automatic boundaries at 700/701/1024/1025px
and reload persistence. Cancel controls must remain `type="button"` and must
not submit their surrounding forms. Browser MCP acceptance is controller-owned;
this runbook does not claim that acceptance from static or Node-backed tests.

## Interpreting Results

- Direct `/ui` passes but `/Overseer/ui` cannot find `#token`: backend or gateway is not serving the console at the protected path.
- HTTP matrix passes but browser panel 401s: UI token storage, Authorization header propagation, or browser state is suspect.
- Authorization header present and token hash matches, but API returns 401: backend auth token mismatch or proxy stripping may be present.
- Absolute-root fetches from a gateway page are suspicious unless the gateway is intentionally same-origin and root-routed.
- Gateway-prefixed fetches from a gateway page are expected. Compare the
  expected endpoint list to the observed path base before treating a `partial`
  result as a functional failure.
- A `partial` result on `/Overseer/runtime-status` or either Odo queue route
  must first be classified by response body: a missing `overseer` heartbeat or
  missing host snapshot is a disposable-fixture defect; a `404`/`400` with a
  complete fixture is an application route regression. Keep route names and
  protected-prefix joining unchanged while repairing the fixture.

## Handoff

After fixing a UI auth issue:

1. Restart `overseer-api.service`.
2. Verify `/health`.
3. Run `tests/test_ui_regression.py`.
4. Queue Tank protected-gateway smoke jobs.
5. Record a Julian crew message with the result summary.
6. Have Ezri capture this runbook update into Documents.

## Latest Local Full Regression

Last local packaged run:

```text
artifacts/regression/full-regression-20260725T152325Z.json
```

Result:

- `operator-functional`: passed.
- `operator-performance`: passed.
- `project-regression`: passed.
- Overall package: passed.

Current Tank jobs requested:

- `job-20260721T042300Z-overseer-full-ui-regression-all-workflows`
- `job-20260721T042301Z-overseer-performance-regression-gateway`
- `job-20260721T043000Z-overseer-performance-regression-gateway-rerun`

Current Tank results:

- `job-20260725T052139Z-overseer-auth-panel-smoke-display-check`: passed at
  `authenticated-panel-fetch`. All expected `/Overseer` display/auth endpoints
  returned `200`, `console_error_count=0`, and findings were empty.
- `job-20260725T052140Z-overseer-full-ui-regression-display-check`: passed at
  `full-ui-regression` with `observed_request_count=49`,
  `console_error_count=0`, and no findings.
- `job-20260725T054840Z-overseer-http-status-unlock-panels-postfix`: passed at
  `api-status-matrix`. `/health` plus the reported `/Overseer` unlock and
  panel paths returned `200`; findings were empty.
- `job-20260725T054841Z-overseer-full-ui-regression-unlock-postfix`: passed at
  `full-ui-regression` with `observed_request_count=49`,
  `console_error_count=0`, and no findings.
- Tank worker `overseer-msi-test-agent-v4` was restarted and verified with live
  ping `job-20260725T063633Z-ping-251e786363`; the pending remote-testing queue
  was clear after the run. Tank returned only redacted status, counts, hashes,
  endpoint names, and findings.
- `job-20260725T070700Z-overseer-performance-regression-load-marker-v5-diagnostic`:
  passed at `performance-regression` after Tank runner v5 honored
  `body[data-load-state='ready']` as the panel completion marker. Initial load
  was `245ms`; all panels loaded in `4950ms`; final load state was `ready`;
  `failure_selector_matched=false`; view switching was `p95=61ms`; endpoint
  round trips covered `33` samples with `p95=1428ms`; observed browser requests
  were `49`; `console_error_count=0`; findings were empty.
- Tank worker `overseer-msi-test-agent-v5` was restarted and verified with live
  ping `job-20260725T070724Z-ping-3a9cf265c2`; the pending remote-testing queue
  was clear after the run. Tank returned only redacted status, counts, hashes,
  endpoint names, and findings.
- `job-20260721T042300Z-overseer-full-ui-regression-all-workflows`: passed
  with `observed_request_count=29`, `console_error_count=0`, and no findings.
- `job-20260721T042301Z-overseer-performance-regression-gateway`: failed at
  `job-dispatch` because Tank runner v3 does not yet support
  `overseer.performance_regression`.
- `job-20260721T043000Z-overseer-performance-regression-gateway-rerun`: failed
  at `performance-regression` on latency only. Auth/status failures were not
  observed, console errors were `0`, and the browser observed `29` requests.
  Initial load was `239ms`, view switching passed with `p95=70ms`, and endpoint
  round trips covered `81` samples across `27` protected endpoints.

Current remote performance findings:

- No current remote performance findings after the Tank v5 marker-aware run.

Tank follow-up:

```text
local-secrets/remote-testing/RUN_NOW_TANK_20260721T042500Z.md
```
