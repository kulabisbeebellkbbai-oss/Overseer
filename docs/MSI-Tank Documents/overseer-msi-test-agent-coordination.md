# Overseer MSI Test Agent Coordination

Tank is the MSI-side operator for Overseer browser, device, and local-resource tests. Quark coordinates work for Sisko through the Overseer protected gateway and the remote-testing queue.

## Transport Rule

Use the protected gateway/VPN-reachable route for coordination. Do not depend on `192.168.68.xxx` LAN addresses; that path only works when MSI is on HulaHut.

Local worker defaults:

- SSH target: `god@10.50.0.100`
- Queue root: `/home/god/Documents/Codex Workspace/Overseer/local-secrets/remote-testing`
- Protected gateway path: `/Overseer`
- Protected UI path: `/Overseer/ui`

## Durable Local Worker

Preferred current transport is the Tailscale listener. This avoids requiring a standing SSH session with key passphrase and server TOTP.

The preferred durable launcher is the current-user Windows startup entry `TankOverseerMsiTestListener`, which starts:

`Captures/overseer-msi-test-agent-listener-start.ps1`

Listener defaults:

- Endpoint: `http://100.104.141.96:18767`
- Allowed caller: protected gateway tailnet source `100.86.135.42`
- Health: `GET /health`
- Contract: `GET /contract`
- Submit job: `POST /jobs`
- Read result: `GET /jobs/<job_id>`

If an elevated maintenance window is available and remote protected-gateway calls cannot reach the listener, add the Windows firewall rule:

```powershell
New-NetFirewallRule -DisplayName "Tank MSI Tailscale Listener" -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 100.104.141.96 -LocalPort 18767 -RemoteAddress 100.86.135.42 -Profile Any
```

Quark/Overseer should call Tank through the protected gateway tailnet route and should not use `192.168.68.xxx` addresses. The listener authorizes requests by Tailscale source address and injects the internal listener authorization marker before invoking the local runner. Jobs and results remain local under `%LOCALAPPDATA%\OverseerMsiTestAgent\listener\jobs`.

Minimal listener submission:

```json
{
  "schema": "overseer.remote-test.job.v1",
  "job_id": "job-20260824-tank-ping",
  "job_type": "ping",
  "requested_by": "quark",
  "project": "Overseer",
  "mutates": false
}
```

Legacy SSH queue polling remains documented below for older queue workflows, but it is not the preferred steady-state path when the SSH key is encrypted and the server requires TOTP.

The user-level scheduled task `Overseer MSI Test Agent` starts:

`Captures/overseer-msi-test-agent-start.ps1`

The launcher starts one background worker and ignores duplicate starts. Worker status is written locally to:

`%LOCALAPPDATA%\OverseerMsiTestAgent\status.json`

Logs:

- `%LOCALAPPDATA%\OverseerMsiTestAgent\launcher.log`
- `%LOCALAPPDATA%\OverseerMsiTestAgent\agent.log`
- `%LOCALAPPDATA%\OverseerMsiTestAgent\worker.stderr.log`
- `%LOCALAPPDATA%\OverseerMsiTestAgent\worker.stdout.log`

## Quark Queue Protocol

Quark should use the existing queue contract and control file:

- `local-secrets/remote-testing/QUEUE_CONTRACT.md`
- `local-secrets/remote-testing/quark-control.json`

Submit work by creating JSON files in `jobs/pending/`. The worker atomically moves them to `jobs/claimed/`, then writes redacted results to `jobs/done/` or `jobs/failed/`.

Supported non-destructive job types:

- `ping`
- `overseer.http_status`
- `overseer.auth_panel_smoke`
- `overseer.admin_approve_smoke`
- `overseer.full_ui_regression`
- `overseer.performance_regression`
- `protected_gateway.request_sequence`
- `roadex.project_creation_flow`
- `roadex.authenticated_session_prompt`
- `psychlo.authenticated_browser_verify`
- `tank.local_facility_request`

Mutation is allowed for `protected_gateway.request_sequence` when the job sets `mutates: true`, `params.allow_mutation: true`, and every request resolves under the protected gateway origin and an allowed gateway service path such as `/Overseer` or `/Roadex`. Roadex mutating requests must also include `params.mutation_authorization` showing Roadex console human approval, Odo approval, Quark issuance, active-development target scope, and `roadex_protected_gateway_active_development` scope. The worker rejects requests that escape the protected gateway origin, leave the configured service path, contain URL credentials/fragments, use encoded path separators, or try to supply raw `Authorization` or `Cookie` headers from the queue.

Other mutating/admin/device jobs still require disposable fixtures or explicit approved safe scope. Results must never include raw tokens, cookies, browser storage, response bodies, device IDs, MACs, serial numbers, or secrets.

## Generic Protected Gateway Request Job

Use `protected_gateway.request_sequence` for future tests against pages or services exposed by Protected Service Gateway.

Minimal read-only job:

```json
{
  "schema": "overseer.remote-test.job.v1",
  "job_id": "job-20260726-protected-gateway-overseer-health",
  "job_type": "protected_gateway.request_sequence",
  "created_at": "2026-07-26T16:30:00Z",
  "requested_by": "quark",
  "project": "Protected Gateway",
  "base_url": "https://roadex.home.arpa:9443",
  "gateway_path": "/Overseer",
  "ui_path": "/Overseer",
  "mutates": false,
  "redaction": {
    "no_raw_tokens": true,
    "no_raw_cookies": true,
    "no_raw_local_storage": true,
    "no_raw_response_bodies": true,
    "allow_hashes": true
  },
  "params": {
    "gateway_base_url": "https://roadex.home.arpa:9443",
    "service_path": "/Overseer",
    "requests": [
      { "label": "health", "method": "GET", "path": "/Overseer/health" }
    ]
  }
}
```

Mutating jobs use the same shape, but must set both `mutates: true` and `params.allow_mutation: true`. For Roadex targets, include:

```json
"mutation_authorization": {
  "scope": "roadex_protected_gateway_active_development",
  "approval_source": "roadex_console",
  "human_console_approval": true,
  "odo_approved": true,
  "issued_by": "quark",
  "active_development_target": true
}
```

Request bodies are allowed as `json` or `body`, but only short request and response hashes, lengths, statuses, content types, cache headers, route labels, authorization evidence booleans, and findings are returned.

## Roadex Authenticated Session Prompt

Use `roadex.authenticated_session_prompt` when Quark needs Tank to submit an approved prompt to an existing Roadex managed session through Protected Service Gateway. This job loads the local Roadex authenticated browser storage state, requires a scoped `auth_token_id`, bootstraps `/Roadex/api/bootstrap` with `Authorization: Bearer <scoped-token>` to pick up the Roadex CSRF token, and posts to the exact session prompt endpoint with the same scoped token.

Required controls:

- `mutates: true`
- `params.allow_mutation: true`
- `params.require_explicit_user_approval: true`
- `params.mutation_authorization.scope: roadex_protected_gateway_active_development`
- `params.mutation_authorization.approval_source: roadex_console`
- `params.mutation_authorization.human_console_approval: true`
- `params.mutation_authorization.odo_approved: true`
- `params.mutation_authorization.issued_by: quark`
- `params.mutation_authorization.active_development_target: true`
- `params.gateway_base_url: https://roadex.home.arpa:9443`
- `params.service_path: /Roadex`
- `auth_token_id` for a scoped remote-testing token issued by Quark
- `params.prompt_path: /Roadex/api/sessions/<safe-session-id>/prompts`
- `params.json` or `params.prompt_json`

Allowed output is limited to gateway origin, app/bootstrap/prompt statuses, content types, cache headers, CSRF/auth/storage booleans, role-presence booleans/counts, short token/request/response body hashes, response lengths, operation-accepted boolean, validation stage, authorization evidence booleans, and findings.

## Psychlo Authenticated Browser Verify

Use `psychlo.authenticated_browser_verify` when Quark/Terl needs Tank to visually verify the protected Psychlo dashboard from MSI. This job is read-only, requires a scoped `auth_token_id` for queue admission and grant validation, then opens `/Psychlo` through Protected Service Gateway using Tank's authenticated gateway cookie state. It must not send `Authorization` to `/Psychlo`; Psychlo is cookie-session-only at the gateway. The runner checks stable DOM markers across desktop/mobile viewports, captures screenshot hashes, and returns redacted console/page/request evidence.

Required controls:

- `mutates: false`
- `auth_token_id` for a scoped remote-testing token issued by Quark; the token authorizes the job and is not attached to page navigation
- `params.gateway_base_url: https://roadex.home.arpa:9443`
- `params.service_path: /Psychlo`
- `params.page_path: /Psychlo`
- `params.expected_status: 200`
- `params.expected_title: Psychlo operator dashboard`
- `params.required_text`
- `params.required_selectors`
- `params.viewports`

Allowed output is limited to gateway origin, service path, viewport names/dimensions, status, final path, content type, title and title hash, body-text hash/length, gateway-html and authorization-fixture booleans, auth-header boolean, gateway-session boolean, short token hash/grant hash prefix, screenshot hash/byte count, horizontal-overflow boolean, responsive-mode hash/length, required-text hashes with presence booleans, selector names/counts, console/page/request error hashes/counts, validation stage, and findings. Raw screenshots, page HTML, response bodies, cookies, local storage, tokens, CSRF values, device identifiers, and personal exports remain forbidden.

## Roadex Project Creation Flow

Use `tank.local_facility_request` when Quark needs Tank to prepare or check local MSI facilities for protected-gateway browser tests.

Supported facilities:

- `roadex.protected_gateway_browser` for `/Roadex` browser tests and Roadex project-creation flows.
- `overseer.protected_gateway_browser` for `/Overseer` semantic gateway tests such as `/Overseer/auth-check` and `/Overseer/operator-dashboard`.
- `psychlo.protected_gateway_browser` for `/Psychlo` authenticated dashboard verification.

For `/Overseer` protected-gateway request sequences, set `params.authenticated_gateway_context: true` so Tank loads the local authenticated gateway storage state before issuing requests. Tank returns only redacted booleans, statuses, short hashes, content types, and findings.

Use `roadex.project_creation_flow` when Roadex needs an approved project-creation test through the protected gateway. This job uses the local Roadex authenticated browser storage state, captures a fresh gateway CSRF token from `/Roadex/api/bootstrap`, creates the proposal, requests the one-time challenge, and confirms the proposal inside one browser context.

Required controls:

- `mutates: true`
- `params.allow_mutation: true`
- `params.require_explicit_user_approval: true`
- `params.mutation_authorization.scope: roadex_protected_gateway_active_development`
- `params.mutation_authorization.approval_source: roadex_console`
- `params.mutation_authorization.human_console_approval: true`
- `params.mutation_authorization.odo_approved: true`
- `params.mutation_authorization.issued_by: quark`
- `params.mutation_authorization.active_development_target: true`
- `params.project_name`
- `params.visibility`
- `params.team_id`
- `params.summary`

Allowed output is limited to project name, visibility, team ID hash, bootstrap/proposal/challenge/confirm statuses, CSRF presence boolean, role-presence booleans, session readiness booleans, proposal ID, operation ID, operation phase, response hash, validation stage, and findings. The challenge value is never returned.

## Local Submission Helper

Tank can also submit a job manually from MSI:

```powershell
& "C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File "C:\Users\chris\Documents\Codex\AI Project Manager\ai-project-manager\Captures\overseer-msi-test-agent-submit.ps1" -Type ping
```

The helper defaults to `god@10.50.0.100`.
