# Quark Remote Testing Authenticator

## Intent

Quark issues short-lived scoped credentials so Tank and future testing agents can run protected-gateway tests without using the standing Overseer API token or requiring human token relay.

## Account Model

Remote testing accounts are service accounts owned by Quark and monitored by Odo. Accounts are platform neutral. Current and future agents identify themselves with `agent_kind` and `agent_id`, for example:

- `windows` / `tank-msi`
- `android` / a future Android worker id
- `ios` / a future iOS worker id
- `macos` / a future Apple worker id
- `gateway` / a gateway-native probe

Accounts are read-only by default. Odo records token issue, use, denial, revocation, expiry, source or scope violation, and mutation attempts. Scope violations can disable the account automatically.

Each account also records an explicit `gateway_principal`. Protected Service
Gateway may establish backend identity only from that validated account field;
it must not infer a Roadex user from the project, worker, lease, or request.

## Token Model

Quark token grants are bound to:

- one account
- one lease, when available
- one job, when available
- one project and optional thread id
- explicit protected-gateway service paths such as `/Overseer`, `/Roadex`, `/_gateway`, or a future app path
- explicit HTTP methods and route patterns
- short expiry capped by Overseer
- an optional exact mutation scope

Raw tokens are not written to queue files, result files, chat, screenshots, or logs. `quark-control.json` stores only token hashes and redacted metadata. The raw token is written once to `local-secrets/remote-testing/tokens/` with local-only permissions for the worker exchange path.

## Mutation Policy

Read-only is the default. Mutating tokens require `mutates=true`, an exact mutation scope, and a job contract that names the fixture, project, thread, endpoint, method, expected side effect, and cleanup or rollback. Runtime authorization checks both the broader token grant and the exact mutation scope before allowing a non-read method. Broad admin, credential, user-management, firewall, package, route, or approval mutations remain outside routine test-token authority.

## Gateway Scope

The model is not tied to Overseer. A token can be issued for any current or future app/web page served through the Protected Service Gateway by granting the exact service path and routes needed for that test. The gateway itself can be represented as its own service path, such as `/_gateway`, with route-specific read-only checks unless a specific mutation is approved.

For `roadex.authenticated_session_prompt`, Quark must issue the token before enqueueing and scope it to project `Roadex`, service path `/Roadex`, the protected gateway origin, `GET /api/bootstrap`, and the exact `POST /api/sessions/:sessionId/prompts` mutation. Overseer rejects the queue operation when the grant is missing, inactive, assigned to another lease or project, outside the gateway scope, or read-only.

Protected Service Gateway validates every `qrt_` bearer request through Overseer's loopback authorization bridge using the actual method and path. It creates only an in-memory Roadex session context for CSRF continuity and removes the bearer header before proxying to Roadex. Revocation and expiry therefore take effect on the next request.

## Security Risks And Mitigations

Primary risk: a compromised testing worker could use an active token within its grant. Mitigations are short TTLs, route and method scopes, one-lease and one-job binding, read-only defaults, Odo monitoring, auto-disable on scope violations, revocation, no raw token in queue/results, and exact mutation scopes.

Residual risk remains during the active lease window. Keep test windows short and mutation scopes narrow.
