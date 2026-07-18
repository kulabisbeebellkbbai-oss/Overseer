# Local API

The Overseer API is a loopback-only HTTP surface for local Codex threads and tools that should not shell out to the CLI for every operation.

## Boundary

- The API may bind only to `127.0.0.1` or `localhost`.
- No firewall rule is created.
- No external address is exposed.
- It uses the same explicit SQLite store path as the CLI and user service.

## Run

```bash
PYTHONPATH=src python3 -m overseer.cli serve-api --store state/overseer.sqlite3 --host 127.0.0.1 --port 8766 --auth-token-file state/api-token
```

`GET /health` is always available for local service monitoring. All other endpoints require `Authorization: Bearer <token>` when `--auth-token-file` is configured.

## Read Endpoints

- `GET /health`
- `GET /service-status`
- `GET /runtime-status`
- `GET /command-summary`
- `GET /operator-dashboard`
- `GET /maintenance-summary`
- `GET /alerts-summary`
- `GET /audit-summary`
- `GET /security-summary`
- `GET /usage-summary`
- `GET /physical-summary`
- `GET /virtual-summary`
- `GET /health-summary`
- `GET /health-efficiency`
- `GET /host/security`
- `GET /host/security/findings`
- `GET /host/security/triage`
- `GET /host/security/sources`
- `GET /host/security/source-reviews`
- `GET /host/security/ids-review-packages`
- `GET /host/security/ids-review-summary`
- `GET /admin/authorizations-required`
- `GET /admin/executions`
- `GET /admin/execution-readiness`
- `GET /admin/history-review`
- `GET /admin/history-archive-plan`
- `GET /admin/history-archives`
- `GET /admin/history-restore-readiness`
- `GET /admin/summary`
- `GET /state`

## Claim Endpoints

- `POST /claims/request`
- `POST /claims/approve`
- `POST /claims/activate`
- `POST /claims/release`
- `POST /host/inspect`
- `POST /host/security/source-reviews`
- `POST /host/security/source-reviews/block-plans`
- `POST /host/security/ids-review-packages`
- `POST /host/security/ids-review-packages/submit`
- `POST /host/security/ids-review-packages/prompts`
- `POST /host/security/ids-review-packages/results`
- `POST /host/security/remediations/plans`
- `POST /admin/plans`
- `POST /admin/approve`
- `POST /admin/cancel`
- `POST /admin/execute`
- `POST /admin/history-restore-requests`

All request bodies are JSON objects. Claim operations use the same field names as the CLI options, with underscores instead of hyphens.

`POST /host/inspect` captures read-only host evidence and persists it to the API store.
`POST /admin/plans` creates and persists an approval-gated admin change plan without executing it.
`POST /admin/approve` records approval metadata for a stored plan without executing it.
`POST /admin/cancel` marks a stored plan canceled without deleting history or executing it.
`POST /admin/execute` executes only a stored plan that passes the existing approval and completeness gates, then persists the result. Current live execution support is limited to approved user-service restart plans; unsupported or unapproved plans return persisted `blocked` results.
`GET /admin/executions` lists persisted admin execution results, including blocked and failed attempts.
`GET /admin/execution-readiness` explains each admin plan's execution gate state, including approval, missing fields, IDS review, manual execution, and Overseer-supported execution readiness.
`GET /admin/history-review` identifies completed and canceled admin plans that are candidates for future archive support. It is read-only and does not delete plans or audit evidence.
`GET /admin/history-archive-plan` prepares a read-only archive manifest for inactive admin plans. It groups each archive candidate with related execution, IDS review, and audit records, and does not mutate state.
`GET /admin/history-archives` lists persisted archive records and supports `?plan_id=...` filtering. It is read-only and does not restore or modify plans.
`GET /admin/history-restore-readiness` lists archived plans with restore risk, required approval level, archive record presence, and related evidence. It supports `?plan_id=...` filtering and is read-only.
`POST /admin/history-restore-requests` creates the approval request required before an archived plan can be restored.
`POST /admin/history-archive` marks archive-ready admin plans archived after explicit approval. It preserves the original plan, execution, IDS review, and audit records, persists an archive record, and emits an audit event.
`POST /admin/history-unarchive` restores one archived admin plan to active admin history after the restore approval is approved. It keeps the archive record and emits an audit event.
`GET /admin/summary` returns a compact operator view of admin plans, pending authorizations, execution outcomes, archive candidates, restore approvals, and recent admin audit events.

`GET /command-summary` returns Sisko's compact cross-domain view of service freshness, resources, claims, health targets, usage limits, physical assets, virtual assets, admin plans, and alerts without persisting new records.
`GET /operator-dashboard` returns a unified role-focused dashboard with overall status, attention counts, admin archive candidates, security review gate blockers, and embedded command, physical, virtual, maintenance, security, usage, health, and health-efficiency summaries.
`GET /maintenance-summary` returns O'Brien's compact view of maintenance targets, install/restart plans, pending approvals, rollback and verification readiness, and execution results.
`GET /runtime-status` returns service heartbeat freshness and host inspection freshness in a compact monitoring payload. Freshness states are `ok`, `warning`, `high`, or `missing`. Non-OK freshness states persist stable `alert` audit events in the same store.
`GET /alerts-summary` returns only persisted `alert` audit events, with counts by risk and owner domain for quick Odo/Julian review.
`GET /audit-summary` returns persisted audit events with optional `event_type`, `owner`, and `subject_prefix` query filters.
`GET /security-summary` returns Odo's compact view of security surfaces, alert audit events, latest host security findings, protective firewall/block plans, and IDS review gates.
`GET /host/security/findings` returns Odo's detailed host-security finding list, severity counts, evidence lines, and recommended actions from the latest persisted host snapshot.
`GET /host/security/triage` groups Odo's host-security findings by listener, bind scope, severity, evidence, and read-only mitigation path. It does not change firewall, route, IDS, or service-bind state.
`GET /host/security/sources` correlates established TCP remote sources to triaged listeners and reports source scope. It is evidence only; it does not declare a source hostile or change firewall, IDS, route, or service-bind state.
`GET /host/security/source-reviews` lists persisted Odo source reviews, dispositions, and whether a reviewed source is eligible for a later block-plan staging step.
`POST /host/security/source-reviews` records Odo's review of a correlated source. It does not stage a block plan or change firewall policy.
`POST /host/security/source-reviews/block-plans` stages an Odo-owned, human-approval source block plan from a reviewed hostile source. It records the plan only; firewall and IDS enforcement remain blocked until separate approval and Intrusion Detection advisory review.
`GET /host/security/ids-review-packages` lists prepared Intrusion Detection advisory packages and prompts tied to security admin plans.
`GET /host/security/ids-review-summary` returns compact IDS/firewall review gate counters, package next steps, and latest Odo audit events without full prompts or advisory text.
`POST /host/security/ids-review-packages` prepares the review package required before firewall or source-block plans can be approved. It does not run the advisor or apply policy.
`POST /host/security/ids-review-packages/submit` records manual handoff metadata for an IDS/firewall review package. It does not execute the advisor.
`POST /host/security/ids-review-packages/prompts` writes the advisory prompt under the store directory and records the prompt path. It does not execute the advisor.
`POST /host/security/ids-review-packages/results` records a manual advisory result. Firewall-affecting admin plans require an accepted result before approval.
`POST /host/security/remediations/plans` stages an Odo-owned, human-approval firewall deny plan for a triaged listener. It records the plan only; live firewall execution remains blocked until a separate approval and supported executor exist.
`GET /usage-summary` returns persisted usage-limit counts, available or exhausted capacity, unknown reset counts, low-confidence counts, next reset time, and per-limit detail for Quark review.
`GET /physical-summary` returns persisted physical identity counts, checkout readiness, power risk, storage risk, and per-asset detail for Kira review.
`GET /virtual-summary` returns persisted virtual asset counts, checkout readiness, active claims, queued claims, reserved ports, and per-asset detail for Dax review.
`GET /health-efficiency` returns Julian's compact service-health view of target status counts, probe-type coverage, owner routing, recovery requirements, and latest failures.

## Python Client

Local Python tools can use `overseer.client.OverseerApiClient` to read the token file and call the API:

```python
from overseer.client import OverseerApiClient

client = OverseerApiClient(auth_token_file="state/api-token")
runtime = client.runtime_status()
command = client.command_summary()
dashboard = client.operator_dashboard()
maintenance = client.maintenance_summary()
alerts = client.alerts_summary()
audit = client.audit_summary(owner="odo", subject_prefix="ids-review.")
security = client.security_summary()
usage = client.usage_summary()
physical = client.physical_summary()
virtual = client.virtual_summary()
efficiency = client.health_efficiency()
summary = client.health_summary()
snapshot = client.inspect_host()
findings = client.host_security_findings()
triage = client.host_security_triage()
sources = client.host_security_sources()
reviews = client.host_security_source_reviews()
review = client.create_host_security_source_review({"remote_address": "8.8.8.8", "disposition": "suspicious", "reviewed_by": "odo", "rationale": "unexpected remote source"})
source_block = client.plan_host_security_source_block({"review_id": "source-review.example"})
ids_package = client.prepare_host_security_ids_review_package({"plan_id": "admin.host-security.block-source.8-8-8-8", "source_review_id": "source-review.example"})
exported_prompt = client.export_host_security_ids_review_prompt({"package_id": ids_package["id"]})
submitted = client.submit_host_security_ids_review_package({"package_id": ids_package["id"], "submitted_by": "odo", "prompt_path": exported_prompt["prompt_path"]})
result = client.record_host_security_ids_review_result({"package_id": ids_package["id"], "status": "accepted", "advisory_result": "approved staged package", "reviewed_by": "odo"})
remediation = client.plan_host_security_remediation({"listener": "0.0.0.0:22"})
plan = client.plan_admin_change(
    {
        "plan_id": "admin.restart.overseer-api",
        "kind": "user_service_restart",
        "target": "overseer-api.service",
        "reason": "reload approved code",
    }
)
pending = client.authorizations_required()
approved = client.approve_admin_change({"plan_id": "admin.restart.overseer-api", "approved_by": "sisko"})
execution = client.execute_admin_change({"plan_id": "admin.restart.overseer-api"})
executions = client.admin_executions()
admin = client.admin_summary()
canceled = client.cancel_admin_change(
    {
        "plan_id": "admin.block.example",
        "canceled_by": "odo",
        "cancellation_reason": "reserved documentation address; no observed hostile traffic",
    }
)
```

## Installed User Service

The approved local service is installed as:

```text
/home/god/.config/systemd/user/overseer-api.service
```

The installed service reads its bearer token from an ignored local file:

```text
/home/god/.local/share/overseer/project/state/api-token
```

Rollback:

```bash
systemctl --user disable --now overseer-api.service
```
