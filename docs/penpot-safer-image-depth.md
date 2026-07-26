# Penpot Safer Image Depth Work

## Current Classification

- Core app services: `penpot-frontend`, `penpot-backend`, `penpot-exporter`, `penpot-mcp`.
- Data service: `penpot-postgres`.
- Support services already replaced after clean scans and compatibility smoke tests: `penpot-valkey`, `penpot-mailcatch`.

## Completed Support Replacements

- `penpot-valkey` now uses `valkey/valkey:8.1-alpine`.
- `penpot-mailcatch` now uses `axllent/mailpit:latest`.
- Live verification passed with Penpot HTTP 200, Mailpit HTTP 200, and Valkey `PONG`.

## App Image Candidate

- Candidate: Penpot app family `2.17`.
- Registry tag `2.17` resolves to the same digests as `2.17.0`.
- Fresh scan comparison:
  - Current `2.16` app images: 97 critical/high findings total.
  - Candidate `2.17` app images: 45 critical/high findings total.
  - Reduction: 52 findings.
- Isolated smoke test:
  - Separate Compose project.
  - Separate Postgres and asset volume names.
  - Localhost-only test ports.
  - Result: frontend HTTP 200, Mailpit HTTP 200, app containers running.
- Boundary:
  - Candidate reduces risk but still has residual critical/high findings.
  - Staged plan requires human approval and explicit acceptance of `admin.scan.residual-findings`.

## Database Image Candidate

- Candidate: `postgres:15-alpine`.
- Fresh scan comparison:
  - Current `postgres:15`: 70 critical/high findings total.
  - Candidate `postgres:15-alpine`: 15 critical/high findings total.
  - Reduction: 55 findings.
- Compatibility rehearsal:
  - Schema-only dump from live database was written under Penpot `local-secrets`.
  - Disposable `postgres:15-alpine` container became ready.
  - Schema-only import passed and created 60 public-schema tables.
- Boundary:
  - Candidate changes the database image family while preserving the same major PostgreSQL version.
  - Live execution must stay human-approved, backed up, rollback-capable, and residual-warning accepted.

## Staged Overseer Plans

- `admin.compose.penpot.app-2-17-risk-reduction.20260726`
- `admin.compose.penpot.postgres-15-alpine-risk-reduction.20260726`

Both plans are intentionally not approved. They are blocked until the operator approves the exact plan and accepts the residual scan warning.

## Approval Checklist

For each plan:

1. Review the command list, backup path, rollback command, and verification steps in the Admin page.
2. Confirm the residual vulnerability warning is acceptable as a risk-reduction change.
3. Approve the admin plan.
4. Approve the policy warning `admin.scan.residual-findings`.
5. Execute the plan.
6. Verify Penpot UI health and service status after execution.
