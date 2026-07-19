# Policies

Policies are Sisko's machine-readable gate checks for actions that may change local state.

## Admin Policy Status

Admin policy evaluation is available with:

```bash
PYTHONPATH=src python3 -m overseer.cli admin-policy-status --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli admin-policy-status --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api
```

The matching API endpoint is:

```text
GET /admin/policies
GET /admin/policies?plan_id=admin.restart.overseer-api
```

## Checks

Each admin plan is evaluated against:

- plan state: archived or canceled plans block execution
- completeness: commands, risks, rollback, and verification must be present
- approval: required approval must be recorded before execution
- adapter enablement: live execution requires an enabled adapter for the exact plan kind
- IDS review: firewall-affecting plans require an accepted IDS/firewall advisory
- rollback: rollback evidence must exist; irreversible package upgrades produce a warning
- verification: post-change verification steps must be present
- risk approval: high and critical risks must use an appropriate approval level

## Decision Status

- `pass`: no blocking or warning checks
- `warn`: no blocking checks, but operator attention is required
- `block`: at least one policy check blocks execution

Warnings are intentionally not treated as automatic execution approval. They identify cases where a human operator should confirm the residual risk before continuing.
