# Policies

Policies are Sisko's machine-readable gate checks for actions that may change local state.

## Admin Policy Status

Admin policy evaluation is available with:

```bash
PYTHONPATH=src python3 -m overseer.cli admin-policy-status --store state/overseer.sqlite3
PYTHONPATH=src python3 -m overseer.cli admin-policy-status --store state/overseer.sqlite3 --plan-id admin.restart.overseer-api
PYTHONPATH=src python3 -m overseer.cli admin-policy-status --store state/overseer.sqlite3 --policy-profile state/policy-profile.json
PYTHONPATH=src python3 -m overseer.cli active-policy-profile --store state/overseer.sqlite3
```

The matching API endpoint is:

```text
GET /admin/policies
GET /admin/policies?plan_id=admin.restart.overseer-api
GET /admin/active-policy-profile
```

When `--policy-profile` is omitted, the CLI and API look for an active profile named `policy-profile.json` in the same directory as the selected store. For the default local store, that path is `state/policy-profile.json`. If the file is missing, Overseer uses the bundled `best-practice` profile.

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

## Best-Practice Policy Profile

When no custom profile is provided, Overseer uses the bundled `best-practice` profile:

- low risk: no minimum approval beyond the plan's own approval requirement
- medium risk: Sisko approval
- high risk: Sisko approval
- critical risk: human approval
- live execution requires an enabled adapter for the exact admin change kind
- rollback steps are required
- package upgrades keep a residual rollback warning until explicitly accepted
- verification steps are required
- firewall-affecting plans require accepted Intrusion Detection advisory review
- warnings block execution until they are explicitly accepted

## Customization Helper

Generate the reusable customization questionnaire and JSON template with:

```bash
PYTHONPATH=src python3 -m overseer.cli policy-customization-helper
PYTHONPATH=src python3 -m overseer.cli policy-customization-helper --output state/policy-customization-helper.json
PYTHONPATH=src python3 -m overseer.cli build-policy-profile --answers state/policy-answers.json --output state/policy-profile.json
PYTHONPATH=src python3 -m overseer.cli active-policy-profile --store state/overseer.sqlite3
```

The helper output contains:

- `profile`: the best-practice JSON profile that can be copied into a custom policy profile file
- `questions`: stable question IDs, profile keys, defaults, options, and rationale
- `next_step`: the handoff instruction for applying the customized profile

The answer file is a JSON object keyed by stable question IDs. Example:

```json
{
  "name": "lab-profile",
  "description": "Local lab policy profile.",
  "risk-medium-approval": "sisko",
  "warnings-block": true
}
```

Use the same helper on new installs before local policy customization sessions. Keep the generated policy profile out of public commits when it contains site-specific operational choices.

Policy customization should be the final local setup step after the functional adapters and default gates are in place. Until then, use `active-policy-profile` to confirm that the best-practice defaults are active.

## Decision Status

- `pass`: no blocking or warning checks
- `warn`: no blocking checks, but operator attention is required
- `block`: at least one policy check blocks execution

Warnings are intentionally not treated as automatic execution approval. They identify cases where a human operator should confirm the residual risk before continuing.
