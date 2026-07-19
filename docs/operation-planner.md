# Operation Planner

The operation planner converts approved domain objects into execution requests. It does not run live actions. The first planner slice emits dry-run requests only and marks approval requirements before execution.

## Planned Inputs

- maintenance plans
- security signals and recommended responses

## Planner Rules

- Low-risk dry-run requests may be planned immediately.
- Maintenance plans must pass readiness checks before planning.
- Security responses that are active defense remain dry-run until a live adapter is explicitly authorized.
- Any request requiring Sisko or human approval is labeled and carries a pending approval request, but is not activated by the planner.
- Approval request ids are deterministic from the dry-run request id.

## Future Work

- Add live adapter injection after operator approval.
- Add scheduler integration for maintenance windows and usage-limit windows.
