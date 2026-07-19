# Operation Planner

The operation planner converts approved domain objects into execution requests. It does not run live actions directly; live admin execution is handled by the admin adapter layer after the required approvals, advisory gates, and command boundaries are satisfied.

## Planned Inputs

- maintenance plans
- security signals and recommended responses

## Planner Rules

- Low-risk dry-run requests may be planned immediately.
- Maintenance plans must pass readiness checks before planning.
- Security responses that are active defense remain dry-run until a live adapter is explicitly authorized.
- Any request requiring Sisko or human approval is labeled and carries a pending approval request, but is not activated by the planner.
- Approval request ids are deterministic from the dry-run request id.
- Maintenance plans carry scheduler metadata so overlapping exclusive windows are visible before execution.
- Usage-limited work can be planned against current limit records to produce ready, waiting, blocked, or escalated scheduler output.

## Boundary

The planner never runs live commands. It produces dry-run requests and approval metadata. The live admin adapter layer is responsible for verifying approved plans, executing only approved command steps, recording evidence, and preserving rollback status.
