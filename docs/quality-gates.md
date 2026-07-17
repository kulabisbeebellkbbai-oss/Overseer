# Quality Gates

Overseer starts with conservative best-practice gates and refines them as implementation evidence accumulates.

## Universal Gates

- Every resource-changing action must identify the target resource.
- Shared resources require a lock, lease, or explicit checkout record.
- Work completion requires evidence, not only a summary.
- Audit logs must capture owner, reason, action, result, and timestamp.
- Secrets, credentials, local databases, live service state, and personal exports must not be committed.

## High-Risk Actions

The following require explicit approval before execution:

- network, gateway, firewall, proxy, or routing changes,
- service restarts that can interrupt active work,
- software installs, updates, or patch deployment,
- security protective actions,
- device flashing or hardware-affecting actions,
- deletion of remote repositories or durable state.

## Health Gates

- Service health checks must report the exact endpoint, command, or path tested.
- Failures must include the observed error and owner domain.
- Recovery must be verified before closing the incident.

## Checkout Gates

- Checkout requests must include resource identity, owner, intended action, expected duration, and release condition.
- Conflicting checkout requests must be blocked or queued.
- Expired or abandoned leases must be visible for operator review.

## Maintenance Gates

- Risky maintenance requires a rollback plan.
- Update work must record before and after versions where practical.
- Post-change checks must run before the resource is marked available.

## Security Gates

- Security events must preserve evidence.
- Active defense must be scoped to the detected risk.
- Protective changes that affect network access or service behavior require explicit approval.
