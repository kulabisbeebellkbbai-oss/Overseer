# Approval And Audit

Overseer must produce an audit artifact whenever a request is allowed, queued, blocked, escalated, quarantined, approved, rejected, executed, verified, or released.

## Intent

The approval and audit slice gives the command model a durable contract before any real host, service, package-manager, security, or device action exists. It records what was requested, why it needed approval, who owns the decision, and what evidence is expected.

## Approval Records

An approval request should include:

- approval id
- claim id or operation id
- requested approval level
- requester thread
- owner domain
- reason
- required evidence ids or evidence names
- status: pending, approved, rejected, expired, or superseded

## Audit Events

An audit event should include:

- event id
- event type
- actor or owner domain
- subject id
- summary
- risk level
- evidence ids
- timestamp when known

## Closure Gate

High-risk or live-change workflows should not close until the related audit records include both decision evidence and verification evidence.
