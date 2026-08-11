# Task 11 authoritative-workflows correction

## Scope

Corrected the rejected Overseer Task 11 bridge workflows from `d2c7dd9`.
The implementation is source-only in the isolated worktree and does not
activate or restart a live service.

## Corrections

- Added immutable persisted approval records and approval-ID-only initiators.
  Initiators validate human approval, owner, action, target, expiry,
  cancellation, payload digest, and evidence before computing outbound
  payloads and Roadex decision fields.
- Added authenticated Admin, local-admin, and Roadex aliases for all five
  initiators. Added an authenticated Psychlo HMAC canary-result route with a
  strict full result contract and nested execution/digest/overlap validation.
- Ceiling authorization now requires a delivered, parsed canary result bound
  to exact target ceiling and revision; arbitrary protocol rows are rejected.
- Changed coordination work so a lead dispatch persists only a dispatch ID.
  Added exact participant-result callbacks, optional configured supervisor
  review dispatch/callback, durable replay/conflict binding, and restart-safe
  forwarding without fabricating terminal results or normal rounds.
- Forward failures now leave `forward-pending` durable state and raise a
  controlled pending error. Recovery retries are bounded and never turns a
  dispatch ID into a terminal result.
- Fixed ingress `projectId` optional-key parsing and added strict contract and
  route regression tests.

## Verification

- Focused bridge/contracts/external-round tests: 34 passed.
- Full Overseer test suite: 1,139 passed, 5 skipped.
- `python3 -m compileall -q src/overseer tests`: passed.
- `git diff --check`: passed.

## Commit

`8cd75cf` — `Harden authoritative Psychlo bridge workflows`
