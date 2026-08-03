# Protected App Publication Workflow Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development`, test-driven development, and
> independent security/code review. This plan is separate from DonutHole backup
> provisioning and grants no deployment or network authority.

**Goal:** Turn Roadex's existing default-off publication request intake into a
reusable, authoritative, approval-gated workflow for multiple protected
projects without allowing Roadex to activate routes itself.

**Architecture:** Roadex remains a bounded requester. Overseer owns the durable
publication lifecycle and exact approvals. Protected Service Gateway owns the
allowlisted prefix registry, route validation, deployment, activation, and
rollback. A project can request only an already-enrolled prefix capability; it
cannot create gateway authority through its request payload.

## Constraints

- Existing Roadex requests remain `submitted` until an authoritative workflow
  reference is bound prospectively.
- Roadex cannot approve, deploy, activate, edit gateway configuration, change
  firewall/IDS policy, or register a new prefix.
- Prefix enrollment is a separate Protected Service Gateway and Overseer
  operation with security/IDS review and explicit human approval.
- A publication approval is not route activation, application deployment, or
  firewall authorization.
- No existing submitted request is retroactively promoted without an exact
  migration decision and new binding.

---

### Task 1: Define the cross-repository publication contract

**Files:**

- Create in Overseer: `tests/fixtures/protected_app_publication_v1.json`
- Create in Roadex: `tests/fixtures/protected_app_publication_v1.json`
- Create in Protected Service Gateway:
  `tests/fixtures/protected_app_publication_v1.json`
- Modify in Roadex: `src/shared/appPublicationContracts.ts`

- [ ] Define canonical request, enrollment capability, authoritative workflow
  reference, status, deployment evidence, activation evidence, rollback, and
  terminal failure fields.
- [ ] Keep requester fields separate from gateway-owned prefix, listener,
  backend, route-policy, firewall/IDS, and activation fields.
- [ ] Make Overseer the canonical fixture owner and require exact mirror
  equality in the other repositories.
- [ ] Add negative fixtures for an unenrolled prefix, prefix overlap, traversal,
  method-policy mismatch, stale deployment artifact, and approval-scope drift.
- [ ] Review and commit the fixture before producer or gateway implementation.

---

### Task 2: Add an authoritative default-off Overseer lifecycle

**Files:**

- Create: `src/overseer/protected_gateway_publication.py`
- Modify: `src/overseer/store.py`
- Modify: `src/overseer/api.py`
- Create: `tests/test_protected_gateway_publication.py`
- Modify: `tests/test_ui_regression.py`

- [ ] Add immutable request binding, review, human decision, deployment-ready,
  activation-ready, active, failed, rolled-back, and successor-required states.
- [ ] Prospectively bind a Roadex request to its exact authoritative workflow;
  reject retroactive or changed binding.
- [ ] Expose authenticated read-only status with a digest-derived decision
  version and no GET mutation.
- [ ] Keep deployment and activation transitions callable only through exact
  separately approved operator adapters.
- [ ] Test replay, tamper, redaction, stale enrollment, rollback, and successor
  behavior before any live integration.

---

### Task 3: Bind Roadex request intake to authoritative status

**Roadex files:**

- Modify: `src/server/appPublicationRequester.ts`
- Modify: `server/index.ts`
- Modify: `src/client/sessionApi.ts`
- Modify: `src/App.tsx`
- Modify matching requester, policy, API, state-persistence, and UI tests.

- [ ] Return the durable Roadex request immediately as `submitted`.
- [ ] Bind only a returned authoritative Overseer workflow reference; never
  accept caller-provided approval, gateway, or activation state.
- [ ] Poll and render the exact authoritative status without creating a Roadex
  lifecycle store or optimistic completion.
- [ ] Keep approve, deploy, and activate routes absent from Roadex.
- [ ] Show explicit pending owner, blocker, successor, and rollback evidence.

---

### Task 4: Add gateway-owned prefix enrollment and route validation

**Protected Service Gateway files:**

- Modify: `src/protected_service_gateway/config.py`
- Modify: `src/protected_service_gateway/gateway.py`
- Modify matching configuration, routing, security, and protected-prefix tests.

- [ ] Define an exact operator-owned prefix enrollment registry with project,
  application, upstream mode, route policy, and approval references.
- [ ] Reject unregistered, overlapping, ambiguous, traversal, case-variant, and
  stale enrollment requests.
- [ ] Prove longest-prefix and path-preservation behavior for every enrolled
  application without weakening existing `/Roadex` routing.
- [ ] Keep listener, backend, identity assertion, method/body/rate policy, and
  route activation owned by the gateway deployment artifact.
- [ ] Require Odo/IDS review for any exposure or policy change; absence of a new
  external exposure must be demonstrated rather than inferred.

---

### Task 5: Verify the harmless full path and stage operations separately

- [ ] Compose Roadex request, prospective Overseer binding, independent human
  decision fixture, gateway enrollment validation, deployment evidence,
  activation evidence, read-only status, and rollback in disposable stores and
  loopback-only test services.
- [ ] Prove an unenrolled second project is denied, then enroll a fixture-only
  second project through the operator-owned registry and pass the same
  conformance suite.
- [ ] Run focused and full suites in each repository and record a reviewed SHA
  manifest.
- [ ] Prepare separate exact deployment plans for Roadex, Overseer, Protected
  Service Gateway, and any firewall/IDS change. Each plan names backups,
  artifacts, configuration, health checks, acceptance, and rollback.
- [ ] After explicit approvals, deploy in owner order and run protected-gateway
  acceptance. Never treat request submission or human approval alone as active
  publication.

## Completion Gate

- [ ] Roadex remains requester-only.
- [ ] Overseer owns authoritative workflow and approval state.
- [ ] Protected Service Gateway owns prefix enrollment and activation.
- [ ] A second fixture project passes the same contract without copying Roadex
  or DonutHole-specific logic.
- [ ] Submitted, approved, deployed, and active remain distinct.
- [ ] Cross-repository tests and separately approved live acceptance pass.
