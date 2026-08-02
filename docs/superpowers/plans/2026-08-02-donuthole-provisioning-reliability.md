# DonutHole Provisioning Reliability Program Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent future DonutHole provisioning changes from reaching human approval before their cross-repository contracts, host prerequisites, active runtime, and real storage behavior are deterministically verifiable.

**Architecture:** Deliver four capability plans in dependency order. The contract harness defines executable correctness; the typed bundle moves deterministic failures before approval; the resumable executor attests and accepts the live candidate; the lifecycle UI projects those authoritative records without inventing parallel state.

**Tech Stack:** Python, SQLite, Starlette, FastMCP, systemd allowlisted operations, embedded JavaScript UI, canonical JSON/SHA-256 evidence, pytest, and Superpowers test-driven execution.

## Global Constraints

- Preserve immutable plans, evidence, and independent human approval.
- Preserve root-owned protected configuration and service-owned mutable state boundaries.
- Roadex and DonutHole provide typed intent; they never manufacture authority, crew, or approval evidence.
- Terminal success requires active-runtime attestation and behavior acceptance.
- No approval transfers across changed plan, bundle, source, runtime, configuration, contract, or acceptance digests.
- Planning approval does not authorize implementation, service restart, protected-host mutation, DonutHole provisioning, or deployment.
- Each repository is committed and reviewed independently while cross-repository contract fixtures remain synchronized.
- Existing unrelated worktree changes must be preserved.

---

## Plan Set

- [Capability A: Contract and Acceptance Harness](2026-08-02-donuthole-contract-acceptance-harness.md)
- [Capability B: Typed Bundle and Deterministic Preflight](2026-08-02-donuthole-typed-bundle-preflight.md)
- [Capability C: Resumable Execution and Runtime Attestation](2026-08-02-donuthole-resumable-execution-attestation.md)
- [Capability D: Human Lifecycle UI and Operations](2026-08-02-donuthole-lifecycle-ui-operations.md)

## Dependency Graph

```text
Capability A: executable contract and disposable acceptance harness
    |
    +--> Capability B: authoritative bundle, preflight, and review outbox
    |
    +--> Capability C: checkpoints, runtime attestation, and acceptance
             |
             +--> Capability D: lifecycle projection, UI, and operations
```

Capabilities B and C may use separate worktrees after Capability A is reviewed,
but they must not publish incompatible changes to the shared plan or contract
types. Capability D begins only after the B and C read models are stable.

---

### Task 1: Deliver the Executable Cross-Repository Contract

**Files:**
- Follow exactly: `docs/superpowers/plans/2026-08-02-donuthole-contract-acceptance-harness.md`

**Interfaces:**
- Produces: named provisioning contract version, mirrored fixtures, normalized tool schemas, disposable production-component harness, and clean-install/upgrade acceptance scenarios.
- Consumes: current Overseer and TheUnderdark source without production mutation.

- [ ] **Step 1: Create isolated worktrees for both repositories**

Use `superpowers:using-git-worktrees` at execution time. Preserve the current checkouts and unrelated files.

- [ ] **Step 2: Execute Capability A test-first tasks**

Run every checkbox in the Capability A plan in order. Do not begin runtime or UI implementation while the contract fixture and composed acceptance harness are failing.

- [ ] **Step 3: Verify both repositories independently and together**

Run the exact focused and full-suite commands in the Capability A completion gate. Expected: local suites pass independently and sibling-checkout contract equality passes when both are present.

- [ ] **Step 4: Request cross-repository code review**

Use `superpowers:requesting-code-review`. Review source identity, fixture equality, protected-path isolation, real collaborator composition, and empty-root behavior.

- [ ] **Step 5: Record reviewed source commits**

Record the reviewed Overseer and TheUnderdark commits as planning inputs for Capabilities B and C. Do not create or approve a live provisioning plan.

---

### Task 2: Move Deterministic Failures Before Approval

**Files:**
- Follow exactly: `docs/superpowers/plans/2026-08-02-donuthole-typed-bundle-preflight.md`

**Interfaces:**
- Consumes: Capability A contract version, schemas, digest algorithms, and reviewed source commits.
- Produces: typed intent, authoritative server-side bundle, read-only preflight, atomic plan/outbox staging, and idempotent review materialization.

- [ ] **Step 1: Confirm the Capability A contract is unchanged**

Run the contract equality and schema tests from Capability A. Expected: all pass before Capability B writes code.

- [ ] **Step 2: Execute Capability B test-first tasks**

Run every checkbox in the Capability B plan in order. The public stage surface must accept only typed intent plus expected preview digests; it must rebuild authority and crew data server-side.

- [ ] **Step 3: Verify atomicity and legacy behavior**

Run the transaction-failure, exact-retry, outbox, legacy-plan, API, and CLI tests specified by Capability B. Expected: no partial plan, bundle, outbox, or crew state survives an injected failure.

- [ ] **Step 4: Request security and workflow code review**

Use `superpowers:requesting-code-review`. Review raw-field rejection, source resolution, authorization freshness, outbox ordering, immutable digest boundaries, redaction, and legacy staging policy.

- [ ] **Step 5: Stop at the deployment boundary**

Do not deploy or restart Overseer. A separate exact admin plan and human approval are required after the implementation branch is reviewed.

---

### Task 3: Make Approved Execution Resumable and Verifiable

**Files:**
- Follow exactly: `docs/superpowers/plans/2026-08-02-donuthole-resumable-execution-attestation.md`

**Interfaces:**
- Consumes: reviewed Capability A contract and Capability B immutable bundle/preflight records.
- Produces: durable execution checkpoints, convergent host operations, TheUnderdark runtime attestation, behavior acceptance, and evidence unique to the actual execution.

- [ ] **Step 1: Confirm B's plan and bundle interfaces are stable**

Run Capability B's focused contract and persistence tests. Expected: all pass without compatibility shims in Capability C.

- [ ] **Step 2: Execute Capability C test-first tasks in repository order**

Implement Overseer contracts/coordinator first, TheUnderdark runtime attestation second, and Overseer acceptance wiring third. Record separate repository commits.

- [ ] **Step 3: Verify resume, conflict, and stale-runtime behavior**

Run the exact Capability C checkpoint, idempotency, restart, attestation, and acceptance tests. Expected: exact state becomes verified no-op, conflicts fail closed, and stale runtime cannot produce terminal success.

- [ ] **Step 4: Request two-stage review**

Use `superpowers:requesting-code-review` for both the spec compliance and code quality/security review. Verify that evidence contains safe identities rather than secrets or raw process output.

- [ ] **Step 5: Stop at the protected-host boundary**

Do not install the runtime, restart services, or execute a provisioning plan. Those operations require their existing exact approval records.

---

### Task 4: Expose the Authoritative Lifecycle to Humans

**Files:**
- Follow exactly: `docs/superpowers/plans/2026-08-02-donuthole-lifecycle-ui-operations.md`

**Interfaces:**
- Consumes: Capability B bundle/preflight/review records and Capability C execution/checkpoint/attestation/acceptance records.
- Produces: pure lifecycle projection, read-only lifecycle API, accurate approval actions, responsive UI state rendering, and operator documentation.

- [ ] **Step 1: Freeze the B/C read-model fixtures**

Run the backend lifecycle fixtures specified by Capability D. Expected: every required state can be produced without UI-local mutation.

- [ ] **Step 2: Execute Capability D test-first tasks**

Run every checkbox in the Capability D plan in order. Approval labels and responses must never claim completion before acceptance.

- [ ] **Step 3: Verify backend, API, UI, accessibility, and responsive behavior**

Run the focused UI/API suites and full local suite from Capability D. Expected: buttons are enabled only for the exact ready state and every disabled action has an accessible reason.

- [ ] **Step 4: Request UI and workflow review**

Use `superpowers:requesting-code-review`. Review state derivation, stale predecessor suppression, polling idempotency, redaction, protected-route behavior, and display-mode regressions.

- [ ] **Step 5: Stage deployment and remote validation separately**

Prepare—but do not execute—the exact Overseer restart/admin plan. After human approval and deployment, request the separately authorized Quark protected-gateway UI regression and record its redacted result.

---

## Program Completion Gate

The program is complete only when all capability completion gates pass and code review confirms:

- malformed intent fails before immutable review publication;
- committed review messages cannot precede their plan;
- nonexistent or changed source identity fails before approval;
- exact retries converge without replaying completed state;
- the active service attests the approved runtime and configuration;
- real root-relative, nested, pagination, backup, and restore behavior pass;
- terminal success is impossible without acceptance;
- execution evidence distinguishes deployments and process starts;
- the UI never presents approval or handler completion as acceptance;
- protected configuration ownership and independent approval remain intact.

Use `superpowers:verification-before-completion` before any completion claim and `superpowers:finishing-a-development-branch` only after all local and separately approved live verification is complete.
