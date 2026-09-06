# Overseer Dedicated Collector Bridge Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the dedicated-principal successor collect the three required
user-session projections through the typed bridge, diagnose acceptance failures
exactly, and leave a reusable empty destination after sealed rollback.

**Architecture:** Extend the existing fixed Unix bridge with two read-only,
empty-parameter projections. The dedicated runtime persists sanitized results
in its authority store. Full rollback atomically archives the verified failed
successor namespace beside preservation evidence and recreates the empty
numeric-owner destination before writer restoration.

**Tech Stack:** Python 3.13, SQLite, systemd socket activation, pytest.

## Global Constraints

- Do not import or execute a package or mutate live service, approval, claim,
  VM, gateway, firewall, reboot, Phase B, canary, or cutover state.
- Do not expose caller-selected paths, units, argv, environment, credentials,
  prompts, remote URLs, or arbitrary Git refs through the bridge.
- Preserve independent schedules, bounded provider concurrency, hard timeouts,
  durable scheduler/triage evidence, and UI reads from stored data.
- Preserve failed successor stores and sidecars recoverably; never overwrite a
  legacy authority database.

---

### Task 1: Extend the closed user-bridge protocol

**Files:**
- Modify: `src/overseer/user_bridge.py`
- Modify: `src/overseer/user_bridge_providers.py`
- Modify: `tests/test_user_bridge.py`

**Interfaces:**
- Produces: `overseer.scheduler.freshness.v1` and
  `overseer.git.status.v1`, both with empty params and bounded allowlisted
  projections.

- [ ] Add protocol tests for valid projections, sanitization, unsupported
  parameters, output bounds, provider timeout, and default-provider wiring.
- [ ] Run the focused tests and confirm they fail because the methods and
  providers do not exist.
- [ ] Implement fixed systemd and Git providers plus method-specific response
  sanitization with no shell or caller-selected input.
- [ ] Run `python3 -m pytest -q tests/test_user_bridge.py` and require success.

### Task 2: Route the three built-in jobs through the bridge

**Files:**
- Modify: `src/overseer/runtime.py`
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/git.py`
- Modify: `systemd/overseer-runtime-system.service`
- Modify: `systemd/overseer-codex-user-bridge.service`
- Modify: `tests/test_collection_runtime.py`
- Modify: `tests/test_dedicated_principal_api.py`
- Modify: `tests/test_user_bridge.py`

**Interfaces:**
- Consumes: the two bridge projections from Task 1.
- Produces: bridge-backed collection executions and the existing durable Git
  dashboard projection.

- [ ] Add tests proving only the three fixed jobs remain enabled in dedicated
  mode, custom/user-mutation jobs stay disabled, bridge failures are bounded,
  and sanitized Git status is persisted.
- [ ] Run the tests and confirm the old blanket-disable/direct-command behavior
  fails them.
- [ ] Add shared environment client construction, bridge-backed adapters,
  durable Git projection persistence, and required systemd dependencies and
  read-only bindings.
- [ ] Run the bridge, runtime, API, and systemd focused tests and require
  success.

### Task 3: Prove real dedicated-principal acceptance and diagnostics

**Files:**
- Modify: `src/overseer/activation_package.py`
- Modify: `tests/test_maintenance_window_controls.py`

**Interfaces:**
- Consumes: real scheduler job/state serialization from Task 2.
- Produces: exact bounded scheduler acceptance failure reasons.

- [ ] Add an integration test that seeds a temporary authority store in
  dedicated mode, executes the three typed bridge jobs, serializes their real
  job state, and passes that data through maintenance acceptance.
- [ ] Add negative tests for missing, disabled, unsuccessful, invalid-interval,
  missing-age, and stale job diagnostics.
- [ ] Run those tests and confirm they fail against the current boolean-only
  acceptance implementation.
- [ ] Implement the minimal diagnostic result and keep the required job set
  unchanged.
- [ ] Run the maintenance-control tests and require success.

### Task 4: Archive failed successor state during rollback

**Files:**
- Modify: `src/overseer/activation_package.py`
- Modify: `tests/test_maintenance_window_storage.py`
- Modify: `tests/test_maintenance_window.py`
- Modify: `docs/v1.1.6-maintenance-window-deployment.md`

**Interfaces:**
- Consumes: the locked destination descriptor, sealed `evidenceRoot`, and
  fixed numeric principal identity.
- Produces: root-owned `failed-successor-store` evidence and a verified empty
  `984:984` mode `0700` destination namespace.

- [ ] Add tests for atomic no-replace archive, replay after rename, conflicting
  archive rejection, same-filesystem enforcement, destination recreation, and
  no legacy writer restart after cleanup failure.
- [ ] Run the focused tests and confirm they fail because rollback currently
  leaves the root-locked destination in place.
- [ ] Implement descriptor-bound archive/recreate behavior inside the existing
  store-restoration command without deleting failed successor evidence.
- [ ] Run storage, contract, and rollback tests and require success.

### Task 5: Verify, review, and prepare the replacement package

**Files:**
- Modify: `docs/v1.1.6-user-bridge.md`
- Modify: `docs/v1.1.6-dedicated-principal-design.md`
- Modify: `docs/v1.1.6-maintenance-window-deployment.md`
- Modify: `docs/superpowers/plans/2026-09-02-overseer-maintenance-window-deployment.md`

**Interfaces:**
- Produces: reviewed source and one verified owner-scoped package awaiting a
  separate digest-bound import approval.

- [ ] Run all focused bridge, runtime, API, maintenance, package, and systemd
  suites.
- [ ] Run the complete repository test suite and inspect all output.
- [ ] Obtain independent correctness review and resolve every critical or
  important finding.
- [ ] Obtain final security review using `gpt-daybreak-blue-latest`, with
  `gpt-5.6-terra` only if the security model is unavailable.
- [ ] Regenerate and verify the owner-scoped package through the existing
  package tooling without importing or executing it.
- [ ] Confirm live Overseer health and unchanged approval/claim/service state,
  then report the replacement digest and exact next approval boundary.
