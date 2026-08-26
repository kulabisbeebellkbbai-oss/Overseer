# Overseer v1.1.6 Activation Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:test-driven-development and superpowers:verification-before-completion. This plan is executed inline in the existing isolated worktree. It prepares artifacts only and never activates them.

**Goal:** Produce a closed, hash-bound v1.1.6 activation package from the final reviewed successor to baseline commit `c3379ffad988c9ea88ef870008cb341e447ba928` while leaving live v1.1.5 services, accounts, gateway, firewall, and authority database unchanged.

**Architecture:** A new source-only package builder inventories the reviewed runtime source, the fixed installed dependency root, resolved Python interpreter, complete standard library, rendered systemd units, rollback inputs, and non-secret configuration. It writes an owner-only staging package, performs a throttled SQLite online-backup rehearsal into that package, migrates only a copied canary, and emits exact activation and rollback contracts. Human approval verifier secrets remain an explicit local interactive gate; the package cannot report `ready_for_approval` until both verifier documents are present and independently validated. Later activation is additionally gated by a root-owned final-package approval record, installed-artifact verification, and an exact digest-bound canary attestation.

**Tech Stack:** Python 3.13, SQLite backup API, Ed25519 from `cryptography`, systemd unit templates, Git tree identity, SHA-256 canonical JSON, pytest.

## Global Constraints

- Do not create the `overseer` account/group or write `/opt`, `/etc`, `/var/lib`, `/run`, or `/etc/systemd`.
- Do not stop, start, restart, reload, enable, or disable any service.
- Do not change gateway, firewall, VPN, route, SSH, other-project source, or non-Overseer databases.
- Do not print or place credentials in argv, environment variables, manifests, Git, logs, or assistant output.
- Use system UID/GID `984` only after activation preflight proves both remain unused.
- Use the resolved regular interpreter `/usr/bin/python3.13` plus release-local, hash-inventoried standard-library and `site-packages` trees.
- Preserve live v1.1.5 and its database as rollback authority; the current phase may create only a read-only online rehearsal backup and copied migration canary.
- The ordinary API token is rotation-required at activation because it appeared in a diagnostic process argument; no live rotation occurs in this plan.

---

### Task 1: Close generated package metadata

**Files:**
- Modify: `src/overseer_local.egg-info/PKG-INFO`
- Test: `tests/test_release_metadata.py`

**Interfaces:**
- Consumes: current `README.md` approval-verifier command.
- Produces: generated metadata with no plaintext human-token flags.

- [x] Add a regression assertion rejecting `--human-approval-token-file` and `--human-approval-identity` in tracked package metadata.
- [x] Run the test and observe the stale metadata failure.
- [x] Regenerate metadata from `pyproject.toml` and `README.md` without installing into the live venv.
- [x] Run the metadata test green.

### Task 2: Build a deterministic dedicated-principal release manifest

**Files:**
- Create: `src/overseer/activation_package.py`
- Create: `tests/test_activation_package.py`
- Modify: `systemd/overseer-api-system.service`
- Modify: `systemd/overseer-runtime-system.service`
- Modify: `systemd/overseer-codex-user-bridge.service`
- Modify: `systemd/overseer-admin-executor@.service`
- Modify: `tests/test_dedicated_principal_systemd.py`

**Interfaces:**
- Consumes: reviewed Git commit/tree, `src/overseer`, fixed dependency root, `/usr/bin/python3.13`, `/usr/lib/python3.13`, and systemd templates.
- Produces: canonical `overseer.dedicated-principal-release.v1` manifest and staged release payload.

- [x] Test rejection of a dirty tracked tree, symlinks, duplicate paths, unsafe modes, and dependency-root drift.
- [x] Test manifest stability and exact source/dependency/root-Python hashes.
- [x] Test rendered units use `PYTHONPATH=<release>/app/src:<release>/site-packages` and exact UIDs.
- [x] Implement the minimum closed manifest and renderer.
- [x] Run the focused manifest and systemd tests green.

### Task 3: Stage credentials without exposing secrets

**Files:**
- Modify: `src/overseer/activation_package.py`
- Modify: `tests/test_activation_package.py`

**Interfaces:**
- Consumes: existing Psychlo and Roadex secret files by verified descriptor plus the binding snapshot.
- Produces: owner-only staged copies, a fresh ordinary API token, an Ed25519 ticket keypair, non-secret credential metadata, and an interactive verifier-generation command.

- [x] Test owner/mode/link/size enforcement and destination no-replacement behavior.
- [x] Test generated credentials never appear in public manifests or command text.
- [x] Test `ready_for_approval` remains false until both scoped verifier documents exist, differ from each other, and differ from the API token.
- [x] Implement secure staging and the local interactive gate.
- [x] Run the credential tests green.

### Task 4: Rehearse WAL-consistent migration on copies only

**Files:**
- Modify: `src/overseer/activation_package.py`
- Modify: `tests/test_activation_package.py`

**Interfaces:**
- Consumes: owner-only live SQLite source opened read-only.
- Produces: throttled online backup, untouched backup digest, migrated canary digest, integrity results, schema ledger, and key-table row-count comparison.

- [x] Test backup consistency while a WAL writer commits concurrently.
- [x] Test source identity/mode/link checks and destination exclusive creation.
- [x] Test migration touches only the copied canary and preserves source/backup digests.
- [x] Test integrity failure and row-loss fail closed.
- [x] Implement the bounded backup and copied-canary migration report.
- [x] Run the migration tests green.

### Task 5: Emit exact activation, verification, and rollback contracts

**Files:**
- Modify: `src/overseer/activation_package.py`
- Modify: `tests/test_activation_package.py`
- Modify: `docs/v1.1.6-dedicated-principal-activation-plan.md`

**Interfaces:**
- Consumes: release/config/unit/rollback/credential/backup manifests.
- Produces: exact command JSON, a root-only state-machine runner, a root-only final-migration primitive, an immutable rollback bundle, and a closed package manifest. No preparation artifact grants activation without a separate digest-bound root approval record.

- [x] Test exact account UID/GID, paths, units, allowlist, install modes, hostile user-site exclusion, canary order, root-owned digest approval, installed-artifact verification, execution locking, interrupted cleanup/rollback, root-manager transient identity and every recovery state, exact live controls, cutover order, and rollback order.
- [x] Test no unresolved angle-bracket values, globs, recursive copies, token argv, or unapproved service names.
- [x] Test finalization refuses missing interactive verifier documents and any artifact drift.
- [x] Implement command rendering, package self-verification, state-machine execution, interrupted-cutover rollback recovery, and status reporting.
- [x] Run focused tests, `systemd-analyze verify`, and `git diff --check`.

### Task 6: Build the real preparation package and stop at the human gate

**Files:**
- Create outside Git: `/home/god/.local/share/overseer/activation-packages/v1.1.6-<final-commit-short>/`

**Interfaces:**
- Consumes: committed clean source and current read-only live inputs.
- Produces: owner-only package with release payload, rollback manifest, rendered units, credential staging, rehearsal backup/canary, and `awaiting_human_verifiers` status.

- [ ] Commit source implementation before package generation.
- [ ] Run the full clean test suite.
- [ ] Generate the package without live service or database mutation, using the recorded 4,096-page/no-sleep SQLite backup bound under nice-level-10 and idle-I/O process scheduling so continuous WAL commits cannot starve the rehearsal.
- [ ] Run package self-verification and inspect the exact status.
- [ ] Stop and request local interactive creation of the two human verifier documents.

### Task 7: Final defensive review and approval handoff

**Files:**
- No writes during review.

**Interfaces:**
- Consumes: committed source, clean tests, package digest, and package self-verification.
- Produces: PASS/FAIL review and a separate exact live-activation approval request.

- [ ] Run final Daybreak defensive review.
- [ ] Resolve any blocking finding and repeat verification.
- [ ] Present exact current state, proposed changes, risks, rollback, outage boundary, and commands.
- [ ] Do not execute activation without a new explicit approval for that rendered package digest.
