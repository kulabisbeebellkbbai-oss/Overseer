# Psychlo Credential-Scoped Recurring Cycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and approval-gate a recurring Psychlo accounting cycle that creates a fresh authority-signed Codex percentage observation before every delivery and never exposes broader Codex or signing credentials.

**Architecture:** A credential-bearing meter one-shot publishes an observation, a credential-separated delivery one-shot sends it, and a credential-free cycle one-shot sequences both with `systemctl --user start --wait`. A new narrow Overseer admin adapter installs only reviewed unit bytes, creates only the plan-owned activation marker, runs one canary, and enables only the named timer after exact human approval.

**Tech Stack:** Python 3.13, pytest, systemd user units, SQLite-backed Overseer admin plans, Codex app-server JSON-RPC, Ed25519, HMAC-authenticated Psychlo peer delivery.

## Global Constraints

- Keep signing credentials, Codex authentication, and peer-delivery credentials in separate service boundaries.
- Bind only `/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin/codex`, expected SHA-256 `cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40`, for this deployment generation.
- Set `CODEX_HOME=%d` and load only `auth.json` as a systemd credential; never bind `%h/.codex`, `%h`, conversation history, or unrelated configuration.
- Keep `overseer-psychlo-meter.service`, `overseer-psychlo-usage.service`, and `overseer-psychlo-cycle.service` static; only the timer has an `[Install]` section.
- A cycle must stop before delivery when meter production fails.
- Existing strict percentage accounting, provider-reset, policy, single-stream, lifecycle, callback, and rollout-proof gates remain authoritative.
- Source installation, marker creation, daemon reload, canary execution, and timer enablement require an exact immutable `psychlo_recurring_cycle_activation` admin plan and separate adapter-enablement approval.
- Rollback disables recurrence first and preserves observations, ledgers, projects, rounds, results, policy history, and audit records.
- No network, firewall, gateway, listener, package, credential-content, or scheduling-policy change is in scope.

---

## File Structure

- `systemd/overseer-psychlo-meter.service`: narrowly expose Codex auth and the pinned Codex executable to the producer only.
- `systemd/overseer-psychlo-cycle.service`: fixed credential-free meter-then-delivery sequencing.
- `systemd/overseer-psychlo-usage.timer`: trigger the cycle service at the existing cadence.
- `tests/test_psychlo_usage_systemd.py`: source-contract and fail-closed orchestration assertions.
- `src/overseer/psychlo_cycle_activation.py`: immutable deployment manifest validation, canonical plan construction, fixed internal execution markers, backups, canary, activation, verification, and rollback.
- `src/overseer/admin.py`: register the dedicated admin kind/capability and route internal marker execution.
- `src/overseer/cli.py`: typed plan-staging command and enabled-adapter execution integration.
- `src/overseer/ui.py`: show the new kind in the existing admin review surface without exposing raw commands.
- `src/overseer/__init__.py`: export the typed plan constructor.
- `tests/test_psychlo_cycle_activation.py`: manifest, immutable-plan, runner, rollback, and concurrency tests.
- `tests/test_core.py`: CLI/capability/persistence compatibility coverage.
- `tests/test_ui_regression.py`: approval UI visibility and no raw secret/command fields.
- `docs/admin-change-plans.md`: operator lifecycle and approval boundaries.
- `docs/local-api.md`: inactive template and recurring-cycle contract.

### Task 1: Credential-scoped meter and fail-closed cycle units

**Files:**
- Modify: `systemd/overseer-psychlo-meter.service`
- Create: `systemd/overseer-psychlo-cycle.service`
- Modify: `systemd/overseer-psychlo-usage.timer`
- Modify: `tests/test_psychlo_usage_systemd.py`

**Interfaces:**
- Consumes: existing `overseer.psychlo_usage_meter_cli`, `overseer-psychlo-usage.service`, owner-only authority/config files, systemd credential directory `%d`.
- Produces: static `overseer-psychlo-cycle.service`; timer target `overseer-psychlo-cycle.service`; meter environment `CODEX_HOME=%d` and exact pinned Codex executable path.

- [ ] **Step 1: Add failing unit-contract tests**

Add assertions equivalent to:

```python
def test_percentage_meter_receives_only_scoped_codex_login_and_binary():
    meter = (ROOT / "systemd/overseer-psychlo-meter.service").read_text()
    codex = "/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin/codex"
    assert "LoadCredential=auth.json:%h/.codex/auth.json" in meter
    assert "Environment=CODEX_HOME=%d" in meter
    assert f"Environment=PATH={Path(codex).parent}:/usr/bin" in meter
    assert f"BindReadOnlyPaths={codex}" in meter
    assert "BindReadOnlyPaths=%h/.codex" not in meter
    assert "LoadCredential=psychlo-overseer-peer-secret" not in meter


def test_cycle_sequences_meter_before_delivery_and_timer_targets_cycle():
    cycle = (ROOT / "systemd/overseer-psychlo-cycle.service").read_text()
    timer = (ROOT / "systemd/overseer-psychlo-usage.timer").read_text()
    commands = [line for line in cycle.splitlines() if line.startswith("ExecStart=")]
    assert commands == [
        "ExecStart=/usr/bin/systemctl --user start --wait overseer-psychlo-meter.service",
        "ExecStart=/usr/bin/systemctl --user start --wait overseer-psychlo-usage.service",
    ]
    assert "LoadCredential=" not in cycle
    assert "[Install]" not in cycle
    assert "Unit=overseer-psychlo-cycle.service" in timer
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_psychlo_usage_systemd.py`

Expected: failure because the auth credential, `CODEX_HOME`, pinned Codex bind, cycle unit, and timer target are absent.

- [ ] **Step 3: Implement the minimal unit changes**

Add to the meter service:

```ini
Environment=CODEX_HOME=%d
Environment=PATH=/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin:/usr/bin
LoadCredential=auth.json:%h/.codex/auth.json
BindReadOnlyPaths=/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin/codex
```

Create the cycle unit with only:

```ini
[Unit]
Description=Produce and deliver one fresh authenticated Psychlo accounting snapshot

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl --user start --wait overseer-psychlo-meter.service
ExecStart=/usr/bin/systemctl --user start --wait overseer-psychlo-usage.service
```

Change the timer target to `Unit=overseer-psychlo-cycle.service`. Do not add `[Install]` to the meter or cycle service.

- [ ] **Step 4: Verify unit source and systemd syntax**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q tests/test_psychlo_usage_systemd.py
systemd-analyze verify systemd/overseer-psychlo-meter.service systemd/overseer-psychlo-usage.service systemd/overseer-psychlo-cycle.service systemd/overseer-psychlo-usage.timer
```

Expected: all tests pass and `systemd-analyze verify` exits zero.

- [ ] **Step 5: Commit the unit slice**

```bash
git add systemd/overseer-psychlo-meter.service systemd/overseer-psychlo-cycle.service systemd/overseer-psychlo-usage.timer tests/test_psychlo_usage_systemd.py
git commit -m "Add credential-scoped Psychlo accounting cycle"
```

### Task 2: Immutable recurring-cycle activation plan

**Files:**
- Create: `src/overseer/psychlo_cycle_activation.py`
- Modify: `src/overseer/admin.py`
- Modify: `src/overseer/__init__.py`
- Create: `tests/test_psychlo_cycle_activation.py`

**Interfaces:**
- Consumes: reviewed source tree, explicit installed-unit directory, exact Codex executable path/digest, marker path, backup directory, timer name, and `AdminChangePlan`.
- Produces: `PsychloCycleActivationSpec.from_json(dict)`, `psychlo_cycle_activation_plan_digest(spec)`, `plan_psychlo_recurring_cycle_activation(plan_id, spec, reason, current_state)`, and internal fixed markers handled by `execute_psychlo_cycle_activation_marker(command)`.

- [ ] **Step 1: Write RED tests for closed manifest validation**

Test a valid manifest with exact keys:

```python
VALID = {
    "schemaVersion": "overseer.psychlo-recurring-cycle-activation.v1",
    "sourceRoot": str(source_root),
    "sourceCommit": source_commit,
    "sourceTreeDigest": source_tree_digest,
    "installedUnitDirectory": str(unit_dir),
    "backupDirectory": str(backup_dir),
    "activationMarker": str(marker),
    "codexExecutable": "/home/god/.codex/packages/standalone/releases/0.147.0-x86_64-unknown-linux-musl/bin/codex",
    "codexExecutableSha256": "cb0a15567e9a60a5820d54b0f6ae86d504dc3805c1eab21a47f70e3eb7b73a40",
    "meterCredential": str(auth_json),
    "signingCredential": str(signing_key),
    "timerUnit": "overseer-psychlo-usage.timer",
    "cycleUnit": "overseer-psychlo-cycle.service",
    "meterUnit": "overseer-psychlo-meter.service",
    "deliveryUnit": "overseer-psychlo-usage.service",
}
```

Assert rejection of unknown keys, relative paths, symlinks, paths outside the approved roots, wrong owner/mode, missing source units, changed unit digest, non-Codex binary, digest mismatch, alternate unit names, a pre-existing unowned marker, and a world-writable parent.

- [ ] **Step 2: Run the manifest tests and confirm RED**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_psychlo_cycle_activation.py -k 'manifest or digest'`

Expected: import failure because `overseer.psychlo_cycle_activation` does not exist.

- [ ] **Step 3: Implement the frozen spec and canonical digest**

Create a frozen dataclass:

```python
@dataclass(frozen=True)
class PsychloCycleActivationSpec:
    schema_version: str
    source_root: Path
    source_commit: str
    source_tree_digest: str
    installed_unit_directory: Path
    backup_directory: Path
    activation_marker: Path
    codex_executable: Path
    codex_executable_sha256: str
    meter_credential: Path
    signing_credential: Path
    timer_unit: str
    cycle_unit: str
    meter_unit: str
    delivery_unit: str

    @classmethod
    def from_json(cls, value: dict[str, object]) -> "PsychloCycleActivationSpec": ...
```

Implement exact-key parsing, canonical absolute-path checks with one leading slash and no `.`/`..`, no-follow owner/mode validation, exact unit-name allowlisting, Git commit/tree verification under a minimal `GIT_*`-free environment, source-unit SHA-256 capture, and exact executable digest verification. Canonical JSON must sort unit hashes and paths before computing the plan digest.

- [ ] **Step 4: Add RED tests for immutable admin-plan construction**

Assert:

```python
plan = plan_psychlo_recurring_cycle_activation("admin.psychlo-cycle.activate.20260816", spec, "activate approved cycle", "disabled")
assert plan.kind == AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION
assert plan.owner_domain == OwnerDomain.OBRIEN
assert plan.risk_level == RiskLevel.HIGH
assert plan.approval_level == ApprovalLevel.HUMAN
assert plan.approved is False
assert plan.adapter_metadata["specDigest"] == psychlo_cycle_activation_plan_digest(spec)
assert all(step.command[0].startswith("__overseer_psychlo_cycle_") for step in plan.steps + plan.rollback_steps + plan.verification_steps)
```

Mutate every immutable header, step, rollback, verification, or metadata field after approval and assert execution blocks before a runner is called.

- [ ] **Step 5: Register the dedicated disabled-by-default capability and plan constructor**

Add:

```python
class AdminChangeKind(StrEnum):
    PSYCHLO_RECURRING_CYCLE_ACTIVATION = "psychlo_recurring_cycle_activation"


DEFAULT_ADMIN_EXECUTION_CAPABILITIES[AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION] = AdminExecutionCapability(
    kind=AdminChangeKind.PSYCHLO_RECURRING_CYCLE_ACTIVATION,
    adapter_name="psychlo-recurring-cycle-activation",
    status=AdminAdapterStatus.DISABLED,
    summary="Psychlo recurring accounting activation requires exact adapter enablement and human approval",
    authorization_required_before_enable=True,
    approval_plan_required=True,
    supported_commands=(("__overseer_psychlo_cycle_",),),
)
```

The constructor must derive every command from the validated spec. It must not accept caller-provided commands, environment, unit names, or rollback steps.

- [ ] **Step 6: Verify the model slice**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_psychlo_cycle_activation.py -k 'manifest or digest or plan or immutable'`

Expected: all selected tests pass.

- [ ] **Step 7: Commit the immutable-plan slice**

```bash
git add src/overseer/psychlo_cycle_activation.py src/overseer/admin.py src/overseer/__init__.py tests/test_psychlo_cycle_activation.py
git commit -m "Add immutable Psychlo cycle activation plan"
```

### Task 3: Transactional deployment, canary, activation, and rollback adapter

**Files:**
- Modify: `src/overseer/psychlo_cycle_activation.py`
- Modify: `src/overseer/admin.py`
- Modify: `tests/test_psychlo_cycle_activation.py`

**Interfaces:**
- Consumes: an approved immutable activation plan and an independently approved adapter enablement record.
- Produces: fixed internal marker results for backup, install, marker publication, daemon reload, canary, enablement, verification, and rollback; no raw shell command input.

- [ ] **Step 1: Write RED fake-runner lifecycle tests**

Cover the exact ordered success path:

```python
assert calls == [
    "validate",
    "lock",
    "backup",
    "install-units",
    "publish-marker",
    "daemon-reload",
    "manual-cycle-canary",
    "verify-fresh-observation",
    "verify-durable-receipt",
    "enable-timer",
    "verify-timer",
]
```

Assert meter-canary failure prevents delivery and timer enablement; delivery failure prevents timer enablement; missing/changed executable blocks before backup; concurrent exact-plan execution returns busy without rollback; changed source/unit bytes after approval block; and a second exact execution returns verified replay rather than rerunning the canary.

- [ ] **Step 2: Run lifecycle tests and confirm RED**

Run: `PYTHONPATH=src python3 -m pytest -q tests/test_psychlo_cycle_activation.py -k 'lifecycle or canary or concurrent or replay'`

Expected: failures because marker execution and lifecycle locking are not implemented.

- [ ] **Step 3: Implement exact-plan locking and owned staging**

Use one no-follow `flock` keyed by the canonical installed-unit directory and plan digest. Hold it across validation, backup, all mutations, verification, and rollback. Create backup and marker material in private sibling directories, fsync files/directories, and publish with no-replace semantics. Reject mismatched or unmarked pre-existing state; never delete it automatically.

- [ ] **Step 4: Implement fixed internal operations**

Implement only these marker names:

```python
PSYCHLO_CYCLE_MARKERS = {
    "__overseer_psychlo_cycle_backup",
    "__overseer_psychlo_cycle_install_units",
    "__overseer_psychlo_cycle_publish_marker",
    "__overseer_psychlo_cycle_daemon_reload",
    "__overseer_psychlo_cycle_canary",
    "__overseer_psychlo_cycle_enable_timer",
    "__overseer_psychlo_cycle_verify",
    "__overseer_psychlo_cycle_rollback",
}
```

Each marker must re-read and compare the authoritative plan/spec digest before mutation. External commands are fixed absolute argv: `/usr/bin/systemctl --user daemon-reload`, `start --wait overseer-psychlo-cycle.service`, `enable --now overseer-psychlo-usage.timer`, `is-enabled`, `is-active`, and `show ... NextElapseUSecRealtime`. Use a minimal environment and bounded redacted output.

The canary must capture the pre-run observation digest and latest delivered intent/receipt identity, start the cycle once, then require a changed fresh observation plus a new durable inserted or exact duplicate receipt. It must not infer success from process exit alone.

- [ ] **Step 5: Implement rollback-first failure semantics**

Rollback order must be fixed:

```text
disable --now overseer-psychlo-usage.timer
restore exact backed-up unit bytes and prior timer-enabled state
remove only a marker whose owner record matches this plan digest
daemon-reload
verify no unintended recurring trigger remains
```

Before deleting or restoring anything, validate all backup and marker ownership records. If any ownership check fails, stop without partially deleting another resource.

- [ ] **Step 6: Route the dedicated plan through admin execution**

In `execute_admin_change_plan`, acquire the activation lifecycle lock before calling `_execute_admin_change_plan_body`. In `run_admin_command_step`, dispatch only the exact `__overseer_psychlo_cycle_*` markers to `execute_psychlo_cycle_activation_marker`; reject unexpected arguments.

- [ ] **Step 7: Run adversarial and lifecycle tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q tests/test_psychlo_cycle_activation.py
PYTHONPATH=src python3 -m pytest -q tests/test_core.py -k 'admin_execution or adapter_capabilit'
```

Expected: all selected tests pass; no real systemd command runs because tests use the injected runner and disposable paths.

- [ ] **Step 8: Commit the executor slice**

```bash
git add src/overseer/psychlo_cycle_activation.py src/overseer/admin.py tests/test_psychlo_cycle_activation.py tests/test_core.py
git commit -m "Execute approved Psychlo cycle activation safely"
```

### Task 4: Typed staging CLI and approval UI visibility

**Files:**
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/ui.py`
- Modify: `src/overseer/client.py`
- Modify: `tests/test_core.py`
- Modify: `tests/test_ui_regression.py`
- Modify: `docs/admin-change-plans.md`
- Modify: `docs/local-api.md`

**Interfaces:**
- Consumes: `plan_psychlo_recurring_cycle_activation` and a private owner-only manifest file.
- Produces: CLI `plan-psychlo-recurring-cycle-activation --store ... --plan-id ... --manifest ... --reason ...`; ordinary existing admin approval UI entry with no credential contents.

- [ ] **Step 1: Write RED CLI and UI tests**

Assert the CLI accepts only a private no-follow manifest file, stages an unapproved HUMAN/HIGH plan, and prints only plan ID/spec digest/path identities. Assert the UI lists `psychlo_recurring_cycle_activation`, shows reviewed source/unit/executable digests, and never renders auth JSON, private-key content, peer secret, arbitrary commands, or editable raw metadata.

- [ ] **Step 2: Run tests and confirm RED**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q tests/test_core.py -k psychlo_recurring_cycle
PYTHONPATH=src python3 -m pytest -q tests/test_ui_regression.py -k psychlo_recurring_cycle
```

Expected: failures because the command and UI kind do not exist.

- [ ] **Step 3: Implement typed staging only**

Add a dedicated parser that reads the manifest through the existing private-file boundary, constructs the canonical plan, and calls `store.save_admin_change_plan(plan)`. Do not add a generic command-array field. Add the kind label to the existing review UI and render only the allowlisted redacted metadata fields.

- [ ] **Step 4: Document exact approval and execution boundaries**

Document that source approval is not activation, adapter enablement and the exact plan require separate approval, the timer remains disabled until canary success, and rollback preserves durable accounting/project state. Include exact staging and status commands, but no credential contents.

- [ ] **Step 5: Verify CLI, UI, and compatibility**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q tests/test_core.py -k 'psychlo_recurring_cycle or admin_adapter'
PYTHONPATH=src python3 -m pytest -q tests/test_ui_regression.py -k 'psychlo_recurring_cycle or admin'
python3 -m compileall -q src
```

Expected: selected tests pass and Python compilation succeeds.

- [ ] **Step 6: Commit the operator-surface slice**

```bash
git add src/overseer/cli.py src/overseer/ui.py src/overseer/client.py tests/test_core.py tests/test_ui_regression.py docs/admin-change-plans.md docs/local-api.md
git commit -m "Expose approved Psychlo cycle activation workflow"
```

### Task 5: Source verification, security review, and exact deployment staging

**Files:**
- Modify only if review corrections are required: files from Tasks 1-4
- Create at runtime, not in Git: owner-only deployment manifest under `/home/god/.local/share/overseer/admin-manifests/`
- Persist at runtime: adapter-enablement record and exact admin plan in the authoritative Overseer SQLite store

**Interfaces:**
- Consumes: reviewed source commits, clean worktree, exact runtime/unit/Codex identities, authoritative Overseer store.
- Produces: source-ready evidence and two pending approval items: adapter enablement, then exact activation plan. No live mutation occurs in this task.

- [ ] **Step 1: Run focused and full verification**

Run:

```bash
PYTHONPATH=src python3 -m pytest -q tests/test_psychlo_usage_systemd.py tests/test_psychlo_cycle_activation.py tests/test_psychlo_usage_meter.py tests/test_usage_attribution.py tests/test_psychlo_bridge_cli_usage.py
PYTHONPATH=src python3 -m pytest -q
python3 -m compileall -q src
systemd-analyze verify systemd/overseer-psychlo-meter.service systemd/overseer-psychlo-usage.service systemd/overseer-psychlo-cycle.service systemd/overseer-psychlo-usage.timer
git diff --check
```

Expected: all suites pass, units verify, and the diff check is clean.

- [ ] **Step 2: Perform a final security review**

Review credential visibility, unit ordering, exact plan immutability, symlink/TOCTOU resistance, concurrent execution, crash recovery, rollback ownership, output redaction, approval binding, and timer non-activation. Any Critical or Important finding returns to RED/GREEN correction before staging.

- [ ] **Step 3: Freeze deployment inputs**

Create an owner-only manifest containing the final reviewed commit/tree digest, exact hashes of the four source units, installed-unit directory, backup directory, marker path, credential paths without contents, timer state, and the exact Codex executable path/version/SHA-256 from Global Constraints. Validate it with the typed parser before persisting a plan.

- [ ] **Step 4: Stage adapter enablement and the exact activation plan**

Use the existing adapter-enablement workflow for `psychlo_recurring_cycle_activation`, then stage:

```bash
PYTHONPATH=src python3 -m overseer.cli plan-psychlo-recurring-cycle-activation \
  --store /home/god/.local/share/overseer/project/state/overseer.sqlite3 \
  --plan-id admin.psychlo-recurring-cycle-activation.20260816 \
  --manifest /home/god/.local/share/overseer/admin-manifests/psychlo-recurring-cycle-activation.20260816.json \
  --reason "activate fresh signed accounting before every approved Psychlo scheduling cycle"
```

Expected: both records are pending; no unit, marker, service, or timer state changes.

- [ ] **Step 5: Stop at the authoritative human-approval gate**

Report the exact record IDs and expected immutable fields. Do not execute until both records are authoritatively approved in Overseer. After approval, execute only the exact plan ID; require the manual canary and verification to complete before the adapter enables the timer.

- [ ] **Step 6: Commit final source corrections and evidence docs**

```bash
git add -A
git commit -m "Prepare Psychlo recurring cycle activation"
git status --short
```

Expected: clean worktree; live deployment remains unchanged until the separately approved exact plan executes.

## Self-Review

- Spec coverage: credential scoping, service separation, fail-closed ordering, strict scheduling semantics, canary, timer activation, rollback, and exact approval binding are each assigned to Tasks 1-5.
- Placeholder scan: every implementation and test step contains concrete names, commands, and expected behavior.
- Type consistency: the spec, digest, plan constructor, marker executor, CLI, tests, and admin kind consistently use `psychlo_recurring_cycle_activation` and `PsychloCycleActivationSpec`.
- Scope discipline: recurring activation is the only new live adapter; no package, gateway, firewall, listener, quota-policy, or credential-content mutation is included.
