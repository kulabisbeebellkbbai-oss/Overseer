# DonutHole Resumable Execution and Runtime Attestation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make approved DonutHole provisioning converge through durable phases and reach terminal success only after the active TheUnderdark process attests the approved runtime and passes real behavior acceptance.

**Architecture:** Add immutable execution records and append-only phase checkpoints beside the existing immutable plan. Refactor execution into materialize, register, activate, attest, and accept phases; exact verified state resumes as a no-op, while conflicting state fails before mutation. TheUnderdark computes its active runtime and configuration identities at startup, and Overseer verifies those identities plus the Capability A behavior contract before marking the plan executed.

**Tech Stack:** Python frozen dataclasses and enums, SQLite JSON payload records, existing allowlisted subprocess adapter, systemd, Starlette/FastMCP, SHA-256 canonical JSON, pytest, and the Capability A cross-repository contract fixtures.

## Global Constraints

- Capability A must be merged in both Overseer and TheUnderdark before this plan begins.
- Capability B must supply an immutable bundle, passing preflight report, and exact human approval before execution starts.
- Root-owned authorization configuration remains immutable to TheUnderdark and DonutHole.
- Human approval never transfers across plan, bundle, runtime, configuration, or acceptance-contract digest changes.
- The executor remains an exact operation allowlist and never accepts a generic command or shell string.
- Secrets, private paths, token contents, and raw subprocess output never enter execution evidence.
- Plan status remains approved while phases are in progress and becomes executed only after attestation and behavior acceptance pass.
- Exact existing state is a verified no-op; conflicting existing state is a stable fail-closed error.
- No implementation task authorizes a service restart, protected-host mutation, live DonutHole provisioning, or deployment.
- Existing unrelated worktree changes must be preserved.

---

## File and Responsibility Map

**Create in Overseer**

- `src/overseer/backup_execution.py` — execution phases, evidence records, digesting, checkpoint persistence orchestration, and resumable phase coordinator.
- `src/overseer/backup_acceptance.py` — production read-only TheUnderdark attestation and behavior-acceptance runner built from the Capability A contract.
- `tests/test_backup_execution.py` — phase transitions, checkpoint resume, failure, rollback, and evidence digest tests.
- `tests/test_backup_acceptance.py` — attestation and project/root/list behavior tests with a protocol fake.
- `tests/test_backup_execution_integration.py` — approved-plan execution through real phase/checkpoint storage with an allowlisted adapter fake.

**Modify in Overseer**

- `src/overseer/store.py` — additive execution-record and checkpoint tables plus transaction-aware CRUD.
- `src/overseer/backup_provisioning.py` — delegate approved execution to the phased coordinator and expose authoritative summaries without changing legacy plan digests.
- `src/overseer/backup_host_operations.py` — structured dispositions, explicit service activation, state probes, runtime attestation, and acceptance operations.
- `src/overseer/api.py` — exact start/continue execution routes and read-only execution status.
- `src/overseer/backup_provisioning_cli.py` — exact start/continue/status commands.
- `tests/test_backup_provisioning.py` — compatibility and terminal-status assertions.
- `tests/test_backup_host_operations.py` — idempotent/no-op/conflict and explicit-restart tests.
- `tests/test_backup_provisioning_review_flow.py` — approval remains exact and execution remains separately gated.
- `docs/operator-workflows.md` — phased execution, retry, rollback, and successor procedure.

**Create in TheUnderdark**

- `src/theunderdark/runtime_identity.py` — deterministic runtime/config identity calculation and immutable runtime-attestation record.
- `tests/test_runtime_identity.py` — exclusions, mode sensitivity, expected-identity mismatch, and redaction tests.

**Modify in TheUnderdark**

- `src/theunderdark/production_cli.py` — compute and verify active identities before serving and inject them into the production app.
- `src/theunderdark/production_app.py` — include safe runtime attestation in HTTP and MCP health output.
- `tests/test_production_cli.py` — expected identity arguments and startup rejection.
- `tests/test_production_app.py` — exact attested health contract.
- `tests/test_production_readiness.py` — composed health and no-secret assertions.
- `docs/encrypted-backups.md` — runtime identity and acceptance contract.

---

### Task 1: Add Durable Execution and Checkpoint Contracts

**Files:**
- Create: `src/overseer/backup_execution.py`
- Create: `tests/test_backup_execution.py`
- Modify: `src/overseer/store.py`

**Interfaces:**
- Consumes: immutable `DonutHoleBackupProvisioningPlan.plan_id`, `plan_digest`, and Capability B `bundle_digest`.
- Produces: `ExecutionPhase`, `StepDisposition`, `PhaseStatus`, `ProvisioningStepEvidence`, `ProvisioningCheckpoint`, `RuntimeAttestation`, `BehaviorAcceptance`, `ProvisioningExecutionRecord`, and transaction-aware store CRUD.

- [ ] **Step 1: Write failing contract and digest tests**

```python
from dataclasses import replace

import pytest

from overseer.backup_execution import (
    BehaviorAcceptance,
    ExecutionPhase,
    PhaseStatus,
    ProvisioningExecutionRecord,
    ProvisioningStepEvidence,
    RuntimeAttestation,
    StepDisposition,
    execution_evidence_digest,
)


def test_execution_digest_changes_with_active_runtime_and_acceptance() -> None:
    attestation = RuntimeAttestation(
        runtime_digest="sha256:" + "a" * 64,
        config_digest="sha256:" + "b" * 64,
        process_start_id="sha256:" + "c" * 64,
    )
    acceptance = BehaviorAcceptance(
        contract_version="donuthole-backup-provisioning-v1",
        passed=True,
        results_digest="sha256:" + "d" * 64,
    )
    record = ProvisioningExecutionRecord.new(
        execution_id="execution.plan-1",
        plan_id="plan-1",
        plan_digest="sha256:" + "e" * 64,
        bundle_digest="sha256:" + "f" * 64,
    )
    first = execution_evidence_digest(replace(record, attestation=attestation, acceptance=acceptance))
    changed = execution_evidence_digest(
        replace(record, attestation=replace(attestation, process_start_id="sha256:" + "1" * 64), acceptance=acceptance)
    )
    assert first != changed


def test_failed_acceptance_cannot_form_terminal_success() -> None:
    with pytest.raises(ValueError, match="acceptance"):
        ProvisioningExecutionRecord.new(
            execution_id="execution.plan-1",
            plan_id="plan-1",
            plan_digest="sha256:" + "e" * 64,
            bundle_digest="sha256:" + "f" * 64,
        ).complete(
            BehaviorAcceptance("donuthole-backup-provisioning-v1", False, "sha256:" + "d" * 64)
        )
```

- [ ] **Step 2: Run the focused test and verify the missing-module failure**

Run: `pytest -q tests/test_backup_execution.py`

Expected: collection fails because `overseer.backup_execution` does not exist.

- [ ] **Step 3: Implement the immutable contracts and canonical evidence digest**

```python
class ExecutionPhase(StrEnum):
    MATERIALIZE = "materialize"
    REGISTER = "register"
    ACTIVATE = "activate"
    ATTEST = "attest"
    ACCEPT = "accept"


class PhaseStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class StepDisposition(StrEnum):
    CHANGED = "changed"
    VERIFIED_NOOP = "verified_noop"
    FAILED = "failed"


@dataclass(frozen=True)
class RuntimeAttestation:
    runtime_digest: str
    config_digest: str
    process_start_id: str


@dataclass(frozen=True)
class BehaviorAcceptance:
    contract_version: str
    passed: bool
    results_digest: str


def execution_evidence_digest(record: ProvisioningExecutionRecord) -> str:
    payload = asdict(record)
    payload.pop("evidence_digest", None)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
```

Validate every identifier and digest, keep timestamps out of deterministic target digests but inside execution evidence, and make all collections tuples or immutable mappings.

- [ ] **Step 4: Add transaction-aware store methods and rollback tests**

```python
def save_backup_execution(self, record: ProvisioningExecutionRecord) -> None:
    self._connection.execute(
        "INSERT INTO backup_provisioning_executions(id, plan_id, payload) VALUES(?,?,?)",
        (record.execution_id, record.plan_id, _dump(record)),
    )
    self._commit_agent_mutation()


def save_backup_checkpoint(self, checkpoint: ProvisioningCheckpoint) -> None:
    self._connection.execute(
        "INSERT INTO backup_provisioning_checkpoints(id, execution_id, payload) VALUES(?,?,?)",
        (checkpoint.id, checkpoint.execution_id, _dump(checkpoint)),
    )
    self._commit_agent_mutation()
```

Add tests that inject a failure between the execution record and checkpoint insert inside `store.agent_transaction()` and assert neither row survives.

- [ ] **Step 5: Run focused store and execution tests**

Run: `pytest -q tests/test_backup_execution.py tests/test_agent_store.py -x`

Expected: all selected tests pass, including transaction rollback and exact-byte idempotency.

- [ ] **Step 6: Commit the execution contracts**

```bash
git add src/overseer/backup_execution.py src/overseer/store.py tests/test_backup_execution.py
git commit -m "Add durable backup execution checkpoints"
```

---

### Task 2: Implement the Resumable Phase Coordinator

**Files:**
- Modify: `src/overseer/backup_execution.py`
- Modify: `src/overseer/backup_provisioning.py`
- Create: `tests/test_backup_execution_integration.py`
- Modify: `tests/test_backup_provisioning.py`

**Interfaces:**
- Consumes: Capability B `load_provisioning_bundle(plan_id)`, passing preflight digest, approved plan, and exact `ProvisioningAdapter.execute(step)`.
- Produces: `start_execution(store_path, plan_id, adapter, acceptance_runner, now=None)` and `continue_execution(store_path, execution_id, adapter, acceptance_runner, now=None)`.

- [ ] **Step 1: Write failing phase-order and resume tests**

```python
def test_resume_skips_only_digest_bound_passed_steps(prepared_bundle, recording_adapter) -> None:
    first = start_execution(prepared_bundle.store, prepared_bundle.plan_id, recording_adapter, acceptance_runner=None)
    assert first.current_phase == "attest"
    assert first.status == "failed"

    resumed = continue_execution(prepared_bundle.store, first.execution_id, recording_adapter, passing_acceptance)
    assert resumed.status == "passed"
    assert recording_adapter.calls.count("install_runtime") == 1
    assert resumed.acceptance.passed is True


def test_changed_plan_digest_cannot_resume_checkpoint(prepared_bundle, recording_adapter) -> None:
    execution = start_execution(prepared_bundle.store, prepared_bundle.plan_id, recording_adapter, acceptance_runner=None)
    prepared_bundle.replace_plan_digest("sha256:" + "9" * 64)
    with pytest.raises(ValueError, match="checkpoint.*digest"):
        continue_execution(prepared_bundle.store, execution.execution_id, recording_adapter, passing_acceptance)
```

- [ ] **Step 2: Run the focused tests and observe the missing coordinator**

Run: `pytest -q tests/test_backup_execution_integration.py`

Expected: tests fail because `start_execution` and `continue_execution` are unavailable.

- [ ] **Step 3: Group existing immutable steps into explicit phases**

```python
PHASE_OPERATIONS = {
    ExecutionPhase.MATERIALIZE: (
        "verify_published_adapter_source", "install_runtime", "ensure_system_user",
        "ensure_directory", "generate_secret_file", "install_overseer_api_token",
        "generate_cursor_key", "ensure_read_only_acl", "install_private_config",
        "install_systemd_unit",
    ),
    ExecutionPhase.REGISTER: ("register_authorized_roots",),
    ExecutionPhase.ACTIVATE: ("stop_disable_user_service", "start_enable_system_service"),
    ExecutionPhase.ATTEST: ("verify_runtime_attestation",),
    ExecutionPhase.ACCEPT: ("run_behavior_acceptance", "verify_gpg_identity", "verify_backup_policy"),
}
```

Build phase lists from the approved plan and reject missing, duplicate, or out-of-order operations before starting execution.

- [ ] **Step 4: Implement checkpointed execution and exact resume**

```python
def _execute_step(store, record, step, adapter):
    step_digest = canonical_step_digest(record.plan_digest, step)
    prior = store.load_passed_backup_checkpoint(record.execution_id, step.operation, step_digest)
    if prior is not None:
        return prior
    result = adapter.execute(step)
    evidence = ProvisioningStepEvidence.from_result(step, step_digest, result)
    store.save_backup_checkpoint(ProvisioningCheckpoint.passed(record.execution_id, evidence))
    return evidence
```

Persist the running phase before calling the adapter and persist each passed step immediately. On failure, preserve the first stable error and invoke only rollback operations owned by completed mutable phases.

- [ ] **Step 5: Delegate legacy `execute_plan` to the coordinator**

```python
def execute_plan(store_path, plan_id, adapter=None, executed_at=None, acceptance_runner=None):
    if adapter is None or acceptance_runner is None:
        raise ValueError("explicit provisioning adapter and acceptance runner are required")
    execution = start_execution(store_path, plan_id, adapter, acceptance_runner, now=executed_at)
    return _public_execution_plan(store_path, execution)
```

Keep legacy terminal records readable. Do not recompute or modify their historical plan or evidence digests.

- [ ] **Step 6: Run integration and compatibility tests**

Run: `pytest -q tests/test_backup_execution.py tests/test_backup_execution_integration.py tests/test_backup_provisioning.py tests/test_backup_provisioning_review_flow.py`

Expected: all selected tests pass; an approved plan remains non-terminal until acceptance passes.

- [ ] **Step 7: Commit the phased coordinator**

```bash
git add src/overseer/backup_execution.py src/overseer/backup_provisioning.py tests/test_backup_execution_integration.py tests/test_backup_provisioning.py
git commit -m "Execute backup provisioning through resumable phases"
```

---

### Task 3: Make Host Operations Convergent and Evidence-Bearing

**Files:**
- Modify: `src/overseer/backup_host_operations.py`
- Modify: `tests/test_backup_host_operations.py`

**Interfaces:**
- Consumes: exact approved `ProvisioningStep` objects.
- Produces: adapter results containing exactly `ok`, `operation`, `disposition`, `safe_code`, `evidence`, and `redactions_applied`.

- [ ] **Step 1: Write failing changed/no-op/conflict tests**

```python
def test_exact_active_unit_is_restarted_and_attested(host, runner) -> None:
    result = host.execute(step("start_enable_system_service"))
    assert result["disposition"] == "changed"
    assert runner.argv[-2:] == [
        ["/usr/bin/sudo", "--", "/usr/bin/systemctl", "restart", "theunderdark-donuthole.service"],
        ["/usr/bin/sudo", "--", "/usr/bin/systemctl", "show", "theunderdark-donuthole.service", "--property=ActiveEnterTimestampMonotonic", "--value"],
    ]


def test_exact_existing_root_registration_is_verified_noop(host, runner) -> None:
    runner.return_registration_code("ROOT_EXISTS")
    runner.return_exact_registration(True)
    result = host.execute(step("register_authorized_roots"))
    assert result["disposition"] == "verified_noop"


def test_conflicting_existing_root_fails_closed(host, runner) -> None:
    runner.return_registration_code("ROOT_EXISTS")
    runner.return_exact_registration(False)
    with pytest.raises(RedactedHostOperationError) as failure:
        host.execute(step("register_authorized_roots"))
    assert failure.value.code == "ROOT_CONFLICT"
```

- [ ] **Step 2: Run the focused tests and observe missing structured dispositions**

Run: `pytest -q tests/test_backup_host_operations.py -k 'noop or conflict or restart'`

Expected: the new assertions fail against Boolean handler results.

- [ ] **Step 3: Normalize allowlisted handler results**

```python
def execute(self, step: ProvisioningStep) -> Mapping[str, object]:
    if step not in self._allowed:
        raise ValueError("host provisioning step is not an exact approved plan step")
    result = self._handlers[step.operation](dict(step.arguments))
    if not isinstance(result, HostOperationResult):
        raise ValueError("host provisioning result is invalid")
    return {
        "ok": True,
        "operation": step.operation,
        "disposition": result.disposition.value,
        "safe_code": result.safe_code,
        "evidence": dict(result.evidence),
        "redactions_applied": True,
    }
```

Define `HostOperationResult.changed`, `verified_noop`, and `failed` factories. Evidence may contain digests and systemd monotonic process identity, never raw stdout or stderr.

- [ ] **Step 4: Add exact-state probes before convergent operations**

Implement allowlisted probes for the system user, directory mode/owner, installed artifact digest, config digest, unit digest, root registration, and systemd enable/active state. A mismatch returns a stable conflict code; it is never silently overwritten unless the approved operation explicitly permits replacement.

```python
if existing_digest == approved_digest:
    return HostOperationResult.verified_noop("RUNTIME_ALREADY_CURRENT", {"runtime_digest": existing_digest})
if existing_digest is not None:
    raise RedactedHostOperationError("RUNTIME_CONFLICT")
```

- [ ] **Step 5: Run the complete host-adapter suite**

Run: `pytest -q tests/test_backup_host_operations.py`

Expected: all tests pass, with exact restart and conflict behavior covered.

- [ ] **Step 6: Commit convergent operations**

```bash
git add src/overseer/backup_host_operations.py tests/test_backup_host_operations.py
git commit -m "Make backup host operations convergent"
```

---

### Task 4: Add TheUnderdark Active Runtime Attestation

**Files:**
- Create: `../TheUnderdark/src/theunderdark/runtime_identity.py`
- Create: `../TheUnderdark/tests/test_runtime_identity.py`
- Modify: `../TheUnderdark/src/theunderdark/production_cli.py`
- Modify: `../TheUnderdark/src/theunderdark/production_app.py`
- Modify: `../TheUnderdark/tests/test_production_cli.py`
- Modify: `../TheUnderdark/tests/test_production_app.py`
- Modify: `../TheUnderdark/tests/test_production_readiness.py`

**Interfaces:**
- Consumes: Capability A named provisioning contract and runtime-digest exclusions.
- Produces: `RuntimeIdentity`, `compute_runtime_digest(path, commit)`, `compute_config_digest(path)`, and an attested health result containing `runtime_digest`, `config_digest`, and `process_start_id`.

- [ ] **Step 1: Write failing identity and health tests in TheUnderdark**

```python
def test_runtime_identity_rejects_wrong_expected_digest(tmp_path) -> None:
    expected = "sha256:" + "a" * 64
    with pytest.raises(RuntimeIdentityError, match="RUNTIME_IDENTITY_MISMATCH"):
        RuntimeIdentity.capture(tmp_path, "b" * 40, expected, config_path(tmp_path), expected_config_digest(tmp_path))


def test_health_exposes_only_safe_attestation(injected_service, runtime_identity) -> None:
    app = create_production_http_app(injected_service, runtime_identity=runtime_identity)
    health = request_health(app)
    assert health["runtime"] == {
        "runtime_digest": runtime_identity.runtime_digest,
        "config_digest": runtime_identity.config_digest,
        "process_start_id": runtime_identity.process_start_id,
    }
    assert "path" not in repr(health)
```

- [ ] **Step 2: Run the TheUnderdark focused tests and verify missing identity support**

Run: `.venv/bin/pytest -q tests/test_runtime_identity.py tests/test_production_cli.py tests/test_production_app.py`

Working directory: `/home/god/Documents/Codex Workspace/TheUnderdark`

Expected: collection or assertions fail because runtime attestation is unavailable.

- [ ] **Step 3: Implement deterministic identity capture**

```python
@dataclass(frozen=True)
class RuntimeIdentity:
    runtime_digest: str
    config_digest: str
    process_start_id: str

    @classmethod
    def capture(cls, runtime_path, commit, expected_runtime, config_path, expected_config):
        runtime = compute_runtime_digest(runtime_path, commit)
        config = compute_config_digest(config_path)
        if runtime != expected_runtime:
            raise RuntimeIdentityError("RUNTIME_IDENTITY_MISMATCH")
        if config != expected_config:
            raise RuntimeIdentityError("CONFIG_IDENTITY_MISMATCH")
        start = "sha256:" + hashlib.sha256(f"{os.getpid()}:{time.monotonic_ns()}".encode()).hexdigest()
        return cls(runtime, config, start)
```

Use the Capability A exclusions and canonical digest algorithm. Do not include absolute paths or raw process values in the returned identity.

- [ ] **Step 4: Require expected identities on `serve` and inject attestation**

```python
serve.add_argument("--expected-runtime-digest", required=True)
serve.add_argument("--expected-config-digest", required=True)
serve.add_argument("--source-commit", required=True)

identity = RuntimeIdentity.capture(
    Path(__file__).resolve().parents[2], args.source_commit,
    args.expected_runtime_digest, args.config, args.expected_config_digest,
)
app = create_production_http_app(runtime.service, runtime_identity=identity)
```

Update the approved systemd unit arguments in Overseer during Task 5; do not add environment-variable or configuration-file fallback.

- [ ] **Step 5: Run focused and full TheUnderdark tests**

Run: `.venv/bin/pytest -q tests/test_runtime_identity.py tests/test_production_cli.py tests/test_production_app.py tests/test_production_readiness.py`

Expected: all selected tests pass and health exposes only safe digest identities.

Run: `.venv/bin/pytest -q`

Expected: the full TheUnderdark suite passes.

- [ ] **Step 6: Commit the TheUnderdark attestation change**

```bash
git add src/theunderdark/runtime_identity.py src/theunderdark/production_cli.py src/theunderdark/production_app.py tests/test_runtime_identity.py tests/test_production_cli.py tests/test_production_app.py tests/test_production_readiness.py
git commit -m "Attest active TheUnderdark runtime identity"
```

Record this reviewed TheUnderdark commit for the successor immutable bundle. Do not reuse an approval bound to the previous source commit.

---

### Task 5: Verify Attestation and Run Behavior Acceptance in Overseer

**Files:**
- Create: `src/overseer/backup_acceptance.py`
- Create: `tests/test_backup_acceptance.py`
- Modify: `src/overseer/backup_host_operations.py`
- Modify: `src/overseer/backup_provisioning.py`
- Modify: `tests/test_backup_host_operations.py`
- Modify: `tests/test_backup_execution_integration.py`

**Interfaces:**
- Consumes: Capability A contract fixture/version, TheUnderdark attested health, approved project/root/policy, and read-only MCP loader.
- Produces: `TheUnderdarkAcceptanceClient`, `run_donuthole_acceptance(client, expected) -> BehaviorAcceptance`, `verify_runtime_attestation`, and `run_behavior_acceptance` allowlisted operations.

- [ ] **Step 1: Write failing attestation and behavior tests**

```python
def test_stale_runtime_blocks_acceptance(fake_client, expected) -> None:
    fake_client.health["runtime"]["runtime_digest"] = "sha256:" + "0" * 64
    report = run_donuthole_acceptance(fake_client, expected)
    assert report.passed is False
    assert report.safe_code == "ACTIVE_RUNTIME_MISMATCH"
    assert fake_client.project_calls == 0


def test_acceptance_exercises_root_and_nested_paths(fake_client, expected) -> None:
    report = run_donuthole_acceptance(fake_client, expected)
    assert report.passed is True
    assert fake_client.directory_calls == ["", expected.nested_relative_path]
    assert report.results_digest.startswith("sha256:")
```

- [ ] **Step 2: Run the focused tests and observe the missing production runner**

Run: `pytest -q tests/test_backup_acceptance.py`

Expected: collection fails because `overseer.backup_acceptance` does not exist.

- [ ] **Step 3: Implement ordered read-only acceptance with stable results**

```python
def run_donuthole_acceptance(client, expected) -> BehaviorAcceptance:
    health = client.health_get()
    _require_identity(health, expected)
    project = client.project_get(expected.project_id)
    root = client.root_get(expected.project_id, expected.root_id)
    root_page = client.directory_list(expected.project_id, expected.root_id, "", expected.policy_revision)
    nested_page = client.directory_list(
        expected.project_id, expected.root_id, expected.nested_relative_path, expected.policy_revision
    )
    payload = canonical_safe_results(health, project, root, root_page, nested_page)
    return BehaviorAcceptance(expected.contract_version, True, digest(payload))
```

Reject the first mismatch with a stable code. Include only safe status, digest, and schema fields in the result payload.

- [ ] **Step 4: Add attestation and acceptance to the immutable plan**

Add `verify_runtime_attestation` after explicit activation and `run_behavior_acceptance` before backup-policy completion. Update unit `exec_start` to pass the approved source commit, runtime digest, and configuration digest to TheUnderdark.

```python
ProvisioningStep("verify_runtime_attestation", {
    "url": f"http://{LISTEN_HOST}:{LISTEN_PORT}/health",
    "runtime_digest": runtime_digest,
    "config_digest": config_digest,
})
```

Changing the step sequence creates a new plan digest and requires a successor plan. Never rewrite historical plans.

- [ ] **Step 5: Run the complete execution and contract suites**

Run: `pytest -q tests/test_backup_acceptance.py tests/test_backup_execution.py tests/test_backup_execution_integration.py tests/test_backup_host_operations.py tests/test_backup_provisioning.py tests/test_backup_cross_repo_contract.py tests/test_donuthole_backup_acceptance.py`

Expected: all selected tests pass; stale-runtime and empty-root regressions fail closed before terminal success.

- [ ] **Step 6: Commit Overseer acceptance gating**

```bash
git add src/overseer/backup_acceptance.py src/overseer/backup_host_operations.py src/overseer/backup_provisioning.py tests/test_backup_acceptance.py tests/test_backup_execution_integration.py tests/test_backup_host_operations.py
git commit -m "Gate backup completion on runtime acceptance"
```

---

### Task 6: Expose Exact Execution Control and Document Recovery

**Files:**
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/backup_provisioning_cli.py`
- Modify: `tests/test_backup_execution_integration.py`
- Modify: `tests/test_core.py`
- Modify: `docs/operator-workflows.md`

**Interfaces:**
- Produces: GET `/backup-provisioning/executions?plan_id=...`, POST `/backup-provisioning/executions/start`, POST `/backup-provisioning/executions/continue`, and matching CLI commands.
- Consumes: exact plan ID, execution ID, privileged confirmation, and the approved bundle/preflight state.

- [ ] **Step 1: Write failing API and CLI contract tests**

```python
def test_start_execution_requires_exact_confirmation(api) -> None:
    response = api.post("/backup-provisioning/executions/start", json={"plan_id": "plan-1"})
    assert response.status_code == 400
    assert response.json()["error"] == "exact privileged execution confirmation is required"


def test_continue_is_idempotent_for_terminal_execution(api, completed_execution) -> None:
    first = api.post("/backup-provisioning/executions/continue", json={
        "execution_id": completed_execution.id,
        "privileged_confirmation": "continue-exact-donuthole-provisioning-execution",
    }).json()
    second = api.post("/backup-provisioning/executions/continue", json={
        "execution_id": completed_execution.id,
        "privileged_confirmation": "continue-exact-donuthole-provisioning-execution",
    }).json()
    assert second == first
```

- [ ] **Step 2: Run API tests and observe missing routes**

Run: `pytest -q tests/test_core.py tests/test_backup_execution_integration.py -k 'execution'`

Expected: route tests fail with not-found or missing-handler assertions.

- [ ] **Step 3: Add exact routes and CLI commands**

```python
if path == "/backup-provisioning/executions/start":
    self._handle_admin_json(lambda payload: start_execution_api(store_path, payload, adapter_factory, acceptance_factory))
elif path == "/backup-provisioning/executions/continue":
    self._handle_admin_json(lambda payload: continue_execution_api(store_path, payload, adapter_factory, acceptance_factory))
```

Do not add a generic operation endpoint. GET responses expose safe summaries only.

- [ ] **Step 4: Document checkpoint, rollback, and successor handling**

Add exact operator procedures for inspecting an execution, identifying its first stable failure, deciding whether an exact continue is allowed, and requiring a successor when any immutable digest changes. State explicitly that implementation tests do not authorize deployment or restart.

- [ ] **Step 5: Run focused and full Overseer verification**

Run: `pytest -q tests/test_backup_execution.py tests/test_backup_execution_integration.py tests/test_backup_acceptance.py tests/test_backup_provisioning.py tests/test_backup_provisioning_review_flow.py tests/test_backup_host_operations.py tests/test_core.py`

Expected: all selected tests pass.

Run: `pytest -q`

Expected: the complete Overseer suite passes.

Run: `git diff --check`

Expected: no whitespace errors.

- [ ] **Step 6: Commit API, CLI, and recovery documentation**

```bash
git add src/overseer/api.py src/overseer/backup_provisioning_cli.py tests/test_backup_execution_integration.py tests/test_core.py docs/operator-workflows.md
git commit -m "Expose resumable backup execution controls"
```

---

## Capability Completion Gate

Before declaring Capability C complete:

- verify all touched tests in both repositories from fresh processes;
- verify different active runtime or process identities produce different execution evidence;
- verify handler completion without acceptance cannot produce plan status `executed`;
- verify exact resume does not replay passed digest-bound operations;
- verify changed immutable input requires a successor plan;
- request code review for each repository's focused commits;
- do not restart or deploy either live service without its separately staged and human-approved admin plan.

After separately approved deployment, run the Capability A read-only live acceptance sequence and record its redacted result as deployment evidence.
