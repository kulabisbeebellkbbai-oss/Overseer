# DonutHole Contract and Acceptance Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish a versioned, executable cross-repository contract that proves DonutHole provisioning behavior before human approval, using real TheUnderdark storage collaborators and the real Overseer adapter in disposable test environments.

**Architecture:** Store one canonical JSON contract fixture, mirrored byte-for-byte in Overseer and TheUnderdark, and give each repository a small production-owned parser for its half of the contract. Run composed acceptance scenarios in a subprocess using TheUnderdark's virtual environment and both repositories' source trees. The harness uses the real registry, filesystem read backend, snapshot paginator, authorization verifier, production service, MCP application, and Overseer adapter; only approval transport and host lifecycle state are deterministic test fixtures. Clean-install and already-active upgrade scenarios use disposable directories and never contact systemd, protected paths, live ports, or a human-approval service.

**Tech Stack:** Python 3.11+, frozen dataclasses, canonical JSON and SHA-256, pytest, subprocess, temporary directories, TheUnderdark MCP production composition, Overseer bounded storage adapter.

## Global Constraints

- This is Capability A only; it must not implement typed bundle construction, phased privileged execution, active-process attestation, or lifecycle UI from Capabilities B through D.
- `PROVISIONING_CONTRACT_VERSION` is distinct from the existing MCP envelope `CONTRACT_VERSION`; neither value substitutes for the other.
- The mirrored fixture must be canonical JSON and byte-for-byte identical in both repositories.
- Production code in either repository must not import the sibling repository.
- Cross-repository composition is allowed only in test support launched with explicit `PYTHONPATH` entries.
- Tests must compose the real TheUnderdark registry, read backend, paginator, authorization verifier, journal, admission controller, production service, and MCP application.
- The real `MCPBoundedStorageAdapterClient` request and response contract must be exercised; a test-only sync-to-async bridge may adapt its injected `call_tool` boundary.
- The clean-install scenario begins with no mutable service state. The upgrade scenario begins with durable registered state and an active-runtime fixture representing the previous artifact.
- Runtime-identity acceptance in this capability compares deterministic planned and installed artifact identities. Live PID, process-start, and restarted-process attestation remain Capability C.
- Empty relative paths are valid root-list requests and must not be normalized into rejection or a different directory.
- Pagination assertions include ordered entries, cursor behavior, page size, total count, and snapshot identity.
- Backup and restore operate only on disposable roots. If the real encryption dependency is unavailable, the test must skip with the exact missing dependency named; it must never silently replace encryption with a fake executor.
- Root-owned authorization configuration remains immutable. Tests may create a disposable equivalent before service composition but service code must not rewrite it.
- No test may access `/opt`, `/etc`, `/var/lib`, the protected gateway, port 8799, live credentials, live approval records, or real systemd units.
- Existing unrelated worktree changes must be preserved.

---

## File and Responsibility Map

**Create in Overseer**

- `src/overseer/backup_contract.py` — versioned fixture parser, canonical serialization, schema normalization, and deterministic identity helpers.
- `tests/fixtures/contracts/donuthole_backup_provisioning_v1.json` — Overseer's mirror of the authoritative contract fixture.
- `tests/support/donuthole_backup_acceptance.py` — subprocess entry point that composes both repositories through public production interfaces.
- `tests/test_donuthole_backup_acceptance.py` — clean-install and already-active upgrade acceptance tests.

**Modify in Overseer**

- `src/overseer/backup_host_operations.py` — derive expected normalized MCP schemas and capability identity from the parsed contract.
- `src/overseer/backup_provisioning.py` — bind the provisioning contract version and planned runtime identity into immutable plan validation.
- `tests/test_backup_cross_repo_contract.py` — assert mirrored bytes, parser agreement, schema agreement, request digests, and root-registration behavior.
- `tests/test_backup_host_operations.py` — verify contract-derived schemas and runtime identity mismatch behavior.
- `tests/test_backup_provisioning.py` — verify immutable plan input includes the provisioning contract version and planned runtime identity.

**Create in TheUnderdark**

- `src/theunderdark/backup_contract.py` — TheUnderdark parser and validation for the shared fixture.
- `tests/fixtures/contracts/donuthole_backup_provisioning_v1.json` — byte-identical mirror of Overseer's fixture.
- `tests/test_backup_contract.py` — fixture version, schema, request, and canonicalization tests.

**Modify in TheUnderdark**

- `tests/test_production_app.py` — assert production MCP registration matches the fixture schemas.
- `tests/test_backup_production_integration.py` — expose reusable real-component construction for disposable acceptance tests without weakening existing coverage.

---

### Task 1: Define and Parse the Versioned Provisioning Contract

**Files:**
- Create: `src/overseer/backup_contract.py`
- Create: `tests/fixtures/contracts/donuthole_backup_provisioning_v1.json`
- Modify: `tests/test_backup_cross_repo_contract.py`

**Interfaces:**
- Produces: `PROVISIONING_CONTRACT_VERSION`, `ProvisioningContract`, `load_provisioning_contract(path: Path)`, `canonical_contract_bytes(contract: Mapping[str, object])`, and `runtime_artifact_identity(commit: str, schemas: Mapping[str, object])`.
- Consumes: `EXPECTED_BACKUP_TOOL_SCHEMAS`, `BACKUP_ACTION_PARAMETERS`, canonical plan input fields, crew requirements, root registration, runtime identity, acceptance requests, and both scenario definitions.
- Fixture top-level keys are exactly: `version`, `canonical_plan_input`, `crew_requirements`, `root_registration`, `runtime_identity`, `mcp_tools`, `acceptance_requests`, and `scenarios`.

- [ ] **Step 1: Write failing parser and fixture-shape tests**

```python
from pathlib import Path

from overseer.backup_contract import (
    PROVISIONING_CONTRACT_VERSION,
    canonical_contract_bytes,
    load_provisioning_contract,
)


FIXTURE = Path(__file__).parent / "fixtures/contracts/donuthole_backup_provisioning_v1.json"


def test_provisioning_contract_fixture_is_canonical_and_complete() -> None:
    contract = load_provisioning_contract(FIXTURE)
    assert contract.version == PROVISIONING_CONTRACT_VERSION == "1"
    assert set(contract.raw) == {
        "version",
        "canonical_plan_input",
        "crew_requirements",
        "root_registration",
        "runtime_identity",
        "mcp_tools",
        "acceptance_requests",
        "scenarios",
    }
    assert FIXTURE.read_bytes() == canonical_contract_bytes(contract.raw)
    assert [scenario["name"] for scenario in contract.raw["scenarios"]] == [
        "clean_install",
        "active_service_upgrade",
    ]
```

- [ ] **Step 2: Run the focused test and verify the expected failure**

Run: `pytest -q tests/test_backup_cross_repo_contract.py`

Expected: collection fails with `ModuleNotFoundError: No module named 'overseer.backup_contract'`.

- [ ] **Step 3: Implement strict parsing and canonical serialization**

```python
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Mapping

PROVISIONING_CONTRACT_VERSION = "1"
_REQUIRED_KEYS = frozenset({
    "version", "canonical_plan_input", "crew_requirements",
    "root_registration", "runtime_identity", "mcp_tools",
    "acceptance_requests", "scenarios",
})


@dataclass(frozen=True)
class ProvisioningContract:
    version: str
    raw: Mapping[str, object]


def canonical_contract_bytes(contract: Mapping[str, object]) -> bytes:
    return (json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n").encode()


def load_provisioning_contract(path: Path) -> ProvisioningContract:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != _REQUIRED_KEYS:
        raise ValueError("invalid provisioning contract fields")
    if raw["version"] != PROVISIONING_CONTRACT_VERSION:
        raise ValueError("unsupported provisioning contract version")
    if path.read_bytes() != canonical_contract_bytes(raw):
        raise ValueError("provisioning contract is not canonical JSON")
    return ProvisioningContract(version=raw["version"], raw=raw)


def runtime_artifact_identity(commit: str, schemas: Mapping[str, object]) -> str:
    payload = {"commit": commit, "schemas": schemas, "version": PROVISIONING_CONTRACT_VERSION}
    return "sha256:" + hashlib.sha256(canonical_contract_bytes(payload)).hexdigest()
```

- [ ] **Step 4: Add the complete canonical fixture**

Populate every required field with concrete values already used by `DonutHoleBackupProvisioningPlan`, the required O'Brien/Odo review records, the immutable root-registration digest input, both exact MCP tool schemas, the eight minimum acceptance requests, and the `clean_install` and `active_service_upgrade` initial states. Do not add environment-specific paths, tokens, passwords, PIDs, or timestamps.

- [ ] **Step 5: Run focused tests and verify success**

Run: `pytest -q tests/test_backup_cross_repo_contract.py`

Expected: all tests pass.

- [ ] **Step 6: Commit the contract foundation**

```bash
git add src/overseer/backup_contract.py tests/fixtures/contracts/donuthole_backup_provisioning_v1.json tests/test_backup_cross_repo_contract.py
git commit -m "test: define DonutHole provisioning contract"
```

---

### Task 2: Mirror and Validate the Contract in TheUnderdark

**Files:**
- Create: `../TheUnderdark/src/theunderdark/backup_contract.py`
- Create: `../TheUnderdark/tests/fixtures/contracts/donuthole_backup_provisioning_v1.json`
- Create: `../TheUnderdark/tests/test_backup_contract.py`
- Modify: `tests/test_backup_cross_repo_contract.py`

**Interfaces:**
- Produces in TheUnderdark: the same five public names from Task 1 with behaviorally identical validation.
- Consumes: TheUnderdark `COMMON_FIELDS`, `ACTION_FIELDS`, `CONTRACT_VERSION`, and production MCP tool names.
- Cross-repository invariant: `sha256(overseer_fixture_bytes) == sha256(theunderdark_fixture_bytes)` and each parser produces the same canonical bytes.

- [ ] **Step 1: Write failing mirror and schema-agreement tests**

```python
import hashlib
import json
from pathlib import Path

from theunderdark.backup_contract import load_provisioning_contract
from theunderdark.production import ACTION_FIELDS, COMMON_FIELDS


FIXTURE = Path(__file__).parent / "fixtures/contracts/donuthole_backup_provisioning_v1.json"


def test_fixture_schema_matches_production_action_fields() -> None:
    contract = load_provisioning_contract(FIXTURE)
    tools = contract.raw["mcp_tools"]
    assert set(tools["underdark_backup_create"]["properties"]) == set(COMMON_FIELDS) | set(ACTION_FIELDS["backup"])
    assert set(tools["underdark_backup_verify_restore"]["properties"]) == set(COMMON_FIELDS) | set(ACTION_FIELDS["verify_restore"])


def test_repository_fixture_bytes_match(overseer_fixture: Path) -> None:
    assert hashlib.sha256(FIXTURE.read_bytes()).digest() == hashlib.sha256(overseer_fixture.read_bytes()).digest()
    assert json.loads(FIXTURE.read_text()) == json.loads(overseer_fixture.read_text())
```

- [ ] **Step 2: Run TheUnderdark tests and verify the expected failure**

Run from TheUnderdark: `.venv/bin/pytest -q tests/test_backup_contract.py`

Expected: collection fails with `ModuleNotFoundError: No module named 'theunderdark.backup_contract'`.

- [ ] **Step 3: Implement the TheUnderdark parser and copy the fixture bytes exactly**

Implement the same strict version and canonical-byte checks as Task 1. The module may import TheUnderdark production constants for validation, but it must not import Overseer. Copy the fixture without reformatting and make the test resolve the Overseer fixture from an explicit repository path supplied by the test command.

- [ ] **Step 4: Strengthen Overseer's cross-repository subprocess assertion**

```python
script = """
from pathlib import Path
from theunderdark.backup_contract import canonical_contract_bytes, load_provisioning_contract
fixture = Path(__import__('sys').argv[1])
contract = load_provisioning_contract(fixture)
assert fixture.read_bytes() == canonical_contract_bytes(contract.raw)
print(contract.version)
"""
```

Invoke this script with TheUnderdark's `.venv/bin/python`, an explicit `PYTHONPATH` containing only TheUnderdark `src`, and the mirrored fixture path. Assert stdout is exactly `1`.

- [ ] **Step 5: Run both contract suites and verify success**

Run from TheUnderdark: `.venv/bin/pytest -q tests/test_backup_contract.py tests/test_production_app.py`

Expected: all tests pass.

Run from Overseer: `pytest -q tests/test_backup_cross_repo_contract.py`

Expected: all tests pass and the fixture digest assertion succeeds.

- [ ] **Step 6: Commit TheUnderdark's coherent mirror, then Overseer's cross-repository assertion**

```bash
git -C ../TheUnderdark add src/theunderdark/backup_contract.py tests/fixtures/contracts/donuthole_backup_provisioning_v1.json tests/test_backup_contract.py tests/test_production_app.py
git -C ../TheUnderdark commit -m "test: publish DonutHole provisioning contract"
git add tests/test_backup_cross_repo_contract.py
git commit -m "test: verify TheUnderdark contract mirror"
```

---

### Task 3: Bind Provisioning and Capability Identity to the Contract

**Files:**
- Modify: `src/overseer/backup_host_operations.py`
- Modify: `src/overseer/backup_provisioning.py`
- Modify: `tests/test_backup_host_operations.py`
- Modify: `tests/test_backup_provisioning.py`

**Interfaces:**
- `capability_digest(commit: str, schemas: Mapping[str, object], provisioning_contract_version: str = PROVISIONING_CONTRACT_VERSION) -> str`
- `DonutHoleBackupProvisioningPlan.provisioning_contract_version: str`
- `DonutHoleBackupProvisioningPlan.runtime_artifact_identity: str`
- Existing stored plans remain immutable; changing identity inputs creates a successor plan and never rewrites an existing plan.

- [ ] **Step 1: Write failing identity-binding tests**

```python
from dataclasses import replace

import pytest

from overseer.backup_contract import PROVISIONING_CONTRACT_VERSION
from overseer.backup_host_operations import EXPECTED_BACKUP_TOOL_SCHEMAS, capability_digest


def test_capability_digest_is_bound_to_provisioning_contract_version() -> None:
    current = capability_digest("abc123", EXPECTED_BACKUP_TOOL_SCHEMAS, PROVISIONING_CONTRACT_VERSION)
    successor = capability_digest("abc123", EXPECTED_BACKUP_TOOL_SCHEMAS, "2")
    assert current != successor


def test_plan_rejects_changed_runtime_identity(valid_plan) -> None:
    changed = replace(valid_plan, runtime_artifact_identity="0" * 64)
    with pytest.raises(ValueError, match="runtime artifact identity"):
        changed.validate()
```

- [ ] **Step 2: Run focused tests and verify failure**

Run: `pytest -q tests/test_backup_host_operations.py tests/test_backup_provisioning.py`

Expected: tests fail because `capability_digest` does not accept a provisioning contract version and the plan has no runtime identity fields.

- [ ] **Step 3: Implement version-bound capability and plan validation**

```python
def capability_digest(
    commit: str,
    schemas: Mapping[str, object],
    provisioning_contract_version: str = PROVISIONING_CONTRACT_VERSION,
) -> str:
    payload = {
        "version": 2,
        "commit": commit,
        "provisioning_contract_version": provisioning_contract_version,
        "tools": schemas,
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
```

Add both new fields to plan construction, canonical payload reconstruction, serialization, and `_validate_plan`. Compute the runtime identity from the resolved commit, normalized fixture schemas, and provisioning contract version. Reject mismatches before any host operation.

- [ ] **Step 4: Run focused tests and verify success**

Run: `pytest -q tests/test_backup_host_operations.py tests/test_backup_provisioning.py tests/test_storage_adapter.py`

Expected: all tests pass, including legacy plan tests updated to provide explicit version-1 identity input.

- [ ] **Step 5: Commit the immutable identity binding**

```bash
git add src/overseer/backup_host_operations.py src/overseer/backup_provisioning.py tests/test_backup_host_operations.py tests/test_backup_provisioning.py
git commit -m "feat: bind DonutHole plans to contract identity"
```

---

### Task 4: Build the Real In-Process Acceptance Composition

**Files:**
- Create: `tests/support/donuthole_backup_acceptance.py`
- Create: `tests/test_donuthole_backup_acceptance.py`
- Modify: `../TheUnderdark/tests/test_backup_production_integration.py`

**Interfaces:**
- `run_acceptance_scenario(contract_path: Path, scenario_name: str, workspace: Path) -> dict[str, object]`
- `build_real_service(workspace: Path, authority_path: Path) -> ProductionStorageService`
- Test-only `SynchronousMCPBridge.call_tool(name: str, arguments: Mapping[str, object]) -> Mapping[str, object]`
- Result keys: `initialized`, `project`, `root`, `root_listing`, `nested_listing`, `pagination`, `runtime_identity`, `backup`, and `restore`.

- [ ] **Step 1: Write failing clean-install composition test**

```python
def test_clean_install_acceptance_uses_real_components(tmp_path, contract_fixture) -> None:
    result = run_harness("clean_install", tmp_path, contract_fixture)
    assert result["initialized"]["tools"] == [
        "underdark_backup_create",
        "underdark_backup_verify_restore",
    ]
    assert result["project"]["name"] == "DonutHole"
    assert result["root"]["relative_path"] == ""
    assert result["root_listing"]["relative_path"] == ""
    assert result["nested_listing"]["relative_path"] == "nested"
    assert result["pagination"]["total_count"] > result["pagination"]["page_size"]
    assert result["pagination"]["next_cursor"] is not None
```

- [ ] **Step 2: Run the focused acceptance test and verify failure**

Run: `pytest -q tests/test_donuthole_backup_acceptance.py -k clean_install`

Expected: collection fails because `tests/support/donuthole_backup_acceptance.py` does not exist.

- [ ] **Step 3: Implement production composition with disposable state**

Construct `SQLiteRootRegistry`, `FsContainReadBackend`, `SQLiteSnapshotPaginator`, the production authorization verifier, `SQLiteOperationJournal`, `SQLiteAdmissionController`, `EncryptedBackupExecutor`, `ProductionStorageService`, and `create_production_mcp`. Write the disposable authority file before construction, mark it read-only, and assert its digest is unchanged after the scenario.

```python
service = ProductionStorageService(
    registry=registry,
    read_backend=read_backend,
    paginator=paginator,
    authorization_verifier=authorization_verifier,
    journal=journal,
    admission_controller=admission_controller,
    executor_provider=executor_provider,
)
mcp = create_production_mcp(service)
client = MCPBoundedStorageAdapterClient(call_tool=SynchronousMCPBridge(mcp).call_tool)
```

The bridge runs each MCP invocation to completion on a dedicated event loop and returns the real MCP content decoded through the production response envelope. It must not reimplement storage behavior.

- [ ] **Step 4: Exercise initialization, discovery, empty-root, nested, and pagination requests**

Seed a root with deterministic files `alpha.txt`, `bravo.txt`, `charlie.txt`, and `nested/delta.txt`. Use a page size of two. Assert ordered first and second pages, stable snapshot identity, total count four, no duplicates, and terminal `next_cursor is None`.

- [ ] **Step 5: Run component and acceptance tests**

Run from TheUnderdark: `.venv/bin/pytest -q tests/test_read_backend.py tests/test_pagination.py tests/test_root_registry.py tests/test_backup_production_integration.py`

Expected: all tests pass.

Run from Overseer: `pytest -q tests/test_donuthole_backup_acceptance.py -k clean_install`

Expected: the clean-install acceptance test passes under the TheUnderdark subprocess.

- [ ] **Step 6: Commit repository-local composition changes separately**

```bash
git -C ../TheUnderdark add tests/test_backup_production_integration.py
git -C ../TheUnderdark commit -m "test: expose disposable backup composition"
git add tests/support/donuthole_backup_acceptance.py tests/test_donuthole_backup_acceptance.py
git commit -m "test: compose DonutHole clean-install acceptance"
```

---

### Task 5: Exercise Disposable Backup and Restore Through the Overseer Adapter

**Files:**
- Modify: `tests/support/donuthole_backup_acceptance.py`
- Modify: `tests/test_donuthole_backup_acceptance.py`
- Modify: `tests/test_backup_cross_repo_contract.py`

**Interfaces:**
- Consumes: fixture `acceptance_requests.backup_create` and `acceptance_requests.backup_verify_restore`.
- Produces: redacted operation results containing request digest, archive identity, restore verification, and no secret or absolute protected path.
- Uses: `MCPBoundedStorageAdapterClient` and real production MCP tool handlers.

- [ ] **Step 1: Write the failing backup/restore acceptance assertion**

```python
def test_clean_install_performs_disposable_backup_and_restore(tmp_path, contract_fixture) -> None:
    result = run_harness("clean_install", tmp_path, contract_fixture)
    assert result["backup"]["status"] == "completed"
    assert len(result["backup"]["request_digest"]) == 64
    assert result["restore"]["status"] == "verified"
    assert result["restore"]["request_digest"] != result["backup"]["request_digest"]
    assert "/etc/" not in repr(result)
    assert "/var/lib/" not in repr(result)
```

- [ ] **Step 2: Run the focused test and verify failure**

Run: `pytest -q tests/test_donuthole_backup_acceptance.py -k backup_and_restore`

Expected: the test fails because the harness result has no `backup` or `restore` record.

- [ ] **Step 3: Send fixture requests through the real adapter**

Build `StorageExecutionRequest` values from the fixture rather than duplicating request fields in test code. Submit create and verify-restore through `MCPBoundedStorageAdapterClient`, assert the response digest equals `canonical_adapter_request_digest(request)`, and verify the restored content digest matches the source tree digest.

- [ ] **Step 4: Add explicit dependency handling**

Before composing `EncryptedBackupExecutor`, probe the same encryption executable or library used by production. If absent, call `pytest.skip("encrypted backup acceptance requires <dependency-name>")`, substituting the concrete dependency name. Other errors remain failures.

- [ ] **Step 5: Run adapter and composed acceptance suites**

Run: `pytest -q tests/test_storage_adapter.py tests/test_backup_cross_repo_contract.py tests/test_donuthole_backup_acceptance.py`

Expected: all tests pass, or only the backup/restore acceptance test reports the explicit encryption-dependency skip.

- [ ] **Step 6: Commit behavior acceptance**

```bash
git add tests/support/donuthole_backup_acceptance.py tests/test_donuthole_backup_acceptance.py tests/test_backup_cross_repo_contract.py
git commit -m "test: accept DonutHole backup behavior end to end"
```

---

### Task 6: Cover Already-Active Upgrade and Planned Runtime Identity

**Files:**
- Modify: `tests/support/donuthole_backup_acceptance.py`
- Modify: `tests/test_donuthole_backup_acceptance.py`
- Modify: `tests/test_backup_host_operations.py`

**Interfaces:**
- Scenario `active_service_upgrade` contains `previous_runtime_identity`, `planned_runtime_identity`, pre-existing root registration, journal state, and expected convergence disposition.
- Produces: `runtime_identity = {"previous": str, "installed": str, "planned": str, "matches_plan": bool}` and `registration_disposition` equal to `verified_no_op` for exact durable state.
- Does not claim PID or process-start attestation and does not invoke a service manager.

- [ ] **Step 1: Write failing active-upgrade tests**

```python
def test_active_service_upgrade_converges_and_matches_planned_runtime(tmp_path, contract_fixture) -> None:
    result = run_harness("active_service_upgrade", tmp_path, contract_fixture)
    assert result["registration_disposition"] == "verified_no_op"
    assert result["runtime_identity"]["previous"] != result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["installed"] == result["runtime_identity"]["planned"]
    assert result["runtime_identity"]["matches_plan"] is True
    assert result["root_listing"]["relative_path"] == ""


def test_active_service_upgrade_rejects_stale_installed_runtime(tmp_path, contract_fixture) -> None:
    result = run_harness("active_service_upgrade", tmp_path, contract_fixture, retain_previous_runtime=True)
    assert result["runtime_identity"]["matches_plan"] is False
    assert result["terminal_status"] == "acceptance_failed"
```

- [ ] **Step 2: Run upgrade tests and verify failure**

Run: `pytest -q tests/test_donuthole_backup_acceptance.py -k active_service_upgrade`

Expected: tests fail because the harness supports only `clean_install`.

- [ ] **Step 3: Implement durable-state seeding and deterministic runtime installation**

Seed the exact root registration and journal state before composing the new service. Represent the active old runtime and installed candidate with immutable files whose SHA-256 identities are fixture values. The successful scenario installs the planned bytes before composition; the stale scenario deliberately retains the previous bytes. Never spawn or restart a system service.

- [ ] **Step 4: Enforce acceptance gating on identity mismatch**

Run discovery and read checks in both cases, but do not report terminal success unless `installed == planned`. Return stable `acceptance_failed` with redacted `runtime_identity_mismatch` evidence for the stale case.

- [ ] **Step 5: Run both scenarios and host-operation regressions**

Run: `pytest -q tests/test_donuthole_backup_acceptance.py tests/test_backup_host_operations.py`

Expected: clean installation, convergent upgrade, and stale-runtime rejection all pass.

- [ ] **Step 6: Commit upgrade coverage**

```bash
git add tests/support/donuthole_backup_acceptance.py tests/test_donuthole_backup_acceptance.py tests/test_backup_host_operations.py
git commit -m "test: cover active DonutHole runtime upgrades"
```

---

### Task 7: Verify the Capability Across Both Repositories

**Files:**
- Modify only if a regression exposes a Capability A defect in a file already listed above.

**Interfaces:**
- Produces: reviewed Overseer and TheUnderdark source SHAs plus the shared fixture SHA-256 for downstream Capability B plans.
- Consumes: no live service, approval, gateway, firewall, or protected-host state.

- [ ] **Step 1: Verify fixture bytes are identical**

Run:

```bash
cmp tests/fixtures/contracts/donuthole_backup_provisioning_v1.json ../TheUnderdark/tests/fixtures/contracts/donuthole_backup_provisioning_v1.json
sha256sum tests/fixtures/contracts/donuthole_backup_provisioning_v1.json ../TheUnderdark/tests/fixtures/contracts/donuthole_backup_provisioning_v1.json
```

Expected: `cmp` exits zero and both SHA-256 values are identical.

- [ ] **Step 2: Run the focused Overseer capability suite**

Run: `pytest -q tests/test_backup_cross_repo_contract.py tests/test_donuthole_backup_acceptance.py`

Expected: all tests pass, with only the explicitly named encryption dependency allowed to skip.

- [ ] **Step 3: Run the Overseer regression suite**

Run: `pytest -q tests/test_backup_host_operations.py tests/test_backup_provisioning.py tests/test_storage_adapter.py`

Expected: all tests pass.

- [ ] **Step 4: Run the TheUnderdark capability suite in its virtual environment**

Run from TheUnderdark: `.venv/bin/pytest -q tests/test_backup_contract.py tests/test_production_app.py tests/test_read_backend.py tests/test_pagination.py tests/test_backup_production_integration.py tests/test_root_registry.py tests/test_production_cli.py`

Expected: all tests pass, with only the explicitly named encryption dependency allowed to skip.

- [ ] **Step 5: Compile changed production modules**

Run:

```bash
python -m py_compile src/overseer/backup_contract.py src/overseer/backup_host_operations.py src/overseer/backup_provisioning.py
../TheUnderdark/.venv/bin/python -m py_compile ../TheUnderdark/src/theunderdark/backup_contract.py
```

Expected: both commands exit zero with no output.

- [ ] **Step 6: Inspect ownership and repository state before publishing**

Run:

```bash
git status --short
git diff --check
git -C ../TheUnderdark status --short
git -C ../TheUnderdark diff --check
```

Expected: no whitespace errors; only Capability A files remain changed. Preserve and report unrelated changes rather than staging them.

- [ ] **Step 7: Record reviewed identities**

Run:

```bash
git rev-parse HEAD
git -C ../TheUnderdark rev-parse HEAD
sha256sum tests/fixtures/contracts/donuthole_backup_provisioning_v1.json
```

Expected: three concrete identities are captured in the implementation handoff. A downstream plan must bind to these identities or explicitly supersede them.

---

## Dependency and Approval Boundaries

- Task 1 must complete before any other task because it defines the versioned vocabulary.
- Task 2 must complete before composed cross-repository acceptance begins; fixture drift is a hard failure.
- Task 3 may proceed alongside TheUnderdark-local test preparation after Task 1, but its final tests depend on Task 2's schema agreement.
- Tasks 4 and 5 require Tasks 1 through 3 and must use TheUnderdark's `.venv`; system Python is not an accepted substitute for MCP tests.
- Task 6 depends on the stable clean-install harness from Tasks 4 and 5.
- Task 7 is required before Capability A can be presented as complete.
- This plan authorizes repository code, tests, and disposable local test data only. It does not authorize protected gateway access, firewall or VPN changes, package installation, service restart, route activation, root-owned configuration changes, or DonutHole plan execution.
- Missing encryption dependencies are reported as an explicit test prerequisite. Installing them requires the normal shared-resource coordination and approval workflow.
- Human approval remains independent and is not consumed or simulated as valid production evidence. The deterministic approval fixture exists only to let the test reach storage behavior.
- Any change to canonical plan input, crew requirements, authorization digest, runtime identity, schema, or fixture version creates new immutable evidence and cannot reuse a prior approval.
- Capability B may start only after Task 7 records the reviewed source identities and fixture digest. Capabilities C and D must add their behavior to this harness before claiming completion.

## Completion Criteria

- Both repositories parse byte-identical canonical version-1 fixtures.
- Production MCP schemas and Overseer adapter parameters match the fixture exactly.
- Clean-install acceptance initializes MCP, inspects tools, retrieves project and root, lists empty-root and nested paths, verifies pagination, matches installed and planned runtime identities, and completes disposable backup/restore.
- Already-active upgrade acceptance proves exact root registration is a verified no-op, candidate identity matches the plan, and stale installed identity fails closed.
- Real production collaborators are composed; no storage, registry, pagination, authorization, production-service, or MCP handler fake is the sole evidence.
- No protected path, live service, live route, real credential, or real human approval is touched.
- Focused and regression suites pass in both repositories, and the implementation handoff records both reviewed source SHAs and the fixture SHA-256.
