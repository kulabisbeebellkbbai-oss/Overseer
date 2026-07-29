# Provider-Neutral Primary AI Driver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow one configured Codex, Claude, Antigravity, Mistral Vibe, or Qwen Code provider to drive an Overseer instance, with provider-neutral recovery, manual handoff, and policy-controlled failover.

**Architecture:** Preserve Overseer's deterministic policy and coordination core, place a provider-neutral manager and immutable driver epochs above isolated provider adapters, and migrate existing Codex discovery, dispatch, continuation, API, and UI behavior through compatibility aliases. Store normalized sessions, dispatches, checkpoints, and handoffs without credentials or unrestricted transcripts.

**Tech Stack:** Python 3.11+, frozen dataclasses and protocols, SQLite JSON payload records, `subprocess` argument arrays, Starlette local API, embedded JavaScript UI, pytest/unittest, fake provider executables for contract tests.

## Global Constraints

- Each Overseer instance has exactly one primary driver at a time.
- Other providers may act as delegated workers but cannot silently become primary.
- The deterministic Overseer core remains authoritative for authorization, approvals, claims, audit, secrets, scheduling, and state.
- Manual handoff or policy-controlled failover creates a new immutable driver epoch.
- Slow responses alone never trigger failover.
- Old-epoch output is quarantined and cannot mutate current state.
- Provider capabilities describe technical ability and never grant authorization.
- Provider commands use argument arrays, never interpolated shell commands.
- Credentials are secret references only and never enter configuration, records, handoff packages, logs, API output, or fixtures.
- Provider usage retains native units; no provider is converted into fictitious Codex percentage points.
- Existing Codex routes, flags, persisted records, resource identifiers, and registry behavior remain compatible for one documented migration cycle.
- The migration is additive and repeatable; it does not delete legacy data.
- No new provider SDK dependency is added in the initial CLI-adapter release.
- Existing unrelated worktree changes must be preserved.

---

## File and Responsibility Map

**Create**

- `src/overseer/agent_contracts.py` — normalized enums, dataclasses, protocols, and error categories.
- `src/overseer/agent_registry.py` — provider/profile configuration loading, validation, and adapter construction.
- `src/overseer/agent_manager.py` — active epoch lifecycle and provider-neutral operation routing.
- `src/overseer/agent_handoff.py` — redacted handoff creation and compatibility validation.
- `src/overseer/agent_adapters/__init__.py` — adapter exports and built-in factory map.
- `src/overseer/agent_adapters/base_cli.py` — shared safe subprocess/tmux primitives, not provider semantics.
- `src/overseer/agent_adapters/codex.py` — Codex implementation and legacy conversion.
- `src/overseer/agent_adapters/claude.py` — Claude CLI implementation.
- `src/overseer/agent_adapters/qwen_code.py` — Qwen Code CLI implementation.
- `src/overseer/agent_adapters/mistral_vibe.py` — Mistral Vibe CLI implementation.
- `src/overseer/agent_adapters/antigravity.py` — Antigravity implementation selected from verified local interface.
- `config/agent-providers.json` — committed provider definitions without machine paths or secrets.
- `tests/fake_agent_provider.py` — deterministic fake executable shared by adapter contract tests.
- `tests/test_agent_contracts.py` — type and state validation.
- `tests/test_agent_registry.py` — configuration validation and adapter resolution.
- `tests/test_agent_store.py` — persistence and repeatable migration.
- `tests/test_agent_manager.py` — epochs, routing, idempotency, recovery, quarantine.
- `tests/test_agent_handoff.py` — redaction, compatibility, freshness, risk gates.
- `tests/test_agent_adapter_contract.py` — parameterized adapter contract.
- `tests/test_agent_api.py` — generic API and Codex aliases.
- `tests/test_agent_migration.py` — legacy CSV/resource/payload compatibility.
- `docs/agent-provider-architecture.md` — operator-facing architecture and boundaries.
- `docs/provider-adapter-contract.md` — adapter implementer contract.
- `docs/agent-provider-migration.md` — compatibility window and rollback.

**Modify**

- `src/overseer/store.py` — additive agent tables and CRUD.
- `src/overseer/codex_projects.py` — legacy façade delegating to the Codex adapter.
- `src/overseer/usage_limits.py` — optional generic session/epoch/provider references.
- `src/overseer/quark_scheduler.py` — provider-neutral work and executor routing with Codex aliases.
- `src/overseer/quark_scheduler_cli.py` — profile/provider selection.
- `src/overseer/cli.py` — generic commands plus legacy aliases.
- `src/overseer/api.py` — provider-neutral endpoints plus legacy aliases.
- `src/overseer/client.py` — generic local API client methods.
- `src/overseer/ui.py` — primary driver, capabilities, lifecycle controls, and provider-native usage.
- `src/overseer/__init__.py` — public normalized types.
- `tests/test_core.py` — compatibility assertions and IDS/continuation routing.
- `tests/test_quark_scheduler.py` — mixed-provider scheduling and Codex aliases.
- `tests/test_ui_full_regression.py` — generic action payloads and compatibility routes.
- `tests/test_ui_regression.py` — provider dashboard rendering and controls.
- `tests/test_codex_usage.py` — Codex usage remains one provider-specific health view.
- `README.md` — provider-neutral overview.
- `docs/agents.md` — distinguish DS9 responsibility roles from AI drivers.
- `docs/adapters-and-dry-run.md` — agent adapter dry-run behavior.
- `docs/local-api.md` — generic routes and deprecated aliases.
- `docs/runtime.md` — driver lifecycle integration.
- `docs/usage-limit-scheduling.md` — provider-native scheduling.
- `config/local-mcp-services.json` — keep Codex Usage MCP explicitly provider-specific.

---

### Task 1: Define Provider-Neutral Contracts

**Files:**
- Create: `src/overseer/agent_contracts.py`
- Create: `tests/test_agent_contracts.py`
- Modify: `src/overseer/__init__.py`

**Interfaces:**
- Produces: `AgentProvider`, `AgentCapabilities`, `AgentInstanceProfile`, `AgentSession`, `DriverEpoch`, `AgentDispatchRequest`, `AgentDispatchResult`, `AgentCheckpoint`, `AgentHandoffPackage`, `AgentErrorCategory`, `AgentOperationState`, `AgentTransport`, and `PrimaryDriver`.
- Consumes: existing string timestamps and immutable dataclass conventions.

- [ ] **Step 1: Write failing validation and protocol-shape tests**

```python
from dataclasses import replace

import pytest

from overseer.agent_contracts import (
    AgentCapabilities,
    AgentDispatchRequest,
    AgentErrorCategory,
    AgentInstanceProfile,
    AgentOperationState,
    AgentSession,
    AgentTransport,
    DriverEpoch,
)


def test_instance_profile_requires_one_primary_provider() -> None:
    with pytest.raises(ValueError, match="primary provider"):
        AgentInstanceProfile(
            id="instance.overseer",
            primary_provider_id="",
            transport=AgentTransport.INTERACTIVE_CLI,
            workspace="/tmp/workspace",
        )


def test_dispatch_requires_epoch_and_idempotency_key() -> None:
    with pytest.raises(ValueError, match="idempotency"):
        AgentDispatchRequest(
            id="dispatch.1",
            instance_id="instance.overseer",
            session_id="session.1",
            driver_epoch_id="epoch.1",
            idempotency_key="",
            prompt="continue",
        )


def test_old_epoch_result_can_be_quarantined_without_losing_evidence() -> None:
    session = AgentSession(
        id="session.1",
        provider_id="codex",
        external_session_id="external.1",
        workspace="/tmp/workspace",
        transport=AgentTransport.INTERACTIVE_CLI,
        capabilities=AgentCapabilities(session_resume=True),
    )
    epoch = DriverEpoch(
        id="epoch.1",
        instance_id="instance.overseer",
        session_id=session.id,
        provider_id=session.provider_id,
        ordinal=1,
        state=AgentOperationState.RUNNING,
    )
    quarantined = replace(epoch, state=AgentOperationState.QUARANTINED)
    assert quarantined.state is AgentOperationState.QUARANTINED
    assert AgentErrorCategory.QUARANTINED.value == "quarantined"
```

- [ ] **Step 2: Run the tests and verify the missing module failure**

Run: `pytest -q tests/test_agent_contracts.py`

Expected: collection fails with `ModuleNotFoundError: No module named 'overseer.agent_contracts'`.

- [ ] **Step 3: Implement normalized enums, frozen records, and protocol**

```python
class AgentTransport(StrEnum):
    INTERACTIVE_CLI = "interactive_cli"
    NONINTERACTIVE_CLI = "noninteractive_cli"
    API = "api"
    GATEWAY = "gateway"


class AgentOperationState(StrEnum):
    QUEUED = "queued"
    ACKNOWLEDGED = "acknowledged"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


class AgentErrorCategory(StrEnum):
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    CONFIGURATION_ERROR = "configuration_error"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    SESSION_NOT_FOUND = "session_not_found"
    AUTHENTICATION_REQUIRED = "authentication_required"
    DISPATCH_REJECTED = "dispatch_rejected"
    DISPATCH_TIMEOUT = "dispatch_timeout"
    PROVIDER_PROTOCOL_ERROR = "provider_protocol_error"
    POLICY_BLOCKED = "policy_blocked"
    HANDOFF_INCOMPATIBLE = "handoff_incompatible"
    CHECKPOINT_STALE = "checkpoint_stale"
    CANCELLED = "cancelled"
    QUARANTINED = "quarantined"


@runtime_checkable
class PrimaryDriver(Protocol):
    provider: AgentProvider

    def discover(self, workspace: str | None = None) -> tuple[AgentSession, ...]: ...
    def resolve(self, reference: str) -> AgentSession | None: ...
    def start(self, profile: AgentInstanceProfile) -> AgentDispatchResult: ...
    def resume(self, session: AgentSession) -> AgentDispatchResult: ...
    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult: ...
    def inspect(self, session: AgentSession) -> AgentDispatchResult: ...
    def checkpoint(self, session: AgentSession) -> AgentCheckpoint: ...
    def cancel(self, session: AgentSession) -> AgentDispatchResult: ...
    def import_handoff(
        self, profile: AgentInstanceProfile, package: AgentHandoffPackage
    ) -> AgentDispatchResult: ...
```

Implement every dataclass named in the interface block as `frozen=True`, validate stable non-empty identifiers in `__post_init__`, use tuples and mappings for immutable collections, and export them from `overseer.__init__`.

- [ ] **Step 4: Run focused and existing import tests**

Run: `pytest -q tests/test_agent_contracts.py tests/test_core.py -x`

Expected: all selected tests pass.

- [ ] **Step 5: Commit the contracts**

```bash
git add src/overseer/agent_contracts.py src/overseer/__init__.py tests/test_agent_contracts.py
git commit -m "Add provider-neutral agent contracts"
```

---

### Task 2: Add Provider Registry and Safe CLI Foundation

**Files:**
- Create: `src/overseer/agent_registry.py`
- Create: `src/overseer/agent_adapters/__init__.py`
- Create: `src/overseer/agent_adapters/base_cli.py`
- Create: `config/agent-providers.json`
- Create: `tests/test_agent_registry.py`

**Interfaces:**
- Consumes: `AgentProvider`, `AgentCapabilities`, `AgentInstanceProfile`, `AgentTransport`, `PrimaryDriver`.
- Produces: `AgentRegistry.load(committed_path, local_path=None)`, `AgentRegistry.profile(instance_id)`, `AgentRegistry.driver(instance_id)`, `CliCommandRunner.run(argv, input_text=None, timeout_seconds=30)`.

- [ ] **Step 1: Write failing configuration-validation tests**

```python
def test_registry_rejects_shell_command_strings(tmp_path: Path) -> None:
    config = tmp_path / "providers.json"
    config.write_text(json.dumps({
        "providers": [{
            "id": "claude",
            "adapter": "claude",
            "transport": "interactive_cli",
            "executable": "claude --dangerously-skip-permissions",
            "capabilities": {"session_resume": True},
        }],
        "instances": [],
    }))
    with pytest.raises(ValueError, match="executable name"):
        AgentRegistry.load(config)


def test_registry_rejects_cyclic_fallbacks(tmp_path: Path) -> None:
    config = _write_registry(
        tmp_path,
        instances=[
            _instance("one", "codex", ["claude"]),
            _instance("two", "claude", ["codex"]),
        ],
    )
    with pytest.raises(ValueError, match="fallback cycle"):
        AgentRegistry.load(config)


def test_local_override_cannot_contain_secret_values(tmp_path: Path) -> None:
    committed = _write_registry(tmp_path)
    local = tmp_path / "local.json"
    local.write_text(json.dumps({"providers": {"claude": {"api_key": "secret"}}}))
    with pytest.raises(ValueError, match="secret reference"):
        AgentRegistry.load(committed, local)
```

- [ ] **Step 2: Verify the tests fail on missing registry**

Run: `pytest -q tests/test_agent_registry.py`

Expected: collection fails because `AgentRegistry` does not exist.

- [ ] **Step 3: Implement strict merge and validation**

Use this committed shape:

```json
{
  "schema_version": 1,
  "providers": [
    {
      "id": "codex",
      "adapter": "codex",
      "transport": "interactive_cli",
      "executable": "codex",
      "capabilities": {
        "session_discovery": true,
        "session_resume": true,
        "interactive_dispatch": true,
        "structured_events": false,
        "checkpoints": true,
        "cancellation": false,
        "handoff_import": true,
        "usage_observation": true
      }
    },
    {
      "id": "claude",
      "adapter": "claude",
      "transport": "interactive_cli",
      "executable": "claude",
      "capabilities": {}
    },
    {
      "id": "qwen-code",
      "adapter": "qwen_code",
      "transport": "interactive_cli",
      "executable": "qwen",
      "capabilities": {}
    },
    {
      "id": "mistral-vibe",
      "adapter": "mistral_vibe",
      "transport": "interactive_cli",
      "executable": "vibe",
      "capabilities": {}
    },
    {
      "id": "antigravity",
      "adapter": "antigravity",
      "transport": "gateway",
      "executable": null,
      "capabilities": {}
    }
  ],
  "instances": [
    {
      "id": "overseer.default",
      "primary_provider_id": "codex",
      "workspace": ".",
      "fallback_provider_ids": []
    }
  ]
}
```

`CliCommandRunner` accepts only `Sequence[str]`, invokes `subprocess.run` with `shell=False`, captured text output, explicit timeout, and a caller-supplied environment mapping. Validation rejects secret-looking keys except names ending in `_secret_ref`.

- [ ] **Step 4: Run registry tests and configuration parse**

Run: `pytest -q tests/test_agent_registry.py`

Run: `PYTHONPATH=src python3 -c 'from overseer.agent_registry import AgentRegistry; AgentRegistry.load("config/agent-providers.json")'`

Expected: both commands exit zero.

- [ ] **Step 5: Commit registry and safe command foundation**

```bash
git add config/agent-providers.json src/overseer/agent_registry.py src/overseer/agent_adapters tests/test_agent_registry.py
git commit -m "Add agent provider registry"
```

---

### Task 3: Persist Providers, Sessions, Epochs, Dispatches, Checkpoints, and Handoffs

**Files:**
- Modify: `src/overseer/store.py`
- Create: `tests/test_agent_store.py`

**Interfaces:**
- Consumes: all normalized records from `agent_contracts.py`.
- Produces: `save/load/list_agent_provider`, `save/load/list_agent_instance_profile`, `save/load/list_agent_session`, `save/load/list_driver_epoch`, `save/load/list_agent_dispatch`, `save/load/list_agent_checkpoint`, `save/load/list_agent_handoff`.

- [ ] **Step 1: Write failing round-trip and migration tests**

```python
def test_agent_records_round_trip(tmp_path: Path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_agent_session(_session("session.1", "claude"))
        store.save_driver_epoch(_epoch("epoch.1", "session.1", ordinal=1))
        store.save_agent_dispatch(_dispatch("dispatch.1", "epoch.1"))
        assert store.load_agent_session("session.1").provider_id == "claude"
        assert store.load_driver_epoch("epoch.1").ordinal == 1
        assert store.load_agent_dispatch("dispatch.1").idempotency_key == "key.1"


def test_schema_migration_is_repeatable(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    for _ in range(2):
        with OverseerStore(path) as store:
            assert "agent_driver_v1" in {
                row.version for row in store.list_schema_migrations()
            }
    with sqlite3.connect(path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = ?",
            ("agent_driver_v1",),
        ).fetchone()[0]
    assert count == 1
```

- [ ] **Step 2: Verify missing CRUD methods**

Run: `pytest -q tests/test_agent_store.py`

Expected: tests fail with missing agent store methods.

- [ ] **Step 3: Add additive JSON-payload tables and CRUD**

Add tables:

```sql
CREATE TABLE IF NOT EXISTS agent_providers (
    id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_instance_profiles (
    id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_sessions (
    id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_driver_epochs (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    state TEXT NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE(instance_id, ordinal)
);
CREATE TABLE IF NOT EXISTS agent_dispatches (
    id TEXT PRIMARY KEY,
    driver_epoch_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_checkpoints (
    id TEXT PRIMARY KEY,
    driver_epoch_id TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_handoffs (
    id TEXT PRIMARY KEY,
    outgoing_epoch_id TEXT NOT NULL,
    incoming_provider_id TEXT NOT NULL,
    payload TEXT NOT NULL
);
```

Use the store's `_dump`, `_load_dataclass`, `_upsert`, `_get_payload`, and `_list_payloads` conventions. Record `SchemaMigration(version="agent_driver_v1", ...)` only after the transaction succeeds.

- [ ] **Step 4: Run store and core persistence tests**

Run: `pytest -q tests/test_agent_store.py tests/test_core.py -x`

Expected: all selected tests pass and repeatable initialization creates no duplicates.

- [ ] **Step 5: Commit persistence**

```bash
git add src/overseer/store.py tests/test_agent_store.py
git commit -m "Persist agent driver lifecycle"
```

---

### Task 4: Implement Handoff Validation and Driver-Epoch Manager

**Files:**
- Create: `src/overseer/agent_handoff.py`
- Create: `src/overseer/agent_manager.py`
- Create: `tests/test_agent_handoff.py`
- Create: `tests/test_agent_manager.py`

**Interfaces:**
- Consumes: `AgentRegistry`, `OverseerStore`, normalized contracts, existing policy decision callbacks.
- Produces: `AgentHandoffService.build`, `AgentHandoffService.validate`, `AgentManager.activate`, `recover`, `dispatch`, `checkpoint`, `manual_handoff`, `quarantine_result`.

- [ ] **Step 1: Write failing epoch and handoff tests**

```python
def test_dispatch_is_bound_to_active_epoch(manager: AgentManager) -> None:
    epoch = manager.activate("overseer.default", initiated_by="operator")
    result = manager.dispatch(
        instance_id="overseer.default",
        prompt="inspect health",
        idempotency_key="dispatch.health.1",
    )
    assert result.driver_epoch_id == epoch.id


def test_repeated_idempotency_key_returns_recorded_result(
    manager: AgentManager,
) -> None:
    first = manager.dispatch("overseer.default", "continue", "same-key")
    second = manager.dispatch("overseer.default", "different text", "same-key")
    assert second == first


def test_late_result_from_closed_epoch_is_quarantined(
    manager: AgentManager,
) -> None:
    old = manager.activate("overseer.default", initiated_by="operator")
    manager.manual_handoff(
        "overseer.default",
        incoming_provider_id="claude",
        initiated_by="operator",
        approval_id="approval.1",
    )
    result = manager.record_provider_result(old.id, _provider_success(old.id))
    assert result.state is AgentOperationState.QUARANTINED


def test_handoff_rejects_raw_secret_material() -> None:
    with pytest.raises(ValueError, match="sensitive material"):
        AgentHandoffService().build(
            objective="continue",
            evidence={"authorization": "Bearer abc123"},
            required_capabilities=AgentCapabilities(handoff_import=True),
        )
```

- [ ] **Step 2: Run tests and verify missing services**

Run: `pytest -q tests/test_agent_handoff.py tests/test_agent_manager.py`

Expected: collection fails because the manager and handoff service do not exist.

- [ ] **Step 3: Implement manager transaction order**

Implement this mutation sequence:

```python
def manual_handoff(
    self,
    instance_id: str,
    incoming_provider_id: str,
    initiated_by: str,
    approval_id: str,
) -> DriverEpoch:
    outgoing = self.active_epoch(instance_id)
    self._require_approved_handoff(approval_id, instance_id, incoming_provider_id)
    checkpoint = self.checkpoint(instance_id)
    package = self.handoffs.build_from_store(
        instance_id=instance_id,
        outgoing_epoch=outgoing,
        checkpoint=checkpoint,
    )
    incoming_driver = self.registry.driver_for_provider(incoming_provider_id)
    self.handoffs.validate(package, incoming_driver.provider.capabilities)
    incoming = self._open_epoch(
        instance_id=instance_id,
        provider_id=incoming_provider_id,
        reason="manual_handoff",
        initiated_by=initiated_by,
    )
    result = incoming_driver.import_handoff(
        self.registry.profile_for_provider(instance_id, incoming_provider_id),
        package,
    )
    if result.state not in {
        AgentOperationState.ACKNOWLEDGED,
        AgentOperationState.RUNNING,
        AgentOperationState.SUCCEEDED,
    }:
        self._pause_incoming_epoch(incoming, result)
        raise AgentHandoffError(result.error_category)
    self._close_epoch(outgoing, replacement_epoch_id=incoming.id)
    return incoming
```

Do not close the outgoing epoch until the incoming adapter acknowledges the imported handoff. If import fails, leave the instance paused with both the failure and outgoing checkpoint recorded. Redaction recursively rejects keys and string values matching token, cookie, authorization, password, private key, bearer, or known secret-reference resolution output.

- [ ] **Step 4: Run lifecycle tests**

Run: `pytest -q tests/test_agent_handoff.py tests/test_agent_manager.py tests/test_agent_store.py`

Expected: all tests pass, including idempotency and late-output quarantine.

- [ ] **Step 5: Commit lifecycle manager**

```bash
git add src/overseer/agent_handoff.py src/overseer/agent_manager.py tests/test_agent_handoff.py tests/test_agent_manager.py
git commit -m "Add agent driver lifecycle manager"
```

---

### Task 5: Wrap Existing Codex Behavior Without Regression

**Files:**
- Create: `src/overseer/agent_adapters/codex.py`
- Modify: `src/overseer/codex_projects.py`
- Create: `tests/test_agent_adapter_contract.py`
- Create: `tests/test_agent_migration.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: `PrimaryDriver`, `CliCommandRunner`, current Codex CSV and tmux behavior.
- Produces: `CodexDriver`; legacy `CodexProjectThreadAdapter` façade; `legacy_codex_session_resource`.

- [ ] **Step 1: Parameterize the adapter contract and lock legacy expectations**

```python
@pytest.mark.parametrize("provider_id", ["codex"])
def test_adapter_contract_discovers_and_resumes(
    provider_id: str,
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory(provider_id)
    session = adapter.discover()[0]
    assert session.provider_id == provider_id
    result = adapter.resume(session)
    assert result.state in {
        AgentOperationState.ACKNOWLEDGED,
        AgentOperationState.RUNNING,
    }


def test_legacy_codex_resource_id_is_preserved(codex_csv: Path) -> None:
    adapter = CodexProjectThreadAdapter(registry_path=codex_csv)
    resource = codex_project_thread_resources(adapter.list_threads())[0]
    assert resource.id == "thread.codex.example"


def test_legacy_csv_import_links_generic_session(codex_csv: Path) -> None:
    sessions = CodexDriver.from_legacy_registry(codex_csv).discover()
    assert sessions[0].legacy_references["resource_id"] == "thread.codex.example"
```

- [ ] **Step 2: Verify contract fails before Codex adapter exists**

Run: `pytest -q tests/test_agent_adapter_contract.py tests/test_agent_migration.py`

Expected: tests fail importing `overseer.agent_adapters.codex`.

- [ ] **Step 3: Move provider semantics behind `CodexDriver`**

`CodexDriver` keeps the existing defaults:

```python
DEFAULT_CODEX_PROJECTS_REGISTRY = Path("/home/god/.codex/codex-projects.csv")
DEFAULT_CODEX_MEMORY_SESSION = Path("/home/god/.local/bin/codex-memory-session")
DEFAULT_TMUX = Path("/usr/bin/tmux")
PROMPT_REJECTION_MARKERS = (
    "message exceeds maximum length",
    "maximum length allowed",
)
```

Convert each legacy CSV row to `AgentSession(provider_id="codex", ...)`. Keep the exact `tmux new-session`, `load-buffer`, `paste-buffer`, `send-keys`, and rejection-detection behavior. Make `CodexProjectThreadAdapter` translate legacy DTOs to/from `CodexDriver`, so current callers and test assertions remain valid.

- [ ] **Step 4: Run all Codex compatibility tests**

Run: `pytest -q tests/test_agent_adapter_contract.py tests/test_agent_migration.py tests/test_core.py -x`

Expected: all selected tests pass, including current resume, prompt rejection, IDS dispatch, resource discovery, and continuation behavior.

- [ ] **Step 5: Commit Codex compatibility adapter**

```bash
git add src/overseer/agent_adapters/codex.py src/overseer/codex_projects.py tests/test_agent_adapter_contract.py tests/test_agent_migration.py tests/test_core.py
git commit -m "Wrap Codex with primary driver adapter"
```

---

### Task 6: Add Generic CLI, API, and Client Surfaces

**Files:**
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/client.py`
- Create: `tests/test_agent_api.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: `AgentRegistry`, `AgentManager`, persisted lifecycle records.
- Produces: generic CLI commands and `/agent-*` API resources; legacy aliases delegate to generic handlers.

- [ ] **Step 1: Write failing generic API and alias tests**

```python
def test_agent_provider_inventory(client: OverseerClient) -> None:
    response = client.list_agent_providers()
    assert {row["id"] for row in response["providers"]} >= {"codex", "claude"}


def test_manual_handoff_requires_approval_id(api: LocalAPI) -> None:
    response = api.post_json(
        "/agent-handoffs",
        {
            "instance_id": "overseer.default",
            "incoming_provider_id": "claude",
            "initiated_by": "operator",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "approval_id is required"


def test_legacy_discovery_route_delegates_to_generic_handler(api: LocalAPI) -> None:
    legacy = api.post_json("/codex-projects/discover-threads", {})
    generic = api.post_json(
        "/agent-sessions/discover",
        {"provider_id": "codex", "instance_id": "overseer.default"},
    )
    assert legacy.json()["resources"] == generic.json()["resources"]
    assert legacy.headers["Deprecation"] == "true"
```

- [ ] **Step 2: Verify generic routes are absent**

Run: `pytest -q tests/test_agent_api.py`

Expected: tests fail with missing client methods or 404 responses.

- [ ] **Step 3: Add generic handlers and aliases**

Add CLI commands:

```text
agent-providers
agent-instances
discover-agent-sessions
agent-session-status
dispatch-agent-goal
checkpoint-agent
recover-agent
handoff-agent
failover-agent
```

Add API routes:

```text
GET  /agent-providers
GET  /agent-instances
POST /agent-sessions/discover
GET  /agent-sessions
POST /agent-dispatches
GET  /agent-dispatches
POST /agent-checkpoints
POST /agent-recovery
POST /agent-handoffs
POST /agent-failover
```

Every mutation accepts an idempotency key where replay is meaningful and uses the existing API authentication and audit conventions. Set `Deprecation: true` and a `Link` successor header on legacy Codex routes.

- [ ] **Step 4: Run API, CLI, and core tests**

Run: `pytest -q tests/test_agent_api.py tests/test_core.py -x`

Expected: all tests pass and legacy routes still return their existing payload keys.

- [ ] **Step 5: Commit generic operator surfaces**

```bash
git add src/overseer/cli.py src/overseer/api.py src/overseer/client.py tests/test_agent_api.py tests/test_core.py
git commit -m "Expose provider-neutral agent lifecycle API"
```

---

### Task 7: Generalize Quark Work Routing and Continuations

**Files:**
- Modify: `src/overseer/usage_limits.py`
- Modify: `src/overseer/quark_scheduler.py`
- Modify: `src/overseer/quark_scheduler_cli.py`
- Modify: `src/overseer/cli.py`
- Modify: `src/overseer/api.py`
- Modify: `tests/test_quark_scheduler.py`
- Modify: `tests/test_core.py`

**Interfaces:**
- Consumes: `AgentManager.dispatch/recover`, provider limit resource identifiers.
- Produces: `AgentWorkItem`; `ProviderWorkExecutor`; backward-compatible `CodexWorkItem` and `CodexExecSliceAdapter` aliases.

- [ ] **Step 1: Write failing mixed-provider scheduler tests**

```python
def test_mixed_provider_work_keeps_native_limit_ids() -> None:
    work = (
        _agent_work("work.codex", "project-a", "codex", "limit.codex.points", 5),
        _agent_work("work.claude", "project-b", "claude", "limit.claude.tokens", 8),
    )
    plan = plan_quark_work(_policy(), {"limit.codex.points": 20, "limit.claude.tokens": 30}, work)
    assert {row.limit_id for row in plan.allocations} == {
        "limit.codex.points",
        "limit.claude.tokens",
    }


def test_unknown_provider_capacity_uses_conservative_policy() -> None:
    plan = plan_quark_work(
        _policy(),
        {"limit.claude.tokens": None},
        (_agent_work("work.1", "project-a", "claude", "limit.claude.tokens", 8),),
    )
    assert plan.allocations == ()
    assert "unknown capacity" in plan.reason


def test_generic_continuation_routes_through_session_provider(
    manager: FakeAgentManager,
) -> None:
    result = dispatch_usage_continuations_status(
        store_path=":memory:",
        resume_agent_sessions=True,
        agent_manager=manager,
    )
    assert manager.recovered_session_ids == ["session.claude.1"]
    assert result["resume_agent_sessions"] is True
```

- [ ] **Step 2: Verify scheduler signature failures**

Run: `pytest -q tests/test_quark_scheduler.py tests/test_core.py -x`

Expected: the new mixed-provider tests fail because work and capacity are Codex-specific.

- [ ] **Step 3: Introduce generic records and compatibility aliases**

```python
@dataclass(frozen=True)
class AgentWorkItem:
    id: str
    project_id: str
    agent_session_id: str
    provider_id: str
    limit_id: str
    intent: str
    estimated_units: float
    usage_unit: str
    owner_thread: str | None = None
    priority: int = 50
    state: WorkState = WorkState.QUEUED
    reserved_units: float = 0
    generation: int = 0
    checkpoint_ref: str | None = None


CodexWorkItem = AgentWorkItem
```

Persist optional `agent_session_id`, `driver_epoch_id`, and `provider_id` on continuation requests and dispatches while preserving `owner_thread`. Route recovery through `AgentManager` when generic fields exist; fall back to the legacy Codex façade for old records. Keep each limit's units and capacity independent.

- [ ] **Step 4: Run scheduler, usage, API, and compatibility tests**

Run: `pytest -q tests/test_quark_scheduler.py tests/test_core.py tests/test_codex_usage.py -x`

Expected: all selected tests pass; Codex usage evidence remains Codex-specific.

- [ ] **Step 5: Commit provider-neutral scheduling**

```bash
git add src/overseer/usage_limits.py src/overseer/quark_scheduler.py src/overseer/quark_scheduler_cli.py src/overseer/cli.py src/overseer/api.py tests/test_quark_scheduler.py tests/test_core.py
git commit -m "Route Quark work by agent provider"
```

---

### Task 8: Add Primary Driver Dashboard and Compatibility UI

**Files:**
- Modify: `src/overseer/ui.py`
- Modify: `tests/test_ui_regression.py`
- Modify: `tests/test_ui_full_regression.py`
- Modify: `tests/test_codex_usage.py`

**Interfaces:**
- Consumes: `/agent-providers`, `/agent-instances`, `/agent-sessions`, `/agent-dispatches`, provider-native usage evidence.
- Produces: primary-driver status, capability matrix, current epoch/checkpoint, fallback order, and lifecycle actions.

- [ ] **Step 1: Write failing UI assertions**

```python
def test_operator_console_contains_primary_driver_controls() -> None:
    assert "Primary AI Driver" in OPERATOR_CONSOLE_HTML
    assert 'data-action="checkpoint-agent"' in OPERATOR_CONSOLE_HTML
    assert 'data-action="handoff-agent"' in OPERATOR_CONSOLE_HTML
    assert 'data-action="failover-agent"' in OPERATOR_CONSOLE_HTML
    assert "Provider Capabilities" in OPERATOR_CONSOLE_HTML


def test_unsupported_controls_are_disabled_by_capability(page) -> None:
    page.route(
        "**/agent-instances",
        lambda route: route.fulfill(json={
            "instances": [{
                "id": "overseer.default",
                "primary_provider_id": "claude",
                "capabilities": {"cancellation": False},
            }]
        }),
    )
    page.goto("/ui")
    expect(page.locator('[data-action="cancel-agent"]')).to_be_disabled()
    expect(page.locator('[data-action="cancel-agent"]')).to_have_attribute(
        "title", "Provider does not support cancellation"
    )
```

- [ ] **Step 2: Verify missing dashboard controls**

Run: `pytest -q tests/test_ui_regression.py tests/test_codex_usage.py -x`

Expected: new assertions fail because the console is Codex-only.

- [ ] **Step 3: Add provider-neutral UI state and actions**

Add data sources:

```javascript
agentProviders: "/agent-providers",
agentInstances: "/agent-instances",
agentSessions: "/agent-sessions",
agentDispatches: "/agent-dispatches",
```

Rename general actions to “Discover Agent Sessions” and “Resume Agent Sessions.” Keep the Codex usage panel labeled “Codex Usage” when Codex is its source. Render native `usage_unit` beside every provider value. Require operator confirmation plus `approval_id` for handoff and failover requests. Disable controls when capability flags or policy readiness are false and show the exact blocker.

- [ ] **Step 4: Run static and browser regression suites**

Run: `pytest -q tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_codex_usage.py -x`

Expected: all selected tests pass with generic actions and legacy Codex compatibility fixtures.

- [ ] **Step 5: Commit dashboard changes**

```bash
git add src/overseer/ui.py tests/test_ui_regression.py tests/test_ui_full_regression.py tests/test_codex_usage.py
git commit -m "Add primary AI driver dashboard"
```

---

### Task 9: Implement and Prove Claude as the First Replacement Driver

**Files:**
- Create: `src/overseer/agent_adapters/claude.py`
- Modify: `src/overseer/agent_adapters/__init__.py`
- Modify: `tests/test_agent_adapter_contract.py`
- Modify: `tests/test_agent_manager.py`
- Modify: `config/agent-providers.json`

**Interfaces:**
- Consumes: the verified installed Claude CLI help/version output, `PrimaryDriver`, `CliCommandRunner`, handoff package.
- Produces: `ClaudeDriver`; detected capability overrides based on the installed CLI.

- [ ] **Step 1: Capture the actual installed interface read-only**

Run:

```bash
command -v claude
claude --version
claude --help
```

Expected: record the executable path, version, supported session/resume flags, noninteractive mode, structured output options, and permission flags in redacted test fixtures. If `claude` is absent, continue with fake-executable tests and mark the opt-in live smoke test skipped with reason `claude executable not installed`.

- [ ] **Step 2: Add Claude to the shared failing contract**

```python
@pytest.mark.parametrize("provider_id", ["codex", "claude"])
def test_adapter_contract_dispatch_and_status(
    provider_id: str,
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory(provider_id)
    session = adapter.discover()[0]
    request = _dispatch_request(session, prompt="report READY")
    result = adapter.dispatch(request)
    assert result.provider_id == provider_id
    assert result.state is AgentOperationState.ACKNOWLEDGED
    assert result.redacted_evidence == {"ack": "READY"}
```

Run: `pytest -q tests/test_agent_adapter_contract.py -k claude`

Expected: fails because `ClaudeDriver` is not registered.

- [ ] **Step 3: Implement only capabilities proven by the installed interface**

Build `ClaudeDriver` command arrays from the captured CLI contract. Unsupported discovery, resume, structured events, checkpoint, cancellation, or usage features remain `False` and return `unsupported_capability`. Never pass a skip-permissions or unrestricted-access flag from committed defaults. Convert the normalized handoff package to a bounded continuation prompt with evidence references.

- [ ] **Step 4: Prove disposable manual handoff in tests**

Add a fake-executable lifecycle test:

```python
def test_codex_to_claude_to_codex_manual_handoff_does_not_repeat_operation(
    manager: AgentManager,
) -> None:
    manager.activate("overseer.default", initiated_by="operator")
    completed = manager.dispatch("overseer.default", "write marker", "operation.marker")
    assert completed.state is AgentOperationState.SUCCEEDED
    claude_epoch = manager.manual_handoff(
        "overseer.default", "claude", "operator", "approval.to-claude"
    )
    codex_epoch = manager.manual_handoff(
        "overseer.default", "codex", "operator", "approval.to-codex"
    )
    assert claude_epoch.ordinal + 1 == codex_epoch.ordinal
    assert manager.operation_count("operation.marker") == 1
```

Run: `pytest -q tests/test_agent_adapter_contract.py tests/test_agent_manager.py -x`

Expected: all tests pass.

- [ ] **Step 5: Run opt-in live smoke only when explicitly enabled**

Run: `OVERSEER_LIVE_AGENT_PROVIDER=claude pytest -q tests/test_agent_adapter_contract.py -m live_agent`

Expected: pass against a disposable temporary workspace or skip with an explicit installation/authentication reason. It must not use the Overseer checkout as the writable smoke workspace.

- [ ] **Step 6: Commit Claude driver**

```bash
git add src/overseer/agent_adapters/claude.py src/overseer/agent_adapters/__init__.py config/agent-providers.json tests/test_agent_adapter_contract.py tests/test_agent_manager.py
git commit -m "Add Claude primary driver adapter"
```

---

### Task 10: Add Qwen Code, Mistral Vibe, and Antigravity Adapters

**Files:**
- Create: `src/overseer/agent_adapters/qwen_code.py`
- Create: `src/overseer/agent_adapters/mistral_vibe.py`
- Create: `src/overseer/agent_adapters/antigravity.py`
- Modify: `src/overseer/agent_adapters/__init__.py`
- Modify: `tests/test_agent_adapter_contract.py`
- Modify: `config/agent-providers.json`

**Interfaces:**
- Consumes: the same `PrimaryDriver` contract and verified local interface evidence for each provider.
- Produces: three isolated adapters with honest capability declarations.

- [ ] **Step 1: Inspect each installed interface read-only**

Run:

```bash
command -v qwen || command -v qwen-code
command -v vibe || command -v mistral-vibe
command -v antigravity
```

For each discovered executable, run only its documented `--version` and `--help` commands. For Antigravity, first determine whether the installed integration is a CLI, API, desktop automation surface, or gateway. Do not invent a CLI contract when none exists.

Expected: each provider has a recorded transport choice and supported capability set, or an explicit unavailable reason.

- [ ] **Step 2: Add every provider to the shared failing contract**

```python
@pytest.mark.parametrize(
    "provider_id",
    ["codex", "claude", "qwen-code", "mistral-vibe", "antigravity"],
)
def test_adapter_contract_reports_identity_and_capabilities(
    provider_id: str,
    adapter_factory: AdapterFactory,
) -> None:
    adapter = adapter_factory(provider_id)
    assert adapter.provider.id == provider_id
    assert isinstance(adapter.provider.capabilities, AgentCapabilities)
```

Run: `pytest -q tests/test_agent_adapter_contract.py`

Expected: fails for the three unimplemented adapters.

- [ ] **Step 3: Implement provider-specific command and parser modules**

Each adapter must:

```python
class ProviderDriver:
    provider: AgentProvider

    def dispatch(self, request: AgentDispatchRequest) -> AgentDispatchResult:
        if not self.provider.capabilities.interactive_dispatch:
            return AgentDispatchResult.unsupported(
                request=request,
                capability="interactive_dispatch",
            )
        completed = self.runner.run(
            self._dispatch_argv(request),
            input_text=self._dispatch_input(request),
            timeout_seconds=self.dispatch_timeout_seconds,
        )
        return self._parse_dispatch_result(request, completed)
```

Use real provider-specific `_dispatch_argv`, `_dispatch_input`, and parser implementations derived from Step 1. Antigravity may use a gateway adapter when that is its actual interface; the registry transport must match it.

- [ ] **Step 4: Run contract and unavailable-provider tests**

Run: `pytest -q tests/test_agent_adapter_contract.py tests/test_agent_registry.py -x`

Expected: all fake-executable contract cases pass. Missing live executables produce `provider_unavailable`, not configuration crashes or assumed success.

- [ ] **Step 5: Commit remaining adapters**

```bash
git add src/overseer/agent_adapters/qwen_code.py src/overseer/agent_adapters/mistral_vibe.py src/overseer/agent_adapters/antigravity.py src/overseer/agent_adapters/__init__.py config/agent-providers.json tests/test_agent_adapter_contract.py
git commit -m "Add additional primary driver adapters"
```

---

### Task 11: Enable Policy-Controlled Failover

**Files:**
- Modify: `src/overseer/agent_contracts.py`
- Modify: `src/overseer/agent_manager.py`
- Modify: `src/overseer/agent_handoff.py`
- Modify: `src/overseer/api.py`
- Modify: `src/overseer/ui.py`
- Modify: `tests/test_agent_manager.py`
- Modify: `tests/test_agent_api.py`
- Modify: `tests/test_ui_regression.py`

**Interfaces:**
- Consumes: repeated health evidence, checkpoint freshness, active risk state, transferability, capability compatibility, approved fallback order and policy.
- Produces: `FailoverPolicy`, `FailoverDecision`, `AgentManager.evaluate_failover`, `AgentManager.execute_failover`.

- [ ] **Step 1: Write all failover precondition tests**

```python
@pytest.mark.parametrize(
    ("condition", "expected_blocker"),
    [
        ("single_failure", "failure threshold not reached"),
        ("slow_response", "slow response is not a failover trigger"),
        ("stale_checkpoint", "checkpoint is stale"),
        ("high_risk_active", "high-risk action is unresolved"),
        ("non_transferable", "operation is not transferable"),
        ("capability_mismatch", "fallback lacks required capabilities"),
        ("unapproved_policy", "failover policy is not approved"),
    ],
)
def test_failover_pauses_when_precondition_is_missing(
    condition: str,
    expected_blocker: str,
    failover_scenario: FailoverScenario,
) -> None:
    decision = failover_scenario(condition).manager.evaluate_failover("overseer.default")
    assert decision.allowed is False
    assert expected_blocker in decision.blockers


def test_failover_uses_first_healthy_compatible_approved_fallback(
    failover_scenario: FailoverScenario,
) -> None:
    manager = failover_scenario("ready").manager
    decision = manager.evaluate_failover("overseer.default")
    assert decision.allowed is True
    assert decision.incoming_provider_id == "claude"
```

- [ ] **Step 2: Verify failover is not implemented**

Run: `pytest -q tests/test_agent_manager.py -k failover`

Expected: tests fail with missing policy and decision methods.

- [ ] **Step 3: Implement a pure decision function before mutation**

```python
def evaluate_failover(
    policy: FailoverPolicy,
    health: ProviderHealthSummary,
    checkpoint: AgentCheckpoint | None,
    active_risks: tuple[ActiveRisk, ...],
    required_capabilities: AgentCapabilities,
    candidates: tuple[AgentProvider, ...],
    now: datetime,
) -> FailoverDecision:
    blockers: list[str] = []
    if not policy.approved:
        blockers.append("failover policy is not approved")
    if health.slow_only:
        blockers.append("slow response is not a failover trigger")
    if health.consecutive_failures < policy.failure_threshold:
        blockers.append("failure threshold not reached")
    if checkpoint is None or checkpoint.is_stale(now, policy.checkpoint_max_age):
        blockers.append("checkpoint is stale")
    if any(risk.high_risk and not risk.resolved for risk in active_risks):
        blockers.append("high-risk action is unresolved")
    if checkpoint is not None and not checkpoint.transferable:
        blockers.append("operation is not transferable")
    compatible = tuple(
        candidate
        for candidate in candidates
        if candidate.capabilities.supports(required_capabilities)
    )
    if not compatible:
        blockers.append("fallback lacks required capabilities")
    return FailoverDecision(
        allowed=not blockers,
        incoming_provider_id=compatible[0].id if not blockers else None,
        blockers=tuple(blockers),
    )
```

`execute_failover` must require an allowed persisted decision and then reuse the tested manual handoff transaction with `reason="controlled_failover"`.

- [ ] **Step 4: Run manager, API, and UI failover tests**

Run: `pytest -q tests/test_agent_manager.py tests/test_agent_api.py tests/test_ui_regression.py -x`

Expected: all tests pass and blocked failover displays exact blockers without mutation.

- [ ] **Step 5: Commit controlled failover**

```bash
git add src/overseer/agent_contracts.py src/overseer/agent_manager.py src/overseer/agent_handoff.py src/overseer/api.py src/overseer/ui.py tests/test_agent_manager.py tests/test_agent_api.py tests/test_ui_regression.py
git commit -m "Add controlled primary driver failover"
```

---

### Task 12: Document, Migrate, and Run Full Verification

**Files:**
- Create: `docs/agent-provider-architecture.md`
- Create: `docs/provider-adapter-contract.md`
- Create: `docs/agent-provider-migration.md`
- Modify: `README.md`
- Modify: `docs/agents.md`
- Modify: `docs/adapters-and-dry-run.md`
- Modify: `docs/local-api.md`
- Modify: `docs/runtime.md`
- Modify: `docs/usage-limit-scheduling.md`
- Modify: `config/local-mcp-services.json`
- Modify: `scripts/run_full_regression.py`

**Interfaces:**
- Consumes: completed contracts, routes, configuration, lifecycle behavior, and compatibility policy.
- Produces: operator and adapter documentation, migration/rollback instructions, and complete regression coverage.

- [ ] **Step 1: Write documentation assertions**

```python
def test_agent_provider_docs_cover_required_safety_boundaries() -> None:
    architecture = Path("docs/agent-provider-architecture.md").read_text()
    contract = Path("docs/provider-adapter-contract.md").read_text()
    migration = Path("docs/agent-provider-migration.md").read_text()
    for phrase in (
        "one primary driver",
        "driver epoch",
        "manual handoff",
        "controlled failover",
        "old-epoch output",
        "provider-native usage",
    ):
        assert phrase in architecture
    assert "argument arrays" in contract
    assert "unsupported_capability" in contract
    assert "/codex-projects/" in migration
    assert "one migration cycle" in migration
    assert "rollback" in migration
```

Place this test in `tests/test_agent_migration.py`.

- [ ] **Step 2: Write the operator and adapter documentation**

Document:

- how to select one primary provider in committed and local configuration;
- how credential references are resolved without storing values;
- how capabilities affect controls;
- how to inspect health, sessions, epochs, dispatches, and checkpoints;
- exact manual handoff and recovery commands;
- failover preconditions and paused-state behavior;
- provider-native Quark usage semantics;
- how to implement and contract-test a new adapter;
- the Codex compatibility aliases, deprecation signal, migration cycle, and rollback;
- why DS9 crew roles remain responsibility boundaries rather than provider accounts.

Keep `svc.mcp.codex-usage` in `config/local-mcp-services.json` and label it explicitly as the Codex provider's usage observer, not the universal agent usage service.

- [ ] **Step 3: Add new suites to the regression runner**

Ensure `scripts/run_full_regression.py` includes:

```text
tests/test_agent_contracts.py
tests/test_agent_registry.py
tests/test_agent_store.py
tests/test_agent_handoff.py
tests/test_agent_manager.py
tests/test_agent_adapter_contract.py
tests/test_agent_api.py
tests/test_agent_migration.py
```

Do not enable opt-in live provider tests in ordinary regression.

- [ ] **Step 4: Run focused static and migration verification**

Run:

```bash
python3 -m compileall -q src
pytest -q tests/test_agent_contracts.py tests/test_agent_registry.py tests/test_agent_store.py tests/test_agent_handoff.py tests/test_agent_manager.py tests/test_agent_adapter_contract.py tests/test_agent_api.py tests/test_agent_migration.py
```

Expected: compilation exits zero and all provider-neutral tests pass.

- [ ] **Step 5: Run the complete test suite**

Run: `pytest -q`

Expected: all tests pass; live provider tests are skipped unless explicitly enabled.

- [ ] **Step 6: Run the repository regression wrapper**

Run: `PYTHONPATH=src python3 scripts/run_full_regression.py`

Expected: exit zero and a new redacted regression artifact reports all configured stages passed.

- [ ] **Step 7: Inspect secrets and shell-safety invariants**

Run:

```bash
grep -RInE '"(api_key|token|password|authorization|cookie)"[[:space:]]*:' config src tests \
  --exclude='*.pyc'
grep -RInE 'shell[[:space:]]*=[[:space:]]*True|subprocess\.(run|Popen)\([^)]*["'\''][^"'\'']*[;&|]' \
  src/overseer/agent_adapters src/overseer/agent_registry.py
```

Expected: the first command shows only validators, redacted fixtures, or secret-reference field names; the second command returns no unsafe provider execution.

- [ ] **Step 8: Review compatibility and working tree scope**

Run:

```bash
git diff --check
git status --short
git diff --stat
```

Expected: no whitespace errors; only files intentionally changed by this implementation are staged for its final documentation commit, while pre-existing unrelated changes remain unstaged and preserved.

- [ ] **Step 9: Commit documentation and regression integration**

```bash
git add README.md config/local-mcp-services.json docs/agent-provider-architecture.md docs/provider-adapter-contract.md docs/agent-provider-migration.md docs/agents.md docs/adapters-and-dry-run.md docs/local-api.md docs/runtime.md docs/usage-limit-scheduling.md scripts/run_full_regression.py tests/test_agent_migration.py
git commit -m "Document provider-neutral AI drivers"
```

---

## Implementation Checkpoints

1. **Compatibility checkpoint after Task 5:** Codex behavior is running through the neutral contract with no intended operator-visible change.
2. **Control-plane checkpoint after Task 8:** storage, manager, Quark, API, CLI, and UI are provider-neutral, but Codex is still the only proven live primary driver.
3. **Replacement-driver checkpoint after Task 9:** Claude can replace Codex in a disposable Overseer instance through a tested manual handoff.
4. **Provider-coverage checkpoint after Task 10:** remaining providers conform to the adapter contract according to verified interfaces.
5. **Failover checkpoint after Task 11:** controlled failover becomes available only after recovery, handoff, quarantine, idempotency, compatibility, and approval gates pass.
6. **Release checkpoint after Task 12:** full regression, security invariants, compatibility docs, and rollback instructions are complete.

## Execution Boundaries

- Do not run live provider smoke tests without an installed provider, valid local authentication, and a disposable workspace.
- Do not modify provider credentials, system services, package installations, network policy, or shared ports as part of this plan without separate Overseer coordination and applicable approval.
- If a provider's installed CLI differs from assumptions, update only its adapter contract, fixtures, capability declaration, and documentation; do not weaken the neutral manager.
- If Antigravity has no supported programmatic interface, ship its adapter as unavailable with an explicit capability/readiness result rather than automating a GUI or inventing commands.
- Do not enable controlled failover until the Task 9 manual round-trip handoff test and Task 11 precondition suite both pass.
