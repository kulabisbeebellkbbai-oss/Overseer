# Provider-Neutral Primary AI Driver Design

## Purpose

Overseer must be operable by different agentic AI systems. Codex remains a
supported provider, but an Overseer instance may instead select Claude,
Antigravity, Mistral Vibe, or Qwen Code as its primary AI driver.

Each Overseer instance has exactly one primary driver at a time. Other
providers may act as delegated workers. Changing the primary driver requires a
manual handoff or a policy-controlled failover; it never occurs as an
unrecorded configuration side effect.

## Design Goals

- Make the primary AI driver a replaceable provider adapter.
- Preserve Overseer's deterministic policies, approvals, claims, audit trail,
  secrets handling, scheduling, and state as the authoritative control plane.
- Support interactive CLI, noninteractive CLI, direct API, and future gateway
  transports behind one provider-neutral contract.
- Preserve current Codex behavior through a compatibility adapter and
  deprecated compatibility surfaces during migration.
- Permit recovery, manual handoff, and controlled failover without duplicating
  completed work or allowing stale providers to mutate current state.
- Represent provider capabilities honestly rather than assuming feature parity.
- Keep provider credentials out of configuration, persisted agent records, and
  handoff packages.

## Non-Goals

- Building a universal model API or hiding meaningful differences between
  providers.
- Allowing an AI provider to bypass Overseer policy or approval boundaries.
- Automatically converting unrelated provider quota units into Codex quota
  percentage points.
- Persisting unrestricted provider transcripts.
- Enabling automatic failover before manual handoff and recovery are proven.
- Rewriting Overseer's general resource, claim, approval, or crew-domain model.

## Architectural Decision

Use a provider-neutral driver contract implemented by isolated provider
adapters. Do not make other providers impersonate Codex commands or registries.
Do not require a separate driver gateway in the first release. The contract
must allow an adapter to move behind a gateway later without changing
Overseer's core.

```text
Operator
   |
Overseer instance
   |-- deterministic policy and coordination core
   |-- primary-driver manager
   |      `-- selected driver adapter
   |             |-- Codex
   |             |-- Claude
   |             |-- Antigravity
   |             |-- Mistral Vibe
   |             `-- Qwen Code
   `-- optional delegated worker adapters
```

The deterministic core owns authorization and durable state. The primary AI
driver interprets operator goals, proposes actions, invokes scoped Overseer
capabilities, and continues agentic work. Provider capabilities describe
technical ability only; they do not grant authorization.

## Instance Model

An `AgentInstanceProfile` selects and constrains the primary driver for one
Overseer instance. It contains:

- a stable instance identifier;
- the primary provider and adapter identifier;
- the transport kind: interactive CLI, noninteractive CLI, API, or gateway;
- model or provider profile selection;
- workspace and external session identity;
- declared and detected capabilities;
- credential references, never credential values;
- permission and execution policy references;
- provider health and usage-limit sources;
- an ordered list of approved fallback providers; and
- the controlled-failover policy.

Provider selection is resolved at instance startup. Editing configuration while
an instance is active does not replace the current driver. The change is staged
until an operator initiates a handoff or an approved failover policy is
satisfied.

## Primary Driver Contract

The provider-neutral `PrimaryDriver` contract supports:

- provider metadata and capability discovery;
- session discovery and resolution;
- session creation, recovery, and resume;
- normalized goal or continuation dispatch;
- acknowledgement, progress, completion, and failure inspection;
- durable checkpoint creation;
- cancellation requests;
- health and usage observation; and
- export and import of provider-neutral handoff packages.

Normalized types include:

- `AgentProvider`
- `AgentCapabilities`
- `AgentInstanceProfile`
- `AgentSession`
- `DriverEpoch`
- `AgentDispatchRequest`
- `AgentDispatchResult`
- `AgentCheckpoint`
- `AgentHandoffPackage`

Capabilities are explicit flags or typed properties. They include, at minimum,
session discovery, session resume, interactive dispatch, noninteractive
dispatch, structured events, checkpoints, cancellation, delegated workers,
usage observation, and handoff import. An unsupported feature produces a
normalized `unsupported_capability` result; adapters must not weakly emulate
features that could cause unsafe or misleading behavior.

## Components

### Agent contracts

`src/overseer/agent_contracts.py` defines the provider-neutral data types,
states, errors, and protocols. It contains no provider command construction or
configuration loading.

### Agent registry

`src/overseer/agent_registry.py` loads provider definitions and instance
profiles, validates configuration, resolves the selected primary adapter, and
reports adapter readiness. It rejects unknown transports, duplicate stable
identifiers, non-allowlisted executables, missing secret references, and
fallbacks that lack required capabilities.

### Agent manager

`src/overseer/agent_manager.py` owns primary-driver lifecycle and routes
discovery, creation, resume, dispatch, inspection, checkpoint, cancellation,
recovery, handoff, and failover. It binds every operation to the current driver
epoch and requests authorization from existing Overseer policy services before
performing mutations.

### Provider adapters

`src/overseer/agent_adapters/` contains one focused adapter per provider:

- `codex.py`
- `claude.py`
- `antigravity.py`
- `mistral_vibe.py`
- `qwen_code.py`

Each adapter owns its executable discovery, argument construction, transport,
session identifiers, output parsing, acknowledgement rules, rejection markers,
health observation, and capability declaration. Provider commands are
constructed as argument arrays and never through interpolated shell strings.

Current behavior in `src/overseer/codex_projects.py` moves behind the Codex
adapter. Compatibility imports and entry points remain available for one
documented migration cycle.

### Handoff service

`src/overseer/agent_handoff.py` creates and validates normalized, redacted
handoff packages. A handoff package includes:

- the current objective and approved plan reference;
- current task and completion criteria;
- completed work and verification evidence;
- repository and workspace state;
- active claims and pending approvals;
- blockers and known failures;
- latest durable checkpoint references;
- provider-neutral continuation instructions; and
- required capabilities for the incoming driver.

Raw credentials, environment dumps, unrestricted transcripts, cookies, bearer
tokens, and provider-private internal state are excluded.

### Persistence

Persistence adds explicit records for:

- agent providers;
- instance profiles;
- agent sessions;
- driver epochs;
- dispatch attempts;
- checkpoints; and
- handoffs.

Every dispatch attempt has a stable idempotency key, epoch identifier, state,
timestamps, redacted evidence, and optional provider usage association. Dispatch
states are `queued`, `acknowledged`, `running`, `succeeded`, `failed`,
`blocked`, `cancelled`, or `quarantined`.

Raw credentials and unrestricted transcripts are never stored in these records.

## Execution Flow

```text
Operator submits goal
  -> agent manager resolves the active driver epoch
  -> Overseer policy core authorizes the requested operation
  -> adapter creates, recovers, or resumes its provider session
  -> manager sends a normalized dispatch
  -> adapter translates provider events into normalized status
  -> manager persists status, audit evidence, and checkpoints
  -> work completes, waits, recovers, hands off, or fails over
```

The provider never writes directly to Overseer's database. It receives scoped
capabilities through Overseer's existing command, API, or MCP boundaries.

## Recovery, Handoff, and Failover

Recovery resumes the same provider from the latest valid checkpoint and remains
within the same primary-driver identity unless a new epoch is required to
quarantine an uncertain prior process.

Manual handoff requires the operator to select and approve the replacement
provider. Overseer creates a checkpoint, validates the incoming provider's
capabilities, records the handoff package, closes the outgoing epoch, opens a
new epoch, and dispatches the continuation.

Controlled failover selects the first healthy provider in a previously approved
fallback order. Automatic failover requires all of the following:

- repeated health or transport failures crossing the configured threshold;
- a valid checkpoint within the configured freshness window;
- no unresolved high-risk action in progress;
- no non-transferable provider operation in progress;
- a fallback with every required capability; and
- a failover policy approved before the failure.

A slow response by itself never triggers failover. If any failover precondition
is unmet, Overseer pauses the instance and requires operator intervention.

Every handoff or failover creates a new immutable driver epoch. Output arriving
from an earlier epoch is quarantined and cannot mutate current state.
Idempotency keys and completed-operation evidence prevent the incoming driver
from repeating recorded work.

## Security Model

- Provider executables and command templates are allowlisted configuration.
- Provider processes receive only the credential references and environment
  values required for that execution.
- Credential material is obtained through the existing key broker and is never
  returned through agent APIs or persisted in agent records.
- Adapter output is redacted before persistence or display.
- Workspace-writing drivers require the same claims, approvals, and risk
  classification regardless of provider.
- Provider capability declarations never expand authorization.
- Discovery and health inspection are read-only operations.
- Starting processes, dispatching goals, cancelling work, handoff, and failover
  are audited mutations.
- Late provider output, unknown epochs, invalid idempotency keys, and unsigned
  or structurally invalid handoff packages are rejected or quarantined.

## Usage and Scheduling

Quark schedules work against the active provider's own limit resource,
observation source, units, reset policy, and confidence. Provider-independent
work records identify the instance, session, driver epoch, provider limit, and
estimated work without assuming Codex semantics.

Codex percentage-point scheduling remains a Codex-specific usage adapter.
Claude, Antigravity, Mistral Vibe, and Qwen Code retain their native measurable
units. When a provider exposes no reliable usage observation, Quark marks
capacity confidence as unknown and applies the configured conservative policy
instead of inventing a conversion.

## Configuration

Committed provider-neutral configuration lives in
`config/agent-providers.json`. It defines provider identifiers, adapter kinds,
transports, allowlisted executable names, default capabilities, health
strategies, usage-source identifiers, and profile templates.

Ignored machine-local overrides provide executable paths, enabled profiles,
model choices, workspace paths, and secret references. Credential values never
appear in either configuration layer.

Configuration validation must detect:

- missing or non-allowlisted executables;
- unknown adapters or transports;
- duplicate provider, profile, or instance identifiers;
- missing secret references;
- unsupported requested capabilities;
- invalid or cyclic fallback order;
- selecting the active provider as its own fallback; and
- fallback providers unable to import the required handoff shape.

## API and Dashboard

The local API adds provider-neutral resources:

- `/agent-providers`
- `/agent-instances`
- `/agent-sessions`
- `/agent-dispatches`
- `/agent-checkpoints`
- `/agent-handoffs`
- `/agent-failover`

Mutation endpoints use existing authentication, audit, approval, and
idempotency conventions. Existing `/codex-projects/*` endpoints and payload
aliases remain deprecated compatibility surfaces for one migration cycle.

The dashboard displays:

- active primary provider and model or profile;
- current driver epoch and session;
- provider health and capability matrix;
- current work and latest checkpoint;
- active-provider usage status;
- approved fallback order;
- compatibility loss warnings; and
- manual checkpoint, recovery, handoff, and failover controls.

The UI must not imply that every provider supports every control. Unsupported
operations are disabled with the missing capability identified.

## Compatibility and Migration

New records use stable internal `agent_session_id` and `driver_epoch_id`
references. Existing `owner_thread` values remain readable as legacy external
references during migration.

Legacy Codex CSV entries are imported into the provider-neutral session
registry. Existing `thread.codex.*` resources remain resolvable and gain links
to the new session identifier. Existing Codex API routes, CLI flags, persisted
continuation requests, and UI actions remain functional through compatibility
aliases for one documented migration cycle.

The migration must be additive and repeatable. It must not rewrite or delete
legacy records until a separately approved cleanup release.

## Error Handling

All adapters return normalized results with a stable category:

- `unsupported_capability`
- `configuration_error`
- `provider_unavailable`
- `session_not_found`
- `authentication_required`
- `dispatch_rejected`
- `dispatch_timeout`
- `provider_protocol_error`
- `policy_blocked`
- `handoff_incompatible`
- `checkpoint_stale`
- `cancelled`
- `quarantined`

Provider stdout and stderr may contribute redacted evidence but never determine
authorization. Unknown or malformed provider output results in a protocol
error, not assumed success.

Retry policy is explicit per operation. Read-only health and status checks may
retry with bounded backoff. Mutating dispatches retry only when their
idempotency and provider acknowledgement state prove that replay is safe.

## Testing Strategy

### Contract tests

A shared adapter contract suite runs against every provider adapter using fake
executables. It verifies capability reporting, session discovery, create or
resume behavior, argument arrays, dispatch acknowledgement, status
normalization, checkpoint behavior, cancellation, timeouts, missing
executables, malformed output, and secret redaction.

### Provider fixtures

Codex, Claude, Antigravity, Mistral Vibe, and Qwen Code each have captured,
redacted fixtures for supported CLI or API behavior. Provider-specific tests
verify command syntax and parsing without requiring credentials in CI.

### Lifecycle tests

Lifecycle tests cover:

- successful recovery;
- manual handoff;
- controlled failover;
- stale checkpoint rejection;
- capability mismatch;
- unresolved high-risk operation blocking;
- idempotent continuation;
- late-output quarantine; and
- failed incoming driver initialization with safe rollback to a paused state.

### Migration tests

Migration tests load existing Codex CSV records, `thread.codex.*` resources,
legacy `owner_thread` values, old API payload keys, and stored continuation
requests. Repeated migration produces the same resulting links and creates no
duplicates.

### Scheduler tests

Mixed-provider tests verify native quota units, independent limit resources,
fair scheduling, conservative unknown-capacity behavior, provider routing, and
failure isolation.

### API and UI regression

Regression tests cover provider inventory, instance selection, health,
capabilities, sessions, dispatch status, checkpoint, recovery, handoff,
failover, deprecated aliases, and clear unsupported-capability presentation.

### Live smoke tests

Each installed provider may expose an opt-in local smoke test. Live tests verify
the actual installed interface and are excluded from ordinary CI. They must not
modify production workspaces or expose credentials.

## Delivery Sequence

1. Introduce provider-neutral contracts, registry, and manager while wrapping
   existing Codex behavior with no intended functional change.
2. Add persistence, configuration validation, provider-neutral API aliases,
   scheduler routing, and dashboard terminology.
3. Add Claude as the first replacement primary driver and validate recovery and
   a real manual handoff in a disposable workspace.
4. Add Qwen Code, Mistral Vibe, and Antigravity adapters according to their
   verified installed interfaces and declared capabilities.
5. Enable controlled failover only after manual handoff, recovery,
   idempotency, quarantine, and rollback tests pass.

Every stage must leave Overseer functional with Codex and must preserve existing
approval and security boundaries.

## Acceptance Criteria

- An instance can select Codex or Claude as its primary driver without changes
  to the deterministic Overseer core.
- Provider selection creates a recorded driver epoch and all dispatches bind to
  that epoch.
- The existing Codex registry, resume, dispatch, and continuation behavior
  remains available through the compatibility adapter.
- A disposable instance can complete a manual Codex-to-Claude and
  Claude-to-Codex handoff from a normalized checkpoint without repeating a
  recorded operation.
- Qwen Code, Mistral Vibe, and Antigravity can be added through isolated
  adapters without modifying the primary-driver manager.
- Unsupported provider capabilities are reported explicitly and cannot be
  invoked.
- Controlled failover pauses safely whenever its health, checkpoint, risk,
  compatibility, or approval preconditions are not satisfied.
- Old-epoch output cannot mutate the active instance.
- Provider credentials never appear in configuration, persisted records,
  handoff packages, logs, API output, or test fixtures.
- Mixed-provider work uses provider-native usage sources and units.
- Existing automated tests continue to pass, and the new adapter contract,
  lifecycle, migration, scheduler, API, and UI suites pass.
