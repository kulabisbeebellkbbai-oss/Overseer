# Task 9 Report: Claude Replacement Driver

## Outcome

Implemented a safe Claude Code primary-driver adapter using the locally verified
Claude Code 2.1.220 interface. The built-in registry now exposes Claude through
`noninteractive_cli` with only the proven capabilities: session resume,
noninteractive structured dispatch, and handoff import.

The adapter uses `CliCommandRunner`, immutable argument snapshots, stdin prompt
delivery, an explicit UUID session identity for manager-owned sessions,
structured JSON output, `plan` permission mode, a bounded spend argument, a
bounded prompt and output, and an absolute verified working directory. It never
uses permission-bypass flags and never records prompt, transcript, stderr, or
arbitrary provider output in normalized evidence.

Discovery, checkpoint, cancellation, delegated work, and usage observation are
not claimed or emulated. Handoff import incorporates only the normalized
objective and handoff/checkpoint/epoch identifiers.

## TDD Evidence

RED:

```text
pytest -q tests/test_agent_adapter_contract.py -k claude
ModuleNotFoundError: No module named 'overseer.agent_adapters.claude'
```

GREEN:

```text
pytest -q tests/test_agent_adapter_contract.py -k claude
8 passed, 1 skipped, 10 deselected in 0.38s

pytest -q tests/test_agent_adapter_contract.py tests/test_agent_manager.py -x
65 passed, 1 skipped in 1.31s
```

The manager coverage includes a disposable Codex to Claude to Codex handoff
whose completed pre-handoff operation is returned from its durable idempotency
record and is not dispatched again.

## Live-provider Gate

```text
pytest -q tests/test_agent_adapter_contract.py -k live_claude -rs
SKIPPED: live Claude disabled: OVERSEER_LIVE_AGENT_PROVIDER is not claude
```

No live prompt was issued. The test additionally requires the separate
`OVERSEER_LIVE_AGENT_AUTH_VERIFIED=1` assertion and always uses a pytest-created
disposable workspace. It does not change authentication, settings, credentials,
services, packages, or the real checkout.

## Full Verification

```text
pytest -q
715 passed, 1 skipped in 103.05s

python3 -m compileall -q src tests
passed

git diff --check
passed
```

## Shared-code Necessity

- `CliCommandRunner.run(..., cwd=...)` was extended so the provider subprocess
  is actually confined to the configured trusted workspace. It requires an
  absolute, existing directory and preserves all existing executable,
  environment, argv, timeout, and shell-free validation.
- The registry's Claude transport tuple changed from interactive to
  noninteractive to match the proven `--print` interface. Other provider
  combinations and generic validation remain unchanged.
- Existing API/registry synthetic tests were updated to reflect that Claude now
  has an installed built-in adapter and to inject their fake Claude driver with
  the truthful noninteractive transport.

## Residual Risks

- Help and fake-executable evidence do not prove live authentication or
  provider-side behavior. The opt-in live check remains intentionally skipped.
- Claude CLI JSON schema changes may require a future fixture update; malformed,
  missing-identity, oversized, rejected, and nonzero outputs fail closed.
- Native session discovery, checkpoint export, cancellation, delegated workers,
  and usage observation remain unsupported until independently verified.

## Commit

Implementation commit: `62e7bc860a5e0ae4bbe819e843166f8222bdbfd4`

## Independent Review Remediation

All six review findings were addressed test-first:

1. New and resumed Claude invocations now require the terminal JSON session ID
   to exactly equal the UUID supplied through `--session-id` or `--resume`.
   Spoofed identities fail closed as provider protocol errors.
2. Handoff import rejects foreign profiles, instances, providers, and malformed
   normalized incoming session/epoch identifiers before provider invocation.
3. Successful parsing accepts only `type=result`, `subtype=success`, and an
   explicitly boolean false `is_error`. Error results require a boolean true;
   init/system shapes, unknown subtypes, and missing/nonboolean error flags fail
   closed.
4. Claude uses `CliCommandRunner.run_bounded`, which spools stdout and stderr to
   temporary files, checks byte sizes before reading, and kills the isolated
   subprocess group on timeout. Real-process tests cover oversized stdout and
   stderr without materializing them.
5. The live test now runs the read-only
   `claude auth status --json` command with bounded output and requires parsed
   `loggedIn: true`; no environment variable is accepted as authentication
   proof. Provider opt-in remains separately required.
6. `structured_events` is false in the adapter contract and committed registry
   because final JSON output is not a streamed event contract.

Review-remediation verification:

```text
pytest -q tests/test_agent_adapter_contract.py -k claude
15 passed, 1 skipped

pytest -q tests/test_agent_adapter_contract.py tests/test_agent_manager.py \
  tests/test_agent_registry.py tests/test_agent_api.py -x
126 passed, 1 skipped in 8.33s

pytest -q
724 passed, 1 skipped in 103.21s

python3 -m compileall -q src tests
passed

git diff --check
passed
```

The live skip remained:

```text
live Claude disabled: OVERSEER_LIVE_AGENT_PROVIDER is not claude
```

No live prompt, settings mutation, credential change, service action, package
installation, or checkout-as-provider-workspace action occurred.

## Psychlo Policy-Exception Contract Parity Follow-up

The review correction at `318a44c` was repaired test-first. Global canonical
JSON number handling remains unchanged; only the policy-exception
`requestedValue` field tags finite numeric values as normalized IEEE-754
binary64 hex for digesting (`-0` becomes zero), while the wire value remains a
JSON number or boolean. Scalar and proposed-policy forms are now strict and
discriminated, all nine Psychlo rule IDs are accepted, and outcomes mirror the
originating form. Approved outcomes forbid `reason`; rejected outcomes require
bounded `reason`. Actor, correlation, idempotency, scope, decision, and request
digest bindings remain required.

The frozen usage snapshot digests were restored to the established values:
`fbf1f2fbe8a8ae2b11d41cc571a06863de0b554681d6fb94734dcfed9f91da1f` and
`c37736f7d6722374e8c5bb06cdb51d233af3ccea0b3b2432dc5899de3327b46c`.

Verification:

```text
pytest -q tests/test_psychlo_bridge.py
131 passed

pytest -q tests/test_psychlo_contracts.py tests/test_psychlo_usage_systemd.py \
  tests/test_psychlo_external_round.py tests/test_psychlo_learning_protocol.py
33 passed
```

TDD red evidence was observed before implementation: the frozen-digest
assertion failed against the changed `7aa048...`/`d17e50...` values, and the
new proposed-policy/outcome form tests failed because the counterpart accepted
the wrong optional shape and lacked the field-specific digest representation.

No live services, gateways, credentials, packages, or external systems were
changed.
