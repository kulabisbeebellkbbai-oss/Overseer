# Task 10 Report: Additional Verified Provider Adapters

## Outcome

Added isolated `PrimaryDriver` implementations and factories for Qwen Code,
Mistral Vibe, and Antigravity. Each adapter recognizes its configured provider
identity while refusing to claim or invoke any locally unverified interface.
Codex and Claude adapter behavior was left unchanged.

## Local absence evidence

The approved brief records that `qwen`, `qwen-code`, `vibe`,
`mistral-vibe`, and `antigravity` were absent from command lookup and the
inspected executable, desktop-entry, and `/opt` locations. Consequently this
task did not install software, configure credentials or gateways, make network
calls, invoke provider prompts, construct provider commands, or automate a GUI.

## TDD evidence

RED:

- `pytest -q tests/test_agent_adapter_contract.py tests/test_agent_registry.py -x`
  failed during collection with
  `ModuleNotFoundError: No module named 'overseer.agent_adapters.antigravity'`.
- The provider-inventory test then failed because registering a factory made
  `mistral-vibe` report `"available": true`.

GREEN:

- Focused contract, registry, and API suite:
  `82 passed, 1 skipped in 7.35s`.
- Full suite: `727 passed, 1 skipped in 103.33s`.
- `python3 -m compileall -q src tests`: passed.
- `git diff --check`: passed.

## Behavior and status

- All configured capabilities remain false.
- Discovery is empty and resolution returns no session.
- Start, resume, dispatch, inspection, cancellation, and handoff import return
  normalized `provider_unavailable` results with supplied bindings preserved.
- Checkpoint returns normalized `unsupported_capability` evidence.
- Factories reject mismatched provider IDs, adapter IDs, transports,
  executable selections, profile selections, and unverified capability claims.
- No unavailable adapter contains a runner or command construction path.
- Qwen Code and Mistral Vibe report an installed adapter, unavailable live
  provider, and `executable_not_installed`.
- Antigravity reports an installed adapter, unavailable live provider, and
  `programmatic_interface_unverified`.

## Residual risk

These adapters intentionally cannot execute work. A future adapter must be
implemented only after its exact local interface, output grammar, session
protocol, and capabilities are independently verified.

## Commit

Initial implementation: `cdb25e9112e1708aef3ba75f3004b6be52fecdd8`.

## Independent review follow-up

Review found that the unavailable Qwen Code and Mistral Vibe constructors
rejected the absolute canonical executable paths produced by a valid local
registry override. Regression coverage first reproduced that constructor
failure. The adapters now accept either the committed literal executable name
or one absolute canonical path with the expected basename, while rejecting
multiple entries, relative paths, and wrong basenames. No accepted path is
executed.

Added coverage also proves:

- `AgentRegistry.driver` and `driver_for_provider` construct these unavailable
  adapters from local executable-path overrides without configuration crashes;
- status remains unavailable with `executable_not_installed`;
- all three unavailable adapters preserve supplied handoff instance, session,
  epoch, and provider bindings and return privacy-safe
  `provider_unavailable` evidence without invocation.

Review-fix verification:

- focused suite: `89 passed, 1 skipped in 7.42s`;
- full suite: `734 passed, 1 skipped in 103.22s`;
- `python3 -m compileall -q src tests` and `git diff --check`: passed.
