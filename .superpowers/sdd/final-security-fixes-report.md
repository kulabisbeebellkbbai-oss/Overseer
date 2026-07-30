# Final Security Fixes Report

## Scope

Closed the four Important findings from the final whole-branch review without
calling live providers, services, or credential resolvers.

## Changes

- Claude now receives only documented nonsecret process runtime variables:
  `HOME` for CLI configuration discovery, `PATH` for child runtime lookup,
  `LANG`/`LC_ALL`/`LC_CTYPE` for deterministic text handling, and `TMPDIR` for
  runtime temporary files when configured. Credential references remain opaque
  and unrelated secret-bearing environment variables are not inherited.
- Handoff packages carry an `hmac-sha256-v1` attestation. SQLite stores a random
  private key in `agent_private_metadata`, atomically signs and persists new or
  updated packages, compares signatures in constant time, and requires exact
  equality with the persisted package. Schema migration `agent_driver_v9`
  documents that existing unsigned packages remain fail-safe invalid.
- Codex/tmux execution accepts only a `run_bounded` runner protocol. Every tmux
  command uses fixed timeout and stdout/stderr limits, with normalized timeout
  and output-limit failures and no raw failure output in persisted evidence.
- Provider-neutral discovery, dispatch, checkpoint, recovery, and handoff
  payload parsers reject unknown keys before their route handler is invoked.

## TDD and Verification

- RED evidence: the initial focused security run failed for inherited secrets,
  missing/forged/foreign handoff attestations, and unknown fields reaching
  mutation handlers.
- Focused lifecycle/security regression: `175 passed, 1 skipped`.
- Migration/store/core compatibility regression: passed.
- Fresh full suite: `785 passed, 1 skipped`.
- `python3 -m compileall -q src tests`: passed.
- `git diff --check`: passed.
- Static security checks confirmed no unbounded Codex facade default, no
  `capture_output=True` seam in the Codex adapter/facade, and no handoff
  signature references in public API, CLI, or client modules.
