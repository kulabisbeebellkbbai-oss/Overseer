# Task 1 Report: Restore Overseer release baseline

## Outcome

Implemented and committed Task 1 on the isolated worktree branch.

- Implementation commit: `fabf774` — `Restore Overseer release baseline`
- Follow-up repair commit: `ceb111b` — `Route claim cleanup approval through Sisko`
- Worktree: `/home/god/Documents/Codex Workspace/Overseer/.worktrees/overseer-v1-1-autonomous-operations`
- No live Overseer services, gateways, systemd state, integrations, or user data were changed.
- `.superpowers/sdd/progress.md` was not modified.

## TDD evidence

### RED

The exact brief RED command was rerun before edits:

```text
pytest -q tests/test_agent_migration.py::test_legacy_facade_submits_whitespace_prompt_with_exact_tmux_sequence \
  tests/test_codex_dispatch_activation.py::test_live_staged_spec_captures_exact_current_user_manager_identity \
  tests/test_core.py::OverseerApiTests::test_loopback_api_runs_claim_lifecycle \
  tests/test_core.py::OverseerApiClientTests::test_client_reviews_expired_claims \
  tests/test_core.py::OverseerApiClientTests::test_client_runs_claim_lifecycle \
  tests/test_core.py::HostInspectionTests::test_dispatch_ids_review_package_uses_codex_projects_adapter \
  tests/test_psychlo_decision_reconcile.py::test_api_approves_and_activates_the_exact_structurally_bound_claim_before_delivering_outcome \
  tests/test_roadex_approval_fixture.py \
  tests/test_ui_full_regression.py::FullOperatorUiRegressionTests::test_safe_disposable_workflows_execute_through_gateway_routes
```

Result: `10 failed, 6 passed in 14.30s`. Failures reproduced stale `paste-buffer -p` expectations, the linked-worktree `_spec()` bootstrap rejection, role-authority mismatches, incomplete Roadex migration history/rollback, and the UI claim lifecycle fallout.

After updating the tests first, the same focused command produced the expected second RED: `4 failed, 12 passed in 13.58s` (remaining stale tmux assertion, fail-closed error-message mismatch, and two migration-history failures).

### GREEN

After the minimal source changes, the exact focused set passed:

```text
16 passed in 12.66s
```

Additional focused verification:

- `pytest -q tests/test_codex_dispatch_activation.py`: `75 passed in 7.46s`
- `pytest -q tests/test_agent_store.py`: `56 passed in 1.46s`
- `pytest -q tests/test_agent_migration.py tests/test_codex_dispatch_activation.py tests/test_roadex_approval_fixture.py tests/test_psychlo_decision_reconcile.py`: passed during focused verification.

## Follow-up repair evidence

The two residual claim-cleanup tests were reproduced exactly before the repair:

```text
pytest -q tests/test_core.py::RuntimeTests::test_execute_claim_cleanup_handles_missing_release_evidence_and_blocked_claims tests/test_core.py::RuntimeTests::test_execute_claim_cleanup_re_evaluates_stale_queue_after_approval
2 failed in 1.68s
```

The failures showed cleanup subjects being classified as `ApprovalLevel.ROLE`, then rejected by the exact-Claim ROLE authority checks. Tests were first strengthened to require `ApprovalLevel.SISKO`; that test-only RED run remained `2 failed in 0.93s`, with both assertions observing `role != sisko`.

The bounded attribution check was run ten times:

```text
for run in $(seq 1 10); do pytest -q tests/test_usage_attribution.py::test_cross_process_delivery_intent_has_one_winner || exit $?; done
```

Result: `10/10` runs passed, each reporting `1 passed`; no speculative concurrency change was made.

The repair changes `_claim_cleanup_approval_level` to always return `ApprovalLevel.SISKO`. This preserves Sisko as the administrative authority for cleanup mutations and leaves `ApprovalLevel.ROLE` reserved for exact still-requested Claims and their activation continuations. Affected verification after the repair:

- Exact cleanup regressions: `2 passed in 0.53s`
- `tests/test_claim_approval_continuation.py tests/test_claim_activation_group.py tests/test_usage_attribution.py::test_cross_process_delivery_intent_has_one_winner`: `28 passed in 1.60s`
- `tests/test_core.py tests/test_claim_approval_continuation.py tests/test_claim_activation_group.py tests/test_usage_attribution.py`: `441 passed in 96.27s`

## Implementation and design decisions

- Roadex fixture migration now checks for the exact version-3 row, rather than using `MAX(version)`. The fixture migration runs before the aggregate schema marker, yielding `[2, 3, 10]` for legacy v2 stores and `[3, 10]` for new stores. Savepoint rollback removes both fixture DDL and migration history on injected failure.
- `_activate_bound_decision_claim` now fails closed while the owner-role approval is pending. Roadex human approval cannot impersonate the owner role; the exact role claim must first be approved by `dax`.
- Direct Dax claim lifecycle fixtures now approve with `dax`; the Psychlo regression explicitly proves human approval is rejected while role approval is pending, then succeeds after exact Dax approval.
- The live user-manager identity test calls `activation._capture_user_bus_peer_binding()` directly and asserts current UID, GID, parent PID, and argv. It does not call `_spec()` and production bootstrap path validation was not weakened.
- Test-only linked-worktree spec fixtures use a real Git common directory only to construct synthetic fixture metadata. Production `_bootstrap_binding()` still rejects the linked-worktree `.git` file.
- Tmux expectations now include `paste-buffer -p`; the UI claim fixture includes the required activation-group and lifecycle bindings.

## Files changed

- `src/overseer/api.py`
- `src/overseer/cli.py`
- `src/overseer/store.py`
- `tests/test_agent_migration.py`
- `tests/test_agent_store.py`
- `tests/test_codex_dispatch_activation.py`
- `tests/test_core.py`
- `tests/test_psychlo_decision_reconcile.py`
- `tests/test_roadex_approval_fixture.py`
- `tests/test_ui_full_regression.py`

## Full-suite verification

The required uninterrupted clean-worktree run before the follow-up repair was:

```text
pytest -q
2025 passed, 31 skipped, 3 failed in 410.67s (0:06:50)
```

Those three failures were repaired or classified as follows:

1. The two cleanup failures were fixed in `ceb111b` by classifying synthetic cleanup subjects as Sisko approvals.
2. The attribution failure was a one-run flake; ten bounded focused reruns passed.

The earlier pre-commit full run is not treated as final evidence because source-lineage tests correctly saw the dirty worktree. The final authoritative clean-worktree run after `ceb111b` was:

```text
pytest -q
2028 passed, 31 skipped in 406.93s (0:06:46)
```

## Residual concerns

Task 1 implementation and full-suite verification are complete with zero failures. The report update follows the implementation commits and records the final clean-worktree evidence.
