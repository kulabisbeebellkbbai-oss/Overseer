# Task 6 Report: Typed Approval Gate and Legacy Compatibility

## Outcome

Implemented a read-only typed approval verifier over the exact persisted
provisioning bundle, prospective Roadex binding, registered source, passing
preflight report, immutable pending review outbox, code-owned dispatch audits,
and all four `VERIFIED` completion receipts. Approval, denial, and revision now
run that verifier in the same `BEGIN IMMEDIATE` transaction as the plan update.
No readiness or approval path materializes or dispatches a review, rewrites an
outbox row, or edits binding, report, bundle, message, or audit evidence.

The raw stage boundary is serialized with typed activation. Before activation,
legacy raw staging remains compatible. Once any dedicated Task 3 preflight,
bundle, outbox row, or exact `approval.donuthole.*` prospective binding exists,
raw staging returns `TYPED_BUNDLE_REQUIRED`. A legacy staged plan then returns
`SUCCESSOR_REQUIRED`; its evidence does not transfer. Projection-only Roadex
bindings such as `admin.roadex.human` do not activate this facility. Terminal
legacy plans remain listable, and an already-approved legacy plan is not
rewritten or newly gated at execution.

Roadex readiness uses the same verifier in one rollback-only read snapshot and
returns stable server-owned `blocker_codes` plus fixed redacted human
explanations in `blockers`. The browser only renders those fields and exposes
the blocker region as an accessible polite status.

No live crew dispatch, approval, provisioning, deployment, restart, protected
host mutation, or push was performed.

## Task 6 Security Correction RED/GREEN Evidence

- RED: focused reproductions showed typed approval still succeeded after
  revoking the current root authorization or staging a valid successor tip;
  API approval accepted whitespace-padded `kira`; denial and revision accepted
  crew actors; and a projection `RuntimeError` escaped with its private text.
- GREEN: `_require_bundle_preflight_and_reviews` now invokes the locked root
  authority and chain recheck inside the existing approval/denial/revision
  transaction and Roadex read snapshot. Root/preflight drift maps to
  `PREFLIGHT_NOT_CURRENT`; stale chain state maps to `SUCCESSOR_REQUIRED`.
  Approve, deny, and revision share one canonical independent-human validator,
  and both direct and public Roadex projections map ordinary exceptions to the
  fixed `REVIEW_EVIDENCE_NOT_CURRENT` explanation without catching fatal
  `BaseException` subclasses.
- GREEN focused correction slice: 10 passed, including direct and API identity
  regressions and revocation/successor zero-mutation checks; the separate
  direct/public route redaction selector passed 2 tests.

## TDD Evidence

- Initial focused RED: 13 failed and 1 passed. Missing and stale preflight,
  forged or partial completion evidence, legacy successor enforcement, all four
  partial activation shapes, the concurrent first-bundle/raw-stage boundary,
  and approval/denial lock races all failed as expected.
- Transaction RED proved a competing crew-message writer could finish between
  evidence verification and the plan update. Both approval and denial now hold
  the write lock through verification and update.
- Boundary RED paused raw validation, committed the first typed bundle, then
  resumed raw staging. The raw insert initially won; it now observes activation
  under the lock and fails with `TYPED_BUNDLE_REQUIRED`.
- Snapshot RED deleted a completion receipt from a concurrent WAL writer while
  readiness was verifying. The in-flight response now remains internally
  consistent, while the next response reports
  `REVIEW_EVIDENCE_NOT_CURRENT`.
- A legitimate Task 5 `CORRECTION_REQUESTED` completion and unknown exceptions
  are mapped to a stable redacted blocker; a fake private path/token never
  appears in the API explanation.
- Full-suite compatibility RED found five projection-only Roadex fixtures that
  were incorrectly treated as activation. Narrowing the binding marker to the
  exact Task 3 `approval.donuthole.*` namespace made all five GREEN while the
  malformed exact-prefix activation test continued to fail closed.

## Verification

- Focused Task 6/API/UI slice: 22 passed, 431 deselected.
- Backup provisioning and UI: 72 passed.
- Capability B selector: 343 passed, 390 deselected.
- Full affected provisioning, bundle, review-flow, and UI suite: 351 passed.
- Full core suite: 382 passed.
- Projection-only binding compatibility rerun: 5 passed, 131 deselected.
- Full Roadex approval projection suite: 135 passed, 1 unchanged fixed-digest
  failure.
- Configured disposable TheUnderdark acceptance: 10 passed.
- Configured cross-repository contract: 26 passed, 1 skipped.
- Final full repository run: 1468 passed, 2 skipped, 2 failed. The remaining
  failures are outside Task 6:
  - `test_bridge_discovers_tools_in_its_first_call_boundary` uses the system
    pytest interpreter, where `mcp` is not installed. The configured
    TheUnderdark virtual-environment acceptance run passes all 10 tests.
  - `test_roadex_human_scope_and_source_evidence_digest_use_exact_contract`
    retains the pre-existing fixed digest mismatch (`327b...` actual versus
    `0d12...` expected) already attributed by Task 5.
- Python compile checks passed for every modified Python file.
- `git diff --check` passed.

## Files

- `src/overseer/backup_provisioning.py`
- `src/overseer/provisioning_bundle.py`
- `src/overseer/ui.py`
- `tests/test_backup_provisioning.py`
- `tests/test_core.py`
- `tests/test_ui_regression.py`
- `docs/superpowers/specs/2026-08-02-donuthole-provisioning-reliability-design.md`
- `.superpowers/sdd/task-6-report.md`
