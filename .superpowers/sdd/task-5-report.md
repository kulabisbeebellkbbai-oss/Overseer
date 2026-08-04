# Task 5 Report: Atomic Review Outbox Materialization and Exact Dispatch

## Outcome

Implemented Task 5 without mutating the immutable `provisioning_review_outbox`
records. Lifecycle is derived from one exact materialized `CrewMessage` and two
deterministic audit receipts: a pre-dispatch `QUEUED` claim and a post-terminal
`VERIFIED` completion receipt.

Automatic provisioning review dispatch supports exactly two terminal outcomes:
`APPROVED` from a typed `dispatched` reviewer result and
`CORRECTION_REQUESTED` from a typed `skipped` or `blocked` result. The separate
human-decision workflow may record rejection, but Task 5 automatic dispatch does
not produce or accept `REJECTED`; `WAITING_HUMAN_APPROVAL` is also nonterminal.

The public dispatch boundary validates every caller-controlled field before any
mutation, resolves the outbox and audit records through indexed exact-ID reads,
revalidates the complete persisted bundle/binding/preflight/outbox set, and
invokes `dispatch_crew_messages_status()` only with the committed exact
`message_id`. An ambiguous or host-mutating result leaves the claim in place and
fails closed rather than risking a second dispatch.

No host mutation, live crew dispatch, deployment, restart, approval,
provisioning, or protected-host operation was performed during this task.

## TDD Evidence

- Initial RED: 12 failed, 2 passed, 245 deselected. Missing materializer,
  exact dispatcher, CLI command, and API route were observed.
- Audit forgery RED: a terminal-looking message plus forged completion receipt
  but no matching dispatch audit incorrectly passed; exact in-transaction audit
  validation made it GREEN.
- Pre-mutation validation RED: empty/oversized/non-ASCII dispatcher identities
  and invalid/naive timestamps could materialize or reach dispatch; shared
  validation now rejects them with zero Task 5 message/audit mutation.
- API mapping RED: an invalid bounded outbox ID returned 503; it now returns a
  stable redacted 400 `INVALID_REVIEW_OUTBOX_REQUEST` response.
- Real dispatcher integration covers both an O'Brien typed approval and a Kira
  typed correction request using the authoritative evidence shapes.
- Final security correction RED: after a legitimate claim, arbitrary look-alike
  dispatch audit IDs, summaries, event types, and claim/decision timestamps were
  accepted, as was a synthetic terminal `REJECTED` message. The correction uses
  one shared deterministic dispatch-audit ID and verifies the exact typed
  outcome, summary, type, owner, subject, risk, evidence, and timestamp shape.
  Subject and owner forgeries already failed closed and remain regression-tested.

## Verification

- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning_review_flow.py tests/test_backup_provisioning.py -k 'outbox or dispatch or terminal_evidence' --tb=short`
  - 49 passed, 258 deselected after the final audit-shape correction.
- `pytest -q tests/test_provisioning_bundle.py tests/test_backup_provisioning_review_flow.py --tb=short`
  - 279 passed after the final audit-shape correction.
- `pytest -q tests/test_core.py --tb=short`
  - 381 passed after moving dispatch-audit ID generation to the shared crew
    helper.
- Full repository run:
  - 1426 passed, 6 skipped, 10 failed.
  - One concurrent SQLite test passed on isolated rerun.
  - Eight unchanged cross-repository acceptance tests remain blocked by missing
    `mcp`, `THEUNDERDARK_PYTHON`, or `THEUNDERDARK_SOURCE` dependencies.
  - One unchanged Roadex fixed-digest assertion remains reproducibly mismatched.
- Task 4 disposable TheUnderdark acceptance configuration:
  - `THEUNDERDARK_PYTHON='/home/god/Documents/Codex Workspace/TheUnderdark/.venv/bin/python' THEUNDERDARK_SOURCE='/home/god/Documents/Codex Workspace/TheUnderdark/.worktrees/donuthole-contract-acceptance' PYTHONPATH=src '/home/god/Documents/Codex Workspace/TheUnderdark/.venv/bin/python' -m pytest -q tests/test_donuthole_backup_acceptance.py`
  - 10 passed in 6.46s after the final audit-shape correction.

## Files

- `src/overseer/provisioning_bundle.py`
- `src/overseer/cli.py`
- `src/overseer/crew.py` (shared deterministic dispatch-audit ID helper)
- `src/overseer/api.py`
- `src/overseer/backup_provisioning_cli.py`
- `src/overseer/store.py` (bounded exact-ID outbox/audit loaders)
- `tests/test_provisioning_bundle.py`
- `tests/test_backup_provisioning_review_flow.py`
