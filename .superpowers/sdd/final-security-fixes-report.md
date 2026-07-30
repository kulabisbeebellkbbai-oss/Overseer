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

## HMAC Key-at-Rest Follow-up

- SQLite databases are atomically precreated with mode `0600`. Existing paths
  are opened without following symlinks, verified as owner-held regular files,
  and tightened to `0600` before SQLite connects.
- Database, WAL, SHM, and rollback-journal artifacts are rehardened after
  connection setup, schema initialization, commits, checkpoints, and close.
  The implementation does not alter process umask or parent-directory modes.
- Filesystem RED evidence reproduced permissive `0644` creation/reopen behavior
  and symlink acceptance. Focused GREEN evidence verifies a new database plus
  real WAL/SHM files under umask `0022`, legacy-mode tightening, symlink
  rejection, and no chmod of an unrelated file.
- The secure-open path also rechecks device and inode identity immediately
  after SQLite connects, before PRAGMAs or schema writes. The final fresh full
  suite passed with `788 passed, 1 skipped`; compileall and diff checks passed.

## Filesystem Race Follow-up

- Existing database and sidecar candidates are opened with
  `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` before `fstat`, so FIFOs and other
  nonregular paths reject promptly without waiting for a peer. Tests cover
  both an unconsumed FIFO and a bound Unix-domain socket.
- The store retains the original database device/inode and the first securely
  observed identity of each WAL, SHM, or journal sidecar. Commit, checkpoint,
  and close paths compare those identities before any descriptor-based chmod.
- A missing or replaced database prevents all sidecar hardening. Replaced
  sidecars are rejected without chmod; close temporarily moves a compromised
  sidecar pathname aside while SQLite releases its original handles, then
  restores the replacement atomically so SQLite cannot delete it.
- Race reproductions verify unchanged `0644` mode and content for substituted
  database/WAL/SHM files, prompt FIFO rejection, deleted-path close
  compatibility, and normal owner-only modes. The focused store/lifecycle/core
  suite passed with `490 passed`; the final full suite passed with
  `793 passed, 1 skipped`.
