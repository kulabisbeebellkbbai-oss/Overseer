# Task 3 Roadex Durability Correction

## Finding

Roadex JSON state persistence used a fixed `${path}.tmp` opened with truncation,
which could follow a symlink and overwrite an unrelated target. The correction
also needed to make pre-rename cleanup ownership-safe while preserving the
durability ordering from the initial patch.

## Design

`createJsonFilePersistence.save` now creates a bounded unique temporary file in
the target directory with `O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY` and mode `0600`.
Ownership begins only after successful exclusive creation. Write, file-fsync,
close, and rename failures close what can be closed and unlink only that owned
temporary path, preserving the original error if cleanup also fails. Ownership
is cleared immediately after rename, so no post-rename unlink is attempted.
The existing ordering remains: write, file fsync, close, rename, parent-directory
open/fsync/close. A typed post-rename durability failure still forces
`commitAuthoritativeRegistration` to return `indeterminate`, while a generic
exception after a fully durable save still reconciles an exact authoritative
tuple as `committed`. Strict reads and startup quarantine are unchanged.

## Tests

- Deterministic exclusive/no-follow flags, real symlink resistance, and explicit
  owned-temp cleanup tests for write, file-fsync, close, and rename failures;
  unrelated-path preservation, cleanup error precedence, and no post-rename
  unlink.
- Deterministic file-write/sync/close, rename, directory-open/sync/close order.
- Parent-directory fsync failure after rename returns `indeterminate` despite
  exact readback; post-durable-save generic exceptions still reconcile as
  `committed`.
- Complete approval-related suite: 14 files, 180 passed; full Roadex suite:
  55 files, 577 passed; lint, production build, and diff check pass.

## Roadex commit

`4b771b57cae84acf42261b50d37e33f99b0df664`

No live services, deployment, restart, push, approval, or provisioning action
was performed.
