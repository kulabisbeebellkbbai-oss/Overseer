# Task 3 Roadex Durability Correction

## Finding

Roadex JSON state persistence atomically renamed a page-cache-backed temporary
file without syncing the file or its parent directory. A parent-directory sync
failure after rename could therefore be misclassified as a committed
registration from strict readback alone.

## Design

`createJsonFilePersistence.save` now writes through a file descriptor, fsyncs
and closes the temporary file, renames it, then opens, fsyncs, and closes the
parent directory before reporting success. A typed post-rename durability
failure forces `commitAuthoritativeRegistration` to return `indeterminate`,
while a generic exception after a fully durable save still reconciles an exact
authoritative tuple as `committed`. Strict reads and startup quarantine are
unchanged.

## Tests

- Deterministic file-write/sync/close, rename, directory-open/sync/close order.
- Normal JSON save and reload.
- Parent-directory fsync failure after rename returns `indeterminate` despite
  exact readback.
- Existing post-durable-save-then-throw reconciliation remains `committed`.
- Task 3 suite: 173 passed; full Roadex suite: 569 passed; lint and build pass.

## Roadex commit

`7b0bd0e41fc6e87575938cfc9d71f8563061ea31`

No live services, deployment, restart, push, approval, or provisioning action
was performed.
