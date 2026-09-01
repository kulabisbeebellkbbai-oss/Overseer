# Persistence

Overseer needs durable coordination state, but runtime databases must remain local and uncommitted. The first persistence slice defines a small SQLite-backed store that only creates a database when an operator passes an explicit path.

## Stored Records

- resources
- claims
- conflict decisions
- approval requests
- audit events
- schema migrations
- usage limits and continuation requests
- health targets and evidence
- runtime, host, admin, and security review records

## Boundaries

- Database files are ignored by `.gitignore`.
- The store must not persist secrets, credentials, tokens, personal exports, or raw service payloads.
- Runtime state should live under an ignored operator-selected path such as `state/overseer.sqlite3`.
- Ordinary store opens preserve normal SQLite connection semantics, including
  concurrent and nested connections; they do not retain process-wide inode
  pins.
- The one-shot atomic claim transition opts into strict descriptor binding. It
  requires an absolute path, an owner-controlled parent, and
  a pre-existing owner-only, singly linked database in a single-threaded process
  with no same-inode descriptor already open. It retains no-follow pins for the
  parent, main database, WAL, and SHM; attributes every newly opened regular
  descriptor to that exact namespace; and rejects rollback-journal mode or any
  unbound descriptor before schema or record work. Group write is accepted only
  when the parent group is the owner's primary group and has no other account
  members; world write and extended access/default ACLs are always rejected. A
  bounded pin registry fails closed
  before descriptor exhaustion and never closes an unmanaged database
  descriptor. Normal and recovered commit success revalidate every live
  connection descriptor plus fresh parent/main/WAL/SHM path pins. A clean close
  may checkpoint and remove WAL/SHM only after their final live validation;
  rejected namespaces keep checkpoint-on-close disabled. Strict close requires
  the parent and main path to remain bound before and after connection close.
  Any close-time integrity failure is returned as an error even when the
  transaction committed.
- The persistence API stores typed records as JSON payloads so the domain model can continue to evolve before schema hardening.
- `persistence-security` and `GET /persistence/security` inspect database and SQLite sidecar file permissions without creating missing files or changing modes.
- The store records schema migrations in `schema_migrations` so on-disk shape changes are auditable before later hardening.
- `export-state-redacted` and `GET /state/redacted` produce a share-oriented state export that replaces local paths, targets, errors, summaries, reasons, command text, prompt/advisory text, hostnames, listener addresses, and secret-like keys with `[REDACTED]`.

## Next Hardening Steps

- Add append-only audit storage once live actions exist.
