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
- Store open pins the exact database inode with `O_PATH|O_NOFOLLOW`, rejects
  multiply linked files, opens SQLite through the pinned descriptor, and
  verifies the connection's process descriptors before schema or record work.
  One non-I/O pin is retained per inode for the process lifetime so closing a
  nested store never disturbs process-scoped SQLite locks held by another
  connection.
- The persistence API stores typed records as JSON payloads so the domain model can continue to evolve before schema hardening.
- `persistence-security` and `GET /persistence/security` inspect database and SQLite sidecar file permissions without creating missing files or changing modes.
- The store records schema migrations in `schema_migrations` so on-disk shape changes are auditable before later hardening.
- `export-state-redacted` and `GET /state/redacted` produce a share-oriented state export that replaces local paths, targets, errors, summaries, reasons, command text, prompt/advisory text, hostnames, listener addresses, and secret-like keys with `[REDACTED]`.

## Next Hardening Steps

- Add append-only audit storage once live actions exist.
