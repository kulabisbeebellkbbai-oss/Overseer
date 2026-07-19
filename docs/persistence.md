# Persistence

Overseer needs durable coordination state, but runtime databases must remain local and uncommitted. The first persistence slice defines a small SQLite-backed store that only creates a database when an operator passes an explicit path.

## Stored Records

- resources
- claims
- conflict decisions
- approval requests
- audit events

## Boundaries

- Database files are ignored by `.gitignore`.
- The store must not persist secrets, credentials, tokens, personal exports, or raw service payloads.
- Runtime state should live under an ignored operator-selected path such as `state/overseer.sqlite3`.
- The persistence API stores typed records as JSON payloads so the domain model can continue to evolve before schema hardening.
- `persistence-security` and `GET /persistence/security` inspect database and SQLite sidecar file permissions without creating missing files or changing modes.
- `export-state-redacted` and `GET /state/redacted` produce a share-oriented state export that replaces local paths, targets, errors, summaries, reasons, command text, prompt/advisory text, hostnames, listener addresses, and secret-like keys with `[REDACTED]`.

## Next Hardening Steps

- Add migrations before changing on-disk shape.
- Add append-only audit storage once live actions exist.
